//! Positional byte sources for storage media: the shared plumbing every image-format and
//! volume-system [`FormatFactory`](crate::traits::format::FormatFactory) needs, so none of them
//! re-derives it.
//!
//! A disk image is read by many workers at once, through several layers (image -> partition ->
//! filesystem -> file). A `Box<dyn VirtualFile>` has one cursor, so sharing it means a lock
//! around every read at every layer. Instead each layer holds an `Arc<dyn ReadAt>`:
//!
//! - [`into_read_at`] turns any opened file into one (positional if the backend can, a
//!   mutex-guarded seek+read if not).
//! - [`WindowReadAt`] is a bounded range of another source -- a partition.
//! - [`ConcatReadAt`] joins several sources end to end -- a split image's segments.
//! - [`ReadAtFile`] puts a private cursor back on top, so the result is an ordinary
//!   [`VirtualFile`] the next factory can probe.

use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use crate::err::ForensicResult;
use crate::traits::vfs::{FileAttributes, MacbTimes, ReadAt, VFileType, VMetadata, VirtualFile};

/// Turns an opened file into a shareable positional source: the backend's own
/// [`VirtualFile::as_read_at`] when it has one, otherwise the file itself behind a mutex.
pub fn into_read_at(file: Box<dyn VirtualFile>) -> ForensicResult<Arc<dyn ReadAt>> {
    if let Some(read_at) = file.as_read_at() {
        return Ok(read_at);
    }
    let size = file.metadata()?.size;
    Ok(Arc::new(LockedReadAt {
        inner: Mutex::new(file),
        size,
    }))
}

/// The fallback [`ReadAt`] for a backend with no positional read: seek+read under a lock.
/// Correct, but serializes readers; prefer a backend that implements
/// [`VirtualFile::as_read_at`].
pub struct LockedReadAt {
    inner: Mutex<Box<dyn VirtualFile>>,
    size: u64,
}

impl ReadAt for LockedReadAt {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }
        let want = clamp_len(buf.len(), self.size - offset);
        let mut file = self
            .inner
            .lock()
            .map_err(|_| std::io::Error::other("LockedReadAt lock poisoned"))?;
        file.seek(SeekFrom::Start(offset))?;
        file.read(&mut buf[..want])
    }

    fn size(&self) -> u64 {
        self.size
    }
}

/// A bounded range `[start, start + len)` of another source, addressed from 0 -- a partition
/// within a disk, a volume within a container.
///
/// A window that claims more bytes than its source has is not an error: a partition table
/// that points past the end of a truncated image is evidence, and the missing tail simply
/// reads as end of file.
pub struct WindowReadAt {
    source: Arc<dyn ReadAt>,
    start: u64,
    len: u64,
}

impl WindowReadAt {
    pub fn new(source: Arc<dyn ReadAt>, start: u64, len: u64) -> Self {
        Self { source, start, len }
    }

    /// Where this window starts in its source.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// Whether the source actually holds every byte the window claims.
    pub fn is_truncated(&self) -> bool {
        self.start.saturating_add(self.len) > self.source.size()
    }
}

impl ReadAt for WindowReadAt {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        let want = clamp_len(buf.len(), self.len - offset);
        let Some(at) = self.start.checked_add(offset) else {
            return Ok(0);
        };
        self.source.read_at(at, &mut buf[..want])
    }

    fn size(&self) -> u64 {
        self.len
    }
}

/// Several sources joined end to end, in the order given -- a split raw image's `.001`,
/// `.002`, ..., or a VMDK's extents.
pub struct ConcatReadAt {
    /// `(start offset in the joined stream, part)`, sorted by start.
    parts: Vec<(u64, Arc<dyn ReadAt>)>,
    size: u64,
}

impl ConcatReadAt {
    pub fn new(parts: impl IntoIterator<Item = Arc<dyn ReadAt>>) -> Self {
        let mut size = 0u64;
        let parts = parts
            .into_iter()
            .map(|part| {
                let start = size;
                size = size.saturating_add(part.size());
                (start, part)
            })
            .collect();
        Self { parts, size }
    }

    /// Which part holds byte `offset` of the joined stream, and the offset inside that part.
    /// `None` at or past the end.
    pub fn locate(&self, offset: u64) -> Option<(usize, u64)> {
        if offset >= self.size {
            return None;
        }
        // The last part starting at or before `offset`; empty parts are skipped by the
        // `offset < start + size` check below.
        let idx = self.parts.partition_point(|(start, _)| *start <= offset);
        (0..idx).rev().find_map(|i| {
            let (start, part) = &self.parts[i];
            (offset < start + part.size()).then(|| (i, offset - start))
        })
    }
}

impl ReadAt for ConcatReadAt {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        // One part per call, like `Read::read` returning short at a boundary; `read_exact_at`
        // and `ReadAtFile` loop across boundaries.
        let Some((idx, inner)) = self.locate(offset) else {
            return Ok(0);
        };
        let part = &self.parts[idx].1;
        let want = clamp_len(buf.len(), part.size() - inner);
        part.read_at(inner, &mut buf[..want])
    }

    fn size(&self) -> u64 {
        self.size
    }
}

/// A private cursor over a shared [`ReadAt`], making it an ordinary [`VirtualFile`]. Cheap:
/// opening a partition or an image's media file hands out one of these per `open()`, all
/// sharing the same underlying source.
pub struct ReadAtFile {
    source: Arc<dyn ReadAt>,
    pos: u64,
}

impl ReadAtFile {
    pub fn new(source: Arc<dyn ReadAt>) -> Self {
        Self { source, pos: 0 }
    }
}

impl Read for ReadAtFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.source.read_at(self.pos, buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for ReadAtFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.source.size().checked_add_signed(delta),
            SeekFrom::Current(delta) => self.pos.checked_add_signed(delta),
        };
        let target = target.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek to a negative or overflowing position",
            )
        })?;
        self.pos = target;
        Ok(target)
    }
}

impl VirtualFile for ReadAtFile {
    fn metadata(&self) -> ForensicResult<VMetadata> {
        Ok(VMetadata {
            file_type: VFileType::File,
            size: self.source.size(),
            allocated_size: None,
            times: MacbTimes::default(),
            id: None,
            attributes: FileAttributes::empty(),
        })
    }

    fn as_read_at(&self) -> Option<Arc<dyn ReadAt>> {
        Some(Arc::clone(&self.source))
    }
}

/// `min(buf_len, remaining)` without truncating a `u64` on 32-bit targets.
fn clamp_len(buf_len: usize, remaining: u64) -> usize {
    usize::try_from(remaining).map_or(buf_len, |r| buf_len.min(r))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A positional source over a byte vector, for tests.
    struct Bytes(Vec<u8>);
    impl ReadAt for Bytes {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let Some(rest) = usize::try_from(offset).ok().and_then(|o| self.0.get(o..)) else {
                return Ok(0);
            };
            let n = buf.len().min(rest.len());
            buf[..n].copy_from_slice(&rest[..n]);
            Ok(n)
        }
        fn size(&self) -> u64 {
            self.0.len() as u64
        }
    }

    fn bytes(b: &[u8]) -> Arc<dyn ReadAt> {
        Arc::new(Bytes(b.to_vec()))
    }

    fn read_all(source: Arc<dyn ReadAt>) -> Vec<u8> {
        let mut out = Vec::new();
        ReadAtFile::new(source).read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn window_reads_only_its_range() {
        let w = WindowReadAt::new(bytes(b"0123456789"), 2, 5);
        assert_eq!(w.size(), 5);
        assert!(!w.is_truncated());
        assert_eq!(read_all(Arc::new(w)), b"23456");
    }

    #[test]
    fn window_past_the_source_end_reads_what_exists_and_says_so() {
        let w = WindowReadAt::new(bytes(b"0123456789"), 8, 10);
        assert!(w.is_truncated());
        assert_eq!(read_all(Arc::new(w)), b"89");
    }

    #[test]
    fn concat_crosses_part_boundaries_and_skips_empty_parts() {
        let c = ConcatReadAt::new([bytes(b"abc"), bytes(b""), bytes(b"de"), bytes(b"fgh")]);
        assert_eq!(c.size(), 8);
        assert_eq!(c.locate(3), Some((2, 0)));
        assert_eq!(c.locate(7), Some((3, 2)));
        assert_eq!(c.locate(8), None);
        let c = Arc::new(c);
        let mut buf = [0u8; 4];
        c.read_exact_at(2, &mut buf).unwrap();
        assert_eq!(&buf, b"cdef");
        assert_eq!(read_all(c), b"abcdefgh");
    }

    #[test]
    fn read_at_file_seeks_independently_of_other_cursors() {
        let source = bytes(b"0123456789");
        let mut a = ReadAtFile::new(Arc::clone(&source));
        let mut b = ReadAtFile::new(source);
        a.seek(SeekFrom::End(-3)).unwrap();
        let mut one = [0u8; 1];
        b.read_exact(&mut one).unwrap();
        assert_eq!(&one, b"0");
        a.read_exact(&mut one).unwrap();
        assert_eq!(&one, b"7");
        assert!(a.seek(SeekFrom::Current(-100)).is_err());
    }

    #[test]
    fn into_read_at_falls_back_to_a_locked_source() {
        use crate::traits::vfs::FileSystem;
        use crate::utils::testing::InMemoryVirtualFileSystem;
        let fs = InMemoryVirtualFileSystem::new().with_file("x.bin", b"hello world".to_vec());
        let source =
            into_read_at(fs.open(crate::core::path::FPath::new("x.bin")).unwrap()).unwrap();
        let mut buf = [0u8; 5];
        source.read_exact_at(6, &mut buf).unwrap();
        assert_eq!(&buf, b"world");
        assert_eq!(source.read_at(11, &mut buf).unwrap(), 0);
    }

    #[test]
    fn many_threads_share_one_source() {
        let data: Vec<u8> = (0..=255u8).cycle().take(1 << 16).collect();
        let source: Arc<dyn ReadAt> = Arc::new(ConcatReadAt::new([
            bytes(&data[..30_000]),
            bytes(&data[30_000..]),
        ]));
        let handles: Vec<_> = (0..8u64)
            .map(|t| {
                let source = Arc::clone(&source);
                let data = data.clone();
                std::thread::spawn(move || {
                    for i in 0..200u64 {
                        let off = (t * 7919 + i * 331) % (data.len() as u64 - 64);
                        let mut buf = [0u8; 64];
                        source.read_exact_at(off, &mut buf).unwrap();
                        assert_eq!(&buf[..], &data[off as usize..off as usize + 64]);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }
}
