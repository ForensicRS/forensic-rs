//! Paging files: the stores that hold pages which were not in RAM at capture time.
//!
//! A [`Translation::PageFile`](super::Translation::PageFile) names a paging file by the OS's own
//! number for it, plus a byte offset. When the investigator supplies that file next to the
//! capture (Windows `pagefile.sys`, `swapfile.sys`), a backend reads the page from it and reports
//! [`Validity::Paged`] with `data: true`. Without the file, the read still reports where the page
//! lives, with `data: false`.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use crate::err::ForensicResult;

use super::validity::{Backing, ReadReport, Validity};

/// One paging file attached to a memory image, read as raw bytes at the offsets that
/// translations carry.
///
/// Paging files are evidence like the capture itself: implementations bounds-check every read
/// and never panic.
pub trait PagingFile: Send + Sync {
    /// The store this file is: [`Backing::PageFile`] or [`Backing::SwapFile`].
    fn backing(&self) -> Backing;

    /// The file's size in bytes.
    fn size(&self) -> u64;

    /// Reads `buf.len()` bytes at byte `offset`. Bytes past the end of the file (a truncated
    /// copy) are zero-filled and reported `Paged { backing, data: false }`. The report covers
    /// exactly `buf.len()` bytes. An `Err` means the file itself failed (an I/O error).
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> ForensicResult<ReadReport>;
}

/// The paging files attached to one memory image, keyed by the OS's paging-file number (the
/// `file` of [`Translation::PageFile`](super::Translation::PageFile)).
#[derive(Clone, Default)]
pub struct PagingFiles {
    files: BTreeMap<u8, Arc<dyn PagingFile>>,
}

impl PagingFiles {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attaches `file` as paging file `number`, returning the file it replaces.
    pub fn insert(&mut self, number: u8, file: Arc<dyn PagingFile>) -> Option<Arc<dyn PagingFile>> {
        self.files.insert(number, file)
    }

    pub fn get(&self, number: u8) -> Option<&Arc<dyn PagingFile>> {
        self.files.get(&number)
    }

    /// The attached files, in number order.
    pub fn iter(&self) -> impl Iterator<Item = (u8, &Arc<dyn PagingFile>)> {
        self.files.iter().map(|(n, f)| (*n, f))
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Reads the bytes of a `PageFile { file, offset }` translation. When no file `file` is
    /// attached, the bytes are zero-filled and reported `Paged { PageFile, data: false }`: the
    /// translation does not say which kind of store the number is.
    pub fn read(&self, file: u8, offset: u64, buf: &mut [u8]) -> ForensicResult<ReadReport> {
        match self.files.get(&file) {
            Some(f) => f.read_at(offset, buf),
            None => {
                buf.fill(0);
                Ok(ReadReport::uniform(
                    buf.len() as u64,
                    Validity::Paged {
                        backing: Backing::PageFile,
                        data: false,
                    },
                ))
            }
        }
    }
}

impl fmt::Debug for PagingFiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(
                self.files
                    .iter()
                    .map(|(n, file)| (n, (file.backing(), file.size()))),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::testing::InMemoryPagingFile;

    const PAGED_NO_DATA: Validity = Validity::Paged {
        backing: Backing::PageFile,
        data: false,
    };

    #[test]
    fn reads_an_attached_file_and_reports_a_missing_one() {
        let mut files = PagingFiles::new();
        files.insert(
            1,
            Arc::new(InMemoryPagingFile::new(Backing::SwapFile, vec![7; 0x2000])),
        );
        let mut buf = [0u8; 16];
        let r = files.read(1, 0x1000, &mut buf).unwrap();
        assert_eq!(buf, [7; 16]);
        assert_eq!(
            r.runs(),
            &[(
                16,
                Validity::Paged {
                    backing: Backing::SwapFile,
                    data: true
                }
            )]
        );

        let mut buf = [9u8; 16];
        let r = files.read(0, 0, &mut buf).unwrap();
        assert_eq!(buf, [0; 16]);
        assert_eq!(r.runs(), &[(16, PAGED_NO_DATA)]);
    }

    #[test]
    fn a_truncated_file_reports_the_missing_tail() {
        let file = InMemoryPagingFile::new(Backing::PageFile, vec![1; 0x1008]);
        let mut buf = [9u8; 16];
        let r = file.read_at(0x1000, &mut buf).unwrap();
        assert_eq!(&buf[..8], &[1; 8]);
        assert_eq!(&buf[8..], &[0; 8]);
        assert_eq!(
            r.runs(),
            &[
                (
                    8,
                    Validity::Paged {
                        backing: Backing::PageFile,
                        data: true
                    }
                ),
                (8, PAGED_NO_DATA)
            ]
        );
        // Offsets past the end, up to the top of the 64-bit space.
        let r = file.read_at(u64::MAX - 3, &mut buf).unwrap();
        assert_eq!(r.runs(), &[(16, PAGED_NO_DATA)]);
    }
}
