use std::collections::BTreeMap;

use crate::err::ForensicResult;
use crate::field::{Field, Text};
use crate::utils::time::ForensicTimestamp;

pub trait VirtualFile: std::io::Seek + std::io::Read + Send {
    fn metadata(&self) -> ForensicResult<VMetadata>;

    /// Positional, shareable access to the same bytes, when the backend can offer it without
    /// disturbing this handle's own cursor (a `pread`, an in-memory buffer, a window over
    /// another [`ReadAt`]). `None` by default -- use
    /// [`into_read_at`](crate::core::fs::window::into_read_at), which falls back to a
    /// mutex-guarded seek+read, rather than calling this directly.
    ///
    /// This is what lets a disk image be read by many workers at once: a volume system or a
    /// filesystem mounted over an image holds an `Arc<dyn ReadAt>`, not a `Box<dyn VirtualFile>`
    /// every reader would have to lock.
    fn as_read_at(&self) -> Option<std::sync::Arc<dyn ReadAt>> {
        None
    }
}

/// Positional reads over a fixed-size byte source, shareable across threads: `&self`, so one
/// `Arc<dyn ReadAt>` serves any number of concurrent readers, each with its own cursor (see
/// [`ReadAtFile`](crate::core::fs::window::ReadAtFile)).
pub trait ReadAt: Send + Sync {
    /// Reads up to `buf.len()` bytes starting at `offset`. Returns `Ok(0)` at or past
    /// [`size`](ReadAt::size), like `Read::read` at end of file.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize>;

    /// Total size in bytes.
    fn size(&self) -> u64;

    /// Fills `buf` completely from `offset`, or fails with `UnexpectedEof`.
    fn read_exact_at(&self, mut offset: u64, mut buf: &mut [u8]) -> std::io::Result<()> {
        while !buf.is_empty() {
            match self.read_at(offset, buf) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "read_exact_at: source ended before the buffer was filled",
                    ));
                }
                Ok(n) => {
                    offset += n as u64;
                    buf = &mut buf[n..];
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct VMetadata {
    pub file_type: VFileType,
    pub size: u64,
    /// Cluster-rounded / sparse-file real allocation, when the backend can
    /// report it. `None` when unsupported or equal to `size`.
    pub allocated_size: Option<u64>,
    pub times: MacbTimes,
    /// Backend-defined file identifier (NTFS file reference number, inode,
    /// ...), for loop/hardlink detection during a walk.
    pub id: Option<FileId>,
    pub attributes: FileAttributes,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VFileType {
    File,
    Directory,
    Symlink,
}

impl VMetadata {
    /// Returns the creation timestamp, or Unix epoch if unsupported.
    ///
    /// Prefer [`Self::created_opt`] to preserve the distinction between an
    /// unsupported timestamp and an actual epoch timestamp.
    #[deprecated(
        since = "0.14.0",
        note = "use created_opt() to preserve unsupported timestamps"
    )]
    pub fn created(&self) -> ForensicTimestamp {
        self.times.created.unwrap_or_else(|| {
            crate::warn!(
                "this filesystem has no support for creation time, using UNIX_EPOCH instead"
            );
            ForensicTimestamp::from_unix_secs(0)
        })
    }
    /// Returns the last-access timestamp, or Unix epoch if unsupported.
    ///
    /// Prefer [`Self::accessed_opt`] to preserve the distinction between an
    /// unsupported timestamp and an actual epoch timestamp.
    #[deprecated(
        since = "0.14.0",
        note = "use accessed_opt() to preserve unsupported timestamps"
    )]
    pub fn accessed(&self) -> ForensicTimestamp {
        self.times.accessed.unwrap_or_else(|| {
            crate::warn!(
                "this filesystem has no support for access time, using UNIX_EPOCH instead"
            );
            ForensicTimestamp::from_unix_secs(0)
        })
    }
    /// Returns the last-modification timestamp, or Unix epoch if unsupported.
    ///
    /// Prefer [`Self::modified_opt`] to preserve the distinction between an
    /// unsupported timestamp and an actual epoch timestamp.
    #[deprecated(
        since = "0.14.0",
        note = "use modified_opt() to preserve unsupported timestamps"
    )]
    pub fn modified(&self) -> ForensicTimestamp {
        self.times.modified.unwrap_or_else(|| {
            crate::warn!(
                "this filesystem has no support for modification time, using UNIX_EPOCH instead"
            );
            ForensicTimestamp::from_unix_secs(0)
        })
    }

    pub fn created_opt(&self) -> Option<&ForensicTimestamp> {
        self.times.created.as_ref()
    }
    pub fn accessed_opt(&self) -> Option<&ForensicTimestamp> {
        self.times.accessed.as_ref()
    }
    pub fn modified_opt(&self) -> Option<&ForensicTimestamp> {
        self.times.modified.as_ref()
    }
    pub fn is_file(&self) -> bool {
        self.file_type == VFileType::File
    }
    pub fn is_dir(&self) -> bool {
        self.file_type == VFileType::Directory
    }
    pub fn is_symlink(&self) -> bool {
        self.file_type == VFileType::Symlink
    }
    pub fn len(&self) -> u64 {
        self.size
    }
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

// ---------------------------------------------------------------------
// RFC 0001 FileSystem redesign.
// ---------------------------------------------------------------------

use crate::core::path::{FPath, FPathBuf};

/// Where a [`FileSystem`]'s data actually comes from. Replaces the old
/// `is_live(): bool`, which couldn't distinguish "this path is absent from
/// the evidence" ([`SourceKind::Image`]) from "this path was never
/// collected" ([`SourceKind::Triage`]) — a distinction analysts need and a
/// bool can't express.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// A running system; artifacts may change while being read.
    Live,
    /// A full disk/volume image; an absent path really means the file
    /// doesn't exist.
    Image,
    /// A KAPE/CyLR-style targeted collection; an absent path may only mean
    /// it wasn't collected, not that it doesn't exist on the source.
    Triage,
    /// Synthesized / in-memory (tests, carved reconstruction).
    Memory,
}

/// Whether two differently-cased paths address the same entry on a given
/// [`FileSystem`]. This is a property of the filesystem being analyzed (an
/// NTFS image is case-insensitive, an ext4 image is case-sensitive), never
/// of the path text — see [`crate::core::path::path_eq`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseSensitivity {
    Sensitive,
    Insensitive,
}

/// An opaque, backend-defined file identifier (an NTFS file reference
/// number, an inode, ...). Two entries with the same [`FileId`] on the same
/// [`FileSystem`] are the same underlying file — used for hardlink/loop
/// detection during [`FileSystemExt::walk`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId(u128);

impl FileId {
    pub fn from_raw(v: u128) -> Self {
        FileId(v)
    }
    pub fn as_u128(&self) -> u128 {
        self.0
    }
}

/// Hand-rolled bitflags for common file attributes (no `bitflags`
/// dependency — same idiom as [`crate::utils::time::TimestampFlags`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileAttributes(u32);

impl FileAttributes {
    // --- bits 0-15: attributes a backend reads off the evidence itself ---
    pub const READONLY: Self = FileAttributes(1 << 0);
    pub const HIDDEN: Self = FileAttributes(1 << 1);
    pub const SYSTEM: Self = FileAttributes(1 << 2);
    pub const DIRECTORY: Self = FileAttributes(1 << 3);
    pub const REPARSE_POINT: Self = FileAttributes(1 << 4);
    pub const COMPRESSED: Self = FileAttributes(1 << 5);
    pub const ENCRYPTED: Self = FileAttributes(1 << 6);
    pub const SPARSE: Self = FileAttributes(1 << 7);

    // --- bits 16+: attributes the framework itself derives, never read off the evidence ---
    /// A registered `FormatFactory` claims this file's bytes, so `read_dir` on it may succeed
    /// (see `crate::core::fs::ContainerFs`, which sets this bit and is the only thing that
    /// should). Advisory only: the bit means a factory's `probe` returned better than
    /// `ProbeScore::No`, not that the mount is guaranteed to succeed -- a truncated or corrupt
    /// container can still fail to mount even though this bit is set. Never set by a backend
    /// reading raw evidence (that's what bits 0-15 are for); a future backend author reaching
    /// for `from_bits_truncate` on real Win32/POSIX attribute bits cannot collide with it.
    pub const CONTAINER: Self = FileAttributes(1 << 16);

    pub const fn empty() -> Self {
        FileAttributes(0)
    }
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    pub const fn bits(self) -> u32 {
        self.0
    }
    pub const fn from_bits_truncate(bits: u32) -> Self {
        FileAttributes(bits)
    }
}

impl std::ops::BitOr for FileAttributes {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        FileAttributes(self.0 | rhs.0)
    }
}
impl std::ops::BitOrAssign for FileAttributes {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// $MACB-style timestamps for a filesystem entry.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MacbTimes {
    pub modified: Option<ForensicTimestamp>,
    pub accessed: Option<ForensicTimestamp>,
    /// `$STANDARD_INFORMATION` change time (MFT metadata change), not
    /// creation.
    pub changed: Option<ForensicTimestamp>,
    pub created: Option<ForensicTimestamp>,
    /// `$FILE_NAME` attribute times, when the backend exposes them
    /// separately from `$STANDARD_INFORMATION`. `$SI`/`$FN` divergence is a
    /// standard timestomping indicator.
    pub filename_times: Option<Box<MacbTimes>>,
}

/// A directory entry yielded by [`FileSystem::read_dir`].
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// The full path of this entry, not just its name — avoids a
    /// `metadata()` round trip to reconstruct the path while walking.
    pub path: FPathBuf,
    pub file_type: VFileType,
    /// Populated opportunistically when the backend gets it for free (e.g.
    /// an NTFS index or `FindFirstFile`); `None` otherwise.
    pub metadata: Option<VMetadata>,
}

impl DirEntry {
    pub fn file_name(&self) -> Option<&str> {
        self.path.file_name()
    }
}

/// Everything a backend must implement. `&self`-based throughout, so
/// `Arc<dyn FileSystem>` can be shared across worker threads — the mechanism
/// that makes parallel image scanning possible (see RFC 0001 §1, P5).
pub trait FileSystem: Send + Sync {
    fn open(&self, path: &FPath) -> ForensicResult<Box<dyn VirtualFile>>;
    fn metadata(&self, path: &FPath) -> ForensicResult<VMetadata>;
    fn read_dir(
        &self,
        path: &FPath,
    ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<DirEntry>> + '_>>;
    fn source(&self) -> SourceKind;

    // --- defaulted: override only if applicable ---
    fn case_sensitivity(&self) -> CaseSensitivity {
        CaseSensitivity::Insensitive
    }
    fn as_streams(&self) -> Option<&dyn AlternateStreams> {
        None
    }
    fn as_unallocated(&self) -> Option<&dyn Unallocated> {
        None
    }
    fn as_attributes(&self) -> Option<&dyn PathAttributes> {
        None
    }
    fn as_media_map(&self) -> Option<&dyn MediaMap> {
        None
    }
}

/// Blanket-impl'd convenience layer over [`FileSystem`]. A backend author
/// never implements this directly.
pub trait FileSystemExt: FileSystem {
    fn read_all(&self, path: &FPath) -> ForensicResult<Vec<u8>> {
        let mut file = self.open(path)?;
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut buf)?;
        Ok(buf)
    }

    fn exists(&self, path: &FPath) -> bool {
        self.metadata(path).is_ok()
    }

    /// Lazy, `&self`-based walk — a real streaming iterator, so a caller can
    /// bail out early on a huge image without enumerating it.
    fn walk(
        &self,
        root: &FPath,
        opts: &crate::core::fs::walk::WalkOptions,
    ) -> crate::core::fs::walk::Walk<'_, Self> {
        crate::core::fs::walk::Walk::new(self, root, opts.clone())
    }

    fn glob(&self, pattern: &str) -> ForensicResult<Vec<FPathBuf>> {
        Ok(self.glob_iter(pattern).collect())
    }

    fn glob_iter(&self, pattern: &str) -> crate::core::fs::glob::Glob<'_, Self> {
        crate::core::fs::glob::Glob::new(self, pattern, self.case_sensitivity())
    }
}
impl<T: FileSystem + ?Sized> FileSystemExt for T {}

/// Alternate Data Streams — a classic hiding place on NTFS. Discovered via
/// [`FileSystem::as_streams`].
pub trait AlternateStreams: FileSystem {
    fn streams(&self, path: &FPath) -> ForensicResult<Vec<StreamInfo>>;
    fn open_stream(&self, path: &FPath, stream: &str) -> ForensicResult<Box<dyn VirtualFile>>;
}

#[derive(Debug, Clone)]
pub struct StreamInfo {
    pub name: String,
    pub size: u64,
}

/// Access to unallocated (deleted, slack) space. Discovered via
/// [`FileSystem::as_unallocated`].
pub trait Unallocated: FileSystem {
    fn unallocated_regions(&self) -> ForensicResult<Vec<Region>>;
    fn open_unallocated(&self, region: &Region) -> ForensicResult<Box<dyn VirtualFile>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub offset: u64,
    pub length: u64,
}

/// Maps a byte in this filesystem back to where it physically lives in the evidence the
/// filesystem was mounted from. Discovered via [`FileSystem::as_media_map`].
///
/// Implemented by filesystems that are *views* over their parent's bytes -- a volume system's
/// partitions, a split image's concatenated segments. A carver that finds a record at offset
/// `x` of partition `/p2` needs this to report where the bytes really are, so a second examiner
/// can seek to them in the original image: call [`to_parent`](MediaMap::to_parent), then repeat
/// on the filesystem that holds the returned locator, until a filesystem has no media map.
pub trait MediaMap: FileSystem {
    /// Where byte `offset` of the file at `path` lives one hop up. `Ok(None)` when that byte
    /// has no single parent location -- past the end of the file, or inside a compressed or
    /// encrypted run whose bytes exist only after decoding.
    fn to_parent(&self, path: &FPath, offset: u64) -> ForensicResult<Option<MediaOffset>>;
}

/// A byte position one hop up: the file that holds it, and the offset inside that file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaOffset {
    pub locator: crate::core::locator::EvidenceLocator,
    pub offset: u64,
}

/// Untyped, uninterpreted facts about one *path*, discovered via
/// [`FileSystem::as_attributes`].
///
/// The per-path counterpart to
/// [`StructuredObject::attributes`](crate::traits::format::StructuredObject::attributes), which
/// is per-*object* rather than per-path. Deliberately the same return shape, so a
/// container-backed filesystem can forward its mounted object's map verbatim with no conversion
/// and no key rewriting -- see that trait's own doc for why core stays uninterpreting here too:
/// a downstream backend (an OLE reader, a PE reader) surfaces facts core neither validates nor
/// interprets (an author name, a compile timestamp, a macro count), namespaced by that
/// backend's own tag (`ole.*`, `pe.*`) so two backends' keys can never collide. Core reserves
/// exactly two namespaces for itself: `fs.*` and `container.*`.
///
/// A key is omitted -- never zero-filled and never [`Field::Null`] -- when the underlying value
/// is unknown or absent; `Field::Null` asserts "this attribute exists and its value is null",
/// a different, stronger claim than "nothing is known about this attribute".
pub trait PathAttributes: FileSystem {
    /// Facts about `path`. An empty map is a valid answer, meaning "this backend has nothing
    /// extra to say about this path" -- it is **not** an error, and callers must not treat it
    /// as one. A path that does not exist must still be an `Err`, exactly as
    /// [`FileSystem::metadata`] would report it, so this method can never be used to probe
    /// existence more cheaply than `metadata` already allows.
    fn attributes(&self, path: &FPath) -> ForensicResult<BTreeMap<Text, Field>>;
}

#[cfg(test)]
mod fs_tests {
    use super::*;
    use crate::core::path::FPathBuf;
    use crate::err::ForensicError;
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::sync::Arc;

    /// Minimal in-file test double proving `FileSystem` is object-safe and
    /// that the `FileSystemExt` blanket impl works end to end. The real
    /// conformance battery (workstream F) exercises the actual backends.
    struct MiniFs {
        files: BTreeMap<String, Vec<u8>>,
    }

    struct MiniFile(Cursor<Vec<u8>>);
    impl std::io::Read for MiniFile {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }
    impl std::io::Seek for MiniFile {
        fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
            self.0.seek(pos)
        }
    }
    impl VirtualFile for MiniFile {
        fn metadata(&self) -> ForensicResult<VMetadata> {
            Ok(VMetadata {
                file_type: VFileType::File,
                size: self.0.get_ref().len() as u64,
                allocated_size: None,
                times: MacbTimes::default(),
                id: None,
                attributes: FileAttributes::empty(),
            })
        }
    }

    impl FileSystem for MiniFs {
        fn open(&self, path: &FPath) -> ForensicResult<Box<dyn VirtualFile>> {
            let bytes = self
                .files
                .get(path.as_str())
                .cloned()
                .ok_or_else(|| ForensicError::path_not_found(path.to_string()))?;
            Ok(Box::new(MiniFile(Cursor::new(bytes))))
        }
        fn metadata(&self, path: &FPath) -> ForensicResult<VMetadata> {
            self.open(path)?.metadata()
        }
        fn read_dir(
            &self,
            path: &FPath,
        ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<DirEntry>> + '_>> {
            let prefix = format!("{}/", path.as_str());
            let entries: Vec<ForensicResult<DirEntry>> = self
                .files
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .map(|k| {
                    Ok(DirEntry {
                        path: FPathBuf::from(k.as_str()),
                        file_type: VFileType::File,
                        metadata: None,
                    })
                })
                .collect();
            Ok(Box::new(entries.into_iter()))
        }
        fn source(&self) -> SourceKind {
            SourceKind::Memory
        }
    }

    fn accepts_dyn_filesystem(_fs: &dyn FileSystem) {}

    #[test]
    fn filesystem_is_object_safe() {
        let fs = MiniFs {
            files: BTreeMap::new(),
        };
        accepts_dyn_filesystem(&fs);
    }

    #[test]
    fn read_all_round_trips_through_ext_trait() {
        let mut files = BTreeMap::new();
        files.insert("a.txt".to_string(), b"hello".to_vec());
        let fs = MiniFs { files };
        assert_eq!(fs.read_all(FPath::new("a.txt")).unwrap(), b"hello");
        assert!(fs.exists(FPath::new("a.txt")));
        assert!(!fs.exists(FPath::new("missing.txt")));
    }

    #[test]
    fn arc_dyn_filesystem_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Arc<dyn FileSystem>>();
    }

    #[test]
    fn missing_timestamps_remain_distinguishable_from_epoch() {
        let metadata = VMetadata {
            file_type: VFileType::File,
            size: 0,
            allocated_size: None,
            times: MacbTimes::default(),
            id: None,
            attributes: FileAttributes::empty(),
        };

        assert!(metadata.created_opt().is_none());
        assert!(metadata.accessed_opt().is_none());
        assert!(metadata.modified_opt().is_none());
    }

    #[test]
    fn container_bit_does_not_collide_with_any_evidence_side_bit() {
        let evidence_bits = FileAttributes::READONLY
            | FileAttributes::HIDDEN
            | FileAttributes::SYSTEM
            | FileAttributes::DIRECTORY
            | FileAttributes::REPARSE_POINT
            | FileAttributes::COMPRESSED
            | FileAttributes::ENCRYPTED
            | FileAttributes::SPARSE;
        assert_eq!(evidence_bits.bits() & FileAttributes::CONTAINER.bits(), 0);
    }

    #[test]
    fn as_attributes_defaults_to_none() {
        let files = BTreeMap::new();
        let fs = MiniFs { files };
        assert!(fs.as_attributes().is_none());
    }
}
