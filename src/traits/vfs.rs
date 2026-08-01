use std::{fmt::Display, path::Path};

use crate::err::ForensicResult;
use crate::utils::time::ForensicTimestamp;

pub trait VirtualFile: std::io::Seek + std::io::Read {
    fn metadata(&self) -> ForensicResult<VMetadata>;
}

#[allow(clippy::wrong_self_convention)]
pub trait VirtualFileSystem {
    /// Initializes a virtual filesystem from a file. Ex: a Zip FS from a file
    fn from_file(&self, file: Box<dyn VirtualFile>) -> ForensicResult<Box<dyn VirtualFileSystem>>;
    /// Initializes a virtual filesystem from a filesyste. Ex: a remapping of windows routes to Linux routes.
    fn from_fs(&self, fs: Box<dyn VirtualFileSystem>)
        -> ForensicResult<Box<dyn VirtualFileSystem>>;
    /// Read the entire contents of a file into a string.
    fn read_to_string(&mut self, path: &Path) -> ForensicResult<String>;
    /// Read the entire contents of a file into a bytes vector.
    fn read_all(&mut self, path: &Path) -> ForensicResult<Vec<u8>>;
    /// Read part of the content of a file into a bytes vector.
    fn read(&mut self, path: &Path, pos: u64, buf: &mut [u8]) -> ForensicResult<usize>;
    /// Get the metadata of a file/dir
    fn metadata(&mut self, path: &Path) -> ForensicResult<VMetadata>;
    /// Lists the contents of a Directory
    fn read_dir(&mut self, path: &Path) -> ForensicResult<Vec<VDirEntry>>;
    /// Visits directory entries one at a time.
    ///
    /// Implementations can override this method to avoid materializing a full
    /// directory listing. Returning an error from `visitor` stops enumeration
    /// and propagates that error to the caller.
    fn visit_dir(
        &mut self,
        path: &Path,
        visitor: &mut dyn FnMut(&VDirEntry) -> ForensicResult<()>,
    ) -> ForensicResult<()> {
        for entry in self.read_dir(path)? {
            visitor(&entry)?;
        }
        Ok(())
    }
    /// Check if the VirtualFileSystem is an abstraction over the real filesystem and not a virtual (like a ZIP file).
    fn is_live(&self) -> bool;
    /// Open a file
    fn open(&mut self, path: &Path) -> ForensicResult<Box<dyn VirtualFile>>;
    /// Allows duplicating the existing file system
    fn duplicate(&self) -> Box<dyn VirtualFileSystem>;
    /// Check if a file exists
    #[allow(unused_variables)]
    fn exists(&self, path: &Path) -> bool {
        false
    }
}

impl dyn VirtualFileSystem {
    /// Read the entire contents of a file into a string.
    pub fn read_to_string_path<P: AsRef<Path>>(&mut self, path: P) -> ForensicResult<String> {
        self.read_to_string(path.as_ref())
    }

    /// Read the entire contents of a file into a bytes vector.
    pub fn read_all_path<P: AsRef<Path>>(&mut self, path: P) -> ForensicResult<Vec<u8>> {
        self.read_all(path.as_ref())
    }

    /// Read part of the content of a file into a mutable byte slice
    pub fn read_path<P: AsRef<Path>>(
        &mut self,
        path: P,
        pos: u64,
        buf: &mut [u8],
    ) -> ForensicResult<usize> {
        self.read(path.as_ref(), pos, buf)
    }

    /// Get the metadata of a file/dir
    pub fn metadata_path<P: AsRef<Path>>(&mut self, path: P) -> ForensicResult<VMetadata> {
        self.metadata(path.as_ref())
    }

    /// Lists the contents of a Directory
    pub fn read_dir_path<P: AsRef<Path>>(&mut self, path: P) -> ForensicResult<Vec<VDirEntry>> {
        self.read_dir(path.as_ref())
    }

    /// Open a file
    pub fn open_path<P: AsRef<Path>>(&mut self, path: P) -> ForensicResult<Box<dyn VirtualFile>> {
        self.open(path.as_ref())
    }

    /// Check if a file exists
    pub fn exists_path<P: AsRef<Path>>(&mut self, path: P) -> ForensicResult<bool> {
        Ok(self.exists(path.as_ref()))
    }

    /// Recursively walk a directory tree, ignoring errors below `root`.
    ///
    /// This legacy convenience method is best-effort: it returns an error when
    /// `root` cannot be enumerated, but continues when a descendant directory
    /// cannot be read. Use [`Self::walk_dir_strict`] when every inaccessible
    /// descendant must be reported to the caller.
    pub fn walk_dir(
        &mut self,
        root: &Path,
        visitor: &mut dyn FnMut(&Path, &VDirEntry),
    ) -> ForensicResult<()> {
        self.walk_dir_best_effort(root, visitor)
    }

    /// Recursively walk a directory tree, ignoring errors below `root`.
    ///
    /// The visitor receives the full path of each entry found. This is useful
    /// for exploratory interfaces where partial results are acceptable.
    pub fn walk_dir_best_effort(
        &mut self,
        root: &Path,
        visitor: &mut dyn FnMut(&Path, &VDirEntry),
    ) -> ForensicResult<()> {
        let entries = self.read_dir(root)?;
        for entry in &entries {
            let child = root.join(entry.to_string());
            visitor(&child, entry);
            if matches!(entry, VDirEntry::Directory(_)) {
                let _ = self.walk_dir_best_effort(&child, visitor);
            }
        }
        Ok(())
    }

    /// Recursively walk a directory tree, propagating every enumeration error.
    ///
    /// The visitor receives the full path of each entry found. Use this mode
    /// when an unreadable descendant must remain distinguishable from an empty
    /// directory in forensic output.
    pub fn walk_dir_strict(
        &mut self,
        root: &Path,
        visitor: &mut dyn FnMut(&Path, &VDirEntry),
    ) -> ForensicResult<()> {
        let entries = self.read_dir(root)?;
        for entry in &entries {
            let child = root.join(entry.to_string());
            visitor(&child, entry);
            if matches!(entry, VDirEntry::Directory(_)) {
                self.walk_dir_strict(&child, visitor)?;
            }
        }
        Ok(())
    }
}

pub struct VMetadata {
    /// Creation timestamp (optional — some filesystems don't support it)
    pub created: Option<ForensicTimestamp>,

    /// Last access timestamp (optional — some filesystems don't support it)
    pub accessed: Option<ForensicTimestamp>,

    /// Last modification timestamp (optional — some filesystems don't support it)
    pub modified: Option<ForensicTimestamp>,

    pub file_type: VFileType,
    pub size: u64,
}

#[derive(PartialEq)]
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
        self.created.unwrap_or_else(|| {
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
        self.accessed.unwrap_or_else(|| {
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
        self.modified.unwrap_or_else(|| {
            crate::warn!(
                "this filesystem has no support for modification time, using UNIX_EPOCH instead"
            );
            ForensicTimestamp::from_unix_secs(0)
        })
    }

    pub fn created_opt(&self) -> Option<&ForensicTimestamp> {
        self.created.as_ref()
    }
    pub fn accessed_opt(&self) -> Option<&ForensicTimestamp> {
        self.accessed.as_ref()
    }
    pub fn modified_opt(&self) -> Option<&ForensicTimestamp> {
        self.modified.as_ref()
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

pub enum VDirEntry {
    Directory(String),
    File(String),
    Symlink(String),
}

impl Display for VDirEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let content = match self {
            VDirEntry::Directory(v) => v,
            VDirEntry::File(v) => v,
            VDirEntry::Symlink(v) => v,
        };
        write!(f, "{}", content)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::err::{ForensicError, ForensicResult};

    use super::{VDirEntry, VMetadata, VirtualFile, VirtualFileSystem};

    struct TraversalFs;

    impl VirtualFileSystem for TraversalFs {
        fn from_file(
            &self,
            _file: Box<dyn VirtualFile>,
        ) -> ForensicResult<Box<dyn VirtualFileSystem>> {
            Err(ForensicError::other("test", "not implemented".to_string()))
        }

        fn from_fs(
            &self,
            _fs: Box<dyn VirtualFileSystem>,
        ) -> ForensicResult<Box<dyn VirtualFileSystem>> {
            Err(ForensicError::other("test", "not implemented".to_string()))
        }

        fn read_to_string(&mut self, _path: &Path) -> ForensicResult<String> {
            Err(ForensicError::other("test", "not implemented".to_string()))
        }

        fn read_all(&mut self, _path: &Path) -> ForensicResult<Vec<u8>> {
            Err(ForensicError::other("test", "not implemented".to_string()))
        }

        fn read(&mut self, _path: &Path, _pos: u64, _buf: &mut [u8]) -> ForensicResult<usize> {
            Err(ForensicError::other("test", "not implemented".to_string()))
        }

        fn metadata(&mut self, _path: &Path) -> ForensicResult<VMetadata> {
            Err(ForensicError::other("test", "not implemented".to_string()))
        }

        fn read_dir(&mut self, path: &Path) -> ForensicResult<Vec<VDirEntry>> {
            match path.to_string_lossy().as_ref() {
                "root" => Ok(vec![VDirEntry::Directory("denied".to_string())]),
                "root\\denied" | "root/denied" => {
                    Err(ForensicError::other("test", "access denied".to_string()))
                }
                _ => Err(ForensicError::other("test", "unexpected path".to_string())),
            }
        }

        fn is_live(&self) -> bool {
            false
        }

        fn open(&mut self, _path: &Path) -> ForensicResult<Box<dyn VirtualFile>> {
            Err(ForensicError::other("test", "not implemented".to_string()))
        }

        fn duplicate(&self) -> Box<dyn VirtualFileSystem> {
            Box::new(TraversalFs)
        }
    }

    #[test]
    fn best_effort_walk_ignores_descendant_errors() {
        let mut fs = TraversalFs;
        let mut entries = Vec::new();
        let fs: &mut dyn VirtualFileSystem = &mut fs;

        fs.walk_dir_best_effort(Path::new("root"), &mut |path, _| {
            entries.push(path.to_path_buf())
        })
        .unwrap();

        assert_eq!(entries, vec![Path::new("root").join("denied")]);
    }

    #[test]
    fn strict_walk_propagates_descendant_errors() {
        let mut fs = TraversalFs;
        let fs: &mut dyn VirtualFileSystem = &mut fs;

        assert!(fs
            .walk_dir_strict(Path::new("root"), &mut |_, _| {})
            .is_err());
    }

    #[test]
    fn missing_timestamps_remain_distinguishable_from_epoch() {
        let metadata = VMetadata {
            created: None,
            accessed: None,
            modified: None,
            file_type: super::VFileType::File,
            size: 0,
        };

        assert!(metadata.created_opt().is_none());
        assert!(metadata.accessed_opt().is_none());
        assert!(metadata.modified_opt().is_none());
    }
}
