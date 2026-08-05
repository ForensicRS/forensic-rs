use std::sync::Arc;

use crate::{
    core::path::{Component, FPath, FPathBuf},
    prelude::ForensicResult,
    traits::vfs::{CaseSensitivity, DirEntry, FileSystem, SourceKind, VMetadata, VirtualFile},
};

/// Changes the apparent root directory of the underlying filesystem, like
/// `chroot` on Unix.
///
/// Only implements the new [`FileSystem`] trait — this struct was migrated
/// as part of the RFC 0001 consumer ripple (workstream E), since as a
/// compositional wrapper it could not cleanly hold both an old
/// `Box<dyn VirtualFileSystem>` and a new `Arc<dyn FileSystem>` inner value
/// at once.
pub struct ChRootFileSystem {
    path: FPathBuf,
    fs: Arc<dyn FileSystem>,
}
impl ChRootFileSystem {
    /// Creates a new ChRoot file system
    ///
    /// ```
    /// use forensic_rs::prelude::*;
    /// use std::sync::Arc;
    /// let chrfs = ChRootFileSystem::new("C:\\", Arc::new(StdVirtualFS::new()));
    /// let exists_c_windows = chrfs.exists(FPath::new("Windows"));
    /// ```
    pub fn new<P>(path: P, fs: Arc<dyn FileSystem>) -> Self
    where
        P: Into<FPathBuf>,
    {
        Self {
            path: path.into(),
            fs,
        }
    }

    /// Resolves `path` (evidence-relative, possibly absolute-looking)
    /// against the chroot's root. Every component that would escape or
    /// bypass the root (`RootDir`, a drive designator, `.`, `..`) is
    /// dropped rather than honored — a lookup can never resolve outside
    /// `self.path`. `':'` inside a segment is also stripped, so a
    /// Windows-style drive marker embedded mid-path (e.g. a mistakenly
    /// doubled `Windows:\System32`) doesn't produce a stray colon.
    fn resolve(&self, path: &FPath) -> FPathBuf {
        let mut child = FPathBuf::new();
        for comp in path.components() {
            if let Component::Normal(s) = comp {
                let cleaned = s.replace(':', "");
                if !cleaned.trim().is_empty() {
                    child.push(cleaned);
                }
            }
        }
        self.path.join(child.as_str())
    }
}

impl FileSystem for ChRootFileSystem {
    fn open(&self, path: &FPath) -> ForensicResult<Box<dyn VirtualFile>> {
        self.fs.open(self.resolve(path).as_path())
    }

    fn metadata(&self, path: &FPath) -> ForensicResult<VMetadata> {
        self.fs.metadata(self.resolve(path).as_path())
    }

    fn read_dir(
        &self,
        path: &FPath,
    ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<DirEntry>> + '_>> {
        self.fs.read_dir(self.resolve(path).as_path())
    }

    fn source(&self) -> SourceKind {
        self.fs.source()
    }

    fn case_sensitivity(&self) -> CaseSensitivity {
        self.fs.case_sensitivity()
    }
}

#[cfg(test)]
mod tst {
    use crate::core::fs::StdVirtualFS;
    use crate::core::path::FPath;
    use crate::traits::vfs::FileSystemExt;
    use std::io::Write;
    use std::sync::Arc;

    use super::*;

    const CONTENT: &str = "File_Content_Of_VFS";
    const FILE_NAME: &str = "test_chrfs_file.txt";

    #[test]
    fn test_temp_file() {
        let tmp = std::env::temp_dir();
        let tmp_file = tmp.join(FILE_NAME);
        let mut file = std::fs::File::create(&tmp_file).unwrap();
        file.write_all(CONTENT.as_bytes()).unwrap();
        drop(file);

        let std_vfs = StdVirtualFS::new();
        // CHRoot over tmp folder
        let tmp_str = tmp.to_string_lossy().into_owned();
        let chrfs = ChRootFileSystem::new(tmp_str, Arc::new(std_vfs));
        assert_eq!(
            chrfs.read_all(FPath::new(FILE_NAME)).unwrap(),
            CONTENT.as_bytes()
        );
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn should_exists_c_windows() {
        let chrfs = ChRootFileSystem::new("C:\\", Arc::new(StdVirtualFS::new()));
        assert!(chrfs.exists(FPath::new("Windows")));
        let chrfs = ChRootFileSystem::new("C:\\", Arc::new(StdVirtualFS::new()));
        assert!(chrfs.exists(FPath::new("Windows:\\System32")));
        // This will be normalized into C:\Windows\System32
    }

    #[test]
    fn dotdot_escape_attempts_stay_confined_to_root() {
        const ESCAPE_TEST_FILE_NAME: &str = "test_chrfs_escape_file.txt";
        let tmp = std::env::temp_dir();
        let tmp_file = tmp.join(ESCAPE_TEST_FILE_NAME);
        let mut file = std::fs::File::create(&tmp_file).unwrap();
        file.write_all(CONTENT.as_bytes()).unwrap();
        drop(file);

        let tmp_str = tmp.to_string_lossy().into_owned();
        let chrfs = ChRootFileSystem::new(tmp_str, Arc::new(StdVirtualFS::new()));
        // `..` components are dropped entirely, not resolved against the
        // host filesystem, so this can never escape the chroot root.
        assert!(!chrfs.exists(FPath::new("../../../../etc/passwd")));
        // An absolute-looking lookup is still confined to the root: its
        // root/drive component is dropped, leaving a plain relative lookup.
        assert_eq!(
            chrfs
                .read_all(FPath::new(&format!("/{ESCAPE_TEST_FILE_NAME}")))
                .unwrap(),
            CONTENT.as_bytes()
        );
    }
}
