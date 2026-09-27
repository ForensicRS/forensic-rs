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
    /// `self.path`.
    ///
    /// A drive marker embedded mid-path is dropped too: a segment that is
    /// exactly `X:` goes away, and a single trailing `:` is trimmed (a
    /// mistakenly doubled `Windows:\System32`). A colon *inside* a segment
    /// is kept, because it is meaningful: NTFS alternate data streams are
    /// named `file:stream` (`$Extend\$UsnJrnl:$J`).
    fn resolve(&self, path: &FPath) -> FPathBuf {
        let mut child = FPathBuf::new();
        for comp in path.components() {
            if let Component::Normal(s) = comp {
                if is_drive_marker(s) {
                    continue;
                }
                let cleaned = s.strip_suffix(':').unwrap_or(s);
                if !cleaned.trim().is_empty() {
                    child.push(cleaned);
                }
            }
        }
        self.path.join(child.as_str())
    }
}

/// `X:` exactly — a drive designator that did not come first in the path.
fn is_drive_marker(segment: &str) -> bool {
    let b = segment.as_bytes();
    b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
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
        // The inner fs returns each entry's path in *its own* namespace (rooted at
        // `self.path`, not at the chroot's apparent root) -- every caller of `read_dir`
        // (`Walk`, `ContainerFs`, a plain `for entry in fs.read_dir(...)` loop) expects the
        // path it gets back to be directly usable as-is against this same `FileSystem`, so it
        // must be rewritten back into the outer, chroot-relative namespace before being
        // yielded. Only the leaf name is taken from the inner entry and rejoined onto the
        // caller's own `path` -- `read_dir` only ever returns immediate children, so this is
        // exact, not an approximation.
        let outer_prefix = path.as_str().to_string();
        let iter = self.fs.read_dir(self.resolve(path).as_path())?;
        Ok(Box::new(iter.map(move |entry| {
            entry.map(|mut e| {
                let leaf = e
                    .path
                    .as_str()
                    .rsplit(['/', '\\'])
                    .next()
                    .unwrap_or(e.path.as_str())
                    .to_string();
                e.path = if outer_prefix.is_empty() {
                    FPathBuf::from(leaf)
                } else {
                    FPathBuf::from(format!("{outer_prefix}/{leaf}"))
                };
                e
            })
        })))
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

    #[test]
    fn read_dir_returns_paths_in_the_chroot_s_own_namespace_not_the_inner_fs_s() {
        // `read_dir`'s entries must be directly usable as further calls against the *same*
        // `ChRootFileSystem` (open/metadata/read_dir again) -- if they still carried the
        // inner fs's own-rooted path (`<tmp>/subdir/file.txt` instead of `subdir/file.txt`),
        // every caller that walks a chroot (`Walk`, `ContainerFs`, a bare `for` loop) would
        // silently fail to resolve what `read_dir` itself just handed back.
        let root = std::env::temp_dir().join(format!(
            "forensic_rs_stdfs_chroot_read_dir_rewrite_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(root.join("subdir")).unwrap();
        std::fs::write(root.join("subdir").join("leaf.txt"), CONTENT).unwrap();

        let chrfs = ChRootFileSystem::new(
            root.to_string_lossy().into_owned(),
            Arc::new(StdVirtualFS::new()),
        );

        let root_entries: Vec<_> = FileSystem::read_dir(&chrfs, FPath::new(""))
            .unwrap()
            .map(|e| e.unwrap().path.to_string())
            .collect();
        assert_eq!(root_entries, vec!["subdir".to_string()]);

        let sub_entries: Vec<_> = FileSystem::read_dir(&chrfs, FPath::new("subdir"))
            .unwrap()
            .map(|e| e.unwrap().path.to_string())
            .collect();
        assert_eq!(sub_entries, vec!["subdir/leaf.txt".to_string()]);

        // And the returned path must be directly usable against this same filesystem.
        assert_eq!(
            chrfs.read_all(FPath::new(&sub_entries[0])).unwrap(),
            CONTENT.as_bytes()
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn colons_inside_segments_are_kept_so_ads_paths_resolve() {
        use crate::utils::testing::InMemoryVirtualFileSystem;
        let inner = InMemoryVirtualFileSystem::new()
            .with_text_file("evidence/$Extend/$UsnJrnl:$J", CONTENT)
            .with_text_file("evidence/Windows/System32/cmd.exe", CONTENT)
            .with_text_file("outside.txt", CONTENT);
        let chrfs = ChRootFileSystem::new("evidence", Arc::new(inner));
        assert_eq!(
            chrfs.read_all(FPath::new("$Extend\\$UsnJrnl:$J")).unwrap(),
            CONTENT.as_bytes()
        );
        assert_eq!(
            chrfs
                .read_all(FPath::new("C:\\$Extend\\$UsnJrnl:$J"))
                .unwrap(),
            CONTENT.as_bytes()
        );
        // Drive markers are still dropped, first or embedded, and a trailing ':' is trimmed.
        assert!(chrfs.exists(FPath::new("C:\\Windows\\System32\\cmd.exe")));
        assert!(chrfs.exists(FPath::new("Windows\\C:\\System32\\cmd.exe")));
        assert!(chrfs.exists(FPath::new("Windows:\\System32\\cmd.exe")));
        // Confinement is unchanged.
        assert!(!chrfs.exists(FPath::new("..\\outside.txt")));
        assert!(!chrfs.exists(FPath::new("C:\\..\\outside.txt")));
    }
}
