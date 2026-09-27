use std::collections::BTreeMap;
use std::sync::Arc;

use crate::{
    core::path::{Component, FPath, FPathBuf},
    err::ForensicError,
    field::{Field, Text},
    prelude::ForensicResult,
    recovery::{Recovered, RecoveryReport},
    traits::vfs::{
        AlternateStreams, CaseSensitivity, DeletedEntry, DeletedFiles, DirEntry, FileSystem,
        MediaMap, MediaOffset, PathAttributes, Region, SourceKind, StreamInfo, Unallocated,
        VMetadata, VirtualFile,
    },
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

impl ChRootFileSystem {
    /// `inner`, a path in the wrapped filesystem's namespace, in this chroot's namespace, or
    /// `None` when it lies outside the root.
    fn to_outer(&self, inner: &FPath) -> Option<FPathBuf> {
        let insensitive = !matches!(self.fs.case_sensitivity(), CaseSensitivity::Sensitive);
        let normal = |p: &FPath| -> Vec<String> {
            p.components()
                .filter_map(|c| match c {
                    Component::Normal(s) => Some(s.to_string()),
                    _ => None,
                })
                .collect()
        };
        let root = normal(self.path.as_path());
        let path = normal(inner);
        if path.len() < root.len() {
            return None;
        }
        let under_root = root.iter().zip(&path).all(|(r, p)| {
            if insensitive {
                r.eq_ignore_ascii_case(p)
            } else {
                r == p
            }
        });
        under_root.then(|| FPathBuf::from(path[root.len()..].join("/")))
    }
}

fn missing(capability: &str) -> ForensicError {
    ForensicError::other(
        "ChRootFileSystem",
        format!("the wrapped filesystem has no {capability} support"),
    )
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

    // Each capability is claimed only when the wrapped filesystem has it.
    fn as_streams(&self) -> Option<&dyn AlternateStreams> {
        self.fs.as_streams().map(|_| self as &dyn AlternateStreams)
    }

    fn as_unallocated(&self) -> Option<&dyn Unallocated> {
        self.fs.as_unallocated().map(|_| self as &dyn Unallocated)
    }

    fn as_attributes(&self) -> Option<&dyn PathAttributes> {
        self.fs.as_attributes().map(|_| self as &dyn PathAttributes)
    }

    fn as_media_map(&self) -> Option<&dyn MediaMap> {
        self.fs.as_media_map().map(|_| self as &dyn MediaMap)
    }

    fn as_deleted(&self) -> Option<&dyn DeletedFiles> {
        self.fs.as_deleted().map(|_| self as &dyn DeletedFiles)
    }
}

impl AlternateStreams for ChRootFileSystem {
    fn streams(&self, path: &FPath) -> ForensicResult<Vec<StreamInfo>> {
        let inner = self
            .fs
            .as_streams()
            .ok_or_else(|| missing("alternate stream"))?;
        inner.streams(self.resolve(path).as_path())
    }

    fn open_stream(&self, path: &FPath, stream: &str) -> ForensicResult<Box<dyn VirtualFile>> {
        let inner = self
            .fs
            .as_streams()
            .ok_or_else(|| missing("alternate stream"))?;
        inner.open_stream(self.resolve(path).as_path(), stream)
    }
}

/// Free space belongs to the volume, not to a directory, so it passes through unchanged.
impl Unallocated for ChRootFileSystem {
    fn unallocated_regions(&self) -> ForensicResult<Vec<Region>> {
        let inner = self
            .fs
            .as_unallocated()
            .ok_or_else(|| missing("unallocated"))?;
        inner.unallocated_regions()
    }

    fn open_unallocated(&self, region: &Region) -> ForensicResult<Box<dyn VirtualFile>> {
        let inner = self
            .fs
            .as_unallocated()
            .ok_or_else(|| missing("unallocated"))?;
        inner.open_unallocated(region)
    }
}

impl PathAttributes for ChRootFileSystem {
    fn attributes(&self, path: &FPath) -> ForensicResult<BTreeMap<Text, Field>> {
        let inner = self
            .fs
            .as_attributes()
            .ok_or_else(|| missing("attribute"))?;
        inner.attributes(self.resolve(path).as_path())
    }
}

/// The parent location names the evidence the wrapped filesystem was mounted from, which a
/// chroot does not change, so it passes through as is.
impl MediaMap for ChRootFileSystem {
    fn to_parent(&self, path: &FPath, offset: u64) -> ForensicResult<Option<MediaOffset>> {
        let inner = self.fs.as_media_map().ok_or_else(|| missing("media map"))?;
        inner.to_parent(self.resolve(path).as_path(), offset)
    }
}

/// Deleted entries are volume-wide. An entry whose path lies outside the chroot root can't be
/// named in this namespace, so its path becomes `None` (its name is kept); it is not dropped.
impl DeletedFiles for ChRootFileSystem {
    fn deleted_entries(
        &self,
        scope: &FPath,
    ) -> ForensicResult<(Vec<Recovered<DeletedEntry>>, RecoveryReport)> {
        let inner = self
            .fs
            .as_deleted()
            .ok_or_else(|| missing("deleted-file"))?;
        let (entries, report) = inner.deleted_entries(self.resolve(scope).as_path())?;
        let entries = entries
            .into_iter()
            .map(|r| {
                r.map(|mut e| {
                    if let Some(p) = e.path.take() {
                        e.path = self.to_outer(p.as_path());
                        if e.path.is_none() && e.name.is_none() {
                            e.name = p.file_name().map(str::to_string);
                        }
                    }
                    e
                })
            })
            .collect();
        Ok((entries, report))
    }

    fn open_deleted(
        &self,
        scope: &FPath,
        id: u64,
    ) -> ForensicResult<Recovered<Box<dyn VirtualFile>>> {
        let inner = self
            .fs
            .as_deleted()
            .ok_or_else(|| missing("deleted-file"))?;
        inner.open_deleted(self.resolve(scope).as_path(), id)
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

    #[test]
    fn capabilities_are_forwarded_only_when_the_wrapped_fs_has_them() {
        use crate::utils::testing::InMemoryVirtualFileSystem;
        let plain = ChRootFileSystem::new("vol", Arc::new(InMemoryVirtualFileSystem::new()));
        assert!(plain.as_streams().is_none());
        assert!(plain.as_unallocated().is_none());
        assert!(plain.as_attributes().is_none());
        assert!(plain.as_media_map().is_none());
        assert!(plain.as_deleted().is_none());
    }

    #[test]
    fn capabilities_are_forwarded_with_chroot_paths() {
        use crate::core::fs::capable_test_fs::CapableFs;
        use crate::core::locator::{EvidenceLocator, LocatorSegment};
        use crate::utils::testing::InMemoryVirtualFileSystem;
        let inner = InMemoryVirtualFileSystem::new()
            .with_text_file("vol/docs/a.txt", "hello")
            .with_text_file("vol/docs/a.txt:ads", "xyz");
        let chrfs = ChRootFileSystem::new("vol", Arc::new(CapableFs::new(inner)));
        let a = FPath::new("C:\\docs\\a.txt");

        let streams = chrfs.as_streams().unwrap();
        let listed = streams.streams(a).unwrap();
        assert_eq!((listed[0].name.as_str(), listed[0].size), ("ads", 3));
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut streams.open_stream(a, "ads").unwrap(), &mut buf)
            .unwrap();
        assert_eq!(buf, "xyz");

        let attrs = chrfs.as_attributes().unwrap().attributes(a).unwrap();
        assert_eq!(
            attrs.get("capable.path"),
            Some(&Field::Text(Text::Owned("vol/docs/a.txt".into())))
        );

        let parent = chrfs
            .as_media_map()
            .unwrap()
            .to_parent(a, 5)
            .unwrap()
            .unwrap();
        assert_eq!(
            parent.locator,
            EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from("media.bin")))
        );
        assert_eq!(parent.offset, 1005);

        let regions = chrfs
            .as_unallocated()
            .unwrap()
            .unallocated_regions()
            .unwrap();
        assert_eq!(
            regions,
            vec![Region {
                offset: 4096,
                length: 512
            }]
        );

        let deleted = chrfs.as_deleted().unwrap();
        let (entries, _report) = deleted.deleted_entries(FPath::new("")).unwrap();
        let paths: Vec<_> = entries
            .iter()
            .map(|r| r.value().path.as_ref().map(|p| p.to_string()))
            .collect();
        assert_eq!(paths, vec![Some("deleted/gone.txt".to_string()), None]);
        let mut buf = String::new();
        std::io::Read::read_to_string(
            &mut deleted
                .open_deleted(FPath::new(""), 7)
                .unwrap()
                .into_value(),
            &mut buf,
        )
        .unwrap();
        assert_eq!(buf, "gone");
    }

    #[test]
    fn a_deleted_path_outside_the_root_is_not_named_in_the_chroot() {
        use crate::utils::testing::InMemoryVirtualFileSystem;
        let chrfs = ChRootFileSystem::new("vol/sub", Arc::new(InMemoryVirtualFileSystem::new()));
        assert_eq!(
            chrfs.to_outer(FPath::new("VOL/sub/x.txt")),
            Some(FPathBuf::from("x.txt"))
        );
        assert_eq!(chrfs.to_outer(FPath::new("vol/other/x.txt")), None);
        assert_eq!(chrfs.to_outer(FPath::new("vol")), None);
    }
}
