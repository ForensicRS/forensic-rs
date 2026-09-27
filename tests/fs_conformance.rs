//! Shared conformance battery for every `FileSystem` backend (RFC 0001
//! implementation plan, workstream F). The macro expands to a `mod` of
//! individually-named `#[test]` functions per backend, so a failure reports
//! as e.g. `std_fs::open_missing_path_errors` rather than an opaque loop
//! index — each backend still shares the exact same assertion bodies below.

use forensic_rs::core::fs::{ChRootFileSystem, ContainerFs, StdVirtualFS};
use forensic_rs::core::path::FPath;
use forensic_rs::core::resolver::MountResolver;
use forensic_rs::traits::vfs::{FileSystem, FileSystemExt, VFileType};
use forensic_rs::utils::testing::InMemoryVirtualFileSystem;
use std::sync::Arc;

/// A fixture tree shared by every backend's assertions:
/// - `a.txt` -> `b"hello"`
/// - `dir/b.txt` -> `b"world"`
/// - `dir/empty_dir/` (present, but has no entries)
/// - `empty.txt` -> `b""`
fn seed(fs: &mut InMemoryVirtualFileSystem) {
    fs.add_file("a.txt", b"hello".to_vec());
    fs.add_file("dir/b.txt", b"world".to_vec());
    fs.add_file("dir/empty_dir/.keep", b"".to_vec());
    fs.add_file("empty.txt", b"".to_vec());
}

fn in_memory_fixture() -> Arc<dyn FileSystem> {
    let mut fs = InMemoryVirtualFileSystem::new();
    seed(&mut fs);
    Arc::new(fs)
}

/// `ContainerFs` wrapping the same in-memory fixture, with an empty resolver (no `FormatFactory`
/// registered -- there is nothing in this fixture that looks like a container anyway). This is
/// the regression proof that `ContainerFs` is a fully conformant, transparent `FileSystem` when
/// there is nothing to descend into: every assertion below must pass completely unchanged,
/// including `read_dir_on_a_file_errors` (a non-container file has no boundary to find).
fn container_fs_fixture() -> Arc<dyn FileSystem> {
    let mut fs = InMemoryVirtualFileSystem::new();
    seed(&mut fs);
    let resolver = Arc::new(MountResolver::builder().build());
    Arc::new(ContainerFs::new(Arc::new(fs), resolver))
}

/// `StdVirtualFS` rooted (via `ChRootFileSystem`) at a real temp directory
/// seeded with the same fixture tree, so the exact same assertions apply.
fn std_fs_fixture() -> (Arc<dyn FileSystem>, tempdir::TempDir) {
    let dir = tempdir::TempDir::new("fs_conformance");
    std::fs::write(dir.path().join("a.txt"), b"hello").unwrap();
    std::fs::create_dir_all(dir.path().join("dir/empty_dir")).unwrap();
    std::fs::write(dir.path().join("dir/b.txt"), b"world").unwrap();
    std::fs::write(dir.path().join("empty.txt"), b"").unwrap();
    (Arc::new(StdVirtualFS::new()), dir)
}

mod tempdir {
    //! Minimal `TempDir` — this crate is dependency-free, so hand-roll the
    //! tiny bit of temp-directory-with-cleanup logic rather than pull in a
    //! crate for it.
    use std::path::{Path, PathBuf};

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new(prefix: &str) -> Self {
            let mut counter = 0u64;
            loop {
                let candidate = std::env::temp_dir().join(format!(
                    "{prefix}-{}-{}",
                    std::process::id(),
                    counter
                ));
                if std::fs::create_dir(&candidate).is_ok() {
                    return TempDir(candidate);
                }
                counter += 1;
            }
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

// The shared assertions live in `forensic_rs::utils::testing::conformance`, so downstream
// backends run the same battery through `forensic_rs::fs_conformance_battery!`.

forensic_rs::fs_conformance_battery!(in_memory_fs, in_memory_fixture());
forensic_rs::fs_conformance_battery!(container_fs, container_fs_fixture());

mod std_fs {
    use super::*;

    /// `ChRootFileSystem`'s `FileSystem` impl lands in workstream E, so
    /// this battery runs directly against `StdVirtualFS`'s own new-trait
    /// impl using absolute paths built from a real temp directory, rather
    /// than through a chroot-relative view.
    fn fixture() -> (Arc<dyn FileSystem>, super::tempdir::TempDir, String) {
        let (fs, dir) = super::std_fs_fixture();
        let root = dir.path().to_string_lossy().into_owned();
        (fs, dir, root)
    }

    fn full(root: &str, rel: &str) -> forensic_rs::core::path::FPathBuf {
        forensic_rs::core::path::FPathBuf::from(root).join(rel)
    }

    #[test]
    fn open_and_read_existing_file_test() {
        let (fs, _dir, root) = fixture();
        assert_eq!(
            fs.read_all(full(&root, "a.txt").as_path()).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn open_missing_path_errors_test() {
        let (fs, _dir, root) = fixture();
        assert!(fs.open(full(&root, "nope.txt").as_path()).is_err());
    }

    #[test]
    fn read_dir_lists_expected_entries_test() {
        let (fs, _dir, root) = fixture();
        let names: std::collections::BTreeSet<String> = fs
            .read_dir(full(&root, "dir").as_path())
            .unwrap()
            .filter_map(|e| e.ok().and_then(|e| e.file_name().map(str::to_string)))
            .collect();
        assert!(names.contains("b.txt"));
    }

    #[test]
    fn read_dir_on_a_file_errors_test() {
        let (fs, _dir, root) = fixture();
        assert!(fs.read_dir(full(&root, "a.txt").as_path()).is_err());
    }

    #[test]
    fn metadata_reports_correct_size_and_type_test() {
        let (fs, _dir, root) = fixture();
        let m = fs.metadata(full(&root, "a.txt").as_path()).unwrap();
        assert_eq!(m.size, 5);
        assert_eq!(m.file_type, VFileType::File);
    }

    #[test]
    fn zero_byte_file_reads_as_empty_not_error_test() {
        let (fs, _dir, root) = fixture();
        assert_eq!(
            fs.read_all(full(&root, "empty.txt").as_path()).unwrap(),
            b""
        );
    }

    #[test]
    fn exists_true_for_present_false_for_absent_test() {
        let (fs, _dir, root) = fixture();
        assert!(fs.exists(full(&root, "a.txt").as_path()));
        assert!(!fs.exists(full(&root, "nope.txt").as_path()));
    }

    #[test]
    fn send_sync_bound_holds_test() {
        let (fs, _dir, _root) = fixture();
        forensic_rs::utils::testing::conformance::send_sync_bound_holds(fs);
    }
}

#[test]
fn chroot_confines_dotdot_escape_attempts() {
    // Security-relevant: a `..`-escape attempt against a rooted backend must
    // stay confined to the virtual root, not leak to the real filesystem
    // outside it. `ChRootFileSystem` drops `..`/root/drive components
    // entirely rather than resolving them against the host filesystem, so
    // an attempted escape can never leave the chroot root.
    let dir = tempdir::TempDir::new("fs_conformance_chroot");
    std::fs::write(dir.path().join("secret.txt"), b"inside").unwrap();

    let root = dir.path().to_string_lossy().into_owned();
    let chrfs = ChRootFileSystem::new(root, Arc::new(StdVirtualFS::new()));
    let escape_attempt = FPath::new("../../../../etc/passwd");
    assert!(!chrfs.exists(escape_attempt) && chrfs.read_all(escape_attempt).is_err());
}
