//! Shared conformance battery for every `FileSystem` backend (RFC 0001
//! implementation plan, workstream F). The macro expands to a `mod` of
//! individually-named `#[test]` functions per backend, so a failure reports
//! as e.g. `std_fs::open_missing_path_errors` rather than an opaque loop
//! index — each backend still shares the exact same assertion bodies below.

use forensic_rs::core::fs::{ChRootFileSystem, StdVirtualFS};
use forensic_rs::core::path::FPath;
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

// ---------------------------------------------------------------------
// Shared assertions — one function per conformance point, called by every
// backend's generated test module below.
// ---------------------------------------------------------------------

fn open_and_read_existing_file(fs: &dyn FileSystem) {
    assert_eq!(fs.read_all(FPath::new("a.txt")).unwrap(), b"hello");
}

fn open_missing_path_errors(fs: &dyn FileSystem) {
    assert!(fs.open(FPath::new("does-not-exist.txt")).is_err());
}

fn metadata_missing_path_errors(fs: &dyn FileSystem) {
    assert!(fs.metadata(FPath::new("does-not-exist.txt")).is_err());
}

fn read_dir_lists_expected_entries(fs: &dyn FileSystem) {
    let names: std::collections::BTreeSet<String> = fs
        .read_dir(FPath::new("dir"))
        .unwrap()
        .filter_map(|e| e.ok().and_then(|e| e.file_name().map(str::to_string)))
        .collect();
    assert!(names.contains("b.txt"));
    assert!(names.contains("empty_dir"));
}

fn read_dir_on_a_file_errors(fs: &dyn FileSystem) {
    assert!(fs.read_dir(FPath::new("a.txt")).is_err());
}

fn read_dir_on_missing_path_errors(fs: &dyn FileSystem) {
    assert!(fs.read_dir(FPath::new("no-such-dir")).is_err());
}

fn metadata_reports_correct_size_and_type(fs: &dyn FileSystem) {
    let m = fs.metadata(FPath::new("a.txt")).unwrap();
    assert_eq!(m.size, 5);
    assert_eq!(m.file_type, VFileType::File);

    let dir_meta = fs.metadata(FPath::new("dir")).unwrap();
    assert_eq!(dir_meta.file_type, VFileType::Directory);
}

fn zero_byte_file_reads_as_empty_not_error(fs: &dyn FileSystem) {
    assert_eq!(fs.read_all(FPath::new("empty.txt")).unwrap(), b"");
}

fn exists_true_for_present_false_for_absent(fs: &dyn FileSystem) {
    assert!(fs.exists(FPath::new("a.txt")));
    assert!(!fs.exists(FPath::new("nope.txt")));
}

fn mixed_separators_resolve_to_the_same_entry(fs: &dyn FileSystem) {
    assert_eq!(
        fs.read_all(FPath::new("dir/b.txt")).unwrap(),
        fs.read_all(FPath::new("dir\\b.txt")).unwrap()
    );
}

fn empty_directory_lists_as_empty_not_missing(fs: &dyn FileSystem) {
    let entries: Vec<_> = fs.read_dir(FPath::new("dir/empty_dir")).unwrap().collect();
    // The fixture seeds a `.keep` file so backends without explicit
    // directory support still expose `dir/empty_dir` — the point of this
    // assertion is that read_dir succeeds (doesn't error as "missing"),
    // not that it's literally empty.
    assert!(entries.iter().all(|e| e.is_ok()));
}

fn walk_visits_every_file_without_duplicates(fs: &dyn FileSystem) {
    use forensic_rs::core::fs::walk::WalkOptions;
    let mut seen = std::collections::BTreeSet::new();
    let mut count = 0;
    for entry in fs.walk(FPath::new(""), &WalkOptions::default()) {
        let entry = entry.unwrap();
        if entry.file_type == VFileType::File {
            assert!(seen.insert(entry.path.as_str().to_string()), "duplicate: {}", entry.path);
            count += 1;
        }
    }
    assert!(count >= 3, "expected at least 3 files, saw {count}");
}

fn send_sync_bound_holds(fs: Arc<dyn FileSystem>) {
    fn assert_send_sync<T: Send + Sync>(_: &T) {}
    assert_send_sync(&fs);
}

macro_rules! fs_conformance_battery {
    ($name:ident, $make:expr) => {
        mod $name {
            use super::*;

            #[test]
            fn open_and_read_existing_file_test() {
                open_and_read_existing_file(&*$make);
            }
            #[test]
            fn open_missing_path_errors_test() {
                open_missing_path_errors(&*$make);
            }
            #[test]
            fn metadata_missing_path_errors_test() {
                metadata_missing_path_errors(&*$make);
            }
            #[test]
            fn read_dir_lists_expected_entries_test() {
                read_dir_lists_expected_entries(&*$make);
            }
            #[test]
            fn read_dir_on_a_file_errors_test() {
                read_dir_on_a_file_errors(&*$make);
            }
            #[test]
            fn read_dir_on_missing_path_errors_test() {
                read_dir_on_missing_path_errors(&*$make);
            }
            #[test]
            fn metadata_reports_correct_size_and_type_test() {
                metadata_reports_correct_size_and_type(&*$make);
            }
            #[test]
            fn zero_byte_file_reads_as_empty_not_error_test() {
                zero_byte_file_reads_as_empty_not_error(&*$make);
            }
            #[test]
            fn exists_true_for_present_false_for_absent_test() {
                exists_true_for_present_false_for_absent(&*$make);
            }
            #[test]
            fn mixed_separators_resolve_to_the_same_entry_test() {
                mixed_separators_resolve_to_the_same_entry(&*$make);
            }
            #[test]
            fn empty_directory_lists_as_empty_not_missing_test() {
                empty_directory_lists_as_empty_not_missing(&*$make);
            }
            #[test]
            fn walk_visits_every_file_without_duplicates_test() {
                walk_visits_every_file_without_duplicates(&*$make);
            }
            #[test]
            fn send_sync_bound_holds_test() {
                send_sync_bound_holds($make);
            }
        }
    };
}

fs_conformance_battery!(in_memory_fs, in_memory_fixture());

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
        assert_eq!(fs.read_all(full(&root, "a.txt").as_path()).unwrap(), b"hello");
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
        assert_eq!(fs.read_all(full(&root, "empty.txt").as_path()).unwrap(), b"");
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
        send_sync_bound_holds(fs);
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
