//! Shared conformance battery for every `FileSystem` backend.
//!
//! Each function checks one conformance point against a backend seeded with the fixture tree
//! below; [`fs_conformance_battery!`](crate::fs_conformance_battery) expands to a `mod` of
//! individually named `#[test]`s calling all of them, so a downstream backend (a disk image, a
//! volume system, an archive) runs exactly the assertions core's own backends run.
//!
//! Fixture tree every backend must expose:
//! - `a.txt` -> `b"hello"`
//! - `dir/b.txt` -> `b"world"`
//! - `dir/empty_dir/` (a directory; it may hold a `.keep` file)
//! - `empty.txt` -> `b""`

use std::sync::Arc;

use crate::core::path::FPath;
use crate::traits::vfs::{FileSystem, FileSystemExt, VFileType};

pub fn open_and_read_existing_file(fs: &dyn FileSystem) {
    assert_eq!(fs.read_all(FPath::new("a.txt")).unwrap(), b"hello");
}

pub fn open_missing_path_errors(fs: &dyn FileSystem) {
    assert!(fs.open(FPath::new("does-not-exist.txt")).is_err());
}

pub fn metadata_missing_path_errors(fs: &dyn FileSystem) {
    assert!(fs.metadata(FPath::new("does-not-exist.txt")).is_err());
}

pub fn read_dir_lists_expected_entries(fs: &dyn FileSystem) {
    let names: std::collections::BTreeSet<String> = fs
        .read_dir(FPath::new("dir"))
        .unwrap()
        .filter_map(|e| e.ok().and_then(|e| e.file_name().map(str::to_string)))
        .collect();
    assert!(names.contains("b.txt"));
    assert!(names.contains("empty_dir"));
}

pub fn read_dir_on_a_file_errors(fs: &dyn FileSystem) {
    assert!(fs.read_dir(FPath::new("a.txt")).is_err());
}

pub fn read_dir_on_missing_path_errors(fs: &dyn FileSystem) {
    assert!(fs.read_dir(FPath::new("no-such-dir")).is_err());
}

pub fn metadata_reports_correct_size_and_type(fs: &dyn FileSystem) {
    let m = fs.metadata(FPath::new("a.txt")).unwrap();
    assert_eq!(m.size, 5);
    assert_eq!(m.file_type, VFileType::File);

    let dir_meta = fs.metadata(FPath::new("dir")).unwrap();
    assert_eq!(dir_meta.file_type, VFileType::Directory);
}

pub fn zero_byte_file_reads_as_empty_not_error(fs: &dyn FileSystem) {
    assert_eq!(fs.read_all(FPath::new("empty.txt")).unwrap(), b"");
}

pub fn exists_true_for_present_false_for_absent(fs: &dyn FileSystem) {
    assert!(fs.exists(FPath::new("a.txt")));
    assert!(!fs.exists(FPath::new("nope.txt")));
}

pub fn mixed_separators_resolve_to_the_same_entry(fs: &dyn FileSystem) {
    assert_eq!(
        fs.read_all(FPath::new("dir/b.txt")).unwrap(),
        fs.read_all(FPath::new("dir\\b.txt")).unwrap()
    );
}

pub fn empty_directory_lists_as_empty_not_missing(fs: &dyn FileSystem) {
    let entries: Vec<_> = fs.read_dir(FPath::new("dir/empty_dir")).unwrap().collect();
    // The fixture seeds a `.keep` file so backends without explicit
    // directory support still expose `dir/empty_dir` — the point of this
    // assertion is that read_dir succeeds (doesn't error as "missing"),
    // not that it's literally empty.
    assert!(entries.iter().all(|e| e.is_ok()));
}

pub fn walk_visits_every_file_without_duplicates(fs: &dyn FileSystem) {
    use crate::core::fs::walk::WalkOptions;
    let mut seen = std::collections::BTreeSet::new();
    let mut count = 0;
    for entry in fs.walk(FPath::new(""), &WalkOptions::default()) {
        let entry = entry.unwrap();
        if entry.file_type == VFileType::File {
            assert!(
                seen.insert(entry.path.as_str().to_string()),
                "duplicate: {}",
                entry.path
            );
            count += 1;
        }
    }
    assert!(count >= 3, "expected at least 3 files, saw {count}");
}

pub fn send_sync_bound_holds(fs: Arc<dyn FileSystem>) {
    fn assert_send_sync<T: Send + Sync>(_: &T) {}
    assert_send_sync(&fs);
}

/// Expands to `mod $name { #[test] ... }` running every conformance function against the
/// `Arc<dyn FileSystem>` that `$make` evaluates to (evaluated once per test).
#[macro_export]
macro_rules! fs_conformance_battery {
    ($name:ident, $make:expr) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            #[test]
            fn open_and_read_existing_file_test() {
                $crate::utils::testing::conformance::open_and_read_existing_file(&*$make);
            }
            #[test]
            fn open_missing_path_errors_test() {
                $crate::utils::testing::conformance::open_missing_path_errors(&*$make);
            }
            #[test]
            fn metadata_missing_path_errors_test() {
                $crate::utils::testing::conformance::metadata_missing_path_errors(&*$make);
            }
            #[test]
            fn read_dir_lists_expected_entries_test() {
                $crate::utils::testing::conformance::read_dir_lists_expected_entries(&*$make);
            }
            #[test]
            fn read_dir_on_a_file_errors_test() {
                $crate::utils::testing::conformance::read_dir_on_a_file_errors(&*$make);
            }
            #[test]
            fn read_dir_on_missing_path_errors_test() {
                $crate::utils::testing::conformance::read_dir_on_missing_path_errors(&*$make);
            }
            #[test]
            fn metadata_reports_correct_size_and_type_test() {
                $crate::utils::testing::conformance::metadata_reports_correct_size_and_type(
                    &*$make,
                );
            }
            #[test]
            fn zero_byte_file_reads_as_empty_not_error_test() {
                $crate::utils::testing::conformance::zero_byte_file_reads_as_empty_not_error(
                    &*$make,
                );
            }
            #[test]
            fn exists_true_for_present_false_for_absent_test() {
                $crate::utils::testing::conformance::exists_true_for_present_false_for_absent(
                    &*$make,
                );
            }
            #[test]
            fn mixed_separators_resolve_to_the_same_entry_test() {
                $crate::utils::testing::conformance::mixed_separators_resolve_to_the_same_entry(
                    &*$make,
                );
            }
            #[test]
            fn empty_directory_lists_as_empty_not_missing_test() {
                $crate::utils::testing::conformance::empty_directory_lists_as_empty_not_missing(
                    &*$make,
                );
            }
            #[test]
            fn walk_visits_every_file_without_duplicates_test() {
                $crate::utils::testing::conformance::walk_visits_every_file_without_duplicates(
                    &*$make,
                );
            }
            #[test]
            fn send_sync_bound_holds_test() {
                $crate::utils::testing::conformance::send_sync_bound_holds($make);
            }
        }
    };
}
