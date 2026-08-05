//! Proves RFC 0001's P5 fix (parallel image scanning) actually works, not
//! just typechecks: an `Arc<dyn FileSystem>` shared across real OS threads,
//! each doing independent I/O through it. Not airtight against every data
//! race, but catches the obvious "faked `&self`+`Send` via unsynchronized
//! interior mutability" regression cheaply, without needing Miri.

use forensic_rs::core::path::FPath;
use forensic_rs::traits::vfs::{FileSystem, FileSystemExt};
use forensic_rs::utils::testing::InMemoryVirtualFileSystem;
use std::sync::Arc;

fn fixture() -> Arc<dyn FileSystem> {
    let mut fs = InMemoryVirtualFileSystem::new();
    for i in 0..8 {
        fs.add_file(format!("file{i}.txt"), format!("content-{i}").into_bytes());
    }
    Arc::new(fs)
}

#[test]
fn each_worker_reads_its_own_file_concurrently() {
    let fs = fixture();
    std::thread::scope(|scope| {
        for i in 0..8 {
            let fs = Arc::clone(&fs);
            scope.spawn(move || {
                let path = format!("file{i}.txt");
                let content = fs.read_all(FPath::new(&path)).unwrap();
                assert_eq!(content, format!("content-{i}").into_bytes());
            });
        }
    });
}

#[test]
fn many_workers_read_the_same_file_concurrently() {
    let fs = fixture();
    std::thread::scope(|scope| {
        for _ in 0..16 {
            let fs = Arc::clone(&fs);
            scope.spawn(move || {
                for _ in 0..50 {
                    let content = fs.read_all(FPath::new("file0.txt")).unwrap();
                    assert_eq!(content, b"content-0");
                }
            });
        }
    });
}

#[test]
fn workers_open_independent_file_handles() {
    // Each `open()` call must yield an independent, per-thread `VirtualFile`
    // handle — not a single shared cursor whose position races across
    // threads (the exact bug P5 exists to make impossible).
    use std::io::Read;
    let fs = fixture();
    std::thread::scope(|scope| {
        for i in 0..8 {
            let fs = Arc::clone(&fs);
            scope.spawn(move || {
                let path = format!("file{i}.txt");
                let mut file = fs.open(FPath::new(&path)).unwrap();
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).unwrap();
                assert_eq!(buf, format!("content-{i}").into_bytes());
            });
        }
    });
}
