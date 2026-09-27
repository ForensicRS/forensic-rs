//! Storage media through the public API: a split raw image on a real disk, larger than every
//! in-memory limit, walked transparently and read by many workers at once -- the shape every
//! image-format and volume-system crate plugs into.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Arc;

use forensic_rs::prelude::*;

/// A scratch directory under the system temp dir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("forensic-rs-media-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.0.join(name);
        std::fs::File::create(&path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
        path.to_str().unwrap().replace('\\', "/")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The byte at `offset` of the synthetic disk: position-dependent, so a misplaced read shows.
fn disk_byte(offset: u64) -> u8 {
    (offset.wrapping_mul(2_654_435_761) >> 13) as u8
}

const SEGMENT: u64 = 16 << 20;
const SEGMENTS: u64 = 3;

fn write_split_image(scratch: &Scratch) -> String {
    let mut first = String::new();
    for n in 0..SEGMENTS {
        let bytes: Vec<u8> = (n * SEGMENT..(n + 1) * SEGMENT).map(disk_byte).collect();
        let path = scratch.write(&format!("disk.{:03}", n + 1), &bytes);
        if n == 0 {
            first = path;
        }
    }
    first
}

#[test]
fn a_split_image_larger_than_every_memory_limit_is_walked_transparently() {
    let scratch = Scratch::new("walk");
    let first = write_split_image(&scratch);

    let resolver = Arc::new(
        MountResolver::builder()
            .factory(Arc::new(SplitRawFactory::new()))
            .build(),
    );
    let disk_size = SEGMENT * SEGMENTS;
    assert!(disk_size > resolver.limits().materialize_in_memory_limit as u64);

    let fs = ContainerFs::new(Arc::new(StdVirtualFS::new()), resolver);
    let media = format!("{first}/media");
    assert_eq!(fs.metadata(FPath::new(&media)).unwrap().size, disk_size);

    // A read straddling the segment 1 / segment 2 boundary.
    let mut file = fs.open(FPath::new(&media)).unwrap();
    let at = SEGMENT - 100;
    file.seek(SeekFrom::Start(at)).unwrap();
    let mut buf = vec![0u8; 200];
    file.read_exact(&mut buf).unwrap();
    let expected: Vec<u8> = (at..at + 200).map(disk_byte).collect();
    assert_eq!(buf, expected);

    // The later segments are not containers of their own.
    assert!(!fs.exists(FPath::new(&format!(
        "{}/media",
        first.replace(".001", ".002")
    ))));
}

#[test]
fn many_workers_read_one_image_through_a_shared_resolver() {
    let scratch = Scratch::new("parallel");
    let first = write_split_image(&scratch);
    let resolver = Arc::new(
        MountResolver::builder()
            .factory(Arc::new(SplitRawFactory::new()))
            .build(),
    );
    let fs = Arc::new(ContainerFs::new(Arc::new(StdVirtualFS::new()), resolver));
    let media = format!("{first}/media");

    let workers: Vec<_> = (0..8u64)
        .map(|w| {
            let fs = Arc::clone(&fs);
            let media = media.clone();
            std::thread::spawn(move || {
                let mut file = fs.open(FPath::new(&media)).unwrap();
                for i in 0..64u64 {
                    let at = (w * 1_000_003 + i * 777_767) % (SEGMENT * SEGMENTS - 4096);
                    file.seek(SeekFrom::Start(at)).unwrap();
                    let mut buf = [0u8; 4096];
                    file.read_exact(&mut buf).unwrap();
                    assert!(
                        buf.iter().zip(at..).all(|(b, o)| *b == disk_byte(o)),
                        "worker {w} read {at}"
                    );
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

/// A non-cryptographic digest, enough to exercise content interning.
struct Fnv(u64);
impl Digest for Fnv {
    fn algorithm(&self) -> DigestAlgorithm {
        DigestAlgorithm::Other("fnv1a64")
    }
    fn update(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 = (self.0 ^ u64::from(*b)).wrapping_mul(0x100_0000_01b3);
        }
    }
    fn finish(self: Box<Self>) -> ContentAddress {
        ContentAddress::new(
            DigestAlgorithm::Other("fnv1a64"),
            self.0.to_be_bytes().to_vec(),
        )
    }
}

/// Claims everything and expands it (the default `HopCost`), reporting only where it is.
struct ClaimAll;
impl FormatFactory for ClaimAll {
    fn name(&self) -> &'static str {
        "claim-all"
    }
    fn yields(&self) -> MountKind {
        MountKind::File
    }
    fn probe(
        &self,
        _file: &mut dyn VirtualFile,
        _ctx: &MountContext<'_>,
    ) -> ForensicResult<ProbeScore> {
        Ok(ProbeScore::Weak)
    }
    fn mount(
        &self,
        _file: Box<dyn VirtualFile>,
        ctx: &MountContext<'_>,
    ) -> ForensicResult<Mounted> {
        Ok(Mounted::File(ctx.locator().clone()))
    }
}

#[test]
fn content_interning_streams_instead_of_materializing() {
    // 40 MiB is past the 32 MiB in-memory spill limit, which content interning used to go
    // through, refusing the file whenever a digest was configured.
    let scratch = Scratch::new("digest");
    let bytes: Vec<u8> = (0..40u64 << 20).map(disk_byte).collect();
    let path = scratch.write("big.bin", &bytes);

    let resolver = MountResolver::builder()
        .factory(Arc::new(ClaimAll))
        .digest(|| Box::new(Fnv(0xcbf2_9ce4_8422_2325)))
        .build();
    let fs: Arc<dyn FileSystem> = Arc::new(StdVirtualFS::new());
    let locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from(path.as_str())));
    let file = fs.open(FPath::new(&path)).unwrap();
    let mounted = resolver
        .resolve(&fs, &locator, file, None, &CancellationToken::default())
        .unwrap();
    assert_eq!(mounted.as_file(), Some(&locator));
}
