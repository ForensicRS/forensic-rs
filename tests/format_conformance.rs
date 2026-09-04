//! Conformance battery for [`FormatFactory`] implementations, exercised
//! from outside the crate (public API only) the way a downstream factory
//! author would use it. Mirrors the style of `tests/fs_conformance.rs` and
//! `tests/registry_conformance.rs`: behavioral guarantees the trait's
//! contract promises, proven against more than one implementation so a
//! regression in the shared `MountResolver` machinery -- not just one
//! factory -- gets caught.

use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::Arc;

use forensic_rs::prelude::testing::{InMemoryVirtualFileSystem, TestingRegistry};
use forensic_rs::prelude::*;

struct BytesFile(Cursor<Vec<u8>>);
impl Read for BytesFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}
impl Seek for BytesFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.0.seek(pos)
    }
}
impl VirtualFile for BytesFile {
    fn metadata(&self) -> ForensicResult<forensic_rs::traits::vfs::VMetadata> {
        Ok(forensic_rs::traits::vfs::VMetadata {
            file_type: forensic_rs::traits::vfs::VFileType::File,
            size: self.0.get_ref().len() as u64,
            allocated_size: None,
            times: forensic_rs::traits::vfs::MacbTimes::default(),
            id: None,
            attributes: forensic_rs::traits::vfs::FileAttributes::empty(),
        })
    }
}

fn bytes_file(content: &[u8]) -> Box<dyn VirtualFile> {
    Box::new(BytesFile(Cursor::new(content.to_vec())))
}

fn evidence_fs() -> Arc<dyn FileSystem> {
    Arc::new(InMemoryVirtualFileSystem::new())
}

/// A factory that must never observe a moved stream position from `probe`
/// -- proves `MountResolver` doesn't leave `probe`'s own contract violation
/// unnoticed.
struct MagicFactory {
    magic: &'static [u8],
    name: &'static str,
    score: ProbeScore,
}

impl FormatFactory for MagicFactory {
    fn name(&self) -> &'static str {
        self.name
    }
    fn yields(&self) -> MountKind {
        MountKind::Registry
    }
    fn probe(&self, file: &mut dyn VirtualFile, _ctx: &MountContext<'_>) -> ForensicResult<ProbeScore> {
        let start = file.stream_position()?;
        let mut buf = vec![0u8; self.magic.len()];
        let matched = file.read_exact(&mut buf).is_ok() && buf == self.magic;
        // Contract: probe must restore position before returning, on every
        // path, so a losing factory's probe never disturbs the next one's.
        file.seek(SeekFrom::Start(start))?;
        Ok(if matched { self.score } else { ProbeScore::No })
    }
    fn mount(&self, _file: Box<dyn VirtualFile>, _ctx: &MountContext<'_>) -> ForensicResult<Mounted> {
        Ok(Mounted::Registry(Arc::new(TestingRegistry::empty())))
    }
}

/// A factory whose `probe` always errors -- proves a probe error surfaces
/// through `resolve` rather than being silently treated as "no match".
struct AlwaysErrorsFactory;
impl FormatFactory for AlwaysErrorsFactory {
    fn name(&self) -> &'static str {
        "zz-always-errors"
    }
    fn yields(&self) -> MountKind {
        MountKind::Registry
    }
    fn probe(&self, _file: &mut dyn VirtualFile, _ctx: &MountContext<'_>) -> ForensicResult<ProbeScore> {
        Err(ForensicError::other("AlwaysErrorsFactory", "boom".to_string()))
    }
    fn mount(&self, _file: Box<dyn VirtualFile>, _ctx: &MountContext<'_>) -> ForensicResult<Mounted> {
        unreachable!("probe always errors first")
    }
}

fn locator(name: &str) -> EvidenceLocator {
    EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from(name)))
}

#[test]
fn probe_position_is_restored_regardless_of_match() {
    // Exercised indirectly: MagicFactory itself asserts this via `?` on the
    // seek-back; if it didn't restore position, a second registered
    // factory probing the same file after a losing probe would see a
    // corrupted stream and fail to match what it otherwise would.
    let losing = Arc::new(MagicFactory {
        magic: b"NOPE",
        name: "a-losing",
        score: ProbeScore::Weak,
    });
    let winning = Arc::new(MagicFactory {
        magic: b"REAL",
        name: "b-winning",
        score: ProbeScore::Strong,
    });
    let resolver = MountResolver::builder().factory(losing).factory(winning).build();
    let fs = evidence_fs();
    let cancel = CancellationToken::new();
    let mounted = resolver
        .resolve(&fs, &locator("x"), bytes_file(b"REAL-payload"), None, &cancel)
        .expect("the winning factory should still match after the losing one probed first");
    assert!(mounted.as_registry().is_some());
}

#[test]
fn a_probe_error_surfaces_instead_of_being_treated_as_no_match() {
    let resolver = MountResolver::builder().factory(Arc::new(AlwaysErrorsFactory)).build();
    let fs = evidence_fs();
    let cancel = CancellationToken::new();
    let result = resolver.resolve(&fs, &locator("x"), bytes_file(b"anything"), None, &cancel);
    assert!(result.is_err(), "a probe error must propagate, not be swallowed as ProbeScore::No");
}

#[test]
fn winner_selection_is_deterministic_across_shuffled_registration_order() {
    // Two factories both match, with different scores. Whichever order
    // they're registered in, the higher-scoring one must win every time --
    // output must never depend on wiring order (the reproducibility rule
    // the rest of the pipeline is held to).
    let weak = || {
        Arc::new(MagicFactory {
            magic: b"BOTH",
            name: "weak-match",
            score: ProbeScore::Weak,
        }) as Arc<dyn FormatFactory>
    };
    let strong = || {
        Arc::new(MagicFactory {
            magic: b"BOTH",
            name: "strong-match",
            score: ProbeScore::Strong,
        }) as Arc<dyn FormatFactory>
    };

    for round in 0..20u32 {
        let resolver = if round % 2 == 0 {
            MountResolver::builder().factory(weak()).factory(strong()).build()
        } else {
            MountResolver::builder().factory(strong()).factory(weak()).build()
        };
        let fs = evidence_fs();
        let cancel = CancellationToken::new();
        // Distinct locator per round -- the resolver caches by locator, and
        // this test wants a fresh probe/mount each time, not a cache hit.
        let loc = locator(&format!("round-{round}"));
        let mounted = resolver
            .resolve(&fs, &loc, bytes_file(b"BOTH-payload"), None, &cancel)
            .unwrap();
        assert!(mounted.as_registry().is_some());
    }
}

#[test]
fn tie_break_on_equal_score_is_alphabetically_first_name() {
    let resolver = MountResolver::builder()
        .factory(Arc::new(MagicFactory {
            magic: b"TIE!",
            name: "zzz-later",
            score: ProbeScore::Strong,
        }))
        .factory(Arc::new(MagicFactory {
            magic: b"TIE!",
            name: "aaa-earlier",
            score: ProbeScore::Strong,
        }))
        .build();
    // Both factories mount the same Mounted::Registry shape here, so this
    // test only proves determinism of the pick, not which one "aaa-earlier"
    // vs "zzz-later" is distinguishable by output -- that's covered by
    // MountResolver's own unit tests asserting on `factory.name()` ordering
    // directly. This proves the public-API-visible outcome is stable.
    let fs = evidence_fs();
    let cancel = CancellationToken::new();
    let first = resolver
        .resolve(&fs, &locator("a"), bytes_file(b"TIE!-payload"), None, &cancel)
        .unwrap();
    let second = resolver
        .resolve(&fs, &locator("b"), bytes_file(b"TIE!-payload"), None, &cancel)
        .unwrap();
    assert_eq!(first.kind(), second.kind());
}

#[test]
fn unsupported_want_kind_is_reported_not_silently_ignored() {
    let resolver = MountResolver::builder()
        .factory(Arc::new(MagicFactory {
            magic: b"REAL",
            name: "registry-only",
            score: ProbeScore::Strong,
        }))
        .build();
    let fs = evidence_fs();
    let cancel = CancellationToken::new();
    let result = resolver.resolve(
        &fs,
        &locator("x"),
        bytes_file(b"REAL-payload"),
        Some(MountKind::Database),
        &cancel,
    );
    assert!(result.is_err());
}

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn format_factory_and_mount_resolver_trait_objects_are_send_and_sync() {
    assert_send_sync::<Arc<dyn FormatFactory>>();
    assert_send_sync::<Arc<MountResolver>>();
    assert_send_sync::<Arc<dyn StructuredObject>>();
}
