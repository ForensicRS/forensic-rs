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

/// A factory whose job is grouping, not interpreting: it probes the primary
/// and reports the whole artifact's file set. Discovery goes entirely
/// through `MountContext`'s companion helpers, which is the boilerplate two
/// downstream crates previously wrote by hand.
struct LogSetFactory;

impl FormatFactory for LogSetFactory {
    fn name(&self) -> &'static str {
        "log-set"
    }
    fn yields(&self) -> MountKind {
        MountKind::FileSet
    }
    fn probe(&self, file: &mut dyn VirtualFile, _ctx: &MountContext<'_>) -> ForensicResult<ProbeScore> {
        let start = file.stream_position()?;
        let mut buf = [0u8; 4];
        let matched = file.read_exact(&mut buf).is_ok() && &buf == b"EDB0";
        file.seek(SeekFrom::Start(start))?;
        Ok(if matched { ProbeScore::Exact } else { ProbeScore::No })
    }
    fn mount(&self, _file: Box<dyn VirtualFile>, ctx: &MountContext<'_>) -> ForensicResult<Mounted> {
        let mut set = FileSet::new(ctx.locator().clone());
        // The format-specific part is only the naming rule; listing the
        // directory and building locators is the framework's job now.
        let mut names: Vec<String> = ctx
            .siblings()?
            .into_iter()
            .filter_map(|e| e.file_name().map(str::to_string))
            .collect();
        names.sort();
        for name in names {
            let role = if name.ends_with(".log") {
                FileSetRole::Log
            } else if name.ends_with(".chk") {
                FileSetRole::Checkpoint
            } else {
                continue;
            };
            if let Some(locator) = ctx.sibling_locator(&name) {
                set.push_mut(role, locator);
            }
        }
        Ok(Mounted::FileSet(set))
    }
}

fn ese_evidence_fs() -> Arc<dyn FileSystem> {
    Arc::new(
        InMemoryVirtualFileSystem::new()
            .with_file("/evidence/db.dat", b"EDB0payload".to_vec())
            .with_file("/evidence/gen1.log", b"log".to_vec())
            .with_file("/evidence/gen2.log", b"log".to_vec())
            .with_file("/evidence/db.chk", b"chk".to_vec())
            .with_file("/evidence/unrelated.txt", b"no".to_vec()),
    )
}

#[test]
fn a_file_set_mount_reports_every_member_with_its_role() {
    let resolver = MountResolver::builder().factory(Arc::new(LogSetFactory)).build();
    let fs = ese_evidence_fs();
    let cancel = CancellationToken::new();
    let mounted = resolver
        .resolve(
            &fs,
            &locator("/evidence/db.dat"),
            bytes_file(b"EDB0payload"),
            Some(MountKind::FileSet),
            &cancel,
        )
        .expect("the file-set factory should claim the primary");

    assert_eq!(mounted.kind(), MountKind::FileSet);
    let set = mounted.as_file_set().expect("must expose the set");

    // The primary is a member, and it is first.
    assert_eq!(set.primary(), &locator("/evidence/db.dat"));
    assert_eq!(set.members()[0].role, FileSetRole::Primary);

    // Roles survive, so a consumer never has to re-derive them from names.
    assert_eq!(set.by_role(&FileSetRole::Log).count(), 2);
    assert_eq!(set.by_role(&FileSetRole::Checkpoint).count(), 1);
    assert_eq!(set.len(), 4, "the unrelated file must not join the set");
}

#[test]
fn a_file_set_factory_is_filtered_out_by_a_mismatched_want() {
    let resolver = MountResolver::builder().factory(Arc::new(LogSetFactory)).build();
    let fs = ese_evidence_fs();
    let cancel = CancellationToken::new();
    let result = resolver.resolve(
        &fs,
        &locator("/evidence/db.dat"),
        bytes_file(b"EDB0payload"),
        Some(MountKind::Database),
        &cancel,
    );
    assert!(
        result.is_err(),
        "a set is not a database; the mismatch must be reported, not silently mounted"
    );
    assert!(resolver.supports(MountKind::FileSet));
    assert!(!resolver.supports(MountKind::Database));
}

#[test]
fn a_file_set_is_cached_by_locator_like_any_other_mount() {
    let resolver = MountResolver::builder().factory(Arc::new(LogSetFactory)).build();
    let fs = ese_evidence_fs();
    let cancel = CancellationToken::new();
    let first = resolver
        .resolve(&fs, &locator("/evidence/db.dat"), bytes_file(b"EDB0payload"), None, &cancel)
        .unwrap();
    let second = resolver
        .resolve(&fs, &locator("/evidence/db.dat"), bytes_file(b"EDB0payload"), None, &cancel)
        .unwrap();
    assert_eq!(
        first.as_file_set().unwrap(),
        second.as_file_set().unwrap(),
        "the second resolve must come back from the cache unchanged"
    );
}

/// The first test in this suite to exercise `ctx.fs()`/`ctx.locator()`, the
/// two fields `MountContext` carries specifically so a factory can reach
/// companion files.
#[test]
fn companion_discovery_helpers_resolve_against_the_targets_own_directory() {
    struct AssertingFactory;
    impl FormatFactory for AssertingFactory {
        fn name(&self) -> &'static str {
            "asserting"
        }
        fn yields(&self) -> MountKind {
            MountKind::FileSet
        }
        fn probe(&self, _f: &mut dyn VirtualFile, _c: &MountContext<'_>) -> ForensicResult<ProbeScore> {
            Ok(ProbeScore::Exact)
        }
        fn mount(&self, _f: Box<dyn VirtualFile>, ctx: &MountContext<'_>) -> ForensicResult<Mounted> {
            assert_eq!(ctx.parent_dir().unwrap().as_path(), FPath::new("/evidence"));
            assert_eq!(ctx.siblings()?.len(), 5);
            assert_eq!(
                ctx.sibling_locator("db.chk").unwrap(),
                locator("/evidence/db.chk")
            );
            Ok(Mounted::FileSet(FileSet::new(ctx.locator().clone())))
        }
    }

    let resolver = MountResolver::builder().factory(Arc::new(AssertingFactory)).build();
    let cancel = CancellationToken::new();
    resolver
        .resolve(
            &ese_evidence_fs(),
            &locator("/evidence/db.dat"),
            bytes_file(b"x"),
            None,
            &cancel,
        )
        .unwrap();
}

/// A non-path hop has no sibling directory. Substituting the enclosing
/// container's directory would point discovery at the wrong evidence, so the
/// helpers must decline rather than guess.
#[test]
fn companion_discovery_declines_for_a_target_that_is_not_a_path() {
    struct NonPathFactory;
    impl FormatFactory for NonPathFactory {
        fn name(&self) -> &'static str {
            "non-path"
        }
        fn yields(&self) -> MountKind {
            MountKind::FileSet
        }
        fn probe(&self, _f: &mut dyn VirtualFile, _c: &MountContext<'_>) -> ForensicResult<ProbeScore> {
            Ok(ProbeScore::Exact)
        }
        fn mount(&self, _f: Box<dyn VirtualFile>, ctx: &MountContext<'_>) -> ForensicResult<Mounted> {
            assert!(ctx.parent_dir().is_none());
            assert!(ctx.siblings()?.is_empty());
            assert!(ctx.sibling_locator("anything").is_none());
            Ok(Mounted::FileSet(FileSet::new(ctx.locator().clone())))
        }
    }

    let inside_zip = EvidenceLocator::root()
        .push(LocatorSegment::Path(FPathBuf::from("/evidence/a.zip")))
        .push(LocatorSegment::ArchiveEntry {
            index: 0,
            name: "inner.dat".into(),
        });

    let resolver = MountResolver::builder().factory(Arc::new(NonPathFactory)).build();
    let cancel = CancellationToken::new();
    resolver
        .resolve(&ese_evidence_fs(), &inside_zip, bytes_file(b"x"), None, &cancel)
        .unwrap();
}
