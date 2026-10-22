//! The memory contract end to end, through the public API only: a backend-independent analyzer
//! and parser factory, run on a `TestingMemoryImage`, the way any memory backend would be used.

use std::sync::Arc;

use forensic_rs::prelude::testing::{TestingMemoryImage, collect_run, test_provenance_id};
use forensic_rs::prelude::*;

const HIDDEN: Va = Va::new(0xffff_c001_0000_2000);
const SYSTEM: Va = Va::new(0xffff_c001_0000_1000);

/// A process record, its provenance minted in `store` the way a backend does: `Allocated` when an
/// OS list holds it, `Carved` when only a scan found it. Its command line is paged out, so the
/// record's validity is that of the page file.
fn process(
    store: &ProvenanceStore,
    object: Va,
    pid: u64,
    name: &'static str,
    linked: bool,
) -> MemProcess {
    let paged = Validity::Paged {
        backing: Backing::PageFile,
        data: false,
    };
    let recovery = if linked {
        Recovery::Allocated
    } else {
        Recovery::Carved
    };
    let id = store
        .register_source(SourceKey::Synthetic("test-memory-image".to_string()))
        .mint(Acquisition::Memory, recovery);
    let mut meta = MemRecordMeta::new(id, paged);
    if linked {
        meta.sources.push(RecordSource::ListWalk {
            list: text("ActiveProcessList"),
        });
    }
    meta.sources.push(RecordSource::Scan {
        scanner: text("object_scan"),
    });
    let mut p = MemProcess::new(MemRecordKey::Object(object), meta);
    p.pid = MemValue::Known(pid);
    p.name = MemValue::Known(text(name));
    p.in_active_list = MemValue::Known(linked);
    // The command line lives in user memory, which is paged out here.
    p.command_line = MemValue::Unavailable(paged);
    p
}

fn image() -> TestingMemoryImage {
    let store = ProvenanceStore::new();
    let mut os = MemOsInfo::new(MemRecordMeta::new(test_provenance_id(), Validity::Resident));
    os.family = MemValue::Known(text("windows"));
    TestingMemoryImage::empty()
        .with_os(os)
        .with_process(process(&store, SYSTEM, 4, "System", true))
        .with_process(process(&store, HIDDEN, 6620, "evil.exe", false))
        .with_provenance(store)
}

/// A detection written only against the contract: it works on any memory backend.
fn unlinked_processes(image: &dyn MemoryImage) -> ForensicResult<Vec<Finding>> {
    Ok(image
        .unlinked_processes()?
        .into_iter()
        .map(|p| {
            let name = p
                .name
                .known()
                .map_or("<unreadable>", |n| n.as_ref())
                .to_string();
            Finding::new(
                FindingSeverity::High,
                FindingCategory::AntiForensics,
                format!("process {name} is not in the active process list"),
            )
            .with_artifact(Artifact::Common(CommonArtifact::Memory(
                MemoryArtifact::Process,
            )))
        })
        .collect())
}

/// A parser factory written only against the contract: memory records to ECS `ForensicData`.
struct ProcessParser {
    descriptor: ParserDescriptor,
}

impl ProcessParser {
    fn new() -> Self {
        let spec = MemorySpec::new().kind(MemRecordKind::Process);
        Self {
            descriptor: ParserDescriptor::new(
                "memory.process",
                "Processes",
                "Processes in memory",
                "1",
            )
            .with_requirements(vec![Requirement::Memory(spec)]),
        }
    }
}

impl ArtifactParserFactory for ProcessParser {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        let Resolution::Resolved(mounted) = ctx.resolve(&self.descriptor.requirements[0])? else {
            return Ok(ParserRun::Pull(Box::new(std::iter::empty())));
        };
        let image = mounted
            .as_memory()
            .expect("Requirement::Memory resolves to Mounted::Memory")
            .clone();
        let source = ctx.register_source(SourceKey::Synthetic("memory-image".to_string()));
        let mut out = Vec::new();
        for p in image.processes()? {
            let p = p?;
            let found_by_list = p
                .meta
                .sources
                .iter()
                .any(|s| matches!(s, RecordSource::ListWalk { .. }));
            let recovery = if found_by_list {
                Recovery::Allocated
            } else {
                Recovery::Carved
            };
            let provenance = source.mint(ctx.acquisition(), recovery);
            let mut data = ForensicData::new(
                ctx.host(),
                Artifact::Common(CommonArtifact::Memory(MemoryArtifact::Process)),
                provenance,
            );
            let mut unavailable = Vec::new();
            match &p.pid {
                MemValue::Known(pid) => data.insert(text(PROCESS_PID), Field::U64(*pid)),
                MemValue::Unavailable(v) => unavailable.push(format!("{PROCESS_PID}:{v:?}")),
                _ => {}
            }
            match &p.command_line {
                MemValue::Known(Some(cmd)) => {
                    data.insert(text(PROCESS_COMMAND_LINE), Field::Text(cmd.clone()))
                }
                MemValue::Unavailable(v) => {
                    unavailable.push(format!("{PROCESS_COMMAND_LINE}:{v:?}"))
                }
                _ => {}
            }
            if let MemRecordKey::Object(va) = p.key {
                data.insert(text(MEMORY_VA), Field::Text(text_owned(va.to_string())));
            }
            if !unavailable.is_empty() {
                data.insert(
                    text(MEMORY_UNAVAILABLE),
                    Field::Array(unavailable.into_iter().map(text_owned).collect()),
                );
            }
            out.push(Ok(data));
        }
        Ok(ParserRun::Pull(Box::new(out.into_iter())))
    }
}

fn run(sources: &TriageSources) -> Vec<ForensicData> {
    let triage = TriageContext::new("host7", "tenant");
    let cancellation = CancellationToken::new();
    let ctx = ParseContext::new(sources, &triage, &cancellation);
    assert_eq!(ctx.acquisition(), Acquisition::Memory);
    collect_run(ProcessParser::new().open(&ctx).unwrap())
        .unwrap()
        .into_iter()
        .map(|r| r.unwrap())
        .collect()
}

#[test]
fn analyzer_finds_the_unlinked_process() {
    let findings = unlinked_processes(&image()).unwrap();
    assert_eq!(findings.len(), 1);
    assert!(findings[0].title.contains("evil.exe"));
}

#[test]
fn parser_exports_ecs_records_without_fabricating_unreadable_fields() {
    let sources = TriageSources::builder().memory(Arc::new(image())).build();
    let records = run(&sources);
    assert_eq!(records.len(), 2);
    // Deterministic order: by key (object address).
    assert_eq!(records[0].field(PROCESS_PID), Some(&Field::U64(4)));
    assert_eq!(records[1].field(PROCESS_PID), Some(&Field::U64(6620)));
    for r in &records {
        // The paged-out command line is omitted, not an empty string ...
        assert!(r.field(PROCESS_COMMAND_LINE).is_none());
        // ... and listed as unavailable, with why.
        let Some(Field::Array(missing)) = r.field(MEMORY_UNAVAILABLE) else {
            panic!("memory.unavailable missing");
        };
        assert!(missing[0].starts_with("process.command_line:Paged"));
    }
    assert_eq!(
        records[1].field(MEMORY_VA),
        Some(&Field::Text(text_owned(HIDDEN.to_string())))
    );
}

#[test]
fn memory_requirement_resolution() {
    let triage = TriageContext::new("host7", "tenant");
    let cancellation = CancellationToken::new();

    let none = TriageSources::builder().build();
    let ctx = ParseContext::new(&none, &triage, &cancellation);
    let want = Requirement::Memory(MemorySpec::new().kind(MemRecordKind::Process));
    assert!(matches!(
        ctx.resolve(&want).unwrap(),
        Resolution::Unavailable(UnavailableReason::NotPresent)
    ));

    let with = TriageSources::builder().memory(Arc::new(image())).build();
    let ctx = ParseContext::new(&with, &triage, &cancellation);
    assert!(matches!(
        ctx.resolve(&want).unwrap(),
        Resolution::Resolved(Mounted::Memory(_))
    ));
    let windows = Requirement::Memory(MemorySpec::new().os_family("windows"));
    assert!(matches!(
        ctx.resolve(&windows).unwrap(),
        Resolution::Resolved(_)
    ));
    let handles = Requirement::Memory(MemorySpec::new().kind(MemRecordKind::Handle));
    assert!(matches!(
        ctx.resolve(&handles).unwrap(),
        Resolution::Unavailable(UnavailableReason::Unsupported)
    ));
}

#[test]
fn memory_locus_and_locator() {
    let locus = Locus::Memory {
        space: 1,
        va: HIDDEN.as_u64(),
    };
    assert_ne!(
        locus,
        Locus::Physical {
            pa: HIDDEN.as_u64()
        }
    );
    let locator = EvidenceLocator::root().push(LocatorSegment::AddressSpace {
        id: 1,
        va: Some(0x7ff6_0000_0000),
    });
    assert!(locator.to_string().contains("[space 1 @0x7ff600000000]"));
    assert!(
        AnomalyFlags::INFERRED_LAYOUT
            .names()
            .eq(["inferred_layout"])
    );
}

#[test]
fn memory_entities_are_distinct_and_stable() {
    let start = ForensicTimestamp::default();
    let proc_a = EntityId::process("host7", 6620, start);
    assert_eq!(
        EntityId::thread("host7", 6620, 7, start),
        EntityId::thread("host7", 6620, 7, start)
    );
    assert_ne!(
        EntityId::module("host7", Some(&proc_a), r"C:\Windows\System32\ntdll.dll"),
        EntityId::module("host7", None, r"C:\Windows\System32\ntdll.dll")
    );
    assert_ne!(
        EntityId::handle("host7", &proc_a, 4),
        EntityId::handle("host7", &proc_a, 8)
    );
    assert_eq!(
        EntityId::driver("host7", "tcpip").kind(),
        EntityKind::Driver
    );
}

#[test]
fn a_kind_the_backend_does_not_provide_is_unsupported_not_a_failure() {
    let image = TestingMemoryImage::empty();
    // "No handles" and "handles not supported" must not look alike (MemoryImage contract).
    let Err(e) = image.processes() else {
        panic!("an image without processes must not iterate them");
    };
    assert!(e.is_unsupported(), "{e}");
    let Err(e) = image.handles(&MemRecordKey::Object(Va::new(0x10))) else {
        panic!("an image without handles must not iterate them");
    };
    assert!(e.is_unsupported(), "{e}");
    // A real failure is not "unsupported".
    let Err(e) = image.kernel_space() else {
        panic!("the empty test image has no kernel space");
    };
    assert!(!e.is_unsupported(), "{e}");
}

#[test]
fn record_provenance_resolves_through_the_image() {
    let image = image();
    for p in image.processes().unwrap() {
        let p = p.unwrap();
        let snapshot = image
            .provenance()
            .get(p.meta.provenance)
            .expect("a record's provenance id resolves in its image's store");
        assert_eq!(snapshot.acquisition, Acquisition::Memory);
        let want = if p.key == MemRecordKey::Object(HIDDEN) {
            Recovery::Carved
        } else {
            Recovery::Allocated
        };
        assert_eq!(snapshot.recovery, want);
        // The record's validity is what its worst field says, never a default.
        assert!(matches!(p.meta.validity, Validity::Paged { .. }));
    }
}
