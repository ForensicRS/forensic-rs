//! Resolution against evidence: [`resolve_expansion`](super::resolve_expansion),
//! [`ParseContext::resolve_artifact`] and a whole [`TriagePipeline`] run.

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use super::*;
use crate::artifact::Artifact;
use crate::bridge::CancellationToken;
use crate::data::ForensicData;
use crate::err::ForensicResult;
use crate::pipeline::context::{ParseContext, TriageContext};
use crate::pipeline::finding::Finding;
use crate::pipeline::sources::TriageSources;
use crate::pipeline::traits::TriageSink;
use crate::pipeline::{ErrorAction, TriagePipeline};
use crate::traits::forensic::{
    ArtifactParserFactory, ParserDescriptor, ParserRun, Requirement, Resolution, UnavailableReason,
};
use crate::traits::registry::RegValue;
use crate::traits::vfs::FileSystem;
use crate::utils::testing::{InMemoryVirtualFileSystem, TestingRegistry};

const ALICE: &str = "S-1-5-21-1-2-3-1001";
const BOB: &str = "S-1-5-21-1-2-3-1002";
const NT: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";

fn file_def(name: &'static str, paths: &'static [Text]) -> ArtifactDefinition {
    ArtifactDefinition {
        name: Cow::Borrowed(name),
        aliases: Cow::Borrowed(&[]),
        doc: Cow::Borrowed(""),
        sources: Cow::Owned(vec![SourceEntry {
            source: ArtifactSource::File {
                paths: Cow::Borrowed(paths),
                separator: Separator::Backslash,
            },
            supported_os: Cow::Borrowed(&[]),
        }]),
        supported_os: Cow::Borrowed(&[Os::Windows]),
        urls: Cow::Borrowed(&[]),
    }
}

/// Two definitions: per-user hives (files plus a per-user registry value)
/// and prefetch files.
fn catalog() -> Arc<dyn ArtifactCatalog> {
    let mut hives = file_def(
        "WindowsUserRegistryFiles",
        &[Cow::Borrowed("%%users.userprofile%%\\NTUSER.DAT")],
    );
    hives.sources.to_mut().push(SourceEntry {
        source: ArtifactSource::RegistryValue {
            pairs: Cow::Owned(vec![RegistryValueRef {
                key: Cow::Borrowed("HKEY_USERS\\%%users.sid%%\\Environment"),
                value: Cow::Borrowed("TEMP"),
            }]),
        },
        supported_os: Cow::Borrowed(&[]),
    });
    let prefetch = file_def(
        "WindowsPrefetchFiles",
        &[Cow::Borrowed("%%environ_systemroot%%\\Prefetch\\*.pf")],
    );
    Arc::new(SliceCatalog::new(vec![hives, prefetch]).unwrap())
}

fn registry() -> TestingRegistry {
    let mut reg = TestingRegistry::empty();
    reg.add_value(NT, "SystemRoot", RegValue::new_sz(r"C:\Windows"));
    let profiles = format!(r"{NT}\ProfileList");
    reg.add_value(
        &format!(r"{profiles}\{ALICE}"),
        "ProfileImagePath",
        RegValue::new_sz(r"%SystemDrive%\Users\alice"),
    );
    reg.add_value(
        &format!(r"{profiles}\{BOB}"),
        "ProfileImagePath",
        RegValue::new_sz(r"C:\Users\bob"),
    );
    reg.add_value(
        &format!(r"HKU\{ALICE}\Environment"),
        "TEMP",
        RegValue::new_sz(r"%USERPROFILE%\AppData\Local\Temp"),
    );
    reg.add_key(&format!(r"HKU\{BOB}\Environment"));
    reg
}

fn vfs() -> InMemoryVirtualFileSystem {
    InMemoryVirtualFileSystem::new()
        .with_file("Users/alice/NTUSER.DAT", b"a".to_vec())
        .with_file("Users/bob/NTUSER.DAT", b"b".to_vec())
        .with_file("Users/carol/NTUSER.DAT", b"c".to_vec())
        .with_file("Windows/Prefetch/CMD.EXE-1234.pf", b"p".to_vec())
}

fn sources(catalog: Option<Arc<dyn ArtifactCatalog>>) -> TriageSources {
    let mut builder = TriageSources::builder()
        .vfs(Arc::new(vfs()))
        .registry(Arc::new(registry()));
    if let Some(catalog) = catalog {
        builder = builder.catalog(catalog);
    }
    builder.build()
}

fn with_context<T>(sources: &TriageSources, f: impl FnOnce(&ParseContext<'_>) -> T) -> T {
    let triage = TriageContext::default();
    let cancellation = CancellationToken::new();
    f(&ParseContext::new(sources, &triage, &cancellation))
}

#[test]
fn resolves_each_user_s_files_and_values_with_their_sids() {
    let sources = sources(Some(catalog()));
    let resolution = with_context(&sources, |ctx| {
        ctx.resolve_artifact("WindowsUserRegistryFiles").unwrap()
    });

    let files: Vec<(&str, Option<&str>)> = resolution
        .files
        .iter()
        .map(|f| (f.path.as_str(), f.sid.as_deref()))
        .collect();
    // carol has a hive on disk but no profile: expanding for known users
    // doesn't guess at her.
    assert_eq!(
        files,
        vec![
            ("Users/alice/NTUSER.DAT", Some(ALICE)),
            ("Users/bob/NTUSER.DAT", Some(BOB)),
        ]
    );
    let values: Vec<(&str, Option<&str>)> = resolution
        .values
        .iter()
        .map(|v| (v.key.as_str(), v.sid.as_deref()))
        .collect();
    assert_eq!(
        values,
        vec![(&*format!(r"HKEY_USERS\{ALICE}\Environment"), Some(ALICE))]
    );
    assert!(resolution.errors.is_empty(), "{:?}", resolution.errors);
    assert!(resolution.unresolved.is_empty());
}

#[test]
fn without_a_registry_placeholders_fall_back_to_search_patterns() {
    let sources = TriageSources::builder()
        .vfs(Arc::new(vfs()))
        .catalog(catalog())
        .build();
    let resolution = with_context(&sources, |ctx| {
        ctx.resolve_artifact("WindowsUserRegistryFiles").unwrap()
    });

    assert_eq!(
        resolution.files.len(),
        3,
        "every profile folder is searched"
    );
    assert!(resolution.files.iter().all(|f| f.sid.is_none()));
    assert!(
        resolution
            .notes
            .iter()
            .any(|n| n.contains("users.userprofile"))
    );
    assert!(
        resolution
            .notes
            .iter()
            .any(|n| n.contains("no registry configured"))
    );

    let prefetch = with_context(&sources, |ctx| {
        ctx.resolve_artifact("WindowsPrefetchFiles").unwrap()
    });
    assert_eq!(prefetch.files.len(), 1);
    assert!(
        prefetch
            .notes
            .iter()
            .any(|n| n.contains("system root unknown"))
    );
}

#[test]
fn not_present_is_an_empty_result_and_an_unknown_name_is_an_error() {
    let sources = TriageSources::builder()
        .vfs(Arc::new(InMemoryVirtualFileSystem::new()))
        .registry(Arc::new(registry()))
        .catalog(catalog())
        .build();
    with_context(&sources, |ctx| {
        let resolution = ctx.resolve_artifact("WindowsPrefetchFiles").unwrap();
        assert!(resolution.is_empty());
        assert!(resolution.errors.is_empty());
        let requirement = Requirement::artifact("WindowsPrefetchFiles");
        assert!(matches!(
            ctx.resolve(&requirement).unwrap(),
            Resolution::Unavailable(UnavailableReason::NotPresent)
        ));
        assert!(ctx.resolve_artifact("NoSuchArtifact").is_err());
        assert!(
            ctx.resolve(&Requirement::artifact("NoSuchArtifact"))
                .is_err()
        );
    });
}

#[test]
fn an_artifact_requirement_without_a_catalog_is_unsupported() {
    let sources = sources(None);
    with_context(&sources, |ctx| {
        assert!(matches!(
            ctx.resolve(&Requirement::artifact("WindowsPrefetchFiles"))
                .unwrap(),
            Resolution::Unavailable(UnavailableReason::Unsupported)
        ));
        assert!(ctx.resolve_artifact("WindowsPrefetchFiles").is_err());
    });
}

#[test]
fn the_host_profile_is_resolved_once_per_context() {
    let sources = sources(Some(catalog()));
    with_context(&sources, |ctx| {
        let first = ctx.host_profile().unwrap() as *const _;
        let second = ctx.host_profile().unwrap() as *const _;
        assert_eq!(first, second);
        let root = ctx.host_profile().unwrap().system_root.as_ref().unwrap();
        assert_eq!(root.value().as_str(), "C:/Windows");
    });
}

#[test]
fn resolve_files_returns_every_match() {
    let sources = sources(None);
    with_context(&sources, |ctx| {
        let spec = crate::traits::forensic::TargetSpec::new("Users/*/NTUSER.DAT", "hives");
        assert_eq!(ctx.resolve_files(&spec).unwrap().len(), 3);
    });
}

/// A parser that only names the artifact it consumes, and emits one record
/// per file the catalog resolves for it.
struct HiveLister {
    descriptor: ParserDescriptor,
}

impl HiveLister {
    fn new() -> Self {
        static REQUIREMENTS: [Requirement; 1] = [Requirement::Artifact(
            crate::traits::forensic::ArtifactRef::from_static("WindowsUserRegistryFiles"),
        )];
        Self {
            descriptor: ParserDescriptor::new("hive_lister", "Hive lister", "test", "0.0.1")
                .with_requirements(&REQUIREMENTS[..]),
        }
    }
}

impl ArtifactParserFactory for HiveLister {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        let Requirement::Artifact(artifact) = &self.descriptor.requirements[0] else {
            unreachable!("declared above");
        };
        let resolution = ctx.resolve_artifact(&artifact.name)?;
        let source = ctx.register_source(crate::provenance::SourceKey::Synthetic(
            "hive_lister".to_string(),
        ));
        let records: Vec<ForensicResult<ForensicData>> = resolution
            .files
            .into_iter()
            .map(|file| {
                let id = source.mint(ctx.acquisition(), crate::provenance::Recovery::Allocated);
                let mut data = ForensicData::new(ctx.host(), Artifact::Unknown, id);
                data.add_field("file.path", file.path.as_str().to_string().into());
                data.add_field("user.id", file.sid.unwrap_or_default().into());
                Ok(data)
            })
            .collect();
        Ok(ParserRun::Pull(Box::new(records.into_iter())))
    }
}

#[derive(Clone, Default)]
struct Collector(Arc<Mutex<Vec<ForensicData>>>);

impl TriageSink for Collector {
    fn name(&self) -> &str {
        "collector"
    }
    fn on_data(&mut self, data: &ForensicData) -> ForensicResult<()> {
        self.0.lock().unwrap().push(data.clone());
        Ok(())
    }
    fn on_finding(&mut self, _finding: &Finding) -> ForensicResult<()> {
        Ok(())
    }
}

#[test]
fn a_pipeline_parser_resolves_its_declared_artifact_through_the_catalog() {
    let collector = Collector::default();
    let mut pipeline = TriagePipeline::builder()
        .context(TriageContext::new("TEST-HOST", "default"))
        .parser(Arc::new(HiveLister::new()))
        .sink(Box::new(collector.clone()))
        .on_parser_error(ErrorAction::Continue)
        .build()
        .unwrap();

    let result = pipeline.run(&sources(Some(catalog()))).unwrap();

    assert!(result.errors.is_empty(), "{:?}", result.errors);
    let records = collector.0.lock().unwrap();
    let got: Vec<(String, String)> = records
        .iter()
        .map(|r| {
            (
                r.field_as_str("file.path").unwrap().to_string(),
                r.field_as_str("user.id").unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        got,
        vec![
            ("Users/alice/NTUSER.DAT".to_string(), ALICE.to_string()),
            ("Users/bob/NTUSER.DAT".to_string(), BOB.to_string()),
        ]
    );
}

#[test]
fn the_filesystem_trait_object_works_too() {
    let fs: Arc<dyn FileSystem> = Arc::new(vfs());
    let sources = TriageSources::builder().vfs(fs).catalog(catalog()).build();
    let resolution = with_context(&sources, |ctx| {
        ctx.resolve_artifact("WindowsPrefetchFiles").unwrap()
    });
    assert_eq!(
        resolution.files[0].path.as_str(),
        "Windows/Prefetch/CMD.EXE-1234.pf"
    );
}

fn located(sources: &TriageSources, names: &[&str]) -> LocatedFiles {
    with_context(sources, |ctx| ctx.locate_artifact_files(names).unwrap())
}

fn summary(found: &LocatedFiles) -> Vec<(&str, &str, FoundBy)> {
    found
        .files
        .iter()
        .map(|f| (f.path.as_str(), &*f.definition, f.found_by))
        .collect()
}

#[test]
fn a_file_at_its_location_is_found_there_and_names_are_not_searched() {
    let fs = vfs().with_file("Backup/OLD-5678.pf", b"p".to_vec());
    let sources = TriageSources::builder()
        .vfs(Arc::new(fs))
        .catalog(catalog())
        .build();
    let found = located(&sources, &["WindowsPrefetchFiles"]);
    assert_eq!(
        summary(&found),
        vec![(
            "Windows/Prefetch/CMD.EXE-1234.pf",
            "WindowsPrefetchFiles",
            FoundBy::Location
        )]
    );
    assert!(
        !found
            .notes
            .iter()
            .any(|n| n.contains("searched by file name"))
    );
    assert!(found.errors.is_empty(), "{:?}", found.errors);
}

#[test]
fn a_collection_with_its_own_layout_is_searched_by_the_definitions_file_names() {
    // Triage-IR keeps what it copies under its own folders, not where Windows has it.
    let fs = InMemoryVirtualFileSystem::new()
        .with_file(
            "LiveResponseData/CopiedFiles/prefetch/CMD.EXE-1234.pf",
            b"p".to_vec(),
        )
        .with_file(
            "LiveResponseData/CopiedFiles/registry/NTUSER.DAT",
            b"n".to_vec(),
        )
        .with_file("LiveResponseData/BasicInfo/system_info.txt", b"t".to_vec());
    let sources = TriageSources::builder()
        .vfs(Arc::new(fs))
        .catalog(catalog())
        .build();
    let found = located(
        &sources,
        &["WindowsPrefetchFiles", "WindowsUserRegistryFiles"],
    );
    assert_eq!(
        summary(&found),
        vec![
            (
                "LiveResponseData/CopiedFiles/prefetch/CMD.EXE-1234.pf",
                "WindowsPrefetchFiles",
                FoundBy::FileName
            ),
            (
                "LiveResponseData/CopiedFiles/registry/NTUSER.DAT",
                "WindowsUserRegistryFiles",
                FoundBy::FileName
            ),
        ]
    );
    assert!(found.files.iter().all(|f| f.sid.is_none()));
    let note = found
        .notes
        .iter()
        .find(|n| n.contains("searched by file name"))
        .expect("the fallback is noted");
    assert!(
        note.contains("*.pf") && note.contains("NTUSER.DAT"),
        "{note}"
    );
}

#[test]
fn one_definition_at_its_location_means_the_others_are_absent_not_searched_for() {
    // The volume has the layout: a hive under a backup folder is not the user's hive.
    let fs = InMemoryVirtualFileSystem::new()
        .with_file("Windows/Prefetch/CMD.EXE-1234.pf", b"p".to_vec())
        .with_file("Backup/NTUSER.DAT", b"n".to_vec());
    let sources = TriageSources::builder()
        .vfs(Arc::new(fs))
        .catalog(catalog())
        .build();
    let found = located(
        &sources,
        &["WindowsPrefetchFiles", "WindowsUserRegistryFiles"],
    );
    assert_eq!(
        summary(&found),
        vec![(
            "Windows/Prefetch/CMD.EXE-1234.pf",
            "WindowsPrefetchFiles",
            FoundBy::Location
        )]
    );
}

#[test]
fn the_file_name_search_ignores_case() {
    let fs = InMemoryVirtualFileSystem::new()
        // Two levels down, so the unknown-system-root search (`\*\Prefetch\*.pf`) doesn't
        // find it at a location first.
        .with_file("export/copied/PREFETCH/cmd.exe-1234.PF", b"p".to_vec())
        .with_file("export/registry/ntuser.dat", b"n".to_vec());
    let sources = TriageSources::builder()
        .vfs(Arc::new(fs))
        .catalog(catalog())
        .build();
    let found = located(
        &sources,
        &["WindowsPrefetchFiles", "WindowsUserRegistryFiles"],
    );
    assert_eq!(found.files.len(), 2, "{:?}", summary(&found));
    assert!(found.files.iter().all(|f| f.found_by == FoundBy::FileName));
}

#[test]
fn an_unknown_definition_is_an_error_and_the_others_are_still_located() {
    let sources = sources(Some(catalog()));
    let found = located(&sources, &["NoSuchArtifact", "WindowsPrefetchFiles"]);
    assert_eq!(found.files.len(), 1);
    assert_eq!(found.errors.len(), 1);
    assert!(found.errors[0].to_string().contains("NoSuchArtifact"));
}

#[test]
fn locating_without_a_catalog_is_an_error() {
    let sources = sources(None);
    with_context(&sources, |ctx| {
        assert!(
            ctx.locate_artifact_files(&["WindowsPrefetchFiles"])
                .is_err()
        );
    });
}

#[test]
fn an_all_wildcard_file_name_or_a_directory_gives_no_name_to_search() {
    let glob = |pattern: &str, directory: bool| ExpandedGlob {
        pattern: pattern.to_string(),
        sid: None,
        artifact: Cow::Borrowed("Def"),
        directory,
    };
    let expansion = Expansion {
        globs: vec![
            glob(r"\Windows\Temp\*", false),
            glob(r"\Users\*\AppData\**", false),
            glob(r"\Windows\Tasks", true),
            glob(r"\Windows\Prefetch\*.pf", false),
        ],
        ..Expansion::default()
    };
    let names: Vec<String> = file_name_patterns(&expansion)
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    assert_eq!(names, vec!["*.pf".to_string()]);
}
