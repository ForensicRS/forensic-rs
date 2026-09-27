//! Generic, format-agnostic inventory of container-flagged entries reachable through a run's
//! configured VFS.
//!
//! [`ContainerInventoryParser`] knows no format itself: it walks the VFS looking for
//! [`FileAttributes::CONTAINER`]-flagged entries (an OLE document, an archive, whatever the
//! run's `MountResolver` has a factory for -- see `crate::core::fs::ContainerFs`, which is what
//! sets that bit) and, when the backend supports it, forwards [`PathAttributes`]'s per-path facts
//! verbatim. One registration therefore covers every format the resolver knows, with zero
//! per-format code living here.

use compact_str::CompactString;

use crate::{
    artifact::{Artifact, CommonArtifact},
    core::fs::walk::WalkOptions,
    core::locator::{EvidenceLocator, LocatorSegment},
    core::path::{FPath, FPathBuf},
    data::ForensicData,
    dictionary,
    err::ForensicResult,
    pipeline::context::ParseContext,
    provenance::{Acquisition, AnomalyDetail, AnomalyFlags, Anomalies, Parsed, ProvenanceStore, Recovery},
    traits::forensic::{ArtifactParserFactory, ParserDescriptor, ParserRun},
    traits::vfs::{DirEntry, FileAttributes, FileSystem, FileSystemExt, VFileType},
};

/// `container.record_type` value for a `FileAttributes::CONTAINER`-flagged entry's own record.
pub const RECORD_TYPE_CONTAINER: &str = "container";
/// `container.record_type` value for an entry reached by transparently descending into a
/// container (a stream, a storage, an archive member, ...).
pub const RECORD_TYPE_MEMBER: &str = "container.member";

/// The core-owned field keys [`ContainerInventoryParser`] writes on every record. Checked before
/// a format's own [`PathAttributes`] facts are inserted, so a format that happens to use one of
/// these names never silently shadows it -- see [`build_record`].
const CORE_KEYS: &[&str] = &[
    dictionary::FILE_PATH,
    dictionary::FILE_NAME,
    dictionary::FILE_SIZE,
    dictionary::FILE_TYPE,
    dictionary::FILE_INODE,
    dictionary::FILE_CREATED,
    dictionary::FILE_ACCESSED,
    dictionary::FILE_MODIFIED,
    dictionary::FILE_CHANGED,
    "container.record_type",
    "container.parent",
    "container.timestamp",
    "container.error",
];

/// Walks a run's configured VFS and emits one record per [`FileAttributes::CONTAINER`]-flagged
/// entry, plus one per entry reached by transparently descending into it. Parses nothing itself
/// -- every fact beyond generic file metadata comes from [`FileSystem::as_attributes`]
/// ([`crate::traits::vfs::PathAttributes`]), forwarded verbatim.
///
/// Stateless (`&self`); all per-run state lives in the [`ParserRun::Push`] closure
/// [`Self::open`] returns, so one instance behind an `Arc` serves the serial pipeline and every
/// parallel worker.
///
/// A per-item failure (a corrupt container's `metadata`/`attributes` call erroring) never fails
/// the whole run: it becomes a record carrying a `container.error` field and a `TRUNCATED`
/// anomaly (via [`ForensicData::set_parsed`]) instead of a [`crate::err::ForensicError`] --
/// consistent with the pipeline's default [`crate::pipeline::ErrorAction::Continue`] contract, and
/// visible to a downstream analyzer without special-casing errors.
pub struct ContainerInventoryParser {
    descriptor: ParserDescriptor,
    max_depth: Option<u32>,
}

impl Default for ContainerInventoryParser {
    fn default() -> Self {
        Self {
            descriptor: ParserDescriptor::new(
                "core.container_inventory",
                "Container Inventory",
                "Walks the configured VFS and emits a record for every container-flagged entry \
                 (an OLE document, an archive, ...) and its members, carrying whatever facts \
                 the backend's PathAttributes probe surfaces",
                env!("CARGO_PKG_VERSION"),
            )
            // Never leave this empty: an empty list means "every artifact", which would inject
            // this parser into every auto-matched `AnalysisModule`.
            .with_artifacts(&[Artifact::Common(CommonArtifact::ContainerInventory)][..]),
            max_depth: None,
        }
    }
}

impl ContainerInventoryParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Caps how many boundaries deep the walk descends past the outermost container. `None`
    /// (the default) defers entirely to the VFS's own `MountResolver` limits (`ContainerFs`
    /// enforces `Limits::max_nesting_depth` itself).
    #[must_use]
    pub fn with_max_depth(mut self, max_depth: Option<u32>) -> Self {
        self.max_depth = max_depth;
        self
    }
}

impl ArtifactParserFactory for ContainerInventoryParser {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    fn can_parse(&self, ctx: &ParseContext<'_>) -> bool {
        ctx.vfs().is_some()
    }

    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        let Some(fs) = ctx.vfs().cloned() else {
            return Ok(ParserRun::push(|_| Ok(())));
        };
        let host = ctx.host().to_string();
        let acquisition = ctx.acquisition();
        let provenance = ctx.provenance_store().clone();
        let cancellation = ctx.cancellation().clone();
        let max_depth = self.max_depth;

        Ok(ParserRun::push(move |out| {
            let opts = WalkOptions::default()
                .with_descend_into_containers(true)
                .with_max_depth(max_depth);

            // Depth/parent are recovered structurally from walk order, never tracked
            // separately: `Walk` is depth-first and yields a container before its own
            // children, and `FPath::starts_with` is component-wise (so "report.docx" can
            // never falsely match a stack frame for "report.doc"). Popping frames whose
            // path is no longer a prefix of the current entry is what makes this correct
            // across sibling containers and nested ones alike.
            let mut stack: Vec<ContainerFrame> = Vec::new();

            for entry in fs.walk(FPath::new(""), &opts) {
                if cancellation.is_cancelled() {
                    return Ok(());
                }
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(e) => {
                        if out.emit(Err(e)).is_stop() {
                            return Ok(());
                        }
                        continue;
                    }
                };

                while let Some(top) = stack.last() {
                    if entry.path.as_path().starts_with(top.path.as_path()) {
                        break;
                    }
                    stack.pop();
                }

                let record = if is_container_entry(fs.as_ref(), &entry) {
                    let locator = match stack.last() {
                        Some(top) => {
                            let tail = relative_tail(top.path.as_path(), entry.path.as_path());
                            top.locator.clone().push(LocatorSegment::Path(tail))
                        }
                        None => EvidenceLocator::root().push(LocatorSegment::Path(entry.path.clone())),
                    };
                    let record = build_record(
                        fs.as_ref(),
                        &host,
                        acquisition,
                        &provenance,
                        &entry,
                        RECORD_TYPE_CONTAINER,
                        None,
                        &locator,
                    );
                    stack.push(ContainerFrame {
                        path: entry.path.clone(),
                        locator,
                    });
                    Some(record)
                } else {
                    stack.last().map(|top| {
                        let tail = relative_tail(top.path.as_path(), entry.path.as_path());
                        let locator = top.locator.clone().push(LocatorSegment::Path(tail));
                        build_record(
                            fs.as_ref(),
                            &host,
                            acquisition,
                            &provenance,
                            &entry,
                            RECORD_TYPE_MEMBER,
                            Some(&top.path),
                            &locator,
                        )
                    })
                };

                if let Some(record) = record {
                    if out.emit(Ok(record)).is_stop() {
                        return Ok(());
                    }
                }
            }
            Ok(())
        }))
    }
}

/// One open container boundary on the walk stack: its transparent path (for the
/// `starts_with`-based pop check) and the [`EvidenceLocator`] hop that reached it.
struct ContainerFrame {
    path: FPathBuf,
    locator: EvidenceLocator,
}

/// `full` with `base`'s components stripped off the front -- `base` must already be a
/// component-wise prefix of `full` (callers only reach this after a `starts_with` check).
fn relative_tail(base: &FPath, full: &FPath) -> FPathBuf {
    let skip = base.components().count();
    let mut tail = FPathBuf::new();
    for component in full.components().skip(skip) {
        tail.push(component.as_str());
    }
    tail
}

fn is_container_entry(fs: &dyn FileSystem, entry: &DirEntry) -> bool {
    if let Some(meta) = entry.metadata.as_ref() {
        return meta.attributes.contains(FileAttributes::CONTAINER);
    }
    fs.metadata(entry.path.as_path())
        .map(|meta| meta.attributes.contains(FileAttributes::CONTAINER))
        .unwrap_or(false)
}

fn file_type_str(file_type: VFileType) -> &'static str {
    match file_type {
        VFileType::File => "file",
        VFileType::Directory => "directory",
        VFileType::Symlink => "symlink",
    }
}

/// Builds one record for `entry`. Never fails: a `metadata`/`attributes` error on a corrupt
/// container becomes a `container.error` field plus a `TRUNCATED` anomaly on the record instead
/// of aborting it (see the struct-level docs on [`ContainerInventoryParser`]).
#[allow(clippy::too_many_arguments)]
fn build_record(
    fs: &dyn FileSystem,
    host: &str,
    acquisition: Acquisition,
    provenance: &ProvenanceStore,
    entry: &DirEntry,
    record_type: &'static str,
    parent: Option<&FPathBuf>,
    locator: &EvidenceLocator,
) -> ForensicData {
    let source = provenance.register_source(locator.to_source_key());
    let id = source.mint(acquisition, Recovery::Allocated);

    let mut data = ForensicData::new(
        host,
        Artifact::Common(CommonArtifact::ContainerInventory),
        id,
    );

    let mut anomalies = Anomalies::empty();
    let mut errors: Vec<String> = Vec::new();

    // Format keys pass through verbatim, before any core key is written -- so a format that
    // happens to reuse a core field name never silently shadows it; a collision is logged and
    // the core key (written below) wins.
    if let Some(probe) = fs.as_attributes() {
        match probe.attributes(entry.path.as_path()) {
            Ok(attrs) => {
                for (key, value) in attrs {
                    if CORE_KEYS.contains(&key.as_ref()) {
                        crate::warn!(
                            "container inventory: attribute key '{key}' at {} collides with a core field, core value wins",
                            entry.path.as_path()
                        );
                    }
                    data.insert(key, value);
                }
            }
            Err(e) => {
                errors.push(format!("attributes: {e}"));
                anomalies.add(AnomalyFlags::TRUNCATED);
            }
        }
    }

    let meta = entry
        .metadata
        .clone()
        .map(Ok)
        .unwrap_or_else(|| fs.metadata(entry.path.as_path()));
    match meta {
        Ok(meta) => {
            data.set(dictionary::FILE_SIZE, meta.size);
            data.set(dictionary::FILE_TYPE, file_type_str(meta.file_type));
            if let Some(file_id) = meta.id {
                data.set(dictionary::FILE_INODE, file_id.as_u128().to_string());
            }
            if let Some(t) = meta.times.created {
                data.set(dictionary::FILE_CREATED, t);
            }
            if let Some(t) = meta.times.accessed {
                data.set(dictionary::FILE_ACCESSED, t);
            }
            if let Some(t) = meta.times.modified {
                // A documented verbatim alias, never synthesized: whatever the backend
                // reports as `file.mtime` is exactly what `container.timestamp` carries.
                data.set(dictionary::FILE_MODIFIED, t);
                data.set("container.timestamp", t);
            }
            if let Some(t) = meta.times.changed {
                data.set(dictionary::FILE_CHANGED, t);
            }
        }
        Err(e) => {
            errors.push(format!("metadata: {e}"));
            anomalies.add(AnomalyFlags::TRUNCATED);
        }
    }

    data.set(dictionary::FILE_PATH, entry.path.as_path().as_str().to_string());
    if let Some(name) = entry.file_name() {
        data.set(dictionary::FILE_NAME, name.to_string());
    }
    data.set("container.record_type", record_type);
    if let Some(parent) = parent {
        data.set("container.parent", parent.as_path().as_str().to_string());
    }

    if !anomalies.flags().is_empty() {
        for message in &errors {
            anomalies.add_detail(AnomalyDetail {
                kind: AnomalyFlags::TRUNCATED,
                message: CompactString::from(message.as_str()),
            });
        }
        let message = errors.join("; ");
        data.set_parsed("container.error", Parsed::with_anomalies(message, anomalies, id));
    }

    data
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    use crate::{
        bridge::CancellationToken,
        core::path::FPath,
        data::ForensicData,
        err::{ForensicError, ForensicResult},
        field::{Field, Text},
        pipeline::{
            context::TriageContext, finding::Finding, sources::TriageSources,
            traits::TriageSink, ErrorAction, TriagePipeline,
        },
        provenance::{Acquisition, Confidence},
        traits::vfs::{
            CaseSensitivity, DirEntry, FileAttributes, FileSystem, PathAttributes, SourceKind,
            VMetadata,
        },
        utils::testing::{InMemoryVirtualFileSystem, TestingRegistry},
    };

    use super::{ContainerInventoryParser, RECORD_TYPE_CONTAINER, RECORD_TYPE_MEMBER};

    /// A minimal stand-in for a `ContainerFs`-backed VFS: flags one path
    /// `FileAttributes::CONTAINER` and answers `PathAttributes` with canned facts, without
    /// pulling in the real mount-resolver machinery -- this module only needs to prove
    /// `ContainerInventoryParser` reacts correctly to the bit and the probe, not that
    /// `ContainerFs` itself sets them right (that's `core::fs::container`'s own test suite).
    struct FakeContainerFs {
        inner: InMemoryVirtualFileSystem,
        containers: BTreeSet<String>,
        attrs: BTreeMap<String, BTreeMap<Text, Field>>,
        fail_metadata_for: BTreeSet<String>,
    }

    impl FileSystem for FakeContainerFs {
        fn open(&self, path: &FPath) -> ForensicResult<Box<dyn crate::traits::vfs::VirtualFile>> {
            self.inner.open(path)
        }
        fn metadata(&self, path: &FPath) -> ForensicResult<VMetadata> {
            if self.fail_metadata_for.contains(path.as_str()) {
                return Err(ForensicError::path_not_found(path.to_string()));
            }
            let mut meta = self.inner.metadata(path)?;
            if self.containers.contains(path.as_str()) {
                meta.attributes |= FileAttributes::CONTAINER;
            }
            Ok(meta)
        }
        fn read_dir(
            &self,
            path: &FPath,
        ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<DirEntry>> + '_>> {
            self.inner.read_dir(path)
        }
        fn source(&self) -> SourceKind {
            SourceKind::Memory
        }
        fn case_sensitivity(&self) -> CaseSensitivity {
            CaseSensitivity::Sensitive
        }
        fn as_attributes(&self) -> Option<&dyn PathAttributes> {
            Some(self)
        }
    }

    impl PathAttributes for FakeContainerFs {
        fn attributes(&self, path: &FPath) -> ForensicResult<BTreeMap<Text, Field>> {
            Ok(self.attrs.get(path.as_str()).cloned().unwrap_or_default())
        }
    }

    fn fake_fs() -> Arc<FakeContainerFs> {
        let inner = InMemoryVirtualFileSystem::new()
            .with_file("report.doc", Vec::new())
            .with_file("report.doc/Macros/VBA/Module1", b"Sub Foo()\nEnd Sub\n".to_vec())
            .with_file("plain.txt", b"just a file, not a container".to_vec());

        let mut attrs = BTreeMap::new();
        attrs.insert(
            "report.doc".to_string(),
            BTreeMap::from([(Text::Borrowed("ole.class_id"), Field::Text(Text::Borrowed("{00020906-0000-0000-C000-000000000046}")))]),
        );
        attrs.insert(
            "report.doc/Macros/VBA/Module1".to_string(),
            BTreeMap::from([(Text::Borrowed("ole.stream.name"), Field::Text(Text::Borrowed("Module1")))]),
        );

        Arc::new(FakeContainerFs {
            inner,
            containers: BTreeSet::from(["report.doc".to_string()]),
            attrs,
            fail_metadata_for: BTreeSet::new(),
        })
    }

    #[derive(Clone, Default)]
    struct RecordCollector(Arc<std::sync::Mutex<Vec<ForensicData>>>);

    impl TriageSink for RecordCollector {
        fn name(&self) -> &str {
            "record_collector"
        }
        fn on_data(&mut self, data: &ForensicData) -> ForensicResult<()> {
            self.0.lock().unwrap().push(data.clone());
            Ok(())
        }
        fn on_finding(&mut self, _finding: &Finding) -> ForensicResult<()> {
            Ok(())
        }
    }

    fn run(fs: Arc<dyn FileSystem>) -> (Vec<ForensicData>, crate::pipeline::PipelineResult, crate::provenance::ProvenanceStore) {
        let context = TriageContext::new("TEST-HOST", "default");
        let store = context.provenance_store();
        let collector = RecordCollector::default();

        let mut pipeline = TriagePipeline::builder()
            .context(context)
            .parser(Arc::new(ContainerInventoryParser::new()))
            .sink(Box::new(collector.clone()))
            .on_parser_error(ErrorAction::Continue)
            .build()
            .unwrap();

        let sources = TriageSources::builder().vfs(fs).acquisition(Acquisition::ImageRead).build();
        let result = pipeline.run(&sources).unwrap();
        let records = collector.0.lock().unwrap().clone();
        (records, result, store)
    }

    fn field_str<'a>(data: &'a ForensicData, key: &str) -> Option<&'a str> {
        data.field_as_str(key)
    }

    #[test]
    fn emits_container_and_member_records_with_verbatim_attributes() {
        let (records, result, store) = run(fake_fs());

        assert!(result.errors.is_empty());
        assert!(!records.is_empty());

        for record in &records {
            assert_ne!(
                record.confidence(&store),
                Confidence::Unknown,
                "every record must resolve to a real confidence, not Unknown"
            );
        }

        let record_types: BTreeSet<&str> = records
            .iter()
            .filter_map(|d| field_str(d, "container.record_type"))
            .collect();
        assert!(record_types.contains(RECORD_TYPE_CONTAINER));
        assert!(record_types.contains(RECORD_TYPE_MEMBER));
        assert!(record_types.len() > 1, "expected more than one record_type, got {record_types:?}");

        let container = records
            .iter()
            .find(|d| field_str(d, "container.record_type") == Some(RECORD_TYPE_CONTAINER))
            .expect("a container record");
        assert_eq!(field_str(container, "file.path"), Some("report.doc"));
        assert_eq!(field_str(container, "ole.class_id"), Some("{00020906-0000-0000-C000-000000000046}"));

        let member = records
            .iter()
            .find(|d| field_str(d, "file.path") == Some("report.doc/Macros/VBA/Module1"))
            .expect("a member record for the deep stream path");
        assert_eq!(field_str(member, "container.record_type"), Some(RECORD_TYPE_MEMBER));
        assert_eq!(field_str(member, "container.parent"), Some("report.doc"));
        assert_eq!(field_str(member, "ole.stream.name"), Some("Module1"));

        // An ordinary file that is neither a container nor inside one gets no record at all.
        assert!(records.iter().all(|d| field_str(d, "file.path") != Some("plain.txt")));
    }

    #[test]
    fn a_metadata_failure_becomes_an_anomaly_not_a_pipeline_error() {
        let mut fs = fake_fs();
        Arc::get_mut(&mut fs).unwrap().fail_metadata_for.insert("report.doc/Macros/VBA/Module1".to_string());
        let fs: Arc<dyn FileSystem> = fs;

        let (records, result, store) = run(fs);
        assert!(result.errors.is_empty(), "a corrupt member must not surface as a pipeline error");

        let member = records
            .iter()
            .find(|d| field_str(d, "file.path") == Some("report.doc/Macros/VBA/Module1"))
            .expect("a member record for the deep stream path");
        assert!(field_str(member, "container.error").unwrap_or_default().contains("metadata"));
        assert_eq!(
            member.confidence(&store),
            Confidence::Low,
            "a TRUNCATED anomaly caps confidence at Low"
        );
    }

    #[test]
    fn no_vfs_configured_yields_no_records_and_no_error() {
        let context = TriageContext::new("TEST-HOST", "default");
        let collector = RecordCollector::default();
        let mut pipeline = TriagePipeline::builder()
            .context(context)
            .parser(Arc::new(ContainerInventoryParser::new()))
            .sink(Box::new(collector.clone()))
            .build()
            .unwrap();

        let sources = TriageSources::builder().registry(Arc::new(TestingRegistry::new())).build();
        let result = pipeline.run(&sources).unwrap();
        assert_eq!(result.items_processed, 0);
        assert!(result.parsers_skipped.contains(&"core.container_inventory".to_string()));
        assert!(collector.0.lock().unwrap().is_empty());
    }

    #[test]
    fn cancellation_stops_the_walk_early() {
        let fs = fake_fs();
        let context = TriageContext::new("TEST-HOST", "default");
        let collector = RecordCollector::default();
        let mut pipeline = TriagePipeline::builder()
            .context(context)
            .parser(Arc::new(ContainerInventoryParser::new()))
            .sink(Box::new(collector.clone()))
            .build()
            .unwrap();

        let sources = TriageSources::builder().vfs(fs as Arc<dyn FileSystem>).build();
        let token = CancellationToken::new();
        token.cancel();
        let result = pipeline.run_with_cancellation(&sources, token).unwrap();
        assert_eq!(result.items_processed, 0);
    }
}
