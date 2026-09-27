use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use crate::{
    artifact::Artifact,
    bridge::CancellationToken,
    catalog::{ArtifactResolution, Os, expand, resolve_expansion},
    context::{ForensicContext, initialize_context},
    core::locator::{EvidenceLocator, LocatorSegment},
    err::ForensicError,
    field::{Field, Ip, Text},
    host_profile::HostProfile,
    pipeline::sources::TriageSources,
    provenance::{Acquisition, ProvenanceStore, SourceHandle, SourceKey},
    secrets::{Secret, SecretRequest},
    traits::forensic::{Requirement, Resolution, TargetSpec, UnavailableReason},
    traits::format::{MountKind, Mounted},
    traits::registry::Registry,
    traits::vfs::{FileSystem, FileSystemExt, SourceKind, VirtualFile},
    utils::time::ForensicTimestamp,
};

/// Shared context for a triage pipeline run.
///
/// Wraps the thread-local `ForensicContext` (host, tenant, artifact metadata)
/// and adds an extensible key-value store that enrichers can read/write and
/// analyzers can read during pipeline execution, plus the [`ProvenanceStore`]
/// for this run — the non-global owner every [`crate::data::ForensicData`]'s
/// provenance resolves against.
///
/// `Clone` is deliberate and load-bearing: `forensic`/`shared` clone as
/// plain owned data (each clone mutates its own copy independently, which
/// is what a per-thread `TriageContext` in the parallel pipeline wants),
/// but `provenance_store` is an `Arc` handle, so every clone shares the
/// **same** underlying [`ProvenanceStore`]. This is what lets
/// [`crate::pipeline::parallel::ParallelPipelineBuilder::context`]
/// propagate one shared store to every task/module that doesn't set its
/// own override, instead of each one silently minting into an independent
/// store no sink can resolve confidence against.
/// A read-only view of a pipeline run's evidence sources, for an
/// [`Analyzer`](crate::pipeline::traits::Analyzer)/[`Enricher`](crate::pipeline::traits::Enricher)
/// that needs to pull bytes during analysis -- e.g. read an embedded payload found at a nested
/// path a [`ContainerFs`](crate::core::fs::ContainerFs)-backed VFS already makes ordinary, hash
/// it, or recurse into it.
///
/// Deliberately **narrower** than [`TriageSources`]:
///
/// - No [`crate::secrets::SecretProvider`]. Every read of a [`crate::secrets::Secret`] must be
///   a deliberate, specifically-named call site inside a parser's `open()` (see
///   [`ParseContext::resolve_secret`]'s own doc); letting an analyzer reach one by accident,
///   from arbitrary analysis code with no naming discipline, defeats that.
/// - No [`MountResolver`](crate::core::resolver::MountResolver). It has interior mutability and
///   a budget shared across the whole run -- letting analyzers mount things through it would
///   silently spend that budget *after* every parser already reported completing, making a
///   run's limits depend on which analyzers happened to be registered. An analyzer that needs to
///   reach inside a container does it through a `ContainerFs`-backed [`Self::vfs`], where the
///   resolver is driven by the filesystem itself, budgets and all.
#[derive(Clone)]
pub struct SourceView {
    vfs: Option<Arc<dyn FileSystem>>,
    registry: Option<Arc<dyn Registry>>,
    acquisition: Acquisition,
    source_kind: Option<SourceKind>,
}

impl Default for SourceView {
    fn default() -> Self {
        Self {
            vfs: None,
            registry: None,
            acquisition: Acquisition::LiveApi,
            source_kind: None,
        }
    }
}

impl SourceView {
    pub(crate) fn from_sources(sources: &TriageSources) -> Self {
        let (acquisition, source_kind) = derive_acquisition(sources);
        Self {
            vfs: sources.vfs().cloned(),
            registry: sources.registry().cloned(),
            acquisition,
            source_kind,
        }
    }

    /// The run's filesystem source, if one was configured. Reaching inside a nested container
    /// (an embedded file inside a document, say) is just an ordinary path on this handle when
    /// it's backed by a `ContainerFs` -- no new plumbing needed here for that.
    pub fn vfs(&self) -> Option<&Arc<dyn FileSystem>> {
        self.vfs.as_ref()
    }

    /// A pre-opened registry source, if one was configured.
    pub fn registry(&self) -> Option<&Arc<dyn Registry>> {
        self.registry.as_ref()
    }

    /// The same value the run's parsers saw on [`ParseContext::acquisition`], so a record an
    /// analyzer derives from a source read here grades identically to one a parser minted from
    /// the same bytes.
    pub fn acquisition(&self) -> Acquisition {
        self.acquisition
    }

    pub fn source_kind(&self) -> Option<SourceKind> {
        self.source_kind
    }

    /// Convenience over `self.vfs().and_then(|fs| fs.as_attributes())`: per-path facts from the
    /// configured VFS's [`PathAttributes`] probe, when both a VFS is configured and its backend
    /// supports the probe. `None` means "can't answer" (no VFS, or this backend doesn't surface
    /// per-path facts) -- never "the path has no attributes"; that distinction is the inner
    /// `ForensicResult`'s to make.
    pub fn attributes(
        &self,
        path: &crate::core::path::FPath,
    ) -> Option<crate::err::ForensicResult<BTreeMap<Text, Field>>> {
        Some(self.vfs.as_ref()?.as_attributes()?.attributes(path))
    }
}

#[derive(Default, Clone)]
pub struct TriageContext {
    forensic: ForensicContext,
    shared: BTreeMap<Text, Field>,
    provenance_store: ProvenanceStore,
    sources: SourceView,
}

impl TriageContext {
    pub fn new(host: impl Into<String>, tenant: impl Into<String>) -> Self {
        Self {
            forensic: ForensicContext {
                host: host.into(),
                tenant: tenant.into(),
                artifact: Artifact::Unknown,
                metadata: BTreeMap::new(),
            },
            shared: BTreeMap::new(),
            provenance_store: ProvenanceStore::new(),
            sources: SourceView::default(),
        }
    }

    pub fn from_forensic_context(ctx: ForensicContext) -> Self {
        Self {
            forensic: ctx,
            shared: BTreeMap::new(),
            provenance_store: ProvenanceStore::new(),
            sources: SourceView::default(),
        }
    }

    /// Access the underlying `ForensicContext`.
    pub fn forensic_context(&self) -> &ForensicContext {
        &self.forensic
    }

    /// The run's evidence sources, read-only -- for an [`Analyzer`](crate::pipeline::traits::Analyzer)
    /// or [`Enricher`](crate::pipeline::traits::Enricher) that needs to pull bytes during
    /// analysis (read an embedded payload, hash it, recurse into a nested path a
    /// [`ContainerFs`](crate::core::fs::ContainerFs)-backed VFS already makes an ordinary path).
    ///
    /// Empty (every accessor returns `None`) until a pipeline installs the real sources via
    /// [`Self::attach_sources`] at run start, or a caller pre-attaches them with
    /// [`Self::with_sources`] -- an analyzer never has to deal with a second layer of `Option`
    /// to tell "no sources configured" apart from "not running inside a pipeline".
    pub fn sources(&self) -> &SourceView {
        &self.sources
    }

    /// Pre-attaches sources to a context driven outside a [`crate::pipeline::TriagePipeline`]
    /// run (a test harness, a bespoke driver). A real pipeline run calls [`Self::attach_sources`]
    /// itself at run start; this is for everything else.
    #[must_use]
    pub fn with_sources(mut self, sources: &TriageSources) -> Self {
        self.sources = SourceView::from_sources(sources);
        self
    }

    /// Installs `sources` as this context's [`SourceView`]. Called by the pipeline at run start,
    /// once per worker (each holding its own `TriageContext` clone, so this never races).
    pub(crate) fn attach_sources(&mut self, sources: &TriageSources) {
        self.sources = SourceView::from_sources(sources);
    }

    /// The [`ProvenanceStore`] for this pipeline run. Cheap to clone (an
    /// `Arc` handle) — register sources and mint/derive/merge against the
    /// clone before or during the run; analyzers read it back via
    /// [`Analyzer::analyze`](crate::pipeline::traits::Analyzer::analyze)'s
    /// `context` parameter.
    pub fn provenance_store(&self) -> ProvenanceStore {
        self.provenance_store.clone()
    }

    /// Read a value from the shared pipeline state.
    pub fn get(&self, key: &str) -> Option<&Field> {
        self.shared.get(key)
    }

    /// Write a value to the shared pipeline state.
    pub fn set(&mut self, key: Text, value: Field) {
        self.shared.insert(key, value);
    }

    /// Remove a value from the shared pipeline state.
    pub fn remove(&mut self, key: &str) -> Option<Field> {
        self.shared.remove(key)
    }

    /// Check if a key exists in the shared state.
    pub fn contains_key(&self, key: &str) -> bool {
        self.shared.contains_key(key)
    }

    /// Ergonomic setter: insert a value with `Into<Field>` conversion.
    pub fn set_into(&mut self, key: &'static str, value: impl Into<Field>) {
        self.shared.insert(Text::Borrowed(key), value.into());
    }

    /// Iterate over all shared state entries.
    pub fn iter(&self) -> impl Iterator<Item = (&Text, &Field)> {
        self.shared.iter()
    }

    /// Get a shared state value as `&str`.
    pub fn get_str(&self, key: &str) -> Option<&str> {
        match self.shared.get(key)? {
            Field::Text(v) => Some(v),
            _ => None,
        }
    }

    /// Get a shared state value as `u64`.
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        match self.shared.get(key)? {
            Field::U64(v) => Some(*v),
            Field::I64(v) => Some(*v as u64),
            _ => None,
        }
    }

    /// Get a shared state value as `i64`.
    pub fn get_i64(&self, key: &str) -> Option<i64> {
        match self.shared.get(key)? {
            Field::I64(v) => Some(*v),
            Field::U64(v) => Some(*v as i64),
            _ => None,
        }
    }

    /// Get a shared state value as `&ForensicTimestamp`.
    pub fn get_date(&self, key: &str) -> Option<&ForensicTimestamp> {
        match self.shared.get(key)? {
            Field::Date(v) => Some(v),
            _ => None,
        }
    }

    /// Get a shared state value as `Ip`.
    pub fn get_ip(&self, key: &str) -> Option<Ip> {
        match self.shared.get(key)? {
            Field::Ip(v) => Some(*v),
            _ => None,
        }
    }

    /// Set the artifact type currently being processed.
    pub fn set_artifact(&mut self, artifact: Artifact) {
        self.forensic.artifact = artifact;
    }

    /// Get the current host name.
    pub fn host(&self) -> &str {
        &self.forensic.host
    }

    /// Get the current tenant.
    pub fn tenant(&self) -> &str {
        &self.forensic.tenant
    }

    /// Install this context into the thread-local `ForensicContext`,
    /// so that logging macros pick it up.
    pub(crate) fn install(&self) {
        initialize_context(self.forensic.clone());
    }
}

/// Everything a parser is allowed to see during one
/// [`ArtifactParserFactory::open`](crate::traits::forensic::ArtifactParserFactory::open) call.
///
/// Deliberately does **not** borrow [`TriageContext`]: the pipeline needs
/// `&mut TriageContext` for enrichers on the same records while a parser's
/// [`ParserRun::Push`](crate::traits::forensic::ParserRun::Push) closure may
/// still be running, so `ParseContext` clones what it needs (an owned host
/// string, an `Arc`-backed [`ProvenanceStore`] handle, a cheap
/// [`CancellationToken`] clone) instead of borrowing.
pub struct ParseContext<'a> {
    sources: &'a TriageSources,
    host: Text,
    provenance: ProvenanceStore,
    acquisition: Acquisition,
    source_kind: Option<SourceKind>,
    cancellation: CancellationToken,
    /// Resolved on first use by [`ParseContext::host_profile`].
    host_profile: OnceLock<Option<HostProfile>>,
}

/// Shared by [`ParseContext::new`] and [`SourceView::from_sources`], so the two can never
/// silently drift on how acquisition is derived from a run's configured sources: an explicit
/// override via [`crate::pipeline::sources::TriageSourcesBuilder::acquisition`] wins if one was
/// set, else it's derived from the VFS's [`SourceKind`], else the conservative floor
/// [`Acquisition::LiveApi`] -- never [`Acquisition::ImageRead`], which would over-claim `High`
/// confidence for evidence that was never actually shown to have come from an image.
pub(crate) fn derive_acquisition(sources: &TriageSources) -> (Acquisition, Option<SourceKind>) {
    let source_kind = sources.vfs().map(|fs| fs.source());
    let acquisition = sources
        .acquisition()
        .or_else(|| source_kind.map(Acquisition::from))
        .unwrap_or(Acquisition::LiveApi);
    (acquisition, source_kind)
}

impl<'a> ParseContext<'a> {
    /// The context a pipeline hands each parser: host and provenance store from `ctx`,
    /// acquisition derived from `sources`.
    ///
    /// Pipelines build this themselves. It is public so a test can drive an
    /// [`ArtifactParserFactory`](crate::traits::forensic::ArtifactParserFactory) directly --
    /// `can_parse`, `open`, then drain the run with
    /// [`collect_run`](crate::utils::testing::collect_run) -- without a whole `TriagePipeline`
    /// and a custom sink.
    ///
    /// ```
    /// use forensic_rs::prelude::*;
    /// use forensic_rs::prelude::testing::{InMemoryVirtualFileSystem, TestingRegistry, collect_run};
    /// use std::sync::Arc;
    ///
    /// let sources = TriageSources::new(
    ///     Arc::new(InMemoryVirtualFileSystem::new()),
    ///     Arc::new(TestingRegistry::new()),
    /// );
    /// let triage = TriageContext::default();
    /// let cancellation = CancellationToken::new();
    /// let ctx = ParseContext::new(&sources, &triage, &cancellation);
    ///
    /// let parser = ContainerInventoryParser::new();
    /// assert!(parser.can_parse(&ctx));
    /// let records = collect_run(parser.open(&ctx).unwrap()).unwrap();
    /// assert!(records.is_empty());
    /// ```
    pub fn new(
        sources: &'a TriageSources,
        ctx: &TriageContext,
        cancellation: &CancellationToken,
    ) -> Self {
        let (acquisition, source_kind) = derive_acquisition(sources);
        Self {
            sources,
            host: Text::Owned(ctx.host().to_string()),
            provenance: ctx.provenance_store(),
            acquisition,
            source_kind,
            cancellation: cancellation.clone(),
            host_profile: OnceLock::new(),
        }
    }

    /// Access the full [`TriageSources`] for this run.
    pub fn sources(&self) -> &'a TriageSources {
        self.sources
    }

    /// The filesystem source, if one was configured.
    pub fn vfs(&self) -> Option<&'a Arc<dyn FileSystem>> {
        self.sources.vfs()
    }

    /// A pre-opened registry source, if one was configured.
    pub fn registry(&self) -> Option<&'a Arc<dyn Registry>> {
        self.sources.registry()
    }

    /// The host this run is analyzing.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// How the underlying bytes were acquired: an explicit override via
    /// [`crate::pipeline::sources::TriageSourcesBuilder::acquisition`] if
    /// one was set, else derived from the VFS's [`SourceKind`], else the
    /// conservative floor [`Acquisition::LiveApi`]. Never defaults to
    /// [`Acquisition::ImageRead`], which would over-claim `High` confidence.
    pub fn acquisition(&self) -> Acquisition {
        self.acquisition
    }

    /// The VFS's [`SourceKind`], if a VFS is configured.
    pub fn source_kind(&self) -> Option<SourceKind> {
        self.source_kind
    }

    /// The cooperative cancellation token for this run. A [`ParserRun::Push`](crate::traits::forensic::ParserRun::Push)
    /// closure doing long stretches of work between emits should poll this.
    pub fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    /// Shorthand for `cancellation().is_cancelled()`.
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    /// Interns `key` in **this run's** [`ProvenanceStore`] and returns a
    /// handle that mints against it. Always prefer this over a
    /// caller-injected `SourceHandle`: a handle minted against a foreign
    /// store can resolve to another record entirely (`ProvenanceId` is a
    /// dense index), not just degrade to `Confidence::Unknown`.
    pub fn register_source(&self, key: SourceKey) -> SourceHandle {
        self.provenance.register_source(key)
    }

    /// The [`ProvenanceStore`] for this run, for `derive`/`merge` after minting.
    pub fn provenance_store(&self) -> &ProvenanceStore {
        &self.provenance
    }

    /// The host's [`HostProfile`], resolved from this run's registry on
    /// first use and cached for the rest of the parser's run. `None` when no
    /// registry is configured.
    pub fn host_profile(&self) -> Option<&HostProfile> {
        self.host_profile
            .get_or_init(|| HostProfile::resolve_from_context(self))
            .as_ref()
    }

    /// Best-effort resolution of a self-contained
    /// [`Requirement`](crate::traits::forensic::Requirement) — one that
    /// needs no caller-chosen target locator to resolve:
    /// - [`Requirement::File`] resolves to the first match of a glob search
    ///   rooted at the VFS; [`ParseContext::resolve_files`] returns them all.
    /// - [`Requirement::Artifact`] resolves to the first file found for the
    ///   definition; [`ParseContext::resolve_artifact`] returns every file,
    ///   registry key and value. It is `Unsupported` without an artifact
    ///   catalog, and an `Err` for a name the catalog doesn't know.
    ///
    /// `Database`/`Registry`/`EventLog` requirements are declarative only:
    /// they document what a parser needs (for coverage reporting and
    /// pre-flight authorization on [`ParserDescriptor::requirements`]
    /// (crate::traits::forensic::ParserDescriptor::requirements)), but
    /// resolving one needs a specific target locator the parser itself
    /// chose — typically after resolving a `File` requirement first, or
    /// after finding the target another way. There is deliberately no
    /// whole-VFS schema scan here; see the mount-resolver design notes on
    /// lazy, on-demand mounting. Once you have a locator and an opened
    /// file, use [`ParseContext::mount`].
    ///
    /// `Secret` requirements never resolve through this method — see
    /// [`ParseContext::resolve_secret`] and its doc for why.
    pub fn resolve(&self, requirement: &Requirement) -> crate::err::ForensicResult<Resolution> {
        match requirement {
            Requirement::File(spec) => {
                let first = self.resolve_files(spec)?.into_iter().next();
                Ok(Self::first_file(first))
            }
            Requirement::Artifact(artifact) => {
                if self.sources.catalog().is_none() {
                    return Ok(Resolution::Unavailable(UnavailableReason::Unsupported));
                }
                let resolution = self.resolve_artifact(&artifact.name)?;
                let first = resolution.files.into_iter().next().map(|f| f.locator);
                Ok(Self::first_file(first))
            }
            Requirement::Database(_) | Requirement::Registry(_) | Requirement::EventLog(_) => {
                Ok(Resolution::Unavailable(UnavailableReason::Unsupported))
            }
            Requirement::Secret(_) => Ok(Resolution::Unavailable(UnavailableReason::Unsupported)),
        }
    }

    fn first_file(locator: Option<EvidenceLocator>) -> Resolution {
        match locator {
            Some(locator) => Resolution::Resolved(Mounted::File(locator)),
            None => Resolution::Unavailable(UnavailableReason::NotPresent),
        }
    }

    /// Every file matching `spec`'s glob, in walk order. Empty when nothing
    /// matches or no VFS is configured.
    pub fn resolve_files(
        &self,
        spec: &TargetSpec,
    ) -> crate::err::ForensicResult<Vec<EvidenceLocator>> {
        let Some(vfs) = self.sources.vfs() else {
            return Ok(Vec::new());
        };
        Ok(vfs
            .glob(&spec.glob)?
            .into_iter()
            .map(|path| EvidenceLocator::root().push(LocatorSegment::Path(path)))
            .collect())
    }

    /// Every location of the artifact definition `name` (a name or alias
    /// in this run's catalog) found in the evidence: files, registry keys
    /// and values, plus what couldn't be resolved and why.
    ///
    /// The definition is expanded with [`host_profile`](Self::host_profile)
    /// (an empty profile when there is no registry, so every placeholder
    /// falls back to a search pattern) for the OS it targets: Windows when
    /// it supports Windows, else its first supported OS. Use
    /// [`resolve_artifact_for`](Self::resolve_artifact_for) to choose.
    ///
    /// An empty result with no `errors` means the artifact is not present.
    /// `Err` means there is no catalog, or it doesn't know `name`.
    pub fn resolve_artifact(&self, name: &str) -> crate::err::ForensicResult<ArtifactResolution> {
        let os = {
            let (_, def) = self.artifact_definition(name)?;
            if def.supports(Os::Windows) {
                Os::Windows
            } else {
                def.supported_os.first().copied().unwrap_or(Os::Windows)
            }
        };
        self.resolve_artifact_for(name, os)
    }

    /// [`resolve_artifact`](Self::resolve_artifact) for a given OS.
    pub fn resolve_artifact_for(
        &self,
        name: &str,
        os: Os,
    ) -> crate::err::ForensicResult<ArtifactResolution> {
        let (catalog, def) = self.artifact_definition(name)?;
        let empty = HostProfile::default();
        let host = self.host_profile().unwrap_or(&empty);
        let expansion = expand(def, catalog.as_ref(), host, os);
        Ok(resolve_expansion(
            expansion,
            self.sources.vfs().map(|fs| fs.as_ref()),
            self.sources.registry().map(|reg| reg.as_ref()),
        ))
    }

    /// The run's catalog and its definition for `name`.
    fn artifact_definition(
        &self,
        name: &str,
    ) -> crate::err::ForensicResult<(
        &'a Arc<dyn crate::catalog::ArtifactCatalog>,
        &'a crate::catalog::ArtifactDefinition,
    )> {
        let catalog = self.sources.catalog().ok_or_else(|| {
            ForensicError::other("catalog", format!("no artifact catalog configured to resolve {name}"))
        })?;
        let def = catalog.get(name).ok_or_else(|| {
            ForensicError::other("catalog", format!("unknown artifact definition: {name}"))
        })?;
        Ok((catalog, def))
    }

    /// Mounts an already-opened file at `locator` as `want`, through this
    /// run's [`crate::core::resolver::MountResolver`] (see
    /// [`TriageSources::mount_resolver`]). The mount-resolver-level
    /// counterpart to [`ParseContext::resolve`]: use this once a parser has
    /// chosen a specific target (e.g. via `resolve(Requirement::File(..))`
    /// or its own logic) and wants to interpret those bytes as a database,
    /// registry hive, event log, or nested filesystem.
    pub fn mount(
        &self,
        locator: &EvidenceLocator,
        file: Box<dyn VirtualFile>,
        want: MountKind,
    ) -> crate::err::ForensicResult<Mounted> {
        let vfs = self.sources.vfs().ok_or_else(|| {
            ForensicError::other("ParseContext::mount", "no VFS configured".to_string())
        })?;
        let resolver = self.sources.mount_resolver().ok_or_else(|| {
            ForensicError::other(
                "ParseContext::mount",
                "no MountResolver configured".to_string(),
            )
        })?;
        resolver.resolve(vfs, locator, file, Some(want), &self.cancellation)
    }

    /// Requests key material from this run's [`crate::secrets::SecretProvider`],
    /// if one is configured. Kept separate from [`ParseContext::resolve`]
    /// so a [`Secret`] never flows through a `Resolution`/`Mounted` value
    /// that other code might match on, log, or print for diagnostics —
    /// every read of the returned value should be a deliberate,
    /// specifically-named call site.
    ///
    /// Returning `None` — no provider configured, or the provider declined
    /// — means the caller must still emit its record with the ciphertext
    /// present, marked undecrypted, and raise a `Finding`. Never skip the
    /// record silently.
    pub fn resolve_secret(&self, request: &SecretRequest) -> Option<Secret> {
        self.sources.secrets()?.provide(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_context_with_host_and_tenant() {
        let ctx = TriageContext::new("WORKSTATION01", "ACME-Corp");
        assert_eq!(ctx.host(), "WORKSTATION01");
        assert_eq!(ctx.tenant(), "ACME-Corp");
    }

    #[test]
    fn should_read_write_shared_state() {
        let mut ctx = TriageContext::default();
        ctx.set(
            Text::Borrowed("timezone"),
            Field::Text(Text::Borrowed("UTC")),
        );
        assert!(ctx.contains_key("timezone"));
        match ctx.get("timezone") {
            Some(Field::Text(v)) => assert_eq!(v.as_ref(), "UTC"),
            other => panic!("expected Field::Text(\"UTC\"), got {:?}", other),
        }
        ctx.remove("timezone");
        assert!(!ctx.contains_key("timezone"));
    }

    #[test]
    fn should_install_forensic_context() {
        let ctx = TriageContext::new("SERVER01", "TenantX");
        ctx.install();
        let fc = crate::context::context();
        assert_eq!(fc.host, "SERVER01");
        assert_eq!(fc.tenant, "TenantX");
    }
}
