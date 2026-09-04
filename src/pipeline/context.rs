use std::collections::BTreeMap;
use std::sync::Arc;

use crate::{
    artifact::Artifact,
    bridge::CancellationToken,
    context::{initialize_context, ForensicContext},
    core::locator::{EvidenceLocator, LocatorSegment},
    err::ForensicError,
    field::{Field, Ip, Text},
    pipeline::sources::TriageSources,
    provenance::{Acquisition, ProvenanceStore, SourceHandle, SourceKey},
    secrets::{Secret, SecretRequest},
    traits::forensic::{Requirement, Resolution, TargetSpec, UnavailableReason},
    traits::format::{Mounted, MountKind},
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
#[derive(Default, Clone)]
pub struct TriageContext {
    forensic: ForensicContext,
    shared: BTreeMap<Text, Field>,
    provenance_store: ProvenanceStore,
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
        }
    }

    pub fn from_forensic_context(ctx: ForensicContext) -> Self {
        Self {
            forensic: ctx,
            shared: BTreeMap::new(),
            provenance_store: ProvenanceStore::new(),
        }
    }

    /// Access the underlying `ForensicContext`.
    pub fn forensic_context(&self) -> &ForensicContext {
        &self.forensic
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
}

impl<'a> ParseContext<'a> {
    pub(crate) fn new(
        sources: &'a TriageSources,
        ctx: &TriageContext,
        cancellation: &CancellationToken,
    ) -> Self {
        let source_kind = sources.vfs().map(|fs| fs.source());
        let acquisition = sources
            .acquisition()
            .or_else(|| source_kind.map(Acquisition::from))
            .unwrap_or(Acquisition::LiveApi);
        Self {
            sources,
            host: Text::Owned(ctx.host().to_string()),
            provenance: ctx.provenance_store(),
            acquisition,
            source_kind,
            cancellation: cancellation.clone(),
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

    /// Best-effort resolution of a self-contained
    /// [`Requirement`](crate::traits::forensic::Requirement) — one that
    /// needs no caller-chosen target locator to resolve. Today that is only
    /// [`Requirement::File`], resolved via a glob search rooted at the VFS.
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
            Requirement::File(spec) => self.resolve_file(spec),
            Requirement::Database(_) | Requirement::Registry(_) | Requirement::EventLog(_) => {
                Ok(Resolution::Unavailable(UnavailableReason::Unsupported))
            }
            Requirement::Secret(_) => Ok(Resolution::Unavailable(UnavailableReason::Unsupported)),
        }
    }

    fn resolve_file(&self, spec: &TargetSpec) -> crate::err::ForensicResult<Resolution> {
        let Some(vfs) = self.sources.vfs() else {
            return Ok(Resolution::Unavailable(UnavailableReason::NotPresent));
        };
        let matches = vfs.glob(&spec.glob)?;
        let Some(path) = matches.into_iter().next() else {
            return Ok(Resolution::Unavailable(UnavailableReason::NotPresent));
        };
        let locator = EvidenceLocator::root().push(LocatorSegment::Path(path));
        Ok(Resolution::Resolved(Mounted::File(locator)))
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
        let vfs = self
            .sources
            .vfs()
            .ok_or_else(|| ForensicError::other("ParseContext::mount", "no VFS configured".to_string()))?;
        let resolver = self.sources.mount_resolver().ok_or_else(|| {
            ForensicError::other("ParseContext::mount", "no MountResolver configured".to_string())
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
