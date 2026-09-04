use crate::core::resolver::MountResolver;
use crate::provenance::Acquisition;
use crate::secrets::SecretProvider;
use crate::traits::{registry::Registry, vfs::FileSystem};
use std::sync::Arc;

/// Holds the data sources available to parsers during pipeline execution.
///
/// Provides access to the evidence containers that parsers inspect. Database,
/// event-log, and registry-hive files discovered inside a VFS are opened with
/// reader factories rather than stored here as already-open readers.
///
/// Sources are optional. `registry` is retained for live-system and legacy
/// callers that already own a reader. Registry hives discovered in a VFS
/// should be opened through `RegistryReaderFactory`, like other derived files.
///
/// `Arc`, not `Box`: both `FileSystem` and `Registry` are `Send + Sync` with
/// `&self`-based reads, so the same already-open source can be shared
/// (cloned cheaply) across parallel pipeline workers instead of being
/// re-opened per task (RFC 0001 §1, P5).
///
/// `Clone` is cheap — every field is an `Option<Arc<..>>` or `Copy` value —
/// which is what lets [`crate::evidence::EvidenceItem`] cache one resolved
/// `TriageSources` and hand back a fresh, independently-owned wrapper
/// around the same underlying sources on every access.
#[derive(Clone)]
pub struct TriageSources {
    vfs: Option<Arc<dyn FileSystem>>,
    registry: Option<Arc<dyn Registry>>,
    acquisition: Option<Acquisition>,
    mount_resolver: Option<Arc<MountResolver>>,
    secrets: Option<Arc<dyn SecretProvider>>,
}

impl TriageSources {
    /// Create sources with both VFS and registry.
    pub fn new(vfs: Arc<dyn FileSystem>, registry: Arc<dyn Registry>) -> Self {
        Self {
            vfs: Some(vfs),
            registry: Some(registry),
            acquisition: None,
            mount_resolver: None,
            secrets: None,
        }
    }

    /// Start building sources with a fluent API.
    pub fn builder() -> TriageSourcesBuilder {
        TriageSourcesBuilder::default()
    }

    /// Access the filesystem, if available.
    pub fn vfs(&self) -> Option<&Arc<dyn FileSystem>> {
        self.vfs.as_ref()
    }

    /// Access a pre-opened live or compatibility registry reader, if available.
    pub fn registry(&self) -> Option<&Arc<dyn Registry>> {
        self.registry.as_ref()
    }

    /// Whether a VFS source has been configured.
    pub fn has_vfs(&self) -> bool {
        self.vfs.is_some()
    }

    /// Whether a pre-opened registry source has been configured.
    pub fn has_registry(&self) -> bool {
        self.registry.is_some()
    }

    /// The explicit [`Acquisition`] override for this run, if the caller who
    /// mounted the evidence set one via
    /// [`TriageSourcesBuilder::acquisition`]. `None` means "derive it from
    /// the VFS's `SourceKind`" — see [`crate::pipeline::context::ParseContext::acquisition`].
    pub fn acquisition(&self) -> Option<Acquisition> {
        self.acquisition
    }

    /// The mount resolver for this run, if configured — used by
    /// [`crate::pipeline::context::ParseContext::resolve`] to satisfy
    /// [`crate::traits::forensic::Requirement::File`],
    /// `Database`/`Registry`/`EventLog` requirements against nested
    /// containers.
    pub fn mount_resolver(&self) -> Option<&Arc<MountResolver>> {
        self.mount_resolver.as_ref()
    }

    /// The secret provider for this run, if configured — used to satisfy
    /// [`crate::traits::forensic::Requirement::Secret`].
    pub fn secrets(&self) -> Option<&Arc<dyn SecretProvider>> {
        self.secrets.as_ref()
    }
}

/// Builder for constructing `TriageSources` with the available evidence.
#[derive(Default)]
pub struct TriageSourcesBuilder {
    vfs: Option<Arc<dyn FileSystem>>,
    registry: Option<Arc<dyn Registry>>,
    acquisition: Option<Acquisition>,
    mount_resolver: Option<Arc<MountResolver>>,
    secrets: Option<Arc<dyn SecretProvider>>,
}

impl TriageSourcesBuilder {
    pub fn vfs(mut self, vfs: Arc<dyn FileSystem>) -> Self {
        self.vfs = Some(vfs);
        self
    }

    pub fn registry(mut self, registry: Arc<dyn Registry>) -> Self {
        self.registry = Some(registry);
        self
    }

    /// Override the [`Acquisition`] every parser's [`crate::pipeline::context::ParseContext`]
    /// will report for this run — e.g. `Acquisition::ImageRead` for a
    /// full-disk image, or `Acquisition::VssSnapshot { .. }` for a mounted
    /// shadow copy. Without this, acquisition is derived from the VFS's
    /// `SourceKind`, which cannot distinguish these cases.
    pub fn acquisition(mut self, acquisition: Acquisition) -> Self {
        self.acquisition = Some(acquisition);
        self
    }

    /// Attach a [`MountResolver`] so parsers can resolve
    /// [`crate::traits::forensic::Requirement`]s that need nested
    /// containers (a companion database, a hive discovered inside a VFS).
    pub fn mount_resolver(mut self, resolver: Arc<MountResolver>) -> Self {
        self.mount_resolver = Some(resolver);
        self
    }

    /// Attach a [`SecretProvider`] so parsers can resolve
    /// [`crate::traits::forensic::Requirement::Secret`]. Never set this to
    /// anything that caches or logs what it returns.
    pub fn secrets(mut self, secrets: Arc<dyn SecretProvider>) -> Self {
        self.secrets = Some(secrets);
        self
    }

    pub fn build(self) -> TriageSources {
        TriageSources {
            vfs: self.vfs,
            registry: self.registry,
            acquisition: self.acquisition,
            mount_resolver: self.mount_resolver,
            secrets: self.secrets,
        }
    }
}
