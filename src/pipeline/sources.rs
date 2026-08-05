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
pub struct TriageSources {
    vfs: Option<Arc<dyn FileSystem>>,
    registry: Option<Arc<dyn Registry>>,
}

impl TriageSources {
    /// Create sources with both VFS and registry.
    pub fn new(vfs: Arc<dyn FileSystem>, registry: Arc<dyn Registry>) -> Self {
        Self {
            vfs: Some(vfs),
            registry: Some(registry),
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
}

/// Builder for constructing `TriageSources` with the available evidence.
#[derive(Default)]
pub struct TriageSourcesBuilder {
    vfs: Option<Arc<dyn FileSystem>>,
    registry: Option<Arc<dyn Registry>>,
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

    pub fn build(self) -> TriageSources {
        TriageSources {
            vfs: self.vfs,
            registry: self.registry,
        }
    }
}
