use crate::traits::{registry::RegistryReader, vfs::VirtualFileSystem};

/// Holds the data sources available to parsers during pipeline execution.
///
/// Provides access to the evidence containers that parsers inspect. Database,
/// event-log, and registry-hive files discovered inside a VFS are opened with
/// reader factories rather than stored here as already-open readers.
///
/// Sources are optional. `registry` is retained for live-system and legacy
/// callers that already own a reader. Registry hives discovered in a VFS
/// should be opened through `RegistryReaderFactory`, like other derived files.
pub struct TriageSources {
    vfs: Option<Box<dyn VirtualFileSystem>>,
    registry: Option<Box<dyn RegistryReader>>,
}

impl TriageSources {
    /// Create sources with both VFS and registry.
    pub fn new(vfs: Box<dyn VirtualFileSystem>, registry: Box<dyn RegistryReader>) -> Self {
        Self {
            vfs: Some(vfs),
            registry: Some(registry),
        }
    }

    /// Start building sources with a fluent API.
    pub fn builder() -> TriageSourcesBuilder {
        TriageSourcesBuilder::default()
    }

    /// Access the virtual filesystem, if available.
    pub fn vfs(&mut self) -> Option<&mut dyn VirtualFileSystem> {
        match &mut self.vfs {
            Some(v) => Some(&mut **v),
            None => None,
        }
    }

    /// Access a pre-opened live or compatibility registry reader, if available.
    pub fn registry(&self) -> Option<&dyn RegistryReader> {
        match &self.registry {
            Some(r) => Some(&**r),
            None => None,
        }
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
    vfs: Option<Box<dyn VirtualFileSystem>>,
    registry: Option<Box<dyn RegistryReader>>,
}

impl TriageSourcesBuilder {
    pub fn vfs(mut self, vfs: Box<dyn VirtualFileSystem>) -> Self {
        self.vfs = Some(vfs);
        self
    }

    pub fn registry(mut self, registry: Box<dyn RegistryReader>) -> Self {
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
