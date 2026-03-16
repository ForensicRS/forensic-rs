use crate::traits::{
    registry::RegistryReader,
    vfs::VirtualFileSystem,
};

/// Holds the data sources available to parsers during pipeline execution.
///
/// Provides unified access to the forensic data sources (filesystem, registry)
/// that parsers need to extract artifacts. Each source is accessed through its
/// trait interface, keeping parsers decoupled from specific implementations.
///
/// Sources are optional — a parser that only needs the registry does not
/// require a VFS and vice versa.
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

    /// Access the registry reader, if available.
    pub fn registry(&mut self) -> Option<&mut dyn RegistryReader> {
        match &mut self.registry {
            Some(r) => Some(&mut **r),
            None => None,
        }
    }

    /// Whether a VFS source has been configured.
    pub fn has_vfs(&self) -> bool {
        self.vfs.is_some()
    }

    /// Whether a registry source has been configured.
    pub fn has_registry(&self) -> bool {
        self.registry.is_some()
    }
}

/// Builder for constructing `TriageSources` with only the needed data sources.
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
