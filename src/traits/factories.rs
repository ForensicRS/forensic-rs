//! Factories for opening derived forensic readers from virtual evidence.
//!
//! [`FileSystem`](crate::traits::vfs::FileSystem) identifies where evidence
//! lives. These factories interpret files within that evidence as a
//! database, event log, or registry hive without making an already-open
//! reader a top-level pipeline source.

use std::sync::Arc;

use crate::core::path::FPath;
use crate::err::ForensicResult;
use crate::traits::db::ForensicDb;
use crate::traits::events::EventLogReader;
use crate::traits::registry::Registry;
use crate::traits::vfs::FileSystem;

/// Opens database files from virtual evidence.
///
/// The factory owns the supplied filesystem view so implementations can access
/// companion files such as SQLite WAL and shared-memory files beside `path`.
pub trait ForensicDbFactory: Send + Sync {
    fn open(
        &self,
        filesystem: Arc<dyn FileSystem>,
        path: &FPath,
    ) -> ForensicResult<Box<dyn ForensicDb>>;
}

/// Opens event log files from virtual evidence.
pub trait EventLogReaderFactory: Send + Sync {
    fn open(
        &self,
        filesystem: Arc<dyn FileSystem>,
        path: &FPath,
    ) -> ForensicResult<Box<dyn EventLogReader>>;
}

/// Opens registry hive files from virtual evidence.
pub trait RegistryReaderFactory: Send + Sync {
    fn open(
        &self,
        filesystem: Arc<dyn FileSystem>,
        path: &FPath,
    ) -> ForensicResult<Box<dyn Registry>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepts_database_factory(_factory: &dyn ForensicDbFactory) {}
    fn accepts_event_log_factory(_factory: &dyn EventLogReaderFactory) {}
    fn accepts_registry_factory(_factory: &dyn RegistryReaderFactory) {}

    #[test]
    fn reader_factories_are_object_safe() {
        let _ = accepts_database_factory;
        let _ = accepts_event_log_factory;
        let _ = accepts_registry_factory;
    }
}
