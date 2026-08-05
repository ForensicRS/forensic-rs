use std::sync::{Arc, Mutex};

use crate::core::path::FPath;
use crate::err::ForensicResult;
use crate::traits::db::ForensicDb;
use crate::traits::events::EventLogReader;
use crate::traits::factories::{EventLogReaderFactory, ForensicDbFactory, RegistryReaderFactory};
use crate::traits::registry::Registry;
use crate::traits::vfs::FileSystem;

use super::{InMemoryForensicDb, TestingEventLogReader, TestingRegistry};

/// Fixed-value [`RegistryReaderFactory`]: ignores its `filesystem`/`path`
/// arguments and always returns a clone of a pre-built [`TestingRegistry`].
///
/// Wrapped in `Arc<Mutex<_>>` rather than held bare purely so this factory
/// type stays `Clone` + `Debug` without requiring the same of every
/// `TestingRegistry` clone's shared handle cache — `TestingRegistry` itself
/// is already `Send + Sync` (RFC 0001 workstream D8).
#[derive(Clone, Debug)]
pub struct TestingRegistryReaderFactory {
    registry: Arc<Mutex<TestingRegistry>>,
}

impl TestingRegistryReaderFactory {
    pub fn new(registry: TestingRegistry) -> Self {
        Self {
            registry: Arc::new(Mutex::new(registry)),
        }
    }
}

impl RegistryReaderFactory for TestingRegistryReaderFactory {
    fn open(
        &self,
        _filesystem: Arc<dyn FileSystem>,
        _path: &FPath,
    ) -> ForensicResult<Box<dyn Registry>> {
        let registry = self
            .registry
            .lock()
            .expect("TestingRegistryReaderFactory lock poisoned")
            .clone();
        Ok(Box::new(registry))
    }
}

/// Fixed-value [`EventLogReaderFactory`]: ignores its `filesystem`/`path`
/// arguments and always returns a clone of a pre-built [`TestingEventLogReader`].
#[derive(Clone, Debug)]
pub struct TestingEventLogReaderFactory {
    reader: TestingEventLogReader,
}

impl TestingEventLogReaderFactory {
    pub fn new(reader: TestingEventLogReader) -> Self {
        Self { reader }
    }
}

impl EventLogReaderFactory for TestingEventLogReaderFactory {
    fn open(
        &self,
        _filesystem: Arc<dyn FileSystem>,
        _path: &FPath,
    ) -> ForensicResult<Box<dyn EventLogReader>> {
        Ok(Box::new(self.reader.clone()))
    }
}

/// Fixed-value [`ForensicDbFactory`]: ignores its `filesystem`/`path`
/// arguments and always returns a clone of a pre-built [`InMemoryForensicDb`].
#[derive(Clone, Debug, Default)]
pub struct TestingForensicDbFactory {
    db: InMemoryForensicDb,
}

impl TestingForensicDbFactory {
    pub fn new(db: InMemoryForensicDb) -> Self {
        Self { db }
    }
}

impl ForensicDbFactory for TestingForensicDbFactory {
    fn open(
        &self,
        _filesystem: Arc<dyn FileSystem>,
        _path: &FPath,
    ) -> ForensicResult<Box<dyn ForensicDb>> {
        Ok(Box::new(self.db.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::fs::StdVirtualFS;
    use crate::traits::registry::RegistryExt;

    #[test]
    fn registry_factory_open_returns_working_reader() {
        let factory = TestingRegistryReaderFactory::new(TestingRegistry::new());
        let reader = factory
            .open(Arc::new(StdVirtualFS::new()), FPath::new("ignored"))
            .unwrap();
        assert!(reader.key("HKLM").is_ok());
    }

    #[test]
    fn event_log_factory_open_returns_working_reader() {
        let factory = TestingEventLogReaderFactory::new(super::super::basic_event_log());
        let reader = factory
            .open(Arc::new(StdVirtualFS::new()), FPath::new("ignored"))
            .unwrap();
        assert!(reader.channels().unwrap().contains(&"Security".to_string()));
    }

    #[test]
    fn db_factory_open_returns_working_reader() {
        use crate::traits::db::ForensicColumnType;
        use crate::utils::testing::InMemoryTable;

        let table = InMemoryTable::new("T").with_column("A", ForensicColumnType::Text, false);
        let db = InMemoryForensicDb::new().with_table(table);
        let factory = TestingForensicDbFactory::new(db);
        let reader = factory
            .open(Arc::new(StdVirtualFS::new()), FPath::new("ignored"))
            .unwrap();
        assert_eq!(reader.list_tables().unwrap(), vec!["T".to_string()]);
    }
}
