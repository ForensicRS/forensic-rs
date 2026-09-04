use std::sync::Arc;

use crate::err::ForensicResult;
use crate::traits::format::{FormatFactory, MountContext, MountKind, Mounted, ProbeScore};
use crate::traits::vfs::VirtualFile;

use super::{InMemoryForensicDb, TestingEventLogReader, TestingRegistry};

/// A fixed-value [`FormatFactory`] testing double: ignores the probed
/// content entirely, always claims it with [`ProbeScore::Strong`], and
/// always mounts a clone of the pre-built [`Mounted`] value it was
/// constructed with.
///
/// Replaces the three separate `TestingRegistryReaderFactory` /
/// `TestingEventLogReaderFactory` / `TestingForensicDbFactory` doubles from
/// before the `FormatFactory` unification — one shape now covers all three,
/// matching how a real `FormatFactory` implementation only differs in what
/// it mounts, not in the contract it fulfils.
#[derive(Clone)]
pub struct TestingFormatFactory {
    name: &'static str,
    mounted: Mounted,
}

impl TestingFormatFactory {
    pub fn registry(name: &'static str, registry: TestingRegistry) -> Self {
        Self {
            name,
            mounted: Mounted::Registry(Arc::new(registry)),
        }
    }

    pub fn event_log(name: &'static str, reader: TestingEventLogReader) -> Self {
        Self {
            name,
            mounted: Mounted::EventLog(Arc::new(reader)),
        }
    }

    pub fn database(name: &'static str, db: InMemoryForensicDb) -> Self {
        Self {
            name,
            mounted: Mounted::Database(Arc::new(db)),
        }
    }
}

impl FormatFactory for TestingFormatFactory {
    fn name(&self) -> &'static str {
        self.name
    }

    fn yields(&self) -> MountKind {
        self.mounted.kind()
    }

    fn probe(&self, _file: &mut dyn VirtualFile, _ctx: &MountContext<'_>) -> ForensicResult<ProbeScore> {
        Ok(ProbeScore::Strong)
    }

    fn mount(&self, _file: Box<dyn VirtualFile>, _ctx: &MountContext<'_>) -> ForensicResult<Mounted> {
        Ok(self.mounted.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::limits::MemorySpillStore;
    use crate::core::locator::EvidenceLocator;
    use crate::traits::registry::RegistryExt;
    use std::io::{Cursor, Read, Seek, SeekFrom};
    use std::sync::Arc as StdArc;

    struct EmptyFile(Cursor<Vec<u8>>);
    impl Read for EmptyFile {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }
    impl Seek for EmptyFile {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.0.seek(pos)
        }
    }
    impl VirtualFile for EmptyFile {
        fn metadata(&self) -> ForensicResult<crate::traits::vfs::VMetadata> {
            Ok(crate::traits::vfs::VMetadata {
                file_type: crate::traits::vfs::VFileType::File,
                size: 0,
                allocated_size: None,
                times: crate::traits::vfs::MacbTimes::default(),
                id: None,
                attributes: crate::traits::vfs::FileAttributes::empty(),
            })
        }
    }

    fn ctx<'a>(
        fs: &'a StdArc<dyn crate::traits::vfs::FileSystem>,
        locator: &'a EvidenceLocator,
        limits: &'a crate::core::limits::Limits,
        spill: &'a MemorySpillStore,
        cancel: &'a crate::bridge::CancellationToken,
    ) -> MountContext<'a> {
        MountContext::new(fs, locator, limits, 0, spill, None, cancel)
    }

    #[test]
    fn registry_factory_mounts_a_working_reader() {
        let factory = TestingFormatFactory::registry("test-registry", TestingRegistry::new());
        let fs: StdArc<dyn crate::traits::vfs::FileSystem> =
            StdArc::new(super::super::InMemoryVirtualFileSystem::new());
        let locator = EvidenceLocator::root();
        let limits = crate::core::limits::Limits::default();
        let spill = MemorySpillStore::new(1024);
        let cancel = crate::bridge::CancellationToken::new();
        let mount_ctx = ctx(&fs, &locator, &limits, &spill, &cancel);
        let mounted = factory
            .mount(Box::new(EmptyFile(Cursor::new(Vec::new()))), &mount_ctx)
            .unwrap();
        let registry = mounted.as_registry().unwrap();
        assert!(registry.key("HKLM").is_ok());
    }

    #[test]
    fn event_log_factory_mounts_a_working_reader() {
        let factory = TestingFormatFactory::event_log("test-events", super::super::basic_event_log());
        let fs: StdArc<dyn crate::traits::vfs::FileSystem> =
            StdArc::new(super::super::InMemoryVirtualFileSystem::new());
        let locator = EvidenceLocator::root();
        let limits = crate::core::limits::Limits::default();
        let spill = MemorySpillStore::new(1024);
        let cancel = crate::bridge::CancellationToken::new();
        let mount_ctx = ctx(&fs, &locator, &limits, &spill, &cancel);
        let mounted = factory
            .mount(Box::new(EmptyFile(Cursor::new(Vec::new()))), &mount_ctx)
            .unwrap();
        let reader = mounted.as_event_log().unwrap();
        assert!(reader.channels().unwrap().contains(&"Security".to_string()));
    }

    #[test]
    fn db_factory_mounts_a_working_reader() {
        use crate::traits::db::ForensicColumnType;
        use crate::utils::testing::InMemoryTable;

        let table = InMemoryTable::new("T").with_column("A", ForensicColumnType::Text, false);
        let db = InMemoryForensicDb::new().with_table(table);
        let factory = TestingFormatFactory::database("test-db", db);
        let fs: StdArc<dyn crate::traits::vfs::FileSystem> =
            StdArc::new(super::super::InMemoryVirtualFileSystem::new());
        let locator = EvidenceLocator::root();
        let limits = crate::core::limits::Limits::default();
        let spill = MemorySpillStore::new(1024);
        let cancel = crate::bridge::CancellationToken::new();
        let mount_ctx = ctx(&fs, &locator, &limits, &spill, &cancel);
        let mounted = factory
            .mount(Box::new(EmptyFile(Cursor::new(Vec::new()))), &mount_ctx)
            .unwrap();
        let db = mounted.as_database().unwrap();
        assert_eq!(db.list_tables().unwrap(), vec!["T".to_string()]);
    }

    #[test]
    fn probe_always_claims_regardless_of_content() {
        let factory = TestingFormatFactory::registry("test-registry", TestingRegistry::empty());
        let fs: StdArc<dyn crate::traits::vfs::FileSystem> =
            StdArc::new(super::super::InMemoryVirtualFileSystem::new());
        let locator = EvidenceLocator::root();
        let limits = crate::core::limits::Limits::default();
        let spill = MemorySpillStore::new(1024);
        let cancel = crate::bridge::CancellationToken::new();
        let mount_ctx = ctx(&fs, &locator, &limits, &spill, &cancel);
        let mut file = EmptyFile(Cursor::new(b"anything at all".to_vec()));
        assert_eq!(factory.probe(&mut file, &mount_ctx).unwrap(), ProbeScore::Strong);
    }
}
