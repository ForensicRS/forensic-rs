//! Path-level authorization wrappers for forensic pipeline sources.

use std::path::Path;
use std::sync::Arc;

use crate::err::{ForensicError, ForensicResult};
use crate::traits::db::{
    ForensicColumnDef, ForensicColumnType, ForensicDb, ForensicRows, ForensicTable,
    ForensicValueRef,
};
use crate::traits::events::{EventLogIterator, EventLogQuery, EventLogReader, EventRecord};
use crate::traits::registry::{
    RegHiveKey, RegKeyHandle, RegValueType, RegistryKeyInfo, RegistryOpenOptions, RegistryReader,
    RegistryVisit,
};
use crate::traits::vfs::{VDirEntry, VMetadata, VirtualFile, VirtualFileSystem};

use super::{AccessContext, AccessKind, AccessPolicy, AccessRequest};

/// A virtual filesystem that checks source policy before every data operation.
///
/// Denied paths return a generic source error without revealing whether the
/// underlying filesystem contains the requested entry.
pub struct AuthorizedVirtualFileSystem {
    inner: Box<dyn VirtualFileSystem>,
    policy: Arc<dyn AccessPolicy>,
    access: AccessContext,
    source_id: String,
}

impl AuthorizedVirtualFileSystem {
    pub fn new(
        inner: Box<dyn VirtualFileSystem>,
        policy: Arc<dyn AccessPolicy>,
        access: AccessContext,
        source_id: impl Into<String>,
    ) -> Self {
        Self {
            inner,
            policy,
            access,
            source_id: source_id.into(),
        }
    }

    fn wrap(&self, inner: Box<dyn VirtualFileSystem>) -> Box<dyn VirtualFileSystem> {
        Box::new(Self::new(
            inner,
            Arc::clone(&self.policy),
            self.access.clone(),
            self.source_id.clone(),
        ))
    }

    fn ensure_source(&self) -> ForensicResult<()> {
        self.ensure_path(None)
    }

    fn ensure_path(&self, path: Option<&Path>) -> ForensicResult<()> {
        let target = path.map(|path| path.to_string_lossy());
        let request = match target.as_deref() {
            Some(target) => {
                AccessRequest::new(AccessKind::UseSource, &self.source_id).with_target(target)
            }
            None => AccessRequest::new(AccessKind::UseSource, &self.source_id),
        };
        if self.policy.evaluate(&self.access, &request).is_allowed() {
            Ok(())
        } else {
            Err(ForensicError::other(
                "AuthorizedVirtualFileSystem",
                "source path is unavailable".to_string(),
            ))
        }
    }
}

impl VirtualFileSystem for AuthorizedVirtualFileSystem {
    fn from_file(&self, file: Box<dyn VirtualFile>) -> ForensicResult<Box<dyn VirtualFileSystem>> {
        self.ensure_source()?;
        self.inner.from_file(file).map(|inner| self.wrap(inner))
    }

    fn from_fs(
        &self,
        fs: Box<dyn VirtualFileSystem>,
    ) -> ForensicResult<Box<dyn VirtualFileSystem>> {
        self.ensure_source()?;
        self.inner.from_fs(fs).map(|inner| self.wrap(inner))
    }

    fn read_to_string(&mut self, path: &Path) -> ForensicResult<String> {
        self.ensure_path(Some(path))?;
        self.inner.read_to_string(path)
    }

    fn read_all(&mut self, path: &Path) -> ForensicResult<Vec<u8>> {
        self.ensure_path(Some(path))?;
        self.inner.read_all(path)
    }

    fn read(&mut self, path: &Path, pos: u64, buf: &mut [u8]) -> ForensicResult<usize> {
        self.ensure_path(Some(path))?;
        self.inner.read(path, pos, buf)
    }

    fn metadata(&mut self, path: &Path) -> ForensicResult<VMetadata> {
        self.ensure_path(Some(path))?;
        self.inner.metadata(path)
    }

    fn read_dir(&mut self, path: &Path) -> ForensicResult<Vec<VDirEntry>> {
        self.ensure_path(Some(path))?;
        self.inner.read_dir(path)
    }

    fn visit_dir(
        &mut self,
        path: &Path,
        visitor: &mut dyn FnMut(&VDirEntry) -> ForensicResult<()>,
    ) -> ForensicResult<()> {
        self.ensure_path(Some(path))?;
        self.inner.visit_dir(path, visitor)
    }

    fn is_live(&self) -> bool {
        self.ensure_source().is_ok() && self.inner.is_live()
    }

    fn open(&mut self, path: &Path) -> ForensicResult<Box<dyn VirtualFile>> {
        self.ensure_path(Some(path))?;
        self.inner.open(path)
    }

    fn duplicate(&self) -> Box<dyn VirtualFileSystem> {
        self.wrap(self.inner.duplicate())
    }

    fn exists(&self, path: &Path) -> bool {
        self.ensure_path(Some(path)).is_ok() && self.inner.exists(path)
    }
}

/// A registry reader that authorizes key and value paths before exposing them.
///
/// Registry handles opened through this wrapper retain their logical path, so
/// subsequent value reads and enumeration callbacks can be authorized without
/// relying on backend-specific handle internals.
pub struct AuthorizedRegistryReader {
    inner: Box<dyn RegistryReader>,
    policy: Arc<dyn AccessPolicy>,
    access: AccessContext,
    source_id: String,
}

impl AuthorizedRegistryReader {
    pub fn new(
        inner: Box<dyn RegistryReader>,
        policy: Arc<dyn AccessPolicy>,
        access: AccessContext,
        source_id: impl Into<String>,
    ) -> Self {
        Self {
            inner,
            policy,
            access,
            source_id: source_id.into(),
        }
    }

    fn wrap(&self, inner: Box<dyn RegistryReader>) -> Box<dyn RegistryReader> {
        Box::new(Self::new(
            inner,
            Arc::clone(&self.policy),
            self.access.clone(),
            self.source_id.clone(),
        ))
    }

    fn ensure_source(&self) -> ForensicResult<()> {
        self.ensure_target(None)
    }

    fn ensure_target(&self, target: Option<&str>) -> ForensicResult<()> {
        let request = match target {
            Some(target) => {
                AccessRequest::new(AccessKind::UseSource, &self.source_id).with_target(target)
            }
            None => AccessRequest::new(AccessKind::UseSource, &self.source_id),
        };
        if self.policy.evaluate(&self.access, &request).is_allowed() {
            Ok(())
        } else {
            Err(ForensicError::other(
                "AuthorizedRegistryReader",
                "source path is unavailable".to_string(),
            ))
        }
    }

    fn key_path<'a>(&self, key: &'a RegKeyHandle) -> ForensicResult<&'a str> {
        key.access_path().ok_or_else(|| {
            ForensicError::other(
                "AuthorizedRegistryReader",
                "source path is unavailable".to_string(),
            )
        })
    }

    fn hive_path(hive: RegHiveKey, key_path: &str) -> String {
        let hive = format!("{hive:?}");
        if key_path.is_empty() {
            hive
        } else {
            format!("{hive}\\{key_path}")
        }
    }

    fn child_path(parent: &str, child: &str) -> String {
        if parent.is_empty() {
            child.to_string()
        } else if child.is_empty() {
            parent.to_string()
        } else {
            format!("{parent}\\{child}")
        }
    }
}

impl RegistryReader for AuthorizedRegistryReader {
    fn open_key(&self, hive: RegHiveKey, key_path: &str) -> ForensicResult<RegKeyHandle> {
        let path = Self::hive_path(hive, key_path);
        self.ensure_target(Some(&path))?;
        self.inner
            .open_key(hive, key_path)
            .map(|key| key.with_access_path(path))
    }

    fn open_key_with_options(
        &self,
        hive: RegHiveKey,
        key_path: &str,
        options: &RegistryOpenOptions,
    ) -> ForensicResult<RegKeyHandle> {
        let path = Self::hive_path(hive, key_path);
        self.ensure_target(Some(&path))?;
        self.inner
            .open_key_with_options(hive, key_path, options)
            .map(|key| key.with_access_path(path))
    }

    fn open_subkey(&self, parent: &RegKeyHandle, subkey: &str) -> ForensicResult<RegKeyHandle> {
        let path = Self::child_path(self.key_path(parent)?, subkey);
        self.ensure_target(Some(&path))?;
        self.inner
            .open_subkey(parent, subkey)
            .map(|key| key.with_access_path(path))
    }

    fn read_raw_value_into(
        &self,
        key: &RegKeyHandle,
        value_name: &str,
        buf: &mut [u8],
    ) -> ForensicResult<(RegValueType, usize)> {
        let path = Self::child_path(self.key_path(key)?, value_name);
        self.ensure_target(Some(&path))?;
        self.inner.read_raw_value_into(key, value_name, buf)
    }

    fn enumerate_keys(
        &self,
        key: &RegKeyHandle,
        visitor: &mut dyn FnMut(&str) -> ForensicResult<RegistryVisit>,
    ) -> ForensicResult<()> {
        let parent = self.key_path(key)?.to_string();
        self.ensure_target(Some(&parent))?;
        self.inner.enumerate_keys(key, &mut |name| {
            let path = Self::child_path(&parent, name);
            if self.ensure_target(Some(&path)).is_ok() {
                visitor(name)
            } else {
                Ok(RegistryVisit::Continue)
            }
        })
    }

    fn enumerate_values(
        &self,
        key: &RegKeyHandle,
        visitor: &mut dyn FnMut(&str) -> ForensicResult<RegistryVisit>,
    ) -> ForensicResult<()> {
        let parent = self.key_path(key)?.to_string();
        self.ensure_target(Some(&parent))?;
        self.inner.enumerate_values(key, &mut |name| {
            let path = Self::child_path(&parent, name);
            if self.ensure_target(Some(&path)).is_ok() {
                visitor(name)
            } else {
                Ok(RegistryVisit::Continue)
            }
        })
    }

    fn key_info(&self, key: &RegKeyHandle) -> ForensicResult<RegistryKeyInfo> {
        let path = self.key_path(key)?;
        self.ensure_target(Some(path))?;
        self.inner.key_info(key)
    }

    fn mount_file(&self, file: Box<dyn VirtualFile>) -> ForensicResult<Box<dyn RegistryReader>> {
        self.ensure_source()?;
        self.inner.mount_file(file).map(|reader| self.wrap(reader))
    }

    fn mount_fs(&self, fs: Box<dyn VirtualFileSystem>) -> ForensicResult<Box<dyn RegistryReader>> {
        self.ensure_source()?;
        self.inner.mount_fs(fs).map(|reader| self.wrap(reader))
    }
}

/// An event log reader that exposes only caller-authorized channels and records.
pub struct AuthorizedEventLogReader {
    inner: Box<dyn EventLogReader>,
    policy: Arc<dyn AccessPolicy>,
    access: AccessContext,
    source_id: String,
}

impl AuthorizedEventLogReader {
    pub fn new(
        inner: Box<dyn EventLogReader>,
        policy: Arc<dyn AccessPolicy>,
        access: AccessContext,
        source_id: impl Into<String>,
    ) -> Self {
        Self {
            inner,
            policy,
            access,
            source_id: source_id.into(),
        }
    }

    fn allows_channel(&self, channel: &str) -> bool {
        let request =
            AccessRequest::new(AccessKind::UseSource, &self.source_id).with_target(channel);
        self.policy.evaluate(&self.access, &request).is_allowed()
    }

    fn ensure_channel(&self, channel: &str) -> ForensicResult<()> {
        if self.allows_channel(channel) {
            Ok(())
        } else {
            Err(ForensicError::other(
                "AuthorizedEventLogReader",
                "source channel is unavailable".to_string(),
            ))
        }
    }
}

struct AuthorizedEventLogIterator<'a> {
    inner: Box<dyn EventLogIterator + 'a>,
    policy: Arc<dyn AccessPolicy>,
    access: AccessContext,
    source_id: String,
}

impl EventLogIterator for AuthorizedEventLogIterator<'_> {
    fn next(&mut self) -> ForensicResult<Option<EventRecord>> {
        loop {
            let Some(record) = self.inner.next()? else {
                return Ok(None);
            };
            let request = AccessRequest::new(AccessKind::UseSource, &self.source_id)
                .with_target(&record.channel);
            if self.policy.evaluate(&self.access, &request).is_allowed() {
                return Ok(Some(record));
            }
        }
    }
}

struct EmptyEventLogIterator;

impl EventLogIterator for EmptyEventLogIterator {
    fn next(&mut self) -> ForensicResult<Option<EventRecord>> {
        Ok(None)
    }
}

impl EventLogReader for AuthorizedEventLogReader {
    fn channels(&self) -> ForensicResult<Vec<String>> {
        Ok(self
            .inner
            .channels()?
            .into_iter()
            .filter(|channel| self.allows_channel(channel))
            .collect())
    }

    fn query(&self, query: &EventLogQuery) -> ForensicResult<Box<dyn EventLogIterator + '_>> {
        let mut guarded_query = query.clone();
        if guarded_query.channels.is_empty() {
            guarded_query.channels = self.channels()?;
            if guarded_query.channels.is_empty() {
                return Ok(Box::new(EmptyEventLogIterator));
            }
        } else {
            for channel in &guarded_query.channels {
                self.ensure_channel(channel)?;
            }
        }
        let inner = self.inner.query(&guarded_query)?;
        Ok(Box::new(AuthorizedEventLogIterator {
            inner,
            policy: Arc::clone(&self.policy),
            access: self.access.clone(),
            source_id: self.source_id.clone(),
        }))
    }

    fn event_count(&self, channel: &str) -> ForensicResult<u64> {
        self.ensure_channel(channel)?;
        self.inner.event_count(channel)
    }
}

/// A forensic database that exposes only caller-authorized tables and rows.
pub struct AuthorizedForensicDb {
    inner: Box<dyn ForensicDb>,
    policy: Arc<dyn AccessPolicy>,
    access: AccessContext,
    source_id: String,
}

impl AuthorizedForensicDb {
    pub fn new(
        inner: Box<dyn ForensicDb>,
        policy: Arc<dyn AccessPolicy>,
        access: AccessContext,
        source_id: impl Into<String>,
    ) -> Self {
        Self {
            inner,
            policy,
            access,
            source_id: source_id.into(),
        }
    }

    fn allows_target(&self, target: &str) -> bool {
        let request =
            AccessRequest::new(AccessKind::UseSource, &self.source_id).with_target(target);
        self.policy.evaluate(&self.access, &request).is_allowed()
    }

    fn ensure_table(&self, table: &str) -> ForensicResult<()> {
        if self.allows_target(table) {
            Ok(())
        } else {
            Err(ForensicError::other(
                "AuthorizedForensicDb",
                "source table is unavailable".to_string(),
            ))
        }
    }
}

impl ForensicDb for AuthorizedForensicDb {
    fn list_tables(&self) -> ForensicResult<Vec<String>> {
        Ok(self
            .inner
            .list_tables()?
            .into_iter()
            .filter(|table| self.allows_target(table))
            .collect())
    }

    fn list_all_tables(&self) -> ForensicResult<Vec<String>> {
        Ok(self
            .inner
            .list_all_tables()?
            .into_iter()
            .filter(|table| self.allows_target(table))
            .collect())
    }

    fn table(&self, name: &str) -> ForensicResult<Box<dyn ForensicTable + '_>> {
        self.ensure_table(name)?;
        let inner = self.inner.table(name)?;
        Ok(Box::new(AuthorizedForensicTable {
            inner,
            policy: Arc::clone(&self.policy),
            access: self.access.clone(),
            source_id: self.source_id.clone(),
            table_name: name.to_string(),
        }))
    }
}

struct AuthorizedForensicTable<'a> {
    inner: Box<dyn ForensicTable + 'a>,
    policy: Arc<dyn AccessPolicy>,
    access: AccessContext,
    source_id: String,
    table_name: String,
}

impl ForensicTable for AuthorizedForensicTable<'_> {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn columns(&self) -> &[ForensicColumnDef] {
        self.inner.columns()
    }

    fn iter_rows(&self) -> ForensicResult<Box<dyn ForensicRows + '_>> {
        let inner = self.inner.iter_rows()?;
        Ok(Box::new(AuthorizedForensicRows {
            inner,
            policy: Arc::clone(&self.policy),
            access: self.access.clone(),
            source_id: self.source_id.clone(),
            table_name: self.table_name.clone(),
            next_row_index: 0,
            has_visible_row: false,
        }))
    }

    fn row_count(&self) -> Option<u64> {
        None
    }
}

struct AuthorizedForensicRows<'a> {
    inner: Box<dyn ForensicRows + 'a>,
    policy: Arc<dyn AccessPolicy>,
    access: AccessContext,
    source_id: String,
    table_name: String,
    next_row_index: u64,
    has_visible_row: bool,
}

impl AuthorizedForensicRows<'_> {
    fn allows_current_row(&self, row_index: u64) -> bool {
        let target = format!("{}/{}", self.table_name, row_index);
        let request =
            AccessRequest::new(AccessKind::UseSource, &self.source_id).with_target(&target);
        self.policy.evaluate(&self.access, &request).is_allowed()
    }
}

impl ForensicRows for AuthorizedForensicRows<'_> {
    fn column_count(&self) -> usize {
        self.inner.column_count()
    }

    fn column_name(&self, index: usize) -> Option<&str> {
        self.inner.column_name(index)
    }

    fn column_names(&self) -> Vec<&str> {
        self.inner.column_names()
    }

    fn column_type(&self, index: usize) -> ForensicColumnType {
        self.inner.column_type(index)
    }

    fn next(&mut self) -> ForensicResult<bool> {
        self.has_visible_row = false;
        while self.inner.next()? {
            let row_index = self.next_row_index;
            self.next_row_index += 1;
            if self.allows_current_row(row_index) {
                self.has_visible_row = true;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn read_ref(&self, index: usize) -> ForensicResult<ForensicValueRef<'_>> {
        if !self.has_visible_row {
            return Err(ForensicError::no_more_data());
        }
        self.inner.read_ref(index)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::capabilities::AccessDecision;
    use crate::core::fs::StdVirtualFS;
    use crate::traits::db::{
        ForensicColumnDef, ForensicColumnType, ForensicDb, ForensicRows, ForensicTable,
        ForensicValue, ForensicValueRef,
    };
    use crate::traits::events::{EventLogQuery, EventLogReader};
    use crate::traits::registry::{RegistryReader, HKU};
    use crate::utils::testing::{basic_event_log, TestingRegistry};

    struct PathPolicy;

    impl AccessPolicy for PathPolicy {
        fn evaluate(&self, _access: &AccessContext, request: &AccessRequest<'_>) -> AccessDecision {
            if request.kind == AccessKind::UseSource
                && request.capability_id == "evidence-vfs"
                && request
                    .target
                    .is_some_and(|path| path.ends_with("allowed.txt"))
            {
                AccessDecision::Allow
            } else {
                AccessDecision::Deny
            }
        }
    }

    #[test]
    fn virtual_filesystem_hides_denied_paths() {
        let directory =
            std::env::temp_dir().join(format!("forensic_rs_authorized_vfs_{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let allowed = directory.join("allowed.txt");
        let denied = directory.join("hidden.txt");
        std::fs::File::create(&allowed)
            .unwrap()
            .write_all(b"visible")
            .unwrap();
        std::fs::File::create(&denied)
            .unwrap()
            .write_all(b"hidden")
            .unwrap();

        let mut filesystem = AuthorizedVirtualFileSystem::new(
            Box::new(StdVirtualFS::new()),
            Arc::new(PathPolicy),
            AccessContext::new("analyst", "tenant"),
            "evidence-vfs",
        );
        assert_eq!(filesystem.read_to_string(&allowed).unwrap(), "visible");
        assert_eq!(
            filesystem.read_to_string(&denied).unwrap_err().to_string(),
            "AuthorizedVirtualFileSystem error: source path is unavailable"
        );
        assert!(!filesystem.exists(&denied));

        std::fs::remove_dir_all(directory).unwrap();
    }

    struct RegistryPathPolicy;

    impl AccessPolicy for RegistryPathPolicy {
        fn evaluate(&self, _access: &AccessContext, request: &AccessRequest<'_>) -> AccessDecision {
            let Some(path) = request.target else {
                return AccessDecision::Deny;
            };
            if request.kind == AccessKind::UseSource
                && request.capability_id == "evidence-registry"
                && (path.ends_with("Volatile Environment")
                    || path.ends_with("Volatile Environment\\USERPROFILE"))
            {
                AccessDecision::Allow
            } else {
                AccessDecision::Deny
            }
        }
    }

    #[test]
    fn registry_reader_hides_denied_keys_and_values() {
        let registry = AuthorizedRegistryReader::new(
            Box::new(TestingRegistry::new()),
            Arc::new(RegistryPathPolicy),
            AccessContext::new("analyst", "tenant"),
            "evidence-registry",
        );
        let key_path = r"S-1-5-21-1366093794-4292800403-1155380978-513\Volatile Environment";
        let key = registry.open_key(HKU, key_path).unwrap();
        assert!(registry.read_value(&key, "USERPROFILE").is_ok());
        assert_eq!(
            registry
                .read_value(&key, "USERNAME")
                .unwrap_err()
                .to_string(),
            "AuthorizedRegistryReader error: source path is unavailable"
        );
        assert_eq!(
            registry
                .open_key(
                    HKU,
                    r"S-1-5-21-1366093794-4292800403-1155380978-513\Control Panel"
                )
                .unwrap_err()
                .to_string(),
            "AuthorizedRegistryReader error: source path is unavailable"
        );
    }

    struct EventChannelPolicy;

    impl AccessPolicy for EventChannelPolicy {
        fn evaluate(&self, _access: &AccessContext, request: &AccessRequest<'_>) -> AccessDecision {
            if request.kind == AccessKind::UseSource
                && request.capability_id == "case-events"
                && request.target == Some("Security")
            {
                AccessDecision::Allow
            } else {
                AccessDecision::Deny
            }
        }
    }

    #[test]
    fn event_log_reader_hides_denied_channels() {
        let reader = AuthorizedEventLogReader::new(
            Box::new(basic_event_log()),
            Arc::new(EventChannelPolicy),
            AccessContext::new("analyst", "tenant"),
            "case-events",
        );
        assert_eq!(reader.channels().unwrap(), vec!["Security"]);

        let mut iterator = reader.query(&EventLogQuery::new()).unwrap();
        let mut records = Vec::new();
        while let Some(record) = iterator.next().unwrap() {
            records.push(record);
        }
        assert_eq!(records.len(), 3);
        assert!(records.iter().all(|record| record.channel == "Security"));
        drop(iterator);

        assert!(matches!(
            reader.query(&EventLogQuery::new().with_channels(&["System"])),
            Err(error) if error.to_string()
                == "AuthorizedEventLogReader error: source channel is unavailable"
        ));
        assert_eq!(
            reader.event_count("System").unwrap_err().to_string(),
            "AuthorizedEventLogReader error: source channel is unavailable"
        );
    }

    struct TestDatabase;

    impl ForensicDb for TestDatabase {
        fn list_tables(&self) -> ForensicResult<Vec<String>> {
            Ok(vec!["public".to_string(), "private".to_string()])
        }

        fn table(&self, name: &str) -> ForensicResult<Box<dyn ForensicTable + '_>> {
            match name {
                "public" | "private" => Ok(Box::new(TestTable::new(name))),
                _ => Err(ForensicError::other(
                    "TestDatabase",
                    "missing table".to_string(),
                )),
            }
        }
    }

    struct TestTable {
        name: String,
        columns: Vec<ForensicColumnDef>,
    }

    impl TestTable {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                columns: vec![ForensicColumnDef {
                    name: "value".to_string(),
                    col_type: ForensicColumnType::Text,
                    nullable: false,
                }],
            }
        }
    }

    impl ForensicTable for TestTable {
        fn name(&self) -> &str {
            &self.name
        }

        fn columns(&self) -> &[ForensicColumnDef] {
            &self.columns
        }

        fn iter_rows(&self) -> ForensicResult<Box<dyn ForensicRows + '_>> {
            Ok(Box::new(TestRows {
                rows: vec![
                    ForensicValue::Text("visible".to_string()),
                    ForensicValue::Text("hidden".to_string()),
                ],
                position: None,
            }))
        }
    }

    struct TestRows {
        rows: Vec<ForensicValue>,
        position: Option<usize>,
    }

    impl ForensicRows for TestRows {
        fn column_count(&self) -> usize {
            1
        }

        fn column_name(&self, index: usize) -> Option<&str> {
            (index == 0).then_some("value")
        }

        fn column_names(&self) -> Vec<&str> {
            vec!["value"]
        }

        fn column_type(&self, _index: usize) -> ForensicColumnType {
            ForensicColumnType::Text
        }

        fn next(&mut self) -> ForensicResult<bool> {
            let next = self.position.map_or(0, |position| position + 1);
            if next < self.rows.len() {
                self.position = Some(next);
                Ok(true)
            } else {
                Ok(false)
            }
        }

        fn read_ref(&self, index: usize) -> ForensicResult<ForensicValueRef<'_>> {
            if index != 0 {
                return Err(ForensicError::missing_data(
                    "column",
                    "missing column".into(),
                ));
            }
            let value = self
                .position
                .and_then(|position| self.rows.get(position))
                .ok_or_else(ForensicError::no_more_data)?;
            Ok(value.as_ref())
        }
    }

    struct DatabasePolicy;

    impl AccessPolicy for DatabasePolicy {
        fn evaluate(&self, _access: &AccessContext, request: &AccessRequest<'_>) -> AccessDecision {
            if request.kind == AccessKind::UseSource
                && request.capability_id == "case-database"
                && matches!(request.target, Some("public") | Some("public/0"))
            {
                AccessDecision::Allow
            } else {
                AccessDecision::Deny
            }
        }
    }

    #[test]
    fn forensic_database_hides_denied_tables_and_rows() {
        let database = AuthorizedForensicDb::new(
            Box::new(TestDatabase),
            Arc::new(DatabasePolicy),
            AccessContext::new("analyst", "tenant"),
            "case-database",
        );
        assert_eq!(database.list_tables().unwrap(), vec!["public"]);
        assert!(matches!(
            database.table("private"),
            Err(error) if error.to_string()
                == "AuthorizedForensicDb error: source table is unavailable"
        ));

        let table = database.table("public").unwrap();
        assert_eq!(table.row_count(), None);
        let mut rows = table.iter_rows().unwrap();
        assert!(rows.next().unwrap());
        assert_eq!(
            rows.read(0).unwrap(),
            ForensicValue::Text("visible".to_string())
        );
        assert!(!rows.next().unwrap());
        assert!(rows.read(0).is_err());
    }
}
