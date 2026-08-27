//! Path-level authorization wrappers for forensic pipeline sources.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::core::path::FPath;
use crate::err::{ForensicError, ForensicResult};
use crate::traits::db::{
    ForensicColumnDef, ForensicColumnType, ForensicDb, ForensicRows, ForensicTable,
    ForensicValueRef,
};
use crate::traits::events::{EventLogIterator, EventLogQuery, EventLogReader, EventRecord};
use crate::traits::registry::{KeyEntry, KeyInfo, PredefinedHive, RawKey, RegValue, Registry};
use crate::traits::vfs::{CaseSensitivity, DirEntry, FileSystem, SourceKind, VMetadata, VirtualFile};

use super::{AccessContext, AccessKind, AccessPolicy, AccessRequest};

/// A filesystem that checks source policy before every data operation.
///
/// Denied paths return a generic source error without revealing whether the
/// underlying filesystem contains the requested entry.
pub struct AuthorizedVirtualFileSystem {
    inner: Arc<dyn FileSystem>,
    policy: Arc<dyn AccessPolicy>,
    access: AccessContext,
    source_id: String,
}

impl AuthorizedVirtualFileSystem {
    pub fn new(
        inner: Arc<dyn FileSystem>,
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

    fn ensure_path(&self, path: Option<&FPath>) -> ForensicResult<()> {
        let target = path.map(|path| path.to_string());
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

impl FileSystem for AuthorizedVirtualFileSystem {
    fn open(&self, path: &FPath) -> ForensicResult<Box<dyn VirtualFile>> {
        self.ensure_path(Some(path))?;
        self.inner.open(path)
    }

    fn metadata(&self, path: &FPath) -> ForensicResult<VMetadata> {
        self.ensure_path(Some(path))?;
        self.inner.metadata(path)
    }

    fn read_dir(
        &self,
        path: &FPath,
    ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<DirEntry>> + '_>> {
        self.ensure_path(Some(path))?;
        let policy = Arc::clone(&self.policy);
        let access = self.access.clone();
        let source_id = self.source_id.clone();
        let inner_iter = self.inner.read_dir(path)?;
        Ok(Box::new(inner_iter.filter(move |entry| match entry {
            Ok(entry) => {
                let target = entry.path.to_string();
                let request =
                    AccessRequest::new(AccessKind::UseSource, &source_id).with_target(&target);
                policy.evaluate(&access, &request).is_allowed()
            }
            // Let read errors surface rather than being silently dropped.
            Err(_) => true,
        })))
    }

    fn source(&self) -> SourceKind {
        self.inner.source()
    }

    fn case_sensitivity(&self) -> CaseSensitivity {
        self.inner.case_sensitivity()
    }

    fn as_streams(&self) -> Option<&dyn crate::traits::vfs::AlternateStreams> {
        // Not threaded through the authorization boundary yet — a stream
        // read would need its own `ensure_path` gate, deferred until a
        // backend actually implements `AlternateStreams`.
        None
    }

    fn as_unallocated(&self) -> Option<&dyn crate::traits::vfs::Unallocated> {
        None
    }
}

/// A registry reader that authorizes key and value paths before exposing them.
///
/// [`RawKey`]'s fields are deliberately private (RFC 0001 P2 — it's what
/// makes cross-reader misuse a compile error), so unlike the old
/// `RegKeyHandle::with_access_path`/`access_path()` mechanism this wrapper
/// no longer has anywhere on the handle itself to stash the authorized path
/// string. Instead it mints and owns *its own* `RawKey` ids, keeping a
/// side table from each of its own ids to `(inner reader's RawKey,
/// authorized path)` — the same bookkeeping shape `TestingRegistry` itself
/// uses for its handle cache.
pub struct AuthorizedRegistryReader {
    inner: Arc<dyn Registry>,
    policy: Arc<dyn AccessPolicy>,
    access: AccessContext,
    source_id: String,
    paths: Mutex<HashMap<u64, (RawKey, String)>>,
    counter: Mutex<u64>,
}

impl AuthorizedRegistryReader {
    pub fn new(
        inner: Arc<dyn Registry>,
        policy: Arc<dyn AccessPolicy>,
        access: AccessContext,
        source_id: impl Into<String>,
    ) -> Self {
        Self {
            inner,
            policy,
            access,
            source_id: source_id.into(),
            paths: Mutex::new(HashMap::new()),
            counter: Mutex::new(0),
        }
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

    fn child_path(parent: &str, child: &str) -> String {
        if parent.is_empty() {
            child.to_string()
        } else if child.is_empty() {
            parent.to_string()
        } else {
            format!("{parent}\\{child}")
        }
    }

    fn mint(&self, inner_key: RawKey, path: String) -> RawKey {
        let mut counter = self
            .counter
            .lock()
            .expect("AuthorizedRegistryReader counter lock poisoned");
        *counter += 1;
        let id = *counter;
        self.paths
            .lock()
            .expect("AuthorizedRegistryReader paths lock poisoned")
            .insert(id, (inner_key, path));
        RawKey::from_raw(id)
    }

    fn unknown_handle() -> ForensicError {
        ForensicError::other("AuthorizedRegistryReader", "unknown handle".to_string())
    }
}

impl Registry for AuthorizedRegistryReader {
    fn root(&self, hive: PredefinedHive) -> ForensicResult<RawKey> {
        // No policy check here: the bare hive prefix isn't itself a target
        // the caller asked for — `RegistryExt::key(path)` resolves hive +
        // subpath in two calls (`root` then `open_raw`), and `open_raw`
        // checks the *combined* path, matching the old `open_key(hive,
        // key_name)`'s single whole-path check. Checking here too would
        // deny paths a whole-path-scoped policy (like this module's own
        // tests) intends to allow.
        let inner_key = self.inner.root(hive)?;
        Ok(self.mint(inner_key, hive.to_string()))
    }

    fn open_raw(&self, parent: &RawKey, name: &str) -> ForensicResult<RawKey> {
        let (path, inner_key) = {
            let paths = self
                .paths
                .lock()
                .expect("AuthorizedRegistryReader paths lock poisoned");
            let (parent_inner, parent_path) =
                paths.get(&parent.raw()).ok_or_else(Self::unknown_handle)?;
            let path = Self::child_path(parent_path, name);
            self.ensure_target(Some(&path))?;
            (path, self.inner.open_raw(parent_inner, name)?)
        };
        Ok(self.mint(inner_key, path))
    }

    fn close_raw(&self, key: &RawKey) {
        let entry = self
            .paths
            .lock()
            .expect("AuthorizedRegistryReader paths lock poisoned")
            .remove(&key.raw());
        if let Some((inner_key, _path)) = entry {
            self.inner.close_raw(&inner_key);
        }
    }

    fn read_raw(&self, key: &RawKey, value: &str) -> ForensicResult<RegValue> {
        let paths = self
            .paths
            .lock()
            .expect("AuthorizedRegistryReader paths lock poisoned");
        let (inner_key, path) = paths.get(&key.raw()).ok_or_else(Self::unknown_handle)?;
        let full = Self::child_path(path, value);
        self.ensure_target(Some(&full))?;
        self.inner.read_raw(inner_key, value)
    }

    fn values_raw(&self, key: &RawKey) -> ForensicResult<Vec<(String, RegValue)>> {
        let paths = self
            .paths
            .lock()
            .expect("AuthorizedRegistryReader paths lock poisoned");
        let (inner_key, path) = paths.get(&key.raw()).ok_or_else(Self::unknown_handle)?;
        self.ensure_target(Some(path))?;
        let all = self.inner.values_raw(inner_key)?;
        Ok(all
            .into_iter()
            .filter(|(name, _)| {
                let full = Self::child_path(path, name);
                self.ensure_target(Some(&full)).is_ok()
            })
            .collect())
    }

    fn keys_raw(&self, key: &RawKey) -> ForensicResult<Vec<KeyEntry>> {
        let paths = self
            .paths
            .lock()
            .expect("AuthorizedRegistryReader paths lock poisoned");
        let (inner_key, path) = paths.get(&key.raw()).ok_or_else(Self::unknown_handle)?;
        self.ensure_target(Some(path))?;
        let all = self.inner.keys_raw(inner_key)?;
        Ok(all
            .into_iter()
            .filter(|entry| {
                let full = Self::child_path(path, &entry.name);
                self.ensure_target(Some(&full)).is_ok()
            })
            .collect())
    }

    fn info_raw(&self, key: &RawKey) -> ForensicResult<KeyInfo> {
        let paths = self
            .paths
            .lock()
            .expect("AuthorizedRegistryReader paths lock poisoned");
        let (inner_key, path) = paths.get(&key.raw()).ok_or_else(Self::unknown_handle)?;
        self.ensure_target(Some(path))?;
        self.inner.info_raw(inner_key)
    }

    fn values_iter_raw<'a>(
        &'a self,
        key: &RawKey,
    ) -> ForensicResult<Box<dyn Iterator<Item = (String, RegValue)> + 'a>> {
        let (path, inner_iter) = {
            let paths = self
                .paths
                .lock()
                .expect("AuthorizedRegistryReader paths lock poisoned");
            let (inner_key, path) = paths.get(&key.raw()).ok_or_else(Self::unknown_handle)?;
            self.ensure_target(Some(path))?;
            (path.clone(), self.inner.values_iter_raw(inner_key)?)
        };
        Ok(Box::new(inner_iter.filter(move |(name, _)| {
            let full = Self::child_path(&path, name);
            self.ensure_target(Some(&full)).is_ok()
        })))
    }

    fn keys_iter_raw<'a>(&'a self, key: &RawKey) -> ForensicResult<Box<dyn Iterator<Item = KeyEntry> + 'a>> {
        let (path, inner_iter) = {
            let paths = self
                .paths
                .lock()
                .expect("AuthorizedRegistryReader paths lock poisoned");
            let (inner_key, path) = paths.get(&key.raw()).ok_or_else(Self::unknown_handle)?;
            self.ensure_target(Some(path))?;
            (path.clone(), self.inner.keys_iter_raw(inner_key)?)
        };
        Ok(Box::new(inner_iter.filter(move |entry| {
            let full = Self::child_path(&path, &entry.name);
            self.ensure_target(Some(&full)).is_ok()
        })))
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
    use crate::traits::registry::RegistryExt;
    use crate::traits::vfs::FileSystemExt;
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

        let filesystem = AuthorizedVirtualFileSystem::new(
            Arc::new(StdVirtualFS::new()),
            Arc::new(PathPolicy),
            AccessContext::new("analyst", "tenant"),
            "evidence-vfs",
        );
        let allowed_str = allowed.to_string_lossy().into_owned();
        let denied_str = denied.to_string_lossy().into_owned();
        assert_eq!(
            String::from_utf8(filesystem.read_all(FPath::new(&allowed_str)).unwrap()).unwrap(),
            "visible"
        );
        assert_eq!(
            filesystem
                .read_all(FPath::new(&denied_str))
                .unwrap_err()
                .to_string(),
            "AuthorizedVirtualFileSystem error: source path is unavailable"
        );
        assert!(!filesystem.exists(FPath::new(&denied_str)));

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
            Arc::new(TestingRegistry::new()),
            Arc::new(RegistryPathPolicy),
            AccessContext::new("analyst", "tenant"),
            "evidence-registry",
        );
        let key_path =
            r"HKU\S-1-5-21-1366093794-4292800403-1155380978-513\Volatile Environment";
        let key = registry.key(key_path).unwrap();
        assert!(key.value("USERPROFILE").is_ok());
        assert_eq!(
            key.value("USERNAME").unwrap_err().to_string(),
            "AuthorizedRegistryReader error: source path is unavailable"
        );
        assert_eq!(
            registry
                .key(r"HKU\S-1-5-21-1366093794-4292800403-1155380978-513\Control Panel")
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
