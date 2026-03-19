use crate::{
    err::ForensicError,
    traits::{
        events::{EventLevel, EventLogIterator, EventLogQuery, EventLogReader, EventRecord},
        registry::{RegHiveKey, RegValue, RegistryKeyInfo, RegistryReader},
    },
};
use std::{cell::RefCell, collections::BTreeMap};

use super::time::{Filetime, ForensicTimestamp};

/// Basic Registry for testing. Includes the user profile "S-1-5-21-1366093794-4292800403-1155380978-513"
#[derive(Clone, Debug)]
pub struct TestingRegistry {
    pub cell: BTreeMap<String, MountedCell>,
    pub cached: RefCell<BTreeMap<RegHiveKey, String>>,
    pub counter: RefCell<isize>,
}

impl Default for TestingRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TestingRegistry {
    pub fn empty() -> Self {
        Self {
            cell: BTreeMap::new(),
            cached: RefCell::new(basic_cache()),
            counter: RefCell::default(),
        }
    }
    pub fn new() -> Self {
        Self {
            cell: basic_registry(),
            cached: RefCell::new(basic_cache()),
            counter: RefCell::new(0),
        }
    }
    pub fn increase_counter(&self) -> isize {
        let mut borrowed = self.counter.borrow_mut();
        let ret = *borrowed;
        *borrowed += 1;
        ret
    }
    pub fn add_value(&mut self, path: &str, value: &str, data: RegValue) {
        let (hkey, rest) = match path.split_once(['/', '\\']) {
            Some(v) => v,
            None => {
                return self
                    .cell
                    .entry(path.to_string())
                    .or_insert(MountedCell::new(path))
                    .add_value("", value, data)
            }
        };
        self.cell
            .entry(hkey.to_string())
            .or_insert(MountedCell::new(hkey))
            .add_value(rest, value, data);
    }
    pub fn contains(&self, path: &str) -> bool {
        let (hkey, rest) = match path.split_once(['/', '\\']) {
            Some(v) => v,
            None => return self.cell.contains_key(path),
        };
        let hive = match self.cell.get(hkey) {
            Some(v) => v,
            None => return false,
        };
        hive.contains_key(rest)
    }
    pub fn get_value(&self, path: &str, value: &str) -> Option<RegValue> {
        let (hkey, rest) = match path.split_once(['/', '\\']) {
            Some(v) => v,
            None => (path, ""),
        };
        let hive = self.cell.get(hkey)?;
        hive.get_value(rest, value)
    }
    pub fn get_values(&self, path: &str) -> Option<Vec<String>> {
        let (hkey, rest) = match path.split_once(['/', '\\']) {
            Some(v) => v,
            None => (path, ""),
        };
        let hive = self.cell.get(hkey)?;
        Some(hive.get_values(rest))
    }
    pub fn get_keys(&self, path: &str) -> Option<Vec<String>> {
        let (hkey, rest) = match path.split_once(['/', '\\']) {
            Some(v) => v,
            None => (path, ""),
        };
        let hive = self.cell.get(hkey)?;
        Some(hive.get_keys(rest))
    }
}

#[derive(Clone, Debug, Default)]
pub struct MountedCell {
    pub name: String,
    pub keys: BTreeMap<String, MountedCell>,
    pub values: BTreeMap<String, RegValue>,
}
impl MountedCell {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            keys: BTreeMap::new(),
            values: BTreeMap::new(),
        }
    }
    pub fn add_key(&mut self, path: &str) {
        if path.is_empty() {
            return;
        }
        let (first, rest) = match path.split_once(['/', '\\']) {
            Some(v) => v,
            None => {
                self.keys
                    .entry(path.to_string())
                    .or_insert(MountedCell::new(path))
                    .add_key(path);
                return;
            }
        };
        self.keys
            .entry(first.to_string())
            .or_insert(MountedCell::new(first))
            .add_key(rest);
    }
    pub fn contains_key(&self, path: &str) -> bool {
        let (first, rest) = match path.split_once(['/', '\\']) {
            Some(v) => v,
            None => return self.keys.contains_key(path),
        };
        let hive = match self.keys.get(first) {
            Some(v) => v,
            None => return false,
        };
        hive.contains_key(rest)
    }
    pub fn add_value(&mut self, path: &str, value: &str, data: RegValue) {
        if path.is_empty() {
            self.values.insert(value.into(), data);
            return;
        }
        let (first, rest) = match path.split_once(['/', '\\']) {
            Some(v) => v,
            None => {
                self.keys
                    .entry(path.to_string())
                    .or_insert(MountedCell::new(path))
                    .add_value("", value, data);
                return;
            }
        };
        self.keys
            .entry(first.to_string())
            .or_insert(MountedCell::new(first))
            .add_value(rest, value, data);
    }
    pub fn get_value(&self, path: &str, value: &str) -> Option<RegValue> {
        if path.is_empty() {
            return self.values.get(value).cloned();
        }
        let (first, rest) = match path.split_once(['/', '\\']) {
            Some(v) => v,
            None => return self.keys.get(path)?.get_value("", value),
        };
        self.keys.get(first)?.get_value(rest, value)
    }
    pub fn get_values(&self, path: &str) -> Vec<String> {
        if path.is_empty() {
            return self
                .values
                .keys()
                .map(|v| v.to_string())
                .collect();
        }
        let (first, rest) = match path.split_once(['/', '\\']) {
            Some(v) => v,
            None => {
                return match self.keys.get(path) {
                    Some(v) => v.get_values(""),
                    None => Vec::new(),
                }
            }
        };
        match self.keys.get(first) {
            Some(v) => v.get_values(rest),
            None => Vec::new(),
        }
    }
    pub fn get_keys(&self, path: &str) -> Vec<String> {
        if path.is_empty() {
            return self
                .keys
                .keys()
                .map(|v| v.to_string())
                .collect();
        }
        let (first, rest) = match path.split_once(['/', '\\']) {
            Some(v) => v,
            None => {
                return match self.keys.get(path) {
                    Some(v) => v.get_keys(""),
                    None => Vec::new(),
                }
            }
        };
        match self.keys.get(first) {
            Some(v) => v.get_keys(rest),
            None => Vec::new(),
        }
    }
}

impl RegistryReader for TestingRegistry {
    fn from_file(
        &self,
        _file: Box<dyn crate::traits::vfs::VirtualFile>,
    ) -> crate::err::ForensicResult<Box<dyn RegistryReader>> {
        Ok(Box::new(TestingRegistry::new()))
    }

    fn from_fs(
        &self,
        _fs: Box<dyn crate::traits::vfs::VirtualFileSystem>,
    ) -> crate::err::ForensicResult<Box<dyn RegistryReader>> {
        Ok(Box::new(TestingRegistry::new()))
    }

    fn open_key(
        &self,
        hkey: crate::traits::registry::RegHiveKey,
        key_name: &str,
    ) -> crate::err::ForensicResult<crate::traits::registry::RegHiveKey> {
        let mut borrowed = self.cached.borrow_mut();
        let (hkey, path) = match borrowed.get(&hkey) {
            Some(v) => {
                let full_path = format!("{}\\{}", v, key_name);
                if !self.contains(&full_path) {
                    return ForensicError::registry_key_not_found(hkey, Some(full_path.into())).into()
                }
                let handle = self.increase_counter();
                (handle, full_path)
            }
            None => return ForensicError::registry_key_not_found(hkey, None).into()
        };
        borrowed.insert(RegHiveKey::Hkey(hkey), path);
        Ok(RegHiveKey::Hkey(hkey))
    }

    fn read_value(
        &self,
        hkey: crate::traits::registry::RegHiveKey,
        value_name: &str,
    ) -> crate::err::ForensicResult<RegValue> {
        let borrowed = self.cached.borrow();
        let key_path = borrowed
            .get(&hkey)
            .ok_or_else(|| ForensicError::registry_key_not_found(hkey, None))?;
        let value = self.get_value(key_path, value_name).ok_or_else(|| {
            ForensicError::registry_value_not_found(hkey, Some(key_path.into()), value_name.to_string())
        })?;
        Ok(value)
    }

    fn enumerate_values(
        &self,
        hkey: crate::traits::registry::RegHiveKey,
    ) -> crate::err::ForensicResult<Vec<String>> {
        let borrowed = self.cached.borrow();
        let key_path = borrowed
            .get(&hkey)
            .ok_or_else(|| ForensicError::registry_key_not_found(hkey, None))?;
        let value = self.get_values(key_path).ok_or_else(|| {
            ForensicError::registry_value_not_found(hkey, Some(key_path.into()), "")
        })?;
        Ok(value)
    }

    fn enumerate_keys(
        &self,
        hkey: crate::traits::registry::RegHiveKey,
    ) -> crate::err::ForensicResult<Vec<String>> {
        let borrowed = self.cached.borrow();
        let key_path = borrowed
            .get(&hkey)
            .ok_or_else(|| ForensicError::registry_key_not_found(hkey, None))?;
        let value = self.get_keys(key_path).ok_or_else(|| {
            ForensicError::registry_key_not_found(hkey, Some(key_path.into()))
        })?;
        Ok(value)
    }

    fn key_at(
        &self,
        hkey: crate::traits::registry::RegHiveKey,
        pos: u32,
    ) -> crate::err::ForensicResult<String> {
        let borrowed = self.cached.borrow();
        let key_path = borrowed
            .get(&hkey)
            .ok_or_else(|| ForensicError::registry_key_not_found(hkey, None))?;
        let mut value = self.get_keys(key_path).ok_or_else(|| {
            ForensicError::registry_key_not_found(hkey, Some(key_path.into()))
        })?;
        let pos = pos as usize;
        if pos > value.len() {
            return Err(ForensicError::DataAccess(crate::err::DataAccessError::NoMoreData));
        }
        Ok(value.remove(pos))
    }

    fn value_at(
        &self,
        hkey: crate::traits::registry::RegHiveKey,
        pos: u32,
    ) -> crate::err::ForensicResult<String> {
        let borrowed = self.cached.borrow();
        let key_path = borrowed
            .get(&hkey)
            .ok_or_else(|| ForensicError::registry_key_not_found(hkey, None))?;
        let mut value = self.get_values(key_path).ok_or_else(|| {
            ForensicError::registry_value_not_found(hkey, Some(key_path.into()), "")
        })?;
        let pos = pos as usize;
        if pos > value.len() {
            return Err(ForensicError::DataAccess(crate::err::DataAccessError::NoMoreData));
        }
        Ok(value.remove(pos))
    }

    fn key_info(&self, hkey: RegHiveKey) -> crate::err::ForensicResult<crate::traits::registry::RegistryKeyInfo> {
        let borrowed = self.cached.borrow();
        let key_path = borrowed
            .get(&hkey)
            .ok_or_else(|| ForensicError::registry_key_not_found(hkey, None))?;
        let value = self.get_values(key_path).ok_or_else(|| {
            ForensicError::registry_value_not_found(hkey, Some(key_path.into()), "")
        })?;
        let keys = self.get_keys(key_path).ok_or_else(|| {
            ForensicError::registry_key_not_found(hkey, Some(key_path.into()))
        })?;
        Ok(RegistryKeyInfo {
            last_write_time : Filetime::new(0),
            subkeys : keys.len() as u32,
            values : value.len() as u32,
            max_subkey_name_length : keys.iter().map(|v| v.len()).fold(0, |acc, e| e.max(acc)) as u32,
            max_value_name_length: value.iter().map(|v| v.len()).fold(0, |acc, e| e.max(acc)) as u32,
            max_value_length: 0,
        })
    }
}
fn basic_cache() -> BTreeMap<RegHiveKey, String> {
    {
        let mut map = BTreeMap::new();
        for (k, p) in [
            (RegHiveKey::HkeyLocalMachine, "HKLM"),
            (RegHiveKey::HkeyCurrentUser, "HKCU"),
            (RegHiveKey::HkeyUsers, "HKU"),
            (RegHiveKey::HkeyClassesRoot, "HKCR"),
        ] {
            map.insert(k, p.to_string());
        }
        map
    }
}

fn basic_registry() -> BTreeMap<String, MountedCell> {
    let mut map = BTreeMap::new();
    for k in ["HKLM", "HKCU", "HKCR"] {
        map.insert(k.to_string(), MountedCell::new(k));
    }
    let mut hkcu_cell = MountedCell::new("HKU");
    hkcu_cell.add_value(
        "S-1-5-21-1366093794-4292800403-1155380978-513\\Volatile Environment",
        "USERPROFILE",
        RegValue::new_sz(r"C:\Users\Tester"),
    );
    hkcu_cell.add_value(
        "S-1-5-21-1366093794-4292800403-1155380978-513\\Volatile Environment",
        "APPDATA",
        RegValue::new_sz(r"C:\Users\Tester\AppData\Roaming"),
    );
    hkcu_cell.add_value(
        "S-1-5-21-1366093794-4292800403-1155380978-513\\Volatile Environment",
        "LOCALAPPDATA",
        RegValue::new_sz(r"C:\Users\Tester\AppData\Local"),
    );
    hkcu_cell.add_value(
        "S-1-5-21-1366093794-4292800403-1155380978-513\\Volatile Environment",
        "USERDOMAIN",
        RegValue::new_sz(r"TestMachine"),
    );
    hkcu_cell.add_value(
        "S-1-5-21-1366093794-4292800403-1155380978-513\\Volatile Environment",
        "USERNAME",
        RegValue::new_sz(r"Tester"),
    );
    map.insert("HKU".into(), hkcu_cell);
    map
}

pub fn init_testing_logger() {
    let rcv = crate::notifications::testing_notifier_dummy();
    std::thread::spawn(move || loop {
        let msg = match rcv.recv() {
            Ok(v) => v,
            Err(_) => return,
        };
        println!(
            "{:?} - {} - {}:{} - {}",
            msg.r#type, msg.module, msg.file, msg.line, msg.data
        );
    });
    let rcv = crate::logging::testing_logger_dummy();
    std::thread::spawn(move || loop {
        let msg = match rcv.recv() {
            Ok(v) => v,
            Err(_) => return,
        };
        println!(
            "{:?} - {} - {}:{} - {}",
            msg.level, msg.module, msg.file, msg.line, msg.data
        );
    });
}

// ============================================================================
// TestingEventLogReader
// ============================================================================

/// In-memory event log reader for testing.
///
/// Stores events grouped by channel. Use `basic_event_log()` for a pre-populated
/// instance or build your own with `TestingEventLogReader::new()` + `add_event()`.
#[derive(Debug, Clone)]
pub struct TestingEventLogReader {
    events: BTreeMap<String, Vec<EventRecord>>,
}

impl Default for TestingEventLogReader {
    fn default() -> Self {
        Self::new()
    }
}

impl TestingEventLogReader {
    pub fn new() -> Self {
        Self {
            events: BTreeMap::new(),
        }
    }

    pub fn add_event(&mut self, event: EventRecord) {
        self.events
            .entry(event.channel.clone())
            .or_default()
            .push(event);
    }
}

struct TestingEventLogIteratorInner {
    events: Vec<EventRecord>,
    pos: usize,
}

impl EventLogIterator for TestingEventLogIteratorInner {
    fn next(&mut self) -> crate::err::ForensicResult<Option<EventRecord>> {
        if self.pos >= self.events.len() {
            return Ok(None);
        }
        let event = self.events[self.pos].clone();
        self.pos += 1;
        Ok(Some(event))
    }
}

impl EventLogReader for TestingEventLogReader {
    fn channels(&self) -> crate::err::ForensicResult<Vec<String>> {
        Ok(self.events.keys().cloned().collect())
    }

    fn query(&self, query: &EventLogQuery) -> crate::err::ForensicResult<Box<dyn EventLogIterator + '_>> {
        let mut matched: Vec<EventRecord> = Vec::new();
        for events in self.events.values() {
            for event in events {
                if query.matches(event) {
                    matched.push(event.clone());
                }
            }
        }
        // Sort by timestamp then record_id for deterministic output
        matched.sort_by(|a, b| a.timestamp.cmp(&b.timestamp).then(a.record_id.cmp(&b.record_id)));
        Ok(Box::new(TestingEventLogIteratorInner {
            events: matched,
            pos: 0,
        }))
    }

    fn event_count(&self, channel: &str) -> crate::err::ForensicResult<u64> {
        match self.events.get(channel) {
            Some(v) => Ok(v.len() as u64),
            None => Err(ForensicError::other("TestingEventLogReader", "channel not found".to_string())),
        }
    }
}

/// Creates a pre-populated `TestingEventLogReader` with sample Security and System events.
pub fn basic_event_log() -> TestingEventLogReader {
    let mut reader = TestingEventLogReader::new();
    // Security events
    reader.add_event(EventRecord {
        record_id: 1001,
        event_id: 4624,
        timestamp: ForensicTimestamp::from_unix_secs(1700000100),
        provider: "Microsoft-Windows-Security-Auditing".into(),
        channel: "Security".into(),
        level: EventLevel::Information,
        computer: "WORKSTATION1".into(),
        user_sid: Some("S-1-5-18".into()),
        data: BTreeMap::new(),
    });
    reader.add_event(EventRecord {
        record_id: 1002,
        event_id: 4625,
        timestamp: ForensicTimestamp::from_unix_secs(1700000200),
        provider: "Microsoft-Windows-Security-Auditing".into(),
        channel: "Security".into(),
        level: EventLevel::Information,
        computer: "WORKSTATION1".into(),
        user_sid: Some("S-1-5-21-1234567890-1234567890-1234567890-1001".into()),
        data: BTreeMap::new(),
    });
    reader.add_event(EventRecord {
        record_id: 1003,
        event_id: 4688,
        timestamp: ForensicTimestamp::from_unix_secs(1700000300),
        provider: "Microsoft-Windows-Security-Auditing".into(),
        channel: "Security".into(),
        level: EventLevel::Information,
        computer: "WORKSTATION1".into(),
        user_sid: Some("S-1-5-18".into()),
        data: BTreeMap::new(),
    });
    // System events
    reader.add_event(EventRecord {
        record_id: 2001,
        event_id: 7045,
        timestamp: ForensicTimestamp::from_unix_secs(1700000150),
        provider: "Service Control Manager".into(),
        channel: "System".into(),
        level: EventLevel::Information,
        computer: "WORKSTATION1".into(),
        user_sid: None,
        data: BTreeMap::new(),
    });
    reader.add_event(EventRecord {
        record_id: 2002,
        event_id: 104,
        timestamp: ForensicTimestamp::from_unix_secs(1700000250),
        provider: "Microsoft-Windows-Eventlog".into(),
        channel: "System".into(),
        level: EventLevel::Warning,
        computer: "WORKSTATION1".into(),
        user_sid: Some("S-1-5-18".into()),
        data: BTreeMap::new(),
    });
    reader
}
