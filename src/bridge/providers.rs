use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use crate::err::{ForensicError, ForensicResult};
use crate::field::Text;
use crate::traits::db::ForensicDb;
use crate::traits::events::{EventLogQuery, EventLogReader};
use crate::traits::registry::{RegHiveKey, RegistryReader, HKCR, HKC, HKCU, HKLM, HKU};
use crate::traits::vfs::{VDirEntry, VirtualFileSystem};

use super::hooks::{inject_hook_children, split_virtual_path, ProviderHook};
use super::{BridgeValue, CancellationToken, ForensicProvider, NodeEntry, NodeType};

// ============================================================================
// RegistryProvider
// ============================================================================

const HIVE_ROOTS: &[(&str, RegHiveKey)] = &[
    ("HKEY_LOCAL_MACHINE", HKLM),
    ("HKEY_CURRENT_USER", HKCU),
    ("HKEY_USERS", HKU),
    ("HKEY_CLASSES_ROOT", HKCR),
    ("HKEY_CURRENT_CONFIG", HKC),
];

/// Forensic bridge provider wrapping a `RegistryReader`.
pub struct RegistryProvider {
    inner: Mutex<Box<dyn RegistryReader + Send>>,
    name: String,
    hooks: Vec<Box<dyn ProviderHook>>,
}

impl RegistryProvider {
    pub fn new(registry: Box<dyn RegistryReader + Send>) -> Self {
        Self {
            inner: Mutex::new(registry),
            name: "Registry".to_string(),
            hooks: Vec::new(),
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn add_hook(&mut self, hook: Box<dyn ProviderHook>) {
        self.hooks.push(hook);
    }

    fn root_children(&self, offset: u64, limit: u64) -> ForensicResult<(Vec<NodeEntry>, u64)> {
        let total = HIVE_ROOTS.len() as u64;
        let entries: Vec<NodeEntry> = HIVE_ROOTS
            .iter()
            .skip(offset as usize)
            .take(limit as usize)
            .map(|(name, _)| NodeEntry {
                name: Text::Owned(name.to_string()),
                node_type: NodeType::Container,
                description: None,
            })
            .collect();
        Ok((entries, total))
    }

    /// Resolve a root name like "HKEY_LOCAL_MACHINE" to a `RegHiveKey`.
    fn resolve_hive(root: &str) -> Option<RegHiveKey> {
        // Accept both the long form and short aliases
        let normalized = root.to_uppercase();
        match normalized.as_str() {
            "HKEY_LOCAL_MACHINE" | "HKLM" => Some(HKLM),
            "HKEY_CURRENT_USER" | "HKCU" => Some(HKCU),
            "HKEY_USERS" | "HKU" => Some(HKU),
            "HKEY_CLASSES_ROOT" | "HKCR" => Some(HKCR),
            "HKEY_CURRENT_CONFIG" | "HKC" => Some(HKC),
            _ => None,
        }
    }

    /// Parse a registry path like `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft` into
    /// `(hive_key, sub_path)`.
    fn parse_path(path: &str) -> ForensicResult<(RegHiveKey, &str)> {
        if path.is_empty() {
            return Err(ForensicError::other("RegistryProvider", "empty path".to_string()));
        }
        let sep_pos = path.find('\\').unwrap_or(path.len());
        let root = &path[..sep_pos];
        let sub = if sep_pos < path.len() {
            &path[sep_pos + 1..]
        } else {
            ""
        };
        let hive = Self::resolve_hive(root).ok_or_else(|| {
            ForensicError::other("RegistryProvider", format!("unknown hive: {}", root))
        })?;
        Ok((hive, sub))
    }
}

impl ForensicProvider for RegistryProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn children(
        &self,
        path: &str,
        offset: u64,
        limit: u64,
        cancel: &CancellationToken,
    ) -> ForensicResult<(Vec<NodeEntry>, u64)> {
        // Root listing
        if path.is_empty() {
            return self.root_children(offset, limit);
        }

        // Check for virtual path segment (hook delegation)
        if let Some((real_parent, hook_name, virtual_child)) = split_virtual_path(path) {
            if !virtual_child.is_empty() {
                // Nested virtual path — delegate read to the hook
                for hook in &self.hooks {
                    if hook.name() == hook_name {
                        return hook.virtual_children(real_parent, &BridgeValue::Null, offset, limit);
                    }
                }
                return Err(ForensicError::other("RegistryProvider", format!("hook '{}' not found", hook_name)));
            }
            // Empty virtual_child means we're listing the hook namespace root
            let value = self.read(real_parent, cancel)?;
            for hook in &self.hooks {
                if hook.name() == hook_name {
                    return hook.virtual_children(real_parent, &value, offset, limit);
                }
            }
            return Err(ForensicError::other("RegistryProvider", format!("hook '{}' not found", hook_name)));
        }

        let (hive, sub) = Self::parse_path(path)?;
        let reg = self.inner.lock().map_err(|_| {
            ForensicError::other("RegistryProvider", "registry lock poisoned".to_string())
        })?;

        // Open the key (or use hive root if sub is empty)
        let hkey = if sub.is_empty() {
            hive
        } else {
            reg.open_key(hive, sub)?
        };

        // Collect sub-keys + values
        let all_keys: Vec<String> = reg.enumerate_keys(hkey).unwrap_or_default();
        let value_names: Vec<String> = reg.enumerate_values(hkey).unwrap_or_default();

        // Build unified child list: keys first (Container), then values (Leaf)
        let mut entries: Vec<NodeEntry> = Vec::new();
        let total_keys = all_keys.len() as u64;
        let total_values = value_names.len() as u64;

        // Inject hook virtual children (one Container entry per matching hook)
        // We check each value against hooks to see which hooks apply
        let mut hook_entries: Vec<NodeEntry> = Vec::new();
        for vname in &value_names {
            if cancel.is_cancelled() {
                break;
            }
            if let Ok(rv) = reg.read_value(hkey, vname) {
                let bv: BridgeValue = rv.into();
                // Build the full path of this value
                let value_path = format!("{}\\{}", path, vname);
                inject_hook_children(&mut hook_entries, &self.hooks, &value_path, &bv);
            }
        }
        let total_hooks = hook_entries.len() as u64;
        let total = total_keys + total_values + total_hooks;

        // Paginate across the unified sequence: [keys] + [values] + [hook entries]
        let start = offset as usize;
        let count = limit as usize;

        let keys_page = all_keys
            .iter()
            .skip(start)
            .take(count)
            .map(|k| NodeEntry {
                name: Text::Owned(k.clone()),
                node_type: NodeType::Container,
                description: None,
            });
        entries.extend(keys_page);

        if entries.len() < count {
            let val_skip = start.saturating_sub(all_keys.len());
            let val_take = count - entries.len();
            let values_page = value_names
                .iter()
                .skip(val_skip)
                .take(val_take)
                .map(|v| NodeEntry {
                    name: Text::Owned(v.clone()),
                    node_type: NodeType::Leaf,
                    description: None,
                });
            entries.extend(values_page);
        }

        if entries.len() < count {
            let hook_skip = start.saturating_sub(all_keys.len() + value_names.len());
            let hook_take = count - entries.len();
            entries.extend(hook_entries.into_iter().skip(hook_skip).take(hook_take));
        }

        if sub.is_empty() {
            // No close needed for root hive keys
        } else {
            reg.close_key(hkey);
        }

        Ok((entries, total))
    }

    fn read(&self, path: &str, cancel: &CancellationToken) -> ForensicResult<BridgeValue> {
        // Check for virtual path
        if let Some((real_parent, hook_name, virtual_child)) = split_virtual_path(path) {
            for hook in &self.hooks {
                if hook.name() == hook_name {
                    return hook.read_virtual(real_parent, virtual_child);
                }
            }
            return Err(ForensicError::other(
                "RegistryProvider",
                format!("hook '{}' not found", hook_name),
            ));
        }

        let (hive, sub) = Self::parse_path(path)?;
        let sep = sub.rfind('\\');
        let (key_path, value_name) = match sep {
            Some(pos) => (&sub[..pos], &sub[pos + 1..]),
            None => ("", sub),
        };

        let reg = self.inner.lock().map_err(|_| {
            ForensicError::other("RegistryProvider", "registry lock poisoned".to_string())
        })?;

        let hkey = if key_path.is_empty() {
            hive
        } else {
            reg.open_key(hive, key_path)?
        };

        let rv = reg.read_value(hkey, value_name)?;
        if !key_path.is_empty() {
            reg.close_key(hkey);
        }
        Ok(rv.into())
    }

    fn metadata(
        &self,
        path: &str,
        _cancel: &CancellationToken,
    ) -> ForensicResult<BTreeMap<Text, BridgeValue>> {
        let (hive, sub) = Self::parse_path(path)?;
        let reg = self.inner.lock().map_err(|_| {
            ForensicError::other("RegistryProvider", "registry lock poisoned".to_string())
        })?;
        let hkey = if sub.is_empty() {
            hive
        } else {
            reg.open_key(hive, sub)?
        };
        let mut meta = BTreeMap::new();
        if let Ok(info) = reg.key_info(hkey) {
            meta.insert(
                Text::Borrowed("last_written"),
                BridgeValue::Timestamp(info.last_write_time.into()),
            );
            meta.insert(Text::Borrowed("subkeys"), BridgeValue::U64(info.subkeys as u64));
            meta.insert(Text::Borrowed("values"), BridgeValue::U64(info.values as u64));
        }
        if !sub.is_empty() {
            reg.close_key(hkey);
        }
        Ok(meta)
    }
}

// ============================================================================
// VfsProvider
// ============================================================================

/// Forensic bridge provider wrapping a `VirtualFileSystem`.
pub struct VfsProvider {
    inner: Mutex<Box<dyn VirtualFileSystem + Send>>,
    name: String,
    hooks: Vec<Box<dyn ProviderHook>>,
}

impl VfsProvider {
    pub fn new(vfs: Box<dyn VirtualFileSystem + Send>) -> Self {
        Self {
            inner: Mutex::new(vfs),
            name: "Filesystem".to_string(),
            hooks: Vec::new(),
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn add_hook(&mut self, hook: Box<dyn ProviderHook>) {
        self.hooks.push(hook);
    }
}

impl ForensicProvider for VfsProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn children(
        &self,
        path: &str,
        offset: u64,
        limit: u64,
        cancel: &CancellationToken,
    ) -> ForensicResult<(Vec<NodeEntry>, u64)> {
        let dir_path = if path.is_empty() { "/" } else { path };
        let mut vfs = self.inner.lock().map_err(|_| {
            ForensicError::other("VfsProvider", "vfs lock poisoned".to_string())
        })?;
        let entries_raw = vfs.read_dir(Path::new(dir_path))?;
        let total = entries_raw.len() as u64;
        let entries: Vec<NodeEntry> = entries_raw
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .filter_map(|e| {
                if cancel.is_cancelled() {
                    return None;
                }
                let (name, node_type) = match &e {
                    VDirEntry::Directory(n) => (n.clone(), NodeType::Container),
                    VDirEntry::File(n) | VDirEntry::Symlink(n) => (n.clone(), NodeType::Leaf),
                };
                Some(NodeEntry {
                    name: Text::Owned(name),
                    node_type,
                    description: None,
                })
            })
            .collect();
        Ok((entries, total))
    }

    fn read(&self, path: &str, _cancel: &CancellationToken) -> ForensicResult<BridgeValue> {
        let mut vfs = self.inner.lock().map_err(|_| {
            ForensicError::other("VfsProvider", "vfs lock poisoned".to_string())
        })?;
        let data = vfs.read_all(Path::new(path))?;;
        // Try to decode as UTF-8; fall back to binary
        match String::from_utf8(data.clone()) {
            Ok(s) => Ok(BridgeValue::Text(Text::Owned(s))),
            Err(_) => Ok(BridgeValue::Binary(data)),
        }
    }

    fn metadata(
        &self,
        path: &str,
        _cancel: &CancellationToken,
    ) -> ForensicResult<BTreeMap<Text, BridgeValue>> {
        let mut vfs = self.inner.lock().map_err(|_| {
            ForensicError::other("VfsProvider", "vfs lock poisoned".to_string())
        })?;
        let meta = vfs.metadata(Path::new(path))?;
        let mut map = BTreeMap::new();
        map.insert(Text::Borrowed("size"), BridgeValue::U64(meta.len()));
        map.insert(Text::Borrowed("created"), BridgeValue::Timestamp(meta.created()));
        map.insert(Text::Borrowed("accessed"), BridgeValue::Timestamp(meta.accessed()));
        map.insert(Text::Borrowed("modified"), BridgeValue::Timestamp(meta.modified()));
        Ok(map)
    }
}

// ============================================================================
// EventLogProvider
// ============================================================================

/// Forensic bridge provider wrapping an `EventLogReader`.
pub struct EventLogProvider {
    inner: Mutex<Box<dyn EventLogReader + Send>>,
    name: String,
}

impl EventLogProvider {
    pub fn new(reader: Box<dyn EventLogReader + Send>) -> Self {
        Self {
            inner: Mutex::new(reader),
            name: "Events".to_string(),
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }
}

impl ForensicProvider for EventLogProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn children(
        &self,
        path: &str,
        offset: u64,
        limit: u64,
        cancel: &CancellationToken,
    ) -> ForensicResult<(Vec<NodeEntry>, u64)> {
        let reader = self.inner.lock().map_err(|_| {
            ForensicError::other("EventLogProvider", "reader lock poisoned".to_string())
        })?;

        if path.is_empty() {
            // Root: list channels
            let channels = reader.channels()?;
            let total = channels.len() as u64;
            let entries: Vec<NodeEntry> = channels
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .map(|ch| NodeEntry {
                    name: Text::Owned(ch),
                    node_type: NodeType::Container,
                    description: None,
                })
                .collect();
            return Ok((entries, total));
        }

        // path = channel name; list events as Leaf nodes
        let channel_ref: &str = path;
        let query = EventLogQuery::new().with_channels(&[channel_ref]);
        let mut iter = reader.query(&query)?;
        let mut records = Vec::new();
        loop {
            if cancel.is_cancelled() {
                break;
            }
            match iter.next() {
                Ok(Some(rec)) => records.push(rec),
                Ok(None) => break,
                Err(_) => break,
            }
        }
        let total = records.len() as u64;
        let entries: Vec<NodeEntry> = records
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .map(|rec| NodeEntry {
                name: Text::Owned(format!("{}:{}", rec.record_id, rec.event_id)),
                node_type: NodeType::Leaf,
                description: Some(Text::Owned(format!("{}", rec.timestamp))),
            })
            .collect();
        Ok((entries, total))
    }

    fn read(&self, path: &str, _cancel: &CancellationToken) -> ForensicResult<BridgeValue> {
        // path = "channel/record_id:event_id" — parse record_id
        let (channel, record_part) = path.split_once('/').unwrap_or((path, ""));
        let record_id: u64 = record_part
            .split(':')
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let reader = self.inner.lock().map_err(|_| {
            ForensicError::other("EventLogProvider", "reader lock poisoned".to_string())
        })?;
        let query = EventLogQuery::new().with_channels(&[channel]);
        let mut iter = reader.query(&query)?;
        loop {
            match iter.next() {
                Ok(Some(rec)) if rec.record_id == record_id => {
                    let mut map = BTreeMap::new();
                    map.insert(Text::Borrowed("record_id"), BridgeValue::U64(rec.record_id));
                    map.insert(Text::Borrowed("event_id"), BridgeValue::U64(rec.event_id as u64));
                    map.insert(Text::Borrowed("channel"), BridgeValue::Text(Text::Owned(rec.channel)));
                    map.insert(Text::Borrowed("provider"), BridgeValue::Text(Text::Owned(rec.provider)));
                    map.insert(Text::Borrowed("timestamp"), BridgeValue::Timestamp(rec.timestamp));
                    for (k, v) in rec.data {
                        map.insert(k, v.into());
                    }
                    return Ok(BridgeValue::Map(map));
                }
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => break,
            }
        }
        Err(ForensicError::missing_data("EventLogProvider", format!("record not found: {}", path).into()))
    }

    fn metadata(
        &self,
        path: &str,
        _cancel: &CancellationToken,
    ) -> ForensicResult<BTreeMap<Text, BridgeValue>> {
        let reader = self.inner.lock().map_err(|_| {
            ForensicError::other("EventLogProvider", "reader lock poisoned".to_string())
        })?;
        let mut map = BTreeMap::new();
        let channel = path.split('/').next().unwrap_or(path);
        if let Ok(count) = reader.event_count(channel) {
            map.insert(Text::Borrowed("event_count"), BridgeValue::U64(count));
        }
        Ok(map)
    }
}

// ============================================================================
// DatabaseProvider
// ============================================================================

/// Forensic bridge provider wrapping a `ForensicDb`.
pub struct DatabaseProvider {
    inner: Box<dyn ForensicDb + Send>,
    name: String,
}

impl DatabaseProvider {
    pub fn new(db: Box<dyn ForensicDb + Send>) -> Self {
        Self {
            inner: db,
            name: "Database".to_string(),
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }
}

impl ForensicProvider for DatabaseProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn children(
        &self,
        path: &str,
        offset: u64,
        limit: u64,
        _cancel: &CancellationToken,
    ) -> ForensicResult<(Vec<NodeEntry>, u64)> {
        if path.is_empty() {
            // Root: list tables
            let tables = self.inner.list_tables()?;
            let total = tables.len() as u64;
            let entries: Vec<NodeEntry> = tables
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .map(|t| NodeEntry {
                    name: Text::Owned(t),
                    node_type: NodeType::Container,
                    description: None,
                })
                .collect();
            return Ok((entries, total));
        }

        // path = table name; list rows
        let table = self.inner.table(path)?;
        let mut rows_cursor = table.iter_rows()?;
        let col_count = rows_cursor.column_count();
        let col_names: Vec<String> = (0..col_count)
            .filter_map(|i| rows_cursor.column_name(i).map(|s| s.to_string()))
            .collect();

        let mut all_rows: Vec<NodeEntry> = Vec::new();
        let mut row_idx: u64 = 0;
        loop {
            match rows_cursor.next() {
                Ok(true) => {
                    let label = rows_cursor
                        .read_ref(0)
                        .map(|v| v.to_string())
                        .unwrap_or_else(|_| format!("row_{}", row_idx));
                    all_rows.push(NodeEntry {
                        name: Text::Owned(format!("{}/{}", path, row_idx)),
                        node_type: NodeType::Leaf,
                        description: Some(Text::Owned(label)),
                    });
                    row_idx += 1;
                }
                Ok(false) => break,
                Err(_) => break,
            }
        }
        let total = all_rows.len() as u64;
        let entries: Vec<NodeEntry> = all_rows
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok((entries, total))
    }

    fn read(&self, path: &str, _cancel: &CancellationToken) -> ForensicResult<BridgeValue> {
        // path = "table/row_idx"
        let (table_name, row_str) = path.split_once('/').unwrap_or((path, "0"));
        let target_row: u64 = row_str.parse().unwrap_or(0);

        let table = self.inner.table(table_name)?;
        let mut rows = table.iter_rows()?;
        let col_count = rows.column_count();
        let col_names: Vec<String> = (0..col_count)
            .filter_map(|i| rows.column_name(i).map(|s| s.to_string()))
            .collect();

        let mut idx: u64 = 0;
        loop {
            match rows.next() {
                Ok(true) => {
                    if idx == target_row {
                        let mut map = BTreeMap::new();
                        for (i, col) in col_names.iter().enumerate() {
                            if let Ok(val) = rows.read(i) {
                                let bv = forensic_value_to_bridge(val);
                                map.insert(Text::Owned(col.clone()), bv);
                            }
                        }
                        return Ok(BridgeValue::Map(map));
                    }
                    idx += 1;
                }
                Ok(false) => break,
                Err(_) => break,
            }
        }
        Err(ForensicError::missing_data("DatabaseProvider", format!("row {} not found in {}", target_row, table_name).into()))
    }

    fn metadata(
        &self,
        path: &str,
        _cancel: &CancellationToken,
    ) -> ForensicResult<BTreeMap<Text, BridgeValue>> {
        if path.is_empty() {
            return Ok(BTreeMap::new());
        }
        let table = self.inner.table(path)?;
        let mut map = BTreeMap::new();
        if let Some(count) = table.row_count() {
            map.insert(Text::Borrowed("row_count"), BridgeValue::U64(count));
        }
        let cols: Vec<BridgeValue> = table
            .columns()
            .iter()
            .map(|c| BridgeValue::Text(Text::Owned(c.name.clone())))
            .collect();
        map.insert(Text::Borrowed("columns"), BridgeValue::Array(cols));
        Ok(map)
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn forensic_value_to_bridge(val: crate::traits::db::ForensicValue) -> BridgeValue {
    use crate::traits::db::ForensicValue as FV;
    match val {
        FV::Null => BridgeValue::Null,
        FV::Bool(v) => BridgeValue::Bool(v),
        FV::I64(v) => BridgeValue::I64(v),
        FV::U64(v) => BridgeValue::U64(v),
        FV::F64(v) => BridgeValue::F64(v),
        FV::DateTime(ft) => BridgeValue::Timestamp(ft.into()),
        FV::Guid(v) => {
            let s = format!(
                "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                u32::from_le_bytes([v[0], v[1], v[2], v[3]]),
                u16::from_le_bytes([v[4], v[5]]),
                u16::from_le_bytes([v[6], v[7]]),
                v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]
            );
            BridgeValue::Text(Text::Owned(s))
        }
        FV::Text(s) => BridgeValue::Text(Text::Owned(s)),
        FV::Binary(v) => BridgeValue::Binary(v),
    }
}
