use std::collections::BTreeMap;
use std::io::Read;
use std::sync::{Arc, Mutex};

use crate::capabilities::{
    CapabilityError, CapabilityErrorKind, CapabilityResult, CapabilityValue, ResourceContent,
    ResourceEntry, ResourceId, ResourceKind, ResourceMetadata, ResourceProvider,
    ResourceProviderDescriptor,
};
use crate::core::path::FPath;
use crate::err::{ForensicError, ForensicResult};
use crate::field::Text;
use crate::traits::db::ForensicDb;
use crate::traits::events::{EventLogQuery, EventLogReader};
use crate::traits::registry::{Registry, RegistryExt};
use crate::traits::vfs::{FileSystem, FileSystemExt, VFileType};

use super::hooks::{collect_hook_actions, inject_hook_children, split_virtual_path, ProviderHook};
use super::{BridgeValue, CancellationToken, ForensicProvider, NodeEntry, NodeType};

// ============================================================================
// RegistryProvider
// ============================================================================

const HIVE_ROOT_NAMES: &[&str] = &[
    "HKEY_LOCAL_MACHINE",
    "HKEY_CURRENT_USER",
    "HKEY_USERS",
    "HKEY_CLASSES_ROOT",
    "HKEY_CURRENT_CONFIG",
];

/// Forensic bridge provider wrapping a `Registry`.
pub struct RegistryProvider {
    inner: Arc<dyn Registry>,
    name: String,
    resource_descriptor: ResourceProviderDescriptor,
    hooks: Vec<Box<dyn ProviderHook>>,
}

impl RegistryProvider {
    pub fn new(registry: Arc<dyn Registry>) -> Self {
        Self {
            inner: registry,
            name: "Registry".to_string(),
            resource_descriptor: ResourceProviderDescriptor {
                id: "registry".to_string(),
                title: "Registry".to_string(),
                description: "Forensic Windows Registry resources".to_string(),
            },
            hooks: Vec::new(),
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self.resource_descriptor.title = self.name.clone();
        self
    }

    /// Set a stable resource-provider ID for capability registry registration.
    pub fn with_resource_id(mut self, id: impl Into<String>) -> Self {
        self.resource_descriptor.id = id.into();
        self
    }

    pub fn add_hook(&mut self, hook: Box<dyn ProviderHook>) {
        self.hooks.push(hook);
    }

    fn root_children(&self, offset: u64, limit: u64) -> ForensicResult<(Vec<NodeEntry>, u64)> {
        let total = HIVE_ROOT_NAMES.len() as u64;
        let entries: Vec<NodeEntry> = HIVE_ROOT_NAMES
            .iter()
            .skip(offset as usize)
            .take(limit as usize)
            .map(|name| NodeEntry {
                name: Text::Owned(name.to_string()),
                node_type: NodeType::Container,
                description: None,
            })
            .collect();
        Ok((entries, total))
    }
}

impl ResourceProvider for RegistryProvider {
    fn descriptor(&self) -> &ResourceProviderDescriptor {
        &self.resource_descriptor
    }

    fn children(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<Vec<ResourceEntry>> {
        ensure_resource_not_cancelled(cancellation)?;
        let (entries, _) = ForensicProvider::children(self, path, 0, u64::MAX, cancellation)
            .map_err(|_| registry_capability_error())?;
        ensure_resource_not_cancelled(cancellation)?;
        Ok(entries
            .into_iter()
            .map(|entry| ResourceEntry {
                id: ResourceId::new(
                    self.resource_descriptor.id.clone(),
                    resource_child_path(path, entry.name.as_ref()),
                ),
                name: entry.name.into_owned(),
                kind: resource_kind(entry.node_type),
                description: entry.description.map(Text::into_owned),
            })
            .collect())
    }

    fn read(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<ResourceContent> {
        ensure_resource_not_cancelled(cancellation)?;
        let value = ForensicProvider::read(self, path, cancellation)
            .map_err(|_| registry_capability_error())?;
        ensure_resource_not_cancelled(cancellation)?;
        Ok(ResourceContent::Structured {
            value: capability_value_from_bridge(value),
            media_type: Some("application/vnd.forensic-rs.registry-value".to_string()),
        })
    }

    fn metadata(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<ResourceMetadata> {
        ensure_resource_not_cancelled(cancellation)?;
        let values = ForensicProvider::metadata(self, path, cancellation)
            .map_err(|_| registry_capability_error())?
            .into_iter()
            .map(|(name, value)| (name, capability_value_from_bridge(value)))
            .collect();
        ensure_resource_not_cancelled(cancellation)?;
        Ok(ResourceMetadata {
            media_type: None,
            size: None,
            values,
        })
    }

    fn actions(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<Vec<String>> {
        ensure_resource_not_cancelled(cancellation)?;
        ForensicProvider::actions(self, path, cancellation).map_err(|_| registry_capability_error())
    }
}

fn registry_capability_error() -> CapabilityError {
    CapabilityError::new(
        CapabilityErrorKind::Internal,
        "registry resource operation failed",
    )
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
                // Nested virtual path — delegate to the hook, passing the
                // remaining sub-path through so it can self-route arbitrary depth.
                for hook in &self.hooks {
                    if hook.name() == hook_name {
                        return hook.virtual_children(
                            real_parent,
                            &BridgeValue::Null,
                            virtual_child,
                            offset,
                            limit,
                        );
                    }
                }
                return Err(ForensicError::other(
                    "RegistryProvider",
                    format!("hook '{}' not found", hook_name),
                ));
            }
            // Empty virtual_child means we're listing the hook namespace root
            let value = ForensicProvider::read(self, real_parent, cancel)?;
            for hook in &self.hooks {
                if hook.name() == hook_name {
                    return hook.virtual_children(real_parent, &value, "", offset, limit);
                }
            }
            return Err(ForensicError::other(
                "RegistryProvider",
                format!("hook '{}' not found", hook_name),
            ));
        }

        // A bare hive name (no `\`) has no key/value component to enumerate
        // — mirrors the old backend's "cannot enumerate hive root directly"
        // restriction.
        if !path.contains('\\') {
            return Err(ForensicError::other(
                "RegistryProvider",
                "Cannot enumerate hive root directly".to_string(),
            ));
        }
        let hkey = self.inner.key(path)?;
        let all_keys = hkey.keys()?;
        let all_values = hkey.values()?;

        // Build unified child list: keys first (Container), then values (Leaf)
        let mut entries: Vec<NodeEntry> = Vec::new();
        let total_keys = all_keys.len() as u64;
        let total_values = all_values.len() as u64;

        // Inject hook virtual children (one Container entry per matching hook)
        // We check each value against hooks to see which hooks apply
        let mut hook_entries: Vec<NodeEntry> = Vec::new();
        for (vname, rv) in &all_values {
            if cancel.is_cancelled() {
                break;
            }
            let bv: BridgeValue = rv.clone().into();
            // Build the full path of this value
            let value_path = format!("{}\\{}", path, vname);
            inject_hook_children(&mut hook_entries, &self.hooks, &value_path, &bv);
        }
        let total_hooks = hook_entries.len() as u64;
        let total = total_keys + total_values + total_hooks;

        // Paginate across the unified sequence: [keys] + [values] + [hook entries]
        let start = offset as usize;
        let count = limit as usize;

        let keys_page = all_keys.iter().skip(start).take(count).map(|k| NodeEntry {
            name: Text::Owned(k.name.clone()),
            node_type: NodeType::Container,
            description: None,
        });
        entries.extend(keys_page);

        if entries.len() < count {
            let val_skip = start.saturating_sub(all_keys.len());
            let val_take = count - entries.len();
            let values_page = all_values
                .iter()
                .skip(val_skip)
                .take(val_take)
                .map(|(name, _)| NodeEntry {
                    name: Text::Owned(name.clone()),
                    node_type: NodeType::Leaf,
                    description: None,
                });
            entries.extend(values_page);
        }

        if entries.len() < count {
            let hook_skip = start.saturating_sub(all_keys.len() + all_values.len());
            let hook_take = count - entries.len();
            entries.extend(hook_entries.into_iter().skip(hook_skip).take(hook_take));
        }

        Ok((entries, total))
    }

    fn read(&self, path: &str, _cancel: &CancellationToken) -> ForensicResult<BridgeValue> {
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

        let sep = path.rfind('\\').ok_or_else(|| {
            ForensicError::other(
                "RegistryProvider",
                "Cannot read values from hive root".to_string(),
            )
        })?;
        let (key_path, value_name) = (&path[..sep], &path[sep + 1..]);
        if !key_path.contains('\\') {
            // `key_path` is itself a bare hive name — mirrors the old
            // backend's "cannot read values from hive root" restriction.
            return Err(ForensicError::other(
                "RegistryProvider",
                "Cannot read values from hive root".to_string(),
            ));
        }

        let rv = self.inner.value(key_path, value_name)?;
        Ok(rv.into())
    }

    fn metadata(
        &self,
        path: &str,
        _cancel: &CancellationToken,
    ) -> ForensicResult<BTreeMap<Text, BridgeValue>> {
        if !path.contains('\\') {
            return Err(ForensicError::other(
                "RegistryProvider",
                "Cannot get metadata of hive root".to_string(),
            ));
        }
        let hkey = self.inner.key(path)?;
        let mut meta = BTreeMap::new();
        if let Ok(info) = hkey.info() {
            meta.insert(
                Text::Borrowed("last_written"),
                info.last_write_time
                    .map(BridgeValue::Timestamp)
                    .unwrap_or(BridgeValue::Null),
            );
            meta.insert(
                Text::Borrowed("subkeys"),
                BridgeValue::U64(info.subkeys as u64),
            );
            meta.insert(
                Text::Borrowed("values"),
                BridgeValue::U64(info.values as u64),
            );
        }
        Ok(meta)
    }

    fn actions(&self, path: &str, cancel: &CancellationToken) -> ForensicResult<Vec<String>> {
        if let Some((real_parent, hook_name, virtual_tail)) = split_virtual_path(path) {
            for hook in &self.hooks {
                if hook.name() == hook_name {
                    return Ok(hook.virtual_action_ids(real_parent, virtual_tail));
                }
            }
            return Err(ForensicError::other(
                "RegistryProvider",
                format!("hook '{}' not found", hook_name),
            ));
        }
        let value = ForensicProvider::read(self, path, cancel)?;
        Ok(collect_hook_actions(&self.hooks, path, &value))
    }
}

// ============================================================================
// VfsProvider
// ============================================================================

/// Forensic bridge provider wrapping a `FileSystem`.
pub struct VfsProvider {
    inner: Arc<dyn FileSystem>,
    name: String,
    resource_descriptor: ResourceProviderDescriptor,
    hooks: Vec<Box<dyn ProviderHook>>,
}

impl VfsProvider {
    pub fn new(vfs: Arc<dyn FileSystem>) -> Self {
        Self {
            inner: vfs,
            name: "Filesystem".to_string(),
            resource_descriptor: ResourceProviderDescriptor {
                id: "filesystem".to_string(),
                title: "Filesystem".to_string(),
                description: "Forensic virtual filesystem resources".to_string(),
            },
            hooks: Vec::new(),
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self.resource_descriptor.title = self.name.clone();
        self
    }

    /// Set a stable resource-provider ID for capability registry registration.
    pub fn with_resource_id(mut self, id: impl Into<String>) -> Self {
        self.resource_descriptor.id = id.into();
        self
    }

    pub fn add_hook(&mut self, hook: Box<dyn ProviderHook>) {
        self.hooks.push(hook);
    }

    /// Bounded content peek used for hook matching/dispatch, not a full read.
    ///
    /// Files can be large, so hooks never see the whole file just to run
    /// `matches_value` — only the first 64 bytes, as `BridgeValue::Binary`.
    fn content_peek(&self, path: &str) -> ForensicResult<BridgeValue> {
        let mut file = self.inner.open(FPath::new(path))?;
        let mut buf = [0u8; 64];
        let n = Read::read(&mut file, &mut buf).unwrap_or(0);
        Ok(BridgeValue::Binary(buf[..n].to_vec()))
    }

    /// Resolve `path` against a registered hook when it doesn't resolve
    /// directly. VFS has no `[hookname]` bracket-segment marker (unlike
    /// `RegistryProvider`) — a path already maps 1:1 to a single value and a
    /// file has no real children, so a matched hook can simply "become" the
    /// recognized file's children with no collision risk.
    ///
    /// Walks up `path`'s ancestors to find the longest real-file prefix,
    /// takes a content peek of that file, and returns the first hook whose
    /// `matches_path`/`matches_value` gate holds for it, along with the real
    /// file's own path and whatever remains of `path` below it ("" at the
    /// file's own path, e.g. "Applications" one level deeper).
    fn resolve_hook(&self, path: &str) -> Option<(&dyn ProviderHook, String, String, BridgeValue)> {
        let mut candidate = FPath::new(path);
        loop {
            if let Ok(meta) = self.inner.metadata(candidate) {
                if meta.is_file() {
                    let real_file_path = candidate.as_str().to_string();
                    let tail = path[real_file_path.len()..]
                        .trim_start_matches(['/', '\\'])
                        .to_string();
                    let peek = self.content_peek(&real_file_path).ok()?;
                    for hook in &self.hooks {
                        if hook.matches_path(&real_file_path)
                            && hook.matches_value(&real_file_path, &peek)
                        {
                            return Some((hook.as_ref(), real_file_path, tail, peek));
                        }
                    }
                    return None;
                }
            }
            candidate = candidate.parent()?;
        }
    }
}

impl ResourceProvider for VfsProvider {
    fn descriptor(&self) -> &ResourceProviderDescriptor {
        &self.resource_descriptor
    }

    fn children(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<Vec<ResourceEntry>> {
        if cancellation.is_cancelled() {
            return Err(CapabilityError::new(
                CapabilityErrorKind::Cancelled,
                "operation cancelled",
            ));
        }
        let directory = if path.is_empty() { "/" } else { path };
        let entries = self
            .inner
            .read_dir(FPath::new(directory))
            .map_err(|_| vfs_capability_error())?;
        let mut resources = Vec::new();
        for entry in entries {
            if cancellation.is_cancelled() {
                return Err(CapabilityError::new(
                    CapabilityErrorKind::Cancelled,
                    "operation cancelled",
                ));
            }
            let entry = entry.map_err(|_| vfs_capability_error())?;
            let kind = match entry.file_type {
                VFileType::Directory => ResourceKind::Container,
                _ => ResourceKind::Leaf,
            };
            let name = entry.file_name().unwrap_or_default().to_string();
            let child_path = entry.path.to_string();
            resources.push(ResourceEntry {
                id: ResourceId::new(self.resource_descriptor.id.clone(), child_path),
                name,
                kind,
                description: None,
            });
        }
        Ok(resources)
    }

    fn read(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<ResourceContent> {
        if cancellation.is_cancelled() {
            return Err(CapabilityError::new(
                CapabilityErrorKind::Cancelled,
                "operation cancelled",
            ));
        }
        let data = self
            .inner
            .read_all(FPath::new(path))
            .map_err(|_| vfs_capability_error())?;
        match String::from_utf8(data) {
            Ok(text) => Ok(ResourceContent::Text {
                text,
                media_type: Some("text/plain".to_string()),
            }),
            Err(error) => Ok(ResourceContent::Bytes {
                data: error.into_bytes(),
                media_type: Some("application/octet-stream".to_string()),
            }),
        }
    }

    fn metadata(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<ResourceMetadata> {
        if cancellation.is_cancelled() {
            return Err(CapabilityError::new(
                CapabilityErrorKind::Cancelled,
                "operation cancelled",
            ));
        }
        let metadata = self
            .inner
            .metadata(FPath::new(path))
            .map_err(|_| vfs_capability_error())?;
        let mut values = BTreeMap::new();
        values.insert(
            Text::Borrowed("created"),
            metadata
                .created_opt()
                .copied()
                .map(CapabilityValue::Timestamp)
                .unwrap_or(CapabilityValue::Null),
        );
        values.insert(
            Text::Borrowed("accessed"),
            metadata
                .accessed_opt()
                .copied()
                .map(CapabilityValue::Timestamp)
                .unwrap_or(CapabilityValue::Null),
        );
        values.insert(
            Text::Borrowed("modified"),
            metadata
                .modified_opt()
                .copied()
                .map(CapabilityValue::Timestamp)
                .unwrap_or(CapabilityValue::Null),
        );
        Ok(ResourceMetadata {
            media_type: None,
            size: Some(metadata.len()),
            values,
        })
    }

    fn actions(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<Vec<String>> {
        if cancellation.is_cancelled() {
            return Err(CapabilityError::new(
                CapabilityErrorKind::Cancelled,
                "operation cancelled",
            ));
        }
        ForensicProvider::actions(self, path, cancellation).map_err(|_| vfs_capability_error())
    }
}

fn vfs_capability_error() -> CapabilityError {
    CapabilityError::new(
        CapabilityErrorKind::Internal,
        "filesystem resource operation failed",
    )
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
        let read_dir_iter = match self.inner.read_dir(FPath::new(dir_path)) {
            Ok(iter) => iter,
            Err(err) => {
                // `path` isn't a real directory (it may be a file whose
                // content a registered hook recognizes) — try hook dispatch
                // before propagating the original error.
                if let Some((hook, real_file_path, tail, peek)) = self.resolve_hook(path) {
                    return hook.virtual_children(&real_file_path, &peek, &tail, offset, limit);
                }
                return Err(err);
            }
        };
        let entries_raw: Vec<_> = read_dir_iter.collect::<ForensicResult<Vec<_>>>()?;
        let total = entries_raw.len() as u64;
        let entries: Vec<NodeEntry> = entries_raw
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .filter_map(|e| {
                if cancel.is_cancelled() {
                    return None;
                }
                let node_type = match e.file_type {
                    VFileType::Directory => NodeType::Container,
                    _ => NodeType::Leaf,
                };
                let name = e.file_name().unwrap_or_default().to_string();
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
        let data = match self.inner.read_all(FPath::new(path)) {
            Ok(data) => data,
            Err(err) => {
                // `path` isn't a real, directly-readable file — it may be
                // nested inside a registered hook's virtual namespace.
                return match self.resolve_hook(path) {
                    Some((hook, real_file_path, tail, _peek)) => {
                        hook.read_virtual(&real_file_path, &tail)
                    }
                    None => Err(err),
                };
            }
        };
        // Try to decode as UTF-8; fall back to binary
        match String::from_utf8(data) {
            Ok(s) => Ok(BridgeValue::Text(Text::Owned(s))),
            Err(error) => Ok(BridgeValue::Binary(error.into_bytes())),
        }
    }

    fn metadata(
        &self,
        path: &str,
        _cancel: &CancellationToken,
    ) -> ForensicResult<BTreeMap<Text, BridgeValue>> {
        let meta = self.inner.metadata(FPath::new(path))?;
        let mut map = BTreeMap::new();
        map.insert(Text::Borrowed("size"), BridgeValue::U64(meta.len()));
        map.insert(
            Text::Borrowed("created"),
            meta.created_opt()
                .copied()
                .map(BridgeValue::Timestamp)
                .unwrap_or(BridgeValue::Null),
        );
        map.insert(
            Text::Borrowed("accessed"),
            meta.accessed_opt()
                .copied()
                .map(BridgeValue::Timestamp)
                .unwrap_or(BridgeValue::Null),
        );
        map.insert(
            Text::Borrowed("modified"),
            meta.modified_opt()
                .copied()
                .map(BridgeValue::Timestamp)
                .unwrap_or(BridgeValue::Null),
        );
        Ok(map)
    }

    fn actions(&self, path: &str, _cancel: &CancellationToken) -> ForensicResult<Vec<String>> {
        if let Ok(meta) = self.inner.metadata(FPath::new(path)) {
            if meta.is_file() {
                let peek = self.content_peek(path)?;
                return Ok(collect_hook_actions(&self.hooks, path, &peek));
            }
            // A real directory has no hook-matchable content of its own.
            return Ok(Vec::new());
        }
        // `path` doesn't resolve directly — it may be nested inside a
        // registered hook's virtual namespace.
        match self.resolve_hook(path) {
            Some((hook, real_file_path, tail, _peek)) => {
                Ok(hook.virtual_action_ids(&real_file_path, &tail))
            }
            None => Ok(Vec::new()),
        }
    }
}

// ============================================================================
// EventLogProvider
// ============================================================================

/// Forensic bridge provider wrapping an `EventLogReader`.
pub struct EventLogProvider {
    inner: Mutex<Box<dyn EventLogReader + Send>>,
    name: String,
    resource_descriptor: ResourceProviderDescriptor,
}

impl EventLogProvider {
    pub fn new(reader: Box<dyn EventLogReader + Send>) -> Self {
        Self {
            inner: Mutex::new(reader),
            name: "Events".to_string(),
            resource_descriptor: ResourceProviderDescriptor {
                id: "event-log".to_string(),
                title: "Events".to_string(),
                description: "Forensic event log resources".to_string(),
            },
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self.resource_descriptor.title = self.name.clone();
        self
    }

    /// Set a stable resource-provider ID for capability registry registration.
    pub fn with_resource_id(mut self, id: impl Into<String>) -> Self {
        self.resource_descriptor.id = id.into();
        self
    }
}

impl ResourceProvider for EventLogProvider {
    fn descriptor(&self) -> &ResourceProviderDescriptor {
        &self.resource_descriptor
    }

    fn children(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<Vec<ResourceEntry>> {
        ensure_resource_not_cancelled(cancellation)?;
        let (entries, _) = ForensicProvider::children(self, path, 0, u64::MAX, cancellation)
            .map_err(|_| event_log_capability_error())?;
        ensure_resource_not_cancelled(cancellation)?;
        Ok(entries
            .into_iter()
            .map(|entry| ResourceEntry {
                id: ResourceId::new(
                    self.resource_descriptor.id.clone(),
                    resource_child_path(path, entry.name.as_ref()),
                ),
                name: entry.name.into_owned(),
                kind: resource_kind(entry.node_type),
                description: entry.description.map(Text::into_owned),
            })
            .collect())
    }

    fn read(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<ResourceContent> {
        ensure_resource_not_cancelled(cancellation)?;
        let value = ForensicProvider::read(self, path, cancellation)
            .map_err(|_| event_log_capability_error())?;
        ensure_resource_not_cancelled(cancellation)?;
        Ok(ResourceContent::Structured {
            value: capability_value_from_bridge(value),
            media_type: Some("application/vnd.forensic-rs.event-record".to_string()),
        })
    }

    fn metadata(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<ResourceMetadata> {
        ensure_resource_not_cancelled(cancellation)?;
        let values = ForensicProvider::metadata(self, path, cancellation)
            .map_err(|_| event_log_capability_error())?
            .into_iter()
            .map(|(name, value)| (name, capability_value_from_bridge(value)))
            .collect();
        ensure_resource_not_cancelled(cancellation)?;
        Ok(ResourceMetadata {
            media_type: None,
            size: None,
            values,
        })
    }
}

fn event_log_capability_error() -> CapabilityError {
    CapabilityError::new(
        CapabilityErrorKind::Internal,
        "event log resource operation failed",
    )
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
                    map.insert(
                        Text::Borrowed("event_id"),
                        BridgeValue::U64(rec.event_id as u64),
                    );
                    map.insert(
                        Text::Borrowed("channel"),
                        BridgeValue::Text(Text::Owned(rec.channel)),
                    );
                    map.insert(
                        Text::Borrowed("provider"),
                        BridgeValue::Text(Text::Owned(rec.provider)),
                    );
                    map.insert(
                        Text::Borrowed("timestamp"),
                        BridgeValue::Timestamp(rec.timestamp),
                    );
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
        Err(ForensicError::missing_data(
            "EventLogProvider",
            format!("record not found: {}", path).into(),
        ))
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
    inner: Mutex<Box<dyn ForensicDb + Send>>,
    name: String,
    resource_descriptor: ResourceProviderDescriptor,
}

impl DatabaseProvider {
    pub fn new(db: Box<dyn ForensicDb + Send>) -> Self {
        Self {
            inner: Mutex::new(db),
            name: "Database".to_string(),
            resource_descriptor: ResourceProviderDescriptor {
                id: "database".to_string(),
                title: "Database".to_string(),
                description: "Forensic database resources".to_string(),
            },
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self.resource_descriptor.title = self.name.clone();
        self
    }

    /// Set a stable resource-provider ID for capability registry registration.
    pub fn with_resource_id(mut self, id: impl Into<String>) -> Self {
        self.resource_descriptor.id = id.into();
        self
    }
}

impl ResourceProvider for DatabaseProvider {
    fn descriptor(&self) -> &ResourceProviderDescriptor {
        &self.resource_descriptor
    }

    fn children(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<Vec<ResourceEntry>> {
        ensure_resource_not_cancelled(cancellation)?;
        let (entries, _) = ForensicProvider::children(self, path, 0, u64::MAX, cancellation)
            .map_err(|_| database_capability_error())?;
        ensure_resource_not_cancelled(cancellation)?;
        Ok(entries
            .into_iter()
            .map(|entry| ResourceEntry {
                id: ResourceId::new(
                    self.resource_descriptor.id.clone(),
                    resource_child_path(path, entry.name.as_ref()),
                ),
                name: entry.name.into_owned(),
                kind: resource_kind(entry.node_type),
                description: entry.description.map(Text::into_owned),
            })
            .collect())
    }

    fn read(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<ResourceContent> {
        ensure_resource_not_cancelled(cancellation)?;
        let value = ForensicProvider::read(self, path, cancellation)
            .map_err(|_| database_capability_error())?;
        ensure_resource_not_cancelled(cancellation)?;
        Ok(ResourceContent::Structured {
            value: capability_value_from_bridge(value),
            media_type: Some("application/vnd.forensic-rs.database-row".to_string()),
        })
    }

    fn metadata(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<ResourceMetadata> {
        ensure_resource_not_cancelled(cancellation)?;
        let values = ForensicProvider::metadata(self, path, cancellation)
            .map_err(|_| database_capability_error())?
            .into_iter()
            .map(|(name, value)| (name, capability_value_from_bridge(value)))
            .collect();
        ensure_resource_not_cancelled(cancellation)?;
        Ok(ResourceMetadata {
            media_type: None,
            size: None,
            values,
        })
    }
}

fn database_capability_error() -> CapabilityError {
    CapabilityError::new(
        CapabilityErrorKind::Internal,
        "database resource operation failed",
    )
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
        let database = self.inner.lock().map_err(|_| {
            ForensicError::other("DatabaseProvider", "database lock poisoned".to_string())
        })?;
        if path.is_empty() {
            // Root: list tables
            let tables = database.list_tables()?;
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
        let table = database.table(path)?;
        let mut rows_cursor = table.iter_rows()?;

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

        let database = self.inner.lock().map_err(|_| {
            ForensicError::other("DatabaseProvider", "database lock poisoned".to_string())
        })?;
        let table = database.table(table_name)?;
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
        Err(ForensicError::missing_data(
            "DatabaseProvider",
            format!("row {} not found in {}", target_row, table_name).into(),
        ))
    }

    fn metadata(
        &self,
        path: &str,
        _cancel: &CancellationToken,
    ) -> ForensicResult<BTreeMap<Text, BridgeValue>> {
        if path.is_empty() {
            return Ok(BTreeMap::new());
        }
        let database = self.inner.lock().map_err(|_| {
            ForensicError::other("DatabaseProvider", "database lock poisoned".to_string())
        })?;
        let table = database.table(path)?;
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

fn ensure_resource_not_cancelled(cancellation: &CancellationToken) -> CapabilityResult<()> {
    if cancellation.is_cancelled() {
        return Err(CapabilityError::new(
            CapabilityErrorKind::Cancelled,
            "operation cancelled",
        ));
    }
    Ok(())
}

fn resource_child_path(parent: &str, child: &str) -> String {
    if parent.is_empty()
        || child == parent
        || child.starts_with(&format!("{parent}/"))
        || child.starts_with(&format!("{parent}\\"))
    {
        return child.to_string();
    }
    let separator = if parent.contains('\\') { "\\" } else { "/" };
    format!("{parent}{separator}{child}")
}

fn resource_kind(node_type: NodeType) -> ResourceKind {
    match node_type {
        NodeType::Container => ResourceKind::Container,
        NodeType::Leaf => ResourceKind::Leaf,
        NodeType::Virtual => ResourceKind::Virtual,
    }
}

fn capability_value_from_bridge(value: BridgeValue) -> CapabilityValue {
    match value {
        BridgeValue::Null => CapabilityValue::Null,
        BridgeValue::Bool(value) => CapabilityValue::Bool(value),
        BridgeValue::I64(value) => CapabilityValue::I64(value),
        BridgeValue::U64(value) => CapabilityValue::U64(value),
        BridgeValue::F64(value) => CapabilityValue::F64(value),
        BridgeValue::Text(value) => CapabilityValue::Text(value),
        BridgeValue::Timestamp(value) => CapabilityValue::Timestamp(value),
        BridgeValue::Binary(value) => CapabilityValue::Bytes(value),
        BridgeValue::Array(values) => CapabilityValue::Array(
            values
                .into_iter()
                .map(capability_value_from_bridge)
                .collect(),
        ),
        BridgeValue::Map(values) => CapabilityValue::Object(
            values
                .into_iter()
                .map(|(name, value)| (name, capability_value_from_bridge(value)))
                .collect(),
        ),
    }
}

fn forensic_value_to_bridge(val: crate::traits::db::ForensicValue) -> BridgeValue {
    use crate::traits::db::ForensicValue as FV;
    match val {
        FV::Null => BridgeValue::Null,
        FV::Bool(v) => BridgeValue::Bool(v),
        FV::I64(v) => BridgeValue::I64(v),
        FV::U64(v) => BridgeValue::U64(v),
        FV::F64(v) => BridgeValue::F64(v),
        FV::DateTime(ft) => BridgeValue::Timestamp(ft),
        FV::Guid(v) => {
            let s = format!(
                "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                u32::from_le_bytes([v[0], v[1], v[2], v[3]]),
                u16::from_le_bytes([v[4], v[5]]),
                u16::from_le_bytes([v[6], v[7]]),
                v[8],
                v[9],
                v[10],
                v[11],
                v[12],
                v[13],
                v[14],
                v[15]
            );
            BridgeValue::Text(Text::Owned(s))
        }
        FV::Text(s) => BridgeValue::Text(Text::Owned(s)),
        FV::Binary(v) => BridgeValue::Binary(v),
    }
}

#[cfg(test)]
mod registry_tests {
    use super::*;
    use crate::core::fs::StdVirtualFS;
    use crate::traits::db::{
        ForensicColumnDef, ForensicColumnType, ForensicRows, ForensicTable, ForensicValueRef,
    };
    use crate::utils::testing::{basic_event_log, TestingProviderHook, TestingRegistry};
    use std::io::Write;
    use std::sync::Arc;

    const ENVIRONMENT_PATH: &str =
        r"HKEY_USERS\S-1-5-21-1366093794-4292800403-1155380978-513\Volatile Environment";

    #[test]
    fn registry_provider_releases_handles_after_success_and_error() {
        let registry = TestingRegistry::new();
        let cached = Arc::clone(&registry.cached);
        let provider = RegistryProvider::new(Arc::new(registry));
        let cancel = CancellationToken::new();

        let value = ForensicProvider::read(
            &provider,
            &format!(r"{}\USERPROFILE", ENVIRONMENT_PATH),
            &cancel,
        )
        .expect("Reading an existing registry value must succeed");
        assert!(matches!(value, BridgeValue::Text(_)));
        assert!(cached.lock().unwrap().is_empty());

        let err = ForensicProvider::read(
            &provider,
            &format!(r"{}\MissingValue", ENVIRONMENT_PATH),
            &cancel,
        )
        .expect_err("Reading a missing registry value must fail");
        assert!(format!("{}", err).contains("MissingValue"));
        assert!(cached.lock().unwrap().is_empty());
    }

    #[test]
    fn registry_provider_releases_handles_after_child_enumeration() {
        let registry = TestingRegistry::new();
        let cached = Arc::clone(&registry.cached);
        let provider = RegistryProvider::new(Arc::new(registry));
        let cancel = CancellationToken::new();

        let (entries, _) = ForensicProvider::children(&provider, ENVIRONMENT_PATH, 0, 100, &cancel)
            .expect("Enumerating an existing registry key must succeed");

        assert!(!entries.is_empty());
        assert!(cached.lock().unwrap().is_empty());
    }

    #[test]
    fn registry_provider_threads_nested_virtual_path_to_hook() {
        // Regression test: the nested branch of RegistryProvider::children used
        // to discard the requested sub-path and always behave like the hook's
        // root — proving the fix threads `virtual_child` through as `virtual_path`.
        let mut provider = RegistryProvider::new(Arc::new(TestingRegistry::new()));
        let hook = TestingProviderHook::new("testhook")
            .with_child(
                "",
                NodeEntry {
                    name: Text::Borrowed("Applications"),
                    node_type: NodeType::Container,
                    description: None,
                },
            )
            .with_child(
                "Applications",
                NodeEntry {
                    name: Text::Borrowed("Sub"),
                    node_type: NodeType::Leaf,
                    description: None,
                },
            );
        provider.add_hook(Box::new(hook));
        let cancel = CancellationToken::new();

        let value_path = format!(r"{}\USERPROFILE", ENVIRONMENT_PATH);
        let root_virtual_path = format!(r"{}\[testhook]", value_path);
        let (root_children, root_total) =
            ForensicProvider::children(&provider, &root_virtual_path, 0, 100, &cancel).unwrap();
        assert_eq!(root_total, 1);
        assert_eq!(root_children[0].name.as_ref(), "Applications");

        let nested_virtual_path = format!(r"{}\Applications", root_virtual_path);
        let (nested_children, nested_total) =
            ForensicProvider::children(&provider, &nested_virtual_path, 0, 100, &cancel).unwrap();
        assert_eq!(nested_total, 1);
        assert_eq!(nested_children[0].name.as_ref(), "Sub");
    }

    #[test]
    fn registry_provider_actions_cover_real_and_virtual_nodes() {
        let mut provider = RegistryProvider::new(Arc::new(TestingRegistry::new()));
        let hook = TestingProviderHook::new("testhook")
            .with_action("registry.explain")
            .with_virtual_action("Applications", "registry.explain_child");
        provider.add_hook(Box::new(hook));
        let cancel = CancellationToken::new();

        let value_path = format!(r"{}\USERPROFILE", ENVIRONMENT_PATH);
        assert_eq!(
            ForensicProvider::actions(&provider, &value_path, &cancel).unwrap(),
            vec!["registry.explain".to_string()]
        );

        let nested_virtual_path = format!(r"{}\[testhook]\Applications", value_path);
        assert_eq!(
            ForensicProvider::actions(&provider, &nested_virtual_path, &cancel).unwrap(),
            vec!["registry.explain_child".to_string()]
        );
    }

    #[test]
    fn registry_provider_exposes_native_resource_values_and_metadata() {
        let provider = RegistryProvider::new(Arc::new(TestingRegistry::new()))
            .with_resource_id("case-registry");
        let cancellation = CancellationToken::new();

        let entries = ResourceProvider::children(&provider, ENVIRONMENT_PATH, &cancellation)
            .expect("Registry key children must be available as resources");
        assert!(!entries.is_empty());
        assert!(entries
            .iter()
            .all(|entry| entry.id.provider == "case-registry"));

        let content = ResourceProvider::read(
            &provider,
            &format!(r"{}\USERPROFILE", ENVIRONMENT_PATH),
            &cancellation,
        )
        .expect("Registry value must be available as structured resource content");
        assert!(matches!(
            content,
            ResourceContent::Structured {
                value: CapabilityValue::Text(_),
                media_type: Some(_),
            }
        ));

        let metadata = ResourceProvider::metadata(&provider, ENVIRONMENT_PATH, &cancellation)
            .expect("Registry key metadata must be available as a resource");
        assert!(metadata.values.contains_key("subkeys"));
        assert!(metadata.values.contains_key("values"));
    }

    #[test]
    fn event_log_provider_exposes_native_resource_records_and_metadata() {
        let provider =
            EventLogProvider::new(Box::new(basic_event_log())).with_resource_id("case-events");
        let cancellation = CancellationToken::new();

        let channels = ResourceProvider::children(&provider, "", &cancellation)
            .expect("Event log channels must be available as resources");
        assert!(channels.iter().any(|entry| {
            entry.id.provider == "case-events"
                && entry.id.path == "Security"
                && entry.kind == ResourceKind::Container
        }));

        let records = ResourceProvider::children(&provider, "Security", &cancellation)
            .expect("Security records must be available as resources");
        assert!(records
            .iter()
            .any(|entry| entry.id.path == "Security/1001:4624"));

        let content = ResourceProvider::read(&provider, "Security/1001:4624", &cancellation)
            .expect("Event record must be available as structured resource content");
        assert!(matches!(
            content,
            ResourceContent::Structured {
                value: CapabilityValue::Object(_),
                media_type: Some(_),
            }
        ));

        let metadata = ResourceProvider::metadata(&provider, "Security", &cancellation)
            .expect("Channel metadata must be available as a resource");
        assert_eq!(
            metadata.values.get("event_count"),
            Some(&CapabilityValue::U64(3))
        );
    }

    struct TestDatabase;

    impl ForensicDb for TestDatabase {
        fn list_tables(&self) -> ForensicResult<Vec<String>> {
            Ok(vec!["users".to_string()])
        }

        fn table(&self, name: &str) -> ForensicResult<Box<dyn ForensicTable + '_>> {
            if name == "users" {
                Ok(Box::new(TestTable {
                    columns: vec![ForensicColumnDef {
                        name: "name".to_string(),
                        col_type: ForensicColumnType::Text,
                        nullable: false,
                    }],
                }))
            } else {
                Err(ForensicError::missing_data(
                    "TestDatabase",
                    compact_str::CompactString::const_new("missing table"),
                ))
            }
        }
    }

    struct TestTable {
        columns: Vec<ForensicColumnDef>,
    }

    impl ForensicTable for TestTable {
        fn name(&self) -> &str {
            "users"
        }

        fn columns(&self) -> &[ForensicColumnDef] {
            &self.columns
        }

        fn iter_rows(&self) -> ForensicResult<Box<dyn ForensicRows + '_>> {
            Ok(Box::new(TestRows { current: false }))
        }

        fn row_count(&self) -> Option<u64> {
            Some(1)
        }
    }

    struct TestRows {
        current: bool,
    }

    impl ForensicRows for TestRows {
        fn column_count(&self) -> usize {
            1
        }

        fn column_name(&self, index: usize) -> Option<&str> {
            (index == 0).then_some("name")
        }

        fn column_names(&self) -> Vec<&str> {
            vec!["name"]
        }

        fn column_type(&self, _index: usize) -> ForensicColumnType {
            ForensicColumnType::Text
        }

        fn next(&mut self) -> ForensicResult<bool> {
            if self.current {
                Ok(false)
            } else {
                self.current = true;
                Ok(true)
            }
        }

        fn read_ref(&self, index: usize) -> ForensicResult<ForensicValueRef<'_>> {
            if self.current && index == 0 {
                Ok(ForensicValueRef::Text(std::borrow::Cow::Borrowed("Ada")))
            } else {
                Err(ForensicError::no_more_data())
            }
        }
    }

    #[test]
    fn database_provider_exposes_native_resource_rows_and_metadata() {
        let provider = DatabaseProvider::new(Box::new(TestDatabase)).with_resource_id("case-db");
        let cancellation = CancellationToken::new();

        let tables = ResourceProvider::children(&provider, "", &cancellation)
            .expect("Database tables must be available as resources");
        assert_eq!(tables[0].id.provider, "case-db");
        assert_eq!(tables[0].id.path, "users");
        assert_eq!(tables[0].kind, ResourceKind::Container);

        let rows = ResourceProvider::children(&provider, "users", &cancellation)
            .expect("Database rows must be available as resources");
        assert_eq!(rows[0].id.path, "users/0");

        let content = ResourceProvider::read(&provider, "users/0", &cancellation)
            .expect("Database row must be available as structured resource content");
        assert!(matches!(
            content,
            ResourceContent::Structured {
                value: CapabilityValue::Object(_),
                media_type: Some(_),
            }
        ));

        let metadata = ResourceProvider::metadata(&provider, "users", &cancellation)
            .expect("Table metadata must be available as a resource");
        assert_eq!(
            metadata.values.get("row_count"),
            Some(&CapabilityValue::U64(1))
        );
    }

    #[test]
    fn vfs_provider_exposes_resource_content_and_metadata() {
        let directory =
            std::env::temp_dir().join(format!("forensic_rs_vfs_resource_{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let file_path = directory.join("evidence.txt");
        let mut file = std::fs::File::create(&file_path).unwrap();
        file.write_all(b"forensic evidence").unwrap();
        drop(file);

        let provider =
            VfsProvider::new(Arc::new(StdVirtualFS::new())).with_resource_id("evidence-files");
        let cancellation = CancellationToken::new();
        let directory_path = directory.to_string_lossy();
        let entries =
            ResourceProvider::children(&provider, &directory_path, &cancellation).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id.provider, "evidence-files");
        assert_eq!(entries[0].name, "evidence.txt");
        assert_eq!(entries[0].kind, ResourceKind::Leaf);

        let file_path = file_path.to_string_lossy();
        let content = ResourceProvider::read(&provider, &file_path, &cancellation).unwrap();
        assert_eq!(
            content,
            ResourceContent::Text {
                text: "forensic evidence".to_string(),
                media_type: Some("text/plain".to_string()),
            }
        );
        let metadata = ResourceProvider::metadata(&provider, &file_path, &cancellation).unwrap();
        assert_eq!(metadata.size, Some(17));

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn vfs_provider_dispatches_hooks_for_recognized_file_content() {
        let directory =
            std::env::temp_dir().join(format!("forensic_rs_vfs_hook_{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let matching_file = directory.join("bundle.plist");
        std::fs::write(&matching_file, b"bplist00-fake-content").unwrap();
        std::fs::write(directory.join("plain.txt"), b"just text").unwrap();

        let matching_path = matching_file.to_string_lossy().to_string();
        let hook = TestingProviderHook::new("plist")
            .matching_path({
                let matching_path = matching_path.clone();
                move |p| p == matching_path
            })
            .matching_value(|_, value| {
                matches!(value, BridgeValue::Binary(bytes) if bytes.starts_with(b"bplist00"))
            })
            .with_child(
                "",
                NodeEntry {
                    name: Text::Borrowed("Applications"),
                    node_type: NodeType::Container,
                    description: None,
                },
            )
            .with_child(
                "Applications",
                NodeEntry {
                    name: Text::Borrowed("Sub"),
                    node_type: NodeType::Leaf,
                    description: None,
                },
            );

        let mut provider = VfsProvider::new(Arc::new(StdVirtualFS::new()));
        provider.add_hook(Box::new(hook));
        let cancel = CancellationToken::new();

        // A non-matching file lists as a normal Leaf with no virtual children.
        let (entries, total) = ForensicProvider::children(
            &provider,
            &directory.to_string_lossy(),
            0,
            100,
            &cancel,
        )
        .unwrap();
        assert_eq!(total, 2);
        let plain_entry = entries
            .iter()
            .find(|e| e.name.as_ref() == "plain.txt")
            .expect("plain.txt must be listed");
        assert_eq!(plain_entry.node_type, NodeType::Leaf);

        // The matching file's own path returns the hook's root virtual children...
        let (root_children, root_total) =
            ForensicProvider::children(&provider, &matching_path, 0, 100, &cancel).unwrap();
        assert_eq!(root_total, 1);
        assert_eq!(root_children[0].name.as_ref(), "Applications");

        // ...while read() on that same path still returns the raw file content
        // (the fixture is valid UTF-8, so it decodes as Text — the point is
        // that it's the real file's bytes, not something the hook produced).
        let raw = ForensicProvider::read(&provider, &matching_path, &cancel).unwrap();
        assert!(matches!(raw, BridgeValue::Text(text) if text.as_ref() == "bplist00-fake-content"));

        // A path nested one level into the hook's namespace reaches the hook's
        // nested branch (the regression this proves: virtual_path threaded
        // through, not silently treated as the root every time).
        let nested_path = std::path::Path::new(&matching_path)
            .join("Applications")
            .to_string_lossy()
            .to_string();
        let (nested_children, nested_total) =
            ForensicProvider::children(&provider, &nested_path, 0, 100, &cancel).unwrap();
        assert_eq!(nested_total, 1);
        assert_eq!(nested_children[0].name.as_ref(), "Sub");

        std::fs::remove_dir_all(directory).unwrap();
    }
}
