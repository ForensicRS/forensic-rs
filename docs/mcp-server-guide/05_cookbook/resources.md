# Cookbook: Resource Provider Recipes

This cookbook provides reusable code patterns for implementing `ResourceProvider`.

## Recipe 1: Exposing File System Resources

Wrap `FileSystem` as an MCP resource provider.

```rust
use std::sync::Arc;
use forensic_rs::prelude::*;
use forensic_rs::bridge::providers::VfsProvider;

pub struct FileSystemResourceProvider {
    vfs: Arc<dyn FileSystem>,
    root_path: String,
}

impl FileSystemResourceProvider {
    pub fn new(vfs: Arc<dyn FileSystem>, root_path: &str) -> Self {
        Self {
            vfs,
            root_path: root_path.to_string(),
        }
    }
}

impl ResourceProvider for FileSystemResourceProvider {
    fn descriptor(&self) -> &ResourceProviderDescriptor {
        &ResourceProviderDescriptor {
            id: "filesystem".into(),
            name: "File System".into(),
            description: "Browse filesystem paths in the evidence.".into(),
        }
    }

    fn children(&self, path: &str, cancellation: &CancellationToken) -> CapabilityResult<Vec<ResourceEntry>> {
        let full_path = FPath::new(&self.root_path).join(path);
        // `read_dir` now returns a lazy iterator of `ForensicResult<DirEntry>`
        // (not an already-collected `Vec<VDirEntry>`), so each item is
        // fallible and `DirEntry` carries a full `path`/`file_type` rather
        // than the old `name()`/`is_directory()` accessors.
        let entries = self.vfs.read_dir(&full_path)?;

        entries.map(|entry| {
            let entry = entry?;
            let name = entry.file_name().unwrap_or_default().to_string();
            let child_path = format!("{}/{}", path.trim_end_matches('/'), name);
            let is_dir = entry.file_type == VFileType::Directory;

            Ok(ResourceEntry {
                name: name.clone(),
                path: child_path,
                kind: if is_dir { ResourceKind::Directory } else { ResourceKind::File },
            })
        }).collect()
    }

    fn read(&self, path: &str, cancellation: &CancellationToken) -> CapabilityResult<ResourceContent> {
        let full_path = FPath::new(&self.root_path).join(path);

        if self.vfs.exists(&full_path) {
            let metadata = self.vfs.metadata(&full_path)?;
            let content = self.vfs.read_all(&full_path)?;

            Ok(ResourceContent {
                mime_type: guess_mime_type(&path),
                content: ResourceContentData::Binary(content),
            })
        } else {
            Err(CapabilityError::new(
                CapabilityErrorKind::NotFound,
                format!("File not found: {}", path)
            ))
        }
    }

    fn metadata(&self, path: &str, cancellation: &CancellationToken) -> CapabilityResult<ResourceMetadata> {
        let full_path = FPath::new(&self.root_path).join(path);
        let metadata = self.vfs.metadata(&full_path)?;

        Ok(ResourceMetadata {
            size: metadata.len(),
            created: metadata.created_opt(),
            modified: metadata.modified_opt(),
            accessed: metadata.accessed_opt(),
        })
    }
}

fn guess_mime_type(path: &str) -> String {
    if path.ends_with(".txt") { "text/plain".into() }
    else if path.ends_with(".json") { "application/json".into() }
    else if path.ends_with(".xml") { "application/xml".into() }
    else if path.ends_with(".evtx") { "application/xml".into() }
    else { "application/octet-stream".into() }
}
```

## Recipe 2: Exposing Registry Resources

Wrap `Registry` as a resource provider.

```rust
use std::sync::Arc;
use forensic_rs::prelude::*;
use forensic_rs::bridge::providers::RegistryProvider;

pub struct RegistryResourceProvider {
    registry: Arc<dyn Registry>,
}

impl RegistryResourceProvider {
    pub fn new(registry: Arc<dyn Registry>) -> Self {
        Self { registry }
    }
}

impl ResourceProvider for RegistryResourceProvider {
    fn descriptor(&self) -> &ResourceProviderDescriptor {
        &ResourceProviderDescriptor {
            id: "registry".into(),
            name: "Windows Registry".into(),
            description: "Browse registry hives, keys, and values.".into(),
        }
    }

    fn children(&self, path: &str, _cancellation: &CancellationToken) -> CapabilityResult<Vec<ResourceEntry>> {
        // `path` is a single hive-prefixed string, e.g. "HKLM\SOFTWARE\Microsoft".
        // `RegistryExt::key` parses the hive designator (short `HKLM` or long
        // `HKEY_LOCAL_MACHINE` form, case-insensitively) itself, so there's no
        // separate hive argument — or manual hive-name matching — to build here.
        let key = self.registry.key(path)?;
        let mut entries = Vec::new();

        // Enumerate subkeys
        for entry in key.keys()? {
            entries.push(ResourceEntry {
                name: entry.name.clone(),
                path: format!("{}\\{}", path, entry.name),
                kind: ResourceKind::RegistryKey,
            });
        }

        // Enumerate values
        for (name, _value) in key.values()? {
            entries.push(ResourceEntry {
                name: name.clone(),
                path: format!("{}\\{}", path, name),
                kind: ResourceKind::RegistryValue,
            });
        }

        Ok(entries)
    }

    fn read(&self, path: &str, _cancellation: &CancellationToken) -> CapabilityResult<ResourceContent> {
        // If path ends with \, it's a key, otherwise the final segment is a value name
        let (key_path, value_name) = if path.ends_with('\\') {
            (path.trim_end_matches('\\'), None)
        } else {
            match path.rfind('\\') {
                Some(pos) => (&path[..pos], Some(&path[pos + 1..])),
                None => (path, None),
            }
        };

        if let Some(name) = value_name {
            let reg_value = self.registry.value(key_path, name)?;
            let (content, mime_type) = convert_registry_value(&reg_value);
            Ok(ResourceContent { mime_type, content })
        } else {
            Err(CapabilityError::new(
                CapabilityErrorKind::NotFound,
                "Key read not supported, use children to list"
            ))
        }
    }

    fn metadata(&self, path: &str, _cancellation: &CancellationToken) -> CapabilityResult<ResourceMetadata> {
        let key = self.registry.key(path)?;
        let info = key.info()?;

        Ok(ResourceMetadata {
            size: 0,
            created: None,
            modified: info.last_write_time,
            accessed: None,
        })
    }
}
```

## Recipe 3: Exposing Event Log Resources

Expose event channels and records as resources.

```rust
use forensic_rs::prelude::*;

pub struct EventLogResourceProvider {
    reader: Box<dyn EventLogReader>,
}

impl EventLogResourceProvider {
    pub fn new(reader: Box<dyn EventLogReader>) -> Self {
        Self { reader }
    }
}

impl ResourceProvider for EventLogResourceProvider {
    fn descriptor(&self) -> &ResourceProviderDescriptor {
        &ResourceProviderDescriptor {
            id: "eventlog".into(),
            name: "Windows Event Logs".into(),
            description: "Browse Windows event log channels and records.".into(),
        }
    }

    fn children(&self, path: &str, _cancellation: &CancellationToken) -> CapabilityResult<Vec<ResourceEntry>> {
        if path.is_empty() || path == "/" {
            // Root: list channels
            let channels = self.reader.channels()?;
            return channels.into_iter().map(|ch| {
                Ok(ResourceEntry {
                    name: ch.clone(),
                    path: ch,
                    kind: ResourceKind::EventChannel,
                })
            }).collect();
        }

        // Path is a channel name, list recent records
        let count = self.reader.event_count(path)?;
        let mut entries = Vec::new();

        // Limit to last 100 records
        let limit = count.saturating_sub(100).max(0);
        let query = EventLogQuery::new()
            .with_channels(&[path])
            .with_start_index(limit as u64);

        let mut iter = self.reader.query(&query)?;
        let mut index = limit;

        while let Some(_record) = iter.next()? {
            entries.push(ResourceEntry {
                name: format!("{:?}", index),
                path: format!("{}\\{}", path, index),
                kind: ResourceKind::EventRecord,
            });
            index += 1;
            if entries.len() >= 100 {
                break;
            }
        }

        Ok(entries)
    }

    fn read(&self, path: &str, _cancellation: &CancellationToken) -> CapabilityResult<ResourceContent> {
        // Path format: "ChannelName\\record_index"
        let parts: Vec<&str> = path.splitn(2, '\\').collect();
        if parts.len() != 2 {
            return Err(CapabilityError::new(
                CapabilityErrorKind::InvalidInput,
                "Invalid event path"
            ));
        }

        let channel = parts[0];
        let _index: u64 = parts[1].parse().map_err(|_|
            CapabilityError::new(CapabilityErrorKind::InvalidInput, "Invalid index")
        )?;

        let query = EventLogQuery::new()
            .with_channels(&[channel]);

        let mut iter = self.reader.query(&query)?;
        let mut record_index = 0u64;

        while let Some(record) = iter.next()? {
            if record_index.to_string() == parts[1] {
                // Found the record, return as XML
                let xml = format_event_record_xml(&record);
                return Ok(ResourceContent {
                    mime_type: "application/xml".into(),
                    content: ResourceContentData::Text(xml),
                });
            }
            record_index += 1;
        }

        Err(CapabilityError::new(
            CapabilityErrorKind::NotFound,
            "Record not found"
        ))
    }

    fn metadata(&self, path: &str, _cancellation: &CancellationToken) -> CapabilityResult<ResourceMetadata> {
        let count = if path.contains('\\') {
            let channel = path.splitn(2, '\\').next().unwrap();
            self.reader.event_count(channel)?
        } else {
            self.reader.event_count(path)?
        };

        Ok(ResourceMetadata {
            size: count,
            created: None,
            modified: None,
            accessed: None,
        })
    }
}
```

## Recipe 4: Custom Resource Provider with Pagination

Implement pagination for large result sets.

```rust
use forensic_rs::prelude::*;

pub struct PaginatedResourceProvider {
    // ... internal state
}

impl ResourceProvider for PaginatedResourceProvider {
    fn children(&self, path: &str, cancellation: &CancellationToken) -> CapabilityResult<Vec<ResourceEntry>> {
        // Get pagination parameters from path
        // Path format: "collection?offset=0&limit=50"
        let (base_path, offset, limit) = parse_paginated_path(path);

        let all_entries = self.fetch_entries(&base_path)?;
        let total = all_entries.len();

        let page_entries: Vec<_> = all_entries
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|e| {
                // Adjust paths to include pagination info
                ResourceEntry {
                    name: e.name,
                    path: format!("{}?offset={}&limit={}", base_path, offset, limit),
                    kind: e.kind,
                }
            })
            .collect();

        // Store total in context for pagination metadata
        Ok(page_entries)
    }
}

fn parse_paginated_path(path: &str) -> (String, usize, usize) {
    if let Some(q_pos) = path.find('?') {
        let base = path[..q_pos].to_string();
        let params = &path[q_pos + 1..];

        let mut offset = 0;
        let mut limit = 50;

        for param in params.split('&') {
            let mut parts = param.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some("offset"), Some(v)) => offset = v.parse().unwrap_or(0),
                (Some("limit"), Some(v)) => limit = v.parse().unwrap_or(50),
                _ => {}
            }
        }

        (base, offset, limit)
    } else {
        (path.to_string(), 0, 50)
    }
}
```

## Recipe 5: Read-Only Resource Filter

Wrap a provider to enforce read-only access.

```rust
use forensic_rs::prelude::*;

pub struct ReadOnlyResourceProvider<P: ResourceProvider> {
    inner: P,
}

impl<P: ResourceProvider> ReadOnlyResourceProvider<P> {
    pub fn new(inner: P) -> Self {
        Self { inner }
    }
}

impl<P: ResourceProvider> ResourceProvider for ReadOnlyResourceProvider<P> {
    fn descriptor(&self) -> &ResourceProviderDescriptor {
        let inner = self.inner.descriptor();
        &ResourceProviderDescriptor {
            id: inner.id.clone(),
            name: inner.name.clone(),
            description: format!("{} (read-only)", inner.description),
        }
    }

    fn children(&self, path: &str, cancellation: &CancellationToken) -> CapabilityResult<Vec<ResourceEntry>> {
        // Filter out writeable entries
        let entries = self.inner.children(path, cancellation)?;
        Ok(entries.into_iter().filter(|e| {
            matches!(e.kind, ResourceKind::Directory | ResourceKind::File |
                          ResourceKind::RegistryKey | ResourceKind::RegistryValue |
                          ResourceKind::EventChannel | ResourceKind::EventRecord)
        }).collect())
    }

    fn read(&self, path: &str, cancellation: &CancellationToken) -> CapabilityResult<ResourceContent> {
        self.inner.read(path, cancellation)
    }

    fn metadata(&self, path: &str, cancellation: &CancellationToken) -> CapabilityResult<ResourceMetadata> {
        self.inner.metadata(path, cancellation)
    }
}
```

## Summary: Resource Provider Patterns

| Pattern | Use Case |
|---------|----------|
| VFS wrapper | Exposing filesystem evidence |
| Registry wrapper | Exposing registry hives |
| EventLog wrapper | Exposing event channels |
| Pagination | Large collections |
| Read-only filter | Enforcing access restrictions |
