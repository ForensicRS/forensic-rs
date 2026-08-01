# Tutorial: Exposing Resources

This chapter covers exposing forensic data as `ResourceProvider` endpoints, allowing AI clients to browse and read evidence directly.

## What Are Resources?

While `ForensicTool` exposes **actions** (operations that analyze data), `ResourceProvider` exposes **data** (browsable trees of evidence). Resources let AI clients:

- List available data sources
- Navigate hierarchical data (registry keys, filesystem directories)
- Read specific values or files
- Get metadata about resources

## ResourceProvider Trait

```rust
pub trait ResourceProvider: Send + Sync {
    fn descriptor(&self) -> &ResourceProviderDescriptor;
    fn children(&self, path: &str, cancellation: &CancellationToken) -> CapabilityResult<Vec<ResourceEntry>>;
    fn read(&self, path: &str, cancellation: &CancellationToken) -> CapabilityResult<ResourceContent>;
    fn metadata(&self, path: &str, cancellation: &CancellationToken) -> CapabilityResult<ResourceMetadata>;
}

pub struct ResourceProviderDescriptor {
    pub id: String,
    pub name: String,
    pub description: String,
}

pub enum ResourceKind {
    Directory,
    File,
    RegistryKey,
    RegistryValue,
    EventChannel,
    EventRecord,
    Database,
    Table,
    Row,
}
```

## Built-in Resource Providers

ForensicRS includes providers for all major artifact domains:

| Provider | Data | Example Paths |
|----------|------|---------------|
| `RegistryProvider` | Registry hives, keys, values | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| `VfsProvider` | Files and directories | `C:\Windows\System32` |
| `EventLogProvider` | Event channels and records | `Security\1234` |
| `DatabaseProvider` | Database tables and rows | `History\urls` |

## Registering Resource Providers

```rust
use forensic_rs::bridge::providers::{RegistryProvider, VfsProvider};

let registry = RegistryProvider::new(my_registry_reader);
let vfs = VfsProvider::new(my_vfs);

let mut registry = CapabilityRegistry::new(policy);
registry.register_resource_provider(Arc::new(registry))?;
registry.register_resource_provider(Arc::new(vfs))?;
```

## Implementing a Custom Resource Provider

Here's how to implement `VfsProvider` for exposing filesystem access:

```rust
// src/resources/vfs_provider.rs

use std::path::Path;
use forensic_rs::prelude::*;
use forensic_rs::bridge::providers::VfsProvider;

pub struct MyVfsProvider {
    inner: VfsProvider,
}

impl MyVfsProvider {
    pub fn new(vfs: Box<dyn VirtualFileSystem>) -> Self {
        Self {
            inner: VfsProvider::new(vfs)
        }
    }
}

impl ResourceProvider for MyVfsProvider {
    fn descriptor(&self) -> &ResourceProviderDescriptor {
        self.inner.descriptor()
    }

    fn children(&self, path: &str, cancellation: &CancellationToken) -> CapabilityResult<Vec<ResourceEntry>> {
        self.inner.children(path, cancellation)
    }

    fn read(&self, path: &str, cancellation: &CancellationToken) -> CapabilityResult<ResourceContent> {
        self.inner.read(path, cancellation)
    }

    fn metadata(&self, path: &str, cancellation: &CancellationToken) -> CapabilityResult<ResourceMetadata> {
        self.inner.metadata(path, cancellation)
    }
}
```

## URI Encoding for Resources

Resource paths use percent-encoding for special characters:

| Character | Encoded | Example |
|-----------|---------|---------|
| Space | `%20` | `C:\Program Files` → `C:%5CProgram%20Files` |
| Backslash | `%5C` | `HKLM\SOFTWARE` → `HKLM%5CSOFTWARE` |
| Colon | `%3A` | `C:` → `C%3A` |

```rust
fn encode_path(path: &str) -> String {
    path.replace('\\', "%5C")
        .replace(':', "%3A")
        .replace(' ', "%20")
}

fn decode_path(encoded: &str) -> String {
    encoded.replace("%5C", "\\")
           .replace("%3A", ":")
           .replace("%20", " ")
}
```

## MCP Resource Protocol Mapping

| ResourceProvider Method | MCP Method |
|--------------------------|------------|
| `descriptor()` | `resources/list` (provider list) |
| `children()` | `resources/list` (with parent template) |
| `read()` | `resources/read` |
| `metadata()` | Included in `resources/read` response |

## Complete Example: Exposing Registry Resources

```rust
// src/resources/registry_resources.rs

use std::sync::Arc;
use forensic_rs::prelude::*;
use forensic_rs::bridge::providers::RegistryProvider;

/// Sets up registry resources for a forensic case
fn setup_registry_resources(
    registry: Box<dyn RegistryReader>,
) -> CapabilityRegistry {
    // Create registry provider
    let reg_provider = RegistryProvider::new(registry);

    // Create policy (allow all for this example)
    let policy = Arc::new(AllowAllPolicy::new());

    // Create and populate registry
    let mut cap_registry = CapabilityRegistry::new(policy);
    cap_registry
        .register_resource_provider(Arc::new(reg_provider))
        .unwrap();

    cap_registry
}

/// Example: Browse registry at a path
fn browse_registry(
    provider: &dyn ResourceProvider,
    path: &str,
) -> CapabilityResult<Vec<ResourceEntry>> {
    let cancellation = CancellationToken::new();
    provider.children(path, &cancellation)
}

/// Example: Read a specific registry value
fn read_registry_value(
    provider: &dyn ResourceProvider,
    path: &str,
) -> CapabilityResult<ResourceContent> {
    let cancellation = CancellationToken::new();
    provider.read(path, &cancellation)
}
```

## Resource Response Format

When an AI client reads a resource, the content is returned as:

```rust
pub struct ResourceContent {
    pub mime_type: String,           // e.g., "application/octet-stream"
    pub content: ResourceContentData,
}

pub enum ResourceContentData {
    Text(String),
    Binary(Vec<u8>),
    Structured(CapabilityValue),
}
```

## Next Steps

- [Access Control](./07_access_control.md) - Implement authentication and authorization for resources
- See [examples/mcp_stdio_server.rs:304-315](../../examples/mcp_stdio_server.rs) for resource reference handling
