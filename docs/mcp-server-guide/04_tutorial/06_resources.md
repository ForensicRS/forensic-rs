# Tutorial: Exposing Resources

This chapter covers exposing forensic data as `ResourceProvider` endpoints, allowing AI clients to browse and read evidence directly.

## What Are Resources?

While `ForensicTool` exposes **actions** (operations that analyze data), `ResourceProvider` exposes **data** (browsable trees of evidence). Resources let AI clients:

- List available data sources
- Navigate hierarchical data (registry keys, filesystem directories)
- Read specific values or files
- Get metadata about resources
- Discover which already-registered tools apply to a specific node (see
  [Node Actions](#node-actions-linking-resources-to-tools) below) — the one place
  where the resources/tools split above isn't absolute: a resource node can point
  back at the tools that make sense to run against it.

## ResourceProvider Trait

```rust
pub trait ResourceProvider: Send + Sync {
    fn descriptor(&self) -> &ResourceProviderDescriptor;
    fn children(&self, path: &str, cancellation: &CancellationToken) -> CapabilityResult<Vec<ResourceEntry>>;
    fn read(&self, path: &str, cancellation: &CancellationToken) -> CapabilityResult<ResourceContent>;
    fn metadata(&self, path: &str, cancellation: &CancellationToken) -> CapabilityResult<ResourceMetadata>;

    // Default: no actions. See "Node Actions" below.
    fn actions(&self, path: &str, cancellation: &CancellationToken) -> CapabilityResult<Vec<String>> { Ok(Vec::new()) }
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
use std::sync::Arc;
use forensic_rs::bridge::providers::{RegistryProvider, VfsProvider};

// `my_registry: Arc<dyn Registry>` and `my_vfs: Arc<dyn FileSystem>` - the
// same shared handles you would hand to `TriageSources::new`.
let registry_provider = RegistryProvider::new(Arc::clone(&my_registry));
let vfs_provider = VfsProvider::new(Arc::clone(&my_vfs));

let mut cap_registry = CapabilityRegistry::new(policy);
cap_registry.register_resource_provider(Arc::new(registry_provider))?;
cap_registry.register_resource_provider(Arc::new(vfs_provider))?;
```

## Implementing a Custom Resource Provider

Here's how to implement `VfsProvider` for exposing filesystem access:

```rust
// src/resources/vfs_provider.rs

use std::sync::Arc;
use forensic_rs::prelude::*;
use forensic_rs::bridge::providers::VfsProvider;

pub struct MyVfsProvider {
    inner: VfsProvider,
}

impl MyVfsProvider {
    pub fn new(vfs: Arc<dyn FileSystem>) -> Self {
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
    registry: Arc<dyn Registry>,
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

## Node Actions: Linking Resources to Tools

`ForensicTool`/`ResourceProvider` are otherwise two disconnected registries — the only
built-in link is one-directional (a tool's result can reference a resource via
`ToolContent::ResourceReference`, never the other way around). `ResourceProvider::actions()`
closes that gap in the other direction: given a resource path, it returns the IDs of
already-registered tools that make sense to run against that specific node — e.g. "decode
this binary value as a timestamp" for one registry value, but not for another.

This is pure discovery, not a new invocation mechanism. `ScopedCapabilityRegistry::list_node_actions(provider_id, path, cancellation)`
calls `provider.actions()`, drops any ID that isn't a registered tool or that the caller
isn't authorized to discover (same `AccessKind::DiscoverTool` check as `list_tools()`), and
returns the surviving `ToolDescriptor`s. Invocation is unchanged — pass one of their `id`s to
the existing `invoke_tool()`. A tool meant to be used this way should accept a resource
locator (e.g. a `provider`/`path` pair) as part of its `input_schema`, since forensic-rs
stays protocol-neutral and does not auto-inject the path into tool input.

For `RegistryProvider`/`VfsProvider`, a node's actions come from `ProviderHook::action_ids()`
(for a real node) and `ProviderHook::virtual_action_ids()` (for a node nested inside a hook's
own virtual namespace) — the same hooks already used to inject virtual children, gated by the
same `matches_path`/`matches_value` check. A parser or analyzer author registers a hook once
via `add_hook()` and both virtual data *and* applicable commands follow.

No MCP method exists for "list actions on a resource" — this stays a Rust-API-level
capability. A server author wires `list_node_actions` into whatever discovery convention
their own client expects (e.g. attaching it to their own `resources/list` response).

## Next Steps

- [Access Control](./07_access_control.md) - Implement authentication and authorization for resources
- See [examples/mcp_stdio_server.rs:304-315](../../examples/mcp_stdio_server.rs) for resource reference handling
