# Project Setup for ForensicRS MCP Servers

This guide covers creating a production-ready ForensicRS MCP server project.

## Creating the Project

```bash
cargo new --bin forensic-mcp-server
cd forensic-mcp-server
```

## Complete Cargo.toml

```toml
[package]
name = "forensic-mcp-server"
version = "0.1.0"
edition = "2021"
authors = ["Your Name <your@email.com>"]
description = "MCP server for forensic case analysis"
license = "MIT"

[dependencies]
forensic-rs = { version = "0.14", features = ["serde"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
base64 = "0.21"
tokio = { version = "1.0", features = ["rt-multi-thread", "macros"] }

[dev-dependencies]
tempfile = "3.8"

[[example]]
name = "mcp_stdio_server"
path = "examples/mcp_stdio_server.rs"
```

## Project Structure

```
forensic-mcp-server/
├── Cargo.toml
├── src/
│   ├── main.rs           # Entry point, server setup
│   ├── tools/             # Tool implementations
│   │   ├── mod.rs
│   │   ├── case.rs        # case.summary tool
│   │   ├── registry.rs    # registry.autoruns tool
│   │   ├── prefetch.rs   # prefetch.analyze tool
│   │   └── events.rs      # security.logon_events tool
│   ├── resources/         # Resource provider implementations
│   │   ├── mod.rs
│   │   └── providers.rs
│   ├── auth/              # Access policy implementations
│   │   ├── mod.rs
│   │   └── policy.rs
│   └── transport/         # JSON-RPC transport
│       ├── mod.rs
│       └── stdio.rs
└── examples/
    └── mcp_stdio_server.rs
```

## Feature Flags

ForensicRS supports these feature flags:

| Feature | Description | Default |
|---------|-------------|---------|
| `serde` | Enable serde serialization for `CapabilityValue`, schemas | Yes |
| `logging` | Enable logging macros | Yes |
| `notifications` | Enable notification system | Yes |

```toml
# Minimal dependencies (no serde)
forensic-rs = { version = "0.14", default-features = false }

# Full-featured (recommended for MCP)
forensic-rs = { version = "0.14", features = ["serde", "logging", "notifications"] }
```

## Import Prelude

The `forensic_rs::prelude` module re-exports commonly used types:

```rust
use forensic_rs::prelude::*;

// Re-exports include:
// - ForensicResult, ForensicError
// - CapabilityRegistry, ScopedCapabilityRegistry
// - ForensicTool, ToolDescriptor, ToolResult
// - CapabilityValue, ValueSchema, ValueType
// - AccessContext, AccessPolicy, AllowAllPolicy
// - InvocationContext, CancellationToken
// - ForensicData, Field, Text
// - Artifact, WindowsArtifacts, RegistryArtifacts
// - TriageSources, TriagePipeline
```

## Testing Setup

Create `tests/integration_test.rs`:

```rust
use forensic_rs::prelude::*;

#[test]
fn test_case_summary_tool() {
    let tool = CaseSummaryTool::new();
    let descriptor = tool.descriptor();

    assert_eq!(descriptor.id, "case.summary");
    assert!(descriptor.input_schema.is_object());
}

#[test]
fn test_tool_invocation() {
    let tool = CaseSummaryTool::new();
    let access = AccessContext::new("test", "test");
    let context = InvocationContext::new(access);

    let input = CapabilityValue::from(serde_json::json!({
        "case_id": "TEST-001"
    }));

    let result = tool.invoke(input, &context).expect("tool should succeed");
    let fields = result.structured.unwrap().into_object().unwrap();

    assert!(fields.contains_key("case_id"));
    assert!(fields.contains_key("finding_count"));
}
```

## Running Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_case_summary

# Run with all features
cargo test --all-features
```

## Building for Release

```bash
# Debug build
cargo build

# Release build
cargo build --release

# With specific target
cargo build --release --target x86_64-pc-windows-msvc
```

## Adding Your First Tool

See [Your First Tool](./02_first_tool.md) for a detailed walkthrough of implementing the `case.summary` tool.

## Next Steps

- [Registry Tools](./03_registry_tools.md) - Query Run keys for persistence mechanisms
- [VFS Tools](./04_vfs_tools.md) - Analyze Prefetch files via FileSystem
- [Event Log Tools](./05_eventlog_tools.md) - Query Security event logs
