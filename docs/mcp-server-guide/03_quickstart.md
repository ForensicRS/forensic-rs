# Quickstart: Your First Forensic MCP Server

Get a working MCP stdio server running in 5 minutes. This guide creates a minimal server that exposes a single tool.

## Step 1: Create a New Cargo Project

```bash
cargo new --bin forensic-mcp-server
cd forensic-mcp-server
```

## Step 2: Add Dependencies

Edit `Cargo.toml`:

```toml
[package]
name = "forensic-mcp-server"
version = "0.1.0"
edition = "2021"

[dependencies]
forensic-rs = { version = "0.14", features = ["serde"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
base64 = "0.21"
```

## Step 3: Create the Minimal Server

Replace `src/main.rs` with:

```rust
//! Minimal ForensicRS MCP stdio server example.
//!
//! Run with: `cargo run`
//!
//! This server exposes a single tool `case.summary` that returns
//! basic case information. It's intentionally simple to demonstrate
//! the core MCP integration patterns.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use forensic_rs::field::Text;
use forensic_rs::prelude::*;

/// Simple audit sink that prints to stderr
struct StderrAuditSink;

impl AccessAuditSink for StderrAuditSink {
    fn record(&self, event: &AccessAuditEvent) {
        eprintln!(
            "[AUDIT] principal={} decision={:?}",
            event.context.principal, event.decision
        );
    }
}

/// Progress reporter that sends MCP notifications
struct StdioProgressReporter {
    token: Arc<Mutex<Option<serde_json::Value>>>,
}

impl ProgressReporter for StdioProgressReporter {
    fn report(&self, update: ProgressUpdate) -> CapabilityResult<()> {
        let token = self.token.lock().map_err(|_| {
            CapabilityError::new(CapabilityErrorKind::Internal, "lock poisoned")
        })?;
        if let Some(ref t) = *token {
            println!(
                "{}",
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/progress",
                    "params": {
                        "progressToken": t,
                        "progress": update.current,
                        "total": update.total
                    }
                })
            );
            std::io::stdout().flush().ok();
        }
        Ok(())
    }
}

/// Our first forensic tool - returns case summary information
struct CaseSummaryTool {
    descriptor: ToolDescriptor,
}

impl CaseSummaryTool {
    fn new() -> Self {
        Self {
            descriptor: ToolDescriptor {
                id: "case.summary".into(),
                title: "Case Summary".into(),
                description: "Returns summary information for a forensic case.".into(),
                input_schema: ValueSchema::object()
                    .property("case_id", ValueSchema::Type(ValueType::Text))
                    .required("case_id")
                    .into(),
                output_schema: Some(
                    ValueSchema::object()
                        .property("case_id", ValueSchema::Type(ValueType::Text))
                        .property("host", ValueSchema::Type(ValueType::Text))
                        .property("finding_count", ValueSchema::Type(ValueType::Integer))
                        .property("status", ValueSchema::Type(ValueType::Text))
                        .required(["case_id", "host", "finding_count", "status"])
                        .into(),
                ),
                hints: ToolHints::default(),
            },
        }
    }
}

impl ForensicTool for CaseSummaryTool {
    fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    fn invoke(&self, input: CapabilityValue, _context: &InvocationContext) -> CapabilityResult<ToolResult> {
        // Validate input
        let fields = input.as_object().ok_or_else(||
            CapabilityError::new(CapabilityErrorKind::InvalidInput, "input must be an object")
        )?;
        let case_id = fields.get("case_id").and_then(CapabilityValue::as_text)
            .ok_or_else(|| CapabilityError::new(CapabilityErrorKind::InvalidInput, "case_id required"))?;

        // Build response
        let mut result = BTreeMap::new();
        result.insert(Text::Borrowed("case_id"), CapabilityValue::from(case_id.to_string()));
        result.insert(Text::Borrowed("host"), CapabilityValue::from("WORKSTATION01"));
        result.insert(Text::Borrowed("finding_count"), CapabilityValue::from(0u64));
        result.insert(Text::Borrowed("status"), CapabilityValue::from("active"));

        Ok(ToolResult::structured(CapabilityValue::Object(result)))
    }
}

/// Convert JSON-RPC request to internal representation
fn parse_request(raw: &serde_json::Value) -> Option<(Option<serde_json::Value>, String, serde_json::Value)> {
    let id = raw.get("id").cloned();
    let method = raw.get("method")?.as_str()?.to_string();
    let params = raw.get("params").cloned().unwrap_or(serde_json::Value::Null);
    Some((id, method, params))
}

/// Convert forensic-rs Value to JSON Value
fn value_to_json(val: &CapabilityValue) -> serde_json::Value {
    match val {
        CapabilityValue::Null => serde_json::Value::Null,
        CapabilityValue::Bool(b) => serde_json::Value::Bool(*b),
        CapabilityValue::I64(i) => serde_json::json!(*i),
        CapabilityValue::U64(u) => serde_json::json!(*u),
        CapabilityValue::F64(f) => serde_json::json!(*f),
        CapabilityValue::Text(t) => serde_json::Value::String(t.to_string()),
        CapabilityValue::Timestamp(ts) => serde_json::json!(ts.to_rfc3339()),
        CapabilityValue::Bytes(b) => {
            use base64::Engine;
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(b))
        }
        CapabilityValue::Array(arr) => serde_json::Value::Array(arr.iter().map(value_to_json).collect()),
        CapabilityValue::Object(obj) => {
            serde_json::Value::Object(obj.iter().map(|(k, v)| (k.to_string(), value_to_json(v))).collect())
        }
    }
}

/// Convert tool result to MCP content array
fn result_to_content(result: &ToolResult) -> Vec<serde_json::Value> {
    result.content.iter().map(|c| match c {
        ToolContent::Text(t) => serde_json::json!({"type": "text", "text": t.as_ref()}),
        ToolContent::Bytes { data, media_type } => {
            use base64::Engine;
            serde_json::json!({
                "type": "resource",
                "resource": {
                    "blob": base64::engine::general_purpose::STANDARD.encode(data),
                    "mimeType": media_type.as_deref().unwrap_or("application/octet-stream")
                }
            })
        }
        ToolContent::ResourceReference { provider, path, name } => {
            serde_json::json!({
                "type": "resource",
                "resource": {
                    "uri": format!("forensic://{}/{}", provider, path),
                    "name": name
                }
            })
        }
    }).collect()
}

fn main() {
    // Set up the capability registry
    let audit = Arc::new(StderrAuditSink);
    let policy = Arc::new(AuditedAccessPolicy::new(Arc::new(AllowAllPolicy), audit));
    let mut registry = CapabilityRegistry::new(policy);
    registry.register_tool(Arc::new(CaseSummaryTool::new())).unwrap();

    // Create access context for local development
    let access = AccessContext::new("local-analyst", "dev")
        .with_role("developer");

    println!("[INFO] ForensicRS MCP server starting...");

    // Read JSON-RPC requests from stdin
    let stdin = std::io::stdin();
    for line in std::io::BufRead::lines(stdin.lock()) {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }

        let raw: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                println!("{}", serde_json::json!({
                    "jsonrpc": "2.0", "id": null,
                    "error": {"code": -32700, "message": format!("Parse error: {}", e)}
                }));
                continue;
            }
        };

        let (id, method, params) = match parse_request(&raw) {
            Some(r) => r,
            None => {
                println!("{}", serde_json::json!({
                    "jsonrpc": "2.0", "id": null,
                    "error": {"code": -32600, "message": "Invalid request"}
                }));
                continue;
            }
        };

        let response = match method.as_str() {
            "initialize" => {
                serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "forensic-mcp-server", "version": "0.1.0"}
                    }
                })
            }
            "tools/list" => {
                let scoped = registry.scope(access.clone());
                let tools: Vec<_> = scoped.list_tools().iter().map(|t| {
                    serde_json::json!({
                        "name": t.id,
                        "title": t.title,
                        "description": t.description,
                        "inputSchema": serde_json::to_value(&t.input_schema).unwrap()
                    })
                }).collect();
                serde_json::json!({"jsonrpc": "2.0", "id": id, "result": {"tools": tools}})
            }
            "tools/call" => {
                let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(serde_json::Value::Null);
                let progress_token = params.get("_meta").and_then(|m| m.get("progressToken")).cloned();

                let scoped = registry.scope(access.clone());
                let reporter = Arc::new(StdioProgressReporter {
                    token: Arc::new(Mutex::new(progress_token))
                });
                let invocation = InvocationContext::new(access.clone())
                    .with_progress_reporter(reporter);

                let input = json_to_value(&args);
                match scoped.invoke_tool(name, input, invocation) {
                    Ok(result) => {
                        let content = result_to_content(&result);
                        let structured = result.structured.as_ref().map(value_to_json);
                        serde_json::json!({
                            "jsonrpc": "2.0", "id": id,
                            "result": {"content": content, "structuredContent": structured, "isError": false}
                        })
                    }
                    Err(err) => {
                        serde_json::json!({
                            "jsonrpc": "2.0", "id": id,
                            "error": {"code": -32603, "message": err.message}
                        })
                    }
                }
            }
            _ => {
                serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": {"code": -32601, "message": format!("Method not found: {}", method)}
                })
            }
        };

        println!("{}", response);
        std::io::stdout().flush().ok();
    }
}

/// Convert JSON value to CapabilityValue
fn json_to_value(val: &serde_json::Value) -> CapabilityValue {
    match val {
        serde_json::Value::Null => CapabilityValue::Null,
        serde_json::Value::Bool(b) => CapabilityValue::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                CapabilityValue::I64(i)
            } else if let Some(u) = n.as_u64() {
                CapabilityValue::U64(u)
            } else {
                CapabilityValue::F64(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => CapabilityValue::from(s.clone()),
        serde_json::Value::Array(arr) => CapabilityValue::Array(arr.iter().map(json_to_value).collect()),
        serde_json::Value::Object(obj) => {
            let map: BTreeMap<Text, CapabilityValue> = obj.iter()
                .map(|(k, v)| (Text::Owned(k.clone()), json_to_value(v)))
                .collect();
            CapabilityValue::Object(map)
        }
    }
}
```

## Step 4: Run the Server

```bash
cargo run
```

## Step 5: Test with MCP Inspector

In another terminal, test with `mcp` CLI or write a test client:

```bash
# Send initialize request
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | cargo run

# Send tools/list request
echo '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | cargo run

# Call case.summary tool
echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"case.summary","arguments":{"case_id":"INC-001"}}}' | cargo run
```

**Expected output for tools/list:**
```json
{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"case.summary","title":"Case Summary","description":"Returns summary information for a forensic case.","inputSchema":{...}}]}}
```

**Expected output for tools/call:**
```json
{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"..."}],"structuredContent":{"case_id":"INC-001","host":"WORKSTATION01","finding_count":0,"status":"active"},"isError":false}}
```

## What You Built

This minimal server demonstrates:

| Pattern | Location |
|---------|----------|
| `CapabilityRegistry` setup | `main()` |
| `AccessContext` creation | `main()` |
| `ForensicTool` implementation | `CaseSummaryTool` |
| `ToolDescriptor` with schemas | `CaseSummaryTool::new()` |
| `CapabilityValue` input parsing | `invoke()` |
| `ToolResult` output construction | `invoke()` |
| JSON-RPC request handling | `main()` |
| JSON-RPC response formatting | `result_to_content()` |

## Next Steps

- Continue to [Project Setup](./04_tutorial/01_project_setup.md) to add more tools
- See [Your First Tool](./04_tutorial/02_first_tool.md) for detailed walkthrough
- Review [examples/mcp_stdio_server.rs](../../examples/mcp_stdio_server.rs) for complete implementation
