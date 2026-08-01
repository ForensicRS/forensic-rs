//! MCP stdio server example.
//!
//! Exposes forensic-rs capability tools over a JSON-RPC 2.0 stdio transport,
//! demonstrating the MCP integration contract described in
//! `MCP_INTEGRATION.md` without adding any MCP SDK or async runtime to the core.
//!
//! Run with: `cargo run --example mcp_stdio_server`
//!
//! The server reads newline-delimited JSON-RPC 2.0 messages from stdin and writes
//! responses to stdout.  All diagnostics go to stderr so they never pollute the
//! JSON channel.
//!
//! Handled methods:
//!   initialize / notifications/initialized
//!   tools/list
//!   tools/call  (with optional _meta.progressToken → progress notifications)
//!   notifications/cancelled
//!
//! # Security note
//! This example uses [`AllowAllPolicy`] for **trusted local** access only.
//! Do not deploy this binary where untrusted clients can connect.
//!
//! # Documentation
//!
//! This file demonstrates the core patterns for building MCP servers with ForensicRS.
//! For a step-by-step tutorial, see:
//!   - [Quickstart Guide](../docs/mcp-server-guide/03_quickstart.md)
//!   - [Your First Tool](../docs/mcp-server-guide/04_tutorial/02_first_tool.md)
//!   - [Access Control](../docs/mcp-server-guide/04_tutorial/07_access_control.md)
//!   - [Deployment](../docs/mcp-server-guide/04_tutorial/08_deployment.md)

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::sync::{Arc, Mutex};

use forensic_rs::field::Text;
use forensic_rs::prelude::*;

const SECONDS_PER_DAY: i64 = 86_400;

fn civil_from_days(days: i64) -> (i64, u8, u8) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524
        - day_of_era / 146_096)
        / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month as u8, day as u8)
}

fn timestamp_to_iso(ts: ForensicTimestamp) -> String {
    let secs = ts.to_unix_secs();
    let nanos = ts.nanoseconds();
    let days = secs.div_euclid(SECONDS_PER_DAY);
    let seconds_in_day = secs.rem_euclid(SECONDS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    let hour = (seconds_in_day / 3600) as u8;
    let minute = ((seconds_in_day % 3600) / 60) as u8;
    let second = (seconds_in_day % 60) as u8;
    if nanos == 0 {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    } else {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
            year, month, day, hour, minute, second, nanos
        )
    }
}

//! Audit sink that logs all access decisions to stderr.
//!
//! For production use, implement `AccessAuditSink` to write to a secure
//! audit log, SIEM system, or centralized logging service.
//!
//! See [Access Control Tutorial](../docs/mcp-server-guide/04_tutorial/07_access_control.md)
//! for details on implementing audit logging.
struct StderrAuditSink;

impl AccessAuditSink for StderrAuditSink {
    fn record(&self, event: &AccessAuditEvent) {
        eprintln!(
            "[AUDIT] principal={} tenant={} kind={:?} id={} target={:?} decision={:?}",
            event.context.principal,
            event.context.tenant,
            event.kind,
            event.capability_id,
            event.target,
            event.decision
        );
    }
}

//! Progress reporter that sends MCP `notifications/progress` messages.
//!
//! AI clients can subscribe to progress updates by providing a `_meta.progressToken`
//! in the tools/call request. The server then sends progress notifications
//! via stdout while processing.
//!
//! See [Long-Running Tools Cookbook](../docs/mcp-server-guide/05_cookbook/tools.md#recipe-5-long-running-tool-with-progress)
//! for patterns on implementing progress reporting.
struct StdioProgressReporter {
    id: Arc<Mutex<Option<serde_json::Value>>>,
}

impl StdioProgressReporter {
    fn new(id: Arc<Mutex<Option<serde_json::Value>>>) -> Self {
        Self { id }
    }
}

impl ProgressReporter for StdioProgressReporter {
    fn report(&self, update: ProgressUpdate) -> CapabilityResult<()> {
        let token = self.id.lock().map_err(|_| {
            CapabilityError::new(CapabilityErrorKind::Internal, "progress lock poisoned")
        })?;
        if let Some(ref progress_token) = *token {
            let msg = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/progress",
                "params": {
                    "progressToken": progress_token,
                    "progress": update.current,
                    "total": update.total,
                    "message": update.message,
                }
            });
            println!("{}", msg.to_string());
            std::io::stdout().flush().ok();
        }
        Ok(())
    }
}

fn json_to_value(val: &serde_json::Value) -> CapabilityValue {
    match val {
        serde_json::Value::Null => CapabilityValue::Null,
        serde_json::Value::Bool(b) => CapabilityValue::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                CapabilityValue::I64(i)
            } else if let Some(u) = n.as_u64() {
                CapabilityValue::U64(u)
            } else if let Some(f) = n.as_f64() {
                CapabilityValue::F64(f)
            } else {
                CapabilityValue::Null
            }
        }
        serde_json::Value::String(s) => CapabilityValue::from(s.clone()),
        serde_json::Value::Array(arr) => {
            CapabilityValue::Array(arr.iter().map(json_to_value).collect())
        }
        serde_json::Value::Object(obj) => {
            let map: BTreeMap<Text, CapabilityValue> = obj
                .iter()
                .map(|(k, v)| (Text::Owned(k.clone()), json_to_value(v)))
                .collect();
            CapabilityValue::Object(map)
        }
    }
}

fn get_text_field(map: &BTreeMap<Text, CapabilityValue>, key: &str) -> Option<String> {
    for (k, v) in map.iter() {
        if k.as_ref() == key {
            return v.as_text().map(String::from);
        }
    }
    None
}

fn get_nested_u64(value: &CapabilityValue, outer_key: &str, inner_key: &str) -> Option<u64> {
    fn to_u64(cv: &CapabilityValue) -> Option<u64> {
        match cv {
            CapabilityValue::U64(v) => Some(*v),
            CapabilityValue::I64(v) => u64::try_from(*v).ok(),
            _ => None,
        }
    }
    let outer_map = value.as_object()?;
    let inner_cv = {
        let mut found: Option<&CapabilityValue> = None;
        for (k, v) in outer_map.iter() {
            if k.as_ref() == outer_key {
                found = Some(v);
                break;
            }
        }
        found?
    };
    let inner_map = inner_cv.as_object()?;
    let mut found_inner: Option<&CapabilityValue> = None;
    for (k, v) in inner_map.iter() {
        if k.as_ref() == inner_key {
            found_inner = Some(v);
            break;
        }
    }
    to_u64(found_inner?)
}

fn capability_value_to_json(val: &CapabilityValue) -> serde_json::Value {
    match val {
        CapabilityValue::Null => serde_json::Value::Null,
        CapabilityValue::Bool(b) => serde_json::Value::Bool(*b),
        CapabilityValue::I64(i) => serde_json::json!(*i),
        CapabilityValue::U64(u) => serde_json::json!(*u),
        CapabilityValue::F64(f) => serde_json::json!(*f),
        CapabilityValue::Text(t) => serde_json::Value::String(t.as_ref().to_string()),
        CapabilityValue::Timestamp(ts) => {
            serde_json::Value::String(timestamp_to_iso(*ts))
        }
        CapabilityValue::Bytes(b) => {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(b);
            serde_json::Value::String(encoded)
        }
        CapabilityValue::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(capability_value_to_json).collect())
        }
        CapabilityValue::Object(obj) => {
            let map: serde_json::Map<String, serde_json::Value> = obj
                .iter()
                .map(|(k, v)| (k.as_ref().to_string(), capability_value_to_json(v)))
                .collect();
            serde_json::Value::Object(map)
        }
    }
}

fn schema_to_json(schema: &ValueSchema) -> serde_json::Value {
    let raw = serde_json::to_value(schema).expect("schema serializes");
    convert_schema(raw)
}

fn convert_schema(raw: serde_json::Value) -> serde_json::Value {
    use serde_json::json;
    match raw {
        serde_json::Value::String(_) => json!({}),
        serde_json::Value::Object(o) => {
            let (tag, inner) = o.into_iter().next().unwrap();
            match tag.as_str() {
                "Type" => {
                    let vt = inner.as_str().unwrap();
                    let typ = match vt {
                        "Null" => "null",
                        "Boolean" => "boolean",
                        "Integer" => "integer",
                        "Number" => "number",
                        "Text" => "string",
                        "Bytes" => {
                            return json!({ "type": "string", "contentEncoding": "base64" });
                        }
                        "Timestamp" => {
                            return json!({ "type": "string", "format": "date-time" });
                        }
                        "Array" => "array",
                        "Object" => "object",
                        _ => "string",
                    };
                    json!({ "type": typ })
                }
                "Array" => {
                    let items = inner.get("items").cloned().unwrap_or(json!({}));
                    json!({ "type": "array", "items": convert_schema(items) })
                }
                "Object" => {
                    let raw_props = inner.get("properties").cloned().unwrap_or(json!({}));
                    let required = inner
                        .get("required")
                        .and_then(|r| r.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>())
                        .unwrap_or_default();
                    let additional = inner
                        .get("allow_additional_properties")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    let mut props = serde_json::Map::new();
                    if let serde_json::Value::Object(obj_props) = raw_props {
                        for (k, v) in obj_props {
                            props.insert(k, convert_schema(v));
                        }
                    }
                    json!({
                        "type": "object",
                        "properties": serde_json::Value::Object(props),
                        "required": required,
                        "additionalProperties": additional
                    })
                }
                _ => json!({}),
            }
        }
        _ => json!({}),
    }
}

fn tool_result_to_mcp_content(result: &ToolResult) -> Vec<serde_json::Value> {
    result
        .content
        .iter()
        .map(|c| match c {
            ToolContent::Text(t) => {
                serde_json::json!({ "type": "text", "text": t.as_ref() })
            }
            ToolContent::Bytes { data, media_type } => {
                use base64::Engine;
                let encoded = base64::engine::general_purpose::STANDARD.encode(data);
                let mut obj = serde_json::json!({
                    "type": "resource",
                    "resource": {
                        "blob": encoded,
                        "mimeType": media_type.as_deref().unwrap_or("application/octet-stream")
                    }
                });
                if let Some(mt) = media_type {
                    obj["resource"]["mimeType"] = serde_json::Value::String(mt.clone());
                }
                obj
            }
            ToolContent::ResourceReference { provider, path, name } => {
                serde_json::json!({
                    "type": "resource",
                    "resource": {
                        "uri": format!("forensic://{}/{}", provider, path),
                        "name": name,
                        "mimeType": "application/octet-stream"
                    }
                })
            }
        })
        .collect()
}

fn map_error(err: &CapabilityError) -> (i64, String, Option<serde_json::Value>) {
    use CapabilityErrorKind::*;
    match err.kind {
        NotFound | InvalidInput | AccessDenied => (
            -32602,
            err.message.clone(),
            Some(serde_json::json!({ "kind": format!("{:?}", err.kind) })),
        ),
        Cancelled => (
            -32603,
            err.message.clone(),
            Some(serde_json::json!({ "kind": "Cancelled" })),
        ),
        Conflict | Unavailable | Internal => (
            -32603,
            err.message.clone(),
            Some(serde_json::json!({ "kind": format!("{:?}", err.kind) })),
        ),
    }
}

//! Example tool: Returns case summary information.
//!
//! This tool demonstrates:
//! - Defining `ToolDescriptor` with input/output schemas
//! - Validating typed input with `CapabilityValue`
//! - Returning structured results with `ToolResult::structured()`
//! - Proper error handling with `CapabilityError`
//!
//! See [Your First Tool Tutorial](../docs/mcp-server-guide/04_tutorial/02_first_tool.md)
//! for a detailed walkthrough of this pattern.
struct CaseSummaryTool {
    descriptor: ToolDescriptor,
}

impl CaseSummaryTool {
    fn new() -> Self {
        Self {
            descriptor: ToolDescriptor {
                id: "case.summary".to_string(),
                title: "Case summary".to_string(),
                description:
                    "Returns an authorized forensic case summary. Demonstrates schema-validated \
                     structured input and output without requiring real evidence."
                        .to_string(),
                input_schema: ValueSchema::object()
                    .property("case_id", ValueSchema::Type(ValueType::Text))
                    .required("case_id")
                    .into(),
                output_schema: Some(
                    ValueSchema::object()
                        .property("case_id", ValueSchema::Type(ValueType::Text))
                        .property("finding_count", ValueSchema::Type(ValueType::Integer))
                        .property("status", ValueSchema::Type(ValueType::Text))
                        .required("case_id")
                        .required("finding_count")
                        .required("status")
                        .into(),
                ),
                hints: ToolHints {
                    read_only: true,
                    idempotent: true,
                    ..ToolHints::default()
                },
            },
        }
    }
}

impl ForensicTool for CaseSummaryTool {
    fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    fn invoke(
        &self,
        input: CapabilityValue,
        _context: &InvocationContext,
    ) -> CapabilityResult<ToolResult> {
        let Some(fields) = input.as_object() else {
            return Err(CapabilityError::new(
                CapabilityErrorKind::InvalidInput,
                "tool input must be an object",
            ));
        };
        let Some(case_id) = get_text_field(fields, "case_id") else {
            return Err(CapabilityError::new(
                CapabilityErrorKind::InvalidInput,
                "case_id is required",
            ));
        };
        let mut summary = BTreeMap::new();
        summary.insert(
            Text::Borrowed("case_id"),
            CapabilityValue::from(case_id),
        );
        summary.insert(
            Text::Borrowed("finding_count"),
            CapabilityValue::from(3u64),
        );
        summary.insert(Text::Borrowed("status"), CapabilityValue::from("active"));
        Ok(ToolResult::structured(CapabilityValue::Object(summary)))
    }
}

//! Example tool: Demonstrates progress reporting and cancellation.
//!
//! This tool demonstrates:
//! - Cooperative cancellation via `context.cancellation.is_cancelled()`
//! - Progress reporting via `context.report_progress()`
//! - Handling of nested input parameters
//! - Early return on cancellation
//!
//! See [Progress Reporting Cookbook](../docs/mcp-server-guide/05_cookbook/tools.md#recipe-5-long-running-tool-with-progress)
//! for more progress reporting patterns.
struct LongScanTool {
    descriptor: ToolDescriptor,
}

impl LongScanTool {
    fn new() -> Self {
        Self {
            descriptor: ToolDescriptor {
                id: "forensic.long_scan".to_string(),
                title: "Long forensic scan".to_string(),
                description:
                    "Demonstrates progress reporting and cooperative cancellation. \
                     Accepts an optional 'iterations' parameter (default 10); each iteration \
                     sleeps briefly and reports progress."
                        .to_string(),
                input_schema: ValueSchema::object()
                    .property(
                        "iterations",
                        ValueSchema::object()
                            .property("value", ValueSchema::Type(ValueType::Integer))
                            .required("value")
                            .allow_additional_properties()
                            .into(),
                    )
                    .allow_additional_properties()
                    .into(),
                output_schema: Some(
                    ValueSchema::object()
                        .property("completed_iterations", ValueSchema::Type(ValueType::Integer))
                        .property("cancelled", ValueSchema::Type(ValueType::Boolean))
                        .required("completed_iterations")
                        .required("cancelled")
                        .into(),
                ),
                hints: ToolHints {
                    read_only: true,
                    idempotent: true,
                    ..ToolHints::default()
                },
            },
        }
    }
}

impl ForensicTool for LongScanTool {
    fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    fn invoke(
        &self,
        input: CapabilityValue,
        context: &InvocationContext,
    ) -> CapabilityResult<ToolResult> {
        let iterations = get_nested_u64(&input, "iterations", "value").unwrap_or(10) as u64;

        let mut completed = 0u64;
        for i in 0..iterations {
            std::thread::sleep(std::time::Duration::from_millis(50));
            if context.cancellation.is_cancelled() {
                let mut out = BTreeMap::new();
                out.insert(
                    Text::Borrowed("completed_iterations"),
                    CapabilityValue::from(completed),
                );
                out.insert(Text::Borrowed("cancelled"), CapabilityValue::Bool(true));
                return Ok(ToolResult::structured(CapabilityValue::Object(out)));
            }
            completed = i + 1;
            context.report_progress(
                ProgressUpdate::new(completed)
                    .with_total(iterations)
                    .with_message(format!("scanning artifact {}/{}", completed, iterations)),
            )?;
        }
        let mut out = BTreeMap::new();
        out.insert(
            Text::Borrowed("completed_iterations"),
            CapabilityValue::from(completed),
        );
        out.insert(Text::Borrowed("cancelled"), CapabilityValue::Bool(false));
        Ok(ToolResult::structured(CapabilityValue::Object(out)))
    }
}

fn tool_to_mcp(tool: &ToolDescriptor) -> serde_json::Value {
    let input_schema = schema_to_json(&tool.input_schema);
    let mut obj = serde_json::json!({
        "name": tool.id,
        "title": tool.title,
        "description": tool.description,
        "inputSchema": input_schema,
        "annotations": {
            "readOnlyHint": tool.hints.read_only,
            "idempotentHint": tool.hints.idempotent,
            "destructiveHint": tool.hints.destructive,
        }
    });
    if let Some(output) = &tool.output_schema {
        obj["outputSchema"] = schema_to_json(output);
    }
    obj
}

struct McpRequest {
    id: Option<serde_json::Value>,
    method: String,
    params: serde_json::Value,
}

impl McpRequest {
    fn from_json(raw: &serde_json::Value) -> Option<Self> {
        if raw.get("jsonrpc")?.as_str()? != "2.0" {
            return None;
        }
        let id = raw.get("id").cloned();
        let method = raw.get("method")?.as_str()?.to_string();
        let params = raw.get("params").cloned().unwrap_or(serde_json::Value::Null);
        Some(Self { id, method, params })
    }
}

struct Server {
    registry: CapabilityRegistry,
    access: AccessContext,
}

//! Server setup and initialization.
//!
//! This demonstrates:
//! - Creating `CapabilityRegistry` with an access policy
//! - Wrapping policies with `AuditedAccessPolicy` for audit logging
//! - Registering tools with the registry
//! - Creating `AccessContext` for an authenticated principal
//!
//! See [Access Control Tutorial](../docs/mcp-server-guide/04_tutorial/07_access_control.md)
//! for implementing custom access policies.
impl Server {
    fn new() -> Self {
        let audit = Arc::new(StderrAuditSink);
        let policy = Arc::new(AuditedAccessPolicy::new(Arc::new(AllowAllPolicy), audit));
        let mut registry = CapabilityRegistry::new(policy);
        registry
            .register_tool(Arc::new(CaseSummaryTool::new()))
            .unwrap();
        registry
            .register_tool(Arc::new(LongScanTool::new()))
            .unwrap();

        let access = AccessContext::new("analyst-local", "local-triage")
            .with_session("stdio-session")
            .with_role("incident-response");

        Self { registry, access }
    }
}

    fn handle(&self, req: McpRequest) -> Option<String> {
        match req.method.as_str() {
            "initialize" => {
                let id = req.id?;
                let result = serde_json::json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "forensic-rs-mcp-stdio",
                        "version": "0.1.0"
                    }
                });
                Some(serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string())
            }
            "notifications/initialized" => None,
            "tools/list" => {
                let scoped = self.registry.scope(self.access.clone());
                let tools: Vec<_> = scoped
                    .list_tools()
                    .iter()
                    .map(tool_to_mcp)
                    .collect();
                let result = serde_json::json!({ "tools": tools });
                let id = req.id?;
                Some(
                    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result })
                        .to_string(),
                )
            }
            "tools/call" => {
                let name = req.params.get("name")?.as_str()?;
                let args = req.params.get("arguments").unwrap_or(&serde_json::Value::Null);
                let progress_token = req
                    .params
                    .get("_meta")
                    .and_then(|m| m.get("progressToken"))
                    .cloned();
                let token = Arc::new(Mutex::new(progress_token));

                let scoped = self.registry.scope(self.access.clone());
                let invocation = {
                    let reporter = Arc::new(StdioProgressReporter::new(token));
                    InvocationContext::new(self.access.clone())
                        .with_progress_reporter(reporter)
                };

                let input = json_to_value(args);
                let result = scoped.invoke_tool(name, input, invocation);

                match result {
                    Ok(tool_result) => {
                        let mut content = tool_result_to_mcp_content(&tool_result);
                        if let Some(ref structured_val) = tool_result.structured {
                            let json_str = serde_json::to_string(&capability_value_to_json(structured_val)).unwrap_or_default();
                            content.push(serde_json::json!({
                                "type": "text",
                                "text": json_str
                            }));
                        }
                        let structured = tool_result.structured.as_ref()
                            .map(capability_value_to_json);
                        let response = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": req.id,
                            "result": {
                                "content": content,
                                "structuredContent": structured,
                                "isError": false
                            }
                        });
                        Some(response.to_string())
                    }
                    Err(err) => {
                        let (code, msg, data) = map_error(&err);
                        let response = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": req.id,
                            "error": {
                                "code": code,
                                "message": msg,
                                "data": data
                            }
                        });
                        Some(response.to_string())
                    }
                }
            }
            "notifications/cancelled" => {
                let token = req
                    .params
                    .get("progressToken")
                    .and_then(|t| {
                        if t.is_null() {
                            None
                        } else {
                            Some(t.clone())
                        }
                    })
                    .or_else(|| {
                        req.params.get("_meta").and_then(|m| m.get("progressToken").cloned())
                    });
                if let Some(t) = token {
                    eprintln!("[SERVER] cancelled notification for token={}", t);
                }
                None
            }
            _ => {
                let response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": req.id,
                    "error": {
                        "code": -32601,
                        "message": format!("method not found: {}", req.method)
                    }
                });
                Some(response.to_string())
            }
        }
    }
}

//! Main entry point for the MCP stdio server.
//!
//! The server:
//! 1. Initializes the `Server` (registry, policies, tools)
//! 2. Reads JSON-RPC requests line-by-line from stdin
//! 3. Handles each method (initialize, tools/list, tools/call, etc.)
//! 4. Writes JSON-RPC responses to stdout, diagnostics to stderr
//!
//! For a complete walkthrough of building this server from scratch,
//! see the [Quickstart Guide](../docs/mcp-server-guide/03_quickstart.md).
//!
//! For production deployment considerations, see:
//! - [Deployment Tutorial](../docs/mcp-server-guide/04_tutorial/08_deployment.md)
//! - [Troubleshooting Guide](../docs/mcp-server-guide/06_troubleshooting.md)
fn main() {
    eprintln!(
        "[forensic-rs MCP stdio server] Trusted local example — do not expose to untrusted clients"
    );

    let server = Server::new();
    let stdin = std::io::stdin();
    let reader = BufReader::new(stdin.lock());

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let raw: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                let resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32700, "message": format!("parse error: {}", e) }
                });
                println!("{}", resp.to_string());
                std::io::stdout().flush().ok();
                continue;
            }
        };

        let req = match McpRequest::from_json(&raw) {
            Some(r) => r,
            None => {
                let resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32600, "message": "invalid request" }
                });
                println!("{}", resp.to_string());
                std::io::stdout().flush().ok();
                continue;
            }
        };

        if let Some(response) = server.handle(req) {
            println!("{}", response);
            std::io::stdout().flush().ok();
        }
    }
}
