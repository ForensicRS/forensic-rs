//! MCP stdio server example.
//!
//! Exposes forensic-rs capability tools over a JSON-RPC 2.0 stdio transport,
//! demonstrating the MCP capability integration contract without adding any
//! MCP SDK or async runtime to the core.
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
//!   tools/call  (with optional _meta.progressToken → progress notifications;
//!               runs on a worker thread so the read loop stays free)
//!   resources/list / resources/read  (browses the crate's own working
//!               directory via a chrooted VfsProvider, forensic://{provider}/{path}
//!               URIs; reading a container falls back to its children listing,
//!               so a generic client can browse via plain resources/read alone;
//!               reading a recognized container FILE — e.g. examples/sample_triage.frtriage —
//!               additionally returns a mount_uri hint, and resources/read on a
//!               path containing a [mount] marker browses inside it, mounted
//!               lazily on first access and cached — see the module comment
//!               above MiniArchiveFactory)
//!   notifications/cancelled  (cancels the matching in-flight tools/call, keyed
//!               by requestId)
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
use std::io::{BufRead, BufReader, Read, SeekFrom, Write};
use std::sync::{Arc, Mutex};

use forensic_rs::field::Text;
use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;
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

/// Audit sink that logs all access decisions to stderr.
///
/// For production use, implement `AccessAuditSink` to write to a secure
/// audit log, SIEM system, or centralized logging service.
///
/// See [Access Control Tutorial](../docs/mcp-server-guide/04_tutorial/07_access_control.md)
/// for details on implementing audit logging.
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

/// Progress reporter that sends MCP `notifications/progress` messages.
///
/// AI clients can subscribe to progress updates by providing a `_meta.progressToken`
/// in the tools/call request. The server then sends progress notifications
/// via stdout while processing.
///
/// See [Long-Running Tools Cookbook](../docs/mcp-server-guide/05_cookbook/tools.md#recipe-5-long-running-tool-with-progress)
/// for patterns on implementing progress reporting.
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
            println!("{}", msg);
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

/// Example tool: Returns case summary information.
///
/// This tool demonstrates:
/// - Defining `ToolDescriptor` with input/output schemas
/// - Validating typed input with `CapabilityValue`
/// - Returning structured results with `ToolResult::structured()`
/// - Proper error handling with `CapabilityError`
///
/// See [Your First Tool Tutorial](../docs/mcp-server-guide/04_tutorial/02_first_tool.md)
/// for a detailed walkthrough of this pattern.
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

/// Example tool: Demonstrates progress reporting and cancellation.
///
/// This tool demonstrates:
/// - Cooperative cancellation via `context.cancellation.is_cancelled()`
/// - Progress reporting via `context.report_progress()`
/// - Handling of nested input parameters
/// - Early return on cancellation
///
/// See [Progress Reporting Cookbook](../docs/mcp-server-guide/05_cookbook/tools.md#recipe-5-long-running-tool-with-progress)
/// for more progress reporting patterns.
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
        let iterations = get_nested_u64(&input, "iterations", "value").unwrap_or(10);

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

// ============================================================================
// Cross-family resource nesting demo (lazy mount-and-cache)
// ============================================================================
//
// Demonstrates browsing *into* a container file (a zip, an E01, a registry
// hive, ...) discovered inside the "filesystem" resource provider, without
// ever eagerly scanning the whole evidence tree up front. See
// docs/mcp-server-guide/07_capability_coverage.md, "Nested/Cross-Family
// Resource Design", for the full reasoning.
//
// `MiniArchiveFactory` below is a toy `FormatFactory` — forensic-rs ships no
// real zip/E01/OLE parser (that would need an extra dependency this crate
// deliberately doesn't take on), so this stands in for one to demonstrate the
// mechanism end to end. A real deployment registers a real zip/E01-aware
// `FormatFactory` instead; everything else here (the `MountResolver`, the
// `[mount]` path convention, the `resources/read` wiring) is unchanged.
//
// Mounting is driven by `MountResolver`, which caches by `EvidenceLocator`
// (a structured chain of hops) rather than by a flat string path — the
// earlier flat-string cache could represent only one level of nesting,
// because `split_mount_path` located the *first* `[mount]` marker in a
// path and silently handed everything after it, markers included, to the
// single mounted filesystem's `read_all`/`read_dir`. Locating the *last*
// marker and mounting each hop in the chain in turn (see
// `mounted_filesystem` below) removes that ceiling.

const MOUNT_MARKER: &str = "[mount]";
const MINI_ARCHIVE_MAGIC: &str = "FRTRIAGE1";
const MINI_ARCHIVE_ENTRY_SEP: &str = "---ENTRY---";

/// Parses the toy text-based "mini archive" format used by
/// `examples/sample_triage.frtriage`: a magic first line, then
/// `---ENTRY---`-delimited blocks of `name line` + `content lines`.
fn parse_mini_archive(bytes: &[u8]) -> Option<InMemoryVirtualFileSystem> {
    fn flush(fs: &mut InMemoryVirtualFileSystem, name: &Option<String>, content: &[&str]) {
        if let Some(name) = name {
            fs.add_file(name.clone(), content.join("\n"));
        }
    }

    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.lines();
    if lines.next()?.trim() != MINI_ARCHIVE_MAGIC {
        return None;
    }
    let mut fs = InMemoryVirtualFileSystem::new();
    let mut current_name: Option<String> = None;
    let mut current_content: Vec<&str> = Vec::new();
    for line in lines {
        if line.trim() == MINI_ARCHIVE_ENTRY_SEP {
            flush(&mut fs, &current_name, &current_content);
            current_name = None;
            current_content.clear();
        } else if current_name.is_none() {
            current_name = Some(line.trim().to_string());
        } else {
            current_content.push(line);
        }
    }
    flush(&mut fs, &current_name, &current_content);
    Some(fs)
}

/// Toy `FormatFactory`: recognizes the mini-archive magic and mounts its
/// entries into an in-memory filesystem. Stand-in for a real zip/E01/OLE
/// factory — see the module comment above.
struct MiniArchiveFactory;

impl FormatFactory for MiniArchiveFactory {
    fn name(&self) -> &'static str {
        "mini-archive"
    }

    fn yields(&self) -> MountKind {
        MountKind::FileSystem
    }

    fn probe(&self, file: &mut dyn VirtualFile, _ctx: &MountContext<'_>) -> ForensicResult<ProbeScore> {
        let start = file.stream_position()?;
        let mut magic = vec![0u8; MINI_ARCHIVE_MAGIC.len()];
        let matches = file.read_exact(&mut magic).is_ok() && magic == MINI_ARCHIVE_MAGIC.as_bytes();
        file.seek(SeekFrom::Start(start))?;
        Ok(if matches { ProbeScore::Strong } else { ProbeScore::No })
    }

    fn mount(&self, mut file: Box<dyn VirtualFile>, _ctx: &MountContext<'_>) -> ForensicResult<Mounted> {
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let fs = parse_mini_archive(&bytes).ok_or_else(|| {
            ForensicError::other("MiniArchiveFactory", "malformed mini-archive".to_string())
        })?;
        Ok(Mounted::FileSystem(Arc::new(fs)))
    }
}

/// Splits a resource path at the **last** `[mount]` marker into
/// `(container_chain, inner_path)`. `container_chain` may itself contain
/// earlier `[mount]` markers, one per nested container --
/// `"a.zip/[mount]/b.zip/[mount]/x"` -> `Some(("a.zip/[mount]/b.zip", "x"))`.
/// `"case.frtriage/[mount]"` (or with a trailing slash) ->
/// `Some(("case.frtriage", ""))` (the mount's own root).
fn split_mount_path(path: &str) -> Option<(&str, &str)> {
    let marker = "/[mount]";
    let idx = path.rfind(marker)?;
    let container = &path[..idx];
    let inner = path[idx + marker.len()..].trim_start_matches('/');
    Some((container, inner))
}

/// Builds the `forensic://{provider}/{container}/[mount]/{inner}` URI for a
/// path inside a mounted container.
fn mount_child_uri(provider: &str, container_path: &str, inner_path: &str) -> String {
    let suffix = if inner_path.is_empty() {
        String::new()
    } else {
        format!("/{}", inner_path)
    };
    encode_resource_uri(provider, &format!("{}/{}{}", container_path, MOUNT_MARKER, suffix))
}

/// A `Cursor<Vec<u8>>`-backed [`VirtualFile`] over already-read bytes, so
/// [`Server::looks_like_container`] can route through the real registered
/// `FormatFactory::probe` implementations instead of duplicating their
/// magic-byte check.
struct BytesFile(std::io::Cursor<Vec<u8>>);
impl Read for BytesFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}
impl std::io::Seek for BytesFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.0.seek(pos)
    }
}
impl VirtualFile for BytesFile {
    fn metadata(&self) -> ForensicResult<forensic_rs::traits::vfs::VMetadata> {
        Ok(forensic_rs::traits::vfs::VMetadata {
            file_type: VFileType::File,
            size: self.0.get_ref().len() as u64,
            allocated_size: None,
            times: MacbTimes::default(),
            id: None,
            attributes: FileAttributes::empty(),
        })
    }
}

/// Encodes a `(provider, path)` resource identity into a single MCP URI, reusing
/// the same `forensic://` scheme this file already uses for
/// `ToolContent::ResourceReference`.
fn encode_resource_uri(provider: &str, path: &str) -> String {
    format!("forensic://{}/{}", provider, path)
}

/// Inverse of [`encode_resource_uri`]. The first path segment after the scheme is
/// the provider id; everything after the first `/` is the resource path (which
/// may itself contain further `/` or `\` separators).
fn decode_resource_uri(uri: &str) -> Option<(String, String)> {
    let rest = uri.strip_prefix("forensic://")?;
    match rest.split_once('/') {
        Some((provider, path)) => Some((provider.to_string(), path.to_string())),
        None => Some((rest.to_string(), String::new())),
    }
}

/// Lists the authorized children of `path` within `provider`, shaped as the
/// same `{"uri","name","description"}` entries `resources/list` returns. Shared
/// by `resources/list`'s uri-drilldown branch and `resources/read`'s
/// container-read fallback (see `handle`'s `"resources/read"` arm) so the two
/// don't duplicate the mapping.
fn list_children_as_json(
    scoped: &ScopedCapabilityRegistry<'_>,
    provider: &str,
    path: &str,
    cancellation: &CancellationToken,
) -> CapabilityResult<Vec<serde_json::Value>> {
    let page = scoped.list_resources(provider, path, PageRequest::new(0, u64::MAX), cancellation)?;
    Ok(page
        .entries
        .into_iter()
        .map(|entry| {
            serde_json::json!({
                "uri": encode_resource_uri(&entry.id.provider, &entry.id.path),
                "name": entry.name,
                "description": entry.description,
            })
        })
        .collect())
}

/// Maps a `ResourceContent` to an MCP `resources/read` content entry.
fn resource_content_to_mcp(id: &ResourceId, content: ResourceContent) -> serde_json::Value {
    let uri = encode_resource_uri(&id.provider, &id.path);
    match content {
        ResourceContent::Text { text, media_type } => serde_json::json!({
            "uri": uri,
            "mimeType": media_type.unwrap_or_else(|| "text/plain".to_string()),
            "text": text,
        }),
        ResourceContent::Bytes { data, media_type } => {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(&data);
            serde_json::json!({
                "uri": uri,
                "mimeType": media_type.unwrap_or_else(|| "application/octet-stream".to_string()),
                "blob": encoded,
            })
        }
        ResourceContent::Structured { value, media_type } => serde_json::json!({
            "uri": uri,
            "mimeType": media_type.unwrap_or_else(|| "application/json".to_string()),
            "text": serde_json::to_string(&capability_value_to_json(&value)).unwrap_or_default(),
        }),
    }
}

/// Stable stringification of a JSON-RPC id, used as the cancellation-registry key.
/// Applied identically when registering (from `tools/call`'s `req.id`) and when
/// looking up (from `notifications/cancelled`'s `requestId`), so they always agree.
fn request_key(id: &serde_json::Value) -> String {
    id.to_string()
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
    /// Live cancellation tokens for in-flight `tools/call` invocations, keyed by
    /// the stringified JSON-RPC request id. `notifications/cancelled` looks up its
    /// `requestId` here to reach the running call — see `handle_tools_call` and
    /// the `"notifications/cancelled"` arm of `handle`.
    cancellations: Mutex<BTreeMap<String, CancellationToken>>,
    /// The same filesystem `VfsProvider` is registered with, kept directly so
    /// `mounted_filesystem` can open a container file's raw bytes without going
    /// through the resource-authorization layer twice.
    vfs: Arc<dyn FileSystem>,
    /// Registered container-format sniffers plus the lazy mount cache,
    /// keyed by `EvidenceLocator` rather than a flat string path — see
    /// `mounted_filesystem` and "Nested/Cross-Family Resource Design" in
    /// docs/mcp-server-guide/07_capability_coverage.md.
    mount_resolver: MountResolver,
}

/// Server setup and initialization.
///
/// This demonstrates:
/// - Creating `CapabilityRegistry` with an access policy
/// - Wrapping policies with `AuditedAccessPolicy` for audit logging
/// - Registering tools with the registry
/// - Creating `AccessContext` for an authenticated principal
///
/// See [Access Control Tutorial](../docs/mcp-server-guide/04_tutorial/07_access_control.md)
/// for implementing custom access policies.
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

        // Expose the crate's own working directory as browsable evidence via
        // `resources/list`/`resources/read`, chrooted (not the raw host root) —
        // a real deployment would chroot to an actual evidence/triage directory
        // instead of ".". Mirrors the pattern in `examples/registry_and_vfs.rs`.
        let vfs: Arc<dyn FileSystem> =
            Arc::new(ChRootFileSystem::new(".", Arc::new(StdVirtualFS::new())));
        registry
            .register_resource_provider(Arc::new(VfsProvider::new(Arc::clone(&vfs))))
            .unwrap();

        let access = AccessContext::new("analyst-local", "local-triage")
            .with_session("stdio-session")
            .with_role("incident-response");

        Self {
            registry,
            access,
            cancellations: Mutex::new(BTreeMap::new()),
            vfs,
            mount_resolver: MountResolver::builder().factory(Arc::new(MiniArchiveFactory)).build(),
        }
    }

    /// Returns the mounted filesystem for the (possibly multi-hop)
    /// container chain named by `container_chain` — one path segment per
    /// `[mount]` hop, joined by `/[mount]/` (see [`split_mount_path`]).
    /// Mounts and caches each hop on first access, keyed by its full
    /// [`EvidenceLocator`] so a second-level nested container is a distinct
    /// cache entry from the first-level one that contains it, rather than
    /// colliding on a shared flat string. Never scans anything beyond the
    /// containers actually being opened — see the module comment above
    /// `MiniArchiveFactory`.
    fn mounted_filesystem(
        &self,
        container_chain: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<Arc<dyn FileSystem>> {
        let mut current_fs = Arc::clone(&self.vfs);
        let mut locator = EvidenceLocator::root();
        for hop in container_chain.split("/[mount]/") {
            locator = locator.push(LocatorSegment::Path(FPathBuf::from(hop)));
            let file = current_fs.open(FPath::new(hop)).map_err(|_| {
                CapabilityError::new(CapabilityErrorKind::NotFound, "container not found")
            })?;
            let mounted = self
                .mount_resolver
                .resolve(&current_fs, &locator, file, Some(MountKind::FileSystem), cancellation)
                .map_err(|_| {
                    CapabilityError::new(
                        CapabilityErrorKind::InvalidInput,
                        "not a recognized container format, or failed to mount",
                    )
                })?;
            current_fs = mounted
                .as_file_system()
                .ok_or_else(|| {
                    CapabilityError::new(
                        CapabilityErrorKind::Internal,
                        "mount did not yield a filesystem",
                    )
                })?
                .clone();
        }
        Ok(current_fs)
    }

    /// Whether a resource's already-read content looks like a recognized
    /// container format — used to hint a `mount_uri` on an otherwise-
    /// ordinary successful read. Routes through the same registered
    /// `FormatFactory::probe` implementations `mounted_filesystem` mounts
    /// with, via [`MountResolver::probe_only`], instead of duplicating
    /// their magic-byte check.
    fn looks_like_container(
        &self,
        content: &ResourceContent,
        path: &str,
        cancellation: &CancellationToken,
    ) -> bool {
        let bytes = match content {
            ResourceContent::Text { text, .. } => text.as_bytes().to_vec(),
            ResourceContent::Bytes { data, .. } => data.clone(),
            ResourceContent::Structured { .. } => return false,
        };
        let mut file = BytesFile(std::io::Cursor::new(bytes));
        let locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from(path)));
        self.mount_resolver
            .probe_only(&self.vfs, &locator, &mut file, Some(MountKind::FileSystem), cancellation)
            .unwrap_or(false)
    }

    /// Reads or lists `inner_path` inside the container chain
    /// `container_chain`, mounting it on demand via `mounted_filesystem`.
    /// Called from the `"resources/read"` arm of `handle` whenever the
    /// requested path contains a `[mount]` marker.
    fn read_mounted(
        &self,
        provider: &str,
        container_chain: &str,
        inner_path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<serde_json::Value> {
        let fs = self.mounted_filesystem(container_chain, cancellation)?;
        let uri = mount_child_uri(provider, container_chain, inner_path);
        let inner = if inner_path.is_empty() { "/" } else { inner_path };

        if let Ok(bytes) = fs.read_all(FPath::new(inner)) {
            return Ok(match String::from_utf8(bytes) {
                Ok(text) => serde_json::json!({ "uri": uri, "mimeType": "text/plain", "text": text }),
                Err(err) => {
                    use base64::Engine;
                    let encoded = base64::engine::general_purpose::STANDARD.encode(err.into_bytes());
                    serde_json::json!({
                        "uri": uri,
                        "mimeType": "application/octet-stream",
                        "blob": encoded,
                    })
                }
            });
        }

        let entries = fs.read_dir(FPath::new(inner)).map_err(|_| {
            CapabilityError::new(
                CapabilityErrorKind::NotFound,
                "not found in mounted container",
            )
        })?;
        let children: Vec<serde_json::Value> = entries
            .filter_map(|entry| entry.ok())
            .map(|entry| {
                let name = entry.file_name().unwrap_or_default().to_string();
                let child_inner = if inner_path.is_empty() {
                    name.clone()
                } else {
                    format!("{}/{}", inner_path, name)
                };
                serde_json::json!({
                    "uri": mount_child_uri(provider, container_chain, &child_inner),
                    "name": name,
                })
            })
            .collect();
        Ok(serde_json::json!({
            "uri": uri,
            "mimeType": "application/json",
            "text": serde_json::to_string(&serde_json::json!({ "children": children }))
                .unwrap_or_default(),
        }))
    }

    fn handle(&self, req: McpRequest) -> Option<String> {
        match req.method.as_str() {
            "initialize" => {
                let id = req.id?;
                let result = serde_json::json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": { "tools": {}, "resources": {} },
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
            // "tools/call" is intentionally not handled here — `main()` dispatches
            // it directly to `handle_tools_call` on a worker thread instead, so
            // this blocking-loop-based `handle` never runs a long tool call itself.
            "resources/list" => {
                let id = req.id?;
                let scoped = self.registry.scope(self.access.clone());
                let cancellation = CancellationToken::new();
                let uri = req.params.get("uri").and_then(|v| v.as_str());

                let list_result: CapabilityResult<Vec<serde_json::Value>> = match uri {
                    None => Ok(scoped
                        .list_resource_providers()
                        .into_iter()
                        .map(|descriptor| {
                            serde_json::json!({
                                "uri": encode_resource_uri(&descriptor.id, ""),
                                "name": descriptor.title,
                                "description": descriptor.description,
                            })
                        })
                        .collect()),
                    Some(uri) => match decode_resource_uri(uri) {
                        Some((provider, path)) => {
                            list_children_as_json(&scoped, &provider, &path, &cancellation)
                        }
                        None => Err(CapabilityError::new(
                            CapabilityErrorKind::InvalidInput,
                            "invalid resource uri",
                        )),
                    },
                };

                Some(match list_result {
                    Ok(resources) => {
                        let result = serde_json::json!({ "resources": resources });
                        serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
                    }
                    Err(err) => {
                        let (code, msg, data) = map_error(&err);
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": { "code": code, "message": msg, "data": data }
                        })
                        .to_string()
                    }
                })
            }
            "resources/read" => {
                let id = req.id?;
                let scoped = self.registry.scope(self.access.clone());
                let cancellation = CancellationToken::new();
                let uri = req.params.get("uri").and_then(|v| v.as_str());

                let read_result: CapabilityResult<serde_json::Value> =
                    match uri.and_then(decode_resource_uri) {
                        Some((provider, path)) => {
                            // A `[mount]` marker means the caller is asking to
                            // browse *inside* an already-discovered container
                            // file (see the `mount_uri` hint added below) —
                            // handled directly against the mounted filesystem,
                            // bypassing the resource-provider registry entirely
                            // (the mounted filesystem isn't a registered
                            // `ResourceProvider`, just a plain `FileSystem`).
                            if let Some((container_chain, inner_path)) = split_mount_path(&path) {
                                self.read_mounted(&provider, container_chain, inner_path, &cancellation)
                            } else {
                                let resource_id = ResourceId::new(provider, path);
                                match scoped.read_resource(&resource_id, &cancellation) {
                                    Ok(content) => {
                                        let mut value =
                                            resource_content_to_mcp(&resource_id, content.clone());
                                        if self.looks_like_container(&content, &resource_id.path, &cancellation) {
                                            if let serde_json::Value::Object(map) = &mut value {
                                                map.insert(
                                                    "mount_uri".to_string(),
                                                    serde_json::Value::String(mount_child_uri(
                                                        &resource_id.provider,
                                                        &resource_id.path,
                                                        "",
                                                    )),
                                                );
                                            }
                                        }
                                        Ok(value)
                                    }
                                    Err(read_err) => {
                                        // Not readable as content — this may be a
                                        // container (a directory, a registry key, ...)
                                        // rather than a leaf. Fall back to its
                                        // children listing so a generic MCP client
                                        // can still browse it via plain
                                        // `resources/read`, without needing this
                                        // server's non-standard
                                        // `resources/list?uri=...` convention. If it
                                        // isn't a container either, surface the
                                        // original read error.
                                        match list_children_as_json(
                                            &scoped,
                                            &resource_id.provider,
                                            &resource_id.path,
                                            &cancellation,
                                        ) {
                                            Ok(children) => Ok(serde_json::json!({
                                                "uri": encode_resource_uri(&resource_id.provider, &resource_id.path),
                                                "mimeType": "application/json",
                                                "text": serde_json::to_string(&serde_json::json!({ "children": children }))
                                                    .unwrap_or_default(),
                                            })),
                                            Err(_) => Err(read_err),
                                        }
                                    }
                                }
                            }
                        }
                        None => Err(CapabilityError::new(
                            CapabilityErrorKind::InvalidInput,
                            "invalid resource uri",
                        )),
                    };

                Some(match read_result {
                    Ok(contents) => {
                        let result = serde_json::json!({ "contents": [contents] });
                        serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
                    }
                    Err(err) => {
                        let (code, msg, data) = map_error(&err);
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": { "code": code, "message": msg, "data": data }
                        })
                        .to_string()
                    }
                })
            }
            "notifications/cancelled" => {
                // Per the MCP spec, `requestId` is the id of the original request
                // being cancelled (not `progressToken`, which the previous version
                // of this handler incorrectly read).
                if let Some(id) = req.params.get("requestId").cloned() {
                    let key = request_key(&id);
                    if let Some(token) = self.cancellations.lock().unwrap().get(&key) {
                        token.cancel();
                    }
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

    /// Handles `tools/call`. Run on a worker thread by `main()` (not through
    /// `handle`), so the main stdin-reading loop stays free to receive and
    /// dispatch a `notifications/cancelled` while a long call is in flight.
    ///
    /// Registers a `CancellationToken` in `self.cancellations`, keyed by the
    /// request id, for the duration of the call — see `request_key` and the
    /// `"notifications/cancelled"` arm of `handle`.
    fn handle_tools_call(&self, req: McpRequest) -> Option<String> {
        let name = req.params.get("name")?.as_str()?;
        let args = req.params.get("arguments").unwrap_or(&serde_json::Value::Null);
        let progress_token = req
            .params
            .get("_meta")
            .and_then(|m| m.get("progressToken"))
            .cloned();
        let token = Arc::new(Mutex::new(progress_token));

        let scoped = self.registry.scope(self.access.clone());
        let cancellation = CancellationToken::new();
        let key = req.id.as_ref().map(request_key);
        if let Some(key) = &key {
            self.cancellations
                .lock()
                .unwrap()
                .insert(key.clone(), cancellation.clone());
        }

        let mut invocation = {
            let reporter = Arc::new(StdioProgressReporter::new(token));
            InvocationContext::new(self.access.clone())
                .with_progress_reporter(reporter)
        };
        invocation.cancellation = cancellation;

        let input = json_to_value(args);
        let result = scoped.invoke_tool(name, input, invocation);

        if let Some(key) = &key {
            self.cancellations.lock().unwrap().remove(key);
        }

        Some(match result {
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
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": req.id,
                    "result": {
                        "content": content,
                        "structuredContent": structured,
                        "isError": false
                    }
                })
                .to_string()
            }
            Err(err) => {
                let (code, msg, data) = map_error(&err);
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": req.id,
                    "error": {
                        "code": code,
                        "message": msg,
                        "data": data
                    }
                })
                .to_string()
            }
        })
    }
}

/// Main entry point for the MCP stdio server.
///
/// The server:
/// 1. Initializes the `Server` (registry, policies, tools)
/// 2. Reads JSON-RPC requests line-by-line from stdin
/// 3. Handles each method (initialize, tools/list, tools/call, etc.)
/// 4. Writes JSON-RPC responses to stdout, diagnostics to stderr
///
/// For a complete walkthrough of building this server from scratch,
/// see the [Quickstart Guide](../docs/mcp-server-guide/03_quickstart.md).
///
/// For production deployment considerations, see:
/// - [Deployment Tutorial](../docs/mcp-server-guide/04_tutorial/08_deployment.md)
/// - [Troubleshooting Guide](../docs/mcp-server-guide/06_troubleshooting.md)
fn main() {
    eprintln!(
        "[forensic-rs MCP stdio server] Trusted local example — do not expose to untrusted clients"
    );

    let server = Arc::new(Server::new());
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
                println!("{}", resp);
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
                println!("{}", resp);
                std::io::stdout().flush().ok();
                continue;
            }
        };

        if req.method.as_str() == "tools/call" {
            // Run on a worker thread so the main loop keeps reading stdin — in
            // particular so a `notifications/cancelled` for this call can
            // actually be received and dispatched while the call is in flight.
            // One thread per call, fire-and-forget, no pool: an acceptable
            // simplification for a trusted-local reference example, not a
            // production concurrency model. Concurrent `println!` calls each
            // lock stdout for their own full write, so responses/progress
            // notifications from different threads won't interleave mid-line —
            // only their relative order is nondeterministic, which is inherent
            // to real concurrency.
            let server = Arc::clone(&server);
            std::thread::spawn(move || {
                if let Some(response) = server.handle_tools_call(req) {
                    println!("{}", response);
                    std::io::stdout().flush().ok();
                }
            });
        } else if let Some(response) = server.handle(req) {
            println!("{}", response);
            std::io::stdout().flush().ok();
        }
    }
}

#[cfg(test)]
mod nested_mount_tests {
    use super::*;

    fn nested_mini_archive_vfs() -> Arc<dyn FileSystem> {
        let inner = "FRTRIAGE1\nhello.txt\nhi";
        let outer = format!("FRTRIAGE1\ninner.frtriage\n{inner}");
        let vfs = InMemoryVirtualFileSystem::new().with_text_file("outer.frtriage", outer);
        Arc::new(vfs)
    }

    fn test_server(vfs: Arc<dyn FileSystem>) -> Server {
        Server {
            registry: CapabilityRegistry::new(Arc::new(AllowAllPolicy)),
            access: AccessContext::new("test", "test"),
            cancellations: Mutex::new(BTreeMap::new()),
            vfs,
            mount_resolver: MountResolver::builder().factory(Arc::new(MiniArchiveFactory)).build(),
        }
    }

    #[test]
    fn resolves_two_levels_of_nested_mounts() {
        let server = test_server(nested_mini_archive_vfs());
        let cancellation = CancellationToken::new();
        let fs = server
            .mounted_filesystem("outer.frtriage/[mount]/inner.frtriage", &cancellation)
            .expect("second-level mount should resolve");
        let bytes = fs.read_all(FPath::new("hello.txt")).expect("hello.txt inside the inner mount");
        assert_eq!(bytes, b"hi");
    }

    #[test]
    fn read_mounted_serves_content_two_hops_deep() {
        let server = test_server(nested_mini_archive_vfs());
        let cancellation = CancellationToken::new();
        let value = server
            .read_mounted(
                "filesystem",
                "outer.frtriage/[mount]/inner.frtriage",
                "hello.txt",
                &cancellation,
            )
            .expect("read_mounted should serve the doubly-nested file");
        assert_eq!(value["text"], serde_json::Value::String("hi".to_string()));
    }

    #[test]
    fn split_mount_path_finds_the_last_marker_not_the_first() {
        let path = "outer.frtriage/[mount]/inner.frtriage/[mount]/hello.txt";
        let (container_chain, inner) = split_mount_path(path).unwrap();
        assert_eq!(container_chain, "outer.frtriage/[mount]/inner.frtriage");
        assert_eq!(inner, "hello.txt");
    }

    #[test]
    fn single_level_mount_still_works() {
        let server = test_server(nested_mini_archive_vfs());
        let cancellation = CancellationToken::new();
        let fs = server
            .mounted_filesystem("outer.frtriage", &cancellation)
            .expect("single-level mount should still resolve");
        assert!(fs.exists(FPath::new("inner.frtriage")));
    }

    #[test]
    fn looks_like_container_recognizes_mini_archive_bytes_via_probe() {
        let server = test_server(nested_mini_archive_vfs());
        let cancellation = CancellationToken::new();
        let content = ResourceContent::Text {
            text: "FRTRIAGE1\nx\ny".to_string(),
            media_type: None,
        };
        assert!(server.looks_like_container(&content, "outer.frtriage", &cancellation));
        let not_container = ResourceContent::Text {
            text: "just some plain text".to_string(),
            media_type: None,
        };
        assert!(!server.looks_like_container(&not_container, "plain.txt", &cancellation));
    }
}
