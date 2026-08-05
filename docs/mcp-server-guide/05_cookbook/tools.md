# Cookbook: Tool Recipes

This cookbook provides reusable code patterns for creating ForensicTool implementations.

## Recipe 1: Read-Only Tool with No Input

A simple tool that returns static or computed data without requiring input.

```rust
use std::collections::BTreeMap;
use forensic_rs::field::Text;
use forensic_rs::prelude::*;

pub struct ServerInfoTool {
    descriptor: ToolDescriptor,
}

impl ServerInfoTool {
    pub fn new() -> Self {
        Self {
            descriptor: ToolDescriptor {
                id: "server.info".into(),
                title: "Server Information".into(),
                description: "Returns information about this forensic server.".into(),
                input_schema: ValueSchema::object()
                    .allow_additional_properties()
                    .into(),
                output_schema: Some(
                    ValueSchema::object()
                        .property("version", ValueSchema::Type(ValueType::Text))
                        .property("uptime_seconds", ValueSchema::Type(ValueType::Integer))
                        .property("supported_artifacts", ValueSchema::Array(Box::new(ValueSchema::Type(ValueType::Text))))
                        .required(["version", "uptime_seconds"])
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

impl ForensicTool for ServerInfoTool {
    fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    fn invoke(
        &self,
        _input: CapabilityValue,
        _context: &InvocationContext,
    ) -> CapabilityResult<ToolResult> {
        let mut map = BTreeMap::new();
        map.insert(Text::Borrowed("version"), CapabilityValue::from("0.1.0"));
        map.insert(Text::Borrowed("uptime_seconds"), CapabilityValue::from(0u64));
        map.insert(Text::Borrowed("supported_artifacts"), CapabilityValue::Array(vec![
            CapabilityValue::from("Windows.Registry"),
            CapabilityValue::from("Windows.EventLog"),
            CapabilityValue::from("Windows.Prefetch"),
        ]));

        Ok(ToolResult::structured(CapabilityValue::Object(map)))
    }
}
```

## Recipe 2: Tool with Optional Parameters

Handle tools where some parameters are optional with defaults.

```rust
use std::collections::BTreeMap;
use forensic_rs::field::Text;
use forensic_rs::prelude::*;

pub struct SearchTool {
    descriptor: ToolDescriptor,
}

impl SearchTool {
    pub fn new() -> Self {
        Self {
            descriptor: ToolDescriptor {
                id: "evidence.search".into(),
                title: "Search Evidence".into(),
                description: "Searches evidence for a query string.".into(),
                input_schema: ValueSchema::object()
                    .property("query", ValueSchema::Type(ValueType::Text))
                    .property("case_id", ValueSchema::Type(ValueType::Text))
                    .property("limit", ValueSchema::object()
                        .property("value", ValueSchema::Type(ValueType::Integer))
                        .required("value")
                        .into())
                    .required(["query", "case_id"])
                    .into(),
                output_schema: Some(
                    ValueSchema::object()
                        .property("results", ValueSchema::Array(Box::new(ValueSchema::Type(ValueType::Text))))
                        .property("total", ValueSchema::Type(ValueType::Integer))
                        .required(["results", "total"])
                        .into(),
                ),
                hints: ToolHints::default(),
            },
        }
    }
}

impl ForensicTool for SearchTool {
    fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    fn invoke(
        &self,
        input: CapabilityValue,
        _context: &InvocationContext,
    ) -> CapabilityResult<ToolResult> {
        let fields = input.as_object().ok_or_else(||
            CapabilityError::new(CapabilityErrorKind::InvalidInput, "input must be an object")
        )?;

        // Required parameter
        let query = fields.get("query").and_then(CapabilityValue::as_text)
            .ok_or_else(|| CapabilityError::new(CapabilityErrorKind::InvalidInput, "query required"))?;

        // Optional parameter with default
        let limit = fields.get("limit")
            .and_then(|v| v.as_object())
            .and_then(|obj| obj.get("value"))
            .and_then(CapabilityValue::as_u64)
            .unwrap_or(10) as usize;

        // Perform search (mock)
        let results = vec![format!("Result for '{}'", query)];

        let mut map = BTreeMap::new();
        map.insert(Text::Borrowed("results"), CapabilityValue::Array(
            results.into_iter().take(limit).map(CapabilityValue::from).collect()
        ));
        map.insert(Text::Borrowed("total"), CapabilityValue::from(1u64));

        Ok(ToolResult::structured(CapabilityValue::Object(map)))
    }
}
```

## Recipe 3: Tool Returning Binary Data

Return binary content like file extracts or hex dumps.

```rust
use std::collections::BTreeMap;
use forensic_rs::field::Text;
use forensic_rs::prelude::*;

pub struct FileExtractTool {
    descriptor: ToolDescriptor,
}

impl FileExtractTool {
    pub fn new() -> Self {
        Self {
            descriptor: ToolDescriptor {
                id: "evidence.extract".into(),
                title: "Extract File Content".into(),
                description: "Extracts content from a file as binary data.".into(),
                input_schema: ValueSchema::object()
                    .property("case_id", ValueSchema::Type(ValueType::Text))
                    .property("path", ValueSchema::Type(ValueType::Text))
                    .required(["case_id", "path"])
                    .into(),
                output_schema: None,  // Binary content returned as ToolContent::Bytes
                hints: ToolHints {
                    read_only: true,
                    idempotent: true,
                    ..ToolHints::default()
                },
            },
        }
    }
}

impl ForensicTool for FileExtractTool {
    fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    fn invoke(
        &self,
        input: CapabilityValue,
        _context: &InvocationContext,
    ) -> CapabilityResult<ToolResult> {
        let fields = input.as_object().ok_or_else(||
            CapabilityError::new(CapabilityErrorKind::InvalidInput, "input must be an object")
        )?;

        let path = fields.get("path").and_then(CapabilityValue::as_text)
            .ok_or_else(|| CapabilityError::new(CapabilityErrorKind::InvalidInput, "path required"))?;

        // In real implementation, read from VFS (vfs: Arc<dyn FileSystem>)
        // let content = vfs.read_all(FPath::new(path))?;

        // Mock binary content
        let content = vec![0x50, 0x4B, 0x03, 0x04];  // ZIP magic bytes

        Ok(ToolResult {
            content: vec![ToolContent::Bytes {
                data: content,
                media_type: Some("application/octet-stream".into()),
            }],
            structured: None,
        })
    }
}
```

## Recipe 4: Tool with Resource References

Return references to resources for the client to read.

```rust
use std::collections::BTreeMap;
use forensic_rs::field::Text;
use forensic_rs::prelude::*;

pub struct ListArtifactsTool {
    descriptor: ToolDescriptor,
}

impl ListArtifactsTool {
    pub fn new() -> Self {
        Self {
            descriptor: ToolDescriptor {
                id: "case.artifacts".into(),
                title: "List Case Artifacts".into(),
                description: "Lists available artifacts in the case.".into(),
                input_schema: ValueSchema::object()
                    .property("case_id", ValueSchema::Type(ValueType::Text))
                    .required("case_id")
                    .into(),
                output_schema: Some(
                    ValueSchema::object()
                        .property("artifacts", ValueSchema::Array(Box::new(
                            ValueSchema::Object(ObjectSchema {
                                properties: vec![
                                    (Text::Borrowed("name"), ValueSchema::Type(ValueType::Text)),
                                    (Text::Borrowed("type"), ValueSchema::Type(ValueType::Text)),
                                    (Text::Borrowed("resource_uri"), ValueSchema::Type(ValueType::Text)),
                                ],
                                required: vec![Text::Borrowed("name"), Text::Borrowed("type"), Text::Borrowed("resource_uri")],
                                allow_additional_properties: false,
                            })
                        )))
                        .required(["artifacts"])
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

impl ForensicTool for ListArtifactsTool {
    fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    fn invoke(
        &self,
        input: CapabilityValue,
        _context: &InvocationContext,
    ) -> CapabilityResult<ToolResult> {
        let fields = input.as_object().ok_or_else(||
            CapabilityError::new(CapabilityErrorKind::InvalidInput, "input must be an object")
        )?;

        let case_id = fields.get("case_id").and_then(CapabilityValue::as_text)
            .ok_or_else(|| CapabilityError::new(CapabilityErrorKind::InvalidInput, "case_id required"))?;

        // Mock artifact list
        let artifacts = vec![
            ArtifactInfo {
                name: "Security Event Log".to_string(),
                type_: "Windows.EventLog".to_string(),
                provider: "eventlog".to_string(),
                path: "Security".to_string(),
            },
            ArtifactInfo {
                name: "System Registry Hive".to_string(),
                type_: "Windows.Registry".to_string(),
                provider: "registry".to_string(),
                path: "HKLM\\SYSTEM".to_string(),
            },
        ];

        let artifact_values: Vec<_> = artifacts.into_iter().map(|a| {
            let mut map = BTreeMap::new();
            map.insert(Text::Borrowed("name"), CapabilityValue::from(a.name));
            map.insert(Text::Borrowed("type"), CapabilityValue::from(a.type_));
            map.insert(Text::Borrowed("resource_uri"), CapabilityValue::from(
                format!("forensic://{}/{}", a.provider, a.path)
            ));
            CapabilityValue::Object(map)
        }).collect();

        let mut result = BTreeMap::new();
        result.insert(Text::Borrowed("artifacts"), CapabilityValue::Array(artifact_values));

        Ok(ToolResult::structured(CapabilityValue::Object(result)))
    }
}

struct ArtifactInfo {
    name: String,
    type_: String,
    provider: String,
    path: String,
}
```

## Recipe 5: Long-Running Tool with Progress

Report progress during expensive operations.

```rust
use std::collections::BTreeMap;
use forensic_rs::field::Text;
use forensic_rs::prelude::*;

pub struct DeepScanTool {
    descriptor: ToolDescriptor,
}

impl DeepScanTool {
    pub fn new() -> Self {
        Self {
            descriptor: ToolDescriptor {
                id: "analysis.deep_scan".into(),
                title: "Deep Analysis Scan".into(),
                description: "Performs comprehensive analysis of evidence.".into(),
                input_schema: ValueSchema::object()
                    .property("case_id", ValueSchema::Type(ValueType::Text))
                    .required("case_id")
                    .property("intensity", ValueSchema::Type(ValueType::Text))
                    .into(),
                output_schema: Some(
                    ValueSchema::object()
                        .property("findings", ValueSchema::Type(ValueType::Integer))
                        .property("duration_ms", ValueSchema::Type(ValueType::Integer))
                        .required(["findings", "duration_ms"])
                        .into(),
                ),
                hints: ToolHints {
                    read_only: true,
                    idempotent: true,
                    long_running: true,
                    ..ToolHints::default()
                },
            },
        }
    }
}

impl ForensicTool for DeepScanTool {
    fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    fn invoke(
        &self,
        input: CapabilityValue,
        context: &InvocationContext,
    ) -> CapabilityResult<ToolResult> {
        let fields = input.as_object().ok_or_else(||
            CapabilityError::new(CapabilityErrorKind::InvalidInput, "input must be an object")
        )?;

        let case_id = fields.get("case_id").and_then(CapabilityValue::as_text)
            .ok_or_else(|| CapabilityError::new(CapabilityErrorKind::InvalidInput, "case_id required"))?;

        let intensity = fields.get("intensity").and_then(CapabilityValue::as_text)
            .unwrap_or("medium");

        // Simulation of long-running work
        let steps = match intensity {
            "low" => 10,
            "medium" => 20,
            "high" => 50,
            _ => 20,
        };

        let start = std::time::Instant::now();
        let mut findings = 0u64;

        for step in 0..steps {
            // Check cancellation periodically
            if context.cancellation.is_cancelled() {
                let elapsed = start.elapsed().as_millis() as u64;
                let mut result = BTreeMap::new();
                result.insert(Text::Borrowed("findings"), CapabilityValue::from(findings));
                result.insert(Text::Borrowed("duration_ms"), CapabilityValue::from(elapsed));
                result.insert(Text::Borrowed("cancelled"), CapabilityValue::Bool(true));
                return Ok(ToolResult::structured(CapabilityValue::Object(result)));
            }

            // Report progress
            context.report_progress(
                ProgressUpdate::new(step as u64)
                    .with_total(steps as u64)
                    .with_message(format!("Processing step {}/{}", step + 1, steps))
            ).ok();

            // Simulate work
            std::thread::sleep(std::time::Duration::from_millis(50));

            // Simulate findings discovery
            if step % 5 == 0 {
                findings += 1;
            }
        }

        let elapsed = start.elapsed().as_millis() as u64;

        let mut result = BTreeMap::new();
        result.insert(Text::Borrowed("findings"), CapabilityValue::from(findings));
        result.insert(Text::Borrowed("duration_ms"), CapabilityValue::from(elapsed));
        result.insert(Text::Borrowed("cancelled"), CapabilityValue::Bool(false));

        Ok(ToolResult::structured(CapabilityValue::Object(result)))
    }
}
```

## Recipe 6: Idempotent vs Non-Idempotent Tools

Indicate tool behavior for AI client retry logic.

```rust
// Idempotent tool - safe to retry
ToolHints {
    read_only: true,
    idempotent: true,    // Same input always produces same output
    destructive: false,
    ..ToolHints::default()
}

// Non-idempotent tool - retrying may have side effects
ToolHints {
    read_only: false,
    idempotent: false,   // Same input may produce different output
    destructive: true,   // May modify data
    ..ToolHints::default()
}

// Destructive example: Archive case
ToolHints {
    read_only: false,
    idempotent: false,
    destructive: true,   // Cannot undo this operation
    long_running: true,
}
```

## Summary of Patterns

| Pattern | Use When |
|---------|----------|
| No-input tool | Server introspection, status checks |
| Optional parameters | Search with filters, pagination |
| Binary output | File extraction, hex dumps |
| Resource references | Linking to browseable resources |
| Progress reporting | Long analysis operations |
| Hints for idempotency | Guiding AI retry behavior |
