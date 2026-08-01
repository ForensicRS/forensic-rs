# Tutorial: Your First Forensic Tool

This chapter walks through implementing `case.summary`, a tool that returns metadata for a forensic case.

## What We're Building

A tool that accepts a `case_id` and returns:
- `case_id`: The case identifier
- `host`: The hostname being analyzed
- `finding_count`: Number of findings in the case
- `status`: Current case status (active, closed, etc.)

## Tool Implementation Pattern

Every ForensicTool follows this pattern:

```rust
struct MyTool {
    descriptor: ToolDescriptor,  // Static metadata
}

impl MyTool {
    fn new() -> Self { ... }      // Constructor builds descriptor
}

impl ForensicTool for MyTool {
    fn descriptor(&self) -> &ToolDescriptor { &self.descriptor }

    fn invoke(
        &self,
        input: CapabilityValue,
        context: &InvocationContext,
    ) -> CapabilityResult<ToolResult> {
        // 1. Validate input
        // 2. Check cancellation
        // 3. Do work
        // 4. Report progress (optional)
        // 5. Return result
    }
}
```

## Complete Implementation

```rust
// src/tools/case.rs

use std::collections::BTreeMap;

use forensic_rs::field::Text;
use forensic_rs::prelude::*;

/// Tool that returns forensic case summary information
pub struct CaseSummaryTool {
    descriptor: ToolDescriptor,
}

impl CaseSummaryTool {
    pub fn new() -> Self {
        Self {
            descriptor: ToolDescriptor {
                id: "case.summary".into(),
                title: "Case Summary".into(),
                description: "Returns summary information for a forensic case including \
                    host, analyst, finding counts, and current status.".into(),

                // Input schema: requires case_id as text
                input_schema: ValueSchema::object()
                    .property("case_id", ValueSchema::Type(ValueType::Text))
                    .required("case_id")
                    .into(),

                // Output schema: case_id, host, finding_count, status
                output_schema: Some(
                    ValueSchema::object()
                        .property("case_id", ValueSchema::Type(ValueType::Text))
                        .property("host", ValueSchema::Type(ValueType::Text))
                        .property("finding_count", ValueSchema::Type(ValueType::Integer))
                        .property("status", ValueSchema::Type(ValueType::Text))
                        .required(["case_id", "host", "finding_count", "status"])
                        .into(),
                ),

                hints: ToolHints {
                    read_only: true,      // This tool doesn't modify data
                    idempotent: true,     // Same input always same output
                    destructive: false,
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
        // Step 1: Validate input type
        // The MCP adapter already validates against input_schema,
        // but we still validate at the tool level for safety
        let fields = input.as_object().ok_or_else(||
            CapabilityError::new(
                CapabilityErrorKind::InvalidInput,
                "input must be an object"
            )
        )?;

        // Step 2: Extract required field
        // Using as_text() returns Option<&str> for Text variant
        let case_id = fields
            .get("case_id")
            .and_then(CapabilityValue::as_text)
            .ok_or_else(|| {
                CapabilityError::new(
                    CapabilityErrorKind::InvalidInput,
                    "case_id is required and must be text"
                )
            })?;

        // Step 3: Perform work
        // In a real implementation, this would query a case database
        // For now, we return mock data
        let host = "WORKSTATION01";
        let finding_count = 0u64;
        let status = "active";

        // Step 4: Build result
        // Use BTreeMap for deterministic ordering
        let mut result_map = BTreeMap::new();
        result_map.insert(Text::Borrowed("case_id"), CapabilityValue::from(case_id.to_string()));
        result_map.insert(Text::Borrowed("host"), CapabilityValue::from(host));
        result_map.insert(Text::Borrowed("finding_count"), CapabilityValue::from(finding_count));
        result_map.insert(Text::Borrowed("status"), CapabilityValue::from(status));

        // Step 5: Return structured result
        // ToolResult::structured() wraps CapabilityValue
        Ok(ToolResult::structured(CapabilityValue::Object(result_map)))
    }
}
```

## Understanding ToolDescriptor

The `ToolDescriptor` defines the tool's public interface:

```rust
pub struct ToolDescriptor {
    pub id: String,                    // Unique, stable identifier
    pub title: String,                 // Human-readable title
    pub description: String,           // What the tool does
    pub input_schema: ValueSchema,     // Valid input structure
    pub output_schema: Option<ValueSchema>, // Expected output (optional)
    pub hints: ToolHints,              // Behavioral hints for AI
}
```

### Tool ID Conventions

Use dot-separated names for namespacing:

| ID Pattern | Example | Meaning |
|-------------|---------|---------|
| `domain.operation` | `case.summary` | Case domain, summary operation |
| `domain.subdomain.operation` | `registry.autoruns.list` | Registry domain, autoruns subdomain |
| `artifact.verb` | `prefetch.analyze` | Prefetch artifact, analyze verb |

### ToolHints

Hints guide AI client behavior:

```rust
pub struct ToolHints {
    pub read_only: bool,       // Doesn't modify evidence
    pub idempotent: bool,      // Same input = same output
    pub destructive: bool,      // May delete/modify data
    pub long_running: bool,     // May take significant time
}
```

## Understanding CapabilityValue

`CapabilityValue` is the type-safe value container:

```rust
pub enum CapabilityValue {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    F64(f64),
    Text(Text),                    // Smart string type
    Timestamp(ForensicTimestamp), // Nanosecond precision
    Bytes(Vec<u8>),
    Array(Vec<CapabilityValue>),
    Object(BTreeMap<Text, CapabilityValue>),
}
```

### Converting to/from CapabilityValue

**From JSON (in invoke):**
```rust
let fields = input.as_object()?;
// or
let val = fields.get("field_name")?;
let text = val.as_text();  // Option<&str>
let num = val.as_i64();    // Option<i64>
```

**To JSON (in adapter):**
```rust
fn to_json(val: &CapabilityValue) -> serde_json::Value {
    match val {
        CapabilityValue::Text(t) => serde_json::Value::String(t.to_string()),
        CapabilityValue::U64(u) => serde_json::json!(u),
        // ...
    }
}
```

## Understanding ToolResult

```rust
pub struct ToolResult {
    pub content: Vec<ToolContent>,           // Display content
    pub structured: Option<CapabilityValue>,  // Structured data
}

pub enum ToolContent {
    Text(String),                            // Plain text display
    Bytes { data: Vec<u8>, media_type: Option<String> },
    ResourceReference { provider: String, path: String, name: String },
}
```

**Construction patterns:**

```rust
// Structured result only (most common)
Ok(ToolResult::structured(CapabilityValue::Object(map)))

// Text content only
Ok(ToolResult::content(vec![ToolContent::Text("Analysis complete".into())]))

// Both structured and content
Ok(ToolResult {
    content: vec![ToolContent::Text("Summary".into())],
    structured: Some(CapabilityValue::Object(map)),
})
```

## Error Handling

Use `CapabilityError` with appropriate kind:

```rust
use CapabilityErrorKind::*;

// Input validation failed
CapabilityError::new(InvalidInput, "case_id is required")

// Tool not found (handled by registry)
CapabilityError::new(NotFound, "tool not registered")

// Access denied
CapabilityError::new(AccessDenied, "not authorized for this operation")

// Operation cancelled
CapabilityError::new(Cancelled, "operation was cancelled")

// Resource unavailable
CapabilityError::new(Unavailable, "evidence source not available")

// Internal error
CapabilityError::new(Internal, "unexpected error during processing")
```

## Using the Tool in Your Server

Register the tool with the capability registry:

```rust
use forensic_rs::prelude::*;

fn main() {
    let policy = Arc::new(AllowAllPolicy::new());
    let mut registry = CapabilityRegistry::new(policy);

    // Register our tool
    registry.register_tool(Arc::new(CaseSummaryTool::new())).unwrap();

    // Create access context
    let access = AccessContext::new("analyst", "acme");

    // Scope the registry
    let scoped = registry.scope(access);

    // List available tools
    for tool in scoped.list_tools() {
        println!("Tool: {} - {}", tool.id, tool.title);
    }
}
```

## Testing the Tool

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case_summary_success() {
        let tool = CaseSummaryTool::new();
        let context = InvocationContext::new(
            AccessContext::new("test", "test")
        );

        let input = CapabilityValue::Object(
            vec![(Text::Borrowed("case_id"), CapabilityValue::from("TEST-001"))]
                .into_iter()
                .collect()
        );

        let result = tool.invoke(input, &context).unwrap();
        let fields = result.structured.unwrap().into_object().unwrap();

        assert!(fields.contains_key("case_id"));
        assert!(fields.contains_key("host"));
    }

    #[test]
    fn test_case_summary_missing_case_id() {
        let tool = CaseSummaryTool::new();
        let context = InvocationContext::new(
            AccessContext::new("test", "test")
        );

        let input = CapabilityValue::Object(BTreeMap::new());

        let err = tool.invoke(input, &context).unwrap_err();
        assert_eq!(err.kind, CapabilityErrorKind::InvalidInput);
    }
}
```

## Next Steps

- [Registry Tools](./03_registry_tools.md) - Build a tool that queries the Windows registry
- See [examples/mcp_stdio_server.rs:339-411](../../examples/mcp_stdio_server.rs) for reference implementation
