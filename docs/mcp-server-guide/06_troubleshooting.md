# Troubleshooting Guide

Common issues and solutions when building ForensicRS MCP servers.

## Table of Contents

1. [Connection Issues](#connection-issues)
2. [Schema Validation Errors](#schema-validation-errors)
3. [Progress Reporting Not Working](#progress-reporting-not-working)
4. [Cancellation Not Honored](#cancellation-not-honored)
5. [Access Denied Errors](#access-denied-errors)
6. [Tool Not Found](#tool-not-found)
7. [Memory Issues](#memory-issues)
8. [Debugging Techniques](#debugging-techniques)

---

## Connection Issues

### Problem: Server starts but client can't connect

**Symptoms:**
- Client reports "connection refused" or "timeout"
- No output from server

**Solutions:**

1. **Check stderr vs stdout**: The stdio server writes diagnostics to stderr. JSON-RPC traffic goes to stdout. Make sure you're not accidentally capturing stdout.

```bash
# Wrong - captures JSON traffic
cargo run 2>&1 | cat

# Correct - only see diagnostics
cargo run 2>/dev/null
```

2. **Verify binary is executable**: On Windows, check the executable exists and has correct permissions.

3. **Check for startup errors**: Look at stderr for panics or errors during initialization.

### Problem: Server hangs on first request

**Symptoms:**
- Server starts, first request never returns

**Solutions:**

1. **Flush stdout**: Ensure you're flushing after each response.

```rust
println!("{}", response);
std::io::stdout().flush().ok();  // Add this!
```

2. **Check for blocking I/O**: If using blocking I/O, ensure stdin reading doesn't block indefinitely.

---

## Schema Validation Errors

### Problem: Input validation fails for valid input

**Symptoms:**
```
error: {"code": -32602, "message": "Invalid input"}
```

**Solutions:**

1. **Check schema type matching**:
```rust
// Wrong: schema says Integer but passing string
input_schema: ValueSchema::object()
    .property("count", ValueSchema::Type(ValueType::Integer))  // Integer
    .required("count")
    .into(),

// JSON input must be:
// {"count": 42}   NOT   {"count": "42"}
```

2. **Verify required fields**:
```rust
// All required fields must be present
.required("case_id")
.required("limit")
```

3. **Check object vs nested object**:
```rust
// Simple property
.property("case_id", ValueSchema::Type(ValueType::Text))

// Nested object property
.property("pagination", ValueSchema::object()
    .property("offset", ValueSchema::Type(ValueType::Integer))
    .property("limit", ValueSchema::Type(ValueType::Integer))
    .required("offset")
    .into())
```

### Problem: Output doesn't match schema

**Symptoms:**
```
Internal error: output schema mismatch
```

**Solutions:**

1. **Ensure all required fields are present**:
```rust
output_schema: Some(
    ValueSchema::object()
        .property("case_id", ValueSchema::Type(ValueType::Text))
        .property("count", ValueSchema::Type(ValueType::Integer))
        .required(["case_id", "count"])  // Both must be present
        .into()
)
```

2. **Use correct types**:
```rust
// CapabilityValue type must match schema
map.insert(Text::Borrowed("count"), CapabilityValue::from(42u64));  // Integer
map.insert(Text::Borrowed("name"), CapabilityValue::from("test".to_string()));  // Text
```

---

## Progress Reporting Not Working

### Problem: Progress updates not appearing

**Symptoms:**
- Long-running tool completes without progress notifications

**Solutions:**

1. **Check progress token availability**:
```rust
// Progress requires a token from the client
let token = params.get("_meta")
    .and_then(|m| m.get("progressToken"))
    .cloned();

let reporter = Arc::new(StdioProgressReporter {
    token: Arc::new(Mutex::new(token))  // Must be Some(token)
});

let invocation = InvocationContext::new(access)
    .with_progress_reporter(reporter);
```

2. **Ignore errors from report_progress**:
```rust
// report_progress can fail if token expired - don't abort
context.report_progress(update).ok();  // Use .ok() not ?
```

3. **Ensure monotonic updates**:
```rust
// Updates must increase or reach total
ProgressUpdate::new(current)
    .with_total(total)  // Never decrease!
```

---

## Cancellation Not Honored

### Problem: Tool doesn't stop when cancelled

**Symptoms:**
- `notifications/cancelled` sent but tool continues

**Solutions:**

1. **Check cancellation periodically**:
```rust
fn invoke(&self, input: CapabilityValue, context: &InvocationContext) -> CapabilityResult<ToolResult> {
    let items = get_items_to_process()?;

    for (i, item) in items.enumerate() {
        // Check cancellation BEFORE each expensive operation
        if context.cancellation.is_cancelled() {
            return Err(CapabilityError::new(
                CapabilityErrorKind::Cancelled,
                "operation cancelled"
            ));
        }

        process_item(item)?;
    }
    Ok(result)
}
```

2. **Use early returns**:
```rust
// Don't use `continue` - return early on cancellation
if context.cancellation.is_cancelled() {
    return Err(CapabilityError::new(CapabilityErrorKind::Cancelled, "cancelled"));
}
```

3. **Check in tight loops**:
```rust
for i in 0..10000 {
    // Every 100 iterations is often enough
    if i % 100 == 0 && context.cancellation.is_cancelled() {
        return Err(CapabilityError::new(CapabilityErrorKind::Cancelled, "cancelled"));
    }
    do_work(i)?;
}
```

---

## Access Denied Errors

### Problem: Tool invocation returns AccessDenied

**Symptoms:**
```
error: {"code": -32602, "message": "Access denied"}
```

**Solutions:**

1. **Check AccessPolicy**:
```rust
// Using AllowAllPolicy for testing
let policy = Arc::new(AllowAllPolicy::new());

// Using custom policy
let policy = Arc::new(MyCustomPolicy::new());

// Always wrap with audit in production
let audit = Arc::new(MyAuditSink::new());
let policy = Arc::new(AuditedAccessPolicy::new(policy, audit));
```

2. **Verify AccessContext has required roles**:
```rust
let access = AccessContext::new("analyst-42", "acme")
    .with_role("analyst");  // Must have role your policy requires
```

3. **Check policy evaluation**:
```rust
// Debug: print what policy is seeing
impl AccessPolicy for DebugPolicy {
    fn evaluate(&self, context: &AccessContext, request: &AccessRequest<'_>) -> AccessDecision {
        eprintln!("[DEBUG] Evaluating {:?} for {:?}", request, context.principal);
        let result = self.inner.evaluate(context, request);
        eprintln!("[DEBUG] Result: {:?}", result);
        result
    }
}
```

---

## Tool Not Found

### Problem: Registered tool doesn't appear in tools/list

**Symptoms:**
- Tool is registered but `tools/list` doesn't show it

**Solutions:**

1. **Check tool ID matches**:
```rust
// Register with ID
registry.register_tool(Arc::new(MyTool::new())).unwrap();

// Call with exact ID
// "case.summary" not "CaseSummary" or "case-summary"
```

2. **Verify registration succeeded**:
```rust
// unwrap() will panic on error
registry.register_tool(Arc::new(MyTool::new()))
    .expect("Failed to register tool");

// Or handle gracefully
if let Err(e) = registry.register_tool(Arc::new(MyTool::new())) {
    eprintln!("Registration warning: {}", e);
}
```

3. **Check scoped registry filtering**:
```rust
let scoped = registry.scope(access);
// Tools filtered by policy may not appear
for tool in scoped.list_tools() {
    println!("Visible: {}", tool.id);
}
```

---

## Memory Issues

### Problem: Memory grows unbounded

**Symptoms:**
- Server memory usage increases over time
- Eventually crashes with OOM

**Solutions:**

1. **Don't cache mutable state in tools**:
```rust
// Bad: accumulates data
struct BadTool {
    all_results: Vec<ForensicData>,  // Grows forever!
}

impl ForensicTool for BadTool {
    fn invoke(&self, input: CapabilityValue, context: &InvocationContext) -> CapabilityResult<ToolResult> {
        // Add to cumulative list - BAD!
        self.all_results.push(process(input)?);
        Ok(ToolResult::structured(...))
    }
}

// Good: stateless processing
struct GoodTool;

impl ForensicTool for GoodTool {
    fn invoke(&self, input: CapabilityValue, context: &InvocationContext) -> CapabilityResult<ToolResult> {
        // Process and return - no accumulation
        Ok(ToolResult::structured(...))
    }
}
```

2. **Set resource limits**:
```rust
// Limit concurrent operations
let semaphore = Arc::new(Semaphore::new(4));

// Limit memory per operation
if estimated_size > MAX_SIZE {
    return Err(CapabilityError::new(CapabilityErrorKind::Internal, "Too much data"));
}
```

3. **Use streaming for large results**:
```rust
// Return resource reference instead of full content
ToolContent::ResourceReference {
    provider: "filesystem".into(),
    path: "/path/to/large_file".into(),
    name: "large_file.bin".into(),
}
```

---

## Debugging Techniques

### Enable Debug Logging

```rust
use log::{debug, error};

impl ForensicTool for MyTool {
    fn invoke(&self, input: CapabilityValue, context: &InvocationContext) -> CapabilityResult<ToolResult> {
        debug!("Invoking tool with input: {:?}", input);

        let result = do_work(input);

        match &result {
            Ok(r) => debug!("Tool succeeded: {:?}", r),
            Err(e) => error!("Tool failed: {:?}", e),
        }

        result
    }
}
```

### Dump JSON-RPC Traffic

```rust
// Log incoming requests
for line in stdin.lines() {
    let line = line?;
    eprintln!("[REQUEST] {}", line);

    // Process...
    let response = handle(&raw);

    eprintln!("[RESPONSE] {}", response);
}
```

### Test Tool in Isolation

```rust
#[test]
fn test_tool_directly() {
    let tool = MyTool::new();
    let access = AccessContext::new("test", "test");
    let context = InvocationContext::new(access);

    let input = CapabilityValue::from(serde_json::json!({
        "case_id": "TEST-001"
    }));

    let result = tool.invoke(input, &context).unwrap();
    assert!(result.structured.is_some());
}
```

### Common Error Codes

| Code | Meaning | Solution |
|------|---------|----------|
| -32600 | Invalid request | Check JSON-RPC format |
| -32601 | Method not found | Verify method name |
| -32602 | Invalid params | Check input schema |
| -32603 | Internal error | Check server logs |
| -32700 | Parse error | Check JSON syntax |

---

## Getting More Help

1. **Check existing examples**: See [examples/mcp_stdio_server.rs](../../examples/mcp_stdio_server.rs)
2. **Review MCP Integration docs**: See [MCP_INTEGRATION.md](../../MCP_INTEGRATION.md)
3. **Ask on Discord**: Join the [ForensicRS Discord](https://discord.gg/uVq4289B)
4. **File an issue**: Report bugs at [GitHub Issues](https://github.com/ForensicRS/forensic-rs/issues)
