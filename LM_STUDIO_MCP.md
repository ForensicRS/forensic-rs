# forensic-rs MCP Server — LM Studio Setup

A JSON-RPC 2.0 stdio MCP server that exposes forensic-rs capability tools to any
MCP-compatible AI client, including LM Studio.

## Prerequisites

- **LM Studio 0.3.17+** (0.4.x recommended for full MCP tool-calling support)
- **Rust 1.85+** (only needed if building from source)

## Quick start

### 1. Build the server

```powershell
cd C:\Users\TEST_USER\Workspace\forensic-rs
cargo build --example mcp_stdio_server --release
```

The binary will be at:
```
target\release\examples\mcp_stdio_server.exe
```

### 2. Register in LM Studio

Open **LM Studio** → Go to **Program** tab (right sidebar) → Click **Install** →
click **Edit mcp.json**.

Add the following inside the `"mcpServers": { ... }` block:

```json
"forensic-rs": {
  "command": "C:\\path\\to\\mcp_stdio_server.exe",
  "args": []
}
```

Or paste this complete `mcp.json` (replace the path with your actual binary path):

```json
{
  "mcpServers": {
    "forensic-rs": {
      "command": "C:\\Users\\TEST_USER\\Workspace\\forensic-rs\\target\\release\\examples\\mcp_stdio_server.exe",
      "args": []
    }
  }
}
```

> **Important**: Backslashes in JSON strings must be escaped (`\\`). If you copy the path
> from Explorer, make sure to double each backslash.

After saving, LM Studio will start the server automatically. You should see a
notification that the MCP server was connected.

### 3. Load a model and start chatting

1. In LM Studio, load a model (e.g. a Qwen or Llama 3 variant).
2. Start a new chat.
3. The AI will be able to call the registered tools.

## Available tools

### `case.summary`
Returns a static forensic case summary. Demonstrates schema-validated input
and structured JSON output.

**Arguments:**
```json
{ "case_id": "CX-2026-001" }
```

**Output:**
```json
{
  "case_id": "CX-2026-001",
  "finding_count": 3,
  "status": "active"
}
```

### `forensic.long_scan`
Demonstrates progress reporting and cooperative cancellation. Accepts an optional
iterations parameter (default: 10).

**Arguments:**
```json
{ "iterations": { "value": 5 } }
```

**Output:**
```json
{
  "completed_iterations": 5,
  "cancelled": false
}
```

During execution, `notifications/progress` messages are emitted to the server's
stdout, which LM Studio displays as a progress bar.

## Testing the server manually

```powershell
cd C:\Users\TEST_USER\Workspace\forensic-rs
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"manual","version":"0"}}}' | cargo run --example mcp_stdio_server
```

Full smoke test sequence:
```powershell
$msgs = @'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"manual","version":"0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"case.summary","arguments":{"case_id":"CX-2026-001"},"_meta":{"progressToken":100}}}
'@
$msgs | cargo run --example mcp_stdio_server
```

## Security notes

- This example uses `AllowAllPolicy` — it is **trusted local only**.
- Do not expose the binary to untrusted clients.
- `AllowAllPolicy` bypasses all access checks; the AI can call any registered
  tool without restriction. In a real deployment, replace it with a policy that
  enforces least-privilege access.

## Extending with real forensic tools

The example ships with two stub tools. To integrate real forensic capabilities,
implement additional `ForensicTool` impls that:

1. Receive `CapabilityValue` input validated against the tool's `input_schema`
2. Use `TriageSources` / reader factories to access evidence
3. Return typed `CapabilityValue` output matching `output_schema`
4. Call `context.report_progress(...)` for long operations
5. Check `context.cancellation.is_cancelled()` periodically

See `MCP_INTEGRATION.md` for the complete design contract and
`examples/triage_pipeline.rs` for a full forensic analysis pipeline example.
