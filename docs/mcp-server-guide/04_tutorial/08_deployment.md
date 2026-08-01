# Tutorial: Deployment

This chapter covers building, packaging, and deploying your ForensicRS MCP server.

## Build Configuration

### Release Build

```bash
# Build with optimizations
cargo build --release

# Build for specific target
cargo build --release --target x86_64-pc-windows-msvc
```

### Feature Flags

Choose features appropriate for your deployment:

```toml
[dependencies]
forensic-rs = { version = "0.14", default-features = false, features = ["serde"] }
```

| Feature | Use Case |
|---------|----------|
| `serde` | MCP protocol serialization (required) |
| `logging` | Debug logging via `log` crate |
| `notifications` | Alert/notification system |

## Project Structure for Deployment

```
forensic-mcp-server/
├── Cargo.toml
├── src/
│   └── ...
├── examples/
│   └── mcp_stdio_server.rs
└── README.md
```

## Environment Configuration

Use environment variables for deployment-specific settings:

```rust
use std::env;

#[derive(Clone)]
pub struct ServerConfig {
    pub log_level: String,
    pub audit_enabled: bool,
    pub policy_type: PolicyType,
}

impl ServerConfig {
    pub fn from_env() -> Self {
        Self {
            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into()),
            audit_enabled: env::var("AUDIT_ENABLED")
                .unwrap_or_else(|_| "true".into())
                .parse()
                .unwrap_or(true),
            policy_type: env::var("POLICY_TYPE")
                .unwrap_or_else(|_| "allow_all".into())
                .into(),
        }
    }
}
```

## Running the Stdio Server

### Basic Execution

```bash
# Run directly
cargo run --release

# Redirect stderr for logging
cargo run --release 2>> /var/log/forensic-mcp.log

# With environment variables
AUDIT_ENABLED=true POLICY_TYPE=rbac cargo run --release
```

### Input/Output

The stdio server:
- **Reads** JSON-RPC 2.0 requests from stdin (one per line)
- **Writes** JSON-RPC 2.0 responses to stdout
- **Writes** diagnostics to stderr (does not pollute JSON channel)

### Process Management

For production, use a process supervisor:

```bash
# systemd service example (forensic-mcp.service)
[Unit]
Description=ForensicRS MCP Server
After=network.target

[Service]
Type=simple
User=forensic
Group=forensic
Environment=AUDIT_ENABLED=true
ExecStart=/usr/local/bin/forensic-mcp-server
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

## Connecting to MCP Clients

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "forensic": {
      "command": "/path/to/forensic-mcp-server",
      "env": {
        "AUDIT_ENABLED": "true"
      }
    }
  }
}
```

### VS Code

Add to VS Code settings (JSON):

```json
{
  "mcp": {
    "servers": {
      "forensic": {
        "command": "/path/to/forensic-mcp-server"
      }
    }
  }
}
```

### Custom Client

```rust
use serde_json::json;

fn call_tool(server_path: &str, tool_name: &str, args: serde_json::Value) -> serde_json::Value {
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": args
        }
    });

    let output = std::process::Command::new(server_path)
        .arg(request.to_string())
        .output()
        .expect("Failed to execute server");

    serde_json::from_slice(&output.stdout).expect("Invalid JSON response")
}
```

## Performance Considerations

### Startup Time

```bash
# AOT compilation for faster startup (if supported)
cargo build --release

# Or use cargo-binstall for faster installation
```

### Memory Usage

For large evidence sources, limit concurrent operations:

```rust
pub struct ServerLimits {
    pub max_concurrent_tools: usize,
    pub max_memory_mb: usize,
    pub tool_timeout_secs: u64,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_concurrent_tools: 4,
            max_memory_mb: 1024,
            tool_timeout_secs: 300,  // 5 minutes
        }
    }
}
```

## Security Checklist

Before deploying:

- [ ] **Never expose `AllowAllPolicy`** to untrusted networks
- [ ] **Enable audit logging** for all access decisions
- [ ] **Use TLS** for HTTP/SSE transports (if used)
- [ ] **Run as dedicated user** with minimal privileges
- [ ] **Validate input schemas** - rely on `ValueSchema` validation
- [ ] **Implement timeouts** - prevent long-running tool DoS
- [ ] **Monitor resources** - track memory and CPU usage

## Packaging

### Windows

```powershell
# Build release
cargo build --release --target x86_64-pc-windows-msvc

# Create distribution
$dist = "forensic-mcp-server-0.1.0-x86_64-pc-windows-msvc"
New-Item -ItemType Directory -Path $dist
Copy-Item target/x86_64-pc-windows-msvc/release/forensic-mcp-server.exe $dist/
Copy-Item README.md $dist/
Compress-Archive -Path $dist -DestinationPath "$dist.zip"
```

### Linux

```bash
# Build release
cargo build --release --target x86_64-unknown-linux-gnu

# Create distribution
dist="forensic-mcp-server-0.1.0-x86_64-unknown-linux-gnu"
mkdir -p $dist
cp target/x86_64-unknown-linux-gnu/release/forensic-mcp-server $dist/
cp README.md $dist/
tar -czvf "$dist.tar.gz" $dist
```

## Troubleshooting Deployment

| Issue | Solution |
|-------|----------|
| Server won't start | Check stderr for errors |
| Client can't connect | Verify binary is executable |
| Tools not visible | Check AccessPolicy allows the principal |
| Slow response | Enable logging, check resource usage |
| Memory growth | Set process limits, check for leaks |

## Next Steps

- Review [Cookbook: Tools](../05_cookbook/tools.md) for additional tool patterns
- Review [Troubleshooting](../06_troubleshooting.md) for common issues
- See [examples/mcp_stdio_server.rs:680-731](../../examples/mcp_stdio_server.rs) for main function reference
