# ForensicRS MCP Server Developer Guide

Welcome to the ForensicRS MCP Server Developer Guide. This documentation teaches you how to build your own MCP (Model Context Protocol) server that exposes forensic capabilities for AI-assisted incident response.

## What You Will Learn

After completing this guide, you will be able to:

- Understand the Model Context Protocol and its relationship to ForensicRS
- Design and implement custom `ForensicTool` implementations
- Expose forensic data as `ResourceProvider` endpoints
- Implement access control policies for multi-tenant deployments
- Build a complete MCP stdio server for forensic case analysis

## Prerequisites

- **Rust 1.75+** - Required for async trait support
- **Basic forensic knowledge** - Understanding of Windows artifacts (registry, event logs, filesystem)
- **Familiarity with Rust traits and iterators** - The framework uses trait-based abstractions extensively

## Learning Path

We recommend following this guide in order:

1. **[Introduction](./01_introduction.md)** - Understand MCP and why ForensicRS+MCP
2. **[Architecture](./02_architecture.md)** - Learn the component architecture
3. **[Quickstart](./03_quickstart.md)** - Get a minimal server running in 5 minutes
4. **Tutorial** - Step-by-step implementation:
   - [Project Setup](./04_tutorial/01_project_setup.md)
   - [Your First Tool](./04_tutorial/02_first_tool.md)
   - [Registry Tools](./04_tutorial/03_registry_tools.md)
   - [VFS Tools](./04_tutorial/04_vfs_tools.md)
   - [Event Log Tools](./04_tutorial/05_eventlog_tools.md)
   - [Resources](./04_tutorial/06_resources.md)
   - [Access Control](./04_tutorial/07_access_control.md)
   - [Deployment](./04_tutorial/08_deployment.md)
5. **[Cookbook](./05_cookbook/tools.md)** - Reusable patterns and recipes
6. **[Troubleshooting](./06_troubleshooting.md)** - FAQ and common issues
7. **[Capability Coverage & Roadmap](./07_capability_coverage.md)** - What's implemented, what's built but not wired up, and what's still missing (resources, prompts, sampling, roots, and more)

## Scenario: Incident Response Case Analysis

Throughout this guide, we build an MCP server for analyzing a triage collection from a potentially compromised Windows workstation (`WORKSTATION01`).

Our server exposes four forensic tools:

| Tool | Purpose |
|------|---------|
| `case.summary` | Returns case metadata and finding counts |
| `registry.autoruns` | Queries Run/RunOnce keys for persistence mechanisms |
| `prefetch.analyze` | Analyzes Prefetch files for program execution history |
| `security.logon_events` | Queries Security event logs for logon anomalies |

## Quick Links

- [ForensicRS Main Documentation](../README.md)
- [Existing Examples](../examples/mcp_stdio_server.rs)
- [Capability Coverage & Roadmap](./07_capability_coverage.md)
- [ForensicRS crates.io](https://crates.io/crates/forensic-rs)

## Getting Help

If you encounter issues:

1. Check the [Troubleshooting guide](./06_troubleshooting.md)
2. Search existing [GitHub Issues](https://github.com/ForensicRS/forensic-rs/issues)
3. Join the [Discord community](https://discord.gg/uVq4289B)
