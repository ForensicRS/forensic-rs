# Introduction to MCP and ForensicRS

## What is the Model Context Protocol?

The Model Context Protocol (MCP) is an open protocol that enables AI models to interact with external tools and data sources. It provides a standardized way for:

- **AI clients** to discover available tools and resources
- **AI servers** to expose capabilities to AI models
- **Structured communication** between clients and servers

MCP uses JSON-RPC 2.0 as its transport layer, typically over stdio or HTTP/SSE.

## Why Combine ForensicRS with MCP?

ForensicRS excels at artifact analysis but doesn't dictate how results are presented. MCP provides a standardized interface for AI clients (like Claude Desktop, Cursor, or VS Code) to consume forensic capabilities.

Benefits of the ForensicRS + MCP combination:

| Benefit | Description |
|---------|-------------|
| **AI-Assisted Analysis** | Let AI models query forensic data directly |
| **Standardized Interface** | Protocol-agnostic capability exposure |
| **Access Control** | Built-in policy enforcement per principal |
| **Progress Reporting** | Long operations surface to AI clients |
| **Cancellation Support** | AI can interrupt long-running operations |

## Architecture Overview

```
┌─────────────┐     JSON-RPC 2.0      ┌──────────────────┐
│   AI Client │◄──────────────────────►│  MCP Server      │
│  (Claude,   │     stdio or HTTP      │  (Your Server)   │
│   Cursor)   │                        │                  │
└─────────────┘                        └────────┬─────────┘
                                                │
                                     ┌──────────▼─────────┐
                                     │  ForensicRS Core   │
                                     │  - Tools           │
                                     │  - Resources       │
                                     │  - Access Control  │
                                     │  - Pipeline        │
                                     └──────────┬─────────┘
                                                │
                              ┌─────────────────┼─────────────────┐
                              ▼                 ▼                 ▼
                         ┌─────────┐      ┌─────────┐      ┌─────────┐
                         │ Registry│      │   VFS   │      │EventLogs│
                         │ Readers │      │         │      │         │
                         └─────────┘      └─────────┘      └─────────┘
```

## Design Principles

The ForensicRS MCP integration follows these principles:

### 1. Protocol-Neutral Core

The core `forensic-rs` crate deliberately contains **no** MCP, JSON-RPC, async runtime, or authentication. These are external concerns handled by your MCP server implementation.

### 2. Fail-Closed Security

A server-facing registry requires an explicit access policy. You must opt in to `AllowAllPolicy` only for trusted local deployments.

### 3. No Capability Disclosure

A caller can discover only the capabilities they are authorized to use. Denied and unknown identifiers produce the same public result.

### 4. Least-Privilege Evidence Access

Tools may only access parsers, analyzers, artifacts, sources, and paths explicitly granted to them.

### 5. Fresh Analysis State

Analyzer-backed tools create a new pipeline task per invocation. Stateful analyzer values are never shared across callers.

### 6. Lossless Forensic Data

Timestamps, bytes, signed/unsigned numbers, and ordered objects remain typed until the adapter serializes them.

## Core Concepts

### ForensicTool

A `ForensicTool` is the primary way to expose forensic operations via MCP. Each tool has:

- **Descriptor**: Metadata (ID, title, description, schemas)
- **Invocation**: Receives typed input and returns typed output
- **Context**: Access to progress reporting and cancellation

### CapabilityRegistry

The `CapabilityRegistry` holds all registered tools and resources. It requires an access policy to filter what's visible to each caller.

### ScopedCapabilityRegistry

Created per-request from an `AccessContext`, this provides a filtered view of capabilities based on the authenticated principal's permissions.

### AccessPolicy

The `AccessPolicy` trait evaluates whether a principal can perform an operation. Implementations range from simple `AllowAllPolicy` to complex role-based systems.

### ResourceProvider

`ResourceProvider` exposes navigable data trees (registry, filesystem, event logs) as resources that AI clients can browse and read.

## Comparison: ForensicBridge vs MCP

| Aspect | ForensicBridge | MCP |
|--------|---------------|-----|
| **Primary Use** | UI integration (VS Code, web) | AI client integration |
| **Transport | Synchronous channels | JSON-RPC 2.0 (stdio/HTTP) |
| **Protocol** | Custom bridge protocol | Standard MCP |
| **Audience** | Human operators | AI models |

ForensicBridge and MCP share the same underlying providers but serve different consumers.

## Next Steps

- Continue to [Architecture](./02_architecture.md) for a deeper dive into components
- Jump to [Quickstart](./03_quickstart.md) to build a minimal server in 5 minutes
- See [MCP Integration Design](../MCP_INTEGRATION.md) for the full technical specification
