//! Protocol-neutral contracts for exposing forensic-rs capabilities.
//!
//! This module deliberately does not depend on an MCP SDK, JSON-RPC transport,
//! or asynchronous runtime. External servers authenticate callers, construct an
//! [`access::AccessContext`], and use it to obtain a scoped capability view.

pub mod access;
pub mod bridge_adapter;
pub mod pipeline;
pub mod registry;
pub mod resources;
pub mod schema;
pub mod source_guards;
pub mod tools;
pub mod value;

pub use access::{
    AccessAuditEvent, AccessAuditSink, AccessContext, AccessDecision, AccessKind, AccessPolicy,
    AccessRequest, AllowAllPolicy, AuditedAccessPolicy, DenyAllPolicy,
};
pub use bridge_adapter::BridgeResourceProvider;
pub use pipeline::{
    AccessRequirements, AuthorizedPipelineContext, AuthorizedSourceFactory, PipelineSourceKind,
    PipelineTaskFactory, PipelineTaskTool,
};
pub use registry::{CapabilityRegistry, ScopedCapabilityRegistry};
pub use resources::{
    Page, PageRequest, ResourceContent, ResourceEntry, ResourceId, ResourceKind, ResourceMetadata,
    ResourceProvider, ResourceProviderDescriptor,
};
pub use schema::{ObjectSchema, ValueSchema, ValueType};
pub use source_guards::{
    AuthorizedEventLogReader, AuthorizedForensicDb, AuthorizedRegistryReader,
    AuthorizedVirtualFileSystem,
};
pub use tools::{
    CapabilityError, CapabilityErrorKind, CapabilityResult, ForensicTool, InvocationContext,
    NoopProgressReporter, ProgressReporter, ProgressUpdate, ToolContent, ToolDescriptor, ToolHints,
    ToolResult,
};
pub use value::CapabilityValue;
