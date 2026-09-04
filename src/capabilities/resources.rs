//! Protocol-neutral forensic resource contracts.

use std::collections::BTreeMap;

use crate::{bridge::CancellationToken, field::Text};

use super::{tools::CapabilityResult, value::CapabilityValue};

/// Stable identity for a resource within a registered provider.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResourceId {
    pub provider: String,
    pub path: String,
}

impl ResourceId {
    pub fn new(provider: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            path: path.into(),
        }
    }
}

/// Public metadata describing a resource provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceProviderDescriptor {
    /// Stable ID used by registry lookup and external adapters.
    pub id: String,
    /// Human-readable title for an authorized client.
    pub title: String,
    /// Human-readable provider description.
    pub description: String,
}

/// Resource shape exposed by a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    Container,
    Leaf,
    Virtual,
}

/// A discoverable resource node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceEntry {
    pub id: ResourceId,
    pub name: String,
    pub kind: ResourceKind,
    pub description: Option<String>,
}

/// Optional resource attributes supplied by a provider.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ResourceMetadata {
    pub media_type: Option<String>,
    pub size: Option<u64>,
    pub values: BTreeMap<Text, CapabilityValue>,
}

/// Resource payload returned by a provider.
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceContent {
    Text {
        text: String,
        media_type: Option<String>,
    },
    Bytes {
        data: Vec<u8>,
        media_type: Option<String>,
    },
    Structured {
        value: CapabilityValue,
        media_type: Option<String>,
    },
}

/// A page request expressed as core offsets instead of external cursors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRequest {
    pub offset: u64,
    pub limit: u64,
}

impl PageRequest {
    pub fn new(offset: u64, limit: u64) -> Self {
        Self { offset, limit }
    }
}

/// A filtered page returned by a scoped registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    pub entries: Vec<T>,
    pub total: u64,
    pub offset: u64,
    pub next_offset: Option<u64>,
}

/// A hierarchical, read-only forensic resource provider.
///
/// Providers return all children for a requested path. The scoped registry
/// applies authorization filtering before pagination so hidden entries never
/// influence public totals or cursors. Provider implementations must check the
/// supplied cancellation token while traversing expensive source data.
pub trait ResourceProvider: Send + Sync {
    fn descriptor(&self) -> &ResourceProviderDescriptor;

    fn children(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<Vec<ResourceEntry>>;

    fn read(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<ResourceContent>;

    fn metadata(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<ResourceMetadata>;

    /// List command/tool IDs applicable to this node. Default: none.
    ///
    /// This is a *discovery* link to already-registered [`super::ForensicTool`]
    /// IDs, surfaced to callers via `ScopedCapabilityRegistry::list_node_actions`
    /// — it does not invoke anything itself.
    #[allow(unused_variables)]
    fn actions(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<Vec<String>> {
        Ok(Vec::new())
    }
}
