use super::CancellationToken;

// ============================================================================
// BridgeRequest
// ============================================================================

/// Requests sent from `BridgeClient` to the `ForensicBridge` worker thread.
///
/// All requests except `Shutdown` carry a `CancellationToken` so that callers
/// can abort long-running operations.
#[non_exhaustive]
#[derive(Debug)]
pub enum BridgeRequest {
    /// List the names of all registered providers.
    ListProviders,

    /// List the children of a node in a provider's tree, paginated.
    ///
    /// `offset` and `limit` control pagination. A `limit` of `u64::MAX` returns
    /// all children from `offset` onwards (use with caution on large trees).
    Children {
        provider: String,
        path: String,
        offset: u64,
        limit: u64,
        cancel: CancellationToken,
    },

    /// Read the value of a leaf node.
    Read {
        provider: String,
        path: String,
        cancel: CancellationToken,
    },

    /// Get metadata about a node.
    Metadata {
        provider: String,
        path: String,
        cancel: CancellationToken,
    },

    /// List command/tool IDs applicable to a node.
    Actions {
        provider: String,
        path: String,
        cancel: CancellationToken,
    },

    /// Shut down the bridge worker thread.
    Shutdown,
}
