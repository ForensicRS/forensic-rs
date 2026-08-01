use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::time::Duration;

use crate::err::{ForensicError, ForensicResult};

use super::protocol::BridgeRequest;
use super::{BridgeResponse, CancellationToken};

// ============================================================================
// BridgeClient
// ============================================================================

/// Thread-safe handle to the `ForensicBridge` worker.
///
/// Each clone owns an independent `Sender`, so multiple UI threads can issue
/// concurrent requests without coordination.
///
/// # Non-blocking variant
///
/// Methods like `children_cancellable` return `(CancellationToken, Receiver<...>)`
/// immediately. The caller can cancel the operation before the response arrives.
#[derive(Clone)]
pub struct BridgeClient {
    tx: std::sync::mpsc::Sender<(BridgeRequest, SyncSender<BridgeResponse>)>,
}

impl BridgeClient {
    pub(crate) fn new(
        tx: std::sync::mpsc::Sender<(BridgeRequest, SyncSender<BridgeResponse>)>,
    ) -> Self {
        Self { tx }
    }

    // ------------------------------------------------------------------ raw

    /// Send a request and block until a response arrives.
    pub fn request(&self, req: BridgeRequest) -> ForensicResult<BridgeResponse> {
        let (resp_tx, resp_rx) = sync_channel(1);
        self.tx.send((req, resp_tx)).map_err(|_| {
            ForensicError::other(
                "BridgeClient",
                "bridge worker is no longer running".to_string(),
            )
        })?;
        resp_rx.recv().map_err(|_| {
            ForensicError::other(
                "BridgeClient",
                "bridge worker dropped the response channel".to_string(),
            )
        })
    }

    /// Send a request and block up to `timeout` for a response.
    pub fn request_timeout(
        &self,
        req: BridgeRequest,
        timeout: Duration,
    ) -> ForensicResult<BridgeResponse> {
        let (resp_tx, resp_rx) = sync_channel(1);
        self.tx.send((req, resp_tx)).map_err(|_| {
            ForensicError::other(
                "BridgeClient",
                "bridge worker is no longer running".to_string(),
            )
        })?;
        resp_rx
            .recv_timeout(timeout)
            .map_err(|e| ForensicError::other("BridgeClient", format!("response timeout: {}", e)))
    }

    // ------------------------------------------------------------------ convenience: providers

    /// List the names of all registered providers.
    pub fn list_providers(&self) -> ForensicResult<Vec<String>> {
        match self.request(BridgeRequest::ListProviders)? {
            BridgeResponse::Providers(names) => Ok(names),
            BridgeResponse::Error { message } => Err(ForensicError::other("BridgeClient", message)),
            _ => Err(ForensicError::other(
                "BridgeClient",
                "unexpected response type".to_string(),
            )),
        }
    }

    // ------------------------------------------------------------------ convenience: children

    /// List children of a node (first page, limit = 100).
    pub fn children(&self, provider: &str, path: &str) -> ForensicResult<BridgeResponse> {
        self.children_page(provider, path, 0, 100)
    }

    /// List children of a node with explicit pagination.
    pub fn children_page(
        &self,
        provider: &str,
        path: &str,
        offset: u64,
        limit: u64,
    ) -> ForensicResult<BridgeResponse> {
        self.request(BridgeRequest::Children {
            provider: provider.to_string(),
            path: path.to_string(),
            offset,
            limit,
            cancel: CancellationToken::new(),
        })
    }

    /// Non-blocking children request.
    ///
    /// Returns `(token, receiver)` immediately. Call `token.cancel()` to abort.
    /// Receive on `receiver` when ready.
    pub fn children_cancellable(
        &self,
        provider: &str,
        path: &str,
        offset: u64,
        limit: u64,
    ) -> ForensicResult<(CancellationToken, Receiver<BridgeResponse>)> {
        let cancel = CancellationToken::new();
        let (resp_tx, resp_rx) = sync_channel(1);
        self.tx
            .send((
                BridgeRequest::Children {
                    provider: provider.to_string(),
                    path: path.to_string(),
                    offset,
                    limit,
                    cancel: cancel.clone(),
                },
                resp_tx,
            ))
            .map_err(|_| {
                ForensicError::other(
                    "BridgeClient",
                    "bridge worker is no longer running".to_string(),
                )
            })?;
        Ok((cancel, resp_rx))
    }

    // ------------------------------------------------------------------ convenience: read / metadata

    /// Read the value of a leaf node.
    pub fn read(&self, provider: &str, path: &str) -> ForensicResult<BridgeResponse> {
        self.request(BridgeRequest::Read {
            provider: provider.to_string(),
            path: path.to_string(),
            cancel: CancellationToken::new(),
        })
    }

    /// Get metadata about a node.
    pub fn metadata(&self, provider: &str, path: &str) -> ForensicResult<BridgeResponse> {
        self.request(BridgeRequest::Metadata {
            provider: provider.to_string(),
            path: path.to_string(),
            cancel: CancellationToken::new(),
        })
    }

    // ------------------------------------------------------------------ shutdown

    /// Request the bridge worker to shut down. Subsequent requests will error.
    pub fn shutdown(&self) -> ForensicResult<()> {
        let (resp_tx, _) = sync_channel(1);
        self.tx
            .send((BridgeRequest::Shutdown, resp_tx))
            .map_err(|_| {
                ForensicError::other("BridgeClient", "bridge worker already stopped".to_string())
            })
    }
}
