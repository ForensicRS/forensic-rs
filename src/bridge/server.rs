use std::collections::HashMap;
use std::sync::mpsc::{Receiver, SyncSender};
use std::thread;

use crate::field::Text;

use super::client::BridgeClient;
use super::protocol::BridgeRequest;
use super::{BridgeResponse, DataOrigin, ForensicProvider};

// ============================================================================
// ForensicBridge
// ============================================================================

type RequestChannel = (BridgeRequest, SyncSender<BridgeResponse>);

/// A multi-provider forensic data bridge.
///
/// Runs a dedicated worker thread that owns all registered `ForensicProvider`s.
/// Callers interact through a `BridgeClient` handle which can be cloned freely
/// across threads.
///
/// # Example
///
/// ```rust,ignore
/// use forensic_rs::bridge::server::ForensicBridgeBuilder;
/// use forensic_rs::bridge::providers::RegistryProvider;
///
/// let client = ForensicBridgeBuilder::new()
///     .add_provider(RegistryProvider::new(my_registry))
///     .spawn();
///
/// let providers = client.list_providers().unwrap();
/// let children = client.children("Registry", "").unwrap();
/// ```
pub struct ForensicBridge {
    providers: Vec<Box<dyn ForensicProvider>>,
    rx: Receiver<RequestChannel>,
}

impl ForensicBridge {
    fn run(self) {
        // Build a fast name→index lookup
        let mut name_map: HashMap<String, usize> = HashMap::new();
        for (i, p) in self.providers.iter().enumerate() {
            name_map.insert(p.name().to_string(), i);
        }

        loop {
            let (req, resp_tx) = match self.rx.recv() {
                Ok(pair) => pair,
                Err(_) => break, // All clients dropped — shut down
            };

            let response = match req {
                BridgeRequest::Shutdown => {
                    // Acknowledge and exit the loop
                    let _ = resp_tx.send(BridgeResponse::Providers(vec![]));
                    break;
                }

                BridgeRequest::ListProviders => {
                    let names: Vec<String> =
                        self.providers.iter().map(|p| p.name().to_string()).collect();
                    BridgeResponse::Providers(names)
                }

                BridgeRequest::Children { provider, path, offset, limit, cancel } => {
                    match name_map.get(&provider) {
                        None => BridgeResponse::Error {
                            message: format!("provider '{}' not found", provider),
                        },
                        Some(&idx) => match self.providers[idx].children(&path, offset, limit, &cancel) {
                            Ok((entries, total)) => BridgeResponse::Children {
                                origin: DataOrigin {
                                    provider: Text::Owned(provider),
                                    path: Text::Owned(path),
                                },
                                entries,
                                total,
                                offset,
                            },
                            Err(e) => BridgeResponse::Error {
                                message: e.to_string(),
                            },
                        },
                    }
                }

                BridgeRequest::Read { provider, path, cancel } => {
                    match name_map.get(&provider) {
                        None => BridgeResponse::Error {
                            message: format!("provider '{}' not found", provider),
                        },
                        Some(&idx) => match self.providers[idx].read(&path, &cancel) {
                            Ok(value) => BridgeResponse::Value {
                                origin: DataOrigin {
                                    provider: Text::Owned(provider),
                                    path: Text::Owned(path),
                                },
                                value,
                            },
                            Err(e) => BridgeResponse::Error {
                                message: e.to_string(),
                            },
                        },
                    }
                }

                BridgeRequest::Metadata { provider, path, cancel } => {
                    match name_map.get(&provider) {
                        None => BridgeResponse::Error {
                            message: format!("provider '{}' not found", provider),
                        },
                        Some(&idx) => match self.providers[idx].metadata(&path, &cancel) {
                            Ok(metadata) => BridgeResponse::Metadata {
                                origin: DataOrigin {
                                    provider: Text::Owned(provider),
                                    path: Text::Owned(path),
                                },
                                metadata,
                            },
                            Err(e) => BridgeResponse::Error {
                                message: e.to_string(),
                            },
                        },
                    }
                }
            };

            // Best-effort send — client may have timed out
            let _ = resp_tx.send(response);
        }
    }
}

// ============================================================================
// ForensicBridgeBuilder
// ============================================================================

/// Builder for `ForensicBridge`.
///
/// Add providers then call `spawn()` to start the bridge worker and get a `BridgeClient`.
pub struct ForensicBridgeBuilder {
    providers: Vec<Box<dyn ForensicProvider>>,
    channel_capacity: usize,
}

impl Default for ForensicBridgeBuilder {
    fn default() -> Self {
        Self {
            providers: Vec::new(),
            channel_capacity: 64,
        }
    }
}

impl ForensicBridgeBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a provider with the bridge.
    pub fn add_provider(mut self, provider: impl ForensicProvider + 'static) -> Self {
        self.providers.push(Box::new(provider));
        self
    }

    /// Register a boxed provider.
    pub fn add_boxed_provider(mut self, provider: Box<dyn ForensicProvider>) -> Self {
        self.providers.push(provider);
        self
    }

    /// Set the request channel capacity (default: 64).
    pub fn channel_capacity(mut self, cap: usize) -> Self {
        self.channel_capacity = cap;
        self
    }

    /// Spawn the bridge worker thread and return a `BridgeClient`.
    pub fn spawn(self) -> BridgeClient {
        let (tx, rx) = std::sync::mpsc::channel::<RequestChannel>();

        let bridge = ForensicBridge {
            providers: self.providers,
            rx,
        };

        thread::Builder::new()
            .name("forensic-bridge".to_string())
            .spawn(move || bridge.run())
            .expect("failed to spawn forensic bridge worker thread");

        BridgeClient::new(tx)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::bridge::{BridgeValue, CancellationToken, NodeEntry, NodeType};
    use crate::err::ForensicResult;
    use crate::field::Text;

    use super::*;

    // Minimal in-memory provider for testing
    struct StaticProvider {
        name: String,
        children_map: BTreeMap<String, Vec<(String, NodeType)>>,
        values: BTreeMap<String, BridgeValue>,
    }

    impl StaticProvider {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                children_map: BTreeMap::new(),
                values: BTreeMap::new(),
            }
        }

        fn with_children(mut self, path: &str, entries: Vec<(&str, NodeType)>) -> Self {
            self.children_map.insert(
                path.to_string(),
                entries.into_iter().map(|(n, t)| (n.to_string(), t)).collect(),
            );
            self
        }

        fn with_value(mut self, path: &str, value: BridgeValue) -> Self {
            self.values.insert(path.to_string(), value);
            self
        }
    }

    impl ForensicProvider for StaticProvider {
        fn name(&self) -> &str {
            &self.name
        }

        fn children(
            &self,
            path: &str,
            offset: u64,
            limit: u64,
            _cancel: &CancellationToken,
        ) -> ForensicResult<(Vec<NodeEntry>, u64)> {
            let all = self.children_map.get(path).map(|v| v.as_slice()).unwrap_or(&[]);
            let total = all.len() as u64;
            let entries: Vec<NodeEntry> = all
                .iter()
                .skip(offset as usize)
                .take(limit as usize)
                .map(|(n, t)| NodeEntry {
                    name: Text::Owned(n.clone()),
                    node_type: *t,
                    description: None,
                })
                .collect();
            Ok((entries, total))
        }

        fn read(&self, path: &str, _cancel: &CancellationToken) -> ForensicResult<BridgeValue> {
            self.values
                .get(path)
                .cloned()
                .ok_or_else(|| crate::err::ForensicError::other("StaticProvider", format!("not found: {}", path)))
        }

        fn metadata(
            &self,
            _path: &str,
            _cancel: &CancellationToken,
        ) -> ForensicResult<BTreeMap<Text, BridgeValue>> {
            Ok(BTreeMap::new())
        }
    }

    #[test]
    fn bridge_list_providers() {
        let client = ForensicBridgeBuilder::new()
            .add_provider(StaticProvider::new("Alpha"))
            .add_provider(StaticProvider::new("Beta"))
            .spawn();

        let providers = client.list_providers().unwrap();
        assert_eq!(providers, vec!["Alpha", "Beta"]);
        client.shutdown().unwrap();
    }

    #[test]
    fn bridge_children_and_read() {
        let provider = StaticProvider::new("Test")
            .with_children(
                "",
                vec![("root_key", NodeType::Container)],
            )
            .with_value("root_key/value", BridgeValue::U64(99));

        let client = ForensicBridgeBuilder::new()
            .add_provider(provider)
            .spawn();

        let resp = client.children("Test", "").unwrap();
        match resp {
            BridgeResponse::Children { entries, total, .. } => {
                assert_eq!(total, 1);
                assert_eq!(entries[0].name.as_ref(), "root_key");
            }
            _ => panic!("unexpected response"),
        }

        let resp = client.read("Test", "root_key/value").unwrap();
        match resp {
            BridgeResponse::Value { value, .. } => {
                assert!(matches!(value, BridgeValue::U64(99)));
            }
            _ => panic!("unexpected response"),
        }

        client.shutdown().unwrap();
    }

    #[test]
    fn bridge_unknown_provider_returns_error() {
        let client = ForensicBridgeBuilder::new()
            .add_provider(StaticProvider::new("Registry"))
            .spawn();

        let resp = client.children("NoSuchProvider", "").unwrap();
        assert!(matches!(resp, BridgeResponse::Error { .. }));
        client.shutdown().unwrap();
    }
}
