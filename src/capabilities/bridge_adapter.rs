//! Compatibility adapter for legacy bridge providers.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::bridge::{BridgeValue, CancellationToken, ForensicProvider, NodeType};
use crate::field::Text;

use super::{
    CapabilityError, CapabilityErrorKind, CapabilityResult, CapabilityValue, ResourceContent,
    ResourceEntry, ResourceId, ResourceKind, ResourceMetadata, ResourceProvider,
    ResourceProviderDescriptor,
};

/// Exposes a legacy bridge provider through the protocol-neutral resource API.
///
/// The adapter preserves legacy providers while callers migrate to native
/// [`ResourceProvider`] implementations. It requests an unpaged child list;
/// [`super::ScopedCapabilityRegistry`] filters and paginates it only after
/// applying caller-specific policy.
pub struct BridgeResourceProvider {
    inner: Mutex<Box<dyn ForensicProvider>>,
    descriptor: ResourceProviderDescriptor,
}

impl BridgeResourceProvider {
    pub fn new(
        descriptor: ResourceProviderDescriptor,
        provider: Box<dyn ForensicProvider>,
    ) -> Self {
        Self {
            inner: Mutex::new(provider),
            descriptor,
        }
    }
}

impl ResourceProvider for BridgeResourceProvider {
    fn descriptor(&self) -> &ResourceProviderDescriptor {
        &self.descriptor
    }

    fn children(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<Vec<ResourceEntry>> {
        ensure_not_cancelled(cancellation)?;
        let provider = self.inner.lock().map_err(|_| bridge_operation_error())?;
        let (entries, _) = provider
            .children(path, 0, u64::MAX, cancellation)
            .map_err(|_| bridge_operation_error())?;
        ensure_not_cancelled(cancellation)?;
        Ok(entries
            .into_iter()
            .map(|entry| ResourceEntry {
                id: ResourceId::new(
                    self.descriptor.id.clone(),
                    child_path(path, entry.name.as_ref()),
                ),
                name: entry.name.into_owned(),
                kind: match entry.node_type {
                    NodeType::Container => ResourceKind::Container,
                    NodeType::Leaf => ResourceKind::Leaf,
                    NodeType::Virtual => ResourceKind::Virtual,
                },
                description: entry.description.map(Text::into_owned),
            })
            .collect())
    }

    fn read(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<ResourceContent> {
        ensure_not_cancelled(cancellation)?;
        let provider = self.inner.lock().map_err(|_| bridge_operation_error())?;
        let value = provider
            .read(path, cancellation)
            .map_err(|_| bridge_operation_error())?;
        ensure_not_cancelled(cancellation)?;
        Ok(ResourceContent::Structured {
            value: bridge_value(value),
            media_type: Some("application/vnd.forensic-rs.bridge-value".to_string()),
        })
    }

    fn metadata(
        &self,
        path: &str,
        cancellation: &CancellationToken,
    ) -> CapabilityResult<ResourceMetadata> {
        ensure_not_cancelled(cancellation)?;
        let provider = self.inner.lock().map_err(|_| bridge_operation_error())?;
        let metadata = provider
            .metadata(path, cancellation)
            .map_err(|_| bridge_operation_error())?;
        ensure_not_cancelled(cancellation)?;
        let size = metadata.get("size").and_then(|value| match value {
            BridgeValue::U64(size) => Some(*size),
            _ => None,
        });
        let values = metadata
            .into_iter()
            .map(|(name, value)| (name, bridge_value(value)))
            .collect();
        Ok(ResourceMetadata {
            media_type: None,
            size,
            values,
        })
    }
}

fn ensure_not_cancelled(cancellation: &CancellationToken) -> CapabilityResult<()> {
    if cancellation.is_cancelled() {
        return Err(CapabilityError::new(
            CapabilityErrorKind::Cancelled,
            "operation cancelled",
        ));
    }
    Ok(())
}

fn bridge_operation_error() -> CapabilityError {
    CapabilityError::new(
        CapabilityErrorKind::Internal,
        "legacy bridge resource operation failed",
    )
}

fn child_path(parent: &str, child: &str) -> String {
    if parent.is_empty()
        || child == parent
        || child.starts_with(&format!("{parent}/"))
        || child.starts_with(&format!("{parent}\\"))
    {
        return child.to_string();
    }
    let separator = if parent.contains('\\') { "\\" } else { "/" };
    format!("{parent}{separator}{child}")
}

fn bridge_value(value: BridgeValue) -> CapabilityValue {
    match value {
        BridgeValue::Null => CapabilityValue::Null,
        BridgeValue::Bool(value) => CapabilityValue::Bool(value),
        BridgeValue::I64(value) => CapabilityValue::I64(value),
        BridgeValue::U64(value) => CapabilityValue::U64(value),
        BridgeValue::F64(value) => CapabilityValue::F64(value),
        BridgeValue::Text(value) => CapabilityValue::Text(value),
        BridgeValue::Timestamp(value) => CapabilityValue::Timestamp(value),
        BridgeValue::Binary(value) => CapabilityValue::Bytes(value),
        BridgeValue::Array(values) => {
            CapabilityValue::Array(values.into_iter().map(bridge_value).collect())
        }
        BridgeValue::Map(values) => CapabilityValue::Object(
            values
                .into_iter()
                .map(|(name, value)| (name, bridge_value(value)))
                .collect::<BTreeMap<_, _>>(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{err::ForensicResult, field::Text};

    struct TestBridgeProvider;

    impl ForensicProvider for TestBridgeProvider {
        fn name(&self) -> &str {
            "Test bridge"
        }

        fn children(
            &self,
            path: &str,
            _offset: u64,
            _limit: u64,
            _cancellation: &CancellationToken,
        ) -> ForensicResult<(Vec<crate::bridge::NodeEntry>, u64)> {
            assert_eq!(path, "events");
            Ok((
                vec![crate::bridge::NodeEntry {
                    name: Text::Borrowed("42:1000"),
                    node_type: NodeType::Leaf,
                    description: Some(Text::Borrowed("record")),
                }],
                1,
            ))
        }

        fn read(
            &self,
            _path: &str,
            _cancellation: &CancellationToken,
        ) -> ForensicResult<BridgeValue> {
            Ok(BridgeValue::Binary(vec![0, 1]))
        }

        fn metadata(
            &self,
            _path: &str,
            _cancellation: &CancellationToken,
        ) -> ForensicResult<BTreeMap<Text, BridgeValue>> {
            Ok(BTreeMap::from([(
                Text::Borrowed("size"),
                BridgeValue::U64(2),
            )]))
        }
    }

    fn adapter() -> BridgeResourceProvider {
        BridgeResourceProvider::new(
            ResourceProviderDescriptor {
                id: "events".to_string(),
                title: "Events".to_string(),
                description: "Test events".to_string(),
            },
            Box::new(TestBridgeProvider),
        )
    }

    #[test]
    fn adapter_converts_legacy_bridge_data_without_losing_types() {
        let provider = adapter();
        let cancellation = CancellationToken::new();
        let entries = provider.children("events", &cancellation).unwrap();
        assert_eq!(entries[0].id.path, "events/42:1000");
        assert_eq!(entries[0].kind, ResourceKind::Leaf);
        assert_eq!(entries[0].description.as_deref(), Some("record"));

        assert_eq!(
            provider.read("events/42:1000", &cancellation).unwrap(),
            ResourceContent::Structured {
                value: CapabilityValue::Bytes(vec![0, 1]),
                media_type: Some("application/vnd.forensic-rs.bridge-value".to_string()),
            }
        );
        assert_eq!(
            provider
                .metadata("events/42:1000", &cancellation)
                .unwrap()
                .size,
            Some(2)
        );
    }
}
