pub mod client;
pub mod hooks;
pub mod protocol;
pub mod providers;
pub mod server;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::err::ForensicResult;
use crate::field::Text;
use crate::utils::time::ForensicTimestamp;

// ============================================================================
// CancellationToken
// ============================================================================

/// Cooperative cancellation token for long-running bridge operations.
///
/// Thread-safe (`Clone + Send + Sync`). Providers check `is_cancelled()` during
/// iteration and return early.
#[derive(Debug, Clone)]
pub struct CancellationToken {
    flag: Arc<AtomicBool>,
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Signal cancellation. All clones of this token will observe it.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
    }

    /// Check if cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }
}

// ============================================================================
// BridgeValue
// ============================================================================

/// A recursive value type for bridge responses.
///
/// Serves as the common data model between forensic providers and UI consumers.
/// Richer than JSON: includes `Timestamp` and `Binary` as first-class types.
#[derive(Debug, Clone)]
pub enum BridgeValue {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    F64(f64),
    Text(Text),
    Timestamp(ForensicTimestamp),
    Binary(Vec<u8>),
    Array(Vec<BridgeValue>),
    Map(BTreeMap<Text, BridgeValue>),
}

impl From<crate::field::Field> for BridgeValue {
    fn from(field: crate::field::Field) -> Self {
        use crate::field::Field as F;
        match field {
            F::Null => BridgeValue::Null,
            F::Text(t) => BridgeValue::Text(t),
            F::Ip(ip) => BridgeValue::Text(Text::Owned(ip.to_string())),
            F::U64(v) => BridgeValue::U64(v),
            F::I64(v) => BridgeValue::I64(v),
            F::F64(v) => BridgeValue::F64(v),
            F::Date(ft) => BridgeValue::Timestamp(ft),
            F::Array(arr) => BridgeValue::Array(arr.into_iter().map(BridgeValue::Text).collect()),
        }
    }
}

impl From<crate::traits::registry::RegValue> for BridgeValue {
    fn from(rv: crate::traits::registry::RegValue) -> Self {
        use crate::traits::registry::RegValue as RV;
        match rv {
            RV::None => BridgeValue::Null,
            RV::SZ(s) | RV::ExpandSZ(s) | RV::Link(s) => BridgeValue::Text(Text::Owned(s)),
            RV::DWord(v) | RV::DWordBigEndian(v) => BridgeValue::U64(v as u64),
            RV::QWord(v) => BridgeValue::U64(v),
            RV::Binary(v)
            | RV::ResourceList(v)
            | RV::FullResourceDescriptor(v)
            | RV::ResourceRequirementsList(v) => BridgeValue::Binary(v),
            RV::Unknown { data, .. } => BridgeValue::Binary(data),
            RV::MultiSZ(v) => BridgeValue::Array(
                v.into_iter()
                    .map(|s| BridgeValue::Text(Text::Owned(s)))
                    .collect(),
            ),
        }
    }
}

#[cfg(feature = "serde")]
mod serde_impl {
    use super::*;
    use serde::ser::{Serialize, SerializeMap, Serializer};

    impl Serialize for BridgeValue {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            match self {
                BridgeValue::Null => serializer.serialize_none(),
                BridgeValue::Bool(v) => serializer.serialize_bool(*v),
                BridgeValue::I64(v) => serializer.serialize_i64(*v),
                BridgeValue::U64(v) => serializer.serialize_u64(*v),
                BridgeValue::F64(v) => serializer.serialize_f64(*v),
                BridgeValue::Text(t) => serializer.serialize_str(t.as_ref()),
                BridgeValue::Timestamp(ts) => serializer.serialize_str(&ts.to_string()),
                BridgeValue::Binary(data) => {
                    // Serialize as hex string
                    let hex: String = data.iter().map(|b| format!("{:02x}", b)).collect();
                    serializer.serialize_str(&hex)
                }
                BridgeValue::Array(arr) => arr.serialize(serializer),
                BridgeValue::Map(map) => {
                    let mut m = serializer.serialize_map(Some(map.len()))?;
                    for (k, v) in map {
                        m.serialize_entry(k.as_ref(), v)?;
                    }
                    m.end()
                }
            }
        }
    }
}

// ============================================================================
// DataOrigin
// ============================================================================

/// Provenance metadata for bridge responses.
///
/// Tracks which provider produced the data and the path within that provider.
///
/// Not related to [`crate::provenance::Provenance`] — that type tracks
/// evidentiary chain-of-custody (how bytes were acquired and recovered,
/// confidence, lineage); this one only records which bridge provider/path
/// served a UI value.
#[derive(Debug, Clone)]
pub struct DataOrigin {
    pub provider: Text,
    pub path: Text,
}

// ============================================================================
// NodeType / NodeEntry
// ============================================================================

/// The type of a node in the bridge tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    /// A node that can have children (registry key, directory, event channel).
    Container,
    /// A terminal node (registry value, file, event record).
    Leaf,
    /// A node generated by a provider hook (e.g., parsed shellbag data).
    Virtual,
}

/// An entry in a bridge tree listing.
#[derive(Debug, Clone)]
pub struct NodeEntry {
    pub name: Text,
    pub node_type: NodeType,
    pub description: Option<Text>,
}

// ============================================================================
// BridgeResponse
// ============================================================================

/// Response from the bridge server to the client.
#[derive(Debug)]
#[non_exhaustive]
pub enum BridgeResponse {
    Children {
        origin: DataOrigin,
        entries: Vec<NodeEntry>,
        total: u64,
        offset: u64,
    },
    Value {
        origin: DataOrigin,
        value: BridgeValue,
    },
    Metadata {
        origin: DataOrigin,
        metadata: BTreeMap<Text, BridgeValue>,
    },
    Providers(Vec<String>),
    Error {
        message: String,
    },
}

// ============================================================================
// ForensicProvider trait
// ============================================================================

/// Unified tree navigation over any forensic artifact domain.
///
/// Implementations wrap existing forensic-rs trait objects (`Registry`,
/// `FileSystem`, `EventLogReader`, `ForensicDb`) and expose them as a
/// navigable tree of `NodeEntry` children.
///
/// `Send` is required because providers live on the bridge worker thread.
pub trait ForensicProvider: Send {
    /// The display name of this provider (e.g., "Registry", "Filesystem").
    fn name(&self) -> &str;

    /// List children of a node, paginated.
    ///
    /// Returns `(entries, total_count)` where `total_count` is the total number
    /// of children (not just the returned page). Use `offset` and `limit` for pagination.
    fn children(
        &self,
        path: &str,
        offset: u64,
        limit: u64,
        cancel: &CancellationToken,
    ) -> ForensicResult<(Vec<NodeEntry>, u64)>;

    /// Read the value of a leaf node.
    fn read(&self, path: &str, cancel: &CancellationToken) -> ForensicResult<BridgeValue>;

    /// Get metadata about a node (type info, size, timestamps, etc.).
    fn metadata(
        &self,
        path: &str,
        cancel: &CancellationToken,
    ) -> ForensicResult<BTreeMap<Text, BridgeValue>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::providers::RegistryProvider;
    use crate::field::Field;
    use crate::traits::registry::RegValue;
    use crate::utils::testing::TestingRegistry;

    fn assert_send<T: Send>(_: T) {}

    #[test]
    fn registry_provider_is_sendable_to_bridge_worker() {
        let provider = RegistryProvider::new(std::sync::Arc::new(TestingRegistry::new()));
        assert_send(provider);
    }

    #[test]
    fn bridge_value_from_field() {
        let bv: BridgeValue = Field::U64(42).into();
        match bv {
            BridgeValue::U64(v) => assert_eq!(v, 42),
            _ => panic!("expected U64"),
        }

        let bv: BridgeValue = Field::Null.into();
        assert!(matches!(bv, BridgeValue::Null));
    }

    #[test]
    fn bridge_value_from_reg_value() {
        let bv: BridgeValue = RegValue::DWord(100).into();
        match bv {
            BridgeValue::U64(v) => assert_eq!(v, 100),
            _ => panic!("expected U64"),
        }

        let bv: BridgeValue = RegValue::SZ("hello".into()).into();
        match bv {
            BridgeValue::Text(t) => assert_eq!(t.as_ref(), "hello"),
            _ => panic!("expected Text"),
        }

        let bv: BridgeValue = RegValue::Binary(vec![0xDE, 0xAD]).into();
        match bv {
            BridgeValue::Binary(v) => assert_eq!(v, vec![0xDE, 0xAD]),
            _ => panic!("expected Binary"),
        }
    }

    #[test]
    fn cancellation_token_works() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
        let clone = token.clone();
        token.cancel();
        assert!(clone.is_cancelled());
    }
}
