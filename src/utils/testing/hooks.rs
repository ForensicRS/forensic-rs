use std::collections::BTreeMap;

use crate::bridge::hooks::ProviderHook;
use crate::bridge::{BridgeValue, NodeEntry};
use crate::err::{ForensicError, ForensicResult};

/// Parameterized, public mock of [`ProviderHook`] for bridge-layer testing.
///
/// By default matches every path and value, has no children, and no reads —
/// configure it with the builder methods for the specific matching/content
/// behavior a test needs.
type PathPredicate = Box<dyn Fn(&str) -> bool + Send + Sync>;
type ValuePredicate = Box<dyn Fn(&str, &BridgeValue) -> bool + Send + Sync>;

pub struct TestingProviderHook {
    name: String,
    path_predicate: PathPredicate,
    value_predicate: ValuePredicate,
    children: Vec<NodeEntry>,
    reads: BTreeMap<String, BridgeValue>,
}

impl TestingProviderHook {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            path_predicate: Box::new(|_| true),
            value_predicate: Box::new(|_, _| true),
            children: Vec::new(),
            reads: BTreeMap::new(),
        }
    }

    pub fn matching_path(mut self, predicate: impl Fn(&str) -> bool + Send + Sync + 'static) -> Self {
        self.path_predicate = Box::new(predicate);
        self
    }

    pub fn matching_value(
        mut self,
        predicate: impl Fn(&str, &BridgeValue) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.value_predicate = Box::new(predicate);
        self
    }

    pub fn with_child(mut self, entry: NodeEntry) -> Self {
        self.children.push(entry);
        self
    }

    pub fn with_read(mut self, virtual_child: impl Into<String>, value: BridgeValue) -> Self {
        self.reads.insert(virtual_child.into(), value);
        self
    }
}

impl ProviderHook for TestingProviderHook {
    fn name(&self) -> &str {
        &self.name
    }

    fn matches_path(&self, path: &str) -> bool {
        (self.path_predicate)(path)
    }

    fn matches_value(&self, path: &str, value: &BridgeValue) -> bool {
        (self.value_predicate)(path, value)
    }

    fn virtual_children(
        &self,
        _parent_path: &str,
        _parent_value: &BridgeValue,
        offset: u64,
        limit: u64,
    ) -> ForensicResult<(Vec<NodeEntry>, u64)> {
        let total = self.children.len() as u64;
        let page = self
            .children
            .iter()
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect();
        Ok((page, total))
    }

    fn read_virtual(&self, _parent_path: &str, virtual_child: &str) -> ForensicResult<BridgeValue> {
        self.reads.get(virtual_child).cloned().ok_or_else(|| {
            ForensicError::missing_data(
                "virtual_child",
                format!("no read configured for '{virtual_child}'").into(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::NodeType;
    use crate::field::Text;

    #[test]
    fn default_matches_everything() {
        let hook = TestingProviderHook::new("test");
        assert!(hook.matches_path("anything"));
        assert!(hook.matches_value("anything", &BridgeValue::Null));
    }

    #[test]
    fn matching_path_and_value_can_be_narrowed() {
        let hook = TestingProviderHook::new("shellbag")
            .matching_path(|p| p.contains("BagMRU"))
            .matching_value(|_, v| matches!(v, BridgeValue::Binary(_)));
        assert!(hook.matches_path("HKCU\\BagMRU\\0"));
        assert!(!hook.matches_path("HKCU\\Other"));
        assert!(hook.matches_value("x", &BridgeValue::Binary(vec![1])));
        assert!(!hook.matches_value("x", &BridgeValue::Null));
    }

    #[test]
    fn configured_children_and_reads_are_served() {
        let hook = TestingProviderHook::new("shellbag")
            .with_child(NodeEntry {
                name: Text::Borrowed("Desktop"),
                node_type: NodeType::Leaf,
                description: None,
            })
            .with_read("Desktop", BridgeValue::Text(Text::Borrowed("C:\\Desktop")));

        let (entries, total) = hook
            .virtual_children("parent", &BridgeValue::Null, 0, 10)
            .unwrap();
        assert_eq!(total, 1);
        assert_eq!(entries.len(), 1);

        let value = hook.read_virtual("parent", "Desktop").unwrap();
        assert!(matches!(value, BridgeValue::Text(_)));
        assert!(hook.read_virtual("parent", "missing").is_err());
    }
}
