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
    children: BTreeMap<String, Vec<NodeEntry>>,
    reads: BTreeMap<String, BridgeValue>,
    actions: Vec<String>,
    virtual_actions: BTreeMap<String, Vec<String>>,
}

impl TestingProviderHook {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            path_predicate: Box::new(|_| true),
            value_predicate: Box::new(|_, _| true),
            children: BTreeMap::new(),
            reads: BTreeMap::new(),
            actions: Vec::new(),
            virtual_actions: BTreeMap::new(),
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

    /// Register a virtual child at `at` (the hook's own virtual-path namespace,
    /// `""` for the hook's root — e.g. today's existing single-level tests).
    pub fn with_child(mut self, at: &str, entry: NodeEntry) -> Self {
        self.children.entry(at.to_string()).or_default().push(entry);
        self
    }

    pub fn with_read(mut self, virtual_child: impl Into<String>, value: BridgeValue) -> Self {
        self.reads.insert(virtual_child.into(), value);
        self
    }

    /// Action IDs returned by `action_ids` for a matched real node.
    pub fn with_action(mut self, id: impl Into<String>) -> Self {
        self.actions.push(id.into());
        self
    }

    /// Action IDs returned by `virtual_action_ids` at a given virtual path.
    pub fn with_virtual_action(mut self, at: &str, id: impl Into<String>) -> Self {
        self.virtual_actions
            .entry(at.to_string())
            .or_default()
            .push(id.into());
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
        virtual_path: &str,
        offset: u64,
        limit: u64,
    ) -> ForensicResult<(Vec<NodeEntry>, u64)> {
        let all = self
            .children
            .get(virtual_path)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let total = all.len() as u64;
        let page = all
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

    fn action_ids(&self, _path: &str, _value: &BridgeValue) -> Vec<String> {
        self.actions.clone()
    }

    fn virtual_action_ids(&self, _parent_path: &str, virtual_path: &str) -> Vec<String> {
        self.virtual_actions
            .get(virtual_path)
            .cloned()
            .unwrap_or_default()
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
            .with_child(
                "",
                NodeEntry {
                    name: Text::Borrowed("Desktop"),
                    node_type: NodeType::Leaf,
                    description: None,
                },
            )
            .with_read("Desktop", BridgeValue::Text(Text::Borrowed("C:\\Desktop")));

        let (entries, total) = hook
            .virtual_children("parent", &BridgeValue::Null, "", 0, 10)
            .unwrap();
        assert_eq!(total, 1);
        assert_eq!(entries.len(), 1);

        let value = hook.read_virtual("parent", "Desktop").unwrap();
        assert!(matches!(value, BridgeValue::Text(_)));
        assert!(hook.read_virtual("parent", "missing").is_err());
    }

    #[test]
    fn nested_children_are_keyed_by_virtual_path() {
        let hook = TestingProviderHook::new("shellbag")
            .with_child(
                "",
                NodeEntry {
                    name: Text::Borrowed("Desktop"),
                    node_type: NodeType::Leaf,
                    description: None,
                },
            )
            .with_child(
                "Desktop",
                NodeEntry {
                    name: Text::Borrowed("SubFolder"),
                    node_type: NodeType::Leaf,
                    description: None,
                },
            );

        let (root, root_total) = hook
            .virtual_children("parent", &BridgeValue::Null, "", 0, 10)
            .unwrap();
        assert_eq!(root_total, 1);
        assert_eq!(root[0].name.as_ref(), "Desktop");

        let (nested, nested_total) = hook
            .virtual_children("parent", &BridgeValue::Null, "Desktop", 0, 10)
            .unwrap();
        assert_eq!(nested_total, 1);
        assert_eq!(nested[0].name.as_ref(), "SubFolder");

        let (empty, empty_total) = hook
            .virtual_children("parent", &BridgeValue::Null, "NoSuchPath", 0, 10)
            .unwrap();
        assert_eq!(empty_total, 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn configured_actions_are_served() {
        let hook = TestingProviderHook::new("shellbag")
            .with_action("shellbag.explain")
            .with_virtual_action("Desktop", "shellbag.explain_child");

        assert_eq!(
            hook.action_ids("parent", &BridgeValue::Null),
            vec!["shellbag.explain".to_string()]
        );
        assert_eq!(
            hook.virtual_action_ids("parent", "Desktop"),
            vec!["shellbag.explain_child".to_string()]
        );
        assert!(hook.virtual_action_ids("parent", "Downloads").is_empty());
    }
}
