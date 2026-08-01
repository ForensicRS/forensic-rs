use std::collections::BTreeMap;

use crate::{err::ForensicResult, field::Text};

use super::{BridgeValue, NodeEntry, NodeType};

// ============================================================================
// ProviderHook trait
// ============================================================================

/// Postprocessing hook for provider data.
///
/// Hooks inject virtual children into bridge tree nodes, allowing domain-specific
/// parsing of raw artifact data (e.g., parsing shellbags inside registry binary
/// values, or interpreting known file formats in a VFS).
///
/// # Matching
///
/// The match process is two-stage:
/// 1. **Path filter**: `matches_path(path)` — fast check, avoids reading data
///    for paths the hook doesn't care about.
/// 2. **Content inspection**: `matches_value(path, value)` — inspect the actual
///    data (e.g., check binary magic bytes). Only called if `matches_path` is true.
///
/// # Virtual path convention
///
/// Virtual children use a bracketed hook name as a path segment to avoid
/// collisions with real children. For example:
/// - Real key: `HKCU\Software\Microsoft\Windows\Shell\BagMRU\0` (Binary)
/// - Virtual child: `HKCU\Software\Microsoft\Windows\Shell\BagMRU\0\[shellbag]\Desktop`
///
/// The `[hookname]` segment identifies the owning hook. When the bridge receives a
/// `Children` request on a path containing `[hookname]`, the provider delegates to
/// `hook.virtual_children()`, and `Read` requests delegate to `hook.read_virtual()`.
///
/// # Object safety
///
/// The trait is object-safe — all methods take `&self` with concrete argument types.
/// Register hooks via `.add_hook(Box<dyn ProviderHook>)` on concrete provider structs
/// (not on the `ForensicProvider` trait, which keeps the latter object-safe).
pub trait ProviderHook: Send + Sync {
    /// Stable identifier for this hook. Used as the virtual path namespace segment.
    /// Must be unique among hooks registered on the same provider.
    ///
    /// Example: `"shellbag"` → virtual paths like `path\[shellbag]\Desktop`
    fn name(&self) -> &str;

    /// Fast path-based pre-filter. Return `false` to skip expensive value inspection.
    ///
    /// Called with the normalized path of the parent node being listed.
    /// Example: a shellbag hook would check if `path` is under `BagMRU`.
    fn matches_path(&self, path: &str) -> bool;

    /// Content-based filter. Called only when `matches_path` returns `true`.
    ///
    /// The `value` is the current node value (e.g., the raw `BridgeValue::Binary`
    /// bytes from a registry value). Return `false` if the data format is not
    /// recognized.
    fn matches_value(&self, path: &str, value: &BridgeValue) -> bool;

    /// Return the virtual children injected under a matched parent node.
    ///
    /// `parent_path` is the original path (e.g., the registry key).
    /// `parent_value` is the raw value for this node.
    /// Returns `(entries, total_count)` — supports pagination.
    fn virtual_children(
        &self,
        parent_path: &str,
        parent_value: &BridgeValue,
        offset: u64,
        limit: u64,
    ) -> ForensicResult<(Vec<NodeEntry>, u64)>;

    /// Read a specific virtual child node.
    ///
    /// `parent_path` is the original node path.
    /// `virtual_child` is the child name under the hook's namespace.
    fn read_virtual(&self, parent_path: &str, virtual_child: &str) -> ForensicResult<BridgeValue>;

    /// Get metadata for a specific virtual child node.
    ///
    /// Default implementation returns an empty map (no metadata).
    #[allow(unused_variables)]
    fn metadata_virtual(
        &self,
        parent_path: &str,
        virtual_child: &str,
    ) -> ForensicResult<BTreeMap<Text, BridgeValue>> {
        Ok(BTreeMap::new())
    }
}

// ============================================================================
// Path helpers
// ============================================================================

/// Build the virtual namespace segment for a hook.
///
/// Example: `virtual_segment("shellbag")` → `"[shellbag]"`
pub fn virtual_segment(hook_name: &str) -> String {
    format!("[{}]", hook_name)
}

/// Detect if a path component is a virtual hook segment.
///
/// Example: `is_virtual_segment("[shellbag]")` → `Some("shellbag")`
pub fn is_virtual_segment(component: &str) -> Option<&str> {
    if component.starts_with('[') && component.ends_with(']') {
        Some(&component[1..component.len() - 1])
    } else {
        None
    }
}

/// Split a path into `(real_parent, hook_name, virtual_tail)` if it contains
/// a virtual segment. Returns `None` if the path has no virtual segment.
///
/// Example:
/// ```text
/// split_virtual_path("HKCU\\BagMRU\\0\\[shellbag]\\Desktop")
///   → Some(("HKCU\\BagMRU\\0", "shellbag", "Desktop"))
/// ```
pub fn split_virtual_path(path: &str) -> Option<(&str, &str, &str)> {
    // Try both separators
    for sep in ['\\', '/'] {
        let parts: Vec<&str> = path.split(sep).collect();
        for (_i, component) in parts.iter().enumerate() {
            if let Some(hook_name) = is_virtual_segment(component) {
                let real_parent = &path[..path.find(*component).unwrap_or(0).saturating_sub(1)];
                let tail_start = path.find(*component).unwrap_or(0) + component.len();
                let virtual_tail = if tail_start < path.len() {
                    &path[tail_start + 1..]
                } else {
                    ""
                };
                drop(parts);
                return Some((real_parent, hook_name, virtual_tail));
            }
        }
    }
    None
}

/// Inject virtual `NodeEntry` items from all matching hooks into an existing
/// list of real children. Used by provider implementations.
///
/// For each hook that matches `path` + `value`, appends a `NodeType::Virtual`
/// `NodeEntry` whose name is the hook's virtual segment (e.g., `[shellbag]`).
/// Reading that entry delegates to the hook.
pub fn inject_hook_children(
    real_children: &mut Vec<NodeEntry>,
    hooks: &[Box<dyn ProviderHook>],
    path: &str,
    value: &BridgeValue,
) {
    for hook in hooks {
        if hook.matches_path(path) && hook.matches_value(path, value) {
            real_children.push(NodeEntry {
                name: Text::Owned(virtual_segment(hook.name())),
                node_type: NodeType::Virtual,
                description: None,
            });
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_segment_format() {
        assert_eq!(virtual_segment("shellbag"), "[shellbag]");
        assert_eq!(is_virtual_segment("[shellbag]"), Some("shellbag"));
        assert_eq!(is_virtual_segment("regular"), None);
    }

    #[test]
    fn split_virtual_path_works() {
        let path = r"HKCU\Shell\BagMRU\0\[shellbag]\Desktop";
        let result = split_virtual_path(path);
        assert!(result.is_some());
        let (parent, hook, tail) = result.unwrap();
        assert_eq!(hook, "shellbag");
        assert_eq!(tail, "Desktop");
        assert!(parent.contains("BagMRU"));
    }

    /// Mock hook that matches any path ending in "BagMRU\\0".
    struct MockShellbagHook;

    impl ProviderHook for MockShellbagHook {
        fn name(&self) -> &str {
            "shellbag"
        }

        fn matches_path(&self, path: &str) -> bool {
            path.contains("BagMRU")
        }

        fn matches_value(&self, _path: &str, value: &BridgeValue) -> bool {
            matches!(value, BridgeValue::Binary(_))
        }

        fn virtual_children(
            &self,
            _parent_path: &str,
            _parent_value: &BridgeValue,
            offset: u64,
            limit: u64,
        ) -> ForensicResult<(Vec<NodeEntry>, u64)> {
            let all = vec![
                NodeEntry {
                    name: Text::Borrowed("Desktop"),
                    node_type: NodeType::Leaf,
                    description: None,
                },
                NodeEntry {
                    name: Text::Borrowed("Downloads"),
                    node_type: NodeType::Leaf,
                    description: None,
                },
            ];
            let total = all.len() as u64;
            let page: Vec<NodeEntry> = all
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect();
            Ok((page, total))
        }

        fn read_virtual(
            &self,
            _parent_path: &str,
            virtual_child: &str,
        ) -> ForensicResult<BridgeValue> {
            let mut map = BTreeMap::new();
            map.insert(
                Text::Borrowed("path"),
                BridgeValue::Text(Text::Owned(virtual_child.to_string())),
            );
            Ok(BridgeValue::Map(map))
        }
    }

    #[test]
    fn inject_hook_children_appends_virtual_entries() {
        let hooks: Vec<Box<dyn ProviderHook>> = vec![Box::new(MockShellbagHook)];
        let mut children: Vec<NodeEntry> = vec![NodeEntry {
            name: Text::Borrowed("0"),
            node_type: NodeType::Leaf,
            description: None,
        }];
        let path = r"HKCU\Shell\BagMRU";
        let value = BridgeValue::Binary(vec![0xDE, 0xAD]);
        inject_hook_children(&mut children, &hooks, path, &value);
        assert_eq!(children.len(), 2);
        assert_eq!(children[1].name.as_ref(), "[shellbag]");
        assert_eq!(children[1].node_type, NodeType::Virtual);
    }
}
