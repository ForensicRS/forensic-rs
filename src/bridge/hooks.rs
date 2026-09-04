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
/// # Multi-level nesting
///
/// A hook's virtual namespace is not limited to one level. `virtual_children`'s
/// `virtual_path` parameter and `read_virtual`'s `virtual_child` parameter both carry
/// the *entire* remaining path below the `[hookname]` segment, and the hook is
/// responsible for self-routing arbitrary depth from that string — e.g. listing
/// `[shellbag]` itself uses `virtual_path == ""` (the hook's own root), while listing
/// `[shellbag]\Desktop` uses `virtual_path == "Desktop"`, and a hook that wants a
/// third level (`[shellbag]\Desktop\SubFolder`) parses `"Desktop\SubFolder"` itself
/// the same way `read_virtual` implementors already do for arbitrary-depth reads.
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
    /// `virtual_path` is the sub-path within the hook's own namespace being
    /// listed — `""` for the hook's root (e.g. `[shellbag]`), or a nested path
    /// (e.g. `"Desktop"`) for a deeper listing. The hook self-routes on this
    /// value the same way `read_virtual` already self-routes on `virtual_child`.
    /// Returns `(entries, total_count)` — supports pagination.
    fn virtual_children(
        &self,
        parent_path: &str,
        parent_value: &BridgeValue,
        virtual_path: &str,
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

    /// Command/tool IDs this hook makes available for a matched *real* node.
    ///
    /// Gated the same way virtual children are — only called when
    /// `matches_path`/`matches_value` both hold for `path`/`value`. Default: no
    /// actions.
    #[allow(unused_variables)]
    fn action_ids(&self, path: &str, value: &BridgeValue) -> Vec<String> {
        Vec::new()
    }

    /// Command/tool IDs available for a node *within* this hook's own virtual
    /// namespace. `parent_path`/`virtual_path` have the same meaning as in
    /// [`ProviderHook::virtual_children`]/[`ProviderHook::read_virtual`].
    /// Default: no actions.
    #[allow(unused_variables)]
    fn virtual_action_ids(&self, parent_path: &str, virtual_path: &str) -> Vec<String> {
        Vec::new()
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
        for component in parts.iter() {
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

/// Collect command/tool IDs from all hooks matching a *real* node's `path`/`value`.
///
/// Mirrors [`inject_hook_children`]'s two-stage gate but collects
/// [`ProviderHook::action_ids`] instead of injecting virtual children.
pub fn collect_hook_actions(
    hooks: &[Box<dyn ProviderHook>],
    path: &str,
    value: &BridgeValue,
) -> Vec<String> {
    let mut ids = Vec::new();
    for hook in hooks {
        if hook.matches_path(path) && hook.matches_value(path, value) {
            ids.extend(hook.action_ids(path, value));
        }
    }
    ids
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
            _virtual_path: &str,
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

        fn action_ids(&self, _path: &str, _value: &BridgeValue) -> Vec<String> {
            vec!["shellbag.explain".to_string()]
        }

        fn virtual_action_ids(&self, _parent_path: &str, virtual_path: &str) -> Vec<String> {
            if virtual_path == "Desktop" {
                vec!["shellbag.explain_child".to_string()]
            } else {
                Vec::new()
            }
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

    #[test]
    fn virtual_children_receives_nested_virtual_path() {
        let hook = MockShellbagHook;
        let (entries, total) = hook
            .virtual_children("parent", &BridgeValue::Null, "Desktop", 0, 10)
            .unwrap();
        assert_eq!(total, 2);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn collect_hook_actions_gates_on_matches_path_and_value() {
        let hooks: Vec<Box<dyn ProviderHook>> = vec![Box::new(MockShellbagHook)];
        let matching_path = r"HKCU\Shell\BagMRU\0";
        let matching_value = BridgeValue::Binary(vec![0xDE, 0xAD]);
        assert_eq!(
            collect_hook_actions(&hooks, matching_path, &matching_value),
            vec!["shellbag.explain".to_string()]
        );

        // matches_path fails
        assert!(collect_hook_actions(&hooks, "HKCU\\Other", &matching_value).is_empty());
        // matches_value fails (not Binary)
        assert!(collect_hook_actions(&hooks, matching_path, &BridgeValue::Null).is_empty());
    }

    #[test]
    fn virtual_action_ids_is_gated_by_the_provider_dispatching_it() {
        let hook = MockShellbagHook;
        assert_eq!(
            hook.virtual_action_ids("parent", "Desktop"),
            vec!["shellbag.explain_child".to_string()]
        );
        assert!(hook.virtual_action_ids("parent", "Downloads").is_empty());
    }
}
