//! What a collection tool (KAPE, CyLR, Velociraptor, UAC, `.frtriage`, ...)
//! says it did: which tool, when, by whom, against what target list, and
//! what it itself failed to collect.
//!
//! `Acquisition::RemoteCollection` records *that* a collector ran, never
//! *when*, *with what*, *by whom*, or *against which target list*. Without
//! a target list, [`crate::traits::vfs::SourceKind::Triage`]'s central
//! promise — "absent may mean not collected rather than not present" —
//! cannot actually be answered: nothing knows what was ever asked for. A
//! [`CollectionManifest`] closes that gap, and is what
//! [`crate::coverage::CoverageReport`] is computed against.
//!
//! Real parsers for KAPE/CyLR/Velociraptor/UAC log formats are downstream
//! concerns — this module ships only the trait and a plain in-memory
//! implementation for tests and formats simple enough not to need a whole
//! parser (like the toy `.frtriage` format in `examples/mcp_stdio_server.rs`).

use crate::field::Text;
use crate::traits::forensic::TargetSpec;
use crate::utils::time::ForensicTimestamp;

/// Identifies the tool that performed a collection (name + version), for
/// attribution in a coverage report or chain-of-custody statement.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ToolIdentity {
    pub name: Text,
    pub version: Text,
}

impl ToolIdentity {
    pub fn new(name: impl Into<Text>, version: impl Into<Text>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }
}

impl Default for ToolIdentity {
    fn default() -> Self {
        Self::new("unknown", "unknown")
    }
}

/// One failure the collector itself logged while trying to reach a target.
///
/// `target` is matched against a [`TargetSpec::glob`] by exact equality —
/// the convention a [`CollectionManifest`] implementation is expected to
/// follow: log an error against the same glob string the target was
/// declared with, not a resolved path, so [`crate::coverage::CoverageReport::compute`]
/// can attribute it without re-deriving what the collector meant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionError {
    pub target: Text,
    pub message: Text,
}

impl CollectionError {
    pub fn new(target: impl Into<Text>, message: impl Into<Text>) -> Self {
        Self {
            target: target.into(),
            message: message.into(),
        }
    }
}

/// What a collection tool says it did.
///
/// The collector's own error log is evidence in its own right: "KAPE could
/// not read `$MFT` (locked)" is a materially different statement from
/// "`$MFT` was never targeted" — both are absences, but only
/// [`Self::errors`] can distinguish them.
pub trait CollectionManifest: Send + Sync {
    fn collector(&self) -> ToolIdentity;
    fn collected_at(&self) -> Option<ForensicTimestamp>;
    fn operator(&self) -> Option<&str>;
    fn targets(&self) -> &[TargetSpec];
    fn errors(&self) -> &[CollectionError];
}

/// A plain, in-memory [`CollectionManifest`] — for tests, for formats
/// simple enough not to need a dedicated parser, and as a reference shape
/// for a downstream KAPE/CyLR/Velociraptor/UAC implementation to match.
#[derive(Debug, Clone, Default)]
pub struct StaticCollectionManifest {
    collector: ToolIdentity,
    collected_at: Option<ForensicTimestamp>,
    operator: Option<Text>,
    targets: Vec<TargetSpec>,
    errors: Vec<CollectionError>,
}

impl StaticCollectionManifest {
    pub fn new(collector: ToolIdentity) -> Self {
        Self {
            collector,
            collected_at: None,
            operator: None,
            targets: Vec::new(),
            errors: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_collected_at(mut self, collected_at: ForensicTimestamp) -> Self {
        self.collected_at = Some(collected_at);
        self
    }

    #[must_use]
    pub fn with_operator(mut self, operator: impl Into<Text>) -> Self {
        self.operator = Some(operator.into());
        self
    }

    #[must_use]
    pub fn with_target(mut self, target: TargetSpec) -> Self {
        self.targets.push(target);
        self
    }

    #[must_use]
    pub fn with_error(mut self, error: CollectionError) -> Self {
        self.errors.push(error);
        self
    }
}

impl CollectionManifest for StaticCollectionManifest {
    fn collector(&self) -> ToolIdentity {
        self.collector.clone()
    }

    fn collected_at(&self) -> Option<ForensicTimestamp> {
        self.collected_at
    }

    fn operator(&self) -> Option<&str> {
        self.operator.as_deref()
    }

    fn targets(&self) -> &[TargetSpec] {
        &self.targets
    }

    fn errors(&self) -> &[CollectionError] {
        &self.errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_manifest_reports_back_exactly_what_it_was_built_with() {
        let manifest = StaticCollectionManifest::new(ToolIdentity::new("KAPE", "1.2.0"))
            .with_operator("j.doe")
            .with_target(TargetSpec::new("C:/Windows/System32/config/SYSTEM", "SYSTEM hive"))
            .with_error(CollectionError::new(
                "C:/$MFT",
                "access denied (file locked)",
            ));

        assert_eq!(manifest.collector().name, "KAPE");
        assert_eq!(manifest.operator(), Some("j.doe"));
        assert_eq!(manifest.targets().len(), 1);
        assert_eq!(manifest.errors().len(), 1);
        assert_eq!(manifest.errors()[0].target, "C:/$MFT");
    }

    #[test]
    fn default_tool_identity_is_explicit_about_being_unknown() {
        let identity = ToolIdentity::default();
        assert_eq!(identity.name, "unknown");
    }

    fn accepts_dyn_manifest(_m: &dyn CollectionManifest) {}

    #[test]
    fn collection_manifest_is_object_safe() {
        let manifest = StaticCollectionManifest::new(ToolIdentity::new("KAPE", "1.2.0"));
        accepts_dyn_manifest(&manifest);
    }
}
