//! Which expected artifacts a run was actually able to account for, and
//! why the rest are missing.
//!
//! Plaso does not do this, and analysts need it constantly: "I found
//! nothing" and "I found nothing, and here is exactly what I could not
//! look at, and why" are materially different statements in a report.
//! [`CoverageReport::compute`] is cheap once a [`CollectionManifest`]'s
//! target list exists — it is the direct payoff of that module.

use std::sync::Arc;

use crate::collection::CollectionManifest;
use crate::err::ForensicResult;
use crate::field::Text;
use crate::traits::forensic::TargetSpec;
use crate::traits::vfs::{FileSystem, FileSystemExt};

/// Why one target from a [`CollectionManifest`] has no matching evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverageGapReason {
    /// The collector's own log recorded a specific reason for this target.
    CollectionError(Text),
    /// The collector reported no error for this target, but no matching
    /// file exists in the evidence either — absent for an undetermined
    /// reason (never collected, or collected then lost, or a manifest/
    /// evidence mismatch).
    NotFound,
}

/// One target the manifest declared that the evidence doesn't account for.
#[derive(Debug, Clone)]
pub struct CoverageGap {
    pub target: TargetSpec,
    pub reason: CoverageGapReason,
}

/// The result of checking a [`CollectionManifest`]'s declared targets
/// against what evidence is actually present.
#[derive(Debug, Clone, Default)]
pub struct CoverageReport {
    pub present: Vec<TargetSpec>,
    pub gaps: Vec<CoverageGap>,
}

impl CoverageReport {
    /// For every target the manifest declares, checks whether `fs` has a
    /// matching file (via [`FileSystemExt::glob`]). A target with no match
    /// becomes a [`CoverageGap`], attributed to a [`CollectionError`]
    /// logged against the same glob string if one exists, else
    /// [`CoverageGapReason::NotFound`].
    ///
    /// [`CollectionError`]: crate::collection::CollectionError
    pub fn compute(
        manifest: &dyn CollectionManifest,
        fs: &Arc<dyn FileSystem>,
    ) -> ForensicResult<Self> {
        let mut present = Vec::new();
        let mut gaps = Vec::new();

        for target in manifest.targets() {
            let matches = fs.glob(&target.glob)?;
            if !matches.is_empty() {
                present.push(target.clone());
                continue;
            }
            let reason = manifest
                .errors()
                .iter()
                .find(|error| error.target == target.glob)
                .map(|error| CoverageGapReason::CollectionError(error.message.clone()))
                .unwrap_or(CoverageGapReason::NotFound);
            gaps.push(CoverageGap {
                target: target.clone(),
                reason,
            });
        }

        Ok(Self { present, gaps })
    }

    /// Whether every declared target has matching evidence.
    pub fn is_complete(&self) -> bool {
        self.gaps.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collection::{CollectionError, StaticCollectionManifest, ToolIdentity};
    use crate::utils::testing::InMemoryVirtualFileSystem;

    fn evidence_fs() -> Arc<dyn FileSystem> {
        let fs = InMemoryVirtualFileSystem::new()
            .with_text_file("Windows/System32/config/SYSTEM", "hive bytes")
            .with_text_file("Windows/System32/config/SOFTWARE", "hive bytes");
        Arc::new(fs)
    }

    #[test]
    fn present_targets_are_reported_present() {
        let manifest = StaticCollectionManifest::new(ToolIdentity::new("KAPE", "1.2.0"))
            .with_target(TargetSpec::new("Windows/System32/config/SYSTEM", "SYSTEM hive"));
        let report = CoverageReport::compute(&manifest, &evidence_fs()).unwrap();
        assert_eq!(report.present.len(), 1);
        assert!(report.gaps.is_empty());
        assert!(report.is_complete());
    }

    #[test]
    fn missing_target_with_a_logged_error_is_attributed_to_it() {
        let manifest = StaticCollectionManifest::new(ToolIdentity::new("KAPE", "1.2.0"))
            .with_target(TargetSpec::new("C:/$MFT", "Master File Table"))
            .with_error(CollectionError::new("C:/$MFT", "access denied (file locked)"));
        let report = CoverageReport::compute(&manifest, &evidence_fs()).unwrap();
        assert!(report.present.is_empty());
        assert_eq!(report.gaps.len(), 1);
        match &report.gaps[0].reason {
            CoverageGapReason::CollectionError(msg) => assert_eq!(msg, "access denied (file locked)"),
            other => panic!("expected CollectionError, got {other:?}"),
        }
        assert!(!report.is_complete());
    }

    #[test]
    fn missing_target_with_no_logged_error_is_undetermined() {
        let manifest = StaticCollectionManifest::new(ToolIdentity::new("KAPE", "1.2.0"))
            .with_target(TargetSpec::new("Windows/AppCompat/Programs/Amcache.hve", "Amcache"));
        let report = CoverageReport::compute(&manifest, &evidence_fs()).unwrap();
        assert_eq!(report.gaps.len(), 1);
        assert_eq!(report.gaps[0].reason, CoverageGapReason::NotFound);
    }

    #[test]
    fn mixed_manifest_reports_both_present_and_missing() {
        let manifest = StaticCollectionManifest::new(ToolIdentity::new("KAPE", "1.2.0"))
            .with_target(TargetSpec::new("Windows/System32/config/SYSTEM", "SYSTEM hive"))
            .with_target(TargetSpec::new("Windows/System32/config/SAM", "SAM hive"))
            .with_error(CollectionError::new("Windows/System32/config/SAM", "locked"));
        let report = CoverageReport::compute(&manifest, &evidence_fs()).unwrap();
        assert_eq!(report.present.len(), 1);
        assert_eq!(report.gaps.len(), 1);
        assert!(!report.is_complete());
    }
}
