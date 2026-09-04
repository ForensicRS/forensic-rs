//! Structured addressing for evidence reachable through nested containers.
//!
//! A flat string path ("case.zip/evil.exe") cannot safely represent an
//! archive entry named `../../etc/passwd`, cannot distinguish a registry
//! cell from a filesystem path, and cannot be re-parsed without an
//! ambiguity attackers can exploit. [`EvidenceLocator`] replaces string
//! concatenation with a structured chain of typed hops, mirroring
//! [`crate::provenance::SourceKey::Chain`] (which this type projects into).

use std::fmt;

use compact_str::CompactString;

use crate::core::path::FPathBuf;
use crate::provenance::SourceKey;

/// One hop in a chain of containment, interpretation, or embedding
/// relationships leading to a piece of evidence.
///
/// `#[non_exhaustive]`: new container/interpretation kinds are expected as
/// downstream format support grows.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LocatorSegment {
    /// A path within a [`crate::traits::vfs::FileSystem`].
    Path(FPathBuf),
    /// An entry within an archive. `index` is the stable identity (survives
    /// two entries sharing a name); `name` is for display and re-lookup.
    ArchiveEntry { index: u64, name: CompactString },
    /// An alternate/NTFS/OLE named stream.
    Stream(CompactString),
    /// A PE resource, identified by type, id, and language.
    Resource { kind: u32, id: u32, lang: u16 },
    /// A byte range within its parent (a carved or raw region).
    Offset { offset: u64, len: Option<u64> },
    /// A registry hive cell.
    Cell(u32),
    /// A table within a mounted database.
    Table(CompactString),
}

impl fmt::Display for LocatorSegment {
    // A lossy rendering for humans (logs, reports). Never round-trips back
    // into a LocatorSegment -- there is deliberately no FromStr.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LocatorSegment::Path(p) => write!(f, "{}", p.as_path().as_str()),
            LocatorSegment::ArchiveEntry { name, .. } => write!(f, "{name}"),
            LocatorSegment::Stream(name) => write!(f, ":{name}"),
            LocatorSegment::Resource { kind, id, lang } => {
                write!(f, "[resource {kind}:{id}:{lang}]")
            }
            LocatorSegment::Offset {
                offset,
                len: Some(len),
            } => write!(f, "[offset {offset}+{len}]"),
            LocatorSegment::Offset { offset, len: None } => write!(f, "[offset {offset}]"),
            LocatorSegment::Cell(cell) => write!(f, "[cell {cell}]"),
            LocatorSegment::Table(name) => write!(f, "[table {name}]"),
        }
    }
}

/// A structured chain of hops locating one piece of evidence through zero or
/// more nested containers, outermost first.
///
/// Deliberately has no `FromStr`, and `Display` is a lossy rendering for
/// humans only. Identity, lookup, and caching go through the segments
/// themselves, never through a reconstructed string -- that is the whole
/// point of the type: an archive entry legitimately named
/// `../../etc/passwd` must never be representable as a re-parseable path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct EvidenceLocator(Vec<LocatorSegment>);

impl EvidenceLocator {
    /// The locator for the top-level evidence item itself (no hops yet).
    pub fn root() -> Self {
        Self(Vec::new())
    }

    pub fn from_segments(segments: Vec<LocatorSegment>) -> Self {
        Self(segments)
    }

    /// Builder-style: append one hop and return `self`.
    #[must_use]
    pub fn push(mut self, segment: LocatorSegment) -> Self {
        self.0.push(segment);
        self
    }

    /// Mutating append, for callers building a chain in a loop.
    pub fn push_mut(&mut self, segment: LocatorSegment) {
        self.0.push(segment);
    }

    /// Number of hops from the top-level evidence item to this locator.
    pub fn depth(&self) -> u32 {
        self.0.len() as u32
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    pub fn segments(&self) -> &[LocatorSegment] {
        &self.0
    }

    pub fn last(&self) -> Option<&LocatorSegment> {
        self.0.last()
    }

    /// The locator for the container one level up, if any.
    pub fn parent(&self) -> Option<EvidenceLocator> {
        if self.0.is_empty() {
            return None;
        }
        Some(EvidenceLocator(self.0[..self.0.len() - 1].to_vec()))
    }

    /// Projects this locator into [`SourceKey`] for provenance/audit
    /// purposes -- a deliberate, one-way rendering via each segment's
    /// `Display`, never used for lookup or mounting.
    pub fn to_source_key(&self) -> SourceKey {
        match self.0.len() {
            0 => SourceKey::Synthetic("root".to_string()),
            1 => SourceKey::Path(self.0[0].to_string()),
            _ => SourceKey::Chain(
                self.0
                    .iter()
                    .map(|segment| SourceKey::Path(segment.to_string()))
                    .collect(),
            ),
        }
    }
}

impl fmt::Display for EvidenceLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, segment) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, " / ")?;
            }
            write!(f, "{segment}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_empty_and_depth_zero() {
        let root = EvidenceLocator::root();
        assert!(root.is_root());
        assert_eq!(root.depth(), 0);
    }

    #[test]
    fn push_increases_depth_and_preserves_order() {
        let locator = EvidenceLocator::root()
            .push(LocatorSegment::Path(FPathBuf::from("evidence.zip")))
            .push(LocatorSegment::ArchiveEntry {
                index: 3,
                name: CompactString::const_new("evil.exe"),
            });
        assert_eq!(locator.depth(), 2);
        match locator.segments() {
            [LocatorSegment::Path(_), LocatorSegment::ArchiveEntry { name, .. }] => {
                assert_eq!(name, "evil.exe");
            }
            other => panic!("unexpected segments: {other:?}"),
        }
    }

    #[test]
    fn parent_strips_last_segment() {
        let locator = EvidenceLocator::root()
            .push(LocatorSegment::Path(FPathBuf::from("a.zip")))
            .push(LocatorSegment::Path(FPathBuf::from("b.zip")));
        let parent = locator.parent().unwrap();
        assert_eq!(parent.depth(), 1);
        assert_eq!(parent.parent().unwrap().depth(), 0);
        assert!(parent.parent().unwrap().parent().is_none());
    }

    #[test]
    fn traversal_attempt_stays_a_display_only_string() {
        // The whole point of the type: a malicious entry name never becomes
        // a walkable path, because there is no FromStr to reconstruct one.
        let locator = EvidenceLocator::root().push(LocatorSegment::ArchiveEntry {
            index: 0,
            name: CompactString::const_new("../../etc/passwd"),
        });
        assert_eq!(locator.to_string(), "../../etc/passwd");
    }

    #[test]
    fn equal_locators_hash_and_compare_equal() {
        use std::collections::BTreeSet;
        let a = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from("x")));
        let b = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from("x")));
        assert_eq!(a, b);
        let mut set = BTreeSet::new();
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn to_source_key_single_segment_is_flat_path() {
        let locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from("x")));
        assert!(matches!(locator.to_source_key(), SourceKey::Path(_)));
    }

    #[test]
    fn to_source_key_multi_segment_is_chain_outermost_first() {
        let locator = EvidenceLocator::root()
            .push(LocatorSegment::Path(FPathBuf::from("outer.zip")))
            .push(LocatorSegment::Path(FPathBuf::from("inner.db")));
        match locator.to_source_key() {
            SourceKey::Chain(chain) => {
                assert_eq!(chain.len(), 2);
                assert_eq!(chain[0], SourceKey::Path("outer.zip".to_string()));
                assert_eq!(chain[1], SourceKey::Path("inner.db".to_string()));
            }
            other => panic!("expected Chain, got {other:?}"),
        }
    }
}
