//! The evidentiary model: what a source is, how its bytes were acquired, how
//! the structure inside them was located, and how records derive from one
//! another.

use super::ids::{ProvenanceId, SourceId};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// How the bytes underlying a record were obtained.
///
/// Orthogonal to [`Recovery`] — pick one from each independently. Never
/// combine them into a single enum: `Acquisition` alone already answers
/// "can I trust the collection process," `Recovery` alone answers "can I
/// trust that this structure is really there." Conflating the two would
/// explode combinatorially (`CarvedFromLiveVss`, `DeletedCellFromImage`, ...).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Acquisition {
    /// Read directly from a forensic image (dd/E01/raw).
    ImageRead,
    /// Read through a live OS API. Mediated, filtered, and NOT reproducible —
    /// a second read through the same API may return different bytes.
    LiveApi,
    /// Read from a Volume Shadow Copy snapshot.
    VssSnapshot { id: u32 },
    /// Read from a memory image or live memory acquisition.
    Memory,
    /// Collected via a remote/agent-based collection mechanism.
    RemoteCollection,
}

/// Conservative default mapping from a [`crate::traits::vfs::SourceKind`] to
/// an [`Acquisition`]. Never overstates: a parser that knows more (e.g. it
/// resolved a VSS-mounted path) should say so explicitly rather than rely on
/// this default.
///
/// `SourceKind::Triage` has no exact counterpart — a KAPE/CyLR-style targeted
/// collection was mediated by a collection tool, so it maps to
/// [`Acquisition::RemoteCollection`] (which grades to `Medium`, not the
/// `High` a raw image read would). This is a known lossy mapping.
impl From<crate::traits::vfs::SourceKind> for Acquisition {
    fn from(kind: crate::traits::vfs::SourceKind) -> Self {
        use crate::traits::vfs::SourceKind;
        match kind {
            SourceKind::Image => Acquisition::ImageRead,
            SourceKind::Live => Acquisition::LiveApi,
            SourceKind::Memory => Acquisition::Memory,
            SourceKind::Triage => Acquisition::RemoteCollection,
        }
    }
}

/// How the structure was located within the acquired bytes.
///
/// Orthogonal to [`Acquisition`] — see that type's documentation for why the
/// two axes are kept separate.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Recovery {
    /// Found via the filesystem's/format's own allocation metadata, intact.
    Allocated,
    /// Found via metadata marked as deleted, but the metadata itself is intact.
    DeletedMetadata,
    /// Found in slack space (e.g. `$I30` slack, unused directory entry bytes).
    Slack,
    /// Recovered by replaying a log against a base structure (e.g. registry
    /// `.LOG1`/`.LOG2`, `$LogFile`).
    LogReplayed,
    /// Found in a chunk/record that failed an internal integrity check (e.g.
    /// an EVTX chunk with a failing CRC) but was still parseable.
    DirtyChunk,
    /// Found by signature/structure carving with no supporting metadata.
    Carved,
}

/// Where, structurally, a record was found within its source.
///
/// A plain, `Copy`, comparable, non-trait-object enum — deliberately not a
/// `dyn Locus` trait: keeping it a closed, sized type keeps every downstream
/// struct that embeds a `Locus` cheap and cache-friendly. Variants exist ahead
/// of any parser that produces them; that is intentional; this enum is the
/// contract future parsers are written against. Keep variants small (plain
/// integers and interned handles only) — the enum's size is its largest
/// variant.
///
/// Deliberately **not** threaded through [`Provenance`]/[`super::SourceHandle::mint`]/
/// [`super::ProvenanceStore::derive`]: unlike [`SourceId`], a locus rarely
/// repeats across records (each MFT entry/hive cell/evtx record has its own),
/// so there is no interning benefit, and it is treated as instance-level data
/// the caller attaches alongside a [`ProvenanceId`] rather than as part of the
/// interned record itself.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Locus {
    Ntfs {
        entry: u64,
        sequence: u16,
        attribute: u16,
        offset: u64,
    },
    Hive {
        cell: u32,
        value_index: u16,
    },
    Evtx {
        chunk: u32,
        record_id: u64,
    },
    Usn {
        usn: u64,
    },
    RawOffset {
        offset: u64,
    },
    /// No byte locus exists — the value came from an API call, not a
    /// structure at a specific offset.
    Api,
}

/// Identifies a source: a file, a volume region, a live API endpoint, or a
/// chain of nested containers (e.g. E01 image -> volume -> VSS snapshot ->
/// file).
///
/// Used as the interning key in [`super::ProvenanceStore::register_source`] —
/// registering the same `SourceKey` twice returns the same [`SourceId`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SourceKey {
    Path(String),
    ContentHash(String),
    VolumeOffset { volume: String, offset: u64 },
    /// A chain of nested containers, outermost first.
    Chain(Vec<SourceKey>),
    Live { host: String, api: String },
    /// For tests and placeholders — never meant to identify a real source.
    Synthetic(String),
}

/// Why a [`super::ProvenanceStore::merge`] combined several provenance
/// records into one.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MergeReason {
    /// Two disagreeing sources were reconciled into a single derived value.
    Reconciliation,
    /// Independent sources corroborated the same fact.
    CrossSourceCorroboration,
    /// Two records were recognized as describing the same underlying fact.
    Deduplication,
}

/// What a [`Provenance`] record derives from, if anything.
///
/// Not a plain `Option<ProvenanceId>`: a merge must retain *every* parent it
/// combined (merge fidelity) — an `Option` can only hold one.
#[derive(Debug, Clone)]
pub enum DerivedFrom {
    /// Minted directly from a source; does not derive from anything.
    None,
    /// Derived from exactly one parent (e.g. via [`super::ProvenanceStore::derive`]).
    Single(ProvenanceId),
    /// Derived by merging multiple parents; all are retained, never dropped.
    Merged(Box<[ProvenanceId]>, MergeReason),
}

/// The interned, immutable record of how a piece of data came to exist.
///
/// **No public fields, no public constructor, no `Default`.** The only way to
/// obtain a [`ProvenanceId`] pointing at a value of this type is through
/// [`super::SourceHandle::mint`], [`super::ProvenanceStore::derive`], or
/// [`super::ProvenanceStore::merge`] — all of which live in `store.rs`, a
/// sibling module. A `Provenance` can therefore never be forged: its chain of
/// `derived_from` links is only ever built by the store itself.
#[derive(Debug, Clone)]
pub struct Provenance {
    pub(super) source: SourceId,
    pub(super) acquisition: Acquisition,
    pub(super) recovery: Recovery,
    pub(super) derived_from: DerivedFrom,
}

/// A read-only, resolved snapshot of one [`Provenance`] record, with its
/// [`SourceId`] resolved back to the [`SourceKey`] that produced it.
///
/// Returned by [`super::ProvenanceStore::get`] for introspection. Plain public
/// fields are safe here — nothing lets you feed a `ProvenanceSnapshot` back
/// into the store to fabricate a new record.
#[derive(Debug, Clone)]
pub struct ProvenanceSnapshot {
    pub source: SourceKey,
    pub acquisition: Acquisition,
    pub recovery: Recovery,
    pub derived_from: DerivedFrom,
}

const _: [(); std::mem::size_of::<Locus>()] = [(); std::mem::size_of::<Locus>()];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locus_is_copy_and_comparable() {
        let a = Locus::RawOffset { offset: 42 };
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn source_key_interns_by_structural_equality() {
        let a = SourceKey::Path("C:\\$MFT".to_string());
        let b = SourceKey::Path("C:\\$MFT".to_string());
        assert_eq!(a, b);
        let c = SourceKey::Path("C:\\$LogFile".to_string());
        assert_ne!(a, c);
    }
}
