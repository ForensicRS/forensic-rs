//! Confidence is a computed property of a provenance chain, never a stored
//! field — storing it would let it drift out of sync with the chain it
//! describes.

use std::collections::HashSet;

use super::ids::ProvenanceId;
use super::model::{Acquisition, DerivedFrom, Recovery};

/// An absolute cap on how many nodes a single confidence fold will visit,
/// independent of cycle detection — defends against pathologically long (but
/// technically acyclic) chains, not just cycles.
const MAX_CHAIN_NODES: usize = 4096;

/// How much a piece of data can be trusted, derived purely from its
/// [`Acquisition`]/[`Recovery`] and the same for every ancestor in its
/// `derived_from` chain (plus any [`super::Anomalies`] attached to the
/// specific instance being asked about).
///
/// Ordered `Unknown < Low < Medium < High` so folding a chain is a `min()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Confidence {
    /// A cycle, a dangling reference, or a pathologically long chain was
    /// encountered while resolving this — the honest answer is "don't know",
    /// not a guess.
    Unknown = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

/// The confidence contributed by a single [`super::Provenance`] record in
/// isolation, before folding over its ancestors.
pub(super) fn base_confidence(acquisition: Acquisition, recovery: Recovery) -> Confidence {
    use Acquisition::*;
    use Recovery::*;
    match recovery {
        Carved | Slack | DirtyChunk => Confidence::Low,
        DeletedMetadata | LogReplayed => match acquisition {
            ImageRead | VssSnapshot { .. } => Confidence::Medium,
            LiveApi | Memory | RemoteCollection => Confidence::Low,
        },
        Allocated => match acquisition {
            ImageRead | VssSnapshot { .. } => Confidence::High,
            // A live API read of allocated structures can still be racing a
            // concurrent write, or be silently tunneled/mangled by the OS.
            LiveApi | Memory | RemoteCollection => Confidence::Medium,
        },
    }
}

/// Walks the `derived_from` chain (following every parent of a merge, not
/// just one) starting at `start`, folding to the weakest [`Confidence`]
/// anywhere in the reachable graph.
///
/// Iterative, not recursive: an attacker-controlled chain of unbounded length
/// cannot exhaust the call stack. Cycle-guarded: a revisited id, a dangling
/// reference (`lookup` returns `None` — e.g. a malformed deserialized store),
/// or exceeding [`MAX_CHAIN_NODES`] all degrade the result to
/// [`Confidence::Unknown`] rather than looping forever or panicking. This is
/// exactly the property the cycle-safety test and the store-deserialization
/// fuzz target exercise.
pub(super) fn fold_chain_confidence(
    start: ProvenanceId,
    lookup: impl Fn(ProvenanceId) -> Option<(Acquisition, Recovery, DerivedFrom)>,
) -> Confidence {
    let mut stack = vec![start];
    let mut visited = HashSet::with_capacity(64);
    let mut worst = Confidence::High;

    while let Some(id) = stack.pop() {
        if visited.len() >= MAX_CHAIN_NODES || !visited.insert(id) {
            return Confidence::Unknown;
        }
        let Some((acquisition, recovery, derived_from)) = lookup(id) else {
            return Confidence::Unknown;
        };
        worst = worst.min(base_confidence(acquisition, recovery));
        match derived_from {
            DerivedFrom::None => {}
            DerivedFrom::Single(parent) => stack.push(parent),
            DerivedFrom::Merged(parents, _reason) => stack.extend(parents.iter().copied()),
        }
    }
    worst
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::ids::ProvenanceId as Id;
    use std::collections::HashMap;

    fn id(raw: u32) -> ProvenanceId {
        Id::from_raw(raw)
    }

    #[test]
    fn base_confidence_ranks_carved_below_allocated_image_read() {
        assert!(
            base_confidence(Acquisition::ImageRead, Recovery::Carved)
                < base_confidence(Acquisition::ImageRead, Recovery::Allocated)
        );
    }

    #[test]
    fn weakest_link_dominates_the_chain() {
        // High <- Medium <- High : overall must be Medium, not High.
        let mut records = HashMap::new();
        records.insert(id(0), (Acquisition::ImageRead, Recovery::Allocated, DerivedFrom::None));
        records.insert(
            id(1),
            (Acquisition::LiveApi, Recovery::Allocated, DerivedFrom::Single(id(0))),
        );
        records.insert(
            id(2),
            (Acquisition::ImageRead, Recovery::Allocated, DerivedFrom::Single(id(1))),
        );
        let confidence = fold_chain_confidence(id(2), |i| records.get(&i).cloned());
        assert_eq!(confidence, Confidence::Medium);
    }

    #[test]
    fn cycle_terminates_and_degrades_to_unknown() {
        let mut records = HashMap::new();
        records.insert(
            id(0),
            (Acquisition::ImageRead, Recovery::Allocated, DerivedFrom::Single(id(1))),
        );
        records.insert(
            id(1),
            (Acquisition::ImageRead, Recovery::Allocated, DerivedFrom::Single(id(0))),
        );
        let confidence = fold_chain_confidence(id(0), |i| records.get(&i).cloned());
        assert_eq!(confidence, Confidence::Unknown);
    }

    #[test]
    fn dangling_reference_degrades_to_unknown_instead_of_panicking() {
        let records: HashMap<ProvenanceId, (Acquisition, Recovery, DerivedFrom)> = HashMap::new();
        let confidence = fold_chain_confidence(id(0), |i| records.get(&i).cloned());
        assert_eq!(confidence, Confidence::Unknown);
    }

    #[test]
    fn merge_folds_across_every_retained_parent() {
        let mut records = HashMap::new();
        records.insert(id(0), (Acquisition::ImageRead, Recovery::Allocated, DerivedFrom::None));
        records.insert(id(1), (Acquisition::ImageRead, Recovery::Carved, DerivedFrom::None));
        records.insert(
            id(2),
            (
                Acquisition::ImageRead,
                Recovery::Allocated,
                DerivedFrom::Merged(Box::new([id(0), id(1)]), super::super::model::MergeReason::Reconciliation),
            ),
        );
        let confidence = fold_chain_confidence(id(2), |i| records.get(&i).cloned());
        assert_eq!(confidence, Confidence::Low);
    }
}
