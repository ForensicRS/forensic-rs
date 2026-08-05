//! Provenance-aware serialization.
//!
//! Bare [`ProvenanceId`]s are meaningless without the store that resolves
//! them (see `ids.rs` — they deliberately have no `Serialize` impl at all).
//! Exactly two boundary modes exist instead, and both take the store as a
//! mandatory argument, so there is no accidental lossy path:
//!
//! - [`expand`] — inlines the full, human-readable provenance chain for one
//!   id, for reports.
//! - [`ProvenanceStore::to_side_table`]/[`ProvenanceStore::from_side_table`] —
//!   a normalized side table alongside the artifact table, for machine
//!   pipelines.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

#[cfg(test)]
use super::anomalies::Anomalies;
#[cfg(test)]
use super::confidence::Confidence;
use super::ids::ProvenanceId;
use super::model::{Acquisition, DerivedFrom, MergeReason, Recovery, SourceKey};
use super::store::ProvenanceStore;

#[derive(Debug, Clone, Serialize, Deserialize)]
enum DerivedFromDto {
    None,
    Single(u32),
    Merged(Vec<u32>, MergeReason),
}

impl DerivedFromDto {
    fn from_model(derived_from: &DerivedFrom) -> Self {
        match derived_from {
            DerivedFrom::None => DerivedFromDto::None,
            DerivedFrom::Single(id) => DerivedFromDto::Single(id.raw()),
            DerivedFrom::Merged(ids, reason) => {
                DerivedFromDto::Merged(ids.iter().map(|id| id.raw()).collect(), *reason)
            }
        }
    }

    fn into_model(self) -> DerivedFrom {
        match self {
            DerivedFromDto::None => DerivedFrom::None,
            DerivedFromDto::Single(raw) => DerivedFrom::Single(ProvenanceId::from_raw(raw)),
            DerivedFromDto::Merged(raws, reason) => DerivedFrom::Merged(
                raws.into_iter().map(ProvenanceId::from_raw).collect(),
                reason,
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProvenanceRecordDto {
    source: u32,
    acquisition: Acquisition,
    recovery: Recovery,
    derived_from: DerivedFromDto,
}

/// A normalized, deterministic side table for an entire [`ProvenanceStore`]:
/// every interned source and every record, in insertion order — never in
/// `HashMap` iteration order, which is what makes serializing the same store
/// twice produce byte-identical output.
///
/// `tool_version`/`model_version` travel with the table: diffing a re-run
/// months later is only meaningful if you know what changed about the tool
/// that produced it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceSideTable {
    pub tool_version: String,
    pub model_version: u32,
    sources: Vec<SourceKey>,
    records: Vec<ProvenanceRecordDto>,
}

impl ProvenanceStore {
    /// Exports the entire store as a normalized side table.
    pub fn to_side_table(
        &self,
        tool_version: impl Into<String>,
        model_version: u32,
    ) -> ProvenanceSideTable {
        let inner = self.lock();
        ProvenanceSideTable {
            tool_version: tool_version.into(),
            model_version,
            sources: inner.sources.clone(),
            records: inner
                .records
                .iter()
                .map(|record| ProvenanceRecordDto {
                    source: record.source.raw(),
                    acquisition: record.acquisition,
                    recovery: record.recovery,
                    derived_from: DerivedFromDto::from_model(&record.derived_from),
                })
                .collect(),
        }
    }

    /// Rebuilds a store from a previously exported side table.
    ///
    /// This does not validate that every `source`/`derived_from` reference in
    /// `table` is in bounds — a table from an untrusted or corrupted source
    /// can contain dangling or cyclic references. That is intentional:
    /// per "divergence is evidence, not error", a malformed table doesn't
    /// fail to load; [`ProvenanceStore::confidence`] and [`expand`] both
    /// degrade gracefully (to [`Confidence::Unknown`] / a truncated chain)
    /// the first time such a reference is actually resolved, rather than
    /// rejecting the whole store up front.
    pub fn from_side_table(table: ProvenanceSideTable) -> Self {
        use super::model::Provenance;

        let store = ProvenanceStore::new();
        let mut inner = store.lock();
        inner.sources = table.sources;
        inner.records = table
            .records
            .into_iter()
            .map(|dto| Provenance {
                source: super::ids::SourceId::from_raw(dto.source),
                acquisition: dto.acquisition,
                recovery: dto.recovery,
                derived_from: dto.derived_from.into_model(),
            })
            .collect();
        drop(inner);
        store
    }
}

/// The fully resolved, human-readable expansion of one provenance chain.
#[derive(Debug, Clone, Serialize)]
pub struct ExpandedProvenance {
    pub source: SourceKey,
    pub acquisition: Acquisition,
    pub recovery: Recovery,
    pub derived_from: ExpandedDerivedFrom,
}

#[derive(Debug, Clone, Serialize)]
pub enum ExpandedDerivedFrom {
    None,
    Single(Box<ExpandedProvenance>),
    Merged(Vec<ExpandedProvenance>, MergeReason),
    /// The chain was cut short: a revisited id (a cycle) or a dangling
    /// reference was encountered while expanding a parent. The rest of the
    /// chain beyond this point could not be resolved.
    Truncated,
}

/// Recursively resolves `id` against `store` into a full, human-facing
/// report of its provenance chain. Returns `None` only if `id` itself doesn't
/// resolve; a broken *ancestor* instead surfaces as
/// [`ExpandedDerivedFrom::Truncated`] at that point in the chain, so a report
/// for a mostly-healthy store still renders.
///
/// Cycle-guarded: each id is expanded at most once across the whole call,
/// mirroring [`super::ProvenanceStore::confidence`]'s guard against a
/// malformed/deserialized store containing a `derived_from` cycle.
pub fn expand(store: &ProvenanceStore, id: ProvenanceId) -> Option<ExpandedProvenance> {
    let mut visited = HashSet::new();
    expand_inner(store, id, &mut visited)
}

fn expand_inner(
    store: &ProvenanceStore,
    id: ProvenanceId,
    visited: &mut HashSet<ProvenanceId>,
) -> Option<ExpandedProvenance> {
    if !visited.insert(id) {
        return None;
    }
    let snapshot = store.get(id)?;
    let derived_from = match snapshot.derived_from {
        DerivedFrom::None => ExpandedDerivedFrom::None,
        DerivedFrom::Single(parent) => match expand_inner(store, parent, visited) {
            Some(expanded) => ExpandedDerivedFrom::Single(Box::new(expanded)),
            None => ExpandedDerivedFrom::Truncated,
        },
        DerivedFrom::Merged(parents, reason) => {
            let expanded_parents: Vec<_> = parents
                .iter()
                .filter_map(|parent| expand_inner(store, *parent, visited))
                .collect();
            ExpandedDerivedFrom::Merged(expanded_parents, reason)
        }
    };
    Some(ExpandedProvenance {
        source: snapshot.source,
        acquisition: snapshot.acquisition,
        recovery: snapshot.recovery,
        derived_from,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::model::SourceKey;

    #[test]
    fn round_trip_through_side_table_is_deterministic() {
        let store = ProvenanceStore::new();
        let source = store.register_source(SourceKey::Path("C:\\$MFT".to_string()));
        let a = source.mint(Acquisition::ImageRead, Recovery::Allocated);
        let _b = store.derive(a, Recovery::Slack);

        let table = store.to_side_table("forensic-rs-test", 1);
        let json_first = serde_json::to_string(&table).unwrap();

        let restored = ProvenanceStore::from_side_table(table);
        let table_again = restored.to_side_table("forensic-rs-test", 1);
        let json_second = serde_json::to_string(&table_again).unwrap();

        assert_eq!(json_first, json_second);
    }

    #[test]
    fn from_side_table_preserves_confidence() {
        let store = ProvenanceStore::new();
        let source = store.register_source(SourceKey::Synthetic("test".to_string()));
        let a = source.mint(Acquisition::ImageRead, Recovery::Allocated);
        let b = store.derive(a, Recovery::Carved);

        let table = store.to_side_table("t", 1);
        let restored = ProvenanceStore::from_side_table(table);
        assert_eq!(
            restored.confidence(b, &Anomalies::default()),
            Confidence::Low
        );
    }

    #[test]
    fn expand_walks_the_full_chain() {
        let store = ProvenanceStore::new();
        let source = store.register_source(SourceKey::Path("C:\\$MFT".to_string()));
        let a = source.mint(Acquisition::ImageRead, Recovery::Allocated);
        let b = store.derive(a, Recovery::Slack);

        let expanded = expand(&store, b).unwrap();
        assert_eq!(expanded.recovery, Recovery::Slack);
        match expanded.derived_from {
            ExpandedDerivedFrom::Single(parent) => {
                assert_eq!(parent.recovery, Recovery::Allocated);
                assert!(matches!(parent.derived_from, ExpandedDerivedFrom::None));
            }
            other => panic!("expected Single, got {other:?}"),
        }
    }

    #[test]
    fn expand_of_a_hand_built_cycle_truncates_instead_of_hanging() {
        let store = ProvenanceStore::new();
        {
            use crate::provenance::ids::SourceId;
            use crate::provenance::model::Provenance;
            let mut inner = store.lock();
            inner.sources.push(SourceKey::Synthetic("cycle".to_string()));
            inner.records.push(Provenance {
                source: SourceId::from_raw(0),
                acquisition: Acquisition::ImageRead,
                recovery: Recovery::Allocated,
                derived_from: DerivedFrom::Single(ProvenanceId::from_raw(1)),
            });
            inner.records.push(Provenance {
                source: SourceId::from_raw(0),
                acquisition: Acquisition::ImageRead,
                recovery: Recovery::Allocated,
                derived_from: DerivedFrom::Single(ProvenanceId::from_raw(0)),
            });
        }
        let expanded = expand(&store, ProvenanceId::from_raw(0)).unwrap();
        assert!(matches!(expanded.derived_from, ExpandedDerivedFrom::Single(_)));
        if let ExpandedDerivedFrom::Single(parent) = expanded.derived_from {
            assert!(matches!(parent.derived_from, ExpandedDerivedFrom::Truncated));
        }
    }
}
