//! Cross-artifact corroboration: the payoff of the provenance model.
//!
//! Six artifacts independently saying "`evil.exe` ran" should become one
//! reconciled assertion carrying all six `ProvenanceId`s — not six
//! equal-weight rows in a flat event stream. [`FactStore`] is where that
//! reconciliation happens: every fact observed about an [`EntityId`] is an
//! **append-only observation** carrying its own `ProvenanceId`. Agreement
//! between independent sources folds their provenance into one
//! [`MergeReason::CrossSourceCorroboration`] node via
//! [`ProvenanceStore::merge`], queryable back to every source that agreed;
//! disagreement is never resolved by silently picking a side — both values
//! are retained, and the caller gets back an [`AnomalyDetail`] flagged
//! [`AnomalyFlags::SOURCE_DIVERGENCE`] to attach wherever its own output
//! already carries anomalies.
//!
//! One honest limitation: [`ProvenanceStore::confidence`]'s chain folding
//! is conservative by design — it takes the *worst* confidence across a
//! merge chain, the right call for `DerivedFrom::Single`/`Reconciliation`
//! (a value derived through an untrustworthy step must never look more
//! trustworthy than its weakest input). Applied to
//! `CrossSourceCorroboration` too, six agreeing sources today report the
//! same confidence as their weakest single source, not a boosted one.
//! Making corroboration specifically able to outrank a single weak source
//! would mean giving `MergeReason` folding semantics, a change to
//! `provenance::confidence`'s core behavior deliberately left for a future
//! pass rather than bundled in here. What this module gives you today —
//! surfacing *that* six sources agree, with all six provenance chains
//! still reachable — is the corroboration signal that reaches output; how
//! strongly it should move a numeric confidence score is left open.
//!
//! What this module deliberately does not do: temporal rule matching,
//! attack-path graph traversal, threat-intel enrichment, cross-investigation
//! frequency analysis, ML scoring. The test for what belongs here is
//! whether the answer is deterministic and derivable from the evidence
//! alone — everything past that is downstream/user territory.

use std::collections::BTreeMap;
use std::sync::Mutex;

use compact_str::CompactString;

use crate::entity::EntityId;
use crate::field::{Field, Text};
use crate::provenance::{AnomalyDetail, AnomalyFlags, MergeReason, ProvenanceId, ProvenanceStore};

/// What happened when a new value was [`FactStore::observe`]d.
#[derive(Debug, Clone)]
pub enum ObservationOutcome {
    /// The first time this (entity, fact) pair has been observed.
    First { provenance: ProvenanceId },
    /// This value agrees with every prior observation of this fact —
    /// `provenance` is a merge node folding every agreeing source together,
    /// and `agreeing_count` is how many observations (including this one)
    /// now back it.
    Corroborated {
        provenance: ProvenanceId,
        agreeing_count: usize,
    },
    /// This value disagrees with at least one prior observation of this
    /// fact. Both values are retained — see [`FactStore::facts`] — and
    /// `anomaly` is ready to fold into whatever `Anomalies` the caller's
    /// own output already tracks.
    Diverged {
        provenance: ProvenanceId,
        conflicting_value: Field,
        conflicting_provenance: ProvenanceId,
        anomaly: AnomalyDetail,
    },
}

/// One distinct value observed for a fact, and how many observations back
/// it (after corroboration merging).
#[derive(Debug, Clone)]
pub struct FactObservation {
    pub value: Field,
    pub provenance: ProvenanceId,
    pub agreeing_count: usize,
}

/// All recorded observations for one fact key about one entity. More than
/// one entry in `observations` means the fact is disputed — deliberately
/// never collapsed to a single "winning" value.
#[derive(Debug, Clone)]
pub struct FactRecord {
    pub key: Text,
    pub observations: Vec<FactObservation>,
}

impl FactRecord {
    pub fn is_disputed(&self) -> bool {
        self.observations.len() > 1
    }
}

/// Records facts about entities as append-only observations, reconciling
/// agreement and surfacing disagreement — never overwriting.
///
/// `Send + Sync` so a store can be shared across parallel pipeline workers,
/// the same way `TriageSources`' other components are.
pub trait FactStore: Send + Sync {
    /// Records one observation of `value` for `fact` about `entity`,
    /// minted from `provenance`. Compares against every prior observation
    /// of the same (entity, fact) pair already recorded, using `store` to
    /// mint the corroboration merge node on agreement.
    ///
    /// Takes `fact: Text` rather than `impl Into<Text>` deliberately — a
    /// generic parameter would make this method unavailable on `dyn
    /// FactStore`, and `Arc<dyn FactStore>` shared across parallel workers
    /// is the intended way to use this trait. Convert at the call site
    /// (`"executed".into()`) instead.
    fn observe(
        &self,
        entity: EntityId,
        fact: Text,
        value: Field,
        provenance: ProvenanceId,
        store: &ProvenanceStore,
    ) -> ObservationOutcome;

    /// Every fact recorded about `entity`, each with every distinct value
    /// observed for it (see [`FactRecord::is_disputed`]).
    fn facts(&self, entity: &EntityId) -> Vec<FactRecord>;

    /// Every entity with at least one recorded fact.
    fn entities(&self) -> Vec<EntityId>;

    fn entity_count(&self) -> usize;
}

#[derive(Debug, Clone)]
struct ValueGroup {
    value: Field,
    provenance: ProvenanceId,
    count: usize,
}

#[derive(Debug, Default)]
struct EntityFacts {
    facts: BTreeMap<Text, Vec<ValueGroup>>,
}

/// The only [`FactStore`] core ships: a plain in-memory implementation.
/// `Field` has no `Ord`/`Hash` impl (a `Field::F64` can't have one), so
/// matching an observed value against existing groups is a linear scan per
/// (entity, fact) pair — the right tradeoff here, since a single fact is
/// expected to have a handful of distinct observed values at most, never
/// thousands. A persistent (sqlite-backed, say) `FactStore` for an
/// investigation that spans collection waves over weeks is a downstream
/// concern; the trait boundary is exactly where that slots in.
#[derive(Default)]
pub struct InMemoryFactStore {
    entities: Mutex<BTreeMap<EntityId, EntityFacts>>,
}

impl InMemoryFactStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl FactStore for InMemoryFactStore {
    fn observe(
        &self,
        entity: EntityId,
        fact: Text,
        value: Field,
        provenance: ProvenanceId,
        store: &ProvenanceStore,
    ) -> ObservationOutcome {
        let mut entities = self.entities.lock().expect("InMemoryFactStore poisoned");
        let entity_facts = entities.entry(entity).or_default();
        let groups = entity_facts.facts.entry(fact.clone()).or_default();

        if let Some(group) = groups.iter_mut().find(|g| g.value == value) {
            let merged = store.merge(&[group.provenance, provenance], MergeReason::CrossSourceCorroboration);
            group.provenance = merged;
            group.count += 1;
            return ObservationOutcome::Corroborated {
                provenance: merged,
                agreeing_count: group.count,
            };
        }

        if groups.is_empty() {
            groups.push(ValueGroup {
                value,
                provenance,
                count: 1,
            });
            return ObservationOutcome::First { provenance };
        }

        let conflicting = groups[0].clone();
        groups.push(ValueGroup {
            value,
            provenance,
            count: 1,
        });
        ObservationOutcome::Diverged {
            provenance,
            conflicting_value: conflicting.value,
            conflicting_provenance: conflicting.provenance,
            anomaly: AnomalyDetail {
                kind: AnomalyFlags::SOURCE_DIVERGENCE,
                message: CompactString::from(format!(
                    "fact '{fact}' disputed: independent sources disagree on its value"
                )),
            },
        }
    }

    fn facts(&self, entity: &EntityId) -> Vec<FactRecord> {
        let entities = self.entities.lock().expect("InMemoryFactStore poisoned");
        match entities.get(entity) {
            None => Vec::new(),
            Some(entity_facts) => entity_facts
                .facts
                .iter()
                .map(|(key, groups)| FactRecord {
                    key: key.clone(),
                    observations: groups
                        .iter()
                        .map(|g| FactObservation {
                            value: g.value.clone(),
                            provenance: g.provenance,
                            agreeing_count: g.count,
                        })
                        .collect(),
                })
                .collect(),
        }
    }

    fn entities(&self) -> Vec<EntityId> {
        self.entities
            .lock()
            .expect("InMemoryFactStore poisoned")
            .keys()
            .copied()
            .collect()
    }

    fn entity_count(&self) -> usize {
        self.entities.lock().expect("InMemoryFactStore poisoned").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::{Acquisition, Recovery, SourceKey};

    fn mint(store: &ProvenanceStore, tag: &str) -> ProvenanceId {
        store
            .register_source(SourceKey::Synthetic(tag.to_string()))
            .mint(Acquisition::LiveApi, Recovery::Allocated)
    }

    #[test]
    fn first_observation_is_reported_as_first() {
        let facts = InMemoryFactStore::new();
        let store = ProvenanceStore::new();
        let entity = EntityId::host("WORKSTATION01");
        let id = mint(&store, "prefetch");

        let outcome = facts.observe(entity, "executed".into(), Field::Text("evil.exe".into()), id, &store);
        assert!(matches!(outcome, ObservationOutcome::First { .. }));
        assert_eq!(facts.entity_count(), 1);
    }

    #[test]
    fn six_agreeing_sources_corroborate_into_one_merge_chain() {
        let facts = InMemoryFactStore::new();
        let store = ProvenanceStore::new();
        let entity = EntityId::executable_by_path("WORKSTATION01", "C:/evil.exe");

        let mut last_provenance = None;
        for i in 0..6 {
            let id = mint(&store, &format!("source-{i}"));
            let outcome = facts.observe(
                entity,
                "executed".into(),
                Field::Text("true".into()),
                id,
                &store,
            );
            last_provenance = Some(match outcome {
                ObservationOutcome::First { provenance } => provenance,
                ObservationOutcome::Corroborated { provenance, agreeing_count } => {
                    assert_eq!(agreeing_count, i + 1);
                    provenance
                }
                ObservationOutcome::Diverged { .. } => panic!("all six sources agree; must not diverge"),
            });
        }

        let records = facts.facts(&entity);
        assert_eq!(records.len(), 1);
        assert!(!records[0].is_disputed());
        assert_eq!(records[0].observations[0].agreeing_count, 6);

        // The final provenance is a real merge node backed by all six
        // sources -- this is the "one assertion with six ProvenanceIds
        // behind it" the module doc promises, not six equal-weight rows.
        let snapshot = store.get(last_provenance.unwrap()).unwrap();
        match snapshot.derived_from {
            crate::provenance::DerivedFrom::Merged(ids, reason) => {
                assert_eq!(reason, MergeReason::CrossSourceCorroboration);
                assert!(ids.len() >= 2);
            }
            other => panic!("expected a Merged chain, got {other:?}"),
        }
    }

    #[test]
    fn disagreement_retains_both_values_instead_of_picking_one() {
        let facts = InMemoryFactStore::new();
        let store = ProvenanceStore::new();
        let entity = EntityId::host("WORKSTATION01");

        let id1 = mint(&store, "registry");
        facts.observe(entity, "timezone".into(), Field::Text("UTC".into()), id1, &store);

        let id2 = mint(&store, "event_log");
        let outcome = facts.observe(entity, "timezone".into(), Field::Text("EST".into()), id2, &store);

        match outcome {
            ObservationOutcome::Diverged {
                conflicting_value,
                anomaly,
                ..
            } => {
                assert_eq!(conflicting_value, Field::Text("UTC".into()));
                assert_eq!(anomaly.kind, AnomalyFlags::SOURCE_DIVERGENCE);
            }
            other => panic!("expected Diverged, got {other:?}"),
        }

        let records = facts.facts(&entity);
        assert_eq!(records.len(), 1);
        assert!(records[0].is_disputed());
        assert_eq!(records[0].observations.len(), 2);
    }

    #[test]
    fn unrelated_entities_and_facts_do_not_interfere() {
        let facts = InMemoryFactStore::new();
        let store = ProvenanceStore::new();
        let host_a = EntityId::host("HOST-A");
        let host_b = EntityId::host("HOST-B");

        facts.observe(host_a, "timezone".into(), Field::Text("UTC".into()), mint(&store, "s1"), &store);
        facts.observe(host_b, "timezone".into(), Field::Text("EST".into()), mint(&store, "s2"), &store);

        assert!(!facts.facts(&host_a)[0].is_disputed());
        assert!(!facts.facts(&host_b)[0].is_disputed());
        assert_eq!(facts.entity_count(), 2);
    }

    #[test]
    fn querying_an_unknown_entity_returns_no_facts() {
        let facts = InMemoryFactStore::new();
        assert!(facts.facts(&EntityId::host("never-seen")).is_empty());
    }
}
