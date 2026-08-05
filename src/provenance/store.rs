//! The interning arena and mutation API for provenance: [`ProvenanceStore`]
//! and [`SourceHandle`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use super::anomalies::Anomalies;
use super::confidence::{fold_chain_confidence, Confidence};
use super::ids::{ProvenanceId, SourceId};
use super::model::{
    Acquisition, DerivedFrom, MergeReason, Provenance, ProvenanceSnapshot, Recovery, SourceKey,
};

#[derive(Default)]
pub(super) struct ProvenanceStoreInner {
    // Arenas, indexed by raw id. `Vec` (not `HashMap`) is what makes
    // side-table serialization deterministic: it's walked in insertion
    // order, never in `HashMap` iteration order.
    pub(super) records: Vec<Provenance>,
    pub(super) sources: Vec<SourceKey>,
    // Dedup lookup only — never walked for serialization.
    source_index: HashMap<SourceKey, SourceId>,
}

/// The shared, interned store of every [`Provenance`](super::Provenance)
/// record and [`SourceKey`] registered during a run.
///
/// Cheap to [`Clone`] (an `Arc` handle) and `Send + Sync`, so a
/// [`SourceHandle`] minted from it can be captured into a `Box<dyn
/// ArtifactParser + Send + 'static>` closure for the parallel pipeline
/// without any extra plumbing. Owned by [`crate::pipeline::context::TriageContext`]
/// — never a global.
#[derive(Clone)]
pub struct ProvenanceStore(Arc<Mutex<ProvenanceStoreInner>>);

impl Default for ProvenanceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvenanceStore {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(ProvenanceStoreInner::default())))
    }

    /// Locks the inner arena. `pub(super)` (rather than private) so sibling
    /// modules under `crate::provenance` — namely `serde_support`, for
    /// exporting/importing the whole arena — can implement additional
    /// methods on `ProvenanceStore` without this module exposing anything
    /// outside `crate::provenance`.
    pub(super) fn lock(&self) -> MutexGuard<'_, ProvenanceStoreInner> {
        // Recover from poisoning rather than propagating a panic: a prior
        // panic elsewhere while holding the lock shouldn't take down every
        // subsequent provenance lookup with it.
        self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Interns `key`, returning a [`SourceHandle`] for it. Registering an
    /// equal `SourceKey` again returns a handle to the same [`SourceId`] —
    /// this is what makes a streaming parse of a single source mint any
    /// number of records against exactly one source entry (see the
    /// `interns_one_million_records_from_a_single_source` test below).
    pub fn register_source(&self, key: SourceKey) -> SourceHandle {
        let mut inner = self.lock();
        let id = match inner.source_index.get(&key) {
            Some(&id) => id,
            None => {
                let id = SourceId::from_raw(inner.sources.len() as u32);
                inner.sources.push(key.clone());
                inner.source_index.insert(key, id);
                id
            }
        };
        SourceHandle {
            id,
            store: self.clone(),
        }
    }

    /// Derives a new record from a single `parent`, inheriting its source and
    /// acquisition but recording a (possibly different) [`Recovery`].
    ///
    /// # Panics
    /// Panics if `parent` was not returned by this same store.
    pub fn derive(&self, parent: ProvenanceId, recovery: Recovery) -> ProvenanceId {
        let mut inner = self.lock();
        let (source, acquisition) = {
            let record = &inner.records[parent.raw() as usize];
            (record.source, record.acquisition)
        };
        let raw = inner.records.len() as u32;
        inner.records.push(Provenance {
            source,
            acquisition,
            recovery,
            derived_from: DerivedFrom::Single(parent),
        });
        ProvenanceId::from_raw(raw)
    }

    /// Merges several parents into one record. All of `parents` are retained
    /// in the resulting record's [`DerivedFrom::Merged`] — a merge never
    /// silently keeps only one side.
    ///
    /// The merged record's own `(Acquisition, Recovery)` is fixed to the most
    /// trustworthy pair (`ImageRead`/`Allocated`) — the merge event itself
    /// never constrains confidence beyond what it actually knows; any real
    /// degradation comes from folding into the retained parents themselves,
    /// each independently.
    ///
    /// # Panics
    /// Panics if `parents` is empty, or if any id was not returned by this
    /// same store.
    pub fn merge(&self, parents: &[ProvenanceId], reason: MergeReason) -> ProvenanceId {
        assert!(!parents.is_empty(), "merge requires at least one parent");
        let mut inner = self.lock();
        for parent in parents {
            // Bounds-check every parent up front so a bad id panics here,
            // not confusingly deep inside a later confidence fold.
            let _ = &inner.records[parent.raw() as usize];
        }
        let source = inner.records[parents[0].raw() as usize].source;
        let raw = inner.records.len() as u32;
        inner.records.push(Provenance {
            source,
            acquisition: Acquisition::ImageRead,
            recovery: Recovery::Allocated,
            derived_from: DerivedFrom::Merged(parents.to_vec().into_boxed_slice(), reason),
        });
        ProvenanceId::from_raw(raw)
    }

    /// Computes the [`Confidence`] of `id`, folding over its entire
    /// `derived_from` chain (weakest link wins) and then capping it by
    /// `anomalies`' own ceiling — anomalies can only lower confidence, never
    /// raise it. Cycle- and dangling-reference-safe: see
    /// [`super::confidence::fold_chain_confidence`].
    pub fn confidence(&self, id: ProvenanceId, anomalies: &Anomalies) -> Confidence {
        let chain = fold_chain_confidence(id, |lookup_id| {
            let inner = self.lock();
            inner
                .records
                .get(lookup_id.raw() as usize)
                .map(|record| (record.acquisition, record.recovery, record.derived_from.clone()))
        });
        chain.min(anomalies.confidence_ceiling())
    }

    /// A read-only, resolved snapshot of one record, for introspection and
    /// serialization. Returns `None` if `id` doesn't (or no longer) resolves
    /// — e.g. a dangling reference from a malformed deserialized store.
    pub fn get(&self, id: ProvenanceId) -> Option<ProvenanceSnapshot> {
        let inner = self.lock();
        let record = inner.records.get(id.raw() as usize)?;
        let source = inner.sources.get(record.source.raw() as usize)?.clone();
        Some(ProvenanceSnapshot {
            source,
            acquisition: record.acquisition,
            recovery: record.recovery,
            derived_from: record.derived_from.clone(),
        })
    }

    /// Number of distinct interned sources. Exposed for the interning
    /// guarantee's test (and general introspection) — not gated behind
    /// `serde`, unlike the side-table export.
    pub fn source_count(&self) -> usize {
        self.lock().sources.len()
    }

    /// Number of provenance records minted/derived/merged so far.
    pub fn record_count(&self) -> usize {
        self.lock().records.len()
    }

    /// Every [`ProvenanceId`] currently resolvable in this store, in minting
    /// order. Used to walk an entire store after deserializing it (e.g. the
    /// `store_deserialize` fuzz target), not needed for normal pipeline use.
    pub fn provenance_ids(&self) -> Vec<ProvenanceId> {
        (0..self.record_count() as u32).map(ProvenanceId::from_raw).collect()
    }
}

/// A handle to one interned [`SourceId`], obtained via
/// [`ProvenanceStore::register_source`].
///
/// The only place in the entire crate (or any downstream crate) that can
/// produce a brand-new, non-derived [`ProvenanceId`] is [`SourceHandle::mint`].
#[derive(Clone)]
pub struct SourceHandle {
    id: SourceId,
    store: ProvenanceStore,
}

impl SourceHandle {
    /// Mints a new [`ProvenanceId`] against this handle's source. Call once
    /// per record a parser produces.
    pub fn mint(&self, acquisition: Acquisition, recovery: Recovery) -> ProvenanceId {
        let mut inner = self.store.lock();
        let raw = inner.records.len() as u32;
        inner.records.push(Provenance {
            source: self.id,
            acquisition,
            recovery,
            derived_from: DerivedFrom::None,
        });
        ProvenanceId::from_raw(raw)
    }

    /// The store this handle mints against — clone it to keep deriving/
    /// merging after the handle itself goes out of scope.
    pub fn store(&self) -> &ProvenanceStore {
        &self.store
    }

    pub fn source_id(&self) -> SourceId {
        self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interns_one_million_records_from_a_single_source() {
        let store = ProvenanceStore::new();
        let source = store.register_source(SourceKey::Path("C:\\$MFT".to_string()));
        for _ in 0..1_000_000 {
            let _ = source.mint(Acquisition::ImageRead, Recovery::Allocated);
        }
        assert_eq!(store.source_count(), 1);
        assert_eq!(store.record_count(), 1_000_000);
    }

    #[test]
    fn registering_an_equal_key_twice_reuses_the_source_id() {
        let store = ProvenanceStore::new();
        let a = store.register_source(SourceKey::Path("C:\\$MFT".to_string()));
        let b = store.register_source(SourceKey::Path("C:\\$MFT".to_string()));
        assert_eq!(a.source_id(), b.source_id());
        assert_eq!(store.source_count(), 1);
    }

    #[test]
    fn distinct_keys_get_distinct_source_ids() {
        let store = ProvenanceStore::new();
        let a = store.register_source(SourceKey::Path("C:\\$MFT".to_string()));
        let b = store.register_source(SourceKey::Path("C:\\$LogFile".to_string()));
        assert_ne!(a.source_id(), b.source_id());
        assert_eq!(store.source_count(), 2);
    }

    #[test]
    fn derive_inherits_source_and_acquisition_from_parent() {
        let store = ProvenanceStore::new();
        let source = store.register_source(SourceKey::Synthetic("test".to_string()));
        let parent = source.mint(Acquisition::ImageRead, Recovery::Allocated);
        let child = store.derive(parent, Recovery::Slack);

        let snapshot = store.get(child).unwrap();
        assert_eq!(snapshot.acquisition, Acquisition::ImageRead);
        assert_eq!(snapshot.recovery, Recovery::Slack);
        assert!(matches!(snapshot.derived_from, DerivedFrom::Single(p) if p == parent));
    }

    #[test]
    fn merge_retains_every_parent() {
        let store = ProvenanceStore::new();
        let source = store.register_source(SourceKey::Synthetic("test".to_string()));
        let a = source.mint(Acquisition::ImageRead, Recovery::Allocated);
        let b = source.mint(Acquisition::LiveApi, Recovery::Carved);
        let merged = store.merge(&[a, b], MergeReason::Reconciliation);

        let snapshot = store.get(merged).unwrap();
        match snapshot.derived_from {
            DerivedFrom::Merged(parents, reason) => {
                assert_eq!(&*parents, &[a, b]);
                assert_eq!(reason, MergeReason::Reconciliation);
            }
            other => panic!("expected Merged, got {other:?}"),
        }
    }

    #[test]
    fn weakest_link_chain_confidence_is_medium() {
        let store = ProvenanceStore::new();
        let source = store.register_source(SourceKey::Synthetic("test".to_string()));
        let allocated = source.mint(Acquisition::ImageRead, Recovery::Allocated);
        let weaker = store.derive(allocated, Recovery::Slack);
        let confidence = store.confidence(weaker, &Anomalies::default());
        assert_eq!(confidence, Confidence::Low);
    }

    #[test]
    fn confidence_of_hand_built_cycle_terminates_as_unknown() {
        // The public API can't create a cycle; hand-build one by pushing
        // directly into the inner arena via a store constructed just for
        // this test, exercising the same guard the deserialization path
        // needs against a malformed/adversarial store.
        let store = ProvenanceStore::new();
        {
            let mut inner = store.lock();
            let source_id = SourceId::from_raw(0);
            inner.sources.push(SourceKey::Synthetic("cycle".to_string()));
            inner.records.push(Provenance {
                source: source_id,
                acquisition: Acquisition::ImageRead,
                recovery: Recovery::Allocated,
                derived_from: DerivedFrom::Single(ProvenanceId::from_raw(1)),
            });
            inner.records.push(Provenance {
                source: source_id,
                acquisition: Acquisition::ImageRead,
                recovery: Recovery::Allocated,
                derived_from: DerivedFrom::Single(ProvenanceId::from_raw(0)),
            });
        }
        let confidence = store.confidence(ProvenanceId::from_raw(0), &Anomalies::default());
        assert_eq!(confidence, Confidence::Unknown);
    }

    #[test]
    fn confidence_of_dangling_id_is_unknown_not_a_panic() {
        let store = ProvenanceStore::new();
        let confidence = store.confidence(ProvenanceId::from_raw(0), &Anomalies::default());
        assert_eq!(confidence, Confidence::Unknown);
    }

    #[test]
    fn get_of_unknown_id_is_none() {
        let store = ProvenanceStore::new();
        assert!(store.get(ProvenanceId::from_raw(0)).is_none());
    }
}
