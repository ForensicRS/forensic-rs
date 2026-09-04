//! A timeline that is actually a timeline.
//!
//! [`TimelineSink`](super::sinks::TimelineSink) tracks earliest/latest
//! bounds and counts — it never stores a record.
//! [`JsonlTimelineSink`](super::sinks::JsonlTimelineSink) appends in
//! emission order and explicitly declines to sort. So the crate named
//! after triage had no timeline: nothing ordered records, nothing deduped
//! a re-parse of the same evidence, nothing gave a record a stable
//! identity across two runs.
//!
//! [`EventId`] and [`TimelineStore`] close that gap. [`InMemoryTimelineStore`]
//! is the only implementation core ships — bounded by available memory, no
//! spill-to-disk external merge sort. A `sqlite`/`parquet`-backed
//! `TimelineStore` for genuinely large timelines is a downstream concern.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use crate::core::fnv1a64;
use crate::data::ForensicData;
use crate::err::ForensicResult;
use crate::field::{Field, Text};
use crate::pipeline::traits::TriageSink;
use crate::provenance::{Locus, ProvenanceStore, SourceKey};
use crate::traits::forensic::{TimeContext, TimelineData};
use crate::utils::time::ForensicTimestamp;

/// A stable identity for one timeline event, derived from
/// `(evidence_id, source_key, locus, projection_kind)` rather than assigned
/// by a sequence counter.
///
/// The point is reproducibility across runs: re-processing the same
/// evidence (after a parser bug fix, say) must converge on the same event
/// identities, not mint new ones every time — [`crate::provenance::ProvenanceId`]
/// can't serve this role, since it's a dense per-run index that differs
/// between two runs of identical evidence.
///
/// `source_key`/`locus` are hashed via their `Debug` representation rather
/// than a hand-written per-variant encoding — both are plain, deterministic
/// enums with no floating-point or hash-map-ordered fields, so `Debug`
/// output is stable across runs and this avoids a second serialization
/// scheme existing only for hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventId(u64);

impl EventId {
    /// `evidence_id` identifies which evidence item the record came from
    /// (e.g. an [`crate::evidence::EvidenceItemId`]'s string form).
    /// `projection_kind` names which fact this event represents when a
    /// single record yields more than one timeline event (e.g. an MFT
    /// entry's `$SI` created time vs. its `$FN` created time) — pass a
    /// stable tag such as `"si_created"`/`"fn_created"`, or the timestamp
    /// field name for the single-timestamp-per-record case.
    pub fn new(evidence_id: &str, source_key: &SourceKey, locus: Locus, projection_kind: &str) -> Self {
        let mut buf = Vec::new();
        buf.extend_from_slice(evidence_id.as_bytes());
        buf.push(0);
        buf.extend_from_slice(format!("{source_key:?}").as_bytes());
        buf.push(0);
        buf.extend_from_slice(format!("{locus:?}").as_bytes());
        buf.push(0);
        buf.extend_from_slice(projection_kind.as_bytes());
        Self(fnv1a64(&buf))
    }

    /// The raw hash, for logging/dedup-key purposes only — never assume any
    /// meaning beyond equality/ordering.
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// Whether a [`TimelineStore::insert`] call added a new event or found an
/// identical [`EventId`] already present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    Inserted,
    Duplicate,
}

/// Stores timeline events, deduped by [`EventId`], with ordered iteration
/// by timestamp.
///
/// `Send + Sync` so a store can be shared (behind an `Arc`) across a
/// parallel pipeline run's worker threads via a sink each one holds.
pub trait TimelineStore: Send + Sync {
    fn insert(&self, id: EventId, event: TimelineData) -> InsertOutcome;

    /// Every stored event, ordered by [`TimelineData::time`] ascending,
    /// ties broken by `EventId` for a total, reproducible order.
    ///
    /// Takes `&self` (not `&mut self`) and returns an iterator borrowing
    /// `'_` from it, so a streaming/spill-backed implementation can hold a
    /// cursor open for the duration of iteration instead of materializing
    /// everything up front — [`InMemoryTimelineStore`] happens not to need
    /// that, but the trait leaves room for one that does.
    fn iter_ordered(&self) -> Box<dyn Iterator<Item = (EventId, TimelineData)> + '_>;

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Default)]
struct InMemoryTimelineStoreInner {
    ordered: BTreeMap<(ForensicTimestamp, EventId), TimelineData>,
    seen: BTreeSet<EventId>,
}

/// The only [`TimelineStore`] core ships: an in-memory, `BTreeMap`-ordered
/// store. Bounded by available memory — no spill-to-disk. For a timeline
/// too large to hold in memory, implement [`TimelineStore`] over `sqlite`
/// or `parquet` downstream; the trait boundary is exactly where that slots
/// in.
#[derive(Default)]
pub struct InMemoryTimelineStore {
    inner: Mutex<InMemoryTimelineStoreInner>,
}

impl InMemoryTimelineStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TimelineStore for InMemoryTimelineStore {
    fn insert(&self, id: EventId, event: TimelineData) -> InsertOutcome {
        let mut inner = self.inner.lock().expect("InMemoryTimelineStore poisoned");
        if !inner.seen.insert(id) {
            return InsertOutcome::Duplicate;
        }
        inner.ordered.insert((event.time, id), event);
        InsertOutcome::Inserted
    }

    fn iter_ordered(&self) -> Box<dyn Iterator<Item = (EventId, TimelineData)> + '_> {
        let inner = self.inner.lock().expect("InMemoryTimelineStore poisoned");
        let snapshot: Vec<(EventId, TimelineData)> = inner
            .ordered
            .iter()
            .map(|((_, id), data)| (*id, data.clone()))
            .collect();
        Box::new(snapshot.into_iter())
    }

    fn len(&self) -> usize {
        self.inner.lock().expect("InMemoryTimelineStore poisoned").ordered.len()
    }
}

/// A [`TriageSink`] that stores full records into a [`TimelineStore`],
/// ordered and deduped — the sink `TimelineSink`'s own docs point to
/// ("implement a custom `TriageSink` to write findings to disk"), now
/// shipped.
///
/// Reads one configurable `Field::Date` field per record, the same
/// single-timestamp-per-record convention `TimelineSink` already uses.
/// Resolves each record's [`SourceKey`] from `provenance` (its
/// [`crate::provenance::ProvenanceId`]) to build a stable [`EventId`] —
/// requires a *shared* store, i.e. one configured via
/// `TriagePipelineBuilder::context`/`ParallelPipelineBuilder::context`,
/// not each task's own independent default (see that fix's `TriageContext`
/// docs). A record whose provenance doesn't resolve against `provenance`
/// (an unshared-context run) is counted but not inserted.
///
/// `Locus` is not yet available at the sink layer — no pipeline stage
/// currently attaches one to a `ForensicData` — so every `EventId` here
/// uses [`Locus::Api`] uniformly. This still dedupes correctly whenever
/// `SourceKey` resolves consistently (the common case); true byte-level
/// locus precision needs a projector stage that attaches a real `Locus`
/// per record, a further phase.
pub struct TimelineRecordSink<S: TimelineStore> {
    store: Arc<S>,
    provenance: ProvenanceStore,
    timestamp_field: Text,
    evidence_id: Text,
    inserted: u64,
    duplicates: u64,
    missing_timestamp: u64,
    unresolved_provenance: u64,
}

impl<S: TimelineStore> TimelineRecordSink<S> {
    pub fn new(
        store: Arc<S>,
        provenance: ProvenanceStore,
        timestamp_field: impl Into<Text>,
        evidence_id: impl Into<Text>,
    ) -> Self {
        Self {
            store,
            provenance,
            timestamp_field: timestamp_field.into(),
            evidence_id: evidence_id.into(),
            inserted: 0,
            duplicates: 0,
            missing_timestamp: 0,
            unresolved_provenance: 0,
        }
    }

    pub fn inserted(&self) -> u64 {
        self.inserted
    }

    pub fn duplicates(&self) -> u64 {
        self.duplicates
    }

    pub fn missing_timestamp(&self) -> u64 {
        self.missing_timestamp
    }

    pub fn unresolved_provenance(&self) -> u64 {
        self.unresolved_provenance
    }
}

impl<S: TimelineStore> TriageSink for TimelineRecordSink<S> {
    fn name(&self) -> &str {
        "timeline_record_sink"
    }

    fn on_data(&mut self, data: &ForensicData) -> ForensicResult<()> {
        let Some(Field::Date(ts)) = data.field(&self.timestamp_field) else {
            self.missing_timestamp += 1;
            return Ok(());
        };
        let Some(snapshot) = self.provenance.get(data.provenance()) else {
            self.unresolved_provenance += 1;
            return Ok(());
        };
        let id = EventId::new(&self.evidence_id, &snapshot.source, Locus::Api, &self.timestamp_field);
        let event = TimelineData {
            time: *ts,
            data: data.clone(),
            time_context: TimeContext::default(),
        };
        match self.store.insert(id, event) {
            InsertOutcome::Inserted => self.inserted += 1,
            InsertOutcome::Duplicate => self.duplicates += 1,
        }
        Ok(())
    }

    fn on_finding(&mut self, _finding: &crate::pipeline::finding::Finding) -> ForensicResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::Artifact;
    use crate::provenance::{Acquisition, Recovery};

    fn ts(secs: i64) -> ForensicTimestamp {
        ForensicTimestamp::from_unix_secs(secs)
    }

    fn sample_event(secs: i64) -> TimelineData {
        let store = ProvenanceStore::new();
        let source = store.register_source(SourceKey::Synthetic("x".to_string()));
        let id = source.mint(Acquisition::LiveApi, Recovery::Allocated);
        TimelineData {
            time: ts(secs),
            data: ForensicData::new("host", Artifact::Unknown, id),
            time_context: TimeContext::Creation,
        }
    }

    #[test]
    fn event_id_is_deterministic_across_calls() {
        let key = SourceKey::Path("C:/evidence.zip".to_string());
        let a = EventId::new("host1", &key, Locus::Api, "created");
        let b = EventId::new("host1", &key, Locus::Api, "created");
        assert_eq!(a, b);
    }

    #[test]
    fn event_id_differs_when_any_component_differs() {
        let key = SourceKey::Path("C:/evidence.zip".to_string());
        let base = EventId::new("host1", &key, Locus::Api, "created");
        assert_ne!(base, EventId::new("host2", &key, Locus::Api, "created"));
        assert_ne!(
            base,
            EventId::new("host1", &SourceKey::Path("other.zip".to_string()), Locus::Api, "created")
        );
        assert_ne!(base, EventId::new("host1", &key, Locus::Api, "modified"));
        assert_ne!(
            base,
            EventId::new("host1", &key, Locus::Ntfs { entry: 1, sequence: 1, attribute: 0, offset: 0 }, "created")
        );
    }

    #[test]
    fn store_orders_by_timestamp_regardless_of_insertion_order() {
        let store = InMemoryTimelineStore::new();
        let key = SourceKey::Path("evidence".to_string());
        store.insert(EventId::new("h", &key, Locus::Api, "c"), sample_event(300));
        store.insert(EventId::new("h", &key, Locus::Api, "a"), sample_event(100));
        store.insert(EventId::new("h", &key, Locus::Api, "b"), sample_event(200));

        let times: Vec<i64> = store.iter_ordered().map(|(_, e)| e.time.to_unix_secs()).collect();
        assert_eq!(times, vec![100, 200, 300]);
        assert_eq!(store.len(), 3);
    }

    #[test]
    fn store_dedupes_by_event_id_not_by_content() {
        let store = InMemoryTimelineStore::new();
        let key = SourceKey::Path("evidence".to_string());
        let id = EventId::new("h", &key, Locus::Api, "created");

        assert_eq!(store.insert(id, sample_event(100)), InsertOutcome::Inserted);
        // Same id, different (distinguishable) event content -- still a duplicate by id.
        assert_eq!(store.insert(id, sample_event(999)), InsertOutcome::Duplicate);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn reprocessing_identical_evidence_converges_instead_of_duplicating() {
        // Simulates two runs over the same evidence: same evidence_id/source_key
        // both times, so the same EventId is derived and the second run's
        // insert is recognized as a duplicate rather than appended.
        let store = InMemoryTimelineStore::new();
        let key = SourceKey::Path("evidence.zip".to_string());
        for _run in 0..2 {
            let id = EventId::new("host1", &key, Locus::Api, "created");
            store.insert(id, sample_event(100));
        }
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn timeline_record_sink_inserts_records_with_a_resolvable_timestamp() {
        let store = Arc::new(InMemoryTimelineStore::new());
        let provenance = ProvenanceStore::new();
        let source = provenance.register_source(SourceKey::Path("evidence.zip".to_string()));
        let id = source.mint(Acquisition::LiveApi, Recovery::Allocated);

        let mut sink = TimelineRecordSink::new(
            Arc::clone(&store),
            provenance.clone(),
            "@timestamp",
            "host1",
        );

        let mut data = ForensicData::new("host1", Artifact::Unknown, id);
        data.set("@timestamp", Field::Date(ts(1_700_000_000)));
        sink.on_data(&data).unwrap();

        assert_eq!(sink.inserted(), 1);
        assert_eq!(sink.missing_timestamp(), 0);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn timeline_record_sink_counts_but_does_not_insert_records_missing_a_timestamp() {
        let store = Arc::new(InMemoryTimelineStore::new());
        let provenance = ProvenanceStore::new();
        let source = provenance.register_source(SourceKey::Path("evidence.zip".to_string()));
        let id = source.mint(Acquisition::LiveApi, Recovery::Allocated);

        let mut sink = TimelineRecordSink::new(store.clone(), provenance, "@timestamp", "host1");
        let data = ForensicData::new("host1", Artifact::Unknown, id);
        sink.on_data(&data).unwrap();

        assert_eq!(sink.missing_timestamp(), 1);
        assert_eq!(sink.inserted(), 0);
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn reprocessing_the_same_record_through_the_sink_deduplicates() {
        let store = Arc::new(InMemoryTimelineStore::new());
        let provenance = ProvenanceStore::new();
        let source = provenance.register_source(SourceKey::Path("evidence.zip".to_string()));
        let id = source.mint(Acquisition::LiveApi, Recovery::Allocated);

        let mut data = ForensicData::new("host1", Artifact::Unknown, id);
        data.set("@timestamp", Field::Date(ts(1_700_000_000)));

        let mut sink = TimelineRecordSink::new(store.clone(), provenance.clone(), "@timestamp", "host1");
        sink.on_data(&data).unwrap();
        sink.on_data(&data).unwrap();

        assert_eq!(sink.inserted(), 1);
        assert_eq!(sink.duplicates(), 1);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn unshared_provenance_store_is_counted_as_unresolved_not_silently_dropped() {
        let store = Arc::new(InMemoryTimelineStore::new());
        // A record minted against a DIFFERENT store than the sink holds --
        // simulates the exact bug C-8 fixed: an unshared per-task store.
        let foreign_store = ProvenanceStore::new();
        let source = foreign_store.register_source(SourceKey::Synthetic("x".to_string()));
        let id = source.mint(Acquisition::LiveApi, Recovery::Allocated);

        let sink_store = ProvenanceStore::new();
        let mut sink = TimelineRecordSink::new(store.clone(), sink_store, "@timestamp", "host1");

        let mut data = ForensicData::new("host1", Artifact::Unknown, id);
        data.set("@timestamp", Field::Date(ts(1_700_000_000)));
        sink.on_data(&data).unwrap();

        assert_eq!(sink.unresolved_provenance(), 1);
        assert_eq!(sink.inserted(), 0);
    }

    #[allow(dead_code)]
    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn in_memory_timeline_store_is_send_and_sync() {
        assert_send_sync::<InMemoryTimelineStore>();
    }
}
