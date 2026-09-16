use std::collections::BTreeMap;

use crate::{
    data::ForensicData, err::ForensicResult, field::Field, utils::time::ForensicTimestamp,
};
#[cfg(feature = "serde")]
use crate::provenance::{Confidence, ProvenanceStore};

use super::{
    finding::{Finding, FindingSeverity},
    traits::TriageSink,
};

/// A lightweight timeline sink that tracks timestamp statistics without
/// storing records in memory.
///
/// Extracts timestamps from a configurable field and maintains the earliest/
/// latest bounds plus record and missing-timestamp counts. This is safe for
/// arbitrarily large datasets because memory usage is constant.
///
/// For full record collection (e.g. writing to a file or database), implement
/// a custom `TriageSink`.
pub struct TimelineSink {
    timestamp_field: String,
    record_count: u64,
    missing_timestamp_count: u64,
    earliest: Option<ForensicTimestamp>,
    latest: Option<ForensicTimestamp>,
}

impl TimelineSink {
    pub fn new(timestamp_field: &str) -> Self {
        Self {
            timestamp_field: timestamp_field.to_string(),
            record_count: 0,
            missing_timestamp_count: 0,
            earliest: None,
            latest: None,
        }
    }

    /// Total number of records that had a valid timestamp.
    pub fn record_count(&self) -> u64 {
        self.record_count
    }

    /// Number of records that were missing the timestamp field.
    pub fn missing_timestamp_count(&self) -> u64 {
        self.missing_timestamp_count
    }

    /// Earliest timestamp seen, if any.
    pub fn earliest(&self) -> Option<ForensicTimestamp> {
        self.earliest
    }

    /// Latest timestamp seen, if any.
    pub fn latest(&self) -> Option<ForensicTimestamp> {
        self.latest
    }
}

impl TriageSink for TimelineSink {
    fn name(&self) -> &str {
        "timeline_sink"
    }

    fn on_data(&mut self, data: &ForensicData) -> ForensicResult<()> {
        if let Some(Field::Date(ft)) = data.field(&self.timestamp_field) {
            let ts: ForensicTimestamp = *ft;
            self.record_count += 1;
            self.earliest = Some(match self.earliest {
                Some(e) if e <= ts => e,
                _ => ts,
            });
            self.latest = Some(match self.latest {
                Some(l) if l >= ts => l,
                _ => ts,
            });
        } else {
            self.missing_timestamp_count += 1;
        }
        Ok(())
    }

    fn on_finding(&mut self, _finding: &Finding) -> ForensicResult<()> {
        Ok(())
    }
}

/// A lightweight finding counter that tracks severity statistics without
/// storing findings in memory.
///
/// Optionally filters by severity threshold — only findings at or above the
/// threshold are counted.
///
/// For full finding collection, implement a custom `TriageSink`.
pub struct FindingCollector {
    min_severity: FindingSeverity,
    total_count: u64,
    by_severity: BTreeMap<FindingSeverity, u64>,
}

impl Default for FindingCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl FindingCollector {
    /// Count all findings regardless of severity.
    pub fn new() -> Self {
        Self {
            min_severity: FindingSeverity::Info,
            total_count: 0,
            by_severity: BTreeMap::new(),
        }
    }

    /// Only count findings at or above the given severity.
    pub fn with_min_severity(severity: FindingSeverity) -> Self {
        Self {
            min_severity: severity,
            total_count: 0,
            by_severity: BTreeMap::new(),
        }
    }

    /// Total number of findings that matched the severity filter.
    pub fn total_count(&self) -> u64 {
        self.total_count
    }

    /// Count of findings at a specific severity level.
    pub fn count_by_severity(&self, severity: FindingSeverity) -> u64 {
        self.by_severity.get(&severity).copied().unwrap_or(0)
    }
}

impl TriageSink for FindingCollector {
    fn name(&self) -> &str {
        "finding_collector"
    }

    fn on_data(&mut self, _data: &ForensicData) -> ForensicResult<()> {
        Ok(())
    }

    fn on_finding(&mut self, finding: &Finding) -> ForensicResult<()> {
        if finding.severity >= self.min_severity {
            self.total_count += 1;
            *self.by_severity.entry(finding.severity).or_insert(0) += 1;
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
use std::io::Write;

/// A streaming sink that writes each `ForensicData` record as a JSON line.
///
/// Uses constant memory regardless of dataset size. Records appear in parser
/// emission order — sorting is left to downstream tools or databases.
///
/// # Warning: this output carries no provenance
///
/// `ForensicData`'s `Serialize` emits only its field map. Each record's
/// `ProvenanceId`, its `Anomalies`, and therefore its `Confidence` are
/// dropped — silently, with nothing failing at compile time or run time. The
/// result is a file whose rows cannot be traced back to how they were
/// acquired or recovered.
///
/// That is fine for a scratch field dump. For output an examiner keeps, use
/// [`ProvenanceJsonlSink`], which writes the same records paired with the
/// [`ProvenanceStore`] that resolves them.
///
/// Requires the `serde` feature (enabled by default).
#[cfg(feature = "serde")]
pub struct JsonlTimelineSink<W: Write> {
    writer: W,
    record_count: u64,
    errors: u64,
    warned_about_provenance: bool,
}

#[cfg(feature = "serde")]
impl<W: Write> JsonlTimelineSink<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            record_count: 0,
            errors: 0,
            warned_about_provenance: false,
        }
    }

    /// Total records successfully written.
    pub fn record_count(&self) -> u64 {
        self.record_count
    }

    /// Number of serialization errors encountered.
    pub fn error_count(&self) -> u64 {
        self.errors
    }

    /// Consume the sink and return the underlying writer.
    pub fn into_inner(self) -> W {
        self.writer
    }
}

#[cfg(feature = "serde")]
impl<W: Write + 'static> TriageSink for JsonlTimelineSink<W> {
    fn name(&self) -> &str {
        "jsonl_timeline_sink"
    }

    fn on_data(&mut self, data: &ForensicData) -> ForensicResult<()> {
        if !self.warned_about_provenance {
            self.warned_about_provenance = true;
            // Once per sink, not once per record. Engineer-facing
            // diagnostic, not a `Finding`: nothing about the evidence is
            // wrong, the chosen export format simply cannot carry
            // provenance, and nothing else says so at run time.
            crate::warn!(
                "jsonl_timeline_sink drops provenance, anomalies and confidence; use ProvenanceJsonlSink for output an examiner keeps"
            );
        }
        match serde_json::to_writer(&mut self.writer, data) {
            Ok(()) => {
                let _ = self.writer.write_all(b"\n");
                self.record_count += 1;
            }
            Err(_) => {
                self.errors += 1;
            }
        }
        Ok(())
    }

    fn on_finding(&mut self, _finding: &Finding) -> ForensicResult<()> {
        Ok(())
    }

    fn finalize(&mut self) -> ForensicResult<()> {
        self.writer.flush()?;
        Ok(())
    }
}

/// A streaming sink that writes each `Finding` as a JSON line.
///
/// Uses constant memory regardless of the number of findings.
/// Requires the `serde` feature (enabled by default).
#[cfg(feature = "serde")]
pub struct JsonlFindingSink<W: Write> {
    writer: W,
    min_severity: FindingSeverity,
    total_count: u64,
    errors: u64,
}

#[cfg(feature = "serde")]
impl<W: Write> JsonlFindingSink<W> {
    /// Write all findings regardless of severity.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            min_severity: FindingSeverity::Info,
            total_count: 0,
            errors: 0,
        }
    }

    /// Only write findings at or above the given severity.
    pub fn with_min_severity(writer: W, severity: FindingSeverity) -> Self {
        Self {
            writer,
            min_severity: severity,
            total_count: 0,
            errors: 0,
        }
    }

    /// Total findings successfully written.
    pub fn total_count(&self) -> u64 {
        self.total_count
    }

    /// Number of serialization errors encountered.
    pub fn error_count(&self) -> u64 {
        self.errors
    }

    /// Consume the sink and return the underlying writer.
    pub fn into_inner(self) -> W {
        self.writer
    }
}

#[cfg(feature = "serde")]
impl<W: Write + 'static> TriageSink for JsonlFindingSink<W> {
    fn name(&self) -> &str {
        "jsonl_finding_sink"
    }

    fn on_data(&mut self, _data: &ForensicData) -> ForensicResult<()> {
        Ok(())
    }

    fn on_finding(&mut self, finding: &Finding) -> ForensicResult<()> {
        if finding.severity >= self.min_severity {
            match serde_json::to_writer(&mut self.writer, finding) {
                Ok(()) => {
                    let _ = self.writer.write_all(b"\n");
                    self.total_count += 1;
                }
                Err(_) => {
                    self.errors += 1;
                }
            }
        }
        Ok(())
    }

    fn finalize(&mut self) -> ForensicResult<()> {
        self.writer.flush()?;
        Ok(())
    }
}

/// A streaming sink that writes each record *with* its provenance, and the
/// [`ProvenanceStore`] that resolves it, as a paired export.
///
/// This is the sink to reach for when an examiner keeps the output.
/// [`JsonlTimelineSink`] writes `ForensicData`'s own `Serialize`, which is a
/// flat field map: the record's `ProvenanceId`, its `Anomalies`, and
/// therefore its `Confidence` are all dropped, silently and with no error to
/// notice. That is fine for a scratch field dump and wrong for anything an
/// examiner will later have to defend.
///
/// Two outputs, because they have different shapes and lifetimes:
///
/// - the **records** writer gets one JSON line per record:
///   `{"record": {...fields...}, "provenance": 41, "confidence": "High",
///   "anomalies": ["checksum_mismatch"]}`.
/// - the **sidecar** writer gets one [`ProvenanceSideTable`] document at
///   [`finalize`](TriageSink::finalize), interning every source and
///   provenance record the run produced. `provenance` on each record line is
///   an index into its `records` array.
///
/// Both halves are needed: an id without its table is meaningless (which is
/// exactly why [`ProvenanceId`] has no `Serialize` of its own), and the
/// table without the records has nothing to attach to. The side table is
/// deterministic by construction, so re-running the same input produces
/// byte-identical output.
///
/// [`ProvenanceSideTable`]: crate::provenance::ProvenanceSideTable
/// [`ProvenanceId`]: crate::provenance::ProvenanceId
///
/// Requires the `serde` feature (enabled by default).
#[cfg(feature = "serde")]
pub struct ProvenanceJsonlSink<W: Write, S: Write> {
    records: W,
    sidecar: S,
    store: ProvenanceStore,
    tool_version: String,
    model_version: u32,
    record_count: u64,
    errors: u64,
}

#[cfg(feature = "serde")]
impl<W: Write, S: Write> ProvenanceJsonlSink<W, S> {
    /// `store` must be the same store the records' `ProvenanceId`s were
    /// minted from -- in a pipeline, the one owned by `TriageContext`. Ids
    /// minted elsewhere resolve to `Confidence::Unknown` rather than
    /// silently claiming a level nothing backs.
    pub fn new(records: W, sidecar: S, store: ProvenanceStore) -> Self {
        Self {
            records,
            sidecar,
            store,
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            model_version: 1,
            record_count: 0,
            errors: 0,
        }
    }

    /// Stamps the exported side table with the tool that produced it.
    /// Defaults to this crate's version; set it to the *downstream* tool's
    /// version, since diffing a re-run months later is only meaningful if
    /// you know what changed about the tool.
    #[must_use]
    pub fn with_tool_version(mut self, tool_version: impl Into<String>) -> Self {
        self.tool_version = tool_version.into();
        self
    }

    #[must_use]
    pub fn with_model_version(mut self, model_version: u32) -> Self {
        self.model_version = model_version;
        self
    }

    /// Total records successfully written.
    pub fn record_count(&self) -> u64 {
        self.record_count
    }

    /// Number of serialization errors encountered.
    pub fn error_count(&self) -> u64 {
        self.errors
    }

    /// Consume the sink and return both writers, records first.
    pub fn into_inner(self) -> (W, S) {
        (self.records, self.sidecar)
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
struct ProvenanceRecordLine<'a> {
    record: &'a ForensicData,
    provenance: u32,
    confidence: Confidence,
    /// Omitted entirely when clean, so a clean export stays visually clean
    /// and an anomaly is conspicuous rather than one empty array among
    /// thousands.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    anomalies: Vec<&'static str>,
}

#[cfg(feature = "serde")]
impl<W: Write + 'static, S: Write + 'static> TriageSink for ProvenanceJsonlSink<W, S> {
    fn name(&self) -> &str {
        "provenance_jsonl_sink"
    }

    fn on_data(&mut self, data: &ForensicData) -> ForensicResult<()> {
        let line = ProvenanceRecordLine {
            record: data,
            provenance: data.provenance().raw(),
            confidence: data.confidence(&self.store),
            anomalies: data.anomalies().flags().names().collect(),
        };
        match serde_json::to_writer(&mut self.records, &line) {
            Ok(()) => {
                let _ = self.records.write_all(b"\n");
                self.record_count += 1;
            }
            Err(_) => {
                self.errors += 1;
            }
        }
        Ok(())
    }

    fn on_finding(&mut self, _finding: &Finding) -> ForensicResult<()> {
        Ok(())
    }

    fn finalize(&mut self) -> ForensicResult<()> {
        let table = self
            .store
            .to_side_table(self.tool_version.clone(), self.model_version);
        // Unlike a single dropped record, a missing side table makes every
        // record line unreadable, so this one is an error, not a counter.
        serde_json::to_writer(&mut self.sidecar, &table)
            .map_err(|e| crate::err::ForensicError::other("ProvenanceJsonlSink", e.to_string()))?;
        self.sidecar.write_all(b"\n")?;
        self.records.flush()?;
        self.sidecar.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        artifact::Artifact, data::ForensicData, pipeline::finding::FindingCategory,
        utils::testing::test_provenance_id, utils::time::Filetime,
    };

    #[test]
    fn timeline_sink_should_track_stats() {
        let mut sink = TimelineSink::new("@timestamp");

        let mut data_late = ForensicData::new("h", Artifact::Unknown, test_provenance_id());
        data_late.add_field(
            "@timestamp",
            Field::Date(Filetime::with_ymd_and_hms(2024, 6, 15, 14, 0, 0, 0).into()),
        );

        let mut data_early = ForensicData::new("h", Artifact::Unknown, test_provenance_id());
        data_early.add_field(
            "@timestamp",
            Field::Date(Filetime::with_ymd_and_hms(2024, 6, 15, 8, 0, 0, 0).into()),
        );

        sink.on_data(&data_late).unwrap();
        sink.on_data(&data_early).unwrap();

        assert_eq!(sink.record_count(), 2);
        assert_eq!(sink.missing_timestamp_count(), 0);
        assert!(sink.earliest().unwrap() < sink.latest().unwrap());
    }

    #[test]
    fn timeline_sink_should_count_missing_timestamps() {
        let mut sink = TimelineSink::new("@timestamp");
        let data = ForensicData::new("h", Artifact::Unknown, test_provenance_id()); // no @timestamp field
        sink.on_data(&data).unwrap();
        assert_eq!(sink.record_count(), 0);
        assert_eq!(sink.missing_timestamp_count(), 1);
        assert!(sink.earliest().is_none());
    }

    #[test]
    fn finding_collector_should_count_all() {
        let mut collector = FindingCollector::new();
        let finding = Finding::new(FindingSeverity::Low, FindingCategory::MissingData, "test");
        collector.on_finding(&finding).unwrap();
        assert_eq!(collector.total_count(), 1);
        assert_eq!(collector.count_by_severity(FindingSeverity::Low), 1);
        assert_eq!(collector.count_by_severity(FindingSeverity::High), 0);
    }

    #[test]
    fn finding_collector_should_filter_by_severity() {
        let mut collector = FindingCollector::with_min_severity(FindingSeverity::High);
        let low = Finding::new(FindingSeverity::Low, FindingCategory::MissingData, "low");
        let high = Finding::new(
            FindingSeverity::High,
            FindingCategory::AntiForensics,
            "high",
        );
        collector.on_finding(&low).unwrap();
        collector.on_finding(&high).unwrap();
        assert_eq!(collector.total_count(), 1);
        assert_eq!(collector.count_by_severity(FindingSeverity::High), 1);
        assert_eq!(collector.count_by_severity(FindingSeverity::Low), 0);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn jsonl_timeline_should_write_records() {
        let mut sink = JsonlTimelineSink::new(Vec::new());
        let mut data = ForensicData::new("h", Artifact::Unknown, test_provenance_id());
        data.add_field(
            "@timestamp",
            Field::Date(Filetime::with_ymd_and_hms(2024, 6, 15, 10, 0, 0, 0).into()),
        );
        sink.on_data(&data).unwrap();
        sink.finalize().unwrap();
        assert_eq!(sink.record_count(), 1);
        assert_eq!(sink.error_count(), 0);
        let output = String::from_utf8(sink.into_inner()).unwrap();
        assert!(output.ends_with('\n'));
        assert!(output.contains("artifact.host"));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn jsonl_finding_should_write_findings() {
        let mut sink = JsonlFindingSink::new(Vec::new());
        let finding = Finding::new(
            FindingSeverity::High,
            FindingCategory::AntiForensics,
            "test finding",
        );
        sink.on_finding(&finding).unwrap();
        sink.finalize().unwrap();
        assert_eq!(sink.total_count(), 1);
        assert_eq!(sink.error_count(), 0);
        let output = String::from_utf8(sink.into_inner()).unwrap();
        assert!(output.ends_with('\n'));
        assert!(output.contains("AntiForensics"));
        assert!(output.contains("test finding"));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn jsonl_finding_should_filter_by_severity() {
        let mut sink = JsonlFindingSink::with_min_severity(Vec::new(), FindingSeverity::High);
        let low = Finding::new(FindingSeverity::Low, FindingCategory::MissingData, "low");
        let high = Finding::new(
            FindingSeverity::High,
            FindingCategory::AntiForensics,
            "high",
        );
        sink.on_finding(&low).unwrap();
        sink.on_finding(&high).unwrap();
        sink.finalize().unwrap();
        assert_eq!(sink.total_count(), 1);
        let output = String::from_utf8(sink.into_inner()).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("high"));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn provenance_jsonl_keeps_what_the_plain_jsonl_sink_drops() {
        use crate::provenance::{Acquisition, Recovery, SourceKey};

        let store = ProvenanceStore::new();
        let source = store.register_source(SourceKey::Path("C:/db.dat".to_string()));
        let carved = source.mint(Acquisition::ImageRead, Recovery::Carved);

        let mut data = ForensicData::new("h", Artifact::Unknown, carved);
        data.add_field("row", Field::U64(7));

        let mut sink = ProvenanceJsonlSink::new(Vec::new(), Vec::new(), store.clone());
        sink.on_data(&data).unwrap();
        sink.finalize().unwrap();
        assert_eq!(sink.record_count(), 1);
        assert_eq!(sink.error_count(), 0);

        let (records, sidecar) = sink.into_inner();
        let line: serde_json::Value =
            serde_json::from_str(String::from_utf8(records).unwrap().trim()).unwrap();

        // The field map still round-trips...
        assert_eq!(line["record"]["row"], 7);
        // ...and so does everything ForensicData's own Serialize drops.
        assert_eq!(line["provenance"], 0);
        // Carved from an image grades Low, not High.
        assert_eq!(line["confidence"], "Low");

        // The side table resolves the id the record line carries.
        let table: serde_json::Value =
            serde_json::from_str(String::from_utf8(sidecar).unwrap().trim()).unwrap();
        let idx = line["provenance"].as_u64().unwrap() as usize;
        assert_eq!(table["records"][idx]["recovery"], "Carved");
        assert_eq!(table["records"][idx]["acquisition"], "ImageRead");
        assert_eq!(table["sources"][0]["Path"], "C:/db.dat");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn provenance_jsonl_emits_anomaly_names_and_omits_them_when_clean() {
        use crate::provenance::{Acquisition, AnomalyFlags, Parsed, Recovery, SourceKey};

        let store = ProvenanceStore::new();
        let source = store.register_source(SourceKey::Synthetic("t".to_string()));
        let id = source.mint(Acquisition::ImageRead, Recovery::Allocated);

        let clean = ForensicData::new("h", Artifact::Unknown, id);

        let mut anomalies = crate::provenance::Anomalies::empty();
        anomalies.add(AnomalyFlags::CHECKSUM_MISMATCH);
        let mut dirty = ForensicData::new("h", Artifact::Unknown, id);
        dirty.set_parsed("v", Parsed::with_anomalies(Field::U64(1), anomalies, id));

        let mut sink = ProvenanceJsonlSink::new(Vec::new(), Vec::new(), store);
        sink.on_data(&clean).unwrap();
        sink.on_data(&dirty).unwrap();
        sink.finalize().unwrap();

        let (records, _) = sink.into_inner();
        let out = String::from_utf8(records).unwrap();
        let mut lines = out.lines();

        let clean_line: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert!(clean_line.get("anomalies").is_none());
        assert_eq!(clean_line["confidence"], "High");

        let dirty_line: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(dirty_line["anomalies"][0], "checksum_mismatch");
        // A checksum mismatch caps confidence below the clean record's.
        assert_ne!(dirty_line["confidence"], "High");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn provenance_jsonl_export_is_byte_identical_across_runs() {
        use crate::provenance::{Acquisition, Recovery, SourceKey};

        let store = ProvenanceStore::new();
        let source = store.register_source(SourceKey::Path("C:/a.dat".to_string()));
        let ids: Vec<_> = (0..8)
            .map(|_| source.mint(Acquisition::ImageRead, Recovery::DeletedMetadata))
            .collect();

        let export = || {
            let mut sink = ProvenanceJsonlSink::new(Vec::new(), Vec::new(), store.clone())
                .with_tool_version("pinned-for-determinism");
            for (i, id) in ids.iter().enumerate() {
                let mut d = ForensicData::new("h", Artifact::Unknown, *id);
                d.add_field("i", Field::U64(i as u64));
                sink.on_data(&d).unwrap();
            }
            sink.finalize().unwrap();
            sink.into_inner()
        };

        assert_eq!(export(), export());
    }
}
