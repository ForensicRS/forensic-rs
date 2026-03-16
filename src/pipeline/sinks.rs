use std::collections::BTreeMap;

use crate::{
    data::ForensicData,
    err::ForensicResult,
    field::Field,
    utils::time::ForensicTimestamp,
};

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
    fn name(&self) -> &str { "timeline_sink" }

    fn on_data(&mut self, data: &ForensicData) -> ForensicResult<()> {
        if let Some(Field::Date(ft)) = data.field(&self.timestamp_field) {
            let ts: ForensicTimestamp = (*ft).into();
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
    fn name(&self) -> &str { "finding_collector" }

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
/// Requires the `serde` feature (enabled by default).
#[cfg(feature = "serde")]
pub struct JsonlTimelineSink<W: Write> {
    writer: W,
    record_count: u64,
    errors: u64,
}

#[cfg(feature = "serde")]
impl<W: Write> JsonlTimelineSink<W> {
    pub fn new(writer: W) -> Self {
        Self { writer, record_count: 0, errors: 0 }
    }

    /// Total records successfully written.
    pub fn record_count(&self) -> u64 { self.record_count }

    /// Number of serialization errors encountered.
    pub fn error_count(&self) -> u64 { self.errors }

    /// Consume the sink and return the underlying writer.
    pub fn into_inner(self) -> W { self.writer }
}

#[cfg(feature = "serde")]
impl<W: Write + 'static> TriageSink for JsonlTimelineSink<W> {
    fn name(&self) -> &str { "jsonl_timeline_sink" }

    fn on_data(&mut self, data: &ForensicData) -> ForensicResult<()> {
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
        Self { writer, min_severity: FindingSeverity::Info, total_count: 0, errors: 0 }
    }

    /// Only write findings at or above the given severity.
    pub fn with_min_severity(writer: W, severity: FindingSeverity) -> Self {
        Self { writer, min_severity: severity, total_count: 0, errors: 0 }
    }

    /// Total findings successfully written.
    pub fn total_count(&self) -> u64 { self.total_count }

    /// Number of serialization errors encountered.
    pub fn error_count(&self) -> u64 { self.errors }

    /// Consume the sink and return the underlying writer.
    pub fn into_inner(self) -> W { self.writer }
}

#[cfg(feature = "serde")]
impl<W: Write + 'static> TriageSink for JsonlFindingSink<W> {
    fn name(&self) -> &str { "jsonl_finding_sink" }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        artifact::Artifact,
        data::ForensicData,
        pipeline::finding::FindingCategory,
        utils::time::Filetime,
    };

    #[test]
    fn timeline_sink_should_track_stats() {
        let mut sink = TimelineSink::new("@timestamp");

        let mut data_late = ForensicData::new("h", Artifact::Unknown);
        data_late.add_field("@timestamp", Field::Date(Filetime::with_ymd_and_hms(2024, 6, 15, 14, 0, 0, 0)));

        let mut data_early = ForensicData::new("h", Artifact::Unknown);
        data_early.add_field("@timestamp", Field::Date(Filetime::with_ymd_and_hms(2024, 6, 15, 8, 0, 0, 0)));

        sink.on_data(&data_late).unwrap();
        sink.on_data(&data_early).unwrap();

        assert_eq!(sink.record_count(), 2);
        assert_eq!(sink.missing_timestamp_count(), 0);
        assert!(sink.earliest().unwrap() < sink.latest().unwrap());
    }

    #[test]
    fn timeline_sink_should_count_missing_timestamps() {
        let mut sink = TimelineSink::new("@timestamp");
        let data = ForensicData::new("h", Artifact::Unknown); // no @timestamp field
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
        let high = Finding::new(FindingSeverity::High, FindingCategory::AntiForensics, "high");
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
        let mut data = ForensicData::new("h", Artifact::Unknown);
        data.add_field("@timestamp", Field::Date(Filetime::with_ymd_and_hms(2024, 6, 15, 10, 0, 0, 0)));
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
        let finding = Finding::new(FindingSeverity::High, FindingCategory::AntiForensics, "test finding");
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
        let high = Finding::new(FindingSeverity::High, FindingCategory::AntiForensics, "high");
        sink.on_finding(&low).unwrap();
        sink.on_finding(&high).unwrap();
        sink.finalize().unwrap();
        assert_eq!(sink.total_count(), 1);
        let output = String::from_utf8(sink.into_inner()).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("high"));
    }
}
