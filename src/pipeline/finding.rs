use std::collections::BTreeMap;

use crate::{
    artifact::Artifact,
    data::ForensicData,
    err::ForensicError,
    field::Text,
    provenance::{AnomalyFlags, Anomalies},
    scow::SCow,
    utils::time::ForensicTimestamp,
};

/// Severity level for a forensic finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingSeverity::Info => write!(f, "Info"),
            FindingSeverity::Low => write!(f, "Low"),
            FindingSeverity::Medium => write!(f, "Medium"),
            FindingSeverity::High => write!(f, "High"),
            FindingSeverity::Critical => write!(f, "Critical"),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for FindingSeverity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// Category of a forensic finding, indicating what kind of issue was detected.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingCategory {
    /// Data integrity violation (e.g. corrupted records, invalid structures)
    IntegrityIssue,
    /// Expected data is absent (e.g. gaps in event record IDs, missing MFT entries)
    MissingData,
    /// Evidence of deliberate evidence tampering or destruction
    AntiForensics,
    /// Behavioral pattern that warrants investigation
    SuspiciousActivity,
    /// Checksum or hash mismatch in artifact data
    InvalidChecksum,
    /// Timestamp that is logically impossible or inconsistent
    AnomalousTimestamp,
    /// A parser/enricher/analyzer stage failed, so evidence went unexamined
    ProcessingError,
    /// Custom category
    Other(String),
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingCategory::IntegrityIssue => write!(f, "IntegrityIssue"),
            FindingCategory::MissingData => write!(f, "MissingData"),
            FindingCategory::AntiForensics => write!(f, "AntiForensics"),
            FindingCategory::SuspiciousActivity => write!(f, "SuspiciousActivity"),
            FindingCategory::InvalidChecksum => write!(f, "InvalidChecksum"),
            FindingCategory::AnomalousTimestamp => write!(f, "AnomalousTimestamp"),
            FindingCategory::ProcessingError => write!(f, "ProcessingError"),
            FindingCategory::Other(s) => write!(f, "Other({})", s),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for FindingCategory {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// A structured forensic finding produced by an analyzer during pipeline execution.
///
/// Findings represent detected issues, anomalies, or noteworthy observations
/// in forensic artifacts. They are the primary output mechanism for analyzers
/// to communicate results.
#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: FindingSeverity,
    pub category: FindingCategory,
    pub title: String,
    pub description: String,
    pub source_artifact: Artifact,
    pub timestamp: Option<ForensicTimestamp>,
    pub related_data: Option<ForensicData>,
    pub metadata: BTreeMap<Text, Text>,
}

impl Finding {
    pub fn new(
        severity: FindingSeverity,
        category: FindingCategory,
        title: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            category,
            title: title.into(),
            description: String::new(),
            source_artifact: Artifact::Unknown,
            timestamp: None,
            related_data: None,
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    pub fn with_artifact(mut self, artifact: Artifact) -> Self {
        self.source_artifact = artifact;
        self
    }

    pub fn with_timestamp(mut self, ts: ForensicTimestamp) -> Self {
        self.timestamp = Some(ts);
        self
    }

    pub fn with_related_data(mut self, data: ForensicData) -> Self {
        self.related_data = Some(data);
        self
    }

    pub fn with_metadata(mut self, key: Text, value: Text) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Builds a `ProcessingError` finding from a stage failure. A crashed
    /// parser/enricher/analyzer means evidence went unexamined — that is
    /// itself something an analyst should see in the report, not just
    /// something an engineer sees in a log line.
    pub fn from_error(stage: impl Into<String>, err: &ForensicError) -> Self {
        Self::new(
            FindingSeverity::High,
            FindingCategory::ProcessingError,
            format!("{} failed: {err}", stage.into()),
        )
    }

    /// Promotes one tallied anomaly flag, seen `count` times across a run,
    /// into a single aggregate finding. Used by [`AnomalyTally`] instead of
    /// emitting one finding per anomalous record, which would flood the
    /// report at scale.
    pub fn from_anomaly(flag: AnomalyFlags, count: u64, sample: Option<SCow>) -> Self {
        let (category, severity) = anomaly_category_severity(flag);
        let mut finding = Self::new(
            severity,
            category,
            format!("{count} record(s) flagged: {}", describe_anomaly(flag)),
        );
        if let Some(sample) = sample {
            finding = finding.with_description(sample.to_string());
        }
        finding
    }
}

fn describe_anomaly(flag: AnomalyFlags) -> &'static str {
    if flag == AnomalyFlags::CHECKSUM_MISMATCH {
        "checksum/fixup mismatch"
    } else if flag == AnomalyFlags::STALE_REFERENCE {
        "stale reference"
    } else if flag == AnomalyFlags::REFERENCE_CYCLE {
        "reference cycle"
    } else if flag == AnomalyFlags::ALLOCATION_CONFLICT {
        "allocation conflict"
    } else if flag == AnomalyFlags::TIMESTAMP_DIVERGENCE {
        "timestamp divergence"
    } else if flag == AnomalyFlags::TRUNCATED {
        "truncated structure"
    } else if flag == AnomalyFlags::SOURCE_DIVERGENCE {
        "source divergence"
    } else {
        "unrecognized anomaly"
    }
}

fn anomaly_category_severity(flag: AnomalyFlags) -> (FindingCategory, FindingSeverity) {
    if flag == AnomalyFlags::CHECKSUM_MISMATCH {
        (FindingCategory::InvalidChecksum, FindingSeverity::Medium)
    } else if flag == AnomalyFlags::TRUNCATED {
        (FindingCategory::IntegrityIssue, FindingSeverity::Medium)
    } else if flag == AnomalyFlags::TIMESTAMP_DIVERGENCE {
        (FindingCategory::AnomalousTimestamp, FindingSeverity::High)
    } else if flag == AnomalyFlags::ALLOCATION_CONFLICT
        || flag == AnomalyFlags::REFERENCE_CYCLE
        || flag == AnomalyFlags::SOURCE_DIVERGENCE
    {
        (FindingCategory::IntegrityIssue, FindingSeverity::High)
    } else if flag == AnomalyFlags::STALE_REFERENCE {
        (FindingCategory::IntegrityIssue, FindingSeverity::Low)
    } else {
        (
            FindingCategory::Other("unknown-anomaly".to_string()),
            FindingSeverity::Info,
        )
    }
}

const KNOWN_ANOMALY_FLAGS: [AnomalyFlags; 7] = [
    AnomalyFlags::CHECKSUM_MISMATCH,
    AnomalyFlags::STALE_REFERENCE,
    AnomalyFlags::REFERENCE_CYCLE,
    AnomalyFlags::ALLOCATION_CONFLICT,
    AnomalyFlags::TIMESTAMP_DIVERGENCE,
    AnomalyFlags::TRUNCATED,
    AnomalyFlags::SOURCE_DIVERGENCE,
];

fn known_anomaly_mask() -> u32 {
    KNOWN_ANOMALY_FLAGS.iter().fold(0u32, |acc, f| acc | f.bits())
}

/// Accumulates per-flag anomaly counts across a parser run, so cheap,
/// always-present [`Anomalies`] become a handful of aggregate [`Finding`]s
/// instead of one finding per anomalous record.
#[derive(Debug, Default)]
pub struct AnomalyTally {
    counts: BTreeMap<u32, u64>,
    samples: BTreeMap<u32, SCow>,
    unknown_count: u64,
}

impl AnomalyTally {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one record's anomalies into the tally.
    pub fn record(&mut self, anomalies: &Anomalies) {
        let flags = anomalies.flags();
        if flags.is_empty() {
            return;
        }
        for &flag in &KNOWN_ANOMALY_FLAGS {
            if !flags.contains(flag) {
                continue;
            }
            *self.counts.entry(flag.bits()).or_insert(0) += 1;
            self.samples.entry(flag.bits()).or_insert_with(|| {
                anomalies
                    .details()
                    .iter()
                    .find(|d| d.kind == flag)
                    .map(|d| d.message.clone())
                    .unwrap_or(SCow::Borrowed(""))
            });
        }
        if flags.bits() & !known_anomaly_mask() != 0 {
            self.unknown_count += 1;
        }
    }

    /// Drains the tally into one aggregate [`Finding`] per flag observed.
    pub fn into_findings(self) -> Vec<Finding> {
        let AnomalyTally {
            counts,
            samples,
            unknown_count,
        } = self;
        let mut findings: Vec<Finding> = counts
            .into_iter()
            .map(|(bits, count)| {
                let flag = AnomalyFlags::from_bits_retain(bits);
                let sample = samples.get(&bits).cloned().filter(|s| !s.is_empty());
                Finding::from_anomaly(flag, count, sample)
            })
            .collect();
        if unknown_count > 0 {
            findings.push(Finding::new(
                FindingSeverity::Info,
                FindingCategory::Other("unknown-anomaly".to_string()),
                format!(
                    "{unknown_count} record(s) flagged with an anomaly this version doesn't recognize"
                ),
            ));
        }
        findings
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Finding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut count = 3;
        if !self.description.is_empty() {
            count += 1;
        }
        if self.source_artifact != crate::artifact::Artifact::Unknown {
            count += 1;
        }
        if self.timestamp.is_some() {
            count += 1;
        }
        if self.related_data.is_some() {
            count += 1;
        }
        if !self.metadata.is_empty() {
            count += 1;
        }

        let mut map = serializer.serialize_map(Some(count))?;
        map.serialize_entry("severity", &self.severity)?;
        map.serialize_entry("category", &self.category)?;
        map.serialize_entry("title", &self.title)?;
        if !self.description.is_empty() {
            map.serialize_entry("description", &self.description)?;
        }
        if self.source_artifact != crate::artifact::Artifact::Unknown {
            map.serialize_entry("source_artifact", &self.source_artifact)?;
        }
        if let Some(ts) = &self.timestamp {
            map.serialize_entry("timestamp", ts)?;
        }
        if let Some(data) = &self.related_data {
            map.serialize_entry("related_data", data)?;
        }
        if !self.metadata.is_empty() {
            map.serialize_entry("metadata", &self.metadata)?;
        }
        map.end()
    }
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.category, self.title)?;
        if !self.description.is_empty() {
            write!(f, " - {}", self.description)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_finding_with_builder() {
        let finding = Finding::new(
            FindingSeverity::High,
            FindingCategory::MissingData,
            "Gap in EventRecordIDs",
        )
        .with_description("Records 1042-1050 are missing from Security.evtx")
        .with_artifact(
            crate::artifact::WindowsArtifacts::WinEvt(crate::artifact::WindowsEvents::Security)
                .into(),
        )
        .with_metadata(Text::Borrowed("gap_start"), Text::Owned("1042".into()))
        .with_metadata(Text::Borrowed("gap_end"), Text::Owned("1050".into()));

        assert_eq!(finding.severity, FindingSeverity::High);
        assert_eq!(finding.category, FindingCategory::MissingData);
        assert_eq!(finding.title, "Gap in EventRecordIDs");
        assert!(!finding.description.is_empty());
        assert_eq!(finding.metadata.len(), 2);
    }

    #[test]
    fn should_display_finding() {
        let finding = Finding::new(
            FindingSeverity::Critical,
            FindingCategory::AntiForensics,
            "Event log cleared",
        );
        let display = format!("{}", finding);
        assert!(display.contains("Critical"));
        assert!(display.contains("AntiForensics"));
        assert!(display.contains("Event log cleared"));
    }

    #[test]
    fn severity_ordering() {
        assert!(FindingSeverity::Info < FindingSeverity::Low);
        assert!(FindingSeverity::Low < FindingSeverity::Medium);
        assert!(FindingSeverity::Medium < FindingSeverity::High);
        assert!(FindingSeverity::High < FindingSeverity::Critical);
    }
}
