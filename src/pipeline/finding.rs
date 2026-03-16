use std::collections::BTreeMap;

use crate::{
    artifact::Artifact,
    data::ForensicData,
    field::Text,
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
    where S: serde::Serializer,
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
            FindingCategory::Other(s) => write!(f, "Other({})", s),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for FindingCategory {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer,
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
    pub fn new(severity: FindingSeverity, category: FindingCategory, title: impl Into<String>) -> Self {
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
}

#[cfg(feature = "serde")]
impl serde::Serialize for Finding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut count = 3;
        if !self.description.is_empty() { count += 1; }
        if self.source_artifact != crate::artifact::Artifact::Unknown { count += 1; }
        if self.timestamp.is_some() { count += 1; }
        if self.related_data.is_some() { count += 1; }
        if !self.metadata.is_empty() { count += 1; }

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
        let finding = Finding::new(FindingSeverity::High, FindingCategory::MissingData, "Gap in EventRecordIDs")
            .with_description("Records 1042-1050 are missing from Security.evtx")
            .with_artifact(crate::artifact::WindowsArtifacts::WinEvt(crate::artifact::WindowsEvents::Security).into())
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
        let finding = Finding::new(FindingSeverity::Critical, FindingCategory::AntiForensics, "Event log cleared");
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
