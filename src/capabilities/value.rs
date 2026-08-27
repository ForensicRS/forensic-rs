//! Recursive values exchanged by capability tools and resource providers.

use std::collections::BTreeMap;

use crate::{
    data::ForensicData,
    field::{Field, Text},
    pipeline::finding::Finding,
    provenance::{AnomalyFlags, Anomalies, Confidence},
    utils::time::ForensicTimestamp,
};

/// A lossless, protocol-neutral value for capability inputs and outputs.
///
/// Hosting adapters decide how to serialize timestamps and bytes for their
/// transport. Keeping these types explicit prevents forensic values from being
/// silently coerced to strings or nulls inside the core API.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub enum CapabilityValue {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    F64(f64),
    Text(Text),
    Timestamp(ForensicTimestamp),
    Bytes(Vec<u8>),
    Array(Vec<CapabilityValue>),
    Object(BTreeMap<Text, CapabilityValue>),
}

impl CapabilityValue {
    /// Return the stable name of this value's type.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "boolean",
            Self::I64(_) | Self::U64(_) => "integer",
            Self::F64(_) => "number",
            Self::Text(_) => "text",
            Self::Timestamp(_) => "timestamp",
            Self::Bytes(_) => "bytes",
            Self::Array(_) => "array",
            Self::Object(_) => "object",
        }
    }

    /// Return the object members when this value is an object.
    pub fn as_object(&self) -> Option<&BTreeMap<Text, CapabilityValue>> {
        match self {
            Self::Object(values) => Some(values),
            _ => None,
        }
    }

    /// Return the text value when this value is text.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value.as_ref()),
            _ => None,
        }
    }

    /// Return the unsigned integer value when this value is an unsigned integer.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::U64(value) => Some(*value),
            _ => None,
        }
    }
}

impl From<Field> for CapabilityValue {
    fn from(field: Field) -> Self {
        match field {
            Field::Null => Self::Null,
            Field::Text(value) => Self::Text(value),
            Field::Ip(value) => Self::Text(Text::Owned(value.to_string())),
            Field::U64(value) => Self::U64(value),
            Field::I64(value) => Self::I64(value),
            Field::F64(value) => Self::F64(value),
            Field::Date(value) => Self::Timestamp(value),
            Field::Array(values) => Self::Array(values.into_iter().map(Self::Text).collect()),
        }
    }
}

impl From<&ForensicData> for CapabilityValue {
    fn from(data: &ForensicData) -> Self {
        let mut values = BTreeMap::new();
        values.insert(
            Text::Borrowed("artifact"),
            Self::Text(Text::Owned(data.artifact().to_string())),
        );
        values.insert(Text::Borrowed("anomalies"), Self::from(data.anomalies()));
        for (name, value) in data.iter() {
            values.insert(name.clone(), value.clone().into());
        }
        Self::Object(values)
    }
}

impl From<Confidence> for CapabilityValue {
    fn from(confidence: Confidence) -> Self {
        let text = match confidence {
            Confidence::Unknown => "Unknown",
            Confidence::Low => "Low",
            Confidence::Medium => "Medium",
            Confidence::High => "High",
        };
        Self::Text(Text::Borrowed(text))
    }
}

/// Stable, snake_case wire-format name for a single known [`AnomalyFlags`] bit.
///
/// Distinct from the private `describe_anomaly()` in `pipeline::finding`, which
/// renders a human-readable sentence for a finding title — this is a stable API
/// key instead, so the two are not worth sharing over a 7-entry table.
fn anomaly_flag_name(flag: AnomalyFlags) -> &'static str {
    if flag == AnomalyFlags::CHECKSUM_MISMATCH {
        "checksum_mismatch"
    } else if flag == AnomalyFlags::STALE_REFERENCE {
        "stale_reference"
    } else if flag == AnomalyFlags::REFERENCE_CYCLE {
        "reference_cycle"
    } else if flag == AnomalyFlags::ALLOCATION_CONFLICT {
        "allocation_conflict"
    } else if flag == AnomalyFlags::TIMESTAMP_DIVERGENCE {
        "timestamp_divergence"
    } else if flag == AnomalyFlags::TRUNCATED {
        "truncated"
    } else if flag == AnomalyFlags::SOURCE_DIVERGENCE {
        "source_divergence"
    } else {
        "unknown"
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

impl From<&Anomalies> for CapabilityValue {
    fn from(anomalies: &Anomalies) -> Self {
        let flags = Self::Array(
            KNOWN_ANOMALY_FLAGS
                .into_iter()
                .filter(|&flag| anomalies.has(flag))
                .map(|flag| Self::Text(Text::Borrowed(anomaly_flag_name(flag))))
                .collect(),
        );
        let details = Self::Array(
            anomalies
                .details()
                .iter()
                .map(|detail| {
                    let mut map = BTreeMap::new();
                    map.insert(
                        Text::Borrowed("flag"),
                        Self::Text(Text::Borrowed(anomaly_flag_name(detail.kind))),
                    );
                    map.insert(
                        Text::Borrowed("message"),
                        Self::Text(Text::Owned(detail.message.to_string())),
                    );
                    Self::Object(map)
                })
                .collect(),
        );

        let mut values = BTreeMap::new();
        values.insert(Text::Borrowed("flags"), flags);
        values.insert(
            Text::Borrowed("confidence_ceiling"),
            Self::from(anomalies.confidence_ceiling()),
        );
        values.insert(Text::Borrowed("details"), details);
        Self::Object(values)
    }
}

impl From<&Finding> for CapabilityValue {
    fn from(finding: &Finding) -> Self {
        let mut values = BTreeMap::new();
        values.insert(
            Text::Borrowed("severity"),
            Self::Text(Text::Owned(finding.severity.to_string())),
        );
        values.insert(
            Text::Borrowed("category"),
            Self::Text(Text::Owned(finding.category.to_string())),
        );
        values.insert(
            Text::Borrowed("title"),
            Self::Text(Text::Owned(finding.title.clone())),
        );
        values.insert(
            Text::Borrowed("description"),
            Self::Text(Text::Owned(finding.description.clone())),
        );
        values.insert(
            Text::Borrowed("source_artifact"),
            Self::Text(Text::Owned(finding.source_artifact.to_string())),
        );
        values.insert(
            Text::Borrowed("timestamp"),
            finding
                .timestamp
                .map(Self::Timestamp)
                .unwrap_or(Self::Null),
        );
        values.insert(
            Text::Borrowed("related_data"),
            finding
                .related_data
                .as_ref()
                .map(Self::from)
                .unwrap_or(Self::Null),
        );
        values.insert(
            Text::Borrowed("metadata"),
            Self::Object(
                finding
                    .metadata
                    .iter()
                    .map(|(key, value)| (key.clone(), Self::Text(value.clone())))
                    .collect(),
            ),
        );
        Self::Object(values)
    }
}

impl From<bool> for CapabilityValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<u64> for CapabilityValue {
    fn from(value: u64) -> Self {
        Self::U64(value)
    }
}

impl From<i64> for CapabilityValue {
    fn from(value: i64) -> Self {
        Self::I64(value)
    }
}

impl From<f64> for CapabilityValue {
    fn from(value: f64) -> Self {
        Self::F64(value)
    }
}

impl From<Text> for CapabilityValue {
    fn from(value: Text) -> Self {
        Self::Text(value)
    }
}

impl From<String> for CapabilityValue {
    fn from(value: String) -> Self {
        Self::Text(Text::Owned(value))
    }
}

impl From<&'static str> for CapabilityValue {
    fn from(value: &'static str) -> Self {
        Self::Text(Text::Borrowed(value))
    }
}

#[cfg(test)]
mod tests {
    use compact_str::CompactString;
    use crate::{
        artifact::Artifact,
        field::Field,
        pipeline::finding::{FindingCategory, FindingSeverity},
        provenance::AnomalyDetail,
    };

    use super::*;

    #[test]
    fn field_conversion_preserves_scalar_and_timestamp_types() {
        assert_eq!(
            CapabilityValue::from(Field::U64(42)),
            CapabilityValue::U64(42)
        );
        assert_eq!(
            CapabilityValue::from(Field::Ip(crate::field::Ip::V4(0x7f00_0001))),
            CapabilityValue::Text(Text::Owned("127.0.0.1".to_string()))
        );

        let timestamp = crate::utils::time::Filetime::from_unix_secs(1_700_000_000);
        assert!(matches!(
            CapabilityValue::from(Field::Date(timestamp.into())),
            CapabilityValue::Timestamp(_)
        ));
    }

    #[test]
    fn forensic_data_conversion_keeps_artifact_and_fields() {
        let mut data = ForensicData::new("host", Artifact::Unknown, crate::utils::testing::test_provenance_id());
        data.insert(Text::Borrowed("event.code"), Field::U64(4624));

        let CapabilityValue::Object(values) = CapabilityValue::from(&data) else {
            panic!("forensic data must become an object");
        };
        assert_eq!(
            values.get("event.code").and_then(CapabilityValue::as_u64),
            Some(4624)
        );
        assert_eq!(
            values.get("artifact").and_then(CapabilityValue::as_text),
            Some("Unknown")
        );
    }

    #[test]
    fn confidence_conversion_produces_stable_text() {
        assert_eq!(
            CapabilityValue::from(Confidence::Unknown),
            CapabilityValue::Text(Text::Borrowed("Unknown"))
        );
        assert_eq!(
            CapabilityValue::from(Confidence::Low),
            CapabilityValue::Text(Text::Borrowed("Low"))
        );
        assert_eq!(
            CapabilityValue::from(Confidence::Medium),
            CapabilityValue::Text(Text::Borrowed("Medium"))
        );
        assert_eq!(
            CapabilityValue::from(Confidence::High),
            CapabilityValue::Text(Text::Borrowed("High"))
        );
    }

    #[test]
    fn anomalies_conversion_reports_flags_ceiling_and_details() {
        let mut anomalies = Anomalies::empty();
        anomalies.add(AnomalyFlags::TRUNCATED);
        anomalies.add_detail(AnomalyDetail {
            kind: AnomalyFlags::CHECKSUM_MISMATCH,
            message: CompactString::const_new("fixup mismatch"),
        });
        let ceiling = anomalies.confidence_ceiling();

        let CapabilityValue::Object(values) = CapabilityValue::from(&anomalies) else {
            panic!("anomalies must become an object");
        };

        let Some(CapabilityValue::Array(flags)) = values.get("flags") else {
            panic!("flags must be an array");
        };
        let flag_names: Vec<&str> = flags.iter().filter_map(CapabilityValue::as_text).collect();
        assert!(flag_names.contains(&"truncated"));
        assert!(flag_names.contains(&"checksum_mismatch"));

        assert_eq!(
            values.get("confidence_ceiling"),
            Some(&CapabilityValue::from(ceiling))
        );

        let Some(CapabilityValue::Array(details)) = values.get("details") else {
            panic!("details must be an array");
        };
        assert_eq!(details.len(), 1);
        let Some(CapabilityValue::Object(detail)) = details.first() else {
            panic!("each detail must be an object");
        };
        assert_eq!(
            detail.get("flag").and_then(CapabilityValue::as_text),
            Some("checksum_mismatch")
        );
        assert_eq!(
            detail.get("message").and_then(CapabilityValue::as_text),
            Some("fixup mismatch")
        );
    }

    #[test]
    fn finding_conversion_preserves_all_fields() {
        let mut data = ForensicData::new(
            "host",
            Artifact::Unknown,
            crate::utils::testing::test_provenance_id(),
        );
        data.insert(Text::Borrowed("event.code"), Field::U64(4624));
        let timestamp = ForensicTimestamp::from_unix_secs(1_700_000_000);

        let finding = Finding::new(
            FindingSeverity::High,
            FindingCategory::AnomalousTimestamp,
            "Suspicious timestamp",
        )
        .with_description("Manual review recommended")
        .with_timestamp(timestamp)
        .with_related_data(data)
        .with_metadata(Text::Borrowed("case_id"), Text::Borrowed("INC-001"));

        let CapabilityValue::Object(values) = CapabilityValue::from(&finding) else {
            panic!("finding must become an object");
        };

        assert_eq!(
            values.get("severity").and_then(CapabilityValue::as_text),
            Some("High")
        );
        assert_eq!(
            values.get("category").and_then(CapabilityValue::as_text),
            Some("AnomalousTimestamp")
        );
        assert_eq!(
            values.get("title").and_then(CapabilityValue::as_text),
            Some("Suspicious timestamp")
        );
        assert_eq!(
            values.get("description").and_then(CapabilityValue::as_text),
            Some("Manual review recommended")
        );
        assert_eq!(
            values
                .get("source_artifact")
                .and_then(CapabilityValue::as_text),
            Some("Unknown")
        );
        assert!(matches!(
            values.get("timestamp"),
            Some(CapabilityValue::Timestamp(_))
        ));
        assert!(matches!(
            values.get("related_data"),
            Some(CapabilityValue::Object(_))
        ));
        let Some(CapabilityValue::Object(metadata)) = values.get("metadata") else {
            panic!("metadata must be an object");
        };
        assert_eq!(
            metadata.get("case_id").and_then(CapabilityValue::as_text),
            Some("INC-001")
        );
    }

    #[test]
    fn finding_conversion_defaults_absent_fields_to_null() {
        let finding = Finding::new(
            FindingSeverity::Info,
            FindingCategory::MissingData,
            "Nothing to see here",
        );

        let CapabilityValue::Object(values) = CapabilityValue::from(&finding) else {
            panic!("finding must become an object");
        };

        assert_eq!(values.get("timestamp"), Some(&CapabilityValue::Null));
        assert_eq!(values.get("related_data"), Some(&CapabilityValue::Null));
        assert_eq!(
            values.get("description").and_then(CapabilityValue::as_text),
            Some("")
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_preserves_nested_typed_values() {
        let value = CapabilityValue::Object(BTreeMap::from([
            (
                Text::Borrowed("timestamp"),
                CapabilityValue::Timestamp(ForensicTimestamp::from_unix_secs(1_700_000_000)),
            ),
            (
                Text::Borrowed("bytes"),
                CapabilityValue::Bytes(vec![0, 1, 255]),
            ),
            (
                Text::Borrowed("items"),
                CapabilityValue::Array(vec![CapabilityValue::I64(-1), CapabilityValue::U64(2)]),
            ),
        ]));

        let encoded = serde_json::to_string(&value).unwrap();
        let decoded: CapabilityValue = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, value);
    }
}
