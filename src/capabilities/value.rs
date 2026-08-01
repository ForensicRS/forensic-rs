//! Recursive values exchanged by capability tools and resource providers.

use std::collections::BTreeMap;

use crate::{
    data::ForensicData,
    field::{Field, Text},
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
            Field::Date(value) => Self::Timestamp(value.into()),
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
        for (name, value) in data.iter() {
            values.insert(name.clone(), value.clone().into());
        }
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
    use crate::{artifact::Artifact, field::Field};

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
        let mut data = ForensicData::new("host", Artifact::Unknown);
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
