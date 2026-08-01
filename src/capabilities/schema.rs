//! Native schemas for capability inputs and structured outputs.
//!
//! The model is deliberately small and maps directly to the JSON Schema shapes
//! required by protocol adapters without making `serde_json` part of the core
//! public trait surface.

use std::collections::{BTreeMap, BTreeSet};

use super::value::CapabilityValue;

/// The scalar or container type accepted by a [`ValueSchema`].
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    Null,
    Boolean,
    Integer,
    Number,
    Text,
    Timestamp,
    Bytes,
    Array,
    Object,
}

/// Schema for a capability value.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Default)]
pub enum ValueSchema {
    /// Accepts any value.
    #[default]
    Any,
    /// Accepts a concrete scalar or container value type.
    Type(ValueType),
    /// Accepts an array whose items match `items`.
    Array { items: Box<ValueSchema> },
    /// Accepts an object with declared properties.
    Object(ObjectSchema),
}

impl ValueSchema {
    /// Start building an object schema. Convert it into `ValueSchema` after
    /// declaring the allowed properties.
    pub fn object() -> ObjectSchema {
        ObjectSchema::default()
    }

    pub fn array(items: ValueSchema) -> Self {
        Self::Array {
            items: Box::new(items),
        }
    }

    /// Validate a value and return a stable path-oriented failure message.
    pub fn validate(&self, value: &CapabilityValue) -> Result<(), String> {
        self.validate_at(value, "$")
    }

    fn validate_at(&self, value: &CapabilityValue, path: &str) -> Result<(), String> {
        match self {
            Self::Any => Ok(()),
            Self::Type(expected) if expected.matches(value) => Ok(()),
            Self::Type(expected) => Err(format!(
                "{} must be {}, received {}",
                path,
                expected.name(),
                value.type_name()
            )),
            Self::Array { items } => match value {
                CapabilityValue::Array(values) => {
                    for (index, item) in values.iter().enumerate() {
                        items.validate_at(item, &format!("{}[{}]", path, index))?;
                    }
                    Ok(())
                }
                _ => Err(format!(
                    "{} must be array, received {}",
                    path,
                    value.type_name()
                )),
            },
            Self::Object(schema) => schema.validate_at(value, path),
        }
    }
}

impl From<ObjectSchema> for ValueSchema {
    fn from(schema: ObjectSchema) -> Self {
        Self::Object(schema)
    }
}

impl ValueType {
    fn matches(self, value: &CapabilityValue) -> bool {
        matches!(
            (self, value),
            (Self::Null, CapabilityValue::Null)
                | (Self::Boolean, CapabilityValue::Bool(_))
                | (
                    Self::Integer,
                    CapabilityValue::I64(_) | CapabilityValue::U64(_)
                )
                | (
                    Self::Number,
                    CapabilityValue::I64(_) | CapabilityValue::U64(_) | CapabilityValue::F64(_)
                )
                | (Self::Text, CapabilityValue::Text(_))
                | (Self::Timestamp, CapabilityValue::Timestamp(_))
                | (Self::Bytes, CapabilityValue::Bytes(_))
                | (Self::Array, CapabilityValue::Array(_))
                | (Self::Object, CapabilityValue::Object(_))
        )
    }

    fn name(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Boolean => "boolean",
            Self::Integer => "integer",
            Self::Number => "number",
            Self::Text => "text",
            Self::Timestamp => "timestamp",
            Self::Bytes => "bytes",
            Self::Array => "array",
            Self::Object => "object",
        }
    }
}

/// Object-property rules for a [`ValueSchema::Object`].
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ObjectSchema {
    properties: BTreeMap<String, ValueSchema>,
    required: BTreeSet<String>,
    allow_additional_properties: bool,
}

impl ObjectSchema {
    pub fn property(mut self, name: impl Into<String>, schema: ValueSchema) -> Self {
        self.properties.insert(name.into(), schema);
        self
    }

    pub fn required(mut self, name: impl Into<String>) -> Self {
        self.required.insert(name.into());
        self
    }

    pub fn allow_additional_properties(mut self) -> Self {
        self.allow_additional_properties = true;
        self
    }

    fn validate_at(&self, value: &CapabilityValue, path: &str) -> Result<(), String> {
        let CapabilityValue::Object(values) = value else {
            return Err(format!(
                "{} must be object, received {}",
                path,
                value.type_name()
            ));
        };
        for name in &self.required {
            if !values.contains_key(name.as_str()) {
                return Err(format!("{}.{} is required", path, name));
            }
        }
        for (name, value) in values {
            let property_path = format!("{}.{}", path, name);
            match self.properties.get(name.as_ref()) {
                Some(schema) => schema.validate_at(value, &property_path)?,
                None if !self.allow_additional_properties => {
                    return Err(format!("{} is not allowed", property_path));
                }
                None => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::field::Text;

    use super::*;

    #[test]
    fn validates_required_object_properties_and_types() {
        let schema: ValueSchema = ValueSchema::object()
            .property("threshold", ValueSchema::Type(ValueType::Integer))
            .required("threshold")
            .into();
        let mut input = BTreeMap::new();
        input.insert(Text::Borrowed("threshold"), CapabilityValue::U64(42));
        assert!(schema.validate(&CapabilityValue::Object(input)).is_ok());

        assert_eq!(
            schema.validate(&CapabilityValue::Object(BTreeMap::new())),
            Err("$.threshold is required".to_string())
        );
    }

    #[test]
    fn rejects_undeclared_properties_by_default() {
        let schema: ValueSchema = ValueSchema::object().into();
        let mut input = BTreeMap::new();
        input.insert(
            Text::Borrowed("private"),
            CapabilityValue::Text(Text::Borrowed("value")),
        );

        assert_eq!(
            schema.validate(&CapabilityValue::Object(input)),
            Err("$.private is not allowed".to_string())
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_preserves_object_schema_rules() {
        let schema: ValueSchema = ValueSchema::object()
            .property("path", ValueSchema::Type(ValueType::Text))
            .required("path")
            .allow_additional_properties()
            .into();

        let encoded = serde_json::to_string(&schema).unwrap();
        let decoded: ValueSchema = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, schema);
    }
}
