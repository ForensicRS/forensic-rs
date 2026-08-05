use std::{borrow::Cow, collections::BTreeMap};

#[cfg(feature = "serde")]
use serde::{de::Visitor, ser::SerializeMap, Deserialize, Deserializer, Serialize};

use crate::{
    field::{Field, FieldAccess, Ip, Text},
    prelude::{Artifact, *},
    provenance::ProvenanceId,
    utils::time::ForensicTimestamp,
};

/// Basic container for all Forensic Data inside an artifact
#[derive(Debug, Clone)]
pub struct ForensicData {
    artifact: Artifact,
    provenance: ProvenanceId,
    anomalies: Anomalies,
    pub(crate) fields: BTreeMap<Text, Field>,
}

impl ForensicData {
    /// `provenance` must be a real [`ProvenanceId`] obtained from a
    /// [`crate::provenance::SourceHandle`] (directly, or via `derive`/`merge`)
    /// — there is no zero-argument constructor for `ForensicData`, precisely
    /// so every record flowing through the framework carries real provenance.
    pub fn new(host: &str, artifact: Artifact, provenance: ProvenanceId) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert(
            Text::Borrowed(ARTIFACT_HOST),
            Field::Text(Text::Owned(host.to_string())),
        );
        fields.insert(
            Text::Borrowed(ARTIFACT_NAME),
            Field::Text(Text::Owned(artifact.to_string())),
        );
        Self {
            fields,
            artifact,
            provenance,
            anomalies: Anomalies::default(),
        }
    }

    pub fn artifact(&self) -> &Artifact {
        &self.artifact
    }

    pub fn provenance(&self) -> ProvenanceId {
        self.provenance
    }

    /// For enrichers that re-derive provenance after inspecting/transforming
    /// content (e.g. via [`crate::provenance::ProvenanceStore::derive`]).
    pub fn set_provenance(&mut self, provenance: ProvenanceId) {
        self.provenance = provenance;
    }

    pub fn host(&self) -> &str {
        match self.field(ARTIFACT_HOST) {
            Some(Field::Text(v)) => v,
            _ => "",
        }
    }

    pub fn field(&self, field_name: &str) -> Option<&Field> {
        self.fields.get(field_name)
    }

    pub fn has_field(&self, field_name: &str) -> bool {
        self.fields.contains_key(field_name)
    }

    pub fn field_mut(&mut self, field_name: &str) -> Option<&mut Field> {
        self.fields.get_mut(field_name)
    }
    pub fn add_field(&mut self, field_name: &'static str, field_value: Field) {
        self.insert(Text::Borrowed(field_name), field_value);
    }
    pub fn insert(&mut self, field_name: Text, field_value: Field) {
        self.fields.insert(field_name, field_value);
    }
    /// Obtains the field value as `i64`, converting and storing in-place if needed.
    pub fn get_i64(&mut self, field_name: &str) -> FieldAccess<i64> {
        let field = match self.fields.get_mut(field_name) {
            Some(f) => f,
            None => return FieldAccess::None,
        };
        if let Field::I64(v) = field {
            return FieldAccess::Some(*v);
        }
        match (&*field).try_into() {
            Ok(v) => {
                *field = Field::I64(v);
                FieldAccess::Some(v)
            }
            Err(_) => FieldAccess::InvalidCast,
        }
    }
    /// Obtains the field value as `f64`, converting and storing in-place if needed.
    pub fn get_f64(&mut self, field_name: &str) -> FieldAccess<f64> {
        let field = match self.fields.get_mut(field_name) {
            Some(f) => f,
            None => return FieldAccess::None,
        };
        if let Field::F64(v) = field {
            return FieldAccess::Some(*v);
        }
        match (&*field).try_into() {
            Ok(v) => {
                *field = Field::F64(v);
                FieldAccess::Some(v)
            }
            Err(_) => FieldAccess::InvalidCast,
        }
    }
    /// Obtains the field value as `u64`, converting and storing in-place if needed.
    pub fn get_u64(&mut self, field_name: &str) -> FieldAccess<u64> {
        let field = match self.fields.get_mut(field_name) {
            Some(f) => f,
            None => return FieldAccess::None,
        };
        if let Field::U64(v) = field {
            return FieldAccess::Some(*v);
        }
        match (&*field).try_into() {
            Ok(v) => {
                *field = Field::U64(v);
                FieldAccess::Some(v)
            }
            Err(_) => FieldAccess::InvalidCast,
        }
    }
    /// Obtains the field value as `Ip`, converting and storing in-place if needed.
    pub fn get_ip(&mut self, field_name: &str) -> FieldAccess<Ip> {
        let field = match self.fields.get_mut(field_name) {
            Some(f) => f,
            None => return FieldAccess::None,
        };
        if let Field::Ip(v) = field {
            return FieldAccess::Some(*v);
        }
        match (&*field).try_into() {
            Ok(v) => {
                *field = Field::Ip(v);
                FieldAccess::Some(v)
            }
            Err(_) => FieldAccess::InvalidCast,
        }
    }
    /// Obtains the field value as `&str`, converting and storing in-place if needed.
    pub fn get_str(&mut self, field_name: &str) -> FieldAccess<&str> {
        let field = match self.fields.get_mut(field_name) {
            Some(f) => f,
            None => return FieldAccess::None,
        };
        if matches!(field, Field::Text(_)) {
            let Field::Text(t) = field else {
                unreachable!()
            };
            return FieldAccess::Some(&t[..]);
        }
        let val: Result<Text, _> = (&*field).try_into();
        match val {
            Ok(v) => {
                *field = Field::Text(v);
                let Field::Text(t) = field else {
                    unreachable!()
                };
                FieldAccess::Some(&t[..])
            }
            Err(_) => FieldAccess::InvalidCast,
        }
    }
    /// Obtains the field value as `&Vec<Text>`, converting and storing in-place if needed.
    pub fn get_array(&mut self, field_name: &str) -> FieldAccess<&Vec<Text>> {
        let field = match self.fields.get_mut(field_name) {
            Some(f) => f,
            None => return FieldAccess::None,
        };
        if matches!(field, Field::Array(_)) {
            let Field::Array(a) = field else {
                unreachable!()
            };
            return FieldAccess::Some(a);
        }
        let val: Result<Vec<Text>, _> = (&*field).try_into();
        match val {
            Ok(v) => {
                *field = Field::Array(v);
                let Field::Array(a) = field else {
                    unreachable!()
                };
                FieldAccess::Some(a)
            }
            Err(_) => FieldAccess::InvalidCast,
        }
    }

    pub fn fields(&self) -> EventIter<'_> {
        EventIter {
            children: self.fields.iter(),
        }
    }
    pub fn iter(&self) -> EventIter<'_> {
        EventIter {
            children: self.fields.iter(),
        }
    }
    pub fn iter_mut(&mut self) -> EventIterMut<'_> {
        EventIterMut {
            children: self.fields.iter_mut(),
        }
    }

    /// Remove a field by name, returning its value if it existed.
    pub fn remove(&mut self, field_name: &str) -> Option<Field> {
        self.fields.remove(field_name)
    }

    /// Check whether a field exists by name.
    pub fn contains_key(&self, field_name: &str) -> bool {
        self.fields.contains_key(field_name)
    }

    /// Ergonomic setter: insert a field using `Into<Field>` conversion.
    pub fn set(&mut self, field_name: &'static str, value: impl Into<Field>) {
        self.fields.insert(Text::Borrowed(field_name), value.into());
    }

    /// Ergonomic setter for a value whose provenance was tracked separately
    /// from this record's own (e.g. a `$FN` timestamp recovered from slack
    /// while the record overall came from an allocated read — see
    /// [`crate::provenance::Tracked`]'s own docs for the canonical example).
    /// Stores `tracked`'s value under `field_name` via the same `Into<Field>`
    /// conversion as [`Self::set`], and returns the value's own
    /// [`ProvenanceId`] rather than silently discarding or overwriting
    /// `self.provenance()` with it — callers who need the two reconciled
    /// should explicitly [`crate::provenance::ProvenanceStore::merge`] before
    /// calling [`Self::set_provenance`]. This only removes the boilerplate of
    /// unpacking `Tracked<T>` at the call site.
    pub fn set_tracked<T>(&mut self, field_name: &'static str, tracked: Tracked<T>) -> ProvenanceId
    where
        Field: From<T>,
    {
        let provenance = tracked.provenance();
        self.set(field_name, tracked.into_untracked());
        provenance
    }

    /// Ergonomic setter for [`crate::provenance::Parsed`]: stores `parsed.value`
    /// under `field_name`, folds `parsed.anomalies` into this record's own
    /// [`Anomalies`] (see [`Self::anomalies`]), and returns just the value's
    /// [`ProvenanceId`] — mirroring [`Self::set_tracked`]. Anomalies observed
    /// while parsing a field are evidence about the record as a whole, so
    /// they are never left for the caller to (accidentally) drop.
    pub fn set_parsed<T>(&mut self, field_name: &'static str, parsed: Parsed<T>) -> ProvenanceId
    where
        Field: From<T>,
    {
        self.anomalies.merge(parsed.anomalies);
        self.set(field_name, parsed.value);
        parsed.provenance
    }

    /// Anomalies observed while parsing this record's fields (folded in by
    /// [`Self::set_parsed`]). Cheap: [`Anomalies`] is 16 bytes and allocates
    /// nothing unless a detail message was recorded.
    pub fn anomalies(&self) -> &Anomalies {
        &self.anomalies
    }

    /// This record's confidence, combining its provenance chain with the
    /// anomalies observed while parsing it. Equivalent to
    /// `store.confidence(self.provenance(), self.anomalies())`, without
    /// requiring the call site to construct a placeholder `Anomalies`.
    pub fn confidence(&self, store: &ProvenanceStore) -> Confidence {
        store.confidence(self.provenance, &self.anomalies)
    }

    /// Obtains the field value as a `ForensicTimestamp`, if it is a `Field::Date`.
    pub fn get_date(&self, field_name: &str) -> Option<&ForensicTimestamp> {
        match self.fields.get(field_name) {
            Some(Field::Date(v)) => Some(v),
            _ => None,
        }
    }

    /// Read-only accessor: get the field as `u64` without mutating the container.
    pub fn field_as_u64(&self, field_name: &str) -> Option<u64> {
        match self.fields.get(field_name)? {
            Field::U64(v) => Some(*v),
            Field::I64(v) => u64::try_from(*v).ok(),
            Field::F64(v) => {
                if !v.is_finite() || v.fract() != 0.0 || *v < 0.0 || *v >= u64::MAX as f64 {
                    None
                } else {
                    Some(*v as u64)
                }
            }
            _ => None,
        }
    }

    /// Read-only accessor: get the field as `i64` without mutating the container.
    pub fn field_as_i64(&self, field_name: &str) -> Option<i64> {
        match self.fields.get(field_name)? {
            Field::I64(v) => Some(*v),
            Field::U64(v) => i64::try_from(*v).ok(),
            Field::F64(v) => {
                if !v.is_finite()
                    || v.fract() != 0.0
                    || *v < i64::MIN as f64
                    || *v >= i64::MAX as f64
                {
                    None
                } else {
                    Some(*v as i64)
                }
            }
            _ => None,
        }
    }

    /// Read-only accessor: get the field as `f64` without mutating the container.
    pub fn field_as_f64(&self, field_name: &str) -> Option<f64> {
        match self.fields.get(field_name)? {
            Field::F64(v) => Some(*v),
            Field::U64(v) => Some(*v as f64),
            Field::I64(v) => Some(*v as f64),
            _ => None,
        }
    }

    /// Read-only accessor: get the field as `&str` without mutating the container.
    pub fn field_as_str(&self, field_name: &str) -> Option<&str> {
        match self.fields.get(field_name)? {
            Field::Text(v) => Some(v),
            _ => None,
        }
    }

    /// Read-only accessor: get the field as `Ip` without mutating the container.
    pub fn field_as_ip(&self, field_name: &str) -> Option<Ip> {
        match self.fields.get(field_name)? {
            Field::Ip(v) => Some(*v),
            _ => None,
        }
    }

    /// Read-only accessor: get the field as `&ForensicTimestamp` without mutating the container.
    pub fn field_as_date(&self, field_name: &str) -> Option<&ForensicTimestamp> {
        match self.fields.get(field_name)? {
            Field::Date(v) => Some(v),
            _ => None,
        }
    }

    /// Merge all fields from another `ForensicData` into this one.
    /// Existing keys are overwritten.
    pub fn extend_from(&mut self, other: ForensicData) {
        self.fields.extend(other.fields);
    }

    /// Number of fields stored.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether this container has no fields.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

impl std::fmt::Display for ForensicData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{artifact:{:?}, fields:{:?}}}",
            self.artifact, self.fields
        )
    }
}

pub struct EventIter<'a> {
    children: std::collections::btree_map::Iter<'a, Text, Field>,
}
pub struct EventFieldIter<'a> {
    names: std::collections::btree_set::Iter<'a, Text>,
    fields: &'a BTreeMap<Text, Field>,
}

pub struct EventIterMut<'a> {
    children: std::collections::btree_map::IterMut<'a, Text, Field>,
}

impl<'a> Iterator for EventIter<'a> {
    type Item = (&'a Text, &'a Field);

    fn next(&mut self) -> Option<Self::Item> {
        self.children.next()
    }
}
impl<'a> Iterator for EventIterMut<'a> {
    type Item = (&'a Text, &'a mut Field);

    fn next(&mut self) -> Option<Self::Item> {
        self.children.next()
    }
}
impl<'a> Iterator for EventFieldIter<'a> {
    type Item = (&'a Text, &'a Field);

    fn next(&mut self) -> Option<Self::Item> {
        let field = self.names.next()?;
        let value = self.fields.get(field)?;
        Some((field, value))
    }
}
#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for ForensicData {
    fn deserialize<D>(deserializer: D) -> Result<ForensicData, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DataVisitor)
    }
}
#[cfg(feature = "serde")]
impl Serialize for ForensicData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.fields.len()))?;
        for (k, v) in &self.fields {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}
#[cfg(feature = "serde")]
struct DataVisitor;
#[cfg(feature = "serde")]
impl<'de> Visitor<'de> for DataVisitor {
    type Value = ForensicData;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a valid forensic data")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut artifact = Artifact::default();
        let mut fields = BTreeMap::new();
        while let Some((key, value)) = map.next_entry()? {
            fields.insert(Cow::Owned(key), value);
        }
        if let Some(Field::Text(artf)) = fields.get(ARTIFACT_NAME) {
            artifact = (&artf[..]).into();
        }
        Ok(ForensicData {
            artifact,
            fields,
            provenance: unresolved_deserialized_provenance(),
            anomalies: Anomalies::default(),
        })
    }
}

/// This field-only JSON representation predates provenance and doesn't
/// encode it (see [`ProvenanceStore::to_side_table`](crate::provenance::ProvenanceStore::to_side_table)
/// for the format that does). Mints a fresh id from a throwaway,
/// immediately-dropped store, so the id is guaranteed to be unresolvable
/// against any real [`crate::provenance::ProvenanceStore`] a caller queries it
/// with — [`crate::provenance::ProvenanceStore::confidence`]/`get` degrade
/// this to `Unknown`/`None` gracefully, the same as any other dangling
/// reference, rather than silently claiming a specific confidence level this
/// code has no basis for.
#[cfg(feature = "serde")]
fn unresolved_deserialized_provenance() -> ProvenanceId {
    use crate::provenance::{Acquisition, ProvenanceStore, Recovery, SourceKey};
    ProvenanceStore::new()
        .register_source(SourceKey::Synthetic(
            "forensic_data::deserialize (no provenance in this wire format)".to_string(),
        ))
        .mint(Acquisition::LiveApi, Recovery::Allocated)
}

#[cfg(test)]
mod data_tests {
    #[cfg(feature = "serde")]
    use crate::artifact::{Artifact, WindowsArtifacts};
    use crate::prelude::RegistryArtifacts;
    use crate::utils::testing::test_provenance_id;

    use super::ForensicData;

    #[test]
    fn iterate_fields_test() {
        let mut data = ForensicData::new("host007", RegistryArtifacts::ShellBags.into(), test_provenance_id());
        data.insert("field001".into(), "value001".into());
        data.insert("field002".into(), "value002".into());
        data.insert("field003".into(), "value003".into());

        let mut count = 0;
        for (_name, _value) in data.fields() {
            count += 1;
        }
        assert_eq!(5, count); // 3 + 2
    }

    #[cfg(feature = "serde")]
    #[test]
    fn should_serialize_data() {
        let mut data = ForensicData::new("host007", RegistryArtifacts::ShellBags.into(), test_provenance_id());
        data.insert("field001".into(), "value001".into());
        data.insert("field002".into(), "value002".into());
        data.insert("field003".into(), "value003".into());
        data.insert(
            "field004".into(),
            crate::field::Field::Array(vec!["aaa".into(), "bbb".into()]),
        );
        let deserialized = serde_json::to_string(&data).unwrap();
        assert_eq!(
            r#"{"artifact.host":"host007","artifact.name":"Windows::Registry::ShellBags","field001":"value001","field002":"value002","field003":"value003","field004":["aaa","bbb"]}"#,
            deserialized
        );
        let serialized: ForensicData = serde_json::from_str(&deserialized).unwrap();
        assert_eq!(
            Artifact::Windows(WindowsArtifacts::Registry(RegistryArtifacts::ShellBags)),
            serialized.artifact
        );
        let deserialized2 = serde_json::to_string(&serialized).unwrap();
        assert_eq!(deserialized, deserialized2);
    }
}
