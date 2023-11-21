use std::{borrow::Cow, collections::BTreeMap};

#[cfg(feature="serde")]
use serde::{Deserialize, Serialize, de::Visitor, Deserializer, ser::SerializeMap};

use crate::{prelude::{Artifact, *}, field::{internal::{InternalField, PreStoredField}, Text, Field, Ip}, context::context};

/// Basic container for all Forensic Data inside an artifact
#[derive(Debug, Clone)]
pub struct ForensicData {
    artifact : Artifact,
    pub(crate) fields: BTreeMap<Text, InternalField>,
}

impl Default for ForensicData {
    fn default() -> Self {
        let context = context();
        let mut fields = BTreeMap::new();
        fields.insert(Text::Borrowed(ARTIFACT_HOST), Field::Text(Text::Owned(context.host)).into());
        fields.insert(Text::Borrowed(ARTIFACT_TENANT), Field::Text(Text::Owned(context.tenant)).into());
        fields.insert(Text::Borrowed(ARTIFACT_NAME), Field::Text(Text::Owned(context.artifact.to_string())).into());
        Self {
            fields,
            artifact : context.artifact
        }
    }
}


impl<'a> ForensicData {
    pub fn new(host : &str, artifact : Artifact) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert(Text::Borrowed(ARTIFACT_HOST), Field::Text(Text::Owned(host.to_string())).into());
        fields.insert(Text::Borrowed(ARTIFACT_NAME), Field::Text(Text::Owned(artifact.to_string())).into());
        Self {
            fields,
            artifact
        }
    }

    pub fn artifact(&self) -> &Artifact {
        &self.artifact
    }

    pub fn host(&'a self) -> &'a str {
        match self.field(ARTIFACT_HOST) {
            Some(v) => {
                match v {
                    Field::Text(v) => v,
                    _ => ""
                }
            },
            None => ""
        }
    }

    pub fn field(&self, field_name : &str) -> Option<&Field> {
        Some(&self.fields.get(field_name)?.original)
    }

    pub fn has_field(&self, field_name : &str) -> bool {
        self.fields.contains_key(field_name)
    }

    pub fn field_mut(&'a mut self, field_name: &str) -> Option<&mut Field> {
        Some(&mut self.fields.get_mut(field_name)?.original)
    }
    pub fn add_field(&mut self, field_name: &str, field_value: Field) {
        let field_name = Text::Owned(field_name.to_owned());
        self.insert(field_name, field_value);
    }
    pub fn insert(&mut self, field_name: Text, field_value: Field) {
        self.fields.insert(field_name, field_value.into());
    }
    /// Obtains the casted value of the field into i64 and caches it
    pub fn i64_field(&'a mut self, field_name: &str) -> Option<i64> {
        let field = self.fields.get_mut(field_name)?;
        match field.ni64.as_ref() {
            PreStoredField::Invalid => return None,
            PreStoredField::None => {},
            PreStoredField::Some(v) => return Some(*v)
        };
        let i64field : Option<i64> = (&field.original).try_into().ok();
        let pfield = match i64field {
            Some(v) => PreStoredField::Some(v),
            None => PreStoredField::Invalid
        };
        field.ni64 = Box::new(pfield);
        match field.ni64.as_ref() {
            PreStoredField::Some(v) => Some(*v),
            _ => None
        }
    }
    /// Obtains the casted value of the field into f64 and caches it
    pub fn f64_field(&'a mut self, field_name: &str) -> Option<f64> {
        let field = self.fields.get_mut(field_name)?;
        match field.nf64.as_ref() {
            PreStoredField::Invalid => return None,
            PreStoredField::None => {},
            PreStoredField::Some(v) => return Some(*v)
        };
        let i64field : Option<f64> = (&field.original).try_into().ok();
        let pfield = match i64field {
            Some(v) => PreStoredField::Some(v),
            None => PreStoredField::Invalid
        };
        field.nf64 = Box::new(pfield);
        match field.nf64.as_ref() {
            PreStoredField::Some(v) => Some(*v),
            _ => None
        }
    }
    /// Obtains the casted value of the field into u64 and caches it
    pub fn u64_field(&'a mut self, field_name: &str) -> Option<u64> {
        let field = self.fields.get_mut(field_name)?;
        match field.nu64.as_ref() {
            PreStoredField::Invalid => return None,
            PreStoredField::None => {},
            PreStoredField::Some(v) => return Some(*v)
        };
        let i64field : Option<u64> = (&field.original).try_into().ok();
        let pfield = match i64field {
            Some(v) => PreStoredField::Some(v),
            None => PreStoredField::Invalid
        };
        field.nu64 = Box::new(pfield);
        match field.nu64.as_ref() {
            PreStoredField::Some(v) => Some(*v),
            _ => None
        }
    }
    /// Obtains the casted value of the field into IP and caches it
    pub fn ip_field(&'a mut self, field_name: &str) -> Option<Ip> {
        let field = self.fields.get_mut(field_name)?;
        match field.ip.as_ref() {
            PreStoredField::Invalid => return None,
            PreStoredField::None => {},
            PreStoredField::Some(v) => return Some(*v)
        };
        let i64field : Option<Ip> = (&field.original).try_into().ok();
        let pfield = match i64field {
            Some(v) => PreStoredField::Some(v),
            None => PreStoredField::Invalid
        };
        field.ip = Box::new(pfield);
        match field.ip.as_ref() {
            PreStoredField::Some(v) => Some(*v),
            _ => None
        }
    }
    /// Obtains the casted value of the field into Text and caches it
    pub fn txt_field(&'a mut self, field_name: &str) -> Option<&Text> {

        let mut has_value = false;

        let field = self.fields.get_mut(field_name)?;
        match field.text.as_ref() {
            PreStoredField::Invalid => return None,
            PreStoredField::None => {},
            PreStoredField::Some(_) => {
                has_value = true;
            }
        };
        if has_value {
            match field.text.as_ref() {
                PreStoredField::Some(v) => return Some(v),
                _ => return None
            }
        }
        let txtfield : Option<Text> = (&field.original).try_into().ok();
        let pfield = match txtfield {
            Some(v) => PreStoredField::Some(v),
            None => PreStoredField::Invalid
        };
        field.text = Box::new(pfield);
        match field.text.as_ref() {
            PreStoredField::Some(v) => Some(v),
            _ => None
        }
    }
    /// Obtains the casted value of the field into Vec<Text> and caches it
    pub fn array_field(&'a mut self, field_name: &str) -> Option<&Vec<Text>> {

        let mut has_value = false;

        let field = self.fields.get_mut(field_name)?;
        match field.array.as_ref() {
            PreStoredField::Invalid => return None,
            PreStoredField::None => {},
            PreStoredField::Some(_) => {
                has_value = true;
            }
        };
        if has_value {
            match field.array.as_ref() {
                PreStoredField::Some(v) => return Some(v),
                _ => return None
            }
        }
        let txtfield : Option<Vec<Text>> = (&field.original).try_into().ok();
        let pfield = match txtfield {
            Some(v) => PreStoredField::Some(v),
            None => PreStoredField::Invalid
        };
        field.array = Box::new(pfield);
        match field.array.as_ref() {
            PreStoredField::Some(v) => Some(v),
            _ => None
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

}


pub struct ForensicDataInspector<'a> {
    iter : std::collections::btree_map::Iter<'a, Cow<'static, str>, String>
}
pub struct ForensicDataInspectorMut<'a> {
    iter : std::collections::btree_map::IterMut<'a, Cow<'static, str>, String>
}

impl<'a> Iterator for ForensicDataInspector<'a> {
    type Item = (&'a Cow<'a,str>,&'a String);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|wrapper| (wrapper.0, wrapper.1))
    }
}
impl<'a> Iterator for ForensicDataInspectorMut<'a> {
    type Item = (&'a Cow<'a,str>,&'a mut String);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|wrapper| (wrapper.0, wrapper.1))
    }
}

impl std::fmt::Display for ForensicData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{artifact:{:?}, fields:{:?}}}", self.artifact, self.fields)
    }
}

pub struct EventIter<'a> {
    children: std::collections::btree_map::Iter<'a, Text, InternalField>,
}
pub struct EventFieldIter<'a> {
    names: std::collections::btree_set::Iter<'a, Text>,
    fields: &'a BTreeMap<Text, InternalField>,
}

pub struct EventIterMut<'a> {
    children: std::collections::btree_map::IterMut<'a, Text, InternalField>,
}

impl<'a> Iterator for EventIter<'a> {
    type Item = (&'a Text, &'a Field);

    fn next(&mut self) -> Option<Self::Item> {
        let evt = self.children.next()?;
        Some((evt.0, &evt.1.original))
    }
}
impl<'a> Iterator for EventIterMut<'a> {
    type Item = (&'a Text, &'a mut Field);

    fn next(&mut self) -> Option<Self::Item> {
        let evt = self.children.next()?;
        Some((evt.0, &mut evt.1.original))
    }
}
impl<'a> Iterator for EventFieldIter<'a> {
    type Item = (&'a Text, &'a Field);

    fn next(&mut self) -> Option<Self::Item> {
        let field = self.names.next()?;
        let value = self.fields.get(field)?;
        Some((field, &value.original))
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
        S: serde::Serializer {
        let mut map = serializer.serialize_map(Some(self.fields.len()))?;
        for (k,v) in &self.fields {
            map.serialize_entry(k, &v.original)?;
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
            A: serde::de::MapAccess<'de>, {
        let mut artifact = Artifact::default();
        let mut fields = BTreeMap::new();
        while let Some((key, value)) = map.next_entry()? {
            fields.insert(Cow::Owned(key), InternalField::new(value));
        }
        if let Some(artf) = fields.get(ARTIFACT_NAME) {
            if let Field::Text(artf) = &artf.original {
                artifact = (&artf[..]).into();
            }
        }
        Ok(ForensicData { artifact, fields })
    }
}

#[cfg(test)]
mod data_tests {
    use crate::{prelude::RegistryArtifacts, artifact::{Artifact, WindowsArtifacts}};

    use super::ForensicData;

    #[test]
    fn iterate_fields_test() {
        let mut data = ForensicData::new("host007", RegistryArtifacts::ShellBags.into());
        data.insert("field001".into(), "value001".into());
        data.insert("field002".into(), "value002".into());
        data.insert("field003".into(), "value003".into());

        let mut count = 0;
        for (_name, _value) in data.fields() {
            count += 1;
        }
        assert_eq!(5, count);// 3 + 2
    }

    #[test]
    fn should_serialize_data() {
        let mut data = ForensicData::new("host007", RegistryArtifacts::ShellBags.into());
        data.insert("field001".into(), "value001".into());
        data.insert("field002".into(), "value002".into());
        data.insert("field003".into(), "value003".into());
        data.insert("field004".into(), crate::field::Field::Array(vec!["aaa".into(), "bbb".into()]));
        let deserialized = serde_json::to_string(&data).unwrap();
        assert_eq!(r#"{"artifact.host":"host007","artifact.name":"Windows::Registry::ShellBags","field001":"value001","field002":"value002","field003":"value003","field004":["aaa","bbb"]}"#, deserialized);
        let serialized : ForensicData = serde_json::from_str(&deserialized).unwrap();
        assert_eq!(Artifact::Windows(WindowsArtifacts::Registry(RegistryArtifacts::ShellBags)), serialized.artifact);
        let deserialized2 = serde_json::to_string(&serialized).unwrap();
        assert_eq!(deserialized, deserialized2);
    }
}