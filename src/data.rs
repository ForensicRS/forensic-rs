use std::{borrow::Cow, collections::BTreeMap};

use crate::prelude::Artifact;


/// Basic container for all Forensic Data inside an artifact
pub struct ForensicData {
    artifact : Artifact,
    host : String,
    fields : BTreeMap<Cow<'static, str>, String>
}

impl ForensicData {
    pub fn new(host : &str, artifact : Artifact) -> Self {
        Self {
            artifact,
            host : host.to_string(),
            fields : BTreeMap::new()
        }
    }

    pub fn artifact(&self) -> &Artifact {
        &self.artifact
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn field(&self, field_name : &str) -> Option<&String> {
        self.fields.get(field_name)
    }

    pub fn has_field(&self, field_name : &str) -> bool {
        self.fields.contains_key(field_name)
    }

    pub fn fields(&self) -> ForensicDataInspector {
        ForensicDataInspector { iter: self.fields.iter() }
    }
    pub fn fields_mut(&mut self) -> ForensicDataInspectorMut {
        ForensicDataInspectorMut { iter: self.fields.iter_mut() }
    }

    pub fn insert(&mut self, name : &str, value : String) {
        self.fields.insert(Cow::Owned(name.to_owned()), value);
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

#[cfg(test)]
mod data_tests {
    use crate::prelude::RegistryArtifacts;

    use super::ForensicData;

    #[test]
    fn iterate_fields_test() {
        let mut data = ForensicData::new("host007", RegistryArtifacts::ShellBags.into());
        data.insert("field001", "value001".into());
        data.insert("field002", "value002".into());
        data.insert("field003", "value003".into());

        let mut count = 0;
        for (_name, _value) in data.fields() {
            count += 1;
        }
        assert_eq!(3, count);

    }

    #[test]
    fn iterate_mut_fields_test() {
        let mut data = ForensicData::new("host007",  RegistryArtifacts::ShellBags.into());
        data.insert("field001", "value001".into());
        data.insert("field002", "value002".into());
        data.insert("field003", "value003".into());

        for (_name, value) in data.fields_mut() {
            value.push('Ñ');
        }
        for (_name, value) in data.fields() {
            assert!(value.ends_with('Ñ'));
        }

    }
}