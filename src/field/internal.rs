use serde::{Serialize, Deserialize};

use super::{Field, Text, Ip};


#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub enum PreStoredField<T> {
    Invalid,
    #[default]
    None,
    Some(T)
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct InternalField {
    pub original : Field,
    pub array : Box<PreStoredField<Vec<Text>>>,
    pub text : Box<PreStoredField<Text>>,
    pub nu64 : Box<PreStoredField<u64>>,
    pub ni64 : Box<PreStoredField<i64>>,
    pub nf64 : Box<PreStoredField<f64>>,
    pub ip : Box<PreStoredField<Ip>>
}

impl InternalField {
    pub fn new(field : Field) -> Self {
        field.into()
    }
}

impl Into<InternalField> for Field{
    fn into(self) -> InternalField {
        let mut ifield = InternalField {
            original : self,
            ..Default::default()
        };
        match &ifield.original {
            Field::F64(v) => {
                ifield.nf64 = Box::new(PreStoredField::Some(*v));
            },
            Field::I64(v) => {
                ifield.ni64 = Box::new(PreStoredField::Some(*v));
            },
            Field::Date(v) => {
                ifield.ni64 = Box::new(PreStoredField::Some(*v));
            },
            Field::U64(v) => {
                ifield.nu64 = Box::new(PreStoredField::Some(*v));
            },
            Field::Ip(v) => {
                ifield.ip = Box::new(PreStoredField::Some(*v));
            },
            _ => {}
        }
        ifield
    }
}

impl Serialize for InternalField {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
            match &self.original {
                Field::Null => serializer.serialize_none(),
                Field::Text(v) => serializer.serialize_str(&v[..]),
                Field::Ip(v) => v.serialize(serializer),
                Field::Domain(v) => serializer.serialize_str(&v[..]),
                Field::User(v) => serializer.serialize_str(&v[..]),
                Field::AssetID(v) => serializer.serialize_str(&v[..]),
                Field::U64(v) => serializer.serialize_u64(*v),
                Field::I64(v) => serializer.serialize_i64(*v),
                Field::F64(v) => serializer.serialize_f64(*v),
                Field::Date(v) => serializer.serialize_i64(*v),
                Field::Array(v) => v.serialize(serializer),
                Field::Path(v) => serializer.serialize_str(&v.to_string_lossy()[..]),
            }
    }
}