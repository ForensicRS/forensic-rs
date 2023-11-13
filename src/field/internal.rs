use serde::{Serialize, Deserialize};

use super::{Field, Text, Ip};


#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub enum PreStoredField<T> {
    Invalid,
    #[default]
    None,
    Some(T)
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct InternalField {
    pub original : Field,
    pub array : Box<PreStoredField<Vec<Text>>>,
    pub text : Box<PreStoredField<Text>>,
    pub nu64 : Box<PreStoredField<u64>>,
    pub ni64 : Box<PreStoredField<i64>>,
    pub nf64 : Box<PreStoredField<f64>>,
    pub ip : Box<PreStoredField<Ip>>
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