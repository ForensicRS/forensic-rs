use std::{borrow::Cow, path::PathBuf};

use serde::{de::Visitor, Deserializer};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub(crate) mod internal;
pub mod ip;
pub mod utils;

pub use ip::Ip;

use crate::utils::time::Filetime;

pub type Text = Cow<'static, str>;

#[derive(Clone, Default)]
#[non_exhaustive]
pub enum Field {
    #[default]
    Null,
    /// A basic String field
    Text(Text),
    /// IPv4 or IPv6
    Ip(Ip),
    //Domain like contoso.com
    Domain(String),
    User(String),
    ///This is a special field. Uniquely identifies an asset like a system, a
    /// computer or a mobile phone. Reason: the network is dynamic, the IP address
    /// is not fixed certain devices and the hostname of a system can be changed.
    ///
    /// This field should be used with a dataset to recover information about an asset
    /// during the enchance phase:
    /// Getting the IP address, the users logged in the system or another information.
    ///
    /// Can be multiple AssetsID associated with the same event because multiple virtual
    /// machines can be running in the same asset.
    AssetID(String),
    /// unsigned number with 64 bits
    U64(u64),
    /// signed number with 64 bits
    I64(i64),
    /// decimal number with 64 bits
    F64(f64),
    ///A date in a decimal number format with 64 bits
    Date(Filetime),
    Array(Vec<Text>),
    Path(PathBuf),
}

impl std::fmt::Debug for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Null => write!(f, "Null"),
            Self::Text(arg0) => f.write_fmt(format_args!("{:?}", arg0)),
            Self::Ip(arg0) => f.write_fmt(format_args!("{}", arg0)),
            Self::Domain(arg0) => f.write_fmt(format_args!("{:?}", arg0)),
            Self::User(arg0) => f.write_fmt(format_args!("{:?}", arg0)),
            Self::AssetID(arg0) => f.write_fmt(format_args!("{:?}", arg0)),
            Self::U64(arg0) => f.write_fmt(format_args!("{}", arg0)),
            Self::I64(arg0) => f.write_fmt(format_args!("{}", arg0)),
            Self::F64(arg0) => f.write_fmt(format_args!("{}", arg0)),
            Self::Date(arg0) => f.write_fmt(format_args!("{:?}", arg0)),
            Self::Array(arg0) => f.debug_list().entries(arg0.iter()).finish(),
            Self::Path(arg0) => f.write_fmt(format_args!("{:?}", arg0.to_string_lossy())),
        }
    }
}

impl<'a> TryInto<&'a str> for &'a Field {
    type Error = &'static str;

    fn try_into(self) -> Result<&'a str, Self::Error> {
        match self {
            Field::Text(v) => Ok(&v[..]),
            Field::Domain(v) => Ok(&v[..]),
            Field::User(v) => Ok(&v[..]),
            Field::AssetID(v) => Ok(&v[..]),
            _ => Err("Invalid text type"),
        }
    }
}

impl<'a> TryInto<Text> for &'a Field {
    type Error = &'static str;

    fn try_into(self) -> Result<Text, Self::Error> {
        match self {
            Field::Text(v) => Ok(v.clone()),
            Field::Domain(v) => Ok(Text::Owned(v.to_string())),
            Field::User(v) => Ok(Text::Owned(v.to_string())),
            Field::AssetID(v) => Ok(Text::Owned(v.to_string())),
            _ => Err("Invalid type"),
        }
    }
}
impl<'a> TryInto<&'a Text> for &'a Field {
    type Error = &'static str;

    fn try_into(self) -> Result<&'a Text, Self::Error> {
        match self {
            Field::Text(v) => Ok(v),
            _ => Err("Invalid type"),
        }
    }
}

impl<'a> TryInto<&'a Vec<Text>> for &'a Field {
    type Error = &'static str;

    fn try_into(self) -> Result<&'a Vec<Text>, Self::Error> {
        match self {
            Field::Array(v) => Ok(v),
            _ => Err("Invalid type"),
        }
    }
}

impl<'a> TryInto<Vec<Text>> for &'a Field {
    type Error = &'static str;

    fn try_into(self) -> Result<Vec<Text>, Self::Error> {
        let value = match self {
            Field::Array(v) => return Ok(v.clone()),
            Field::AssetID(v) => Text::Owned(v.clone()),
            Field::Text(v) => v.clone(),
            Field::Domain(v) => Text::Owned(v.clone()),
            Field::User(v) => Text::Owned(v.clone()),
            Field::I64(v) => Text::Owned(v.to_string()),
            Field::F64(v) => Text::Owned(v.to_string()),
            Field::U64(v) => Text::Owned(v.to_string()),
            Field::Date(v) => Text::Owned(v.to_string()),
            Field::Ip(v) => Text::Owned(v.to_string()),
            Field::Null => Text::Borrowed(""),
            Field::Path(v) => Text::Owned(v.to_string_lossy().to_string()),
        };
        Ok(vec![value])
    }
}

impl<'a> TryInto<u64> for &'a Field {
    type Error = &'static str;

    fn try_into(self) -> Result<u64, Self::Error> {
        Ok(match self {
            Field::F64(v) => *v as u64,
            Field::I64(v) => *v as u64,
            Field::U64(v) => *v,
            Field::Date(v) => v.filetime() as u64,
            _ => return Err("Invalid type"),
        })
    }
}
impl<'a> TryInto<i64> for &'a Field {
    type Error = &'static str;

    fn try_into(self) -> Result<i64, Self::Error> {
        Ok(match self {
            Field::F64(v) => *v as i64,
            Field::I64(v) => *v as i64,
            Field::U64(v) => *v as i64,
            Field::Date(v) => v.filetime() as i64,
            _ => return Err("Invalid type"),
        })
    }
}
impl<'a> TryInto<f64> for &'a Field {
    type Error = &'static str;

    fn try_into(self) -> Result<f64, Self::Error> {
        Ok(match self {
            Field::F64(v) => *v as f64,
            Field::I64(v) => *v as f64,
            Field::U64(v) => *v as f64,
            Field::Date(v) => v.filetime() as f64,
            _ => return Err("Invalid type"),
        })
    }
}

impl<'a> TryInto<Ip> for &'a Field {
    type Error = &'static str;
    fn try_into(self) -> Result<Ip, Self::Error> {
        Ok(match self {
            Field::Text(v) => Ip::from_ip_str(&v).map_err(|_e| "Invalud ip format")?,
            Field::Ip(v) => v.clone(),
            _ => return Err("Type cannot be converted to Ip"),
        })
    }
}

impl From<&'static str> for Field {
    fn from(v: &'static str) -> Field {
        Field::Text(Text::Borrowed(v))
    }
}
impl From<&String> for Field {
    fn from(v: &String) -> Field {
        Field::Text(Text::Owned(v.to_string()))
    }
}
impl From<String> for Field {
    fn from(v: String) -> Field {
        Field::Text(Text::Owned(v))
    }
}
impl From<Text> for Field {
    fn from(v: Text) -> Field {
        Field::Text(v)
    }
}
impl From<&Text> for Field {
    fn from(v: &Text) -> Field {
        Field::Text(v.clone())
    }
}

impl From<&u64> for Field {
    fn from(v: &u64) -> Field {
        Field::U64(*v)
    }
}
impl From<u64> for Field {
    fn from(v: u64) -> Field {
        Field::U64(v)
    }
}
impl From<&u32> for Field {
    fn from(v: &u32) -> Field {
        Field::U64(*v as u64)
    }
}
impl From<u32> for Field {
    fn from(v: u32) -> Field {
        Field::U64(v as u64)
    }
}

impl From<&i64> for Field {
    fn from(v: &i64) -> Field {
        Field::I64(*v)
    }
}
impl From<i64> for Field {
    fn from(v: i64) -> Field {
        Field::I64(v)
    }
}

impl From<&f64> for Field {
    fn from(v: &f64) -> Field {
        Field::F64(*v)
    }
}
impl From<f64> for Field {
    fn from(v: f64) -> Field {
        Field::F64(v)
    }
}
impl From<Ip> for Field {
    fn from(v: Ip) -> Field {
        Field::Ip(v)
    }
}
impl From<&Ip> for Field {
    fn from(v: &Ip) -> Field {
        Field::Ip(*v)
    }
}
impl From<Vec<Text>> for Field {
    fn from(v: Vec<Text>) -> Field {
        Field::Array(v)
    }
}
impl From<&Vec<Text>> for Field {
    fn from(v: &Vec<Text>) -> Field {
        Field::Array(v.clone())
    }
}

#[cfg(feature = "serde")]
impl Serialize for Field {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Field::Null => serializer.serialize_none(),
            Field::Text(v) => serializer.serialize_str(&v[..]),
            Field::Ip(v) => v.serialize(serializer),
            Field::Domain(v) => serializer.serialize_str(&v[..]),
            Field::User(v) => serializer.serialize_str(&v[..]),
            Field::AssetID(v) => serializer.serialize_str(&v[..]),
            Field::U64(v) => serializer.serialize_u64(*v),
            Field::I64(v) => serializer.serialize_i64(*v),
            Field::F64(v) => serializer.serialize_f64(*v),
            Field::Date(v) => serializer.serialize_str(&v.to_string()),
            Field::Array(v) => v.serialize(serializer),
            Field::Path(v) => serializer.serialize_str(&v.to_string_lossy()[..]),
        }
    }
}
#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Field {
    fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(FieldVisitor)
    }
}
#[cfg(feature = "serde")]
struct FieldVisitor;
#[cfg(feature = "serde")]
impl<'de> Visitor<'de> for FieldVisitor {
    type Value = Field;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a valid forensic data")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Field::Text(Cow::Owned(v.to_string())))
    }
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Field::Text(Cow::Owned(v)))
    }
    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Field::U64(if v { 1 } else { 0 }))
    }

    fn visit_i8<E>(self, v: i8) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Field::I64(v as _))
    }
    fn visit_i16<E>(self, v: i16) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Field::I64(v as _))
    }
    fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Field::I64(v as _))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Field::I64(v))
    }
    fn visit_f32<E>(self, v: f32) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Field::F64(v as _))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Field::F64(v))
    }

    fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Field::U64(v as _))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Field::U64(v))
    }

    fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Field::U64(v as _))
    }
    fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Field::U64(v as _))
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
        Ok(Field::Null)
    }
    fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
        Ok(Field::Null)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>, {
        let mut vc = Vec::with_capacity(32);
        while let Some(value) = seq.next_element()? {
            vc.push(value);
        }
        Ok(Field::Array(vc))
    }
}
