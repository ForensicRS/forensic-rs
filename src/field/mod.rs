use std::borrow::Cow;

#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize};

pub mod ip;
pub mod utils;

pub use ip::Ip;

use compact_str::CompactString;

use crate::err::ForensicError;
use crate::utils::time::{Filetime, ForensicTimestamp};

fn field_cast_err(from: &'static str, to: &'static str) -> ForensicError {
    ForensicError::cast_error(from, to, CompactString::const_new("incompatible field variant"))
}

fn field_range_err(from: &'static str, to: &'static str) -> ForensicError {
    ForensicError::cast_error(
        from,
        to,
        CompactString::const_new("value is outside the target range"),
    )
}

fn f64_to_u64(value: f64) -> Result<u64, ForensicError> {
    if !value.is_finite() || value.fract() != 0.0 || value < 0.0 || value >= u64::MAX as f64 {
        return Err(field_range_err("Field::F64", "u64"));
    }
    Ok(value as u64)
}

fn f64_to_i64(value: f64) -> Result<i64, ForensicError> {
    if !value.is_finite()
        || value.fract() != 0.0
        || value < i64::MIN as f64
        || value >= i64::MAX as f64
    {
        return Err(field_range_err("Field::F64", "i64"));
    }
    Ok(value as i64)
}

pub type Text = Cow<'static, str>;

/// Create a `Text` from a static string literal (zero-copy).
pub fn text(s: &'static str) -> Text {
    Cow::Borrowed(s)
}

/// Create a `Text` from an owned `String`.
pub fn text_owned(s: String) -> Text {
    Cow::Owned(s)
}

#[derive(Clone, Default)]
#[non_exhaustive]
pub enum Field {
    #[default]
    Null,
    /// A basic String field
    Text(Text),
    /// IPv4 or IPv6
    Ip(Ip),
    /// unsigned number with 64 bits
    U64(u64),
    /// signed number with 64 bits
    I64(i64),
    /// decimal number with 64 bits
    F64(f64),
    /// A canonical nanosecond-precision forensic timestamp.
    Date(ForensicTimestamp),
    Array(Vec<Text>),
}

impl PartialEq for Field {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Field::Null, Field::Null) => true,
            (Field::Text(a), Field::Text(b)) => a == b,
            (Field::Ip(a), Field::Ip(b)) => a == b,
            (Field::U64(a), Field::U64(b)) => a == b,
            (Field::I64(a), Field::I64(b)) => a == b,
            (Field::F64(a), Field::F64(b)) => a.to_bits() == b.to_bits(),
            (Field::Date(a), Field::Date(b)) => a == b,
            (Field::Array(a), Field::Array(b)) => a == b,
            _ => false,
        }
    }
}

impl std::fmt::Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Field::Null => write!(f, "null"),
            Field::Text(v) => write!(f, "{}", v),
            Field::Ip(v) => write!(f, "{}", v),
            Field::U64(v) => write!(f, "{}", v),
            Field::I64(v) => write!(f, "{}", v),
            Field::F64(v) => write!(f, "{}", v),
            Field::Date(v) => write!(f, "{}", v),
            Field::Array(v) => {
                for (i, item) in v.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", item)?;
                }
                Ok(())
            }
        }
    }
}

impl std::fmt::Debug for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Null => write!(f, "Null"),
            Self::Text(arg0) => f.write_fmt(format_args!("{:?}", arg0)),
            Self::Ip(arg0) => f.write_fmt(format_args!("{}", arg0)),
            Self::U64(arg0) => f.write_fmt(format_args!("{}", arg0)),
            Self::I64(arg0) => f.write_fmt(format_args!("{}", arg0)),
            Self::F64(arg0) => f.write_fmt(format_args!("{}", arg0)),
            Self::Date(arg0) => f.write_fmt(format_args!("{:?}", arg0)),
            Self::Array(arg0) => f.debug_list().entries(arg0.iter()).finish(),
        }
    }
}

impl<'a> TryInto<&'a str> for &'a Field {
    type Error = ForensicError;

    fn try_into(self) -> Result<&'a str, Self::Error> {
        match self {
            Field::Text(v) => Ok(&v[..]),
            _ => Err(field_cast_err("Field", "&str")),
        }
    }
}

impl TryInto<Text> for &Field {
    type Error = ForensicError;

    fn try_into(self) -> Result<Text, Self::Error> {
        match self {
            Field::Text(v) => Ok(v.clone()),
            _ => Err(field_cast_err("Field", "Text")),
        }
    }
}
impl<'a> TryInto<&'a Text> for &'a Field {
    type Error = ForensicError;

    fn try_into(self) -> Result<&'a Text, Self::Error> {
        match self {
            Field::Text(v) => Ok(v),
            _ => Err(field_cast_err("Field", "&Text")),
        }
    }
}

impl<'a> TryInto<&'a Vec<Text>> for &'a Field {
    type Error = ForensicError;

    fn try_into(self) -> Result<&'a Vec<Text>, Self::Error> {
        match self {
            Field::Array(v) => Ok(v),
            _ => Err(field_cast_err("Field", "&Vec<Text>")),
        }
    }
}

impl TryInto<Vec<Text>> for &Field {
    type Error = ForensicError;

    fn try_into(self) -> Result<Vec<Text>, Self::Error> {
        let value = match self {
            Field::Array(v) => return Ok(v.clone()),
            Field::Text(v) => v.clone(),
            Field::I64(v) => Text::Owned(v.to_string()),
            Field::F64(v) => Text::Owned(v.to_string()),
            Field::U64(v) => Text::Owned(v.to_string()),
            Field::Date(v) => Text::Owned(v.to_string()),
            Field::Ip(v) => Text::Owned(v.to_string()),
            Field::Null => Text::Borrowed(""),
        };
        Ok(vec![value])
    }
}

impl TryInto<u64> for &Field {
    type Error = ForensicError;

    fn try_into(self) -> Result<u64, Self::Error> {
        Ok(match self {
            Field::F64(v) => f64_to_u64(*v)?,
            Field::I64(v) => u64::try_from(*v).map_err(|_| field_range_err("Field::I64", "u64"))?,
            Field::U64(v) => *v,
            Field::Date(v) => u64::try_from(v.to_unix_nanos())
                .map_err(|_| field_range_err("Field::Date", "u64"))?,
            Field::Text(v) => v
                .parse::<u64>()
                .map_err(|_| field_cast_err("Field::Text", "u64"))?,
            _ => return Err(field_cast_err("Field", "u64")),
        })
    }
}
impl TryInto<i64> for &Field {
    type Error = ForensicError;

    fn try_into(self) -> Result<i64, Self::Error> {
        Ok(match self {
            Field::F64(v) => f64_to_i64(*v)?,
            Field::I64(v) => *v,
            Field::U64(v) => i64::try_from(*v).map_err(|_| field_range_err("Field::U64", "i64"))?,
            Field::Date(v) => i64::try_from(v.to_unix_nanos())
                .map_err(|_| field_range_err("Field::Date", "i64"))?,
            Field::Text(v) => v
                .parse::<i64>()
                .map_err(|_| field_cast_err("Field::Text", "i64"))?,
            _ => return Err(field_cast_err("Field", "i64")),
        })
    }
}
impl TryInto<f64> for &Field {
    type Error = ForensicError;

    fn try_into(self) -> Result<f64, Self::Error> {
        Ok(match self {
            Field::F64(v) => *v,
            Field::I64(v) => *v as f64,
            Field::U64(v) => *v as f64,
            Field::Date(v) => v.to_unix_nanos() as f64,
            Field::Text(v) => v
                .parse::<f64>()
                .map_err(|_| field_cast_err("Field::Text", "f64"))?,
            _ => return Err(field_cast_err("Field", "f64")),
        })
    }
}

impl TryInto<Ip> for &Field {
    type Error = ForensicError;
    fn try_into(self) -> Result<Ip, Self::Error> {
        Ok(match self {
            Field::Text(v) => {
                Ip::from_ip_str(v).map_err(|_e| field_cast_err("Field::Text", "Ip"))?
            }
            Field::Ip(v) => *v,
            _ => return Err(field_cast_err("Field", "Ip")),
        })
    }
}

/// The result of accessing a field with a type expectation.
///
/// - `Some(T)` — the field exists and was successfully cast or converted to `T`
/// - `None` — the field does not exist
/// - `InvalidCast` — the field exists but cannot be converted to `T`
#[derive(Debug, Clone, PartialEq)]
pub enum FieldAccess<T> {
    Some(T),
    None,
    InvalidCast,
}

impl<T> FieldAccess<T> {
    pub fn is_some(&self) -> bool {
        matches!(self, FieldAccess::Some(_))
    }
    pub fn is_none(&self) -> bool {
        matches!(self, FieldAccess::None)
    }
    pub fn is_invalid(&self) -> bool {
        matches!(self, FieldAccess::InvalidCast)
    }
    pub fn ok(self) -> Option<T> {
        match self {
            FieldAccess::Some(v) => Option::Some(v),
            _ => Option::None,
        }
    }
    pub fn unwrap(self) -> T {
        match self {
            FieldAccess::Some(v) => v,
            FieldAccess::None => panic!("called unwrap on FieldAccess::None"),
            FieldAccess::InvalidCast => panic!("called unwrap on FieldAccess::InvalidCast"),
        }
    }
    pub fn unwrap_or(self, default: T) -> T {
        match self {
            FieldAccess::Some(v) => v,
            _ => default,
        }
    }
    pub fn unwrap_or_else<F: FnOnce() -> T>(self, f: F) -> T {
        match self {
            FieldAccess::Some(v) => v,
            _ => f(),
        }
    }
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> FieldAccess<U> {
        match self {
            FieldAccess::Some(v) => FieldAccess::Some(f(v)),
            FieldAccess::None => FieldAccess::None,
            FieldAccess::InvalidCast => FieldAccess::InvalidCast,
        }
    }
    pub fn and_then<U, F: FnOnce(T) -> FieldAccess<U>>(self, f: F) -> FieldAccess<U> {
        match self {
            FieldAccess::Some(v) => f(v),
            FieldAccess::None => FieldAccess::None,
            FieldAccess::InvalidCast => FieldAccess::InvalidCast,
        }
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
impl From<bool> for Field {
    fn from(v: bool) -> Field {
        Field::U64(v as u64)
    }
}
impl From<Filetime> for Field {
    fn from(v: Filetime) -> Field {
        Field::Date(v.into())
    }
}
impl From<ForensicTimestamp> for Field {
    fn from(v: ForensicTimestamp) -> Field {
        Field::Date(v)
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
            Field::U64(v) => serializer.serialize_u64(*v),
            Field::I64(v) => serializer.serialize_i64(*v),
            Field::F64(v) => serializer.serialize_f64(*v),
            Field::Date(v) => v.serialize(serializer),
            Field::Array(v) => v.serialize(serializer),
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
        E: serde::de::Error,
    {
        Ok(Field::Null)
    }
    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Field::Null)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut vc = Vec::with_capacity(32);
        while let Some(value) = seq.next_element()? {
            vc.push(value);
        }
        Ok(Field::Array(vc))
    }
}

// ============================================================================
// ForensicValue <-> Field conversions
// ============================================================================
//
// Lossy conversion rules:
//   Bool     -> U64 (0 or 1)
//   I64      -> I64
//   U64      -> U64
//   F64      -> F64
//   DateTime -> Date
//   Guid     -> Text (formatted)
//   Text     -> Text
//   Binary   -> Null (no Field equivalent)
//   Null     -> Null

use crate::traits::db::ForensicValue;

impl From<ForensicValue> for Field {
    fn from(value: ForensicValue) -> Self {
        match value {
            ForensicValue::Null => Field::Null,
            ForensicValue::Bool(v) => Field::U64(if v { 1 } else { 0 }),
            ForensicValue::I64(v) => Field::I64(v),
            ForensicValue::U64(v) => Field::U64(v),
            ForensicValue::F64(v) => Field::F64(v),
            ForensicValue::DateTime(v) => Field::Date(v),
            ForensicValue::Guid(v) => Field::Text(Cow::Owned(format!(
                "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                u32::from_le_bytes([v[0], v[1], v[2], v[3]]),
                u16::from_le_bytes([v[4], v[5]]),
                u16::from_le_bytes([v[6], v[7]]),
                v[8],
                v[9],
                v[10],
                v[11],
                v[12],
                v[13],
                v[14],
                v[15]
            ))),
            ForensicValue::Text(v) => Field::Text(Cow::Owned(v)),
            ForensicValue::Binary(_) => Field::Null,
        }
    }
}

impl From<Field> for ForensicValue {
    fn from(field: Field) -> Self {
        match field {
            Field::Null => ForensicValue::Null,
            Field::Text(v) => ForensicValue::Text(v.into_owned()),
            Field::Ip(v) => ForensicValue::Text(v.to_string()),
            Field::U64(v) => ForensicValue::U64(v),
            Field::I64(v) => ForensicValue::I64(v),
            Field::F64(v) => ForensicValue::F64(v),
            Field::Date(v) => ForensicValue::DateTime(v),
            Field::Array(v) => {
                if let Some(first) = v.into_iter().next() {
                    ForensicValue::Text(first.into_owned())
                } else {
                    ForensicValue::Null
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_lossy_integer_conversions() {
        let negative = Field::I64(-1);
        let oversized = Field::U64(i64::MAX as u64 + 1);
        let fractional = Field::F64(1.5);
        let non_finite = Field::F64(f64::NAN);

        assert!(TryInto::<u64>::try_into(&negative).is_err());
        assert!(TryInto::<i64>::try_into(&oversized).is_err());
        assert!(TryInto::<u64>::try_into(&fractional).is_err());
        assert!(TryInto::<i64>::try_into(&non_finite).is_err());
    }

    #[test]
    fn accepts_integral_numeric_conversions_in_range() {
        let signed = Field::I64(42);
        let unsigned = Field::U64(42);
        let decimal = Field::F64(42.0);

        assert_eq!(TryInto::<u64>::try_into(&signed).unwrap(), 42);
        assert_eq!(TryInto::<i64>::try_into(&unsigned).unwrap(), 42);
        assert_eq!(TryInto::<u64>::try_into(&decimal).unwrap(), 42);
    }
}
