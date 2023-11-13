use std::{borrow::Cow, path::PathBuf};

#[cfg(feature="serde")]
use serde::{Serialize, Deserialize};

pub mod ip;
pub mod utils;
pub(crate) mod internal;

pub use ip::Ip;

pub type Text = Cow<'static, str>;


#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
#[cfg_attr(feature = "serde", serde(untagged))]
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
    Date(i64),
    Array(Vec<Text>),
    Path(PathBuf)
}

impl<'a> TryInto<&'a str> for &'a Field {
    type Error = &'static str;

    fn try_into(self) -> Result<&'a str, Self::Error> {
        match self {
            Field::Text(v) => Ok(&v[..]),
            Field::Domain(v) => Ok(&v[..]),
            Field::User(v) => Ok(&v[..]),
            Field::AssetID(v) => Ok(&v[..]),
            _ => Err("Invalid text type")
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
            _ => Err("Invalid type")
        }
    }
}
impl<'a> TryInto<&'a Text> for &'a Field {
    type Error = &'static str;

    fn try_into(self) -> Result<&'a Text, Self::Error> {
        match self {
            Field::Text(v) => Ok(v),
            _ => Err("Invalid type")
        }
    }
}

impl<'a> TryInto<&'a Vec<Text>> for &'a Field {
    type Error = &'static str;

    fn try_into(self) -> Result<&'a Vec<Text>, Self::Error> {
        match self {
            Field::Array(v) => Ok(v),
            _ => Err("Invalid type")
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
            Field::Date(v) => *v as u64,
            _ => return Err("Invalid type")
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
            Field::Date(v) => *v as i64,
            _ => return Err("Invalid type")
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
            Field::Date(v) => *v as f64,
            _ => return Err("Invalid type")
        })
    }
}

impl<'a> TryInto<Ip> for &'a Field {
    type Error = &'static str;
    fn try_into(self) -> Result<Ip, Self::Error> {
        Ok(match self {
            Field::Text(v) => Ip::from_ip_str(&v).map_err(|_e| "Invalud ip format")?,
            Field::Ip(v) => v.clone(),
            _ => return Err("Type cannot be converted to Ip")
        })
    }
}

impl From<&'static str> for Field {
    fn from(v : &'static str) -> Field {
        Field::Text(Text::Borrowed(v))
    }
}
impl From<&String> for Field {
    fn from(v : &String) -> Field {
        Field::Text(Text::Owned(v.to_string()))
    }
}
impl From<String> for Field {
    fn from(v : String) -> Field {
        Field::Text(Text::Owned(v))
    }
}
impl From<Text> for Field {
    fn from(v : Text) -> Field {
        Field::Text(v)
    }
}
impl From<&Text> for Field {
    fn from(v : &Text) -> Field {
        Field::Text(v.clone())
    }
}

impl From<&u64> for Field {
    fn from(v : &u64) -> Field {
        Field::U64(*v)
    }
}
impl From<u64> for Field {
    fn from(v : u64) -> Field {
        Field::U64(v)
    }
}
impl From<&i64> for Field {
    fn from(v : &i64) -> Field {
        Field::I64(*v)
    }
}
impl From<i64> for Field {
    fn from(v : i64) -> Field {
        Field::I64(v)
    }
}

impl From<&f64> for Field {
    fn from(v : &f64) -> Field {
        Field::F64(*v)
    }
}
impl From<f64> for Field {
    fn from(v : f64) -> Field {
        Field::F64(v)
    }
}
impl From<Ip> for Field {
    fn from(v : Ip) -> Field {
        Field::Ip(v)
    }
}
impl From<&Ip> for Field {
    fn from(v : &Ip) -> Field {
        Field::Ip(*v)
    }
}
impl From<Vec<Text>> for Field {
    fn from(v : Vec<Text>) -> Field {
        Field::Array(v)
    }
}
impl From<&Vec<Text>> for Field {
    fn from(v : &Vec<Text>) -> Field {
        Field::Array(v.clone())
    }
}
