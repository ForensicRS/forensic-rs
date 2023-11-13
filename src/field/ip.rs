use std::fmt::Display;

use serde::{Deserialize, Serialize, Serializer};

use super::utils::{ipv4_to_str, ipv6_to_str, is_local_ipv4, is_local_ipv6, ipv4_from_str, ipv6_from_str};
use super::Field;


#[derive(Deserialize, Debug, Clone, Copy)]
pub enum Ip {
    V4(u32),
    V6(u128),
}
impl PartialEq for Ip {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Ip::V4(v1), Ip::V4(v2)) => v1 == v2,
            (Ip::V6(v1), Ip::V6(v2)) => v1 == v2,
            //TODO: IPv4 in IPV6
            _ => false,
        }
    }
}

impl Ip {
    pub fn is_local(&self) -> bool {
        match self {
            Ip::V4(ip) => is_local_ipv4(*ip),
            Ip::V6(ip) => is_local_ipv6(*ip),
        }
    }
    pub fn equals(&self, val: &str) -> bool {
        match self {
            Ip::V4(ip1) => match ipv4_from_str(val) {
                Ok(ip2) => return *ip1 == ip2,
                Err(_) => false,
            },
            Ip::V6(ip1) => match ipv6_from_str(val) {
                Ok(ip2) => return *ip1 == ip2,
                Err(_) => false,
            },
        }
    }
    pub fn from_ip_str(val: &str) -> Result<Ip, &'static str> {
        match ipv4_from_str(&val) {
            Ok(val) => Ok(Ip::V4(val)),
            Err(_) => {
                let ip = ipv6_from_str(&val)?;
                Ok(Ip::V6(ip))
            }
        }
    }
}
impl Serialize for Ip {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&(&self.to_string())[..])
    }
}

impl From<[u32; 4]> for Ip {
    fn from(v: [u32; 4]) -> Self {
        Self::V4(
            ((v[0] & 0xff) << 24) + ((v[1] & 0xff) << 16) + ((v[2] & 0xff) << 8) + (v[3] & 0xff),
        )
    }
}
impl From<[u32; 16]> for Ip {
    fn from(v: [u32; 16]) -> Self {
        Self::V6(
            ((v[0] as u128 & 0xffu128) << 120)
                + ((v[1] as u128 & 0xffu128) << 112)
                + ((v[2] as u128 & 0xffu128) << 104)
                + ((v[3] as u128 & 0xffu128) << 96)
                + ((v[4] as u128 & 0xffu128) << 88)
                + ((v[5] as u128 & 0xffu128) << 80)
                + ((v[6] as u128 & 0xffu128) << 72)
                + ((v[7] as u128 & 0xffu128) << 64)
                + ((v[8] as u128 & 0xffu128) << 56)
                + ((v[9] as u128 & 0xffu128) << 48)
                + ((v[10] as u128 & 0xffu128) << 40)
                + ((v[11] as u128 & 0xffu128) << 32)
                + ((v[12] as u128 & 0xffu128) << 24)
                + ((v[13] as u128 & 0xffu128) << 16)
                + ((v[14] as u128 & 0xffu128) << 8)
                + (v[15] as u128 & 0xffu128),
        )
    }
}
impl From<&u32> for Ip {
    fn from(v: &u32) -> Self {
        Self::V4(*v)
    }
}
impl From<u32> for Ip {
    fn from(v: u32) -> Self {
        Self::V4(v)
    }
}
impl From<&u128> for Ip {
    fn from(v: &u128) -> Self {
        Self::V6(*v)
    }
}
impl From<u128> for Ip {
    fn from(v: u128) -> Self {
        Self::V6(v)
    }
}

impl<'a> TryFrom<&'a Field> for &'a Ip {
    type Error = &'static str;

    fn try_from(value: &Field) -> Result<&Ip, Self::Error> {
        match value {
            Field::Ip(ip) => Ok(ip),
            _ => Err("Not an IP"),
        }
    }
}

impl TryFrom<Field> for Ip {
    type Error = &'static str;

    fn try_from(value: Field) -> Result<Self, Self::Error> {
        match value {
            Field::Ip(ip) => Ok(ip),
            _ => Err("Not an IP"),
        }
    }
}

impl Display for Ip {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let ip = match self {
            Ip::V4(ip1) => ipv4_to_str(*ip1),
            Ip::V6(ip1) => ipv6_to_str(*ip1),
        };
        write!(f, "{}", ip)
    }
}
impl std::hash::Hash for Ip {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Ip::V4(v) => v.hash(state),
            Ip::V6(v) => v.hash(state),
        }
    }
}

#[cfg(test)]
mod tst {
    use super::*;
    
    #[test]
    fn test_equals_between_ips() {
        assert_eq!(Ip::V4(111), Ip::V4(111));
        assert_eq!(Ip::V6(111), Ip::V6(111));
        assert_eq!(Some(Ip::V6(111)), Some(Ip::V6(111)));
    }
    #[test]
    fn test_serialize_ip_field() {
        assert_eq!(Ip::V4(111).to_string(), "0.0.0.111");
    }

    #[test]
    fn from_u32_vec() {
        let ip: Ip = [192, 168, 1, 1].into();
        assert_eq!(ip.to_string(), "192.168.1.1");
    }

    #[test]
    fn from_u128_vec() {
        let ip: Ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1].into();
        assert_eq!(ip.to_string(), "::1");
    }
}