use crate::{
    err::{ForensicError, ForensicResult}, utils::time::Filetime
};

use super::vfs::{VirtualFile, VirtualFileSystem};

pub const HKCR : RegHiveKey = RegHiveKey::HkeyClassesRoot;
pub const HKC : RegHiveKey = RegHiveKey::HkeyCurrentConfig;
pub const HKCU : RegHiveKey = RegHiveKey::HkeyCurrentUser;
pub const HKLM : RegHiveKey = RegHiveKey::HkeyLocalMachine;
pub const HKU : RegHiveKey = RegHiveKey::HkeyUsers;

pub mod extra;

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug)]
pub enum RegHiveKey {
    HkeyClassesRoot,
    HkeyCurrentConfig,
    HkeyCurrentUser,
    HkeyDynData,
    HkeyLocalMachine,
    KkeyPerformanceData,
    HkeyPerformanceNlstext,
    HkeyPerformanceText,
    HkeyUsers,
    Hkey(isize),
}

#[derive(Clone, PartialEq, PartialOrd, Eq, Ord, Debug)]
pub enum RegValue {
    Binary(Vec<u8>),
    MultiSZ(Vec<String>),
    ExpandSZ(String),
    SZ(String),
    DWord(u32),
    QWord(u64),
}

impl RegValue {
    pub fn from_str(v : &str) -> RegValue {
        RegValue::SZ(v.to_string())
    }
    pub fn from_string(v : String) -> RegValue {
        RegValue::SZ(v.clone())
    }
    pub fn from_u32(v : u32) -> RegValue {
        RegValue::DWord(v)
    }
    pub fn from_u64(v : u64) -> RegValue {
        RegValue::QWord(v)
    }
}

impl Into<RegValue> for String {
    fn into(self) -> RegValue {
        RegValue::SZ(self)
    }
}

impl Into<RegValue> for &str {
    fn into(self) -> RegValue {
        RegValue::SZ(self.to_string())
    }
}

impl Into<RegValue> for u32 {
    fn into(self) -> RegValue {
        RegValue::DWord(self)
    }
}

impl Into<RegValue> for u64 {
    fn into(self) -> RegValue {
        RegValue::QWord(self)
    }
}
impl Into<RegValue> for i32 {
    fn into(self) -> RegValue {
        RegValue::DWord(self as u32)
    }
}

impl Into<RegValue> for i64 {
    fn into(self) -> RegValue {
        RegValue::QWord(self as u64)
    }
}
impl Into<RegValue> for usize {
    fn into(self) -> RegValue {
        #[cfg(target_pointer_width="32")] 
        {
            RegValue::DWord(self as u32)
        }
        #[cfg(target_pointer_width="16")] 
        {
            RegValue::DWord(self as u32)
        }
        #[cfg(target_pointer_width="64")] 
        {
            RegValue::QWord(self as u64)
        }
    }
}

impl Into<RegValue> for Vec<u8> {
    fn into(self) -> RegValue {
        RegValue::Binary(self)
    }
}

impl From<Vec<String>> for RegValue {
    fn from(value: Vec<String>) -> Self {
        RegValue::MultiSZ(value)
    }
}
impl From<&[u8]> for RegValue {
    fn from(value: &[u8]) -> Self {
        let mut vc = Vec::with_capacity(value.len());
        for v in value {
            vc.push(*v);
        }
        RegValue::Binary(vc)
    }
}
impl From<&[String]> for RegValue {
    fn from(value: &[String]) -> Self {
        let mut vc = Vec::with_capacity(value.len());
        for v in value {
            vc.push(v.clone());
        }
        RegValue::MultiSZ(vc)
    }
}
impl From<&[&String]> for RegValue {
    fn from(value: &[&String]) -> Self {
        let mut vc = Vec::with_capacity(value.len());
        for &v in value {
            vc.push(v.clone());
        }
        RegValue::MultiSZ(vc)
    }
}
impl From<&[&str]> for RegValue {
    fn from(value: &[&str]) -> Self {
        let mut vc = Vec::with_capacity(value.len());
        for &v in value {
            vc.push(v.to_string());
        }
        RegValue::MultiSZ(vc)
    }
}

impl TryFrom<RegValue> for String {
    type Error = ForensicError;
    fn try_from(value : RegValue) -> Result<Self, Self::Error> {
        match value {
            RegValue::MultiSZ(v) => Ok(v.join("\n")),
            RegValue::ExpandSZ(v) => Ok(v),
            RegValue::SZ(v) => Ok(v),
            _ => Err(ForensicError::CastError),
        }
    }
}
impl TryFrom<RegValue> for u32 {
    type Error = ForensicError;
    fn try_from(value : RegValue) -> Result<Self, Self::Error> {
        match value {
            RegValue::DWord(v) => Ok(v),
            RegValue::QWord(v) => Ok(v as u32),
            _ => Err(ForensicError::CastError),
        }
    }
}
impl TryFrom<RegValue> for u64 {
    type Error = ForensicError;
    fn try_from(value : RegValue) -> Result<Self, Self::Error> {
        match value {
            RegValue::DWord(v) => Ok(v as u64),
            RegValue::QWord(v) => Ok(v),
            _ => Err(ForensicError::CastError),
        }
    }
}
impl TryFrom<RegValue> for Vec<u8> {
    type Error = ForensicError;
    fn try_from(value : RegValue) -> Result<Self, Self::Error> {
        match value {
            RegValue::Binary(v) => Ok(v),
            _ => Err(ForensicError::CastError),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RegistryKeyInfo {
    pub subkeys : u32,
    pub max_subkey_name_length : u32,
    pub values : u32,
    pub max_value_name_length : u32,
    pub max_value_length : u32,
    pub last_write_time : Filetime

}

/// It allows decoupling the registry access library from the analysis library.
pub trait RegistryReader {
    /// Mounts a registry reader in a hive file
    fn from_file(&self, file: Box<dyn VirtualFile>) -> ForensicResult<Box<dyn RegistryReader>>;
    /// The Windows registry consists of numerous hives and we need access to all of them.
    fn from_fs(&self, fs: Box<dyn VirtualFileSystem>) -> ForensicResult<Box<dyn RegistryReader>>;
    /// Opens a registry key. If the registry reader is a file based one it needs to do the same thing that the Window Kernel does:
    /// store a Map with the association of keys with the path they point to.
    fn open_key(&self, hkey: RegHiveKey, key_name: &str) -> ForensicResult<RegHiveKey>;
    fn read_value(&self, hkey: RegHiveKey, value_name: &str) -> ForensicResult<RegValue>;
    fn enumerate_values(&self, hkey: RegHiveKey) -> ForensicResult<Vec<String>>;
    fn enumerate_keys(&self, hkey: RegHiveKey) -> ForensicResult<Vec<String>>;
    fn key_at(&self, hkey: RegHiveKey, pos: u32) -> ForensicResult<String>;
    fn value_at(&self, hkey: RegHiveKey, pos: u32) -> ForensicResult<String>;
    /// Retrieves information about the key. Emulates RegQueryInfoKey
    fn key_info(&self, hkey: RegHiveKey) -> ForensicResult<RegistryKeyInfo>;
    /// Closes a handle to the specified registry key.
    #[allow(unused_variables)]
    fn close_key(&self, hkey: RegHiveKey) {}

    /// Get the same value as the env var "%SystemRoot%"". It's usually "C:\Windows"
    fn get_system_root(&self) -> ForensicResult<String> {
        let key = self.open_key(
            RegHiveKey::HkeyLocalMachine,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        )?;
        let value = self.read_value(key, "SystemRoot")?;
        Ok(value.try_into()?)
    }

    fn list_users(&self) -> ForensicResult<Vec<String>> {
        let mut users = self.enumerate_keys(RegHiveKey::HkeyUsers)?;
        users.retain(|v| v.starts_with("S-") && !v.ends_with("_Classes"));
        Ok(users)
    }

    /// Get the current build of Windows: See "RTM build" in https://en.wikipedia.org/wiki/Comparison_of_Microsoft_Windows_versions
    fn windows_build(&self) -> ForensicResult<u32> {
        let key = self.open_key(
            RegHiveKey::HkeyLocalMachine,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        )?;
        let value = self.read_value(key, "CurrentBuild")?;
        Ok(value.try_into()?)
    }
}

/// Simplify the process of closing Registry keys
/// 
/// ```rust
/// use std::collections::BTreeMap;
/// use forensic_rs::prelude::*;
/// use forensic_rs::utils::testing::TestingRegistry;
/// let reader = TestingRegistry::new();
/// let user_id = "S-1-5-21-1366093794-4292800403-1155380978-513";
/// let user_key = reader.open_key(RegHiveKey::HkeyUsers, user_id).unwrap();
/// let _user_info : BTreeMap<String, String> = auto_close_key(&reader, user_key, || {
///     let volatile_key = reader.open_key(user_key, "Volatile Environment")?;
///     auto_close_key(&reader, volatile_key, || {
///         let mut user_info = BTreeMap::new();
///         user_info.insert("id".into(), user_id.to_string());
///         user_info.insert("home".into(), reader.read_value(volatile_key, "USERPROFILE")?.try_into()?);
///         user_info.insert("app_data".into(), reader.read_value(volatile_key, "APPDATA")?.try_into()?);
///         user_info.insert("local_app_data".into(), reader.read_value(volatile_key, "LOCALAPPDATA")?.try_into()?);
///         user_info.insert("domain".into(), reader.read_value(volatile_key, "USERDOMAIN")?.try_into()?);
///         user_info.insert("name".into(), reader.read_value(volatile_key, "USERNAME")?.try_into()?);
///         Ok(user_info)
///     })
/// }).unwrap();
/// ```
pub fn auto_close_key<F, T>(reader : &dyn RegistryReader, key : RegHiveKey, operation : F) -> ForensicResult<T> where
    F: FnOnce() -> ForensicResult<T> {
        let result = operation();
        reader.close_key(key);
        result
    }

#[cfg(test)]
mod reg_value {
    use crate::{err::ForensicResult, traits::registry::{RegistryKeyInfo, RegistryReader}};

    use super::RegValue;

    #[test]
    fn should_convert_using_try_into() {
        let _: String = RegValue::SZ(format!("String RegValue"))
            .try_into()
            .expect("Must convert values");
        let _: String = RegValue::MultiSZ(vec![format!("String RegValue")])
            .try_into()
            .expect("Must convert values");
        let _: String = RegValue::ExpandSZ(format!("String RegValue"))
            .try_into()
            .expect("Must convert values");

        let _ = TryInto::<u32>::try_into(RegValue::ExpandSZ(format!("String RegValue")))
            .expect_err("Should return error");
        let _ = TryInto::<u64>::try_into(RegValue::ExpandSZ(format!("String RegValue")))
            .expect_err("Should return error");
        let _ = TryInto::<Vec<u8>>::try_into(RegValue::ExpandSZ(format!("String RegValue")))
            .expect_err("Should return error");

        let _: u32 = RegValue::DWord(123)
            .try_into()
            .expect("Must convert values");
        let _: u64 = RegValue::DWord(123)
            .try_into()
            .expect("Must convert values");

        let _ = TryInto::<String>::try_into(RegValue::DWord(123)).expect_err("Should return error");
        let _ =
            TryInto::<Vec<u8>>::try_into(RegValue::DWord(123)).expect_err("Should return error");

        let _: u32 = RegValue::QWord(123)
            .clone()
            .try_into()
            .expect("Must convert values");
        let _: u64 = RegValue::QWord(123)
            .try_into()
            .expect("Must convert values");

        let _ = TryInto::<String>::try_into(RegValue::QWord(123)).expect_err("Should return error");
        let _ =
            TryInto::<Vec<u8>>::try_into(RegValue::QWord(123)).expect_err("Should return error");

        let _: Vec<u8> = RegValue::Binary((1..255).collect())
            .try_into()
            .expect("Must convert values");
        let _ = TryInto::<u32>::try_into(RegValue::Binary((1..255).collect()))
            .expect_err("Should return error");
        let _ = TryInto::<u32>::try_into(RegValue::Binary((1..255).collect()))
            .expect_err("Should return error");
        let _ = TryInto::<u32>::try_into(RegValue::Binary((1..255).collect()))
            .expect_err("Should return error");
    }

    #[test]
    fn should_generate_dummy_registry_reader() {
        struct RegReader {}
        impl RegistryReader for RegReader {
            fn from_file(
                &self,
                _file: Box<dyn crate::traits::vfs::VirtualFile>,
            ) -> crate::err::ForensicResult<Box<dyn RegistryReader>> {
                Ok(Box::new(RegReader{}))
            }

            fn from_fs(
                &self,
                _fs: Box<dyn crate::traits::vfs::VirtualFileSystem>,
            ) -> crate::err::ForensicResult<Box<dyn RegistryReader>> {
                Ok(Box::new(RegReader{}))
            }

            fn open_key(
                &self,
                _hkey: crate::traits::registry::RegHiveKey,
                _key_name: &str,
            ) -> crate::err::ForensicResult<crate::traits::registry::RegHiveKey> {
                Ok(crate::traits::registry::RegHiveKey::HkeyClassesRoot)
            }

            fn read_value(
                &self,
                _hkey: crate::traits::registry::RegHiveKey,
                _value_name: &str,
            ) -> crate::err::ForensicResult<RegValue> {
                Ok(RegValue::SZ(format!("123")))
            }

            fn enumerate_values(
                &self,
                _hkey: crate::traits::registry::RegHiveKey,
            ) -> crate::err::ForensicResult<Vec<String>> {
                Ok(vec![format!("123")])
            }

            fn enumerate_keys(
                &self,
                _hkey: crate::traits::registry::RegHiveKey,
            ) -> crate::err::ForensicResult<Vec<String>> {
                Ok(vec![format!("123")])
            }

            fn key_at(
                &self,
                _hkey: crate::traits::registry::RegHiveKey,
                _pos: u32,
            ) -> crate::err::ForensicResult<String> {
                Ok(format!("123"))
            }

            fn value_at(
                &self,
                _hkey: crate::traits::registry::RegHiveKey,
                _pos: u32,
            ) -> crate::err::ForensicResult<String> {
                Ok(format!("123"))
            }
            fn key_info(&self, _hkey: crate::traits::registry::RegHiveKey) -> ForensicResult<crate::traits::registry::RegistryKeyInfo>{
                Ok(RegistryKeyInfo::default())
            }
        }

        let reader = RegReader {};
        let mut reader : Box<dyn RegistryReader> = Box::new(reader);
        fn tst(reg : &mut Box<dyn RegistryReader>) -> ForensicResult<()>{
            assert_eq!("123",reg.key_at(crate::traits::registry::RegHiveKey::HkeyClassesRoot, 123)?);
            Ok(())
        }
        tst(&mut reader).unwrap();
    }
}
