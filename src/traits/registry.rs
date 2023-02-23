use crate::{
    core::user::UserInfo,
    err::{ForensicError, ForensicResult},
};

use super::vfs::{VirtualFile, VirtualFileSystem};

#[derive(Clone, Copy)]
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

#[derive(Clone)]
pub enum RegValue {
    Binary(Vec<u8>),
    MultiSZ(String),
    ExpandSZ(String),
    SZ(String),
    DWord(u32),
    QWord(u64),
}

impl TryInto<String> for RegValue {
    type Error = ForensicError;
    fn try_into(self) -> Result<String, Self::Error> {
        match self {
            Self::MultiSZ(v) => Ok(v),
            Self::ExpandSZ(v) => Ok(v),
            Self::SZ(v) => Ok(v),
            _ => Err(ForensicError::CastError),
        }
    }
}

impl TryInto<u32> for RegValue {
    type Error = ForensicError;
    fn try_into(self) -> Result<u32, Self::Error> {
        match self {
            Self::DWord(v) => Ok(v),
            Self::QWord(v) => Ok(v as u32),
            _ => Err(ForensicError::CastError),
        }
    }
}

impl TryInto<u64> for RegValue {
    type Error = ForensicError;
    fn try_into(self) -> Result<u64, Self::Error> {
        match self {
            Self::DWord(v) => Ok(v as u64),
            Self::QWord(v) => Ok(v),
            _ => Err(ForensicError::CastError),
        }
    }
}

impl TryInto<Vec<u8>> for RegValue {
    type Error = ForensicError;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        match self {
            Self::Binary(v) => Ok(v),
            _ => Err(ForensicError::CastError),
        }
    }
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

    fn get_basic_user_info(&self, user_id: &str) -> ForensicResult<UserInfo> {
        let user_key = self.open_key(RegHiveKey::HkeyUsers, user_id)?;
        let user_key = self.open_key(user_key, "Volatile Environment")?;
        let mut user_info = UserInfo::default();
        user_info.id = user_id.to_string();
        user_info.home = self.read_value(user_key, "USERPROFILE")?.try_into()?;
        user_info.app_data = self.read_value(user_key, "APPDATA")?.try_into()?;
        user_info.local_app_data = self.read_value(user_key, "LOCALAPPDATA")?.try_into()?;
        user_info.domain = self.read_value(user_key, "USERDOMAIN")?.try_into()?;
        user_info.name = self.read_value(user_key, "USERNAME")?.try_into()?;
        Ok(user_info)
    }
}

#[cfg(test)]
mod reg_value {
    use crate::{traits::registry::RegistryReader, err::ForensicResult};

    use super::RegValue;

    #[test]
    fn should_convert_using_try_into() {
        let _: String = RegValue::SZ(format!("String RegValue"))
            .try_into()
            .expect("Must convert values");
        let _: String = RegValue::MultiSZ(format!("String RegValue"))
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
