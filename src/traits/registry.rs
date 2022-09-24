use std::borrow::Cow;

use crate::err::ForensicResult;


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
    /// For live systems
    Hkey(isize),
    /// For offline systems
    Other(Cow<'static, str>)
}

pub enum RegValue {
    Binary(Vec<u8>),
    MultiSZ(String),
    ExpandSZ(String),
    SZ(String),
    DWord(u32),
    QWord(u64)
}

/// It allows decoupling the registry access library from the analysis library.
pub trait RegistryReader {
    fn open_key(&mut self, hkey : RegHiveKey, key_name : &str) -> ForensicResult<RegHiveKey>;
    fn read_value(&self, hkey : RegHiveKey, value_name : &str) -> ForensicResult<RegValue>;
    fn enumerate_values(&self, hkey : RegHiveKey, pos : u32) -> ForensicResult<Vec<String>>;
    fn enumerate_keys(&self, hkey : RegHiveKey, pos : u32) -> ForensicResult<Vec<String>>;
}