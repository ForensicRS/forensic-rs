use crate::{
    err::ForensicError,
    traits::registry::{RegHiveKey, RegValue, RegistryKeyInfo, RegistryReader},
};
use std::{cell::RefCell, collections::BTreeMap};

use super::time::Filetime;

/// Basic Registry for testing. Includes the user profile "S-1-5-21-1366093794-4292800403-1155380978-513"
#[derive(Clone, Debug)]
pub struct TestingRegistry {
    pub cell: BTreeMap<String, MountedCell>,
    pub cached: RefCell<BTreeMap<RegHiveKey, String>>,
    pub counter: RefCell<isize>,
}

impl Default for TestingRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TestingRegistry {
    pub fn empty() -> Self {
        Self {
            cell: BTreeMap::new(),
            cached: RefCell::new(basic_cache()),
            counter: RefCell::default(),
        }
    }
    pub fn new() -> Self {
        Self {
            cell: basic_registry(),
            cached: RefCell::new(basic_cache()),
            counter: RefCell::new(0),
        }
    }
    pub fn increase_counter(&self) -> isize {
        let mut borrowed = self.counter.borrow_mut();
        let ret = *borrowed;
        *borrowed += 1;
        ret
    }
    pub fn add_value(&mut self, path: &str, value: &str, data: RegValue) {
        let (hkey, rest) = match path.split_once(|v| v == '/' || v == '\\') {
            Some(v) => v,
            None => {
                return self
                    .cell
                    .entry(path.to_string())
                    .or_insert(MountedCell::new(path))
                    .add_value("", value, data)
            }
        };
        self.cell
            .entry(hkey.to_string())
            .or_insert(MountedCell::new(hkey))
            .add_value(rest, value, data);
    }
    pub fn contains(&self, path: &str) -> bool {
        let (hkey, rest) = match path.split_once(|v| v == '/' || v == '\\') {
            Some(v) => v,
            None => return self.cell.contains_key(path),
        };
        let hive = match self.cell.get(hkey) {
            Some(v) => v,
            None => return false,
        };
        hive.contains_key(rest)
    }
    pub fn get_value(&self, path: &str, value: &str) -> Option<RegValue> {
        let (hkey, rest) = match path.split_once(|v| v == '/' || v == '\\') {
            Some(v) => v,
            None => (path, ""),
        };
        let hive = match self.cell.get(hkey) {
            Some(v) => v,
            None => return None,
        };
        hive.get_value(rest, value)
    }
    pub fn get_values(&self, path: &str) -> Option<Vec<String>> {
        let (hkey, rest) = match path.split_once(|v| v == '/' || v == '\\') {
            Some(v) => v,
            None => (path, ""),
        };
        let hive = match self.cell.get(hkey) {
            Some(v) => v,
            None => return None,
        };
        Some(hive.get_values(rest))
    }
    pub fn get_keys(&self, path: &str) -> Option<Vec<String>> {
        let (hkey, rest) = match path.split_once(|v| v == '/' || v == '\\') {
            Some(v) => v,
            None => (path, ""),
        };
        let hive = match self.cell.get(hkey) {
            Some(v) => v,
            None => return None,
        };
        Some(hive.get_keys(rest))
    }
}

#[derive(Clone, Debug, Default)]
pub struct MountedCell {
    pub name: String,
    pub keys: BTreeMap<String, MountedCell>,
    pub values: BTreeMap<String, RegValue>,
}
impl MountedCell {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            keys: BTreeMap::new(),
            values: BTreeMap::new(),
        }
    }
    pub fn add_key(&mut self, path: &str) {
        if path.is_empty() {
            return;
        }
        let (first, rest) = match path.split_once(|v| v == '/' || v == '\\') {
            Some(v) => v,
            None => {
                self.keys
                    .entry(path.to_string())
                    .or_insert(MountedCell::new(path))
                    .add_key(path);
                return;
            }
        };
        self.keys
            .entry(first.to_string())
            .or_insert(MountedCell::new(first))
            .add_key(rest);
    }
    pub fn contains_key(&self, path: &str) -> bool {
        let (first, rest) = match path.split_once(|v| v == '/' || v == '\\') {
            Some(v) => v,
            None => return self.keys.contains_key(path),
        };
        let hive = match self.keys.get(first) {
            Some(v) => v,
            None => return false,
        };
        hive.contains_key(rest)
    }
    pub fn add_value(&mut self, path: &str, value: &str, data: RegValue) {
        if path.is_empty() {
            self.values.insert(value.into(), data);
            return;
        }
        let (first, rest) = match path.split_once(|v| v == '/' || v == '\\') {
            Some(v) => v,
            None => {
                self.keys
                    .entry(path.to_string())
                    .or_insert(MountedCell::new(path))
                    .add_value("", value, data);
                return;
            }
        };
        self.keys
            .entry(first.to_string())
            .or_insert(MountedCell::new(first))
            .add_value(rest, value, data);
    }
    pub fn get_value(&self, path: &str, value: &str) -> Option<RegValue> {
        if path.is_empty() {
            return self.values.get(value).cloned();
        }
        let (first, rest) = match path.split_once(|v| v == '/' || v == '\\') {
            Some(v) => v,
            None => return self.keys.get(path)?.get_value("", value),
        };
        self.keys.get(first)?.get_value(rest, value)
    }
    pub fn get_values(&self, path: &str) -> Vec<String> {
        if path.is_empty() {
            return self
                .values
                .keys()
                .map(|v| v.to_string())
                .collect();
        }
        let (first, rest) = match path.split_once(|v| v == '/' || v == '\\') {
            Some(v) => v,
            None => {
                return match self.keys.get(path) {
                    Some(v) => v.get_values(""),
                    None => Vec::new(),
                }
            }
        };
        match self.keys.get(first) {
            Some(v) => v.get_values(rest),
            None => Vec::new(),
        }
    }
    pub fn get_keys(&self, path: &str) -> Vec<String> {
        if path.is_empty() {
            return self
                .keys
                .keys()
                .map(|v| v.to_string())
                .collect();
        }
        let (first, rest) = match path.split_once(|v| v == '/' || v == '\\') {
            Some(v) => v,
            None => {
                return match self.keys.get(path) {
                    Some(v) => v.get_keys(""),
                    None => Vec::new(),
                }
            }
        };
        match self.keys.get(first) {
            Some(v) => v.get_keys(rest),
            None => Vec::new(),
        }
    }
}

impl RegistryReader for TestingRegistry {
    fn from_file(
        &self,
        _file: Box<dyn crate::traits::vfs::VirtualFile>,
    ) -> crate::err::ForensicResult<Box<dyn RegistryReader>> {
        Ok(Box::new(TestingRegistry::new()))
    }

    fn from_fs(
        &self,
        _fs: Box<dyn crate::traits::vfs::VirtualFileSystem>,
    ) -> crate::err::ForensicResult<Box<dyn RegistryReader>> {
        Ok(Box::new(TestingRegistry::new()))
    }

    fn open_key(
        &self,
        hkey: crate::traits::registry::RegHiveKey,
        key_name: &str,
    ) -> crate::err::ForensicResult<crate::traits::registry::RegHiveKey> {
        let mut borrowed = self.cached.borrow_mut();
        let (hkey, path) = match borrowed.get(&hkey) {
            Some(v) => {
                let full_path = format!("{}\\{}", v, key_name);
                if !self.contains(&full_path) {
                    return Err(ForensicError::missing_string(format!(
                        "Key path {} not found",
                        full_path
                    )));
                }
                let handle = self.increase_counter();
                (handle, full_path)
            }
            None => return Err(ForensicError::missing_str("Hkey not found")),
        };
        borrowed.insert(RegHiveKey::Hkey(hkey), path);
        Ok(RegHiveKey::Hkey(hkey))
    }

    fn read_value(
        &self,
        hkey: crate::traits::registry::RegHiveKey,
        value_name: &str,
    ) -> crate::err::ForensicResult<RegValue> {
        let borrowed = self.cached.borrow();
        let key_path = borrowed
            .get(&hkey)
            .ok_or_else(|| ForensicError::missing_str("HKey not found"))?;
        let value = self.get_value(key_path, value_name).ok_or_else(|| {
            ForensicError::missing_string(format!("Value {}\\{} not found", key_path, value_name))
        })?;
        Ok(value)
    }

    fn enumerate_values(
        &self,
        hkey: crate::traits::registry::RegHiveKey,
    ) -> crate::err::ForensicResult<Vec<String>> {
        let borrowed = self.cached.borrow();
        let key_path = borrowed
            .get(&hkey)
            .ok_or_else(|| ForensicError::missing_str("HKey not found"))?;
        let value = self.get_values(key_path).ok_or_else(|| {
            ForensicError::missing_string(format!("Values for {} not found", key_path))
        })?;
        Ok(value)
    }

    fn enumerate_keys(
        &self,
        hkey: crate::traits::registry::RegHiveKey,
    ) -> crate::err::ForensicResult<Vec<String>> {
        let borrowed = self.cached.borrow();
        let key_path = borrowed
            .get(&hkey)
            .ok_or_else(|| ForensicError::missing_str("HKey not found"))?;
        let value = self.get_keys(key_path).ok_or_else(|| {
            ForensicError::missing_string(format!("Keys for {} not found", key_path))
        })?;
        Ok(value)
    }

    fn key_at(
        &self,
        hkey: crate::traits::registry::RegHiveKey,
        pos: u32,
    ) -> crate::err::ForensicResult<String> {
        let borrowed = self.cached.borrow();
        let key_path = borrowed
            .get(&hkey)
            .ok_or_else(|| ForensicError::missing_str("HKey not found"))?;
        let mut value = self.get_keys(key_path).ok_or_else(|| {
            ForensicError::missing_string(format!("Keys for {} not found", key_path))
        })?;
        let pos = pos as usize;
        if pos > value.len() {
            return Err(ForensicError::NoMoreData);
        }
        Ok(value.remove(pos))
    }

    fn value_at(
        &self,
        hkey: crate::traits::registry::RegHiveKey,
        pos: u32,
    ) -> crate::err::ForensicResult<String> {
        let borrowed = self.cached.borrow();
        let key_path = borrowed
            .get(&hkey)
            .ok_or_else(|| ForensicError::missing_str("HKey not found"))?;
        let mut value = self.get_values(key_path).ok_or_else(|| {
            ForensicError::missing_string(format!("Values for {} not found", key_path))
        })?;
        let pos = pos as usize;
        if pos > value.len() {
            return Err(ForensicError::NoMoreData);
        }
        Ok(value.remove(pos))
    }

    fn key_info(&self, hkey: RegHiveKey) -> crate::err::ForensicResult<crate::traits::registry::RegistryKeyInfo> {
        let borrowed = self.cached.borrow();
        let key_path = borrowed
            .get(&hkey)
            .ok_or_else(|| ForensicError::missing_str("HKey not found"))?;
        let value = self.get_values(key_path).ok_or_else(|| {
            ForensicError::missing_string(format!("Values for {} not found", key_path))
        })?;
        let keys = self.get_keys(key_path).ok_or_else(|| {
            ForensicError::missing_string(format!("Values for {} not found", key_path))
        })?;
        Ok(RegistryKeyInfo {
            last_write_time : Filetime::new(0),
            subkeys : keys.len() as u32,
            values : value.len() as u32,
            max_subkey_name_length : keys.iter().map(|v| v.len()).fold(0, |acc, e| e.max(acc)) as u32,
            max_value_name_length: value.iter().map(|v| v.len()).fold(0, |acc, e| e.max(acc)) as u32,
            max_value_length: 0,
        })
    }
}
fn basic_cache() -> BTreeMap<RegHiveKey, String> {
    {
        let mut map = BTreeMap::new();
        for (k, p) in [
            (RegHiveKey::HkeyLocalMachine, "HKLM"),
            (RegHiveKey::HkeyCurrentUser, "HKCU"),
            (RegHiveKey::HkeyUsers, "HKU"),
            (RegHiveKey::HkeyClassesRoot, "HKCR"),
        ] {
            map.insert(k, p.to_string());
        }
        map
    }
}

fn basic_registry() -> BTreeMap<String, MountedCell> {
    let mut map = BTreeMap::new();
    for k in ["HKLM", "HKCU", "HKCR"] {
        map.insert(k.to_string(), MountedCell::new(k));
    }
    let mut hkcu_cell = MountedCell::new("HKU");
    hkcu_cell.add_value(
        "S-1-5-21-1366093794-4292800403-1155380978-513\\Volatile Environment",
        "USERPROFILE",
        RegValue::from_str(r"C:\Users\Tester"),
    );
    hkcu_cell.add_value(
        "S-1-5-21-1366093794-4292800403-1155380978-513\\Volatile Environment",
        "APPDATA",
        RegValue::from_str(r"C:\Users\Tester\AppData\Roaming"),
    );
    hkcu_cell.add_value(
        "S-1-5-21-1366093794-4292800403-1155380978-513\\Volatile Environment",
        "LOCALAPPDATA",
        RegValue::from_str(r"C:\Users\Tester\AppData\Local"),
    );
    hkcu_cell.add_value(
        "S-1-5-21-1366093794-4292800403-1155380978-513\\Volatile Environment",
        "USERDOMAIN",
        RegValue::from_str(r"TestMachine"),
    );
    hkcu_cell.add_value(
        "S-1-5-21-1366093794-4292800403-1155380978-513\\Volatile Environment",
        "USERNAME",
        RegValue::from_str(r"Tester"),
    );
    map.insert("HKU".into(), hkcu_cell);
    map
}
