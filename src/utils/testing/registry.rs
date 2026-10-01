use crate::{
    err::ForensicError,
    traits::registry::{KeyEntry, KeyInfo, PredefinedHive, RawKey, RegValue, Registry},
    utils::time::ForensicTimestamp,
};
use compact_str::CompactString;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

/// Basic Registry for testing. Includes the user profile "S-1-5-21-1366093794-4292800403-1155380978-513"
#[derive(Clone, Debug)]
pub struct TestingRegistry {
    pub cell: BTreeMap<String, MountedCell>,
    pub cached: Arc<Mutex<BTreeMap<isize, String>>>,
    /// `Arc<Mutex<_>>`, not `RefCell`: the RFC 0001 `Registry` trait requires
    /// `Send + Sync`, which `RefCell` cannot satisfy — and sharing it (like
    /// `cached`) across `.clone()`s is actually the correct fix, not just a
    /// workaround: an independent-per-clone counter alongside an
    /// `Arc`-shared `cached` map could let two clones allocate the same
    /// handle id concurrently.
    pub counter: Arc<Mutex<isize>>,
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
            cached: Arc::new(Mutex::new(basic_cache())),
            counter: Arc::new(Mutex::new(0)),
        }
    }
    pub fn new() -> Self {
        Self {
            cell: basic_registry(),
            cached: Arc::new(Mutex::new(basic_cache())),
            counter: Arc::new(Mutex::new(0)),
        }
    }
    pub fn increase_counter(&self) -> isize {
        let mut borrowed = self
            .counter
            .lock()
            .expect("TestingRegistry counter lock poisoned");
        let ret = *borrowed;
        *borrowed += 1;
        ret
    }
    pub fn add_value(&mut self, path: &str, value: &str, data: RegValue) {
        let (hkey, rest) = split_path(path);
        self.cell
            .entry(hkey.clone())
            .or_insert(MountedCell::new(&hkey))
            .add_value(rest, value, data);
    }
    /// Creates the key at `path` (and any missing parents), with no values.
    pub fn add_key(&mut self, path: &str) {
        let (hkey, rest) = split_path(path);
        self.cell
            .entry(hkey.clone())
            .or_insert(MountedCell::new(&hkey))
            .add_key(rest);
    }

    /// Sets the last-write time `info()` and subkey listings report for the key at `path`,
    /// creating the key if needed. Keys have none (`None`) until this is called: the double
    /// never makes a timestamp up.
    pub fn set_last_write(&mut self, path: &str, timestamp: ForensicTimestamp) {
        self.add_key(path);
        let (hkey, rest) = split_path(path);
        if let Some(cell) = self.cell.get_mut(&hkey).and_then(|c| c.cell_at_mut(rest)) {
            cell.last_write = Some(timestamp);
        }
    }

    pub fn contains(&self, path: &str) -> bool {
        let (hkey, rest) = split_path(path);
        match self.cell.get(&hkey) {
            Some(hive) => rest.is_empty() || hive.contains_key(rest),
            None => false,
        }
    }
    pub fn get_value(&self, path: &str, value: &str) -> Option<RegValue> {
        let (hkey, rest) = split_path(path);
        self.cell.get(&hkey)?.get_value(rest, value)
    }

    pub fn get_value_ref<'a>(&'a self, path: &str, value: &str) -> Option<&'a RegValue> {
        let (hkey, rest) = split_path(path);
        self.cell.get(&hkey)?.get_value_ref(rest, value)
    }
    pub fn get_values(&self, path: &str) -> Option<Vec<String>> {
        let (hkey, rest) = split_path(path);
        Some(self.cell.get(&hkey)?.get_values(rest))
    }
    pub fn get_keys(&self, path: &str) -> Option<Vec<String>> {
        let (hkey, rest) = split_path(path);
        Some(self.cell.get(&hkey)?.get_keys(rest))
    }
}

/// The short name the double roots a hive at (`HKLM`, `HKU`, `HKCU`, `HKCR`, `HKCC`), whatever
/// spelling or case a path uses: `HKEY_USERS\...` and `hku\...` are the same tree, as in
/// Windows. An unknown name is kept as written.
fn canonical_hive(name: &str) -> String {
    match name.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => "HKLM".into(),
        "HKU" | "HKEY_USERS" => "HKU".into(),
        "HKCU" | "HKEY_CURRENT_USER" => "HKCU".into(),
        "HKCR" | "HKEY_CLASSES_ROOT" => "HKCR".into(),
        "HKCC" | "HKEY_CURRENT_CONFIG" => "HKCC".into(),
        _ => name.to_string(),
    }
}

/// A full path's canonical hive name and the path below it.
fn split_path(path: &str) -> (String, &str) {
    let (hkey, rest) = path.split_once(['/', '\\']).unwrap_or((path, ""));
    (canonical_hive(hkey), rest)
}

#[derive(Clone, Debug, Default)]
pub struct MountedCell {
    pub name: String,
    pub keys: BTreeMap<String, MountedCell>,
    pub values: BTreeMap<String, RegValue>,
    /// The key's last-write time; `None` unless a test sets one.
    pub last_write: Option<ForensicTimestamp>,
}
impl MountedCell {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            keys: BTreeMap::new(),
            values: BTreeMap::new(),
            last_write: None,
        }
    }

    /// The subkey named `name`, compared case-insensitively as in Windows.
    fn child(&self, name: &str) -> Option<&MountedCell> {
        self.keys.get(name).or_else(|| {
            self.keys
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v)
        })
    }

    fn child_mut(&mut self, name: &str) -> Option<&mut MountedCell> {
        let stored = self.stored_key_name(name)?;
        self.keys.get_mut(&stored)
    }

    /// The subkey named `name`, created with that spelling if no key matches it in any case.
    fn child_or_insert(&mut self, name: &str) -> &mut MountedCell {
        let stored = self
            .stored_key_name(name)
            .unwrap_or_else(|| name.to_string());
        self.keys
            .entry(stored.clone())
            .or_insert_with(|| MountedCell::new(&stored))
    }

    fn stored_key_name(&self, name: &str) -> Option<String> {
        self.keys
            .keys()
            .find(|k| k.eq_ignore_ascii_case(name))
            .cloned()
    }

    /// The value named `name`, compared case-insensitively as in Windows.
    fn value_named(&self, name: &str) -> Option<&RegValue> {
        self.values.get(name).or_else(|| {
            self.values
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v)
        })
    }

    pub fn add_key(&mut self, path: &str) {
        if path.is_empty() {
            return;
        }
        let (first, rest) = path.split_once(['/', '\\']).unwrap_or((path, ""));
        self.child_or_insert(first).add_key(rest);
    }
    pub fn contains_key(&self, path: &str) -> bool {
        self.cell_at(path).is_some() && !path.is_empty()
    }
    /// Sets `value` at `path`, replacing a value of the same name in any case.
    pub fn add_value(&mut self, path: &str, value: &str, data: RegValue) {
        if path.is_empty() {
            let stored = self
                .values
                .keys()
                .find(|k| k.eq_ignore_ascii_case(value))
                .cloned()
                .unwrap_or_else(|| value.to_string());
            self.values.insert(stored, data);
            return;
        }
        let (first, rest) = path.split_once(['/', '\\']).unwrap_or((path, ""));
        self.child_or_insert(first).add_value(rest, value, data);
    }
    pub fn get_value(&self, path: &str, value: &str) -> Option<RegValue> {
        self.get_value_ref(path, value).cloned()
    }

    pub fn get_value_ref<'a>(&'a self, path: &str, value: &str) -> Option<&'a RegValue> {
        self.cell_at(path)?.value_named(value)
    }
    pub fn get_values(&self, path: &str) -> Vec<String> {
        self.cell_at(path)
            .map(|cell| cell.values.keys().cloned().collect())
            .unwrap_or_default()
    }
    pub fn get_keys(&self, path: &str) -> Vec<String> {
        self.cell_at(path)
            .map(|cell| cell.keys.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn cell_at(&self, path: &str) -> Option<&MountedCell> {
        if path.is_empty() {
            return Some(self);
        }
        let (first, rest) = path.split_once(['/', '\\']).unwrap_or((path, ""));
        self.child(first)?.cell_at(rest)
    }

    fn cell_at_mut(&mut self, path: &str) -> Option<&mut MountedCell> {
        if path.is_empty() {
            return Some(self);
        }
        let (first, rest) = path.split_once(['/', '\\']).unwrap_or((path, ""));
        self.child_mut(first)?.cell_at_mut(rest)
    }

    fn key_entries(&self) -> impl Iterator<Item = KeyEntry> + '_ {
        self.keys.iter().map(|(name, cell)| KeyEntry {
            name: name.clone(),
            last_write: cell.last_write,
            allocated: true,
        })
    }
}

/// The hive and in-hive path of a full `HKLM\...` style path, for typed not-found errors.
fn split_hive(full_path: &str) -> (PredefinedHive, Option<CompactString>) {
    let (hkey, rest) = split_path(full_path);
    let hive = match hkey.as_str() {
        "HKLM" => PredefinedHive::LocalMachine,
        "HKCU" => PredefinedHive::CurrentUser,
        "HKCR" => PredefinedHive::ClassesRoot,
        "HKCC" => PredefinedHive::CurrentConfig,
        _ => PredefinedHive::Users,
    };
    (hive, (!rest.is_empty()).then(|| CompactString::from(rest)))
}

impl TestingRegistry {
    fn path_of_raw(&self, key: &RawKey) -> crate::err::ForensicResult<String> {
        self.cached
            .lock()
            .expect("TestingRegistry cache lock poisoned")
            .get(&(key.raw() as isize))
            .cloned()
            .ok_or_else(|| ForensicError::registry_invalid_handle(key.raw() as i64))
    }

    /// Locates the [`MountedCell`] for `path` without collecting any
    /// intermediate name list — the direct-reference counterpart to
    /// [`get_values`](TestingRegistry::get_values)/[`get_keys`](TestingRegistry::get_keys),
    /// used by the `_into` buffer-reuse overrides below.
    fn cell_at(&self, path: &str) -> Option<&MountedCell> {
        let (hkey, rest) = split_path(path);
        self.cell.get(&hkey)?.cell_at(rest)
    }
}

impl Registry for TestingRegistry {
    fn root(&self, hive: PredefinedHive) -> crate::err::ForensicResult<RawKey> {
        let hive_prefix = match hive {
            PredefinedHive::LocalMachine => "HKLM",
            PredefinedHive::CurrentUser => "HKCU",
            PredefinedHive::Users => "HKU",
            PredefinedHive::ClassesRoot => "HKCR",
            _ => {
                return Err(ForensicError::other(
                    "TestingRegistry",
                    format!("hive not supported by this testing double: {hive}"),
                ));
            }
        };
        if !self.contains(hive_prefix) {
            return Err(ForensicError::registry_key_not_found(hive, None));
        }
        let handle_id = self.increase_counter();
        self.cached
            .lock()
            .expect("TestingRegistry cache lock poisoned")
            .insert(handle_id, hive_prefix.to_string());
        Ok(RawKey::from_raw(handle_id as u64))
    }

    fn open_raw(&self, parent: &RawKey, name: &str) -> crate::err::ForensicResult<RawKey> {
        let parent_path = self.path_of_raw(parent)?;
        let full_path = if parent_path.is_empty() {
            name.to_string()
        } else {
            format!("{parent_path}\\{name}")
        };
        if !self.contains(&full_path) {
            let (hive, key_path) = split_hive(&full_path);
            return Err(ForensicError::registry_key_not_found(hive, key_path));
        }
        let handle_id = self.increase_counter();
        self.cached
            .lock()
            .expect("TestingRegistry cache lock poisoned")
            .insert(handle_id, full_path);
        Ok(RawKey::from_raw(handle_id as u64))
    }

    fn close_raw(&self, key: &RawKey) {
        self.cached
            .lock()
            .expect("TestingRegistry cache lock poisoned")
            .remove(&(key.raw() as isize));
    }

    fn read_raw(&self, key: &RawKey, value: &str) -> crate::err::ForensicResult<RegValue> {
        let path = self.path_of_raw(key)?;
        self.get_value(&path, value).ok_or_else(|| {
            let (hive, key_path) = split_hive(&path);
            ForensicError::registry_value_not_found(hive, key_path, value)
        })
    }

    fn values_raw(&self, key: &RawKey) -> crate::err::ForensicResult<Vec<(String, RegValue)>> {
        let path = self.path_of_raw(key)?;
        let names = self.get_values(&path).unwrap_or_default();
        Ok(names
            .into_iter()
            .filter_map(|name| {
                let value = self.get_value(&path, &name)?;
                Some((name, value))
            })
            .collect())
    }

    fn keys_raw(&self, key: &RawKey) -> crate::err::ForensicResult<Vec<KeyEntry>> {
        let path = self.path_of_raw(key)?;
        Ok(self
            .cell_at(&path)
            .map(|cell| cell.key_entries().collect())
            .unwrap_or_default())
    }

    fn info_raw(&self, key: &RawKey) -> crate::err::ForensicResult<KeyInfo> {
        let path = self.path_of_raw(key)?;
        let values = self.get_values(&path).unwrap_or_default();
        let keys = self.get_keys(&path).unwrap_or_default();
        Ok(KeyInfo {
            subkeys: keys.len() as u32,
            values: values.len() as u32,
            max_subkey_name_length: keys.iter().map(|v| v.len()).max().unwrap_or(0) as u32,
            max_value_name_length: values.iter().map(|v| v.len()).max().unwrap_or(0) as u32,
            max_value_length: 0,
            // Only what a test set with `set_last_write`: unlike the old
            // `RegistryReader::key_info`, this never fabricates a
            // `from_win_filetime(0)` (1601-01-01) timestamp.
            last_write_time: self.cell_at(&path).and_then(|cell| cell.last_write),
        })
    }

    fn values_raw_into(
        &self,
        key: &RawKey,
        out: &mut Vec<(String, RegValue)>,
    ) -> crate::err::ForensicResult<()> {
        let path = self.path_of_raw(key)?;
        if let Some(cell) = self.cell_at(&path) {
            out.extend(
                cell.values
                    .iter()
                    .map(|(name, value)| (name.clone(), value.clone())),
            );
        }
        Ok(())
    }

    fn keys_raw_into(
        &self,
        key: &RawKey,
        out: &mut Vec<KeyEntry>,
    ) -> crate::err::ForensicResult<()> {
        let path = self.path_of_raw(key)?;
        if let Some(cell) = self.cell_at(&path) {
            out.extend(cell.key_entries());
        }
        Ok(())
    }

    fn values_iter_raw<'a>(
        &'a self,
        key: &RawKey,
    ) -> crate::err::ForensicResult<Box<dyn Iterator<Item = (String, RegValue)> + 'a>> {
        let path = self.path_of_raw(key)?;
        Ok(match self.cell_at(&path) {
            Some(cell) => Box::new(
                cell.values
                    .iter()
                    .map(|(name, value)| (name.clone(), value.clone())),
            ),
            None => Box::new(std::iter::empty()),
        })
    }

    fn keys_iter_raw<'a>(
        &'a self,
        key: &RawKey,
    ) -> crate::err::ForensicResult<Box<dyn Iterator<Item = KeyEntry> + 'a>> {
        let path = self.path_of_raw(key)?;
        Ok(match self.cell_at(&path) {
            Some(cell) => Box::new(cell.key_entries()),
            None => Box::new(std::iter::empty()),
        })
    }
}

fn basic_cache() -> BTreeMap<isize, String> {
    // With the new API, handles are created dynamically on open_key
    // No initial root mappings needed
    BTreeMap::new()
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
        RegValue::new_sz(r"C:\Users\Tester"),
    );
    hkcu_cell.add_value(
        "S-1-5-21-1366093794-4292800403-1155380978-513\\Volatile Environment",
        "APPDATA",
        RegValue::new_sz(r"C:\Users\Tester\AppData\Roaming"),
    );
    hkcu_cell.add_value(
        "S-1-5-21-1366093794-4292800403-1155380978-513\\Volatile Environment",
        "LOCALAPPDATA",
        RegValue::new_sz(r"C:\Users\Tester\AppData\Local"),
    );
    hkcu_cell.add_value(
        "S-1-5-21-1366093794-4292800403-1155380978-513\\Volatile Environment",
        "USERDOMAIN",
        RegValue::new_sz(r"TestMachine"),
    );
    hkcu_cell.add_value(
        "S-1-5-21-1366093794-4292800403-1155380978-513\\Volatile Environment",
        "USERNAME",
        RegValue::new_sz(r"Tester"),
    );
    map.insert("HKU".into(), hkcu_cell);
    map
}

#[cfg(test)]
mod new_registry_trait_tests {
    use super::*;
    use crate::traits::registry::RegistryExt;

    #[test]
    fn reads_seeded_value_via_registry_ext() {
        let reg = TestingRegistry::new();
        let sid = "S-1-5-21-1366093794-4292800403-1155380978-513";
        let value = reg
            .value(&format!(r"HKU\{sid}\Volatile Environment"), "USERNAME")
            .unwrap();
        assert_eq!(value, RegValue::SZ("Tester".to_string()));
    }

    #[test]
    fn missing_key_errors_not_panics() {
        let reg = TestingRegistry::new();
        assert!(reg.key(r"HKLM\Does\Not\Exist").is_err());
    }

    #[test]
    fn key_handle_closes_on_drop() {
        let reg = TestingRegistry::new();
        let before = reg.cached.lock().unwrap().len();
        {
            let _k = reg.key("HKLM").unwrap();
            assert_eq!(reg.cached.lock().unwrap().len(), before + 1);
        }
        assert_eq!(reg.cached.lock().unwrap().len(), before);
    }

    #[test]
    fn for_each_user_hive_finds_seeded_sid() {
        let reg = TestingRegistry::new();
        let mut visited = Vec::new();
        reg.for_each_user_hive(
            &mut |sid, _key| {
                visited.push(sid.to_string());
                Ok(())
            },
            &mut |sid, e| panic!("{sid}: {e}"),
        )
        .unwrap();
        assert_eq!(
            visited,
            vec!["S-1-5-21-1366093794-4292800403-1155380978-513".to_string()]
        );
    }

    #[test]
    fn cloned_registry_shares_counter_and_cache() {
        // Regression guard: `counter` must be Arc-shared like `cached`, or
        // two clones could allocate colliding handle ids concurrently.
        let reg = TestingRegistry::new();
        let clone = reg.clone();
        let _k1 = reg.key("HKLM").unwrap();
        let _k2 = clone.key("HKCU").unwrap();
        assert_eq!(reg.cached.lock().unwrap().len(), 2);
    }

    #[test]
    fn missing_keys_and_values_are_typed_not_found_errors() {
        use crate::err::RegistryError;
        let reg = TestingRegistry::new();
        match reg.key(r"HKLM\Does\Not\Exist") {
            Err(ForensicError::Registry(RegistryError::KeyNotFound { key, key_path })) => {
                assert_eq!(key, PredefinedHive::LocalMachine);
                assert_eq!(key_path.as_deref(), Some(r"Does\Not\Exist"));
            }
            other => panic!("expected KeyNotFound, got {other:?}"),
        }
        assert!(matches!(
            reg.value(r"HKLM", "Nope"),
            Err(ForensicError::Registry(RegistryError::ValueNotFound { .. }))
        ));
    }

    #[test]
    fn key_timestamps_are_none_until_set() {
        let mut reg = TestingRegistry::new();
        reg.add_key(r"HKLM\SOFTWARE\Vendor\App");
        let vendor = reg.key(r"HKLM\SOFTWARE\Vendor").unwrap();
        assert_eq!(vendor.info().unwrap().last_write_time, None);
        assert_eq!(vendor.keys().unwrap()[0].last_write, None);
        drop(vendor);

        let ts = ForensicTimestamp::from_win_filetime(133_514_430_235_959_706);
        reg.set_last_write(r"HKLM\SOFTWARE\Vendor\App", ts);
        let vendor = reg.key(r"HKLM\SOFTWARE\Vendor").unwrap();
        let children = vendor.keys().unwrap();
        assert_eq!(
            (children[0].name.as_str(), children[0].last_write),
            ("App", Some(ts))
        );
        let app = reg.key(r"HKLM\SOFTWARE\Vendor\App").unwrap();
        assert_eq!(app.info().unwrap().last_write_time, Some(ts));
    }

    #[test]
    fn mounted_cell_add_key_creates_a_single_level_key() {
        // It used to recurse forever on a path with no separator.
        let mut cell = MountedCell::new("HKLM");
        cell.add_key("SOFTWARE");
        cell.add_key(r"SYSTEM\Select");
        assert_eq!(
            cell.get_keys(""),
            vec!["SOFTWARE".to_string(), "SYSTEM".to_string()]
        );
        assert!(cell.contains_key(r"SYSTEM\Select"));
    }

    #[test]
    fn long_and_short_hive_names_are_one_tree() {
        use crate::traits::registry::RegistryExt;
        let mut reg = TestingRegistry::empty();
        reg.add_value(
            r"HKEY_USERS\S-1-5-21-1\Software\App",
            "Path",
            RegValue::new_sz("a"),
        );
        reg.add_value(
            r"HKU\S-1-5-21-1\Software\App",
            "Other",
            RegValue::new_sz("b"),
        );
        reg.add_value(r"hklm\SOFTWARE\Vendor", "X", RegValue::DWord(1));
        let users = reg.key(r"HKU\S-1-5-21-1\Software\App").unwrap();
        assert_eq!(users.values().unwrap().len(), 2, "one key, not two trees");
        assert!(reg.key(r"HKEY_USERS\S-1-5-21-1\Software\App").is_ok());
        assert!(reg.key(r"HKEY_LOCAL_MACHINE\SOFTWARE\Vendor").is_ok());
        // `root()` reaches what the long names created.
        assert!(reg.root(PredefinedHive::Users).is_ok());
        assert!(reg.root(PredefinedHive::LocalMachine).is_ok());
    }

    #[test]
    fn key_and_value_names_match_in_any_case_and_keep_their_spelling() {
        use crate::traits::registry::RegistryExt;
        let mut reg = TestingRegistry::empty();
        reg.add_value(
            r"HKLM\SOFTWARE\Microsoft\Windows",
            "ProgramFilesDir",
            RegValue::new_sz("C:"),
        );
        // Re-adding in another case reuses the key and replaces the value, as Windows would.
        reg.add_value(
            r"HKLM\software\MICROSOFT\windows",
            "programfilesdir",
            RegValue::new_sz("D:"),
        );
        let key = reg.key(r"hklm\Software\microsoft\WINDOWS").unwrap();
        assert_eq!(
            key.value("PROGRAMFILESDIR").unwrap(),
            RegValue::new_sz("D:")
        );
        let values = key.values().unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].0, "ProgramFilesDir", "the first spelling is kept");
        let names: Vec<String> = reg
            .key(r"HKLM\SOFTWARE")
            .unwrap()
            .keys()
            .unwrap()
            .into_iter()
            .map(|k| k.name)
            .collect();
        assert_eq!(names, ["Microsoft"]);
        // A missing key is still a typed not-found error, whatever the spelling.
        let missing = reg.key(r"HKEY_LOCAL_MACHINE\SOFTWARE\Nope").unwrap_err();
        assert!(missing.is_registry_not_found());
    }
}
