//! Windows-specific semantics built on top of the generic
//! [`Registry`]/[`RegistryExt`] primitives.
//!
//! Migrated out of the old `RegistryReader` trait per RFC 0001 §1 (P1): these
//! are Windows analysis semantics *derived from* registry operations, not
//! registry primitives themselves. A backend or mock author no longer needs
//! to understand `ProfileList`'s layout before their code compiles — these
//! free functions work identically against any `&dyn Registry`.
//!
//! `windows::timezone`/`windows::computer_name` are deferred (no existing
//! code in this crate reads `TimeZoneInformation` or `ComputerName` yet) —
//! see the RFC 0001 implementation plan, workstream D5.

use super::{Registry, RegistryExt};
use crate::core::path::FPathBuf;
use crate::err::ForensicResult;

const CURRENT_VERSION: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";

/// A discovered user profile.
#[derive(Debug, Clone, Default)]
pub struct UserProfile {
    pub sid: String,
    /// Empty when the SID has no correlating `ProfileList` entry (present
    /// under `HKEY_USERS` but never logged in / no profile created).
    pub profile_path: FPathBuf,
    /// Best-effort guess from the profile path's final segment (e.g.
    /// `C:\Users\Bob` -> `Bob`). Not authoritative — a real display name
    /// lives elsewhere (SAM/LSA) and isn't derived here.
    pub name: Option<String>,
}

/// Windows version/build information. Richer than a bare build number,
/// since build number alone stopped identifying a Windows release years
/// ago.
#[derive(Debug, Clone, Default)]
pub struct WindowsVersion {
    pub build: u32,
    pub major: u32,
    pub minor: u32,
    pub display_version: Option<String>,
    pub product_name: Option<String>,
}

/// Reads `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot`
/// (usually `C:\Windows`).
pub fn system_root(reg: &dyn Registry) -> ForensicResult<FPathBuf> {
    let value = reg.value(CURRENT_VERSION, "SystemRoot")?;
    let s: String = value.try_into()?;
    Ok(FPathBuf::from(s))
}

/// Enumerates user profiles: `HKEY_USERS`' own SID list (via
/// [`RegistryExt::for_each_user_hive`]) correlated against `ProfileList`
/// (SID -> profile path), with `%SystemRoot%` expansion. A SID present in
/// one but not the other still surfaces.
pub fn users(reg: &dyn Registry) -> ForensicResult<Vec<UserProfile>> {
    let sys_root = system_root(reg).ok();
    let profile_list_path = format!(r"{CURRENT_VERSION}\ProfileList");
    let mut profiles = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    if let Ok(profile_list) = reg.key(&profile_list_path) {
        for entry in profile_list.keys()? {
            if !entry.name.starts_with("S-") {
                continue;
            }
            let profile_path: Option<String> = profile_list
                .open(&entry.name)
                .and_then(|k| k.value("ProfileImagePath"))
                .ok()
                .and_then(|v| String::try_from(v).ok())
                .map(|p| expand_system_root(p, sys_root.as_ref()));
            let name = profile_path
                .as_deref()
                .and_then(|p| p.rsplit(['\\', '/']).next())
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            seen.insert(entry.name.clone());
            profiles.push(UserProfile {
                sid: entry.name,
                profile_path: profile_path.map(FPathBuf::from).unwrap_or_default(),
                name,
            });
        }
    }

    reg.for_each_user_hive(&mut |sid, _key| {
        if seen.insert(sid.to_string()) {
            profiles.push(UserProfile {
                sid: sid.to_string(),
                profile_path: FPathBuf::default(),
                name: None,
            });
        }
        Ok(())
    })?;

    Ok(profiles)
}

fn expand_system_root(path: String, sys_root: Option<&FPathBuf>) -> String {
    let stripped = path
        .strip_prefix("%systemroot%")
        .or_else(|| path.strip_prefix("%SystemRoot%"));
    match (stripped, sys_root) {
        (Some(rest), Some(root)) => format!("{root}{rest}"),
        _ => path,
    }
}

/// Reads Windows build/version info from `CurrentVersion`. Only `build`
/// (`CurrentBuild`) is required to succeed; the richer fields are
/// best-effort.
///
/// `CurrentBuild` is a `REG_SZ` on real Windows, not a `REG_DWORD` — parsed
/// as a string and converted to `u32`, not read via the numeric
/// `TryFrom<RegValue>` conversions.
pub fn build(reg: &dyn Registry) -> ForensicResult<WindowsVersion> {
    let build_str: String = reg.value(CURRENT_VERSION, "CurrentBuild")?.try_into()?;
    let build: u32 = build_str
        .parse()
        .map_err(|_| crate::err::ForensicError::cast_error("String", "u32", build_str.into()))?;
    let major = reg
        .value(CURRENT_VERSION, "CurrentMajorVersionNumber")
        .ok()
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    let minor = reg
        .value(CURRENT_VERSION, "CurrentMinorVersionNumber")
        .ok()
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    let display_version = reg
        .value(CURRENT_VERSION, "DisplayVersion")
        .ok()
        .and_then(|v| String::try_from(v).ok());
    let product_name = reg
        .value(CURRENT_VERSION, "ProductName")
        .ok()
        .and_then(|v| String::try_from(v).ok());
    Ok(WindowsVersion {
        build,
        major,
        minor,
        display_version,
        product_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::registry::raw::{KeyEntry, KeyInfo, PredefinedHive, RawKey};
    use crate::traits::registry::RegValue;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// Minimal `Registry` double seeding a `CurrentVersion` + `ProfileList` +
    /// `HKEY_USERS` layout, enough to exercise every function here without
    /// depending on `TestingRegistry` (which gains a real `Registry` impl in
    /// workstream D8).
    struct MiniWindowsRegistry {
        values: BTreeMap<String, Vec<(String, RegValue)>>,
        children: BTreeMap<String, Vec<String>>,
        cache: Mutex<BTreeMap<u64, String>>,
        counter: Mutex<u64>,
    }

    impl MiniWindowsRegistry {
        fn new() -> Self {
            let mut values = BTreeMap::new();
            let mut children = BTreeMap::new();

            values.insert(
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion".to_string(),
                vec![
                    ("SystemRoot".to_string(), RegValue::SZ(r"C:\Windows".to_string())),
                    ("CurrentBuild".to_string(), RegValue::SZ("19045".to_string())),
                ],
            );
            children.insert(
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion".to_string(),
                vec!["ProfileList".to_string()],
            );
            children.insert(
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList".to_string(),
                vec!["S-1-5-21-1".to_string()],
            );
            values.insert(
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-1".to_string(),
                vec![(
                    "ProfileImagePath".to_string(),
                    RegValue::SZ(r"%systemroot%\Users\Bob".to_string()),
                )],
            );
            children.insert(String::new(), vec!["S-1-5-21-1".to_string(), "S-1-5-21-2".to_string()]);
            // Top-level HKEY_USERS entries for `for_each_user_hive`, distinct
            // from the nested ProfileList\<sid> keys above (this flat test
            // double doesn't separate hives into distinct trees).
            children.insert("S-1-5-21-1".to_string(), vec![]);
            children.insert("S-1-5-21-2".to_string(), vec![]);

            MiniWindowsRegistry {
                values,
                children,
                cache: Mutex::new(BTreeMap::new()),
                counter: Mutex::new(0),
            }
        }

        fn intern(&self, path: String) -> RawKey {
            let mut counter = self.counter.lock().unwrap();
            *counter += 1;
            let id = *counter;
            self.cache.lock().unwrap().insert(id, path);
            RawKey::from_raw(id)
        }

        fn path_of(&self, key: &RawKey) -> ForensicResult<String> {
            self.cache
                .lock()
                .unwrap()
                .get(&key.raw())
                .cloned()
                .ok_or_else(|| crate::err::ForensicError::other("registry", "unknown handle".to_string()))
        }
    }

    impl Registry for MiniWindowsRegistry {
        fn root(&self, hive: PredefinedHive) -> ForensicResult<RawKey> {
            if !matches!(hive, PredefinedHive::LocalMachine | PredefinedHive::Users) {
                return Err(crate::err::ForensicError::other("registry", "unsupported hive".to_string()));
            }
            Ok(self.intern(String::new()))
        }
        fn open_raw(&self, parent: &RawKey, name: &str) -> ForensicResult<RawKey> {
            let parent_path = self.path_of(parent)?;
            let full = if parent_path.is_empty() {
                name.to_string()
            } else {
                format!("{parent_path}\\{name}")
            };
            if !self.values.contains_key(&full) && !self.children.contains_key(&full) {
                return Err(crate::err::ForensicError::other("registry", format!("no such key: {full}")));
            }
            Ok(self.intern(full))
        }
        fn close_raw(&self, key: &RawKey) {
            self.cache.lock().unwrap().remove(&key.raw());
        }
        fn read_raw(&self, key: &RawKey, value: &str) -> ForensicResult<RegValue> {
            let path = self.path_of(key)?;
            self.values
                .get(&path)
                .and_then(|values| values.iter().find(|(n, _)| n == value))
                .map(|(_, v)| v.clone())
                .ok_or_else(|| crate::err::ForensicError::other("registry", "value not found".to_string()))
        }
        fn values_raw(&self, key: &RawKey) -> ForensicResult<Vec<(String, RegValue)>> {
            let path = self.path_of(key)?;
            Ok(self.values.get(&path).cloned().unwrap_or_default())
        }
        fn keys_raw(&self, key: &RawKey) -> ForensicResult<Vec<KeyEntry>> {
            let path = self.path_of(key)?;
            Ok(self
                .children
                .get(&path)
                .map(|children| {
                    children
                        .iter()
                        .map(|name| KeyEntry {
                            name: name.clone(),
                            last_write: None,
                            allocated: true,
                        })
                        .collect()
                })
                .unwrap_or_default())
        }
        fn info_raw(&self, key: &RawKey) -> ForensicResult<KeyInfo> {
            let path = self.path_of(key)?;
            Ok(KeyInfo {
                subkeys: self.children.get(&path).map(Vec::len).unwrap_or(0) as u32,
                values: self.values.get(&path).map(Vec::len).unwrap_or(0) as u32,
                ..Default::default()
            })
        }
    }

    #[test]
    fn system_root_reads_current_version() {
        let reg = MiniWindowsRegistry::new();
        assert_eq!(system_root(&reg).unwrap().as_str(), "C:/Windows");
    }

    #[test]
    fn build_reads_current_build() {
        let reg = MiniWindowsRegistry::new();
        assert_eq!(build(&reg).unwrap().build, 19045);
    }

    #[test]
    fn users_correlates_profile_list_and_expands_system_root() {
        let reg = MiniWindowsRegistry::new();
        let mut profiles = users(&reg).unwrap();
        profiles.sort_by(|a, b| a.sid.cmp(&b.sid));

        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[0].sid, "S-1-5-21-1");
        assert_eq!(profiles[0].profile_path.as_str(), "C:/Windows/Users/Bob");
        assert_eq!(profiles[0].name.as_deref(), Some("Bob"));

        // Present under HKEY_USERS but absent from ProfileList: still
        // surfaces, with an empty profile path.
        assert_eq!(profiles[1].sid, "S-1-5-21-2");
        assert!(profiles[1].profile_path.as_str().is_empty());
        assert_eq!(profiles[1].name, None);
    }
}
