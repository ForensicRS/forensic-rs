//! RFC 0001 Registry redesign: a minimal, mechanical, `Send + Sync` core
//! trait ([`Registry`]) plus a lifetime-tied RAII key guard ([`RegKey`])
//! that makes registry handle-lifetime bugs a compile error instead of a
//! runtime one.
//!
//! Replaces the legacy `RegistryReader`/`RegKeyHandle` design (removed once
//! every backend and consumer moved over — see the RFC 0001 implementation
//! plan, workstream D).
//!
//! The compile-time guarantees this design provides (a [`RegKey`] cannot
//! outlive its [`Registry`], cannot cross readers, and [`RawKey`] cannot be
//! duplicated) are proven by the `trybuild` fixtures under
//! `tests/compile_fail/` (RFC 0001 implementation plan, workstream F).

use super::RegValue;
use crate::err::ForensicResult;
use crate::utils::time::ForensicTimestamp;
use std::marker::PhantomData;

/// Root hive discriminant for the [`Registry`] core trait. Distinct from the
/// legacy `RegHiveKey`, which conflated "one of nine well-known roots" with
/// "an arbitrary raw handle value" (`RegHiveKey::Hkey(isize)`). Seeding a
/// backend from an externally-supplied raw handle is now a
/// backend-constructor concern, not part of this enum.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredefinedHive {
    ClassesRoot,
    CurrentConfig,
    CurrentUser,
    LocalMachine,
    Users,
    PerformanceData,
    PerformanceText,
    PerformanceNlsText,
    DynData,
}

impl std::fmt::Display for PredefinedHive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            PredefinedHive::ClassesRoot => "HKEY_CLASSES_ROOT",
            PredefinedHive::CurrentConfig => "HKEY_CURRENT_CONFIG",
            PredefinedHive::CurrentUser => "HKEY_CURRENT_USER",
            PredefinedHive::LocalMachine => "HKEY_LOCAL_MACHINE",
            PredefinedHive::Users => "HKEY_USERS",
            PredefinedHive::PerformanceData => "HKEY_PERFORMANCE_DATA",
            PredefinedHive::PerformanceText => "HKEY_PERFORMANCE_TEXT",
            PredefinedHive::PerformanceNlsText => "HKEY_PERFORMANCE_NLSTEXT",
            PredefinedHive::DynData => "HKEY_DYN_DATA",
        };
        write!(f, "{s}")
    }
}

/// Opaque, backend-assigned key identifier. Deliberately not `Copy`/`Clone`
/// — a `RawKey` is owned by exactly one [`RegKey`], never duplicated. Only a
/// [`Registry`] implementation constructs or meaningfully inspects one.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct RawKey(u64);

impl RawKey {
    /// Backend-only constructor.
    pub fn from_raw(id: u64) -> Self {
        RawKey(id)
    }
    /// Backend-only accessor.
    pub fn raw(&self) -> u64 {
        self.0
    }
}

/// A key name paired with its last-write time, as returned by
/// [`Registry::keys_raw`].
#[derive(Debug, Clone)]
pub struct KeyEntry {
    pub name: String,
    pub last_write: Option<ForensicTimestamp>,
    /// `false` when recovered from an unallocated (deleted) cell rather than
    /// read live. Always `true` for backends without deleted-cell recovery.
    pub allocated: bool,
}

/// Metadata about an open key, analogous to `RegQueryInfoKey`. Parallels the
/// legacy `RegistryKeyInfo` during the migration.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyInfo {
    pub subkeys: u32,
    pub max_subkey_name_length: u32,
    pub values: u32,
    pub max_value_name_length: u32,
    pub max_value_length: u32,
    pub last_write_time: Option<ForensicTimestamp>,
}

/// Everything a backend must implement: seven mechanical, `&self`-based
/// methods. `Vec`-returning rather than visitor-callback — every backend in
/// this crate already materializes the full list before a visitor loop
/// would run anyway, so the callback style buys early-exit ergonomics but no
/// real streaming savings (see the RFC 0001 implementation plan, workstream
/// D1, for the full justification).
pub trait Registry: Send + Sync {
    fn root(&self, hive: PredefinedHive) -> ForensicResult<RawKey>;
    /// `name` may be a full multi-segment relative path (e.g.
    /// `"Microsoft\\Windows\\CurrentVersion"`), not just one component —
    /// matches the legacy `open_key`'s contract, so a backend need not pay
    /// one round trip per path segment.
    fn open_raw(&self, parent: &RawKey, name: &str) -> ForensicResult<RawKey>;
    /// Infallible: called from [`RegKey`]'s `Drop` impl, which cannot
    /// propagate an error. A backend that can fail to close should log
    /// internally; [`RegKey::close`] is the fallible, explicit escape hatch.
    fn close_raw(&self, key: &RawKey);
    fn read_raw(&self, key: &RawKey, value: &str) -> ForensicResult<RegValue>;
    fn values_raw(&self, key: &RawKey) -> ForensicResult<Vec<(String, RegValue)>>;
    fn keys_raw(&self, key: &RawKey) -> ForensicResult<Vec<KeyEntry>>;
    fn info_raw(&self, key: &RawKey) -> ForensicResult<KeyInfo>;

    /// Capability probe for deleted-key/value recovery. `None` by default.
    fn as_recovery(&self) -> Option<&dyn RecoverDeleted> {
        None
    }
}

/// RAII guard for an open registry key, tied to the `&'r T` it was opened
/// from by a lifetime parameter. This is what makes the RFC 0001 P2 bug
/// class a compile error:
///
/// - a key cannot outlive its reader — the borrow checker rejects it
///   (`E0515`)
/// - a key cannot be used with a *different* reader — there is no method
///   that accepts a foreign `RegKey`, and its fields are private
///   (`E0616` if code tries to reach in directly)
/// - a key cannot leak — no `Copy`/`Clone`, unconditional `Drop`
/// - a key cannot be used after close — `close_key` does not exist in this
///   API; closing *is* dropping (`E0382` on any post-move use)
///
/// Generic over `T: Registry + ?Sized` (defaulting to `dyn Registry`, the
/// canonical currency type throughout the framework — see
/// [`crate::traits::vfs::FileSystem`]'s `Arc<dyn FileSystem>` for the same
/// convention) for the same reason [`crate::core::fs::walk::Walk`] is
/// generic over its filesystem type: [`RegistryExt`]'s default methods must
/// build a `RegKey` from `&Self` without an unsized coercion, which doesn't
/// type-check generically when `Self` may already be a trait object.
pub struct RegKey<'r, T: Registry + ?Sized = dyn Registry> {
    reg: &'r T,
    raw: RawKey,
    // Mirrors the legacy `RegKeyHandle`'s thread-confinement contract for
    // backends with thread-confined live handles (e.g. a raw Win32 HKEY).
    // `Registry: Send + Sync` would otherwise make `&'r T` unconditionally
    // shareable; this keeps `RegKey` itself `!Send`/`!Sync`.
    _not_send_sync: PhantomData<*mut ()>,
}

impl<T: Registry + ?Sized> std::fmt::Debug for RegKey<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately doesn't require `T: Debug` (nor prints the raw
        // handle id, which is backend-internal) — just enough for
        // `.unwrap()`/`.expect()` on a `Result<RegKey, _>` to work.
        f.debug_struct("RegKey").finish_non_exhaustive()
    }
}

impl<T: Registry + ?Sized> Drop for RegKey<'_, T> {
    fn drop(&mut self) {
        self.reg.close_raw(&self.raw);
    }
}

impl<'r, T: Registry + ?Sized> RegKey<'r, T> {
    /// Backend/[`RegistryExt`]-only constructor.
    pub fn from_raw(reg: &'r T, raw: RawKey) -> Self {
        RegKey {
            reg,
            raw,
            _not_send_sync: PhantomData,
        }
    }

    pub fn open(&self, name: &str) -> ForensicResult<RegKey<'r, T>> {
        let raw = self.reg.open_raw(&self.raw, name)?;
        Ok(RegKey::from_raw(self.reg, raw))
    }
    pub fn value(&self, name: &str) -> ForensicResult<RegValue> {
        self.reg.read_raw(&self.raw, name)
    }
    pub fn values(&self) -> ForensicResult<Vec<(String, RegValue)>> {
        self.reg.values_raw(&self.raw)
    }
    pub fn keys(&self) -> ForensicResult<Vec<KeyEntry>> {
        self.reg.keys_raw(&self.raw)
    }
    pub fn info(&self) -> ForensicResult<KeyInfo> {
        self.reg.info_raw(&self.raw)
    }

    /// Explicit early close. Prefer letting the key drop; use this only
    /// when a close failure must be observed by the caller.
    pub fn close(self) -> ForensicResult<()> {
        self.reg.close_raw(&self.raw);
        std::mem::forget(self);
        Ok(())
    }
}

/// Path-based convenience over [`Registry`], blanket-impl'd. A backend
/// author never implements this directly.
pub trait RegistryExt: Registry {
    /// `path` is `"HKLM\\Software\\Microsoft\\...\\Run"`-shaped: a hive
    /// designator (accepts both short (`HKLM`) and long
    /// (`HKEY_LOCAL_MACHINE`) forms, case-insensitively) followed by an
    /// optional `\`-separated subpath.
    fn key(&self, path: &str) -> ForensicResult<RegKey<'_, Self>> {
        let (hive, sub) = parse_hive_path(path)?;
        let root = self.root(hive)?;
        let root_key = RegKey::from_raw(self, root);
        if sub.is_empty() {
            Ok(root_key)
        } else {
            root_key.open(sub)
        }
    }
    fn value(&self, path: &str, name: &str) -> ForensicResult<RegValue> {
        self.key(path)?.value(name)
    }
    fn keys_at(&self, path: &str) -> ForensicResult<Vec<KeyEntry>> {
        self.key(path)?.keys()
    }
    fn values_at(&self, path: &str) -> ForensicResult<Vec<(String, RegValue)>> {
        self.key(path)?.values()
    }
    /// Expands `*` over user SIDs under `HKEY_USERS` — the most repeated
    /// loop in DFIR code. Skips `_Classes`-suffixed per-user class roots.
    fn for_each_user_hive(
        &self,
        f: &mut dyn FnMut(&str, RegKey<'_, Self>) -> ForensicResult<()>,
    ) -> ForensicResult<()> {
        let hku = self.root(PredefinedHive::Users)?;
        let hku_key = RegKey::from_raw(self, hku);
        for entry in hku_key.keys()? {
            if entry.name.starts_with("S-") && !entry.name.ends_with("_Classes") {
                let user_key = hku_key.open(&entry.name)?;
                f(&entry.name, user_key)?;
            }
        }
        Ok(())
    }
}
impl<T: Registry + ?Sized> RegistryExt for T {}

fn parse_hive_path(path: &str) -> ForensicResult<(PredefinedHive, &str)> {
    let sep_pos = path.find('\\').unwrap_or(path.len());
    let (root, sub) = (&path[..sep_pos], path.get(sep_pos + 1..).unwrap_or(""));
    let hive = resolve_hive(root)?;
    Ok((hive, sub))
}

fn resolve_hive(name: &str) -> ForensicResult<PredefinedHive> {
    let hive = match name.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => PredefinedHive::LocalMachine,
        "HKCU" | "HKEY_CURRENT_USER" => PredefinedHive::CurrentUser,
        "HKU" | "HKEY_USERS" => PredefinedHive::Users,
        "HKCR" | "HKEY_CLASSES_ROOT" => PredefinedHive::ClassesRoot,
        "HKCC" | "HKEY_CURRENT_CONFIG" => PredefinedHive::CurrentConfig,
        "HKPD" | "HKEY_PERFORMANCE_DATA" => PredefinedHive::PerformanceData,
        "HKEY_PERFORMANCE_TEXT" => PredefinedHive::PerformanceText,
        "HKEY_PERFORMANCE_NLSTEXT" => PredefinedHive::PerformanceNlsText,
        "HKDD" | "HKEY_DYN_DATA" => PredefinedHive::DynData,
        other => {
            return Err(crate::err::ForensicError::other(
                "registry",
                format!("unknown hive designator: {other}"),
            ))
        }
    };
    Ok(hive)
}

/// Deleted-cell recovery capability, discovered via [`Registry::as_recovery`].
/// No backend implements this yet — pure plumbing so a future hive-slack
/// parser can opt in without another core-trait change.
pub trait RecoverDeleted: Registry {
    fn deleted_keys(&self) -> ForensicResult<Vec<RecoveredKey>>;
    fn deleted_values(&self) -> ForensicResult<Vec<RecoveredValue>>;
}

#[derive(Debug, Clone)]
pub struct RecoveredKey {
    pub name: String,
    pub last_write: Option<ForensicTimestamp>,
    pub parent_hint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RecoveredValue {
    pub key_hint: Option<String>,
    pub name: String,
    pub value: RegValue,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// Minimal in-file `Registry` test double: a tree of `path -> (values,
    /// children)`. Proves object-safety and the `RegistryExt` blanket impl.
    /// `TestingRegistry` gains a real `Registry` impl in workstream D8.
    ///
    /// Uses `Mutex` rather than `RefCell` for interior mutability: `Registry:
    /// Send + Sync` requires implementors to be `Sync`, and `RefCell` isn't.
    // path ("" for root, else "Sub\\Key") -> (values, child names)
    type MiniRegistryNode = (Vec<(String, RegValue)>, Vec<String>);

    struct MiniRegistry {
        tree: BTreeMap<String, MiniRegistryNode>,
        cache: Mutex<BTreeMap<u64, String>>,
        counter: Mutex<u64>,
    }

    impl MiniRegistry {
        fn new() -> Self {
            let mut tree = BTreeMap::new();
            tree.insert(
                "Software".to_string(),
                (
                    vec![("InstallDate".to_string(), RegValue::DWord(20240101))],
                    vec!["Run".to_string()],
                ),
            );
            tree.insert(
                "Software\\Run".to_string(),
                (vec![("Updater".to_string(), RegValue::SZ("updater.exe".to_string()))], vec![]),
            );
            MiniRegistry {
                tree,
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

    impl Registry for MiniRegistry {
        fn root(&self, hive: PredefinedHive) -> ForensicResult<RawKey> {
            // This minimal double uses one flat tree for every hive it
            // supports; a real backend maps each hive to a distinct root.
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
            if !self.tree.contains_key(&full) {
                return Err(crate::err::ForensicError::other("registry", format!("no such key: {full}")));
            }
            Ok(self.intern(full))
        }
        fn close_raw(&self, key: &RawKey) {
            self.cache.lock().unwrap().remove(&key.raw());
        }
        fn read_raw(&self, key: &RawKey, value: &str) -> ForensicResult<RegValue> {
            let path = self.path_of(key)?;
            self.tree
                .get(&path)
                .and_then(|(values, _)| values.iter().find(|(n, _)| n == value))
                .map(|(_, v)| v.clone())
                .ok_or_else(|| crate::err::ForensicError::other("registry", "value not found".to_string()))
        }
        fn values_raw(&self, key: &RawKey) -> ForensicResult<Vec<(String, RegValue)>> {
            let path = self.path_of(key)?;
            Ok(self.tree.get(&path).map(|(v, _)| v.clone()).unwrap_or_default())
        }
        fn keys_raw(&self, key: &RawKey) -> ForensicResult<Vec<KeyEntry>> {
            let path = self.path_of(key)?;
            Ok(self
                .tree
                .get(&path)
                .map(|(_, children)| {
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
            let (values, children) = self.tree.get(&path).cloned().unwrap_or_default();
            Ok(KeyInfo {
                subkeys: children.len() as u32,
                values: values.len() as u32,
                ..Default::default()
            })
        }
    }

    fn accepts_dyn_registry(_r: &dyn Registry) {}

    #[test]
    fn registry_is_object_safe() {
        let reg = MiniRegistry::new();
        accepts_dyn_registry(&reg);
    }

    #[test]
    fn key_reads_values_via_path() {
        let reg = MiniRegistry::new();
        let value = reg.value("HKLM\\Software", "InstallDate").unwrap();
        assert_eq!(value, RegValue::DWord(20240101));
    }

    #[test]
    fn nested_key_open_reads_value() {
        let reg = MiniRegistry::new();
        let run = reg.key("HKLM\\Software\\Run").unwrap();
        assert_eq!(run.value("Updater").unwrap(), RegValue::SZ("updater.exe".to_string()));
    }

    #[test]
    fn missing_key_errors_not_panics() {
        let reg = MiniRegistry::new();
        assert!(reg.key("HKLM\\DoesNotExist").is_err());
    }

    #[test]
    fn key_closes_on_drop() {
        let reg = MiniRegistry::new();
        {
            let _k = reg.key("HKLM\\Software").unwrap();
            // The intermediate root handle used to reach "Software" is
            // already closed by the time `key()` returns (mirrors real
            // Windows Registry API usage: close the parent once the child
            // is obtained) — only "Software" itself remains open.
            assert_eq!(reg.cache.lock().unwrap().len(), 1);
        }
        assert_eq!(reg.cache.lock().unwrap().len(), 0);
    }

    #[test]
    fn explicit_close_removes_handle_immediately() {
        let reg = MiniRegistry::new();
        let k = reg.key("HKLM\\Software").unwrap();
        k.close().unwrap();
        assert_eq!(reg.cache.lock().unwrap().len(), 0);
    }

    #[test]
    fn for_each_user_hive_visits_only_sid_keys() {
        let mut tree = BTreeMap::new();
        tree.insert(
            String::new(),
            (vec![], vec!["S-1-5-21-1".to_string(), "S-1-5-21-1_Classes".to_string(), ".DEFAULT".to_string()]),
        );
        tree.insert("S-1-5-21-1".to_string(), (vec![], vec![]));
        tree.insert("S-1-5-21-1_Classes".to_string(), (vec![], vec![]));
        tree.insert(".DEFAULT".to_string(), (vec![], vec![]));
        let reg = MiniRegistry {
            tree,
            cache: Mutex::new(BTreeMap::new()),
            counter: Mutex::new(0),
        };
        let mut visited = Vec::new();
        reg.for_each_user_hive(&mut |sid, _key| {
            visited.push(sid.to_string());
            Ok(())
        })
        .unwrap();
        assert_eq!(visited, vec!["S-1-5-21-1".to_string()]);
    }

    #[test]
    fn resolve_hive_accepts_short_and_long_forms_case_insensitively() {
        assert_eq!(resolve_hive("hklm").unwrap(), PredefinedHive::LocalMachine);
        assert_eq!(resolve_hive("HKEY_LOCAL_MACHINE").unwrap(), PredefinedHive::LocalMachine);
        assert!(resolve_hive("NOT_A_HIVE").is_err());
    }

    #[test]
    fn arc_dyn_registry_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<std::sync::Arc<dyn Registry>>();
    }
}
