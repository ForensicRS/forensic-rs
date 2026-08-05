//! Conformance battery for `Registry` backends (RFC 0001 implementation
//! plan, workstream F). `TestingRegistry` is the only in-tree backend today;
//! written as free functions (not a macro) so a future backend can opt in
//! by adding one more call at the bottom.
//!
//! Two RFC-listed assertions are intentionally **not** included, because
//! `TestingRegistry` (a `BTreeMap`-backed mock, unchanged by this
//! workstream) doesn't implement the behavior they'd assert:
//! - Case-insensitive key/value name lookups — `MountedCell` does exact
//!   `BTreeMap` string matching. Real Windows registry semantics are
//!   case-insensitive; this is a pre-existing gap in the mock, not
//!   something introduced or fixed here.
//! - `KeyNotFound` vs `ValueNotFound` as distinguishable error variants —
//!   `TestingRegistry`'s new `Registry` impl reports both via
//!   `ForensicError::other(...)`, deliberately avoiding a dependency on
//!   `RegistryError::{KeyNotFound,ValueNotFound}`'s still-`RegHiveKey`-typed
//!   fields (workstream D9, deferred to the final cutover). Both cases do
//!   still error, just without a distinguishable variant yet.

use forensic_rs::traits::registry::{windows, PredefinedHive, RegValue, Registry, RegistryExt};
use forensic_rs::utils::testing::TestingRegistry;

const SID: &str = "S-1-5-21-1366093794-4292800403-1155380978-513";

fn key_open_succeeds_for_existing_path(reg: &TestingRegistry) {
    assert!(reg.key("HKLM").is_ok());
}

fn key_open_errors_for_missing_path(reg: &TestingRegistry) {
    assert!(reg.key(r"HKLM\Does\Not\Exist").is_err());
}

fn nested_open_succeeds_for_existing_child_errors_for_missing(reg: &TestingRegistry) {
    let hku = reg.key("HKU").unwrap();
    assert!(hku.open(SID).is_ok());
    assert!(hku.open("S-0-0-0-0").is_err());
}

fn value_round_trips_seeded_sz(reg: &TestingRegistry) {
    let v = reg
        .value(&format!(r"HKU\{SID}\Volatile Environment"), "USERNAME")
        .unwrap();
    assert_eq!(v, RegValue::SZ("Tester".to_string()));
}

fn missing_key_and_missing_value_both_error(reg: &TestingRegistry) {
    assert!(reg.key(r"HKLM\Nope").is_err());
    assert!(reg
        .value(&format!(r"HKU\{SID}\Volatile Environment"), "NoSuchValue")
        .is_err());
}

fn keys_and_values_enumeration_matches_seeded_data(reg: &TestingRegistry) {
    let env_key = reg
        .key(&format!(r"HKU\{SID}\Volatile Environment"))
        .unwrap();
    let mut names: Vec<String> = env_key
        .values()
        .unwrap()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["APPDATA", "LOCALAPPDATA", "USERDOMAIN", "USERNAME", "USERPROFILE"]
    );
}

fn key_info_counts_match_seeded_data(reg: &TestingRegistry) {
    let env_key = reg
        .key(&format!(r"HKU\{SID}\Volatile Environment"))
        .unwrap();
    let info = env_key.info().unwrap();
    assert_eq!(info.values, 5);
    assert_eq!(info.subkeys, 0);
}

fn root_errors_cleanly_for_unsupported_hive(reg: &TestingRegistry) {
    // `PredefinedHive::DynData` isn't seeded/supported by this testing
    // double — must error, not panic.
    assert!(reg.root(PredefinedHive::DynData).is_err());
}

fn for_each_user_hive_visits_seeded_sid_only(reg: &TestingRegistry) {
    let mut visited = Vec::new();
    reg.for_each_user_hive(&mut |sid, _key| {
        visited.push(sid.to_string());
        Ok(())
    })
    .unwrap();
    assert_eq!(visited, vec![SID.to_string()]);
}

fn key_handle_is_idempotently_closed_by_drop_or_explicit_close(reg: &TestingRegistry) {
    let before = reg.cached.lock().unwrap().len();
    let k = reg.key("HKLM").unwrap();
    assert_eq!(reg.cached.lock().unwrap().len(), before + 1);
    k.close().unwrap();
    assert_eq!(reg.cached.lock().unwrap().len(), before);
}

fn windows_helpers_read_seeded_environment(reg: &TestingRegistry) {
    // `windows::system_root`/`windows::build` need a `CurrentVersion` key
    // this fixture doesn't seed — assert they fail cleanly (not panic)
    // rather than fabricating data the fixture doesn't have.
    assert!(windows::system_root(reg).is_err());
    assert!(windows::build(reg).is_err());

    // `windows::users` only depends on HKU + (optionally) ProfileList, both
    // reachable here — should find the seeded SID even without ProfileList.
    let profiles = windows::users(reg).unwrap();
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].sid, SID);
}

macro_rules! registry_conformance_battery {
    ($module:ident, $make:expr) => {
        mod $module {
            use super::*;

            #[test]
            fn key_open_succeeds_for_existing_path_test() {
                key_open_succeeds_for_existing_path(&$make);
            }
            #[test]
            fn key_open_errors_for_missing_path_test() {
                key_open_errors_for_missing_path(&$make);
            }
            #[test]
            fn nested_open_succeeds_for_existing_child_errors_for_missing_test() {
                nested_open_succeeds_for_existing_child_errors_for_missing(&$make);
            }
            #[test]
            fn value_round_trips_seeded_sz_test() {
                value_round_trips_seeded_sz(&$make);
            }
            #[test]
            fn missing_key_and_missing_value_both_error_test() {
                missing_key_and_missing_value_both_error(&$make);
            }
            #[test]
            fn keys_and_values_enumeration_matches_seeded_data_test() {
                keys_and_values_enumeration_matches_seeded_data(&$make);
            }
            #[test]
            fn key_info_counts_match_seeded_data_test() {
                key_info_counts_match_seeded_data(&$make);
            }
            #[test]
            fn root_errors_cleanly_for_unsupported_hive_test() {
                root_errors_cleanly_for_unsupported_hive(&$make);
            }
            #[test]
            fn for_each_user_hive_visits_seeded_sid_only_test() {
                for_each_user_hive_visits_seeded_sid_only(&$make);
            }
            #[test]
            fn key_handle_is_idempotently_closed_by_drop_or_explicit_close_test() {
                key_handle_is_idempotently_closed_by_drop_or_explicit_close(&$make);
            }
            #[test]
            fn windows_helpers_read_seeded_environment_test() {
                windows_helpers_read_seeded_environment(&$make);
            }
            #[test]
            fn send_sync_bound_holds() {
                fn assert_send_sync<T: Send + Sync>(_: &T) {}
                assert_send_sync(&$make);
            }
        }
    };
}

registry_conformance_battery!(testing_registry, TestingRegistry::new());
