//! Conformance battery for [`ForensicDb`]/[`ForensicRows`] implementations,
//! exercised from outside the crate (public API only) the way a downstream
//! backend author would use them. Mirrors the style of
//! `tests/registry_conformance.rs` and `tests/format_conformance.rs`:
//! behavioral guarantees the trait contract promises, not one backend's
//! internals.
//!
//! The theme throughout is that recovery must be reachable *generically*.
//! Every assertion here goes through `&dyn ForensicDb` / `&dyn ForensicRows`,
//! because a triage tool built against the trait family is exactly the caller
//! that could not see recovered rows at all before these seams existed.

use forensic_rs::prelude::testing::{InMemoryForensicDb, InMemoryTable};
use forensic_rs::prelude::*;

fn users_table() -> InMemoryTable {
    InMemoryTable::new("Users")
        .with_column("Name", ForensicColumnType::Text, false)
        .with_column("Age", ForensicColumnType::I32, false)
        .with_row(vec![
            ForensicValue::Text("Alice".into()),
            ForensicValue::I64(42),
        ])
}

fn users_table_with_deleted() -> InMemoryTable {
    users_table().with_deleted_row(
        vec![
            ForensicValue::Text("Mallory".into()),
            ForensicValue::I64(31),
        ],
        7,
        3,
    )
}

/// A backend with nothing to recover must say so, rather than leaving a
/// caller to find out by calling and getting an empty result.
#[test]
fn a_backend_without_recovery_reports_none() {
    let db = InMemoryForensicDb::new().with_table(users_table());
    let db: &dyn ForensicDb = &db;
    assert!(db.as_recovery().is_none());
}

/// The whole point of the probe: recovery is discoverable through the base
/// trait object, without knowing the concrete backend type.
#[test]
fn recovery_is_discoverable_through_a_trait_object() {
    let db = InMemoryForensicDb::new().with_table(users_table_with_deleted());
    let db: &dyn ForensicDb = &db;

    let recovery = db
        .as_recovery()
        .expect("backend with deleted rows must advertise recovery");
    let mut rows = recovery.recovered_rows("Users").unwrap();
    assert!(rows.next().unwrap());
    assert_eq!(
        rows.read_named("Name").unwrap(),
        ForensicValue::Text("Mallory".into())
    );
    assert!(!rows.next().unwrap());
}

/// A recovered row must never appear in an ordinary table scan: the
/// allocated view and the recovered view are different claims about the
/// evidence and must not be conflated.
#[test]
fn recovered_rows_do_not_leak_into_an_ordinary_table_scan() {
    let db = InMemoryForensicDb::new().with_table(users_table_with_deleted());
    let db: &dyn ForensicDb = &db;

    let table = db.table("Users").unwrap();
    assert_eq!(table.row_count(), Some(1));
    let mut rows = table.iter_rows().unwrap();
    assert!(rows.next().unwrap());
    assert_eq!(
        rows.read_named("Name").unwrap(),
        ForensicValue::Text("Alice".into())
    );
    assert!(!rows.next().unwrap(), "the deleted row must not be scanned");
}

/// The defaults must describe an allocated read, so a backend that knows
/// nothing about recovery never accidentally understates its confidence.
#[test]
fn an_allocated_cursor_reports_the_defaults() {
    let db = InMemoryForensicDb::new().with_table(users_table_with_deleted());
    let table = db.table("Users").unwrap();
    let mut rows = table.iter_rows().unwrap();
    assert!(rows.next().unwrap());

    assert!(rows.allocated());
    assert_eq!(rows.recovery(), Recovery::Allocated);
    assert_eq!(rows.locus(), None);
}

#[test]
fn a_recovered_cursor_reports_its_recovery_and_address() {
    let db = InMemoryForensicDb::new().with_table(users_table_with_deleted());
    let recovery = db.as_recovery().unwrap();
    let mut rows = recovery.recovered_rows("Users").unwrap();
    assert!(rows.next().unwrap());

    assert!(!rows.allocated());
    assert_eq!(rows.recovery(), Recovery::DeletedMetadata);
    assert_eq!(rows.locus(), Some(Locus::Record { page: 7, slot: 3 }));
}

/// The default body of `recovery()` is derived from `allocated()`, so a
/// backend that overrides only the boolean still reports a truthful
/// `Recovery` instead of the `Allocated` a bare default would claim.
#[test]
fn recovery_defaults_consistently_with_allocated() {
    struct DeletedOnly;
    impl ForensicRows for DeletedOnly {
        fn column_count(&self) -> usize {
            0
        }
        fn column_name(&self, _i: usize) -> Option<&str> {
            None
        }
        fn column_names(&self) -> Vec<&str> {
            Vec::new()
        }
        fn column_type(&self, _i: usize) -> ForensicColumnType {
            ForensicColumnType::Null
        }
        fn next(&mut self) -> ForensicResult<bool> {
            Ok(false)
        }
        fn read_ref(&self, _i: usize) -> ForensicResult<ForensicValueRef<'_>> {
            Err(ForensicError::no_more_data())
        }
        // Deliberately the only override.
        fn allocated(&self) -> bool {
            false
        }
    }

    let rows: &dyn ForensicRows = &DeletedOnly;
    assert_eq!(rows.recovery(), Recovery::DeletedMetadata);
    assert_ne!(rows.recovery(), Recovery::Allocated);
}

/// A row's byte address is what gives it a timeline identity distinct from
/// the allocated read of the same structure. Without one, every row collapses
/// onto `Locus::Api` and the two dedupe into a single event.
#[test]
fn a_recovered_rows_locus_yields_a_distinct_event_id() {
    let key = SourceKey::Path("C:/db.dat".to_string());

    let db = InMemoryForensicDb::new().with_table(users_table_with_deleted());
    let recovery = db.as_recovery().unwrap();
    let mut recovered = recovery.recovered_rows("Users").unwrap();
    assert!(recovered.next().unwrap());
    let recovered_locus = recovered.locus().expect("recovered row must be addressable");

    let table = db.table("Users").unwrap();
    let mut allocated = table.iter_rows().unwrap();
    assert!(allocated.next().unwrap());
    let allocated_locus = allocated.locus().unwrap_or(Locus::Api);

    let recovered_id = EventId::new("host1", &key, recovered_locus, "created");
    let allocated_id = EventId::new("host1", &key, allocated_locus, "created");
    assert_ne!(recovered_id, allocated_id);

    // ...and the same locus is stable across reads, so a re-run dedupes.
    assert_eq!(
        recovered_id,
        EventId::new("host1", &key, recovered_locus, "created")
    );
}

/// The capability's optional methods default to "nothing to report" rather
/// than to an error, so a caller can ask every backend uniformly.
#[test]
fn unsupported_recovery_kinds_default_to_an_empty_cursor() {
    let db = InMemoryForensicDb::new().with_table(users_table_with_deleted());
    let recovery = db.as_recovery().unwrap();

    let mut slack = recovery.slack_rows("Users").unwrap();
    assert!(!slack.next().unwrap());
    assert_eq!(slack.column_count(), 0);

    let mut history = recovery.row_history("Users").unwrap();
    assert!(!history.next().unwrap());
}

#[test]
fn empty_rows_terminates_immediately_and_has_no_columns() {
    let mut rows = EmptyRows;
    assert_eq!(rows.column_count(), 0);
    assert!(rows.column_names().is_empty());
    assert_eq!(rows.column_name(0), None);
    assert!(!rows.next().unwrap());
    assert!(rows.read_ref(0).is_err());
}

/// Authorization decides *which* rows are visible; it must never relabel
/// where the visible ones came from. A wrapper that inherited the
/// `ForensicRows` defaults instead of forwarding them would silently
/// upgrade a recovered row to "allocated", inflating its confidence at the
/// boundary.
#[test]
fn the_authorization_wrapper_does_not_relabel_rows() {
    use std::sync::Arc;

    let inner = InMemoryForensicDb::new().with_table(users_table_with_deleted());
    let guarded = AuthorizedForensicDb::new(
        Box::new(inner),
        Arc::new(AllowAllPolicy),
        AccessContext::new("analyst-42", "acme"),
        "db",
    );

    let table = guarded.table("Users").unwrap();
    let mut rows = table.iter_rows().unwrap();
    assert!(rows.next().unwrap());
    assert!(rows.allocated());
    assert_eq!(rows.recovery(), Recovery::Allocated);
    assert_eq!(rows.locus(), None);

    // Recovery itself is deliberately not exposed through the authorization
    // boundary yet: recovered rows bypass the per-table gate, so the wrapper
    // must report `None` rather than pass an ungated capability through.
    let guarded_dyn: &dyn ForensicDb = &guarded;
    assert!(guarded_dyn.as_recovery().is_none());
}

#[test]
fn db_and_rows_trait_objects_stay_object_safe() {
    fn accepts_db(_db: &dyn ForensicDb) {}
    fn accepts_recovery(_r: &dyn RecoverRows) {}
    fn accepts_rows(_rows: &dyn ForensicRows) {}

    let db = InMemoryForensicDb::new().with_table(users_table_with_deleted());
    accepts_db(&db);
    accepts_recovery(db.as_recovery().unwrap());
    accepts_rows(&EmptyRows);
}

/// An ordinary allocated-read cursor has not run a recovery scan, so it must
/// report no scan diagnostics at all — a `Some` here from a cursor that
/// never scanned anything would be a fabricated report.
#[test]
fn an_ordinary_cursor_reports_no_scan_diagnostics() {
    let db = InMemoryForensicDb::new().with_table(users_table_with_deleted());
    let table = db.table("Users").unwrap();
    let mut rows = table.iter_rows().unwrap();
    assert!(rows.next().unwrap());
    assert_eq!(rows.scan_report(), None);
}

/// A cursor backing a real recovery scan can report what it found and did
/// with it — the counts two independent crates were computing by hand with
/// nowhere to put them before `RecoveryReport` existed.
#[test]
fn a_recovery_cursor_can_round_trip_its_scan_report() {
    struct ScannedSlack;
    impl ForensicRows for ScannedSlack {
        fn column_count(&self) -> usize {
            0
        }
        fn column_name(&self, _i: usize) -> Option<&str> {
            None
        }
        fn column_names(&self) -> Vec<&str> {
            Vec::new()
        }
        fn column_type(&self, _i: usize) -> ForensicColumnType {
            ForensicColumnType::Null
        }
        fn next(&mut self) -> ForensicResult<bool> {
            Ok(false)
        }
        fn read_ref(&self, _i: usize) -> ForensicResult<ForensicValueRef<'_>> {
            Err(ForensicError::no_more_data())
        }
        fn allocated(&self) -> bool {
            false
        }
        fn scan_report(&self) -> Option<RecoveryReport> {
            Some(RecoveryReport {
                units_scanned: 224,
                candidates_found: 9,
                admitted: 3,
                rejected: 6,
                unreadable: 0,
            })
        }
    }

    let rows: &dyn ForensicRows = &ScannedSlack;
    let report = rows.scan_report().expect("a scan actually ran");
    assert_eq!(report.units_scanned, 224);
    assert_eq!(report.admitted + report.rejected, report.candidates_found);
}
