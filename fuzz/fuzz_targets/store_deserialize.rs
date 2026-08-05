#![no_main]

use forensic_rs::provenance::{Anomalies, ProvenanceSideTable, ProvenanceStore};
use libfuzzer_sys::fuzz_target;

// Exercises the one path in the provenance model that will eventually see
// attacker-influenced bytes: rebuilding a store from a serialized side table.
// A malformed table can contain out-of-bounds source indices or a cyclic
// `derived_from` chain; neither must panic, hang, or allocate unboundedly.
//
// `from_side_table` itself does no validation (see its doc comment) — the
// guarantee under test is that `confidence()` and `to_side_table()` degrade
// gracefully (to `Confidence::Unknown` / a merely-different-looking table)
// instead of misbehaving when actually walking a store built from untrusted
// input.
fuzz_target!(|data: &[u8]| {
    let Ok(table) = serde_json::from_slice::<ProvenanceSideTable>(data) else {
        return;
    };
    let store = ProvenanceStore::from_side_table(table);
    for id in store.provenance_ids() {
        let _ = store.confidence(id, &Anomalies::default());
    }
    // Round-trip once more — must not panic even over a malformed store.
    let _ = store.to_side_table("fuzz", 1);
});
