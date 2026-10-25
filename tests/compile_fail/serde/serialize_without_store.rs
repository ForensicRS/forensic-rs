#![allow(unreachable_code)]
// A bare `ProvenanceId` is meaningless without the `ProvenanceStore` that
// resolves it, so it deliberately has no `Serialize` impl at all — the only
// provenance-aware serialization paths are `ProvenanceStore::to_side_table`
// and `provenance::expand`, both of which require the store as an argument.
fn main() {
    let id: forensic_rs::provenance::ProvenanceId = unimplemented!();
    let _ = serde_json::to_string(&id).unwrap();
}
