// `ProvenanceId`'s only field is `pub(super)` (visible within
// `crate::provenance` only) — constructing one directly, bypassing
// `SourceHandle::mint`/`ProvenanceStore::derive`/`ProvenanceStore::merge`,
// must not compile from outside the crate.
fn main() {
    let _id = forensic_rs::provenance::ProvenanceId(0);
}
