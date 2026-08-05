#![allow(unreachable_code)]
// `Provenance` has no public fields and no public constructor — the only way
// to obtain a `ProvenanceId` pointing at one is through `SourceHandle::mint`,
// `ProvenanceStore::derive`, or `ProvenanceStore::merge`. Constructing one
// directly via struct literal must not compile, from outside the crate.
fn main() {
    let _provenance = forensic_rs::provenance::Provenance {
        source: unimplemented!(),
        acquisition: unimplemented!(),
        recovery: unimplemented!(),
        derived_from: unimplemented!(),
    };
}
