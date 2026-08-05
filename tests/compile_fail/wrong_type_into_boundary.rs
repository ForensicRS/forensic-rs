// `ForensicData::new`'s third parameter is the pipeline's real enforcement
// boundary in this codebase (provenance fields live directly on
// `ForensicData`, not behind a separate generic `HasProvenance` trait): only
// a genuinely minted `ProvenanceId` can occupy that position, not a bare
// integer.
fn main() {
    let _data = forensic_rs::data::ForensicData::new(
        "host",
        forensic_rs::artifact::Artifact::Unknown,
        42u32,
    );
}
