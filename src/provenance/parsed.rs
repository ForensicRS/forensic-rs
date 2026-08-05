//! [`Parsed<T>`] — a container that lets divergence and corruption travel as
//! data alongside a value, rather than short-circuiting into `Err`.

use super::anomalies::Anomalies;
use super::ids::ProvenanceId;

/// A value, the anomalies observed while producing it, and the provenance it
/// was produced under.
///
/// `Err` stays reserved for "cannot proceed" — a cross-check that finds two
/// sources disagreeing about `value` returns the divergence via `anomalies`,
/// it does not silently pick one side and it does not fail the parse.
/// Governing principle: divergence is evidence, not error.
///
/// Fields are public — unlike [`super::Provenance`], there is nothing to
/// forge here: you still can't fabricate the [`ProvenanceId`] inside it,
/// only attach one you already legitimately hold.
#[must_use = "this carries anomalies observed while producing the value; \
              fold them into a record with `ForensicData::set_parsed` \
              instead of dropping them"]
#[derive(Debug, Clone)]
pub struct Parsed<T> {
    pub value: T,
    pub anomalies: Anomalies,
    pub provenance: ProvenanceId,
}

impl<T> Parsed<T> {
    pub fn new(value: T, provenance: ProvenanceId) -> Self {
        Self {
            value,
            anomalies: Anomalies::default(),
            provenance,
        }
    }

    pub fn with_anomalies(value: T, anomalies: Anomalies, provenance: ProvenanceId) -> Self {
        Self {
            value,
            anomalies,
            provenance,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::model::{Acquisition, Recovery, SourceKey};
    use crate::provenance::store::ProvenanceStore;

    #[test]
    fn new_carries_no_anomalies_by_default() {
        let store = ProvenanceStore::new();
        let source = store.register_source(SourceKey::Synthetic("test".to_string()));
        let id = source.mint(Acquisition::ImageRead, Recovery::Allocated);
        let parsed = Parsed::new(42, id);
        assert_eq!(parsed.value, 42);
        assert!(parsed.anomalies.flags().is_empty());
        assert_eq!(parsed.provenance, id);
    }
}
