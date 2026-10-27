//! The [`Locus`] of a memory record exported as [`ForensicData`].

use crate::data::ForensicData;
use crate::dictionary::{MEMORY_PA, MEMORY_SPACE, MEMORY_VA};
use crate::field::Field;
use crate::provenance::Locus;

/// An address field: a `"0x…"` string (the dictionary's form) or an integer.
fn address(data: &ForensicData, name: &str) -> Option<u64> {
    match data.field(name)? {
        Field::U64(v) => Some(*v),
        Field::Text(t) => {
            let hex = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X"))?;
            u64::from_str_radix(hex, 16).ok()
        }
        _ => None,
    }
}

/// Where a memory record was read from: [`Locus::Memory`] from its `memory.space` and
/// `memory.va`, else [`Locus::Physical`] from `memory.pa`, else [`Locus::Api`] (no byte locus: an
/// OS fact, a value assembled from several structures).
///
/// For [`TimelineRecordSink::with_locus`](crate::pipeline::timeline::TimelineRecordSink::with_locus):
/// the records of one capture usually share a source, so only their locus tells their events
/// apart.
pub fn record_locus(data: &ForensicData) -> Locus {
    let space = address(data, MEMORY_SPACE).and_then(|s| u32::try_from(s).ok());
    match (space, address(data, MEMORY_VA), address(data, MEMORY_PA)) {
        (Some(space), Some(va), _) => Locus::Memory { space, va },
        (_, _, Some(pa)) => Locus::Physical { pa },
        _ => Locus::Api,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::Artifact;
    use crate::provenance::{Acquisition, ProvenanceStore, Recovery, SourceKey};

    fn record(fields: &[(&'static str, Field)]) -> ForensicData {
        let store = ProvenanceStore::new();
        let source = store.register_source(SourceKey::Synthetic("capture".into()));
        let mut d = ForensicData::new(
            "host",
            Artifact::Unknown,
            source.mint(Acquisition::Memory, Recovery::Allocated),
        );
        for (name, value) in fields {
            d.insert((*name).into(), value.clone());
        }
        d
    }

    #[test]
    fn memory_then_physical_then_api() {
        let va = Field::Text("0xffffc58a1d2e3080".into());
        assert_eq!(
            record_locus(&record(&[
                (MEMORY_SPACE, Field::U64(0)),
                (MEMORY_VA, va.clone())
            ])),
            Locus::Memory {
                space: 0,
                va: 0xffff_c58a_1d2e_3080
            }
        );
        // A VA without its space is not a locus; the physical address is.
        assert_eq!(
            record_locus(&record(&[(MEMORY_VA, va), (MEMORY_PA, Field::U64(0x1000))])),
            Locus::Physical { pa: 0x1000 }
        );
        assert_eq!(
            record_locus(&record(&[(MEMORY_VA, Field::Text("not hex".into()))])),
            Locus::Api
        );
        assert_eq!(record_locus(&record(&[])), Locus::Api);
    }
}
