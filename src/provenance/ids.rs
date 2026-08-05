//! Interned handles into a [`super::ProvenanceStore`].
//!
//! Both types are 4-byte `Copy` newtypes with no public constructor: the only
//! way to obtain one is through [`super::SourceHandle::mint`] or
//! [`super::ProvenanceStore::derive`]/[`super::ProvenanceStore::merge`], all of
//! which live in `store.rs`. No other module in this crate (or any downstream
//! crate) can construct a `ProvenanceId`/`SourceId` out of thin air.
//!
//! Neither type implements `Serialize`/`Deserialize`, even under the `serde`
//! feature. A bare id is meaningless without the [`super::ProvenanceStore`]
//! that resolves it, so there is deliberately no serialization path for one in
//! isolation — only [`super::ProvenanceStore::to_side_table`] (which takes the
//! store) and [`super::expand`] can turn provenance into serialized form. This
//! is enforced at compile time, not by convention: see
//! `tests/compile_fail/serialize_without_store.rs`.

/// A handle into a [`super::ProvenanceStore`], identifying one interned
/// [`super::Provenance`] record.
///
/// `Copy`, 4 bytes. Carries no meaning on its own — resolve it against the
/// [`super::ProvenanceStore`] it came from to inspect the actual provenance.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProvenanceId(pub(super) u32);

/// A handle into a [`super::ProvenanceStore`], identifying one interned
/// source identity (a path, a content hash, a volume offset, a container
/// chain, ...).
///
/// `Copy`, 4 bytes. Many [`ProvenanceId`]s can share the same `SourceId` —
/// that's the entire point of interning: a streaming parse producing a
/// million records from one file mints a million [`ProvenanceId`]s against a
/// single `SourceId`.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SourceId(pub(super) u32);

impl ProvenanceId {
    pub(super) const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    pub(super) const fn raw(self) -> u32 {
        self.0
    }
}

impl SourceId {
    pub(super) const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    pub(super) const fn raw(self) -> u32 {
        self.0
    }
}

const _: [(); 4] = [(); std::mem::size_of::<ProvenanceId>()];
const _: [(); 4] = [(); std::mem::size_of::<SourceId>()];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_four_bytes_and_copy() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<ProvenanceId>();
        assert_copy::<SourceId>();
        assert_eq!(std::mem::size_of::<ProvenanceId>(), 4);
        assert_eq!(std::mem::size_of::<SourceId>(), 4);
    }

    #[test]
    fn distinct_raw_values_are_distinct_ids() {
        assert_ne!(ProvenanceId::from_raw(0), ProvenanceId::from_raw(1));
        assert_eq!(ProvenanceId::from_raw(7).raw(), 7);
        assert_ne!(SourceId::from_raw(0), SourceId::from_raw(1));
        assert_eq!(SourceId::from_raw(7).raw(), 7);
    }
}
