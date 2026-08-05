//! Instance-level anomaly tracking.
//!
//! Unlike [`super::Provenance`], anomalies can't be interned — they describe
//! *this specific instance* of data, not a reusable identity. `Vec<Anomaly>`
//! would cost 24 bytes even when empty (24 MB of nothing across a million
//! artifacts), so this uses a 4-byte bitflag plus a rare, optionally-boxed
//! detail payload instead.

use crate::provenance::confidence::Confidence;
use crate::scow::SCow;

/// A cross-family classification of what disagreed or failed a check.
///
/// Seeded with only cross-family kinds — anomaly kinds specific to one
/// artifact family (an `$MFT` fixup mismatch, a hive log-replay conflict, an
/// EVTX chunk CRC failure) belong with the parser that detects them, added as
/// new `#[non_exhaustive]` variants there, not partitioned into this bit
/// space with reused bit meanings (the same bit meaning different things
/// depending on [`super::Locus`] would be a correctness trap in serialized
/// output).
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct AnomalyFlags(u32);

impl AnomalyFlags {
    pub const NONE: Self = Self(0);
    /// A structural integrity check (checksum/hash/fixup) failed.
    pub const CHECKSUM_MISMATCH: Self = Self(1 << 0);
    /// A referenced record has since been reused for something else.
    pub const STALE_REFERENCE: Self = Self(1 << 1);
    /// A parent/link chain loops back on itself.
    pub const REFERENCE_CYCLE: Self = Self(1 << 2);
    /// Two sources disagree on whether something is allocated.
    pub const ALLOCATION_CONFLICT: Self = Self(1 << 3);
    /// Two metadata sources disagree on a timestamp for the same fact.
    pub const TIMESTAMP_DIVERGENCE: Self = Self(1 << 4);
    /// The structure ended before its declared length.
    pub const TRUNCATED: Self = Self(1 << 5);
    /// Mirrored/duplicated copies of the source disagree with each other.
    pub const SOURCE_DIVERGENCE: Self = Self(1 << 6);

    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Preserves bits this version of the crate doesn't know the meaning of
    /// — required for forward-compatible round-tripping of data written by a
    /// newer tool version.
    pub const fn from_bits_retain(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for AnomalyFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for AnomalyFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for AnomalyFlags {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

/// An elaboration of one flagged anomaly, kept out of the hot 4-byte
/// [`AnomalyFlags`] path since a message payload is the rare case.
#[derive(Debug, Clone)]
pub struct AnomalyDetail {
    /// Which single flag this detail elaborates.
    pub kind: AnomalyFlags,
    pub message: SCow,
}

/// Cheap, always-present anomaly tracking for one instance of data.
///
/// `size_of::<Anomalies>() == 16`: `flags` is a 4-byte bitfield, and `detail`
/// is a thin (8-byte, niche-optimized) `Box<Vec<AnomalyDetail>>` rather than a
/// `Box<[AnomalyDetail]>` (whose fat pointer alone would already be 16 bytes,
/// blowing the budget before `flags` is even added). `Anomalies::default()`
/// allocates nothing — the `Option` stays `None` until [`Anomalies::add_detail`]
/// is actually called.
#[derive(Debug, Clone, Default)]
pub struct Anomalies {
    flags: AnomalyFlags,
    // `Box<Vec<_>>`, not `Vec<_>`: the box keeps this field (and thus
    // `Option<_>`, via niche optimization) a thin 8-byte pointer, which is
    // what keeps `size_of::<Anomalies>() == 16` asserted below.
    #[allow(clippy::box_collection)]
    detail: Option<Box<Vec<AnomalyDetail>>>,
}

impl Anomalies {
    pub const fn empty() -> Self {
        Self {
            flags: AnomalyFlags::NONE,
            detail: None,
        }
    }

    pub fn flags(&self) -> AnomalyFlags {
        self.flags
    }

    pub fn has(&self, flag: AnomalyFlags) -> bool {
        self.flags.contains(flag)
    }

    pub fn details(&self) -> &[AnomalyDetail] {
        self.detail.as_deref().map(Vec::as_slice).unwrap_or(&[])
    }

    /// Sets a flag with no accompanying detail message.
    pub fn add(&mut self, flag: AnomalyFlags) {
        self.flags |= flag;
    }

    /// Sets a flag and records a human-readable elaboration for it.
    pub fn add_detail(&mut self, detail: AnomalyDetail) {
        self.flags |= detail.kind;
        self.detail.get_or_insert_with(|| Box::new(Vec::new())).push(detail);
    }

    /// Folds another instance's anomalies into this one: ORs the flags and
    /// appends the detail messages. Used when a record accumulates anomalies
    /// from more than one parsed value (e.g. multiple `set_parsed` calls).
    pub fn merge(&mut self, other: Anomalies) {
        self.flags |= other.flags;
        if let Some(mut other_detail) = other.detail {
            self.detail
                .get_or_insert_with(|| Box::new(Vec::new()))
                .append(&mut other_detail);
        }
    }

    /// The confidence ceiling implied purely by the anomalies present here,
    /// independent of any provenance chain. [`super::ProvenanceStore::confidence`]
    /// combines this with the chain-folded confidence by taking the minimum
    /// of the two — anomalies can only ever lower confidence, never raise it.
    pub fn confidence_ceiling(&self) -> Confidence {
        if self.flags.contains(AnomalyFlags::REFERENCE_CYCLE)
            || self.flags.contains(AnomalyFlags::ALLOCATION_CONFLICT)
        {
            Confidence::Unknown
        } else if !self.flags.is_empty() {
            Confidence::Low
        } else {
            Confidence::High
        }
    }
}

const _: [(); 16] = [(); std::mem::size_of::<Anomalies>()];
const _: [(); 4] = [(); std::mem::size_of::<AnomalyFlags>()];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_empty_and_allocates_nothing() {
        let anomalies = Anomalies::default();
        assert!(anomalies.flags().is_empty());
        assert!(anomalies.details().is_empty());
        assert_eq!(anomalies.confidence_ceiling(), Confidence::High);
    }

    #[test]
    fn merge_ors_flags_and_appends_details() {
        let mut a = Anomalies::empty();
        a.add(AnomalyFlags::TRUNCATED);
        let mut b = Anomalies::empty();
        b.add_detail(AnomalyDetail {
            kind: AnomalyFlags::CHECKSUM_MISMATCH,
            message: SCow::Borrowed("checksum failed"),
        });

        a.merge(b);

        assert!(a.has(AnomalyFlags::TRUNCATED));
        assert!(a.has(AnomalyFlags::CHECKSUM_MISMATCH));
        assert_eq!(a.details().len(), 1);
    }

    #[test]
    fn add_sets_flag_without_detail() {
        let mut anomalies = Anomalies::empty();
        anomalies.add(AnomalyFlags::TRUNCATED);
        assert!(anomalies.has(AnomalyFlags::TRUNCATED));
        assert!(anomalies.details().is_empty());
        assert_eq!(anomalies.confidence_ceiling(), Confidence::Low);
    }

    #[test]
    fn add_detail_sets_flag_and_stores_message() {
        let mut anomalies = Anomalies::empty();
        anomalies.add_detail(AnomalyDetail {
            kind: AnomalyFlags::CHECKSUM_MISMATCH,
            message: SCow::Borrowed("fixup signature mismatch"),
        });
        assert!(anomalies.has(AnomalyFlags::CHECKSUM_MISMATCH));
        assert_eq!(anomalies.details().len(), 1);
    }

    #[test]
    fn allocation_conflict_and_reference_cycle_degrade_to_unknown() {
        let mut anomalies = Anomalies::empty();
        anomalies.add(AnomalyFlags::ALLOCATION_CONFLICT);
        assert_eq!(anomalies.confidence_ceiling(), Confidence::Unknown);

        let mut anomalies = Anomalies::empty();
        anomalies.add(AnomalyFlags::REFERENCE_CYCLE);
        assert_eq!(anomalies.confidence_ceiling(), Confidence::Unknown);
    }

    #[test]
    fn from_bits_retain_preserves_unknown_future_bits() {
        let flags = AnomalyFlags::from_bits_retain(0xFFFF_FFFF);
        assert!(flags.contains(AnomalyFlags::TRUNCATED));
        assert_eq!(flags.bits(), 0xFFFF_FFFF);
    }
}
