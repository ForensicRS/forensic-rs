//! Provenance: distinguishing an allocated `$STANDARD_INFORMATION` read from
//! disk from the same fact recovered out of unallocated space, `$I30` slack,
//! `$UsnJrnl`, or a live Win32 API call.
//!
//! `"file X modified at T"` looks identical downstream no matter which of
//! those produced it — but they carry very different evidentiary weight, and
//! a timeline that can't distinguish them presents inference with the same
//! authority as a direct read. This module makes that distinction a type-level
//! property instead of tribal knowledge, and enforces it mechanically: a
//! [`ProvenanceId`] can only be obtained by minting one against a
//! [`SourceHandle`] (via [`ProvenanceStore::register_source`]) or deriving/
//! merging an existing one through [`ProvenanceStore`] — there is no public
//! constructor for [`Provenance`] itself.
//!
//! # The pieces
//!
//! - [`Acquisition`] / [`Recovery`] — two independent axes: how the bytes
//!   were obtained, and how the structure was located within them.
//! - [`Locus`] — where, structurally, within the source (an exact MFT entry,
//!   hive cell, evtx record, ...). Instance-level, not interned — see its
//!   own documentation for why it isn't part of [`Provenance`] itself.
//! - [`ProvenanceStore`] / [`SourceHandle`] — the interning arena and the
//!   only legitimate mint/derive/merge path.
//! - [`Confidence`] — computed, never stored, from a chain's weakest link.
//! - [`Anomalies`] / [`AnomalyFlags`] — cheap, always-present, per-instance
//!   flags for cross-family divergence/corruption signals.
//! - [`Tracked<T>`] — field-level provenance for the rare fields (in
//!   practice: timestamps) whose derivation differs from their parent
//!   artifact's.
//! - [`Parsed<T>`] — a value plus its anomalies plus its provenance, for
//!   producers that want divergence to travel as data rather than as `Err`.
//!
//! This module ships types, the store, and the enforcement mechanism only —
//! no artifact parsers, and no family-specific anomaly kinds. Those are
//! deliberately out of scope; see the design discussion this module was
//! built from.

mod anomalies;
mod confidence;
mod ids;
mod model;
mod parsed;
#[cfg(feature = "serde")]
mod serde_support;
mod store;
mod tracked;

pub use anomalies::{AnomalyDetail, AnomalyFlags, Anomalies};
pub use confidence::Confidence;
pub use ids::{ProvenanceId, SourceId};
pub use model::{
    Acquisition, DerivedFrom, Locus, MergeReason, Provenance, ProvenanceSnapshot, Recovery,
    SourceKey,
};
pub use parsed::Parsed;
#[cfg(feature = "serde")]
pub use serde_support::{expand, ExpandedDerivedFrom, ExpandedProvenance, ProvenanceSideTable};
pub use store::{ProvenanceStore, SourceHandle};
pub use tracked::Tracked;
