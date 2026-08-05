//! Field-level provenance for the rare fields whose derivation genuinely
//! differs from their parent artifact — in practice, timestamps: `$SI` vs
//! `$FN` vs `$UsnJrnl` for the same file is the whole timestomping analysis.

use super::ids::ProvenanceId;
use super::model::MergeReason;
use super::store::ProvenanceStore;

/// A value paired with the [`ProvenanceId`] describing how it specifically
/// came to exist — distinct from whatever provenance the artifact it lives on
/// carries as a whole.
///
/// Deliberately does **not** implement `Deref`/`DerefMut`. If `*tracked`
/// compiled, `let t = *entry.modified;` would silently discard the
/// provenance with no diagnostic. Use the explicitly-named
/// [`Tracked::into_untracked`] instead, so discarding provenance reads as a
/// deliberate choice in review — see `tests/compile_fail/tracked_no_deref.rs`.
///
/// ## Composing with [`crate::utils::time::TimestampFlags`]
///
/// `Tracked<ForensicTimestamp>` is the intended use for the "which timestamp
/// source do I trust" case above, and it composes cleanly with
/// `ForensicTimestamp`'s own [`crate::utils::time::TimestampFlags`] rather
/// than duplicating it: `TimestampFlags` answers *how the value is encoded*
/// (precision, source format, APPROXIMATE/INFERRED/TRUNCATED/NORMALIZED) — a
/// property of the value itself, unchanged by wrapping it. `Tracked`'s
/// `ProvenanceId` answers *where the containing structure was found and how
/// it was acquired/recovered* — resolved via a [`ProvenanceStore`] into
/// [`super::Acquisition`]/[`super::Recovery`]/lineage/[`super::Confidence`]. A
/// `$SI` and a `$FN` `LastModified` timestamp on the same MFT record can
/// carry **identical** `TimestampFlags` (both `WindowsFiletime`,
/// `HundredNanoseconds` precision) while having **different** `ProvenanceId`s,
/// if, say, the `$FN` attribute was recovered from slack while `$SI` was
/// allocated.
#[derive(Debug, Clone)]
pub struct Tracked<T> {
    value: T,
    prov: ProvenanceId,
}

impl<T> Tracked<T> {
    /// Attaches a [`ProvenanceId`] you already legitimately obtained to a
    /// value. This does not weaken the forgery guarantee — you still can't
    /// manufacture the `ProvenanceId` itself, only attach one you hold.
    pub fn new(value: T, prov: ProvenanceId) -> Self {
        Self { value, prov }
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn provenance(&self) -> ProvenanceId {
        self.prov
    }

    /// The only way to get the bare `T` back out. Named explicitly so
    /// discarding provenance is visible at the call site.
    pub fn into_untracked(self) -> T {
        self.value
    }

    /// A pure transformation of the same underlying value — the provenance
    /// carries over unchanged, since nothing new was derived.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Tracked<U> {
        Tracked {
            value: f(self.value),
            prov: self.prov,
        }
    }

    /// Like [`Option::and_then`]/[`Result::and_then`]: `f` produces a whole
    /// new `Tracked<U>`, so its provenance fully replaces `self`'s. Use this
    /// when the closure derives a new value via the store itself (e.g. calling
    /// `store.derive(..)` internally) rather than merely transforming in place.
    pub fn and_then<U>(self, f: impl FnOnce(T) -> Tracked<U>) -> Tracked<U> {
        f(self.value)
    }

    /// Combines two *different* tracked instances into one. Unlike `map`/
    /// `and_then`, this is a real derivation event with two parents, so it
    /// requires the store to mint a proper merge node rather than silently
    /// picking one side's provenance.
    pub fn zip<U>(
        self,
        other: Tracked<U>,
        store: &ProvenanceStore,
        reason: MergeReason,
    ) -> Tracked<(T, U)> {
        let merged = store.merge(&[self.prov, other.prov], reason);
        Tracked {
            value: (self.value, other.value),
            prov: merged,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::model::{Acquisition, Recovery, SourceKey};

    fn store_and_id() -> (ProvenanceStore, ProvenanceId) {
        let store = ProvenanceStore::new();
        let source = store.register_source(SourceKey::Synthetic("test".to_string()));
        let id = source.mint(Acquisition::ImageRead, Recovery::Allocated);
        (store, id)
    }

    #[test]
    fn map_preserves_provenance() {
        let (_store, id) = store_and_id();
        let tracked = Tracked::new(41, id).map(|v| v + 1);
        assert_eq!(*tracked.value(), 42);
        assert_eq!(tracked.provenance(), id);
    }

    #[test]
    fn into_untracked_returns_bare_value() {
        let (_store, id) = store_and_id();
        let tracked = Tracked::new("hello", id);
        assert_eq!(tracked.into_untracked(), "hello");
    }

    #[test]
    fn zip_mints_a_merge_node_retaining_both_parents() {
        let (store, id_a) = store_and_id();
        let source_b = store.register_source(SourceKey::Synthetic("other".to_string()));
        let id_b = source_b.mint(Acquisition::LiveApi, Recovery::Carved);

        let left = Tracked::new(1, id_a);
        let right = Tracked::new(2, id_b);
        let zipped = left.zip(right, &store, MergeReason::CrossSourceCorroboration);
        assert_eq!(*zipped.value(), (1, 2));
        assert_ne!(zipped.provenance(), id_a);
        assert_ne!(zipped.provenance(), id_b);
    }
}
