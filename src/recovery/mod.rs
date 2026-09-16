//! Format-agnostic scaffolding for recovering deleted, slack, and carved
//! records — plus the soundness rules every implementer should inherit
//! instead of rediscovering.
//!
//! Two independent downstream crates have now built the same shape by hand:
//! `frnsc-hive` for deleted registry cells and an ESE parser for deleted
//! table rows. Both wrote free-space discovery and a strict-validation
//! admission gate from scratch, and both learned the same lesson the same
//! expensive way. What is generic lives here; what is format-specific —
//! knowing that *this* page layout means *that* record boundary — stays
//! downstream, where the format knowledge is.
//!
//! # The soundness checklist
//!
//! Recovery reads bytes that nothing vouches for. The framework cannot
//! enforce these for you, so they are stated once, here:
//!
//! 1. **Strict validation over recall.** A recovered record that is wrong is
//!    worse than one that is missing: an examiner can act on a gap, but a
//!    plausible-looking fabrication contaminates the analysis. When a
//!    candidate is ambiguous, reject it.
//!
//! 2. **Reject trivial content — "not `Nil`" is not an admission bar.** This
//!    is the specific bug both crates shipped and then fixed. A field that
//!    decodes to zero, an empty string, or an all-`0xFF` run is
//!    indistinguishable from unwritten padding that merely happens to parse.
//!    A decoder that succeeds proves the *bytes were parseable*, never that
//!    a record *was there*. Gate on content, with
//!    [`looks_like_padding`], not on decode success.
//!
//! 3. **Never guess a schema or a type against unattributed bytes.** Slack
//!    has no metadata saying which table, column, or version it belonged to.
//!    Applying a schema you inferred rather than read produces confident
//!    nonsense. If the region cannot be attributed, carve it as opaque bytes
//!    or leave it.
//!
//! 4. **Always attach a [`Recovery`], and a [`Locus`] where one exists.** A
//!    recovered value that travels without its recovery mode silently grades
//!    as trustworthy as an allocated read —
//!    [`Confidence`](crate::provenance::Confidence) is computed from the
//!    provenance chain, so an unlabelled recovery *is* a false claim of
//!    confidence. [`Recovered<T>`] exists to make attaching both the path of
//!    least resistance.
//!
//! 5. **A failed integrity check is a result, not an error.** A record from a
//!    chunk with a bad CRC is [`Recovery::DirtyChunk`], reported and graded
//!    down — not discarded, and not silently promoted.
//!
//! # What is here
//!
//! - [`Recovered<T>`] — a value with the recovery mode and byte address it
//!   was found at.
//! - [`slack_regions`] — the "used range vs. total range" complement, the
//!   arithmetic every slack scan needs.
//! - [`looks_like_padding`] — rule 2 as code rather than as prose.
//! - [`RecoveryReport`] — scan-level counters (units walked, candidates
//!   found/admitted/rejected) two independent crates computed by hand with
//!   nowhere to put them.

use crate::provenance::{Locus, Recovery};
use crate::traits::vfs::Region;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A value recovered from something other than live, allocated storage,
/// carrying how it was found and where.
///
/// Distinct from its two neighbours in [`crate::provenance`], which answer
/// different questions:
///
/// | Type | Answers |
/// |---|---|
/// | [`Recovered<T>`] | *How was this located, and at exactly which bytes?* |
/// | [`Parsed<T>`](crate::provenance::Parsed) | *What diverged while decoding it?* |
/// | [`Tracked<T>`](crate::provenance::Tracked) | *Which interned provenance chain does this field belong to?* |
///
/// The three compose: a recovered row's [`Recovery`] is what you pass to
/// [`SourceHandle::mint`](crate::provenance::SourceHandle::mint) or
/// [`ProvenanceStore::derive`](crate::provenance::ProvenanceStore::derive) to
/// obtain the `ProvenanceId` a `Tracked`/`Parsed` then carries, and its
/// [`Locus`] is what
/// [`EventId::new`](crate::pipeline::timeline::EventId::new) needs to give the
/// record a stable timeline identity distinct from the allocated read of the
/// same structure.
///
/// Deliberately no `Deref`, for the reason
/// [`Tracked`](crate::provenance::Tracked) has none: `let v = *recovered;`
/// would drop the recovery mode with no diagnostic, which is exactly the
/// silent confidence inflation rule 4 warns about. Use
/// [`Recovered::into_value`].
#[must_use = "this value was not read from allocated storage; attach its \
              `Recovery` to a provenance record instead of dropping it"]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Recovered<T> {
    value: T,
    recovery: Recovery,
    locus: Locus,
}

impl<T> Recovered<T> {
    /// Pairs a value with how it was located and where.
    ///
    /// Pass [`Locus::Api`] only when no byte address exists at all; for a
    /// carved region with no finer structure, [`Locus::RawOffset`] is the
    /// honest answer.
    pub fn new(value: T, recovery: Recovery, locus: Locus) -> Self {
        Self {
            value,
            recovery,
            locus,
        }
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn recovery(&self) -> Recovery {
        self.recovery
    }

    pub fn locus(&self) -> Locus {
        self.locus
    }

    /// The only way to get the bare `T` back. Named explicitly so discarding
    /// the recovery mode reads as a deliberate choice in review.
    pub fn into_value(self) -> T {
        self.value
    }

    /// A pure transformation of the same underlying value — recovery and
    /// locus carry over unchanged, since nothing new was located.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Recovered<U> {
        Recovered {
            value: f(self.value),
            recovery: self.recovery,
            locus: self.locus,
        }
    }
}

/// The regions of `total` not covered by any of `used` — the slack.
///
/// Parameterized over "used range" vs. "total range" rather than over any one
/// format, so it serves an ESE page's used space vs. page size, a directory
/// entry's record length vs. its allocated length, and a file's logical size
/// vs. its allocated size equally.
///
/// `used` entries may arrive unsorted, may overlap each other, and may extend
/// outside `total`; they are clipped, sorted, and merged first. The result is
/// disjoint, ascending by offset, and contains no zero-length regions. An
/// empty `used` yields `total` itself (unless `total` is empty).
///
/// ```
/// use forensic_rs::prelude::*;
///
/// let page = Region { offset: 0, length: 100 };
/// let used = [Region { offset: 0, length: 40 }, Region { offset: 60, length: 10 }];
/// assert_eq!(
///     slack_regions(page, &used),
///     vec![Region { offset: 40, length: 20 }, Region { offset: 70, length: 30 }],
/// );
/// ```
pub fn slack_regions(total: Region, used: &[Region]) -> Vec<Region> {
    let total_end = total.offset.saturating_add(total.length);
    if total.length == 0 {
        return Vec::new();
    }

    // Clip every used range into `total`, dropping the ones that fall
    // entirely outside it. A backend reporting a used range past the end of
    // its own container is a bug in that backend, but it must not corrupt
    // the slack it reports elsewhere.
    let mut clipped: Vec<(u64, u64)> = used
        .iter()
        .filter_map(|r| {
            let start = r.offset.max(total.offset);
            let end = r.offset.saturating_add(r.length).min(total_end);
            (start < end).then_some((start, end))
        })
        .collect();
    clipped.sort_unstable();

    let mut slack = Vec::new();
    let mut cursor = total.offset;
    for (start, end) in clipped {
        if start > cursor {
            slack.push(Region {
                offset: cursor,
                length: start - cursor,
            });
        }
        cursor = cursor.max(end);
    }
    if cursor < total_end {
        slack.push(Region {
            offset: cursor,
            length: total_end - cursor,
        });
    }
    slack
}

/// Whether `bytes` is indistinguishable from unwritten padding: shorter than
/// `min_len`, empty, all zero, or all `0xFF`.
///
/// This is checklist rule 2 as code. The trap it closes: a decoder that
/// returns a value rather than an error proves only that the bytes were
/// *parseable*, not that a record was ever written there — a run of zeros
/// decodes to a perfectly valid zero. Gate admission on this before believing
/// a candidate record, not on whether decoding succeeded.
///
/// A conservative filter, not a proof of absence: a genuinely all-zero record
/// that was really written is rejected too. That is the intended trade —
/// checklist rule 1 prefers a missing record over a fabricated one.
///
/// ```
/// use forensic_rs::prelude::*;
///
/// assert!(looks_like_padding(&[0, 0, 0, 0], 1));
/// assert!(looks_like_padding(&[0xFF; 16], 1));
/// assert!(looks_like_padding(b"hi", 8));      // below the caller's floor
/// assert!(!looks_like_padding(b"MZ\x90\x00", 1));
/// ```
pub fn looks_like_padding(bytes: &[u8], min_len: usize) -> bool {
    if bytes.len() < min_len || bytes.is_empty() {
        return true;
    }
    let first = bytes[0];
    (first == 0x00 || first == 0xFF) && bytes.iter().all(|&b| b == first)
}

/// Counters for one recovery scan: how much ground it covered and what it
/// did with what it found.
///
/// A recovered value's [`Recovery`]/[`Locus`] answer "is this one row
/// trustworthy, and where". This answers a different, scan-level question a
/// case report also needs: how hard did the scan look, and how much of what
/// it found did it actually admit. Two independent crates (an ESE table-row
/// carver and a registry hive-cell carver) computed exactly these counts by
/// hand and then had nowhere to report them — the fields here are that
/// information, named once instead of reinvented per backend. The specific
/// counter *names* are new; the underlying counts were already being kept
/// downstream before this type existed.
///
/// Deliberately plain `u64` counters, not a richer per-rejection-reason
/// breakdown: the reasons a candidate is rejected are format-specific (a
/// value too short, a checksum that failed, a schema mismatch), so a fixed
/// enumeration here would either be incomplete or grow one variant per
/// backend. A backend wanting reason-level detail reports it through
/// [`Finding`](crate::traits::forensic) or a domain-specific log, the same
/// place any other per-candidate detail goes; this type stays the one
/// scan-level shape every backend can fill in without guessing at fields it
/// doesn't have a meaning for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RecoveryReport {
    /// Units the scan walked — pages, registry bins, hive cells, whatever
    /// the format's own free-space layout is measured in. Not comparable
    /// across backends; comparable across two runs of the *same* backend.
    pub units_scanned: u64,
    /// Byte windows that looked plausible enough to attempt a decode.
    pub candidates_found: u64,
    /// Candidates that passed the admission gate and were returned.
    pub admitted: u64,
    /// Candidates rejected by the admission gate (checklist rules 1-3) —
    /// silently dropped from the result, not reported at lower confidence.
    pub rejected: u64,
    /// Units the scan could not read or parse at all (a bad checksum on the
    /// container itself, a truncated read) — distinct from `rejected`,
    /// which is a candidate the scan *did* read.
    pub unreadable: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(offset: u64, length: u64) -> Region {
        Region { offset, length }
    }

    #[test]
    fn recovered_carries_mode_and_locus_through_map() {
        let recovered = Recovered::new(21u32, Recovery::Slack, Locus::Record { page: 7, slot: 3 });
        let doubled = recovered.map(|v| v * 2);
        assert_eq!(*doubled.value(), 42);
        assert_eq!(doubled.recovery(), Recovery::Slack);
        assert_eq!(doubled.locus(), Locus::Record { page: 7, slot: 3 });
        assert_eq!(doubled.into_value(), 42);
    }

    #[test]
    fn no_used_ranges_leaves_the_whole_region_as_slack() {
        assert_eq!(slack_regions(region(0, 100), &[]), vec![region(0, 100)]);
    }

    #[test]
    fn fully_used_region_has_no_slack() {
        assert!(slack_regions(region(0, 100), &[region(0, 100)]).is_empty());
    }

    #[test]
    fn empty_total_has_no_slack() {
        assert!(slack_regions(region(50, 0), &[]).is_empty());
    }

    #[test]
    fn adjacent_used_ranges_do_not_produce_zero_length_slack() {
        let slack = slack_regions(region(0, 100), &[region(0, 50), region(50, 25)]);
        assert_eq!(slack, vec![region(75, 25)]);
        assert!(slack.iter().all(|r| r.length > 0));
    }

    #[test]
    fn overlapping_and_unsorted_used_ranges_are_merged_first() {
        let used = [region(60, 20), region(0, 30), region(20, 25)];
        assert_eq!(
            slack_regions(region(0, 100), &used),
            vec![region(45, 15), region(80, 20)]
        );
    }

    #[test]
    fn used_ranges_outside_total_are_clipped_not_trusted() {
        // A used range reaching past the container end must not shrink the
        // slack reported before it, nor produce a negative-length region.
        let used = [region(90, 1_000), region(0, 10)];
        assert_eq!(slack_regions(region(0, 100), &used), vec![region(10, 80)]);
        // Entirely outside: ignored.
        assert_eq!(
            slack_regions(region(0, 50), &[region(500, 10)]),
            vec![region(0, 50)]
        );
    }

    #[test]
    fn slack_respects_a_non_zero_total_offset() {
        let slack = slack_regions(region(1_000, 100), &[region(1_020, 30)]);
        assert_eq!(slack, vec![region(1_000, 20), region(1_050, 50)]);
    }

    #[test]
    fn padding_detection_rejects_zeros_and_ff_runs_but_not_content() {
        assert!(looks_like_padding(&[], 0));
        assert!(looks_like_padding(&[0x00; 32], 1));
        assert!(looks_like_padding(&[0xFF; 32], 1));
        assert!(!looks_like_padding(&[0x00, 0x01], 1));
        assert!(!looks_like_padding(&[0xFF, 0xFE], 1));
        assert!(!looks_like_padding(b"real record", 1));
    }

    #[test]
    fn padding_detection_enforces_the_callers_minimum_length() {
        assert!(looks_like_padding(b"abc", 8));
        assert!(!looks_like_padding(b"abcdefgh", 8));
    }
}
