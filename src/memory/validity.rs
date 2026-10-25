//! Whether bytes read from memory evidence are real, and if not, why.
//!
//! A memory capture never holds the whole address space: pages are paged out, compressed, never
//! captured, or simply invalid. A read therefore never returns bare bytes. It returns a
//! [`ReadReport`] saying, run by run, how each byte was obtained, so missing data is never
//! mistaken for zeros.

/// The state of one page (and so of every byte read from it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "state", rename_all = "snake_case"))]
pub enum Validity {
    /// Read from the capture, including pages on the standby/modified lists.
    Resident,
    /// Not in RAM at capture time. `data` says whether the bytes were recovered from the backing
    /// store (a supplied pagefile, a mapped file) or are unavailable.
    Paged { backing: Backing, data: bool },
    /// In the OS's compressed store. `decompressed` says whether the bytes were recovered.
    Compressed { decompressed: bool },
    /// The physical address lies outside the captured ranges.
    NotCaptured,
    /// No data exists: an invalid or demand-zero page, or an unreadable structure.
    Invalid,
}

impl Validity {
    /// Whether the bytes are real data from the evidence (resident, or recovered from a backing
    /// or the compressed store), rather than filler.
    pub const fn has_data(self) -> bool {
        matches!(
            self,
            Validity::Resident
                | Validity::Paged { data: true, .. }
                | Validity::Compressed { decompressed: true }
        )
    }

    /// A total "how bad" order: `Resident` < recovered data < unavailable paged/compressed <
    /// `NotCaptured` < `Invalid`. Ties within a rank are broken deterministically.
    fn badness(self) -> (u8, u8) {
        match self {
            Validity::Resident => (0, 0),
            Validity::Paged {
                backing,
                data: true,
            } => (1, backing.rank()),
            Validity::Compressed { decompressed: true } => (1, 8),
            Validity::Paged {
                backing,
                data: false,
            } => (2, backing.rank()),
            Validity::Compressed {
                decompressed: false,
            } => (2, 8),
            Validity::NotCaptured => (3, 0),
            Validity::Invalid => (4, 0),
        }
    }

    /// The worse of two validities, for a value built from several pages: a record is only as
    /// trustworthy as its worst field.
    pub fn worst(self, other: Validity) -> Validity {
        if other.badness() > self.badness() {
            other
        } else {
            self
        }
    }
}

/// The store a paged-out page lives in.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Backing {
    PageFile,
    SwapFile,
    MappedFile,
    Unknown,
}

impl Backing {
    const fn rank(self) -> u8 {
        match self {
            Backing::PageFile => 0,
            Backing::SwapFile => 1,
            Backing::MappedFile => 2,
            Backing::Unknown => 3,
        }
    }
}

/// How the bytes of one read were obtained: a run list of `(len, Validity)` covering exactly the
/// requested range, in order.
///
/// Bytes whose validity has no data ([`Validity::has_data`] is false) are zero-filled in the
/// caller's buffer, and this report is the only way to tell them from real zeros.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReadReport {
    runs: Vec<(u64, Validity)>,
}

impl ReadReport {
    pub fn new() -> Self {
        Self::default()
    }

    /// A report for a read whose bytes all share one validity.
    pub fn uniform(len: u64, validity: Validity) -> Self {
        let mut report = Self::new();
        report.push(len, validity);
        report
    }

    /// Appends `len` bytes of `validity`, merging with the last run when it has the same
    /// validity. Zero-length runs are ignored.
    pub fn push(&mut self, len: u64, validity: Validity) {
        if len == 0 {
            return;
        }
        match self.runs.last_mut() {
            Some((last_len, last)) if *last == validity => *last_len = last_len.saturating_add(len),
            _ => self.runs.push((len, validity)),
        }
    }

    /// Appends every run of `other`.
    pub fn extend(&mut self, other: &ReadReport) {
        for &(len, validity) in &other.runs {
            self.push(len, validity);
        }
    }

    pub fn runs(&self) -> &[(u64, Validity)] {
        &self.runs
    }

    /// The number of bytes the report covers. Equals the length of the read it describes.
    pub fn total_len(&self) -> u64 {
        self.runs
            .iter()
            .fold(0u64, |acc, (len, _)| acc.saturating_add(*len))
    }

    /// The worst validity in the report, or `None` for an empty read.
    pub fn worst(&self) -> Option<Validity> {
        self.runs.iter().map(|(_, v)| *v).reduce(Validity::worst)
    }

    /// Every byte was resident.
    pub fn is_fully_resident(&self) -> bool {
        self.runs.iter().all(|(_, v)| *v == Validity::Resident)
    }

    /// Every byte is real data ([`Validity::has_data`]).
    pub fn has_all_data(&self) -> bool {
        self.runs.iter().all(|(_, v)| v.has_data())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worst_is_a_total_order() {
        let all = [
            Validity::Resident,
            Validity::Paged {
                backing: Backing::PageFile,
                data: true,
            },
            Validity::Compressed { decompressed: true },
            Validity::Paged {
                backing: Backing::Unknown,
                data: false,
            },
            Validity::Compressed {
                decompressed: false,
            },
            Validity::NotCaptured,
            Validity::Invalid,
        ];
        for a in all {
            for b in all {
                assert_eq!(a.worst(b), b.worst(a), "{a:?} vs {b:?}");
            }
            assert_eq!(a.worst(Validity::Resident), a);
            assert_eq!(a.worst(Validity::Invalid), Validity::Invalid);
        }
    }

    #[test]
    fn has_data() {
        assert!(Validity::Resident.has_data());
        assert!(!Validity::NotCaptured.has_data());
        assert!(
            !Validity::Paged {
                backing: Backing::PageFile,
                data: false
            }
            .has_data()
        );
    }

    #[test]
    fn report_coalesces_and_sums() {
        let mut r = ReadReport::new();
        r.push(0x800, Validity::Resident);
        r.push(0x800, Validity::Resident);
        r.push(0, Validity::Invalid);
        r.push(0x1000, Validity::NotCaptured);
        assert_eq!(
            r.runs(),
            &[
                (0x1000, Validity::Resident),
                (0x1000, Validity::NotCaptured)
            ]
        );
        assert_eq!(r.total_len(), 0x2000);
        assert_eq!(r.worst(), Some(Validity::NotCaptured));
        assert!(!r.is_fully_resident());
        assert_eq!(ReadReport::new().worst(), None);
    }
}
