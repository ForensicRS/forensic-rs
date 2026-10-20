//! The physical memory of a capture: the bottom of every memory backend.

use std::collections::BTreeMap;

use crate::err::ForensicResult;
use crate::field::{Field, Text};
use crate::utils::time::ForensicTimestamp;

use super::addr::{Pa, Va};
use super::validity::ReadReport;

/// One populated range of physical memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhysRange {
    pub start: Pa,
    pub len: u64,
    /// Where the range starts in the capture file, when the format stores it contiguously.
    pub file_offset: Option<u64>,
}

impl PhysRange {
    pub const fn new(start: Pa, len: u64) -> Self {
        Self {
            start,
            len,
            file_offset: None,
        }
    }

    /// One past the last address, or `None` when the range would end past the 64-bit space
    /// (a hostile header).
    pub const fn end(&self) -> Option<Pa> {
        self.start.checked_add(self.len)
    }

    pub fn contains(&self, pa: Pa) -> bool {
        match pa.offset_from(self.start) {
            Some(off) => off < self.len,
            None => false,
        }
    }
}

/// What the input format says about the capture.
///
/// Every hint is optional: a format that does not record something leaves it `None`, and it is
/// never filled with a default (a zero DTB or an epoch capture time would be fabricated
/// evidence).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MemoryInputInfo {
    /// The input format, e.g. `"raw"`, `"lime"`, `"crashdump.full"`.
    pub format: Text,
    /// The machine type the format records, e.g. `"x64"`.
    pub machine: Option<Text>,
    /// The page-table root of the kernel address space.
    pub dtb: Option<Pa>,
    pub kernel_base: Option<Va>,
    /// The OS build number.
    pub build: Option<u32>,
    pub processor_count: Option<u32>,
    pub capture_time: Option<ForensicTimestamp>,
    /// Format-specific hints under the format's own names (e.g. `"PsActiveProcessHead"`).
    pub extra: BTreeMap<Text, Field>,
}

impl MemoryInputInfo {
    pub fn new(format: impl Into<Text>) -> Self {
        Self {
            format: format.into(),
            ..Self::default()
        }
    }
}

/// The physical memory of one capture (a raw dump, LiME, a crash dump, a live connector).
///
/// Implementations are hostile-input parsers: they bounds-check everything and never panic.
pub trait PhysicalMemory: Send + Sync {
    /// Populated physical ranges, sorted and non-overlapping. Everything else is not captured.
    fn ranges(&self) -> &[PhysRange];

    /// Reads `buf.len()` bytes at `pa`. Bytes outside the captured ranges are zero-filled **and
    /// reported** as [`Validity::NotCaptured`](super::Validity::NotCaptured) in the returned
    /// report, which covers exactly `buf.len()` bytes. An `Err` means the backing itself failed
    /// (an I/O error), not that the address was missing.
    fn read_phys(&self, pa: Pa, buf: &mut [u8]) -> ForensicResult<ReadReport>;

    /// Zero-copy access when the backing allows it (a memory-mapped file) and the whole range is
    /// captured. `None` means "use `read_phys`".
    fn slice(&self, _pa: Pa, _len: usize) -> Option<&[u8]> {
        None
    }

    /// Format facts and the hints the format provides.
    fn info(&self) -> &MemoryInputInfo;

    /// `true` for live sources, whose reads are not repeatable. Results from a live source say
    /// so.
    fn is_live(&self) -> bool {
        false
    }
}
