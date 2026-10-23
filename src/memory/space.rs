//! Virtual address spaces: the kernel's, and one per process.

use crate::err::{ForensicError, ForensicResult};

use super::addr::{Pa, PageSize, Va};
use super::model::MemValue;
use super::validity::{Backing, ReadReport, Validity};

/// Identifies one address space within a [`MemoryImage`](super::MemoryImage). Opaque: its value
/// only means something to the backend that issued it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SpaceId(pub u32);

/// Why a virtual address has no translation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvalidReason {
    /// The entry is not present and carries no software state that locates the data.
    NotPresent,
    /// The address is outside the architecture's canonical range.
    NonCanonical,
    /// A page-table page on the walk could not be read.
    TableUnreadable,
    /// An entry has a combination of bits the architecture or OS does not allow.
    Malformed,
    /// The walk exceeded its depth bound (a cyclic or hostile table).
    DepthLimit,
}

/// The result of translating one virtual address.
///
/// Backends classify every state, even the ones they cannot resolve to bytes yet; a consumer
/// can always tell "paged out" from "never existed".
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Translation {
    /// A valid hardware mapping.
    Resident {
        pa: Pa,
        size: PageSize,
    },
    /// Not mapped by hardware, but still in RAM (standby/modified lists).
    Transition {
        pa: Pa,
    },
    /// Resolved through a prototype (shared) entry at `pte_va`.
    Prototype {
        pte_va: Va,
    },
    /// In a paging file: `file` is the OS's paging-file number and `offset` the byte offset in
    /// that file. [`PagingFiles`](super::PagingFiles) reads it when the file is supplied.
    PageFile {
        file: u8,
        offset: u64,
    },
    /// Not in RAM; the bytes are those of a mapped file at `offset`. `file` identifies the
    /// file within the backend and is opaque to consumers (equal keys, same file).
    FileBacked {
        file: u64,
        offset: u64,
    },
    /// In the OS's compressed store; `key` is opaque to consumers.
    Compressed {
        key: u64,
    },
    /// Allocated but never touched: reads as zeros, and no data exists.
    DemandZero,
    Invalid {
        reason: InvalidReason,
    },
}

impl Translation {
    /// The physical address of the byte, when the data is in RAM.
    pub fn pa(self) -> Option<Pa> {
        match self {
            Translation::Resident { pa, .. } | Translation::Transition { pa } => Some(pa),
            _ => None,
        }
    }

    /// The validity of a read through this translation when the backend does not resolve it
    /// further (an unresolved prototype, pagefile or compressed page).
    pub fn unresolved_validity(self) -> Validity {
        match self {
            Translation::Resident { .. } | Translation::Transition { .. } => Validity::Resident,
            Translation::Prototype { .. } => Validity::Paged {
                backing: Backing::Unknown,
                data: false,
            },
            Translation::PageFile { .. } => Validity::Paged {
                backing: Backing::PageFile,
                data: false,
            },
            Translation::FileBacked { .. } => Validity::Paged {
                backing: Backing::MappedFile,
                data: false,
            },
            Translation::Compressed { .. } => Validity::Compressed {
                decompressed: false,
            },
            Translation::DemandZero | Translation::Invalid { .. } => Validity::Invalid,
        }
    }
}

/// One virtual address space of a memory image.
pub trait AddressSpace: Send + Sync {
    fn id(&self) -> SpaceId;

    /// Pointer size in bytes (8 for x64, 4 for x86 and WOW64 views).
    fn pointer_size(&self) -> u8;

    /// The page-table root, when the architecture has one.
    fn dtb(&self) -> Option<Pa> {
        None
    }

    fn translate(&self, va: Va) -> ForensicResult<Translation>;

    /// Reads `buf.len()` bytes at `va`. Bytes without data are zero-filled and reported; the
    /// report covers exactly `buf.len()` bytes, with one validity per page or better.
    fn read(&self, va: Va, buf: &mut [u8]) -> ForensicResult<ReadReport>;
}

/// The longest string the bounded string readers will scan for a terminator.
pub const MAX_STRING_SCAN: usize = 0x1_0000;

/// The most bytes [`AddressSpaceExt::read_bytes`] allocates for one read. Lengths in memory
/// images are attacker-controlled, so a larger request is an error, not an allocation. Read
/// larger spans with [`AddressSpace::read`] into a buffer the caller owns and sized.
pub const MAX_READ: usize = 16 << 20;

/// A string read up to a bound. `truncated` is true when the bound cut it: no terminator within
/// the bound, or a counted length larger than [`MAX_STRING_SCAN`]. The value is then a prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bounded<T> {
    pub value: T,
    pub truncated: bool,
}

/// Typed reads over any [`AddressSpace`]. A value is `Known` only when every byte of it is real
/// data; otherwise it is `Unavailable` with the worst validity of its bytes.
pub trait AddressSpaceExt: AddressSpace {
    /// Reads `len` bytes and the report for them. `len` above [`MAX_READ`] is an error.
    fn read_bytes(&self, va: Va, len: usize) -> ForensicResult<(Vec<u8>, ReadReport)> {
        if len > MAX_READ {
            return Err(ForensicError::too_big(
                "memory read_bytes",
                len as u64,
                MAX_READ as u64,
            ));
        }
        let mut buf = vec![0u8; len];
        let report = self.read(va, &mut buf)?;
        Ok((buf, report))
    }

    fn read_u8(&self, va: Va) -> ForensicResult<MemValue<u8>> {
        read_le::<1>(self, va).map(|v| v.map(|b| b[0]))
    }

    fn read_u16(&self, va: Va) -> ForensicResult<MemValue<u16>> {
        read_le::<2>(self, va).map(|v| v.map(u16::from_le_bytes))
    }

    fn read_u32(&self, va: Va) -> ForensicResult<MemValue<u32>> {
        read_le::<4>(self, va).map(|v| v.map(u32::from_le_bytes))
    }

    fn read_u64(&self, va: Va) -> ForensicResult<MemValue<u64>> {
        read_le::<8>(self, va).map(|v| v.map(u64::from_le_bytes))
    }

    /// Reads a pointer of [`AddressSpace::pointer_size`] bytes.
    fn read_ptr(&self, va: Va) -> ForensicResult<MemValue<Va>> {
        if self.pointer_size() == 4 {
            Ok(self.read_u32(va)?.map(|p| Va::new(u64::from(p))))
        } else {
            Ok(self.read_u64(va)?.map(Va::new))
        }
    }

    /// Reads a NUL-terminated byte string of at most `max` bytes (capped at
    /// [`MAX_STRING_SCAN`]), without the terminator. A string with no terminator within the bound
    /// is the prefix up to the bound, marked [`Bounded::truncated`].
    fn read_cstr(&self, va: Va, max: usize) -> ForensicResult<MemValue<Bounded<Vec<u8>>>> {
        let max = max.min(MAX_STRING_SCAN);
        let (bytes, report) = self.read_bytes(va, max)?;
        let found = bytes.iter().position(|&b| b == 0);
        let end = found.unwrap_or(bytes.len());
        Ok(prefix_value(bytes, &report, end, 1).map(|value| Bounded {
            value,
            truncated: found.is_none(),
        }))
    }

    /// Reads a NUL-terminated UTF-16LE string of at most `max_units` code units (capped at
    /// [`MAX_STRING_SCAN`] bytes). Invalid surrogates are replaced (U+FFFD). A string with no
    /// terminator within the bound is marked [`Bounded::truncated`].
    fn read_utf16(&self, va: Va, max_units: usize) -> ForensicResult<MemValue<Bounded<String>>> {
        let max_bytes = max_units.saturating_mul(2).min(MAX_STRING_SCAN);
        let (bytes, report) = self.read_bytes(va, max_bytes)?;
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let found = units.iter().position(|&u| u == 0);
        let end = found.unwrap_or(units.len());
        Ok(prefix_value(units, &report, end * 2, 2).map(|u| Bounded {
            value: String::from_utf16_lossy(&u),
            truncated: found.is_none(),
        }))
    }

    /// Reads a counted UTF-16LE string (`len_bytes` bytes, e.g. a `UNICODE_STRING` buffer),
    /// capped at [`MAX_STRING_SCAN`] bytes; a longer count is marked [`Bounded::truncated`].
    fn read_utf16_counted(
        &self,
        va: Va,
        len_bytes: usize,
    ) -> ForensicResult<MemValue<Bounded<String>>> {
        let len = (len_bytes & !1).min(MAX_STRING_SCAN);
        let (bytes, report) = self.read_bytes(va, len)?;
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Ok(value_if_data(&report, units).map(|u| Bounded {
            value: String::from_utf16_lossy(&u),
            truncated: len_bytes > MAX_STRING_SCAN,
        }))
    }
}

impl<T: AddressSpace + ?Sized> AddressSpaceExt for T {}

fn read_le<const N: usize>(
    space: &(impl AddressSpace + ?Sized),
    va: Va,
) -> ForensicResult<MemValue<[u8; N]>> {
    let mut buf = [0u8; N];
    let report = space.read(va, &mut buf)?;
    Ok(value_if_data(&report, buf))
}

fn value_if_data<T>(report: &ReadReport, value: T) -> MemValue<T> {
    if report.has_all_data() {
        MemValue::Known(value)
    } else {
        MemValue::Unavailable(report.worst().unwrap_or(Validity::Invalid))
    }
}

/// Keeps the first `end_bytes` bytes' worth of `items` (each `unit` bytes wide), known only when
/// those bytes, plus the terminator if one was found inside the read, are real data.
fn prefix_value<T>(
    mut items: Vec<T>,
    report: &ReadReport,
    end_bytes: usize,
    unit: usize,
) -> MemValue<Vec<T>> {
    let needed = (end_bytes as u64)
        .saturating_add(unit as u64)
        .min(report.total_len());
    let mut remaining = needed;
    let mut worst: Option<Validity> = None;
    for &(len, validity) in report.runs() {
        if remaining == 0 {
            break;
        }
        if !validity.has_data() {
            worst = Some(worst.map_or(validity, |w| w.worst(validity)));
        }
        remaining = remaining.saturating_sub(len);
    }
    match worst {
        Some(validity) => MemValue::Unavailable(validity),
        None => {
            items.truncate(end_bytes / unit);
            MemValue::Known(items)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::PhysRange;
    use crate::utils::testing::{InMemoryPhysicalMemory, TestingAddressSpace};
    use std::sync::Arc;

    fn space() -> TestingAddressSpace {
        let mut page0 = vec![0u8; 0x1000];
        page0[0..8].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        page0[0x10..0x16].copy_from_slice(b"abc\0de");
        // "hi" in UTF-16, then the terminator in the next (unmapped) page.
        page0[0xffc..0x1000].copy_from_slice(&[b'h', 0, b'i', 0]);
        let phys = InMemoryPhysicalMemory::new("test")
            .with_range(Pa::new(0x5000), page0)
            .unwrap();
        TestingAddressSpace::new(SpaceId(1), 8, Arc::new(phys))
            .map_page(Va::new(0x1000), Pa::new(0x5000))
    }

    #[test]
    fn file_backed_pages_have_no_data_until_resolved() {
        let t = Translation::FileBacked {
            file: 0xffff_c000_0000_1000,
            offset: 0x2000,
        };
        assert_eq!(t.pa(), None);
        assert_eq!(
            t.unresolved_validity(),
            Validity::Paged {
                backing: Backing::MappedFile,
                data: false
            }
        );
    }

    #[test]
    fn typed_reads() {
        let s = space();
        assert_eq!(
            s.read_u64(Va::new(0x1000)).unwrap(),
            MemValue::Known(0x1122_3344_5566_7788)
        );
        assert_eq!(
            s.read_u16(Va::new(0x1000)).unwrap(),
            MemValue::Known(0x7788)
        );
        assert_eq!(
            s.read_ptr(Va::new(0x1000)).unwrap(),
            MemValue::Known(Va::new(0x1122_3344_5566_7788))
        );
        // Straddles into the unmapped page.
        assert_eq!(
            s.read_u32(Va::new(0x1ffe)).unwrap(),
            MemValue::Unavailable(Validity::Invalid)
        );
    }

    #[test]
    fn strings_stop_at_the_terminator_and_report_missing_ones() {
        let s = space();
        assert_eq!(
            s.read_cstr(Va::new(0x1010), 64).unwrap(),
            MemValue::Known(Bounded {
                value: b"abc".to_vec(),
                truncated: false
            })
        );
        // No terminator within the bound: a prefix, and it says so.
        assert_eq!(
            s.read_cstr(Va::new(0x1010), 2).unwrap(),
            MemValue::Known(Bounded {
                value: b"ab".to_vec(),
                truncated: true
            })
        );
        // The terminator would be in the unmapped page: the string is not known.
        assert_eq!(
            s.read_utf16(Va::new(0x1ffc), 16).unwrap(),
            MemValue::Unavailable(Validity::Invalid)
        );
        assert_eq!(
            s.read_utf16_counted(Va::new(0x1ffc), 4).unwrap(),
            MemValue::Known(Bounded {
                value: "hi".to_string(),
                truncated: false
            })
        );
        assert_eq!(
            s.read_utf16(Va::new(0x1ffc), 1).unwrap(),
            MemValue::Known(Bounded {
                value: "h".to_string(),
                truncated: true
            })
        );
    }

    #[test]
    fn oversized_reads_are_errors_not_allocations() {
        let s = space();
        assert!(s.read_bytes(Va::new(0x1000), MAX_READ).is_ok());
        assert!(s.read_bytes(Va::new(0x1000), MAX_READ + 1).is_err());
        assert!(s.read_bytes(Va::new(0x1000), usize::MAX).is_err());
    }

    #[test]
    fn phys_range_end_is_checked() {
        assert_eq!(PhysRange::new(Pa::new(u64::MAX), 2).end(), None);
        assert!(PhysRange::new(Pa::new(0x1000), 0x1000).contains(Pa::new(0x1fff)));
        assert!(!PhysRange::new(Pa::new(0x1000), 0x1000).contains(Pa::new(0x2000)));
    }
}
