//! Virtual and physical addresses, and page sizes.
//!
//! Addresses come from evidence, so every arithmetic operation is checked: there is no `Add` or
//! `Sub` impl that could wrap silently on a hostile value. A computation that would overflow
//! returns `None`, and the caller reports the structure as unreadable instead of reading the
//! wrong bytes.

use std::fmt;

macro_rules! address_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[repr(transparent)]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name(u64);

        impl $name {
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            pub const fn as_u64(self) -> u64 {
                self.0
            }

            /// `self + bytes`, or `None` on overflow.
            pub const fn checked_add(self, bytes: u64) -> Option<Self> {
                match self.0.checked_add(bytes) {
                    Some(v) => Some(Self(v)),
                    None => None,
                }
            }

            /// `self - bytes`, or `None` on underflow.
            pub const fn checked_sub(self, bytes: u64) -> Option<Self> {
                match self.0.checked_sub(bytes) {
                    Some(v) => Some(Self(v)),
                    None => None,
                }
            }

            /// `self + delta` for a signed delta (a relative offset read from a structure), or
            /// `None` when the result leaves the 64-bit range.
            pub const fn checked_offset(self, delta: i64) -> Option<Self> {
                match self.0.checked_add_signed(delta) {
                    Some(v) => Some(Self(v)),
                    None => None,
                }
            }

            /// The distance from `base` up to `self`, or `None` when `self` is below `base`.
            pub const fn offset_from(self, base: Self) -> Option<u64> {
                self.0.checked_sub(base.0)
            }

            /// The start of the page that contains `self`.
            pub const fn align_down(self, page: PageSize) -> Self {
                Self(self.0 & !(page.bytes() - 1))
            }

            /// The offset of `self` inside its page.
            pub const fn page_offset(self, page: PageSize) -> u64 {
                self.0 & (page.bytes() - 1)
            }

            pub const fn is_aligned(self, page: PageSize) -> bool {
                self.page_offset(page) == 0
            }
        }

        impl From<u64> for $name {
            fn from(value: u64) -> Self {
                Self(value)
            }
        }

        impl From<$name> for u64 {
            fn from(value: $name) -> u64 {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:#x}", self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({:#x})", stringify!($name), self.0)
            }
        }

        impl fmt::LowerHex for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::LowerHex::fmt(&self.0, f)
            }
        }

        // Serialized as a `"0x…"` string: JSON numbers above 2^53 lose precision in common
        // readers, and a hex string is how an analyst reads an address anyway.
        #[cfg(feature = "serde")]
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
                parse_hex(&s).map(Self).ok_or_else(|| {
                    serde::de::Error::custom(format!(
                        "expected a \"0x…\" hex address, got {s:?}"
                    ))
                })
            }
        }
    };
}

address_type!(
    /// A virtual address, in some [`AddressSpace`](super::AddressSpace).
    Va
);
address_type!(
    /// A physical address, in a [`PhysicalMemory`](super::PhysicalMemory).
    Pa
);

impl Va {
    /// Whether this address is canonical in a space of `va_bits` implemented bits
    /// ([`AddressSpace::va_bits`](super::AddressSpace::va_bits)): bits 63 down to `va_bits - 1`
    /// all equal (x86-64 "canonical addressing", Intel SDM Vol. 1 §3.3.7.1; 48 bits with 4-level
    /// paging, 57 with 5-level). With 64 or more bits (or 0) every address is canonical.
    pub const fn is_canonical(self, va_bits: u8) -> bool {
        if va_bits == 0 || va_bits >= 64 {
            return true;
        }
        let top = self.0 >> (va_bits - 1);
        top == 0 || top == u64::MAX >> (va_bits - 1)
    }

    /// Whether this address is in the upper (kernel) half of a space of `va_bits` bits: canonical,
    /// with the sign bit set.
    pub const fn is_upper_half(self, va_bits: u8) -> bool {
        self.is_canonical(va_bits) && self.0 >> 63 == 1
    }
}

#[cfg(feature = "serde")]
fn parse_hex(s: &str) -> Option<u64> {
    let digits = s.strip_prefix("0x")?;
    if digits.is_empty() || digits.len() > 16 {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

/// A page size of the paging hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PageSize {
    /// 4 KiB.
    K4,
    /// 2 MiB (x64 large page).
    M2,
    /// 1 GiB (x64 huge page).
    G1,
}

impl PageSize {
    pub const fn bytes(self) -> u64 {
        match self {
            PageSize::K4 => 0x1000,
            PageSize::M2 => 0x20_0000,
            PageSize::G1 => 0x4000_0000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_is_checked() {
        assert_eq!(Va::new(u64::MAX).checked_add(1), None);
        assert_eq!(Pa::new(0).checked_sub(1), None);
        assert_eq!(Va::new(0x10).checked_offset(-0x20), None);
        assert_eq!(Va::new(0x10).checked_offset(-0x10), Some(Va::new(0)));
        assert_eq!(Va::new(0x1000).offset_from(Va::new(0x1800)), None);
        assert_eq!(Va::new(0x1800).offset_from(Va::new(0x1000)), Some(0x800));
    }

    #[test]
    fn page_helpers() {
        let va = Va::new(0x1234_5678);
        assert_eq!(va.align_down(PageSize::K4), Va::new(0x1234_5000));
        assert_eq!(va.page_offset(PageSize::K4), 0x678);
        assert_eq!(va.align_down(PageSize::M2), Va::new(0x1220_0000));
        assert!(Pa::new(0x4000_0000).is_aligned(PageSize::G1));
    }

    #[test]
    fn canonical_addresses() {
        // 4-level paging: bits 63:47 equal.
        assert!(Va::new(0x0000_7fff_ffff_f000).is_canonical(48));
        assert!(Va::new(0xffff_8000_0000_0000).is_upper_half(48));
        assert!(!Va::new(0x0000_8000_0000_0000).is_canonical(48));
        assert!(!Va::new(0xff00_0000_0000_0000).is_canonical(48));
        // 5-level paging: bits 63:56 equal, so the same address is canonical there.
        assert!(Va::new(0xff00_0000_0000_0000).is_upper_half(57));
        assert!(Va::new(0x00ff_ffff_ffff_f000).is_canonical(57));
        assert!(!Va::new(0x0100_0000_0000_0000).is_canonical(57));
        assert!(!Va::new(0x0000_7fff_ffff_f000).is_upper_half(57));
        // 32-bit spaces and degenerate widths.
        assert!(Va::new(0xffff_ffff_8000_0000).is_canonical(32));
        assert!(!Va::new(0x1_0000_0000).is_canonical(32));
        assert!(Va::new(0x8000_0000_0000_0000).is_canonical(64));
        assert!(Va::new(0x8000_0000_0000_0000).is_canonical(0));
    }

    #[test]
    fn formatting() {
        assert_eq!(Va::new(0x1ad000).to_string(), "0x1ad000");
        assert_eq!(format!("{:?}", Pa::new(0x10)), "Pa(0x10)");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_uses_hex_strings() {
        let json = serde_json::to_string(&Va::new(0xfffff800_00000000)).unwrap();
        assert_eq!(json, "\"0xfffff80000000000\"");
        let back: Va = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Va::new(0xfffff800_00000000));
        assert!(serde_json::from_str::<Pa>("\"1234\"").is_err());
        assert!(serde_json::from_str::<Pa>("\"0x\"").is_err());
        assert!(serde_json::from_str::<Pa>("\"0x1ffffffffffffffff\"").is_err());
        assert!(serde_json::from_str::<Pa>("4096").is_err());
    }
}
