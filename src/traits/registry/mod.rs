//! Windows Registry abstraction layer.
//!
//! This module provides the core types and the [`Registry`]/[`RegistryExt`]
//! traits for decoupled, backend-agnostic registry access. An analyzer
//! written against this API works identically whether it talks to a live
//! Windows registry, a parsed hive file, or a
//! [`crate::utils::testing::TestingRegistry`] mock in a unit test — without
//! any code changes.
//!
//! # Core Types
//!
//! | Type | Role |
//! |------|------|
//! | [`PredefinedHive`] | Root hive discriminant (`HKLM`, `HKU`, …) |
//! | [`Registry`] | Low-level trait implemented by all registry backends |
//! | [`RegistryExt`] | Ergonomic, path-based API layered over [`Registry`] |
//! | [`RegKey`] | Borrowed handle to an opened key ([`RegistryExt::key`]) |
//! | [`RegValue`] | Owned registry value (allocating) |
//! | [`RegValueRef`] | Borrowed, zero-copy view into a byte buffer |
//! | [`RegistryBuffer`] | Reusable heap buffer for low-allocation reads |
//!
//! # Reading Values
//!
//! ```rust
//! use forensic_rs::prelude::*;
//! use forensic_rs::utils::testing::TestingRegistry;
//!
//! let reg = TestingRegistry::new();
//! let sid = "S-1-5-21-1366093794-4292800403-1155380978-513";
//! let key = reg.key(&format!(r"HKU\{}\Volatile Environment", sid)).unwrap();
//!
//! // 1. Owned value via the opened key — simplest; allocates.
//! let val: String = key.value("USERNAME").unwrap().try_into().unwrap();
//!
//! // 2. One-shot path + value name, no intermediate `RegKey`.
//! let val2: String = reg
//!     .value(&format!(r"HKU\{}\Volatile Environment", sid), "USERNAME")
//!     .unwrap()
//!     .try_into()
//!     .unwrap();
//!
//! assert_eq!(val, val2);
//! ```
//!
//! # Path Convention
//!
//! Every path is a single string, hive-prefixed, exactly as it would be
//! typed into `regedit`'s address bar — there's no separate "hive" argument:
//!
//! ```text
//! // Correct
//! reg.key(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion")
//! reg.key(r"HKU\S-1-5-21-...\Volatile Environment")
//!
//! // Wrong — HKLM/HKU are part of the path string, not a separate parameter
//! reg.root(PredefinedHive::LocalMachine)?.open(r"SOFTWARE\...")
//! ```

use crate::err::{ForensicError, ForensicResult};

pub mod extra;
pub mod raw;
pub mod windows;
pub use raw::{
    KeyEntry, KeyInfo, OwnedRegKey, PredefinedHive, RawKey, RecoverDeleted, RecoveredKey,
    RecoveredValue, RegKey, Registry, RegistryExt,
};

/// Owned registry value. Allocates heap memory for variable-length data.
///
/// Use [`RegValueRef`] for a borrowed, zero-copy alternative when working
/// with a [`RegistryBuffer`].
///
/// `#[non_exhaustive]` (RFC 0001 §4.5): a corrupt or unrecognized value is
/// evidence, not something to drop — [`RegValue::Unknown`] preserves the raw
/// type id and bytes rather than discarding them, and future variants can be
/// added without a breaking change for downstream matches (which must
/// already include a wildcard arm).
///
/// # Conversions
///
/// `TryFrom<RegValue>` is implemented for `String`, `u32`, `u64`, and
/// `Vec<u8>` (each also accepting closely-related variants, e.g. `String`
/// accepts `Link`, `u32`/`u64` accept `DWordBigEndian`). `From<&str>`,
/// `From<String>`, `From<u32>`, `From<u64>`, `From<Vec<u8>>`,
/// `From<Vec<String>>`, and slice variants are also available to construct
/// `RegValue` ergonomically. [`RegValue::raw_bytes`] gives the on-disk byte
/// representation for every variant uniformly.
#[non_exhaustive]
#[derive(Clone, PartialEq, PartialOrd, Eq, Ord, Debug)]
pub enum RegValue {
    /// No data (`REG_NONE`).
    None,
    /// Raw binary data (`REG_BINARY`).
    Binary(Vec<u8>),
    /// List of null-terminated strings (`REG_MULTI_SZ`).
    MultiSZ(Vec<String>),
    /// Expandable string containing environment-variable references (`REG_EXPAND_SZ`).
    ExpandSZ(String),
    /// Plain string (`REG_SZ`).
    SZ(String),
    /// 32-bit unsigned integer, stored little-endian (`REG_DWORD`).
    DWord(u32),
    /// 32-bit unsigned integer, stored big-endian (`REG_DWORD_BIG_ENDIAN`).
    DWordBigEndian(u32),
    /// 64-bit unsigned integer, stored little-endian (`REG_QWORD`).
    QWord(u64),
    /// Symbolic link target (`REG_LINK`).
    Link(String),
    /// Device driver resource list (`REG_RESOURCE_LIST`).
    ResourceList(Vec<u8>),
    /// Device driver resource descriptor (`REG_FULL_RESOURCE_DESCRIPTOR`).
    FullResourceDescriptor(Vec<u8>),
    /// Device driver resource requirements (`REG_RESOURCE_REQUIREMENTS_LIST`).
    ResourceRequirementsList(Vec<u8>),
    /// Unrecognized or corrupt value type: preserves the raw on-disk type id
    /// and bytes rather than dropping them. A corrupt value is evidence.
    Unknown { ty: u32, data: Vec<u8> },
}

/// Discriminant-only counterpart of [`RegValue`], used for typed buffer reads.
///
/// Describes the shape of a value written into a [`RegistryBuffer`] (see
/// [`RegistryBuffer::commit_write`]) without requiring an allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegValueType {
    /// No data (`REG_NONE`).
    None,
    /// Raw binary data (`REG_BINARY`).
    Binary,
    /// Multi-string value (`REG_MULTI_SZ`).
    MultiSZ,
    /// Expandable string (`REG_EXPAND_SZ`).
    ExpandSZ,
    /// Plain string (`REG_SZ`).
    SZ,
    /// 32-bit big-endian integer (`REG_DWORD_BIG_ENDIAN`).
    DWordBigEndian,
    /// Symbolic link target (`REG_LINK`).
    Link,
    /// Device driver resource list (`REG_RESOURCE_LIST`).
    ResourceList,
    /// Device driver resource descriptor (`REG_FULL_RESOURCE_DESCRIPTOR`).
    FullResourceDescriptor,
    /// Device driver resource requirements (`REG_RESOURCE_REQUIREMENTS_LIST`).
    ResourceRequirementsList,
    /// Unrecognized or corrupt value type, carrying the raw on-disk type id.
    Unknown(u32),
    /// 32-bit little-endian integer (`REG_DWORD`).
    DWord,
    /// 64-bit little-endian integer (`REG_QWORD`).
    QWord,
}

/// Reusable heap buffer for low-allocation registry reads.
///
/// Grow-on-demand buffer that can be written to repeatedly (via
/// [`RegistryBuffer::write_reg_value`]) across multiple values to amortise
/// allocation cost. The buffer retains both the raw bytes and the
/// [`RegValueType`] of the last successful write, so it can be
/// re-interpreted as a [`RegValueRef`] at any time via
/// [`RegistryBuffer::as_value_ref`].
///
/// # Example
///
/// ```rust
/// use forensic_rs::prelude::*;
///
/// let mut buf = RegistryBuffer::with_capacity(256);
/// let v1 = buf.write_reg_value(&RegValue::SZ("Tester".to_string())).unwrap();
/// println!("{}", v1.as_str().unwrap());
/// // Reuse `buf` for the next value — no new allocation if it fits.
/// let v2 = buf
///     .write_reg_value(&RegValue::SZ(r"C:\Users\Tester".to_string()))
///     .unwrap();
/// println!("{}", v2.as_str().unwrap());
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegistryBuffer {
    buf: Vec<u8>,
    len: usize,
    value_type: Option<RegValueType>,
}

impl RegistryBuffer {
    /// Creates an empty buffer with no pre-allocated capacity.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty buffer with `capacity` bytes pre-allocated.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: vec![0; capacity],
            len: 0,
            value_type: None,
        }
    }

    /// Returns the number of valid (written) bytes in the buffer.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if no bytes have been written since the last [`clear`](Self::clear).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the total allocated capacity of the underlying byte slice.
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    pub fn value_type(&self) -> Option<RegValueType> {
        self.value_type
    }

    /// Resets the valid-byte count and recorded type without deallocating.
    pub fn clear(&mut self) {
        self.len = 0;
        self.value_type = None;
    }

    /// Grows the allocated capacity by `additional` bytes.
    pub fn reserve(&mut self, additional: usize) {
        self.buf.resize(self.buf.len() + additional, 0);
    }

    /// Resizes the allocated capacity to exactly `new_len` bytes, truncating
    /// the valid-byte count if needed.
    pub fn resize(&mut self, new_len: usize) {
        self.buf.resize(new_len, 0);
        if self.len > new_len {
            self.len = new_len;
        }
        if self.len == 0 {
            self.value_type = None;
        }
    }

    /// Returns a slice over the valid (written) bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Returns a mutable slice over the valid (written) bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        let len = self.len;
        &mut self.buf[..len]
    }

    /// Returns the full allocated slice, including unwritten bytes.
    /// Used to write raw bytes directly into the buffer before recording the
    /// write with [`Self::commit_write`].
    pub fn writable_bytes(&mut self) -> &mut [u8] {
        &mut self.buf[..]
    }

    /// Grows the allocation to at least `required` bytes if necessary.
    pub fn ensure_capacity(&mut self, required: usize) {
        if self.buf.len() < required {
            self.buf.resize(required, 0);
        }
    }

    /// Sets the valid-byte count, growing the allocation as needed.
    /// Passing `0` also clears the stored value type.
    pub fn set_len(&mut self, len: usize) {
        self.ensure_capacity(len);
        self.len = len;
        if len == 0 {
            self.value_type = None;
        }
    }

    /// Stores the registry value type tag without changing the byte content.
    pub fn set_value_type(&mut self, value_type: Option<RegValueType>) {
        self.value_type = value_type;
    }

    /// Records a successful write: sets the valid-byte count and the value type tag.
    /// Call after writing to [`writable_bytes`](Self::writable_bytes).
    pub fn commit_write(&mut self, len: usize, value_type: RegValueType) {
        self.set_len(len);
        self.value_type = Some(value_type);
    }

    /// Interprets the current buffer contents as a [`RegValueRef`].
    /// Returns `Err` if no type tag has been recorded (buffer was never written).
    pub fn as_value_ref(&self) -> ForensicResult<RegValueRef<'_>> {
        let value_type = self.value_type.ok_or_else(|| {
            ForensicError::missing_data(
                "registry_value",
                compact_str::CompactString::const_new(
                    "RegistryBuffer does not contain a registry value",
                ),
            )
        })?;
        value_type.parse_bytes(self.as_bytes())
    }

    /// Converts the current buffer to an owned [`RegValue`]. Allocates.
    pub fn to_reg_value(&self) -> ForensicResult<RegValue> {
        Ok(self.as_value_ref()?.to_owned())
    }

    /// Serialises `value` into this buffer and returns a borrowed view.
    ///
    /// Ensures the buffer is large enough, then delegates to [`RegValue::write_into`].
    pub fn write_reg_value<'a>(&'a mut self, value: &RegValue) -> ForensicResult<RegValueRef<'a>> {
        let required = value.serialized_size();
        self.ensure_capacity(required);
        let written = value.write_into(&mut self.buf[..required])?;
        self.len = written;
        self.value_type = Some(value.value_type());
        self.as_value_ref()
    }
}

/// Borrowed view of a `REG_MULTI_SZ` value stored in a byte buffer.
///
/// Iterates lines via [`RegMultiSzRef::iter`] (backed by [`str::lines`]) without
/// allocating a `Vec<String>`. The newline delimiter is the internal serialisation
/// detail of [`RegistryBuffer`]; this type hides it from callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegMultiSzRef<'a> {
    raw: &'a str,
}

impl<'a> RegMultiSzRef<'a> {
    /// Creates a new view over a newline-separated multi-string slice.
    pub fn new(raw: &'a str) -> Self {
        Self { raw }
    }

    /// Returns the underlying newline-separated string slice.
    pub fn as_str(&self) -> &'a str {
        self.raw
    }

    /// Iterates the individual strings (splits on `\n`).
    pub fn iter(&self) -> std::str::Lines<'a> {
        self.raw.lines()
    }
}

/// Borrowed, zero-copy view of a registry value inside a byte buffer.
///
/// Returned by [`RegistryBuffer::write_reg_value`] and
/// [`RegistryBuffer::as_value_ref`]. Variable-length variants (`Binary`,
/// `MultiSZ`, `ExpandSZ`, `SZ`) borrow from the buffer they were written
/// into, so the view cannot outlive that buffer.
///
/// Convert to an owned [`RegValue`] via [`RegValueRef::to_owned`] when
/// you need to store or move the value.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegValueRef<'a> {
    /// No data (`REG_NONE`).
    None,
    /// Raw binary data (`REG_BINARY`).
    Binary(&'a [u8]),
    /// Multi-string value (`REG_MULTI_SZ`).
    MultiSZ(RegMultiSzRef<'a>),
    /// Expandable string (`REG_EXPAND_SZ`).
    ExpandSZ(&'a str),
    /// Plain string (`REG_SZ`).
    SZ(&'a str),
    /// 32-bit little-endian integer (`REG_DWORD`).
    DWord(u32),
    /// 32-bit big-endian integer (`REG_DWORD_BIG_ENDIAN`).
    DWordBigEndian(u32),
    /// 64-bit little-endian integer (`REG_QWORD`).
    QWord(u64),
    /// Symbolic link target (`REG_LINK`).
    Link(&'a str),
    /// Device driver resource list (`REG_RESOURCE_LIST`).
    ResourceList(&'a [u8]),
    /// Device driver resource descriptor (`REG_FULL_RESOURCE_DESCRIPTOR`).
    FullResourceDescriptor(&'a [u8]),
    /// Device driver resource requirements (`REG_RESOURCE_REQUIREMENTS_LIST`).
    ResourceRequirementsList(&'a [u8]),
    /// Unrecognized or corrupt value type.
    Unknown { ty: u32, data: &'a [u8] },
}

impl<'a> RegValueRef<'a> {
    pub fn value_type(&self) -> RegValueType {
        match self {
            RegValueRef::None => RegValueType::None,
            RegValueRef::Binary(_) => RegValueType::Binary,
            RegValueRef::MultiSZ(_) => RegValueType::MultiSZ,
            RegValueRef::ExpandSZ(_) => RegValueType::ExpandSZ,
            RegValueRef::SZ(_) => RegValueType::SZ,
            RegValueRef::DWord(_) => RegValueType::DWord,
            RegValueRef::DWordBigEndian(_) => RegValueType::DWordBigEndian,
            RegValueRef::QWord(_) => RegValueType::QWord,
            RegValueRef::Link(_) => RegValueType::Link,
            RegValueRef::ResourceList(_) => RegValueType::ResourceList,
            RegValueRef::FullResourceDescriptor(_) => RegValueType::FullResourceDescriptor,
            RegValueRef::ResourceRequirementsList(_) => RegValueType::ResourceRequirementsList,
            RegValueRef::Unknown { ty, .. } => RegValueType::Unknown(*ty),
        }
    }

    pub fn as_str(&self) -> Option<&'a str> {
        match self {
            RegValueRef::SZ(s) | RegValueRef::ExpandSZ(s) | RegValueRef::Link(s) => Some(s),
            _ => None,
        }
    }

    /// Raw bytes, for `Binary` and every other opaque-bytes-shaped variant
    /// (`ResourceList`, `FullResourceDescriptor`,
    /// `ResourceRequirementsList`, `Unknown`).
    pub fn as_binary(&self) -> Option<&'a [u8]> {
        match self {
            RegValueRef::Binary(v)
            | RegValueRef::ResourceList(v)
            | RegValueRef::FullResourceDescriptor(v)
            | RegValueRef::ResourceRequirementsList(v) => Some(v),
            RegValueRef::Unknown { data, .. } => Some(data),
            _ => None,
        }
    }

    pub fn as_multi_sz(&self) -> Option<RegMultiSzRef<'a>> {
        match self {
            RegValueRef::MultiSZ(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_dword(&self) -> Option<u32> {
        match self {
            RegValueRef::DWord(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_qword(&self) -> Option<u64> {
        match self {
            RegValueRef::QWord(v) => Some(*v),
            _ => None,
        }
    }

    pub fn to_owned(&self) -> RegValue {
        match self {
            RegValueRef::None => RegValue::None,
            RegValueRef::Binary(v) => RegValue::Binary(v.to_vec()),
            RegValueRef::MultiSZ(v) => RegValue::MultiSZ(v.iter().map(str::to_string).collect()),
            RegValueRef::ExpandSZ(v) => RegValue::ExpandSZ((*v).to_string()),
            RegValueRef::SZ(v) => RegValue::SZ((*v).to_string()),
            RegValueRef::DWord(v) => RegValue::DWord(*v),
            RegValueRef::DWordBigEndian(v) => RegValue::DWordBigEndian(*v),
            RegValueRef::QWord(v) => RegValue::QWord(*v),
            RegValueRef::Link(v) => RegValue::Link((*v).to_string()),
            RegValueRef::ResourceList(v) => RegValue::ResourceList(v.to_vec()),
            RegValueRef::FullResourceDescriptor(v) => RegValue::FullResourceDescriptor(v.to_vec()),
            RegValueRef::ResourceRequirementsList(v) => RegValue::ResourceRequirementsList(v.to_vec()),
            RegValueRef::Unknown { ty, data } => RegValue::Unknown {
                ty: *ty,
                data: data.to_vec(),
            },
        }
    }
}

impl RegValue {
    /// Creates a `REG_SZ` value from a string slice.
    pub fn new_sz(v: &str) -> RegValue {
        RegValue::SZ(v.to_string())
    }
    /// Creates a `REG_SZ` value from an owned `String`.
    pub fn from_string(v: String) -> RegValue {
        RegValue::SZ(v)
    }
    /// Creates a `REG_DWORD` value from a `u32`.
    pub fn from_u32(v: u32) -> RegValue {
        RegValue::DWord(v)
    }
    /// Creates a `REG_QWORD` value from a `u64`.
    pub fn from_u64(v: u64) -> RegValue {
        RegValue::QWord(v)
    }

    /// Returns the [`RegValueType`] discriminant for this value.
    pub fn value_type(&self) -> RegValueType {
        match self {
            RegValue::None => RegValueType::None,
            RegValue::Binary(_) => RegValueType::Binary,
            RegValue::MultiSZ(_) => RegValueType::MultiSZ,
            RegValue::ExpandSZ(_) => RegValueType::ExpandSZ,
            RegValue::SZ(_) => RegValueType::SZ,
            RegValue::DWord(_) => RegValueType::DWord,
            RegValue::DWordBigEndian(_) => RegValueType::DWordBigEndian,
            RegValue::QWord(_) => RegValueType::QWord,
            RegValue::Link(_) => RegValueType::Link,
            RegValue::ResourceList(_) => RegValueType::ResourceList,
            RegValue::FullResourceDescriptor(_) => RegValueType::FullResourceDescriptor,
            RegValue::ResourceRequirementsList(_) => RegValueType::ResourceRequirementsList,
            RegValue::Unknown { ty, .. } => RegValueType::Unknown(*ty),
        }
    }

    /// Returns the string value if this is an `SZ`, `ExpandSZ`, or `Link`
    /// variant.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            RegValue::SZ(s) | RegValue::ExpandSZ(s) | RegValue::Link(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the `DWord` value.
    pub fn as_dword(&self) -> Option<u32> {
        match self {
            RegValue::DWord(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns the `QWord` value.
    pub fn as_qword(&self) -> Option<u64> {
        match self {
            RegValue::QWord(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns the raw bytes for `Binary` and every other opaque-bytes-shaped
    /// variant (`ResourceList`, `FullResourceDescriptor`,
    /// `ResourceRequirementsList`, `Unknown`).
    pub fn as_binary(&self) -> Option<&[u8]> {
        match self {
            RegValue::Binary(v)
            | RegValue::ResourceList(v)
            | RegValue::FullResourceDescriptor(v)
            | RegValue::ResourceRequirementsList(v) => Some(v),
            RegValue::Unknown { data, .. } => Some(data),
            _ => None,
        }
    }

    /// Returns the multi-string list if this is a `MultiSZ` variant.
    pub fn as_multi_sz(&self) -> Option<&[String]> {
        match self {
            RegValue::MultiSZ(v) => Some(v),
            _ => None,
        }
    }

    /// Returns the serialized size of this value (as if written to buffer).
    /// - `None`: 0 bytes
    /// - `SZ`/`ExpandSZ`/`Link`: UTF-8 byte length
    /// - `Binary`/`ResourceList`/`FullResourceDescriptor`/
    ///   `ResourceRequirementsList`/`Unknown`: byte length
    /// - `MultiSZ`: newline-separated UTF-8 strings (no trailing newline)
    /// - `DWord`/`DWordBigEndian`: 4 bytes
    /// - `QWord`: 8 bytes
    pub fn serialized_size(&self) -> usize {
        match self {
            RegValue::None => 0,
            RegValue::SZ(s) | RegValue::ExpandSZ(s) | RegValue::Link(s) => s.len(),
            RegValue::Binary(b)
            | RegValue::ResourceList(b)
            | RegValue::FullResourceDescriptor(b)
            | RegValue::ResourceRequirementsList(b) => b.len(),
            RegValue::Unknown { data, .. } => data.len(),
            RegValue::MultiSZ(v) => {
                if v.is_empty() {
                    0
                } else {
                    // Calculate total size: each string as UTF-8 + newlines between them
                    v.iter().map(|s| s.len()).sum::<usize>() + (v.len() - 1) // v.len()-1 newlines
                }
            }
            RegValue::DWord(_) | RegValue::DWordBigEndian(_) => 4,
            RegValue::QWord(_) => 8,
        }
    }

    /// Writes this registry value to a buffer, returning bytes written.
    ///
    /// **Serialization Format:**
    /// - `None`: nothing written
    /// - `SZ`/`ExpandSZ`/`Link`: UTF-8 string (no null terminator)
    /// - `Binary`/`ResourceList`/`FullResourceDescriptor`/
    ///   `ResourceRequirementsList`/`Unknown`: raw bytes
    /// - `MultiSZ`: newline-separated UTF-8 strings (no trailing newline, no null terminators)
    /// - `DWord`: 4 bytes (little-endian)
    /// - `DWordBigEndian`: 4 bytes (big-endian)
    /// - `QWord`: 8 bytes (little-endian)
    ///
    /// Returns `Err` if buffer too small (error message includes required size).
    pub fn write_into(&self, buf: &mut [u8]) -> ForensicResult<usize> {
        let required = self.serialized_size();
        if buf.len() < required {
            return Err(ForensicError::buffer_too_small(
                required,
                buf.len(),
                "RegValue",
            ));
        }

        match self {
            RegValue::None => Ok(0),
            RegValue::SZ(s) | RegValue::ExpandSZ(s) | RegValue::Link(s) => {
                let bytes = s.as_bytes();
                buf[..bytes.len()].copy_from_slice(bytes);
                Ok(bytes.len())
            }
            RegValue::Binary(b)
            | RegValue::ResourceList(b)
            | RegValue::FullResourceDescriptor(b)
            | RegValue::ResourceRequirementsList(b) => {
                buf[..b.len()].copy_from_slice(b);
                Ok(b.len())
            }
            RegValue::Unknown { data, .. } => {
                buf[..data.len()].copy_from_slice(data);
                Ok(data.len())
            }
            RegValue::MultiSZ(v) => {
                let mut pos = 0;
                for (i, s) in v.iter().enumerate() {
                    let bytes = s.as_bytes();
                    buf[pos..pos + bytes.len()].copy_from_slice(bytes);
                    pos += bytes.len();
                    if i < v.len() - 1 {
                        buf[pos] = b'\n';
                        pos += 1;
                    }
                }
                Ok(pos)
            }
            RegValue::DWord(v) => {
                buf[..4].copy_from_slice(&v.to_le_bytes());
                Ok(4)
            }
            RegValue::DWordBigEndian(v) => {
                buf[..4].copy_from_slice(&v.to_be_bytes());
                Ok(4)
            }
            RegValue::QWord(v) => {
                buf[..8].copy_from_slice(&v.to_le_bytes());
                Ok(8)
            }
        }
    }

    /// Writes this value into the provided buffer and returns a borrowed, typed view.
    ///
    /// This provides an ergonomic zero-copy API where string and binary variants borrow
    /// directly from the caller-provided buffer.
    pub fn write_into_ref<'a>(&self, buf: &'a mut [u8]) -> ForensicResult<RegValueRef<'a>> {
        let written = self.write_into(buf)?;
        let raw = &buf[..written];

        match self {
            RegValue::None => Ok(RegValueRef::None),
            RegValue::SZ(_) => {
                let s = std::str::from_utf8(raw).map_err(|e| {
                    ForensicError::cast_error(
                        "RegValue",
                        "RegValueRef::SZ",
                        format!("Invalid UTF-8 in serialized string: {}", e).into(),
                    )
                })?;
                Ok(RegValueRef::SZ(s))
            }
            RegValue::ExpandSZ(_) => {
                let s = std::str::from_utf8(raw).map_err(|e| {
                    ForensicError::cast_error(
                        "RegValue",
                        "RegValueRef::ExpandSZ",
                        format!("Invalid UTF-8 in serialized string: {}", e).into(),
                    )
                })?;
                Ok(RegValueRef::ExpandSZ(s))
            }
            RegValue::Link(_) => {
                let s = std::str::from_utf8(raw).map_err(|e| {
                    ForensicError::cast_error(
                        "RegValue",
                        "RegValueRef::Link",
                        format!("Invalid UTF-8 in serialized link target: {}", e).into(),
                    )
                })?;
                Ok(RegValueRef::Link(s))
            }
            RegValue::Binary(_) => Ok(RegValueRef::Binary(raw)),
            RegValue::ResourceList(_) => Ok(RegValueRef::ResourceList(raw)),
            RegValue::FullResourceDescriptor(_) => Ok(RegValueRef::FullResourceDescriptor(raw)),
            RegValue::ResourceRequirementsList(_) => Ok(RegValueRef::ResourceRequirementsList(raw)),
            RegValue::Unknown { ty, .. } => Ok(RegValueRef::Unknown { ty: *ty, data: raw }),
            RegValue::MultiSZ(_) => {
                let s = std::str::from_utf8(raw).map_err(|e| {
                    ForensicError::cast_error(
                        "RegValue",
                        "RegValueRef::MultiSZ",
                        format!("Invalid UTF-8 in serialized MultiSZ: {}", e).into(),
                    )
                })?;
                Ok(RegValueRef::MultiSZ(RegMultiSzRef::new(s)))
            }
            RegValue::DWord(_) => {
                let mut le = [0u8; 4];
                le.copy_from_slice(raw);
                Ok(RegValueRef::DWord(u32::from_le_bytes(le)))
            }
            RegValue::DWordBigEndian(_) => {
                let mut be = [0u8; 4];
                be.copy_from_slice(raw);
                Ok(RegValueRef::DWordBigEndian(u32::from_be_bytes(be)))
            }
            RegValue::QWord(_) => {
                let mut le = [0u8; 8];
                le.copy_from_slice(raw);
                Ok(RegValueRef::QWord(u64::from_le_bytes(le)))
            }
        }
    }

    /// The on-disk byte representation of this value, for every variant
    /// uniformly. Borrows already-`Vec<u8>`-backed variants; serializes
    /// allocating variants into an owned buffer.
    ///
    /// String variants (`SZ`/`ExpandSZ`/`Link`/`MultiSZ`) serialize as UTF-8
    /// here, matching [`Self::write_into`] — real on-disk Windows hives use
    /// UTF-16LE, which this crate does not yet model (a known
    /// simplification, consistent throughout this module).
    pub fn raw_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        match self {
            RegValue::None => std::borrow::Cow::Borrowed(&[]),
            RegValue::Binary(v)
            | RegValue::ResourceList(v)
            | RegValue::FullResourceDescriptor(v)
            | RegValue::ResourceRequirementsList(v) => std::borrow::Cow::Borrowed(v),
            RegValue::Unknown { data, .. } => std::borrow::Cow::Borrowed(data),
            RegValue::DWord(v) => std::borrow::Cow::Owned(v.to_le_bytes().to_vec()),
            RegValue::DWordBigEndian(v) => std::borrow::Cow::Owned(v.to_be_bytes().to_vec()),
            RegValue::QWord(v) => std::borrow::Cow::Owned(v.to_le_bytes().to_vec()),
            RegValue::SZ(_) | RegValue::ExpandSZ(_) | RegValue::Link(_) | RegValue::MultiSZ(_) => {
                let mut buf = vec![0u8; self.serialized_size()];
                let _ = self.write_into(&mut buf);
                std::borrow::Cow::Owned(buf)
            }
        }
    }
}

impl RegValueType {
    pub fn parse_bytes<'a>(&self, raw: &'a [u8]) -> ForensicResult<RegValueRef<'a>> {
        match self {
            RegValueType::SZ => {
                let s = std::str::from_utf8(raw).map_err(|e| {
                    ForensicError::cast_error(
                        "RegistryBuffer",
                        "RegValueRef::SZ",
                        format!("Invalid UTF-8 in buffered string: {}", e).into(),
                    )
                })?;
                Ok(RegValueRef::SZ(s))
            }
            RegValueType::ExpandSZ => {
                let s = std::str::from_utf8(raw).map_err(|e| {
                    ForensicError::cast_error(
                        "RegistryBuffer",
                        "RegValueRef::ExpandSZ",
                        format!("Invalid UTF-8 in buffered expand string: {}", e).into(),
                    )
                })?;
                Ok(RegValueRef::ExpandSZ(s))
            }
            RegValueType::None => Ok(RegValueRef::None),
            RegValueType::Binary => Ok(RegValueRef::Binary(raw)),
            RegValueType::ResourceList => Ok(RegValueRef::ResourceList(raw)),
            RegValueType::FullResourceDescriptor => Ok(RegValueRef::FullResourceDescriptor(raw)),
            RegValueType::ResourceRequirementsList => Ok(RegValueRef::ResourceRequirementsList(raw)),
            RegValueType::Unknown(ty) => Ok(RegValueRef::Unknown { ty: *ty, data: raw }),
            RegValueType::Link => {
                let s = std::str::from_utf8(raw).map_err(|e| {
                    ForensicError::cast_error(
                        "RegistryBuffer",
                        "RegValueRef::Link",
                        format!("Invalid UTF-8 in buffered link target: {}", e).into(),
                    )
                })?;
                Ok(RegValueRef::Link(s))
            }
            RegValueType::MultiSZ => {
                let s = std::str::from_utf8(raw).map_err(|e| {
                    ForensicError::cast_error(
                        "RegistryBuffer",
                        "RegValueRef::MultiSZ",
                        format!("Invalid UTF-8 in buffered MultiSZ: {}", e).into(),
                    )
                })?;
                Ok(RegValueRef::MultiSZ(RegMultiSzRef::new(s)))
            }
            RegValueType::DWord => {
                if raw.len() != 4 {
                    return Err(ForensicError::cast_error(
                        "RegistryBuffer",
                        "RegValueRef::DWord",
                        format!("Expected 4 bytes for DWord, got {}", raw.len()).into(),
                    ));
                }
                let mut le = [0u8; 4];
                le.copy_from_slice(raw);
                Ok(RegValueRef::DWord(u32::from_le_bytes(le)))
            }
            RegValueType::DWordBigEndian => {
                if raw.len() != 4 {
                    return Err(ForensicError::cast_error(
                        "RegistryBuffer",
                        "RegValueRef::DWordBigEndian",
                        format!("Expected 4 bytes for DWordBigEndian, got {}", raw.len()).into(),
                    ));
                }
                let mut be = [0u8; 4];
                be.copy_from_slice(raw);
                Ok(RegValueRef::DWordBigEndian(u32::from_be_bytes(be)))
            }
            RegValueType::QWord => {
                if raw.len() != 8 {
                    return Err(ForensicError::cast_error(
                        "RegistryBuffer",
                        "RegValueRef::QWord",
                        format!("Expected 8 bytes for QWord, got {}", raw.len()).into(),
                    ));
                }
                let mut le = [0u8; 8];
                le.copy_from_slice(raw);
                Ok(RegValueRef::QWord(u64::from_le_bytes(le)))
            }
        }
    }
}

impl std::fmt::Display for RegValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegValue::None => Ok(()),
            RegValue::SZ(s) | RegValue::ExpandSZ(s) | RegValue::Link(s) => write!(f, "{}", s),
            RegValue::DWord(v) | RegValue::DWordBigEndian(v) => write!(f, "{}", v),
            RegValue::QWord(v) => write!(f, "{}", v),
            RegValue::Binary(v)
            | RegValue::ResourceList(v)
            | RegValue::FullResourceDescriptor(v)
            | RegValue::ResourceRequirementsList(v) => {
                for (i, b) in v.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            RegValue::Unknown { data, .. } => {
                for (i, b) in data.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            RegValue::MultiSZ(v) => {
                for (i, s) in v.iter().enumerate() {
                    if i > 0 {
                        writeln!(f)?;
                    }
                    write!(f, "{}", s)?;
                }
                Ok(())
            }
        }
    }
}

impl From<String> for RegValue {
    fn from(v: String) -> RegValue {
        RegValue::SZ(v)
    }
}

impl From<&str> for RegValue {
    fn from(v: &str) -> RegValue {
        RegValue::SZ(v.to_string())
    }
}

impl From<u32> for RegValue {
    fn from(v: u32) -> RegValue {
        RegValue::DWord(v)
    }
}

impl From<u64> for RegValue {
    fn from(v: u64) -> RegValue {
        RegValue::QWord(v)
    }
}
impl From<i32> for RegValue {
    fn from(v: i32) -> RegValue {
        RegValue::DWord(v as u32)
    }
}

impl From<i64> for RegValue {
    fn from(v: i64) -> RegValue {
        RegValue::QWord(v as u64)
    }
}
impl From<usize> for RegValue {
    fn from(v: usize) -> RegValue {
        #[cfg(target_pointer_width = "32")]
        {
            RegValue::DWord(v as u32)
        }
        #[cfg(target_pointer_width = "16")]
        {
            RegValue::DWord(v as u32)
        }
        #[cfg(target_pointer_width = "64")]
        {
            RegValue::QWord(v as u64)
        }
    }
}

impl From<Vec<u8>> for RegValue {
    fn from(v: Vec<u8>) -> RegValue {
        RegValue::Binary(v)
    }
}

impl From<Vec<String>> for RegValue {
    fn from(value: Vec<String>) -> Self {
        RegValue::MultiSZ(value)
    }
}
impl From<&[u8]> for RegValue {
    fn from(value: &[u8]) -> Self {
        let mut vc = Vec::with_capacity(value.len());
        for v in value {
            vc.push(*v);
        }
        RegValue::Binary(vc)
    }
}
impl From<&[String]> for RegValue {
    fn from(value: &[String]) -> Self {
        let mut vc = Vec::with_capacity(value.len());
        for v in value {
            vc.push(v.clone());
        }
        RegValue::MultiSZ(vc)
    }
}
impl From<&[&String]> for RegValue {
    fn from(value: &[&String]) -> Self {
        let mut vc = Vec::with_capacity(value.len());
        for &v in value {
            vc.push(v.clone());
        }
        RegValue::MultiSZ(vc)
    }
}
impl From<&[&str]> for RegValue {
    fn from(value: &[&str]) -> Self {
        let mut vc = Vec::with_capacity(value.len());
        for &v in value {
            vc.push(v.to_string());
        }
        RegValue::MultiSZ(vc)
    }
}

impl TryFrom<RegValue> for String {
    type Error = ForensicError;
    fn try_from(value: RegValue) -> Result<Self, Self::Error> {
        match value {
            RegValue::MultiSZ(v) => Ok(v.join("\n")),
            RegValue::ExpandSZ(v) => Ok(v),
            RegValue::SZ(v) => Ok(v),
            RegValue::Link(v) => Ok(v),
            _ => Err(ForensicError::cast_error(
                "RegValue",
                "String",
                compact_str::CompactString::const_new("Incompatible registry value type"),
            )),
        }
    }
}
impl TryFrom<RegValue> for u32 {
    type Error = ForensicError;
    fn try_from(value: RegValue) -> Result<Self, Self::Error> {
        match value {
            RegValue::DWord(v) | RegValue::DWordBigEndian(v) => Ok(v),
            RegValue::QWord(v) => Ok(v as u32),
            _ => Err(ForensicError::cast_error(
                "RegValue",
                "u32",
                compact_str::CompactString::const_new("Incompatible registry value type"),
            )),
        }
    }
}
impl TryFrom<RegValue> for u64 {
    type Error = ForensicError;
    fn try_from(value: RegValue) -> Result<Self, Self::Error> {
        match value {
            RegValue::DWord(v) | RegValue::DWordBigEndian(v) => Ok(v as u64),
            RegValue::QWord(v) => Ok(v),
            _ => Err(ForensicError::cast_error(
                "RegValue",
                "u64",
                compact_str::CompactString::const_new("Incompatible registry value type"),
            )),
        }
    }
}
impl TryFrom<RegValue> for Vec<u8> {
    type Error = ForensicError;
    fn try_from(value: RegValue) -> Result<Self, Self::Error> {
        match value {
            RegValue::Binary(v)
            | RegValue::ResourceList(v)
            | RegValue::FullResourceDescriptor(v)
            | RegValue::ResourceRequirementsList(v) => Ok(v),
            RegValue::Unknown { data, .. } => Ok(data),
            _ => Err(ForensicError::cast_error(
                "RegValue",
                "Vec<u8>",
                compact_str::CompactString::const_new("Incompatible registry value type"),
            )),
        }
    }
}

#[cfg(test)]
mod reg_value {
    use super::{RegValue, RegValueRef, RegValueType, RegistryBuffer};

    #[test]
    fn should_convert_using_try_into() {
        let _: String = RegValue::SZ("String RegValue".to_string())
            .try_into()
            .expect("Must convert values");
        let _: String = RegValue::MultiSZ(vec!["String RegValue".to_string()])
            .try_into()
            .expect("Must convert values");
        let _: String = RegValue::ExpandSZ("String RegValue".to_string())
            .try_into()
            .expect("Must convert values");

        let _ = TryInto::<u32>::try_into(RegValue::ExpandSZ("String RegValue".to_string()))
            .expect_err("Should return error");
        let _ = TryInto::<u64>::try_into(RegValue::ExpandSZ("String RegValue".to_string()))
            .expect_err("Should return error");
        let _ = TryInto::<Vec<u8>>::try_into(RegValue::ExpandSZ("String RegValue".to_string()))
            .expect_err("Should return error");

        let _: u32 = RegValue::DWord(123)
            .try_into()
            .expect("Must convert values");
        let _: u64 = RegValue::DWord(123)
            .try_into()
            .expect("Must convert values");

        let _ = TryInto::<String>::try_into(RegValue::DWord(123)).expect_err("Should return error");
        let _ =
            TryInto::<Vec<u8>>::try_into(RegValue::DWord(123)).expect_err("Should return error");

        let _: u32 = RegValue::QWord(123)
            .clone()
            .try_into()
            .expect("Must convert values");
        let _: u64 = RegValue::QWord(123)
            .try_into()
            .expect("Must convert values");

        let _ = TryInto::<String>::try_into(RegValue::QWord(123)).expect_err("Should return error");
        let _ =
            TryInto::<Vec<u8>>::try_into(RegValue::QWord(123)).expect_err("Should return error");

        let _: Vec<u8> = RegValue::Binary((1..255).collect())
            .try_into()
            .expect("Must convert values");
        let _ = TryInto::<u32>::try_into(RegValue::Binary((1..255).collect()))
            .expect_err("Should return error");
        let _ = TryInto::<u32>::try_into(RegValue::Binary((1..255).collect()))
            .expect_err("Should return error");
        let _ = TryInto::<u32>::try_into(RegValue::Binary((1..255).collect()))
            .expect_err("Should return error");
    }

    #[test]
    fn should_serialize_sz_to_buffer() {
        let val = RegValue::SZ("Hello".to_string());
        assert_eq!(val.serialized_size(), 5);

        let mut buf = [0u8; 10];
        let written = val.write_into(&mut buf).unwrap();
        assert_eq!(written, 5);
        assert_eq!(&buf[..5], b"Hello");
    }

    #[test]
    fn should_serialize_binary_to_buffer() {
        let val = RegValue::Binary(vec![1, 2, 3, 4, 5]);
        assert_eq!(val.serialized_size(), 5);

        let mut buf = [0u8; 10];
        let written = val.write_into(&mut buf).unwrap();
        assert_eq!(written, 5);
        assert_eq!(&buf[..5], &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn should_serialize_dword_to_buffer() {
        let val = RegValue::DWord(0x12345678);
        assert_eq!(val.serialized_size(), 4);

        let mut buf = [0u8; 10];
        let written = val.write_into(&mut buf).unwrap();
        assert_eq!(written, 4);
        // Little-endian
        assert_eq!(&buf[..4], &[0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn should_serialize_qword_to_buffer() {
        let val = RegValue::QWord(0x0102030405060708);
        assert_eq!(val.serialized_size(), 8);

        let mut buf = [0u8; 16];
        let written = val.write_into(&mut buf).unwrap();
        assert_eq!(written, 8);
        // Little-endian
        assert_eq!(&buf[..8], &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn should_serialize_multisz_to_buffer() {
        let val = RegValue::MultiSZ(vec!["Hello".to_string(), "World".to_string()]);
        // "Hello\nWorld" = 11 bytes
        assert_eq!(val.serialized_size(), 11);

        let mut buf = [0u8; 20];
        let written = val.write_into(&mut buf).unwrap();
        assert_eq!(written, 11);
        assert_eq!(&buf[..11], b"Hello\nWorld");
    }

    #[test]
    fn should_error_when_buffer_too_small() {
        let val = RegValue::SZ("Hello".to_string());
        let mut buf = [0u8; 3]; // Too small
        let result = val.write_into(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn should_handle_empty_multisz() {
        let val = RegValue::MultiSZ(vec![]);
        assert_eq!(val.serialized_size(), 0);

        let mut buf = [0u8; 10];
        let written = val.write_into(&mut buf).unwrap();
        assert_eq!(written, 0);
    }

    #[test]
    fn should_write_borrowed_ref_for_string() {
        let val = RegValue::SZ("Hello".to_string());
        let mut buf = [0u8; 16];
        let view = val.write_into_ref(&mut buf).unwrap();

        match view {
            RegValueRef::SZ(s) => assert_eq!(s, "Hello"),
            _ => panic!("Expected SZ borrowed view"),
        }
    }

    #[test]
    fn should_write_borrowed_ref_for_dword() {
        let val = RegValue::DWord(0x11223344);
        let mut buf = [0u8; 8];
        let view = val.write_into_ref(&mut buf).unwrap();

        match view {
            RegValueRef::DWord(v) => assert_eq!(v, 0x11223344),
            _ => panic!("Expected DWord borrowed view"),
        }
    }

    #[test]
    fn should_store_typed_registry_buffer() {
        let mut buffer = RegistryBuffer::new();
        {
            let view = buffer
                .write_reg_value(&RegValue::ExpandSZ("%SystemRoot%".to_string()))
                .unwrap();

            assert_eq!(view.value_type(), RegValueType::ExpandSZ);
            assert_eq!(view.as_str(), Some("%SystemRoot%"));
        }

        assert_eq!(buffer.value_type(), Some(RegValueType::ExpandSZ));
        assert_eq!(buffer.as_bytes(), b"%SystemRoot%");
        assert_eq!(
            buffer.to_reg_value().unwrap(),
            RegValue::ExpandSZ("%SystemRoot%".to_string())
        );
    }

    #[test]
    fn should_reuse_registry_buffer_for_different_types() {
        let mut buffer = RegistryBuffer::with_capacity(2);

        let first = buffer
            .write_reg_value(&RegValue::Binary(vec![1, 2, 3, 4]))
            .unwrap();
        assert_eq!(first.as_binary(), Some(&[1, 2, 3, 4][..]));
        assert_eq!(buffer.value_type(), Some(RegValueType::Binary));
        assert_eq!(buffer.len(), 4);

        let second = buffer.write_reg_value(&RegValue::DWord(42)).unwrap();
        assert_eq!(second.as_dword(), Some(42));
        assert_eq!(buffer.value_type(), Some(RegValueType::DWord));
        assert_eq!(buffer.len(), 4);
        assert!(buffer.capacity() >= 4);
    }
}

/// Tests for the RFC 0001 §4.5 `RegValue` expansion (6 -> 13 variants).
#[cfg(test)]
mod reg_value_expansion {
    use super::{RegValue, RegValueRef, RegValueType};

    #[test]
    fn none_serializes_to_nothing() {
        let v = RegValue::None;
        assert_eq!(v.serialized_size(), 0);
        let mut buf = [0u8; 0];
        assert_eq!(v.write_into(&mut buf).unwrap(), 0);
        assert_eq!(v.to_string(), "");
        assert!(v.raw_bytes().is_empty());
    }

    #[test]
    fn dword_big_endian_serializes_big_endian() {
        let v = RegValue::DWordBigEndian(0x0102_0304);
        let mut buf = [0u8; 4];
        assert_eq!(v.write_into(&mut buf).unwrap(), 4);
        assert_eq!(buf, [0x01, 0x02, 0x03, 0x04]);
        assert_ne!(buf, 0x0102_0304u32.to_le_bytes());

        let mut buf2 = buf;
        let parsed = v.write_into_ref(&mut buf2).unwrap();
        assert_eq!(parsed, RegValueRef::DWordBigEndian(0x0102_0304));
    }

    #[test]
    fn dword_big_endian_converts_to_u32_and_u64() {
        let v = RegValue::DWordBigEndian(42);
        assert_eq!(TryInto::<u32>::try_into(v.clone()).unwrap(), 42);
        assert_eq!(TryInto::<u64>::try_into(v).unwrap(), 42);
    }

    #[test]
    fn link_behaves_like_a_string_value() {
        let v = RegValue::Link("C:\\Target\\Path".to_string());
        assert_eq!(v.as_str(), Some("C:\\Target\\Path"));
        assert_eq!(v.to_string(), "C:\\Target\\Path");
        let s: String = v.try_into().unwrap();
        assert_eq!(s, "C:\\Target\\Path");
    }

    #[test]
    fn resource_variants_behave_like_binary() {
        for v in [
            RegValue::ResourceList(vec![1, 2, 3]),
            RegValue::FullResourceDescriptor(vec![1, 2, 3]),
            RegValue::ResourceRequirementsList(vec![1, 2, 3]),
        ] {
            assert_eq!(v.as_binary(), Some(&[1u8, 2, 3][..]));
            assert_eq!(v.serialized_size(), 3);
            let bytes: Vec<u8> = v.clone().try_into().unwrap();
            assert_eq!(bytes, vec![1, 2, 3]);
            assert_eq!(v.raw_bytes().as_ref(), &[1u8, 2, 3][..]);
        }
    }

    #[test]
    fn unknown_preserves_type_id_and_bytes() {
        let v = RegValue::Unknown {
            ty: 0xDEAD_BEEF,
            data: vec![0xAA, 0xBB],
        };
        assert_eq!(v.value_type(), RegValueType::Unknown(0xDEAD_BEEF));
        assert_eq!(v.as_binary(), Some(&[0xAA, 0xBB][..]));
        let mut buf = [0u8; 2];
        let reff = v.write_into_ref(&mut buf).unwrap();
        assert_eq!(reff, RegValueRef::Unknown { ty: 0xDEAD_BEEF, data: &[0xAA, 0xBB] });
    }

    #[test]
    fn raw_bytes_round_trips_for_dword_and_qword() {
        assert_eq!(RegValue::DWord(0x11223344).raw_bytes().as_ref(), &0x11223344u32.to_le_bytes());
        assert_eq!(
            RegValue::DWordBigEndian(0x11223344).raw_bytes().as_ref(),
            &0x11223344u32.to_be_bytes()
        );
        assert_eq!(RegValue::QWord(0x1122334455667788).raw_bytes().as_ref(), &0x1122334455667788u64.to_le_bytes());
    }

    #[test]
    fn ref_value_type_round_trips_through_parse_bytes() {
        let v = RegValueType::Link;
        let bytes = b"C:\\Target";
        let parsed = v.parse_bytes(bytes).unwrap();
        assert_eq!(parsed, RegValueRef::Link("C:\\Target"));
    }

    #[test]
    fn regvalueref_to_owned_covers_new_variants() {
        assert_eq!(RegValueRef::None.to_owned(), RegValue::None);
        assert_eq!(
            RegValueRef::Unknown { ty: 7, data: &[1, 2] }.to_owned(),
            RegValue::Unknown { ty: 7, data: vec![1, 2] }
        );
    }
}
