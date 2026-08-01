//! Windows Registry abstraction layer.
//!
//! This module provides the core types and the [`RegistryReader`] trait for
//! decoupled, backend-agnostic registry access. An analyzer written against
//! this API works identically whether it talks to a live Windows registry,
//! a parsed hive file, or a [`crate::utils::testing::TestingRegistry`] mock
//! in a unit test — without any code changes.
//!
//! # Core Types
//!
//! | Type | Role |
//! |------|------|
//! | [`RegHiveKey`] | Root hive discriminant (`HKLM`, `HKU`, …) |
//! | [`RegKeyHandle`] | Move-only RAII handle for an opened key |
//! | [`RegValue`] | Owned registry value (allocating) |
//! | [`RegValueRef`] | Borrowed, zero-copy view into a byte buffer |
//! | [`RegistryBuffer`] | Reusable heap buffer for low-allocation reads |
//! | [`RegistryReader`] | Trait implemented by all registry backends |
//!
//! # Reading Values
//!
//! Three strategies, ordered by allocation cost:
//!
//! ```rust
//! use forensic_rs::prelude::*;
//! use forensic_rs::utils::testing::TestingRegistry;
//!
//! let reader = TestingRegistry::new();
//! let user_sid = "S-1-5-21-1366093794-4292800403-1155380978-513";
//! let key = reader.open_key(HKU, &format!(r"{}\Volatile Environment", user_sid)).unwrap();
//!
//! // 1. Owned value — simplest; allocates.
//! let val: String = reader.read_value(&key, "USERNAME").unwrap().try_into().unwrap();
//!
//! // 2. Typed helper — same allocation, ergonomic.
//! let dyn_reader: &dyn RegistryReader = &reader;
//! let val2: String = dyn_reader.read_value_as::<String>(&key, "USERNAME").unwrap();
//!
//! // 3. Reusable buffer — amortises allocation across repeated reads.
//! let mut buf = RegistryBuffer::with_capacity(256);
//! let view: RegValueRef = reader.read_value_buffered(&key, "USERNAME", &mut buf).unwrap();
//! let s: &str = view.as_str().unwrap();
//! ```
//!
//! # Handle Lifecycle
//!
//! Opened keys close automatically when they leave scope:
//!
//! ```rust
//! use forensic_rs::prelude::*;
//! use forensic_rs::utils::testing::TestingRegistry;
//!
//! let reader = TestingRegistry::new();
//! let user_sid = "S-1-5-21-1366093794-4292800403-1155380978-513";
//! let key = reader.open_key(HKU, &format!(r"{}\Volatile Environment", user_sid)).unwrap();
//! let _ = reader.read_value(&key, "USERNAME");
//! // key is closed when it drops at the end of this scope
//! ```
//!
//! # Path Convention
//!
//! The `key_path` argument to [`RegistryReader::open_key`] should be the
//! sub-path **below** the hive root, **without** a hive-name prefix:
//!
//! ```text
//! // Correct
//! reader.open_key(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
//! reader.open_key(HKU,  r"S-1-5-21-...\Volatile Environment")
//!
//! // Wrong — the hive is already supplied as the first argument
//! reader.open_key(HKLM, r"HKLM\SOFTWARE\...")
//! ```

use crate::{
    err::{BufferError, ForensicError, ForensicResult, RegistryError},
    utils::time::ForensicTimestamp,
};

use super::vfs::{VirtualFile, VirtualFileSystem};
use std::{any::Any, marker::PhantomData};

type CloseResource = dyn FnOnce(Box<dyn Any>) -> ForensicResult<()>;

/// Alias for [`RegHiveKey::HkeyClassesRoot`] (`HKEY_CLASSES_ROOT`).
pub const HKCR: RegHiveKey = RegHiveKey::HkeyClassesRoot;
/// Alias for [`RegHiveKey::HkeyCurrentConfig`] (`HKEY_CURRENT_CONFIG`).
pub const HKC: RegHiveKey = RegHiveKey::HkeyCurrentConfig;
/// Alias for [`RegHiveKey::HkeyCurrentUser`] (`HKEY_CURRENT_USER`).
pub const HKCU: RegHiveKey = RegHiveKey::HkeyCurrentUser;
/// Alias for [`RegHiveKey::HkeyLocalMachine`] (`HKEY_LOCAL_MACHINE`).
pub const HKLM: RegHiveKey = RegHiveKey::HkeyLocalMachine;
/// Alias for [`RegHiveKey::HkeyUsers`] (`HKEY_USERS`).
pub const HKU: RegHiveKey = RegHiveKey::HkeyUsers;

pub mod extra;

/// Root hive discriminant for registry operations.
///
/// Pass one of the predefined constants ([`HKLM`], [`HKU`], [`HKCU`],
/// [`HKCR`], [`HKC`]) or this enum's variants to [`RegistryReader::open_key`].
/// `Hkey(isize)` is reserved for backends that need raw handle values.
#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug)]
pub enum RegHiveKey {
    /// `HKEY_CLASSES_ROOT` — file-extension and COM class associations.
    HkeyClassesRoot,
    /// `HKEY_CURRENT_CONFIG` — hardware profile active at boot.
    HkeyCurrentConfig,
    /// `HKEY_CURRENT_USER` — settings for the currently logged-in user.
    HkeyCurrentUser,
    /// `HKEY_DYN_DATA` — legacy Windows 9x dynamic data hive.
    HkeyDynData,
    /// `HKEY_LOCAL_MACHINE` — system-wide configuration.
    HkeyLocalMachine,
    /// `HKEY_PERFORMANCE_DATA` — performance counter data (live only).
    HkeyPerformanceData,
    /// `HKEY_PERFORMANCE_NLSTEXT` — localised performance counter names.
    HkeyPerformanceNlstext,
    /// `HKEY_PERFORMANCE_TEXT` — English performance counter names.
    HkeyPerformanceText,
    /// `HKEY_USERS` — per-user profile hives (one sub-key per SID).
    HkeyUsers,
    /// Raw handle value used internally by live Windows backends.
    Hkey(isize),
}

/// Owned registry value. Allocates heap memory for variable-length data.
///
/// Use [`RegValueRef`] for a borrowed, zero-copy alternative when working
/// with a [`RegistryBuffer`].
///
/// # Conversions
///
/// `TryFrom<RegValue>` is implemented for `String`, `u32`, `u64`, and
/// `Vec<u8>`. `From<&str>`, `From<String>`, `From<u32>`, `From<u64>`,
/// `From<Vec<u8>>`, `From<Vec<String>>`, and slice variants are also
/// available to construct `RegValue` ergonomically.
#[derive(Clone, PartialEq, PartialOrd, Eq, Ord, Debug)]
pub enum RegValue {
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
    /// 64-bit unsigned integer, stored little-endian (`REG_QWORD`).
    QWord(u64),
}

/// Discriminant-only counterpart of [`RegValue`], used for typed buffer reads.
///
/// Returned by [`RegistryReader::read_raw_value_into`] to describe the type
/// of data written into a caller-supplied byte slice, without requiring an
/// allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegValueType {
    /// Raw binary data (`REG_BINARY`).
    Binary,
    /// Multi-string value (`REG_MULTI_SZ`).
    MultiSZ,
    /// Expandable string (`REG_EXPAND_SZ`).
    ExpandSZ,
    /// Plain string (`REG_SZ`).
    SZ,
    /// 32-bit little-endian integer (`REG_DWORD`).
    DWord,
    /// 64-bit little-endian integer (`REG_QWORD`).
    QWord,
}

/// Reusable heap buffer for low-allocation registry reads.
///
/// Grow-on-demand buffer that can be passed to [`RegistryReader::read_value_buffered`]
/// repeatedly across multiple key/value reads to amortise allocation cost.
/// The buffer retains both the raw bytes and the [`RegValueType`] of the last
/// successful read, so it can be re-interpreted as a [`RegValueRef`] at any
/// time via [`RegistryBuffer::as_value_ref`].
///
/// # Example
///
/// ```rust
/// use forensic_rs::prelude::*;
/// use forensic_rs::utils::testing::TestingRegistry;
///
/// let reader = TestingRegistry::new();
/// let sid = "S-1-5-21-1366093794-4292800403-1155380978-513";
/// let key = reader.open_key(HKU, &format!(r"{}\Volatile Environment", sid)).unwrap();
///
/// let mut buf = RegistryBuffer::with_capacity(256);
/// let v1 = reader.read_value_buffered(&key, "USERNAME", &mut buf).unwrap();
/// println!("{}", v1.as_str().unwrap());
/// // Reuse `buf` for the next read — no new allocation if it fits.
/// let v2 = reader.read_value_buffered(&key, "USERPROFILE", &mut buf).unwrap();
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
    /// Used by [`RegistryReader`] implementations to write directly into the buffer.
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
    /// Called by [`RegistryReader`] implementations after writing to [`writable_bytes`](Self::writable_bytes).
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
                "RegistryBuffer does not contain a registry value".into(),
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
/// Returned by low-allocation read paths such as
/// [`RegistryReader::read_value_buffered`] and
/// [`RegistryReader::read_value_ref_into`]. Variable-length variants
/// (`Binary`, `MultiSZ`, `ExpandSZ`, `SZ`) borrow from the buffer that was
/// passed to the read call, so the view cannot outlive that buffer.
///
/// Convert to an owned [`RegValue`] via [`RegValueRef::to_owned`] when
/// you need to store or move the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegValueRef<'a> {
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
    /// 64-bit little-endian integer (`REG_QWORD`).
    QWord(u64),
}

impl<'a> RegValueRef<'a> {
    pub fn value_type(&self) -> RegValueType {
        match self {
            RegValueRef::Binary(_) => RegValueType::Binary,
            RegValueRef::MultiSZ(_) => RegValueType::MultiSZ,
            RegValueRef::ExpandSZ(_) => RegValueType::ExpandSZ,
            RegValueRef::SZ(_) => RegValueType::SZ,
            RegValueRef::DWord(_) => RegValueType::DWord,
            RegValueRef::QWord(_) => RegValueType::QWord,
        }
    }

    pub fn as_str(&self) -> Option<&'a str> {
        match self {
            RegValueRef::SZ(s) | RegValueRef::ExpandSZ(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_binary(&self) -> Option<&'a [u8]> {
        match self {
            RegValueRef::Binary(v) => Some(v),
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
            RegValueRef::Binary(v) => RegValue::Binary(v.to_vec()),
            RegValueRef::MultiSZ(v) => RegValue::MultiSZ(v.iter().map(str::to_string).collect()),
            RegValueRef::ExpandSZ(v) => RegValue::ExpandSZ((*v).to_string()),
            RegValueRef::SZ(v) => RegValue::SZ((*v).to_string()),
            RegValueRef::DWord(v) => RegValue::DWord(*v),
            RegValueRef::QWord(v) => RegValue::QWord(*v),
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
            RegValue::Binary(_) => RegValueType::Binary,
            RegValue::MultiSZ(_) => RegValueType::MultiSZ,
            RegValue::ExpandSZ(_) => RegValueType::ExpandSZ,
            RegValue::SZ(_) => RegValueType::SZ,
            RegValue::DWord(_) => RegValueType::DWord,
            RegValue::QWord(_) => RegValueType::QWord,
        }
    }

    /// Returns the string value if this is an `SZ` or `ExpandSZ` variant.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            RegValue::SZ(s) | RegValue::ExpandSZ(s) => Some(s),
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

    /// Returns the binary data if this is a `Binary` variant.
    pub fn as_binary(&self) -> Option<&[u8]> {
        match self {
            RegValue::Binary(v) => Some(v),
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
    /// - `SZ`/`ExpandSZ`: UTF-8 byte length
    /// - `Binary`: byte length
    /// - `MultiSZ`: newline-separated UTF-8 strings (no trailing newline)
    /// - `DWord`: 4 bytes (as little-endian u32)
    /// - `QWord`: 8 bytes (as little-endian u64)
    pub fn serialized_size(&self) -> usize {
        match self {
            RegValue::SZ(s) | RegValue::ExpandSZ(s) => s.len(),
            RegValue::Binary(b) => b.len(),
            RegValue::MultiSZ(v) => {
                if v.is_empty() {
                    0
                } else {
                    // Calculate total size: each string as UTF-8 + newlines between them
                    v.iter().map(|s| s.len()).sum::<usize>() + (v.len() - 1) // v.len()-1 newlines
                }
            }
            RegValue::DWord(_) => 4,
            RegValue::QWord(_) => 8,
        }
    }

    /// Writes this registry value to a buffer, returning bytes written.
    ///
    /// **Serialization Format:**
    /// - `SZ`/`ExpandSZ`: UTF-8 string (no null terminator)
    /// - `Binary`: raw bytes
    /// - `MultiSZ`: newline-separated UTF-8 strings (no trailing newline, no null terminators)
    /// - `DWord`: 4 bytes (little-endian)
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
            RegValue::SZ(s) | RegValue::ExpandSZ(s) => {
                let bytes = s.as_bytes();
                buf[..bytes.len()].copy_from_slice(bytes);
                Ok(bytes.len())
            }
            RegValue::Binary(b) => {
                buf[..b.len()].copy_from_slice(b);
                Ok(b.len())
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
            RegValue::Binary(_) => Ok(RegValueRef::Binary(raw)),
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
            RegValue::QWord(_) => {
                let mut le = [0u8; 8];
                le.copy_from_slice(raw);
                Ok(RegValueRef::QWord(u64::from_le_bytes(le)))
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
            RegValueType::Binary => Ok(RegValueRef::Binary(raw)),
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
            RegValue::SZ(s) | RegValue::ExpandSZ(s) => write!(f, "{}", s),
            RegValue::DWord(v) => write!(f, "{}", v),
            RegValue::QWord(v) => write!(f, "{}", v),
            RegValue::Binary(v) => {
                for (i, b) in v.iter().enumerate() {
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
            _ => Err(ForensicError::cast_error(
                "RegValue",
                "String",
                "Incompatible registry value type".into(),
            )),
        }
    }
}
impl TryFrom<RegValue> for u32 {
    type Error = ForensicError;
    fn try_from(value: RegValue) -> Result<Self, Self::Error> {
        match value {
            RegValue::DWord(v) => Ok(v),
            RegValue::QWord(v) => Ok(v as u32),
            _ => Err(ForensicError::cast_error(
                "RegValue",
                "u32",
                "Incompatible registry value type".into(),
            )),
        }
    }
}
impl TryFrom<RegValue> for u64 {
    type Error = ForensicError;
    fn try_from(value: RegValue) -> Result<Self, Self::Error> {
        match value {
            RegValue::DWord(v) => Ok(v as u64),
            RegValue::QWord(v) => Ok(v),
            _ => Err(ForensicError::cast_error(
                "RegValue",
                "u64",
                "Incompatible registry value type".into(),
            )),
        }
    }
}
impl TryFrom<RegValue> for Vec<u8> {
    type Error = ForensicError;
    fn try_from(value: RegValue) -> Result<Self, Self::Error> {
        match value {
            RegValue::Binary(v) => Ok(v),
            _ => Err(ForensicError::cast_error(
                "RegValue",
                "Vec<u8>",
                "Incompatible registry value type".into(),
            )),
        }
    }
}

impl std::fmt::Display for RegHiveKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegHiveKey::HkeyClassesRoot => write!(f, "HKEY_CLASSES_ROOT"),
            RegHiveKey::HkeyCurrentConfig => write!(f, "HKEY_CURRENT_CONFIG"),
            RegHiveKey::HkeyCurrentUser => write!(f, "HKEY_CURRENT_USER"),
            RegHiveKey::HkeyDynData => write!(f, "HKEY_CURRENT_USER_LOCAL_SETTINGS"),
            RegHiveKey::HkeyLocalMachine => write!(f, "HKEY_LOCAL_MACHINE"),
            RegHiveKey::HkeyPerformanceData => write!(f, "HKEY_PERFORMANCE_DATA"),
            RegHiveKey::HkeyPerformanceNlstext => write!(f, "HKEY_PERFORMANCE_NLSTEXT"),
            RegHiveKey::HkeyPerformanceText => write!(f, "HKEY_PERFORMANCE_TEXT"),
            RegHiveKey::HkeyUsers => write!(f, "HKEY_USERS"),
            RegHiveKey::Hkey(v) => write!(f, "Hkey({})", v),
        }
    }
}

// ============================================================================
// NEW TYPES FOR REDESIGNED API
// ============================================================================

/// Options for opening registry keys (live Windows backend).
/// For hive/offline backends, these options are best-effort or ignored.
#[derive(Clone, Debug)]
pub struct RegistryOpenOptions {
    pub access: RegistryAccess,
    pub wow64_view: Option<Wow64View>,
}

/// Registry access rights (live Windows only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryAccess {
    Read,
    ReadWrite,
    All,
}

/// WOW64 registry view selection (live Windows only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wow64View {
    Bits32,
    Bits64,
}

impl Default for RegistryOpenOptions {
    fn default() -> Self {
        Self {
            access: RegistryAccess::Read,
            wow64_view: None,
        }
    }
}

/// Controls whether a registry enumeration visitor continues or stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryVisit {
    /// Continue enumerating additional names.
    Continue,
    /// Stop successfully without treating the early exit as an error.
    Break,
}

/// Opened registry key handle. Move-only, closes on drop.
/// For live Windows backend: not Send + not Sync to enforce thread-confinement.
///
/// Handles are opaque to the user:
/// - Live Windows: wraps HKEY
/// - Hive/offline: wraps backend-specific identifier
///
/// Calling `close()` explicitly or allowing it to drop both close the handle.
/// Closing twice is safe (idempotent).
pub struct RegKeyHandle {
    resource: Option<Box<dyn Any>>,
    close: Option<Box<CloseResource>>,
    access_path: Option<String>,
    _phantom: PhantomData<*mut ()>, // Non-Send + Non-Sync
}

impl RegKeyHandle {
    /// Creates a new opened key handle (internal use by implementations).
    #[doc(hidden)]
    pub fn new<T, F>(resource: T, close: F) -> Self
    where
        T: Any,
        F: FnOnce(T) -> ForensicResult<()> + 'static,
    {
        let close = move |resource: Box<dyn Any>| match resource.downcast::<T>() {
            Ok(resource) => close(*resource),
            Err(_) => Err(ForensicError::registry_invalid_handle(0)),
        };
        Self {
            resource: Some(Box::new(resource)),
            close: Some(Box::new(close)),
            access_path: None,
            _phantom: PhantomData,
        }
    }

    /// Attach an internal authorization path to this handle.
    #[doc(hidden)]
    pub fn with_access_path(mut self, path: impl Into<String>) -> Self {
        self.access_path = Some(path.into());
        self
    }

    /// Return the internal authorization path attached by a guarded reader.
    #[doc(hidden)]
    pub fn access_path(&self) -> Option<&str> {
        self.access_path.as_deref()
    }

    /// Returns this handle's backend-specific resource.
    ///
    /// Backends must request the same resource type used to construct the
    /// handle. A mismatch indicates a handle from another backend.
    #[doc(hidden)]
    pub fn resource<T: Any>(&self) -> ForensicResult<&T> {
        self.resource
            .as_deref()
            .and_then(|resource| resource.downcast_ref::<T>())
            .ok_or_else(|| ForensicError::registry_invalid_handle(0))
    }

    /// Closes this key handle early.
    ///
    /// This consumes the handle, so its drop implementation cannot close the
    /// underlying backend resource a second time.
    #[doc(hidden)]
    pub fn close(mut self) -> ForensicResult<()> {
        match (self.resource.take(), self.close.take()) {
            (Some(resource), Some(close)) => close(resource),
            (None, None) => Ok(()),
            _ => Err(ForensicError::registry_invalid_handle(0)),
        }
    }
}

impl std::fmt::Debug for RegKeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegKeyHandle")
            .field(
                "resource_type",
                &self
                    .resource
                    .as_ref()
                    .map(|resource| std::any::type_name_of_val(&**resource)),
            )
            .field("closed", &self.close.is_none())
            .finish()
    }
}

impl Drop for RegKeyHandle {
    fn drop(&mut self) {
        if let (Some(resource), Some(close)) = (self.resource.take(), self.close.take()) {
            let _ = close(resource);
        }
    }
}

// Explicitly not impl Clone, Copy to enforce move-only semantics

/// Converts a [`RegValue`] into a typed Rust value.
///
/// Implemented for `String`, `u32`, `u64`, `bool`, and `Vec<u8>`/`Vec<String>`.
/// Used by [`RegistryReader::read_value_as`] to provide a type-safe,
/// single-call read-and-convert API.
///
/// Implement this trait on your own types to extend the typed read API.
pub trait FromRegistryValue: Sized {
    /// Performs the conversion, returning `Err` if `value` has an incompatible type.
    fn from_reg_value(value: RegValue) -> ForensicResult<Self>;
}

impl FromRegistryValue for String {
    fn from_reg_value(value: RegValue) -> ForensicResult<Self> {
        value.try_into()
    }
}

impl FromRegistryValue for u32 {
    fn from_reg_value(value: RegValue) -> ForensicResult<Self> {
        value.try_into()
    }
}

impl FromRegistryValue for u64 {
    fn from_reg_value(value: RegValue) -> ForensicResult<Self> {
        value.try_into()
    }
}

impl FromRegistryValue for Vec<String> {
    fn from_reg_value(value: RegValue) -> ForensicResult<Self> {
        match value {
            RegValue::MultiSZ(v) => Ok(v),
            RegValue::SZ(s) => Ok(vec![s]),
            RegValue::ExpandSZ(s) => Ok(vec![s]),
            _ => Err(ForensicError::cast_error(
                "RegValue",
                "Vec<String>",
                "Incompatible registry value type".into(),
            )),
        }
    }
}

impl FromRegistryValue for bool {
    fn from_reg_value(value: RegValue) -> ForensicResult<Self> {
        match value {
            RegValue::DWord(v) => Ok(v != 0),
            RegValue::QWord(v) => Ok(v != 0),
            _ => Err(ForensicError::cast_error(
                "RegValue",
                "bool",
                "Incompatible registry value type".into(),
            )),
        }
    }
}

impl FromRegistryValue for Vec<u8> {
    fn from_reg_value(value: RegValue) -> ForensicResult<Self> {
        value.try_into()
    }
}

/// Metadata about an open registry key, analogous to `RegQueryInfoKey`.
///
/// Returned by [`RegistryReader::key_info`]. Use the counts to pre-allocate
/// buffers before enumerating subkeys or values.
#[derive(Clone, Copy, Debug, Default)]
pub struct RegistryKeyInfo {
    /// Number of direct subkeys.
    pub subkeys: u32,
    /// Length of the longest subkey name, in characters (excluding null terminator).
    pub max_subkey_name_length: u32,
    /// Number of values in this key.
    pub values: u32,
    /// Length of the longest value name, in characters (excluding null terminator).
    pub max_value_name_length: u32,
    /// Size of the largest value data, in bytes.
    pub max_value_length: u32,
    /// Timestamp of the last write to this key.
    pub last_write_time: ForensicTimestamp,
}

/// Reader trait for Windows registry (live, hive-based, or mocked).
///
/// # Thread-Confinement Contract
/// Implementations are thread-confined: a single reader instance should not be shared
/// across threads. Opened key handles are move-only and close on drop.
/// Cross-thread usage should be orchestrated at a higher level if needed.
///
/// # Interior Mutability
/// All trait methods use `&self` (not `&mut self`). Implementations use interior mutability
/// (Cell/RefCell) to manage mutable state like handle caches and counters. This enables
/// use with trait objects (`dyn RegistryReader`) which don't support mutable methods.
///
/// # Handle Lifecycle
/// - `open_key()` and variants return a `RegKeyHandle` that owns the handle.
/// - Handles are closed when dropped, or earlier with [`RegKeyHandle::close`].
/// - A handle closes its backend resource exactly once.
/// - A handle owns the cleanup state needed for its backend resource.
///
/// # Reading Values
/// - Use `read_value_buffered()` for low-allocation access into a reusable buffer.
/// - Use `read_value()` when you explicitly need an owned `RegValue`.
/// - Use `read_value_as::<T>()` for type-safe conversion.
pub trait RegistryReader {
    /// Opens a registry key from a root hive.
    /// Returns a move-only handle that closes on drop.
    fn open_key(&self, hive: RegHiveKey, key_path: &str) -> ForensicResult<RegKeyHandle>;

    /// Opens a registry key with options (access rights, WOW64 view for live registry).
    /// Options are best-effort for hive backends; they may be ignored.
    fn open_key_with_options(
        &self,
        hive: RegHiveKey,
        key_path: &str,
        options: &RegistryOpenOptions,
    ) -> ForensicResult<RegKeyHandle> {
        // Default implementation ignores options and delegates to open_key
        let _ = options;
        self.open_key(hive, key_path)
    }

    /// Opens a subkey under an already-opened parent key.
    fn open_subkey(&self, parent: &RegKeyHandle, subkey: &str) -> ForensicResult<RegKeyHandle>;

    /// Reads a registry value by name into an owned representation.
    ///
    /// This allocates only when the caller explicitly asks for ownership.
    fn read_value(&self, key: &RegKeyHandle, value_name: &str) -> ForensicResult<RegValue> {
        let mut buffer = RegistryBuffer::new();
        {
            let _ = self.read_value_buffered(key, value_name, &mut buffer)?;
        }
        buffer.to_reg_value()
    }

    /// Reads the size of a registry value without reading its data (low-allocation).
    /// Useful for pre-allocating buffers or querying data size.
    fn read_value_size(&self, key: &RegKeyHandle, value_name: &str) -> ForensicResult<usize> {
        let mut empty: [u8; 0] = [];
        match self.read_raw_value_into(key, value_name, &mut empty) {
            Ok((_, written)) => Ok(written),
            Err(ForensicError::Buffer(BufferError::TooSmall { required, .. })) => Ok(required),
            Err(err) => Err(err),
        }
    }

    /// Reads a registry value directly into a caller-provided byte buffer.
    ///
    /// This is the primitive low-allocation registry read operation.
    /// Implementations should write directly into `buf` and return the registry value
    /// type along with the number of bytes written.
    fn read_raw_value_into(
        &self,
        key: &RegKeyHandle,
        value_name: &str,
        buf: &mut [u8],
    ) -> ForensicResult<(RegValueType, usize)>;

    /// Reads a registry value directly into a buffer.
    /// Returns the number of bytes written, or an error if the buffer is too small.
    /// The error includes the required buffer size.
    fn read_value_into(
        &self,
        key: &RegKeyHandle,
        value_name: &str,
        buf: &mut [u8],
    ) -> ForensicResult<usize> {
        let (_, written) = self.read_raw_value_into(key, value_name, buf)?;
        Ok(written)
    }

    /// Reads a registry value into a buffer and returns a typed borrowed view.
    ///
    /// The returned `RegValueRef` may borrow from `buf`, so it cannot outlive the buffer.
    fn read_value_ref_into<'a>(
        &self,
        key: &RegKeyHandle,
        value_name: &str,
        buf: &'a mut [u8],
    ) -> ForensicResult<RegValueRef<'a>> {
        let (value_type, written) = self.read_raw_value_into(key, value_name, buf)?;
        value_type.parse_bytes(&buf[..written])
    }

    /// Reads a registry value into a reusable, resizeable buffer.
    ///
    /// The buffer stores the serialized bytes and the last registry value type.
    /// The returned `RegValueRef` borrows from `buffer`, allowing repeated reads
    /// without forcing the caller to manage raw slices manually.
    fn read_value_buffered<'a>(
        &self,
        key: &RegKeyHandle,
        value_name: &str,
        buffer: &'a mut RegistryBuffer,
    ) -> ForensicResult<RegValueRef<'a>> {
        if buffer.capacity() == 0 {
            buffer.resize(64);
            buffer.set_len(0);
            buffer.set_value_type(None);
        }

        loop {
            match self.read_raw_value_into(key, value_name, buffer.writable_bytes()) {
                Ok((value_type, written)) => {
                    buffer.commit_write(written, value_type);
                    return buffer.as_value_ref();
                }
                Err(ForensicError::Buffer(BufferError::TooSmall { required, .. })) => {
                    let next_capacity = required.max(buffer.capacity().saturating_mul(2)).max(1);
                    buffer.resize(next_capacity);
                    buffer.set_len(0);
                    buffer.set_value_type(None);
                }
                Err(err) => return Err(err),
            }
        }
    }

    /// Checks if a value exists without reading its data (low-allocation operation).
    fn value_exists(&self, key: &RegKeyHandle, value_name: &str) -> ForensicResult<bool> {
        match self.read_value_size(key, value_name) {
            Ok(_) => Ok(true),
            Err(ForensicError::Registry(RegistryError::ValueNotFound { .. })) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Enumerates subkeys using a visitor callback (streaming, low-allocation).
    /// The callback returns [`RegistryVisit::Continue`] to continue,
    /// [`RegistryVisit::Break`] to stop successfully, or `Err(_)` to fail.
    fn enumerate_keys(
        &self,
        key: &RegKeyHandle,
        visitor: &mut dyn FnMut(&str) -> ForensicResult<RegistryVisit>,
    ) -> ForensicResult<()>;

    /// Enumerates values using a visitor callback (streaming, low-allocation).
    /// The callback returns [`RegistryVisit::Continue`] to continue,
    /// [`RegistryVisit::Break`] to stop successfully, or `Err(_)` to fail.
    fn enumerate_values(
        &self,
        key: &RegKeyHandle,
        visitor: &mut dyn FnMut(&str) -> ForensicResult<RegistryVisit>,
    ) -> ForensicResult<()>;

    /// Retrieves metadata about a key (emulates RegQueryInfoKey).
    fn key_info(&self, key: &RegKeyHandle) -> ForensicResult<RegistryKeyInfo>;

    /// Mounts a registry reader from a hive file.
    fn mount_file(&self, file: Box<dyn VirtualFile>) -> ForensicResult<Box<dyn RegistryReader>>;

    /// Mounts a registry reader from a filesystem.
    fn mount_fs(&self, fs: Box<dyn VirtualFileSystem>) -> ForensicResult<Box<dyn RegistryReader>>;

    /// Get the same value as the env var "%SystemRoot%". Usually "C:\Windows".
    fn get_system_root(&self) -> ForensicResult<String> {
        let key = self.open_key(
            RegHiveKey::HkeyLocalMachine,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        )?;
        let value = self.read_value(&key, "SystemRoot")?;
        value.try_into()
    }

    /// Get the current Windows build number.
    fn windows_build(&self) -> ForensicResult<u32> {
        let key = self.open_key(
            RegHiveKey::HkeyLocalMachine,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        )?;
        let value = self.read_value(&key, "CurrentBuild")?;
        value.try_into()
    }

    /// Returns all user SIDs from `HKEY_USERS`, excluding `_Classes` keys.
    fn list_users(&self) -> ForensicResult<Vec<String>> {
        let key = self.open_key(RegHiveKey::HkeyUsers, "")?;
        let mut users = Vec::new();
        self.enumerate_keys(&key, &mut |name| {
            if name.starts_with("S-") && !name.ends_with("_Classes") {
                users.push(name.to_string());
            }
            Ok(RegistryVisit::Continue)
        })?;
        Ok(users)
    }
}

impl dyn RegistryReader + '_ {
    /// Typed read: automatically converts RegValue to target type.
    pub fn read_value_as<T: FromRegistryValue>(
        &self,
        key: &RegKeyHandle,
        value_name: &str,
    ) -> ForensicResult<T> {
        let raw = self.read_value(key, value_name)?;
        T::from_reg_value(raw)
    }

    /// Reads a string value (SZ, ExpandSZ, or MultiSZ) directly into a buffer as UTF-8.
    /// Returns bytes written or error if buffer too small.
    pub fn read_value_str_into(
        &self,
        key: &RegKeyHandle,
        value_name: &str,
        buf: &mut [u8],
    ) -> ForensicResult<usize> {
        match self.read_value_ref_into(key, value_name, buf)? {
            RegValueRef::SZ(s) | RegValueRef::ExpandSZ(s) => Ok(s.len()),
            RegValueRef::MultiSZ(v) => Ok(v.as_str().len()),
            _ => Err(ForensicError::cast_error(
                "RegValue",
                "&str",
                "Registry value is not a string type".into(),
            )),
        }
    }

    /// Reads binary data directly into a buffer.
    /// Only works for Binary registry values. Returns error for other types.
    pub fn read_value_binary_into(
        &self,
        key: &RegKeyHandle,
        value_name: &str,
        buf: &mut [u8],
    ) -> ForensicResult<usize> {
        match self.read_value_ref_into(key, value_name, buf)? {
            RegValueRef::Binary(b) => Ok(b.len()),
            _ => Err(ForensicError::cast_error(
                "RegValue",
                "Binary",
                "Registry value is not binary type".into(),
            )),
        }
    }

    /// Recursively walks registry keys, ignoring inaccessible descendants.
    ///
    /// This convenience method is best-effort. Use [`Self::walk_keys_strict`]
    /// when every child-open and descendant-enumeration error matters.
    pub fn walk_keys(
        &self,
        root: RegHiveKey,
        visitor: &mut dyn FnMut(&str, &RegKeyHandle) -> ForensicResult<()>,
    ) -> ForensicResult<()> {
        self.walk_keys_best_effort(root, visitor)
    }

    /// Recursively walks registry keys, ignoring inaccessible descendants.
    ///
    /// The visitor receives each child path and handle. Errors enumerating the
    /// root and errors returned by the visitor still propagate to the caller.
    pub fn walk_keys_best_effort(
        &self,
        root: RegHiveKey,
        visitor: &mut dyn FnMut(&str, &RegKeyHandle) -> ForensicResult<()>,
    ) -> ForensicResult<()> {
        let root_key = self.open_key(root, "")?;
        self.walk_keys_recursive(&root_key, "", visitor, false)?;
        Ok(())
    }

    /// Recursively walks registry keys, propagating every traversal error.
    ///
    /// Use this mode when an inaccessible key must remain distinguishable from
    /// an empty key in forensic output.
    pub fn walk_keys_strict(
        &self,
        root: RegHiveKey,
        visitor: &mut dyn FnMut(&str, &RegKeyHandle) -> ForensicResult<()>,
    ) -> ForensicResult<()> {
        let root_key = self.open_key(root, "")?;
        self.walk_keys_recursive(&root_key, "", visitor, true)
    }

    fn walk_keys_recursive(
        &self,
        parent: &RegKeyHandle,
        path_prefix: &str,
        visitor: &mut dyn FnMut(&str, &RegKeyHandle) -> ForensicResult<()>,
        strict: bool,
    ) -> ForensicResult<()> {
        let mut subkeys = Vec::new();
        self.enumerate_keys(parent, &mut |name| {
            subkeys.push(name.to_string());
            Ok(RegistryVisit::Continue)
        })?;

        for subkey_name in subkeys {
            let full_path = if path_prefix.is_empty() {
                subkey_name.clone()
            } else {
                format!("{}\\{}", path_prefix, subkey_name)
            };

            match self.open_subkey(parent, &subkey_name) {
                Ok(child_key) => {
                    visitor(&full_path, &child_key)?;
                    if strict {
                        self.walk_keys_recursive(&child_key, &full_path, visitor, true)?;
                    } else {
                        let _ = self.walk_keys_recursive(&child_key, &full_path, visitor, false);
                    }
                }
                Err(err) if strict => return Err(err),
                Err(_) => {}
            }
        }
        Ok(())
    }

    /// Recursively walks keys starting from an already-opened key handle.
    ///
    /// Useful when you want to walk from a subkey you've already opened,
    /// rather than from a hive root. The visitor receives the relative path
    /// from `root` and a reference to the opened child key.
    pub fn walk_keys_from(
        &self,
        root: &RegKeyHandle,
        visitor: &mut dyn FnMut(&str, &RegKeyHandle) -> ForensicResult<()>,
    ) -> ForensicResult<()> {
        self.walk_keys_recursive(root, "", visitor, false)
    }
}

#[cfg(test)]
mod reg_value {
    use crate::{
        err::{ForensicError, ForensicResult},
        traits::registry::{RegistryKeyInfo, RegistryReader},
        utils::testing::TestingRegistry,
    };

    use super::{RegValue, RegValueRef, RegValueType, RegistryBuffer, RegistryVisit};

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

    #[test]
    fn should_read_value_into_registry_buffer() {
        let reader = TestingRegistry::new();
        let key = reader
            .open_key(
                crate::traits::registry::RegHiveKey::HkeyUsers,
                r"HKU\S-1-5-21-1366093794-4292800403-1155380978-513\Volatile Environment",
            )
            .expect("Must open test key");
        let mut buffer = RegistryBuffer::with_capacity(4);

        {
            let view = reader
                .read_value_buffered(&key, "USERPROFILE", &mut buffer)
                .expect("Buffered read must succeed");

            assert_eq!(view.as_str(), Some("C:\\Users\\Tester"));
        }

        assert_eq!(buffer.value_type(), Some(RegValueType::SZ));
        assert_eq!(
            buffer.to_reg_value().unwrap(),
            RegValue::SZ("C:\\Users\\Tester".to_string())
        );
        assert_eq!(buffer.as_bytes(), b"C:\\Users\\Tester");
    }

    #[test]
    fn should_generate_dummy_registry_reader() {
        struct RegReader {}
        impl RegistryReader for RegReader {
            fn open_key(
                &self,
                _hkey: crate::traits::registry::RegHiveKey,
                _key_name: &str,
            ) -> crate::err::ForensicResult<crate::traits::registry::RegKeyHandle> {
                Ok(crate::traits::registry::RegKeyHandle::new(0isize, |_| {
                    Ok(())
                }))
            }

            fn open_subkey(
                &self,
                _parent: &crate::traits::registry::RegKeyHandle,
                _subkey: &str,
            ) -> crate::err::ForensicResult<crate::traits::registry::RegKeyHandle> {
                Ok(crate::traits::registry::RegKeyHandle::new(0isize, |_| {
                    Ok(())
                }))
            }

            fn read_value(
                &self,
                _hkey: &crate::traits::registry::RegKeyHandle,
                _value_name: &str,
            ) -> crate::err::ForensicResult<RegValue> {
                Ok(RegValue::SZ("123".to_string()))
            }

            fn read_raw_value_into(
                &self,
                _key: &crate::traits::registry::RegKeyHandle,
                _value_name: &str,
                buf: &mut [u8],
            ) -> crate::err::ForensicResult<(RegValueType, usize)> {
                let raw = b"123";
                if buf.len() < raw.len() {
                    return Err(ForensicError::buffer_too_small(
                        raw.len(),
                        buf.len(),
                        "RegValue::SZ",
                    ));
                }
                buf[..raw.len()].copy_from_slice(raw);
                Ok((RegValueType::SZ, raw.len()))
            }

            fn enumerate_keys(
                &self,
                _key: &crate::traits::registry::RegKeyHandle,
                visitor: &mut dyn FnMut(&str) -> ForensicResult<RegistryVisit>,
            ) -> ForensicResult<()> {
                if visitor("123")? == RegistryVisit::Break {
                    return Ok(());
                }
                Ok(())
            }

            fn enumerate_values(
                &self,
                _key: &crate::traits::registry::RegKeyHandle,
                visitor: &mut dyn FnMut(&str) -> ForensicResult<RegistryVisit>,
            ) -> ForensicResult<()> {
                if visitor("123")? == RegistryVisit::Break {
                    return Ok(());
                }
                Ok(())
            }

            fn key_info(
                &self,
                _hkey: &crate::traits::registry::RegKeyHandle,
            ) -> ForensicResult<crate::traits::registry::RegistryKeyInfo> {
                Ok(RegistryKeyInfo::default())
            }

            fn mount_file(
                &self,
                _file: Box<dyn crate::traits::vfs::VirtualFile>,
            ) -> crate::err::ForensicResult<Box<dyn RegistryReader>> {
                Ok(Box::new(RegReader {}))
            }

            fn mount_fs(
                &self,
                _fs: Box<dyn crate::traits::vfs::VirtualFileSystem>,
            ) -> crate::err::ForensicResult<Box<dyn RegistryReader>> {
                Ok(Box::new(RegReader {}))
            }
        }

        let reader = RegReader {};
        let reader: Box<dyn RegistryReader> = Box::new(reader);
        fn tst(reg: &dyn RegistryReader) -> ForensicResult<()> {
            let key = reg.open_key(crate::traits::registry::RegHiveKey::HkeyClassesRoot, "")?;
            assert_eq!("123", reg.read_value_as::<String>(&key, "test")?);

            // Test buffer read
            let mut buf = [0u8; 10];
            let bytes = reg.read_value_into(&key, "test", &mut buf)?;
            assert_eq!(bytes, 3);
            assert_eq!(&buf[..3], b"123");

            // Test ergonomic borrowed read
            let mut borrowed_buf = [0u8; 10];
            let view = reg.read_value_ref_into(&key, "test", &mut borrowed_buf)?;
            assert_eq!(view.as_str(), Some("123"));

            Ok(())
        }
        tst(&*reader).unwrap();
    }

    #[test]
    fn should_use_direct_raw_buffer_path_without_owned_value() {
        struct DirectBufferReader;

        impl RegistryReader for DirectBufferReader {
            fn open_key(
                &self,
                _hkey: crate::traits::registry::RegHiveKey,
                _key_name: &str,
            ) -> crate::err::ForensicResult<crate::traits::registry::RegKeyHandle> {
                Ok(crate::traits::registry::RegKeyHandle::new(7isize, |_| {
                    Ok(())
                }))
            }

            fn open_subkey(
                &self,
                _parent: &crate::traits::registry::RegKeyHandle,
                _subkey: &str,
            ) -> crate::err::ForensicResult<crate::traits::registry::RegKeyHandle> {
                Ok(crate::traits::registry::RegKeyHandle::new(8isize, |_| {
                    Ok(())
                }))
            }

            fn read_value(
                &self,
                _hkey: &crate::traits::registry::RegKeyHandle,
                _value_name: &str,
            ) -> crate::err::ForensicResult<RegValue> {
                panic!("read_value should not be used when read_raw_value_into is overridden")
            }

            fn read_raw_value_into(
                &self,
                _key: &crate::traits::registry::RegKeyHandle,
                _value_name: &str,
                buf: &mut [u8],
            ) -> crate::err::ForensicResult<(RegValueType, usize)> {
                let raw = b"direct-path";
                if buf.len() < raw.len() {
                    return Err(ForensicError::buffer_too_small(
                        raw.len(),
                        buf.len(),
                        "RegValue::SZ",
                    ));
                }
                buf[..raw.len()].copy_from_slice(raw);
                Ok((RegValueType::SZ, raw.len()))
            }

            fn enumerate_keys(
                &self,
                _key: &crate::traits::registry::RegKeyHandle,
                visitor: &mut dyn FnMut(&str) -> ForensicResult<RegistryVisit>,
            ) -> ForensicResult<()> {
                if visitor("child")? == RegistryVisit::Break {
                    return Ok(());
                }
                Ok(())
            }

            fn enumerate_values(
                &self,
                _key: &crate::traits::registry::RegKeyHandle,
                visitor: &mut dyn FnMut(&str) -> ForensicResult<RegistryVisit>,
            ) -> ForensicResult<()> {
                if visitor("value")? == RegistryVisit::Break {
                    return Ok(());
                }
                Ok(())
            }

            fn key_info(
                &self,
                _hkey: &crate::traits::registry::RegKeyHandle,
            ) -> ForensicResult<crate::traits::registry::RegistryKeyInfo> {
                Ok(RegistryKeyInfo::default())
            }

            fn mount_file(
                &self,
                _file: Box<dyn crate::traits::vfs::VirtualFile>,
            ) -> crate::err::ForensicResult<Box<dyn RegistryReader>> {
                Ok(Box::new(DirectBufferReader))
            }

            fn mount_fs(
                &self,
                _fs: Box<dyn crate::traits::vfs::VirtualFileSystem>,
            ) -> crate::err::ForensicResult<Box<dyn RegistryReader>> {
                Ok(Box::new(DirectBufferReader))
            }
        }

        let reader = DirectBufferReader;
        let key = reader
            .open_key(crate::traits::registry::RegHiveKey::HkeyClassesRoot, "")
            .unwrap();
        let mut buffer = RegistryBuffer::with_capacity(2);

        {
            let value = reader
                .read_value_buffered(&key, "demo", &mut buffer)
                .unwrap();
            assert_eq!(value.as_str(), Some("direct-path"));
        }

        assert_eq!(buffer.value_type(), Some(RegValueType::SZ));
        assert_eq!(buffer.as_bytes(), b"direct-path");
        assert!(buffer.capacity() >= b"direct-path".len());
    }

    #[test]
    fn should_remove_handle_mapping_on_explicit_close() {
        let reader = TestingRegistry::new();
        let key = reader
            .open_key(
                crate::traits::registry::RegHiveKey::HkeyUsers,
                r"HKU\S-1-5-21-1366093794-4292800403-1155380978-513\Volatile Environment",
            )
            .expect("Must open test key");

        let handle_id = *key.resource::<isize>().unwrap();
        assert!(reader.cached.lock().unwrap().contains_key(&handle_id));

        key.close().expect("Must close key");
        assert!(!reader.cached.lock().unwrap().contains_key(&handle_id));
    }

    #[test]
    fn should_close_key_when_handle_drops() {
        let reader = TestingRegistry::new();
        let handle_id;

        {
            let key = reader
                .open_key(
                    crate::traits::registry::RegHiveKey::HkeyUsers,
                    r"HKU\S-1-5-21-1366093794-4292800403-1155380978-513\Volatile Environment",
                )
                .expect("Must open test key");
            handle_id = *key.resource::<isize>().unwrap();
            assert!(reader.cached.lock().unwrap().contains_key(&handle_id));
        }

        assert!(!reader.cached.lock().unwrap().contains_key(&handle_id));
    }

    #[test]
    fn testing_registry_should_reject_mounting_a_filesystem() {
        let reader = TestingRegistry::new();
        let err = match reader.mount_fs(Box::new(crate::core::fs::StdVirtualFS::new())) {
            Ok(_) => panic!("TestingRegistry must not fabricate a mounted registry"),
            Err(err) => err,
        };

        assert!(format!("{}", err).contains("mount_fs is not supported"));
    }

    #[test]
    fn should_enumerate_values_with_callback() {
        let reader = TestingRegistry::new();
        let key = reader
            .open_key(
                crate::traits::registry::RegHiveKey::HkeyUsers,
                r"HKU\S-1-5-21-1366093794-4292800403-1155380978-513\Volatile Environment",
            )
            .expect("Must open test key");

        let mut names = Vec::new();
        reader
            .enumerate_values(&key, &mut |name| {
                names.push(name.to_string());
                Ok(RegistryVisit::Continue)
            })
            .expect("Callback enumeration must succeed");

        assert!(names.iter().any(|v| v == "USERPROFILE"));
        assert!(names.iter().any(|v| v == "APPDATA"));
        assert!(names.iter().any(|v| v == "LOCALAPPDATA"));
    }

    #[test]
    fn should_return_false_only_for_missing_value() {
        let reader = TestingRegistry::new();
        let key = reader
            .open_key(
                crate::traits::registry::RegHiveKey::HkeyUsers,
                r"HKU\S-1-5-21-1366093794-4292800403-1155380978-513\Volatile Environment",
            )
            .expect("Must open test key");

        assert!(!reader.value_exists(&key, "MissingValue").unwrap());

        let invalid_key =
            crate::traits::registry::RegKeyHandle::new("other-backend".to_string(), |_| Ok(()));
        assert!(reader.value_exists(&invalid_key, "USERPROFILE").is_err());
    }

    #[test]
    fn should_stop_enumeration_with_successful_break() {
        let reader = TestingRegistry::new();
        let key = reader
            .open_key(
                crate::traits::registry::RegHiveKey::HkeyUsers,
                r"HKU\S-1-5-21-1366093794-4292800403-1155380978-513\Volatile Environment",
            )
            .expect("Must open test key");
        let mut visited = 0usize;

        reader
            .enumerate_values(&key, &mut |_| {
                visited += 1;
                Ok(RegistryVisit::Break)
            })
            .expect("A successful break must not return an error");

        assert_eq!(visited, 1);
    }

    #[test]
    fn should_distinguish_strict_and_best_effort_walks() {
        struct TraversalReader;

        impl RegistryReader for TraversalReader {
            fn open_key(
                &self,
                _hive: crate::traits::registry::RegHiveKey,
                _key_path: &str,
            ) -> ForensicResult<crate::traits::registry::RegKeyHandle> {
                Ok(crate::traits::registry::RegKeyHandle::new(0isize, |_| {
                    Ok(())
                }))
            }

            fn open_subkey(
                &self,
                _parent: &crate::traits::registry::RegKeyHandle,
                subkey: &str,
            ) -> ForensicResult<crate::traits::registry::RegKeyHandle> {
                if subkey == "inaccessible" {
                    return Err(ForensicError::other("test", "inaccessible key".to_string()));
                }
                Ok(crate::traits::registry::RegKeyHandle::new(1isize, |_| {
                    Ok(())
                }))
            }

            fn read_raw_value_into(
                &self,
                _key: &crate::traits::registry::RegKeyHandle,
                _value_name: &str,
                _buf: &mut [u8],
            ) -> ForensicResult<(RegValueType, usize)> {
                Err(ForensicError::other("test", "not used".to_string()))
            }

            fn enumerate_keys(
                &self,
                key: &crate::traits::registry::RegKeyHandle,
                visitor: &mut dyn FnMut(&str) -> ForensicResult<RegistryVisit>,
            ) -> ForensicResult<()> {
                if *key.resource::<isize>()? == 0 {
                    if visitor("available")? == RegistryVisit::Break {
                        return Ok(());
                    }
                    let _ = visitor("inaccessible")?;
                }
                Ok(())
            }

            fn enumerate_values(
                &self,
                _key: &crate::traits::registry::RegKeyHandle,
                _visitor: &mut dyn FnMut(&str) -> ForensicResult<RegistryVisit>,
            ) -> ForensicResult<()> {
                Ok(())
            }

            fn key_info(
                &self,
                _key: &crate::traits::registry::RegKeyHandle,
            ) -> ForensicResult<RegistryKeyInfo> {
                Ok(RegistryKeyInfo::default())
            }

            fn mount_file(
                &self,
                _file: Box<dyn crate::traits::vfs::VirtualFile>,
            ) -> ForensicResult<Box<dyn RegistryReader>> {
                Ok(Box::new(TraversalReader))
            }

            fn mount_fs(
                &self,
                _fs: Box<dyn crate::traits::vfs::VirtualFileSystem>,
            ) -> ForensicResult<Box<dyn RegistryReader>> {
                Ok(Box::new(TraversalReader))
            }
        }

        let reader = TraversalReader;
        let dyn_reader: &dyn RegistryReader = &reader;
        let mut best_effort_paths = Vec::new();
        dyn_reader
            .walk_keys_best_effort(crate::traits::registry::HKU, &mut |path, _| {
                best_effort_paths.push(path.to_string());
                Ok(())
            })
            .expect("Best-effort traversal must ignore inaccessible descendants");
        assert_eq!(best_effort_paths, vec!["available"]);

        let err = dyn_reader
            .walk_keys_strict(crate::traits::registry::HKU, &mut |_, _| Ok(()))
            .expect_err("Strict traversal must report inaccessible descendants");
        assert!(format!("{}", err).contains("inaccessible key"));
    }

    #[test]
    fn should_stop_enumeration_when_callback_returns_error() {
        let reader = TestingRegistry::new();
        let key = reader
            .open_key(
                crate::traits::registry::RegHiveKey::HkeyUsers,
                r"HKU\S-1-5-21-1366093794-4292800403-1155380978-513\Volatile Environment",
            )
            .expect("Must open test key");

        let mut visited = 0usize;
        let err = reader
            .enumerate_values(&key, &mut |_name| {
                visited += 1;
                Err(ForensicError::other(
                    "test",
                    "stop-on-first-callback-error".to_string(),
                ))
            })
            .expect_err("Enumeration must propagate callback error");

        assert_eq!(visited, 1);
        let err_text = format!("{}", err);
        assert!(err_text.contains("stop-on-first-callback-error"));
    }

    #[test]
    fn should_list_users_from_hku() {
        let reader = TestingRegistry::new();
        let users = reader.list_users().expect("list_users must succeed");
        assert!(
            users.iter().any(|s| s.starts_with("S-1-5-")),
            "Expected at least one SID; got: {:?}",
            users
        );
        for user in &users {
            assert!(user.starts_with("S-"), "Non-SID entry: {}", user);
            assert!(
                !user.ends_with("_Classes"),
                "Classes suffix leaked: {}",
                user
            );
        }
    }
}
