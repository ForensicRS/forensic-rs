/*!
# ForensicRS Error System

This module provides a comprehensive error handling system designed specifically for forensic artifact parsing.
The error system is optimized for memory efficiency and provides rich contextual information.

## Design Principles

1. **Memory Efficient**: Uses `SCow` (Static Copy-On-Write) to minimize allocations
2. **Contextual**: Each error provides detailed information about what went wrong and where
3. **Categorized**: Errors are grouped by their domain (Buffer, Format, Compression, etc.)
4. **Type Safe**: Strongly typed error variants prevent misuse

## Error Categories

- **Buffer**: Memory access and bounds checking errors
- **Format**: File format validation and parsing errors  
- **Compression**: Compression/decompression algorithm errors
- **DataAccess**: File system and data access errors
- **Registry**: Windows registry-specific errors
- **Cast**: Type conversion and casting errors
- **Timestamp**: Time validation errors
- **Io**: Standard I/O operations
- **Other**: Generic fallback errors

## Usage Examples

```rust
use forensic_rs::prelude::*;

// Buffer errors with detailed context
if buffer.len() < required_size {
    return Err(ForensicError::buffer_too_small(required_size, buffer.len(), "PE header"));
}

// Format errors with artifact context
if magic != b"MZ" {
    return Err(ForensicError::invalid_magic("PE", "MZ", format!("{:?}", magic)));
}

// Registry errors with path context  
if let None = registry.get_value(&key_path, &value_name) {
    return Err(ForensicError::registry_value_not_found(key_path, value_name));
}

// Using helper macros
ensure_buffer_size!(buffer, offset, size_of::<u32>(), "DWORD");
ensure_format!(signature == 0x12345678, "custom_format", "invalid signature");
```

## Helper Macros

The error system includes convenient macros for common validation patterns:

- `ensure_buffer_size!`: Validates buffer bounds  
- `ensure_buffer_range!`: Validates buffer ranges
- `ensure_format!`: Validates format conditions
- `ensure_version!`: Validates version numbers
- `ensure_min_length!`: Validates minimum lengths
- `ensure_max_length!`: Validates maximum lengths

## Constructor Methods Summary

### Buffer Errors
- `buffer_too_small()`: Not enough data in buffer
- `buffer_out_of_bounds()`: Position beyond buffer bounds  
- `buffer_invalid_range()`: Invalid range parameters

### Format Errors
- `invalid_format()`: General format validation failure
- `invalid_version()`: Version mismatch
- `invalid_magic()`: Magic bytes/signature mismatch
- `format_corrupted()`: Data corruption at specific location

### Compression Errors  
- `compression_error()`: Algorithm-specific errors
- `invalid_offset()`: Invalid offset in compressed data
- `too_big()` / `too_small()`: Size validation failures

### Data Access Errors
- `missing_data()`: Expected data not found
- `file_size_error()`: File size limit exceeded  
- `path_not_found()`: Filesystem path doesn't exist
- `access_denied()`: Permission denied

### Registry Errors
- `registry_key_not_found()`: Registry key doesn't exist
- `registry_value_not_found()`: Registry value doesn't exist  
- `registry_invalid_type()`: Wrong registry value type
- `registry_cell_error()`: Registry cell parsing error
- `registry_hive_error()`: Registry hive parsing error

### Cast Errors
- `cast_error()`: General type conversion failure
- `value_out_of_range()`: Value too large/small for target type

### Timestamp Errors
- `illegal_timestamp()`: Invalid timestamp value
- `timestamp_out_of_range()`: Timestamp outside valid range

### I/O Errors  
- `io_error()`: Standard I/O error with context

### Generic Errors
- `other()`: Uncategorized errors (use sparingly)
- `no_more_data()`: End of iteration

See individual method documentation for detailed usage examples and parameters.
*/

/// Type alias for Results that may return forensic parsing errors
pub type ForensicResult<T> = Result<T, ForensicError>;

impl<T> Into<ForensicResult<T>> for ForensicError {
    fn into(self) -> ForensicResult<T> {
        Err(self)
    }
}

// Macro for creating buffer bounds checking errors
#[macro_export]
macro_rules! ensure_buffer_size {
    ($buffer:expr, $pos:expr, $size:expr, $data_type:literal) => {
        if $pos + $size > $buffer.len() {
            return Err($crate::err::ForensicError::buffer_too_small(
                $pos + $size, 
                $buffer.len(), 
                $data_type
            ));
        }
    };
}

// Macro for creating buffer range validation
#[macro_export]
macro_rules! ensure_buffer_range {
    ($buffer:expr, $start:expr, $end:expr) => {
        if $end > $buffer.len() || $start > $end {
            return Err($crate::err::ForensicError::buffer_invalid_range(
                $start, 
                $end, 
                $buffer.len()
            ));
        }
    };
}

// Macro for creating format validation errors
#[macro_export]
macro_rules! ensure_format {
    ($condition:expr, $artifact:literal, $reason:literal) => {
        if !$condition {
            return Err($crate::err::ForensicError::invalid_format($artifact, $reason));
        }
    };
}

/// Macro for ensuring a value is at least X size: 
/// 
/// length >= min_length
/// 
/// ensure_min_length!(min_length, length, operation);
/// ```rust
/// fn test() -> forensic_rs::err::ForensicResult<()> {
///     forensic_rs::ensure_min_length!(10, 20, "20 >= 20");
///     forensic_rs::ensure_min_length!(10, 10, "10 >= 10");
///     forensic_rs::ensure_min_length!(10,  5, "5 !>= 10");
///     Ok(())
/// }
/// assert!(test().unwrap_err().to_string().contains("5 !>= 10"))
/// ```
#[macro_export]
macro_rules! ensure_min_length {
    ($min_length:expr, $length:expr, $operation:literal) => {
        if ($length as usize) < ($min_length as usize) {
            return Err($crate::err::ForensicError::too_small($operation, $length as _, $min_length as _));
        }
    };
}

/// Macro for ensuring a value is less than a maximum
/// 
/// length < max_length
/// 
/// ensure_max_length!(max_length, length, operation);
/// ```rust
/// fn test() -> forensic_rs::err::ForensicResult<()> {
///     
///     forensic_rs::ensure_max_length!(10, 9, "10 > 9");
///     forensic_rs::ensure_max_length!(10,  5, "10 > 5");
///     forensic_rs::ensure_max_length!(10, 20, "10 !> 20");
///     Ok(())
/// }
/// assert!(test().unwrap_err().to_string().contains("10 !> 20"))
/// ```
#[macro_export]
macro_rules! ensure_max_length {
    ($max_length:literal, $length:literal, $operation:literal) => {
        if ($length as usize) >= ($max_length as usize)  {
            return Err($crate::err::ForensicError::too_big($operation, $length, $max_length));
        }
    };
}

// Macro for creating version validation errors
#[macro_export]
macro_rules! ensure_version {
    ($found:expr, $expected:expr, $artifact:literal) => {
        if $found != $expected {
            return Err($crate::err::ForensicError::invalid_version($artifact, $expected, $found));
        }
    };
}

// Macro for creating compression errors
#[macro_export]
macro_rules! compression_error {
    ($algorithm:literal, $reason:literal) => {
        $crate::err::ForensicError::compression_error($algorithm, $reason)
    };
}

// Macro for invalid offset errors
#[macro_export]
macro_rules! invalid_offset {
    ($operation:literal, $offset:expr, $file_size:expr) => {
        $crate::err::ForensicError::invalid_offset($operation, $offset, $file_size)
    };
}

// Macro for missing data errors
#[macro_export]
macro_rules! missing_data {
    ($data_type:literal, $context:literal) => {
        $crate::err::ForensicError::missing_data($data_type, $context)
    };
}

// Macro for registry errors
#[macro_export]
macro_rules! registry_key_not_found {
    ($key_path:expr) => {
        $crate::err::ForensicError::registry_key_not_found($key_path)
    };
}

#[macro_export]
macro_rules! registry_value_not_found {
    ($key_path:expr, $value_name:expr) => {
        $crate::err::ForensicError::registry_value_not_found($key_path, $value_name)
    };
}


use crate::{prelude::RegHiveKey, scow::SCow};

/// The main error type for forensic artifact parsing operations.
///
/// `ForensicError` provides a comprehensive error handling system optimized for forensic
/// analysis workflows. Each variant contains structured information about the error
/// context, making debugging and error handling more effective.
///
/// ## Error Categories
///
/// ### Buffer Errors
/// The most common errors in binary parsing. These occur when reading data from buffers.
/// - Use `buffer_too_small()` when not enough data is available
/// - Use `buffer_out_of_bounds()` when accessing beyond buffer limits
/// - Use `buffer_invalid_range()` when range parameters are invalid
///
/// ### Format Errors  
/// Errors related to file format validation and parsing.
/// - Use `invalid_format()` for general format validation failures
/// - Use `invalid_version()` when file version doesn't match expectations
/// - Use `invalid_magic()` when magic bytes/signatures don't match
/// - Use `format_corrupted()` when data appears corrupted at a specific location
///
/// ### Compression Errors
/// Errors during compression/decompression operations.
/// - Use `compression_error()` for algorithm-specific issues
/// - Use `invalid_offset()` for offset validation in compressed data
/// - Use `too_big()`/`too_small()` for size validation
///
/// ### Data Access Errors
/// File system and data availability errors.
/// - Use `missing_data()` when expected data is not found
/// - Use `file_size_error()` when file size constraints are violated
/// - Use `path_not_found()` for missing file paths
/// - Use `access_denied()` for permission issues
///
/// ### Registry Errors
/// Windows registry-specific errors with rich context.
/// - Use `registry_key_not_found()` for missing registry keys
/// - Use `registry_value_not_found()` for missing registry values  
/// - Use `registry_invalid_value_type()` for type validation
///
/// ### Cast Errors
/// Type conversion and casting failures.
/// - Use `cast_error()` for general conversion issues
/// - Use `value_out_of_range()` when values don't fit target types
///
/// ### Timestamp Errors
/// Time validation and conversion errors.
/// - Use `illegal_timestamp()` for invalid timestamp values
/// - Use `timestamp_out_of_range()` for timestamps outside valid ranges
///
/// ## Usage Examples
///
/// ```rust
/// use forensic_rs::prelude::*;
///
/// // Buffer validation
/// fn parse_header(data: &[u8]) -> ForensicResult<Header> {
///     if data.len() < 16 {
///         return Err(ForensicError::buffer_too_small(16, data.len(), "file_header"));
///     }
///     // ... parsing logic
/// }
///
/// // Format validation
/// fn validate_pe_signature(data: &[u8]) -> ForensicResult<()> {
///     if &data[0..2] != b"MZ" {
///         return Err(ForensicError::invalid_magic("PE", "MZ", 
///             format!("{:02X}{:02X}", data[0], data[1])));
///     }
///     Ok(())
/// }
///
/// // Registry operations
/// fn get_install_date(reg: &Registry) -> ForensicResult<u32> {
///     reg.get_value("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "InstallDate")
///         .ok_or_else(|| ForensicError::registry_value_not_found(
///             "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion".into(),
///             "InstallDate".into()
///         ))
/// }
/// ```
#[derive(Debug)]
pub enum ForensicError {
    /// Buffer access and bounds checking errors
    /// 
    /// These are the most common errors in binary parsing, occurring when there's
    /// insufficient data or invalid memory access patterns.
    Buffer(BufferError),
    
    /// File format validation and parsing errors
    /// 
    /// Used when parsing structured data formats like PE files, registry hives, etc.
    Format(FormatError),
    
    /// Compression and decompression errors
    /// 
    /// Errors from compression algorithms like LZNT1, Xpress, etc.
    Compression(CompressionError),
    
    /// File system and data access errors
    /// 
    /// Issues with file availability, permissions, and data retrieval.
    DataAccess(DataAccessError),
    
    /// Windows registry-specific errors
    /// 
    /// Specialized errors for registry operations with rich contextual information.
    Registry(RegistryError),
    
    /// Type conversion and casting errors
    /// 
    /// Failures when converting between different data types.
    Cast(CastError),
    
    /// Timestamp validation and conversion errors
    /// 
    /// Issues with time-related data parsing and validation.
    Timestamp(TimestampError),
    
    /// Standard I/O operation errors
    /// 
    /// Wrapper for `std::io::Error` with additional context.
    Io {
        /// The underlying I/O error kind
        kind: std::io::ErrorKind,
        /// Additional context about the operation that failed
        context: SCow,
    },
    
    /// Generic fallback for uncategorized errors
    /// 
    /// Use this sparingly - prefer specific error types when possible.
    Other {
        /// Category identifier for the error type
        category: &'static str,
        /// Human-readable error message
        message: String,
    },
}

/// Buffer access and bounds checking errors
///
/// These errors occur during binary data parsing when there are memory access issues.
/// They provide detailed information about buffer sizes and access patterns to help
/// with debugging parsing logic.
///
/// ## Usage Examples
///
/// ```rust
/// use forensic_rs::prelude::*;
///
/// fn read_u32(data: &[u8], offset: usize) -> ForensicResult<u32> {
///     if offset + 4 > data.len() {
///         return Err(ForensicError::buffer_too_small(
///             offset + 4, data.len(), "u32 value"
///         ));
///     }
///     Ok(u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]))
/// }
///
/// fn validate_range(data: &[u8], start: usize, end: usize) -> ForensicResult<()> {
///     if end > data.len() || start > end {
///         return Err(ForensicError::buffer_invalid_range(start, end, data.len()));
///     }
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BufferError {
    /// Buffer doesn't contain enough data for the requested operation
    ///
    /// This is the most common buffer error, occurring when trying to read
    /// more data than is available in the buffer.
    TooSmall {
        /// Number of bytes required for the operation
        required: usize,
        /// Number of bytes actually available in the buffer
        available: usize,
        /// Description of the data type being read (e.g., "PE header", "DWORD")
        data_type: &'static str,
    },
    
    /// Attempted to access buffer at position beyond its bounds
    ///
    /// Used when a specific position is accessed that exceeds the buffer size.
    OutOfBounds {
        /// The position that was accessed
        position: usize,
        /// The actual size of the buffer
        buffer_size: usize,
    },
    
    /// Invalid range specification for buffer access
    ///
    /// Used when range parameters don't make sense (e.g., start > end, 
    /// or range extends beyond buffer).
    InvalidRange {
        /// Start position of the range
        start: usize,
        /// End position of the range  
        end: usize,
        /// The actual size of the buffer
        buffer_size: usize,
    },
}

impl std::fmt::Display for BufferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BufferError::TooSmall { required, available, data_type } => {
                write!(f, "Buffer too small for {}: need {} bytes, only {} available", 
                       data_type, required, available)
            },
            BufferError::OutOfBounds { position, buffer_size } => {
                write!(f, "Buffer access out of bounds: position {} exceeds buffer size {}", 
                       position, buffer_size)
            },
            BufferError::InvalidRange { start, end, buffer_size } => {
                write!(f, "Invalid buffer range [{}, {}): exceeds buffer size {}", 
                       start, end, buffer_size)
            },
        }
    }
}

/// File format validation and parsing errors
///
/// These errors occur when parsing structured file formats. They provide context
/// about which artifact type was being parsed and what validation failed.
///
/// ## Usage Examples
///
/// ```rust
/// use forensic_rs::prelude::*;
///
/// fn parse_pe_header(data: &[u8]) -> ForensicResult<PEHeader> {
///     // Check magic bytes
///     if &data[0..2] != b"MZ" {
///         return Err(ForensicError::invalid_magic("PE", "MZ", 
///             format!("{:02X} {:02X}", data[0], data[1])));
///     }
///     
///     // Check version
///     let version = u16::from_le_bytes([data[4], data[5]]);
///     if version != 0x014C {
///         return Err(ForensicError::invalid_version("PE", 0x014C, version as u32));
///     }
///     
///     // Check for corruption
///     let checksum_pos = 64;
///     if data.len() < checksum_pos + 4 {
///         return Err(ForensicError::format_corrupted("PE", checksum_pos as u64, 
///             "Missing checksum field".into()));
///     }
///     
///     Ok(PEHeader { /* ... */ })
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    /// General format validation failure
    ///
    /// Use this for format-specific validation that doesn't fit other categories.
    Invalid {
        /// Type of artifact being parsed (e.g., "PE", "registry_hive", "prefetch")
        artifact_type: &'static str,
        /// Detailed description of what validation failed
        reason: SCow,
    },
    
    /// File version doesn't match expectations
    ///
    /// Used when the file version field doesn't match what the parser expects.
    InvalidVersion {
        /// Type of artifact being parsed
        artifact_type: &'static str,
        /// The version number expected by the parser
        expected: u32,
        /// The version number found in the file
        found: u32,
    },
    
    /// Magic bytes/signature doesn't match expectations
    ///
    /// Used when file signatures or magic values don't match the expected format.
    InvalidMagic {
        /// Type of artifact being parsed
        artifact_type: &'static str,
        /// The expected magic bytes/signature
        expected: &'static str,
        /// The actual magic bytes found in the file
        found: SCow,
    },
    
    /// Data appears corrupted at a specific location
    ///
    /// Used when the file structure suggests corruption or truncation.
    Corrupted {
        /// Type of artifact being parsed
        artifact_type: &'static str,
        /// Byte position where corruption was detected
        position: u64,
        /// Description of the corruption detected
        reason: SCow,
    },
}



impl std::fmt::Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FormatError::Invalid { artifact_type, reason } => {
                write!(f, "Invalid {} format: {}", artifact_type, reason)
            },
            FormatError::InvalidVersion { artifact_type, expected, found } => {
                write!(f, "Invalid {} version: expected {}, found {}", 
                       artifact_type, expected, found)
            },
            FormatError::InvalidMagic { artifact_type, expected, found } => {
                write!(f, "Invalid {} magic bytes: expected '{}', found '{}'", 
                       artifact_type, expected, found)
            },
            FormatError::Corrupted { artifact_type, position, reason } => {
                write!(f, "Corrupted {} at position {}: {}", 
                       artifact_type, position, reason)
            },
        }
    }
}

/// Compression and decompression algorithm errors
///
/// These errors occur when working with compressed data using algorithms like
/// LZNT1, Xpress, Xpress Huffman, etc. They provide context about the specific
/// algorithm and operation that failed.
///
/// ## Usage Examples
///
/// ```rust
/// use forensic_rs::prelude::*;
///
/// fn decompress_lznt1(compressed: &[u8], output: &mut [u8]) -> ForensicResult<usize> {
///     if compressed.len() < 4 {
///         return Err(ForensicError::too_small("LZNT1 decompression", 
///             compressed.len() as u64, 4));
///     }
///     
///     let offset = read_offset_from_header(compressed)?;
///     if offset < 0 || offset as u64 > compressed.len() as u64 {
///         return Err(ForensicError::invalid_offset("LZNT1 decompression", 
///             offset, compressed.len() as u64));
///     }
///     
///     // ... decompression logic
///     Ok(output.len())
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressionError {
    /// Algorithm-specific error during compression/decompression
    ///
    /// Use this for errors specific to compression algorithms that don't fit
    /// other categories.
    AlgorithmError {
        /// Name of the compression algorithm (e.g., "LZNT1", "Xpress", "XpressHuff")
        algorithm: &'static str,
        /// Detailed description of the algorithm error
        reason: SCow,
    },
    
    /// Invalid offset encountered during compression operations
    ///
    /// Used when offset values in compressed data are invalid or out of bounds.
    InvalidOffset {
        /// Description of the operation being performed
        operation: &'static str,
        /// The invalid offset value (can be negative)
        offset: i64,
        /// Size of the file/buffer being processed
        file_size: u64,
    },
    
    /// Length value exceeds maximum allowed
    ///
    /// Used when compression parameters or data lengths are too large.
    TooBig {
        /// Description of the operation being performed
        operation: &'static str,
        /// The length value that was too large
        length: u64,
        /// Maximum allowed length
        max_length: u64,
    },
    
    /// Length value is below minimum required
    ///
    /// Used when compression parameters or data lengths are too small.
    TooSmall {
        /// Description of the operation being performed  
        operation: &'static str,
        /// The length value that was too small
        length: u64,
        /// Minimum required length
        min_length: u64,
    },
}

impl std::fmt::Display for CompressionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompressionError::AlgorithmError { algorithm, reason } => {
                write!(f, "{} compression error: {}", algorithm, reason)
            },
            CompressionError::InvalidOffset { operation, offset, file_size } => {
                write!(f, "Invalid offset {} during {} (file size: {})", 
                       offset, operation, file_size)
            },
            CompressionError::TooBig { operation, length, max_length } => {
                write!(f, "Invalid length {} during {}: exceeds maximum {}", 
                       length, operation, max_length)
            },
            CompressionError::TooSmall { operation, length, min_length } => {
                write!(f, "Invalid length {} during {}: less than minimum {}", 
                       length, operation, min_length)
            },
        }
    }
}

/// Data access and file system operation errors
///
/// These errors occur when accessing files, directories, or other data sources.
/// They provide context about what resource was being accessed and why it failed.
///
/// ## Usage Examples
///
/// ```rust
/// use forensic_rs::prelude::*;
///
/// fn load_file(path: &str) -> ForensicResult<Vec<u8>> {
///     let metadata = std::fs::metadata(path)
///         .map_err(|_| ForensicError::path_not_found(path))?;
///     
///     if metadata.len() > 100_000_000 {
///         return Err(ForensicError::file_size_error("file_loading", 
///             100_000_000, metadata.len()));
///     }
///     
///     std::fs::read(path)
///         .map_err(|_| ForensicError::access_denied(path.into(), 
///             "Permission denied".into()))
/// }
///
/// fn parse_directory_entries(entries: &[u8]) -> ForensicResult<Vec<Entry>> {
///     if entries.is_empty() {
///         return Err(ForensicError::missing_data("directory_entries", 
///             "Directory contains no entries".into()));
///     }
///     // ... parsing logic
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataAccessError {
    /// Expected data is missing or not found
    ///
    /// Use this when data that should exist is not available.
    Missing {
        /// Type of data that was expected (e.g., "file", "registry_key", "metadata")
        data_type: &'static str,
        /// Additional context about what was missing and where
        context: SCow,
    },
    
    /// File size exceeds allowed limits
    ///
    /// Used when files are larger than expected or allowed by the parser.
    FileSizeExceeded {
        /// Description of the operation that has size limits
        operation: &'static str,
        /// Maximum allowed file size
        max_size: u64,
        /// Actual size of the file
        actual_size: u64,
    },
    
    /// File or directory path not found
    ///
    /// Used when filesystem paths don't exist.
    PathNotFound {
        /// The path that was not found
        path: String,
    },
    
    /// Access denied to a resource
    ///
    /// Used when permission issues prevent accessing a resource.
    AccessDenied {
        /// The resource that couldn't be accessed
        resource: SCow,
        /// Additional context about the access denial
        context: SCow,
    },
    
    /// No more data available for iteration
    ///
    /// Used when iterating over data sources and reaching the end.
    NoMoreData
}

impl std::fmt::Display for DataAccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataAccessError::Missing { data_type, context } => {
                write!(f, "Missing {}: {}", data_type, context)
            },
            DataAccessError::FileSizeExceeded { operation, max_size, actual_size } => {
                write!(f, "File size error during {}: {} bytes exceeds maximum {}", 
                       operation, actual_size, max_size)
            },
            DataAccessError::PathNotFound { path } => {
                write!(f, "Path not found: {}", path)
            },
            DataAccessError::AccessDenied { resource, context } => {
                write!(f, "Access denied to {}: {}", resource, context)
            },
            DataAccessError::NoMoreData => {
                write!(f, "No more content/data/files")
            },
        }
    }
}

/// Windows registry-specific errors with rich contextual information
///
/// These errors provide detailed context for registry operations, including
/// hive keys, paths, and value names to make debugging easier.
///
/// ## Usage Examples
///
/// ```rust
/// use forensic_rs::prelude::*;
///
/// fn get_windows_version(registry: &Registry) -> ForensicResult<String> {
///     let key = RegHiveKey::HKEY_LOCAL_MACHINE;
///     let path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
///     let value_name = "ProductName";
///     
///     registry.get_value(key, path, value_name)
///         .ok_or_else(|| ForensicError::registry_value_not_found(
///             key, Some(path.into()), value_name.into()
///         ))
/// }
///
/// fn validate_registry_cell(data: &[u8], offset: u64) -> ForensicResult<()> {
///     if data.len() < 8 {
///         return Err(ForensicError::Registry(RegistryError::CellStructure {
///             cell_type: "key_node",
///             offset,
///             expected_type: "NK cell with minimum 8 bytes"
///         }));
///     }
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// Registry key not found at the specified path
    ///
    /// Used when attempting to access a registry key that doesn't exist.
    KeyNotFound {
        /// The registry hive key (e.g., HKEY_LOCAL_MACHINE)
        key : RegHiveKey,
        /// Optional sub-path within the hive
        key_path: Option<SCow>,
    },
    
    /// Registry value not found within a key
    ///
    /// Used when attempting to access a registry value that doesn't exist.
    ValueNotFound {
        /// The registry hive key where the value was expected
        key : RegHiveKey,
        /// Optional sub-path within the hive  
        key_path: Option<SCow>,
        /// Name of the value that was not found
        value_name: SCow,
    },
    
    /// Registry value has wrong data type
    ///
    /// Used when a registry value exists but has a different type than expected.
    InvalidValueType {
        /// The expected registry value type (e.g., "REG_DWORD", "REG_SZ")
        expected: &'static str,
        /// The actual type found in the registry
        found: SCow,
    },
    
    /// Invalid registry handle encountered
    ///
    /// Used when registry handle values are invalid or corrupted.
    InvalidHandle { 
        /// The invalid handle value
        handle : i64 
    },
    
    /// Registry cell structure validation failed
    ///
    /// Used when parsing registry hive cells and the structure is invalid.
    CellStructure {
        /// Type of registry cell being parsed (e.g., "key_node", "value_node")
        cell_type: &'static str,
        /// Offset in the hive where the error occurred
        offset: u64,
        /// Description of the expected cell structure
        expected_type: &'static str,
    },
}

impl From<RegistryError> for ForensicError {
    fn from(value: RegistryError) -> Self {
        ForensicError::Registry(value)
    }
}
impl<T> From<RegistryError> for ForensicResult<T> {
    fn from(value: RegistryError) -> Self {
        Err(ForensicError::Registry(value))
    }
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::KeyNotFound { key, key_path } => {
                match key_path {
                    Some(v) => write!(f, "Registry key not found: {}\\{}", key, v),
                    None => write!(f, "Registry key not found: {}", key)
                }
            },
            RegistryError::ValueNotFound { key, key_path, value_name } => {
                match key_path {
                    Some(v) => write!(f, "Registry value {} not found: {}\\{}",value_name, key, v),
                    None => write!(f, "Registry value {} not found: {}",value_name, key),
                }
            },
            RegistryError::InvalidValueType { expected, found } => {
                write!(f, "Invalid registry value type: expected {}, found {}", 
                       expected, found)
            },
            RegistryError::InvalidHandle {handle} => {
                write!(f, "Invalid handle {}", handle)
            },
            RegistryError::CellStructure { cell_type, offset, expected_type } => {
                write!(f, "Invalid {} type at offset={}. Expected {}", 
                       cell_type, offset, expected_type)
            },
        }
    }
}

/// Type conversion and casting errors
///
/// These errors occur when converting between different data types, especially
/// when parsing binary data or converting registry values.
///
/// ## Usage Examples
///
/// ```rust
/// use forensic_rs::prelude::*;
///
/// fn registry_value_to_u32(value: &RegistryValue) -> ForensicResult<u32> {
///     match value {
///         RegistryValue::DWord(val) => Ok(*val),
///         RegistryValue::QWord(val) => {
///             if *val > u32::MAX as u64 {
///                 Err(ForensicError::value_out_of_range(val.to_string().into(), "u32"))
///             } else {
///                 Ok(*val as u32)
///             }
///         },
///         other => Err(ForensicError::cast_error("RegistryValue", "u32", 
///             format!("Cannot convert {:?} to u32", other).into()))
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CastError {
    /// General type conversion failure
    ///
    /// Used when types are fundamentally incompatible for conversion.
    InvalidConversion {
        /// The source type name
        from_type: &'static str,
        /// The target type name
        to_type: &'static str,
        /// Explanation of why the conversion failed
        reason: SCow,
    },
    
    /// Value is outside the valid range for the target type
    ///
    /// Used when the value could theoretically be converted but is too large/small.
    ValueOutOfRange {
        /// The value that couldn't be converted (as string)
        value: SCow,
        /// The target type that couldn't accommodate the value
        target_type: &'static str,
    },
}

impl std::fmt::Display for CastError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CastError::InvalidConversion { from_type, to_type, reason } => {
                write!(f, "Cannot cast from {} to {}: {}", from_type, to_type, reason)
            },
            CastError::ValueOutOfRange { value, target_type } => {
                write!(f, "Value '{}' is out of range for type {}", value, target_type)
            },
        }
    }
}

/// Timestamp validation and conversion errors
///
/// These errors occur when working with time-related data in forensic artifacts.
/// Timestamps are common in many file formats and registry entries.
///
/// ## Usage Examples
///
/// ```rust
/// use forensic_rs::prelude::*;
///
/// fn parse_filetime(filetime: u64) -> ForensicResult<SystemTime> {
///     // FILETIME epoch is January 1, 1601
///     let filetime_epoch = 116444736000000000u64; // 100-nanosecond intervals
///     
///     if filetime < filetime_epoch {
///         return Err(ForensicError::illegal_timestamp(filetime, 
///             "FILETIME before epoch (1601-01-01)".into()));
///     }
///     
///     let unix_timestamp = (filetime - filetime_epoch) / 10_000_000;
///     if unix_timestamp > i64::MAX as u64 {
///         return Err(ForensicError::timestamp_out_of_range(
///             unix_timestamp, 0, i64::MAX as u64));
///     }
///     
///     // ... conversion logic
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimestampError {
    /// Timestamp value is invalid or malformed
    ///
    /// Used when timestamp values don't make sense or are corrupted.
    Invalid {
        /// The invalid timestamp value
        timestamp: u64,
        /// Explanation of why the timestamp is invalid
        reason: SCow,
    },
    
    /// Timestamp is outside acceptable range
    ///
    /// Used when timestamp values are too large or small for the context.
    OutOfRange {
        /// The out-of-range timestamp value
        timestamp: u64,
        /// Minimum acceptable timestamp value
        min: u64,
        /// Maximum acceptable timestamp value  
        max: u64,
    },
}

impl std::fmt::Display for TimestampError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimestampError::Invalid { timestamp, reason } => {
                write!(f, "Invalid timestamp {}: {}", timestamp, reason)
            },
            TimestampError::OutOfRange { timestamp, min, max } => {
                write!(f, "Timestamp {} out of range [{}, {}]", timestamp, min, max)
            },
        }
    }
}

impl ForensicError {
    /// Creates a "no more data" error for iteration scenarios
    ///
    /// Use this when iterating over data sources and reaching the end.
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn next_entry(&mut self) -> ForensicResult<Entry> {
    ///     if self.position >= self.data.len() {
    ///         return Err(ForensicError::no_more_data());
    ///     }
    ///     // ... return next entry
    /// }
    /// ```
    pub fn no_more_data() -> Self {
        Self::DataAccess(DataAccessError::NoMoreData)
    }
    
    // ========================================================================
    // Buffer Error Constructors
    // ========================================================================
    
    /// Creates a buffer too small error
    ///
    /// Use this when attempting to read more data than is available in a buffer.
    ///
    /// # Parameters
    /// - `required`: Number of bytes needed for the operation
    /// - `available`: Number of bytes actually available
    /// - `data_type`: Description of what was being read (e.g., "PE header", "u32")
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn read_header(data: &[u8]) -> ForensicResult<Header> {
    ///     if data.len() < 64 {
    ///         return Err(ForensicError::buffer_too_small(64, data.len(), "file header"));
    ///     }
    ///     // ... parse header
    /// }
    /// ```
    pub fn buffer_too_small(required: usize, available: usize, data_type: &'static str) -> Self {
        Self::Buffer(BufferError::TooSmall { required, available, data_type })
    }
    
    /// Creates a buffer out of bounds error
    ///
    /// Use this when accessing a specific position beyond the buffer's bounds.
    ///
    /// # Parameters
    /// - `position`: The position that was accessed
    /// - `buffer_size`: The actual size of the buffer
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn read_at_offset(data: &[u8], offset: usize) -> ForensicResult<u8> {
    ///     if offset >= data.len() {
    ///         return Err(ForensicError::buffer_out_of_bounds(offset, data.len()));
    ///     }
    ///     Ok(data[offset])
    /// }
    /// ```
    pub fn buffer_out_of_bounds(position: usize, buffer_size: usize) -> Self {
        Self::Buffer(BufferError::OutOfBounds { position, buffer_size })
    }
    
    /// Creates a buffer invalid range error
    ///
    /// Use this when range parameters don't make sense (start > end, range too large, etc.).
    ///
    /// # Parameters
    /// - `start`: Start position of the invalid range
    /// - `end`: End position of the invalid range
    /// - `buffer_size`: The actual size of the buffer
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn read_range(data: &[u8], start: usize, end: usize) -> ForensicResult<&[u8]> {
    ///     if end > data.len() || start > end {
    ///         return Err(ForensicError::buffer_invalid_range(start, end, data.len()));
    ///     }
    ///     Ok(&data[start..end])
    /// }
    /// ```
    pub fn buffer_invalid_range(start: usize, end: usize, buffer_size: usize) -> Self {
        Self::Buffer(BufferError::InvalidRange { start, end, buffer_size })
    }
    
    // ========================================================================
    // Format Error Constructors  
    // ========================================================================
    
    /// Creates a general format validation error
    ///
    /// Use this for format-specific validation that doesn't fit other categories.
    ///
    /// # Parameters
    /// - `artifact_type`: Type of artifact being parsed (e.g., "PE", "prefetch")
    /// - `reason`: Detailed description of the validation failure
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn validate_pe_sections(sections: &[Section]) -> ForensicResult<()> {
    ///     if sections.is_empty() {
    ///         return Err(ForensicError::invalid_format("PE", "No sections found"));
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub fn invalid_format(artifact_type: &'static str, reason: impl Into<SCow>) -> Self {
        Self::Format(FormatError::Invalid { artifact_type, reason : reason.into() })
    }
    
    /// Creates a version mismatch error
    ///
    /// Use this when file versions don't match parser expectations.
    ///
    /// # Parameters
    /// - `artifact_type`: Type of artifact being parsed
    /// - `expected`: The version number expected by the parser
    /// - `found`: The version number found in the file
    ///
    /// # Examples  
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn parse_prefetch(data: &[u8]) -> ForensicResult<Prefetch> {
    ///     let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    ///     if version != 30 {
    ///         return Err(ForensicError::invalid_version("prefetch", 30, version));
    ///     }
    ///     // ... continue parsing
    /// }
    /// ```
    pub fn invalid_version(artifact_type: &'static str, expected: u32, found: u32) -> Self {
        Self::Format(FormatError::InvalidVersion { artifact_type, expected, found })
    }
    
    /// Creates a magic bytes/signature mismatch error
    ///
    /// Use this when file signatures don't match expected values.
    ///
    /// # Parameters
    /// - `artifact_type`: Type of artifact being parsed
    /// - `expected`: The expected magic bytes/signature
    /// - `found`: The actual magic bytes found
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn validate_pe_signature(data: &[u8]) -> ForensicResult<()> {
    ///     if &data[0..2] != b"MZ" {
    ///         return Err(ForensicError::invalid_magic("PE", "MZ", 
    ///             format!("{:02X}{:02X}", data[0], data[1])));
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub fn invalid_magic(artifact_type: &'static str, expected: &'static str, found: impl Into<SCow>) -> Self {
        Self::Format(FormatError::InvalidMagic { artifact_type, expected, found : found.into() })
    }
    
    /// Creates a format corruption error at a specific location
    ///
    /// Use this when data appears corrupted or truncated.
    ///
    /// # Parameters
    /// - `artifact_type`: Type of artifact being parsed
    /// - `position`: Byte position where corruption was detected
    /// - `reason`: Description of the corruption
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn parse_section_table(data: &[u8], offset: u64) -> ForensicResult<Vec<Section>> {
    ///     if (offset as usize + 40) > data.len() {
    ///         return Err(ForensicError::format_corrupted("PE", offset, 
    ///             "Section table extends beyond file".into()));
    ///     }
    ///     // ... parse sections
    /// }
    /// ```
    pub fn format_corrupted(artifact_type: &'static str, position: u64, reason: SCow) -> Self {
        Self::Format(FormatError::Corrupted { artifact_type, position, reason })
    }
    
    // ========================================================================
    // Registry Error Constructors (Simplified)
    // ========================================================================
    
    /// Creates a registry cell parsing error
    ///
    /// Use this when parsing individual registry cells (nodes) fails.
    ///
    /// # Parameters  
    /// - `cell_type`: Type of registry cell (e.g., "key_node", "value_node")
    /// - `reason`: Description of why the cell parsing failed
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn parse_key_node(data: &[u8]) -> ForensicResult<KeyNode> {
    ///     if data.len() < 20 {
    ///         return Err(ForensicError::registry_cell_error("key_node", 
    ///             "Cell too small for key node header"));
    ///     }
    ///     // ... parse key node
    /// }
    /// ```
    pub fn registry_cell_error(cell_type: &'static str, reason: impl Into<SCow>) -> Self {
        Self::Format(FormatError::Invalid {
            artifact_type: cell_type,
            reason: reason.into(),
        })
    }
    
    /// Creates a registry hive parsing error  
    ///
    /// Use this when parsing registry hive structures fails.
    ///
    /// # Parameters
    /// - `hive_type`: Type of hive (e.g., "SYSTEM", "SAM", "SOFTWARE") 
    /// - `reason`: Description of why the hive parsing failed
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn parse_hive_header(data: &[u8]) -> ForensicResult<HiveHeader> {
    ///     if &data[0..4] != b"regf" {
    ///         return Err(ForensicError::registry_hive_error("registry_hive",
    ///             "Invalid hive signature"));
    ///     }
    ///     // ... parse hive header  
    /// }
    /// ```
    pub fn registry_hive_error(hive_type: &'static str, reason: impl Into<SCow>) -> Self {
        Self::Format(FormatError::Invalid {
            artifact_type: hive_type,
            reason: reason.into(),
        })
    }
    
    // ========================================================================
    // Compression Error Constructors
    // ========================================================================
    
    /// Creates a compression algorithm error
    ///
    /// Use this for algorithm-specific errors during compression/decompression.
    ///
    /// # Parameters
    /// - `algorithm`: Name of the compression algorithm (e.g., "LZNT1", "Xpress")
    /// - `reason`: Description of the algorithm error
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn decompress_lznt1(data: &[u8]) -> ForensicResult<Vec<u8>> {
    ///     if data[0] & 0x8000 == 0 {
    ///         return Err(ForensicError::compression_error("LZNT1", 
    ///             "Invalid compression flag in header"));
    ///     }
    ///     // ... decompression logic
    /// }
    /// ```
    pub fn compression_error(algorithm: &'static str, reason: impl Into<SCow>) -> Self {
        Self::Compression(CompressionError::AlgorithmError { algorithm, reason : reason.into() })
    }
    
    /// Creates an invalid offset error for compression operations
    ///
    /// Use this when offset values in compressed data are invalid.
    ///
    /// # Parameters
    /// - `operation`: Description of the compression operation
    /// - `offset`: The invalid offset value (can be negative)
    /// - `file_size`: Size of the file/buffer being processed
    ///
    /// # Examples  
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn validate_compression_offset(offset: i64, data_size: u64) -> ForensicResult<()> {
    ///     if offset < 0 || offset as u64 >= data_size {
    ///         return Err(ForensicError::invalid_offset("decompression", offset, data_size));
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub fn invalid_offset(operation: &'static str, offset: i64, file_size: u64) -> Self {
        Self::Compression(CompressionError::InvalidOffset { operation, offset, file_size })
    }
    
    /// Creates a "length too big" error for compression operations
    ///
    /// Use this when length values exceed maximum allowed sizes.
    ///
    /// # Parameters
    /// - `operation`: Description of the compression operation
    /// - `length`: The length value that was too large
    /// - `max_length`: Maximum allowed length
    ///
    /// # Examples
    /// ```rust  
    /// use forensic_rs::prelude::*;
    ///
    /// fn validate_decompressed_size(size: u64) -> ForensicResult<()> {
    ///     const MAX_DECOMPRESSED_SIZE: u64 = 100_000_000; // 100MB
    ///     if size > MAX_DECOMPRESSED_SIZE {
    ///         return Err(ForensicError::too_big("decompression", size, MAX_DECOMPRESSED_SIZE));
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub fn too_big(operation: &'static str, length: u64, max_length: u64) -> Self {
        Self::Compression(CompressionError::TooBig { operation, length, max_length })
    }
    
    /// Creates a "length too small" error for compression operations
    ///
    /// Use this when length values are below minimum requirements.
    ///
    /// # Parameters
    /// - `operation`: Description of the compression operation
    /// - `length`: The length value that was too small
    /// - `min_length`: Minimum required length
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*; 
    ///
    /// fn validate_compressed_data(data: &[u8]) -> ForensicResult<()> {
    ///     const MIN_COMPRESSED_SIZE: u64 = 16; // Minimum for headers
    ///     if (data.len() as u64) < MIN_COMPRESSED_SIZE {
    ///         return Err(ForensicError::too_small("compression parsing", 
    ///             data.len() as u64, MIN_COMPRESSED_SIZE));
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub fn too_small(operation: &'static str, length: u64, min_length: u64) -> Self {
        Self::Compression(CompressionError::TooSmall { operation, length, min_length })
    }
    
    // ========================================================================
    // Data Access Error Constructors
    // ========================================================================
    
    /// Creates a missing data error
    ///
    /// Use this when expected data is not available or not found.
    ///
    /// # Parameters
    /// - `data_type`: Type of data that was missing (e.g., "file", "metadata")
    /// - `context`: Additional context about what was missing
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn get_file_metadata(path: &str) -> ForensicResult<Metadata> {
    ///     std::fs::metadata(path)
    ///         .map_err(|_| ForensicError::missing_data("file_metadata", 
    ///             format!("Could not read metadata for {}", path).into()))
    /// }
    /// ```
    pub fn missing_data(data_type: &'static str, context: SCow) -> Self {
        Self::DataAccess(DataAccessError::Missing { data_type, context })
    }
    
    /// Creates a file size error
    ///
    /// Use this when files exceed allowed size limits.
    ///
    /// # Parameters
    /// - `operation`: Description of the operation with size limits
    /// - `max_size`: Maximum allowed file size
    /// - `actual_size`: Actual size of the file
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn load_small_file(path: &str) -> ForensicResult<Vec<u8>> {
    ///     let metadata = std::fs::metadata(path)?;
    ///     const MAX_SIZE: u64 = 10_000_000; // 10MB
    ///     
    ///     if metadata.len() > MAX_SIZE {
    ///         return Err(ForensicError::file_size_error("small_file_loading", 
    ///             MAX_SIZE, metadata.len()));
    ///     }
    ///     std::fs::read(path).map_err(Into::into)
    /// }
    /// ```
    pub fn file_size_error(operation: &'static str, max_size: u64, actual_size: u64) -> Self {
        Self::DataAccess(DataAccessError::FileSizeExceeded { operation, max_size, actual_size })
    }
    
    /// Creates a path not found error
    ///
    /// Use this when filesystem paths don't exist.
    ///
    /// # Parameters
    /// - `path`: The path that was not found
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn ensure_path_exists(path: &str) -> ForensicResult<()> {
    ///     if !std::path::Path::new(path).exists() {
    ///         return Err(ForensicError::path_not_found(path.to_string()));
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub fn path_not_found(path: String) -> Self {
        Self::DataAccess(DataAccessError::PathNotFound { path })
    }
    
    /// Creates an access denied error
    ///
    /// Use this when permission issues prevent accessing resources.
    ///
    /// # Parameters
    /// - `resource`: The resource that couldn't be accessed
    /// - `context`: Additional context about the access denial
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn read_protected_file(path: &str) -> ForensicResult<Vec<u8>> {
    ///     std::fs::read(path)
    ///         .map_err(|e| match e.kind() {
    ///             std::io::ErrorKind::PermissionDenied => 
    ///                 ForensicError::access_denied(path, "Permission denied"),
    ///             _ => ForensicError::from(e)
    ///         })
    /// }
    /// ```
    pub fn access_denied(resource: impl Into<SCow>, context: impl Into<SCow>) -> Self {
        Self::DataAccess(DataAccessError::AccessDenied { resource : resource.into(), context: context.into() })
    }
    
    // ========================================================================
    // Registry Error Constructors (High-Level)
    // ========================================================================
    
    /// Creates a registry key not found error
    ///
    /// Use this when attempting to access a registry key that doesn't exist.
    ///
    /// # Parameters
    /// - `key`: The registry hive key (e.g., HKEY_LOCAL_MACHINE)
    /// - `key_path`: Optional sub-path within the hive
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn get_registry_key(hive: RegHiveKey, path: &str) -> ForensicResult<RegistryKey> {
    ///     // ... attempt to find key
    ///     Err(ForensicError::registry_key_not_found(hive, Some(path.into())))
    /// }
    /// ```
    pub fn registry_key_not_found(key : RegHiveKey, key_path :Option<SCow>) -> Self {
        Self::Registry(RegistryError::KeyNotFound { key, key_path })
    }
    
    /// Creates a registry value not found error
    ///
    /// Use this when attempting to access a registry value that doesn't exist.
    ///
    /// # Parameters
    /// - `key`: The registry hive key where the value was expected
    /// - `key_path`: Optional sub-path within the hive
    /// - `value_name`: Name of the value that was not found
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn get_windows_version() -> ForensicResult<String> {
    ///     // ... attempt to read ProductName value
    ///     Err(ForensicError::registry_value_not_found(
    ///         RegHiveKey::HkeyLocalMachine,
    ///         Some("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion".into()),
    ///         "ProductName"
    ///     ))
    /// }
    /// ```
    pub fn registry_value_not_found(key : RegHiveKey, key_path: Option<SCow>, value_name: impl Into<SCow>) -> Self {
        Self::Registry(RegistryError::ValueNotFound { key, key_path, value_name : value_name.into() })
    }
    
    /// Creates a registry value type validation error
    ///
    /// Use this when a registry value exists but has the wrong data type.
    ///
    /// # Parameters
    /// - `expected`: The expected registry value type (e.g., "REG_DWORD")
    /// - `found`: The actual type found in the registry
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn get_dword_value(value: &RegistryValue) -> ForensicResult<u32> {
    ///     match value {
    ///         RegistryValue::DWord(val) => Ok(*val),
    ///         other => Err(ForensicError::registry_invalid_type("REG_DWORD", 
    ///             format!("{:?}", other)))
    ///     }
    /// }
    /// ```
    pub fn registry_invalid_type(expected: &'static str, found: impl Into<SCow>) -> Self {
        Self::Registry(RegistryError::InvalidValueType { expected, found : found.into() })
    }
    
    /// Creates an invalid registry handle error
    ///
    /// Use this when registry handle values are invalid or corrupted.
    ///
    /// # Parameters
    /// - `handle`: The invalid handle value
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn validate_registry_handle(handle: i64) -> ForensicResult<()> {
    ///     if handle < 0 || handle > i32::MAX as i64 {
    ///         return Err(ForensicError::registry_invalid_handle(handle));
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub fn registry_invalid_handle(handle : i64) -> Self {
        Self::Registry(RegistryError::InvalidHandle {handle})
    }
    
    /// Creates a registry cell structure error
    ///
    /// Use this when parsing registry hive cells and the structure is invalid.
    ///
    /// # Parameters
    /// - `cell_type`: Type of registry cell being parsed
    /// - `offset`: Offset in the hive where the error occurred
    /// - `expected_type`: Description of expected cell structure
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn parse_registry_cell(data: &[u8], offset: u64) -> ForensicResult<Cell> {
    ///     if data.len() < 8 {
    ///         return Err(ForensicError::registry_cell_structure_error(
    ///             "key_node", offset, "NK cell with minimum 8 bytes"));
    ///     }
    ///     // ... parse cell
    /// }
    /// ```
    pub fn registry_cell_structure_error(cell_type: &'static str, offset: u64, expected_type: &'static str) -> Self {
        Self::Registry(RegistryError::CellStructure { cell_type, offset, expected_type })
    }
    
    // ========================================================================
    // Cast Error Constructors
    // ========================================================================
    
    /// Creates a type conversion error
    ///
    /// Use this for general type conversion failures.
    ///
    /// # Parameters
    /// - `from_type`: The source type name
    /// - `to_type`: The target type name
    /// - `reason`: Explanation of why the conversion failed
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn convert_registry_value(value: &RegistryValue) -> ForensicResult<String> {
    ///     match value {
    ///         RegistryValue::String(s) => Ok(s.clone()),
    ///         RegistryValue::DWord(_) => Err(ForensicError::cast_error(
    ///             "REG_DWORD", "String", "DWORD values cannot be converted to strings".into())),
    ///         // ... other variants
    ///     }
    /// }
    /// ```
    pub fn cast_error(from_type: &'static str, to_type: &'static str, reason: SCow) -> Self {
        Self::Cast(CastError::InvalidConversion { from_type, to_type, reason })
    }
    
    /// Creates a value out of range error
    ///
    /// Use this when values are too large/small for the target type.
    ///
    /// # Parameters
    /// - `value`: The value that couldn't be converted (as string)
    /// - `target_type`: The target type that couldn't accommodate the value
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn u64_to_u32(value: u64) -> ForensicResult<u32> {
    ///     if value > u32::MAX as u64 {
    ///         return Err(ForensicError::value_out_of_range(value.to_string(), "u32"));
    ///     }
    ///     Ok(value as u32)
    /// }
    /// ```
    pub fn value_out_of_range(value: impl Into<SCow>, target_type: &'static str) -> Self {
        Self::Cast(CastError::ValueOutOfRange { value : value.into(), target_type })
    }
    
    // ========================================================================
    // Timestamp Error Constructors
    // ========================================================================
    
    /// Creates an invalid timestamp error
    ///
    /// Use this when timestamp values are malformed or don't make sense.
    ///
    /// # Parameters
    /// - `timestamp`: The invalid timestamp value
    /// - `reason`: Explanation of why the timestamp is invalid
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn parse_filetime(filetime: u64) -> ForensicResult<SystemTime> {
    ///     const FILETIME_EPOCH: u64 = 116444736000000000;
    ///     if filetime < FILETIME_EPOCH {
    ///         return Err(ForensicError::illegal_timestamp(filetime, 
    ///             "FILETIME before epoch (1601-01-01)".into()));
    ///     }
    ///     // ... conversion logic
    /// }
    /// ```
    pub fn illegal_timestamp(timestamp: u64, reason: SCow) -> Self {
        Self::Timestamp(TimestampError::Invalid { timestamp, reason })
    }
    
    /// Creates a timestamp out of range error
    ///
    /// Use this when timestamps are outside acceptable bounds.
    ///
    /// # Parameters
    /// - `timestamp`: The out-of-range timestamp value
    /// - `min`: Minimum acceptable timestamp value
    /// - `max`: Maximum acceptable timestamp value
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn validate_unix_timestamp(timestamp: u64) -> ForensicResult<()> {
    ///     const MIN_UNIX: u64 = 0; // 1970-01-01
    ///     const MAX_UNIX: u64 = 2147483647; // 2038-01-19 (32-bit limit)
    ///     
    ///     if timestamp < MIN_UNIX || timestamp > MAX_UNIX {
    ///         return Err(ForensicError::timestamp_out_of_range(timestamp, MIN_UNIX, MAX_UNIX));
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub fn timestamp_out_of_range(timestamp: u64, min: u64, max: u64) -> Self {
        Self::Timestamp(TimestampError::OutOfRange { timestamp, min, max })
    }
    
    // ========================================================================
    // I/O Error Constructors
    // ========================================================================
    
    /// Creates an I/O error with additional context
    ///
    /// Use this to wrap standard I/O errors with forensic-specific context.
    ///
    /// # Parameters
    /// - `kind`: The I/O error kind from `std::io::ErrorKind`
    /// - `context`: Additional context about the failed operation
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn read_evidence_file(path: &str) -> ForensicResult<Vec<u8>> {
    ///     std::fs::read(path)
    ///         .map_err(|e| ForensicError::io_error(e.kind(), 
    ///             format!("Failed to read evidence file: {}", path)))
    /// }
    /// ```
    pub fn io_error(kind: std::io::ErrorKind, context: impl Into<SCow>) -> Self {
        Self::Io { kind, context: context.into() }
    }
    
    // ========================================================================
    // Generic Error Constructors
    // ========================================================================
    
    /// Creates a generic error for uncategorized cases
    ///
    /// Use this sparingly - prefer specific error types when possible.
    ///
    /// # Parameters
    /// - `category`: Category identifier for the error type
    /// - `message`: Human-readable error message
    ///
    /// # Examples
    /// ```rust
    /// use forensic_rs::prelude::*;
    ///
    /// fn some_operation() -> ForensicResult<()> {
    ///     // Only use this when no specific error type fits
    ///     Err(ForensicError::other("custom_operation", 
    ///         "Something unexpected happened".to_string()))
    /// }
    /// ```
    pub fn other(category: &'static str, message: String) -> Self {
        Self::Other { category, message }
    }
    
    // Legacy compatibility helpers (deprecated - use specific methods instead)
    #[deprecated(since = "0.15.0", note = "Use specific error constructors like invalid_format()")]
    pub fn bad_format_str(err: &'static str) -> Self {
        Self::Format(FormatError::Invalid { artifact_type: "unknown", reason: SCow::borrowed(err) })
    }
    
    #[deprecated(since = "0.15.0", note = "Use specific error constructors like invalid_format()")]
    pub fn bad_format_string(err: String) -> Self {
        Self::Other { category: "format", message: err }
    }
    
    #[deprecated(since = "0.15.0", note = "Use specific error constructors like missing_data()")]
    pub fn missing_str(err: &'static str) -> Self {
        Self::DataAccess(DataAccessError::Missing { data_type: "unknown", context: SCow::borrowed(err) })
    }
    
    #[deprecated(since = "0.15.0", note = "Use specific error constructors like missing_data()")]
    pub fn missing_string(err: String) -> Self {
        Self::Other { category: "missing", message: err }
    }
}

impl Clone for ForensicError {
    fn clone(&self) -> Self {
        match self {
            Self::Buffer(e) => Self::Buffer(e.clone()),
            Self::Format(e) => Self::Format(e.clone()),
            Self::Compression(e) => Self::Compression(e.clone()),
            Self::DataAccess(e) => Self::DataAccess(e.clone()),
            Self::Registry(e) => Self::Registry(e.clone()),
            Self::Cast(e) => Self::Cast(e.clone()),
            Self::Timestamp(e) => Self::Timestamp(e.clone()),
            Self::Io { kind, context } => {
                Self::Io { kind: *kind, context: context.clone() }
            },
            Self::Other { category, message } => {
                Self::Other { category: *category, message: message.clone() }
            },
        }
    }
}

impl PartialEq for ForensicError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Buffer(e1), Self::Buffer(e2)) => e1 == e2,
            (Self::Format(e1), Self::Format(e2)) => e1 == e2,
            (Self::Compression(e1), Self::Compression(e2)) => e1 == e2,
            (Self::DataAccess(e1), Self::DataAccess(e2)) => e1 == e2,
            (Self::Registry(e1), Self::Registry(e2)) => e1 == e2,
            (Self::Cast(e1), Self::Cast(e2)) => e1 == e2,
            (Self::Timestamp(e1), Self::Timestamp(e2)) => e1 == e2,
            (Self::Io { kind: k1, context: c1 }, Self::Io { kind: k2, context: c2 }) => {
                k1 == k2 && c1 == c2
            },
            (Self::Other { category: c1, message: m1 }, Self::Other { category: c2, message: m2 }) => {
                c1 == c2 && m1 == m2
            },
            _ => false
        }
    }
}

impl Eq for ForensicError {}

impl From<std::io::Error> for ForensicError {
    fn from(e: std::io::Error) -> Self {
        ForensicError::Io { 
            kind: e.kind(), 
            context: SCow::Borrowed("IO operation failed") 
        }
    }
}

impl From<String> for ForensicError {
    fn from(value: String) -> Self {
        ForensicError::Other { category: "generic", message: value }
    }
}

impl From<&str> for ForensicError {
    fn from(value: &str) -> Self {
        ForensicError::Other { category: "generic", message: value.to_string() }
    }
}

impl From<&String> for ForensicError {
    fn from(value: &String) -> Self {
        ForensicError::Other { category: "generic", message: value.clone() }
    }
}


impl std::fmt::Display for ForensicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForensicError::Buffer(err) => err.fmt(f),
            ForensicError::Format(err) => err.fmt(f),
            ForensicError::Compression(err) => err.fmt(f),
            ForensicError::DataAccess(err) => err.fmt(f),
            ForensicError::Registry(err) => err.fmt(f),
            ForensicError::Cast(err) => err.fmt(f),
            ForensicError::Timestamp(err) => err.fmt(f),
            ForensicError::Io { kind, context } => {
                write!(f, "IO error ({:?}): {}", kind, context)
            },
            ForensicError::Other { category, message } => {
                write!(f, "{} error: {}", category, message)
            },
        }
    }
}

impl std::error::Error for ForensicError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // No inner errors in this implementation since we use structured data
        None
    }

    fn description(&self) -> &str {
        match self {
            ForensicError::Buffer(_) => "Buffer access error",
            ForensicError::Format(_) => "Format validation error",
            ForensicError::Compression(_) => "Compression/decompression error",
            ForensicError::DataAccess(_) => "Data access error",
            ForensicError::Registry(_) => "Registry error",
            ForensicError::Cast(_) => "Type conversion error",
            ForensicError::Timestamp(_) => "Timestamp validation error",
            ForensicError::Io { .. } => "IO error",
            ForensicError::Other { category, .. } => match *category {
                "format" => "Format error",
                "missing" => "Missing data",
                "generic" => "Generic error",
                _ => "Other error",
            },
        }
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.source()
    }
}

#[test]
fn error_compatible_with_anyhow() {
    fn this_returns_error() -> anyhow::Result<u64> {
        let value = second_function()?;
        Ok(value)
    }
    fn second_function() -> ForensicResult<u64> {
        Err(ForensicError::invalid_format("prefetch", "Invalid prefetch format"))
    }

    let error = this_returns_error().unwrap_err();
    let frns_err = error.downcast_ref::<ForensicError>().unwrap();
    assert_eq!(&ForensicError::invalid_format("prefetch", "Invalid prefetch format"), frns_err);
}