# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.16.0] - Unreleased

### Added

- `ForensicTimestamp`: Bitpacked u64 timestamp (8 bytes, microsecond precision, year 0-4095) with constructors for Windows FILETIME, Unix seconds/millis/micros, OLE Automation dates, WebKit/Chrome, HFS+, and Cocoa timestamps. Full bidirectional conversion with `Filetime`.
- `VMetadata` timestamps migrated from `Option<usize>` (seconds) to `Option<ForensicTimestamp>` (microsecond precision).
- `RegistryKeyGuard`: RAII wrapper that automatically calls `close_key()` on drop.
- `walk_dir()` on `dyn VirtualFileSystem`: Recursive directory traversal with visitor callback.
- `walk_keys()` on `dyn RegistryReader`: Recursive registry key traversal with visitor callback.
- `ForensicData` helper methods: `remove()`, `contains_key()`, `get_date()`, `extend_from()`, `len()`, `is_empty()`.
- `ForensicContext::metadata`: Extensible `BTreeMap<Text, Text>` for custom analysis context.
- `From<bool>`, `From<Filetime>`, `From<ForensicTimestamp>` implementations for `Field`.
- `ProgramExecution` enriched with `arguments`, `working_directory`, `run_count` fields.
- `FileSystemActivity::Rename`, `FileSystemActivity::Read`, `FileSystemActivity::Write` variants.
- `ForensicActivity::extras`: Extensible `BTreeMap<Text, Text>` for additional context.

### Changed

- **Breaking**: `ArtifactParser` now requires `IntoIterator<Item = ForensicResult<ForensicData>>` (was `Item = ForensicData`).
- **Breaking**: `IntoTimeline` iterator item changed to `ForensicResult<TimelineData>`.
- **Breaking**: `IntoActivity` iterator item changed to `ForensicResult<ForensicActivity>`.
- **Breaking**: `Field` `TryInto` impls now return `ForensicError` instead of `&'static str`.
- **Breaking**: `VMetadata::created()`, `accessed()`, `modified()` now return `ForensicTimestamp` instead of `usize`.

## [0.15.0] - 16/03/2026

### Added

- Categorized `ForensicError` variants: `Buffer`, `Format`, `Compression`, `DataAccess`, `Registry`, `Cast`, `Timestamp`, `Io`, `Other`
- Validation macros for ergonomic error construction: `ensure_buffer_size!`, `ensure_buffer_range!`, `ensure_format!`, `ensure_min_length!`, `ensure_max_length!`, `ensure_version!`, `compression_error!`, `invalid_offset!`, `missing_data!`
- `registry_key_not_found!` and `registry_value_not_found!` macros for registry-specific errors
- `SCow` type (`src/scow.rs`) for static copy-on-write strings, used in error messages to avoid heap allocations on compile-time constants

### Deprecated

- `ForensicError::bad_format_str()` / `bad_format_string()` — use `ensure_format!` macro instead
- `ForensicError::missing_str()` / `missing_string()` — use `missing_data!` macro instead

## [0.14.0] - xx/xx/2025 

### Added

- Windows decompression algorithms: LZNT1, LZ77 and LZ77+Huffman
- Added ergonomic wrappers for VFS to accept `AsRef<Path>` for improved path flexibility.

### Fixed


## [0.13.1] - 18/02/2025 

### Added

- Improved time and filetime ergonomics
- Added support for MacOS in Github CI

### Fixed

- Added support for MacOS in StdVirtualFS


## [0.13.0] - 05/04/2024 

### Added

- Improved documentation

## [0.12.0] - 04/03/2024 

### Fixed

- Handle missing timestamps: https://github.com/ForensicRS/forensic-rs/pull/3

