# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.16.0] - Unreleased

### Added

- Protocol-neutral capability API (`src/capabilities/`) for external MCP server integrations: caller-scoped tool and resource discovery, typed `CapabilityValue` inputs and outputs, native schemas, progress reporting, cancellation, and sanitized public errors.
- Feature-gated serde support for `CapabilityValue`, native schemas, tool descriptors, tool content/results, progress updates, and capability errors, with JSON round-trip compatibility tests for adapter-owned wire messages.
- Capability access controls: `AccessContext`, `AccessPolicy`, `AuditedAccessPolicy`, trusted `AccessAuditSink` records, execution-plan authorization, and path/channel/table/row guards for VFS, Registry, Event Log, and Database sources.
- Object-safe `ForensicDbFactory`, `EventLogReaderFactory`, and `RegistryReaderFactory` traits for opening derived artifacts from a VFS path while retaining access to companion files.
- Native `ResourceProvider` implementations for `VfsProvider`, `RegistryProvider`, `EventLogProvider`, and `DatabaseProvider`; `BridgeResourceProvider` remains available for legacy third-party bridge providers.
- `MCP_INTEGRATION.md`: protocol-neutral MCP architecture, external server setup, capability/tool/resource contracts, non-disclosure rules, and migration guidance.
- `EventLogReader` trait (`src/traits/events.rs`): abstract interface for querying Windows event logs with filtering, pagination, and fallible iteration. Includes `EventLogQuery` builder (filter by event ID, time range, provider, severity level, channel), `EventLogIterator` (fallible `next() -> ForensicResult<Option<EventRecord>>`), `EventRecord` (record_id, event_id, timestamp, provider, channel, level, computer, user_sid, extensible `data` map), and `EventLevel` enum (Critical=1..Verbose=5). `EventRecord` implements `Into<ForensicData>` mapping standard fields to ECS names.
- `EventLogReader` ergonomic wrappers on `dyn EventLogReader`: `query_all()` and `query_channel(channel)`.
- `TestingEventLogReader` in `src/utils/testing.rs`: in-memory mock implementing `EventLogReader` for unit testing. `basic_event_log()` convenience constructor populates sample Security and System events.
- `ForensicBridge` module (`src/bridge/`): channel-based multi-threaded bridge exposing all artifact domains as navigable trees for UI consumers (VSCode extensions, web frontends, etc.):
  - `ForensicProvider` trait: object-safe interface with `name()`, `children()`, `read()`, `metadata()` methods supporting pagination and cooperative cancellation.
  - `CancellationToken`: thread-safe `Arc<AtomicBool>` cooperative cancellation for long-running operations.
  - `BridgeValue`: recursive value enum (`Null`, `Bool`, `I64`, `U64`, `F64`, `Text`, `Timestamp`, `Binary`, `Array`, `Map`). Implements `From<Field>` and `From<RegValue>`. Serializes to JSON via serde feature.
  - `NodeEntry` / `NodeType`: tree node model (`Container`, `Leaf`, `Virtual`).
  - `BridgeRequest` / `BridgeResponse`: channel-based protocol (ListProviders, Children, Read, Metadata, Shutdown).
  - `BridgeClient`: cloneable `Send` handle to the bridge worker thread. Methods: `list_providers()`, `children()`, `children_page()`, `children_cancellable()`, `read()`, `metadata()`, `shutdown()`, configurable timeout via `request_timeout()`.
  - `ForensicBridgeBuilder` / `ForensicBridge`: builder spawns a dedicated worker thread owning all providers; returns a `BridgeClient`.
  - `RegistryProvider`, `VfsProvider`, `EventLogProvider`, `DatabaseProvider`: concrete `ForensicProvider` implementations wrapping each artifact trait behind a `Mutex`.
  - `ProviderHook` trait (`src/bridge/hooks.rs`): postprocessing hooks that inject virtual parsed children into bridge tree nodes (e.g., parsed shellbag data inside registry binary values). Two-stage matching: `matches_path()` (fast) then `matches_value()` (content inspection). Virtual path convention: `[hookname]` bracketed segment avoids collisions with real children.
  - Hook utilities: `virtual_segment(name)`, `is_virtual_segment(s)`, `split_virtual_path(path)`, `inject_hook_children()`.
- `ForensicTimestamp`: Bitpacked u64 timestamp (8 bytes, microsecond precision, year 0-4095) with constructors for Windows FILETIME, Unix seconds/millis/micros, OLE Automation dates, WebKit/Chrome, HFS+, and Cocoa timestamps. Full bidirectional conversion with `Filetime`.
- **Breaking**: `ForensicTimestamp` is now the canonical 16-byte, 16-byte-aligned timestamp with nanosecond precision, validated parts, optional UTC-offset metadata, provenance flags, and portable endian-specific byte encodings. `Timestamp128` aliases it. Framework timestamp carriers, including `Field::Date`, database values, VFS metadata, activities, timelines, event records, and registry metadata now retain this representation. `Filetime` remains an input-format adapter.
- `VMetadata` timestamps migrated from `Option<usize>` (seconds) to `Option<ForensicTimestamp>` (microsecond precision).
- `RegistryVisit`: explicit streaming enumeration control. Registry callbacks return `Continue` to keep scanning or `Break` to stop successfully.
- `walk_dir()` on `dyn VirtualFileSystem`: Recursive directory traversal with visitor callback.
- `walk_dir_strict()` and `walk_dir_best_effort()` on `dyn VirtualFileSystem`: explicit recursive traversal modes that either propagate or ignore descendant enumeration errors.
- `VirtualFileSystem::visit_dir()`: fallible callback-based directory enumeration; `StdVirtualFS` streams entries without materializing a full `Vec<VDirEntry>`.
- `ParallelPipeline::run_with_cancellation()`: cooperative cancellation for built-in parallel tasks using `CancellationToken`.
- `ParallelPipelineBuilder::parser_factory_with_artifacts()`: metadata-aware parser registration that avoids constructing unmatched expensive parsers during auto-matching.
- `walk_keys()` on `dyn RegistryReader`: Recursive registry key traversal with visitor callback.
- `ForensicData` helper methods: `remove()`, `contains_key()`, `get_date()`, `extend_from()`, `len()`, `is_empty()`.
- `ForensicContext::metadata`: Extensible `BTreeMap<Text, Text>` for custom analysis context.
- `From<bool>`, `From<Filetime>`, `From<ForensicTimestamp>` implementations for `Field`.
- `ProgramExecution` enriched with `arguments`, `working_directory`, `run_count` fields.
- `FileSystemActivity::Rename`, `FileSystemActivity::Read`, `FileSystemActivity::Write` variants.
- `ForensicActivity::extras`: Extensible `BTreeMap<Text, Text>` for additional context.

### Changed

- **Breaking**: `TriageSources` no longer stores one pre-opened `EventLogReader` or `ForensicDb`. Parsers discover event-log and database files through the VFS and open each one with an injected reader factory. This keeps evidence acquisition separate from artifact decoding.
- **Breaking**: The crate now uses Rust 2024 edition and requires Rust 1.85 or newer.
- **Breaking**: `ArtifactParser` now requires `IntoIterator<Item = ForensicResult<ForensicData>>` (was `Item = ForensicData`).
- **Breaking**: `IntoTimeline` iterator item changed to `ForensicResult<TimelineData>`.
- **Breaking**: `IntoActivity` iterator item changed to `ForensicResult<ForensicActivity>`.
- **Breaking**: `Field` `TryInto` impls now return `ForensicError` instead of `&'static str`.
- **Breaking**: `VMetadata::created()`, `accessed()`, `modified()` now return `ForensicTimestamp` instead of `usize`.
- **Breaking**: Registry keys now use move-only, opaque `RegKeyHandle` values that close their backend resource exactly once on drop. The compatibility `RegistryKeyGuard` type and manual `RegistryReader::close_key()` API were removed.
- **Breaking**: `RegistryReader::enumerate_keys()` and `enumerate_values()` visitors now return `ForensicResult<RegistryVisit>` so enumeration can stop successfully without manufacturing an error.
- Registry traversal now offers `walk_keys_strict()` to propagate inaccessible descendant errors and `walk_keys_best_effort()` to skip them; `walk_keys()` remains the best-effort alias.
- `RegistryReader::value_exists()` now returns `false` only for a missing value and propagates all other registry failures.
- `TestingRegistry` now rejects unsupported `mount_file()` and `mount_fs()` operations instead of returning an unrelated in-memory registry.
- `VfsProvider` metadata now returns `BridgeValue::Null` for unavailable timestamps instead of fabricating Unix epoch values.
- `Field` conversions to `u64` and `i64` now reject lossy signed, floating-point, non-finite, and out-of-range conversions.

### Fixed

- Binary offset validation is overflow-safe, and new fallible endian-explicit unpack helpers prevent truncated artifact data from panicking.
- `ForensicError` now preserves original `std::io::Error` values created through `From<std::io::Error>` or `io_error_with_source()`, exposing them through `Error::source()`.
- Parallel pipeline worker panics are reported as task errors without preventing healthy tasks from completing.

### Deprecated

- `VMetadata::created()`, `accessed()`, and `modified()` epoch-substituting accessors; use their corresponding `*_opt()` methods.
- Legacy `u16_at_pos`, `u32_at_pos`, `u64_at_pos`, and big-endian variants; use `read_u*_le_at()` or `read_u*_be_at()`.

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

