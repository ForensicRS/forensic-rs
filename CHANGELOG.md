# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.14.0] - Unreleased

### Added

- Windows decompression algorithms: LZNT1, LZ77 and LZ77+Huffman
- Added ergonomic wrappers for VFS to accept `AsRef<Path>` for improved path flexibility.
- Categorized `ForensicError` variants: `Buffer`, `Format`, `Compression`, `DataAccess`, `Registry`, `Cast`, `Timestamp`, `Io`, `Other`
- Validation macros for ergonomic error construction: `ensure_buffer_size!`, `ensure_buffer_range!`, `ensure_format!`, `ensure_min_length!`, `ensure_max_length!`, `ensure_version!`, `compression_error!`, `invalid_offset!`, `missing_data!`
- `registry_key_not_found!` and `registry_value_not_found!` macros for registry-specific errors
- `compact_str::CompactString` used throughout error messages and metadata to avoid heap allocations for both short strings (inline storage) and `'static` strings of any length (via `CompactString::const_new`)
- Protocol-neutral capability API (`src/capabilities/`) for external MCP server integrations: caller-scoped tool and resource discovery, typed `CapabilityValue` inputs and outputs, native schemas, progress reporting, cancellation, and sanitized public errors.
- Feature-gated serde support for `CapabilityValue`, native schemas, tool descriptors, tool content/results, progress updates, and capability errors, with JSON round-trip compatibility tests for adapter-owned wire messages.
- Capability access controls: `AccessContext`, `AccessPolicy`, `AuditedAccessPolicy`, trusted `AccessAuditSink` records, execution-plan authorization, and path/channel/table/row guards for VFS, Registry, Event Log, and Database sources.
- Object-safe `ForensicDbFactory`, `EventLogReaderFactory`, and `RegistryReaderFactory` traits for opening derived artifacts from a VFS path while retaining access to companion files.
- Native `ResourceProvider` implementations for `VfsProvider`, `RegistryProvider`, `EventLogProvider`, and `DatabaseProvider`; `BridgeResourceProvider` remains available for legacy third-party bridge providers.
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
  - `RegistryProvider`, `VfsProvider`, `EventLogProvider`, `DatabaseProvider`: concrete `ForensicProvider` implementations wrapping each artifact trait. `RegistryProvider`/`VfsProvider` hold their `Arc<dyn Registry>`/`Arc<dyn FileSystem>` directly (both traits are `&self`-based, so no lock is needed); `EventLogProvider`/`DatabaseProvider` still wrap their reader behind a `Mutex`.
  - `ProviderHook` trait (`src/bridge/hooks.rs`): postprocessing hooks that inject virtual parsed children into bridge tree nodes (e.g., parsed shellbag data inside registry binary values). Two-stage matching: `matches_path()` (fast) then `matches_value()` (content inspection). Virtual path convention: `[hookname]` bracketed segment avoids collisions with real children.
  - Hook utilities: `virtual_segment(name)`, `is_virtual_segment(s)`, `split_virtual_path(path)`, `inject_hook_children()`.
- `ForensicTimestamp`: Bitpacked u64 timestamp (8 bytes, microsecond precision, year 0-4095) with constructors for Windows FILETIME, Unix seconds/millis/micros, OLE Automation dates, WebKit/Chrome, HFS+, and Cocoa timestamps. Full bidirectional conversion with `Filetime`.
- **Breaking**: `ForensicTimestamp` is now the canonical 16-byte, 16-byte-aligned timestamp with nanosecond precision, validated parts, optional UTC-offset metadata, provenance flags, and portable endian-specific byte encodings. `Timestamp128` aliases it. Framework timestamp carriers, including `Field::Date`, database values, VFS metadata, activities, timelines, event records, and registry metadata now retain this representation. `Filetime` remains an input-format adapter.
- `VMetadata` timestamps migrated from `Option<usize>` (seconds) to `Option<ForensicTimestamp>` (microsecond precision).
- **Breaking (RFC 0001 core trait redesign)**: `FileSystem`/`Registry` are rebuilt around a minimal, mechanical, `Send + Sync`, `&self`-based core trait per resource, an object-safe blanket "ext" trait for ergonomics, opt-in capability traits, and factory traits for construction. This replaces the `&mut self`-based `VirtualFileSystem`/`RegistryReader` traits entirely (not deprecated — removed) and is the headline breaking change of this release:
  - `FPath`/`FPathBuf` (`src/core/path.rs`): a `/`-normalized, drive-aware, case-preserving evidence-path type distinct from `std::path::Path` (which carries host, not evidence, semantics). Case-insensitive comparison goes through `path_eq(a, b, CaseSensitivity)`, driven by the filesystem being analyzed, never by the path text itself.
  - `FileSystem` (core, `&self`, `Send + Sync`): `open()`, `metadata()`, `read_dir()` (returns a lazy `Box<dyn Iterator<Item = ForensicResult<DirEntry>>>`), `source() -> SourceKind` (`Live`/`Image`/`Triage`/`Memory` — replaces the old bare `is_live(): bool`, which couldn't distinguish "absent from the evidence" from "never collected"), `case_sensitivity() -> CaseSensitivity`. `Arc<dyn FileSystem>` can now be shared across worker threads, which is what makes genuinely parallel image scanning possible — the old `&mut self` design could not do this.
  - `FileSystemExt` (blanket-impl'd convenience layer): `read_all()`, `exists()`, `walk()` (a real lazy, `&self`-based streaming DFS with loop/hardlink detection via `FileId`, replacing `walk_dir`/`walk_dir_strict`/`walk_dir_best_effort`), `glob()`/`glob_iter()` (metachar-prefix-scoped, never enumerates a whole drive for a pattern like `C:/Users/*/NTUSER.DAT`).
  - `DirEntry`, `VMetadata` (now carrying `MacbTimes`, `FileAttributes`, optional `FileId`, `allocated_size`), `AlternateStreams` and `Unallocated` capability traits (opt-in via `FileSystem::as_streams()`/`as_unallocated()`), `MountTable`/`OverlayFs` (longest-prefix and first-match layered filesystem composition), `FileSystemFactory` (sniffs and mounts a nested filesystem — ZIP, E01, OLE — from an opened file).
  - `Registry` (core, `&self`, `Send + Sync`): `root(PredefinedHive)`, `open_raw`/`close_raw`/`read_raw`/`values_raw`/`keys_raw`/`info_raw`, all keyed by an opaque, non-`Clone` `RawKey`. `RegKey<'r>` is a lifetime-tied RAII guard (private fields, `!Send`/`!Sync`) that closes on drop — a `RegKey` cannot outlive its `Registry`, cannot cross readers, and `RawKey` cannot be duplicated, all enforced at compile time (proven by `trybuild` fixtures in `tests/compile_fail/`). This replaces `RegKeyHandle`, which was move-only but not lifetime-tied to its reader, making cross-reader misuse and use-after-reader-drop *runtime* errors instead of compile errors.
  - `RegistryExt` (blanket convenience layer): `key(path)`/`value(path, name)`/`keys_at(path)`/`values_at(path)` take a single hive-prefixed path string (`"HKLM\Software\..."`, accepting both short and long hive forms, case-insensitively) instead of a separate `(hive, key_path)` pair; `for_each_user_hive()` expands `*` over `HKEY_USERS` SIDs.
  - `PredefinedHive` replaces `RegHiveKey`; the old `Hkey(isize)` raw-seed-handle variant has no equivalent — seeding a backend from an externally-supplied raw handle is now a backend-constructor concern, not part of this enum.
  - `windows::system_root()`, `windows::users()`, `windows::build()` (`src/traits/registry/windows.rs`): free functions replacing the old `RegistryReader::get_system_root()`/`list_users()`/`windows_build()` default trait methods — Windows analysis semantics derived from registry operations, not registry primitives. `windows::users()` returns a richer `UserProfile { sid, profile_path, name }` correlating `ProfileList` against `HKEY_USERS`; `windows::build()` returns a richer `WindowsVersion { build, major, minor, display_version, product_name }` instead of a bare `u32`.
  - `RegValue` expanded from 6 to 13 variants (now `#[non_exhaustive]`): added `DWordBigEndian`, `Link`, `ResourceList`, `FullResourceDescriptor`, `ResourceRequirementsList`, `Unknown { ty, data }` (preserves unrecognized/corrupt values as evidence instead of discarding them). `RegValue::raw_bytes()` gives the on-disk byte representation uniformly across every variant.
  - `RecoverDeleted` capability trait (`deleted_keys()`/`deleted_values()`) and `KeyEntry.allocated: bool` — plumbing for future hive-slack recovery; no backend implements it yet.
  - Every in-repo consumer (`TriageSources`, `ParallelPipeline`, the `capabilities` authorization layer, the `bridge` providers, testing factories) now holds `Arc<dyn FileSystem>`/`Arc<dyn Registry>` instead of `Box<dyn VirtualFileSystem>`/a `Mutex`-wrapped registry reader — construction is `Arc::new(...)`, not `Box::new(...)`, and sharing a source across parallel workers is a plain `Arc::clone()`.
  - Removed entirely (not deprecated): `VirtualFileSystem`, `VDirEntry`, `RegistryReader`, `RegHiveKey`, `RegKeyHandle`, `RegistryVisit`, `RegistryOpenOptions`, `RegistryAccess`, `Wow64View`, `FromRegistryValue`, `RegistryKeyInfo`, the `HKLM`/`HKU`/`HKCU`/`HKCR`/`HKC` constants, and `TestingRegistry`'s `mount_file()`/`mount_fs()` stubs.
- **Breaking**: `RegistryError::{KeyNotFound, ValueNotFound}.key` is now `PredefinedHive` instead of `RegHiveKey`.
- **Breaking**: `ForensicError` and its 7 category enums (`BufferError`, `FormatError`, `CompressionError`, `DataAccessError`, `RegistryError`, `CastError`, `TimestampError`) are now `#[non_exhaustive]`.
- `ForensicError::with_path()`/`with_offset()`/`path()`/`offset()`: attach and read back an `FPathBuf` and/or byte offset on any error via an additive `Contextualized` wrapping variant, without restructuring existing constructors.
- `ParallelPipeline::run_with_cancellation()`: cooperative cancellation for built-in parallel tasks using `CancellationToken`.
- `ParallelPipelineBuilder::parser_factory_with_artifacts()`: metadata-aware parser registration that avoids constructing unmatched expensive parsers during auto-matching.
- `ForensicData` helper methods: `remove()`, `contains_key()`, `get_date()`, `extend_from()`, `len()`, `is_empty()`.
- `ForensicContext::metadata`: Extensible `BTreeMap<Text, Text>` for custom analysis context.
- `From<bool>`, `From<Filetime>`, `From<ForensicTimestamp>` implementations for `Field`.
- `ProgramExecution` enriched with `arguments`, `working_directory`, `run_count` fields.
- `FileSystemActivity::Rename`, `FileSystemActivity::Read`, `FileSystemActivity::Write` variants.
- `ForensicActivity::extras`: Extensible `BTreeMap<Text, Text>` for additional context.
- `ForensicData::anomalies()`/`confidence(&ProvenanceStore)`: a record now carries the `Anomalies` folded in by `set_parsed`, instead of the caller having to thread them through separately.
- `Anomalies::merge()`: folds another instance's flags/details into this one.
- `CapabilityValue` conversions for `Confidence`, `Anomalies`, and `Finding` (`src/capabilities/value.rs`): pipeline findings and evidentiary confidence/anomaly data can now flow into MCP tool/resource output without every server author hand-rolling the mapping.
- `FindingCategory::ProcessingError` and `Finding::from_error()`: a crashed parser/enricher/analyzer now produces a finding (evidence went unexamined), not just a log line — `TriagePipeline`/`ParallelPipeline` do this automatically for every stage failure.
- `AnomalyTally` (`src/pipeline/finding.rs`): accumulates per-flag anomaly counts across a parser run and lowers them into one aggregate `Finding` per flag observed, instead of one finding per anomalous record. Wired automatically into `TriagePipeline`/`ParallelPipeline`.
- `Walk`/`WalkOptions::skip_errors`: an unreadable subtree is now yielded once as a `ForensicResult::Err` item (in addition to the existing `warn!` log) instead of being silently swallowed.
- Widened the `Artifact` taxonomy (`src/artifact.rs`) with common artifacts: `WindowsArtifacts::{JumpLists, LnkFiles, Bits, WmiRepository, PowerShellHistory, RdpCache, Timeline}`, `RegistryArtifacts::{AmCache, Services, UserAssist, Bam, TypedPaths, RecentDocs}`, `WindowsEvents::PowerShell`, `LinuxArtifacts::{Journal, Accounts, Ssh}`, and a real `MacArtifacts` taxonomy (`FsEvents`, `Spotlight`, `UnifiedLogs`, `Tcc`, `LaunchAgents`, `LaunchDaemons`, `KnowledgeC`) replacing the previous `Other`/`Unknown`-only stub.

### Changed

- **Breaking**: `TriageSources` no longer stores one pre-opened `EventLogReader` or `ForensicDb`. Parsers discover event-log and database files through the VFS and open each one with an injected reader factory. This keeps evidence acquisition separate from artifact decoding.
- **Breaking**: The crate now uses Rust 2024 edition and requires Rust 1.85 or newer.
- **Breaking**: `ArtifactParser` now requires `IntoIterator<Item = ForensicResult<ForensicData>>` (was `Item = ForensicData`).
- **Breaking**: `IntoTimeline` iterator item changed to `ForensicResult<TimelineData>`.
- **Breaking**: `IntoActivity` iterator item changed to `ForensicResult<ForensicActivity>`.
- **Breaking**: `Field` `TryInto` impls now return `ForensicError` instead of `&'static str`.
- **Breaking**: `VMetadata::created()`, `accessed()`, `modified()` now return `ForensicTimestamp` instead of `usize`.
- **Breaking**: Registry keys are opened and read through `RegKey<'r>`, a lifetime-tied RAII guard that closes exactly once on drop and cannot outlive the `Registry` (or reader) that opened it — see the RFC 0001 entry above.
- `VfsProvider` metadata now returns `BridgeValue::Null` for unavailable timestamps instead of fabricating Unix epoch values.
- `Field` conversions to `u64` and `i64` now reject lossy signed, floating-point, non-finite, and out-of-range conversions.
- **Breaking**: `Analyzer::analyze()`/`finalize()` now take an `out: &mut Vec<Finding>` accumulator and return `ForensicResult<()>`, instead of returning `ForensicResult<Vec<Finding>>`. Findings pushed to `out` before a `?` bails out with `Err` are still delivered to the sinks — previously they were discarded along with the error.
- **Breaking**: `ForensicData::set_parsed()` now folds the value's `Anomalies` into the record (see `Self::anomalies()`) and returns only `ProvenanceId`, instead of handing back a droppable `(Anomalies, ProvenanceId)` tuple. `Parsed<T>` is now `#[must_use]`.
- **Breaking**: `Artifact`, `WindowsArtifacts`, `WindowsEvents`, `RegistryArtifacts`, `LinuxArtifacts`, `LinuxService`, `MacArtifacts`, `CommonArtifact`, and `WebBrowsingArtifact` are now `#[non_exhaustive]`, so this catalog can keep growing without every addition being a semver-breaking change for downstream `match` expressions. Any exhaustive match on these enums outside this crate now needs a wildcard arm.

### Removed

- `src/notifications/` (`Notifier`, `Notification`, `NotificationType`, `Priority`, `notify!`/`notify_low!`/`notify_info!`/`notify_informational!`/`notify_medium!`/`notify_high!`/`notify_critical!`, `initialize_notifier()`, `testing_notifier_dummy()`): removed entirely, not deprecated. It was a thread-local channel that silently dropped every message unless a receiver was explicitly installed (`Notifier::default()` opened a channel and immediately dropped the receiver), had zero call sites in `src/`, and duplicated `Finding`/`FindingSeverity`/`FindingCategory` less safely. Forensic alerts go through `Finding` (routed to every `TriageSink`, can't silently no-op) instead.

### Fixed

- Binary offset validation is overflow-safe, and new fallible endian-explicit unpack helpers prevent truncated artifact data from panicking.
- `ForensicError` now preserves original `std::io::Error` values created through `From<std::io::Error>` or `io_error_with_source()`, exposing them through `Error::source()`.
- Parallel pipeline worker panics are reported as task errors without preventing healthy tasks from completing.
- `Artifact`'s `Display`/`FromStr` string protocol (`src/artifact.rs`) no longer silently loses or mangles data on round-trip: `RegistryArtifacts::ShimCache` displayed as `"InitD"`; `Artifact::MacOs` displayed with tag `"Mac::"` while parsing only recognized `"MacOs::"` (every macOS artifact silently became `Artifact::Other`); `LinuxArtifacts::Unknown` displayed as `"Log::Unknown"`; `LinuxArtifacts::Service(_)` failed to parse back (wrong substring was forwarded to the nested parser); and free-form `Other(String)`/bare unrecognized tags without a `"::"` separator were coerced into `Unknown` or an empty string instead of preserving the original text (`WindowsArtifacts`, `LinuxArtifacts`, `CommonArtifact`, `OtherOS`).

### Deprecated

- `ForensicError::bad_format_str()` / `bad_format_string()` — use `ensure_format!` macro instead
- `ForensicError::missing_str()` / `missing_string()` — use `missing_data!` macro instead
- `VMetadata::created()`, `accessed()`, and `modified()` epoch-substituting accessors; use their corresponding `*_opt()` methods.
- Legacy `u16_at_pos`, `u32_at_pos`, `u64_at_pos`, and big-endian variants; use `read_u*_le_at()` or `read_u*_be_at()`.

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

