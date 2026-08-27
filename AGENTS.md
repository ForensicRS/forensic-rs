# forensic-rs Agent Guide

## Project Overview

**forensic-rs** is a Rust framework for building reusable forensic artifact analysis tools. The core design principle is **decoupling analysis logic from data access**: an analyzer that reads registry keys should work identically whether it talks to a live Windows registry, a parsed hive file, or a mock in a unit test — without any code changes.

The framework achieves this through **trait-based polymorphism** across three artifact domains:
- **Windows Registry** — `Registry` (core) / `RegistryExt` (ergonomic path-based layer) traits
- **SQL Databases** — `SqlStatement` / `SqlDb` / `ForensicDb` traits
- **Virtual Filesystems** — `FileSystem` (core) / `FileSystemExt` (ergonomic layer) / `VirtualFile` traits

Both the Registry and Filesystem domains follow the same four-layer pattern:
1. **Core** — a minimal, mechanical, `&self`-based, `Send + Sync` trait implemented by backends (`Registry`, `FileSystem`). Object-safe so `Arc<dyn Registry>`/`Arc<dyn FileSystem>` can be shared across worker threads.
2. **Ext** — a blanket-impl'd trait with the ergonomic convenience API callers actually use (`RegistryExt::key()`/`value()`, `FileSystemExt::read_all()`/`exists()`/`walk()`/`glob()`). A backend author never implements these directly.
3. **Capability** — an authorization-checking wrapper around a core trait object (`AuthorizedRegistryReader`, `AuthorizedVirtualFileSystem`, in `src/capabilities/source_guards.rs`) used by the MCP capability layer (`src/capabilities/`) to enforce per-caller path/source grants.
4. **Factory** — opens a derived reader from evidence discovered through the filesystem (`RegistryReaderFactory`, `ForensicDbFactory`, `EventLogReaderFactory`), taking `(filesystem: Arc<dyn FileSystem>, path: &FPath)`.

**Current version**: 0.14.0
**Repository**: https://github.com/ForensicRS/forensic-rs
**License**: MIT

---

## Module Structure

```
src/
  lib.rs              — Module declarations + `prelude` with all public re-exports
  traits/             — Core abstraction traits (the "interfaces" of the framework)
    vfs.rs            — FileSystem, FileSystemExt, VirtualFile, VMetadata, DirEntry, VFileType, SourceKind, CaseSensitivity, FileSystemFactory
    forensic.rs       — ArtifactParser, IntoTimeline, IntoActivity, RegistryParser
    sql.rs            — SqlStatement, SqlDb, ColumnValue
    db.rs             — ForensicDb, ForensicRows, ForensicValue, ForensicRow, RowIterator
    events.rs         — EventLogReader, EventLogIterator, EventLogQuery, EventRecord, EventLevel
    factories.rs      — ForensicDbFactory, EventLogReaderFactory, RegistryReaderFactory (open a derived reader from an Arc<dyn FileSystem> + path)
    registry/         — mod.rs: RegValue (13 variants), RegValueRef, RegistryBuffer; raw.rs: Registry, RegistryExt, RegKey, RawKey, PredefinedHive; windows.rs: system_root(), users(), build() free functions
      extra/          — Registry helpers (e.g., get_env_vars_of_users())
  capabilities/       — MCP-facing authorization layer: gate access to sources, expose them as discoverable tools/resources
    access.rs         — AccessContext, AccessKind, AccessRequest, AccessDecision, AccessAuditEvent, AccessAuditSink, AccessPolicy, AuditedAccessPolicy, AllowAllPolicy, DenyAllPolicy
    source_guards.rs  — AuthorizedVirtualFileSystem, AuthorizedRegistryReader, AuthorizedEventLogReader, AuthorizedForensicDb (path/policy-checking wrappers around the core source traits)
    registry.rs       — CapabilityRegistry, ScopedCapabilityRegistry (caller-scoped discovery/invocation of tools and resource providers)
    tools.rs          — ForensicTool, ToolDescriptor, ToolHints, ToolContent, ToolResult, InvocationContext, ProgressReporter, CapabilityError
    resources.rs      — ResourceProvider, ResourceId, ResourceEntry, ResourceMetadata, ResourceContent, ResourceKind, Page/PageRequest
    schema.rs         — ValueType, ValueSchema, ObjectSchema (native JSON-Schema-like model for tool/resource inputs and outputs)
    value.rs          — CapabilityValue (lossless, protocol-neutral value type exchanged by tools/resource providers)
    pipeline.rs       — PipelineSourceKind, AccessRequirements, AuthorizedSourceFactory, PipelineTaskFactory, PipelineTaskTool (authorization prerequisites for wiring an Analyzer into a capability tool)
    bridge_adapter.rs — BridgeResourceProvider (adapts a legacy `ForensicProvider` bridge provider to the protocol-neutral ResourceProvider API)
  pipeline/           — Triage orchestration: run Analyzers/Enrichers over evidence and route Findings to sinks
    finding.rs        — Finding, FindingSeverity, FindingCategory, AnomalyTally
    traits.rs         — Analyzer, Enricher, TriageSink
    mod.rs            — TriagePipeline, TriagePipelineBuilder, ErrorAction, PipelineResult (serial pipeline orchestration/routing)
    parallel.rs       — ParallelPipeline, ParallelPipelineBuilder, AnalysisModule, PipelineEvent, TaskStats (thread-pool parallel triage pipeline)
    context.rs        — TriageContext (shared run context: host/tenant/artifact metadata, shared KV store, ProvenanceStore)
    sources.rs        — TriageSources, TriageSourcesBuilder (VFS/registry evidence sources available to parsers)
    sinks.rs          — TimelineSink, FindingCollector, JsonlTimelineSink, JsonlFindingSink
  provenance/         — Where a value came from and how much to trust it — tracked separately from the value itself
    model.rs          — Acquisition, Recovery, Locus, SourceKey, MergeReason, DerivedFrom, Provenance, ProvenanceSnapshot
    anomalies.rs       — AnomalyFlags, AnomalyDetail, Anomalies (instance-level, bitflag-based anomaly tracking — "divergence is evidence, not error")
    confidence.rs      — Confidence (trust level computed from a provenance chain)
    parsed.rs          — Parsed<T> (value + Anomalies + ProvenanceId container)
    tracked.rs         — Tracked<T> (field-level provenance for values whose derivation differs from their parent artifact, e.g. a timestamp normalized from a different source)
    store.rs           — ProvenanceStore, SourceHandle (interning arena; mint/derive/merge API)
    ids.rs             — ProvenanceId, SourceId (opaque 4-byte interned handles into a ProvenanceStore)
    serde_support.rs   — ProvenanceSideTable, ExpandedProvenance, expand() (serde-feature-gated provenance-aware serialization)
  parsing/            — Byte-level parsing helpers shared by binary artifact parsers
    reader.rs         — ByteReader (zero-copy, position-tracking cursor over &[u8])
    from_bytes.rs      — FromBytes (raw-bytes-to-typed-struct trait)
    mod.rs             — read_to_reader()
  bridge/             — Multi-provider UI bridge (channel-based, thread-safe)
    mod.rs            — CancellationToken, BridgeValue, DataOrigin, NodeType, NodeEntry, BridgeResponse, ForensicProvider trait
    client.rs         — BridgeClient: Clone+Send handle; list_providers, children, read, metadata, shutdown
    server.rs         — ForensicBridge worker loop, ForensicBridgeBuilder
    protocol.rs       — BridgeRequest enum (ListProviders, Children, Read, Metadata, Shutdown)
    providers.rs      — RegistryProvider, VfsProvider, EventLogProvider, DatabaseProvider
    hooks.rs          — ProviderHook trait, virtual_segment(), inject_hook_children(), path helpers
  core/
    path.rs           — FPath, FPathBuf: `/`-normalized, drive-aware, case-preserving evidence paths (replace std::path::Path/PathBuf in FileSystem/Registry APIs)
    fs/
      stdfs.rs        — StdVirtualFS: FileSystem over std::fs
      chroot.rs       — ChRootFileSystem: path-remapping FileSystem wrapper (wraps an Arc<dyn FileSystem>)
      mount.rs        — MountTable, OverlayFs: layered filesystem composition
      walk.rs         — Walk, WalkOptions: lazy streaming directory-tree traversal (FileSystemExt::walk)
      glob.rs         — Glob: pattern matching over FileSystem paths (FileSystemExt::glob/glob_iter)
  field/
    mod.rs            — Field enum, Text, FieldAccess, From/TryInto impls
    ip.rs             — Ip enum (V4/V6), IP parsing and utilities
    utils.rs          — IP parsing helpers (ipv4_from_str, is_local_ipv4, etc.)
  utils/
    time.rs           — Filetime, WinFiletime, UnixTimestamp, filetime_to_unix_timestamp; re-exports ForensicTimestamp and friends from time/timestamp128.rs
    time/
      timestamp128.rs — ForensicTimestamp (alias Timestamp128): 16-byte nanosecond-precision timestamp with TimestampPrecision, TimestampSource, TimestampFlags (see ForensicTimestamp section below)
    unpack.rs         — Binary unpacking helpers (u16/u32/u64_at_pos, safe variants)
    testing/          — Test doubles implementing the crate's traits: TestingRegistry (Registry), InMemoryVirtualFileSystem (FileSystem), TestingEventLogReader, InMemoryForensicDb, TestParserBuilder, TestingProviderHook, testing factory wrappers, basic_event_log(), testing_logger_dummy()
    win/
      sid.rs          — to_string_sid(), SID constants (LOCAL_SYSTEM, BUILTIN_ADMINS, etc.)
      csidl.rs        — FOLDERID_* constants for 60+ Windows shell folders
      decompress/     — Windows decompression algorithms
        mod.rs        — CompressionAlgorithm enum, decompress() dispatcher
        lz77.rs       — LZ77 and LZNT1 decompression
        xpress_huff.rs — LZ77+Huffman (Xpress Huffman) decompression
  data.rs             — ForensicData container (BTreeMap<Text, Field> + Artifact)
  err.rs              — ForensicError, ForensicResult, validation macros (uses compact_str::CompactString)
  artifact.rs         — Artifact enum, OS-specific artifact type enums
  context.rs          — ForensicContext: thread-local artifact/host/tenant metadata
  logging/            — Logger, Level, channel-based log macros (error!, warn!, info!, debug!, trace!) — engineer-facing diagnostics only, not forensic alerts (see Findings vs. logs vs. errors below)
  channel.rs          — Underlying channel for logging
  dictionary.rs       — Elastic Common Schema (ECS) field name constants (~80+)
  activity.rs         — ForensicActivity: user activity event type
```

---

## Public API

The `prelude` in `src/lib.rs` re-exports everything consumers need. Prefer importing from the prelude:

```rust
use forensic_rs::prelude::*;
```

Key prelude exports:
- `ForensicResult<T>`, `ForensicError` — error types
- `ForensicData`, `Field`, `Text`, `FieldAccess`, `Ip` — data/field types
- `FileSystem`, `FileSystemExt`, `VirtualFile`, `DirEntry`, `VFileType`, `SourceKind`, `CaseSensitivity` — filesystem traits/types
- `StdVirtualFS`, `ChRootFileSystem`, `MountTable`, `OverlayFs`, `StdVirtualFile` — filesystem implementations
- `FPath`, `FPathBuf` — evidence path types (replace `std::path::Path`/`PathBuf` in filesystem/registry APIs)
- `Registry`, `RegistryExt`, `RegKey`, `RawKey`, `RegValue`, `PredefinedHive` — registry (path-based `key()`/`value()`, RAII `RegKey`)
- `windows` — free functions (`system_root()`, `users()`, `build()`) for Windows-specific registry semantics
- `ForensicDbFactory`, `EventLogReaderFactory`, `RegistryReaderFactory` — factories that open a derived reader from evidence discovered through a filesystem
- `ForensicDb`, `ForensicTable`, `ForensicRows`, `ForensicValue`, `ForensicRow`, `RowIterator` — database
- `EventLogReader`, `EventLogIterator`, `EventLogQuery`, `EventRecord`, `EventLevel` — event logs
- `BridgeClient`, `ForensicBridge`, `ForensicBridgeBuilder` — bridge server/client
- `ForensicProvider`, `BridgeValue`, `BridgeResponse`, `CancellationToken`, `DataOrigin`, `NodeEntry`, `NodeType` — bridge types
- `ProviderHook` — bridge postprocessing hook trait
- `Artifact` — artifact type categorization
- `compact_str::CompactString` — inline-SSO string, re-exported; use `CompactString::const_new(...)` for `'static` literals to keep them allocation-free
- `Filetime`, `ForensicTimestamp`, `Timestamp128`, `TimestampPrecision`, `TimestampSource`, `TimestampFlags`, `WinFiletime`, `UnixTimestamp`, `filetime_to_unix_timestamp` — time types (`src/utils/time.rs` and `src/utils/time/timestamp128.rs`; see ForensicTimestamp section below)
- Logging macros: `error!`, `warn!`, `info!`, `debug!`, `trace!`, `log!` — engineer-facing diagnostics, not forensic alerts
- `Finding`, `FindingSeverity`, `FindingCategory` — structured, severity-ranked forensic alerts (`src/pipeline/finding.rs`), produced by an `Analyzer` and routed to every `TriageSink`
- `TriagePipeline`, `TriagePipelineBuilder`, `ParallelPipeline`, `Analyzer`, `Enricher`, `TriageSink`, `TriageContext`, `TriageSources` — pipeline orchestration (`src/pipeline/`): run `Analyzer`s/`Enricher`s over `TriageSources`, route `Finding`s to `TriageSink`s
- `Anomalies`, `AnomalyFlags`, `AnomalyDetail`, `Parsed<T>` — cheap, value-carried divergence tracking for parsers (`src/provenance/`; "divergence is evidence, not error")
- `ProvenanceStore`, `ProvenanceId`, `Provenance`, `Confidence`, `Tracked<T>` — provenance/lineage tracking (`src/provenance/`): where a value came from and how much to trust it
- `ForensicTool`, `CapabilityRegistry`, `ResourceProvider`, `AccessPolicy`, `ValueSchema`, `CapabilityValue`, `AuthorizedVirtualFileSystem`, `AuthorizedRegistryReader` — MCP capability layer (`src/capabilities/`): authorization, and exposing sources as discoverable tools/resources
- `FromBytes`, `ByteReader`, `read_to_reader()` — zero-copy byte-cursor parsing helpers for binary artifact formats (`src/parsing/`)

**Findings vs. logs vs. errors**: if an analyst would want it in the case report, it's a `Finding` (or an `Anomaly` on the value it describes, folded in via `ForensicData::set_parsed`). If only an engineer debugging the tool wants it, it's a log. If the tool can't proceed, it's a `ForensicError`. There is no fourth option — do not add a new notification/alert side-channel; extend `Finding`/`Anomalies` instead.

---

## Coding Conventions

### Error Handling

Always use `ForensicResult<T>` (an alias for `Result<T, ForensicError>`). Never use `unwrap()` in library code — use `?` for propagation.

`ForensicError` has categorized variants. Prefer the constructor methods and macros over constructing error structs directly:

```rust
// Validation macros — return Err early if condition fails
ensure_buffer_size!(buf, required_size);    // buf.len() >= required_size
ensure_buffer_range!(buf, start, end);      // range is valid within buf
ensure_format!(condition, "message {}", x); // generic format check
ensure_min_length!(buf, min_len);
ensure_max_length!(buf, max_len);
ensure_version!(actual_ver, expected_ver);  // version compatibility check
compression_error!("message {}", x);       // returns Err(ForensicError::Compression{..})
invalid_offset!(offset, context);          // returns Err for bad offsets
missing_data!("message {}", x);            // returns Err for absent data

// Direct constructors (use when macros don't fit)
ForensicError::bad_format_str("description") // DEPRECATED since 0.14.0 — use ensure_format! instead
ForensicError::missing_str("description")    // DEPRECATED since 0.14.0 — use missing_data! instead
```

**Error categories** (ForensicError variants):
- `Buffer` — out of bounds, insufficient space
- `Format` — invalid file format, magic, version, corrupt data
- `Compression` — decompression algorithm failures
- `DataAccess` — filesystem, I/O errors
- `Registry` — registry key/value not found, access errors
- `Cast` — type conversion failures
- `Timestamp` — invalid time values
- `Io` — generic I/O
- `Other` — fallback

### String Types

```rust
// Text = Cow<'static, str>. Use for zero-copy field names and values.
// Prefer borrowed static strings when possible:
let name: Text = Text::Borrowed("process_name");
let name: Text = Text::Owned(runtime_string);

// CompactString: for error messages and other metadata.
// Use const_new for 'static literals (zero-cost, any length);
// .into()/From for dynamic content (inline up to 24 bytes, heap beyond):
let msg = CompactString::const_new("file not found");
let msg = CompactString::from(format!("key '{}' not found", key_name));
```

### Data Containers

`ForensicData` stores artifact fields in a `BTreeMap<Text, Field>` — ordered storage matters for forensic reproducibility. Use the typed accessor methods to safely read and (lazily) convert fields:

```rust
let data: ForensicData = ForensicData::new(&artifact);
data.insert(Text::Borrowed("pid"), Field::U64(1234));

// Read with in-place type coercion:
let pid: Option<u64> = data.get_u64("pid");
let name: Option<&str> = data.get_str("process_name");
```

### Field Types

The `Field` enum is the union type for all artifact field values:

```rust
pub enum Field {
    Null,
    Text(Text),      // string data
    Ip(Ip),          // IPv4 (V4(u32)) or IPv6 (V6(u128))
    Domain(String),  // semantic domain name — currently constructed from external data only
    User(String),    // semantic user name  — currently constructed from external data only
    AssetID(String), // semantic asset ID   — currently constructed from external data only
    U64(u64),
    I64(i64),
    F64(f64),
    Date(Filetime),  // Windows FILETIME as parsed struct
    Array(Vec<Text>),
    Path(PathBuf),   // currently pattern-matched only; not yet constructed internally
}
```

Use `From`/`Into` implementations for ergonomic construction:
```rust
let f: Field = "hello".into();              // Field::Text(...)
let f: Field = 42u64.into();                // Field::U64(42)
let f: Field = true.into();                 // Field::U64(1)
let f: Field = Ip::V4(0xC0A80101).into();   // Field::Ip(...)
let f: Field = my_filetime.into();          // Field::Date(...)
let f: Field = my_forensic_ts.into();       // Field::Date(...) via Filetime conversion
```

### Naming Conventions

| Kind | Pattern | Examples |
|------|---------|---------|
| Traits | Concept noun, `Ext` suffix for the ergonomic layer | `FileSystem` / `FileSystemExt`, `Registry` / `RegistryExt`, `ArtifactParser` |
| Structs | PascalCase | `ForensicData`, `ChRootFileSystem`, `StdVirtualFS` |
| Enums | PascalCase | `Field`, `RegValue`, `Artifact`, `CompressionAlgorithm` |
| Enum variants | PascalCase | `CompressionFormatLznt1`, `RegValue::DWord` |
| Constants | SCREAMING_SNAKE_CASE | `FOLDER_ID_DESKTOP`, `LOCAL_SYSTEM` |
| Functions | snake_case | `filetime_to_unix_timestamp`, `to_string_sid` |
| Macros | snake_case! | `ensure_buffer_size!`, `compression_error!`, `warn!` |

### Module Organization

- Each feature area lives in its own subdirectory or file under `src/`
- Complex modules use `mod.rs` with sub-files for implementations
- Internal-only helpers can live in the same file as their consumers
- All public items should be accessible via `use forensic_rs::prelude::*`
- Add items to the `prelude` in `src/lib.rs` when they are part of the intended public API

---

## Trait Design Patterns

### Trait Objects and `dyn` dispatch

The framework heavily relies on trait objects (`Box<dyn Trait>`) for runtime polymorphism:

```rust
// Core traits are object-safe by design — avoid generics in trait methods.
// Both are `&self`-based (not `&mut self`), so `Arc<dyn FileSystem>` /
// `Arc<dyn Registry>` can be shared across worker threads.
fn analyze(vfs: &dyn FileSystem, registry: &dyn Registry) { ... }
```

### Ergonomic Convenience via Blanket-Impl'd `Ext` Traits

Rather than inherent methods on `impl dyn Trait` blocks, ergonomic convenience methods live on a separate `Ext` trait that is blanket-impl'd for every implementor of the core trait. This keeps the core trait minimal and object-safe while giving every caller a rich API for free:

```rust
// In src/traits/vfs.rs:
pub trait FileSystemExt: FileSystem {
    fn read_all(&self, path: &FPath) -> ForensicResult<Vec<u8>> { ... }
    fn exists(&self, path: &FPath) -> bool { ... }
    fn walk(&self, root: &FPath, opts: &WalkOptions) -> Walk<'_, Self> { ... }
    fn glob(&self, pattern: &str) -> ForensicResult<Vec<FPathBuf>> { ... }
}
impl<T: FileSystem + ?Sized> FileSystemExt for T {}
```

A backend author implements only the minimal core trait (`FileSystem`, `Registry`); every consumer automatically gets the `Ext` methods on `&dyn FileSystem`, `Arc<dyn FileSystem>`, a concrete backend, etc. — no manual wiring required. `RegistryExt` follows the same pattern over `Registry`.

### Stacking File Systems

`FileSystem` supports nesting without any special core-trait methods, since `Arc<dyn FileSystem>` is the common currency type: a `FileSystemFactory` sniffs and mounts a nested filesystem (ZIP, E01, ...) out of an opened `VirtualFile`; `MountTable`/`OverlayFs` (`src/core/fs/mount.rs`) compose several filesystems into one layered view; `ChRootFileSystem` wraps an `Arc<dyn FileSystem>` and remaps paths under a different root.

### Default Implementations

Use default method bodies in trait definitions for opt-in behavior that may not apply to all implementations — e.g. `FileSystem`'s capability probes default to "not supported":

```rust
fn case_sensitivity(&self) -> CaseSensitivity {
    CaseSensitivity::Insensitive  // Default: conservative — most backends are case-insensitive (NTFS, FAT)
}
fn as_streams(&self) -> Option<&dyn AlternateStreams> {
    None  // Default: no Alternate Data Streams support unless a backend overrides this
}
```

---

## Testing Patterns

### Mock Implementations

Implement traits directly on test-local structs rather than using mocking libraries:

```rust
struct MockRegistry {
    data: BTreeMap<String, RegValue>,
}
impl Registry for MockRegistry { ... }
```

`src/utils/testing/registry.rs` provides `TestingRegistry` — a pre-built mock implementing `Registry`, seeded with a sample user profile hierarchy. Use it in tests for registry-dependent code:

```rust
use forensic_rs::utils::testing::TestingRegistry;
let registry = TestingRegistry::new();
let key = registry.key(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion")?;
```

`src/utils/testing/vfs.rs` similarly provides `InMemoryVirtualFileSystem`, implementing `FileSystem`, for filesystem-dependent code that shouldn't touch the real disk.

Also available: `TestingEventLogReader` with `basic_event_log()` for event log tests, and `testing_logger_dummy()` for capturing logging messages in tests.

```rust
use forensic_rs::utils::testing::basic_event_log;
let reader = basic_event_log();
let mut iter = reader.query_all().unwrap();
while let Some(record) = iter.next().unwrap() {
    // process record
}
```

### In-Memory Databases

For SQL trait tests, use the `sqlite` dev-dependency with in-memory databases:

```rust
let conn = sqlite::open(":memory:").unwrap();
```

### Filesystem Tests

Use `std::env::temp_dir()` for temporary files in VFS tests. Clean up after the test or use unique file names to avoid conflicts.

### Thread-Local Receivers

The logging and notification systems use thread-local channels. In tests, set up a receiver before exercising macro code, then assert on received messages:

```rust
let receiver = testing_logger_dummy();
error!("test message");
let msg = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
assert_eq!(msg.level, Level::Error);
```

### Test Module Convention

Place unit tests in `#[cfg(test)]` modules at the bottom of each source file:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    // ...
}
```

Integration tests (those requiring multiple modules) belong in `tests/`.

---

## Windows Decompression

The `utils::win::decompress` module implements the [MS-XCA](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/) decompression specification:

```rust
use forensic_rs::utils::win::decompress::{CompressionAlgorithm, decompress};

let mut output = Vec::new();
decompress(&compressed_data, &mut output, CompressionAlgorithm::CompressionFormatLznt1)?;
```

Supported algorithms:
| Variant | Format ID | Notes |
|---------|-----------|-------|
| `CompressionFormatNone` | 0x0000 | No-op |
| `CompressionFormatDefault` | 0x0001 | Not supported (returns error) |
| `CompressionFormatLznt1` | 0x0002 | LZNT1 |
| `CompressionFormatXpress` | 0x0003 | LZ77 |
| `CompressionFormatXpressHuff` | 0x0004 | LZ77 + Huffman |

---

## Windows Utilities

### SID Conversion (`src/utils/win/sid.rs`)

```rust
use forensic_rs::utils::win::sid::{to_string_sid, LOCAL_SYSTEM, BUILTIN_ADMINS};

let sid_str = to_string_sid(&sid_bytes)?;  // e.g. "S-1-5-18"
```

Available SID constants: `LOCAL_SYSTEM`, `BUILTIN_ADMINS`, `BUILTIN_USERS`, `BUILTIN_GUESTS`.

### Shell Folder IDs (`src/utils/win/csidl.rs`)

60+ `FOLDERID_*` constants for well-known Windows shell folder paths (Desktop, Documents, Downloads, AppData, etc.):

```rust
use forensic_rs::utils::win::csidl::FOLDER_ID_APPDATA;
```

### Registry Environment Variables (`src/traits/registry/extra/env_vars.rs`)

```rust
use forensic_rs::traits::registry::extra::get_env_vars_of_users;

let user_envs = get_env_vars_of_users(&registry)?; // registry: &dyn Registry
// Returns UsersEnvVars, keyed by user SID
```

---

## Binary Unpacking (`src/utils/unpack.rs`)

Low-level helpers for reading integers from byte slices at a given offset. Used for parsing binary forensic artifacts:

```rust
use forensic_rs::utils::unpack::{u32_at_pos, u64_at_pos};

let value = u32_at_pos(&buffer, offset)?;  // safe, returns ForensicResult
```

For structured binary parsing, prefer `FromBytes` + `ByteReader` (`src/parsing/`) over raw offset arithmetic when a format has more than a couple of fields — the cursor tracks position for you and composes across nested structs.

---

## ECS Dictionary (`src/dictionary.rs`)

String constants for [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) field names. Use these when populating `ForensicData` to ensure consistent field naming across analyzers:

```rust
use forensic_rs::dictionary::{FIELD_EVENT_ACTION, FIELD_SOURCE_IP, FIELD_PROCESS_PID};

data.insert(Text::Borrowed(FIELD_PROCESS_PID), Field::U64(pid));
```

---

## Feature Flags

| Feature | Default | Effect |
|---------|---------|--------|
| `serde` | enabled | Derives `Serialize`/`Deserialize` on `Field`, `ForensicData`, and related types |

Disable serde in environments where serialization is not needed:

```toml
[dependencies]
forensic-rs = { version = "0.14", default-features = false }
```

---

## CI / Commit Conventions

### CI

GitHub Actions runs `cargo test --verbose` on **ubuntu-latest**, **windows-latest**, and **macos-latest** with the stable Rust toolchain on every push/PR to `main`.

### Commit Message Format

Following the project's [CONTRIBUTING.md](CONTRIBUTING.md):

1. **First line**: `<subcrate>: <short description>` (≤ 50 chars, lowercase except proper nouns/code)
   - `forensic-rs: add lznt1 decompression support`
   - `forensic-rs: deprecate bad_format_str in err`
2. **Second line**: blank
3. **Body**: wrap at 72 columns, explain *what* and *why*
4. **Footer**: `Fixes: #1234` or `Refs: #1000, #1100`

---

## Deprecation Policy

When deprecating API:
- Mark with `#[deprecated(since = "X.Y.Z", note = "use replacement() instead")]`
- Keep the deprecated function working for at least one minor release
- Document the replacement in both the deprecation attribute and the CHANGELOG
- Add a migration note in the module-level doc comment if many users are affected

---

## ForensicTimestamp

`ForensicTimestamp` (type alias `Timestamp128`, defined in `src/utils/time/timestamp128.rs`) is a validated, nanosecond-precision forensic timestamp: a 16-byte `#[repr(C, align(16))]` struct (`utc_seconds: i64`, `nanoseconds: u32`, `utc_offset_minutes: i16`, `flags: TimestampFlags`). The stored instant is always UTC — the optional offset only records source display context and never affects chronological comparison. `TimestampFlags` packs a `TimestampPrecision` (`Unknown`/`Days`/`Seconds`/`Milliseconds`/`Microseconds`/`HundredNanoseconds`/`Nanoseconds`) and a `TimestampSource` (`Unknown`/`Unix`/`WindowsFiletime`/`WebKit`/`OleAutomation`/`HfsPlus`/`Cocoa`/`Calendar`/`SystemTime`/`ParsedText`/`Derived`), plus marker bits (`APPROXIMATE`, `NORMALIZED`) — so every timestamp carries how precise it is and where it came from, not just an instant.

```rust
use forensic_rs::prelude::*;

// Infallible constructors for common forensic timestamp formats
let ts = ForensicTimestamp::from_unix_secs(1706969423);
let ts = ForensicTimestamp::from_unix_millis(1706969423596);
let ts = ForensicTimestamp::from_unix_micros(1706969423596123);
let ts = ForensicTimestamp::from_win_filetime(133514430235959706); // Windows FILETIME
let ts = ForensicTimestamp::from_webkit(13351443023595970);       // Chrome/WebKit
let ts = ForensicTimestamp::from_hfs_plus(3_789_814_223);         // macOS HFS+

// Fallible constructors return ForensicResult<Self> — the input can be out of range
let ts = ForensicTimestamp::try_from_unix_nanos(1_706_969_423_596_123_000)?;
let ts = ForensicTimestamp::try_from_ole_date(25569.0)?;                        // OLE Automation
let ts = ForensicTimestamp::try_from_cocoa(728_662_223.0)?;                     // macOS/iOS Cocoa
let ts = ForensicTimestamp::with_ymd_and_hms(2024, 2, 3, 14, 10, 23, 596_000)?; // -> ForensicResult<Self>

// Accessors
ts.year(); ts.month(); ts.day(); ts.hour(); ts.minute(); ts.second();
ts.milliseconds(); ts.microseconds(); ts.utc_offset_minutes(); ts.flags();

// Output conversions
ts.to_unix_secs(); ts.to_unix_millis(); ts.to_unix_micros();
ts.to_win_filetime()?; // -> ForensicResult<u64>; fails if the instant predates the FILETIME epoch

// One-directional conversion from the legacy Filetime type — Filetime -> ForensicTimestamp only,
// there is no reverse `From<ForensicTimestamp> for Filetime`
let ts: ForensicTimestamp = my_filetime.into();

// Fixed-width (de)serialization for on-disk/wire formats
let bytes: [u8; 16] = ts.to_le_bytes();
let ts2 = ForensicTimestamp::from_le_bytes(bytes)?;
```

`ForensicTimestamp` implements `Display` (`"{utc_seconds}.{nanoseconds:09} UTC"`), `Ord`/`PartialOrd` (instant-only comparison — offset and flags are ignored), `Add<Duration>`/`Sub<Duration>` (saturating), and serde `Serialize`/`Deserialize` (feature-gated). Prefer the `try_*` constructors at call sites that must reject out-of-range input rather than silently clamp or panic.

---

## RegKey

`RegKey` is a lifetime-tied RAII guard returned by `RegistryExt::key()`/`RegKey::open()`. It closes the underlying key automatically when it goes out of scope, and the borrow checker enforces that it cannot outlive the `Registry` it was opened from or be mixed up with a key opened from a different reader:

```rust
use forensic_rs::prelude::*;

let key = reader.key(&format!(r"HKU\{}\Volatile Environment", user_sid))?;
let value: String = key.value("ProfileImagePath")?.try_into()?;
// key is closed when it drops; call `key.close()` for an explicit early close
```

Unlike the core `Registry` trait (`Send + Sync`), `RegKey` itself is `!Send`/`!Sync` — it mirrors a thread-confined live handle even though the reader it borrows from is shareable.

---

## Recursive Traversal Helpers

### FileSystemExt::walk (FileSystem)

```rust
let vfs = StdVirtualFS::new();
for entry in vfs.walk(FPath::new("/var/log"), &WalkOptions::default()) {
    let entry = entry?;
    println!("{}: {:?}", entry.path, entry.file_type);
}
```

### Iterating registry keys (Registry)

There is no recursive registry walk built into the core API; `RegKey::keys()` lists one level of child key names, and `RegistryExt::for_each_user_hive()` expands a callback over every user SID under `HKEY_USERS`:

```rust
let key = reader.key(r"HKLM\SOFTWARE\Microsoft")?;
for entry in key.keys()? {
    println!("Key: {}", entry.name);
}
```

---

## ForensicData Container Methods

`ForensicData` provides the following methods for working with fields:

| Method | Description |
|--------|-------------|
| `insert(name, field)` | Add/overwrite a field |
| `add_field(name, field)` | Add a `&'static str` keyed field |
| `field(name)` | Get field reference by name |
| `field_mut(name)` | Get mutable field reference |
| `has_field(name)` | Check if field exists (legacy) |
| `contains_key(name)` | Check if field exists |
| `remove(name)` | Remove a field, returning its value |
| `get_i64(name)` | Get field as i64 with lazy coercion |
| `get_f64(name)` | Get field as f64 with lazy coercion |
| `get_u64(name)` | Get field as u64 with lazy coercion |
| `get_ip(name)` | Get field as Ip with lazy coercion |
| `get_str(name)` | Get field as &str with lazy coercion |
| `get_array(name)` | Get field as &Vec\<Text\> with lazy coercion |
| `get_date(name)` | Get field as &Filetime (Date fields only) |
| `extend_from(other)` | Merge fields from another ForensicData |
| `len()` | Number of fields |
| `is_empty()` | Whether container has no fields |
| `iter()` / `fields()` | Iterate over (name, field) pairs |

---

## Activity Model

`ForensicActivity` represents user activity on a device:

```rust
pub struct ForensicActivity {
    pub timestamp: Filetime,
    pub user: String,
    pub session_id: SessionId,
    pub activity: ActivityType,
    pub extras: BTreeMap<Text, Text>,  // extensible metadata
}
```

`ProgramExecution` includes:
- `executable: String`
- `arguments: Option<String>`
- `working_directory: Option<String>`
- `run_count: Option<u32>`

`FileSystemActivity` variants: `Open`, `Delete`, `Move`, `Create`, `Rename`, `Read`, `Write`, `Unknown`.

---

## v0.14.0 Breaking Changes

These changes affect downstream code:

1. **Fallible iterators**: `ArtifactParser` now requires `IntoIterator<Item = ForensicResult<ForensicData>>`. `IntoTimeline` and `IntoActivity` similarly wrap items in `ForensicResult`.
2. **Field TryInto errors**: `TryInto` impls on `&Field` now return `ForensicError` instead of `&'static str`.
3. **VMetadata timestamps**: `created`/`accessed`/`modified` changed from `Option<usize>` to `Option<ForensicTimestamp>`. Accessor methods return `ForensicTimestamp` instead of `usize`.
