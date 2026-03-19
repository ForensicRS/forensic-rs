# GitHub Copilot Instructions for forensic-rs

## Project Overview

**forensic-rs** is a Rust framework for building reusable forensic artifact analysis tools. The core design principle is **decoupling analysis logic from data access**: an analyzer that reads registry keys should work identically whether it talks to a live Windows registry, a parsed hive file, or a mock in a unit test — without any code changes.

The framework achieves this through **trait-based polymorphism** across three artifact domains:
- **Windows Registry** — `RegistryReader` trait
- **SQL Databases** — `SqlStatement` / `SqlDb` / `ForensicDb` traits
- **Virtual Filesystems** — `VirtualFileSystem` / `VirtualFile` traits

**Current version**: 0.14.0  
**Repository**: https://github.com/ForensicRS/forensic-rs  
**License**: MIT

---

## Module Structure

```
src/
  lib.rs              — Module declarations + `prelude` with all public re-exports
  traits/             — Core abstraction traits (the "interfaces" of the framework)
    vfs.rs            — VirtualFileSystem, VirtualFile, VMetadata, VDirEntry, VFileType
    forensic.rs       — ArtifactParser, IntoTimeline, IntoActivity, RegistryParser
    sql.rs            — SqlStatement, SqlDb, ColumnValue
    db.rs             — ForensicDb, ForensicRows, ForensicValue, ForensicRow, RowIterator
    events.rs         — EventLogReader, EventLogIterator, EventLogQuery, EventRecord, EventLevel
    registry/         — RegistryReader, RegValue, RegHiveKey, hive key constants
      extra/          — Registry helpers (e.g., get_env_vars_of_users())
  bridge/             — Multi-provider UI bridge (channel-based, thread-safe)
    mod.rs            — CancellationToken, BridgeValue, DataOrigin, NodeType, NodeEntry, BridgeResponse, ForensicProvider trait
    client.rs         — BridgeClient: Clone+Send handle; list_providers, children, read, metadata, shutdown
    server.rs         — ForensicBridge worker loop, ForensicBridgeBuilder
    protocol.rs       — BridgeRequest enum (ListProviders, Children, Read, Metadata, Shutdown)
    providers.rs      — RegistryProvider, VfsProvider, EventLogProvider, DatabaseProvider
    hooks.rs          — ProviderHook trait, virtual_segment(), inject_hook_children(), path helpers
  core/
    fs/
      stdfs.rs        — StdVirtualFS: VFS over std::fs
      chroot.rs       — ChRootFileSystem: path-remapping VFS wrapper
  field/
    mod.rs            — Field enum, Text, FieldAccess, From/TryInto impls
    ip.rs             — Ip enum (V4/V6), IP parsing and utilities
    utils.rs          — IP parsing helpers (ipv4_from_str, is_local_ipv4, etc.)
  utils/
    time.rs           — Filetime, ForensicTimestamp, WinFiletime, UnixTimestamp, filetime_to_unix_timestamp
    unpack.rs         — Binary unpacking helpers (u16/u32/u64_at_pos, safe variants)
    testing.rs        — TestingRegistry mock, TestingEventLogReader, basic_event_log(), testing_logger_dummy, testing_notifier_dummy
    win/
      sid.rs          — to_string_sid(), SID constants (LOCAL_SYSTEM, BUILTIN_ADMINS, etc.)
      csidl.rs        — FOLDERID_* constants for 60+ Windows shell folders
      decompress/     — Windows decompression algorithms
        mod.rs        — CompressionAlgorithm enum, decompress() dispatcher
        lz77.rs       — LZ77 and LZNT1 decompression
        xpress_huff.rs — LZ77+Huffman (Xpress Huffman) decompression
  data.rs             — ForensicData container (BTreeMap<Text, Field> + Artifact)
  err.rs              — ForensicError, ForensicResult, validation macros
  artifact.rs         — Artifact enum, OS-specific artifact type enums
  scow.rs             — SCow: Static Copy-On-Write string type
  context.rs          — ForensicContext: thread-local artifact/host/tenant metadata
  logging/            — Logger, Level, channel-based log macros (error!, warn!, info!, debug!, trace!)
  notifications/      — Notifier, Priority, NotificationType, notify_* macros
  channel.rs          — Underlying channel for logging and notifications
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
- `VirtualFileSystem`, `VirtualFile`, `VDirEntry`, `VFileType` — VFS traits
- `StdVirtualFS`, `ChRootFileSystem`, `StdVirtualFile` — VFS implementations
- `RegistryReader`, `RegValue`, `RegHiveKey`, `HKLM`, `HKCU`, `HKCR`, `HKU` — registry
- `ForensicDb`, `ForensicTable`, `ForensicRows`, `ForensicValue`, `ForensicRow`, `RowIterator` — database
- `EventLogReader`, `EventLogIterator`, `EventLogQuery`, `EventRecord`, `EventLevel` — event logs
- `BridgeClient`, `ForensicBridge`, `ForensicBridgeBuilder` — bridge server/client
- `ForensicProvider`, `BridgeValue`, `BridgeResponse`, `CancellationToken`, `DataOrigin`, `NodeEntry`, `NodeType` — bridge types
- `RegistryProvider`, `VfsProvider`, `EventLogProvider`, `DatabaseProvider` — bridge provider impls
- `ProviderHook` — bridge postprocessing hook trait
- `Artifact` — artifact type categorization
- `SCow` — static copy-on-write string
- `Filetime`, `ForensicTimestamp`, `WinFiletime`, `UnixTimestamp`, `filetime_to_unix_timestamp` — time types
- Logging macros: `error!`, `warn!`, `info!`, `debug!`, `trace!`, `log!`
- Notification macros: `notify!`, `notify_low!`, `notify_info!`, `notify_informational!`, `notify_medium!`, `notify_high!`, `notify_critical!`

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

// SCow: Static Copy-On-Write for error messages and other metadata.
// Avoids heap allocation for compile-time constant strings:
let msg = SCow::Borrowed("file not found");
let msg = SCow::Owned(format!("key '{}' not found", key_name));
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
| Traits | Concept noun + role suffix | `VirtualFileSystem`, `RegistryReader`, `ArtifactParser` |
| Structs | PascalCase | `ForensicData`, `ChRootFileSystem`, `StdVirtualFS` |
| Enums | PascalCase | `Field`, `RegValue`, `Artifact`, `CompressionAlgorithm` |
| Enum variants | PascalCase | `CompressionFormatLznt1`, `RegValue::DWord` |
| Constants | SCREAMING_SNAKE_CASE | `HKLM`, `FOLDER_ID_DESKTOP`, `LOCAL_SYSTEM` |
| Functions | snake_case | `filetime_to_unix_timestamp`, `to_string_sid` |
| Macros | snake_case! | `ensure_buffer_size!`, `compression_error!`, `notify_high!` |

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
// Traits are object-safe by design — avoid generics in trait methods
fn analyze(vfs: &mut dyn VirtualFileSystem, registry: &mut dyn RegistryReader) { ... }
```

### Ergonomic Wrappers on `impl dyn Trait`

When a trait method takes `&Path` but callers often have `PathBuf` or `&str`, add ergonomic wrappers in an `impl dyn Trait` block (not in the trait definition). This keeps the trait object-safe while providing a better API:

```rust
// In src/traits/vfs.rs:
impl dyn VirtualFileSystem {
    pub fn read_all_path<P: AsRef<Path>>(&mut self, path: P) -> ForensicResult<Vec<u8>> {
        self.read_all(path.as_ref())
    }
    // ... other _path suffix variants
}
```

Callers working with `Box<dyn VirtualFileSystem>` or `&mut dyn VirtualFileSystem` get these methods automatically.

### Stacking File Systems

`VirtualFileSystem` supports nesting — a ZIP filesystem can wrap a standard filesystem, which can itself be chroot'd. Enable this via `from_file()` and `from_fs()` on the trait.

### Default Implementations

Use default method bodies in trait definitions for opt-in behavior that may not apply to all implementations:

```rust
fn exists(&self, path: &Path) -> bool {
    false  // Default: conservative — assume no existence checking
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
impl RegistryReader for MockRegistry { ... }
```

`src/utils/testing.rs` provides `TestingRegistry` — a pre-built mock registry with a sample user profile hierarchy. Use it in tests for registry-dependent code:

```rust
use forensic_rs::utils::testing::{basic_registry, TestingRegistry};
let registry = basic_registry();
```

Also available: `TestingEventLogReader` with `basic_event_log()` for event log tests, and `testing_logger_dummy()` / `testing_notifier_dummy()` for capturing logging/notification messages in tests.

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

let user_envs = get_env_vars_of_users(&mut registry_reader)?;
// Returns BTreeMap<SID string, BTreeMap<var_name, expanded_value>>
```

---

## Binary Unpacking (`src/utils/unpack.rs`)

Low-level helpers for reading integers from byte slices at a given offset. Used for parsing binary forensic artifacts:

```rust
use forensic_rs::utils::unpack::{u32_at_pos, u64_at_pos};

let value = u32_at_pos(&buffer, offset)?;  // safe, returns ForensicResult
```

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

Following the project's [CONTRIBUTING.md](../CONTRIBUTING.md):

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

`ForensicTimestamp` is a compact, bitpacked u64 type (8 bytes) with microsecond precision and a year range of 0–4095. It provides a format-agnostic timestamp for forensic artifacts:

**Bit layout**: `year(12)|month(4)|day(5)|hour(5)|minute(6)|second(6)|micros(22)|reserved(4)` = 64 bits

```rust
use forensic_rs::prelude::*;

// Constructors for common forensic timestamp formats
let ts = ForensicTimestamp::with_ymd_and_hms(2024, 2, 3, 14, 10, 23, 596_000);
let ts = ForensicTimestamp::from_win_filetime(133514430235959706); // Windows FILETIME
let ts = ForensicTimestamp::from_unix_secs(1706969423);
let ts = ForensicTimestamp::from_unix_millis(1706969423596);
let ts = ForensicTimestamp::from_unix_micros(1706969423596123);
let ts = ForensicTimestamp::from_ole_date(25569.0);               // OLE Automation
let ts = ForensicTimestamp::from_webkit(13351443023595970);       // Chrome/WebKit
let ts = ForensicTimestamp::from_hfs_plus(3_789_814_223);         // macOS HFS+
let ts = ForensicTimestamp::from_cocoa(728_662_223.0);            // macOS/iOS Cocoa

// Accessors
ts.year(); ts.month(); ts.day(); ts.hour(); ts.minute(); ts.second();
ts.milliseconds(); ts.microseconds();

// Output conversions
ts.to_unix_secs(); ts.to_unix_millis(); ts.to_unix_micros(); ts.to_win_filetime();

// Bidirectional conversion with Filetime
let ft: Filetime = ts.into();
let ts2: ForensicTimestamp = ft.into();
```

`ForensicTimestamp` implements `Display` (DD-MM-YYYY HH:MM:SS.mmm), `Ord`, `Add<Duration>`, `Sub<Duration>`, and serde `Serialize`/`Deserialize` (feature-gated).

---

## RegistryKeyGuard

`RegistryKeyGuard` is an RAII wrapper that automatically calls `close_key()` when it goes out of scope:

```rust
use forensic_rs::prelude::*;

let key = reader.open_key(HKU, user_sid)?;
let guard = RegistryKeyGuard::new(&reader, key);
let value = reader.read_value(*guard, "ProfileImagePath")?;
// key is closed when `guard` drops
```

Derefs to `RegHiveKey` so it can be used directly in `RegistryReader` methods.

---

## Recursive Traversal Helpers

### walk_dir (VirtualFileSystem)

```rust
let mut vfs = StdVirtualFS::new();
vfs.walk_dir(Path::new("/var/log"), &mut |path, entry| {
    println!("{}: {:?}", path.display(), entry);
})?;
```

### walk_keys (RegistryReader)

```rust
let root = reader.open_key(HKLM, r"SOFTWARE\Microsoft")?;
reader.walk_keys(root, "SOFTWARE\\Microsoft", &mut |full_path, key| {
    println!("Key: {}", full_path);
})?;
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
