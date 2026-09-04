# Forensic-rs
[![crates.io](https://img.shields.io/crates/v/forensic-rs.svg?style=for-the-badge&logo=rust)](https://crates.io/crates/forensic-rs) [![documentation](https://img.shields.io/badge/read%20the-docs-9cf.svg?style=for-the-badge&logo=docs.rs)](https://docs.rs/forensic-rs) [![MIT License](https://img.shields.io/crates/l/forensic-rs?style=for-the-badge)](https://github.com/ForensicRS/forensic-rs/blob/main/LICENSE) [![Rust](https://img.shields.io/github/actions/workflow/status/ForensicRS/forensic-rs/rust.yml?style=for-the-badge)](https://github.com/ForensicRS/forensic-rs/workflows/Rust/badge.svg?branch=main)


A Rust-based framework to build tools that analyze forensic artifacts and can be reused as libraries across multiple projects without changing anything.

**Current version**: 0.14.0

## Community

[![Discord][discord-badge]][chat-url]

Join [the conversation on Discord][chat-url] to discuss anything related to ForensicRS.

[chat-url]: https://discord.gg/uVq4289B
[discord-badge]: https://img.shields.io/badge/Discord-chat-5865F2?style=for-the-badge&logo=discord

## Introduction
The idea behind the framework is to allow the reuse of forensic artifact analysis tools. For this reason, the framework decouples the code of the analysis tools that parses or reads artifacts from the ones that access the readed value: registry keys, files, SQL rows. Thus, a tool that analyzes [UAL](https://learn.microsoft.com/en-us/windows-server/administration/user-access-logging/get-started-with-user-access-logging
) artifacts can be used regardless of whether the artifact is inside a ZIP as a result of triage or directly on the file system.

In this way, the same tools can be used if we want to make a triage processor like [Plaso](https://plaso.readthedocs.io/en/latest/), a module within an EDR or even a tool with a graphical interface like Eric Zimmerman's [Registry Explorer](https://ericzimmerman.github.io) with the advantage of the reliability of the Rust code and its easy integration into Python scripts.

### Supported artifacts

* **Windows Registry**: See [`Registry`/`RegistryExt`](./src/traits/registry/mod.rs) traits. `RegistryExt::key()` opens a single hive-prefixed path (e.g. `r"HKLM\SOFTWARE\..."`) into a lifetime-tied `RegKey` handle that closes automatically on drop and also supports explicit `close()`. Windows-specific semantics (`system_root()`, `users()`, `build()`) live as free functions over `&dyn Registry` in [`traits::registry::windows`](./src/traits/registry/windows.rs).
* **SQL databases**: See [`SqlStatement`](./src/traits/sql.rs) trait and the richer [`ForensicDb`](./src/traits/db.rs) abstraction. Parsers discover database files through a VFS and mount each one with a [`FormatFactory`](./src/traits/format.rs) without losing access to companion files such as SQLite WAL files. A basic sqlite wrapper example is included in the SQL trait tests.
* **File Systems**: Read files and directories with support for stacked virtual filesystems (e.g., a file inside a ZIP inside another ZIP), composed via `MountTable`/`OverlayFs` or mounted on demand through a [`FormatFactory`](./src/traits/format.rs)/[`MountResolver`](./src/core/resolver.rs), addressed by a structured [`EvidenceLocator`](./src/core/locator.rs) rather than a string path. `FileSystemExt::walk()` returns a lazy, streaming iterator driven by `WalkOptions` (`skip_errors` tolerates unreadable descendants instead of aborting the walk, `max_depth` bounds recursion); `FileSystemExt::glob()`/`glob_iter()` match paths against a pattern. See [`FileSystem`/`FileSystemExt`](./src/traits/vfs.rs) and the standard library implementation [`StdVirtualFS`](./src/core/fs/stdfs.rs).
* **Windows Event Logs**: Abstract `EventLogReader` trait for querying event log records with filtering by event ID, time range, provider, severity, and channel. File-backed logs are discovered through a VFS and opened by mounting them with a [`FormatFactory`](./src/traits/format.rs). Includes a fallible `EventLogIterator` and `EventLogQuery` builder. See [`src/traits/events.rs`](./src/traits/events.rs).
* **Timestamps**: `ForensicTimestamp` — a 16-byte, 16-byte-aligned UTC timestamp with nanosecond precision, optional source offset, and precision/provenance flags. `Timestamp128` is an alias for the same type. Constructors cover Windows FILETIME, Unix secs/millis/micros/nanos, OLE Automation dates, WebKit/Chrome, macOS HFS+, Cocoa/Core Data, and `SystemTime`.
* **Windows Decompression**: LZNT1, LZ77 and LZ77+Huffman algorithms per the MS-XCA specification. See [`decompress()`](./src/utils/win/decompress/mod.rs).
* **Windows Utilities**: SID-to-string conversion, well-known shell folder ID constants (60+), and registry-based user environment variable resolution. See [`src/utils/win/`](./src/utils/win/).
* **Binary Unpacking**: Safe integer extraction helpers for parsing binary forensic artifacts. See [`src/utils/unpack.rs`](./src/utils/unpack.rs).
* **ECS Field Dictionary**: ~80 Elastic Common Schema field name constants for consistent artifact field naming. See [`src/dictionary.rs`](./src/dictionary.rs).
* **User Activity Tracking**: `ForensicActivity` with enriched `ProgramExecution` (arguments, working directory, run count) and extended `FileSystemActivity` variants (Rename, Read, Write). See [`src/activity.rs`](./src/activity.rs).
* **ForensicBridge**: A channel-based multi-threaded bridge that exposes all artifact domains (registry, VFS, event logs, databases) as navigable trees for UI consumers such as VSCode extensions. Supports pagination, cooperative cancellation, and extensible `ProviderHook`s for injecting virtual parsed nodes. See [`src/bridge/`](./src/bridge/).
* **MCP capability integration**: Protocol-neutral, caller-scoped tools and resources for external MCP servers, including non-disclosing access control, source guards, progress, cancellation, and trusted audit records. See the [MCP Server Developer Guide](./docs/mcp-server-guide/).


### Registry Example
So in this framework we will have libraries that allows us to access the Windows registry. One in a live environment using the Windows API, and another one that parses a registry hive.
So we will also have libraries that extracts data from the registry, theses libraries need to be decoupled from the registry access implementation.

Here is where this framework comes to help with the traits:

```rust
pub trait Registry: Send + Sync {
    fn root(&self, hive: PredefinedHive) -> ForensicResult<RawKey>;
    fn open_raw(&self, parent: &RawKey, name: &str) -> ForensicResult<RawKey>;
    fn close_raw(&self, key: &RawKey);
    fn read_raw(&self, key: &RawKey, value: &str) -> ForensicResult<RegValue>;
    fn values_raw(&self, key: &RawKey) -> ForensicResult<Vec<(String, RegValue)>>;
    fn keys_raw(&self, key: &RawKey) -> ForensicResult<Vec<KeyEntry>>;
    fn info_raw(&self, key: &RawKey) -> ForensicResult<KeyInfo>;
    // Required: lazy, one-at-a-time enumeration (no default — see the
    // trait's doc comment for why boxing `values_raw`'s `Vec` wouldn't do).
    fn values_iter_raw<'a>(&'a self, key: &RawKey) -> ForensicResult<Box<dyn Iterator<Item = (String, RegValue)> + 'a>>;
    fn keys_iter_raw<'a>(&'a self, key: &RawKey) -> ForensicResult<Box<dyn Iterator<Item = KeyEntry> + 'a>>;
}
```

`Registry` is the mechanical, backend-implemented core, keyed by an opaque `RawKey`. Analysis code instead uses the blanket-impl'd `RegistryExt`, which turns a single hive-prefixed path string into a lifetime-tied `RegKey` handle:

```rust
use forensic_rs::prelude::*;

fn read_system_root(reg: &dyn Registry) -> ForensicResult<String> {
    let key = reg.key(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion")?;
    let system_root: String = key.value("SystemRoot")?.try_into()?;
    Ok(system_root)
    // `key` closes automatically here, when it goes out of scope.
}
```

So now we can write our analysis library without knowing if we are accessing a live system or a hive file.
* LiveRegistry Library: implements the *Registry* trait.
* HiveParser Library: implements the *Registry* trait.
* ShellBags analyzer: accepts a `&dyn Registry` as a parameter to access the registry.

And ShellBags analyzer can be used in a EDR-like agent or as a analysis tool in a forensic case.

### SQL Example 

Extracted from the [SQL trait](./src/traits/sql.rs) tests using sqlite db.
```rust
let conn = prepare_db();
let w_conn = prepare_wrapper(conn);
let mut statement = w_conn.prepare("SELECT name, age FROM users;").unwrap();
test_database_content(statement.as_mut()).expect("Should not return error");

fn test_database_content<'a>(statement : &mut dyn SqlStatement) -> ForensicResult<()> {
    assert!(statement.next()?);
    let name : String = statement.read(0)?.try_into()?;
    let age : usize = statement.read(1)?.try_into()?;
    assert_eq!("Alice", name);
    assert_eq!(42, age);
    assert!(statement.next()?);
    let name : String = statement.read(0)?.try_into()?;
    let age : usize = statement.read(1)?.try_into()?;
    assert_eq!("Bob", name);
    assert_eq!(69, age);
    assert!(!statement.next()?);
    Ok(())
}
```

### VFS Example
Extracted from [StdVirtualFS](./src/core/fs/stdfs.rs) tests.

```rust
use forensic_rs::prelude::*;

const CONTENT: &'static str = "File_Content_Of_VFS";
let tmp = std::env::temp_dir();
let tmp_file = tmp.join("test_vfs_file.txt");
let mut file = std::fs::File::create(&tmp_file).unwrap();
file.write_all(CONTENT.as_bytes()).unwrap();
drop(file);

let fs = StdVirtualFS::new();
let tmp_file_str = tmp_file.to_string_lossy().into_owned();
let path = FPath::new(&tmp_file_str);
let content = String::from_utf8(fs.read_all(path).unwrap()).unwrap();
assert_eq!(CONTENT, content);
```

`FileSystem` is `&self`-based and object-safe, so an `Arc<dyn FileSystem>` can be
shared across worker threads. Ergonomic helpers such as `read_all()`, `exists()`,
`walk()`, and `glob()` come from the blanket-impl'd `FileSystemExt` — automatically
available on every backend, with no separate implementation required:

```rust
use std::sync::Arc;
use forensic_rs::core::fs::walk::WalkOptions;

let vfs: Arc<dyn FileSystem> = Arc::new(StdVirtualFS::new());
let bytes = vfs.read_all(FPath::new("/var/log/syslog"))?;
let present = vfs.exists(FPath::new("/var/log/syslog"));

// Lazily stream a directory tree; tolerate unreadable descendants instead of
// aborting the whole walk (the default `WalkOptions::skip_errors`).
for entry in vfs.walk(FPath::new("/var/log"), &WalkOptions::default()) {
    let entry = entry?;
    println!("{}: {:?}", entry.path, entry.file_type);
}
```

`VMetadata::created_opt()`, `accessed_opt()`, and `modified_opt()` preserve
unsupported filesystem timestamps as `None`. The older epoch-substituting
accessors are deprecated because an unknown timestamp is not evidence of an
epoch timestamp.

### Error Handling Example

All operations return `ForensicResult<T>`. Use the validation macros to produce categorized errors:

```rust
use forensic_rs::prelude::*;
use forensic_rs::utils::unpack::read_u32_le_at;

fn parse_header(buf: &[u8]) -> ForensicResult<u32> {
    ensure_buffer_size!(buf, 0, 8, "header");
    ensure_format!(buf[0] == 0x4D, "header", "invalid magic");
    read_u32_le_at(buf, 4)
}
```

For binary parsing, prefer the fallible endian-explicit readers:
`read_u16_le_at`, `read_u32_le_at`, `read_u64_le_at`, and their `_be_`
counterparts. The legacy `*_at_pos` helpers are deprecated because truncated
input can panic.

`Field` conversions to `u64` and `i64` now reject negative, fractional,
non-finite, and out-of-range values. Handle the returned `ForensicError`
instead of relying on wrapping or truncating casts.

### Windows Decompression Example

```rust
use forensic_rs::utils::win::decompress::{CompressionAlgorithm, decompress};

let mut output = Vec::new();
decompress(&compressed_data, &mut output, CompressionAlgorithm::CompressionFormatLznt1)?;
```

Supported algorithms: `CompressionFormatNone`, `CompressionFormatLznt1`, `CompressionFormatXpress`, `CompressionFormatXpressHuff`.

### ForensicTimestamp Example

`ForensicTimestamp` is a validated 16-byte timestamp with nanosecond precision. The UTC instant is canonical; an optional source offset and provenance flags remain available as metadata. `Timestamp128` is a width-oriented alias.

```rust
use forensic_rs::prelude::*;

// From explicit components
let ts = ForensicTimestamp::with_ymd_and_hms(2024, 2, 3, 14, 10, 23, 596_000)?;
assert_eq!(2024, ts.year());
assert_eq!(596, ts.milliseconds());

// From common forensic formats
let ts = ForensicTimestamp::from_win_filetime(133514430235959706); // Windows FILETIME
let ts = ForensicTimestamp::from_unix_secs(1706969423);            // Unix seconds
let ts = ForensicTimestamp::from_webkit(13351443023595970);        // Chrome/WebKit
let ts = ForensicTimestamp::from_hfs_plus(3_789_814_223);          // macOS HFS+
let ts = ForensicTimestamp::try_from_cocoa(728_662_223.0)?;        // macOS/iOS Cocoa
let ts = ForensicTimestamp::try_from_ole_date(25569.0)?;           // OLE Automation

// Output conversions
let unix = ts.to_unix_secs();
let win  = ts.to_win_filetime()?;

// Convert existing Filetime input without losing 100-nanosecond precision
let ft = Filetime::new(win);
let ts2: ForensicTimestamp = ft.into();
```

### Registry Handle Example

`RegKey` is a lifetime-tied RAII guard that automatically closes the opened key
when dropped. It cannot outlive the `Registry` it was opened from, and cannot be
mixed up with a key opened from a different reader — both are enforced at
compile time:

```rust
use forensic_rs::prelude::*;

fn read_user_profile(reader: &dyn Registry, user_sid: &str) -> ForensicResult<String> {
    let key = reader.key(&format!(r"HKU\{}", user_sid))?;
    // `key` is automatically closed when it goes out of scope.
    let profile: String = key.value("ProfileImagePath")?.try_into()?;
    Ok(profile)
}
```

### EventLogReader Example

`EventLogReader` is the abstract interface for querying Windows event logs — works identically against live Event Log API, parsed `.evtx` files, or in-memory mocks.

```rust
use forensic_rs::prelude::*;
use forensic_rs::traits::events::{EventLogQuery, EventLevel};

fn count_failed_logons(reader: &dyn EventLogReader) -> ForensicResult<u32> {
    let query = EventLogQuery::new()
        .with_channels(&["Security"])
        .with_event_ids(&[4625])                    // Logon failure event
        .with_levels(&[EventLevel::Information]);

    let mut iter = reader.query(&query)?;
    let mut count = 0u32;
    while let Some(_record) = iter.next()? {
        count += 1;
    }
    Ok(count)
}
```

Query filters are optional and combinable — an empty `EventLogQuery::new()` matches all events. Multiple values within one filter are OR'd; distinct filter fields are AND'd.

### ForensicBridge Example

`ForensicBridge` exposes all artifact domains (registry, VFS, event logs, databases) as navigable trees consumable by any UI layer (VSCode extensions, web frontends, etc.) via a thread-safe channel-based protocol.

```rust
use std::sync::Arc;
use forensic_rs::bridge::server::ForensicBridgeBuilder;
use forensic_rs::bridge::providers::{RegistryProvider, VfsProvider};
use forensic_rs::core::fs::stdfs::StdVirtualFS;

// Build the bridge — all providers are owned by the worker thread
let client = ForensicBridgeBuilder::new()
    .add_provider(RegistryProvider::new(my_registry))          // my_registry: Arc<dyn Registry>
    .add_provider(VfsProvider::new(Arc::new(StdVirtualFS::new())))
    .spawn();              // → BridgeClient (Clone + Send)

// The client can be cloned and sent across threads
let providers = client.list_providers()?;       // ["Registry", "FileSystem"]
let (children, total) = client.children("Registry", "HKLM\\SOFTWARE", 0, 50)?;
let value = client.read("Registry", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProductName")?;
let meta  = client.metadata("Registry", "HKLM\\SOFTWARE")?;

client.shutdown();
```

VFS bridge metadata represents unavailable timestamps as `BridgeValue::Null`;
an epoch timestamp remains a `BridgeValue::Timestamp` and is therefore
distinguishable from missing metadata.

### Parallel Pipeline Example

`ParallelPipeline::run_with_cancellation()` accepts a cloneable
`CancellationToken`. Built-in tasks check it between records, enrichers, and
analyzers, then report their final task statistics normally.

```rust,ignore
let cancellation = CancellationToken::new();
let cancellation_for_ui = cancellation.clone();
// cancellation_for_ui.cancel(); // request cooperative shutdown from another thread
let result = pipeline.run_with_cancellation(cancellation)?;
```

When auto-matching parsers to analysis modules, use
`parser_factory_with_artifacts()` if supported artifact metadata is known
without constructing the parser. This prevents expensive unmatched parsers
from being created only to inspect their metadata.

**ProviderHooks** let you inject virtual parsed children into bridge tree nodes. This is useful for domain-specific interpretation of raw artifact data — for example, a shellbag hook can parse the binary contents of `BagMRU` registry values and expose them as decoded folder tree entries in the bridge UI without any changes to the provider itself:

```rust
use forensic_rs::bridge::hooks::{ProviderHook, virtual_segment};
use forensic_rs::bridge::{BridgeValue, NodeEntry, NodeType};

struct ShellbagHook;

impl ProviderHook for ShellbagHook {
    fn name(&self) -> &str { "shellbag" }

    fn matches_path(&self, path: &str) -> bool {
        path.contains("BagMRU")
    }

    fn matches_value(&self, _path: &str, value: &BridgeValue) -> bool {
        matches!(value, BridgeValue::Binary(_))
    }

    fn virtual_children(&self, parent_path: &str, parent_value: &BridgeValue,
                         virtual_path: &str, offset: u64, limit: u64) -> ForensicResult<(Vec<NodeEntry>, u64)> {
        // `virtual_path` is "" for this hook's own root, or a nested sub-path
        // (e.g. "Desktop") for a deeper listing within `[shellbag]`.
        // parse `parent_value` binary data and return decoded folder entries
        // virtual child paths: `{parent_path}\[shellbag]\Desktop` etc.
        todo!()
    }

    fn read_virtual(&self, parent_path: &str, virtual_child: &str) -> ForensicResult<BridgeValue> {
        todo!()
    }
}

let client = ForensicBridgeBuilder::new()
    .add_provider(RegistryProvider::new(my_registry).with_hook(Box::new(ShellbagHook)))    // my_registry: Arc<dyn Registry>
    .spawn();
```

Virtual path segments use the `[hookname]` convention so they never collide with real children:
```
HKCU\Software\Microsoft\Windows\Shell\BagMRU\0             ← real key
HKCU\Software\Microsoft\Windows\Shell\BagMRU\0\[shellbag]  ← hook root (virtual)
HKCU\Software\Microsoft\Windows\Shell\BagMRU\0\[shellbag]\Desktop  ← decoded entry
```

## Logs
To simplify the development of modules, plugins and libraries its availabe some macros with the same syntax as that of the [log](https://crates.io/crates/log) crate:
```rust
// For production use initialize_logger(logger) instead of testing_logger_dummy()
let log_receiver = testing_logger_dummy();
error!("This is log name: {}", "ERROR");
warn!("This is log name: {}", "WARN");
info!("This is log name: {}", "INFO");
debug!("This is log name: {}", "DEBUG");
trace!("This is log name: {}", "TRACE");
assert_eq!("This is log name: ERROR", log_receiver.recv().unwrap());
```


## Findings and Anomalies

Logs are for the engineer debugging the tool — they're easy to miss and carry no severity or structure. Forensic alerts don't go through logging macros; they use two value-carried mechanisms instead, so they can't be silently dropped the way a log line can:

- **`Anomalies`**: cheap (16 bytes), always-present, attached to the value a parser produced. When two sources disagree, or a checksum fails, that's evidence, not necessarily a hard error — `ForensicData::set_parsed` folds a value's `Anomalies` straight into the record.
- **`Finding`**: a structured, severity-ranked observation (`FindingSeverity`, `FindingCategory`) produced by an `Analyzer` and routed to every `TriageSink`.

The rule: if an analyst would want it in the case report, it's a `Finding` (or an `Anomaly` on the value it describes). If only an engineer debugging the tool wants it, it's a log. If the tool can't proceed, it's a `ForensicError`.

```rust
fn analyze(&mut self, data: &ForensicData, context: &TriageContext, out: &mut Vec<Finding>) -> ForensicResult<()> {
    if /* suspicious condition */ true {
        out.push(Finding::new(
            FindingSeverity::High,
            FindingCategory::AntiForensics,
            "The registry key HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList is not present. The only possibility is that someone deleted it.",
        ));
    }
    Ok(())
}
```

## Building Your Own Tool

Building a tool that implements one or more of these traits? [`docs/agent-guide/`](./docs/agent-guide/README.md) has scaffolding guidance (what a new repo needs: README, CHANGELOG, AGENTS.md, CI) and a Claude Code review skill covering both code quality and forensic soundness for tools built on this framework.

## List of libraries
* **frnsc-liveregistry-rs**: Implements *Registry* using the Windows API to access the registry of a live system. https://github.com/ForensicRS/frnsc-liveregistry-rs
* **reg-analyzer-rs**: Analyzes registry artifacts for evidences. https://github.com/SecSamDev/reg-analyzer-rs
* **Hive Reader**: Implements *Registry* parsing HIVE files. https://github.com/ForensicRS/frnsc-hive