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

* **Windows Registry**: See [`RegistryReader`](./src/traits/registry/mod.rs) trait. Includes `RegistryKeyGuard` for RAII-based key lifetime management, `auto_close_key()` for closure-scoped key cleanup, and `walk_keys()` for recursive registry traversal.
* **SQL databases**: See [`SqlStatement`](./src/traits/sql.rs) trait and the richer [`ForensicDb`](./src/traits/db.rs) abstraction. A basic sqlite wrapper example is included in the SQL trait tests.
* **File Systems**: Read files and directories with support for stacked virtual filesystems (e.g., a file inside a ZIP inside another ZIP). Includes `walk_dir()` for recursive directory traversal. See [`VirtualFileSystem`](./src/traits/vfs.rs) and the standard library implementation [`StdVirtualFS`](./src/core/fs/stdfs.rs).
* **Windows Event Logs**: Abstract `EventLogReader` trait for querying event log records with filtering by event ID, time range, provider, severity, and channel. Includes a fallible `EventLogIterator` and `EventLogQuery` builder. See [`src/traits/events.rs`](./src/traits/events.rs).
* **Timestamps**: `ForensicTimestamp` — a compact, bitpacked u64 timestamp (8 bytes, microsecond precision, year range 0–4095) with constructors for Windows FILETIME, Unix secs/millis/micros, OLE Automation dates, WebKit/Chrome, macOS HFS+, and Cocoa/Core Data timestamps. Bidirectional conversion with the existing `Filetime` type.
* **Windows Decompression**: LZNT1, LZ77 and LZ77+Huffman algorithms per the MS-XCA specification. See [`decompress()`](./src/utils/win/decompress/mod.rs).
* **Windows Utilities**: SID-to-string conversion, well-known shell folder ID constants (60+), and registry-based user environment variable resolution. See [`src/utils/win/`](./src/utils/win/).
* **Binary Unpacking**: Safe integer extraction helpers for parsing binary forensic artifacts. See [`src/utils/unpack.rs`](./src/utils/unpack.rs).
* **ECS Field Dictionary**: ~80 Elastic Common Schema field name constants for consistent artifact field naming. See [`src/dictionary.rs`](./src/dictionary.rs).
* **User Activity Tracking**: `ForensicActivity` with enriched `ProgramExecution` (arguments, working directory, run count) and extended `FileSystemActivity` variants (Rename, Read, Write). See [`src/activity.rs`](./src/activity.rs).
* **ForensicBridge**: A channel-based multi-threaded bridge that exposes all artifact domains (registry, VFS, event logs, databases) as navigable trees for UI consumers such as VSCode extensions. Supports pagination, cooperative cancellation, and extensible `ProviderHook`s for injecting virtual parsed nodes. See [`src/bridge/`](./src/bridge/).


### Registry Example
So in this framework we will have libraries that allows us to access the Windows registry. One in a live environment using the Windows API, and another one that parses a registry hive.
So we will also have libraries that extracts data from the registry, theses libraries need to be decoupled from the registry access implementation.

Here is where this framework comes to help with the traits:

```rust
pub trait RegistryReader {
    fn open_key(&mut self, hkey : RegHiveKey, key_name : &str) -> ForensicResult<RegHiveKey>;
    fn read_value(&self, hkey : RegHiveKey, value_name : &str) -> ForensicResult<RegValue>;
    fn enumerate_values(&self, hkey : RegHiveKey) -> ForensicResult<Vec<String>>;
    fn enumerate_keys(&self, hkey : RegHiveKey) -> ForensicResult<Vec<String>>;
    fn key_at(&self, hkey : RegHiveKey, pos : u32) -> ForensicResult<String>;
    fn value_at(&self, hkey : RegHiveKey, pos : u32) -> ForensicResult<String>;
}
```

So now we can write our analysis library without knowing if we are accessing a live system or a hive file.
* LiveRegistry Library: implements the *RegistryReader* trait.
* HiveParser Library: implements the *RegistryReader* trait.
* ShellBags analyzer: accepts a *RegistryReader* as a parameter to access the registry.

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
const CONTENT: &'static str = "File_Content_Of_VFS";
let tmp = std::env::temp_dir();
let tmp_file = tmp.join("test_vfs_file.txt");
let mut file = std::fs::File::create(&tmp_file).unwrap();
file.write_all(CONTENT.as_bytes()).unwrap();
drop(file);

let mut std_vfs = StdVirtualFS::new();
let content = std_vfs.read_to_string(&tmp_file).unwrap();
assert_eq!(CONTENT, content);
```

VFS trait objects also accept `PathBuf` and `&str` via ergonomic `_path`-suffixed wrappers:

```rust
let mut vfs: Box<dyn VirtualFileSystem> = Box::new(StdVirtualFS::new());
let bytes = vfs.read_all_path("/var/log/syslog")?;
let entries = vfs.read_dir_path("/var/log")?;
```

### Error Handling Example

All operations return `ForensicResult<T>`. Use the validation macros to produce categorized errors:

```rust
use forensic_rs::prelude::*;

fn parse_header(buf: &[u8]) -> ForensicResult<u32> {
    ensure_buffer_size!(buf, 8);                      // returns Err if buf.len() < 8
    ensure_format!(buf[0] == 0x4D, "invalid magic"); // returns Err if magic is wrong
    Ok(u32::from_le_bytes(buf[4..8].try_into().unwrap()))
}
```

### Windows Decompression Example

```rust
use forensic_rs::utils::win::decompress::{CompressionAlgorithm, decompress};

let mut output = Vec::new();
decompress(&compressed_data, &mut output, CompressionAlgorithm::CompressionFormatLznt1)?;
```

Supported algorithms: `CompressionFormatNone`, `CompressionFormatLznt1`, `CompressionFormatXpress`, `CompressionFormatXpressHuff`.

### ForensicTimestamp Example

`ForensicTimestamp` is a compact bitpacked u64 (8 bytes) with microsecond precision. It can be created from many common forensic timestamp formats:

```rust
use forensic_rs::prelude::*;

// From explicit components
let ts = ForensicTimestamp::with_ymd_and_hms(2024, 2, 3, 14, 10, 23, 596_000);
assert_eq!(2024, ts.year());
assert_eq!(596, ts.milliseconds());

// From common forensic formats
let ts = ForensicTimestamp::from_win_filetime(133514430235959706); // Windows FILETIME
let ts = ForensicTimestamp::from_unix_secs(1706969423);            // Unix seconds
let ts = ForensicTimestamp::from_webkit(13351443023595970);        // Chrome/WebKit
let ts = ForensicTimestamp::from_hfs_plus(3_789_814_223);          // macOS HFS+
let ts = ForensicTimestamp::from_cocoa(728_662_223.0);             // macOS/iOS Cocoa
let ts = ForensicTimestamp::from_ole_date(25569.0);                // OLE Automation

// Output conversions
let unix = ts.to_unix_secs();
let win  = ts.to_win_filetime();

// Bidirectional conversion with Filetime
let ft: Filetime = ts.into();
let ts2: ForensicTimestamp = ft.into();
```

### RegistryKeyGuard Example

`RegistryKeyGuard` is an RAII wrapper that automatically closes registry keys when dropped:

```rust
use forensic_rs::prelude::*;

fn read_user_profile(reader: &dyn RegistryReader, user_sid: &str) -> ForensicResult<String> {
    let key = reader.open_key(HKU, user_sid)?;
    let guard = RegistryKeyGuard::new(reader, key);
    // key is automatically closed when `guard` goes out of scope
    let profile: String = reader.read_value(*guard, "ProfileImagePath")?.try_into()?;
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
use forensic_rs::bridge::server::ForensicBridgeBuilder;
use forensic_rs::bridge::providers::{RegistryProvider, VfsProvider};
use forensic_rs::core::fs::stdfs::StdVirtualFS;

// Build the bridge — all providers are owned by the worker thread
let client = ForensicBridgeBuilder::new()
    .add_provider(RegistryProvider::new(my_registry_reader))
    .add_provider(VfsProvider::new(StdVirtualFS::new()))
    .spawn();              // → BridgeClient (Clone + Send)

// The client can be cloned and sent across threads
let providers = client.list_providers()?;       // ["Registry", "FileSystem"]
let (children, total) = client.children("Registry", "HKLM\\SOFTWARE", 0, 50)?;
let value = client.read("Registry", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProductName")?;
let meta  = client.metadata("Registry", "HKLM\\SOFTWARE")?;

client.shutdown();
```

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
                         offset: u64, limit: u64) -> ForensicResult<(Vec<NodeEntry>, u64)> {
        // parse `parent_value` binary data and return decoded folder entries
        // virtual child paths: `{parent_path}\[shellbag]\Desktop` etc.
        todo!()
    }

    fn read_virtual(&self, parent_path: &str, virtual_child: &str) -> ForensicResult<BridgeValue> {
        todo!()
    }
}

let client = ForensicBridgeBuilder::new()
    .add_provider(RegistryProvider::new(my_registry).with_hook(Box::new(ShellbagHook)))
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


## Notifications and Alerts

To simplify the detection of anomalies when processing or analyzing artifacts, we can use the notifications. It uses a syntax similar as that of the [log](https://crates.io/crates/log) crate.
```rust
// For production use initialize_notifier(notifier) instead of testing_notifier_dummy()
let notification_receiver = testing_notifier_dummy();
notify_high!(NotificationType::AntiForensicsDetected, "The registry key {} is not present. The only possibility is that someone deleted it.", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
assert_eq!(r"The registry key HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList is not present. The only possibility is that someone deleted it.", notification_receiver.recv().unwrap().data);
```

## List of libraries
* **frnsc-liveregistry-rs**: Implements *RegistryReader* using the Windows API to access the registry of a live system. https://github.com/ForensicRS/frnsc-liveregistry-rs
* **reg-analyzer-rs**: Analyzes registry artifacts for evidences. https://github.com/SecSamDev/reg-analyzer-rs
* **Hive Reader**: Implements *RegistryReader* parsing HIVE files. https://github.com/ForensicRS/frnsc-hive