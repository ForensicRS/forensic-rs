# Forensic-rs
[![crates.io](https://img.shields.io/crates/v/forensic-rs)](https://crates.io/crates/forensic-rs) [![documentation](https://docs.rs/forensic-rs/badge.svg)](https://docs.rs/forensic-rs) ![MIT License](https://img.shields.io/crates/l/forensic-rs)


A Rust-based framework to build tools that analyze forensic artifacts and can be reused as libraries across multiple projects without changing anything.

Note: still in Alpha version

## Introduction
The idea behind the framework is to allow the reuse of forensic artifact analysis tools. For this reason, the framework allows decoupling the code of the analysis tools from the reading of the artifacts. Thus, a tool that analyzes [UAL](https://learn.microsoft.com/en-us/windows-server/administration/user-access-logging/get-started-with-user-access-logging
) artifacts can be used regardless of whether the artifact is inside a ZIP as a result of triage or directly on the file system.

In this way, the same tools can be used if we want to make a triage processor like [Plaso](https://plaso.readthedocs.io/en/latest/), a module within an EDR or even a tool with a graphical interface like Eric Zimmerman's [Registry Explorer](https://ericzimmerman.github.io) with the advantage of the reliability of the Rust code and its easy integration into Python scripts.

### Supported artifacts

* Windows Registry: See [RegistryReader](./src/traits/registry.rs) trait.
* SQL databases: See [SqlStatement](./src/traits/sql.rs) trait. There is also a basic wrapper example around the sqlite crate in [sql_tests](./src/traits/sql.rs).
* File Systems: With this trait we can read files and directories. It is very useful because we can stack file systems: A file inside a OleObject inside a ZIP file that is also inside a ZIP. See [VirtualFileSystem](./src/traits/vfs.rs) and the implementation using the standard library (std::fs) in [StdVirtualFS](./src/core/fs.rs).


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
let conn : sqlite::Connection = prepare_db();
let statement : sqlite::Statement = prepare_statement(&conn, "SELECT name, age FROM users;");
let mut wrap = SqliteWrapper::new(statement);
test_database_content(&mut wrap);

fn test_database_content(wrap : &mut impl SqlStatement) {
    assert!(wrap.next().unwrap());
    let name : String = wrap.read(0).unwrap();
    let age : usize = wrap.read(1).unwrap();
    assert_eq!("Alice", name);
    assert_eq!(42, age);
    assert!(wrap.next().unwrap());
    let name : String = wrap.read(0).unwrap();
    let age : usize = wrap.read(1).unwrap();
    assert_eq!("Bob", name);
    assert_eq!(69, age);
    assert!(!wrap.next().unwrap());
}
```

### VFS Example
Extracted from [StdVirtualFS](./src/core/fs.rs) tests using sqlite db.

```rust
const CONTENT: &'static str = "File_Content_Of_VFS";
let tmp = std::env::temp_dir();
let tmp_file = tmp.join("test_vfs_file.txt");
let mut file = std::fs::File::create(&tmp_file).unwrap();
file.write_all(CONTENT.as_bytes()).unwrap();
drop(file);

let std_vfs = StdVirtualFS::new();
test_file_content(&std_vfs,&tmp_file);

fn test_file_content(std_vfs : &impl VirtualFileSystem, tmp_file : &PathBuf) {
    let content = std_vfs.read_to_string(tmp_file).unwrap();
    assert_eq!(CONTENT, content);
    
}
```

## List of libraries
* **frnsc-liveregistry-rs**: Implements *RegistryReader* using the Windows API to access the registry of a live system. https://github.com/SecSamDev/frnsc-liveregistry-rs
* **reg-analyzer-rs**: Analyzes registry artifacts for evidences. https://github.com/SecSamDev/reg-analyzer-rs