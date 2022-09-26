# Forensic-rs

A Rust-based framework to build tools that analyze forensic artifacts and can be reused as libraries across multiple projects without changing anything.

Note: still in Alpha version

## Inner workings

We'll have some libraries that parse certaing artifacts, some for live systems that access artifacts from the host they're runing on, and some for artifacts extracted from them.

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

So with this we have:
* LiveRegistry Library: implements the *RegistryReader* trait.
* HiveParser Library: implements the *RegistryReader* trait.
* ShellBags analyzer: accepts a *RegistryReader* as a parameter to access the registry.

With this, we can reause the ShellBags analyzer to be used in a EDR-like tool or an offline analysis tool used in a forensic case.