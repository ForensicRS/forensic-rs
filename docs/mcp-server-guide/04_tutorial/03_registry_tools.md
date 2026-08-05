# Tutorial: Building Registry Tools

This chapter walks through implementing `registry.autoruns`, a tool that queries Windows Registry `Run` and `RunOnce` keys to identify potential persistence mechanisms.

## Scenario

During incident response, you need to identify programs that automatically start when a user logs on. The Windows Registry stores these in:
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`

## What We're Building

A tool that:
- Accepts `case_id` and optional `hive` parameter
- Queries registry Run/RunOnce keys
- Returns list of autorun entries with key path, value name, and command

## Understanding TriageSources

The `TriageSources` type provides access to forensic evidence:

```rust
pub struct TriageSources {
    vfs: Option<Arc<dyn FileSystem>>,
    registry: Option<Arc<dyn Registry>>,
}

impl TriageSources {
    pub fn vfs(&self) -> Option<&Arc<dyn FileSystem>> { ... }
    pub fn registry(&self) -> Option<&Arc<dyn Registry>> { ... }
    pub fn has_vfs(&self) -> bool { ... }
    pub fn has_registry(&self) -> bool { ... }
}
```

Both sources are `Arc`-based: `FileSystem` and `Registry` are `&self`-based
and `Send + Sync`, so the same already-open source can be shared cheaply
across parallel pipeline workers instead of being re-opened per task.

For this tool, we need the registry source.

## Registry and RegistryExt Traits

The `Registry` trait is the minimal, mechanical core every backend implements:

```rust
pub trait Registry: Send + Sync {
    fn root(&self, hive: PredefinedHive) -> ForensicResult<RawKey>;
    fn open_raw(&self, parent: &RawKey, name: &str) -> ForensicResult<RawKey>;
    fn close_raw(&self, key: &RawKey);
    fn read_raw(&self, key: &RawKey, value: &str) -> ForensicResult<RegValue>;
    fn values_raw(&self, key: &RawKey) -> ForensicResult<Vec<(String, RegValue)>>;
    fn keys_raw(&self, key: &RawKey) -> ForensicResult<Vec<KeyEntry>>;
    fn info_raw(&self, key: &RawKey) -> ForensicResult<KeyInfo>;
}

pub enum PredefinedHive {
    ClassesRoot,
    CurrentConfig,
    CurrentUser,
    LocalMachine,
    Users,
    PerformanceData,
    PerformanceText,
    PerformanceNlsText,
    DynData,
}
```

You will rarely call `Registry`'s raw methods directly. Instead, use the
blanket-implemented `RegistryExt` convenience layer — this is the day-to-day
API a tool author works with:

```rust
pub trait RegistryExt: Registry {
    // `path` is a single hive-prefixed string, e.g.
    // r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" — accepts both
    // short (HKLM) and long (HKEY_LOCAL_MACHINE) forms, case-insensitively.
    fn key(&self, path: &str) -> ForensicResult<RegKey<'_, Self>>;
    fn value(&self, path: &str, name: &str) -> ForensicResult<RegValue>;
    fn keys_at(&self, path: &str) -> ForensicResult<Vec<KeyEntry>>;
    fn values_at(&self, path: &str) -> ForensicResult<Vec<(String, RegValue)>>;
    fn for_each_user_hive(
        &self,
        f: &mut dyn FnMut(&str, RegKey<'_, Self>) -> ForensicResult<()>,
    ) -> ForensicResult<()>;
}
```

`RegKey` is a lifetime-tied RAII guard returned by `key()`/`open()` — it
closes automatically when it goes out of scope (its `Drop` impl calls
`close_raw`), it cannot outlive the `Registry` it was opened from, and it
cannot be mixed up with a key opened from a different reader. There's no
`close_key()` to remember to call:

```rust
let key = registry.key(r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")?;
let values: Vec<(String, RegValue)> = key.values()?;
let subkeys: Vec<KeyEntry> = key.keys()?;
let child = key.open("SomeSubkey")?; // another RegKey, same lifetime family
// `key` (and `child`) close automatically here, at end of scope.
```

## Complete Implementation

```rust
// src/tools/registry.rs

use std::collections::BTreeMap;

use forensic_rs::field::Text;
use forensic_rs::prelude::*;

/// Tool that queries Run/RunOnce registry keys for persistence mechanisms
pub struct AutorunTool {
    descriptor: ToolDescriptor,
}

impl AutorunTool {
    pub fn new() -> Self {
        Self {
            descriptor: ToolDescriptor {
                id: "registry.autoruns".into(),
                title: "Registry Autoruns".into(),
                description: "Queries Run and RunOnce registry keys to identify \
                    programs that execute at startup. Returns key path, value name, \
                    and command for each entry.".into(),

                input_schema: ValueSchema::object()
                    .property("case_id", ValueSchema::Type(ValueType::Text))
                    .required("case_id")
                    .property("hive", ValueSchema::Type(ValueType::Text))
                    .into(),

                output_schema: Some(
                    ValueSchema::object()
                        .property("case_id", ValueSchema::Type(ValueType::Text))
                        .property("entries", ValueSchema::Array(Box::new(
                            ValueSchema::Object(ObjectSchema {
                                properties: vec![
                                    (Text::Borrowed("key"), ValueSchema::Type(ValueType::Text)),
                                    (Text::Borrowed("value"), ValueSchema::Type(ValueType::Text)),
                                    (Text::Borrowed("command"), ValueSchema::Type(ValueType::Text)),
                                    (Text::Borrowed("type"), ValueSchema::Type(ValueType::Text)),
                                ],
                                required: vec![Text::Borrowed("key"), Text::Borrowed("value"),
                                               Text::Borrowed("command"), Text::Borrowed("type")],
                                allow_additional_properties: false,
                            })
                        )))
                        .required(["case_id", "entries"])
                        .into(),
                ),

                hints: ToolHints {
                    read_only: true,
                    idempotent: true,
                    ..ToolHints::default()
                },
            },
        }
    }
}

impl ForensicTool for AutorunTool {
    fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    fn invoke(
        &self,
        input: CapabilityValue,
        context: &InvocationContext,
    ) -> CapabilityResult<ToolResult> {
        // Parse input
        let fields = input.as_object().ok_or_else(||
            CapabilityError::new(CapabilityErrorKind::InvalidInput, "input must be an object")
        )?;

        let case_id = fields
            .get("case_id")
            .and_then(CapabilityValue::as_text)
            .ok_or_else(|| CapabilityError::new(CapabilityErrorKind::InvalidInput, "case_id required"))?;

        let hive = fields.get("hive").and_then(CapabilityValue::as_text);

        // Get registry source from context
        // Note: In a real implementation, TriageSources would be passed via context
        // For this example, we demonstrate the pattern
        //
        // Each entry is a single hive-prefixed path string — the `Registry`/
        // `RegistryExt` API takes one path argument, not a separate hive enum
        // plus a relative subkey.
        let registry_paths = vec![
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ];

        // Check cancellation before starting
        if context.cancellation.is_cancelled() {
            return Err(CapabilityError::new(CapabilityErrorKind::Cancelled, "cancelled"));
        }

        let mut entries = Vec::new();
        let mut checked = 0u64;
        let total = registry_paths.len() as u64;

        // Query each registry path
        for path in &registry_paths {
            // Report progress
            checked += 1;
            context.report_progress(
                ProgressUpdate::new(checked)
                    .with_total(total)
                    .with_message(format!("Checking {}", path))
            ).ok();

            // Filter by hive if specified
            if let Some(h) = hive {
                let h_lower = h.to_lowercase();
                let is_local_machine = path.starts_with("HKLM");
                let is_current_user = path.starts_with("HKCU");
                if is_local_machine && !h_lower.contains("lm") && !h_lower.contains("local") {
                    continue;
                }
                if is_current_user && !h_lower.contains("cu") && !h_lower.contains("user") {
                    continue;
                }
            }

            // Query this registry key (pseudocode - requires a `Registry` source)
            // let key = registry.key(path)?;
            // for (value_name, value) in key.values()? {
            //     entries.push(...);
            // } // `key` closes automatically when it drops at the end of scope

            // For demo: add mock data if this is the first iteration
            if entries.is_empty() {
                entries.push(AutorunEntry {
                    key: path.to_string(),
                    value: "SecurityHealth".to_string(),
                    command: "C:\\Windows\\System32\\SecurityHealthSystray.exe".to_string(),
                    type_: "Run".to_string(),
                });
            }
        }

        // Build result
        let entries_value: Vec<CapabilityValue> = entries.into_iter().map(|e| {
            let mut map = BTreeMap::new();
            map.insert(Text::Borrowed("key"), CapabilityValue::from(e.key));
            map.insert(Text::Borrowed("value"), CapabilityValue::from(e.value));
            map.insert(Text::Borrowed("command"), CapabilityValue::from(e.command));
            map.insert(Text::Borrowed("type"), CapabilityValue::from(e.type_));
            CapabilityValue::Object(map)
        }).collect();

        let mut result_map = BTreeMap::new();
        result_map.insert(Text::Borrowed("case_id"), CapabilityValue::from(case_id.to_string()));
        result_map.insert(Text::Borrowed("entries"), CapabilityValue::Array(entries_value));

        Ok(ToolResult::structured(CapabilityValue::Object(result_map)))
    }
}

#[derive(Clone)]
struct AutorunEntry {
    key: String,
    value: String,
    command: String,
    type_: String,
}
```

## Integration with Real Registry

For a complete implementation that uses actual registry data, see the pattern from `examples/triage_pipeline.rs:24-80`. The key integration points are:

```rust
use std::sync::Arc;

// 1. Create TriageSources with a registry
let registry: Arc<dyn Registry> = Arc::new(MyRegistry::new()); // implements `Registry`
let sources = TriageSources::builder()
    .registry(registry)
    .build();

// 2. Pass sources to tool via context or thread-local
// This varies by implementation - check how your server wires
// `TriageSources` into `ForensicTool::invoke`

// 3. Query registry keys via RegistryExt/RegKey - a single hive-prefixed
// path, no separate hive argument. The key closes automatically when it
// drops at the end of scope.
if let Some(registry) = sources.registry() {
    let key = registry.key(r"HKU\S-1-5-21-...\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")?;
    let values: Vec<(String, RegValue)> = key.values()?;
    for (value_name, value) in &values {
        println!("{} = {:?}", value_name, value);
    }
}

// `for_each_user_hive` expands `*` over every user SID under HKEY_USERS -
// useful for a "check this Run key for every user" tool like this one.
if let Some(registry) = sources.registry() {
    registry.for_each_user_hive(&mut |sid, hku| {
        if let Ok(run_key) = hku.open(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run") {
            for (value_name, value) in run_key.values()? {
                println!("[{}] {} = {:?}", sid, value_name, value);
            }
        }
        Ok(())
    })?;
}
```

## Understanding ForensicsData

When building tools that analyze registry data, you may work with `ForensicData`:

```rust
pub struct ForensicData {
    artifact: Artifact,
    fields: BTreeMap<Text, Field>,
}

impl ForensicData {
    pub fn new(host: &str, artifact: Artifact) -> Self { ... }
    pub fn field(&self, field_name: &str) -> Option<&Field> { ... }
    pub fn set(&mut self, field_name: &'static str, value: impl Into<Field>) { ... }
}
```

The `Field` type supports registry values:
```rust
pub enum Field {
    Null,
    Bool(bool),
    U64(u64),
    I64(i64),
    F64(f64),
    Text(Text),
    Date(ForensicTimestamp),
    Binary(Vec<u8>),
    // ...
}
```

## Next Steps

- [VFS Tools](./04_vfs_tools.md) - Analyze Prefetch files via FileSystem
- See [examples/triage_pipeline.rs:24-80](../../examples/triage_pipeline.rs) for real parser implementation
