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
    vfs: Option<Box<dyn VirtualFileSystem>>,
    registry: Option<Box<dyn RegistryReader>>,
}

impl TriageSources {
    pub fn vfs(&mut self) -> Option<&mut dyn VirtualFileSystem> { ... }
    pub fn registry(&self) -> Option<&dyn RegistryReader> { ... }
    pub fn has_vfs(&self) -> bool { ... }
    pub fn has_registry(&self) -> bool { ... }
}
```

For this tool, we need the registry source.

## RegistryReader Trait

The `RegistryReader` trait provides registry access:

```rust
pub trait RegistryReader {
    fn open_key(&self, hive: RegHiveKey, key_path: &str) -> ForensicResult<RegKeyHandle>;
    fn open_subkey(&self, parent: &RegKeyHandle, subkey: &str) -> ForensicResult<RegKeyHandle>;
    fn read_value(&self, key: &RegKeyHandle, value_name: &str) -> ForensicResult<RegValue>;
    fn enumerate_values(&self, key: &RegKeyHandle, visitor: &mut dyn FnMut(&str) -> ForensicResult<RegistryVisit>) -> ForensicResult<()>;
    fn enumerate_keys(&self, key: &RegKeyHandle, visitor: &mut dyn FnMut(&str) ForensicResult<RegistryVisit>) -> ForensicResult<()>;
}

pub enum RegHiveKey {
    HKEY_LOCAL_MACHINE,
    HKEY_CURRENT_USER,
    HKEY_CLASSES_ROOT,
    HKEY_USERS,
    HKEY_CURRENT_CONFIG,
}
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
        let registry_paths = vec![
            (RegHiveKey::HKEY_LOCAL_MACHINE,
             "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (RegHiveKey::HKEY_LOCAL_MACHINE,
             "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
            (RegHiveKey::HKEY_CURRENT_USER,
             "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (RegHiveKey::HKEY_CURRENT_USER,
             "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        ];

        // Check cancellation before starting
        if context.cancellation.is_cancelled() {
            return Err(CapabilityError::new(CapabilityErrorKind::Cancelled, "cancelled"));
        }

        let mut entries = Vec::new();
        let mut checked = 0u64;
        let total = registry_paths.len() as u64;

        // Query each registry path
        for (hive_key, subkey_path) in &registry_paths {
            // Report progress
            checked += 1;
            context.report_progress(
                ProgressUpdate::new(checked)
                    .with_total(total)
                    .with_message(format!("Checking {:?}", hive_key))
            ).ok();

            // Filter by hive if specified
            if let Some(h) = hive {
                let h_lower = h.to_lowercase();
                match hive_key {
                    RegHiveKey::HKEY_LOCAL_MACHINE if !h_lower.contains("lm") && !h_lower.contains("local") => continue,
                    RegHiveKey::HKEY_CURRENT_USER if !h_lower.contains("cu") && !h_lower.contains("user") => continue,
                    _ => {}
                }
            }

            // Query this registry key (pseudocode - requires registry reader)
            // let values = query_run_key(registry, hive_key, subkey_path)?;
            // for (value_name, command) in values {
            //     entries.push(...);
            // }

            // For demo: add mock data if this is the first iteration
            if entries.is_empty() {
                entries.push(AutorunEntry {
                    key: format!("{:?}\\{}", hive_key, subkey_path),
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
// 1. Create TriageSources with a registry reader
let registry = MyRegistryReader::new(); // implements RegistryReader
let sources = TriageSources::builder()
    .registry(Box::new(registry))
    .build();

// 2. Pass sources to tool via context or thread-local
// This varies by implementation - check your registry reader's API

// 3. Query registry keys
let handle = registry.open_key(HKU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")?;
let mut values = Vec::new();
registry.enumerate_values(&handle, &mut |name| {
    let value = registry.read_value(&handle, name)?;
    values.push((name.to_string(), value));
    Ok(RegistryVisit::Continue)
})?;
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

- [VFS Tools](./04_vfs_tools.md) - Analyze Prefetch files via VirtualFileSystem
- See [examples/triage_pipeline.rs:24-80](../../examples/triage_pipeline.rs) for real parser implementation
