# Tutorial: Building VFS Tools

This chapter walks through implementing `prefetch.analyze`, a tool that analyzes Windows Prefetch files to understand program execution history.

## Scenario

Prefetch files in `C:\Windows\Prefetch` contain execution history of applications. Analyzing them reveals:
- Programs that have been run
- Execution counts
- Last run times
- File paths accessed

**Note:** This example uses a **mock implementation** that returns realistic-looking data without requiring actual Prefetch files.

## Understanding VirtualFileSystem

The `VirtualFileSystem` trait provides abstract file access:

```rust
pub trait VirtualFileSystem: Send + Sync {
    fn read_to_string(&mut self, path: &Path) -> ForensicResult<String>;
    fn read_all(&mut self, path: &Path) -> ForensicResult<Vec<u8>>;
    fn metadata(&mut self, path: &Path) -> ForensicResult<VMetadata>;
    fn read_dir(&mut self, path: &Path) -> ForensicResult<Vec<VDirEntry>>;
    fn open(&mut self, path: &Path) -> ForensicResult<Box<dyn VirtualFile>>;
    fn duplicate(&self) -> Box<dyn VirtualFileSystem>;
    fn exists(&mut self, path: &Path) -> bool { ... }
}
```

**Implementations:**
- `StdVirtualFS` - Real filesystem access
- `ChRootFileSystem` - Path remapping/chroot
- ZIP-contained files - Via stacked VFS

## What We're Building

A tool that:
- Accepts `case_id` and optional `limit` parameter
- Lists Prefetch files from the VFS
- Returns filename, last run time, and execution count

## Complete Mock Implementation

```rust
// src/tools/prefetch.rs

use std::collections::BTreeMap;

use forensic_rs::field::Text;
use forensic_rs::prelude::*;

/// Tool that analyzes Windows Prefetch files for program execution history
///
/// Note: This is a MOCK implementation that returns realistic-looking data
/// without requiring actual Prefetch files. For a real implementation,
/// see the VirtualFileSystem trait and examples/triage_pipeline.rs.
pub struct PrefetchTool {
    descriptor: ToolDescriptor,
}

impl PrefetchTool {
    pub fn new() -> Self {
        Self {
            descriptor: ToolDescriptor {
                id: "prefetch.analyze".into(),
                title: "Prefetch Analyzer".into(),
                description: "Analyzes Windows Prefetch files to identify programs that have \
                    been executed, their run counts, and last execution times.".into(),

                input_schema: ValueSchema::object()
                    .property("case_id", ValueSchema::Type(ValueType::Text))
                    .required("case_id")
                    .property("limit", ValueSchema::Type(ValueType::Integer))
                    .into(),

                output_schema: Some(
                    ValueSchema::object()
                        .property("case_id", ValueSchema::Type(ValueType::Text))
                        .property("files", ValueSchema::Array(Box::new(
                            ValueSchema::Object(ObjectSchema {
                                properties: vec![
                                    (Text::Borrowed("name"), ValueSchema::Type(ValueType::Text)),
                                    (Text::Borrowed("path"), ValueSchema::Type(ValueType::Text)),
                                    (Text::Borrowed("last_run"), ValueSchema::Type(ValueType::Timestamp)),
                                    (Text::Borrowed("run_count"), ValueSchema::Type(ValueType::Integer)),
                                ],
                                required: vec![Text::Borrowed("name"), Text::Borrowed("path"),
                                               Text::Borrowed("run_count")],
                                allow_additional_properties: false,
                            })
                        )))
                        .property("total_found", ValueSchema::Type(ValueType::Integer))
                        .required(["case_id", "files", "total_found"])
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

impl ForensicTool for PrefetchTool {
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

        let limit = fields
            .get("limit")
            .and_then(CapabilityValue::as_u64)
            .unwrap_or(50) as usize;

        // Check cancellation
        if context.cancellation.is_cancelled() {
            return Err(CapabilityError::new(CapabilityErrorKind::Cancelled, "cancelled"));
        }

        // Report that we're scanning
        context.report_progress(
            ProgressUpdate::new(0).with_total(1).with_message("Scanning Prefetch directory"))
        .ok();

        // MOCK DATA: In a real implementation, you would:
        //
        // 1. Get VFS from TriageSources
        //    let vfs = sources.vfs().ok_or_else(|| ...)?;
        //
        // 2. Read directory listing
        //    let entries = vfs.read_dir(Path::new("C:\\Windows\\Prefetch"))?;
        //
        // 3. Filter for .pf files
        //    let pf_files: Vec<_> = entries.iter()
        //        .filter(|e| e.name().ends_with(".pf"))
        //        .collect();
        //
        // 4. Parse each Prefetch file
        //    for entry in pf_files.iter().take(limit) {
        //        let path = Path::new(&entry.path());
        //        let data = vfs.read_all(path)?;
        //        let parsed = parse_prefetch(&data)?;
        //        files.push(parsed);
        //    }

        // Mock Prefetch data (realistic for a compromised workstation)
        let mock_files = vec![
            PrefetchFile {
                name: "CMD.EXE".to_string(),
                path: "\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\PREFETCH\\CMD.EXE-A1B2C3D4.pf".to_string(),
                last_run: ForensicTimestamp::with_ymd_and_hms(2024, 1, 15, 14, 32, 0, 0).unwrap(),
                run_count: 156,
            },
            PrefetchFile {
                name: "POWERSHELL.EXE".to_string(),
                path: "\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\PREFETCH\\POWERSHELL.EXE-D3C4B5A6.pf".to_string(),
                last_run: ForensicTimestamp::with_ymd_and_hms(2024, 1, 15, 14, 35, 0, 0).unwrap(),
                run_count: 89,
            },
            PrefetchFile {
                name: "WMIC.EXE".to_string(),
                path: "\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\PREFETCH\\WMIC.EXE-C5D6E7F8.pf".to_string(),
                last_run: ForensicTimestamp::with_ymd_and_hms(2024, 1, 15, 14, 38, 0, 0).unwrap(),
                run_count: 12,
            },
            PrefetchFile {
                name: "NET.EXE".to_string(),
                path: "\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\PREFETCH\\NET.EXE-A7B8C9D0.pf".to_string(),
                last_run: ForensicTimestamp::with_ymd_and_hms(2024, 1, 15, 14, 40, 0, 0).unwrap(),
                run_count: 234,
            },
            PrefetchFile {
                name: "CERTUTIL.EXE".to_string(),
                path: "\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\PREFETCH\\CERTUTIL.EXE-E1F2A3B4.pf".to_string(),
                last_run: ForensicTimestamp::with_ymd_and_hms(2024, 1, 15, 14, 42, 0, 0).unwrap(),
                run_count: 5,
            },
        ];

        let total_found = mock_files.len();
        let files: Vec<_> = mock_files.into_iter().take(limit).map(|f| {
            let mut map = BTreeMap::new();
            map.insert(Text::Borrowed("name"), CapabilityValue::from(f.name));
            map.insert(Text::Borrowed("path"), CapabilityValue::from(f.path));
            map.insert(Text::Borrowed("last_run"), CapabilityValue::Timestamp(f.last_run));
            map.insert(Text::Borrowed("run_count"), CapabilityValue::from(f.run_count));
            CapabilityValue::Object(map)
        }).collect();

        // Report completion
        context.report_progress(
            ProgressUpdate::new(1).with_total(1).with_message("Scan complete"))
        .ok();

        // Build result
        let mut result_map = BTreeMap::new();
        result_map.insert(Text::Borrowed("case_id"), CapabilityValue::from(case_id.to_string()));
        result_map.insert(Text::Borrowed("files"), CapabilityValue::Array(files));
        result_map.insert(Text::Borrowed("total_found"), CapabilityValue::from(total_found as u64));

        Ok(ToolResult::structured(CapabilityValue::Object(result_map)))
    }
}

#[derive(Clone)]
struct PrefetchFile {
    name: String,
    path: String,
    last_run: ForensicTimestamp,
    run_count: u64,
}
```

## Real VFS Implementation Pattern

For a real Prefetch analyzer, you would use VFS like this:

```rust
// Pattern from examples/registry_and_vfs.rs
use forensic_rs::core::fs::stdfs::StdVirtualFS;

fn analyze_prefetch(sources: &mut TriageSources) -> ForensicResult<Vec<PrefetchFile>> {
    let vfs = sources.vfs().ok_or_else(||
        ForensicError::missing_data("prefetch", "VFS source required")
    )?;

    let prefetch_dir = Path::new("C:\\Windows\\Prefetch");
    if !vfs.exists(prefetch_dir) {
        return Ok(Vec::new());
    }

    let entries = vfs.read_dir(prefetch_dir)?;
    let mut files = Vec::new();

    for entry in entries {
        if entry.name().ends_with(".pf") {
            let full_path = prefetch_dir.join(entry.name());
            let data = vfs.read_all(&full_path)?;
            if let Some(prefetch) = parse_prefetch(&data)? {
                files.push(prefetch);
            }
        }
    }

    Ok(files)
}
```

## ForensicTimestamp Usage

`ForensicTimestamp` provides nanosecond precision:

```rust
use forensic_rs::prelude::*;

// Create from components
let ts = ForensicTimestamp::with_ymd_and_hms(2024, 1, 15, 14, 32, 0, 0)?;

// Create from Unix timestamp
let ts = ForensicTimestamp::from_unix_secs(1705326720);

// Convert to RFC 3339 for JSON
let s = ts.to_rfc3339();  // "2024-01-15T14:32:00.000000000Z"

// Convert to Unix seconds
let secs = ts.to_unix_secs();
```

## Next Steps

- [Event Log Tools](./05_eventlog_tools.md) - Query Security event logs
- [Resources](./06_resources.md) - Expose VFS as ResourceProvider
- See [examples/registry_and_vfs.rs](../../examples/registry_and_vfs.rs) for VFS usage patterns
