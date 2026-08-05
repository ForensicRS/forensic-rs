//! Core types and direct API usage (no pipeline).
//!
//! Demonstrates:
//! - `Registry`/`RegistryExt` with `TestingRegistry` and RAII `RegKey` handles
//! - `FileSystem`/`FileSystemExt` with `StdVirtualFS` and `ChRootFileSystem`
//! - `ForensicData` container: inserting fields, typed accessors, ECS dictionary
//! - `Field` enum and `Into` conversions
//! - `ForensicTimestamp` multi-format constructors
//! - Logging macros (`info!`, `warn!`, `error!`) and forensic `Finding`s
//! - `ForensicContext` initialization
//!
//! Run with: `cargo run --example registry_and_vfs`

use std::sync::Arc;

use forensic_rs::prelude::*;
use forensic_rs::utils::testing::TestingRegistry;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // -----------------------------------------------------------------------
    // 1. Registry: TestingRegistry and RAII RegKey handles
    // -----------------------------------------------------------------------
    println!("=== Registry Operations ===\n");

    let mut registry = TestingRegistry::new();

    // The default TestingRegistry has user profile data under HKU
    let user_sid = "S-1-5-21-1366093794-4292800403-1155380978-513";

    // Add some custom registry values
    registry.add_value(
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "SystemRoot",
        RegValue::new_sz(r"C:\Windows"),
    );
    registry.add_value(
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "CurrentBuild",
        RegValue::new_sz("22631"),
    );

    let env_path = format!(r"HKU\{}\Volatile Environment", user_sid);
    let key = registry.key(&env_path)?;
    let profile: String = key.value("USERPROFILE")?.try_into()?;
    let username: String = key.value("USERNAME")?.try_into()?;
    println!("User profile: {}", profile);
    println!("Username: {}", username);

    // A key closes automatically at the end of its scope.
    let app_data = {
        let key = registry.key(&env_path)?;
        let val: String = key.value("APPDATA")?.try_into()?;
        val
    };
    println!("AppData: {}", app_data);

    // One handle can be used for multiple reads.
    {
        let key = registry.key(&env_path)?;
        let domain: String = key.value("USERDOMAIN")?.try_into()?;
        println!("Domain: {}", domain);
    }

    // List users and get system info via the `windows::` free functions
    // (RFC 0001 P1: Windows semantics live outside the core `Registry` trait).
    let users = windows::users(&registry)?;
    println!("Users: {:?}", users.iter().map(|u| &u.sid).collect::<Vec<_>>());

    let sys_root = windows::system_root(&registry)?;
    println!("SystemRoot: {}", sys_root);

    // -----------------------------------------------------------------------
    // 2. FileSystem: StdVirtualFS and ChRootFileSystem
    // -----------------------------------------------------------------------
    println!("\n=== FileSystem Operations ===\n");

    let vfs = StdVirtualFS::new();

    // Read a file using the FileSystem trait (works on the real filesystem)
    let cargo_path = FPath::new("Cargo.toml");
    // `VirtualFileSystem::exists` (old, &self) and `FileSystemExt::exists`
    // (new, also &self) both apply to `StdVirtualFS` and are both in the
    // prelude — qualify explicitly to use the new trait.
    if FileSystemExt::exists(&vfs, cargo_path) {
        let metadata = vfs.metadata(cargo_path)?;
        println!("Cargo.toml size: {} bytes", metadata.len());
        println!("Cargo.toml is file: {}", metadata.is_file());
    }

    // ChRootFileSystem: remaps paths to a different root
    // This is useful for analyzing forensic images mounted at a different path
    let chroot = ChRootFileSystem::new(".", Arc::new(StdVirtualFS::new()));
    println!("ChRootFileSystem created (root: current directory)");

    // List directory contents
    let entries: Vec<DirEntry> = vfs
        .read_dir(FPath::new("."))?
        .collect::<ForensicResult<Vec<_>>>()?;
    println!("Files in current directory:");
    for entry in entries.iter().take(5) {
        let kind = match entry.file_type {
            VFileType::Directory => "dir",
            VFileType::File => "file",
            VFileType::Symlink => "symlink",
        };
        println!("  {} ({})", entry.path, kind);
    }
    if entries.len() > 5 {
        println!("  ... and {} more", entries.len() - 5);
    }

    // We keep `chroot` alive to avoid a warning
    drop(chroot);

    // -----------------------------------------------------------------------
    // 3. ForensicData: container, fields, typed accessors, ECS dictionary
    // -----------------------------------------------------------------------
    println!("\n=== ForensicData Container ===\n");

    // Initialize context for logging macros to pick up host/tenant.
    initialize_context(forensic_rs::context::ForensicContext {
        host: "WORKSTATION01".into(),
        tenant: "ACME".into(),
        artifact: Artifact::Windows(WindowsArtifacts::WinEvt(WindowsEvents::Security)),
        metadata: Default::default(),
    });

    // Every ForensicData requires a real ProvenanceId. Outside a pipeline
    // (no TriageContext here), mint one from a standalone ProvenanceStore.
    let provenance_store = ProvenanceStore::new();
    let event_log_source = provenance_store.register_source(SourceKey::Live {
        host: "WORKSTATION01".to_string(),
        api: "EventLogReader".to_string(),
    });
    let provenance = event_log_source.mint(Acquisition::LiveApi, Recovery::Allocated);

    // Create with explicit host
    let mut data = ForensicData::new("WORKSTATION01",
        Artifact::Windows(WindowsArtifacts::WinEvt(WindowsEvents::Security)), provenance);

    // Insert fields using ECS dictionary constants
    data.add_field(EVENT_CODE, Field::U64(4624));
    data.add_field(EVENT_ACTION, Field::Text(Text::Borrowed("logon-success")));
    data.add_field(USER_NAME, Field::Text(Text::Borrowed("admin")));
    data.add_field(SOURCE_IP, "192.168.1.100".into());
    data.add_field(SOURCE_PORT, 52341u64.into());

    // Insert a timestamp
    data.add_field("@timestamp",
        Field::Date(Filetime::with_ymd_and_hms(2024, 6, 15, 14, 30, 0, 0).into()));

    // Typed accessors (with lazy coercion)
    if let FieldAccess::Some(code) = data.get_u64(EVENT_CODE) {
        println!("Event code: {}", code);
    }
    if let FieldAccess::Some(action) = data.get_str(EVENT_ACTION) {
        println!("Event action: {}", action);
    }
    if let FieldAccess::Some(port) = data.get_u64(SOURCE_PORT) {
        println!("Source port: {}", port);
    }

    // Check field existence and iterate
    println!("Has user.name: {}", data.has_field(USER_NAME));
    println!("Field count: {}", data.len());

    println!("\nAll fields:");
    for (key, value) in data.iter() {
        println!("  {} = {:?}", key, value);
    }

    // -----------------------------------------------------------------------
    // 4. Field enum: Into conversions
    // -----------------------------------------------------------------------
    println!("\n=== Field Conversions ===\n");

    let f1: Field = "hello".into();
    let f2: Field = 42u64.into();
    let f3: Field = std::f64::consts::PI.into();
    let f4: Field = true.into();   // -> Field::U64(1)
    let f5: Field = false.into();  // -> Field::U64(0)

    println!("String: {:?}", f1);
    println!("u64:    {:?}", f2);
    println!("f64:    {:?}", f3);
    println!("true:   {:?}", f4);
    println!("false:  {:?}", f5);

    // -----------------------------------------------------------------------
    // 5. ForensicTimestamp: multi-format constructors
    // -----------------------------------------------------------------------
    println!("\n=== ForensicTimestamp ===\n");

    let ts1 = ForensicTimestamp::with_ymd_and_hms(2024, 6, 15, 14, 30, 0, 0)?;
    let ts2 = ForensicTimestamp::from_unix_secs(1718458200);
    let ts3 = ForensicTimestamp::from_win_filetime(133_514_430_235_959_706);
    let ts4 = ForensicTimestamp::from_webkit(13_351_443_023_595_970);

    println!("From components: {}", ts1);
    println!("From Unix secs:  {}", ts2);
    println!("From WinFT:      {}", ts3);
    println!("From WebKit:     {}", ts4);

    // Accessors
    println!("\nts1 decomposed: {}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        ts1.year(), ts1.month(), ts1.day(),
        ts1.hour(), ts1.minute(), ts1.second(), ts1.milliseconds());

    // Output conversions
    println!("ts1 -> unix_secs:    {}", ts1.to_unix_secs());
    println!("ts1 -> unix_millis:  {}", ts1.to_unix_millis());
    println!("ts1 -> win_filetime: {}", ts1.to_win_filetime()?);

    // Comparison (implements Ord)
    if ts1 < ts3 {
        println!("\nts1 is before ts3");
    } else {
        println!("\nts1 is after or equal to ts3");
    }

    // Convert between Filetime and ForensicTimestamp
    let ft = Filetime::from_unix_secs(1718458200);
    let ts_from_ft: ForensicTimestamp = ft.into();
    println!("Filetime -> ForensicTimestamp: {}", ts_from_ft);

    // -----------------------------------------------------------------------
    // 6. Logging and Findings
    // -----------------------------------------------------------------------
    println!("\n=== Logging & Findings ===\n");

    // Logging: for the engineer debugging the tool. In production you'd set
    // up a receiver; here the messages just go to the thread-local channel.
    info!("Processing artifact: {}", "Security.evtx");
    warn!("Found {} duplicate records", 3);
    error!("Failed to parse record at offset {:#x}", 0xDEAD);

    // Findings: for the analyst reading the case report. Unlike a log line,
    // a `Finding` is a structured, severity-ranked value routed to every
    // `TriageSink` when produced inside a pipeline — see the
    // `triage_pipeline` example for an `Analyzer` pushing these into the
    // pipeline's finding stream.
    let finding = Finding::new(
        FindingSeverity::High,
        FindingCategory::SuspiciousActivity,
        "Suspicious logon",
    )
    .with_description(format!(
        "Suspicious logon from {} to {}",
        "192.168.1.100", "WORKSTATION01"
    ));
    println!("{finding}");

    println!("\nDone!");

    Ok(())
}
