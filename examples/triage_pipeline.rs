//! Full triage pipeline example.
//!
//! Demonstrates:
//! - Custom `ArtifactParser` reading registry autorun entries
//! - Custom `Enricher` that resolves user SIDs and caches results in `TriageContext`
//! - Custom `Analyzer` that flags suspicious autorun locations
//! - Custom `TriageSink` that prints a report
//! - Built-in `TimelineSink` and `FindingCollector`
//! - `TriagePipeline` builder API
//!
//! Run with: `cargo run --example triage_pipeline`

use std::collections::BTreeMap;

use forensic_rs::prelude::*;
use forensic_rs::utils::testing::TestingRegistry;

// ---------------------------------------------------------------------------
// 1. Parser: reads Windows autorun registry keys
// ---------------------------------------------------------------------------

struct AutorunParser;

impl ArtifactParser for AutorunParser {
    fn name(&self) -> &str { "autoruns" }
    fn description(&self) -> &str { "Reads Run/RunOnce registry keys for all users" }
    fn version(&self) -> &str { "0.1.0" }

    fn supported_artifacts(&self) -> Vec<Artifact> {
        vec![Artifact::Windows(WindowsArtifacts::Registry(RegistryArtifacts::AutoRuns))]
    }

    fn parse<'a>(
        &'a mut self,
        sources: &'a mut TriageSources,
    ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<ForensicData>> + 'a>> {
        let registry = sources.registry()
            .ok_or(ForensicError::missing_data("Registry source required", SCow::Borrowed("AutorunParser")))?;
        let users = registry.list_users()?;
        let mut records = Vec::new();

        for user_sid in &users {
            let run_path = format!(r"{}\Software\Microsoft\Windows\CurrentVersion\Run", user_sid);
            let key = match registry.open_key(HKU, &run_path) {
                Ok(k) => k,
                Err(_) => continue,
            };

            let values = match registry.enumerate_values(key) {
                Ok(v) => v,
                Err(_) => { registry.close_key(key); continue; }
            };

            for value_name in values {
                let reg_val = match registry.read_value(key, &value_name) {
                    Ok(v) => v,
                    Err(e) => {
                        records.push(Err(e));
                        continue;
                    }
                };

                let mut data = ForensicData::new("WORKSTATION01",
                    Artifact::Windows(WindowsArtifacts::Registry(RegistryArtifacts::AutoRuns)));
                data.insert(Text::Borrowed("autorun.name"), Field::Text(Text::Owned(value_name)));
                data.insert(Text::Borrowed("autorun.value"), Field::Text(Text::Owned(format!("{:?}", reg_val))));
                data.insert(Text::Borrowed(USER_NAME), Field::Text(Text::Owned(user_sid.clone())));
                data.insert(Text::Borrowed("@timestamp"),
                    Field::Date(Filetime::with_ymd_and_hms(2024, 3, 15, 10, 30, 0, 0)));

                records.push(Ok(data));
            }
            registry.close_key(key);
        }

        Ok(Box::new(records.into_iter()))
    }
}

// ---------------------------------------------------------------------------
// 2. Enricher: resolves user SIDs to readable names using context cache
// ---------------------------------------------------------------------------

struct UserProfileEnricher {
    cache: BTreeMap<String, String>,
}

impl UserProfileEnricher {
    fn new() -> Self {
        Self { cache: BTreeMap::new() }
    }
}

impl Enricher for UserProfileEnricher {
    fn name(&self) -> &str { "user_profile_enricher" }

    fn enrich(&mut self, data: &mut ForensicData, context: &mut TriageContext) -> ForensicResult<()> {
        let sid = match data.field(USER_NAME) {
            Some(Field::Text(t)) => t.to_string(),
            _ => return Ok(()),
        };

        // Check local cache first
        if let Some(username) = self.cache.get(&sid) {
            data.insert(Text::Borrowed("user.resolved_name"), Field::Text(Text::Owned(username.clone())));
            return Ok(());
        }

        // Check shared context (another enricher may have resolved it)
        let ctx_key = format!("resolved_user:{}", sid);
        if let Some(Field::Text(name)) = context.get(&ctx_key) {
            let name = name.to_string();
            self.cache.insert(sid, name.clone());
            data.insert(Text::Borrowed("user.resolved_name"), Field::Text(Text::Owned(name)));
            return Ok(());
        }

        // Simulate SID resolution (in real code, this would query the registry)
        let resolved = format!("User_{}", &sid[sid.len().saturating_sub(3)..]);
        self.cache.insert(sid, resolved.clone());
        context.set(Text::Owned(ctx_key), Field::Text(Text::Owned(resolved.clone())));
        data.insert(Text::Borrowed("user.resolved_name"), Field::Text(Text::Owned(resolved)));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 3. Analyzer: flags suspicious autorun entries
// ---------------------------------------------------------------------------

struct SuspiciousAutorunAnalyzer;

impl Analyzer for SuspiciousAutorunAnalyzer {
    fn name(&self) -> &str { "suspicious_autorun" }

    fn supported_artifacts(&self) -> Vec<Artifact> {
        vec![Artifact::Windows(WindowsArtifacts::Registry(RegistryArtifacts::AutoRuns))]
    }

    fn analyze(&mut self, data: &ForensicData) -> ForensicResult<Vec<Finding>> {
        let mut findings = Vec::new();

        let value = match data.field("autorun.value") {
            Some(Field::Text(t)) => t.to_string().to_lowercase(),
            _ => return Ok(findings),
        };

        // Flag autoruns pointing to temp directories or using suspicious tools
        let suspicious_patterns = [
            ("\\temp\\", "Autorun from temp directory"),
            ("powershell", "PowerShell in autorun"),
            ("cmd.exe /c", "cmd.exe with /c flag in autorun"),
            ("wscript", "WScript in autorun"),
            ("mshta", "MSHTA in autorun"),
        ];

        for (pattern, reason) in suspicious_patterns {
            if value.contains(pattern) {
                let name = data.field("autorun.name")
                    .map(|f| format!("{:?}", f))
                    .unwrap_or_default();

                let finding = Finding::new(
                    FindingSeverity::Medium,
                    FindingCategory::SuspiciousActivity,
                    format!("Suspicious autorun: {}", name),
                )
                .with_description(format!("{}: {}", reason, value))
                .with_artifact(Artifact::Windows(WindowsArtifacts::Registry(RegistryArtifacts::AutoRuns)))
                .with_related_data(data.clone());

                findings.push(finding);
            }
        }

        Ok(findings)
    }
}

// ---------------------------------------------------------------------------
// 4. Custom Sink: prints a simple report
// ---------------------------------------------------------------------------

struct ReportSink {
    record_count: u64,
    finding_count: u64,
}

impl ReportSink {
    fn new() -> Self {
        Self { record_count: 0, finding_count: 0 }
    }
}

impl TriageSink for ReportSink {
    fn name(&self) -> &str { "report_sink" }

    fn on_data(&mut self, data: &ForensicData) -> ForensicResult<()> {
        self.record_count += 1;
        println!("  [RECORD] host={} artifact={}", data.host(), data.artifact());
        for (key, value) in data.iter() {
            println!("    {} = {:?}", key, value);
        }
        Ok(())
    }

    fn on_finding(&mut self, finding: &Finding) -> ForensicResult<()> {
        self.finding_count += 1;
        println!("  [FINDING] [{}] [{}] {}", finding.severity, finding.category, finding.title);
        if !finding.description.is_empty() {
            println!("    Description: {}", finding.description);
        }
        Ok(())
    }

    fn finalize(&mut self) -> ForensicResult<()> {
        println!("\n--- Report Summary ---");
        println!("Records processed: {}", self.record_count);
        println!("Findings generated: {}", self.finding_count);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up mock data sources
    let mut registry = TestingRegistry::new();

    // Add some autorun entries to the test registry
    let user_sid = "S-1-5-21-1366093794-4292800403-1155380978-513";
    let run_path = format!(r"{}\Software\Microsoft\Windows\CurrentVersion\Run", user_sid);

    registry.add_value(&format!("HKU\\{}", run_path), "SecurityHealth",
        RegValue::new_sz(r"C:\Windows\System32\SecurityHealthSystray.exe"));
    registry.add_value(&format!("HKU\\{}", run_path), "SuspiciousTask",
        RegValue::new_sz(r"powershell.exe -ep bypass -file C:\temp\update.ps1"));
    registry.add_value(&format!("HKU\\{}", run_path), "OneDrive",
        RegValue::new_sz(r"C:\Users\Tester\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background"));

    let vfs = StdVirtualFS::new();

    let mut sources = TriageSources::new(Box::new(vfs), Box::new(registry));

    // Build the pipeline
    let mut pipeline = TriagePipeline::builder()
        .context(TriageContext::new("WORKSTATION01", "ACME-Corp"))
        .parser(Box::new(AutorunParser))
        .enricher(Box::new(UserProfileEnricher::new()))
        .analyzer(Box::new(SuspiciousAutorunAnalyzer))
        .sink(Box::new(ReportSink::new()))
        .sink(Box::new(TimelineSink::new("@timestamp")))
        .sink(Box::new(FindingCollector::with_min_severity(FindingSeverity::Low)))
        .on_parser_error(ErrorAction::Continue)
        .build()?;

    // Run the pipeline
    println!("=== Triage Pipeline Execution ===\n");
    let result = pipeline.run(&mut sources)?;

    // Print pipeline summary
    println!("\n=== Pipeline Result ===");
    println!("Parsers run: {:?}", result.parsers_run);
    println!("Parsers skipped: {:?}", result.parsers_skipped);
    println!("Items processed: {}", result.items_processed);
    println!("Findings: {}", result.findings_count);
    println!("Errors: {}", result.errors.len());

    Ok(())
}
