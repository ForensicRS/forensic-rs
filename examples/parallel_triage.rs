//! Parallel triage pipeline example.
//!
//! Demonstrates the analyzer-centric [`AnalysisModule`] API with auto-matching
//! and the lower-level [`StandardParallelTask`] for comparison.
//!
//! Scenario: a triage ZIP from a Windows machine contains MFT records, Windows
//! Event Log entries, and autorun registry keys. Each artifact type has its own
//! parser and analyzer. By registering parser factories on the parallel pipeline,
//! the framework automatically wires each analyzer to the parsers it needs
//! based on their declared [`Artifact`] types — no manual per-module wiring.
//!
//! Key concepts shown:
//! - [`AnalysisModule`] / [`AnalysisModuleBuilder`] — analyzer-first task
//! - [`ParserFactory`] — factory registered once, cloned into N matching modules
//! - Auto-matching via `Analyzer::supported_artifacts` ∩ `ArtifactParser::supported_artifacts`
//! - [`StandardParallelTask`] as a lower-level escape hatch (explicit parser)
//! - Pipeline-level sinks shared across all parallel tasks
//! - Bounded channel backpressure via [`ParallelPipelineBuilder::channel_capacity`]
//!
//! Run with: `cargo run --example parallel_triage`

use std::collections::BTreeMap;

use forensic_rs::prelude::*;

// ===========================================================================
// Artifact helpers
// ===========================================================================

fn mft_artifact() -> Artifact {
    Artifact::Windows(WindowsArtifacts::MFT)
}

fn evt_artifact() -> Artifact {
    Artifact::Windows(WindowsArtifacts::WinEvt(WindowsEvents::Unknown))
}

fn autorun_artifact() -> Artifact {
    Artifact::Windows(WindowsArtifacts::Registry(RegistryArtifacts::AutoRuns))
}

// ===========================================================================
// Mock parsers
// ===========================================================================

/// Simulates an MFT parser that emits file-creation records.
struct MockMftParser {
    records: Vec<(&'static str, u64)>, // (path, inode)
}

impl MockMftParser {
    fn new() -> Self {
        Self {
            records: vec![
                (r"C:\Windows\System32\cmd.exe",            1001),
                (r"C:\Windows\Temp\suspicious.ps1",         1002),
                (r"C:\Users\Alice\Documents\report.docx",   1003),
                (r"C:\Windows\Temp\update.exe",             1004),
            ],
        }
    }
}

impl ArtifactParser for MockMftParser {
    fn name(&self) -> &str { "mft_parser" }
    fn description(&self) -> &str { "Mock MFT parser" }
    fn version(&self) -> &str { "0.1.0" }
    fn supported_artifacts(&self) -> Vec<Artifact> { vec![mft_artifact()] }

    fn parse<'a>(
        &'a mut self,
        _sources: &'a mut TriageSources,
    ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<ForensicData>> + 'a>> {
        let items: Vec<ForensicResult<ForensicData>> = self.records.iter().map(|(path, inode)| {
            let mut d = ForensicData::new("WORKSTATION01", mft_artifact());
            d.insert(Text::Borrowed("file.path"),  Field::Text(Text::Owned(path.to_string())));
            d.insert(Text::Borrowed("file.inode"), Field::U64(*inode));
            d.insert(Text::Borrowed("@timestamp"),
                Field::Date(Filetime::with_ymd_and_hms(2024, 6, 15, 10, 0, 0, 0)));
            Ok(d)
        }).collect();
        Ok(Box::new(items.into_iter()))
    }
}

/// Simulates a Windows Event Log parser.
struct MockEvtxParser {
    channel: &'static str,
    events: Vec<(u64, u64)>, // (record_id, event_id)
}

impl MockEvtxParser {
    fn security() -> Self {
        Self {
            channel: "Security",
            events: vec![
                (1001, 4624), // Logon success
                (1002, 4625), // Logon failure
                (1003, 4634), // Logoff
                // deliberate gap: 1004-1006 missing
                (1007, 4624),
                (1008, 4672),
            ],
        }
    }
}

impl ArtifactParser for MockEvtxParser {
    fn name(&self) -> &str { self.channel }
    fn description(&self) -> &str { "Mock EVTX parser" }
    fn version(&self) -> &str { "0.1.0" }
    fn supported_artifacts(&self) -> Vec<Artifact> { vec![evt_artifact()] }

    fn parse<'a>(
        &'a mut self,
        _sources: &'a mut TriageSources,
    ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<ForensicData>> + 'a>> {
        let channel = self.channel;
        let items: Vec<ForensicResult<ForensicData>> = self.events.iter().map(|&(record_id, event_id)| {
            let mut d = ForensicData::new("WORKSTATION01", evt_artifact());
            d.insert(Text::Borrowed("event.record_id"), Field::U64(record_id));
            d.insert(Text::Borrowed("event.code"),      Field::U64(event_id));
            d.insert(Text::Borrowed("event.channel"),   Field::Text(Text::Borrowed(channel)));
            d.insert(Text::Borrowed("@timestamp"),
                Field::Date(Filetime::with_ymd_and_hms(2024, 6, 15, 10, 0, 0, 0)));
            Ok(d)
        }).collect();
        Ok(Box::new(items.into_iter()))
    }
}

/// Emits hardcoded autorun entries (simulating a registry parser output).
///
/// In production this would read from `sources.registry()`. Here we use
/// static data so the parser is `Send + 'static` without any real registry.
struct MockAutorunParser {
    entries: Vec<(&'static str, &'static str)>, // (name, command)
}

impl MockAutorunParser {
    fn new() -> Self {
        Self {
            entries: vec![
                ("Malware",  r"powershell.exe -ep bypass C:\temp\malware.ps1"),
                ("OneDrive", r"C:\Users\Alice\AppData\Local\Microsoft\OneDrive\OneDrive.exe"),
                ("Teams",    r"C:\Users\Alice\AppData\Local\Microsoft\Teams\Update.exe --processStart Teams.exe"),
            ],
        }
    }
}

impl ArtifactParser for MockAutorunParser {
    fn name(&self) -> &str { "autorun_parser" }
    fn description(&self) -> &str { "Mock autorun registry parser" }
    fn version(&self) -> &str { "0.1.0" }
    fn supported_artifacts(&self) -> Vec<Artifact> { vec![autorun_artifact()] }

    fn parse<'a>(
        &'a mut self,
        _sources: &'a mut TriageSources,
    ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<ForensicData>> + 'a>> {
        let sid = "S-1-5-21-1366093794-4292800403-1155380978-513";
        let items: Vec<ForensicResult<ForensicData>> = self.entries.iter().map(|&(name, cmd)| {
            let mut d = ForensicData::new("WORKSTATION01", autorun_artifact());
            d.insert(Text::Borrowed("autorun.name"),  Field::Text(Text::Borrowed(name)));
            d.insert(Text::Borrowed("autorun.value"), Field::Text(Text::Borrowed(cmd)));
            d.insert(Text::Borrowed("autorun.user"),  Field::Text(Text::Borrowed(sid)));
            d.insert(Text::Borrowed("@timestamp"),
                Field::Date(Filetime::with_ymd_and_hms(2024, 6, 15, 10, 0, 0, 0)));
            Ok(d)
        }).collect();
        Ok(Box::new(items.into_iter()))
    }
}

// ===========================================================================
// Analyzers
// ===========================================================================

/// Flags files created in temp directories.
struct TempWriteAnalyzer;

impl Analyzer for TempWriteAnalyzer {
    fn name(&self) -> &str { "temp_write_analyzer" }
    fn supported_artifacts(&self) -> Vec<Artifact> { vec![mft_artifact()] }

    fn analyze(&mut self, data: &ForensicData) -> ForensicResult<Vec<Finding>> {
        let path = match data.field("file.path") {
            Some(Field::Text(t)) => t.to_lowercase(),
            _ => return Ok(vec![]),
        };
        if path.contains("\\temp\\") || path.contains("/tmp/") {
            let label = match data.field("file.path") {
                Some(Field::Text(t)) => t.to_string(),
                _ => String::new(),
            };
            return Ok(vec![
                Finding::new(
                    FindingSeverity::Medium,
                    FindingCategory::SuspiciousActivity,
                    format!("File created in temp: {label}"),
                )
                .with_artifact(mft_artifact()),
            ]);
        }
        Ok(vec![])
    }
}

/// Detects gaps in event record ID sequences (see `event_gap_detector.rs` for the full version).
struct EventGapAnalyzer {
    channels: BTreeMap<String, Vec<u64>>,
}

impl EventGapAnalyzer {
    fn new() -> Self { Self { channels: BTreeMap::new() } }
}

impl Analyzer for EventGapAnalyzer {
    fn name(&self) -> &str { "event_gap_analyzer" }
    fn supported_artifacts(&self) -> Vec<Artifact> { vec![evt_artifact()] }

    fn analyze(&mut self, data: &ForensicData) -> ForensicResult<Vec<Finding>> {
        if let (Some(Field::Text(ch)), Some(Field::U64(rid))) = (
            data.field("event.channel"),
            data.field("event.record_id"),
        ) {
            self.channels.entry(ch.to_string()).or_default().push(*rid);
        }
        Ok(vec![])
    }

    fn finalize(&mut self) -> ForensicResult<Vec<Finding>> {
        let mut findings = Vec::new();
        for (channel, ids) in &self.channels {
            let mut sorted = ids.clone();
            sorted.sort_unstable();
            for w in sorted.windows(2) {
                if w[1] - w[0] > 1 {
                    findings.push(
                        Finding::new(
                            FindingSeverity::High,
                            FindingCategory::MissingData,
                            format!("Gap in {} between record {} and {}", channel, w[0], w[1]),
                        )
                        .with_description(format!("{} record(s) missing", w[1] - w[0] - 1))
                        .with_artifact(evt_artifact()),
                    );
                }
            }
        }
        Ok(findings)
    }
}

/// Flags suspicious autorun entries containing known living-off-the-land binaries.
struct SuspiciousAutorunAnalyzer;

impl Analyzer for SuspiciousAutorunAnalyzer {
    fn name(&self) -> &str { "suspicious_autorun" }
    // No supported_artifacts() override → accepts everything; useful when
    // combined with an explicit parser (as in the StandardParallelTask below).
    fn supported_artifacts(&self) -> Vec<Artifact> { vec![] }

    fn analyze(&mut self, data: &ForensicData) -> ForensicResult<Vec<Finding>> {
        let value = match data.field("autorun.value") {
            Some(Field::Text(t)) => t.to_lowercase(),
            _ => String::new(),
        };
        let name = match data.field("autorun.name") {
            Some(Field::Text(t)) => t.to_string(),
            _ => String::new(),
        };
        for pat in &["powershell", "wscript", "mshta", "\\temp\\"] {
            if value.contains(pat) {
                return Ok(vec![
                    Finding::new(
                        FindingSeverity::High,
                        FindingCategory::SuspiciousActivity,
                        format!("Suspicious autorun: {name}"),
                    )
                    .with_description(format!("Pattern '{pat}' found in autorun value"))
                    .with_artifact(autorun_artifact()),
                ]);
            }
        }
        Ok(vec![])
    }
}

// ===========================================================================
// Custom sink: collects and prints a summary report
// ===========================================================================

struct ReportSink {
    records: u64,
    findings: Vec<String>,
}

impl ReportSink {
    fn new() -> Self { Self { records: 0, findings: Vec::new() } }
}

impl TriageSink for ReportSink {
    fn name(&self) -> &str { "report_sink" }

    fn on_data(&mut self, _data: &ForensicData) -> ForensicResult<()> {
        self.records += 1;
        Ok(())
    }

    fn on_finding(&mut self, finding: &Finding) -> ForensicResult<()> {
        self.findings.push(format!(
            "[{sev}] [{cat}] {title}",
            sev   = finding.severity,
            cat   = finding.category,
            title = finding.title,
        ));
        Ok(())
    }

    fn finalize(&mut self) -> ForensicResult<()> {
        println!("\n=== Pipeline Report ===");
        println!("Records processed : {}", self.records);
        println!("Findings          : {}", self.findings.len());
        for f in &self.findings {
            println!("  • {f}");
        }
        Ok(())
    }
}

// ===========================================================================
// Main
// ===========================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Parallel Triage Pipeline ===\n");

    // -----------------------------------------------------------------------
    // AnalysisModules — no explicit parsers; auto-matching injects them.
    //
    // At build() time the pipeline calls each registered factory and compares
    // supported_artifacts() sets. Matching parsers are injected into the module.
    // -----------------------------------------------------------------------

    let mft_module = AnalysisModuleBuilder::new("mft_analysis")
        .analyzer(Box::new(TempWriteAnalyzer))
        // No .parser() → auto-match injects MockMftParser (artifacts overlap: MFT)
        .sources(|| TriageSources::builder().build())
        .context(TriageContext::new("WORKSTATION01", "ACME-Corp"))
        .build()?;

    let evt_module = AnalysisModuleBuilder::new("evt_gap_analysis")
        .analyzer(Box::new(EventGapAnalyzer::new()))
        // No .parser() → auto-match injects MockEvtxParser (artifacts overlap: WinEvt)
        .sources(|| TriageSources::builder().build())
        .context(TriageContext::new("WORKSTATION01", "ACME-Corp"))
        .build()?;

    // -----------------------------------------------------------------------
    // StandardParallelTask — lower-level API for when you need an explicit
    // parser and full control over the parser/analyzer pairing.
    // SuspiciousAutorunAnalyzer declares supported_artifacts() = [] (accept-all),
    // but here we use StandardParallelTask so the parser is always explicit.
    // -----------------------------------------------------------------------

    let autorun_task = StandardParallelTaskBuilder::new("registry_autoruns")
        .parser(Box::new(MockAutorunParser::new()))
        .analyzer(Box::new(SuspiciousAutorunAnalyzer))
        .sources(|| TriageSources::builder().build())
        .context(TriageContext::new("WORKSTATION01", "ACME-Corp"))
        .build()?;

    // -----------------------------------------------------------------------
    // Build the parallel pipeline.
    //
    // Factories are registered once. build() calls each factory and compares
    // artifacts with pending AnalysisModules. Matching parsers are cloned into
    // the module; non-matching ones are dropped. StandardParallelTask gets no
    // factories — it already has an explicit parser.
    // -----------------------------------------------------------------------

    let mut pipeline = ParallelPipeline::builder()
        .workers(3)
        .channel_capacity(128)
        // Factory pool — matched to modules by supported_artifacts() overlap.
        .parser_factory(Box::new(|| Box::new(MockMftParser::new())))
        .parser_factory(Box::new(|| Box::new(MockEvtxParser::security())))
        // Modules — receive auto-matched parsers at build() time.
        .module(mft_module)
        .module(evt_module)
        // Low-level task — has explicit parser, bypasses factory matching.
        .task(Box::new(autorun_task))
        // Shared sinks — called on the main thread for all tasks.
        .sink(Box::new(TimelineSink::new("@timestamp")))
        .sink(Box::new(FindingCollector::new()))
        .sink(Box::new(ReportSink::new()))
        .build()?;

    let result = pipeline.run()?;

    // -----------------------------------------------------------------------
    // Pipeline-level summary and per-task breakdown.
    // -----------------------------------------------------------------------

    println!("\n=== Pipeline Result ===");
    println!("Tasks completed : {:?}", result.tasks_run);
    println!("Items processed : {}", result.items_processed);
    println!("Findings        : {}", result.findings_count);
    if !result.errors.is_empty() {
        println!("Errors          : {}", result.errors.len());
        for (task, err) in &result.errors {
            println!("  [{task}] {err}");
        }
    }

    println!("\n=== Per-task Stats ===");
    for (task, stats) in &result.task_stats {
        println!("  {task:<28} items={i:>3}  findings={f:>2}",
            task = task,
            i    = stats.items_processed,
            f    = stats.findings_count);
    }

    Ok(())
}

