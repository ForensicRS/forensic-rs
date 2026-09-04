//! Parallel triage pipeline example.
//!
//! Demonstrates the analyzer-centric [`AnalysisModule`] API with auto-matching
//! and the lower-level [`StandardParallelTask`] for comparison.
//!
//! Scenario: a triage ZIP from a Windows machine contains MFT records, Windows
//! Event Log entries, and autorun registry keys. Each artifact type has its own
//! parser and analyzer. By registering parsers on the parallel pipeline's pool,
//! the framework automatically wires each analyzer to the parsers it needs
//! based on their declared [`Artifact`] types — no manual per-module wiring.
//!
//! Key concepts shown:
//! - [`AnalysisModule`] / [`AnalysisModuleBuilder`] — analyzer-first task
//! - `Arc<dyn ArtifactParserFactory>` — registered once, `Arc::clone`d into N matching modules
//! - Auto-matching via `Analyzer::supported_artifacts` ∩ `ParserDescriptor::artifacts`
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
    descriptor: ParserDescriptor,
    records: Vec<(&'static str, u64)>, // (path, inode)
}

impl MockMftParser {
    fn new() -> Self {
        Self {
            descriptor: ParserDescriptor::new("mft_parser", "mft_parser", "Mock MFT parser", "0.1.0")
                .with_artifacts(vec![mft_artifact()]),
            records: vec![
                (r"C:\Windows\System32\cmd.exe",            1001),
                (r"C:\Windows\Temp\suspicious.ps1",         1002),
                (r"C:\Users\Alice\Documents\report.docx",   1003),
                (r"C:\Windows\Temp\update.exe",             1004),
            ],
        }
    }
}

impl ArtifactParserFactory for MockMftParser {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        let source = ctx.register_source(SourceKey::Path(r"C:\$MFT".to_string()));
        let records = self.records.clone();
        let items: Vec<ForensicResult<ForensicData>> = records.into_iter().map(|(path, inode)| {
            let provenance = source.mint(Acquisition::ImageRead, Recovery::Allocated);
            let mut d = ForensicData::new("WORKSTATION01", mft_artifact(), provenance);
            d.insert(Text::Borrowed("file.path"),  Field::Text(Text::Owned(path.to_string())));
            d.insert(Text::Borrowed("file.inode"), Field::U64(inode));
            d.insert(Text::Borrowed("@timestamp"),
                Field::Date(Filetime::with_ymd_and_hms(2024, 6, 15, 10, 0, 0, 0).into()));
            Ok(d)
        }).collect();
        Ok(ParserRun::pull(items.into_iter()))
    }
}

/// Simulates a Windows Event Log parser.
struct MockEvtxParser {
    descriptor: ParserDescriptor,
    channel: &'static str,
    events: Vec<(u64, u64)>, // (record_id, event_id)
}

impl MockEvtxParser {
    fn security() -> Self {
        Self {
            descriptor: ParserDescriptor::new("Security", "Security", "Mock EVTX parser", "0.1.0")
                .with_artifacts(vec![evt_artifact()]),
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

impl ArtifactParserFactory for MockEvtxParser {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        let channel = self.channel;
        let source = ctx.register_source(SourceKey::Path(format!("{channel}.evtx")));
        let events = self.events.clone();
        let items: Vec<ForensicResult<ForensicData>> = events.into_iter().map(|(record_id, event_id)| {
            let provenance = source.mint(Acquisition::ImageRead, Recovery::Allocated);
            let mut d = ForensicData::new("WORKSTATION01", evt_artifact(), provenance);
            d.insert(Text::Borrowed("event.record_id"), Field::U64(record_id));
            d.insert(Text::Borrowed("event.code"),      Field::U64(event_id));
            d.insert(Text::Borrowed("event.channel"),   Field::Text(Text::Borrowed(channel)));
            d.insert(Text::Borrowed("@timestamp"),
                Field::Date(Filetime::with_ymd_and_hms(2024, 6, 15, 10, 0, 0, 0).into()));
            Ok(d)
        }).collect();
        Ok(ParserRun::pull(items.into_iter()))
    }
}

/// Emits hardcoded autorun entries (simulating a registry parser output).
///
/// In production this would read from `ctx.registry()`. Here we use
/// static data so the parser is `Send + Sync` without any real registry.
struct MockAutorunParser {
    descriptor: ParserDescriptor,
    entries: Vec<(&'static str, &'static str)>, // (name, command)
}

impl MockAutorunParser {
    fn new() -> Self {
        Self {
            descriptor: ParserDescriptor::new(
                "autorun_parser",
                "autorun_parser",
                "Mock autorun registry parser",
                "0.1.0",
            )
            .with_artifacts(vec![autorun_artifact()]),
            entries: vec![
                ("Malware",  r"powershell.exe -ep bypass C:\temp\malware.ps1"),
                ("OneDrive", r"C:\Users\Alice\AppData\Local\Microsoft\OneDrive\OneDrive.exe"),
                ("Teams",    r"C:\Users\Alice\AppData\Local\Microsoft\Teams\Update.exe --processStart Teams.exe"),
            ],
        }
    }
}

impl ArtifactParserFactory for MockAutorunParser {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        let source = ctx.register_source(SourceKey::Live {
            host: ctx.host().to_string(),
            api: "RegistryReader".to_string(),
        });
        let sid = "S-1-5-21-1366093794-4292800403-1155380978-513";
        let entries = self.entries.clone();
        let items: Vec<ForensicResult<ForensicData>> = entries.into_iter().map(|(name, cmd)| {
            let provenance = source.mint(Acquisition::LiveApi, Recovery::Allocated);
            let mut d = ForensicData::new("WORKSTATION01", autorun_artifact(), provenance);
            d.insert(Text::Borrowed("autorun.name"),  Field::Text(Text::Borrowed(name)));
            d.insert(Text::Borrowed("autorun.value"), Field::Text(Text::Borrowed(cmd)));
            d.insert(Text::Borrowed("autorun.user"),  Field::Text(Text::Borrowed(sid)));
            d.insert(Text::Borrowed("@timestamp"),
                Field::Date(Filetime::with_ymd_and_hms(2024, 6, 15, 10, 0, 0, 0).into()));
            Ok(d)
        }).collect();
        Ok(ParserRun::pull(items.into_iter()))
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

    fn analyze(
        &mut self,
        data: &ForensicData,
        _context: &TriageContext,
        out: &mut Vec<Finding>,
    ) -> ForensicResult<()> {
        let path = match data.field("file.path") {
            Some(Field::Text(t)) => t.to_lowercase(),
            _ => return Ok(()),
        };
        if path.contains("\\temp\\") || path.contains("/tmp/") {
            let label = match data.field("file.path") {
                Some(Field::Text(t)) => t.to_string(),
                _ => String::new(),
            };
            out.push(
                Finding::new(
                    FindingSeverity::Medium,
                    FindingCategory::SuspiciousActivity,
                    format!("File created in temp: {label}"),
                )
                .with_artifact(mft_artifact()),
            );
        }
        Ok(())
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

    fn analyze(
        &mut self,
        data: &ForensicData,
        _context: &TriageContext,
        _out: &mut Vec<Finding>,
    ) -> ForensicResult<()> {
        if let (Some(Field::Text(ch)), Some(Field::U64(rid))) = (
            data.field("event.channel"),
            data.field("event.record_id"),
        ) {
            self.channels.entry(ch.to_string()).or_default().push(*rid);
        }
        Ok(())
    }

    fn finalize(&mut self, _context: &TriageContext, out: &mut Vec<Finding>) -> ForensicResult<()> {
        for (channel, ids) in &self.channels {
            let mut sorted = ids.clone();
            sorted.sort_unstable();
            for w in sorted.windows(2) {
                if w[1] - w[0] > 1 {
                    out.push(
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
        Ok(())
    }
}

/// Flags suspicious autorun entries containing known living-off-the-land binaries.
struct SuspiciousAutorunAnalyzer;

impl Analyzer for SuspiciousAutorunAnalyzer {
    fn name(&self) -> &str { "suspicious_autorun" }
    // No supported_artifacts() override → accepts everything; useful when
    // combined with an explicit parser (as in the StandardParallelTask below).
    fn supported_artifacts(&self) -> Vec<Artifact> { vec![] }

    fn analyze(
        &mut self,
        data: &ForensicData,
        _context: &TriageContext,
        out: &mut Vec<Finding>,
    ) -> ForensicResult<()> {
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
                out.push(
                    Finding::new(
                        FindingSeverity::High,
                        FindingCategory::SuspiciousActivity,
                        format!("Suspicious autorun: {name}"),
                    )
                    .with_description(format!("Pattern '{pat}' found in autorun value"))
                    .with_artifact(autorun_artifact()),
                );
                return Ok(());
            }
        }
        Ok(())
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
    // At build() time the pipeline compares each registered parser's
    // descriptor artifacts against each module's analyzer. Matching parsers
    // are injected into the module by cloning their `Arc` — no construction.
    // -----------------------------------------------------------------------

    let mft_module = AnalysisModuleBuilder::new("mft_analysis")
        .analyzer(Box::new(TempWriteAnalyzer))
        // No .parser() → auto-match injects MockMftParser (artifacts overlap: MFT)
        .sources(|| TriageSources::builder().build())
        // No .context() here — it adopts the pipeline-wide one set below,
        // via ParallelPipelineBuilder::context(). Set one explicitly only
        // when a module genuinely needs to diverge from the run's shared
        // identity/provenance store (see that method's docs).
        .build()?;

    let evt_module = AnalysisModuleBuilder::new("evt_gap_analysis")
        .analyzer(Box::new(EventGapAnalyzer::new()))
        // No .parser() → auto-match injects MockEvtxParser (artifacts overlap: WinEvt)
        .sources(|| TriageSources::builder().build())
        .build()?;

    // -----------------------------------------------------------------------
    // StandardParallelTask — lower-level API for when you need an explicit
    // parser and full control over the parser/analyzer pairing.
    // SuspiciousAutorunAnalyzer declares supported_artifacts() = [] (accept-all),
    // but here we use StandardParallelTask so the parser is always explicit.
    // -----------------------------------------------------------------------

    let autorun_task = StandardParallelTaskBuilder::new("registry_autoruns")
        .parser(std::sync::Arc::new(MockAutorunParser::new()))
        .analyzer(Box::new(SuspiciousAutorunAnalyzer))
        .sources(|| TriageSources::builder().build())
        .build()?;

    // -----------------------------------------------------------------------
    // Build the parallel pipeline.
    //
    // Parsers are registered once in the pool. build() compares descriptor
    // artifacts against pending AnalysisModules; matching parsers are cloned
    // (as `Arc`s) into the module, non-matching ones are skipped.
    // StandardParallelTask bypasses the pool — it already has an explicit
    // parser.
    //
    // `.context(...)` here is what makes this one investigation rather than
    // three unrelated ones: every module/task above left its own `.context()`
    // unset, so each adopts a clone of this single `TriageContext` — and a
    // clone shares its `ProvenanceStore` (an `Arc` handle) with every other
    // clone. Without this, each of the three tasks above would default to
    // its own independent `TriageContext`/store, and a record reaching a
    // sink on the main thread would carry a `ProvenanceId` no single store
    // handle here could resolve — `data.confidence(&store)` would be
    // unavailable. See `ParallelPipelineBuilder::context`'s docs.
    // -----------------------------------------------------------------------

    let mut pipeline = ParallelPipeline::builder()
        .workers(3)
        .channel_capacity(128)
        .context(TriageContext::new("WORKSTATION01", "ACME-Corp"))
        // Parser pool — matched to modules by descriptor artifact overlap.
        .parser(std::sync::Arc::new(MockMftParser::new()))
        .parser(std::sync::Arc::new(MockEvtxParser::security()))
        // Modules — receive auto-matched parsers at build() time.
        .module(mft_module)
        .module(evt_module)
        // Low-level task — has explicit parser, bypasses the pool.
        .task(Box::new(autorun_task))
        // Shared sinks — called on the main thread for all tasks.
        .sink(Box::new(TimelineSink::new("@timestamp")))
        .sink(Box::new(FindingCollector::new()))
        .sink(Box::new(ReportSink::new()))
        .build()?;

    let result = pipeline.run()?;

    // The one store every task above minted into — reachable here because
    // `.context()` was set on the pipeline builder, not per-module/task.
    if let Some(store) = &result.provenance_store {
        println!(
            "\nShared provenance store: {} interned source(s) across all 3 tasks",
            store.source_count()
        );
    }

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

