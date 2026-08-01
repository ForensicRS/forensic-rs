//! Stateful analyzer that detects gaps in Windows Event Log record IDs.
//!
//! Demonstrates:
//! - Multiple parser instances (Security + System logs)
//! - Stateful `Analyzer` with `finalize()` for aggregate cross-record analysis
//! - Per-record detection (Event ID 104 = log cleared)
//! - `FindingCategory::MissingData` and `FindingCategory::AntiForensics`
//! - `ForensicTimestamp` used inside `Finding`s
//! - Parallel variant: the same detector wrapped in an `AnalysisModule` with
//!   parser factories auto-matched by the `ParallelPipeline` builder
//!
//! Run with: `cargo run --example event_gap_detector`

use std::collections::BTreeMap;

use forensic_rs::prelude::*;
use forensic_rs::utils::testing::TestingRegistry;

// ---------------------------------------------------------------------------
// Mock Event Log Parser
// ---------------------------------------------------------------------------

/// Simulates parsing a Windows Event Log channel.
/// In production, this would read .evtx files from the VFS.
struct MockEvtxParser {
    channel: &'static str,
    events: Vec<(u64, u64, u64)>, // (record_id, event_id, unix_secs)
}

impl MockEvtxParser {
    fn security_log() -> Self {
        Self {
            channel: "Security",
            events: vec![
                // Normal sequence with a gap: records 1001-1003, then 1007-1010 (missing 1004-1006)
                (1001, 4624, 1718400000), // Logon success
                (1002, 4625, 1718400060), // Logon failure
                (1003, 4634, 1718400120), // Logoff
                // Gap: 1004, 1005, 1006 missing
                (1007, 4624, 1718400600), // Logon success
                (1008, 4672, 1718400660), // Special privileges assigned
                (1009, 4624, 1718400720), // Logon success
                (1010, 4634, 1718400780), // Logoff
            ],
        }
    }

    fn system_log() -> Self {
        Self {
            channel: "System",
            events: vec![
                (501, 7045, 1718400000),  // Service installed
                (502, 7036, 1718400060),  // Service state change
                (503, 104, 1718400120),   // Log cleared! (anti-forensics indicator)
                (504, 7036, 1718400180),  // Service state change
                // Gap: 505 missing
                (506, 7040, 1718400300),  // Service config change
            ],
        }
    }
}

impl ArtifactParser for MockEvtxParser {
    fn name(&self) -> &str { self.channel }
    fn description(&self) -> &str { "Mock Windows Event Log parser" }
    fn version(&self) -> &str { "0.1.0" }

    fn supported_artifacts(&self) -> Vec<Artifact> {
        vec![Artifact::Windows(WindowsArtifacts::WinEvt(WindowsEvents::Unknown))]
    }

    fn parse<'a>(
        &'a mut self,
        _sources: &'a mut TriageSources,
    ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<ForensicData>> + 'a>> {
        let channel = self.channel;
        let iter = self.events.iter().map(move |&(record_id, event_id, unix_secs)| {
            let mut data = ForensicData::new("WORKSTATION01",
                Artifact::Windows(WindowsArtifacts::WinEvt(WindowsEvents::Unknown)));

            data.insert(Text::Borrowed("event.record_id"), Field::U64(record_id));
            data.insert(Text::Borrowed(EVENT_CODE), Field::U64(event_id));
            data.insert(Text::Borrowed("event.channel"), Field::Text(Text::Borrowed(channel)));
            data.insert(Text::Borrowed("@timestamp"),
                Field::Date(ForensicTimestamp::from_unix_secs(unix_secs as i64)));

            Ok(data)
        });

        Ok(Box::new(iter))
    }
}

// ---------------------------------------------------------------------------
// Event Gap Detector Analyzer
// ---------------------------------------------------------------------------

/// Tracks EventRecordIDs per channel and detects:
/// - Gaps in record ID sequences (MissingData)
/// - Event ID 104 (log cleared, AntiForensics)
struct EventGapDetector {
    /// channel -> sorted list of (record_id, timestamp)
    channels: BTreeMap<String, Vec<(u64, ForensicTimestamp)>>,
}

impl EventGapDetector {
    fn new() -> Self {
        Self { channels: BTreeMap::new() }
    }
}

impl Analyzer for EventGapDetector {
    fn name(&self) -> &str { "event_gap_detector" }

    fn supported_artifacts(&self) -> Vec<Artifact> {
        vec![Artifact::Windows(WindowsArtifacts::WinEvt(WindowsEvents::Unknown))]
    }

    fn analyze(&mut self, data: &ForensicData) -> ForensicResult<Vec<Finding>> {
        let mut findings = Vec::new();

        // Extract channel and record ID
        let channel = match data.field("event.channel") {
            Some(Field::Text(t)) => t.to_string(),
            _ => return Ok(findings),
        };
        let record_id = match data.field("event.record_id") {
            Some(Field::U64(id)) => *id,
            _ => return Ok(findings),
        };
        let event_id = match data.field(EVENT_CODE) {
            Some(Field::U64(id)) => *id,
            _ => 0,
        };

        // Extract timestamp
        let ts = match data.field("@timestamp") {
            Some(Field::Date(timestamp)) => *timestamp,
            _ => ForensicTimestamp::from_unix_secs(0),
        };

        // Track record for gap analysis in finalize()
        self.channels.entry(channel.clone()).or_default().push((record_id, ts));

        // Per-record check: Event ID 104 = "The System log file was cleared"
        if event_id == 104 {
            let finding = Finding::new(
                FindingSeverity::High,
                FindingCategory::AntiForensics,
                format!("Event log cleared: {}", channel),
            )
            .with_description(format!(
                "Event ID 104 detected in {} channel at record {}. This indicates the event log was manually cleared.",
                channel, record_id
            ))
            .with_timestamp(ts)
            .with_artifact(Artifact::Windows(WindowsArtifacts::WinEvt(WindowsEvents::Unknown)))
            .with_related_data(data.clone());

            findings.push(finding);
        }

        Ok(findings)
    }

    fn finalize(&mut self) -> ForensicResult<Vec<Finding>> {
        let mut findings = Vec::new();

        for (channel, records) in &self.channels {
            let mut sorted = records.clone();
            sorted.sort_by_key(|(id, _)| *id);

            // Detect gaps in record ID sequence
            for window in sorted.windows(2) {
                let (prev_id, prev_ts) = window[0];
                let (next_id, _next_ts) = window[1];

                let gap = next_id.saturating_sub(prev_id);
                if gap > 1 {
                    let missing_count = gap - 1;
                    let severity = if missing_count > 100 {
                        FindingSeverity::Critical
                    } else if missing_count > 10 {
                        FindingSeverity::High
                    } else {
                        FindingSeverity::Medium
                    };

                    let finding = Finding::new(
                        severity,
                        FindingCategory::MissingData,
                        format!("Event log gap in {}", channel),
                    )
                    .with_description(format!(
                        "Missing {} record(s) in {} channel between record IDs {} and {}",
                        missing_count, channel, prev_id, next_id
                    ))
                    .with_timestamp(prev_ts)
                    .with_artifact(Artifact::Windows(WindowsArtifacts::WinEvt(WindowsEvents::Unknown)))
                    .with_metadata(Text::Borrowed("gap.start_id"), Text::Owned(prev_id.to_string()))
                    .with_metadata(Text::Borrowed("gap.end_id"), Text::Owned(next_id.to_string()))
                    .with_metadata(Text::Borrowed("gap.missing_count"), Text::Owned(missing_count.to_string()));

                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }
}

// ---------------------------------------------------------------------------
// Parallel variant using AnalysisModule + parser factories
// ---------------------------------------------------------------------------

/// Demonstrates the same [`EventGapDetector`] running inside a
/// [`ParallelPipeline`] via [`AnalysisModule`].
///
/// Both EVTX parsers are registered as factories. The pipeline builder
/// auto-matches them to the module at `build()` time — neither the analyzer
/// nor the module needs to know about the concrete parser type.
fn run_parallel() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Parallel Variant (AnalysisModule) ===\n");

    // AnalysisModule wraps the detector. No explicit parsers — they come
    // from the factories below, matched by supported_artifacts() overlap.
    let module = AnalysisModuleBuilder::new("event_gap_analysis")
        .analyzer(Box::new(EventGapDetector::new()))
        .sources(|| TriageSources::builder().build())
        .context(TriageContext::new("WORKSTATION01", "INCIDENT-2024-001"))
        .build()?;

    let mut pipeline = ParallelPipeline::builder()
        .workers(2)
        // Both parsers declare Artifact::Windows(WinEvt(Unknown)), which
        // matches EventGapDetector::supported_artifacts() — auto-injected.
        .parser_factory(Box::new(|| Box::new(MockEvtxParser::security_log())))
        .parser_factory(Box::new(|| Box::new(MockEvtxParser::system_log())))
        .module(module)
        .sink(Box::new(FindingCollector::new()))
        .build()?;

    let result = pipeline.run()?;

    println!("Parallel result:");
    println!("  Items processed : {}", result.items_processed);
    println!("  Findings        : {}", result.findings_count);
    println!();
    for (task, stats) in &result.task_stats {
        println!("  {task:<28} items={i:>3}  findings={f:>2}",
            task = task,
            i    = stats.items_processed,
            f    = stats.findings_count);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let registry = TestingRegistry::new();
    let vfs = StdVirtualFS::new();
    let mut sources = TriageSources::new(Box::new(vfs), Box::new(registry));

    // Build pipeline with two parser instances and built-in sinks
    let mut pipeline = TriagePipeline::builder()
        .context(TriageContext::new("WORKSTATION01", "INCIDENT-2024-001"))
        .parser(Box::new(MockEvtxParser::security_log()))
        .parser(Box::new(MockEvtxParser::system_log()))
        .analyzer(Box::new(EventGapDetector::new()))
        .sink(Box::new(TimelineSink::new("@timestamp")))
        .sink(Box::new(FindingCollector::new()))
        .on_parser_error(ErrorAction::Continue)
        .build()?;

    println!("=== Event Gap Detector ===\n");
    let result = pipeline.run(&mut sources)?;

    // Print results
    println!("Parsers run: {:?}", result.parsers_run);
    println!("Items processed: {}", result.items_processed);
    println!("Findings generated: {}", result.findings_count);
    println!("Errors: {}\n", result.errors.len());

    // FindingCollector is a stats-only sink — it counts findings by severity
    // without storing them in memory. For full finding collection (e.g. writing
    // to a file), implement a custom TriageSink.
    //
    // The finding count is also tracked by PipelineResult:
    if result.findings_count > 0 {
        println!("--- Findings Summary ---");
        println!("The pipeline detected {} finding(s):", result.findings_count);
        println!("  - Event log gaps (MissingData findings from finalize())");
        println!("  - Event log cleared indicators (AntiForensics findings from per-record analysis)");
        println!();
        println!("In production, implement a custom TriageSink to write findings");
        println!("to disk, a database, or any other destination.");
    }

    // Run the parallel variant for comparison.
    run_parallel()?;

    Ok(())
}
