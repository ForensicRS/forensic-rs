//! Demonstrates the value-carried diagnostics from this pass, end to end:
//!
//! - **Parsing**: a soft integrity issue (checksum mismatch) is attached to
//!   the record via `Parsed`/`ForensicData::set_parsed` instead of failing
//!   the parse — "divergence is evidence, not error." Nobody writes a
//!   `Finding` by hand for it; the pipeline promotes it into one aggregate
//!   finding at parser exhaustion (not one finding per bad record).
//! - **Analyzing**: `Analyzer::analyze` pushes findings into an `out`
//!   accumulator instead of returning `Vec<Finding>`, so findings pushed
//!   before a hard error would still reach the sinks (see
//!   `findings_pushed_before_a_hard_error_still_reach_the_sink` in
//!   `src/pipeline/mod.rs` for that half of the guarantee in isolation).
//!
//! Run with: `cargo run --example anomaly_diagnostics`

use std::sync::Arc;

use forensic_rs::prelude::*;

/// One measurement record: a sensor-style value plus a checksum that
/// occasionally fails to match — bit rot, a bad sector, a corrupted export,
/// anything that survives to disk mangled.
struct MeasurementParser {
    descriptor: ParserDescriptor,
    records: Vec<(u64, u32)>, // (value, stored_checksum)
}

impl MeasurementParser {
    fn new() -> Self {
        Self {
            descriptor: ParserDescriptor::new(
                "measurement_parser",
                "measurement_parser",
                "Mock sensor-log parser demonstrating anomaly tracking",
                "0.1.0",
            )
            .with_artifacts(vec![Artifact::Unknown]),
            records: vec![
                (42, checksum(42)),     // clean
                (9001, checksum(9001)), // clean, but analyzer-worthy (over threshold)
                (7, 0xDEAD_BEEF),        // checksum mismatch — corrupted on disk
                (13, checksum(13)),     // clean
                (500, 0xDEAD_BEEF),      // another mismatch
            ],
        }
    }
}

/// Stand-in for a real integrity check (CRC32, a fixup signature, ...).
fn checksum(value: u64) -> u32 {
    (value as u32).wrapping_mul(2_654_435_761)
}

impl ArtifactParserFactory for MeasurementParser {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        // Registered here, not injected at construction — the parser is the
        // only thing that knows what its own source key should be.
        let source = ctx.register_source(SourceKey::Synthetic("sensor-log".to_string()));
        let records = self.records.clone();
        let iter = records.into_iter().map(move |(value, stored_checksum)| {
            let provenance = source.mint(Acquisition::ImageRead, Recovery::Allocated);
            let mut data = ForensicData::new("SENSOR01", Artifact::Unknown, provenance);

            // Parse this field the "divergence is evidence" way: a checksum
            // mismatch doesn't fail the record — it rides along as an
            // Anomaly, folded into the record by `set_parsed` below.
            let mut anomalies = Anomalies::empty();
            if checksum(value) != stored_checksum {
                anomalies.add_detail(AnomalyDetail {
                    kind: AnomalyFlags::CHECKSUM_MISMATCH,
                    message: CompactString::from(format!(
                        "stored checksum {stored_checksum:#010x} does not match computed {:#010x}",
                        checksum(value)
                    )),
                });
            }
            let parsed = Parsed::with_anomalies(value, anomalies, provenance);
            data.set_parsed("measurement.value", parsed);

            Ok(data)
        });

        Ok(ParserRun::pull(iter))
    }
}

/// Flags measurements above a threshold — the "hand-written Finding" half
/// of the story, using the new accumulator-parameter signature.
struct ThresholdAnalyzer {
    threshold: u64,
}

impl Analyzer for ThresholdAnalyzer {
    fn name(&self) -> &str {
        "threshold_analyzer"
    }

    fn analyze(
        &mut self,
        data: &ForensicData,
        _context: &TriageContext,
        out: &mut Vec<Finding>,
    ) -> ForensicResult<()> {
        if let Some(Field::U64(value)) = data.field("measurement.value") {
            if *value > self.threshold {
                out.push(
                    Finding::new(
                        FindingSeverity::Medium,
                        FindingCategory::SuspiciousActivity,
                        format!("Measurement {value} exceeds threshold {}", self.threshold),
                    )
                    .with_artifact(data.artifact().clone()),
                );
            }
        }
        Ok(())
    }
}

/// Prints every finding as it arrives, so the demo shows both the
/// hand-written finding and the automatically-promoted one.
struct PrintingSink;

impl TriageSink for PrintingSink {
    fn name(&self) -> &str {
        "printing_sink"
    }
    fn on_data(&mut self, _data: &ForensicData) -> ForensicResult<()> {
        Ok(())
    }
    fn on_finding(&mut self, finding: &Finding) -> ForensicResult<()> {
        print!("  [{}] [{}] {}", finding.severity, finding.category, finding.title);
        if finding.description.is_empty() {
            println!();
        } else {
            println!(" — {}", finding.description);
        }
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut pipeline = TriagePipeline::builder()
        .context(TriageContext::new("SENSOR01", "DEMO"))
        .parser(Arc::new(MeasurementParser::new()))
        .analyzer(Box::new(ThresholdAnalyzer { threshold: 1000 }))
        .sink(Box::new(PrintingSink))
        .sink(Box::new(FindingCollector::new()))
        .build()?;

    let sources = TriageSources::builder().build();

    println!("=== Anomaly + Finding Diagnostics Demo ===\n");
    println!("5 records parsed: 3 clean, 1 over-threshold, 2 with a checksum mismatch.\n");
    println!("Findings:");
    let result = pipeline.run(&sources)?;

    println!("\nItems processed : {}", result.items_processed);
    println!("Findings raised : {}", result.findings_count);
    println!(
        "\n1 came from ThresholdAnalyzer (hand-written); the other is an aggregate\n\
         finding for the 2 checksum-mismatch records — nobody wrote it by hand,\n\
         it came from ForensicData::set_parsed + the pipeline's per-parser\n\
         AnomalyTally lowering the anomaly at parser exhaustion."
    );

    Ok(())
}
