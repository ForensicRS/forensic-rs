use crate::{
    artifact::Artifact,
    data::ForensicData,
    err::ForensicResult,
    pipeline::{
        context::TriageContext,
        finding::Finding,
    },
};

/// Enriches `ForensicData` records with additional context during pipeline execution.
///
/// Enrichers run after parsing and before analysis. They can modify each record
/// in-place (e.g. resolve SIDs to usernames, expand environment variables,
/// add geolocation data) and read/write the shared `TriageContext` state.
///
/// Enrichers are stateful (`&mut self`) to support internal caches.
pub trait Enricher {
    /// Short identifier for this enricher.
    fn name(&self) -> &str;
    /// Enrich a single record. May modify both the data and the shared context.
    fn enrich(&mut self, data: &mut ForensicData, context: &mut TriageContext) -> ForensicResult<()>;
}

/// Analyzes `ForensicData` records to detect anomalies, integrity issues, and suspicious patterns.
///
/// Analyzers run after enrichment. They are stateful (`&mut self`) so they can
/// track data across records for aggregate analysis — e.g. detecting gaps in
/// EventRecordIDs, missing MFT entries, or timestamp anomalies.
///
/// Two analysis phases:
/// - `analyze()`: called per record — fast per-item checks
/// - `finalize()`: called after a parser is exhausted — aggregate/cross-record analysis
pub trait Analyzer {
    /// Short identifier for this analyzer.
    fn name(&self) -> &str;
    /// The artifact types this analyzer is interested in.
    /// Return an empty vec (default) to receive all records regardless of artifact type.
    fn supported_artifacts(&self) -> Vec<Artifact> {
        Vec::new()
    }
    /// Analyze a single record and return any findings.
    fn analyze(&mut self, data: &ForensicData) -> ForensicResult<Vec<Finding>>;
    /// Produce aggregate findings after all records from a parser have been processed.
    /// Default implementation returns no findings.
    fn finalize(&mut self) -> ForensicResult<Vec<Finding>> {
        Ok(Vec::new())
    }
}

/// Consumes pipeline output: processed `ForensicData` records and `Finding`s.
///
/// Sinks are the terminal stage of the pipeline. Implement this trait to write
/// output to any destination: files (JSON, CSV), databases, Elasticsearch,
/// in-memory collections for further processing, etc.
///
/// Built-in sinks: `TimelineSink` (timestamp stats), `FindingCollector` (severity counts).
pub trait TriageSink {
    /// Short identifier for this sink.
    fn name(&self) -> &str;
    /// Called for each processed `ForensicData` record.
    fn on_data(&mut self, data: &ForensicData) -> ForensicResult<()>;
    /// Called for each `Finding` produced by analyzers.
    fn on_finding(&mut self, finding: &Finding) -> ForensicResult<()>;
    /// Called after all parsers have finished. Use to flush buffers, close files, etc.
    fn finalize(&mut self) -> ForensicResult<()> {
        Ok(())
    }
}
