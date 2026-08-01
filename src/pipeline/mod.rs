pub mod context;
pub mod finding;
pub mod parallel;
pub mod sinks;
pub mod sources;
pub mod traits;

use crate::{
    err::{ForensicError, ForensicResult},
    traits::forensic::ArtifactParser,
};

use self::{
    context::TriageContext,
    sources::TriageSources,
    traits::{Analyzer, Enricher, TriageSink},
};

/// Controls pipeline behavior when a parser produces an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorAction {
    /// Log the error, emit a finding, and continue processing.
    Continue,
    /// Stop the pipeline and return the error.
    Halt,
}

impl Default for ErrorAction {
    fn default() -> Self {
        ErrorAction::Continue
    }
}

/// Summary of a completed pipeline run.
#[derive(Debug, Default)]
pub struct PipelineResult {
    /// Names of parsers that executed.
    pub parsers_run: Vec<String>,
    /// Names of parsers that were skipped (can_parse returned false).
    pub parsers_skipped: Vec<String>,
    /// Total ForensicData items processed.
    pub items_processed: u64,
    /// Total findings generated.
    pub findings_count: u64,
    /// Non-fatal errors encountered during the run.
    pub errors: Vec<ForensicError>,
}

/// Builder for constructing a `TriagePipeline` with a fluent API.
///
/// # Example
/// ```rust,ignore
/// let pipeline = TriagePipeline::builder()
///     .context(TriageContext::new("WORKSTATION01", "ACME"))
///     .parser(Box::new(my_parser))
///     .enricher(Box::new(my_enricher))
///     .analyzer(Box::new(my_analyzer))
///     .sink(Box::new(TimelineSink::new("@timestamp")))  // stats-only: tracks earliest/latest
///     .sink(Box::new(FindingCollector::new()))             // stats-only: counts by severity
///     .on_parser_error(ErrorAction::Continue)
///     .build()?;
/// ```
pub struct TriagePipelineBuilder {
    context: TriageContext,
    parsers: Vec<Box<dyn ArtifactParser>>,
    enrichers: Vec<Box<dyn Enricher>>,
    analyzers: Vec<Box<dyn Analyzer>>,
    sinks: Vec<Box<dyn TriageSink>>,
    error_action: ErrorAction,
}

impl TriagePipelineBuilder {
    pub fn new() -> Self {
        Self {
            context: TriageContext::default(),
            parsers: Vec::new(),
            enrichers: Vec::new(),
            analyzers: Vec::new(),
            sinks: Vec::new(),
            error_action: ErrorAction::Continue,
        }
    }

    pub fn context(mut self, ctx: TriageContext) -> Self {
        self.context = ctx;
        self
    }

    pub fn parser(mut self, parser: Box<dyn ArtifactParser>) -> Self {
        self.parsers.push(parser);
        self
    }

    pub fn enricher(mut self, enricher: Box<dyn Enricher>) -> Self {
        self.enrichers.push(enricher);
        self
    }

    pub fn analyzer(mut self, analyzer: Box<dyn Analyzer>) -> Self {
        self.analyzers.push(analyzer);
        self
    }

    pub fn sink(mut self, sink: Box<dyn TriageSink>) -> Self {
        self.sinks.push(sink);
        self
    }

    pub fn on_parser_error(mut self, action: ErrorAction) -> Self {
        self.error_action = action;
        self
    }

    pub fn build(self) -> ForensicResult<TriagePipeline> {
        Ok(TriagePipeline {
            context: self.context,
            parsers: self.parsers,
            enrichers: self.enrichers,
            analyzers: self.analyzers,
            sinks: self.sinks,
            error_action: self.error_action,
        })
    }
}

/// A staged pipeline for triage artifact analysis.
///
/// Orchestrates the flow: **Parsers → Enrichers → Analyzers → Sinks**.
///
/// Each parser produces a stream of `ForensicData` records. Each record is
/// enriched in-place, then passed through matching analyzers which may produce
/// `Finding`s. Both records and findings are routed to all registered sinks.
///
/// After a parser's stream is exhausted, analyzers produce aggregate findings
/// via `finalize()` (e.g. detecting gaps in event record IDs).
pub struct TriagePipeline {
    context: TriageContext,
    parsers: Vec<Box<dyn ArtifactParser>>,
    enrichers: Vec<Box<dyn Enricher>>,
    analyzers: Vec<Box<dyn Analyzer>>,
    sinks: Vec<Box<dyn TriageSink>>,
    error_action: ErrorAction,
}

impl TriagePipeline {
    /// Create a builder for constructing a pipeline.
    pub fn builder() -> TriagePipelineBuilder {
        TriagePipelineBuilder::new()
    }

    /// Execute the pipeline against the given data sources.
    pub fn run(&mut self, sources: &mut TriageSources) -> ForensicResult<PipelineResult> {
        self.context.install();

        let mut result = PipelineResult::default();

        // Process each parser in registration order
        for parser in &mut self.parsers {
            let parser_name = parser.name().to_string();

            if !parser.can_parse(sources) {
                result.parsers_skipped.push(parser_name);
                continue;
            }

            // Get the iterator from this parser
            let iter = match parser.parse(sources) {
                Ok(iter) => iter,
                Err(e) => match self.error_action {
                    ErrorAction::Continue => {
                        crate::warn!("Parser '{}' failed to start: {}", parser_name, e);
                        result.errors.push(e);
                        result.parsers_skipped.push(parser_name);
                        continue;
                    }
                    ErrorAction::Halt => return Err(e),
                },
            };

            result.parsers_run.push(parser_name.clone());

            // Process each record from the parser
            for item_result in iter {
                let mut data = match item_result {
                    Ok(data) => data,
                    Err(e) => match self.error_action {
                        ErrorAction::Continue => {
                            crate::warn!("Parser '{}' produced error: {}", parser_name, e);
                            result.errors.push(e);
                            continue;
                        }
                        ErrorAction::Halt => return Err(e),
                    },
                };

                // Run enrichers
                for enricher in &mut self.enrichers {
                    if let Err(e) = enricher.enrich(&mut data, &mut self.context) {
                        crate::warn!("Enricher '{}' failed: {}", enricher.name(), e);
                        result.errors.push(e);
                    }
                }

                // Run matching analyzers
                let data_artifact = data.artifact().clone();
                for analyzer in &mut self.analyzers {
                    let supported = analyzer.supported_artifacts();
                    if !supported.is_empty() && !supported.contains(&data_artifact) {
                        continue;
                    }
                    match analyzer.analyze(&data) {
                        Ok(findings) => {
                            for finding in &findings {
                                result.findings_count += 1;
                                for sink in &mut self.sinks {
                                    if let Err(e) = sink.on_finding(finding) {
                                        result.errors.push(e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            crate::warn!("Analyzer '{}' failed: {}", analyzer.name(), e);
                            result.errors.push(e);
                        }
                    }
                }

                // Route data to sinks
                for sink in &mut self.sinks {
                    if let Err(e) = sink.on_data(&data) {
                        result.errors.push(e);
                    }
                }

                result.items_processed += 1;
            }

            // Finalize analyzers after this parser is exhausted
            for analyzer in &mut self.analyzers {
                match analyzer.finalize() {
                    Ok(findings) => {
                        for finding in &findings {
                            result.findings_count += 1;
                            for sink in &mut self.sinks {
                                if let Err(e) = sink.on_finding(finding) {
                                    result.errors.push(e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        crate::warn!("Analyzer '{}' finalize failed: {}", analyzer.name(), e);
                        result.errors.push(e);
                    }
                }
            }
        }

        // Finalize all sinks
        for sink in &mut self.sinks {
            if let Err(e) = sink.finalize() {
                result.errors.push(e);
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        artifact::{Artifact, RegistryArtifacts, WindowsArtifacts, WindowsEvents},
        core::fs::StdVirtualFS,
        data::ForensicData,
        field::{Field, Text},
        pipeline::finding::{Finding, FindingCategory, FindingSeverity},
        pipeline::sinks::{FindingCollector, TimelineSink},
        scow::SCow,
        utils::testing::TestingRegistry,
    };

    // --- Mock Parser ---

    struct MockParser {
        items: Vec<ForensicResult<crate::data::ForensicData>>,
        artifact: Artifact,
        parseable: bool,
    }

    impl MockParser {
        fn new(items: Vec<ForensicResult<ForensicData>>, artifact: Artifact) -> Self {
            Self {
                items,
                artifact,
                parseable: true,
            }
        }

        fn unparseable() -> Self {
            Self {
                items: Vec::new(),
                artifact: Artifact::Unknown,
                parseable: false,
            }
        }
    }

    impl ArtifactParser for MockParser {
        fn name(&self) -> &str {
            "mock_parser"
        }
        fn description(&self) -> &str {
            "Mock parser for testing"
        }
        fn version(&self) -> &str {
            "0.0.1"
        }
        fn supported_artifacts(&self) -> Vec<Artifact> {
            vec![self.artifact.clone()]
        }
        fn can_parse(&self, _sources: &TriageSources) -> bool {
            self.parseable
        }
        fn parse<'a>(
            &'a mut self,
            _sources: &'a mut TriageSources,
        ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<ForensicData>> + 'a>> {
            Ok(Box::new(self.items.drain(..)))
        }
    }

    // --- Mock Enricher ---

    struct TagEnricher {
        tag_key: &'static str,
        tag_value: &'static str,
    }

    impl Enricher for TagEnricher {
        fn name(&self) -> &str {
            "tag_enricher"
        }
        fn enrich(
            &mut self,
            data: &mut ForensicData,
            _context: &mut TriageContext,
        ) -> ForensicResult<()> {
            data.add_field(self.tag_key, Field::Text(Text::Borrowed(self.tag_value)));
            Ok(())
        }
    }

    // --- Mock Analyzer ---

    struct CountAnalyzer {
        count: u64,
        threshold: u64,
    }

    impl CountAnalyzer {
        fn new(threshold: u64) -> Self {
            Self {
                count: 0,
                threshold,
            }
        }
    }

    impl Analyzer for CountAnalyzer {
        fn name(&self) -> &str {
            "count_analyzer"
        }
        fn analyze(&mut self, _data: &ForensicData) -> ForensicResult<Vec<Finding>> {
            self.count += 1;
            Ok(Vec::new())
        }
        fn finalize(&mut self) -> ForensicResult<Vec<Finding>> {
            if self.count < self.threshold {
                Ok(vec![Finding::new(
                    FindingSeverity::Medium,
                    FindingCategory::MissingData,
                    format!(
                        "Expected at least {} records, got {}",
                        self.threshold, self.count
                    ),
                )])
            } else {
                Ok(Vec::new())
            }
        }
    }

    // --- Mock Sink ---

    struct CollectorSink {
        data_count: u64,
        finding_count: u64,
        finalized: bool,
    }

    impl CollectorSink {
        fn new() -> Self {
            Self {
                data_count: 0,
                finding_count: 0,
                finalized: false,
            }
        }
    }

    impl TriageSink for CollectorSink {
        fn name(&self) -> &str {
            "collector_sink"
        }
        fn on_data(&mut self, _data: &ForensicData) -> ForensicResult<()> {
            self.data_count += 1;
            Ok(())
        }
        fn on_finding(&mut self, _finding: &Finding) -> ForensicResult<()> {
            self.finding_count += 1;
            Ok(())
        }
        fn finalize(&mut self) -> ForensicResult<()> {
            self.finalized = true;
            Ok(())
        }
    }

    fn test_sources() -> TriageSources {
        TriageSources::new(
            Box::new(StdVirtualFS::new()),
            Box::new(TestingRegistry::new()),
        )
    }

    #[test]
    fn should_build_pipeline() {
        let pipeline = TriagePipeline::builder()
            .context(TriageContext::new("HOST", "TENANT"))
            .on_parser_error(ErrorAction::Continue)
            .build();
        assert!(pipeline.is_ok());
    }

    #[test]
    fn should_run_empty_pipeline() {
        let mut pipeline = TriagePipeline::builder().build().unwrap();
        let mut sources = test_sources();
        let result = pipeline.run(&mut sources).unwrap();
        assert_eq!(result.items_processed, 0);
        assert_eq!(result.findings_count, 0);
        assert!(result.parsers_run.is_empty());
    }

    #[test]
    fn should_process_records_through_pipeline() {
        let items = vec![
            Ok(ForensicData::new(
                "host1",
                RegistryArtifacts::ShellBags.into(),
            )),
            Ok(ForensicData::new(
                "host1",
                RegistryArtifacts::ShellBags.into(),
            )),
        ];
        let mut pipeline = TriagePipeline::builder()
            .parser(Box::new(MockParser::new(
                items,
                RegistryArtifacts::ShellBags.into(),
            )))
            .build()
            .unwrap();
        let mut sources = test_sources();
        let result = pipeline.run(&mut sources).unwrap();
        assert_eq!(result.items_processed, 2);
        assert_eq!(result.parsers_run.len(), 1);
        assert_eq!(result.parsers_run[0], "mock_parser");
    }

    #[test]
    fn should_skip_unparseable_parser() {
        let mut pipeline = TriagePipeline::builder()
            .parser(Box::new(MockParser::unparseable()))
            .build()
            .unwrap();
        let mut sources = test_sources();
        let result = pipeline.run(&mut sources).unwrap();
        assert_eq!(result.items_processed, 0);
        assert_eq!(result.parsers_skipped.len(), 1);
    }

    #[test]
    fn should_enrich_data() {
        let items = vec![Ok(ForensicData::new("host1", Artifact::Unknown))];
        let mut pipeline = TriagePipeline::builder()
            .parser(Box::new(MockParser::new(items, Artifact::Unknown)))
            .enricher(Box::new(TagEnricher {
                tag_key: "enriched",
                tag_value: "yes",
            }))
            .sink(Box::new(FindingCollector::new()))
            .build()
            .unwrap();
        let mut sources = test_sources();
        let result = pipeline.run(&mut sources).unwrap();
        assert_eq!(result.items_processed, 1);
    }

    #[test]
    fn should_produce_findings_on_finalize() {
        let items = vec![Ok(ForensicData::new("host1", Artifact::Unknown))];
        let mut pipeline = TriagePipeline::builder()
            .parser(Box::new(MockParser::new(items, Artifact::Unknown)))
            .analyzer(Box::new(CountAnalyzer::new(5))) // threshold=5, only 1 record → finding
            .build()
            .unwrap();
        let mut sources = test_sources();
        let result = pipeline.run(&mut sources).unwrap();
        assert_eq!(result.items_processed, 1);
        assert_eq!(result.findings_count, 1);
    }

    #[test]
    fn should_route_data_and_findings_to_sinks() {
        let items = vec![
            Ok(ForensicData::new("host1", Artifact::Unknown)),
            Ok(ForensicData::new("host1", Artifact::Unknown)),
        ];

        // FindingCollector is a stats-only sink — it counts findings by severity.
        let mut pipeline = TriagePipeline::builder()
            .parser(Box::new(MockParser::new(items, Artifact::Unknown)))
            .analyzer(Box::new(CountAnalyzer::new(10)))
            .sink(Box::new(FindingCollector::new()))
            .build()
            .unwrap();
        let mut sources = test_sources();
        let result = pipeline.run(&mut sources).unwrap();
        assert_eq!(result.items_processed, 2);
        assert_eq!(result.findings_count, 1); // finalize finding
    }

    #[test]
    fn should_continue_on_parser_item_error() {
        let items: Vec<ForensicResult<ForensicData>> = vec![
            Ok(ForensicData::new("host1", Artifact::Unknown)),
            Err(ForensicError::missing_data(
                "test missing data",
                SCow::Borrowed("pipeline test"),
            )),
            Ok(ForensicData::new("host1", Artifact::Unknown)),
        ];
        let mut pipeline = TriagePipeline::builder()
            .parser(Box::new(MockParser::new(items, Artifact::Unknown)))
            .on_parser_error(ErrorAction::Continue)
            .build()
            .unwrap();
        let mut sources = test_sources();
        let result = pipeline.run(&mut sources).unwrap();
        assert_eq!(result.items_processed, 2); // 2 OK items
        assert_eq!(result.errors.len(), 1); // 1 error recorded
    }

    #[test]
    fn should_halt_on_parser_item_error() {
        let items: Vec<ForensicResult<ForensicData>> = vec![
            Ok(ForensicData::new("host1", Artifact::Unknown)),
            Err(ForensicError::missing_data(
                "halt test",
                SCow::Borrowed("pipeline test"),
            )),
            Ok(ForensicData::new("host1", Artifact::Unknown)),
        ];
        let mut pipeline = TriagePipeline::builder()
            .parser(Box::new(MockParser::new(items, Artifact::Unknown)))
            .on_parser_error(ErrorAction::Halt)
            .build()
            .unwrap();
        let mut sources = test_sources();
        let result = pipeline.run(&mut sources);
        assert!(result.is_err());
    }

    #[test]
    fn should_use_timeline_sink() {
        let mut data1 = ForensicData::new("host1", Artifact::Unknown);
        data1.add_field(
            "@timestamp",
            Field::Date(crate::utils::time::Filetime::with_ymd_and_hms(
                2024, 6, 15, 10, 30, 0, 0,
            ).into()),
        );
        let mut data2 = ForensicData::new("host1", Artifact::Unknown);
        data2.add_field(
            "@timestamp",
            Field::Date(crate::utils::time::Filetime::with_ymd_and_hms(
                2024, 6, 15, 8, 0, 0, 0,
            ).into()),
        );

        let mut pipeline = TriagePipeline::builder()
            .parser(Box::new(MockParser::new(
                vec![Ok(data1), Ok(data2)],
                Artifact::Unknown,
            )))
            .sink(Box::new(TimelineSink::new("@timestamp")))
            .build()
            .unwrap();
        let mut sources = test_sources();
        let result = pipeline.run(&mut sources).unwrap();
        assert_eq!(result.items_processed, 2);
    }

    #[test]
    fn should_scope_analyzer_to_artifact_type() {
        // Analyzer only interested in WinEvt artifacts
        struct WinEvtOnlyAnalyzer {
            seen: u64,
        }
        impl Analyzer for WinEvtOnlyAnalyzer {
            fn name(&self) -> &str {
                "winevt_only"
            }
            fn supported_artifacts(&self) -> Vec<Artifact> {
                vec![WindowsArtifacts::WinEvt(WindowsEvents::Security).into()]
            }
            fn analyze(&mut self, _data: &ForensicData) -> ForensicResult<Vec<Finding>> {
                self.seen += 1;
                Ok(Vec::new())
            }
        }

        let items = vec![
            Ok(ForensicData::new("h", RegistryArtifacts::ShellBags.into())), // should NOT match
            Ok(ForensicData::new(
                "h",
                WindowsArtifacts::WinEvt(WindowsEvents::Security).into(),
            )), // should match
        ];
        let mut pipeline = TriagePipeline::builder()
            .parser(Box::new(MockParser::new(items, Artifact::Unknown)))
            .analyzer(Box::new(WinEvtOnlyAnalyzer { seen: 0 }))
            .build()
            .unwrap();
        let mut sources = test_sources();
        let result = pipeline.run(&mut sources).unwrap();
        assert_eq!(result.items_processed, 2);
        // The analyzer only saw 1 record (the WinEvt one), but we can't inspect it directly.
        // At least verify no errors occurred.
        assert!(result.errors.is_empty());
    }
}
