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
    finding::{AnomalyTally, Finding},
    sources::TriageSources,
    traits::{Analyzer, Enricher, TriageSink},
};

/// Routes one finding to every sink and counts it. A free function (not a
/// `&mut self` method) so it can be called from inside `for parser in &mut
/// self.parsers` without the borrow checker seeing a conflicting whole-`self`
/// borrow — it only touches the `sinks`/`result` fields it's given.
fn route_finding(sinks: &mut [Box<dyn TriageSink>], result: &mut PipelineResult, finding: &Finding) {
    result.findings_count += 1;
    for sink in sinks {
        if let Err(e) = sink.on_finding(finding) {
            result.errors.push(e);
        }
    }
}

/// Controls pipeline behavior when a parser produces an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ErrorAction {
    /// Log the error, emit a finding, and continue processing.
    #[default]
    Continue,
    /// Stop the pipeline and return the error.
    Halt,
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

impl Default for TriagePipelineBuilder {
    fn default() -> Self {
        Self::new()
    }
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
                        let finding = Finding::from_error(format!("parser '{parser_name}'"), &e);
                        route_finding(&mut self.sinks, &mut result, &finding);
                        result.errors.push(e);
                        result.parsers_skipped.push(parser_name);
                        continue;
                    }
                    ErrorAction::Halt => return Err(e),
                },
            };

            result.parsers_run.push(parser_name.clone());
            let mut anomaly_tally = AnomalyTally::new();

            // Process each record from the parser
            for item_result in iter {
                let mut data = match item_result {
                    Ok(data) => data,
                    Err(e) => match self.error_action {
                        ErrorAction::Continue => {
                            crate::warn!("Parser '{}' produced error: {}", parser_name, e);
                            let finding = Finding::from_error(format!("parser '{parser_name}'"), &e);
                            route_finding(&mut self.sinks, &mut result, &finding);
                            result.errors.push(e);
                            continue;
                        }
                        ErrorAction::Halt => return Err(e),
                    },
                };
                let data_artifact = data.artifact().clone();

                // Run enrichers
                for enricher in &mut self.enrichers {
                    if let Err(e) = enricher.enrich(&mut data, &mut self.context) {
                        crate::warn!("Enricher '{}' failed: {}", enricher.name(), e);
                        let finding = Finding::from_error(format!("enricher '{}'", enricher.name()), &e)
                            .with_artifact(data_artifact.clone());
                        route_finding(&mut self.sinks, &mut result, &finding);
                        result.errors.push(e);
                    }
                }

                // Anomalies observed while parsing/enriching this record feed
                // the per-parser tally instead of becoming one finding each.
                anomaly_tally.record(data.anomalies());

                // Run matching analyzers
                for analyzer in &mut self.analyzers {
                    let supported = analyzer.supported_artifacts();
                    if !supported.is_empty() && !supported.contains(&data_artifact) {
                        continue;
                    }
                    let mut findings = Vec::new();
                    let outcome = analyzer.analyze(&data, &self.context, &mut findings);
                    for finding in &findings {
                        route_finding(&mut self.sinks, &mut result, finding);
                    }
                    if let Err(e) = outcome {
                        crate::warn!("Analyzer '{}' failed: {}", analyzer.name(), e);
                        let finding = Finding::from_error(format!("analyzer '{}'", analyzer.name()), &e)
                            .with_artifact(data_artifact.clone());
                        route_finding(&mut self.sinks, &mut result, &finding);
                        result.errors.push(e);
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
                let mut findings = Vec::new();
                let outcome = analyzer.finalize(&self.context, &mut findings);
                for finding in &findings {
                    route_finding(&mut self.sinks, &mut result, finding);
                }
                if let Err(e) = outcome {
                    crate::warn!("Analyzer '{}' finalize failed: {}", analyzer.name(), e);
                    let finding = Finding::from_error(format!("analyzer '{}' finalize", analyzer.name()), &e);
                    route_finding(&mut self.sinks, &mut result, &finding);
                    result.errors.push(e);
                }
            }

            // Flush this parser's anomaly tally into aggregate findings —
            // one per flag observed, not one per anomalous record.
            for finding in anomaly_tally.into_findings() {
                route_finding(&mut self.sinks, &mut result, &finding);
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
    use compact_str::CompactString;
    use super::*;
    use crate::{
        artifact::{Artifact, RegistryArtifacts, WindowsArtifacts, WindowsEvents},
        core::fs::StdVirtualFS,
        data::ForensicData,
        field::{Field, Text},
        pipeline::finding::{Finding, FindingCategory, FindingSeverity},
        pipeline::sinks::{FindingCollector, TimelineSink},
        utils::testing::{test_provenance_id, TestParserBuilder, TestingRegistry},
    };

    fn mock_parser(
        items: Vec<ForensicResult<ForensicData>>,
        artifact: Artifact,
    ) -> TestParserBuilder {
        TestParserBuilder::new("mock_parser")
            .description("Mock parser for testing")
            .version("0.0.1")
            .with_artifact(artifact)
            .with_results(items)
    }

    fn unparseable_mock_parser() -> TestParserBuilder {
        TestParserBuilder::new("mock_parser")
            .description("Mock parser for testing")
            .version("0.0.1")
            .parseable(false)
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
        fn analyze(
            &mut self,
            _data: &ForensicData,
            _context: &TriageContext,
            _out: &mut Vec<Finding>,
        ) -> ForensicResult<()> {
            self.count += 1;
            Ok(())
        }
        fn finalize(&mut self, _context: &TriageContext, out: &mut Vec<Finding>) -> ForensicResult<()> {
            if self.count < self.threshold {
                out.push(Finding::new(
                    FindingSeverity::Medium,
                    FindingCategory::MissingData,
                    format!(
                        "Expected at least {} records, got {}",
                        self.threshold, self.count
                    ),
                ));
            }
            Ok(())
        }
    }

    fn test_sources() -> TriageSources {
        TriageSources::new(
            std::sync::Arc::new(StdVirtualFS::new()),
            std::sync::Arc::new(TestingRegistry::new()),
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
                test_provenance_id(),
            )),
            Ok(ForensicData::new(
                "host1",
                RegistryArtifacts::ShellBags.into(),
                test_provenance_id(),
            )),
        ];
        let mut pipeline = TriagePipeline::builder()
            .parser(Box::new(
                mock_parser(items, RegistryArtifacts::ShellBags.into()).build(),
            ))
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
            .parser(Box::new(unparseable_mock_parser().build()))
            .build()
            .unwrap();
        let mut sources = test_sources();
        let result = pipeline.run(&mut sources).unwrap();
        assert_eq!(result.items_processed, 0);
        assert_eq!(result.parsers_skipped.len(), 1);
    }

    #[test]
    fn should_enrich_data() {
        let items = vec![Ok(ForensicData::new("host1", Artifact::Unknown, test_provenance_id()))];
        let mut pipeline = TriagePipeline::builder()
            .parser(Box::new(mock_parser(items, Artifact::Unknown).build()))
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
        let items = vec![Ok(ForensicData::new("host1", Artifact::Unknown, test_provenance_id()))];
        let mut pipeline = TriagePipeline::builder()
            .parser(Box::new(mock_parser(items, Artifact::Unknown).build()))
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
            Ok(ForensicData::new("host1", Artifact::Unknown, test_provenance_id())),
            Ok(ForensicData::new("host1", Artifact::Unknown, test_provenance_id())),
        ];

        // FindingCollector is a stats-only sink — it counts findings by severity.
        let mut pipeline = TriagePipeline::builder()
            .parser(Box::new(mock_parser(items, Artifact::Unknown).build()))
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
            Ok(ForensicData::new("host1", Artifact::Unknown, test_provenance_id())),
            Err(ForensicError::missing_data(
                "test missing data",
                CompactString::const_new("pipeline test"),
            )),
            Ok(ForensicData::new("host1", Artifact::Unknown, test_provenance_id())),
        ];
        let mut pipeline = TriagePipeline::builder()
            .parser(Box::new(mock_parser(items, Artifact::Unknown).build()))
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
            Ok(ForensicData::new("host1", Artifact::Unknown, test_provenance_id())),
            Err(ForensicError::missing_data(
                "halt test",
                CompactString::const_new("pipeline test"),
            )),
            Ok(ForensicData::new("host1", Artifact::Unknown, test_provenance_id())),
        ];
        let mut pipeline = TriagePipeline::builder()
            .parser(Box::new(mock_parser(items, Artifact::Unknown).build()))
            .on_parser_error(ErrorAction::Halt)
            .build()
            .unwrap();
        let mut sources = test_sources();
        let result = pipeline.run(&mut sources);
        assert!(result.is_err());
    }

    #[test]
    fn should_use_timeline_sink() {
        let mut data1 = ForensicData::new("host1", Artifact::Unknown, test_provenance_id());
        data1.add_field(
            "@timestamp",
            Field::Date(crate::utils::time::Filetime::with_ymd_and_hms(
                2024, 6, 15, 10, 30, 0, 0,
            ).into()),
        );
        let mut data2 = ForensicData::new("host1", Artifact::Unknown, test_provenance_id());
        data2.add_field(
            "@timestamp",
            Field::Date(crate::utils::time::Filetime::with_ymd_and_hms(
                2024, 6, 15, 8, 0, 0, 0,
            ).into()),
        );

        let mut pipeline = TriagePipeline::builder()
            .parser(Box::new(
                mock_parser(vec![Ok(data1), Ok(data2)], Artifact::Unknown).build(),
            ))
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
            fn analyze(
                &mut self,
                _data: &ForensicData,
                _context: &TriageContext,
                _out: &mut Vec<Finding>,
            ) -> ForensicResult<()> {
                self.seen += 1;
                Ok(())
            }
        }

        let items = vec![
            Ok(ForensicData::new("h", RegistryArtifacts::ShellBags.into(), test_provenance_id())), // should NOT match
            Ok(ForensicData::new(
                "h",
                WindowsArtifacts::WinEvt(WindowsEvents::Security).into(),
                test_provenance_id(),
            )), // should match
        ];
        let mut pipeline = TriagePipeline::builder()
            .parser(Box::new(mock_parser(items, Artifact::Unknown).build()))
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

    #[test]
    fn parse_time_anomaly_reaches_report_with_no_analyzer_registered() {
        // Proves the value-carried diagnostics guarantee end-to-end: nobody
        // hand-writes a `Finding` here, yet a parse-time anomaly still shows
        // up in the report — via `set_parsed` folding it into the record and
        // the pipeline's per-parser `AnomalyTally` lowering it at exhaustion.
        use crate::provenance::{AnomalyFlags, Anomalies, Parsed};

        let mut data = ForensicData::new("host1", Artifact::Unknown, test_provenance_id());
        let mut anomalies = Anomalies::empty();
        anomalies.add(AnomalyFlags::CHECKSUM_MISMATCH);
        let parsed = Parsed::with_anomalies(42u64, anomalies, test_provenance_id());
        data.set_parsed("checksum_field", parsed);

        let items = vec![Ok(data)];
        let mut pipeline = TriagePipeline::builder()
            .parser(Box::new(mock_parser(items, Artifact::Unknown).build()))
            .sink(Box::new(FindingCollector::new()))
            .build()
            .unwrap();
        let mut sources = test_sources();
        let result = pipeline.run(&mut sources).unwrap();

        assert_eq!(result.items_processed, 1);
        assert_eq!(result.findings_count, 1, "the tallied anomaly should promote to exactly one finding");
    }

    #[test]
    fn findings_pushed_before_a_hard_error_still_reach_the_sink() {
        // Proves the other half of the guarantee: an analyzer that pushes
        // findings and then bails out with `?` doesn't lose them — `out` is
        // an accumulator parameter, not a return value `?` can discard.
        struct PushThenFailAnalyzer;
        impl Analyzer for PushThenFailAnalyzer {
            fn name(&self) -> &str {
                "push_then_fail"
            }
            fn analyze(
                &mut self,
                _data: &ForensicData,
                _context: &TriageContext,
                out: &mut Vec<Finding>,
            ) -> ForensicResult<()> {
                out.push(Finding::new(FindingSeverity::Low, FindingCategory::Other("a".to_string()), "a"));
                out.push(Finding::new(FindingSeverity::Low, FindingCategory::Other("b".to_string()), "b"));
                Err(ForensicError::other("test", "intentional failure after pushing findings".to_string()))
            }
        }

        let items = vec![Ok(ForensicData::new("host1", Artifact::Unknown, test_provenance_id()))];
        let mut pipeline = TriagePipeline::builder()
            .parser(Box::new(mock_parser(items, Artifact::Unknown).build()))
            .analyzer(Box::new(PushThenFailAnalyzer))
            .sink(Box::new(FindingCollector::new()))
            .build()
            .unwrap();
        let mut sources = test_sources();
        let result = pipeline.run(&mut sources).unwrap();

        // 2 pushed findings + 1 ProcessingError finding for the analyzer's own failure.
        assert_eq!(result.findings_count, 3);
        assert_eq!(result.errors.len(), 1);
    }

    // --- Reference adopter: proves the real enforcement boundary works end-to-end ---
    //
    // Not a real artifact parser — just enough of one, implementing the real
    // `ArtifactParser` trait and flowing through a real `TriagePipeline`, to
    // prove that a `ProvenanceId` minted at parse time via `SourceHandle::mint`
    // survives untouched through `Enricher` and resolves correctly at
    // `Analyzer` via the real `TriageContext`. Without this, the central
    // guarantee (provenance-less artifacts can't enter the framework, and a
    // legitimately-minted id resolves to real confidence) is asserted in
    // isolated unit tests but never exercised through the actual boundary.

    use crate::provenance::{Acquisition, Confidence, Recovery, SourceHandle, SourceKey};

    struct ReferenceAdopterParser {
        source: SourceHandle,
        remaining: u32,
    }

    impl ArtifactParser for ReferenceAdopterParser {
        fn name(&self) -> &str {
            "reference_adopter"
        }
        fn description(&self) -> &str {
            "Proves the provenance enforcement boundary end-to-end"
        }
        fn version(&self) -> &str {
            "0.0.0"
        }
        fn supported_artifacts(&self) -> Vec<Artifact> {
            vec![Artifact::Unknown]
        }
        fn parse<'a>(
            &'a mut self,
            _sources: &'a mut TriageSources,
        ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<ForensicData>> + 'a>> {
            let source = self.source.clone();
            let remaining = self.remaining;
            self.remaining = 0;
            let iter = (0..remaining).map(move |_| {
                let provenance = source.mint(Acquisition::ImageRead, Recovery::Allocated);
                Ok(ForensicData::new("host", Artifact::Unknown, provenance))
            });
            Ok(Box::new(iter))
        }
    }

    struct ConfidenceCheckingAnalyzer {
        checked: u64,
    }

    impl Analyzer for ConfidenceCheckingAnalyzer {
        fn name(&self) -> &str {
            "confidence_checking"
        }
        fn analyze(
            &mut self,
            data: &ForensicData,
            context: &TriageContext,
            _out: &mut Vec<Finding>,
        ) -> ForensicResult<()> {
            let confidence = data.confidence(&context.provenance_store());
            assert_eq!(
                confidence,
                Confidence::High,
                "an ImageRead+Allocated record with no anomalies must resolve to High confidence"
            );
            self.checked += 1;
            Ok(())
        }
    }

    #[test]
    fn should_flow_provenance_through_real_pipeline() {
        let context = TriageContext::new("HOST", "TENANT");
        let source = context
            .provenance_store()
            .register_source(SourceKey::Path("C:\\reference-adopter".to_string()));

        let mut pipeline = TriagePipeline::builder()
            .context(context)
            .parser(Box::new(ReferenceAdopterParser { source, remaining: 5 }))
            .analyzer(Box::new(ConfidenceCheckingAnalyzer { checked: 0 }))
            .build()
            .unwrap();
        let mut sources = test_sources();
        let result = pipeline.run(&mut sources).unwrap();

        assert_eq!(result.items_processed, 5);
        assert!(result.errors.is_empty());
    }
}
