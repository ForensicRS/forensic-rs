pub mod context;
pub mod finding;
pub mod parallel;
pub(crate) mod processor;
pub mod registry;
pub mod sinks;
pub mod sources;
pub mod timeline;
pub mod traits;

use std::sync::Arc;

use crate::{
    bridge::CancellationToken,
    err::{ForensicError, ForensicResult},
    traits::forensic::{ArtifactParserFactory, ParserRun},
};

use self::{
    context::{ParseContext, TriageContext},
    finding::{AnomalyTally, Finding},
    processor::{RecordProcessor, SinkDestination},
    registry::ParserRegistry,
    sources::TriageSources,
    traits::{Analyzer, Enricher, TriageSink},
};

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
///     .parser(std::sync::Arc::new(my_parser))
///     .enricher(Box::new(my_enricher))
///     .analyzer(Box::new(my_analyzer))
///     .sink(Box::new(TimelineSink::new("@timestamp")))  // stats-only: tracks earliest/latest
///     .sink(Box::new(FindingCollector::new()))             // stats-only: counts by severity
///     .on_parser_error(ErrorAction::Continue)
///     .build()?;
/// ```
pub struct TriagePipelineBuilder {
    context: TriageContext,
    parsers: Vec<Arc<dyn ArtifactParserFactory>>,
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

    pub fn parser(mut self, parser: Arc<dyn ArtifactParserFactory>) -> Self {
        self.parsers.push(parser);
        self
    }

    /// Adds every factory currently registered in `registry`.
    pub fn parsers_from(mut self, registry: &ParserRegistry) -> Self {
        self.parsers
            .extend(registry.ids().filter_map(|id| registry.get(id)).cloned());
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
    parsers: Vec<Arc<dyn ArtifactParserFactory>>,
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
    pub fn run(&mut self, sources: &TriageSources) -> ForensicResult<PipelineResult> {
        self.run_with_cancellation(sources, CancellationToken::new())
    }

    /// Execute the pipeline with cooperative cancellation support.
    ///
    /// Checked before each parser starts, between records of a
    /// [`crate::traits::forensic::ParserRun::Pull`] stream, and passed to a
    /// [`crate::traits::forensic::ParserRun::Push`] parser via
    /// [`ParseContext::cancellation`] for it to poll during long stretches
    /// between emits.
    pub fn run_with_cancellation(
        &mut self,
        sources: &TriageSources,
        cancellation: CancellationToken,
    ) -> ForensicResult<PipelineResult> {
        self.context.install();

        let mut result = PipelineResult::default();
        let analyzer_artifacts: Vec<Vec<crate::artifact::Artifact>> = self
            .analyzers
            .iter()
            .map(|analyzer| analyzer.supported_artifacts())
            .collect();

        // Process each parser in registration order
        for factory in &self.parsers {
            if cancellation.is_cancelled() {
                break;
            }
            let id = factory.descriptor().id.to_string();

            let ctx = ParseContext::new(sources, &self.context, &cancellation);
            if !factory.can_parse(&ctx) {
                result.parsers_skipped.push(id);
                continue;
            }

            let run = match factory.open(&ctx) {
                Ok(run) => run,
                Err(e) => match self.error_action {
                    ErrorAction::Continue => {
                        crate::warn!("Parser '{}' failed to start: {}", id, e);
                        let finding = Finding::from_error(format!("parser '{id}'"), &e);
                        result.findings_count += 1;
                        for sink in &mut self.sinks {
                            if let Err(se) = sink.on_finding(&finding) {
                                result.errors.push(se);
                            }
                        }
                        result.errors.push(e);
                        result.parsers_skipped.push(id);
                        continue;
                    }
                    ErrorAction::Halt => return Err(e),
                },
            };

            let mut tally = AnomalyTally::new();
            let mut dest = SinkDestination { sinks: &mut self.sinks };
            let mut proc = RecordProcessor::new(
                &mut dest,
                &mut self.enrichers,
                &mut self.analyzers,
                &analyzer_artifacts,
                &mut self.context,
                &mut tally,
                &cancellation,
                self.error_action,
                // The serial pipeline has only ever checked `ErrorAction` at
                // the parser-record stage, never at enricher/analyzer stages
                // — preserved rather than unified, see `processor::RecordProcessor`.
                false,
                &id,
            );

            match run {
                ParserRun::Pull(stream) => proc.drive_pull(stream),
                ParserRun::Push(drive) => {
                    if let Err(e) = drive(&mut proc) {
                        proc.parser_error(e);
                    }
                }
            }

            // A hard failure (`ErrorAction::Halt`) aborts the whole run
            // immediately, matching this pipeline's long-standing behavior:
            // no finalize, no further parsers.
            if proc.is_halted() {
                let outcome = proc.finish();
                return Err(outcome
                    .halt_error
                    .expect("is_halted() implies halt_error is Some"));
            }

            proc.finalize_analyzers();
            proc.flush_tally();
            let outcome = proc.finish();

            result.parsers_run.push(id);
            result.items_processed += outcome.items;
            result.findings_count += outcome.findings;
            result.errors.extend(outcome.errors);
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
        traits::forensic::ParserDescriptor,
        utils::testing::{test_provenance_id, TestParserFactoryBuilder, TestingRegistry},
    };

    fn mock_parser(
        items: Vec<ForensicResult<ForensicData>>,
        artifact: Artifact,
    ) -> TestParserFactoryBuilder {
        TestParserFactoryBuilder::new("mock_parser")
            .description("Mock parser for testing")
            .version("0.0.1")
            .with_artifact(artifact)
            .with_results(items)
    }

    fn unparseable_mock_parser() -> TestParserFactoryBuilder {
        TestParserFactoryBuilder::new("mock_parser")
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
        let sources = test_sources();
        let result = pipeline.run(&sources).unwrap();
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
            .parser(Arc::new(
                mock_parser(items, RegistryArtifacts::ShellBags.into()).build(),
            ))
            .build()
            .unwrap();
        let sources = test_sources();
        let result = pipeline.run(&sources).unwrap();
        assert_eq!(result.items_processed, 2);
        assert_eq!(result.parsers_run.len(), 1);
        assert_eq!(result.parsers_run[0], "mock_parser");
    }

    #[test]
    fn should_skip_unparseable_parser() {
        let mut pipeline = TriagePipeline::builder()
            .parser(Arc::new(unparseable_mock_parser().build()))
            .build()
            .unwrap();
        let sources = test_sources();
        let result = pipeline.run(&sources).unwrap();
        assert_eq!(result.items_processed, 0);
        assert_eq!(result.parsers_skipped.len(), 1);
    }

    #[test]
    fn should_enrich_data() {
        let items = vec![Ok(ForensicData::new("host1", Artifact::Unknown, test_provenance_id()))];
        let mut pipeline = TriagePipeline::builder()
            .parser(Arc::new(mock_parser(items, Artifact::Unknown).build()))
            .enricher(Box::new(TagEnricher {
                tag_key: "enriched",
                tag_value: "yes",
            }))
            .sink(Box::new(FindingCollector::new()))
            .build()
            .unwrap();
        let sources = test_sources();
        let result = pipeline.run(&sources).unwrap();
        assert_eq!(result.items_processed, 1);
    }

    #[test]
    fn should_produce_findings_on_finalize() {
        let items = vec![Ok(ForensicData::new("host1", Artifact::Unknown, test_provenance_id()))];
        let mut pipeline = TriagePipeline::builder()
            .parser(Arc::new(mock_parser(items, Artifact::Unknown).build()))
            .analyzer(Box::new(CountAnalyzer::new(5))) // threshold=5, only 1 record → finding
            .build()
            .unwrap();
        let sources = test_sources();
        let result = pipeline.run(&sources).unwrap();
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
            .parser(Arc::new(mock_parser(items, Artifact::Unknown).build()))
            .analyzer(Box::new(CountAnalyzer::new(10)))
            .sink(Box::new(FindingCollector::new()))
            .build()
            .unwrap();
        let sources = test_sources();
        let result = pipeline.run(&sources).unwrap();
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
            .parser(Arc::new(mock_parser(items, Artifact::Unknown).build()))
            .on_parser_error(ErrorAction::Continue)
            .build()
            .unwrap();
        let sources = test_sources();
        let result = pipeline.run(&sources).unwrap();
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
            .parser(Arc::new(mock_parser(items, Artifact::Unknown).build()))
            .on_parser_error(ErrorAction::Halt)
            .build()
            .unwrap();
        let sources = test_sources();
        let result = pipeline.run(&sources);
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
            .parser(Arc::new(
                mock_parser(vec![Ok(data1), Ok(data2)], Artifact::Unknown).build(),
            ))
            .sink(Box::new(TimelineSink::new("@timestamp")))
            .build()
            .unwrap();
        let sources = test_sources();
        let result = pipeline.run(&sources).unwrap();
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
            .parser(Arc::new(mock_parser(items, Artifact::Unknown).build()))
            .analyzer(Box::new(WinEvtOnlyAnalyzer { seen: 0 }))
            .build()
            .unwrap();
        let sources = test_sources();
        let result = pipeline.run(&sources).unwrap();
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
            .parser(Arc::new(mock_parser(items, Artifact::Unknown).build()))
            .sink(Box::new(FindingCollector::new()))
            .build()
            .unwrap();
        let sources = test_sources();
        let result = pipeline.run(&sources).unwrap();

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
            .parser(Arc::new(mock_parser(items, Artifact::Unknown).build()))
            .analyzer(Box::new(PushThenFailAnalyzer))
            .sink(Box::new(FindingCollector::new()))
            .build()
            .unwrap();
        let sources = test_sources();
        let result = pipeline.run(&sources).unwrap();

        // 2 pushed findings + 1 ProcessingError finding for the analyzer's own failure.
        assert_eq!(result.findings_count, 3);
        assert_eq!(result.errors.len(), 1);
    }

    // --- Reference adopter: proves the real enforcement boundary works end-to-end ---
    //
    // Not a real artifact parser — just enough of one, implementing the real
    // `ArtifactParserFactory` trait and flowing through a real
    // `TriagePipeline`, to prove that a `ProvenanceId` minted at parse time
    // via `SourceHandle::mint` survives untouched through `Enricher` and
    // resolves correctly at `Analyzer` via the real `TriageContext`. Also
    // the showcase for `ParseContext::register_source`: unlike the old
    // `ArtifactParser`, this factory is never handed a `SourceHandle` at
    // construction — it registers its own `SourceKey` against whichever
    // store the pipeline that runs it actually owns, so there is no way to
    // mint against the wrong store.

    use crate::provenance::{Acquisition, Confidence, Recovery, SourceKey};

    struct ReferenceAdopterParser {
        descriptor: ParserDescriptor,
        remaining: u32,
    }

    impl ReferenceAdopterParser {
        fn new(remaining: u32) -> Self {
            Self {
                descriptor: ParserDescriptor::new(
                    "reference_adopter",
                    "reference_adopter",
                    "Proves the provenance enforcement boundary end-to-end",
                    "0.0.0",
                )
                .with_artifacts(vec![Artifact::Unknown]),
                remaining,
            }
        }
    }

    impl ArtifactParserFactory for ReferenceAdopterParser {
        fn descriptor(&self) -> &ParserDescriptor {
            &self.descriptor
        }
        fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
            let source = ctx.register_source(SourceKey::Path("C:\\reference-adopter".to_string()));
            let remaining = self.remaining;
            Ok(ParserRun::pull((0..remaining).map(move |_| {
                let provenance = source.mint(Acquisition::ImageRead, Recovery::Allocated);
                Ok(ForensicData::new("host", Artifact::Unknown, provenance))
            })))
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
        let mut pipeline = TriagePipeline::builder()
            .context(TriageContext::new("HOST", "TENANT"))
            .parser(Arc::new(ReferenceAdopterParser::new(5)))
            .analyzer(Box::new(ConfidenceCheckingAnalyzer { checked: 0 }))
            .build()
            .unwrap();
        let sources = test_sources();
        let result = pipeline.run(&sources).unwrap();

        assert_eq!(result.items_processed, 5);
        assert!(result.errors.is_empty());
    }
}
