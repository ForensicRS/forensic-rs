use crate::artifact::Artifact;
use crate::data::ForensicData;
use crate::err::ForensicResult;
use crate::field::Text;
use crate::pipeline::context::ParseContext;
use crate::traits::forensic::{ArtifactParserFactory, ParserDescriptor, ParserRun};

use super::test_provenance_id;

/// Builder for [`TestParserFactory`], a shared, public test double of
/// [`ArtifactParserFactory`].
///
/// ```
/// use forensic_rs::prelude::testing::TestParserFactoryBuilder;
/// use forensic_rs::prelude::*;
///
/// let parser = TestParserFactoryBuilder::new("mock_parser")
///     .with_artifact(Artifact::Unknown)
///     .with_records(3, "host1", Artifact::Unknown)
///     .build();
/// assert_eq!(parser.descriptor().artifacts.as_ref(), &[Artifact::Unknown]);
/// ```
pub struct TestParserFactoryBuilder {
    id: Text,
    description: Text,
    version: Text,
    artifacts: Vec<Artifact>,
    items: Vec<ForensicResult<ForensicData>>,
    parseable: bool,
    push_mode: bool,
}

impl TestParserFactoryBuilder {
    pub fn new(id: impl Into<Text>) -> Self {
        Self {
            id: id.into(),
            description: Text::Borrowed("Test parser"),
            version: Text::Borrowed("0.0.1"),
            artifacts: Vec::new(),
            items: Vec::new(),
            parseable: true,
            push_mode: false,
        }
    }

    pub fn description(mut self, description: impl Into<Text>) -> Self {
        self.description = description.into();
        self
    }

    pub fn version(mut self, version: impl Into<Text>) -> Self {
        self.version = version.into();
        self
    }

    /// Adds one artifact to `descriptor().artifacts`. Call once per artifact.
    pub fn with_artifact(mut self, artifact: Artifact) -> Self {
        self.artifacts.push(artifact);
        self
    }

    /// Pushes one `Ok(ForensicData)` record.
    pub fn with_record(mut self, data: ForensicData) -> Self {
        self.items.push(Ok(data));
        self
    }

    /// Generates `n` records against `artifact`, each with an `"index"` field.
    /// Does not also call `with_artifact` — chain that explicitly if
    /// `descriptor().artifacts` should include it.
    pub fn with_records(mut self, n: usize, host: &str, artifact: Artifact) -> Self {
        for i in 0..n {
            let mut data = ForensicData::new(host, artifact.clone(), test_provenance_id());
            data.add_field("index", crate::field::Field::U64(i as u64));
            self.items.push(Ok(data));
        }
        self
    }

    /// Pushes an arbitrary `ForensicResult` item (including `Err(..)`, for
    /// partial-failure stream testing).
    pub fn with_result(mut self, item: ForensicResult<ForensicData>) -> Self {
        self.items.push(item);
        self
    }

    pub fn with_results(mut self, items: Vec<ForensicResult<ForensicData>>) -> Self {
        self.items.extend(items);
        self
    }

    /// Overrides `can_parse()`'s return value.
    pub fn parseable(mut self, parseable: bool) -> Self {
        self.parseable = parseable;
        self
    }

    /// When `true`, `open()` returns [`ParserRun::Push`] instead of
    /// [`ParserRun::Pull`] — lets a test exercise both delivery modes
    /// against the same fixture data.
    pub fn push_mode(mut self, push_mode: bool) -> Self {
        self.push_mode = push_mode;
        self
    }

    pub fn build(self) -> TestParserFactory {
        let title = self.id.clone();
        let descriptor = ParserDescriptor::new(self.id, title, self.description, self.version)
            .with_artifacts(self.artifacts);
        TestParserFactory {
            descriptor,
            items: self.items,
            parseable: self.parseable,
            push_mode: self.push_mode,
        }
    }
}

/// Shared, public test double of [`ArtifactParserFactory`]: yields a fixed
/// set of pre-built records/errors. Build one via [`TestParserFactoryBuilder`].
///
/// `open()` clones its fixture items rather than draining them —
/// [`ArtifactParserFactory::open`] takes `&self`, matching every real
/// factory (stateless, shareable via `Arc`), and cloning means the same
/// built factory replays identically on every `open()` call, which an
/// `Arc`-shared factory used by several parallel modules relies on.
pub struct TestParserFactory {
    descriptor: ParserDescriptor,
    items: Vec<ForensicResult<ForensicData>>,
    parseable: bool,
    push_mode: bool,
}

impl ArtifactParserFactory for TestParserFactory {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    fn can_parse(&self, _ctx: &ParseContext<'_>) -> bool {
        self.parseable
    }

    fn open(&self, _ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        let items = self.items.clone();
        if self.push_mode {
            Ok(ParserRun::push(move |out| {
                for item in items {
                    if out.emit(item).is_stop() {
                        break;
                    }
                }
                Ok(())
            }))
        } else {
            Ok(ParserRun::pull(items.into_iter()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::fs::StdVirtualFS;
    use crate::pipeline::context::TriageContext;
    use crate::pipeline::sources::TriageSources;
    use crate::traits::forensic::{OutputFlow, ParserOutput};
    use crate::utils::testing::TestingRegistry;
    use crate::bridge::CancellationToken;

    fn test_sources() -> TriageSources {
        TriageSources::new(
            std::sync::Arc::new(StdVirtualFS::new()),
            std::sync::Arc::new(TestingRegistry::new()),
        )
    }

    fn test_ctx() -> (TriageContext, CancellationToken) {
        (TriageContext::default(), CancellationToken::new())
    }

    /// Drains a [`ParserRun`] into a `Vec`, regardless of whether it is
    /// `Pull` or `Push` — the common shape a test needs.
    struct CollectSink(Vec<ForensicResult<ForensicData>>);
    impl ParserOutput for CollectSink {
        fn emit(&mut self, record: ForensicResult<ForensicData>) -> OutputFlow {
            self.0.push(record);
            OutputFlow::Continue
        }
    }
    fn collect(run: ParserRun) -> Vec<ForensicResult<ForensicData>> {
        match run {
            ParserRun::Pull(stream) => stream.collect(),
            ParserRun::Push(drive) => {
                let mut sink = CollectSink(Vec::new());
                drive(&mut sink).unwrap();
                sink.0
            }
        }
    }

    #[test]
    fn defaults_match_legacy_mock_parser() {
        let parser = TestParserFactoryBuilder::new("mock_parser").build();
        assert_eq!(parser.descriptor().id, "mock_parser");
        assert_eq!(parser.descriptor().description, "Test parser");
        assert_eq!(parser.descriptor().version, "0.0.1");
        assert!(parser.descriptor().artifacts.is_empty());
        let sources = test_sources();
        let (ctx_owner, cancellation) = test_ctx();
        let ctx = ParseContext::new(&sources, &ctx_owner, &cancellation);
        assert!(parser.can_parse(&ctx));
        assert!(collect(parser.open(&ctx).unwrap()).is_empty());
    }

    #[test]
    fn parseable_false_mirrors_unparseable() {
        let parser = TestParserFactoryBuilder::new("mock_parser").parseable(false).build();
        let sources = test_sources();
        let (ctx_owner, cancellation) = test_ctx();
        let ctx = ParseContext::new(&sources, &ctx_owner, &cancellation);
        assert!(!parser.can_parse(&ctx));
    }

    #[test]
    fn with_records_generates_indexed_records() {
        let parser = TestParserFactoryBuilder::new("mock_parser")
            .with_artifact(Artifact::Unknown)
            .with_records(3, "host-a", Artifact::Unknown)
            .build();
        assert_eq!(parser.descriptor().artifacts.as_ref(), &[Artifact::Unknown]);
        let sources = test_sources();
        let (ctx_owner, cancellation) = test_ctx();
        let ctx = ParseContext::new(&sources, &ctx_owner, &cancellation);
        let items = collect(parser.open(&ctx).unwrap());
        assert_eq!(items.len(), 3);
        for item in items {
            assert!(item.is_ok());
        }
    }

    #[test]
    fn with_result_supports_partial_failures() {
        let parser = TestParserFactoryBuilder::new("mock_parser")
            .with_record(ForensicData::new("h", Artifact::Unknown, test_provenance_id()))
            .with_result(Err(crate::err::ForensicError::missing_data(
                "test",
                compact_str::CompactString::const_new("intentional"),
            )))
            .build();
        let sources = test_sources();
        let (ctx_owner, cancellation) = test_ctx();
        let ctx = ParseContext::new(&sources, &ctx_owner, &cancellation);
        let items = collect(parser.open(&ctx).unwrap());
        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        assert!(items[1].is_err());
    }

    #[test]
    fn push_mode_delivers_the_same_records() {
        let parser = TestParserFactoryBuilder::new("mock_parser")
            .with_records(3, "host-a", Artifact::Unknown)
            .push_mode(true)
            .build();
        let sources = test_sources();
        let (ctx_owner, cancellation) = test_ctx();
        let ctx = ParseContext::new(&sources, &ctx_owner, &cancellation);
        let run = parser.open(&ctx).unwrap();
        assert!(matches!(run, ParserRun::Push(_)));
        assert_eq!(collect(run).len(), 3);
    }

    #[test]
    fn open_is_replayable() {
        let parser = TestParserFactoryBuilder::new("mock_parser")
            .with_records(2, "host-a", Artifact::Unknown)
            .build();
        let sources = test_sources();
        let (ctx_owner, cancellation) = test_ctx();
        let ctx = ParseContext::new(&sources, &ctx_owner, &cancellation);

        assert_eq!(collect(parser.open(&ctx).unwrap()).len(), 2);
        // A second `open()` on the same instance yields the same records
        // again, instead of the drained-empty behavior a `&mut self` parser
        // would have — required for an `Arc`-shared factory used by more
        // than one parallel module.
        assert_eq!(collect(parser.open(&ctx).unwrap()).len(), 2);
    }
}
