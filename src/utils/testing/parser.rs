use std::borrow::Cow;

use crate::artifact::Artifact;
use crate::data::ForensicData;
use crate::err::ForensicResult;
use crate::pipeline::sources::TriageSources;
use crate::traits::forensic::ArtifactParser;

use super::test_provenance_id;

/// Builder for [`TestParser`], a shared, public test double of [`ArtifactParser`].
///
/// ```
/// use forensic_rs::prelude::testing::TestParserBuilder;
/// use forensic_rs::prelude::*;
///
/// let mut parser = TestParserBuilder::new("mock_parser")
///     .with_artifact(Artifact::Unknown)
///     .with_records(3, "host1", Artifact::Unknown)
///     .build();
/// assert_eq!(parser.supported_artifacts(), vec![Artifact::Unknown]);
/// ```
pub struct TestParserBuilder {
    name: Cow<'static, str>,
    description: Cow<'static, str>,
    version: Cow<'static, str>,
    artifacts: Vec<Artifact>,
    items: Vec<ForensicResult<ForensicData>>,
    parseable: bool,
}

impl TestParserBuilder {
    pub fn new(name: impl Into<Cow<'static, str>>) -> Self {
        Self {
            name: name.into(),
            description: Cow::Borrowed("Test parser"),
            version: Cow::Borrowed("0.0.1"),
            artifacts: Vec::new(),
            items: Vec::new(),
            parseable: true,
        }
    }

    pub fn description(mut self, description: impl Into<Cow<'static, str>>) -> Self {
        self.description = description.into();
        self
    }

    pub fn version(mut self, version: impl Into<Cow<'static, str>>) -> Self {
        self.version = version.into();
        self
    }

    /// Adds one artifact to `supported_artifacts()`. Call once per artifact.
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
    /// `supported_artifacts()` should include it.
    pub fn with_records(mut self, n: usize, host: &str, artifact: Artifact) -> Self {
        for i in 0..n {
            let mut data = ForensicData::new(host, artifact.clone(), test_provenance_id());
            data.add_field("index", crate::field::Field::U64(i as u64));
            self.items.push(Ok(data));
        }
        self
    }

    /// Pushes an arbitrary `ForensicResult` item (including `Err(..)`, for
    /// partial-failure iterator testing).
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

    pub fn build(self) -> TestParser {
        TestParser {
            name: self.name,
            description: self.description,
            version: self.version,
            artifacts: self.artifacts,
            items: self.items,
            parseable: self.parseable,
        }
    }
}

/// Shared, public test double of [`ArtifactParser`]: yields a fixed set of
/// pre-built records/errors. Build one via [`TestParserBuilder`].
pub struct TestParser {
    name: Cow<'static, str>,
    description: Cow<'static, str>,
    version: Cow<'static, str>,
    artifacts: Vec<Artifact>,
    items: Vec<ForensicResult<ForensicData>>,
    parseable: bool,
}

impl ArtifactParser for TestParser {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn supported_artifacts(&self) -> Vec<Artifact> {
        self.artifacts.clone()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::fs::StdVirtualFS;
    use crate::utils::testing::TestingRegistry;

    fn test_sources() -> TriageSources {
        TriageSources::new(
            std::sync::Arc::new(StdVirtualFS::new()),
            std::sync::Arc::new(TestingRegistry::new()),
        )
    }

    #[test]
    fn defaults_match_legacy_mock_parser() {
        let mut parser = TestParserBuilder::new("mock_parser").build();
        assert_eq!(parser.name(), "mock_parser");
        assert_eq!(parser.description(), "Test parser");
        assert_eq!(parser.version(), "0.0.1");
        assert!(parser.supported_artifacts().is_empty());
        let mut sources = test_sources();
        assert!(parser.can_parse(&sources));
        assert!(parser.parse(&mut sources).unwrap().next().is_none());
    }

    #[test]
    fn parseable_false_mirrors_unparseable() {
        let parser = TestParserBuilder::new("mock_parser").parseable(false).build();
        let sources = test_sources();
        assert!(!parser.can_parse(&sources));
    }

    #[test]
    fn with_records_generates_indexed_records() {
        let mut parser = TestParserBuilder::new("mock_parser")
            .with_artifact(Artifact::Unknown)
            .with_records(3, "host-a", Artifact::Unknown)
            .build();
        assert_eq!(parser.supported_artifacts(), vec![Artifact::Unknown]);
        let mut sources = test_sources();
        let items: Vec<_> = parser.parse(&mut sources).unwrap().collect();
        assert_eq!(items.len(), 3);
        for item in items {
            assert!(item.is_ok());
        }
    }

    #[test]
    fn with_result_supports_partial_failures() {
        let mut parser = TestParserBuilder::new("mock_parser")
            .with_record(ForensicData::new(
                "h",
                Artifact::Unknown,
                test_provenance_id(),
            ))
            .with_result(Err(crate::err::ForensicError::missing_data(
                "test",
                "intentional".into(),
            )))
            .build();
        let mut sources = test_sources();
        let items: Vec<_> = parser.parse(&mut sources).unwrap().collect();
        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        assert!(items[1].is_err());
    }
}
