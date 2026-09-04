//! ID-keyed store of parser factories available to a run.
//!
//! Mirrors [`crate::capabilities::CapabilityRegistry`]: registration only, a
//! `BTreeMap` for deterministic iteration order, and a hard error on a
//! duplicate id. This is the backing store
//! [`crate::capabilities::AccessRequirements::parser`] has been authorizing
//! against nothing — a parser id it names can now actually resolve to a
//! constructor here.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::artifact::Artifact;
use crate::err::{ForensicError, ForensicResult};
use crate::field::Text;
use crate::traits::forensic::{ArtifactParserFactory, ParserDescriptor};

/// ID-keyed collection of [`ArtifactParserFactory`] instances.
#[derive(Default)]
pub struct ParserRegistry {
    parsers: BTreeMap<Text, Arc<dyn ArtifactParserFactory>>,
}

impl ParserRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `factory` under its `descriptor().id`. Errors on a
    /// duplicate id — a silently-overwritten parser would be a much harder
    /// bug to notice than a loud registration-time failure.
    pub fn register(&mut self, factory: Arc<dyn ArtifactParserFactory>) -> ForensicResult<()> {
        let id = factory.descriptor().id.clone();
        if self.parsers.contains_key(&id) {
            return Err(ForensicError::other(
                "parser_registry",
                format!("a parser is already registered under id '{id}'"),
            ));
        }
        self.parsers.insert(id, factory);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&Arc<dyn ArtifactParserFactory>> {
        self.parsers.get(id)
    }

    pub fn descriptors(&self) -> impl Iterator<Item = &ParserDescriptor> {
        self.parsers.values().map(|p| p.descriptor())
    }

    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.parsers.keys().map(|t| t.as_ref())
    }

    /// Every parser whose descriptor [`ParserDescriptor::handles`] any of
    /// `wanted`. An empty `wanted` (the analyzer "accept all" default)
    /// matches every parser, mirroring
    /// [`ParserDescriptor::handles`]'s own "empty = all" convention on the
    /// parser side.
    pub fn matching(&self, wanted: &[Artifact]) -> Vec<Arc<dyn ArtifactParserFactory>> {
        self.parsers
            .values()
            .filter(|factory| {
                let descriptor = factory.descriptor();
                wanted.is_empty() || wanted.iter().any(|a| descriptor.handles(a))
            })
            .cloned()
            .collect()
    }

    pub fn len(&self) -> usize {
        self.parsers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.parsers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::RegistryArtifacts;
    use crate::pipeline::context::ParseContext;
    use crate::traits::forensic::ParserRun;

    struct StubParser {
        descriptor: ParserDescriptor,
    }

    impl ArtifactParserFactory for StubParser {
        fn descriptor(&self) -> &ParserDescriptor {
            &self.descriptor
        }
        fn open(&self, _ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
            Ok(ParserRun::pull(std::iter::empty()))
        }
    }

    fn stub(id: &str, artifacts: Vec<Artifact>) -> Arc<dyn ArtifactParserFactory> {
        Arc::new(StubParser {
            descriptor: ParserDescriptor::new(id.to_string(), id.to_string(), "stub", "0.0.0")
                .with_artifacts(artifacts),
        })
    }

    #[test]
    fn duplicate_id_is_a_conflict() {
        let mut registry = ParserRegistry::new();
        registry.register(stub("windows.amcache", vec![])).unwrap();
        let err = registry.register(stub("windows.amcache", vec![]));
        assert!(err.is_err());
    }

    #[test]
    fn get_resolves_by_id() {
        let mut registry = ParserRegistry::new();
        registry.register(stub("windows.amcache", vec![])).unwrap();
        assert!(registry.get("windows.amcache").is_some());
        assert!(registry.get("windows.other").is_none());
    }

    #[test]
    fn matching_empty_wanted_matches_everything() {
        let mut registry = ParserRegistry::new();
        registry
            .register(stub("a", vec![RegistryArtifacts::AutoRuns.into()]))
            .unwrap();
        registry.register(stub("b", vec![])).unwrap();
        assert_eq!(registry.matching(&[]).len(), 2);
    }

    #[test]
    fn matching_empty_parser_artifacts_matches_everything() {
        let mut registry = ParserRegistry::new();
        registry.register(stub("a", vec![])).unwrap();
        let wanted = vec![RegistryArtifacts::AutoRuns.into()];
        assert_eq!(registry.matching(&wanted).len(), 1);
    }

    #[test]
    fn matching_disjoint_artifacts_matches_nothing() {
        let mut registry = ParserRegistry::new();
        registry
            .register(stub("a", vec![RegistryArtifacts::AmCache.into()]))
            .unwrap();
        let wanted = vec![RegistryArtifacts::AutoRuns.into()];
        assert!(registry.matching(&wanted).is_empty());
    }

    #[test]
    fn descriptors_iterate_in_deterministic_order() {
        let mut registry = ParserRegistry::new();
        registry.register(stub("b", vec![])).unwrap();
        registry.register(stub("a", vec![])).unwrap();
        let ids: Vec<&str> = registry.ids().collect();
        assert_eq!(ids, vec!["a", "b"]);
    }
}
