//! Authorization prerequisites for analyzer-backed pipeline capabilities.

use std::sync::Arc;

use crate::pipeline::sources::TriageSources;
use crate::traits::registry::RegistryReader;
use crate::traits::vfs::VirtualFileSystem;

use super::{
    AccessContext, AccessKind, AccessPolicy, AccessRequest, AuthorizedRegistryReader,
    AuthorizedVirtualFileSystem, CapabilityError, CapabilityErrorKind, CapabilityResult,
    CapabilityValue, ForensicTool, InvocationContext, ToolDescriptor, ToolResult,
};

/// A source type required by a pipeline execution plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineSourceKind {
    VirtualFileSystem,
    Registry,
}

/// Private dependencies required before a pipeline task may be constructed.
///
/// Requirement details are deliberately not returned to callers when a check
/// fails: a denied parser, analyzer, source, or artifact must remain
/// indistinguishable from one that was never registered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessRequirements {
    requirements: Vec<AccessRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AccessRequirement {
    kind: AccessKind,
    capability_id: String,
    target: Option<String>,
    source_kind: Option<PipelineSourceKind>,
}

impl AccessRequirements {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parser(mut self, id: impl Into<String>) -> Self {
        self.push(AccessKind::UseParser, id.into(), None, None);
        self
    }

    pub fn analyzer(mut self, id: impl Into<String>) -> Self {
        self.push(AccessKind::UseAnalyzer, id.into(), None, None);
        self
    }

    pub fn enricher(mut self, id: impl Into<String>) -> Self {
        self.push(AccessKind::UseEnricher, id.into(), None, None);
        self
    }

    pub fn reader_factory(mut self, id: impl Into<String>) -> Self {
        self.push(AccessKind::UseReaderFactory, id.into(), None, None);
        self
    }

    pub fn artifact(mut self, id: impl Into<String>) -> Self {
        self.push(AccessKind::ReadArtifact, id.into(), None, None);
        self
    }

    pub fn virtual_file_system(mut self, id: impl Into<String>) -> Self {
        self.push(
            AccessKind::UseSource,
            id.into(),
            None,
            Some(PipelineSourceKind::VirtualFileSystem),
        );
        self
    }

    pub fn registry(mut self, id: impl Into<String>) -> Self {
        self.push(
            AccessKind::UseSource,
            id.into(),
            None,
            Some(PipelineSourceKind::Registry),
        );
        self
    }

    fn push(
        &mut self,
        kind: AccessKind,
        capability_id: String,
        target: Option<String>,
        source_kind: Option<PipelineSourceKind>,
    ) {
        self.requirements.push(AccessRequirement {
            kind,
            capability_id,
            target,
            source_kind,
        });
    }

    fn authorize(&self, policy: &dyn AccessPolicy, access: &AccessContext) -> CapabilityResult<()> {
        for requirement in &self.requirements {
            let request = match requirement.target.as_deref() {
                Some(target) => AccessRequest::new(requirement.kind, &requirement.capability_id)
                    .with_target(target),
                None => AccessRequest::new(requirement.kind, &requirement.capability_id),
            };
            if !policy.evaluate(access, &request).is_allowed() {
                return Err(CapabilityError::not_found());
            }
        }
        Ok(())
    }

    fn source_kinds(&self) -> impl Iterator<Item = PipelineSourceKind> + '_ {
        self.requirements
            .iter()
            .filter_map(|requirement| requirement.source_kind)
    }

    fn has_source(&self, source_kind: PipelineSourceKind, id: &str) -> bool {
        self.requirements.iter().any(|requirement| {
            requirement.kind == AccessKind::UseSource
                && requirement.source_kind == Some(source_kind)
                && requirement.capability_id == id
        })
    }
}

/// Creates pipeline sources only after the complete execution plan is allowed.
///
/// The source factory is consumed after one use, which prevents a caller from
/// authorizing one context and reusing raw source handles for another.
pub struct AuthorizedSourceFactory {
    policy: Arc<dyn AccessPolicy>,
    access: AccessContext,
    requirements: AccessRequirements,
    factory: Option<Box<dyn FnOnce() -> TriageSources + Send + 'static>>,
}

impl AuthorizedSourceFactory {
    pub fn new(
        policy: Arc<dyn AccessPolicy>,
        access: AccessContext,
        requirements: AccessRequirements,
        factory: impl FnOnce() -> TriageSources + Send + 'static,
    ) -> Self {
        Self {
            policy,
            access,
            requirements,
            factory: Some(Box::new(factory)),
        }
    }

    /// Verify every dependency before constructing the underlying sources.
    pub fn create(mut self) -> CapabilityResult<TriageSources> {
        self.requirements
            .authorize(self.policy.as_ref(), &self.access)?;
        let factory = self.factory.take().ok_or_else(|| {
            CapabilityError::new(CapabilityErrorKind::Conflict, "source factory was consumed")
        })?;
        let sources = factory();
        for source_kind in self.requirements.source_kinds() {
            let available = match source_kind {
                PipelineSourceKind::VirtualFileSystem => sources.has_vfs(),
                PipelineSourceKind::Registry => sources.has_registry(),
            };
            if !available {
                return Err(CapabilityError::new(
                    CapabilityErrorKind::Internal,
                    "authorized pipeline source was not provided",
                ));
            }
        }
        Ok(sources)
    }
}

/// Creates one fresh pipeline-backed tool execution.
///
/// Implementations must construct fresh parsers, analyzers, enrichers, and
/// pipeline tasks for every call. They can use [`AuthorizedPipelineContext`]
/// to create worker-local sources only after the full dependency plan has been
/// authorized.
pub trait PipelineTaskFactory: Send + Sync {
    fn create(
        &self,
        input: CapabilityValue,
        invocation: &InvocationContext,
        execution: &AuthorizedPipelineContext<'_>,
    ) -> CapabilityResult<ToolResult>;
}

/// Internal execution context given to an authorized pipeline task factory.
pub struct AuthorizedPipelineContext<'a> {
    policy: &'a Arc<dyn AccessPolicy>,
    access: &'a AccessContext,
    requirements: &'a AccessRequirements,
}

impl AuthorizedPipelineContext<'_> {
    /// Create sources for this one execution after checking the same complete
    /// dependency plan again at the source-construction boundary.
    pub fn source_factory(
        &self,
        factory: impl FnOnce() -> TriageSources + Send + 'static,
    ) -> AuthorizedSourceFactory {
        AuthorizedSourceFactory::new(
            Arc::clone(self.policy),
            self.access.clone(),
            self.requirements.clone(),
            factory,
        )
    }

    /// Wrap a declared virtual filesystem so every path access is authorized.
    pub fn virtual_file_system(
        &self,
        id: impl Into<String>,
        inner: Box<dyn VirtualFileSystem>,
    ) -> CapabilityResult<Box<dyn VirtualFileSystem>> {
        let id = id.into();
        if !self
            .requirements
            .has_source(PipelineSourceKind::VirtualFileSystem, &id)
        {
            return Err(CapabilityError::not_found());
        }
        Ok(Box::new(AuthorizedVirtualFileSystem::new(
            inner,
            Arc::clone(self.policy),
            self.access.clone(),
            id,
        )))
    }

    /// Wrap a declared registry source so every key and value access is authorized.
    pub fn registry(
        &self,
        id: impl Into<String>,
        inner: Box<dyn RegistryReader>,
    ) -> CapabilityResult<Box<dyn RegistryReader>> {
        let id = id.into();
        if !self
            .requirements
            .has_source(PipelineSourceKind::Registry, &id)
        {
            return Err(CapabilityError::not_found());
        }
        Ok(Box::new(AuthorizedRegistryReader::new(
            inner,
            Arc::clone(self.policy),
            self.access.clone(),
            id,
        )))
    }
}

/// A [`ForensicTool`] that delegates to a fresh, authorized pipeline factory.
///
/// The public descriptor intentionally excludes the private dependency plan.
/// Authorization happens before the factory is invoked, so denied callers
/// cannot infer factory availability, parser support, or source configuration.
pub struct PipelineTaskTool {
    descriptor: ToolDescriptor,
    requirements: AccessRequirements,
    policy: Arc<dyn AccessPolicy>,
    factory: Arc<dyn PipelineTaskFactory>,
}

impl PipelineTaskTool {
    pub fn new(
        descriptor: ToolDescriptor,
        requirements: AccessRequirements,
        policy: Arc<dyn AccessPolicy>,
        factory: Arc<dyn PipelineTaskFactory>,
    ) -> Self {
        Self {
            descriptor,
            requirements,
            policy,
            factory,
        }
    }
}

impl ForensicTool for PipelineTaskTool {
    fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    fn invoke(
        &self,
        input: CapabilityValue,
        invocation: &InvocationContext,
    ) -> CapabilityResult<ToolResult> {
        if invocation.cancellation.is_cancelled() {
            return Err(CapabilityError::new(
                CapabilityErrorKind::Cancelled,
                "operation cancelled",
            ));
        }
        self.requirements
            .authorize(self.policy.as_ref(), &invocation.access)?;
        let execution = AuthorizedPipelineContext {
            policy: &self.policy,
            access: &invocation.access,
            requirements: &self.requirements,
        };
        self.factory.create(input, invocation, &execution)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::capabilities::{AccessDecision, AllowAllPolicy, ToolHints, ValueSchema};

    struct DenyPipelinePolicy;

    impl AccessPolicy for DenyPipelinePolicy {
        fn evaluate(
            &self,
            _access: &AccessContext,
            _request: &AccessRequest<'_>,
        ) -> AccessDecision {
            AccessDecision::Deny
        }
    }

    #[test]
    fn denied_requirements_do_not_construct_sources() {
        let calls = Arc::new(AtomicUsize::new(0));
        let factory_calls = Arc::clone(&calls);
        let factory = AuthorizedSourceFactory::new(
            Arc::new(DenyPipelinePolicy),
            AccessContext::new("analyst", "tenant"),
            AccessRequirements::new()
                .parser("windows.evtx")
                .reader_factory("windows.evtx.reader"),
            move || {
                factory_calls.fetch_add(1, Ordering::Relaxed);
                TriageSources::builder().build()
            },
        );

        assert!(matches!(
            factory.create(),
            Err(error) if error == CapabilityError::not_found()
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn allowed_requirements_construct_sources_once() {
        let factory = AuthorizedSourceFactory::new(
            Arc::new(AllowAllPolicy),
            AccessContext::new("analyst", "tenant"),
            AccessRequirements::new().parser("windows.evtx"),
            || TriageSources::builder().build(),
        );

        assert!(!factory.create().unwrap().has_vfs());
    }

    struct CountingPipelineFactory {
        calls: Arc<AtomicUsize>,
    }

    impl PipelineTaskFactory for CountingPipelineFactory {
        fn create(
            &self,
            _input: CapabilityValue,
            _invocation: &InvocationContext,
            _execution: &AuthorizedPipelineContext<'_>,
        ) -> CapabilityResult<ToolResult> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(ToolResult::structured(CapabilityValue::U64(1)))
        }
    }

    fn pipeline_descriptor() -> ToolDescriptor {
        ToolDescriptor {
            id: "windows.pipeline".to_string(),
            title: "Pipeline".to_string(),
            description: "Test pipeline".to_string(),
            input_schema: ValueSchema::Any,
            output_schema: None,
            hints: ToolHints::default(),
        }
    }

    #[test]
    fn denied_pipeline_tool_does_not_construct_task_factory() {
        let calls = Arc::new(AtomicUsize::new(0));
        let tool = PipelineTaskTool::new(
            pipeline_descriptor(),
            AccessRequirements::new().analyzer("event-gap"),
            Arc::new(DenyPipelinePolicy),
            Arc::new(CountingPipelineFactory {
                calls: Arc::clone(&calls),
            }),
        );
        let invocation = InvocationContext::new(AccessContext::new("analyst", "tenant"));

        assert!(matches!(
            tool.invoke(CapabilityValue::Null, &invocation),
            Err(error) if error == CapabilityError::not_found()
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn allowed_pipeline_tool_creates_a_fresh_task_execution() {
        let calls = Arc::new(AtomicUsize::new(0));
        let tool = PipelineTaskTool::new(
            pipeline_descriptor(),
            AccessRequirements::new().analyzer("event-gap"),
            Arc::new(AllowAllPolicy),
            Arc::new(CountingPipelineFactory {
                calls: Arc::clone(&calls),
            }),
        );
        let invocation = InvocationContext::new(AccessContext::new("analyst", "tenant"));

        tool.invoke(CapabilityValue::Null, &invocation).unwrap();
        tool.invoke(CapabilityValue::Null, &invocation).unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn execution_context_rejects_undeclared_sources() {
        let requirements = AccessRequirements::new()
            .virtual_file_system("declared-vfs")
            .registry("declared-registry");
        let policy: Arc<dyn AccessPolicy> = Arc::new(AllowAllPolicy);
        let access = AccessContext::new("analyst", "tenant");
        let context = AuthorizedPipelineContext {
            policy: &policy,
            access: &access,
            requirements: &requirements,
        };

        assert!(matches!(
            context.virtual_file_system("other-vfs", Box::new(crate::core::fs::StdVirtualFS::new())),
            Err(error) if error == CapabilityError::not_found()
        ));
        assert!(matches!(
            context.registry("other-registry", Box::new(crate::utils::testing::TestingRegistry::new())),
            Err(error) if error == CapabilityError::not_found()
        ));
    }
}
