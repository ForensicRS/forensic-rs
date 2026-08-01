//! Caller-scoped discovery and invocation for forensic capabilities.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::{
    access::{AccessContext, AccessKind, AccessPolicy, AccessRequest},
    resources::{
        Page, PageRequest, ResourceContent, ResourceEntry, ResourceId, ResourceMetadata,
        ResourceProvider, ResourceProviderDescriptor,
    },
    tools::{
        CapabilityError, CapabilityErrorKind, CapabilityResult, ForensicTool, InvocationContext,
        ToolDescriptor, ToolResult,
    },
    value::CapabilityValue,
};

/// Administrative capability registry.
///
/// This type owns registrations but intentionally offers no unscoped discovery
/// or invocation methods. Server-facing callers must first obtain a
/// [`ScopedCapabilityRegistry`] with trusted access context.
pub struct CapabilityRegistry {
    policy: Arc<dyn AccessPolicy>,
    tools: BTreeMap<String, Arc<dyn ForensicTool>>,
    resources: BTreeMap<String, Arc<dyn ResourceProvider>>,
}

impl CapabilityRegistry {
    /// Create a registry with an explicit policy. MCP-facing callers should
    /// provide a deny-by-default policy until real grants are configured.
    pub fn new(policy: Arc<dyn AccessPolicy>) -> Self {
        Self {
            policy,
            tools: BTreeMap::new(),
            resources: BTreeMap::new(),
        }
    }

    /// Register a tool by its stable descriptor ID.
    pub fn register_tool(&mut self, tool: Arc<dyn ForensicTool>) -> CapabilityResult<()> {
        let id = tool.descriptor().id.clone();
        if self.tools.contains_key(&id) {
            return Err(CapabilityError::new(
                CapabilityErrorKind::Conflict,
                format!("capability '{}' is already registered", id),
            ));
        }
        self.tools.insert(id, tool);
        Ok(())
    }

    /// Register a resource provider by its stable descriptor ID.
    pub fn register_resource_provider(
        &mut self,
        provider: Arc<dyn ResourceProvider>,
    ) -> CapabilityResult<()> {
        let id = provider.descriptor().id.clone();
        if self.resources.contains_key(&id) {
            return Err(CapabilityError::new(
                CapabilityErrorKind::Conflict,
                format!("resource provider '{}' is already registered", id),
            ));
        }
        self.resources.insert(id, provider);
        Ok(())
    }

    /// Create the only server-facing view of registered capabilities.
    pub fn scope(&self, context: AccessContext) -> ScopedCapabilityRegistry<'_> {
        ScopedCapabilityRegistry {
            registry: self,
            context,
        }
    }
}

/// Access-controlled view of a [`CapabilityRegistry`].
pub struct ScopedCapabilityRegistry<'a> {
    registry: &'a CapabilityRegistry,
    context: AccessContext,
}

impl ScopedCapabilityRegistry<'_> {
    /// Return only tool descriptors discoverable by this caller.
    pub fn list_tools(&self) -> Vec<ToolDescriptor> {
        self.registry
            .tools
            .values()
            .filter(|tool| {
                self.allows(
                    AccessKind::DiscoverTool,
                    tool.descriptor().id.as_str(),
                    None,
                )
            })
            .map(|tool| tool.descriptor().clone())
            .collect()
    }

    /// Return only resource providers discoverable by this caller.
    pub fn list_resource_providers(&self) -> Vec<ResourceProviderDescriptor> {
        self.registry
            .resources
            .values()
            .filter(|provider| {
                self.allows(
                    AccessKind::DiscoverResourceProvider,
                    provider.descriptor().id.as_str(),
                    None,
                )
            })
            .map(|provider| provider.descriptor().clone())
            .collect()
    }

    /// List authorized children after filtering every child before pagination.
    pub fn list_resources(
        &self,
        provider_id: &str,
        path: &str,
        page: PageRequest,
        cancellation: &crate::bridge::CancellationToken,
    ) -> CapabilityResult<Page<ResourceEntry>> {
        let provider = self.visible_resource_provider(provider_id)?;
        if !self.allows(AccessKind::ListResource, provider_id, Some(path)) {
            return Err(CapabilityError::not_found());
        }
        if cancellation.is_cancelled() {
            return Err(CapabilityError::new(
                CapabilityErrorKind::Cancelled,
                "operation cancelled",
            ));
        }
        let mut visible_entries: Vec<ResourceEntry> = provider
            .children(path, cancellation)?
            .into_iter()
            .filter(|entry| {
                entry.id.provider == provider_id
                    && self.allows(AccessKind::ListResource, provider_id, Some(&entry.id.path))
            })
            .collect();
        visible_entries.sort_by(|left, right| left.id.cmp(&right.id));
        let total = visible_entries.len() as u64;
        let entries: Vec<ResourceEntry> = visible_entries
            .into_iter()
            .skip(page.offset as usize)
            .take(page.limit as usize)
            .collect();
        let next_offset = page
            .offset
            .checked_add(entries.len() as u64)
            .filter(|next| *next < total);
        Ok(Page {
            entries,
            total,
            offset: page.offset,
            next_offset,
        })
    }

    /// Read a caller-authorized resource. Hidden and missing resources share
    /// the same public error.
    pub fn read_resource(
        &self,
        id: &ResourceId,
        cancellation: &crate::bridge::CancellationToken,
    ) -> CapabilityResult<ResourceContent> {
        let provider = self.visible_resource_provider(&id.provider)?;
        if !self.allows(AccessKind::ReadResource, &id.provider, Some(&id.path)) {
            return Err(CapabilityError::not_found());
        }
        provider.read(&id.path, cancellation)
    }

    /// Return metadata only for a caller-authorized resource.
    pub fn resource_metadata(
        &self,
        id: &ResourceId,
        cancellation: &crate::bridge::CancellationToken,
    ) -> CapabilityResult<ResourceMetadata> {
        let provider = self.visible_resource_provider(&id.provider)?;
        if !self.allows(AccessKind::ReadResource, &id.provider, Some(&id.path)) {
            return Err(CapabilityError::not_found());
        }
        provider.metadata(&id.path, cancellation)
    }

    /// Invoke a visible tool. Hidden and unknown IDs have identical errors.
    pub fn invoke_tool(
        &self,
        id: &str,
        input: CapabilityValue,
        invocation: InvocationContext,
    ) -> CapabilityResult<ToolResult> {
        let Some(tool) = self.registry.tools.get(id) else {
            return Err(CapabilityError::not_found());
        };
        if !self.allows(AccessKind::InvokeTool, id, None) {
            return Err(CapabilityError::not_found());
        }
        if invocation.access != self.context {
            return Err(CapabilityError::new(
                CapabilityErrorKind::AccessDenied,
                "invocation access context does not match registry scope",
            ));
        }
        if invocation.cancellation.is_cancelled() {
            return Err(CapabilityError::new(
                CapabilityErrorKind::Cancelled,
                "operation cancelled",
            ));
        }
        tool.descriptor()
            .input_schema
            .validate(&input)
            .map_err(|message| CapabilityError::new(CapabilityErrorKind::InvalidInput, message))?;
        let result = tool.invoke(input, &invocation)?;
        if let Some(schema) = &tool.descriptor().output_schema {
            let value = result.structured.as_ref().ok_or_else(|| {
                CapabilityError::new(
                    CapabilityErrorKind::Internal,
                    "tool did not return required structured output",
                )
            })?;
            schema
                .validate(value)
                .map_err(|message| CapabilityError::new(CapabilityErrorKind::Internal, message))?;
        }
        Ok(result)
    }

    /// Return the trusted context that scopes this registry view.
    pub fn access_context(&self) -> &AccessContext {
        &self.context
    }

    fn visible_resource_provider(&self, id: &str) -> CapabilityResult<&Arc<dyn ResourceProvider>> {
        let Some(provider) = self.registry.resources.get(id) else {
            return Err(CapabilityError::not_found());
        };
        if !self.allows(AccessKind::DiscoverResourceProvider, id, None) {
            return Err(CapabilityError::not_found());
        }
        Ok(provider)
    }

    fn allows(&self, kind: AccessKind, id: &str, target: Option<&str>) -> bool {
        let request = match target {
            Some(target) => AccessRequest::new(kind, id).with_target(target),
            None => AccessRequest::new(kind, id),
        };
        self.registry
            .policy
            .evaluate(&self.context, &request)
            .is_allowed()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use crate::{bridge::CancellationToken, field::Text};

    use super::*;
    use crate::capabilities::{
        AccessAuditEvent, AccessAuditSink, AccessDecision, AllowAllPolicy, AuditedAccessPolicy,
        CapabilityValue, ToolContent, ToolHints, ValueSchema, ValueType,
    };
    use crate::capabilities::{
        PageRequest, ResourceContent, ResourceEntry, ResourceId, ResourceKind, ResourceMetadata,
        ResourceProvider, ResourceProviderDescriptor,
    };

    struct TestTool {
        descriptor: ToolDescriptor,
    }

    impl TestTool {
        fn new(id: &str) -> Self {
            Self {
                descriptor: ToolDescriptor {
                    id: id.to_string(),
                    title: id.to_string(),
                    description: "test tool".to_string(),
                    input_schema: ValueSchema::Any,
                    output_schema: Some(ValueSchema::Type(ValueType::Text)),
                    hints: ToolHints {
                        read_only: true,
                        ..ToolHints::default()
                    },
                },
            }
        }
    }

    impl ForensicTool for TestTool {
        fn descriptor(&self) -> &ToolDescriptor {
            &self.descriptor
        }

        fn invoke(
            &self,
            _input: CapabilityValue,
            _context: &InvocationContext,
        ) -> CapabilityResult<ToolResult> {
            Ok(ToolResult {
                content: vec![ToolContent::Text(Text::Borrowed("ok"))],
                structured: Some(CapabilityValue::from("ok")),
            })
        }
    }

    struct ExactToolPolicy;

    impl AccessPolicy for ExactToolPolicy {
        fn evaluate(
            &self,
            _context: &AccessContext,
            request: &AccessRequest<'_>,
        ) -> AccessDecision {
            if request.capability_id == "visible" {
                AccessDecision::Allow
            } else {
                AccessDecision::Deny
            }
        }
    }

    #[derive(Default)]
    struct CollectingAuditSink {
        events: Mutex<Vec<AccessAuditEvent>>,
    }

    impl AccessAuditSink for CollectingAuditSink {
        fn record(&self, event: &AccessAuditEvent) {
            self.events.lock().unwrap().push(event.clone());
        }
    }

    struct ResourcePolicy;

    impl AccessPolicy for ResourcePolicy {
        fn evaluate(
            &self,
            _context: &AccessContext,
            request: &AccessRequest<'_>,
        ) -> AccessDecision {
            match (request.kind, request.capability_id, request.target) {
                (AccessKind::DiscoverResourceProvider, "evidence", None) => AccessDecision::Allow,
                (AccessKind::ListResource, "evidence", Some("" | "public-a" | "public-c")) => {
                    AccessDecision::Allow
                }
                (AccessKind::ReadResource, "evidence", Some("public-a")) => AccessDecision::Allow,
                _ => AccessDecision::Deny,
            }
        }
    }

    struct TestResourceProvider {
        descriptor: ResourceProviderDescriptor,
    }

    impl TestResourceProvider {
        fn new(id: &str) -> Self {
            Self {
                descriptor: ResourceProviderDescriptor {
                    id: id.to_string(),
                    title: id.to_string(),
                    description: "test resources".to_string(),
                },
            }
        }
    }

    impl ResourceProvider for TestResourceProvider {
        fn descriptor(&self) -> &ResourceProviderDescriptor {
            &self.descriptor
        }

        fn children(
            &self,
            _path: &str,
            _cancellation: &CancellationToken,
        ) -> CapabilityResult<Vec<ResourceEntry>> {
            Ok(["public-a", "private-b", "public-c"]
                .into_iter()
                .map(|path| ResourceEntry {
                    id: ResourceId::new(self.descriptor.id.clone(), path),
                    name: path.to_string(),
                    kind: ResourceKind::Leaf,
                    description: None,
                })
                .collect())
        }

        fn read(
            &self,
            path: &str,
            _cancellation: &CancellationToken,
        ) -> CapabilityResult<ResourceContent> {
            Ok(ResourceContent::Text {
                text: path.to_string(),
                media_type: Some("text/plain".to_string()),
            })
        }

        fn metadata(
            &self,
            _path: &str,
            _cancellation: &CancellationToken,
        ) -> CapabilityResult<ResourceMetadata> {
            Ok(ResourceMetadata::default())
        }
    }

    #[test]
    fn scoped_discovery_hides_denied_tools() {
        let mut registry = CapabilityRegistry::new(Arc::new(ExactToolPolicy));
        registry
            .register_tool(Arc::new(TestTool::new("visible")))
            .unwrap();
        registry
            .register_tool(Arc::new(TestTool::new("hidden")))
            .unwrap();

        let tools = registry
            .scope(AccessContext::new("analyst", "tenant"))
            .list_tools();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].id, "visible");
    }

    #[test]
    fn denied_and_unknown_tools_have_the_same_public_error() {
        let mut registry = CapabilityRegistry::new(Arc::new(ExactToolPolicy));
        registry
            .register_tool(Arc::new(TestTool::new("hidden")))
            .unwrap();
        let scoped = registry.scope(AccessContext::new("analyst", "tenant"));
        let invocation = InvocationContext::new(AccessContext::new("analyst", "tenant"));

        let denied = scoped
            .invoke_tool("hidden", CapabilityValue::Null, invocation.clone())
            .unwrap_err();
        let unknown = scoped
            .invoke_tool("missing", CapabilityValue::Null, invocation)
            .unwrap_err();
        assert_eq!(denied, unknown);
        assert_eq!(denied.kind, CapabilityErrorKind::NotFound);
    }

    #[test]
    fn audited_denial_preserves_public_not_found_error() {
        let sink = Arc::new(CollectingAuditSink::default());
        let policy = Arc::new(AuditedAccessPolicy::new(
            Arc::new(ExactToolPolicy),
            sink.clone(),
        ));
        let mut registry = CapabilityRegistry::new(policy);
        registry
            .register_tool(Arc::new(TestTool::new("hidden")))
            .unwrap();
        let access = AccessContext::new("analyst", "tenant");

        let error = registry
            .scope(access.clone())
            .invoke_tool(
                "hidden",
                CapabilityValue::Null,
                InvocationContext::new(access),
            )
            .unwrap_err();
        assert_eq!(error, CapabilityError::not_found());

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, AccessKind::InvokeTool);
        assert_eq!(events[0].capability_id, "hidden");
        assert_eq!(events[0].decision, AccessDecision::Deny);
    }

    #[test]
    fn scoped_registry_invokes_an_allowed_tool() {
        let mut registry = CapabilityRegistry::new(Arc::new(AllowAllPolicy));
        registry
            .register_tool(Arc::new(TestTool::new("visible")))
            .unwrap();
        let access = AccessContext::new("analyst", "tenant");
        let result = registry
            .scope(access.clone())
            .invoke_tool(
                "visible",
                CapabilityValue::Null,
                InvocationContext::new(access),
            )
            .unwrap();

        assert_eq!(
            result
                .structured
                .and_then(|value| value.as_text().map(str::to_owned)),
            Some("ok".to_string())
        );
    }

    #[test]
    fn scoped_registry_rejects_invalid_input_before_invocation() {
        let mut registry = CapabilityRegistry::new(Arc::new(AllowAllPolicy));
        registry
            .register_tool(Arc::new(TestTool {
                descriptor: ToolDescriptor {
                    id: "validated".to_string(),
                    title: "validated".to_string(),
                    description: "test tool".to_string(),
                    input_schema: ValueSchema::Type(ValueType::Object),
                    output_schema: Some(ValueSchema::Type(ValueType::Text)),
                    hints: ToolHints::default(),
                },
            }))
            .unwrap();
        let access = AccessContext::new("analyst", "tenant");

        let error = registry
            .scope(access.clone())
            .invoke_tool(
                "validated",
                CapabilityValue::Text(Text::Borrowed("wrong type")),
                InvocationContext::new(access),
            )
            .unwrap_err();
        assert_eq!(error.kind, CapabilityErrorKind::InvalidInput);
        assert_eq!(error.message, "$ must be object, received text");
    }

    #[test]
    fn resource_discovery_and_pagination_hide_denied_entries() {
        let mut registry = CapabilityRegistry::new(Arc::new(ResourcePolicy));
        registry
            .register_resource_provider(Arc::new(TestResourceProvider::new("evidence")))
            .unwrap();
        registry
            .register_resource_provider(Arc::new(TestResourceProvider::new("hidden-provider")))
            .unwrap();
        let scoped = registry.scope(AccessContext::new("analyst", "tenant"));

        let providers = scoped.list_resource_providers();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].id, "evidence");

        let page = scoped
            .list_resources(
                "evidence",
                "",
                PageRequest::new(1, 1),
                &CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(page.total, 2);
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].id.path, "public-c");
        assert_eq!(page.next_offset, None);
    }

    #[test]
    fn denied_resource_read_is_not_disclosed() {
        let mut registry = CapabilityRegistry::new(Arc::new(ResourcePolicy));
        registry
            .register_resource_provider(Arc::new(TestResourceProvider::new("evidence")))
            .unwrap();
        let scoped = registry.scope(AccessContext::new("analyst", "tenant"));

        let public = scoped
            .read_resource(
                &ResourceId::new("evidence", "public-a"),
                &CancellationToken::new(),
            )
            .unwrap();
        assert!(matches!(public, ResourceContent::Text { .. }));

        let denied = scoped
            .read_resource(
                &ResourceId::new("evidence", "private-b"),
                &CancellationToken::new(),
            )
            .unwrap_err();
        assert_eq!(denied, CapabilityError::not_found());
    }
}
