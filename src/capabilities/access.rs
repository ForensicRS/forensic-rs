//! Authorization contracts for protocol-neutral forensic capabilities.
//!
//! Authentication belongs to the hosting server. Once it has authenticated a
//! request, it constructs an [`AccessContext`] and passes it to forensic-rs.
//! Policies are evaluated by scoped capability registries before discovery,
//! invocation, and data access.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::field::Text;

/// Trusted identity and scope supplied by a hosting server after authentication.
///
/// This context must not be constructed from tool arguments or resource URIs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessContext {
    /// Stable authenticated principal identifier.
    pub principal: String,
    /// Tenant that owns the requested evidence and capabilities.
    pub tenant: String,
    /// Optional server-issued session identifier.
    pub session: Option<String>,
    /// Server-issued roles or claims used by policy implementations.
    pub roles: BTreeSet<String>,
    /// Additional trusted attributes supplied by the hosting server.
    pub metadata: BTreeMap<Text, Text>,
}

impl AccessContext {
    /// Create a caller context with no roles or metadata.
    pub fn new(principal: impl Into<String>, tenant: impl Into<String>) -> Self {
        Self {
            principal: principal.into(),
            tenant: tenant.into(),
            session: None,
            roles: BTreeSet::new(),
            metadata: BTreeMap::new(),
        }
    }

    /// Add a trusted role or claim to this context.
    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.roles.insert(role.into());
        self
    }

    /// Attach a server-issued session identifier.
    pub fn with_session(mut self, session: impl Into<String>) -> Self {
        self.session = Some(session.into());
        self
    }
}

/// The operation being authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    DiscoverTool,
    InvokeTool,
    DiscoverResourceProvider,
    ListResource,
    ReadResource,
    UseParser,
    UseAnalyzer,
    UseEnricher,
    UseReaderFactory,
    UseSource,
    ReadArtifact,
}

/// A protocol-neutral authorization request.
///
/// `capability_id` is a stable internal ID. `target` may identify a path,
/// channel, database table, artifact instance, or data-source-specific object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRequest<'a> {
    pub kind: AccessKind,
    pub capability_id: &'a str,
    pub target: Option<&'a str>,
}

impl<'a> AccessRequest<'a> {
    pub fn new(kind: AccessKind, capability_id: &'a str) -> Self {
        Self {
            kind,
            capability_id,
            target: None,
        }
    }

    pub fn with_target(mut self, target: &'a str) -> Self {
        self.target = Some(target);
        self
    }
}

/// A policy result. Denials are intentionally data-free to avoid exposing why
/// a hidden capability or evidence path exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecision {
    Allow,
    Deny,
}

impl AccessDecision {
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Trusted internal record of one access-policy decision.
///
/// This data is for server-side audit sinks only. It must never be returned in
/// capability descriptors, resource results, or caller-visible errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessAuditEvent {
    pub context: AccessContext,
    pub kind: AccessKind,
    pub capability_id: String,
    pub target: Option<String>,
    pub decision: AccessDecision,
}

impl AccessAuditEvent {
    fn from_request(
        context: &AccessContext,
        request: &AccessRequest<'_>,
        decision: AccessDecision,
    ) -> Self {
        Self {
            context: context.clone(),
            kind: request.kind,
            capability_id: request.capability_id.to_string(),
            target: request.target.map(str::to_string),
            decision,
        }
    }
}

/// Receives trusted internal authorization records.
///
/// Sinks must not expose events to untrusted callers. Recording is infallible
/// so audit delivery cannot turn a policy denial into a public error change.
pub trait AccessAuditSink: Send + Sync {
    fn record(&self, event: &AccessAuditEvent);
}

/// Evaluates access to capabilities and evidence.
///
/// Policies must fail closed: implementations should return [`AccessDecision::Deny`]
/// when policy data is unavailable or cannot be evaluated. Detailed denial reasons
/// belong in the host's audit system, never in a caller-visible result.
pub trait AccessPolicy: Send + Sync {
    fn evaluate(&self, context: &AccessContext, request: &AccessRequest<'_>) -> AccessDecision;
}

/// Decorates an access policy with a trusted audit sink.
///
/// Use this policy wherever authorization is enforced. It preserves the
/// wrapped policy's decision exactly while emitting an owned audit record for
/// every evaluation, including denied nested source accesses.
pub struct AuditedAccessPolicy {
    policy: Arc<dyn AccessPolicy>,
    audit: Arc<dyn AccessAuditSink>,
}

impl AuditedAccessPolicy {
    pub fn new(policy: Arc<dyn AccessPolicy>, audit: Arc<dyn AccessAuditSink>) -> Self {
        Self { policy, audit }
    }
}

impl AccessPolicy for AuditedAccessPolicy {
    fn evaluate(&self, context: &AccessContext, request: &AccessRequest<'_>) -> AccessDecision {
        let decision = self.policy.evaluate(context, request);
        self.audit
            .record(&AccessAuditEvent::from_request(context, request, decision));
        decision
    }
}

/// Explicit opt-in policy for trusted local or backward-compatible deployments.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllPolicy;

impl AccessPolicy for AllowAllPolicy {
    fn evaluate(&self, _context: &AccessContext, _request: &AccessRequest<'_>) -> AccessDecision {
        AccessDecision::Allow
    }
}

/// Default-safe policy for server-facing registries until a real policy is supplied.
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAllPolicy;

impl AccessPolicy for DenyAllPolicy {
    fn evaluate(&self, _context: &AccessContext, _request: &AccessRequest<'_>) -> AccessDecision {
        AccessDecision::Deny
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct CollectingAuditSink {
        events: Mutex<Vec<AccessAuditEvent>>,
    }

    impl AccessAuditSink for CollectingAuditSink {
        fn record(&self, event: &AccessAuditEvent) {
            self.events.lock().unwrap().push(event.clone());
        }
    }

    #[test]
    fn access_context_preserves_server_issued_scope() {
        let context = AccessContext::new("analyst-42", "acme")
            .with_session("session-7")
            .with_role("forensics.read");

        assert_eq!(context.principal, "analyst-42");
        assert_eq!(context.tenant, "acme");
        assert_eq!(context.session.as_deref(), Some("session-7"));
        assert!(context.roles.contains("forensics.read"));
    }

    #[test]
    fn explicit_policies_allow_or_deny_without_disclosure() {
        let context = AccessContext::new("analyst-42", "acme");
        let request = AccessRequest::new(AccessKind::DiscoverTool, "private.tool");

        assert!(AllowAllPolicy.evaluate(&context, &request).is_allowed());
        assert!(!DenyAllPolicy.evaluate(&context, &request).is_allowed());
    }

    #[test]
    fn access_request_can_describe_a_scoped_target() {
        let request = AccessRequest::new(AccessKind::ReadResource, "filesystem")
            .with_target(r"C:\\evidence\\case-17");

        assert_eq!(request.target, Some(r"C:\\evidence\\case-17"));
    }

    #[test]
    fn audited_policy_records_detailed_denials_without_changing_decisions() {
        let sink = Arc::new(CollectingAuditSink::default());
        let policy = AuditedAccessPolicy::new(Arc::new(DenyAllPolicy), sink.clone());
        let context = AccessContext::new("analyst-42", "acme").with_session("session-7");
        let request = AccessRequest::new(AccessKind::ReadResource, "case-files")
            .with_target(r"C:\\evidence\\case-17\\private.txt");

        assert_eq!(policy.evaluate(&context, &request), AccessDecision::Deny);
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].context, context);
        assert_eq!(events[0].kind, AccessKind::ReadResource);
        assert_eq!(events[0].capability_id, "case-files");
        assert_eq!(
            events[0].target.as_deref(),
            Some(r"C:\\evidence\\case-17\\private.txt")
        );
        assert_eq!(events[0].decision, AccessDecision::Deny);
    }
}
