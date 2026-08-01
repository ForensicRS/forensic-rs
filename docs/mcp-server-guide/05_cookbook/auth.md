# Cookbook: Access Control Recipes

This cookbook provides reusable code patterns for implementing `AccessPolicy`.

## Recipe 1: Allow-All for Development

Use `AllowAllPolicy` for local development only.

```rust
use forensic_rs::prelude::*;

// WARNING: Never use in production with untrusted clients!
let policy = Arc::new(AllowAllPolicy::new());

let mut registry = CapabilityRegistry::new(policy);
registry.register_tool(Arc::new(MyTool::new())).unwrap();

// Test with full access
let access = AccessContext::new("test-user", "test-tenant");
let scoped = registry.scope(access);
assert!(!scoped.list_tools().is_empty());
```

## Recipe 2: Role-Based Access Control (RBAC)

Implement fine-grained role-based permissions.

```rust
use std::collections::BTreeMap;
use forensic_rs::field::Text;
use forensic_rs::prelude::*;

pub struct RbacPolicy {
    role_permissions: BTreeMap<Text, Vec<Permission>>,
}

#[derive(Clone)]
struct Permission {
    target: Target,
    actions: Vec<Action>,
}

enum Target {
    Tool(String),
    ResourceProvider(String),
    Path { provider: String, pattern: String },
}

enum Action {
    Discover,
    Invoke,
    Read,
}

impl RbacPolicy {
    pub fn new() -> Self {
        let mut policy = Self {
            role_permissions: BTreeMap::new(),
        };

        // Analyst role: read-only access to most tools
        policy.role_permissions.insert(
            Text::Borrowed("analyst"),
            vec![
                Permission {
                    target: Target::Tool("case.summary".into()),
                    actions: vec![Action::Discover, Action::Invoke],
                },
                Permission {
                    target: Target::Tool("registry.autoruns".into()),
                    actions: vec![Action::Discover, Action::Invoke],
                },
                Permission {
                    target: Target::Tool("prefetch.analyze".into()),
                    actions: vec![Action::Discover, Action::Invoke],
                },
                Permission {
                    target: Target::ResourceProvider("registry".into()),
                    actions: vec![Action::Discover, Action::Read],
                },
            ],
        );

        // Admin role: full access
        policy.role_permissions.insert(
            Text::Borrowed("admin"),
            vec![
                Permission {
                    target: Target::Tool("*".into()),  // Wildcard
                    actions: vec![Action::Discover, Action::Invoke],
                },
                Permission {
                    target: Target::ResourceProvider("*".into()),
                    actions: vec![Action::Discover, Action::Read],
                },
            ],
        );

        policy
    }

    fn has_permission(&self, context: &AccessContext, target: &Target, action: &Action) -> bool {
        for role in &context.roles {
            if let Some(permissions) = self.role_permissions.get(role) {
                for perm in permissions {
                    if self.target_matches(&perm.target, target) && perm.actions.contains(action) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn target_matches(&self, pattern: &Target, actual: &Target) -> bool {
        match (pattern, actual) {
            (Target::Tool(p), Target::Tool(a)) => self.glob_match(p, a),
            (Target::ResourceProvider(p), Target::ResourceProvider(a)) => self.glob_match(p, a),
            _ => false,
        }
    }

    fn glob_match(&self, pattern: &str, value: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if let Some(rest) = pattern.strip_prefix("*") {
            return value.ends_with(rest);
        }
        pattern == value
    }
}

impl AccessPolicy for RbacPolicy {
    fn evaluate(&self, context: &AccessContext, request: &AccessRequest<'_>) -> AccessDecision {
        let (target, action) = match request {
            AccessRequest::DiscoverTool { tool_id } => {
                (Target::Tool(tool_id.to_string()), Action::Discover)
            }
            AccessRequest::InvokeTool { tool_id } => {
                (Target::Tool(tool_id.to_string()), Action::Invoke)
            }
            AccessRequest::DiscoverResourceProvider { provider_id } => {
                (Target::ResourceProvider(provider_id.to_string()), Action::Discover)
            }
            AccessRequest::ReadResource { provider_id, path } => {
                (Target::Path { provider: provider_id.to_string(), pattern: path.to_string() }, Action::Read)
            }
            _ => return AccessDecision::Allow,
        };

        if self.has_permission(context, &target, &action) {
            AccessDecision::Allow
        } else {
            AccessDecision::Deny
        }
    }
}
```

## Recipe 3: Audit Logging

Log all access decisions for compliance.

```rust
use std::sync::Arc;
use forensic_rs::field::Text;
use forensic_rs::prelude::*;

pub struct JsonAuditSink {
    // Could write to file, syslog, etc.
}

impl JsonAuditSink {
    pub fn new() -> Self {
        Self
    }
}

impl AccessAuditSink for JsonAuditSink {
    fn record(&self, event: &AccessAuditEvent) {
        let audit_record = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "principal": event.context.principal.as_ref(),
            "tenant": event.context.tenant.as_ref(),
            "session": event.context.session.as_ref().map(|s| s.as_ref()),
            "kind": format!("{:?}", event.kind),
            "capability_id": event.capability_id,
            "target": event.target,
            "decision": format!("{:?}", event.decision),
            "roles": event.context.roles.iter().map(|r| r.as_ref()).collect::<Vec<_>>(),
        });

        // In production, write to file or send to SIEM
        println!("[AUDIT] {}", audit_record);
    }
}

// Usage
let base_policy = Arc::new(RbacPolicy::new());
let audit_sink = Arc::new(JsonAuditSink::new());
let policy = Arc::new(AuditedAccessPolicy::new(base_policy, audit_sink));
```

## Recipe 4: Multi-Tenant Isolation

Ensure tenants cannot access each other's data.

```rust
use std::sync::Arc;
use forensic_rs::prelude::*;

pub struct TenantIsolationPolicy<P: AccessPolicy> {
    inner: P,
}

impl<P: AccessPolicy> TenantIsolationPolicy<P> {
    pub fn new(inner: P) -> Self {
        Self { inner }
    }
}

impl<P: AccessPolicy> AccessPolicy for TenantIsolationPolicy<P> {
    fn evaluate(&self, context: &AccessContext, request: &AccessRequest<'_>) -> AccessDecision {
        // First, delegate to inner policy
        let inner_decision = self.inner.evaluate(context, request);

        // Then, enforce tenant isolation for resource access
        if let AccessRequest::ReadResource { path, .. } = request {
            // Check if path contains tenant identifier
            // This assumes paths include tenant info, e.g., "tenant-123/evidence/..."
            if !path.contains(&context.tenant.to_string()) {
                eprintln!(
                    "[SECURITY] Tenant {} attempted to access path {} belonging to another tenant",
                    context.principal,
                    path
                );
                return AccessDecision::Deny;
            }
        }

        inner_decision
    }
}

// Usage
let base_policy = Arc::new(RbacPolicy::new());
let tenant_policy = Arc::new(TenantIsolationPolicy::new(base_policy.as_ref().clone()));
let audit_sink = Arc::new(JsonAuditSink::new());
let policy = Arc::new(AuditedAccessPolicy::new(tenant_policy, audit_sink));
```

## Recipe 5: Path-Based Restrictions (Source Guards)

Use source guards to enforce path-level restrictions on evidence access.

```rust
use forensic_rs::prelude::*;

// Source guards wrap evidence sources with path-based authorization

pub struct PathRestrictions {
    allowed_paths: Vec<String>,
    denied_paths: Vec<String>,
}

impl PathRestrictions {
    pub fn new() -> Self {
        Self {
            allowed_paths: vec![
                "C:\\Windows".into(),
                "C:\\Program Files".into(),
                "HKLM\\SOFTWARE".into(),
            ],
            denied_paths: vec![
                "C:\\Windows\\System32\\config\\SAM".into(),  // Sensitive
                "HKLM\\SECURITY".into(),  // Sensitive
            ],
        }
    }

    pub fn check_path(&self, path: &str) -> bool {
        // Check deny list first
        for denied in &self.denied_paths {
            if path.starts_with(denied) {
                return false;
            }
        }

        // Check allow list (if non-empty)
        if !self.allowed_paths.is_empty() {
            for allowed in &self.allowed_paths {
                if path.starts_with(allowed) {
                    return true;
                }
            }
            return false;
        }

        true
    }
}

// Wrap VirtualFileSystem with path restrictions
pub struct AuthorizedVfs {
    inner: Box<dyn VirtualFileSystem>,
    restrictions: PathRestrictions,
}

impl AuthorizedVfs {
    pub fn new(inner: Box<dyn VirtualFileSystem>, restrictions: PathRestrictions) -> Self {
        Self { inner, restrictions }
    }
}

impl VirtualFileSystem for AuthorizedVfs {
    fn read_to_string(&mut self, path: &Path) -> ForensicResult<String> {
        if !self.restrictions.check_path(path.to_string_lossy().as_ref()) {
            return Err(ForensicError::access_denied(
                "path",
                format!("Access denied to path: {}", path.display())
            ));
        }
        self.inner.read_to_string(path)
    }

    fn read_all(&mut self, path: &Path) -> ForensicResult<Vec<u8>> {
        if !self.restrictions.check_path(path.to_string_lossy().as_ref()) {
            return Err(ForensicError::access_denied(
                "path",
                format!("Access denied to path: {}", path.display())
            ));
        }
        self.inner.read_all(path)
    }

    // ... delegate other methods similarly
}
```

## Recipe 6: Combining Policies

Compose multiple policies together.

```rust
use std::sync::Arc;
use forensic_rs::prelude::*;

// Policy that requires BOTH RBAC AND audit
pub struct AndPolicy<A: AccessPolicy, B: AccessPolicy> {
    first: A,
    second: B,
}

impl<A: AccessPolicy, B: AccessPolicy> AndPolicy<A, B> {
    pub fn new(first: A, second: B) -> Self {
        Self { first, second }
    }
}

impl<A: AccessPolicy + 'static, B: AccessPolicy + 'static> AccessPolicy for AndPolicy<A, B> {
    fn evaluate(&self, context: &AccessContext, request: &AccessRequest<'_>) -> AccessDecision {
        // Both policies must allow
        match self.first.evaluate(context, request) {
            AccessDecision::Allow => self.second.evaluate(context, request),
            AccessDecision::Deny => AccessDecision::Deny,
        }
    }
}

// Policy that requires EITHER RBAC OR IP-based
pub struct OrPolicy<A: AccessPolicy, B: AccessPolicy> {
    first: A,
    second: B,
}

impl<A: AccessPolicy, B: AccessPolicy> OrPolicy<A, B> {
    pub fn new(first: A, second: B) -> Self {
        Self { first, second }
    }
}

impl<A: AccessPolicy + 'static, B: AccessPolicy + 'static> AccessPolicy for OrPolicy<A, B> {
    fn evaluate(&self, context: &AccessContext, request: &AccessRequest<'_>) -> AccessDecision {
        // Either policy can allow
        match self.first.evaluate(context, request) {
            AccessDecision::Allow => AccessDecision::Allow,
            AccessDecision::Deny => self.second.evaluate(context, request),
        }
    }
}

// Usage
let rbac = RbacPolicy::new();
let audit = AuditedAccessPolicy::new(rbac, audit_sink);
let tenant = TenantIsolationPolicy::new(audit);

// This组合: tenant isolation + RBAC + audit
let policy = Arc::new(tenant);
```

## Summary: Access Control Patterns

| Pattern | Use Case |
|---------|----------|
| AllowAllPolicy | Development only |
| RBAC | Role-based permissions |
| Audit logging | Compliance requirements |
| Tenant isolation | Multi-tenant deployments |
| Source guards | Path-level restrictions |
| Policy composition | Complex requirements |
