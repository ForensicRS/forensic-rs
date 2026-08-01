# Tutorial: Access Control

This chapter covers implementing access control policies for multi-tenant forensic MCP servers.

## Why Access Control?

In production deployments, you need to:

- **Authenticate users** - Verify who is making the request
- **Authorize actions** - Determine what they're allowed to do
- **Audit operations** - Log all access decisions for compliance
- **Isolate tenants** - Ensure one tenant cannot access another's data

## AccessContext

The `AccessContext` represents an authenticated principal:

```rust
pub struct AccessContext {
    pub principal: Text,           // Who (e.g., "analyst-42")
    pub tenant: Text,              // Which organization (e.g., "acme-corp")
    pub session: Option<Text>,     // Session identifier
    pub roles: Vec<Text>,          // Assigned roles
    pub metadata: HashMap<Text, CapabilityValue>,  // Extra data
}

impl AccessContext {
    pub fn new(principal: &str, tenant: &str) -> Self { ... }
    pub fn with_session(mut self, session: &str) -> Self { ... }
    pub fn with_role(mut self, role: &str) -> Self { ... }
    pub fn with_metadata(mut self, key: &str, value: CapabilityValue) -> Self { ... }
}
```

## AccessPolicy Trait

```rust
pub trait AccessPolicy: Send + Sync {
    fn evaluate(
        &self,
        context: &AccessContext,
        request: &AccessRequest<'_>,
    ) -> AccessDecision;
}

pub enum AccessDecision {
    Allow,
    Deny,
}

pub enum AccessRequest<'_> {
    DiscoverTool { tool_id: &str },
    InvokeTool { tool_id: &str },
    DiscoverResourceProvider { provider_id: &str },
    ReadResource { provider_id: &str, path: &str },
    // ... other access targets
}
```

## Built-in Policies

### AllowAllPolicy

Trust any principal (development only):

```rust
let policy = Arc::new(AllowAllPolicy::new());
```

**Never use in production with untrusted clients.**

### DenyAllPolicy

Deny all operations:

```rust
let policy = Arc::new(DenyAllPolicy::new());
```

### AuditedAccessPolicy

Wrap any policy to log all decisions:

```rust
use forensic_rs::prelude::*;

struct StderrAuditSink;

impl AccessAuditSink for StderrAuditSink {
    fn record(&self, event: &AccessAuditEvent) {
        eprintln!(
            "[AUDIT] {} {} {:?} -> {:?}",
            event.context.principal,
            event.context.tenant,
            event.kind,
            event.decision
        );
    }
}

let base_policy = Arc::new(MyCustomPolicy::new());
let audit_sink = Arc::new(StderrAuditSink);
let policy = Arc::new(AuditedAccessPolicy::new(base_policy, audit_sink));
```

## Implementing a Custom Policy

### Role-Based Access Control (RBAC)

```rust
// src/auth/rbac_policy.rs

use std::collections::BTreeMap;
use forensic_rs::prelude::*;

pub struct RoleBasedPolicy {
    // Maps roles to allowed tool IDs
    role_permissions: BTreeMap<Text, Vec<Text>>,
    // Maps roles to allowed provider/path patterns
    resource_permissions: BTreeMap<Text, Vec<ResourcePattern>>,
}

#[derive(Clone)]
struct ResourcePattern {
    provider_id: String,
    path_prefix: String,
}

impl RoleBasedPolicy {
    pub fn new() -> Self {
        let mut policy = Self {
            role_permissions: BTreeMap::new(),
            resource_permissions: BTreeMap::new(),
        };

        // Define role permissions
        policy.role_permissions.insert(
            Text::Borrowed("analyst"),
            vec![
                Text::Borrowed("case.summary"),
                Text::Borrowed("registry.autoruns"),
                Text::Borrowed("prefetch.analyze"),
                Text::Borrowed("security.logon_events"),
            ],
        );

        policy.role_permissions.insert(
            Text::Borrowed("admin"),
            vec![
                Text::Borrowed("case.*"),  // Wildcard pattern
            ],
        );

        // Define resource permissions
        policy.resource_permissions.insert(
            Text::Borrowed("analyst"),
            vec![
                ResourcePattern {
                    provider_id: "registry".into(),
                    path_prefix: "HKLM\\SOFTWARE".into(),
                },
                ResourcePattern {
                    provider_id: "filesystem".into(),
                    path_prefix: "C:\\Windows".into(),
                },
            ],
        );

        policy
    }

    fn tool_allowed(&self, context: &AccessContext, tool_id: &str) -> bool {
        for role in &context.roles {
            if let Some(permissions) = self.role_permissions.get(role) {
                for pattern in permissions {
                    if matches_pattern(pattern, tool_id) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn resource_allowed(&self, context: &AccessContext, provider_id: &str, path: &str) -> bool {
        for role in &context.roles {
            if let Some(patterns) = self.resource_permissions.get(role) {
                for pattern in patterns {
                    if pattern.provider_id == provider_id
                        && path.starts_with(&pattern.path_prefix)
                    {
                        return true;
                    }
                }
            }
        }
        false
    }
}

fn matches_pattern(pattern: &Text, value: &str) -> bool {
    if pattern.as_ref().contains('*') {
        let prefix = pattern.as_ref().trim_end_matches('*');
        value.starts_with(prefix)
    } else {
        pattern.as_ref() == value
    }
}

impl AccessPolicy for RoleBasedPolicy {
    fn evaluate(
        &self,
        context: &AccessContext,
        request: &AccessRequest<'_>,
    ) -> AccessDecision {
        match request {
            AccessRequest::DiscoverTool { tool_id } |
            AccessRequest::InvokeTool { tool_id } => {
                if self.tool_allowed(context, tool_id) {
                    AccessDecision::Allow
                } else {
                    AccessDecision::Deny
                }
            }
            AccessRequest::ReadResource { provider_id, path } => {
                if self.resource_allowed(context, provider_id, path) {
                    AccessDecision::Allow
                } else {
                    AccessDecision::Deny
                }
            }
            _ => AccessDecision::Allow,  // Allow other operations
        }
    }
}
```

### Audit Event Structure

```rust
pub struct AccessAuditEvent {
    pub context: AccessContext,
    pub kind: AccessKind,
    pub capability_id: String,
    pub target: Option<String>,
    pub decision: AccessDecision,
}

pub enum AccessKind {
    DiscoverTool,
    InvokeTool,
    DiscoverResourceProvider,
    ReadResource,
    // ...
}
```

## Multi-Tenant Isolation

Ensure tenants cannot access each other's data:

```rust
pub struct TenantIsolationPolicy<P: AccessPolicy> {
    inner: P,
}

impl<P: AccessPolicy> TenantIsolationPolicy<P> {
    pub fn new(policy: P) -> Self {
        Self { inner: policy }
    }
}

impl<P: AccessPolicy> AccessPolicy for TenantIsolationPolicy<P> {
    fn evaluate(
        &self,
        context: &AccessContext,
        request: &AccessRequest<'_>,
    ) -> AccessDecision {
        // First, evaluate the inner policy
        let decision = self.inner.evaluate(context, request);

        // For resource access, verify tenant ownership
        if let AccessRequest::ReadResource { path, .. } = request {
            if !path.contains(&context.tenant.to_string()) {
                return AccessDecision::Deny;  // Tenant can only access their own data
            }
        }

        decision
    }
}
```

## Using Policies with the Registry

```rust
fn main() {
    // Create policy
    let policy = Arc::new(RoleBasedPolicy::new());
    let audit = Arc::new(StderrAuditSink);
    let policy = Arc::new(AuditedAccessPolicy::new(policy, audit));

    // Create registry with policy
    let mut registry = CapabilityRegistry::new(policy);
    registry.register_tool(Arc::new(CaseSummaryTool::new())).unwrap();
    registry.register_tool(Arc::new(AutorunTool::new())).unwrap();
    registry.register_tool(Arc::new(PrefetchTool::new())).unwrap();
    registry.register_tool(Arc::new(LogonEventsTool::new())).unwrap();

    // Simulate authenticated request
    let access = AccessContext::new("analyst-42", "acme-corp")
        .with_role("analyst")
        .with_session("session-123");

    let scoped = registry.scope(access);

    // List tools - only authorized tools visible
    for tool in scoped.list_tools() {
        println!("Visible tool: {}", tool.id);
    }
}
```

## Access Control Checklist

When implementing access control:

1. **Always authenticate** before creating AccessContext
2. **Use AllowAllPolicy only** for trusted local development
3. **Wrap with AuditedAccessPolicy** in production
4. **Implement least privilege** - grant minimum necessary permissions
5. **Test tenant isolation** - verify cross-tenant access is impossible
6. **Log all denials** - security-relevant events must be audited

## Next Steps

- [Deployment](./08_deployment.md) - Build and deploy your MCP server
- See [MCP_INTEGRATION.md:393-445](../../MCP_INTEGRATION.md) for complete authorization details
