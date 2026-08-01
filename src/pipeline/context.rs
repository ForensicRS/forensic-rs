use std::collections::BTreeMap;

use crate::{
    artifact::Artifact,
    context::{initialize_context, ForensicContext},
    field::{Field, Ip, Text},
    utils::time::ForensicTimestamp,
};

/// Shared context for a triage pipeline run.
///
/// Wraps the thread-local `ForensicContext` (host, tenant, artifact metadata)
/// and adds an extensible key-value store that enrichers can read/write and
/// analyzers can read during pipeline execution.
pub struct TriageContext {
    forensic: ForensicContext,
    shared: BTreeMap<Text, Field>,
}

impl TriageContext {
    pub fn new(host: impl Into<String>, tenant: impl Into<String>) -> Self {
        Self {
            forensic: ForensicContext {
                host: host.into(),
                tenant: tenant.into(),
                artifact: Artifact::Unknown,
                metadata: BTreeMap::new(),
            },
            shared: BTreeMap::new(),
        }
    }

    pub fn from_forensic_context(ctx: ForensicContext) -> Self {
        Self {
            forensic: ctx,
            shared: BTreeMap::new(),
        }
    }

    /// Access the underlying `ForensicContext`.
    pub fn forensic_context(&self) -> &ForensicContext {
        &self.forensic
    }

    /// Read a value from the shared pipeline state.
    pub fn get(&self, key: &str) -> Option<&Field> {
        self.shared.get(key)
    }

    /// Write a value to the shared pipeline state.
    pub fn set(&mut self, key: Text, value: Field) {
        self.shared.insert(key, value);
    }

    /// Remove a value from the shared pipeline state.
    pub fn remove(&mut self, key: &str) -> Option<Field> {
        self.shared.remove(key)
    }

    /// Check if a key exists in the shared state.
    pub fn contains_key(&self, key: &str) -> bool {
        self.shared.contains_key(key)
    }

    /// Ergonomic setter: insert a value with `Into<Field>` conversion.
    pub fn set_into(&mut self, key: &'static str, value: impl Into<Field>) {
        self.shared.insert(Text::Borrowed(key), value.into());
    }

    /// Iterate over all shared state entries.
    pub fn iter(&self) -> impl Iterator<Item = (&Text, &Field)> {
        self.shared.iter()
    }

    /// Get a shared state value as `&str`.
    pub fn get_str(&self, key: &str) -> Option<&str> {
        match self.shared.get(key)? {
            Field::Text(v) => Some(v),
            _ => None,
        }
    }

    /// Get a shared state value as `u64`.
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        match self.shared.get(key)? {
            Field::U64(v) => Some(*v),
            Field::I64(v) => Some(*v as u64),
            _ => None,
        }
    }

    /// Get a shared state value as `i64`.
    pub fn get_i64(&self, key: &str) -> Option<i64> {
        match self.shared.get(key)? {
            Field::I64(v) => Some(*v),
            Field::U64(v) => Some(*v as i64),
            _ => None,
        }
    }

    /// Get a shared state value as `&ForensicTimestamp`.
    pub fn get_date(&self, key: &str) -> Option<&ForensicTimestamp> {
        match self.shared.get(key)? {
            Field::Date(v) => Some(v),
            _ => None,
        }
    }

    /// Get a shared state value as `Ip`.
    pub fn get_ip(&self, key: &str) -> Option<Ip> {
        match self.shared.get(key)? {
            Field::Ip(v) => Some(*v),
            _ => None,
        }
    }

    /// Set the artifact type currently being processed.
    pub fn set_artifact(&mut self, artifact: Artifact) {
        self.forensic.artifact = artifact;
    }

    /// Get the current host name.
    pub fn host(&self) -> &str {
        &self.forensic.host
    }

    /// Get the current tenant.
    pub fn tenant(&self) -> &str {
        &self.forensic.tenant
    }

    /// Install this context into the thread-local `ForensicContext`,
    /// so that `ForensicData::default()` and logging macros pick it up.
    pub(crate) fn install(&self) {
        initialize_context(self.forensic.clone());
    }
}

impl Default for TriageContext {
    fn default() -> Self {
        Self {
            forensic: ForensicContext::default(),
            shared: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_context_with_host_and_tenant() {
        let ctx = TriageContext::new("WORKSTATION01", "ACME-Corp");
        assert_eq!(ctx.host(), "WORKSTATION01");
        assert_eq!(ctx.tenant(), "ACME-Corp");
    }

    #[test]
    fn should_read_write_shared_state() {
        let mut ctx = TriageContext::default();
        ctx.set(
            Text::Borrowed("timezone"),
            Field::Text(Text::Borrowed("UTC")),
        );
        assert!(ctx.contains_key("timezone"));
        match ctx.get("timezone") {
            Some(Field::Text(v)) => assert_eq!(v.as_ref(), "UTC"),
            other => panic!("expected Field::Text(\"UTC\"), got {:?}", other),
        }
        ctx.remove("timezone");
        assert!(!ctx.contains_key("timezone"));
    }

    #[test]
    fn should_install_forensic_context() {
        let ctx = TriageContext::new("SERVER01", "TenantX");
        ctx.install();
        let fc = crate::context::context();
        assert_eq!(fc.host, "SERVER01");
        assert_eq!(fc.tenant, "TenantX");
    }
}
