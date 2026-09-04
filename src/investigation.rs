//! An investigation's identity, deliberately kept small.
//!
//! [`Investigation`] is not case management — no status, no workflow, no
//! ticketing. Its job is to **seal provenance**: today's
//! [`crate::provenance`] model has no examiner, no opening time, and no
//! stable identity for the investigation a run belongs to, so it cannot by
//! itself produce a chain-of-custody statement even though that is
//! precisely what it exists for. Before this module, `case_id` was a bare
//! `String` in example tool schemas and there was no typed `Case`/
//! `Investigation` anywhere in the crate.

use std::collections::BTreeMap;

use crate::field::Text;
use crate::utils::time::ForensicTimestamp;

/// Stable identifier for one investigation, opaque outside this crate's
/// consumers beyond string equality/ordering.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InvestigationId(Text);

impl InvestigationId {
    pub fn new(id: impl Into<Text>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for InvestigationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<T: Into<Text>> From<T> for InvestigationId {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

/// Identifies the client/tenant an investigation belongs to (an MSSP
/// customer, a business unit). Kept opaque and small on purpose — the
/// crate never grows a `Client` struct with contacts, contracts, or
/// billing; what a tenant *means* is entirely a caller/downstream concern.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TenantId(Text);

impl TenantId {
    pub fn new(id: impl Into<Text>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<T: Into<Text>> From<T> for TenantId {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

/// The identity an investigation's evidence, records, and findings are
/// sealed against.
///
/// Deliberately opaque and small: no status, no assignee, no workflow, no
/// report body. Case management, ticketing, and reporting are out of
/// scope for this crate (see `AGENTS.md`'s scope boundaries) — this type
/// exists only to give provenance and coverage reporting a real identity
/// and examiner to attach to, instead of a bare string threaded through
/// tool schemas by convention.
#[derive(Debug, Clone)]
pub struct Investigation {
    id: InvestigationId,
    tenant: TenantId,
    examiner: Option<Text>,
    opened_at: Option<ForensicTimestamp>,
    metadata: BTreeMap<Text, Text>,
}

impl Investigation {
    pub fn new(id: impl Into<InvestigationId>, tenant: impl Into<TenantId>) -> Self {
        Self {
            id: id.into(),
            tenant: tenant.into(),
            examiner: None,
            opened_at: None,
            metadata: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_examiner(mut self, examiner: impl Into<Text>) -> Self {
        self.examiner = Some(examiner.into());
        self
    }

    #[must_use]
    pub fn with_opened_at(mut self, opened_at: ForensicTimestamp) -> Self {
        self.opened_at = Some(opened_at);
        self
    }

    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<Text>, value: impl Into<Text>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn id(&self) -> &InvestigationId {
        &self.id
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn examiner(&self) -> Option<&str> {
        self.examiner.as_deref()
    }

    pub fn opened_at(&self) -> Option<ForensicTimestamp> {
        self.opened_at
    }

    pub fn metadata(&self) -> &BTreeMap<Text, Text> {
        &self.metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_compare_by_underlying_text() {
        let a = InvestigationId::new("case-42");
        let b = InvestigationId::new("case-42");
        let c = InvestigationId::new("case-43");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.as_str(), "case-42");
        assert_eq!(a.to_string(), "case-42");
    }

    #[test]
    fn investigation_defaults_are_all_absent() {
        let investigation = Investigation::new("case-42", "acme-corp");
        assert_eq!(investigation.id().as_str(), "case-42");
        assert_eq!(investigation.tenant().as_str(), "acme-corp");
        assert!(investigation.examiner().is_none());
        assert!(investigation.opened_at().is_none());
        assert!(investigation.metadata().is_empty());
    }

    #[test]
    fn builder_methods_set_the_expected_fields() {
        let ts = ForensicTimestamp::from_unix_secs(1_700_000_000);
        let investigation = Investigation::new("case-42", "acme-corp")
            .with_examiner("j.doe")
            .with_opened_at(ts)
            .with_metadata("priority", "high");
        assert_eq!(investigation.examiner(), Some("j.doe"));
        assert_eq!(investigation.opened_at(), Some(ts));
        assert_eq!(
            investigation.metadata().get(&Text::Borrowed("priority")),
            Some(&Text::Borrowed("high"))
        );
    }

    #[test]
    fn investigation_id_accepts_str_or_string() {
        let from_str: InvestigationId = "case-42".into();
        let from_string: InvestigationId = "case-42".to_string().into();
        assert_eq!(from_str, from_string);
    }
}
