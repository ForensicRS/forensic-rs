//! An investigation's evidence, as an ordered set of typed items rather
//! than the single `(vfs, registry)` pair [`TriageSources`] alone can
//! express.
//!
//! `TriageSources` answers "what can a parser read from *right now*" for
//! one pipeline run. It cannot say "this investigation has three hosts,
//! each with a triage collection, one of them also with a memory image" --
//! there is no place to put the second and third host, and no identity to
//! hang a coverage report or chain-of-custody statement off. [`EvidenceSet`]
//! is that container: an [`Investigation`] plus an ordered list of
//! [`EvidenceItem`]s, each of which lazily resolves into the
//! [`TriageSources`] view a pipeline run actually consumes.

use std::sync::Mutex;

use crate::err::ForensicResult;
use crate::field::Text;
use crate::investigation::Investigation;
use crate::pipeline::sources::TriageSources;
use crate::provenance::{Acquisition, SourceKey};
use crate::traits::format::MountKind;

/// Stable identifier for one [`EvidenceItem`] within an [`EvidenceSet`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EvidenceItemId(Text);

impl EvidenceItemId {
    pub fn new(id: impl Into<Text>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EvidenceItemId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<T: Into<Text>> From<T> for EvidenceItemId {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

/// A lazily-resolved, then cached, [`TriageSources`] view.
///
/// "Lazy" here means exactly what it means elsewhere in this crate's mount
/// machinery (see `crate::core::resolver::MountResolver`): resolution is
/// never eager, and cost is paid only for an item someone actually reads
/// from. The factory is a repeatable `Fn`, not a one-shot `FnOnce` — a
/// transient failure (a locked file, a not-yet-mounted network share) can
/// be retried on the next access instead of permanently poisoning the item.
struct LazyMount {
    factory: Box<dyn Fn() -> ForensicResult<TriageSources> + Send + Sync>,
    cached: Mutex<Option<TriageSources>>,
}

impl LazyMount {
    fn new(factory: impl Fn() -> ForensicResult<TriageSources> + Send + Sync + 'static) -> Self {
        Self {
            factory: Box::new(factory),
            cached: Mutex::new(None),
        }
    }

    fn resolve(&self) -> ForensicResult<TriageSources> {
        let mut cached = self.cached.lock().expect("LazyMount cache poisoned");
        if let Some(sources) = &*cached {
            return Ok(sources.clone());
        }
        let sources = (self.factory)()?;
        *cached = Some(sources.clone());
        Ok(sources)
    }

    fn is_resolved(&self) -> bool {
        self.cached.lock().expect("LazyMount cache poisoned").is_some()
    }
}

/// One piece of evidence within an investigation: a host's triage
/// collection, a full-disk image, a memory capture, a live registry
/// export.
///
/// `kind` reuses [`MountKind`] rather than introducing a parallel taxonomy
/// — it says what the item resolves *into* (a `FileSystem`, a `Registry`,
/// ...), the same vocabulary `crate::traits::format::FormatFactory`
/// already uses for exactly this question one level down, inside a single
/// container.
pub struct EvidenceItem {
    id: EvidenceItemId,
    kind: MountKind,
    source_key: SourceKey,
    acquisition: Option<Acquisition>,
    host_hint: Option<Text>,
    mount: LazyMount,
}

impl EvidenceItem {
    /// `sources_factory` is called on first access to [`Self::sources`] (or
    /// whichever thread gets there first, under a lock) and its result is
    /// cached for every subsequent call.
    pub fn new(
        id: impl Into<EvidenceItemId>,
        kind: MountKind,
        source_key: SourceKey,
        sources_factory: impl Fn() -> ForensicResult<TriageSources> + Send + Sync + 'static,
    ) -> Self {
        Self {
            id: id.into(),
            kind,
            source_key,
            acquisition: None,
            host_hint: None,
            mount: LazyMount::new(sources_factory),
        }
    }

    #[must_use]
    pub fn with_acquisition(mut self, acquisition: Acquisition) -> Self {
        self.acquisition = Some(acquisition);
        self
    }

    #[must_use]
    pub fn with_host_hint(mut self, host_hint: impl Into<Text>) -> Self {
        self.host_hint = Some(host_hint.into());
        self
    }

    pub fn id(&self) -> &EvidenceItemId {
        &self.id
    }

    pub fn kind(&self) -> MountKind {
        self.kind
    }

    pub fn source_key(&self) -> &SourceKey {
        &self.source_key
    }

    pub fn acquisition(&self) -> Option<Acquisition> {
        self.acquisition
    }

    pub fn host_hint(&self) -> Option<&str> {
        self.host_hint.as_deref()
    }

    /// Resolves this item into the [`TriageSources`] view a pipeline run
    /// consumes, caching the result after the first successful call.
    pub fn sources(&self) -> ForensicResult<TriageSources> {
        self.mount.resolve()
    }

    /// Whether [`Self::sources`] has already been resolved and cached.
    pub fn is_resolved(&self) -> bool {
        self.mount.is_resolved()
    }
}

/// An investigation's evidence: an [`Investigation`] identity plus an
/// ordered set of [`EvidenceItem`]s.
pub struct EvidenceSet {
    investigation: Investigation,
    items: Vec<EvidenceItem>,
}

impl EvidenceSet {
    pub fn new(investigation: Investigation) -> Self {
        Self {
            investigation,
            items: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_item(mut self, item: EvidenceItem) -> Self {
        self.items.push(item);
        self
    }

    pub fn add_item(&mut self, item: EvidenceItem) {
        self.items.push(item);
    }

    pub fn investigation(&self) -> &Investigation {
        &self.investigation
    }

    pub fn items(&self) -> &[EvidenceItem] {
        &self.items
    }

    pub fn item(&self, id: &EvidenceItemId) -> Option<&EvidenceItem> {
        self.items.iter().find(|item| item.id() == id)
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::vfs::FileSystem;
    use crate::utils::testing::InMemoryVirtualFileSystem;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn working_item(id: &'static str) -> EvidenceItem {
        EvidenceItem::new(id, MountKind::FileSystem, SourceKey::Synthetic(id.to_string()), || {
            let fs: Arc<dyn FileSystem> = Arc::new(InMemoryVirtualFileSystem::new());
            Ok(TriageSources::builder().vfs(fs).build())
        })
    }

    #[test]
    fn resolving_an_item_calls_the_factory_once_then_caches() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = Arc::clone(&calls);
        let item = EvidenceItem::new(
            "host1",
            MountKind::FileSystem,
            SourceKey::Synthetic("host1".to_string()),
            move || {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                let fs: Arc<dyn FileSystem> = Arc::new(InMemoryVirtualFileSystem::new());
                Ok(TriageSources::builder().vfs(fs).build())
            },
        );

        assert!(!item.is_resolved());
        item.sources().unwrap();
        item.sources().unwrap();
        item.sources().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(item.is_resolved());
    }

    #[test]
    fn a_failing_factory_can_be_retried_on_the_next_access() {
        let attempt = Arc::new(AtomicUsize::new(0));
        let attempt_clone = Arc::clone(&attempt);
        let item = EvidenceItem::new(
            "flaky",
            MountKind::FileSystem,
            SourceKey::Synthetic("flaky".to_string()),
            move || {
                let n = attempt_clone.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    Err(crate::err::ForensicError::other(
                        "test",
                        "transient failure".to_string(),
                    ))
                } else {
                    let fs: Arc<dyn FileSystem> = Arc::new(InMemoryVirtualFileSystem::new());
                    Ok(TriageSources::builder().vfs(fs).build())
                }
            },
        );

        assert!(item.sources().is_err());
        assert!(!item.is_resolved(), "a failed resolution must not be cached");
        assert!(item.sources().is_ok());
        assert!(item.is_resolved());
    }

    #[test]
    fn evidence_set_expresses_multiple_hosts_of_different_kinds() {
        let investigation = Investigation::new("case-42", "acme-corp");
        let set = EvidenceSet::new(investigation)
            .with_item(working_item("host1"))
            .with_item(working_item("host2"))
            .with_item(EvidenceItem::new(
                "host2-mem",
                MountKind::File,
                SourceKey::Synthetic("host2-mem".to_string()),
                || Err(crate::err::ForensicError::other("test", "not needed for this test".to_string())),
            ));

        assert_eq!(set.len(), 3);
        assert!(!set.is_empty());
        assert_eq!(set.investigation().id().as_str(), "case-42");
        assert_eq!(set.item(&EvidenceItemId::new("host1")).unwrap().kind(), MountKind::FileSystem);
        assert_eq!(set.item(&EvidenceItemId::new("host2-mem")).unwrap().kind(), MountKind::File);
        assert!(set.item(&EvidenceItemId::new("no-such-host")).is_none());
    }
}
