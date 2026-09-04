//! Recursive, budget-enforcing resolution of nested evidence containers.
//!
//! [`MountResolver`] is the single place that drives
//! [`FormatFactory::probe`]/[`FormatFactory::mount`] across every registered
//! factory, picks a winner deterministically when more than one claims the
//! same bytes, caches by [`EvidenceLocator`] (not by string path -- the bug
//! this replaces: a flat `"a.zip/[mount]/b.zip/[mount]/x"` cache key cannot
//! represent more than one level of nesting), enforces [`Limits`] shared
//! across the whole resolution graph, and interns content so the same bytes
//! reached through two different chains resolve to one entry.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::core::limits::{LimitExceeded, Limits, MemorySpillStore, SpillStore};
use crate::core::locator::EvidenceLocator;
use crate::err::{ForensicError, ForensicResult};
use crate::traits::digest::{ContentAddress, Digest};
use crate::traits::format::{FormatFactory, MountContext, MountKind, Mounted, ProbeScore};
use crate::traits::vfs::{FileSystem, VirtualFile};

/// Resolves one containment/interpretation/embedding hop at a time,
/// recursing is the caller's responsibility (each `resolve` call is one
/// hop; a parser or a resource server drives the chain).
///
/// `Send + Sync` -- shared across parallel pipeline workers via
/// `TriageSources`, the same way `FileSystem`/`Registry` already are.
pub struct MountResolver {
    factories: Vec<Arc<dyn FormatFactory>>,
    limits: Limits,
    spill: Arc<dyn SpillStore>,
    digest_factory: Option<Arc<dyn Fn() -> Box<dyn Digest> + Send + Sync>>,
    cache: Mutex<BTreeMap<EvidenceLocator, Mounted>>,
    visited_content: Mutex<BTreeSet<ContentAddress>>,
    root_bytes: Mutex<Option<u64>>,
    expanded_bytes: AtomicU64,
}

impl MountResolver {
    pub fn builder() -> MountResolverBuilder {
        MountResolverBuilder::new()
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Number of hops resolved and cached so far.
    pub fn cache_len(&self) -> usize {
        self.cache.lock().expect("MountResolver cache poisoned").len()
    }

    /// Registered factories that could produce `want` (or all of them, if
    /// `want` is `None`). Exposed so a caller (e.g.
    /// `ParseContext::resolve`) can check "is this even supported" without
    /// opening a file.
    pub fn supports(&self, want: MountKind) -> bool {
        self.factories.iter().any(|f| f.yields() == want)
    }

    /// Whether any registered factory claims `file` as `want` (or as
    /// anything, if `want` is `None`) -- without mounting, caching, or
    /// charging any resource budget. For a lightweight "does this look
    /// like a container" hint on content already read for another reason;
    /// mounting itself stays strictly on-demand, only when a caller
    /// actually asks to read inside it via [`MountResolver::resolve`].
    pub fn probe_only(
        &self,
        fs: &Arc<dyn FileSystem>,
        locator: &EvidenceLocator,
        file: &mut dyn VirtualFile,
        want: Option<MountKind>,
        cancellation: &crate::bridge::CancellationToken,
    ) -> ForensicResult<bool> {
        let ctx = MountContext::new(
            fs,
            locator,
            &self.limits,
            locator.depth(),
            self.spill.as_ref(),
            None,
            cancellation,
        );
        for factory in &self.factories {
            if let Some(want) = want {
                if factory.yields() != want {
                    continue;
                }
            }
            if factory.probe(file, &ctx)? != ProbeScore::No {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Resolve one hop: probe every registered factory against `file`
    /// (optionally restricted to those yielding `want`), deterministically
    /// pick a winner, mount, cache by `locator`, and enforce budgets.
    ///
    /// A cache hit short-circuits everything below, including budget
    /// checks -- the whole point of caching by `EvidenceLocator` is that a
    /// container mounted once is mounted once, however many times its
    /// contents are subsequently read.
    pub fn resolve(
        &self,
        fs: &Arc<dyn FileSystem>,
        locator: &EvidenceLocator,
        file: Box<dyn VirtualFile>,
        want: Option<MountKind>,
        cancellation: &crate::bridge::CancellationToken,
    ) -> ForensicResult<Mounted> {
        if let Some(cached) = self
            .cache
            .lock()
            .expect("MountResolver cache poisoned")
            .get(locator)
        {
            return Ok(cached.clone());
        }
        if cancellation.is_cancelled() {
            return Err(ForensicError::other(
                "MountResolver",
                "cancelled".to_string(),
            ));
        }

        let depth = locator.depth();
        if depth > self.limits.max_nesting_depth {
            return Err(ForensicError::other(
                "MountResolver",
                LimitExceeded::NestingDepth {
                    at: depth,
                    max: self.limits.max_nesting_depth,
                }
                .to_string(),
            ));
        }

        let mut working_file = file;
        let size = working_file
            .metadata()
            .map(|meta| meta.size)
            .unwrap_or(0);

        let would_total = self.expanded_bytes.load(Ordering::Relaxed) + size;
        if would_total > self.limits.max_expanded_bytes {
            return Err(ForensicError::other(
                "MountResolver",
                LimitExceeded::ExpandedBytes {
                    would_total,
                    max: self.limits.max_expanded_bytes,
                }
                .to_string(),
            ));
        }
        let root = {
            let mut guard = self.root_bytes.lock().expect("MountResolver root poisoned");
            *guard.get_or_insert(size.max(1))
        };
        let ratio = would_total / root;
        if ratio > self.limits.max_expansion_ratio as u64 {
            return Err(ForensicError::other(
                "MountResolver",
                LimitExceeded::ExpansionRatio {
                    observed: ratio.min(u32::MAX as u64) as u32,
                    max: self.limits.max_expansion_ratio,
                }
                .to_string(),
            ));
        }

        let ctx = MountContext::new(
            fs,
            locator,
            &self.limits,
            depth,
            self.spill.as_ref(),
            self.digest_factory
                .as_deref()
                .map(|f| f as &(dyn Fn() -> Box<dyn Digest> + Send + Sync)),
            cancellation,
        );

        // Content interning: only pay the cost of a full read when a
        // digest is actually configured. This both dedupes the same bytes
        // reached through two chains and catches a cycle (a container that
        // contains itself) before it can recurse unboundedly.
        if let Some(make_digest) = &self.digest_factory {
            let materialized = self.spill.spill(&mut *working_file, Some(size))?;
            working_file = materialized;
            let mut buf = Vec::new();
            working_file
                .read_to_end(&mut buf)
                .map_err(|e| ForensicError::other("MountResolver", e.to_string()))?;
            working_file
                .seek(SeekFrom::Start(0))
                .map_err(|e| ForensicError::other("MountResolver", e.to_string()))?;
            let mut digest = make_digest();
            digest.update(&buf);
            let address = digest.finish();
            let mut visited = self
                .visited_content
                .lock()
                .expect("MountResolver visited-content poisoned");
            if !visited.insert(address) {
                return Err(ForensicError::other(
                    "MountResolver",
                    format!("cycle or duplicate content detected at {locator}"),
                ));
            }
        }

        let mut best: Option<(ProbeScore, &Arc<dyn FormatFactory>)> = None;
        for factory in &self.factories {
            if let Some(want) = want {
                if factory.yields() != want {
                    continue;
                }
            }
            let score = factory.probe(working_file.as_mut(), &ctx)?;
            if score == ProbeScore::No {
                continue;
            }
            let better = match &best {
                None => true,
                Some((best_score, best_factory)) => {
                    score > *best_score
                        || (score == *best_score && factory.name() < best_factory.name())
                }
            };
            if better {
                best = Some((score, factory));
            }
        }

        let Some((_, factory)) = best else {
            return Err(ForensicError::other(
                "MountResolver",
                format!("no registered format factory claims {locator}"),
            ));
        };

        let mounted = factory.mount(working_file, &ctx)?;
        self.expanded_bytes.fetch_add(size, Ordering::Relaxed);
        self.cache
            .lock()
            .expect("MountResolver cache poisoned")
            .insert(locator.clone(), mounted.clone());
        Ok(mounted)
    }
}

#[derive(Default)]
pub struct MountResolverBuilder {
    factories: Vec<Arc<dyn FormatFactory>>,
    limits: Limits,
    spill: Option<Arc<dyn SpillStore>>,
    digest_factory: Option<Arc<dyn Fn() -> Box<dyn Digest> + Send + Sync>>,
}

impl MountResolverBuilder {
    pub fn new() -> Self {
        Self {
            factories: Vec::new(),
            limits: Limits::default(),
            spill: None,
            digest_factory: None,
        }
    }

    #[must_use]
    pub fn factory(mut self, factory: Arc<dyn FormatFactory>) -> Self {
        self.factories.push(factory);
        self
    }

    #[must_use]
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    #[must_use]
    pub fn spill_store(mut self, spill: Arc<dyn SpillStore>) -> Self {
        self.spill = Some(spill);
        self
    }

    /// Enables content interning (dedup across chains, cycle detection) by
    /// supplying a factory for fresh [`Digest`] instances. Without this,
    /// the resolver still enforces depth/byte/ratio budgets but falls back
    /// to depth + byte budget only for cycle avoidance.
    #[must_use]
    pub fn digest(mut self, make: impl Fn() -> Box<dyn Digest> + Send + Sync + 'static) -> Self {
        self.digest_factory = Some(Arc::new(make));
        self
    }

    pub fn build(self) -> MountResolver {
        let limits = self.limits;
        MountResolver {
            factories: self.factories,
            limits,
            spill: self
                .spill
                .unwrap_or_else(|| Arc::new(MemorySpillStore::new(limits.materialize_in_memory_limit))),
            digest_factory: self.digest_factory,
            cache: Mutex::new(BTreeMap::new()),
            visited_content: Mutex::new(BTreeSet::new()),
            root_bytes: Mutex::new(None),
            expanded_bytes: AtomicU64::new(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::CancellationToken;
    use crate::core::locator::LocatorSegment;
    use crate::core::path::FPathBuf;
    use crate::err::ForensicResult as Result_;
    use crate::traits::digest::DigestAlgorithm;
    use crate::utils::testing::{InMemoryVirtualFileSystem, TestingRegistry};
    use std::io::Cursor;

    fn open(text: &'static str) -> Box<dyn VirtualFile> {
        struct MemFile(Cursor<Vec<u8>>);
        impl Read for MemFile {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.0.read(buf)
            }
        }
        impl Seek for MemFile {
            fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
                self.0.seek(pos)
            }
        }
        impl VirtualFile for MemFile {
            fn metadata(&self) -> Result_<crate::traits::vfs::VMetadata> {
                Ok(crate::traits::vfs::VMetadata {
                    file_type: crate::traits::vfs::VFileType::File,
                    size: self.0.get_ref().len() as u64,
                    allocated_size: None,
                    times: crate::traits::vfs::MacbTimes::default(),
                    id: None,
                    attributes: crate::traits::vfs::FileAttributes::empty(),
                })
            }
        }
        Box::new(MemFile(Cursor::new(text.as_bytes().to_vec())))
    }

    /// Claims any bytes starting with "REG", mounts a fixed empty registry.
    struct RegistryFactory;
    impl FormatFactory for RegistryFactory {
        fn name(&self) -> &'static str {
            "test-registry"
        }
        fn yields(&self) -> MountKind {
            MountKind::Registry
        }
        fn probe(&self, file: &mut dyn VirtualFile, _ctx: &MountContext<'_>) -> Result_<ProbeScore> {
            let start = file.stream_position().unwrap_or(0);
            let mut magic = [0u8; 3];
            let matched = file.read_exact(&mut magic).is_ok() && &magic == b"REG";
            let _ = file.seek(SeekFrom::Start(start));
            Ok(if matched { ProbeScore::Strong } else { ProbeScore::No })
        }
        fn mount(&self, _file: Box<dyn VirtualFile>, _ctx: &MountContext<'_>) -> Result_<Mounted> {
            Ok(Mounted::Registry(Arc::new(TestingRegistry::empty())))
        }
    }

    fn fs() -> Arc<dyn FileSystem> {
        Arc::new(InMemoryVirtualFileSystem::new())
    }

    fn locator_at(name: &str) -> EvidenceLocator {
        EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from(name)))
    }

    #[test]
    fn resolves_and_caches_by_locator() {
        let resolver = MountResolver::builder().factory(Arc::new(RegistryFactory)).build();
        let fs = fs();
        let locator = locator_at("hive.dat");
        let cancel = CancellationToken::new();
        let first = resolver
            .resolve(&fs, &locator, open("REG-hive-bytes"), None, &cancel)
            .unwrap();
        assert!(first.as_registry().is_some());
        assert_eq!(resolver.cache_len(), 1);
        // Second resolve at the same locator is a cache hit -- proven by
        // not needing a real file (an empty Cursor would fail the probe).
        let second = resolver
            .resolve(&fs, &locator, open(""), None, &cancel)
            .unwrap();
        assert!(second.as_registry().is_some());
        assert_eq!(resolver.cache_len(), 1);
    }

    #[test]
    fn unsupported_bytes_report_no_factory_claims_them() {
        let resolver = MountResolver::builder().factory(Arc::new(RegistryFactory)).build();
        let fs = fs();
        let cancel = CancellationToken::new();
        let result = resolver.resolve(&fs, &locator_at("plain.txt"), open("not a hive"), None, &cancel);
        assert!(result.is_err());
    }

    #[test]
    fn nesting_depth_over_limit_is_refused() {
        let resolver = MountResolver::builder()
            .factory(Arc::new(RegistryFactory))
            .limits(Limits {
                max_nesting_depth: 1,
                ..Limits::default()
            })
            .build();
        let fs = fs();
        let mut locator = EvidenceLocator::root();
        for i in 0..3 {
            locator = locator.push(LocatorSegment::Path(FPathBuf::from(format!("layer{i}"))));
        }
        let cancel = CancellationToken::new();
        let result = resolver.resolve(&fs, &locator, open("REG-x"), None, &cancel);
        assert!(result.is_err());
    }

    #[test]
    fn expanded_bytes_budget_is_enforced_across_calls() {
        let resolver = MountResolver::builder()
            .factory(Arc::new(RegistryFactory))
            .limits(Limits {
                max_expanded_bytes: 10,
                max_expansion_ratio: u32::MAX,
                ..Limits::default()
            })
            .build();
        let fs = fs();
        let cancel = CancellationToken::new();
        // First 9-byte mount fits under the 10-byte total budget.
        resolver
            .resolve(&fs, &locator_at("a"), open("REG123456"), None, &cancel)
            .unwrap();
        // A second, distinct locator pushes the running total over budget.
        let result = resolver.resolve(&fs, &locator_at("b"), open("REG123456"), None, &cancel);
        assert!(result.is_err());
    }

    #[test]
    fn digest_enabled_resolver_detects_duplicate_content_as_a_cycle() {
        let resolver = MountResolver::builder()
            .factory(Arc::new(RegistryFactory))
            .digest(|| Box::new(FakeDigest::default()))
            .build();
        let fs = fs();
        let cancel = CancellationToken::new();
        resolver
            .resolve(&fs, &locator_at("a"), open("REG-same-bytes"), None, &cancel)
            .unwrap();
        // Same content bytes reached through a different locator: the
        // second call is not a cache hit (different key) but must still be
        // rejected as previously-visited content.
        let result = resolver.resolve(&fs, &locator_at("b"), open("REG-same-bytes"), None, &cancel);
        assert!(result.is_err());
    }

    #[derive(Default)]
    struct FakeDigest {
        acc: u64,
    }
    impl Digest for FakeDigest {
        fn algorithm(&self) -> DigestAlgorithm {
            DigestAlgorithm::Other("fake-test-digest")
        }
        fn update(&mut self, bytes: &[u8]) {
            for &b in bytes {
                self.acc = self.acc.wrapping_mul(31).wrapping_add(b as u64);
            }
        }
        fn finish(self: Box<Self>) -> ContentAddress {
            ContentAddress::new(DigestAlgorithm::Other("fake-test-digest"), self.acc.to_le_bytes().to_vec())
        }
    }

    #[test]
    fn cancellation_is_honoured_before_any_probing() {
        let resolver = MountResolver::builder().factory(Arc::new(RegistryFactory)).build();
        let fs = fs();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let result = resolver.resolve(&fs, &locator_at("x"), open("REG-anything"), None, &cancel);
        assert!(result.is_err());
    }

    #[test]
    fn want_filter_skips_factories_yielding_a_different_kind() {
        let resolver = MountResolver::builder().factory(Arc::new(RegistryFactory)).build();
        let fs = fs();
        let cancel = CancellationToken::new();
        let result = resolver.resolve(
            &fs,
            &locator_at("x"),
            open("REG-anything"),
            Some(MountKind::Database),
            &cancel,
        );
        assert!(result.is_err());
    }

    #[test]
    fn probe_only_reports_a_match_without_mounting_or_caching() {
        let resolver = MountResolver::builder().factory(Arc::new(RegistryFactory)).build();
        let fs = fs();
        let cancel = CancellationToken::new();
        let mut file = open("REG-anything");
        let matched = resolver
            .probe_only(&fs, &locator_at("x"), file.as_mut(), None, &cancel)
            .unwrap();
        assert!(matched);
        assert_eq!(resolver.cache_len(), 0);
    }

    #[test]
    fn probe_only_reports_no_match_for_unrecognized_bytes() {
        let resolver = MountResolver::builder().factory(Arc::new(RegistryFactory)).build();
        let fs = fs();
        let cancel = CancellationToken::new();
        let mut file = open("not a hive");
        let matched = resolver
            .probe_only(&fs, &locator_at("x"), file.as_mut(), None, &cancel)
            .unwrap();
        assert!(!matched);
    }

    #[test]
    fn supports_reports_registered_mount_kinds() {
        let resolver = MountResolver::builder().factory(Arc::new(RegistryFactory)).build();
        assert!(resolver.supports(MountKind::Registry));
        assert!(!resolver.supports(MountKind::Database));
    }
}
