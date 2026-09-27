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
//!
//! The mount cache is **bytes-bounded and evictable**
//! ([`Limits::max_resident_bytes`]), not an ever-growing map -- a caller that walks a whole
//! evidence tree and resolves thousands of containers does not retain every one of them in
//! memory forever. Whether a mounted locator is still *resident* is deliberately kept separate
//! from whether it has been *charged* against `Limits::max_expanded_bytes`/
//! `Limits::max_expansion_ratio`/content-cycle detection: the latter is permanent for the
//! resolver's lifetime, so evicting and later re-mounting the same locator never re-charges its
//! budget or re-trips cycle detection against its own recurring bytes. Budget outcomes are a
//! function of the evidence resolved, never of cache pressure.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::core::limits::{LimitExceeded, Limits, MemorySpillStore, SpillStore};
use crate::core::locator::{EvidenceLocator, LocatorSegment};
use crate::err::{ForensicError, ForensicResult};
use crate::traits::digest::{ContentAddress, Digest};
use crate::traits::format::{FormatFactory, HopCost, MountContext, MountKind, Mounted, ProbeScore};
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
    /// Bytes-bounded, evictable: holds whole mounted containers. Distinct from `charged` below
    /// -- a locator can be evicted from here and later re-mounted without being charged again.
    resident: Mutex<ResidentCache>,
    /// Every locator ever successfully mounted by this resolver, permanent for the resolver's
    /// whole lifetime. Small (one `EvidenceLocator` per hop ever mounted, not per byte), and
    /// what makes eviction from `resident` safe: it decouples "has this been charged against
    /// `expanded_bytes`/`visited_content`" from "is it currently resident". Without this split,
    /// adding eviction to `resident` alone would make budget outcomes -- whether a run hits
    /// `max_expanded_bytes`, or spuriously re-triggers the "cycle or duplicate content" check on
    /// a legitimate re-mount -- depend on cache pressure instead of on the evidence, which is
    /// non-deterministic across otherwise-identical runs.
    charged: Mutex<BTreeSet<EvidenceLocator>>,
    visited_content: Mutex<BTreeSet<ContentAddress>>,
    /// The expansion-ratio denominator, keyed by each resolution chain's own root (its
    /// locator's first segment) rather than one process-wide value. Without this, walking many
    /// evidence roots in sequence pins the ratio's denominator to whichever root happened to
    /// resolve first -- typically small -- and every larger root afterward is refused for a
    /// reason unrelated to its own bytes (see the `expansion_ratio_is_scoped_per_root` test).
    root_bytes: Mutex<BTreeMap<Option<LocatorSegment>, u64>>,
    expanded_bytes: AtomicU64,
}

/// A small hand-rolled least-recently-used cache, bounded by total resident bytes rather than
/// entry count (entry count says nothing about memory; a handful of large mounts can dwarf
/// thousands of tiny ones). No external LRU dependency -- this crate stays deliberately
/// dependency-light, and the entry count in flight here (bounded by
/// `max_resident_bytes` / typical mount size, realistically dozens to low hundreds) makes the
/// linear eviction scan below cheap relative to the cost of a mount itself.
struct ResidentCache {
    entries: BTreeMap<EvidenceLocator, ResidentEntry>,
    total_bytes: u64,
    max_bytes: u64,
    next_tick: u64,
}

struct ResidentEntry {
    mounted: Mounted,
    weight: u64,
    last_used: u64,
}

impl ResidentCache {
    fn new(max_bytes: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            total_bytes: 0,
            max_bytes,
            next_tick: 0,
        }
    }

    /// Reads a still-resident entry and marks it most-recently-used. `None` means either never
    /// mounted, or evicted -- the caller can't tell which from this alone, and doesn't need to:
    /// both are handled the same way, by falling through to `MountResolver::charged`.
    fn get(&mut self, locator: &EvidenceLocator) -> Option<Mounted> {
        let tick = self.next_tick;
        self.next_tick += 1;
        let entry = self.entries.get_mut(locator)?;
        entry.last_used = tick;
        Some(entry.mounted.clone())
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Inserts or replaces `locator`'s mount, then evicts least-recently-used *other* entries
    /// until back within `max_bytes`. A single mount whose own weight exceeds the whole budget
    /// is inserted, handed back to the caller via the return of `resolve`, and then immediately
    /// dropped from the cache -- refusing to mount it at all would make an oversized-but-valid
    /// container unreadable purely because of a cache policy, not anything wrong with it.
    fn insert(&mut self, locator: EvidenceLocator, mounted: Mounted, weight: u64) {
        if let Some(old) = self.entries.remove(&locator) {
            self.total_bytes -= old.weight;
        }
        let tick = self.next_tick;
        self.next_tick += 1;
        self.entries.insert(
            locator.clone(),
            ResidentEntry {
                mounted,
                weight,
                last_used: tick,
            },
        );
        self.total_bytes += weight;

        while self.total_bytes > self.max_bytes {
            let victim = self
                .entries
                .iter()
                .filter(|(k, _)| **k != locator)
                .min_by_key(|(_, e)| e.last_used)
                .map(|(k, _)| k.clone());
            match victim {
                Some(v) => {
                    if let Some(e) = self.entries.remove(&v) {
                        self.total_bytes -= e.weight;
                    }
                }
                // Nothing left but the entry we just inserted, and it alone is over budget.
                None => {
                    if let Some(e) = self.entries.remove(&locator) {
                        self.total_bytes -= e.weight;
                    }
                    break;
                }
            }
        }
    }
}

impl MountResolver {
    pub fn builder() -> MountResolverBuilder {
        MountResolverBuilder::new()
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Number of hops **currently resident** in the mount cache. Unlike before eviction existed,
    /// this is not monotonic -- it can decrease as older mounts are evicted to make room for
    /// newer ones under `Limits::max_resident_bytes`.
    pub fn cache_len(&self) -> usize {
        self.resident
            .lock()
            .expect("MountResolver cache poisoned")
            .len()
    }

    /// Registered factories that could produce `want` (or all of them, if
    /// `want` is `None`). Exposed so a caller (e.g.
    /// `ParseContext::resolve`) can check "is this even supported" without
    /// opening a file.
    pub fn supports(&self, want: MountKind) -> bool {
        self.factories.iter().any(|f| f.yields() == want)
    }

    /// Every registered factory, in registration order. Exposed so a caller (e.g.
    /// `ContainerFs::DescentPolicy::from_resolver`) can derive its own policy from what this
    /// resolver actually knows how to mount, without core needing to name any format.
    pub fn factories(&self) -> impl Iterator<Item = &Arc<dyn FormatFactory>> {
        self.factories.iter()
    }

    /// Whether any registered factory claims `file` as `want` (or as
    /// anything, if `want` is `None`) -- without mounting, caching, or
    /// charging any resource budget. For a lightweight "does this look
    /// like a container" hint on content already read for another reason;
    /// mounting itself stays strictly on-demand, only when a caller
    /// actually asks to read inside it via [`MountResolver::resolve`].
    ///
    /// Does **not** enforce [`Limits::max_nesting_depth`] -- unlike `resolve`, this never
    /// recurses, so there is nothing here for the depth budget to bound. A caller that drives
    /// its own multi-hop chain (rather than calling `resolve` once per hop) must check depth
    /// itself before each probe.
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
    /// contents are subsequently read. A locator that was mounted once but
    /// has since been evicted from the (bounded) resident cache is
    /// re-mounted here without being charged a second time -- see
    /// `charged`'s doc comment.
    pub fn resolve(
        &self,
        fs: &Arc<dyn FileSystem>,
        locator: &EvidenceLocator,
        file: Box<dyn VirtualFile>,
        want: Option<MountKind>,
        cancellation: &crate::bridge::CancellationToken,
    ) -> ForensicResult<Mounted> {
        if let Some(cached) = self
            .resident
            .lock()
            .expect("MountResolver cache poisoned")
            .get(locator)
        {
            // A cache hit is only valid for the kind actually being asked for. Without this
            // check, a locator resolved once as e.g. `MountKind::FileSystem` would silently
            // hand back that same `Mounted::FileSystem` to a later caller asking for
            // `MountKind::Object` at the identical locator -- `as_object()` would then return
            // `None` with no indication the resolver ever ran. This is reachable wherever one
            // locator legitimately mounts two ways (e.g. an OLE container as both a
            // `FileSystem` and a `StructuredObject`). A mismatch falls through to a full
            // resolution for the requested kind rather than erroring, and its result overwrites
            // this cache entry.
            if want.is_none_or(|want| cached.kind() == want) {
                return Ok(cached);
            }
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
        let size = working_file.metadata().map(|meta| meta.size).unwrap_or(0);

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

        // Pick the winner first: which budgets apply depends on what the winning factory's
        // mount does with the bytes (`HopCost`), not merely on how many bytes there are.
        // Probing is a header sniff, so running it before the budget checks costs nothing a
        // refused hop would have saved.
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
        let expands = factory.hop_cost() == HopCost::Expansion;

        // Whether this locator's bytes were already charged against `expanded_bytes` /
        // `visited_content` by an earlier resolve -- possibly since evicted from `resident`,
        // possibly still there but under a `want` this call doesn't match. Either way, this is
        // not new expansion: the bytes were already accounted for once, and re-materializing an
        // already-validated mount must not cost the run's budget a second time, nor spuriously
        // re-trigger the duplicate-content check against content that legitimately recurs here
        // by construction (it's the same locator).
        let already_charged = self
            .charged
            .lock()
            .expect("MountResolver charged-set poisoned")
            .contains(locator);

        // A `HopCost::View` hop creates no bytes, so it is neither charged nor interned: a
        // partition or an image's media stream is the evidence itself, not an expansion of it,
        // and hashing a 500 GB disk to detect a zip-bomb cycle would cost more than the whole
        // rest of the run.
        if expands && !already_charged {
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
            let root_key = locator.segments().first().cloned();
            let root = {
                let mut guard = self.root_bytes.lock().expect("MountResolver root poisoned");
                *guard.entry(root_key).or_insert(size.max(1))
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

            // Content interning: only pay the cost of a full read when a digest is actually
            // configured, AND only on the first time this locator is charged. Re-running it on a
            // re-mount would insert the same content address a second time and spuriously report
            // a "cycle or duplicate content" error against bytes that are legitimately recurring
            // here -- they're the same locator's own bytes, re-materialized after eviction, not a
            // new occurrence of duplicate content.
            if let Some(make_digest) = &self.digest_factory {
                let mut digest = make_digest();
                working_file =
                    self.hash_content(working_file, size, digest.as_mut(), cancellation)?;
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
        }

        let mounted = factory.mount(working_file, &ctx)?;
        if !already_charged {
            if expands {
                self.expanded_bytes.fetch_add(size, Ordering::Relaxed);
            }
            self.charged
                .lock()
                .expect("MountResolver charged-set poisoned")
                .insert(locator.clone());
        }
        // A view holds no copy of its input, so it costs the byte-bounded cache nothing; charging
        // it the input size would evict an image's mount the moment it was made, and re-mount it
        // (re-reading its partition table or chunk index) on every path resolved through it.
        let weight = if expands { size } else { 0 };
        self.resident
            .lock()
            .expect("MountResolver cache poisoned")
            .insert(locator.clone(), mounted.clone(), weight);
        Ok(mounted)
    }

    /// Feeds `file`'s content to `digest` and hands back a file positioned at its start.
    ///
    /// Streams in fixed-size chunks when the file can seek back to its start, so the content
    /// check costs one buffer of memory however large the file is. Only a file that cannot seek
    /// is materialized through the `SpillStore` first -- the one case where the bytes must be
    /// kept to be read twice.
    fn hash_content(
        &self,
        mut file: Box<dyn VirtualFile>,
        size: u64,
        digest: &mut dyn Digest,
        cancellation: &crate::bridge::CancellationToken,
    ) -> ForensicResult<Box<dyn VirtualFile>> {
        let io = |e: std::io::Error| ForensicError::other("MountResolver", e.to_string());
        if file.seek(SeekFrom::Start(0)).is_err() {
            file = self.spill.spill(&mut *file, Some(size))?;
        }
        let mut buf = vec![0u8; 64 << 10];
        loop {
            if cancellation.is_cancelled() {
                return Err(ForensicError::other(
                    "MountResolver",
                    "cancelled".to_string(),
                ));
            }
            let n = match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(io(e)),
            };
            digest.update(&buf[..n]);
        }
        file.seek(SeekFrom::Start(0)).map_err(io)?;
        Ok(file)
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

    /// Registers several factories at once — e.g. a downstream crate's own
    /// `standard_factories()` helper — without a `for` loop of `.factory(...)` calls at
    /// every call site.
    #[must_use]
    pub fn factories(
        mut self,
        factories: impl IntoIterator<Item = Arc<dyn FormatFactory>>,
    ) -> Self {
        self.factories.extend(factories);
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
            spill: self.spill.unwrap_or_else(|| {
                Arc::new(MemorySpillStore::new(limits.materialize_in_memory_limit))
            }),
            digest_factory: self.digest_factory,
            resident: Mutex::new(ResidentCache::new(limits.max_resident_bytes)),
            charged: Mutex::new(BTreeSet::new()),
            visited_content: Mutex::new(BTreeSet::new()),
            root_bytes: Mutex::new(BTreeMap::new()),
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

    fn open(bytes: impl Into<Vec<u8>>) -> Box<dyn VirtualFile> {
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
        Box::new(MemFile(Cursor::new(bytes.into())))
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
        fn probe(
            &self,
            file: &mut dyn VirtualFile,
            _ctx: &MountContext<'_>,
        ) -> Result_<ProbeScore> {
            let start = file.stream_position().unwrap_or(0);
            let mut magic = [0u8; 3];
            let matched = file.read_exact(&mut magic).is_ok() && &magic == b"REG";
            let _ = file.seek(SeekFrom::Start(start));
            Ok(if matched {
                ProbeScore::Strong
            } else {
                ProbeScore::No
            })
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
        let resolver = MountResolver::builder()
            .factory(Arc::new(RegistryFactory))
            .build();
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
        let resolver = MountResolver::builder()
            .factory(Arc::new(RegistryFactory))
            .build();
        let fs = fs();
        let cancel = CancellationToken::new();
        let result = resolver.resolve(
            &fs,
            &locator_at("plain.txt"),
            open("not a hive"),
            None,
            &cancel,
        );
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
    fn expansion_ratio_is_scoped_per_root_not_poisoned_by_an_earlier_small_root() {
        // Regression for the bug where `root_bytes` was a single process-wide value pinned by
        // whichever locator resolved *first* -- here, a legitimately tiny root -- so every
        // larger, entirely unrelated root resolved afterward had its ratio measured against
        // the wrong denominator and was refused for a reason unrelated to its own bytes.
        let resolver = MountResolver::builder()
            .factory(Arc::new(RegistryFactory))
            .limits(Limits {
                max_expanded_bytes: u64::MAX,
                max_expansion_ratio: 10,
                ..Limits::default()
            })
            .build();
        let fs = fs();
        let cancel = CancellationToken::new();

        // Root A: 5 bytes. Resolves first, so under the old bug it pins the global denominator.
        resolver
            .resolve(&fs, &locator_at("a"), open("REG12"), None, &cancel)
            .unwrap();

        // Root B: 50 bytes, completely unrelated to A. Its own size is a perfectly reasonable
        // denominator for its own expansion (ratio 1:1 against itself), but under the old bug
        // the ratio was computed against A's 5-byte size instead, giving a spurious ~11:1.
        let big = format!("REG{}", "x".repeat(47));
        assert_eq!(big.len(), 50);
        match resolver.resolve(&fs, &locator_at("b"), open(big), None, &cancel) {
            Ok(_) => {}
            Err(e) => panic!("root B must be judged against its own size, not root A's: {e}"),
        }
    }

    #[test]
    fn a_cache_hit_of_the_wrong_kind_is_treated_as_a_miss() {
        // Regression for the bug where the cache was consulted before the `want` filter: a
        // locator resolved once as one `MountKind` would silently hand back that same `Mounted`
        // to a later caller asking for a *different* kind at the identical locator.
        struct DualKindFactory;
        impl FormatFactory for DualKindFactory {
            fn name(&self) -> &'static str {
                "test-dual-database"
            }
            fn yields(&self) -> MountKind {
                MountKind::Database
            }
            fn probe(
                &self,
                file: &mut dyn VirtualFile,
                _ctx: &MountContext<'_>,
            ) -> Result_<ProbeScore> {
                let start = file.stream_position().unwrap_or(0);
                let mut magic = [0u8; 3];
                let matched = file.read_exact(&mut magic).is_ok() && &magic == b"REG";
                let _ = file.seek(SeekFrom::Start(start));
                // Weaker than RegistryFactory's `Strong`, so an untargeted resolve still
                // deterministically picks the registry mount -- this factory only ever wins
                // when `want` explicitly filters it in.
                Ok(if matched {
                    ProbeScore::Weak
                } else {
                    ProbeScore::No
                })
            }
            fn mount(
                &self,
                _file: Box<dyn VirtualFile>,
                _ctx: &MountContext<'_>,
            ) -> Result_<Mounted> {
                Ok(Mounted::Database(Arc::new(
                    crate::utils::testing::InMemoryForensicDb::new(),
                )))
            }
        }

        let resolver = MountResolver::builder()
            .factory(Arc::new(RegistryFactory))
            .factory(Arc::new(DualKindFactory))
            .build();
        let fs = fs();
        let locator = locator_at("dual.dat");
        let cancel = CancellationToken::new();

        let first = resolver
            .resolve(&fs, &locator, open("REG-first"), None, &cancel)
            .unwrap();
        assert!(
            first.as_registry().is_some(),
            "untargeted resolve picks the higher-scoring factory"
        );

        // Same locator, same bytes, but now explicitly asking for the OTHER kind. Without the
        // fix this returns the cached Registry mount and `as_database()` is `None`.
        let second = resolver
            .resolve(
                &fs,
                &locator,
                open("REG-second"),
                Some(MountKind::Database),
                &cancel,
            )
            .unwrap();
        assert!(
            second.as_database().is_some(),
            "a kind-mismatched cache entry must not be returned"
        );
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
            ContentAddress::new(
                DigestAlgorithm::Other("fake-test-digest"),
                self.acc.to_le_bytes().to_vec(),
            )
        }
    }

    #[test]
    fn cancellation_is_honoured_before_any_probing() {
        let resolver = MountResolver::builder()
            .factory(Arc::new(RegistryFactory))
            .build();
        let fs = fs();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let result = resolver.resolve(&fs, &locator_at("x"), open("REG-anything"), None, &cancel);
        assert!(result.is_err());
    }

    #[test]
    fn want_filter_skips_factories_yielding_a_different_kind() {
        let resolver = MountResolver::builder()
            .factory(Arc::new(RegistryFactory))
            .build();
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
        let resolver = MountResolver::builder()
            .factory(Arc::new(RegistryFactory))
            .build();
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
        let resolver = MountResolver::builder()
            .factory(Arc::new(RegistryFactory))
            .build();
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
        let resolver = MountResolver::builder()
            .factory(Arc::new(RegistryFactory))
            .build();
        assert!(resolver.supports(MountKind::Registry));
        assert!(!resolver.supports(MountKind::Database));
    }

    #[test]
    fn eviction_keeps_the_resident_cache_within_the_byte_budget() {
        // Every mount below is 5 bytes; a 12-byte budget can hold at most 2 at once.
        let resolver = MountResolver::builder()
            .factory(Arc::new(RegistryFactory))
            .limits(Limits {
                max_resident_bytes: 12,
                ..Limits::default()
            })
            .build();
        let fs = fs();
        let cancel = CancellationToken::new();

        for i in 0..5 {
            resolver
                .resolve(
                    &fs,
                    &locator_at(&format!("m{i}")),
                    open(format!("REG{i:02}")),
                    None,
                    &cancel,
                )
                .unwrap();
            assert!(
                resolver.cache_len() <= 2,
                "resident cache exceeded its byte budget after mount {i}"
            );
        }
    }

    #[test]
    fn re_mounting_an_evicted_locator_does_not_charge_the_expanded_bytes_budget_again() {
        // max_expanded_bytes is exactly enough for the two *distinct* locators below (5 bytes
        // each) and no more -- a third fresh charge of 5 bytes would exceed it. max_resident_bytes
        // holds only one 5-byte mount at a time, so resolving A then B evicts A.
        let resolver = MountResolver::builder()
            .factory(Arc::new(RegistryFactory))
            .limits(Limits {
                max_expanded_bytes: 10,
                max_resident_bytes: 5,
                max_expansion_ratio: u32::MAX,
                ..Limits::default()
            })
            .build();
        let fs = fs();
        let cancel = CancellationToken::new();

        resolver
            .resolve(&fs, &locator_at("a"), open("REG12"), None, &cancel)
            .unwrap();
        assert_eq!(resolver.cache_len(), 1);

        // Distinct locator, same weight: evicts "a" from the resident cache and consumes the
        // rest of the expanded-bytes budget (5 + 5 == 10, right at the limit).
        resolver
            .resolve(&fs, &locator_at("b"), open("REG34"), None, &cancel)
            .unwrap();
        assert_eq!(resolver.cache_len(), 1);

        // "a" is no longer resident, but it WAS already charged once. If this re-mount charged
        // it again, would_total would be 10 + 5 = 15 > the 10-byte budget and this would error.
        let result = resolver.resolve(&fs, &locator_at("a"), open("REG12"), None, &cancel);
        match result {
            Ok(_) => {}
            Err(e) => panic!(
                "re-mounting an evicted-but-already-charged locator must not re-charge the budget: {e}"
            ),
        }
    }

    #[test]
    fn a_single_mount_larger_than_the_whole_budget_is_still_returned_but_not_retained() {
        let resolver = MountResolver::builder()
            .factory(Arc::new(RegistryFactory))
            .limits(Limits {
                max_resident_bytes: 5,
                ..Limits::default()
            })
            .build();
        let fs = fs();
        let cancel = CancellationToken::new();

        let big = format!("REG{}", "x".repeat(17)); // 20 bytes, over the 5-byte cache budget
        let mounted = resolver
            .resolve(&fs, &locator_at("huge"), open(big), None, &cancel)
            .unwrap();
        assert!(
            mounted.as_registry().is_some(),
            "an oversized-for-the-cache mount is still handed back"
        );
        assert_eq!(
            resolver.cache_len(),
            0,
            "but it is never retained in the resident cache"
        );
    }

    #[test]
    fn builder_factories_registers_every_factory_in_one_call() {
        struct AnotherRegistryFactory;
        impl FormatFactory for AnotherRegistryFactory {
            fn name(&self) -> &'static str {
                "test-registry-2"
            }
            fn yields(&self) -> MountKind {
                MountKind::Registry
            }
            fn probe(
                &self,
                _file: &mut dyn VirtualFile,
                _ctx: &MountContext<'_>,
            ) -> Result_<ProbeScore> {
                Ok(ProbeScore::No)
            }
            fn mount(
                &self,
                _file: Box<dyn VirtualFile>,
                _ctx: &MountContext<'_>,
            ) -> Result_<Mounted> {
                unreachable!("never probes Strong enough to be asked to mount")
            }
        }

        let batch: Vec<Arc<dyn FormatFactory>> =
            vec![Arc::new(RegistryFactory), Arc::new(AnotherRegistryFactory)];
        let resolver = MountResolver::builder().factories(batch).build();
        let names: Vec<&str> = resolver.factories().map(|f| f.name()).collect();
        assert_eq!(names, vec!["test-registry", "test-registry-2"]);
    }
}
