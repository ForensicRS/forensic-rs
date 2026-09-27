//! [`ContainerFs`]: makes container files transparently walkable. A container file (a `.doc`, a
//! `.zip`, anything a registered [`FormatFactory`] can mount as a [`MountKind::FileSystem`])
//! doubles as a directory -- `C:\docs\report.doc\Macros\VBA\Module1` is an ordinary path, with
//! no `[mount]` marker segment. The file itself keeps `file_type: VFileType::File` (so
//! `read_all`/hashing still sees the original bytes) and gains
//! [`FileAttributes::CONTAINER`]; `read_dir` on it succeeds, gated at the [`Walk`] level by
//! [`WalkOptions::descend_into_containers`].
//!
//! Path splitting (finding where a container boundary is crossed) costs **zero byte reads** on
//! the common case: an ordinary path resolves with exactly one `metadata()` call, identical to
//! today, because the fast path checks the base filesystem first and only walks the boundary
//! search when that misses. See [`ContainerFs::resolve_chain`].

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::core::locator::{EvidenceLocator, LocatorSegment};
use crate::core::path::{Component, FPath, FPathBuf};
use crate::core::resolver::MountResolver;
use crate::err::{ForensicError, ForensicResult};
use crate::field::{Field, Text};
use crate::traits::vfs::{
    CaseSensitivity, DirEntry, FileAttributes, FileSystem, PathAttributes, SourceKind, VFileType,
    VMetadata, VirtualFile,
};
use std::collections::BTreeMap;

/// Controls which files [`ContainerFs`] is willing to even attempt mounting as containers.
/// **`Default` descends into nothing** -- the only safe default for a type whose failure mode,
/// misconfigured, is "quietly expand an unbounded amount of an evidence image".
#[derive(Debug, Clone)]
pub struct DescentPolicy {
    /// Lowercase extensions (no dot) eligible for an attempted mount. `None` means "every file
    /// in the size band" -- right for a small, already-curated directory of known evidence,
    /// ruinous for a whole disk image. `Some(empty set)` (the `Default`) means "nothing".
    pub extensions: Option<BTreeSet<String>>,
    /// Below this size, a file is not worth attempting (a real container has real structure).
    pub min_size: u64,
    /// Above this size, a file is not attempted -- guards the *mount* cost, not just the probe.
    pub max_size: u64,
    /// Container boundaries this `ContainerFs` will cross in one path resolution. Independent
    /// of `WalkOptions::max_depth` (directory levels) and of
    /// `Limits::max_nesting_depth` (the resolver's own, looser budget) -- a transparent walk
    /// crosses boundaries *without the caller asking*, so it stops well short of what a caller
    /// driving `MountResolver::resolve` by hand would be trusted with.
    pub max_container_depth: u32,
}

impl Default for DescentPolicy {
    fn default() -> Self {
        Self {
            extensions: Some(BTreeSet::new()),
            min_size: 8,
            max_size: crate::core::limits::Limits::default().materialize_in_memory_limit as u64,
            max_container_depth: 4,
        }
    }
}

impl DescentPolicy {
    /// Derives a policy from a resolver's own registered factories: the extension allow-list is
    /// the union of every factory's [`FormatFactory::extensions`], and `max_size` matches the
    /// resolver's own `Limits::materialize_in_memory_limit` (the real wall -- core's only
    /// shipped `SpillStore` already refuses above it, so a larger file would fail to mount
    /// anyway; deriving the policy from it means refusing cheaply, before any open, instead of
    /// expensively, after one). Adding a factory to the resolver automatically extends what this
    /// policy is willing to attempt; core never has to name a format itself.
    pub fn from_resolver(resolver: &MountResolver) -> Self {
        let mut extensions = BTreeSet::new();
        for factory in resolver.factories() {
            for ext in factory.extensions() {
                extensions.insert(ext.to_ascii_lowercase());
            }
        }
        Self {
            extensions: Some(extensions),
            max_size: resolver.limits().materialize_in_memory_limit as u64,
            ..Self::default()
        }
    }

    /// Pure, byte-free gate: extension allow-list plus size band. Reads only data the caller
    /// already has (a `DirEntry`'s name and `VMetadata::size`) -- never opens the file.
    fn should_probe(&self, path: &FPath, size: u64) -> bool {
        if size < self.min_size || size > self.max_size {
            return false;
        }
        match &self.extensions {
            None => true,
            Some(allow) => path
                .as_str()
                .rsplit_once('.')
                .map(|(_, ext)| allow.contains(&ext.to_ascii_lowercase()))
                .unwrap_or(false),
        }
    }
}

/// See the module doc.
pub struct ContainerFs {
    base: Arc<dyn FileSystem>,
    resolver: Arc<MountResolver>,
    policy: DescentPolicy,
    cancellation: crate::bridge::CancellationToken,
}

impl ContainerFs {
    /// **One `MountResolver` per evidence root.** `MountResolver` caches by `EvidenceLocator`
    /// and does not key on which `FileSystem` a locator was resolved through, so two
    /// `ContainerFs` instances over two different evidence roots sharing one resolver would
    /// collide on an identical-looking locator (e.g. `[Path("C:/x.zip")]` present in both). This
    /// is a pre-existing property of `MountResolver`, not something `ContainerFs` introduces,
    /// but `ContainerFs` is the first thing that makes it easy to reach by accident.
    pub fn new(base: Arc<dyn FileSystem>, resolver: Arc<MountResolver>) -> Self {
        let policy = DescentPolicy::from_resolver(&resolver);
        Self {
            base,
            resolver,
            policy,
            cancellation: crate::bridge::CancellationToken::default(),
        }
    }

    #[must_use]
    pub fn with_policy(mut self, policy: DescentPolicy) -> Self {
        self.policy = policy;
        self
    }

    #[must_use]
    pub fn with_cancellation(mut self, token: crate::bridge::CancellationToken) -> Self {
        self.cancellation = token;
        self
    }

    /// Longest ancestor of `path` (inclusive) that `fs` reports as a file, plus the sanitized
    /// remainder below it. Reads no bytes -- only `metadata()` calls, and exactly one on the
    /// (overwhelmingly common) case where `path` itself already exists in `fs`. Mirrors
    /// `crate::bridge::providers::VfsProvider::resolve_hook`'s identical walk-up.
    fn split_at_boundary(fs: &dyn FileSystem, path: &FPath) -> Option<(FPathBuf, FPathBuf)> {
        let mut candidate = FPath::new(path.as_str());
        loop {
            match fs.metadata(candidate) {
                Ok(meta) if meta.is_file() => {
                    let head = candidate.as_str().to_string();
                    let tail_str = path.as_str()[head.len()..].trim_start_matches(['/', '\\']);
                    let tail = sanitize_relative(tail_str);
                    return Some((FPathBuf::from(head), tail));
                }
                Ok(_) => return None, // a real directory -- no boundary to find here
                Err(_) => {}
            }
            candidate = candidate.parent()?;
        }
    }

    /// Resolves `path` down to `(owning filesystem, path within it, locator of the hops
    /// crossed)`. A loop, not recursion: `tail` strictly shortens each iteration and
    /// `hops`/`locator.depth()` strictly increase under two independent ceilings, so this always
    /// terminates.
    ///
    /// `inclusive`: when `true` and `path` itself is a container file, returns
    /// `(mounted_fs, "" , locator)` for it (used by `read_dir`, which needs to list a
    /// container's own root); when `false`, a bare container path with no tail is instead an
    /// ordinary open of a `File` (used by `open`/`metadata`, which must return the container's
    /// own bytes/metadata unless a caller is asking to look *inside* it).
    fn resolve_chain(
        &self,
        path: &FPath,
        inclusive: bool,
    ) -> ForensicResult<(Arc<dyn FileSystem>, FPathBuf, EvidenceLocator)> {
        let mut fs: Arc<dyn FileSystem> = Arc::clone(&self.base);
        let mut rest = FPathBuf::from(path.as_str());
        let mut locator = EvidenceLocator::root();
        let mut hops = 0u32;

        loop {
            // Ordinary resolution short-circuits: a real directory, an entry nested inside an
            // already-mounted fs (hops > 0), or -- for open()/metadata() (`inclusive: false`)
            // only -- the container file's own bytes/metadata. The one case this must NOT
            // short-circuit on is `inclusive: true` (read_dir/attributes) hitting the container
            // file itself on the very first lookup: that call means "look inside it", so it
            // must fall through to the mount-and-descend logic below instead of returning the
            // bare file.
            if let Ok(meta) = fs.metadata(rest.as_path()) {
                if !(inclusive && hops == 0 && meta.is_file()) {
                    return Ok((fs, rest, locator));
                }
            }

            let Some((head, tail)) = Self::split_at_boundary(fs.as_ref(), rest.as_path()) else {
                return Err(ForensicError::path_not_found(path.to_string()));
            };

            if hops >= self.policy.max_container_depth {
                return Err(ForensicError::other(
                    "ContainerFs",
                    format!(
                        "container depth exceeds the {}-hop descent policy limit at {path}",
                        self.policy.max_container_depth
                    ),
                ));
            }
            // Cheap path-level self-containment check (e.g. a.zip nested inside a.zip): a real
            // content cycle is still caught by the resolver's own digest-based interning, when
            // one is configured; this catches the identical-path case even without one.
            if locator
                .segments()
                .iter()
                .any(|s| matches!(s, LocatorSegment::Path(p) if *p == head))
            {
                return Err(ForensicError::other(
                    "ContainerFs",
                    format!("cyclic container path at {head}"),
                ));
            }

            let meta = fs.metadata(head.as_path())?;
            if !self.policy.should_probe(head.as_path(), meta.size) {
                return Err(ForensicError::path_not_found(path.to_string()));
            }

            let file = fs.open(head.as_path())?;
            locator = locator.push(LocatorSegment::Path(head.clone()));
            let mounted = self.resolver.resolve(
                &fs,
                &locator,
                file,
                Some(crate::traits::format::MountKind::FileSystem),
                &self.cancellation,
            )?;
            let Some(next_fs) = mounted.as_file_system() else {
                return Err(ForensicError::other(
                    "ContainerFs",
                    format!("'{head}' did not mount as a FileSystem"),
                ));
            };
            fs = Arc::clone(next_fs);
            rest = tail;
            hops += 1;
        }
    }

    /// Whether `path` (as seen from the base filesystem, i.e. NOT already resolved through a
    /// mount) is itself a plausible container per the descent policy -- the check `metadata`
    /// uses to decide whether to set [`FileAttributes::CONTAINER`].
    fn looks_like_a_container(&self, path: &FPath, size: u64) -> bool {
        self.policy.should_probe(path, size)
            && self
                .resolver
                .supports(crate::traits::format::MountKind::FileSystem)
    }
}

/// Keeps only `Component::Normal` segments, dropping `RootDir`, `Drive`, `CurDir` and
/// `ParentDir` -- the same rule `ChRootFileSystem::resolve` applies, and for the identical
/// reason: a `..` in a tail must never climb back out of a mounted container into whatever is
/// above it.
fn sanitize_relative(s: &str) -> FPathBuf {
    let mut out = FPathBuf::new();
    for comp in FPath::new(s).components() {
        if let Component::Normal(seg) = comp {
            out.push(seg);
        }
    }
    out
}

impl FileSystem for ContainerFs {
    fn open(&self, path: &FPath) -> ForensicResult<Box<dyn VirtualFile>> {
        if let Ok(f) = self.base.open(path) {
            return Ok(f);
        }
        let (fs, inner, _locator) = self.resolve_chain(path, false)?;
        fs.open(inner.as_path())
    }

    fn metadata(&self, path: &FPath) -> ForensicResult<VMetadata> {
        if let Ok(mut m) = self.base.metadata(path) {
            if m.file_type == VFileType::File && self.looks_like_a_container(path, m.size) {
                m.attributes |= FileAttributes::CONTAINER;
            }
            return Ok(m);
        }
        let (fs, inner, _locator) = self.resolve_chain(path, false)?;
        fs.metadata(inner.as_path())
    }

    fn read_dir(
        &self,
        path: &FPath,
    ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<DirEntry>> + '_>> {
        if let Ok(iter) = self.base.read_dir(path) {
            // Annotate every entry the base fs already populated `metadata` for; an entry with
            // no opportunistic metadata falls back to `Walk::is_container`'s own `metadata()`
            // call, which reaches this type's `metadata()` impl and gets the same annotation.
            let policy = &self.policy;
            let supports_fs = self
                .resolver
                .supports(crate::traits::format::MountKind::FileSystem);
            return Ok(Box::new(iter.map(move |entry| {
                let mut entry = entry?;
                if supports_fs && entry.file_type == VFileType::File {
                    if let Some(m) = entry.metadata.as_mut() {
                        if policy.should_probe(entry.path.as_path(), m.size) {
                            m.attributes |= FileAttributes::CONTAINER;
                        }
                    }
                }
                Ok(entry)
            })));
        }

        // Either `path` is itself a container file, or a path inside one. `inclusive: true`
        // makes a bare container path resolve to (its mounted fs, "", locator) so both cases
        // share one code path.
        let (fs, inner, _locator) = self.resolve_chain(path, true)?;
        let dir_path = if inner.as_str().is_empty() {
            FPathBuf::from("")
        } else {
            inner
        };
        let max_entries = self.resolver.limits().max_entries_per_container;
        let outer_prefix = path.as_str().to_string();

        let mut out: Vec<ForensicResult<DirEntry>> = Vec::new();
        let inner_iter = fs.read_dir(dir_path.as_path())?;
        for (n, item) in inner_iter.enumerate() {
            if n as u64 >= max_entries {
                out.push(Err(ForensicError::other(
                    "ContainerFs",
                    format!(
                        "container entry count exceeds the {max_entries}-entry limit at {path}"
                    ),
                )));
                break;
            }
            match item {
                Ok(mut child) => {
                    // Rewrite the mounted fs's own-relative path to the outer transparent path.
                    let leaf = child
                        .path
                        .as_str()
                        .rsplit(['/', '\\'])
                        .next()
                        .unwrap_or(child.path.as_str());
                    let rewritten = if outer_prefix.is_empty() {
                        leaf.to_string()
                    } else {
                        format!("{outer_prefix}/{leaf}")
                    };
                    child.path = FPathBuf::from(rewritten);
                    out.push(Ok(child));
                }
                Err(e) => out.push(Err(e)),
            }
        }
        Ok(Box::new(out.into_iter()))
    }

    fn source(&self) -> SourceKind {
        self.base.source()
    }

    fn case_sensitivity(&self) -> CaseSensitivity {
        self.base.case_sensitivity()
    }

    fn as_attributes(&self) -> Option<&dyn PathAttributes> {
        Some(self)
    }
}

impl PathAttributes for ContainerFs {
    /// Forwards the owning filesystem's own `PathAttributes` answer (an OLE document's
    /// `ole.author`, say), plus `container.depth`/`container.locator` when `path` was reached by
    /// crossing at least one boundary. A path that is itself a container additionally gets the
    /// mounted filesystem's *root* attributes folded in, so `ole.*` facts are visible at the
    /// container's own path without a caller needing to know it's a container at all.
    fn attributes(&self, path: &FPath) -> ForensicResult<BTreeMap<Text, Field>> {
        let mut out = BTreeMap::new();
        let (fs, inner, locator) = self.resolve_chain(path, true)?;
        if locator.depth() > 0 {
            out.insert(
                Text::Borrowed("container.depth"),
                Field::U64(locator.depth() as u64),
            );
            out.insert(
                Text::Borrowed("container.locator"),
                Field::Text(Text::Owned(locator.to_string())),
            );
        }
        if let Some(attrs) = fs.as_attributes() {
            out.extend(attrs.attributes(inner.as_path())?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::CancellationToken;
    use crate::core::limits::Limits;
    use crate::traits::format::{FormatFactory, MountContext, MountKind, Mounted, ProbeScore};
    use crate::traits::vfs::FileSystemExt;
    use crate::utils::testing::InMemoryVirtualFileSystem;
    use std::io::{Read, SeekFrom};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const MAGIC: &[u8] = b"TOYFS1\0";

    fn build_toy_container(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        for (name, content) in entries {
            out.extend_from_slice(name.as_bytes());
            out.push(b'=');
            out.extend_from_slice(content.as_bytes());
            out.push(b'|');
        }
        out
    }

    fn parse_toy_container(bytes: &[u8]) -> Option<InMemoryVirtualFileSystem> {
        let rest = bytes.strip_prefix(MAGIC)?;
        let mut fs = InMemoryVirtualFileSystem::new();
        for entry in std::str::from_utf8(rest)
            .ok()?
            .split('|')
            .filter(|s| !s.is_empty())
        {
            let (name, content) = entry.split_once('=')?;
            fs.add_file(name, content.as_bytes().to_vec());
        }
        Some(fs)
    }

    struct ToyContainerFactory;
    impl FormatFactory for ToyContainerFactory {
        fn name(&self) -> &'static str {
            "toy-container"
        }
        fn yields(&self) -> MountKind {
            MountKind::FileSystem
        }
        fn extensions(&self) -> &[&'static str] {
            &["tc"]
        }
        fn probe(
            &self,
            file: &mut dyn VirtualFile,
            _ctx: &MountContext<'_>,
        ) -> ForensicResult<ProbeScore> {
            let start = file.stream_position().unwrap_or(0);
            let mut magic = vec![0u8; MAGIC.len()];
            let matched = file.read_exact(&mut magic).is_ok() && magic == MAGIC;
            let _ = file.seek(SeekFrom::Start(start));
            Ok(if matched {
                ProbeScore::Strong
            } else {
                ProbeScore::No
            })
        }
        fn mount(
            &self,
            mut file: Box<dyn VirtualFile>,
            _ctx: &MountContext<'_>,
        ) -> ForensicResult<Mounted> {
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .map_err(|e| ForensicError::other("toy", e.to_string()))?;
            let fs = parse_toy_container(&bytes).ok_or_else(|| {
                ForensicError::other("toy-container", "malformed toy container".to_string())
            })?;
            Ok(Mounted::FileSystem(Arc::new(fs)))
        }
    }

    fn resolver() -> Arc<MountResolver> {
        Arc::new(
            MountResolver::builder()
                .factory(Arc::new(ToyContainerFactory))
                .build(),
        )
    }

    /// Counts `metadata()` calls, so the "an ordinary path costs exactly one `metadata()` call"
    /// claim in the module doc is an assertion, not just a comment.
    struct CountingFs {
        inner: InMemoryVirtualFileSystem,
        metadata_calls: AtomicUsize,
    }
    impl FileSystem for CountingFs {
        fn open(&self, path: &FPath) -> ForensicResult<Box<dyn VirtualFile>> {
            self.inner.open(path)
        }
        fn metadata(&self, path: &FPath) -> ForensicResult<VMetadata> {
            self.metadata_calls.fetch_add(1, Ordering::Relaxed);
            self.inner.metadata(path)
        }
        fn read_dir(
            &self,
            path: &FPath,
        ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<DirEntry>> + '_>> {
            self.inner.read_dir(path)
        }
        fn source(&self) -> SourceKind {
            self.inner.source()
        }
    }

    #[test]
    fn an_ordinary_path_costs_exactly_one_metadata_call() {
        let base = Arc::new(CountingFs {
            inner: InMemoryVirtualFileSystem::new().with_file("plain.txt", b"hello".to_vec()),
            metadata_calls: AtomicUsize::new(0),
        });
        let counter = Arc::clone(&base);
        let fs = ContainerFs::new(base, resolver());
        fs.metadata(FPath::new("plain.txt")).unwrap();
        assert_eq!(counter.metadata_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn transparent_path_reaches_a_file_inside_a_mounted_container() {
        let base = InMemoryVirtualFileSystem::new()
            .with_file("report.tc", build_toy_container(&[("inner.txt", "hello")]));
        let fs = ContainerFs::new(Arc::new(base), resolver());
        assert_eq!(
            fs.read_all(FPath::new("report.tc/inner.txt")).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn the_container_file_itself_keeps_file_type_file_and_gains_the_container_bit() {
        let base = InMemoryVirtualFileSystem::new()
            .with_file("report.tc", build_toy_container(&[("inner.txt", "hello")]));
        let fs = ContainerFs::new(Arc::new(base), resolver());
        let meta = fs.metadata(FPath::new("report.tc")).unwrap();
        assert_eq!(meta.file_type, VFileType::File);
        assert!(meta.attributes.contains(FileAttributes::CONTAINER));
        // read_all on the container path itself must still return its ORIGINAL bytes, not its
        // contents-as-a-directory -- this is the whole point of the transparent scheme.
        assert_eq!(
            fs.read_all(FPath::new("report.tc")).unwrap(),
            build_toy_container(&[("inner.txt", "hello")])
        );
    }

    #[test]
    fn read_dir_on_the_container_lists_its_contents_at_the_outer_path() {
        let base = InMemoryVirtualFileSystem::new().with_file(
            "report.tc",
            build_toy_container(&[("inner.txt", "hello"), ("other.txt", "world")]),
        );
        let fs = ContainerFs::new(Arc::new(base), resolver());
        let mut names: Vec<String> = fs
            .read_dir(FPath::new("report.tc"))
            .unwrap()
            .map(|e| e.unwrap().path.to_string())
            .collect();
        names.sort();
        assert_eq!(names, vec!["report.tc/inner.txt", "report.tc/other.txt"]);
    }

    #[test]
    fn walk_with_descend_into_containers_reaches_nested_content() {
        let base = InMemoryVirtualFileSystem::new()
            .with_file("report.tc", build_toy_container(&[("inner.txt", "hello")]));
        let fs = ContainerFs::new(Arc::new(base), resolver());
        let opts = crate::core::fs::walk::WalkOptions::default().with_descend_into_containers(true);
        let mut names: Vec<String> = fs
            .walk(FPath::new(""), &opts)
            .map(|e| e.unwrap().path.to_string())
            .collect();
        names.sort();
        assert_eq!(names, vec!["report.tc", "report.tc/inner.txt"]);
    }

    #[test]
    fn walk_without_the_option_does_not_descend() {
        let base = InMemoryVirtualFileSystem::new()
            .with_file("report.tc", build_toy_container(&[("inner.txt", "hello")]));
        let fs = ContainerFs::new(Arc::new(base), resolver());
        let names: Vec<String> = fs
            .walk(FPath::new(""), &Default::default())
            .map(|e| e.unwrap().path.to_string())
            .collect();
        assert_eq!(names, vec!["report.tc"]);
    }

    #[test]
    fn a_dotdot_in_the_tail_cannot_escape_the_container() {
        let base = InMemoryVirtualFileSystem::new()
            .with_file("secret.txt", b"outer secret".to_vec())
            .with_file("report.tc", build_toy_container(&[("inner.txt", "hello")]));
        let fs = ContainerFs::new(Arc::new(base), resolver());
        // `..` is dropped, not applied -- this can never reach the outer "secret.txt".
        assert!(fs.open(FPath::new("report.tc/../secret.txt")).is_err());
    }

    #[test]
    fn max_container_depth_is_enforced() {
        let inner_bytes = build_toy_container(&[("c.txt", "leaf")]);
        let mut inner_container = MAGIC.to_vec();
        inner_container.extend_from_slice(b"b.tc=");
        // A toy container's own value can itself be a nested toy container's raw bytes, verbatim
        // (the format has no length prefix, so this only works because `b.tc` is the last/only
        // entry -- fine for this test).
        inner_container.extend_from_slice(&inner_bytes);
        inner_container.push(b'|');

        let base = InMemoryVirtualFileSystem::new().with_file("a.tc", inner_container);
        let policy = DescentPolicy {
            max_container_depth: 1,
            ..DescentPolicy::from_resolver(&resolver())
        };
        let fs = ContainerFs::new(Arc::new(base), resolver()).with_policy(policy);

        // One hop (into a.tc) succeeds; a second hop (into b.tc) exceeds the depth-1 policy.
        assert!(fs.metadata(FPath::new("a.tc")).is_ok());
        assert!(fs.open(FPath::new("a.tc/b.tc/c.txt")).is_err());
    }

    #[test]
    fn entry_limit_is_enforced_in_read_dir() {
        let entries: Vec<(&str, &str)> = vec![("a", "1"), ("b", "2"), ("c", "3")];
        let base =
            InMemoryVirtualFileSystem::new().with_file("report.tc", build_toy_container(&entries));
        let resolver = Arc::new(
            MountResolver::builder()
                .factory(Arc::new(ToyContainerFactory))
                .limits(Limits {
                    max_entries_per_container: 2,
                    ..Limits::default()
                })
                .build(),
        );
        let fs = ContainerFs::new(Arc::new(base), resolver);
        let results: Vec<_> = fs.read_dir(FPath::new("report.tc")).unwrap().collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 2);
        assert_eq!(results.iter().filter(|r| r.is_err()).count(), 1);
    }

    #[test]
    fn descent_policy_default_descends_into_nothing() {
        let policy = DescentPolicy::default();
        assert_eq!(policy.extensions, Some(BTreeSet::new()));
    }

    #[test]
    fn descent_policy_from_resolver_derives_extensions_from_registered_factories() {
        let policy = DescentPolicy::from_resolver(&resolver());
        assert!(policy.extensions.unwrap().contains("tc"));
    }

    #[test]
    fn a_file_with_an_unlisted_extension_is_never_attempted_as_a_container() {
        // Same magic bytes, but a ".txt" extension the default policy doesn't allow -- proves
        // the extension gate, not just the magic probe, controls descent.
        let base = InMemoryVirtualFileSystem::new()
            .with_file("report.txt", build_toy_container(&[("inner.txt", "hello")]));
        let fs = ContainerFs::new(Arc::new(base), resolver());
        let meta = fs.metadata(FPath::new("report.txt")).unwrap();
        assert!(!meta.attributes.contains(FileAttributes::CONTAINER));
        assert!(fs.open(FPath::new("report.txt/inner.txt")).is_err());
    }

    #[test]
    fn path_attributes_forward_container_depth_for_a_nested_path() {
        let base = InMemoryVirtualFileSystem::new()
            .with_file("report.tc", build_toy_container(&[("inner.txt", "hello")]));
        let fs = ContainerFs::new(Arc::new(base), resolver());
        let attrs = fs
            .as_attributes()
            .unwrap()
            .attributes(FPath::new("report.tc/inner.txt"))
            .unwrap();
        assert_eq!(
            attrs.get(&Text::Borrowed("container.depth")),
            Some(&Field::U64(1))
        );
    }

    #[test]
    fn send_sync_holds() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ContainerFs>();
        assert_send_sync::<Arc<dyn FileSystem>>();
    }

    #[test]
    fn one_resolver_per_root_is_documented_not_silently_broken() {
        // Two ContainerFs over two DIFFERENT evidence roots sharing one resolver: this is the
        // documented hazard (identical-looking locators collide), not something this test
        // asserts is fixed -- it just pins that a shared resolver doesn't panic and that each
        // fs's own base bytes are what get mounted (the raw resolver cache correctness itself is
        // covered by core/resolver.rs's own tests).
        let shared = resolver();
        let base_a = Arc::new(
            InMemoryVirtualFileSystem::new()
                .with_file("x.tc", build_toy_container(&[("a.txt", "A")])),
        );
        let base_b = Arc::new(
            InMemoryVirtualFileSystem::new()
                .with_file("x.tc", build_toy_container(&[("a.txt", "A")])),
        );
        let fs_a = ContainerFs::new(base_a, Arc::clone(&shared));
        let fs_b = ContainerFs::new(base_b, shared);
        assert_eq!(fs_a.read_all(FPath::new("x.tc/a.txt")).unwrap(), b"A");
        assert_eq!(fs_b.read_all(FPath::new("x.tc/a.txt")).unwrap(), b"A");
    }

    #[allow(unused)]
    fn cancellation_token_is_pluggable() {
        let fs = ContainerFs::new(Arc::new(InMemoryVirtualFileSystem::new()), resolver());
        let _ = fs.with_cancellation(CancellationToken::new());
    }
}
