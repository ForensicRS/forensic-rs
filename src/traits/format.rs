//! Unified sniff-and-mount contract for evidence reachable through nested
//! containers.
//!
//! Replaces the four disjoint traits `FileSystemFactory`,
//! `ForensicDbFactory`, `EventLogReaderFactory`, and `RegistryReaderFactory`
//! (formerly in `traits::factories`, now removed). "Inside" a piece of
//! evidence is really three different relationships, and conflating them
//! made a generic recursion impossible:
//!
//! - **Containment**: a ZIP holds `evil.exe` -> yields a new [`FileSystem`].
//! - **Interpretation**: the *same* bytes are a SQLite DB / an EVTX / a hive
//!   -> yields a new reader over the same bytes.
//! - **Embedding**: a structured object (a PE, an OLE compound file) exposes
//!   child streams -> yields child objects, not files.
//!
//! [`FormatFactory`] covers all three through one `probe`/`mount` contract
//! and the [`Mounted`] result enum, so a single resolver
//! ([`crate::core::resolver::MountResolver`]) can recurse across them.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bridge::CancellationToken;
use crate::core::limits::{Limits, SpillStore};
use crate::core::locator::{EvidenceLocator, LocatorSegment};
use crate::err::ForensicResult;
use crate::field::{Field, Text};
use crate::traits::db::ForensicDb;
use crate::traits::digest::Digest;
use crate::traits::events::EventLogReader;
use crate::traits::registry::Registry;
use crate::traits::vfs::{FileSystem, VirtualFile};

/// What kind of thing a [`FormatFactory`] produces, or a resolved
/// [`Requirement`](crate::traits::forensic::Requirement) points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MountKind {
    FileSystem,
    Registry,
    Database,
    EventLog,
    Object,
    /// A located companion file (no interpretation applied).
    File,
}

/// The result of mounting one container/interpretation/embedding hop.
pub enum Mounted {
    /// Containment: a new addressable filesystem (a ZIP, an E01 volume, a
    /// triage tree).
    FileSystem(Arc<dyn FileSystem>),
    /// Interpretation: the same bytes read as a registry hive.
    Registry(Arc<dyn Registry>),
    /// Interpretation: the same bytes read as a database.
    Database(Arc<dyn ForensicDb>),
    /// Interpretation: the same bytes read as an event log.
    EventLog(Arc<dyn EventLogReader>),
    /// Embedding: a structured object exposing typed child streams (a PE, an
    /// OLE compound file, an LNK).
    Object(Arc<dyn StructuredObject>),
    /// A located companion file, addressed by its locator rather than an
    /// already-open handle -- the caller re-opens it through the
    /// `FileSystem` it already holds. Distinct from `Mounted::FileSystem`
    /// (which contains a whole new addressable tree): this result means
    /// only "here is where it is."
    File(EvidenceLocator),
}

impl Mounted {
    pub fn kind(&self) -> MountKind {
        match self {
            Mounted::FileSystem(_) => MountKind::FileSystem,
            Mounted::Registry(_) => MountKind::Registry,
            Mounted::Database(_) => MountKind::Database,
            Mounted::EventLog(_) => MountKind::EventLog,
            Mounted::Object(_) => MountKind::Object,
            Mounted::File(_) => MountKind::File,
        }
    }

    pub fn as_file_system(&self) -> Option<&Arc<dyn FileSystem>> {
        match self {
            Mounted::FileSystem(fs) => Some(fs),
            _ => None,
        }
    }

    pub fn as_registry(&self) -> Option<&Arc<dyn Registry>> {
        match self {
            Mounted::Registry(registry) => Some(registry),
            _ => None,
        }
    }

    pub fn as_database(&self) -> Option<&Arc<dyn ForensicDb>> {
        match self {
            Mounted::Database(db) => Some(db),
            _ => None,
        }
    }

    pub fn as_event_log(&self) -> Option<&Arc<dyn EventLogReader>> {
        match self {
            Mounted::EventLog(reader) => Some(reader),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&Arc<dyn StructuredObject>> {
        match self {
            Mounted::Object(object) => Some(object),
            _ => None,
        }
    }

    pub fn as_file(&self) -> Option<&EvidenceLocator> {
        match self {
            Mounted::File(locator) => Some(locator),
            _ => None,
        }
    }
}

impl Clone for Mounted {
    fn clone(&self) -> Self {
        match self {
            Mounted::FileSystem(fs) => Mounted::FileSystem(Arc::clone(fs)),
            Mounted::Registry(registry) => Mounted::Registry(Arc::clone(registry)),
            Mounted::Database(db) => Mounted::Database(Arc::clone(db)),
            Mounted::EventLog(reader) => Mounted::EventLog(Arc::clone(reader)),
            Mounted::Object(object) => Mounted::Object(Arc::clone(object)),
            Mounted::File(locator) => Mounted::File(locator.clone()),
        }
    }
}

/// How strongly a [`FormatFactory`] claims a byte stream is its format.
///
/// Not a `bool`: several factories can plausibly claim the same bytes (a
/// `.db` file could be SQLite, ESE, or a renamed archive), and the resolver
/// must pick deterministically -- highest score wins, ties broken by
/// [`FormatFactory::name`] (lexicographic), never by registration order,
/// which would make output depend on wiring order and break run-to-run
/// reproducibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProbeScore {
    /// Not this format.
    No,
    /// Plausible but weak evidence (e.g. a file extension, a loose
    /// structural heuristic).
    Weak,
    /// Strong evidence (e.g. matching magic bytes).
    Strong,
    /// Unambiguous (e.g. magic bytes plus a verified structural checksum).
    Exact,
}

/// Everything a [`FormatFactory`] is allowed to see and use while probing or
/// mounting one hop.
///
/// Deliberately carries both `fs` (the filesystem the target file lives in)
/// and `locator` (its position within it), not just the opened
/// [`VirtualFile`] alone -- an interpretation factory (SQLite, a registry
/// hive) commonly needs companion files beside its target (WAL/SHM,
/// `.LOG1`/`.LOG2`), which a bare byte stream cannot express.
pub struct MountContext<'a> {
    fs: &'a Arc<dyn FileSystem>,
    locator: &'a EvidenceLocator,
    limits: &'a Limits,
    depth: u32,
    spill: &'a dyn SpillStore,
    digest: Option<&'a (dyn Fn() -> Box<dyn Digest> + Send + Sync)>,
    cancellation: &'a CancellationToken,
}

impl<'a> MountContext<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fs: &'a Arc<dyn FileSystem>,
        locator: &'a EvidenceLocator,
        limits: &'a Limits,
        depth: u32,
        spill: &'a dyn SpillStore,
        digest: Option<&'a (dyn Fn() -> Box<dyn Digest> + Send + Sync)>,
        cancellation: &'a CancellationToken,
    ) -> Self {
        Self {
            fs,
            locator,
            limits,
            depth,
            spill,
            digest,
            cancellation,
        }
    }

    /// The filesystem the target being probed/mounted lives in -- for
    /// reaching companion files beside it.
    pub fn fs(&self) -> &Arc<dyn FileSystem> {
        self.fs
    }

    /// This hop's position in the evidence chain.
    pub fn locator(&self) -> &EvidenceLocator {
        self.locator
    }

    pub fn limits(&self) -> &Limits {
        self.limits
    }

    /// Nesting depth of this hop (0 = the top-level evidence item).
    pub fn depth(&self) -> u32 {
        self.depth
    }

    pub fn spill(&self) -> &dyn SpillStore {
        self.spill
    }

    /// A fresh digest instance, if the resolver was configured with one.
    /// `None` means content interning falls back to depth + byte budget
    /// only.
    pub fn new_digest(&self) -> Option<Box<dyn Digest>> {
        self.digest.map(|make| make())
    }

    pub fn cancellation(&self) -> &CancellationToken {
        self.cancellation
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

/// Sniffs and mounts a nested container, interpretation, or embedded object
/// out of an opened file.
///
/// Replaces `FileSystemFactory`, `ForensicDbFactory`, `EventLogReaderFactory`,
/// and `RegistryReaderFactory` with one contract so
/// [`crate::core::resolver::MountResolver`] can recurse across container,
/// interpretation, and embedding hops uniformly.
pub trait FormatFactory: Send + Sync {
    fn name(&self) -> &'static str;

    /// What kind of [`Mounted`] this factory produces on success. Declared
    /// up front so the resolver can pre-filter candidates by what a
    /// [`crate::traits::forensic::Requirement`] actually needs, without
    /// calling `probe`.
    fn yields(&self) -> MountKind;

    /// Content-based sniff. Must restore the stream position before
    /// returning, on every path including an error return.
    fn probe(&self, file: &mut dyn VirtualFile, ctx: &MountContext<'_>) -> ForensicResult<ProbeScore>;

    /// Mount the file as this factory's [`MountKind`]. Only called after
    /// this factory won the deterministic tie-break among every factory
    /// that returned better than [`ProbeScore::No`].
    fn mount(&self, file: Box<dyn VirtualFile>, ctx: &MountContext<'_>) -> ForensicResult<Mounted>;
}

/// A structured object exposing typed child streams -- the "embedding"
/// relationship (a PE's resources, an OLE compound file's streams, an LNK's
/// embedded structures).
///
/// Deliberately thin: core knows only that children exist and how to open
/// them, never what a PE resource *means*. `attributes()` lets a downstream
/// parser (e.g. a PE parser) surface untyped facts -- compile timestamp,
/// section names, a signer -- that core neither validates nor interprets.
pub trait StructuredObject: Send + Sync {
    /// A short format tag ("pe", "ole", "lnk"), for logging and dispatch.
    fn kind(&self) -> &'static str;

    /// Enumerate this object's children, if any.
    fn children(&self) -> ForensicResult<Vec<(LocatorSegment, MountKind)>>;

    /// Open one child's bytes, for further probing/mounting by the
    /// resolver.
    fn open_child(&self, segment: &LocatorSegment) -> ForensicResult<Box<dyn VirtualFile>>;

    /// Untyped, uninterpreted metadata about this object. Empty by default
    /// -- most `StructuredObject` implementations expose only children.
    fn attributes(&self) -> BTreeMap<Text, Field> {
        BTreeMap::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepts_format_factory(_factory: &dyn FormatFactory) {}
    fn accepts_structured_object(_object: &dyn StructuredObject) {}

    #[test]
    fn format_factory_and_structured_object_are_object_safe() {
        let _ = accepts_format_factory;
        let _ = accepts_structured_object;
    }

    #[test]
    fn probe_score_orders_no_below_weak_below_strong_below_exact() {
        assert!(ProbeScore::No < ProbeScore::Weak);
        assert!(ProbeScore::Weak < ProbeScore::Strong);
        assert!(ProbeScore::Strong < ProbeScore::Exact);
    }

    #[test]
    fn mounted_kind_matches_the_variant_constructed() {
        use crate::utils::testing::InMemoryVirtualFileSystem;
        let mounted = Mounted::FileSystem(Arc::new(InMemoryVirtualFileSystem::new()));
        assert_eq!(mounted.kind(), MountKind::FileSystem);
        assert!(mounted.as_file_system().is_some());
        assert!(mounted.as_registry().is_none());
    }

    #[test]
    fn mounted_clone_shares_the_underlying_arc() {
        use crate::utils::testing::InMemoryVirtualFileSystem;
        let inner: Arc<dyn FileSystem> = Arc::new(InMemoryVirtualFileSystem::new());
        let mounted = Mounted::FileSystem(Arc::clone(&inner));
        let cloned = mounted.clone();
        assert_eq!(Arc::strong_count(&inner), 3); // inner + mounted + cloned
        drop(mounted);
        drop(cloned);
        assert_eq!(Arc::strong_count(&inner), 1);
    }
}
