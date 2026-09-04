use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use crate::artifact::Artifact;
use crate::field::Text;
use crate::pipeline::context::ParseContext;
use crate::secrets::SecretKind;
use crate::traits::db::ForensicDb;
use crate::traits::format::Mounted;
use crate::{
    activity::ForensicActivity,
    prelude::{ForensicData, ForensicResult},
    utils::time::ForensicTimestamp,
};

/// Quickly transform a structure into one or more events that are part of a timeline
/// ```rust,ignore
/// impl<'a> IntoTimeline<'a> for PrefetchFile {
///     fn timeline(&'a self) -> Self::IntoIter {
///         PrefetchTimelineIterator {
///             prefetch : self,
///             time_pos : 0
///         }
///     }
///
///     type IntoIter = PrefetchTimelineIterator<'a> where Self: 'a;
/// }
/// ```
pub trait IntoTimeline<'a> {
    type IntoIter: Iterator<Item = ForensicResult<TimelineData>>
    where
        Self: 'a;

    fn timeline(&'a self) -> Self::IntoIter;
}

/// Quickly transform a structure into one or more user activity events. In order to know what a user did at a high level at a specific moment.
///
/// Example: `ForensicActivity { timestamp: 06-11-2023 15:18:00.237, user: "", session_id: Unknown, activity: ProgramExecution(\VOLUME{01d98a6b9e4a0a35-1c9e547d}\WINDOWS\SYSWOW64\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE) }`
///
/// ```rust,ignore
/// impl<'a> IntoActivity<'a> for PrefetchFile {
///     fn activity(&'a self) -> Self::IntoIter {
///         PrefetchActivityIterator {
///             prefetch : self,
///             time_pos : 0
///         }
///     }
///
///     type IntoIter = PrefetchActivityIterator<'a> where Self: 'a;
/// }
/// ```
pub trait IntoActivity<'a> {
    type IntoIter: Iterator<Item = ForensicResult<ForensicActivity>>
    where
        Self: 'a;

    fn activity(&'a self) -> Self::IntoIter;
}

#[derive(Clone, Debug, Default)]
pub enum TimeContext {
    #[default]
    Creation,
    Modification,
    Accessed,
    Other(Cow<'static, str>),
}

#[derive(Clone, Debug)]
pub struct TimelineData {
    pub time: ForensicTimestamp,
    pub data: ForensicData,
    pub time_context: TimeContext,
}

/// Stable identity and capability declaration for one [`ArtifactParserFactory`].
///
/// `id` is the registration key: it is what [`crate::pipeline::registry::ParserRegistry`]
/// maps to a parser and the same namespace
/// [`crate::capabilities::AccessRequirements::parser`] authorizes against.
/// Namespace it (`"windows.amcache"`, `"linux.journal"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserDescriptor {
    pub id: Text,
    pub title: Text,
    pub description: Text,
    pub version: Text,
    /// Artifact types this parser produces. **Empty means "all"** — the same
    /// convention [`crate::pipeline::traits::Analyzer::supported_artifacts`]
    /// already uses.
    pub artifacts: Cow<'static, [Artifact]>,
    /// What this parser needs beyond a bare VFS/registry handle — a
    /// companion file, a database of a given shape, a fact from an earlier
    /// resolve pass, an externally supplied secret. Empty means "just the
    /// bytes named by `open()`", the historical default. Declared here,
    /// introspectable without calling `open()`, so a resolver can check
    /// availability up front and a coverage report can explain *why* a
    /// parser did not run instead of staying silent about it. See
    /// [`Requirement`].
    pub requirements: Cow<'static, [Requirement]>,
}

impl ParserDescriptor {
    pub fn new(
        id: impl Into<Text>,
        title: impl Into<Text>,
        description: impl Into<Text>,
        version: impl Into<Text>,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            description: description.into(),
            version: version.into(),
            artifacts: Cow::Borrowed(&[]),
            requirements: Cow::Borrowed(&[]),
        }
    }

    pub fn with_artifacts(mut self, artifacts: impl Into<Cow<'static, [Artifact]>>) -> Self {
        self.artifacts = artifacts.into();
        self
    }

    pub fn with_requirements(mut self, requirements: impl Into<Cow<'static, [Requirement]>>) -> Self {
        self.requirements = requirements.into();
        self
    }

    /// Whether this parser is relevant to `artifact`. Empty `artifacts`
    /// matches everything — centralizes the "empty = all" rule that used to
    /// be open-coded at every auto-match call site.
    pub fn handles(&self, artifact: &Artifact) -> bool {
        self.artifacts.is_empty() || self.artifacts.contains(artifact)
    }
}

/// A fully-owned record stream. No lifetime parameter by construction: it
/// cannot borrow the factory, the [`ParseContext`], or the `TriageSources`
/// that produced it.
pub type ArtifactStream = Box<dyn Iterator<Item = ForensicResult<ForensicData>>>;

/// Where a push-mode parser sends records. Implemented by the pipeline,
/// never by parser authors. Named `ParserOutput`, not `RecordSink`, to stay
/// unmistakable from [`crate::pipeline::traits::TriageSink`] (the *report*
/// sink, downstream of this one).
pub trait ParserOutput {
    fn emit(&mut self, record: ForensicResult<ForensicData>) -> OutputFlow;
}

/// What a [`ParserOutput::emit`] call means for the parser driving it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFlow {
    /// Keep going.
    Continue,
    /// The consumer is done (cancellation, `ErrorAction::Halt`, downstream
    /// closed). Stop parsing and return `Ok(())` — this is not an error.
    Stop,
}

impl OutputFlow {
    pub fn is_stop(self) -> bool {
        matches!(self, OutputFlow::Stop)
    }
}

/// A [`ParserRun::Push`] driver closure: given the pipeline's output sink,
/// pushes records into it and returns whether the parser completed cleanly.
pub type PushDriver = Box<dyn FnOnce(&mut dyn ParserOutput) -> ForensicResult<()>>;

/// How one parse run delivers records.
pub enum ParserRun {
    /// The parser hands back an owned iterator; the pipeline drives it and
    /// keeps unilateral control of stopping.
    Pull(ArtifactStream),
    /// The parser drives its own loop — the escape hatch for readers that
    /// return borrowed cursors (a registry key, a database row cursor, an
    /// event-log iterator). The whole borrow chain lives inside the
    /// closure's stack frame, so nothing self-referential is ever stored.
    /// Must honour [`OutputFlow::Stop`]; should poll [`ParseContext::cancellation`]
    /// during long stretches between emits.
    Push(PushDriver),
}

impl ParserRun {
    pub fn pull(it: impl Iterator<Item = ForensicResult<ForensicData>> + 'static) -> Self {
        ParserRun::Pull(Box::new(it))
    }
    pub fn push(
        f: impl FnOnce(&mut dyn ParserOutput) -> ForensicResult<()> + 'static,
    ) -> Self {
        ParserRun::Push(Box::new(f))
    }
}

/// Core trait for artifact parsers in the forensic pipeline.
///
/// A factory is stateless and `&self`: one instance behind an `Arc` serves
/// the serial pipeline, every parallel worker, and every `AnalysisModule`
/// that needs it. All parse-local state (open hives, byte buffers, borrowed
/// iterators) lives in the stack frame of [`ArtifactParserFactory::open`] or
/// the [`ParserRun::Push`] closure it returns — never in `self`.
///
/// # Example — pull (the common case, an owned iterator)
/// ```rust,ignore
/// impl ArtifactParserFactory for EvtxParserFactory {
///     fn descriptor(&self) -> &ParserDescriptor { &DESCRIPTOR }
///
///     fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
///         let records: Vec<_> = read_all_records(ctx)?;
///         Ok(ParserRun::pull(records.into_iter().map(Ok)))
///     }
/// }
/// ```
///
/// # Example — push (a reader that returns borrowed cursors)
/// ```rust,ignore
/// impl ArtifactParserFactory for AmCacheParserFactory {
///     fn descriptor(&self) -> &ParserDescriptor { &DESCRIPTOR }
///
///     fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
///         let fs = Arc::clone(ctx.vfs()?);
///         let host: Text = ctx.host().to_string().into();
///         let source = ctx.register_source(SourceKey::Path(hive_path()));
///         let acquisition = ctx.acquisition();
///         Ok(ParserRun::push(move |out| {
///             let reader = open_amcache(&fs)?; // a plain local — the whole point
///             for entry in reader.applications()? {
///                 if out.emit(Ok(map(&host, &source, acquisition, entry))).is_stop() {
///                     return Ok(());
///                 }
///             }
///             Ok(())
///         }))
///     }
/// }
/// ```
pub trait ArtifactParserFactory: Send + Sync {
    fn descriptor(&self) -> &ParserDescriptor;
    /// Whether the artifacts this parser needs are present. `true` by
    /// default — override to skip parsing when they are absent.
    fn can_parse(&self, _ctx: &ParseContext<'_>) -> bool {
        true
    }
    /// Open this parser's data source and choose how it will deliver
    /// records. The one required method.
    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun>;
}

// ============================================================================
// Requirements and resolution
// ============================================================================
//
// The direct answer to "a SQLite parser is not a Chromium parser": a
// low-level format factory only knows how to open bytes as a database; the
// artifact parser that interprets those rows as browser history declares
// what it *needs* (a companion file, a database of a given shape, a fact,
// a secret) and asks `ParseContext::resolve` for it, instead of hand-rolling
// discovery against `vfs()`/`registry()` directly.

/// A glob-style target specification for a file a parser needs, typically
/// beside its main artifact (e.g. Chromium's `Local State`, a hive's
/// `.LOG1`/`.LOG2`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TargetSpec {
    /// A glob pattern, resolved relative to the evidence root (see
    /// [`crate::core::fs::glob`]).
    pub glob: Text,
    pub description: Text,
}

impl TargetSpec {
    pub fn new(glob: impl Into<Text>, description: impl Into<Text>) -> Self {
        Self {
            glob: glob.into(),
            description: description.into(),
        }
    }
}

/// A registry key path a parser needs (e.g.
/// `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeySpec {
    pub path: Text,
}

impl KeySpec {
    pub fn new(path: impl Into<Text>) -> Self {
        Self { path: path.into() }
    }
}

/// An event log channel a parser needs (e.g. `"Security"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChannelSpec {
    pub channel: Text,
}

impl ChannelSpec {
    pub fn new(channel: impl Into<Text>) -> Self {
        Self {
            channel: channel.into(),
        }
    }
}

/// Identifies a database by the shape of a required subset of its schema
/// (table names and, per table, required column names), rather than by
/// filename.
///
/// A file named `History` is Chromium's schema today and a dozen other
/// things tomorrow; a file named `places.sqlite` is Firefox until someone
/// renames it. Matching a *required subset* rather than schema equality
/// means upstream column additions (a browser version bump) do not break
/// the match, while a genuinely different schema — or a same-named file
/// that fails to match at all — is a detectable, reportable condition
/// instead of a silent wrong-column read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SchemaFingerprint {
    required: BTreeMap<String, BTreeSet<String>>,
}

impl SchemaFingerprint {
    pub fn new() -> Self {
        Self::default()
    }

    /// Requires `table` to exist with at least the given columns (case
    /// preserved for lookup against the backend, compared
    /// case-insensitively per [`ForensicDb::table`]'s own convention).
    #[must_use]
    pub fn require_table(
        mut self,
        table: impl Into<String>,
        columns: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.required
            .entry(table.into())
            .or_default()
            .extend(columns.into_iter().map(Into::into));
        self
    }

    /// A deterministic hash of the required shape (sorted table then column
    /// names), for logging, dedup keys, and cache lookups — not for
    /// matching, which always re-checks the real schema via [`Self::matches`].
    pub fn fingerprint(&self) -> u64 {
        let mut buf = Vec::new();
        for (table, columns) in &self.required {
            buf.extend_from_slice(table.as_bytes());
            buf.push(0);
            for column in columns {
                buf.extend_from_slice(column.as_bytes());
                buf.push(0);
            }
            buf.push(0xff);
        }
        crate::core::fnv1a64(&buf)
    }

    /// Whether `db` contains every required table with every required
    /// column, matched case-insensitively (ASCII).
    pub fn matches(&self, db: &dyn ForensicDb) -> ForensicResult<bool> {
        let tables = db.list_all_tables()?;
        for (required_table, required_columns) in &self.required {
            let Some(actual_name) = tables
                .iter()
                .find(|name| name.eq_ignore_ascii_case(required_table))
            else {
                return Ok(false);
            };
            let handle = db.table(actual_name)?;
            let have: BTreeSet<String> = handle
                .columns()
                .iter()
                .map(|c| c.name.to_ascii_lowercase())
                .collect();
            for column in required_columns {
                if !have.contains(&column.to_ascii_lowercase()) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

/// What an [`ArtifactParserFactory`] needs beyond a bare VFS/registry
/// handle, declared on [`ParserDescriptor::requirements`] and resolved via
/// [`ParseContext::resolve`](crate::pipeline::context::ParseContext::resolve).
///
/// `#[non_exhaustive]`: `Fact(FactKind)` — a value produced by an earlier
/// resolve pass over a `HostProfile` (SID→username maps, DPAPI master
/// keys, timezone) — is a deferred-phase addition; declaring this
/// non-exhaustive now means adding it later is not a breaking change.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Requirement {
    /// A companion file, typically beside the parser's main target.
    File(TargetSpec),
    /// A database matching a required schema subset.
    Database(SchemaFingerprint),
    /// A registry key.
    Registry(KeySpec),
    /// An event log channel.
    EventLog(ChannelSpec),
    /// Externally supplied key material.
    Secret(SecretKind),
}

/// The outcome of resolving one [`Requirement`].
pub enum Resolution {
    Resolved(Mounted),
    Unavailable(UnavailableReason),
}

impl Resolution {
    pub fn is_resolved(&self) -> bool {
        matches!(self, Resolution::Resolved(_))
    }

    pub fn mounted(self) -> Option<Mounted> {
        match self {
            Resolution::Resolved(mounted) => Some(mounted),
            Resolution::Unavailable(_) => None,
        }
    }
}

/// Why a [`Requirement`] could not be resolved.
///
/// `NotCollected` vs `NotPresent` is the answer to the question
/// [`crate::traits::vfs::SourceKind::Triage`] raises but cannot itself
/// settle: whether an absence means "outside what the collector was told to
/// gather" or "gathered for, genuinely not there" — answerable once a
/// collection manifest (a deferred-phase addition) is available; until
/// then, resolvers should prefer `NotPresent` and let the caller narrow it.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnavailableReason {
    /// Outside the collection's declared target list.
    NotCollected,
    /// Was a collection target, but genuinely absent from the evidence.
    NotPresent,
    /// Present, but access was denied by policy.
    Denied,
    /// No registered `FormatFactory` claims to produce what was asked for.
    Unsupported,
    /// A resource budget (`crate::core::limits::Limits`) would be exceeded.
    BudgetExceeded,
    /// A required `Secret` was not supplied by the configured
    /// `SecretProvider`.
    SecretUnavailable,
    /// A `FormatFactory` claimed the bytes but `mount()` failed.
    MountFailed,
}

#[cfg(test)]
mod requirement_tests {
    use super::*;
    use crate::utils::testing::{InMemoryForensicDb, InMemoryTable};
    use crate::traits::db::ForensicColumnType;

    fn sample_db() -> InMemoryForensicDb {
        let table = InMemoryTable::new("logins")
            .with_column("origin_url", ForensicColumnType::Text, false)
            .with_column("password_value", ForensicColumnType::Binary, false);
        InMemoryForensicDb::new().with_table(table)
    }

    #[test]
    fn schema_fingerprint_matches_required_subset() {
        let db = sample_db();
        let fp = SchemaFingerprint::new().require_table("logins", ["origin_url"]);
        assert!(fp.matches(&db).unwrap());
    }

    #[test]
    fn schema_fingerprint_matches_case_insensitively() {
        let db = sample_db();
        let fp = SchemaFingerprint::new().require_table("LOGINS", ["Origin_URL"]);
        assert!(fp.matches(&db).unwrap());
    }

    #[test]
    fn schema_fingerprint_rejects_missing_table() {
        let db = sample_db();
        let fp = SchemaFingerprint::new().require_table("cookies", ["value"]);
        assert!(!fp.matches(&db).unwrap());
    }

    #[test]
    fn schema_fingerprint_rejects_missing_column() {
        let db = sample_db();
        let fp = SchemaFingerprint::new().require_table("logins", ["does_not_exist"]);
        assert!(!fp.matches(&db).unwrap());
    }

    #[test]
    fn schema_fingerprint_tolerates_extra_columns_not_required() {
        // Schema drift (an upstream browser adding a column) must not break
        // an existing match on the columns actually required.
        let db = sample_db();
        let fp = SchemaFingerprint::new().require_table("logins", ["origin_url"]);
        assert!(fp.matches(&db).unwrap());
    }

    #[test]
    fn schema_fingerprint_is_stable_across_instances() {
        let a = SchemaFingerprint::new().require_table("logins", ["origin_url", "password_value"]);
        let b = SchemaFingerprint::new().require_table("logins", ["password_value", "origin_url"]);
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn schema_fingerprint_differs_for_different_shapes() {
        let a = SchemaFingerprint::new().require_table("logins", ["origin_url"]);
        let b = SchemaFingerprint::new().require_table("cookies", ["origin_url"]);
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn resolution_mounted_extracts_the_resolved_value() {
        use crate::traits::format::Mounted;
        use crate::utils::testing::InMemoryVirtualFileSystem;
        use std::sync::Arc;

        let resolution = Resolution::Resolved(Mounted::FileSystem(Arc::new(
            InMemoryVirtualFileSystem::new(),
        )));
        assert!(resolution.is_resolved());
        assert!(resolution.mounted().is_some());
    }

    #[test]
    fn resolution_unavailable_carries_no_mount() {
        let resolution = Resolution::Unavailable(UnavailableReason::NotPresent);
        assert!(!resolution.is_resolved());
        assert!(resolution.mounted().is_none());
    }
}
