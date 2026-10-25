//! A framework for building forensic artifact analysis tools that can be reused as libraries,
//! unchanged, across many projects.
//!
//! The core idea is to separate *analysis* from *data access*. An analyzer that reads registry
//! keys, files, database rows or event-log records is written against a trait, so the same code
//! runs on a live system, a parsed hive or disk image, a triage ZIP, or a mock in a unit test.
//!
//! ```
//! use forensic_rs::prelude::*;
//! use forensic_rs::utils::testing::TestingRegistry;
//!
//! // Works on any `Registry` backend: live API, hive parser, memory image, test double.
//! fn product_name(reg: &dyn Registry) -> ForensicResult<String> {
//!     let key = reg.key(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion")?;
//!     key.value("ProductName")?.try_into()
//! }
//!
//! let registry = TestingRegistry::new();
//! let _ = product_name(&registry);
//! ```
//!
//! # Where to start
//!
//! - [`prelude`]: everything a consumer normally needs, in one `use`.
//! - Evidence sources: [`traits::vfs`] (`FileSystem`), [`traits::registry`] (`Registry`),
//!   [`traits::db`] (`ForensicDb`), [`traits::events`] (`EventLogReader`), and [`memory`]
//!   (`MemoryImage`). Each has a minimal, object-safe core trait that backends implement and a
//!   blanket-implemented `Ext` trait with the convenience API callers use.
//! - Nested evidence (an archive inside an image inside a volume): [`traits::format`]
//!   (`FormatFactory`) and [`core::resolver`] (`MountResolver`).
//! - Running parsers and analyzers over evidence: [`pipeline`].
//! - Where a value came from and how far to trust it: [`provenance`]. Recovered and carved
//!   records: [`recovery`].
//! - Exposing sources as MCP tools and resources with per-caller authorization:
//!   [`capabilities`].
//! - Test doubles for every source trait: [`utils::testing`].
//!
//! # Features
//!
//! - `serde` (default): `Serialize`/`Deserialize` on data types, the JSONL sinks, and
//!   provenance side tables.

pub mod activity;
pub mod artifact;
pub mod bridge;
pub mod capabilities;
pub mod catalog;
pub mod channel;
pub mod collection;
pub mod context;
pub mod core;
pub mod coverage;
pub mod data;
pub mod dictionary;
pub mod entity;
pub mod err;
pub mod evidence;
pub mod fact_store;
pub mod field;
pub mod host_profile;
pub mod investigation;
pub mod logging;
pub mod memory;
pub mod parsing;
pub mod pipeline;
pub mod provenance;
pub mod recovery;
pub mod secrets;
pub mod traits;
pub mod utils;

pub mod prelude {
    pub use crate::artifact::*;
    // `catalog::expand` is not re-exported: it would clash with the serde
    // feature's `provenance::expand`. Call it as `catalog::expand`.
    pub use crate::catalog::{
        ArtifactCatalog, ArtifactDefinition, ArtifactResolution, ArtifactSource, CatalogIndexEntry,
        ExpandedGlob, ExpandedKey, ExpandedValue, Expansion, FoundBy, LocatedFile, LocatedFiles,
        Os, RegistryValueRef, ResolvedFile, ResolvedKey, ResolvedValue, Separator, SliceCatalog,
        SourceEntry, UnresolvedSource,
    };
    pub use crate::context::initialize_context;
    pub use crate::core::fs::glob::GlobOutcome;
    pub use crate::core::fs::{
        ChRootFileSystem, ConcatReadAt, ContainerFs, DescentPolicy, MountTable, OverlayFs,
        ReadAtFile, SplitRawFactory, StdVirtualFS, StdVirtualFile, WindowReadAt, into_read_at,
    };
    pub use crate::core::limits::{LimitExceeded, Limits, MemorySpillStore, SpillStore};
    pub use crate::core::locator::{EvidenceLocator, LocatorSegment};
    pub use crate::core::path::{FPath, FPathBuf};
    pub use crate::core::resolver::{MountResolver, MountResolverBuilder};
    pub use crate::data::*;
    pub use crate::dictionary::*;
    pub use crate::err::*;
    pub use crate::field::{Field, FieldAccess, Ip, Text, text, text_owned};
    pub use crate::logging::{
        Level, Message, enabled_level, initialize_logger, max_level, set_max_level,
    };
    pub use crate::parsing::{ByteReader, FromBytes, read_to_reader};
    #[cfg(feature = "serde")]
    pub use crate::pipeline::sinks::{JsonlFindingSink, JsonlTimelineSink, ProvenanceJsonlSink};
    pub use crate::pipeline::{
        ErrorAction, PipelineResult, TriagePipeline, TriagePipelineBuilder,
        context::{ParseContext, SourceView, TriageContext},
        finding::{Finding, FindingCategory, FindingSeverity},
        inventory::{ContainerInventoryParser, RECORD_TYPE_CONTAINER, RECORD_TYPE_MEMBER},
        parallel::{
            AnalysisModule, AnalysisModuleBuilder, ParallelPipeline, ParallelPipelineBuilder,
            ParallelPipelineResult, ParallelPipelineTask, PipelineEvent, StandardParallelTask,
            StandardParallelTaskBuilder, TaskStats,
        },
        registry::ParserRegistry,
        registry_collector::RegistryCollector,
        sinks::{FindingCollector, TimelineSink},
        sources::TriageSources,
        sources::TriageSourcesBuilder,
        timeline::{
            EventId, InMemoryTimelineStore, InsertOutcome, TimelineRecordSink, TimelineStore,
        },
        traits::{Analyzer, Enricher, TriageSink},
    };
    pub use crate::traits::db::{
        EmptyRows, ForensicColumnDef, ForensicColumnType, ForensicDb, ForensicRow, ForensicRows,
        ForensicTable, ForensicValue, ForensicValueRef, RecoverRows, RowIterator, SqlCapable,
    };
    pub use crate::traits::digest::{ContentAddress, Digest, DigestAlgorithm};
    pub use crate::traits::forensic::{
        ArtifactParserFactory, ArtifactRef, ArtifactStream, ChannelSpec, IntoActivity,
        IntoTimeline, KeySpec, OutputFlow, ParserDescriptor, ParserOutput, ParserRun, PushDriver,
        Requirement, Resolution, SchemaFingerprint, TargetSpec, TimeContext, TimelineData,
        UnavailableReason,
    };
    pub use crate::traits::format::{
        FileSet, FileSetMember, FileSetRole, FormatFactory, HopCost, MountContext, MountKind,
        Mounted, ProbeScore, StructuredObject,
    };
    pub use crate::traits::registry::windows;
    pub use crate::traits::registry::*;
    pub use crate::traits::vfs::{
        AlternateStreams, CaseSensitivity, DeletedEntry, DeletedFiles, DirEntry, FileAttributes,
        FileId, FileSystem, FileSystemExt, MacbTimes, MediaMap, MediaOffset, PathAttributes,
        ReadAt, Region, SourceKind, StreamInfo, Unallocated, VFileType, VirtualFile,
    };
    pub use crate::utils::time::{
        Filetime, ForensicTimestamp, Timestamp128, TimestampFlags, TimestampPrecision,
        TimestampSource, UnixTimestamp, WinFiletime, filetime_to_unix_timestamp,
    };
    pub use crate::{debug, error, info, log, trace, warn};
    pub use compact_str::CompactString;
    // Events trait
    pub use crate::traits::events::{
        EventLevel, EventLogIterator, EventLogQuery, EventLogReader, EventRecord,
    };
    // Bridge
    pub use crate::bridge::client::BridgeClient;
    pub use crate::bridge::hooks::ProviderHook;
    pub use crate::bridge::providers::{
        DatabaseProvider, EventLogProvider, RegistryProvider, VfsProvider,
    };
    pub use crate::bridge::server::{ForensicBridge, ForensicBridgeBuilder};
    pub use crate::bridge::{
        BridgeResponse, BridgeValue, CancellationToken, DataOrigin, ForensicProvider, NodeEntry,
        NodeType,
    };
    pub use crate::capabilities::{
        AccessAuditEvent, AccessAuditSink, AccessContext, AccessDecision, AccessKind, AccessPolicy,
        AccessRequest, AccessRequirements, AllowAllPolicy, AuditedAccessPolicy,
        AuthorizedEventLogReader, AuthorizedForensicDb, AuthorizedPipelineContext,
        AuthorizedRegistryReader, AuthorizedSourceFactory, AuthorizedVirtualFileSystem,
        BridgeResourceProvider, CapabilityError, CapabilityErrorKind, CapabilityRegistry,
        CapabilityResult, CapabilityValue, DenyAllPolicy, ForensicTool, InvocationContext,
        NoopProgressReporter, ObjectSchema, Page, PageRequest, PipelineSourceKind,
        PipelineTaskFactory, PipelineTaskTool, ProgressReporter, ProgressUpdate, ResourceContent,
        ResourceEntry, ResourceId, ResourceKind, ResourceMetadata, ResourceProvider,
        ResourceProviderDescriptor, ScopedCapabilityRegistry, ToolContent, ToolDescriptor,
        ToolHints, ToolResult, ValueSchema, ValueType,
    };
    pub use crate::collection::{
        CollectionError, CollectionManifest, StaticCollectionManifest, ToolIdentity,
    };
    pub use crate::coverage::{CoverageGap, CoverageGapReason, CoverageReport};
    pub use crate::entity::{EntityId, EntityKind};
    pub use crate::evidence::{EvidenceItem, EvidenceItemId, EvidenceSet};
    pub use crate::fact_store::{
        FactObservation, FactRecord, FactStore, InMemoryFactStore, ObservationOutcome,
    };
    pub use crate::host_profile::HostProfile;
    pub use crate::investigation::{Investigation, InvestigationId, TenantId};
    pub use crate::memory::{
        AddressSpace, AddressSpaceExt, Backing, Bounded, InvalidReason, MemHandle, MemIter,
        MemLocation, MemModule, MemOsInfo, MemProcess, MemRecordKey, MemRecordKind, MemRecordMeta,
        MemRegion, MemThread, MemValue, MemoryImage, MemoryImageExt, MemoryInputInfo, MemorySpec,
        Pa, PageSize, PagingFile, PagingFiles, PhysRange, PhysicalMemory, ReadReport, RecordSource,
        RegionKind, SpaceId, Translation, Va, Validity,
    };
    pub use crate::provenance::{
        Acquisition, Anomalies, AnomalyDetail, AnomalyFlags, Confidence, DerivedFrom, Locus,
        MergeReason, Parsed, Provenance, ProvenanceId, ProvenanceSnapshot, ProvenanceStore,
        Recovery, SourceHandle, SourceId, SourceKey, Tracked,
    };
    #[cfg(feature = "serde")]
    pub use crate::provenance::{
        ExpandedDerivedFrom, ExpandedProvenance, ProvenanceSideTable, expand,
    };
    pub use crate::recovery::{Recovered, RecoveryReport, looks_like_padding, slack_regions};
    pub use crate::secrets::{Secret, SecretKind, SecretProvider, SecretRequest};
    /// Test-double implementations of this crate's traits (`TestingRegistry`,
    /// `InMemoryVirtualFileSystem`, `TestParserBuilder`, `InMemoryForensicDb`,
    /// `TestingProviderHook`, factory wrappers, ...) for downstream crates
    /// writing tests against `forensic-rs` traits. Always compiled, not
    /// feature-gated. Namespaced deliberately — `use
    /// forensic_rs::prelude::testing::*;` in a `#[cfg(test)]` module, not part
    /// of the top-level prelude glob.
    pub use crate::utils::testing;
}
