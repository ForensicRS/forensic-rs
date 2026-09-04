pub mod activity;
pub mod artifact;
pub mod bridge;
pub mod capabilities;
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
pub mod parsing;
pub mod pipeline;
pub mod provenance;
pub mod secrets;
pub mod traits;
pub mod utils;

pub mod prelude {
    pub use crate::artifact::*;
    pub use crate::context::initialize_context;
    pub use crate::core::fs::{ChRootFileSystem, MountTable, OverlayFs, StdVirtualFS, StdVirtualFile};
    pub use crate::core::limits::{LimitExceeded, Limits, MemorySpillStore, SpillStore};
    pub use crate::core::locator::{EvidenceLocator, LocatorSegment};
    pub use crate::core::path::{FPath, FPathBuf};
    pub use crate::core::resolver::{MountResolver, MountResolverBuilder};
    pub use crate::data::*;
    pub use crate::dictionary::*;
    pub use crate::err::*;
    pub use crate::field::{text, text_owned, Field, FieldAccess, Ip, Text};
    pub use crate::logging::{
        enabled_level, initialize_logger, max_level, set_max_level, Level, Message,
    };
    pub use crate::parsing::{read_to_reader, ByteReader, FromBytes};
    #[cfg(feature = "serde")]
    pub use crate::pipeline::sinks::{JsonlFindingSink, JsonlTimelineSink};
    pub use crate::pipeline::{
        context::{ParseContext, TriageContext},
        finding::{Finding, FindingCategory, FindingSeverity},
        parallel::{
            AnalysisModule, AnalysisModuleBuilder, ParallelPipeline, ParallelPipelineBuilder,
            ParallelPipelineResult, ParallelPipelineTask, PipelineEvent, StandardParallelTask,
            StandardParallelTaskBuilder, TaskStats,
        },
        registry::ParserRegistry,
        sinks::{FindingCollector, TimelineSink},
        sources::TriageSources,
        sources::TriageSourcesBuilder,
        timeline::{EventId, InMemoryTimelineStore, InsertOutcome, TimelineRecordSink, TimelineStore},
        traits::{Analyzer, Enricher, TriageSink},
        ErrorAction, PipelineResult, TriagePipeline, TriagePipelineBuilder,
    };
    pub use compact_str::CompactString;
    pub use crate::traits::db::{
        ForensicColumnDef, ForensicColumnType, ForensicDb, ForensicRow, ForensicRows,
        ForensicTable, ForensicValue, ForensicValueRef, RowIterator, SqlCapable,
    };
    pub use crate::traits::digest::{ContentAddress, Digest, DigestAlgorithm};
    pub use crate::traits::format::{
        FormatFactory, MountContext, MountKind, Mounted, ProbeScore, StructuredObject,
    };
    pub use crate::traits::forensic::{
        ArtifactParserFactory, ArtifactStream, ChannelSpec, IntoActivity, IntoTimeline, KeySpec,
        OutputFlow, ParserDescriptor, ParserOutput, ParserRun, PushDriver, Requirement, Resolution,
        SchemaFingerprint, TargetSpec, TimeContext, TimelineData, UnavailableReason,
    };
    pub use crate::traits::registry::*;
    pub use crate::traits::registry::windows;
    pub use crate::traits::vfs::{
        AlternateStreams, CaseSensitivity, DirEntry, FileAttributes, FileId, FileSystem,
        FileSystemExt, MacbTimes, Region, SourceKind, StreamInfo, Unallocated, VFileType,
        VirtualFile,
    };
    pub use crate::utils::time::{
        filetime_to_unix_timestamp, Filetime, ForensicTimestamp, Timestamp128, TimestampFlags,
        TimestampPrecision, TimestampSource, UnixTimestamp, WinFiletime,
    };
    pub use crate::{debug, error, info, log, trace, warn};
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
    pub use crate::provenance::{
        Acquisition, AnomalyDetail, AnomalyFlags, Anomalies, Confidence, DerivedFrom, Locus,
        MergeReason, Parsed, Provenance, ProvenanceId, ProvenanceSnapshot, ProvenanceStore,
        Recovery, SourceHandle, SourceId, SourceKey, Tracked,
    };
    #[cfg(feature = "serde")]
    pub use crate::provenance::{expand, ExpandedDerivedFrom, ExpandedProvenance, ProvenanceSideTable};
    pub use crate::secrets::{Secret, SecretKind, SecretProvider, SecretRequest};
    pub use crate::collection::{CollectionError, CollectionManifest, StaticCollectionManifest, ToolIdentity};
    pub use crate::coverage::{CoverageGap, CoverageGapReason, CoverageReport};
    pub use crate::entity::{EntityId, EntityKind};
    pub use crate::evidence::{EvidenceItem, EvidenceItemId, EvidenceSet};
    pub use crate::fact_store::{FactObservation, FactRecord, FactStore, InMemoryFactStore, ObservationOutcome};
    pub use crate::host_profile::HostProfile;
    pub use crate::investigation::{Investigation, InvestigationId, TenantId};
    /// Test-double implementations of this crate's traits (`TestingRegistry`,
    /// `InMemoryVirtualFileSystem`, `TestParserBuilder`, `InMemoryForensicDb`,
    /// `TestingProviderHook`, factory wrappers, ...) for downstream crates
    /// writing tests against `forensic-rs` traits. Always compiled, not
    /// feature-gated. Namespaced deliberately — `use
    /// forensic_rs::prelude::testing::*;` in a `#[cfg(test)]` module, not part
    /// of the top-level prelude glob.
    pub use crate::utils::testing;
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
}
