//! The memory-forensics contract: what a memory backend provides and what analyzers, parsers and
//! tools consume.
//!
//! forensic-rs defines the contract; backends (a dump-file engine, a live connector, another OS)
//! implement it. Code written against these types keeps working when the backend changes.
//!
//! Layers, bottom up:
//! - [`PhysicalMemory`]: the captured physical memory, with [`ReadReport`]s saying which bytes
//!   are real ([`Validity`]);
//! - [`AddressSpace`]: a virtual address space over it, with [`Translation`]s and typed reads
//!   ([`AddressSpaceExt`]);
//! - [`MemoryImage`]: typed OS records ([`MemProcess`], [`MemThread`], [`MemModule`],
//!   [`MemRegion`], [`MemHandle`], [`MemOsInfo`]) whose fields are [`MemValue`]s, each with
//!   provenance and anomalies ([`MemRecordMeta`]).
//!
//! A memory image reaches the rest of forensic-rs as [`Mounted::Memory`] from a
//! [`FormatFactory`], as [`Requirement::Memory`] for parsers, and through
//! [`TriageSourcesBuilder::memory`] for pipelines. Records exported as `ForensicData` use
//! [`CommonArtifact::Memory`], [`Locus::Memory`]/[`Locus::Physical`] and the `memory.*`
//! dictionary fields.
//!
//! Rules every backend follows:
//! - memory images are attacker-controlled: bounds-check every read, bound every count, detect
//!   cycles, never panic;
//! - never fabricate: a value that could not be read is `MemValue::Unavailable`, a field the
//!   backend does not extract is `MemValue::Unsupported`;
//! - divergence is evidence: when two ways of finding an object disagree, keep both and record
//!   an anomaly ([`AnomalyFlags::SOURCE_DIVERGENCE`]);
//! - output is deterministic: records are yielded in key order.
//!
//! Test doubles: [`InMemoryPhysicalMemory`], [`TestingAddressSpace`] and [`TestingMemoryImage`]
//! in [`crate::utils::testing`].
//!
//! [`Mounted::Memory`]: crate::traits::format::Mounted::Memory
//! [`FormatFactory`]: crate::traits::format::FormatFactory
//! [`Requirement::Memory`]: crate::traits::forensic::Requirement::Memory
//! [`TriageSourcesBuilder::memory`]: crate::pipeline::sources::TriageSourcesBuilder::memory
//! [`CommonArtifact::Memory`]: crate::artifact::CommonArtifact::Memory
//! [`Locus::Memory`]: crate::provenance::Locus::Memory
//! [`Locus::Physical`]: crate::provenance::Locus::Physical
//! [`AnomalyFlags::SOURCE_DIVERGENCE`]: crate::provenance::AnomalyFlags::SOURCE_DIVERGENCE
//! [`InMemoryPhysicalMemory`]: crate::utils::testing::InMemoryPhysicalMemory
//! [`TestingAddressSpace`]: crate::utils::testing::TestingAddressSpace
//! [`TestingMemoryImage`]: crate::utils::testing::TestingMemoryImage

mod addr;
mod image;
mod model;
mod physical;
mod space;
mod validity;

pub use addr::{Pa, PageSize, Va};
pub use image::{MemIter, MemoryImage, MemoryImageExt, MemorySpec, unsupported};
pub use model::{
    MemHandle, MemLocation, MemModule, MemOsInfo, MemProcess, MemRecordKey, MemRecordKind,
    MemRecordMeta, MemRegion, MemThread, MemValue, RecordSource, RegionKind,
};
pub use physical::{MemoryInputInfo, PhysRange, PhysicalMemory};
pub use space::{
    AddressSpace, AddressSpaceExt, Bounded, InvalidReason, MAX_READ, MAX_STRING_SCAN, SpaceId,
    Translation,
};
pub use validity::{Backing, ReadReport, Validity};
