//! Typed records of an operating system's state, as recovered from memory.
//!
//! These are the backend-independent view: an analyzer or parser written against them works on
//! any [`MemoryImage`](super::MemoryImage). Every field that comes from guest memory is a
//! [`MemValue`], so "could not be read" is never confused with "empty" or "zero".

use crate::field::Text;
use crate::provenance::{Anomalies, ProvenanceId};
use crate::utils::time::ForensicTimestamp;

use super::addr::{Pa, Va};
use super::space::SpaceId;
use super::validity::Validity;

/// A value read from guest memory.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum MemValue<T> {
    /// Read successfully.
    Known(T),
    /// The bytes it lives in have no data (paged out, not captured, invalid). The validity says
    /// why.
    Unavailable(Validity),
    /// This backend does not extract this field. Distinct from `Unavailable`: nothing was tried,
    /// so nothing can be concluded about the memory. The default.
    #[default]
    Unsupported,
}

impl<T> MemValue<T> {
    pub fn known(&self) -> Option<&T> {
        match self {
            MemValue::Known(v) => Some(v),
            _ => None,
        }
    }

    pub fn into_known(self) -> Option<T> {
        match self {
            MemValue::Known(v) => Some(v),
            _ => None,
        }
    }

    pub fn is_known(&self) -> bool {
        matches!(self, MemValue::Known(_))
    }

    pub fn as_ref(&self) -> MemValue<&T> {
        match self {
            MemValue::Known(v) => MemValue::Known(v),
            MemValue::Unavailable(v) => MemValue::Unavailable(*v),
            MemValue::Unsupported => MemValue::Unsupported,
        }
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> MemValue<U> {
        match self {
            MemValue::Known(v) => MemValue::Known(f(v)),
            MemValue::Unavailable(v) => MemValue::Unavailable(v),
            MemValue::Unsupported => MemValue::Unsupported,
        }
    }

    /// The validity of the field: `Some` only when it was tried and not read.
    pub fn unavailable(&self) -> Option<Validity> {
        match self {
            MemValue::Unavailable(v) => Some(*v),
            _ => None,
        }
    }
}

/// Where a record's main structure was found.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MemLocation {
    /// The structure type, module-qualified (`"nt!_EPROCESS"`).
    pub struct_type: Option<Text>,
    pub object_va: Option<Va>,
    pub object_pa: Option<Pa>,
    /// The address space `object_va` belongs to.
    pub space: Option<SpaceId>,
}

/// How a record was found. A record found several ways lists every source; a record found by a
/// scan but not by the OS's own list is how hidden objects show.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordSource {
    /// Walking a live OS list, tree or table, named by the backend (`"PsActiveProcessHead"`).
    ListWalk { list: Text },
    /// A scan or carve, named by the backend (`"object_scan"`).
    Scan { scanner: Text },
    /// Derived from other records.
    Derived,
    /// The capture format's header.
    FormatHeader,
    /// Supplied by the user.
    User,
}

/// The provenance, consistency and location every record carries.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct MemRecordMeta {
    /// Minted by the backend against the store it was opened with
    /// (`Acquisition::Memory`, and the `Recovery` matching how it was found).
    pub provenance: ProvenanceId,
    /// Broken invariants (back-links that don't point back, loops, sources that disagree).
    pub anomalies: Anomalies,
    pub location: MemLocation,
    /// The worst validity among the fields read.
    pub validity: Validity,
    pub sources: Vec<RecordSource>,
}

impl MemRecordMeta {
    /// `validity` is the worst validity among the record's fields. It has no default: a default
    /// would let a backend that forgot to compute it claim the record was fully read.
    pub fn new(provenance: ProvenanceId, validity: Validity) -> Self {
        Self {
            provenance,
            anomalies: Anomalies::empty(),
            location: MemLocation::default(),
            validity,
            sources: Vec::new(),
        }
    }

    pub fn with_source(mut self, source: RecordSource) -> Self {
        self.sources.push(source);
        self
    }

    pub fn with_location(mut self, location: MemLocation) -> Self {
        self.location = location;
        self
    }
}

/// A record's stable identity within one image. Backends choose the variant that matches how the
/// OS identifies the object; ordering by key is the deterministic iteration order.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemRecordKey {
    /// The address of the object itself (a process or thread object).
    Object(Va),
    /// An object identified within a process (a memory region by start page, a handle by value).
    InProcess { process: Va, key: u64 },
    /// Anything else, named by the backend.
    Other(Text),
}

/// The kinds of record a [`MemoryImage`](super::MemoryImage) can provide.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemRecordKind {
    OsInfo,
    Process,
    Thread,
    /// Kernel modules: [`MemoryImage::kernel_modules`](super::MemoryImage::kernel_modules).
    KernelModule,
    /// Modules loaded in a process: [`MemoryImage::modules`](super::MemoryImage::modules).
    ProcessModule,
    Region,
    Handle,
}

/// Facts about the captured operating system.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct MemOsInfo {
    pub meta: MemRecordMeta,
    /// `"windows"`, `"linux"`, `"macos"`.
    pub family: MemValue<Text>,
    /// Human-readable version, e.g. `"Windows 10 22H2"`.
    pub version: MemValue<Text>,
    pub build: MemValue<u32>,
    /// `"x64"`, `"x86"`, `"arm64"`.
    pub arch: MemValue<Text>,
    pub kernel_base: MemValue<Va>,
    pub dtb: MemValue<Pa>,
    /// The capture time as the OS recorded it, never host time.
    pub capture_time: MemValue<ForensicTimestamp>,
    pub processor_count: MemValue<u32>,
}

impl MemOsInfo {
    pub fn new(meta: MemRecordMeta) -> Self {
        Self {
            meta,
            family: MemValue::Unsupported,
            version: MemValue::Unsupported,
            build: MemValue::Unsupported,
            arch: MemValue::Unsupported,
            kernel_base: MemValue::Unsupported,
            dtb: MemValue::Unsupported,
            capture_time: MemValue::Unsupported,
            processor_count: MemValue::Unsupported,
        }
    }
}

/// A process. Optional facts (no parent, not exited) are `Known(None)`, not `Unavailable`.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct MemProcess {
    pub key: MemRecordKey,
    pub meta: MemRecordMeta,
    pub pid: MemValue<u64>,
    pub ppid: MemValue<u64>,
    /// The short name the kernel keeps (may be truncated by the OS).
    pub name: MemValue<Text>,
    pub image_path: MemValue<Option<Text>>,
    pub command_line: MemValue<Option<Text>>,
    pub create_time: MemValue<Option<ForensicTimestamp>>,
    pub exit_time: MemValue<Option<ForensicTimestamp>>,
    pub dtb: MemValue<Pa>,
    pub session_id: MemValue<Option<u32>>,
    /// A 32-bit process on a 64-bit OS.
    pub wow64: MemValue<bool>,
    /// Whether the OS's own active-process list contains it. `Known(false)` for a process found
    /// only by scanning: unlinked or terminated.
    pub in_active_list: MemValue<bool>,
}

impl MemProcess {
    pub fn new(key: MemRecordKey, meta: MemRecordMeta) -> Self {
        Self {
            key,
            meta,
            pid: MemValue::Unsupported,
            ppid: MemValue::Unsupported,
            name: MemValue::Unsupported,
            image_path: MemValue::Unsupported,
            command_line: MemValue::Unsupported,
            create_time: MemValue::Unsupported,
            exit_time: MemValue::Unsupported,
            dtb: MemValue::Unsupported,
            session_id: MemValue::Unsupported,
            wow64: MemValue::Unsupported,
            in_active_list: MemValue::Unsupported,
        }
    }
}

/// A thread.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct MemThread {
    pub key: MemRecordKey,
    pub meta: MemRecordMeta,
    pub tid: MemValue<u64>,
    /// The owning process's key.
    pub process: MemValue<MemRecordKey>,
    pub pid: MemValue<u64>,
    pub start_address: MemValue<Va>,
    pub create_time: MemValue<Option<ForensicTimestamp>>,
    pub exit_time: MemValue<Option<ForensicTimestamp>>,
    /// The scheduler state as the OS names it.
    pub state: MemValue<Text>,
}

impl MemThread {
    pub fn new(key: MemRecordKey, meta: MemRecordMeta) -> Self {
        Self {
            key,
            meta,
            tid: MemValue::Unsupported,
            process: MemValue::Unsupported,
            pid: MemValue::Unsupported,
            start_address: MemValue::Unsupported,
            create_time: MemValue::Unsupported,
            exit_time: MemValue::Unsupported,
            state: MemValue::Unsupported,
        }
    }
}

/// A loaded module: a kernel module (driver) when `process` is `None`, otherwise a module mapped
/// into that process.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct MemModule {
    pub key: MemRecordKey,
    pub meta: MemRecordMeta,
    pub process: Option<MemRecordKey>,
    pub base: MemValue<Va>,
    pub size: MemValue<u64>,
    pub name: MemValue<Text>,
    pub path: MemValue<Option<Text>>,
    pub load_time: MemValue<Option<ForensicTimestamp>>,
    /// Whether the OS's own module list contains it (vs found only through a memory region).
    pub in_load_list: MemValue<bool>,
}

impl MemModule {
    pub fn new(key: MemRecordKey, meta: MemRecordMeta, process: Option<MemRecordKey>) -> Self {
        Self {
            key,
            meta,
            process,
            base: MemValue::Unsupported,
            size: MemValue::Unsupported,
            name: MemValue::Unsupported,
            path: MemValue::Unsupported,
            load_time: MemValue::Unsupported,
            in_load_list: MemValue::Unsupported,
        }
    }
}

/// What backs a memory region.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegionKind {
    Private,
    /// A mapped data file.
    Mapped,
    /// A mapped executable image.
    Image,
    Other,
}

/// A reserved virtual memory region of a process (a VAD on Windows).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct MemRegion {
    pub key: MemRecordKey,
    pub meta: MemRecordMeta,
    pub process: MemRecordKey,
    pub start: Va,
    /// One past the last byte.
    pub end: Va,
    /// The protection as the OS names it (`"PAGE_EXECUTE_READWRITE"`).
    pub protection: MemValue<Text>,
    pub kind: MemValue<RegionKind>,
    pub committed_bytes: MemValue<u64>,
    pub mapped_path: MemValue<Option<Text>>,
}

impl MemRegion {
    pub fn new(
        key: MemRecordKey,
        meta: MemRecordMeta,
        process: MemRecordKey,
        start: Va,
        end: Va,
    ) -> Self {
        Self {
            key,
            meta,
            process,
            start,
            end,
            protection: MemValue::Unsupported,
            kind: MemValue::Unsupported,
            committed_bytes: MemValue::Unsupported,
            mapped_path: MemValue::Unsupported,
        }
    }
}

/// An open handle of a process.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct MemHandle {
    pub key: MemRecordKey,
    pub meta: MemRecordMeta,
    pub process: MemRecordKey,
    pub value: u64,
    pub object: MemValue<Va>,
    /// The object type as the OS names it (`"File"`, `"Key"`, `"Process"`).
    pub object_type: MemValue<Text>,
    pub granted_access: MemValue<u32>,
    pub name: MemValue<Option<Text>>,
}

impl MemHandle {
    pub fn new(key: MemRecordKey, meta: MemRecordMeta, process: MemRecordKey, value: u64) -> Self {
        Self {
            key,
            meta,
            process,
            value,
            object: MemValue::Unsupported,
            object_type: MemValue::Unsupported,
            granted_access: MemValue::Unsupported,
            name: MemValue::Unsupported,
        }
    }
}
