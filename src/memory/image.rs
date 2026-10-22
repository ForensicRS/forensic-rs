//! The backend-independent view of one memory image.

use std::sync::Arc;

use crate::err::{ForensicError, ForensicResult};
use crate::field::Text;
use crate::provenance::ProvenanceStore;
use crate::traits::registry::Registry;
use crate::traits::vfs::FileSystem;

use super::addr::Va;
use super::model::{
    MemHandle, MemModule, MemOsInfo, MemProcess, MemRecordKey, MemRecordKind, MemRegion, MemThread,
    MemValue,
};
use super::physical::PhysicalMemory;
use super::space::{AddressSpace, AddressSpaceExt};
use super::validity::ReadReport;

/// A stream of records. Each item is a `Result` so one unreadable record never hides the rest.
pub type MemIter<'a, T> = Box<dyn Iterator<Item = ForensicResult<T>> + 'a>;

/// One memory image, as a provider of typed OS records.
///
/// This is what analyzers, parser factories and tools consume. A memory backend implements it;
/// a [`FormatFactory`](crate::traits::format::FormatFactory) hands it out as
/// [`Mounted::Memory`](crate::traits::format::Mounted::Memory).
///
/// Contract for implementors:
/// - iterators yield records in a deterministic order (sorted by [`MemRecordKey`]), so the same
///   image always gives the same output;
/// - a record kind the backend does not provide is left out of [`MemoryImage::kinds`], and its
///   method returns an error (the default), never an empty iterator: "no handles" and "handles
///   not supported" must not look alike;
/// - provenance ids in [`MemRecordMeta`](super::MemRecordMeta) are minted with
///   `Acquisition::Memory` and the `Recovery` matching how each record was found, in the store
///   [`MemoryImage::provenance`] returns;
/// - whether the source is live (reads not repeatable) is [`PhysicalMemory::is_live`], the only
///   place it is stated.
pub trait MemoryImage: Send + Sync {
    /// The record kinds this backend provides.
    fn kinds(&self) -> &[MemRecordKind];

    /// The store the records' provenance ids were minted in, so a consumer can resolve them
    /// (`get`, `derive`). Parsers still mint their own ids against the pipeline's store for what
    /// they export; this store is the backend's lineage of each record.
    fn provenance(&self) -> &ProvenanceStore;

    fn os(&self) -> ForensicResult<MemOsInfo>;

    fn physical(&self) -> &dyn PhysicalMemory;

    fn kernel_space(&self) -> ForensicResult<Arc<dyn AddressSpace>>;

    /// The address space of a process, by its record key.
    fn process_space(&self, process: &MemRecordKey) -> ForensicResult<Arc<dyn AddressSpace>>;

    fn processes(&self) -> ForensicResult<MemIter<'_, MemProcess>>;

    /// Threads of one process, or of every process when `process` is `None`.
    fn threads(&self, _process: Option<&MemRecordKey>) -> ForensicResult<MemIter<'_, MemThread>> {
        Err(unsupported(MemRecordKind::Thread))
    }

    fn kernel_modules(&self) -> ForensicResult<MemIter<'_, MemModule>> {
        Err(unsupported(MemRecordKind::Module))
    }

    fn modules(&self, _process: &MemRecordKey) -> ForensicResult<MemIter<'_, MemModule>> {
        Err(unsupported(MemRecordKind::Module))
    }

    fn regions(&self, _process: &MemRecordKey) -> ForensicResult<MemIter<'_, MemRegion>> {
        Err(unsupported(MemRecordKind::Region))
    }

    fn handles(&self, _process: &MemRecordKey) -> ForensicResult<MemIter<'_, MemHandle>> {
        Err(unsupported(MemRecordKind::Handle))
    }

    /// The registry as it was in memory (hives, including volatile ones), when supported.
    fn as_registry(&self) -> Option<&dyn Registry> {
        None
    }

    /// Files recovered from memory (cache manager, mapped sections), when supported.
    fn as_files(&self) -> Option<&dyn FileSystem> {
        None
    }
}

/// The error a [`MemoryImage`] returns for a record kind it does not provide. It is
/// [`ForensicError::is_unsupported`], so callers can tell it from a failed read.
pub fn unsupported(kind: MemRecordKind) -> ForensicError {
    ForensicError::unsupported(
        "memory records",
        format!("this memory backend does not provide {kind:?} records"),
    )
}

/// What a parser needs from a memory image, for
/// [`Requirement::Memory`](crate::traits::forensic::Requirement::Memory).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct MemorySpec {
    /// The OS family (`"windows"`), or `None` for any.
    pub os_family: Option<Text>,
    /// Record kinds the backend must provide.
    pub kinds: Vec<MemRecordKind>,
}

impl MemorySpec {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn os_family(mut self, family: impl Into<Text>) -> Self {
        self.os_family = Some(family.into());
        self
    }

    pub fn kind(mut self, kind: MemRecordKind) -> Self {
        if !self.kinds.contains(&kind) {
            self.kinds.push(kind);
        }
        self
    }

    /// Whether `image` provides every kind asked for and, when an OS family is asked for, reports
    /// that family. An image whose family is unreadable does not satisfy a family requirement.
    pub fn is_satisfied_by(&self, image: &dyn MemoryImage) -> bool {
        if !self.kinds.iter().all(|k| image.kinds().contains(k)) {
            return false;
        }
        match &self.os_family {
            None => true,
            Some(want) => match image.os() {
                Ok(os) => os
                    .family
                    .known()
                    .is_some_and(|f| f.eq_ignore_ascii_case(want)),
                Err(_) => false,
            },
        }
    }
}

/// Conveniences over any [`MemoryImage`].
pub trait MemoryImageExt: MemoryImage {
    /// Every process record with this pid. There can be several: pids are reused, and a
    /// terminated process found by a scan keeps its old pid.
    fn processes_by_pid(&self, pid: u64) -> ForensicResult<Vec<MemProcess>> {
        let mut out = Vec::new();
        for process in self.processes()? {
            let process = process?;
            if process.pid.known() == Some(&pid) {
                out.push(process);
            }
        }
        Ok(out)
    }

    /// Processes the OS's own active list does not contain (`in_active_list == Known(false)`):
    /// unlinked or terminated processes found by scanning. A process whose list membership is
    /// unknown is not included.
    fn unlinked_processes(&self) -> ForensicResult<Vec<MemProcess>> {
        let mut out = Vec::new();
        for process in self.processes()? {
            let process = process?;
            if process.in_active_list == MemValue::Known(false) {
                out.push(process);
            }
        }
        Ok(out)
    }

    /// Reads `len` bytes of a process's memory, with the report saying which bytes are real.
    fn read_process_bytes(
        &self,
        process: &MemRecordKey,
        va: Va,
        len: usize,
    ) -> ForensicResult<(Vec<u8>, ReadReport)> {
        self.process_space(process)?.read_bytes(va, len)
    }
}

impl<T: MemoryImage + ?Sized> MemoryImageExt for T {}
