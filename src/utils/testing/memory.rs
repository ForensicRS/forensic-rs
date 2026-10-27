//! Test doubles for the memory contract ([`crate::memory`]): build a physical memory, an address
//! space and a memory image by hand, so analyzers, parsers and tools can be tested without any
//! memory backend.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::err::{ForensicError, ForensicResult};
use crate::memory::{
    AddressSpace, Backing, MemHandle, MemHive, MemIter, MemModule, MemOsInfo, MemProcess,
    MemRecordKey, MemRecordKind, MemRegion, MemThread, MemoryImage, MemoryInputInfo, Pa, PageSize,
    PagingFile, PhysRange, PhysicalMemory, ReadReport, SpaceId, Translation, Va, Validity,
    unsupported,
};
use crate::provenance::ProvenanceStore;
use crate::traits::registry::Registry;
use crate::traits::vfs::FileSystem;

/// Physical memory made of byte ranges, with everything else not captured.
pub struct InMemoryPhysicalMemory {
    ranges: Vec<PhysRange>,
    data: Vec<Vec<u8>>,
    info: MemoryInputInfo,
    live: bool,
}

impl InMemoryPhysicalMemory {
    pub fn new(format: &'static str) -> Self {
        Self {
            ranges: Vec::new(),
            data: Vec::new(),
            info: MemoryInputInfo::new(format),
            live: false,
        }
    }

    /// Adds a captured range holding `bytes` at `start`. Errors when it overlaps an existing
    /// range or ends past the 64-bit space.
    pub fn with_range(mut self, start: Pa, bytes: Vec<u8>) -> ForensicResult<Self> {
        let range = PhysRange::new(start, bytes.len() as u64);
        let end = range
            .end()
            .ok_or_else(|| ForensicError::other("memory", "range ends past 2^64".to_string()))?;
        let overlaps = self.ranges.iter().any(|r| match r.end() {
            Some(r_end) => start < r_end && r.start < end,
            None => true,
        });
        if overlaps {
            return Err(ForensicError::other(
                "memory",
                format!("range at {start} overlaps an existing range"),
            ));
        }
        let at = self.ranges.partition_point(|r| r.start < start);
        self.ranges.insert(at, range);
        self.data.insert(at, bytes);
        Ok(self)
    }

    /// Edits the format facts and hints.
    pub fn with_info(mut self, edit: impl FnOnce(&mut MemoryInputInfo)) -> Self {
        edit(&mut self.info);
        self
    }

    pub fn live(mut self, live: bool) -> Self {
        self.live = live;
        self
    }

    /// The range containing `pa`, as (index, offset into it).
    fn locate(&self, pa: Pa) -> Option<(usize, u64)> {
        let idx = self
            .ranges
            .partition_point(|r| r.start <= pa)
            .checked_sub(1)?;
        let off = pa.offset_from(self.ranges[idx].start)?;
        (off < self.ranges[idx].len).then_some((idx, off))
    }
}

impl PhysicalMemory for InMemoryPhysicalMemory {
    fn ranges(&self) -> &[PhysRange] {
        &self.ranges
    }

    fn read_phys(&self, pa: Pa, buf: &mut [u8]) -> ForensicResult<ReadReport> {
        let mut report = ReadReport::new();
        let mut pos = 0usize;
        while pos < buf.len() {
            let remaining = buf.len() - pos;
            let Some(cur) = pa.checked_add(pos as u64) else {
                buf[pos..].fill(0);
                report.push(remaining as u64, Validity::NotCaptured);
                break;
            };
            let n = match self.locate(cur) {
                Some((idx, off)) => {
                    let avail = (self.ranges[idx].len - off).min(remaining as u64) as usize;
                    let start = off as usize;
                    buf[pos..pos + avail].copy_from_slice(&self.data[idx][start..start + avail]);
                    report.push(avail as u64, Validity::Resident);
                    avail
                }
                None => {
                    let next = self.ranges.iter().find(|r| r.start > cur);
                    let gap = next
                        .and_then(|r| r.start.offset_from(cur))
                        .map_or(remaining, |g| g.min(remaining as u64) as usize);
                    buf[pos..pos + gap].fill(0);
                    report.push(gap as u64, Validity::NotCaptured);
                    gap
                }
            };
            pos += n;
        }
        Ok(report)
    }

    fn slice(&self, pa: Pa, len: usize) -> Option<&[u8]> {
        let (idx, off) = self.locate(pa)?;
        let start = usize::try_from(off).ok()?;
        self.data[idx].get(start..start.checked_add(len)?)
    }

    fn info(&self) -> &MemoryInputInfo {
        &self.info
    }

    fn is_live(&self) -> bool {
        self.live
    }
}

/// A paging file held in memory.
pub struct InMemoryPagingFile {
    backing: Backing,
    bytes: Vec<u8>,
}

impl InMemoryPagingFile {
    pub fn new(backing: Backing, bytes: Vec<u8>) -> Self {
        Self { backing, bytes }
    }
}

impl PagingFile for InMemoryPagingFile {
    fn backing(&self) -> Backing {
        self.backing
    }

    fn size(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> ForensicResult<ReadReport> {
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        let have = self.bytes.len().saturating_sub(start).min(buf.len());
        if have > 0 {
            buf[..have].copy_from_slice(&self.bytes[start..start + have]);
        }
        buf[have..].fill(0);
        let mut report = ReadReport::new();
        report.push(
            have as u64,
            Validity::Paged {
                backing: self.backing,
                data: true,
            },
        );
        report.push(
            (buf.len() - have) as u64,
            Validity::Paged {
                backing: self.backing,
                data: false,
            },
        );
        Ok(report)
    }
}

const PAGE: u64 = PageSize::K4.bytes();

/// A 4 KiB-paged address space defined by a page map; unmapped pages are
/// `Invalid { NotPresent }`.
pub struct TestingAddressSpace {
    id: SpaceId,
    pointer_size: u8,
    dtb: Option<Pa>,
    phys: Arc<dyn PhysicalMemory>,
    pages: BTreeMap<u64, Translation>,
}

impl TestingAddressSpace {
    pub fn new(id: SpaceId, pointer_size: u8, phys: Arc<dyn PhysicalMemory>) -> Self {
        Self {
            id,
            pointer_size,
            dtb: None,
            phys,
            pages: BTreeMap::new(),
        }
    }

    pub fn with_dtb(mut self, dtb: Pa) -> Self {
        self.dtb = Some(dtb);
        self
    }

    /// Maps the 4 KiB page containing `va` to the page containing `pa`.
    pub fn map_page(self, va: Va, pa: Pa) -> Self {
        let pa = pa.align_down(PageSize::K4);
        self.with_translation(
            va,
            Translation::Resident {
                pa,
                size: PageSize::K4,
            },
        )
    }

    /// Maps `len` bytes (rounded up to whole pages) starting at `va` to consecutive physical
    /// pages starting at `pa`.
    pub fn map_range(mut self, va: Va, pa: Pa, len: u64) -> Self {
        let pages = len.div_ceil(PAGE);
        for i in 0..pages {
            let (Some(v), Some(p)) = (va.checked_add(i * PAGE), pa.checked_add(i * PAGE)) else {
                break;
            };
            self = self.map_page(v, p);
        }
        self
    }

    /// Sets the translation of the page containing `va`. For `Resident` and `Transition`, `pa`
    /// is the page's base.
    pub fn with_translation(mut self, va: Va, translation: Translation) -> Self {
        self.pages.insert(va.as_u64() / PAGE, translation);
        self
    }
}

impl AddressSpace for TestingAddressSpace {
    fn id(&self) -> SpaceId {
        self.id
    }

    fn pointer_size(&self) -> u8 {
        self.pointer_size
    }

    fn dtb(&self) -> Option<Pa> {
        self.dtb
    }

    fn translate(&self, va: Va) -> ForensicResult<Translation> {
        let off = va.page_offset(PageSize::K4);
        Ok(match self.pages.get(&(va.as_u64() / PAGE)) {
            Some(Translation::Resident { pa, size }) => match pa.checked_add(off) {
                Some(pa) => Translation::Resident { pa, size: *size },
                None => Translation::Invalid {
                    reason: crate::memory::InvalidReason::Malformed,
                },
            },
            Some(Translation::Transition { pa }) => match pa.checked_add(off) {
                Some(pa) => Translation::Transition { pa },
                None => Translation::Invalid {
                    reason: crate::memory::InvalidReason::Malformed,
                },
            },
            Some(other) => *other,
            None => Translation::Invalid {
                reason: crate::memory::InvalidReason::NotPresent,
            },
        })
    }

    fn read(&self, va: Va, buf: &mut [u8]) -> ForensicResult<ReadReport> {
        let mut report = ReadReport::new();
        let mut pos = 0usize;
        while pos < buf.len() {
            let remaining = buf.len() - pos;
            let Some(cur) = va.checked_add(pos as u64) else {
                buf[pos..].fill(0);
                report.push(remaining as u64, Validity::Invalid);
                break;
            };
            let in_page = (PAGE - cur.page_offset(PageSize::K4)) as usize;
            let n = in_page.min(remaining);
            let chunk = &mut buf[pos..pos + n];
            let translation = self.translate(cur)?;
            match translation.pa() {
                Some(pa) => report.extend(&self.phys.read_phys(pa, chunk)?),
                None => {
                    chunk.fill(0);
                    report.push(n as u64, translation.unresolved_validity());
                }
            }
            pos += n;
        }
        Ok(report)
    }
}

/// A memory image assembled from records, for testing code written against [`MemoryImage`].
///
/// Adding a record declares its kind as provided; [`TestingMemoryImage::with_kind`] declares a
/// kind with no records ("supported, and there are none"). Records are yielded sorted by key.
pub struct TestingMemoryImage {
    kinds: Vec<MemRecordKind>,
    physical: Arc<dyn PhysicalMemory>,
    kernel: Option<Arc<dyn AddressSpace>>,
    spaces: BTreeMap<MemRecordKey, Arc<dyn AddressSpace>>,
    os: Option<MemOsInfo>,
    processes: Vec<MemProcess>,
    threads: Vec<MemThread>,
    modules: Vec<MemModule>,
    regions: Vec<MemRegion>,
    handles: Vec<MemHandle>,
    hives: Vec<MemHive>,
    registry: Option<Arc<dyn Registry>>,
    files: Option<Arc<dyn FileSystem>>,
    provenance: ProvenanceStore,
}

impl TestingMemoryImage {
    pub fn new(physical: Arc<dyn PhysicalMemory>) -> Self {
        Self {
            kinds: Vec::new(),
            physical,
            kernel: None,
            spaces: BTreeMap::new(),
            os: None,
            processes: Vec::new(),
            threads: Vec::new(),
            modules: Vec::new(),
            regions: Vec::new(),
            handles: Vec::new(),
            hives: Vec::new(),
            registry: None,
            files: None,
            provenance: ProvenanceStore::new(),
        }
    }

    /// The store the test minted its records' provenance ids in, returned by
    /// [`MemoryImage::provenance`]. Without it the image has an empty store of its own.
    pub fn with_provenance(mut self, store: ProvenanceStore) -> Self {
        self.provenance = store;
        self
    }

    /// An image over an empty physical memory, for tests that only need records.
    pub fn empty() -> Self {
        Self::new(Arc::new(InMemoryPhysicalMemory::new("test")))
    }

    pub fn with_kind(mut self, kind: MemRecordKind) -> Self {
        if let Err(at) = self.kinds.binary_search(&kind) {
            self.kinds.insert(at, kind);
        }
        self
    }

    pub fn with_kernel_space(mut self, space: Arc<dyn AddressSpace>) -> Self {
        self.kernel = Some(space);
        self
    }

    pub fn with_process_space(
        mut self,
        process: MemRecordKey,
        space: Arc<dyn AddressSpace>,
    ) -> Self {
        self.spaces.insert(process, space);
        self
    }

    pub fn with_os(mut self, os: MemOsInfo) -> Self {
        self.os = Some(os);
        self.with_kind(MemRecordKind::OsInfo)
    }

    pub fn with_process(mut self, process: MemProcess) -> Self {
        self.processes.push(process);
        self.processes.sort_by(|a, b| a.key.cmp(&b.key));
        self.with_kind(MemRecordKind::Process)
    }

    pub fn with_thread(mut self, thread: MemThread) -> Self {
        self.threads.push(thread);
        self.threads.sort_by(|a, b| a.key.cmp(&b.key));
        self.with_kind(MemRecordKind::Thread)
    }

    /// Adds a module: a kernel module when its `process` is `None`.
    pub fn with_module(mut self, module: MemModule) -> Self {
        let kind = if module.process.is_none() {
            MemRecordKind::KernelModule
        } else {
            MemRecordKind::ProcessModule
        };
        self.modules.push(module);
        self.modules.sort_by(|a, b| a.key.cmp(&b.key));
        self.with_kind(kind)
    }

    pub fn with_region(mut self, region: MemRegion) -> Self {
        self.regions.push(region);
        self.regions.sort_by(|a, b| a.key.cmp(&b.key));
        self.with_kind(MemRecordKind::Region)
    }

    /// The registry [`MemoryImage::as_registry`] returns (a `TestingRegistry`, say).
    pub fn with_registry(mut self, registry: Arc<dyn Registry>) -> Self {
        self.registry = Some(registry);
        self
    }

    /// The files [`MemoryImage::as_files`] returns (an `InMemoryVirtualFileSystem`, say).
    pub fn with_files(mut self, files: Arc<dyn FileSystem>) -> Self {
        self.files = Some(files);
        self
    }

    pub fn with_handle(mut self, handle: MemHandle) -> Self {
        self.handles.push(handle);
        self.handles.sort_by(|a, b| a.key.cmp(&b.key));
        self.with_kind(MemRecordKind::Handle)
    }

    pub fn with_hive(mut self, hive: MemHive) -> Self {
        self.hives.push(hive);
        self.hives.sort_by(|a, b| a.key.cmp(&b.key));
        self.with_kind(MemRecordKind::Hive)
    }

    fn provides(&self, kind: MemRecordKind) -> ForensicResult<()> {
        if self.kinds.contains(&kind) {
            Ok(())
        } else {
            Err(unsupported(kind))
        }
    }
}

fn iter_of<'a, T: Clone + 'a>(items: impl Iterator<Item = &'a T> + 'a) -> MemIter<'a, T> {
    Box::new(items.cloned().map(Ok))
}

impl MemoryImage for TestingMemoryImage {
    fn kinds(&self) -> &[MemRecordKind] {
        &self.kinds
    }

    fn provenance(&self) -> &ProvenanceStore {
        &self.provenance
    }

    fn os(&self) -> ForensicResult<MemOsInfo> {
        self.os
            .clone()
            .ok_or_else(|| unsupported(MemRecordKind::OsInfo))
    }

    fn physical(&self) -> &dyn PhysicalMemory {
        self.physical.as_ref()
    }

    fn kernel_space(&self) -> ForensicResult<Arc<dyn AddressSpace>> {
        self.kernel.clone().ok_or_else(|| {
            ForensicError::other(
                "memory",
                "no kernel address space in this test image".into(),
            )
        })
    }

    fn process_space(&self, process: &MemRecordKey) -> ForensicResult<Arc<dyn AddressSpace>> {
        self.spaces.get(process).cloned().ok_or_else(|| {
            ForensicError::other("memory", format!("no address space for {process:?}"))
        })
    }

    fn processes(&self) -> ForensicResult<MemIter<'_, MemProcess>> {
        self.provides(MemRecordKind::Process)?;
        Ok(iter_of(self.processes.iter()))
    }

    fn threads(&self, process: Option<&MemRecordKey>) -> ForensicResult<MemIter<'_, MemThread>> {
        self.provides(MemRecordKind::Thread)?;
        let process = process.cloned();
        Ok(iter_of(self.threads.iter().filter(
            move |t| match &process {
                None => true,
                Some(p) => t.process.known() == Some(p),
            },
        )))
    }

    fn kernel_modules(&self) -> ForensicResult<MemIter<'_, MemModule>> {
        self.provides(MemRecordKind::KernelModule)?;
        Ok(iter_of(self.modules.iter().filter(|m| m.process.is_none())))
    }

    fn modules(&self, process: &MemRecordKey) -> ForensicResult<MemIter<'_, MemModule>> {
        self.provides(MemRecordKind::ProcessModule)?;
        let process = process.clone();
        Ok(iter_of(
            self.modules
                .iter()
                .filter(move |m| m.process.as_ref() == Some(&process)),
        ))
    }

    fn regions(&self, process: &MemRecordKey) -> ForensicResult<MemIter<'_, MemRegion>> {
        self.provides(MemRecordKind::Region)?;
        let process = process.clone();
        Ok(iter_of(
            self.regions.iter().filter(move |r| r.process == process),
        ))
    }

    fn handles(&self, process: &MemRecordKey) -> ForensicResult<MemIter<'_, MemHandle>> {
        self.provides(MemRecordKind::Handle)?;
        let process = process.clone();
        Ok(iter_of(
            self.handles.iter().filter(move |h| h.process == process),
        ))
    }

    fn hives(&self) -> ForensicResult<MemIter<'_, MemHive>> {
        self.provides(MemRecordKind::Hive)?;
        Ok(iter_of(self.hives.iter()))
    }

    fn as_registry(&self) -> Option<Arc<dyn Registry>> {
        self.registry.clone()
    }

    fn as_files(&self) -> Option<Arc<dyn FileSystem>> {
        self.files.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemRecordMeta, MemValue, MemoryImageExt, MemorySpec};
    use crate::utils::testing::test_provenance_id;

    #[test]
    fn physical_reads_report_gaps() {
        let phys = InMemoryPhysicalMemory::new("test")
            .with_range(Pa::new(0x1000), vec![0xaa; 0x1000])
            .unwrap()
            .with_range(Pa::new(0x3000), vec![0xbb; 0x10])
            .unwrap();
        let mut buf = vec![0xffu8; 0x2010];
        let report = phys.read_phys(Pa::new(0x1000), &mut buf).unwrap();
        assert_eq!(
            report.runs(),
            &[
                (0x1000, Validity::Resident),
                (0x1000, Validity::NotCaptured),
                (0x10, Validity::Resident)
            ]
        );
        assert_eq!(report.total_len(), buf.len() as u64);
        assert!(buf[0x1000..0x2000].iter().all(|&b| b == 0));
        assert_eq!(buf[0x2000], 0xbb);
        assert!(phys.slice(Pa::new(0x1ff0), 0x20).is_none());
        assert_eq!(phys.slice(Pa::new(0x3000), 2), Some(&[0xbb, 0xbb][..]));
        // Reading at the very top of the address space never wraps.
        let mut top = [0u8; 4];
        let r = phys.read_phys(Pa::new(u64::MAX - 1), &mut top).unwrap();
        assert_eq!(r.total_len(), 4);
    }

    #[test]
    fn overlapping_ranges_are_rejected() {
        let phys = InMemoryPhysicalMemory::new("test")
            .with_range(Pa::new(0x1000), vec![0; 0x1000])
            .unwrap();
        assert!(phys.with_range(Pa::new(0x1800), vec![0; 0x10]).is_err());
    }

    #[test]
    fn unsupported_kinds_error_instead_of_being_empty() {
        let key = MemRecordKey::Object(Va::new(0xffff_8000_0000_1000));
        let mut p = MemProcess::new(
            key.clone(),
            MemRecordMeta::new(test_provenance_id(), Validity::Resident),
        );
        p.pid = MemValue::Known(4);
        p.in_active_list = MemValue::Known(false);
        let image = TestingMemoryImage::empty()
            .with_process(p)
            .with_kind(MemRecordKind::ProcessModule);
        assert!(image.threads(None).is_err());
        assert_eq!(image.modules(&key).unwrap().count(), 0);
        assert_eq!(image.unlinked_processes().unwrap().len(), 1);
        assert_eq!(image.processes_by_pid(4).unwrap().len(), 1);
        assert!(
            MemorySpec::new()
                .kind(MemRecordKind::Process)
                .is_satisfied_by(&image)
        );
        assert!(
            !MemorySpec::new()
                .kind(MemRecordKind::Handle)
                .is_satisfied_by(&image)
        );
        assert!(
            !MemorySpec::new()
                .os_family("windows")
                .is_satisfied_by(&image)
        );
    }
}
