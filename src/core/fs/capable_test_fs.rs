//! Test double for capability forwarding: an in-memory filesystem that also answers
//! [`AlternateStreams`], [`DeletedFiles`], [`MediaMap`], [`PathAttributes`] and
//! [`Unallocated`], so wrappers (`ContainerFs`, `ChRootFileSystem`) can be checked to pass each
//! one through with their own path mapping.

use std::collections::BTreeMap;

use crate::core::locator::{EvidenceLocator, LocatorSegment};
use crate::core::path::{FPath, FPathBuf};
use crate::err::{ForensicError, ForensicResult};
use crate::field::{Field, Text};
use crate::provenance::{Locus, Recovery};
use crate::recovery::{Recovered, RecoveryReport};
use crate::traits::vfs::{
    AlternateStreams, DeletedEntry, DeletedFiles, DirEntry, FileAttributes, FileSystem, MacbTimes,
    MediaMap, MediaOffset, PathAttributes, Region, SourceKind, StreamInfo, Unallocated, VFileType,
    VMetadata, VirtualFile,
};
use crate::utils::testing::InMemoryVirtualFileSystem;

/// Files are `inner`; a stream `name` of file `f` is the inner file `f:name`. Deleted entries
/// are fixed: id 7 at `<scope>/deleted/gone.txt` (content `"gone"`), id 8 an orphan with no
/// path.
pub(crate) struct CapableFs {
    pub inner: InMemoryVirtualFileSystem,
}

impl CapableFs {
    pub fn new(inner: InMemoryVirtualFileSystem) -> Self {
        Self { inner }
    }
}

impl FileSystem for CapableFs {
    fn open(&self, path: &FPath) -> ForensicResult<Box<dyn VirtualFile>> {
        self.inner.open(path)
    }
    fn metadata(&self, path: &FPath) -> ForensicResult<VMetadata> {
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
    fn as_streams(&self) -> Option<&dyn AlternateStreams> {
        Some(self)
    }
    fn as_unallocated(&self) -> Option<&dyn Unallocated> {
        Some(self)
    }
    fn as_attributes(&self) -> Option<&dyn PathAttributes> {
        Some(self)
    }
    fn as_media_map(&self) -> Option<&dyn MediaMap> {
        Some(self)
    }
    fn as_deleted(&self) -> Option<&dyn DeletedFiles> {
        Some(self)
    }
}

impl AlternateStreams for CapableFs {
    fn streams(&self, path: &FPath) -> ForensicResult<Vec<StreamInfo>> {
        let size = self
            .inner
            .metadata(&FPathBuf::from(format!("{path}:ads")))?
            .size;
        Ok(vec![StreamInfo {
            name: "ads".into(),
            size,
        }])
    }
    fn open_stream(&self, path: &FPath, stream: &str) -> ForensicResult<Box<dyn VirtualFile>> {
        self.inner.open(&FPathBuf::from(format!("{path}:{stream}")))
    }
}

impl Unallocated for CapableFs {
    fn unallocated_regions(&self) -> ForensicResult<Vec<Region>> {
        Ok(vec![Region {
            offset: 4096,
            length: 512,
        }])
    }
    fn open_unallocated(&self, _region: &Region) -> ForensicResult<Box<dyn VirtualFile>> {
        Err(ForensicError::other("CapableFs", "no bytes".into()))
    }
}

impl PathAttributes for CapableFs {
    fn attributes(&self, path: &FPath) -> ForensicResult<BTreeMap<Text, Field>> {
        self.inner.metadata(path)?;
        Ok(BTreeMap::from([(
            Text::Borrowed("capable.path"),
            Field::Text(Text::Owned(path.to_string())),
        )]))
    }
}

impl MediaMap for CapableFs {
    /// Byte `offset` of any file lives at `1000 + offset` of a fixed parent file `media.bin`.
    fn to_parent(&self, path: &FPath, offset: u64) -> ForensicResult<Option<MediaOffset>> {
        self.inner.metadata(path)?;
        Ok(Some(MediaOffset {
            locator: EvidenceLocator::root()
                .push(LocatorSegment::Path(FPathBuf::from("media.bin"))),
            offset: 1000 + offset,
        }))
    }
}

impl DeletedFiles for CapableFs {
    fn deleted_entries(
        &self,
        scope: &FPath,
    ) -> ForensicResult<(Vec<Recovered<DeletedEntry>>, RecoveryReport)> {
        let gone = if scope.as_str().is_empty() {
            "deleted/gone.txt".to_string()
        } else {
            format!("{scope}/deleted/gone.txt")
        };
        let meta = |size| VMetadata {
            file_type: VFileType::File,
            size,
            allocated_size: None,
            times: MacbTimes::default(),
            id: None,
            attributes: FileAttributes::empty(),
        };
        let entries = vec![
            DeletedEntry::new(7, meta(4))
                .with_path(gone)
                .with_name("gone.txt")
                .with_content(true, "recoverable"),
            DeletedEntry::new(8, meta(0))
                .with_name("orphan.txt")
                .with_content(false, "reallocated"),
        ];
        let entries = entries
            .into_iter()
            .map(|e| Recovered::new(e, Recovery::DeletedMetadata, Locus::RawOffset { offset: 0 }))
            .collect();
        Ok((entries, RecoveryReport::default()))
    }
    fn open_deleted(
        &self,
        _scope: &FPath,
        id: u64,
    ) -> ForensicResult<Recovered<Box<dyn VirtualFile>>> {
        if id != 7 {
            return Err(ForensicError::other(
                "CapableFs",
                format!("no content for {id}"),
            ));
        }
        let file = InMemoryVirtualFileSystem::new()
            .with_text_file("gone", "gone")
            .open(FPath::new("gone"))?;
        Ok(Recovered::new(
            file,
            Recovery::DeletedMetadata,
            Locus::RawOffset { offset: 0 },
        ))
    }
}
