//! Split raw images: `disk.001`, `disk.002`, ... joined back into the one disk they were cut
//! from.
//!
//! The only image format core ships, because it is the only one that needs no parser: the
//! segments are the disk's bytes, in order. A single unsplit raw/dd image needs no factory at
//! all -- it already *is* the media, and a volume-system or filesystem factory probes it
//! directly.
//!
//! [`SplitRawFactory`] mounts the set as a [`SplitRawFs`] holding one file, [`MEDIA_FILE`],
//! the same shape every image-format factory should produce (an E01, a VMDK), so the next hop
//! probes the media without knowing how it was stored.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::core::limits::LimitExceeded;
use crate::core::locator::{EvidenceLocator, LocatorSegment};
use crate::core::path::{FPath, FPathBuf};
use crate::err::{ForensicError, ForensicResult};
use crate::field::{Field, Text};
use crate::traits::format::{FormatFactory, HopCost, MountContext, MountKind, Mounted, ProbeScore};
use crate::traits::vfs::{
    CaseSensitivity, DirEntry, FileAttributes, FileSystem, MacbTimes, MediaMap, MediaOffset,
    PathAttributes, ReadAt, SourceKind, VFileType, VMetadata, VirtualFile,
};

use super::window::{ConcatReadAt, ReadAtFile, into_read_at};

/// The one file a mounted image exposes: the reconstructed media, addressed from byte 0.
pub const MEDIA_FILE: &str = "media";

/// Mounts `name.001` plus its consecutively numbered siblings as one [`MEDIA_FILE`].
///
/// Claims a file only when it is segment 1 *and* segment 2 exists beside it, and then claims
/// it [`ProbeScore::Exact`]: a numbered run of sibling files is unambiguous structure, and it
/// has to outrank a volume-system factory, which would otherwise also claim the first
/// segment's partition table and silently truncate every partition at the segment boundary.
#[derive(Debug, Default, Clone, Copy)]
pub struct SplitRawFactory;

impl SplitRawFactory {
    pub fn new() -> Self {
        Self
    }
}

/// `name.001` -> `("name.", 3)`: the text before the counter and the counter's width. `None`
/// unless the extension is all digits, at least three wide, and equal to 1.
fn first_segment(name: &str) -> Option<(&str, usize)> {
    let (stem, digits) = name.rsplit_once('.')?;
    let width = digits.len();
    if width < 3 || !digits.bytes().all(|b| b.is_ascii_digit()) || digits.parse::<u64>().ok()? != 1
    {
        return None;
    }
    Some((&name[..stem.len() + 1], width))
}

/// Segment numbers present beside the target, keyed by number, for names `prefix` + exactly
/// `width` digits.
fn numbered_siblings(
    ctx: &MountContext<'_>,
    prefix: &str,
    width: usize,
) -> ForensicResult<BTreeMap<u64, String>> {
    let mut found = BTreeMap::new();
    for entry in ctx.siblings()? {
        if entry.file_type != VFileType::File {
            continue;
        }
        let Some(name) = entry.file_name() else {
            continue;
        };
        let Some(digits) = name.strip_prefix(prefix) else {
            continue;
        };
        if digits.len() == width && digits.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(n) = digits.parse::<u64>() {
                found.insert(n, name.to_string());
            }
        }
    }
    Ok(found)
}

fn target_name<'a>(ctx: &'a MountContext<'_>) -> Option<&'a str> {
    match ctx.locator().last()? {
        LocatorSegment::Path(path) => path.file_name(),
        _ => None,
    }
}

impl FormatFactory for SplitRawFactory {
    fn name(&self) -> &'static str {
        "split-raw"
    }

    fn yields(&self) -> MountKind {
        MountKind::FileSystem
    }

    fn probe(
        &self,
        _file: &mut dyn VirtualFile,
        ctx: &MountContext<'_>,
    ) -> ForensicResult<ProbeScore> {
        let Some((prefix, width)) = target_name(ctx).and_then(first_segment) else {
            return Ok(ProbeScore::No);
        };
        let siblings = numbered_siblings(ctx, prefix, width)?;
        Ok(if siblings.contains_key(&2) {
            ProbeScore::Exact
        } else {
            ProbeScore::No
        })
    }

    fn mount(&self, file: Box<dyn VirtualFile>, ctx: &MountContext<'_>) -> ForensicResult<Mounted> {
        let (prefix, width) = target_name(ctx).and_then(first_segment).ok_or_else(|| {
            ForensicError::other(
                "SplitRawFactory",
                format!(
                    "{} is not the first segment of a split image",
                    ctx.locator()
                ),
            )
        })?;
        let dir = ctx.parent_dir().ok_or_else(|| {
            ForensicError::other(
                "SplitRawFactory",
                format!("{} has no directory", ctx.locator()),
            )
        })?;
        let siblings = numbered_siblings(ctx, prefix, width)?;

        // Segment 1 is the file already open; the rest are taken while the numbering is
        // unbroken. A gap ends the media there -- the bytes after it cannot be placed -- and is
        // reported as an attribute, because a missing segment is evidence about the
        // acquisition, not a reason to refuse the part that is present.
        let mut names = vec![target_name(ctx).unwrap_or_default().to_string()];
        let mut locators = vec![ctx.locator().clone()];
        let mut parts: Vec<Arc<dyn ReadAt>> = vec![into_read_at(file)?];
        let mut next = 2u64;
        while let Some(name) = siblings.get(&next) {
            if ctx.is_cancelled() {
                return Err(ForensicError::other(
                    "SplitRawFactory",
                    "cancelled".to_string(),
                ));
            }
            let max = ctx.limits().max_entries_per_container;
            if next > max {
                return Err(ForensicError::other(
                    "SplitRawFactory",
                    LimitExceeded::EntriesPerContainer { at: next, max }.to_string(),
                ));
            }
            let locator = ctx.sibling_locator(name).ok_or_else(|| {
                ForensicError::other("SplitRawFactory", format!("no locator for {name}"))
            })?;
            parts.push(into_read_at(ctx.fs().open(dir.join(name).as_path())?)?);
            names.push(name.clone());
            locators.push(locator);
            next += 1;
        }
        let missing = siblings
            .range(next..)
            .next()
            .map(|_| format!("{prefix}{next:0width$}"));

        Ok(Mounted::FileSystem(Arc::new(SplitRawFs {
            media: Arc::new(ConcatReadAt::new(parts)),
            names,
            locators,
            missing,
            source: ctx.fs().source(),
        })))
    }

    fn extensions(&self) -> &[&'static str] {
        &["001"]
    }

    fn hop_cost(&self) -> HopCost {
        HopCost::View
    }
}

/// A mounted split image: a root directory holding [`MEDIA_FILE`].
pub struct SplitRawFs {
    media: Arc<ConcatReadAt>,
    /// Segment file names, in media order.
    names: Vec<String>,
    /// Each segment's locator, in media order, for [`MediaMap`].
    locators: Vec<EvidenceLocator>,
    /// The first absent segment name, when a later-numbered one exists.
    missing: Option<String>,
    source: SourceKind,
}

/// Which of the two paths a `SplitRawFs` has: `Some(true)` for the media file, `Some(false)`
/// for the root.
fn which(path: &FPath) -> Option<bool> {
    match path.as_str().trim_matches(['/', '\\']) {
        "" => Some(false),
        MEDIA_FILE => Some(true),
        _ => None,
    }
}

fn not_found(path: &FPath) -> ForensicError {
    ForensicError::path_not_found(path.as_str())
}

impl SplitRawFs {
    fn media_metadata(&self) -> VMetadata {
        VMetadata {
            file_type: VFileType::File,
            size: self.media.size(),
            allocated_size: None,
            times: MacbTimes::default(),
            id: None,
            attributes: FileAttributes::VOLUME,
        }
    }
}

impl FileSystem for SplitRawFs {
    fn open(&self, path: &FPath) -> ForensicResult<Box<dyn VirtualFile>> {
        match which(path) {
            Some(true) => Ok(Box::new(ReadAtFile::new(
                Arc::clone(&self.media) as Arc<dyn ReadAt>
            ))),
            _ => Err(not_found(path)),
        }
    }

    fn metadata(&self, path: &FPath) -> ForensicResult<VMetadata> {
        match which(path) {
            Some(true) => Ok(self.media_metadata()),
            Some(false) => Ok(VMetadata {
                file_type: VFileType::Directory,
                size: 0,
                attributes: FileAttributes::empty(),
                ..self.media_metadata()
            }),
            None => Err(not_found(path)),
        }
    }

    fn read_dir(
        &self,
        path: &FPath,
    ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<DirEntry>> + '_>> {
        match which(path) {
            Some(false) => Ok(Box::new(std::iter::once(Ok(DirEntry {
                path: FPathBuf::from(MEDIA_FILE),
                file_type: VFileType::File,
                metadata: Some(self.media_metadata()),
            })))),
            _ => Err(not_found(path)),
        }
    }

    /// The acquisition the segments came from: a split image read off a live system's disk is
    /// still live.
    fn source(&self) -> SourceKind {
        self.source
    }

    fn case_sensitivity(&self) -> CaseSensitivity {
        CaseSensitivity::Sensitive
    }

    fn as_attributes(&self) -> Option<&dyn PathAttributes> {
        Some(self)
    }

    fn as_media_map(&self) -> Option<&dyn MediaMap> {
        Some(self)
    }
}

impl PathAttributes for SplitRawFs {
    /// On the media file: `raw.segment_count`, `raw.segments` (names, in media order) and,
    /// when the numbering has a gap, `raw.missing_segment` (the first absent name). Nothing on
    /// the root.
    fn attributes(&self, path: &FPath) -> ForensicResult<BTreeMap<Text, Field>> {
        let mut attrs = BTreeMap::new();
        match which(path) {
            Some(true) => {}
            Some(false) => return Ok(attrs),
            None => return Err(not_found(path)),
        }
        attrs.insert(
            Text::Borrowed("raw.segment_count"),
            Field::U64(self.names.len() as u64),
        );
        attrs.insert(
            Text::Borrowed("raw.segments"),
            Field::Array(self.names.iter().map(|n| Text::Owned(n.clone())).collect()),
        );
        if let Some(missing) = &self.missing {
            attrs.insert(
                Text::Borrowed("raw.missing_segment"),
                Field::Text(Text::Owned(missing.clone())),
            );
        }
        Ok(attrs)
    }
}

impl MediaMap for SplitRawFs {
    fn to_parent(&self, path: &FPath, offset: u64) -> ForensicResult<Option<MediaOffset>> {
        if which(path) != Some(true) {
            return Err(not_found(path));
        }
        Ok(self.media.locate(offset).map(|(idx, inner)| MediaOffset {
            locator: self.locators[idx].clone(),
            offset: inner,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::resolver::MountResolver;
    use crate::traits::vfs::FileSystemExt;
    use crate::utils::testing::InMemoryVirtualFileSystem;

    fn resolver() -> MountResolver {
        MountResolver::builder()
            .factory(Arc::new(SplitRawFactory::new()))
            .build()
    }

    fn mount(fs: InMemoryVirtualFileSystem, first: &str) -> ForensicResult<Arc<dyn FileSystem>> {
        let fs: Arc<dyn FileSystem> = Arc::new(fs);
        let locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from(first)));
        let file = fs.open(FPath::new(first))?;
        let mounted = resolver().resolve(&fs, &locator, file, None, &Default::default())?;
        Ok(Arc::clone(mounted.as_file_system().expect("a filesystem")))
    }

    #[test]
    fn first_segment_accepts_only_segment_one() {
        assert_eq!(first_segment("disk.001"), Some(("disk.", 3)));
        assert_eq!(first_segment("disk.raw.0001"), Some(("disk.raw.", 4)));
        assert_eq!(first_segment("disk.002"), None);
        assert_eq!(first_segment("disk.01"), None);
        assert_eq!(first_segment("disk.dd"), None);
    }

    #[test]
    fn segments_join_in_numeric_order() {
        let fs = InMemoryVirtualFileSystem::new()
            .with_file("case/disk.002", b"DEF".to_vec())
            .with_file("case/disk.001", b"ABC".to_vec())
            .with_file("case/disk.003", b"GH".to_vec())
            .with_file("case/other.002", b"xx".to_vec());
        let image = mount(fs, "case/disk.001").unwrap();
        assert_eq!(image.read_all(FPath::new(MEDIA_FILE)).unwrap(), b"ABCDEFGH");
        assert_eq!(image.source(), SourceKind::Memory);
        let attrs = image
            .as_attributes()
            .unwrap()
            .attributes(FPath::new(MEDIA_FILE))
            .unwrap();
        assert_eq!(attrs.get("raw.segment_count"), Some(&Field::U64(3)));
        assert!(!attrs.contains_key("raw.missing_segment"));
    }

    #[test]
    fn a_gap_ends_the_media_and_is_reported() {
        let fs = InMemoryVirtualFileSystem::new()
            .with_file("disk.001", b"AB".to_vec())
            .with_file("disk.002", b"CD".to_vec())
            .with_file("disk.004", b"GH".to_vec());
        let image = mount(fs, "disk.001").unwrap();
        assert_eq!(image.read_all(FPath::new(MEDIA_FILE)).unwrap(), b"ABCD");
        let attrs = image
            .as_attributes()
            .unwrap()
            .attributes(FPath::new(MEDIA_FILE))
            .unwrap();
        assert_eq!(
            attrs.get("raw.missing_segment"),
            Some(&Field::Text(Text::Borrowed("disk.003")))
        );
    }

    #[test]
    fn a_lone_first_segment_is_not_claimed() {
        let fs = InMemoryVirtualFileSystem::new().with_file("disk.001", b"ABC".to_vec());
        assert!(mount(fs, "disk.001").is_err());
    }

    #[test]
    fn media_offsets_map_back_to_their_segment() {
        let fs = InMemoryVirtualFileSystem::new()
            .with_file("case/disk.001", b"ABC".to_vec())
            .with_file("case/disk.002", b"DEF".to_vec());
        let image = mount(fs, "case/disk.001").unwrap();
        let map = image.as_media_map().unwrap();
        let at = map.to_parent(FPath::new(MEDIA_FILE), 4).unwrap().unwrap();
        assert_eq!(at.offset, 1);
        assert_eq!(
            at.locator,
            EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from("case/disk.002")))
        );
        assert_eq!(map.to_parent(FPath::new(MEDIA_FILE), 6).unwrap(), None);
    }

    #[test]
    fn an_image_larger_than_every_expansion_budget_still_mounts() {
        use crate::core::limits::Limits;
        // Two 3 MiB segments against a 1 MiB expansion budget and a 1:1 ratio: an `Expansion`
        // hop this size is refused outright; a `View` hop must not be.
        let seg = vec![0xA5u8; 3 << 20];
        let fs: Arc<dyn FileSystem> = Arc::new(
            InMemoryVirtualFileSystem::new()
                .with_file("disk.001", seg.clone())
                .with_file("disk.002", seg),
        );
        let resolver = MountResolver::builder()
            .factory(Arc::new(SplitRawFactory::new()))
            .limits(Limits {
                max_expanded_bytes: 1 << 20,
                max_expansion_ratio: 1,
                max_resident_bytes: 1 << 20,
                ..Limits::default()
            })
            .build();
        let locator =
            EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from("disk.001")));
        let file = fs.open(FPath::new("disk.001")).unwrap();
        let mounted = resolver
            .resolve(&fs, &locator, file, None, &Default::default())
            .unwrap();
        let image = mounted.as_file_system().unwrap();
        assert_eq!(
            image.metadata(FPath::new(MEDIA_FILE)).unwrap().size,
            6 << 20
        );
        // Held in the cache at no byte cost, not evicted on arrival.
        assert_eq!(resolver.cache_len(), 1);
    }
}
