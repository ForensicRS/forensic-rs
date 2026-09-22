//! Lazy directory tree traversal over a [`FileSystem`].

use std::collections::HashSet;

use crate::core::path::FPath;
use crate::err::ForensicResult;
use crate::traits::vfs::{DirEntry, FileAttributes, FileId, FileSystem, VFileType};

/// Hard backstop against pathological or adversarial directory trees, even
/// when the caller passes `max_depth: None`.
const WALK_HARD_DEPTH_CAP: u32 = 4096;

/// Options controlling a [`Walk`].
#[derive(Debug, Clone)]
pub struct WalkOptions {
    /// Currently has no effect: [`VFileType`] doesn't yet distinguish a
    /// symlink pointing at a directory from one pointing at a file, so a
    /// walk never descends into a `VFileType::Symlink` entry regardless of
    /// this flag. Kept for forward compatibility with a future
    /// reparse-point-aware backend.
    ///
    /// DESIGN: revisit once a backend can report symlink targets.
    pub follow_symlinks: bool,
    pub max_depth: Option<u32>,
    /// If `true` (the default), an unreadable descendant directory is
    /// logged via [`crate::warn!`] rather than aborting the whole walk — the
    /// error is still yielded once as a `ForensicResult::Err` item (evidence
    /// that a subtree went unexamined), the walk just doesn't stop there.
    pub skip_errors: bool,
    /// Whether the walk descends into files flagged [`FileAttributes::CONTAINER`] (in addition
    /// to real directories) -- see `crate::core::fs::ContainerFs`, which is what sets that bit.
    ///
    /// `false` by default, and doubly safe: on a plain `FileSystem` nothing ever sets
    /// `CONTAINER`, so the default is a genuine no-op there too. A caller who wraps their
    /// filesystem in a `ContainerFs` still gets today's walk behavior until they opt in here --
    /// two independent switches, both off by default.
    pub descend_into_containers: bool,
}

impl Default for WalkOptions {
    fn default() -> Self {
        WalkOptions {
            follow_symlinks: false,
            max_depth: None,
            skip_errors: true,
            descend_into_containers: false,
        }
    }
}

impl WalkOptions {
    #[must_use]
    pub fn with_descend_into_containers(mut self, descend: bool) -> Self {
        self.descend_into_containers = descend;
        self
    }

    #[must_use]
    pub fn with_max_depth(mut self, max_depth: Option<u32>) -> Self {
        self.max_depth = max_depth;
        self
    }

    #[must_use]
    pub fn with_skip_errors(mut self, skip_errors: bool) -> Self {
        self.skip_errors = skip_errors;
        self
    }
}

#[derive(PartialEq, Eq, Hash)]
enum VisitedKey {
    Id(FileId),
    Path(String),
}

type DirEntryIter<'a> = Box<dyn Iterator<Item = ForensicResult<DirEntry>> + 'a>;

/// A lazy, depth-first traversal of a [`FileSystem`] starting at a root
/// path. Driven by an explicit stack rather than recursion, so depth is
/// bounded by a real counter, not the call stack.
///
/// Generic over `T: FileSystem + ?Sized` (rather than storing `&'a dyn
/// FileSystem` directly) so [`crate::traits::vfs::FileSystemExt`]'s default
/// `walk` method can return one without an unsized coercion from `&Self` —
/// which fails to type-check generically since `Self` may already be `dyn
/// FileSystem`. This lets `.walk()` work identically whether called on a
/// concrete backend or on `Arc<dyn FileSystem>`.
pub struct Walk<'a, T: FileSystem + ?Sized> {
    fs: &'a T,
    stack: Vec<(DirEntryIter<'a>, u32)>,
    visited: HashSet<VisitedKey>,
    opts: WalkOptions,
    pending_error: Option<crate::err::ForensicError>,
}

impl<'a, T: FileSystem + ?Sized> Walk<'a, T> {
    pub fn new(fs: &'a T, root: &FPath, opts: WalkOptions) -> Self {
        let mut walk = Walk {
            fs,
            stack: Vec::new(),
            visited: HashSet::new(),
            opts,
            pending_error: None,
        };
        walk.push_dir(root, 0);
        walk
    }

    fn push_dir(&mut self, path: &FPath, depth: u32) {
        match self.fs.read_dir(path) {
            Ok(iter) => self.stack.push((iter, depth)),
            Err(e) => {
                if self.opts.skip_errors {
                    crate::warn!("walk: skipping unreadable dir {path}: {e}");
                }
                // Surfaced as a yielded item either way — the walk doesn't
                // abort (the stack still holds the other pending
                // directories), but a skipped subtree is evidence a caller
                // should be able to see, not just an operational log line.
                self.pending_error = Some(e);
            }
        }
    }

    /// Whether `entry` is flagged [`FileAttributes::CONTAINER`]. Prefers the metadata the
    /// backend already attached to the `DirEntry` (documented as populated only
    /// "opportunistically"); falls back to a `metadata()` call so this works over any backend
    /// regardless, gated entirely behind `descend_into_containers` so it can never cost the
    /// default walk anything. A backend that populates `DirEntry::metadata` itself halves the
    /// cost of a container-descending walk.
    fn is_container(&self, entry: &DirEntry) -> bool {
        if let Some(m) = entry.metadata.as_ref() {
            return m.attributes.contains(FileAttributes::CONTAINER);
        }
        self.fs.metadata(entry.path.as_path()).map(|m| m.attributes.contains(FileAttributes::CONTAINER)).unwrap_or(false)
    }
}

impl<'a, T: FileSystem + ?Sized> Iterator for Walk<'a, T> {
    type Item = ForensicResult<DirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(e) = self.pending_error.take() {
            return Some(Err(e));
        }
        loop {
            let (iter, depth) = self.stack.last_mut()?;
            let depth = *depth;
            match iter.next() {
                Some(Ok(entry)) => {
                    let is_dir = entry.file_type == VFileType::Directory;
                    let is_container = self.opts.descend_into_containers && !is_dir && self.is_container(&entry);
                    if (is_dir || is_container)
                        && depth < WALK_HARD_DEPTH_CAP
                        && self.opts.max_depth.is_none_or(|m| depth < m)
                    {
                        let key = entry
                            .metadata
                            .as_ref()
                            .and_then(|m| m.id)
                            .map(VisitedKey::Id)
                            .unwrap_or_else(|| VisitedKey::Path(entry.path.as_str().to_string()));
                        if self.visited.insert(key) {
                            let child_path = entry.path.clone();
                            self.push_dir(&child_path, depth + 1);
                        }
                    }
                    return Some(Ok(entry));
                }
                Some(Err(e)) => {
                    if self.opts.skip_errors {
                        crate::warn!("walk: error reading entry: {e}");
                    }
                    // Yielded either way — the underlying iterator already
                    // advanced past this entry, so returning it here doesn't
                    // stop the walk, it just stops the error from being
                    // silently dropped.
                    return Some(Err(e));
                }
                None => {
                    self.stack.pop();
                    continue;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::path::FPathBuf;
    use crate::err::ForensicError;
    use crate::traits::vfs::{MacbTimes, SourceKind, VMetadata, VirtualFile};
    use std::collections::BTreeMap;

    /// A minimal `FileSystem` double whose `read_dir` is driven entirely by a
    /// `path -> Vec<DirEntry>` map, so `CONTAINER`-descent can be tested without a real
    /// container-mounting backend.
    struct MapFs(BTreeMap<String, Vec<DirEntry>>);

    struct EmptyFile;
    impl std::io::Read for EmptyFile {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }
    impl std::io::Seek for EmptyFile {
        fn seek(&mut self, _pos: std::io::SeekFrom) -> std::io::Result<u64> {
            Ok(0)
        }
    }
    impl VirtualFile for EmptyFile {
        fn metadata(&self) -> ForensicResult<VMetadata> {
            Ok(VMetadata {
                file_type: VFileType::File,
                size: 0,
                allocated_size: None,
                times: MacbTimes::default(),
                id: None,
                attributes: FileAttributes::empty(),
            })
        }
    }

    fn dir_entry(path: &str, file_type: VFileType, container: bool) -> DirEntry {
        DirEntry {
            path: FPathBuf::from(path),
            file_type,
            metadata: Some(VMetadata {
                file_type,
                size: 0,
                allocated_size: None,
                times: MacbTimes::default(),
                id: None,
                attributes: if container { FileAttributes::CONTAINER } else { FileAttributes::empty() },
            }),
        }
    }

    impl FileSystem for MapFs {
        fn open(&self, _path: &FPath) -> ForensicResult<Box<dyn VirtualFile>> {
            Ok(Box::new(EmptyFile))
        }
        fn metadata(&self, path: &FPath) -> ForensicResult<VMetadata> {
            self.0
                .get(path.as_str())
                .map(|_| VMetadata {
                    file_type: VFileType::Directory,
                    size: 0,
                    allocated_size: None,
                    times: MacbTimes::default(),
                    id: None,
                    attributes: FileAttributes::empty(),
                })
                .ok_or_else(|| ForensicError::path_not_found(path.to_string()))
        }
        fn read_dir(&self, path: &FPath) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<DirEntry>> + '_>> {
            match self.0.get(path.as_str()) {
                Some(entries) => Ok(Box::new(entries.clone().into_iter().map(Ok))),
                None => Err(ForensicError::path_not_found(path.to_string())),
            }
        }
        fn source(&self) -> SourceKind {
            SourceKind::Memory
        }
    }

    fn container_fixture() -> MapFs {
        let mut fs = BTreeMap::new();
        fs.insert(
            "".to_string(),
            vec![dir_entry("report.doc", VFileType::File, true), dir_entry("plain.txt", VFileType::File, false)],
        );
        fs.insert("report.doc".to_string(), vec![dir_entry("report.doc/WordDocument", VFileType::File, false)]);
        MapFs(fs)
    }

    #[test]
    fn default_options_do_not_descend_into_a_container_flagged_file() {
        let fs = container_fixture();
        let mut entries: Vec<String> =
            Walk::new(&fs, FPath::new(""), WalkOptions::default()).map(|e| e.unwrap().path.to_string()).collect();
        entries.sort();
        assert_eq!(entries, vec!["plain.txt", "report.doc"]);
    }

    #[test]
    fn descend_into_containers_reaches_the_container_s_own_children() {
        let fs = container_fixture();
        let opts = WalkOptions::default().with_descend_into_containers(true);
        let mut entries: Vec<String> = Walk::new(&fs, FPath::new(""), opts).map(|e| e.unwrap().path.to_string()).collect();
        entries.sort();
        assert_eq!(entries, vec!["plain.txt", "report.doc", "report.doc/WordDocument"]);
    }

    #[test]
    fn a_container_entry_is_still_yielded_with_its_own_file_type() {
        // The container file itself must still be reported as a File (so read_all/hashing still
        // gets the original bytes), even though the walk descends past it.
        let fs = container_fixture();
        let opts = WalkOptions::default().with_descend_into_containers(true);
        let container = Walk::new(&fs, FPath::new(""), opts).map(|e| e.unwrap()).find(|e| e.path.as_str() == "report.doc").unwrap();
        assert_eq!(container.file_type, VFileType::File);
    }

    #[test]
    fn glob_style_default_is_unaffected_by_the_new_option() {
        // WalkOptions::default() must keep descend_into_containers off -- proven by the same
        // assertion as the first test, phrased as a regression guard on the Default impl itself.
        assert!(!WalkOptions::default().descend_into_containers);
    }
}
