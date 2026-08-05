//! Lazy directory tree traversal over a [`FileSystem`].

use std::collections::HashSet;

use crate::core::path::FPath;
use crate::err::ForensicResult;
use crate::traits::vfs::{DirEntry, FileId, FileSystem, VFileType};

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
}

impl Default for WalkOptions {
    fn default() -> Self {
        WalkOptions {
            follow_symlinks: false,
            max_depth: None,
            skip_errors: true,
        }
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
                    if entry.file_type == VFileType::Directory
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
