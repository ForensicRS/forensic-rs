//! Finding an artifact's files on a source whatever its layout.
//!
//! [`resolve_expansion`] answers "is the artifact where the definition says it is?". That is
//! the right question for a mounted volume, or a collection rooted at the system drive (KAPE's
//! `C/`), and the wrong one for a collection with its own layout (Triage-IR's
//! `CopiedFiles/registry/SYSTEM`, a folder of exported logs), where every definition resolves
//! to nothing. [`locate_files`] asks the first question and, when the source plainly doesn't
//! have the layout, falls back to the file names the same definitions end in. The catalog stays
//! the only list of names: nothing here is a parser's own guess.

use std::collections::{BTreeMap, BTreeSet};

use super::{Expansion, resolve_expansion};
use crate::core::fs::glob::segment_matches;
use crate::core::fs::walk::WalkOptions;
use crate::core::locator::{EvidenceLocator, LocatorSegment};
use crate::core::path::{FPath, FPathBuf};
use crate::err::ForensicError;
use crate::field::Text;
use crate::traits::vfs::{CaseSensitivity, FileSystem, FileSystemExt, VFileType};

/// How deep the search by file name goes below the source's root.
pub const FILE_NAME_SEARCH_DEPTH: u32 = 16;

/// How a file of an artifact was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FoundBy {
    /// At a location the definition names, for this host.
    Location,
    /// Only by its file name, because none of the requested definitions has a file at its
    /// locations on this source. The name is the definition's; the place is not, so a parser
    /// should check the format before treating the file as the artifact.
    FileName,
}

impl FoundBy {
    /// The value of [`crate::dictionary::ARTIFACT_LOCATED_BY`].
    pub fn as_str(&self) -> &'static str {
        match self {
            FoundBy::Location => "location",
            FoundBy::FileName => "file_name",
        }
    }
}

/// One file of an artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatedFile {
    pub locator: EvidenceLocator,
    pub path: FPathBuf,
    /// The definition the caller asked for that names this file (the first one, in the order
    /// asked, when several do).
    pub definition: Text,
    /// The definition that holds the path or name it matched: `definition` itself, or a member
    /// when `definition` is a group.
    pub artifact: Text,
    /// The user it was found for, when the location came from a `%%users.*%%` placeholder and
    /// the user is known. Always `None` for [`FoundBy::FileName`].
    pub sid: Option<String>,
    pub found_by: FoundBy,
}

/// Every file found for some definitions, and what got in the way.
#[derive(Debug, Default)]
pub struct LocatedFiles {
    /// Sorted by path, each path once.
    pub files: Vec<LocatedFile>,
    /// The expansions' notes, and whether and why names were searched instead of locations.
    pub notes: Vec<String>,
    /// Unknown definitions, unreadable directories and the like. A directory that couldn't be
    /// listed is a hole in the evidence, not an absent artifact.
    pub errors: Vec<ForensicError>,
}

impl LocatedFiles {
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// The file-name patterns `expansion`'s file globs end in, with the definition each comes from.
/// A last component made only of wildcards (`*`, `**`) names nothing, and a `PATH` source names
/// directories, so neither gives a pattern.
pub fn file_name_patterns(expansion: &Expansion) -> Vec<(String, Text)> {
    let mut out = BTreeSet::new();
    for glob in expansion.globs.iter().filter(|g| !g.directory) {
        let Some(last) = glob.pattern.rsplit(['\\', '/']).next() else {
            continue;
        };
        if last.chars().all(|c| matches!(c, '*' | '?')) {
            continue;
        }
        out.insert((last.to_string(), glob.artifact.clone()));
    }
    out.into_iter().collect()
}

/// Finds the files of every `(definition, expansion)` on `vfs`: at the expansions' locations,
/// or, when none of them has a file there, by the file names they end in
/// ([`file_name_patterns`], case-insensitive, at most [`FILE_NAME_SEARCH_DEPTH`] deep, in one
/// walk). Registry keys and values in the expansions are ignored.
///
/// The fallback is all or nothing on purpose. If any definition is at its location, the source
/// has the layout, and a definition missing from it is absent: searching a whole volume by name
/// for it would turn up copies (backups, a user's downloads) that aren't the artifact.
pub fn locate_files(
    expansions: Vec<(Text, Expansion)>,
    vfs: Option<&dyn FileSystem>,
) -> LocatedFiles {
    let mut out = LocatedFiles::default();
    let Some(vfs) = vfs else {
        if !expansions.is_empty() {
            out.notes
                .push("no filesystem configured: no file was searched".to_string());
        }
        return out;
    };

    let mut found: BTreeMap<FPathBuf, LocatedFile> = BTreeMap::new();
    let mut names: Vec<(String, Text, Text)> = Vec::new();
    for (definition, expansion) in expansions {
        names.extend(
            file_name_patterns(&expansion)
                .into_iter()
                .map(|(pattern, artifact)| (pattern, definition.clone(), artifact)),
        );
        let files_only = Expansion {
            keys: Vec::new(),
            values: Vec::new(),
            ..expansion
        };
        let resolution = resolve_expansion(files_only, Some(vfs), None);
        out.notes.extend(resolution.notes);
        out.errors.extend(resolution.errors);
        for file in resolution.files.into_iter().filter(|f| !f.directory) {
            found.entry(file.path.clone()).or_insert(LocatedFile {
                locator: file.locator,
                path: file.path,
                definition: definition.clone(),
                artifact: file.artifact,
                sid: file.sid,
                found_by: FoundBy::Location,
            });
        }
    }

    if found.is_empty() && !names.is_empty() {
        let listed: BTreeSet<&str> = names.iter().map(|(p, _, _)| p.as_str()).collect();
        out.notes.push(format!(
            "no file at any location the definitions name; searched by file name instead: {}",
            listed.into_iter().collect::<Vec<_>>().join(", ")
        ));
        let opts = WalkOptions::default()
            .with_max_depth(Some(FILE_NAME_SEARCH_DEPTH))
            .with_skip_errors(false);
        for item in vfs.walk(FPath::new(""), &opts) {
            let entry = match item {
                Ok(entry) => entry,
                Err(e) => {
                    out.errors.push(e);
                    continue;
                }
            };
            if entry.file_type != VFileType::File {
                continue;
            }
            let Some(name) = entry.path.as_path().file_name() else {
                continue;
            };
            let Some((_, definition, artifact)) = names
                .iter()
                .find(|(p, _, _)| segment_matches(p, name, CaseSensitivity::Insensitive))
            else {
                continue;
            };
            let located = LocatedFile {
                locator: EvidenceLocator::root().push(LocatorSegment::Path(entry.path.clone())),
                path: entry.path.clone(),
                definition: definition.clone(),
                artifact: artifact.clone(),
                sid: None,
                found_by: FoundBy::FileName,
            };
            found.entry(entry.path).or_insert(located);
        }
    }

    out.files = found.into_values().collect();
    out
}
