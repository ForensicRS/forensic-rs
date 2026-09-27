//! [`resolve_expansion`]: an [`Expansion`] matched against the evidence.

use std::collections::BTreeSet;

use super::{Expansion, UnresolvedSource};
use crate::core::locator::{EvidenceLocator, LocatorSegment};
use crate::core::path::FPathBuf;
use crate::err::ForensicError;
use crate::field::Text;
use crate::traits::registry::{Registry, RegistryExt};
use crate::traits::vfs::{FileSystem, FileSystemExt};

/// A file or directory found for an artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedFile {
    pub locator: EvidenceLocator,
    pub path: FPathBuf,
    /// The user it was found for, when the pattern came from a
    /// `%%users.*%%` placeholder and the user is known.
    pub sid: Option<String>,
    pub artifact: Text,
    /// From a `PATH` source, which names directories.
    pub directory: bool,
}

/// A registry key that exists for an artifact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResolvedKey {
    pub path: String,
    pub sid: Option<String>,
    pub artifact: Text,
}

/// A registry value that exists for an artifact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResolvedValue {
    pub key: String,
    pub value: String,
    pub sid: Option<String>,
    pub artifact: Text,
}

/// Every location of an artifact found in the evidence. Empty lists with no
/// [`errors`](Self::errors) mean "not present"; errors mean part of the
/// evidence couldn't be examined.
#[derive(Debug, Default)]
pub struct ArtifactResolution {
    /// Sorted by path.
    pub files: Vec<ResolvedFile>,
    pub keys: Vec<ResolvedKey>,
    pub values: Vec<ResolvedValue>,
    /// Sources the expansion couldn't turn into patterns.
    pub unresolved: Vec<UnresolvedSource>,
    /// The expansion's notes, plus the sources that had no backend to
    /// search.
    pub notes: Vec<String>,
    /// Read errors met while searching: unreadable directories, registry
    /// keys or values that exist but can't be read.
    pub errors: Vec<ForensicError>,
}

impl ArtifactResolution {
    /// Whether nothing was found.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.keys.is_empty() && self.values.is_empty()
    }
}

/// Matches `expansion`'s globs against `vfs` and its key and value patterns
/// against `registry`. Keeps going past read errors, which it collects; a
/// missing backend leaves its patterns unsearched, with a note.
pub fn resolve_expansion(
    expansion: Expansion,
    vfs: Option<&dyn FileSystem>,
    registry: Option<&dyn Registry>,
) -> ArtifactResolution {
    let Expansion {
        globs,
        keys,
        values,
        unresolved,
        mut notes,
    } = expansion;
    let mut out = ArtifactResolution {
        unresolved,
        ..ArtifactResolution::default()
    };

    match vfs {
        Some(vfs) => {
            let mut found = BTreeSet::new();
            for glob in globs {
                let outcome = match vfs.glob_report(&glob.pattern) {
                    Ok(outcome) => outcome,
                    Err(e) => {
                        out.errors.push(e);
                        continue;
                    }
                };
                out.errors.extend(outcome.errors);
                for path in outcome.matches {
                    found.insert((
                        path.as_str().to_string(),
                        glob.sid.clone(),
                        glob.artifact.clone(),
                        glob.directory,
                    ));
                }
            }
            out.files = found
                .into_iter()
                .map(|(path, sid, artifact, directory)| {
                    let path = FPathBuf::from(path);
                    ResolvedFile {
                        locator: EvidenceLocator::root().push(LocatorSegment::Path(path.clone())),
                        path,
                        sid,
                        artifact,
                        directory,
                    }
                })
                .collect();
        }
        None if !globs.is_empty() => notes.push(format!(
            "no filesystem configured: {} file pattern(s) not searched",
            globs.len()
        )),
        None => {}
    }

    match registry {
        Some(reg) => {
            let mut found_keys = BTreeSet::new();
            for key in keys {
                match reg.expand_key_pattern(&key.pattern) {
                    Ok(paths) => found_keys.extend(paths.into_iter().map(|path| ResolvedKey {
                        path,
                        sid: key.sid.clone(),
                        artifact: key.artifact.clone(),
                    })),
                    Err(e) => out.errors.push(e),
                }
            }
            out.keys = found_keys.into_iter().collect();

            let mut found_values = BTreeSet::new();
            for value in values {
                let paths = match reg.expand_key_pattern(&value.key) {
                    Ok(paths) => paths,
                    Err(e) => {
                        out.errors.push(e);
                        continue;
                    }
                };
                for key in paths {
                    match reg.value(&key, &value.value) {
                        Ok(_) => {
                            found_values.insert(ResolvedValue {
                                key,
                                value: value.value.clone(),
                                sid: value.sid.clone(),
                                artifact: value.artifact.clone(),
                            });
                        }
                        Err(e) if e.is_registry_not_found() => {}
                        Err(e) => out.errors.push(e),
                    }
                }
            }
            out.values = found_values.into_iter().collect();
        }
        None if !keys.is_empty() || !values.is_empty() => notes.push(format!(
            "no registry configured: {} key and {} value pattern(s) not searched",
            keys.len(),
            values.len()
        )),
        None => {}
    }

    out.notes = notes;
    out
}
