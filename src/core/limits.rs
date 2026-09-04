//! Resource budgets for processing hostile/untrusted evidence containers.
//!
//! Triage evidence is attacker-influenced input: a zip bomb, a deeply
//! nested archive, or a forward-only compressed stream that needs full
//! materialization to seek can each turn a bounded triage run into an
//! unbounded one. [`Limits`] and [`SpillStore`] give the mount resolver
//! (`crate::core::resolver::MountResolver`) somewhere to enforce budgets
//! deterministically, with every refusal reported rather than silently
//! swallowed or truncated.

use std::io::{Cursor, Read, Seek, SeekFrom};

use crate::err::{ForensicError, ForensicResult};
use crate::traits::vfs::{FileAttributes, MacbTimes, VFileType, VMetadata, VirtualFile};

/// Resource budgets applied while resolving nested containers.
///
/// `Clone` so a resolver can hand a narrowed copy (e.g. a smaller remaining
/// byte budget) down into a recursive mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum containment/interpretation/embedding hops from the top-level
    /// evidence item.
    pub max_nesting_depth: u32,
    /// Maximum total bytes materialized across every mount in one
    /// resolution (not per-container -- a budget shared across the whole
    /// chain, so ten small archives cannot each individually pass a
    /// per-container check and still sum to an unbounded expansion).
    pub max_expanded_bytes: u64,
    /// Maximum directory/archive entries read from one container.
    pub max_entries_per_container: u64,
    /// Maximum ratio of expanded bytes to compressed input bytes, a
    /// zip-bomb-specific guard independent of the absolute byte budget.
    pub max_expansion_ratio: u32,
    /// Below this size, in-memory materialization is used directly, no
    /// [`SpillStore`] call. Above it, the resolver asks the configured
    /// `SpillStore` to hand back a seekable backing.
    pub materialize_in_memory_limit: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_nesting_depth: 8,
            max_expanded_bytes: 1 << 30, // 1 GiB
            max_entries_per_container: 100_000,
            max_expansion_ratio: 200,
            materialize_in_memory_limit: 32 << 20, // 32 MiB
        }
    }
}

/// Why a resolution step was refused by [`Limits`] enforcement.
///
/// Every variant is meant to become a `Finding` at the call site -- a zip
/// bomb inside a triage collection is itself a reportable observation, not
/// a silent stop.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitExceeded {
    NestingDepth { at: u32, max: u32 },
    ExpandedBytes { would_total: u64, max: u64 },
    EntriesPerContainer { at: u64, max: u64 },
    ExpansionRatio { observed: u32, max: u32 },
}

impl std::fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LimitExceeded::NestingDepth { at, max } => {
                write!(f, "nesting depth {at} exceeds limit {max}")
            }
            LimitExceeded::ExpandedBytes { would_total, max } => write!(
                f,
                "expanding would total {would_total} bytes, exceeding limit {max}"
            ),
            LimitExceeded::EntriesPerContainer { at, max } => {
                write!(f, "container entry count {at} exceeds limit {max}")
            }
            LimitExceeded::ExpansionRatio { observed, max } => write!(
                f,
                "expansion ratio {observed}:1 exceeds limit {max}:1"
            ),
        }
    }
}

/// Provides a seekable backing for content that must be fully materialized
/// to be interpreted (e.g. a SQLite database mounted over a forward-only
/// deflate stream) but is too large to hold as a plain in-memory buffer.
///
/// Writing evidence-derived bytes to disk is a decision an examiner must
/// own, not a library default: core ships only [`MemorySpillStore`], which
/// refuses rather than spilling to a temp file. A `TempDirSpillStore` is a
/// downstream concern, with the spill directory chosen explicitly by the
/// caller.
pub trait SpillStore: Send + Sync {
    fn spill(
        &self,
        src: &mut dyn Read,
        size_hint: Option<u64>,
    ) -> ForensicResult<Box<dyn VirtualFile>>;
}

/// The only [`SpillStore`] core ships: materializes into memory up to
/// [`Limits::materialize_in_memory_limit`] and refuses past it.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemorySpillStore {
    pub limit: usize,
}

impl MemorySpillStore {
    pub fn new(limit: usize) -> Self {
        Self { limit }
    }
}

struct MemoryFile(Cursor<Vec<u8>>);

impl Read for MemoryFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Seek for MemoryFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.0.seek(pos)
    }
}

impl VirtualFile for MemoryFile {
    fn metadata(&self) -> ForensicResult<VMetadata> {
        Ok(VMetadata {
            file_type: VFileType::File,
            size: self.0.get_ref().len() as u64,
            allocated_size: None,
            times: MacbTimes::default(),
            id: None,
            attributes: FileAttributes::empty(),
        })
    }
}

impl SpillStore for MemorySpillStore {
    fn spill(
        &self,
        src: &mut dyn Read,
        size_hint: Option<u64>,
    ) -> ForensicResult<Box<dyn VirtualFile>> {
        if let Some(hint) = size_hint {
            if hint as usize > self.limit {
                return Err(ForensicError::other(
                    "MemorySpillStore",
                    format!(
                        "refusing to materialize {hint} bytes in memory (limit {})",
                        self.limit
                    ),
                ));
            }
        }
        // Read one byte past the limit to detect an unbounded/lying
        // size_hint without ever holding more than limit+1 bytes.
        let mut buf = Vec::with_capacity(size_hint.unwrap_or(0).min(self.limit as u64) as usize);
        let mut chunk = [0u8; 64 * 1024];
        loop {
            let n = src
                .read(&mut chunk)
                .map_err(|e| ForensicError::other("MemorySpillStore", e.to_string()))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > self.limit {
                return Err(ForensicError::other(
                    "MemorySpillStore",
                    format!(
                        "content exceeds in-memory materialization limit ({} bytes)",
                        self.limit
                    ),
                ));
            }
        }
        Ok(Box::new(MemoryFile(Cursor::new(buf))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spill_within_limit_succeeds_and_is_readable() {
        let store = MemorySpillStore::new(1024);
        let mut src: &[u8] = b"hello world";
        let mut file = store.spill(&mut src, Some(11)).unwrap();
        let mut out = Vec::new();
        file.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn spill_rejects_declared_size_over_limit_without_reading() {
        let store = MemorySpillStore::new(4);
        let mut src: &[u8] = b"way too big for this";
        assert!(store.spill(&mut src, Some(1000)).is_err());
    }

    #[test]
    fn spill_rejects_actual_content_over_limit_even_with_no_hint() {
        let store = MemorySpillStore::new(4);
        let mut src: &[u8] = b"way too big for this";
        assert!(store.spill(&mut src, None).is_err());
    }

    #[test]
    fn limit_exceeded_display_is_human_readable() {
        let err = LimitExceeded::NestingDepth { at: 9, max: 8 };
        assert_eq!(err.to_string(), "nesting depth 9 exceeds limit 8");
    }
}
