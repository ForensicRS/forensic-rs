//! Glob-pattern matching over a [`FileSystem`], with mandatory prefix
//! optimization: a pattern is split at its first metacharacter, and the walk
//! starts from that literal prefix only. Walking from the filesystem root
//! for `C:/Users/*/NTUSER.DAT` would enumerate the whole image; starting
//! from `C:/Users` does not.
//!
//! Supports `*` (matches any run of characters within one path component),
//! `?` (matches exactly one character), and `**` (matches zero or more path
//! components, enabling recursive patterns like `**/winevt/Logs/*.evtx`).

use crate::core::fs::walk::{Walk, WalkOptions};
use crate::core::path::{FPath, FPathBuf};
use crate::traits::vfs::{CaseSensitivity, FileSystem};

/// Splits `pattern` into `(literal_prefix, pattern)` at the last separator
/// before the first metacharacter. `literal_prefix` is empty when the
/// pattern has no separator before its first metacharacter (or no
/// metacharacter at all).
fn split_glob_prefix(pattern: &str) -> &str {
    let meta_pos = pattern.find(['*', '?']).unwrap_or(pattern.len());
    let last_sep = pattern[..meta_pos].rfind(['/', '\\']);
    match last_sep {
        Some(i) => &pattern[..i],
        None => "",
    }
}

/// Case-aware glob match of a full pattern against a full path, component by
/// component. Pure and independently testable — no filesystem access.
///
/// Supports `*` (any run within one component), `?` (one character), and `**`
/// (zero or more path components, i.e. recursive wildcard).
pub fn matches(pattern: &str, path: &FPath, cs: CaseSensitivity) -> bool {
    let pattern_comps: Vec<&str> = pattern
        .split(['/', '\\'])
        .filter(|s| !s.is_empty())
        .collect();
    let path_comps: Vec<&str> = path.components().map(|c| c.as_str()).collect();
    match_components(&pattern_comps, &path_comps, cs)
}

/// Recursive backtracking matcher over pre-split component slices.
///
/// `**` is handled by trying two branches: consuming it (advance pattern only,
/// allowing it to match zero components) and expanding it (advance path only,
/// keeping `**` to match one more component).
fn match_components(pattern: &[&str], path: &[&str], cs: CaseSensitivity) -> bool {
    match (pattern.first(), path.first()) {
        (None, None) => true,
        (None, _) | (Some(_), None) if pattern.first() != Some(&"**") => false,
        (Some(&"**"), _) => {
            // consume ** (matches 0 components) or expand ** (matches 1 more)
            match_components(&pattern[1..], path, cs)
                || (!path.is_empty() && match_components(pattern, &path[1..], cs))
        }
        (Some(p), Some(s)) => {
            segment_matches(p, s, cs) && match_components(&pattern[1..], &path[1..], cs)
        }
        _ => false,
    }
}

fn segment_matches(pattern: &str, text: &str, cs: CaseSensitivity) -> bool {
    let case_fold = cs == CaseSensitivity::Insensitive;
    let p: Vec<char> = if case_fold {
        pattern.to_ascii_lowercase().chars().collect()
    } else {
        pattern.chars().collect()
    };
    let t: Vec<char> = if case_fold {
        text.to_ascii_lowercase().chars().collect()
    } else {
        text.chars().collect()
    };
    glob_match(&p, &t)
}

/// Classic two-pointer wildcard matcher supporting `*` and `?`.
fn glob_match(pattern: &[char], text: &[char]) -> bool {
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star_idx: Option<usize> = None;
    let mut match_idx = 0usize;
    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == '?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == '*' {
            star_idx = Some(pi);
            match_idx = ti;
            pi += 1;
        } else if let Some(si) = star_idx {
            pi = si + 1;
            match_idx += 1;
            ti = match_idx;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == '*' {
        pi += 1;
    }
    pi == pattern.len()
}

/// A lazy iterator over paths matching a glob pattern, returned by
/// [`crate::traits::vfs::FileSystemExt::glob_iter`].
pub struct Glob<'a, T: FileSystem + ?Sized> {
    walk: Walk<'a, T>,
    pattern: String,
    cs: CaseSensitivity,
}

impl<'a, T: FileSystem + ?Sized> Glob<'a, T> {
    pub fn new(fs: &'a T, pattern: &str, cs: CaseSensitivity) -> Self {
        let prefix = split_glob_prefix(pattern);
        let root = FPathBuf::from(prefix);
        let walk = Walk::new(fs, root.as_path(), WalkOptions::default());
        Glob {
            walk,
            pattern: pattern.to_string(),
            cs,
        }
    }
}

impl<'a, T: FileSystem + ?Sized> Iterator for Glob<'a, T> {
    type Item = FPathBuf;

    fn next(&mut self) -> Option<FPathBuf> {
        for entry in self.walk.by_ref() {
            let Ok(entry) = entry else { continue };
            if matches(&self.pattern, entry.path.as_path(), self.cs) {
                return Some(entry.path);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_prefix_stops_before_first_metachar() {
        assert_eq!(split_glob_prefix("C:/Users/*/NTUSER.DAT"), "C:/Users");
    }

    #[test]
    fn split_prefix_empty_when_metachar_in_first_component() {
        assert_eq!(split_glob_prefix("*.txt"), "");
    }

    #[test]
    fn split_prefix_handles_question_mark() {
        assert_eq!(split_glob_prefix("C:/Users/bob?/file"), "C:/Users");
    }

    #[test]
    fn matches_exact_path() {
        assert!(matches("C:/Windows/System32", FPath::new("C:/Windows/System32"), CaseSensitivity::Sensitive));
    }

    #[test]
    fn matches_star_within_one_component() {
        assert!(matches("C:/Users/*/NTUSER.DAT", FPath::new("C:/Users/Bob/NTUSER.DAT"), CaseSensitivity::Sensitive));
        assert!(!matches(
            "C:/Users/*/NTUSER.DAT",
            FPath::new("C:/Users/Bob/AppData/NTUSER.DAT"),
            CaseSensitivity::Sensitive
        ));
    }

    #[test]
    fn matches_question_mark_single_char() {
        assert!(matches("report?.txt", FPath::new("report1.txt"), CaseSensitivity::Sensitive));
        assert!(!matches("report?.txt", FPath::new("report12.txt"), CaseSensitivity::Sensitive));
    }

    #[test]
    fn matches_is_case_insensitive_when_requested() {
        assert!(matches("*.TXT", FPath::new("report.txt"), CaseSensitivity::Insensitive));
        assert!(!matches("*.TXT", FPath::new("report.txt"), CaseSensitivity::Sensitive));
    }

    #[test]
    fn matches_requires_same_component_count() {
        assert!(!matches("C:/Users/*", FPath::new("C:/Users/Bob/NTUSER.DAT"), CaseSensitivity::Sensitive));
    }

    #[test]
    fn double_star_matches_zero_components() {
        assert!(matches(
            "C:/Windows/**/foo.txt",
            FPath::new("C:/Windows/foo.txt"),
            CaseSensitivity::Sensitive
        ));
    }

    #[test]
    fn double_star_matches_one_component() {
        assert!(matches(
            "C:/Windows/**/foo.txt",
            FPath::new("C:/Windows/System32/foo.txt"),
            CaseSensitivity::Sensitive
        ));
    }

    #[test]
    fn double_star_matches_multiple_components() {
        assert!(matches(
            "C:/Windows/**/foo.txt",
            FPath::new("C:/Windows/a/b/c/foo.txt"),
            CaseSensitivity::Sensitive
        ));
    }

    #[test]
    fn double_star_at_end_matches_any_suffix() {
        assert!(matches(
            "C:/Users/**",
            FPath::new("C:/Users/Bob/AppData/Local/file.dat"),
            CaseSensitivity::Sensitive
        ));
    }

    #[test]
    fn double_star_alone_matches_any_path() {
        assert!(matches("**", FPath::new("a/b/c"), CaseSensitivity::Sensitive));
        assert!(matches("**", FPath::new("x"), CaseSensitivity::Sensitive));
    }

    #[test]
    fn single_star_still_rejects_depth_mismatch() {
        assert!(!matches(
            "C:/Users/*/file",
            FPath::new("C:/Users/Bob/AppData/file"),
            CaseSensitivity::Sensitive
        ));
    }

    #[test]
    fn matches_multiple_stars() {
        assert!(matches("*.tar.*", FPath::new("archive.tar.gz"), CaseSensitivity::Sensitive));
    }

    #[test]
    fn matches_star_can_match_empty() {
        assert!(matches("report*.txt", FPath::new("report.txt"), CaseSensitivity::Sensitive));
    }
}
