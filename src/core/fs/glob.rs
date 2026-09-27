//! Glob-pattern matching over a [`FileSystem`], with mandatory prefix
//! optimization: a pattern is split at its first metacharacter, and the walk
//! starts from that literal prefix only. Walking from the filesystem root
//! for `C:/Users/*/NTUSER.DAT` would enumerate the whole image; starting
//! from `C:/Users` does not.
//!
//! Syntax, per path component:
//! - `*` matches any run of characters within one component;
//! - `?` matches exactly one character;
//! - `[abc]`, `[a-z]` and `[!a-z]` (or `[^a-z]`) match one character from, or
//!   not from, a set; an unterminated `[` is a literal;
//! - `**` as a whole component matches zero or more components, enabling
//!   recursive patterns like `**/winevt/Logs/*.evtx`;
//! - `**N` as a whole component (for example `**5`) matches zero to `N`
//!   components. This is the ForensicArtifacts bounded-recursion syntax.
//!
//! When a pattern has no unbounded `**`, the walk is pruned to the deepest
//! level the pattern can reach.

use crate::core::fs::walk::{Walk, WalkOptions};
use crate::core::path::{FPath, FPathBuf};
use crate::err::ForensicError;
use crate::traits::vfs::{CaseSensitivity, FileSystem};

/// Splits `pattern` into `(literal_prefix, pattern)` at the last separator
/// before the first metacharacter. `literal_prefix` is empty when the
/// pattern has no separator before its first metacharacter (or no
/// metacharacter at all).
fn split_glob_prefix(pattern: &str) -> &str {
    let meta_pos = pattern.find(['*', '?', '[']).unwrap_or(pattern.len());
    let last_sep = pattern[..meta_pos].rfind(['/', '\\']);
    match last_sep {
        Some(i) => &pattern[..i],
        None => "",
    }
}

/// One pre-parsed pattern component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Component<'p> {
    /// `**` (`None`) or `**N` (`Some(N)`).
    Globstar(Option<u32>),
    /// Any other component, matched within one path component.
    Segment(&'p str),
}

pub(crate) fn parse_component(s: &str) -> Component<'_> {
    match s.strip_prefix("**") {
        Some("") => Component::Globstar(None),
        Some(n) if n.bytes().all(|b| b.is_ascii_digit()) => {
            Component::Globstar(n.parse().ok().or(Some(u32::MAX)))
        }
        _ => Component::Segment(s),
    }
}

fn split_components(pattern: &str) -> Vec<Component<'_>> {
    pattern
        .split(['/', '\\'])
        .filter(|s| !s.is_empty())
        .map(parse_component)
        .collect()
}

/// The deepest walk level (0 = the prefix directory's own entries) that
/// `pattern` can reach below its literal prefix, or `None` when it contains
/// an unbounded `**`.
fn max_walk_depth(pattern: &str) -> Option<u32> {
    let prefix = split_glob_prefix(pattern);
    let levels = split_components(&pattern[prefix.len()..])
        .into_iter()
        .try_fold(0u32, |acc, c| match c {
            Component::Globstar(None) => None,
            Component::Globstar(Some(n)) => Some(acc.saturating_add(n)),
            Component::Segment(_) => Some(acc.saturating_add(1)),
        })?;
    Some(levels.saturating_sub(1))
}

/// Case-aware glob match of a full pattern against a full path, component by
/// component. Pure and independently testable — no filesystem access.
///
/// See the [module docs](self) for the supported syntax.
pub fn matches(pattern: &str, path: &FPath, cs: CaseSensitivity) -> bool {
    let pattern_comps = split_components(pattern);
    // The pattern side drops separators, so a leading root means nothing
    // there; drop it here too, or no rooted path (`/Windows/..`, as a
    // `ChRootFileSystem` or an absolute `StdVirtualFS` path yields) could
    // ever match.
    let path_comps: Vec<&str> = path
        .components()
        .filter(|c| !matches!(c, crate::core::path::Component::RootDir))
        .map(|c| c.as_str())
        .collect();
    match_components(&pattern_comps, &path_comps, cs)
}

/// Recursive backtracking matcher over pre-split component slices.
///
/// A globstar is handled by trying two branches: consuming it (advance
/// pattern only, allowing it to match zero components) and expanding it
/// (advance path only, keeping the globstar with one less component of
/// budget).
fn match_components(pattern: &[Component<'_>], path: &[&str], cs: CaseSensitivity) -> bool {
    match (pattern.first(), path.first()) {
        (None, None) => true,
        (None, Some(_)) => false,
        (Some(Component::Globstar(limit)), _) => {
            if match_components(&pattern[1..], path, cs) {
                return true;
            }
            if path.is_empty() || *limit == Some(0) {
                return false;
            }
            let mut rest = pattern.to_vec();
            rest[0] = Component::Globstar(limit.map(|n| n - 1));
            match_components(&rest, &path[1..], cs)
        }
        (Some(Component::Segment(p)), Some(s)) => {
            segment_matches(p, s, cs) && match_components(&pattern[1..], &path[1..], cs)
        }
        (Some(Component::Segment(_)), None) => false,
    }
}

/// Case-aware match of one pattern component against one path component.
/// Public so the registry key-pattern expansion shares the exact same syntax.
pub fn segment_matches(pattern: &str, text: &str, cs: CaseSensitivity) -> bool {
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

/// Two-pointer wildcard matcher supporting `*`, `?` and `[..]` classes.
fn glob_match(pattern: &[char], text: &[char]) -> bool {
    let (mut pi, mut ti) = (0usize, 0usize);
    // (index of the last `*`, text index it is currently matched up to)
    let mut star: Option<(usize, usize)> = None;
    while ti < text.len() {
        if pi < pattern.len() && pattern[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
            continue;
        }
        if let Some(next) = match_single(pattern, pi, text[ti]) {
            pi = next;
            ti += 1;
            continue;
        }
        match star {
            Some((si, mi)) => {
                pi = si + 1;
                ti = mi + 1;
                star = Some((si, mi + 1));
            }
            None => return false,
        }
    }
    while pi < pattern.len() && pattern[pi] == '*' {
        pi += 1;
    }
    pi == pattern.len()
}

/// Matches the single-character token at `pattern[pi]` against `c`, and
/// returns the index after the token on a match.
fn match_single(pattern: &[char], pi: usize, c: char) -> Option<usize> {
    match *pattern.get(pi)? {
        '?' => Some(pi + 1),
        '[' => match match_class(pattern, pi, c) {
            Some((true, next)) => Some(next),
            Some((false, _)) => None,
            // unterminated class: `[` is a literal
            None => (c == '[').then_some(pi + 1),
        },
        p => (p == c).then_some(pi + 1),
    }
}

/// Evaluates the class starting at `pattern[start] == '['`. Returns whether
/// `c` matches and the index after the closing `]`, or `None` when the class
/// is unterminated. A `]` right after the opening (or negation) is a member.
fn match_class(pattern: &[char], start: usize, c: char) -> Option<(bool, usize)> {
    let mut i = start + 1;
    let negate = matches!(pattern.get(i), Some('!' | '^'));
    if negate {
        i += 1;
    }
    let mut matched = false;
    let mut first = true;
    loop {
        let p = *pattern.get(i)?;
        if p == ']' && !first {
            return Some((matched != negate, i + 1));
        }
        first = false;
        match (pattern.get(i + 1), pattern.get(i + 2)) {
            (Some('-'), Some(&hi)) if hi != ']' => {
                matched |= (p..=hi).contains(&c);
                i += 3;
            }
            _ => {
                matched |= p == c;
                i += 1;
            }
        }
    }
}

/// The result of [`crate::traits::vfs::FileSystemExt::glob_report`]: every
/// match, plus the errors met along the walk (unreadable directories or
/// entries). A literal prefix that does not exist is not an error: it just
/// yields no matches.
#[derive(Debug, Default)]
pub struct GlobOutcome {
    pub matches: Vec<FPathBuf>,
    pub errors: Vec<ForensicError>,
}

/// A lazy iterator over paths matching a glob pattern, returned by
/// [`crate::traits::vfs::FileSystemExt::glob_iter`].
///
/// Walk errors don't stop the iteration. They are collected, and
/// [`errors`](Self::errors) returns them once the iterator is drained.
pub struct Glob<'a, T: FileSystem + ?Sized> {
    walk: Walk<'a, T>,
    pattern: String,
    cs: CaseSensitivity,
    errors: Vec<ForensicError>,
}

impl<'a, T: FileSystem + ?Sized> Glob<'a, T> {
    pub fn new(fs: &'a T, pattern: &str, cs: CaseSensitivity) -> Self {
        let prefix = split_glob_prefix(pattern);
        let root = FPathBuf::from(prefix);
        let opts = WalkOptions::default().with_max_depth(max_walk_depth(pattern));
        let mut walk = Walk::new(fs, root.as_path(), opts);
        // A missing prefix only means "nothing here", not a failed read.
        walk.clear_root_error_if(ForensicError::is_path_not_found);
        Glob {
            walk,
            pattern: pattern.to_string(),
            cs,
            errors: Vec::new(),
        }
    }

    /// The walk errors met so far.
    pub fn errors(&self) -> &[ForensicError] {
        &self.errors
    }

    /// Drains the iterator into a [`GlobOutcome`].
    pub fn into_outcome(mut self) -> GlobOutcome {
        let matches = self.by_ref().collect();
        GlobOutcome {
            matches,
            errors: self.errors,
        }
    }
}

impl<'a, T: FileSystem + ?Sized> Iterator for Glob<'a, T> {
    type Item = FPathBuf;

    fn next(&mut self) -> Option<FPathBuf> {
        for entry in self.walk.by_ref() {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    self.errors.push(e);
                    continue;
                }
            };
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
        assert!(matches(
            "C:/Windows/System32",
            FPath::new("C:/Windows/System32"),
            CaseSensitivity::Sensitive
        ));
    }

    #[test]
    fn matches_star_within_one_component() {
        assert!(matches(
            "C:/Users/*/NTUSER.DAT",
            FPath::new("C:/Users/Bob/NTUSER.DAT"),
            CaseSensitivity::Sensitive
        ));
        assert!(!matches(
            "C:/Users/*/NTUSER.DAT",
            FPath::new("C:/Users/Bob/AppData/NTUSER.DAT"),
            CaseSensitivity::Sensitive
        ));
    }

    #[test]
    fn matches_question_mark_single_char() {
        assert!(matches(
            "report?.txt",
            FPath::new("report1.txt"),
            CaseSensitivity::Sensitive
        ));
        assert!(!matches(
            "report?.txt",
            FPath::new("report12.txt"),
            CaseSensitivity::Sensitive
        ));
    }

    #[test]
    fn matches_is_case_insensitive_when_requested() {
        assert!(matches(
            "*.TXT",
            FPath::new("report.txt"),
            CaseSensitivity::Insensitive
        ));
        assert!(!matches(
            "*.TXT",
            FPath::new("report.txt"),
            CaseSensitivity::Sensitive
        ));
    }

    #[test]
    fn matches_requires_same_component_count() {
        assert!(!matches(
            "C:/Users/*",
            FPath::new("C:/Users/Bob/NTUSER.DAT"),
            CaseSensitivity::Sensitive
        ));
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
        assert!(matches(
            "**",
            FPath::new("a/b/c"),
            CaseSensitivity::Sensitive
        ));
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
        assert!(matches(
            "*.tar.*",
            FPath::new("archive.tar.gz"),
            CaseSensitivity::Sensitive
        ));
    }

    #[test]
    fn matches_star_can_match_empty() {
        assert!(matches(
            "report*.txt",
            FPath::new("report.txt"),
            CaseSensitivity::Sensitive
        ));
    }

    #[test]
    fn split_prefix_stops_before_a_character_class() {
        assert_eq!(split_glob_prefix("var/log/gc.log.[0-9]"), "var/log");
    }

    #[test]
    fn bounded_globstar_matches_up_to_n_components() {
        let cs = CaseSensitivity::Sensitive;
        assert!(matches("a/**2/f", FPath::new("a/f"), cs));
        assert!(matches("a/**2/f", FPath::new("a/b/f"), cs));
        assert!(matches("a/**2/f", FPath::new("a/b/c/f"), cs));
        assert!(!matches("a/**2/f", FPath::new("a/b/c/d/f"), cs));
    }

    #[test]
    fn bounded_globstar_at_end_limits_the_suffix() {
        let cs = CaseSensitivity::Sensitive;
        assert!(matches("Extensions/**1", FPath::new("Extensions/abc"), cs));
        assert!(!matches(
            "Extensions/**1",
            FPath::new("Extensions/abc/def"),
            cs
        ));
    }

    #[test]
    fn character_class_matches_members_and_ranges() {
        let cs = CaseSensitivity::Sensitive;
        assert!(matches("gc.log.[0-9]", FPath::new("gc.log.7"), cs));
        assert!(!matches("gc.log.[0-9]", FPath::new("gc.log.x"), cs));
        assert!(matches("[a-z][0-9]", FPath::new("q4"), cs));
        assert!(matches("swapfile[0-9]*", FPath::new("swapfile12"), cs));
        assert!(matches("[abc].txt", FPath::new("b.txt"), cs));
    }

    #[test]
    fn negated_character_class() {
        let cs = CaseSensitivity::Sensitive;
        assert!(matches("[!0-9]x", FPath::new("ax"), cs));
        assert!(!matches("[!0-9]x", FPath::new("5x"), cs));
        assert!(matches("[^0-9]x", FPath::new("ax"), cs));
    }

    #[test]
    fn character_class_folds_case_when_insensitive() {
        assert!(matches(
            "[A-C].TXT",
            FPath::new("b.txt"),
            CaseSensitivity::Insensitive
        ));
        assert!(!matches(
            "[A-C].TXT",
            FPath::new("b.txt"),
            CaseSensitivity::Sensitive
        ));
    }

    #[test]
    fn unterminated_class_is_a_literal_bracket() {
        assert!(matches(
            "a[b",
            FPath::new("a[b"),
            CaseSensitivity::Sensitive
        ));
        assert!(!matches(
            "a[b",
            FPath::new("ab"),
            CaseSensitivity::Sensitive
        ));
    }

    #[test]
    fn walk_depth_is_bounded_unless_the_pattern_has_a_bare_globstar() {
        assert_eq!(max_walk_depth("Users/*/NTUSER.DAT"), Some(1));
        assert_eq!(max_walk_depth("Users/**3/x"), Some(3));
        assert_eq!(max_walk_depth("Users/**/x"), None);
        assert_eq!(max_walk_depth("Windows/Prefetch/*.pf"), Some(0));
    }

    mod over_a_filesystem {
        use super::*;
        use crate::err::ForensicResult;
        use crate::traits::vfs::{DirEntry, FileSystemExt, SourceKind, VMetadata, VirtualFile};
        use crate::utils::testing::InMemoryVirtualFileSystem;

        /// Delegates to an in-memory filesystem, but fails `read_dir` on one path.
        struct FailingDir {
            inner: InMemoryVirtualFileSystem,
            broken: &'static str,
        }

        impl FileSystem for FailingDir {
            fn open(&self, path: &FPath) -> ForensicResult<Box<dyn VirtualFile>> {
                self.inner.open(path)
            }
            fn metadata(&self, path: &FPath) -> ForensicResult<VMetadata> {
                self.inner.metadata(path)
            }
            fn read_dir(
                &self,
                path: &FPath,
            ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<DirEntry>> + '_>>
            {
                if path.as_str() == self.broken {
                    return Err(ForensicError::other("test", "unreadable directory".into()));
                }
                self.inner.read_dir(path)
            }
            fn source(&self) -> SourceKind {
                SourceKind::Memory
            }
        }

        fn fs() -> InMemoryVirtualFileSystem {
            InMemoryVirtualFileSystem::new()
                .with_file("Users/alice/NTUSER.DAT", b"a".to_vec())
                .with_file("Users/bob/NTUSER.DAT", b"b".to_vec())
                .with_file("Users/bob/deep/er/x.log.1", b"c".to_vec())
        }

        #[test]
        fn rooted_paths_match_rooted_and_unrooted_patterns() {
            let cs = CaseSensitivity::Sensitive;
            assert!(matches("/etc/*", FPath::new("/etc/passwd"), cs));
            assert!(matches("\\Windows\\*.pf", FPath::new("/Windows/A.pf"), cs));
            assert!(matches("Windows/*.pf", FPath::new("/Windows/A.pf"), cs));
        }

        #[test]
        fn a_rooted_literal_prefix_matches_through_a_chroot() {
            let inner = InMemoryVirtualFileSystem::new()
                .with_file("ev/Windows/Prefetch/A.pf", b"x".to_vec());
            let fs = crate::core::fs::ChRootFileSystem::new("ev", std::sync::Arc::new(inner));
            let got = fs.glob("\\Windows\\Prefetch\\*.pf").unwrap();
            assert_eq!(got.len(), 1, "{got:?}");
        }

        #[test]
        fn a_missing_prefix_is_no_matches_not_an_error() {
            let outcome = fs().glob_report("Windows/Prefetch/*.pf").unwrap();
            assert!(outcome.matches.is_empty());
            assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        }

        #[test]
        fn returns_every_match() {
            let outcome = fs().glob_report("Users/*/NTUSER.DAT").unwrap();
            let got: Vec<&str> = outcome.matches.iter().map(|p| p.as_str()).collect();
            assert_eq!(got.len(), 2);
            assert!(
                got.contains(&"Users/alice/NTUSER.DAT") && got.contains(&"Users/bob/NTUSER.DAT")
            );
        }

        #[test]
        fn bounded_globstar_and_class_work_through_the_walk() {
            let fs = fs();
            assert_eq!(fs.glob("Users/**3/x.log.[0-9]").unwrap().len(), 1);
            assert!(fs.glob("Users/**2/x.log.[0-9]").unwrap().is_empty());
        }

        #[test]
        fn an_unreadable_directory_is_reported_not_dropped() {
            let fs = FailingDir {
                inner: fs(),
                broken: "Users/bob",
            };
            let outcome = fs.glob_report("Users/*/NTUSER.DAT").unwrap();
            let got: Vec<&str> = outcome.matches.iter().map(|p| p.as_str()).collect();
            assert_eq!(got, vec!["Users/alice/NTUSER.DAT"]);
            assert_eq!(outcome.errors.len(), 1);
        }
    }
}
