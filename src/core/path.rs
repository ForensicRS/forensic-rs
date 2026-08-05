//! Forensic path types.
//!
//! [`FPath`]/[`FPathBuf`] mirror [`std::path::Path`]/[`std::path::PathBuf`],
//! but carry **evidence** semantics instead of **host** semantics:
//!
//! - Both `/` and `\` are accepted as separators, regardless of the host OS —
//!   analyzing a Windows image from a Linux workstation (or vice versa) is
//!   the normal case for this crate, not the edge case.
//! - A leading drive designator (`C:`) is a first-class [`Component`], never
//!   folded into a `Normal` segment.
//! - Case is preserved verbatim in storage. [`FPath`]'s own `Eq`/`Hash`/`Ord`
//!   are case-sensitive (component-wise, separator-insensitive); a
//!   case-insensitive comparison is done with [`path_eq`], driven by
//!   whichever [`crate::traits::vfs::FileSystem`] owns the path — case rules
//!   are a property of the filesystem being analyzed, not of the path text.
//!
//! `UNC` paths (`\\server\share\...`) parse without error but their leading
//! `\\server\share` segment is folded into two plain [`Component::Normal`]
//! segments in this version — round-tripping through [`FPath::to_string`]
//! preserves the text, but `\\server` is not yet a distinct addressable
//! component. Likewise, a drive-relative path with no separator after the
//! drive (`C:Windows`, a legacy DOS oddity) parses identically to the
//! absolute form (`C:\Windows`) and is reported as absolute — real Windows
//! evidence overwhelmingly uses the unambiguous absolute form.
//!
//! [`FPath::to_std_path`] exists **only** for bridging into
//! [`std::fs`]-backed backends (e.g. `StdFileSystem`) and must not be called
//! anywhere else in the framework.

use std::borrow::Borrow;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

fn is_sep(c: char) -> bool {
    c == '/' || c == '\\'
}

/// Returns the byte length of a drive designator (`X:`) at the start of `s`,
/// if present. Always `2` when present, since both the letter and the colon
/// are single-byte ASCII.
fn drive_len(s: &str) -> Option<usize> {
    let mut chars = s.chars();
    let c0 = chars.next()?;
    let c1 = chars.next()?;
    if c0.is_ascii_alphabetic() && c1 == ':' {
        Some(2)
    } else {
        None
    }
}

/// A single component of an [`FPath`], yielded by [`FPath::components`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component<'a> {
    /// A root separator with no preceding drive designator, e.g. the leading
    /// `/` in `/etc/passwd`.
    RootDir,
    /// A drive designator, e.g. `"C:"` in `C:\Windows`. Always includes the
    /// colon, never a trailing separator.
    Drive(&'a str),
    /// A normal named segment, e.g. `"Windows"`.
    Normal(&'a str),
    /// `".."`
    ParentDir,
    /// `"."`
    CurDir,
}

impl<'a> Component<'a> {
    /// The textual form of this component, as it would appear in a path.
    pub fn as_str(&self) -> &'a str {
        match self {
            Component::RootDir => "/",
            Component::Drive(d) => d,
            Component::Normal(s) => s,
            Component::ParentDir => "..",
            Component::CurDir => ".",
        }
    }
}

fn parse_components(s: &str) -> Vec<Component<'_>> {
    let mut out = Vec::new();
    let mut rest = s;
    if let Some(len) = drive_len(rest) {
        out.push(Component::Drive(&rest[..len]));
        rest = rest[len..].trim_start_matches(is_sep);
    } else if rest.starts_with(is_sep) {
        out.push(Component::RootDir);
        rest = rest.trim_start_matches(is_sep);
    }
    for seg in rest.split(is_sep) {
        if seg.is_empty() {
            continue;
        }
        match seg {
            "." => out.push(Component::CurDir),
            ".." => out.push(Component::ParentDir),
            _ => out.push(Component::Normal(seg)),
        }
    }
    out
}

/// Iterator over the [`Component`]s of an [`FPath`], returned by
/// [`FPath::components`].
pub struct Components<'a> {
    inner: std::vec::IntoIter<Component<'a>>,
}

impl<'a> Iterator for Components<'a> {
    type Item = Component<'a>;
    fn next(&mut self) -> Option<Component<'a>> {
        self.inner.next()
    }
}

/// Borrowed forensic path. See the [module docs](self) for the semantics
/// that distinguish this from [`std::path::Path`].
#[derive(Debug)]
#[repr(transparent)]
pub struct FPath(str);

impl FPath {
    /// Borrows `s` as an `FPath`. Never allocates or normalizes; storage is
    /// exactly the bytes passed in. Use [`FPathBuf::from`] to obtain an
    /// owned, separator-normalized path from an arbitrary string.
    pub fn new<S: AsRef<str> + ?Sized>(s: &S) -> &FPath {
        unsafe { &*(s.as_ref() as *const str as *const FPath) }
    }

    /// The raw, unnormalized backing string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Iterates the path's components, treating `/` and `\` uniformly as
    /// separators regardless of what this instance's storage contains.
    pub fn components(&self) -> Components<'_> {
        Components {
            inner: parse_components(&self.0).into_iter(),
        }
    }

    /// `true` if the path starts with a root separator or a drive
    /// designator.
    pub fn is_absolute(&self) -> bool {
        matches!(
            self.components().next(),
            Some(Component::RootDir) | Some(Component::Drive(_))
        )
    }

    /// The leading drive designator (e.g. `"C:"`), if present.
    pub fn drive(&self) -> Option<&str> {
        match self.components().next() {
            Some(Component::Drive(d)) => Some(d),
            _ => None,
        }
    }

    /// The final component of the path, if it has a normal name (not a bare
    /// drive, root, `.`, or `..`).
    pub fn file_name(&self) -> Option<&str> {
        let s = self.0.trim_end_matches(is_sep);
        if s.is_empty() {
            return None;
        }
        let dlen = drive_len(s).unwrap_or(0);
        let body = &s[dlen..];
        if body.is_empty() {
            return None; // bare drive, e.g. "C:" or "C:/"
        }
        let name = match body.rfind(is_sep) {
            Some(pos) => &body[pos + 1..],
            None => body,
        };
        if name.is_empty() || name == "." || name == ".." {
            None
        } else {
            Some(name)
        }
    }

    /// The file extension of [`Self::file_name`], without the leading dot.
    /// A leading-dot-only name (e.g. `".bashrc"`) has no extension.
    pub fn extension(&self) -> Option<&str> {
        let name = self.file_name()?;
        let dot = name.rfind('.')?;
        if dot == 0 {
            return None;
        }
        Some(&name[dot + 1..])
    }

    /// The path with its final component removed, or `None` if this path
    /// has no parent (root, a bare drive, or empty).
    pub fn parent(&self) -> Option<&FPath> {
        let s = self.0.trim_end_matches(is_sep);
        if s.is_empty() {
            return None;
        }
        let dlen = drive_len(s).unwrap_or(0);
        let body = &s[dlen..];
        if body.is_empty() {
            return None; // bare drive
        }
        match body.rfind(is_sep) {
            Some(0) => Some(FPath::new(&s[..dlen + 1])), // parent is drive-root or filesystem root
            Some(pos) => Some(FPath::new(&s[..dlen + pos])),
            None => Some(FPath::new(&s[..dlen])), // single relative segment; parent is "" or "C:"
        }
    }

    /// Joins `other` onto this path, producing an owned, separator-normalized
    /// result. If `other` is absolute, it replaces this path entirely
    /// (mirrors [`std::path::Path::join`]).
    pub fn join(&self, other: impl AsRef<str>) -> FPathBuf {
        let mut buf = FPathBuf::from(self.as_str());
        buf.push(other.as_ref());
        buf
    }

    /// Component-wise, case-sensitive prefix check. `/` vs `\` differences
    /// don't affect the result; use [`path_eq`] for case-insensitive
    /// comparison.
    pub fn starts_with(&self, base: impl AsRef<FPath>) -> bool {
        let base = base.as_ref();
        let mut a = self.components();
        let mut b = base.components();
        loop {
            match (a.next(), b.next()) {
                (_, None) => return true,
                (Some(x), Some(y)) => {
                    if x != y {
                        return false;
                    }
                }
                (None, Some(_)) => return false,
            }
        }
    }

    /// Converts to a host [`std::path::PathBuf`] via the canonical,
    /// `/`-joined display form. Must be called **only** from
    /// [`std::fs`]-backed backends (e.g. `StdFileSystem`) — nothing else in
    /// the framework should touch host path semantics.
    pub fn to_std_path(&self) -> std::path::PathBuf {
        std::path::PathBuf::from(self.to_string())
    }
}

fn component_strs(p: &FPath) -> Vec<&str> {
    p.components().map(|c| c.as_str()).collect()
}

impl PartialEq for FPath {
    fn eq(&self, other: &Self) -> bool {
        component_strs(self) == component_strs(other)
    }
}
impl Eq for FPath {}

impl PartialOrd for FPath {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for FPath {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        component_strs(self).cmp(&component_strs(other))
    }
}
impl Hash for FPath {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for s in component_strs(self) {
            s.hash(state);
            state.write_u8(0xFF);
        }
    }
}

impl fmt::Display for FPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut need_sep = false;
        for c in self.components() {
            match c {
                Component::Drive(d) => {
                    write!(f, "{d}")?;
                    need_sep = true;
                }
                Component::RootDir => {
                    // Already the separator itself; don't let the next
                    // component add a second one.
                    write!(f, "/")?;
                    need_sep = false;
                }
                other => {
                    if need_sep {
                        write!(f, "/")?;
                    }
                    write!(f, "{}", other.as_str())?;
                    need_sep = true;
                }
            }
        }
        Ok(())
    }
}

impl ToOwned for FPath {
    type Owned = FPathBuf;
    fn to_owned(&self) -> FPathBuf {
        FPathBuf(self.0.to_string())
    }
}

impl AsRef<FPath> for FPath {
    fn as_ref(&self) -> &FPath {
        self
    }
}
impl AsRef<FPath> for str {
    fn as_ref(&self) -> &FPath {
        FPath::new(self)
    }
}
impl AsRef<FPath> for String {
    fn as_ref(&self) -> &FPath {
        FPath::new(self.as_str())
    }
}

/// Owned forensic path. See the [module docs](self) for semantics.
///
/// Unlike [`FPath`] (which stores whatever bytes it was given), constructing
/// an `FPathBuf` from a string ([`From<&str>`], [`From<String>`],
/// [`FPath::join`], [`FPathBuf::push`]) normalizes separators to `/` and
/// collapses repeated separators, so owned paths converge on the canonical
/// form even when built from mixed `/`/`\` input.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FPathBuf(String);

fn normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_sep = false;
    for ch in s.chars() {
        if is_sep(ch) {
            if !prev_sep {
                out.push('/');
                prev_sep = true;
            }
        } else {
            out.push(ch);
            prev_sep = false;
        }
    }
    if out.len() > 1 && out.ends_with('/') {
        let without = &out[..out.len() - 1];
        if !without.ends_with(':') {
            out.truncate(out.len() - 1);
        }
    }
    out
}

impl FPathBuf {
    /// An empty path.
    pub fn new() -> Self {
        FPathBuf(String::new())
    }

    /// Borrows this owned path as an [`FPath`].
    pub fn as_path(&self) -> &FPath {
        FPath::new(&self.0)
    }

    /// Appends `other`, normalizing separators. If `other` is absolute, it
    /// replaces the current content entirely (mirrors
    /// [`std::path::PathBuf::push`]).
    pub fn push(&mut self, other: impl AsRef<str>) {
        let other = other.as_ref();
        if FPath::new(other).is_absolute() {
            self.0 = normalize(other);
            return;
        }
        let normalized_other = normalize(other);
        if normalized_other.is_empty() {
            return;
        }
        if !self.0.is_empty() && !self.0.ends_with('/') {
            self.0.push('/');
        }
        self.0.push_str(&normalized_other);
    }

    /// Consumes this path, returning its normalized backing `String`.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl Deref for FPathBuf {
    type Target = FPath;
    fn deref(&self) -> &FPath {
        self.as_path()
    }
}
impl Borrow<FPath> for FPathBuf {
    fn borrow(&self) -> &FPath {
        self.as_path()
    }
}
impl AsRef<FPath> for FPathBuf {
    fn as_ref(&self) -> &FPath {
        self.as_path()
    }
}

impl From<&str> for FPathBuf {
    fn from(s: &str) -> Self {
        FPathBuf(normalize(s))
    }
}
impl From<String> for FPathBuf {
    fn from(s: String) -> Self {
        FPathBuf(normalize(&s))
    }
}
impl From<&FPath> for FPathBuf {
    fn from(p: &FPath) -> Self {
        p.to_owned()
    }
}

impl fmt::Display for FPathBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_path(), f)
    }
}

/// Case-insensitive-aware path comparison, component-wise and
/// separator-insensitive. `case_sensitive` should come from the owning
/// [`crate::traits::vfs::FileSystem`]'s declared case-folding policy — case
/// rules are a property of the filesystem, never of the path text itself.
pub fn path_eq(a: &FPath, b: &FPath, case_sensitive: bool) -> bool {
    let mut ca = a.components();
    let mut cb = b.components();
    loop {
        match (ca.next(), cb.next()) {
            (None, None) => return true,
            (Some(x), Some(y)) => {
                if !component_eq(x, y, case_sensitive) {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

fn component_eq(a: Component<'_>, b: Component<'_>, case_sensitive: bool) -> bool {
    match (a, b) {
        (Component::RootDir, Component::RootDir) => true,
        (Component::CurDir, Component::CurDir) => true,
        (Component::ParentDir, Component::ParentDir) => true,
        (Component::Drive(x), Component::Drive(y)) | (Component::Normal(x), Component::Normal(y)) => {
            if case_sensitive {
                x == y
            } else {
                x.eq_ignore_ascii_case(y)
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comps(s: &str) -> Vec<Component<'_>> {
        FPath::new(s).components().collect()
    }

    #[test]
    fn drive_and_segments_are_decomposed() {
        assert_eq!(
            comps("C:\\Windows\\System32"),
            vec![
                Component::Drive("C:"),
                Component::Normal("Windows"),
                Component::Normal("System32"),
            ]
        );
    }

    #[test]
    fn forward_and_back_slash_parse_identically() {
        assert_eq!(comps("C:/Windows/System32"), comps("C:\\Windows\\System32"));
    }

    #[test]
    fn fpath_eq_is_separator_insensitive() {
        assert_eq!(FPath::new("C:/Windows"), FPath::new("C:\\Windows"));
    }

    #[test]
    fn fpath_eq_is_case_sensitive() {
        assert_ne!(FPath::new("Report.TXT"), FPath::new("report.txt"));
    }

    #[test]
    fn path_eq_can_fold_case() {
        assert!(path_eq(FPath::new("Report.TXT"), FPath::new("report.txt"), false));
        assert!(!path_eq(FPath::new("Report.TXT"), FPath::new("report.txt"), true));
    }

    #[test]
    fn unix_root_is_root_dir_component() {
        assert_eq!(comps("/etc/passwd"), vec![Component::RootDir, Component::Normal("etc"), Component::Normal("passwd")]);
    }

    #[test]
    fn repeated_separators_collapse() {
        assert_eq!(comps("C:\\\\Windows"), vec![Component::Drive("C:"), Component::Normal("Windows")]);
    }

    #[test]
    fn dot_and_dotdot_are_distinct_components() {
        assert_eq!(
            comps("a/./b/../c"),
            vec![
                Component::Normal("a"),
                Component::CurDir,
                Component::Normal("b"),
                Component::ParentDir,
                Component::Normal("c"),
            ]
        );
    }

    #[test]
    fn is_absolute_true_for_drive_and_root() {
        assert!(FPath::new("C:\\Windows").is_absolute());
        assert!(FPath::new("/etc").is_absolute());
        assert!(!FPath::new("Windows").is_absolute());
        assert!(!FPath::new("relative/path").is_absolute());
    }

    #[test]
    fn drive_accessor() {
        assert_eq!(FPath::new("C:\\Windows").drive(), Some("C:"));
        assert_eq!(FPath::new("/etc").drive(), None);
        assert_eq!(FPath::new("relative").drive(), None);
    }

    #[test]
    fn file_name_basic() {
        assert_eq!(FPath::new("C:\\Windows\\System32\\ntdll.dll").file_name(), Some("ntdll.dll"));
        assert_eq!(FPath::new("/etc/passwd").file_name(), Some("passwd"));
        assert_eq!(FPath::new("report.txt").file_name(), Some("report.txt"));
    }

    #[test]
    fn file_name_none_on_bare_drive_and_root() {
        assert_eq!(FPath::new("C:").file_name(), None);
        assert_eq!(FPath::new("C:\\").file_name(), None);
        assert_eq!(FPath::new("/").file_name(), None);
        assert_eq!(FPath::new("").file_name(), None);
    }

    #[test]
    fn file_name_none_on_dot_and_dotdot() {
        assert_eq!(FPath::new(".").file_name(), None);
        assert_eq!(FPath::new("..").file_name(), None);
        assert_eq!(FPath::new("C:\\Windows\\..").file_name(), None);
    }

    #[test]
    fn file_name_ignores_trailing_separator() {
        assert_eq!(FPath::new("C:\\Windows\\System32\\").file_name(), Some("System32"));
    }

    #[test]
    fn extension_basic() {
        assert_eq!(FPath::new("ntdll.dll").extension(), Some("dll"));
        assert_eq!(FPath::new("archive.tar.gz").extension(), Some("gz"));
        assert_eq!(FPath::new("README").extension(), None);
    }

    #[test]
    fn extension_none_for_dotfile() {
        assert_eq!(FPath::new(".bashrc").extension(), None);
    }

    #[test]
    fn parent_basic() {
        assert_eq!(FPath::new("C:\\Windows\\System32").parent(), Some(FPath::new("C:\\Windows")));
        assert_eq!(FPath::new("/etc/passwd").parent(), Some(FPath::new("/etc")));
    }

    #[test]
    fn parent_of_top_level_under_drive_is_bare_drive() {
        assert_eq!(FPath::new("C:\\Windows").parent(), Some(FPath::new("C:")));
    }

    #[test]
    fn parent_of_top_level_under_root_is_root() {
        assert_eq!(FPath::new("/etc").parent(), Some(FPath::new("/")));
    }

    #[test]
    fn parent_none_for_bare_drive_root_and_empty() {
        assert_eq!(FPath::new("C:").parent(), None);
        assert_eq!(FPath::new("/").parent(), None);
        assert_eq!(FPath::new("").parent(), None);
    }

    #[test]
    fn parent_of_relative_single_segment_is_empty() {
        assert_eq!(FPath::new("report.txt").parent(), Some(FPath::new("")));
    }

    #[test]
    fn join_relative_onto_absolute() {
        assert_eq!(FPath::new("C:\\Users").join("Bob").as_path(), FPath::new("C:/Users/Bob"));
    }

    #[test]
    fn join_normalizes_separators() {
        let joined = FPath::new("C:\\Users").join("Bob\\NTUSER.DAT");
        assert_eq!(joined.as_str(), "C:/Users/Bob/NTUSER.DAT");
    }

    #[test]
    fn join_absolute_other_replaces() {
        let joined = FPath::new("C:\\Users\\Bob").join("D:\\Other");
        assert_eq!(joined.as_path(), FPath::new("D:\\Other"));
    }

    #[test]
    fn starts_with_is_component_wise_not_string_prefix() {
        assert!(!FPath::new("C:/Windows").starts_with(FPath::new("C:/Win")));
        assert!(FPath::new("C:/Windows/System32").starts_with(FPath::new("C:/Windows")));
        assert!(FPath::new("C:/Windows").starts_with(FPath::new("C:/Windows")));
    }

    #[test]
    fn starts_with_ignores_separator_style() {
        assert!(FPath::new("C:\\Windows\\System32").starts_with(FPath::new("C:/Windows")));
    }

    #[test]
    fn display_round_trips_to_canonical_form() {
        assert_eq!(FPath::new("C:\\Windows\\System32").to_string(), "C:/Windows/System32");
        assert_eq!(FPath::new("/etc//passwd").to_string(), "/etc/passwd");
    }

    #[test]
    fn fpathbuf_from_str_normalizes() {
        assert_eq!(FPathBuf::from("C:\\Windows\\\\System32").as_str(), "C:/Windows/System32");
    }

    #[test]
    fn fpathbuf_from_str_preserves_drive_root_slash() {
        assert_eq!(FPathBuf::from("C:\\").as_str(), "C:/");
        assert_eq!(FPathBuf::from("C:").as_str(), "C:");
    }

    #[test]
    fn fpathbuf_from_str_trims_trailing_separator() {
        assert_eq!(FPathBuf::from("C:\\Windows\\").as_str(), "C:/Windows");
    }

    #[test]
    fn fpathbuf_push_appends_relative() {
        let mut buf = FPathBuf::from("C:\\Users");
        buf.push("Bob");
        assert_eq!(buf.as_str(), "C:/Users/Bob");
    }

    #[test]
    fn fpathbuf_push_absolute_replaces() {
        let mut buf = FPathBuf::from("C:\\Users\\Bob");
        buf.push("/etc/passwd");
        assert_eq!(buf.as_str(), "/etc/passwd");
    }

    #[test]
    fn fpathbuf_deref_to_fpath() {
        let buf = FPathBuf::from("C:\\Windows");
        let p: &FPath = &buf;
        assert_eq!(p, FPath::new("C:/Windows"));
    }

    #[test]
    fn case_preserved_in_storage() {
        let buf = FPathBuf::from("C:\\Users\\BoB\\Report.TXT");
        assert_eq!(buf.as_str(), "C:/Users/BoB/Report.TXT");
        assert_eq!(buf.file_name(), Some("Report.TXT"));
    }

    #[test]
    fn unc_paths_parse_without_erroring() {
        // Known v1 limitation: the leading `\\` collapses to a single
        // RootDir marker and the server/share segment folds into two plain
        // Normal components rather than a distinct addressable component.
        let comps = comps("\\\\host\\share\\file.txt");
        assert_eq!(
            comps,
            vec![
                Component::RootDir,
                Component::Normal("host"),
                Component::Normal("share"),
                Component::Normal("file.txt"),
            ]
        );
    }

    #[test]
    fn unc_path_round_trips_through_display() {
        assert_eq!(FPath::new("\\\\host\\share\\file.txt").to_string(), "/host/share/file.txt");
    }

    #[test]
    fn ordering_is_component_wise() {
        assert!(FPath::new("C:/A") < FPath::new("C:/B"));
        assert!(FPath::new("C:/A") < FPath::new("C:/A/B"));
    }

    #[test]
    fn as_fpath_from_str_and_string() {
        let s: &str = "C:\\Windows";
        let owned: String = s.to_string();
        assert_eq!(AsRef::<FPath>::as_ref(s), FPath::new("C:/Windows"));
        assert_eq!(AsRef::<FPath>::as_ref(&owned), FPath::new("C:/Windows"));
    }

    #[test]
    fn to_std_path_uses_canonical_form() {
        let std_path = FPath::new("C:\\Windows\\System32").to_std_path();
        assert_eq!(std_path, std::path::PathBuf::from("C:/Windows/System32"));
    }
}
