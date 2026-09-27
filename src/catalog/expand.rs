//! [`expand`]: an [`ArtifactDefinition`] made concrete for one host.
//!
//! File paths come out drive-less and rooted at the evidence root, with `\`
//! on Windows (`\Windows\Prefetch\*.pf`) and `/` elsewhere. Registry keys
//! come out as key-path patterns for
//! [`RegistryExt::expand_key_pattern`](crate::traits::registry::RegistryExt::expand_key_pattern).
//!
//! `%%placeholders%%` take their values from the [`HostProfile`]. A fact the
//! profile lacks is never given a default value (such as `C:\Windows`).
//! It becomes a search pattern instead, following the definition format's
//! decomposition rules where it has one (`%%users.userprofile%%` becomes
//! `\Users\*` and `\Documents and Settings\*`) and a one-level `\*`
//! otherwise, and a note in [`Expansion::notes`] records it.

use std::collections::BTreeSet;

use super::{ArtifactCatalog, ArtifactDefinition, ArtifactSource, Os, Separator};
use crate::core::path::{FPath, FPathBuf};
use crate::field::Text;
use crate::host_profile::HostProfile;
use crate::provenance::Tracked;

/// The depth a bare `**` gets: the definition format means "up to 10
/// levels" by it, while a bare `**` in [`crate::core::fs::glob`] is
/// unbounded.
pub const GLOBSTAR_DEFAULT_DEPTH: u32 = 10;

/// Pattern matching a user SID under `HKEY_USERS` when no users are known.
/// SIDs end in a digit, so this leaves out the `<SID>_Classes` roots.
const ANY_SID: &str = "S-*[0-9]";

/// A file or directory glob.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExpandedGlob {
    pub pattern: String,
    /// The user it was expanded for, when it came from a `%%users.*%%`
    /// placeholder and the user is known.
    pub sid: Option<String>,
    /// The definition the source belongs to (a group member, for a group).
    pub artifact: Text,
    /// From a `PATH` source, which names directories.
    pub directory: bool,
}

/// A registry key-path pattern.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExpandedKey {
    pub pattern: String,
    pub sid: Option<String>,
    pub artifact: Text,
}

/// A registry value under a key-path pattern.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExpandedValue {
    pub key: String,
    pub value: String,
    pub sid: Option<String>,
    pub artifact: Text,
}

/// A source that can't be turned into a pattern: a live-only source (WMI,
/// command), an unknown placeholder, or an unknown group member.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnresolvedSource {
    pub artifact: Text,
    /// The path, key, query or name as written in the definition.
    pub source: String,
    pub reason: String,
}

/// The result of [`expand`]. Every list is sorted and has no duplicates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Expansion {
    pub globs: Vec<ExpandedGlob>,
    pub keys: Vec<ExpandedKey>,
    pub values: Vec<ExpandedValue>,
    pub unresolved: Vec<UnresolvedSource>,
    /// Which fallbacks were used, which users were skipped, and which
    /// definitions were left out, in words.
    pub notes: Vec<String>,
}

impl Expansion {
    pub fn is_empty(&self) -> bool {
        self.globs.is_empty() && self.keys.is_empty() && self.values.is_empty()
    }
}

/// Expands `def` for a host running `os`. Group members are looked up in
/// `catalog` and expanded recursively; a group cycle or a definition that
/// doesn't support `os` is left out with a note.
pub fn expand(
    def: &ArtifactDefinition,
    catalog: &dyn ArtifactCatalog,
    host: &HostProfile,
    os: Os,
) -> Expansion {
    let mut state = State {
        catalog,
        host,
        os,
        globs: BTreeSet::new(),
        keys: BTreeSet::new(),
        values: BTreeSet::new(),
        unresolved: BTreeSet::new(),
        notes: BTreeSet::new(),
        stack: Vec::new(),
        done: BTreeSet::new(),
    };
    state.definition(def);
    Expansion {
        globs: state.globs.into_iter().collect(),
        keys: state.keys.into_iter().collect(),
        values: state.values.into_iter().collect(),
        unresolved: state.unresolved.into_iter().collect(),
        notes: state.notes.into_iter().collect(),
    }
}

struct State<'a> {
    catalog: &'a dyn ArtifactCatalog,
    host: &'a HostProfile,
    os: Os,
    globs: BTreeSet<ExpandedGlob>,
    keys: BTreeSet<ExpandedKey>,
    values: BTreeSet<ExpandedValue>,
    unresolved: BTreeSet<UnresolvedSource>,
    notes: BTreeSet<String>,
    stack: Vec<Text>,
    done: BTreeSet<Text>,
}

/// How a pattern is written once expanded.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Style {
    WindowsPath,
    PosixPath,
    RegistryKey,
}

/// The user a pattern is expanded for. All `%%users.*%%` placeholders in
/// one pattern take their values from the same binding, so one user's
/// paths never mix with another's.
struct UserBinding {
    sid: Option<String>,
    /// Drive-less; `None` when unknown.
    profile: Option<String>,
    name: Option<String>,
}

impl State<'_> {
    fn definition(&mut self, def: &ArtifactDefinition) {
        if !def.supports(self.os) {
            self.notes
                .insert(format!("{}: not defined for {}", def.name, self.os));
            return;
        }
        if self.stack.contains(&def.name) {
            let cycle: Vec<&str> = self.stack.iter().map(|n| n.as_ref()).collect();
            self.notes.insert(format!(
                "{}: group cycle through {}, not followed",
                def.name,
                cycle.join(" -> ")
            ));
            return;
        }
        if !self.done.insert(def.name.clone()) {
            return;
        }
        self.stack.push(def.name.clone());
        let os = self.os;
        for entry in def.sources.iter().filter(|e| e.supports(os)) {
            self.source(def, &entry.source);
        }
        self.stack.pop();
    }

    fn source(&mut self, def: &ArtifactDefinition, source: &ArtifactSource) {
        let path_style = if self.os == Os::Windows {
            Style::WindowsPath
        } else {
            Style::PosixPath
        };
        match source {
            ArtifactSource::File { paths, separator }
            | ArtifactSource::Path { paths, separator } => {
                let directory = matches!(source, ArtifactSource::Path { .. });
                for path in paths.iter() {
                    for (pattern, sid) in self.pattern(def, path, *separator, path_style) {
                        self.globs.insert(ExpandedGlob {
                            pattern,
                            sid,
                            artifact: def.name.clone(),
                            directory,
                        });
                    }
                }
            }
            ArtifactSource::RegistryKey { keys } => {
                for key in keys.iter() {
                    for (pattern, sid) in
                        self.pattern(def, key, Separator::Backslash, Style::RegistryKey)
                    {
                        self.keys.insert(ExpandedKey {
                            pattern,
                            sid,
                            artifact: def.name.clone(),
                        });
                    }
                }
            }
            ArtifactSource::RegistryValue { pairs } => {
                for pair in pairs.iter() {
                    for (key, sid) in
                        self.pattern(def, &pair.key, Separator::Backslash, Style::RegistryKey)
                    {
                        self.values.insert(ExpandedValue {
                            key,
                            value: pair.value.to_string(),
                            sid,
                            artifact: def.name.clone(),
                        });
                    }
                }
            }
            ArtifactSource::Wmi { query, .. } => {
                self.unresolved(def, query, "WMI query: live host only")
            }
            ArtifactSource::Command { cmd, args } => {
                let line = std::iter::once(cmd.as_ref())
                    .chain(args.iter().map(|a| a.as_ref()))
                    .collect::<Vec<_>>()
                    .join(" ");
                self.unresolved(def, &line, "command: live host only");
            }
            ArtifactSource::Group { names } => {
                for name in names.iter() {
                    let catalog = self.catalog;
                    match catalog.get(name) {
                        Some(member) => self.definition(member),
                        None => self.unresolved(def, name, "group member not in the catalog"),
                    }
                }
            }
        }
    }

    fn unresolved(&mut self, def: &ArtifactDefinition, source: &str, reason: &str) {
        self.unresolved.insert(UnresolvedSource {
            artifact: def.name.clone(),
            source: source.to_string(),
            reason: reason.to_string(),
        });
    }

    /// Expands one path or key as written in `def`. An unresolvable
    /// placeholder makes the whole pattern unresolved.
    fn pattern(
        &mut self,
        def: &ArtifactDefinition,
        raw: &str,
        separator: Separator,
        style: Style,
    ) -> Vec<(String, Option<String>)> {
        let out_sep = if style == Style::PosixPath { '/' } else { '\\' };
        let normalized: String = raw
            .split(separator.as_char())
            .collect::<Vec<_>>()
            .join(&out_sep.to_string());
        let tokens = placeholders(&normalized);
        let bindings = self.bindings(def, &tokens, style);
        let mut out = Vec::new();
        for binding in &bindings {
            let mut resolve = |name: &str| self.placeholder(name, binding, style);
            match substitute(&normalized, &mut resolve) {
                Ok(values) => out.extend(
                    values
                        .into_iter()
                        .map(|v| (finish(&v, style), binding.sid.clone())),
                ),
                Err(reason) => {
                    self.unresolved(def, raw, &reason);
                    return Vec::new();
                }
            }
        }
        out
    }

    /// The users `tokens` get expanded for: every known user that has the
    /// facts the tokens need, or one anonymous binding that falls back to
    /// search patterns.
    fn bindings(
        &mut self,
        def: &ArtifactDefinition,
        tokens: &[String],
        style: Style,
    ) -> Vec<UserBinding> {
        let anonymous = || {
            vec![UserBinding {
                sid: None,
                profile: None,
                name: None,
            }]
        };
        let user_tokens: Vec<&str> = tokens
            .iter()
            .filter_map(|t| t.strip_prefix("users."))
            .collect();
        if user_tokens.is_empty() || style == Style::PosixPath {
            return anonymous();
        }
        let needs_profile = user_tokens.iter().any(|t| *t != "sid" && *t != "username");
        let needs_name = user_tokens.contains(&"username");
        let users = self.host.users.as_ref().map(Tracked::value);
        let mut bindings = Vec::new();
        for user in users.into_iter().flatten() {
            let profile = (!user.profile_path.as_str().is_empty())
                .then(|| drive_less(user.profile_path.as_path()));
            let missing = if needs_profile && profile.is_none() {
                Some("profile path")
            } else if needs_name && user.name.is_none() {
                Some("user name")
            } else {
                None
            };
            if let Some(fact) = missing {
                self.notes.insert(format!(
                    "{}: user {} left out, no {fact} known",
                    def.name, user.sid
                ));
                continue;
            }
            bindings.push(UserBinding {
                sid: Some(user.sid.clone()),
                profile,
                name: user.name.clone(),
            });
        }
        if bindings.is_empty() {
            anonymous()
        } else {
            bindings
        }
    }

    /// Records that `var` fell back to search `patterns`, and returns them.
    fn fallback(&mut self, var: &str, patterns: &[&str], why: &str) -> Vec<String> {
        self.notes.insert(format!(
            "%%{var}%%: {why}, searched as {}",
            patterns.join(" and ")
        ));
        patterns.iter().map(|p| p.to_string()).collect()
    }

    /// The user's profile folder, or the decomposition rule's patterns.
    fn profiles(&mut self, user: &UserBinding) -> Vec<String> {
        match &user.profile {
            Some(p) => vec![p.clone()],
            None => self.fallback(
                "users.userprofile",
                &["\\Users\\*", "\\Documents and Settings\\*"],
                "no user profiles known",
            ),
        }
    }

    /// The values of one placeholder, or why it has none.
    fn placeholder(
        &mut self,
        name: &str,
        user: &UserBinding,
        style: Style,
    ) -> Result<Vec<String>, String> {
        let host = self.host;
        let fact =
            |f: &Option<Tracked<FPathBuf>>| f.as_ref().map(|t| drive_less(t.value().as_path()));
        let under = |bases: Vec<String>, subs: &[&str]| -> Vec<String> {
            bases
                .iter()
                .flat_map(|b| subs.iter().map(move |s| format!("{b}{s}")))
                .collect()
        };
        if style == Style::PosixPath {
            let why = "home directories follow the decomposition rule";
            return match (name, self.os) {
                ("users.homedir", Os::Linux | Os::Esxi) => {
                    Ok(self.fallback(name, &["/home/*", "/root"], why))
                }
                ("users.homedir", Os::Darwin) => Ok(self.fallback(name, &["/Users/*"], why)),
                _ => Err(format!("%%{name}%% has no expansion on {}", self.os)),
            };
        }
        let values = match name {
            "environ_systemroot" | "environ_windir" => match fact(&host.system_root) {
                Some(root) => vec![root],
                None => self.fallback(name, &["\\*"], "system root unknown"),
            },
            "environ_systemdrive" => vec![String::new()],
            "environ_programfiles" => match fact(&host.program_files) {
                Some(p) => vec![p],
                None => self.fallback(name, &["\\*"], "program files folder unknown"),
            },
            "environ_programfilesx86" => match fact(&host.program_files_x86) {
                Some(p) => vec![p],
                None => self.fallback(name, &["\\*"], "x86 program files folder unknown"),
            },
            "environ_programdata" | "environ_allusersappdata" => {
                match (fact(&host.program_data), fact(&host.all_users_profile)) {
                    (Some(p), _) => vec![p],
                    (None, Some(all_users)) => vec![format!("{all_users}\\Application Data")],
                    (None, None) => self.fallback(name, &["\\*"], "program data folder unknown"),
                }
            }
            "environ_allusersprofile" => match fact(&host.all_users_profile) {
                Some(p) => vec![p],
                None => self.fallback(name, &["\\*"], "all users profile unknown"),
            },
            "users.sid" => match &user.sid {
                Some(sid) => vec![sid.clone()],
                None => self.fallback(name, &[ANY_SID], "no users known"),
            },
            "users.username" => match &user.name {
                Some(n) => vec![n.clone()],
                None => self.fallback(name, &["*"], "no user names known"),
            },
            "users.userprofile" | "users.homedir" => self.profiles(user),
            "users.appdata" => under(
                self.profiles(user),
                &["\\AppData\\Roaming", "\\Application Data"],
            ),
            "users.localappdata" => under(
                self.profiles(user),
                &["\\AppData\\Local", "\\Local Settings\\Application Data"],
            ),
            "users.localappdata_low" => under(self.profiles(user), &["\\AppData\\LocalLow"]),
            "users.temp" => under(
                self.profiles(user),
                &[
                    "\\AppData\\Local\\Temp",
                    "\\Local Settings\\Application Data\\Temp",
                ],
            ),
            _ => return Err(format!("unknown placeholder %%{name}%%")),
        };
        Ok(values)
    }
}

/// The `%%name%%` placeholders in `s`, in order.
fn placeholders(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(start) = rest.find("%%") {
        let after = &rest[start + 2..];
        let Some(len) = after.find("%%") else { break };
        out.push(after[..len].to_string());
        rest = &after[len + 2..];
    }
    out
}

/// Replaces every placeholder in `s` with each of its values, giving the
/// cartesian product.
fn substitute(
    s: &str,
    resolve: &mut dyn FnMut(&str) -> Result<Vec<String>, String>,
) -> Result<Vec<String>, String> {
    let Some(start) = s.find("%%") else {
        return Ok(vec![s.to_string()]);
    };
    let after = &s[start + 2..];
    let Some(len) = after.find("%%") else {
        return Ok(vec![s.to_string()]);
    };
    let values = resolve(&after[..len])?;
    let tails = substitute(&after[len + 2..], resolve)?;
    let head = &s[..start];
    Ok(values
        .iter()
        .flat_map(|v| tails.iter().map(move |t| format!("{head}{v}{t}")))
        .collect())
}

/// Drive-less, `\`-separated, rooted form of a Windows path fact:
/// `C:\Windows` becomes `\Windows`, and a bare drive becomes "".
fn drive_less(path: &FPath) -> String {
    let s = path.as_str();
    let s = &s[path.drive().map_or(0, str::len)..];
    let parts: Vec<&str> = s.split(['/', '\\']).filter(|c| !c.is_empty()).collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!("\\{}", parts.join("\\"))
    }
}

/// Final form: no empty components, a bounded `**`, and for paths a
/// leading separator and no drive.
fn finish(pattern: &str, style: Style) -> String {
    let sep = if style == Style::PosixPath { '/' } else { '\\' };
    let bounded = format!("**{GLOBSTAR_DEFAULT_DEPTH}");
    let mut parts: Vec<&str> = pattern.split(sep).filter(|c| !c.is_empty()).collect();
    if style == Style::WindowsPath {
        if let Some(first) = parts.first() {
            if first.len() == 2 && first.ends_with(':') {
                parts.remove(0);
            }
        }
    }
    let parts: Vec<&str> = parts
        .into_iter()
        .map(|c| if c == "**" { bounded.as_str() } else { c })
        .collect();
    let joined = parts.join(&sep.to_string());
    match style {
        Style::RegistryKey => joined,
        _ => format!("{sep}{joined}"),
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::catalog::{RegistryValueRef, SliceCatalog, SourceEntry};
    use crate::provenance::{Acquisition, ProvenanceStore, Recovery, SourceKey};
    use crate::traits::registry::windows::UserProfile;

    const ALICE: &str = "S-1-5-21-1-2-3-1001";
    const BOB: &str = "S-1-5-21-1-2-3-1002";

    fn text(s: &str) -> Text {
        Cow::Owned(s.to_string())
    }

    fn texts(items: &[&str]) -> Cow<'static, [Text]> {
        Cow::Owned(items.iter().map(|s| text(s)).collect())
    }

    fn entry(source: ArtifactSource, os: &[Os]) -> SourceEntry {
        SourceEntry {
            source,
            supported_os: Cow::Owned(os.to_vec()),
        }
    }

    fn def(name: &str, os: &[Os], sources: Vec<SourceEntry>) -> ArtifactDefinition {
        ArtifactDefinition {
            name: text(name),
            aliases: Cow::Borrowed(&[]),
            doc: Cow::Borrowed(""),
            sources: Cow::Owned(sources),
            supported_os: Cow::Owned(os.to_vec()),
            urls: Cow::Borrowed(&[]),
        }
    }

    fn windows_files(name: &str, paths: &[&str]) -> ArtifactDefinition {
        def(
            name,
            &[Os::Windows],
            vec![entry(
                ArtifactSource::File {
                    paths: texts(paths),
                    separator: Separator::Backslash,
                },
                &[],
            )],
        )
    }

    fn group(name: &str, members: &[&str]) -> ArtifactDefinition {
        def(
            name,
            &[],
            vec![entry(
                ArtifactSource::Group {
                    names: texts(members),
                },
                &[],
            )],
        )
    }

    /// A profile with the given system root and users (`(sid, profile path)`).
    fn host(system_root: Option<&str>, users: &[(&str, &str)]) -> HostProfile {
        let store = ProvenanceStore::new();
        let source = store.register_source(SourceKey::Synthetic("test".to_string()));
        let mint = || source.mint(Acquisition::LiveApi, Recovery::Allocated);
        let users: Vec<UserProfile> = users
            .iter()
            .map(|(sid, path)| UserProfile {
                sid: sid.to_string(),
                profile_path: FPathBuf::from(*path),
                name: path
                    .rsplit('\\')
                    .next()
                    .filter(|n| !n.is_empty())
                    .map(str::to_string),
            })
            .collect();
        HostProfile {
            system_root: system_root.map(|r| Tracked::new(FPathBuf::from(r), mint())),
            users: (!users.is_empty()).then(|| Tracked::new(users, mint())),
            ..HostProfile::default()
        }
    }

    fn run(
        def: &ArtifactDefinition,
        others: Vec<ArtifactDefinition>,
        host: &HostProfile,
        os: Os,
    ) -> Expansion {
        let catalog = SliceCatalog::new(others).unwrap();
        expand(def, &catalog, host, os)
    }

    fn patterns(e: &Expansion) -> Vec<(&str, Option<&str>)> {
        e.globs
            .iter()
            .map(|g| (g.pattern.as_str(), g.sid.as_deref()))
            .collect()
    }

    #[test]
    fn a_known_system_root_loses_its_drive() {
        let d = windows_files("Prefetch", &["%%environ_systemroot%%\\Prefetch\\*.pf"]);
        let e = run(&d, vec![], &host(Some("C:\\Windows"), &[]), Os::Windows);
        assert_eq!(patterns(&e), vec![("\\Windows\\Prefetch\\*.pf", None)]);
        assert!(e.notes.is_empty(), "{:?}", e.notes);
    }

    #[test]
    fn a_missing_system_root_becomes_a_one_level_search_with_a_note() {
        let d = windows_files("Prefetch", &["%%environ_systemroot%%\\Prefetch\\*.pf"]);
        let e = run(&d, vec![], &host(None, &[]), Os::Windows);
        assert_eq!(patterns(&e), vec![("\\*\\Prefetch\\*.pf", None)]);
        assert_eq!(e.notes.len(), 1);
        assert!(e.notes[0].contains("system root unknown"), "{:?}", e.notes);
    }

    #[test]
    fn multi_user_expansion_keeps_sids_apart() {
        let d = def(
            "UserHives",
            &[Os::Windows],
            vec![
                entry(
                    ArtifactSource::File {
                        paths: texts(&["%%users.userprofile%%\\NTUSER.DAT"]),
                        separator: Separator::Backslash,
                    },
                    &[],
                ),
                entry(
                    ArtifactSource::RegistryValue {
                        pairs: Cow::Owned(vec![RegistryValueRef {
                            key: text("HKEY_USERS\\%%users.sid%%\\Software\\X"),
                            value: text("Y"),
                        }]),
                    },
                    &[],
                ),
            ],
        );
        let h = host(
            Some("C:\\Windows"),
            &[(ALICE, "C:\\Users\\alice"), (BOB, "C:\\Users\\bob")],
        );
        let e = run(&d, vec![], &h, Os::Windows);
        assert_eq!(
            patterns(&e),
            vec![
                ("\\Users\\alice\\NTUSER.DAT", Some(ALICE)),
                ("\\Users\\bob\\NTUSER.DAT", Some(BOB)),
            ]
        );
        let values: Vec<(&str, Option<&str>)> = e
            .values
            .iter()
            .map(|v| (v.key.as_str(), v.sid.as_deref()))
            .collect();
        assert_eq!(
            values,
            vec![
                (&*format!("HKEY_USERS\\{ALICE}\\Software\\X"), Some(ALICE)),
                (&*format!("HKEY_USERS\\{BOB}\\Software\\X"), Some(BOB)),
            ]
        );
        assert!(e.values.iter().all(|v| v.value == "Y"));
    }

    #[test]
    fn unknown_users_follow_the_xp_and_vista_decomposition_rules() {
        let d = windows_files("Roaming", &["%%users.appdata%%\\App\\x.db"]);
        let e = run(&d, vec![], &host(None, &[]), Os::Windows);
        assert_eq!(
            patterns(&e),
            vec![
                (
                    "\\Documents and Settings\\*\\AppData\\Roaming\\App\\x.db",
                    None
                ),
                (
                    "\\Documents and Settings\\*\\Application Data\\App\\x.db",
                    None
                ),
                ("\\Users\\*\\AppData\\Roaming\\App\\x.db", None),
                ("\\Users\\*\\Application Data\\App\\x.db", None),
            ]
        );
        assert!(e.notes.iter().any(|n| n.contains("users.userprofile")));
    }

    #[test]
    fn unknown_sids_match_user_roots_but_not_classes_roots() {
        let d = def(
            "Run",
            &[Os::Windows],
            vec![entry(
                ArtifactSource::RegistryKey {
                    keys: texts(&["HKEY_USERS\\%%users.sid%%\\Software\\Run"]),
                },
                &[],
            )],
        );
        let e = run(&d, vec![], &host(None, &[]), Os::Windows);
        assert_eq!(e.keys.len(), 1);
        assert_eq!(e.keys[0].pattern, "HKEY_USERS\\S-*[0-9]\\Software\\Run");
        let pattern = "S-*[0-9]";
        let cs = crate::traits::vfs::CaseSensitivity::Insensitive;
        assert!(crate::core::fs::glob::segment_matches(pattern, ALICE, cs));
        assert!(!crate::core::fs::glob::segment_matches(
            pattern,
            &format!("{ALICE}_Classes"),
            cs
        ));
    }

    #[test]
    fn a_user_without_the_needed_fact_is_left_out_with_a_note() {
        let d = windows_files("Hive", &["%%users.userprofile%%\\NTUSER.DAT"]);
        let h = host(None, &[(ALICE, "C:\\Users\\alice"), (BOB, "")]);
        let e = run(&d, vec![], &h, Os::Windows);
        assert_eq!(
            patterns(&e),
            vec![("\\Users\\alice\\NTUSER.DAT", Some(ALICE))]
        );
        assert!(e
            .notes
            .iter()
            .any(|n| n.contains(BOB) && n.contains("profile path")));
    }

    #[test]
    fn groups_expand_recursively_and_a_cycle_is_a_note() {
        let a = group("A", &["B"]);
        let b = def(
            "B",
            &[Os::Windows],
            vec![
                entry(
                    ArtifactSource::File {
                        paths: texts(&["%%environ_systemdrive%%\\$MFT"]),
                        separator: Separator::Backslash,
                    },
                    &[],
                ),
                entry(
                    ArtifactSource::Group {
                        names: texts(&["A", "Missing"]),
                    },
                    &[],
                ),
            ],
        );
        let e = run(&a, vec![a.clone(), b], &host(None, &[]), Os::Windows);
        assert_eq!(patterns(&e), vec![("\\$MFT", None)]);
        assert_eq!(e.globs[0].artifact, "B");
        assert!(e.notes.iter().any(|n| n.contains("cycle")), "{:?}", e.notes);
        assert_eq!(e.unresolved.len(), 1);
        assert_eq!(e.unresolved[0].source, "Missing");
    }

    #[test]
    fn looks_up_group_members_by_alias() {
        let mut member = windows_files("New", &["\\x"]);
        member.aliases = texts(&["Old"]);
        let g = group("G", &["Old"]);
        let e = run(&g, vec![member], &host(None, &[]), Os::Windows);
        assert_eq!(patterns(&e), vec![("\\x", None)]);
    }

    #[test]
    fn filters_sources_and_definitions_by_os() {
        let d = def(
            "Mixed",
            &[Os::Windows, Os::Linux, Os::Darwin],
            vec![
                entry(
                    ArtifactSource::File {
                        paths: texts(&["%%environ_systemroot%%\\x"]),
                        separator: Separator::Backslash,
                    },
                    &[Os::Windows],
                ),
                entry(
                    ArtifactSource::File {
                        paths: texts(&["%%users.homedir%%/.bash_history"]),
                        separator: Separator::Slash,
                    },
                    &[Os::Linux, Os::Darwin],
                ),
            ],
        );
        let linux = run(&d, vec![], &host(Some("C:\\Windows"), &[]), Os::Linux);
        assert_eq!(
            patterns(&linux),
            vec![
                ("/home/*/.bash_history", None),
                ("/root/.bash_history", None)
            ]
        );
        let darwin = run(&d, vec![], &host(None, &[]), Os::Darwin);
        assert_eq!(patterns(&darwin), vec![("/Users/*/.bash_history", None)]);

        let windows_only = windows_files("W", &["\\x"]);
        let e = run(&windows_only, vec![], &host(None, &[]), Os::Linux);
        assert!(e.is_empty());
        assert!(e.notes.iter().any(|n| n.contains("not defined for Linux")));
    }

    #[test]
    fn globstars_are_bounded_and_drives_stripped() {
        let d = windows_files("Deep", &["C:\\Data\\**\\*.log", "\\Logs\\**3\\x"]);
        let e = run(&d, vec![], &host(None, &[]), Os::Windows);
        assert_eq!(
            patterns(&e),
            vec![("\\Data\\**10\\*.log", None), ("\\Logs\\**3\\x", None)]
        );
    }

    #[test]
    fn live_only_sources_and_unknown_placeholders_are_unresolved() {
        let d = def(
            "Live",
            &[Os::Windows],
            vec![
                entry(
                    ArtifactSource::Wmi {
                        query: text("SELECT * FROM Win32_Process"),
                        base_object: None,
                    },
                    &[],
                ),
                entry(
                    ArtifactSource::Command {
                        cmd: text("ipconfig"),
                        args: texts(&["/all"]),
                    },
                    &[],
                ),
                entry(
                    ArtifactSource::File {
                        paths: texts(&["%%environ_bogus%%\\x", "\\ok"]),
                        separator: Separator::Backslash,
                    },
                    &[],
                ),
            ],
        );
        let e = run(&d, vec![], &host(None, &[]), Os::Windows);
        assert_eq!(patterns(&e), vec![("\\ok", None)]);
        let sources: Vec<&str> = e.unresolved.iter().map(|u| u.source.as_str()).collect();
        assert_eq!(
            sources,
            vec![
                "%%environ_bogus%%\\x",
                "SELECT * FROM Win32_Process",
                "ipconfig /all"
            ]
        );
    }

    #[test]
    fn program_data_falls_back_to_all_users_application_data() {
        let store = ProvenanceStore::new();
        let source = store.register_source(SourceKey::Synthetic("t".to_string()));
        let h = HostProfile {
            all_users_profile: Some(Tracked::new(
                FPathBuf::from("C:\\Documents and Settings\\All Users"),
                source.mint(Acquisition::LiveApi, Recovery::Allocated),
            )),
            ..HostProfile::default()
        };
        let d = windows_files("PD", &["%%environ_programdata%%\\Vendor\\x"]);
        let e = run(&d, vec![], &h, Os::Windows);
        assert_eq!(
            patterns(&e),
            vec![(
                "\\Documents and Settings\\All Users\\Application Data\\Vendor\\x",
                None
            )]
        );
    }
}
