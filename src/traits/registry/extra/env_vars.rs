use std::collections::BTreeMap;

use crate::core::UsersEnvVars;
use crate::err::{ForensicError, ForensicResult};
use crate::traits::registry::{windows, Registry, RegistryExt};

const CURRENT_VERSION: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion";

/// Extract the principal environment variables for all users which have a profile:
/// * USERPROFILE
/// * SystemRoot
/// * windir
/// * SystemDrive
/// * ProgramFiles
/// * ProgramData
/// * ProgramFiles(x86)
/// * ProgramW6432
/// * LOCALAPPDATA
/// * APPDATA
/// * TMP
/// * TEMP
/// * HOMEPATH
/// * HOMEDRIVE
/// * USERNAME
///
/// A value the registry doesn't provide is filled with the Windows default (`C:\Windows`,
/// `C:\Program Files`, ...), and the result doesn't say which values were read and which were
/// assumed; failures are only logged. Use [`get_env_vars_of_users_report`] when that matters,
/// e.g. before resolving evidence paths from these values.
pub fn get_env_vars_of_users(reg: &dyn Registry) -> ForensicResult<UsersEnvVars> {
    let report = get_env_vars_of_users_report(reg)?;
    for fallback in &report.fallbacks {
        crate::debug!(
            "get_env_vars_of_users: assumed {}={} ({})",
            fallback.var,
            fallback.assumed,
            fallback.reason
        );
    }
    for e in &report.errors {
        crate::warn!("get_env_vars_of_users: {}", e);
    }
    Ok(report.vars)
}

/// The result of [`get_env_vars_of_users_report`].
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct EnvVarsReport {
    /// Per-user variables, keyed by SID, exactly what [`get_env_vars_of_users`] returns.
    pub vars: UsersEnvVars,
    /// Every value in `vars` that was assumed rather than read.
    pub fallbacks: Vec<EnvFallback>,
    /// Keys or values that exist but could not be read. The users they affect are still in
    /// `vars`, with fallbacks where needed.
    pub errors: Vec<ForensicError>,
}

/// A variable [`get_env_vars_of_users_report`] filled with a default because the registry did not
/// provide it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EnvFallback {
    /// The user it was assumed for; `None` for a machine-wide variable, assumed for every user.
    pub sid: Option<String>,
    pub var: String,
    pub assumed: String,
    /// Why the registry value was not used.
    pub reason: String,
}

/// [`get_env_vars_of_users`], plus which values were assumed and which reads failed.
pub fn get_env_vars_of_users_report(reg: &dyn Registry) -> ForensicResult<EnvVarsReport> {
    let mut report = EnvVarsReport::default();
    let (system_root_path, root_was_read) = system_root(reg, &mut report);
    let system_drive = match system_root_path.get(..2) {
        Some(d) if root_was_read && is_drive(d) => d.to_string(),
        _ => {
            let reason = if root_was_read {
                format!("no drive letter in SystemRoot '{system_root_path}'")
            } else {
                "taken from the assumed SystemRoot".to_string()
            };
            report.assume(None, "SystemDrive", "C:".into(), reason)
        }
    };
    let program_files = program_files(reg, &mut report);
    let program_data = program_data(reg, &mut report);

    let profiles = list_all_profiles(reg, &mut report.errors);
    for (user_sid, user_home) in profiles {
        let mut user_map = BTreeMap::new();
        user_map.insert("USERPROFILE".into(), user_home.clone());
        user_map.insert("SystemRoot".into(), system_root_path.clone());
        user_map.insert("windir".into(), system_root_path.clone());
        user_map.insert("SystemDrive".into(), system_drive.clone());
        user_map.insert("ProgramFiles".into(), program_files.program_files.clone());
        user_map.insert("ProgramData".into(), program_data.clone());
        user_map.insert(
            "ProgramFiles(x86)".into(),
            program_files.program_files_86.clone(),
        );
        user_map.insert(
            "ProgramW6432".into(),
            program_files.program_files_w6432.clone(),
        );
        for (k, v) in user_specific_env_vars(reg, &user_sid, &user_home, &mut report) {
            user_map.insert(k, v);
        }
        report.vars.insert(user_sid, user_map);
    }
    Ok(report)
}

impl EnvVarsReport {
    /// Records that `var` was assumed to be `value`, and returns `value`.
    fn assume(&mut self, sid: Option<&str>, var: &str, value: String, reason: String) -> String {
        self.fallbacks.push(EnvFallback {
            sid: sid.map(str::to_string),
            var: var.to_string(),
            assumed: value.clone(),
            reason,
        });
        value
    }

    /// The string at `path\value`, or `default()` recorded as a fallback for `var`. A value
    /// that exists but can't be read is also kept in `errors`.
    fn read_or_assume(
        &mut self,
        reg: &dyn Registry,
        sid: Option<&str>,
        (path, value): (&str, &str),
        var: &str,
        default: impl FnOnce() -> String,
    ) -> String {
        let reason = match reg.value(path, value).and_then(String::try_from) {
            Ok(read) => return read,
            Err(e) if e.is_registry_not_found() => format!(r"{path}\{value} is absent"),
            Err(e) => {
                let reason = format!(r"{path}\{value} could not be read: {e}");
                self.errors.push(e);
                reason
            }
        };
        self.assume(sid, var, default(), reason)
    }
}

fn is_drive(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// Converts an [`crate::core::path::FPathBuf`]-normalized (`/`-separated)
/// path string back to the backslash form real Windows environment variable
/// values use. `windows::system_root`/`windows::users` route through
/// `FPathBuf`, which normalizes separators for internal path-manipulation
/// purposes; the values handed back here are meant to look like genuine
/// `%SystemRoot%`/`%USERPROFILE%` values (and downstream string-splitting in
/// [`user_specific_env_vars`] assumes backslashes), so it's converted back
/// at the boundary.
fn win_sep(s: String) -> String {
    s.replace('/', "\\")
}

// Ports the original's `list_all_profiles` (which walked ProfileList only) on
// top of `windows::users`, which correlates ProfileList *and* HKEY_USERS.
// Entries with an empty profile_path (HKU-only, no ProfileList match) are
// filtered out here to match the original's `if !profile_path.is_empty()`
// gate exactly.
fn list_all_profiles(
    reg: &dyn Registry,
    errors: &mut Vec<ForensicError>,
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let profiles = match windows::users_with_errors(reg) {
        Ok((profiles, user_errors)) => {
            errors.extend(user_errors);
            profiles
        }
        Err(e) => {
            errors.push(e);
            Vec::new()
        }
    };
    for profile in profiles {
        if profile.profile_path.as_str().is_empty() {
            continue;
        }
        let path = win_sep(profile.profile_path.to_string());
        if profile.sid == "S-1-5-18" {
            map.insert(String::new(), path.clone());
        }
        map.insert(profile.sid, path);
    }
    map
}

/// SystemRoot, and whether it was read (`false`: assumed).
fn system_root(reg: &dyn Registry, report: &mut EnvVarsReport) -> (String, bool) {
    let reason = match windows::system_root(reg) {
        Ok(p) => return (win_sep(p.to_string()), true),
        Err(e) if e.is_registry_not_found() => "SystemRoot is absent".to_string(),
        Err(e) => {
            let reason = format!("SystemRoot could not be read: {e}");
            report.errors.push(e);
            reason
        }
    };
    (report.assume(None, "SystemRoot", r"C:\Windows".into(), reason), false)
}

fn program_data(reg: &dyn Registry, report: &mut EnvVarsReport) -> String {
    report.read_or_assume(
        reg,
        None,
        (
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            "Common AppData",
        ),
        "ProgramData",
        || r"C:\ProgramData".into(),
    )
}

fn program_files(reg: &dyn Registry, report: &mut EnvVarsReport) -> ProgramFiles {
    let program_files = report.read_or_assume(
        reg,
        None,
        (CURRENT_VERSION, "ProgramFilesDir"),
        "ProgramFiles",
        || r"C:\Program Files".into(),
    );
    let program_files_86 = report.read_or_assume(
        reg,
        None,
        (CURRENT_VERSION, "ProgramFilesDir (x86)"),
        "ProgramFiles(x86)",
        || r"C:\Program Files (x86)".into(),
    );
    let program_files_w6432 = report.read_or_assume(
        reg,
        None,
        (CURRENT_VERSION, "ProgramW6432Dir"),
        "ProgramW6432",
        || r"C:\Program Files".into(),
    );
    ProgramFiles {
        program_files,
        program_files_86,
        program_files_w6432,
    }
}

fn user_specific_env_vars(
    reg: &dyn Registry,
    user: &str,
    user_profile: &str,
    report: &mut EnvVarsReport,
) -> Vec<(String, String)> {
    // Mirrors the original's two early-return gates exactly: if the user's
    // hive isn't loaded (`HKU\{sid}` absent) or it has no
    // `User Shell Folders` subkey, no per-user env vars are produced at all
    // (not even the pure-string-derived HOMEPATH/HOMEDRIVE/USERNAME). A key
    // that exists but can't be opened is kept as an error.
    let user_root_path = format!(r"HKU\{user}");
    let shell_folders_path =
        format!(r"{user_root_path}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders");
    for gate in [&user_root_path, &shell_folders_path] {
        if let Err(e) = reg.key(gate) {
            if !e.is_registry_not_found() {
                report.errors.push(e);
            }
            return Vec::new();
        }
    }

    let sid = Some(user);
    let mut to_ret = Vec::with_capacity(12);
    let app_data = report.read_or_assume(reg, sid, (&shell_folders_path, "AppData"), "APPDATA", || {
        format!("{}\\AppData\\Roaming", user_profile)
    });
    let local_app_data =
        report.read_or_assume(reg, sid, (&shell_folders_path, "Local AppData"), "LOCALAPPDATA", || {
            format!("{}\\AppData\\Local", user_profile)
        });
    to_ret.push((
        "LOCALAPPDATA".into(),
        replace_user_profile(local_app_data, user_profile),
    ));
    to_ret.push((
        "APPDATA".into(),
        replace_user_profile(app_data, user_profile),
    ));

    let env_path = format!(r"HKU\{user}\Environment");
    for var in ["TMP", "TEMP"] {
        let value = report.read_or_assume(reg, sid, (&env_path, var), var, || {
            format!("{}\\AppData\\Local\\Temp", user_profile)
        });
        to_ret.push((var.into(), replace_user_profile(value, user_profile)));
    }

    // Byte-indexed on evidence text, so only split at a char boundary: a profile path that
    // doesn't start with an ASCII drive letter must not panic.
    match (user_profile.get(0..2), user_profile.get(2..)) {
        (Some(home_drive), Some(home_path)) if user_profile.len() > 3 && is_drive(home_drive) => {
            let username = user_profile.rsplit('\\').next().unwrap_or_default();
            to_ret.push(("HOMEPATH".into(), home_path.to_string()));
            to_ret.push(("HOMEDRIVE".into(), home_drive.to_string()));
            to_ret.push(("USERNAME".into(), username.to_string()));
        }
        _ => {
            let username = user_profile.rsplit('\\').next().unwrap_or_default();
            let reason = format!("no drive letter in profile path '{user_profile}'");
            let home_path = report.assume(
                sid,
                "HOMEPATH",
                format!("\\Users\\{}", username),
                reason.clone(),
            );
            let home_drive = report.assume(sid, "HOMEDRIVE", "C:".into(), reason);
            to_ret.push(("HOMEPATH".into(), home_path));
            to_ret.push(("HOMEDRIVE".into(), home_drive));
            to_ret.push(("USERNAME".into(), username.to_string()));
        }
    }
    to_ret
}

struct ProgramFiles {
    program_files: String,
    program_files_86: String,
    program_files_w6432: String,
}

fn replace_user_profile(txt: String, user_profile: &str) -> String {
    if let Some(rest) = txt.strip_prefix("%USERPROFILE%") {
        format!("{}{}", user_profile, rest)
    } else {
        txt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::registry::RegValue;
    use crate::utils::testing::TestingRegistry;

    const SID: &str = "S-1-5-21-1";
    const NT_CURRENT_VERSION: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    fn with_profile(profile: &str) -> TestingRegistry {
        let mut reg = TestingRegistry::new();
        reg.add_value(
            &format!(r"{NT_CURRENT_VERSION}\ProfileList\{SID}"),
            "ProfileImagePath",
            RegValue::new_sz(profile),
        );
        reg.add_value(
            &format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"),
            "AppData",
            RegValue::new_sz(r"%USERPROFILE%\AppData\Roaming"),
        );
        reg
    }

    fn assumed(report: &EnvVarsReport, sid: Option<&str>) -> Vec<String> {
        report
            .fallbacks
            .iter()
            .filter(|f| f.sid.as_deref() == sid)
            .map(|f| f.var.clone())
            .collect()
    }

    #[test]
    fn every_default_is_reported_as_a_fallback() {
        let reg = with_profile(r"C:\Users\Bob");
        let report = get_env_vars_of_users_report(&reg).unwrap();
        let vars = &report.vars[SID];
        assert_eq!(vars["SystemRoot"], r"C:\Windows");
        assert_eq!(vars["APPDATA"], r"C:\Users\Bob\AppData\Roaming");
        assert_eq!(
            assumed(&report, None),
            [
                "SystemRoot",
                "SystemDrive",
                "ProgramFiles",
                "ProgramFiles(x86)",
                "ProgramW6432",
                "ProgramData"
            ]
        );
        // AppData was read; the rest of the per-user values were assumed.
        assert_eq!(assumed(&report, Some(SID)), ["LOCALAPPDATA", "TMP", "TEMP"]);
        assert!(report.errors.is_empty(), "{:?}", report.errors);
    }

    #[test]
    fn values_read_from_the_registry_are_not_fallbacks() {
        let mut reg = with_profile(r"D:\Users\Bob");
        reg.add_value(NT_CURRENT_VERSION, "SystemRoot", RegValue::new_sz(r"D:\Windows"));
        reg.add_value(CURRENT_VERSION, "ProgramFilesDir", RegValue::new_sz(r"D:\Program Files"));
        reg.add_value(
            CURRENT_VERSION,
            "ProgramFilesDir (x86)",
            RegValue::new_sz(r"D:\Program Files (x86)"),
        );
        reg.add_value(CURRENT_VERSION, "ProgramW6432Dir", RegValue::new_sz(r"D:\Program Files"));
        reg.add_value(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            "Common AppData",
            RegValue::new_sz(r"D:\ProgramData"),
        );
        reg.add_value(
            &format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"),
            "Local AppData",
            RegValue::new_sz(r"%USERPROFILE%\AppData\Local"),
        );
        for var in ["TMP", "TEMP"] {
            reg.add_value(
                &format!(r"HKU\{SID}\Environment"),
                var,
                RegValue::new_sz(r"%USERPROFILE%\AppData\Local\Temp"),
            );
        }
        let report = get_env_vars_of_users_report(&reg).unwrap();
        assert!(report.fallbacks.is_empty(), "{:?}", report.fallbacks);
        let vars = &report.vars[SID];
        assert_eq!(vars["SystemDrive"], "D:");
        // `ProgramFilesDir`, not the misspelled `ProgrammFilesDir` it used to read.
        assert_eq!(vars["ProgramFiles"], r"D:\Program Files");
        assert_eq!(vars["HOMEDRIVE"], "D:");
        assert_eq!(vars["HOMEPATH"], r"\Users\Bob");
    }

    #[test]
    fn a_profile_path_without_a_drive_is_a_fallback_not_a_panic() {
        let reg = with_profile(r"ñ\Users\Bob");
        let report = get_env_vars_of_users_report(&reg).unwrap();
        let vars = &report.vars[SID];
        assert_eq!(vars["USERNAME"], "Bob");
        assert_eq!(vars["HOMEDRIVE"], "C:");
        assert!(assumed(&report, Some(SID)).contains(&"HOMEDRIVE".to_string()));
    }
}
