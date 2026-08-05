use std::collections::BTreeMap;

use crate::core::UsersEnvVars;
use crate::err::ForensicResult;
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
pub fn get_env_vars_of_users(reg: &dyn Registry) -> ForensicResult<UsersEnvVars> {
    let system_root_path = system_root(reg);
    let system_dive: String = {
        let s = &system_root_path[0..system_root_path.len().min(2)];
        if s.is_empty() {
            "C:".into()
        } else {
            s.into()
        }
    };
    let program_files = program_files(reg);
    let program_data = program_data(reg);

    let profiles = list_all_profiles(reg)?;
    let mut map = BTreeMap::new();
    for (user_sid, user_home) in profiles {
        let mut user_map = BTreeMap::new();
        user_map.insert("USERPROFILE".into(), user_home.clone());
        user_map.insert("SystemRoot".into(), system_root_path.clone());
        user_map.insert("windir".into(), system_root_path.clone());
        user_map.insert("SystemDrive".into(), system_dive.clone());
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
        for (k, v) in user_specific_env_vars(reg, &user_sid, &user_home) {
            user_map.insert(k, v);
        }
        map.insert(user_sid, user_map);
    }
    Ok(map)
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
fn list_all_profiles(reg: &dyn Registry) -> ForensicResult<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for profile in windows::users(reg)? {
        if profile.profile_path.as_str().is_empty() {
            continue;
        }
        let path = win_sep(profile.profile_path.to_string());
        if profile.sid == "S-1-5-18" {
            map.insert(String::new(), path.clone());
        }
        map.insert(profile.sid, path);
    }
    Ok(map)
}

fn system_root(reg: &dyn Registry) -> String {
    windows::system_root(reg)
        .map(|p| win_sep(p.to_string()))
        .unwrap_or_else(|_| r"C:\Windows".into())
}

fn program_data(reg: &dyn Registry) -> String {
    reg.value(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        "Common AppData",
    )
    .ok()
    .and_then(|v| String::try_from(v).ok())
    .unwrap_or_else(|| r"C:\ProgramData".into())
}

fn program_files(reg: &dyn Registry) -> ProgramFiles {
    let program_files = reg_value(reg, CURRENT_VERSION, "ProgrammFilesDir", || {
        r"C:\Program Files".into()
    });
    let program_files_86 = reg_value(reg, CURRENT_VERSION, "ProgramFilesDir (x86)", || {
        r"C:\Program Files (x86)".into()
    });
    let program_files_w6432 = reg_value(reg, CURRENT_VERSION, "ProgramW6432Dir", || {
        r"C:\Program Files".into()
    });
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
) -> Vec<(String, String)> {
    // Mirrors the original's two early-return gates exactly: if the user's
    // hive isn't loaded (`HKU\{sid}` absent) or it has no
    // `User Shell Folders` subkey, no per-user env vars are produced at all
    // (not even the pure-string-derived HOMEPATH/HOMEDRIVE/USERNAME).
    let user_root_path = format!(r"HKU\{user}");
    if reg.key(&user_root_path).is_err() {
        return Vec::new();
    }
    let shell_folders_path =
        format!(r"{user_root_path}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders");
    if reg.key(&shell_folders_path).is_err() {
        return Vec::new();
    }

    let mut to_ret = Vec::with_capacity(12);
    let app_data = reg_value(reg, &shell_folders_path, "AppData", || {
        format!("{}\\AppData\\Roaming", user_profile)
    });
    let local_app_data = reg_value(reg, &shell_folders_path, "Local AppData", || {
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
    if reg.key(&env_path).is_ok() {
        let tmp = reg_value(reg, &env_path, "TMP", || {
            format!("{}\\AppData\\Local\\Temp", user_profile)
        });
        let temp = reg_value(reg, &env_path, "TEMP", || {
            format!("{}\\AppData\\Local\\Temp", user_profile)
        });
        to_ret.push(("TMP".into(), replace_user_profile(tmp, user_profile)));
        to_ret.push(("TEMP".into(), replace_user_profile(temp, user_profile)));
    } else {
        to_ret.push((
            "TMP".into(),
            format!("{}\\AppData\\Local\\Temp", user_profile),
        ));
        to_ret.push((
            "TEMP".into(),
            format!("{}\\AppData\\Local\\Temp", user_profile),
        ));
    }
    if user_profile.len() > 3 {
        let (home_drive, home_path) = (
            user_profile[0..2].to_string(),
            user_profile[2..].to_string(),
        );
        let mut splited = user_profile.split('\\').rev();
        let username = splited
            .next()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "".into());
        to_ret.push(("HOMEPATH".into(), home_path));
        to_ret.push(("HOMEDRIVE".into(), home_drive));
        to_ret.push(("USERNAME".into(), username));
    } else {
        let up_u8 = user_profile.as_bytes();
        let end_slice = up_u8.iter().rev().position(|&v| v == b'\\').unwrap_or(0);
        let username = &user_profile[user_profile.len() - end_slice..];
        to_ret.push(("HOMEPATH".into(), format!("\\Users\\{}", username)));
        to_ret.push(("HOMEDRIVE".into(), "C:".into()));
        to_ret.push(("USERNAME".into(), username.into()));
    }
    to_ret
}

fn reg_value<F, T>(reg: &dyn Registry, path: &str, value: &str, default: F) -> T
where
    T: TryFrom<crate::traits::registry::RegValue>,
    F: FnOnce() -> T,
{
    match reg.value(path, value) {
        Ok(v) => v.try_into().unwrap_or_else(|_| default()),
        Err(_) => default(),
    }
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
