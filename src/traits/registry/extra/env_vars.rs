use std::collections::BTreeMap;

use crate::core::UsersEnvVars;
use crate::err::ForensicResult;

use crate::traits::registry::{RegValue, RegistryReader, HKLM, HKU};

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
pub fn get_env_vars_of_users(
    reg_reader: &dyn RegistryReader,
) -> ForensicResult<UsersEnvVars> {
    let system_root_path = system_root(reg_reader);
    let system_dive = &system_root_path[0..system_root_path.len().min(2)];
    let system_dive: String = if system_dive.is_empty() { "C:" } else { system_dive }.into();
    let program_files = program_files(reg_reader);
    let program_data = program_data(reg_reader);

    let profiles = list_all_profiles(reg_reader, &system_root_path)?;
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
        for (k, v) in user_specific_env_vars(reg_reader, &user_sid, &user_home) {
            user_map.insert(k, v);
        }
        map.insert(user_sid, user_map);
    }
    Ok(map)
}

fn list_all_profiles(reg_reader: &dyn RegistryReader, system_root : &str) -> ForensicResult<BTreeMap<String, String>> {
    let key = reg_reader.open_key(
        HKLM,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
    )?;
    let users = reg_reader.enumerate_keys(key).unwrap_or_default();
    let mut map = BTreeMap::new();
    for user_sid in users {
        let user_key = match reg_reader.open_key(key, &user_sid) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let mut profile_path: String = match reg_reader.read_value(user_key, "ProfileImagePath") {
            Ok(v) => v.try_into().unwrap_or_default(),
            Err(_) => {
                reg_reader.close_key(user_key);
                continue;
            }
        };
        if profile_path.starts_with("%systemroot%") {
            profile_path = format!("{}{}", system_root, &profile_path[12..])
        }else if profile_path.starts_with("%SystemRoot%") {
            profile_path = format!("{}{}", system_root, &profile_path[12..])
        }
        if !profile_path.is_empty() {
            if user_sid == "S-1-5-18" {
                map.insert(String::new(), profile_path.clone());
            }
            map.insert(user_sid, profile_path);
        }
        reg_reader.close_key(user_key);
    }
    reg_reader.close_key(key);
    Ok(map)
}

fn system_root(reg_reader: &dyn RegistryReader) -> String {
    let key = match reg_reader.open_key(
        HKLM,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
    ) {
        Ok(v) => v,
        Err(_) => return r"C:\Windows".into(),
    };
    let value = reg_reader
        .read_value(key, "SystemRoot")
        .unwrap_or_else(|_| RegValue::SZ(r"C:\Windows".into()));
    reg_reader.close_key(key);
    value.try_into().unwrap_or_else(|_| r"C:\Windows".into())
}

fn program_data(reg_reader: &dyn RegistryReader) -> String {
    let key = match reg_reader.open_key(
        HKLM,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    ) {
        Ok(v) => v,
        Err(_) => return r"C:\ProgramData".into(),
    };
    let value = reg_reader
        .read_value(key, "Common AppData")
        .unwrap_or_else(|_| RegValue::SZ(r"C:\ProgramData".into()));
    reg_reader.close_key(key);
    value
        .try_into()
        .unwrap_or_else(|_| r"C:\ProgramData".into())
}
fn program_files(reg_reader: &dyn RegistryReader) -> ProgramFiles {
    let key = match reg_reader.open_key(
        HKLM,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion",
    ) {
        Ok(v) => v,
        Err(_) => {
            return ProgramFiles {
                program_files: r"C:\Program Files".into(),
                program_files_86: r"C:\Program Files (x86)".into(),
                program_files_w6432: r"C:\Program Files".into(),
            }
        }
    };
    let program_files: String = reg_value(reg_reader, key, "ProgrammFilesDir", || {
        r"C:\Program Files".into()
    });
    let program_files_86: String = reg_value(reg_reader, key, "ProgramFilesDir (x86)", || {
        r"C:\Program Files (x86)".into()
    });
    let program_files_w6432: String = reg_value(reg_reader, key, "ProgramW6432Dir", || {
        r"C:\Program Files".into()
    });
    reg_reader.close_key(key);
    ProgramFiles {
        program_files,
        program_files_86,
        program_files_w6432,
    }
}

fn user_specific_env_vars(
    reg_reader: &dyn RegistryReader,
    user: &str,
    user_profile: &str,
) -> Vec<(String, String)> {
    let user_key = match reg_reader.open_key(HKU, user) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let shell_folders = match reg_reader.open_key(
        user_key,
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    ) {
        Ok(v) => v,
        Err(_) => {
            reg_reader.close_key(user_key);
            return Vec::new()
        }
    };
    let mut to_ret = Vec::with_capacity(12);
    let app_data: String = reg_value(reg_reader, shell_folders, "AppData", || {
        format!("{}\\AppData\\Roaming", user_profile)
    });
    let local_app_data: String = reg_value(reg_reader, shell_folders, "Local AppData", || {
        format!("{}\\AppData\\Local", user_profile)
    });
    to_ret.push(("LOCALAPPDATA".into(), replace_user_profile(local_app_data, user_profile)));
    to_ret.push(("APPDATA".into(), replace_user_profile(app_data, user_profile)));
    reg_reader.close_key(shell_folders);

    if let Ok(env_key) = reg_reader.open_key(user_key, r"Environment") {
        let tmp: String = reg_value(reg_reader, shell_folders, "TMP", || {
            format!("{}\\AppData\\Local\\Temp", user_profile)
        });
        let temp: String = reg_value(reg_reader, shell_folders, "TEMP", || {
            format!("{}\\AppData\\Local\\Temp", user_profile)
        });
        reg_reader.close_key(env_key);
        to_ret.push(("TMP".into(), replace_user_profile(tmp, user_profile)));
        to_ret.push(("TEMP".into(), replace_user_profile(temp, user_profile)));
    }else {
        to_ret.push(("TMP".into(), format!("{}\\AppData\\Local\\Temp", user_profile)));
        to_ret.push(("TEMP".into(), format!("{}\\AppData\\Local\\Temp", user_profile)));
    };
    reg_reader.close_key(user_key);
    if user_profile.len() > 3 {
        let (home_drive, home_path) = if user_profile.starts_with('%') {
            (user_profile[0..2].to_string(), user_profile[2..].to_string())
        } else {
            (user_profile[0..2].to_string(), user_profile[2..].to_string())
        };

        let mut splited = user_profile.split('\\').rev();
        let username = splited
            .next()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "".into());
        to_ret.push(("HOMEPATH".into(), home_path));
        to_ret.push(("HOMEDRIVE".into(), home_drive));
        to_ret.push(("USERNAME".into(), username));
    }else {
        let up_u8 = user_profile.as_bytes();
        let end_slice = up_u8.iter().rev().position(|&v| v == b'\\').unwrap_or(0);
        let username = &user_profile[user_profile.len() - end_slice..];
        to_ret.push(("HOMEPATH".into(), format!("\\Users\\{}", username)));
        to_ret.push(("HOMEDRIVE".into(), "C:".into()));
        to_ret.push(("USERNAME".into(), username.into()));
    }
    to_ret
}

fn reg_value<F, T>(reg_reader: &dyn RegistryReader, key: crate::prelude::RegHiveKey, value: &str, default: F) -> T
where
    T: TryFrom<RegValue>,
    F: FnOnce() -> T,
{
    match reg_reader.read_value(key, value) {
        Ok(v) => v.try_into().unwrap_or_else(|_| default()),
        Err(_) => default(),
    }
}

struct ProgramFiles {
    program_files: String,
    program_files_86: String,
    program_files_w6432: String,
}

fn replace_user_profile(txt : String, user_profile : &str) -> String {
    if txt.starts_with("%USERPROFILE%") {
        format!("{}{}", user_profile, &txt[13..])
    }else{
        txt
    }
}