use std::{fmt::Write, time::UNIX_EPOCH};

use crate::prelude::{ForensicError, ForensicResult};

pub const LOCAL_SYSTEM_SID_STR : &str = "S-1-5-18";
pub const LOCAL_SYSTEM_SID_BIN : [u8; 12] = [0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,0x12,0x00,0x00,0x00];
pub const BUILTIN_ADMINS_SID_STR : &str = "S-1-5-32-544";
pub const BUILTIN_ADMINS_SID_BIN : [u8; 16] = [0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00];
pub const BUILTIN_USERS_SID_STR : &str = "S-1-5-32-545";
pub const BUILTIN_USERS_SID_BIN : [u8; 16] = [0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x21,0x02,0x00,0x00];
pub const BUILTIN_GUESTS_SID_STR : &str = "S-1-5-32-546";
pub const BUILTIN_GUESTS_SID_BIN : [u8; 16] = [0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x22,0x02,0x00,0x00];

/// Converts a binary SID to a string
/// 
/// https://learn.microsoft.com/es-es/windows/win32/secauthz/sid-components?redirectedfrom=MSDN
/// 
/// ```rust
/// use forensic_rs::utils::win::to_string_sid;
/// // Builtin/Administrators
/// assert_eq!("S-1-5-32-544", to_string_sid(&[0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00]).unwrap());
/// ```
pub fn to_string_sid(sid : &[u8]) -> ForensicResult<String> {
    if sid.len() < 8 {
        return Err(ForensicError::bad_format_str("SID must have at least 8 bytes"))
    }

    let mut id = String::with_capacity(32);
    
    let subauthority_count = sid[1];
    let mut identifier_authority = (u16::from_be_bytes(sid[2..4].try_into().unwrap_or_default()) as u64) << 32;
    identifier_authority |= u32::from_be_bytes(sid[4..8].try_into().unwrap_or_default()) as u64;
    let _ = write!(&mut id, "S-{}-{}", sid[0], identifier_authority);
    let mut start = 8;

    for _ in 0..subauthority_count {
        if start + 4 > sid.len() {
            break
        }
        let authority = &sid[start..start + 4];
        let tmp = u32::from_le_bytes(authority.try_into().unwrap_or_default());
        let _ = write!(&mut id, "-{}", tmp);
        start += 4;
    }

    Ok(id)
}

/// Converts a Windows filetime to unix timestamp in milliseconds
/// 
/// ```rust
/// use forensic_rs::utils::win::filetime_to_unix_timestamp;
/// //Sat 3 February 2024 14:10:23 UTC
/// assert_eq!(1706969423596, filetime_to_unix_timestamp(133514430235959706u64));
/// ```
pub fn filetime_to_unix_timestamp(filetime : u64) -> u64 {
    (filetime as u128).div_ceil(10_000u128).saturating_sub(11644473600000u128) as u64
}

/// Converts a Windows filetime to unix timestamp with millisecond precision
/// 
/// ```rust
/// use forensic_rs::utils::win::filetime_to_system_time;
/// //Sat 3 February 2024 14:10:23 UTC
/// let time = filetime_to_system_time(133514430235959706u64);
/// assert_eq!(1706969423596, time.duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
/// ```
pub fn filetime_to_system_time(filetime : u64) -> std::time::SystemTime {
    UNIX_EPOCH + std::time::Duration::from_millis(filetime_to_unix_timestamp(filetime))
}

#[test]
fn should_generate_valid_sids() {
    // https://devblogs.microsoft.com/oldnewthing/20040315-00/?p=40253
    assert_eq!("S-1-5-21-2127521184-1604012920-1887927527-72713", to_string_sid(&[0x01,0x05,0x00,0x00,0x00,0x00,0x00,0x05,0x15,0x00,0x00,0x00,0xA0,0x65,0xCF,0x7E,0x78,0x4B,0x9B,0x5F,0xE7,0x7C,0x87,0x70,0x09,0x1C,0x01,0x00]).unwrap());
    assert_eq!(BUILTIN_ADMINS_SID_STR, to_string_sid(&BUILTIN_ADMINS_SID_BIN).unwrap());
    assert_eq!(BUILTIN_USERS_SID_STR, to_string_sid(&BUILTIN_USERS_SID_BIN).unwrap());
    assert_eq!(BUILTIN_GUESTS_SID_STR, to_string_sid(&BUILTIN_GUESTS_SID_BIN).unwrap());
    assert_eq!(LOCAL_SYSTEM_SID_STR, to_string_sid(&LOCAL_SYSTEM_SID_BIN).unwrap());
    assert_eq!("S-1-5-21-1366093794-4292800403-1155380978-513", to_string_sid(&[0x01,0x05,0x00,0x00,0x00,0x00,0x00,0x05,0x15,0x00,0x00,0x00,0xe2,0xef,0x6c,0x51,0x93,0xef,0xde,0xff,0xf2,0xb6,0xdd,0x44,0x01,0x02,0x00,0x00]).unwrap());
}

#[test]
fn should_generate_valid_windows_timestamps() {
    assert_eq!(1706969423596, filetime_to_unix_timestamp(133514430235959706u64));
    let time = filetime_to_system_time(133514430235959706u64);//Sat 3 February 2024 14:10:23 UTC = EPOCH 1706969423
    assert_eq!(1706969423, time.duration_since(UNIX_EPOCH).unwrap().as_secs());
    assert_eq!(1706969423596, time.duration_since(UNIX_EPOCH).unwrap().as_millis());
    println!("{:?}", time.duration_since(UNIX_EPOCH).unwrap().as_millis());
    
}