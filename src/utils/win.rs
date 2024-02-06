use std::{fmt::Write, time::UNIX_EPOCH};

use crate::prelude::{ForensicError, ForensicResult};

pub const LOCAL_SYSTEM_SID_STR: &str = "S-1-5-18";
pub const LOCAL_SYSTEM_SID_BIN: [u8; 12] = [
    0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
];
pub const BUILTIN_ADMINS_SID_STR: &str = "S-1-5-32-544";
pub const BUILTIN_ADMINS_SID_BIN: [u8; 16] = [
    0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
];
pub const BUILTIN_USERS_SID_STR: &str = "S-1-5-32-545";
pub const BUILTIN_USERS_SID_BIN: [u8; 16] = [
    0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x21, 0x02, 0x00, 0x00,
];
pub const BUILTIN_GUESTS_SID_STR: &str = "S-1-5-32-546";
pub const BUILTIN_GUESTS_SID_BIN: [u8; 16] = [
    0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x22, 0x02, 0x00, 0x00,
];

/// Simplifies the handling of dates in Windows filetime format. Use only with UTC dates as it does not take time zones into account. Eliminates the need to use the chrono library.
/// ```rust
/// use forensic_rs::prelude::*;
/// assert_eq!("01-01-1601 00:00:00", format!("{:?}", WinFiletime(0)));
/// assert_eq!("01-01-1605 00:00:00", format!("{:?}", WinFiletime(1262304000000000)));
/// assert_eq!("14-11-1999 18:27:59", format!("{:?}", WinFiletime(125870776790000000)));
/// assert_eq!("14-11-2000 18:27:59.001", format!("{:?}", WinFiletime(126187000790010000)));
/// ```
#[derive(Clone, Default)]
pub struct WinFiletime(pub u64);

/// Simplifies the handling of dates in unix timestamp format. Use only with UTC dates as it does not take time zones into account. Eliminates the need to use the chrono library.
/// 
/// ```rust
/// use forensic_rs::prelude::*;
/// assert_eq!("01-01-1970 00:00:00", format!("{:?}", UnixTimestamp(0)));
/// assert_eq!("01-01-1972 00:00:00", format!("{:?}", UnixTimestamp(63072000000)));
/// ```
#[derive(Clone, Default)]
pub struct UnixTimestamp(pub u64);

/// Converts a binary SID to a string
///
/// https://learn.microsoft.com/es-es/windows/win32/secauthz/sid-components?redirectedfrom=MSDN
///
/// ```rust
/// use forensic_rs::utils::win::to_string_sid;
/// // Builtin/Administrators
/// assert_eq!("S-1-5-32-544", to_string_sid(&[0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00]).unwrap());
/// ```
pub fn to_string_sid(sid: &[u8]) -> ForensicResult<String> {
    if sid.len() < 8 {
        return Err(ForensicError::bad_format_str(
            "SID must have at least 8 bytes",
        ));
    }

    let mut id = String::with_capacity(32);

    let subauthority_count = sid[1];
    let mut identifier_authority =
        (u16::from_be_bytes(sid[2..4].try_into().unwrap_or_default()) as u64) << 32;
    identifier_authority |= u32::from_be_bytes(sid[4..8].try_into().unwrap_or_default()) as u64;
    let _ = write!(&mut id, "S-{}-{}", sid[0], identifier_authority);
    let mut start = 8;

    for _ in 0..subauthority_count {
        if start + 4 > sid.len() {
            break;
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
pub fn filetime_to_unix_timestamp(filetime: u64) -> u64 {
    (filetime as u128)
        .div_ceil(10_000u128)
        .saturating_sub(11644473600000u128) as u64
}

/// Converts a Windows filetime to unix timestamp with millisecond precision
///
/// ```rust
/// use forensic_rs::utils::win::filetime_to_system_time;
/// //Sat 3 February 2024 14:10:23 UTC
/// let time = filetime_to_system_time(133514430235959706u64);
/// assert_eq!(1706969423596, time.duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
/// ```
pub fn filetime_to_system_time(filetime: u64) -> std::time::SystemTime {
    UNIX_EPOCH + std::time::Duration::from_millis(filetime_to_unix_timestamp(filetime))
}

impl From<u64> for WinFiletime {
    fn from(value: u64) -> Self {
        WinFiletime(value)
    }
}
impl From<u64> for UnixTimestamp {
    fn from(value: u64) -> Self {
        UnixTimestamp(value)
    }
}


impl std::fmt::Debug for WinFiletime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let milliseconds_since_beginning = (self.0 as u128).div_euclid(10_000u128);
        let days_since_beginning = milliseconds_since_beginning.div_euclid(60 * 60 * 24 * 1000);
        let milliseconds_in_day = milliseconds_since_beginning - days_since_beginning *60 * 60 * 24 * 1000;
        let (year, restant_days) = to_years(days_since_beginning);
        let (month, acumulated_day_month) = if is_leap_year(year) {
            [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335]
                .iter()
                .position(|&v| v > restant_days)
                .map(|pos| {
                    (
                        pos,
                        [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335][pos - 1],
                    )
                })
        } else {
            [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
                .iter()
                .position(|&v| v > restant_days)
                .map(|pos| {
                    (
                        pos,
                        [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334][pos - 1],
                    )
                })
        }
        .unwrap_or((12, 335));
        let day = restant_days.saturating_sub(acumulated_day_month) + 1;
        let hours = milliseconds_in_day.div_euclid(60 * 60 * 1000);
        let rest_millis = milliseconds_in_day - hours * 60*60*1000;
        let minute = rest_millis.div_euclid(60 * 1000);
        let rest_millis = rest_millis - minute * 60 * 1000;
        let seconds = rest_millis.div_euclid(1000);
        let millis = rest_millis - seconds*1000;
        if millis == 0 {
            f.write_fmt(format_args!(
                "{:02}-{:02}-{:04} {:02}:{:02}:{:02}", day, month,year, hours, minute, seconds
            ))
        }else {
            f.write_fmt(format_args!(
                "{:02}-{:02}-{:04} {:02}:{:02}:{:02}.{:03}", day, month,year, hours, minute, seconds, millis
            ))
        }
    }
}

impl std::fmt::Debug for UnixTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let milliseconds_since_beginning = self.0 as u128;
        let days_since_beginning = milliseconds_since_beginning.div_euclid(60 * 60 * 24 * 1000);
        let milliseconds_in_day = milliseconds_since_beginning - days_since_beginning *60 * 60 * 24 * 1000;
        let (year, restant_days) = to_years_unix(days_since_beginning);
        let (month, acumulated_day_month) = if is_leap_year(year) {
            [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335]
                .iter()
                .position(|&v| v > restant_days)
                .map(|pos| {
                    (
                        pos,
                        [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335][pos - 1],
                    )
                })
        } else {
            [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
                .iter()
                .position(|&v| v > restant_days)
                .map(|pos| {
                    (
                        pos,
                        [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334][pos - 1],
                    )
                })
        }
        .unwrap_or((12, 335));
        let day = restant_days.saturating_sub(acumulated_day_month) + 1;
        let hours = milliseconds_in_day.div_euclid(60 * 60 * 1000);
        let rest_millis = milliseconds_in_day - hours * 60*60*1000;
        let minute = rest_millis.div_euclid(60 * 1000);
        let rest_millis = rest_millis - minute * 60 * 1000;
        let seconds = rest_millis.div_euclid(1000);
        let millis = rest_millis - seconds*1000;
        if millis == 0 {
            f.write_fmt(format_args!(
                "{:02}-{:02}-{:04} {:02}:{:02}:{:02}", day, month,year, hours, minute, seconds
            ))
        }else {
            f.write_fmt(format_args!(
                "{:02}-{:02}-{:04} {:02}:{:02}:{:02}.{:03}", day, month,year, hours, minute, seconds, millis
            ))
        }
    }
}

fn is_leap_year(year: u128) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 100 == 0 && year % 400 == 0)
}
fn to_years(mut days : u128) -> (u128, u128) {
    let mut year = 1601;
    while days >= 365 {
        days -= 365;
        year += 1;
        if days < 365 {
            break
        }
        if is_leap_year(year) {
            days -= 1;
        }
    }
    (year, days)
}
fn to_years_unix(mut days : u128) -> (u128, u128) {
    let mut year = 1970;
    while days >= 365 {
        days -= 365;
        year += 1;
        if days < 365 {
            break
        }
        if is_leap_year(year) {
            days -= 1;
        }
    }
    (year, days)
}

#[test]
fn should_generate_valid_sids() {
    // https://devblogs.microsoft.com/oldnewthing/20040315-00/?p=40253
    assert_eq!(
        "S-1-5-21-2127521184-1604012920-1887927527-72713",
        to_string_sid(&[
            0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0xA0, 0x65,
            0xCF, 0x7E, 0x78, 0x4B, 0x9B, 0x5F, 0xE7, 0x7C, 0x87, 0x70, 0x09, 0x1C, 0x01, 0x00
        ])
        .unwrap()
    );
    assert_eq!(
        BUILTIN_ADMINS_SID_STR,
        to_string_sid(&BUILTIN_ADMINS_SID_BIN).unwrap()
    );
    assert_eq!(
        BUILTIN_USERS_SID_STR,
        to_string_sid(&BUILTIN_USERS_SID_BIN).unwrap()
    );
    assert_eq!(
        BUILTIN_GUESTS_SID_STR,
        to_string_sid(&BUILTIN_GUESTS_SID_BIN).unwrap()
    );
    assert_eq!(
        LOCAL_SYSTEM_SID_STR,
        to_string_sid(&LOCAL_SYSTEM_SID_BIN).unwrap()
    );
    assert_eq!(
        "S-1-5-21-1366093794-4292800403-1155380978-513",
        to_string_sid(&[
            0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0xe2, 0xef,
            0x6c, 0x51, 0x93, 0xef, 0xde, 0xff, 0xf2, 0xb6, 0xdd, 0x44, 0x01, 0x02, 0x00, 0x00
        ])
        .unwrap()
    );
}

#[test]
fn should_generate_valid_windows_timestamps() {
    assert_eq!(
        1706969423596,
        filetime_to_unix_timestamp(133514430235959706u64)
    );
    let time = filetime_to_system_time(133514430235959706u64); //Sat 3 February 2024 14:10:23 UTC = EPOCH 1706969423
    assert_eq!(
        1706969423,
        time.duration_since(UNIX_EPOCH).unwrap().as_secs()
    );
    assert_eq!(
        1706969423596,
        time.duration_since(UNIX_EPOCH).unwrap().as_millis()
    );
    println!("{:?}", time.duration_since(UNIX_EPOCH).unwrap().as_millis());
}

#[test]
fn should_transform_to_calendar() {
    assert_eq!("01-02-2024 00:00:00", format!("{:?}", WinFiletime(133512192000000000)));
    assert_eq!("01-01-2024 14:10:23", format!("{:?}", WinFiletime(133485918230000000)));
    assert_eq!("03-02-2024 14:10:23", format!("{:?}", WinFiletime(133514430230000000)));
    assert_eq!("03-02-2024 14:10:23", format!("{:?}", WinFiletime(133514430230000000)));
    assert_eq!("01-01-1601 00:00:00", format!("{:?}", WinFiletime(0)));
    assert_eq!("01-01-1602 00:00:00", format!("{:?}", WinFiletime(315360000000000)));
    assert_eq!("01-01-1605 00:00:00", format!("{:?}", WinFiletime(1262304000000000)));
    assert_eq!("14-11-1999 18:27:59", format!("{:?}", WinFiletime(125870776790000000)));
    assert_eq!("14-11-2000 18:27:59", format!("{:?}", WinFiletime(126187000790000000)));
    // 2000 is a leap year
    assert_eq!("29-02-2000 18:27:59.001", format!("{:?}", WinFiletime(125963224790010000)));
    // 1900 not a leap year
    assert_eq!("01-03-1900 18:27:59", format!("{:?}", WinFiletime(94406488790000000)));
    assert_eq!("28-02-1900 18:27:59", format!("{:?}", WinFiletime(94405624790000000)));
}

#[test]
fn should_transform_unix_to_calendar() {
    assert_eq!("01-02-2024 00:00:00", format!("{:?}", UnixTimestamp(1706745600000)));
    assert_eq!("01-01-2024 14:10:23", format!("{:?}", UnixTimestamp(1704118223000)));
    assert_eq!("03-02-2024 14:10:23", format!("{:?}", UnixTimestamp(1706969423000)));
    assert_eq!("01-01-1970 00:00:00", format!("{:?}", UnixTimestamp(0)));
    assert_eq!("01-01-1972 00:00:00", format!("{:?}", UnixTimestamp(63072000000)));
    assert_eq!("14-11-1999 18:27:59", format!("{:?}", UnixTimestamp(942604079000)));
    assert_eq!("14-11-2000 18:27:59", format!("{:?}", UnixTimestamp(974226479000)));
    // 2000 is a leap year
    assert_eq!("29-02-2000 18:27:59.001", format!("{:?}", UnixTimestamp(951848879001)));
}
