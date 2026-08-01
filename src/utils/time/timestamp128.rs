use std::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    ops::{Add, BitAnd, BitOr, BitOrAssign, Sub},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::err::{ForensicError, ForensicResult};

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const NANOS_PER_SECOND: u32 = 1_000_000_000;
const SECONDS_PER_DAY: i64 = 86_400;
const OFFSET_UNKNOWN: i16 = i16::MIN;
const FILETIME_UNIX_EPOCH_TICKS: i128 = 116_444_736_000_000_000;
const FILETIME_TICKS_PER_SECOND: i128 = 10_000_000;
const WEBKIT_UNIX_EPOCH_MICROS: i128 = 11_644_473_600_000_000;
const HFS_UNIX_EPOCH_SECONDS: i64 = 2_082_844_800;
const COCOA_UNIX_EPOCH_SECONDS: i64 = 978_307_200;
const OLE_UNIX_EPOCH_DAYS: f64 = 25_569.0;

/// Describes the precision supplied by a timestamp source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TimestampPrecision {
    Unknown = 0,
    Days = 1,
    Seconds = 2,
    Milliseconds = 3,
    Microseconds = 4,
    HundredNanoseconds = 5,
    Nanoseconds = 6,
}

impl TimestampPrecision {
    const fn from_bits(bits: u16) -> Self {
        match bits {
            1 => Self::Days,
            2 => Self::Seconds,
            3 => Self::Milliseconds,
            4 => Self::Microseconds,
            5 => Self::HundredNanoseconds,
            6 => Self::Nanoseconds,
            _ => Self::Unknown,
        }
    }
}

/// Identifies the format or process that produced a timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TimestampSource {
    Unknown = 0,
    Unix = 1,
    WindowsFiletime = 2,
    WebKit = 3,
    OleAutomation = 4,
    HfsPlus = 5,
    Cocoa = 6,
    Calendar = 7,
    SystemTime = 8,
    ParsedText = 9,
    Derived = 10,
}

impl TimestampSource {
    const fn from_bits(bits: u16) -> Self {
        match bits {
            1 => Self::Unix,
            2 => Self::WindowsFiletime,
            3 => Self::WebKit,
            4 => Self::OleAutomation,
            5 => Self::HfsPlus,
            6 => Self::Cocoa,
            7 => Self::Calendar,
            8 => Self::SystemTime,
            9 => Self::ParsedText,
            10 => Self::Derived,
            _ => Self::Unknown,
        }
    }
}

/// Provenance, precision, and normalization metadata for [`Timestamp128`].
///
/// Bits 0-3 represent [`TimestampPrecision`], bits 4-7 represent
/// [`TimestampSource`], bits 8-11 are metadata flags, and bits 12-15 are
/// retained for forward-compatible consumers.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TimestampFlags(u16);

impl TimestampFlags {
    const PRECISION_MASK: u16 = 0x000f;
    const SOURCE_MASK: u16 = 0x00f0;

    pub const APPROXIMATE: Self = Self(0x0100);
    pub const INFERRED: Self = Self(0x0200);
    pub const TRUNCATED: Self = Self(0x0400);
    pub const NORMALIZED: Self = Self(0x0800);

    pub const fn new(precision: TimestampPrecision, source: TimestampSource) -> Self {
        Self((precision as u16) | ((source as u16) << 4))
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn from_bits_retain(bits: u16) -> Self {
        Self(bits)
    }

    pub const fn precision(self) -> TimestampPrecision {
        TimestampPrecision::from_bits(self.0 & Self::PRECISION_MASK)
    }

    pub const fn source(self) -> TimestampSource {
        TimestampSource::from_bits((self.0 & Self::SOURCE_MASK) >> 4)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn with_precision(self, precision: TimestampPrecision) -> Self {
        Self((self.0 & !Self::PRECISION_MASK) | precision as u16)
    }

    pub const fn with_source(self, source: TimestampSource) -> Self {
        Self((self.0 & !Self::SOURCE_MASK) | ((source as u16) << 4))
    }
}

impl BitOr for TimestampFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for TimestampFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for TimestampFlags {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

/// A validated, nanosecond-precision forensic timestamp.
///
/// The stored instant is UTC. The optional offset records source display
/// context and never changes the instant used for chronological comparison.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct ForensicTimestamp {
    utc_seconds: i64,
    nanoseconds: u32,
    utc_offset_minutes: i16,
    flags: TimestampFlags,
}

/// Width-oriented alias for [`ForensicTimestamp`].
pub type Timestamp128 = ForensicTimestamp;

const _: [(); 16] = [(); std::mem::size_of::<ForensicTimestamp>()];
const _: [(); 16] = [(); std::mem::align_of::<ForensicTimestamp>()];

impl ForensicTimestamp {
    /// Creates a timestamp from normalized UTC seconds and nanoseconds.
    pub fn try_from_parts(
        utc_seconds: i64,
        nanoseconds: u32,
        utc_offset_minutes: Option<i16>,
        flags: TimestampFlags,
    ) -> ForensicResult<Self> {
        if nanoseconds >= NANOS_PER_SECOND {
            return Err(invalid_timestamp(
                nanoseconds as u64,
                "nanoseconds must be below 1_000_000_000",
            ));
        }
        let utc_offset_minutes = match utc_offset_minutes {
            Some(offset) if (-1440..=1440).contains(&offset) => offset,
            Some(offset) => {
                return Err(invalid_timestamp(
                    offset.unsigned_abs() as u64,
                    "UTC offset must be between -1440 and 1440 minutes",
                ));
            }
            None => OFFSET_UNKNOWN,
        };
        Ok(Self {
            utc_seconds,
            nanoseconds,
            utc_offset_minutes,
            flags,
        })
    }

    pub fn from_unix_secs(seconds: i64) -> Self {
        Self::from_parts_unchecked(
            seconds,
            0,
            None,
            TimestampFlags::new(TimestampPrecision::Seconds, TimestampSource::Unix),
        )
    }

    pub fn from_unix_millis(milliseconds: i64) -> Self {
        Self::from_unix_nanos_unchecked(
            milliseconds as i128 * 1_000_000,
            TimestampFlags::new(TimestampPrecision::Milliseconds, TimestampSource::Unix),
        )
    }

    pub fn from_unix_micros(microseconds: i64) -> Self {
        Self::from_unix_nanos_unchecked(
            microseconds as i128 * 1_000,
            TimestampFlags::new(TimestampPrecision::Microseconds, TimestampSource::Unix),
        )
    }

    pub fn try_from_unix_nanos(nanoseconds: i128) -> ForensicResult<Self> {
        let seconds = nanoseconds.div_euclid(NANOS_PER_SECOND as i128);
        let nanos = nanoseconds.rem_euclid(NANOS_PER_SECOND as i128) as u32;
        let seconds = i64::try_from(seconds).map_err(|_| {
            invalid_timestamp(u64::MAX, "Unix nanoseconds exceed Timestamp128 range")
        })?;
        Self::try_from_parts(
            seconds,
            nanos,
            None,
            TimestampFlags::new(TimestampPrecision::Nanoseconds, TimestampSource::Unix),
        )
    }

    pub fn from_win_filetime(filetime: u64) -> Self {
        let unix_ticks = filetime as i128 - FILETIME_UNIX_EPOCH_TICKS;
        let seconds = unix_ticks.div_euclid(FILETIME_TICKS_PER_SECOND);
        let nanos = (unix_ticks.rem_euclid(FILETIME_TICKS_PER_SECOND) * 100) as u32;
        Self::from_parts_unchecked(
            seconds as i64,
            nanos,
            None,
            TimestampFlags::new(
                TimestampPrecision::HundredNanoseconds,
                TimestampSource::WindowsFiletime,
            ),
        )
    }

    pub fn from_webkit(microseconds: i64) -> Self {
        Self::from_unix_nanos_unchecked(
            (microseconds as i128 - WEBKIT_UNIX_EPOCH_MICROS) * 1_000,
            TimestampFlags::new(TimestampPrecision::Microseconds, TimestampSource::WebKit),
        )
    }

    pub fn from_hfs_plus(seconds: u32) -> Self {
        Self::from_parts_unchecked(
            seconds as i64 - HFS_UNIX_EPOCH_SECONDS,
            0,
            None,
            TimestampFlags::new(TimestampPrecision::Seconds, TimestampSource::HfsPlus),
        )
    }

    pub fn try_from_cocoa(seconds: f64) -> ForensicResult<Self> {
        Self::try_from_float_seconds(seconds, COCOA_UNIX_EPOCH_SECONDS, TimestampSource::Cocoa)
    }

    pub fn try_from_ole_date(days: f64) -> ForensicResult<Self> {
        if !days.is_finite() {
            return Err(invalid_timestamp(0, "OLE Automation date must be finite"));
        }
        let unix_nanos = ((days - OLE_UNIX_EPOCH_DAYS) * 86_400_000_000_000.0).round();
        if !(i128::MIN as f64..=i128::MAX as f64).contains(&unix_nanos) {
            return Err(invalid_timestamp(0, "OLE Automation date exceeds Timestamp128 range"));
        }
        let mut timestamp = Self::try_from_unix_nanos(unix_nanos as i128)?;
        timestamp.flags = TimestampFlags::new(
            TimestampPrecision::Milliseconds,
            TimestampSource::OleAutomation,
        ) | TimestampFlags::APPROXIMATE;
        Ok(timestamp)
    }

    pub fn try_with_ymd_and_hms_nanos(
        year: i64,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        nanoseconds: u32,
        utc_offset_minutes: Option<i16>,
    ) -> ForensicResult<Self> {
        if !(1..=12).contains(&month) {
            return Err(invalid_timestamp(month as u64, "month must be between 1 and 12"));
        }
        if day == 0 || day > days_in_month(year, month) {
            return Err(invalid_timestamp(day as u64, "day is invalid for the supplied month"));
        }
        if hour > 23 || minute > 59 || second > 59 {
            return Err(invalid_timestamp(
                hour.max(minute).max(second) as u64,
                "time component is out of range",
            ));
        }
        let offset = utc_offset_minutes.unwrap_or(0) as i64;
        let local_seconds = days_from_civil(year, month, day)
            .checked_mul(SECONDS_PER_DAY)
            .and_then(|days| days.checked_add(hour as i64 * 3_600 + minute as i64 * 60 + second as i64))
            .ok_or_else(|| invalid_timestamp(u64::MAX, "calendar time exceeds Timestamp128 range"))?;
        let utc_seconds = local_seconds
            .checked_sub(offset * 60)
            .ok_or_else(|| invalid_timestamp(u64::MAX, "UTC offset exceeds Timestamp128 range"))?;
        Self::try_from_parts(
            utc_seconds,
            nanoseconds,
            utc_offset_minutes,
            TimestampFlags::new(TimestampPrecision::Nanoseconds, TimestampSource::Calendar),
        )
    }

    pub const fn utc_seconds(self) -> i64 {
        self.utc_seconds
    }

    pub const fn nanoseconds(self) -> u32 {
        self.nanoseconds
    }

    pub const fn utc_offset_minutes(self) -> Option<i16> {
        if self.utc_offset_minutes == OFFSET_UNKNOWN {
            None
        } else {
            Some(self.utc_offset_minutes)
        }
    }

    pub const fn flags(self) -> TimestampFlags {
        self.flags
    }

    pub fn year(self) -> i64 {
        self.utc_components().0
    }

    pub fn month(self) -> u8 {
        self.utc_components().1
    }

    pub fn day(self) -> u8 {
        self.utc_components().2
    }

    pub fn hour(self) -> u8 {
        self.utc_components().3
    }

    pub fn minute(self) -> u8 {
        self.utc_components().4
    }

    pub fn second(self) -> u8 {
        self.utc_components().5
    }

    pub fn with_ymd_and_hms(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        microseconds: u32,
    ) -> ForensicResult<Self> {
        Self::try_with_ymd_and_hms_nanos(
            year as i64,
            month,
            day,
            hour,
            minute,
            second,
            microseconds.checked_mul(1_000).ok_or_else(|| {
                invalid_timestamp(microseconds as u64, "microseconds exceed nanosecond precision")
            })?,
            None,
        )
    }

    pub const fn milliseconds(self) -> u32 {
        self.nanoseconds / 1_000_000
    }

    pub const fn microseconds(self) -> u32 {
        self.nanoseconds / 1_000
    }

    pub fn to_unix_millis(self) -> i128 {
        self.to_unix_nanos() / 1_000_000
    }

    pub fn to_unix_micros(self) -> i128 {
        self.to_unix_nanos() / 1_000
    }

    pub const fn to_unix_nanos(self) -> i128 {
        self.utc_seconds as i128 * NANOS_PER_SECOND as i128 + self.nanoseconds as i128
    }

    pub const fn to_unix_secs(self) -> i64 {
        self.utc_seconds
    }

    pub fn to_win_filetime(self) -> ForensicResult<u64> {
        let ticks = self
            .to_unix_nanos()
            .div_euclid(100)
            .checked_add(FILETIME_UNIX_EPOCH_TICKS)
            .ok_or_else(|| invalid_timestamp(u64::MAX, "FILETIME conversion overflow"))?;
        u64::try_from(ticks)
            .map_err(|_| invalid_timestamp(u64::MAX, "timestamp predates the FILETIME epoch"))
    }

    pub fn try_from_system_time(time: SystemTime) -> ForensicResult<Self> {
        let nanos = match time.duration_since(UNIX_EPOCH) {
            Ok(duration) => i128::try_from(duration.as_nanos())
                .map_err(|_| invalid_timestamp(u64::MAX, "SystemTime exceeds Timestamp128 range"))?,
            Err(error) => -i128::try_from(error.duration().as_nanos())
                .map_err(|_| invalid_timestamp(u64::MAX, "SystemTime exceeds Timestamp128 range"))?,
        };
        let mut timestamp = Self::try_from_unix_nanos(nanos)?;
        timestamp.flags = TimestampFlags::new(TimestampPrecision::Nanoseconds, TimestampSource::SystemTime);
        Ok(timestamp)
    }

    pub fn to_system_time(self) -> ForensicResult<SystemTime> {
        let nanos = self.to_unix_nanos();
        let magnitude = u64::try_from(nanos.unsigned_abs())
            .map_err(|_| invalid_timestamp(u64::MAX, "timestamp exceeds SystemTime range"))?;
        if nanos >= 0 {
            UNIX_EPOCH
                .checked_add(Duration::from_nanos(magnitude))
                .ok_or_else(|| invalid_timestamp(u64::MAX, "timestamp exceeds SystemTime range"))
        } else {
            UNIX_EPOCH
                .checked_sub(Duration::from_nanos(magnitude))
                .ok_or_else(|| invalid_timestamp(u64::MAX, "timestamp exceeds SystemTime range"))
        }
    }

    pub fn same_instant(self, other: Self) -> bool {
        self.utc_seconds == other.utc_seconds && self.nanoseconds == other.nanoseconds
    }

    pub fn cmp_instant(self, other: Self) -> Ordering {
        (self.utc_seconds, self.nanoseconds).cmp(&(other.utc_seconds, other.nanoseconds))
    }

    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        let nanos = self.to_unix_nanos().checked_add(duration.as_nanos() as i128)?;
        Self::from_total_nanos(nanos, self.utc_offset_minutes(), self.flags | TimestampFlags::NORMALIZED)
    }

    pub fn checked_sub(self, duration: Duration) -> Option<Self> {
        let nanos = self.to_unix_nanos().checked_sub(duration.as_nanos() as i128)?;
        Self::from_total_nanos(nanos, self.utc_offset_minutes(), self.flags | TimestampFlags::NORMALIZED)
    }

    pub fn saturating_add(self, duration: Duration) -> Self {
        self.checked_add(duration).unwrap_or_else(|| {
            Self::from_parts_unchecked(i64::MAX, 999_999_999, self.utc_offset_minutes(), self.flags)
        })
    }

    pub fn saturating_sub(self, duration: Duration) -> Self {
        self.checked_sub(duration).unwrap_or_else(|| {
            Self::from_parts_unchecked(i64::MIN, 0, self.utc_offset_minutes(), self.flags)
        })
    }

    pub fn to_le_bytes(self) -> [u8; 16] {
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&self.utc_seconds.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.nanoseconds.to_le_bytes());
        bytes[12..14].copy_from_slice(&self.utc_offset_minutes.to_le_bytes());
        bytes[14..].copy_from_slice(&self.flags.bits().to_le_bytes());
        bytes
    }

    pub fn from_le_bytes(bytes: [u8; 16]) -> ForensicResult<Self> {
        let seconds = i64::from_le_bytes(bytes[..8].try_into().expect("fixed timestamp length"));
        let nanoseconds = u32::from_le_bytes(bytes[8..12].try_into().expect("fixed timestamp length"));
        let offset = i16::from_le_bytes(bytes[12..14].try_into().expect("fixed timestamp length"));
        let flags = TimestampFlags::from_bits_retain(u16::from_le_bytes(
            bytes[14..].try_into().expect("fixed timestamp length"),
        ));
        Self::try_from_parts(seconds, nanoseconds, (offset != OFFSET_UNKNOWN).then_some(offset), flags)
    }

    pub fn to_be_bytes(self) -> [u8; 16] {
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&self.utc_seconds.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.nanoseconds.to_be_bytes());
        bytes[12..14].copy_from_slice(&self.utc_offset_minutes.to_be_bytes());
        bytes[14..].copy_from_slice(&self.flags.bits().to_be_bytes());
        bytes
    }

    pub fn from_be_bytes(bytes: [u8; 16]) -> ForensicResult<Self> {
        let seconds = i64::from_be_bytes(bytes[..8].try_into().expect("fixed timestamp length"));
        let nanoseconds = u32::from_be_bytes(bytes[8..12].try_into().expect("fixed timestamp length"));
        let offset = i16::from_be_bytes(bytes[12..14].try_into().expect("fixed timestamp length"));
        let flags = TimestampFlags::from_bits_retain(u16::from_be_bytes(
            bytes[14..].try_into().expect("fixed timestamp length"),
        ));
        Self::try_from_parts(seconds, nanoseconds, (offset != OFFSET_UNKNOWN).then_some(offset), flags)
    }

    fn utc_components(self) -> (i64, u8, u8, u8, u8, u8) {
        let days = self.utc_seconds.div_euclid(SECONDS_PER_DAY);
        let seconds_in_day = self.utc_seconds.rem_euclid(SECONDS_PER_DAY);
        let (year, month, day) = civil_from_days(days);
        (
            year,
            month,
            day,
            (seconds_in_day / 3_600) as u8,
            ((seconds_in_day % 3_600) / 60) as u8,
            (seconds_in_day % 60) as u8,
        )
    }

    fn try_from_float_seconds(
        seconds: f64,
        epoch_offset_seconds: i64,
        source: TimestampSource,
    ) -> ForensicResult<Self> {
        if !seconds.is_finite() {
            return Err(invalid_timestamp(0, "timestamp value must be finite"));
        }
        let unix_nanos = (seconds + epoch_offset_seconds as f64) * NANOS_PER_SECOND as f64;
        if !(i128::MIN as f64..=i128::MAX as f64).contains(&unix_nanos) {
            return Err(invalid_timestamp(0, "timestamp value exceeds Timestamp128 range"));
        }
        let mut timestamp = Self::try_from_unix_nanos(unix_nanos.round() as i128)?;
        timestamp.flags = TimestampFlags::new(TimestampPrecision::Nanoseconds, source)
            | TimestampFlags::APPROXIMATE;
        Ok(timestamp)
    }

    fn from_unix_nanos_unchecked(nanoseconds: i128, flags: TimestampFlags) -> Self {
        Self::from_total_nanos(nanoseconds, None, flags).expect("i64 input always fits Timestamp128")
    }

    fn from_total_nanos(
        nanoseconds: i128,
        utc_offset_minutes: Option<i16>,
        flags: TimestampFlags,
    ) -> Option<Self> {
        let seconds = i64::try_from(nanoseconds.div_euclid(NANOS_PER_SECOND as i128)).ok()?;
        let nanos = nanoseconds.rem_euclid(NANOS_PER_SECOND as i128) as u32;
        Self::try_from_parts(seconds, nanos, utc_offset_minutes, flags).ok()
    }

    const fn from_parts_unchecked(
        utc_seconds: i64,
        nanoseconds: u32,
        utc_offset_minutes: Option<i16>,
        flags: TimestampFlags,
    ) -> Self {
        Self {
            utc_seconds,
            nanoseconds,
            utc_offset_minutes: match utc_offset_minutes {
                Some(offset) => offset,
                None => OFFSET_UNKNOWN,
            },
            flags,
        }
    }
}

impl PartialEq for ForensicTimestamp {
    fn eq(&self, other: &Self) -> bool {
        (self.utc_seconds, self.nanoseconds, self.utc_offset_minutes, self.flags)
            == (other.utc_seconds, other.nanoseconds, other.utc_offset_minutes, other.flags)
    }
}

impl Eq for ForensicTimestamp {}

impl Hash for ForensicTimestamp {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.utc_seconds, self.nanoseconds, self.utc_offset_minutes, self.flags).hash(state);
    }
}

impl PartialOrd for ForensicTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ForensicTimestamp {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.utc_seconds, self.nanoseconds, self.utc_offset_minutes, self.flags).cmp(&(
            other.utc_seconds,
            other.nanoseconds,
            other.utc_offset_minutes,
            other.flags,
        ))
    }
}

impl fmt::Debug for ForensicTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Timestamp128")
            .field("utc_seconds", &self.utc_seconds)
            .field("nanoseconds", &self.nanoseconds)
            .field("utc_offset_minutes", &self.utc_offset_minutes())
            .field("flags", &self.flags)
            .finish()
    }
}

impl fmt::Display for ForensicTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{:09} UTC", self.utc_seconds, self.nanoseconds)
    }
}

impl Add<Duration> for ForensicTimestamp {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        self.saturating_add(rhs)
    }
}

impl Sub<Duration> for ForensicTimestamp {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self::Output {
        self.saturating_sub(rhs)
    }
}

impl From<super::Filetime> for ForensicTimestamp {
    fn from(filetime: super::Filetime) -> Self {
        Self::from_win_filetime(filetime.filetime())
    }
}

fn invalid_timestamp(timestamp: u64, reason: &'static str) -> ForensicError {
    ForensicError::illegal_timestamp(timestamp, reason.into())
}

fn is_leap_year(year: i64) -> bool {
    year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

fn days_in_month(year: i64, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

// Howard Hinnant's civil-date algorithm, with Unix epoch day zero.
fn days_from_civil(year: i64, month: u8, day: u8) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = month as i64;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, u8, u8) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524
        - day_of_era / 146_096)
        / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month as u8, day as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_16_bytes_and_16_byte_aligned() {
        assert_eq!(std::mem::size_of::<Timestamp128>(), 16);
        assert_eq!(std::mem::align_of::<Timestamp128>(), 16);
    }

    #[test]
    fn normalizes_negative_unix_fractions() {
        let timestamp = ForensicTimestamp::try_from_unix_nanos(-500_000_000).unwrap();
        assert_eq!(timestamp.utc_seconds(), -1);
        assert_eq!(timestamp.nanoseconds(), 500_000_000);
    }

    #[test]
    fn validates_parts_and_preserves_unknown_flag_bits() {
        assert!(ForensicTimestamp::try_from_parts(0, NANOS_PER_SECOND, None, TimestampFlags::default()).is_err());
        assert!(ForensicTimestamp::try_from_parts(0, 0, Some(1_441), TimestampFlags::default()).is_err());

        let flags = TimestampFlags::from_bits_retain(0xf8a6);
        let timestamp = ForensicTimestamp::try_from_parts(0, 1, Some(60), flags).unwrap();
        assert_eq!(timestamp.flags().bits(), flags.bits());
        assert_eq!(timestamp.flags().precision(), TimestampPrecision::Nanoseconds);
    }

    #[test]
    fn calendar_constructor_handles_leap_year_and_offsets() {
        let timestamp = ForensicTimestamp::try_with_ymd_and_hms_nanos(
            2024,
            2,
            29,
            1,
            0,
            0,
            42,
            Some(60),
        )
        .unwrap();
        assert_eq!(timestamp.utc_seconds(), 1_709_164_800);
        assert_eq!(timestamp.nanoseconds(), 42);
        assert_eq!(timestamp.utc_offset_minutes(), Some(60));
    }

    #[test]
    fn binary_round_trip_preserves_all_parts() {
        let timestamp = ForensicTimestamp::try_from_parts(
            -1,
            999_999_999,
            Some(-720),
            TimestampFlags::new(TimestampPrecision::Nanoseconds, TimestampSource::Derived)
                | TimestampFlags::INFERRED,
        )
        .unwrap();
        assert_eq!(Timestamp128::from_le_bytes(timestamp.to_le_bytes()).unwrap(), timestamp);
        assert_eq!(Timestamp128::from_be_bytes(timestamp.to_be_bytes()).unwrap(), timestamp);
    }

    #[test]
    fn ordering_preserves_metadata_after_instant_tie() {
        let left = ForensicTimestamp::try_from_parts(1, 0, None, TimestampFlags::default()).unwrap();
        let right = ForensicTimestamp::try_from_parts(1, 0, Some(60), TimestampFlags::default()).unwrap();
        assert!(left.same_instant(right));
        assert_ne!(left, right);
        assert!(left < right);
    }

    #[test]
    fn system_time_round_trip_handles_times_before_the_unix_epoch() {
        let system_time = UNIX_EPOCH.checked_sub(Duration::from_millis(1)).unwrap();
        let timestamp = ForensicTimestamp::try_from_system_time(system_time).unwrap();
        assert_eq!(timestamp.to_unix_nanos(), -1_000_000);
        assert_eq!(timestamp.to_system_time().unwrap(), system_time);
        assert_eq!(timestamp.flags().source(), TimestampSource::SystemTime);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_preserves_timestamp_metadata() {
        let timestamp = ForensicTimestamp::try_from_parts(
            -1,
            999_999_999,
            Some(-60),
            TimestampFlags::new(TimestampPrecision::Nanoseconds, TimestampSource::ParsedText)
                | TimestampFlags::INFERRED,
        )
        .unwrap();
        let json = serde_json::to_string(&timestamp).unwrap();
        assert!(json.contains("utc_offset_minutes"));
        assert_eq!(serde_json::from_str::<ForensicTimestamp>(&json).unwrap(), timestamp);
    }
}

#[cfg(feature = "serde")]
impl Serialize for ForensicTimestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("ForensicTimestamp", 4)?;
        state.serialize_field("utc_seconds", &self.utc_seconds)?;
        state.serialize_field("nanoseconds", &self.nanoseconds)?;
        state.serialize_field(
            "utc_offset_minutes",
            &self.utc_offset_minutes(),
        )?;
        state.serialize_field("flags", &self.flags.bits())?;
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for ForensicTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct TimestampParts {
            utc_seconds: i64,
            nanoseconds: u32,
            utc_offset_minutes: Option<i16>,
            flags: u16,
        }

        let parts = TimestampParts::deserialize(deserializer)?;
        Self::try_from_parts(
            parts.utc_seconds,
            parts.nanoseconds,
            parts.utc_offset_minutes,
            TimestampFlags::from_bits_retain(parts.flags),
        )
        .map_err(serde::de::Error::custom)
    }
}

impl Default for ForensicTimestamp {
    fn default() -> Self {
        Self::from_parts_unchecked(0, 0, None, TimestampFlags::default())
    }
}