use std::{ops::{Add, AddAssign, Sub}, time::{Duration, SystemTime, UNIX_EPOCH}};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize, Serializer, Deserializer};

/// Simplifies handling Windows filetime dates. Use only with UTC dates as it does not take time zones into account. Eliminates the need to use the chrono library.
/// ```rust
/// use forensic_rs::prelude::*;
/// assert_eq!("01-01-1601 00:00:00", format!("{:?}", WinFiletime(0)));
/// assert_eq!("01-01-1605 00:00:00", format!("{:?}", WinFiletime(1262304000000000)));
/// assert_eq!("14-11-1999 18:27:59", format!("{:?}", WinFiletime(125870776790000000)));
/// assert_eq!("14-11-2000 18:27:59.001", format!("{:?}", WinFiletime(126187000790010000)));
/// ```
#[derive(Clone, Default, Copy)]
pub struct WinFiletime(pub u64);


/// Simplifies handling unix timestamp dates. Use only with UTC dates as it does not take time zones into account. Eliminates the need to use the chrono library.
/// 
/// ```rust
/// use forensic_rs::prelude::*;
/// assert_eq!("01-01-1970 00:00:00", format!("{:?}", UnixTimestamp(0)));
/// assert_eq!("01-01-1972 00:00:00", format!("{:?}", UnixTimestamp(63072000000)));
/// ```
#[derive(Clone, Default, Copy)]
pub struct UnixTimestamp(pub u64);

/// Simplifies handling Windows filetime dates. Use only with UTC dates as it does not take time zones into account. Eliminates the need to use the chrono library.
/// Its more complex than WinFiletime and uses more space, but its much faster when getting date parameters like hour,minute,day... as it parses the date when created. 
/// ```rust
/// use forensic_rs::prelude::*;
/// assert_eq!("01-01-1601 00:00:00", format!("{:?}", Filetime::new(0)));
/// assert_eq!("01-01-1605 00:00:00", format!("{:?}", Filetime::new(1262304000000000)));
/// assert_eq!("14-11-1999 18:27:59", format!("{:?}", Filetime::new(125870776790000000)));
/// assert_eq!("14-11-2000 18:27:59.001", format!("{:?}", Filetime::new(126187000790010000)));
/// assert_eq!(2000, Filetime::new(126187000790010000).year());
/// assert_eq!(100, Filetime::new(126187000790000001).nanoseconds());
/// ```
#[derive(Clone, Default, Copy)]
pub struct Filetime {
    original : u64,
    year : u16,
    month : u8,
    day : u8,
    hour : u8,
    minute : u8,
    second : u8,
    nanos : u32
}

impl Filetime {
    /// Makes a new Filetime from windows u64 filetime
    pub fn new(timestap : u64) -> Self {
        let nanoseconds_since_beginning = (timestap as u128) * 100;
        let days_since_beginning = nanoseconds_since_beginning.div_euclid(60 * 60 * 24 * 1_000_000_000);
        let nanoseconds_in_day = nanoseconds_since_beginning - days_since_beginning *60 * 60 * 24 * 1_000_000_000;
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
        let hour = nanoseconds_in_day.div_euclid(60 * 60 * 1_000_000_000);
        let rest_nanos = nanoseconds_in_day - hour * 60*60*1_000_000_000;
        let minute = rest_nanos.div_euclid(60 * 1_000_000_000);
        let rest_nanos = rest_nanos - minute * 60 * 1_000_000_000;
        let second = rest_nanos.div_euclid(1_000_000_000);
        let nanos = rest_nanos - second*1_000_000_000;
        Self {
            original : timestap,
            year,
            month: month as u8,
            day: day as u8,
            hour: hour as u8,
            minute: minute as u8,
            second: second as u8,
            nanos: nanos as u32,
        }
    }
    /// Create a Filetime from a Unix timestamp in seconds (signed, since 1970-01-01 UTC).
    ///
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let ft = Filetime::from_unix_secs(0); // 1970-01-01 00:00:00
    /// assert_eq!(1970, ft.year());
    /// assert_eq!(1, ft.month());
    /// assert_eq!(1, ft.day());
    /// assert_eq!(0, ft.hour());
    /// ```
    pub fn from_unix_secs(secs: i64) -> Self {
        // Offset between Windows FILETIME epoch (1601-01-01) and Unix epoch (1970-01-01)
        // in 100-nanosecond intervals.
        const EPOCH_DIFF: i64 = 116_444_736_000_000_000;
        let filetime = (secs as i128 * 10_000_000 + EPOCH_DIFF as i128).max(0) as u64;
        Self::new(filetime)
    }

    /// Create a Filetime from an OLE Automation date (f64, days since 1899-12-30).
    ///
    /// Used by ESE databases for DateTime columns.
    ///
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// // OLE date 25569.0 = 1970-01-01 (matches Unix epoch)
    /// let ft = Filetime::from_ole_date(25569.0);
    /// assert_eq!(1970, ft.year());
    /// assert_eq!(1, ft.month());
    /// assert_eq!(1, ft.day());
    /// ```
    pub fn from_ole_date(ole_date: f64) -> Self {
        // OLE epoch is 1899-12-30, FILETIME epoch is 1601-01-01.
        // Difference from 1601-01-01 to 1899-12-30 in days = 109_205 days.
        const OLE_EPOCH_FILETIME_DAYS: f64 = 109_205.0;
        let total_days = ole_date + OLE_EPOCH_FILETIME_DAYS;
        // Convert to 100-nanosecond intervals
        let filetime = (total_days * 24.0 * 60.0 * 60.0 * 10_000_000.0).max(0.0) as u64;
        Self::new(filetime)
    }

    /// Make a new Filetime from year, month, day, time components assuming UTC.
    pub fn with_ymd_and_hms(year : u16, month : u8, day : u8, hour : u8, minute : u8, second : u8, nanos : u32 ) -> Self {
        let days_since_begining = days_from_year(year) as u64;
        let days_since_start_year = acumulated_day_month(month, year) as u64;
        let days = days_since_begining + days_since_start_year + day as u64 - 1;
        let original = (nanos as u64 / 100) + ((second as u64 + (60u64 * (minute as u64 + (60u64 * (hour as u64 + 24 * days))))) * 10_000_000u64);
        
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanos,
            original 
        }
    }

    /// Returns the year number 
    /// 
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let time = Filetime::new(125963224790010000); // 29-02-2000 18:27:59.001
    /// assert_eq!(2000, time.year());
    /// ```
    pub fn year(&self) -> u16 {
        self.year
    }
    /// Returns the month number 
    /// 
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let time = Filetime::new(125963224790010000); // 29-02-2000 18:27:59.001
    /// assert_eq!(2, time.month());
    /// ```
    pub fn month(&self) -> u8 {
        self.month
    }
    /// Returns the day number 
    /// 
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let time = Filetime::new(125963224790010000); // 29-02-2000 18:27:59.001
    /// assert_eq!(29, time.day());
    /// ```
    pub fn day(&self) -> u8 {
        self.day
    }
    /// Returns the hour number 
    /// 
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let time = Filetime::new(125963224790010000); // 29-02-2000 18:27:59.001
    /// assert_eq!(18, time.hour());
    /// ```
    pub fn hour(&self) -> u8 {
        self.hour
    }
    /// Returns the minute number 
    /// 
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let time = Filetime::new(125963224790010000); // 29-02-2000 18:27:59.001
    /// assert_eq!(27, time.minute());
    /// ```
    pub fn minute(&self) -> u8 {
        self.minute
    }
    /// Returns the second number 
    /// 
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let time = Filetime::new(125963224790010000); // 29-02-2000 18:27:59.001
    /// assert_eq!(59, time.second());
    /// ```
    pub fn second(&self) -> u8 {
        self.second
    }
    /// Returns the second number 
    /// 
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let time = Filetime::new(125963224790010000); // 29-02-2000 18:27:59.001
    /// assert_eq!(1, time.millis());
    /// ```
    pub fn millis(&self) -> u32 {
        self.nanos / 1_000_000
    }
    /// Returns the nanoseconds number 
    /// 
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let time = Filetime::new(125963224790010000); // 29-02-2000 18:27:59.001
    /// assert_eq!(1000000, time.nanoseconds());
    /// ```
    pub fn nanoseconds(&self) -> u32 {
        self.nanos
    }
    /// Returns the original filetime since 1601
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let time = Filetime::new(125963224790010000); // 29-02-2000 18:27:59.001
    /// assert_eq!(125963224790010000, time.filetime());
    /// ```
    pub fn filetime(&self) -> u64 {
        self.original
    }

    /// Returns the amount of time elapsed from an earlier point in time.
    /// 
    /// This function may fail because measurements taken earlier are not guaranteed to always be before later measurements (due to anomalies such as the system clock being adjusted either forwards or backwards). Instant can be used to measure elapsed time without this risk of failure.
    /// 
    /// If successful, Ok(Duration) is returned where the duration represents the amount of time elapsed from the specified measurement to this one.
    /// 
    /// Returns an Err if earlier is later than self, and the error contains how far from self the time is.
    pub fn duration_since(&self, earlier : SystemTime) -> Result<Duration, Duration> {
        let nano_epoch = earlier.duration_since(UNIX_EPOCH).map_err(|e| e.duration())?;
        let nanos = nano_epoch.as_nanos();
        let self_nanos = self.original as u128 * 100;

        if nanos > self_nanos {
            return Err(Duration::from_nanos((nanos - self_nanos) as u64))
        }
        Ok(Duration::from_nanos((self_nanos - nanos) as u64))
    }
}

impl std::fmt::Debug for Filetime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.nanos == 0 {
            f.write_fmt(format_args!(
                "{:02}-{:02}-{:04} {:02}:{:02}:{:02}", self.day, self.month, self.year, self.hour, self.minute, self.second
            ))
        }else {
            f.write_fmt(format_args!(
                "{:02}-{:02}-{:04} {:02}:{:02}:{:02}.{:03}", self.day, self.month, self.year, self.hour, self.minute, self.second, self.nanos / 1_000_000
            ))
        }
    }
}

impl std::fmt::Display for Filetime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Add<Duration> for Filetime {
    type Output = Filetime;

    fn add(self, rhs: Duration) -> Self::Output {
        let nanos = rhs.as_nanos();
        Self::new(((self.original as u128) * 100 + nanos).div_euclid(100) as u64)
    }
}

impl AddAssign<Duration> for Filetime {
    fn add_assign(&mut self, rhs: Duration) {
        let nanos = rhs.as_nanos();
        let nw = Self::new(((self.original as u128) * 100 + nanos).div_euclid(100) as u64);
        self.hour = nw.hour;
        self.day = nw.day;
        self.minute = nw.minute;
        self.nanos = nw.nanos;
        self.second = nw.second;
        self.year = nw.year;
        self.original = nw.original;
    }
}

impl Sub<Duration> for Filetime {
    type Output = Filetime;

    fn sub(self, rhs: Duration) -> Self::Output {
        let nanos = rhs.as_nanos();
        Self::new(((self.original as u128) * 100 - nanos).div_euclid(100) as u64)
    }
}

// ============================================================================
// ForensicTimestamp — bitpacked u64, microsecond precision
// ============================================================================

/// A compact, format-agnostic timestamp with microsecond precision.
///
/// Stored as a single `u64` using bitpacking:
///
/// | Field   | Bits  | Width | Range       |
/// |---------|-------|-------|-------------|
/// | year    | 63–52 | 12    | 0–4095      |
/// | month   | 51–48 | 4     | 1–12        |
/// | day     | 47–43 | 5     | 1–31        |
/// | hour    | 42–38 | 5     | 0–23        |
/// | minute  | 37–32 | 6     | 0–59        |
/// | second  | 31–26 | 6     | 0–59        |
/// | micros  | 25–4  | 22    | 0–999,999   |
/// | reserved| 3–0   | 4     | 0           |
///
/// Supports construction from Windows FILETIME, Unix timestamps, OLE dates,
/// WebKit timestamps, HFS+ timestamps, and Cocoa timestamps.
///
/// ```rust
/// use forensic_rs::prelude::*;
/// assert_eq!(8, std::mem::size_of::<ForensicTimestamp>());
///
/// let ts = ForensicTimestamp::with_ymd_and_hms(2024, 2, 3, 14, 10, 23, 596_000);
/// assert_eq!(2024, ts.year());
/// assert_eq!(2, ts.month());
/// assert_eq!(3, ts.day());
/// assert_eq!(14, ts.hour());
/// assert_eq!(10, ts.minute());
/// assert_eq!(23, ts.second());
/// assert_eq!(596_000, ts.microseconds());
/// assert_eq!(596, ts.milliseconds());
/// ```
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ForensicTimestamp(u64);

// Bit layout constants
const YEAR_SHIFT: u32 = 52;
const MONTH_SHIFT: u32 = 48;
const DAY_SHIFT: u32 = 43;
const HOUR_SHIFT: u32 = 38;
const MINUTE_SHIFT: u32 = 32;
const SECOND_SHIFT: u32 = 26;
const MICROS_SHIFT: u32 = 4;

const YEAR_MASK: u64 = 0xFFF; // 12 bits
const MONTH_MASK: u64 = 0xF;  // 4 bits
const DAY_MASK: u64 = 0x1F;   // 5 bits
const HOUR_MASK: u64 = 0x1F;  // 5 bits
const MINUTE_MASK: u64 = 0x3F; // 6 bits
const SECOND_MASK: u64 = 0x3F; // 6 bits
const MICROS_MASK: u64 = 0x3FFFFF; // 22 bits

/// Offset between Windows FILETIME epoch (1601-01-01) and Unix epoch (1970-01-01) in microseconds.
const WIN_EPOCH_UNIX_OFFSET_MICROS: i128 = 11_644_473_600_000_000;

/// Offset between HFS+ epoch (1904-01-01) and Unix epoch (1970-01-01) in seconds.
const HFS_EPOCH_UNIX_OFFSET_SECS: i64 = 2_082_844_800;

/// Offset between Cocoa epoch (2001-01-01) and Unix epoch (1970-01-01) in seconds.
const COCOA_EPOCH_UNIX_OFFSET_SECS: i64 = 978_307_200;

/// OLE epoch is 1899-12-30. Offset from Unix epoch in days.
const OLE_EPOCH_UNIX_OFFSET_DAYS: f64 = 25_569.0;

#[inline]
fn pack_forensic_ts(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8, micros: u32) -> u64 {
    ((year as u64 & YEAR_MASK) << YEAR_SHIFT)
        | ((month as u64 & MONTH_MASK) << MONTH_SHIFT)
        | ((day as u64 & DAY_MASK) << DAY_SHIFT)
        | ((hour as u64 & HOUR_MASK) << HOUR_SHIFT)
        | ((minute as u64 & MINUTE_MASK) << MINUTE_SHIFT)
        | ((second as u64 & SECOND_MASK) << SECOND_SHIFT)
        | ((micros as u64 & MICROS_MASK) << MICROS_SHIFT)
}

/// Break total microseconds since Unix epoch into date/time components and pack.
fn forensic_ts_from_unix_micros(unix_micros: i64) -> ForensicTimestamp {
    // Convert to microseconds since 1601-01-01 to reuse the existing calendar logic
    let win_micros = unix_micros as i128 + WIN_EPOCH_UNIX_OFFSET_MICROS;
    if win_micros < 0 {
        return ForensicTimestamp(0);
    }
    let total_micros = win_micros as u128;
    let total_seconds = total_micros / 1_000_000;
    let sub_second_micros = (total_micros % 1_000_000) as u32;

    let total_days = total_seconds / 86_400;
    let seconds_in_day = total_seconds % 86_400;

    let (year, remaining_days) = to_years(total_days);
    let (month, acum) = month_and_acum(year, remaining_days);
    let day = (remaining_days - acum as u128) + 1;

    let hour = seconds_in_day / 3600;
    let rest = seconds_in_day % 3600;
    let minute = rest / 60;
    let second = rest % 60;

    ForensicTimestamp(pack_forensic_ts(
        year, month as u8, day as u8,
        hour as u8, minute as u8, second as u8,
        sub_second_micros,
    ))
}

/// Resolve month and accumulated-day-in-month from year and remaining days in year.
fn month_and_acum(year: u16, remaining_days: u128) -> (usize, usize) {
    if is_leap_year(year) {
        let days = [0u128, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335];
        days.iter()
            .position(|&v| v > remaining_days)
            .map(|pos| (pos, days[pos - 1] as usize))
            .unwrap_or((12, 335))
    } else {
        let days = [0u128, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
        days.iter()
            .position(|&v| v > remaining_days)
            .map(|pos| (pos, days[pos - 1] as usize))
            .unwrap_or((12, 334))
    }
}

impl ForensicTimestamp {
    /// Create a timestamp from explicit date/time components.
    ///
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let ts = ForensicTimestamp::with_ymd_and_hms(2000, 2, 29, 18, 27, 59, 1_000);
    /// assert_eq!(2000, ts.year());
    /// assert_eq!(2, ts.month());
    /// assert_eq!(29, ts.day());
    /// assert_eq!(18, ts.hour());
    /// assert_eq!(27, ts.minute());
    /// assert_eq!(59, ts.second());
    /// assert_eq!(1_000, ts.microseconds());
    /// ```
    pub fn with_ymd_and_hms(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8, micros: u32) -> Self {
        Self(pack_forensic_ts(year, month, day, hour, minute, second, micros))
    }

    /// Create from a Windows FILETIME value (100-nanosecond intervals since 1601-01-01 UTC).
    ///
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let ts = ForensicTimestamp::from_win_filetime(133514430235959706);
    /// assert_eq!(2024, ts.year());
    /// assert_eq!(2, ts.month());
    /// assert_eq!(3, ts.day());
    /// assert_eq!(14, ts.hour());
    /// assert_eq!(10, ts.minute());
    /// assert_eq!(23, ts.second());
    /// ```
    pub fn from_win_filetime(filetime: u64) -> Self {
        // Convert 100ns intervals to microseconds, then to Unix-epoch microseconds
        let win_micros = filetime as i128 / 10;
        let unix_micros = win_micros - WIN_EPOCH_UNIX_OFFSET_MICROS;
        forensic_ts_from_unix_micros(unix_micros as i64)
    }

    /// Create from a Unix timestamp in seconds since 1970-01-01 UTC.
    ///
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let ts = ForensicTimestamp::from_unix_secs(0);
    /// assert_eq!(1970, ts.year());
    /// assert_eq!(1, ts.month());
    /// assert_eq!(1, ts.day());
    /// ```
    pub fn from_unix_secs(secs: i64) -> Self {
        forensic_ts_from_unix_micros(secs.saturating_mul(1_000_000))
    }

    /// Create from a Unix timestamp in milliseconds since 1970-01-01 UTC.
    ///
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let ts = ForensicTimestamp::from_unix_millis(1706969423596);
    /// assert_eq!(2024, ts.year());
    /// assert_eq!(2, ts.month());
    /// assert_eq!(3, ts.day());
    /// assert_eq!(596, ts.milliseconds());
    /// ```
    pub fn from_unix_millis(millis: i64) -> Self {
        forensic_ts_from_unix_micros(millis.saturating_mul(1_000))
    }

    /// Create from a Unix timestamp in microseconds since 1970-01-01 UTC.
    ///
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let ts = ForensicTimestamp::from_unix_micros(1706969423596000);
    /// assert_eq!(2024, ts.year());
    /// assert_eq!(596_000, ts.microseconds());
    /// ```
    pub fn from_unix_micros(micros: i64) -> Self {
        forensic_ts_from_unix_micros(micros)
    }

    /// Create from an OLE Automation date (f64, days since 1899-12-30).
    ///
    /// Used by ESE databases for DateTime columns.
    ///
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let ts = ForensicTimestamp::from_ole_date(25569.0); // 1970-01-01
    /// assert_eq!(1970, ts.year());
    /// assert_eq!(1, ts.month());
    /// assert_eq!(1, ts.day());
    /// ```
    pub fn from_ole_date(ole_date: f64) -> Self {
        let unix_days = ole_date - OLE_EPOCH_UNIX_OFFSET_DAYS;
        let unix_micros = (unix_days * 86_400.0 * 1_000_000.0) as i64;
        forensic_ts_from_unix_micros(unix_micros)
    }

    /// Create from a WebKit/Chrome timestamp (microseconds since 1601-01-01 UTC).
    ///
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let ts = ForensicTimestamp::from_webkit(13351443023595970);
    /// assert_eq!(2024, ts.year());
    /// assert_eq!(2, ts.month());
    /// assert_eq!(3, ts.day());
    /// ```
    pub fn from_webkit(webkit_micros: i64) -> Self {
        let unix_micros = webkit_micros - WIN_EPOCH_UNIX_OFFSET_MICROS as i64;
        forensic_ts_from_unix_micros(unix_micros)
    }

    /// Create from a macOS HFS+ timestamp (seconds since 1904-01-01 UTC).
    ///
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let ts = ForensicTimestamp::from_hfs_plus(3_789_814_223); // 2024-02-03 14:10:23
    /// assert_eq!(2024, ts.year());
    /// assert_eq!(2, ts.month());
    /// assert_eq!(3, ts.day());
    /// ```
    pub fn from_hfs_plus(hfs_secs: u32) -> Self {
        let unix_secs = hfs_secs as i64 - HFS_EPOCH_UNIX_OFFSET_SECS;
        forensic_ts_from_unix_micros(unix_secs.saturating_mul(1_000_000))
    }

    /// Create from a macOS/iOS Cocoa (Core Data) timestamp (seconds since 2001-01-01 UTC).
    ///
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let ts = ForensicTimestamp::from_cocoa(728_662_223.0); // 2024-02-03 14:10:23
    /// assert_eq!(2024, ts.year());
    /// assert_eq!(2, ts.month());
    /// assert_eq!(3, ts.day());
    /// ```
    pub fn from_cocoa(cocoa_secs: f64) -> Self {
        let unix_secs = cocoa_secs + COCOA_EPOCH_UNIX_OFFSET_SECS as f64;
        let unix_micros = (unix_secs * 1_000_000.0) as i64;
        forensic_ts_from_unix_micros(unix_micros)
    }

    // ========================= Accessors =========================

    /// Returns the year (0–4095).
    #[inline]
    pub fn year(&self) -> u16 {
        ((self.0 >> YEAR_SHIFT) & YEAR_MASK) as u16
    }

    /// Returns the month (1–12).
    #[inline]
    pub fn month(&self) -> u8 {
        ((self.0 >> MONTH_SHIFT) & MONTH_MASK) as u8
    }

    /// Returns the day of month (1–31).
    #[inline]
    pub fn day(&self) -> u8 {
        ((self.0 >> DAY_SHIFT) & DAY_MASK) as u8
    }

    /// Returns the hour (0–23).
    #[inline]
    pub fn hour(&self) -> u8 {
        ((self.0 >> HOUR_SHIFT) & HOUR_MASK) as u8
    }

    /// Returns the minute (0–59).
    #[inline]
    pub fn minute(&self) -> u8 {
        ((self.0 >> MINUTE_SHIFT) & MINUTE_MASK) as u8
    }

    /// Returns the second (0–59).
    #[inline]
    pub fn second(&self) -> u8 {
        ((self.0 >> SECOND_SHIFT) & SECOND_MASK) as u8
    }

    /// Returns the microseconds component (0–999,999).
    #[inline]
    pub fn microseconds(&self) -> u32 {
        ((self.0 >> MICROS_SHIFT) & MICROS_MASK) as u32
    }

    /// Returns the milliseconds component (0–999), truncating microseconds.
    #[inline]
    pub fn milliseconds(&self) -> u32 {
        self.microseconds() / 1_000
    }

    // ========================= Output conversions =========================

    /// Convert to Unix timestamp in seconds since 1970-01-01 UTC.
    pub fn to_unix_secs(&self) -> i64 {
        self.to_unix_micros() / 1_000_000
    }

    /// Convert to Unix timestamp in milliseconds since 1970-01-01 UTC.
    pub fn to_unix_millis(&self) -> i64 {
        self.to_unix_micros() / 1_000
    }

    /// Convert to Unix timestamp in microseconds since 1970-01-01 UTC.
    pub fn to_unix_micros(&self) -> i64 {
        let year = self.year();
        let month = self.month();
        let day = self.day();

        // Days from 1601-01-01 to start of this year
        let days_to_year = days_from_year(year) as i128;
        // Days from start of year to start of this month
        let days_to_month = acumulated_day_month(month, year) as i128;
        // Total days from 1601-01-01
        let total_days = days_to_year + days_to_month + (day as i128 - 1);

        // Total seconds from 1601-01-01
        let total_secs = total_days * 86_400
            + self.hour() as i128 * 3600
            + self.minute() as i128 * 60
            + self.second() as i128;

        // Total microseconds from 1601-01-01
        let total_micros = total_secs * 1_000_000 + self.microseconds() as i128;

        // Subtract epoch offset to get Unix microseconds
        (total_micros - WIN_EPOCH_UNIX_OFFSET_MICROS) as i64
    }

    /// Convert to a Windows FILETIME value (100-nanosecond intervals since 1601-01-01 UTC).
    pub fn to_win_filetime(&self) -> u64 {
        let unix_micros = self.to_unix_micros() as i128;
        let win_micros = unix_micros + WIN_EPOCH_UNIX_OFFSET_MICROS;
        // Convert microseconds to 100ns intervals
        (win_micros * 10).max(0) as u64
    }
}

impl std::fmt::Debug for ForensicTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let micros = self.microseconds();
        if micros == 0 {
            write!(f, "{:02}-{:02}-{:04} {:02}:{:02}:{:02}",
                self.day(), self.month(), self.year(),
                self.hour(), self.minute(), self.second())
        } else {
            write!(f, "{:02}-{:02}-{:04} {:02}:{:02}:{:02}.{:03}",
                self.day(), self.month(), self.year(),
                self.hour(), self.minute(), self.second(),
                micros / 1_000)
        }
    }
}

impl std::fmt::Display for ForensicTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl PartialOrd for ForensicTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ForensicTimestamp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Bit layout has year as MSB, so raw u64 comparison gives chronological order
        self.0.cmp(&other.0)
    }
}

impl Add<Duration> for ForensicTimestamp {
    type Output = ForensicTimestamp;

    fn add(self, rhs: Duration) -> Self::Output {
        let micros = self.to_unix_micros().saturating_add(rhs.as_micros() as i64);
        forensic_ts_from_unix_micros(micros)
    }
}

impl Sub<Duration> for ForensicTimestamp {
    type Output = ForensicTimestamp;

    fn sub(self, rhs: Duration) -> Self::Output {
        let micros = self.to_unix_micros().saturating_sub(rhs.as_micros() as i64);
        forensic_ts_from_unix_micros(micros)
    }
}

impl From<Filetime> for ForensicTimestamp {
    fn from(ft: Filetime) -> Self {
        Self::with_ymd_and_hms(
            ft.year(), ft.month(), ft.day(),
            ft.hour(), ft.minute(), ft.second(),
            ft.nanoseconds() / 1_000, // nanoseconds → microseconds
        )
    }
}

impl From<ForensicTimestamp> for Filetime {
    fn from(ts: ForensicTimestamp) -> Self {
        Filetime::with_ymd_and_hms(
            ts.year(), ts.month(), ts.day(),
            ts.hour(), ts.minute(), ts.second(),
            ts.microseconds() * 1_000, // microseconds → nanoseconds
        )
    }
}

impl From<ForensicTimestamp> for SystemTime {
    fn from(ts: ForensicTimestamp) -> Self {
        let unix_micros = ts.to_unix_micros();
        if unix_micros >= 0 {
            UNIX_EPOCH + Duration::from_micros(unix_micros as u64)
        } else {
            UNIX_EPOCH - Duration::from_micros((-unix_micros) as u64)
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for ForensicTimestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for ForensicTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        // Parse "DD-MM-YYYY HH:MM:SS" or "DD-MM-YYYY HH:MM:SS.mmm"
        let parts: Vec<&str> = s.split(' ').collect();
        if parts.len() != 2 {
            return Err(serde::de::Error::custom("expected 'DD-MM-YYYY HH:MM:SS[.mmm]'"));
        }
        let date_parts: Vec<&str> = parts[0].split('-').collect();
        if date_parts.len() != 3 {
            return Err(serde::de::Error::custom("expected 'DD-MM-YYYY'"));
        }
        let day: u8 = date_parts[0].parse().map_err(serde::de::Error::custom)?;
        let month: u8 = date_parts[1].parse().map_err(serde::de::Error::custom)?;
        let year: u16 = date_parts[2].parse().map_err(serde::de::Error::custom)?;

        let time_and_millis: Vec<&str> = parts[1].split('.').collect();
        let time_parts: Vec<&str> = time_and_millis[0].split(':').collect();
        if time_parts.len() != 3 {
            return Err(serde::de::Error::custom("expected 'HH:MM:SS'"));
        }
        let hour: u8 = time_parts[0].parse().map_err(serde::de::Error::custom)?;
        let minute: u8 = time_parts[1].parse().map_err(serde::de::Error::custom)?;
        let second: u8 = time_parts[2].parse().map_err(serde::de::Error::custom)?;
        let millis: u32 = if time_and_millis.len() > 1 {
            time_and_millis[1].parse().map_err(serde::de::Error::custom)?
        } else {
            0
        };

        Ok(ForensicTimestamp::with_ymd_and_hms(year, month, day, hour, minute, second, millis * 1_000))
    }
}



///
/// ```rust
/// use forensic_rs::utils::time::filetime_to_unix_timestamp;
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
/// use forensic_rs::utils::time::filetime_to_system_time;
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

fn acumulated_day_month(month : u8, year : u16) -> u16 {
    if is_leap_year(year) {
        if month >= 12 {
            return 366u16
        }
        [0,0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335][month as usize]
    } else {
        if month >= 12 {
            return 365u16
        }
        [0,0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334][month as usize]
    }
}

fn is_leap_year(year: u16) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || (year.is_multiple_of(100) && year.is_multiple_of(400))
}
fn to_years(mut days : u128) -> (u16, u128) {
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
fn days_from_year(year : u16) -> u128 {
    let mut days = 0;
    if year <= 1601 {
        return 0
    }
    for yr in 1601..year {
        if is_leap_year(yr) {
            days += 1;
        }
        days += 365;
    }
    days
}
fn to_years_unix(mut days : u128) -> (u16, u128) {
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

impl From<WinFiletime> for SystemTime {
    fn from(val: WinFiletime) -> Self {
        filetime_to_system_time(val.0)
    }
}
impl From<&WinFiletime> for SystemTime {
    fn from(val: &WinFiletime) -> Self {
        filetime_to_system_time(val.0)
    }
}
impl From<Filetime> for SystemTime {
    fn from(val: Filetime) -> Self {
        filetime_to_system_time(val.original)
    }
}
impl From<&Filetime> for SystemTime {
    fn from(val: &Filetime) -> Self {
        filetime_to_system_time(val.original)
    }
}

impl WinFiletime {
    pub fn new() -> Self {
        Self(0)
    }

    /// Returns the year number 
    /// 
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let time = WinFiletime(125963224790010000); // 29-02-2000 18:27:59.001
    /// assert_eq!(2000, time.year());
    /// ```
    pub fn year(&self) -> u32 {
        let milliseconds_since_beginning = (self.0 as u128).div_euclid(10_000u128);
        let days_since_beginning = milliseconds_since_beginning.div_euclid(60 * 60 * 24 * 1000);
        let (year, _) = to_years(days_since_beginning);
        year as u32
    }

    /// Returns the month number starting from 1
    /// 
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let time = WinFiletime(125963224790010000); // 29-02-2000 18:27:59.001
    /// assert_eq!(2, time.month());
    /// ```
    pub fn month(&self) -> u32 {
        let milliseconds_since_beginning = (self.0 as u128).div_euclid(10_000u128);
        let days_since_beginning = milliseconds_since_beginning.div_euclid(60 * 60 * 24 * 1000);
        let (year, restant_days) = to_years(days_since_beginning);
        let (month, _acumulated_day_month) = if is_leap_year(year) {
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
        month as u32
    }

    /// Returns the day of month starting from 1
    /// 
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let time = WinFiletime(125963224790010000); // 29-02-2000 18:27:59.001
    /// assert_eq!(29, time.day());
    /// ```
    pub fn day(&self) -> u32 {
        let milliseconds_since_beginning = (self.0 as u128).div_euclid(10_000u128);
        let days_since_beginning = milliseconds_since_beginning.div_euclid(60 * 60 * 24 * 1000);
        let (year, restant_days) = to_years(days_since_beginning);
        let (_month, acumulated_day_month) = if is_leap_year(year) {
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
        day as u32
    }

    /// Returns the hour number from 0 to 23.
    /// 
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let time = WinFiletime(125963224790010000); // 29-02-2000 18:27:59.001
    /// assert_eq!(18, time.hour());
    /// ```
    pub fn hour(&self) -> u32 {
        let milliseconds_since_beginning = (self.0 as u128).div_euclid(10_000u128);
        let days_since_beginning = milliseconds_since_beginning.div_euclid(60 * 60 * 24 * 1000);
        let milliseconds_in_day = milliseconds_since_beginning - days_since_beginning *60 * 60 * 24 * 1000;
        let hours = milliseconds_in_day.div_euclid(60 * 60 * 1000);
        hours as u32
    }

    /// Returns the minute number from 0 to 59.
    /// 
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let time = WinFiletime(125963224790010000); // 29-02-2000 18:27:59.001
    /// assert_eq!(27, time.minute());
    /// ```
    pub fn minute(&self) -> u32 {
        let milliseconds_since_beginning = (self.0 as u128).div_euclid(10_000u128);
        let days_since_beginning = milliseconds_since_beginning.div_euclid(60 * 60 * 24 * 1000);
        let milliseconds_in_day = milliseconds_since_beginning - days_since_beginning *60 * 60 * 24 * 1000;
        let hours = milliseconds_in_day.div_euclid(60 * 60 * 1000);
        let rest_millis = milliseconds_in_day - hours * 60*60*1000;
        let minute = rest_millis.div_euclid(60 * 1000);
        minute as u32
    }
    /// Returns the second number from 0 to 59.
    /// 
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let time = WinFiletime(125963224790010000); // 29-02-2000 18:27:59.001
    /// assert_eq!(59, time.second());
    /// ```
    pub fn second(&self) -> u32 {
        let milliseconds_since_beginning = (self.0 as u128).div_euclid(10_000u128);
        let days_since_beginning = milliseconds_since_beginning.div_euclid(60 * 60 * 24 * 1000);
        let milliseconds_in_day = milliseconds_since_beginning - days_since_beginning *60 * 60 * 24 * 1000;
        let hours = milliseconds_in_day.div_euclid(60 * 60 * 1000);
        let rest_millis = milliseconds_in_day - hours * 60*60*1000;
        let minute = rest_millis.div_euclid(60 * 1000);
        let rest_millis = rest_millis - minute * 60 * 1000;
        let seconds = rest_millis.div_euclid(1000);
        seconds as u32
    }
    /// Obtain the millisecond part
    /// 
    /// ```rust
    /// use forensic_rs::prelude::*;
    /// let time = WinFiletime(125963224790010000); // 29-02-2000 18:27:59.001
    /// assert_eq!(1, time.milliseconds());
    /// ```
    pub fn milliseconds(&self) -> u32 {
        let milliseconds_since_beginning = (self.0 as u128).div_euclid(10_000u128);
        let days_since_beginning = milliseconds_since_beginning.div_euclid(60 * 60 * 24 * 1000);
        let milliseconds_in_day = milliseconds_since_beginning - days_since_beginning *60 * 60 * 24 * 1000;
        let hours = milliseconds_in_day.div_euclid(60 * 60 * 1000);
        let rest_millis = milliseconds_in_day - hours * 60*60*1000;
        let minute = rest_millis.div_euclid(60 * 1000);
        let rest_millis = rest_millis - minute * 60 * 1000;
        let seconds = rest_millis.div_euclid(1000);
        let millis = rest_millis - seconds*1000;
        millis as u32
    }
    
}

impl PartialEq for Filetime {
    fn eq(&self, other: &Self) -> bool {
        self.original == other.original
    }
}
impl Eq for Filetime {}

impl PartialOrd for Filetime {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Filetime {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.original.cmp(&other.original)
    }
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

    let time = WinFiletime(125963224790010000);
    assert_eq!(29, time.day());
    assert_eq!(2, time.month());
    assert_eq!(2000, time.year());
    assert_eq!(18, time.hour());
    assert_eq!(27, time.minute());
    assert_eq!(59, time.second());
    assert_eq!(1, time.milliseconds());
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

#[test]
fn should_generate_valid_filetime() {
    let time = Filetime::new(125963224790010000);
    assert_eq!("29-02-2000 18:27:59.001", &format!("{}", time));
    assert_eq!(time, Filetime::with_ymd_and_hms(2000, 2, 29, 18, 27, 59, 1000000));
    let time = Filetime::new(94405624790010000);
    assert_eq!(time, Filetime::with_ymd_and_hms(1900, 2, 28, 18, 27, 59, 1000000));
    assert_eq!("28-02-1900 18:27:59.001", format!("{}", time));
}

// ============================================================================
// ForensicTimestamp tests
// ============================================================================

#[test]
fn forensic_timestamp_size_is_8_bytes() {
    assert_eq!(8, std::mem::size_of::<ForensicTimestamp>());
}

#[test]
fn forensic_timestamp_pack_unpack_roundtrip() {
    let ts = ForensicTimestamp::with_ymd_and_hms(2024, 2, 3, 14, 10, 23, 596_000);
    assert_eq!(2024, ts.year());
    assert_eq!(2, ts.month());
    assert_eq!(3, ts.day());
    assert_eq!(14, ts.hour());
    assert_eq!(10, ts.minute());
    assert_eq!(23, ts.second());
    assert_eq!(596_000, ts.microseconds());
    assert_eq!(596, ts.milliseconds());
}

#[test]
fn forensic_timestamp_from_win_filetime() {
    // 133514430235959706 = 2024-02-03 14:10:23.595 (known FILETIME)
    let ts = ForensicTimestamp::from_win_filetime(133514430235959706);
    assert_eq!(2024, ts.year());
    assert_eq!(2, ts.month());
    assert_eq!(3, ts.day());
    assert_eq!(14, ts.hour());
    assert_eq!(10, ts.minute());
    assert_eq!(23, ts.second());
    assert_eq!(595, ts.milliseconds());
}

#[test]
fn forensic_timestamp_from_win_filetime_epoch() {
    let ts = ForensicTimestamp::from_win_filetime(0);
    assert_eq!(1601, ts.year());
    assert_eq!(1, ts.month());
    assert_eq!(1, ts.day());
}

#[test]
fn forensic_timestamp_from_unix_secs() {
    let ts = ForensicTimestamp::from_unix_secs(0);
    assert_eq!(1970, ts.year());
    assert_eq!(1, ts.month());
    assert_eq!(1, ts.day());
    assert_eq!(0, ts.hour());

    // 1706969423 = 2024-02-03 14:10:23
    let ts = ForensicTimestamp::from_unix_secs(1706969423);
    assert_eq!(2024, ts.year());
    assert_eq!(2, ts.month());
    assert_eq!(3, ts.day());
    assert_eq!(14, ts.hour());
    assert_eq!(10, ts.minute());
    assert_eq!(23, ts.second());
}

#[test]
fn forensic_timestamp_from_unix_millis() {
    let ts = ForensicTimestamp::from_unix_millis(1706969423596);
    assert_eq!(2024, ts.year());
    assert_eq!(2, ts.month());
    assert_eq!(3, ts.day());
    assert_eq!(596, ts.milliseconds());
    assert_eq!(596_000, ts.microseconds());
}

#[test]
fn forensic_timestamp_from_unix_micros() {
    let ts = ForensicTimestamp::from_unix_micros(1706969423596123);
    assert_eq!(2024, ts.year());
    assert_eq!(596_123, ts.microseconds());
}

#[test]
fn forensic_timestamp_from_ole_date() {
    // OLE 25569.0 = 1970-01-01
    let ts = ForensicTimestamp::from_ole_date(25569.0);
    assert_eq!(1970, ts.year());
    assert_eq!(1, ts.month());
    assert_eq!(1, ts.day());

    // OLE 0.0 = 1899-12-30
    let ts = ForensicTimestamp::from_ole_date(0.0);
    assert_eq!(1899, ts.year());
    assert_eq!(12, ts.month());
    assert_eq!(30, ts.day());
}

#[test]
fn forensic_timestamp_from_webkit() {
    // WebKit uses microseconds since 1601-01-01
    // 13351443023595970 µs from 1601 = 2024-02-03 14:10:23.595
    let ts = ForensicTimestamp::from_webkit(13351443023595970);
    assert_eq!(2024, ts.year());
    assert_eq!(2, ts.month());
    assert_eq!(3, ts.day());
    assert_eq!(14, ts.hour());
    assert_eq!(10, ts.minute());
    assert_eq!(23, ts.second());
}

#[test]
fn forensic_timestamp_from_hfs_plus() {
    // HFS+ epoch is 1904-01-01
    // 3789814223 seconds from 1904-01-01 = 2024-02-03 14:10:23
    let ts = ForensicTimestamp::from_hfs_plus(3_789_814_223);
    assert_eq!(2024, ts.year());
    assert_eq!(2, ts.month());
    assert_eq!(3, ts.day());
    assert_eq!(14, ts.hour());
    assert_eq!(10, ts.minute());
    assert_eq!(23, ts.second());
}

#[test]
fn forensic_timestamp_from_cocoa() {
    // Cocoa epoch is 2001-01-01
    // 728662223.0 seconds from 2001-01-01 = 2024-02-03 14:10:23
    let ts = ForensicTimestamp::from_cocoa(728_662_223.0);
    assert_eq!(2024, ts.year());
    assert_eq!(2, ts.month());
    assert_eq!(3, ts.day());
    assert_eq!(14, ts.hour());
    assert_eq!(10, ts.minute());
    assert_eq!(23, ts.second());
}

#[test]
fn forensic_timestamp_output_conversions() {
    let ts = ForensicTimestamp::from_unix_secs(1706969423);
    assert_eq!(1706969423, ts.to_unix_secs());

    let ts = ForensicTimestamp::from_unix_millis(1706969423596);
    assert_eq!(1706969423596, ts.to_unix_millis());

    let ts = ForensicTimestamp::from_unix_micros(1706969423596123);
    assert_eq!(1706969423596123, ts.to_unix_micros());
}

#[test]
fn forensic_timestamp_win_filetime_roundtrip() {
    // Small precision loss is expected (100ns → µs), so we compare within ±5 ticks
    let original: u64 = 133514430235959706;
    let ts = ForensicTimestamp::from_win_filetime(original);
    let back = ts.to_win_filetime();
    assert!((original as i64 - back as i64).unsigned_abs() < 10,
        "expected ~{}, got {}", original, back);
}

#[test]
fn forensic_timestamp_display() {
    let ts = ForensicTimestamp::with_ymd_and_hms(2024, 2, 3, 14, 10, 23, 596_000);
    assert_eq!("03-02-2024 14:10:23.596", format!("{}", ts));

    let ts = ForensicTimestamp::with_ymd_and_hms(2024, 2, 3, 14, 10, 23, 0);
    assert_eq!("03-02-2024 14:10:23", format!("{}", ts));
}

#[test]
fn forensic_timestamp_ordering() {
    let t1 = ForensicTimestamp::with_ymd_and_hms(2023, 1, 1, 0, 0, 0, 0);
    let t2 = ForensicTimestamp::with_ymd_and_hms(2024, 1, 1, 0, 0, 0, 0);
    let t3 = ForensicTimestamp::with_ymd_and_hms(2024, 1, 1, 0, 0, 0, 1);
    assert!(t1 < t2);
    assert!(t2 < t3);
    assert_eq!(t1, t1);
}

#[test]
fn forensic_timestamp_arithmetic() {
    let ts = ForensicTimestamp::with_ymd_and_hms(2024, 1, 1, 0, 0, 0, 0);

    let plus_one_hour = ts + Duration::from_secs(3600);
    assert_eq!(1, plus_one_hour.hour());

    let minus_one_day = ts - Duration::from_secs(86400);
    assert_eq!(2023, minus_one_day.year());
    assert_eq!(12, minus_one_day.month());
    assert_eq!(31, minus_one_day.day());
}

#[test]
fn forensic_timestamp_leap_year() {
    // 2000 is a leap year
    let ts = ForensicTimestamp::with_ymd_and_hms(2000, 2, 29, 18, 27, 59, 1_000);
    assert_eq!("29-02-2000 18:27:59.001", format!("{}", ts));

    // 1900 is NOT a leap year
    let ts = ForensicTimestamp::with_ymd_and_hms(1900, 2, 28, 18, 27, 59, 1_000);
    assert_eq!("28-02-1900 18:27:59.001", format!("{}", ts));
}

#[test]
fn forensic_timestamp_from_filetime_conversion() {
    let ft = Filetime::new(125963224790010000); // 29-02-2000 18:27:59.001
    let ts: ForensicTimestamp = ft.into();
    assert_eq!(2000, ts.year());
    assert_eq!(2, ts.month());
    assert_eq!(29, ts.day());
    assert_eq!(18, ts.hour());
    assert_eq!(27, ts.minute());
    assert_eq!(59, ts.second());
    assert_eq!(1, ts.milliseconds());

    // Round-trip back to Filetime
    let ft_back: Filetime = ts.into();
    assert_eq!(ft.year(), ft_back.year());
    assert_eq!(ft.month(), ft_back.month());
    assert_eq!(ft.day(), ft_back.day());
    assert_eq!(ft.hour(), ft_back.hour());
    assert_eq!(ft.minute(), ft_back.minute());
    assert_eq!(ft.second(), ft_back.second());
}

#[test]
fn forensic_timestamp_edge_cases() {
    // Epoch of 1601 (Windows)
    let ts = ForensicTimestamp::with_ymd_and_hms(1601, 1, 1, 0, 0, 0, 0);
    assert_eq!("01-01-1601 00:00:00", format!("{}", ts));

    // Maximum year
    let ts = ForensicTimestamp::with_ymd_and_hms(4095, 12, 31, 23, 59, 59, 999_999);
    assert_eq!(4095, ts.year());
    assert_eq!(12, ts.month());
    assert_eq!(31, ts.day());
    assert_eq!(23, ts.hour());
    assert_eq!(59, ts.minute());
    assert_eq!(59, ts.second());
    assert_eq!(999_999, ts.microseconds());
}