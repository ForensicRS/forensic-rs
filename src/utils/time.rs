use std::{ops::{Add, AddAssign, Sub}, time::{Duration, SystemTime, UNIX_EPOCH}};

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
            year : year as u16,
            month: month as u8,
            day: day as u8,
            hour: hour as u8,
            minute: minute as u8,
            second: second as u8,
            nanos: nanos as u32,
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


/// Converts a Windows filetime to unix timestamp in milliseconds
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

impl From<WinFiletime> for SystemTime {
    fn from(val: WinFiletime) -> Self {
        filetime_to_system_time(val.0)
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
        Some(self.original.cmp(&other.original))
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
    println!("{:?}", time);
}