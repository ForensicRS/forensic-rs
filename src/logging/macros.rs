
/// Logs a message at the error level.
/// ```rust
/// use forensic_rs::error;
/// error!("The artifact {} cannot be parsed", r"C:\Windows\Prefetch\POWERSHELL.EXE-AE8EDC9B.pf")
/// ```
#[macro_export(local_inner_macros)]
macro_rules! error {
    ($($arg:tt)+) => (log!($crate::logging::Level::Error, $($arg)+))
}

/// Logs a message at the warn level.
/// ```rust
/// use forensic_rs::warn;
/// warn!("The artifact {} cannot be parsed", r"C:\Windows\Prefetch\POWERSHELL.EXE-AE8EDC9B.pf")
/// ```
#[macro_export(local_inner_macros)]
macro_rules! warn {
    ($($arg:tt)+) => (log!($crate::logging::Level::Warn, $($arg)+))
}

/// Logs a message at the info level.
/// ```rust
/// use forensic_rs::info;
/// info!("The artifact {} cannot be parsed", r"C:\Windows\Prefetch\POWERSHELL.EXE-AE8EDC9B.pf")
/// ```
#[macro_export(local_inner_macros)]
macro_rules! info {
    ($($arg:tt)+) => (log!($crate::logging::Level::Info, $($arg)+))
}
/// Logs a message at the debug level.
/// ```rust
/// use forensic_rs::debug;
/// debug!("The artifact {} cannot be parsed", r"C:\Windows\Prefetch\POWERSHELL.EXE-AE8EDC9B.pf")
/// ```
#[macro_export(local_inner_macros)]
macro_rules! debug {
    ($($arg:tt)+) => (log!($crate::logging::Level::Debug, $($arg)+))
}
/// Logs a message at the trace level.
/// ```rust
/// use forensic_rs::trace;
/// trace!("The artifact {} cannot be parsed", r"C:\Windows\Prefetch\POWERSHELL.EXE-AE8EDC9B.pf")
/// ```
#[macro_export(local_inner_macros)]
macro_rules! trace {
    ($($arg:tt)+) => (log!($crate::logging::Level::Trace, $($arg)+))
}

/// Logs a message with the desired level
/// ```rust
/// use forensic_rs::log;
/// use forensic_rs::logging::Level;
/// log!(Level::Info, "The artifact {} cannot be parsed", r"C:\Windows\Prefetch\POWERSHELL.EXE-AE8EDC9B.pf")
/// ```
#[macro_export(local_inner_macros)]
macro_rules! log {
    ($lvl:expr, $($arg:tt)+) => ({
        let lvl = $lvl;
        if lvl <= $crate::logging::Level::Trace && lvl <= $crate::logging::max_level() {
            let _ = $crate::logging::COMPONENT_LOGGER.with(|v| {
                let msngr = v.borrow();
                msngr.log(lvl, std::module_path!(), std::file!(), std::line!(), std::borrow::Cow::Owned(std::format!($($arg)+)));
            });
        }
    });
}