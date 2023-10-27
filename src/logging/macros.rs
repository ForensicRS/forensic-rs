#[macro_export(local_inner_macros)]
macro_rules! error {
    // error!("a {} event", "log")
    ($($arg:tt)+) => (log!($crate::logging::LogLevel::Error, $($arg)+))
}

#[macro_export(local_inner_macros)]
macro_rules! warn {
    // warn!("a {} event", "log")
    ($($arg:tt)+) => (log!($crate::logging::LogLevel::Warn, $($arg)+))
}

#[macro_export(local_inner_macros)]
macro_rules! info {
    // info!("a {} event", "log")
    ($($arg:tt)+) => (log!($crate::logging::LogLevel::Info, $($arg)+))
}

#[macro_export(local_inner_macros)]
macro_rules! debug {
    // debug!("a {} event", "log")
    ($($arg:tt)+) => (log!($crate::logging::LogLevel::Debug, $($arg)+))
}

#[macro_export(local_inner_macros)]
macro_rules! trace {
    // trace!("a {} event", "log")
    ($($arg:tt)+) => (log!($crate::logging::LogLevel::Trace, $($arg)+))
}

#[macro_export(local_inner_macros)]
macro_rules! log {
    // log!( Level::Info; "a {} event", "log");
    ($lvl:expr, $($arg:tt)+) => ({
        let lvl = $lvl;
        if lvl <= $crate::logging::LogLevel::Trace && lvl <= $crate::logging::max_level() {
            let _ = $crate::logging::COMPONENT_LOGGER.with(|v| {
                let msngr = v.borrow();
                msngr.log(lvl, std::module_path!(), std::file!(), std::line!(), std::borrow::Cow::Owned(std::format!($($arg)+)));
            });
        }
    });
}