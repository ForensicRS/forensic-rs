#[macro_export(local_inner_macros)]
macro_rules! notify_informational {
    // trace!("a {} event", "log")
    ($typ:expr, $($arg:tt)+) => (notify!($crate::notifications::Priority::Informational, $typ, $($arg)+))
}

#[macro_export(local_inner_macros)]
macro_rules! notify_info {
    // trace!("a {} event", "log")
    ($typ:expr, $($arg:tt)+) => (notify!($crate::notifications::Priority::Informational, $typ, $($arg)+))
}

#[macro_export(local_inner_macros)]
macro_rules! notify_low {
    // trace!("a {} event", "log")
    ($typ:expr, $($arg:tt)+) => (notify!($crate::notifications::Priority::Low, $typ, $($arg)+))
}

#[macro_export(local_inner_macros)]
macro_rules! notify_medium {
    // trace!("a {} event", "log")
    ($typ:expr, $($arg:tt)+) => (notify!($crate::notifications::Priority::Medium, $typ, $($arg)+))
}

#[macro_export(local_inner_macros)]
macro_rules! notify_high {
    // trace!("a {} event", "log")
    ($typ:expr, $($arg:tt)+) => (notify!($crate::notifications::Priority::High, $typ, $($arg)+))
}
#[macro_export(local_inner_macros)]
macro_rules! notify_critical {
    // trace!("a {} event", "log")
    ($typ:expr, $($arg:tt)+) => (notify!($crate::notifications::Priority::Critical, $typ, $($arg)+))
}

#[macro_export(local_inner_macros)]
macro_rules! notify {
    // log!( Level::Info; "a {} event", "log");
    ($priority:expr, $typ:expr, $($arg:tt)+) => ({
        let priority = $priority;
        let typ = $typ;
        let _ = $crate::notifications::NOTIFIER.with(|v| {
            let notifier = v.borrow();
            notifier.notify(priority,typ, std::module_path!(), std::file!(), std::line!(), std::borrow::Cow::Owned(std::format!($($arg)+)));
        });
    });
}
