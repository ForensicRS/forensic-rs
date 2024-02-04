/// Alerts of a suspicious evidence found during the processing of an artifact.
/// ```rust
/// use forensic_rs::prelude::*;
/// notify_informational!(NotificationType::AntiForensicsDetected, "The artifact {} has been tampered: filled with zeros.", r"C:\Windows\Prefetch\POWERSHELL.EXE-AE8EDC9B.pf")
/// ```
#[macro_export(local_inner_macros)]
macro_rules! notify_informational {
    ($typ:expr, $($arg:tt)+) => (notify!($crate::notifications::Priority::Informational, $typ, $($arg)+))
}
/// Alerts of a suspicious evidence found during the processing of an artifact.
/// ```rust
/// use forensic_rs::prelude::*;
/// notify_info!(NotificationType::AntiForensicsDetected, "The artifact {} has been tampered: filled with zeros.", r"C:\Windows\Prefetch\POWERSHELL.EXE-AE8EDC9B.pf")
/// ```
#[macro_export(local_inner_macros)]
macro_rules! notify_info {
    ($typ:expr, $($arg:tt)+) => (notify!($crate::notifications::Priority::Informational, $typ, $($arg)+))
}

/// Alerts of a suspicious evidence found during the processing of an artifact.
/// ```rust
/// use forensic_rs::prelude::*;
/// notify_low!(NotificationType::AntiForensicsDetected, "The artifact {} has been tampered: filled with zeros.", r"C:\Windows\Prefetch\POWERSHELL.EXE-AE8EDC9B.pf")
/// ```
#[macro_export(local_inner_macros)]
macro_rules! notify_low {
    ($typ:expr, $($arg:tt)+) => (notify!($crate::notifications::Priority::Low, $typ, $($arg)+))
}

/// Alerts of a suspicious evidence found during the processing of an artifact.
/// ```rust
/// use forensic_rs::prelude::*;
/// notify_medium!(NotificationType::AntiForensicsDetected, "The artifact {} has been tampered: filled with zeros.", r"C:\Windows\Prefetch\POWERSHELL.EXE-AE8EDC9B.pf")
/// ```
#[macro_export(local_inner_macros)]
macro_rules! notify_medium {
    ($typ:expr, $($arg:tt)+) => (notify!($crate::notifications::Priority::Medium, $typ, $($arg)+))
}
/// Alerts of a suspicious evidence found during the processing of an artifact.
/// ```rust
/// use forensic_rs::prelude::*;
/// notify_high!(NotificationType::AntiForensicsDetected, "The artifact {} has been tampered: filled with zeros.", r"C:\Windows\Prefetch\POWERSHELL.EXE-AE8EDC9B.pf")
/// ```
#[macro_export(local_inner_macros)]
macro_rules! notify_high {
    ($typ:expr, $($arg:tt)+) => (notify!($crate::notifications::Priority::High, $typ, $($arg)+))
}
/// Alerts of a suspicious evidence found during the processing of an artifact.
/// ```rust
/// use forensic_rs::prelude::*;
/// notify_critical!(NotificationType::AntiForensicsDetected, "The artifact {} has been tampered: filled with zeros.", r"C:\Windows\Prefetch\POWERSHELL.EXE-AE8EDC9B.pf")
/// ```
#[macro_export(local_inner_macros)]
macro_rules! notify_critical {
    // trace!("a {} event", "log")
    ($typ:expr, $($arg:tt)+) => (notify!($crate::notifications::Priority::Critical, $typ, $($arg)+))
}
/// Alerts of a suspicious evidence found during the processing of an artifact.
/// ```rust
/// use forensic_rs::prelude::*;
/// notify!(Priority::High, NotificationType::AntiForensicsDetected, "The artifact {} has been tampered: filled with zeros.", r"C:\Windows\Prefetch\POWERSHELL.EXE-AE8EDC9B.pf")
/// ```
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
