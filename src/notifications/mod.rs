use std::borrow::Cow;
use std::cell::RefCell;
use crate::channel::{self, Receiver, Sender};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum NotificationType {
    Informational,
    SuspiciousArtifact,
    AntiForensicsDetected,
    DeletedArtifact
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum Priority {
    Informational,
    Low,
    Medium,
    High,
    Critical
}

#[derive(Clone)]
pub struct Notifier {
    pub channel : Sender<Notification>
}

impl Default for Notifier {
    fn default() -> Self {
        let (sender,_reveiver) = channel::channel();
        Self { channel: sender }
    }
}
impl Notifier {
    pub fn new(sender : Sender<Notification>) -> Self {
        Self {
            channel : sender
        }
    }
    pub fn notify(&self, priority: Priority, r#type : NotificationType, module : &'static str, file : &'static str, line : u32, data : Cow<'static, str>) {
        let _ = self.channel.send(Notification { r#type,priority, module, file, line, data });
    }
}

#[derive(Debug, Clone)]
pub struct Notification {
    pub r#type : NotificationType,
    pub priority : Priority,
    pub module : &'static str,
    pub line : u32,
    pub file : &'static str,
    pub data : Cow<'static, str>,
}

#[macro_use]
pub mod macros;

thread_local! {
    pub static NOTIFIER : RefCell<Notifier> = RefCell::new(Notifier::default());
}

/// Initializes the Notifier for the current thread/component.
pub fn initialize_notifier(msngr: Notifier) {
    let _ = NOTIFIER.with(|v| {
        let mut brw = v.borrow_mut();
        *brw = msngr;
        Ok::<(), ()>(())
    });
    // Wait for local_key_cell_methods
}

/// Use for fast initialization during testing
pub fn testing_notifier_dummy() -> Receiver<Notification> {
    let (sender, receiver) = channel::channel();
    let msngr = Notifier::new(sender);
    initialize_notifier(msngr);
    receiver
}