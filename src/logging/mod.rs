use std::{
    cell::RefCell, borrow::Cow, sync::atomic::{AtomicUsize, Ordering},
};

use crate::channel::{self, Receiver, Sender};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Clone)]
pub struct Logger {
    pub channel : Sender<Message>
}

impl Default for Logger {
    fn default() -> Self {
        let (sender,_reveiver) = channel::channel();
        Self { channel: sender }
    }
}
impl Logger {
    pub fn new(sender : Sender<Message>) -> Self {
        Self {
            channel : sender
        }
    }
    pub fn log(&self, level : LogLevel, module : &'static str, file : &'static str, line : u32, data : Cow<'static, str>) {
        let _ = self.channel.send(Message { level, module, file, line, data });
    }
}

#[derive(Debug, Clone)]
pub struct Message {
    pub level : LogLevel,
    pub module : &'static str,
    pub line : u32,
    pub file : &'static str,
    pub data : Cow<'static, str>,
}

#[macro_use]
pub mod macros;

static MAX_NOTIFY_LEVEL_FILTER: AtomicUsize = AtomicUsize::new(5);
//static NOTIFY_LEVEL_NAMES: [&str; 6] = ["OFF", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"];

#[inline]
pub fn set_max_level(level: LogLevel) {
    MAX_NOTIFY_LEVEL_FILTER.store(level as usize, Ordering::Relaxed);
}

#[inline]
pub fn enabled_level(level: &LogLevel) -> bool {
    MAX_NOTIFY_LEVEL_FILTER.load(Ordering::Relaxed) >= (*level as usize)
}
#[inline]
pub fn max_level() -> LogLevel {
    unsafe { std::mem::transmute(MAX_NOTIFY_LEVEL_FILTER.load(Ordering::Relaxed)) }
}

thread_local! {
    pub static COMPONENT_LOGGER : RefCell<Logger> = RefCell::new(Logger::default());
}

/// Initializes the logger for the current thread/component.
pub fn initialize_logger(msngr: Logger) {
    let _ = COMPONENT_LOGGER.with(|v| {
        let mut brw = v.borrow_mut();
        *brw = msngr;
        Ok::<(), ()>(())
    });
    // Wait for local_key_cell_methods
    //COMPONENT_LOGGER.replace(msngr);
}

/// Use for fast initialization during testing
pub fn testing_logger_dummy() -> Receiver<Message> {
    let (sender, receiver) = channel::channel();
    let msngr = Logger::new(sender);
    initialize_logger(msngr);
    receiver
}