pub mod traits;
pub mod data;
pub mod err;
pub mod bitacora;
pub mod core;
pub mod activity;
pub mod artifact;
pub mod logging;
pub mod channel;
pub mod notifications;
pub mod field;
pub mod dictionary;
pub mod context;

pub mod prelude {
    pub use crate::context::initialize_context;
    pub use crate::dictionary::*;
    pub use crate::traits::registry::*;
    pub use crate::err::*;
    pub use crate::data::*;
    pub use crate::bitacora::*;
    pub use crate::artifact::*;
    pub use crate::logging::{Message, LogLevel, enabled_level, initialize_logger, max_level, set_max_level, macros::{*}};
    pub use crate::notifications::{Notification, NotificationType, Priority, initialize_notifier, macros::{*}};
}