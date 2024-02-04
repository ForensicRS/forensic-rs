use std::{borrow::Cow, collections::BTreeMap};

/// Activity of a user in a device
#[derive(Clone, Debug, Default)]
pub struct ForensicActivity {
    pub timestamp : i64,
    pub artifact : Cow<'static, str>,
    pub host : String,
    pub user : String,
    pub session_id : SessionId,
    pub fields : BTreeMap<Cow<'static, str>, String>,
    pub activity : ActivityType
}
#[derive(Clone, Debug, Default)]
pub enum SessionId {
    #[default]
    Unknown,
    Id(String)
}
#[derive(Clone, Debug, Default)]
pub enum ActivityType {
    Login,
    Browsing,
    FileSystem,
    #[default]
    Unknown
}