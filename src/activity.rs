use std::{borrow::Cow, rc::Rc, collections::BTreeMap};

/// User activity of a user in a device
pub struct ForensicActivity {
    pub timestamp : i64,
    pub artifact : Cow<'static, str>,
    pub host : Rc<String>,
    pub user : Rc<String>,
    pub session_id : SessionId,
    pub fields : BTreeMap<Cow<'static, str>, String>,
    pub activity : ActivityType
}

pub enum SessionId {
    Unknown,
    Id(Rc<String>)
}

pub enum ActivityType {
    Login,
    Browsing,
    FileSystem,
}