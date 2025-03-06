
use crate::{prelude::Artifact, utils::time::Filetime};

/// Activity of a user in a device
#[derive(Clone, Debug, Default)]
pub struct ForensicActivity {
    /// When the activity took place
    pub timestamp : Filetime,
    /// Which user did it
    pub user : String,
    /// In which session
    pub session_id : SessionId,
    /// Activity being done
    pub activity : ActivityType,
    /// In which artifact the activity was detected
    pub origin : Artifact
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
    Browsing(String),
    FileSystem(FileSystemActivity),
    ProgramExecution(ProgramExecution),
    #[default]
    Unknown
}

#[derive(Clone, Default)]
pub struct ProgramExecution {
    pub executable : String
}

impl ProgramExecution {
    pub fn new(executable : String) -> Self {
        Self {
            executable
        }
    }
}

impl From<ProgramExecution> for ActivityType {
    fn from(v: ProgramExecution) -> Self {
        ActivityType::ProgramExecution(v)
    }
}
impl std::fmt::Debug for ProgramExecution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.executable)
    }
}

#[derive(Clone, Default, Debug)]
pub enum FileSystemActivity {
    Open(String),
    Delete(String),
    Move((String, String)),
    Create(String),
    #[default]
    Unknown
}