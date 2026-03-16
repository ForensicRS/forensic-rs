
use std::collections::BTreeMap;

use crate::field::Text;
use crate::utils::time::Filetime;

/// Activity of a user in a device
#[derive(Clone, Debug, Default)]
pub struct ForensicActivity {
    pub timestamp : Filetime,
    pub user : String,
    pub session_id : SessionId,
    pub activity : ActivityType,
    /// Extensible key-value metadata for additional context.
    pub extras : BTreeMap<Text, Text>,
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
    pub executable : String,
    pub arguments : Option<String>,
    pub working_directory : Option<String>,
    pub run_count : Option<u32>,
}

impl ProgramExecution {
    pub fn new(executable : String) -> Self {
        Self {
            executable,
            arguments: None,
            working_directory: None,
            run_count: None,
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
    Rename((String, String)),
    Read(String),
    Write(String),
    #[default]
    Unknown
}