
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Artifact {
    #[default]
    Unknown,
    Other(OtherSO),
    Windows(WindowsArtifacts),
    Linux(LinuxArtifacts),
    MacOs
}
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct OtherSO {
    pub so : &'static str,
    pub artifact : &'static str,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum WindowsArtifacts {
    Registry(RegistryArtifacts),
    MFT,
    WinEvt(WindowsEvents),
    Other(String),
    Prefetch,
    UAL,
    Clipboard,
    ScheduledTasks,
    GPO,
    SRU,
    Startup,
    RecycleBin,
    #[default]
    Unknown
}
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum WindowsEvents {
    /// Sysmon event
    Sysmon,
    /// System event
    System,
    /// Security event
    Security,
    /// Other events not defined. The value is the Channel of the event.
    Other(String),
    #[default]
    Unknown
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegistryArtifacts {
    /// Shim Cache
    ShimCache,
    /// Shell Bags
    ShellBags,
    /// Run and RunOnce keys
    AutoRuns,
    Other(String),
    #[default]
    Unknown
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum LinuxArtifacts {
    Log(String),
    ShellHistory(String),
    Cron(String),
    Service(LinuxService),
    Other(String),
    #[default]
    Unknown
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum LinuxService {
    SysV,
    InitD,
    SystemD,
    Other(String),
    #[default]
    Unknown
}

impl Into<Artifact> for WindowsArtifacts {
    fn into(self) -> Artifact {
        Artifact::Windows(self)
    }
}
impl Into<Artifact> for RegistryArtifacts {
    fn into(self) -> Artifact {
        Artifact::Windows(WindowsArtifacts::Registry(self))
    }
}
impl Into<Artifact> for WindowsEvents {
    fn into(self) -> Artifact {
        Artifact::Windows(WindowsArtifacts::WinEvt(self))
    }
}

impl Into<WindowsArtifacts> for String {
    fn into(self) -> WindowsArtifacts {
        WindowsArtifacts::Other(self)
    }
}
impl Into<RegistryArtifacts> for String {
    fn into(self) -> RegistryArtifacts {
        RegistryArtifacts::Other(self)
    }
}
impl Into<WindowsEvents> for String {
    fn into(self) -> WindowsEvents {
        WindowsEvents::Other(self)
    }
}


