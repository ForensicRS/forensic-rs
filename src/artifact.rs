#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize};

use crate::field::Text;

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Artifact {
    #[default]
    Unknown,
    Other(OtherOS),
    Windows(WindowsArtifacts),
    Linux(LinuxArtifacts),
    MacOs(MacArtifacts),
    Common(CommonArtifact),
}
impl std::fmt::Display for Artifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Artifact::Unknown => write!(f, "Unknown"),
            Artifact::Other(v) => write!(f, "{}", v),
            Artifact::Windows(v) => write!(f, "Windows::{}", v),
            Artifact::Linux(v) => write!(f, "Linux::{}", v),
            Artifact::MacOs(v) => write!(f, "MacOs::{}", v),
            Artifact::Common(v) => write!(f, "Common::{}", v),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct OtherOS {
    pub os: Text,
    pub artifact: Text,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
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
    /// AutomaticDestinations/CustomDestinations Jump List files
    JumpLists,
    /// Shortcut files (recent items, taskbar pins, etc.)
    LnkFiles,
    /// Background Intelligent Transfer Service job database
    Bits,
    /// WMI repository / event-subscription persistence
    WmiRepository,
    /// PowerShell console history and transcripts
    PowerShellHistory,
    /// RDP bitmap cache files
    RdpCache,
    /// Windows Timeline (ActivitiesCache.db)
    Timeline,
    #[default]
    Unknown,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum WindowsEvents {
    /// Sysmon event
    Sysmon,
    /// System event
    System,
    /// Security event
    Security,
    /// Setup event
    Setup,
    /// Application event
    Application,
    /// Microsoft-Windows-PowerShell/Operational channel
    PowerShell,
    /// Other events not defined. The value is the Channel of the event.
    Other(String),
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum RegistryArtifacts {
    /// Shim Cache
    ShimCache,
    /// Shell Bags
    ShellBags,
    /// Run and RunOnce keys
    AutoRuns,
    /// Amcache.hve
    AmCache,
    /// HKLM\SYSTEM\CurrentControlSet\Services
    Services,
    /// UserAssist
    UserAssist,
    /// Background/Desktop Activity Moderator
    Bam,
    /// TypedPaths (Explorer address bar MRU)
    TypedPaths,
    /// RecentDocs
    RecentDocs,
    Other(String),
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum LinuxArtifacts {
    Log(String),
    ShellHistory(String),
    Cron(String),
    Service(LinuxService),
    /// systemd-journald binary journal
    Journal,
    /// /etc/passwd, /etc/shadow, /etc/group
    Accounts,
    /// authorized_keys / known_hosts / sshd_config
    Ssh,
    Other(String),
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum LinuxService {
    SysV,
    InitD,
    SystemD,
    Other(String),
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum MacArtifacts {
    /// FSEvents (file system event store)
    FsEvents,
    /// Spotlight metadata store
    Spotlight,
    /// Unified logging (tracev3)
    UnifiedLogs,
    /// TCC.db privacy consent database
    Tcc,
    /// LaunchAgents plists
    LaunchAgents,
    /// LaunchDaemons plists
    LaunchDaemons,
    /// KnowledgeC.db (app/device usage)
    KnowledgeC,
    Other(String),
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum CommonArtifact {
    WebBrowsing(WebBrowsingArtifact),
    Other(String),
    #[default]
    Unknown,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum WebBrowsingArtifact {
    BrowserHistory,
    BrowserStorage,
    BrowserCache,
    Cookie,
    Extension,
    ExtensionActivity,
    FileSystem,
    LocalStorage,
    Preferences,
    SessionStorage,
    Download,
    AutoFill,
    RSSFeed,
    Other(String),
    #[default]
    Unknown,
}

impl From<WindowsArtifacts> for Artifact {
    fn from(value: WindowsArtifacts) -> Artifact {
        Artifact::Windows(value)
    }
}
impl From<RegistryArtifacts> for Artifact {
    fn from(value: RegistryArtifacts) -> Artifact {
        Artifact::Windows(WindowsArtifacts::Registry(value))
    }
}
impl From<WindowsEvents> for Artifact {
    fn from(value: WindowsEvents) -> Artifact {
        Artifact::Windows(WindowsArtifacts::WinEvt(value))
    }
}

impl From<String> for WindowsArtifacts {
    fn from(value: String) -> WindowsArtifacts {
        WindowsArtifacts::Other(value)
    }
}
impl From<String> for RegistryArtifacts {
    fn from(value: String) -> RegistryArtifacts {
        RegistryArtifacts::Other(value)
    }
}
impl From<String> for WindowsEvents {
    fn from(value: String) -> WindowsEvents {
        WindowsEvents::Other(value)
    }
}

impl std::fmt::Display for LinuxArtifacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinuxArtifacts::Log(v) => write!(f, "Log::{}", v),
            LinuxArtifacts::ShellHistory(v) => write!(f, "ShellHistory::{}", v),
            LinuxArtifacts::Cron(v) => write!(f, "Cron::{}", v),
            LinuxArtifacts::Service(v) => write!(f, "Service::{}", v),
            LinuxArtifacts::Journal => write!(f, "Journal"),
            LinuxArtifacts::Accounts => write!(f, "Accounts"),
            LinuxArtifacts::Ssh => write!(f, "Ssh"),
            LinuxArtifacts::Other(v) => write!(f, "{}", v),
            LinuxArtifacts::Unknown => write!(f, "Unknown"),
        }
    }
}

impl std::fmt::Display for LinuxService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinuxService::InitD => write!(f, "InitD"),
            LinuxService::SysV => write!(f, "SysV"),
            LinuxService::SystemD => write!(f, "SystemD"),
            LinuxService::Unknown => write!(f, "Unknown"),
            LinuxService::Other(v) => write!(f, "{}", v),
        }
    }
}

impl std::fmt::Display for RegistryArtifacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryArtifacts::ShimCache => write!(f, "ShimCache"),
            RegistryArtifacts::ShellBags => write!(f, "ShellBags"),
            RegistryArtifacts::AutoRuns => write!(f, "AutoRuns"),
            RegistryArtifacts::AmCache => write!(f, "AmCache"),
            RegistryArtifacts::Services => write!(f, "Services"),
            RegistryArtifacts::UserAssist => write!(f, "UserAssist"),
            RegistryArtifacts::Bam => write!(f, "Bam"),
            RegistryArtifacts::TypedPaths => write!(f, "TypedPaths"),
            RegistryArtifacts::RecentDocs => write!(f, "RecentDocs"),
            RegistryArtifacts::Other(v) => write!(f, "{}", v),
            RegistryArtifacts::Unknown => write!(f, "Unknown"),
        }
    }
}

impl std::fmt::Display for WindowsEvents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WindowsEvents::Sysmon => write!(f, "Sysmon"),
            WindowsEvents::System => write!(f, "System"),
            WindowsEvents::Security => write!(f, "Security"),
            WindowsEvents::Application => write!(f, "Application"),
            WindowsEvents::Setup => write!(f, "Setup"),
            WindowsEvents::PowerShell => write!(f, "PowerShell"),
            WindowsEvents::Other(v) => write!(f, "{}", v),
            WindowsEvents::Unknown => write!(f, "Unknown"),
        }
    }
}

impl std::fmt::Display for WindowsArtifacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WindowsArtifacts::Registry(v) => write!(f, "Registry::{}", v),
            WindowsArtifacts::MFT => write!(f, "MFT"),
            WindowsArtifacts::WinEvt(v) => write!(f, "WinEvt::{}", v),
            WindowsArtifacts::Other(v) => write!(f, "{}", v),
            WindowsArtifacts::Prefetch => write!(f, "Prefetch"),
            WindowsArtifacts::UAL => write!(f, "UAL"),
            WindowsArtifacts::Clipboard => write!(f, "Clipboard"),
            WindowsArtifacts::ScheduledTasks => write!(f, "ScheduledTasks"),
            WindowsArtifacts::GPO => write!(f, "GPO"),
            WindowsArtifacts::SRU => write!(f, "SRU"),
            WindowsArtifacts::Startup => write!(f, "Startup"),
            WindowsArtifacts::RecycleBin => write!(f, "RecycleBin"),
            WindowsArtifacts::JumpLists => write!(f, "JumpLists"),
            WindowsArtifacts::LnkFiles => write!(f, "LnkFiles"),
            WindowsArtifacts::Bits => write!(f, "Bits"),
            WindowsArtifacts::WmiRepository => write!(f, "WmiRepository"),
            WindowsArtifacts::PowerShellHistory => write!(f, "PowerShellHistory"),
            WindowsArtifacts::RdpCache => write!(f, "RdpCache"),
            WindowsArtifacts::Timeline => write!(f, "Timeline"),
            WindowsArtifacts::Unknown => write!(f, "Unknown"),
        }
    }
}

impl std::fmt::Display for MacArtifacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MacArtifacts::FsEvents => write!(f, "FsEvents"),
            MacArtifacts::Spotlight => write!(f, "Spotlight"),
            MacArtifacts::UnifiedLogs => write!(f, "UnifiedLogs"),
            MacArtifacts::Tcc => write!(f, "Tcc"),
            MacArtifacts::LaunchAgents => write!(f, "LaunchAgents"),
            MacArtifacts::LaunchDaemons => write!(f, "LaunchDaemons"),
            MacArtifacts::KnowledgeC => write!(f, "KnowledgeC"),
            MacArtifacts::Other(v) => write!(f, "{}", v),
            MacArtifacts::Unknown => write!(f, "Unknown"),
        }
    }
}

impl std::fmt::Display for OtherOS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.os, self.artifact)
    }
}

impl std::fmt::Display for CommonArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommonArtifact::WebBrowsing(v) => write!(f, "WebBrowsing::{}", v),
            CommonArtifact::Other(v) => write!(f, "{}", v),
            CommonArtifact::Unknown => write!(f, "Unknown"),
        }
    }
}
impl std::fmt::Display for WebBrowsingArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebBrowsingArtifact::AutoFill => write!(f, "AutoFill"),
            WebBrowsingArtifact::Other(v) => write!(f, "{}", v),
            WebBrowsingArtifact::Unknown => write!(f, "Unknown"),
            WebBrowsingArtifact::BrowserHistory => write!(f, "BrowserHistory"),
            WebBrowsingArtifact::BrowserStorage => write!(f, "BrowserStorage"),
            WebBrowsingArtifact::BrowserCache => write!(f, "BrowserCache"),
            WebBrowsingArtifact::Cookie => write!(f, "Cookie"),
            WebBrowsingArtifact::Extension => write!(f, "Extension"),
            WebBrowsingArtifact::ExtensionActivity => write!(f, "ExtensionActivity"),
            WebBrowsingArtifact::FileSystem => write!(f, "FileSystem"),
            WebBrowsingArtifact::LocalStorage => write!(f, "LocalStorage"),
            WebBrowsingArtifact::Preferences => write!(f, "Preferences"),
            WebBrowsingArtifact::SessionStorage => write!(f, "SessionStorage"),
            WebBrowsingArtifact::Download => write!(f, "Download"),
            WebBrowsingArtifact::RSSFeed => write!(f, "RSSFeed"),
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for Artifact {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&self)
    }
}
#[cfg(feature = "serde")]
impl Serialize for OtherOS {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&self)
    }
}
#[cfg(feature = "serde")]
impl Serialize for WindowsArtifacts {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&self)
    }
}
#[cfg(feature = "serde")]
impl Serialize for WindowsEvents {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&self)
    }
}
#[cfg(feature = "serde")]
impl Serialize for RegistryArtifacts {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&self)
    }
}
#[cfg(feature = "serde")]
impl Serialize for LinuxService {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&self)
    }
}
#[cfg(feature = "serde")]
impl Serialize for MacArtifacts {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&self)
    }
}
#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Artifact {
    fn deserialize<D>(deserializer: D) -> Result<Artifact, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(ArtifactVisitor)
    }
}
#[cfg(feature = "serde")]
pub struct LinuxServiceVisitor;

#[cfg(feature = "serde")]
impl<'de> Visitor<'de> for LinuxServiceVisitor {
    type Value = LinuxService;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a linux service name")
    }

    fn visit_str<E>(self, txt: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(linux_service_from_str(txt))
    }
    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(v)
    }
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&v[..])
    }
}
#[cfg(feature = "serde")]
pub struct ArtifactVisitor;
#[cfg(feature = "serde")]
impl<'de> Visitor<'de> for ArtifactVisitor {
    type Value = Artifact;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("an artifact name")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(artifact_from_str(v))
    }
    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(v)
    }
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&v[..])
    }
}

#[cfg(feature = "serde")]
pub struct WindowsArtifactVisitor;
#[cfg(feature = "serde")]
impl<'de> Visitor<'de> for WindowsArtifactVisitor {
    type Value = WindowsArtifacts;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("an artifact name")
    }

    fn visit_str<E>(self, txt: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(windows_artifacts_from_str(txt))
    }
    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(v)
    }
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&v[..])
    }
}
#[cfg(feature = "serde")]
pub struct WinEvtVisitor;
#[cfg(feature = "serde")]
impl<'de> Visitor<'de> for WinEvtVisitor {
    type Value = WindowsEvents;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a windows event name")
    }

    fn visit_str<E>(self, txt: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(winevt_artifacts_from_str(txt))
    }
    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(v)
    }
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&v[..])
    }
}
#[cfg(feature = "serde")]
pub struct RegistryArtifactsVisitor;
#[cfg(feature = "serde")]
impl<'de> Visitor<'de> for RegistryArtifactsVisitor {
    type Value = RegistryArtifacts;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a registry name")
    }

    fn visit_str<E>(self, txt: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(registry_artifacts_from_str(txt))
    }
    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(v)
    }
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&v[..])
    }
}
#[cfg(feature = "serde")]
pub struct OtherOsVisitor;
#[cfg(feature = "serde")]
impl<'de> Visitor<'de> for OtherOsVisitor {
    type Value = OtherOS;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a Operating System name")
    }

    fn visit_str<E>(self, txt: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(other_artifact_from_str(txt))
    }
    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(v)
    }
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&v[..])
    }
}

#[cfg(feature = "serde")]
pub struct LinuxArtifactVisitor;
#[cfg(feature = "serde")]
impl<'de> Visitor<'de> for LinuxArtifactVisitor {
    type Value = LinuxArtifacts;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a Operating System name")
    }

    fn visit_str<E>(self, txt: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(linux_artifacts_from_str(txt))
    }
    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(v)
    }
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&v[..])
    }
}
#[cfg(feature = "serde")]
pub struct MacOsArtifactVisitor;
#[cfg(feature = "serde")]
impl<'de> Visitor<'de> for MacOsArtifactVisitor {
    type Value = MacArtifacts;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("Invalid Mac artifact")
    }

    fn visit_str<E>(self, txt: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let (artifact, subartifact) = match txt.find("::") {
            Some(v) => (&txt[0..v], &txt[v + 2..]),
            None => (txt, ""),
        };
        Ok(match artifact {
            "Unknown" => Self::Value::Unknown,
            _ => Self::Value::Other(subartifact.to_string()),
        })
    }
    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(v)
    }
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&v[..])
    }
}

pub fn artifact_from_str(txt: &str) -> Artifact {
    let (os, artifact) = match txt.split_once("::") {
        Some(v) => v,
        None => return Artifact::Unknown,
    };
    match os {
        "Unknown" => Artifact::Unknown,
        "Windows" => Artifact::Windows(windows_artifacts_from_str(artifact)),
        "Linux" => Artifact::Linux(linux_artifacts_from_str(artifact)),
        "MacOs" => Artifact::MacOs(mac_artifact_from_str(artifact)),
        "Common" => Artifact::Common(common_artifact_from_str(artifact)),
        _ => Artifact::Other(other_artifact_from_str(txt)),
    }
}
pub fn windows_artifacts_from_str(txt: &str) -> WindowsArtifacts {
    let (artifact, subartifact) = match txt.find("::") {
        Some(v) => (&txt[0..v], &txt[v + 2..]),
        None => (txt, ""),
    };
    match artifact {
        "Unknown" => WindowsArtifacts::Unknown,
        "Registry" => WindowsArtifacts::Registry(registry_artifacts_from_str(subartifact)),
        "MFT" => WindowsArtifacts::MFT,
        "Prefetch" => WindowsArtifacts::Prefetch,
        "WinEvt" => WindowsArtifacts::WinEvt(winevt_artifacts_from_str(subartifact)),
        "UAL" => WindowsArtifacts::UAL,
        "Clipboard" => WindowsArtifacts::Clipboard,
        "ScheduledTasks" => WindowsArtifacts::ScheduledTasks,
        "GPO" => WindowsArtifacts::GPO,
        "SRU" => WindowsArtifacts::SRU,
        "Startup" => WindowsArtifacts::Startup,
        "RecycleBin" => WindowsArtifacts::RecycleBin,
        "JumpLists" => WindowsArtifacts::JumpLists,
        "LnkFiles" => WindowsArtifacts::LnkFiles,
        "Bits" => WindowsArtifacts::Bits,
        "WmiRepository" => WindowsArtifacts::WmiRepository,
        "PowerShellHistory" => WindowsArtifacts::PowerShellHistory,
        "RdpCache" => WindowsArtifacts::RdpCache,
        "Timeline" => WindowsArtifacts::Timeline,
        _ => WindowsArtifacts::Other(txt.to_string()),
    }
}

pub fn registry_artifacts_from_str(txt: &str) -> RegistryArtifacts {
    match txt {
        "Unknown" => RegistryArtifacts::Unknown,
        "ShimCache" => RegistryArtifacts::ShimCache,
        "ShellBags" => RegistryArtifacts::ShellBags,
        "AutoRuns" => RegistryArtifacts::AutoRuns,
        "AmCache" => RegistryArtifacts::AmCache,
        "Services" => RegistryArtifacts::Services,
        "UserAssist" => RegistryArtifacts::UserAssist,
        "Bam" => RegistryArtifacts::Bam,
        "TypedPaths" => RegistryArtifacts::TypedPaths,
        "RecentDocs" => RegistryArtifacts::RecentDocs,
        _ => RegistryArtifacts::Other(txt.to_string()),
    }
}

pub fn winevt_artifacts_from_str(txt: &str) -> WindowsEvents {
    match txt {
        "Unknown" => WindowsEvents::Unknown,
        "Sysmon" => WindowsEvents::Sysmon,
        "System" => WindowsEvents::System,
        "Security" => WindowsEvents::Security,
        "Application" => WindowsEvents::Application,
        "Setup" => WindowsEvents::Setup,
        "PowerShell" => WindowsEvents::PowerShell,
        _ => WindowsEvents::Other(txt.to_string()),
    }
}

pub fn linux_artifacts_from_str(txt: &str) -> LinuxArtifacts {
    let (artifact, subartifact) = match txt.find("::") {
        Some(v) => (&txt[0..v], &txt[v + 2..]),
        None => (txt, ""),
    };
    match artifact {
        "Unknown" => LinuxArtifacts::Unknown,
        "Log" => LinuxArtifacts::Log(subartifact.to_string()),
        "ShellHistory" => LinuxArtifacts::ShellHistory(subartifact.to_string()),
        "Cron" => LinuxArtifacts::Cron(subartifact.to_string()),
        "Service" => LinuxArtifacts::Service(linux_service_from_str(subartifact)),
        "Journal" => LinuxArtifacts::Journal,
        "Accounts" => LinuxArtifacts::Accounts,
        "Ssh" => LinuxArtifacts::Ssh,
        _ => LinuxArtifacts::Other(txt.to_string()),
    }
}
pub fn linux_service_from_str(txt: &str) -> LinuxService {
    match txt {
        "SysV" => LinuxService::SysV,
        "InitD" => LinuxService::InitD,
        "SystemD" => LinuxService::SystemD,
        "Unknown" => LinuxService::Unknown,
        _ => LinuxService::Other(txt.to_string()),
    }
}

pub fn mac_artifact_from_str(txt: &str) -> MacArtifacts {
    match txt {
        "Unknown" => MacArtifacts::Unknown,
        "FsEvents" => MacArtifacts::FsEvents,
        "Spotlight" => MacArtifacts::Spotlight,
        "UnifiedLogs" => MacArtifacts::UnifiedLogs,
        "Tcc" => MacArtifacts::Tcc,
        "LaunchAgents" => MacArtifacts::LaunchAgents,
        "LaunchDaemons" => MacArtifacts::LaunchDaemons,
        "KnowledgeC" => MacArtifacts::KnowledgeC,
        _ => MacArtifacts::Other(txt.to_string()),
    }
}
pub fn common_artifact_from_str(txt: &str) -> CommonArtifact {
    let (artifact, subartifact) = match txt.find("::") {
        Some(v) => (&txt[0..v], &txt[v + 2..]),
        None if txt == "Unknown" => return CommonArtifact::Unknown,
        None => return CommonArtifact::Other(txt.to_string()),
    };
    match artifact {
        "Unknown" => CommonArtifact::Unknown,
        "WebBrowsing" => CommonArtifact::WebBrowsing(webbrowsing_artifact_from_str(subartifact)),
        _ => CommonArtifact::Other(txt.to_string()),
    }
}
pub fn webbrowsing_artifact_from_str(txt: &str) -> WebBrowsingArtifact {
    match txt {
        "AutoFill" => WebBrowsingArtifact::AutoFill,
        "BrowserCache" => WebBrowsingArtifact::BrowserCache,
        "BrowserHistory" => WebBrowsingArtifact::BrowserHistory,
        "BrowserStorage" => WebBrowsingArtifact::BrowserStorage,
        "Cookie" => WebBrowsingArtifact::Cookie,
        "Download" => WebBrowsingArtifact::Download,
        "Extension" => WebBrowsingArtifact::Extension,
        "ExtensionActivity" => WebBrowsingArtifact::ExtensionActivity,
        "FileSystem" => WebBrowsingArtifact::FileSystem,
        "LocalStorage" => WebBrowsingArtifact::LocalStorage,
        "Preferences" => WebBrowsingArtifact::Preferences,
        "RSSFeed" => WebBrowsingArtifact::RSSFeed,
        "SessionStorage" => WebBrowsingArtifact::SessionStorage,
        "Unknown" => WebBrowsingArtifact::Unknown,
        _ => WebBrowsingArtifact::Other(txt.to_string()),
    }
}
pub fn other_artifact_from_str(txt: &str) -> OtherOS {
    let (os, subartifact) = match txt.find("::") {
        Some(v) => (&txt[0..v], &txt[v + 2..]),
        None => {
            return OtherOS {
                os: std::borrow::Cow::Owned(txt.to_string()),
                artifact: std::borrow::Cow::Owned("Unknown".to_string()),
            }
        }
    };
    OtherOS {
        os: std::borrow::Cow::Owned(os.to_string()),
        artifact: std::borrow::Cow::Owned(subartifact.to_string()),
    }
}

impl From<&str> for Artifact {
    fn from(txt: &str) -> Self {
        artifact_from_str(txt)
    }
}
impl From<&String> for Artifact {
    fn from(txt: &String) -> Self {
        artifact_from_str(txt)
    }
}
impl From<String> for Artifact {
    fn from(txt: String) -> Self {
        artifact_from_str(&txt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(artifact: Artifact) {
        let text = artifact.to_string();
        let parsed = artifact_from_str(&text);
        assert_eq!(artifact, parsed, "round-trip failed for {text:?}");
    }

    #[test]
    fn windows_variants_roundtrip() {
        roundtrip(Artifact::Windows(WindowsArtifacts::MFT));
        roundtrip(Artifact::Windows(WindowsArtifacts::Prefetch));
        roundtrip(Artifact::Windows(WindowsArtifacts::UAL));
        roundtrip(Artifact::Windows(WindowsArtifacts::Clipboard));
        roundtrip(Artifact::Windows(WindowsArtifacts::ScheduledTasks));
        roundtrip(Artifact::Windows(WindowsArtifacts::GPO));
        roundtrip(Artifact::Windows(WindowsArtifacts::SRU));
        roundtrip(Artifact::Windows(WindowsArtifacts::Startup));
        roundtrip(Artifact::Windows(WindowsArtifacts::RecycleBin));
        roundtrip(Artifact::Windows(WindowsArtifacts::JumpLists));
        roundtrip(Artifact::Windows(WindowsArtifacts::LnkFiles));
        roundtrip(Artifact::Windows(WindowsArtifacts::Bits));
        roundtrip(Artifact::Windows(WindowsArtifacts::WmiRepository));
        roundtrip(Artifact::Windows(WindowsArtifacts::PowerShellHistory));
        roundtrip(Artifact::Windows(WindowsArtifacts::RdpCache));
        roundtrip(Artifact::Windows(WindowsArtifacts::Timeline));
        roundtrip(Artifact::Windows(WindowsArtifacts::Unknown));
        roundtrip(Artifact::Windows(WindowsArtifacts::Other(
            "CustomThing".to_string(),
        )));
    }

    #[test]
    fn windows_registry_variants_roundtrip() {
        roundtrip(RegistryArtifacts::ShimCache.into());
        roundtrip(RegistryArtifacts::ShellBags.into());
        roundtrip(RegistryArtifacts::AutoRuns.into());
        roundtrip(RegistryArtifacts::AmCache.into());
        roundtrip(RegistryArtifacts::Services.into());
        roundtrip(RegistryArtifacts::UserAssist.into());
        roundtrip(RegistryArtifacts::Bam.into());
        roundtrip(RegistryArtifacts::TypedPaths.into());
        roundtrip(RegistryArtifacts::RecentDocs.into());
        roundtrip(RegistryArtifacts::Unknown.into());
        roundtrip(RegistryArtifacts::Other("Custom".to_string()).into());
    }

    #[test]
    fn windows_event_variants_roundtrip() {
        roundtrip(WindowsEvents::Sysmon.into());
        roundtrip(WindowsEvents::System.into());
        roundtrip(WindowsEvents::Security.into());
        roundtrip(WindowsEvents::Setup.into());
        roundtrip(WindowsEvents::Application.into());
        roundtrip(WindowsEvents::PowerShell.into());
        roundtrip(WindowsEvents::Unknown.into());
        roundtrip(WindowsEvents::Other("Custom-Channel".to_string()).into());
    }

    #[test]
    fn linux_variants_roundtrip() {
        roundtrip(Artifact::Linux(LinuxArtifacts::Log("auth.log".to_string())));
        roundtrip(Artifact::Linux(LinuxArtifacts::ShellHistory(
            "bash".to_string(),
        )));
        roundtrip(Artifact::Linux(LinuxArtifacts::Cron("root".to_string())));
        roundtrip(Artifact::Linux(LinuxArtifacts::Service(LinuxService::SysV)));
        roundtrip(Artifact::Linux(LinuxArtifacts::Service(
            LinuxService::InitD,
        )));
        roundtrip(Artifact::Linux(LinuxArtifacts::Service(
            LinuxService::SystemD,
        )));
        roundtrip(Artifact::Linux(LinuxArtifacts::Service(
            LinuxService::Other("upstart".to_string()),
        )));
        roundtrip(Artifact::Linux(LinuxArtifacts::Journal));
        roundtrip(Artifact::Linux(LinuxArtifacts::Accounts));
        roundtrip(Artifact::Linux(LinuxArtifacts::Ssh));
        roundtrip(Artifact::Linux(LinuxArtifacts::Unknown));
        roundtrip(Artifact::Linux(LinuxArtifacts::Other("docker".to_string())));
    }

    #[test]
    fn mac_variants_roundtrip() {
        roundtrip(Artifact::MacOs(MacArtifacts::FsEvents));
        roundtrip(Artifact::MacOs(MacArtifacts::Spotlight));
        roundtrip(Artifact::MacOs(MacArtifacts::UnifiedLogs));
        roundtrip(Artifact::MacOs(MacArtifacts::Tcc));
        roundtrip(Artifact::MacOs(MacArtifacts::LaunchAgents));
        roundtrip(Artifact::MacOs(MacArtifacts::LaunchDaemons));
        roundtrip(Artifact::MacOs(MacArtifacts::KnowledgeC));
        roundtrip(Artifact::MacOs(MacArtifacts::Unknown));
        roundtrip(Artifact::MacOs(MacArtifacts::Other(
            "QuarantineEvents".to_string(),
        )));
    }

    #[test]
    fn common_variants_roundtrip() {
        roundtrip(Artifact::Common(CommonArtifact::WebBrowsing(
            WebBrowsingArtifact::BrowserHistory,
        )));
        roundtrip(Artifact::Common(CommonArtifact::WebBrowsing(
            WebBrowsingArtifact::Cookie,
        )));
        roundtrip(Artifact::Common(CommonArtifact::Unknown));
        roundtrip(Artifact::Common(CommonArtifact::Other(
            "CloudSync".to_string(),
        )));
    }

    #[test]
    fn top_level_unknown_roundtrips() {
        roundtrip(Artifact::Unknown);
    }

    // Regression tests for the specific round-trip bugs fixed alongside this
    // taxonomy expansion.
    #[test]
    fn macos_display_tag_matches_from_str_tag() {
        // `Artifact::MacOs` used to `Display` as `"Mac::..."` while
        // `artifact_from_str` only recognized the `"MacOs::"` tag, so every
        // macOS artifact silently round-tripped into `Artifact::Other` instead
        // of `Artifact::MacOs`.
        let artifact = Artifact::MacOs(MacArtifacts::FsEvents);
        let text = artifact.to_string();
        assert_eq!(text, "MacOs::FsEvents");
        assert_eq!(artifact_from_str(&text), artifact);
    }

    #[test]
    fn shimcache_display_is_not_initd() {
        let artifact: Artifact = RegistryArtifacts::ShimCache.into();
        assert_eq!(artifact.to_string(), "Windows::Registry::ShimCache");
    }

    #[test]
    fn linux_unknown_display_is_plain_unknown() {
        assert_eq!(Artifact::Linux(LinuxArtifacts::Unknown).to_string(), "Linux::Unknown");
    }

    #[test]
    fn linux_service_roundtrips_through_display() {
        let artifact = Artifact::Linux(LinuxArtifacts::Service(LinuxService::SystemD));
        assert_eq!(artifact.to_string(), "Linux::Service::SystemD");
        assert_eq!(artifact_from_str(&artifact.to_string()), artifact);
    }

    #[test]
    fn windows_other_survives_roundtrip_without_double_colon() {
        let artifact = Artifact::Windows(WindowsArtifacts::Other("VendorTool".to_string()));
        let text = artifact.to_string();
        assert_eq!(text, "Windows::VendorTool");
        assert_eq!(artifact_from_str(&text), artifact);
    }

    #[test]
    fn common_other_survives_roundtrip_without_double_colon() {
        let artifact = Artifact::Common(CommonArtifact::Other("CloudSync".to_string()));
        let text = artifact.to_string();
        assert_eq!(artifact_from_str(&text), artifact);
    }

    #[test]
    fn linux_other_survives_roundtrip_without_double_colon() {
        let artifact = Artifact::Linux(LinuxArtifacts::Other("docker".to_string()));
        let text = artifact.to_string();
        assert_eq!(artifact_from_str(&text), artifact);
    }

    #[test]
    fn other_os_bare_token_preserves_text() {
        let other = other_artifact_from_str("Solaris");
        assert_eq!(&*other.os, "Solaris");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_json_roundtrip() {
        let artifact = Artifact::MacOs(MacArtifacts::Tcc);
        let json = serde_json::to_string(&artifact).expect("serialize");
        let parsed: Artifact = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, artifact);
    }
}
