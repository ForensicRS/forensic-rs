#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize,de::Visitor, Deserializer};

use crate::field::Text;

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Artifact {
    #[default]
    Unknown,
    Other(OtherOS),
    Windows(WindowsArtifacts),
    Linux(LinuxArtifacts),
    MacOs(MacArtifacts),
    Common(CommonArtifact)
}
impl std::fmt::Display for Artifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Artifact::Unknown => write!(f, "Unknown"),
            Artifact::Other(v) => write!(f, "{}", v),
            Artifact::Windows(v) => write!(f, "Windows::{}", v),
            Artifact::Linux(v) => write!(f, "Linux::{}", v),
            Artifact::MacOs(v) => write!(f, "Mac::{}", v),
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
    Unknown,
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
    Unknown,
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
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum LinuxArtifacts {
    Log(String),
    ShellHistory(String),
    Cron(String),
    Service(LinuxService),
    Other(String),
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum LinuxService {
    SysV,
    InitD,
    SystemD,
    Other(String),
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum MacArtifacts {
    Other(String),
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum CommonArtifact {
    WebBrowsing(WebBrowsingArtifact),
    Other(String),
    #[default]
    Unknown,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
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

impl std::fmt::Display for LinuxArtifacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinuxArtifacts::Log(v) => write!(f, "Log::{}", v),
            LinuxArtifacts::ShellHistory(v) => write!(f, "ShellHistory::{}", v),
            LinuxArtifacts::Cron(v) => write!(f, "Cron::{}", v),
            LinuxArtifacts::Service(v) => write!(f, "Service::{}", v),
            LinuxArtifacts::Other(v) => write!(f, "{}", v),
            LinuxArtifacts::Unknown => write!(f, "Log::Unknown"),
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
            RegistryArtifacts::ShimCache => write!(f, "InitD"),
            RegistryArtifacts::ShellBags => write!(f, "ShellBags"),
            RegistryArtifacts::AutoRuns => write!(f, "AutoRuns"),
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
            WindowsArtifacts::Unknown => write!(f, "Unknown"),
        }
    }
}

impl std::fmt::Display for MacArtifacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
            WebBrowsingArtifact::BrowserHistory  => write!(f, "BrowserHistory"),
            WebBrowsingArtifact::BrowserStorage  => write!(f, "BrowserStorage"),
            WebBrowsingArtifact::BrowserCache  => write!(f, "BrowserCache"),
            WebBrowsingArtifact::Cookie  => write!(f, "Cookie"),
            WebBrowsingArtifact::Extension  => write!(f, "Extension"),
            WebBrowsingArtifact::ExtensionActivity  => write!(f, "ExtensionActivity"),
            WebBrowsingArtifact::FileSystem  => write!(f, "FileSystem"),
            WebBrowsingArtifact::LocalStorage  => write!(f, "LocalStorage"),
            WebBrowsingArtifact::Preferences  => write!(f, "Preferences"),
            WebBrowsingArtifact::SessionStorage  => write!(f, "SessionStorage"),
            WebBrowsingArtifact::Download  => write!(f, "Download"),
            WebBrowsingArtifact::RSSFeed  => write!(f, "RSSFeed"),
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
struct LinuxServiceVisitor;
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
struct WindowsArtifactVisitor;
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
struct WinEvtVisitor;
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
struct RegistryArtifactsVisitor;
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
struct OtherOsVisitor;
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
struct LinuxArtifactVisitor;
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
struct MacOsArtifactVisitor;
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
            Some(v) => (&txt[0..v], &txt[v+2..]),
            None => (txt, "")
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

pub fn artifact_from_str(txt : &str) -> Artifact {
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
pub fn windows_artifacts_from_str(txt : &str) -> WindowsArtifacts {
    let (artifact, subartifact) = match txt.find("::") {
        Some(v) => (&txt[0..v], &txt[v+2..]),
        None => (&txt[..], ""),
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
        _ => WindowsArtifacts::Other(subartifact.to_string())
    }
}

pub fn registry_artifacts_from_str(txt : &str) -> RegistryArtifacts {
    match txt {
        "Unknown" => RegistryArtifacts::Unknown,
        "ShimCache" => RegistryArtifacts::ShimCache,
        "ShellBags" => RegistryArtifacts::ShellBags,
        "AutoRuns" => RegistryArtifacts::AutoRuns,
        _ => RegistryArtifacts::Other(txt.to_string())
    }
}

pub fn winevt_artifacts_from_str(txt : &str) -> WindowsEvents {
    match txt {
        "Unknown" => WindowsEvents::Unknown,
        "Sysmon" => WindowsEvents::Sysmon,
        "System" => WindowsEvents::System,
        "Security" => WindowsEvents::Security,
        _ => WindowsEvents::Other(txt.to_string())
    }
}

pub fn linux_artifacts_from_str(txt : &str) -> LinuxArtifacts {
    let (artifact, subartifact) = match txt.find("::") {
        Some(v) => (&txt[0..v], &txt[v+2..]),
        None => return LinuxArtifacts::Unknown
    };
    match artifact {
        "Log" => LinuxArtifacts::Log(subartifact.to_string()),
        "ShellHistory" => LinuxArtifacts::ShellHistory(subartifact.to_string()),
        "Cron" => LinuxArtifacts::Cron(subartifact.to_string()),
        "Service" => LinuxArtifacts::Service(linux_service_from_str(txt)),
        _ => LinuxArtifacts::Other(subartifact.to_string()),
    }
}
pub fn linux_service_from_str(txt : &str) -> LinuxService {
    match txt {
        "SysV" => LinuxService::SysV,
        "InitD" => LinuxService::InitD,
        "SystemD" => LinuxService::SystemD,
        "Unknown" => LinuxService::Unknown,
        _ => LinuxService::Other(txt.to_string())
    }
}

pub fn mac_artifact_from_str(txt : &str) -> MacArtifacts {
    match txt {
        "Unknown" => MacArtifacts::Unknown,
        _ => MacArtifacts::Other(txt.to_string())
    }
}
pub fn common_artifact_from_str(txt : &str) -> CommonArtifact {
    let (artifact, subartifact) = match txt.find("::") {
        Some(v) => (&txt[0..v], &txt[v+2..]),
        None => return CommonArtifact::Unknown
    };
    match artifact {
        "Unknown" => CommonArtifact::Unknown,
        "WebBrowsing" => CommonArtifact::WebBrowsing(webbrowsing_artifact_from_str(subartifact)),
        _ => CommonArtifact::Other(txt.to_string())
    }
}
pub fn webbrowsing_artifact_from_str(txt : &str) -> WebBrowsingArtifact {
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
        _ => WebBrowsingArtifact::Other(txt.to_string())
    }
}
pub fn other_artifact_from_str(txt : &str) -> OtherOS {
    let (os, subartifact) = match txt.find("::") {
        Some(v) => (&txt[0..v], &txt[v+2..]),
        None =>  return OtherOS { os: std::borrow::Cow::Owned("Unknown".to_string()), artifact: std::borrow::Cow::Owned("Unknown".to_string()) }
    };
    OtherOS { os: std::borrow::Cow::Owned(os.to_string()), artifact: std::borrow::Cow::Owned(subartifact.to_string()) }
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