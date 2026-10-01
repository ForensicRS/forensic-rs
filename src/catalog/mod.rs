//! Artifact *locations*: where on a host an artifact lives, as opposed to
//! [`crate::provenance::Locus`], which is where inside a source a record
//! was read.
//!
//! The vocabulary follows the ForensicArtifacts definition format
//! (<https://github.com/ForensicArtifacts/artifacts>): an
//! [`ArtifactDefinition`] names a set of [`ArtifactSource`]s (file globs,
//! registry keys and values, WMI queries, commands, or other definitions),
//! with `%%placeholder%%` parameters for per-host values. The data itself
//! lives outside this crate (`frnsc-artifacts`); parsers only name the
//! definitions they consume, through
//! [`Requirement::Artifact`](crate::traits::forensic::Requirement::Artifact).
//!
//! - [`ArtifactCatalog`] looks definitions up by name or alias.
//! - [`SliceCatalog`] implements it over a sorted slice, built at run time
//!   or from `static` data.
//! - [`expand`] turns a definition into concrete glob and registry-key
//!   patterns for one host, using its [`HostProfile`](crate::host_profile::HostProfile).
//!
//! Every type is built from `Cow<'static, ..>`, so generated code can
//! declare whole catalogs as `static` items.

use std::borrow::Cow;

use crate::field::Text;

mod expand;
mod resolve;
mod slice;
#[cfg(test)]
mod tests;

pub use expand::{
    ExpandedGlob, ExpandedKey, ExpandedValue, Expansion, GLOBSTAR_DEFAULT_DEPTH, UnresolvedSource,
    expand,
};
pub use resolve::{
    ArtifactResolution, ResolvedFile, ResolvedKey, ResolvedValue, resolve_expansion,
};
pub use slice::{CatalogIndexEntry, SliceCatalog};

/// An operating system, as named by a definition's `supported_os`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Os {
    Windows,
    Linux,
    Darwin,
    Esxi,
    Android,
    Ios,
}

impl Os {
    /// The name the definition format uses (`Windows`, `Darwin`, `iOS`, ..).
    pub const fn as_str(self) -> &'static str {
        match self {
            Os::Windows => "Windows",
            Os::Linux => "Linux",
            Os::Darwin => "Darwin",
            Os::Esxi => "ESXi",
            Os::Android => "Android",
            Os::Ios => "iOS",
        }
    }

    /// Parses a definition-format name, ignoring ASCII case.
    pub fn from_name(name: &str) -> Option<Self> {
        [
            Os::Windows,
            Os::Linux,
            Os::Darwin,
            Os::Esxi,
            Os::Android,
            Os::Ios,
        ]
        .into_iter()
        .find(|os| os.as_str().eq_ignore_ascii_case(name))
    }
}

impl std::fmt::Display for Os {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The path segment separator a `FILE` or `PATH` source is written with.
/// The definition format defaults to `/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Separator {
    #[default]
    Slash,
    Backslash,
}

impl Separator {
    pub const fn as_char(self) -> char {
        match self {
            Separator::Slash => '/',
            Separator::Backslash => '\\',
        }
    }
}

/// One `key` + `value` pair of a `REGISTRY_VALUE` source.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegistryValueRef {
    pub key: Text,
    pub value: Text,
}

/// Where one part of an artifact lives. Mirrors the definition format's
/// source types.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ArtifactSource {
    /// `FILE`: file path globs, possibly with `%%placeholders%%`.
    File {
        paths: Cow<'static, [Text]>,
        separator: Separator,
    },
    /// `PATH`: directory path globs.
    Path {
        paths: Cow<'static, [Text]>,
        separator: Separator,
    },
    /// `REGISTRY_KEY`: key path patterns.
    RegistryKey { keys: Cow<'static, [Text]> },
    /// `REGISTRY_VALUE`: named values under key path patterns.
    RegistryValue {
        pairs: Cow<'static, [RegistryValueRef]>,
    },
    /// `WMI`: a WQL query. Only resolvable on a live host.
    Wmi {
        query: Text,
        base_object: Option<Text>,
    },
    /// `COMMAND`: a command to run. Only resolvable on a live host.
    Command {
        cmd: Text,
        args: Cow<'static, [Text]>,
    },
    /// `ARTIFACT_GROUP`: other definitions, by name.
    Group { names: Cow<'static, [Text]> },
}

/// A source plus the operating systems it applies to (empty: every OS the
/// definition supports).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourceEntry {
    pub source: ArtifactSource,
    pub supported_os: Cow<'static, [Os]>,
}

/// A named artifact and where it lives.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArtifactDefinition {
    pub name: Text,
    pub aliases: Cow<'static, [Text]>,
    pub doc: Text,
    pub sources: Cow<'static, [SourceEntry]>,
    /// Empty: every OS.
    pub supported_os: Cow<'static, [Os]>,
    pub urls: Cow<'static, [Text]>,
}

impl ArtifactDefinition {
    /// Whether the definition applies to `os`.
    pub fn supports(&self, os: Os) -> bool {
        self.supported_os.is_empty() || self.supported_os.contains(&os)
    }
}

impl SourceEntry {
    /// Whether the source applies to `os`.
    pub fn supports(&self, os: Os) -> bool {
        self.supported_os.is_empty() || self.supported_os.contains(&os)
    }
}

/// A set of artifact definitions, looked up by name or alias.
///
/// Implementations must be deterministic: [`iter`](Self::iter) yields in a
/// stable order, and lookups never depend on hash order.
pub trait ArtifactCatalog: Send + Sync {
    /// The definition named `name`, or the one that has `name` as an alias.
    fn get(&self, name: &str) -> Option<&ArtifactDefinition>;
    /// Every definition, in a stable order.
    fn iter(&self) -> Box<dyn Iterator<Item = &ArtifactDefinition> + '_>;
}
