use std::borrow::Cow;

use crate::{activity::ForensicActivity, prelude::{ForensicData, ForensicResult}, utils::time::Filetime};
use crate::artifact::Artifact;
use crate::pipeline::sources::TriageSources;

/// Quickly transform a structure into one or more events that are part of a timeline
/// ```rust,ignore
/// impl<'a> IntoTimeline<'a> for PrefetchFile {
///     fn timeline(&'a self) -> Self::IntoIter {
///         PrefetchTimelineIterator {
///             prefetch : self,
///             time_pos : 0
///         }
///     }
/// 
///     type IntoIter = PrefetchTimelineIterator<'a> where Self: 'a;
/// }
/// ```
pub trait IntoTimeline<'a> {
    type IntoIter: Iterator<Item = ForensicResult<TimelineData>> where Self: 'a;
    
    fn timeline(&'a self) -> Self::IntoIter;
}

/// Quickly transform a structure into one or more user activity events. In order to know what a user did at a high level at a specific moment.
/// 
/// Example: `ForensicActivity { timestamp: 06-11-2023 15:18:00.237, user: "", session_id: Unknown, activity: ProgramExecution(\VOLUME{01d98a6b9e4a0a35-1c9e547d}\WINDOWS\SYSWOW64\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE) }`
/// 
/// ```rust,ignore
/// impl<'a> IntoActivity<'a> for PrefetchFile {
///     fn activity(&'a self) -> Self::IntoIter {
///         PrefetchActivityIterator {
///             prefetch : self,
///             time_pos : 0
///         }
///     }
/// 
///     type IntoIter = PrefetchActivityIterator<'a> where Self: 'a;
/// }
/// ```
pub trait IntoActivity<'a> {
    type IntoIter: Iterator<Item = ForensicResult<ForensicActivity>> where Self: 'a;
    
    fn activity(&'a self) -> Self::IntoIter;
}

#[derive(Clone, Debug, Default)]
pub enum TimeContext {
    #[default]
    Creation,
    Modification,
    Accessed,
    Other(Cow<'static, str>)
}

#[derive(Clone, Debug, Default)]
pub struct TimelineData {
    pub time : Filetime,
    pub data : ForensicData,
    pub time_context : TimeContext
}

/// Core trait for artifact parsers in the forensic pipeline.
///
/// An `ArtifactParser` extracts structured `ForensicData` records from forensic
/// data sources (filesystem, registry, databases). Each parser declares which
/// artifact types it handles and produces a streaming iterator of results.
///
/// # Example
/// ```rust,ignore
/// struct EvtxParser;
///
/// impl ArtifactParser for EvtxParser {
///     fn name(&self) -> &str { "evtx" }
///     fn description(&self) -> &str { "Windows Event Log parser" }
///     fn version(&self) -> &str { "1.0.0" }
///
///     fn supported_artifacts(&self) -> Vec<Artifact> {
///         vec![WindowsArtifacts::WinEvt(WindowsEvents::Unknown).into()]
///     }
///
///     fn parse(&mut self, sources: &mut TriageSources)
///         -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<ForensicData>> + '_>>
///     {
///         // Read .evtx files from the VFS and yield parsed records
///         todo!()
///     }
/// }
/// ```
pub trait ArtifactParser {
    /// Short identifier for this parser.
    fn name(&self) -> &str;
    /// Human-readable description of what this parser does.
    fn description(&self) -> &str;
    /// Semantic version of this parser implementation.
    fn version(&self) -> &str;
    /// The artifact types this parser can handle.
    fn supported_artifacts(&self) -> Vec<Artifact>;
    /// Check whether the required artifacts are present in the given sources.
    /// Returns `true` by default — override to skip parsing when artifacts are absent.
    fn can_parse(&self, _sources: &TriageSources) -> bool {
        true
    }
    /// Parse the data sources and return a streaming iterator of forensic records.
    fn parse<'a>(&'a mut self, sources: &'a mut TriageSources)
        -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<ForensicData>> + 'a>>;
}

pub trait RegistryParser : ArtifactParser {
    fn valid_path(&self, pth : &str) -> bool;
    fn first_path_pattern(&self) -> &str;
}

#[cfg(test)]
mod artifacts {
    use crate::{
        data::ForensicData,
        prelude::{RegistryArtifacts, Artifact, ForensicResult},
        pipeline::sources::TriageSources,
        core::fs::StdVirtualFS,
        utils::testing::TestingRegistry,
    };
    use super::ArtifactParser;

    struct Parser123 {
        items: Vec<ForensicResult<ForensicData>>,
    }

    impl Parser123 {
        fn new() -> Self {
            Self {
                items: vec![
                    Ok(ForensicData::new("123", RegistryArtifacts::ShellBags.into())),
                ],
            }
        }
    }

    impl ArtifactParser for Parser123 {
        fn name(&self) -> &str { "parser123" }
        fn description(&self) -> &str { "parser123" }
        fn version(&self) -> &str { "1.2.3" }

        fn supported_artifacts(&self) -> Vec<Artifact> {
            vec![RegistryArtifacts::ShellBags.into()]
        }

        fn parse<'a>(&'a mut self, _sources: &'a mut TriageSources)
            -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<ForensicData>> + 'a>>
        {
            Ok(Box::new(self.items.drain(..)))
        }
    }

    #[test]
    fn should_iterate_parser() {
        let mut parser = Parser123::new();
        let mut sources = TriageSources::new(
            Box::new(StdVirtualFS::new()),
            Box::new(TestingRegistry::new()),
        );
        let mut iter = parser.parse(&mut sources).unwrap();
        let artfct: Artifact = RegistryArtifacts::ShellBags.into();
        assert_eq!(&artfct, iter.next().unwrap().unwrap().artifact());
        assert!(iter.next().is_none());
    }
}