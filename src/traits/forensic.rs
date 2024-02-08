use std::borrow::Cow;

use crate::{activity::ForensicActivity, prelude::ForensicData, utils::time::Filetime};

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
    type IntoIter: Iterator<Item = TimelineData> where Self: 'a;
    
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
    type IntoIter: Iterator<Item = ForensicActivity> where Self: 'a;
    
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

pub trait ArtifactParser : IntoIterator<Item = ForensicData>  {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn version(&self) -> &'static str;
}


pub trait RegistryParser : ArtifactParser  {
    fn valid_path(&self, pth : &str) -> bool;
    fn first_path_pattern(&self) -> &str;
}

#[cfg(test)]
mod artifacts {
    use crate::{data::ForensicData, prelude::{RegistryArtifacts, Artifact}};

    use super::ArtifactParser;

    struct Parser123 {}

    impl ArtifactParser for Parser123 {
        fn name(&self) -> &'static str {
            "parser123"
        }

        fn description(&self) -> &'static str {
            "parser123"    
        }

        fn version(&self) -> &'static str {
            "1.2.3"
        }
    }
    struct IterParser123 {}
    impl Iterator for IterParser123 {
        type Item = ForensicData;

        fn next(&mut self) -> Option<Self::Item> {
           Some(ForensicData::new("123",  RegistryArtifacts::ShellBags.into()))
        }
    }

    impl IntoIterator for Parser123 {
        type Item = ForensicData;

        type IntoIter = IterParser123;

        fn into_iter(self) -> Self::IntoIter {
            IterParser123{}
        }
    }

    #[test]
    fn should_iterate_parser() {
        let parser = Parser123{};
        let mut iter = parser.into_iter();
        let artfct : Artifact = RegistryArtifacts::ShellBags.into();
        assert_eq!(&artfct, iter.next().unwrap().artifact());

    }
}