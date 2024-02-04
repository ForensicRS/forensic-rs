use std::borrow::Cow;

use crate::{prelude::ForensicData, activity::ForensicActivity};


pub trait Forensicable {
    /// A processed forensic artifact entry struct that implements forensicable can be transformed into a list of events/logs/data with a
    fn to_timeline(&self) -> Option<Vec<TimelineData>>;
    fn to_activity(&self) -> Option<Vec<ActivityData>>;
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
    pub time : i64,
    pub data : ForensicData,
    pub time_context : TimeContext
}

#[derive(Clone, Debug, Default)]
pub struct ActivityData {
    pub time : i64,
    pub data : ForensicActivity,
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