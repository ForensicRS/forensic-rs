use crate::{prelude::ForensicData, activity::ForensicActivity};


pub trait Forensicable{
    fn to_timeline(&self) -> Option<(i64, ForensicData)>;
    fn to_activity(&self) -> Option<(i64, ForensicActivity)>;
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