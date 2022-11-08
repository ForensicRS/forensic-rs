use crate::{prelude::ForensicData, activity::ForensicActivity};


pub trait Forensicable {
    fn to_timeline(&self) -> Option<(i64, ForensicData)>;
    fn to_activity(&self) -> Option<(i64, ForensicActivity)>;
}