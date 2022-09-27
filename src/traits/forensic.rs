use crate::prelude::ForensicData;


pub trait Forensicable {
    fn to_timeline(&self) -> Option<(i64, ForensicData)>;
}