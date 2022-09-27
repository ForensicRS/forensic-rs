use std::{collections::BTreeMap};

use crate::prelude::ForensicError;

#[derive(Default)]
pub struct Bitacora<T : Default> {
    pub data : T,
    pub errors : BTreeMap<String, Vec<(String, ForensicError)>>
}

impl<T : Default> Bitacora <T> {
    pub fn new( data : T) -> Self {
        Self { data, errors: BTreeMap::default() }
    }

    pub fn error(parser : &str, element : String, err: ForensicError) -> Self {
        let mut errors = BTreeMap::default();
        errors.insert(parser.to_string(), vec![(element, err)]);
        Self {
            data : T::default(),
            errors
        }
    }

    pub fn copy_errors(&mut self, errors : &mut BTreeMap<String, Vec<(String, ForensicError)>>) {
        self.errors.append(errors);
    }

    pub fn add_error(&mut self, parser : &str, element : String, err : ForensicError) {
        let mut error_list = match self.errors.remove(parser) {
            Some(v) => v,
            None => vec![]
        };
        error_list.push((element, err));
        self.errors.insert(parser.to_string(), error_list);
    }
    pub fn add_errors(&mut self, parser : &str, mut errors : Vec<(String, ForensicError)>) {
        let mut error_list = match self.errors.remove(parser) {
            Some(v) => v,
            None => vec![]
        };
        error_list.append(&mut errors);
        self.errors.insert(parser.to_string(), error_list);
    }

    pub fn copy(&mut self, other : &Self) {
        for (parser_name, error_list) in &other.errors {
            if !self.errors.contains_key(parser_name) {
                self.errors.insert(parser_name.to_string(), error_list.clone());
            }else{
                let mut data = self.errors.remove(parser_name).unwrap_or_else(|| vec![]);
                for error in error_list {
                    data.push(error.clone());
                }
                self.errors.insert(parser_name.to_string(), data);
            }
        }
    }
    pub fn join(&mut self, other : Self) {
        for (parser_name, error_list) in other.errors {
            if !self.errors.contains_key(&parser_name) {
                self.errors.insert(parser_name, error_list);
            }else{
                let mut data = self.errors.remove(&parser_name).unwrap_or_else(|| vec![]);
                for error in error_list {
                    data.push(error);
                }
                self.errors.insert(parser_name, data);
            }
        }
    }
}