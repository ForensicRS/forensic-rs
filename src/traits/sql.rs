use crate::prelude::ForensicResult;

/// It allows decoupling the SQL database access library from the analysis library.
pub trait SqlStatement {
    /// Return the number of columns.
    fn column_count(&self) -> usize;
    /// Return the name of a column. The first column has index 0.
    fn column_name(&self, i: usize) -> &str;
    /// Return column names.
    fn column_names(&self) -> Vec<&str>;
    /// Return the type of a column. The first column has index 0.
    fn column_type(&self, i: usize) -> ColumnType;
    /// Advance to the next state until there no more data is available (return=Ok(false)).
    fn next(&mut self) -> ForensicResult<bool>;
    /// If supported, convert the row to a struct that implements Deserialized
    fn read<T: SqlValueInto>(&self, i: usize) -> ForensicResult<T>;
    /// Read a value from a column. The first column has index 0.
    fn read_value(&self, i: usize) -> ForensicResult<ColumnValue>;
}

pub trait SqlValueInto: Sized {
    fn into(value: &ColumnValue) -> ForensicResult<Self>;
    fn into_owned(value: ColumnValue) -> ForensicResult<Self>;
}

pub enum ColumnType {
    Binary,
    Float,
    Integer,
    String,
    Null,
}

pub enum ColumnValue {
    Binary(Vec<u8>),
    Float(f64),
    Integer(i64),
    String(String),
    Null,
}

impl SqlValueInto for String {
    fn into(value: &ColumnValue) -> ForensicResult<Self> {
        Ok(match value {
            ColumnValue::String(v) => v.clone(),
            ColumnValue::Binary(v) => format!("{:?}",v),
            ColumnValue::Float(v) => format!("{:?}",v),
            ColumnValue::Integer(v) => format!("{:?}",v),
            ColumnValue::Null => String::new()
        })
    }

    fn into_owned(value: ColumnValue) -> ForensicResult<Self> {
        Ok(match value {
            ColumnValue::String(v) => v,
            ColumnValue::Binary(v) => format!("{:?}",v),
            ColumnValue::Float(v) => format!("{:?}",v),
            ColumnValue::Integer(v) => format!("{:?}",v),
            ColumnValue::Null => String::new()
        })
    }
}
impl SqlValueInto for i64 {
    fn into(value: &ColumnValue) -> ForensicResult<Self> {
        match value {
            ColumnValue::Integer(v) => Ok(*v),
            _ => Err(crate::prelude::ForensicError::BadFormat)
        }
    }

    fn into_owned(value: ColumnValue) -> ForensicResult<Self> {
        match value {
            ColumnValue::Integer(v) => Ok(v),
            _ => Err(crate::prelude::ForensicError::BadFormat)
        }
    }
}

impl SqlValueInto for usize {
    fn into(value: &ColumnValue) -> ForensicResult<Self> {
        match value {
            ColumnValue::Integer(v) => Ok(*v as usize),
            _ => Err(crate::prelude::ForensicError::BadFormat)
        }
    }

    fn into_owned(value: ColumnValue) -> ForensicResult<Self> {
        match value {
            ColumnValue::Integer(v) => Ok(v as usize),
            _ => Err(crate::prelude::ForensicError::BadFormat)
        }
    }
}

impl SqlValueInto for f64 {
    fn into(value: &ColumnValue) -> ForensicResult<Self> {
        match value {
            ColumnValue::Float(v) => Ok(*v),
            _ => Err(crate::prelude::ForensicError::BadFormat)
        }
    }

    fn into_owned(value: ColumnValue) -> ForensicResult<Self> {
        match value {
            ColumnValue::Float(v) => Ok(v),
            _ => Err(crate::prelude::ForensicError::BadFormat)
        }
    }
}

impl SqlValueInto for Vec<u8> {
    fn into(value: &ColumnValue) -> ForensicResult<Self> {
        match value {
            ColumnValue::Binary(v) => Ok(v.clone()),
            _ => Err(crate::prelude::ForensicError::BadFormat)
        }
    }

    fn into_owned(value: ColumnValue) -> ForensicResult<Self> {
        match value {
            ColumnValue::Binary(v) => Ok(v),
            _ => Err(crate::prelude::ForensicError::BadFormat)
        }
    }
}


#[cfg(test)]
mod sql_tests {
    extern crate sqlite;
    use crate::prelude::{ForensicResult, ForensicError};
    use self::sqlite::{Connection, Statement};
    use super::{SqlStatement, ColumnValue};

    struct SqliteWrapper<'a> {
        conn: Statement<'a>,
    }
    impl<'a> SqliteWrapper<'a>{
        pub fn new(conn: Statement<'a>) -> Self{
            Self { conn }
        }
    }

    impl SqlStatement for SqliteWrapper<'_> {
        fn column_count(&self) -> usize {
            self.conn.column_count()
        }

        fn column_name(&self, i: usize) -> &str {
            self.conn.column_name(i)
        }

        fn column_names(&self) -> Vec<&str> {
            self.conn.column_names()
        }

        fn column_type(&self, i: usize) -> super::ColumnType {
            match self.conn.column_type(i) {
                sqlite::Type::Binary => super::ColumnType::Binary,
                sqlite::Type::Float => super::ColumnType::Float,
                sqlite::Type::Integer => super::ColumnType::Integer,
                sqlite::Type::String => super::ColumnType::String,
                sqlite::Type::Null => super::ColumnType::Null,
            }
        }

        fn next(&mut self) -> ForensicResult<bool> {
            match self.conn.next() {
                Ok(v) => Ok(match v {
                    sqlite::State::Row => true,
                    sqlite::State::Done => false,
                }),
                Err(e) => Err(ForensicError::Other(e.to_string())),
            }
        }

        fn read<T: super::SqlValueInto>(&self, i: usize) -> ForensicResult<T> {
            T::into_owned(self.read_value(i)?)
        }

        fn read_value(&self, i: usize) -> ForensicResult<ColumnValue> {
            match self.conn.column_type(i) {
                sqlite::Type::Binary => match self.conn.read(i) {
                    Ok(v) => Ok(ColumnValue::Binary(v)),
                    Err(e) => Err(ForensicError::Other(e.to_string())),
                },
                sqlite::Type::Float => match self.conn.read(i) {
                    Ok(v) => Ok(ColumnValue::Float(v)),
                    Err(e) => Err(ForensicError::Other(e.to_string())),
                },
                sqlite::Type::Integer => match self.conn.read(i) {
                    Ok(v) => Ok(ColumnValue::Integer(v)),
                    Err(e) => Err(ForensicError::Other(e.to_string())),
                },
                sqlite::Type::String => match self.conn.read(i) {
                    Ok(v) => Ok(ColumnValue::String(v)),
                    Err(e) => Err(ForensicError::Other(e.to_string())),
                },
                sqlite::Type::Null => Ok(ColumnValue::Null),
            }
            
        }
    }

    fn prepare_db() -> Connection {
        let connection = sqlite::open(":memory:").unwrap();
        connection
            .execute(
                "
            CREATE TABLE users (name TEXT, age INTEGER);
            INSERT INTO users VALUES ('Alice', 42);
            INSERT INTO users VALUES ('Bob', 69);
            ",
            )
            .unwrap();
        connection
    }

    fn prepare_statement<'a>(conn: &'a Connection, st: &'a str) -> Statement<'a> {
        conn.prepare(st).unwrap()
    }

    #[test]
    fn test_sqlite_wrapper() {
        let conn = prepare_db();
        let statement = prepare_statement(&conn, "SELECT name, age FROM users;");
        let mut wrap = SqliteWrapper::new(statement);
        test_database_content(&mut wrap);
    }

    fn test_database_content(wrap : &mut impl SqlStatement) {
        assert!(wrap.next().unwrap());
        let name : String = wrap.read(0).unwrap();
        let age : usize = wrap.read(1).unwrap();
        assert_eq!("Alice", name);
        assert_eq!(42, age);
        assert!(wrap.next().unwrap());
        let name : String = wrap.read(0).unwrap();
        let age : usize = wrap.read(1).unwrap();
        assert_eq!("Bob", name);
        assert_eq!(69, age);
        assert!(!wrap.next().unwrap());
    }
}
