use crate::{prelude::ForensicResult, err::ForensicError};

use super::vfs::VirtualFile;

pub trait SqlDb {
    fn list_tables(&self) -> ForensicResult<Vec<String>>;
    fn prepare<'a>(&'a self, statement : &'a str) -> ForensicResult<Box<dyn SqlStatement + 'a>>;
    /// Mounts a SQL reader from a sqlite file
    fn from_file(&self, file: Box<dyn VirtualFile>) -> ForensicResult<Box<dyn SqlDb>>;
}

/// It allows decoupling the SQL database access library from the analysis library.
pub trait SqlStatement {
    /// Return the number of columns.
    fn column_count(&self) -> usize;
    /// Return the name of a column. The first column has index 0.
    fn column_name(&self, i: usize) -> Option<&str>;
    /// Return column names.
    fn column_names(&self) -> Vec<&str>;
    /// Return the type of a column. The first column has index 0.
    fn column_type(&self, i: usize) -> ColumnType;
    /// Advance to the next state until there no more data is available (return=Ok(false)).
    fn next(&mut self) -> ForensicResult<bool>;
    /// Read a value from a column. The first column has index 0.
    fn read(&self, i: usize) -> ForensicResult<ColumnValue>;
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

impl TryInto<String> for ColumnValue {
    type Error = ForensicError;

    fn try_into(self) -> Result<String, Self::Error> {
        Ok(match self {
            ColumnValue::String(v) => v.clone(),
            ColumnValue::Binary(v) => format!("{:?}",v),
            ColumnValue::Float(v) => format!("{:?}",v),
            ColumnValue::Integer(v) => format!("{:?}",v),
            ColumnValue::Null => String::new()
        })
    }
}

impl TryInto<i64> for ColumnValue {
    type Error = ForensicError;

    fn try_into(self) -> Result<i64, Self::Error> {
        match self {
            ColumnValue::Integer(v) => Ok(v),
            _ => Err(ForensicError::BadFormat)
        }
    }
}

impl TryInto<usize> for ColumnValue {
    type Error = ForensicError;

    fn try_into(self) -> Result<usize, Self::Error> {
        match self {
            ColumnValue::Integer(v) => Ok(v as usize),
            _ => Err(ForensicError::BadFormat)
        }
    }
}

impl TryInto<f64> for ColumnValue {
    type Error = ForensicError;

    fn try_into(self) -> Result<f64, Self::Error> {
        match self {
            ColumnValue::Float(v) => Ok(v),
            _ => Err(ForensicError::BadFormat)
        }
    }
}

impl TryInto<Vec<u8>> for ColumnValue {
    type Error = ForensicError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        match self {
            ColumnValue::Binary(v) => Ok(v),
            _ => Err(ForensicError::BadFormat)
        }
    }
}


#[cfg(test)]
mod sql_tests {
    extern crate sqlite;

    use crate::prelude::{ForensicResult, ForensicError};
    use self::sqlite::{Connection, Statement};
    use super::{SqlStatement, ColumnValue, SqlDb};

    struct SqliteWDB {
        conn : Connection
    }

    impl SqliteWDB{
        pub fn new(conn : Connection) -> SqliteWDB {
            SqliteWDB {
                conn
            }
        }
    }

    impl SqlDb for SqliteWDB {
        fn prepare<'a>(&'a self, statement : &'a str) -> ForensicResult<Box<dyn SqlStatement +'a>> {
            Ok(Box::new(SqliteStatement::new( &self.conn, statement)?))
        }

        fn from_file(&self, _file: Box<dyn crate::traits::vfs::VirtualFile>) -> ForensicResult<Box<dyn SqlDb>> {
            match sqlite::open(":memory:") {
                Ok(v) => Ok(Box::new(Self::new(v))),
                Err(e) => Err(ForensicError::Other(e.to_string()))
            }
        }

        fn list_tables(&self) -> ForensicResult<Vec<String>> {
            let mut ret = Vec::with_capacity(32);
            let mut sts = self.prepare(r#"SELECT 
            name
        FROM 
            sqlite_schema
        WHERE 
            type ='table' AND 
            name NOT LIKE 'sqlite_%';"#)?;
            loop {
                if !sts.next()? {
                    break;
                }
                let name : String = sts.read(0)?.try_into()?;
                ret.push(name);
            }
            Ok(ret)
        }
    }

    pub struct SqliteStatement<'conn> {
        stmt: Statement<'conn>
    }
    impl<'conn> SqliteStatement<'conn>{
        pub fn new(conn : &'conn Connection, statement : &str) -> ForensicResult<SqliteStatement<'conn>>{
            Ok(Self { stmt : match conn.prepare(statement) {
                    Ok(st) => st,
                    Err(e) => return Err(ForensicError::Other(e.to_string()))
                }
            })
        }
    }

    impl<'conn> SqlStatement for SqliteStatement<'conn>{
        fn column_count(&self) -> usize {
            self.stmt.column_count()
        }

        fn column_name(&self, i: usize) -> Option<&str> {
            Some(self.stmt.column_name(i))
        }

        fn column_names(&self) -> Vec<&str> {
            self.stmt.column_names()
        }

        fn column_type(&self, i: usize) -> super::ColumnType {
            match self.stmt.column_type(i) {
                sqlite::Type::Binary => super::ColumnType::Binary,
                sqlite::Type::Float => super::ColumnType::Float,
                sqlite::Type::Integer => super::ColumnType::Integer,
                sqlite::Type::String => super::ColumnType::String,
                sqlite::Type::Null => super::ColumnType::Null,
            }
        }

        fn next(&mut self) -> ForensicResult<bool> {
            match self.stmt.next() {
                Ok(v) => Ok(match v {
                    sqlite::State::Row => true,
                    sqlite::State::Done => false,
                }),
                Err(e) => Err(ForensicError::Other(e.to_string())),
            }
        }

        fn read(&self, i: usize) -> ForensicResult<ColumnValue> {
            match self.stmt.column_type(i) {
                sqlite::Type::Binary => match self.stmt.read(i) {
                    Ok(v) => Ok(ColumnValue::Binary(v)),
                    Err(e) => Err(ForensicError::Other(e.to_string())),
                },
                sqlite::Type::Float => match self.stmt.read(i) {
                    Ok(v) => Ok(ColumnValue::Float(v)),
                    Err(e) => Err(ForensicError::Other(e.to_string())),
                },
                sqlite::Type::Integer => match self.stmt.read(i) {
                    Ok(v) => Ok(ColumnValue::Integer(v)),
                    Err(e) => Err(ForensicError::Other(e.to_string())),
                },
                sqlite::Type::String => match self.stmt.read(i) {
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
    fn prepare_wrapper(connection :Connection) -> SqliteWDB{
        SqliteWDB::new(connection)
    }


    #[test]
    fn test_sqlite_wrapper() {
        let conn = prepare_db();
        let w_conn = prepare_wrapper(conn);
        let mut statement = w_conn.prepare("SELECT name, age FROM users;").unwrap();
        test_database_content(statement.as_mut()).expect("Should not return error");
        
    }

    fn test_database_content<'a>(statement : &mut dyn SqlStatement) -> ForensicResult<()> {
        assert!(statement.next()?);
        let name : String = statement.read(0)?.try_into()?;
        let age : usize = statement.read(1)?.try_into()?;
        assert_eq!("Alice", name);
        assert_eq!(42, age);
        assert!(statement.next()?);
        let name : String = statement.read(0)?.try_into()?;
        let age : usize = statement.read(1)?.try_into()?;
        assert_eq!("Bob", name);
        assert_eq!(69, age);
        assert!(!statement.next()?);
        Ok(())
    }
}
