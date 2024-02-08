use std::{borrow::Cow, fmt::Display};
use thiserror::Error;

pub type ForensicResult<T> = Result<T, ForensicError>;

/// Cannot parse certain data because the format is invalid
#[derive(Debug, Clone)]
pub struct BadFormatError(Cow<'static, str>);

impl  Display for BadFormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// The expected content cannot be found
#[derive(Debug, Clone)]
pub struct MissingError(Cow<'static, str>);

#[derive(Error, Debug)]
pub enum ForensicError {
    #[error("Not enough permissions")]
    PermissionError,

    #[error("No more content/data/files")]
    NoMoreData,

    #[error("Some error has occured: {0}")]
    Other(String),

    #[error("A file/data cannot be found")]
    Missing(MissingError),

    #[error("The data have an unexpected format: {0}")]
    BadFormat(BadFormatError),

    #[error("IO operations error: {0}")]
    Io(std::io::Error),

    #[error("The Into/Form operation cannot executed")]
    CastError,
}

impl ForensicError {
    /// Create a BadFormatError from a static string slice
    pub fn bad_format_str(err: &'static str) -> Self {
        Self::BadFormat(BadFormatError(Cow::Borrowed(err)))
    }
    /// Create a BadFormatError from a String
    pub fn bad_format_string(err: String) -> Self {
        Self::BadFormat(BadFormatError(Cow::Owned(err)))
    }
    /// Create a MissingError from a static string slice
    pub fn missing_str(err: &'static str) -> Self {
        Self::Missing(MissingError(Cow::Borrowed(err)))
    }
    /// Create a MissingError from a String
    pub fn missing_string(err: String) -> Self {
        Self::Missing(MissingError(Cow::Owned(err)))
    }
}

impl Clone for ForensicError {
    fn clone(&self) -> Self {
        match self {
            Self::PermissionError => Self::PermissionError,
            Self::CastError => Self::CastError,
            Self::NoMoreData => Self::NoMoreData,
            Self::Other(arg0) => Self::Other(arg0.clone()),
            Self::Missing(e) => Self::Missing(e.clone()),
            Self::BadFormat(e) => Self::BadFormat(e.clone()),
            Self::Io(e) => Self::Io(std::io::Error::new(e.kind(), e.to_string())),
        }
    }
}

impl From<std::io::Error> for ForensicError {
    fn from(e: std::io::Error) -> Self {
        ForensicError::Io(e)
    }
}

impl From<MissingError> for ForensicError {
    fn from(value: MissingError) -> Self {
        ForensicError::Missing(value)
    }
}
impl From<&MissingError> for ForensicError {
    fn from(value: &MissingError) -> Self {
        ForensicError::Missing(MissingError(match &value.0 {
            Cow::Borrowed(v) => Cow::Borrowed(v),
            Cow::Owned(v) => Cow::Owned(v.clone()),
        }))
    }
}

impl From<BadFormatError> for ForensicError {
    fn from(value: BadFormatError) -> Self {
        ForensicError::BadFormat(value)
    }
}
impl From<&BadFormatError> for ForensicError {
    fn from(value: &BadFormatError) -> Self {
        ForensicError::BadFormat(BadFormatError(match &value.0 {
            Cow::Borrowed(v) => Cow::Borrowed(v),
            Cow::Owned(v) => Cow::Owned(v.clone()),
        }))
    }
}

impl From<String> for ForensicError {
    fn from(value: String) -> Self {
        ForensicError::Other(value)
    }
}
impl From<&str> for ForensicError {
    fn from(value: &str) -> Self {
        ForensicError::Other(value.to_string())
    }
}
impl From<&String> for ForensicError {
    fn from(value: &String) -> Self {
        ForensicError::Other(value.to_string())
    }
}
