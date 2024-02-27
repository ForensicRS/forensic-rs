use std::{borrow::Cow, fmt::Display};

pub type ForensicResult<T> = Result<T, ForensicError>;

/// Cannot parse certain data because the format is invalid
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadFormatError(Cow<'static, str>);

impl  Display for BadFormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// The expected content cannot be found
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingError(Cow<'static, str>);

impl std::fmt::Display for MissingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug)]
pub enum ForensicError {
    PermissionError,
    NoMoreData,
    Other(String),
    Missing(MissingError),
    BadFormat(BadFormatError),
    Io(std::io::Error),
    CastError,
    IllegalTimestamp(String)
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
            Self::IllegalTimestamp(reason) => Self::IllegalTimestamp(reason.clone()),
        }
    }
}

impl PartialEq for ForensicError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Other(l0), Self::Other(r0)) => l0 == r0,
            (Self::Missing(l0), Self::Missing(r0)) => l0 == r0,
            (Self::BadFormat(l0), Self::BadFormat(r0)) => l0 == r0,
            (Self::PermissionError, Self::PermissionError) => true,
            (Self::NoMoreData, Self::NoMoreData) => true,
            (Self::CastError, Self::CastError) => true,
            (Self::IllegalTimestamp(l0), Self::IllegalTimestamp(r0)) => l0 == r0,
            _ => false
        }
    }
}
impl Eq for ForensicError {}

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

impl std::fmt::Display for ForensicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForensicError::PermissionError => f.write_str("Not enough permissions"),
            ForensicError::NoMoreData => f.write_str("No more content/data/files"),
            ForensicError::Other(e) => f.write_fmt(format_args!("An error ocurred: {}", e)),
            ForensicError::Missing(e) => f.write_fmt(format_args!("A file/data cannot be found: {}", e)),
            ForensicError::BadFormat(e) => f.write_fmt(format_args!("The data have an unexpected format: {}", e)),
            ForensicError::Io(e) => f.write_fmt(format_args!("IO operations error: {}", e)),
            ForensicError::CastError => f.write_str("The Into/Form operation cannot be executed"),
            ForensicError::IllegalTimestamp(reason) => f.write_fmt(format_args!("Illegal timestamp: '{reason}'"))
        }
    }
}

impl std::error::Error for ForensicError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }

    fn description(&self) -> &str {
        match self {
            ForensicError::PermissionError => "Not enough permissions",
            ForensicError::NoMoreData => "No more content/data/files",
            ForensicError::Other(e) => e,
            ForensicError::Missing(e) => &e.0,
            ForensicError::BadFormat(e) => &e.0,
            ForensicError::Io(_) => "IO operations error",
            ForensicError::CastError => "The Into/Form operation cannot be executed",
            ForensicError::IllegalTimestamp(_) => "Illegal timestamp"
        }
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.source()
    }
    
}

#[test]
fn error_compatible_with_anyhow() {
    fn this_returns_error() -> anyhow::Result<u64> {
        let value = second_function()?;
        Ok(value)
    }
    fn second_function() -> ForensicResult<u64> {
        Err(ForensicError::bad_format_str("Invalid prefetch format"))
    }

    let error = this_returns_error().unwrap_err();
    let frns_err = error.downcast_ref::<ForensicError>().unwrap();
    assert_eq!(&ForensicError::bad_format_str("Invalid prefetch format"), frns_err);
}