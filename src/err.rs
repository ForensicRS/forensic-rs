pub type ForensicResult<T> = Result<T, ForensicError>;

#[derive(Debug)]
pub enum ForensicError {
    PermissionError,
    NoMoreData,
    Other(String),
    Missing,
    BadFormat,
    Io(std::io::Error)
}

impl Clone for ForensicError {
    fn clone(&self) -> Self {
        match self {
            Self::PermissionError => Self::PermissionError,
            Self::NoMoreData => Self::NoMoreData,
            Self::Other(arg0) => Self::Other(arg0.clone()),
            Self::Missing => Self::Missing,
            Self::BadFormat => Self::BadFormat,
            Self::Io(e) => Self::Io(std::io::Error::new(e.kind().clone(), e.to_string())),
        }
    }
}

impl From<std::io::Error> for ForensicError {
    fn from(e: std::io::Error) -> Self {
        ForensicError::Io(e)
    }
}