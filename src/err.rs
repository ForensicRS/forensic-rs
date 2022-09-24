pub type ForensicResult<T> = Result<T, ForensicError>;

pub enum ForensicError {
    PermissionError,
    NoMoreData,
    Other(String),
    Io(std::io::Error)
}