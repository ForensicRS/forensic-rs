pub type ForensicResult<T> = Result<T, ForensicError>;

#[derive(Clone, Debug)]
pub enum ForensicError {
    PermissionError,
    NoMoreData,
    Other(String),
    Missing,
    BadFormat,
    Io(String)
}