
use std::borrow::Cow;
use std::fmt;
use std::ops::Deref;

/// StaticString Copy-On-Write
/// 
/// A simplified version of `Cow<'static, str>` that only works with static lifetime strings.
/// This is optimized for frequent use of static strings in error messages and other contexts
/// where most strings are known at compile time.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SCow {
    /// An owned String
    Owned(String),
    /// A borrowed static string slice
    Borrowed(&'static str),
}

impl SCow {
    /// Create a new SCow from a static string slice
    #[inline]
    pub const fn borrowed(s: &'static str) -> Self {
        Self::Borrowed(s)
    }
    
    /// Create a new SCow from an owned String
    #[inline]
    pub fn owned(s: String) -> Self {
        Self::Owned(s)
    }
    
    /// Returns true if this SCow is borrowed
    #[inline]
    pub const fn is_borrowed(&self) -> bool {
        matches!(self, Self::Borrowed(_))
    }
    
    /// Returns true if this SCow is owned
    #[inline]
    pub const fn is_owned(&self) -> bool {
        matches!(self, Self::Owned(_))
    }
    
    /// Extract the owned String, cloning if necessary
    pub fn into_owned(self) -> String {
        match self {
            Self::Owned(s) => s,
            Self::Borrowed(s) => s.to_owned(),
        }
    }
    
    /// Get a reference to the string content
    pub fn as_str(&self) -> &str {
        match self {
            Self::Owned(s) => s.as_str(),
            Self::Borrowed(s) => s,
        }
    }
    
    /// Convert to an owned String if not already owned
    pub fn to_mut(&mut self) -> &mut String {
        match self {
            Self::Owned(s) => s,
            Self::Borrowed(s) => {
                *self = Self::Owned(s.to_owned());
                match self {
                    Self::Owned(s) => s,
                    _ => unreachable!(),
                }
            }
        }
    }
}

// Deref to str for convenient access
impl Deref for SCow {
    type Target = str;
    
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

// AsRef implementations
impl AsRef<str> for SCow {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for SCow {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_str().as_bytes()
    }
}

// From implementations
impl From<&'static str> for SCow {
    #[inline]
    fn from(s: &'static str) -> Self {
        Self::Borrowed(s)
    }
}

impl From<String> for SCow {
    #[inline]
    fn from(s: String) -> Self {
        Self::Owned(s)
    }
}

impl From<&String> for SCow {
    #[inline]
    fn from(s: &String) -> Self {
        Self::Owned(s.clone())
    }
}

impl From<Cow<'static, str>> for SCow {
    fn from(cow: Cow<'static, str>) -> Self {
        match cow {
            Cow::Borrowed(s) => Self::Borrowed(s),
            Cow::Owned(s) => Self::Owned(s),
        }
    }
}

// Into implementations
impl Into<String> for SCow {
    #[inline]
    fn into(self) -> String {
        self.into_owned()
    }
}

impl Into<Cow<'static, str>> for SCow {
    fn into(self) -> Cow<'static, str> {
        match self {
            Self::Borrowed(s) => Cow::Borrowed(s),
            Self::Owned(s) => Cow::Owned(s),
        }
    }
}

// Display implementation
impl fmt::Display for SCow {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

// PartialEq with various string types
impl PartialEq<str> for SCow {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for SCow {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<String> for SCow {
    #[inline]
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other.as_str()
    }
}

impl PartialEq<SCow> for str {
    #[inline]
    fn eq(&self, other: &SCow) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<SCow> for &str {
    #[inline]
    fn eq(&self, other: &SCow) -> bool {
        *self == other.as_str()
    }
}

impl PartialEq<SCow> for String {
    #[inline]
    fn eq(&self, other: &SCow) -> bool {
        self.as_str() == other.as_str()
    }
}

impl PartialEq<&&str> for SCow {
    #[inline]
    fn eq(&self, other: &&&str) -> bool {
        self.as_str() == **other
    }
}

impl PartialEq<SCow> for &&str {
    #[inline]
    fn eq(&self, other: &SCow) -> bool {
        **self == other.as_str()
    }
}

// Default implementation
impl Default for SCow {
    #[inline]
    fn default() -> Self {
        Self::Borrowed("")
    }
}

// Convenient macros for creating SCow instances
#[macro_export]
macro_rules! scow {
    ($s:expr) => {
        $crate::scow::SCow::from($s)
    };
}

#[macro_export]
macro_rules! scow_borrowed {
    ($s:literal) => {
        $crate::scow::SCow::borrowed($s)
    };
}

#[macro_export]
macro_rules! scow_owned {
    ($s:expr) => {
        $crate::scow::SCow::owned($s)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    #[test]
    fn test_borrowed() {
        let s = SCow::borrowed("hello");
        assert!(s.is_borrowed());
        assert!(!s.is_owned());
        assert_eq!(s.as_str(), "hello");
    }

    #[test]
    fn test_owned() {
        let s = SCow::owned("world".to_string());
        assert!(s.is_owned());
        assert!(!s.is_borrowed());
        assert_eq!(s.as_str(), "world");
    }

    #[test]
    fn test_from_static_str() {
        let s = SCow::from("static");
        assert!(s.is_borrowed());
        assert_eq!(s.as_str(), "static");
    }

    #[test]
    fn test_from_string() {
        let s = SCow::from("dynamic".to_string());
        assert!(s.is_owned());
        assert_eq!(s.as_str(), "dynamic");
    }

    #[test]
    fn test_from_cow() {
        let cow_borrowed: Cow<'static, str> = Cow::Borrowed("borrowed");
        let scow = SCow::from(cow_borrowed);
        assert!(scow.is_borrowed());

        let cow_owned: Cow<'static, str> = Cow::Owned("owned".to_string());
        let scow = SCow::from(cow_owned);
        assert!(scow.is_owned());
    }

    #[test]
    fn test_into_owned() {
        let s1 = SCow::borrowed("test");
        let owned1 = s1.into_owned();
        assert_eq!(owned1, "test");

        let s2 = SCow::owned("test2".to_string());
        let owned2 = s2.into_owned();
        assert_eq!(owned2, "test2");
    }

    #[test]
    fn test_to_mut() {
        let mut s = SCow::borrowed("immutable");
        assert!(s.is_borrowed());
        
        let mutable = s.to_mut();
        mutable.push_str(" now mutable");
        
        assert!(s.is_owned());
        assert_eq!(s.as_str(), "immutable now mutable");
    }

    #[test]
    fn test_equality() {
        let scow = SCow::borrowed("test");
        
        assert_eq!(scow, "test");
        assert_eq!(scow, &"test");
        assert_eq!(scow, "test".to_string());
        
        assert_eq!("test", scow);
        assert_eq!(&"test", scow);
        assert_eq!("test".to_string(), scow);
    }

    #[test]
    fn test_display() {
        let scow = SCow::borrowed("display test");
        assert_eq!(format!("{}", scow), "display test");
    }

    #[test]
    fn test_macros() {
        let s1 = scow!("macro test");
        assert_eq!(s1.as_str(), "macro test");

        let s2 = scow_borrowed!("borrowed macro");
        assert!(s2.is_borrowed());

        let s3 = scow_owned!("owned".to_string());
        assert!(s3.is_owned());
    }

    #[test]
    fn test_deref() {
        let scow = SCow::borrowed("deref test");
        assert_eq!(scow.len(), 10); // Uses Deref to access str methods
        assert!(scow.starts_with("deref"));
    }
}