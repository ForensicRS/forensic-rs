use std::borrow::Cow;
use std::fmt;

use crate::err::{ForensicError, ForensicResult};
use crate::utils::time::{Filetime, ForensicTimestamp};

// ============================================================================
// Column Type
// ============================================================================

/// Column type descriptor for forensic database columns.
///
/// Maps cleanly from both SQLite affinity types and all 17 ESE column types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForensicColumnType {
    Null,
    Bool,
    U8,
    I16,
    I32,
    I64,
    U16,
    U32,
    U64,
    F32,
    F64,
    DateTime,
    Guid,
    Text,
    Binary,
}

// ============================================================================
// Column Definition
// ============================================================================

/// Describes a single column in a forensic table.
#[derive(Debug, Clone)]
pub struct ForensicColumnDef {
    pub name: String,
    pub col_type: ForensicColumnType,
    pub nullable: bool,
}

// ============================================================================
// ForensicValue (owned)
// ============================================================================

/// Owned database value — for storage, returning from functions, moving across threads.
#[derive(Debug, Clone, PartialEq)]
pub enum ForensicValue {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    F64(f64),
    DateTime(ForensicTimestamp),
    Guid([u8; 16]),
    Text(String),
    Binary(Vec<u8>),
}

impl ForensicValue {
    pub fn is_null(&self) -> bool {
        matches!(self, ForensicValue::Null)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            ForensicValue::Text(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            ForensicValue::I64(v) => Some(*v),
            ForensicValue::U64(v) => i64::try_from(*v).ok(),
            ForensicValue::Bool(v) => Some(if *v { 1 } else { 0 }),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            ForensicValue::F64(v) => Some(*v),
            ForensicValue::I64(v) => Some(*v as f64),
            ForensicValue::U64(v) => Some(*v as f64),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            ForensicValue::Binary(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ForensicValue::Bool(v) => Some(*v),
            ForensicValue::I64(v) => Some(*v != 0),
            ForensicValue::U64(v) => Some(*v != 0),
            _ => None,
        }
    }

    pub fn as_datetime(&self) -> Option<ForensicTimestamp> {
        match self {
            ForensicValue::DateTime(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_guid(&self) -> Option<[u8; 16]> {
        match self {
            ForensicValue::Guid(v) => Some(*v),
            _ => None,
        }
    }

    /// Convert to a borrowed reference form.
    pub fn as_ref(&self) -> ForensicValueRef<'_> {
        match self {
            ForensicValue::Null => ForensicValueRef::Null,
            ForensicValue::Bool(v) => ForensicValueRef::Bool(*v),
            ForensicValue::I64(v) => ForensicValueRef::I64(*v),
            ForensicValue::U64(v) => ForensicValueRef::U64(*v),
            ForensicValue::F64(v) => ForensicValueRef::F64(*v),
            ForensicValue::DateTime(v) => ForensicValueRef::DateTime(*v),
            ForensicValue::Guid(v) => ForensicValueRef::Guid(*v),
            ForensicValue::Text(v) => ForensicValueRef::Text(Cow::Borrowed(v.as_str())),
            ForensicValue::Binary(v) => ForensicValueRef::Binary(Cow::Borrowed(v.as_slice())),
        }
    }
}

impl fmt::Display for ForensicValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ForensicValue::Null => write!(f, "NULL"),
            ForensicValue::Bool(v) => write!(f, "{v}"),
            ForensicValue::I64(v) => write!(f, "{v}"),
            ForensicValue::U64(v) => write!(f, "{v}"),
            ForensicValue::F64(v) => write!(f, "{v}"),
            ForensicValue::DateTime(v) => write!(f, "{v}"),
            ForensicValue::Guid(v) => {
                write!(
                    f,
                    "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    u32::from_le_bytes([v[0], v[1], v[2], v[3]]),
                    u16::from_le_bytes([v[4], v[5]]),
                    u16::from_le_bytes([v[6], v[7]]),
                    v[8],
                    v[9],
                    v[10],
                    v[11],
                    v[12],
                    v[13],
                    v[14],
                    v[15]
                )
            }
            ForensicValue::Text(v) => write!(f, "{v}"),
            ForensicValue::Binary(v) => {
                write!(f, "[")?;
                for (i, byte) in v.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{byte:02x}")?;
                }
                write!(f, "]")
            }
        }
    }
}

// --- TryInto impls for ForensicValue ---

impl TryInto<String> for ForensicValue {
    type Error = ForensicError;

    fn try_into(self) -> Result<String, Self::Error> {
        match self {
            ForensicValue::Text(v) => Ok(v),
            ForensicValue::Null => Ok(String::new()),
            other => Ok(other.to_string()),
        }
    }
}

impl TryInto<i64> for ForensicValue {
    type Error = ForensicError;

    fn try_into(self) -> Result<i64, Self::Error> {
        match self {
            ForensicValue::I64(v) => Ok(v),
            ForensicValue::U64(v) => i64::try_from(v)
                .map_err(|_| ForensicError::value_out_of_range(v.to_string(), "i64")),
            ForensicValue::Bool(v) => Ok(if v { 1 } else { 0 }),
            _ => Err(ForensicError::cast_error(
                "ForensicValue",
                "i64",
                compact_str::CompactString::const_new("Incompatible value type"),
            )),
        }
    }
}

impl TryInto<f64> for ForensicValue {
    type Error = ForensicError;

    fn try_into(self) -> Result<f64, Self::Error> {
        match self {
            ForensicValue::F64(v) => Ok(v),
            ForensicValue::I64(v) => Ok(v as f64),
            ForensicValue::U64(v) => Ok(v as f64),
            _ => Err(ForensicError::cast_error(
                "ForensicValue",
                "f64",
                compact_str::CompactString::const_new("Incompatible value type"),
            )),
        }
    }
}

impl TryInto<Vec<u8>> for ForensicValue {
    type Error = ForensicError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        match self {
            ForensicValue::Binary(v) => Ok(v),
            _ => Err(ForensicError::cast_error(
                "ForensicValue",
                "Vec<u8>",
                compact_str::CompactString::const_new("Incompatible value type"),
            )),
        }
    }
}

// --- From<primitive> for ForensicValue ---

impl From<bool> for ForensicValue {
    fn from(v: bool) -> Self {
        ForensicValue::Bool(v)
    }
}
impl From<u8> for ForensicValue {
    fn from(v: u8) -> Self {
        ForensicValue::U64(v as u64)
    }
}
impl From<i16> for ForensicValue {
    fn from(v: i16) -> Self {
        ForensicValue::I64(v as i64)
    }
}
impl From<i32> for ForensicValue {
    fn from(v: i32) -> Self {
        ForensicValue::I64(v as i64)
    }
}
impl From<i64> for ForensicValue {
    fn from(v: i64) -> Self {
        ForensicValue::I64(v)
    }
}
impl From<u16> for ForensicValue {
    fn from(v: u16) -> Self {
        ForensicValue::U64(v as u64)
    }
}
impl From<u32> for ForensicValue {
    fn from(v: u32) -> Self {
        ForensicValue::U64(v as u64)
    }
}
impl From<u64> for ForensicValue {
    fn from(v: u64) -> Self {
        ForensicValue::U64(v)
    }
}
impl From<f32> for ForensicValue {
    fn from(v: f32) -> Self {
        ForensicValue::F64(v as f64)
    }
}
impl From<f64> for ForensicValue {
    fn from(v: f64) -> Self {
        ForensicValue::F64(v)
    }
}
impl From<String> for ForensicValue {
    fn from(v: String) -> Self {
        ForensicValue::Text(v)
    }
}
impl From<&str> for ForensicValue {
    fn from(v: &str) -> Self {
        ForensicValue::Text(v.to_string())
    }
}
impl From<Vec<u8>> for ForensicValue {
    fn from(v: Vec<u8>) -> Self {
        ForensicValue::Binary(v)
    }
}
impl From<Filetime> for ForensicValue {
    fn from(v: Filetime) -> Self {
        ForensicValue::DateTime(v.into())
    }
}

impl From<ForensicTimestamp> for ForensicValue {
    fn from(v: ForensicTimestamp) -> Self {
        ForensicValue::DateTime(v)
    }
}
impl From<[u8; 16]> for ForensicValue {
    fn from(v: [u8; 16]) -> Self {
        ForensicValue::Guid(v)
    }
}

// ============================================================================
// ForensicValueRef (borrowed, Cow-backed)
// ============================================================================

/// Borrowed database value — for zero-copy scanning.
///
/// Same variants as `ForensicValue` but `Text` and `Binary` use `Cow`
/// to avoid allocation when borrowing from page buffers.
#[derive(Debug, Clone, PartialEq)]
pub enum ForensicValueRef<'a> {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    F64(f64),
    DateTime(ForensicTimestamp),
    Guid([u8; 16]),
    Text(Cow<'a, str>),
    Binary(Cow<'a, [u8]>),
}

impl<'a> ForensicValueRef<'a> {
    pub fn to_owned(&self) -> ForensicValue {
        match self {
            ForensicValueRef::Null => ForensicValue::Null,
            ForensicValueRef::Bool(v) => ForensicValue::Bool(*v),
            ForensicValueRef::I64(v) => ForensicValue::I64(*v),
            ForensicValueRef::U64(v) => ForensicValue::U64(*v),
            ForensicValueRef::F64(v) => ForensicValue::F64(*v),
            ForensicValueRef::DateTime(v) => ForensicValue::DateTime(*v),
            ForensicValueRef::Guid(v) => ForensicValue::Guid(*v),
            ForensicValueRef::Text(v) => ForensicValue::Text(v.clone().into_owned()),
            ForensicValueRef::Binary(v) => ForensicValue::Binary(v.clone().into_owned()),
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, ForensicValueRef::Null)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            ForensicValueRef::Text(v) => Some(v.as_ref()),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            ForensicValueRef::I64(v) => Some(*v),
            ForensicValueRef::U64(v) => i64::try_from(*v).ok(),
            ForensicValueRef::Bool(v) => Some(if *v { 1 } else { 0 }),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            ForensicValueRef::Binary(v) => Some(v.as_ref()),
            _ => None,
        }
    }
}

impl<'a> fmt::Display for ForensicValueRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ForensicValueRef::Null => write!(f, "NULL"),
            ForensicValueRef::Bool(v) => write!(f, "{v}"),
            ForensicValueRef::I64(v) => write!(f, "{v}"),
            ForensicValueRef::U64(v) => write!(f, "{v}"),
            ForensicValueRef::F64(v) => write!(f, "{v}"),
            ForensicValueRef::DateTime(v) => write!(f, "{v}"),
            ForensicValueRef::Guid(v) => {
                write!(
                    f,
                    "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    u32::from_le_bytes([v[0], v[1], v[2], v[3]]),
                    u16::from_le_bytes([v[4], v[5]]),
                    u16::from_le_bytes([v[6], v[7]]),
                    v[8],
                    v[9],
                    v[10],
                    v[11],
                    v[12],
                    v[13],
                    v[14],
                    v[15]
                )
            }
            ForensicValueRef::Text(v) => write!(f, "{v}"),
            ForensicValueRef::Binary(v) => {
                write!(f, "[")?;
                for (i, byte) in v.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{byte:02x}")?;
                }
                write!(f, "]")
            }
        }
    }
}

impl<'a> From<ForensicValueRef<'a>> for ForensicValue {
    fn from(val: ForensicValueRef<'a>) -> Self {
        val.to_owned()
    }
}

impl<'a> From<&'a ForensicValue> for ForensicValueRef<'a> {
    fn from(val: &'a ForensicValue) -> Self {
        val.as_ref()
    }
}

// ============================================================================
// Traits
// ============================================================================

/// Unified database access trait. Replaces `SqlDb`.
///
/// Construction is handled by each backend's own `open()` / `from_bytes()`.
///
/// `Send + Sync`: a mounted database is cached and shared across parallel
/// pipeline workers the same way `FileSystem`/`Registry` are (RFC 0001 §1,
/// P5) -- see [`crate::traits::format::Mounted::Database`].
pub trait ForensicDb: Send + Sync {
    /// List all user table names.
    fn list_tables(&self) -> ForensicResult<Vec<String>>;

    /// List all tables including system/catalog tables.
    /// Default implementation delegates to `list_tables()`.
    fn list_all_tables(&self) -> ForensicResult<Vec<String>> {
        self.list_tables()
    }

    /// Open a table by name (ASCII case-insensitive recommended).
    fn table(&self, name: &str) -> ForensicResult<Box<dyn ForensicTable + '_>>;
}

/// A single table within a forensic database.
pub trait ForensicTable {
    /// Table name.
    fn name(&self) -> &str;

    /// Column definitions. Returns a slice to avoid repeated allocation.
    fn columns(&self) -> &[ForensicColumnDef];

    /// Start iterating all rows. Each call returns a fresh cursor.
    fn iter_rows(&self) -> ForensicResult<Box<dyn ForensicRows + '_>>;

    /// Optional hint: total row count (None if unknown / expensive).
    fn row_count(&self) -> Option<u64> {
        None
    }
}

/// Row cursor for reading data from a table or query result.
///
/// No lifetime parameter — `Box<dyn ForensicRows>` works without `+ 'a`.
/// `next(&mut self)` naturally invalidates outstanding `ForensicValueRef`s
/// through the borrow checker.
pub trait ForensicRows {
    /// Number of columns per row.
    fn column_count(&self) -> usize;

    /// Column name by position (0-based).
    fn column_name(&self, i: usize) -> Option<&str>;

    /// All column names.
    fn column_names(&self) -> Vec<&str>;

    /// Column type by position.
    fn column_type(&self, i: usize) -> ForensicColumnType;

    /// Advance to the next row. Returns `false` when exhausted.
    /// Calling this invalidates all outstanding `ForensicValueRef`s.
    fn next(&mut self) -> ForensicResult<bool>;

    /// Read a value from the current row (0-based column index).
    /// Zero-copy when the backend supports it.
    fn read_ref(&self, i: usize) -> ForensicResult<ForensicValueRef<'_>>;

    /// Read an owned value (default impl clones from `read_ref`).
    fn read(&self, i: usize) -> ForensicResult<ForensicValue> {
        self.read_ref(i).map(|r| r.to_owned())
    }

    /// Read by column name (ASCII case-insensitive).
    fn read_named(&self, name: &str) -> ForensicResult<ForensicValue> {
        let i = self.find_column_index(name)?;
        self.read(i)
    }

    /// Read by column name, zero-copy.
    fn read_named_ref(&self, name: &str) -> ForensicResult<ForensicValueRef<'_>> {
        let i = self.find_column_index(name)?;
        self.read_ref(i)
    }

    /// Read a multi-valued column (0-based column index).
    /// ESE tagged columns can have multiple values per row.
    /// Default: wraps the single value in a vec.
    fn read_multi_ref(&self, i: usize) -> ForensicResult<Vec<ForensicValueRef<'_>>> {
        self.read_ref(i).map(|v| vec![v])
    }

    /// Read a multi-valued column as owned values.
    fn read_multi(&self, i: usize) -> ForensicResult<Vec<ForensicValue>> {
        self.read_multi_ref(i)
            .map(|refs| refs.into_iter().map(|r| r.to_owned()).collect())
    }
}

/// Helper trait with a default column-name lookup implementation.
trait ForensicRowsExt {
    fn find_column_index(&self, name: &str) -> ForensicResult<usize>;
}

impl<T: ForensicRows + ?Sized> ForensicRowsExt for T {
    fn find_column_index(&self, name: &str) -> ForensicResult<usize> {
        let count = self.column_count();
        for i in 0..count {
            if let Some(col_name) = self.column_name(i) {
                if col_name.eq_ignore_ascii_case(name) {
                    return Ok(i);
                }
            }
        }
        Err(ForensicError::missing_data(
            "column",
            format!("Column '{}' not found", name).into(),
        ))
    }
}

/// Optional SQL extension for databases that support SQL queries.
///
/// Only implemented by SQL-capable backends (e.g. SQLite).
/// **Warning:** Never interpolate untrusted input into SQL strings.
pub trait SqlCapable: ForensicDb {
    /// Execute an SQL statement and return a row cursor.
    fn prepare(&self, statement: &str) -> ForensicResult<Box<dyn ForensicRows + '_>>;
}

// ============================================================================
// Iterator Adapter
// ============================================================================

/// An owned snapshot of a single row — all values materialized.
#[derive(Debug, Clone)]
pub struct ForensicRow {
    values: Vec<(String, ForensicValue)>,
}

impl ForensicRow {
    /// Get a value by column index.
    pub fn get(&self, i: usize) -> Option<&ForensicValue> {
        self.values.get(i).map(|(_, v)| v)
    }

    /// Get a value by column name (ASCII case-insensitive).
    pub fn get_named(&self, name: &str) -> Option<&ForensicValue> {
        self.values
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    /// Number of columns in this row.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the row has no columns.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Iterate over (column_name, value) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &ForensicValue)> {
        self.values.iter().map(|(n, v)| (n.as_str(), v))
    }
}

impl IntoIterator for ForensicRow {
    type Item = (String, ForensicValue);
    type IntoIter = std::vec::IntoIter<(String, ForensicValue)>;
    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter()
    }
}

/// Iterator adapter that wraps a `ForensicRows` cursor and yields
/// owned `ForensicRow` values, enabling `.filter()`, `.map()`, `.collect()`.
///
/// ```ignore
/// let rows = table.iter_rows()?;
/// for row in RowIterator::new(rows) {
///     let row = row?;
///     println!("{}", row.get_named("Name").unwrap());
/// }
/// ```
pub struct RowIterator {
    rows: Box<dyn ForensicRows>,
    exhausted: bool,
}

impl RowIterator {
    pub fn new(rows: Box<dyn ForensicRows>) -> Self {
        Self {
            rows,
            exhausted: false,
        }
    }
}

impl Iterator for RowIterator {
    type Item = ForensicResult<ForensicRow>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.exhausted {
            return None;
        }
        match self.rows.next() {
            Ok(true) => {
                let count = self.rows.column_count();
                let mut values = Vec::with_capacity(count);
                for i in 0..count {
                    let name = self.rows.column_name(i).unwrap_or("").to_string();
                    match self.rows.read(i) {
                        Ok(val) => values.push((name, val)),
                        Err(e) => return Some(Err(e)),
                    }
                }
                Some(Ok(ForensicRow { values }))
            }
            Ok(false) => {
                self.exhausted = true;
                None
            }
            Err(e) => {
                self.exhausted = true;
                Some(Err(e))
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::time::Filetime;

    // ---- Value round-trip tests ----

    #[test]
    fn value_ref_round_trip() {
        let values = vec![
            ForensicValue::Null,
            ForensicValue::Bool(true),
            ForensicValue::I64(-1_000_000_000),
            ForensicValue::U64(u64::MAX),
            ForensicValue::F64(std::f64::consts::E),
            ForensicValue::DateTime(Filetime::new(125870776790000000).into()),
            ForensicValue::Guid([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            ForensicValue::Text("hello".to_string()),
            ForensicValue::Binary(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        ];
        for val in &values {
            let val_ref: ForensicValueRef<'_> = val.into();
            let round_tripped: ForensicValue = val_ref.into();
            assert_eq!(*val, round_tripped);
        }
    }

    #[test]
    fn value_try_into_string() {
        let v = ForensicValue::Text("test".into());
        let s: String = v.try_into().unwrap();
        assert_eq!(s, "test");

        let v = ForensicValue::I64(42);
        let s: String = v.try_into().unwrap();
        assert_eq!(s, "42");

        let v = ForensicValue::Null;
        let s: String = v.try_into().unwrap();
        assert_eq!(s, "");
    }

    #[test]
    fn value_try_into_i64() {
        let v = ForensicValue::I64(-42);
        let n: i64 = v.try_into().unwrap();
        assert_eq!(n, -42);

        let v = ForensicValue::U64(100);
        let n: i64 = v.try_into().unwrap();
        assert_eq!(n, 100);

        let v = ForensicValue::Text("nope".into());
        let result: Result<i64, _> = v.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn value_try_into_f64() {
        let v = ForensicValue::F64(1.5);
        let n: f64 = v.try_into().unwrap();
        assert!((n - 1.5).abs() < 0.001);
    }

    #[test]
    fn value_try_into_bytes() {
        let v = ForensicValue::Binary(vec![1, 2, 3]);
        let b: Vec<u8> = v.try_into().unwrap();
        assert_eq!(b, vec![1, 2, 3]);

        let v = ForensicValue::I64(42);
        let result: Result<Vec<u8>, _> = v.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn value_display() {
        assert_eq!(ForensicValue::Null.to_string(), "NULL");
        assert_eq!(ForensicValue::Bool(true).to_string(), "true");
        assert_eq!(ForensicValue::I64(-42).to_string(), "-42");
        assert_eq!(ForensicValue::U64(100).to_string(), "100");
        assert_eq!(ForensicValue::Text("hello".into()).to_string(), "hello");
        assert_eq!(
            ForensicValue::Binary(vec![0xDE, 0xAD]).to_string(),
            "[de, ad]"
        );
    }

    #[test]
    fn value_accessors() {
        assert!(ForensicValue::Null.is_null());
        assert!(!ForensicValue::Bool(false).is_null());

        assert_eq!(ForensicValue::Text("hi".into()).as_str(), Some("hi"));
        assert_eq!(ForensicValue::I64(42).as_str(), None);

        assert_eq!(ForensicValue::I64(-5).as_i64(), Some(-5));
        assert_eq!(ForensicValue::U64(1000).as_i64(), Some(1000));

        assert_eq!(ForensicValue::F64(1.0).as_f64(), Some(1.0f64));

        assert_eq!(
            ForensicValue::Binary(vec![1, 2]).as_bytes(),
            Some([1u8, 2].as_slice())
        );

        assert_eq!(ForensicValue::Bool(true).as_bool(), Some(true));
        assert_eq!(ForensicValue::U64(0).as_bool(), Some(false));
    }

    // ---- Mock ForensicRows for testing iterator adapter ----

    struct MockRows {
        columns: Vec<ForensicColumnDef>,
        data: Vec<Vec<ForensicValue>>,
        position: isize,
    }

    impl MockRows {
        fn new(columns: Vec<ForensicColumnDef>, data: Vec<Vec<ForensicValue>>) -> Self {
            Self {
                columns,
                data,
                position: -1,
            }
        }
    }

    impl ForensicRows for MockRows {
        fn column_count(&self) -> usize {
            self.columns.len()
        }

        fn column_name(&self, i: usize) -> Option<&str> {
            self.columns.get(i).map(|c| c.name.as_str())
        }

        fn column_names(&self) -> Vec<&str> {
            self.columns.iter().map(|c| c.name.as_str()).collect()
        }

        fn column_type(&self, i: usize) -> ForensicColumnType {
            self.columns
                .get(i)
                .map(|c| c.col_type)
                .unwrap_or(ForensicColumnType::Null)
        }

        fn next(&mut self) -> ForensicResult<bool> {
            self.position += 1;
            Ok((self.position as usize) < self.data.len())
        }

        fn read_ref(&self, i: usize) -> ForensicResult<ForensicValueRef<'_>> {
            let row_idx = self.position as usize;
            let row = self
                .data
                .get(row_idx)
                .ok_or_else(ForensicError::no_more_data)?;
            let val = row.get(i).ok_or_else(|| {
                ForensicError::missing_data(
                    "column",
                    format!("Column index {i} out of bounds").into(),
                )
            })?;
            Ok(val.as_ref())
        }
    }

    fn mock_table_data() -> (Vec<ForensicColumnDef>, Vec<Vec<ForensicValue>>) {
        let columns = vec![
            ForensicColumnDef {
                name: "Name".into(),
                col_type: ForensicColumnType::Text,
                nullable: false,
            },
            ForensicColumnDef {
                name: "Age".into(),
                col_type: ForensicColumnType::I32,
                nullable: false,
            },
        ];
        let data = vec![
            vec![ForensicValue::Text("Alice".into()), ForensicValue::I64(42)],
            vec![ForensicValue::Text("Bob".into()), ForensicValue::I64(69)],
        ];
        (columns, data)
    }

    #[test]
    fn test_read_named_case_insensitive() {
        let (columns, data) = mock_table_data();
        let mut rows = MockRows::new(columns, data);
        assert!(rows.next().unwrap());

        let name = rows.read_named("name").unwrap();
        assert_eq!(name, ForensicValue::Text("Alice".into()));

        let name = rows.read_named("NAME").unwrap();
        assert_eq!(name, ForensicValue::Text("Alice".into()));

        let name = rows.read_named("nAmE").unwrap();
        assert_eq!(name, ForensicValue::Text("Alice".into()));

        let result = rows.read_named("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_read_multi_ref_default() {
        let (columns, data) = mock_table_data();
        let mut rows = MockRows::new(columns, data);
        assert!(rows.next().unwrap());

        let multi = rows.read_multi_ref(0).unwrap();
        assert_eq!(multi.len(), 1);
        assert_eq!(multi[0].as_str(), Some("Alice"));
    }

    #[test]
    fn test_row_iterator() {
        let (columns, data) = mock_table_data();
        let rows = MockRows::new(columns, data);

        let collected: Vec<ForensicRow> = RowIterator::new(Box::new(rows))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(collected.len(), 2);
        assert_eq!(
            collected[0].get_named("Name"),
            Some(&ForensicValue::Text("Alice".into()))
        );
        assert_eq!(collected[0].get_named("age"), Some(&ForensicValue::I64(42)));
        assert_eq!(
            collected[1].get_named("name"),
            Some(&ForensicValue::Text("Bob".into()))
        );
    }

    #[test]
    fn test_row_iterator_filter_map() {
        let (columns, data) = mock_table_data();
        let rows = MockRows::new(columns, data);

        let names: Vec<String> = RowIterator::new(Box::new(rows))
            .filter_map(|r| {
                let row = r.ok()?;
                row.get_named("Name")?.as_str().map(String::from)
            })
            .collect();

        assert_eq!(names, vec!["Alice", "Bob"]);
    }

    #[test]
    fn test_forensic_row_iter_and_len() {
        let (columns, data) = mock_table_data();
        let rows = MockRows::new(columns, data);

        let mut iter = RowIterator::new(Box::new(rows));
        let row = iter.next().unwrap().unwrap();

        assert_eq!(row.len(), 2);
        assert!(!row.is_empty());

        let pairs: Vec<(&str, &ForensicValue)> = row.iter().collect();
        assert_eq!(pairs[0].0, "Name");
        assert_eq!(pairs[1].0, "Age");
    }
}
