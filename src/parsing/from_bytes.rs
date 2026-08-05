//! [`FromBytes`]: the "raw bytes → typed struct" convention for parser authors.

use crate::err::ForensicResult;

use super::ByteReader;

/// Standardizes the "raw bytes → typed struct" step for third-party parsers.
///
/// Implement this on your own artifact-header/record structs so callers can
/// decode them uniformly via [`ByteReader::read_as`], regardless of which
/// parser produced them.
///
/// ```
/// use forensic_rs::parsing::{ByteReader, FromBytes};
/// use forensic_rs::err::ForensicResult;
///
/// struct LnkHeader {
///     signature: u32,
///     size: u32,
/// }
///
/// impl FromBytes for LnkHeader {
///     fn from_bytes(reader: &mut ByteReader) -> ForensicResult<Self> {
///         let signature = reader.read_u32_le()?;
///         let size = reader.read_u32_le()?;
///         Ok(Self { signature, size })
///     }
/// }
///
/// let data = [0x01, 0x00, 0x00, 0x00, 0x4C, 0x00, 0x00, 0x00];
/// let mut reader = ByteReader::new(&data);
/// let header: LnkHeader = reader.read_as().unwrap();
/// assert_eq!(header.signature, 1);
/// assert_eq!(header.size, 0x4C);
/// ```
pub trait FromBytes: Sized {
    fn from_bytes(reader: &mut ByteReader) -> ForensicResult<Self>;
}
