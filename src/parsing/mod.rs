//! Byte-level parsing helpers: a position-tracking cursor over `&[u8]`
//! ([`ByteReader`]) and the [`FromBytes`] convention for turning raw bytes
//! into typed structs.
//!
//! Complements [`crate::utils::unpack`]'s flat, offset-based readers with a
//! stateful cursor that tracks its own position, and adds coverage
//! (`u8`/`i8`/`i16`/`i32`/`i64`/`f32`/`f64`, fixed-size arrays, UTF-16LE/UTF-8
//! strings) that `unpack` doesn't have. Every fallible method reuses the same
//! [`crate::err::ForensicError`] buffer-bounds machinery as `unpack`, via
//! [`crate::ensure_buffer_size!`]/[`crate::ensure_buffer_range!`].

mod from_bytes;
mod reader;

pub use from_bytes::FromBytes;
pub use reader::ByteReader;

use crate::err::ForensicResult;
use crate::traits::vfs::VirtualFile;

/// Reads `file` to completion into `buf` and returns a [`ByteReader`]
/// borrowing from it.
///
/// Caller owns/reuses `buf` across calls to avoid reallocating per file. For
/// the already-buffered case (`vfs.read_all(path)? -> Vec<u8>`), no helper is
/// needed — just `ByteReader::new(&bytes)`.
pub fn read_to_reader<'a>(
    file: &mut dyn VirtualFile,
    buf: &'a mut Vec<u8>,
) -> ForensicResult<ByteReader<'a>> {
    buf.clear();
    file.read_to_end(buf)?;
    Ok(ByteReader::new(buf))
}
