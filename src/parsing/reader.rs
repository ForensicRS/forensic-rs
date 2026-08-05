//! [`ByteReader`]: a zero-copy, position-tracking cursor over a byte slice.

use crate::err::{ForensicError, ForensicResult};

/// Maximum bytes scanned looking for a null terminator before giving up with
/// a corruption error — guards against unbounded loops over malformed or
/// adversarial input that never contains a terminator.
const MAX_CSTRING_SCAN: usize = 32 * 1024;

/// A position-tracking cursor over `&[u8]`.
///
/// Every fallible method reuses the same [`crate::err::ForensicError`]
/// buffer-bounds machinery as [`crate::utils::unpack`]
/// (`ensure_buffer_size!`/`ensure_buffer_range!`) — reads never panic on
/// truncated input, they return a `Buffer` error instead.
pub struct ByteReader<'a> {
    buffer: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, pos: 0 }
    }

    /// Current cursor position.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Total length of the underlying buffer.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the cursor has reached (or passed) the end of the buffer.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buffer.len()
    }

    /// Bytes left to read from the current position.
    pub fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.pos)
    }

    /// The unread tail of the buffer, without advancing the cursor.
    pub fn remaining_slice(&self) -> &'a [u8] {
        &self.buffer[self.pos.min(self.buffer.len())..]
    }

    /// Moves the cursor to an absolute position.
    pub fn seek_to(&mut self, pos: usize) -> ForensicResult<()> {
        crate::ensure_buffer_range!(self.buffer, pos, pos);
        self.pos = pos;
        Ok(())
    }

    /// Advances the cursor by `n` bytes without reading them.
    pub fn skip(&mut self, n: usize) -> ForensicResult<()> {
        crate::ensure_buffer_size!(self.buffer, self.pos, n, "skip");
        self.pos += n;
        Ok(())
    }

    /// Moves the cursor back by `n` bytes.
    pub fn rewind(&mut self, n: usize) -> ForensicResult<()> {
        self.pos = self
            .pos
            .checked_sub(n)
            .ok_or_else(|| ForensicError::buffer_out_of_bounds(0, self.buffer.len()))?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Raw bytes
    // ------------------------------------------------------------------

    /// Reads `n` raw bytes, advancing the cursor.
    pub fn read_bytes(&mut self, n: usize) -> ForensicResult<&'a [u8]> {
        crate::ensure_buffer_size!(self.buffer, self.pos, n, "bytes");
        let slice = &self.buffer[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Reads exactly `N` raw bytes into a fixed-size array, advancing the cursor.
    pub fn read_fixed<const N: usize>(&mut self) -> ForensicResult<[u8; N]> {
        crate::ensure_buffer_size!(self.buffer, self.pos, N, "fixed array");
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buffer[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    /// Reads `n` raw bytes without advancing the cursor.
    pub fn peek_bytes(&self, n: usize) -> ForensicResult<&'a [u8]> {
        crate::ensure_buffer_size!(self.buffer, self.pos, n, "bytes");
        Ok(&self.buffer[self.pos..self.pos + n])
    }

    /// Reads one byte without advancing the cursor.
    pub fn peek_u8(&self) -> ForensicResult<u8> {
        crate::ensure_buffer_size!(self.buffer, self.pos, 1, "u8");
        Ok(self.buffer[self.pos])
    }

    // ------------------------------------------------------------------
    // Integers
    // ------------------------------------------------------------------

    pub fn read_u8(&mut self) -> ForensicResult<u8> {
        Ok(self.read_fixed::<1>()?[0])
    }

    pub fn read_i8(&mut self) -> ForensicResult<i8> {
        Ok(self.read_u8()? as i8)
    }

    pub fn read_u16_le(&mut self) -> ForensicResult<u16> {
        Ok(u16::from_le_bytes(self.read_fixed::<2>()?))
    }

    pub fn read_u16_be(&mut self) -> ForensicResult<u16> {
        Ok(u16::from_be_bytes(self.read_fixed::<2>()?))
    }

    pub fn read_i16_le(&mut self) -> ForensicResult<i16> {
        Ok(i16::from_le_bytes(self.read_fixed::<2>()?))
    }

    pub fn read_i16_be(&mut self) -> ForensicResult<i16> {
        Ok(i16::from_be_bytes(self.read_fixed::<2>()?))
    }

    pub fn read_u32_le(&mut self) -> ForensicResult<u32> {
        Ok(u32::from_le_bytes(self.read_fixed::<4>()?))
    }

    pub fn read_u32_be(&mut self) -> ForensicResult<u32> {
        Ok(u32::from_be_bytes(self.read_fixed::<4>()?))
    }

    pub fn read_i32_le(&mut self) -> ForensicResult<i32> {
        Ok(i32::from_le_bytes(self.read_fixed::<4>()?))
    }

    pub fn read_i32_be(&mut self) -> ForensicResult<i32> {
        Ok(i32::from_be_bytes(self.read_fixed::<4>()?))
    }

    pub fn read_u64_le(&mut self) -> ForensicResult<u64> {
        Ok(u64::from_le_bytes(self.read_fixed::<8>()?))
    }

    pub fn read_u64_be(&mut self) -> ForensicResult<u64> {
        Ok(u64::from_be_bytes(self.read_fixed::<8>()?))
    }

    pub fn read_i64_le(&mut self) -> ForensicResult<i64> {
        Ok(i64::from_le_bytes(self.read_fixed::<8>()?))
    }

    pub fn read_i64_be(&mut self) -> ForensicResult<i64> {
        Ok(i64::from_be_bytes(self.read_fixed::<8>()?))
    }

    // ------------------------------------------------------------------
    // Floats
    // ------------------------------------------------------------------

    pub fn read_f32_le(&mut self) -> ForensicResult<f32> {
        Ok(f32::from_le_bytes(self.read_fixed::<4>()?))
    }

    pub fn read_f32_be(&mut self) -> ForensicResult<f32> {
        Ok(f32::from_be_bytes(self.read_fixed::<4>()?))
    }

    pub fn read_f64_le(&mut self) -> ForensicResult<f64> {
        Ok(f64::from_le_bytes(self.read_fixed::<8>()?))
    }

    pub fn read_f64_be(&mut self) -> ForensicResult<f64> {
        Ok(f64::from_be_bytes(self.read_fixed::<8>()?))
    }

    // ------------------------------------------------------------------
    // Strings
    // ------------------------------------------------------------------

    /// Reads exactly `byte_len` bytes and decodes them as UTF-16LE.
    ///
    /// Decoding is lossy (invalid code units become U+FFFD): forensic data is
    /// often malformed, and callers generally prefer best-effort text over a
    /// hard parse failure for a single string field.
    pub fn read_utf16le_string(&mut self, byte_len: usize) -> ForensicResult<String> {
        if byte_len % 2 != 0 {
            return Err(ForensicError::format_corrupted(
                "utf16le_string",
                self.pos as u64,
                "odd byte length for a UTF-16LE string".into(),
            ));
        }
        let bytes = self.read_bytes(byte_len)?;
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Ok(String::from_utf16_lossy(&units))
    }

    /// Reads a null-terminated (`u16 == 0`) UTF-16LE string, consuming the
    /// terminator. The scan is capped so malformed input without a terminator
    /// fails fast instead of scanning to the end of an arbitrarily large buffer.
    pub fn read_utf16le_cstring(&mut self) -> ForensicResult<String> {
        let start = self.pos;
        let mut units = Vec::new();
        loop {
            if self.pos - start >= MAX_CSTRING_SCAN {
                return Err(ForensicError::format_corrupted(
                    "utf16le_cstring",
                    start as u64,
                    "no null terminator found within the scan limit".into(),
                ));
            }
            let unit = self.read_u16_le()?;
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        Ok(String::from_utf16_lossy(&units))
    }

    /// Reads `len` bytes and decodes them as ASCII/Latin-1, lossily.
    pub fn read_ascii_string(&mut self, len: usize) -> ForensicResult<String> {
        let bytes = self.read_bytes(len)?;
        Ok(bytes.iter().map(|&b| b as char).collect())
    }

    /// Reads `len` bytes and decodes them as UTF-8, failing on invalid input.
    pub fn read_utf8_string(&mut self, len: usize) -> ForensicResult<String> {
        let bytes = self.read_bytes(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_string)
            .map_err(|e| ForensicError::cast_error("&[u8]", "utf8 String", e.to_string().into()))
    }

    /// Reads a null-terminated (`u8 == 0`) string, consuming the terminator,
    /// decoded as UTF-8 lossily. Scan is capped like [`Self::read_utf16le_cstring`].
    pub fn read_cstring(&mut self) -> ForensicResult<String> {
        let start = self.pos;
        loop {
            if self.pos - start >= MAX_CSTRING_SCAN {
                return Err(ForensicError::format_corrupted(
                    "cstring",
                    start as u64,
                    "no null terminator found within the scan limit".into(),
                ));
            }
            let byte = self.read_u8()?;
            if byte == 0 {
                let bytes = &self.buffer[start..self.pos - 1];
                return Ok(String::from_utf8_lossy(bytes).into_owned());
            }
        }
    }

    /// Reads a value implementing [`super::FromBytes`] from this cursor.
    pub fn read_as<T: super::FromBytes>(&mut self) -> ForensicResult<T> {
        T::from_bytes(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_all_integer_widths_le_and_be() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut r = ByteReader::new(&data);
        assert_eq!(r.read_u8().unwrap(), 0x01);
        r.seek_to(0).unwrap();
        assert_eq!(r.read_u16_le().unwrap(), 0x0201);
        r.seek_to(0).unwrap();
        assert_eq!(r.read_u16_be().unwrap(), 0x0102);
        r.seek_to(0).unwrap();
        assert_eq!(r.read_u32_le().unwrap(), 0x04030201);
        r.seek_to(0).unwrap();
        assert_eq!(r.read_u32_be().unwrap(), 0x01020304);
        r.seek_to(0).unwrap();
        assert_eq!(r.read_u64_le().unwrap(), 0x0807060504030201);
        r.seek_to(0).unwrap();
        assert_eq!(r.read_u64_be().unwrap(), 0x0102030405060708);
    }

    #[test]
    fn signed_widths_round_trip() {
        let data = (-1i64).to_le_bytes();
        let mut r = ByteReader::new(&data);
        assert_eq!(r.read_i8().unwrap(), -1);
        r.seek_to(0).unwrap();
        assert_eq!(r.read_i16_le().unwrap(), -1);
        r.seek_to(0).unwrap();
        assert_eq!(r.read_i32_le().unwrap(), -1);
        r.seek_to(0).unwrap();
        assert_eq!(r.read_i64_le().unwrap(), -1);
    }

    #[test]
    fn floats_round_trip() {
        let mut data = Vec::new();
        data.extend_from_slice(&1.5f32.to_le_bytes());
        data.extend_from_slice(&2.5f64.to_le_bytes());
        let mut r = ByteReader::new(&data);
        assert_eq!(r.read_f32_le().unwrap(), 1.5f32);
        assert_eq!(r.read_f64_le().unwrap(), 2.5f64);
    }

    #[test]
    fn rejects_truncated_reads() {
        let data = [0x01u8];
        let mut r = ByteReader::new(&data);
        assert!(r.read_u32_le().is_err());
    }

    #[test]
    fn read_fixed_returns_exact_array() {
        let data = [1, 2, 3, 4, 5];
        let mut r = ByteReader::new(&data);
        let arr: [u8; 3] = r.read_fixed().unwrap();
        assert_eq!(arr, [1, 2, 3]);
        assert_eq!(r.position(), 3);
        assert_eq!(r.remaining(), 2);
    }

    #[test]
    fn skip_and_seek_bounds_check() {
        let data = [0u8; 4];
        let mut r = ByteReader::new(&data);
        assert!(r.skip(2).is_ok());
        assert!(r.skip(10).is_err());
        assert!(r.seek_to(4).is_ok());
        assert!(r.seek_to(5).is_err());
        assert!(r.rewind(4).is_ok());
        assert!(r.rewind(1).is_err());
    }

    #[test]
    fn read_utf16le_string_decodes_text() {
        let text = "Hi";
        let bytes: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let mut r = ByteReader::new(&bytes);
        assert_eq!(r.read_utf16le_string(bytes.len()).unwrap(), "Hi");
    }

    #[test]
    fn read_utf16le_cstring_finds_terminator() {
        let mut bytes: Vec<u8> = "Hi".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0xAAu16.to_le_bytes()); // trailing garbage, must not be read
        let mut r = ByteReader::new(&bytes);
        assert_eq!(r.read_utf16le_cstring().unwrap(), "Hi");
        assert_eq!(r.position(), 6);
    }

    #[test]
    fn read_cstring_finds_terminator() {
        let mut bytes = b"hello".to_vec();
        bytes.push(0);
        bytes.extend_from_slice(b"garbage");
        let mut r = ByteReader::new(&bytes);
        assert_eq!(r.read_cstring().unwrap(), "hello");
        assert_eq!(r.position(), 6);
    }

    #[test]
    fn read_utf8_string_rejects_invalid_utf8() {
        let bytes = [0xFF, 0xFE];
        let mut r = ByteReader::new(&bytes);
        assert!(r.read_utf8_string(2).is_err());
    }

    #[test]
    fn read_as_uses_from_bytes_impl() {
        use super::super::FromBytes;
        struct Pair(u16, u16);
        impl FromBytes for Pair {
            fn from_bytes(reader: &mut ByteReader) -> ForensicResult<Self> {
                Ok(Pair(reader.read_u16_le()?, reader.read_u16_le()?))
            }
        }
        let data = [1, 0, 2, 0];
        let mut r = ByteReader::new(&data);
        let pair: Pair = r.read_as().unwrap();
        assert_eq!((pair.0, pair.1), (1, 2));
    }
}
