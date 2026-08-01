use crate::err::ForensicResult;

/// Reads a little-endian `u16` at `pos`.
///
/// Returns a buffer error when the requested bytes are unavailable.
pub fn read_u16_le_at(buffer: &[u8], pos: usize) -> ForensicResult<u16> {
    crate::ensure_buffer_size!(buffer, pos, 2, "u16");
    let bytes = buffer[pos..pos + 2]
        .try_into()
        .map_err(|_| crate::err::ForensicError::buffer_too_small(pos + 2, buffer.len(), "u16"))?;
    Ok(u16::from_le_bytes(bytes))
}

/// Reads a little-endian `u32` at `pos`.
///
/// Returns a buffer error when the requested bytes are unavailable.
pub fn read_u32_le_at(buffer: &[u8], pos: usize) -> ForensicResult<u32> {
    crate::ensure_buffer_size!(buffer, pos, 4, "u32");
    let bytes = buffer[pos..pos + 4]
        .try_into()
        .map_err(|_| crate::err::ForensicError::buffer_too_small(pos + 4, buffer.len(), "u32"))?;
    Ok(u32::from_le_bytes(bytes))
}

/// Reads a little-endian `u64` at `pos`.
///
/// Returns a buffer error when the requested bytes are unavailable.
pub fn read_u64_le_at(buffer: &[u8], pos: usize) -> ForensicResult<u64> {
    crate::ensure_buffer_size!(buffer, pos, 8, "u64");
    let bytes = buffer[pos..pos + 8]
        .try_into()
        .map_err(|_| crate::err::ForensicError::buffer_too_small(pos + 8, buffer.len(), "u64"))?;
    Ok(u64::from_le_bytes(bytes))
}

/// Reads a big-endian `u16` at `pos`.
///
/// Returns a buffer error when the requested bytes are unavailable.
pub fn read_u16_be_at(buffer: &[u8], pos: usize) -> ForensicResult<u16> {
    crate::ensure_buffer_size!(buffer, pos, 2, "u16 (big-endian)");
    let bytes = buffer[pos..pos + 2].try_into().map_err(|_| {
        crate::err::ForensicError::buffer_too_small(pos + 2, buffer.len(), "u16 (big-endian)")
    })?;
    Ok(u16::from_be_bytes(bytes))
}

/// Reads a big-endian `u32` at `pos`.
///
/// Returns a buffer error when the requested bytes are unavailable.
pub fn read_u32_be_at(buffer: &[u8], pos: usize) -> ForensicResult<u32> {
    crate::ensure_buffer_size!(buffer, pos, 4, "u32 (big-endian)");
    let bytes = buffer[pos..pos + 4].try_into().map_err(|_| {
        crate::err::ForensicError::buffer_too_small(pos + 4, buffer.len(), "u32 (big-endian)")
    })?;
    Ok(u32::from_be_bytes(bytes))
}

/// Reads a big-endian `u64` at `pos`.
///
/// Returns a buffer error when the requested bytes are unavailable.
pub fn read_u64_be_at(buffer: &[u8], pos: usize) -> ForensicResult<u64> {
    crate::ensure_buffer_size!(buffer, pos, 8, "u64 (big-endian)");
    let bytes = buffer[pos..pos + 8].try_into().map_err(|_| {
        crate::err::ForensicError::buffer_too_small(pos + 8, buffer.len(), "u64 (big-endian)")
    })?;
    Ok(u64::from_be_bytes(bytes))
}

#[deprecated(
    since = "0.14.0",
    note = "use read_u16_le_at() to handle truncated input"
)]
pub fn u16_at_pos(buffer: &[u8], pos: usize) -> u16 {
    u16::from_le_bytes(buffer[pos..pos + 2].try_into().unwrap_or_default())
}
#[deprecated(
    since = "0.14.0",
    note = "use read_u32_le_at() to handle truncated input"
)]
pub fn u32_at_pos(buffer: &[u8], pos: usize) -> u32 {
    u32::from_le_bytes(buffer[pos..pos + 4].try_into().unwrap_or_default())
}
#[deprecated(
    since = "0.14.0",
    note = "use read_u64_le_at() to handle truncated input"
)]
pub fn u64_at_pos(buffer: &[u8], pos: usize) -> u64 {
    u64::from_le_bytes(buffer[pos..pos + 8].try_into().unwrap_or_default())
}

#[deprecated(
    since = "0.14.0",
    note = "use read_u16_be_at() to handle truncated input"
)]
pub fn u16b_at_pos(buffer: &[u8], pos: usize) -> u16 {
    u16::from_be_bytes(buffer[pos..pos + 2].try_into().unwrap_or_default())
}
#[deprecated(
    since = "0.14.0",
    note = "use read_u32_be_at() to handle truncated input"
)]
pub fn u32b_at_pos(buffer: &[u8], pos: usize) -> u32 {
    u32::from_be_bytes(buffer[pos..pos + 4].try_into().unwrap_or_default())
}
#[deprecated(
    since = "0.14.0",
    note = "use read_u64_be_at() to handle truncated input"
)]
pub fn u64b_at_pos(buffer: &[u8], pos: usize) -> u64 {
    u64::from_be_bytes(buffer[pos..pos + 8].try_into().unwrap_or_default())
}

#[deprecated(since = "0.14.0", note = "use read_u16_le_at()")]
pub fn u16_at_pos_safe(buffer: &[u8], pos: usize) -> ForensicResult<u16> {
    read_u16_le_at(buffer, pos)
}

#[deprecated(since = "0.14.0", note = "use read_u32_le_at()")]
pub fn u32_at_pos_safe(buffer: &[u8], pos: usize) -> ForensicResult<u32> {
    read_u32_le_at(buffer, pos)
}

#[deprecated(since = "0.14.0", note = "use read_u64_le_at()")]
pub fn u64_at_pos_safe(buffer: &[u8], pos: usize) -> ForensicResult<u64> {
    read_u64_le_at(buffer, pos)
}

#[deprecated(since = "0.14.0", note = "use read_u16_be_at()")]
pub fn u16b_at_pos_safe(buffer: &[u8], pos: usize) -> ForensicResult<u16> {
    read_u16_be_at(buffer, pos)
}

#[deprecated(since = "0.14.0", note = "use read_u32_be_at()")]
pub fn u32b_at_pos_safe(buffer: &[u8], pos: usize) -> ForensicResult<u32> {
    read_u32_be_at(buffer, pos)
}

#[deprecated(since = "0.14.0", note = "use read_u64_be_at()")]
pub fn u64b_at_pos_safe(buffer: &[u8], pos: usize) -> ForensicResult<u64> {
    read_u64_be_at(buffer, pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_endian_values_at_offsets() {
        let buffer = [0xaa, 0x78, 0x56, 0x34, 0x12];

        assert_eq!(read_u16_le_at(&buffer, 1).unwrap(), 0x5678);
        assert_eq!(read_u32_le_at(&buffer, 1).unwrap(), 0x12345678);
    }

    #[test]
    fn reads_big_endian_values_at_offsets() {
        let buffer = [0xaa, 0x12, 0x34, 0x56, 0x78];

        assert_eq!(read_u16_be_at(&buffer, 1).unwrap(), 0x1234);
        assert_eq!(read_u32_be_at(&buffer, 1).unwrap(), 0x12345678);
    }

    #[test]
    fn rejects_truncated_and_overflowed_offsets() {
        let buffer = [0u8; 4];

        assert!(read_u64_le_at(&buffer, 0).is_err());
        assert!(read_u32_le_at(&buffer, 1).is_err());
        assert!(read_u16_be_at(&buffer, usize::MAX).is_err());
    }
}
