use crate::err::ForensicResult;

pub fn u16_at_pos(buffer: &[u8], pos: usize) -> u16 {
    u16::from_le_bytes(buffer[pos..pos + 2].try_into().unwrap_or_default())
}
pub fn u32_at_pos(buffer: &[u8], pos: usize) -> u32 {
    u32::from_le_bytes(buffer[pos..pos + 4].try_into().unwrap_or_default())
}
pub fn u64_at_pos(buffer: &[u8], pos: usize) -> u64 {
    u64::from_le_bytes(buffer[pos..pos + 8].try_into().unwrap_or_default())
}

pub fn u16b_at_pos(buffer: &[u8], pos: usize) -> u16 {
    u16::from_be_bytes(buffer[pos..pos + 2].try_into().unwrap_or_default())
}
pub fn u32b_at_pos(buffer: &[u8], pos: usize) -> u32 {
    u32::from_be_bytes(buffer[pos..pos + 4].try_into().unwrap_or_default())
}
pub fn u64b_at_pos(buffer: &[u8], pos: usize) -> u64 {
    u64::from_be_bytes(buffer[pos..pos + 8].try_into().unwrap_or_default())
}

pub fn u16_at_pos_safe(buffer: &[u8], pos: usize) -> ForensicResult<u16> {
    crate::ensure_buffer_size!(buffer, pos, 2, "u16");
    Ok(u16::from_le_bytes(buffer[pos..pos + 2].try_into().unwrap_or_default()))
}

pub fn u32_at_pos_safe(buffer: &[u8], pos: usize) -> ForensicResult<u32> {
    crate::ensure_buffer_size!(buffer, pos, 4, "u32");
    Ok(u32::from_le_bytes(buffer[pos..pos + 4].try_into().unwrap_or_default()))
}

pub fn u64_at_pos_safe(buffer: &[u8], pos: usize) -> ForensicResult<u64> {
    crate::ensure_buffer_size!(buffer, pos, 8, "u64");
    Ok(u64::from_le_bytes(buffer[pos..pos + 8].try_into().unwrap_or_default()))
}

pub fn u16b_at_pos_safe(buffer: &[u8], pos: usize) -> ForensicResult<u16> {
    crate::ensure_buffer_size!(buffer, pos, 2, "u16 (big-endian)");
    Ok(u16::from_be_bytes(buffer[pos..pos + 2].try_into().unwrap_or_default()))
}

pub fn u32b_at_pos_safe(buffer: &[u8], pos: usize) -> ForensicResult<u32> {
    crate::ensure_buffer_size!(buffer, pos, 4, "u32 (big-endian)");
    Ok(u32::from_be_bytes(buffer[pos..pos + 4].try_into().unwrap_or_default()))
}

pub fn u64b_at_pos_safe(buffer: &[u8], pos: usize) -> ForensicResult<u64> {
    crate::ensure_buffer_size!(buffer, pos, 8, "u64 (big-endian)");
    Ok(u64::from_be_bytes(buffer[pos..pos + 8].try_into().unwrap_or_default()))
}