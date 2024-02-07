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
    if pos + 2 > buffer.len() {
        return Err(crate::err::ForensicError::bad_format_str("Buffer does not have enough space for u16"))
    }
    Ok(u16::from_le_bytes(buffer[pos..pos + 2].try_into().unwrap_or_default()))
}
pub fn u32_at_pos_safe(buffer: &[u8], pos: usize) -> ForensicResult<u32> {
    if pos + 4 > buffer.len() {
        return Err(crate::err::ForensicError::bad_format_str("Buffer does not have enough space for u32"))
    }
    Ok(u32::from_le_bytes(buffer[pos..pos + 4].try_into().unwrap_or_default()))
}
pub fn u64_at_pos_safe(buffer: &[u8], pos: usize) -> ForensicResult<u64> {
    if pos + 8 > buffer.len() {
        return Err(crate::err::ForensicError::bad_format_str("Buffer does not have enough space for u64"))
    }
    Ok(u64::from_le_bytes(buffer[pos..pos + 8].try_into().unwrap_or_default()))
}

pub fn u16b_at_pos_safe(buffer: &[u8], pos: usize) -> ForensicResult<u16> {
    if pos + 2 > buffer.len() {
        return Err(crate::err::ForensicError::bad_format_str("Buffer does not have enough space for u16"))
    }
    Ok(u16::from_be_bytes(buffer[pos..pos + 2].try_into().unwrap_or_default()))
}
pub fn u32b_at_pos_safe(buffer: &[u8], pos: usize) -> ForensicResult<u32> {
    if pos + 4 > buffer.len() {
        return Err(crate::err::ForensicError::bad_format_str("Buffer does not have enough space for u32"))
    }
    Ok(u32::from_be_bytes(buffer[pos..pos + 4].try_into().unwrap_or_default()))
}
pub fn u64b_at_pos_safe(buffer: &[u8], pos: usize) -> ForensicResult<u64> {
    if pos + 8 > buffer.len() {
        return Err(crate::err::ForensicError::bad_format_str("Buffer does not have enough space for u64"))
    }
    Ok(u64::from_be_bytes(buffer[pos..pos + 8].try_into().unwrap_or_default()))
}