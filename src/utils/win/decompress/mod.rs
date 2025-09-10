use crate::err::{ForensicError, ForensicResult};

pub mod lz77;
pub mod xpress_huff;

/// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/a8b7cb0a-92a6-4187-a23b-5e14273b96f8
#[repr(u32)]
#[derive(Debug, Clone)]
pub enum CompressionAlgorithm {
    CompressionFormatNone = 0x0000,
    CompressionFormatDefault = 0x0001,
    CompressionFormatLznt1 = 0x0002,
    CompressionFormatXpress = 0x0003,
    CompressionFormatXpressHuff = 0x0004,
}

impl From<u32> for CompressionAlgorithm {
    fn from(value: u32) -> Self {
        match value {
            1 => CompressionAlgorithm::CompressionFormatDefault,
            2 => CompressionAlgorithm::CompressionFormatLznt1,
            3 => CompressionAlgorithm::CompressionFormatXpress,
            4 => CompressionAlgorithm::CompressionFormatXpressHuff,
            _ => CompressionAlgorithm::CompressionFormatNone,
        }
    }
}

pub fn decompress(
    in_buf: &[u8],
    out_buf: &mut Vec<u8>,
    algorithm: CompressionAlgorithm,
) -> ForensicResult<()> {
    match algorithm {
        CompressionAlgorithm::CompressionFormatNone => {
            out_buf.copy_from_slice(in_buf);
        }
        CompressionAlgorithm::CompressionFormatDefault => {
            return Err(ForensicError::Other(
                "Default compression algorithm not supported".into(),
            ))
        }
        CompressionAlgorithm::CompressionFormatLznt1 => lz77::decompress(in_buf, out_buf)?,
        CompressionAlgorithm::CompressionFormatXpress => xpress_huff::decompress(in_buf, out_buf)?, // Can't happen
        CompressionAlgorithm::CompressionFormatXpressHuff => {
            xpress_huff::decompress(in_buf, out_buf)?
        }
    }
    Ok(())
}
