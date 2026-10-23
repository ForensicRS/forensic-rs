//! Plain LZ77 ("Xpress", [MS-XCA] 2.3 and 2.4), as used by the Windows memory-compression
//! store, hibernation files and `COMPRESSION_FORMAT_XPRESS`.
//!
//! The input is attacker-influenced in every forensic use, so every read is bounds-checked, a
//! back-reference may only reach into the output this call produced, and
//! [`decompress_bounded`] caps the output size.

use crate::err::{ForensicError, ForensicResult};

fn truncated(what: &str) -> ForensicError {
    ForensicError::compression_error("lz77", format!("truncated input: {what}"))
}

/// Decompresses `in_buf`, appending to `out_buf`. No output bound: prefer
/// [`decompress_bounded`] for untrusted input.
pub fn decompress(in_buf: &[u8], out_buf: &mut Vec<u8>) -> ForensicResult<()> {
    decompress_bounded(in_buf, out_buf, usize::MAX).map(|_| ())
}

/// Decompresses `in_buf`, appending at most `max_out` bytes to `out_buf`, and returns how many
/// bytes were appended.
///
/// Decoding stops once `max_out` bytes are out (the input may carry padding after the data, as
/// memory-compression pages do), at a match flag with no input left (the end the format
/// defines), or with the input ending exactly at a flags word. A literal, flags word, match or
/// length cut by the end of the input is an error, as is a back-reference before the start of
/// this call's output.
pub fn decompress_bounded(
    in_buf: &[u8],
    out_buf: &mut Vec<u8>,
    max_out: usize,
) -> ForensicResult<usize> {
    let start = out_buf.len();
    let produced = |out: &Vec<u8>| out.len() - start;
    let mut ip = 0usize;
    let mut flags = 0u32;
    let mut flag_count = 0u32;
    // Where the shared length nibble was read, waiting for its second half.
    let mut half_byte: Option<usize> = None;
    let byte = |at: usize, what: &str| in_buf.get(at).copied().ok_or_else(|| truncated(what));
    while produced(out_buf) < max_out {
        if flag_count == 0 {
            if ip == in_buf.len() {
                break;
            }
            let word = in_buf.get(ip..ip + 4).ok_or_else(|| truncated("flags"))?;
            flags = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
            ip += 4;
            flag_count = 32;
        }
        flag_count -= 1;
        if flags & (1 << flag_count) == 0 {
            out_buf.push(byte(ip, "literal")?);
            ip += 1;
            continue;
        }
        if ip == in_buf.len() {
            break;
        }
        let m = in_buf.get(ip..ip + 2).ok_or_else(|| truncated("match"))?;
        let match_bytes = usize::from(u16::from_le_bytes([m[0], m[1]]));
        ip += 2;
        let offset = (match_bytes >> 3) + 1;
        let mut length = match_bytes & 7;
        if length == 7 {
            length = match half_byte.take() {
                None => {
                    half_byte = Some(ip);
                    let nibble = byte(ip, "length")? & 0x0f;
                    ip += 1;
                    usize::from(nibble)
                }
                Some(at) => usize::from(byte(at, "length")? >> 4),
            };
            if length == 15 {
                length = usize::from(byte(ip, "length")?);
                ip += 1;
                if length == 255 {
                    let w = in_buf.get(ip..ip + 2).ok_or_else(|| truncated("length"))?;
                    length = usize::from(u16::from_le_bytes([w[0], w[1]]));
                    ip += 2;
                    if length == 0 {
                        let d = in_buf.get(ip..ip + 4).ok_or_else(|| truncated("length"))?;
                        length = u32::from_le_bytes([d[0], d[1], d[2], d[3]]) as usize;
                        ip += 4;
                    }
                    length = length.checked_sub(22).ok_or_else(|| {
                        ForensicError::compression_error("lz77", "match length below 22")
                    })?;
                }
                length += 15;
            }
            length += 7;
        }
        length += 3;
        let from = produced(out_buf).checked_sub(offset).ok_or_else(|| {
            ForensicError::compression_error("lz77", "back-reference before the start of output")
        })?;
        // Overlapping copies repeat bytes just written, so copy one at a time.
        let length = length.min(max_out - produced(out_buf));
        for k in 0..length {
            let b = out_buf[start + from + k];
            out_buf.push(b);
        }
    }
    Ok(produced(out_buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_lz77_decompression() {
        let uncompressed = b"abcdefghijklmnopqrstuvwxyz";
        let encoded: [u8; 30] = [
            0x3f, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
            0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
            0x79, 0x7a,
        ];

        let mut decoded_value = Vec::with_capacity(1024);
        decompress(&encoded, &mut decoded_value).unwrap();
        assert_eq!(uncompressed, &decoded_value[..]);
    }

    #[test]
    fn basic_lz77_decompression_2() {
        let uncompressed = b"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc";
        let encoded: [u8; 13] = [
            0xff, 0xff, 0xff, 0x1f, 0x61, 0x62, 0x63, 0x17, 0x00, 0x0f, 0xff, 0x26, 0x01,
        ];

        let mut decoded_value = Vec::with_capacity(1024);
        decompress(&encoded, &mut decoded_value).unwrap();
        assert_eq!(uncompressed, &decoded_value[..]);
    }

    #[test]
    fn the_bound_stops_decoding_and_padding_is_ignored() {
        let mut encoded = vec![
            0xff, 0xff, 0xff, 0x1f, 0x61, 0x62, 0x63, 0x17, 0x00, 0x0f, 0xff, 0x26, 0x01,
        ];
        // Trailing padding, as a memory-compression slot carries after the data.
        encoded.extend_from_slice(&[0xaa; 7]);
        let mut out = b"prefix".to_vec();
        let n = decompress_bounded(&encoded, &mut out, 10).unwrap();
        assert_eq!(n, 10);
        assert_eq!(&out, b"prefixabcabcabca");
    }

    #[test]
    fn truncated_and_hostile_inputs_are_errors() {
        // Flags announce a literal that is not there.
        assert!(decompress(&[0x00, 0x00, 0x00, 0x00], &mut Vec::new()).is_err());
        // More literals announced than there are bytes, and a partial flags word.
        assert!(decompress(&[0x00, 0x00, 0x00, 0x00, 0x61, 0x00, 0x00], &mut Vec::new()).is_err());
        assert!(decompress(&[0x00, 0x00], &mut Vec::new()).is_err());
        // A back-reference before any output.
        assert!(decompress(&[0x00, 0x00, 0x00, 0x80, 0x08, 0x00], &mut Vec::new()).is_err());
        // A match cut after one byte.
        assert!(decompress(&[0x00, 0x00, 0x00, 0x40, 0x61, 0x08], &mut Vec::new()).is_err());
        // A long length below 22.
        let mut bad = vec![
            0x00, 0x00, 0x00, 0x40, 0x61, 0x07, 0x00, 0x0f, 0xff, 0x05, 0x00,
        ];
        assert!(decompress(&bad, &mut Vec::new()).is_err());
        bad.truncate(9);
        assert!(decompress(&bad, &mut Vec::new()).is_err());
        // A back-reference reaches only this call's output, never what was already there.
        let mut out = b"already here".to_vec();
        assert!(decompress(&[0x00, 0x00, 0x00, 0x80, 0x08, 0x00], &mut out).is_err());
    }

    #[test]
    fn garbage_never_panics() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for len in 0..600usize {
            let input: Vec<u8> = (0..len)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect();
            let mut out = Vec::new();
            let _ = decompress_bounded(&input, &mut out, 0x1000);
            assert!(out.len() <= 0x1000);
        }
    }
}
