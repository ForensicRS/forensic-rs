use crate::err::{ForensicError, ForensicResult};

pub fn decompress(in_buf: &[u8], out_buf: &mut Vec<u8>) -> ForensicResult<()> {
    let mut buffered_flags = 0;
    let mut buffered_flag_count = 0;
    let mut input_position = 0;
    let mut output_position = 0;
    let mut last_length_half_byte = 0;
    loop {
        if buffered_flag_count == 0 {
            buffered_flags = u32::from_le_bytes(
                in_buf[input_position..input_position + 4]
                    .try_into()
                    .unwrap(),
            );
            input_position += 4;
            buffered_flag_count = 32;
        }
        buffered_flag_count -= 1;
        if (buffered_flags & (1 << buffered_flag_count)) == 0 {
            out_buf.push(in_buf[input_position]);
            input_position += 1;
            output_position += 1;
        } else {
            if input_position == in_buf.len() {
                return Ok(());
            }
            let match_bytes = u16::from_le_bytes(
                in_buf[input_position..input_position + 2]
                    .try_into()
                    .unwrap(),
            ) as u32;
            input_position += 2;
            let mut match_length = match_bytes % 8;
            let match_offset = (match_bytes / 8) + 1;
            if match_length == 7 {
                if last_length_half_byte == 0 {
                    match_length = (in_buf[input_position] as u32) % 16;
                    last_length_half_byte = input_position;
                    input_position += 1;
                } else {
                    match_length = (in_buf[last_length_half_byte] as u32) / 16;
                    last_length_half_byte = 0;
                }
                if match_length == 15 {
                    match_length = in_buf[input_position] as u32;
                    input_position += 1;
                    if match_length == 255 {
                        match_length = u16::from_le_bytes(
                            in_buf[input_position..input_position + 2]
                                .try_into()
                                .unwrap(),
                        ) as u32;
                        input_position += 2;
                        if match_length == 0 {
                            match_length = u32::from_le_bytes(
                                in_buf[input_position..input_position + 4]
                                    .try_into()
                                    .unwrap(),
                            );
                            input_position += 4;
                        }
                        if match_length < 22 {
                            return Err(ForensicError::bad_format_str(
                                "decompress_LZ77(): Invalid match length, must be greater than 22",
                            ));
                        }
                        match_length -= 22;
                    }
                    match_length += 15;
                }
                match_length += 7;
            }
            match_length += 3;
            for _ in 0..match_length {
                out_buf.push(out_buf[output_position - match_offset as usize]);
                output_position += 1;
            }
        }
    }
}

#[test]
fn basic_lz77_decompression() {
    let uncompressed = b"abcdefghijklmnopqrstuvwxyz";
    let encoded: [u8; 30] = [
        0x3f, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
        0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a,
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
