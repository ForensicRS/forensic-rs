//! `cargo +nightly fuzz run decompress`: plain LZ77, Xpress Huffman and LZNT1 on hostile input.
//! The first byte picks the decoder and the output bound; no input may panic, and no decoder may
//! write past its bound.
#![no_main]

use forensic_rs::utils::win::decompress::{lz77, lznt1, xpress_huff};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&pick, input)) = data.split_first() else {
        return;
    };
    let bound = 1usize << (8 + (pick >> 2) % 9); // 256 B .. 64 KiB
    match pick & 3 {
        0 => {
            let mut out = Vec::new();
            if let Ok(n) = lz77::decompress_bounded(input, &mut out, bound) {
                assert_eq!(n, out.len());
            }
            assert!(out.len() <= bound);
        }
        1 => {
            let mut out = Vec::with_capacity(bound);
            let cap = out.capacity();
            let _ = xpress_huff::decompress(input, &mut out);
            assert!(out.len() <= cap);
        }
        _ => {
            let mut out = Vec::new();
            let _ = lznt1::decompress_bounded(input, &mut out, bound);
        }
    }
});
