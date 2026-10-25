//! LZ77 + Huffman ("Xpress Huffman", [MS-XCA] 2.1 and 2.2).
//!
//! The input is attacker-influenced in every forensic use: every read is bounds-checked, a
//! back-reference may only reach into the output this call produced, and a malformed Huffman
//! table is an error, never a panic.

use crate::err::{DataAccessError, ForensicError, ForensicResult};
use std::{cell::RefCell, cmp::Ordering, rc::Rc};

/// Size of the Huffman code-length table at the start of every chunk.
const TABLE: usize = 256;
/// The bit stream starts with two 16-bit words after the table.
const STREAM_HEADER: usize = 4;
/// Nodes of a prefix-code tree built from one table (512 symbols).
const TREE_NODES: usize = 1024;
/// Longest code the format allows (lengths are 4-bit), so decoding a symbol takes at most this
/// many steps on a well-formed tree.
const MAX_CODE_BITS: usize = 15;

/// Decompresses `in_buf`, appending to `out_buf` up to `out_buf.capacity()` bytes in total (the
/// expected uncompressed size).
///
/// Inspired by <https://raw.githubusercontent.com/Velocidex/go-prefetch/master/lzxpress.go>
pub fn decompress(in_buf: &[u8], out_buf: &mut Vec<u8>) -> ForensicResult<()> {
    let mut in_index = 0;
    let start = out_buf.len();
    let mut out_index = start;
    let output_size = out_buf.capacity();
    while out_index < output_size && in_index < in_buf.len() {
        let chunk_size = (output_size - out_index).min(65536);
        let (new_in_index, new_out_index) =
            decompress_chunk(start, in_index, in_buf, out_index, out_buf, chunk_size)?;
        if new_in_index <= in_index && new_out_index <= out_index {
            return Err(ForensicError::compression_error(
                "xpress_huff",
                "no progress when decompressing a chunk",
            ));
        }
        (in_index, out_index) = (new_in_index, new_out_index);
    }
    if output_size < out_buf.len() {
        out_buf.resize(output_size, 0);
    }
    Ok(())
}

/// One chunk. `start` is where this call's output begins in `out_buf`; `out_index` equals
/// `out_buf.len()`.
fn decompress_chunk(
    start: usize,
    in_index: usize,
    in_buf: &[u8],
    out_index: usize,
    out_buf: &mut Vec<u8>,
    chunk_size: usize,
) -> ForensicResult<(usize, usize)> {
    if in_buf.len().saturating_sub(in_index) < TABLE + STREAM_HEADER {
        return Err(ForensicError::compression_error(
            "xpress_huff",
            "not enough compressed data for Huffman table",
        ));
    }
    let root = prefix_code_tree_rebuild(&in_buf[in_index..])?;
    let mut bstr = BitStream::new(in_buf, in_index + TABLE)?;
    let mut i = out_index;
    while i < out_index + chunk_size {
        let mut symbol = match prefix_code_tree_decode_symbol(&mut bstr, root.clone()) {
            Ok(v) => v,
            Err(e) => match e {
                ForensicError::DataAccess(DataAccessError::NoMoreData) => {
                    return Ok((bstr.index, i));
                }
                _ => return Err(e),
            },
        };
        if symbol < 256 {
            out_buf.push(symbol as u8);
            i += 1;
        } else {
            symbol -= 256;
            let mut length = symbol & 15;
            symbol >>= 4;

            let mut offset = 0;
            if symbol != 0 {
                offset = bstr.lookup(symbol) as i32;
            }
            offset |= 1 << symbol;
            offset = -offset;

            if length == 15 {
                if bstr.index >= bstr.source.len() {
                    return Ok((bstr.index, i));
                }
                length = (bstr.source[bstr.index] as u32) + 15;
                bstr.index += 1;
                if length == 270 {
                    if bstr.index + 2 > bstr.source.len() {
                        return Ok((bstr.index, i));
                    }
                    length = u16::from_le_bytes(
                        bstr.source[bstr.index..bstr.index + 2].try_into().unwrap(),
                    ) as u32;
                    bstr.index += 2;
                }
            }
            bstr.skip(symbol)?;

            length += 3;
            // A back-reference reaches only into this call's output.
            let distance = offset.unsigned_abs() as usize;
            let Some(position) = (out_buf.len() - start).checked_sub(distance) else {
                return ForensicError::invalid_offset(
                    "decompress_expres_huff",
                    offset as _,
                    chunk_size as _,
                )
                .into();
            };
            for k in 0..length as usize {
                let b = out_buf[start + position + k];
                out_buf.push(b);
            }
            i += length as usize;
        }
    }
    Ok((bstr.index, i))
}

struct BitStream<'a> {
    pub source: &'a [u8],
    pub index: usize,
    pub mask: u32,
    pub bits: u32,
}
impl<'a> BitStream<'a> {
    pub fn new(source: &'a [u8], in_pos: usize) -> ForensicResult<Self> {
        let Some(h) = source.get(in_pos..in_pos + STREAM_HEADER) else {
            return ForensicError::no_more_data().into();
        };
        let mask = (u32::from(u16::from_le_bytes([h[0], h[1]])) << 16)
            + u32::from(u16::from_le_bytes([h[2], h[3]]));
        Ok(Self {
            source,
            index: in_pos + STREAM_HEADER,
            bits: 32,
            mask,
        })
    }

    pub fn lookup(&self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        self.mask >> (32 - n)
    }
    pub fn skip(&mut self, n: u32) -> ForensicResult<()> {
        self.mask <<= n;
        self.bits = self.bits.saturating_sub(n);
        if self.bits < 16 {
            if (self.index + 2) > self.source.len() {
                return ForensicError::no_more_data().into();
            }
            let w = &self.source[self.index..self.index + 2];
            self.mask += u32::from(u16::from_le_bytes([w[0], w[1]])) << (16 - self.bits);
            self.index += 2;
            self.bits += 16;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
struct PrefixCodeNode {
    pub id: u32,
    pub symbol: u32,
    pub leaf: bool,
    pub child: [Option<Rc<RefCell<PrefixCodeNode>>>; 2],
}

#[derive(Clone, Debug, Default)]
struct PrefixCodeSymbol {
    pub id: u32,
    pub symbol: u32,
    pub length: u32,
}

impl Ord for PrefixCodeSymbol {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.length, &self.symbol).cmp(&(other.length, &other.symbol))
    }
}

impl PartialOrd for PrefixCodeSymbol {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for PrefixCodeSymbol {
    fn eq(&self, other: &Self) -> bool {
        (self.length, &self.symbol) == (other.length, &other.symbol)
    }
}

impl Eq for PrefixCodeSymbol {}

fn prefix_code_tree_add_leaf(
    tree_nodes: &[Rc<RefCell<PrefixCodeNode>>],
    leaf_index: usize,
    mask: u32,
    bits: u32,
) -> ForensicResult<u32> {
    let mut node = match tree_nodes.first() {
        Some(v) => v.clone(),
        None => {
            return ForensicError::compression_error(
                "express_huff",
                compact_str::CompactString::const_new("No valid PrefixCodeNode"),
            )
            .into();
        }
    };
    let mut i = leaf_index + 1;
    let mut child_index;
    let mut bits = bits;
    while bits > 1 {
        bits -= 1;
        child_index = (mask >> bits) & 1;
        let mut nt = node.borrow_mut();
        if nt.child[child_index as usize].is_none() {
            // An over-subscribed table (more codes than lengths allow) runs out of nodes.
            let Some(next) = tree_nodes.get(i) else {
                return ForensicError::compression_error(
                    "express_huff",
                    compact_str::CompactString::const_new("invalid Huffman table"),
                )
                .into();
            };
            nt.child[child_index as usize] = Some(next.clone());
            let mut i_node = next.borrow_mut();
            i_node.leaf = false;
            i += 1;
        }
        let new_node = nt.child[child_index as usize].as_ref().unwrap().clone();
        drop(nt);
        node = new_node;
    }
    let mut nt = node.borrow_mut();
    nt.child[(mask & 1) as usize] = Some(tree_nodes[leaf_index].clone());
    Ok(i as u32)
}

fn prefix_code_tree_rebuild(input: &[u8]) -> ForensicResult<Rc<RefCell<PrefixCodeNode>>> {
    let mut tree_nodes: Vec<Rc<RefCell<PrefixCodeNode>>> = (0..TREE_NODES)
        .map(|_| Rc::new(RefCell::new(PrefixCodeNode::default())))
        .collect();
    let mut symbol_info: Vec<PrefixCodeSymbol> =
        (0..512).map(|_| PrefixCodeSymbol::default()).collect();
    for i in 0..256 {
        let mut value = input[i] as usize;

        symbol_info[2 * i].id = (2 * i) as u32;
        symbol_info[2 * i].symbol = (2 * i) as u32;
        symbol_info[2 * i].length = (value & 0xf) as u32;

        value >>= 4;
        symbol_info[(2 * i) + 1].id = ((2 * i) + 1) as u32;
        symbol_info[(2 * i) + 1].symbol = ((2 * i) + 1) as u32;
        symbol_info[(2 * i) + 1].length = (value & 0xf) as u32;
    }
    symbol_info.sort_by(|a, b| {
        if a.length < b.length {
            return Ordering::Less;
        }
        if a.length > b.length {
            return Ordering::Greater;
        }

        if a.symbol < b.symbol {
            return Ordering::Less;
        }
        if a.symbol > b.symbol {
            return Ordering::Greater;
        }
        Ordering::Equal
    });
    let mut i = 0;
    while i < 512 && symbol_info[i].length == 0 {
        i += 1
    }
    let mut mask = 0;
    let mut bits = 1;

    let mut j = 1;
    for symbol in symbol_info.iter().take(512).skip(i) {
        let Some(node) = tree_nodes.get(j) else {
            return ForensicError::compression_error(
                "express_huff",
                compact_str::CompactString::const_new("invalid Huffman table"),
            )
            .into();
        };
        let mut tree_node_j = node.borrow_mut();
        tree_node_j.id = j as u32;
        tree_node_j.symbol = symbol.symbol;
        tree_node_j.leaf = true;
        drop(tree_node_j);

        mask <<= symbol.length - bits;
        bits = symbol.length;
        j = prefix_code_tree_add_leaf(&tree_nodes, j, mask, bits)? as usize;
        mask += 1;
    }
    let root = tree_nodes.remove(0);
    Ok(root)
}

fn prefix_code_tree_decode_symbol(
    bstr: &mut BitStream,
    root: Rc<RefCell<PrefixCodeNode>>,
) -> ForensicResult<u32> {
    let mut node = root;
    // A malformed tree could be deeper than any code: bound the walk.
    for step in 0.. {
        if step > MAX_CODE_BITS {
            return ForensicError::compression_error(
                "express_huff",
                compact_str::CompactString::const_new("Huffman code longer than 15 bits"),
            )
            .into();
        }
        let bit = bstr.lookup(1);
        bstr.skip(1)?;
        let nt = node.borrow();
        let new_node = match &nt.child[bit as usize] {
            Some(v) => v.clone(),
            None => {
                return ForensicError::too_small(
                    "get_prefix_code_symbol",
                    bit as _,
                    bstr.bits as _,
                )
                .into();
            }
        };
        drop(nt);
        node = new_node;
        if node.borrow().leaf {
            break;
        }
    }
    let nt = node.borrow();
    Ok(nt.symbol)
}

#[test]
fn basic_huffman_decoding() {
    let uncompressed = b"abcdefghijklmnopqrstuvwxyz";
    let encoded: [u8; 276] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x50, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x45,
        0x44, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xd8, 0x52, 0x3e, 0xd7, 0x94, 0x11, 0x5b, 0xe9, 0x19, 0x5f, 0xf9, 0xd6, 0x7c, 0xdf,
        0x8d, 0x04, 0x00, 0x00, 0x00, 0x00,
    ];

    let mut decoded_value = Vec::with_capacity(uncompressed.len());
    decompress(&encoded, &mut decoded_value).unwrap();
    assert_eq!(uncompressed, &decoded_value[..]);

    // Truncated Huffman table must error instead of looping forever
    let mut truncated_value = Vec::with_capacity(uncompressed.len());
    assert!(decompress(&encoded[..200], &mut truncated_value).is_err());
}

#[test]
fn basic_huffman_decoding2() {
    let uncompressed = b"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc";
    let encoded: [u8; 263] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x30, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xa8, 0xdc, 0x00, 0x00, 0xff, 0x26, 0x01,
    ];

    let mut decoded_value = Vec::with_capacity(uncompressed.len());
    decompress(&encoded, &mut decoded_value).unwrap();
    assert_eq!(uncompressed, &decoded_value[..]);
}

#[test]
fn a_table_without_its_stream_header_is_an_error() {
    // 256..259 bytes hold the table but not the two words the bit stream starts with; this
    // indexed past the input.
    for len in 256..260 {
        let input = vec![0x55u8; len];
        let mut out = Vec::with_capacity(0x1000);
        assert!(decompress(&input, &mut out).is_err(), "{len}");
    }
}

#[test]
fn hostile_tables_and_streams_never_panic() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state as u8
    };
    for round in 0..3000usize {
        let len = 256 + round % 700;
        let mut input: Vec<u8> = (0..len).map(|_| next()).collect();
        // Mostly small code lengths, so the table builds deep, over-subscribed trees.
        if round % 2 == 0 {
            for b in &mut input[..256] {
                *b &= 0x33;
            }
        }
        let mut out = Vec::with_capacity(0x1000);
        let _ = decompress(&input, &mut out);
        assert!(out.len() <= 0x1000);
    }
}
