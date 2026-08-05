//! End-to-end: raw bytes -> ByteReader -> typed struct via FromBytes -> ForensicData.
//!
//! Parses a Windows Recycle Bin `$I` header (version 2, Vista+): a small,
//! real forensic artifact whose ~24-byte fixed header plus a UTF-16LE
//! filename exercises most of `ByteReader`'s surface (u64 LE, a FILETIME
//! feeding directly into `ForensicTimestamp`, u32 LE, and a UTF-16LE string)
//! in one struct.
//!
//! Run with: `cargo run --example byte_parsing`

use forensic_rs::ensure_format;
use forensic_rs::parsing::{ByteReader, FromBytes};
use forensic_rs::prelude::*;

/// A parsed Windows Recycle Bin `$I` record (version 2, Vista and later).
///
/// On-disk layout:
/// - `header_version: u64` (LE) — must be `2` for this layout.
/// - `original_size: u64` (LE) — size in bytes of the deleted file.
/// - `deleted_at: u64` (LE) — FILETIME of deletion.
/// - `name_length: u32` (LE) — number of UTF-16 code units in the name.
/// - `original_name: [u16; name_length]` (LE) — the original full path.
#[derive(Debug)]
struct RecycleBinRecord {
    original_size: u64,
    deleted_at: ForensicTimestamp,
    original_name: String,
}

impl FromBytes for RecycleBinRecord {
    fn from_bytes(reader: &mut ByteReader) -> ForensicResult<Self> {
        let header_version = reader.read_u64_le()?;
        ensure_format!(
            header_version == 2,
            "recycle_bin",
            "unsupported $I header version"
        );
        let original_size = reader.read_u64_le()?;
        let deleted_filetime = reader.read_u64_le()?;
        let name_length = reader.read_u32_le()? as usize;
        let original_name = reader.read_utf16le_string(name_length * 2)?;
        Ok(Self {
            original_size,
            deleted_at: ForensicTimestamp::from_win_filetime(deleted_filetime),
            original_name,
        })
    }
}

/// Hand-built `$I` bytes standing in for a file read via a `VirtualFileSystem`
/// in a real parser (`vfs.read_all(path)?`, then `ByteReader::new(&bytes)`).
fn build_sample_bytes() -> Vec<u8> {
    let name = "C:\\Users\\alice\\Desktop\\secret-plan.docx";
    let name_units: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&2u64.to_le_bytes()); // header_version
    bytes.extend_from_slice(&4096u64.to_le_bytes()); // original_size
    bytes.extend_from_slice(&133_514_430_235_959_706u64.to_le_bytes()); // deleted_at (FILETIME)
    bytes.extend_from_slice(&((name.encode_utf16().count()) as u32).to_le_bytes()); // name_length
    bytes.extend_from_slice(&name_units);
    bytes
}

fn build_forensic_data(record: &RecycleBinRecord) -> ForensicData {
    // In a real parser, register_source() is called once per evidence source
    // (e.g. once per acquired disk image) and the resulting SourceHandle is
    // reused to mint one ProvenanceId per record it yields.
    let store = ProvenanceStore::new();
    let source = store.register_source(SourceKey::Path(
        "C:\\$Recycle.Bin\\S-1-5-21-.../$IABCDEF.docx".to_string(),
    ));
    let provenance = source.mint(Acquisition::ImageRead, Recovery::Allocated);

    let mut data = ForensicData::new(
        "WORKSTATION01",
        Artifact::Windows(WindowsArtifacts::RecycleBin),
        provenance,
    );
    data.set(FILE_NAME, record.original_name.clone());
    data.set(FILE_SIZE, record.original_size);
    data.set("@timestamp", record.deleted_at);
    data
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = build_sample_bytes();

    let mut reader = ByteReader::new(&bytes);
    let record: RecycleBinRecord = reader.read_as()?;
    println!("Parsed record: {:#?}", record);

    let data = build_forensic_data(&record);
    println!("As ForensicData: {}", data);

    Ok(())
}
