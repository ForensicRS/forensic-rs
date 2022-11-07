use std::{path::Path, fmt::Display};

use crate::err::ForensicResult;


pub trait VirtualFileSystem {
    /// Read the entire contents of a file into a string.
    fn read_to_string<P: AsRef<Path>>(&self, path: P) -> ForensicResult<String>;
    /// Read the entire contents of a file into a bytes vector.
    fn read_all<P: AsRef<Path>>(&self, path: P) -> ForensicResult<Vec<u8>>;
    /// Read part of the content of a file into a bytes vector.
    fn read<P: AsRef<Path>>(&self, path: P, pos: u64, buf: &mut [u8]) -> ForensicResult<usize>;
    /// Get the metadata of a file/dir
    fn metadata<P: AsRef<Path>>(&self, path: P) -> ForensicResult<VMetadata>;
    /// Lists the contents of a Directory
    fn read_dir<P: AsRef<Path>>(&self, path: P) -> ForensicResult<Vec<VDirEntry>>;
    /// Check if the VirtualFileSystem is an abstraction over the real filesystem and not a virtual (like a ZIP file).
    fn is_live(&self) -> bool;
}
pub struct VMetadata {
    /// Seconds elapsed since UNIX_EPOCH in UTC
    pub created : usize,
    /// Seconds elapsed since UNIX_EPOCH in UTC
    pub accessed : usize,
    /// Seconds elapsed since UNIX_EPOCH in UTC
    pub modified : usize,
    pub file_type : VFileType,
    pub size : u64
}

#[derive(PartialEq)]
pub enum VFileType {
    File,
    Directory,
    Symlink
}

impl VMetadata {
    /// Seconds elapsed since UNIX_EPOCH in UTC
    pub fn created(&self) -> usize{
        self.created
    }
    /// Seconds elapsed since UNIX_EPOCH in UTC
    pub fn accessed(&self)  -> usize{
        self.accessed
    }
    /// Seconds elapsed since UNIX_EPOCH in UTC
    pub fn modified(&self)  -> usize{
        self.modified
    }
    pub fn is_file(&self) -> bool {
        self.file_type == VFileType::File
    }
    pub fn is_dir(&self) -> bool {
        self.file_type == VFileType::Directory
    }
    pub fn is_symlink(&self) -> bool {
        self.file_type == VFileType::Symlink
    }
    pub fn len(&self) -> u64 {
        self.size
    }
}

pub enum VDirEntry {
    Directory(String),
    File(String),
    Symlink(String)
}

impl Display for VDirEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let content = match self {
            VDirEntry::Directory(v) => v,
            VDirEntry::File(v) => v,
            VDirEntry::Symlink(v) => v,
        };
        write!(f, "{}", content)
    }
}