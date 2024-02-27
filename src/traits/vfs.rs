use std::{
    fmt::Display,
    path::{Path, PathBuf},
};

use crate::err::ForensicResult;

pub struct VPath(PathBuf);

impl From<&str> for VPath {
    fn from(v: &str) -> Self {
        VPath(PathBuf::from(v))
    }
}
impl From<String> for VPath {
    fn from(v: String) -> Self {
        VPath(PathBuf::from(v))
    }
}
impl From<PathBuf> for VPath {
    fn from(v: PathBuf) -> Self {
        VPath(v)
    }
}
impl From<&Path> for VPath {
    fn from(v: &Path) -> Self {
        VPath(v.to_path_buf())
    }
}

pub trait VirtualFile: std::io::Seek + std::io::Read {
    fn metadata(&self) -> ForensicResult<VMetadata>;
}

pub trait VirtualFileSystem {
    /// Initializes a virtual filesystem from a file. Ex: a Zip FS from a file
    fn from_file(&self, file: Box<dyn VirtualFile>) -> ForensicResult<Box<dyn VirtualFileSystem>>;
    /// Initializes a virtual filesystem from a filesyste. Ex: a remapping of windows routes to Linux routes.
    fn from_fs(&self, fs: Box<dyn VirtualFileSystem>)
        -> ForensicResult<Box<dyn VirtualFileSystem>>;
    /// Read the entire contents of a file into a string.
    fn read_to_string(&mut self, path: &Path) -> ForensicResult<String>;
    /// Read the entire contents of a file into a bytes vector.
    fn read_all(&mut self, path: &Path) -> ForensicResult<Vec<u8>>;
    /// Read part of the content of a file into a bytes vector.
    fn read(&mut self, path: &Path, pos: u64, buf: &mut [u8]) -> ForensicResult<usize>;
    /// Get the metadata of a file/dir
    fn metadata(&mut self, path: &Path) -> ForensicResult<VMetadata>;
    /// Lists the contents of a Directory
    fn read_dir(&mut self, path: &Path) -> ForensicResult<Vec<VDirEntry>>;
    /// Check if the VirtualFileSystem is an abstraction over the real filesystem and not a virtual (like a ZIP file).
    fn is_live(&self) -> bool;
    /// Open a file
    fn open(&mut self, path: &Path) -> ForensicResult<Box<dyn VirtualFile>>;
    /// Allows duplicating the existing file system
    fn duplicate(&self) -> Box<dyn VirtualFileSystem>;
    /// Check if a file exists
    #[allow(unused_variables)]
    fn exists(&self, path: &Path) -> bool {
        false
    }
}

pub struct VMetadata {
    /// Seconds elapsed since UNIX_EPOCH in UTC
    ///
    /// this is optional, because some filesystems might not support this timestamp
    pub created: Option<usize>,

    /// Seconds elapsed since UNIX_EPOCH in UTC
    ///
    /// this is optional, because some filesystems might not support this timestamp
    pub accessed: Option<usize>,

    /// Seconds elapsed since UNIX_EPOCH in UTC
    ///
    /// this is optional, because some filesystems might not support this timestamp
    pub modified: Option<usize>,

    pub file_type: VFileType,
    pub size: u64,
}

#[derive(PartialEq)]
pub enum VFileType {
    File,
    Directory,
    Symlink,
}

impl VMetadata {
    /// Seconds elapsed since UNIX_EPOCH in UTC
    pub fn created(&self) -> usize {
        self.created.unwrap_or_else(|| {
            log::warn!(
                "this filesystem has no support for creation time, using UNIX_EPOCH instead"
            );
            0
        })
    }
    /// Seconds elapsed since UNIX_EPOCH in UTC
    pub fn accessed(&self) -> usize {
        self.accessed.unwrap_or_else(|| {
            log::warn!("this filesystem has no support for access time, using UNIX_EPOCH instead");
            0
        })
    }
    /// Seconds elapsed since UNIX_EPOCH in UTC
    pub fn modified(&self) -> usize {
        self.modified.unwrap_or_else(|| {
            log::warn!(
                "this filesystem has no support for modification time, using UNIX_EPOCH instead"
            );
            0
        })
    }

    /// Seconds elapsed since UNIX_EPOCH in UTC
    pub fn created_opt(&self) -> Option<&usize> {
        self.created.as_ref()
    }
    /// Seconds elapsed since UNIX_EPOCH in UTC
    pub fn accessed_opt(&self) -> Option<&usize> {
        self.accessed.as_ref()
    }
    /// Seconds elapsed since UNIX_EPOCH in UTC
    pub fn modified_opt(&self) -> Option<&usize> {
        self.modified.as_ref()
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
    Symlink(String),
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
