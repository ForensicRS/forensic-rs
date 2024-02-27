use std::{io::ErrorKind, path::Path, time::SystemTime};

use crate::{
    err::{ForensicError, ForensicResult},
    traits::vfs::{VDirEntry, VFileType, VMetadata, VirtualFile, VirtualFileSystem},
};

/// this is an error handling routine.
///
/// - if `ts_res` contains a valid unix timestamp `ts`, then `Ok(Some(ts))` is returned
/// - if `ts_res` contains a value which cannot be converted into a unix timestamp, then Err(_) is returned
/// - if `ts_res` contains an error, then:
///    - if `kind() == Unsupported` then Ok(None) is returned (because this is not an error)
///    - otherwise, the error is returned
fn timestamp_from(ts_res: std::io::Result<SystemTime>) -> ForensicResult<Option<usize>> {
    match ts_res {
        Ok(ts) => match ts.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(v) => Ok(Some(v.as_secs() as usize)),
            Err(_why) => Err(ForensicError::IllegalTimestamp(format!(
                "timestamp {ts:?} cannot be converted into a unix timestamp"
            ))),
        },
        Err(why) => {
            if why.kind() == ErrorKind::Unsupported {
                Ok(None)
            } else {
                Err(why.into())
            }
        }
    }
}

/// A basic Virtual filesystem that uses the Rust standard library filesystem
///
#[derive(Clone, Default)]
pub struct StdVirtualFS {}

impl StdVirtualFS {
    pub fn new() -> Self {
        Self::default()
    }
}

pub struct StdVirtualFile {
    pub file: std::fs::File,
}

impl std::io::Read for StdVirtualFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}
impl std::io::Seek for StdVirtualFile {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.file.seek(pos)
    }
}
impl VirtualFile for StdVirtualFile {
    fn metadata(&self) -> ForensicResult<VMetadata> {
        let metadata = self.file.metadata()?;
        let file_type = if metadata.file_type().is_dir() {
            VFileType::Directory
        } else if metadata.file_type().is_symlink() {
            VFileType::Symlink
        } else {
            VFileType::File
        };
        let created = timestamp_from(metadata.created())?;
        let accessed = timestamp_from(metadata.accessed())?;
        let modified = timestamp_from(metadata.modified())?;

        Ok(VMetadata {
            created,
            accessed,
            modified,
            file_type,
            size: metadata.len(),
        })
    }
}

impl VirtualFileSystem for StdVirtualFS {
    fn read_to_string(&mut self, path: &Path) -> ForensicResult<String> {
        Ok(std::fs::read_to_string(path)?)
    }

    fn read_all(&mut self, path: &Path) -> ForensicResult<Vec<u8>> {
        Ok(std::fs::read(path)?)
    }
    #[cfg(target_os = "linux")]
    fn read(&mut self, path: &Path, pos: u64, buf: &mut [u8]) -> ForensicResult<usize> {
        use std::os::unix::prelude::FileExt;
        let file = std::fs::File::open(path)?;
        Ok(file.read_at(buf, pos)?)
    }

    #[cfg(target_os = "windows")]
    fn read(&mut self, path: &Path, pos: u64, buf: &mut [u8]) -> ForensicResult<usize> {
        use std::os::windows::prelude::FileExt;
        let file = std::fs::File::open(path)?;
        Ok(file.seek_read(buf, pos)?)
    }

    fn metadata(&mut self, path: &Path) -> ForensicResult<VMetadata> {
        let metadata = std::fs::metadata(path)?;
        let file_type = if metadata.file_type().is_dir() {
            VFileType::Directory
        } else if metadata.file_type().is_symlink() {
            VFileType::Symlink
        } else {
            VFileType::File
        };

        let created = timestamp_from(metadata.created())?;
        let accessed = timestamp_from(metadata.accessed())?;
        let modified = timestamp_from(metadata.modified())?;

        Ok(VMetadata {
            created,
            accessed,
            modified,
            file_type,
            size: metadata.len(),
        })
    }

    fn read_dir(&mut self, path: &Path) -> ForensicResult<Vec<VDirEntry>> {
        let mut ret = Vec::with_capacity(128);
        for dir_entry in std::fs::read_dir(path)? {
            let entry = dir_entry?;
            let file_type = entry.file_type()?;
            let file_entry = if file_type.is_dir() {
                VDirEntry::Directory(entry.file_name().to_string_lossy().into_owned())
            } else if file_type.is_symlink() {
                VDirEntry::Symlink(entry.file_name().to_string_lossy().into_owned())
            } else {
                VDirEntry::File(entry.file_name().to_string_lossy().into_owned())
            };
            ret.push(file_entry);
        }
        Ok(ret)
    }

    fn is_live(&self) -> bool {
        true
    }

    fn open(&mut self, path: &Path) -> ForensicResult<Box<dyn VirtualFile>> {
        Ok(Box::new(StdVirtualFile {
            file: std::fs::File::open(path)?,
        }))
    }

    fn duplicate(&self) -> Box<dyn VirtualFileSystem> {
        Box::new(StdVirtualFS {})
    }

    fn from_file(&self, _file: Box<dyn VirtualFile>) -> ForensicResult<Box<dyn VirtualFileSystem>> {
        Err(crate::err::ForensicError::NoMoreData)
    }

    fn from_fs(
        &self,
        _fs: Box<dyn VirtualFileSystem>,
    ) -> ForensicResult<Box<dyn VirtualFileSystem>> {
        Err(crate::err::ForensicError::NoMoreData)
    }
    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }
}

#[cfg(test)]
mod tst {
    use crate::traits::vfs::VirtualFileSystem;
    use std::io::Write;
    use std::path::Path;

    use crate::core::fs::StdVirtualFS;

    const CONTENT: &str = "File_Content_Of_VFS";
    const FILE_NAME: &str = "test_vfs_file.txt";

    #[test]
    fn test_temp_file() {
        let tmp = std::env::temp_dir();
        let tmp_file = tmp.join(FILE_NAME);
        let mut file = std::fs::File::create(&tmp_file).unwrap();
        file.write_all(CONTENT.as_bytes()).unwrap();
        drop(file);

        let mut std_vfs = StdVirtualFS::new();
        test_file_content(&mut std_vfs, &tmp_file);
        assert!(std_vfs
            .read_dir(tmp.as_path())
            .unwrap()
            .into_iter()
            .map(|v| v.to_string())
            .collect::<Vec<String>>()
            .contains(&"test_vfs_file.txt".to_string()));
    }

    fn test_file_content(std_vfs: &mut impl VirtualFileSystem, tmp_file: &Path) {
        let content = std_vfs.read_to_string(tmp_file).unwrap();
        assert_eq!(CONTENT, content);
    }

    #[test]
    fn should_allow_boxing() {
        struct Test {
            _fs: Box<dyn VirtualFileSystem>,
        }
        let boxed = Box::new(StdVirtualFS::new());
        Test { _fs: boxed };
    }
}
