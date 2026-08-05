use std::{io::ErrorKind, time::SystemTime};

use crate::{
    core::path::{FPath, FPathBuf},
    err::{ForensicError, ForensicResult},
    traits::vfs::{
        DirEntry, FileAttributes, FileSystem, MacbTimes, SourceKind, VFileType, VMetadata,
        VirtualFile,
    },
    utils::time::ForensicTimestamp,
};

/// this is an error handling routine.
///
/// - if `ts_res` contains a valid system timestamp `ts`, then `Ok(Some(ts))` is returned
/// - if `ts_res` contains a value outside the canonical timestamp range, then Err(_) is returned
/// - if `ts_res` contains an error, then:
///    - if `kind() == Unsupported` then Ok(None) is returned (because this is not an error)
///    - otherwise, the error is returned
fn timestamp_from(
    ts_res: std::io::Result<SystemTime>,
) -> ForensicResult<Option<ForensicTimestamp>> {
    match ts_res {
        Ok(ts) => ForensicTimestamp::try_from_system_time(ts)
            .map(Some)
            .map_err(|_| ForensicError::illegal_timestamp(
                0,
                format!("timestamp {ts:?} cannot be represented").into(),
            )),
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
            file_type,
            size: metadata.len(),
            allocated_size: None,
            times: MacbTimes {
                modified,
                accessed,
                changed: None,
                created,
                filename_times: None,
            },
            id: None,
            attributes: FileAttributes::empty(),
        })
    }
}

// ---------------------------------------------------------------------
// RFC 0001 FileSystem redesign.
// ---------------------------------------------------------------------
impl FileSystem for StdVirtualFS {
    fn open(&self, path: &FPath) -> ForensicResult<Box<dyn VirtualFile>> {
        Ok(Box::new(StdVirtualFile {
            file: std::fs::File::open(path.to_std_path())?,
        }))
    }

    fn metadata(&self, path: &FPath) -> ForensicResult<VMetadata> {
        let metadata = std::fs::metadata(path.to_std_path())?;
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
            file_type,
            size: metadata.len(),
            allocated_size: None,
            times: MacbTimes {
                modified,
                accessed,
                changed: None,
                created,
                filename_times: None,
            },
            id: None,
            attributes: FileAttributes::empty(),
        })
    }

    fn read_dir(
        &self,
        path: &FPath,
    ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<DirEntry>> + '_>> {
        let iter = std::fs::read_dir(path.to_std_path())?;
        Ok(Box::new(iter.map(|entry| {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let file_type = if file_type.is_dir() {
                VFileType::Directory
            } else if file_type.is_symlink() {
                VFileType::Symlink
            } else {
                VFileType::File
            };
            Ok(DirEntry {
                path: FPathBuf::from(entry.path().to_string_lossy().into_owned()),
                file_type,
                metadata: None,
            })
        })))
    }

    fn source(&self) -> SourceKind {
        SourceKind::Live
    }
}

#[cfg(test)]
mod tst {
    use std::io::Write;

    use crate::core::fs::StdVirtualFS;

    const CONTENT: &str = "File_Content_Of_VFS";

    #[test]
    fn new_filesystem_trait_reads_the_same_file() {
        use crate::core::path::FPath;
        use crate::traits::vfs::{FileSystem, FileSystemExt, SourceKind};

        // An isolated per-test subdirectory, not the bare shared system temp
        // root: `read_dir` below lists this directory's full contents, and
        // other tests in this suite write into the shared root directly.
        let dir = std::env::temp_dir().join(format!(
            "forensic_rs_stdfs_new_trait_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let tmp_file = dir.join("test_vfs_file_new_trait.txt");
        let mut file = std::fs::File::create(&tmp_file).unwrap();
        file.write_all(CONTENT.as_bytes()).unwrap();
        drop(file);

        let fs = StdVirtualFS::new();
        assert_eq!(fs.source(), SourceKind::Live);
        let tmp_file_str = tmp_file.to_string_lossy().into_owned();
        let path = FPath::new(&tmp_file_str);
        assert_eq!(fs.read_all(path).unwrap(), CONTENT.as_bytes());
        assert!(fs.exists(path));

        let dir_str = dir.to_string_lossy().into_owned();
        let dir_path = FPath::new(&dir_str);
        let names: Vec<String> = FileSystem::read_dir(&fs, dir_path)
            .unwrap()
            .filter_map(|e| e.ok().and_then(|e| e.file_name().map(str::to_string)))
            .collect();
        assert!(names.contains(&"test_vfs_file_new_trait.txt".to_string()));

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
