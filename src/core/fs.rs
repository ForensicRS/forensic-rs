use std::{time::SystemTime, path::Path};

use crate::{traits::vfs::{VirtualFileSystem, VMetadata, VDirEntry, VFileType}, err::ForensicResult};

pub struct StdVirtualFS {

}
impl StdVirtualFS {
    pub fn new() -> Self {
        Self{}
    }
}

impl VirtualFileSystem for StdVirtualFS {
    fn read_to_string(&mut self, path: &Path) -> ForensicResult<String>{
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
        }else if metadata.file_type().is_symlink() {
            VFileType::Symlink
        }else{
            VFileType::File
        };
        let created = match metadata.created()?.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(v) => v,
            Err(_e) => std::time::Duration::ZERO
        }.as_secs() as usize;

        let accessed = match metadata.accessed()?.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(v) => v,
            Err(_e) => std::time::Duration::ZERO
        }.as_secs() as usize;

        let modified = match metadata.modified()?.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(v) => v,
            Err(_e) => std::time::Duration::ZERO
        }.as_secs() as usize;
        
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
            }else if file_type.is_symlink() {
                VDirEntry::Symlink(entry.file_name().to_string_lossy().into_owned())
            }else{
                VDirEntry::File(entry.file_name().to_string_lossy().into_owned())
            };
            ret.push(file_entry);
        }
        Ok(ret)
    }

    fn is_live(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod virtual_fs_tests {
    use std::path::PathBuf;
    use std::{io::Write};
    use crate::traits::vfs::VirtualFileSystem;

    use crate::core::fs::StdVirtualFS;

    const CONTENT: &'static str = "File_Content_Of_VFS";
    const FILE_NAME: &'static str = "test_vfs_file.txt";

    #[test]
    fn test_temp_file() {
        
        let tmp = std::env::temp_dir();
        let tmp_file = tmp.join(FILE_NAME);
        let mut file = std::fs::File::create(&tmp_file).unwrap();
        file.write_all(CONTENT.as_bytes()).unwrap();
        drop(file);

        let mut std_vfs = StdVirtualFS::new();
        test_file_content(&mut std_vfs,&tmp_file);
        assert!(std_vfs.read_dir(tmp.as_path()).unwrap().into_iter().map(|v| v.to_string()).collect::<Vec<String>>().contains(&"test_vfs_file.txt".to_string()));
    }

    fn test_file_content(std_vfs : &mut impl VirtualFileSystem, tmp_file : &PathBuf) {
        let content = std_vfs.read_to_string(tmp_file).unwrap();
        assert_eq!(CONTENT, content);
        
    }

    #[test]
    fn should_allow_boxing() {
        struct Test {
            _fs : Box<dyn VirtualFileSystem>
        }
        let boxed = Box::new(StdVirtualFS::new());
        Test {
            _fs : boxed
        };

    }
}