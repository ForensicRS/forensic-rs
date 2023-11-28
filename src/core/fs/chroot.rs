use std::path::{PathBuf, Path};

use crate::{traits::vfs::VirtualFileSystem, prelude::ForensicResult};

pub struct ChRootFileSystem {
    path : PathBuf,
    fs : Box<dyn VirtualFileSystem>
}
impl ChRootFileSystem {
    pub fn new<P>(path : P, fs : Box<dyn VirtualFileSystem>) -> Self 
    where
        P : Into<std::path::PathBuf>
    {
        Self {
            path : path.into(),
            fs
        }
    }
}
fn normalize_prefix(path : &Path) -> PathBuf {
    let striped = strip_prefix(path);
    let path_comps = striped.components().into_iter();
    let mut final_path = PathBuf::new();
    for next in path_comps.into_iter() {
        if let std::path::Component::RootDir = &next {
            continue
        }
        for splt in next.as_os_str().to_string_lossy().split(split_path) {
            if splt.trim().is_empty() {
                continue
            }
            if splt.contains(":") {
                final_path.push(&splt.replace(":", ""));
            }else {
                final_path.push(splt);
            }
            
        }
    }
    final_path
}
fn split_path(chr : char) -> bool {
    chr == '\\' || chr == '/'
}
fn strip_prefix(path : &Path) -> PathBuf {
    if path.starts_with("/") {
        match path.strip_prefix("/") {
            Ok(v) => v.to_path_buf(),
            Err(_) => path.to_path_buf()
        }
    }else if path.starts_with("\\") {
        match path.strip_prefix("\\") {
            Ok(v) => v.to_path_buf(),
            Err(_) => path.to_path_buf()
        }
    }else{
        path.to_path_buf()
    }
}
impl VirtualFileSystem for ChRootFileSystem {
    fn read_to_string(&mut self, path: &Path) -> ForensicResult<String> {
        self.fs.read_to_string(self.path.join(normalize_prefix(path)).as_path())
    }

    fn is_live(&self) -> bool {
        false
    }

    fn read_all(&mut self, path: &Path) -> ForensicResult<Vec<u8>> {
        self.fs.read_all(self.path.join(normalize_prefix(path)).as_path())
    }

    fn read(& mut self, path: &Path, pos: u64, buf: & mut [u8]) -> ForensicResult<usize> {
        self.fs.read(self.path.join(normalize_prefix(path)).as_path(), pos, buf)
    }

    fn metadata(&mut self, path: &Path) -> ForensicResult<crate::traits::vfs::VMetadata> {
        self.fs.metadata(self.path.join(normalize_prefix(path)).as_path())
    }

    fn read_dir(&mut self, path: &Path) -> ForensicResult<Vec<crate::traits::vfs::VDirEntry>> {
        self.fs.read_dir(self.path.join(normalize_prefix(path)).as_path())
    }

    fn from_file(&self, _file : Box<dyn crate::traits::vfs::VirtualFile>) -> ForensicResult<Box<dyn VirtualFileSystem>> {
        Err(crate::prelude::ForensicError::Missing)
    }

    fn from_fs(&self, fs : Box<dyn VirtualFileSystem>) -> ForensicResult<Box<dyn VirtualFileSystem>> {
        Ok(Box::new(Self::new("/", fs)))
    }

    fn open(&mut self, path : &Path) -> ForensicResult<Box<dyn crate::traits::vfs::VirtualFile>> {
        self.fs.open(self.path.join(normalize_prefix(path)).as_path())
    }

    fn duplicate(&self) -> Box<dyn VirtualFileSystem> {
        Box::new(Self {
            fs : self.fs.duplicate(),
            path : self.path.clone()
        })
    }
    fn exists(&self, path : &Path) -> bool {
        self.path.join(normalize_prefix(path)).exists()
    }
}

#[cfg(test)]
mod tst {
    use std::path::PathBuf;
    use std::io::Write;
    use crate::core::fs::StdVirtualFS;

    use super::*;

    const CONTENT: &'static str = "File_Content_Of_VFS";
    const FILE_NAME: &'static str = "test_chrfs_file.txt";

    #[test]
    fn test_temp_file() {
        
        let tmp = std::env::temp_dir();
        let tmp_file = tmp.join(FILE_NAME);
        let file_path_in_chroot = std::path::PathBuf::from(&FILE_NAME);
        let mut file = std::fs::File::create(&tmp_file).unwrap();
        file.write_all(CONTENT.as_bytes()).unwrap();
        drop(file);

        let std_vfs = StdVirtualFS::new();
        // CHRoot over tmp folder
        let mut chrfs = ChRootFileSystem::new(&tmp, Box::new(std_vfs));
        test_file_content(&mut chrfs,&file_path_in_chroot);
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

    #[test]
    #[cfg(target_os="windows")]
    fn should_exists_c_windows() {
        let chrfs = ChRootFileSystem::new(Path::new("C:\\"), Box::new(StdVirtualFS::new()));
        assert!(chrfs.exists(Path::new("Windows")));
        let chrfs = ChRootFileSystem::new(Path::new("C:\\"), Box::new(StdVirtualFS::new()));
        assert!(chrfs.exists(Path::new("Windows:\\System32")));
        // This will be normalized into C:\Windows\System32
    }
}