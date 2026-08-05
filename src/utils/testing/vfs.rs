use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Seek, SeekFrom},
    sync::{Arc, Mutex},
};

use crate::core::path::{FPath, FPathBuf};
use crate::err::{ForensicError, ForensicResult};
use crate::traits::vfs::{
    DirEntry, FileAttributes, FileSystem, MacbTimes, SourceKind, VFileType, VMetadata, VirtualFile,
};

fn normalize(path: &str) -> String {
    path.replace('\\', "/").trim_matches('/').to_string()
}

/// In-memory virtual filesystem for testing: an owned map of path -> bytes.
///
/// Directories are synthesized from path prefixes — there is no separate
/// directory-creation call; writing `"a/b/c.txt"` makes `"a"` and `"a/b"`
/// list as directories automatically.
#[derive(Clone, Debug, Default)]
pub struct InMemoryVirtualFileSystem {
    files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
}

impl InMemoryVirtualFileSystem {
    /// No pre-seeded files (there's no canonical "basic" file layout to
    /// default to, unlike `TestingRegistry::new()` — `new()` and `empty()`
    /// are equivalent, both provided for API-family consistency).
    pub fn new() -> Self {
        Self::default()
    }

    pub fn empty() -> Self {
        Self::default()
    }

    /// Builder-style: add a file and return `self`.
    pub fn with_file(mut self, path: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        self.add_file(path, bytes);
        self
    }

    /// Builder-style convenience for UTF-8 text content.
    pub fn with_text_file(mut self, path: impl Into<String>, text: impl Into<String>) -> Self {
        self.add_file(path, text.into().into_bytes());
        self
    }

    /// Mutate in place.
    pub fn add_file(&mut self, path: impl Into<String>, bytes: impl Into<Vec<u8>>) {
        let key = normalize(&path.into());
        self.files
            .lock()
            .expect("InMemoryVirtualFileSystem lock poisoned")
            .insert(key, bytes.into());
    }

    pub fn contains(&self, path: &str) -> bool {
        let key = normalize(path);
        self.files
            .lock()
            .expect("InMemoryVirtualFileSystem lock poisoned")
            .contains_key(&key)
    }
}

pub struct InMemoryVirtualFile {
    data: Vec<u8>,
    pos: u64,
}

impl Read for InMemoryVirtualFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let start = self.pos as usize;
        if start >= self.data.len() {
            return Ok(0);
        }
        let n = (&self.data[start..]).read(buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for InMemoryVirtualFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(p) => p as i64,
            SeekFrom::End(p) => self.data.len() as i64 + p,
            SeekFrom::Current(p) => self.pos as i64 + p,
        };
        if new_pos < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek to a negative position",
            ));
        }
        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}

impl VirtualFile for InMemoryVirtualFile {
    fn metadata(&self) -> ForensicResult<VMetadata> {
        Ok(VMetadata {
            file_type: VFileType::File,
            size: self.data.len() as u64,
            allocated_size: None,
            times: MacbTimes::default(),
            id: None,
            attributes: FileAttributes::empty(),
        })
    }
}

// ---------------------------------------------------------------------
// RFC 0001 FileSystem redesign.
// ---------------------------------------------------------------------
impl FileSystem for InMemoryVirtualFileSystem {
    fn open(&self, path: &FPath) -> ForensicResult<Box<dyn VirtualFile>> {
        let key = normalize(path.as_str());
        let bytes = self
            .files
            .lock()
            .expect("InMemoryVirtualFileSystem lock poisoned")
            .get(&key)
            .cloned()
            .ok_or_else(|| ForensicError::path_not_found(key))?;
        Ok(Box::new(InMemoryVirtualFile { data: bytes, pos: 0 }))
    }

    fn metadata(&self, path: &FPath) -> ForensicResult<VMetadata> {
        let key = normalize(path.as_str());
        let files = self
            .files
            .lock()
            .expect("InMemoryVirtualFileSystem lock poisoned");
        if let Some(bytes) = files.get(&key) {
            return Ok(VMetadata {
                file_type: VFileType::File,
                size: bytes.len() as u64,
                allocated_size: None,
                times: MacbTimes::default(),
                id: None,
                attributes: FileAttributes::empty(),
            });
        }
        let dir_prefix = format!("{key}/");
        if key.is_empty() || files.keys().any(|k| k.starts_with(&dir_prefix)) {
            return Ok(VMetadata {
                file_type: VFileType::Directory,
                size: 0,
                allocated_size: None,
                times: MacbTimes::default(),
                id: None,
                attributes: FileAttributes::empty(),
            });
        }
        Err(ForensicError::path_not_found(key))
    }

    fn read_dir(
        &self,
        path: &FPath,
    ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<DirEntry>> + '_>> {
        let key = normalize(path.as_str());
        let prefix = if key.is_empty() {
            String::new()
        } else {
            format!("{key}/")
        };
        let files = self
            .files
            .lock()
            .expect("InMemoryVirtualFileSystem lock poisoned");
        let mut seen = BTreeSet::new();
        let mut entries = Vec::new();
        let mut any_prefix_match = key.is_empty();
        for full_key in files.keys() {
            let Some(rest) = full_key.strip_prefix(&prefix[..]) else {
                continue;
            };
            any_prefix_match = true;
            if rest.is_empty() {
                continue;
            }
            let join = |name: &str| {
                if key.is_empty() {
                    name.to_string()
                } else {
                    format!("{key}/{name}")
                }
            };
            match rest.split_once('/') {
                Some((child, _)) => {
                    if seen.insert(child.to_string()) {
                        entries.push(Ok(DirEntry {
                            path: FPathBuf::from(join(child)),
                            file_type: VFileType::Directory,
                            metadata: None,
                        }));
                    }
                }
                None => {
                    if seen.insert(rest.to_string()) {
                        entries.push(Ok(DirEntry {
                            path: FPathBuf::from(join(rest)),
                            file_type: VFileType::File,
                            metadata: None,
                        }));
                    }
                }
            }
        }
        if !any_prefix_match {
            return Err(ForensicError::path_not_found(key));
        }
        Ok(Box::new(entries.into_iter()))
    }

    fn source(&self) -> SourceKind {
        SourceKind::Memory
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::vfs::FileSystemExt;

    #[test]
    fn with_file_round_trips_through_read_all_and_open() {
        let fs = InMemoryVirtualFileSystem::new().with_file("dir/a.txt", b"hello".to_vec());
        assert_eq!(fs.read_all(FPath::new("dir/a.txt")).unwrap(), b"hello");

        let mut file = FileSystem::open(&fs, FPath::new("dir/a.txt")).unwrap();
        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "hello");
    }

    #[test]
    fn read_dir_synthesizes_directories() {
        let fs = InMemoryVirtualFileSystem::new()
            .with_file("a/b/c.txt", b"1".to_vec())
            .with_file("a/d.txt", b"2".to_vec());

        let mut root: Vec<String> = FileSystem::read_dir(&fs, FPath::new(""))
            .unwrap()
            .filter_map(|e| e.ok().and_then(|e| e.file_name().map(str::to_string)))
            .collect();
        root.sort();
        assert_eq!(root, vec!["a"]);

        let mut children: Vec<String> = FileSystem::read_dir(&fs, FPath::new("a"))
            .unwrap()
            .filter_map(|e| e.ok().and_then(|e| e.file_name().map(str::to_string)))
            .collect();
        children.sort();
        assert_eq!(children, vec!["b", "d.txt"]);
    }

    #[test]
    fn exists_reports_files_and_synthesized_directories() {
        let fs = InMemoryVirtualFileSystem::new().with_file("a/b.txt", b"1".to_vec());
        assert!(fs.exists(FPath::new("a/b.txt")));
        assert!(fs.exists(FPath::new("a")));
        assert!(!fs.exists(FPath::new("missing")));
    }

    #[test]
    fn clone_shares_backing_store() {
        let mut fs = InMemoryVirtualFileSystem::new();
        let dup = fs.clone();
        fs.add_file("shared.txt", b"data".to_vec());
        assert_eq!(dup.read_all(FPath::new("shared.txt")).unwrap(), b"data");
    }

    mod new_filesystem_trait {
        use super::*;
        use crate::traits::vfs::SourceKind;

        #[test]
        fn read_all_and_exists_via_new_trait() {
            let fs = InMemoryVirtualFileSystem::new().with_file("dir/a.txt", b"hello".to_vec());
            assert_eq!(fs.read_all(FPath::new("dir/a.txt")).unwrap(), b"hello");
            assert!(fs.exists(FPath::new("dir/a.txt")));
            assert!(!fs.exists(FPath::new("missing.txt")));
            assert_eq!(fs.source(), SourceKind::Memory);
        }

        #[test]
        fn read_dir_synthesizes_directories_via_new_trait() {
            let fs = InMemoryVirtualFileSystem::new()
                .with_file("a/b/c.txt", b"1".to_vec())
                .with_file("a/d.txt", b"2".to_vec());

            let mut root: Vec<String> = FileSystem::read_dir(&fs, FPath::new(""))
                .unwrap()
                .filter_map(|e| e.ok().and_then(|e| e.file_name().map(str::to_string)))
                .collect();
            root.sort();
            assert_eq!(root, vec!["a"]);

            let mut children: Vec<String> = FileSystem::read_dir(&fs, FPath::new("a"))
                .unwrap()
                .filter_map(|e| e.ok().and_then(|e| e.file_name().map(str::to_string)))
                .collect();
            children.sort();
            assert_eq!(children, vec!["b", "d.txt"]);
        }

        #[test]
        fn read_dir_on_missing_path_errors_via_new_trait() {
            let fs = InMemoryVirtualFileSystem::new().with_file("a/b.txt", b"1".to_vec());
            assert!(FileSystem::read_dir(&fs, FPath::new("nope")).is_err());
        }

        #[test]
        fn arc_dyn_filesystem_shared_across_threads() {
            use std::sync::Arc;
            let fs: Arc<dyn FileSystem> =
                Arc::new(InMemoryVirtualFileSystem::new().with_file("a.txt", b"data".to_vec()));
            std::thread::scope(|scope| {
                for _ in 0..4 {
                    let fs = Arc::clone(&fs);
                    scope.spawn(move || {
                        assert_eq!(fs.read_all(FPath::new("a.txt")).unwrap(), b"data");
                    });
                }
            });
        }
    }
}
