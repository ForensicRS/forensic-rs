//! Composition of multiple [`FileSystem`]s: [`MountTable`] (routes by path
//! prefix, like mounting volumes into a directory tree) and [`OverlayFs`]
//! (layers filesystems, first layer with the path wins — the canonical use
//! is a triage collection layered over a full image over the live host).

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::core::path::{FPath, FPathBuf};
use crate::err::{ForensicError, ForensicResult};
use crate::traits::vfs::{CaseSensitivity, DirEntry, FileSystem, SourceKind, VirtualFile};

/// Routes paths to mounted filesystems by longest-matching-prefix.
pub struct MountTable {
    mounts: Vec<(FPathBuf, Arc<dyn FileSystem>)>,
}

impl Default for MountTable {
    fn default() -> Self {
        Self::new()
    }
}

impl MountTable {
    pub fn new() -> Self {
        MountTable { mounts: Vec::new() }
    }

    /// Mounts `fs` at `at`. Ties between equally-long prefixes are broken by
    /// most-recently-mounted.
    pub fn mount(&mut self, at: impl Into<FPathBuf>, fs: Arc<dyn FileSystem>) -> &mut Self {
        self.mounts.push((at.into(), fs));
        self
    }

    fn resolve(&self, path: &FPath) -> Option<(&FPathBuf, &Arc<dyn FileSystem>)> {
        self.mounts
            .iter()
            .filter(|(prefix, _)| path.starts_with(prefix.as_path()) || prefix.as_str() == path.as_str())
            .max_by_key(|(prefix, _)| prefix.components().count())
            .map(|(p, f)| (p, f))
    }

    fn relative_path(path: &FPath, prefix: &FPath) -> FPathBuf {
        let stripped = path
            .as_str()
            .strip_prefix(prefix.as_str())
            .unwrap_or(path.as_str())
            .trim_start_matches(['/', '\\']);
        FPathBuf::from(stripped)
    }
}

impl FileSystem for MountTable {
    fn open(&self, path: &FPath) -> ForensicResult<Box<dyn VirtualFile>> {
        let (prefix, fs) = self
            .resolve(path)
            .ok_or_else(|| ForensicError::path_not_found(path.to_string()))?;
        fs.open(Self::relative_path(path, prefix.as_path()).as_path())
    }

    fn metadata(&self, path: &FPath) -> ForensicResult<crate::traits::vfs::VMetadata> {
        let (prefix, fs) = self
            .resolve(path)
            .ok_or_else(|| ForensicError::path_not_found(path.to_string()))?;
        fs.metadata(Self::relative_path(path, prefix.as_path()).as_path())
    }

    fn read_dir(
        &self,
        path: &FPath,
    ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<DirEntry>> + '_>> {
        if let Some((prefix, fs)) = self.resolve(path) {
            let rel = Self::relative_path(path, prefix.as_path());
            if let Ok(inner) = fs.read_dir(rel.as_path()) {
                return Ok(inner);
            }
        }
        // Synthesize mount points directly under `path`, so e.g. `/` shows
        // every top-level mount even without a backing directory entry.
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for (prefix, _) in &self.mounts {
            if let Some(parent) = prefix.parent() {
                if parent == path {
                    if let Some(name) = prefix.file_name() {
                        if seen.insert(name.to_string()) {
                            out.push(Ok(DirEntry {
                                path: prefix.clone(),
                                file_type: crate::traits::vfs::VFileType::Directory,
                                metadata: None,
                            }));
                        }
                    }
                }
            }
        }
        if out.is_empty() {
            return Err(ForensicError::path_not_found(path.to_string()));
        }
        Ok(Box::new(out.into_iter()))
    }

    fn source(&self) -> SourceKind {
        SourceKind::Triage
    }
}

/// Layers filesystems: the first layer that has a path wins whole-file. No
/// copy-on-write directory merge beyond that — simplest correct semantics.
pub struct OverlayFs {
    layers: Vec<Arc<dyn FileSystem>>,
}

impl Default for OverlayFs {
    fn default() -> Self {
        Self::new()
    }
}

impl OverlayFs {
    pub fn new() -> Self {
        OverlayFs { layers: Vec::new() }
    }

    pub fn push_layer(&mut self, fs: Arc<dyn FileSystem>) -> &mut Self {
        self.layers.push(fs);
        self
    }
}

impl FileSystem for OverlayFs {
    fn open(&self, path: &FPath) -> ForensicResult<Box<dyn VirtualFile>> {
        for layer in &self.layers {
            if layer.metadata(path).is_ok() {
                return layer.open(path);
            }
        }
        Err(ForensicError::path_not_found(path.to_string()))
    }

    fn metadata(&self, path: &FPath) -> ForensicResult<crate::traits::vfs::VMetadata> {
        for layer in &self.layers {
            if let Ok(m) = layer.metadata(path) {
                return Ok(m);
            }
        }
        Err(ForensicError::path_not_found(path.to_string()))
    }

    fn read_dir(
        &self,
        path: &FPath,
    ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<DirEntry>> + '_>> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        let mut any_ok = false;
        for layer in &self.layers {
            if let Ok(entries) = layer.read_dir(path) {
                any_ok = true;
                for entry in entries {
                    let Ok(entry) = entry else { continue };
                    if let Some(name) = entry.file_name() {
                        if seen.insert(name.to_string()) {
                            out.push(Ok(entry));
                        }
                    }
                }
            }
        }
        if !any_ok {
            return Err(ForensicError::path_not_found(path.to_string()));
        }
        Ok(Box::new(out.into_iter()))
    }

    fn source(&self) -> SourceKind {
        SourceKind::Triage
    }

    fn case_sensitivity(&self) -> CaseSensitivity {
        self.layers
            .first()
            .map(|l| l.case_sensitivity())
            .unwrap_or(CaseSensitivity::Insensitive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::vfs::{VFileType, VMetadata};
    use std::collections::BTreeMap;
    use std::io::Cursor;

    /// Minimal in-memory `FileSystem` test double, local to this test
    /// module. `InMemoryVirtualFileSystem` (utils::testing) gains a real
    /// `FileSystem` impl in workstream C6; this avoids depending on that
    /// ahead of schedule.
    struct TestFs(BTreeMap<String, Vec<u8>>);

    struct TestFile(Cursor<Vec<u8>>);
    impl std::io::Read for TestFile {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }
    impl std::io::Seek for TestFile {
        fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
            self.0.seek(pos)
        }
    }
    impl VirtualFile for TestFile {
        fn metadata(&self) -> ForensicResult<VMetadata> {
            Ok(VMetadata {
                file_type: VFileType::File,
                size: self.0.get_ref().len() as u64,
                allocated_size: None,
                times: Default::default(),
                id: None,
                attributes: Default::default(),
            })
        }
    }

    impl FileSystem for TestFs {
        fn open(&self, path: &FPath) -> ForensicResult<Box<dyn VirtualFile>> {
            self.0
                .get(path.as_str())
                .cloned()
                .map(|b| Box::new(TestFile(Cursor::new(b))) as Box<dyn VirtualFile>)
                .ok_or_else(|| ForensicError::path_not_found(path.to_string()))
        }
        fn metadata(&self, path: &FPath) -> ForensicResult<VMetadata> {
            self.open(path)?.metadata()
        }
        fn read_dir(
            &self,
            path: &FPath,
        ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<DirEntry>> + '_>> {
            let prefix = format!("{}/", path.as_str());
            let entries: Vec<ForensicResult<DirEntry>> = self
                .0
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .map(|k| {
                    Ok(DirEntry {
                        path: FPathBuf::from(k.as_str()),
                        file_type: VFileType::File,
                        metadata: None,
                    })
                })
                .collect();
            Ok(Box::new(entries.into_iter()))
        }
        fn source(&self) -> SourceKind {
            SourceKind::Memory
        }
    }

    #[test]
    fn mount_table_routes_by_longest_prefix() {
        let mut inner_a = BTreeMap::new();
        inner_a.insert("file.txt".to_string(), b"from-a".to_vec());
        let mut inner_b = BTreeMap::new();
        inner_b.insert("file.txt".to_string(), b"from-b".to_vec());

        let mut table = MountTable::new();
        table.mount("C:/", Arc::new(TestFs(inner_a)));
        table.mount("C:/nested", Arc::new(TestFs(inner_b)));

        assert_eq!(
            table.open(FPath::new("C:/file.txt")).and_then(|mut f| {
                let mut buf = Vec::new();
                std::io::Read::read_to_end(&mut f, &mut buf).map_err(ForensicError::from)?;
                Ok(buf)
            }).unwrap(),
            b"from-a"
        );
        assert_eq!(
            table.open(FPath::new("C:/nested/file.txt")).and_then(|mut f| {
                let mut buf = Vec::new();
                std::io::Read::read_to_end(&mut f, &mut buf).map_err(ForensicError::from)?;
                Ok(buf)
            }).unwrap(),
            b"from-b"
        );
    }

    #[test]
    fn mount_table_missing_path_errors() {
        let table = MountTable::new();
        assert!(table.open(FPath::new("C:/nope")).is_err());
    }

    #[test]
    fn overlay_fs_first_layer_wins() {
        let mut top = BTreeMap::new();
        top.insert("shared.txt".to_string(), b"top".to_vec());
        let mut bottom = BTreeMap::new();
        bottom.insert("shared.txt".to_string(), b"bottom".to_vec());
        bottom.insert("only-bottom.txt".to_string(), b"bottom-only".to_vec());

        let mut overlay = OverlayFs::new();
        overlay.push_layer(Arc::new(TestFs(top)));
        overlay.push_layer(Arc::new(TestFs(bottom)));

        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut overlay.open(FPath::new("shared.txt")).unwrap(), &mut buf).unwrap();
        assert_eq!(buf, b"top");

        let mut buf2 = Vec::new();
        std::io::Read::read_to_end(
            &mut overlay.open(FPath::new("only-bottom.txt")).unwrap(),
            &mut buf2,
        )
        .unwrap();
        assert_eq!(buf2, b"bottom-only");
    }
}
