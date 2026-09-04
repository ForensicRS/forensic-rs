//! Integration proof for the worked example the phase-1 layering refactor
//! was designed against: containment -> containment -> embedding, resolved
//! through the public API only (`FormatFactory`, `MountResolver`,
//! `EvidenceLocator`, `StructuredObject`), the way a downstream crate would
//! use them -- not the crate's own private test doubles.
//!
//! Scenario: a triage tree contains `outer.tzip`, a toy "zip" containing
//! `inner.tzip`, itself a toy "zip" containing `evil.exe`, a toy "PE" with
//! one embedded resource. Three hops, three different relationships
//! (containment, containment, embedding), one `EvidenceLocator` chain.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::Arc;

use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;
use forensic_rs::prelude::*;

struct BytesFile(Cursor<Vec<u8>>);
impl Read for BytesFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}
impl Seek for BytesFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.0.seek(pos)
    }
}
impl VirtualFile for BytesFile {
    fn metadata(&self) -> ForensicResult<forensic_rs::traits::vfs::VMetadata> {
        Ok(forensic_rs::traits::vfs::VMetadata {
            file_type: forensic_rs::traits::vfs::VFileType::File,
            size: self.0.get_ref().len() as u64,
            allocated_size: None,
            times: forensic_rs::traits::vfs::MacbTimes::default(),
            id: None,
            attributes: forensic_rs::traits::vfs::FileAttributes::empty(),
        })
    }
}

fn bytes_file(content: &[u8]) -> Box<dyn VirtualFile> {
    Box::new(BytesFile(Cursor::new(content.to_vec())))
}

const TOY_ZIP_MAGIC: &[u8] = b"TOYZIP1\n";

/// `name=content` pairs separated by `|`, prefixed by the magic line.
fn build_toy_zip(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut out = TOY_ZIP_MAGIC.to_vec();
    let body = entries
        .iter()
        .map(|(name, content)| format!("{name}={content}"))
        .collect::<Vec<_>>()
        .join("|");
    out.extend_from_slice(body.as_bytes());
    out
}

fn parse_toy_zip(bytes: &[u8]) -> Option<InMemoryVirtualFileSystem> {
    let rest = bytes.strip_prefix(TOY_ZIP_MAGIC)?;
    let text = std::str::from_utf8(rest).ok()?;
    let mut fs = InMemoryVirtualFileSystem::new();
    for entry in text.split('|').filter(|s| !s.is_empty()) {
        let (name, content) = entry.split_once('=')?;
        fs.add_file(name, content.as_bytes().to_vec());
    }
    Some(fs)
}

struct ToyZipFactory;
impl FormatFactory for ToyZipFactory {
    fn name(&self) -> &'static str {
        "toy-zip"
    }
    fn yields(&self) -> MountKind {
        MountKind::FileSystem
    }
    fn probe(&self, file: &mut dyn VirtualFile, _ctx: &MountContext<'_>) -> ForensicResult<ProbeScore> {
        let start = file.stream_position()?;
        let mut magic = vec![0u8; TOY_ZIP_MAGIC.len()];
        let matched = file.read_exact(&mut magic).is_ok() && magic == TOY_ZIP_MAGIC;
        file.seek(SeekFrom::Start(start))?;
        Ok(if matched { ProbeScore::Strong } else { ProbeScore::No })
    }
    fn mount(&self, mut file: Box<dyn VirtualFile>, _ctx: &MountContext<'_>) -> ForensicResult<Mounted> {
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let fs = parse_toy_zip(&bytes)
            .ok_or_else(|| ForensicError::other("ToyZipFactory", "malformed toy zip".to_string()))?;
        Ok(Mounted::FileSystem(Arc::new(fs)))
    }
}

const TOY_PE_MAGIC: &[u8] = b"MZ";

/// A toy "PE": embeds exactly one resource, `secret`, whose content is
/// everything after the magic bytes.
struct ToyPe {
    resource: Vec<u8>,
}
impl StructuredObject for ToyPe {
    fn kind(&self) -> &'static str {
        "toy-pe"
    }
    fn children(&self) -> ForensicResult<Vec<(LocatorSegment, MountKind)>> {
        Ok(vec![(
            LocatorSegment::Resource {
                kind: 1,
                id: 1,
                lang: 0,
            },
            MountKind::File,
        )])
    }
    fn open_child(&self, segment: &LocatorSegment) -> ForensicResult<Box<dyn VirtualFile>> {
        match segment {
            LocatorSegment::Resource { kind: 1, id: 1, .. } => Ok(bytes_file(&self.resource)),
            _ => Err(ForensicError::other("ToyPe", "no such child".to_string())),
        }
    }
    fn attributes(&self) -> BTreeMap<Text, Field> {
        let mut map = BTreeMap::new();
        map.insert(Text::Borrowed("compile_timestamp"), Field::U64(1_700_000_000));
        map
    }
}

struct ToyPeFactory;
impl FormatFactory for ToyPeFactory {
    fn name(&self) -> &'static str {
        "toy-pe"
    }
    fn yields(&self) -> MountKind {
        MountKind::Object
    }
    fn probe(&self, file: &mut dyn VirtualFile, _ctx: &MountContext<'_>) -> ForensicResult<ProbeScore> {
        let start = file.stream_position()?;
        let mut magic = vec![0u8; TOY_PE_MAGIC.len()];
        let matched = file.read_exact(&mut magic).is_ok() && magic == TOY_PE_MAGIC;
        file.seek(SeekFrom::Start(start))?;
        Ok(if matched { ProbeScore::Strong } else { ProbeScore::No })
    }
    fn mount(&self, mut file: Box<dyn VirtualFile>, _ctx: &MountContext<'_>) -> ForensicResult<Mounted> {
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let resource = bytes[TOY_PE_MAGIC.len()..].to_vec();
        Ok(Mounted::Object(Arc::new(ToyPe { resource })))
    }
}

fn resolver() -> MountResolver {
    MountResolver::builder()
        .factory(Arc::new(ToyZipFactory))
        .factory(Arc::new(ToyPeFactory))
        .build()
}

fn evidence_root() -> Arc<dyn FileSystem> {
    let inner_zip = build_toy_zip(&[("evil.exe", "MZsecret-app-code")]);
    let outer_zip = build_toy_zip(&[(
        "inner.tzip",
        std::str::from_utf8(&inner_zip).unwrap(),
    )]);
    let mut root = InMemoryVirtualFileSystem::new();
    root.add_file("outer.tzip", outer_zip);
    Arc::new(root)
}

#[test]
fn resolves_containment_containment_embedding_as_one_locator_chain() {
    let resolver = resolver();
    let root = evidence_root();
    let cancel = CancellationToken::new();

    // Hop 1: containment. outer.tzip -> a FileSystem holding inner.tzip.
    let mut locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from("outer.tzip")));
    let file = root.open(FPath::new("outer.tzip")).unwrap();
    let outer_mounted = resolver
        .resolve(&root, &locator, file, Some(MountKind::FileSystem), &cancel)
        .expect("outer.tzip should mount as a FileSystem");
    let outer_fs = outer_mounted.as_file_system().unwrap().clone();

    // Hop 2: containment. inner.tzip -> a FileSystem holding evil.exe.
    locator = locator.push(LocatorSegment::Path(FPathBuf::from("inner.tzip")));
    let file = outer_fs.open(FPath::new("inner.tzip")).unwrap();
    let inner_mounted = resolver
        .resolve(&outer_fs, &locator, file, Some(MountKind::FileSystem), &cancel)
        .expect("inner.tzip should mount as a FileSystem");
    let inner_fs = inner_mounted.as_file_system().unwrap().clone();

    // Hop 3: embedding. evil.exe -> a StructuredObject with one resource.
    locator = locator.push(LocatorSegment::Path(FPathBuf::from("evil.exe")));
    let file = inner_fs.open(FPath::new("evil.exe")).unwrap();
    let pe_mounted = resolver
        .resolve(&inner_fs, &locator, file, Some(MountKind::Object), &cancel)
        .expect("evil.exe should mount as a StructuredObject");
    let pe = pe_mounted.as_object().unwrap();

    assert_eq!(locator.depth(), 3);
    match locator.to_source_key() {
        forensic_rs::provenance::SourceKey::Chain(chain) => assert_eq!(chain.len(), 3),
        other => panic!("expected a 3-hop Chain, got {other:?}"),
    }

    let children = pe.children().unwrap();
    assert_eq!(children.len(), 1);
    let (resource_segment, kind) = &children[0];
    assert_eq!(*kind, MountKind::File);
    let mut resource_bytes = Vec::new();
    pe.open_child(resource_segment)
        .unwrap()
        .read_to_end(&mut resource_bytes)
        .unwrap();
    assert_eq!(resource_bytes, b"secret-app-code");
    assert_eq!(
        pe.attributes().get(&Text::Borrowed("compile_timestamp")),
        Some(&Field::U64(1_700_000_000))
    );
}

#[test]
fn identical_content_at_two_locations_is_caught_not_silently_duplicated() {
    // Phase 1 deliberately errs conservative: with a digest configured,
    // seeing the same content bytes twice anywhere in one resolution --
    // whether that is truly a self-referential cycle or an unrelated
    // sibling with identical bytes -- is reported rather than silently
    // mounted twice as if it were unrelated evidence. Distinguishing "real
    // cycle" from "legitimate corroborating duplicate" needs ancestry
    // tracking, deferred past this phase; see the design record.
    let resolver = MountResolver::builder()
        .factory(Arc::new(ToyPeFactory))
        .digest(|| Box::new(SimpleDigest::default()))
        .build();
    let root = evidence_root();
    let cancel = CancellationToken::new();

    let loc_a = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from("a.exe")));
    resolver
        .resolve(&root, &loc_a, bytes_file(b"MZsame-bytes"), Some(MountKind::Object), &cancel)
        .expect("first sighting of these bytes should mount cleanly");

    let loc_b = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from("b.exe")));
    let result = resolver.resolve(&root, &loc_b, bytes_file(b"MZsame-bytes"), Some(MountKind::Object), &cancel);
    assert!(result.is_err(), "duplicate content at a distinct locator must be reported");
}

#[test]
fn nesting_at_the_limit_succeeds_one_hop_deeper_is_refused() {
    let resolver = MountResolver::builder()
        .factory(Arc::new(ToyZipFactory))
        .factory(Arc::new(ToyPeFactory))
        .limits(Limits {
            max_nesting_depth: 2,
            ..Limits::default()
        })
        .build();
    let root = evidence_root();
    let cancel = CancellationToken::new();

    // Depth 1: within the limit.
    let mut locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from("outer.tzip")));
    let file = root.open(FPath::new("outer.tzip")).unwrap();
    let outer_mounted = resolver
        .resolve(&root, &locator, file, Some(MountKind::FileSystem), &cancel)
        .expect("depth 1 must succeed");
    let outer_fs = outer_mounted.as_file_system().unwrap().clone();

    // Depth 2: exactly at the limit -- must still succeed.
    locator = locator.push(LocatorSegment::Path(FPathBuf::from("inner.tzip")));
    let file = outer_fs.open(FPath::new("inner.tzip")).unwrap();
    let inner_mounted = resolver
        .resolve(&outer_fs, &locator, file, Some(MountKind::FileSystem), &cancel)
        .expect("depth == max_nesting_depth must still succeed");
    let inner_fs = inner_mounted.as_file_system().unwrap().clone();

    // Depth 3: one hop past the limit -- must be refused.
    locator = locator.push(LocatorSegment::Path(FPathBuf::from("evil.exe")));
    let file = inner_fs.open(FPath::new("evil.exe")).unwrap();
    let result = resolver.resolve(&inner_fs, &locator, file, Some(MountKind::Object), &cancel);
    assert!(result.is_err(), "depth exceeding max_nesting_depth must be refused");
}

#[derive(Default)]
struct SimpleDigest {
    acc: u64,
}
impl forensic_rs::traits::digest::Digest for SimpleDigest {
    fn algorithm(&self) -> forensic_rs::traits::digest::DigestAlgorithm {
        forensic_rs::traits::digest::DigestAlgorithm::Other("nesting-test-digest")
    }
    fn update(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.acc = self.acc.wrapping_mul(31).wrapping_add(b as u64);
        }
    }
    fn finish(self: Box<Self>) -> forensic_rs::traits::digest::ContentAddress {
        forensic_rs::traits::digest::ContentAddress::new(
            forensic_rs::traits::digest::DigestAlgorithm::Other("nesting-test-digest"),
            self.acc.to_le_bytes().to_vec(),
        )
    }
}
