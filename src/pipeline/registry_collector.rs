//! [`RegistryCollector`]: the raw registry keys and values every artifact-catalog definition
//! names, uninterpreted.
//!
//! A dedicated parser knows what a value means (a BAM entry's `FILETIME`, a ShimCache blob). This
//! one knows only where the knowledge base says to look, and records what is there, as stored:
//! it gives every `REGISTRY_KEY`/`REGISTRY_VALUE` definition of the run's catalog coverage, so
//! nothing the KB names goes unexamined just because no parser interprets it yet.
//!
//! A key pattern ending in `\*` follows the ForensicArtifacts (GRR) reading: it matches the
//! key's subkeys *and* its values. `...\CurrentVersion\Run\*` names the Run entries, which are
//! values of `Run`, not subkeys.

use std::collections::BTreeMap;

use crate::artifact::{Artifact, RegistryArtifacts};
use crate::catalog::{ArtifactCatalog, ArtifactSource, Os, expand};
use crate::data::ForensicData;
use crate::dictionary::{
    ARTIFACT_DEFINITION, REGISTRY_DATA_BYTES, REGISTRY_DATA_STRINGS, REGISTRY_DATA_TYPE,
    REGISTRY_HIVE, REGISTRY_KEY, REGISTRY_KEY_LAST_WRITE, REGISTRY_PATH, REGISTRY_VALUE, USER_ID,
};
use crate::err::{ForensicError, ForensicResult};
use crate::field::{Field, Text};
use crate::host_profile::HostProfile;
use crate::pipeline::context::ParseContext;
use crate::provenance::{Acquisition, Recovery, SourceHandle, SourceKey};
use crate::traits::forensic::{ArtifactParserFactory, ParserDescriptor, ParserRun};
use crate::traits::registry::{RegValue, Registry, RegistryExt};

/// Registration id of [`RegistryCollector`].
pub const PARSER_ID: &str = "core.registry_collector";

/// At most this many keys are collected for one definition. A pattern like `HKU\*\Software\**`
/// would otherwise copy whole hives; past the cap the definition is truncated, with an `Err`
/// item that says so.
pub const MAX_KEYS_PER_DEFINITION: usize = 10_000;

/// Emits one [`ForensicData`] per registry value the run's catalog names, and one per named key
/// that has no values (so its existence and last-write time still show). Each record carries
/// the definition that named it (`artifact.definition`), the ECS `registry.*` fields, the value
/// as stored (`registry.data.strings` for strings and numbers, base64 `registry.data.bytes` for
/// everything else), the key's last-write time, and the user's SID for a `%%users.sid%%` key.
///
/// Nothing is interpreted and no `@timestamp` is set: a key's last-write time is not the time
/// any one value was written. A key or value both a definition and a later one name is
/// collected once, for the first definition in catalog order.
///
/// Stateless (`&self`); needs a registry and a catalog, and declines without either.
pub struct RegistryCollector {
    descriptor: ParserDescriptor,
}

impl Default for RegistryCollector {
    fn default() -> Self {
        Self {
            descriptor: ParserDescriptor::new(
                PARSER_ID,
                "Registry collector",
                "Collects, uninterpreted, the registry keys and values every artifact-catalog \
                 definition names",
                env!("CARGO_PKG_VERSION"),
            )
            // Never empty: an empty list means "every artifact".
            .with_artifacts(
                &[Artifact::Windows(
                    crate::artifact::WindowsArtifacts::Registry(RegistryArtifacts::CatalogValues),
                )][..],
            ),
        }
    }
}

impl RegistryCollector {
    pub fn new() -> Self {
        Self::default()
    }
}

/// What to read at one key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Read {
    /// Every value, or a key-only record when it has none.
    Key,
    /// Every value, and nothing when it has none: the parent of a `\*` pattern.
    ValuesOf,
    /// One named value.
    Value(String),
}

/// Every key to read, keyed by path and what to read there.
type Plan = BTreeMap<(String, Read), Target>;

/// One key to read, and for whom.
struct Target {
    definition: Text,
    sid: Option<String>,
}

impl ArtifactParserFactory for RegistryCollector {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    fn can_parse(&self, ctx: &ParseContext<'_>) -> bool {
        ctx.registry().is_some() && ctx.sources().catalog().is_some()
    }

    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        let (Some(registry), Some(catalog)) = (ctx.registry().cloned(), ctx.sources().catalog())
        else {
            return Ok(ParserRun::pull(std::iter::empty()));
        };
        let empty = HostProfile::default();
        let host_profile = ctx.host_profile().unwrap_or(&empty);
        let (targets, mut head) = plan(registry.as_ref(), catalog.as_ref(), host_profile);

        let host = ctx.host().to_string();
        let acquisition = ctx.acquisition();
        let live = (acquisition == Acquisition::LiveApi).then(|| {
            ctx.register_source(SourceKey::Live {
                host: host.clone(),
                api: "Registry".into(),
            })
        });
        let mut sources: BTreeMap<String, SourceHandle> = BTreeMap::new();
        for (key, _) in targets.keys() {
            if !sources.contains_key(key) {
                let source = match &live {
                    Some(live) => live.clone(),
                    None => ctx.register_source(SourceKey::Path(key.clone())),
                };
                sources.insert(key.clone(), source);
            }
        }

        let mut out: Vec<ForensicResult<ForensicData>> = std::mem::take(&mut head);
        for ((key, read), target) in targets {
            let Some(source) = sources.get(&key) else {
                continue;
            };
            let record = |value: Option<(&str, &RegValue)>| {
                let mut data = ForensicData::new(
                    &host,
                    Artifact::Windows(crate::artifact::WindowsArtifacts::Registry(
                        RegistryArtifacts::CatalogValues,
                    )),
                    source.mint(acquisition, Recovery::Allocated),
                );
                data.set(ARTIFACT_DEFINITION, target.definition.to_string());
                let (hive, sub) = key.split_once('\\').unwrap_or((key.as_str(), ""));
                data.set(REGISTRY_HIVE, hive_abbreviation(hive));
                data.set(REGISTRY_KEY, sub.to_string());
                if let Some(sid) = &target.sid {
                    data.set(USER_ID, sid.clone());
                }
                if let Some((name, value)) = value {
                    data.set(REGISTRY_PATH, format!("{key}\\{name}"));
                    data.set(REGISTRY_VALUE, name.to_string());
                    set_data(&mut data, value);
                } else {
                    data.set(REGISTRY_PATH, key.clone());
                }
                data
            };
            // A read error names the key: the registry error types carry no path of their own
            // for anything but a missing key or value, and those are no match, not errors.
            let at = |e: ForensicError| ForensicError::other(PARSER_ID, format!("{key}: {e}"));
            let opened = match registry.key(&key) {
                Ok(opened) => opened,
                Err(e) if e.is_registry_not_found() => continue,
                Err(e) => {
                    out.push(Err(at(e)));
                    continue;
                }
            };
            let last_write = match opened.info() {
                Ok(info) => info.last_write_time,
                Err(e) => {
                    out.push(Err(at(e)));
                    None
                }
            };
            let stamp = |mut data: ForensicData| {
                if let Some(ts) = last_write {
                    data.set(REGISTRY_KEY_LAST_WRITE, ts);
                }
                Ok(data)
            };
            match read {
                Read::Value(name) => match opened.value(&name) {
                    Ok(value) => out.push(stamp(record(Some((&name, &value))))),
                    Err(e) if e.is_registry_not_found() => {}
                    Err(e) => out.push(Err(at(e))),
                },
                Read::Key | Read::ValuesOf => match opened.values() {
                    Ok(values) if values.is_empty() => {
                        if read == Read::Key {
                            out.push(stamp(record(None)));
                        }
                    }
                    Ok(values) => {
                        out.extend(
                            values
                                .iter()
                                .map(|(name, value)| stamp(record(Some((name, value))))),
                        );
                    }
                    Err(e) => out.push(Err(at(e))),
                },
            }
        }
        Ok(ParserRun::pull(out.into_iter()))
    }
}

/// Every key to read, sorted by path, each once (the first definition in catalog order that
/// names it), plus what went wrong while expanding the patterns.
fn plan(
    registry: &dyn Registry,
    catalog: &dyn ArtifactCatalog,
    host: &HostProfile,
) -> (Plan, Vec<ForensicResult<ForensicData>>) {
    let mut targets: Plan = BTreeMap::new();
    let mut errors: Vec<ForensicResult<ForensicData>> = Vec::new();
    for def in catalog.iter() {
        let names_registry = def.sources.iter().any(|entry| {
            matches!(
                entry.source,
                ArtifactSource::RegistryKey { .. } | ArtifactSource::RegistryValue { .. }
            )
        });
        if !names_registry || !def.supports(Os::Windows) {
            continue;
        }
        let expansion = expand(def, catalog, host, Os::Windows);
        let at = |pattern: &str, e: ForensicError| {
            Err(ForensicError::other(
                PARSER_ID,
                format!("{}: expanding {pattern}: {e}", def.name),
            ))
        };
        let mut found: Vec<((String, Read), Option<String>)> = Vec::new();
        for key in &expansion.keys {
            match registry.expand_key_pattern(&key.pattern) {
                Ok(paths) => {
                    found.extend(paths.into_iter().map(|p| ((p, Read::Key), key.sid.clone())))
                }
                Err(e) => errors.push(at(&key.pattern, e)),
            }
            if let Some(parent) = key.pattern.strip_suffix("\\*") {
                match registry.expand_key_pattern(parent) {
                    Ok(paths) => found.extend(
                        paths
                            .into_iter()
                            .map(|p| ((p, Read::ValuesOf), key.sid.clone())),
                    ),
                    Err(e) => errors.push(at(parent, e)),
                }
            }
        }
        for value in &expansion.values {
            match registry.expand_key_pattern(&value.key) {
                Ok(paths) => found.extend(
                    paths
                        .into_iter()
                        .map(|p| ((p, Read::Value(value.value.clone())), value.sid.clone())),
                ),
                Err(e) => errors.push(at(&value.key, e)),
            }
        }
        if found.len() > MAX_KEYS_PER_DEFINITION {
            errors.push(Err(ForensicError::other(
                PARSER_ID,
                format!(
                    "{}: {} keys match, more than {MAX_KEYS_PER_DEFINITION}; only the first \
                     {MAX_KEYS_PER_DEFINITION} by path were collected",
                    def.name,
                    found.len()
                ),
            )));
            found.sort_by(|a, b| a.0.cmp(&b.0));
            found.truncate(MAX_KEYS_PER_DEFINITION);
        }
        for (key, sid) in found {
            targets.entry(key).or_insert_with(|| Target {
                definition: def.name.clone(),
                sid,
            });
        }
    }
    (targets, errors)
}

/// The ECS short form of a hive designator (`HKEY_LOCAL_MACHINE` → `HKLM`), as written when it
/// already is one, or isn't a hive this knows.
fn hive_abbreviation(hive: &str) -> String {
    match hive.to_ascii_uppercase().as_str() {
        "HKEY_LOCAL_MACHINE" => "HKLM".into(),
        "HKEY_USERS" => "HKU".into(),
        "HKEY_CURRENT_USER" => "HKCU".into(),
        "HKEY_CLASSES_ROOT" => "HKCR".into(),
        "HKEY_CURRENT_CONFIG" => "HKCC".into(),
        _ => hive.to_string(),
    }
}

/// The value's type and its data as stored: strings and numbers as text, everything else as
/// base64 bytes.
fn set_data(data: &mut ForensicData, value: &RegValue) {
    data.set(REGISTRY_DATA_TYPE, value.value_type().name().into_owned());
    let strings: Option<Vec<Text>> = match value {
        RegValue::SZ(s) | RegValue::ExpandSZ(s) | RegValue::Link(s) => {
            Some(vec![Text::Owned(s.clone())])
        }
        RegValue::MultiSZ(list) => Some(list.iter().map(|s| Text::Owned(s.clone())).collect()),
        RegValue::DWord(v) | RegValue::DWordBigEndian(v) => Some(vec![Text::Owned(v.to_string())]),
        RegValue::QWord(v) => Some(vec![Text::Owned(v.to_string())]),
        _ => None,
    };
    if let Some(strings) = strings {
        data.insert(Text::Borrowed(REGISTRY_DATA_STRINGS), Field::Array(strings));
        return;
    }
    let bytes: &[u8] = match value {
        RegValue::Binary(b)
        | RegValue::ResourceList(b)
        | RegValue::FullResourceDescriptor(b)
        | RegValue::ResourceRequirementsList(b) => b,
        RegValue::Unknown { data, .. } => data,
        _ => &[],
    };
    if !bytes.is_empty() {
        data.set(REGISTRY_DATA_BYTES, base64(bytes));
    }
}

/// Standard base64 (RFC 4648, padded).
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> shift) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::sync::Arc;

    use super::*;
    use crate::bridge::CancellationToken;
    use crate::catalog::{ArtifactDefinition, RegistryValueRef, SliceCatalog, SourceEntry};
    use crate::pipeline::context::TriageContext;
    use crate::pipeline::sources::TriageSources;
    use crate::utils::testing::{TestingRegistry, collect_run};
    use crate::utils::time::ForensicTimestamp;

    const ALICE: &str = "S-1-5-21-1-2-3-1001";
    const NT: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

    fn def(name: &'static str, source: ArtifactSource) -> ArtifactDefinition {
        ArtifactDefinition {
            name: Cow::Borrowed(name),
            aliases: Cow::Borrowed(&[]),
            doc: Cow::Borrowed(""),
            sources: Cow::Owned(vec![SourceEntry {
                source,
                supported_os: Cow::Borrowed(&[]),
            }]),
            supported_os: Cow::Borrowed(&[Os::Windows]),
            urls: Cow::Borrowed(&[]),
        }
    }

    fn keys(keys: &'static [Text]) -> ArtifactSource {
        ArtifactSource::RegistryKey {
            keys: Cow::Borrowed(keys),
        }
    }

    /// The real definitions' shapes: Run keys (`\*`, machine and per user), a named value
    /// (AppCompatCache), a key with no wildcard (MountedDevices), and a second definition naming
    /// a key the first already does.
    fn catalog() -> Arc<dyn ArtifactCatalog> {
        Arc::new(
            SliceCatalog::new(vec![
                def(
                    "WindowsAppCompatCache",
                    ArtifactSource::RegistryValue {
                        pairs: Cow::Owned(vec![RegistryValueRef {
                            key: Cow::Borrowed(
                                r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\AppCompatCache",
                            ),
                            value: Cow::Borrowed("AppCompatCache"),
                        }]),
                    },
                ),
                def(
                    "WindowsMountedDevices",
                    keys(&[Cow::Borrowed(r"HKEY_LOCAL_MACHINE\System\MountedDevices")]),
                ),
                def(
                    "WindowsRunKeys",
                    keys(&[
                        Cow::Borrowed(
                            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\*",
                        ),
                        Cow::Borrowed(
                            r"HKEY_USERS\%%users.sid%%\Software\Microsoft\Windows\CurrentVersion\Run\*",
                        ),
                    ]),
                ),
                def(
                    "ZDuplicateRunKeys",
                    keys(&[Cow::Borrowed(
                        r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\*",
                    )]),
                ),
            ])
            .unwrap(),
        )
    }

    fn registry() -> TestingRegistry {
        let mut reg = TestingRegistry::empty();
        reg.add_value(NT, "SystemRoot", RegValue::new_sz(r"C:\Windows"));
        reg.add_value(
            &format!(r"{NT}\ProfileList\{ALICE}"),
            "ProfileImagePath",
            RegValue::new_sz(r"C:\Users\alice"),
        );
        let machine_run = format!(r"HKLM\{RUN}");
        reg.add_value(
            &machine_run,
            "Updater",
            RegValue::new_sz(r"C:\Tools\upd.exe"),
        );
        reg.set_last_write(
            &machine_run,
            ForensicTimestamp::from_win_filetime(133_514_430_235_959_706),
        );
        reg.add_value(
            &format!(r"HKU\{ALICE}\{RUN}"),
            "OneDrive",
            RegValue::ExpandSZ(r"%LOCALAPPDATA%\OneDrive.exe".into()),
        );
        reg.add_value(
            r"HKLM\System\CurrentControlSet\Control\Session Manager\AppCompatCache",
            "AppCompatCache",
            RegValue::Binary(b"foobar".to_vec()),
        );
        reg.add_key(r"HKLM\System\MountedDevices");
        reg
    }

    fn run(sources: &TriageSources) -> Vec<ForensicData> {
        let triage = TriageContext::new("HOST", "t");
        let cancellation = CancellationToken::new();
        let ctx = ParseContext::new(sources, &triage, &cancellation);
        let parser = RegistryCollector::new();
        assert!(parser.can_parse(&ctx));
        collect_run(parser.open(&ctx).unwrap())
            .unwrap()
            .into_iter()
            .map(|item| item.unwrap())
            .collect()
    }

    fn sources() -> TriageSources {
        TriageSources::builder()
            .registry(Arc::new(registry()))
            .catalog(catalog())
            .acquisition(Acquisition::ImageRead)
            .build()
    }

    fn text<'a>(data: &'a ForensicData, field: &str) -> Option<&'a str> {
        data.field_as_str(field)
    }

    #[test]
    fn run_entries_are_the_values_of_the_run_key_each_with_its_definition_and_user() {
        let records = run(&sources());
        type Row<'a> = (
            Option<&'a str>,
            Option<&'a str>,
            Option<&'a str>,
            Option<&'a str>,
        );
        let run: Vec<Row<'_>> = records
            .iter()
            .filter(|d| text(d, ARTIFACT_DEFINITION) == Some("WindowsRunKeys"))
            .map(|d| {
                (
                    text(d, REGISTRY_HIVE),
                    text(d, REGISTRY_VALUE),
                    text(d, USER_ID),
                    text(d, REGISTRY_DATA_TYPE),
                )
            })
            .collect();
        assert_eq!(
            run,
            vec![
                (Some("HKLM"), Some("Updater"), None, Some("REG_SZ")),
                (
                    Some("HKU"),
                    Some("OneDrive"),
                    Some(ALICE),
                    Some("REG_EXPAND_SZ")
                ),
            ]
        );
        let updater = records
            .iter()
            .find(|d| text(d, REGISTRY_VALUE) == Some("Updater"))
            .unwrap();
        assert_eq!(
            updater.field(REGISTRY_DATA_STRINGS),
            Some(&Field::Array(vec![Text::Borrowed(r"C:\Tools\upd.exe")]))
        );
        assert_eq!(text(updater, REGISTRY_KEY), Some(RUN));
        assert!(updater.field(REGISTRY_KEY_LAST_WRITE).is_some());
        // A key's last write is not the value's event time.
        assert!(updater.field(crate::dictionary::TIMESTAMP).is_none());
    }

    #[test]
    fn a_key_two_definitions_name_is_collected_once_for_the_first() {
        let records = run(&sources());
        assert!(
            records
                .iter()
                .all(|d| text(d, ARTIFACT_DEFINITION) != Some("ZDuplicateRunKeys"))
        );
        assert_eq!(
            records
                .iter()
                .filter(|d| text(d, REGISTRY_VALUE) == Some("Updater"))
                .count(),
            1
        );
    }

    #[test]
    fn a_named_binary_value_is_kept_as_base64_and_a_key_without_values_still_shows() {
        let records = run(&sources());
        let cache = records
            .iter()
            .find(|d| text(d, ARTIFACT_DEFINITION) == Some("WindowsAppCompatCache"))
            .unwrap();
        assert_eq!(text(cache, REGISTRY_DATA_TYPE), Some("REG_BINARY"));
        assert_eq!(text(cache, REGISTRY_DATA_BYTES), Some("Zm9vYmFy"));
        assert!(cache.field(REGISTRY_DATA_STRINGS).is_none());
        let mounted: Vec<&ForensicData> = records
            .iter()
            .filter(|d| text(d, ARTIFACT_DEFINITION) == Some("WindowsMountedDevices"))
            .collect();
        assert_eq!(mounted.len(), 1);
        assert!(mounted[0].field(REGISTRY_VALUE).is_none());
        assert_eq!(
            text(mounted[0], REGISTRY_PATH),
            Some(r"HKEY_LOCAL_MACHINE\System\MountedDevices")
        );
    }

    #[test]
    fn each_key_is_its_own_provenance_source() {
        let triage = TriageContext::new("HOST", "t");
        let store = triage.provenance_store();
        let cancellation = CancellationToken::new();
        let sources = sources();
        let ctx = ParseContext::new(&sources, &triage, &cancellation);
        let records = collect_run(RegistryCollector::new().open(&ctx).unwrap()).unwrap();
        for record in records.iter().map(|r| r.as_ref().unwrap()) {
            let key = text(record, REGISTRY_PATH).unwrap();
            let source = store.get(record.provenance()).unwrap().source;
            let SourceKey::Path(path) = source else {
                panic!("{source:?}");
            };
            assert!(key.starts_with(&path), "{key} from {path}");
        }
    }

    #[test]
    fn a_source_with_no_user_hives_is_no_match_not_an_error() {
        let mut machine_only = TestingRegistry::empty();
        machine_only.add_value(
            &format!(r"HKLM\{RUN}"),
            "Updater",
            RegValue::new_sz(r"C:\Tools\upd.exe"),
        );
        let sources = TriageSources::builder()
            .registry(Arc::new(machine_only))
            .catalog(catalog())
            .acquisition(Acquisition::ImageRead)
            .build();
        // `run` unwraps every item: an `Err` for the missing `HKEY_USERS` would fail here.
        let records = run(&sources);
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn without_a_registry_or_a_catalog_it_declines() {
        let triage = TriageContext::new("HOST", "t");
        let cancellation = CancellationToken::new();
        for sources in [
            TriageSources::builder().catalog(catalog()).build(),
            TriageSources::builder()
                .registry(Arc::new(registry()))
                .build(),
        ] {
            let ctx = ParseContext::new(&sources, &triage, &cancellation);
            assert!(!RegistryCollector::new().can_parse(&ctx));
        }
    }

    #[test]
    fn base64_matches_rfc_4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), expected, "{input}");
        }
    }
}
