//! [`SliceCatalog`]: an [`ArtifactCatalog`] over a sorted slice.

use std::borrow::Cow;

use super::{ArtifactCatalog, ArtifactDefinition, ArtifactSource};
use crate::err::{ForensicError, ForensicResult};
use crate::field::Text;

/// One entry of a [`SliceCatalog`] lookup index: a name or alias, and the
/// position of its definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogIndexEntry {
    pub key: Text,
    pub def: usize,
}

/// An [`ArtifactCatalog`] over definitions sorted by name, plus an index of
/// every name and alias sorted by key. Lookups are binary searches, and
/// iteration follows the definitions' order.
///
/// Build one at run time with [`new`](Self::new), which sorts and checks
/// the input, or over generated `static` data with
/// [`from_static`](Self::from_static), whose invariants
/// [`validate`](Self::validate) checks.
#[derive(Debug, Clone)]
pub struct SliceCatalog {
    defs: Cow<'static, [ArtifactDefinition]>,
    index: Cow<'static, [CatalogIndexEntry]>,
}

impl SliceCatalog {
    /// Sorts `defs` by name and indexes every name and alias. Fails when a
    /// name or alias is used twice.
    pub fn new(mut defs: Vec<ArtifactDefinition>) -> ForensicResult<Self> {
        defs.sort_by(|a, b| a.name.cmp(&b.name));
        let mut index: Vec<CatalogIndexEntry> = defs
            .iter()
            .enumerate()
            .flat_map(|(i, def)| {
                std::iter::once(&def.name)
                    .chain(def.aliases.iter())
                    .map(move |key| CatalogIndexEntry {
                        key: key.clone(),
                        def: i,
                    })
            })
            .collect();
        index.sort_by(|a, b| a.key.cmp(&b.key));
        let catalog = SliceCatalog {
            defs: Cow::Owned(defs),
            index: Cow::Owned(index),
        };
        catalog.validate()?;
        Ok(catalog)
    }

    /// Wraps pre-sorted `static` data, as generated code emits it: `defs`
    /// sorted by name, `index` sorted by key with every name and alias
    /// exactly once. Not checked here, so that it stays `const`; test the
    /// generated catalog with [`validate`](Self::validate).
    pub const fn from_static(
        defs: &'static [ArtifactDefinition],
        index: &'static [CatalogIndexEntry],
    ) -> Self {
        SliceCatalog {
            defs: Cow::Borrowed(defs),
            index: Cow::Borrowed(index),
        }
    }

    /// Checks the invariants [`from_static`](Self::from_static) relies on:
    /// definitions sorted by unique name; the index sorted by unique key,
    /// covering exactly every name and alias, each pointing at its own
    /// definition.
    pub fn validate(&self) -> ForensicResult<()> {
        let fail = |msg: String| Err(ForensicError::other("catalog", msg));
        for pair in self.defs.windows(2) {
            if pair[0].name >= pair[1].name {
                return fail(format!(
                    "definitions not sorted by unique name at {}",
                    pair[1].name
                ));
            }
        }
        for pair in self.index.windows(2) {
            if pair[0].key >= pair[1].key {
                return fail(format!("name or alias used twice: {}", pair[1].key));
            }
        }
        let expected: usize = self.defs.iter().map(|d| 1 + d.aliases.len()).sum();
        if expected != self.index.len() {
            return fail(format!(
                "index has {} entries, the definitions have {expected} names and aliases",
                self.index.len()
            ));
        }
        for entry in self.index.iter() {
            let Some(def) = self.defs.get(entry.def) else {
                return fail(format!("index entry {} points past the end", entry.key));
            };
            if def.name != entry.key && !def.aliases.contains(&entry.key) {
                return fail(format!(
                    "index entry {} points at {}, which doesn't carry that name",
                    entry.key, def.name
                ));
            }
        }
        Ok(())
    }

    /// Names referenced by `ARTIFACT_GROUP` sources that no definition
    /// carries, as `(group, missing member)`, sorted.
    pub fn dangling_group_members(&self) -> Vec<(Text, Text)> {
        let mut missing: Vec<(Text, Text)> = self
            .defs
            .iter()
            .flat_map(|def| def.sources.iter().map(move |entry| (def, entry)))
            .filter_map(|(def, entry)| match &entry.source {
                ArtifactSource::Group { names } => Some((def, names)),
                _ => None,
            })
            .flat_map(|(def, names)| {
                names
                    .iter()
                    .filter(|name| self.get(name).is_none())
                    .map(|name| (def.name.clone(), name.clone()))
            })
            .collect();
        missing.sort();
        missing
    }

    pub fn len(&self) -> usize {
        self.defs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.defs.is_empty()
    }
}

impl ArtifactCatalog for SliceCatalog {
    fn get(&self, name: &str) -> Option<&ArtifactDefinition> {
        let i = self
            .index
            .binary_search_by(|entry| entry.key.as_ref().cmp(name))
            .ok()?;
        self.defs.get(self.index[i].def)
    }

    fn iter(&self) -> Box<dyn Iterator<Item = &ArtifactDefinition> + '_> {
        Box::new(self.defs.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{Separator, SourceEntry};

    pub(crate) fn def(name: &'static str, aliases: &'static [Text]) -> ArtifactDefinition {
        ArtifactDefinition {
            name: Cow::Borrowed(name),
            aliases: Cow::Borrowed(aliases),
            doc: Cow::Borrowed(""),
            sources: Cow::Owned(vec![SourceEntry {
                source: ArtifactSource::File {
                    paths: Cow::Owned(vec![Cow::Borrowed("/x")]),
                    separator: Separator::Slash,
                },
                supported_os: Cow::Borrowed(&[]),
            }]),
            supported_os: Cow::Borrowed(&[]),
            urls: Cow::Borrowed(&[]),
        }
    }

    #[test]
    fn looks_up_by_name_and_alias_and_iterates_sorted() {
        let catalog = SliceCatalog::new(vec![
            def("Zeta", &[]),
            def("Alpha", &[Cow::Borrowed("OldAlpha")]),
        ])
        .unwrap();
        assert_eq!(catalog.get("Alpha").unwrap().name, "Alpha");
        assert_eq!(catalog.get("OldAlpha").unwrap().name, "Alpha");
        assert_eq!(catalog.get("Zeta").unwrap().name, "Zeta");
        assert!(catalog.get("alpha").is_none());
        let names: Vec<&str> = catalog.iter().map(|d| d.name.as_ref()).collect();
        assert_eq!(names, vec!["Alpha", "Zeta"]);
    }

    #[test]
    fn rejects_a_name_used_twice_even_as_an_alias() {
        let err = SliceCatalog::new(vec![def("A", &[]), def("B", &[Cow::Borrowed("A")])]);
        assert!(err.is_err());
    }

    static STATIC_DEFS: [ArtifactDefinition; 1] = [ArtifactDefinition {
        name: Cow::Borrowed("Static"),
        aliases: Cow::Borrowed(&[Cow::Borrowed("Alias")]),
        doc: Cow::Borrowed("built as a static"),
        sources: Cow::Borrowed(&[SourceEntry {
            source: ArtifactSource::File {
                paths: Cow::Borrowed(&[Cow::Borrowed("%%environ_systemroot%%\\x")]),
                separator: Separator::Backslash,
            },
            supported_os: Cow::Borrowed(&[]),
        }]),
        supported_os: Cow::Borrowed(&[crate::catalog::Os::Windows]),
        urls: Cow::Borrowed(&[]),
    }];
    static STATIC_INDEX: [CatalogIndexEntry; 2] = [
        CatalogIndexEntry {
            key: Cow::Borrowed("Alias"),
            def: 0,
        },
        CatalogIndexEntry {
            key: Cow::Borrowed("Static"),
            def: 0,
        },
    ];
    static STATIC_CATALOG: SliceCatalog = SliceCatalog::from_static(&STATIC_DEFS, &STATIC_INDEX);

    #[test]
    fn a_catalog_can_be_a_static_item() {
        STATIC_CATALOG.validate().unwrap();
        assert_eq!(STATIC_CATALOG.get("Alias").unwrap().name, "Static");
    }

    #[test]
    fn validate_catches_a_bad_static_index() {
        static BAD_INDEX: [CatalogIndexEntry; 1] = [CatalogIndexEntry {
            key: Cow::Borrowed("Static"),
            def: 0,
        }];
        let bad = SliceCatalog::from_static(&STATIC_DEFS, &BAD_INDEX);
        assert!(bad.validate().is_err());
    }

    #[test]
    fn reports_dangling_group_members() {
        let mut group = def("Group", &[]);
        group.sources = Cow::Owned(vec![SourceEntry {
            source: ArtifactSource::Group {
                names: Cow::Owned(vec![Cow::Borrowed("A"), Cow::Borrowed("Missing")]),
            },
            supported_os: Cow::Borrowed(&[]),
        }]);
        let catalog = SliceCatalog::new(vec![def("A", &[]), group]).unwrap();
        assert_eq!(
            catalog.dangling_group_members(),
            vec![(Cow::Borrowed("Group"), Cow::Borrowed("Missing"))]
        );
    }
}
