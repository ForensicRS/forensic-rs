//! A host's resolved identity facts, gathered in one pass so every
//! analyzer downstream works from the same answer to "what host is this,
//! what timezone, which users" instead of each re-deriving it ad hoc or
//! silently assuming UTC/no users.
//!
//! Every field is `Option<Tracked<T>>`: absence stays absence, and a
//! resolved value carries the `ProvenanceId` of the registry read that
//! produced it. Nothing here ever defaults a value — a missing computer
//! name must never silently become an empty string, a missing timezone
//! must never silently become UTC.

use crate::core::path::FPathBuf;
use crate::provenance::{Acquisition, Recovery, SourceHandle, SourceKey, Tracked};
use crate::traits::registry::windows::{self, UserProfile, WindowsVersion};
use crate::traits::registry::{Registry, RegistryExt};

const COMPUTER_NAME_KEY: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName";

/// A host's identity facts, resolved from a registry read. See the module
/// docs for why every field is `Option<Tracked<T>>`.
#[derive(Debug, Clone, Default)]
pub struct HostProfile {
    pub computer_name: Option<Tracked<String>>,
    pub system_root: Option<Tracked<FPathBuf>>,
    pub os_version: Option<Tracked<WindowsVersion>>,
    pub users: Option<Tracked<Vec<UserProfile>>>,
    /// Always `None` today: no registry-based timezone resolver exists yet
    /// (`windows::timezone` is itself deferred — see that module's docs).
    /// Kept here, rather than added later, so a future resolver slots into
    /// this same shape without a breaking change and every caller that
    /// already matches on `HostProfile`'s fields sees the gap explicitly.
    pub timezone: Option<Tracked<String>>,
}

impl HostProfile {
    /// Resolves what it can from `registry`, minting one `ProvenanceId` per
    /// successfully-resolved field against `source` — all sharing the same
    /// interned `SourceId`, since every field here comes from reading the
    /// same registry. A field that can't be resolved stays `None`.
    pub fn resolve(registry: &dyn Registry, source: &SourceHandle, acquisition: Acquisition) -> Self {
        let mint = |recovery: Recovery| source.mint(acquisition, recovery);

        let system_root = windows::system_root(registry)
            .ok()
            .map(|root| Tracked::new(root, mint(Recovery::Allocated)));

        let os_version = windows::build(registry)
            .ok()
            .map(|version| Tracked::new(version, mint(Recovery::Allocated)));

        let users = windows::users(registry)
            .ok()
            .filter(|users| !users.is_empty())
            .map(|users| Tracked::new(users, mint(Recovery::Allocated)));

        // No `windows::computer_name` free function exists yet (deferred,
        // same as timezone), and `ComputerName` lives under a different
        // registry root than the `CurrentVersion`-anchored functions above,
        // so it's read directly here rather than inventing a one-off free
        // function in `windows` for a single caller.
        let computer_name = registry
            .value(COMPUTER_NAME_KEY, "ComputerName")
            .ok()
            .and_then(|value| String::try_from(value).ok())
            .map(|name| Tracked::new(name, mint(Recovery::Allocated)));

        Self {
            computer_name,
            system_root,
            os_version,
            users,
            timezone: None,
        }
    }

    /// Convenience: resolves against the registry and provenance store a
    /// [`crate::pipeline::context::ParseContext`] already carries, minting
    /// against a freshly-interned `SourceKey::Live` source. Returns `None`
    /// only when no registry is configured for this run at all — otherwise
    /// individual fields resolve independently and stay `None` on their
    /// own failure.
    pub fn resolve_from_context(ctx: &crate::pipeline::context::ParseContext<'_>) -> Option<Self> {
        let registry = ctx.registry()?;
        let source = ctx.register_source(SourceKey::Live {
            host: ctx.host().to_string(),
            api: "windows.registry".to_string(),
        });
        Some(Self::resolve(registry.as_ref(), &source, ctx.acquisition()))
    }

    /// Whether every field resolved. Useful as a quick pre-flight check
    /// before analysis that assumes a fully-known host context; most
    /// callers should still handle partial resolution gracefully rather
    /// than gating on this.
    pub fn is_fully_resolved(&self) -> bool {
        self.computer_name.is_some()
            && self.system_root.is_some()
            && self.os_version.is_some()
            && self.users.is_some()
        // `timezone` is deliberately excluded: it can never resolve today,
        // so requiring it would make `is_fully_resolved()` permanently false.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::ProvenanceStore;
    use crate::utils::testing::TestingRegistry;

    #[test]
    fn resolves_the_fields_a_populated_testing_registry_provides() {
        let registry = TestingRegistry::new();
        let store = ProvenanceStore::new();
        let source = store.register_source(SourceKey::Synthetic("test-host".to_string()));

        let profile = HostProfile::resolve(&registry, &source, Acquisition::LiveApi);

        // TestingRegistry::new() seeds a Volatile Environment key under one
        // user's hive (so `users` resolves) but not CurrentVersion/
        // ComputerName (so those stay None). This is the point: no field is
        // ever guessed to fill the gap.
        assert!(profile.users.is_some());
        assert!(profile.system_root.is_none());
        assert!(profile.os_version.is_none());
        assert!(profile.computer_name.is_none());
        assert!(profile.timezone.is_none());
        assert!(!profile.is_fully_resolved());
    }

    #[test]
    fn every_resolved_field_carries_a_real_provenance_id_from_the_same_source() {
        let registry = TestingRegistry::new();
        let store = ProvenanceStore::new();
        let source = store.register_source(SourceKey::Synthetic("test-host".to_string()));

        // TestingRegistry::new() seeds a SID under HKEY_USERS
        // (S-1-5-21-...-513\Volatile Environment), so `users` must resolve
        // even though ProfileList doesn't exist -- a SID present in one but
        // not the other still surfaces (see `windows::users`'s docs).
        let profile = HostProfile::resolve(&registry, &source, Acquisition::LiveApi);
        let users = profile.users.expect("the seeded HKEY_USERS SID must resolve");
        let snapshot = store.get(users.provenance()).expect("minted id must resolve");
        assert_eq!(snapshot.acquisition, Acquisition::LiveApi);
    }

    #[test]
    fn timezone_never_resolves_today_by_design() {
        let registry = TestingRegistry::new();
        let store = ProvenanceStore::new();
        let source = store.register_source(SourceKey::Synthetic("test-host".to_string()));
        let profile = HostProfile::resolve(&registry, &source, Acquisition::LiveApi);
        assert!(profile.timezone.is_none());
    }
}
