//! Stable identity for the subjects an investigation correlates evidence
//! about: a host, a user, an executable, a process, ...
//!
//! [`EntityId`] is deliberately **content-derived**, never a sequence
//! number: two artifacts that describe the same real-world host, user, or
//! executable must resolve to the same `EntityId` whether they were parsed
//! in the same run or two collection waves a month apart. A sequence
//! counter can't offer that — the whole point of an entity graph is to let
//! evidence collected later corroborate evidence collected earlier.

use crate::core::fnv1a64;
use crate::traits::digest::ContentAddress;
use crate::utils::time::ForensicTimestamp;

/// What kind of real-world subject an [`EntityId`] identifies.
///
/// `#[non_exhaustive]`: new subject kinds are expected as correlation
/// coverage grows.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EntityKind {
    Host,
    User,
    Executable,
    File,
    Process,
    NetworkEndpoint,
    RegistryKey,
    ScheduledTask,
    Service,
}

/// A stable, content-derived identifier for one entity.
///
/// Two `EntityId`s are equal exactly when they were built from the same
/// [`EntityKind`] and the same identity fields — never by chance collision
/// across kinds, since the kind tag is folded into the hash. There is no
/// public constructor other than the per-kind functions below: an
/// `EntityId` always says *how* it was derived from its type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EntityId {
    kind: EntityKind,
    hash: u64,
}

impl EntityId {
    fn from_parts(kind: EntityKind, parts: &[&str]) -> Self {
        let mut buf = Vec::new();
        buf.extend_from_slice(format!("{kind:?}").as_bytes());
        for part in parts {
            buf.push(0);
            buf.extend_from_slice(part.as_bytes());
        }
        Self {
            kind,
            hash: fnv1a64(&buf),
        }
    }

    pub fn kind(&self) -> EntityKind {
        self.kind
    }

    /// A host, identified by whatever stable name/id the caller has for it
    /// (a hostname, a machine SID, an asset tag — the crate takes no
    /// position on which is authoritative).
    pub fn host(identity: &str) -> Self {
        Self::from_parts(EntityKind::Host, &[identity])
    }

    /// A user, scoped to the host they were observed on (a SID is unique
    /// within a host/domain, not globally).
    pub fn user(host: &str, sid: &str) -> Self {
        Self::from_parts(EntityKind::User, &[host, sid])
    }

    /// An executable identified by content hash — prefer this over
    /// [`Self::executable_by_path`] whenever a hash is available, since a
    /// path alone can't distinguish a legitimate binary from malware
    /// dropped at the same path.
    pub fn executable_by_hash(hash: &ContentAddress) -> Self {
        Self::from_parts(
            EntityKind::Executable,
            &[&format!("{:?}", hash.algorithm), &hash.to_hex()],
        )
    }

    /// An executable identified only by host + path, when no content hash
    /// is available.
    pub fn executable_by_path(host: &str, path: &str) -> Self {
        Self::from_parts(EntityKind::Executable, &[host, path])
    }

    /// A file identified by content hash.
    pub fn file_by_hash(hash: &ContentAddress) -> Self {
        Self::from_parts(EntityKind::File, &[&format!("{:?}", hash.algorithm), &hash.to_hex()])
    }

    /// A file identified by host + path, when no content hash is available.
    pub fn file_by_path(host: &str, path: &str) -> Self {
        Self::from_parts(EntityKind::File, &[host, path])
    }

    /// A process instance: PID alone is reused constantly, so identity
    /// requires the host and the process's start time too.
    pub fn process(host: &str, pid: u32, start_time: ForensicTimestamp) -> Self {
        Self::from_parts(EntityKind::Process, &[host, &pid.to_string(), &format!("{start_time:?}")])
    }

    /// A network endpoint: an address, optionally scoped by port.
    pub fn network_endpoint(address: &str, port: Option<u16>) -> Self {
        let port_str = port.map(|p| p.to_string()).unwrap_or_default();
        Self::from_parts(EntityKind::NetworkEndpoint, &[address, &port_str])
    }

    /// A registry key, scoped to the host it was observed on.
    pub fn registry_key(host: &str, key_path: &str) -> Self {
        Self::from_parts(EntityKind::RegistryKey, &[host, key_path])
    }

    pub fn scheduled_task(host: &str, name: &str) -> Self {
        Self::from_parts(EntityKind::ScheduledTask, &[host, name])
    }

    pub fn service(host: &str, name: &str) -> Self {
        Self::from_parts(EntityKind::Service, &[host, name])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::digest::DigestAlgorithm;

    #[test]
    fn same_inputs_produce_the_same_id() {
        assert_eq!(EntityId::host("WORKSTATION01"), EntityId::host("WORKSTATION01"));
        assert_eq!(
            EntityId::user("WORKSTATION01", "S-1-5-21-1"),
            EntityId::user("WORKSTATION01", "S-1-5-21-1")
        );
    }

    #[test]
    fn different_kinds_never_collide_even_with_identical_field_text() {
        // Same literal string, different kind -- must not collide.
        let host = EntityId::host("shared-name");
        let service = EntityId::service("h", "shared-name");
        assert_ne!(host, service);
        assert_ne!(host.kind(), service.kind());
    }

    #[test]
    fn different_hosts_never_collide_for_the_same_user_sid() {
        let a = EntityId::user("HOST-A", "S-1-5-21-1");
        let b = EntityId::user("HOST-B", "S-1-5-21-1");
        assert_ne!(a, b);
    }

    #[test]
    fn executable_by_hash_prefers_content_over_path() {
        let hash = ContentAddress::new(DigestAlgorithm::Sha256, vec![1, 2, 3]);
        let by_hash = EntityId::executable_by_hash(&hash);
        let by_path = EntityId::executable_by_path("host", "C:/evil.exe");
        assert_ne!(by_hash, by_path);
        // Same hash, different (irrelevant) path on disk -- still the same entity.
        assert_eq!(by_hash, EntityId::executable_by_hash(&hash));
    }

    #[test]
    fn process_identity_includes_start_time_not_just_pid() {
        let t1 = ForensicTimestamp::from_unix_secs(1_700_000_000);
        let t2 = ForensicTimestamp::from_unix_secs(1_700_000_100);
        assert_ne!(EntityId::process("h", 1234, t1), EntityId::process("h", 1234, t2));
    }

    #[test]
    fn entity_id_is_a_stable_size_copy_type() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<EntityId>();
    }
}
