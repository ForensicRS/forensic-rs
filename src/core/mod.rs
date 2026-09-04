pub mod fs;
pub mod limits;
pub mod locator;
pub mod path;
pub mod resolver;

pub type UserEnvVars = std::collections::BTreeMap<String, String>;
pub type UsersEnvVars = std::collections::BTreeMap<String, UserEnvVars>;

/// A deterministic FNV-1a hash, chosen instead of `std::hash::DefaultHasher`
/// specifically because `RandomState` is seeded per-process: a value hashed
/// the same way twice must produce the same `u64` in two separate runs, or
/// two identical evidence sets processed on different days would report
/// different fingerprint/id values, breaking the reproducibility guarantee
/// the rest of the pipeline is held to.
///
/// Shared by [`crate::traits::forensic::SchemaFingerprint::fingerprint`] and
/// [`crate::pipeline::timeline::EventId::new`] — both need the same
/// deterministic-across-runs property for the same reason.
pub(crate) fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = OFFSET;
    for &byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

pub fn interpolate_env_vars(pth: &str, env_vars: &UserEnvVars, ret: &mut String) -> Option<()> {
    if let Some(stripped) = pth.strip_prefix('%') {
        let pos = stripped.as_bytes().iter().position(|&v| v == b'%')?;
        let env_var = &stripped[..pos];
        let rest = if pos + 1 > stripped.len() {
            ""
        } else {
            &stripped[pos + 1..]
        };
        let to_replace_with = env_vars.get(env_var)?;
        interpolate_env_vars(to_replace_with, env_vars, ret)?;
        ret.push_str(rest);
    } else {
        ret.push_str(pth);
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a64_is_deterministic_and_sensitive_to_input() {
        assert_eq!(fnv1a64(b"hello"), fnv1a64(b"hello"));
        assert_ne!(fnv1a64(b"hello"), fnv1a64(b"world"));
        assert_ne!(fnv1a64(b""), fnv1a64(b"\0"));
    }
}
