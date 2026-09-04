//! Content hashing -- a trait only, no implementation.
//!
//! `forensic-rs` deliberately takes no hashing dependency (see the crate's
//! single-dependency stance). A real `sha2`/`blake3`-backed [`Digest`] lives
//! in a downstream crate; this module only defines the contract so
//! [`crate::provenance::SourceKey::ContentHash`] can be produced from real
//! bytes instead of a caller-computed string, and so the mount resolver can
//! intern the same content reached through two different container chains.

/// Which digest algorithm produced a [`ContentAddress`].
///
/// `#[non_exhaustive]`: new algorithms may be added without a breaking
/// change.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DigestAlgorithm {
    Sha1,
    Sha256,
    Blake3,
    /// A backend-specific algorithm identified by name (e.g. a fuzzy hash).
    Other(&'static str),
}

/// A computed digest, tagged with the algorithm that produced it.
///
/// Two `ContentAddress` values are only meaningfully comparable when their
/// `algorithm` matches -- callers must not compare bytes across algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentAddress {
    pub algorithm: DigestAlgorithm,
    pub bytes: Box<[u8]>,
}

impl ContentAddress {
    pub fn new(algorithm: DigestAlgorithm, bytes: impl Into<Box<[u8]>>) -> Self {
        Self {
            algorithm,
            bytes: bytes.into(),
        }
    }

    /// Lowercase hex rendering, for [`crate::provenance::SourceKey::ContentHash`]
    /// and for display/logging.
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(self.bytes.len() * 2);
        for byte in self.bytes.iter() {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

/// An incremental content digest. Implemented downstream (a `sha2`/`blake3`
/// wrapper); core defines only the shape a [`crate::core::resolver::MountResolver`]
/// needs to intern content across nested-container chains.
pub trait Digest: Send + Sync {
    fn algorithm(&self) -> DigestAlgorithm;
    fn update(&mut self, bytes: &[u8]);
    /// Consumes the digest, producing the final address.
    fn finish(self: Box<Self>) -> ContentAddress;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_hex_renders_lowercase_two_digit_bytes() {
        let addr = ContentAddress::new(DigestAlgorithm::Sha256, vec![0x00, 0xab, 0xff]);
        assert_eq!(addr.to_hex(), "00abff");
    }

    #[test]
    fn addresses_with_different_algorithms_are_not_equal_even_with_same_bytes() {
        let a = ContentAddress::new(DigestAlgorithm::Sha1, vec![1, 2, 3]);
        let b = ContentAddress::new(DigestAlgorithm::Sha256, vec![1, 2, 3]);
        assert_ne!(a, b);
    }
}
