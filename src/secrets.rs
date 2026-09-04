//! Key material supplied by the caller to decrypt evidence-derived
//! ciphertext (DPAPI-protected credentials, BitLocker volumes, encrypted
//! archives, ...).
//!
//! `forensic-rs` never stores, caches, prompts for, or persists a secret --
//! backends (an interactive prompt, a key file, KeePass, an HSM, a domain
//! backup key) are entirely downstream. What lives here is the boundary
//! type: [`Secret`] cannot be logged, serialized, or cloned by construction,
//! so a secret that reaches a log line, a `Finding`, a `ForensicData`, or an
//! audit sink is a compile error, not a review comment.
//!
//! A failed decryption is a recorded outcome, never a silent skip: the
//! ciphertext record is still emitted, marked undecrypted, with a `Finding`
//! explaining why. See `docs` (the phase-1 refactor design record) for the
//! full worked example this type exists for -- a Chromium saved password,
//! DPAPI-protected under a master key that itself needs the user's
//! password.

use std::sync::atomic::{compiler_fence, Ordering};

use crate::field::Text;

/// What kind of key material a [`SecretRequest`] is asking for.
///
/// `#[non_exhaustive]`: new secret kinds are expected as downstream formats
/// grow (BitLocker, LUKS, encrypted archive passwords, ...).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SecretKind {
    /// A user's logon password.
    UserPassword,
    /// A user's NTLM hash, usable in place of a password for some DPAPI
    /// unlock paths.
    UserNtlmHash,
    /// The domain's DPAPI backup key (recoverable by a domain controller
    /// regardless of the user's own password).
    DpapiDomainBackupKey,
    /// A BitLocker recovery key or password.
    BitlockerRecoveryKey,
    /// An opaque key file's contents.
    KeyFile,
    /// A free-form passphrase (an encrypted archive, a keystore, ...).
    Passphrase,
    /// A downstream-defined kind not covered above.
    Other(Text),
}

/// One request for key material, made by a parser through
/// [`SecretProvider::provide`].
#[derive(Debug, Clone)]
pub struct SecretRequest {
    pub kind: SecretKind,
    /// Who/what the secret belongs to, when known (a SID, a username, a
    /// volume identifier). `None` when the kind is inherently subject-less
    /// (e.g. a domain backup key).
    pub subject: Option<Text>,
    /// A short, human-readable reason for the request, surfaced to whatever
    /// backend prompts for or looks up the secret (e.g. "DPAPI master key
    /// for S-1-5-21-...-1001, needed to decrypt Chromium saved passwords").
    pub hint: Text,
}

impl SecretRequest {
    pub fn new(kind: SecretKind, hint: impl Into<Text>) -> Self {
        Self {
            kind,
            subject: None,
            hint: hint.into(),
        }
    }

    #[must_use]
    pub fn with_subject(mut self, subject: impl Into<Text>) -> Self {
        self.subject = Some(subject.into());
        self
    }
}

/// Externally supplied key material.
///
/// Deliberately implements **none** of `Debug`, `Display`, `Serialize`,
/// `Clone`, or `Deref` -- there is no accidental path from a `Secret` into a
/// log line, a `Finding`, a `ForensicData`, or the capability audit sink.
/// The only way to read the bytes is the explicitly named [`Secret::expose`],
/// which is easy to grep for in a downstream review. The backing buffer is
/// zeroed on drop.
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Explicit, greppable access to the raw key material. Named `expose`,
    /// not `as_bytes` or `Deref`, so every read site is visibly a read of
    /// secret material during review.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        for byte in self.0.iter_mut() {
            // SAFETY: `byte` is a valid, aligned `&mut u8` for the duration
            // of this write; `write_volatile` prevents the compiler from
            // eliding the store as dead code ahead of deallocation.
            unsafe {
                std::ptr::write_volatile(byte as *mut u8, 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Supplies externally-held key material on request.
///
/// Implemented entirely downstream (an interactive prompt, a key file, a
/// password manager integration, an HSM). Core never implements this trait
/// with a real backend, never caches what it returns, and never persists
/// it. Returning `None` means "not available" -- a parser that cannot
/// obtain a required secret must still emit its record with the ciphertext
/// present, marked undecrypted, and raise a `Finding`; it must never skip
/// the record silently.
pub trait SecretProvider: Send + Sync {
    fn provide(&self, request: &SecretRequest) -> Option<Secret>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expose_returns_the_stored_bytes() {
        let secret = Secret::new(vec![1, 2, 3]);
        assert_eq!(secret.expose(), &[1, 2, 3]);
        assert_eq!(secret.len(), 3);
        assert!(!secret.is_empty());
    }

    #[test]
    fn empty_secret_reports_empty() {
        let secret = Secret::new(Vec::new());
        assert!(secret.is_empty());
    }

    struct FixedProvider(Vec<u8>);
    impl SecretProvider for FixedProvider {
        fn provide(&self, _request: &SecretRequest) -> Option<Secret> {
            Some(Secret::new(self.0.clone()))
        }
    }

    #[test]
    fn secret_provider_is_object_safe_and_returns_secret() {
        let provider: Box<dyn SecretProvider> = Box::new(FixedProvider(vec![9, 9, 9]));
        let request = SecretRequest::new(SecretKind::UserPassword, "test")
            .with_subject("S-1-5-21-0-0-0-1001");
        let secret = provider.provide(&request).unwrap();
        assert_eq!(secret.expose(), &[9, 9, 9]);
    }

    struct DenyingProvider;
    impl SecretProvider for DenyingProvider {
        fn provide(&self, _request: &SecretRequest) -> Option<Secret> {
            None
        }
    }

    #[test]
    fn secret_provider_may_decline() {
        let provider = DenyingProvider;
        let request = SecretRequest::new(SecretKind::DpapiDomainBackupKey, "unavailable");
        assert!(provider.provide(&request).is_none());
    }
}
