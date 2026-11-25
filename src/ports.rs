//! Ports (driven side).

use crate::domain::{Fingerprint, KeyId, Nonce, RootKey, Tag};

/// Cryptographic primitives. The domain never sees a concrete algorithm.
pub trait Crypto {
    /// Keyed MAC with a 32-byte output.
    fn mac(&self, key: &[u8], msg: &[u8]) -> Tag;
    /// Constant-time equality.
    fn tag_eq(&self, a: &Tag, b: &Tag) -> bool;
    /// One-way hash of a tag, safe to persist.
    fn fingerprint(&self, tag: &Tag) -> Fingerprint;
    /// Fresh unpredictable nonce.
    fn nonce(&self) -> Nonce;
}

/// Key ring (Repository). Exactly one key is active for minting; retired
/// keys remain valid for verification until removed.
pub trait KeyStore {
    fn active(&self) -> Option<(KeyId, RootKey)>;
    fn get(&self, id: &KeyId) -> Option<RootKey>;
}

/// Revocation list (Repository) keyed by fingerprint.
pub trait RevocationStore {
    type Error: std::error::Error + Send + Sync + 'static;

    /// `expires_at`: after this unix time the entry can be purged because the
    /// token it targets cannot verify anymore. `None` keeps it forever.
    fn revoke(&mut self, fp: Fingerprint, expires_at: Option<u64>) -> Result<(), Self::Error>;
    fn is_revoked_any(&self, fps: &[Fingerprint]) -> Result<bool, Self::Error>;
    /// Removes entries whose `expires_at <= now`; returns how many.
    fn purge_expired(&mut self, now: u64) -> Result<usize, Self::Error>;
}

/// Wall clock in unix seconds.
pub trait Clock {
    fn now_unix(&self) -> u64;
}
