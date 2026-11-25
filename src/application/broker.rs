//! Broker use cases: mint, attenuate, verify, revoke, purge.

use super::builder::TokenBuilder;
use crate::domain::*;
use crate::ports::{Clock, Crypto, KeyStore, RevocationStore};
use std::cell::RefCell;
use std::fmt;

/// Inbound DTO with raw strings (e.g. from an HTTP layer). It is parsed into a
/// domain `Request` and never enters the domain itself.
#[derive(Clone, Debug)]
pub struct AccessRequest<'a> {
    pub audience: &'a str,
    pub path: &'a str,
    pub action: &'a str,
}

#[derive(Debug)]
pub enum BrokerError {
    Invalid(DomainError),
    Denied(Denial),
    NoActiveKey,
    Storage(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BrokerError::Invalid(e) => write!(f, "{e}"),
            BrokerError::Denied(d) => write!(f, "denied: {d}"),
            BrokerError::NoActiveKey => write!(f, "no active signing key"),
            BrokerError::Storage(e) => write!(f, "storage: {e}"),
        }
    }
}
impl std::error::Error for BrokerError {}
impl From<DomainError> for BrokerError {
    fn from(e: DomainError) -> Self {
        BrokerError::Invalid(e)
    }
}
impl From<Denial> for BrokerError {
    fn from(d: Denial) -> Self {
        BrokerError::Denied(d)
    }
}

impl BrokerError {
    /// True for any outcome that must be treated as "access denied".
    pub fn is_denial(&self) -> bool {
        // Storage failures during verification also deny (fail closed).
        !matches!(self, BrokerError::Invalid(_) | BrokerError::NoActiveKey)
    }
}

pub struct Broker<K, R, C, T>
where
    K: KeyStore,
    R: RevocationStore,
    C: Crypto,
    T: Clock,
{
    keys: K,
    revocations: R,
    crypto: C,
    clock: T,
}

impl<K, R, C, T> Broker<K, R, C, T>
where
    K: KeyStore,
    R: RevocationStore,
    C: Crypto,
    T: Clock,
{
    pub fn new(keys: K, revocations: R, crypto: C, clock: T) -> Self {
        Self {
            keys,
            revocations,
            crypto,
            clock,
        }
    }

    pub fn revocations(&self) -> &R {
        &self.revocations
    }

    /// Mints a token with the active key.
    pub fn mint(&self, b: TokenBuilder) -> Result<Token, BrokerError> {
        let (key_id, root) = self.keys.active().ok_or(BrokerError::NoActiveKey)?;
        let (subject, caveats) = b.resolve(self.clock.now_unix())?;
        let id = Identifier {
            key_id,
            nonce: self.crypto.nonce(),
            subject,
        };
        Ok(Token::mint(&self.crypto, &root, id, caveats)?)
    }

    /// Holder-side attenuation; needs no key.
    pub fn attenuate(&self, t: &Token, c: Caveat) -> Result<Token, BrokerError> {
        Ok(t.attenuate(&self.crypto, c)?)
    }

    fn root_for(&self, t: &Token) -> Result<RootKey, BrokerError> {
        self.keys
            .get(&t.identifier().key_id)
            .ok_or(BrokerError::Denied(Denial::UnknownKey))
    }

    /// Verifies signature, revocation and caveats for one request.
    pub fn verify(&self, t: &Token, req: AccessRequest<'_>) -> Result<Grant, BrokerError> {
        let parsed = (|| {
            Ok::<_, DomainError>(Request {
                now: self.clock.now_unix(),
                audience: Audience::parse(req.audience)?,
                path: ResourcePath::parse(req.path)?,
                action: Action::parse(req.action)?,
            })
        })()
        .map_err(|_| BrokerError::Denied(Denial::MalformedRequest))?;
        let root = self.root_for(t)?;
        let storage_err = RefCell::new(None);
        let is_revoked = |fps: &[Fingerprint]| match self.revocations.is_revoked_any(fps) {
            Ok(b) => b,
            Err(e) => {
                *storage_err.borrow_mut() = Some(e);
                true // fail closed
            }
        };
        let res = t.authorize(&self.crypto, &root, &parsed, &is_revoked);
        if let Some(e) = storage_err.into_inner() {
            return Err(BrokerError::Storage(Box::new(e)));
        }
        Ok(res?)
    }

    /// Revokes this token and everything attenuated from it.
    pub fn revoke(&mut self, t: &Token) -> Result<(), BrokerError> {
        let root = self.root_for(t)?;
        let fps = t.chain_fingerprints(&self.crypto, &root)?;
        let fp = *fps.last().expect("chain has at least tag_0");
        let exp = min_expiry(t.caveats());
        self.revocations
            .revoke(fp, exp)
            .map_err(|e| BrokerError::Storage(Box::new(e)))
    }

    /// Revokes the whole family (the root token and every attenuation).
    pub fn revoke_family(&mut self, t: &Token) -> Result<(), BrokerError> {
        let root = self.root_for(t)?;
        let fps = t.chain_fingerprints(&self.crypto, &root)?;
        self.revocations
            .revoke(fps[0], None)
            .map_err(|e| BrokerError::Storage(Box::new(e)))
    }

    /// Drops revocation entries for tokens that can no longer verify.
    pub fn purge_revocations(&mut self) -> Result<usize, BrokerError> {
        let now = self.clock.now_unix();
        self.revocations
            .purge_expired(now)
            .map_err(|e| BrokerError::Storage(Box::new(e)))
    }
}

/// Earliest expiry among caveats: every descendant inherits it, so the
/// revocation entry is useless after it.
fn min_expiry(caveats: &[Caveat]) -> Option<u64> {
    caveats
        .iter()
        .filter_map(|c| match c {
            Caveat::ExpiresAt(t) => Some(*t),
            _ => None,
        })
        .min()
}
