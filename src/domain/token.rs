//! Tokens and the chained-MAC algebra (mint, attenuate, verify).

use super::caveat::{first_unsatisfied, put_str, Caveat, Request};
use super::error::{Denial, DomainError};
use super::values::*;
use crate::ports::Crypto;
use std::fmt;

/// Root key material for a `KeyId`. Debug output is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct RootKey(Vec<u8>);

impl RootKey {
    /// At least 32 bytes are required.
    pub fn new(bytes: Vec<u8>) -> Result<Self, DomainError> {
        if bytes.len() < 32 {
            return Err(DomainError::Invalid("root key (need >= 32 bytes)"));
        }
        Ok(Self(bytes))
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RootKey(<redacted>)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identifier {
    pub key_id: KeyId,
    pub nonce: Nonce,
    pub subject: Subject,
}

const DOMAIN_SEP: &[u8] = b"cx9-cap-token/v1\0";

impl Identifier {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = DOMAIN_SEP.to_vec();
        put_str(&mut out, self.key_id.as_str());
        out.extend_from_slice(&self.nonce.0);
        put_str(&mut out, self.subject.as_str());
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    identifier: Identifier,
    caveats: Vec<Caveat>,
    tag: Tag,
}

/// Successful authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub subject: Subject,
    pub key_id: KeyId,
    pub nonce: Nonce,
    /// Earliest `ExpiresAt` in the chain, if any.
    pub expires_at: Option<u64>,
    pub caveats: usize,
}

impl Token {
    /// Rebuilds a token from decoded parts (signature is checked by `verify`).
    pub fn from_parts(
        identifier: Identifier,
        caveats: Vec<Caveat>,
        tag: Tag,
    ) -> Result<Self, DomainError> {
        if caveats.len() > MAX_CAVEATS {
            return Err(DomainError::TooManyCaveats);
        }
        Ok(Self {
            identifier,
            caveats,
            tag,
        })
    }

    /// Issues a token. Only the holder of `root` can do this.
    pub fn mint<C: Crypto + ?Sized>(
        crypto: &C,
        root: &RootKey,
        identifier: Identifier,
        caveats: Vec<Caveat>,
    ) -> Result<Self, DomainError> {
        if caveats.len() > MAX_CAVEATS {
            return Err(DomainError::TooManyCaveats);
        }
        let mut tag = crypto.mac(root.expose(), &identifier.canonical_bytes());
        for c in &caveats {
            tag = crypto.mac(&tag.0, &c.canonical_bytes());
        }
        Ok(Self {
            identifier,
            caveats,
            tag,
        })
    }

    /// Adds a restriction. Needs no secret: any holder can attenuate, nobody
    /// can remove a caveat (it would require inverting the MAC).
    pub fn attenuate<C: Crypto + ?Sized>(
        &self,
        crypto: &C,
        caveat: Caveat,
    ) -> Result<Self, DomainError> {
        if self.caveats.len() >= MAX_CAVEATS {
            return Err(DomainError::TooManyCaveats);
        }
        let tag = crypto.mac(&self.tag.0, &caveat.canonical_bytes());
        let mut caveats = self.caveats.clone();
        caveats.push(caveat);
        Ok(Self {
            identifier: self.identifier.clone(),
            caveats,
            tag,
        })
    }

    pub fn identifier(&self) -> &Identifier {
        &self.identifier
    }
    pub fn caveats(&self) -> &[Caveat] {
        &self.caveats
    }
    pub fn tag(&self) -> &Tag {
        &self.tag
    }

    /// Recomputes the chain with the root key; returns every intermediate tag
    /// (`tag_0 ..= tag_n`) if the final one matches in constant time.
    pub fn verify_chain<C: Crypto + ?Sized>(
        &self,
        crypto: &C,
        root: &RootKey,
    ) -> Result<Vec<Tag>, Denial> {
        let mut tags = Vec::with_capacity(self.caveats.len() + 1);
        let mut t = crypto.mac(root.expose(), &self.identifier.canonical_bytes());
        tags.push(t);
        for c in &self.caveats {
            t = crypto.mac(&t.0, &c.canonical_bytes());
            tags.push(t);
        }
        if crypto.tag_eq(&t, &self.tag) {
            Ok(tags)
        } else {
            Err(Denial::BadSignature)
        }
    }

    /// Fingerprints of the chain, root first. Revoking any of them revokes
    /// this token; revoking `[0]` revokes the whole family.
    pub fn chain_fingerprints<C: Crypto + ?Sized>(
        &self,
        crypto: &C,
        root: &RootKey,
    ) -> Result<Vec<Fingerprint>, Denial> {
        Ok(self
            .verify_chain(crypto, root)?
            .iter()
            .map(|t| crypto.fingerprint(t))
            .collect())
    }

    /// Full authorization: signature, revocation, then every caveat.
    pub fn authorize<C: Crypto + ?Sized>(
        &self,
        crypto: &C,
        root: &RootKey,
        req: &Request,
        is_revoked: &dyn Fn(&[Fingerprint]) -> bool,
    ) -> Result<Grant, Denial> {
        let fps = self.chain_fingerprints(crypto, root)?;
        if is_revoked(&fps) {
            return Err(Denial::Revoked);
        }
        if let Some(index) = first_unsatisfied(&self.caveats, req) {
            return Err(Denial::CaveatFailed { index });
        }
        let expires_at = self
            .caveats
            .iter()
            .filter_map(|c| match c {
                Caveat::ExpiresAt(t) => Some(*t),
                _ => None,
            })
            .min();
        Ok(Grant {
            subject: self.identifier.subject.clone(),
            key_id: self.identifier.key_id.clone(),
            nonce: self.identifier.nonce,
            expires_at,
            caveats: self.caveats.len(),
        })
    }
}
