use crate::domain::{Fingerprint, Nonce, Tag, NONCE_LEN};
use crate::ports::Crypto;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// HMAC-SHA256 chain, SHA-256 fingerprints, OS randomness for nonces.
#[derive(Clone, Copy, Debug, Default)]
pub struct HmacSha256;

impl Crypto for HmacSha256 {
    fn mac(&self, key: &[u8], msg: &[u8]) -> Tag {
        let mut m =
            <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
        m.update(msg);
        Tag(m.finalize().into_bytes().into())
    }

    fn tag_eq(&self, a: &Tag, b: &Tag) -> bool {
        a.0.ct_eq(&b.0).into()
    }

    fn fingerprint(&self, tag: &Tag) -> Fingerprint {
        let mut h = Sha256::new();
        h.update(b"cx9-cap-fingerprint/v1\0");
        h.update(tag.0);
        Fingerprint(h.finalize().into())
    }

    fn nonce(&self) -> Nonce {
        let mut b = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut b).expect("OS random source unavailable");
        Nonce(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 test case 2.
    #[test]
    fn rfc4231_case2() {
        let t = HmacSha256.mac(b"Jefe", b"what do ya want for nothing?");
        let hex: String = t.0.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn nonces_differ() {
        assert_ne!(HmacSha256.nonce(), HmacSha256.nonce());
    }
}
