//! The domain depends only on the `Crypto` port: it works with any
//! implementation. This deliberately weak fake proves the wiring, not security.

use cortex9_cap_token_broker::domain::caveat::Request;
use cortex9_cap_token_broker::domain::*;
use cortex9_cap_token_broker::ports::Crypto;

struct FakeCrypto;

impl Crypto for FakeCrypto {
    fn mac(&self, key: &[u8], msg: &[u8]) -> Tag {
        // FNV-style mixing spread over 32 bytes. NOT secure; test double only.
        let mut out = [0u8; 32];
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for (i, b) in key.iter().chain(msg.iter()).enumerate() {
            h = (h ^ *b as u64).wrapping_mul(0x100_0000_01b3);
            out[i % 32] ^= (h >> 24) as u8;
        }
        Tag(out)
    }
    fn tag_eq(&self, a: &Tag, b: &Tag) -> bool {
        a == b
    }
    fn fingerprint(&self, t: &Tag) -> Fingerprint {
        Fingerprint(self.mac(b"fp", &t.0).0)
    }
    fn nonce(&self) -> Nonce {
        Nonce([4; 16])
    }
}

#[test]
fn domain_is_crypto_agnostic() {
    let root = RootKey::new(vec![1; 32]).unwrap();
    let id = Identifier {
        key_id: KeyId::parse("k").unwrap(),
        nonce: FakeCrypto.nonce(),
        subject: Subject::parse("s").unwrap(),
    };
    let t = Token::mint(&FakeCrypto, &root, id, vec![Caveat::ExpiresAt(10)]).unwrap();
    let t2 = t
        .attenuate(&FakeCrypto, Caveat::Audience(Audience::parse("a").unwrap()))
        .unwrap();
    let r = Request {
        now: 5,
        audience: Audience::parse("a").unwrap(),
        path: ResourcePath::parse("/").unwrap(),
        action: Action::parse("read").unwrap(),
    };
    assert!(t2.authorize(&FakeCrypto, &root, &r, &|_| false).is_ok());
    assert_eq!(
        t2.authorize(&FakeCrypto, &root, &r, &|_| true),
        Err(Denial::Revoked)
    );
    let other = RootKey::new(vec![2; 32]).unwrap();
    assert_eq!(
        t2.authorize(&FakeCrypto, &other, &r, &|_| false),
        Err(Denial::BadSignature)
    );
    assert_eq!(t2.chain_fingerprints(&FakeCrypto, &root).unwrap().len(), 3);
}
