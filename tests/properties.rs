//! Property tests for the security invariants in CONTRACT.md.

mod common;

use common::*;
use cortex9_cap_token_broker::adapters::clock::ManualClock;
use cortex9_cap_token_broker::adapters::hmac_sha256::HmacSha256;
use cortex9_cap_token_broker::adapters::wire;
use cortex9_cap_token_broker::application::{AccessRequest, TokenBuilder};
use cortex9_cap_token_broker::domain::*;
use proptest::prelude::*;

const AUDS: [&str; 3] = ["billing", "search", "admin"];
const PATHS: [&str; 6] = ["/", "/data", "/data/x", "/data/x/y", "/database", "/other"];
const ACTS: [&str; 3] = ["read", "write", "delete"];

fn caveat() -> impl Strategy<Value = Caveat> {
    prop_oneof![
        (0u64..20).prop_map(|d| Caveat::ExpiresAt(T0 + d)),
        (0u64..20).prop_map(|d| Caveat::NotBefore(T0 + d)),
        (0usize..3).prop_map(|i| Caveat::Audience(Audience::parse(AUDS[i]).unwrap())),
        (0usize..6).prop_map(|i| Caveat::PathPrefix(ResourcePath::parse(PATHS[i]).unwrap())),
        prop::collection::btree_set(0usize..3, 1..=3).prop_map(|s| {
            Caveat::actions(s.into_iter().map(|i| Action::parse(ACTS[i]).unwrap())).unwrap()
        }),
    ]
}

fn request() -> impl Strategy<Value = (u64, usize, usize, usize)> {
    (0u64..25, 0usize..3, 0usize..6, 0usize..3)
}

proptest! {
    /// Invariant 1: attenuation never amplifies.
    #[test]
    fn attenuation_is_monotonic(
        base in prop::collection::vec(caveat(), 0..4),
        extra in prop::collection::vec(caveat(), 1..4),
        (dt, a, p, x) in request(),
    ) {
        let clock = ManualClock::at(T0);
        let b = broker(&clock);
        let mut t = b.mint(TokenBuilder::new("alice")).unwrap();
        for c in base { t = b.attenuate(&t, c).unwrap(); }
        let mut narrowed = t.clone();
        for c in extra { narrowed = b.attenuate(&narrowed, c).unwrap(); }
        clock.set(T0 + dt);
        let r = AccessRequest { audience: AUDS[a], path: PATHS[p], action: ACTS[x] };
        if b.verify(&narrowed, r.clone()).is_ok() {
            prop_assert!(b.verify(&t, r).is_ok());
        }
    }

    /// Invariant 2: dropping any caveat while keeping the tag is detected.
    #[test]
    fn dropping_a_caveat_is_detected(cavs in prop::collection::vec(caveat(), 1..6), k in 0usize..6) {
        let clock = ManualClock::at(T0);
        let b = broker(&clock);
        let mut t = b.mint(TokenBuilder::new("alice")).unwrap();
        for c in cavs { t = b.attenuate(&t, c).unwrap(); }
        let k = k % t.caveats().len();
        let mut cs = t.caveats().to_vec();
        cs.remove(k);
        let forged = Token::from_parts(t.identifier().clone(), cs, *t.tag()).unwrap();
        let r = AccessRequest { audience: "billing", path: "/data", action: "read" };
        prop_assert!(matches!(b.verify(&forged, r), Err(e) if e.is_denial()));
    }

    /// Wire roundtrip is lossless for every valid token.
    #[test]
    fn wire_roundtrip(cavs in prop::collection::vec(caveat(), 0..8)) {
        let clock = ManualClock::at(T0);
        let b = broker(&clock);
        let mut t = b.mint(TokenBuilder::new("svc-1")).unwrap();
        for c in cavs { t = t.attenuate(&HmacSha256, c).unwrap(); }
        prop_assert_eq!(wire::decode(&wire::encode(&t)).unwrap(), t);
    }

    /// Invariant 3: decoding arbitrary input never panics.
    #[test]
    fn decode_arbitrary_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        use base64::Engine;
        let s = format!("{}{}", wire::PREFIX, base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes));
        let _ = wire::decode(&s);
        let _ = wire::decode(&String::from_utf8_lossy(&bytes));
    }

    /// Flipping any bit of an encoded token never yields a valid grant for a
    /// different token.
    #[test]
    fn bit_flips_never_verify(bit in 0usize..2000) {
        use base64::Engine;
        let clock = ManualClock::at(T0);
        let b = broker(&clock);
        let t = b.mint(TokenBuilder::new("alice").audience("billing")).unwrap();
        let enc = wire::encode(&t);
        let mut raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&enc[wire::PREFIX.len()..]).unwrap();
        let bit = bit % (raw.len() * 8);
        raw[bit / 8] ^= 1 << (bit % 8);
        let s = format!("{}{}", wire::PREFIX, base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw));
        if let Ok(f) = wire::decode(&s) {
            let r = AccessRequest { audience: "billing", path: "/", action: "read" };
            prop_assert!(b.verify(&f, r).is_err());
        }
    }

    /// Invariant 4: prefix coverage is segment-wise and requires equal segments.
    #[test]
    fn path_cover_is_segment_prefix(a in prop::collection::vec("[a-z]{1,3}", 0..4), b in prop::collection::vec("[a-z]{1,3}", 0..4)) {
        let pa = ResourcePath::parse(&format!("/{}", a.join("/"))).unwrap();
        let pb = ResourcePath::parse(&format!("/{}", b.join("/"))).unwrap();
        prop_assert_eq!(pa.covers(&pb), b.len() >= a.len() && b[..a.len()] == a[..]);
    }
}
