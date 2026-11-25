mod common;

use common::*;
use cortex9_cap_token_broker::adapters::clock::ManualClock;
use cortex9_cap_token_broker::adapters::hmac_sha256::HmacSha256;
use cortex9_cap_token_broker::adapters::keyring::KeyRing;
use cortex9_cap_token_broker::adapters::revocation::{FileRevocations, MemoryRevocations};
use cortex9_cap_token_broker::adapters::wire;
use cortex9_cap_token_broker::application::{AccessRequest, Broker, BrokerError, TokenBuilder};
use cortex9_cap_token_broker::domain::*;
use cortex9_cap_token_broker::ports::RevocationStore;

fn req<'a>(aud: &'a str, path: &'a str, action: &'a str) -> AccessRequest<'a> {
    AccessRequest {
        audience: aud,
        path,
        action,
    }
}

fn denied(r: Result<Grant, BrokerError>) -> Denial {
    match r {
        Err(BrokerError::Denied(d)) => d,
        other => panic!("expected denial, got {other:?}"),
    }
}

#[test]
fn mint_and_verify_happy_path() {
    let clock = ManualClock::at(T0);
    let b = broker(&clock);
    let t = b
        .mint(
            TokenBuilder::new("alice")
                .expires_in(600)
                .audience("billing")
                .path_prefix("/reports")
                .actions(&["read", "write"]),
        )
        .unwrap();
    let g = b
        .verify(&t, req("billing", "/reports/2026/q1", "read"))
        .unwrap();
    assert_eq!(g.subject.as_str(), "alice");
    assert_eq!(g.expires_at, Some(T0 + 600));
    assert_eq!(g.caveats, 4);
}

#[test]
fn each_caveat_is_enforced() {
    let clock = ManualClock::at(T0);
    let b = broker(&clock);
    let t = b
        .mint(
            TokenBuilder::new("alice")
                .not_before(T0)
                .expires_at(T0 + 10)
                .audience("billing")
                .path_prefix("/data")
                .actions(&["read"]),
        )
        .unwrap();
    assert_eq!(
        denied(b.verify(&t, req("other", "/data", "read"))),
        Denial::CaveatFailed { index: 2 }
    );
    assert_eq!(
        denied(b.verify(&t, req("billing", "/database", "read"))),
        Denial::CaveatFailed { index: 3 }
    );
    assert_eq!(
        denied(b.verify(&t, req("billing", "/data/x", "write"))),
        Denial::CaveatFailed { index: 4 }
    );
    clock.set(T0 - 1);
    assert_eq!(
        denied(b.verify(&t, req("billing", "/data", "read"))),
        Denial::CaveatFailed { index: 0 }
    );
    clock.set(T0 + 10);
    assert_eq!(
        denied(b.verify(&t, req("billing", "/data", "read"))),
        Denial::CaveatFailed { index: 1 }
    );
    clock.set(T0 + 9);
    assert!(b.verify(&t, req("billing", "/data", "read")).is_ok());
}

#[test]
fn path_traversal_and_ambiguity_rejected() {
    let clock = ManualClock::at(T0);
    let b = broker(&clock);
    let t = b
        .mint(TokenBuilder::new("alice").path_prefix("/public"))
        .unwrap();
    for bad in [
        "/public/../secret",
        "/public/./x",
        "/public//x",
        "/public/%2e%2e/secret",
        "/public\\..\\secret",
        "public/x",
        "/public/x?y=1",
        "/public/\u{e9}",
        "",
    ] {
        assert_eq!(
            denied(b.verify(&t, req("svc", bad, "read"))),
            Denial::MalformedRequest,
            "{bad:?}"
        );
    }
    assert!(b.verify(&t, req("svc", "/public", "read")).is_ok());
    assert!(b.verify(&t, req("svc", "/public/a/b", "read")).is_ok());
    assert!(b.verify(&t, req("svc", "/publicity", "read")).is_err());
}

#[test]
fn holder_attenuation_narrows_and_survives_wire() {
    let clock = ManualClock::at(T0);
    let b = broker(&clock);
    let t = b
        .mint(TokenBuilder::new("svc-a").actions(&["read", "write"]))
        .unwrap();
    // The holder narrows to read-only before delegating; no key involved.
    let ro = t
        .attenuate(
            &HmacSha256,
            Caveat::actions([Action::parse("read").unwrap()]).unwrap(),
        )
        .unwrap();
    let ro = wire::decode(&wire::encode(&ro)).unwrap();
    assert!(b.verify(&ro, req("x", "/a", "read")).is_ok());
    assert_eq!(
        denied(b.verify(&ro, req("x", "/a", "write"))),
        Denial::CaveatFailed { index: 1 }
    );
    // Trying to "widen" by adding a broader allow-list does not help: conjunction.
    let widened = ro
        .attenuate(
            &HmacSha256,
            Caveat::actions([
                Action::parse("read").unwrap(),
                Action::parse("write").unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
    assert!(b.verify(&widened, req("x", "/a", "write")).is_err());
}

#[test]
fn removing_reordering_or_editing_caveats_breaks_signature() {
    let clock = ManualClock::at(T0);
    let b = broker(&clock);
    let t = b
        .mint(
            TokenBuilder::new("alice")
                .audience("a")
                .path_prefix("/p")
                .actions(&["read"]),
        )
        .unwrap();
    let cav = t.caveats().to_vec();
    let id = t.identifier().clone();
    let tag = *t.tag();
    let variants = vec![
        cav[..2].to_vec(),
        vec![cav[1].clone(), cav[0].clone(), cav[2].clone()],
        vec![
            cav[0].clone(),
            Caveat::PathPrefix(ResourcePath::parse("/").unwrap()),
            cav[2].clone(),
        ],
    ];
    for v in variants {
        let forged = Token::from_parts(id.clone(), v, tag).unwrap();
        assert_eq!(
            denied(b.verify(&forged, req("a", "/p", "read"))),
            Denial::BadSignature
        );
    }
    // Changing the subject also breaks it.
    let mut id2 = id.clone();
    id2.subject = Subject::parse("mallory").unwrap();
    let forged = Token::from_parts(id2, cav, tag).unwrap();
    assert_eq!(
        denied(b.verify(&forged, req("a", "/p", "read"))),
        Denial::BadSignature
    );
}

#[test]
fn hierarchical_revocation() {
    let clock = ManualClock::at(T0);
    let mut b = broker(&clock);
    let root = b.mint(TokenBuilder::new("alice")).unwrap();
    let child = b
        .attenuate(&root, Caveat::Audience(Audience::parse("a").unwrap()))
        .unwrap();
    let grandchild = b
        .attenuate(
            &child,
            Caveat::PathPrefix(ResourcePath::parse("/x").unwrap()),
        )
        .unwrap();
    let sibling = b
        .attenuate(&root, Caveat::Audience(Audience::parse("b").unwrap()))
        .unwrap();

    b.revoke(&child).unwrap();
    assert_eq!(
        denied(b.verify(&child, req("a", "/x", "read"))),
        Denial::Revoked
    );
    assert_eq!(
        denied(b.verify(&grandchild, req("a", "/x", "read"))),
        Denial::Revoked
    );
    assert!(
        b.verify(&root, req("a", "/x", "read")).is_ok(),
        "ancestor unaffected"
    );
    assert!(
        b.verify(&sibling, req("b", "/x", "read")).is_ok(),
        "sibling unaffected"
    );

    b.revoke_family(&sibling).unwrap();
    assert_eq!(
        denied(b.verify(&root, req("a", "/x", "read"))),
        Denial::Revoked
    );
    assert_eq!(
        denied(b.verify(&sibling, req("b", "/x", "read"))),
        Denial::Revoked
    );
}

#[test]
fn forged_tokens_cannot_be_revoked_or_pollute_the_list() {
    let clock = ManualClock::at(T0);
    let mut b = broker(&clock);
    let t = b.mint(TokenBuilder::new("alice")).unwrap();
    let forged = Token::from_parts(t.identifier().clone(), vec![], Tag([0; 32])).unwrap();
    assert!(b.revoke(&forged).is_err());
    assert!(b.revocations().is_empty());
}

#[test]
fn revocation_entries_expire_with_the_token() {
    let clock = ManualClock::at(T0);
    let mut b = broker(&clock);
    let t = b.mint(TokenBuilder::new("alice").expires_in(100)).unwrap();
    let forever = b.mint(TokenBuilder::new("bob")).unwrap();
    b.revoke(&t).unwrap();
    b.revoke(&forever).unwrap();
    clock.advance(99);
    assert_eq!(b.purge_revocations().unwrap(), 0);
    clock.advance(1);
    assert_eq!(b.purge_revocations().unwrap(), 1);
    assert_eq!(b.revocations().len(), 1);
    // The purged token is dead anyway because it expired.
    assert!(b.verify(&t, req("a", "/", "read")).is_err());
}

#[test]
fn key_rotation_and_retirement() {
    let clock = ManualClock::at(T0);
    let mut ring = ring();
    let old_tok = {
        let b = Broker::new(&ring, MemoryRevocations::default(), HmacSha256, &clock);
        b.mint(TokenBuilder::new("alice")).unwrap()
    };
    ring.rotate(KeyId::parse("k2").unwrap(), key(9));
    {
        let b = Broker::new(&ring, MemoryRevocations::default(), HmacSha256, &clock);
        let new_tok = b.mint(TokenBuilder::new("alice")).unwrap();
        assert_eq!(new_tok.identifier().key_id.as_str(), "k2");
        assert!(
            b.verify(&old_tok, req("a", "/", "read")).is_ok(),
            "retired-but-present key verifies"
        );
    }
    assert!(
        !ring.retire(&KeyId::parse("k2").unwrap()),
        "cannot retire the active key"
    );
    assert!(ring.retire(&KeyId::parse("k1").unwrap()));
    let b = Broker::new(&ring, MemoryRevocations::default(), HmacSha256, &clock);
    assert_eq!(
        denied(b.verify(&old_tok, req("a", "/", "read"))),
        Denial::UnknownKey
    );
}

#[test]
fn builder_reports_invalid_input_and_empty_ring_cannot_mint() {
    let clock = ManualClock::at(T0);
    let b = broker(&clock);
    assert!(matches!(
        b.mint(TokenBuilder::new("bad subject!")),
        Err(BrokerError::Invalid(_))
    ));
    assert!(matches!(
        b.mint(TokenBuilder::new("a").path_prefix("/x/../y")),
        Err(BrokerError::Invalid(_))
    ));
    assert!(matches!(
        b.mint(TokenBuilder::new("a").actions(&[])),
        Err(BrokerError::Invalid(_))
    ));
    assert!(matches!(
        b.mint(TokenBuilder::new("a").actions(&["READ"])),
        Err(BrokerError::Invalid(_))
    ));
    let empty = Broker::new(
        KeyRing::default(),
        MemoryRevocations::default(),
        HmacSha256,
        &clock,
    );
    assert!(matches!(
        empty.mint(TokenBuilder::new("a")),
        Err(BrokerError::NoActiveKey)
    ));
    assert!(
        RootKey::new(vec![1; 16]).is_err(),
        "short root keys are refused"
    );
}

#[test]
fn caveat_limit_enforced() {
    let clock = ManualClock::at(T0);
    let b = broker(&clock);
    let mut t = b.mint(TokenBuilder::new("a")).unwrap();
    for i in 0..MAX_CAVEATS {
        t = b.attenuate(&t, Caveat::NotBefore(i as u64)).unwrap();
    }
    assert!(matches!(
        b.attenuate(&t, Caveat::NotBefore(0)),
        Err(BrokerError::Invalid(DomainError::TooManyCaveats))
    ));
}

#[test]
fn debug_output_never_leaks_secrets() {
    let clock = ManualClock::at(T0);
    let b = broker(&clock);
    let t = b.mint(TokenBuilder::new("a")).unwrap();
    let dbg = format!("{t:?} {:?}", key(1));
    assert!(dbg.contains("<redacted>"));
    let tag_hex: String = t.tag().0.iter().map(|x| format!("{x:02x}")).collect();
    assert!(!dbg.contains(&tag_hex));
}

#[test]
fn file_revocations_persist_and_survive_torn_tail() {
    let dir = std::env::temp_dir().join(format!("cx9-cap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("revoked.log");
    let clock = ManualClock::at(T0);
    let t = {
        let mut b = Broker::new(
            ring(),
            FileRevocations::open(&path).unwrap(),
            HmacSha256,
            &clock,
        );
        let t = b.mint(TokenBuilder::new("alice").expires_in(50)).unwrap();
        b.revoke(&t).unwrap();
        t
    };
    // Torn write after the valid entry.
    use std::io::Write;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"R abcd")
        .unwrap();
    let mut store = FileRevocations::open(&path).unwrap();
    let b = Broker::new(
        ring(),
        FileRevocations::open(&path).unwrap(),
        HmacSha256,
        &clock,
    );
    assert_eq!(denied(b.verify(&t, req("a", "/", "read"))), Denial::Revoked);
    assert_eq!(store.purge_expired(T0 + 50).unwrap(), 1);
    assert!(!std::fs::read_to_string(&path).unwrap().contains("R abcd"));
    // A corrupted complete line fails closed.
    std::fs::write(&path, "R zz -\n").unwrap();
    assert!(FileRevocations::open(&path).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
