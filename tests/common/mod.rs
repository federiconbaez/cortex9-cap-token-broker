#![allow(dead_code)]
use cortex9_cap_token_broker::adapters::clock::ManualClock;
use cortex9_cap_token_broker::adapters::hmac_sha256::HmacSha256;
use cortex9_cap_token_broker::adapters::keyring::KeyRing;
use cortex9_cap_token_broker::adapters::revocation::MemoryRevocations;
use cortex9_cap_token_broker::application::Broker;
use cortex9_cap_token_broker::domain::*;

pub const T0: u64 = 1_800_000_000;

pub fn key(byte: u8) -> RootKey {
    RootKey::new(vec![byte; 32]).unwrap()
}

pub fn ring() -> KeyRing {
    let mut r = KeyRing::default();
    r.rotate(KeyId::parse("k1").unwrap(), key(7));
    r
}

pub type TestBroker<'c> = Broker<KeyRing, MemoryRevocations, HmacSha256, &'c ManualClock>;

pub fn broker(clock: &ManualClock) -> TestBroker<'_> {
    Broker::new(ring(), MemoryRevocations::default(), HmacSha256, clock)
}
