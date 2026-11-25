//! End-to-end: a broker mints a token for a service, the service narrows it
//! before handing it to a batch job, the job is checked, then revoked.
//!
//! The root key here is a fixed demo value; real deployments load keys from a
//! secret manager into a `KeyStore` adapter.

use cortex9_cap_token_broker::adapters::{
    clock::SystemClock, hmac_sha256::HmacSha256, keyring::KeyRing, revocation::MemoryRevocations,
    wire,
};
use cortex9_cap_token_broker::application::{AccessRequest, Broker, TokenBuilder};
use cortex9_cap_token_broker::domain::{Caveat, KeyId, ResourcePath, RootKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut ring = KeyRing::default();
    ring.rotate(
        KeyId::parse("demo-2026-11")?,
        RootKey::new(b"demo-only-root-key-not-a-secret!".to_vec())?,
    );
    let mut broker = Broker::new(ring, MemoryRevocations::default(), HmacSha256, SystemClock);

    let token = broker.mint(
        TokenBuilder::new("reporting-svc")
            .expires_in(3600)
            .audience("storage")
            .actions(&["read", "list"]),
    )?;
    println!("issued:    {}", wire::encode(&token));

    // Holder-side: narrow to one folder, no key needed.
    let job = token.attenuate(
        &HmacSha256,
        Caveat::PathPrefix(ResourcePath::parse("/reports/2026")?),
    )?;
    let job = wire::decode(&wire::encode(&job))?;

    let ok = broker.verify(
        &job,
        AccessRequest {
            audience: "storage",
            path: "/reports/2026/nov.csv",
            action: "read",
        },
    );
    let outside = broker.verify(
        &job,
        AccessRequest {
            audience: "storage",
            path: "/hr/salaries.csv",
            action: "read",
        },
    );
    println!("in scope:  {:?}", ok.map(|g| g.subject.to_string()));
    println!("outside:   {}", outside.unwrap_err());

    broker.revoke(&job)?;
    let after = broker.verify(
        &job,
        AccessRequest {
            audience: "storage",
            path: "/reports/2026/nov.csv",
            action: "read",
        },
    );
    println!("revoked:   {}", after.unwrap_err());
    println!(
        "parent ok: {}",
        broker
            .verify(
                &token,
                AccessRequest {
                    audience: "storage",
                    path: "/x",
                    action: "list"
                }
            )
            .is_ok()
    );
    Ok(())
}
