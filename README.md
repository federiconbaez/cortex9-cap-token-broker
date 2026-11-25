# cortex9-cap-token-broker

Attenuable **capability tokens** in Rust: chained HMAC-SHA256 in the style of
macaroons, with mint / attenuate / verify / hierarchical revoke, key rotation
and a strict, fail-closed request model. Hexagonal: the domain knows nothing
about HMAC, SHA-256, base64, files or clocks.

> Ref: CX9-6199 · License: Apache-2.0 · Contract: [`CONTRACT.md`](CONTRACT.md)

## Why

A service gets a broad token, then narrows it (*read-only, only `/reports/2026`,
only for `storage`, for one hour*) before handing it to a job — **without
calling the issuer**. The issuer verifies offline and can revoke a single
delegated token without touching its parent.

```
tag_0 = HMAC(root_key[key_id], "cx9-cap-token/v1" ‖ key_id ‖ nonce ‖ subject)
tag_i = HMAC(tag_{i-1}, canonical(caveat_i))
```

Adding a caveat only needs the current tag; removing one would require
inverting HMAC. Caveats are a conjunction, so attenuation can only narrow.

## Features

- Caveats: `ExpiresAt`, `NotBefore`, `Audience`, `PathPrefix`
  (segment-aware: `/data` ≠ `/database`), `Actions` allow-list.
- Strict request paths: `.`/`..`, empty segments, `%`, `\`, `?`, `#`,
  non-ASCII and control characters are **rejected**, never normalized.
- Hierarchical revocation by fingerprint (SHA-256 of a chain tag): revoking a
  token kills its descendants, not its parent or siblings; `revoke_family`
  kills all. Entries carry the token's earliest expiry so they can be purged.
  The list stores fingerprints, never tags.
- Constant-time tag comparison (`subtle`), redacted `Debug` for tags and keys,
  32-byte minimum root keys, size limits on everything decoded.
- Key ring with rotation: retired keys keep verifying until removed.
- Wire format `cx9t1.<base64url>`; decoding revalidates every value and
  rejects non-canonical action sets and trailing bytes.
- Append-only file revocation store: torn tail ignored and repaired, any
  other corruption is an error (fail closed).

## Architecture

```
src/
├── domain/        # value objects, Caveat (Specification), Token algebra — pure
├── ports.rs       # Crypto, KeyStore, RevocationStore (Repositories), Clock
├── application/   # Broker use cases, TokenBuilder, AccessRequest DTO
└── adapters/      # HMAC-SHA256, wire codec, KeyRing, Memory/File revocations, clocks
```

| Pattern | Where |
|---------|-------|
| Specification | `Caveat: Specification`, composite `first_unsatisfied` |
| Builder | `TokenBuilder` (validates input, resolves `expires_in` with the clock) |
| Repository | `KeyStore`, `RevocationStore` |
| Strategy / Port | `Crypto` (tests swap in a fake to prove the domain is algorithm-agnostic) |

`scripts/check-architecture.sh` fails CI if `src/domain` imports crypto or
encoding crates, I/O, time or outer layers.

## Example

```
cargo run --example delegation
```

```rust
let token = broker.mint(TokenBuilder::new("reporting-svc").expires_in(3600).audience("storage").actions(&["read", "list"]))?;
let job = token.attenuate(&HmacSha256, Caveat::PathPrefix(ResourcePath::parse("/reports/2026")?))?;
broker.verify(&job, AccessRequest { audience: "storage", path: "/reports/2026/nov.csv", action: "read" })?; // Ok(Grant)
broker.revoke(&job)?; // job and its descendants denied; `token` still valid
```

## Verification

```
./scripts/check-architecture.sh
cargo fmt --check && cargo clippy --all-targets -- -D warnings
cargo test                                          # 22 tests (6 property suites)
PROPTEST_CASES=2000 cargo test --release --test properties
```

Properties checked: attenuation never amplifies; dropping any caveat is
detected; wire round-trip is lossless; decoding arbitrary bytes never panics;
single bit flips never verify; path coverage equals segment-prefix. Plus
RFC 4231 HMAC vector, revocation hierarchy, expiry-based purge, key rotation,
torn-tail recovery and secret redaction.

## Honest limits (out of scope)

- First-party caveats only: no third-party/discharge caveats, no public-key
  (Ed25519) verification — the verifier needs the root key.
- No stateful caveats (max uses, rate limits).
- Revocation is local to one store; no distributed propagation.
- Keys live in memory; no KMS/HSM adapter, no zeroization on drop.
- `Denial` is detailed for operators; collapse it to a single "denied" before
  returning it to untrusted clients.
- Not externally audited.
