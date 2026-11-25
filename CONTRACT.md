# CONTRACT — cortex9-cap-token-broker

Ref: CX9-6199

## Problem

Services need to hand out credentials that the **holder** can narrow before
delegating them (e.g. "read-only, only under `/reports/2026`, for the next
10 minutes, only for the `billing` service") without calling back to the
issuer, while the issuer can still verify them offline and revoke them.
This crate implements chained-HMAC capability tokens in the style of
macaroons: mint, attenuate, verify and revoke, with a hexagonal layout.

## Token model

```
tag_0 = MAC(root_key[key_id], canonical(identifier))
tag_i = MAC(tag_{i-1}, canonical(caveat_i))
token = (identifier, [caveat_1..caveat_n], tag_n)
```

`identifier = (key_id, nonce, subject)`. Caveats are first-party predicates
evaluated against a request: `ExpiresAt`, `NotBefore`, `Audience`,
`PathPrefix` (segment-aware), `Actions` (allow-list).

## Invariants (tested)

1. **Attenuation never amplifies**: for every token *T*, caveat *c* and
   request *r*: `verify(attenuate(T, c), r) = Ok ⇒ verify(T, r) = Ok`
   (property test over random caveats and requests).
2. **Caveats cannot be removed, reordered or edited** without the root key:
   any such change fails signature verification.
3. **Fail closed**: unknown key id, malformed token, unknown caveat tag,
   over-limit sizes, unparseable request path → deny.
4. **Path safety**: `PathPrefix("/data")` does not match `/database`;
   requests containing `.`/`..` segments, empty segments, backslashes,
   percent-encoding or control characters are rejected before matching.
5. **Revocation is hierarchical**: revoking a token revokes it and every
   token derived from it, but not its ancestors or siblings; revoking the
   family (nonce) revokes all of them. The revocation list stores only
   hashes of tags (fingerprints), never tags.
6. **Constant-time tag comparison** (behind the `Crypto` port).
7. **Key rotation**: tokens minted under a retired key still verify until the
   key is removed; new tokens always use the active key.

## Architecture

| Layer | Path | Rules |
|-------|------|-------|
| Domain | `src/domain/` | Tokens, caveats (Specification), chain signing/verification, revocation fingerprints. No crypto crates, no I/O, no clock. |
| Ports | `src/ports.rs` | `Crypto` (MAC, constant-time eq, fingerprint, random), `KeyStore`, `RevocationStore`, `Clock`. |
| Application | `src/application/` | `Broker` use cases; `TokenBuilder`; maps `AccessRequest` DTO → domain `Request`. |
| Adapters | `src/adapters/` | HMAC-SHA256 (`hmac`/`sha2`/`subtle`/`getrandom`), wire codec (`cx9t1.` + base64url), in-memory and append-only file revocation stores, in-memory key ring, system/manual clocks. |

`scripts/check-architecture.sh` fails CI if `src/domain` imports crypto
crates, I/O, time or outer layers.

## Acceptance criteria

- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` green in CI; gitleaks clean.
- Property tests for invariants 1–4 and wire decoding of arbitrary bytes
  never panics.

## Out of scope

- Third-party/discharge caveats, public-key (Ed25519) verification.
- Stateful caveats (max uses, rate limits).
- Distributed revocation propagation; KMS/HSM key storage.
- An HTTP server; the broker is a library (an example shows wiring).
