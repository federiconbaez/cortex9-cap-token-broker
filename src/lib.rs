//! # cortex9-cap-token-broker
//!
//! Attenuable capability tokens (chained HMAC, macaroon-style) with
//! hierarchical revocation. See `CONTRACT.md`.

#![forbid(unsafe_code)]

pub mod adapters;
pub mod application;
pub mod domain;
pub mod ports;
