//! Caveats are Specifications evaluated against a `Request`. A token grants
//! access only if **all** of its caveats are satisfied (conjunction), which
//! is what makes attenuation monotonic.

use super::values::*;
use std::collections::BTreeSet;

/// The request being authorized, in domain terms (already validated).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// Unix seconds, supplied by the application from the `Clock` port.
    pub now: u64,
    pub audience: Audience,
    pub path: ResourcePath,
    pub action: Action,
}

/// Specification pattern.
pub trait Specification {
    fn is_satisfied_by(&self, req: &Request) -> bool;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caveat {
    /// Valid while `now < t`.
    ExpiresAt(u64),
    /// Valid when `now >= t`.
    NotBefore(u64),
    Audience(Audience),
    PathPrefix(ResourcePath),
    /// Allow-list of actions.
    Actions(BTreeSet<Action>),
}

impl Specification for Caveat {
    fn is_satisfied_by(&self, r: &Request) -> bool {
        match self {
            Caveat::ExpiresAt(t) => r.now < *t,
            Caveat::NotBefore(t) => r.now >= *t,
            Caveat::Audience(a) => &r.audience == a,
            Caveat::PathPrefix(p) => p.covers(&r.path),
            Caveat::Actions(set) => set.contains(&r.action),
        }
    }
}

/// Composite specification: all caveats must hold. Returns the index of the
/// first failing caveat.
pub fn first_unsatisfied(caveats: &[Caveat], r: &Request) -> Option<usize> {
    caveats.iter().position(|c| !c.is_satisfied_by(r))
}

pub(crate) const T_EXPIRES: u8 = 1;
pub(crate) const T_NOT_BEFORE: u8 = 2;
pub(crate) const T_AUDIENCE: u8 = 3;
pub(crate) const T_PATH: u8 = 4;
pub(crate) const T_ACTIONS: u8 = 5;

pub(crate) fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

impl Caveat {
    /// Canonical, unambiguous encoding. This is what gets MAC'd, so it is a
    /// security boundary: every field is tagged and length-prefixed.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Caveat::ExpiresAt(t) => {
                out.push(T_EXPIRES);
                out.extend_from_slice(&t.to_be_bytes());
            }
            Caveat::NotBefore(t) => {
                out.push(T_NOT_BEFORE);
                out.extend_from_slice(&t.to_be_bytes());
            }
            Caveat::Audience(a) => {
                out.push(T_AUDIENCE);
                put_str(&mut out, a.as_str());
            }
            Caveat::PathPrefix(p) => {
                out.push(T_PATH);
                put_str(&mut out, &p.to_string());
            }
            Caveat::Actions(set) => {
                out.push(T_ACTIONS);
                out.push(set.len() as u8);
                for a in set {
                    put_str(&mut out, a.as_str());
                }
            }
        }
        out
    }

    /// Validating constructor for the action allow-list.
    pub fn actions<I: IntoIterator<Item = Action>>(
        it: I,
    ) -> Result<Self, super::error::DomainError> {
        let set: BTreeSet<Action> = it.into_iter().collect();
        if set.is_empty() || set.len() > MAX_ACTIONS {
            return Err(super::error::DomainError::Invalid("actions"));
        }
        Ok(Caveat::Actions(set))
    }
}
