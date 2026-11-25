use std::fmt;

/// Validation errors for value objects and token structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DomainError {
    Invalid(&'static str),
    TooManyCaveats,
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainError::Invalid(what) => write!(f, "invalid {what}"),
            DomainError::TooManyCaveats => write!(f, "too many caveats"),
        }
    }
}
impl std::error::Error for DomainError {}

/// Why access was denied. Callers exposing this to untrusted clients should
/// collapse it into a single "denied" to avoid acting as an oracle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Denial {
    UnknownKey,
    BadSignature,
    Revoked,
    /// Index of the first caveat (in chain order) that was not satisfied.
    CaveatFailed {
        index: usize,
    },
    MalformedRequest,
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Denial::UnknownKey => write!(f, "unknown key"),
            Denial::BadSignature => write!(f, "bad signature"),
            Denial::Revoked => write!(f, "revoked"),
            Denial::CaveatFailed { index } => write!(f, "caveat {index} not satisfied"),
            Denial::MalformedRequest => write!(f, "malformed request"),
        }
    }
}
impl std::error::Error for Denial {}
