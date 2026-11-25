//! Validated value objects. Constructors enforce limits so the rest of the
//! domain can assume well-formed data.

use super::error::DomainError;
use std::fmt;

pub const MAX_CAVEATS: usize = 32;
pub const MAX_TEXT: usize = 128;
pub const MAX_PATH: usize = 512;
pub const MAX_ACTIONS: usize = 16;
pub const TAG_LEN: usize = 32;
pub const NONCE_LEN: usize = 16;

fn check_text(s: &str, what: &'static str) -> Result<(), DomainError> {
    if s.is_empty() || s.len() > MAX_TEXT {
        return Err(DomainError::Invalid(what));
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'@'))
    {
        return Err(DomainError::Invalid(what));
    }
    Ok(())
}

macro_rules! text_value {
    ($name:ident, $what:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn parse(s: &str) -> Result<Self, DomainError> {
                check_text(s, $what)?;
                Ok(Self(s.to_owned()))
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

text_value!(KeyId, "key id");
text_value!(Subject, "subject");
text_value!(Audience, "audience");

/// Action names are lowercase ASCII identifiers (`read`, `write`, `admin:keys`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Action(String);

impl Action {
    pub fn parse(s: &str) -> Result<Self, DomainError> {
        if s.is_empty()
            || s.len() > 32
            || !s.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b':')
            })
        {
            return Err(DomainError::Invalid("action"));
        }
        Ok(Self(s.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Absolute, normalized resource path stored as segments.
///
/// Parsing is deliberately strict: anything that could be interpreted two
/// ways by different layers (dot segments, empty segments, `%`-encoding,
/// backslashes, control or non-ASCII characters) is rejected instead of
/// being normalized.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourcePath(Vec<String>);

impl ResourcePath {
    pub fn parse(s: &str) -> Result<Self, DomainError> {
        if s.len() > MAX_PATH || !s.starts_with('/') {
            return Err(DomainError::Invalid("path"));
        }
        if s == "/" {
            return Ok(Self(Vec::new()));
        }
        let mut segs = Vec::new();
        for seg in s[1..].split('/') {
            let ok = !seg.is_empty()
                && seg != "."
                && seg != ".."
                && seg.bytes().all(|b| {
                    b.is_ascii_graphic() && b != b'%' && b != b'\\' && b != b'?' && b != b'#'
                });
            if !ok {
                return Err(DomainError::Invalid("path"));
            }
            segs.push(seg.to_owned());
        }
        Ok(Self(segs))
    }

    pub fn segments(&self) -> &[String] {
        &self.0
    }

    /// Segment-wise prefix: `/data` covers `/data` and `/data/x`, not `/database`.
    pub fn covers(&self, other: &ResourcePath) -> bool {
        other.0.starts_with(&self.0)
    }
}

impl fmt::Display for ResourcePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("/");
        }
        for s in &self.0 {
            write!(f, "/{s}")?;
        }
        Ok(())
    }
}

/// Chained MAC output.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag(pub [u8; TAG_LEN]);

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print tag material: it is a bearer secret.
        f.write_str("Tag(<redacted>)")
    }
}

/// One-way hash of a `Tag`; safe to store in revocation lists and logs.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint(pub [u8; 32]);

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.to_hex())
    }
}

impl Fingerprint {
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn from_hex(s: &str) -> Result<Self, DomainError> {
        if s.len() != 64 {
            return Err(DomainError::Invalid("fingerprint"));
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hex =
                std::str::from_utf8(chunk).map_err(|_| DomainError::Invalid("fingerprint"))?;
            out[i] =
                u8::from_str_radix(hex, 16).map_err(|_| DomainError::Invalid("fingerprint"))?;
        }
        Ok(Self(out))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Nonce(pub [u8; NONCE_LEN]);
