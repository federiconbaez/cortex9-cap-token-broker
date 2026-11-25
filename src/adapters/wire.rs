//! Wire format: `cx9t1.` + base64url(no padding) of
//!
//! ```text
//! version:u8=1 | key_id:str16 | nonce[16] | subject:str16 | n:u8 | caveat* | tag[32]
//! ```
//!
//! Caveats use their canonical encoding. Decoding re-validates every value
//! through the domain constructors and rejects trailing bytes, so a decoded
//! token is structurally identical to what was signed.

use crate::domain::caveat::Caveat;
use crate::domain::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use std::collections::BTreeSet;
use std::fmt;

pub const PREFIX: &str = "cx9t1.";
pub const MAX_ENCODED: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub &'static str);

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "token decode: {}", self.0)
    }
}
impl std::error::Error for DecodeError {}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

pub fn encode(t: &Token) -> String {
    let mut b = vec![1u8];
    let id = t.identifier();
    put_str(&mut b, id.key_id.as_str());
    b.extend_from_slice(&id.nonce.0);
    put_str(&mut b, id.subject.as_str());
    b.push(t.caveats().len() as u8);
    for c in t.caveats() {
        b.extend(c.canonical_bytes());
    }
    b.extend_from_slice(&t.tag().0);
    format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(b))
}

struct R<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.b.len() - self.p < n {
            return Err(DecodeError("truncated"));
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("8")))
    }
    fn str(&mut self) -> Result<&'a str, DecodeError> {
        let n = u16::from_be_bytes(self.take(2)?.try_into().expect("2")) as usize;
        std::str::from_utf8(self.take(n)?).map_err(|_| DecodeError("utf8"))
    }
}

fn v<T>(r: Result<T, DomainError>) -> Result<T, DecodeError> {
    r.map_err(|_| DecodeError("invalid value"))
}

fn caveat(r: &mut R<'_>) -> Result<Caveat, DecodeError> {
    Ok(match r.u8()? {
        1 => Caveat::ExpiresAt(r.u64()?),
        2 => Caveat::NotBefore(r.u64()?),
        3 => Caveat::Audience(v(Audience::parse(r.str()?))?),
        4 => Caveat::PathPrefix(v(ResourcePath::parse(r.str()?))?),
        5 => {
            let n = r.u8()? as usize;
            if n == 0 || n > MAX_ACTIONS {
                return Err(DecodeError("actions count"));
            }
            let mut set = BTreeSet::new();
            let mut prev: Option<Action> = None;
            for _ in 0..n {
                let a = v(Action::parse(r.str()?))?;
                // Canonical form is strictly sorted and unique.
                if prev.as_ref().is_some_and(|p| p >= &a) {
                    return Err(DecodeError("actions not canonical"));
                }
                prev = Some(a.clone());
                set.insert(a);
            }
            Caveat::Actions(set)
        }
        _ => return Err(DecodeError("unknown caveat")),
    })
}

pub fn decode(s: &str) -> Result<Token, DecodeError> {
    if s.len() > MAX_ENCODED {
        return Err(DecodeError("too long"));
    }
    let body = s.strip_prefix(PREFIX).ok_or(DecodeError("prefix"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| DecodeError("base64"))?;
    let mut r = R { b: &bytes, p: 0 };
    if r.u8()? != 1 {
        return Err(DecodeError("version"));
    }
    let key_id = v(KeyId::parse(r.str()?))?;
    let nonce = Nonce(r.take(NONCE_LEN)?.try_into().expect("16"));
    let subject = v(Subject::parse(r.str()?))?;
    let n = r.u8()? as usize;
    if n > MAX_CAVEATS {
        return Err(DecodeError("too many caveats"));
    }
    let mut caveats = Vec::with_capacity(n);
    for _ in 0..n {
        caveats.push(caveat(&mut r)?);
    }
    let tag = Tag(r.take(TAG_LEN)?.try_into().expect("32"));
    if r.p != bytes.len() {
        return Err(DecodeError("trailing bytes"));
    }
    v(Token::from_parts(
        Identifier {
            key_id,
            nonce,
            subject,
        },
        caveats,
        tag,
    ))
}
