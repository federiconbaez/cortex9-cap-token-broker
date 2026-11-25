//! Pure domain: value objects, caveats (Specification), token algebra.
//! No crypto crates, no I/O, no clock — those arrive through `crate::ports`.

pub mod caveat;
pub mod error;
pub mod token;
pub mod values;

pub use caveat::{Caveat, Request, Specification};
pub use error::{Denial, DomainError};
pub use token::{Grant, Identifier, RootKey, Token};
pub use values::*;
