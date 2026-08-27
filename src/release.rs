//! Re-export shim: release identity/verification semantics and the frozen
//! behavior-contract digest functions moved to [`crate::verify::release`]
//! (with the behavior-contract functions in [`crate::verify::behavior`]).
//! Keeps `crate::release::*` resolving as before.

pub use crate::verify::release::*;
