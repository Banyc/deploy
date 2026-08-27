//! Re-export shim: capacity preflight moved to [`crate::deploy`]. Keeps
//! `crate::push::capacity::*` resolving as before.

pub use crate::deploy::*;
