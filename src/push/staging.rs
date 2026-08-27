//! Re-export shim: the staging lifecycle moved to [`crate::deploy`]. Keeps
//! `crate::push::staging::*` resolving as before.

pub use crate::deploy::*;
