//! Re-export shim: deployment planning moved to [`crate::deploy`]. Keeps
//! `crate::push::plan::*` resolving as before.

pub use crate::deploy::*;
