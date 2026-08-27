//! Re-export shim: template rendering moved to
//! [`crate::remote::materialize`]. Keeps `crate::template::*` resolving as
//! before.

pub use crate::remote::materialize::*;
