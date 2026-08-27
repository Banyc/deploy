//! Re-export shim: mapping materialization moved to
//! [`crate::remote::materialize`]. Keeps `crate::mapper::*` resolving as
//! before.

pub use crate::remote::materialize::*;
