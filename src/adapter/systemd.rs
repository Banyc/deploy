//! Re-export shim: the systemd activation adapter moved to
//! [`crate::verify::systemd`]. Keeps `crate::adapter::systemd::*` resolving
//! as before.

pub use crate::verify::systemd::*;
