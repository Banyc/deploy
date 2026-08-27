//! Re-export shim: the command verification adapter moved to
//! [`crate::verify::command`]. Keeps `crate::adapter::verify::*` resolving
//! as before.

pub use crate::verify::command::*;
