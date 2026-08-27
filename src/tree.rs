//! Re-export shim: canonical tree logic moved to
//! [`crate::remote::canonical`]. Keeps `crate::tree::*` resolving as before.

pub use crate::remote::canonical::*;
