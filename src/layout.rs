//! Re-export shim: canonical on-server layout paths moved to
//! [`crate::remote::layout`]. Keeps `crate::layout::*` resolving as before.

pub use crate::remote::layout::*;
