//! Re-export shim: checkpoint persistence / history-floor moved to
//! [`crate::retention::history_floor`]. Keeps `crate::store::history_floor::*`
//! resolving as before (`LedgerDiscards` / `ReachableSet` were `pub`,
//! `LedgerOverride` was `pub(crate)` — the visibilities are preserved).

pub(crate) use crate::retention::history_floor::LedgerOverride;
pub use crate::retention::history_floor::{LedgerDiscards, ReachableSet};
