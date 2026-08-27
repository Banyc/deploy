//! Re-export shim: artifact garbage collection moved to [`crate::retention::gc`].
//! Keeps `crate::store::gc::*` resolving as before (`GcOutcome` was `pub`,
//! `SweepStageStats` was `pub(crate)` — the visibilities are preserved).

pub use crate::retention::gc::GcOutcome;
pub(crate) use crate::retention::gc::SweepStageStats;
