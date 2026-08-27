//! The CAPACITY + STAGING preflight pair: [`capacity`] (preflight
//! headroom: [`capacity_preflight`], [`capacity_fits`]) and [`staging`]
//! (the disposable staging lifecycle: [`StagingCleanup`], the best-effort
//! cleanup helpers). Jointly the capacity + staging preflight of steps 8-9.

mod capacity;
mod staging;

pub(crate) use capacity::*;
pub(crate) use staging::*;
