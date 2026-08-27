//! Generation-state facets of the remote helper: the `current`-chain status
//! inspection and CAS swap, the write-once commit markers, and the immutable
//! generation assignment records.
//!
//! # Submodules
//!
//! * [`current`] — status/current-chain inspection and the swap/CAS operations.
//! * [`markers`] — write-once commit markers.
//! * [`assignment`] — the generation assignment record.

mod assignment;
pub mod current;
mod markers;

pub use assignment::GenerationAssignment;
