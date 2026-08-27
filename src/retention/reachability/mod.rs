//! Reachability and the mark-and-sweep machinery: the two modules that
//! jointly own WHAT is retained and WHAT is reclaimed.
//!
//! * [`gc`] — the global artifact garbage collection (moved from
//!   `crate::store::gc`): reachability, the sweep stages, the
//!   PLANNED-vs-REMOVED counting, and the sweep-debt interactions.
//! * [`history_floor`] — the pusher-side ledger/history semantics (moved from
//!   `crate::store::history_floor`): `reachable_set`, the retained-suffix
//!   [`LedgerOverride`](history_floor::LedgerOverride), the
//!   Unknown-observation conservatism, and the post-commit sweep.

pub mod gc;
pub mod history_floor;
