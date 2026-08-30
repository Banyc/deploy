//! Retention: the slot-owned mark-and-sweep policy and pass (feature area A4).
//!
//! Retention is evaluated per server. For each server, the retained content set
//! is the union of:
//! * the artifact referenced by the current generation
//! * the prior distinct successful artifact when `protect_previous` is true
//! * artifacts referenced by incomplete transactions
//! * artifacts or releases selected by durable pins
//! * the newest `keep_distinct_artifacts` distinct successful artifact bindings
//! * artifacts successfully activated less than `keep_days` ago
//! * that server's artifacts in the newest `protect_deployments` deployment window
//!
//! A slot has EXACTLY ONE retention policy, owned by the slot itself: the
//! policy of the slot's OWNING VARIANT (the variant file whose `[[slots]]`
//! entry declares the slot). Each slot belongs to EXACTLY ONE owning target
//! (its single `target` field) and stores its state once physically — one
//! observed record, one retention policy — and targets are only selection
//! views over that slot state. There is NO per-target policy and NO union
//! across targets: the caller resolves the slot's single policy from its
//! owning variant (`ProjectConfig::slot_retention`) and passes it here; every generation
//! record on the server is evaluated under that one policy, so changing a
//! slot's target membership never changes what is retained.
//!
//! Retention is a mark-and-sweep operation: a tree object is deleted only when no
//! retained binding or applicable pin references it.
//!
//! # Modules (recursively nested by relatedness)
//!
//! * [`policy`] — the slot-owned retention policy semantics ([`compute_retained`]):
//!   `per_server` (`keep_distinct_artifacts` / `keep_days` / `protect_previous`),
//!   `deployment` (`protect_deployments`), and the retained-set computation.
//!   The policy group also owns its selection concerns:
//!   * [`policy::pins`] — pin honoring, fail closed on BOTH sweep sides: the
//!     pusher-side GC anchor semantics (`LocalStore::honor_release_pin`) and the
//!     receiver-side retention pin expansion. The config/store pin types live in
//!     `crate::config::pins` and the store; the honoring logic lives here.
//!   * [`policy::rotate`] — receiver-side rotation semantics: the mark-and-sweep
//!     pass ([`crate::remote::helper::RemoteHelper::rotate`]) deletes every tree
//!     object NOT in the retained set; the rotation I/O lives in
//!     [`crate::remote::helper`].
//! * [`reachability`] — the reachability / mark-and-sweep machinery that
//!   computes WHAT survives and reclaims WHAT does not:
//!   * [`reachability::gc`] — the global artifact garbage collection (moved from
//!     `crate::store::gc`): reachability, the sweep stages, the
//!     PLANNED-vs-REMOVED counting, and the sweep-debt interactions.
//!   * [`reachability::history_floor`] — the pusher-side ledger/history
//!     semantics (moved from `crate::store::history_floor`): the ONE locked
//!     `ReachabilitySnapshot`, the retained-suffix
//!     `LedgerOverride`, the
//!     Unknown-observation conservatism, and the post-commit sweep.
//! * [`checkpoint`] — the checkpoint command (moved from `crate::push::checkpoint`):
//!   the retained suffix, the atomic replace, the post-commit sweep,
//!   preview/override parity, and the post-commit warnings. Its sweep-debt
//!   orchestration nests with it:
//!   * `checkpoint::debt` — when a sweep is incomplete the durable TYPED
//!     marker is recorded so the next push retries it; a completed sweep
//!     clears the marker. The marker
//!     ([`crate::store::local::debt::SweepDebt`],
//!     two states —
//!     [`crate::store::local::debt::SweepDebt::AwaitingCheckpointDurability`] when the
//!     checkpoint's ledger replace is visible but its durability is
//!     unconfirmed, [`crate::store::local::debt::SweepDebt::Ready`] when the floor IS durable) gates
//!     the sweep: the push-side runner refuses to sweep an awaiting marker
//!     until a durability-confirming rewrite transitions it. The marker I/O
//!     lives in [`crate::store::local::LocalStore`]
//!     (`LocalStore::read_sweep_debt` / `LocalStore::write_sweep_debt`); the
//!     orchestration lives here.
//! * `sweep_tests` (test-only) — the two-sided sweep contract tests (moved
//!   from `crate::sweep`): receiver retention +
//!   pusher checkpoint independence, no-leak, and maintenance-not-correction.

pub mod checkpoint;
pub mod policy;
pub mod reachability;

// Keep the pre-nesting flat paths resolving (`crate::retention::gc::X`,
// `crate::retention::history_floor::X`, `crate::retention::pins::X`,
// `crate::retention::rotate::X`) for the rest of the crate.
pub use policy::{pins, rotate};
pub use reachability::{gc, history_floor};

pub use policy::{compute_retained, retained_summary};

#[cfg(test)]
mod sweep_tests;
