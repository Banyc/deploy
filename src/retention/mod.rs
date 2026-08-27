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
//! entry declares the slot). A slot may be a member of SEVERAL targets (the
//! multi-target feature) but its state is shared — one physical observed
//! record, one retention policy — and targets are only selection views over
//! that slot state. There is NO per-target policy and NO union across member
//! targets: the caller resolves the slot's single policy from its owning
//! variant (`ProjectConfig::slot_retention`) and passes it here; every generation
//! record on the server is evaluated under that one policy, so changing a
//! slot's target membership never changes what is retained.
//!
//! Retention is a mark-and-sweep operation: a tree object is deleted only when no
//! retained binding or applicable pin references it.
//!
//! # Modules
//!
//! * [`policy`] — the slot-owned retention policy semantics ([`compute_retained`]):
//!   `per_server` (`keep_distinct_artifacts` / `keep_days` / `protect_previous`),
//!   `deployment` (`protect_deployments`), and the retained-set computation.
//! * [`pins`] — pin honoring, fail closed on BOTH sweep sides: the pusher-side
//!   GC anchor semantics ([`LocalStore::honor_release_pin`]) and the
//!   receiver-side retention pin expansion. The config/store pin types live in
//!   [`crate::config::pins`] and the store; the honoring logic lives here.
//! * [`gc`] — the global artifact garbage collection (moved from
//!   `crate::store::gc`): reachability, the sweep stages, the
//!   PLANNED-vs-REMOVED counting, and the sweep-debt interactions.
//! * [`history_floor`] — the pusher-side ledger/history semantics (moved from
//!   `crate::store::history_floor`): `reachable_set`,
//!   the retained-suffix [`LedgerOverride`](history_floor::LedgerOverride), the
//!   Unknown-observation conservatism, and the post-commit sweep.
//! * [`checkpoint`] — the checkpoint command (moved from `crate::push::checkpoint`):
//!   the retained suffix, the atomic replace, the
//!   post-commit sweep, preview/override parity, and the post-commit warnings.
//! * [`debt`] — the sweep-debt orchestration: when a sweep is incomplete the
//!   durable marker is recorded so the next push retries it; a completed sweep
//!   clears the marker. The marker I/O lives in
//!   [`crate::store::local::LocalStore`] ([`LocalStore::read_sweep_debt`] /
//!   [`LocalStore::write_sweep_debt`]); the orchestration lives here.
//! * [`rotate`] — receiver-side rotation semantics: the mark-and-sweep pass
//!   ([`crate::remote::helper::RemoteHelper::rotate`]) deletes every tree
//!   object NOT in the retained set; the rotation I/O lives in
//!   [`crate::remote::helper`].
//! * [`sweep_tests`] (test-only) — the two-sided sweep contract tests (moved
//!   from `crate::sweep`): receiver retention +
//!   pusher checkpoint independence, no-leak, and maintenance-not-correction.

pub mod checkpoint;
pub mod gc;
pub mod history_floor;
pub mod pins;
pub mod policy;
pub mod rotate;

pub(crate) mod debt;

#[cfg(test)]
mod sweep_tests;

pub use policy::{compute_retained, retained_summary};
