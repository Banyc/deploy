//! Deployment semantics (A1): the push transaction, its reference grammar,
//! and the per-slot rollout machinery.
//!
//! Module ownership (the encapsulation-run split of `push::engine` +
//! `push::plan` + `push::server` + `push::staging` + `push::capacity` +
//! `revset`):
//!
//! * [`push`] — the push ORCHESTRATION: `push`/`push_inner` (the numbered
//!   steps), the ref-resolution ordering, the preflight/batch/finalization
//!   calls, the maintenance wiring, the abandoned-incoming cleanup and the
//!   commit-diverged handling (A7) — the spine of the old `push::engine`,
//!   kept together with the interdependent private helpers and the giant
//!   `#[cfg(test)] mod tests` (which drives `push_inner` directly).
//! * [`noop`] — the "Everything up to date" no-op (A1): the up-to-date
//!   detection (complete [`ArtifactRef`] equality + per-slot verification
//!   rendering the EXISTING generation's identities) and the no-op path's
//!   hidden maintenance wiring (A7: deferred-retention retry, pending-sweep
//!   retry, observed refresh).
//! * [`maintenance`] — post-commit maintenance (A4): the step-17 per-slot
//!   retention loop + [`maintenance::retain_slot_post_commit`] +
//!   [`maintenance::retry_deferred_retentions`] +
//!   [`maintenance::retry_pending_sweep`] + the observed-refresh call (A7
//!   durable debt wiring; shared by the real-push path and the no-op path).
//! * [`coverage`] — the behavior-coverage gate (A5):
//!   [`coverage::validate_behavior_coverage`].
//! * [`refs`] — the push reference GRAMMAR (pure, store-free): the old
//!   `revset` module, `parse_ref_expr`, [`refs::RefExpr`], and the
//!   `@`/`@-`/`@--`/`parent(...)`/deployment-id/`release:<id>` forms.
//! * [`groups`] — rollout-group selection semantics: the {target, group}
//!   selection ([`groups::SlotSelection`]), frozen-vs-current topology
//!   selection (`current_members` / `release_members`), and the
//!   direct-release membership gate (`validate_direct_release_membership`).
//! * [`batching`] — the deployment-order batch loop (`batch_size`,
//!   `stop_on_failure`, the `'batches` iteration).
//! * [`failure`] — failure-policy semantics (`rollback_changed` /
//!   `leave_changed`), the step-13 batch compensation pass, the degraded
//!   derivation, and never-advanced outcome handling.
//! * [`plan`] — assignment planning (the old `push::plan`):
//!   `plan_assignments`, the proof-bearing [`plan::ResolvedSelection`], the
//!   `VerifiedReleaseRebinding` usage, and `latest_successful_rollback`.
//! * [`server`] — the per-server mutation pipeline (the old `push::server`):
//!   `process_server` (publish/swap/activate/verify/commit per slot), the
//!   step hooks.
//! * [`partial_rollout`] — the PARTIAL-ROLLOUT GUARDS (A1):
//!   [`partial_rollout::validate_partial_rollout`], the first-deployment /
//!   membership-change rules a group push must satisfy before any remote
//!   mutation.
//! * [`exact_rollback`] — the EXACT ROLLBACK verification (A2):
//!   [`exact_rollback::verify_exact_rollback_bindings`], the per-slot
//!   physical-binding checks (recorded binding missing / rebound / moved
//!   deploy_dir refuses) a deployment rollback runs before planning.
//! * [`compensation`] — per-slot COMPENSATION (A1 step 11):
//!   [`compensation::compensate_server`], the prior-generation restore /
//!   remove-`current`-on-first-deploy logic with its CAS precondition.
//! * [`staging`] — the disposable staging lifecycle (the old `push::staging`).
//! * [`dryrun`] — the dry-run plan computation/rendering from the push spine.
//! * [`capacity`] — capacity preflight (the old `push::capacity`).
//!
//! The old `push::engine` / `push::plan` / `push::server` / `push::staging` /
//! `push::capacity` and `revset` modules have been folded in here, and their
//! items are reachable either at the area root (the re-export globs below) or
//! through the submodule paths (`crate::deploy::plan::…`,
//! `crate::deploy::refs::…`, …).

pub mod batching;
pub mod capacity;
pub mod compensation;
pub mod coverage;
pub mod dryrun;
pub mod exact_rollback;
pub mod failure;
pub mod groups;
pub mod lock;
pub mod maintenance;
pub mod noop;
pub mod partial_rollout;
pub mod plan;
pub mod push;
pub mod refs;
pub mod server;
pub mod staging;

// The area-root re-export globs make every submodule's items nameable at
// `crate::deploy::…` (the old `push::engine::*` / `revset::*` call sites
// resolve here); the `pub(crate)` globs are kept for the items the engine
// consumes by the area-root path rather than by submodule path.
#[allow(unused_imports)]
pub(crate) use batching::*;
#[allow(unused_imports)]
pub(crate) use capacity::*;
#[allow(unused_imports)]
pub(crate) use compensation::*;
#[allow(unused_imports)]
pub(crate) use coverage::*;
#[allow(unused_imports)]
pub(crate) use dryrun::*;
#[allow(unused_imports)]
pub(crate) use exact_rollback::*;
#[allow(unused_imports)]
pub(crate) use failure::*;
pub use groups::*;
#[allow(unused_imports)]
pub(crate) use maintenance::*;
#[allow(unused_imports)]
pub(crate) use noop::*;
#[allow(unused_imports)]
pub(crate) use partial_rollout::*;
pub use plan::*;
pub use push::*;
#[allow(unused_imports)]
pub(crate) use refs::*;
#[allow(unused_imports)]
pub(crate) use server::*;
#[allow(unused_imports)]
pub(crate) use staging::*;
