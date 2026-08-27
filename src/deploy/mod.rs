//! Deployment semantics (A1): the push transaction, its reference grammar,
//! and the per-slot rollout machinery.
//!
//! Module ownership (the encapsulation-run split of `push::engine` +
//! `push::plan` + `push::server` + `push::staging` + `push::capacity` +
//! `revset`):
//!
//! * [`push`] — the push ORCHESTRATION: `push`/`push_inner` (the numbered
//!   steps), the no-op up-to-date path, dry-run orchestration, the
//!   maintenance/step-17 wiring, the observed-refresh call, and the
//!   ref-resolution ordering — the spine of the old `push::engine`, kept
//!   together with the interdependent private helpers and the giant
//!   `#[cfg(test)] mod tests` (which drives `push_inner` directly).
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
//!   `plan_assignments`, the proof-bearing [`plan::ResolvedSelection`],
//!   partial-rollout guards, `VerifiedReleaseRebinding` usage, and
//!   `latest_successful_rollback`.
//! * [`server`] — the per-server mutation pipeline (the old `push::server`):
//!   `process_server` (publish/swap/activate/verify/commit per slot),
//!   `compensate_server`, the step hooks.
//! * [`staging`] — the disposable staging lifecycle (the old `push::staging`).
//! * [`dryrun`] — the dry-run plan computation/rendering from the push spine.
//! * [`capacity`] — capacity preflight (the old `push::capacity`).
//!
//! The old `push::engine` / `push::plan` / `push::server` / `push::staging` /
//! `push::capacity` and `revset` modules are re-export shims over this
//! module, so `crate::push::*` and `crate::revset::*` keep resolving as
//! before.

pub mod batching;
pub mod capacity;
pub mod dryrun;
pub mod failure;
pub mod groups;
pub mod plan;
pub mod push;
pub mod refs;
pub mod server;
pub mod staging;

// The re-export globs feed the `push::*` / `revset` shims' own globs
// (`pub use crate::deploy::*`), which the unused-imports lint cannot see;
// the modules' items are consumed through those shims, not by name here.
#[allow(unused_imports)]
pub(crate) use batching::*;
#[allow(unused_imports)]
pub(crate) use capacity::*;
#[allow(unused_imports)]
pub(crate) use dryrun::*;
#[allow(unused_imports)]
pub(crate) use failure::*;
pub use groups::*;
pub use plan::*;
pub use push::*;
#[allow(unused_imports)]
pub(crate) use refs::*;
#[allow(unused_imports)]
pub(crate) use server::*;
#[allow(unused_imports)]
pub(crate) use staging::*;
