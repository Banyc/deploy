//! Deployment semantics (A1): the push transaction, its reference grammar,
//! and the per-slot rollout machinery.
//!
//! Six cohesive feature modules (the ~25-module phase split was over-grained;
//! related features are grouped under one module where maintenance makes sense):
//!
//! * [`push`] — THE PUSH OPERATION: the push spine (`push` / `push_inner`, the
//!   numbered steps) plus the preflight phases, execute phases, commit phases,
//!   the up-to-date no-op path, and the dry-run mode (the former `preflight`,
//!   `execute`, `commit`, `noop`, `dryrun` modules).
//! * [`plan`] — PLANNING: `plan_assignments` plus every pre-mutation semantic:
//!   slot selection, the direct-release membership gate, capacity preflight,
//!   staging lifecycle, partial-rollout guards, exact-rollback verification,
//!   and the behavior-coverage gate (the former `selection`, `groups`,
//!   `capacity`, `staging`, `partial_rollout`, `exact_rollback`, `coverage`
//!   modules).
//! * [`rollout`] — EXECUTION SEMANTICS: the batch loop, failure policies,
//!   result/status/disposition shaping, compensation, and the per-server
//!   pipeline (the former `batching`, `failure`, `results`, `status`,
//!   `compensation`, `server` modules).
//! * [`refs`] — the push reference GRAMMAR (pure, store-free).
//! * [`maintenance`] — post-commit maintenance (step-17 retention loop,
//!   deferred-retention retry, pending-sweep retry, observed refresh).
//! * [`lock`] — the deployment lock.
//!
//! The area-root re-export globs keep every former submodule path compiling:
//! items that lived in the merged-away modules are nameable at the area root
//! (`crate::deploy::push::run_preflight`, `crate::deploy::plan::capacity_fits`,
//! `crate::deploy::rollout::process_server`, …).

pub mod lock;
pub mod maintenance;
pub mod plan;
pub mod push;
pub mod refs;
pub mod rollout;

// The shared test fixtures for the push spine and its phase modules
// (test-only; consumed by the phase modules' tests and by
// [`noop`]/[`maintenance`] tests).
#[cfg(test)]
pub(crate) mod testsupport;

// The area-root re-export globs make every submodule's items nameable at
// `crate::deploy::…`; the `pub(crate)` globs are kept for the items the
// engine consumes by the area-root path rather than by submodule path.
#[allow(unused_imports)]
pub(crate) use maintenance::*;
pub use plan::*;
pub use push::*;
#[allow(unused_imports)]
pub(crate) use refs::*;
#[allow(unused_imports)]
pub(crate) use rollout::*;
