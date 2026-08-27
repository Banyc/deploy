//! Deployment semantics (A1): the push transaction, its reference grammar,
//! and the per-slot rollout machinery.
//!
//! The area is nested RECURSIVELY: the three big feature modules became
//! group directories whose related sub-modules are grouped again at the next
//! level, down to single-concern leaves. The area-root re-export globs keep
//! every former submodule path compiling:
//!
//! * [`push`] — THE PUSH OPERATION, nested by phase: the spine
//!   (`push` / `push_inner`, the numbered steps, report assembly) in
//!   `push/mod.rs`, plus `execute`, `commit`, `noop`, `dryrun` and the
//!   multi-phase [`push::preflight`] group (`gate`, `locks`, `remotes`,
//!   `capacity`, `intent`).
//! * [`plan`] — PLANNING, nested by concern: the planner core in
//!   `plan/mod.rs`, plus `selection`, `groups`, the [`plan::preflight`]
//!   pair (`capacity`, `staging`) and the [`plan::guards`] gates
//!   (`partial_rollout`, `exact_rollback`, `coverage`).
//! * [`rollout`] — EXECUTION SEMANTICS, nested by concern: the batch loop in
//!   `rollout/mod.rs`, the [`rollout::attempt`] outcome derivation
//!   (`failure`, `results`, `status`) and the [`rollout::server`] per-server
//!   pipeline (`server`, `compensation`).
//! * [`refs`] — the push reference GRAMMAR (pure, store-free).
//! * [`maintenance`] — post-commit maintenance (step-17 retention loop,
//!   deferred-retention retry, pending-sweep retry, observed refresh).
//! * [`lock`] — the deployment lock.
//!
//! Every directory's `mod.rs` re-exports its sub-modules' items, so the
//! pre-nesting paths keep resolving (`crate::deploy::push::run_preflight`,
//! `crate::deploy::plan::capacity_fits`, `crate::deploy::rollout::process_server`, …).

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
