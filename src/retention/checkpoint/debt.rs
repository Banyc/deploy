//! The sweep-debt orchestration (feature area A4): deferred retry and
//! post-commit maintenance.
//!
//! Both sweeps are POST-COMMIT MAINTENANCE, never corrections: a sweep
//! failure (or a sweep that has not run) never blocks or rolls back the
//! operation that triggered it and never reports an ordinary failure — it
//! records DURABLE DEBT and the NEXT PUSH (real or no-op) fires the pending
//! sweep. The pusher's sweep debt is `<base>/sweep-debt.json`, serviced by
//! [`crate::deploy::retry_pending_sweep`] (the engine loop lives in
//! `crate::deploy`, owned by another pass); the receiver's retention
//! debt is `targets/<target>/retention-debt.json`, serviced by
//! [`crate::deploy::retry_deferred_retentions`]. Both reports surface a
//! pending sweep as a WARNING, never an error.
//!
//! THE MARKER IS TYPED (TWO STATES — [`crate::store::local::debt::SweepDebt`]):
//! the durability gate is STRUCTURAL. A checkpoint whose ledger replace is
//! VISIBLE but whose durability is UNCONFIRMED records
//! [`SweepDebt::AwaitingCheckpointDurability`] — the sweep must NOT run (a
//! crash could restore an older, longer ledger that still references
//! below-floor history already deleted by the sweep). The marker transitions
//! to [`SweepDebt::Ready`] only via the durability-confirming rewrite
//! (`ReplacedDurable` — the same-suffix ledger rewrite + parent-directory
//! fsync confirmed), and the push-side sweep runner serves the sweep only
//! for a `Ready` marker.
//!
//! The marker I/O lives in [`crate::store::local::LocalStore`]
//! ([`LocalStore::read_sweep_debt`] / [`LocalStore::write_sweep_debt`]); the
//! decision orchestration — record `AwaitingCheckpointDurability` when the
//! floor is unconfirmed, record `Ready` when the floor is durable but the
//! sweep is outstanding, clear the stale marker when the sweep completed —
//! lives here.

use crate::identity::{DeploymentId, TargetName};
use crate::store::local::LocalStore;
use crate::store::local::debt::SweepDebt;

/// Persist (or clear) the durable sweep-debt marker after a checkpoint's
/// post-commit sweep: a COMPLETED sweep clears any stale marker (a
/// fully-serviced store leaves no trace — the next push has nothing to
/// retry); an INCOMPLETE OR FAILED sweep records [`SweepDebt::Ready`] — the
/// checkpoint's ledger replace confirmed BOTH commit points (the rename and
/// the parent-directory fsync), so the floor IS durable and the sweep may
/// run on a later push. The write/clear is itself non-fallible maintenance —
/// a failure is a warning on the report, never an `Err`. Returns the debt
/// warning (`None` when the marker was recorded or cleared cleanly).
pub(crate) fn reconcile_sweep_debt(
    store: &LocalStore,
    completed: bool,
    target: &TargetName,
    retained_from: &DeploymentId,
) -> Option<String> {
    if completed {
        match store.write_sweep_debt(None) {
            Ok(()) => None,
            Err(e) => Some(format!(
                "sweep debt maintenance deferred: failed to clear sweep debt: {e}"
            )),
        }
    } else {
        record_ready(store, target, retained_from)
    }
}

/// Record the durability-gated marker: the triggering checkpoint's ledger
/// replace is VISIBLE but its durability is UNCONFIRMED (the rename
/// happened, the parent-directory fsync failed) — the marker MUST be
/// [`SweepDebt::AwaitingCheckpointDurability`] so no maintenance/no-op push
/// runs the sweep until a durability-confirming rewrite ([`ReplacedDurable`])
/// transitions it to `Ready`. Non-fallible: a marker-write failure is a
/// warning on the report, never an `Err`.
pub(crate) fn record_awaiting_durability(
    store: &LocalStore,
    target: &TargetName,
    retained_from: &DeploymentId,
) -> Option<String> {
    record(
        store,
        SweepDebt::AwaitingCheckpointDurability {
            target: target.clone(),
            retained_from: retained_from.clone(),
        },
    )
}

/// The durable side of the transition: the checkpoint's ledger replace is
/// durably rewritten (`ReplacedDurable`) — record [`SweepDebt::Ready`] so
/// the push-side sweep runner may execute the owed sweep.
fn record_ready(
    store: &LocalStore,
    target: &TargetName,
    retained_from: &DeploymentId,
) -> Option<String> {
    record(
        store,
        SweepDebt::Ready {
            target: target.clone(),
            retained_from: retained_from.clone(),
        },
    )
}

fn record(store: &LocalStore, debt: SweepDebt) -> Option<String> {
    match store.write_sweep_debt(Some(&debt)) {
        Ok(()) => None,
        Err(e) => Some(format!(
            "sweep debt maintenance deferred: failed to write sweep debt: {e}"
        )),
    }
}
