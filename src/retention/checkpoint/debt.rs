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
//! The marker I/O lives in [`crate::store::local::LocalStore`]
//! ([`LocalStore::read_sweep_debt`] / [`LocalStore::write_sweep_debt`]); the
//! decision orchestration — write retry-required when the sweep did not
//! complete, clear the stale marker when it did — lives here in
//! [`reconcile_sweep_debt`].

use crate::store::local::LocalStore;

/// Reconcile the durable sweep-debt marker after a checkpoint's post-commit
/// sweep: an incomplete OR failed sweep records retry-required so the NEXT
/// PUSH recomputes reachability FRESH (no persisted deletion worklist) and
/// finishes it; a COMPLETED sweep clears any stale marker. The write/clear is
/// itself non-fallible maintenance — a failure is a warning on the report,
/// never an `Err`. Returns the debt warning (`None` when the marker was
/// recorded or cleared cleanly).
pub(crate) fn reconcile_sweep_debt(
    store: &LocalStore,
    completed: bool,
    warning: &Option<String>,
) -> Option<String> {
    if completed {
        match store.write_sweep_debt(None) {
            Ok(()) => None,
            Err(e) => Some(format!(
                "sweep debt maintenance deferred: failed to clear sweep debt: {e}"
            )),
        }
    } else {
        let reason = match warning {
            Some(failed) => failed.clone(),
            None => "checkpoint sweep did not complete; the next push retries it".to_string(),
        };
        match store.write_sweep_debt(Some(reason.as_str())) {
            Ok(()) => None,
            Err(e) => Some(format!(
                "sweep debt maintenance deferred: failed to write sweep debt: {e}"
            )),
        }
    }
}
