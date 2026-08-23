//! Shared test-only utilities.
//!
//! # The env-lock invariant
//!
//! ANY test that mutates the process-global environment must hold
//! [`ENV_LOCK`] for the entire duration of the mutation — `PATH`,
//! `XDG_CONFIG_HOME`, `DEPLOY_SSH_KNOWNHOSTS_DIR`,
//! `FAKE_SSH_ROOT` / `FAKE_SSH_REMOTE_PREFIX`, or anything else.
//!
//! All lib unit tests share one process, and edition-2024
//! `std::env::set_var` / `remove_var` are process-global (and `unsafe`), so
//! two env-mutating tests running concurrently corrupt each other's
//! environment: the fake-`ssh`/`ssh-keyscan` fingerprint suite and the
//! fake-`systemctl` suite both rewrite the same `PATH`, and a race could make
//! one of them spawn the REAL binaries (e.g. the real `ssh-keyscan`, whose
//! getaddrinfo DNS failure panics and poisons the lock). Every env-mutating
//! test must therefore serialize on THIS single lock — a private per-suite
//! lock does not protect against the other suite.
//!
//! Per-test state that lives OUTSIDE the process env (e.g. each test's own
//! `DEPLOY_SSH_KNOWNHOSTS_DIR` temp dir for the pin cache) stays isolated as
//! before; the lock only serializes the env itself.
//!
//! Note: each integration-test *binary* (`tests/*.rs`) is a separate process
//! and cannot race the lib tests, so it only needs its own lock to serialize
//! its own tests within that binary.

use std::sync::Mutex;

/// THE lock guarding every env-mutating test in the lib test binary. See the
/// module docs for the invariant.
pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Test-only one-shot fault injection for crash-mid-finalization tests.
///
/// Arm a fault keyed by the DEPLOYMENT ID of the attempt under test; the NEXT
/// matching store call fails exactly once (and disarms itself), while every
/// other call — including identical methods for different deployment IDs from
/// concurrently running tests — passes through untouched. Keying by deployment
/// ID keeps the in-crate engine tests deterministic under parallel `cargo test`
/// execution: no other test can consume a fault armed for a specific attempt.
///
/// Faults exist for the intent persist (`arm_append_attempt`), the outcomes
/// store (`arm_write_results`), the snapshot append, `refs/last-successful`,
/// and status-qualified transition appends (`arm_append_transition`,
/// `arm_append_transition_successful`, `arm_append_transition_pending`).
#[cfg(test)]
pub(crate) mod test_faults {
    use std::sync::Mutex;

    fn arm(fault: &Mutex<Option<String>>, deployment_id: &str) {
        *fault.lock().unwrap() = Some(deployment_id.to_string());
    }

    /// Arm the next `append_snapshot` call for `deployment_id` to fail once.
    pub(crate) fn arm_append_snapshot(deployment_id: &str) {
        arm(&FAIL_APPEND_SNAPSHOT, deployment_id);
    }

    /// Arm the next `write_last_successful` call for `deployment_id` to fail once.
    pub(crate) fn arm_write_last_successful(deployment_id: &str) {
        arm(&FAIL_WRITE_LAST_SUCCESSFUL, deployment_id);
    }

    /// Arm the next `append_transition` call for `deployment_id` to fail once.
    pub(crate) fn arm_append_transition(deployment_id: &str) {
        arm(&FAIL_APPEND_TRANSITION, deployment_id);
    }

    /// Arm the next `append_transition` call recording a `Successful` status
    /// for `deployment_id` to fail once. The replay-safe finalizer
    /// ([`crate::history::finalize_successful_attempt`]) writes the
    /// recoverable `PendingCommit` marker FIRST and the terminal `Successful`
    /// transition LAST, so faulting the terminal transition (rather than the
    /// earlier marker) requires qualifying on the recorded status: the
    /// `PendingCommit` marker append passes through untouched.
    pub(crate) fn arm_append_transition_successful(deployment_id: &str) {
        arm(&FAIL_APPEND_TRANSITION_SUCCESSFUL, deployment_id);
    }

    /// Arm the next `append_attempt` call for `deployment_id` to fail once.
    /// The attempt intent is persisted BEFORE any remote mutation, so a
    /// one-shot failure here leaves the remote untouched (no generation, no
    /// `current` change).
    pub(crate) fn arm_append_attempt(deployment_id: &str) {
        arm(&FAIL_APPEND_ATTEMPT, deployment_id);
    }

    /// Arm the next `write_results` call for `deployment_id` to fail once.
    /// The outcomes store (`deployments/<id>/results.json`) is then absent; a
    /// later recovery finalizes from the verified desired state instead.
    pub(crate) fn arm_write_results(deployment_id: &str) {
        arm(&FAIL_WRITE_RESULTS, deployment_id);
    }

    /// Arm the next `append_transition` call recording a `PendingCommit`
    /// status for `deployment_id` to fail once. Qualifies on the recorded
    /// status, mirroring [`arm_append_transition_successful`]: the earlier
    /// `InProgress` transition (and every non-pending transition) passes
    /// through untouched, and the one-shot fires ONLY at the recoverable
    /// `PendingCommit` marker — the first step of the shared finalizer
    /// ([`crate::history::finalize_successful_attempt`]) — leaving the
    /// attempt's latest transition `InProgress` with intent + outcomes
    /// durable.
    pub(crate) fn arm_append_transition_pending(deployment_id: &str) {
        arm(&FAIL_APPEND_TRANSITION_PENDING, deployment_id);
    }

    /// Consume the one-shot fault for `deployment_id` if armed. Returns `true`
    /// when the fault fired (and is now disarmed).
    pub(crate) fn consume(fault: &Mutex<Option<String>>, deployment_id: &str) -> bool {
        let mut guard = fault.lock().unwrap();
        if guard.as_deref() == Some(deployment_id) {
            *guard = None;
            true
        } else {
            false
        }
    }

    pub(crate) static FAIL_APPEND_SNAPSHOT: Mutex<Option<String>> = Mutex::new(None);
    pub(crate) static FAIL_WRITE_LAST_SUCCESSFUL: Mutex<Option<String>> = Mutex::new(None);
    pub(crate) static FAIL_APPEND_TRANSITION: Mutex<Option<String>> = Mutex::new(None);
    pub(crate) static FAIL_APPEND_TRANSITION_SUCCESSFUL: Mutex<Option<String>> = Mutex::new(None);
    pub(crate) static FAIL_APPEND_ATTEMPT: Mutex<Option<String>> = Mutex::new(None);
    pub(crate) static FAIL_WRITE_RESULTS: Mutex<Option<String>> = Mutex::new(None);
    pub(crate) static FAIL_APPEND_TRANSITION_PENDING: Mutex<Option<String>> = Mutex::new(None);
}
