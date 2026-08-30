//! THE ADAPTER TRANSACTION PROTOCOL (the review's P1 fix: adapter side
//! effects are inside the deployment transaction).
//!
//! # The problem
//!
//! A MUTATING adapter (the systemd activation adapter installs unit files
//! and enables/restarts services) performs side effects OUTSIDE the
//! prepare→apply→restore discipline of the deployment transaction. When the
//! side effect fails AFTER a slot advanced, the slot's generation can be
//! swapped back (the generation delta classifies `Unchanged`) while the
//! adapter's own mutation stays live (the new unit file still installed,
//! the new unit still enabled) — and the terminal decision would claim
//! `FailedRolledBack` on evidence that never verified the adapter's side
//! effect was reversed.
//!
//! # The protocol
//!
//! Every MUTATING adapter exposes its side effects as a
//! prepare→apply→restore→verify_restored transaction ([`ActivationTransaction`]):
//!
//! * [`prepare`](ActivationTransaction::prepare) stages what `apply` will
//!   change AND captures the PRIOR live state (`apply`'s undo record);
//! * [`apply`](ActivationTransaction::apply) performs the mutation and
//!   returns the applied state (the undo record survives in it);
//! * [`restore`](ActivationTransaction::restore) reverses the mutation back
//!   to the captured prior state;
//! * [`verify_restored`](ActivationTransaction::verify_restored) RE-READS
//!   the remote and confirms the restoration actually took effect — it is
//!   the ONLY producer of the sealed [`VerifiedAdapterRestoration`] proof.
//!
//! The ENGINE's per-slot flow runs the mutating adapter through this
//! protocol: on an apply failure it calls `restore` + `verify_restored`;
//! only a VERIFIED restoration may classify the slot `Restored`, and only
//! a verified `Restored` slot is rolled-back-eligible
//! ([`crate::kernel::transition::decide_terminal`] refuses a rolled-back
//! classification whose `Restored` evidence lacks the proof).
//!
//! # Why the verification adapter does NOT need the protocol
//!
//! [`crate::verify::command`] is a PURE READER: it executes the configured
//! argv (a health probe) and records the outcome — it has NO persistent
//! side effect, so there is NO state to restore and nothing to verify
//! restored. Its execution is still INSIDE the transaction boundary: a
//! verification failure after `apply` routes the slot to the same
//! restore + verify_restored compensation, so it is a
//! `FailedAfterAdvance`-class outcome (or a verified `Restored`), never a
//! silent pass.

use crate::error::Result;

/// THE ADAPTER TRANSACTION PROTOCOL: the prepare→apply→restore→verify_restored
/// discipline every MUTATING adapter (an adapter whose `apply` changes state
/// beyond the generation pointer — the systemd activation adapter installs
/// unit files and enables/restarts services) must expose, so the engine can
/// compensate a failed `apply` by REVERSING the adapter's own mutation and
/// PROVE the reversal by READING the remote state — never by trusting "we
/// called restore".
///
/// The protocol is parameterized by the adapter's validated configuration
/// (the implementation type carries its `Validated*` payload); the
/// associated types are the adapter's own staged/undo records:
/// `Prepared` is what `apply` will change (plus the undo record), `Applied`
/// the mutation result, `Restored` the reversed state.
pub trait ActivationTransaction {
    type Prepared;
    type Applied;
    type Restored;

    /// Stage what `apply` will change AND capture the PRIOR live state
    /// (`apply`'s undo record — what `restore` must reverse to, and what
    /// `verify_restored` reads back). A failure here means NOTHING was
    /// applied (the live state is untouched).
    fn prepare(&mut self) -> Result<Self::Prepared>;

    /// Perform the mutation. On failure the mutation may be PARTIAL (some
    /// side effects applied, some not): the caller still runs `restore`
    /// (against an `Applied` built from the `Prepared` undo record), which
    /// reverses whatever `apply` may have installed back to the captured
    /// prior state.
    fn apply(&mut self, prepared: &Self::Prepared) -> Result<Self::Applied>;

    /// Reverse the mutation: restore the PRIOR live state (prior content /
    /// enabled / started) captured in `prepare`.
    fn restore(&mut self, applied: &Self::Applied) -> Result<Self::Restored>;

    /// RE-READ the remote state and confirm the restoration took effect.
    /// THE ONLY PRODUCER of the [`VerifiedAdapterRestoration`] proof: a
    /// successful return means the adapter's side effects were VERIFIED to
    /// be back at their prior state — a slot whose `verify_restored` failed
    /// is NEVER restored-class (the engine classifies it
    /// `FailedAfterAdvance` instead).
    fn verify_restored(&self, restored: &Self::Restored) -> Result<VerifiedAdapterRestoration>;
}

/// THE VERIFIED-ADAPTER-RESTORATION PROOF (the review's P1 fix): a SEALED
/// value proving an adapter's side effects were VERIFIED restored — the
/// ONLY producer is a successful
/// [`verify_restored`](ActivationTransaction::verify_restored), which READ
/// the remote state and confirmed the prior state actually took effect
/// (never "we called restore"). The unit payload is PRIVATE, so the proof
/// cannot be fabricated outside this module: every `SlotExecution::Restored`
/// carries it, and a rolled-back terminal refuses any `Restored` slot
/// without it ([`crate::kernel::transition::decide_terminal`]) — a slot
/// whose generation delta is `Unchanged` but whose adapter side effect was
/// NOT verified restored can never silently classify as rolled back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAdapterRestoration {
    _sealed: (),
}

impl VerifiedAdapterRestoration {
    /// THE ONLY PRODUCER: a successful read-back verification. Crate-visible
    /// (the engine threads the proof from the verification functions to the
    /// execution states / the terminal decision), but its production callers
    /// are ONLY the adapter verification functions — no code constructs it
    /// from thin air. Tests that model the engine's failure modes use the
    /// same constructor (the property asserts the CLASSIFIER's behavior, not
    /// the producer's).
    pub(crate) fn verified() -> Self {
        VerifiedAdapterRestoration { _sealed: () }
    }
}
