//! THE STRICT-LINEAR LINEAGE VIOLATION (feature: strictly linear successful
//! ledger history) — the state machine's lineage refusal, named by the
//! spec: the successful history of a target is STRICTLY LINEAR, so there
//! are exactly two lineage refusals at INTENT-append time:
//!
//! * [`PendingAttemptExists`](LineageViolation::PendingAttemptExists) — an
//!   unresolved (terminal-less) intent already exists: at most ONE pending
//!   attempt may exist at any time, so a push that cannot finish the
//!   previous pending attempt is REFUSED (never plans a second intent on
//!   top, never merges two pending attempts even for disjoint groups);
//! * [`ParentMismatch`](LineageViolation::ParentMismatch) — the intent's
//!   parent is not the current successful head: every ordinary intent's
//!   parent must equal the successful head AT INTENT-APPEND TIME.
//!
//! [`LineageViolation`] is the DOMAIN refusal (the pure state machine's
//! decision). It is mapped onto the existing [`KernelError`] taxonomy at
//! each boundary: at the WRITE boundary (planning/append — the store's
//! pre-write intent validation, recovery, preflight) a refusal is a
//! [`Conflict`](KernelError::Conflict) — a valid operation against stale or
//! concurrently changed state; when READ from persisted bytes
//! ([`crate::kernel::transition::apply_event`] folding a ledger) it is
//! corruption → [`Integrity`](KernelError::Integrity).
//!
//! The inherited-slot congruence (an intent's inherited entries must match
//! the successful head it claims) is validated separately by
//! [`crate::kernel::transition::validate_inherited_slots`] — it refuses a
//! wire intent whose frozen `Inherit` entries disagree with the head's
//! snapshot, in the same taxonomies.

use std::fmt;

/// The STRICT-LINEAR lineage refusal: exactly the two intent-append
/// violations of the strictly-linear successful history model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineageViolation {
    /// An unresolved (terminal-less) intent already exists — at most ONE
    /// pending attempt may exist at any time.
    PendingAttemptExists,
    /// The intent's parent is not the target's current successful head —
    /// every ordinary intent's parent must equal the head at intent-append
    /// time.
    ParentMismatch,
}

impl fmt::Display for LineageViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LineageViolation::PendingAttemptExists => {
                write!(f, "pending attempt exists")
            }
            LineageViolation::ParentMismatch => write!(f, "parent mismatch"),
        }
    }
}
