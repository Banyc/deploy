//! The SUCCESSFUL membership-equation enforcement (the terminal-local half)
//! — a RECORD-VALIDATION facet of
//! [`crate::ledger::records::validation`].
//!
//! A `Successful` terminal event PERSISTS selected membership so the record
//! PROVES the membership equations:
//!
//! * **outcomes == selected** — the outcomes are the selected slots'
//!   results (`SlotTable` key set == `selected_membership`);
//! * **selected ⊆ rollback** — the rollback is the COMPLETE resulting
//!   target snapshot, so its keys ⊇ the activated set.
//!
//! The FULL membership is derivable as `rollback.keys()` — no separate
//! persisted full_membership. The intent-binding legs (terminal reproducing
//! the intent's snapshot) are enforced at the ledger read.

use crate::error::{Error, Result};
use crate::identity::{DeploymentId, SlotId};
use std::collections::BTreeSet;
/// Verify THE SUCCESSFUL MEMBERSHIP EQUATIONS for a `Successful` terminal
/// (the terminal-local half): the outcomes' key set must EXACTLY equal the
/// `selected_membership`, `selected_membership` must be a SUBSET of
/// `rollback_slot_keys`, and a successful deployment always records NON-EMPTY
/// outcomes and selected membership.
pub(crate) fn verify_successful_membership_equations(
    deployment_id: &DeploymentId,
    outcome_keys: &BTreeSet<SlotId>,
    rollback_slot_keys: &BTreeSet<SlotId>,
    selected_membership: &BTreeSet<SlotId>,
) -> Result<()> {
    if selected_membership.is_empty() {
        return Err(Error::integrity(format!(
            "terminal {}: status Successful requires NON-EMPTY selected_membership — a successful deployment records the slots it selected",
            deployment_id
        )));
    }
    if outcome_keys.is_empty() {
        return Err(Error::integrity(format!(
            "terminal {}: status Successful requires NON-EMPTY outcomes — a successful deployment records outcomes for the slots it selected",
            deployment_id
        )));
    }
    if rollback_slot_keys.is_empty() {
        return Err(Error::integrity(format!(
            "terminal {}: status Successful requires NON-EMPTY rollback — a successful deployment covers at least one slot",
            deployment_id
        )));
    }
    if outcome_keys != selected_membership {
        let missing: Vec<&SlotId> = selected_membership.difference(outcome_keys).collect();
        let extra: Vec<&SlotId> = outcome_keys.difference(selected_membership).collect();
        return Err(Error::integrity(format!(
            "terminal {}: status Successful requires the outcomes to EXACTLY equal the selected_membership (outcomes {outcome_keys:?} vs selected_membership {selected_membership:?}; missing outcomes for {missing:?}, extra outcomes for {extra:?} — the outcomes ARE the selected slots' results)",
            deployment_id
        )));
    }
    if !selected_membership.is_subset(rollback_slot_keys) {
        let outside: Vec<&SlotId> = selected_membership.difference(rollback_slot_keys).collect();
        return Err(Error::integrity(format!(
            "terminal {}: status Successful requires selected_membership ⊆ rollback keys (selected slots outside the rollback: {outside:?} — the rollback is the complete snapshot)",
            deployment_id
        )));
    }
    Ok(())
}
