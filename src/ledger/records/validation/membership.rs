//! The SUCCESSFUL membership-equation enforcement (the terminal-local half)
//! — a RECORD-VALIDATION facet of
//! [`crate::ledger::records::validation`].
//!
//! A `Successful` terminal event PERSISTS both memberships so the record
//! PROVES the membership equations:
//!
//! * **outcomes == selected** — the outcomes are the selected slots'
//!   results ([`crate::ledger::records::SlotTable`] key set ==
//!   `selected_membership`);
//! * **rollback == full** — the rollback is the COMPLETE resulting target
//!   snapshot (rollback slot set == `full_membership`);
//! * **selected ⊆ full** — a group push's selected set is a subset of the
//!   full target (an unselected slot is carried forward from the base).
//!
//! The FULL-push EQUALITY (selected == full) and THE INTENT-BINDING legs
//! (the terminal's memberships must REPRODUCE the intent's frozen
//! `selected_membership` / `full_membership`) are the CROSS-RECORD legs,
//! enforced where the terminal merges into its ledger entry (the mode —
//! group vs full — lives in the intent's `group`), not here.
//!
//! The single verification helper is shared by the wire → domain conversion
//! ([`crate::ledger::records::LedgerTerminalWire::into_domain`]); the
//! successful writer ([`crate::ledger::finalize::finalize_successful_attempt`])
//! produces the proven shape by construction and pins the rollback-key
//! equality itself.

use crate::error::{Error, Result};
use crate::identity::{DeploymentId, SlotId};
use std::collections::BTreeSet;
/// Verify THE SUCCESSFUL MEMBERSHIP EQUATIONS for a `Successful` terminal
/// (the terminal-local half): the outcomes' key set must EXACTLY equal the
/// `selected_membership`, the rollback's slot set must EXACTLY equal the
/// `full_membership`, `selected_membership` must be a SUBSET of
/// `full_membership`, and a successful deployment always records NON-EMPTY
/// outcomes and both memberships (a successful deployment selected and
/// covered at least one slot). A violation → `Error::integrity` (fail
/// closed — a record that cannot prove its memberships is never read as if
/// it could).
pub(crate) fn verify_successful_membership_equations(
    deployment_id: &DeploymentId,
    outcome_keys: &BTreeSet<SlotId>,
    rollback_slot_keys: &BTreeSet<SlotId>,
    selected_membership: &BTreeSet<SlotId>,
    full_membership: &BTreeSet<SlotId>,
) -> Result<()> {
    if selected_membership.is_empty() || full_membership.is_empty() {
        return Err(Error::integrity(format!(
            "terminal {}: status Successful requires NON-EMPTY selected_membership and full_membership — a successful deployment records the slots it selected and the complete target membership it covered",
            deployment_id
        )));
    }
    if outcome_keys.is_empty() {
        return Err(Error::integrity(format!(
            "terminal {}: status Successful requires NON-EMPTY outcomes — a successful deployment records outcomes for the slots it selected",
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
    if rollback_slot_keys != full_membership {
        let missing: Vec<&SlotId> = full_membership.difference(rollback_slot_keys).collect();
        let extra: Vec<&SlotId> = rollback_slot_keys.difference(full_membership).collect();
        return Err(Error::integrity(format!(
            "terminal {}: status Successful requires the rollback's slots to EXACTLY equal the full_membership (rollback slots {rollback_slot_keys:?} vs full_membership {full_membership:?}; missing rollback coverage for {missing:?}, extra rollback slots for {extra:?} — the rollback IS the complete snapshot over the full membership)",
            deployment_id
        )));
    }
    if !selected_membership.is_subset(full_membership) {
        let outside: Vec<&SlotId> = selected_membership.difference(full_membership).collect();
        return Err(Error::integrity(format!(
            "terminal {}: status Successful requires selected_membership ⊆ full_membership (selected slots outside the full membership: {outside:?} — a push can only select slots the target covers)",
            deployment_id
        )));
    }
    Ok(())
}
