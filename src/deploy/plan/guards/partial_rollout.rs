//! The partial-rollout guards: [`validate_partial_rollout`] refuses a
//! group push whose selected slots do not form a valid partial rollout.

use crate::config::ProjectConfig;
use crate::deploy::plan::SlotSelection;
use crate::deploy::plan::latest_successful_rollback;
use crate::error::Error;
use crate::error::Result;
use crate::identity::ServerId;
use crate::identity::SlotId;
use crate::ledger::PhysicalBinding;
use crate::store::local::LocalStore;
use std::collections::HashSet;

// PARTIAL-ROLLOUT GUARDS (A1): the first-deployment / membership-change
// rules a group push must satisfy before ANY remote mutation. The guard's
// base — the latest successful target snapshot — lives with the planner
// ([`crate::deploy::plan::latest_successful_rollback`]).

/// PARTIAL-ROLLOUT GUARDS, validated BEFORE any remote mutation: a group push
/// derives its complete snapshot by overlaying the selected slots onto the
/// latest successful target snapshot, so the base must be able to carry every
/// unselected slot forward.
///
/// * On a target's FIRST deployment (no base snapshot), a partial group push
///   is allowed only if the selected group covers every target slot.
/// * After target membership changes, a partial push is allowed only when
///   every current UNSELECTED slot has a prior assignment in the base AND its
///   physical binding still matches (a slot added to the target after the
///   base, or rebound/moved since, would otherwise be silently dropped from
///   the new snapshot).
///
/// A full-target push (no group) is always allowed: it establishes a new
/// complete snapshot from its own actuals.
///
/// `selected` is the PER-BRANCH resolved slot-ID set (the plan's assignments
/// — HEAD/deployment from the current topology, `release:<id>` from the
/// release's FROZEN group topology), NOT a resolution from the caller's
/// current configuration: a historical release's frozen group partition may
/// legitimately differ from the current one, and the guard must compare the
/// slots the push actually selects against the current membership.
pub(crate) fn validate_partial_rollout(
    selection: &SlotSelection,
    selected: &[SlotId],
    config: &ProjectConfig,
    store: &LocalStore,
) -> Result<()> {
    if selection.group.is_none() {
        return Ok(());
    }
    let current = config.target_slots(selection.target.as_str())?;
    let selected: HashSet<&str> = selected.iter().map(|s| s.as_str()).collect();
    let unselected: Vec<(&crate::config::SlotConfig, &crate::config::ServerDef)> = current
        .iter()
        .filter(|(s, _)| !selected.contains(s.id.as_str()))
        .copied()
        .collect();
    let base = latest_successful_rollback(store, selection.target.as_str())?;
    match base {
        None => {
            // First deployment: the group must cover every target slot.
            if !unselected.is_empty() {
                return Err(Error::preflight(format!(
                    "partial rollout of target '{}' with group '{}' on its first deployment is refused: \
                     the group must cover every target slot (unselected: {})",
                    selection.target,
                    selection.group.as_deref().unwrap_or(""),
                    unselected
                        .iter()
                        .map(|(s, _)| s.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        }
        Some(base) => {
            // Membership drift: every unselected slot must have a prior
            // assignment in the base and its physical binding must still
            // match.
            for (slot, sdef) in &unselected {
                let slot_id =
                    SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment");

                let current_binding = PhysicalBinding::new(
                    ServerId::parse(sdef.id.as_str())
                        .expect("validated server id is a safe segment"),
                    slot.deploy_dir(),
                )
                .expect("a config-validated deploy_dir is absolute and traversal-free");
                if base.get(&slot_id).is_none() {
                    return Err(Error::preflight(format!(
                        "partial rollout of target '{}' with group '{}' is refused: unselected slot \
                         '{}' has no prior assignment in the latest successful snapshot (it was \
                         added to the target after that deployment)",
                        selection.target,
                        selection.group.as_deref().unwrap_or(""),
                        slot_id
                    )));
                }
                let recorded = base.get(&slot_id).map(|e| e.binding()).ok_or_else(|| {
                    Error::preflight(format!(
                        "partial rollout of target '{}' with group '{}' is refused: unselected slot \
                         '{}' has no recorded physical binding in the latest successful snapshot",
                        selection.target,
                        selection.group.as_deref().unwrap_or(""),
                        slot_id
                    ))
                })?;
                if recorded != &current_binding {
                    return Err(Error::preflight(format!(
                        "partial rollout of target '{}' with group '{}' is refused: unselected slot \
                         '{}' was bound to server '{}' at '{}' in the latest successful snapshot, \
                         now bound to '{}' at '{}'; the new snapshot could not carry it forward",
                        selection.target,
                        selection.group.as_deref().unwrap_or(""),
                        slot_id,
                        recorded.server(),
                        recorded.deploy_dir(),
                        current_binding.server(),
                        current_binding.deploy_dir()
                    )));
                }
            }
        }
    }
    Ok(())
}
