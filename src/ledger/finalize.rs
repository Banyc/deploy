//! REPLAY-SAFE, LOCK-VERIFIED FINALIZATION of a successful deployment,
//! reduced to EVIDENCE GATHERING (the semantic decision lives in the
//! kernel's [`crate::kernel::transition::decide_terminal`]).

use crate::error::{Error, Result};
use crate::identity::{GenerationRef, OperationId, PlacementSlotAssignment, SlotId};
// The re-exports keep the pre-kernel `crate::ledger::finalize::X` paths
// resolving for consumers: the wire intent/terminal shapes, the derived
// snapshot value, and the physical binding.
pub use crate::ledger::records::{
    CheckpointWire, DeploymentIntent, LedgerEntry, LedgerEventWire, LedgerIntentWire,
    LedgerTerminal, LedgerTerminalWire, PhysicalBinding, TargetSnapshot, TerminalDisposition,
};
use crate::remote::helper::{HeldSlotLock, RemoteHelper};
use crate::store::local::LocalStore;
use std::collections::{BTreeMap, HashMap};

/// The two/three physical append line kinds — the WIRE enum the
/// append-only JSONL stream carries: intent / terminal / checkpoint
/// ([`crate::ledger::records::LedgerEventWire`]). Re-exported under the
/// pre-kernel `LedgerLine` name so existing paths keep resolving.
pub type LedgerLine = LedgerEventWire;

/// Finalize a successful deployment: acquire every selected slot's
/// mutation lock, GATHER the verification evidence (each selected slot's
/// live generation + assignment artifact equal the intent's planned
/// result), write the commit markers, re-verify, and — only when the
/// intent's parent is still the target's successful head — append the
/// PAYLOAD-FREE `Successful` terminal (bound to the intent by its canonical
/// digest). The kernel decides the disposition; this function only gathers
/// evidence and orchestrates the guarded mutations.
pub fn finalize_successful_locked(
    store: &LocalStore,
    attempt: &DeploymentIntent,
    helpers: &HashMap<SlotId, RemoteHelper>,
    settings: &FinalizeSettings<'_>,
) -> Result<FinalizeOutcome> {
    let FinalizeSettings {
        reason,
        op_id,
        enforce_parent,
    } = settings;
    let entries = store.read_ledger(attempt.target().as_str())?;
    if let Some(e) = entries
        .iter()
        .find(|e| e.deployment_id == *attempt.deployment_id())
        && e.terminal.is_some()
    {
        return Ok(FinalizeOutcome::Finalized);
    }
    let mut selected: Vec<SlotId> = attempt.selected_membership().into_iter().collect();
    selected.sort();
    let mut guards: Vec<HeldSlotLock<'_>> = Vec::with_capacity(selected.len());
    for sid in &selected {
        let Some(helper) = helpers.get(sid) else {
            return Ok(FinalizeOutcome::Refused {
                reason: "state diverged",
                slot: sid.clone(),
            });
        };
        match helper.acquire_lock_guard(op_id) {
            Ok(guard) => guards.push(guard),
            Err(_) => return Ok(FinalizeOutcome::Pending),
        }
    }
    match verify_selected_locked(helpers, attempt)? {
        LockedObservation::Diverged(slot) => {
            return Ok(FinalizeOutcome::Refused {
                reason: "state diverged",
                slot,
            });
        }
        LockedObservation::Verified(_) => {}
    }
    let slot_ids: Vec<String> = selected.iter().map(|s| s.as_str().to_string()).collect();
    let snapshot = attempt.resulting_snapshot();
    for (idx, sid) in selected.iter().enumerate() {
        let guard = &guards[idx];
        let entry = snapshot.get(sid).expect("selected in snapshot");
        match guard.write_commit_marker(
            attempt.deployment_id().as_str(),
            entry.generation().as_str(),
            &slot_ids,
            Some(attempt.target().as_str()),
        ) {
            Err(Error::Integrity(_)) => {
                return Ok(FinalizeOutcome::Refused {
                    reason: "marker integrity conflict",
                    slot: sid.clone(),
                });
            }
            Err(_) => return Ok(FinalizeOutcome::Pending),
            Ok(_) => {}
        }
    }
    let observed = match verify_selected_locked(helpers, attempt)? {
        LockedObservation::Verified(o) => o,
        LockedObservation::Diverged(slot) => {
            return Ok(FinalizeOutcome::Refused {
                reason: "state diverged",
                slot,
            });
        }
    };
    let _ = observed;
    // THE ONE-PARENT RULE (before successful finalization): the intent's
    // parent must still be the target's successful head — a drifted head
    // means the plan was computed against a stale snapshot. Enforced for
    // NEW plans only: the MAIN success path gates its finalize here (a
    // concurrent success would make THIS plan a fork — refused, never
    // reconciled implicitly). RECOVERY
    // ([`crate::ledger::recovery::reconcile_pending_commits`]) sets
    // `enforce_parent: false`: a recovered attempt's plan was already
    // validated at plan time and durably recorded before mutation, and the
    // recovery contract (requirement.md step 15) completes it `Successful`
    // once the LIVE state still matches — independent of any head that
    // later landed.
    if *enforce_parent {
        let head = store
            .read_last_successful(attempt.target().as_str())
            .and_then(|h| crate::identity::DeploymentId::parse(&h).ok());
        if let Err(_e) = crate::kernel::terminal::assert_parent_is_head(attempt, head.as_ref()) {
            return Ok(FinalizeOutcome::Refused {
                reason: "stale plan",
                slot: selected
                    .first()
                    .cloned()
                    .unwrap_or_else(|| SlotId::new("no-slot".to_string())),
            });
        }
    }
    // THE KERNEL DECIDES: with the verification evidence gathered (every
    // selected slot verified at its planned result) the disposition is
    // `Successful` — payload-free; the result resolves from the intent.
    let disposition = crate::kernel::transition::decide_terminal(
        attempt,
        crate::kernel::transition::ExecutionReport {
            preflight_failed: false,
            verified: true,
            all_restored: true,
            outcomes: crate::ledger::records::SlotTable::new(),
        },
    )
    .map_err(|e| Error::integrity(format!("finalize {}: {e}", attempt.deployment_id())))?;
    let terminal = LedgerTerminal::new(
        crate::remote::helper::now_rfc3339_ts(),
        crate::kernel::terminal::intent_digest(attempt),
        disposition,
        Some(reason.to_string()),
    );
    store.append_terminal(
        attempt.target().as_str(),
        attempt.deployment_id(),
        &terminal,
    )?;
    Ok(FinalizeOutcome::Finalized)
}

pub struct FinalizeSettings<'a> {
    pub reason: &'a str,
    pub op_id: &'a OperationId,
    /// Whether the one-parent rule gates this finalization: `true` for the
    /// MAIN success path (a NEW plan must still be the head's child),
    /// `false` for RECOVERY of an already-recorded intent-only attempt
    /// (its plan was validated when it was durably recorded; recovery
    /// completes it on live-state verification).
    pub enforce_parent: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FinalizeOutcome {
    Finalized,
    Pending,
    Refused { reason: &'static str, slot: SlotId },
}
enum LockedObservation {
    Verified(BTreeMap<SlotId, GenerationRef>),
    Diverged(SlotId),
}
fn verify_selected_locked(
    helpers: &HashMap<SlotId, RemoteHelper>,
    attempt: &DeploymentIntent,
) -> Result<LockedObservation> {
    let mut observed: BTreeMap<SlotId, GenerationRef> = BTreeMap::new();
    let mut selected: Vec<SlotId> = attempt.selected_membership().into_iter().collect();
    selected.sort();
    let snapshot = attempt.resulting_snapshot();
    for sid in selected {
        let entry = snapshot.get(&sid).expect("selected in snapshot");
        let Some(helper) = helpers.get(&sid) else {
            return Ok(LockedObservation::Diverged(sid.clone()));
        };
        let st1 = helper.status()?;
        let Some(live_gen) = st1.current_generation else {
            return Ok(LockedObservation::Diverged(sid.clone()));
        };
        let asn = helper.read_assignment(live_gen.as_str())?;
        let st2 = helper.status()?;
        if st2.current_generation.as_ref() != Some(&live_gen)
            || live_gen != *entry.generation()
            || asn.artifact != *entry.artifact()
        {
            return Ok(LockedObservation::Diverged(sid.clone()));
        }
        observed.insert(
            sid.clone(),
            GenerationRef {
                generation: live_gen,
                assignment: PlacementSlotAssignment {
                    placement_slot: sid,
                    artifact: asn.artifact,
                },
            },
        );
    }
    Ok(LockedObservation::Verified(observed))
}
