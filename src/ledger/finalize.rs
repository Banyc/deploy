//! REPLAY-SAFE, LOCK-VERIFIED FINALIZATION of a successful deployment,
//! reduced to EVIDENCE GATHERING (the semantic decision lives in the
//! kernel's [`crate::kernel::transition::decide_terminal`]).
//!
//! THE LINEAR GATES ARE ALWAYS ON — THERE IS NO `enforce_parent` FLAG: the
//! finalizer REQUIRES `intent.parent() == store.read_last_successful(target)`
//! at finalization time (an explicit pre-check, spec item 2) AND appends the
//! PAYLOAD-FREE `Successful` terminal through the store, whose pre-write
//! validation mirrors the kernel's [`crate::kernel::transition::apply_event`]
//! — THAT gate also requires `intent.parent == current successful head` at
//! append time, with NO bypass (recovery is a caller of the same transition,
//! not a second authority). The parent/head check and the append are ATOMIC
//! under the target lock, so at most ONE plan per parent can ever append
//! `Successful`; a finalizer that observes a drifted head is REFUSED
//! ([`FinalizeOutcome::Refused`], the reason carrying the kernel's
//! Conflict/StalePlan message) and its caller finalizes the stale plan
//! `Degraded` — never stranded, never successful.

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
/// result), write the commit markers, re-verify, and append the
/// PAYLOAD-FREE `Successful` terminal (bound to the intent by its
/// canonical digest) — subject to the STATE MACHINE's one-parent gate
/// (the intent's parent must still be the target's successful head at
/// append time; a drifted head is refused and the caller finalizes the
/// stale plan `Degraded`). The kernel decides the disposition; this
/// function only gathers evidence and orchestrates the guarded mutations.
pub fn finalize_successful_locked(
    store: &LocalStore,
    attempt: &DeploymentIntent,
    helpers: &HashMap<SlotId, RemoteHelper>,
    settings: &FinalizeSettings<'_>,
) -> Result<FinalizeOutcome> {
    let FinalizeSettings { reason, op_id } = settings;
    let entries = store.read_ledger(attempt.target().as_str())?;
    if let Some(e) = entries
        .iter()
        .find(|e| e.deployment_id == *attempt.deployment_id())
        && e.terminal.is_some()
    {
        return Ok(FinalizeOutcome::Finalized);
    }
    // THE STRICTLY-LINEAR HEAD CHECK (the spec's item 2 — the finalizer
    // ALWAYS requires `intent.parent() == store.read_last_successful(target)`,
    // no flag, no bypass): the attempt's parent must be the target's current
    // successful head, verified HERE against the same ledger read the append
    // gate uses — BEFORE any lock or marker mutation. A drifted head (a later
    // deployment already succeeded on this parent) makes the plan STALE and
    // the finalizer REFUSES ([`FinalizeOutcome::Refused`], the reason
    // carrying the kernel's Conflict/StalePlan message); the caller finalizes
    // the stale plan `Degraded` — never stranded, never `Successful`. The
    // ATOMIC store/kernel gate (the pre-write terminal validation in
    // [`crate::store::local::ledger`]) remains the ultimate authority; this
    // is the early, no-mutation check.
    let head = entries
        .iter()
        .rev()
        .find(|e| {
            e.terminal
                .as_ref()
                .is_some_and(|t| t.status() == crate::ledger::records::DeploymentStatus::Successful)
        })
        .map(|e| &e.deployment_id);
    if let Err(parent_error) = crate::kernel::terminal::assert_parent_is_head(attempt, head) {
        let slot = attempt
            .selected_membership()
            .into_iter()
            .next()
            .unwrap_or_else(|| SlotId::new("no-slot".to_string()));
        return Ok(FinalizeOutcome::Refused {
            reason: parent_error.message().to_string(),
            slot,
        });
    }
    let mut selected: Vec<SlotId> = attempt.selected_membership().into_iter().collect();
    selected.sort();
    let mut guards: Vec<HeldSlotLock<'_>> = Vec::with_capacity(selected.len());
    for sid in &selected {
        let Some(helper) = helpers.get(sid) else {
            return Ok(FinalizeOutcome::Refused {
                reason: "state diverged".to_string(),
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
                reason: "state diverged".to_string(),
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
                    reason: "marker integrity conflict".to_string(),
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
                reason: "state diverged".to_string(),
                slot,
            });
        }
    };
    let _ = observed;
    // THE KERNEL DECIDES: with the verification evidence gathered (every
    // selected slot verified at its planned result) the disposition is
    // `Successful` — payload-free; the result resolves from the intent.
    let disposition = crate::kernel::transition::decide_terminal(
        attempt,
        crate::kernel::transition::ExecutionReport::Verified,
    )
    .map_err(|e| Error::integrity(format!("finalize {}: {e}", attempt.deployment_id())))?;
    let terminal = LedgerTerminal::new(
        crate::remote::helper::now_rfc3339_ts(),
        crate::kernel::terminal::intent_digest(attempt),
        disposition,
        Some(reason.to_string()),
    );
    // THE STORE APPENDS THROUGH THE STATE MACHINE'S GATE: the pre-write
    // validation ([`crate::store::local::ledger`]'s mirror of
    // `apply_event`) refuses a `Successful` terminal whose intent's parent
    // is no longer the current successful head — a drifted head (a later
    // deployment already succeeded on this parent) makes THIS plan stale.
    // The Conflict (StalePlan) refusal is translated into
    // [`FinalizeOutcome::Refused`] with the kernel's conflict message as
    // the reason (the structured stale-plan source); the caller finalizes
    // the stale plan `Degraded`, never `Successful`, and the stale intent
    // never becomes the head — the newer head's snapshot is untouched.
    match store.append_terminal(
        attempt.target().as_str(),
        attempt.deployment_id(),
        &terminal,
    ) {
        Ok(()) => Ok(FinalizeOutcome::Finalized),
        Err(Error::Conflict(message)) => Ok(FinalizeOutcome::Refused {
            reason: message,
            slot: selected
                .first()
                .cloned()
                .unwrap_or_else(|| SlotId::new("no-slot".to_string())),
        }),
        Err(e) => Err(e),
    }
}

pub struct FinalizeSettings<'a> {
    pub reason: &'a str,
    pub op_id: &'a OperationId,
    // DELIBERATELY NO `enforce_parent` FLAG (spec item 1): the strictly-
    // linear head check (`intent.parent == current successful head`) is
    // ALWAYS required, in the explicit pre-check AND in the store's atomic
    // append gate — no caller can opt out.
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FinalizeOutcome {
    Finalized,
    Pending,
    Refused { reason: String, slot: SlotId },
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
