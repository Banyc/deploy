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
use crate::kernel::error::{ConflictError, KernelError};
// The re-exports keep the pre-kernel `crate::ledger::finalize::X` paths
// resolving for consumers: the wire intent/terminal shapes, the derived
// snapshot value, and the physical binding.
pub use crate::ledger::records::{
    CheckpointWire, DeploymentIntent, LedgerEntry, LedgerEventWire, LedgerIntentWire,
    LedgerTerminal, LedgerTerminalWire, PhysicalBinding, TargetSnapshot, TerminalDisposition,
};
use crate::remote::helper::{HeldSlotLock, RemoteHelper};
use crate::store::local::ledger::TargetLedgerTxn;
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
///
/// THE TXN IS THE WRITE SURFACE: the caller holds the target's
/// [`TargetLedgerTxn`] (the target `operation.lock` + the folded ledger
/// state) for the WHOLE finalization — the parent/head check and the
/// terminal append are atomic under the txn's lock, and the `Successful`
/// terminal is constructed with the SEALED [`VerifiedExecution`] proof
/// minted EXACTLY at the verified-execution evidence point below
/// ([`crate::kernel::terminal::VerifiedExecution::from_verified_report`]).
pub(crate) fn finalize_successful_locked(
    txn: &mut TargetLedgerTxn<'_>,
    attempt: &DeploymentIntent,
    helpers: &HashMap<SlotId, RemoteHelper>,
    settings: &FinalizeSettings<'_>,
) -> Result<FinalizeOutcome> {
    let FinalizeSettings {
        reason,
        op_id,
        application,
    } = settings;
    let entries = txn.state().entries();
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
    // successful head, verified HERE against the TXN'S OWN FOLDED STATE (the
    // same fold the append gate uses — a single source, no re-read) —
    // BEFORE any lock or marker mutation. A drifted head (a later
    // deployment already succeeded on this parent) makes the plan STALE and
    // the finalizer REFUSES ([`FinalizeOutcome::Refused`], the reason
    // carrying the kernel's Conflict/StalePlan message); the caller finalizes
    // the stale plan `Degraded` — never stranded, never `Successful`. The
    // ATOMIC store/kernel gate (the txn's in-memory `apply_event` fold)
    // remains the ultimate authority; this is the early, no-mutation check.
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
            .unwrap_or_else(|| {
                SlotId::parse("no-slot").expect("the no-slot sentinel is a safe segment")
            });
        return Ok(FinalizeOutcome::Refused {
            reason: parent_error.message(),
            slot,
        });
    }
    let mut selected: Vec<SlotId> = attempt.selected_membership().into_iter().collect();
    selected.sort();
    let mut guards: Vec<HeldSlotLock<'_>> = Vec::with_capacity(selected.len());
    for sid in &selected {
        let Some(helper) = helpers.get(sid) else {
            return Ok(FinalizeOutcome::Refused {
                reason: state_diverged_reason(sid),
                slot: sid.clone(),
            });
        };
        match crate::remote::helper::SlotRemote::new(
            helper,
            crate::remote::helper::GenerationOwner::new((*application).clone(), sid.clone()),
        )
        .acquire_lock_guard(op_id)
        {
            Ok(guard) => guards.push(guard),
            Err(_) => return Ok(FinalizeOutcome::Pending),
        }
    }
    match verify_selected_locked(helpers, attempt, application)? {
        LockedObservation::Diverged(slot) => {
            return Ok(FinalizeOutcome::Refused {
                reason: state_diverged_reason(&slot),
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
            attempt.deployment_id(),
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
    let observed = match verify_selected_locked(helpers, attempt, application)? {
        LockedObservation::Verified(o) => o,
        LockedObservation::Diverged(slot) => {
            return Ok(FinalizeOutcome::Refused {
                reason: state_diverged_reason(&slot),
                slot,
            });
        }
    };
    let _ = observed;
    // THE SEALED PROOF — minted EXACTLY at the verified-execution evidence
    // point (the second `LockedObservation::Verified` above): the ONLY
    // production path that can produce a `Successful` terminal. The proof
    // type is sealed (private field, `pub(crate)` mint), so a library
    // caller without verified evidence cannot fabricate success. The
    // kernel's [`crate::kernel::transition::decide_terminal`] truth table
    // is what makes `Verified` mean `Successful`; the proof mint is the
    // evidence gate.
    let proof = crate::kernel::terminal::VerifiedExecution::from_verified_report();
    let terminal = LedgerTerminal::successful(
        proof,
        crate::remote::helper::now_rfc3339_ts(),
        crate::kernel::terminal::intent_digest(attempt),
        Some(reason.to_string()),
    );
    // THE TXN APPENDS THROUGH THE STATE MACHINE'S GATE: the in-memory
    // `apply_event` fold refuses a `Successful` terminal whose intent's
    // parent is no longer the current successful head — a drifted head (a
    // later deployment already succeeded on this parent) makes THIS plan
    // stale. The Conflict (StalePlan) refusal is translated into
    // [`FinalizeOutcome::Refused`] with the kernel's conflict message as
    // the reason (the structured stale-plan source); the caller finalizes
    // the stale plan `Degraded`, never `Successful`, and the stale intent
    // never becomes the head — the newer head's snapshot is untouched.
    match txn.append_terminal(attempt.deployment_id(), &terminal) {
        Ok(()) => Ok(FinalizeOutcome::Finalized),
        // The store mirror routes the stale-plan refusal through the TYPED
        // facade error ([`Error::Kernel`] carrying the complete
        // [`ConflictError::ParentMismatch`] evidence); the structured
        // refusal reason stays the kernel's Display sentence (the stale-plan
        // source the caller records on the degraded terminal).
        Err(Error::Kernel(KernelError::Conflict(conflict))) => Ok(FinalizeOutcome::Refused {
            reason: conflict.to_string(),
            slot: selected.first().cloned().unwrap_or_else(|| {
                SlotId::parse("no-slot").expect("the no-slot sentinel is a safe segment")
            }),
        }),
        Err(e) => Err(e),
    }
}

pub struct FinalizeSettings<'a> {
    pub reason: &'a str,
    pub op_id: &'a OperationId,
    /// The application whose store this finalization verifies: the
    /// lock-verified evidence gathering reads each selected slot's live
    /// generation assignment and must verify its OWNER MARKER against this
    /// application + the slot (fail closed on transplanted state).
    pub application: &'a crate::identity::ApplicationStoreKey,
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

/// THE FINALIZER'S "STATE DIVERGED" REASON: a selected slot's live state no
/// longer matches the plan is a [`ConflictError::TopologyChanged`] refusal
/// (the CONFLICT class — a valid operation against concurrently changed
/// state), its Display sentence (keeping the "state diverged" keyword) is
/// the refused reason the caller records on the degraded terminal.
fn state_diverged_reason(slot: &SlotId) -> String {
    KernelError::Conflict(ConflictError::TopologyChanged { slot: slot.clone() }).message()
}
fn verify_selected_locked(
    helpers: &HashMap<SlotId, RemoteHelper>,
    attempt: &DeploymentIntent,
    application: &crate::identity::ApplicationStoreKey,
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
        // Every read verifies the generation's OWNER MARKER against this
        // application + slot: a transplanted record is a diverged slot
        // (fail closed — never verified as the intent's planned result).
        let owner = crate::remote::helper::GenerationOwner::new(application.clone(), sid.clone());
        let st1 = helper.status(&owner)?;
        let Some(live_gen) = st1.current_generation() else {
            return Ok(LockedObservation::Diverged(sid.clone()));
        };
        let asn = helper.read_assignment(live_gen, &owner)?;
        let st2 = helper.status(&owner)?;
        if st2.current_generation() != Some(live_gen)
            || live_gen != entry.generation()
            || asn.artifact != *entry.artifact()
        {
            return Ok(LockedObservation::Diverged(sid.clone()));
        }
        observed.insert(
            sid.clone(),
            GenerationRef {
                generation: live_gen.clone(),
                assignment: PlacementSlotAssignment {
                    placement_slot: sid,
                    artifact: asn.artifact,
                },
            },
        );
    }
    Ok(LockedObservation::Verified(observed))
}
