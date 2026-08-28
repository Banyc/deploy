//! Pending-attempt reconciliation (feature area A2: Ledger semantics — the
//! RECOVERY / RECONCILIATION of intent-only ledger entries).
//!
//! `reconcile_pending_commits` completes incomplete attempts left by earlier
//! pushes: a ledger entry WITHOUT a terminal event is the recoverable pending
//! state (the intent is durable, the finalization never completed — a crash
//! between the intent append and the terminal append, a faulted terminal
//! append, or a demoted `PendingCommit` commit). Eligibility gating is the
//! ENTRY SHAPE itself — no transition stream exists anymore. Recovery
//! verifies membership and bindings, then finalizes replay-safely through
//! the SAME shared LOCK-VERIFIED finalizer as the main success path
//! ([`crate::ledger::finalize::finalize_successful_locked`]): ONE operation
//! that acquires ALL selected-slot locks (deterministic order), re-observes
//! every selected slot's live `GenerationRef` under the locks and requires
//! it to EXACTLY equal the frozen desired assignment, writes the missing
//! commit markers, and appends the terminal before releasing the locks.

use crate::config::ProjectConfig;
use crate::error::{Error, Result};
use crate::identity::{OperationId, SlotId};
use crate::ledger::finalize::{FinalizeOutcome, FinalizeSettings, finalize_successful_locked};
use crate::ledger::records::DeploymentIntent;
use crate::ledger::records::SlotTable;
use crate::ledger::records::{LedgerTerminal, TerminalDisposition};
use crate::ledger::records::{Observation, ObservedGeneration};
use crate::ledger::records::{PhysicalBinding, SlotOutcome, SlotOutcomeKind, SlotTransition};
use crate::remote::helper::RemoteHelper;
use crate::store::local::LocalStore;
use std::collections::{BTreeMap, HashMap, HashSet};

/// Reconcile incomplete attempts recorded by earlier pushes (steps 15 of
/// `requirement.md`). An attempt is ELIGIBLE when its ledger entry has NO
/// TERMINAL EVENT: the intent was persisted before any remote mutation but
/// finalization never completed (a crash between the intent append and the
/// terminal append, a faulted terminal append, or a `PendingCommit` demotion
/// whose commit markers were not all durable). A naive "Everything up to
/// date" push would otherwise skip the missing markers/finalization.
///
/// For each eligible entry, oldest first (ledger order, so the successful
/// chain stays ordered):
/// 1. Membership: every participating server must still exist in the target.
/// 2. Binding drift: every selected slot's LIVE physical binding must equal
///    the intent's FROZEN binding.
/// 3. THE ONE LOCK-VERIFIED FINALIZATION (the SAME shared operation as the
///    main success path
///    ([`crate::ledger::finalize::finalize_successful_locked`])): acquire
///    ALL selected-slot mutation locks in deterministic sorted-slot-id
///    order, re-observe EVERY selected slot's live `GenerationRef`
///    (generation AND artifact) under the locks and require it to EXACTLY
///    equal the frozen desired assignment, write the missing markers under
///    the locks (idempotent: already-written markers are a byte-for-byte
///    no-op) using the attempt's ORIGINAL deployment ID, and append the
///    terminal REPLAY-SAFELY — ONE atomic terminal append carrying the
///    `Successful` status, the ACTIVATED slot-id set, and the rollback state
///    (built EXCLUSIVELY from the VERIFIED LIVE `GenerationRef`s the
///    lock-verified re-observation returns — the values read under the
///    locks; the old `deployments/<id>/results.json` outcomes store is
///    GONE, and the successful finalizer no longer accepts observation
///    records at all). The locks are
///    released only after the terminal is appended. This replaces the old
///    per-slot lock + generation check: a slot whose live state diverged
///    (the old "generation diverged" degraded case) is the shared
///    operation's REFUSAL.
/// 4. A confirmed membership/binding mismatch OR the shared operation's
///    REFUSAL (a selected slot's live `GenerationRef` diverged — "state
///    diverged" — or a conflicting marker exists — "marker integrity
///    conflict") finalizes the attempt as `Degraded` (a terminal event with
///    no rollback). An existing marker whose content differs from the
///    deterministic payload is an integrity conflict — a concurrent
///    controller recorded a different fact or the remote state diverged —
///    and is NOT transient: the conflicting marker is left untouched and the
///    attempt is finalized `Degraded` (terminal only, no rollback) instead
///    of being stranded pending forever. Only transient remote failures
///    (lock held, status read error, transport-level marker write error)
///    leave the attempt pending (no terminal) for a later retry.
///
/// Recovery only touches markers and the ledger's terminal event: no
/// activation, no verification adapters, no `current` changes, no restart of
/// healthy services.
pub(crate) fn reconcile_pending_commits(
    store: &LocalStore,
    config: &ProjectConfig,
    target_name: &str,
    op_id: &OperationId,
    helpers: &HashMap<SlotId, RemoteHelper>,
) -> Result<()> {
    // Eligible attempts: ledger entries WITHOUT a terminal event (the intent
    // is durable; finalization never completed). An entry WITH a terminal
    // (Successful / Degraded / FailedPreflight / FailedRolledBack) is
    // finalized and skipped forever.
    let mut pending: Vec<DeploymentIntent> = Vec::new();
    for entry in store.read_ledger(target_name)? {
        if entry.terminal.is_none() {
            pending.push(entry.intent);
        }
    }
    if pending.is_empty() {
        return Ok(());
    }

    // Current target membership: a pending attempt whose participants were
    // removed from the target can no longer be completed as a commit.
    let members: HashSet<String> = config
        .target_slots(target_name)?
        .iter()
        .map(|(slot, _)| slot.id.clone())
        .collect();
    // The slot→physical-binding map of the CURRENT configuration (the LIVE
    // bindings at recovery time). These are compared per pending attempt
    // against the intent's FROZEN bindings — the rollback's bindings are
    // NEVER taken from this live map: a server rebound or a moved
    // `deploy_dir` since the intent was written must be recorded as a
    // DEGRADED attempt, not as a false historical fact.
    let live_bindings = config.target_slot_bindings(target_name)?;

    for attempt in pending {
        // 1. Membership check.
        let membership_ok = attempt
            .slots
            .keys()
            .all(|sid| members.contains(sid.as_str()));
        if !membership_ok {
            append_degraded(store, target_name, &attempt, "membership mismatch")?;
            continue;
        }

        // 2. BINDING-DRIFT CHECK (schema v6): the intent FROZE each selected
        // slot's physical binding (`{server, deploy_dir}`) at plan time;
        // recovery compares each selected slot's LIVE binding against that
        // frozen value. ALL equal → the attempt is still on the exact
        // physical placement it was planned against (finalization below uses
        // the FROZEN values — equal to the live map's then, by construction).
        // ANY selected slot's live binding DRIFTS (server or deploy_dir
        // differs from the frozen value) → the attempt can no longer be
        // completed as the historical commit it was planned to be: mark it
        // DEGRADED (terminal only, no rollback) — recording the LIVE
        // bindings as if they were the plan-time bindings would make exact
        // rollback verify against the wrong host/location. A slot REMOVED
        // from the target has no live binding at all — already handled by
        // the membership check above (a missing live binding is also drift,
        // fail closed).
        let mut bindings_equal = true;
        let frozen_bindings: BTreeMap<SlotId, PhysicalBinding> = attempt
            .slots
            .iter()
            .map(|(sid, slot)| {
                let equal = live_bindings.get(sid) == Some(&slot.binding);
                bindings_equal &= equal;
                (sid.clone(), slot.binding.clone())
            })
            .collect();
        if !bindings_equal {
            append_degraded(store, target_name, &attempt, "binding drift")?;
            continue;
        }

        // 3. THE ONE LOCK-VERIFIED FINALIZATION — the SAME shared operation
        //    as the main success path
        //    ([`crate::ledger::finalize::finalize_successful_locked`]):
        //    acquire ALL selected-slot mutation locks (deterministic
        //    sorted-slot-id order), re-observe EVERY selected slot's LIVE
        //    `GenerationRef` (generation AND artifact) under the locks and
        //    require it to EXACTLY equal the frozen desired assignment, write
        //    the missing markers under the locks (already-present markers are
        //    a byte-for-byte idempotent no-op), and append the terminal — ONE
        //    atomic terminal append (status `Successful`, the ACTIVATED
        //    slot-id set, and the rollback state built EXCLUSIVELY from the
        //    VERIFIED LIVE `GenerationRef`s the re-observation returned —
        //    never from the engine's observation records, which the
        //    successful finalizer no longer even accepts) — then release the
        //    locks. This replaces the old per-slot
        //    lock + generation check: a slot whose live state diverged (the
        //    old "generation diverged" degraded case) is the shared
        //    operation's REFUSAL. A crash or error at the append leaves the
        //    entry intent-only (eligible) and the next push replays exactly
        //    the remaining steps; once the terminal exists, every earlier
        //    step is already durable. The terminal's FULL MEMBERSHIP is the
        //    intent's FROZEN value (the finalizer reads
        //    `attempt.full_membership()` — the complete target membership at
        //    PLAN TIME): the live configuration may have changed arbitrarily
        //    since the intent was written, and recovery must reproduce
        //    exactly what the intent froze — never derive the memberships
        //    from the current configuration. The rollback's PHYSICAL
        //    BINDINGS are likewise the intent's FROZEN per-slot bindings
        //    ([`frozen_bindings`], built above from `attempt.slots[sid].binding`
        //    — the values the binding-drift check just verified EQUAL the
        //    live map's): recovery never stamps the live configuration's
        //    bindings into a rollback, because a drifted configuration is
        //    degraded, never recorded as history.
        match finalize_successful_locked(
            store,
            &attempt,
            helpers,
            &frozen_bindings,
            &FinalizeSettings {
                reason: "recovery finalized",
                op_id,
            },
        )? {
            FinalizeOutcome::Finalized => {}
            FinalizeOutcome::Pending => {
                // A TRANSIENT failure (a slot lock held elsewhere, a live
                // status/assignment read failure, a marker transport write
                // failure): the attempt stays PENDING (intent-only) for a
                // later retry — never finalized on unverified state.
                continue;
            }
            FinalizeOutcome::Refused { reason, .. } => {
                // The shared operation REFUSED: a selected slot's live
                // `GenerationRef` diverged from the frozen desired
                // ("state diverged") or a conflicting marker exists
                // ("marker integrity conflict" — left untouched; a retry
                // would only hit the same permanent condition). Finalize
                // THIS attempt as `Degraded` (terminal only, no rollback)
                // and move on to the next pending attempt — NEVER
                // `Successful`.
                append_degraded(store, target_name, &attempt, reason)?;
            }
        }
    }
    Ok(())
}

/// Append a `Degraded` TERMINAL EVENT (no rollback state) for an attempt
/// whose pending state cannot be completed (membership/generation mismatch,
/// marker integrity conflict).
fn append_degraded(
    store: &LocalStore,
    target_name: &str,
    attempt: &DeploymentIntent,
    reason: &str,
) -> Result<()> {
    // The Degraded disposition's REMAINING CHANGES are DERIVED from the
    // outcomes (the slots whose FINAL OBSERVED STATE differs from their
    // pre_push state) — never stored. The wire record therefore records the
    // pending changes — the attempt's desired generations, each as an
    // UNCOMPENSATED `Failed` outcome (a pre-swap failure / failed
    // compensation: the advance outcome is unknown, and the outcome's
    // observed generation differs from the intent's pre_push, so the
    // derived remaining-changes set is non-empty).
    let outcomes: BTreeMap<SlotId, SlotOutcome> = attempt
        .slots
        .iter()
        .map(|(sid, slot)| {
            (
                sid.clone(),
                SlotOutcome {
                    outcome: SlotOutcomeKind::Failed,
                    observation: Observation::Known(ObservedGeneration {
                        generation: slot.desired.generation.clone(),
                    }),
                    compensated: false,
                    error: None,
                    transition: SlotTransition::AdvanceUnknown,
                },
            )
        })
        .collect();
    let outcomes: SlotTable<SlotOutcome> = SlotTable::from_map(outcomes);
    // Verify the disposition is not all-restored (fail fast — the read path
    // refuses a Degraded wire whose outcomes are ALL restored; a
    // fully-compensated attempt must be `FailedRolledBack`, never Degraded).
    if outcomes
        .values()
        .all(|r| r.outcome == SlotOutcomeKind::Restored)
    {
        return Err(Error::store(
            "a Degraded terminal requires at least one non-restored outcome — none recorded"
                .to_string(),
        ));
    }
    store.append_terminal(
        target_name,
        &attempt.deployment_id,
        &LedgerTerminal {
            recorded_at: crate::remote::helper::now_rfc3339(),
            disposition: TerminalDisposition::Degraded { outcomes },
            reason: Some(reason.to_string()),
        },
    )
}
