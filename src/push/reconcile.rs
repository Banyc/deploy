//! Pending-attempt reconciliation (intent-only ledger entries).
//!
//! `reconcile_pending_commits` completes incomplete attempts left by earlier
//! pushes: a ledger entry WITHOUT a terminal event is the recoverable pending
//! state (the intent is durable, the finalization never completed — a crash
//! between the intent append and the terminal append, a faulted terminal
//! append, or a demoted `PendingCommit` commit). Eligibility gating is the
//! ENTRY SHAPE itself — no transition stream exists anymore. Recovery
//! verifies membership and generations, writes missing commit markers, and
//! finalizes replay-safely through the SAME shared finalizer as the main
//! success path ([`crate::history::finalize_successful_attempt`]).

use crate::config::ProjectConfig;
use crate::error::{Error, Result};
use crate::history;
use crate::model::{GenerationId, OperationId, SlotId};
use crate::records::{
    DeploymentIntent, LedgerTerminal, SlotOutcome, SlotOutcomeKind, SlotResult, SlotTable,
    TerminalDisposition,
};
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
/// 2. Generations: each participating server's CURRENT generation (fresh
///    `helper.status()`) must equal the generation the attempt recorded for it
///    (`desired[slot].generation`).
/// 3. If everything matches, write the missing markers under each server's
///    mutation lock (idempotent: already-written markers are a byte-for-byte
///    no-op) using the attempt's ORIGINAL deployment ID, then finalize
///    REPLAY-SAFELY through the SAME shared finalizer as the main success
///    path ([`crate::history::finalize_successful_attempt`]): ONE atomic
///    terminal append carrying the `Successful` status, the per-slot
///    outcomes, and the rollback state (built from the VERIFIED DESIRED
///    state — the old `deployments/<id>/results.json` outcomes store is
///    GONE, and a terminal-less entry has no outcomes by construction).
/// 4. A confirmed membership/generation mismatch finalizes the attempt as
///    `Degraded` (a terminal event with no rollback). An existing marker
///    whose content differs from the deterministic payload is an integrity
///    conflict — a concurrent controller recorded a different fact or the
///    remote state diverged — and is NOT transient: the conflicting marker
///    is left untouched and the attempt is finalized `Degraded` (terminal
///    only, no rollback) instead of being stranded pending forever. Only
///    transient remote failures (lock held, status read error,
///    transport-level marker write error) leave the attempt pending (no
///    terminal) for a later retry.
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
    // The slot→physical-binding map recorded into rollbacks finalized by
    // recovery (identical to the map the original commit would have
    // recorded: the current config's `{server, deploy_dir}` per slot).
    let slot_bindings = config.target_slot_bindings(target_name)?;

    'pending: for attempt in pending {
        // 1. Membership check.
        let membership_ok = attempt
            .slots
            .keys()
            .all(|sid| members.contains(sid.as_str()));
        if !membership_ok {
            append_degraded(store, target_name, &attempt, "membership mismatch")?;
            continue;
        }

        // 2. Generation verification against fresh remote status reads.
        let mut recorded: BTreeMap<SlotId, GenerationId> = BTreeMap::new();
        let mut all_match = true;
        let mut unverifiable = false;
        for sid in attempt.slots.keys() {
            let Some(slot) = attempt.slots.get(sid) else {
                // No recorded generation for a participant: the attempt is not
                // a coherent commit; finalize as degraded.
                all_match = false;
                break;
            };
            let recorded_gen = slot.desired.generation.clone();
            let Some(helper) = helpers.get(sid) else {
                all_match = false;
                break;
            };
            match helper.status() {
                Ok(st) if st.current_generation.as_deref() == Some(recorded_gen.as_str()) => {
                    recorded.insert(sid.clone(), recorded_gen);
                }
                Ok(_) => {
                    // Confirmed divergence: the slot no longer points at the
                    // generation this attempt minted.
                    all_match = false;
                    break;
                }
                Err(_) => {
                    // Transient status read failure: cannot verify, so leave
                    // the attempt pending for a later retry (fail-closed).
                    unverifiable = true;
                    break;
                }
            }
        }
        if unverifiable {
            continue;
        }
        if !all_match {
            append_degraded(store, target_name, &attempt, "generation diverged")?;
            continue;
        }

        // 3. Write the missing markers under each slot's mutation lock
        // (mirroring step 15's lock discipline: the guard is held for the
        // whole write and released on drop). The marker payload carries the
        // full participating slot set; already-present markers are an
        // idempotent byte-for-byte no-op.
        let slot_ids: Vec<String> = attempt
            .slots
            .keys()
            .map(|s| s.as_str().to_string())
            .collect();
        let mut markers_written = true;
        for sid in attempt.slots.keys() {
            let helper = &helpers[sid];
            let _guard = match helper.acquire_lock_guard(op_id.as_str()) {
                Ok(g) => g,
                Err(_) => {
                    // Lock transiently held elsewhere: keep the attempt pending
                    // so a later push retries rather than degrading a healthy
                    // attempt on a transient blip.
                    markers_written = false;
                    break;
                }
            };
            match helper.write_commit_marker(
                attempt.deployment_id.as_str(),
                recorded[sid].as_str(),
                &slot_ids,
                Some(attempt.target.as_str()),
            ) {
                Err(Error::Integrity(_)) => {
                    // Conflicting marker already exists with different
                    // content: a permanent condition, not a transient blip.
                    // Leave the conflicting marker untouched, finalize THIS
                    // attempt as `Degraded` (terminal only, no rollback) and
                    // move on to the next pending attempt — a later retry
                    // would only hit the same integrity error again.
                    append_degraded(store, target_name, &attempt, "marker integrity conflict")?;
                    continue 'pending;
                }
                Err(_) => {
                    // Marker not durable yet: leave the attempt pending.
                    markers_written = false;
                    break;
                }
                Ok(_) => {}
            }
            // `_guard` drops here, releasing the lock.
        }
        if !markers_written {
            continue;
        }

        // 4. Finalize REPLAY-SAFELY through the SAME shared finalizer as the
        //    main success path ([`history::finalize_successful_attempt`]): ONE
        //    atomic terminal append (status `Successful`, the per-slot
        //    outcomes, and the rollback state built from the VERIFIED DESIRED
        //    state). A crash or error at the append leaves the entry
        //    intent-only (eligible) and the next push replays exactly the
        //    remaining steps; once the terminal exists, every earlier step is
        //    already durable.
        let (outcomes, actuals) = history::recovery_outcomes(&attempt);
        // The CURRENT target slot set: the complete snapshot omits slots
        // removed from the current configuration and carries every current
        // unselected slot forward from the base.
        let current_slot_ids: Vec<SlotId> = members
            .iter()
            .map(|m| SlotId::parse(m).expect("config slot id is a safe segment"))
            .collect();
        history::finalize_successful_attempt(
            store,
            &attempt,
            &outcomes,
            &actuals,
            "recovery finalized",
            &slot_bindings,
            &current_slot_ids,
        )?;
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
    // The Degraded disposition's REMAINING CHANGES are DERIVED from the
    // outcomes (the slots whose FINAL OBSERVED STATE differs from their
    // pre_push state) — never stored. The wire record therefore records the
    // pending changes — the attempt's desired generations, each as an
    // UNCOMPENSATED `Failed` outcome (a pre-swap failure / failed
    // compensation: the advance outcome is unknown, and the outcome's
    // observed generation differs from the intent's pre_push, so the
    // derived remaining-changes set is non-empty).
    let outcomes: BTreeMap<SlotId, SlotResult> = attempt
        .slots
        .iter()
        .map(|(sid, slot)| {
            (
                sid.clone(),
                SlotResult {
                    slot_id: sid.clone(),
                    outcome: SlotOutcomeKind::Failed,
                    generation: Some(slot.desired.generation.clone()),
                    compensated: false,
                    error: None,
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
            outcomes,
            disposition: TerminalDisposition::Degraded,
            reason: Some(reason.to_string()),
        },
    )
}
