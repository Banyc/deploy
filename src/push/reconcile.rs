//! Pending-attempt reconciliation (`PendingCommit` / `InProgress` recovery).
//!
//! `reconcile_pending_commits` completes incomplete attempts left by earlier
//! pushes: eligibility gating on the latest transition, membership and
//! generation verification, missing fleet-commit markers under each slot's
//! mutation lock, and replay-safe finalization through the same shared
//! finalizer as the main success path
//! ([`crate::history::finalize_successful_attempt`]). Extracted from
//! `push::engine`; the engine calls it before its early no-op check.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::history;
use crate::model::{GenerationId, OperationId, PlacementSlotId};
use crate::records::{DeploymentAttempt, DeploymentStatus};
use crate::remote::helper::RemoteHelper;
use crate::store::local::LocalStore;
use std::collections::{BTreeMap, HashMap, HashSet};

/// Reconcile incomplete attempts recorded by earlier pushes (steps 15 of
/// `requirement.md`). An attempt is eligible when its fleet-commit markers
/// were not all durable and/or its finalization never completed — the latest
/// transition is `PendingCommit` (markers missing: the earlier push gave up
/// during the metadata phase) OR `InProgress` (the intent was persisted before
/// mutation but finalization never started/completed — e.g. a crash between
/// `append_attempt` and the finalize marker, or a faulted `write_results`);
/// the snapshot log never advanced, and a naive "Everything up to date" push
/// would otherwise skip the missing markers/finalization.
///
/// Eligibility is determined by the attempt's LATEST transition
/// (`deployments/<id>/transitions.jsonl`), not the append-only
/// `attempts.jsonl` record (which carries no status at all): an attempt is
/// reconciled only while its latest transition is `PendingCommit` or
/// `InProgress` (or no transition exists yet for a just-recorded attempt).
/// Once a push finalizes the attempt with a `Successful` or `Degraded`
/// transition, it is skipped on every later push — a finalized attempt is
/// never re-reconciled and never re-entered into the snapshot log.
///
/// For each eligible attempt, oldest first (attempts.jsonl order, so
/// snapshot indices stay monotonic):
/// 1. Membership: every participating server must still exist in the target.
/// 2. Generations: each participating server's CURRENT generation (fresh
///    `helper.status()`) must equal the generation the attempt recorded for it
///    (`desired[server].generation`, falling back to `servers[server].generation`).
/// 3. If everything matches, write the missing markers under each server's
///    mutation lock (idempotent: already-written markers are a byte-for-byte
///    no-op) using the attempt's ORIGINAL deployment ID, then finalize
///    REPLAY-SAFELY through the SAME shared finalizer as the main success
///    path ([`history::finalize_successful_attempt`]): the recoverable
///    `PendingCommit` marker step is a no-op here when the latest transition
///    is already `PendingCommit` (for an `InProgress` attempt it appends the
///    marker — the attempt becomes re-eligible), then the idempotent snapshot
///    entry + `refs/last-successful` repair ([`history::ensure_snapshot`]),
///    and the final `Successful` transition LAST. The snapshot is built from
///    the attempt's OUTCOMES — `deployments/<id>/results.json` when present,
///    else the verified desired state
///    ([`history::resolve_attempt_outcomes`]). The latest transition is the
///    eligibility gate for recovery: as long as it still says `PendingCommit`
///    (or `InProgress`), any crash or error mid-finalization leaves the attempt
///    eligible and the next push replays exactly the remaining steps; once it
///    says `Successful`, every earlier step is already durable, so nothing is
///    lost.
/// 4. A confirmed membership/generation mismatch finalizes the attempt as
///    `Degraded` (no snapshot entry). An existing marker whose content differs
///    from the deterministic payload is an integrity conflict — a concurrent
///    controller recorded a different fact or the remote state diverged — and
///    is NOT transient: the conflicting marker is left untouched and the
///    attempt is finalized `Degraded` (transition only, no snapshot entry)
///    instead of being stranded `PendingCommit` forever. Only transient remote
///    failures (lock held, status read error, transport-level marker write
///    error) leave the attempt `PendingCommit` for a later retry: it is never
///    falsely marked `Successful` (markers are missing) and never falsely
///    accused of divergence (fail-closed, not degrade, on errors we cannot
///    attribute to state change).
///
/// Recovery only touches markers, the transition stream, the snapshot log,
/// and `refs/last-successful`: no activation, no verification adapters, no
/// `current` changes, no restart of healthy services.
pub(crate) fn reconcile_pending_commits(
    store: &LocalStore,
    config: &Config,
    target_name: &str,
    op_id: &OperationId,
    helpers: &HashMap<PlacementSlotId, RemoteHelper>,
) -> Result<()> {
    // Eligible attempts: the attempts.jsonl record must exist AND the latest
    // transition must be `PendingCommit` or `InProgress` (or the transition
    // stream is momentarily absent for a just-recorded attempt). A finalized
    // attempt (latest transition `Successful` / `Degraded`, or any other
    // non-eligible status) is skipped — an already-reconciled attempt is
    // never re-reconciled on a later push. `InProgress` is eligible because
    // the intent is now persisted BEFORE any remote mutation: a crash after
    // the mutation phase but before finalization leaves the latest transition
    // `InProgress` with the servers already at the desired generations, and
    // skipping it would strand the deployment unrecoverable (the next push
    // would see everything up to date but never record a snapshot/ref).
    let mut pending: Vec<DeploymentAttempt> = Vec::new();
    for attempt in store.read_attempts(target_name)? {
        match store.latest_status(attempt.deployment_id.as_str())? {
            // No transition recorded yet: legitimately new pending attempt.
            None => pending.push(attempt),
            Some(DeploymentStatus::PendingCommit) => pending.push(attempt),
            // Intent persisted but finalization never completed: recover it
            // exactly like a pending attempt (the finalizer appends the
            // recoverable `PendingCommit` marker first, since the latest
            // transition is not yet `PendingCommit`).
            Some(DeploymentStatus::InProgress) => pending.push(attempt),
            // Finalized on an earlier push (Successful/Degraded): skip.
            Some(_) => {}
        }
    }
    if pending.is_empty() {
        return Ok(());
    }

    // Current target membership: a pending attempt whose participants were
    // removed from the target can no longer be completed as a fleet commit.
    let members: HashSet<String> = config
        .target_slots(target_name)?
        .iter()
        .map(|(slot, _)| slot.id.clone())
        .collect();
    // The slot→physical-binding map recorded into snapshots finalized by
    // recovery (identical to the map the original commit would have
    // recorded: the current config's `{server, deploy_dir}` per slot).
    let slot_bindings = config.target_slot_bindings(target_name)?;

    'pending: for attempt in pending {
        // 1. Membership check.
        let membership_ok = attempt
            .slot_ids
            .iter()
            .all(|sid| members.contains(sid.as_str()));
        if !membership_ok {
            store.append_transition(
                attempt.deployment_id.as_str(),
                &DeploymentStatus::Degraded,
                Some("membership mismatch"),
            )?;
            continue;
        }

        // 2. Generation verification against fresh remote status reads.
        // `recorded` collects the generation the attempt minted for each
        // slot (the same value step 15 compared against when writing the
        // markers), so recovery writes markers identical to what the original
        // commit would have written.
        let mut recorded: BTreeMap<PlacementSlotId, GenerationId> = BTreeMap::new();
        let mut all_match = true;
        let mut unverifiable = false;
        for sid in &attempt.slot_ids {
            let Some(recorded_gen) = attempt
                .desired
                .get(sid)
                .map(|d| d.generation.clone())
                .or_else(|| attempt.slots.get(sid).and_then(|s| s.generation.clone()))
            else {
                // No recorded generation for a participant: the attempt is not
                // a coherent fleet commit; finalize as degraded.
                all_match = false;
                break;
            };
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
            store.append_transition(
                attempt.deployment_id.as_str(),
                &DeploymentStatus::Degraded,
                Some("generation diverged"),
            )?;
            continue;
        }

        // 3. Write the missing markers under each slot's mutation lock
        // (mirroring step 15's lock discipline: the guard is held for the
        // whole write and released on drop). The marker payload carries the
        // full participating slot set; already-present markers are an
        // idempotent byte-for-byte no-op.
        let slot_ids: Vec<String> = attempt
            .slot_ids
            .iter()
            .map(|s| s.as_str().to_string())
            .collect();
        let mut markers_written = true;
        for sid in &attempt.slot_ids {
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
                    // attempt as `Degraded` (transition only, no snapshot
                    // entry) and move on to the next pending attempt — a later
                    // retry would only hit the same integrity error again.
                    store.append_transition(
                        attempt.deployment_id.as_str(),
                        &DeploymentStatus::Degraded,
                        Some("marker integrity conflict"),
                    )?;
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
        //    main success path ([`history::finalize_successful_attempt`]):
        //    the recoverable `PendingCommit` marker step is a no-op here when
        //    the attempt's latest transition is already `PendingCommit` (for
        //    an `InProgress` attempt it appends the marker — the eligibility
        //    gate for recovery), then the idempotent snapshot
        //    insert + `refs/last-successful` repair
        //    ([`history::ensure_snapshot`] never appends a second entry for
        //    the same deployment), and the terminal `Successful` transition
        //    LAST. A crash or error at ANY of these steps leaves the attempt
        //    eligible (`PendingCommit` / `InProgress`) and the next push
        //    replays exactly the remaining steps; once the transition says
        //    `Successful`, every earlier step is already durable. The
        //    append-only attempts.jsonl record is untouched (still the
        //    original deployment ID, no status field, no outcomes). The
        //    snapshot is built from the attempt's OUTCOMES —
        //    `deployments/<id>/results.json` when present, else the verified
        //    desired state ([`history::resolve_attempt_outcomes`]) — and
        //    records each slot's physical server binding from the current
        //    records each slot's complete physical binding (`{server,
        //    deploy_dir}`) from the current config (`slot_bindings`), so
        //    rollback can verify a slot still lives at the exact on-host
        //    location it was deployed onto.
        let outcomes = history::resolve_attempt_outcomes(store, &attempt)?;
        history::finalize_successful_attempt(
            store,
            &attempt,
            &outcomes,
            "recovery finalized",
            &slot_bindings,
        )?;
    }
    Ok(())
}
