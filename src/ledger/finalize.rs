//! REPLAY-SAFE, LOCK-VERIFIED FINALIZATION of a successful deployment
//! (feature area A2: Ledger semantics).
//!
//! [`finalize_successful_locked`] is the SINGLE shared terminal path used
//! by BOTH the normal push success path and recovery
//! (`crate::ledger::recovery::reconcile_pending_commits`): it ACQUIRES ALL
//! SELECTED-SLOT MUTATION LOCKS (deterministic sorted-slot-id order, held
//! TOGETHER for the whole finalize), RE-OBSERVES every selected slot's LIVE
//! assignment under the locks and requires the COMPLETE `GenerationRef`
//! (generation AND artifact: release/variant/tree) to EXACTLY EQUAL the
//! attempt's FROZEN DESIRED assignment (`attempt.slots[sid].desired` — the
//! value the intent froze at plan time), writes the commit markers, and
//! APPENDS the TERMINAL EVENT (status `Successful`, the ACTIVATED slot-id
//! set, and the rollback state) — ONE atomic
//! line append, the only commit of the finalize — then releases the locks.
//! Replay idempotency: a crash after the append can never duplicate the
//! terminal (a repeated finalize for the same deployment id is a no-op; the
//! store refuses duplicate appends). The rollback payload itself is built
//! by [`crate::ledger::records::build_rollback`] (the complete-snapshot
//! overlay) EXCLUSIVELY from the VERIFIED LIVE `GenerationRef`s the
//! lock-verified re-observation RETURNED — the values read under the locks
//! and proved equal to the frozen desired — NEVER from the engine's earlier
//! observation records (`actuals`/`outcomes`: the old rollback source a
//! concurrent controller can make STALE — recorded before the locks, then
//! diverged on the remote — while the verification still passes).
//!
//! ANY SELECTED SLOT whose LIVE `GenerationRef` diverges from the frozen
//! desired assignment — a concurrent controller swapped the slot's `current`
//! (or otherwise changed its live generation/artifact) since the attempt
//! was planned — REFUSES the finalization ([`FinalizeOutcome::Refused`]):
//! the attempt ends `Degraded` (a "state diverged" disposition), NEVER
//! `Successful`, and no rollback payload is recorded. The refusal is the
//! shared operation's replacement for recovery's old per-slot generation
//! check (the "generation diverged" degraded case).
//!
//! THE ONE PRIVATE VALIDATED MAP (the unreadable-terminal fix): the
//! observed `GenerationRef`s and the intent's FROZEN bindings are merged
//! into a SINGLE map — `SlotId -> BoundGeneration { generation, binding }`
//! ([`crate::ledger::records::BoundGeneration`]) — and the rollback payload
//! is built from that ONE map, so the construction has NO parallel maps to
//! drift (the old two-map construction could append a terminal whose
//! bindings key set diverged from its slots key set — MISSING / EXTRA /
//! RENAMED bindings — and the strict reader then refused it: the ledger
//! became UNREADABLE immediately after a SUCCESSFUL finalization). The
//! merge is VALIDATED (a selected slot with no binding, an extra binding
//! for a non-selected slot, or a renamed key is a construction ERROR — the
//! finalization refuses with an `Err`, never appends), [`build_rollback`]
//! is FALLIBLE (it verifies its own result's key-set equality + own-key
//! agreement), and the terminal append is additionally validated against
//! its intent BEFORE writing by the store
//! ([`crate::store::local::LocalStore::append_terminal`] — the strict
//! reader's own legs, run on the constructed pair pre-write): a rejected
//! pair leaves the ledger bytes UNCHANGED; any successful append is
//! immediately readable.
//!
//! The two PHYSICAL LINE KINDS of the append-only JSONL stream
//! ([`LedgerLine`] — the WIRE enum) and the MERGED ENTRY re-export
//! ([`LedgerEntry`], owned by [`crate::ledger::records`]) complete the
//! write path; see the "append / read line kinds" section below.

use crate::error::{Error, Result};
use crate::identity::{DeploymentId, GenerationRef, OperationId, PlacementSlotAssignment, SlotId};
use crate::ledger::records::{BoundGeneration, build_rollback};
pub use crate::ledger::records::{
    DeploymentIntent, LedgerEntry, LedgerIntentWire, LedgerRollback, LedgerTerminal,
    LedgerTerminalWire, PhysicalBinding, TerminalDisposition,
};
use crate::remote::helper::{LockGuard, RemoteHelper};
use crate::store::local::LocalStore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Finalize a successful deployment replay-safely and LOCK-VERIFIED: the
/// SINGLE shared terminal path used by BOTH the normal push success path
/// and recovery (`crate::ledger::recovery::reconcile_pending_commits`).
///
/// # The lock-verified window (the ONE operation)
///
/// 1. ACQUIRE ALL SELECTED-SLOT MUTATION LOCKS in DETERMINISTIC ORDER — the
///    selected slot ids SORTED (every controller acquires in the same
///    sequence, so two controllers can never deadlock), all held TOGETHER
///    for the whole finalize and released only on guard drop after the
///    terminal is appended.
/// 2. WHILE HOLDING THE LOCKS, RE-OBSERVE every selected slot's LIVE
///    assignment: a fresh `status()` read, the live generation's
///    assignment record (`read_assignment`), and a SECOND fresh `status()`
///    read (so a swap between the generation read and the assignment read
///    cannot be missed). The COMPLETE live `GenerationRef` — the live
///    generation AND its artifact (release/variant/tree) — must EXACTLY
///    EQUAL the FROZEN DESIRED assignment (`attempt.slots[sid].desired`).
///    ANY slot whose live `GenerationRef` diverges REFUSES the finalization
///    ([`FinalizeOutcome::Refused`] — the attempt ends `Degraded`, never
///    `Successful`; no rollback payload is recorded). This re-observation
///    is done TWICE: once before the markers and once IMMEDIATELY BEFORE
///    the terminal append, so a swap at ANY boundary (before the status
///    read, between the status and assignment reads, between marker writes,
///    or right before the terminal append) is caught.
/// 3. WHILE HOLDING THE LOCKS, write the per-slot COMMIT MARKERS (already-
///    present markers are a byte-for-byte idempotent no-op) and APPEND THE
///    TERMINAL — the `Successful` status, the ACTIVATED slot-id set, and
///    the rollback state built EXCLUSIVELY from the VERIFIED LIVE
///    `GenerationRef`s the re-observation RETURNED (the values read under
///    the locks and proved equal to the frozen desired — never the engine's
///    earlier observation records, which a concurrent controller can make
///    STALE) — ONE atomic line append, the only commit of the finalize.
/// 4. The locks are RELEASED only after the terminal is appended (the RAII
///    guards drop on every return path, including the refusals and the
///    transient-pending path).
///
/// Replay idempotency: if the entry already carries a terminal event, every
/// durable step already happened and this call is a no-op — a crash after
/// the append can never duplicate the terminal
/// ([`LocalStore::append_terminal`] refuses duplicates).
///
/// THE ROLLBACK SOURCE (the stale-snapshot fix): the terminal's rollback
/// entries are constructed EXCLUSIVELY from the OBSERVED LIVE
/// `GenerationRef`s the lock-verified re-observation returned (the frozen
/// desired assignment is an equally-valid source — the verification proved
/// the two EQUAL; the observed values are used because they are the values
/// actually read under the locks). The finalizer takes NO `actuals` /
/// `outcomes` inputs — the engine's per-slot observation records, the old
/// rollback source, are GONE: a concurrent controller that changed the
/// remote between the engine's observation and this finalization can no
/// longer leak a STALE rollback snapshot into the payload. The ACTIVATED
/// slot-id set is DERIVED from the INTENT (its selected slots), and a
/// PRE-APPEND GUARD ([`verify_rollback_matches_desired`]) enforces
/// `rollback[selected] == intent.desired` (the complete GenerationRef
/// equality: generation AND artifact) for every selected slot BEFORE the
/// terminal is appended — a mismatch aborts (fail closed), never appends.
///
/// PARTIAL-ROLLOUT SNAPSHOT SEMANTICS: every successful deployment —
/// including a group deployment — produces a COMPLETE snapshot of the
/// target's resulting state. The base is the latest successful snapshot
/// BEFORE this attempt; the SELECTED slots (the attempt's `slot_ids`) are
/// replaced with their VERIFIED assignments and current physical bindings,
/// unselected slots are carried forward unchanged, and slots
/// outside the attempt's FROZEN FULL MEMBERSHIP (`attempt.full_membership()`
/// — the complete target membership at PLAN TIME) are omitted.
///
/// THE PERSISTED MEMBERSHIPS: the terminal records BOTH memberships so the
/// record PROVES the membership equations — `selected_membership` = the
/// ACTIVATED set (the slots this attempt actually deployed; ==
/// `attempt.membership()` — the selected slot set derived from the INTENT)
/// and `full_membership` = the
/// INTENT'S FROZEN FULL MEMBERSHIP (never recomputed from the live
/// configuration — recovery finalizes a pending intent whose configuration
/// may have changed arbitrarily since the intent was written, and the
/// terminal must REPRODUCE exactly what the intent froze). The writer also
/// VERIFIES `build_rollback`'s result key set EQUALS the frozen full
/// membership (fail closed): the read side rejects a mismatch (rollback
/// slots == full_membership), so the writer must produce equality — by
/// construction the overlay covers exactly the frozen full slots (unselected
/// slots carried forward from the base, outside slots omitted, and the
/// partial-rollout guards in `crate::deploy::plan::validate_partial_rollout`
/// refuse any current slot without a base entry), and this check pins it.
///
/// DATA-THEN-SETTINGS: the positional arguments are the pure inputs the
/// operation acts on (the store, the attempt intent with its frozen desired
/// assignments, the per-slot live helpers, the
/// rollback bindings); the LAST argument is the [`FinalizeSettings`] bundle
/// (the terminal `reason` and the `op_id` the selected-slot mutation locks
/// are acquired under).
pub fn finalize_successful_locked(
    store: &LocalStore,
    attempt: &DeploymentIntent,
    helpers: &HashMap<SlotId, RemoteHelper>,
    bindings: &BTreeMap<SlotId, PhysicalBinding>,
    settings: &FinalizeSettings<'_>,
) -> Result<FinalizeOutcome> {
    let FinalizeSettings { reason, op_id } = settings;
    // Replay idempotency: a repeated finalize for the same deployment id is
    // a no-op — every durable step already happened.
    let entries = store.read_ledger(attempt.target.as_str())?;
    if let Some(e) = entries
        .iter()
        .find(|e| e.deployment_id == attempt.deployment_id)
        && e.terminal.is_some()
    {
        return Ok(FinalizeOutcome::Finalized);
    }
    // The base for the complete snapshot: the latest successful snapshot
    // BEFORE this attempt (this attempt's terminal is not yet appended).
    let base = crate::deploy::plan::latest_successful_rollback(store, attempt.target.as_str())?;
    // THE FROZEN FULL MEMBERSHIP (the complete snapshot's coverage): the
    // intent's own frozen value — resolved at PLAN TIME, never recomputed
    // from the live configuration (which may have changed since the intent
    // was written, and the terminal must reproduce exactly what the intent
    // froze).
    let current_slot_ids: Vec<SlotId> = attempt.full_membership().iter().cloned().collect();

    // 1. ACQUIRE ALL SELECTED-SLOT MUTATION LOCKS IN DETERMINISTIC ORDER —
    //    the SELECTED slot ids SORTED (the slot table iterates in
    //    deployment order, so the sorted order is chosen explicitly): every
    //    controller acquires the same sequence and two controllers can
    //    never deadlock. All guards stay alive TOGETHER for the whole
    //    finalize and release their locks on drop (every return path,
    //    including the refusals and the transient-pending path).
    let mut selected: Vec<&SlotId> = attempt.slots.keys().collect();
    selected.sort();
    let mut guards: Vec<LockGuard<'_>> = Vec::with_capacity(selected.len());
    for sid in &selected {
        let Some(helper) = helpers.get(sid) else {
            // No live helper for a selected slot: the live state cannot be
            // verified — fail closed, refuse the Successful finalization.
            return Ok(FinalizeOutcome::Refused {
                reason: "state diverged",
                slot: (*sid).clone(),
            });
        };
        match helper.acquire_lock_guard(op_id.as_str()) {
            Ok(guard) => guards.push(guard),
            Err(_) => {
                // The lock is transiently held elsewhere: leave the attempt
                // PENDING for a later retry (fail closed — never finalize
                // without the locks).
                return Ok(FinalizeOutcome::Pending);
            }
        }
    }

    // 2. THE LOCK-VERIFIED RE-OBSERVATION (pass 1, before the markers):
    //    re-observe EVERY selected slot's live assignment under the locks
    //    and require the COMPLETE GenerationRef to exactly equal the frozen
    //    desired assignment; any divergence REFUSES the finalization. The
    //    re-observation RETURNS the observed live GenerationRefs (the
    //    values read under the locks) — pass 2's observed values feed the
    //    rollback construction below.
    match verify_selected_locked(helpers, attempt)? {
        LockedObservation::Diverged(slot) => {
            return Ok(FinalizeOutcome::Refused {
                reason: "state diverged",
                slot,
            });
        }
        LockedObservation::Verified(_) => {}
    }

    // 3. WRITE THE COMMIT MARKERS under the locks (already-present markers
    //    are a byte-for-byte idempotent no-op). A conflicting existing
    //    marker is a PERMANENT condition: refuse — the caller finalizes the
    //    attempt `Degraded` rather than stranding it pending forever.
    let slot_ids: Vec<String> = attempt
        .slots
        .keys()
        .map(|s| s.as_str().to_string())
        .collect();
    for sid in &selected {
        let helper = &helpers[*sid];
        let slot = &attempt.slots[*sid];
        match helper.write_commit_marker(
            attempt.deployment_id.as_str(),
            slot.desired.generation.as_str(),
            &slot_ids,
            Some(attempt.target.as_str()),
        ) {
            Err(Error::Integrity(_)) => {
                return Ok(FinalizeOutcome::Refused {
                    reason: "marker integrity conflict",
                    slot: (*sid).clone(),
                });
            }
            Err(_) => {
                // Marker not durable yet: leave the attempt pending for a
                // later retry.
                return Ok(FinalizeOutcome::Pending);
            }
            Ok(_) => {}
        }
    }

    // 4. THE FINAL LOCK-VERIFIED RE-OBSERVATION, IMMEDIATELY BEFORE THE
    //    TERMINAL APPEND: a swap injected at ANY boundary — before the
    //    status read, between the status and assignment reads, BETWEEN
    //    MARKER WRITES, or right before the terminal append — is caught
    //    here (and by pass 1), so the terminal is never appended for a
    //    diverged attempt. This pass's OBSERVED GenerationRefs are the
    //    VERIFIED LIVE VALUES the rollback payload is built from (the
    //    values read under the locks and proved equal to the frozen desired
    //    — never the engine's earlier observation records).
    let observed = match verify_selected_locked(helpers, attempt)? {
        LockedObservation::Verified(observed) => observed,
        LockedObservation::Diverged(slot) => {
            return Ok(FinalizeOutcome::Refused {
                reason: "state diverged",
                slot,
            });
        }
    };

    // 5. BUILD THE ROLLBACK from the VERIFIED LIVE GenerationRefs (the
    //    values observed under the locks) — the STALE-ROLLBACK-SNAPSHOT
    //    FIX: the payload's selected entries are constructed EXCLUSIVELY
    //    from these observed values (the frozen desired is an equally-valid
    //    source — the verification proved the two EQUAL; the observed
    //    values are used because they are the values actually read under
    //    the locks), NEVER from the `actuals`/`outcomes` observation
    //    records (removed from this finalizer's inputs).
    //
    //    THE ONE PRIVATE VALIDATED MAP (the unreadable-terminal fix): the
    //    observed GenerationRefs and the intent's FROZEN bindings are FIRST
    //    merged into a SINGLE map (`SlotId -> BoundGeneration` — each
    //    selected slot's verified generation PAIRED with its physical
    //    binding), and `build_rollback` consumes that one map — the
    //    rollback's `slots` and `bindings` wire fields are filled from the
    //    SAME iteration, so there are NO parallel maps to drift (a slot
    //    present in one but not the other — MISSING / EXTRA / RENAMED
    //    bindings — could otherwise produce an appended-but-unreadable
    //    terminal). The MERGE itself is the validation (fail closed): a
    //    selected slot with NO binding, a binding keyed under a DIFFERENT
    //    slot, or an EXTRA binding for a non-selected slot is a
    //    CONSTRUCTION ERROR — the finalization refuses (an `Err`), never
    //    appends a broken terminal. `build_rollback` is FALLIBLE too: it
    //    verifies its own result (slots key set == bindings key set, every
    //    ref names its own slot) before returning.
    let verified: BTreeMap<SlotId, BoundGeneration> = observed
        .into_iter()
        .map(|(sid, generation)| {
            let binding = bindings.get(&sid).cloned().ok_or_else(|| {
                Error::integrity(format!(
                    "finalize {}: the frozen-binding intent carries NO physical binding for selected slot '{sid}' — every selected slot's verified generation must be paired with its physical binding in ONE map (a missing binding cannot produce a consistent rollback payload; refusing to append a terminal the strict reader would reject)",
                    attempt.deployment_id
                ))
            })?;
            Ok((sid, BoundGeneration { generation, binding }))
        })
        .collect::<Result<BTreeMap<SlotId, BoundGeneration>>>()?;
    // THE MERGE'S EXACT-KEY VALIDATION (fail closed): the input bindings
    // must key EXACTLY the selected slots — an EXTRA binding (a slot this
    // attempt never deployed) or a RENAMED key (the same slot under a
    // different id) is a divergent construction input, refused here the
    // same way the strict reader refuses a binding for a non-slotted
    // generation (never silently dropped, never written).
    let selected_keys: BTreeSet<SlotId> = verified.keys().cloned().collect();
    let binding_keys: BTreeSet<SlotId> = bindings.keys().cloned().collect();
    if selected_keys != binding_keys {
        let missing: Vec<&SlotId> = selected_keys.difference(&binding_keys).collect();
        let extra: Vec<&SlotId> = binding_keys.difference(&selected_keys).collect();
        return Err(Error::integrity(format!(
            "finalize {}: the frozen-binding intent diverges from the selected slots — missing bindings for {missing:?}; extra bindings for {extra:?} (the rollback payload must pair EXACTLY the selected slots' verified generations with their physical bindings in ONE map)",
            attempt.deployment_id
        )));
    }
    let rollback = build_rollback(&verified, base.as_ref(), &current_slot_ids)?;
    // THE WRITER'S EQUALITY (fail closed): the rollback's key set must
    // EXACTLY equal the frozen full membership (`attempt.full_membership()`)
    // — the read path rejects a mismatch (rollback slots ==
    // full_membership), so the writer must produce equality. By construction
    // the overlay covers exactly the frozen full slots; this check pins the
    // invariant at the WRITER so a drift surfaces as a clear error here
    // rather than as a ledger that can never be read again.
    let rollback_keys: BTreeSet<SlotId> = rollback.slots.keys().cloned().collect();
    let current: BTreeSet<SlotId> = current_slot_ids.iter().cloned().collect();
    if rollback_keys != current {
        return Err(Error::integrity(format!(
            "finalize {}: the rollback snapshot covers slots {rollback_keys:?} but the attempt's frozen full membership is {current:?} — the complete snapshot must cover exactly the frozen full slots (unselected slots are carried forward from the base; slots outside the plan-time membership are omitted)",
            attempt.deployment_id
        )));
    }
    // THE PRE-APPEND GUARD (fail closed): every selected slot's constructed
    // rollback entry must EXACTLY equal the frozen desired assignment (the
    // complete GenerationRef equality: generation AND artifact). The
    // verification above proved the observed values equal the desired ones,
    // so this guard can only fire on an internal construction bug — a
    // mismatched payload ABORTS (integrity error), the terminal is NEVER
    // appended for a rollback that does not reproduce the verified state.
    verify_rollback_matches_desired(&attempt.deployment_id, &rollback, attempt)?;

    // 6. APPEND THE TERMINAL while still holding the locks (the ONLY
    //    commit of the finalize); a failure propagates as an `Err` — the
    //    caller aborts and the next push replays the whole finalize. The
    //    guards drop after this line, releasing every lock.
    let terminal = LedgerTerminal {
        recorded_at: crate::remote::helper::now_rfc3339(),
        // The Successful disposition ALWAYS carries the complete rollback
        // payload (the truth table is structural in the domain — the
        // rollback is the single source of truth for each slot's
        // generation/artifact facts) AND THE ACTIVATED SLOT-ID SET (the
        // slots this attempt actually deployed — DERIVED FROM THE INTENT's
        // selected slot set; the per-slot facts are DERIVED from the
        // rollback, never stored/trusted separately) AND THE PERSISTED
        // FULL MEMBERSHIP = the intent's FROZEN FULL MEMBERSHIP (the
        // complete target membership at plan time, never the live
        // configuration) — the record PROVES the membership equations
        // (activated == selected, rollback == full, selected ⊆ full,
        // full-push selected == full) AND REPRODUCES the intent's frozen
        // values (the read's intent-binding legs refuse a divergence).
        disposition: TerminalDisposition::Successful {
            rollback,
            // SUCCESS IS THE ACTIVATED SLOT-ID SET — DERIVED FROM THE
            // INTENT: the selected slot set of the attempt (every selected
            // slot is activated; the per-slot generation/artifact facts
            // are DERIVED from the rollback — the single source of truth).
            activated: selected.iter().map(|sid| (*sid).clone()).collect(),
            full_membership: current,
        },
        reason: Some(reason.to_string()),
    };
    store.append_terminal(attempt.target.as_str(), &attempt.deployment_id, &terminal)?;
    Ok(FinalizeOutcome::Finalized)
}

/// The FINALIZATION SETTINGS (the caller-policy bundle, LAST argument per
/// the data-then-settings convention): the terminal event's `reason` label
/// and the `op_id` under which the selected-slot mutation locks are
/// acquired (and released on guard drop).
pub struct FinalizeSettings<'a> {
    /// The terminal event's reason label (e.g. "push completed" /
    /// "recovery finalized").
    pub reason: &'a str,
    /// The operation identity the selected-slot mutation locks are acquired
    /// under — the deterministic-order lock hold keyed by this operation.
    pub op_id: &'a OperationId,
}

/// The outcome of the ONE lock-verified finalization
/// ([`finalize_successful_locked`]): either the `Successful` terminal was
/// appended, or the finalization did not complete — the caller acts on the
/// outcome (a `Refused` attempt ends `Degraded`, a `Pending` attempt stays
/// intent-only for a later retry).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FinalizeOutcome {
    /// The `Successful` terminal was appended under the locks; every
    /// selected slot's live `GenerationRef` equaled the frozen desired
    /// assignment at both verification passes, the markers are durable, and
    /// the locks have been released.
    Finalized,
    /// A TRANSIENT condition (a slot lock held elsewhere, a live status /
    /// assignment read failure, a marker transport write failure): no
    /// terminal is appended and the attempt stays PENDING (intent-only) for
    /// a later retry — never finalized `Successful` on unverified state.
    Pending,
    /// A PERMANENT refusal: a selected slot's live `GenerationRef` diverged
    /// from the frozen desired assignment (`reason` "state diverged") or a
    /// conflicting commit marker already exists (`reason` "marker integrity
    /// conflict"). No terminal is appended; the caller finalizes the attempt
    /// `Degraded` (terminal only, no rollback) — NEVER `Successful`.
    Refused {
        reason: &'static str,
        /// The slot whose live state (or marker) refused the finalization.
        slot: SlotId,
    },
}

/// The result of one lock-verified re-observation pass
/// ([`verify_selected_locked`]): every selected slot's live `GenerationRef`
/// was re-observed under the mutation locks and REQUIRED to EXACTLY EQUAL
/// the frozen desired assignment — the pass either VERIFIES the whole
/// selected set (returning the OBSERVED live `GenerationRef` per selected
/// slot, the values read under the locks) or reports the first DIVERGED
/// slot (the refusal the caller finalizes `Degraded`).
enum LockedObservation {
    /// Every selected slot's live `GenerationRef` exactly equals the frozen
    /// desired assignment; the map is the OBSERVED LIVE `GenerationRef` per
    /// selected slot — the values actually read under the locks (the
    /// successful terminal's rollback entries are built EXCLUSIVELY from
    /// these, never from the engine's earlier observation records).
    Verified(BTreeMap<SlotId, GenerationRef>),
    /// The first selected slot whose live `GenerationRef` diverged from the
    /// frozen desired assignment — the caller refuses the finalization
    /// (the attempt ends `Degraded`, never `Successful`).
    Diverged(SlotId),
}

/// Re-observe EVERY selected slot's LIVE assignment while the mutation
/// locks are held and require the COMPLETE `GenerationRef` — the live
/// generation AND its artifact (release/variant/tree) — to EXACTLY EQUAL
/// the FROZEN DESIRED assignment (`attempt.slots[sid].desired`). Each slot
/// is read as a status read, the live generation's assignment record, and a
/// SECOND status read: the second read verifies the generation did not
/// change while the assignment was read, so a swap between the two reads is
/// never missed. Returns the OBSERVED live `GenerationRef` per selected
/// slot alongside the verdict ([`LockedObservation::Verified`] = every
/// selected slot's live `GenerationRef` matches the frozen desired, with
/// the observed values the terminal's rollback is built from;
/// [`LockedObservation::Diverged`] = the first diverged slot); a transient
/// read failure is an `Err` (the caller leaves the attempt pending).
fn verify_selected_locked(
    helpers: &HashMap<SlotId, RemoteHelper>,
    attempt: &DeploymentIntent,
) -> Result<LockedObservation> {
    let mut observed: BTreeMap<SlotId, GenerationRef> = BTreeMap::new();
    let mut selected: Vec<&SlotId> = attempt.slots.keys().collect();
    selected.sort();
    for sid in selected {
        let slot = &attempt.slots[sid];
        let Some(helper) = helpers.get(sid) else {
            // No live helper for a selected slot: cannot verify — fail
            // closed (the live state is not provably the frozen desired).
            return Ok(LockedObservation::Diverged(sid.clone()));
        };
        let st1 = helper.status()?;
        let Some(live_gen) = st1.current_generation else {
            // No `current` at all: the slot's live state diverged from the
            // frozen desired (this attempt deployed a generation).
            return Ok(LockedObservation::Diverged(sid.clone()));
        };
        let asn = helper.read_assignment(live_gen.as_str())?;
        let st2 = helper.status()?;
        if st2.current_generation.as_ref() != Some(&live_gen)
            || live_gen != slot.desired.generation
            || asn.artifact != slot.desired.artifact
        {
            return Ok(LockedObservation::Diverged(sid.clone()));
        }
        // Record the OBSERVED LIVE GenerationRef (the value read under the
        // locks — the terminal's rollback entries are built from these).
        observed.insert(
            sid.clone(),
            GenerationRef {
                generation: live_gen,
                assignment: PlacementSlotAssignment {
                    placement_slot: sid.clone(),
                    artifact: asn.artifact,
                },
            },
        );
    }
    Ok(LockedObservation::Verified(observed))
}

/// THE PRE-APPEND GUARD (fail closed): every selected slot's constructed
/// rollback entry must EXACTLY EQUAL the frozen desired assignment — the
/// COMPLETE `GenerationRef` equality (generation AND artifact:
/// release/variant/tree). The lock-verified re-observation proved the
/// observed values equal the desired ones, so this guard can only fire on
/// an internal construction bug; a mismatch ABORTS the finalization with an
/// integrity error — the terminal is NEVER appended for a rollback payload
/// that does not reproduce the verified desired state (a stale or diverged
/// snapshot must never be persisted).
fn verify_rollback_matches_desired(
    deployment_id: &DeploymentId,
    rollback: &LedgerRollback,
    attempt: &DeploymentIntent,
) -> Result<()> {
    for (sid, slot) in attempt.slots.iter() {
        let rb = rollback.slots.get(sid).ok_or_else(|| {
            Error::integrity(format!(
                "finalize {deployment_id}: the rollback snapshot has no entry for selected slot '{sid}' — every selected slot's rollback entry must exactly equal the frozen desired assignment"
            ))
        })?;
        if rb.generation != slot.desired.generation
            || rb.assignment.artifact != slot.desired.artifact
        {
            return Err(Error::integrity(format!(
                "finalize {deployment_id}: the rollback entry for selected slot '{sid}' ({:?}, {:?}) does not exactly equal the frozen desired assignment ({:?}, {:?}) — the rollback must reproduce exactly the verified desired state (generation AND artifact); refusing to append a stale or diverged snapshot",
                rb.generation,
                rb.assignment.artifact,
                slot.desired.generation,
                slot.desired.artifact
            )));
        }
    }
    Ok(())
}

// ---- append / read line kinds ----
// The ledger's append/read SEMANTIC types: the two physical line kinds
// (the WIRE enum the append-only JSONL stream carries). The MERGED entry
// ([`LedgerEntry`] — the durable intent + optional terminal event, with the
// entry owning the deployment identity) lives in [`crate::ledger::records`]
// and is re-exported here for the append/read path.
//
// A target's ENTIRE deployment history lives in ONE ordered, append-only
// JSONL file: `targets/<target>/ledger.jsonl`. There are exactly two
// physical line kinds ([`LedgerLine`]):
//
// * [`LedgerLine::Intent`] — the DURABLE INTENT of one deployment
//   ([`LedgerIntentWire`] → verified [`DeploymentIntent`]): deployment_id,
//   target, behavior digest, membership, and the `desired` / `pre_push`
//   per-slot maps. It is appended BEFORE any remote mutation (the
//   append-attempt contract) and never edited. It carries NO status, NO
//   outcomes, and NO rollback state.
// * [`LedgerLine::Terminal`] — the TERMINAL EVENT of one deployment
//   ([`LedgerTerminalWire`] → verified [`LedgerTerminal`]): the status and
//   the DISPOSITION. Appended once, after the mutation loop, and never
//   edited.
//
// CRASH-ATOMIC APPENDS: every ledger write is a SINGLE atomic line append
// (one durable line, no partial state). An entry WITHOUT a terminal is the
// CURRENT/INCOMPLETE state (the deployment is in flight or crashed
// mid-finalization): its status is `PendingCommit`-like (recoverable), and
// the next push reconciles it ([`crate::ledger::recovery`]).
//
// DEPLOYMENT-ID KEYING: every entry is keyed by its
// [`crate::identity::DeploymentId`] — the ledger is the deployment's full
// history record, and appends are idempotent by id (a duplicate intent or
// terminal for the same deployment is refused by the store's writer).
//
// The PHYSICAL I/O (append_intent / append_terminal / read_ledger, the
// atomic line appends, the wire-version gate on read) lives in
// [`crate::store::local::LocalStore`] — infrastructure, NOT ledger
// semantics. This module owns only the semantic TYPES the append/read path
// carries; the wire shapes and their VERIFYING CONVERSIONS live with the
// records in [`crate::ledger::records`].
/// ONE physical line of a target's deployment ledger — the WIRE enum: the
/// raw serde shapes ([`LedgerIntentWire`], [`LedgerTerminalWire`]) exactly as
/// the append-only JSONL stream carries them. The ledger is append-only: each
/// deployment contributes at most one [`LedgerLine::Intent`] (written BEFORE
/// any remote mutation) and at most one [`LedgerLine::Terminal`] (appended
/// when the deployment completes). The line ORDER is the history order.
/// [`crate::store::local::LocalStore::read_ledger`] parses these wire lines,
/// runs the VERIFYING CONVERSION (refusing disagreeing records), and merges
/// the validated domain records into [`LedgerEntry`]s keyed by deployment id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LedgerLine {
    /// The durable intent of one deployment, written before any remote
    /// mutation (the append-attempt contract).
    Intent(LedgerIntentWire),
    /// The terminal event of one deployment, appended after the mutation
    /// loop.
    Terminal(LedgerTerminalWire),
}

// The MERGED deployment entry — re-exported above from its home in
// [`crate::ledger::records`] so the append/read path (`LedgerLine` consumers,
// [`crate::store::local::LocalStore::read_ledger`]) keeps one path to the
// entry type.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{
        ArtifactRef, ServerId, SlotId, TargetName, VariantName, test_deployment_id,
        test_generation_id, test_tree_digest,
    };
    use crate::ledger::records::{DeploymentIntent, DesiredGeneration, IntentSlot};
    use crate::ledger::records::{DeploymentStatus, NonEmptySlotTable};
    use std::collections::BTreeMap;

    /// A minimal but VALID intent for the target (EXACT key-set equality:
    /// `slot_ids == desired.keys() == pre_push.keys()`).
    fn intent(dep: &str) -> DeploymentIntent {
        let p1 = SlotId::new("p1".to_string());
        // ONE slot table (the membership + desired/pre-push entries).
        let slots = BTreeMap::from([(
            p1.clone(),
            IntentSlot {
                desired: DesiredGeneration {
                    generation: test_generation_id("gen-1"),
                    artifact: ArtifactRef {
                        release: crate::identity::test_release_id("rel-1"),
                        variant: VariantName::new("standard".to_string()),
                        tree: test_tree_digest("tree-1"),
                    },
                },
                pre_push: None,
                // The FROZEN plan-time physical binding (schema v6): the
                // fixture's single slot is bound to server s1 at
                // /srv/deploy/p1 (matching the rollback's binding the test
                // finalizes).
                binding: crate::ledger::PhysicalBinding {
                    server: ServerId::new("s1".to_string()),
                    deploy_dir: "/srv/deploy/p1".to_string(),
                },
            },
        )]);
        DeploymentIntent {
            deployment_id: test_deployment_id(dep),
            target: TargetName::new("production".to_string()),
            group: None,
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            slots: NonEmptySlotTable::build(slots)
                .expect("a fixture intent always has at least one slot"),
            full_membership: BTreeSet::from([SlotId::new("p1".to_string())]),
        }
    }

    /// Finalization appends the terminal event exactly once (replay-safe by
    /// deployment id): a repeated finalize for the same attempt is a no-op.
    /// The finalize is LOCK-VERIFIED, so the fixture mints the attempt's
    /// desired generation on a live remote and points `current` at it (the
    /// live `GenerationRef` == the frozen desired) — the shared operation
    /// then acquires the slot lock, re-observes the matching live state,
    /// writes the marker, and appends the terminal under the lock.
    #[test]
    fn finalize_is_idempotent_by_deployment_id() {
        use crate::identity::OperationId;
        use crate::remote::helper::{ExpectedCurrent, RemoteHelper};
        use crate::remote::transport::{LocalTransport, Remote};

        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let target = TargetName::new("production".to_string());
        let bindings: BTreeMap<SlotId, PhysicalBinding> = BTreeMap::from([(
            SlotId::new("p1"),
            PhysicalBinding {
                server: ServerId::new("server-01"),
                deploy_dir: "/srv/deploy/p1".to_string(),
            },
        )]);
        let attempt = intent("deploy-idempotent");
        store.append_intent(target.as_str(), &attempt).unwrap();

        // The LOCK-VERIFIED finalize re-observes the slot's LIVE state under
        // the mutation lock, so the fixture mints the attempt's desired
        // generation on a live remote (a valid `generations/<gen>/root`
        // chain + the tree object) and points `current` at it: the live
        // `GenerationRef` EXACTLY equals the frozen desired assignment.
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), tmp.path().join("remote"))
                .unwrap();
        let helper = RemoteHelper::new(&remote);
        remote
            .create_dir_all(&crate::remote::layout::tree_root(
                test_tree_digest("tree-1").as_str(),
            ))
            .unwrap();
        helper
            .create_generation(
                "op-seed",
                &crate::remote::helper::GenerationAssignment {
                    deployment_id: attempt.deployment_id.clone(),
                    generation_id: test_generation_id("gen-1"),
                    artifact: ArtifactRef {
                        release: crate::identity::test_release_id("rel-1"),
                        variant: VariantName::new("standard".to_string()),
                        tree: test_tree_digest("tree-1"),
                    },
                    behavior_sha256: "sha256-aa".to_string(),
                    prior_generation: None,
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                    target: Some(target.clone()),
                },
            )
            .unwrap();
        helper
            .swap_current(
                &ExpectedCurrent::Absent,
                test_generation_id("gen-1").as_str(),
                "op-seed",
            )
            .unwrap();
        let helpers = HashMap::from([(SlotId::new("p1"), helper)]);
        let settings = FinalizeSettings {
            reason: "push completed",
            op_id: &OperationId::new("op-finalize-test".to_string()),
        };

        assert_eq!(
            finalize_successful_locked(&store, &attempt, &helpers, &bindings, &settings).unwrap(),
            FinalizeOutcome::Finalized,
            "the live GenerationRef equals the frozen desired, so the lock-verified finalize appends the terminal"
        );
        let entries = store.read_ledger(target.as_str()).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].terminal.is_some());
        assert_eq!(
            store
                .latest_status(test_deployment_id("deploy-idempotent").as_str())
                .unwrap(),
            Some(DeploymentStatus::Successful)
        );

        // Repeated finalize with the same deployment ID is a no-op: same
        // key, no duplicate terminal.
        assert_eq!(
            finalize_successful_locked(&store, &attempt, &helpers, &bindings, &settings).unwrap(),
            FinalizeOutcome::Finalized,
            "a replay for a finalized deployment id is a no-op"
        );
        let entries = store.read_ledger(target.as_str()).unwrap();
        assert_eq!(entries.len(), 1, "no duplicate terminal event");
    }

    /// THE STALE-ROLLBACK-SNAPSHOT REGRESSION TEST: the engine's earlier
    /// observation records (the old `actuals`/`outcomes` finalizer inputs)
    /// DIVERGE from the frozen desired while the LIVE state — what the
    /// lock-verified finalizer re-observes under the locks — EQUALS the
    /// frozen desired (a concurrent controller changed the remote between
    /// the engine's observation and this finalization). The finalization
    /// MUST succeed and the rollback payload MUST equal the frozen desired
    /// (the verified live values), NEVER the stale observed values. Under
    /// the pre-fix code the rollback was built from the passed-in
    /// observation records, so the stale values LEAKED into the persisted
    /// snapshot (this test then fails); the fix REMOVED those inputs from
    /// the successful finalizer, so the payload is constructed exclusively
    /// from the verified live `GenerationRef`s, and the pre-append guard
    /// ([`verify_rollback_matches_desired`]) pins `rollback[selected] ==
    /// intent.desired` (generation AND artifact) before the append.
    #[test]
    fn finalize_payload_ignores_stale_observed_values() {
        use crate::identity::OperationId;
        use crate::remote::helper::{ExpectedCurrent, RemoteHelper};
        use crate::remote::transport::{LocalTransport, Remote};

        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let target = TargetName::new("production".to_string());
        let attempt = intent("deploy-stale-observed");
        store.append_intent(target.as_str(), &attempt).unwrap();
        // The STALE OBSERVED VALUES: a DIVERGED generation AND artifact the
        // engine could have recorded for the slot BEFORE a concurrent
        // controller changed the remote — under the old code these are the
        // values the rollback payload was built from (a stale rollback
        // snapshot persisted even though the verification passed). They are
        // constructed here to pin the bug scenario; the fix means they are
        // NEVER consulted (they cannot even be passed to the finalizer).
        let stale_generation = test_generation_id("gen-stale");
        let stale_artifact = ArtifactRef {
            release: crate::identity::test_release_id("rel-stale"),
            variant: VariantName::new("standard".to_string()),
            tree: test_tree_digest("tree-stale"),
        };
        let desired = &attempt.slots[&SlotId::new("p1")].desired;
        assert_ne!(
            stale_generation, desired.generation,
            "the stale fixture must diverge from the frozen desired generation"
        );
        assert_ne!(
            stale_artifact, desired.artifact,
            "the stale fixture must diverge from the frozen desired artifact"
        );

        // The LIVE state equals the frozen desired: mint the desired
        // generation on a live remote and point `current` at it — the
        // lock-verified re-observation then reads EXACTLY the frozen
        // desired and the finalization succeeds.
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), tmp.path().join("remote"))
                .unwrap();
        let helper = RemoteHelper::new(&remote);
        remote
            .create_dir_all(&crate::remote::layout::tree_root(
                test_tree_digest("tree-1").as_str(),
            ))
            .unwrap();
        helper
            .create_generation(
                "op-seed",
                &crate::remote::helper::GenerationAssignment {
                    deployment_id: attempt.deployment_id.clone(),
                    generation_id: test_generation_id("gen-1"),
                    artifact: ArtifactRef {
                        release: crate::identity::test_release_id("rel-1"),
                        variant: VariantName::new("standard".to_string()),
                        tree: test_tree_digest("tree-1"),
                    },
                    behavior_sha256: "sha256-aa".to_string(),
                    prior_generation: None,
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                    target: Some(target.clone()),
                },
            )
            .unwrap();
        helper
            .swap_current(
                &ExpectedCurrent::Absent,
                test_generation_id("gen-1").as_str(),
                "op-seed",
            )
            .unwrap();
        let helpers = HashMap::from([(SlotId::new("p1"), helper)]);
        let bindings: BTreeMap<SlotId, PhysicalBinding> = BTreeMap::from([(
            SlotId::new("p1"),
            PhysicalBinding {
                server: ServerId::new("server-01"),
                deploy_dir: "/srv/deploy/p1".to_string(),
            },
        )]);
        let settings = FinalizeSettings {
            reason: "push completed",
            op_id: &OperationId::new("op-stale-test".to_string()),
        };

        assert_eq!(
            finalize_successful_locked(&store, &attempt, &helpers, &bindings, &settings).unwrap(),
            FinalizeOutcome::Finalized,
            "the live state equals the frozen desired, so the finalization succeeds — the stale observed values are never consulted"
        );
        // THE ROLLBACK PAYLOAD EQUALS THE FROZEN DESIRED (the verified
        // live values) — generation AND artifact — NEVER the stale observed
        // values. The ACTIVATED set is the INTENT's selected slot set.
        let entries = store.read_ledger(target.as_str()).unwrap();
        let terminal = entries[0].terminal.as_ref().expect("terminal appended");
        let TerminalDisposition::Successful {
            rollback,
            activated,
            ..
        } = &terminal.disposition
        else {
            panic!("the finalization must append a Successful terminal");
        };
        assert_eq!(
            activated,
            &BTreeSet::from([SlotId::new("p1")]),
            "the activated slot-id set is derived from the intent's selected slots"
        );
        let rb = rollback
            .slots
            .get(&SlotId::new("p1"))
            .expect("the rollback covers the selected slot");
        assert_eq!(
            rb.generation, desired.generation,
            "the rollback generation equals the frozen desired (the verified live value), never the stale observation"
        );
        assert_eq!(
            rb.assignment.artifact, desired.artifact,
            "the rollback artifact equals the frozen desired (the verified live value), never the stale observation"
        );
    }

    /// THE PRE-APPEND GUARD, unit-tested in isolation: a deliberately-
    /// DIVERGED rollback payload is REFUSED — every selected slot's
    /// constructed rollback entry must EXACTLY equal the frozen desired
    /// assignment (the complete `GenerationRef` equality: generation AND
    /// artifact); a mismatch aborts with an integrity error and the
    /// terminal is NEVER appended. The matching payload (the healthy case)
    /// passes.
    #[test]
    fn rollback_desired_guard_refuses_diverged_payload() {
        let attempt = intent("deploy-guard");
        let sid = SlotId::new("p1".to_string());
        let desired = &attempt.slots[&sid].desired;
        // The MATCHING rollback: the selected entry reproduces the frozen
        // desired assignment exactly (generation AND artifact).
        let matching = crate::ledger::LedgerRollback {
            slots: BTreeMap::from([(
                sid.clone(),
                GenerationRef {
                    generation: desired.generation.clone(),
                    assignment: PlacementSlotAssignment {
                        placement_slot: sid.clone(),
                        artifact: desired.artifact.clone(),
                    },
                },
            )]),
            bindings: BTreeMap::new(),
        };
        verify_rollback_matches_desired(&attempt.deployment_id, &matching, &attempt)
            .expect("the matching rollback passes the pre-append guard");
        // A DIVERGED rollback: the selected entry carries a DIFFERENT
        // generation AND a different artifact — refused before any append.
        let diverged = crate::ledger::LedgerRollback {
            slots: BTreeMap::from([(
                sid.clone(),
                GenerationRef {
                    generation: test_generation_id("gen-stale"),
                    assignment: PlacementSlotAssignment {
                        placement_slot: sid.clone(),
                        artifact: ArtifactRef {
                            release: crate::identity::test_release_id("rel-stale"),
                            variant: VariantName::new("standard".to_string()),
                            tree: test_tree_digest("tree-stale"),
                        },
                    },
                },
            )]),
            bindings: BTreeMap::new(),
        };
        let err = verify_rollback_matches_desired(&attempt.deployment_id, &diverged, &attempt)
            .expect_err("a diverged rollback entry must refuse the finalization before any append");
        assert!(
            err.to_string().contains("does not exactly equal"),
            "the refusal names the divergence from the frozen desired, got: {err}"
        );
    }
}
