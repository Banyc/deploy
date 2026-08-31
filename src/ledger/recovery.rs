//! Pending-attempt reconciliation (feature area A2: Ledger semantics — the
//! RECOVERY / RECONCILIATION of intent-only ledger entries).
//!
//! Recovery is a CALLER of the one kernel transition, not a second
//! authority: it completes a recorded attempt `Successful` ONLY through the
//! same replay-safe finalizer as the main success path, which appends
//! through the PURE STATE MACHINE's one-parent gate (no recovery bypass). A
//! recovered attempt whose parent is no longer the successful head — a
//! later deployment already succeeded on that parent — is finalized through
//! the SAME terminal decision as normal execution
//! ([`crate::kernel::transition::decide_terminal`], fed the backend-re-read
//! per-slot EVIDENCE): a non-empty `Degraded` terminal with the stale-plan
//! source as its reason when at least one slot's delta is
//! `Desired`/`Diverged`/`Unknown`, `FailedRolledBack` when every slot is
//! back at its pre-push state — never `Successful`: it can never become the
//! head or overlay a newer head's inherited state.
//!
//! # Degraded terminals record BACKEND-OBSERVED facts, never plan desires
//!
//! The per-slot outcomes of a recovery-degraded terminal are built from
//! per-slot EVIDENCE (`RecoverySlotEvidence`) collected — under the
//! selected slots' mutation locks — by RE-READING each slot's live state
//! (status + assignment) from its remote BEFORE the terminal is decided
//! (`collect_recovery_evidence` / `observe_recovery_slot`). A `Known`
//! observation appears ONLY when a successful backend read confirmed that
//! generation; the intent's `resulting_snapshot` is a PLAN TIME DESIRED
//! state, so the degraded terminal NEVER converts it into an observed fact
//! (the plan may create desired facts, but only a successful backend read
//! may create observed facts — a later rollback / `remaining_changes` /
//! reference read must never treat a fabrication as live-server truth).
//! `KnownAbsent` appears ONLY from a successful status read showing no
//! `current`; `Unknown` preserves the read error. The collection runs ONLY
//! on the degraded paths (membership mismatch, binding drift, finalizer
//! `Refused`) — the `Successful` path keeps the finalizer's own
//! lock-verified acquisition — and ONLY a TRANSIENT lock-acquisition
//! failure during the collection yields `RecoveryOutcome::StillPending`
//! (a truthful terminal cannot be built without the backend read).

use crate::config::ProjectConfig;
use crate::error::{Error, Result};
use crate::identity::{GenerationId, OperationId, SlotId};
use crate::kernel;
use crate::ledger::finalize::{FinalizeOutcome, FinalizeSettings, finalize_successful_locked};
use crate::ledger::records::{
    DeploymentIntent, LedgerTerminal, NonEmptySlotTable, Observation, ObservationError,
    ObservedGeneration, PhysicalBinding, SlotOutcome,
};
use crate::remote::helper::{HeldSlotLock, RemoteHelper};
use crate::store::local::ledger::TargetLedgerTxn;
use std::collections::{BTreeMap, HashMap, HashSet};

/// The per-attempt outcome of the recovery step — one pending attempt is
/// reconciled to EXACTLY one of these (under the strictly-linear model at
/// most ONE pending intent can exist at a time, so a call returns at most
/// one outcome). The preflight consumes it to decide whether the push may
/// plan a new intent: only [`Finalized`](RecoveryOutcome::Finalized) or
/// [`Degraded`](RecoveryOutcome::Degraded) release the push to continue;
/// [`StillPending`](RecoveryOutcome::StillPending) (the finalizer could not
/// finish right now — locks contended / live state not finalizable) makes
/// the push REFUSE (it can never plan a second intent on top of an
/// unresolved one, even for disjoint groups).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryOutcome {
    /// The pending attempt was finalized `Successful` by the shared
    /// replay-safe finalizer (its parent was still the successful head).
    Finalized,
    /// The pending attempt could not finalize on the live state (membership
    /// mismatch, binding drift, or a state-diverged / stale finalizer
    /// refusal) and was finalized `Degraded` — never stranded, never
    /// silently ignored, never `Successful`.
    Degraded,
    /// The finalizer could not finish RIGHT NOW (locks contended / live
    /// state not finalizable — a TRANSIENT non-finalization), or the
    /// degraded-path EVIDENCE collection could not acquire a selected
    /// slot's mutation lock (a truthful degraded terminal cannot be built
    /// without the backend read): the attempt remains intent-only
    /// (pending). The push REFUSES to plan a new intent on top.
    StillPending,
}

/// Reconcile the target's pending (intent-only) attempts — at most ONE
/// exists under the strictly-linear model — reporting the per-attempt
/// outcome (`None` when no pending attempt exists). Recovery is a CALLER of
/// the one kernel state machine, not a second authority: it completes a
/// recorded attempt `Successful` ONLY through the same replay-safe
/// finalizer as the main success path. A recovered attempt that can no
/// longer finalize `Successful` on the live state (membership mismatch,
/// binding drift, or a drifted head — the finalizer's `Refused`) is
/// finalized through the SAME terminal decision as normal execution
/// ([`crate::kernel::transition::decide_terminal`] — fed the per-slot
/// EVIDENCE [`RecoverySlotEvidence`] collected under the selected slots'
/// mutation locks on the degraded path only, so the terminal records
/// OBSERVED facts, never the plan's desired snapshot): a non-empty
/// `Degraded` terminal (at least one `Desired`/`Diverged`/`Unknown` delta)
/// or `FailedRolledBack` (every slot back at its pre-push state — the
/// exact-pre-push state NEVER settles `Degraded`, the review's fix) with
/// the refusal source as its reason, never `Successful`: it can never
/// become the head or overlay a newer head's inherited state. ONLY a TRANSIENT
/// non-finalization (the finalizer's [`FinalizeOutcome::Pending`], or a
/// lock-acquisition failure during the degraded-path evidence collection
/// — the new StillPending trigger, since a truthful terminal cannot be
/// built without the backend read) yields [`RecoveryOutcome::StillPending`]
/// — the caller (preflight) then REFUSES the push: a push that cannot
/// finish the previous pending attempt never plans a second intent on top.
pub(crate) fn reconcile_pending_commits(
    txn: &mut TargetLedgerTxn<'_>,
    config: &ProjectConfig,
    op_id: &OperationId,
    helpers: &HashMap<SlotId, RemoteHelper>,
    receiver_uuids: &BTreeMap<SlotId, Option<crate::identity::ReceiverUuid>>,
) -> Result<Option<RecoveryOutcome>> {
    let mut pending: Vec<DeploymentIntent> = Vec::new();
    for entry in txn.state().entries() {
        if entry.terminal.is_none() {
            pending.push(entry.intent.clone());
        }
    }
    if pending.is_empty() {
        return Ok(None);
    }
    let target_name = txn.target();

    let members: HashSet<String> = config
        .target_slots(target_name)?
        .iter()
        .map(|(slot, _)| slot.id.clone())
        .collect();
    // The CURRENT configured bindings, with each slot's deploy_dir's
    // IMMUTABLE receiver UUID (read from the provisioned remote during
    // preflight) filled in — the PHYSICAL identity the binding-drift check
    // compares. A slot whose receiver is not yet readable (unprovisioned
    // deploy_dir) keeps its config-derived binding (unknown physical
    // identity).
    let live_bindings: BTreeMap<SlotId, PhysicalBinding> = config
        .target_slot_bindings(target_name)?
        .into_iter()
        .map(|(sid, b)| {
            let uuid = receiver_uuids.get(&sid).cloned().flatten();
            (
                sid,
                match uuid {
                    Some(u) => b.with_receiver_uuid(u),
                    None => b,
                },
            )
        })
        .collect();

    // At most ONE pending attempt exists under the strictly-linear model
    // (the store's read path refuses a second unresolved intent); the loop
    // stays to keep the oldest-first reconciliation order structural.
    let mut outcome: Option<RecoveryOutcome> = None;
    for attempt in pending {
        let membership_ok = attempt
            .selected_membership()
            .iter()
            .all(|sid| members.contains(sid.as_str()));
        if !membership_ok {
            // MEMBERSHIP MISMATCH (a selected slot is no longer a
            // configured member): gather the per-slot EVIDENCE — acquiring
            // the selected slots' mutation locks and re-reading each slot's
            // live state; a slot that is no longer a configured member has
            // no remote to read and records an `Unknown` evidence — then
            // finalize through the SHARED decision
            // ([`crate::kernel::transition::decide_terminal`]) with the
            // TRUTHFUL per-slot observations (the plan's frozen snapshot
            // is never converted into an observed fact). A lock-acquisition
            // failure -> `StillPending` (a truthful terminal cannot be
            // built without the backend read).
            let Some(evidence) = collect_recovery_evidence(
                &attempt,
                helpers,
                &live_bindings,
                op_id,
                config.application(),
            )?
            else {
                outcome = Some(RecoveryOutcome::StillPending);
                continue;
            };
            append_degraded(txn, &attempt, &evidence, "membership mismatch")?;
            outcome = Some(RecoveryOutcome::Degraded);
            continue;
        }

        let mut bindings_equal = true;
        let snapshot = attempt.resulting_snapshot();
        for sid in attempt.selected_membership() {
            let frozen_binding = snapshot.get(&sid).expect("selected in snapshot").binding();
            // THE PHYSICAL-IDENTITY COMPARISON: the deploy_dir's IMMUTABLE
            // receiver UUID is the physical identity — two ServerIds naming
            // the same physical host+dir share the receiver, and a slot
            // whose physical receiver changed (even under the same
            // ServerId/path) is a drift. A binding whose receiver is unknown
            // on either side falls back to the legacy `{server, deploy_dir}`
            // evidence.
            let equal = live_bindings
                .get(&sid)
                .is_some_and(|b| b.same_physical_location(frozen_binding));
            bindings_equal &= equal;
        }
        if !bindings_equal {
            // BINDING DRIFT (a selected slot's current configured binding !=
            // the intent's frozen binding): the binding check stays a
            // pre-finalizer check, but when it fails recovery acquires the
            // selected slots' guards, re-reads each slot's LIVE state, and
            let Some(evidence) = collect_recovery_evidence(
                &attempt,
                helpers,
                &live_bindings,
                op_id,
                config.application(),
            )?
            else {
                outcome = Some(RecoveryOutcome::StillPending);
                continue;
            };
            append_degraded(txn, &attempt, &evidence, "binding drift")?;
            outcome = Some(RecoveryOutcome::Degraded);
            continue;
        }

        // RECOVERY COMPLETES THE RECORDED ATTEMPT through the SAME
        // replay-safe finalizer as the main success path — with NO lineage
        // carve-out: the finalizer requires `intent.parent == current
        // successful head` (a drifted head is REFUSED and the attempt is
        // finalized through the SHARED decision below — it can never
        // overlay a newer head's inherited state on the logical history). A
        // TRANSIENT
        // non-finalization (locks contended / live state not finalizable
        // right now) reports [`RecoveryOutcome::StillPending`] — the
        // attempt stays intent-only and the push REFUSES to plan on top.
        match finalize_successful_locked(
            txn,
            &attempt,
            helpers,
            &FinalizeSettings {
                reason: "recovery finalized",
                op_id,
                application: config.application(),
            },
        )? {
            FinalizeOutcome::Finalized => {
                outcome = Some(RecoveryOutcome::Finalized);
            }
            FinalizeOutcome::Pending => {
                outcome = Some(RecoveryOutcome::StillPending);
            }
            FinalizeOutcome::Refused { reason, .. } => {
                // The finalizer ran and dropped its guards; recovery then
                // ACQUIRES the selected slots' guards, re-reads each slot's
                let Some(evidence) = collect_recovery_evidence(
                    &attempt,
                    helpers,
                    &live_bindings,
                    op_id,
                    config.application(),
                )?
                else {
                    outcome = Some(RecoveryOutcome::StillPending);
                    continue;
                };
                append_degraded(txn, &attempt, &evidence, reason.as_str())?;
                outcome = Some(RecoveryOutcome::Degraded);
            }
        }
    }
    Ok(outcome)
}

/// Append the RECOVERY TERMINAL of a recovered attempt whose live state no
/// longer admits `Successful`: one per-slot causal-agnostic
/// [`SlotOutcome::Indeterminate`] outcome per SELECTED slot (recovery never
/// claims a slot was `Restored`/compensated or `Skipped`/never-started
/// without transaction evidence). The outcome's OBSERVATION is copied from
/// the per-slot EVIDENCE ([`RecoverySlotEvidence`]) that
/// `reconcile_pending_commits` collected from the backends BEFORE deciding
/// the terminal; this function NEVER reads a generation from
/// `attempt.resulting_snapshot()` (the plan-time DESIRED state) to populate
/// an observation — a plan may create desired facts, but only a successful
/// BACKEND READ may create an OBSERVED fact, and a recovery terminal
/// records observed facts only.
///
/// THE DISPOSITION IS DECIDED BY THE ONE CLASSIFIER — the review's exact
/// fix: the evidence-built outcomes are handed to
/// [`crate::kernel::transition::decide_terminal`] — the SAME decision path
/// uninterrupted execution uses, so recovery and normal execution produce
/// the SAME terminal classification for the SAME evidence (never a direct
/// `DegradedTerminal::try_new` construction that could manufacture a
/// `Degraded` disposition for an exact-pre-push state). The decision
/// derives the disposition from the evidence's deltas (vs the attempt's
/// pre-push and DESIRED generations): EVERY slot `Unchanged` (the exact
/// pre-push state — e.g. a binding drift whose live generations all still
/// match pre-push, or a recovered attempt whose preflight-terminal append
/// failed before anything mutated) → `FailedRolledBack` — a Degraded
/// terminal with NO remaining change is unrepresentable (exactly the
/// review's finding a Degraded disposition could contain no remaining
/// changes); AT LEAST ONE `Desired`/`Diverged`/`Unknown` delta →
/// `Degraded`.
fn append_degraded(
    txn: &mut TargetLedgerTxn<'_>,
    attempt: &DeploymentIntent,
    per_slot_evidence: &BTreeMap<SlotId, RecoverySlotEvidence>,
    reason: &str,
) -> Result<()> {
    let outcomes: BTreeMap<SlotId, SlotOutcome> = attempt
        .selected()
        .map(|(sid, _)| {
            let evidence = per_slot_evidence.get(&sid).expect(
                "recovery collects evidence for every selected slot before deciding the terminal",
            );
            (sid.clone(), failed_outcome_from_evidence(evidence))
        })
        .collect();
    // THE DECISION IS THE SINGLE CLASSIFICATION AUTHORITY: recovery builds
    // the SAME `ExecutionReport::Failed` the engine's failure path builds
    // (outcome keys EXACTLY covering the selected membership) and calls the
    // SAME [`crate::kernel::transition::decide_terminal`]. The kernel owns
    // the key-set check and the delta derivation; recovery never decides a
    // disposition itself.
    let non_empty = NonEmptySlotTable::build(outcomes).map_err(|e| {
        Error::integrity(format!(
            "recovery for '{}' failed-outcomes must cover the selected membership (nonempty): {e}",
            attempt.deployment_id()
        ))
    })?;
    let disposition = crate::kernel::transition::decide_terminal(
        attempt,
        crate::kernel::transition::ExecutionReport::Failed {
            outcomes: non_empty,
            // Recovery never runs the mutating adapters itself — its
            // outcomes are the evidence-kind (Indeterminate/Failed), never
            // `Restored` — so no adapter-restoration proof is owed.
            adapter_restored: std::collections::BTreeMap::new(),
        },
    )
    .map_err(|e| {
        Error::integrity(format!(
            "recovery for '{}' refused a terminal disposition: {e}",
            attempt.deployment_id()
        ))
    })?;
    let terminal = LedgerTerminal::new(
        crate::remote::helper::now_rfc3339_ts(),
        kernel::terminal::intent_digest(attempt),
        crate::kernel::terminal::NonSuccessfulDisposition::from_decision(disposition),
        Some(reason.to_string()),
    );
    txn.append_terminal(attempt.deployment_id(), &terminal)
}

/// The PER-SLOT EVIDENCE of a recovery-degraded terminal: the slot's
/// OBSERVED state, collected from its BACKEND (under its mutation lock)
/// BEFORE the degraded terminal is decided. `observation` is the live
/// generation (or its lack / a read failure) the backend actually reported;
/// `binding` is the slot's CURRENT CONFIGURED physical binding (a per-slot
/// CONFIG fact, never a value from the intent's frozen snapshot); `error`
/// preserves the read failure (the `Unknown` observation/binding carry the
/// same preserved error). The degraded terminal's per-slot outcomes are
/// built from this evidence ONLY: a plan may DESIRE a fact, but only a
/// successful backend read may create an OBSERVED fact.
pub(crate) struct RecoverySlotEvidence {
    /// The slot's observed GENERATION, from the backend status + assignment
    /// reads: `Known` ONLY on a successful read of that generation,
    /// `KnownAbsent` ONLY on a successful status read showing no `current`,
    /// `Unknown` on a read failure.
    pub observation: Observation<ObservedGeneration>,
    /// The slot's CURRENT CONFIGURED binding (the config fact the slot is
    /// bound to today) under the same reads as `observation` — never the
    /// intent's frozen snapshot binding. Not persisted (the wire outcome
    /// carries no binding field); exposed for the assertion suite / the
    /// spec contract that the evidence names the slot's live location.
    #[allow(dead_code)]
    pub binding: Observation<PhysicalBinding>,
    /// The failed read's preserved error (when `observation`/`binding` are
    /// `Unknown`); `None` when the reads succeeded.
    pub error: Option<String>,
}

/// The PURE per-slot backend observation decision — the RESOLVED outcome of
/// the TWO backend reads ([`observe_recovery_slot`] performs them: status,
/// then assignment only when status reports a generation). The property
/// tests drive this value directly to assert the evidence-construction
/// semantics without heavyweight IO.
pub(crate) enum BackendObservation {
    /// status -> a current generation, assignment -> read successfully: the
    /// generation is LIVE — the ONLY source of a `Known` observation.
    Live(GenerationId),
    /// status -> no current: the slot has no observed state.
    Absent,
    /// status -> read failed, or status succeeded but the assignment read
    /// failed: the preserved error.
    Failed(String),
}

/// THE ONLY remote-observation-constructed path to [`RecoverySlotEvidence`]
/// (the governing rule: a plan may create desired facts, but only a
/// successful backend read may create observed facts). `helper` is the
/// selected slot's HELD mutation-lock guard; `configured_binding` is the
/// slot's CURRENT configured binding (`None` when the slot is no longer a
/// configured member). `Known` values appear ONLY from a successful
/// status + assignment read; `KnownAbsent` ONLY from a successful status
/// read showing no `current`; `Unknown` preserves the read error. The
/// `Known` binding is the slot's live/config binding — never the intent's
/// frozen snapshot binding; a non-member slot records an `Unknown` binding
/// (no configured location exists to bind it to).
fn observe_recovery_slot(
    helper: &HeldSlotLock<'_>,
    configured_binding: Option<&PhysicalBinding>,
    owner: &crate::remote::helper::GenerationOwner,
) -> RecoverySlotEvidence {
    // Every backend read verifies the generation's OWNER MARKER against the
    // expected application + slot: a transplanted generation is refused
    // (fail closed — never observed as this slot's live state).
    let backend = match helper.helper().status(owner) {
        Err(e) => BackendObservation::Failed(e.to_string()),
        Ok(status) => match status.current_generation() {
            None => BackendObservation::Absent,
            Some(generation) => match helper.helper().read_assignment(generation, owner) {
                Ok(_) => BackendObservation::Live(generation.clone()),
                Err(e) => BackendObservation::Failed(e.to_string()),
            },
        },
    };
    recovery_evidence_from_backend(backend, configured_binding)
}

/// The PURE evidence-construction decision: map the resolved backend
/// observation to the per-slot evidence. A `Known` observation appears ONLY
/// from [`BackendObservation::Live`]; a `KnownAbsent` observation ONLY from
/// [`BackendObservation::Absent`]; an `Unknown` observation carries the read
/// error. NO branch ever sources a `Known` value from the intent's desired
/// snapshot.
fn recovery_evidence_from_backend(
    backend: BackendObservation,
    configured_binding: Option<&PhysicalBinding>,
) -> RecoverySlotEvidence {
    match backend {
        BackendObservation::Failed(e) => RecoverySlotEvidence {
            observation: Observation::Unknown(ObservationError { message: e.clone() }),
            binding: Observation::Unknown(ObservationError { message: e.clone() }),
            error: Some(e),
        },
        BackendObservation::Absent => RecoverySlotEvidence {
            observation: Observation::KnownAbsent,
            binding: Observation::KnownAbsent,
            error: None,
        },
        BackendObservation::Live(generation) => RecoverySlotEvidence {
            observation: Observation::Known(ObservedGeneration { generation }),
            binding: match configured_binding {
                Some(b) => Observation::Known(b.clone()),
                // The slot is not a configured member: there is no physical
                // binding to record — the observation may still be Known
                // (the backend read succeeded), but the binding has no
                // source and is honestly `Unknown`.
                None => Observation::Unknown(ObservationError {
                    message: "slot is not a configured member — no physical binding".to_string(),
                }),
            },
            error: None,
        },
    }
}

/// The causal-agnostic per-slot outcome a recovery-degraded terminal
/// records for the given evidence: [`SlotOutcome::Indeterminate`] — the
/// backend read reports the observed state, but recovery has NO transaction
/// evidence of what the attempt's mutation did (recovery never claims
/// `Restored`/compensated or `Skipped`/never-started without transaction
/// evidence). The observation is the evidence's TRUTHFUL backend
/// observation; the `error` is the evidence's read error (the only
/// operation-level error a non-mutating recovery carries). The plan's
/// desired snapshot NEVER appears here.
fn failed_outcome_from_evidence(evidence: &RecoverySlotEvidence) -> SlotOutcome {
    SlotOutcome::Indeterminate {
        observation: evidence.observation.clone(),
        error: evidence.error.clone(),
    }
}

/// Collect the per-slot recovery EVIDENCE of the attempt's SELECTED
/// membership — on a DEGRADED path ONLY: acquire each selected slot's
/// mutation lock (sorted-slot-id order, like the finalizer) and re-read its
/// live state ([`observe_recovery_slot`]). A selected slot with NO helper
/// (no configured remote — it is not a configured member) records an
/// `Unknown` evidence (its state cannot be read at all). On a
/// lock-acquisition failure the collection returns `Ok(None)`: the caller
/// must choose [`RecoveryOutcome::StillPending`] — a truthful terminal
/// cannot be built without the backend read. This path runs ONLY for the
/// degraded paths (membership mismatch, binding drift, finalizer `Refused`),
/// never for the `Successful` path, whose finalizer performs its own
/// lock-verified acquisition (pre-acquiring the guards here would make the
/// finalizer's own acquisition contend).
fn collect_recovery_evidence(
    attempt: &DeploymentIntent,
    helpers: &HashMap<SlotId, RemoteHelper>,
    live_bindings: &BTreeMap<SlotId, PhysicalBinding>,
    op_id: &OperationId,
    application: &crate::identity::ApplicationStoreKey,
) -> Result<Option<BTreeMap<SlotId, RecoverySlotEvidence>>> {
    let mut evidence: BTreeMap<SlotId, RecoverySlotEvidence> = BTreeMap::new();
    let mut selected: Vec<SlotId> = attempt.selected_membership().into_iter().collect();
    selected.sort();
    for sid in selected {
        let Some(helper) = helpers.get(&sid) else {
            // Not a configured member: no remote to observe — the slot's
            // state is honestly UNKNOWN (a membership-mismatch degraded
            // path).
            let msg = format!("slot '{sid}' has no configured remote to observe");
            evidence.insert(
                sid,
                RecoverySlotEvidence {
                    observation: Observation::Unknown(ObservationError {
                        message: msg.clone(),
                    }),
                    binding: Observation::Unknown(ObservationError {
                        message: msg.clone(),
                    }),
                    error: Some(msg),
                },
            );
            continue;
        };
        match helper.acquire_lock_guard(op_id) {
            Err(_) => return Ok(None),
            Ok(guard) => {
                let configured_binding = live_bindings.get(&sid);
                let owner =
                    crate::remote::helper::GenerationOwner::new(application.clone(), sid.clone());
                evidence.insert(
                    sid.clone(),
                    observe_recovery_slot(&guard, configured_binding, &owner),
                );
            }
        }
    }
    Ok(Some(evidence))
}

/// The causal-agnostic per-slot classification of a recovery evidence
/// (test/assertion view — the degraded terminal itself stays the
/// causal-agnostic `Indeterminate`; this is a derived view, never a stored
/// field): delegates to the SHARED classifier
/// ([`crate::kernel::terminal::classify_slot_delta`] / [`crate::kernel::terminal::SlotDelta`]) —
/// the same `Desired`/`Unchanged`/`Diverged`/`Unknown` taxonomy the
/// terminal decision, the payload validators, and `remaining_changes` use
/// (the old recovery-specific `Advanced`/`Unchanged`/`Diverged`/`Unknown`
/// classification is REPLACED — [`SlotDelta::Desired`] is the backend-
/// confirmed verified slot, and a slot is a remaining change iff its class
/// is not `Unchanged`, exactly as before).
#[cfg(test)]
pub(crate) fn classify_recovery_slot(
    evidence: &RecoverySlotEvidence,
    desired: &GenerationId,
    pre_push: Option<&GenerationId>,
) -> crate::kernel::terminal::SlotDelta {
    crate::kernel::terminal::classify_slot_delta(&evidence.observation, desired, pre_push)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::testsupport::{RefExpr, TwoSlotHarness, known_generation, two_slot_push};
    use crate::identity::{
        ArtifactRef, BehaviorDigest, DeploymentId, GenerationId, RolloutGroupName, TargetName,
        Timestamp, VariantName, test_deployment_id, test_generation_id, test_release_id,
        test_tree_digest,
    };
    use crate::kernel::intent::{PlanInput, PlannedDeploy};
    use crate::kernel::snapshot::{PreviousGeneration, SnapshotSlot};
    use crate::kernel::terminal::{SlotDelta, TerminalDisposition};
    use crate::ledger::{DeploymentStatus, PhysicalBinding};
    use crate::remote::helper::{ExpectedCurrent, GenerationAssignment, RemoteHelper};
    use crate::remote::transport::{LocalTransport, Remote};
    use crate::store::local::LocalStore;
    #[cfg(test)]
    use proptest::prelude::*;
    #[cfg(test)]
    use proptest::test_runner::RngSeed;

    fn p1() -> SlotId {
        SlotId::parse("p1").unwrap()
    }
    fn p2() -> SlotId {
        SlotId::parse("p2").unwrap()
    }

    fn art(tag: &str) -> ArtifactRef {
        ArtifactRef {
            release: test_release_id(tag),
            variant: VariantName::parse("standard").unwrap(),
            tree: test_tree_digest(tag),
        }
    }

    /// A GROUP intent over the head `base`: the given slot is deployed at
    /// its own generation, the other target slot is INHERITED from the
    /// head's snapshot (the overlay pattern of a partial push).
    fn group_over_head(
        dep: &str,
        group: &str,
        base: &crate::kernel::intent::DeploymentIntent,
        bindings: &std::collections::BTreeMap<SlotId, PhysicalBinding>,
        deploy_slot: SlotId,
        new_gen: &str,
        artifact: ArtifactRef,
    ) -> crate::kernel::intent::DeploymentIntent {
        crate::kernel::intent::plan(PlanInput {
            deployment_id: test_deployment_id(dep),
            target: TargetName::parse("t1").unwrap(),
            parent: Some(base.deployment_id().clone()),
            parent_snapshot: Some(base.resulting_snapshot()),
            group: Some(RolloutGroupName::parse(group).unwrap()),
            selection: vec![p1(), p2()],
            planned: vec![PlannedDeploy {
                slot: deploy_slot.clone(),
                result: SnapshotSlot::new(
                    test_generation_id(new_gen),
                    artifact,
                    bindings
                        .get(&deploy_slot)
                        .cloned()
                        .expect("a selected slot binds"),
                ),
                pre_push: Observation::KnownAbsent,
            }],
            behavior_digest: BehaviorDigest::parse(crate::identity::DIGEST_TEST_HEX_1).unwrap(),
            attempted_at: Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        })
        .expect("a valid group intent plans")
    }

    fn resolved_of(store: &LocalStore, dep: &DeploymentId) -> crate::ledger::TargetSnapshot {
        let entries = store.read_ledger("t1").unwrap();
        let entry = entries
            .iter()
            .find(|e| e.deployment_id == *dep)
            .expect("the entry exists");
        crate::kernel::snapshot::resolve_snapshot(entry).expect("a Successful entry resolves")
    }

    /// THE STRICT-LINEAR INTEGRATION PROPERTY (spec items 6 + 9): force
    /// group A to remain PENDING (its finalizer cannot finish RIGHT NOW —
    /// its slot's mutation lock is held by a foreign operation, so
    /// [`finalize_successful_locked`] returns `Pending`), then attempt
    /// group B (a DISJOINT selection, deploys p2): the push is REFUSED with
    /// a Conflict ("a previous deployment is still pending") WITHOUT
    /// appending B's intent — a push that cannot finish the previous
    /// pending attempt NEVER plans a second intent on top, even for
    /// disjoint groups. After A reaches its Successful terminal (the lock
    /// is released; the retry's recovery finalizes A over head H),
    /// RETRYING B succeeds with B's parent == A and B's inherited p1 ==
    /// A's entry — the strictly-linear chain H → A → B.
    #[test]
    fn push_refuses_group_b_while_group_a_is_unfinalized_and_repairs_on_retry() {
        let h = TwoSlotHarness::new();
        // A REAL full HEAD push establishes live state for BOTH slots (so the
        // pending A's later finalization and B's later push both verify
        // against minted remotes).
        let head_id = test_deployment_id("deploy-h");
        let r_head = two_slot_push(&h, &h.config, &RefExpr::Head, None, &head_id).unwrap();
        assert_eq!(r_head.status, Some(DeploymentStatus::Successful));
        let head = h
            .store
            .read_ledger("t1")
            .unwrap()
            .into_iter()
            .find(|e| e.deployment_id == head_id)
            .expect("the head entry exists")
            .intent;
        let bindings = h.config.target_slot_bindings("t1").unwrap();
        // The REAL head push minted p1's live generation at runtime (not a
        // test fixture id) — the prior state A's deployment advances.
        let head_p1 = known_generation(
            &r_head
                .attempt
                .as_ref()
                .expect("the head push records an attempt")
                .slots[&p1()],
        )
        .clone();

        // A (group-a): deploys p1 (generation a-p1), inherits p2 from the
        // head. PENDING (intent-only — a push that crashed after the remote
        // advanced but before the terminal landed). A's live p1 IS the frozen
        // desired (minted over the head's generation), so its finalizer
        // would SUCCEED — if it could acquire the lock.
        let a = group_over_head(
            "deploy-a",
            "group-a",
            &head,
            &bindings,
            p1(),
            "a-p1",
            art("rel-a"),
        );
        h.store.append_attempt("t1", &a).unwrap();
        advance_live_slot(
            &h,
            "s1",
            &head_p1,
            &test_generation_id("a-p1"),
            &art("rel-a"),
            a.deployment_id(),
        );

        // HOLD p1's mutation lock with a FOREIGN operation id: A's
        // finalization must acquire p1's lock, fails (a transient
        // non-finalization), and the attempt stays intent-only.
        let env = crate::testutil::fixture_env();
        let r1: Box<dyn Remote> =
            Box::new(LocalTransport::new(&env, h.remotes_base.join("s1")).unwrap());
        let helper = RemoteHelper::new(r1.as_ref());
        let _guard = helper
            .acquire_lock_guard(&OperationId::new("op-foreign-a".to_string()))
            .unwrap();

        // Attempt group B (DISJOINT: deploys p2, inherits p1 from the head)
        // through the REAL push path: preflight recovery cannot finish A, so
        // the push is REFUSED with the spec's Conflict and NO intent is
        // appended.
        let b_id = test_deployment_id("deploy-b");
        let err = two_slot_push(&h, &h.config, &RefExpr::Head, Some("group-b"), &b_id).expect_err(
            "a push cannot plan a second intent while a previous deployment is still pending",
        );
        assert!(
            err.to_string()
                .contains("a previous deployment is still pending"),
            "the refusal must carry the spec's exact conflict message, got: {err}"
        );
        assert!(
            err.to_string().contains("conflict"),
            "the still-pending refusal is a Conflict, got: {err}"
        );
        // NOTHING appended: no intent for B, A still pending, head still H.
        let entries = h.store.read_ledger("t1").unwrap();
        assert!(
            !entries.iter().any(|e| e.deployment_id == b_id),
            "B's intent must NOT be appended while A is unfinalized"
        );
        assert_eq!(
            h.store.latest_status(a.deployment_id().as_str()).unwrap(),
            None,
            "A is still pending (intent-only)"
        );
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(head_id.as_str()),
            "the head is still H"
        );

        // RELEASE the foreign lock and give the target NEW content (a
        // distinct release R2): the retry's recovery FINALIZES A
        // (`Successful` — its parent H is still the head), then B — planning
        // group-b over the NEW head — deploys the new content under R2 and
        // becomes the newest successful entry.
        drop(_guard);
        let project_root = h.config.project_root(&h.cfg_path);
        let variant_path = project_root
            .join("releases")
            .join("v1")
            .join("standard.toml");
        let v2 = std::fs::read_to_string(&variant_path)
            .unwrap()
            .replace("argv = [\"true\", \"a\"]", "argv = [\"true\", \"b\"]");
        assert_ne!(
            v2,
            std::fs::read_to_string(&variant_path).unwrap(),
            "the fixture must actually change the verification argv"
        );
        std::fs::write(&variant_path, v2).unwrap();
        std::fs::write(
            project_root
                .join("releases")
                .join("v1")
                .join("artifacts")
                .join("build/output/app/server"),
            "v2\n",
        )
        .unwrap();
        let config2 = ProjectConfig::load(&h.cfg_path).unwrap();
        let r2 = two_slot_push(&h, &config2, &RefExpr::Head, Some("group-b"), &b_id).unwrap();
        assert_eq!(r2.status, Some(DeploymentStatus::Successful));
        assert_eq!(
            h.store.latest_status(a.deployment_id().as_str()).unwrap(),
            Some(DeploymentStatus::Successful),
            "A finalized Successful on the retry's recovery"
        );
        // B USES A AS ITS PARENT: H → A → B; B's inherited p1 is A's entry.
        let entries = h.store.read_ledger("t1").unwrap();
        let b_entry = entries
            .iter()
            .find(|e| e.deployment_id == b_id)
            .expect("B is recorded");
        assert_eq!(
            b_entry.intent.parent(),
            Some(a.deployment_id()),
            "B must be planned over A (the head its recovery established)"
        );
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(b_id.as_str()),
            "B is the newest head"
        );
        let b_snapshot = resolved_of(&h.store, &b_id);
        assert_eq!(
            b_snapshot.get(&p1()).map(|e| e.generation()),
            Some(&test_generation_id("a-p1")),
            "B's inherited p1 is A's entry — the overlay is A's snapshot"
        );
        assert_eq!(
            b_snapshot.get(&p2()).map(|e| e.generation()),
            Some(known_generation(
                &r2.attempt.as_ref().expect("attempt").slots[&p2()]
            )),
            "B's deployed p2 is its own plan-minted generation"
        );
        assert_ne!(
            b_snapshot.get(&p2()).map(|e| e.generation().clone()),
            Some(
                a.resulting_snapshot()
                    .get(&p2())
                    .expect("A covers p2")
                    .generation()
                    .clone()
            ),
            "B deployed NEW p2 content over A's inherited entry"
        );
        assert_eq!(b_snapshot, b_entry.intent.resulting_snapshot());
    }

    /// Mint a slot's LIVE state on its remote OVER an existing generation
    /// (the head's): create a real `generations/<gen>/root` chain with the
    /// given prior generation and CAS `current` from the prior generation to
    /// the new one — exactly the state A's deployment leaves behind while
    /// the attempt stays intent-only.
    fn advance_live_slot(
        h: &TwoSlotHarness,
        server: &str,
        prior: &GenerationId,
        generation: &GenerationId,
        artifact: &ArtifactRef,
        deployment_id: &DeploymentId,
    ) {
        let base = h.remotes_base.join(server);
        let remote = LocalTransport::new(&crate::testutil::fixture_env(), base).unwrap();
        remote
            .create_dir_all(&crate::remote::layout::tree_root(&artifact.tree))
            .unwrap();
        let helper = RemoteHelper::new(&remote);
        helper
            .acquire_lock_guard(&OperationId::new("op-mint".to_string()))
            .unwrap()
            .create_generation(&GenerationAssignment {
                deployment_id: deployment_id.clone(),
                generation_id: generation.clone(),
                artifact: artifact.clone(),
                behavior_sha256: crate::identity::DIGEST_TEST_HEX_1.to_string(),
                prior_generation: Some(prior.clone()),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                application: crate::identity::ApplicationStoreKey::parse("eng").unwrap(),
                slot: crate::identity::SlotId::parse("p1").unwrap(),
                target: Some(TargetName::parse("t1").unwrap()),
            })
            .unwrap();
        helper
            .acquire_lock_guard(&OperationId::new("op-mint".to_string()))
            .unwrap()
            .swap_current(
                &ExpectedCurrent::Generation(prior.clone()),
                generation,
                "op-mint",
            )
            .unwrap();
    }

    // ---- DEGRADED TERMINALS RECORD BACKEND-OBSERVED FACTS (the spec's
    // acceptance gate) ------------------------------------------------------
    //
    // THE PROPERTY FAMILY: generate INDEPENDENTLY the desired generation D
    // (the intent's frozen snapshot), the pre-push generation P, the backend
    // result (in {P, D, a third generation X, absent, read error}) and the
    // recovery failure (membership / binding / finalizer refusal), and drive
    // the PURE evidence machinery — `recovery_evidence_from_backend`
    // (evidence construction), `failed_outcome_from_evidence` (evidence →
    // degraded outcome), `classify_recovery_slot` (the derived per-slot
    // classification) and the REAL terminal construction (DegradedTerminal +
    // [`LedgerTerminal::remaining_changes`]) — asserting:
    //
    // * the terminal's per-slot observations are the BACKEND's — a
    //   `Known(G)` observation implies a successful backend read of G (the
    //   terminal NEVER fabricates `Known(desired)` from the plan's frozen
    //   snapshot: when the backend reports a third generation the terminal
    //   records THIRD, never DESIRED);
    // * the binding is `Known` under the same successful read (the slot's
    //   CURRENT configured binding), `KnownAbsent` under an absent current,
    //   `Unknown` under a read failure;
    // * a slot verified at its desired generation through a backend read
    //   PRESERVES that verified evidence (`Known(desired)` — the backend
    //   confirmed it, `Advanced`);
    // * `remaining_changes` contains exactly the honestly-changed slots
    //   (the `Unchanged` class is never a remaining change; every
    //   `Advanced`/`Diverged`/`Unknown` slot is), matching the kernel's
    //   derivation for the causal-agnostic `Failed { compensated: false }`
    //   outcomes.

    /// A deterministic valid generation per tag (distinct tags yield
    /// distinct ids). The desired/pre-push/third generations of every
    /// generated case embed the case tag with DISTINCT suffixes, so the
    /// three are pairwise distinct for ANY generated tag (shrinking-safe).
    fn prop_gen(tag: &str) -> GenerationId {
        test_generation_id(tag)
    }

    /// The BACKEND result of one slot's reads, relative to the generated
    /// desired (D) and pre-push (P) generations.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum PropBackend {
        /// The backend reported the DESIRED generation live.
        AtDesired,
        /// The backend reported the PRE-PUSH generation live.
        AtPrePush,
        /// The backend reported a THIRD generation (neither D nor P).
        AtThird,
        /// The backend reported NO current state.
        Absent,
        /// The backend read failed.
        ReadError,
    }

    /// The RECOVERY failure that sent the attempt to the degraded path.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum PropFailure {
        MembershipDrift,
        BindingDrift,
        FinalizerRefusal,
    }

    impl PropFailure {
        fn reason(self) -> &'static str {
            match self {
                PropFailure::MembershipDrift => "membership mismatch",
                PropFailure::BindingDrift => "binding drift",
                PropFailure::FinalizerRefusal => "state diverged",
            }
        }
    }

    fn arbitrary_backend() -> impl Strategy<Value = PropBackend> {
        prop_oneof![
            Just(PropBackend::AtDesired),
            Just(PropBackend::AtPrePush),
            Just(PropBackend::AtThird),
            Just(PropBackend::Absent),
            Just(PropBackend::ReadError),
        ]
    }

    fn arbitrary_failure() -> impl Strategy<Value = PropFailure> {
        prop_oneof![
            Just(PropFailure::MembershipDrift),
            Just(PropFailure::BindingDrift),
            Just(PropFailure::FinalizerRefusal),
        ]
    }

    /// Build the generated case: D = prop_gen(tag), P = prop_gen(tag + "-p"),
    /// X = prop_gen(tag + "-x") — pairwise DISTINCT for any generated tag
    /// (deterministic distinct suffixes), pre-push = P (a KNOWN generation).
    #[derive(Clone, Debug)]
    struct EvidenceCase {
        desired: GenerationId,
        pre_push: GenerationId,
        third: GenerationId,
        backend: PropBackend,
        failure: PropFailure,
        boundary: PropBoundary,
    }

    /// THE PERSISTENCE BOUNDARY whose failure left the attempt intent-only
    /// (the review's acceptance dimension — generate failures at EVERY
    /// persistence boundary crossed with the live-state evidence).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum PropBoundary {
        /// The PREFLIGHT TERMINAL append failed — NOW PROPAGATED (the
        /// review's fix): the push surfaces the append failure, the attempt
        /// stays intent-only, and NOTHING was mutated, so the truthful
        /// evidence is EXACTLY the original pre-push state (the review's P1
        /// finding — this boundary's recovery MUST settle `FailedRolledBack`,
        /// never `Degraded`).
        PreflightTerminalAppend,
        /// The COMMIT-MARKER write failed: the attempt's mutations are
        /// visible on the live state, so the evidence follows the backend
        /// read.
        MarkerWrite,
        /// The FINALIZER refused (a drifted head / diverged live state): the
        /// evidence follows the backend read.
        FinalizeRefusal,
    }

    fn arbitrary_boundary() -> impl Strategy<Value = PropBoundary> {
        prop_oneof![
            Just(PropBoundary::PreflightTerminalAppend),
            Just(PropBoundary::MarkerWrite),
            Just(PropBoundary::FinalizeRefusal),
        ]
    }

    fn arbitrary_evidence_case() -> impl Strategy<Value = EvidenceCase> {
        (
            "[a-z0-9]{1,14}",
            arbitrary_backend(),
            arbitrary_failure(),
            arbitrary_boundary(),
        )
            .prop_map(|(tag, backend, failure, boundary)| {
                // THE PREFLIGHT-TERMINAL-APPEND BOUNDARY (the review's P1
                // scenario): the attempt never mutated a remote — the
                // preflight failed before any `current` change and the
                // FailedPreflight terminal append then failed, so the
                // truthful evidence on the retry is EXACTLY the original
                // pre-push state. The generated backend is pinned to
                // `AtPrePush` for this boundary (its semantics, not an
                // independent choice); the other boundaries keep the
                // generated evidence.
                let backend = if boundary == PropBoundary::PreflightTerminalAppend {
                    PropBackend::AtPrePush
                } else {
                    backend
                };
                EvidenceCase {
                    desired: prop_gen(&tag),
                    pre_push: prop_gen(&format!("{tag}-p")),
                    third: prop_gen(&format!("{tag}-x")),
                    backend,
                    failure,
                    boundary,
                }
            })
    }

    /// A VALID first-push intent for the property: one selected slot (p1)
    /// deploying `desired` over the KNOWN pre-push generation, planned
    /// through the kernel's validated constructor.
    fn evidence_prop_intent(
        deploy_slot: &SlotId,
        desired: &GenerationId,
        pre_push: &GenerationId,
        binding: &PhysicalBinding,
        artifact: ArtifactRef,
    ) -> DeploymentIntent {
        crate::kernel::intent::plan(PlanInput {
            deployment_id: test_deployment_id("deploy-evidence-prop"),
            target: TargetName::parse("t1").unwrap(),
            parent: None,
            parent_snapshot: None,
            group: None,
            selection: vec![deploy_slot.clone()],
            planned: vec![PlannedDeploy {
                slot: deploy_slot.clone(),
                result: SnapshotSlot::new(desired.clone(), artifact.clone(), binding.clone()),
                pre_push: Observation::Known(PreviousGeneration {
                    generation: pre_push.clone(),
                    artifact,
                }),
            }],
            behavior_digest: BehaviorDigest::parse(crate::identity::DIGEST_TEST_HEX_1).unwrap(),
            attempted_at: Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        })
        .expect("a valid evidence property intent plans")
    }

    /// Drive ONE generated case through the PURE evidence machinery, the
    /// REAL terminal DECISION (the SAME [`crate::kernel::transition::
    /// decide_terminal`] path recovery's `append_degraded` and normal
    /// execution both use), and the REAL terminal construction; assert the
    /// spec's acceptance assertions.
    fn run_evidence_case(case: EvidenceCase) {
        let EvidenceCase {
            desired,
            pre_push,
            third,
            backend,
            failure,
            boundary,
        } = case;
        let slot = p1();
        // The generated cases deploy a CONFIGURED member slot: the
        // evidence's binding source is the slot's current configured binding
        // (the non-member `None` arm is pinned by
        // [`non_member_slot_evidence_has_unknown_binding_under_a_known_generation`]).
        let config_binding = PhysicalBinding::default();

        // The backend observation the reads resolve to (mirroring the
        // production decision order: status, then assignment).
        let backend_obs = match backend {
            PropBackend::AtDesired => BackendObservation::Live(desired.clone()),
            PropBackend::AtPrePush => BackendObservation::Live(pre_push.clone()),
            PropBackend::AtThird => BackendObservation::Live(third.clone()),
            PropBackend::Absent => BackendObservation::Absent,
            PropBackend::ReadError => {
                BackendObservation::Failed("status read failed: boom".to_string())
            }
        };
        let evidence = recovery_evidence_from_backend(backend_obs, Some(&config_binding));
        let class = classify_recovery_slot(&evidence, &desired, Some(&pre_push));

        // (1) THE TERMINAL OBSERVATION IS THE BACKEND'S — `Known` appears
        // ONLY from a successful backend read, NEVER from the plan's desired
        // state; `KnownAbsent` ONLY from a successful status read showing no
        // current; `Unknown` preserves the read error.
        let expected_observation = match backend {
            PropBackend::AtDesired => Observation::Known(ObservedGeneration {
                generation: desired.clone(),
            }),
            PropBackend::AtPrePush => Observation::Known(ObservedGeneration {
                generation: pre_push.clone(),
            }),
            PropBackend::AtThird => Observation::Known(ObservedGeneration {
                generation: third.clone(),
            }),
            PropBackend::Absent => Observation::KnownAbsent,
            PropBackend::ReadError => Observation::Unknown(ObservationError {
                message: "status read failed: boom".to_string(),
            }),
        };
        assert_eq!(
            evidence.observation, expected_observation,
            "the evidence observation is the BACKEND's fact ({backend:?}), never the plan's desired state"
        );
        // The desired-fabrication ban, stated explicitly (property-1750 the
        // evidence path, including the desired != backend case): a `Known`
        // observed generation equals EXACTLY the backend's reported
        // generation — when the backend reports the third generation the
        // terminal records THIRD, never the desired D.
        if let Observation::Known(og) = &evidence.observation {
            let backend_gen = match backend {
                PropBackend::AtDesired => &desired,
                PropBackend::AtPrePush => &pre_push,
                PropBackend::AtThird => &third,
                _ => unreachable!("non-Live backends never produce a Known observation"),
            };
            assert_eq!(
                &og.generation, backend_gen,
                "a Known observed generation implies a successful backend read OF THAT generation — the desired state is never converted into an observed fact"
            );
        }

        // (2) THE BINDING is Known under the same successful read (the
        // slot's CURRENT configured binding — a config fact, never the
        // intent's frozen snapshot binding), KnownAbsent under an absent
        // current, Unknown under a read failure.
        let expected_binding = match backend {
            PropBackend::AtDesired | PropBackend::AtPrePush | PropBackend::AtThird => {
                Observation::Known(config_binding.clone())
            }
            PropBackend::Absent => Observation::KnownAbsent,
            PropBackend::ReadError => Observation::Unknown(ObservationError {
                message: "status read failed: boom".to_string(),
            }),
        };
        assert_eq!(
            evidence.binding, expected_binding,
            "the binding is Known under the same read — the current configured binding, never the intent's frozen snapshot binding"
        );

        // (3) THE DERIVED CLASSIFICATION (the SHARED classifier — the
        // recovery `classify_recovery_slot` delegating to
        // [`crate::kernel::terminal::classify_slot_delta`]): actual ==
        // desired -> Desired (the backend-confirmed verified slot), actual
        // == pre-push -> Unchanged, third generation / vanished prior state
        // -> Diverged, failed read -> Unknown.
        let expected_class = match backend {
            PropBackend::AtDesired => SlotDelta::Desired,
            PropBackend::AtPrePush => SlotDelta::Unchanged,
            PropBackend::AtThird | PropBackend::Absent => SlotDelta::Diverged,
            PropBackend::ReadError => SlotDelta::Unknown,
        };
        assert_eq!(
            class, expected_class,
            "the derived per-slot classification matches the evidence vs desired/pre-push ({backend:?})"
        );

        // (4) THE RECOVERED TERMINAL: the causal-agnostic Indeterminate
        // outcome built from the evidence, carrying the case's recovery
        // failure as the reason; the honest remaining set.
        let artifact = art("rel-evidence");
        let intent = evidence_prop_intent(&slot, &desired, &pre_push, &config_binding, artifact);
        let outcome = failed_outcome_from_evidence(&evidence);
        assert_eq!(
            outcome.observation(),
            &evidence.observation,
            "the degraded outcome copies the BACKEND-observed fact from the evidence"
        );
        assert!(
            matches!(
                outcome,
                crate::ledger::records::SlotOutcome::Indeterminate { .. }
            ),
            "the degraded terminal stays the causal-agnostic Indeterminate — never Restored/Skipped without transaction evidence"
        );
        let non_empty = NonEmptySlotTable::build(BTreeMap::from([(slot.clone(), outcome)]))
            .expect("a single outcome builds a non-empty table");

        // (0) THE BOUNDARY SEMANTICS (the review's acceptance dimension): a
        // PREFLIGHT-TERMINAL-APPEND failure left the attempt intent-only
        // with NOTHING mutated — the truthful evidence is EXACTLY the
        // original pre-push state (the generator pinned the backend to
        // `AtPrePush`), so this boundary's recovery MUST settle
        // `FailedRolledBack`, never `Degraded` (asserted below).
        if boundary == PropBoundary::PreflightTerminalAppend {
            assert_eq!(
                backend,
                PropBackend::AtPrePush,
                "the preflight-terminal-append boundary never mutated the remote — the evidence is the original pre-push state"
            );
        }

        // (5) THE RECOVERY DISPOSITION IS DECIDED BY THE ONE CLASSIFIER —
        // the SAME [`crate::kernel::transition::decide_terminal`] path as
        // uninterrupted execution (the review's fix: recovery's
        // `append_degraded` builds the outcomes from this evidence and hands
        // them to the decision — never a direct `DegradedTerminal::try_new`
        // construction that could manufacture a `Degraded` disposition for
        // an exact-pre-push state). The decision derives the disposition
        // from the evidence's deltas vs the intent's pre-push and DESIRED
        // generations:
        //
        // * EVERY slot `Unchanged` — the EXACT PRE-PUSH STATE (including
        //   the review's preflight-terminal-append-boundary scenario) →
        //   `FailedRolledBack`, never `Degraded`;
        // * AT LEAST ONE `Desired`/`Diverged`/`Unknown` delta → `Degraded`
        //   (nonempty deltas).
        let disposition = crate::kernel::transition::decide_terminal(
            &intent,
            crate::kernel::transition::ExecutionReport::Failed {
                outcomes: non_empty,
                adapter_restored: std::collections::BTreeMap::new(),
            },
        )
        .expect(
            "recovery evidence covers exactly the selected membership — the decision accepts it",
        );
        match &disposition {
            TerminalDisposition::FailedRolledBack(_) => {
                assert_eq!(
                    class,
                    SlotDelta::Unchanged,
                    "the exact pre-push state settles FailedRolledBack — never Degraded (backend {backend:?}, boundary {boundary:?})"
                );
                assert_eq!(
                    disposition.status(),
                    DeploymentStatus::FailedRolledBack,
                    "an all-Unchanged evidence set decides FailedRolledBack (backend {backend:?}, boundary {boundary:?})"
                );
            }
            TerminalDisposition::Degraded(_) => {
                assert_ne!(
                    class,
                    SlotDelta::Unchanged,
                    "a Degraded terminal requires at least one Desired/Diverged/Unknown delta (backend {backend:?}, boundary {boundary:?})"
                );
                assert_eq!(
                    disposition.status(),
                    DeploymentStatus::Degraded,
                    "a non-Unchanged evidence set decides Degraded (backend {backend:?}, boundary {boundary:?})"
                );
            }
            _ => panic!("a failure report never decides Successful/FailedPreflight"),
        }

        // (6) THE RECOVERED TERMINAL — what `append_degraded` appends (the
        // decision's disposition, the case's recovery failure as the
        // reason): SAME status and reason; ONLY the honestly-changed slots
        // appear as remaining changes — the Unchanged class (observed ==
        // pre-push) is never a remaining change, every
        // Desired/Diverged/Unknown slot is.
        let expected_status = disposition.status();
        let terminal = LedgerTerminal::new(
            crate::remote::helper::now_rfc3339_ts(),
            kernel::terminal::intent_digest(&intent),
            crate::kernel::terminal::NonSuccessfulDisposition::from_decision(disposition),
            Some(failure.reason().to_string()),
        );
        assert_eq!(
            terminal.status(),
            expected_status,
            "the recovered terminal carries the DECISION's status (backend {backend:?}, boundary {boundary:?})"
        );
        assert_eq!(terminal.reason(), Some(failure.reason()));
        match &terminal.disposition() {
            TerminalDisposition::Degraded(_) => {
                let remaining = terminal
                    .remaining_changes(&intent)
                    .expect("a Degraded terminal derives remaining changes");
                assert_eq!(
                    remaining.len(),
                    1,
                    "a non-Unchanged slot is the one remaining change ({class:?}, {backend:?})"
                );
                assert!(
                    remaining.contains_key(&slot),
                    "a {class:?} slot is a remaining change (its observed state differs from pre-push or is unknown)"
                );
            }
            _ => {
                assert!(
                    terminal.remaining_changes(&intent).is_none(),
                    "a FailedRolledBack terminal derives no remaining changes"
                );
            }
        }
    }

    /// THE BINDING-JUDGMENT CALL, pinned: a selected slot that is NO LONGER
    /// a configured member can have a KNOWN live generation (a successful
    /// backend read) but NO physical binding source — the evidence records
    /// `binding: Unknown` (never the intent's frozen snapshot binding, which
    /// would claim a location that no longer exists). Under an ABSENT
    /// current the non-member binding is `KnownAbsent` (consistent with the
    /// same-read rule: the reads succeeded and showed no state at all).
    #[test]
    fn non_member_slot_evidence_has_unknown_binding_under_a_known_generation() {
        let desired = test_generation_id("non-member-d");
        let evidence =
            recovery_evidence_from_backend(BackendObservation::Live(desired.clone()), None);
        assert_eq!(
            evidence.observation,
            Observation::Known(ObservedGeneration {
                generation: desired
            }),
            "a successful backend read still records the live generation for a non-member"
        );
        match &evidence.binding {
            Observation::Unknown(e) => assert!(
                e.message.contains("not a configured member"),
                "a non-member slot has NO binding source — Unknown, got {e:?}"
            ),
            b => panic!("a non-member's binding must be Unknown, got {b:?}"),
        }
        assert_eq!(evidence.error, None);
        // The consistent absent-current choice: a successful status read
        // showing no current yields an absent binding too (nothing to bind).
        let absent = recovery_evidence_from_backend(BackendObservation::Absent, None);
        assert_eq!(absent.binding, Observation::KnownAbsent);
        assert_eq!(absent.observation, Observation::KnownAbsent);
    }

    proptest! {
        // THE SPEC'S ACCEPTANCE GATE (bounded cases, fixed seed, no failure
        // persistence — house style): every generated (desired, pre-push,
        // backend result, recovery failure, persistence boundary) case —
        // failures at EVERY persistence boundary (the preflight terminal
        // append — NOW PROPAGATED, the marker writes, the finalize refusal;
        // the intent-append boundary is the fourth: it leaves NO pending
        // attempt to classify and the push reports the append failure —
        // pinned by the integration fault test
        // [`intent_persist_fault_leaves_remote_untouched`]) crossed with the
        // live-state evidence (original pre-push / desired /
        // third generation / absent / read-error) — yields a recovered
        // terminal whose per-slot observations are the BACKEND's facts — a
        // `Known` observed generation implies a successful backend read of
        // that generation (the terminal NEVER shows the desired state when
        // the backend reports a different generation), an absent backend
        // yields `KnownAbsent`, a failed read `Unknown(error)`; the binding
        // is `Known` (the slot's current configured binding) under the same
        // successful read; a slot verified at its desired generation through
        // a backend read preserves that verified evidence; and the terminal
        // class follows THE ONE DECISION — recovery and uninterrupted
        // execution produce the SAME classification for the SAME evidence:
        // the EXACT PRE-PUSH state (including the preflight-terminal-append
        // boundary) settles `FailedRolledBack` (never `Degraded`), any
        // Desired/Diverged/Unknown delta settles `Degraded` with exactly
        // those slots as remaining changes.
        #![proptest_config(ProptestConfig {
            cases: 64,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn degraded_terminal_records_backend_observed_facts_never_desired_state(
            case in arbitrary_evidence_case(),
        ) {
            run_evidence_case(case);
        }
    }
}
