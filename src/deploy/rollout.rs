//! EXECUTION SEMANTICS: the per-slot rollout machinery.
//!
//! The deployment-order batch loop, failure-policy compensation and
//! attempt-status derivation, result/status/disposition shaping, the
//! post-mutation status decision, and the per-server mutation pipeline
//! (`process_server`: publish/swap/activate/verify/commit per slot).

use crate::config::FailurePolicy;
use crate::config::ProjectConfig;
use crate::config::ServerDef;
use crate::config::SlotConfig;
use crate::deploy::plan::PlannedAssignment;
use crate::deploy::push::slot_vars;
use crate::error::Error;
use crate::error::Result;
use crate::identity::ArtifactRef;
use crate::identity::BehaviorContract;
use crate::identity::DeploymentId;
use crate::identity::GenerationId;
use crate::identity::OperationId;
use crate::identity::ReleaseId;
use crate::identity::SlotId;
use crate::identity::TargetName;
use crate::ledger::BehaviorIndex;
use crate::ledger::DeploymentStatus;
use crate::ledger::Observation;
use crate::ledger::ObservationError;
use crate::ledger::ObservedGeneration;
use crate::ledger::SlotAttemptState;
use crate::ledger::SlotOutcome;
use crate::ledger::SlotOutcomeKind;
use crate::ledger::SlotPlan;
use crate::ledger::SlotResult;
use crate::ledger::SlotTable;
use crate::ledger::TerminalDisposition;
use crate::remote::canonical as tree;
use crate::remote::helper::RemoteHelper;
use crate::remote::helper::RemoteStatus;
use crate::remote::layout;
use crate::remote::transport::Remote;
use crate::store::local::LocalStore;
use crate::verify::command::run_verification;
use crate::verify::systemd::run_activation;
use crate::verify::systemd::validate_artifact_paths;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

// ---- batching: deployment-order batch loop ----

// The deployment-order batch loop (A1 deployment semantics).
//
// `run_batches` executes the step-10/11/12 batch loop of the push
// transaction: the SELECTED slots are processed in `batch_size`-sized
// batches in deployment order (the plan's assignment order), each slot via
// [`process_server`], stopping the whole push after
// the first failed batch when `stop_on_failure` is set. Extracted from the
// old `push::engine` spine ([`crate::deploy::push`]); `push_inner` consumes
// the outcome and hands the failure-policy signals to
// [`apply_failure_policy`]. The never-started
// `Skipped` filler that completes the result table lives in
// [`fill_skipped_slots`] (in the results section below).

/// The outcome of one deployment-order batch run: the per-slot results
/// (every SELECTED slot appears — never-started slots are filled as
/// `Skipped` with their reconciled current assignment via
/// [`fill_skipped_slots`]), plus the failure-policy signals: which slots this
/// deployment advanced, which compensated, which never advanced (pre-swap
/// failure or compare-and-swap skip), and whether any slot failed.
pub(crate) struct BatchRun {
    pub(crate) results: BTreeMap<SlotId, SlotResult>,
    pub(crate) advanced: Vec<SlotId>,
    pub(crate) compensated: Vec<SlotId>,
    pub(crate) never_advanced: Vec<SlotId>,
    pub(crate) had_failure: bool,
}

// 16 parameters: one batch run is the full per-slot publication context
// (data: assignments, behavior index, plan/statuses/generations, the
// already-open remotes/helpers; policy: batch_size, stop_on_failure) plus
// the deployment identity. Bundling the policy half into one settings struct
// is a dedicated refactor (deferred: `run_batches` is a straight extraction
// of the `push_inner` batch loop — the allow documents the deliberate
// choice, mirroring `push_inner` itself).
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_batches(
    assignments: &[PlannedAssignment],
    behavior_index: &BehaviorIndex,
    members: &[(&SlotConfig, &ServerDef)],
    config: &ProjectConfig,
    target_name: &str,
    store: &LocalStore,
    remotes: &HashMap<SlotId, Box<dyn Remote>>,
    helpers: &HashMap<SlotId, RemoteHelper>,
    statuses: &HashMap<SlotId, RemoteStatus>,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
    plan_servers: &BTreeMap<SlotId, SlotPlan>,
    new_gen: &HashMap<SlotId, GenerationId>,
    servers_order: &[SlotId],
    batch_size: usize,
    stop_on_failure: bool,
) -> Result<BatchRun> {
    let mut results: BTreeMap<SlotId, SlotResult> = BTreeMap::new();
    let mut advanced: Vec<SlotId> = Vec::new();
    let mut compensated: Vec<SlotId> = Vec::new();
    // Pre-swap failures (never advanced): the slot's outcome records the
    // ACTUAL observed generation (the post-mutation status read below),
    // never the desired one — the outcome's generation field is the observed
    // post-state the remaining-changes derivation compares against pre_push.
    let mut never_advanced: Vec<SlotId> = Vec::new();
    let mut had_failure = false;

    let mut idx = 0;
    'batches: while idx < servers_order.len() {
        let end = (idx + batch_size).min(servers_order.len());
        for sid in &servers_order[idx..end] {
            let a = assignments
                .iter()
                .find(|x| &x.placement_slot == sid)
                .unwrap();
            // Select the assigned slot's OWN (release, variant) frozen
            // behavior contract (never the caller's current variant file, and
            // never another release's contract) before
            // activation/verification. Coverage was validated before any
            // remote mutation, so a miss here is an internal invariant
            // violation: record a per-slot failure instead of panicking.
            let Some(variant_behavior) = behavior_index
                .get(&a.artifact.release)
                .and_then(|m| m.get(a.artifact.variant.as_str()))
            else {
                had_failure = true;
                results.insert(
                    sid.clone(),
                    SlotResult {
                        slot_id: sid.clone(),
                        outcome: SlotOutcomeKind::Failed,
                        generation: Some(new_gen[sid].clone()),
                        compensated: false,
                        error: Some(format!(
                            "internal: no behavior contract for variant '{}' after coverage check",
                            a.artifact.variant
                        )),
                        observation_error: None,
                    },
                );
                if stop_on_failure {
                    break 'batches;
                }
                continue;
            };
            let variant_behavior_sha =
                crate::verify::release::behavior_contract_digest(variant_behavior);
            let vars = slot_vars(
                members,
                config,
                target_name,
                sid,
                &a.artifact,
                Some(deployment_id),
                Some(&new_gen[sid]),
            )?;
            let outcome = process_server(
                store,
                remotes[sid].as_ref(),
                &helpers[sid],
                op_id,
                deployment_id,
                target_name,
                &a.artifact,
                &new_gen[sid],
                plan_servers[sid].expected_generation.as_ref(),
                variant_behavior,
                &variant_behavior_sha,
                &vars,
                config,
            )?;
            let ServerProc {
                kind,
                generation,
                did_advance,
                did_compensate,
                error,
            } = outcome;
            if kind == SlotOutcomeKind::Failed {
                had_failure = true;
            }
            if did_compensate {
                compensated.push(sid.clone());
            } else if did_advance {
                // Any slot this deployment advanced — Activated, or a
                // post-swap failure whose compensation failed — remains a
                // "still-advanced" server for the failure-policy pass and the
                // status decision. Pre-swap failures (never advanced) are NOT
                // included: for them `advanced.is_empty()` correctly yields
                // `FailedRolledBack` (nothing to roll back).
                advanced.push(sid.clone());
            } else {
                // A pre-swap failure (never advanced) or a compare-and-swap
                // skip: the slot's outcome records the ACTUAL observed
                // generation (the post-mutation status read below), never the
                // desired one.
                never_advanced.push(sid.clone());
            }
            results.insert(
                sid.clone(),
                SlotResult {
                    slot_id: sid.clone(),
                    outcome: kind,
                    generation: Some(generation),
                    compensated: did_compensate,
                    error,
                    observation_error: None,
                },
            );
            if had_failure && stop_on_failure {
                break 'batches;
            }
        }
        idx = end;
    }

    // Any slot never started (e.g. skipped after an earlier failure under
    // stop_on_failure) still appears in the attempt, with its reconciled
    // current assignment rather than a generated desired generation. The
    // filler lives in [`fill_skipped_slots`] (the
    // result-table shaping module).
    fill_skipped_slots(&mut results, assignments, statuses);
    Ok(BatchRun {
        results,
        advanced,
        compensated,
        never_advanced,
        had_failure,
    })
}

// ---- failure: failure policies + compensation pass ----

// Failure-policy semantics (A1 deployment semantics).
//
// The step-13 batch compensation pass and the step-14 attempt-status
// derivation of the push transaction ([`crate::deploy::push`]): under
// [`FailurePolicy::RollbackChanged`] every server a later failed batch had
// already advanced is compensated back to its pre-push generation (a failed
// compensation leaves the slot advanced and the attempt `Degraded`); under
// [`FailurePolicy::LeaveChanged`] the advances are retained deliberately
// and the attempt is `Degraded`. Also owns the never-advanced outcome
// fix-up (`record_never_advanced_outcomes`): a pre-swap failure records the
// ACTUAL observed post-state, never the desired generation.

// 16 parameters: one failure-policy pass is the full compensation context
// (data: the plan, the still-advanced/compensated signals and results it
// mutates, the already-open remotes/helpers; policy: the typed failure
// policy + config) plus the deployment identity. Bundling the policy half
// into one settings struct is a dedicated refactor (deferred: the pass is a
// straight extraction of the `push_inner` step-13/14 blocks — the allow
// documents the deliberate choice, mirroring `push_inner` itself).
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_failure_policy(
    had_failure: bool,
    failure_policy: FailurePolicy,
    assignments: &[PlannedAssignment],
    members: &[(&SlotConfig, &ServerDef)],
    config: &ProjectConfig,
    target_name: &str,
    store: &LocalStore,
    remotes: &HashMap<SlotId, Box<dyn Remote>>,
    helpers: &HashMap<SlotId, RemoteHelper>,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
    plan_servers: &BTreeMap<SlotId, SlotPlan>,
    new_gen: &HashMap<SlotId, GenerationId>,
    advanced: &mut Vec<SlotId>,
    compensated: &mut Vec<SlotId>,
    results: &mut BTreeMap<SlotId, SlotResult>,
) -> Result<DeploymentStatus> {
    // 13. Failure policy compensation of still-advanced servers. The policy
    // is matched EXHAUSTIVELY (no `_ =>` fallback, no string compare):
    //
    // * [`FailurePolicy::RollbackChanged`] (the default) — postcondition:
    //   every server whose batch already advanced when a later batch failed
    //   is COMPENSATED back to its pre-push generation. A compensation
    //   failure (e.g. prior behavior unavailable, or activation/verification
    //   failed during rollback) is reported as a failed compensation rather
    //   than aborting the whole push; the slot stays advanced and the
    //   attempt is marked Degraded.
    // * [`FailurePolicy::LeaveChanged`] — postcondition: the earlier
    //   successfully-mutated batches are RETAINED deliberately; no
    //   compensation pass runs and the attempt ends Degraded with the mixed
    //   per-server state.
    if had_failure {
        match failure_policy {
            FailurePolicy::RollbackChanged => {
                for sid in &*advanced {
                    let prior = plan_servers[sid].expected_generation.as_ref();
                    let vars = slot_vars(
                        members,
                        config,
                        target_name,
                        sid,
                        &plan_servers[sid].artifact,
                        Some(deployment_id),
                        Some(&new_gen[sid]),
                    )?;
                    let ok = compensate_server(
                        store,
                        remotes[sid].as_ref(),
                        &helpers[sid],
                        op_id,
                        deployment_id,
                        prior,
                        &new_gen[sid],
                        config,
                        &vars,
                    )
                    .unwrap_or_default();
                    if ok {
                        compensated.push(sid.clone());
                        if let Some(r) = results.get_mut(sid) {
                            r.compensated = true;
                            r.outcome = SlotOutcomeKind::Restored;
                        }
                    }
                }
                advanced.retain(|s| !compensated.contains(s));
            }
            FailurePolicy::LeaveChanged => {
                // Deliberate retention: earlier batches keep their new
                // state, so no compensation pass runs at all.
            }
        }
    }

    // 14. Determine attempt status — again an EXHAUSTIVE match on the typed
    // policy (no string compare, no fallback): a failed push is
    // `FailedRolledBack` under `RollbackChanged` when every advanced server
    // was compensated (or nothing had advanced), `Degraded` when any
    // compensation failed; under `LeaveChanged` a failed push is always
    // `Degraded` (the advances are retained deliberately).
    let status = if !had_failure {
        DeploymentStatus::Successful
    } else {
        match failure_policy {
            FailurePolicy::RollbackChanged => {
                if compensated.len() == assignments.len() || advanced.is_empty() {
                    DeploymentStatus::FailedRolledBack
                } else {
                    DeploymentStatus::Degraded
                }
            }
            FailurePolicy::LeaveChanged => DeploymentStatus::Degraded,
        }
    };
    Ok(status)
}

/// A pre-swap failure (never advanced) records the ACTUAL observed
/// post-state — the outcome's observation is the observed post-state the
/// remaining-changes derivation compares against pre_push, never the
/// desired generation. The post-mutation status read reflects the true
/// state: the slot never advanced, so it is still on its pre-push
/// generation. The observation is written into the wire's OBSERVATION
/// fields only, INDEPENDENTLY of the outcome's operation error (`error`,
/// which already carries the failure that stopped the slot — e.g.
/// "swap failed: ..."): a FAILED read is `Unknown(error)` — the state is
/// unknown, and an unknown state is NOT evidence of no change — so the
/// wire records `generation: None` with the observation error in
/// `observation_error` (the wire → domain conversion reads that back as
/// `Unknown`, never as "unchanged"); a successful read showing no state
/// is `KnownAbsent` (generation `None`, no observation error). The
/// operation error is NEVER rewritten by the observation. Skipped
/// outcomes already record the reconciled current assignment.
pub(crate) fn record_never_advanced_outcomes(
    results: &mut BTreeMap<SlotId, SlotResult>,
    actual_observations: &BTreeMap<SlotId, Observation<ObservedGeneration>>,
    never_advanced: &[SlotId],
) {
    for sid in never_advanced {
        if let Some(r) = results.get_mut(sid)
            && r.outcome == SlotOutcomeKind::Failed
        {
            match actual_observations.get(sid) {
                Some(Observation::Known(og)) => {
                    r.generation = Some(og.generation.clone());
                }
                Some(Observation::Unknown(e)) => {
                    r.generation = None;
                    r.observation_error = Some(e.message.clone());
                }
                Some(Observation::KnownAbsent) | None => {
                    r.generation = None;
                    r.observation_error = None;
                }
            }
        }
    }
}

// ---- results: result-table shaping ----

// Result-table shaping (A1 deployment semantics).
//
// The per-slot result table of a push attempt is shaped in two places:
//
// * [`fill_skipped_slots`] — every SELECTED slot appears in the results even
//   when the batch loop never started it (a later failed batch under
//   `stop_on_failure`): the filler inserts a `Skipped` outcome carrying the
//   slot's RECONCILED current assignment (the observed generation, never a
//   generated desired one). Extracted from the old `push::engine` batch loop
//   (the batching section above).
// * [`observe_actual_servers`] — the post-mutation observation of each
//   slot's REAL final state, read from the remote generation it currently
//   points at (never the desired plan values), as the two parallel tables
//   the terminal event and the never-advanced outcome fix-up consume.
//
// The never-advanced OUTCOME fix-up that consumes the generation-half
// observation ([`record_never_advanced_outcomes`])
// stays with the failure-policy pass (failure section), where
// the degraded derivation and the never-advanced handling are documented
// together; the final outcome-map assembly (the `results` clone feeding the
// terminal append) is spine glue in [`crate::deploy::push::push_inner`].

/// Any slot never started (e.g. skipped after an earlier failure under
/// `stop_on_failure`) still appears in the attempt, with its reconciled
/// current assignment rather than a generated desired generation.
pub(crate) fn fill_skipped_slots(
    results: &mut BTreeMap<SlotId, SlotResult>,
    assignments: &[PlannedAssignment],
    statuses: &HashMap<SlotId, RemoteStatus>,
) {
    for a in assignments {
        if !results.contains_key(&a.placement_slot) {
            let cur = statuses
                .get(&a.placement_slot)
                .and_then(|s| s.current_generation.clone());
            results.insert(
                a.placement_slot.clone(),
                SlotResult {
                    slot_id: a.placement_slot.clone(),
                    outcome: SlotOutcomeKind::Skipped,
                    generation: cur,
                    compensated: false,
                    error: None,
                    observation_error: None,
                },
            );
        }
    }
}

/// Observe each slot's *real* final state, read from the remote generation it
/// currently points at, rather than the desired plan values.
/// Failed/skipped/restored slots therefore report their actual artifact
/// instead of the desired one. The per-slot THREE-STATE OBSERVATION: the
/// actual's `artifact` is itself an [`Observation<ArtifactRef>`] — a FAILED
/// assignment read is `Observation::Unknown(error)`, a distinct value that
/// never looks like a known artifact (there is no sentinel artifact) — and
/// the parallel `actual_observations` map carries the GENERATION half of the
/// observation (a different fact, feeding the never-advanced outcomes below):
/// a FAILED post-mutation status read is `Unknown(error)`, never a `None`
/// that downstream code reads as "unchanged". The wire-shaped `actual_servers`
/// keeps the current on-disk shape — generation only — so the observation's
/// `Unknown` half is recorded into the never-advanced outcomes'
/// `observation_error` field, while the outcome's OWN operation error
/// (`error`) is left untouched.
pub(crate) fn observe_actual_servers(
    assignments: &[PlannedAssignment],
    helpers: &HashMap<SlotId, RemoteHelper>,
) -> (
    BTreeMap<SlotId, SlotAttemptState>,
    BTreeMap<SlotId, Observation<ObservedGeneration>>,
) {
    let mut actual_servers: BTreeMap<SlotId, SlotAttemptState> = BTreeMap::new();
    let mut actual_observations: BTreeMap<SlotId, Observation<ObservedGeneration>> =
        BTreeMap::new();
    for a in assignments {
        let sid = &a.placement_slot;
        let helper = &helpers[sid];
        let status = helper.status();
        let (actual, observation) = match status {
            Ok(s) => match s.current_generation {
                Some(g) => match helper.read_assignment(g.as_str()) {
                    Ok(asn) => (
                        SlotAttemptState {
                            artifact: Observation::Known(asn.artifact.clone()),
                            generation: Some(g.clone()),
                        },
                        Observation::Known(ObservedGeneration {
                            generation: g.clone(),
                        }),
                    ),
                    Err(e) => (
                        SlotAttemptState {
                            artifact: Observation::Unknown(ObservationError {
                                message: format!("assignment read failed: {e}"),
                            }),
                            generation: Some(g.clone()),
                        },
                        Observation::Unknown(ObservationError {
                            message: format!("assignment read failed: {e}"),
                        }),
                    ),
                },
                None => (
                    SlotAttemptState {
                        artifact: Observation::Known(a.artifact.clone()),
                        generation: None,
                    },
                    Observation::KnownAbsent,
                ),
            },
            Err(e) => (
                SlotAttemptState {
                    artifact: Observation::Known(a.artifact.clone()),
                    generation: None,
                },
                Observation::Unknown(ObservationError {
                    message: format!("status read failed: {e}"),
                }),
            ),
        };
        actual_servers.insert(sid.clone(), actual);
        actual_observations.insert(sid.clone(), observation);
    }
    (actual_servers, actual_observations)
}

// ---- status: post-mutation status / disposition ----

// Post-mutation status / disposition decision (A7 pending-commit demotion
// reasons).
//
// After the batches and the failure-policy pass
// ([`apply_failure_policy`]) derived the attempt's
// base status, this module decides the FINAL status and its terminal
// disposition:
//
// * [`decide_commit_status`] — the step-15 commit-marker step for an
//   otherwise-successful attempt. A marker that cannot be made durable
//   demotes the attempt to `PendingCommit` ("recoverable metadata failure"),
//   a live-generation mismatch after the swap demotes it to `Degraded`
//   ("commit diverged"), and a conflicting existing marker (`Error::Integrity`)
//   is a PERMANENT condition that finalizes `Degraded` ("marker integrity
//   conflict") rather than stranding the attempt as pending forever. The
//   same demotion applies when a slot's committed-transaction record write
//   failed (active but not durably bookkept).
// * [`disposition_for`] — the final status → [`TerminalDisposition`] mapping
//   (the domain truth table is structural): `FailedPreflight` carries
//   nothing, `FailedRolledBack` owns the outcome table as its compensation
//   report, `Degraded` owns the outcome table its remaining changes are
//   derived from. A `PendingCommit` status is NOT terminal at all — the
//   entry stays intent-only, the recoverable pending state a later push's
//   `reconcile_pending_commits` completes before its own no-op check.
//
// Extracted from the old `push::engine` spine ([`crate::deploy::push`]);
// `push_inner` appends the returned disposition as the terminal event.

/// The step-15 commit-marker decision for an otherwise-successful attempt,
/// plus the "active but not durably bookkept" demotion. Returns the final
/// commit status and the demotion reason (recorded alongside the final
/// transition so `deploy log` can explain why an attempt ended up
/// `PendingCommit` or `Degraded` — e.g. "recoverable metadata failure",
/// "commit diverged", "marker integrity conflict").
#[allow(clippy::too_many_arguments)]
pub(crate) fn decide_commit_status(
    status: &DeploymentStatus,
    results: &BTreeMap<SlotId, SlotResult>,
    helpers: &HashMap<SlotId, RemoteHelper>,
    servers_order: &[SlotId],
    new_gen: &HashMap<SlotId, GenerationId>,
    deployment_id: &DeploymentId,
    target_name: &str,
    op_id: &OperationId,
) -> (DeploymentStatus, Option<&'static str>) {
    let mut commit_status = status.clone();
    let mut commit_reason: Option<&'static str> = None;
    if *status == DeploymentStatus::Successful {
        // The full placement-slot set participating in this commit.
        let slot_ids: Vec<String> = servers_order
            .iter()
            .map(|s| s.as_str().to_string())
            .collect();
        for sid in servers_order {
            let helper = &helpers[sid];
            // Hold the lock for the whole commit step so a failure cannot leak it
            // (a `?` on a manual lock would otherwise leave the lock held).
            let _guard = match helper.acquire_lock_guard(op_id.as_str()) {
                Ok(g) => g,
                Err(_) => {
                    commit_status = DeploymentStatus::PendingCommit;
                    commit_reason = Some("recoverable metadata failure");
                    continue;
                }
            };
            // Check the generation *before* writing the marker; a mismatch means
            // another controller changed `current` and this marker would be wrong.
            let cur = match helper.status() {
                Ok(s) => s.current_generation,
                Err(_) => {
                    // Recoverable metadata failure: do not abort the whole push
                    // (which would leave the attempt unrecorded); mark the
                    // commit incomplete and keep going. A later push reconciles
                    // this `PendingCommit` attempt (see
                    // `reconcile_pending_commits`) before its own no-op check.
                    commit_status = DeploymentStatus::PendingCommit;
                    commit_reason = Some("recoverable metadata failure");
                    continue;
                }
            };
            if cur.as_ref().map(|g| g.as_str()) != Some(new_gen[sid].as_str()) {
                // The live generation no longer matches what we deployed: the
                // controller's view diverged, so this marker would be wrong.
                // Report Degraded rather than a falsely successful commit.
                commit_status = DeploymentStatus::Degraded;
                commit_reason = Some("commit diverged");
                continue;
            }
            match helper.write_commit_marker(
                deployment_id.as_str(),
                new_gen[sid].as_str(),
                &slot_ids,
                Some(target_name),
            ) {
                Err(Error::Integrity(_)) => {
                    // A conflicting marker already exists with different
                    // content: a concurrent controller recorded a different
                    // fact, or the remote state diverged/corrupted. This is a
                    // PERMANENT condition — retrying will never fix it, and
                    // leaving the attempt `PendingCommit` would strand it
                    // forever (every later push re-hits the same integrity
                    // error). Finalize as `Degraded` (no snapshot entry) rather
                    // than falsely reporting `Successful`.
                    commit_status = DeploymentStatus::Degraded;
                    commit_reason = Some("marker integrity conflict");
                    continue;
                }
                Err(_) => {
                    // Recoverable metadata failure writing the marker: the
                    // attempt is recorded `PendingCommit` and a later push's
                    // `reconcile_pending_commits` completes the marker set
                    // before its no-op check.
                    commit_status = DeploymentStatus::PendingCommit;
                    continue;
                }
                Ok(_) => {}
            }
            // `_guard` drops here, releasing the lock.
        }
    }

    // A server whose committed-transaction record write failed is still active
    // but not durably bookkept. Do not report the attempt as `Successful`:
    // demote to `PendingCommit` so the metadata gap is visible.
    if commit_status == DeploymentStatus::Successful {
        for sid in servers_order {
            if let Some(r) = results.get(sid)
                && r.outcome == SlotOutcomeKind::Activated
                && r.error.is_some()
            {
                commit_status = DeploymentStatus::PendingCommit;
                commit_reason = Some("recoverable metadata failure");
                break;
            }
        }
    }
    (commit_status, commit_reason)
}

/// Map the final status to its DISPOSITION (the domain truth table is
/// structural): FailedPreflight carries nothing (no slot touched),
/// FailedRolledBack owns the outcome table as its compensation report,
/// Degraded owns the outcome table its remaining changes are derived from
/// (the slots whose FINAL OBSERVED STATE differs from their pre_push state)
/// — the same derivation the read path applies, so the domain and the wire
/// conversion stay in sync. `PendingCommit` and any other status are refused:
/// only FailedPreflight / FailedRolledBack / Degraded reach the terminal
/// append.
pub(crate) fn disposition_for(
    status: &DeploymentStatus,
    outcomes: SlotTable<SlotOutcome>,
) -> Result<TerminalDisposition> {
    let disposition = match status {
        DeploymentStatus::FailedPreflight => TerminalDisposition::FailedPreflight,
        DeploymentStatus::FailedRolledBack => TerminalDisposition::FailedRolledBack { outcomes },
        DeploymentStatus::Degraded => {
            // The Degraded disposition's remaining changes are DERIVED from
            // the outcomes (the slots whose final observed state differs from
            // their pre_push state) — never stored. The conversion refuses a
            // Degraded wire whose outcomes are ALL restored (a
            // fully-compensated attempt must be `FailedRolledBack`, never
            // `Degraded`); a Degraded terminal whose outcomes are all
            // never-advanced (e.g. a `leave_changed` failure that advanced
            // nothing) is legitimate — the policy marks the attempt Degraded
            // even though no slot changed.
            if outcomes
                .values()
                .all(|r| r.outcome == SlotOutcomeKind::Restored)
            {
                return Err(Error::store(
                    "a Degraded terminal requires at least one non-restored outcome — none recorded"
                        .to_string(),
                ));
            }
            TerminalDisposition::Degraded { outcomes }
        }
        other => {
            return Err(Error::store(format!(
                "internal: cannot append a terminal for status {other:?} — only FailedPreflight / FailedRolledBack / Degraded reach the terminal append"
            )));
        }
    };
    Ok(disposition)
}

// ---- compensation: per-slot prior-generation restore ----

// PER-SLOT COMPENSATION (A1 step 11): restore the prior generation after a
// failed activation/verification (or remove `current` on a first deploy),
// re-running the PRIOR generation's stored behavior contract with the PRIOR
// assignment's identity, and only while `current` still names the generation
// the failed push advanced (compare-and-swap). Consumed by the per-server
// process ([`process_server`]) and by the
// failure-policy pass (failure section).

/// Restore the prior generation (or remove `current` on first deploy). Uses the
/// prior generation's stored behavior contract rather than the caller's current
/// configuration. `advanced_gen` is the generation this slot was just advanced
/// to; it is used as the compare-and-swap precondition so a concurrent
/// controller cannot have its `current` clobbered. `template_vars` supplies the
/// slot context (deploy_dir, application, ...); the VARIANT is overridden with
/// the prior assignment's variant, because compensation re-runs the PRIOR
/// generation's contract. Returns true if compensation restored prior state.
// 11 parameters mirror `process_server` (same rationale: a settings-struct
// consolidation of the trailing config/vars args is a dedicated refactor;
// the allow documents the deliberate choice).
#[allow(clippy::too_many_arguments)]
pub(crate) fn compensate_server(
    _store: &LocalStore,
    remote: &dyn Remote,
    helper: &RemoteHelper,
    op_id: &OperationId,
    _deployment_id: &DeploymentId,
    prior_gen: Option<&GenerationId>,
    advanced_gen: &GenerationId,
    _config: &ProjectConfig,
    template_vars: &crate::remote::canonical::TemplateVars,
) -> Result<bool> {
    // Hold the slot's mutation lock for the duration of compensation. Re-acquiring
    // is idempotent when the same op_id already holds it (process_server holds it
    // via a guard that is still alive on the in-process failure paths).
    let _guard = match helper.acquire_lock_guard(op_id.as_str()) {
        Ok(g) => g,
        Err(_) => return Ok(false),
    };
    match prior_gen {
        Some(prior) => {
            // Load the prior generation's behavior contract from the remote.
            let prior_assignment = match helper.read_assignment(prior.as_str()) {
                Ok(a) => a,
                Err(_) => return Ok(false),
            };
            // Load the prior generation's behavior contract from the remote. If it
            // is unavailable we cannot verify what we are restoring, so we must
            // not pretend restoration succeeded by substituting a default
            // contract: report the failure so the attempt is marked Degraded.
            let prior_behavior = helper
                .read_behavior(
                    &prior_assignment.artifact.release,
                    prior_assignment.artifact.variant.as_str(),
                )
                .map_err(|e| {
                    Error::remote(format!("compensation: prior behavior unavailable: {e}"))
                })?;
            // Compare-and-swap: only roll back if `current` still points at the
            // generation we just activated. Otherwise another controller changed
            // it and we must not clobber their state.
            if helper
                .swap_current(Some(advanced_gen.as_str()), prior.as_str(), op_id.as_str())
                .is_err()
            {
                return Ok(false);
            }
            let root = remote
                .root()
                .join(layout::generation(prior.as_str()))
                .join("root");
            // Re-run prior activation contract + verification. A failure means the
            // service was not actually restored to prior behavior, so propagate
            // it as a compensation failure (the attempt is marked Degraded).
            // The prior contract is rendered with the PRIOR assignment: its own
            // release (the immutable ReleaseId), variant, tree, AND the prior
            // deployment identity (`deployment_id`/`generation`) move together
            // via `with_assignment`, so a restored slot never renders a torn
            // combination (e.g. the prior variant with the desired release, or
            // the prior artifact with the failed generation's deployment id).
            let prior_vars = template_vars.with_assignment(&prior_assignment);
            run_activation(remote, &root, &prior_behavior.activation, &prior_vars)
                .map_err(|e| Error::remote(format!("compensation activation failed: {e}")))?;
            run_verification(remote, &prior_behavior.verification, &prior_vars)
                .map_err(|e| Error::remote(format!("compensation verification failed: {e}")))?;
            Ok(true)
        }
        None => {
            // First deploy: remove `current` only if it still points at the
            // generation we advanced (compare-and-swap style).
            Ok(helper
                .remove_current_if(advanced_gen.as_str())
                .unwrap_or(false))
        }
    }
}

#[cfg(test)]
mod compensation_tests {
    use super::*;
    use crate::identity::{ArtifactRef, TreeDigest, VariantName, test_deployment_id};
    use crate::ledger::SlotOutcomeKind;
    use server_tests::{Harness, NONE_TOML, NONE_VARIANT, SYSTEMD_TOML, SYSTEMD_VARIANT};
    use std::os::unix::fs::PermissionsExt;

    /// Compensation re-runs the PRIOR generation's activation contract with the
    /// PRIOR assignment's identity: the unit it installs renders the PRIOR
    /// immutable release id (`{{ release }}`), variant, tree, AND the prior
    /// deployment identity (`{{ deployment_id }}`/`{{ generation }}`) — never a
    /// torn mix of the desired release with the prior variant, and never the
    /// failed generation's deployment id. This pins the
    /// `TemplateVars::with_assignment` path through the real systemd adapter.
    #[test]
    fn compensation_renders_prior_artifact_release_id() {
        let _lock = crate::testutil::ENV_LOCK.lock().unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let bindir = tmp.path().join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let fake = bindir.join("systemctl");
        std::fs::write(&fake, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let config_home = tmp.path().join("xdg");
        let old_path = std::env::var_os("PATH");
        let old_xdg = std::env::var_os("XDG_CONFIG_HOME");
        unsafe {
            std::env::set_var(
                "PATH",
                format!(
                    "{}:{}",
                    bindir.display(),
                    old_path
                        .as_ref()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default()
                ),
            );
            std::env::set_var("XDG_CONFIG_HOME", &config_home);
        }

        let outcome = (|| {
            let h = Harness::new(
                SYSTEMD_TOML,
                SYSTEMD_VARIANT,
                &[
                    ("build/output/app/server", "v1"),
                    ("deployment/common/README", "common"),
                    (
                        "units/example.service",
                        "[Service]\nExecStart=/srv/eng/bin/server --release={{ release }} --variant={{ variant }} --tree={{ tree }} --deployment={{ deployment_id }} --generation={{ generation }}\n",
                    ),
                ],
            );
            // First deploy: establishes the PRIOR generation whose assignment
            // carries the immutable release id of the PRIOR assignment and the PRIOR
            // deployment identity (deployment_id + generation_id).
            let first = h.run(None);
            assert_eq!(
                first.kind,
                SlotOutcomeKind::Activated,
                "first deploy must activate: {:?}",
                first.error
            );
            // The prior generation's assignment is the source of truth for the
            // five values compensation must render: read it back from the
            // remote record (generations/<gen>/assignment.json).
            let prior_assignment = h
                .helper()
                .read_assignment(first.generation.as_str())
                .unwrap();

            // A subsequent (desired) push fails activation and the engine
            // compensates back to the prior generation. Drive the same
            // compensation directly: the desired artifact's vars carry a
            // DIFFERENT release/tree AND a DIFFERENT (failed) deployment
            // identity than the prior assignment.
            let op_id = OperationId::generate();
            let failed_deployment_id = DeploymentId::generate();
            let failed_generation = GenerationId::generate();
            let members = h.config.target_slots("t1").unwrap();
            let (slot, server) = members[0];
            let desired = ArtifactRef {
                release: crate::identity::test_release_id("rel-sha256-desired"),
                variant: VariantName::new("standard"),
                tree: TreeDigest::new("desired-tree"),
            };
            let desired_vars = crate::remote::canonical::TemplateVars::slot(
                slot.deploy_dir(),
                desired.variant.as_str(),
                h.config.application().as_str(),
                desired.release.as_str(),
                "t1",
                server.id.as_str(),
            )
            .with_server(server.user(), server.address(), server.port())
            .with_slot_id(&slot.id)
            .with_deployment(
                Some(&failed_deployment_id),
                Some(&failed_generation),
                Some(&desired.tree),
            );
            let helper = h.helper();
            // The prior generation's behavior must be readable from the remote
            // (in a real push, push_inner publishes it; the harness bypasses
            // push_inner, so publish it the same way).
            let behaviors =
                std::collections::BTreeMap::from([("standard".to_string(), h.behave())]);
            helper
                .publish_release(
                    h.harness_release_id().as_str(),
                    &h.harness_release_json(),
                    &serde_json::to_string(&behaviors).unwrap(),
                )
                .unwrap();
            let ok = compensate_server(
                &h.store,
                &h.remote,
                &helper,
                &op_id,
                &failed_deployment_id,
                Some(&first.generation),
                &first.generation, // current still points at the first generation
                &h.config,
                &desired_vars,
            )
            .map_err(|e| e.to_string())?;
            assert!(ok, "compensation must restore the prior generation");

            // The installed unit was re-rendered with the PRIOR assignment:
            // its own immutable release id, variant, tree, AND the prior
            // deployment identity (`deployment_id`/`generation`) — never the
            // desired release/tree or the failed generation's identities the
            // failed push would have rendered.
            let installed =
                std::fs::read_to_string(config_home.join("systemd/user/example.service")).unwrap();
            assert!(
                installed.contains(&format!(
                    "--release={}",
                    prior_assignment.artifact.release.as_str()
                )),
                "compensated unit must render the PRIOR release id, got: {installed}"
            );
            assert!(
                !installed.contains("rel-sha256-desired"),
                "compensated unit must not render the desired release, got: {installed}"
            );
            assert!(
                installed.contains(&format!(
                    "--variant={}",
                    prior_assignment.artifact.variant.as_str()
                )) && installed.contains(&format!(
                    "--tree={}",
                    prior_assignment.artifact.tree.as_str()
                )),
                "compensated unit must render the prior variant/tree, got: {installed}"
            );
            assert!(
                installed.contains(&format!(
                    "--deployment={}",
                    prior_assignment.deployment_id.as_str()
                )),
                "compensated unit must render the PRIOR deployment id, got: {installed}"
            );
            assert!(
                installed.contains(&format!(
                    "--generation={}",
                    prior_assignment.generation_id.as_str()
                )),
                "compensated unit must render the PRIOR generation id, got: {installed}"
            );
            assert!(
                !installed.contains(&format!("--deployment={}", failed_deployment_id.as_str()))
                    && !installed.contains(&format!("--generation={}", failed_generation.as_str())),
                "compensated unit must not render the failed generation's identities, got: {installed}"
            );
            Ok::<(), String>(())
        })();
        match old_path {
            Some(p) => unsafe { std::env::set_var("PATH", p) },
            None => unsafe { std::env::remove_var("PATH") },
        }
        match old_xdg {
            Some(v) => unsafe { std::env::set_var("XDG_CONFIG_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_CONFIG_HOME") },
        }
        outcome.unwrap();
    }

    /// Compensation is a compare-and-swap: it restores the prior generation
    /// only while `current` still names the generation the failed push
    /// advanced. If a concurrent controller has since moved `current`
    /// elsewhere, compensation REFUSES (returns `false`) and leaves the
    /// foreign `current` untouched.
    #[test]
    fn compensation_refuses_when_current_moved() {
        let h = Harness::new(
            NONE_TOML,
            NONE_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
            ],
        );
        // First deploy: the PRIOR generation g1 is live.
        let first = h.run(None);
        assert_eq!(first.kind, SlotOutcomeKind::Activated);
        let helper = h.helper();

        // The failed push advanced to g2 (its generation record exists, and
        // `current` moved to g2)...
        let g2 = GenerationId::generate();
        helper
            .create_generation(
                "op2",
                &crate::remote::helper::GenerationAssignment {
                    deployment_id: test_deployment_id("d2"),
                    generation_id: g2.clone(),
                    artifact: ArtifactRef {
                        release: h.harness_release_id(),
                        variant: crate::identity::VariantName::new("standard"),
                        tree: h.tree.clone(),
                    },
                    behavior_sha256: "b".into(),
                    prior_generation: Some(first.generation.clone()),
                    created_at: crate::remote::helper::now_rfc3339(),
                    target: Some(crate::identity::TargetName::new("t1")),
                },
            )
            .unwrap();
        helper
            .swap_current(Some(first.generation.as_str()), g2.as_str(), "op2")
            .unwrap();
        // ...but a concurrent controller moved `current` to g3 BEFORE this
        // op's compensation ran: the CAS precondition (current == g2) fails.
        let g3 = GenerationId::generate();
        helper
            .create_generation(
                "op3",
                &crate::remote::helper::GenerationAssignment {
                    deployment_id: test_deployment_id("d3"),
                    generation_id: g3.clone(),
                    artifact: ArtifactRef {
                        release: h.harness_release_id(),
                        variant: crate::identity::VariantName::new("standard"),
                        tree: h.tree.clone(),
                    },
                    behavior_sha256: "b".into(),
                    prior_generation: Some(g2.clone()),
                    created_at: crate::remote::helper::now_rfc3339(),
                    target: Some(crate::identity::TargetName::new("t1")),
                },
            )
            .unwrap();
        helper
            .swap_current(Some(g2.as_str()), g3.as_str(), "op3")
            .unwrap();

        // The prior generation's behavior must be readable for compensation to
        // attempt restoration (it still refuses on the CAS before using it).
        let behaviors = std::collections::BTreeMap::from([("standard".to_string(), h.behave())]);
        helper
            .publish_release(
                h.harness_release_id().as_str(),
                &h.harness_release_json(),
                &serde_json::to_string(&behaviors).unwrap(),
            )
            .unwrap();

        let members = h.config.target_slots("t1").unwrap();
        let (slot, server) = members[0];
        let vars = crate::remote::canonical::TemplateVars::slot(
            slot.deploy_dir(),
            "standard",
            h.config.application().as_str(),
            "rel-sha256-desired",
            "t1",
            server.id.as_str(),
        )
        .with_server(server.user(), server.address(), server.port())
        .with_slot_id(&slot.id)
        .with_deployment(
            Some(&DeploymentId::generate()),
            Some(&GenerationId::generate()),
            Some(&h.tree),
        );
        let ok = compensate_server(
            &h.store,
            &h.remote,
            &helper,
            &OperationId::generate(),
            &DeploymentId::generate(),
            Some(&first.generation),
            &g2,
            &h.config,
            &vars,
        )
        .unwrap();
        assert!(
            !ok,
            "compensation must refuse when current no longer names the advanced generation"
        );
        // The foreign current (g3) survives untouched.
        let current = h.helper().status().unwrap().current_generation.unwrap();
        assert_eq!(
            current.as_str(),
            g3.as_str(),
            "the concurrent controller's current must survive a refused compensation"
        );
    }
}

// ---- server: per-server mutation pipeline ----

// Per-server mutation pipeline.
//
// `process_server` (publish, integrity re-verify, artifact-path validation,
// generation creation, atomic `current` swap, activation + verification with
// compensation — the compensation step itself lives in
// [`compensate_server`]), plus the
// tree-download helper and the per-process release-JSON publication cache
// shared with `push::engine`. Extracted from `push::engine`.

pub(crate) struct ServerProc {
    pub(crate) kind: SlotOutcomeKind,
    pub(crate) generation: GenerationId,
    /// True when this slot's `current` was advanced (the per-slot commit point
    /// was moved to the new generation) at some point during the attempt —
    /// either it still points there, or compensation moved it back. This is
    /// the failure-policy/status signal for "a server this deployment
    /// advanced", distinct from `did_compensate`: a pre-swap failure never
    /// advanced the slot (nothing to roll back, `FailedRolledBack` is
    /// vacuously accurate), while a post-swap failure whose compensation
    /// failed IS still changed from prior state and the attempt must be
    /// `Degraded`, never a falsely clean `FailedRolledBack`.
    pub(crate) did_advance: bool,
    pub(crate) did_compensate: bool,
    pub(crate) error: Option<String>,
}

// 13 parameters: the per-server deployment is the full publication context
// (data: store, remote, helper, op_id, deployment_id, target_name, artifact,
// new_gen, expected_gen; policy: behavior, behavior_sha256, template_vars,
// config). Bundling the policy half into one settings struct is a dedicated
// refactor (deferred: `process_server` is the single hottest function in the
// push path and every caller would change with no behavioral gain); the allow
// documents the deliberate choice.
#[allow(clippy::too_many_arguments)]
pub(crate) fn process_server(
    store: &LocalStore,
    remote: &dyn Remote,
    helper: &RemoteHelper,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
    target_name: &str,
    artifact: &ArtifactRef,
    new_gen: &GenerationId,
    expected_gen: Option<&GenerationId>,
    behavior: &BehaviorContract,
    behavior_sha256: &str,
    template_vars: &crate::remote::canonical::TemplateVars,
    config: &ProjectConfig,
) -> Result<ServerProc> {
    // Acquire the slot's mutation lock via an RAII guard so every return path
    // (including errors) releases it.
    let _guard = match helper.acquire_lock_guard(op_id.as_str()) {
        Ok(g) => g,
        Err(e) => {
            return Ok(ServerProc {
                kind: SlotOutcomeKind::Failed,
                generation: new_gen.clone(),
                did_advance: false,
                did_compensate: false,
                error: Some(format!("lock acquire failed: {e}")),
            });
        }
    };

    // Compare-and-swap precondition on current generation.
    let status = match helper.status() {
        Ok(s) => s,
        Err(e) => {
            return Ok(ServerProc {
                kind: SlotOutcomeKind::Failed,
                generation: new_gen.clone(),
                did_advance: false,
                did_compensate: false,
                error: Some(format!("status failed: {e}")),
            });
        }
    };
    if let Some(exp) = expected_gen
        && status.current_generation.as_ref().map(|g| g.as_str()) != Some(exp.as_str())
    {
        return Ok(ServerProc {
            kind: SlotOutcomeKind::Skipped,
            generation: exp.clone(),
            did_advance: false,
            did_compensate: false,
            error: Some(format!(
                "compare-and-swap precondition failed: current {:?} expected {exp}",
                status.current_generation
            )),
        });
    }

    // 1. Publish the staged tree (from incoming), reusing an existing object.
    if let Err(e) = helper.publish_from_incoming(deployment_id.as_str(), artifact.tree.as_str()) {
        return Ok(ServerProc {
            kind: SlotOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_advance: false,
            did_compensate: false,
            error: Some(format!("publish failed: {e}")),
        });
    }

    // 2. Canonically hash the remote tree and compare with the requested digest.
    //    Existing remote objects are re-verified here rather than trusted.
    let verify_tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => {
            return Ok(ServerProc {
                kind: SlotOutcomeKind::Failed,
                generation: new_gen.clone(),
                did_advance: false,
                did_compensate: false,
                error: Some(format!("tempdir: {e}")),
            });
        }
    };
    let object_rel = layout::tree_root(artifact.tree.as_str());
    if let Err(e) = download_tree_to_host(remote, &object_rel, verify_tmp.path()) {
        return Ok(ServerProc {
            kind: SlotOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_advance: false,
            did_compensate: false,
            error: Some(format!("download for verify failed: {e}")),
        });
    }
    let meta = match tree::canonicalize_tree(verify_tmp.path()) {
        Ok(m) => m,
        Err(e) => {
            return Ok(ServerProc {
                kind: SlotOutcomeKind::Failed,
                generation: new_gen.clone(),
                did_advance: false,
                did_compensate: false,
                error: Some(format!("canonicalize remote tree failed: {e}")),
            });
        }
    };
    if meta.tree_sha256 != artifact.tree.as_str() {
        return Ok(ServerProc {
            kind: SlotOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_advance: false,
            did_compensate: false,
            error: Some(format!(
                "integrity: remote tree digest {} does not match requested {}",
                meta.tree_sha256, artifact.tree
            )),
        });
    }

    // 3. Validate all declared artifact paths and types before changing current.
    if let Err(e) = validate_artifact_paths(remote, &object_rel, &behavior.activation) {
        return Ok(ServerProc {
            kind: SlotOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_advance: false,
            did_compensate: false,
            error: Some(format!("artifact validation: {e}")),
        });
    }

    // 4. Publish the release record (idempotent) and create the generation.
    if let Some((release_json, behavior_json)) =
        REMOTE_RELEASE_JSON.with(|c| c.borrow().get(&artifact.release).cloned())
        && let Err(e) =
            helper.publish_release(artifact.release.as_str(), &release_json, &behavior_json)
    {
        return Ok(ServerProc {
            kind: SlotOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_advance: false,
            did_compensate: false,
            error: Some(format!("publish release failed: {e}")),
        });
    }
    let assignment = crate::remote::helper::GenerationAssignment {
        deployment_id: deployment_id.clone(),
        generation_id: new_gen.clone(),
        artifact: artifact.clone(),
        behavior_sha256: behavior_sha256.to_string(),
        prior_generation: expected_gen.cloned(),
        created_at: crate::remote::helper::now_rfc3339(),
        target: Some(TargetName::parse(target_name).expect("target name is a safe segment")),
    };
    if let Err(e) = helper.create_generation(op_id.as_str(), &assignment) {
        return Ok(ServerProc {
            kind: SlotOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_advance: false,
            did_compensate: false,
            error: Some(format!("create generation failed: {e}")),
        });
    }
    if let Err(e) = helper.transaction_record(op_id.as_str(), "prepared") {
        return Ok(ServerProc {
            kind: SlotOutcomeKind::Failed,
            generation: new_gen.clone(),
            did_advance: false,
            did_compensate: false,
            error: Some(format!("transaction record failed: {e}")),
        });
    }

    // Atomically move `current` (the per-slot commit point).
    let swap = helper.swap_current(
        expected_gen.map(|g| g.as_str()),
        new_gen.as_str(),
        op_id.as_str(),
    );
    match swap {
        Ok(()) => {}
        Err(e) => {
            return Ok(ServerProc {
                kind: SlotOutcomeKind::Failed,
                generation: new_gen.clone(),
                did_advance: false,
                did_compensate: false,
                error: Some(format!("swap failed: {e}")),
            });
        }
    };
    // The generation's tree content root: `generations/<gen>/root` is a
    // symlink to `objects/sha256/<tree>/root`, the same directory `current`
    // points at (it is the tree content root, not a nested `root/root`).
    let generation_root = remote
        .root()
        .join(layout::generation(new_gen.as_str()))
        .join("root");

    // Activation adapter. On failure, compensate (current was advanced).
    if let Err(e) = run_activation(
        remote,
        &generation_root,
        &behavior.activation,
        template_vars,
    ) {
        let comp = compensate_server(
            store,
            remote,
            helper,
            op_id,
            deployment_id,
            expected_gen,
            new_gen,
            config,
            template_vars,
        );
        let _ = helper.transaction_record(op_id.as_str(), "compensated");
        let did_comp = matches!(comp, Ok(true));
        let generation = if did_comp {
            expected_gen.cloned().unwrap_or_else(|| new_gen.clone())
        } else {
            new_gen.clone()
        };
        return Ok(ServerProc {
            kind: SlotOutcomeKind::Failed,
            generation,
            // The desired swap already moved `current` to the new generation:
            // this slot WAS advanced by the attempt, even if compensation
            // (partially) moved it back. A failed compensation must not be
            // mistaken for a never-advanced slot (the status logic treats
            // empty `advanced` as "nothing to roll back").
            did_advance: true,
            did_compensate: did_comp,
            error: Some(format!("activation failed: {e}")),
        });
    }

    // Verification adapter. On failure, compensate.
    if let Err(e) = run_verification(remote, &behavior.verification, template_vars) {
        let comp = compensate_server(
            store,
            remote,
            helper,
            op_id,
            deployment_id,
            expected_gen,
            new_gen,
            config,
            template_vars,
        );
        let _ = helper.transaction_record(op_id.as_str(), "compensated");
        let did_comp = matches!(comp, Ok(true));
        let generation = if did_comp {
            expected_gen.cloned().unwrap_or_else(|| new_gen.clone())
        } else {
            new_gen.clone()
        };
        return Ok(ServerProc {
            kind: SlotOutcomeKind::Failed,
            generation,
            did_advance: true,
            did_compensate: did_comp,
            error: Some(format!("verification failed: {e}")),
        });
    }

    // The swap, activation, and verification all succeeded, so the new generation
    // is live (current points at it and the service is healthy). A failure to
    // write the bookkeeping record is a *recoverable metadata* failure: the
    // service is active but the attempt cannot be durably marked committed. We
    // still report the server as Activated, but carry the error so the attempt
    // status is demoted to `PendingCommit` rather than erroneously `Successful`.
    // A later push's `reconcile_pending_commits` completes the marker set
    // without touching the healthy server when its generation still matches.
    if helper
        .transaction_record(op_id.as_str(), "committed")
        .is_err()
    {
        return Ok(ServerProc {
            kind: SlotOutcomeKind::Activated,
            generation: new_gen.clone(),
            did_advance: true,
            did_compensate: false,
            error: Some(
                "committed transaction record write failed; server active but bookkeeping incomplete"
                    .to_string(),
            ),
        });
    }
    Ok(ServerProc {
        kind: SlotOutcomeKind::Activated,
        generation: new_gen.clone(),
        did_advance: true,
        did_compensate: false,
        error: None,
    })
}

pub(crate) fn download_tree_to_host(
    remote: &dyn Remote,
    rel: &Path,
    host_dest: &Path,
) -> Result<()> {
    std::fs::create_dir_all(host_dest)
        .map_err(|e| Error::transport(format!("mkdir {}: {e}", host_dest.display())))?;
    for entry in remote.list(rel)? {
        let child_rel = rel.join(&entry.name);
        let dest = host_dest.join(&entry.name);
        if entry.is_symlink {
            // Reconstruct the exact symlink target; remove any stale entry first.
            // Best-effort prep: in the only caller (`recover_if_missing`) the
            // destination tree is freshly downloaded, so `dest` does not exist
            // and remove_file returns NotFound. If a stale entry did linger, the
            // subsequent symlink fails loudly with EEXIST rather than silently
            // producing a wrong tree.
            let target = remote.read_link(&child_rel)?;
            let _ = std::fs::remove_file(&dest);
            std::os::unix::fs::symlink(&target, &dest)
                .map_err(|e| Error::transport(format!("symlink {}: {e}", dest.display())))?;
        } else if entry.is_dir {
            download_tree_to_host(remote, &child_rel, &dest)?;
            set_mode(&dest, entry.mode)?;
        } else {
            let data = remote.read(&child_rel)?;
            std::fs::write(&dest, data)
                .map_err(|e| Error::transport(format!("write {}: {e}", dest.display())))?;
            set_mode(&dest, entry.mode)?;
        }
    }
    Ok(())
}

/// Apply a mode to a local file/directory, preserving only the permission bits.
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777))
        .map_err(|e| Error::transport(format!("chmod {}: {e}", path.display())))
}

// Per-process cache of release JSON for remote publication (avoids re-reading
// the local store inside the nested helper calls).
thread_local! {
    pub(crate) static REMOTE_RELEASE_JSON: std::cell::RefCell<
        HashMap<ReleaseId, (String, String)>
    > = std::cell::RefCell::new(HashMap::new());
}

#[cfg(test)]
pub(crate) mod server_tests {
    use super::*;
    use crate::identity::{TreeDigest, VariantName};
    use crate::remote::transport::LocalTransport;
    use crate::verify::release::RELEASE_RECORD_SCHEMA_VERSION;
    use std::path::PathBuf;

    pub(crate) const NONE_VARIANT: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/eng"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
to = "app-common/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[retention.deployment]
protect_deployments = 1

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

    pub(crate) const NONE_TOML: &str = r#"
schema_version = 2
application = "eng"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;

    pub(crate) const SYSTEMD_VARIANT: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/eng"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
to = "app-common/"
recursive = true

[[artifact.mappings]]
from = "artifacts/units/"
to = "integration/systemd/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[retention.deployment]
protect_deployments = 1

[activation]
adapter = "systemd"
scope = "user"

[[activation.units]]
name = "example.service"
artifact_path = "integration/systemd/example.service"
enable = true
restart = true

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

    pub(crate) const SYSTEMD_TOML: &str = r#"
schema_version = 2
application = "eng"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;

    /// Build the minimal release record for the harness's synthetic release: a
    /// CURRENT-format record carrying its OWN canonical slot snapshot (slot
    /// p1 -> variant `standard`, matching the harness config's NONE_VARIANT
    /// declaration) with the identity RECOMPUTED from the stored content, so
    /// the publish path's recompute-and-verify accepts it. The provenance
    /// `behavior_sha256` must be the canonical digest of the behavior payload
    /// published alongside the record (computed from the harness's own
    /// configured contract), or the publish path refuses the pair.
    fn harness_release_record(behavior_sha: &str) -> crate::identity::ReleaseRecord {
        let mut rec = crate::identity::ReleaseRecord {
            release_schema_version: RELEASE_RECORD_SCHEMA_VERSION,
            release_id: String::new(),
            release_sha256: String::new(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            provenance: crate::identity::Provenance {
                mapping_sha256: "m".to_string(),
                behavior_sha256: behavior_sha.to_string(),
            },
            variants: std::collections::BTreeMap::from([(
                "standard".to_string(),
                "tree".to_string(),
            )]),
            slots: std::collections::BTreeMap::from([(
                "standard".to_string(),
                crate::identity::CanonicalSlots {
                    slots: vec![crate::identity::CanonicalSlot {
                        id: "p1".to_string(),
                        server: "s1".to_string(),
                        deploy_dir: "/srv/eng".to_string(),
                        target: "t1".to_string(),
                        groups: Vec::new(),
                    }],
                },
            )]),
        };
        let digest = crate::verify::release::recompute_release_digest(&rec)
            .expect("harness release must carry a slot snapshot");
        rec.release_sha256 = digest.as_str().to_string();
        rec.release_id = crate::identity::ReleaseId::from_digest(&digest)
            .as_str()
            .to_string();
        rec
    }

    pub(crate) struct Harness {
        pub(crate) _dir: tempfile::TempDir,
        pub(crate) config: ProjectConfig,
        pub(crate) store: LocalStore,
        pub(crate) _project: PathBuf,
        pub(crate) tree: TreeDigest,
        pub(crate) remote: LocalTransport,
    }

    impl Harness {
        pub(crate) fn new(
            deploy_toml: &str,
            variant_toml: &str,
            files: &[(&str, &str)],
        ) -> Harness {
            let dir = tempfile::tempdir().unwrap();
            let project = dir.path().join("proj");
            std::fs::create_dir_all(&project).unwrap();
            let release_dir = project.join("releases").join("v1");
            std::fs::create_dir_all(&release_dir).unwrap();
            std::fs::write(release_dir.join("standard.toml"), variant_toml).unwrap();
            let cfg_path = project.join("deploy.toml");
            std::fs::write(&cfg_path, deploy_toml).unwrap();
            // Artifact sources live beneath the release directory (release_root /
            // `artifacts`), so a `from` never reaches into the project root.
            let artifacts_dir = release_dir.join("artifacts");
            for (p, c) in files {
                let fp = artifacts_dir.join(p);
                std::fs::create_dir_all(fp.parent().unwrap()).unwrap();
                std::fs::write(&fp, c).unwrap();
            }
            let config = ProjectConfig::load(&cfg_path).unwrap();
            let store = LocalStore::with_base(dir.path().join("store")).unwrap();

            // Materialize from the release directory, not the project root.
            let release_root = config.release_root(&cfg_path);
            let vcfg = config.variant("standard").unwrap();
            let staging = store.staging_dir().join("standard");
            crate::remote::canonical::materialize_variant(
                &release_root,
                &vcfg.artifact.mappings,
                &crate::remote::canonical::TemplateVars::mapping(
                    config.application().as_str(),
                    config.release().as_str(),
                    "standard",
                ),
                &staging,
            )
            .unwrap();
            let meta = tree::canonicalize_tree(&staging).unwrap();
            let tree = TreeDigest::parse(&meta.tree_sha256)
                .expect("canonicalized tree sha256 is a valid digest");
            store
                .store_object(
                    &TreeDigest::parse(&meta.tree_sha256)
                        .expect("canonicalized tree sha256 is a valid digest"),
                    &staging,
                )
                .unwrap();

            let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
            Harness {
                _dir: dir,
                config,
                store,
                _project: project,
                tree,
                remote,
            }
        }

        pub(crate) fn behave(&self) -> BehaviorContract {
            let v = self.config.variant("standard").unwrap();
            BehaviorContract {
                activation: crate::config::ActivationConfig::from(v.activation.clone()),
                verification: v.verification.clone(),
            }
        }

        /// The canonical digest of THIS harness's `standard` variant behavior
        /// contract — the provenance `behavior_sha256` the harness release
        /// record must carry so the behavior JSON published alongside it
        /// verifies on the publish path.
        fn behavior_sha256(&self) -> String {
            let behaviors =
                std::collections::BTreeMap::from([("standard".to_string(), self.behave())]);
            crate::verify::release::variant_behaviors_digest(&behaviors)
        }

        /// The synthetic release record bound to THIS harness's configured
        /// behavior (so the published behavior JSON matches its provenance).
        fn harness_release(&self) -> crate::identity::ReleaseRecord {
            harness_release_record(&self.behavior_sha256())
        }

        pub(crate) fn harness_release_id(&self) -> crate::identity::ReleaseId {
            crate::identity::ReleaseId::new(self.harness_release().release_id)
        }

        pub(crate) fn harness_release_json(&self) -> String {
            serde_json::to_string(&self.harness_release()).unwrap()
        }

        pub(crate) fn run(&self, expected_gen: Option<GenerationId>) -> ServerProc {
            let deployment_id = DeploymentId::generate();
            let op_id = OperationId::generate();
            self.helper()
                .stage_incoming(
                    deployment_id.as_str(),
                    self.tree.as_str(),
                    &self.store.object_root(&self.tree),
                )
                .unwrap();
            let behavior = self.behave();
            let sha = crate::verify::release::behavior_contract_digest(&behavior);
            let new_gen = GenerationId::generate();
            let helper = self.helper();
            // Slot context from the harness config (one slot p1 on server s1,
            // target t1, deploy_dir /srv/eng), built from the artifact being
            // processed like the engine's `slot_vars`: release/variant/tree
            // come from the ArtifactRef, never the config release name.
            let artifact = ArtifactRef {
                release: self.harness_release_id(),
                variant: VariantName::new("standard"),
                tree: self.tree.clone(),
            };
            let members = self.config.target_slots("t1").unwrap();
            let (slot, server) = members[0];
            let vars = crate::remote::canonical::TemplateVars::slot(
                slot.deploy_dir(),
                artifact.variant.as_str(),
                self.config.application().as_str(),
                artifact.release.as_str(),
                "t1",
                server.id.as_str(),
            )
            .with_server(server.user(), server.address(), server.port())
            .with_slot_id(&slot.id)
            .with_deployment(
                Some(&deployment_id),
                Some(&new_gen),
                Some(&artifact.tree),
            );
            process_server(
                &self.store,
                &self.remote,
                &helper,
                &op_id,
                &deployment_id,
                "t1",
                &artifact,
                &new_gen,
                expected_gen.as_ref(),
                &behavior,
                &sha,
                &vars,
                &self.config,
            )
            .unwrap()
        }

        pub(crate) fn helper(&self) -> RemoteHelper<'_> {
            RemoteHelper::new(&self.remote)
        }
    }

    #[test]
    fn clean_publish_activates() {
        let h = Harness::new(
            NONE_TOML,
            NONE_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
            ],
        );
        let proc = h.run(None);
        assert_eq!(proc.kind, SlotOutcomeKind::Activated);
        assert!(!proc.did_compensate);
        assert!(h.remote.exists(layout::current()));
    }

    #[test]
    fn corrupted_existing_remote_object_fails_integrity() {
        let h = Harness::new(
            NONE_TOML,
            NONE_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
            ],
        );
        let first = h.run(None);
        assert_eq!(first.kind, SlotOutcomeKind::Activated);

        // Corrupt the already-published remote object's content.
        let obj_file = h
            .remote
            .root()
            .join(crate::remote::layout::objects())
            .join(h.tree.as_str())
            .join("root")
            .join("app-common")
            .join("README");
        assert!(obj_file.exists(), "expected object file to exist");
        std::fs::write(&obj_file, "TAMPERED").unwrap();

        // A second generation reuses the corrupted object and must detect the
        // digest mismatch before advancing `current`.
        let second = h.run(Some(first.generation.clone()));
        assert_eq!(second.kind, SlotOutcomeKind::Failed);
        assert!(second.error.unwrap().contains("integrity"));
    }

    #[test]
    fn corrupted_upload_fails_integrity() {
        let h = Harness::new(
            NONE_TOML,
            NONE_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
            ],
        );
        // Corrupt the local object store so the staged upload carries bad bytes.
        let local_file = h.store.object_root(&h.tree).join("app").join("README");
        std::fs::write(&local_file, "CORRUPT-LOCAL").unwrap();

        let proc = h.run(None);
        assert_eq!(proc.kind, SlotOutcomeKind::Failed);
        assert!(proc.error.unwrap().contains("integrity"));
    }

    #[test]
    fn missing_systemd_unit_fails() {
        // The unit file is NOT present in the tree.
        let h = Harness::new(
            SYSTEMD_TOML,
            SYSTEMD_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
                ("units/other.txt", "x"),
            ],
        );
        let proc = h.run(None);
        assert_eq!(proc.kind, SlotOutcomeKind::Failed);
        assert!(proc.error.unwrap().contains("missing"));
        assert!(!h.remote.exists(layout::current()));
    }

    #[test]
    fn wrong_artifact_type_fails() {
        // The artifact path exists but is a DIRECTORY, not a regular file.
        let h = Harness::new(
            SYSTEMD_TOML,
            SYSTEMD_VARIANT,
            &[
                ("build/output/app/server", "v1"),
                ("deployment/common/README", "common"),
                ("units/example.service/placeholder", "x"),
            ],
        );
        let proc = h.run(None);
        assert_eq!(proc.kind, SlotOutcomeKind::Failed);
        assert!(proc.error.unwrap().to_lowercase().contains("type"));
    }

    /// Regression: the engine must hand the activation adapter
    /// `<remote>/generations/<gid>/root` (the `root` symlink to the tree
    /// content root) as the generation root — never a nested `root/root`. A
    /// full push with the systemd adapter exercises the real path
    /// construction at both `run_activation` call sites; staging reads the
    /// unit from `generations/<gid>/root/<artifact>`, so a `root/root`
    /// double-join would ENOENT and the push would never reach Activated.
    /// Fake `systemctl` in PATH and a temp `XDG_CONFIG_HOME` keep the
    /// activation hermetic (same pattern as the adapter end-to-end test; the
    /// shared `ENV_LOCK` serializes env-mutating tests).
    #[test]
    fn systemd_push_activation_uses_generation_root_not_nested() {
        let _lock = crate::testutil::ENV_LOCK.lock().unwrap();

        let tmp = tempfile::tempdir().unwrap();
        // Fake systemctl (daemon-reload/enable/restart all succeed) and a temp
        // config home so the installed unit lands somewhere hermetic.
        let bindir = tmp.path().join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        let fake = bindir.join("systemctl");
        std::fs::write(&fake, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let config_home = tmp.path().join("xdg");
        let old_path = std::env::var_os("PATH");
        let old_xdg = std::env::var_os("XDG_CONFIG_HOME");
        unsafe {
            std::env::set_var(
                "PATH",
                format!(
                    "{}:{}",
                    bindir.display(),
                    old_path
                        .as_ref()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default()
                ),
            );
            std::env::set_var("XDG_CONFIG_HOME", &config_home);
        }

        let outcome = {
            let h = Harness::new(
                SYSTEMD_TOML,
                SYSTEMD_VARIANT,
                &[
                    ("build/output/app/server", "v1"),
                    ("deployment/common/README", "common"),
                    (
                        "units/example.service",
                        "[Service]\nExecStart={{ deploy_dir }}/current/app/server\n",
                    ),
                ],
            );
            let proc = h.run(None);
            // The activation read the unit from `generations/<gid>/root`
            // (through the `root` symlink into the tree content root). A
            // `root/root` double-join would fail that read and never reach
            // Activated.
            assert_eq!(
                proc.kind,
                SlotOutcomeKind::Activated,
                "activation failed (root/root double-join?): {:?}",
                proc.error
            );
            assert!(!proc.did_compensate);
            let gen_root = h
                .remote
                .root()
                .join(crate::remote::layout::generation(proc.generation.as_str()))
                .join("root");
            assert!(
                gen_root.ends_with(
                    Path::new("generations")
                        .join(proc.generation.as_str())
                        .join("root")
                ),
                "activation generation root must be <root>/generations/<gid>/root, got {}",
                gen_root.display()
            );
            assert!(
                !gen_root.to_string_lossy().contains("root/root"),
                "activation generation root must not be a nested root/root"
            );
            // The double-joined path resolves to nothing on the published
            // layout: the tree content root has no nested `root` directory.
            assert!(
                !h.remote
                    .root()
                    .join(crate::remote::layout::generation(proc.generation.as_str()))
                    .join("root/root")
                    .exists(),
                "published tree must have no nested root dir (root/root double-join would ENOENT)"
            );
            // The installed unit's content proves staging read the artifact
            // through `generations/<gid>/root` and rendered it with the slot
            // context (deploy_dir /srv/eng from the variant).
            let installed = config_home.join("systemd/user/example.service");
            assert_eq!(
                std::fs::read_to_string(&installed).unwrap(),
                "[Service]\nExecStart=/srv/eng/current/app/server\n"
            );
            Ok::<(), String>(())
        };
        match old_path {
            Some(p) => unsafe { std::env::set_var("PATH", p) },
            None => unsafe { std::env::remove_var("PATH") },
        }
        match old_xdg {
            Some(v) => unsafe { std::env::set_var("XDG_CONFIG_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_CONFIG_HOME") },
        }
        outcome.unwrap();
    }
}
