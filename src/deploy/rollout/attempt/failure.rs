//! Failure policies + compensation pass: [`apply_failure_policy`] derives
//! each slot's attempt state under the failure policy; the never-advanced
//! fix-up ([`record_never_advanced_outcomes`]) records the ACTUAL observed
//! post-state when a pre-swap failure stopped the push.

use crate::config::FailurePolicy;
use crate::config::ProjectConfig;
use crate::config::ServerDef;
use crate::config::SlotConfig;
use crate::deploy::plan::PlannedAssignment;
use crate::deploy::push::slot_vars;
use crate::deploy::rollout::compensate_server;
use crate::error::Result;
use crate::identity::DeploymentId;
use crate::identity::GenerationId;
use crate::identity::OperationId;
use crate::identity::SlotId;
use crate::ledger::DeploymentStatus;
use crate::ledger::Observation;
use crate::ledger::ObservationWire;
use crate::ledger::ObservedGeneration;
use crate::ledger::SlotOutcomeKind;
use crate::ledger::SlotPlan;
use crate::ledger::SlotResult;
use crate::remote::helper::RemoteHelper;
use crate::remote::transport::Remote;
use crate::store::local::LocalStore;
use std::collections::BTreeMap;
use std::collections::HashMap;

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
    _store: &LocalStore,
    _remotes: &HashMap<SlotId, Box<dyn Remote>>,
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
                    let request = crate::deploy::rollout::server::CompensationRequest {
                        op_id: op_id.clone(),
                        deployment_id: deployment_id.clone(),
                        prior_gen: prior.cloned(),
                        advanced_gen: new_gen[sid].clone(),
                        template_vars: vars.clone(),
                    };
                    let ok = compensate_server(&helpers[sid], &request).unwrap_or_default();
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
/// generation. The observation is written into the wire's OBSERVATION only,
/// INDEPENDENTLY of the outcome's operation error (`error`, which already
/// carries the failure that stopped the slot — e.g. "swap failed: ..."): a
/// FAILED read is `Unknown(error)` — the state is unknown, and an unknown
/// state is NOT evidence of no change — so the wire carries the `Unknown`
/// wire observation (the wire → domain conversion reads that back as
/// `Unknown`, never as "unchanged"); a successful read showing no state is
/// `KnownAbsent` (a unit wire observation). The operation error is NEVER
/// rewritten by the observation. Skipped outcomes already record the
/// reconciled current assignment.
pub(crate) fn record_never_advanced_outcomes(
    results: &mut BTreeMap<SlotId, SlotResult>,
    actual_observations: &BTreeMap<SlotId, Observation<ObservedGeneration>>,
    never_advanced: &[SlotId],
) {
    for sid in never_advanced {
        if let Some(r) = results.get_mut(sid)
            && r.outcome == SlotOutcomeKind::Failed
        {
            // DOMAIN → WIRE (exact): the observed post-state's strict wire
            // form; a missing observation reads back as `KnownAbsent` (the
            // old `None` generation with no observation error).
            match actual_observations.get(sid) {
                Some(obs) => r.observation = ObservationWire::from(obs),
                None => r.observation = ObservationWire::KnownAbsent,
            }
        }
    }
}
