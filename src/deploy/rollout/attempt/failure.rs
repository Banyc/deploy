//! Failure policies + compensation pass: [`apply_failure_policy`] derives
//! each slot's execution state under the failure policy — the step-13
//! compensation of the ADVANCE-REQUIRED set (a slot this deployment
//! advanced: a successful `Advanced` or an uncompensated
//! [`SlotExecution::FailedAfterAdvance`]) — by flipping the compensated
//! slots to [`SlotExecution::Restored`]. The never-advanced (pre-swap
//! failure / not-started) slots are NEVER compensated; their post-mutation
//! OBSERVATION is attached when the terminal inputs are derived
//! ([`crate::deploy::push::execute::ExecutionOutcome`]) — the old separate
//! fix-up ([`record_never_advanced_outcomes`]) is GONE.

use crate::config::FailurePolicy;
use crate::config::ProjectConfig;
use crate::config::ServerDef;
use crate::config::SlotConfig;
use crate::deploy::push::slot_vars;
use crate::deploy::rollout::SlotExecution;
use crate::deploy::rollout::compensate_server;
use crate::deploy::rollout::server::CompensationOutcome;
use crate::error::Result;
use crate::identity::DeploymentId;
use crate::identity::GenerationId;
use crate::identity::OperationId;
use crate::identity::SlotId;
use crate::ledger::Observation;
use crate::ledger::ObservedGeneration;
use crate::ledger::SlotPlan;
use crate::remote::helper::RemoteHelper;
use std::collections::BTreeMap;
use std::collections::HashMap;

// Failure-policy semantics (A1 deployment semantics).
//
// The step-13 batch compensation pass of the push transaction
// ([`crate::deploy::push`]): under [`FailurePolicy::RollbackChanged`] every
// slot a later failed batch had already advanced (an `Advanced` or
// `FailedAfterAdvance` execution) is compensated back to its pre-push
// generation — a successful compensation FLIPS the state to
// [`SlotExecution::Restored`] (compensation is a TRANSITION between states,
// never a boolean next to a flat `Failed`); a failed compensation leaves
// the slot `FailedAfterAdvance` (still on the advanced generation — the
// attempt is `Degraded`). Under [`FailurePolicy::LeaveChanged`] the
// advances are retained deliberately — no compensation pass runs — and the
// attempt is `Degraded`. The pass operates on the ONE execution table
// ([`SlotExecution`] values); the old free-floating
// `advanced`/`compensated`/`never_advanced` vectors and the wire-row
// mutation as the state store are GONE.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_failure_policy(
    failure_policy: FailurePolicy,
    members: &[(&SlotConfig, &ServerDef)],
    config: &ProjectConfig,
    target_name: &str,
    helpers: &HashMap<SlotId, RemoteHelper>,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
    plan_servers: &BTreeMap<SlotId, SlotPlan>,
    new_gen: &HashMap<SlotId, GenerationId>,
    executions: &mut BTreeMap<SlotId, SlotExecution>,
) -> Result<()> {
    // 13. Failure policy compensation of still-advanced servers. The policy
    // is matched EXHAUSTIVELY (no `_ =>` fallback, no string compare):
    //
    // * [`FailurePolicy::RollbackChanged`] (the default) — postcondition:
    //   every slot whose batch already advanced when a later batch failed
    //   (an `Advanced` or `FailedAfterAdvance` execution — the ADVANCE-
    //   REQUIRED compensation set) is COMPENSATED back to its pre-push
    //   generation. A compensation failure (e.g. prior behavior unavailable,
    //   or activation/verification failed during rollback) is reported as a
    //   failed compensation rather than aborting the whole push; the slot
    //   stays `FailedAfterAdvance` and the attempt is marked Degraded.
    // * [`FailurePolicy::LeaveChanged`] — postcondition: the earlier
    //   successfully-mutated batches are RETAINED deliberately; no
    //   compensation pass runs and the attempt ends Degraded with the mixed
    //   per-server state.
    let had_failure = executions.iter().any(|(_, e)| e.is_failure());
    if had_failure {
        match failure_policy {
            FailurePolicy::RollbackChanged => {
                for (sid, execution) in executions.iter_mut() {
                    if !execution.is_advanced() {
                        continue;
                    }
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
                    let comp = compensate_server(&helpers[sid], &request)
                        .unwrap_or(CompensationOutcome::Refused);
                    if let CompensationOutcome::Restored { adapter_restored } = comp {
                        // Compensation is a TRANSITION between states: the
                        // compensated slot becomes `Restored` with the
                        // restored generation's observation (the observed
                        // post-state the decision compares against pre_push —
                        // the old flat wire kept the DESIRED generation here,
                        // which would classify an uncompensated slot). The
                        // slot is rolled-back-eligible ONLY with the
                        // VERIFIED-adapter-restoration proof the compensation
                        // produced (the review's P1 fix: a generation-delta
                        // `Unchanged` alone cannot see the unit file left in
                        // the new state).
                        let observation = match prior {
                            Some(g) => Observation::Known(ObservedGeneration {
                                generation: g.clone(),
                            }),
                            None => Observation::KnownAbsent,
                        };
                        *execution = SlotExecution::Restored {
                            observation,
                            adapter_restored,
                        };
                    }
                    // A failed compensation leaves the execution as-is
                    // (`Advanced` keeps the bookkeeping error — the demotion
                    // signal; `FailedAfterAdvance` stays a remaining change).
                }
            }
            FailurePolicy::LeaveChanged => {
                // Deliberate retention: earlier batches keep their new
                // state, so no compensation pass runs at all.
            }
        }
    }
    Ok(())
}
