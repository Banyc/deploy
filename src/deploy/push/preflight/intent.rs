//! Intent persistence: [`persist_intent`] writes the plan + the attempt
//! INTENT record (the plan/record half of steps 5-9) — the intent carries
//! NO outcomes (the actuals live in the terminal event).

use super::PreflightOutcome;
use crate::deploy::push::PushContext;
use crate::error::Result;
use crate::identity::SlotId;
use crate::identity::TargetName;
use crate::ledger::DeploymentIntent;
use crate::ledger::DesiredGeneration;
use crate::ledger::IntentSlot;
use crate::ledger::NonEmptySlotTable;
use crate::ledger::PreviousGeneration;

/// Persist the plan + the attempt INTENT (the plan/record half of steps 5-9),
/// run AFTER the early no-op check and BEFORE the capacity/staging preflight:
/// the intent is the deployment's durable key — it is appended BEFORE any
/// server mutation, and its TERMINAL EVENT (appended by
/// [`crate::deploy::push`] after the mutation loop) carries the status,
/// outcomes, and rollback state. There is no separate `InProgress`
/// transition: an intent-only ledger entry IS the in-progress/pending state.
/// The record carries NO outcomes — the `slots` (actual) map is persisted
/// empty; the actual per-slot outcomes and the status live in the
/// deployment's TERMINAL EVENT. The DOMAIN intent stores ONE slot table (the
/// membership + the desired/pre-push entries are the same table — the
/// exact-key-set invariant is structural); the wire re-expands it on
/// serialization.
pub(crate) fn persist_intent(
    ctx: &PushContext,
    outcome: &PreflightOutcome,
) -> Result<DeploymentIntent> {
    let store = ctx.store;
    let target_name = ctx.target_name;
    let selection = ctx.selection;
    let deployment_id = ctx.deployment_id;
    store.write_plan(deployment_id.as_str(), &outcome.plan)?;
    let desired_behavior_sha =
        crate::verify::release::behavior_index_digest(&outcome.behavior_index);
    let intent_slots: Vec<(SlotId, IntentSlot)> = outcome
        .assignments
        .iter()
        .map(|a| {
            (
                a.placement_slot.clone(),
                IntentSlot {
                    desired: DesiredGeneration {
                        generation: outcome.new_gen[&a.placement_slot].clone(),
                        artifact: a.artifact.clone(),
                    },
                    pre_push: outcome
                        .pre_push
                        .get(&a.placement_slot)
                        .and_then(|p| p.clone())
                        .map(|p| PreviousGeneration {
                            artifact: p.artifact,
                            generation: p.generation,
                        }),
                },
            )
        })
        .collect();
    let attempt_intent = DeploymentIntent {
        deployment_id: deployment_id.clone(),
        target: TargetName::parse(target_name).expect("target name is a safe segment"),
        group: selection.group.clone(),
        behavior_sha256: desired_behavior_sha.clone(),
        attempted_at: crate::remote::helper::now_rfc3339(),
        slots: NonEmptySlotTable::build(intent_slots)?,
    };
    store.append_intent(target_name, &attempt_intent)?;
    Ok(attempt_intent)
}
