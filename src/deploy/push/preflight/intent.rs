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
/// serialization. Since schema v4 the intent ALSO freezes BOTH memberships:
/// the selected membership (the slot table's keys) and the FULL membership
/// (the complete target membership resolved AT PLAN TIME from the current
/// configuration) — the terminal must reproduce the frozen values and
/// recovery must finalize from them, never from the live configuration.
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
    // THE FROZEN PHYSICAL BINDINGS (schema v6): the plan-time `{server,
    // deploy_dir}` per target slot — resolved ONCE here, from the SAME
    // plan-time configuration the assignments were resolved against, and
    // frozen into the intent. Recovery finalizes from these frozen values
    // (never the live config re-read at finalize/recovery time), so a
    // server rebound or a moved `deploy_dir` between the intent's write and
    // recovery can never be recorded as the historical location the attempt
    // was planned against.
    let slot_bindings = ctx.config.target_slot_bindings(target_name)?;
    let intent_slots: Vec<(SlotId, IntentSlot)> = outcome
        .assignments
        .iter()
        .map(|a| {
            let binding = slot_bindings.get(&a.placement_slot).cloned().ok_or_else(|| {
                crate::error::Error::integrity(format!(
                    "intent {}: no physical binding for planned slot '{}' — the plan resolved it against a config that does not bind it",
                    deployment_id, a.placement_slot
                ))
            })?;
            Ok((
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
                    // The slot's plan-time physical binding — the value the
                    // plan actually resolved (the assignments are exactly
                    // the SELECTED slots, every one a member of the target,
                    // so the binding exists by construction; a missing entry
                    // would be an internal inconsistency and fails closed).
                    binding,
                },
            ))
        })
        .collect::<Result<Vec<(SlotId, IntentSlot)>>>()?;
    let attempt_intent = DeploymentIntent {
        deployment_id: deployment_id.clone(),
        target: TargetName::parse(target_name).expect("target name is a safe segment"),
        group: selection.group.clone(),
        behavior_sha256: desired_behavior_sha.clone(),
        attempted_at: crate::remote::helper::now_rfc3339(),
        slots: NonEmptySlotTable::build(intent_slots)?,
        // THE FROZEN FULL MEMBERSHIP: the COMPLETE target membership AT PLAN
        // TIME (every slot the target's current configuration owns when this
        // immutable intent is written — a full push's every target slot, a
        // group push's unselected slots included). The terminal event must
        // REPRODUCE this frozen value and recovery must finalize from it —
        // never from the live configuration, which may change arbitrarily
        // after this intent is durable.
        full_membership: ctx
            .config
            .target_slots(target_name)?
            .into_iter()
            .map(|(slot, _)| {
                SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment")
            })
            .collect(),
    };
    store.append_intent(target_name, &attempt_intent)?;
    Ok(attempt_intent)
}
