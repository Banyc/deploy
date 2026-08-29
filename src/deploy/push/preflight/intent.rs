//! Intent persistence: [`persist_intent`] builds the attempt INTENT through
//! the KERNEL's validated constructor ([`crate::kernel::intent::plan`]) and
//! writes it (the plan/record half of steps 5-9) — the intent FREEZES the
//! COMPLETE RESULT in ONE full slot table at plan time.

use super::PreflightOutcome;
use crate::deploy::push::PushContext;
use crate::error::Result;
use crate::identity::{DeploymentId, RolloutGroupName, SlotId, TargetName};
use crate::kernel;
use crate::kernel::intent::{PlanInput, PlannedDeploy};
use crate::kernel::snapshot::{PreviousGeneration, SnapshotSlot};
use crate::ledger::Observation;
use crate::ledger::TargetSnapshot;

/// The intent built by [`persist_intent`] before the append.
pub(crate) fn persist_intent(
    ctx: &PushContext,
    outcome: &PreflightOutcome,
) -> Result<kernel::intent::DeploymentIntent> {
    let store = ctx.store;
    let target_name = ctx.target_name;
    let selection = ctx.selection;
    let deployment_id = ctx.deployment_id;
    store.write_plan(deployment_id.as_str(), &outcome.plan)?;
    let desired_behavior_sha =
        crate::verify::release::behavior_index_digest(&outcome.behavior_index);
    let slot_bindings = ctx.config.target_slot_bindings(target_name)?;

    // The parent snapshot: the target's current successful head's resulting
    // snapshot (the overlay base for a group push's Inherit slots) + the
    // head's deployment id (the one parent).
    let (parent, parent_snapshot): (Option<DeploymentId>, Option<TargetSnapshot>) =
        match crate::deploy::plan::latest_successful_rollback(store, target_name)? {
            Some(snapshot) => (
                store
                    .read_last_successful(target_name)
                    .and_then(|h| DeploymentId::parse(&h).ok()),
                Some(snapshot),
            ),
            None => (None, None),
        };
    if parent.is_some() != parent_snapshot.is_some() {
        return Err(crate::error::Error::integrity(
            "intent planning: the successful head's id and snapshot must be coherent",
        ));
    }

    // Every SELECTED slot's plan-minted result + observed pre-push state.
    let mut planned: Vec<PlannedDeploy> = Vec::with_capacity(outcome.assignments.len());
    for a in &outcome.assignments {
        let binding = slot_bindings
            .get(&a.placement_slot)
            .cloned()
            .ok_or_else(|| {
                crate::error::Error::integrity(format!(
                    "intent {}: no physical binding for planned slot '{}'",
                    deployment_id, a.placement_slot
                ))
            })?;
        let generation = outcome.new_gen[&a.placement_slot].clone();
        let result = SnapshotSlot::new(generation, a.artifact.clone(), binding);
        let pre_push = pre_push_observation(&a.placement_slot, &outcome.pre_push);
        planned.push(PlannedDeploy {
            slot: a.placement_slot.clone(),
            result,
            pre_push,
        });
    }

    // The target's COMPLETE current slot set, in configuration order (the
    // deployment order — every slot the new intent covers must be a member).
    let selection_slots: Vec<SlotId> = ctx
        .config
        .target_slots(target_name)?
        .into_iter()
        .map(|(slot, _)| SlotId::parse(slot.id.as_str()).expect("validated slot id"))
        .collect();

    let group = match &selection.group {
        Some(g) => Some(RolloutGroupName::parse(g).map_err(|_| {
            crate::error::Error::integrity(format!(
                "intent {}: rollout group {g:?} is not a valid group name",
                deployment_id
            ))
        })?),
        None => None,
    };

    let attempt_intent = kernel::intent::plan(PlanInput {
        deployment_id: deployment_id.clone(),
        target: TargetName::parse(target_name).expect("target name is a safe segment"),
        parent,
        parent_snapshot,
        group,
        selection: selection_slots,
        planned,
        behavior_digest: crate::identity::BehaviorDigest::parse(&desired_behavior_sha).map_err(
            |_| {
                crate::error::Error::integrity(format!(
                    "intent {}: behavior_sha256 is not a valid digest",
                    deployment_id
                ))
            },
        )?,
        attempted_at: crate::identity::Timestamp::parse(&crate::remote::helper::now_rfc3339())
            .map_err(|_| {
                crate::error::Error::integrity(format!(
                    "intent {}: attempted_at is not a valid timestamp",
                    deployment_id
                ))
            })?,
    })
    .map_err(|e| crate::error::Error::integrity(format!("intent {deployment_id}: {e}")))?;

    // THE ONE-PARENT RULE (before mutation): the intent's parent must be the
    // target's current successful head AT THE MOMENT OF MUTATION — a drifted
    // head is a stale plan (refused, never reconciled implicitly). The
    // ledger is a SINGLE-WRITER authority under the target lock, so this is
    // the defensive cross-process check.
    let head = store
        .read_last_successful(target_name)
        .and_then(|h| DeploymentId::parse(&h).ok());
    kernel::terminal::assert_parent_is_head(&attempt_intent, head.as_ref()).map_err(|e| {
        crate::error::Error::conflict(format!(
            "push for target '{target_name}' refused before mutation: {e}"
        ))
    })?;

    store.append_intent(target_name, &attempt_intent)?;
    Ok(attempt_intent)
}

/// The observed pre-push state of one selected slot, as the kernel's
/// three-state [`Observation<PreviousGeneration>`]: `Known` prior
/// generation (with its artifact), `KnownAbsent` (never deployed), or
/// `Unknown(error)` (the read failed).
fn pre_push_observation(
    sid: &SlotId,
    pre_push: &std::collections::BTreeMap<SlotId, Option<crate::ledger::SlotAttemptState>>,
) -> Observation<PreviousGeneration> {
    match pre_push.get(sid).and_then(|p| p.clone()) {
        None => Observation::KnownAbsent,
        Some(state) => match (state.artifact, state.generation) {
            (Observation::Known(artifact), Some(generation)) => {
                Observation::Known(PreviousGeneration {
                    generation,
                    artifact,
                })
            }
            (Observation::KnownAbsent, _) | (_, None) => Observation::KnownAbsent,
            (Observation::Unknown(e), _) => Observation::Unknown(e),
        },
    }
}
