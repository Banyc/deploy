//! Intent persistence: [`persist_intent`] writes the plan + the attempt
//! INTENT record (the plan/record half of steps 5-9) — the intent freezes
//! the COMPLETE resulting snapshot at plan time.

use super::PreflightOutcome;
use crate::deploy::push::PushContext;
use crate::error::Result;
use crate::identity::{GenerationRef, PlacementSlotAssignment, SlotId, TargetName};
use crate::ledger::DeploymentIntent;
use crate::ledger::NonEmptySlotTable;
use crate::ledger::records::SelectedSlotIntent;
use crate::ledger::records::{BoundGeneration, build_rollback};

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
    let slot_bindings = ctx.config.target_slot_bindings(target_name)?;

    // Build verified map for selected slots
    let mut verified: std::collections::BTreeMap<SlotId, BoundGeneration> =
        std::collections::BTreeMap::new();
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
        verified.insert(
            a.placement_slot.clone(),
            BoundGeneration {
                generation: GenerationRef {
                    generation,
                    assignment: PlacementSlotAssignment {
                        placement_slot: a.placement_slot.clone(),
                        artifact: a.artifact.clone(),
                    },
                },
                binding,
            },
        );
    }

    let base = crate::deploy::plan::latest_successful_rollback(store, target_name)?;
    let current_slot_ids: Vec<SlotId> = ctx
        .config
        .target_slots(target_name)?
        .into_iter()
        .map(|(slot, _)| SlotId::parse(slot.id.as_str()).expect("validated slot id"))
        .collect();

    let resulting_snapshot = build_rollback(&verified, base.as_ref(), &current_slot_ids)?;
    // Assert snapshot keys == full membership
    let snapshot_keys: std::collections::BTreeSet<SlotId> =
        resulting_snapshot.keys().cloned().collect();
    let full_set: std::collections::BTreeSet<SlotId> = current_slot_ids.iter().cloned().collect();
    if snapshot_keys != full_set {
        return Err(crate::error::Error::integrity(format!(
            "intent {}: resulting_snapshot keys {snapshot_keys:?} != full membership {full_set:?}",
            deployment_id
        )));
    }

    // Build selected table with pre_push conversion, fail closed on unreadable
    let mut selected_entries: Vec<(SlotId, SelectedSlotIntent)> = Vec::new();
    for a in &outcome.assignments {
        let sid = a.placement_slot.clone();
        let pre = outcome.pre_push.get(&sid).and_then(|p| p.clone());
        let pre_push = match pre {
            None => None,
            Some(p) => match p.artifact {
                crate::ledger::Observation::Known(ref artifact) => {
                    let generation_val = p.generation.clone().ok_or_else(|| {
                            crate::error::Error::integrity(format!(
                                "intent {}: pre_push for slot '{sid}' has Known artifact but missing generation — unrepresentable",
                                deployment_id
                            ))
                        })?;
                    Some(GenerationRef {
                        generation: generation_val,
                        assignment: PlacementSlotAssignment {
                            placement_slot: sid.clone(),
                            artifact: artifact.clone(),
                        },
                    })
                }
                crate::ledger::Observation::KnownAbsent => {
                    return Err(crate::error::Error::integrity(format!(
                        "intent {}: pre_push for slot '{sid}' is KnownAbsent — unrepresentable (unreadable pre-push cannot be frozen)",
                        deployment_id
                    )));
                }
                crate::ledger::Observation::Unknown(_) => {
                    return Err(crate::error::Error::integrity(format!(
                        "intent {}: pre_push for slot '{sid}' is Unknown — unrepresentable (unreadable pre-push cannot be frozen)",
                        deployment_id
                    )));
                }
            },
        };
        selected_entries.push((
            sid,
            SelectedSlotIntent {
                pre_push,
                ..Default::default()
            },
        ));
    }

    let group = match &selection.group {
        Some(g) => Some(crate::identity::RolloutGroupName::parse(g).map_err(|_| {
            crate::error::Error::integrity(format!(
                "intent {}: rollout group {g:?} is not a valid group name",
                deployment_id
            ))
        })?),
        None => None,
    };

    let attempt_intent = DeploymentIntent {
        deployment_id: deployment_id.clone(),
        target: TargetName::parse(target_name).expect("target name is a safe segment"),
        group,
        resulting_snapshot,
        selected: NonEmptySlotTable::build(selected_entries)?,
        behavior_sha256: crate::identity::BehaviorDigest::parse(&desired_behavior_sha).map_err(
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
        ..Default::default()
    };
    store.append_intent(target_name, &attempt_intent)?;
    Ok(attempt_intent)
}
