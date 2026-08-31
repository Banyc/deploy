//! Intent persistence: [`persist_intent`] builds the attempt INTENT through
//! the KERNEL's validated constructor ([`crate::kernel::intent::plan`]) and
//! writes it (the plan/record half of steps 5-9) — the intent FREEZES the
//! COMPLETE RESULT in ONE full slot table at plan time. The intent is then
//! wrapped in the SEALED [`PreparedDeployment`] — the ONE value the mutation
//! and commit phases consume: every execution input is a PROJECTION of the
//! intent, never re-derived from the preflight outcome.

use super::PreflightOutcome;
use crate::deploy::push::PreparedDeployment;
use crate::deploy::push::PushContext;
use crate::error::Result;
use crate::identity::{DeploymentId, RolloutGroupName, SlotId, TargetName};
use crate::kernel;
use crate::kernel::intent::{PlanInput, PlannedDeploy};
use crate::kernel::snapshot::SnapshotSlot;
use crate::ledger::TargetSnapshot;
use crate::store::local::ledger::TargetLedgerTxn;

/// Build the attempt INTENT from the preflight outcome — the PURE
/// construction (no store write, no append): the intent FREEZES the
/// complete result (deployment identity, target, parent, group, the ONE
/// full slot table with each selected slot's plan-minted result + observed
/// pre-push state, the behavior digest, attempted_at) through the kernel's
/// validated constructor. Shared by the real push ([`persist_intent`]) and
/// the dry run (which builds the intent read-only to render its plan from
/// the intent's projections).
///
/// The binding recorded in the intent carries the deploy_dir's IMMUTABLE
/// receiver UUID (read from the provisioned remote during preflight) — the
/// PHYSICAL identity exact rollback compares. A real push's deploy_dir is
/// always provisioned in phase B, so the UUID is present; a dry run never
/// provisions, so the binding carries the config binding without a physical
/// identity (the dry-run intent is never persisted).
pub(crate) fn build_intent(
    ctx: &PushContext,
    outcome: &PreflightOutcome,
) -> Result<kernel::intent::DeploymentIntent> {
    let store = ctx.store;
    let target_name = ctx.target_name;
    let selection = ctx.selection;
    let deployment_id = ctx.deployment_id;
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
    // The binding recorded in the intent carries the deploy_dir's IMMUTABLE
    // receiver UUID (read from the provisioned remote during preflight) —
    // the PHYSICAL identity exact rollback compares. `ServerId`/`deploy_dir`
    // are display only: two ServerIds naming the same physical host+dir
    // share the receiver, and a slot whose physical receiver changed (even
    // under the same ServerId/path) must NOT receive the historical
    // generations.
    let mut planned: Vec<PlannedDeploy> = Vec::with_capacity(outcome.assignments.len());
    for a in &outcome.assignments {
        let config_binding = slot_bindings
            .get(&a.placement_slot)
            .cloned()
            .ok_or_else(|| {
                crate::error::Error::integrity(format!(
                    "intent {}: no physical binding for planned slot '{}'",
                    deployment_id, a.placement_slot
                ))
            })?;
        let binding = match outcome
            .receiver_uuids
            .get(&a.placement_slot)
            .cloned()
            .flatten()
        {
            Some(receiver_uuid) => config_binding.with_receiver_uuid(receiver_uuid),
            // A dry run never provisions (its receiver UUIDs are all
            // `None`), so the intent's binding carries the config binding
            // without a physical identity; a real push's deploy_dir is
            // always provisioned in phase B, so `None` is unreachable there.
            None => config_binding,
        };
        let generation = outcome.new_gen[&a.placement_slot].clone();
        let result = SnapshotSlot::new(generation, a.artifact.clone(), binding);
        // The intent's pre-push observation IS the map entry — the preflight
        // built it DIRECTLY as `Observation<PreviousGeneration>` (from the
        // live status/assignment reads), so there is no intermediate
        // re-conversion to lose or re-wrap.
        let pre_push = outcome.pre_push[&a.placement_slot].clone();
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

    kernel::intent::plan(PlanInput {
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
    .map_err(|e| crate::error::Error::integrity(format!("intent {deployment_id}: {e}")))
}

/// The intent built by [`persist_intent`] before the append, wrapped in the
/// SEALED [`PreparedDeployment`] the mutation + commit phases consume. The
/// append happens through the push's [`TargetLedgerTxn`] — the ONLY ledger
/// write surface (the txn owns the target lock + the folded state).
pub(crate) fn persist_intent(
    ctx: &PushContext,
    txn: &mut TargetLedgerTxn<'_>,
    outcome: &PreflightOutcome,
) -> Result<PreparedDeployment> {
    let store = ctx.store;
    let target_name = ctx.target_name;
    let deployment_id = ctx.deployment_id;
    let attempt_intent = build_intent(ctx, outcome)?;
    store.write_plan(deployment_id, &outcome.plan)?;

    // THE ONE-PARENT RULE (before mutation): the intent's parent must be the
    // target's current successful head AT THE MOMENT OF MUTATION — a drifted
    // head is a stale plan (refused, never reconciled implicitly). The
    // ledger is a SINGLE-WRITER authority under the target lock, so this is
    // the defensive cross-process check. THE HEAD COMES FROM THE TXN'S OWN
    // FOLDED STATE (the same fold the append gate validates against — a
    // single source, never a second read that could disagree).
    kernel::terminal::assert_parent_is_head(&attempt_intent, txn.state().successful_head())
        .map_err(|e| {
            crate::error::Error::conflict(format!(
                "push for target '{target_name}' refused before mutation: {e}"
            ))
        })?;

    txn.append_intent(&attempt_intent)?;
    // RETAIN the sealed prepared deployment: the intent is persisted and the
    // execution consumes ONLY its projections.
    PreparedDeployment::new(attempt_intent, outcome.behavior_index.clone())
}
