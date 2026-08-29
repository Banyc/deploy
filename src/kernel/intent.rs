//! THE INTENT FACET of the semantic kernel (feature area: the pure
//! deployment semantic kernel) — the deployment intent domain with ONE slot
//! table and the ONE validated constructor ([`plan`]).
//!
//! # Store the complete result once
//!
//! The intent is EXACTLY
//! `{deployment_id, target, parent, group, slots, behavior_digest,
//! attempted_at}`: ONE full slot table ([`DeploymentIntent::slots`]) whose
//! entries carry the slot's plan-minted RESULT ([`PlannedSlot::result`],
//! a [`SnapshotSlot`]) and its ACTION ([`PlannedSlot::action`],
//! [`SlotAction::Deploy`] or [`SlotAction::Inherit`]). Every membership and
//! the resulting snapshot are DERIVED VIEWS of this table, never stored
//! facts:
//!
//! * full membership      = `intent.slots.keys()`
//! * selected membership  = slots where `action == Deploy`
//! * resulting snapshot   = map each slot to `PlannedSlot.result`
//! * group membership     = selected membership (the `SlotAction` records it)
//!
//! # Construction rules (the constructor is the ONE validator)
//!
//! [`plan`] validates every relationship at construction; the derived views
//! then cannot disagree with the table:
//!
//! 1. at least one slot must be `Deploy`;
//! 2. `group == None` requires every slot to be `Deploy`;
//! 3. an inherited slot must reproduce its parent snapshot entry;
//! 4. a group deployment requires a parent snapshot covering every
//!    inherited slot;
//! 5. removed slots simply do not appear in the new intent;
//! 6. added slots must be selected and deployed; they cannot be inherited.
//!
//! There is NO `SnapshotId`: a successful deployment id IS the snapshot
//! identifier.

use crate::identity::{
    BehaviorDigest, DeploymentId, RolloutGroupName, SlotId, TargetName, Timestamp,
};
use crate::kernel::error::{KernelError, KernelResult};
use crate::kernel::snapshot::{PreviousGeneration, SnapshotSlot};
use crate::ledger::{NonEmptySlotTable, Observation, TargetSnapshot};
use std::collections::{BTreeMap, BTreeSet};

/// ONE planned slot's ACTION: `Deploy` (this push mutates the slot, knowing
/// its observed pre-push state) or `Inherit` (a group push carries the slot
/// forward unchanged from its parent's snapshot).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotAction {
    /// The slot is carried forward from the parent's snapshot: its result
    /// must reproduce the parent's snapshot entry for that slot.
    Inherit,
    /// The slot is deployed by this push; its pre-push state was observed
    /// before any mutation (the three-state observation — `Known` prior
    /// generation, `KnownAbsent` (never deployed), or `Unknown` (the read
    /// failed)).
    Deploy {
        pre_push: Observation<PreviousGeneration>,
    },
}

/// ONE planned slot of the intent: its RESULT (the plan-minted
/// [`SnapshotSlot`]) and its ACTION (how it is produced).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedSlot {
    result: SnapshotSlot,
    action: SlotAction,
}

impl PlannedSlot {
    pub fn new(result: SnapshotSlot, action: SlotAction) -> Self {
        Self { result, action }
    }
    pub fn result(&self) -> &SnapshotSlot {
        &self.result
    }
    pub fn action(&self) -> &SlotAction {
        &self.action
    }
    pub fn is_deploy(&self) -> bool {
        matches!(self.action, SlotAction::Deploy { .. })
    }
}

/// The VALIDATED DOMAIN intent of one deployment attempt: what was planned
/// and frozen BEFORE any server mutation. The remaining fields are the
/// deployment's identity + frozen scalar facts. THE CONSTRUCTOR ([`plan`])
/// IS THE ONE VALIDATOR of the slot-table relationships; the derived views
/// (memberships, the resulting snapshot) are accessors over the table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentIntent {
    deployment_id: DeploymentId,
    target: TargetName,
    /// The successful deployment this intent derives from — the target's
    /// successful head at plan time. `None` for a first deployment. Every
    /// intent records its parent; the state machine's `Successful` gate
    /// ([`crate::kernel::transition::apply_event`]) requires
    /// `parent == current successful head` at terminal-append time for EVERY
    /// path (recovery included) — a drifted head is refused as a stale plan
    /// (never successful, never reconciled implicitly), so at most one plan
    /// per parent ever appends `Successful`.
    parent: Option<DeploymentId>,
    group: Option<RolloutGroupName>,
    /// THE ONE FULL SLOT TABLE: every slot the resulting snapshot covers
    /// (full membership = keys), each with its plan-minted result and its
    /// action. The selected membership and the resulting snapshot are
    /// derived views of this table.
    slots: NonEmptySlotTable<PlannedSlot>,
    behavior_digest: BehaviorDigest,
    attempted_at: Timestamp,
}

/// One DEPLOY input to [`plan`]: the slot, its plan-minted result, and the
/// observed pre-push state.
#[derive(Clone, Debug)]
pub struct PlannedDeploy {
    pub slot: SlotId,
    pub result: SnapshotSlot,
    pub pre_push: Observation<PreviousGeneration>,
}

/// The plan input for [`plan`]: the deployment identity, the target's
/// COMPLETE current slot set (in configuration order — the deployment
/// order), the parent snapshot it derives overlays from, the optional
/// rollout group, and the DEPLOY slots.
#[derive(Clone, Debug)]
pub struct PlanInput {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    /// The successful deployment this intent derives from (the target's
    /// successful head at plan time). Coherent with `parent_snapshot`:
    /// `parent.is_some()` iff `parent_snapshot.is_some()`.
    pub parent: Option<DeploymentId>,
    /// The parent's resulting snapshot (the current head's snapshot), the
    /// overlay base for `Inherit` slots. `None` for a first deployment.
    pub parent_snapshot: Option<TargetSnapshot>,
    pub group: Option<RolloutGroupName>,
    /// The target's COMPLETE current slot set, in configuration order (the
    /// deployment order). Every slot the new intent covers must be a member;
    /// removed target slots simply do not appear.
    pub selection: Vec<SlotId>,
    /// The slots this push deploys (non-empty — a push selects at least one
    /// slot). Each carries its plan-minted result and observed pre-push
    /// state.
    pub planned: Vec<PlannedDeploy>,
    pub behavior_digest: BehaviorDigest,
    pub attempted_at: Timestamp,
}

impl DeploymentIntent {
    // ---- derived views (never stored) -------------------------------------

    /// THE FULL MEMBERSHIP — every slot the resulting snapshot covers,
    /// DERIVED from the slot table's keys.
    pub fn full_membership(&self) -> BTreeSet<SlotId> {
        self.slots.keys().cloned().collect()
    }

    /// THE SELECTED MEMBERSHIP — the slots this push deploys, DERIVED from
    /// the slot actions (`Deploy`).
    pub fn selected_membership(&self) -> BTreeSet<SlotId> {
        self.slots
            .iter()
            .filter(|(_, p)| p.is_deploy())
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// THE GROUP MEMBERSHIP — the slots this push selected. A group push
    /// records its membership through the `Deploy` actions; a full push
    /// selects every slot. Derived, never stored.
    pub fn group_membership(&self) -> BTreeSet<SlotId> {
        self.selected_membership()
    }

    /// THE SELECTED SLOTS IN DEPLOYMENT ORDER (the table's insertion order
    /// — the deployment order).
    pub fn selected(&self) -> impl Iterator<Item = (SlotId, &PlannedSlot)> {
        self.slots
            .iter()
            .filter(|(_, p)| p.is_deploy())
            .map(|(k, p)| (k.clone(), p))
    }

    /// THE RESULTING SNAPSHOT — map each slot to its planned result,
    /// DERIVED from the slot table (never stored; the successful terminal
    /// carries no snapshot payload — the deployment id IS the snapshot
    /// identifier).
    pub fn resulting_snapshot(&self) -> TargetSnapshot {
        crate::kernel::snapshot::snapshot_from_slots(
            self.slots
                .iter()
                .map(|(k, p)| (k.clone(), p.result.clone())),
        )
    }

    /// The distinct releases the SELECTED slots' results reference —
    /// DERIVED from the slot table (a partial snapshot can span several
    /// releases).
    pub fn releases(&self) -> BTreeSet<crate::identity::ReleaseId> {
        let mut out = BTreeSet::new();
        for (_, p) in self.selected() {
            out.insert(p.result().artifact().release.clone());
        }
        out
    }

    /// The pre-push observation of a SELECTED slot, if this intent deploys
    /// it. `None` for an inherited slot / unknown slot.
    pub fn pre_push(&self, slot: &SlotId) -> Option<&Observation<PreviousGeneration>> {
        match self.slots.get(slot) {
            Some(p) => match &p.action {
                SlotAction::Deploy { pre_push } => Some(pre_push),
                SlotAction::Inherit => None,
            },
            None => None,
        }
    }

    // ---- identity + scalar accessors --------------------------------------

    pub fn deployment_id(&self) -> &DeploymentId {
        &self.deployment_id
    }
    pub fn target(&self) -> &TargetName {
        &self.target
    }
    pub fn parent(&self) -> Option<&DeploymentId> {
        self.parent.as_ref()
    }
    pub fn group(&self) -> Option<&RolloutGroupName> {
        self.group.as_ref()
    }
    pub fn slots(&self) -> &NonEmptySlotTable<PlannedSlot> {
        &self.slots
    }
    pub fn behavior_digest(&self) -> &BehaviorDigest {
        &self.behavior_digest
    }
    pub fn attempted_at(&self) -> &Timestamp {
        &self.attempted_at
    }
    pub fn is_full_push(&self) -> bool {
        self.group.is_none()
    }

    /// The canonical WIRE BYTES of this intent (its wire form serialized) —
    /// the canonical bytes `intent_digest` is the sha256 of.
    pub fn canonical_wire_bytes(&self) -> Vec<u8> {
        let wire = crate::ledger::records::LedgerIntentWire::from(self);
        serde_json::to_vec(&wire).expect("a valid intent always serializes")
    }
}

/// THE ONE VALIDATED CONSTRUCTOR (the construction rules above). Builds the
/// intent's full slot table by overlaying the DEPLOY slots on the parent's
/// snapshot, validating every relationship at construction:
///
/// * the plan selects at least one slot, and every selected slot is a
///   target slot;
/// * `group == None` requires every target slot to be selected (every slot
///   of the intent is a `Deploy`);
/// * a group push carries every unselected target slot forward from the
///   parent snapshot (a `Deploy` slot never inherits; an added slot — one
///   with no parent entry — must be selected and deployed);
/// * `parent` and `parent_snapshot` are coherent (both or neither);
/// * removed target slots (not in `selection`) never appear.
pub fn plan(input: PlanInput) -> KernelResult<DeploymentIntent> {
    let PlanInput {
        deployment_id,
        target,
        parent,
        parent_snapshot,
        group,
        selection,
        planned,
        behavior_digest,
        attempted_at,
    } = input;

    // RULE 1: at least one slot must be Deploy.
    if planned.is_empty() {
        return Err(KernelError::invariant(
            "a deployment plan selects at least one slot",
        ));
    }
    // No duplicate planned slots, and every planned slot is a target slot.
    let selected_keys: BTreeSet<SlotId> = planned.iter().map(|p| p.slot.clone()).collect();
    if selected_keys.len() != planned.len() {
        return Err(KernelError::invariant(
            "a deployment plan selects each slot at most once",
        ));
    }
    let selection_keys: BTreeSet<SlotId> = selection.iter().cloned().collect();
    if selection_keys.len() != selection.len() {
        return Err(KernelError::invariant(
            "the target's slot selection carries duplicates",
        ));
    }
    for s in &selected_keys {
        if !selection_keys.contains(s) {
            return Err(KernelError::invariant(format!(
                "planned slot '{s}' is not a target slot of '{}'",
                target
            )));
        }
    }
    // Coherence: parent and parent_snapshot come together.
    if parent.is_some() != parent_snapshot.is_some() {
        return Err(KernelError::invariant(
            "a deployment plan's parent id and parent snapshot must be coherent (both or neither)",
        ));
    }
    let base = parent_snapshot.as_ref();
    let base_keys: BTreeSet<SlotId> = match base {
        Some(b) => b.keys().cloned().collect(),
        None => BTreeSet::new(),
    };

    // RULE 6: an added slot (not covered by the parent) must be selected and
    // deployed — it cannot be inherited.
    for slot in &selection_keys {
        if !base_keys.contains(slot) && !selected_keys.contains(slot) {
            return Err(KernelError::invariant(format!(
                "slot '{slot}' is new to target '{}' — an added slot must be selected and deployed, it cannot be inherited",
                target
            )));
        }
    }

    // RULE 2: group == None requires every slot of the intent to be Deploy —
    // every target slot must be selected.
    if group.is_none() {
        for slot in &selection_keys {
            if !selected_keys.contains(slot) {
                return Err(KernelError::invariant(format!(
                    "a full push (no group) selects every target slot — slot '{slot}' is unselected"
                )));
            }
        }
    }

    // Build the full slot table in deployment (selection) order: a selected
    // slot is `Deploy`, an unselected slot is `Inherit` from the parent.
    // RULE 4: a group push requires the parent snapshot covering every
    // inherited slot.
    let mut entries: Vec<(SlotId, PlannedSlot)> = Vec::with_capacity(selection.len());
    let planned_map: BTreeMap<SlotId, &PlannedDeploy> =
        planned.iter().map(|p| (p.slot.clone(), p)).collect();
    for slot in &selection {
        if let Some(p) = planned_map.get(slot) {
            entries.push((
                slot.clone(),
                PlannedSlot::new(
                    p.result.clone(),
                    SlotAction::Deploy {
                        pre_push: p.pre_push.clone(),
                    },
                ),
            ));
        } else {
            // RULE 3 + 4: an inherited slot must reproduce its parent
            // snapshot entry — the entry IS the parent's (the constructor
            // takes it directly, so no second copy can disagree) — and the
            // parent snapshot must cover it.
            let base_entry = base
                .and_then(|b| b.get(slot))
                .cloned()
                .ok_or_else(|| {
                    KernelError::invariant(format!(
                        "slot '{slot}' is unselected but has no parent snapshot entry — a group deployment requires a parent snapshot covering every inherited slot",
                    ))
                })?;
            entries.push((
                slot.clone(),
                PlannedSlot::new(base_entry, SlotAction::Inherit),
            ));
        }
    }
    // The table is non-empty by construction (every planned slot is in
    // selection and planned is non-empty).
    let slots = NonEmptySlotTable::build(entries).map_err(|e| {
        KernelError::invariant(format!("the full slot table must be non-empty: {e}"))
    })?;

    Ok(DeploymentIntent {
        deployment_id,
        target,
        parent,
        group,
        slots,
        behavior_digest,
        attempted_at,
    })
}

/// Convert a WIRE-BUILT (already scalar-validated) slot table into a
/// validated domain intent WITHOUT re-running the constructor's parent
/// checks (the wire is self-contained: the Inherit entries are frozen
/// overlays). The read path runs this after the wire conversion validated
/// the self-contained rules (at least one Deploy, group None → all Deploy);
/// the parent-congruence rules were validated at plan() time, and the
/// cross-record reproduction check (inherited == parent entry) runs where
/// the parent entry is still resolvable ([`crate::kernel::transition`]).
pub(crate) fn from_wire(
    deployment_id: DeploymentId,
    target: TargetName,
    parent: Option<DeploymentId>,
    group: Option<RolloutGroupName>,
    slots: NonEmptySlotTable<PlannedSlot>,
    behavior_digest: BehaviorDigest,
    attempted_at: Timestamp,
) -> KernelResult<DeploymentIntent> {
    // The wire conversion already enforced the self-contained rules, but the
    // domain must be uncorruptible by construction: re-validate the
    // constructor's self-contained legs.
    let selected: Vec<SlotId> = slots
        .iter()
        .filter(|(_, p)| p.is_deploy())
        .map(|(k, _)| k.clone())
        .collect();
    if selected.is_empty() {
        return Err(KernelError::integrity(
            "an intent must carry at least one Deploy slot",
        ));
    }
    if group.is_none() && slots.iter().any(|(_, p)| !p.is_deploy()) {
        return Err(KernelError::integrity(
            "a full push (group None) requires every slot to be Deploy",
        ));
    }
    Ok(DeploymentIntent {
        deployment_id,
        target,
        parent,
        group,
        slots,
        behavior_digest,
        attempted_at,
    })
}
