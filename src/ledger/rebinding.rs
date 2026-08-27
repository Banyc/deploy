//! The REBINDING records of the deployment ledger (feature area A6
//! "RebindingPlan"): the wire's claimed [`RebindingPlan`] and the domain's
//! verified [`VerifiedReleaseRebinding`] (with the ONLY construction path
//! [`VerifiedReleaseRebinding::verify`]), plus the [`FrozenSlotTopology`]
//! payload they carry.

use crate::error::{Error, Result};
use crate::identity::{MatchingMembership, ReleaseId, SlotId, TargetName};
use crate::ledger::records::PhysicalBinding;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The logical topology one slot is FROZEN into inside a release record:
/// which variant declares the slot and which rollout groups it belongs to
/// (the declaring variant file names the slot; a slot can belong to several
/// groups or none). This is the slot→variant/group half of a release's
/// temporal source — a `release:<id>` push resolves each slot's variant
/// from THIS frozen map, never the caller's current variant files.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenSlotTopology {
    /// The variant that declares the slot in the release's canonical slot
    /// snapshot (`ReleaseRecord.slots` is keyed by variant name).
    pub variant: String,
    /// The rollout groups the slot belongs to within its owning target
    /// (empty when the slot is not grouped).
    #[serde(default)]
    pub groups: Vec<String>,
}

/// The WIRE (claimed) rebinding context of a direct `release:<id>` plan: the
/// historical release's frozen topology applied onto the CURRENT physical
/// slots. This is the ON-DISK shape ([`DeploymentPlanWire::rebinding`]); the
/// domain's verified form is [`VerifiedReleaseRebinding`] — the wire →
/// domain conversion RECOMPUTES the proof from this claimed shape and the
/// plan's own source/target/membership, succeeding only when the claimed
/// rebinding matches the recomputed proof (a mismatch →
/// [`crate::error::Error::integrity`]).
///
/// The membership proof backing a historical-release rebinding: the PROOF
/// ([`MatchingMembership`]) that the release's FROZEN slot-id membership for
/// the destination target and the target's CURRENT slot-id membership were
/// verified EXACTLY EQUAL before planning proceeded (the only construction
/// path is [`MatchingMembership::verify`], so a [`RebindingPlan`] can only
/// record an already-verified agreement). The proof carries the agreed
/// NON-EMPTY slot set; the comparison is LOGICAL membership only — slot IDs,
/// never physical bindings (server / deploy_dir) — so two sets may be
/// identical while every physical binding differs.
///
/// The serialized form is the agreed slot set (the persisted wire replay of
/// the verified proof).
///
/// An EXPLICIT record that a `release:<id>` push is REBINDING a historical
/// release's frozen topology onto the CURRENT physical slots.
///
/// The temporal-source rule names four sources — HEAD (current variant slot
/// declarations), `release:<id>` (that release's frozen slot→variant and
/// group topology), a deployment rollback (that deployment's exact per-slot
/// artifact and physical binding), and the current server configuration
/// (connectivity and live capacity ONLY, never topology). A direct release
/// push is the one historically IMPLICIT exception: it applies the frozen
/// release topology onto the CURRENT target's slots, so the physical
/// rebinding happened without being named. This plan makes it explicit: it
/// records the release, the destination target, the frozen
/// slot→variant/group topology, the LOGICAL membership check (physical
/// bindings MAY differ; the logical membership MUST match), and the CURRENT
/// physical slots (`{server, deploy_dir}`) the frozen topology is bound
/// onto. Produced at plan time in the `PushRef::Release` branch; HEAD and
/// deployment-keyed plans carry `None`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebindingPlan {
    /// The historical release being rebound.
    pub release: ReleaseId,
    /// The destination target the release is rebound onto.
    pub target: TargetName,
    /// The release's frozen slot→variant/group topology, filtered to the
    /// destination target (from the release record's OWN canonical slot
    /// snapshot). Complete regardless of group selection: a `--group` push
    /// narrows the PLANNED assignments, never the recorded topology.
    pub frozen_topology: BTreeMap<SlotId, FrozenSlotTopology>,
    /// The membership PROOF that ran before planning (see
    /// [`MatchingMembership`]): `frozen == current` verified (slot IDs only;
    /// physical bindings may differ). For a group push this is the COMPLETE
    /// membership — the group narrows the planned slots, never the
    /// membership check.
    pub(crate) membership: MatchingMembership,
    /// The CURRENT physical slots the frozen topology is bound onto, per
    /// PLANNED slot: `slot -> {server, deploy_dir}` from the caller's
    /// current configuration. A group selection records exactly the selected
    /// slots (the group-filtered assignments); a full push records every
    /// member slot.
    pub current_physical_slots: BTreeMap<SlotId, PhysicalBinding>,
}

/// The VERIFIED rebinding proof carried by a Release-origin plan: the
/// complete evidence that the plan's claimed rebinding is REAL — the
/// historical release, the destination target, the release's frozen
/// slot→variant/group topology, the membership PROOF (frozen == current,
/// verified), the SELECTED plan slots (the plan's membership), and the
/// current physical slots the frozen topology is bound onto. A Release
/// origin WITHOUT this proof is unrepresentable ([`PlanOrigin::Release`]
/// carries it INSIDE the source); HEAD and deployment origins carry none.
///
/// The ONLY construction path is [`VerifiedReleaseRebinding::verify`], which
/// checks that every component agrees — the frozen topology's keys equal the
/// membership's agreed slots, every selected plan slot is a member of the
/// agreed membership, and the current physical slots cover exactly the
/// selected plan slots. The wire → domain conversion
/// ([`DeploymentPlanWire::into_domain`]) RECOMPUTES the proof from the
/// wire's claimed [`RebindingPlan`] and the plan's own source/target/
/// membership, succeeding only when the claimed rebinding matches the
/// recomputed proof (a mismatch → [`crate::error::Error::integrity`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedReleaseRebinding {
    /// The historical release being rebound.
    pub release: ReleaseId,
    /// The destination target the release is rebound onto.
    pub target: TargetName,
    /// The release's frozen slot→variant/group topology, filtered to the
    /// destination target (from the release record's OWN canonical slot
    /// snapshot). Complete regardless of group selection: a `--group` push
    /// narrows the PLANNED assignments, never the recorded topology.
    pub frozen_topology: BTreeMap<SlotId, FrozenSlotTopology>,
    /// The membership PROOF that ran before planning (see
    /// [`MatchingMembership`]): `frozen == current` verified (slot IDs only;
    /// physical bindings may differ). For a group push this is the COMPLETE
    /// membership — the group narrows the planned slots, never the
    /// membership check.
    pub(crate) membership: MatchingMembership,
    /// The SELECTED plan slots: the plan's membership (the `slots` map keys)
    /// — the slots the frozen topology is actually bound onto. A group
    /// selection records exactly the selected slots (the group-filtered
    /// assignments); a full push records every member slot.
    pub selected_plan_slots: BTreeSet<SlotId>,
    /// The CURRENT physical slots the frozen topology is bound onto, per
    /// SELECTED slot: `slot -> {server, deploy_dir}` from the caller's
    /// current configuration.
    pub current_physical_slots: BTreeMap<SlotId, PhysicalBinding>,
}

impl VerifiedReleaseRebinding {
    /// The ONLY construction path: verify that the claimed rebinding
    /// components agree — the frozen topology's keys must equal the
    /// membership's agreed slots, every selected plan slot must be a member
    /// of the agreed membership, and the current physical slots must cover
    /// exactly the selected plan slots. Any disagreement →
    /// [`crate::error::Error::integrity`] (fail closed: a hand-constructed
    /// proof can never put the components out of agreement).
    pub(crate) fn verify(
        release: ReleaseId,
        target: TargetName,
        frozen_topology: BTreeMap<SlotId, FrozenSlotTopology>,
        membership: MatchingMembership,
        selected_plan_slots: BTreeSet<SlotId>,
        current_physical_slots: BTreeMap<SlotId, PhysicalBinding>,
    ) -> Result<Self> {
        let membership_slots: BTreeSet<SlotId> = membership.slots().iter().cloned().collect();
        let frozen_keys: BTreeSet<SlotId> = frozen_topology.keys().cloned().collect();
        if frozen_keys != membership_slots {
            return Err(Error::integrity(
                "rebinding proof refused: the frozen topology keys disagree with the membership's agreed slots",
            ));
        }
        for slot in &selected_plan_slots {
            if !membership_slots.contains(slot) {
                return Err(Error::integrity(format!(
                    "rebinding proof refused: selected slot '{slot}' is outside the agreed membership"
                )));
            }
        }
        let physical_keys: BTreeSet<SlotId> = current_physical_slots.keys().cloned().collect();
        if physical_keys != selected_plan_slots {
            return Err(Error::integrity(
                "rebinding proof refused: the current physical slots disagree with the selected plan slots",
            ));
        }
        Ok(VerifiedReleaseRebinding {
            release,
            target,
            frozen_topology,
            membership,
            selected_plan_slots,
            current_physical_slots,
        })
    }
}
