//! The REBINDING records of the deployment ledger (feature area A6
//! "RebindingPlan"): the wire's claimed [`RebindingPlan`] and the domain's
//! verified [`VerifiedReleaseRebinding`] (with the ONLY construction paths
//! [`VerifiedReleaseRebinding::verify`] — the plan-time mint — and
//! [`VerifiedReleaseRebinding::revalidate`] — the load-time revalidation
//! against the release graph), plus the [`FrozenSlotTopology`] payload they
//! carry — the proof VERIFICATION this facet performs is one of the
//! record-validation concerns of [`crate::ledger::records::validation`].
//!
//! # Wire claims deserialize; proofs never do
//!
//! The WIRE (persisted) form is the CLAIM [`RebindingPlan`] — the only type
//! that derives `Serialize`/`Deserialize` here. The claim records the
//! AGREED MEMBERSHIP as a PLAIN SLOT SET (a claim component, never a proof:
//! [`crate::identity::MatchingMembership`] implements neither `Serialize`
//! nor `Deserialize`). The domain's [`VerifiedReleaseRebinding`] is a
//! SEALED PROOF (private invariant-bearing fields + a private `_sealed`
//! marker): it neither implements serde nor exposes struct literals — a
//! caller CANNOT deserialize a "verified" proof without running the
//! verification, and cannot hand-construct one. The wire → domain
//! conversion ([`DeploymentPlanWire::into_domain`]) REVALIDATES the claim
//! against the release graph ([`crate::verify::release::ValidatedRelease`])
//! plus the plan's own membership, succeeding only when the claimed
//! rebinding matches the recomputed proof (a mismatch →
//! [`crate::error::Error::integrity`]). The domain → wire direction
//! ([`From<&VerifiedReleaseRebinding>`]) is the projection of a verified
//! proof back into its claimed wire form.

use crate::error::{Error, Result};
use crate::identity::{MatchingMembership, ReleaseId, SlotId, SlotSet, TargetName};
use crate::verify::release::ValidatedRelease;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::super::PhysicalBinding;
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
/// slots. This is the ON-DISK shape ([`crate::ledger::DeploymentPlanWire::rebinding`]); the
/// domain's verified form is [`VerifiedReleaseRebinding`] — the wire →
/// domain conversion ([`DeploymentPlanWire::into_domain`]) REVALIDATES this
/// claimed shape against the release graph ([`crate::verify::release::ValidatedRelease`])
/// plus the plan's own source/target/membership, succeeding only when the
/// claimed rebinding matches the recomputed proof (a mismatch →
/// [`crate::error::Error::integrity`]).
///
/// The membership agreement backing a historical-release rebinding: the
/// claim records the AGREED SLOT SET — the membership the release's frozen
/// slot-id set for the destination target and the target's CURRENT slot-id
/// membership were verified EXACTLY EQUAL over at plan time. The agreed set
/// is a CLAIM COMPONENT (a plain [`BTreeSet`], never a proof): the PROOF
/// ([`crate::identity::MatchingMembership`]) is re-minted on read by
/// re-verifying the claimed set against the release graph — a proof is
/// produced only by verification, never parsed from the wire. The agreed
/// set is NON-EMPTY (a target's membership is never empty); the comparison
/// is LOGICAL membership only — slot IDs, never physical bindings (server /
/// deploy_dir) — so two sets may be identical while every physical binding
/// differs.
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
/// slot→variant/group topology, the LOGICAL membership agreement (physical
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
    /// The AGREED MEMBERSHIP — the slot set the release's frozen membership
    /// for the destination target and the target's CURRENT membership were
    /// verified EXACTLY EQUAL over at plan time (see
    /// [`crate::identity::MatchingMembership`]). A CLAIM COMPONENT (a plain
    /// set, never a proof): the proof is re-minted on read by re-verifying
    /// this set against the release graph. For a group push this is the
    /// COMPLETE membership — the group narrows the planned slots, never the
    /// membership check.
    pub membership: BTreeSet<SlotId>,
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
/// origin WITHOUT this proof is unrepresentable ([`crate::ledger::PlanOrigin::Release`]
/// carries it INSIDE the source); HEAD and deployment origins carry none.
///
/// The ONLY construction paths are the crate-internal verification
/// ([`VerifiedReleaseRebinding::verify`] — the plan-time mint, `pub(crate)`)
/// and the load-time revalidation
/// ([`VerifiedReleaseRebinding::revalidate`] — the wire → domain
/// conversion [`DeploymentPlanWire::into_domain`] runs it against the
/// release graph). Both check that every component agrees — the frozen
/// topology's keys equal the membership's agreed slots, every selected plan
/// slot is a member of the agreed membership, and the current physical
/// slots cover exactly the selected plan slots; the load-time revalidation
/// additionally checks the claimed components against the release graph
/// ([`crate::verify::release::ValidatedRelease`]).
///
/// THE PROOF IS SEALED (mirrors [`crate::kernel::terminal::VerifiedExecution`]):
/// every invariant-bearing field is private, the type carries a private
/// `_sealed` marker, and it NEITHER implements `Serialize`/`Deserialize` NOR
/// exposes struct literals — a caller can never deserialize a "verified"
/// rebinding proof without running the verification, and can never
/// hand-construct one. The persisted/wire form is the CLAIM
/// ([`RebindingPlan`]); only the verification mints the proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedReleaseRebinding {
    /// The historical release being rebound.
    release: ReleaseId,
    /// The destination target the release is rebound onto.
    target: TargetName,
    /// The release's frozen slot→variant/group topology, filtered to the
    /// destination target (from the release record's OWN canonical slot
    /// snapshot). Complete regardless of group selection: a `--group` push
    /// narrows the PLANNED assignments, never the recorded topology.
    frozen_topology: BTreeMap<SlotId, FrozenSlotTopology>,
    /// The membership PROOF that ran before planning (see
    /// [`MatchingMembership`]): `frozen == current` verified (slot IDs only;
    /// physical bindings may differ). For a group push this is the COMPLETE
    /// membership — the group narrows the planned slots, never the
    /// membership check.
    membership: MatchingMembership,
    /// The SELECTED plan slots: the plan's membership (the `slots` map keys)
    /// — the slots the frozen topology is actually bound onto. A group
    /// selection records exactly the selected slots (the group-filtered
    /// assignments); a full push records every member slot.
    selected_plan_slots: BTreeSet<SlotId>,
    /// The CURRENT physical slots the frozen topology is bound onto, per
    /// SELECTED slot: `slot -> {server, deploy_dir}` from the caller's
    /// current configuration.
    current_physical_slots: BTreeMap<SlotId, PhysicalBinding>,
    /// The SEAL marker: the proof has NO public constructor and exposes no
    /// struct literal — a `VerifiedReleaseRebinding` can only be minted by
    /// the verification paths ([`VerifiedReleaseRebinding::verify`] /
    /// [`VerifiedReleaseRebinding::revalidate`]).
    _sealed: (),
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
            _sealed: (),
        })
    }

    /// The historical release being rebound.
    pub fn release(&self) -> &ReleaseId {
        &self.release
    }
    /// The destination target the release is rebound onto.
    pub fn target(&self) -> &TargetName {
        &self.target
    }
    /// The release's frozen slot→variant/group topology (see the field
    /// docs on the wire's [`RebindingPlan`]).
    pub fn frozen_topology(&self) -> &BTreeMap<SlotId, FrozenSlotTopology> {
        &self.frozen_topology
    }
    /// The membership PROOF (frozen == current, verified). Test-facing: the
    /// property suite reads the agreed set through this accessor. The
    /// production paths read the private field in-module (the wire
    /// projection) and the claim's `membership` set (the wire → domain
    /// conversion), so the accessor is `#[cfg(test)]` like
    /// [`MatchingMembership`]'s own test-facing `len`.
    #[cfg(test)]
    pub(crate) fn membership(&self) -> &MatchingMembership {
        &self.membership
    }
    /// The SELECTED plan slots (the plan's membership).
    pub fn selected_plan_slots(&self) -> &BTreeSet<SlotId> {
        &self.selected_plan_slots
    }
    /// The CURRENT physical slots the frozen topology is bound onto.
    pub fn current_physical_slots(&self) -> &BTreeMap<SlotId, PhysicalBinding> {
        &self.current_physical_slots
    }

    /// THE LOAD-TIME REVALIDATION: revalidate a CLAIMED rebinding
    /// ([`RebindingPlan`] — the persisted wire form) against the release
    /// graph ([`ValidatedRelease`]) plus the plan's own membership
    /// (`selected_plan_slots`). The claim is UNTRUSTED: every component is
    /// re-derived from the release graph and the plan — the claimed release
    /// must BE the validated release, the claimed frozen topology must equal
    /// the release graph's OWN frozen topology for the claimed target, the
    /// claimed agreed membership must equal the release graph's frozen
    /// membership for the claimed target (this re-mints the membership
    /// PROOF — a proof is produced only by verification, never parsed from
    /// the wire), and the internal agreement check must hold (frozen
    /// topology keys == membership, every selected plan slot a member,
    /// physical slots == selected). Any disagreement →
    /// [`crate::error::Error::integrity`] (fail closed: an unverified claim
    /// can never enter the domain as a verified fact).
    pub(crate) fn revalidate(
        claimed: &RebindingPlan,
        release: &ValidatedRelease,
        selected_plan_slots: &BTreeSet<SlotId>,
    ) -> Result<Self> {
        // 1. The claimed release must BE the validated release (the caller
        //    supplies the release graph for the plan's source release; the
        //    claim is bound to it by identity).
        let release_id = ReleaseId::parse(&release.record().release_id).map_err(|_| {
            Error::integrity(format!(
                "rebinding claim refused: the validated release record carries an invalid release id {:?}",
                release.record().release_id
            ))
        })?;
        if claimed.release != release_id {
            return Err(Error::integrity(format!(
                "rebinding claim refused: the claimed release {} disagrees with the validated release {}",
                claimed.release, release_id
            )));
        }
        // 2. The release graph's OWN frozen topology for the claimed target
        //    (from the validated release's canonical slot snapshot) must
        //    equal the claimed frozen topology — a claim that invents,
        //    drops, or alters a slot's variant/group is refused.
        let mut actual_topology: BTreeMap<SlotId, FrozenSlotTopology> = BTreeMap::new();
        for (variant, slots) in release.slots() {
            for slot in slots {
                if slot.target() == &claimed.target {
                    actual_topology.insert(
                        slot.id().clone(),
                        FrozenSlotTopology {
                            variant: variant.as_str().to_string(),
                            groups: slot
                                .groups()
                                .iter()
                                .map(|g| g.as_str().to_string())
                                .collect(),
                        },
                    );
                }
            }
        }
        if actual_topology != claimed.frozen_topology {
            return Err(Error::integrity(
                "rebinding claim refused: the claimed frozen topology disagrees with the release graph's frozen topology for the claimed target",
            ));
        }
        // 3. The claimed AGREED MEMBERSHIP must equal the release graph's
        //    frozen membership for the claimed target — this RE-MINTS the
        //    membership PROOF (verify is the only construction path; the
        //    claimed set is never trusted as a proof).
        let frozen: SlotSet = SlotSet::new(actual_topology.keys().cloned());
        let membership = MatchingMembership::verify(frozen, SlotSet::new(claimed.membership.clone()))
            .map_err(|e| {
                Error::integrity(format!(
                    "rebinding claim refused: the claimed membership disagrees with the release graph's frozen membership: {e}"
                ))
            })?;
        // 4. The internal agreement check (frozen topology keys ==
        //    membership, selected ⊆ membership, physical == selected).
        Self::verify(
            claimed.release.clone(),
            claimed.target.clone(),
            claimed.frozen_topology.clone(),
            membership,
            selected_plan_slots.clone(),
            claimed.current_physical_slots.clone(),
        )
    }
}

/// The DOMAIN → WIRE projection: re-expand a VERIFIED proof into its
/// claimed wire form ([`RebindingPlan`]) for persistence. The selected plan
/// slots are NOT part of the claim (they are re-derived from the plan's own
/// membership on the next read); the agreed membership is projected as the
/// PLAIN SLOT SET (a claim component — the proof itself is never
/// serialized). The ONLY production path that produces a claim (besides
/// wire deserialization).
impl From<&VerifiedReleaseRebinding> for RebindingPlan {
    fn from(p: &VerifiedReleaseRebinding) -> Self {
        RebindingPlan {
            release: p.release.clone(),
            target: p.target.clone(),
            frozen_topology: p.frozen_topology.clone(),
            membership: p.membership.slots().as_set().clone(),
            current_physical_slots: p.current_physical_slots.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Activation, SlotConfig, ValidatedCommand, Verification};
    use crate::identity::{BehaviorContract, ServerId, VariantName, test_tree_digest};
    use crate::verify::release::{ValidatedRelease, build_release, variant_behaviors_digest};
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::collections::BTreeSet;

    fn slot(i: u32) -> SlotId {
        SlotId::new(format!("s{i}"))
    }

    /// An arbitrary NON-EMPTY membership (a membership proof can never be
    /// empty — `MatchingMembership::verify` refuses an empty agreement, so
    /// the claim's agreed set is non-empty by construction).
    fn arbitrary_membership() -> impl Strategy<Value = BTreeSet<SlotId>> {
        prop::collection::btree_set((0u32..6).prop_map(slot), 1..=4)
    }

    /// An arbitrary (possibly EMPTY) slot set — the tamper dimension: the
    /// claimed agreed membership, the frozen topology keys, the selected
    /// plan slots, and the physical slots may drift from the release graph's
    /// frozen membership independently.
    fn arbitrary_slot_set() -> impl Strategy<Value = BTreeSet<SlotId>> {
        prop::collection::btree_set((0u32..6).prop_map(slot), 0..=4)
    }

    /// A VALIDATED RELEASE whose frozen topology for target `t1` covers
    /// EXACTLY `membership` (every slot in variant `standard`, no groups,
    /// on server `s1`), with a consistent identity (the behavior digest
    /// matches the record provenance) — the release graph the revalidation
    /// checks claims against.
    fn validated_release(membership: &BTreeSet<SlotId>) -> ValidatedRelease {
        let variants: BTreeMap<VariantName, crate::identity::TreeDigest> =
            BTreeMap::from([(VariantName::new("standard"), test_tree_digest("t"))]);
        let slots: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::from([(
            "standard".to_string(),
            membership
                .iter()
                .map(|s| {
                    SlotConfig::new(
                        s.as_str().to_string(),
                        "s1".to_string(),
                        std::path::PathBuf::from("/srv/x"),
                        "t1".to_string(),
                        Vec::new(),
                    )
                })
                .collect(),
        )]);
        let behaviors: BTreeMap<String, BehaviorContract> = BTreeMap::from([(
            "standard".to_string(),
            BehaviorContract::new(
                Activation::None,
                Verification::Command(
                    ValidatedCommand::new(vec!["true".to_string()], 30, 2, 1)
                        .expect("validated command"),
                ),
            ),
        )]);
        let sha = variant_behaviors_digest(&behaviors);
        let rec = build_release("m", &sha, &variants, &slots, std::path::Path::new("."));
        let servers: BTreeSet<String> = BTreeSet::from(["s1".to_string()]);
        ValidatedRelease::try_new(rec, behaviors, &servers)
            .expect("a consistent release graph validates")
    }

    /// Build the WIRE CLAIM with the given (possibly inconsistent)
    /// components: the claimed agreed membership, the frozen topology keys,
    /// and the physical slot keys are independent — the claim is
    /// constructible (the wire shape is a claim, not a proof) and the
    /// revalidation decides its validity against the release graph + plan.
    fn claim_with(
        release: &ValidatedRelease,
        claimed_membership: &BTreeSet<SlotId>,
        frozen_keys: &BTreeSet<SlotId>,
        physical_keys: &BTreeSet<SlotId>,
    ) -> RebindingPlan {
        let frozen_topology = frozen_keys
            .iter()
            .map(|k| {
                (
                    k.clone(),
                    FrozenSlotTopology {
                        variant: "standard".to_string(),
                        groups: Vec::new(),
                    },
                )
            })
            .collect();
        let current_physical_slots = physical_keys
            .iter()
            .map(|k| {
                (
                    k.clone(),
                    PhysicalBinding::from_config(
                        ServerId::parse("s1").expect("safe segment"),
                        "/srv/x",
                    )
                    .expect("the test binding is absolute and traversal-free"),
                )
            })
            .collect();
        RebindingPlan {
            release: ReleaseId::parse(&release.record().release_id).expect("the release id parses"),
            target: TargetName::parse("t1").expect("safe segment"),
            frozen_topology,
            membership: claimed_membership.clone(),
            current_physical_slots,
        }
    }

    proptest! {
        // THE REVALIDATION PROPERTY (the review's acceptance): over
        // ARBITRARY claimed components — a non-empty release-graph
        // membership plus independent (possibly inconsistent) claimed agreed
        // memberships, frozen-topology keys, selected plan slots, and
        // physical slot keys — the load-time revalidation
        // ([`VerifiedReleaseRebinding::revalidate`]) accepts EXACTLY the
        // claims that match the release graph AND the plan (claimed frozen
        // keys == the release's frozen membership, claimed agreed
        // membership == the release's frozen membership, selected ⊆
        // membership, physical keys == selected) and refuses every tamper,
        // and every accepted proof's components agree (the proof's
        // invariants hold by construction). Bounded `proptest_cases(16)`
        // (full 16 with `DEPLOY_FULL_TESTS=1`, fast 4 otherwise), fixed
        // seed 0x5EED_5EED (house style), no failure persistence.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn claim_revalidates_exactly_when_it_matches_the_release_graph_and_plan(
            membership in arbitrary_membership(),
            claimed_membership in arbitrary_slot_set(),
            frozen_keys in arbitrary_slot_set(),
            selected in arbitrary_slot_set(),
            physical_keys in arbitrary_slot_set(),
        ) {
            // The release graph freezes EXACTLY `membership` for target t1.
            let release = validated_release(&membership);
            let claim =
                claim_with(&release, &claimed_membership, &frozen_keys, &physical_keys);
            // The claim is valid EXACTLY when it matches the release graph
            // (the claimed frozen topology keys AND the claimed agreed
            // membership both equal the release's frozen membership) AND the
            // plan (selected ⊆ membership, physical == selected).
            let expected_valid = frozen_keys == membership
                && claimed_membership == membership
                && selected.is_subset(&membership)
                && physical_keys == selected;
            let result = VerifiedReleaseRebinding::revalidate(&claim, &release, &selected);
            if expected_valid {
                let proof = result.expect("a valid claim revalidates to a verified proof");
                // THE PROOF'S INVARIANTS: the components agree — the frozen
                // topology keys equal the membership's agreed slots, every
                // selected plan slot is a member, and the physical slots
                // cover exactly the selected plan slots.
                let frozen: BTreeSet<SlotId> =
                    proof.frozen_topology().keys().cloned().collect();
                prop_assert_eq!(
                    frozen,
                    membership.clone(),
                    "the proof's frozen topology keys equal the agreed membership"
                );
                prop_assert!(
                    proof.selected_plan_slots().is_subset(&membership),
                    "every selected plan slot is a member of the agreed membership"
                );
                let physical: BTreeSet<SlotId> =
                    proof.current_physical_slots().keys().cloned().collect();
                prop_assert_eq!(
                    physical,
                    proof.selected_plan_slots().clone(),
                    "the proof's physical slots cover exactly the selected plan slots"
                );
                prop_assert_eq!(
                    proof.release().as_str(),
                    &release.record().release_id,
                    "the proof carries the validated release"
                );
                prop_assert_eq!(proof.target().as_str(), "t1");
            } else {
                prop_assert!(
                    result.is_err(),
                    "a tampered claim must be refused by the revalidation"
                );
            }
        }

        // THE DOMAIN → WIRE PROJECTION ROUND TRIP: a verified proof
        // projects back into a CLAIM ([`From<&VerifiedReleaseRebinding>`])
        // whose revalidation reproduces the EXACT proof (the claim is the
        // wire form; the selected slots are re-derived from the plan's own
        // membership on the next read).
        #[test]
        fn verified_proof_projects_to_a_claim_that_revalidates(
            membership in arbitrary_membership(),
            selected in arbitrary_membership(),
        ) {
            // Restrict `selected` to a subset of the membership (a valid
            // claim).
            let selected: BTreeSet<SlotId> = selected
                .iter()
                .filter(|s| membership.contains(s))
                .cloned()
                .collect();
            if selected.is_empty() {
                return Ok(());
            }
            let release = validated_release(&membership);
            let claim = claim_with(&release, &membership, &membership, &selected);
            let proof = VerifiedReleaseRebinding::revalidate(&claim, &release, &selected)
                .expect("the claim is valid");
            let claim2 = RebindingPlan::from(&proof);
            let proof2 = VerifiedReleaseRebinding::revalidate(&claim2, &release, &selected)
                .expect("revalidates");
            prop_assert_eq!(proof, proof2);
        }
    }
}
