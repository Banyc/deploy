//! PLANNING: every pre-mutation planning / preflight semantic.
//!
//! Nested along the planning concerns: this module holds the assignment
//! planner itself ([`plan_assignments`], [`release_behavior_index`]);
//! `selection` holds slot selection + the proof-bearing resolution;
//! `groups` the direct-release membership gate; `preflight` the
//! capacity preflight + the disposable staging lifecycle (the capacity +
//! staging preflight pair); `guards` the partial-rollout guards, the
//! exact-rollback binding verification and the behavior-coverage gate.

use crate::config::ProjectConfig;
use crate::error::Error;
use crate::error::Result;
use crate::identity::ArtifactRef;
use crate::identity::PlacementSlotAssignment;
use crate::identity::ReleaseId;
use crate::identity::ServerId;
use crate::identity::SlotId;
use crate::identity::TreeDigest;
use crate::identity::VariantName;
use crate::ledger::FrozenSlotTopology;
use crate::ledger::LedgerRollback;
use crate::ledger::PhysicalBinding;
use crate::ledger::PlanOrigin;
use crate::ledger::PushRef;
use crate::ledger::VerifiedReleaseRebinding;
use crate::ledger::resolve_deployment;
use crate::store::local::LocalStore;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

mod groups;
mod guards;
mod preflight;
mod selection;

pub(crate) use groups::*;
pub(crate) use guards::*;
pub(crate) use preflight::*;
pub(crate) use selection::*;

// ---- planning: assignment planner ----
// Deployment planning: resolve the desired per-slot assignment from a push
// reference.
//
// # One rule: each reference kind consults ONLY its declared temporal source
//
// The temporal sources are declared explicitly, and every push reference
// resolves against EXACTLY one:
//
// * **HEAD** (``/`HEAD`/`@`/`parent(@, 0)`): the CURRENT variant slot
//   declarations. Planning reads only the caller's current configuration
//   (the current variant files and the current physical slots) and is blind
//   to every historical record.
// * **`release:<id>`**: that RELEASE's frozen slot→variant and group
//   topology (the release record's OWN canonical slot snapshot), applied
//   onto the CURRENT physical slots under the LOGICAL membership check. The
//   rebinding is now EXPLICIT and VERIFIED: the plan's origin
//   ([`crate::ledger::PlanOrigin::Release`]) CARRIES its
//   [`crate::ledger::VerifiedReleaseRebinding`] proof INSIDE the source —
//   the frozen topology, the membership check, the selected plan slots, and
//   the current physical slots it binds onto. A
//   `--group <g>` selection resolves the group's slot IDs from THIS frozen
//   topology (each frozen slot's era `groups` list), never from the caller's
//   current group partition: a slot the release pushed inside `g` but the
//   current config moved out of `g` still belongs to the push, and a group
//   named only in the frozen topology still resolves.
// * **a deployment rollback** (`deploy push <target> <deployment-id>`, and
//   the `@`-relative / `parent(...)` walk resolved by
//   [`crate::ledger::resolve_ref_expr`] against the target's ledger): that
//   DEPLOYMENT's exact per-slot artifact AND physical binding (the rollback
//   payload's generation refs + recorded `bindings`). The caller's current
//   variant files never re-map them.
// * **the CURRENT server configuration**: connectivity and live capacity
//   ONLY. It never contributes topology — no reference resolves slot→variant
//   or membership from `deploy.toml`'s servers — and capacity headroom is a
//   per-server policy resolved from the caller's current configuration on
//   every push (servers have no per-release history).
//
// The one historically IMPLICIT exception — a `release:<id>` push applying a
// historical release's frozen topology onto the CURRENT physical slots — is
// now an explicit, typed, VERIFIED artifact: the plan's origin
// ([`crate::ledger::PlanOrigin::Release`]) carries its
// [`crate::ledger::VerifiedReleaseRebinding`] proof INSIDE the source,
// built in the `PushRef::Release` branch of [`plan_assignments`] from the
// membership gate's proof.

/// The plan for one placement slot: exactly the canonical slot→artifact
/// assignment ([`PlacementSlotAssignment`]), reused rather than re-declared.
pub type PlannedAssignment = PlacementSlotAssignment;

/// The resolution of one push reference into a planned assignment set: the
/// per-slot assignments, the SET of releases they reference (per-slot
/// artifact provenance — a partial snapshot can span several releases, so
/// there is NO single snapshot-wide release), and the VERIFIED plan origin
/// ([`PlanOrigin`]) — THE SOURCE OWNS ITS REQUIRED PAYLOAD: a DIRECT
/// release reference carries its [`VerifiedReleaseRebinding`] proof INSIDE
/// the source (a Release origin without the proof is unrepresentable);
/// HEAD and deployment references carry none — plus the PROOF-BEARING
/// `ResolvedSelection` the assignments were derived from: the target, its
/// declared temporal source, and the non-empty resolved slot set. The
/// engine consumes the resolution by accessor (`PlannedResolution::resolved`);
/// it can never construct one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedResolution {
    pub assignments: Vec<PlannedAssignment>,
    pub releases: BTreeSet<ReleaseId>,
    /// THE SOURCE OWNS ITS REQUIRED PAYLOAD: the verified [`PlanOrigin`] —
    /// a Release origin carries its [`VerifiedReleaseRebinding`] proof
    /// inside the source; HEAD and deployment origins carry none.
    pub origin: PlanOrigin,
    resolved: ResolvedSelection,
}

impl PlannedResolution {
    /// The planner-produced, proof-bearing resolution this plan was derived
    /// from: target + declared temporal source + non-empty resolved slot set.
    /// The engine consumes it by accessor, never by construction.
    pub(crate) fn resolved(&self) -> &ResolvedSelection {
        &self.resolved
    }
}

/// The latest successful rollback state of a target (the base for a partial
/// rollout's complete snapshot), or `None` when the target has no successful
/// deployment yet.
pub(crate) fn latest_successful_rollback(
    store: &LocalStore,
    target: &str,
) -> Result<Option<LedgerRollback>> {
    for entry in store.read_ledger(target)?.into_iter().rev() {
        if let Some(t) = entry.terminal
            && let crate::ledger::TerminalDisposition::Successful { rollback, .. } = t.disposition
        {
            return Ok(Some(rollback));
        }
    }
    Ok(None)
}

/// Resolve the desired assignment for each SELECTED slot given the push
/// reference. The selection (target + optional group) is normalized once near
/// command entry; each reference branch resolves its selected slot IDs
/// against its own declared temporal source (HEAD and deployment refs: the
/// current topology; `release:<id>`: the release's FROZEN topology) and
/// planning consumes the resolution instead of independently filtering
/// slots. Returns the assignments, the SET of
/// releases the assignments reference (per-slot artifact provenance — a
/// partial snapshot can span several releases, so there is NO single
/// snapshot-wide release), the plan source, and — for a DIRECT release
/// reference — the explicit [`crate::ledger::RebindingPlan`] documenting that the
/// historical release's frozen topology is being applied onto the CURRENT
/// physical slots (`None` for HEAD and deployment references). Each
/// reference kind consults ONLY its declared temporal source: HEAD reads the
/// caller's current variant declarations, `release:<id>` reads the release
/// record's frozen slot→variant/group topology, a deployment ref reads the
/// snapshot's exact per-slot artifact + binding, and the current server
/// configuration contributes only connectivity + live capacity.
///
/// ### Temporal sources
///
/// See the module docs for the full rule; in short: HEAD plans from the
/// CURRENT variant slot declarations; `release:<id>` plans from the
/// RELEASE's frozen topology + the logical membership check and produces the
/// explicit [`crate::ledger::RebindingPlan`]; a deployment rollback uses the DEPLOYMENT's
/// exact per-slot artifact and physical binding.
pub fn plan_assignments(
    selection: &SlotSelection,
    pref: &PushRef,
    local_release_id: &ReleaseId,
    variant_trees: &BTreeMap<String, TreeDigest>,
    store: &LocalStore,
    config: &ProjectConfig,
) -> Result<PlannedResolution> {
    if config.target(selection.target.as_str()).is_none() {
        return Err(Error::not_found(format!("target '{}'", selection.target)));
    }

    // SLOT-ID RESOLUTION HAPPENS INSIDE EACH REFERENCE BRANCH against that
    // branch's declared temporal source: HEAD resolves the selected slots
    // from the CURRENT config's declarations; `release:<id>` resolves them
    // from the RELEASE's FROZEN per-slot `groups` (rebound onto the current
    // physical slots); a deployment ref resolves them from the current
    // config (narrowed by the snapshot's exact per-slot checks). The
    // selection itself carries only {target, group} — never slot IDs — so a
    // historical release's frozen group partition governs its push even when
    // it differs from the current partition (and a group named only in the
    // frozen topology still resolves).
    match pref {
        PushRef::Head => {
            // HEAD's declared temporal source is the CURRENT topology: the
            // group's slot IDs resolve from the caller's current variant slot
            // declarations (`config.target_group_slots` — an unknown group,
            // or one selecting zero slots in the current config, is a
            // configuration error, unchanged).
            let members = selection.current_members(config)?;
            // THE PROOF-BEARING RESOLUTION: the planner resolves the
            // reference against its declared temporal source (HEAD — the
            // CURRENT topology) into a non-empty slot set, then derives the
            // assignments from it. The engine consumes the resolution by
            // accessor, never by construction.
            let resolved = ResolvedSelection::new(
                selection.target.clone(),
                ResolvedSelectionSource::Head,
                members.iter().map(|(slot, _)| {
                    SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment")
                }),
            )?;
            let mut out = Vec::new();
            for (slot, _sdef) in &members {
                let slot_id =
                    SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment");

                // The slot's variant is the variant file that declares it (the
                // declaring file is the binding; there is no per-slot `variant`
                // field).
                let variant_name = config.slot_variant(&slot.id)?;
                let variant =
                    VariantName::parse(variant_name).expect("variant name is a safe segment");
                let tree = variant_trees.get(variant_name).cloned().ok_or_else(|| {
                    Error::plan(format!("variant '{variant_name}' not materialized"))
                })?;
                out.push(PlannedAssignment {
                    placement_slot: slot_id,
                    artifact: ArtifactRef {
                        release: local_release_id.clone(),
                        variant,
                        tree,
                    },
                });
            }
            Ok(PlannedResolution {
                assignments: out,
                releases: BTreeSet::from([local_release_id.clone()]),
                origin: PlanOrigin::Head,
                resolved,
            })
        }
        PushRef::Deployment {
            target: ft,
            deployment_id,
        } => {
            // A deployment rollback's SELECTED slots also resolve from the
            // CURRENT topology (as for HEAD): the snapshot's exact per-slot
            // artifact and physical-binding checks below narrow them. There
            // is no per-deployment group partition — groups are a
            // current-config selection view.
            let members = selection.current_members(config)?;
            // THE PROOF-BEARING RESOLUTION of the DEPLOYMENT reference: the
            // target, its declared temporal source (the deployment's exact
            // per-slot assignment), and the non-empty selected slot set
            // (resolved from the current topology, narrowed by the
            // snapshot's exact per-slot checks below).
            let resolved = ResolvedSelection::new(
                selection.target.clone(),
                ResolvedSelectionSource::Deployment(deployment_id.clone()),
                members.iter().map(|(slot, _)| {
                    SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment")
                }),
            )?;
            let slot_ids: Vec<SlotId> = members
                .iter()
                .map(|(slot, _)| {
                    SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment")
                })
                .collect();
            let entry = resolve_deployment(store, ft, deployment_id)?;
            let recorded: BTreeSet<String> =
                entry.slots.keys().map(|s| s.as_str().to_string()).collect();
            let current: BTreeSet<String> =
                slot_ids.iter().map(|s| s.as_str().to_string()).collect();
            // A FULL rollback (no group) restores every current slot, so the
            // snapshot's slot set must equal the target's current set. A GROUP
            // rollback restores only the selected slots: the snapshot must
            // contain every selected slot (checked per slot below), while
            // unselected slots remain at the latest current state.
            if selection.group.is_none() && recorded != current {
                return Err(Error::rollback(
                    "target membership changed; exact rollback requires identical stable placement-slot set",
                ));
            }
            // The EXACT-ROLLBACK VERIFICATION (A2): every SELECTED member's
            // COMPLETE physical binding — the server AND the on-server
            // deploy_dir — must match the one recorded in the snapshot (see
            // [`verify_exact_rollback_bindings`]).
            // Unselected slots are not planned (they remain at the latest
            // current state).
            verify_exact_rollback_bindings(&members, &entry, deployment_id, ft)?;
            // The releases the snapshot's slots reference, derived PER SLOT
            // from each slot's OWN artifact binding: a partial snapshot can
            // carry slots from DIFFERENT releases (group pushes over time —
            // group A pushed R1, group B pushed R2), so there is no single
            // snapshot-wide release.
            let mut out = Vec::new();
            for (slot, _sdef) in &members {
                let slot_id =
                    SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment");

                let g = entry.slots.get(&slot_id).ok_or_else(|| {
                    Error::rollback(format!("slot {slot_id} missing in snapshot"))
                })?;
                out.push(PlannedAssignment {
                    placement_slot: slot_id,
                    artifact: g.assignment.artifact.clone(),
                });
            }
            let releases: BTreeSet<ReleaseId> =
                out.iter().map(|a| a.artifact.release.clone()).collect();
            Ok(PlannedResolution {
                assignments: out,
                releases,
                origin: PlanOrigin::Deployment(deployment_id.clone()),
                resolved,
            })
        }
        PushRef::Release { release } => {
            let rec = store
                .read_release(release)
                .map_err(|_| Error::rollback(format!("release {release} not available locally")))?;
            // DIRECT-RELEASE MEMBERSHIP CHECK (before any remote access) — see
            // [`validate_direct_release_membership`]. The engine's `push()`
            // ALSO runs this gate before the remote factory is ever invoked
            // (real AND dry-run modes); this plan-time call is the second line
            // of defense, protecting the direct-`push_inner` test entry points.
            // The gate compares the release's frozen slots against the target's
            // COMPLETE current membership — EVERY slot whose owning `target`
            // equals the target (`config.target_slots`), never the
            // group-filtered selection: a `release:<id> --group <g>` push
            // validates the FULL set here (and in the engine gate) and then
            // plans ONLY the selected slots (the `members` loop below is
            // already group-aware).
            let current_slot_ids: Vec<SlotId> = config
                .target_slots(selection.target.as_str())?
                .into_iter()
                .map(|(slot, _)| {
                    SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment")
                })
                .collect();
            // THE MEMBERSHIP GATE PRODUCES THE PROOF: the frozen and current
            // memberships verified EXACTLY EQUAL (the agreed non-empty slot
            // set); the planner consumes it as the rebinding record's
            // membership check below.
            let membership = validate_direct_release_membership(
                selection.target.as_str(),
                release,
                &rec,
                &current_slot_ids,
            )?;
            // THE RELEASE'S FROZEN GROUP PARTITION GOVERNS: the selected
            // slots resolve from the release record's OWN canonical slot
            // snapshot — each frozen [`crate::identity::CanonicalSlot`] carries
            // its era's `groups` list, so a slot the release pushed inside
            // the group but the current config moved OUT of it still belongs
            // to this push, and a group named only in the frozen topology
            // (unknown in the current config) still resolves. The frozen IDs
            // are then REBOUND onto their current physical locations
            // (server / deploy_dir from the target's current member
            // declarations) — the explicit [`RebindingPlan`] below records
            // exactly this frozen-topology → current-physical-slot
            // composition. A frozen group selecting zero slots is a
            // configuration error as today. (The membership gate above
            // guarantees the frozen slot-ID set equals the target's COMPLETE
            // current membership, so every frozen id rebinds to a current
            // physical declaration.)
            let members = selection.release_members(config, &rec)?;
            // THE PROOF-BEARING RESOLUTION of the FROZEN-RELEASE reference:
            // the target, its declared temporal source (the release's frozen
            // topology), and the non-empty resolved slot set (the PLANNED
            // slots — a `--group` push narrows the assignments, never the
            // full-membership gate above).
            let resolved = ResolvedSelection::new(
                selection.target.clone(),
                ResolvedSelectionSource::FrozenRelease(release.clone()),
                members.iter().map(|(slot, _)| {
                    SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment")
                }),
            )?;
            let mut out = Vec::new();
            for (slot, _sdef) in &members {
                let slot_id =
                    SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment");

                // The variant ALWAYS comes from the release's OWN stored slot
                // snapshot: a historical release resolves each slot's
                // slot→variant binding against the slots it was materialized
                // from, never the caller's current variant files. Note this
                // slot declaration snapshot is distinct from a deployment
                // snapshot's slot→SERVER bindings (the exact-rollback
                // physical-host check): those remain a per-target deployment
                // concern.
                let variant_name = if rec.slots.is_empty() {
                    // A record without a canonical slot snapshot is
                    // unverifiable; the store rejects such records at read,
                    // so this is a belt-and-braces refusal rather than a
                    // reachable fallback to the current configuration.
                    return Err(Error::rollback(format!(
                        "release {release} carries no stored slot snapshot; cannot resolve slot '{slot_id}'"
                    )));
                } else {
                    rec.slots
                        .iter()
                        .find_map(|(v, cs)| {
                            cs.slots
                                .iter()
                                .any(|s| s.id == slot_id.as_str())
                                .then(|| v.clone())
                        })
                        .ok_or_else(|| {
                            Error::rollback(format!(
                                "release {release} declares no slot '{slot_id}'"
                            ))
                        })?
                };
                let variant =
                    VariantName::parse(&variant_name).expect("variant name is a safe segment");
                let tree = rec.variants.get(&variant_name).cloned().ok_or_else(|| {
                    Error::rollback(format!("release {release} lacks variant '{variant_name}'"))
                })?;
                out.push(PlannedAssignment {
                    placement_slot: slot_id,
                    artifact: ArtifactRef {
                        release: release.clone(),
                        variant,
                        tree: TreeDigest::parse(&tree)
                            .expect("release record variant tree is a valid digest"),
                    },
                });
            }
            // THE EXPLICIT REBINDING CONTEXT — the plan-level record that this
            // `release:<id>` push is REBINDING the historical release's frozen
            // topology onto the CURRENT physical slots. Historically this was
            // the one IMPLICIT exception to the temporal-source rule (HEAD
            // plans from current decls, a deployment ref uses the deployment's
            // exact binding, current server configuration contributes only
            // connectivity + capacity): the release resolved slot→variant from
            // its own frozen record while its slot→SERVER rebinding onto the
            // current target stayed implicit. The RebindingPlan makes it
            // explicit and typed: the frozen slot→variant/group topology
            // (from the record's OWN snapshot, filtered to the destination
            // target), the LOGICAL membership check that ran (the release's
            // frozen slot IDs == the target's COMPLETE current membership —
            // physical bindings may differ, the logical membership must
            // match), and the CURRENT physical slots the topology is bound
            // onto (the PLANNED slots: a `--group` push narrows the
            // assignments — the membership check still covers the complete
            // set, composed with the engine's full-membership gate).
            let mut frozen_topology: BTreeMap<SlotId, FrozenSlotTopology> = BTreeMap::new();
            for (variant, cs) in &rec.slots {
                for slot in &cs.slots {
                    if slot.target == selection.target.as_str() {
                        frozen_topology.insert(
                            SlotId::parse(slot.id.as_str())
                                .expect("validated slot id is a safe segment"),
                            FrozenSlotTopology {
                                variant: variant.clone(),
                                groups: slot.groups.clone(),
                            },
                        );
                    }
                }
            }
            // THE VERIFIED REBINDING PROOF — the plan-level record that this
            // `release:<id>` push is REBINDING the historical release's frozen
            // topology onto the CURRENT physical slots. Historically this was
            // the one IMPLICIT exception to the temporal-source rule (HEAD
            // plans from current decls, a deployment ref uses the deployment's
            // exact binding, current server configuration contributes only
            // connectivity + capacity): the release resolved slot→variant from
            // its own frozen record while its slot→SERVER rebinding onto the
            // current target stayed implicit. The proof makes it explicit and
            // typed: the frozen slot→variant/group topology (from the record's
            // OWN snapshot, filtered to the destination target), the LOGICAL
            // membership check that ran (the release's frozen slot IDs == the
            // target's COMPLETE current membership — physical bindings may
            // differ, the logical membership must match), the SELECTED plan
            // slots (the PLANNED slots: a `--group` push narrows the
            // assignments — the membership check still covers the complete
            // set, composed with the engine's full-membership gate), and the
            // CURRENT physical slots the topology is bound onto. The ONLY
            // construction path is [`VerifiedReleaseRebinding::verify`], which
            // checks that every component agrees (frozen topology keys ==
            // membership, selected slots ⊆ membership, physical slots ==
            // selected).
            let rebinding = VerifiedReleaseRebinding::verify(
                release.clone(),
                selection.target.clone(),
                frozen_topology,
                // The PROOF the membership gate produced above: the frozen
                // and current memberships verified EXACTLY EQUAL. Only a
                // verified [`crate::identity::MatchingMembership`] can be
                // recorded here — the proof is the only construction path.
                membership,
                members
                    .iter()
                    .map(|(slot, _)| {
                        SlotId::parse(slot.id.as_str())
                            .expect("validated slot id is a safe segment")
                    })
                    .collect(),
                members
                    .iter()
                    .map(|(slot, sdef)| {
                        (
                            SlotId::parse(slot.id.as_str())
                                .expect("validated slot id is a safe segment"),
                            PhysicalBinding {
                                server: ServerId::parse(sdef.id.as_str())
                                    .expect("validated server id is a safe segment"),
                                deploy_dir: slot.deploy_dir().to_string_lossy().into_owned(),
                            },
                        )
                    })
                    .collect(),
            )?;
            Ok(PlannedResolution {
                assignments: out,
                releases: BTreeSet::from([release.clone()]),
                origin: PlanOrigin::Release {
                    release: release.clone(),
                    rebinding,
                },
                resolved,
            })
        }
    }
}

/// Load the frozen per-release, per-variant behavior contracts for EVERY
/// release an attempt's slots reference. Historical and rollback pushes
/// resolve EACH SLOT's behavior from ITS OWN (release, variant) binding — the
/// release record's stored per-variant contract, verified against the
/// release's provenance digest via [`LocalStore::read_release_behaviors`]. A
/// partial snapshot's slots can carry artifacts from DIFFERENT releases
/// (group pushes over time), so the index is keyed by release, then variant
/// — there is NO snapshot-wide single release/behavior. Failures (a missing
/// or tampered release record / behavior snapshot) propagate closed: a
/// historical push never silently substitutes the caller's current
/// configuration.
pub fn release_behavior_index(
    store: &LocalStore,
    releases: &BTreeSet<ReleaseId>,
) -> Result<crate::ledger::BehaviorIndex> {
    let mut index = crate::ledger::BehaviorIndex::new();
    for rid in releases {
        let behaviors = store.read_release_behaviors(rid)?;
        index.insert(rid.clone(), behaviors);
    }
    Ok(index)
}

#[cfg(test)]
mod plan_tests {
    use super::*;
    use crate::identity::{
        ArtifactRef, BehaviorContract, CanonicalSlot, CanonicalSlots, DeploymentId, GenerationRef,
        Provenance, ReleaseRecord, ServerId, SlotId, TargetName, TreeDigest, VariantName,
        test_deployment_id, test_generation_id, test_tree_digest,
    };
    use crate::ledger::{
        DeploymentIntent, DesiredGeneration, IntentSlot, LedgerRollback, LedgerTerminal,
        NonEmptySlotTable, ObservationWire, ObservedGenerationWire, PhysicalBinding, SlotOutcome,
        SlotOutcomeKind, SlotResult, SlotTable, TerminalDisposition,
    };
    use crate::verify::release::RELEASE_RECORD_SCHEMA_VERSION;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    /// Assert the planned origin is a Release origin naming the given
    /// release and carrying the VERIFIED rebinding proof; returns the proof
    /// (the caller then asserts its frozen topology / membership / physical
    /// slots). A Release origin without its proof is unrepresentable, so
    /// this single assertion covers both the release identity and the
    /// proof's presence.
    fn release_origin<'a>(
        origin: &'a PlanOrigin,
        release: &ReleaseId,
    ) -> &'a VerifiedReleaseRebinding {
        match origin {
            PlanOrigin::Release {
                release: r,
                rebinding,
            } => {
                assert_eq!(
                    r, release,
                    "the release origin must name the planned release"
                );
                rebinding
            }
            other => panic!("expected a Release origin for {release}, got {other:?}"),
        }
    }

    const DEPLOY_TOML: &str = r#"
schema_version = 2
application = "plan"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;

    /// Two-target fixture for the direct-release property: `t1` is the
    /// SOURCE (it carries the snapshot that recorded the old physical
    /// binding), `t2` the DESTINATION with NO snapshot history (the release
    /// was built/pushed elsewhere). Both declare the same slot `p1`.
    const DEPLOY_TOML_TWO: &str = r#"
schema_version = 2
application = "plan"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s2"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }

[targets.t2]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;

    /// The `standard` variant file declares slot `p1` on server `s1` for
    /// target `t1`: the declaring file is the slot's CURRENT variant binding
    /// and owns the slot's ONE retention policy.
    const VARIANT_TOML: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/plan"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[retention.deployment]
protect_deployments = 1

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

    /// The direct-release property's variant: slot `p1` bound to server `s1`
    /// at `/srv/plan` for BOTH targets `t1` (source) and `t2` (destination).
    /// The owning variant file carries the slot's single retention policy.
    const VARIANT_TOML_TWO: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/plan"

[[slots]]
id = "p2"
server = "s2"
target = "t2"
deploy_dir = "/srv/plan-2"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[retention.deployment]
protect_deployments = 1

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

    fn project_with_config() -> (tempfile::TempDir, ProjectConfig) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), VARIANT_TOML).unwrap();
        let p = project.join("deploy.toml");
        std::fs::write(&p, DEPLOY_TOML).unwrap();
        let config = ProjectConfig::load(&p).unwrap();
        (dir, config)
    }

    /// Seed a SUCCESSFUL ledger entry for `t1` (intent + `Successful`
    /// terminal carrying the rollback payload), mirroring the old
    /// `append_snapshot` test helper. The rollback payload carries the
    /// snapshot's `slots`/`bindings`; there is NO snapshot-wide release —
    /// each slot's generation ref carries its OWN artifact (release, variant,
    /// tree), and a partial snapshot can span several releases.
    fn append_successful_snapshot(
        store: &LocalStore,
        deployment_id: &str,
        behavior_sha256: &str,
        slots: BTreeMap<SlotId, GenerationRef>,
        bindings: BTreeMap<SlotId, PhysicalBinding>,
    ) {
        let id = test_deployment_id(deployment_id);
        let target = TargetName::new("t1".to_string());
        // ONE slot table: the membership + per-slot desired entries.
        let slot_table: BTreeMap<SlotId, IntentSlot> = slots
            .iter()
            .map(|(k, g)| {
                (
                    k.clone(),
                    IntentSlot {
                        desired: DesiredGeneration {
                            generation: g.generation.clone(),
                            artifact: g.assignment.artifact.clone(),
                        },
                        pre_push: None,
                        // The intent FREEZES each slot's plan-time physical
                        // binding (schema v6) — seed it from the same
                        // bindings the terminal's rollback records when the
                        // caller binds the slot; a deliberately UNBOUND seed
                        // (a legacy-snapshot test whose terminal's rollback
                        // omits the bindings the conversion must refuse) is
                        // given the canonical fixture binding so the INTENT
                        // itself stays a valid schema-v6 record.
                        binding: bindings.get(k).cloned().unwrap_or(PhysicalBinding {
                            server: ServerId::new("s1".to_string()),
                            deploy_dir: "/srv/eng".to_string(),
                        }),
                    },
                )
            })
            .collect();
        store
            .append_intent(
                "t1",
                &DeploymentIntent {
                    deployment_id: id.clone(),
                    target: target.clone(),
                    group: None,
                    behavior_sha256: behavior_sha256.to_string(),
                    attempted_at: "2026-01-01T00:00:00Z".to_string(),
                    slots: NonEmptySlotTable::build(slot_table)
                        .expect("a seeded snapshot always has at least one slot"),
                    full_membership: slots.keys().cloned().collect(),
                },
            )
            .unwrap();
        store
            .append_terminal(
                "t1",
                &id,
                &LedgerTerminal {
                    recorded_at: "2026-01-01T00:00:00Z".to_string(),
                    // The EXACT-EQUAL shape: one Activated outcome per
                    // slotted generation, and the memberships PROVE the
                    // equations (outcomes == selected == full == the
                    // rollback's slots — the read enforces them, so a
                    // seeded Successful terminal must carry one outcome per
                    // slotted generation).
                    disposition: TerminalDisposition::Successful {
                        rollback: LedgerRollback {
                            slots: slots.clone(),
                            bindings,
                        },
                        outcomes: SlotTable::from_map(
                            slots
                                .iter()
                                .map(|(k, g)| {
                                    (
                                        k.clone(),
                                        SlotOutcome::from_wire(SlotResult {
                                            slot_id: k.clone(),
                                            outcome: SlotOutcomeKind::Activated,
                                            observation: ObservationWire::Known(
                                                ObservedGenerationWire {
                                                    generation: g.generation.clone(),
                                                },
                                            ),
                                            compensated: false,
                                            error: None,
                                        })
                                        .unwrap(),
                                    )
                                })
                                .collect(),
                        ),
                        // THE EXACT-EQUAL MEMBERSHIPS: selected == full ==
                        // the slotted generations' keys (the rollback's
                        // slots / the outcomes' keys) — the proven shape the
                        // conversion + read require.
                        selected_membership: slots.keys().cloned().collect(),
                        full_membership: slots.keys().cloned().collect(),
                    },
                    reason: None,
                },
            )
            .unwrap();
    }

    /// A release record in the pre-snapshot SHAPE: an EMPTY `slots` map (the
    /// shape written before the slots-into-identity refactor, and what
    /// `#[serde(default)]` yields for records without a `slots` member). The
    /// store now REJECTS empty slot snapshots at write and read (an empty
    /// snapshot cannot be verified from content), so fixtures that need a
    /// WRITABLE record must fill `slots` and recompute the identity with
    /// [`consistent`]. The bare empty-snapshot record is used directly only
    /// when a test needs the on-disk legacy shape. It still carries the
    /// per-variant tree bindings.
    fn legacy_record(id: &str, tree: &str) -> ReleaseRecord {
        ReleaseRecord {
            release_schema_version: RELEASE_RECORD_SCHEMA_VERSION,
            release_id: id.to_string(),
            release_sha256: format!("sha256-{id}"),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            provenance: Provenance {
                mapping_sha256: "m".to_string(),
                behavior_sha256: "b".to_string(),
            },
            // The variant tree must be a VALID digest (the record is read
            // back through the validated parse), so derive the canonical
            // 64-hex form of the tag.
            variants: BTreeMap::from([(
                "standard".to_string(),
                test_tree_digest(tree).as_str().to_string(),
            )]),
            slots: BTreeMap::new(),
        }
    }

    /// Recompute a release record's stored identity from its own content so
    /// `read_release`'s recompute-and-verify passes: the digest is derived
    /// from the record's slot snapshot, bindings, and provenance digests
    /// exactly as `build_release` derives it. Returns the record's release id
    /// (the digest form, which is also the store directory key).
    fn consistent(rec: &mut ReleaseRecord) -> ReleaseId {
        let digest = crate::verify::release::recompute_release_digest(rec)
            .expect("consistent record must carry a slot snapshot");
        rec.release_sha256 = digest.as_str().to_string();
        rec.release_id = crate::identity::ReleaseId::from_digest(&digest)
            .as_str()
            .to_string();
        crate::identity::ReleaseId::parse(&rec.release_id)
            .expect("consistent record carries a validated release id")
    }

    /// A `PushRef::Release` resolution against a release record that carries
    /// its OWN stored canonical snapshot: each slot's variant binding resolves
    /// from the snapshot, the tree from the record's own per-variant
    /// bindings, and the assignment keeps the release's identity and resolves
    /// as `ReleaseRef`. (Empty-snapshot records are now REJECTED at the store
    /// boundary — see `empty_slot_snapshot_record_fails_closed_at_read` — so
    /// every writable release record carries its snapshot.)
    #[test]
    fn release_snapshot_resolves_variant_and_tree() {
        let (_dir, config) = project_with_config();
        let store = LocalStore::with_base(_dir.path().join("store")).unwrap();
        // The release's OWN snapshot declares p1 -> `standard` (matching the
        // current config's declaring file, `config.slot_variant`); the tree
        // comes from the record's own bindings.
        let mut rec = legacy_record("unused", "tree-legacy");
        rec.slots = BTreeMap::from([(
            "standard".to_string(),
            CanonicalSlots {
                slots: vec![CanonicalSlot {
                    id: "p1".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: "/srv/plan".to_string(),
                    target: "t1".to_string(),
                    groups: Vec::new(),
                }],
            },
        )]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();
        // The current config declares p1 inside the `standard` variant file.
        assert_eq!(config.slot_variant("p1").unwrap(), "standard");

        let (assignments, desired, origin) = plan_assignments(
            &SlotSelection::normalize(&config, "t1", None).unwrap(),
            &PushRef::Release {
                release: release.clone(),
            },
            &crate::identity::test_release_id("unused-local"),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .map(|planned| (planned.assignments, planned.releases, planned.origin))
        .expect("snapshot-carrying release resolves");

        assert_eq!(assignments.len(), 1);
        let a = &assignments[0];
        assert_eq!(a.placement_slot, SlotId::new("p1"));
        assert_eq!(
            a.artifact.variant.as_str(),
            "standard",
            "the variant must come from the release's OWN stored snapshot"
        );
        assert_eq!(
            a.artifact.tree.as_str(),
            test_tree_digest("tree-legacy").as_str(),
            "the tree must come from the release's own variant bindings"
        );
        assert_eq!(a.artifact.release, release);
        assert_eq!(desired, BTreeSet::from([release.clone()]));
        release_origin(&origin, &release);
    }

    /// An on-disk record with an EMPTY stored slot snapshot (the pre-snapshot
    /// legacy shape) fails closed at the STORE: `read_release` refuses it
    /// (an empty snapshot cannot be recomputed into an identity), so a
    /// `PushRef::Release` ref pointing at it surfaces as the release-rollback
    /// error and can never silently fall back to the caller's current
    /// configuration.
    #[test]
    fn empty_slot_snapshot_record_fails_closed_at_read() {
        let (_dir, config) = project_with_config();
        let store = LocalStore::with_base(_dir.path().join("store")).unwrap();
        let release = crate::identity::test_release_id("rel-sha256-legacy");
        // `write_release` refuses empty-snapshot records, so install the
        // legacy-shaped record directly (as pre-refactor on-disk data would
        // appear).
        let rec = legacy_record(release.as_str(), "tree-legacy");
        let dir = store.release_dir(&release);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("release.json"),
            serde_json::to_vec_pretty(&rec).unwrap(),
        )
        .unwrap();

        let err = plan_assignments(
            &SlotSelection::normalize(&config, "t1", None).unwrap(),
            &PushRef::Release {
                release: release.clone(),
            },
            &crate::identity::test_release_id("unused-local"),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect_err("an empty-slot-snapshot release must fail closed at read");
        assert!(
            err.to_string().contains("not available locally"),
            "the refusal must surface as the release-resolution rollback error, got: {err}"
        );
    }

    /// A NON-legacy release record whose stored slot snapshot does NOT
    /// declare the current target's member slot must fail closed with the
    /// MEMBERSHIP-DRIFT refusal before any remote access: the release froze a
    /// DIFFERENT slot set (here a renamed slot `pX` where the current config
    /// has `p1`) — the stored snapshot is authoritative, so direct release
    /// planning refuses rather than deploying to the wrong slot set.
    #[test]
    fn release_snapshot_missing_slot_refuses_drift() {
        let (_dir, config) = project_with_config();
        let store = LocalStore::with_base(_dir.path().join("store")).unwrap();
        let mut rec = legacy_record("unused", "tree-x");
        // A stored snapshot that declares a DIFFERENT slot (not the target's
        // member p1): renamed-slot drift.
        rec.slots = BTreeMap::from([(
            "standard".to_string(),
            CanonicalSlots {
                slots: vec![CanonicalSlot {
                    id: "pX".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: "/srv/other".to_string(),
                    target: "t1".to_string(),
                    groups: Vec::new(),
                }],
            },
        )]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();

        let err = plan_assignments(
            &SlotSelection::normalize(&config, "t1", None).unwrap(),
            &PushRef::Release {
                release: release.clone(),
            },
            &crate::identity::test_release_id("unused"),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect_err("a stored snapshot whose slot set drifts from the target must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("release") && msg.contains("drift"),
            "error must be the membership-drift refusal, got: {msg}"
        );
        assert!(
            msg.contains("pX") && msg.contains("p1"),
            "error must name the expected vs current slot sets, got: {msg}"
        );
        assert!(
            msg.contains("before remote access"),
            "error must explain the refusal happens before remote access, got: {msg}"
        );
    }

    /// MISSING-SLOT drift: the current target has a slot `p2` the release's
    /// stored snapshot does not declare — direct release planning refuses
    /// with the membership-drift error (expected [p1] vs current [p1, p2]).
    #[test]
    fn release_membership_drift_missing_slot_refuses() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        // Current config: TWO slots for t1 (p1 and p2, distinct servers).
        std::fs::write(
            release_dir.join("standard.toml"),
            r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/plan"

[[slots]]
id = "p2"
server = "s2"
target = "t1"
deploy_dir = "/srv/plan-2"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#,
        )
        .unwrap();
        let cfg_path = project.join("deploy.toml");
        // A second server entry so slot p2's server exists.
        std::fs::write(
            &cfg_path,
            DEPLOY_TOML.replace(
                "[[servers]]\nid = \"s1\"",
                "[[servers]]\nid = \"s2\"\naddress = \"a2\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n[[servers]]\nid = \"s1\"",
            ),
        )
        .unwrap();
        let config = ProjectConfig::load(&cfg_path).unwrap();
        assert_eq!(config.target_slot_ids("t1").unwrap(), ["p1", "p2"]);
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // The release's own snapshot pins ONLY p1 (p2 was added to the target
        // after the release was built elsewhere).
        let mut rec = legacy_record("unused", "tree-x");
        rec.slots = BTreeMap::from([(
            "standard".to_string(),
            CanonicalSlots {
                slots: vec![CanonicalSlot {
                    id: "p1".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: "/srv/plan".to_string(),
                    target: "t1".to_string(),
                    groups: Vec::new(),
                }],
            },
        )]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();

        let err = plan_assignments(
            &SlotSelection::normalize(&config, "t1", None).unwrap(),
            &PushRef::Release {
                release: release.clone(),
            },
            &crate::identity::test_release_id("unused"),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect_err("a release whose snapshot lacks a current member slot must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("membership") && msg.contains("[p1]") && msg.contains("[p1, p2]"),
            "drift error must name expected [p1] vs current [p1, p2], got: {msg}"
        );
    }

    /// EXTRA-SLOT drift: the release's own snapshot pins a slot `p2` the
    /// current target does not have — direct release refuses (expected
    /// [p1, p2] vs current [p1]).
    #[test]
    fn release_membership_drift_extra_slot_refuses() {
        let (_dir, config) = project_with_config();
        let store = LocalStore::with_base(_dir.path().join("store")).unwrap();
        let mut rec = legacy_record("unused", "tree-x");
        // The release pins p1 AND a p2 the current t1 has no member for.
        rec.slots = BTreeMap::from([(
            "standard".to_string(),
            CanonicalSlots {
                slots: vec![
                    CanonicalSlot {
                        id: "p1".to_string(),
                        server: "s1".to_string(),
                        deploy_dir: "/srv/plan".to_string(),
                        target: "t1".to_string(),
                        groups: Vec::new(),
                    },
                    CanonicalSlot {
                        id: "p2".to_string(),
                        server: "s2".to_string(),
                        deploy_dir: "/srv/plan-2".to_string(),
                        target: "t1".to_string(),
                        groups: Vec::new(),
                    },
                ],
            },
        )]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();

        let err = plan_assignments(
            &SlotSelection::normalize(&config, "t1", None).unwrap(),
            &PushRef::Release {
                release: release.clone(),
            },
            &crate::identity::test_release_id("unused"),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect_err("a release whose snapshot pins a slot the target lacks must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("membership") && msg.contains("[p1, p2]") && msg.contains("[p1]"),
            "error must name expected [p1, p2] vs current [p1], got: {msg}"
        );
    }

    /// LOGICAL-ONLY: a slot whose PHYSICAL binding changed (different server,
    /// same id) but whose id stays is still a member — the membership check
    /// compares slot IDs only, so a slot rebound to another server plans
    /// (contrast with the exact-rollback Snapshot branch, which refuses).
    #[test]
    fn release_membership_physical_binding_drift_plans() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        // CURRENT config: p1 rebound to server s2 at a moved deploy_dir.
        std::fs::write(
            release_dir.join("standard.toml"),
            r#"
[[slots]]
id = "p1"
server = "s2"
target = "t1"
deploy_dir = "/srv/moved"

[[artifact.mappings]]
from = "src/artifacts/build/output/"
to = "app/"
recursive = true

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#,
        )
        .unwrap();
        let cfg_path = project.join("deploy.toml");
        std::fs::write(
            &cfg_path,
            DEPLOY_TOML.replace(
                "[[servers]]\nid = \"s1\"",
                "[[servers]]\nid = \"s2\"\naddress = \"a2\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n[[servers]]\nid = \"s1\"",
            ),
        )
        .unwrap();
        let config = ProjectConfig::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // The release's OWN snapshot froze p1 at its ORIGINAL physical
        // binding (s1, /srv/plan) — the membership set is unchanged, so the
        // direct release plans onto the current (moved) binding.
        let mut rec = legacy_record("unused", "tree-x");
        rec.slots = BTreeMap::from([(
            "standard".to_string(),
            CanonicalSlots {
                slots: vec![CanonicalSlot {
                    id: "p1".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: "/srv/plan".to_string(),
                    target: "t1".to_string(),
                    groups: Vec::new(),
                }],
            },
        )]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();

        let (assignments, desired, origin) = plan_assignments(
            &SlotSelection::normalize(&config, "t1", None).unwrap(),
            &PushRef::Release {
                release: release.clone(),
            },
            &crate::identity::test_release_id("unused"),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .map(|planned| (planned.assignments, planned.releases, planned.origin))
        .expect("physical binding drift must not block logical-membership planning");
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].placement_slot, SlotId::new("p1"));
        assert_eq!(desired, BTreeSet::from([release.clone()]));
        release_origin(&origin, &release);
    }

    /// The TREE must come from the release record's own variant bindings: a
    /// release whose bindings lack the snapshot-resolved variant fails closed
    /// with a rollback error naming the release.
    #[test]
    fn release_missing_variant_tree_fails_rollback() {
        let (_dir, config) = project_with_config();
        let store = LocalStore::with_base(_dir.path().join("store")).unwrap();
        let mut rec = legacy_record("unused", "tree-x");
        rec.slots = BTreeMap::from([(
            "standard".to_string(),
            CanonicalSlots {
                slots: vec![CanonicalSlot {
                    id: "p1".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: "/srv/plan".to_string(),
                    target: "t1".to_string(),
                    groups: Vec::new(),
                }],
            },
        )]);
        rec.variants.clear(); // no variant bindings at all
        // Recompute the identity from the ACTUAL stored content (empty
        // bindings + snapshot) so the record verifies on write and read.
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();

        let err = plan_assignments(
            &SlotSelection::normalize(&config, "t1", None).unwrap(),
            &PushRef::Release {
                release: release.clone(),
            },
            &crate::identity::test_release_id("unused"),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect_err("a release without the resolved variant's tree must refuse");
        assert!(
            err.to_string().contains("lacks variant 'standard'"),
            "error must name the missing variant tree, got: {err}"
        );
    }

    /// The stored slot snapshot is authoritative for NON-legacy records even
    /// when it contradicts the current config: the slot's variant binding
    /// resolves from the snapshot, never `config.slot_variant`. (Contrast
    /// with `legacy_empty_slots_snapshot_falls_back_to_current_config_variant`.)
    #[test]
    fn release_snapshot_binding_wins_over_current_config() {
        let (_dir, config) = project_with_config();
        let store = LocalStore::with_base(_dir.path().join("store")).unwrap();
        // Current config declares p1 under `standard`; the stored snapshot
        // instead records p1 under `other` (as if the slot later moved).
        let mut rec = legacy_record("unused", "tree-x");
        rec.slots = BTreeMap::from([(
            "other".to_string(),
            CanonicalSlots {
                slots: vec![CanonicalSlot {
                    id: "p1".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: "/srv/plan".to_string(),
                    target: "t1".to_string(),
                    groups: Vec::new(),
                }],
            },
        )]);
        rec.variants = BTreeMap::from([
            (
                "standard".to_string(),
                test_tree_digest("tree-standard").as_str().to_string(),
            ),
            (
                "other".to_string(),
                test_tree_digest("tree-other").as_str().to_string(),
            ),
        ]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();

        let (assignments, _, origin) = plan_assignments(
            &SlotSelection::normalize(&config, "t1", None).unwrap(),
            &PushRef::Release {
                release: release.clone(),
            },
            &crate::identity::test_release_id("unused"),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .map(|planned| (planned.assignments, planned.releases, planned.origin))
        .expect("snapshot-declared release resolves");
        release_origin(&origin, &release);
        assert_eq!(
            assignments[0].artifact.variant.as_str(),
            "other",
            "the stored slot snapshot must win over the current config's declaring file"
        );
        assert_eq!(
            assignments[0].artifact.tree.as_str(),
            test_tree_digest("tree-other").as_str(),
            "the tree must pair with the snapshot-resolved variant"
        );
    }

    /// EXACT SNAPSHOT ROLLBACK ALWAYS RESTORES THE SNAPSHOT'S OWN HISTORICAL
    /// VARIANT — never the caller's current config. Variant-renamed scenario:
    /// the snapshot's release ships BOTH the historical variant `old` (which
    /// declares p1 at snapshot time) and the current `new` variant, and the
    /// CURRENT config declares p1 inside `new.toml`. A `PushRef::Deployment`
    /// ref must still plan `old` + its tree, not the current declaring file.
    #[test]
    fn snapshot_ref_restores_historical_variant_after_rename() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        // The CURRENT config declares p1 inside the `new` variant file.
        std::fs::write(release_dir.join("new.toml"), VARIANT_TOML).unwrap();
        let cfg_path = project.join("deploy.toml");
        std::fs::write(&cfg_path, DEPLOY_TOML).unwrap();
        let config = ProjectConfig::load(&cfg_path).unwrap();
        assert_eq!(config.slot_variant("p1").unwrap(), "new");
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // The snapshot's release ships BOTH the historical variant `old` and
        // the current variant `new`; its slot snapshot records p1 under `old`.
        let mut rec = legacy_record("unused", "tree-x");
        rec.variants = BTreeMap::from([
            ("old".to_string(), "tree-old".to_string()),
            ("new".to_string(), "tree-new".to_string()),
        ]);
        rec.slots = BTreeMap::from([(
            "old".to_string(),
            CanonicalSlots {
                slots: vec![CanonicalSlot {
                    id: "p1".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: "/srv/plan".to_string(),
                    target: "t1".to_string(),
                    groups: Vec::new(),
                }],
            },
        )]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();
        append_successful_snapshot(
            &store,
            "deploy-snapshot-histvar",
            "sha256-aa",
            BTreeMap::from([(
                SlotId::new("p1".to_string()),
                GenerationRef {
                    generation: test_generation_id("gen-old"),
                    assignment: PlacementSlotAssignment {
                        placement_slot: SlotId::new("p1".to_string()),
                        artifact: ArtifactRef {
                            release: release.clone(),
                            variant: VariantName::new("old".to_string()),
                            tree: test_tree_digest("tree-old"),
                        },
                    },
                },
            )]),
            BTreeMap::from([(
                SlotId::new("p1".to_string()),
                PhysicalBinding {
                    server: ServerId::new("s1".to_string()),
                    deploy_dir: "/srv/plan".to_string(),
                },
            )]),
        );

        // Exact rollback restores the historical artifact (variant `old` +
        // tree-old together) even though the current config declares p1 in
        // `new` and the release also ships it.
        let (assignments, desired, origin) = plan_assignments(
            &SlotSelection::normalize(&config, "t1", None).unwrap(),
            &PushRef::Deployment {
                target: TargetName::new("t1".to_string()),
                deployment_id: test_deployment_id("deploy-snapshot-histvar"),
            },
            &crate::identity::test_release_id("unused"),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .map(|planned| (planned.assignments, planned.releases, planned.origin))
        .expect("deployment ref resolves");
        assert_eq!(assignments[0].artifact.variant.as_str(), "old");
        assert_eq!(assignments[0].artifact.tree, test_tree_digest("tree-old"));
        assert_eq!(assignments[0].artifact.release, release);
        assert_eq!(desired, BTreeSet::from([release.clone()]));
        assert_eq!(
            origin,
            PlanOrigin::Deployment(test_deployment_id("deploy-snapshot-histvar"))
        );
    }

    /// A LEGACY snapshot (no `bindings` map — the pre-feature shape)
    /// makes exact rollback unverifiable: `plan_assignments` must REFUSE the
    /// deployment ref with a rollback error naming the slot, rather than guessing
    /// the host/location. The integration tests cover binding MISMATCH
    /// (`rollback_refuses_rebound_slot` / `rollback_refuses_moved_deploy_dir`);
    /// this pins the MISSING-binding refusal (the `#[serde(default)]` empty
    /// map path).
    #[test]
    fn snapshot_ref_without_recorded_bindings_refuses_rollback() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), VARIANT_TOML).unwrap();
        let cfg_path = project.join("deploy.toml");
        std::fs::write(&cfg_path, DEPLOY_TOML).unwrap();
        let config = ProjectConfig::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // A snapshot whose `slots` record the generation but whose `bindings`
        // map is EMPTY (legacy pre-feature line). The exact-binding-keys
        // invariant now refuses such a payload at the STORE READ (the wire →
        // domain conversion): the missing binding is caught at conversion
        // time, BEFORE `plan_assignments` can resolve the rollback, and the
        // refusal propagates out of the plan as an integrity error naming
        // the missing binding.
        append_successful_snapshot(
            &store,
            "deploy-legacy-snapshot",
            "sha256-aa",
            BTreeMap::from([(
                SlotId::new("p1".to_string()),
                GenerationRef {
                    generation: test_generation_id("gen-legacy"),
                    assignment: PlacementSlotAssignment {
                        placement_slot: SlotId::new("p1".to_string()),
                        artifact: ArtifactRef {
                            release: crate::identity::test_release_id("rel-sha256-legacy"),
                            variant: VariantName::new("standard".to_string()),
                            tree: test_tree_digest("tree-legacy"),
                        },
                    },
                },
            )]),
            BTreeMap::new(),
        );

        let err = plan_assignments(
            &SlotSelection::normalize(&config, "t1", None).unwrap(),
            &PushRef::Deployment {
                target: TargetName::new("t1".to_string()),
                deployment_id: test_deployment_id("deploy-legacy-snapshot"),
            },
            &crate::identity::test_release_id("unused"),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect_err("a deployment ref whose snapshot recorded no physical binding must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("missing bindings") && msg.contains("p1"),
            "error must name the unverifiable slot and the missing binding, got: {msg}"
        );
        assert!(
            msg.contains("EXACTLY the slotted generations"),
            "error must explain the exact-binding-keys verification failure, got: {msg}"
        );
    }

    // ---------------------------------------------------------------------
    // DIRECT-RELEASE PROPERTY: `release:<id>` plans where a snapshot ref
    // cannot — changed physical bindings, or a destination with no snapshot
    // history — while snapshot refs RETAIN their exact-binding checks.
    // ---------------------------------------------------------------------

    /// A generated change to a slot's physical binding between the source
    /// deployment and now: either the slot was REBOUND to a different server
    /// (same deploy_dir), or MOVED to a different deploy_dir on the SAME
    /// server. Returns the binding the source deployment's snapshot recorded
    /// (the OLD one); the current config binds the slot to `s1` at
    /// `/srv/plan`, so the two always differ in at least one dimension.
    fn old_binding_strategy() -> impl Strategy<Value = (String, String)> {
        prop_oneof![
            // Rebound: recorded on a different server, same deploy_dir.
            (
                "[a-z0-9]{6,16}".prop_map(|s: String| format!("srv-{s}")),
                Just("/srv/plan".to_string()),
            ),
            // Moved: same server, a different deploy_dir.
            (
                Just("s1".to_string()),
                "[a-z0-9]{2,10}".prop_map(|s: String| format!("/srv/{s}/old")),
            ),
        ]
    }

    /// Build the direct-release property fixture: a project with source
    /// target `t1` and destination target `t2` (no history), a release
    /// record whose OWN stored slot snapshot declares `p1` -> `standard`
    /// (tree `tree-direct`), and a snapshot on `t1` that records `old` as
    /// p1's physical binding at deployment time — the binding the CURRENT
    /// config no longer has.
    ///
    /// The record's canonical slot carries the SAME `targets` list as the
    /// current config's `p1` (`["t1", "t2"]`), so the release-versioned
    /// membership and the CURRENT membership both reduce to the set `{p1}`
    /// on every target — the planning-succeeds side of the direct-release
    /// membership rule (only the PHYSICAL binding differs, which is
    /// intentionally allowed).
    fn direct_release_fixture(
        old_binding: &(String, String),
    ) -> (tempfile::TempDir, ProjectConfig, LocalStore, ReleaseId) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), VARIANT_TOML_TWO).unwrap();
        let cfg_path = project.join("deploy.toml");
        std::fs::write(&cfg_path, DEPLOY_TOML_TWO).unwrap();
        let config = ProjectConfig::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // The release's OWN stored slot-variant snapshot: p1 -> `standard`
        // (t1's slot) and p2 -> `standard` (t2's slot). A slot has exactly
        // one owning target, so the snapshot declares each target's own slot.
        let mut rec = legacy_record("unused", "tree-direct");
        rec.slots = BTreeMap::from([(
            "standard".to_string(),
            CanonicalSlots {
                slots: vec![
                    CanonicalSlot {
                        id: "p1".to_string(),
                        server: "s1".to_string(),
                        deploy_dir: "/srv/plan".to_string(),
                        target: "t1".to_string(),
                        groups: Vec::new(),
                    },
                    CanonicalSlot {
                        id: "p2".to_string(),
                        server: "s2".to_string(),
                        deploy_dir: "/srv/plan-2".to_string(),
                        target: "t2".to_string(),
                        groups: Vec::new(),
                    },
                ],
            },
        )]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();

        // The SOURCE deployment's snapshot records the OLD binding.
        append_successful_snapshot(
            &store,
            "deploy-source",
            "sha256-aa",
            BTreeMap::from([(
                SlotId::new("p1".to_string()),
                GenerationRef {
                    generation: test_generation_id("gen-old"),
                    assignment: PlacementSlotAssignment {
                        placement_slot: SlotId::new("p1".to_string()),
                        artifact: ArtifactRef {
                            release: release.clone(),
                            variant: VariantName::new("standard".to_string()),
                            tree: test_tree_digest("tree-direct"),
                        },
                    },
                },
            )]),
            BTreeMap::from([(
                SlotId::new("p1".to_string()),
                PhysicalBinding {
                    server: ServerId::new(old_binding.0.clone()),
                    deploy_dir: old_binding.1.clone(),
                },
            )]),
        );

        (dir, config, store, release)
    }

    // The required direct-release property: for a generated changed
    // physical binding (a slot REBOUND to a different server, or MOVED to a
    // different deploy_dir) — and for a source/destination pair whose
    // destination `t2` has NO snapshot history — `release:<id>` (resolved
    // to [`PushRef::Release`]) plans successfully against the CURRENT
    // target's slots from the release's OWN stored slot snapshot, while the
    // equivalent SNAPSHOT ref retains its exact physical-binding refusal
    // (a snapshot that recorded the old binding fails closed; on the
    // no-history destination the snapshot-family refs cannot even resolve).
    // The membership rule is satisfied on both targets: the record's
    // snapshot and the current config bind the same slot set `{p1}`, so the
    // direct form passes its logical-membership check; only the physical
    // binding differs, which the direct form intentionally allows.
    proptest! {
        #![proptest_config(ProptestConfig {
            // Bounded + fixed seed: deterministic floor, fast.
            cases: crate::testutil::proptest_cases(4),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn direct_release_plans_where_snapshot_ref_refuses(
            old_binding in old_binding_strategy(),
            cross_target in prop::bool::ANY,
        ) {
            let (_dir, config, store, release) = direct_release_fixture(&old_binding);
            let release_ref = PushRef::Release {
                release: release.clone(),
            };

            // DIRECT: plans successfully on the CURRENT target's slots (the
            // source `t1` AND the no-history destination `t2` alike), the
            // variant per slot from the release's OWN stored snapshot and the
            // tree from its own bindings — never the caller's config, never
            // any snapshot chain, regardless of the changed binding. Each
            // target owns its own slot (t1 -> p1, t2 -> p2).
            for dest in ["t1", "t2"] {
                let (assignments, desired, origin) = plan_assignments(
                    &SlotSelection::normalize(&config, dest, None).unwrap(),
                    &release_ref,
                    &crate::identity::test_release_id("unused-local"),
                    &BTreeMap::new(),
                    &store,
                    &config,
                )
                    .map(|planned| (planned.assignments, planned.releases, planned.origin))
                .unwrap_or_else(|e| panic!("release:<id> must plan on target {dest}: {e}"));
                assert_eq!(assignments.len(), 1, "one slot per target");
                let a = &assignments[0];
                let want_slot = if dest == "t1" { "p1" } else { "p2" };
                assert_eq!(a.placement_slot, SlotId::new(want_slot));
                assert_eq!(
                    a.artifact.variant.as_str(),
                    "standard",
                    "the variant must come from the release's OWN stored snapshot"
                );
                assert_eq!(
                    a.artifact.tree.as_str(),
                    test_tree_digest("tree-direct").as_str(),
                    "the tree must come from the release's own variant bindings"
                );
                assert_eq!(a.artifact.release, release);
                assert_eq!(desired, BTreeSet::from([release.clone()]));
                release_origin(&origin, &release);
            }

            // The SNAPSHOT ref RETAINS the exact physical-binding checks: on
            // the source `t1`, the snapshot recorded the generated OLD
            // binding (rebound or moved), which no longer matches the current
            // config, so rollback refuses with the exact-rollback error — the
            // same refusal as before this feature.
            let err = plan_assignments(
                &SlotSelection::normalize(&config, "t1", None).unwrap(),
                &PushRef::Deployment {
                    target: TargetName::new("t1".to_string()),
                    deployment_id: test_deployment_id("deploy-source"),
                },
                &crate::identity::test_release_id("unused"),
                &BTreeMap::new(),
                &store,
                &config,
            )
            .expect_err("a snapshot ref whose recorded binding changed must refuse");
            let msg = err.to_string();
            assert!(
                msg.contains("exact rollback would deploy to the wrong host") && msg.contains("p1"),
                "snapshot ref must keep the exact-binding refusal naming the slot, got: {msg}"
            );

            // Cross-target branch: the destination `t2` has ZERO snapshot
            // history — the release was built/pushed elsewhere. The
            // deployment-history refs cannot even RESOLVE there (no chain to
            // step — the source deployment id is not a t2 deployment), while
            // the direct form works.
            if cross_target {
                for token in ["@-", "parent(@, 1)"] {
                    crate::ledger::resolve_ref_expr(
                        &crate::ledger::parse_ref_expr(token).expect("family tokens must parse"),
                        "t2",
                        &store,
                    )
                    .expect_err(&format!("{token} on the no-history destination must fail"));
                }
                crate::ledger::resolve_ref_expr(
                    &crate::ledger::parse_ref_expr(test_deployment_id("deploy-source").as_str())
                        .expect("deployment id must parse"),
                    "t2",
                    &store,
                )
                .expect_err("no snapshot for the deployment on t2; the deployment id must fail");
                // The removed release-refid / sN forms are rejected at parse.
                for token in ["s0", &format!("parent({release}, 0)")] {
                    crate::ledger::parse_ref_expr(token)
                        .expect_err(&format!("legacy form '{token}' must be rejected"));
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    // DEPLOYMENT-KEYED ROLLBACK PROPERTY: `deploy push <target> <id>` plans
    // EXACTLY the snapshot recorded for that deployment (the user's
    // requirement — the plan's slots/behavior/release equal the stored
    // payload, keyed by deployment id).
    // ---------------------------------------------------------------------

    // THE DEPLOYMENT-KEYED ROLLBACK PROPERTY: for generated deployment
    // histories, `PushRef::Deployment { deployment_id }` (the resolution of
    // `deploy push <target> <deployment-id>`) plans EXACTLY the snapshot
    // recorded for that deployment — each slot's artifact (release, variant,
    // tree) equals the snapshot's stored generation ref, the plan's release
    // is the snapshot's release, and the source is `DeploymentRef(id)`.
    // The plan runs the exact-binding checks (membership + physical
    // bindings) against the CURRENT config, so the generated snapshot is
    // bound to the config's own member slot (`p1` on server `s1` at
    // `/srv/plan`); a deployment id with NO snapshot never plans.
    proptest! {
        #![proptest_config(ProptestConfig {
            // Bounded + fixed seed: deterministic floor, fast.
            cases: crate::testutil::proptest_cases(4),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn deployment_ref_plans_exactly_the_recorded_snapshot(
            tree in "[a-f0-9]{64}",
            generation in "[a-z0-9]{4,10}",
            behavior in "[a-f0-9]{4,16}",
        ) {
            let (_dir, config) = project_with_config();
            let store = LocalStore::with_base(_dir.path().join("store")).unwrap();
            let deployment_id = test_deployment_id("deploy-prop-plan");
            let snapshot_release = crate::identity::test_release_id(&tree);
            let slots = BTreeMap::from([(
                SlotId::new("p1".to_string()),
                GenerationRef {
                    generation: test_generation_id(&format!("gen-{generation}")),
                    assignment: PlacementSlotAssignment {
                        placement_slot: SlotId::new("p1".to_string()),
                        artifact: ArtifactRef {
                            release: snapshot_release.clone(),
                            variant: VariantName::new("standard".to_string()),
                            tree: TreeDigest::new(tree.clone()),
                        },
                    },
                },
            )]);
            append_successful_snapshot(
                &store,
                "deploy-prop-plan",
                &format!("sha256-{behavior}"),
                slots.clone(),
                BTreeMap::from([(
                    SlotId::new("p1".to_string()),
                    PhysicalBinding {
                        server: ServerId::new("s1".to_string()),
                        deploy_dir: "/srv/plan".to_string(),
                    },
                )]),
            );

            let (assignments, desired, origin) = plan_assignments(
                &SlotSelection::normalize(&config, "t1", None).unwrap(),
                &PushRef::Deployment {
                    target: TargetName::new("t1".to_string()),
                    deployment_id: deployment_id.clone(),
                },
                &crate::identity::test_release_id("unused-local"),
                &BTreeMap::new(),
                &store,
                &config,
            )
                .map(|planned| (planned.assignments, planned.releases, planned.origin))
            .unwrap_or_else(|e| panic!("the deployment id must plan its stored state: {e}"));

            // EXACTLY the stored state: one slot, its artifact (variant +
            // tree + release) byte-identical to the snapshot's recorded
            // GenerationRef.
            assert_eq!(assignments.len(), 1, "one member slot");
            let a = &assignments[0];
            let stored = &slots[&SlotId::new("p1")];
            assert_eq!(a.placement_slot, SlotId::new("p1"));
            assert_eq!(a.artifact, stored.assignment.artifact, "the planned artifact must equal the snapshot's stored artifact");
            assert_eq!(
                desired,
                BTreeSet::from([snapshot_release.clone()]),
                "the rollout releases are exactly the snapshot's referenced releases"
            );
            assert_eq!(
                origin,
                PlanOrigin::Deployment(deployment_id.clone()),
                "the plan origin records the deployment key"
            );

            // A deployment id with NO snapshot never plans (failed / unknown
            // ids fail closed at the plan boundary too).
            let missing = test_deployment_id("deploy-prop-missing");
            let err = plan_assignments(
                &SlotSelection::normalize(&config, "t1", None).unwrap(),
                &PushRef::Deployment {
                    target: TargetName::new("t1".to_string()),
                    deployment_id: missing.clone(),
                },
                &crate::identity::test_release_id("unused"),
                &BTreeMap::new(),
                &store,
                &config,
            )
            .expect_err("an unknown deployment id must refuse to plan");
            assert!(
                err.to_string().contains(missing.as_str())
                    || err.to_string().contains("deployment"),
                "the refusal must name the missing deployment, got: {err}"
            );
        }
    }

    // ---------------------------------------------------------------------
    // MULTI-RELEASE PARTIAL-SNAPSHOT ROLLBACK PROPERTY: a partial snapshot
    // can carry slots from DIFFERENT releases (group pushes over time), and
    // rollback must resolve EACH SLOT's behavior from ITS OWN (release,
    // variant) binding — never a snapshot-wide single release/behavior.
    // ---------------------------------------------------------------------

    /// The two-group fixture variant: `p1` in `group-a` (server `s1`), `p2`
    /// in `group-b` (server `s2`). The alternating partial pushes build their
    /// multi-release snapshot on exactly this membership/bindings, so both
    /// FULL and GROUP rollback selections plan against a stable placement
    /// set.
    const TWO_GROUP_VARIANT: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
groups = ["group-a"]
deploy_dir = "/srv/plan-a"

[[slots]]
id = "p2"
server = "s2"
target = "t1"
groups = ["group-b"]
deploy_dir = "/srv/plan-b"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

    /// The two-server config backing [`TWO_GROUP_VARIANT`] (one server per
    /// group slot, so each slot's remote is its own host).
    const TWO_GROUP_TOML: &str = r#"
schema_version = 2
application = "plan"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s2"
address = "b"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;

    fn two_group_project() -> (tempfile::TempDir, ProjectConfig) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), TWO_GROUP_VARIANT).unwrap();
        let p = project.join("deploy.toml");
        std::fs::write(&p, TWO_GROUP_TOML).unwrap();
        let config = ProjectConfig::load(&p).unwrap();
        (dir, config)
    }

    /// Write a release record whose `standard` variant carries a DISTINCT
    /// behavior contract (verification argv seeded by `seed`, so no two
    /// releases share a contract digest) plus its identity-verified
    /// `behavior.json` aux snapshot. The record's own canonical slot snapshot
    /// records the current two-group membership/bindings (the rollback
    /// property plans against that same config), and its identity is
    /// recomputed from its own content ([`consistent`]) so the store's
    /// recompute-and-verify reads succeed. Returns the release id.
    fn seed_distinct_release(store: &LocalStore, seed: usize) -> ReleaseId {
        let contract = BehaviorContract {
            activation: crate::config::ActivationConfig::default(),
            verification: crate::config::VerificationConfig {
                adapter: "command".to_string(),
                argv: vec![format!("verify-{seed}")],
                timeout_seconds: 5,
                ..Default::default()
            },
        };
        let behaviors = BTreeMap::from([("standard".to_string(), contract)]);
        let behavior_sha = crate::verify::release::variant_behaviors_digest(&behaviors);
        let mut rec = ReleaseRecord {
            release_schema_version: RELEASE_RECORD_SCHEMA_VERSION,
            release_id: String::new(),
            release_sha256: String::new(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            provenance: Provenance {
                mapping_sha256: format!("m-{seed}"),
                behavior_sha256: behavior_sha,
            },
            variants: BTreeMap::from([("standard".to_string(), format!("tree-{seed}"))]),
            slots: BTreeMap::from([(
                "standard".to_string(),
                CanonicalSlots {
                    slots: vec![
                        CanonicalSlot {
                            id: "p1".to_string(),
                            server: "s1".to_string(),
                            deploy_dir: "/srv/plan-a".to_string(),
                            target: "t1".to_string(),
                            groups: vec!["group-a".to_string()],
                        },
                        CanonicalSlot {
                            id: "p2".to_string(),
                            server: "s2".to_string(),
                            deploy_dir: "/srv/plan-b".to_string(),
                            target: "t1".to_string(),
                            groups: vec!["group-b".to_string()],
                        },
                    ],
                },
            )]),
        };
        let rid = consistent(&mut rec);
        store.write_release(&rec).unwrap();
        store
            .write_release_aux(
                &rid,
                &format!("mapping-{seed}"),
                &serde_json::to_value(&behaviors).unwrap(),
            )
            .unwrap();
        rid
    }

    /// ONE multi-release rollback case (the user's property): ALTERNATE
    /// PARTIAL PUSHES ACROSS GROUPS — each push deploys a release with a
    /// DISTINGUISHABLE behavior contract (so the per-slot behavior digest is
    /// a per-release fact) — then roll back an ARBITRARY FULL/GROUP snapshot
    /// and assert EVERY SELECTED SLOT receives EXACTLY its stored (release,
    /// tree, variant, behavior digest): the planned artifact equals the
    /// snapshot's stored generation ref, and the per-slot behavior contract
    /// (what the slot's publication/verification would run) resolves from the
    /// slot's OWN (release, variant) — never another release's contract.
    fn multi_release_rollback_case(
        partial_groups: Vec<bool>,
        rollback_pos: usize,
        rollback_full: bool,
    ) {
        let (_dir, config) = two_group_project();
        let store = LocalStore::with_base(_dir.path().join("store")).unwrap();

        let slot_a = SlotId::new("p1".to_string());
        let slot_b = SlotId::new("p2".to_string());
        let bindings: BTreeMap<SlotId, PhysicalBinding> = BTreeMap::from([
            (
                slot_a.clone(),
                PhysicalBinding {
                    server: ServerId::new("s1".to_string()),
                    deploy_dir: "/srv/plan-a".to_string(),
                },
            ),
            (
                slot_b.clone(),
                PhysicalBinding {
                    server: ServerId::new("s2".to_string()),
                    deploy_dir: "/srv/plan-b".to_string(),
                },
            ),
        ]);

        // Push 0 is the FULL first deployment (a partial group push needs a
        // base snapshot carrying every unselected slot); every later push is
        // a PARTIAL push of one group (its slots receive a fresh release with
        // its own distinct contract). The per-slot state overlay mirrors
        // `build_rollback`: selected slots are replaced, unselected slots are
        // carried forward.
        let mut expected_digests: BTreeMap<ReleaseId, String> = BTreeMap::new();
        let mut state: BTreeMap<SlotId, ArtifactRef> = BTreeMap::new();
        let mut chain: Vec<(DeploymentId, BTreeMap<SlotId, GenerationRef>)> = Vec::new();

        let push_count = partial_groups.len() + 1;
        for i in 0..push_count {
            let rid = seed_distinct_release(&store, i);
            let behaviors = store.read_release_behaviors(&rid).unwrap();
            let digest = crate::verify::release::behavior_contract_digest(&behaviors["standard"]);
            expected_digests.insert(rid.clone(), digest);
            let artifact = ArtifactRef {
                release: rid.clone(),
                variant: VariantName::new("standard".to_string()),
                tree: test_tree_digest(&format!("tree-{i}")),
            };
            if i == 0 {
                state.insert(slot_a.clone(), artifact.clone());
                state.insert(slot_b.clone(), artifact);
            } else if partial_groups[i - 1] {
                // group-a: p1 only.
                state.insert(slot_a.clone(), artifact);
            } else {
                // group-b: p2 only.
                state.insert(slot_b.clone(), artifact);
            }
            let slots: BTreeMap<SlotId, GenerationRef> = state
                .iter()
                .map(|(slot, art)| {
                    (
                        slot.clone(),
                        GenerationRef {
                            generation: test_generation_id(&format!("gen-{i}")),
                            assignment: PlacementSlotAssignment {
                                placement_slot: slot.clone(),
                                artifact: art.clone(),
                            },
                        },
                    )
                })
                .collect();
            let id = test_deployment_id(&format!("deploy-mr-{i}"));
            append_successful_snapshot(
                &store,
                &format!("deploy-mr-{i}"),
                &format!("sha256-{i}"),
                slots.clone(),
                bindings.clone(),
            );
            chain.push((id, slots));
        }

        // The seeded contracts are pairwise DISTINGUISHABLE (the property's
        // premise: per-slot digests are per-release facts).
        let distinct: BTreeSet<&String> = expected_digests.values().collect();
        assert_eq!(
            distinct.len(),
            expected_digests.len(),
            "every seeded release must carry a DISTINGUISHABLE behavior digest"
        );

        // Roll back an ARBITRARY snapshot of the chain, FULL or GROUP.
        let (rollback_id, snapshot_slots) = &chain[rollback_pos % chain.len()];
        let selection = if rollback_full {
            SlotSelection::normalize(&config, "t1", None).unwrap()
        } else {
            SlotSelection::normalize(&config, "t1", Some("group-a")).unwrap()
        };
        let (assignments, referenced, origin) = plan_assignments(
            &selection,
            &PushRef::Deployment {
                target: TargetName::new("t1".to_string()),
                deployment_id: rollback_id.clone(),
            },
            &crate::identity::test_release_id("unused"),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .map(|planned| (planned.assignments, planned.releases, planned.origin))
        .expect("the deployment id must plan its stored state");

        // The plan's referenced-releases set is EXACTLY the releases of the
        // SELECTED slots' stored bindings (derived from the slot bindings,
        // never a snapshot-wide single release): a full rollback references
        // every slot's release, a group rollback only its selected slots'.
        let selected_slots: BTreeSet<SlotId> = assignments
            .iter()
            .map(|a| a.placement_slot.clone())
            .collect();
        let stored_releases: BTreeSet<ReleaseId> = snapshot_slots
            .iter()
            .filter(|(s, _)| selected_slots.contains(*s))
            .map(|(_, g)| g.assignment.artifact.release.clone())
            .collect();
        assert_eq!(referenced, stored_releases);
        assert_eq!(
            origin,
            PlanOrigin::Deployment(rollback_id.clone()),
            "the plan origin records the deployment key"
        );

        // EVERY SELECTED SLOT: exactly its stored (release, tree, variant) and
        // exactly its OWN (release, variant) behavior digest — the per-slot
        // publication/verification matches the slot's artifact binding, never
        // a snapshot-wide single release's contract.
        let index = release_behavior_index(&store, &referenced).unwrap();
        for a in &assignments {
            let stored = &snapshot_slots[&a.placement_slot];
            assert_eq!(
                a.artifact, stored.assignment.artifact,
                "slot {} must receive exactly its stored artifact",
                a.placement_slot
            );
            let digest = crate::verify::release::behavior_contract_digest(
                &index[&a.artifact.release][a.artifact.variant.as_str()],
            );
            assert_eq!(
                digest, expected_digests[&a.artifact.release],
                "slot {} behavior must resolve from ITS OWN release's contract",
                a.placement_slot
            );
            // A different release's contract must NEVER leak into this slot
            // (the bug: a snapshot-wide single release applied to every
            // slot).
            for other in index.keys() {
                if other != &a.artifact.release {
                    let other_contract = &index[other][a.artifact.variant.as_str()];
                    assert_ne!(
                        crate::verify::release::behavior_contract_digest(other_contract),
                        digest,
                        "slot {} must not receive release {other}'s contract",
                        a.placement_slot
                    );
                }
            }
        }
        // A GROUP rollback plans ONLY the selected slots (unselected slots
        // stay at the latest current state); a FULL rollback plans every
        // slot.
        if rollback_full {
            assert_eq!(assignments.len(), 2, "a full rollback plans both slots");
        } else {
            assert_eq!(
                assignments.len(),
                1,
                "a group rollback plans only the selected slots"
            );
            assert_eq!(assignments[0].placement_slot, slot_a);
        }
    }

    proptest! {
        // THE USER'S MULTI-RELEASE PROPERTY: alternating partial pushes
        // across groups with distinguishable behavior contracts, then an
        // arbitrary FULL/GROUP rollback of an arbitrary snapshot. Bounded
        // `proptest_cases(4)` (full 4 with `DEPLOY_FULL_TESTS=1`, fast
        // default) + the pinned 0x5EED_5EED seed (house style) keep the
        // deterministic floor fast; each case is store-only (no remote).
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(4),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn multi_release_rollback_per_slot_behavior(
            partial_groups in prop::collection::vec(any::<bool>(), 1..=3),
            rollback_pos in any::<usize>(),
            rollback_full in any::<bool>(),
        ) {
            multi_release_rollback_case(partial_groups, rollback_pos, rollback_full);
        }
    }

    // ---------------------------------------------------------------------
    // THE USER'S TEMPORAL-SOURCES PROPERTY: for generated DIFFERING CURRENT,
    // RELEASE, and DEPLOYMENT topologies, each reference kind consults ONLY
    // its declared temporal source (HEAD → current variant slot declarations;
    // `release:<id>` → the release's frozen topology + the LOGICAL membership
    // check, producing the EXPLICIT RebindingPlan; a deployment rollback →
    // the deployment's exact per-slot artifact + physical binding) and FAILS
    // when the required identities cannot be reconciled (a recorded binding
    // ≠ current physical binding → refuse; a release's logical membership ≠
    // current → refuse; a broken current declaration → refuse). The four
    // generated booleans span exactly 16 cases; the fixed seed makes the
    // floor deterministic.
    // ---------------------------------------------------------------------

    /// The temporal-sources property fixture. The CURRENT variant file
    /// declares `p1` (server `s1`) and `p2` (server `s2`) for target `t1`;
    /// the WRITABLE release record's OWN frozen snapshot varies
    /// (`release_variant` renames its declaring variant, `release_drift`
    /// drops `p2` from its frozen membership — a LOGICAL drift); and one
    /// successful DEPLOYMENT snapshot records per-slot artifacts (release
    /// `rel-deploy`, variant `standard`, tree `tree-deploy`) with physical
    /// bindings that either match the current config or drift `p1`'s
    /// deploy_dir (`binding_drift` — the exact-binding check must refuse).
    /// `head_broken` is applied by the TEST (not the fixture): it leaves the
    /// current variant's tree out of `variant_trees` so the HEAD branch's own
    /// declaration source cannot materialize.
    fn temporal_sources_fixture(
        release_variant: bool,
        release_drift: bool,
        binding_drift: bool,
    ) -> (tempfile::TempDir, ProjectConfig, LocalStore, ReleaseId) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(
            release_dir.join("standard.toml"),
            r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/p1"

[[slots]]
id = "p2"
server = "s2"
target = "t1"
deploy_dir = "/srv/p2"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[retention.deployment]
protect_deployments = 1

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#,
        )
        .unwrap();
        let p = project.join("deploy.toml");
        std::fs::write(
            &p,
            r#"
schema_version = 2
application = "plan"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s2"
address = "b"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#,
        )
        .unwrap();
        let config = ProjectConfig::load(&p).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // The release's OWN frozen snapshot under the variant name
        // `frozen_variant` (the current variant file is `standard`; renaming
        // the declaring variant proves the release consults ITS OWN frozen
        // topology, never the current decls). `release_drift` drops `p2` —
        // the LOGICAL membership then differs from the current {p1, p2}.
        let frozen_variant = if release_variant {
            "special"
        } else {
            "standard"
        };
        let mut rec = legacy_record("unused", "tree-rel");
        let mut frozen_slots: Vec<CanonicalSlot> = vec![CanonicalSlot {
            id: "p1".to_string(),
            server: "s1".to_string(),
            deploy_dir: "/srv/p1".to_string(),
            target: "t1".to_string(),
            groups: Vec::new(),
        }];
        if !release_drift {
            frozen_slots.push(CanonicalSlot {
                id: "p2".to_string(),
                server: "s2".to_string(),
                deploy_dir: "/srv/p2".to_string(),
                target: "t1".to_string(),
                groups: Vec::new(),
            });
        }
        rec.variants = BTreeMap::from([(
            frozen_variant.to_string(),
            test_tree_digest("tree-rel").as_str().to_string(),
        )]);
        rec.slots = BTreeMap::from([(
            frozen_variant.to_string(),
            CanonicalSlots {
                slots: frozen_slots,
            },
        )]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();

        // The DEPLOYMENT's exact per-slot snapshot: its own artifact
        // (release `rel-deploy`, variant `standard`, tree `tree-deploy`) and
        // physical bindings that either match the current config (`/srv/p1`)
        // or drift `p1`'s deploy_dir (`/srv/drifted` on the same server) —
        // the exact-binding check must refuse the drifted case.
        let snapshot_slots: BTreeMap<SlotId, GenerationRef> = BTreeMap::from([
            (
                SlotId::new("p1".to_string()),
                GenerationRef {
                    generation: test_generation_id("gen-p1"),
                    assignment: PlacementSlotAssignment {
                        placement_slot: SlotId::new("p1".to_string()),
                        artifact: ArtifactRef {
                            release: crate::identity::test_release_id("rel-deploy"),
                            variant: VariantName::new("standard".to_string()),
                            tree: test_tree_digest("tree-deploy"),
                        },
                    },
                },
            ),
            (
                SlotId::new("p2".to_string()),
                GenerationRef {
                    generation: test_generation_id("gen-p2"),
                    assignment: PlacementSlotAssignment {
                        placement_slot: SlotId::new("p2".to_string()),
                        artifact: ArtifactRef {
                            release: crate::identity::test_release_id("rel-deploy"),
                            variant: VariantName::new("standard".to_string()),
                            tree: test_tree_digest("tree-deploy"),
                        },
                    },
                },
            ),
        ]);
        append_successful_snapshot(
            &store,
            "deploy-snapshot",
            "sha256-behavior",
            snapshot_slots,
            BTreeMap::from([
                (
                    SlotId::new("p1".to_string()),
                    PhysicalBinding {
                        server: ServerId::new("s1".to_string()),
                        deploy_dir: if binding_drift {
                            "/srv/drifted".to_string()
                        } else {
                            "/srv/p1".to_string()
                        },
                    },
                ),
                (
                    SlotId::new("p2".to_string()),
                    PhysicalBinding {
                        server: ServerId::new("s2".to_string()),
                        deploy_dir: "/srv/p2".to_string(),
                    },
                ),
            ]),
        );

        (dir, config, store, release)
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            // Bounded `proptest_cases(16)`: the exactly-2^4 case space of the
            // four generated topology dimensions. Fixed seed per house style
            // keeps the deterministic floor fast; each case is store-only (no
            // remote).
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn each_reference_kind_consults_only_its_declared_temporal_source(
            release_variant in prop::bool::ANY,
            release_drift in prop::bool::ANY,
            binding_drift in prop::bool::ANY,
            head_broken in prop::bool::ANY,
        ) {
            let (_dir, config, store, release) =
                temporal_sources_fixture(release_variant, release_drift, binding_drift);
            let local_release = crate::identity::test_release_id("unused-local");
            let variant_trees: BTreeMap<String, TreeDigest> = if head_broken {
                BTreeMap::new()
            } else {
                BTreeMap::from([(
                    "standard".to_string(),
                    test_tree_digest("tree-current"),
                )])
            };
            let frozen_variant = if release_variant { "special" } else { "standard" };
            let selection = SlotSelection::normalize(&config, "t1", None).unwrap();

            // HEAD — the CURRENT variant slot declarations are its ONLY
            // temporal source: it plans each slot's variant from the current
            // declaring file and its tree from `variant_trees`, BLIND to the
            // release's frozen variant (`special`) and to the deployment's
            // stored artifact (`tree-deploy`). A BROKEN current declaration
            // (the declared variant's tree missing from `variant_trees`)
            // refuses.
            let head = plan_assignments(
                &selection,
                &PushRef::Head,
                &local_release,
                &variant_trees,
                &store,
                &config,
            );
            if head_broken {
                let msg = head
                    .expect_err("a broken current declaration must refuse HEAD")
                    .to_string();
                assert!(
                    msg.contains("not materialized"),
                    "HEAD's refusal must name the current decl, got: {msg}"
                );
            } else {
                let planned = head.unwrap();
                let (assignments, desired, origin) = (
                    planned.assignments,
                    planned.releases,
                    planned.origin,
                );
                assert_eq!(assignments.len(), 2);
                for a in &assignments {
                    assert_eq!(
                        a.artifact.variant.as_str(),
                        "standard",
                        "HEAD plans the CURRENT declaring variant"
                    );
                    assert_eq!(
                        a.artifact.tree.as_str(),
                        test_tree_digest("tree-current").as_str(),
                        "HEAD plans from the CURRENT tree, never release/deployment"
                    );
                    assert_eq!(a.artifact.release, local_release);
                }
                assert_eq!(desired, BTreeSet::from([local_release.clone()]));
                assert_eq!(origin, PlanOrigin::Head);
                assert!(matches!(origin, PlanOrigin::Head), "HEAD records no rebinding");
            }

            // `release:<id>` — the RELEASE's frozen topology is its ONLY
            // temporal source for slot→variant, bound onto the CURRENT slots
            // under the LOGICAL membership check, and the rebinding is the
            // EXPLICIT RebindingPlan. A drifted logical membership refuses
            // (the existing drift check); the release's own frozen
            // variant/tree win over the current declarations.
            let rel = plan_assignments(
                &selection,
                &PushRef::Release {
                    release: release.clone(),
                },
                &local_release,
                &variant_trees,
                &store,
                &config,
            );
            if release_drift {
                let msg = rel
                    .expect_err("a logical membership drift must refuse release:<id>")
                    .to_string();
                assert!(
                    msg.contains("drift"),
                    "refusal must be the membership-drift error, got: {msg}"
                );
            } else {
                let planned = rel.unwrap();
                let (assignments, desired, origin) = (
                    planned.assignments,
                    planned.releases,
                    planned.origin,
                );
                assert_eq!(assignments.len(), 2);
                for a in &assignments {
                    assert_eq!(
                        a.artifact.variant.as_str(),
                        frozen_variant,
                        "the variant comes from the release's OWN frozen topology"
                    );
                    assert_eq!(
                        a.artifact.tree.as_str(),
                        test_tree_digest("tree-rel").as_str(),
                        "the tree comes from the release's own bindings"
                    );
                    assert_eq!(a.artifact.release, release);
                }
                assert_eq!(desired, BTreeSet::from([release.clone()]));
                release_origin(&origin, &release);
                // THE EXPLICIT REBINDING PLAN: the frozen topology, the
                // logical membership check (frozen == current; physical
                // bindings may differ), and the CURRENT physical slots the
                // topology is bound onto — never the deployment's recorded
                // binding, even when the fixture drifted it.
                let rp = release_origin(&origin, &release);
                assert_eq!(rp.release, release);
                assert_eq!(rp.target, TargetName::parse("t1").expect("safe segment"));
                // The membership proof carries the AGREED set (frozen ==
                // current verified): the target's complete membership.
                assert_eq!(
                    rp.membership
                        .slots()
                        .iter()
                        .map(|s| s.as_str().to_string())
                        .collect::<BTreeSet<_>>(),
                    BTreeSet::from(["p1".to_string(), "p2".to_string()])
                );
                assert_eq!(rp.frozen_topology.len(), 2);
                for (slot, topo) in &rp.frozen_topology {
                    assert_eq!(topo.variant, frozen_variant);
                    assert!(topo.groups.is_empty());
                    assert!(matches!(slot.as_str(), "p1" | "p2"));
                }
                let p1 = &rp.current_physical_slots[&SlotId::new("p1".to_string())];
                assert_eq!(p1.server.as_str(), "s1");
                assert_eq!(p1.deploy_dir, "/srv/p1");
                let p2 = &rp.current_physical_slots[&SlotId::new("p2".to_string())];
                assert_eq!(p2.server.as_str(), "s2");
                assert_eq!(p2.deploy_dir, "/srv/p2");
            }

            // DEPLOYMENT rollback — the DEPLOYMENT's exact per-slot artifact
            // and physical binding is its ONLY temporal source: the planned
            // artifacts byte-match the stored generation refs, and a recorded
            // binding that no longer matches the CURRENT physical binding
            // refuses.
            let dep = plan_assignments(
                &selection,
                &PushRef::Deployment {
                    target: TargetName::new("t1".to_string()),
                    deployment_id: test_deployment_id("deploy-snapshot"),
                },
                &local_release,
                &variant_trees,
                &store,
                &config,
            );
            if binding_drift {
                let msg = dep
                    .expect_err(
                        "a recorded binding that no longer matches the current one must refuse rollback",
                    )
                    .to_string();
                assert!(
                    msg.contains("exact rollback would deploy to the wrong host")
                        && msg.contains("p1"),
                    "refusal must be the exact-binding error naming p1, got: {msg}"
                );
            } else {
                let planned = dep.unwrap();
                let (assignments, desired, origin) = (
                    planned.assignments,
                    planned.releases,
                    planned.origin,
                );
                assert_eq!(assignments.len(), 2);
                for a in &assignments {
                    assert_eq!(
                        a.artifact.release.as_str(),
                        crate::identity::test_release_id("rel-deploy").as_str(),
                        "the artifact comes from the deployment's exact stored state"
                    );
                    assert_eq!(a.artifact.variant.as_str(), "standard");
                    assert_eq!(a.artifact.tree, test_tree_digest("tree-deploy"));
                }
                assert_eq!(
                    desired,
                    BTreeSet::from([crate::identity::test_release_id("rel-deploy")])
                );
                assert_eq!(
                    origin,
                    PlanOrigin::Deployment(test_deployment_id("deploy-snapshot"))

                );
                assert!(
                    matches!(origin, PlanOrigin::Deployment(_)),
                    "a deployment rollback records no rebinding"
                );
            }
        }
    }
}
