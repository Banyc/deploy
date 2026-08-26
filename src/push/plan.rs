//! Deployment planning: resolve the desired per-slot assignment from a push
//! reference.
//!
//! # One rule: each reference kind consults ONLY its declared temporal source
//!
//! The temporal sources are declared explicitly, and every push reference
//! resolves against EXACTLY one:
//!
//! * **HEAD** (``/`HEAD`/`@`/`parent(@, 0)`): the CURRENT variant slot
//!   declarations. Planning reads only the caller's current configuration
//!   (the current variant files and the current physical slots) and is blind
//!   to every historical record.
//! * **`release:<id>`**: that RELEASE's frozen slot→variant and group
//!   topology (the release record's OWN canonical slot snapshot), applied
//!   onto the CURRENT physical slots under the LOGICAL membership check. The
//!   rebinding is now EXPLICIT: the plan carries a
//!   [`crate::records::RebindingPlan`] recording the frozen topology, the
//!   membership check, and the current physical slots it binds onto.
//! * **a deployment rollback** (`deploy push <target> <deployment-id>`, and
//!   the `@`-relative / `parent(...)` walk resolved by
//!   [`crate::history::resolve_ref_expr`] against the target's ledger): that
//!   DEPLOYMENT's exact per-slot artifact AND physical binding (the rollback
//!   payload's generation refs + recorded `bindings`). The caller's current
//!   variant files never re-map them.
//! * **the CURRENT server configuration**: connectivity and live capacity
//!   ONLY. It never contributes topology — no reference resolves slot→variant
//!   or membership from `deploy.toml`'s servers — and capacity headroom is a
//!   per-server policy resolved from the caller's current configuration on
//!   every push (servers have no per-release history).
//!
//! The one historically IMPLICIT exception — a `release:<id>` push applying a
//! historical release's frozen topology onto the CURRENT physical slots — is
//! now an explicit, typed artifact: [`crate::records::RebindingPlan`], built
//! in the `PushRef::Release` branch of [`plan_assignments`] and recorded in
//! [`crate::records::DeploymentPlan::rebinding`].

use crate::config::Config;
use crate::error::{Error, Result};
use crate::history::{PushRef, resolve_deployment};
use crate::model::{
    ArtifactRef, PlacementSlotAssignment, PlacementSlotId, ReleaseId, ReleaseRecord, ServerId,
    TargetName, TreeDigest, VariantName,
};
use crate::records::{
    FrozenSlotTopology, LedgerRollback, MembershipCheck, PhysicalBinding, PlanSource, RebindingPlan,
};
use crate::store::local::LocalStore;
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// The plan for one placement slot: exactly the canonical slot→artifact
/// assignment ([`PlacementSlotAssignment`]), reused rather than re-declared.
pub type PlannedAssignment = PlacementSlotAssignment;

/// The resolution of one push reference into a planned assignment set: the
/// per-slot assignments, the SET of releases they reference (per-slot
/// artifact provenance — a partial snapshot can span several releases, so
/// there is NO single snapshot-wide release), the plan source, and — for a
/// DIRECT release reference — the explicit [`RebindingPlan`] documenting
/// that the historical release's frozen topology is being applied onto the
/// CURRENT physical slots (`None` for HEAD and deployment references).
pub type PlannedResolution = (
    Vec<PlannedAssignment>,
    BTreeSet<ReleaseId>,
    PlanSource,
    Option<RebindingPlan>,
);

/// The NORMALIZED selection of one push/status invocation: the owning target,
/// the optional rollout group, and the EXACT selected slot IDs. Normalized
/// once near command entry (from the caller's current configuration — the
/// selection source, including for historical references); planning,
/// execution, reporting, and persistence consume this instead of
/// independently filtering slots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotSelection {
    pub target: TargetName,
    /// The optional rollout group (`deploy push <target> --group <name>`).
    /// `None` selects every slot owned by the target.
    pub group: Option<String>,
    /// The exact selected slot IDs, in deterministic order (variants in name
    /// order, then each variant's slots in file order).
    pub slot_ids: Vec<PlacementSlotId>,
}

impl SlotSelection {
    /// Normalize a target + optional group into the exact selected slot set
    /// from the caller's current configuration. Omitting the group selects
    /// every slot owned by the target; a group selects exactly the target's
    /// slots whose `groups` list contains it (an unknown group, or a group
    /// selecting zero slots, is a configuration error).
    pub fn normalize(config: &Config, target: &str, group: Option<&str>) -> Result<Self> {
        let members = match group {
            Some(g) => config.target_group_slots(target, g)?,
            None => config.target_slots(target)?,
        };
        let slot_ids = members
            .iter()
            .map(|(s, _)| PlacementSlotId::new(s.id.clone()))
            .collect();
        Ok(SlotSelection {
            target: TargetName::new(target.to_string()),
            group: group.map(str::to_string),
            slot_ids,
        })
    }

    /// The selected (slot, server) pairs from the caller's current
    /// configuration, in the same deterministic order as the selection's
    /// `slot_ids` (derived by filtering the target's members to the
    /// selection).
    pub fn members<'a>(
        &self,
        config: &'a Config,
    ) -> Result<Vec<(&'a crate::config::SlotDef, &'a crate::config::ServerDef)>> {
        let all = config.target_slots(self.target.as_str())?;
        Ok(all
            .into_iter()
            .filter(|(s, _)| self.slot_ids.iter().any(|id| id.as_str() == s.id))
            .collect())
    }

    /// True when the selection covers every slot owned by the target.
    pub fn is_full(&self, config: &Config) -> Result<bool> {
        let all = config.target_slots(self.target.as_str())?;
        Ok(all.len() == self.slot_ids.len())
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
            && t.status == crate::records::DeploymentStatus::Successful
            && let Some(rb) = t.rollback
        {
            return Ok(Some(rb));
        }
    }
    Ok(None)
}

/// PARTIAL-ROLLOUT GUARDS, validated BEFORE any remote mutation: a group push
/// derives its complete snapshot by overlaying the selected slots onto the
/// latest successful target snapshot, so the base must be able to carry every
/// unselected slot forward.
///
/// * On a target's FIRST deployment (no base snapshot), a partial group push
///   is allowed only if the selected group covers every target slot.
/// * After target membership changes, a partial push is allowed only when
///   every current UNSELECTED slot has a prior assignment in the base AND its
///   physical binding still matches (a slot added to the target after the
///   base, or rebound/moved since, would otherwise be silently dropped from
///   the new snapshot).
///
/// A full-target push (no group) is always allowed: it establishes a new
/// complete snapshot from its own actuals.
pub(crate) fn validate_partial_rollout(
    selection: &SlotSelection,
    config: &Config,
    store: &LocalStore,
) -> Result<()> {
    if selection.group.is_none() {
        return Ok(());
    }
    let current = config.target_slots(selection.target.as_str())?;
    let selected: HashSet<&str> = selection.slot_ids.iter().map(|s| s.as_str()).collect();
    let unselected: Vec<(&crate::config::SlotDef, &crate::config::ServerDef)> = current
        .iter()
        .filter(|(s, _)| !selected.contains(s.id.as_str()))
        .copied()
        .collect();
    let base = latest_successful_rollback(store, selection.target.as_str())?;
    match base {
        None => {
            // First deployment: the group must cover every target slot.
            if !unselected.is_empty() {
                return Err(Error::preflight(format!(
                    "partial rollout of target '{}' with group '{}' on its first deployment is refused: \
                     the group must cover every target slot (unselected: {})",
                    selection.target,
                    selection.group.as_deref().unwrap_or(""),
                    unselected
                        .iter()
                        .map(|(s, _)| s.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        }
        Some(base) => {
            // Membership drift: every unselected slot must have a prior
            // assignment in the base and its physical binding must still
            // match.
            for (slot, sdef) in &unselected {
                let slot_id = PlacementSlotId::new(slot.id.clone());
                let current_binding = PhysicalBinding {
                    server: ServerId::new(sdef.id.clone()),
                    deploy_dir: slot.deploy_dir.to_string_lossy().into_owned(),
                };
                if !base.slots.contains_key(&slot_id) {
                    return Err(Error::preflight(format!(
                        "partial rollout of target '{}' with group '{}' is refused: unselected slot \
                         '{}' has no prior assignment in the latest successful snapshot (it was \
                         added to the target after that deployment)",
                        selection.target,
                        selection.group.as_deref().unwrap_or(""),
                        slot_id
                    )));
                }
                let recorded = base.bindings.get(&slot_id).ok_or_else(|| {
                    Error::preflight(format!(
                        "partial rollout of target '{}' with group '{}' is refused: unselected slot \
                         '{}' has no recorded physical binding in the latest successful snapshot",
                        selection.target,
                        selection.group.as_deref().unwrap_or(""),
                        slot_id
                    ))
                })?;
                if recorded != &current_binding {
                    return Err(Error::preflight(format!(
                        "partial rollout of target '{}' with group '{}' is refused: unselected slot \
                         '{}' was bound to server '{}' at '{}' in the latest successful snapshot, \
                         now bound to '{}' at '{}'; the new snapshot could not carry it forward",
                        selection.target,
                        selection.group.as_deref().unwrap_or(""),
                        slot_id,
                        recorded.server,
                        recorded.deploy_dir,
                        current_binding.server,
                        current_binding.deploy_dir
                    )));
                }
            }
        }
    }
    Ok(())
}

/// DIRECT-RELEASE MEMBERSHIP VALIDATION (before any remote access): a
/// `release:<id>` push deploys onto the CURRENT target's slots, so the
/// release's OWN canonical slot snapshot must freeze EXACTLY the slot-id set
/// the target currently has.
///
/// The expected set is the union over every variant in the record's snapshot
/// of the slots whose ONE owning `target` equals the destination target
/// (each slot has exactly one target, so the union is deduplicated by slot
/// id; the membership is a set). The comparison is LOGICAL membership only:
/// physical bindings (server / deploy_dir) are intentionally allowed to
/// differ — unlike the exact-rollback `Snapshot` branch, which also demands
/// identical physical bindings. A target whose membership DRIFTED since the
/// release was built — a slot added, removed, or renamed — is refused, before
/// any assignment is built and before any remote access, rather than
/// deploying to the wrong slot set.
///
/// Runs at TWO sites: the engine's early gate in `push()` — immediately
/// after the ref is parsed/resolved, BEFORE any lock and BEFORE the remote
/// factory is invoked, in both real and dry-run modes — and here, in the
/// `PushRef::Release` plan branch (the second line of defense protecting the
/// direct-`push_inner` test entry points). `current_slot_ids` is the target's
/// CURRENT member slot-id set, derived from the caller's config exactly as
/// [`plan_assignments`] derives it (`config.target_slots`, in deterministic
/// order), so both gates compare the SAME sets.
///
/// BOTH call sites pass the target's COMPLETE current member-slot set —
/// EVERY slot whose owning `target` equals the target — never a
/// group-filtered selection: a `release:<id> --group <g>` push validates
/// the FULL membership here and then plans ONLY the selected slots (the
/// group narrows the planned assignments, never the membership gate). A
/// `--group` push selecting a proper subset would otherwise compare the
/// release's full frozen set against the subset and fail for every proper
/// group.
pub(crate) fn validate_direct_release_membership(
    target_name: &str,
    release: &ReleaseId,
    rec: &ReleaseRecord,
    current_slot_ids: &[PlacementSlotId],
) -> Result<()> {
    let expected: BTreeSet<String> = rec
        .slots
        .values()
        .flat_map(|cs| cs.slots.iter())
        .filter(|s| s.target == target_name)
        .map(|s| s.id.clone())
        .collect();
    let current: BTreeSet<String> = current_slot_ids
        .iter()
        .map(|s| s.as_str().to_string())
        .collect();
    if expected != current {
        return Err(Error::rollback(format!(
            "release {release} targets slots [{}] but target '{target_name}' currently has [{}]; direct release membership drift is rejected before remote access",
            expected.iter().cloned().collect::<Vec<_>>().join(", "),
            current.iter().cloned().collect::<Vec<_>>().join(", "),
        )));
    }
    Ok(())
}

/// Resolve the desired assignment for each SELECTED slot given the push
/// reference. The selection (target + optional group + exact slot IDs) is
/// normalized once near command entry; planning consumes it instead of
/// independently filtering slots. Returns the assignments, the SET of
/// releases the assignments reference (per-slot artifact provenance — a
/// partial snapshot can span several releases, so there is NO single
/// snapshot-wide release), the plan source, and — for a DIRECT release
/// reference — the explicit [`RebindingPlan`] documenting that the
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
/// explicit [`RebindingPlan`]; a deployment rollback uses the DEPLOYMENT's
/// exact per-slot artifact and physical binding.
pub fn plan_assignments(
    selection: &SlotSelection,
    pref: &PushRef,
    local_release_id: &ReleaseId,
    variant_trees: &BTreeMap<String, TreeDigest>,
    store: &LocalStore,
    config: &Config,
) -> Result<PlannedResolution> {
    if !config.targets.contains_key(selection.target.as_str()) {
        return Err(Error::not_found(format!("target '{}'", selection.target)));
    }
    let members = selection.members(config)?;
    let slot_ids: Vec<PlacementSlotId> = members
        .iter()
        .map(|(slot, _)| PlacementSlotId::new(slot.id.clone()))
        .collect();

    match pref {
        PushRef::Head => {
            let mut out = Vec::new();
            for (slot, _sdef) in &members {
                let slot_id = PlacementSlotId::new(slot.id.clone());
                // The slot's variant is the variant file that declares it (the
                // declaring file is the binding; there is no per-slot `variant`
                // field).
                let variant_name = config.slot_variant(&slot.id)?;
                let variant = VariantName::new(variant_name.to_string());
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
            Ok((
                out,
                BTreeSet::from([local_release_id.clone()]),
                PlanSource::Head,
                None,
            ))
        }
        PushRef::Deployment {
            target: ft,
            deployment_id,
        } => {
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
            // Every SELECTED member's COMPLETE physical binding — the server
            // AND the on-server deploy_dir — must match the one recorded in
            // the snapshot: the generation is mapped to a slot by SLOT ID, so a
            // slot rebound to a different server, or moved to a different
            // deploy_dir on the SAME server, would otherwise silently roll
            // the historical assignment onto the wrong host/location. A
            // missing recorded binding (legacy pre-feature snapshot) is
            // unverifiable and refuses for the same reason. Unselected slots
            // are not planned (they remain at the latest current state).
            for (slot, sdef) in &members {
                let slot_id = PlacementSlotId::new(slot.id.clone());
                let current_binding = PhysicalBinding {
                    server: ServerId::new(sdef.id.clone()),
                    deploy_dir: slot.deploy_dir.to_string_lossy().into_owned(),
                };
                let recorded = entry.bindings.get(&slot_id).ok_or_else(|| {
                    Error::rollback(format!(
                        "slot '{slot_id}' has no recorded physical binding in deployment '{deployment_id}' of target '{ft}'; exact rollback cannot verify the deployment location"
                    ))
                })?;
                if recorded != &current_binding {
                    return Err(Error::rollback(format!(
                        "slot '{slot_id}' was bound to server '{}' at '{}' in deployment '{deployment_id}' of target '{ft}', now bound to '{}' at '{}'; exact rollback would deploy to the wrong host",
                        recorded.server,
                        recorded.deploy_dir,
                        current_binding.server,
                        current_binding.deploy_dir
                    )));
                }
            }
            // The releases the snapshot's slots reference, derived PER SLOT
            // from each slot's OWN artifact binding: a partial snapshot can
            // carry slots from DIFFERENT releases (group pushes over time —
            // group A pushed R1, group B pushed R2), so there is no single
            // snapshot-wide release.
            let mut out = Vec::new();
            for (slot, _sdef) in &members {
                let slot_id = PlacementSlotId::new(slot.id.clone());
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
            Ok((
                out,
                releases,
                PlanSource::DeploymentRef(deployment_id.clone()),
                None,
            ))
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
            let current_slot_ids: Vec<PlacementSlotId> = config
                .target_slots(selection.target.as_str())?
                .into_iter()
                .map(|(slot, _)| PlacementSlotId::new(slot.id.clone()))
                .collect();
            validate_direct_release_membership(
                selection.target.as_str(),
                release,
                &rec,
                &current_slot_ids,
            )?;
            let mut out = Vec::new();
            for (slot, _sdef) in &members {
                let slot_id = PlacementSlotId::new(slot.id.clone());
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
                let variant = VariantName::new(variant_name.clone());
                let tree = rec.variants.get(&variant_name).cloned().ok_or_else(|| {
                    Error::rollback(format!("release {release} lacks variant '{variant_name}'"))
                })?;
                out.push(PlannedAssignment {
                    placement_slot: slot_id,
                    artifact: ArtifactRef {
                        release: release.clone(),
                        variant,
                        tree: TreeDigest::new(tree),
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
            let rebinding_current: BTreeSet<String> = config
                .target_slots(selection.target.as_str())?
                .into_iter()
                .map(|(slot, _)| slot.id.clone())
                .collect();
            let mut rebinding_frozen: BTreeSet<String> = BTreeSet::new();
            let mut frozen_topology: BTreeMap<PlacementSlotId, FrozenSlotTopology> =
                BTreeMap::new();
            for (variant, cs) in &rec.slots {
                for slot in &cs.slots {
                    if slot.target == selection.target.as_str() {
                        rebinding_frozen.insert(slot.id.clone());
                        frozen_topology.insert(
                            PlacementSlotId::new(slot.id.clone()),
                            FrozenSlotTopology {
                                variant: variant.clone(),
                                groups: slot.groups.clone(),
                            },
                        );
                    }
                }
            }
            let rebinding = RebindingPlan {
                release: release.clone(),
                target: selection.target.clone(),
                frozen_topology,
                membership: MembershipCheck {
                    frozen: rebinding_frozen,
                    current: rebinding_current,
                },
                current_physical_slots: members
                    .iter()
                    .map(|(slot, sdef)| {
                        (
                            PlacementSlotId::new(slot.id.clone()),
                            PhysicalBinding {
                                server: ServerId::new(sdef.id.clone()),
                                deploy_dir: slot.deploy_dir.to_string_lossy().into_owned(),
                            },
                        )
                    })
                    .collect(),
            };
            Ok((
                out,
                BTreeSet::from([release.clone()]),
                PlanSource::ReleaseRef(release.clone()),
                Some(rebinding),
            ))
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
) -> Result<crate::records::BehaviorIndex> {
    let mut index = crate::records::BehaviorIndex::new();
    for rid in releases {
        let behaviors = store.read_release_behaviors(rid)?;
        index.insert(rid.clone(), behaviors);
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ArtifactRef, BehaviorContract, CanonicalSlot, CanonicalSlots, DeploymentId, GenerationId,
        GenerationRef, LEDGER_SCHEMA_VERSION, Provenance, RELEASE_RECORD_SCHEMA_VERSION,
        ReleaseRecord, ServerId, TargetName, TreeDigest, VariantName,
    };
    use crate::records::{
        DeploymentStatus, LedgerIntent, LedgerRollback, LedgerTerminal, PhysicalBinding,
    };
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

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

[rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[rotation.deployment]
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

[rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[rotation.deployment]
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

    fn project_with_config() -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), VARIANT_TOML).unwrap();
        let p = project.join("deploy.toml");
        std::fs::write(&p, DEPLOY_TOML).unwrap();
        let config = Config::load(&p).unwrap();
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
        slots: BTreeMap<PlacementSlotId, GenerationRef>,
        bindings: BTreeMap<PlacementSlotId, PhysicalBinding>,
    ) {
        let id = DeploymentId::new(deployment_id.to_string());
        let target = TargetName::new("t1".to_string());
        store
            .append_intent(
                "t1",
                &LedgerIntent {
                    deployment_schema_version: LEDGER_SCHEMA_VERSION,
                    deployment_id: id.clone(),
                    target: target.clone(),
                    group: None,
                    slot_ids: slots.keys().cloned().collect(),
                    behavior_sha256: behavior_sha256.to_string(),
                    attempted_at: "2026-01-01T00:00:00Z".to_string(),
                    desired: BTreeMap::new(),
                    pre_push: BTreeMap::new(),
                    slots: BTreeMap::new(),
                },
            )
            .unwrap();
        store
            .append_terminal(
                "t1",
                &LedgerTerminal {
                    deployment_id: id,
                    target,
                    status: DeploymentStatus::Successful,
                    recorded_at: "2026-01-01T00:00:00Z".to_string(),
                    outcomes: BTreeMap::new(),
                    rollback: Some(LedgerRollback { slots, bindings }),
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
                git_revision: None,
                mapping_sha256: "m".to_string(),
                behavior_sha256: "b".to_string(),
            },
            variants: BTreeMap::from([("standard".to_string(), tree.to_string())]),
            slots: BTreeMap::new(),
        }
    }

    /// Recompute a release record's stored identity from its own content so
    /// `read_release`'s recompute-and-verify passes: the digest is derived
    /// from the record's slot snapshot, bindings, and provenance digests
    /// exactly as `build_release` derives it. Returns the record's release id
    /// (the digest form, which is also the store directory key).
    fn consistent(rec: &mut ReleaseRecord) -> ReleaseId {
        let digest = crate::release::recompute_release_digest(rec)
            .expect("consistent record must carry a slot snapshot");
        rec.release_sha256 = digest.as_str().to_string();
        rec.release_id = crate::model::ReleaseId::from_digest(&digest)
            .as_str()
            .to_string();
        ReleaseId::new(rec.release_id.clone())
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

        let (assignments, desired, source, rebinding) = plan_assignments(
            &SlotSelection::normalize(&config, "t1", None).unwrap(),
            &PushRef::Release {
                release: release.clone(),
            },
            &ReleaseId::new("unused-local".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect("snapshot-carrying release resolves");

        assert_eq!(assignments.len(), 1);
        let a = &assignments[0];
        assert_eq!(a.placement_slot, PlacementSlotId::new("p1"));
        assert_eq!(
            a.artifact.variant.as_str(),
            "standard",
            "the variant must come from the release's OWN stored snapshot"
        );
        assert_eq!(
            a.artifact.tree.as_str(),
            "tree-legacy",
            "the tree must come from the release's own variant bindings"
        );
        assert_eq!(a.artifact.release, release);
        assert_eq!(desired, BTreeSet::from([release.clone()]));
        assert_eq!(source, PlanSource::ReleaseRef(release));
        assert!(
            rebinding.is_some(),
            "a direct release plan must record the explicit RebindingPlan"
        );
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
        let release = ReleaseId::new("rel-sha256-legacy".to_string());
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
            &ReleaseId::new("unused-local".to_string()),
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
            &ReleaseId::new("unused".to_string()),
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
        let dir = tempfile::tempdir().unwrap();
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
        let config = Config::load(&cfg_path).unwrap();
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
            &ReleaseId::new("unused".to_string()),
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
            &ReleaseId::new("unused".to_string()),
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
        let dir = tempfile::tempdir().unwrap();
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
        let config = Config::load(&cfg_path).unwrap();
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

        let (assignments, desired, source, rebinding) = plan_assignments(
            &SlotSelection::normalize(&config, "t1", None).unwrap(),
            &PushRef::Release {
                release: release.clone(),
            },
            &ReleaseId::new("unused".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect("physical binding drift must not block logical-membership planning");
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].placement_slot, PlacementSlotId::new("p1"));
        assert_eq!(desired, BTreeSet::from([release.clone()]));
        assert_eq!(source, PlanSource::ReleaseRef(release));
        assert!(
            rebinding.is_some(),
            "a release:<id> plan must record the explicit RebindingPlan"
        );
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
            &ReleaseId::new("unused".to_string()),
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
            ("standard".to_string(), "tree-standard".to_string()),
            ("other".to_string(), "tree-other".to_string()),
        ]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();

        let (assignments, _, _, rebinding) = plan_assignments(
            &SlotSelection::normalize(&config, "t1", None).unwrap(),
            &PushRef::Release {
                release: release.clone(),
            },
            &ReleaseId::new("unused".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect("snapshot-declared release resolves");
        assert!(
            rebinding.is_some(),
            "a direct release plan must record the explicit RebindingPlan"
        );
        assert_eq!(
            assignments[0].artifact.variant.as_str(),
            "other",
            "the stored slot snapshot must win over the current config's declaring file"
        );
        assert_eq!(
            assignments[0].artifact.tree.as_str(),
            "tree-other",
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
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        // The CURRENT config declares p1 inside the `new` variant file.
        std::fs::write(release_dir.join("new.toml"), VARIANT_TOML).unwrap();
        let cfg_path = project.join("deploy.toml");
        std::fs::write(&cfg_path, DEPLOY_TOML).unwrap();
        let config = Config::load(&cfg_path).unwrap();
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
                PlacementSlotId::new("p1".to_string()),
                GenerationRef {
                    generation: GenerationId::new("gen-old".to_string()),
                    assignment: PlacementSlotAssignment {
                        placement_slot: PlacementSlotId::new("p1".to_string()),
                        artifact: ArtifactRef {
                            release: release.clone(),
                            variant: VariantName::new("old".to_string()),
                            tree: TreeDigest::new("tree-old".to_string()),
                        },
                    },
                },
            )]),
            BTreeMap::from([(
                PlacementSlotId::new("p1".to_string()),
                PhysicalBinding {
                    server: ServerId::new("s1".to_string()),
                    deploy_dir: "/srv/plan".to_string(),
                },
            )]),
        );

        // Exact rollback restores the historical artifact (variant `old` +
        // tree-old together) even though the current config declares p1 in
        // `new` and the release also ships it.
        let (assignments, desired, source, _rebinding) = plan_assignments(
            &SlotSelection::normalize(&config, "t1", None).unwrap(),
            &PushRef::Deployment {
                target: TargetName::new("t1".to_string()),
                deployment_id: DeploymentId::new("deploy-snapshot-histvar".to_string()),
            },
            &ReleaseId::new("unused".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect("deployment ref resolves");
        assert_eq!(assignments[0].artifact.variant.as_str(), "old");
        assert_eq!(assignments[0].artifact.tree.as_str(), "tree-old");
        assert_eq!(assignments[0].artifact.release, release);
        assert_eq!(desired, BTreeSet::from([release.clone()]));
        assert_eq!(
            source,
            PlanSource::DeploymentRef(DeploymentId::new("deploy-snapshot-histvar".to_string()))
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
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), VARIANT_TOML).unwrap();
        let cfg_path = project.join("deploy.toml");
        std::fs::write(&cfg_path, DEPLOY_TOML).unwrap();
        let config = Config::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // A snapshot whose `slots` record the generation but whose `bindings`
        // map is EMPTY (legacy pre-feature line).
        append_successful_snapshot(
            &store,
            "deploy-legacy-snapshot",
            "sha256-aa",
            BTreeMap::from([(
                PlacementSlotId::new("p1".to_string()),
                GenerationRef {
                    generation: GenerationId::new("gen-legacy".to_string()),
                    assignment: PlacementSlotAssignment {
                        placement_slot: PlacementSlotId::new("p1".to_string()),
                        artifact: ArtifactRef {
                            release: ReleaseId::new("rel-sha256-legacy".to_string()),
                            variant: VariantName::new("standard".to_string()),
                            tree: TreeDigest::new("tree-legacy".to_string()),
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
                deployment_id: DeploymentId::new("deploy-legacy-snapshot".to_string()),
            },
            &ReleaseId::new("unused".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect_err("a deployment ref whose snapshot recorded no physical binding must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("no recorded physical binding") && msg.contains("p1"),
            "error must name the unverifiable slot and the missing binding, got: {msg}"
        );
        assert!(
            msg.contains("exact rollback"),
            "error must explain the exact-rollback verification failure, got: {msg}"
        );
    }

    /// THE DIRECT-RELEASE GROUP PROPERTY (deterministic form): a
    /// `release:<id>` push with `--group <g>` validates the release against
    /// the target's COMPLETE current membership and then plans ONLY the
    /// group's slots. A 3-slot target (`p1`/`p2`/`p3`) with a release frozen
    /// to all three: every single-slot group (`g1`/`g2`/`g3`) and every pair
    /// group (`g12`/`g13`/`g23`) plans exactly its selected slots — the
    /// membership gate compares the FULL frozen set against the FULL target
    /// membership, never the group-filtered selection (the bug: a `--group`
    /// push compared the release's full set against the subset and failed for
    /// every proper group). Adding a 4th slot to the target's config is a
    /// COMPLETE-membership drift: the release froze 3 slots, the target now
    /// has 4, so EVERY group refuses at plan time with the membership-drift
    /// error (even a group selecting a single drifted slot).
    #[test]
    fn direct_release_group_plans_every_subset_but_full_membership_drift_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        // Three slots on three servers; each slot belongs to its own
        // single-slot group plus the two pair groups that contain it.
        const VARIANT_3: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
groups = ["g1", "g12", "g13"]
deploy_dir = "/srv/p1"

[[slots]]
id = "p2"
server = "s2"
target = "t1"
groups = ["g2", "g12", "g23"]
deploy_dir = "/srv/p2"

[[slots]]
id = "p3"
server = "s3"
target = "t1"
groups = ["g3", "g13", "g23"]
deploy_dir = "/srv/p3"

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
        std::fs::write(release_dir.join("standard.toml"), VARIANT_3).unwrap();
        let cfg_path = project.join("deploy.toml");
        std::fs::write(
            &cfg_path,
            r#"
schema_version = 2
application = "plan"
release = "v1"

[[servers]]
id = "s1"
address = "a1"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s2"
address = "a2"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s3"
address = "a3"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#,
        )
        .unwrap();
        let config = Config::load(&cfg_path).unwrap();
        assert_eq!(config.target_slot_ids("t1").unwrap(), ["p1", "p2", "p3"]);
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // The release's OWN frozen canonical snapshot: all three slots, with
        // the SAME group declarations as the current config (the release was
        // built when the target had exactly this membership).
        let mut rec = legacy_record("unused", "tree-group");
        rec.slots = BTreeMap::from([(
            "standard".to_string(),
            CanonicalSlots {
                slots: vec![
                    CanonicalSlot {
                        id: "p1".to_string(),
                        server: "s1".to_string(),
                        deploy_dir: "/srv/p1".to_string(),
                        target: "t1".to_string(),
                        groups: vec!["g1".to_string(), "g12".to_string(), "g13".to_string()],
                    },
                    CanonicalSlot {
                        id: "p2".to_string(),
                        server: "s2".to_string(),
                        deploy_dir: "/srv/p2".to_string(),
                        target: "t1".to_string(),
                        groups: vec!["g2".to_string(), "g12".to_string(), "g23".to_string()],
                    },
                    CanonicalSlot {
                        id: "p3".to_string(),
                        server: "s3".to_string(),
                        deploy_dir: "/srv/p3".to_string(),
                        target: "t1".to_string(),
                        groups: vec!["g3".to_string(), "g13".to_string(), "g23".to_string()],
                    },
                ],
            },
        )]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();

        // EVERY single-slot and pair group plans EXACTLY its selected slots:
        // the membership gate passes on the FULL set (release froze 3, the
        // target has 3) and the plan narrows to the group.
        let groups: &[(&str, &[&str])] = &[
            ("g1", &["p1"]),
            ("g2", &["p2"]),
            ("g3", &["p3"]),
            ("g12", &["p1", "p2"]),
            ("g13", &["p1", "p3"]),
            ("g23", &["p2", "p3"]),
        ];
        for (group, want) in groups {
            let selection = SlotSelection::normalize(&config, "t1", Some(group)).unwrap();
            assert_eq!(
                selection
                    .slot_ids
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>(),
                *want,
                "group {group} must select exactly {want:?}"
            );
            let (assignments, desired, source, _rebinding) = plan_assignments(
                &selection,
                &PushRef::Release {
                    release: release.clone(),
                },
                &ReleaseId::new("unused-local".to_string()),
                &BTreeMap::new(),
                &store,
                &config,
            )
            .unwrap_or_else(|e| panic!("group {group} must plan a direct release: {e}"));
            let got: Vec<&str> = assignments
                .iter()
                .map(|a| a.placement_slot.as_str())
                .collect();
            assert_eq!(got, *want, "group {group} must plan exactly its slots");
            for a in &assignments {
                assert_eq!(a.artifact.release, release);
                assert_eq!(a.artifact.variant.as_str(), "standard");
            }
            assert_eq!(desired, BTreeSet::from([release.clone()]));
            assert_eq!(source, PlanSource::ReleaseRef(release.clone()));
        }

        // A 4th slot (`p4` on a new server `s4`) joins the target's config:
        // a COMPLETE-membership drift (the release froze 3 slots, the target
        // now has 4). EVERY group — single AND pair — refuses at plan time
        // with the membership-drift error: the gate validates the FULL set,
        // so even a group selecting a subset of the drifted slots fails.
        let mut drifted_variant = String::from(VARIANT_3);
        drifted_variant.push_str(
            "[[slots]]\nid = \"p4\"\nserver = \"s4\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/p4\"\n",
        );
        std::fs::write(release_dir.join("standard.toml"), drifted_variant).unwrap();
        std::fs::write(
            &cfg_path,
            r#"
schema_version = 2
application = "plan"
release = "v1"

[[servers]]
id = "s1"
address = "a1"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s2"
address = "a2"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s3"
address = "a3"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s4"
address = "a4"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#,
        )
        .unwrap();
        let drifted = Config::load(&cfg_path).unwrap();
        assert_eq!(
            drifted.target_slot_ids("t1").unwrap(),
            ["p1", "p2", "p3", "p4"]
        );
        for (group, _) in groups {
            let selection = SlotSelection::normalize(&drifted, "t1", Some(group)).unwrap();
            let err = plan_assignments(
                &selection,
                &PushRef::Release {
                    release: release.clone(),
                },
                &ReleaseId::new("unused-local".to_string()),
                &BTreeMap::new(),
                &store,
                &drifted,
            )
            .expect_err(&format!(
                "a 4th slot added to the target must refuse every group ({group})"
            ));
            let msg = err.to_string();
            assert!(
                msg.contains("membership")
                    && msg.contains("[p1, p2, p3]")
                    && msg.contains("[p1, p2, p3, p4]"),
                "drift error must name expected [p1, p2, p3] vs current [p1, p2, p3, p4], got: {msg}"
            );
            assert!(
                msg.contains("before remote access"),
                "refusal must explain it happens before remote access, got: {msg}"
            );
        }
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
    ) -> (tempfile::TempDir, Config, LocalStore, ReleaseId) {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), VARIANT_TOML_TWO).unwrap();
        let cfg_path = project.join("deploy.toml");
        std::fs::write(&cfg_path, DEPLOY_TOML_TWO).unwrap();
        let config = Config::load(&cfg_path).unwrap();
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
                PlacementSlotId::new("p1".to_string()),
                GenerationRef {
                    generation: GenerationId::new("gen-old".to_string()),
                    assignment: PlacementSlotAssignment {
                        placement_slot: PlacementSlotId::new("p1".to_string()),
                        artifact: ArtifactRef {
                            release: release.clone(),
                            variant: VariantName::new("standard".to_string()),
                            tree: TreeDigest::new("tree-direct".to_string()),
                        },
                    },
                },
            )]),
            BTreeMap::from([(
                PlacementSlotId::new("p1".to_string()),
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
            cases: 4,
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
                let (assignments, desired, source, rebinding) = plan_assignments(
                    &SlotSelection::normalize(&config, dest, None).unwrap(),
                    &release_ref,
                    &ReleaseId::new("unused-local".to_string()),
                    &BTreeMap::new(),
                    &store,
                    &config,
                )
                .unwrap_or_else(|e| panic!("release:<id> must plan on target {dest}: {e}"));
                assert_eq!(assignments.len(), 1, "one slot per target");
                let a = &assignments[0];
                let want_slot = if dest == "t1" { "p1" } else { "p2" };
                assert_eq!(a.placement_slot, PlacementSlotId::new(want_slot));
                assert_eq!(
                    a.artifact.variant.as_str(),
                    "standard",
                    "the variant must come from the release's OWN stored snapshot"
                );
                assert_eq!(
                    a.artifact.tree.as_str(),
                    "tree-direct",
                    "the tree must come from the release's own variant bindings"
                );
                assert_eq!(a.artifact.release, release);
                assert_eq!(desired, BTreeSet::from([release.clone()]));
                assert_eq!(source, PlanSource::ReleaseRef(release.clone()));
                assert!(
                    rebinding.is_some(),
                    "a release:<id> plan must record the explicit RebindingPlan"
                );
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
                    deployment_id: DeploymentId::new("deploy-source".to_string()),
                },
                &ReleaseId::new("unused".to_string()),
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
                    crate::history::resolve_ref_expr(
                        &crate::history::parse_ref_expr(token).expect("family tokens must parse"),
                        "t2",
                        &store,
                    )
                    .expect_err(&format!("{token} on the no-history destination must fail"));
                }
                crate::history::resolve_ref_expr(
                    &crate::history::parse_ref_expr("deploy-source")
                        .expect("deployment id must parse"),
                    "t2",
                    &store,
                )
                .expect_err("no snapshot for the deployment on t2; the deployment id must fail");
                // The removed release-refid / sN forms are rejected at parse.
                for token in ["s0", &format!("parent({release}, 0)")] {
                    crate::history::parse_ref_expr(token)
                        .expect_err(&format!("legacy form '{token}' must be rejected"));
                }
            }
        }
    }

    // The slot universe + fixed members the membership property draws from:
    // `p1`/`p2`/`p3` are the generated COMMON members (declared for BOTH
    // targets), `iso` is a `t2`-ONLY member (cross-target isolation: it must
    // never leak into t1's derived membership), and `phys` is a constant
    // member whose PHYSICAL binding (server) the fixture may drift while its
    // id stays (logical-only comparison). Each slot owns a distinct server so
    // the config's per-target server-uniqueness validation passes for every
    // generated membership.
    const SLOT_UNIVERSE: [&str; 3] = ["p1", "p2", "p3"];

    /// Build the membership-drift property fixture from two generated
    /// membership sets: `release_inc[i]` says whether universe slot `i` is
    /// frozen in the release record's OWN canonical slot snapshot (targets
    /// `t1`+`t2`); `current_inc[i]` says whether it is declared in the
    /// CURRENT config for both targets. `iso` (t2-only) and `phys`
    /// (t1+t2) are constant members of BOTH the record and the config;
    /// `physical_drift` rebinds `phys` to a different server in the config
    /// only (its id stays — logical membership unchanged). Returns the
    /// fixture plus the written record (so the test can cross-check the
    /// realized physical drift against the canonical binding).
    fn membership_drift_fixture(
        release_inc: [bool; 3],
        current_inc: [bool; 3],
        physical_drift: bool,
    ) -> (
        tempfile::TempDir,
        Config,
        LocalStore,
        ReleaseId,
        ReleaseRecord,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();

        // Current variant file: one slot entry per generated current member,
        // plus the constant `iso` (t2-only) and `phys` (rebound when
        // `physical_drift`).
        let mut variant = String::new();
        let add_slot = |variant: &mut String, id: &str, server: &str, target: &str, dir: &str| {
            variant.push_str(&format!(
                "[[slots]]\nid = \"{id}\"\nserver = \"{server}\"\ntarget = \"{target}\"\ndeploy_dir = \"{dir}\"\n\n"
            ));
        };
        for (i, inc) in current_inc.iter().enumerate() {
            if *inc {
                let id = SLOT_UNIVERSE[i];
                add_slot(
                    &mut variant,
                    id,
                    &format!("s{}", i + 1),
                    "t1",
                    &format!("/srv/{id}"),
                );
            }
        }
        add_slot(&mut variant, "iso", "s4", "t2", "/srv/iso");
        add_slot(
            &mut variant,
            "phys",
            if physical_drift { "s6" } else { "s5" },
            "t1",
            "/srv/phys",
        );
        variant.push_str(
            "[[artifact.mappings]]\nfrom = \"artifacts/build/output/\"\nto = \"app/\"\nrecursive = true\n\n[rotation.per_server]\nkeep_distinct_artifacts = 1\nkeep_days = 0\nprotect_previous = true\n\n[rotation.deployment]\nprotect_deployments = 1\n\n[activation]\nadapter = \"none\"\n\n[verification]\nadapter = \"command\"\nargv = [\"true\"]\ntimeout_seconds = 5\nattempts = 1\ninterval_seconds = 0\n",
        );
        std::fs::write(release_dir.join("standard.toml"), variant).unwrap();

        let mut servers = String::new();
        for i in 1..=6 {
            servers.push_str(&format!(
                "[[servers]]\nid = \"s{i}\"\naddress = \"a{i}\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n"
            ));
        }
        let cfg_path = project.join("deploy.toml");
        std::fs::write(
            &cfg_path,
            format!(
                "schema_version = 2\napplication = \"plan\"\nrelease = \"v1\"\n\n\
                 {servers}\
                 [targets.t1]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n\n\
                 [targets.t2]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n"
            ),
        )
        .unwrap();
        let config = Config::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // The release's OWN frozen canonical snapshot: the generated
        // membership (targets t1+t2) plus the constant phys (t1+t2, at its
        // ORIGINAL server s5) and iso (t2-only), exactly mirroring the
        // current config's targets lists.
        let mut rec = legacy_record("unused", "tree-x");
        let mut canonical: Vec<CanonicalSlot> = Vec::new();
        for (i, id) in SLOT_UNIVERSE.iter().enumerate() {
            if release_inc[i] {
                canonical.push(CanonicalSlot {
                    id: id.to_string(),
                    server: format!("s{}", i + 1),
                    deploy_dir: format!("/srv/{id}"),
                    target: "t1".to_string(),
                    groups: Vec::new(),
                });
            }
        }
        canonical.push(CanonicalSlot {
            id: "phys".to_string(),
            server: "s5".to_string(),
            deploy_dir: "/srv/phys".to_string(),
            target: "t1".to_string(),
            groups: Vec::new(),
        });
        canonical.push(CanonicalSlot {
            id: "iso".to_string(),
            server: "s4".to_string(),
            deploy_dir: "/srv/iso".to_string(),
            target: "t2".to_string(),
            groups: Vec::new(),
        });
        canonical.sort_by(|a, b| a.id.cmp(&b.id));
        rec.slots = BTreeMap::from([("standard".to_string(), CanonicalSlots { slots: canonical })]);
        let release = consistent(&mut rec);
        store.write_release(&rec).unwrap();

        (dir, config, store, release, rec)
    }

    // THE REQUIRED DIRECT-RELEASE MEMBERSHIP PROPERTY: for generated
    // release-versioned and current membership sets, direct release planning
    // onto the destination target SUCCEEDS iff the two slot-ID sets match
    // EXACTLY (logical equality) and REFUSES with the membership-drift error
    // otherwise — the drift refusal lands at PLAN time, before any remote
    // access. Also: cross-target isolation (t2's extra `iso` member never
    // disturbs t1's derived membership) and logical-only comparison (phys's
    // SERVER rebind with an unchanged id still plans).
    proptest! {
        #![proptest_config(ProptestConfig {
            // Bounded + fixed seed: deterministic floor, fast.
            cases: 4,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn direct_release_membership_must_match_release_record(
            release_inc in prop::array::uniform3(prop::bool::ANY),
            current_inc in prop::array::uniform3(prop::bool::ANY),
            physical_drift in prop::bool::ANY,
        ) {
            let (_dir, config, store, release, rec) =
                membership_drift_fixture(release_inc, current_inc, physical_drift);
            let release_ref = PushRef::Release {
                release: release.clone(),
            };
            let expected: BTreeSet<String> = SLOT_UNIVERSE
                .iter()
                .enumerate()
                .filter(|(i, _)| release_inc[*i])
                .map(|(_, id)| id.to_string())
                .collect();
            let current: BTreeSet<String> = SLOT_UNIVERSE
                .iter()
                .enumerate()
                .filter(|(i, _)| current_inc[*i])
                .map(|(_, id)| id.to_string())
                .collect();

            if expected == current {
                // Membership match: the direct release plans on BOTH targets.
                // Cross-target isolation: t2's extra `iso` member (frozen in
                // the record AND declared in the config) must not disturb
                // t1's derived membership — t1 plans exactly its own set.
                for dest in ["t1", "t2"] {
                    let (assignments, desired, source, rebinding) = plan_assignments(
                        &SlotSelection::normalize(&config, dest, None).unwrap(),
                        &release_ref,
                        &ReleaseId::new("unused-local".to_string()),
                        &BTreeMap::new(),
                        &store,
                        &config,
                    )
                    .unwrap_or_else(|e| {
                        panic!("release:<id> must plan on target {dest} when the membership matches: {e}")
                    });
                    // The universe slots and `phys` are t1's; `iso` is
                    // t2's (a slot has exactly one owning target).
                    let mut want: Vec<String> = if dest == "t1" {
                        let mut w: Vec<String> = expected.iter().cloned().collect();
                        w.push("phys".to_string());
                        w
                    } else {
                        vec!["iso".to_string()]
                    };
                    want.sort();
                    let mut got: Vec<String> = assignments
                        .iter()
                        .map(|a| a.placement_slot.as_str().to_string())
                        .collect();
                    got.sort();
                    assert_eq!(
                        got, want,
                        "target {dest} must plan exactly its frozen membership"
                    );
                    for a in &assignments {
                        assert_eq!(a.artifact.variant.as_str(), "standard");
                        assert_eq!(a.artifact.release, release);
                    }
                    assert_eq!(desired, BTreeSet::from([release.clone()]));
                    assert_eq!(source, PlanSource::ReleaseRef(release.clone()));
                    assert!(
                        rebinding.is_some(),
                        "a release:<id> plan must record the explicit RebindingPlan"
                    );
                }
                // LOGICAL-ONLY: when the fixture realized a physical binding
                // change (phys's server rebound), planning still succeeded
                // above — the membership check compares slot IDs only, never
                // server or deploy_dir. Cross-check the fixture actually
                // drifted (config server differs from the record's frozen
                // canonical binding) so the assertion is meaningful.
                if physical_drift {
                    let rec_phys = rec
                        .slots["standard"]
                        .slots
                        .iter()
                        .find(|s| s.id == "phys")
                        .expect("phys is frozen in the record");
                    let bindings = config.target_slot_bindings("t1").unwrap();
                    let cfg_phys = bindings
                        .get(&PlacementSlotId::new("phys"))
                        .expect("phys is a member of t1");
                    assert_ne!(
                        cfg_phys.server.as_str(),
                        rec_phys.server,
                        "the fixture must realize the physical drift: config server {} vs record server {}",
                        cfg_phys.server,
                        rec_phys.server
                    );
                    assert_eq!(
                        cfg_phys.deploy_dir, rec_phys.deploy_dir,
                        "only the server drifted; deploy_dir stays put"
                    );
                }
            } else {
                // Membership drift (missing / extra / renamed slots): REFUSED
                // at plan time on the DRIFTED target (`t1` — the universe
                // slots are t1's), with the drift error naming the release,
                // the expected vs current slot sets, and the
                // before-remote-access clause. `t2`'s membership is
                // unchanged ({iso} in both the record and the config), so it
                // still plans — a slot has exactly one owning target, so a
                // drift on t1 never disturbs t2.
                let err = plan_assignments(
                    &SlotSelection::normalize(&config, "t1", None).unwrap(),
                    &release_ref,
                    &ReleaseId::new("unused-local".to_string()),
                    &BTreeMap::new(),
                    &store,
                    &config,
                )
                .expect_err("membership drift must refuse direct release planning");
                let msg = err.to_string();
                assert!(
                    msg.contains("release")
                        && msg.contains("drift")
                        && msg.contains("before remote access"),
                    "refusal must be the membership-drift error, got: {msg}"
                );
                // t2's membership is unchanged: it plans its own slot.
                let (assignments, _, _, _rebinding) = plan_assignments(
                    &SlotSelection::normalize(&config, "t2", None).unwrap(),
                    &release_ref,
                    &ReleaseId::new("unused-local".to_string()),
                    &BTreeMap::new(),
                    &store,
                    &config,
                )
                .expect("t2's membership is unchanged, so it still plans");
                assert_eq!(assignments.len(), 1);
                assert_eq!(assignments[0].placement_slot, PlacementSlotId::new("iso"));
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
            cases: 4,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn deployment_ref_plans_exactly_the_recorded_snapshot(
            tree in "[a-f0-9]{6,16}",
            generation in "[a-z0-9]{4,10}",
            behavior in "[a-f0-9]{4,16}",
        ) {
            let (_dir, config) = project_with_config();
            let store = LocalStore::with_base(_dir.path().join("store")).unwrap();
            let deployment_id = DeploymentId::new("deploy-prop-plan".to_string());
            let snapshot_release = ReleaseId::new(format!("rel-sha256-{tree}"));
            let slots = BTreeMap::from([(
                PlacementSlotId::new("p1".to_string()),
                GenerationRef {
                    generation: GenerationId::new(format!("gen-{generation}")),
                    assignment: PlacementSlotAssignment {
                        placement_slot: PlacementSlotId::new("p1".to_string()),
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
                deployment_id.as_str(),
                &format!("sha256-{behavior}"),
                slots.clone(),
                BTreeMap::from([(
                    PlacementSlotId::new("p1".to_string()),
                    PhysicalBinding {
                        server: ServerId::new("s1".to_string()),
                        deploy_dir: "/srv/plan".to_string(),
                    },
                )]),
            );

            let (assignments, desired, source, _rebinding) = plan_assignments(
                &SlotSelection::normalize(&config, "t1", None).unwrap(),
                &PushRef::Deployment {
                    target: TargetName::new("t1".to_string()),
                    deployment_id: deployment_id.clone(),
                },
                &ReleaseId::new("unused-local".to_string()),
                &BTreeMap::new(),
                &store,
                &config,
            )
            .unwrap_or_else(|e| panic!("the deployment id must plan its stored state: {e}"));

            // EXACTLY the stored state: one slot, its artifact (variant +
            // tree + release) byte-identical to the snapshot's recorded
            // GenerationRef.
            assert_eq!(assignments.len(), 1, "one member slot");
            let a = &assignments[0];
            let stored = &slots[&PlacementSlotId::new("p1")];
            assert_eq!(a.placement_slot, PlacementSlotId::new("p1"));
            assert_eq!(a.artifact, stored.assignment.artifact, "the planned artifact must equal the snapshot's stored artifact");
            assert_eq!(
                desired,
                BTreeSet::from([snapshot_release.clone()]),
                "the rollout releases are exactly the snapshot's referenced releases"
            );
            assert_eq!(
                source,
                PlanSource::DeploymentRef(deployment_id.clone()),
                "the plan source records the deployment key"
            );

            // A deployment id with NO snapshot never plans (failed / unknown
            // ids fail closed at the plan boundary too).
            let missing = DeploymentId::new("deploy-prop-missing".to_string());
            let err = plan_assignments(
                &SlotSelection::normalize(&config, "t1", None).unwrap(),
                &PushRef::Deployment {
                    target: TargetName::new("t1".to_string()),
                    deployment_id: missing.clone(),
                },
                &ReleaseId::new("unused".to_string()),
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

    fn two_group_project() -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), TWO_GROUP_VARIANT).unwrap();
        let p = project.join("deploy.toml");
        std::fs::write(&p, TWO_GROUP_TOML).unwrap();
        let config = Config::load(&p).unwrap();
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
        let behavior_sha = crate::release::variant_behaviors_digest(&behaviors);
        let mut rec = ReleaseRecord {
            release_schema_version: RELEASE_RECORD_SCHEMA_VERSION,
            release_id: String::new(),
            release_sha256: String::new(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            provenance: Provenance {
                git_revision: None,
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

        let slot_a = PlacementSlotId::new("p1".to_string());
        let slot_b = PlacementSlotId::new("p2".to_string());
        let bindings: BTreeMap<PlacementSlotId, PhysicalBinding> = BTreeMap::from([
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
        let mut state: BTreeMap<PlacementSlotId, ArtifactRef> = BTreeMap::new();
        let mut chain: Vec<(DeploymentId, BTreeMap<PlacementSlotId, GenerationRef>)> = Vec::new();

        let push_count = partial_groups.len() + 1;
        for i in 0..push_count {
            let rid = seed_distinct_release(&store, i);
            let behaviors = store.read_release_behaviors(&rid).unwrap();
            let digest = crate::release::behavior_contract_digest(&behaviors["standard"]);
            expected_digests.insert(rid.clone(), digest);
            let artifact = ArtifactRef {
                release: rid.clone(),
                variant: VariantName::new("standard".to_string()),
                tree: TreeDigest::new(format!("tree-{i}")),
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
            let slots: BTreeMap<PlacementSlotId, GenerationRef> = state
                .iter()
                .map(|(slot, art)| {
                    (
                        slot.clone(),
                        GenerationRef {
                            generation: GenerationId::new(format!("gen-{i}")),
                            assignment: PlacementSlotAssignment {
                                placement_slot: slot.clone(),
                                artifact: art.clone(),
                            },
                        },
                    )
                })
                .collect();
            let id = DeploymentId::new(format!("deploy-mr-{i}"));
            append_successful_snapshot(
                &store,
                id.as_str(),
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
        let (assignments, referenced, source, _rebinding) = plan_assignments(
            &selection,
            &PushRef::Deployment {
                target: TargetName::new("t1".to_string()),
                deployment_id: rollback_id.clone(),
            },
            &ReleaseId::new("unused".to_string()),
            &BTreeMap::new(),
            &store,
            &config,
        )
        .expect("the deployment id must plan its stored state");

        // The plan's referenced-releases set is EXACTLY the releases of the
        // SELECTED slots' stored bindings (derived from the slot bindings,
        // never a snapshot-wide single release): a full rollback references
        // every slot's release, a group rollback only its selected slots'.
        let selected_slots: BTreeSet<PlacementSlotId> = assignments
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
            source,
            PlanSource::DeploymentRef(rollback_id.clone()),
            "the plan source records the deployment key"
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
            let digest = crate::release::behavior_contract_digest(
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
                        crate::release::behavior_contract_digest(other_contract),
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
        // arbitrary FULL/GROUP rollback of an arbitrary snapshot. Bounded 4
        // cases + the pinned 0x5EED_5EED seed (house style) keep the
        // deterministic floor fast; each case is store-only (no remote).
        #![proptest_config(ProptestConfig {
            cases: 4,
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
    ) -> (tempfile::TempDir, Config, LocalStore, ReleaseId) {
        let dir = tempfile::tempdir().unwrap();
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

[rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[rotation.deployment]
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
        let config = Config::load(&p).unwrap();
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
        rec.variants = BTreeMap::from([(frozen_variant.to_string(), "tree-rel".to_string())]);
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
        let snapshot_slots: BTreeMap<PlacementSlotId, GenerationRef> = BTreeMap::from([
            (
                PlacementSlotId::new("p1".to_string()),
                GenerationRef {
                    generation: GenerationId::new("gen-p1".to_string()),
                    assignment: PlacementSlotAssignment {
                        placement_slot: PlacementSlotId::new("p1".to_string()),
                        artifact: ArtifactRef {
                            release: ReleaseId::new("rel-deploy".to_string()),
                            variant: VariantName::new("standard".to_string()),
                            tree: TreeDigest::new("tree-deploy".to_string()),
                        },
                    },
                },
            ),
            (
                PlacementSlotId::new("p2".to_string()),
                GenerationRef {
                    generation: GenerationId::new("gen-p2".to_string()),
                    assignment: PlacementSlotAssignment {
                        placement_slot: PlacementSlotId::new("p2".to_string()),
                        artifact: ArtifactRef {
                            release: ReleaseId::new("rel-deploy".to_string()),
                            variant: VariantName::new("standard".to_string()),
                            tree: TreeDigest::new("tree-deploy".to_string()),
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
                    PlacementSlotId::new("p1".to_string()),
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
                    PlacementSlotId::new("p2".to_string()),
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
            // Bounded 16: the exactly-2^4 case space of the four generated
            // topology dimensions. Fixed seed per house style keeps the
            // deterministic floor fast; each case is store-only (no remote).
            cases: 16,
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
            let local_release = ReleaseId::new("unused-local".to_string());
            let variant_trees: BTreeMap<String, TreeDigest> = if head_broken {
                BTreeMap::new()
            } else {
                BTreeMap::from([(
                    "standard".to_string(),
                    TreeDigest::new("tree-current".to_string()),
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
                let (assignments, desired, source, rebinding) = head.unwrap();
                assert_eq!(assignments.len(), 2);
                for a in &assignments {
                    assert_eq!(
                        a.artifact.variant.as_str(),
                        "standard",
                        "HEAD plans the CURRENT declaring variant"
                    );
                    assert_eq!(
                        a.artifact.tree.as_str(),
                        "tree-current",
                        "HEAD plans from the CURRENT tree, never release/deployment"
                    );
                    assert_eq!(a.artifact.release, local_release);
                }
                assert_eq!(desired, BTreeSet::from([local_release.clone()]));
                assert_eq!(source, PlanSource::Head);
                assert!(rebinding.is_none(), "HEAD records no rebinding");
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
                let (assignments, desired, source, rebinding) = rel.unwrap();
                assert_eq!(assignments.len(), 2);
                for a in &assignments {
                    assert_eq!(
                        a.artifact.variant.as_str(),
                        frozen_variant,
                        "the variant comes from the release's OWN frozen topology"
                    );
                    assert_eq!(
                        a.artifact.tree.as_str(),
                        "tree-rel",
                        "the tree comes from the release's own bindings"
                    );
                    assert_eq!(a.artifact.release, release);
                }
                assert_eq!(desired, BTreeSet::from([release.clone()]));
                assert_eq!(source, PlanSource::ReleaseRef(release.clone()));
                // THE EXPLICIT REBINDING PLAN: the frozen topology, the
                // logical membership check (frozen == current; physical
                // bindings may differ), and the CURRENT physical slots the
                // topology is bound onto — never the deployment's recorded
                // binding, even when the fixture drifted it.
                let rp = rebinding
                    .expect("a release:<id> plan must carry the explicit RebindingPlan");
                assert_eq!(rp.release, release);
                assert_eq!(rp.target.as_str(), "t1");
                assert_eq!(
                    rp.membership.frozen,
                    BTreeSet::from(["p1".to_string(), "p2".to_string()])
                );
                assert_eq!(
                    rp.membership.current, rp.membership.frozen,
                    "frozen membership must equal the current membership (logical-only)"
                );
                assert_eq!(rp.frozen_topology.len(), 2);
                for (slot, topo) in &rp.frozen_topology {
                    assert_eq!(topo.variant, frozen_variant);
                    assert!(topo.groups.is_empty());
                    assert!(matches!(slot.as_str(), "p1" | "p2"));
                }
                let p1 = &rp.current_physical_slots[&PlacementSlotId::new("p1".to_string())];
                assert_eq!(p1.server.as_str(), "s1");
                assert_eq!(p1.deploy_dir, "/srv/p1");
                let p2 = &rp.current_physical_slots[&PlacementSlotId::new("p2".to_string())];
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
                    deployment_id: DeploymentId::new("deploy-snapshot".to_string()),
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
                let (assignments, desired, source, rebinding) = dep.unwrap();
                assert_eq!(assignments.len(), 2);
                for a in &assignments {
                    assert_eq!(
                        a.artifact.release.as_str(),
                        "rel-deploy",
                        "the artifact comes from the deployment's exact stored state"
                    );
                    assert_eq!(a.artifact.variant.as_str(), "standard");
                    assert_eq!(a.artifact.tree.as_str(), "tree-deploy");
                }
                assert_eq!(
                    desired,
                    BTreeSet::from([ReleaseId::new("rel-deploy".to_string())])
                );
                assert_eq!(
                    source,
                    PlanSource::DeploymentRef(DeploymentId::new("deploy-snapshot".to_string()))
                );
                assert!(
                    rebinding.is_none(),
                    "a deployment rollback records no rebinding"
                );
            }
        }
    }
}
