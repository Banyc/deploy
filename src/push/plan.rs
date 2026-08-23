//! Deployment planning: resolve the desired per-slot assignment from a push
//! reference.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::history::{PushRef, resolve_snapshot};
use crate::model::{
    ArtifactRef, PlacementSlotAssignment, PlacementSlotId, ReleaseId, ServerId, TreeDigest,
    VariantName,
};
use crate::records::{PhysicalBinding, PlanSource};
use crate::store::local::LocalStore;
use std::collections::{BTreeMap, BTreeSet};

/// The plan for one placement slot: exactly the canonical slot→artifact
/// assignment ([`PlacementSlotAssignment`]), reused rather than re-declared.
pub type PlannedAssignment = PlacementSlotAssignment;

/// Resolve the desired assignment for each slot of `target_name` given the
/// push reference. Returns the assignments, the release the attempt is bound
/// to, and the plan source.
pub fn plan_assignments(
    target_name: &str,
    pref: &PushRef,
    local_release_id: &ReleaseId,
    variant_trees: &BTreeMap<String, TreeDigest>,
    store: &LocalStore,
    config: &Config,
) -> Result<(Vec<PlannedAssignment>, ReleaseId, PlanSource)> {
    if !config.targets.contains_key(target_name) {
        return Err(Error::not_found(format!("target '{target_name}'")));
    }
    let members = config.target_slots(target_name)?;
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
            Ok((out, local_release_id.clone(), PlanSource::Head))
        }
        PushRef::Fleet {
            target: ft, index, ..
        } => {
            let entry = resolve_snapshot(store, ft, *index)?;
            let recorded: BTreeSet<String> =
                entry.slots.keys().map(|s| s.as_str().to_string()).collect();
            let current: BTreeSet<String> =
                slot_ids.iter().map(|s| s.as_str().to_string()).collect();
            if recorded != current {
                return Err(Error::rollback(
                    "target membership changed; exact fleet rollback requires identical stable placement-slot set",
                ));
            }
            // Every member's COMPLETE physical binding — the server AND the
            // on-server deploy_dir — must match the one recorded in the
            // snapshot: the generation is mapped to a slot by SLOT ID, so a
            // slot rebound to a different server, or moved to a different
            // deploy_dir on the SAME server, would otherwise silently roll
            // the historical assignment onto the wrong host/location. A
            // missing recorded binding (legacy pre-feature snapshot) is
            // unverifiable and refuses for the same reason.
            for (slot, sdef) in &members {
                let slot_id = PlacementSlotId::new(slot.id.clone());
                let current = PhysicalBinding {
                    server: ServerId::new(sdef.id.clone()),
                    deploy_dir: slot.deploy_dir.to_string_lossy().into_owned(),
                };
                let recorded = entry.bindings.get(&slot_id).ok_or_else(|| {
                    Error::rollback(format!(
                        "slot '{slot_id}' has no recorded physical binding in {ft}@f{index}; exact rollback cannot verify the deployment location"
                    ))
                })?;
                if recorded != &current {
                    return Err(Error::rollback(format!(
                        "slot '{slot_id}' was bound to server '{}' at '{}' in {ft}@f{index}, now bound to '{}' at '{}'; exact rollback would deploy to the wrong host",
                        recorded.server, recorded.deploy_dir, current.server, current.deploy_dir
                    )));
                }
            }
            let mut out = Vec::new();
            // The variant comes from the historical snapshot, not the current
            // slot binding.
            for (slot, _sdef) in &members {
                let slot_id = PlacementSlotId::new(slot.id.clone());
                let g = entry.slots.get(&slot_id).ok_or_else(|| {
                    Error::rollback(format!("slot {slot_id} missing in fleet snapshot"))
                })?;
                out.push(PlannedAssignment {
                    placement_slot: slot_id,
                    artifact: g.assignment.artifact.clone(),
                });
            }
            let desired = entry
                .slots
                .values()
                .next()
                .map(|g| g.assignment.artifact.release.clone())
                .unwrap_or_else(|| local_release_id.clone());
            Ok((out, desired, PlanSource::FleetRef(*index)))
        }
        PushRef::Release { release, .. } => {
            let rec = store
                .read_release(release)
                .map_err(|_| Error::rollback(format!("release {release} not available locally")))?;
            let mut out = Vec::new();
            for (slot, _sdef) in &members {
                let slot_id = PlacementSlotId::new(slot.id.clone());
                // The variant comes from the release's OWN stored slot
                // snapshot: a historical release resolves each slot's
                // slot→variant binding against the slots it was materialized
                // from, never the caller's current variant files. A record
                // written before the canonical slot snapshot existed (empty
                // `rec.slots`) falls back to the current configuration's
                // declaring file. Note this slot declaration snapshot is
                // distinct from a fleet snapshot's slot→SERVER bindings (the
                // exact-rollback physical-host check): those remain a
                // per-target deployment concern.
                let variant_name = if rec.slots.is_empty() {
                    // Legacy record: fall back to the current declaring file.
                    config.slot_variant(&slot.id)?.to_string()
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
            Ok((
                out,
                release.clone(),
                PlanSource::ReleaseRef(release.clone()),
            ))
        }
    }
}
