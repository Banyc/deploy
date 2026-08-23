//! Deployment planning: resolve the desired per-slot assignment from a push
//! reference.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::history::{PushRef, resolve_fleet_ref};
use crate::model::{
    ArtifactRef, PlacementSlotAssignment, PlacementSlotId, ReleaseId, TreeDigest, VariantName,
};
use crate::records::PlanSource;
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
                let variant = VariantName::new(slot.variant.clone());
                let tree = variant_trees.get(&slot.variant).cloned().ok_or_else(|| {
                    Error::plan(format!("variant '{}' not materialized", slot.variant))
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
            let entry = resolve_fleet_ref(store, ft, *index)?;
            let recorded: BTreeSet<String> =
                entry.slots.keys().map(|s| s.as_str().to_string()).collect();
            let current: BTreeSet<String> =
                slot_ids.iter().map(|s| s.as_str().to_string()).collect();
            if recorded != current {
                return Err(Error::rollback(
                    "target membership changed; exact fleet rollback requires identical stable placement-slot set",
                ));
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
                let variant = VariantName::new(slot.variant.clone());
                let tree = rec.variants.get(&slot.variant).cloned().ok_or_else(|| {
                    Error::rollback(format!(
                        "release {release} lacks variant '{}'",
                        slot.variant
                    ))
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
