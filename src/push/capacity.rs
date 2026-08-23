//! Capacity preflight.
//!
//! Coarse per-server headroom check (`capacity_preflight`) plus the on-host
//! tree-size walker (`tree_size_on_host`), resolved from the caller's current
//! `deploy.toml` capacity policy. Extracted from `push::engine`.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::model::{DeploymentId, OperationId, PlacementSlotId};
use crate::remote::helper::RemoteHelper;
use crate::rotation::compute_retained;
use crate::store::local::LocalStore;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Coarse capacity preflight: ensure each server has room for the new trees plus
/// the configured safety headroom, running protected rotation first if needed.
///
/// Capacity headroom is a per-server policy declared on the top-level
/// `[[servers]]` entry (`ServerDef.capacity`) and is ALWAYS resolved from the
/// caller's current `deploy.toml` — for HEAD pushes and historical/rollback
/// pushes alike. Servers have no per-release history, so capacity is never
/// part of the release snapshot: the release identity covers mappings,
/// behavior, and trees only. Rotation (used for the protected pre-rotation) is
/// target-level configuration from `deploy.toml`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn capacity_preflight(
    store: &LocalStore,
    assignments: &[crate::push::plan::PlannedAssignment],
    helpers: &HashMap<PlacementSlotId, RemoteHelper>,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
    config: &Config,
    rotation: &crate::config::RotationConfig,
) -> Result<()> {
    for a in assignments {
        // Resolve the server's CURRENT capacity policy for this assignment.
        // Capacity is a per-server policy resolved from the caller's current
        // config (never a release snapshot). The assignment names a placement
        // slot; the slot binds one server. A miss is an internal invariant
        // violation: the assignment was planned against this config.
        let slot = config
            .slot_defs()
            .into_iter()
            .find(|s| s.id.as_str() == a.placement_slot.as_str())
            .expect("assignment slot present in config");
        let server = config
            .servers
            .iter()
            .find(|s| s.id == slot.server)
            .expect("slot's server present in config");
        let capacity = &server.capacity;
        let reserve_bytes = capacity.reserve_bytes;
        let reserve_percent = capacity.reserve_percent as f64 / 100.0;
        let helper = helpers.get(&a.placement_slot).expect("helper present");
        if helper.tree_exists(a.artifact.tree.as_str()) {
            continue;
        }
        let need = tree_size_on_host(&store.object_root(&a.artifact.tree));
        let avail = helper.remote().available_bytes().unwrap_or(0);
        let total = helper
            .remote()
            .root()
            .metadata()
            .map(|m| m.len())
            .unwrap_or(0);
        let _ = total;
        let reserve = reserve_bytes.max((avail as f64 * reserve_percent) as u64);
        if need + reserve > avail {
            // Run protected rotation using the target's rotation policy, then
            // recheck capacity directly rather than failing the restore.
            // Best-effort by design: rotation is only an optimization to free
            // capacity, and the hard capacity check below decides the outcome.
            // A rotation failure is not recoverable at this point (the push
            // would have to abort mid-preflight), and the recheck fails the
            // push loudly if space is genuinely short.
            if helper.acquire_lock(op_id.as_str(), false).is_ok() {
                let retained = compute_retained(helper, &config.pins, store, rotation)?;
                let active = HashSet::from([deployment_id.as_str().to_string()]);
                helper.rotate(&retained, &active).ok();
                helper.release_lock(op_id.as_str()).ok();
            }
            let avail2 = helper.remote().available_bytes().unwrap_or(0);
            if need + reserve > avail2 {
                return Err(Error::preflight(format!(
                    "insufficient capacity on slot {}: need {} + reserve {} > avail {}",
                    a.placement_slot, need, reserve, avail2
                )));
            }
        }
    }
    Ok(())
}

fn tree_size_on_host(root: &Path) -> u64 {
    walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok().filter(|m| m.is_file()).map(|m| m.len()))
        .sum()
}
