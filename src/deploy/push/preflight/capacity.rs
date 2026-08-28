//! The CAPACITY + STAGING preflight (steps 8-9): [`run_capacity_and_staging`]
//! reserves capacity headroom and prepares the disposable staging tree,
//! AFTER the attempt intent was persisted and BEFORE any `current` change.

use super::PreflightFailure;
use crate::config::ProjectConfig;
use crate::deploy::plan::PlannedAssignment;
use crate::deploy::plan::capacity_preflight;
use crate::identity::DeploymentId;
use crate::identity::OperationId;
use crate::identity::SlotId;
use crate::remote::helper::RemoteHelper;
use crate::store::local::LocalStore;
use std::collections::HashMap;

/// Capacity + staging preflight for one push, run AFTER the attempt intent
/// was persisted and BEFORE any `current` change. A failure in either phase
/// is tagged with the failing phase's terminal reason (see
/// [`PreflightFailure`]); the caller ends the attempt `FailedPreflight`,
/// cleans incoming staging best-effort, and returns the ORIGINAL error.
pub(crate) fn run_capacity_and_staging(
    store: &LocalStore,
    assignments: &[PlannedAssignment],
    helpers: &HashMap<SlotId, RemoteHelper>,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
    config: &ProjectConfig,
) -> std::result::Result<(), PreflightFailure> {
    if let Err(source) =
        capacity_preflight(store, assignments, helpers, op_id, deployment_id, config)
    {
        return Err(PreflightFailure {
            reason: "preflight failed",
            source,
        });
    }
    // Stage every needed tree into operation-unique incoming paths.
    for a in assignments {
        let helper = &helpers[&a.placement_slot];
        if !helper
            .tree_exists(a.artifact.tree.as_str())
            .map_err(|source| PreflightFailure {
                reason: "staging failed",
                source,
            })?
        {
            let host_obj = store.object_root(&a.artifact.tree);
            if let Err(source) =
                helper.stage_incoming(deployment_id.as_str(), a.artifact.tree.as_str(), &host_obj)
            {
                return Err(PreflightFailure {
                    reason: "staging failed",
                    source,
                });
            }
        }
    }
    Ok(())
}
