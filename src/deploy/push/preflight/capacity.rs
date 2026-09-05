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
use crate::remote::helper::{RemoteHelper, RemoteStatus};
use crate::store::local::LocalStore;
use std::collections::HashMap;

/// Capacity + staging preflight for one push, run AFTER the attempt intent
/// was persisted and BEFORE any `current` change. A failure in either phase
/// is tagged with the failing phase's terminal reason (see
/// [`PreflightFailure`]); the caller ends the attempt `FailedPreflight`,
/// cleans incoming staging best-effort, and returns the ORIGINAL error.
/// Returns the number of stages that used the PER-FILE DEDUP (the caller
/// traces it).
pub(crate) fn run_capacity_and_staging(
    store: &LocalStore,
    assignments: &[PlannedAssignment],
    helpers: &HashMap<SlotId, RemoteHelper>,
    statuses: &HashMap<SlotId, RemoteStatus>,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
    config: &ProjectConfig,
) -> std::result::Result<usize, PreflightFailure> {
    if let Err(source) =
        capacity_preflight(store, assignments, helpers, op_id, deployment_id, config)
    {
        return Err(PreflightFailure {
            reason: "preflight failed",
            source,
        });
    }
    // Stage every needed tree into operation-unique incoming paths. The
    // slot's CURRENT tree (from its verified status) is passed as the
    // per-file dedup base: unchanged files are copied from it on the server
    // instead of being re-uploaded.
    let mut deduped = 0usize;
    for a in assignments {
        let helper = &helpers[&a.placement_slot];
        if !helper
            .tree_exists(&a.artifact.tree)
            .map_err(|source| PreflightFailure {
                reason: "staging failed",
                source,
            })?
        {
            let host_obj = store.object_root(&a.artifact.tree);
            let prev = statuses
                .get(&a.placement_slot)
                .and_then(|st| st.current_tree().cloned());
            let used_dedup = match helper.stage_incoming(
                deployment_id,
                &a.artifact.tree,
                &host_obj,
                prev.as_ref(),
            ) {
                Ok(used) => used,
                Err(source) => {
                    return Err(PreflightFailure {
                        reason: "staging failed",
                        source,
                    });
                }
            };
            if used_dedup {
                deduped += 1;
            }
        }
    }
    Ok(deduped)
}
