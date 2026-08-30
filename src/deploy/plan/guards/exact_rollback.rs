//! Exact-rollback binding verification:
//! [`verify_exact_rollback_bindings`] requires the historical release's
//! rollback to bind exactly the current slots.

use crate::config::ServerDef;
use crate::config::SlotConfig;
use crate::error::Error;
use crate::error::Result;
use crate::identity::DeploymentId;
use crate::identity::ServerId;
use crate::identity::SlotId;
use crate::identity::TargetName;
use crate::ledger::PhysicalBinding;
use crate::ledger::TargetSnapshot;

// EXACT ROLLBACK VERIFICATION (A2): a deployment rollback restores the
// snapshot's exact per-slot artifact AND physical binding, so every
// SELECTED slot's current physical location must match the one the snapshot
// recorded — a slot recorded with NO binding (legacy pre-feature snapshot)
// is unverifiable and refuses, a slot rebound to a different server, or
// moved to a different deploy_dir on the SAME server, would otherwise
// silently roll the historical assignment onto the wrong host/location.
// The checks run inside the `PushRef::Deployment` branch of
// [`crate::deploy::plan::plan_assignments`] before any remote mutation.

/// Verify every SELECTED member's COMPLETE physical binding — the server
/// AND the on-server deploy_dir — against the one recorded in the snapshot:
/// the generation is mapped to a slot by SLOT ID, so a slot rebound to a
/// different server, or moved to a different deploy_dir on the SAME server,
/// would otherwise silently roll the historical assignment onto the wrong
/// host/location. A missing recorded binding (legacy pre-feature snapshot)
/// is unverifiable and refuses for the same reason. Unselected slots are not
/// planned (they remain at the latest current state).
pub(crate) fn verify_exact_rollback_bindings(
    members: &[(&SlotConfig, &ServerDef)],
    entry: &TargetSnapshot,
    deployment_id: &DeploymentId,
    ft: &TargetName,
) -> Result<()> {
    for (slot, sdef) in members {
        let slot_id = SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment");

        let current_binding = PhysicalBinding::new(
            ServerId::parse(sdef.id.as_str()).expect("validated server id is a safe segment"),
            slot.deploy_dir(),
        )
        .expect("a config-validated deploy_dir is absolute and traversal-free");
        let recorded = entry.get(&slot_id).map(|e| e.binding()).ok_or_else(|| {
            Error::rollback(format!(
                "slot '{slot_id}' has no recorded physical binding in deployment '{deployment_id}' of target '{ft}'; exact rollback cannot verify the deployment location"
            ))
        })?;
        if recorded != &current_binding {
            return Err(Error::rollback(format!(
                "slot '{slot_id}' was bound to server '{}' at '{}' in deployment '{deployment_id}' of target '{ft}', now bound to '{}' at '{}'; exact rollback would deploy to the wrong host",
                recorded.server(),
                recorded.deploy_dir(),
                current_binding.server(),
                current_binding.deploy_dir()
            )));
        }
    }
    Ok(())
}
