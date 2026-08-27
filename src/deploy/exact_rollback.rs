//! EXACT ROLLBACK VERIFICATION (A2): a deployment rollback restores the
//! snapshot's exact per-slot artifact AND physical binding, so every
//! SELECTED slot's current physical location must match the one the snapshot
//! recorded — a slot recorded with NO binding (legacy pre-feature snapshot)
//! is unverifiable and refuses, a slot rebound to a different server, or
//! moved to a different deploy_dir on the SAME server, would otherwise
//! silently roll the historical assignment onto the wrong host/location.
//! The checks run inside the `PushRef::Deployment` branch of
//! [`crate::deploy::plan::plan_assignments`] before any remote mutation.

use crate::config::{ServerDef, SlotConfig};
use crate::error::{Error, Result};
use crate::identity::{DeploymentId, ServerId, SlotId, TargetName};
use crate::ledger::{LedgerRollback, PhysicalBinding};

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
    entry: &LedgerRollback,
    deployment_id: &DeploymentId,
    ft: &TargetName,
) -> Result<()> {
    for (slot, sdef) in members {
        let slot_id = SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment");

        let current_binding = PhysicalBinding {
            server: ServerId::parse(sdef.id.as_str())
                .expect("validated server id is a safe segment"),
            deploy_dir: slot.deploy_dir().to_string_lossy().into_owned(),
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
    Ok(())
}
