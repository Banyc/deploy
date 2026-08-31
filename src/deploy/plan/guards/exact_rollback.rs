//! Exact-rollback binding verification:
//! [`verify_exact_rollback_bindings`] requires the historical release's
//! rollback to bind exactly the current slots.

use crate::config::ServerDef;
use crate::config::SlotConfig;
use crate::error::Error;
use crate::error::Result;
use crate::identity::DeploymentId;
use crate::identity::ReceiverUuid;
use crate::identity::ServerId;
use crate::identity::SlotId;
use crate::identity::TargetName;
use crate::ledger::PhysicalBinding;
use crate::ledger::TargetSnapshot;
use std::collections::BTreeMap;

// EXACT ROLLBACK VERIFICATION (A2): a deployment rollback restores the
// snapshot's exact per-slot artifact AND physical binding, so every
// SELECTED slot's current physical location must match the one the snapshot
// recorded — a slot recorded with NO binding (legacy pre-feature snapshot)
// is unverifiable and refuses, a slot whose PHYSICAL RECEIVER changed (even
// under the same ServerId/path — the deploy_dir's immutable receiver UUID
// is the physical identity, not the logical ServerId) would otherwise
// silently roll the historical assignment onto the wrong host/location.
// The checks run inside the `PushRef::Deployment` branch of
// [`crate::deploy::plan::plan_assignments`] before any remote mutation.

/// Verify every SELECTED member's COMPLETE physical binding — the
/// deploy_dir's IMMUTABLE receiver UUID (the PHYSICAL identity: two
/// ServerIds naming the same physical host+dir share the receiver, and a
/// slot rebound to a different ServerId pointing at the same physical
/// location keeps it) — against the one recorded in the snapshot: the
/// generation is mapped to a slot by SLOT ID, so a slot whose physical
/// receiver changed (even under the same ServerId/path) would otherwise
/// silently roll the historical assignment onto the wrong host/location.
/// `receiver_uuids` carries each member slot's CURRENT receiver UUID read
/// from its provisioned remote during preflight (`None` when the deploy_dir
/// is not yet provisioned — the marker is created by provisioning). A
/// missing recorded binding (legacy pre-feature snapshot) is unverifiable
/// and refuses for the same reason. Unselected slots are not planned (they
/// remain at the latest current state).
pub(crate) fn verify_exact_rollback_bindings(
    members: &[(&SlotConfig, &ServerDef)],
    entry: &TargetSnapshot,
    deployment_id: &DeploymentId,
    ft: &TargetName,
    receiver_uuids: &BTreeMap<SlotId, Option<ReceiverUuid>>,
) -> Result<()> {
    for (slot, sdef) in members {
        let slot_id = SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment");

        let current_binding = match receiver_uuids.get(&slot_id) {
            Some(Some(uuid)) => PhysicalBinding::new(
                ServerId::parse(sdef.id.as_str()).expect("validated server id is a safe segment"),
                slot.deploy_dir(),
                uuid.clone(),
            )
            .expect("a config-validated deploy_dir is absolute and traversal-free"),
            _ => PhysicalBinding::from_config(
                ServerId::parse(sdef.id.as_str()).expect("validated server id is a safe segment"),
                slot.deploy_dir(),
            )
            .expect("a config-validated deploy_dir is absolute and traversal-free"),
        };
        let recorded = entry.get(&slot_id).map(|e| e.binding()).ok_or_else(|| {
            Error::rollback(format!(
                "slot '{slot_id}' has no recorded physical binding in deployment '{deployment_id}' of target '{ft}'; exact rollback cannot verify the deployment location"
            ))
        })?;
        if !recorded.same_physical_location(&current_binding) {
            return Err(Error::rollback(format!(
                "slot '{slot_id}' was bound to server '{}' at '{}' (receiver '{}') in deployment '{deployment_id}' of target '{ft}', now bound to '{}' at '{}' (receiver '{}'); exact rollback would deploy to the wrong host",
                recorded.server(),
                recorded.deploy_dir(),
                recorded
                    .receiver_uuid()
                    .map(|u| u.as_str())
                    .unwrap_or("<unknown>"),
                current_binding.server(),
                current_binding.deploy_dir(),
                current_binding
                    .receiver_uuid()
                    .map(|u| u.as_str())
                    .unwrap_or("<unknown>"),
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CapacityConfig, HostIdentity, ServerConnection};
    use crate::identity::{
        ArtifactRef, Identifier, VariantName, test_deployment_id, test_generation_id,
        test_receiver_uuid, test_release_id, test_tree_digest,
    };
    use crate::kernel::snapshot::SnapshotSlot;
    use crate::ledger::TargetSnapshot;
    use std::collections::BTreeMap;

    /// A one-slot member: the slot's config declaration + its server def.
    fn member(slot_id: &str, server: &str, deploy_dir: &str) -> (&'static SlotConfig, ServerDef) {
        // The slot config is leaked for the test (the guard borrows it).
        let slot = Box::leak(Box::new(SlotConfig::new(
            slot_id,
            server,
            deploy_dir,
            "t1",
            vec![],
        )));
        let sdef = ServerDef::new(
            Identifier::parse(server).expect("safe segment"),
            ServerConnection::Local {
                identity: HostIdentity::Local,
            },
            CapacityConfig::default(),
        );
        (slot, sdef)
    }

    /// A one-slot snapshot recording the given binding.
    fn snapshot_with(binding: PhysicalBinding) -> TargetSnapshot {
        let slot = SnapshotSlot::new(
            test_generation_id("gen"),
            ArtifactRef {
                release: test_release_id("rel"),
                variant: VariantName::parse("standard").unwrap(),
                tree: test_tree_digest("tree"),
            },
            binding,
        );
        TargetSnapshot::from_entries(BTreeMap::from([(SlotId::parse("p1").unwrap(), slot)]))
    }

    /// THE PHYSICAL-IDENTITY RULE at the guard level: the receiver UUID is
    /// the SOLE physical identity — a slot whose physical receiver changed
    /// (even under the same ServerId/path) must NOT receive the historical
    /// generations, and a slot whose receiver is UNCHANGED (even under a
    /// different ServerId/path — two ServerIds naming the same physical
    /// host+dir share the receiver) still rolls back.
    #[test]
    fn guard_compares_receiver_uuid_not_server_or_path() {
        let dep = test_deployment_id("deploy-guard");
        let ft = TargetName::parse("t1").unwrap();
        let recv_a = test_receiver_uuid("recv-a");
        let recv_b = test_receiver_uuid("recv-b");

        // The recorded binding: server s1 at /srv/deploy/p1, receiver A.
        let recorded = PhysicalBinding::new(
            ServerId::parse("s1").unwrap(),
            "/srv/deploy/p1",
            recv_a.clone(),
        )
        .unwrap();
        let snapshot = snapshot_with(recorded);

        // (1) SAME receiver, DIFFERENT ServerId/path: the physical location
        // is unchanged (the receiver is the identity) — rollback succeeds.
        let (slot_b, sdef_b) = member("p1", "s2", "/srv/deploy/p2");
        let members = vec![(slot_b, &sdef_b)];
        let uuids = BTreeMap::from([(SlotId::parse("p1").unwrap(), Some(recv_a.clone()))]);
        verify_exact_rollback_bindings(&members, &snapshot, &dep, &ft, &uuids)
            .expect("an unchanged receiver rolls back even under a different ServerId/path");

        // (2) DIFFERENT receiver, SAME ServerId/path: the physical location
        // changed — rollback refuses (the exact class the feature closes:
        // the same logical identity pointing at a different physical
        // receiver).
        let (slot_a, sdef_a) = member("p1", "s1", "/srv/deploy/p1");
        let members = vec![(slot_a, &sdef_a)];
        let uuids = BTreeMap::from([(SlotId::parse("p1").unwrap(), Some(recv_b.clone()))]);
        let err = verify_exact_rollback_bindings(&members, &snapshot, &dep, &ft, &uuids)
            .expect_err("a changed receiver must refuse the rollback");
        assert!(
            err.to_string()
                .contains("exact rollback would deploy to the wrong host"),
            "the refusal names the wrong-host class, got: {err}"
        );

        // (3) An UNKNOWN current receiver (the deploy_dir is not yet
        // provisioned) falls back to the legacy `{server, deploy_dir}`
        // evidence: same server+dir as the recorded binding → still rolls
        // back.
        let uuids = BTreeMap::from([(SlotId::parse("p1").unwrap(), None)]);
        verify_exact_rollback_bindings(&members, &snapshot, &dep, &ft, &uuids)
            .expect("an unknown receiver falls back to the legacy server+dir evidence");
    }
}
