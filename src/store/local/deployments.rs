//! Per-deployment plan records (A3 `deployments/<id>/`): the immutable
//! `plan.json` snapshot written via the create-or-compare CAS protocol.

use crate::error::{Error, Result};
use crate::identity::DeploymentId;
use crate::ledger::DeploymentPlan;
use crate::store::atomic::ensure_private_dir;
use crate::store::local::{LocalStore, sanitize, write_atomic_cas};
use std::path::PathBuf;

impl LocalStore {
    // ---- deployments ------------------------------------------------------

    /// The deployment plan directory (`deployments/<id>/`). The id is a
    /// validated deployment id (`deploy-<uuid-v7>` — a filesystem-safe ASCII
    /// string by the fixed grammar), stored VERBATIM: two distinct
    /// deployment ids always map to two distinct directories (injective by
    /// construction; no re-encoding, so no collision class).
    pub fn deployment_dir(&self, id: &DeploymentId) -> PathBuf {
        self.base.join("deployments").join(id.as_str())
    }

    /// The on-disk directory for a deployment dir NAME (an arbitrary store
    /// dir name). The GC computes deletion paths for candidate dirs that may
    /// not be valid deployment ids (junk-named dirs are still candidates),
    /// so this takes the raw name — never a validated [`DeploymentId`] — and
    /// keeps the [`sanitize`](crate::store::local::sanitize) confinement for
    /// non-grammar junk (a valid name passes through unchanged).
    pub(crate) fn deployment_dir_named(&self, name: &str) -> PathBuf {
        self.base.join("deployments").join(sanitize(name))
    }

    /// Write the recorded deployment plan (`deployments/<id>/plan.json`). The
    /// plan is the deployment's immutable plan artifact (deployment IDs are
    /// unique, so a conflicting same-ID rewrite is corruption and must fail
    /// rather than silently rewrite history). The outcomes and status of a
    /// deployment live in the LEDGER's terminal event, not here — this file
    /// is purely the plan snapshot the deployment was planned from (the
    /// checkpoint sweep deletes unreachable `deployments/<id>/` dirs).
    ///
    /// THE EMBEDDED-IDENTITY BINDING (write side): the plan being persisted
    /// must carry the deployment id of the key it is written under — a plan
    /// whose embedded `deployment_id` differs from `id` is refused with an
    /// integrity error naming both ids, never persisted.
    pub fn write_plan(&self, id: &DeploymentId, plan: &DeploymentPlan) -> Result<()> {
        if plan.deployment_id() != id {
            return Err(Error::integrity(format!(
                "refusing to write a plan declaring deployment_id {} under key {} at {}: the plan's embedded identity does not match its storage key",
                plan.deployment_id(),
                id.as_str(),
                self.deployment_dir(id).join("plan.json").display()
            )));
        }
        let dir = self.deployment_dir(id);
        ensure_private_dir(&dir)?;
        let bytes = serde_json::to_vec_pretty(plan)
            .map_err(|e| Error::store(format!("serialize plan: {e}")))?;
        write_atomic_cas(&dir.join("plan.json"), &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{
        ArtifactRef, SlotId, TargetName, VariantName, test_deployment_id, test_generation_id,
        test_release_id, test_tree_digest,
    };
    use crate::ledger::{BehaviorIndex, PlanOrigin, SlotPlan};
    use std::collections::BTreeMap;

    /// A minimal valid plan for one slot (empty behavior index, HEAD
    /// origin), carrying the given deployment id and target.
    fn plan(id: &DeploymentId, target: &str) -> DeploymentPlan {
        let slot = SlotId::parse("p1").unwrap();
        let mut slots = BTreeMap::new();
        slots.insert(
            slot.clone(),
            SlotPlan {
                slot_id: slot,
                artifact: ArtifactRef {
                    release: test_release_id("r"),
                    variant: VariantName::parse("standard").unwrap(),
                    tree: test_tree_digest("t"),
                },
                expected_generation: Some(test_generation_id("g")),
            },
        );
        DeploymentPlan::new(
            id.clone(),
            TargetName::parse(target).unwrap(),
            BehaviorIndex::new(),
            slots,
            PlanOrigin::Head,
        )
    }

    /// A recorded plan is immutable: deployment IDs are unique, so a
    /// same-ID rewrite with different content is corruption.
    #[test]
    fn recorded_plan_is_immutable() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let id = test_deployment_id("deploy-1");
        store
            .write_plan(&id, &plan(&id, "t1"))
            .expect("first plan write");
        store
            .write_plan(&id, &plan(&id, "t1"))
            .expect("identical rewrite is idempotent");
        let err = store
            .write_plan(&id, &plan(&id, "t2"))
            .expect_err("conflicting plan rewrite must fail");
        assert!(err.to_string().contains("different content"));
    }

    /// THE EMBEDDED-IDENTITY BINDING (write side): a plan whose embedded
    /// deployment id differs from the key it is written under is refused
    /// with an integrity error naming both ids — never persisted.
    #[test]
    fn write_plan_refuses_a_mismatched_embedded_identity() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let id = test_deployment_id("deploy-1");
        let other = test_deployment_id("deploy-2");
        let err = store
            .write_plan(&other, &plan(&id, "t1"))
            .expect_err("a plan whose embedded deployment id differs from the key must be refused");
        assert!(
            err.to_string().contains("does not match its storage key"),
            "the refusal must name the identity binding, got: {err}"
        );
        assert!(
            !store.deployment_dir(&other).join("plan.json").exists(),
            "a refused plan must never be persisted"
        );
    }
}
