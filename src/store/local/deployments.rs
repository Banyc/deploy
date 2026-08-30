//! Per-deployment plan records (A3 `deployments/<id>/`): the immutable
//! `plan.json` snapshot written via the create-or-compare CAS protocol.

use crate::error::{Error, Result};
use crate::store::atomic::ensure_private_dir;
use crate::store::local::{LocalStore, write_atomic_cas};
use serde::Serialize;
use std::path::PathBuf;

impl LocalStore {
    // ---- deployments ------------------------------------------------------

    /// The deployment plan directory (`deployments/<id>/`). The id is a
    /// validated deployment id (`deploy-<uuid-v7>` — a filesystem-safe ASCII
    /// string by the fixed grammar), stored VERBATIM: two distinct
    /// deployment ids always map to two distinct directories (injective by
    /// construction; no re-encoding, so no collision class).
    pub fn deployment_dir(&self, id: &str) -> PathBuf {
        self.base.join("deployments").join(id)
    }

    /// Write the recorded deployment plan (`deployments/<id>/plan.json`). The
    /// plan is the deployment's immutable plan artifact (deployment IDs are
    /// unique, so a conflicting same-ID rewrite is corruption and must fail
    /// rather than silently rewrite history). The outcomes and status of a
    /// deployment live in the LEDGER's terminal event, not here — this file
    /// is purely the plan snapshot the deployment was planned from (the
    /// checkpoint sweep deletes unreachable `deployments/<id>/` dirs).
    pub fn write_plan<T: Serialize>(&self, id: &str, plan: &T) -> Result<()> {
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
    /// A recorded plan is immutable: deployment IDs are unique, so a
    /// same-ID rewrite with different content is corruption.
    #[test]
    fn recorded_plan_is_immutable() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let plan = serde_json::json!({ "target": "t1" });
        store
            .write_plan("deploy-1", &plan)
            .expect("first plan write");
        store
            .write_plan("deploy-1", &plan)
            .expect("identical rewrite is idempotent");
        let err = store
            .write_plan("deploy-1", &serde_json::json!({ "target": "t2" }))
            .expect_err("conflicting plan rewrite must fail");
        assert!(err.to_string().contains("different content"));
    }
}
