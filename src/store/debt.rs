//! Durable debt markers (A4/A7): the per-target deferred-retention marker
//! (`targets/<target>/retention-debt.json`) and the store-global sweep
//! marker (`sweep-debt.json`), both with tri-state read semantics.

use crate::error::{Error, Result};
use crate::store::atomic::{path_state, read_json};
use crate::store::local::{LocalStore, write_json};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[cfg(test)]
use crate::testutil::test_faults::FaultKind;

impl LocalStore {
    // ---- retention maintenance debt ---------------------------------------

    /// Path of the target's deferred-retention debt marker file.
    ///
    /// Retention is POST-COMMIT maintenance: a retention failure after the
    /// deployment already committed must not change the reported outcome.
    /// Instead the failure is recorded here — keyed by target (the file's
    /// location under `targets/<target>/`) and by placement slot (the map
    /// key) — so later pushes retry the maintenance and clear the marker
    /// once the retention succeeds. The marker is intentionally a separate,
    /// small record: it does not ride along in `observed.json` (which
    /// describes the deployed state, not pending controller work) and it
    /// survives across pushes.
    pub fn retention_debt_path(&self, target: &str) -> PathBuf {
        self.target_dir(target).join("retention-debt.json")
    }

    /// Read the target's deferred-retention markers: a map of placement slot
    /// id to the reason the retention was deferred. Empty when no maintenance
    /// is pending.
    pub fn read_retention_debt(&self, target: &str) -> Result<BTreeMap<String, String>> {
        // Post-commit maintenance fault injection, keyed by target (the debt
        // file lives under `targets/<target>/`). Absorbs the debt-I/O
        // sibling agent's `arm_read_retention_debt`.
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::ReadRetentionDebt, target)
        {
            return Err(Error::store(
                "test fault: read_retention_debt forced to fail once",
            ));
        }
        let p = self.retention_debt_path(target);
        // Tri-state: only a genuine NotFound is "no maintenance debt" (the
        // empty map); a stat failure propagates as a Store error (an
        // unreadable debt marker must not read as "no debt").
        if path_state(&p)? {
            read_json(&p)
        } else {
            Ok(BTreeMap::new())
        }
    }

    /// Persist the target's deferred-retention markers. An EMPTY map removes
    /// the marker file, so a fully-serviced target leaves no trace.
    pub fn write_retention_debt(
        &self,
        target: &str,
        debt: &BTreeMap<String, String>,
    ) -> Result<()> {
        // Post-commit maintenance write fault, keyed by target. Absorbs the
        // debt-I/O sibling agent's `arm_write_retention_debt`.
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::WriteRetentionDebt, target)
        {
            return Err(Error::store(
                "test fault: write_retention_debt forced to fail once",
            ));
        }
        let p = self.retention_debt_path(target);
        if debt.is_empty() {
            // Tri-state removal decision: a genuine NotFound is nothing to
            // remove; any other stat error propagates (an unreadable marker
            // must not silently survive as a stale "debt" record).
            if path_state(&p)? {
                std::fs::remove_file(&p).map_err(|e| {
                    Error::store(format!("remove retention debt {}: {e}", p.display()))
                })?;
            }
            return Ok(());
        }
        write_json(&p, debt)
    }

    // ---- the store-global sweep debt (checkpoint sweep maintenance) ------

    /// Path of the store-global sweep-debt marker (`<base>/sweep-debt.json`).
    /// The checkpoint's best-effort GLOBAL sweep is POST-COMMIT maintenance:
    /// an incomplete sweep records a durable marker here (the reason the
    /// sweep did not complete) so the NEXT PUSH — not just the next
    /// checkpoint — retries the sweep (recomputing reachability fresh, no
    /// persisted deletion worklist) and clears the marker once it completes.
    /// The marker is store-global because the sweep is global: release
    /// records and tree objects are content-addressed and shared across
    /// targets, so a pending sweep is a property of the whole store, not of
    /// one target's ledger.
    pub fn sweep_debt_path(&self) -> PathBuf {
        self.base.join("sweep-debt.json")
    }

    /// Read the store-global sweep-debt marker: `Some(reason)` when a sweep
    /// is pending, `None` when no maintenance is outstanding. Tri-state:
    /// only a genuine NotFound is "no debt"; a stat failure propagates (an
    /// unreadable marker must not read as "no debt").
    pub fn read_sweep_debt(&self) -> Result<Option<String>> {
        // Post-commit maintenance fault injection, keyed by the empty global
        // key (the sweep debt is store-global, not target-keyed).
        #[cfg(test)]
        if self.fault_registry.consume(FaultKind::ReadSweepDebt, "") {
            return Err(Error::store(
                "test fault: read_sweep_debt forced to fail once",
            ));
        }
        let p = self.sweep_debt_path();
        if path_state(&p)? {
            let v: serde_json::Value = read_json(&p)?;
            Ok(v.get("reason").and_then(|r| r.as_str()).map(str::to_string))
        } else {
            Ok(None)
        }
    }

    /// Persist (or clear) the store-global sweep-debt marker. `None` removes
    /// the marker file, so a fully-serviced store leaves no trace.
    pub fn write_sweep_debt(&self, reason: Option<&str>) -> Result<()> {
        // Post-commit maintenance write fault, keyed by the empty global key.
        #[cfg(test)]
        if self.fault_registry.consume(FaultKind::WriteSweepDebt, "") {
            return Err(Error::store(
                "test fault: write_sweep_debt forced to fail once",
            ));
        }
        let p = self.sweep_debt_path();
        match reason {
            None => {
                // Tri-state removal decision: a genuine NotFound is nothing
                // to remove; any other stat error propagates (an unreadable
                // marker must not silently survive as a stale "debt" record).
                if path_state(&p)? {
                    std::fs::remove_file(&p).map_err(|e| {
                        Error::store(format!("remove sweep debt {}: {e}", p.display()))
                    })?;
                }
                Ok(())
            }
            Some(r) => write_json(&p, &serde_json::json!({ "reason": r })),
        }
    }
}
