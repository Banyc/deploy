//! Durable debt markers (A4/A7): the per-target deferred-retention marker
//! (`targets/<target>/retention-debt.json`) and the store-global sweep
//! marker (`sweep-debt.json`), both with tri-state read semantics.

#[cfg(test)]
use crate::error::Error;
use crate::error::Result;
use crate::identity::{DeploymentId, TargetName};
use crate::store::atomic::{path_state, read_json};
use crate::store::local::{LocalStore, read_keyed_json};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[cfg(test)]
use crate::store::atomic::ReplaceStage;
#[cfg(test)]
use crate::testutil::test_faults::FaultKind;

/// THE TYPED, two-state store-global sweep-debt marker (`<base>/sweep-debt.json`).
/// The checkpoint's best-effort GLOBAL sweep is POST-COMMIT maintenance: an
/// incomplete sweep records a durable marker here so the NEXT PUSH — not
/// just the next checkpoint — retries the sweep (recomputing reachability
/// fresh, no persisted deletion worklist) and clears the marker once it
/// completes. The marker is store-global because the sweep is global:
/// release records and tree objects are content-addressed and shared across
/// targets, so a pending sweep is a property of the whole store, not of one
/// target's ledger.
///
/// THE MARKER IS TYPED (TWO STATES), never a free-form reason: the old
/// string-reasoned marker let a later maintenance/no-op push run the sweep
/// REGARDLESS of whether the triggering checkpoint's ledger replace was ever
/// made durable — a crash could restore an OLDER, longer ledger that still
/// references below-floor history already deleted by the sweep. The typed
/// marker makes the durability gate STRUCTURAL: the sweep runner refuses an
/// [`SweepDebt::AwaitingCheckpointDurability`] marker — running only the
/// durability-confirming rewrite first — and only a durably-rewritten ledger
/// ([`SweepDebt::Ready`]) may be swept. THE MARKER IS TRIAGE-ONLY: every
/// push (real and no-op) and checkpoint runs the sweep RECONCILIATION
/// regardless of any marker — the marker decides HOW the reconciliation
/// proceeds (Awaiting → confirm durability only; Ready → run the sweep
/// pass; missing → run the sweep pass), never WHETHER work is attempted. A
/// missing or failed marker write can therefore never cause the owed
/// maintenance to be skipped forever: the next push reconciles again
/// anyway.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SweepDebt {
    /// The triggering checkpoint's ledger replace is VISIBLE but its
    /// durability is UNCONFIRMED — the sweep must NOT run until the ledger
    /// is durably rewritten (`ReplacedDurable`), or a crash could restore an
    /// older ledger that still references already-deleted below-floor
    /// history.
    AwaitingCheckpointDurability {
        target: TargetName,
        retained_from: DeploymentId,
    },
    /// The checkpoint ledger rewrite is durable — the sweep may run.
    Ready {
        target: TargetName,
        retained_from: DeploymentId,
    },
}

/// THE DURABLE PER-TARGET RETENTION-DEBT MARKER (`targets/<target>/retention-debt.json`):
/// the target it belongs to (the storage key) bound to the per-slot
/// deferred-retention reasons. THE RECORD EMBEDS ITS OWN TARGET IDENTITY so
/// the store can verify the binding between the record and its storage key
/// on every read: a marker swapped into the wrong target's directory is
/// refused with an integrity error naming both targets, never returned as
/// the wrong target's debt.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionDebt {
    /// THE RECORD'S OWN TARGET IDENTITY — the storage key the marker is
    /// bound to (`targets/<target>/retention-debt.json`). The store verifies
    /// it equals the path key on every read.
    pub target: TargetName,
    /// The per-slot deferred-retention reasons (placement slot id → reason).
    pub debt: BTreeMap<String, String>,
}

/// TEST-ONLY: the per-stage fault kinds of a retention-debt marker's atomic
/// replacement (keyed by the target), mirroring the checkpoint's
/// [`FaultKind::LedgerReplace*`] stage pattern.
#[cfg(test)]
fn retention_debt_replace_kind(stage: ReplaceStage) -> FaultKind {
    match stage {
        ReplaceStage::Write => FaultKind::RetentionDebtReplaceWrite,
        ReplaceStage::Sync => FaultKind::RetentionDebtReplaceSync,
        ReplaceStage::Rename => FaultKind::RetentionDebtReplaceRename,
        ReplaceStage::DirSync => FaultKind::RetentionDebtReplaceDirSync,
    }
}

/// TEST-ONLY: the per-stage fault kinds of the store-global sweep-debt
/// marker's atomic replacement (keyed by the empty global key).
#[cfg(test)]
fn sweep_debt_replace_kind(stage: ReplaceStage) -> FaultKind {
    match stage {
        ReplaceStage::Write => FaultKind::SweepDebtReplaceWrite,
        ReplaceStage::Sync => FaultKind::SweepDebtReplaceSync,
        ReplaceStage::Rename => FaultKind::SweepDebtReplaceRename,
        ReplaceStage::DirSync => FaultKind::SweepDebtReplaceDirSync,
    }
}

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
    pub fn retention_debt_path(&self, target: &TargetName) -> PathBuf {
        self.target_dir(target.as_str()).join("retention-debt.json")
    }

    /// Read the target's deferred-retention markers: a map of placement slot
    /// id to the reason the retention was deferred. Empty when no maintenance
    /// is pending.
    ///
    /// THE EMBEDDED-IDENTITY BINDING (read side): the stored marker's own
    /// target must equal the requested `target` (the path key —
    /// `targets/<target>/retention-debt.json`) — a marker swapped into the
    /// wrong target's directory is refused with an integrity error naming
    /// both targets, never returned as the wrong target's debt.
    pub fn read_retention_debt(&self, target: &TargetName) -> Result<BTreeMap<String, String>> {
        // Post-commit maintenance fault injection, keyed by target (the debt
        // file lives under `targets/<target>/`). Absorbs the debt-I/O
        // sibling agent's `arm_read_retention_debt`.
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::ReadRetentionDebt, target.as_str())
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
            let rec: RetentionDebt =
                read_keyed_json(&p, target.as_str(), |r: &RetentionDebt| r.target.as_str())?;
            Ok(rec.debt)
        } else {
            Ok(BTreeMap::new())
        }
    }

    /// Persist the target's deferred-retention markers. An EMPTY map removes
    /// the marker file, so a fully-serviced target leaves no trace.
    ///
    /// THE EMBEDDED-IDENTITY BINDING (write side): the marker is persisted
    /// WITH its own target identity (the storage key it is written under),
    /// so a later read can verify the binding. The key IS the target
    /// argument — a mismatched write is structurally unrepresentable (the
    /// record is built from the key).
    pub fn write_retention_debt(
        &self,
        target: &TargetName,
        debt: &BTreeMap<String, String>,
    ) -> Result<()> {
        // Post-commit maintenance write fault, keyed by target. Absorbs the
        // debt-I/O sibling agent's `arm_write_retention_debt`.
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::WriteRetentionDebt, target.as_str())
        {
            return Err(Error::store(
                "test fault: write_retention_debt forced to fail once",
            ));
        }
        let p = self.retention_debt_path(target);
        if debt.is_empty() {
            // Tri-state removal decision: a genuine NotFound is nothing to
            // remove; any other stat error propagates (an unreadable marker
            // must not silently survive as a stale "debt" record). The
            // removal is made DURABLE before returning (a removal is a
            // directory-entry change; never report success while the entry
            // is unsynced).
            if path_state(&p)? {
                self.remove_file_at(&p)?;
                self.sync_parent_dir_at(&p)?;
            }
            return Ok(());
        }
        // The marker is persisted WITH its own target identity (the storage
        // key), replaced ATOMICALLY (see [`LocalStore::write_json`]); the test seam
        // faults each replacement stage keyed by the target.
        let rec = RetentionDebt {
            target: target.clone(),
            debt: debt.clone(),
        };
        #[cfg(test)]
        {
            let mut hook = self.replace_stage_hook(target.as_str(), retention_debt_replace_kind);
            self.write_keyed_json(&p, target.as_str(), &rec, |r| r.target.as_str(), &mut hook)
        }
        #[cfg(not(test))]
        self.write_keyed_json(&p, target.as_str(), &rec, |r| r.target.as_str())
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

    /// Read the store-global sweep-debt marker: `Some(SweepDebt)` when a
    /// sweep is pending (TYPED — the durability gate is structural), `None`
    /// when no maintenance is outstanding. Tri-state: only a genuine
    /// NotFound is "no debt"; a stat failure propagates (an unreadable
    /// marker must not read as "no debt"), and a MALFORMED marker fails
    /// closed as a Store error (a marker that cannot deserialize to the
    /// typed enum must never read as "no debt" or as a sweepable state).
    pub fn read_sweep_debt(&self) -> Result<Option<SweepDebt>> {
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
            read_json(&p)
        } else {
            Ok(None)
        }
    }

    /// Persist (or clear) the store-global sweep-debt marker. `None` removes
    /// the marker file, so a fully-serviced store leaves no trace; `Some`
    /// records the TYPED marker (the durability gate for the pending sweep).
    pub fn write_sweep_debt(&self, debt: Option<&SweepDebt>) -> Result<()> {
        // Post-commit maintenance write fault, keyed by the empty global key.
        #[cfg(test)]
        if self.fault_registry.consume(FaultKind::WriteSweepDebt, "") {
            return Err(Error::store(
                "test fault: write_sweep_debt forced to fail once",
            ));
        }
        let p = self.sweep_debt_path();
        match debt {
            None => {
                // Tri-state removal decision: a genuine NotFound is nothing
                // to remove; any other stat error propagates (an unreadable
                // marker must not silently survive as a stale "debt" record).
                // The removal is made DURABLE before returning (a removal is
                // a directory-entry change; never report success while the
                // entry is unsynced).
                if path_state(&p)? {
                    self.remove_file_at(&p)?;
                    self.sync_parent_dir_at(&p)?;
                }
                Ok(())
            }
            Some(d) => {
                // The mutable sweep-debt marker is replaced ATOMICALLY (see
                // [`LocalStore::write_json`]); the test seam faults each replacement
                // stage keyed by the empty global key.
                #[cfg(test)]
                {
                    let mut hook = self.replace_stage_hook("", sweep_debt_replace_kind);
                    self.write_json_seam(&p, d, &mut hook)
                }
                #[cfg(not(test))]
                self.write_json(&p, d)
            }
        }
    }
}
