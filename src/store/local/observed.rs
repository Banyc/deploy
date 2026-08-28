//! Observed-state I/O: the ONE physical observed record per placement slot
//! (`slots/<slot-id>/observed.json`), the target selection view over the
//! global slot map, and the per-server records (`servers/<id>.json`).

use crate::error::{Error, Result};
use crate::identity::SlotId;
use crate::ledger::{ObservedSlot, ObservedTarget, ServerState};
use crate::store::atomic::{ensure_private_dir, path_state, read_json};
use crate::store::local::{LocalStore, sanitize, write_json};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[cfg(test)]
use crate::ledger::ObservedAssignment;
#[cfg(test)]
use crate::testutil::test_faults::FaultKind;

impl LocalStore {
    // ---- slots: the ONE physical observed state ---------------------------

    /// Path of a placement slot's single physical observed record
    /// (`slots/<slot-id>/observed.json`). Observed state is stored EXACTLY
    /// ONCE per placement slot — never replicated per target: targets are
    /// selection views over the global slot map (see
    /// [`LocalStore::read_observed`]).
    pub fn slot_observed_path(&self, slot: &SlotId) -> PathBuf {
        self.base
            .join("slots")
            .join(sanitize(slot.as_str()))
            .join("observed.json")
    }

    /// Write ONE placement slot's physical observed state. The engine's
    /// post-commit observed-refresh writes each advanced slot EXACTLY ONCE
    /// (never once per member target), so a slot shared across several
    /// targets has a single record and every target's view of it agrees with
    /// the physical record by construction.
    ///
    /// Post-commit observed-refresh fault injection: the observed refresh
    /// runs AFTER the deployment is durably committed, so a fault here is
    /// reported as a maintenance warning by the engine, never a push error.
    /// The fault is keyed by (deployment id, SLOT id) — one write selects
    /// exactly one slot's physical record.
    pub fn write_slot_observed(&self, slot: &SlotId, observed: &ObservedSlot) -> Result<()> {
        #[cfg(test)]
        if let Some(d) = match &observed.assignment {
            ObservedAssignment::Known { .. } => {
                observed.last_deployment.as_ref().map(|d| d.as_str())
            }
            _ => None,
        } && self
            .fault_registry
            .consume_target(FaultKind::WriteObserved, d, slot.as_str())
        {
            return Err(Error::store(
                "test fault: write_slot_observed forced to fail once",
            ));
        }
        let p = self.slot_observed_path(slot);
        let dir = p
            .parent()
            .expect("a slot observed record always sits inside a slot directory");
        ensure_private_dir(dir)?;
        write_json(&p, observed)
    }

    /// Read one placement slot's physical observed record. `None` when the
    /// slot has never been observed (or its record was removed). Tri-state:
    /// only a genuine NotFound is "no observed record"; a stat failure
    /// propagates as a Store error (a permission error on the record must
    /// not read as "never observed").
    pub fn read_slot_observed(&self, slot: &SlotId) -> Result<Option<ObservedSlot>> {
        let p = self.slot_observed_path(slot);
        if path_state(&p)? {
            read_json(&p).map(Some)
        } else {
            Ok(None)
        }
    }

    /// The GLOBAL physical slot map: every placement slot's single observed
    /// record (`slots/<slot-id>/observed.json`), keyed by [`SlotId`].
    /// This is the ONE physical state the per-target views are filtered
    /// from — a shared slot exists here exactly once.
    pub fn read_global_observed(&self) -> Result<BTreeMap<SlotId, ObservedSlot>> {
        let root = self.base.join("slots");
        let mut out = BTreeMap::new();
        let entries = match std::fs::read_dir(&root) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(Error::store(format!("read slots {}: {e}", root.display()))),
        };
        for entry in entries {
            let entry = entry.map_err(|e| Error::store(format!("read slots: {e}")))?;
            let rec = entry.path().join("observed.json");
            if !path_state(&rec)? {
                continue;
            }
            let observed: ObservedSlot = read_json(&rec)?;
            out.insert(
                SlotId::parse(&entry.file_name().to_string_lossy())
                    .expect("stored slot dir name is a safe segment"),
                observed,
            );
        }
        Ok(out)
    }

    /// The TARGET VIEW over the single physical slot state: the global slot
    /// map ([`LocalStore::read_global_observed`]) filtered to the target's
    /// member slots. Membership is DERIVED from the config's slot-declaration
    /// `target` field (as everywhere in the codebase): `deploy status
    /// <target>` and every other consumer see exactly the physical records of
    /// the target's member slots — never a replicated per-target copy. A
    /// slot has EXACTLY ONE owning target, so its single physical record
    /// serves exactly that target's view. A member slot with no physical
    /// record yet is simply absent from the view.
    pub fn read_observed(
        &self,
        target: &str,
        config: &crate::config::ProjectConfig,
    ) -> Result<ObservedTarget> {
        let members: std::collections::HashSet<&str> = config
            .slot_defs()
            .iter()
            .filter(|s| s.target == target)
            .map(|s| s.id.as_str())
            .collect();
        let slots = self
            .read_global_observed()?
            .into_iter()
            .filter(|(id, _)| members.contains(id.as_str()))
            .collect();
        Ok(ObservedTarget {
            target: crate::identity::TargetName::parse(target)
                .expect("target name is a safe segment"),
            slots,
        })
    }

    // ---- servers ----------------------------------------------------------

    pub fn write_server(&self, state: &ServerState) -> Result<()> {
        // Post-commit observed-refresh fault injection, keyed by the recorded
        // deployment id AND target (see `write_slot_observed`).
        #[cfg(test)]
        if let (Some(deployment_id), Some(target)) = (
            state
                .last_observed
                .as_ref()
                .and_then(|o| match &o.assignment {
                    ObservedAssignment::Known { .. } => {
                        o.last_deployment.as_ref().map(|d| d.as_str())
                    }
                    _ => None,
                }),
            state.last_seen_target.as_ref(),
        ) && self.fault_registry.consume_target(
            FaultKind::WriteServer,
            deployment_id,
            target.as_str(),
        ) {
            return Err(Error::store("test fault: write_server forced to fail once"));
        }
        let p = self
            .base
            .join("servers")
            .join(format!("{}.json", sanitize(state.id.as_str())));
        write_json(&p, state)
    }

    pub fn read_server(&self, id: &str) -> Result<ServerState> {
        let p = self
            .base
            .join("servers")
            .join(format!("{id}.json", id = sanitize(id)));
        read_json(&p)
    }

    pub fn server_exists(&self, id: &str) -> bool {
        self.base
            .join("servers")
            .join(format!("{}.json", sanitize(id)))
            .exists()
    }
}
