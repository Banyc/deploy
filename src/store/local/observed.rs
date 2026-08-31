//! Observed-state I/O: the ONE physical observed record per placement slot
//! (`slots/<slot-id>/observed.json`), the target selection view over the
//! global slot map, and the per-server records (`servers/<id>.json`).

use crate::error::{Error, Result};
use crate::identity::{ServerId, SlotId, TargetName};
use crate::ledger::{ObservedSlot, ObservedTarget, ServerState};
use crate::store::atomic::path_state;
use crate::store::local::{LocalStore, read_keyed_json};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[cfg(test)]
use crate::ledger::ObservedAssignment;
#[cfg(test)]
use crate::store::atomic::ReplaceStage;
#[cfg(test)]
use crate::testutil::test_faults::FaultKind;

/// TEST-ONLY: the per-stage fault kinds of a slot-observed record's atomic
/// replacement (keyed by the slot id), mirroring the checkpoint's
/// [`FaultKind::LedgerReplace*`] stage pattern.
#[cfg(test)]
fn observed_replace_kind(stage: ReplaceStage) -> FaultKind {
    match stage {
        ReplaceStage::Write => FaultKind::ObservedReplaceWrite,
        ReplaceStage::Sync => FaultKind::ObservedReplaceSync,
        ReplaceStage::Rename => FaultKind::ObservedReplaceRename,
        ReplaceStage::DirSync => FaultKind::ObservedReplaceDirSync,
    }
}

/// TEST-ONLY: the per-stage fault kinds of a server record's atomic
/// replacement (keyed by the server id).
#[cfg(test)]
fn server_replace_kind(stage: ReplaceStage) -> FaultKind {
    match stage {
        ReplaceStage::Write => FaultKind::ServerReplaceWrite,
        ReplaceStage::Sync => FaultKind::ServerReplaceSync,
        ReplaceStage::Rename => FaultKind::ServerReplaceRename,
        ReplaceStage::DirSync => FaultKind::ServerReplaceDirSync,
    }
}

impl LocalStore {
    // ---- slots: the ONE physical observed state ---------------------------

    /// Path of a placement slot's single physical observed record
    /// (`slots/<slot-id>/observed.json`). Observed state is stored EXACTLY
    /// ONCE per placement slot — never replicated per target: targets are
    /// selection views over the global slot map (see
    /// [`LocalStore::read_observed`]).
    ///
    /// THE SLOT ID IS STORED VERBATIM: the validated `SlotId` grammar is a
    /// single filesystem-safe ASCII segment (the shared identity-name rule),
    /// so no re-encoding is needed and two distinct slot ids ALWAYS map to
    /// two distinct slot directories (injective by construction).
    pub fn slot_observed_path(&self, slot: &SlotId) -> PathBuf {
        self.base
            .join("slots")
            .join(slot.as_str())
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
    pub(crate) fn write_slot_observed(&self, slot: &SlotId, observed: &ObservedSlot) -> Result<()> {
        #[cfg(test)]
        if let Some(d) = match &observed.assignment {
            ObservedAssignment::Known {
                last_deployment, ..
            } => Some(last_deployment.as_str()),
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
        // THE EMBEDDED-IDENTITY BINDING (write side): the record being
        // persisted must carry the slot id of the key it is written under —
        // a record whose embedded slot id differs from `slot` is refused
        // with an integrity error naming both identities, never persisted.
        let dir = p.parent().ok_or_else(|| {
            Error::store(format!(
                "slot observed record {} has no parent directory",
                p.display()
            ))
        })?;
        self.ensure_private_dir_at(dir)?;
        // The mutable observed record is replaced ATOMICALLY (temp + fsync +
        // chmod + rename + parent-dir fsync — see [`LocalStore::write_json`]), so a
        // crash never leaves a torn record: the slot reads wholly-old or
        // wholly-new. The test seam faults each replacement stage from the
        // fixture's OWN registry (keyed by the slot id), so the
        // crash-consistency property can force every stage.
        #[cfg(test)]
        {
            let mut hook = self.replace_stage_hook(slot.as_str(), observed_replace_kind);
            self.write_keyed_json(&p, slot.as_str(), observed, |o| o.slot.as_str(), &mut hook)
        }
        #[cfg(not(test))]
        self.write_keyed_json(&p, slot.as_str(), observed, |o| o.slot.as_str())
    }

    /// Read one placement slot's physical observed record. `None` when the
    /// slot has never been observed (or its record was removed). Tri-state:
    /// only a genuine NotFound is "no observed record"; a stat failure
    /// propagates as a Store error (a permission error on the record must
    /// not read as "never observed").
    ///
    /// THE EMBEDDED-IDENTITY BINDING (read side): the stored record's own
    /// slot id must equal the requested `slot` (the path key) — a record
    /// swapped into the wrong slot directory is refused with an integrity
    /// error naming both identities, never returned as if it were `slot`.
    pub fn read_slot_observed(&self, slot: &SlotId) -> Result<Option<ObservedSlot>> {
        let p = self.slot_observed_path(slot);
        if path_state(&p)? {
            read_keyed_json(&p, slot.as_str(), |o: &ObservedSlot| o.slot.as_str()).map(Some)
        } else {
            Ok(None)
        }
    }

    /// The GLOBAL physical slot map: every placement slot's single observed
    /// record (`slots/<slot-id>/observed.json`), keyed by [`SlotId`].
    /// This is the ONE physical state the per-target views are filtered
    /// from — a shared slot exists here exactly once.
    ///
    /// THE EMBEDDED-IDENTITY BINDING: each stored record's own slot id must
    /// equal the directory it was read from — a record swapped into the
    /// wrong slot directory is refused with an integrity error naming both
    /// identities, never silently keyed under the wrong slot.
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
            let observed: ObservedSlot = read_keyed_json(
                &rec,
                entry.file_name().to_string_lossy().as_ref(),
                |o: &ObservedSlot| o.slot.as_str(),
            )?;
            out.insert(observed.slot.clone(), observed);
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
        let target_name = TargetName::parse(target).map_err(|e| {
            Error::integrity(format!(
                "read_observed: target {target:?} is not a valid target name: {e}"
            ))
        })?;
        Ok(ObservedTarget {
            target: target_name,
            slots,
        })
    }

    // ---- servers ----------------------------------------------------------

    pub(crate) fn write_server(&self, state: &ServerState) -> Result<()> {
        // Post-commit observed-refresh fault injection, keyed by the recorded
        // deployment id AND target (see `write_slot_observed`).
        #[cfg(test)]
        if let (Some(deployment_id), Some(target)) = (
            state
                .last_observed
                .as_ref()
                .and_then(|o| match &o.assignment {
                    ObservedAssignment::Known {
                        last_deployment, ..
                    } => Some(last_deployment.as_str()),
                    _ => None,
                }),
            Some(&state.last_seen_target),
        ) && self.fault_registry.consume_target(
            FaultKind::WriteServer,
            deployment_id,
            target.as_str(),
        ) {
            return Err(Error::store("test fault: write_server forced to fail once"));
        }
        // THE EMBEDDED-IDENTITY BINDING (write side): the server record's
        // path is derived from its OWN embedded `id` — the storage key IS the
        // record's identity, so a mismatched write is structurally
        // unrepresentable (there is no separate key argument to disagree
        // with). The read side ([`LocalStore::read_server`]) verifies the
        // binding the other way: a record swapped into the wrong server file
        // is refused.
        let p = self
            .base
            .join("servers")
            .join(format!("{}.json", state.id.as_str()));
        // The mutable server record is replaced ATOMICALLY (see [`LocalStore::write_json`]);
        // the test seam faults each replacement stage keyed by the server id.
        #[cfg(test)]
        {
            let mut hook = self.replace_stage_hook(state.id.as_str(), server_replace_kind);
            self.write_keyed_json(&p, state.id.as_str(), state, |s| s.id.as_str(), &mut hook)
        }
        #[cfg(not(test))]
        self.write_keyed_json(&p, state.id.as_str(), state, |s| s.id.as_str())
    }

    /// Read a server's local record by its typed [`ServerId`] (the storage
    /// key — `servers/<id>.json`, stored VERBATIM: distinct server ids
    /// always map to distinct files).
    ///
    /// THE EMBEDDED-IDENTITY BINDING (read side): the stored record's own
    /// `id` must equal the requested `id` (the path key) — a record swapped
    /// into the wrong server file is refused with an integrity error naming
    /// both identities, never returned as if it were `id`.
    pub fn read_server(&self, id: &ServerId) -> Result<ServerState> {
        let p = self
            .base
            .join("servers")
            .join(format!("{}.json", id.as_str()));
        read_keyed_json(&p, id.as_str(), |s: &ServerState| s.id.as_str())
    }

    pub fn server_exists(&self, id: &ServerId) -> bool {
        self.base
            .join("servers")
            .join(format!("{}.json", id.as_str()))
            .exists()
    }
}
