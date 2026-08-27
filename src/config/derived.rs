//! The DERIVED views of the validated graph: everything a caller asks a
//! [`ProjectConfig`] to RESOLVE rather than to store. Slot membership is
//! never stored on targets — a target's member slots are DERIVED by
//! scanning every variant's `[[slots]]` declarations for the target name —
//! and a slot's owning variant (the file that declares it) is its SINGLE
//! source for retention and its slot-variant binding. These read-only
//! resolutions ([`ProjectConfig::slot_defs`], [`ProjectConfig::slot_variant`],
//! [`ProjectConfig::slot_retention`], [`ProjectConfig::target_slots`],
//! [`ProjectConfig::target_group_slots`], [`ProjectConfig::target_slot_ids`],
//! [`ProjectConfig::target_slot_bindings`]) live here, away from the graph
//! record itself.

use crate::config::domain::ProjectConfig;
use crate::config::retention::RetentionConfig;
use crate::config::servers::ServerDef;
use crate::config::slots::SlotConfig;
use crate::error::{Error, Result};
use crate::identity::{ServerId, SlotId};
use crate::ledger::PhysicalBinding;
use std::collections::BTreeMap;

impl ProjectConfig {
    /// The aggregated slot declarations of every variant: each variant's
    /// `[[slots]]` entries in deterministic order — variants in name order
    /// (the `BTreeMap` is already sorted), then each variant's slots in file
    /// order.
    pub fn slot_defs(&self) -> Vec<&SlotConfig> {
        self.variants
            .values()
            .flat_map(|v| v.slots.iter())
            .collect()
    }

    /// The variant whose file declares the given slot: slots are declared
    /// inside a variant's file, so the declaring file IS the slot's variant
    /// binding.
    pub fn slot_variant(&self, slot_id: &str) -> Result<&str> {
        for (name, variant) in &self.variants {
            if variant.slots.iter().any(|s| s.id == slot_id) {
                return Ok(name);
            }
        }
        Err(Error::config(format!(
            "slot '{slot_id}' is not declared by any variant"
        )))
    }

    /// The slot's ONE retention policy: the retention config of the slot's
    /// OWNING VARIANT (the file that declares the slot). Retention is
    /// slot-owned — a shared slot's policy is resolved here, from a single
    /// source, regardless of how many targets the slot is a member of, so
    /// membership changes never change retention.
    pub fn slot_retention(&self, slot_id: &str) -> Result<&RetentionConfig> {
        let variant_name = self.slot_variant(slot_id)?;
        Ok(&self.variant(variant_name)?.retention)
    }

    /// Resolve a target's member slots, pairing each slot with its declared
    /// server. Membership is DERIVED from the slots' declared `target` field
    /// (targets do not list their slots): every slot whose ONE owning
    /// `target` equals `target_name`, in deterministic order — variants in
    /// name order, then each variant's slots in file order.
    pub fn target_slots(&self, target_name: &str) -> Result<Vec<(&SlotConfig, &ServerDef)>> {
        self.targets
            .get(target_name)
            .ok_or_else(|| Error::not_found(format!("target '{target_name}'")))?;
        let mut out = Vec::new();
        for slot in self.slot_defs() {
            if slot.target != target_name {
                continue;
            }
            let server = self
                .servers
                .iter()
                .find(|s| s.id.as_str() == slot.server)
                .ok_or_else(|| {
                    Error::config(format!(
                        "slot '{}' references unknown server '{}'",
                        slot.id, slot.server
                    ))
                })?;
            out.push((slot, server));
        }
        Ok(out)
    }

    /// Resolve the slots of `target_name` selected by a rollout group: every
    /// slot whose ONE owning `target` equals `target_name` AND whose `groups`
    /// list contains `group`, in the same deterministic order as
    /// [`ProjectConfig::target_slots`]. An unknown group, or a group selecting zero
    /// slots, is a configuration error (the caller's current configuration is
    /// the selection source, including for historical references).
    pub fn target_group_slots(
        &self,
        target_name: &str,
        group: &str,
    ) -> Result<Vec<(&SlotConfig, &ServerDef)>> {
        let all = self.target_slots(target_name)?;
        let selected: Vec<(&SlotConfig, &ServerDef)> = all
            .into_iter()
            .filter(|(slot, _)| slot.groups.iter().any(|g| g == group))
            .collect();
        if selected.is_empty() {
            return Err(Error::config(format!(
                "group '{group}' selects no slots of target '{target_name}'"
            )));
        }
        Ok(selected)
    }

    /// The slot IDs of a target's members, in the same deterministic order as
    /// [`ProjectConfig::target_slots`].
    pub fn target_slot_ids(&self, target_name: &str) -> Result<Vec<String>> {
        Ok(self
            .target_slots(target_name)?
            .into_iter()
            .map(|(slot, _)| slot.id.clone())
            .collect())
    }

    /// The slot→physical-binding map for a target, keyed by placement slot
    /// ID: the complete `{server, deploy_dir}` binding ([`PhysicalBinding`])
    /// each slot currently has in the configuration — the physical server
    /// AND the absolute on-server directory its deployment state lives in.
    /// Used to record (and later verify) the exact physical location a
    /// deployment snapshot's slots were deployed onto: exact rollback must
    /// see BOTH halves unchanged, because a slot that keeps its server but
    /// moves its `deploy_dir` would otherwise roll back onto the new
    /// location.
    pub fn target_slot_bindings(
        &self,
        target_name: &str,
    ) -> Result<BTreeMap<SlotId, PhysicalBinding>> {
        Ok(self
            .target_slots(target_name)?
            .into_iter()
            .map(|(slot, server)| {
                (
                    SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment"),
                    PhysicalBinding {
                        server: ServerId::parse(server.id.as_str())
                            .expect("validated server id is a safe segment"),
                        deploy_dir: slot.deploy_dir().to_string_lossy().into_owned(),
                    },
                )
            })
            .collect())
    }
}
