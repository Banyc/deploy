//! Rollout-group selection semantics (A1 deployment semantics).
//!
//! The branch-agnostic {target, group} selection
//! ([`SlotSelection`]), normalized once near command entry and resolved PER
//! REFERENCE BRANCH against that branch's declared temporal source: HEAD and
//! deployment references resolve the selected slots from the CURRENT config's
//! group declarations ([`SlotSelection::current_members`]), a `release:<id>`
//! reference from the RELEASE's FROZEN per-slot groups rebound onto the
//! current physical slots ([`SlotSelection::release_members`] — the frozen
//! partition governs, so a group named only in the frozen topology still
//! resolves). Also owns the DIRECT-RELEASE MEMBERSHIP GATE
//! ([`validate_direct_release_membership`]): a `release:<id>` push deploys
//! onto the CURRENT target's slots, so the release's frozen slot set must
//! EXACTLY equal the target's current membership — refused before any lock
//! or remote access. Extracted from the old `push::plan`.

use crate::config::ProjectConfig;
use crate::error::{Error, Result};
use crate::identity::{MatchingMembership, ReleaseId, ReleaseRecord, SlotId, SlotSet, TargetName};

/// The NORMALIZED selection of one push/status invocation: the owning target
/// and the optional rollout group. Normalized once near command entry as the
/// branch-agnostic {target, group} pair — the selection deliberately does
/// NOT resolve slot IDs from the caller's current configuration. Each
/// reference branch resolves the selected slot IDs against ITS OWN declared
/// temporal source ([`crate::deploy::plan::plan_assignments`]): HEAD and deployment references
/// from the CURRENT config's group declarations, `release:<id>` from the
/// release record's FROZEN per-slot groups (rebound onto the current
/// physical slots). Planning, execution, reporting, and persistence consume
/// this selection plus the per-branch resolution instead of independently
/// filtering slots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotSelection {
    pub target: TargetName,
    /// The optional rollout group (`deploy push <target> --group <name>`).
    /// `None` selects every slot owned by the target.
    pub group: Option<String>,
}

impl SlotSelection {
    /// Normalize a target + optional group into the branch-agnostic
    /// selection: ONLY the owning target and the requested group, without
    /// resolving slot IDs from the caller's current configuration. Slot-ID
    /// resolution is deliberately deferred to each reference branch: the
    /// CURRENT group partition governs a HEAD push, while a `release:<id>`
    /// push must select from the RELEASE's FROZEN per-slot groups (a group
    /// named in the release's frozen topology but unknown in the current
    /// config still works — the frozen partition governs), so resolving the
    /// group against the current config here would both reject release-only
    /// groups and select the wrong slot IDs for a historical release whose
    /// frozen partition drifted. The target must exist in the current config
    /// (validated here, before any lock or remote access).
    pub fn normalize(config: &ProjectConfig, target: &str, group: Option<&str>) -> Result<Self> {
        config
            .target(target)
            .ok_or_else(|| Error::not_found(format!("target '{target}'")))?;
        Ok(SlotSelection {
            target: TargetName::parse(target).expect("target name is a safe segment"),
            group: group.map(str::to_string),
        })
    }

    /// The selected (slot, server) pairs resolved from the caller's CURRENT
    /// configuration — the declared temporal source for HEAD and deployment
    /// references, and the physical-rebinding half of a release reference
    /// (each frozen slot id looked up in the target's current member
    /// declarations). `None` selects every slot owned by the target; a group
    /// selects exactly the target's slots whose CURRENT `groups` list
    /// contains it (an unknown group, or a group selecting zero slots in the
    /// current config, is a configuration error — HEAD/deployment behavior,
    /// unchanged). Deterministic order: variants in name order, then each
    /// variant's slots in file order.
    pub fn current_members<'a>(
        &self,
        config: &'a ProjectConfig,
    ) -> Result<Vec<(&'a crate::config::SlotConfig, &'a crate::config::ServerDef)>> {
        match &self.group {
            Some(g) => config.target_group_slots(self.target.as_str(), g),
            None => config.target_slots(self.target.as_str()),
        }
    }

    /// The selected (slot, server) pairs for a DIRECT RELEASE reference: the
    /// group's slot IDs resolve from the RELEASE's FROZEN topology — each
    /// frozen [`crate::identity::CanonicalSlot`] in the record's own snapshot
    /// carries its era's `groups` list, so the frozen partition governs (a
    /// slot the release pushed inside the group but the current config moved
    /// OUT of it still belongs to this push; a group named only in the
    /// frozen topology — unknown in the current config — still resolves).
    /// The frozen IDs are then REBOUND onto their current physical locations
    /// (server / deploy_dir from the target's CURRENT member declarations) —
    /// composing with the explicit [`RebindingPlan`]'s frozen-topology →
    /// current-physical-slot record built in the `PushRef::Release` plan
    /// branch. Deterministic order follows the frozen snapshot: variants in
    /// name order, then each variant's slots in the canonical slot order.
    /// `None` selects every slot the release froze for the target; a group
    /// selecting zero frozen slots is a configuration error as today.
    pub fn release_members<'a>(
        &self,
        config: &'a ProjectConfig,
        rec: &ReleaseRecord,
    ) -> Result<Vec<(&'a crate::config::SlotConfig, &'a crate::config::ServerDef)>> {
        let frozen_ids: Vec<SlotId> = rec
            .slots
            .values()
            .flat_map(|cs| cs.slots.iter())
            .filter(|s| s.target == self.target.as_str())
            .filter(|s| match &self.group {
                Some(g) => s.groups.iter().any(|x| x == g),
                None => true,
            })
            .map(|s| SlotId::parse(s.id.as_str()).expect("validated slot id is a safe segment"))
            .collect();
        if self.group.is_some() && frozen_ids.is_empty() {
            return Err(Error::config(format!(
                "group '{}' selects no slots of target '{}' in the release's frozen topology",
                self.group.as_deref().unwrap_or(""),
                self.target
            )));
        }
        // Rebind the frozen slot IDs onto the CURRENT physical locations.
        // The direct-release membership gate (which the caller runs first)
        // guarantees the frozen slot-ID set equals the target's complete
        // current membership, so every frozen id has a current declaration.
        let all = config.target_slots(self.target.as_str())?;
        let mut out = Vec::with_capacity(frozen_ids.len());
        for id in &frozen_ids {
            out.push(
                all.iter()
                    .find(|(s, _)| s.id == id.as_str())
                    .copied()
                    .ok_or_else(|| {
                        Error::rollback(format!(
                            "release's frozen slot '{id}' is not declared by target '{}' today; \
                             membership drift is rejected before planning",
                            self.target
                        ))
                    })?,
            );
        }
        Ok(out)
    }
}

/// DIRECT-RELEASE MEMBERSHIP VALIDATION (before any remote access): a
/// `release:<id>` push deploys onto the CURRENT target's slots, so the
/// release's OWN canonical slot snapshot must freeze EXACTLY the slot-id set
/// the target currently has.
///
/// The expected set is the union over every variant in the record's snapshot
/// of the slots whose ONE owning `target` equals the destination target
/// (each slot has exactly one target, so the union is deduplicated by slot
/// id; the membership is a set). The comparison is LOGICAL membership only:
/// physical bindings (server / deploy_dir) are intentionally allowed to
/// differ — unlike the exact-rollback `Snapshot` branch, which also demands
/// identical physical bindings. A target whose membership DRIFTED since the
/// release was built — a slot added, removed, or renamed — is refused, before
/// any assignment is built and before any remote access, rather than
/// deploying to the wrong slot set.
///
/// Runs at TWO sites: the engine's early gate in `push()` — immediately
/// after the ref is parsed/resolved, BEFORE any lock and BEFORE the remote
/// factory is invoked, in both real and dry-run modes — and here, in the
/// `PushRef::Release` plan branch (the second line of defense protecting the
/// direct-`push_inner` test entry points). `current_slot_ids` is the target's
/// CURRENT member slot-id set, derived from the caller's config exactly as
/// [`crate::deploy::plan::plan_assignments`] derives it (`config.target_slots`, in deterministic
/// order), so both gates compare the SAME sets.
///
/// BOTH call sites pass the target's COMPLETE current member-slot set —
/// EVERY slot whose owning `target` equals the target — never a
/// group-filtered selection: a `release:<id> --group <g>` push validates
/// the FULL membership here and then plans ONLY the selected slots (the
/// group narrows the planned assignments, never the membership gate). A
/// `--group` push selecting a proper subset would otherwise compare the
/// release's full frozen set against the subset and fail for every proper
/// group.
pub(crate) fn validate_direct_release_membership(
    target_name: &str,
    release: &ReleaseId,
    rec: &ReleaseRecord,
    current_slot_ids: &[SlotId],
) -> Result<MatchingMembership> {
    let frozen: SlotSet = SlotSet::new(
        rec.slots
            .values()
            .flat_map(|cs| cs.slots.iter())
            .filter(|s| s.target == target_name)
            .map(|s| SlotId::parse(s.id.as_str()).expect("validated slot id is a safe segment")),
    );
    let current: SlotSet = SlotSet::new(current_slot_ids.iter().cloned());
    MatchingMembership::verify(frozen.clone(), current.clone()).map_err(|_| {
        let expected: Vec<String> = frozen.iter().map(|s| s.as_str().to_string()).collect();
        let current_list: Vec<String> = current.iter().map(|s| s.as_str().to_string()).collect();
        Error::rollback(format!(
            "release {release} targets slots [{}] but target '{target_name}' currently has [{}]; direct release membership drift is rejected before remote access",
            expected.join(", "),
            current_list.join(", "),
        ))
    })
}
