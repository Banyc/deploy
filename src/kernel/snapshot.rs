//! THE SNAPSHOT FACET of the semantic kernel (feature area: the pure
//! deployment semantic kernel) — the per-slot RESULT fact ([`SnapshotSlot`])
//! and the DERIVED SNAPSHOT VIEWS.
//!
//! ONE FACT, ONE OWNER: the deployment intent's slot table
//! ([`crate::kernel::intent::DeploymentIntent`]) carries each slot's
//! [`SnapshotSlot`] ONCE (the plan-minted generation + artifact + physical
//! binding). The complete resulting snapshot
//! ([`crate::kernel::intent::DeploymentIntent::resulting_snapshot`]) is a
//! DERIVED VIEW over that table — map each slot to its `result` — never a
//! second stored fact. A successful deployment's snapshot IS
//! `entry.intent.resulting_snapshot()` ([`resolve_snapshot`]): the terminal
//! event carries no duplicated payload (its `intent_digest` binds it to the
//! exact canonical intent), so there is exactly ONE stored copy of every
//! snapshot fact.
//!
//! [`PreviousGeneration`] is the KNOWN prior state of a slot recorded in a
//! `Deploy` action's pre-push observation: the generation the slot ran and
//! the artifact bound to it, as observed before mutation.

use crate::identity::{ArtifactRef, GenerationId, PlacementSlotAssignment, SlotId};
use crate::ledger::TargetSnapshot;
use std::collections::BTreeMap;

/// The per-slot RESULT fact of a deployment intent: the generation that
/// slot ends on, the artifact bound to it, and the physical binding it was
/// planned against. Exactly the per-slot facts a snapshot view needs —
/// stored ONCE in the intent's slot table and never duplicated in any
/// terminal payload. This is the ledger's [`SnapshotEntry`] (the alias
/// keeps the record-name path resolving).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotSlot {
    generation: GenerationId,
    artifact: ArtifactRef,
    binding: crate::ledger::PhysicalBinding,
}

impl SnapshotSlot {
    pub fn new(
        generation: GenerationId,
        artifact: ArtifactRef,
        binding: crate::ledger::PhysicalBinding,
    ) -> Self {
        Self {
            generation,
            artifact,
            binding,
        }
    }
    pub fn generation(&self) -> &GenerationId {
        &self.generation
    }
    pub fn artifact(&self) -> &ArtifactRef {
        &self.artifact
    }
    pub fn binding(&self) -> &crate::ledger::PhysicalBinding {
        &self.binding
    }
    /// The canonical per-slot assignment naming this slot: its generation
    /// bound to its artifact at its placement slot.
    pub fn assignment(&self, slot: &SlotId) -> PlacementSlotAssignment {
        PlacementSlotAssignment {
            placement_slot: slot.clone(),
            artifact: self.artifact.clone(),
        }
    }
}

/// The KNOWN prior state of a slot before a `Deploy` action: the generation
/// it ran and the artifact bound to it, as observed before mutation. The
/// pre-push observation carries this inside its `Known` half.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviousGeneration {
    pub generation: GenerationId,
    pub artifact: ArtifactRef,
}

/// THE SNAPSHOT RESOLUTION RULE (section 2 of the semantic-kernel pass): a
/// successful deployment's resulting snapshot IS the intent's planned
/// result — a DERIVED VIEW of the intent's slot table, resolved on demand,
/// never stored in any terminal payload. A deployment that is not
/// terminal-successful has NO snapshot: resolving it is an integrity error
/// (its deployment id never resolves as a rollback key — there is no
/// `SnapshotId`; the successful deployment id IS the snapshot identifier).
pub fn resolve_snapshot(
    entry: &crate::ledger::LedgerEntry,
) -> crate::kernel::error::KernelResult<TargetSnapshot> {
    use crate::kernel::terminal::TerminalDisposition;
    match entry.terminal.as_ref().map(|t| t.disposition()) {
        Some(TerminalDisposition::Successful) => Ok(entry.intent.resulting_snapshot()),
        _ => Err(crate::kernel::error::KernelError::Integrity(
            crate::kernel::error::IntegrityError::Message(format!(
                "deployment '{}' of target '{}' is not successful — only a successful deployment carries a resolving snapshot",
                entry.deployment_id, entry.target
            )),
        )),
    }
}

/// Build the derived resulting snapshot VIEW over a slot table: map every
/// slot to its planned result. The facts live in the slots; the snapshot is
/// derived on demand and never stored.
pub(crate) fn snapshot_from_slots<I>(slots: I) -> TargetSnapshot
where
    I: IntoIterator<Item = (SlotId, SnapshotSlot)>,
{
    let entries: BTreeMap<SlotId, crate::ledger::records::SnapshotEntry> =
        slots.into_iter().collect();
    TargetSnapshot::from_entries(entries)
}
