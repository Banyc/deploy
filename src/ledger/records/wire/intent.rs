//! The INTENT records of the deployment ledger (feature area A2 "two line
//! kinds — intent"): the durable intent WIRE shape ([`LedgerIntentWire`])
//! and the in-memory push report ([`LedgerIntentReport`]).
//!
//! Since schema v10 the intent FREEZES the COMPLETE RESULT in ONE full slot
//! ROW ARRAY: `slots` carries every slot the resulting snapshot covers as
//! an ORDERED ARRAY OF ROWS ([`PlannedSlotRowWire`]), each row OWNING its
//! slot id and carrying its plan-minted RESULT ([`PlannedSlotWire`]) and
//! its ACTION ([`SlotActionWire`] — `Deploy` with the observed pre-push
//! state, or `Inherit`). The ROW ORDER is the DEPLOYMENT ORDER (the
//! domain's insertion order — never sorted by slot id), so the wire can
//! carry the exact order the user recorded. The full membership = the
//! rows' slot ids, the selected membership = the `Deploy` slots, and the
//! resulting snapshot = each row's `result` — the DOMAIN derives all of
//! them ([`crate::kernel::intent::DeploymentIntent`]); the wire carries NO
//! duplicated projection (no `desired`/`bindings`/`selected_membership`/
//! `full_membership`/`resulting_snapshot`) and NO object-keyed map (a JSON
//! object sorts its keys — order could never survive a round trip).
//!
//! The VERIFYING CONVERSION ([`LedgerIntentWire::into_domain`]) scalar-gates
//! every field, REFUSES A DUPLICATE SLOT ROW explicitly (the row fold
//! names the duplicate slot — ambiguous JSON is never last-wins), and
//! enforces the self-contained construction rules (at least one `Deploy`
//! slot; `group: None` → every slot `Deploy`) through the kernel's
//! validated domain constructor ([`crate::kernel::intent::from_wire`]);
//! the parent-congruence rules (inherited slots reproduce the parent's
//! snapshot entries) are validated at plan time and best-effort at read
//! where the parent entry is still resolvable. The row fold inserts each
//! row in FILE ORDER into the ordered domain table, so the round trip
//! `valid domain → wire → domain` is EXACTLY the original domain, order
//! included.

use crate::error::{Error, Result};
use crate::identity::{
    ArtifactRef, BehaviorDigest, DeploymentId, GenerationId, RolloutGroupName, SlotId, TargetName,
    Timestamp,
};
use crate::kernel;
use crate::kernel::intent::{DeploymentIntent, PlannedSlot, SlotAction};
use crate::kernel::snapshot::{PreviousGeneration, SnapshotSlot};
use crate::ledger::records::NonEmptySlotTable;
use crate::ledger::{ArtifactRefWire, ObservationWire, PhysicalBinding};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// THE STRICT WIRE PAYLOAD of one slot's plan-minted RESULT: generation +
/// artifact + physical binding, `deny_unknown_fields`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotSlotWire {
    pub generation: GenerationId,
    pub artifact: ArtifactRef,
    pub binding: PhysicalBinding,
}

impl From<&SnapshotSlot> for SnapshotSlotWire {
    fn from(s: &SnapshotSlot) -> Self {
        SnapshotSlotWire {
            generation: s.generation().clone(),
            artifact: s.artifact().clone(),
            binding: s.binding().clone(),
        }
    }
}

impl From<SnapshotSlotWire> for SnapshotSlot {
    fn from(w: SnapshotSlotWire) -> Self {
        SnapshotSlot::new(w.generation, w.artifact, w.binding)
    }
}

/// The KNOWN prior state of a slot before a `Deploy` action, in its strict
/// wire form (a validated generation + the strict artifact payload).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviousGenerationWire {
    pub generation: GenerationId,
    pub artifact: ArtifactRefWire,
}

/// The WIRE action of one planned slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SlotActionWire {
    /// Carried forward from the parent's snapshot.
    Inherit,
    /// Deployed by this push, with the observed pre-push state (the strict
    /// three-state wire observation).
    Deploy {
        pre_push: ObservationWire<PreviousGenerationWire>,
    },
}

/// The WIRE entry of one planned slot: its plan-minted result and its
/// action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedSlotWire {
    pub result: SnapshotSlotWire,
    pub action: SlotActionWire,
}

impl From<&PlannedSlot> for PlannedSlotWire {
    fn from(p: &PlannedSlot) -> Self {
        PlannedSlotWire {
            result: SnapshotSlotWire::from(p.result()),
            action: match p.action() {
                SlotAction::Inherit => SlotActionWire::Inherit,
                SlotAction::Deploy { pre_push } => SlotActionWire::Deploy {
                    pre_push: ObservationWire::from(pre_push.clone()),
                },
            },
        }
    }
}

/// The WIRE ROW of one planned slot INSIDE the intent's `slots` ARRAY: the
/// ROW OWNS ITS SLOT ID (the slot identity lives in the row, never in an
/// object key — the key and any row-internal id can never disagree). The
/// ROW ORDER inside the array IS the deployment order (the wire carries
/// the domain's insertion order — never sorted by slot id).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedSlotRowWire {
    pub slot_id: SlotId,
    pub result: SnapshotSlotWire,
    pub action: SlotActionWire,
}

/// The WIRE shape of a durable intent line — the RAW serde form the
/// ledger's JSONL carries. Schema v10: THE COMPLETE RESULT IS STORED ONCE in
/// the ONE full slot ROW ARRAY (`slots`); every membership and the
/// resulting snapshot are DERIVED views of it (the domain derives them;
/// the wire carries no duplicated projection). The ROW ORDER IS THE
/// DEPLOYMENT ORDER — a JSON object (whose keys sort) could never carry
/// it; the row array preserves the exact order the user recorded through
/// the round trip. `deny_unknown_fields`: a line with stray/unknown
/// members is refused on deserialization, never silently accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerIntentWire {
    pub deployment_schema_version: u32,
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    /// The successful deployment this intent derives from (the target's
    /// successful head at plan time). `None` for a first deployment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// The optional rollout group this attempt selected (`deploy push
    /// <target> --group <name>`). `None` means the attempt selected every
    /// slot of the target (a full push — every slot must be `Deploy`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// THE FULL SLOT ROW ARRAY: every slot the resulting snapshot covers in
    /// DEPLOYMENT ORDER, each row owning its slot id and carrying its
    /// plan-minted result and its action (Deploy / Inherit). The rows' slot
    /// ids ARE the full membership — there is no separate
    /// full_membership/selected_membership/resulting_snapshot projection.
    /// REQUIRED, DUPLICATE-FREE, and ORDER-PRESERVING: the wire → domain
    /// conversion REFUSES a duplicate slot row explicitly (the row fold
    /// names the duplicate — ambiguous JSON can never read as a valid
    /// intent) and inserts the rows in file order into the ordered domain
    /// table.
    pub slots: Vec<PlannedSlotRowWire>,
    pub behavior_sha256: String,
    pub attempted_at: String,
}

impl LedgerIntentWire {
    /// VERIFYING CONVERSION (wire → domain): scalar-gate every field
    /// (attempted_at as RFC 3339, the optional rollout group, the parent
    /// deployment id, the behavior digest) and enforce the self-contained
    /// construction rules through the kernel's validated domain constructor
    /// (at least one `Deploy` slot; `group: None` → every slot is `Deploy`).
    /// The cross-record rules (inherited slots reproduce the parent's
    /// snapshot entries) are validated at plan time ([`kernel::intent::plan`])
    /// and best-effort at read where the parent entry is still resolvable.
    pub fn into_domain(self) -> Result<DeploymentIntent> {
        let attempted_at = Timestamp::parse(&self.attempted_at).map_err(|_| {
            Error::integrity(format!(
                "intent {}: attempted_at {:?} is not an RFC 3339 timestamp",
                self.deployment_id, self.attempted_at
            ))
        })?;
        let group = match &self.group {
            Some(g) => Some(RolloutGroupName::parse(g).map_err(|_| {
                Error::integrity(format!(
                    "intent {}: rollout group {g:?} is not a valid group name",
                    self.deployment_id
                ))
            })?),
            None => None,
        };
        let parent = match &self.parent {
            Some(p) => Some(DeploymentId::parse(p).map_err(|_| {
                Error::integrity(format!(
                    "intent {}: parent {:?} is not a valid deployment id",
                    self.deployment_id, p
                ))
            })?),
            None => None,
        };
        let behavior_sha256 = BehaviorDigest::parse(&self.behavior_sha256).map_err(|_| {
            Error::integrity(format!(
                "intent {}: stored behavior_sha256 {:?} is not a sha256 digest",
                self.deployment_id, self.behavior_sha256
            ))
        })?;
        if self.slots.is_empty() {
            return Err(Error::integrity(format!(
                "intent {}: slots is empty — the domain refuses an empty intent",
                self.deployment_id
            )));
        }
        // THE ROW-ARRAY FOLD (order-preserving + duplicate-rejecting): each
        // row is folded IN FILE ORDER into the ordered domain table (insert
        // APPENDS at the end), so the round-tripped domain's keys == the
        // wire's row order — the deployment order — never a re-sort. A row
        // whose slot id was already seen is REFUSED with an integrity-class
        // error naming the duplicate (ambiguous JSON is never last-wins on
        // the wire boundary).
        let mut seen: BTreeSet<SlotId> = BTreeSet::new();
        let mut entries: Vec<(SlotId, PlannedSlot)> = Vec::with_capacity(self.slots.len());
        for row in self.slots {
            if !seen.insert(row.slot_id.clone()) {
                return Err(Error::integrity(format!(
                    "intent {}: duplicate slot '{}' in the wire rows — the slot table must be duplicate-free (the wire never last-wins ambiguous JSON)",
                    self.deployment_id, row.slot_id
                )));
            }
            let result: SnapshotSlot = row.result.into();
            let action = match row.action {
                SlotActionWire::Inherit => SlotAction::Inherit,
                SlotActionWire::Deploy { pre_push } => {
                    let obs: crate::ledger::Observation<PreviousGeneration> =
                        convert_pre_push(&row.slot_id, pre_push)?;
                    SlotAction::Deploy { pre_push: obs }
                }
            };
            entries.push((row.slot_id, PlannedSlot::new(result, action)));
        }
        let slots = NonEmptySlotTable::build(entries)
            .map_err(|e| Error::integrity(format!("intent {}: {e}", self.deployment_id)))?;
        kernel::intent::from_wire(
            self.deployment_id,
            self.target,
            parent,
            group,
            slots,
            behavior_sha256,
            attempted_at,
        )
        .map_err(|e| Error::integrity(format!("intent wire refused: {e}")))
    }
}

fn convert_pre_push(
    key: &SlotId,
    wire: ObservationWire<PreviousGenerationWire>,
) -> Result<crate::ledger::Observation<PreviousGeneration>> {
    Ok(match wire {
        ObservationWire::KnownAbsent => crate::ledger::Observation::KnownAbsent,
        ObservationWire::Known(p) => {
            let artifact: ArtifactRef = p.artifact.try_into().map_err(|_| {
                Error::integrity(format!(
                    "intent: pre_push for slot '{key}' carries an invalid artifact"
                ))
            })?;
            crate::ledger::Observation::Known(PreviousGeneration {
                generation: p.generation,
                artifact,
            })
        }
        ObservationWire::Unknown(e) => crate::ledger::Observation::Unknown(e),
    })
}

impl From<crate::ledger::Observation<PreviousGeneration>>
    for ObservationWire<PreviousGenerationWire>
{
    fn from(o: crate::ledger::Observation<PreviousGeneration>) -> Self {
        match o {
            crate::ledger::Observation::KnownAbsent => ObservationWire::KnownAbsent,
            crate::ledger::Observation::Known(p) => {
                ObservationWire::Known(PreviousGenerationWire {
                    generation: p.generation,
                    artifact: ArtifactRefWire::from(&p.artifact),
                })
            }
            crate::ledger::Observation::Unknown(e) => ObservationWire::Unknown(e),
        }
    }
}

impl From<&DeploymentIntent> for LedgerIntentWire {
    fn from(i: &DeploymentIntent) -> Self {
        // THE ROW ARRAY EMITS THE DOMAIN'S INSERTION ORDER: iterate the
        // ordered slot table (`keys()`/`iter()` — deployment order, never
        // sorted by id), each row embedding its OWN slot id. The wire's
        // row order is exactly the domain's deployment order, so the round
        // trip `valid domain → wire → domain` reproduces the original
        // domain exactly.
        let slots: Vec<PlannedSlotRowWire> = i
            .slots()
            .iter()
            .map(|(slot_id, p)| PlannedSlotRowWire {
                slot_id: slot_id.clone(),
                result: SnapshotSlotWire::from(p.result()),
                action: match p.action() {
                    SlotAction::Inherit => SlotActionWire::Inherit,
                    SlotAction::Deploy { pre_push } => SlotActionWire::Deploy {
                        pre_push: ObservationWire::from(pre_push.clone()),
                    },
                },
            })
            .collect();
        LedgerIntentWire {
            deployment_schema_version: crate::ledger::LEDGER_SCHEMA_VERSION,
            deployment_id: i.deployment_id().clone(),
            target: i.target().clone(),
            parent: i.parent().map(|p| p.as_str().to_string()),
            group: i.group().map(|g| g.as_str().to_string()),
            slots,
            behavior_sha256: i.behavior_digest().as_str().to_string(),
            attempted_at: i.attempted_at().to_string(),
        }
    }
}

/// The in-memory push REPORT form of a deployment attempt: the verified
/// intent fields PLUS the observed per-slot ACTUALS (`slots`). Built in
/// memory from the durable intent at push time and NEVER persisted: the
/// ledger's intent line carries NO outcomes. The report is display-facing
/// and keeps the split shape: the display `desired` map re-expands each
/// SELECTED slot's result from the full slot table, the `pre_push` map is
/// the intent's OWN observed pre-push observations (the three-state
/// [`crate::ledger::Observation<crate::ledger::PreviousGeneration>`] — used DIRECTLY, never re-wrapped),
/// and the actuals are the observed post-mutation states
/// ([`crate::ledger::ActualSlotState`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerIntentReport {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    pub group: Option<RolloutGroupName>,
    pub slot_ids: Vec<SlotId>,
    pub behavior_sha256: BehaviorDigest,
    pub attempted_at: Timestamp,
    pub desired: BTreeMap<SlotId, crate::identity::GenerationRef>,
    pub pre_push: BTreeMap<SlotId, crate::ledger::Observation<PreviousGeneration>>,
    pub slots: BTreeMap<SlotId, crate::ledger::ActualSlotState>,
}

impl LedgerIntentReport {
    /// Build the in-memory report from a verified domain intent, re-expanding
    /// the one full slot table into the display-facing split maps. The
    /// intent's values are already scalar-gated by the wire → domain
    /// conversion, so no re-parsing is needed here. The `pre_push` entries
    /// come from the intent's OWN pre-push observations directly; the
    /// `slots` map (the ACTUAL post-mutation states) starts EMPTY and is
    /// overwritten by the engine's actuals (`observe_actual_servers`) — a
    /// report never fabricates an actual that was not observed.
    pub fn from_intent(i: &DeploymentIntent) -> Result<LedgerIntentReport> {
        let slot_ids: Vec<SlotId> = i.selected().map(|(k, _)| k).collect();
        let desired: BTreeMap<SlotId, crate::identity::GenerationRef> = i
            .selected()
            .map(|(k, p)| {
                let result = p.result();
                (
                    k.clone(),
                    crate::identity::GenerationRef {
                        generation: result.generation().clone(),
                        assignment: result.assignment(&k),
                    },
                )
            })
            .collect();
        let pre_push: BTreeMap<SlotId, crate::ledger::Observation<PreviousGeneration>> = i
            .selected()
            .map(|(k, p)| {
                let obs = match &p.action() {
                    SlotAction::Deploy { pre_push } => pre_push.clone(),
                    SlotAction::Inherit => crate::ledger::Observation::KnownAbsent,
                };
                (k, obs)
            })
            .collect();
        Ok(LedgerIntentReport {
            deployment_id: i.deployment_id().clone(),
            target: i.target().clone(),
            group: i.group().cloned(),
            slot_ids,
            behavior_sha256: i.behavior_digest().clone(),
            attempted_at: *i.attempted_at(),
            desired,
            pre_push,
            slots: BTreeMap::new(),
        })
    }
}

/// A DEFAULT valid intent for test fixtures: one slot `p1` at a
/// deterministic generation/artifact/binding, full push (`group: None`,
/// `parent: None`), no pre-push state. Fixtures override the fields they
/// need via struct-update syntax on the DOMAIN (the wire fixtures build the
/// explicit wire shape).
impl Default for DeploymentIntent {
    fn default() -> Self {
        let p1 = SlotId::parse("p1").unwrap();
        let artifact = ArtifactRef {
            release: crate::identity::ReleaseId::parse(
                "rel-sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            variant: crate::identity::VariantName::parse("standard").unwrap(),
            tree: crate::identity::TreeDigest::parse(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
        };
        let binding = crate::ledger::PhysicalBinding {
            server: crate::identity::ServerId::parse("s1").unwrap(),
            deploy_dir: "/srv/deploy/p1".to_string(),
        };
        let slot = SnapshotSlot::new(
            crate::identity::GenerationId::parse("gen-00000000-0000-7000-8000-000000000001")
                .unwrap(),
            artifact,
            binding,
        );
        kernel::intent::plan(kernel::intent::PlanInput {
            deployment_id: crate::identity::DeploymentId::parse(
                "deploy-00000000-0000-7000-8000-000000000001",
            )
            .unwrap(),
            target: TargetName::parse("t1").unwrap(),
            parent: None,
            parent_snapshot: None,
            group: None,
            selection: vec![p1.clone()],
            planned: vec![kernel::intent::PlannedDeploy {
                slot: p1,
                result: slot,
                pre_push: crate::ledger::Observation::KnownAbsent,
            }],
            behavior_digest: BehaviorDigest::parse(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )
            .unwrap(),
            attempted_at: Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        })
        .expect("the default fixture intent is valid")
    }
}
