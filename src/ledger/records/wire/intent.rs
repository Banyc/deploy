//! The INTENT records of the deployment ledger (feature area A2 "two line
//! kinds — intent"): the durable intent wire/domain pair
//! ([`LedgerIntentWire`] / [`DeploymentIntent`]) with the VERIFYING
//! CONVERSION, the per-slot payload types ([`IntentSlot`],
//! [`DesiredGeneration`], [`PreviousGeneration`]), and the in-memory push
//! report ([`LedgerIntentReport`]). The physical [`crate::ledger::finalize::LedgerLine::Intent`]
//! line lives in [`crate::ledger::finalize`].

use crate::error::{Error, Result};
use crate::identity::{
    ArtifactRef, BehaviorDigest, DeploymentId, GenerationId, GenerationRef,
    PlacementSlotAssignment, ReleaseId, RolloutGroupName, SlotId, TargetName, Timestamp,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};

use super::super::observation::Observation;
use super::super::{NonEmptySlotTable, SlotAttemptState};
/// The WIRE shape of a durable intent line: the RAW serde form the ledger's
/// JSONL carries, holding every redundant member the domain reconciles (the
/// per-slot maps' key sets next to the authoritative `slot_ids` membership,
/// each [`crate::identity::GenerationRef`]'s assignment slot next to its map
/// key). [`crate::ledger::finalize::LedgerLine::Intent`] serializes this type; the ledger's wire
/// format is therefore unchanged (existing ledgers keep loading — the wire
/// reads the current format). The VERIFYING CONVERSION
/// ([`LedgerIntentWire::into_domain`]) checks every duplicate projection and
/// exposes only the validated [`DeploymentIntent`] domain type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerIntentWire {
    pub deployment_schema_version: u32,
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    /// The optional rollout group this attempt selected (`deploy push
    /// <target> --group <name>`). `None` means the attempt selected every
    /// slot owned by the target. The group name is DESCRIPTIVE (later
    /// releases may change group membership); the exact selected slot IDs in
    /// `slot_ids` are the authoritative historical evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// The placement slots participating in this deployment, in deployment
    /// order (the same set the commit marker `slots` payload records). This
    /// is the AUTHORITATIVE membership: it must be DUPLICATE-FREE, and the
    /// `desired` / `pre_push` maps' key sets must EQUAL it EXACTLY (every
    /// member slot has exactly one desired + one pre_push entry), verified by
    /// the wire → domain conversion.
    pub slot_ids: Vec<SlotId>,
    pub behavior_sha256: String,
    pub attempted_at: String,
    /// Desired per-slot assignments (what the plan intended): each slot's
    /// minted generation for its planned artifact. The key set must equal
    /// `slot_ids` EXACTLY, and each `GenerationRef`'s assignment must name
    /// its own map key.
    pub desired: BTreeMap<SlotId, GenerationRef>,
    /// Pre-push per-slot state before mutation (`None` if first deployment).
    /// Each entry's assignment artifact is a THREE-STATE observation
    /// ([`Observation<ArtifactRef>`]: `Known` / `KnownAbsent` / `Unknown`)
    /// — an unreadable pre-push assignment is `Unknown(error)`, a distinct
    /// value that can never be mistaken for a known artifact. The key set
    /// must equal `slot_ids` EXACTLY.
    pub pre_push: BTreeMap<SlotId, Option<SlotAttemptState>>,
    /// Actual per-slot result after the attempt. The persisted ledger intent
    /// keeps this map EMPTY (outcomes are recorded in the terminal event's
    /// `outcomes` map); the in-memory REPORT ([`LedgerIntentReport`]) carries
    /// the observed actuals for display — the verified domain [`DeploymentIntent`]
    /// does NOT carry this map, so it is not part of the intent's key-set
    /// invariant. Every key must be a member of `slot_ids`.
    pub slots: BTreeMap<SlotId, SlotAttemptState>,
}

impl LedgerIntentWire {
    /// VERIFYING CONVERSION (wire → domain): every duplicate projection must
    /// AGREE, and the DOMAIN then enforces the key-set invariant
    /// STRUCTURALLY. The authoritative membership is `slot_ids`, which must
    /// be DUPLICATE-FREE and NON-EMPTY, and the `desired` / `pre_push` key
    /// sets must EQUAL it EXACTLY — every member slot has exactly one
    /// desired + one pre_push entry; a missing OR extra key (and a duplicated
    /// member id) fails closed, so an incomplete authoritative projection is
    /// never read as if the maps were authoritative. Each desired
    /// [`crate::identity::GenerationRef`]'s assignment must name its own map key,
    /// and every wire `slots` (actuals) key must be a member of `slot_ids`
    /// (the persisted intent keeps that map EMPTY — outcomes live in the
    /// terminal event's `outcomes` map and the in-memory report
    /// [`LedgerIntentReport`]). The AGREED slots are then COLLAPSED into ONE
    /// authoritative [`NonEmptySlotTable`] (the domain's
    /// [`DeploymentIntent::slots`]): the membership + the per-slot maps are a
    /// single table, so the exact-key-set invariant is STRUCTURAL in the
    /// domain (no duplicates, no missing keys — `BTreeMap` uniqueness + the
    /// non-empty refusal below). A disagreement is an [`Error::integrity`]
    /// error (fail closed — a hand-constructed record can never be read as
    /// whichever projection a consumer happens to use).
    pub fn into_domain(self) -> Result<DeploymentIntent> {
        // The scalar invariants are validated HERE (fail closed): the attempt
        // timestamp must parse as RFC 3339, and the optional rollout group
        // must be a well-formed group name. A wire record violating either is
        // refused with an integrity error before any membership check runs.
        // (The stored `behavior_sha256` is NOT format-gated here: legacy
        // records may carry a snapshot-wide digest that is only carried, and
        // the canonical sha256-form digest is enforced where the value is
        // INTERPRETED — the in-memory report's [`BehaviorDigest`] and the
        // plan conversion's derived-digest check.)
        Timestamp::parse(&self.attempted_at).map_err(|_| {
            Error::integrity(format!(
                "intent {}: attempted_at {:?} is not an RFC 3339 timestamp",
                self.deployment_id, self.attempted_at
            ))
        })?;
        if let Some(g) = &self.group {
            RolloutGroupName::parse(g).map_err(|_| {
                Error::integrity(format!(
                    "intent {}: rollout group {g:?} is not a valid group name",
                    self.deployment_id
                ))
            })?;
        }
        // `slot_ids` is the AUTHORITATIVE membership and must be
        // DUPLICATE-FREE: a duplicated member would silently weaken the
        // key-set equality below (a set collapses the duplicate, so the
        // duplicated id would never be checked against the maps).
        let mut seen: BTreeSet<&SlotId> = BTreeSet::new();
        for sid in &self.slot_ids {
            if !seen.insert(sid) {
                return Err(Error::integrity(format!(
                    "intent {}: slot_ids carries duplicate slot '{sid}' — the membership must be unique",
                    self.deployment_id
                )));
            }
        }
        let membership: BTreeSet<&SlotId> = self.slot_ids.iter().collect();
        let desired_keys: BTreeSet<&SlotId> = self.desired.keys().collect();
        let pre_push_keys: BTreeSet<&SlotId> = self.pre_push.keys().collect();
        // EXACT KEY-SET EQUALITY: every member slot has exactly one desired +
        // one pre_push entry, and neither map carries a slot the membership
        // omits — a missing OR extra key fails the conversion (an incomplete
        // authoritative projection is a disagreement, never read as if the
        // maps were the membership).
        if membership != desired_keys {
            return Err(Error::integrity(format!(
                "intent {}: slot_ids {:?} disagrees with the desired key set {:?} — every member slot needs exactly one desired entry",
                self.deployment_id, membership, desired_keys
            )));
        }
        if membership != pre_push_keys {
            return Err(Error::integrity(format!(
                "intent {}: slot_ids {:?} disagrees with the pre_push key set {:?} — every member slot needs exactly one pre_push entry",
                self.deployment_id, membership, pre_push_keys
            )));
        }
        // An EMPTY membership is refused here: the domain intent's slots are
        // a [`NonEmptySlotTable`], so a deployment that selects no slot is
        // unrepresentable in the domain (and meaningless — a push always
        // selects at least one slot).
        if membership.is_empty() {
            return Err(Error::integrity(format!(
                "intent {}: slot_ids is empty — the domain refuses an empty deployment membership",
                self.deployment_id
            )));
        }
        for (key, g) in &self.desired {
            if &g.assignment.placement_slot != key {
                return Err(Error::integrity(format!(
                    "intent {}: desired assignment for slot '{key}' names placement '{}'",
                    self.deployment_id, g.assignment.placement_slot
                )));
            }
        }
        // The wire `slots` (actuals) map is the REPORT's map in the old
        // single-datatype design; it is persisted EMPTY. The domain intent
        // does NOT carry it; any wire key must still be a member — fail
        // closed.
        for key in self.slots.keys() {
            if !membership.contains(key) {
                return Err(Error::integrity(format!(
                    "intent {}: slots key '{key}' is not in slot_ids",
                    self.deployment_id
                )));
            }
        }
        // COLLAPSE the three projections into ONE table, in the wire's
        // `slot_ids` SEQUENCE order (the deployment order) — never the
        // sorted-by-id order of the per-slot maps. The exact-key-set
        // equality verified above guarantees every member has its desired +
        // pre_push entry, so each member's facts are read by member id.
        let slots: Vec<(SlotId, IntentSlot)> =
            self.slot_ids
                .iter()
                .map(|key| {
                    let desired = &self.desired[key];
                    let pre_push = self.pre_push.get(key).and_then(|p| p.clone()).map(|p| {
                        PreviousGeneration {
                            artifact: p.artifact,
                            generation: p.generation,
                        }
                    });
                    (
                        key.clone(),
                        IntentSlot {
                            desired: DesiredGeneration {
                                generation: desired.generation.clone(),
                                artifact: desired.assignment.artifact.clone(),
                            },
                            pre_push,
                        },
                    )
                })
                .collect();
        Ok(DeploymentIntent {
            deployment_id: self.deployment_id,
            target: self.target,
            group: self.group,
            behavior_sha256: self.behavior_sha256,
            attempted_at: self.attempted_at,
            slots: NonEmptySlotTable::build(slots)?,
        })
    }
}

/// ONE member slot's slot-table entry: the DESIRED assignment (the
/// generation the plan minted for the slot's planned artifact) plus the
/// OPTIONAL PRE-PUSH state (what the slot ran before the attempt — `None`
/// for a first deployment). The slot id itself is the enclosing
/// [`NonEmptySlotTable`] key — the enclosing object owns identity, so
/// neither payload re-declares it (the wire's redundant projections are
/// verified and dropped by the conversion).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentSlot {
    pub desired: DesiredGeneration,
    pub pre_push: Option<PreviousGeneration>,
}

/// One slot's DESIRED generation: the generation the plan minted for the
/// slot's planned artifact. The DOMAIN form of the wire's per-slot
/// [`crate::identity::GenerationRef`] with the REDUNDANT assignment slot
/// dropped (the enclosing table key owns the slot identity — "store each
/// fact exactly once"); the wire conversion verifies the assignment named
/// its own map key before dropping it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredGeneration {
    pub generation: GenerationId,
    /// The artifact (release, variant, tree) the slot planned to advance to.
    pub artifact: ArtifactRef,
}

/// One slot's PRE-PUSH state before the attempt: what the slot ran
/// (`artifact`, a three-state observation) and the generation it was on
/// (`None` when only the pre-push state is unknown / the slot was never
/// deployed). The DOMAIN form of the wire's [`SlotAttemptState`] under the
/// table's name; the enclosing table key owns the slot. The artifact is an
/// [`Observation`]: an unreadable pre-push assignment is `Unknown(error)` —
/// a distinct value, never a valid-looking artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviousGeneration {
    pub artifact: Observation<ArtifactRef>,
    pub generation: Option<GenerationId>,
}

/// The durable INTENT of one deployment attempt, the VALIDATED DOMAIN form
/// of [`LedgerIntentWire`]: what was planned and observed BEFORE any server
/// mutation. Appended once to the target's ledger ([`crate::ledger::finalize::LedgerLine::Intent`])
/// BEFORE the remote mutation phase (a crash after servers advanced to new
/// generations can never lose the deployment: the intent is already durable
/// and the next push reconciles it) and never edited. The attempt's STATUS,
/// per-slot OUTCOMES and (when successful) ROLLBACK STATE come from its
/// TERMINAL EVENT ([`LedgerTerminal`]), never from this record.
///
/// STORE EACH FACT EXACTLY ONCE: the wire's `slot_ids` / `desired` /
/// `pre_push` split collapses into ONE authoritative table
/// [`DeploymentIntent::slots`] — the membership AND the per-slot maps are a
/// single [`NonEmptySlotTable<IntentSlot>`], so the exact-key-set invariant
/// (`slot_ids == desired == pre_push`, no duplicates) is STRUCTURAL: the
/// table has no duplicates (`BTreeMap` keys) and no missing keys (non-empty,
/// every member carries its desired + pre_push entry). The `group`,
/// `behavior_sha256` and `attempted_at` members are SINGLE facts (display /
/// rollback context), not duplicated projections — they are not part of the
/// reshape. The wire `deployment_schema_version` is a WIRE format concern
/// (checked by the reader on the wire, refused if not
/// [`crate::ledger::LEDGER_SCHEMA_VERSION`]); the validated domain does not
/// carry it and writers emit exactly the constant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentIntent {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    /// The optional rollout group this attempt selected (`deploy push
    /// <target> --group <name>`). `None` means the attempt selected every
    /// slot owned by the target. The group name is DESCRIPTIVE (later
    /// releases may change group membership); the exact selected slot IDs in
    /// `slots` are the authoritative historical evidence. Single fact
    /// (display), not a duplicated projection.
    pub group: Option<String>,
    /// The attempt's behavior digest (see [`LedgerIntentWire`]). Single
    /// fact (wire round-trip), not a duplicated projection.
    pub behavior_sha256: String,
    /// When the intent was recorded (RFC 3339). Single fact (display).
    pub attempted_at: String,
    /// THE AUTHORITATIVE SLOT TABLE: the deployment's membership (the keys)
    /// and each member's desired + pre-push entries, ONE table. Non-empty +
    /// unique by construction ([`NonEmptySlotTable`]) — the exact-key-set
    /// invariant is structural here, not checked.
    pub slots: NonEmptySlotTable<IntentSlot>,
}

impl DeploymentIntent {
    /// The deployment's membership: the AUTHORITATIVE selected placement
    /// slots (in deployment order — the table's key order).
    pub fn membership(&self) -> Vec<SlotId> {
        self.slots.keys().cloned().collect()
    }

    /// The distinct releases referenced by the intent's per-slot desired
    /// assignments — DERIVED from the authoritative `slots` table, never
    /// stored separately (a partial snapshot can span several releases).
    pub fn releases(&self) -> BTreeSet<ReleaseId> {
        self.slots
            .values()
            .map(|s| s.desired.artifact.release.clone())
            .collect()
    }
}

impl From<&DeploymentIntent> for LedgerIntentWire {
    fn from(i: &DeploymentIntent) -> Self {
        // Re-expand the ONE table into the wire's split shape (slot_ids +
        // desired + pre_push) for serialization; the reader re-collapses it.
        // The member order is the table's key order (deployment order).
        let slot_ids: Vec<SlotId> = i.slots.keys().cloned().collect();
        let desired: BTreeMap<SlotId, GenerationRef> = i
            .slots
            .iter()
            .map(|(key, s)| {
                (
                    key.clone(),
                    GenerationRef {
                        generation: s.desired.generation.clone(),
                        assignment: PlacementSlotAssignment {
                            placement_slot: key.clone(),
                            artifact: s.desired.artifact.clone(),
                        },
                    },
                )
            })
            .collect();
        let pre_push: BTreeMap<SlotId, Option<SlotAttemptState>> = i
            .slots
            .iter()
            .map(|(key, s)| {
                (
                    key.clone(),
                    s.pre_push.as_ref().map(|p| SlotAttemptState {
                        artifact: p.artifact.clone(),
                        generation: p.generation.clone(),
                    }),
                )
            })
            .collect();
        LedgerIntentWire {
            deployment_schema_version: crate::ledger::LEDGER_SCHEMA_VERSION,
            deployment_id: i.deployment_id.clone(),
            target: i.target.clone(),
            group: i.group.clone(),
            slot_ids,
            behavior_sha256: i.behavior_sha256.clone(),
            attempted_at: i.attempted_at.clone(),
            desired,
            pre_push,
            // The persisted intent carries NO outcomes: the wire keeps the
            // `slots` member EMPTY (outcomes live in the terminal event's
            // `outcomes` map; the in-memory report [`LedgerIntentReport`]
            // carries the observed actuals).
            slots: BTreeMap::new(),
        }
    }
}

/// The in-memory push REPORT form of a deployment attempt: the verified
/// intent fields PLUS the observed per-slot ACTUALS (`slots`). Built in
/// memory from the durable intent at push time and NEVER persisted: the
/// ledger's intent line carries NO outcomes (the wire [`LedgerIntentWire`]
/// keeps its `slots` map empty; outcomes live in the terminal event's
/// `outcomes` map and the rollback payload). Keeping the report as its OWN
/// type — rather than reusing [`DeploymentIntent`] — means the verified
/// intent object never carries an outcomes map, so the intent's structural
/// key-set invariant is not weakened by a report map that is not part of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerIntentReport {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    /// The optional rollout group this attempt selected, as a validated
    /// [`RolloutGroupName`] (parsed from the verified intent's group string).
    pub group: Option<RolloutGroupName>,
    pub slot_ids: Vec<SlotId>,
    /// The attempt's behavior digest, as a validated [`BehaviorDigest`]
    /// (parsed from the wire's `behavior_sha256` string).
    pub behavior_sha256: BehaviorDigest,
    /// When the attempt was recorded, as a parsed RFC 3339 [`Timestamp`].
    pub attempted_at: Timestamp,
    /// Desired per-slot assignments, re-expanded from the domain table (the
    /// report is display-facing and keeps the wire's split shape).
    pub desired: BTreeMap<SlotId, GenerationRef>,
    /// Pre-push per-slot state before mutation, re-expanded from the domain
    /// table (same observation-shaped [`SlotAttemptState`] as the wire — an
    /// unknown assignment is `Observation::Unknown`, never a sentinel
    /// artifact).
    pub pre_push: BTreeMap<SlotId, Option<SlotAttemptState>>,
    /// Actual per-slot result after the attempt, for display. The report is
    /// in-memory only — the persisted intent never carries this map.
    pub slots: BTreeMap<SlotId, SlotAttemptState>,
}

impl LedgerIntentReport {
    /// Build the in-memory report from a verified domain intent, parsing the
    /// intent's bare strings into the validated scalars AND re-expanding the
    /// one slot table into the display-facing split maps. The intent's values
    /// were already scalar-gated by the wire → domain conversion
    /// ([`LedgerIntentWire::into_domain`]), so the parses succeed in
    /// practice; a violation still fails closed with an integrity error
    /// rather than constructing an invalid report.
    pub fn from_intent(i: &DeploymentIntent) -> Result<LedgerIntentReport> {
        let group = match &i.group {
            Some(g) => Some(RolloutGroupName::parse(g).map_err(|_| {
                Error::integrity(format!(
                    "intent {}: rollout group {g:?} is not a valid group name",
                    i.deployment_id
                ))
            })?),
            None => None,
        };
        // Re-expand the ONE table into the display-facing split maps.
        let slot_ids: Vec<SlotId> = i.slots.keys().cloned().collect();
        let desired: BTreeMap<SlotId, GenerationRef> = i
            .slots
            .iter()
            .map(|(key, s)| {
                (
                    key.clone(),
                    GenerationRef {
                        generation: s.desired.generation.clone(),
                        assignment: PlacementSlotAssignment {
                            placement_slot: key.clone(),
                            artifact: s.desired.artifact.clone(),
                        },
                    },
                )
            })
            .collect();
        let pre_push: BTreeMap<SlotId, Option<SlotAttemptState>> = i
            .slots
            .iter()
            .map(|(key, s)| {
                (
                    key.clone(),
                    s.pre_push.as_ref().map(|p| SlotAttemptState {
                        artifact: p.artifact.clone(),
                        generation: p.generation.clone(),
                    }),
                )
            })
            .collect();
        Ok(LedgerIntentReport {
            deployment_id: i.deployment_id.clone(),
            target: i.target.clone(),
            group,
            slot_ids,
            behavior_sha256: BehaviorDigest::parse(&i.behavior_sha256).map_err(|_| {
                Error::integrity(format!(
                    "intent {}: stored behavior_sha256 {:?} is not a sha256 digest",
                    i.deployment_id, i.behavior_sha256
                ))
            })?,
            attempted_at: Timestamp::parse(&i.attempted_at).map_err(|_| {
                Error::integrity(format!(
                    "intent {}: attempted_at {:?} is not an RFC 3339 timestamp",
                    i.deployment_id, i.attempted_at
                ))
            })?,
            desired,
            pre_push,
            slots: BTreeMap::new(),
        })
    }
}

impl Serialize for DeploymentIntent {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        LedgerIntentWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DeploymentIntent {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = LedgerIntentWire::deserialize(deserializer)?;
        wire.into_domain()
            .map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}
