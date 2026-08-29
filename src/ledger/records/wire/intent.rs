//! The INTENT records of the deployment ledger (feature area A2 "two line
//! kinds — intent"): the durable intent wire/domain pair
//! ([`LedgerIntentWire`] / [`DeploymentIntent`]) with the VERIFYING
//! CONVERSION, the per-slot payload types ([`SelectedSlotIntent`]),
//! and the in-memory push report ([`LedgerIntentReport`]). The physical
//! [`crate::ledger::finalize::LedgerLine::Intent`] line lives in
//! [`crate::ledger::finalize`].

use crate::error::{Error, Result};
use crate::identity::{
    ArtifactRef, BehaviorDigest, DeploymentId, GenerationId, GenerationRef,
    PlacementSlotAssignment, ReleaseId, RolloutGroupName, SlotId, TargetName, Timestamp,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};

use super::super::TargetSnapshotWire;
use super::super::observation::{ArtifactRefWire, Observation, ObservationWire};
use super::super::{NonEmptySlotTable, SlotAttemptState, TargetSnapshot};

/// The WIRE shape of a durable intent line: the RAW serde form the ledger's
/// JSONL carries. Since schema v8 the intent FREEZES the COMPLETE RESULTING
/// SNAPSHOT: `resulting_snapshot` carries every target slot's generation,
/// artifact and physical binding (its keys ARE the frozen full membership),
/// while `slot_ids` (the SELECTED membership, in deployment order, the
/// authoritative key set for the `pre_push` map) + `pre_push` record the
/// selected slots' pre-push state. The old redundant projections
/// (`desired` / `bindings` / `selected_membership` / `full_membership`) are
/// GONE — a selected slot's desired generation/artifact/binding is its entry
/// in `resulting_snapshot` (no duplication), and the full membership is the
/// snapshot's key set. The VERIFYING CONVERSION
/// ([`LedgerIntentWire::into_domain`]) checks every duplicate projection and
/// exposes only the validated [`DeploymentIntent`] domain type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerIntentWire {
    pub deployment_schema_version: u32,
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    /// The optional rollout group this attempt selected (`deploy push
    /// <target> --group <name>`). `None` means the attempt selected every
    /// slot of the target (a full push).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// The SELECTED membership, in deployment order — the authoritative key
    /// set of the `pre_push` map. DUPLICATE-FREE and NON-EMPTY (verified by
    /// the conversion, fail closed).
    pub slot_ids: Vec<SlotId>,
    /// THE FROZEN RESULTING SNAPSHOT: every target slot's generation,
    /// artifact and physical binding, exactly as the plan computed it (the
    /// selected slots at their minted generations with their planned
    /// artifacts and plan-time bindings; a group push's unselected slots
    /// carried forward from the base). Its keys ARE the frozen FULL
    /// membership — there is no separate full_membership projection. The
    /// selected slots' entries double as their DESIRED state (the selected
    /// slot's desired generation/artifact/binding is derived from its
    /// snapshot entry — no duplication). REQUIRED (no serde default — an
    /// old-shape line fails deserialization fail closed).
    pub resulting_snapshot: TargetSnapshotWire,
    pub behavior_sha256: String,
    pub attempted_at: String,
    /// Pre-push per-slot state before mutation (`None` if first deployment).
    /// The key set must EQUAL `slot_ids` EXACTLY, and the per-slot wire value
    /// must be representable as a known [`GenerationRef`] (the conversion
    /// refuses an `Unknown` / `KnownAbsent` observation or a missing
    /// generation — an unreadable pre-push cannot be frozen into the intent).
    pub pre_push: BTreeMap<SlotId, Option<SlotAttemptStateWire>>,
    /// Actual per-slot result after the attempt, in its STRICT WIRE form.
    /// The persisted ledger intent keeps this map EMPTY (outcomes are
    /// recorded in the terminal event's `outcomes` map); the in-memory
    /// REPORT ([`LedgerIntentReport`]) carries the observed actuals for
    /// display. Every key must be a member of `slot_ids`.
    pub slots: BTreeMap<SlotId, SlotAttemptStateWire>,
}

impl LedgerIntentWire {
    /// VERIFYING CONVERSION (wire → domain): every duplicate projection must
    /// AGREE, and the DOMAIN then enforces the key-set invariant
    /// STRUCTURALLY. The authoritative selected membership is `slot_ids`
    /// (DUPLICATE-FREE and NON-EMPTY, and the `pre_push` key set must EQUAL
    /// it EXACTLY); the snapshot is non-empty and its keys ARE the full
    /// membership. The two membership invariants are enforced here, fail
    /// closed: `selected ⊆ snapshot keys` (a deployment can only select
    /// slots the frozen snapshot covers) and — for a FULL push (no group) —
    /// `selected == snapshot keys` (a full push selects every target slot).
    /// Each selected slot's pre-push wire value converts to a KNOWN
    /// [`GenerationRef`] (`None` = first deployment; `Unknown` / `KnownAbsent`
    /// / missing-generation values are refused — an unreadable pre-push
    /// cannot be frozen into the intent). A disagreement is an
    /// [`Error::integrity`] error (fail closed — a hand-constructed record
    /// can never be read as whichever projection a consumer happens to use).
    pub fn into_domain(self) -> Result<DeploymentIntent> {
        // The scalar invariants are validated HERE (fail closed): the attempt
        // timestamp must parse as RFC 3339, the stored digest as sha256, and
        // the optional rollout group must be a well-formed group name.
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
        let behavior_sha256 = BehaviorDigest::parse(&self.behavior_sha256).map_err(|_| {
            Error::integrity(format!(
                "intent {}: stored behavior_sha256 {:?} is not a sha256 digest",
                self.deployment_id, self.behavior_sha256
            ))
        })?;
        // `slot_ids` is the AUTHORITATIVE selected membership and must be
        // DUPLICATE-FREE: a duplicated member would silently weaken the
        // key-set equality below.
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
        // An EMPTY selected membership is refused: a push always selects at
        // least one slot.
        if membership.is_empty() {
            return Err(Error::integrity(format!(
                "intent {}: slot_ids is empty — the domain refuses an empty deployment membership",
                self.deployment_id
            )));
        }
        // EXACT KEY-SET EQUALITY: every selected slot has exactly one
        // pre_push entry, and the map carries no slot the membership omits.
        let pre_push_keys: BTreeSet<&SlotId> = self.pre_push.keys().collect();
        if membership != pre_push_keys {
            return Err(Error::integrity(format!(
                "intent {}: slot_ids {:?} disagrees with the pre_push key set {:?} — every member slot needs exactly one pre_push entry",
                self.deployment_id, membership, pre_push_keys
            )));
        }
        // The wire `slots` (actuals) map is the REPORT's map; it is persisted
        // EMPTY. Any wire key must still be a member — fail closed.
        for key in self.slots.keys() {
            if !membership.contains(key) {
                return Err(Error::integrity(format!(
                    "intent {}: slots key '{key}' is not in slot_ids",
                    self.deployment_id
                )));
            }
        }
        // THE RESULTING SNAPSHOT: its keys ARE the frozen full membership.
        let snapshot: TargetSnapshot = self.resulting_snapshot.into();
        if snapshot.is_empty() {
            return Err(Error::integrity(format!(
                "intent {}: resulting_snapshot is empty — the domain refuses an empty snapshot",
                self.deployment_id
            )));
        }
        let snapshot_keys: BTreeSet<SlotId> = snapshot.keys().cloned().collect();
        let selected_set: BTreeSet<SlotId> = self.slot_ids.iter().cloned().collect();
        // INVARIANT 1: selected ⊆ snapshot keys — a deployment can only
        // select slots its frozen snapshot covers.
        if !selected_set.is_subset(&snapshot_keys) {
            let outside: Vec<SlotId> = selected_set.difference(&snapshot_keys).cloned().collect();
            return Err(Error::integrity(format!(
                "intent {}: selected slots {outside:?} are not in resulting_snapshot keys {snapshot_keys:?} — selected ⊆ snapshot",
                self.deployment_id
            )));
        }
        // INVARIANT 2: a FULL push (no group) selects every target slot, so
        // selected == snapshot keys.
        if group.is_none() && selected_set != snapshot_keys {
            return Err(Error::integrity(format!(
                "intent {}: group None requires selected == resulting_snapshot keys (selected {selected_set:?} vs snapshot {snapshot_keys:?}) — a full push selects every target slot",
                self.deployment_id
            )));
        }
        // COLLAPSE into ONE selected table, in the wire's `slot_ids` SEQUENCE
        // order (the deployment order). Each selected slot's pre-push state
        // converts to a KNOWN GenerationRef or `None` (its desired
        // generation/artifact/binding comes from the snapshot entry — never
        // duplicated here).
        let selected_entries: Result<Vec<(SlotId, SelectedSlotIntent)>> = self
            .slot_ids
            .iter()
            .map(|key| {
                let pre_push = self
                    .pre_push
                    .get(key)
                    .and_then(|p| p.clone())
                    .map(|p| -> Result<GenerationRef> {
                        let generation = p.generation.clone().ok_or_else(|| {
                            Error::integrity(format!(
                                "intent {}: pre_push for slot '{key}' has no generation — unrepresentable as a known GenerationRef",
                                self.deployment_id
                            ))
                        })?;
                        match p.artifact {
                            ObservationWire::Known(a) => {
                                let obs: Observation<ArtifactRef> =
                                    ObservationWire::Known(a).try_into().map_err(|_| {
                                        Error::integrity(format!(
                                            "intent {}: pre_push for slot '{key}' carries an invalid artifact",
                                            self.deployment_id
                                        ))
                                    })?;
                                let artifact: ArtifactRef = match obs {
                                    Observation::Known(a) => a,
                                    _ => unreachable!(),
                                };
                                Ok(GenerationRef {
                                    generation,
                                    assignment: PlacementSlotAssignment {
                                        placement_slot: key.clone(),
                                        artifact,
                                    },
                                })
                            }
                            ObservationWire::KnownAbsent => Err(Error::integrity(format!(
                                "intent {}: pre_push for slot '{key}' is KnownAbsent — an unreadable pre-push cannot be frozen (the intent records a KNOWN prior state or None)",
                                self.deployment_id
                            ))),
                            ObservationWire::Unknown(_) => Err(Error::integrity(format!(
                                "intent {}: pre_push for slot '{key}' is Unknown — an unreadable pre-push cannot be frozen (the push must retry rather than freeze an unknown prior state)",
                                self.deployment_id
                            ))),
                        }
                    })
                    .transpose()?;
                Ok((key.clone(), SelectedSlotIntent { pre_push }))
            })
            .collect();
        let selected = NonEmptySlotTable::build(selected_entries?)?;
        Ok(DeploymentIntent {
            deployment_id: self.deployment_id,
            target: self.target,
            group,
            resulting_snapshot: snapshot,
            selected,
            behavior_sha256,
            attempted_at,
        })
    }
}

/// ONE selected slot's slot-table entry: ONLY the OPTIONAL PRE-PUSH state (a
/// known [`GenerationRef`] — what the slot ran before the attempt; `None` for
/// a first deployment / no prior state). The slot's DESIRED state — the
/// generation, artifact and physical binding the plan minted — is DERIVED
/// from its entry in [`DeploymentIntent::resulting_snapshot`], so it is never
/// duplicated here (the wire's snapshot is the single source of the planned
/// facts). The slot id itself is the enclosing table key — the enclosing
/// object owns identity, so the payload never re-declares it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SelectedSlotIntent {
    pub pre_push: Option<GenerationRef>,
}

/// THE WIRE FORM of a [`SlotAttemptState`] — the pre-push / actuals entry
/// the PERSISTED intent line carries (`[LedgerIntentWire::pre_push]` and
/// `[LedgerIntentWire::slots]`): the shared-core shape with its artifact
/// observation in the STRICT adjacently-tagged wire form
/// ([`ObservationWire<ArtifactRefWire>`], `deny_unknown_fields`), so the
/// raw wire document rejects any field beyond `artifact`/`generation` and
/// any observation shape that is not EXACTLY one variant. The DOMAIN
/// [`SlotAttemptState`] keeps the permissive in-memory
/// [`Observation<ArtifactRef>`]; the wire → domain conversion and the
/// domain → wire re-expansion convert between the two — the wire ↔ domain
/// bijection is EXACT.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotAttemptStateWire {
    /// The slot's assignment as a THREE-STATE observation in its STRICT
    /// wire form: `Known(artifact)` is a real artifact read from the remote,
    /// `KnownAbsent` carries no artifact, and `Unknown(error)` preserves the
    /// read failure.
    pub artifact: ObservationWire<ArtifactRefWire>,
    /// The generation this slot actually advanced to.
    pub generation: Option<GenerationId>,
}

impl SlotAttemptStateWire {
    /// WIRE → DOMAIN, FAIL CLOSED: the strict wire observation converts to
    /// the permissive domain observation. A wire value that is not
    /// representable is refused with an integrity error rather than read as
    /// a half-known state (in practice the serde-gated wire types make the
    /// conversion total — the refusal is the boundary's fail-closed
    /// contract).
    pub fn into_domain(self) -> Result<SlotAttemptState> {
        Ok(SlotAttemptState {
            artifact: self.artifact.try_into()?,
            generation: self.generation,
        })
    }
}

impl From<&SlotAttemptState> for SlotAttemptStateWire {
    /// DOMAIN → WIRE: the permissive in-memory observation converts to its
    /// EXACT strict wire form (the bijection is exact — every domain value
    /// has exactly one wire form).
    fn from(s: &SlotAttemptState) -> Self {
        SlotAttemptStateWire {
            artifact: ObservationWire::from(&s.artifact),
            generation: s.generation.clone(),
        }
    }
}

/// The durable INTENT of one deployment attempt, the VALIDATED DOMAIN form
/// of [`LedgerIntentWire`]: what was planned and frozen BEFORE any server
/// mutation. Appended once to the target's ledger
/// ([`crate::ledger::finalize::LedgerLine::Intent`]) BEFORE the remote
/// mutation phase and never edited. The attempt's STATUS, per-slot OUTCOMES
/// and (when successful) ROLLBACK STATE come from its TERMINAL EVENT
/// ([`crate::ledger::LedgerTerminal`]), never from this record.
///
/// STORE EACH FACT EXACTLY ONCE: the COMPLETE RESULTING SNAPSHOT
/// ([`resulting_snapshot`]) carries every target slot's generation, artifact
/// and physical binding (its keys ARE the frozen full membership — the
/// selected slot's desired state is its snapshot entry), and the SELECTED
/// table ([`selected`]) carries only each selected slot's pre-push state.
/// The two memberships are therefore structural: `selected.keys` is the
/// frozen selected set, `resulting_snapshot.keys` the frozen full set, and
/// the two invariants — selected ⊆ snapshot and (group = None → selected ==
/// snapshot) — are enforced by the conversion, fail closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentIntent {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    /// The optional rollout group this attempt selected. `None` means the
    /// attempt selected every slot of the target (a full push —
    /// `selected.keys == snapshot.keys`).
    pub group: Option<RolloutGroupName>,
    /// THE FROZEN RESULTING SNAPSHOT: every target slot's generation,
    /// artifact and physical binding as planned. Its keys ARE the full
    /// membership; the selected slots' entries are their desired state.
    pub resulting_snapshot: TargetSnapshot,
    /// THE SELECTED SLOTS: the non-empty membership (the keys, in
    /// deployment order) and each selected slot's pre-push state only.
    pub selected: NonEmptySlotTable<SelectedSlotIntent>,
    pub behavior_sha256: BehaviorDigest,
    pub attempted_at: Timestamp,
}

impl DeploymentIntent {
    /// The deployment's SELECTED membership, in deployment order (the
    /// selected table's key order).
    pub fn membership(&self) -> Vec<SlotId> {
        self.selected.keys().cloned().collect()
    }

    /// THE FROZEN SELECTED MEMBERSHIP, as the SORTED UNIQUE SET — the
    /// selected table's keys.
    pub fn selected_membership(&self) -> BTreeSet<SlotId> {
        self.selected.keys().cloned().collect()
    }

    /// THE FROZEN FULL MEMBERSHIP — the COMPLETE target membership at plan
    /// time, DERIVED from the resulting snapshot's keys (never stored
    /// separately, never the live configuration).
    pub fn full_membership(&self) -> BTreeSet<SlotId> {
        self.resulting_snapshot.keys().cloned().collect()
    }

    /// The distinct releases referenced by the SELECTED slots' desired
    /// assignments — DERIVED from the resulting snapshot's entries for the
    /// selected keys (a partial snapshot can span several releases).
    pub fn releases(&self) -> BTreeSet<ReleaseId> {
        self.selected
            .keys()
            .filter_map(|sid| self.resulting_snapshot.get(sid))
            .map(|e| e.artifact().release.clone())
            .collect()
    }
}

impl From<&DeploymentIntent> for LedgerIntentWire {
    fn from(i: &DeploymentIntent) -> Self {
        // Re-expand the domain into the wire's split shape: the selected
        // membership (in deployment order), the per-selected-slot pre_push
        // (as the strict wire observation), and the frozen resulting snapshot
        // (the full membership, one entry per target slot).
        let slot_ids: Vec<SlotId> = i.selected.keys().cloned().collect();
        let pre_push: BTreeMap<SlotId, Option<SlotAttemptStateWire>> = i
            .selected
            .iter()
            .map(|(key, s)| {
                let wire = s.pre_push.as_ref().map(|gr| SlotAttemptStateWire {
                    artifact: ObservationWire::Known(ArtifactRefWire::from(
                        &gr.assignment.artifact,
                    )),
                    generation: Some(gr.generation.clone()),
                });
                (key.clone(), wire)
            })
            .collect();
        LedgerIntentWire {
            deployment_schema_version: crate::ledger::LEDGER_SCHEMA_VERSION,
            deployment_id: i.deployment_id.clone(),
            target: i.target.clone(),
            group: i.group.as_ref().map(|g| g.as_str().to_string()),
            slot_ids,
            resulting_snapshot: TargetSnapshotWire::from(&i.resulting_snapshot),
            behavior_sha256: i.behavior_sha256.as_str().to_string(),
            attempted_at: i.attempted_at.to_string(),
            pre_push,
            // The persisted intent carries NO outcomes: the wire keeps the
            // `slots` member EMPTY (outcomes live in the terminal event's
            // `outcomes` map; the in-memory report carries the observed
            // actuals).
            slots: BTreeMap::new(),
        }
    }
}

/// The in-memory push REPORT form of a deployment attempt: the verified
/// intent fields PLUS the observed per-slot ACTUALS (`slots`). Built in
/// memory from the durable intent at push time and NEVER persisted: the
/// ledger's intent line carries NO outcomes. The report is display-facing and
/// keeps the split shape: the display `desired` map re-expands each SELECTED
/// slot's entry from the frozen snapshot (its desired generation/artifact).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerIntentReport {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    pub group: Option<RolloutGroupName>,
    pub slot_ids: Vec<SlotId>,
    pub behavior_sha256: BehaviorDigest,
    pub attempted_at: Timestamp,
    pub desired: BTreeMap<SlotId, GenerationRef>,
    pub pre_push: BTreeMap<SlotId, Option<SlotAttemptState>>,
    pub slots: BTreeMap<SlotId, SlotAttemptState>,
}

impl LedgerIntentReport {
    /// Build the in-memory report from a verified domain intent, re-expanding
    /// the one selected table + frozen snapshot into the display-facing split
    /// maps. The intent's values are already scalar-gated by the wire → domain
    /// conversion, so no re-parsing is needed here.
    pub fn from_intent(i: &DeploymentIntent) -> Result<LedgerIntentReport> {
        let slot_ids: Vec<SlotId> = i.selected.keys().cloned().collect();
        // THE SELECTED SLOT'S DESIRED STATE IS ITS SNAPSHOT ENTRY: the
        // report's desired map re-expands each selected slot's generation +
        // artifact from the frozen resulting snapshot (selected ⊆ snapshot is
        // enforced by the conversion, so every selected key has an entry).
        let desired: BTreeMap<SlotId, GenerationRef> = i
            .selected
            .keys()
            .filter_map(|k| {
                let entry = i.resulting_snapshot.get(k)?;
                Some((
                    k.clone(),
                    GenerationRef {
                        generation: entry.generation().clone(),
                        assignment: PlacementSlotAssignment {
                            placement_slot: k.clone(),
                            artifact: entry.artifact().clone(),
                        },
                    },
                ))
            })
            .collect();
        let pre_push: BTreeMap<SlotId, Option<SlotAttemptState>> = i
            .selected
            .iter()
            .map(|(key, s)| {
                (
                    key.clone(),
                    s.pre_push.as_ref().map(|gr| SlotAttemptState {
                        artifact: Observation::Known(gr.assignment.artifact.clone()),
                        generation: Some(gr.generation.clone()),
                    }),
                )
            })
            .collect();
        Ok(LedgerIntentReport {
            deployment_id: i.deployment_id.clone(),
            target: i.target.clone(),
            group: i.group.clone(),
            slot_ids,
            behavior_sha256: i.behavior_sha256.clone(),
            attempted_at: i.attempted_at,
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

/// A DEFAULT valid intent for test fixtures: one slot `p1` at a deterministic
/// generation/artifact/binding, full push (`group: None`, selected ==
/// snapshot), no pre-push state. Fixtures override the fields they need via
/// struct-update syntax.
impl Default for DeploymentIntent {
    fn default() -> Self {
        let p1 = SlotId::parse("p1").unwrap();
        let artifact = ArtifactRef {
            release: ReleaseId::parse(
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
        let entries = BTreeMap::from([(
            p1.clone(),
            crate::ledger::SnapshotEntry::new(
                crate::identity::GenerationId::parse("gen-00000000-0000-7000-8000-000000000001")
                    .unwrap(),
                artifact,
                binding,
            ),
        )]);
        let snapshot = TargetSnapshot::from_entries(entries);
        DeploymentIntent {
            deployment_id: crate::identity::DeploymentId::parse(
                "deploy-00000000-0000-7000-8000-000000000001",
            )
            .unwrap(),
            target: TargetName::parse("t1").unwrap(),
            group: None,
            resulting_snapshot: snapshot,
            selected: NonEmptySlotTable::build(BTreeMap::from([(
                p1,
                SelectedSlotIntent { pre_push: None },
            )]))
            .expect("the default fixture has one slot"),
            behavior_sha256: BehaviorDigest::parse(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )
            .unwrap(),
            attempted_at: Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        }
    }
}
