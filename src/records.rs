//! Shared record structures persisted by the local store, the push engine, and
//! the deployment history / rollback subsystem.
//!
//! Assignment relationships are expressed exclusively through the canonical
//! model types ([`crate::model::ArtifactRef`],
//! [`crate::model::PlacementSlotAssignment`], [`crate::model::GenerationRef`])
//! rather than re-declared per record. Every slot→assignment map (ledger
//! intent `desired` / `pre_push`, terminal `outcomes`, the rollback payload)
//! is keyed by [`crate::model::PlacementSlotId`] — the deployment-location
//! identity — while [`crate::model::ServerId`] remains the actual-server
//! identity used for transport addressing (`ServerState`, config `ServerDef`).
//!
//! # ONE authoritative collection per record; WIRE → VERIFIED DOMAIN
//!
//! Every record keeps ONE authoritative collection and derives the rest
//! through methods (`membership()`, `releases()`, `behavior_digest()`); the
//! redundant on-disk members exist only in the WIRE types (the raw serde
//! shapes, [`LedgerIntentWire`], [`LedgerRollbackWire`], [`LedgerTerminalWire`],
//! [`DeploymentPlanWire`]) and are RECONCILED by a VERIFYING CONVERSION
//! (`Wire::into_domain`). The conversion checks that every duplicate
//! projection AGREES — e.g. the intent's `slot_ids` is DUPLICATE-FREE and
//! its `desired`/`pre_push` key sets EQUAL the authoritative `slot_ids`
//! membership EXACTLY (a missing or extra key, or a duplicated member id,
//! is a disagreement — an incomplete authoritative projection is never read
//! as if it were complete), each [`crate::model::GenerationRef`]'s assignment
//! names its own map key, the stored `behavior_sha256` equals the digest
//! derived from the behavior index, and the stored `desired_releases` equals
//! the releases derived from the per-slot artifacts. A disagreement is an
//! [`crate::error::Error::integrity`]
//! error (fail closed — a hand-constructed record can never put the
//! duplicates out of agreement, and the code then reads whichever projection
//! it happens to use). The rest of the codebase consumes ONLY the validated
//! domain types; the store's readers convert wire → domain on read and refuse
//! disagreeing records.
//!
//! # INTENT vs REPORT (outcomes are never part of the intent)
//!
//! The INTENT carries NO outcomes: the ledger's intent line keeps its `slots`
//! (actuals) map EMPTY (outcomes live in the terminal event's `outcomes` map
//! and the rollback payload), and the verified domain [`DeploymentIntent`] does
//! NOT carry an outcomes map at all — the wire keeps the empty member for
//! format stability, and the in-memory push REPORT ([`LedgerIntentReport`])
//! carries the observed per-slot actuals for display. Splitting the datatypes
//! means the report's `slots` map can never weaken the intent's key-set
//! invariant (`slot_ids == desired == pre_push`): it is simply not part of
//! the verified intent object.
//!
//! # ONE history ledger per target
//!
//! A target's ENTIRE deployment history lives in ONE ordered, append-only
//! JSONL file: `targets/<target>/ledger.jsonl`. There are exactly two
//! physical line kinds ([`LedgerLine`]):
//!
//! * [`LedgerLine::Intent`] — the DURABLE INTENT of one deployment
//!   ([`LedgerIntentWire`] → verified [`DeploymentIntent`]): deployment_id,
//!   target, behavior digest, membership, and the `desired` / `pre_push`
//!   per-slot maps. It is appended BEFORE any remote mutation (the
//!   append-attempt contract) and never edited. It carries NO status, NO
//!   outcomes, and NO rollback state.
//! * [`LedgerLine::Terminal`] — the TERMINAL EVENT of one deployment
//!   ([`LedgerTerminalWire`] → verified [`LedgerTerminal`]): the status, the
//!   per-slot OUTCOMES, and — when the deployment was SUCCESSFUL — the
//!   ROLLBACK STATE ([`LedgerRollbackWire`] → verified [`LedgerRollback`],
//!   the snapshot payload: per-slot generation refs + physical bindings).
//!   Appended once, after the mutation loop, and never edited.
//!
//! A merged [`LedgerEntry`] (intent + optional terminal) is the deployment's
//! full history record. The ledger's APPEND ORDER is the HISTORY ORDER: the
//! position of an intent line is the entry's `seq`; successful entries carry
//! an implicit rollback-chain position (`sN` = the Nth successful entry of
//! the CURRENT ledger — the ledger's append order, never a separately-minted
//! index). An entry WITHOUT a terminal is the CURRENT/INCOMPLETE state (the
//! deployment is in flight or crashed mid-finalization): its status is
//! `PendingCommit`-like (recoverable), it carries no outcomes/rollback, and
//! the next push reconciles it.
//!
//! The old multi-file model (immutable `attempts.jsonl` intents + the
//! `refs/snapshots.jsonl` op log with explicit indices + per-deployment
//! `results.json` / `transitions.jsonl` + the `history-floor.json` marker +
//! the `cleanup-pending.json` debt flag) is GONE: the ledger replaces all of
//! it. A checkpoint is an ATOMIC REPLACEMENT of the ledger with the retained
//! suffix (the floor is implicit — the ledger's first entry is the oldest
//! retained rollback state) followed by a best-effort global sweep of
//! unreachable deployment directories, release records, and tree objects
//! (see [`crate::store::history_floor`]).

use crate::error::{Error, Result};
use crate::model::{
    ArtifactRef, BehaviorContract, DeploymentId, GenerationId, GenerationRef, MatchingMembership,
    PlacementSlotAssignment, PlacementSlotId, ReleaseId, ServerId, TargetName, TreeDigest,
};
use crate::scalar::{BehaviorDigest, GroupName, Timestamp};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;

// ---------------------------------------------------------------------------
// DOMAIN SLOT TABLES: the membership + per-slot data are ONE table
// ---------------------------------------------------------------------------
//
// The DOMAIN intent collapses the wire's `slot_ids` / `desired` / `pre_push`
// split into a single authoritative slot→slot-data table, so the
// exact-key-set invariant (membership == desired keys == pre_push keys, no
// duplicates) becomes STRUCTURAL: a [`NonEmptySlotTable`] is non-empty and
// its keys are unique (a `BTreeMap` has no duplicate keys), so an intent can
// never carry a member slot without its desired/pre-push entries, or an
// entry for a non-member slot. The WIRE types keep the split on-disk shape;
// the wire → domain conversion builds the table and refuses disagreements
// exactly as before.

/// A possibly-empty ordered slot→value table keyed by
/// [`PlacementSlotId`] — the domain's keyed-by-slot collection type
/// (the possibly-empty variant of [`NonEmptySlotTable`], used for the
/// terminal's per-slot OUTCOMES, which are legitimately empty for a
/// pre-mutation failure). Uniqueness is structural (`BTreeMap` keys); the
/// table carries no other invariant. `Deref` exposes the underlying map so
/// indexing / iteration / `get` work transparently.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SlotTable<T>(BTreeMap<PlacementSlotId, T>);

impl<T> SlotTable<T> {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn from_map(map: BTreeMap<PlacementSlotId, T>) -> Self {
        Self(map)
    }

    pub fn into_map(self) -> BTreeMap<PlacementSlotId, T> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T> Deref for SlotTable<T> {
    type Target = BTreeMap<PlacementSlotId, T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A NON-EMPTY ordered slot→value table keyed by [`PlacementSlotId`] — the
/// domain's authoritative membership-bearing collection type (the
/// non-empty variant of [`SlotTable`], used for the deployment intent's
/// slots and the degraded disposition's remaining changes). The domain
/// invariant is STRUCTURAL: the key set is unique (`BTreeMap`) and
/// NON-EMPTY (the only constructor is the VERIFIED
/// [`NonEmptySlotTable::build`], which refuses the empty map — a deployment
/// that selects no slot cannot be represented). No duplicate/missing-key
/// state exists in the domain: a member slot always carries its desired +
/// pre-push entry, and no entry exists for a non-member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonEmptySlotTable<T>(BTreeMap<PlacementSlotId, T>);

impl<T> NonEmptySlotTable<T> {
    /// The VERIFIED constructor: refuse the empty map (fail closed — the
    /// domain cannot represent an empty deployment membership or an empty
    /// remaining-changes set). Uniqueness needs no check (`BTreeMap` keys
    /// are unique by construction).
    pub fn build(map: BTreeMap<PlacementSlotId, T>) -> Result<Self> {
        if map.is_empty() {
            return Err(Error::integrity(
                "a non-empty slot table cannot be empty — the domain refuses an empty deployment membership / remaining-changes set",
            ));
        }
        Ok(Self(map))
    }

    pub fn get(&self, key: &PlacementSlotId) -> Option<&T> {
        self.0.get(key)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn keys(&self) -> impl Iterator<Item = &PlacementSlotId> {
        self.0.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&PlacementSlotId, &T)> {
        self.0.iter()
    }

    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.0.values()
    }

    pub fn into_map(self) -> BTreeMap<PlacementSlotId, T> {
        self.0
    }
}

impl<T> Deref for NonEmptySlotTable<T> {
    type Target = BTreeMap<PlacementSlotId, T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentStatus {
    /// A deployment attempt is currently being executed, or was interrupted
    /// before its terminal event was appended (an intent-only ledger entry):
    /// a later push reconciles it before its own no-op check.
    InProgress,
    Successful,
    /// The commit markers are not all durable yet; a later push
    /// reconciles this attempt before its own no-op check.
    PendingCommit,
    FailedPreflight,
    FailedRolledBack,
    Degraded,
}

impl DeploymentStatus {
    pub fn is_terminal_failure(&self) -> bool {
        matches!(
            self,
            DeploymentStatus::FailedPreflight
                | DeploymentStatus::FailedRolledBack
                | DeploymentStatus::Degraded
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerOutcomeKind {
    Activated,
    Failed,
    /// Reserved: never emitted today. In-process compensation (a post-swap
    /// activation/verification failure restored by the per-server pipeline,
    /// step 11) is recorded as [`ServerOutcomeKind::Failed`] with
    /// `SlotResult.compensated = true` — "record both the failure and the
    /// compensation result" — and failure-policy compensation (step 13)
    /// upgrades the slot to [`ServerOutcomeKind::Restored`].
    Compensated,
    Skipped,
    Restored,
}

/// A per-slot assignment snapshot: the artifact a slot runs (or planned to
/// run) plus the generation it is bound to. `generation` is `None` when the
/// slot's server was never started (e.g. skipped after an earlier failure
/// under `stop_on_failure`), or when only the pre-push state is unknown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotAttemptState {
    pub artifact: ArtifactRef,
    /// The generation this slot actually advanced to. `None` when the slot's
    /// server was never started (e.g. skipped after an earlier failure under
    /// `stop_on_failure`).
    pub generation: Option<GenerationId>,
}

/// The WIRE shape of a durable intent line: the RAW serde form the ledger's
/// JSONL carries, holding every redundant member the domain reconciles (the
/// per-slot maps' key sets next to the authoritative `slot_ids` membership,
/// each [`crate::model::GenerationRef`]'s assignment slot next to its map
/// key). [`LedgerLine::Intent`] serializes this type; the ledger's wire
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
    pub slot_ids: Vec<PlacementSlotId>,
    pub behavior_sha256: String,
    pub attempted_at: String,
    /// Desired per-slot assignments (what the plan intended): each slot's
    /// minted generation for its planned artifact. The key set must equal
    /// `slot_ids` EXACTLY, and each `GenerationRef`'s assignment must name
    /// its own map key.
    pub desired: BTreeMap<PlacementSlotId, GenerationRef>,
    /// Pre-push per-slot state before mutation (`None` if first deployment).
    /// The key set must equal `slot_ids` EXACTLY.
    pub pre_push: BTreeMap<PlacementSlotId, Option<SlotAttemptState>>,
    /// Actual per-slot result after the attempt. The persisted ledger intent
    /// keeps this map EMPTY (outcomes are recorded in the terminal event's
    /// `outcomes` map); the in-memory REPORT ([`LedgerIntentReport`]) carries
    /// the observed actuals for display — the verified domain [`DeploymentIntent`]
    /// does NOT carry this map, so it is not part of the intent's key-set
    /// invariant. Every key must be a member of `slot_ids`.
    pub slots: BTreeMap<PlacementSlotId, SlotAttemptState>,
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
    /// [`crate::model::GenerationRef`]'s assignment must name its own map key,
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
            GroupName::parse(g).map_err(|_| {
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
        let mut seen: BTreeSet<&PlacementSlotId> = BTreeSet::new();
        for sid in &self.slot_ids {
            if !seen.insert(sid) {
                return Err(Error::integrity(format!(
                    "intent {}: slot_ids carries duplicate slot '{sid}' — the membership must be unique",
                    self.deployment_id
                )));
            }
        }
        let membership: BTreeSet<&PlacementSlotId> = self.slot_ids.iter().collect();
        let desired_keys: BTreeSet<&PlacementSlotId> = self.desired.keys().collect();
        let pre_push_keys: BTreeSet<&PlacementSlotId> = self.pre_push.keys().collect();
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
        // COLLAPSE the three projections into ONE table. The wire's per-slot
        // duplicate facts (the `GenerationRef`'s assignment slot, the
        // `pre_push` map key) are VERIFIED above and then dropped: the table
        // key owns the slot identity, so the domain stores each fact exactly
        // once (`DesiredGeneration` carries no redundant slot id, and
        // `PreviousGeneration` has no map-key claim of its own).
        let mut slots: BTreeMap<PlacementSlotId, IntentSlot> = BTreeMap::new();
        for (key, desired) in &self.desired {
            let pre_push =
                self.pre_push
                    .get(key)
                    .and_then(|p| p.clone())
                    .map(|p| PreviousGeneration {
                        artifact: p.artifact,
                        generation: p.generation,
                    });
            slots.insert(
                key.clone(),
                IntentSlot {
                    desired: DesiredGeneration {
                        generation: desired.generation.clone(),
                        artifact: desired.assignment.artifact.clone(),
                    },
                    pre_push,
                },
            );
        }
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
/// [`crate::model::GenerationRef`] with the REDUNDANT assignment slot
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
/// (`artifact`) and the generation it was on (`None` when only the pre-push
/// state is unknown / the slot was never deployed). The DOMAIN form of the
/// wire's [`SlotAttemptState`] under the table's name; the enclosing table
/// key owns the slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviousGeneration {
    pub artifact: ArtifactRef,
    pub generation: Option<GenerationId>,
}

/// The durable INTENT of one deployment attempt, the VALIDATED DOMAIN form
/// of [`LedgerIntentWire`]: what was planned and observed BEFORE any server
/// mutation. Appended once to the target's ledger ([`LedgerLine::Intent`])
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
/// [`crate::model::LEDGER_SCHEMA_VERSION`]); the validated domain does not
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
    pub fn membership(&self) -> Vec<PlacementSlotId> {
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
        let slot_ids: Vec<PlacementSlotId> = i.slots.keys().cloned().collect();
        let desired: BTreeMap<PlacementSlotId, GenerationRef> = i
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
        let pre_push: BTreeMap<PlacementSlotId, Option<SlotAttemptState>> = i
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
            deployment_schema_version: crate::model::LEDGER_SCHEMA_VERSION,
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
    /// [`GroupName`] (parsed from the verified intent's group string).
    pub group: Option<GroupName>,
    pub slot_ids: Vec<PlacementSlotId>,
    /// The attempt's behavior digest, as a validated [`BehaviorDigest`]
    /// (parsed from the wire's `behavior_sha256` string).
    pub behavior_sha256: BehaviorDigest,
    /// When the attempt was recorded, as a parsed RFC 3339 [`Timestamp`].
    pub attempted_at: Timestamp,
    /// Desired per-slot assignments, re-expanded from the domain table (the
    /// report is display-facing and keeps the wire's split shape).
    pub desired: BTreeMap<PlacementSlotId, GenerationRef>,
    pub pre_push: BTreeMap<PlacementSlotId, Option<SlotAttemptState>>,
    /// Actual per-slot result after the attempt, for display. The report is
    /// in-memory only — the persisted intent never carries this map.
    pub slots: BTreeMap<PlacementSlotId, SlotAttemptState>,
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
            Some(g) => Some(GroupName::parse(g).map_err(|_| {
                Error::integrity(format!(
                    "intent {}: rollout group {g:?} is not a valid group name",
                    i.deployment_id
                ))
            })?),
            None => None,
        };
        // Re-expand the ONE table into the display-facing split maps.
        let slot_ids: Vec<PlacementSlotId> = i.slots.keys().cloned().collect();
        let desired: BTreeMap<PlacementSlotId, GenerationRef> = i
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
        let pre_push: BTreeMap<PlacementSlotId, Option<SlotAttemptState>> = i
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

/// The complete PHYSICAL binding of one placement slot at terminal time: the
/// actual server ([`ServerId`]) AND the absolute `deploy_dir` on that server
/// where the slot's deployment state (objects, releases, generations,
/// `current`) lives. Together `{server, deploy_dir}` name the exact on-host
/// deployment location a terminal successful event's generations were
/// advanced on. Exact rollback must verify BOTH halves: a slot that keeps
/// its server but moves its `deploy_dir` would otherwise receive the
/// historical generations at the new location, silently deploying to the
/// wrong place on the same host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalBinding {
    /// The physical server the slot was bound to at the time of the
    /// deployment.
    pub server: ServerId,
    /// The absolute on-server directory the slot's deployment state lives
    /// in, exactly as declared in the slot's `deploy_dir` at deployment time.
    pub deploy_dir: String,
}

/// The ROLLBACK STATE carried by the terminal event of a SUCCESSFUL
/// deployment, the VALIDATED DOMAIN form: the snapshot payload of the attempt
/// — the complete per-slot [`GenerationRef`]s it advanced to (a successful
/// terminal always has a generation per slot) and the physical bindings
/// (`{server, deploy_dir}`) each slot had.
///
/// THERE IS NO SNAPSHOT-WIDE RELEASE/BEHAVIOR: each slot's [`GenerationRef`]
/// carries its OWN artifact binding (`release`, `variant`, `tree`), and a
/// PARTIAL snapshot can legitimately carry slots from DIFFERENT releases
/// (group pushes over time: group A pushed release R1, group B pushed
/// release R2, and the overlay snapshot keeps each slot's own artifact). The
/// referenced releases are DERIVED from `slots` ([`LedgerRollback::releases`])
/// — never stored once per snapshot — and rollback resolves EACH SLOT's
/// behavior from ITS OWN (release, variant) binding. Legacy ledger lines that
/// still carry the old snapshot-wide `behavior_sha256`/`release` members
/// deserialize into the WIRE form ([`LedgerRollbackWire`]), where the stored
/// `release` must equal the snapshot's ONE derived release (a disagreement
/// → `Error::integrity`); the legacy `behavior_sha256` is not derivable from
/// the per-slot payload (behavior contracts are not stored) and is carried
/// only for wire parseability, never interpreted.
///
/// `bindings` records the COMPLETE PHYSICAL BINDING each slot had when the
/// deployment ran. The snapshot maps a terminal's generations to slots by
/// SLOT, so without this map a slot that rebinds to a different server — or
/// moves to a different `deploy_dir` on the same server — in `deploy.toml`
/// would silently roll back onto the wrong host/location. The bindings key
/// set must equal the `slots` key set EXACTLY (every slotted generation has
/// a physical binding and vice versa — no missing, no extra binding keys):
/// a MISSING entry makes the binding unverifiable (rollback must never
/// guess the host), an EXTRA entry binds a slot that carried no generation,
/// and the wire → domain conversion REFUSES both at CONVERSION time —
/// before history rendering, rollback resolution, reconciliation, or the
/// GC sweep can consume the payload. Kept as a separate `#[serde(default)]`
/// field so the `slots` map and its [`GenerationRef`]s stay intact and
/// ledger lines without a bindings map still deserialize (the exact-key
/// conversion then refuses any payload whose slots are non-empty).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerRollback {
    /// Per-slot generation refs, keyed by [`PlacementSlotId`]. Each
    /// generation ref's assignment carries the slot's OWN artifact binding
    /// (`release`, `variant`, `tree`); the referenced releases are the set
    /// derived from these bindings ([`LedgerRollback::releases`]).
    pub slots: BTreeMap<PlacementSlotId, GenerationRef>,
    /// The complete physical binding (`{server, deploy_dir}`) each slot had
    /// at deployment time, keyed by [`PlacementSlotId`]. Every binding key
    /// must be a slotted generation (verified by the wire → domain
    /// conversion).
    #[serde(default)]
    pub bindings: BTreeMap<PlacementSlotId, PhysicalBinding>,
}

impl LedgerRollback {
    /// The distinct releases referenced by the snapshot's per-slot generation
    /// bindings — DERIVED from the authoritative `slots` map, never stored
    /// once per snapshot (a partial snapshot can legitimately span several
    /// releases).
    pub fn releases(&self) -> BTreeSet<ReleaseId> {
        self.slots
            .values()
            .map(|g| g.assignment.artifact.release.clone())
            .collect()
    }
}

/// The WIRE shape of a rollback payload: the snapshot's `slots` + `bindings`
/// plus the legacy snapshot-wide `behavior_sha256`/`release` members (carried
/// so pre-refactor ledger lines still deserialize; writers never emit them).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerRollbackWire {
    pub slots: BTreeMap<PlacementSlotId, GenerationRef>,
    #[serde(default)]
    pub bindings: BTreeMap<PlacementSlotId, PhysicalBinding>,
    /// Legacy snapshot-wide behavior digest. NOT derivable from the per-slot
    /// payload (behavior contracts are not stored) — carried only for wire
    /// parseability, never interpreted (per-slot behavior resolution governs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior_sha256: Option<String>,
    /// Legacy snapshot-wide release. When present it must equal the
    /// snapshot's ONE derived release (the conversion fails closed on a
    /// disagreement — a multi-release partial snapshot cannot be represented
    /// by the legacy single release).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<ReleaseId>,
}

impl LedgerRollbackWire {
    /// VERIFYING CONVERSION (wire → domain): every duplicate projection must
    /// agree — each slot's [`crate::model::GenerationRef`] assignment names
    /// its own map key, the `bindings` key set EQUALS the `slots` key set
    /// EXACTLY (every slotted generation has a physical binding and vice
    /// versa — no missing/extra binding keys), and the legacy snapshot-wide
    /// `release` (when present) equals the snapshot's ONE derived release.
    /// A disagreement → `Error::integrity`.
    pub fn into_domain(self) -> Result<LedgerRollback> {
        for (key, g) in &self.slots {
            if &g.assignment.placement_slot != key {
                return Err(Error::integrity(format!(
                    "rollback: generation for slot '{key}' names placement '{}'",
                    g.assignment.placement_slot
                )));
            }
        }
        // EXACT ROLLBACK BINDING KEYS (cross-field invariant): the
        // `bindings` key set must equal the `slots` key set EXACTLY. A
        // missing binding makes the slot's physical location unverifiable;
        // an extra binding names a slot with no generation. Both are
        // REFUSED here, at conversion time, before rollback resolution can
        // consume the payload (a hand-constructed or tampered record can
        // never be read as whichever projection a consumer happens to use).
        let slot_keys: BTreeSet<&PlacementSlotId> = self.slots.keys().collect();
        let binding_keys: BTreeSet<&PlacementSlotId> = self.bindings.keys().collect();
        if slot_keys != binding_keys {
            let missing: Vec<&PlacementSlotId> =
                slot_keys.difference(&binding_keys).copied().collect();
            let extra: Vec<&PlacementSlotId> =
                binding_keys.difference(&slot_keys).copied().collect();
            return Err(Error::integrity(format!(
                "rollback: bindings must key EXACTLY the slotted generations (missing bindings for {missing:?}; extra bindings for {extra:?})"
            )));
        }
        if let Some(legacy) = &self.release {
            let derived: BTreeSet<ReleaseId> = self
                .slots
                .values()
                .map(|g| g.assignment.artifact.release.clone())
                .collect();
            if derived.len() != 1 || !derived.contains(legacy) {
                return Err(Error::integrity(format!(
                    "rollback: legacy release '{legacy}' disagrees with the derived snapshot releases {derived:?}"
                )));
            }
        }
        Ok(LedgerRollback {
            slots: self.slots,
            bindings: self.bindings,
        })
    }
}

impl From<&LedgerRollback> for LedgerRollbackWire {
    fn from(r: &LedgerRollback) -> Self {
        LedgerRollbackWire {
            slots: r.slots.clone(),
            bindings: r.bindings.clone(),
            behavior_sha256: None,
            release: None,
        }
    }
}

/// The per-release, per-variant behavior contracts an attempt is bound to:
/// keyed by release id, then variant name. Historical and rollback pushes
/// resolve EACH SLOT's behavior from ITS OWN artifact binding
/// (`slot.assignment.artifact = {release, variant, tree}`) — the release
/// record's stored per-variant contract, verified against the release's
/// provenance digest — never a snapshot-wide single release. A partial
/// snapshot's slots can carry artifacts from DIFFERENT releases, so the
/// index spans every release the attempt's slots reference.
pub type BehaviorIndex = BTreeMap<ReleaseId, BTreeMap<String, BehaviorContract>>;

/// The per-slot OUTCOME of one slot during a deployment's mutation loop —
/// the existing [`SlotResult`] under the domain terminal's name (the domain
/// keeps the existing type; the OUTCOME OWN-KEY agreement — each outcome's
/// `slot_id` names its own table key — is verified by the wire → domain
/// conversion and by the ledger read, per the cross-field-invariants work).
pub type SlotOutcome = SlotResult;

/// The COMPLETE ROLLBACK payload of a SUCCESSFUL deployment — the existing
/// [`LedgerRollback`] under the domain terminal's name: the per-slot
/// generation refs + physical bindings the terminal event carries exactly
/// when the deployment was successful.
pub type CompleteRollback = LedgerRollback;

/// The COMPENSATION REPORT of a [`TerminalDisposition::FailedRolledBack`]
/// terminal — the existing per-slot outcomes table under the disposition's
/// name: each slot's result during the failed-then-rolled-back attempt
/// (which slots were compensated back and which compensation failed).
pub type CompensationReport = SlotTable<SlotOutcome>;

/// The DISPOSITION of a deployment's terminal event — the DOMAIN replaces
/// the wire's `status: String` + optional rollback TAG-PLUS-OPTIONAL-PAYLOAD
/// shape with an ENUM whose variants carry exactly the payload their
/// disposition allows, so the STATUS/ROLLBACK TRUTH TABLE is STRUCTURAL
/// (unrepresentable-invalid states simply do not exist in the domain):
///
/// * [`TerminalDisposition::Successful`] ALWAYS carries its complete
///   rollback payload (a successful deployment always records its rollback
///   state).
/// * [`TerminalDisposition::FailedPreflight`] carries NOTHING — a
///   pre-mutation failure cannot carry a rollback, and no slot was touched.
/// * [`TerminalDisposition::FailedRolledBack`] carries its COMPENSATION
///   REPORT (the per-slot results of the compensation pass).
/// * [`TerminalDisposition::Degraded`] carries its REMAINING CHANGES (the
///   slots that did not reach a restored state, each mapped to the
///   generation it recorded — derived from the wire outcomes).
///
/// The WIRE keeps the current `status` + `rollback` shape; the wire → domain
/// conversion maps every status to EXACTLY ONE disposition and refuses a
/// status whose payload does not match its disposition (a `Successful` with
/// no rollback, a failed status carrying a rollback, a `Degraded` with no
/// remaining changes, an `InProgress`/`PendingCommit` terminal — all are
/// conversion errors, fail closed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalDisposition {
    /// The deployment succeeded: the complete rollback payload (the full
    /// snapshot: per-slot generations + physical bindings).
    Successful { rollback: CompleteRollback },
    /// The attempt failed before any slot mutation: no payload (no
    /// rollback — and the conversion also refuses outcomes, since a
    /// pre-mutation failure touched no slot).
    FailedPreflight,
    /// The attempt failed after mutating slots and was rolled back: the
    /// compensation report — each slot's per-slot result of the
    /// compensation pass (which slots were restored and which compensation
    /// failed).
    FailedRolledBack { compensation: CompensationReport },
    /// The attempt ended degraded (some slots advanced and were not
    /// restored, or the commit could not be finalized): the REMAINING
    /// CHANGES — the slots that did not reach a restored state, each mapped
    /// to the generation it recorded (derived from the wire outcomes;
    /// NON-EMPTY by construction).
    Degraded {
        remaining_changes: NonEmptySlotTable<GenerationId>,
    },
}

impl TerminalDisposition {
    /// The disposition's status — the inverse of the wire's
    /// status→disposition mapping (a domain terminal derives its status
    /// from its disposition; the two are never stored side by side).
    pub fn status(&self) -> DeploymentStatus {
        match self {
            TerminalDisposition::Successful { .. } => DeploymentStatus::Successful,
            TerminalDisposition::FailedPreflight => DeploymentStatus::FailedPreflight,
            TerminalDisposition::FailedRolledBack { .. } => DeploymentStatus::FailedRolledBack,
            TerminalDisposition::Degraded { .. } => DeploymentStatus::Degraded,
        }
    }

    pub fn is_successful(&self) -> bool {
        matches!(self, TerminalDisposition::Successful { .. })
    }
}

/// The TERMINAL EVENT of one deployment, the VALIDATED DOMAIN form of
/// [`LedgerTerminalWire`]. Appended ONCE to the target's ledger after the
/// mutation loop; the entry's current status is the status of its terminal
/// event (an entry WITHOUT a terminal is the recoverable in-progress /
/// pending-commit state).
///
/// LET THE ENCLOSING OBJECT OWN IDENTITY: the domain terminal does NOT carry
/// `deployment_id` / `target` — the merged [`LedgerEntry`] owns them (the
/// intent's, verified equal by the reader when the terminal merges into its
/// entry). The terminal's own shape is the disposition enum: the
/// status/rollback TRUTH TABLE is STRUCTURAL (see [`TerminalDisposition`])
/// — an invalid status/payload combination is unrepresentable. `reason`
/// carries optional human context (e.g. "push completed", "recovery
/// finalized", "preflight failed") — a single fact for display, not a
/// duplicated projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerTerminal {
    /// When the terminal event was recorded (RFC 3339).
    pub recorded_at: String,
    /// Actual per-slot outcomes after the mutation loop, the domain
    /// [`SlotTable`] (possibly empty — a pre-mutation failure touched no
    /// slot). The per-slot outcomes of a failed-then-rolled-back terminal
    /// are ALSO the disposition's compensation report (see
    /// [`TerminalDisposition::FailedRolledBack`]).
    pub outcomes: SlotTable<SlotOutcome>,
    /// HOW the attempt ended — the enum whose variants carry exactly their
    /// payload (the truth table is structural).
    pub disposition: TerminalDisposition,
    /// Optional human context: why this terminal event happened.
    pub reason: Option<String>,
}

impl LedgerTerminal {
    /// The terminal's status, DERIVED from its disposition (never stored
    /// separately — a status and a disposition can never disagree).
    pub fn status(&self) -> DeploymentStatus {
        self.disposition.status()
    }
}

/// The WIRE shape of a terminal event — the RAW serde form the ledger's
/// JSONL carries: the current `status` + optional `rollback`
/// tag-plus-optional-payload shape, plus the deployment/target identity the
/// ENTRY owns in the domain (the wire keeps them; the conversion and the
/// reader verify they equal the enclosing entry's). The terminal's own
/// duplicates — the STATUS/ROLLBACK TRUTH TABLE (`Successful` ⇔ rollback
/// present) and each outcome's value naming its own key — are verified by
/// the conversion; the CROSS-RECORD agreement (outcome key set vs the
/// intent's authoritative `slot_ids`, the `target` field vs the read path
/// and the intent) is enforced where the intent and terminal merge
/// ([`crate::store::local::LocalStore::read_ledger`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerTerminalWire {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    pub status: DeploymentStatus,
    pub recorded_at: String,
    pub outcomes: BTreeMap<PlacementSlotId, SlotResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback: Option<LedgerRollbackWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl LedgerTerminalWire {
    /// VERIFYING CONVERSION (wire → domain): the rollback payload is
    /// converted through [`LedgerRollbackWire::into_domain`] (which fails
    /// closed on any disagreement), the STATUS/ROLLBACK TRUTH TABLE is
    /// enforced (`Successful` always records its rollback state; every other
    /// status never carries one), and each outcome's value must name its OWN
    /// map key (the outcome's `slot_id` is the placement slot it records). A
    /// disagreement → `Error::integrity`. The cross-record claims (outcome
    /// key set vs the intent's `slot_ids`, and the `target` field vs the
    /// read path / intent) are enforced by the ledger read that merges the
    /// intent and the terminal ([`crate::store::local::LocalStore::read_ledger`]).
    pub fn into_domain(self) -> Result<LedgerTerminal> {
        // The recorded timestamp must parse as RFC 3339 (fail closed).
        Timestamp::parse(&self.recorded_at).map_err(|_| {
            Error::integrity(format!(
                "terminal {}: recorded_at {:?} is not an RFC 3339 timestamp",
                self.deployment_id, self.recorded_at
            ))
        })?;
        let rollback = match self.rollback {
            Some(wire) => Some(wire.into_domain()?),
            None => None,
        };
        // OUTCOME OWN-KEY AGREEMENT (self-contained half): each outcome's
        // value names ITS OWN map key — an outcome for a different slot is a
        // disagreement. (The other half — the outcome KEY SET vs the
        // intent's authoritative membership — is cross-record and lives in
        // the ledger read that merges intent + terminal.)
        for (key, result) in &self.outcomes {
            if &result.slot_id != key {
                return Err(Error::integrity(format!(
                    "terminal {}: outcome for slot '{key}' names placement '{}'",
                    self.deployment_id, result.slot_id
                )));
            }
        }
        let outcomes = SlotTable::from_map(self.outcomes);
        // STATUS → DISPOSITION: each status maps to exactly one disposition,
        // and a status whose payload does not match its disposition is a
        // conversion error (fail closed).
        let disposition = match (&self.status, rollback) {
            (DeploymentStatus::Successful, Some(rollback)) => {
                TerminalDisposition::Successful { rollback }
            }
            (DeploymentStatus::Successful, None) => {
                return Err(Error::integrity(format!(
                    "terminal {}: status Successful requires the complete rollback payload — a successful deployment always records its rollback state",
                    self.deployment_id
                )));
            }
            (DeploymentStatus::FailedPreflight, None) => {
                if !outcomes.is_empty() {
                    return Err(Error::integrity(format!(
                        "terminal {}: status FailedPreflight must carry NO outcomes (a pre-mutation failure touched no slot)",
                        self.deployment_id
                    )));
                }
                TerminalDisposition::FailedPreflight
            }
            (DeploymentStatus::FailedPreflight, Some(_)) => {
                return Err(Error::integrity(format!(
                    "terminal {}: status FailedPreflight must not carry a rollback payload (only Successful does)",
                    self.deployment_id
                )));
            }
            (DeploymentStatus::FailedRolledBack, None) => {
                // The compensation report IS the outcome table: the record
                // of what the compensation pass did to each slot.
                TerminalDisposition::FailedRolledBack {
                    compensation: outcomes.clone(),
                }
            }
            (DeploymentStatus::FailedRolledBack, Some(_)) => {
                return Err(Error::integrity(format!(
                    "terminal {}: status FailedRolledBack must not carry a rollback payload (only Successful does)",
                    self.deployment_id
                )));
            }
            (DeploymentStatus::Degraded, None) => {
                // REMAINING CHANGES: the slots whose outcome did NOT restore
                // (compensated back), each mapped to the generation it
                // recorded. Derived from the wire outcomes; NON-EMPTY by
                // construction (a degraded terminal with every slot restored
                // — or with no recorded outcome — has no remaining change and
                // is refused: a status whose payload does not match its
                // disposition).
                let remaining: BTreeMap<PlacementSlotId, GenerationId> = outcomes
                    .iter()
                    .filter(|(_, r)| {
                        r.outcome != ServerOutcomeKind::Restored && r.generation.is_some()
                    })
                    .map(|(key, r)| {
                        (
                            key.clone(),
                            r.generation.clone().expect(
                                "a non-restored outcome whose generation is Some (filtered above)",
                            ),
                        )
                    })
                    .collect();
                TerminalDisposition::Degraded {
                    remaining_changes: NonEmptySlotTable::build(remaining).map_err(|_| {
                        Error::integrity(format!(
                            "terminal {}: status Degraded requires at least one REMAINING change (a non-restored outcome with a recorded generation)",
                            self.deployment_id
                        ))
                    })?,
                }
            }
            (DeploymentStatus::Degraded, Some(_)) => {
                return Err(Error::integrity(format!(
                    "terminal {}: status Degraded must not carry a rollback payload (only Successful does)",
                    self.deployment_id
                )));
            }
            (DeploymentStatus::InProgress | DeploymentStatus::PendingCommit, _) => {
                return Err(Error::integrity(format!(
                    "terminal {}: status {:?} never appears on a terminal event (it is the recoverable intent-only state)",
                    self.deployment_id, self.status
                )));
            }
        };
        Ok(LedgerTerminal {
            recorded_at: self.recorded_at,
            outcomes,
            disposition,
            reason: self.reason,
        })
    }

    /// Build the WIRE form of a domain terminal for a given (deployment,
    /// target) identity — the enclosing [`LedgerEntry`] owns the identity,
    /// so the wire's `deployment_id` / `target` come from the CALLER (the
    /// append path), never from the domain terminal.
    pub fn from_domain(
        deployment_id: &DeploymentId,
        target: &TargetName,
        t: &LedgerTerminal,
    ) -> Self {
        let rollback = match &t.disposition {
            TerminalDisposition::Successful { rollback } => {
                Some(LedgerRollbackWire::from(rollback))
            }
            _ => None,
        };
        LedgerTerminalWire {
            deployment_id: deployment_id.clone(),
            target: target.clone(),
            status: t.disposition.status(),
            recorded_at: t.recorded_at.clone(),
            outcomes: t.outcomes.clone().into_map(),
            rollback,
            reason: t.reason.clone(),
        }
    }
}

/// ONE physical line of a target's deployment ledger — the WIRE enum: the
/// raw serde shapes ([`LedgerIntentWire`], [`LedgerTerminalWire`]) exactly as
/// the append-only JSONL stream carries them. The ledger is append-only: each
/// deployment contributes at most one [`LedgerLine::Intent`] (written BEFORE
/// any remote mutation) and at most one [`LedgerLine::Terminal`] (appended
/// when the deployment completes). The line ORDER is the history order.
/// [`crate::store::local::LocalStore::read_ledger`] parses these wire lines,
/// runs the VERIFYING CONVERSION (refusing disagreeing records), and merges
/// the validated domain records into [`LedgerEntry`]s keyed by deployment id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LedgerLine {
    /// The durable intent of one deployment, written before any remote
    /// mutation (the append-attempt contract).
    Intent(LedgerIntentWire),
    /// The terminal event of one deployment, appended after the mutation
    /// loop.
    Terminal(LedgerTerminalWire),
}

/// A merged deployment entry of the target's ledger: the durable INTENT plus
/// the optional TERMINAL EVENT (absent while the deployment is in flight or
/// recoverable-pending). The append order is the history order; `seq` is the
/// position of the intent line in the ledger. Only VALIDATED domain records
/// ([`DeploymentIntent`], [`LedgerTerminal`]) live here — never raw wire shapes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerEntry {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    pub intent: DeploymentIntent,
    pub terminal: Option<LedgerTerminal>,
    /// The position of this entry's intent line in the ledger (0-based
    /// append order — the entry's history position).
    pub seq: u64,
}

/// A durable pin: retained artifact CONTENT, store-global (a release or
/// binding is shared by every target that references it, so a pin protects
/// it everywhere). Persisted at `<base>/pins.json`; the artifact garbage
/// collector ([`crate::store::gc`]) folds every pin into the retained
/// binding set BEFORE it unlinks anything, so a pinned release record and
/// tree object are never deleted. These STORE-LEVEL pins are DISTINCT from
/// the rotation subsystem's project-file `[[pins]]`
/// ([`crate::config::Pin`]): the checkpoint flow is store-only (it never
/// loads the caller's `deploy.toml`), so its retention anchors live in the
/// store, while rotation's config pins protect the REMOTE retained set and
/// are never consulted by the local GC.
///
/// PINS RETAIN ARTIFACT CONTENT ONLY. A pin is a pure retention anchor for
/// the artifact store — it never creates, keeps, or reinserts a deployment
/// in any target's ledger, and it never extends a target's retained
/// history. The checkpoint's retained set is the LEDGER SUFFIX alone (the
/// first retained ledger entry is the oldest rollback state), so pinning
/// the artifacts of a pre-retention deployment keeps the bytes but NEVER
/// the history.
///
/// Two pin forms (both supported, mix freely):
///
/// * `releases` — a RELEASE pin: retains the whole release record AND
///   every variant/tree binding in that record (the GC expands the record's
///   `variants` map). The canonical `rel-sha256-<digest>` id is required
///   (accepted as a bare digest too via [`crate::model::ReleaseId::parse`]);
///   a release pin whose record is missing fails the GC closed (the pin
///   cannot be expanded — nothing is deleted that run).
/// * `bindings` — an EXACT BINDING pin: one (release, variant, tree)
///   [`ArtifactRef`], which keeps that release record and that tree object.
///
/// `schema_version` is exactly [`crate::model::PINS_SCHEMA_VERSION`];
/// readers refuse any other version (fail closed).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pins {
    pub schema_version: u32,
    /// Whole-release pins: every variant/tree in each named release record
    /// is retained (release pins expand via the release record's `variants`
    /// map at GC time).
    #[serde(default)]
    pub releases: Vec<ReleaseId>,
    /// Exact-binding pins: each `(release, variant, tree)` retains exactly
    /// that release record + tree object.
    #[serde(default)]
    pub bindings: Vec<ArtifactRef>,
}

/// Observed remote state for one placement slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ObservedSlot {
    #[serde(default)]
    pub generation: Option<GenerationId>,
    #[serde(default)]
    pub artifact: Option<ArtifactRef>,
    #[serde(default)]
    pub last_deployment: Option<DeploymentId>,
}

/// Observed remote state for a whole target (`observed.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ObservedTarget {
    pub target: TargetName,
    #[serde(default)]
    pub slots: BTreeMap<PlacementSlotId, ObservedSlot>,
}

/// Persisted per-server local record (`servers/<id>.json`). Keyed by the
/// ACTUAL server identity ([`ServerId`], transport addressing); the
/// slot→assignment maps live in [`ObservedTarget`] keyed by
/// [`PlacementSlotId`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ServerState {
    pub id: ServerId,
    #[serde(default)]
    pub last_seen_target: Option<TargetName>,
    #[serde(default)]
    pub last_observed: Option<ObservedSlot>,
}

/// Where a plan's desired assignment comes from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanSource {
    /// Materialize the currently mapped local files and assign each slot its
    /// target-configured (current) variant.
    Head,
    /// Restore the stored state of a successful deployment, keyed by its
    /// deployment id (`deploy push <target> <deployment-id>` and the
    /// `@` / `parent(...)` deployment-history walk): the rollback state
    /// resolved from the target's ledger.
    DeploymentRef(DeploymentId),
    /// Assign each current slot its variant from a named release — the
    /// release's OWN frozen topology applied onto the CURRENT physical
    /// slots. The rebinding this performs is EXPLICIT: the plan carries it
    /// as [`DeploymentPlan::rebinding`] ([`RebindingPlan`]), recording the
    /// frozen slot→variant/group topology, the logical membership check,
    /// and the current physical slots it binds onto.
    ReleaseRef(ReleaseId),
}

/// The logical topology one slot is FROZEN into inside a release record:
/// which variant declares the slot and which rollout groups it belongs to
/// (the declaring variant file names the slot; a slot can belong to several
/// groups or none). This is the slot→variant/group half of a release's
/// temporal source — a `release:<id>` push resolves each slot's variant
/// from THIS frozen map, never the caller's current variant files.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenSlotTopology {
    /// The variant that declares the slot in the release's canonical slot
    /// snapshot (`ReleaseRecord.slots` is keyed by variant name).
    pub variant: String,
    /// The rollout groups the slot belongs to within its owning target
    /// (empty when the slot is not grouped).
    #[serde(default)]
    pub groups: Vec<String>,
}

/// The membership proof backing a historical-release rebinding: the PROOF
/// ([`MatchingMembership`]) that the release's FROZEN slot-id membership for
/// the destination target and the target's CURRENT slot-id membership were
/// verified EXACTLY EQUAL before planning proceeded (the only construction
/// path is [`MatchingMembership::verify`], so a [`RebindingPlan`] can only
/// record an already-verified agreement). The proof carries the agreed
/// NON-EMPTY slot set; the comparison is LOGICAL membership only — slot IDs,
/// never physical bindings (server / deploy_dir) — so two sets may be
/// identical while every physical binding differs.
///
/// The serialized form is the agreed slot set (the persisted wire replay of
/// the verified proof).
///
/// An EXPLICIT record that a `release:<id>` push is REBINDING a historical
/// release's frozen topology onto the CURRENT physical slots.
///
/// The temporal-source rule names four sources — HEAD (current variant slot
/// declarations), `release:<id>` (that release's frozen slot→variant and
/// group topology), a deployment rollback (that deployment's exact per-slot
/// artifact and physical binding), and the current server configuration
/// (connectivity and live capacity ONLY, never topology). A direct release
/// push is the one historically IMPLICIT exception: it applies the frozen
/// release topology onto the CURRENT target's slots, so the physical
/// rebinding happened without being named. This plan makes it explicit: it
/// records the release, the destination target, the frozen
/// slot→variant/group topology, the LOGICAL membership check (physical
/// bindings MAY differ; the logical membership MUST match), and the CURRENT
/// physical slots (`{server, deploy_dir}`) the frozen topology is bound
/// onto. Produced at plan time in the `PushRef::Release` branch and recorded
/// in [`DeploymentPlan::rebinding`]; HEAD and deployment-keyed plans carry
/// `None`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebindingPlan {
    /// The historical release being rebound.
    pub release: ReleaseId,
    /// The destination target the release is rebound onto.
    pub target: TargetName,
    /// The release's frozen slot→variant/group topology, filtered to the
    /// destination target (from the release record's OWN canonical slot
    /// snapshot). Complete regardless of group selection: a `--group` push
    /// narrows the PLANNED assignments, never the recorded topology.
    pub frozen_topology: BTreeMap<PlacementSlotId, FrozenSlotTopology>,
    /// The membership PROOF that ran before planning (see
    /// [`MatchingMembership`]): `frozen == current` verified (slot IDs only;
    /// physical bindings may differ). For a group push this is the COMPLETE
    /// membership — the group narrows the planned slots, never the
    /// membership check.
    pub(crate) membership: MatchingMembership,
    /// The CURRENT physical slots the frozen topology is bound onto, per
    /// PLANNED slot: `slot -> {server, deploy_dir}` from the caller's
    /// current configuration. A group selection records exactly the selected
    /// slots (the group-filtered assignments); a full push records every
    /// member slot.
    pub current_physical_slots: BTreeMap<PlacementSlotId, PhysicalBinding>,
}

/// Per-slot plan for one placement slot: its slot identity, the artifact it
/// should run, and the compare-and-swap preconditions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotPlan {
    pub slot_id: PlacementSlotId,
    pub artifact: ArtifactRef,
    /// Pre-push generation that must match for the compare-and-swap precondition.
    pub expected_generation: Option<GenerationId>,
    pub expected_tree: Option<TreeDigest>,
}

/// The WIRE shape of a deployment plan (`deployments/<id>/plan.json`): the
/// raw serde form holding the REDUNDANT members the domain reconciles away —
/// `slot_ids` next to the authoritative per-slot `slots` map, `behavior_sha256`
/// next to the authoritative `behaviors` index, `desired_releases` next to the
/// releases derived from the per-slot artifacts. The on-disk plan keeps the
/// redundant shape (the write path serializes the domain through this wire
/// form); the VERIFYING CONVERSION ([`DeploymentPlanWire::into_domain`])
/// checks every duplicate projection and exposes only the validated
/// [`DeploymentPlan`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentPlanWire {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    /// The stored snapshot-wide behavior digest; must equal the digest
    /// derived from `behaviors` (the authoritative index).
    pub behavior_sha256: String,
    /// The frozen, per-release name-keyed activation + verification contracts
    /// this attempt is bound to — THE AUTHORITATIVE BEHAVIOR COLLECTION (the
    /// digest is derived from it).
    pub behaviors: BehaviorIndex,
    /// The selected placement slots; the DEDUPLICATED SET must equal the
    /// `slots` map's key set (the authoritative membership).
    pub slot_ids: Vec<PlacementSlotId>,
    pub slots: BTreeMap<PlacementSlotId, SlotPlan>,
    pub source: PlanSource,
    /// When the plan was built from a DIRECT release reference
    /// (`PlanSource::ReleaseRef`), the explicit rebinding context: the
    /// historical release's frozen topology applied onto the CURRENT
    /// physical slots ([`RebindingPlan`]). `None` for HEAD and
    /// deployment-keyed plans. `#[serde(default)]` keeps deployment records
    /// written before this field loadable; `skip_serializing_if` keeps the
    /// recorded wire shape unchanged for plans that carry no rebinding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebinding: Option<RebindingPlan>,
    /// The releases this attempt's slots reference; must equal the set
    /// derived from the per-slot artifacts (a partial snapshot can span
    /// several releases).
    pub desired_releases: BTreeSet<ReleaseId>,
}

impl DeploymentPlanWire {
    /// VERIFYING CONVERSION (wire → domain): every duplicate projection must
    /// agree — the `slot_ids` set (deduplicated) equals the `slots` map keys,
    /// every `SlotPlan` names its own map key, `desired_releases` equals
    /// the releases derived from the per-slot artifacts, and
    /// `behavior_sha256` equals the canonical digest of `behaviors`. A
    /// disagreement → `Error::integrity` (fail closed).
    pub fn into_domain(self) -> Result<DeploymentPlan> {
        // The stored behavior digest must be a sha256 digest before it can
        // even be compared with the digest derived from `behaviors` (fail
        // closed: a tampered non-digest is refused on format, not just on
        // disagreement).
        BehaviorDigest::parse(&self.behavior_sha256).map_err(|_| {
            Error::integrity(format!(
                "plan {}: stored behavior_sha256 {:?} is not a sha256 digest",
                self.deployment_id, self.behavior_sha256
            ))
        })?;
        let wire_slots: BTreeSet<&PlacementSlotId> = self.slot_ids.iter().collect();
        let keys: BTreeSet<&PlacementSlotId> = self.slots.keys().collect();
        if wire_slots != keys {
            return Err(Error::integrity(format!(
                "plan {}: slot_ids {:?} disagrees with the per-slot plan keys {:?}",
                self.deployment_id, wire_slots, keys
            )));
        }
        for (key, plan) in &self.slots {
            if &plan.slot_id != key {
                return Err(Error::integrity(format!(
                    "plan {}: per-slot plan for '{key}' names slot '{}'",
                    self.deployment_id, plan.slot_id
                )));
            }
        }
        let releases: BTreeSet<ReleaseId> = self
            .slots
            .values()
            .map(|p| p.artifact.release.clone())
            .collect();
        if self.desired_releases != releases {
            return Err(Error::integrity(format!(
                "plan {}: desired_releases {:?} disagrees with the derived releases {:?}",
                self.deployment_id, self.desired_releases, releases
            )));
        }
        let digest = crate::release::behavior_index_digest(&self.behaviors);
        if self.behavior_sha256 != digest {
            return Err(Error::integrity(format!(
                "plan {}: stored behavior_sha256 disagrees with the derived digest of the behavior index",
                self.deployment_id
            )));
        }
        Ok(DeploymentPlan {
            deployment_id: self.deployment_id,
            target: self.target,
            behaviors: self.behaviors,
            slots: self.slots,
            source: self.source,
            rebinding: self.rebinding,
        })
    }
}

impl From<&DeploymentPlan> for DeploymentPlanWire {
    fn from(p: &DeploymentPlan) -> Self {
        DeploymentPlanWire {
            deployment_id: p.deployment_id.clone(),
            target: p.target.clone(),
            behavior_sha256: p.behavior_digest(),
            behaviors: p.behaviors.clone(),
            slot_ids: p.membership().cloned().collect(),
            slots: p.slots.clone(),
            source: p.source.clone(),
            rebinding: p.rebinding.clone(),
            desired_releases: p.releases(),
        }
    }
}

/// A deployment plan, the VALIDATED DOMAIN form of [`DeploymentPlanWire`]:
/// the attempt's snapshot-wide behavior digest, the frozen per-release
/// name-keyed activation + verification contracts, and the per-slot plans.
/// ONE AUTHORITATIVE COLLECTION PER CONCEPT — `slots` (per-slot plans) is
/// the membership AND the release source; `behaviors` (the index) is the
/// behavior source. The `slot_ids` / `desired_releases` / `behavior_sha256`
/// members exist only in the wire (the serialized `plan.json` keeps the
/// redundant shape) and are derived here through
/// [`DeploymentPlan::membership`], [`DeploymentPlan::releases`],
/// [`DeploymentPlan::behavior_digest`] — the verified conversion guarantees
/// they agree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentPlan {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    /// The frozen, per-release name-keyed activation + verification contracts
    /// this attempt is bound to, one per declared variant per referenced
    /// release — THE AUTHORITATIVE BEHAVIOR COLLECTION (the digest is
    /// derived from it). Historical and rollback pushes carry the historical
    /// contracts here rather than the caller's current configuration.
    pub behaviors: BehaviorIndex,
    /// THE AUTHORITATIVE PER-SLOT COLLECTION: the selected slots (the map
    /// keys are the membership) and their plans (their artifacts are the
    /// release source).
    pub slots: BTreeMap<PlacementSlotId, SlotPlan>,
    pub source: PlanSource,
    /// When the plan was built from a DIRECT release reference
    /// (`PlanSource::ReleaseRef`), the explicit rebinding context: the
    /// historical release's frozen topology applied onto the CURRENT
    /// physical slots ([`RebindingPlan`]). `None` for HEAD and
    /// deployment-keyed plans.
    pub rebinding: Option<RebindingPlan>,
}

impl DeploymentPlan {
    /// The plan's membership: the selected placement slots, DERIVED from the
    /// authoritative `slots` map (its keys) — never stored separately.
    pub fn membership(&self) -> impl Iterator<Item = &PlacementSlotId> {
        self.slots.keys()
    }

    /// The distinct releases the plan's slots reference (per-slot artifact
    /// provenance: a partial snapshot can span several releases) — DERIVED
    /// from the authoritative `slots` map, never stored separately.
    pub fn releases(&self) -> BTreeSet<ReleaseId> {
        self.slots
            .values()
            .map(|p| p.artifact.release.clone())
            .collect()
    }

    /// The attempt's snapshot-wide behavior digest: the canonical digest of
    /// the [`BehaviorIndex`] the attempt is bound to — DERIVED from the
    /// authoritative `behaviors` index, never stored separately.
    pub fn behavior_digest(&self) -> String {
        crate::release::behavior_index_digest(&self.behaviors)
    }
}

impl Serialize for DeploymentPlan {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        DeploymentPlanWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DeploymentPlan {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = DeploymentPlanWire::deserialize(deserializer)?;
        wire.into_domain()
            .map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotResult {
    pub slot_id: PlacementSlotId,
    pub outcome: ServerOutcomeKind,
    /// The generation this slot advanced to, or `None` if it never started.
    pub generation: Option<GenerationId>,
    pub compensated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PlacementSlotAssignment, VariantName};
    use crate::store::local::LocalStore;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    // ---- fixtures ----------------------------------------------------------

    fn slot(i: u32) -> PlacementSlotId {
        PlacementSlotId::new(format!("slot-{i}"))
    }

    fn slot_strategy() -> impl Strategy<Value = PlacementSlotId> {
        (0u32..6).prop_map(slot)
    }

    fn binding(sid: &PlacementSlotId) -> PhysicalBinding {
        PhysicalBinding {
            server: ServerId::new("s1".to_string()),
            deploy_dir: format!("/srv/deploy/{}", sid.as_str()),
        }
    }

    /// A generation ref whose assignment names its own key (the agreeing
    /// form); the artifact's release is derived from the slot id.
    fn gen_ref_for(key: &PlacementSlotId) -> GenerationRef {
        GenerationRef {
            generation: GenerationId::new(format!("gen-{}", key.as_str())),
            assignment: PlacementSlotAssignment {
                placement_slot: key.clone(),
                artifact: ArtifactRef {
                    release: ReleaseId::new(format!("rel-{}", key.as_str())),
                    variant: VariantName::new("standard".to_string()),
                    tree: TreeDigest::new(format!("tree-{}", key.as_str())),
                },
            },
        }
    }

    // ---- agreeing (base) wire strategies -----------------------------------
    //
    // Every base wire is deterministic in its AGREED projections: a
    // NON-EMPTY duplicate-free membership K, `slot_ids` = K (deployment
    // order), `desired`/`pre_push` = K with agreeing per-slot payloads, the
    // wire `slots` (actuals) map EMPTY (the persisted intent carries no
    // outcomes), and a terminal whose deployment_id/target EQUAL the
    // intent's, whose outcome keys are members of K, and whose status →
    // disposition payload matches (Successful ⇔ rollback, FailedPreflight ⇔
    // no outcomes, Degraded ⇔ non-restored outcomes). The property then
    // mutates ONE field at a time and asserts the conversion / reader fails
    // closed on EVERY tamper while accepting the untampered record.

    fn agreeing_intent(keys: &[PlacementSlotId]) -> LedgerIntentWire {
        let desired: BTreeMap<PlacementSlotId, GenerationRef> =
            keys.iter().map(|k| (k.clone(), gen_ref_for(k))).collect();
        let pre_push: BTreeMap<PlacementSlotId, Option<SlotAttemptState>> =
            keys.iter().map(|k| (k.clone(), None)).collect();
        LedgerIntentWire {
            deployment_schema_version: crate::model::LEDGER_SCHEMA_VERSION,
            deployment_id: DeploymentId::new("deploy-w".to_string()),
            target: TargetName::new("t1".to_string()),
            group: None,
            slot_ids: keys.to_vec(),
            behavior_sha256: "sha256-w".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired,
            pre_push,
            slots: BTreeMap::new(),
        }
    }

    fn outcome_for(key: &PlacementSlotId, kind: ServerOutcomeKind) -> SlotResult {
        let compensated = matches!(&kind, ServerOutcomeKind::Restored);
        SlotResult {
            slot_id: key.clone(),
            outcome: kind,
            generation: Some(GenerationId::new(format!("gen-{}", key.as_str()))),
            compensated,
            error: None,
        }
    }

    /// A terminal wire AGREEING with its intent (identity + outcome-key
    /// membership + status→disposition payload). `status_idx` selects the
    /// status: 0 Successful (complete rollback over the membership), 1
    /// FailedPreflight (no outcomes, no rollback), 2 FailedRolledBack
    /// (outcomes = the compensation report), 3 Degraded (non-restored
    /// outcomes over the membership → non-empty remaining changes).
    fn agreeing_terminal(keys: &[PlacementSlotId], status_idx: u32) -> LedgerTerminalWire {
        let deployment_id = DeploymentId::new("deploy-w".to_string());
        let target = TargetName::new("t1".to_string());
        match status_idx {
            // Successful: EVERY member slot recorded Activated, and the
            // COMPLETE rollback payload covers the same membership with
            // exact bindings.
            0 => LedgerTerminalWire {
                deployment_id: deployment_id.clone(),
                target: target.clone(),
                status: DeploymentStatus::Successful,
                recorded_at: "2026-01-01T00:00:00Z".to_string(),
                outcomes: keys
                    .iter()
                    .map(|k| (k.clone(), outcome_for(k, ServerOutcomeKind::Activated)))
                    .collect(),
                rollback: Some(LedgerRollbackWire {
                    slots: keys.iter().map(|k| (k.clone(), gen_ref_for(k))).collect(),
                    bindings: keys.iter().map(|k| (k.clone(), binding(k))).collect(),
                    behavior_sha256: None,
                    release: None,
                }),
                reason: Some("push completed".to_string()),
            },
            // FailedPreflight: pre-mutation — NO outcomes, NO rollback.
            1 => LedgerTerminalWire {
                deployment_id,
                target,
                status: DeploymentStatus::FailedPreflight,
                recorded_at: "2026-01-01T00:00:00Z".to_string(),
                outcomes: BTreeMap::new(),
                rollback: None,
                reason: Some("preflight failed".to_string()),
            },
            // FailedRolledBack: the outcome table IS the compensation
            // report.
            2 => LedgerTerminalWire {
                deployment_id,
                target,
                status: DeploymentStatus::FailedRolledBack,
                recorded_at: "2026-01-01T00:00:00Z".to_string(),
                outcomes: keys
                    .iter()
                    .map(|k| (k.clone(), outcome_for(k, ServerOutcomeKind::Restored)))
                    .collect(),
                rollback: None,
                reason: Some("rolled back".to_string()),
            },
            // Degraded: every member's outcome is a REMAINING change
            // (non-restored, with a recorded generation).
            _ => LedgerTerminalWire {
                deployment_id,
                target,
                status: DeploymentStatus::Degraded,
                recorded_at: "2026-01-01T00:00:00Z".to_string(),
                outcomes: keys
                    .iter()
                    .map(|k| (k.clone(), outcome_for(k, ServerOutcomeKind::Skipped)))
                    .collect(),
                rollback: None,
                reason: Some("degraded".to_string()),
            },
        }
    }

    /// A valid (intent + terminal) WIRE PAIR strategy: non-empty membership
    /// K, exact key-set equality in the intent, and a terminal AGREEING with
    /// the intent's identity and membership.
    fn agreeing_pair() -> impl Strategy<Value = (LedgerIntentWire, LedgerTerminalWire)> {
        (prop::collection::btree_set(slot_strategy(), 1..4), 0u32..4).prop_map(
            |(keys, status_idx)| {
                let keys: Vec<PlacementSlotId> = keys.into_iter().collect();
                (
                    agreeing_intent(keys.as_slice()),
                    agreeing_terminal(keys.as_slice(), status_idx),
                )
            },
        )
    }

    // ---- THE VERIFYING PAIR CONVERSION + the read_ledger consumer ---------

    /// Run the full verifying conversion of an intent + terminal pair — the
    /// SAME checks `read_ledger` runs when it merges a terminal into its
    /// entry (the entry owns identity: the terminal's id is the entry key,
    /// its target must equal the entry's, and every outcome key must be a
    /// member of the intent's membership) — returning the validated domain
    /// pair.
    fn pair_to_domain(
        pair: &(LedgerIntentWire, LedgerTerminalWire),
    ) -> Result<(DeploymentIntent, LedgerTerminal)> {
        let intent = pair.0.clone().into_domain()?;
        if pair.1.deployment_id != intent.deployment_id {
            return Err(Error::integrity(format!(
                "terminal {}: deployment_id disagrees with its entry (the intent's)",
                pair.1.deployment_id
            )));
        }
        if pair.1.target != intent.target {
            return Err(Error::integrity(format!(
                "terminal {}: target '{}' disagrees with its entry (the intent's target '{}')",
                pair.1.deployment_id, pair.1.target, intent.target
            )));
        }
        for key in pair.1.outcomes.keys() {
            if !intent.slots.contains_key(key) {
                return Err(Error::integrity(format!(
                    "terminal {}: outcome for slot '{key}' is outside the intent's membership",
                    pair.1.deployment_id
                )));
            }
        }
        let terminal = pair.1.clone().into_domain()?;
        Ok((intent, terminal))
    }

    /// Write the pair as a two-line ledger and read it back through the REAL
    /// consumer path (`read_ledger` — the FIRST consumer; rollback resolve
    /// and GC reachability consume its output, so failing here means failing
    /// BEFORE every consumer).
    fn write_pair_ledger(
        pair: &(LedgerIntentWire, LedgerTerminalWire),
    ) -> Result<Vec<LedgerEntry>> {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let line1 = serde_json::to_string(&LedgerLine::Intent(pair.0.clone())).unwrap();
        let line2 = serde_json::to_string(&LedgerLine::Terminal(pair.1.clone())).unwrap();
        let p = store.ledger_path("t1");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, format!("{line1}\n{line2}\n")).unwrap();
        store.read_ledger("t1")
    }

    /// Inspect the DOMAIN shapes produced from a VALID pair: the intent's
    /// ONE table (non-empty, unique keys, every member carries its desired +
    /// pre_push), the terminal's outcomes table, and the disposition's
    /// structural payloads.
    fn assert_domain_shape(
        intent: &DeploymentIntent,
        terminal: &LedgerTerminal,
        keys: &[PlacementSlotId],
        status_idx: u32,
    ) {
        assert!(!intent.slots.is_empty(), "the membership is non-empty");
        assert_eq!(
            intent.slots.len(),
            keys.len(),
            "the table's key count equals the membership count (no duplicates, no missing)"
        );
        assert_eq!(
            intent.membership(),
            keys.to_vec(),
            "the membership is exactly the wire's slot_ids (deployment order)"
        );
        for key in keys {
            let entry = &intent.slots[key];
            assert!(
                entry.desired.artifact.release.as_str().starts_with("rel-"),
                "each member carries its desired assignment"
            );
            // The pre_push ENTRY is structural: every member slot has an
            // IntentSlot (with `pre_push: Option<PreviousGeneration>`,
            // `None` for a first deployment) — there is no member without
            // its per-slot data.
        }
        for (key, result) in terminal.outcomes.iter() {
            assert_eq!(&result.slot_id, key, "each outcome names its own key");
        }
        match (&terminal.disposition, status_idx) {
            (TerminalDisposition::Successful { rollback }, 0) => {
                assert_eq!(
                    rollback.slots.len(),
                    keys.len(),
                    "the complete rollback covers every member slot"
                );
                assert_eq!(
                    rollback.bindings.len(),
                    keys.len(),
                    "every slotted generation carries its physical binding"
                );
            }
            (TerminalDisposition::FailedPreflight, 1) => {
                assert!(terminal.outcomes.is_empty(), "preflight touched no slot");
            }
            (TerminalDisposition::FailedRolledBack { compensation }, 2) => {
                assert_eq!(
                    compensation.len(),
                    keys.len(),
                    "the compensation report covers every compensated slot"
                );
                assert!(
                    compensation
                        .iter()
                        .all(|(_, r)| r.outcome == ServerOutcomeKind::Restored),
                    "the compensation records the restored slots"
                );
            }
            (TerminalDisposition::Degraded { remaining_changes }, 3) => {
                assert!(
                    !remaining_changes.is_empty(),
                    "degraded keeps non-empty remaining changes"
                );
                assert_eq!(
                    remaining_changes.len(),
                    keys.len(),
                    "every non-restored slot is a remaining change"
                );
            }
            (d, s) => panic!("disposition {d:?} does not match the wire status index {s}"),
        }
    }

    // ---- the mutations: ONE field at a time --------------------------------

    /// A single-field terminal tamper (the property applies ONE per case).
    type TerminalMutation = fn(&mut LedgerTerminalWire);

    fn tamper_status(t: &mut LedgerTerminalWire) {
        t.status = match &t.status {
            DeploymentStatus::Successful => DeploymentStatus::FailedPreflight,
            DeploymentStatus::FailedPreflight => DeploymentStatus::Successful,
            DeploymentStatus::FailedRolledBack => DeploymentStatus::Successful,
            DeploymentStatus::Degraded => DeploymentStatus::FailedPreflight,
            other => other.clone(),
        };
    }
    fn rollback_added_to_failed(t: &mut LedgerTerminalWire) {
        if t.status != DeploymentStatus::Successful {
            t.rollback = Some(LedgerRollbackWire {
                slots: BTreeMap::new(),
                bindings: BTreeMap::new(),
                behavior_sha256: None,
                release: None,
            });
        } else {
            t.rollback = None;
        }
    }
    fn rollback_extra_binding(t: &mut LedgerTerminalWire) {
        if let Some(rb) = t.rollback.as_mut() {
            rb.bindings.insert(slot(9), binding(&slot(9)));
        } else {
            t.rollback = Some(LedgerRollbackWire {
                slots: BTreeMap::new(),
                bindings: BTreeMap::new(),
                behavior_sha256: None,
                release: None,
            });
        }
    }
    fn outcome_slot_mismatch(t: &mut LedgerTerminalWire) {
        if let Some((_, r)) = t.outcomes.iter_mut().next() {
            // An outcome value naming a DIFFERENT placement than its key.
            r.slot_id = slot(9);
        } else {
            // No outcomes (FailedPreflight): add one whose value names a
            // different placement than its key.
            t.outcomes
                .insert(slot(0), outcome_for(&slot(9), ServerOutcomeKind::Activated));
        }
    }
    fn outcome_outside_membership(t: &mut LedgerTerminalWire) {
        t.outcomes
            .insert(slot(9), outcome_for(&slot(9), ServerOutcomeKind::Activated));
    }
    fn target_mismatch(t: &mut LedgerTerminalWire) {
        t.target = TargetName::new("other-target".to_string());
    }
    fn deployment_id_mismatch(t: &mut LedgerTerminalWire) {
        t.deployment_id = DeploymentId::new("deploy-other".to_string());
    }

    proptest! {
        // PROPERTY (the directive's point 4): generate VALID wire pairs
        // (intent + terminal), then mutate ONE field at a time — the
        // status→disposition mapping, the rollback payload, an outcome slot,
        // the target identity — and assert EVERY mutation fails the
        // verifying conversion BEFORE any consumer (the REAL read_ledger
        // consumer path), while the VALID pair converts to a DOMAIN whose
        // SHAPE has no duplicates/missing keys (asserted by inspection of
        // the NonEmptySlotTable / outcomes / disposition). Bounded 16 cases,
        // fixed seed 0x5EED_5EED (house style), no persistence.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn wire_pair_mutations_fail_before_any_consumer_and_valid_pairs_shape(
            (intent, terminal) in agreeing_pair()
        ) {
            let keys: Vec<PlacementSlotId> = intent.slot_ids.clone();
            let status_idx = match terminal.status {
                DeploymentStatus::Successful => 0,
                DeploymentStatus::FailedPreflight => 1,
                DeploymentStatus::FailedRolledBack => 2,
                DeploymentStatus::Degraded => 3,
                other => panic!("unexpected wire status {other:?}"),
            };
            let (d_intent, d_terminal) = pair_to_domain(&(intent.clone(), terminal.clone()))
                .expect("the agreeing pair converts");
            assert_domain_shape(&d_intent, &d_terminal, &keys, status_idx);
            let entries = write_pair_ledger(&(intent.clone(), terminal.clone()))
                .expect("the agreeing pair reads through the real ledger");
            assert_eq!(entries.len(), 1, "one merged entry");
            assert_domain_shape(
                &entries[0].intent,
                entries[0].terminal.as_ref().unwrap(),
                &keys,
                status_idx,
            );

            let mutations: [(&str, TerminalMutation); 7] = [
                ("status→disposition mismatch", tamper_status),
                ("rollback payload mismatch (missing on Successful / added to a failed status)", rollback_added_to_failed),
                ("rollback binding without a generation", rollback_extra_binding),
                ("outcome value naming a different slot", outcome_slot_mismatch),
                ("outcome key outside the membership", outcome_outside_membership),
                ("terminal target disagrees with the entry", target_mismatch),
                ("terminal deployment id keys no intent line", deployment_id_mismatch),
            ];
            for (name, mutate) in mutations {
                let mut bad = (intent.clone(), terminal.clone());
                mutate(&mut bad.1);
                let err = pair_to_domain(&bad);
                assert!(
                    err.is_err(),
                    "{name} must fail the conversion BEFORE any consumer"
                );
                let ledger_err = write_pair_ledger(&bad);
                assert!(
                    ledger_err.is_err(),
                    "{name} must fail read_ledger (the first consumer)"
                );
            }
        }
    }

    // ---- deterministic unit tests -----------------------------------------

    /// [`DeploymentIntent`]: the wire's three projections COLLAPSE into ONE
    /// slot table; every duplicate-projection disagreement (duplicate member,
    /// missing/extra desired or pre_push key, an EMPTY membership, an
    /// assignment naming another placement, a wire actuals key outside the
    /// membership) fails the conversion, and the domain round-trips stably.
    #[test]
    fn intent_collapses_into_one_table_and_refuses_disagreements() {
        let keys = vec![slot(1)];
        let wire = agreeing_intent(&keys);
        let domain = wire.clone().into_domain().unwrap();
        assert_eq!(domain.membership(), vec![slot(1)]);
        assert_eq!(
            domain.releases(),
            BTreeSet::from([ReleaseId::new("rel-slot-1".to_string())])
        );
        assert_eq!(domain.slots.len(), 1, "one table, one member");
        assert!(
            domain.slots[&slot(1)]
                .desired
                .artifact
                .release
                .as_str()
                .starts_with("rel-")
        );
        // Round trip: the one table re-expands into the wire split shape and
        // back unchanged.
        let json = serde_json::to_string(&domain).unwrap();
        let wire2: LedgerIntentWire = serde_json::from_str(&json).unwrap();
        assert_eq!(
            wire2.slot_ids,
            vec![slot(1)],
            "the wire split shape is preserved"
        );
        let domain2 = wire2.into_domain().unwrap();
        assert_eq!(
            domain2, domain,
            "an agreeing intent survives the round trip"
        );

        // (a) a DUPLICATE member weakens the membership.
        let mut bad = wire.clone();
        bad.slot_ids.push(slot(1));
        assert!(
            bad.into_domain().is_err(),
            "a duplicate member fails closed"
        );
        // (b) a DELETED member: the membership omits a key the maps carry.
        let mut bad = wire.clone();
        bad.slot_ids.pop();
        assert!(bad.into_domain().is_err(), "a deleted member fails closed");
        // (c) an EMPTY membership: the domain's NonEmptySlotTable refuses it.
        let mut bad = wire.clone();
        bad.slot_ids.clear();
        bad.desired.clear();
        bad.pre_push.clear();
        assert!(
            bad.into_domain().is_err(),
            "an empty membership fails closed"
        );
        // (d) a MISSING desired key.
        let mut bad = wire.clone();
        bad.desired.remove(&slot(1));
        assert!(
            bad.into_domain().is_err(),
            "a missing desired key fails closed"
        );
        // (e) an EXTRA desired key outside the membership.
        let mut bad = wire.clone();
        bad.desired.insert(slot(2), gen_ref_for(&slot(2)));
        assert!(
            bad.into_domain().is_err(),
            "an extra desired key fails closed"
        );
        // (f) a missing pre_push key.
        let mut bad = wire.clone();
        bad.pre_push.remove(&slot(1));
        assert!(
            bad.into_domain().is_err(),
            "a missing pre_push key fails closed"
        );
        // (g) an extra pre_push key outside the membership.
        let mut bad = wire.clone();
        bad.pre_push.insert(slot(2), None);
        assert!(
            bad.into_domain().is_err(),
            "an extra pre_push key fails closed"
        );
        // (h) a wire actuals key outside the membership.
        let mut bad = wire.clone();
        bad.slots.insert(
            slot(9),
            SlotAttemptState {
                artifact: ArtifactRef::default(),
                generation: None,
            },
        );
        assert!(
            bad.into_domain().is_err(),
            "a slots key outside slot_ids fails closed"
        );
        // (i) an assignment naming a different placement.
        let mut bad = wire.clone();
        bad.desired
            .get_mut(&slot(1))
            .unwrap()
            .assignment
            .placement_slot = slot(9);
        assert!(
            bad.into_domain().is_err(),
            "an assignment naming another placement fails closed"
        );
    }

    /// INTENT vs REPORT datatype split: the verified domain
    /// [`DeploymentIntent`] carries NO outcomes map (the wire keeps the
    /// intentionally-empty `slots` member for format stability), while the
    /// in-memory [`LedgerIntentReport`] carries the observed per-slot
    /// actuals — the report's map is not part of the intent's key-set
    /// invariant.
    #[test]
    fn intent_report_carries_outcomes_while_persisted_intent_slots_stay_empty() {
        let keys = vec![slot(1)];
        let mut wire = agreeing_intent(&keys);
        // The report parses the intent's digest into a [`BehaviorDigest`], so
        // the fixture must carry a canonical sha256 digest.
        wire.behavior_sha256 = crate::scalar::DIGEST_TEST_HEX_1.to_string();
        let domain = wire.into_domain().unwrap();
        // The REPORT carries the observed per-slot actuals for display.
        let mut report = LedgerIntentReport::from_intent(&domain).expect("verified intent parses");
        report.slots.insert(
            slot(1),
            SlotAttemptState {
                artifact: ArtifactRef::default(),
                generation: None,
            },
        );
        assert_eq!(report.slots.len(), 1, "the report carries the actuals");
        // The PERSISTED intent keeps its wire `slots` map EMPTY (the wire
        // conversion never reads the report's map): the intent round-trips
        // without the outcomes.
        let json = serde_json::to_string(&domain).unwrap();
        let wire2: LedgerIntentWire = serde_json::from_str(&json).unwrap();
        assert!(
            wire2.slots.is_empty(),
            "the persisted intent keeps the `slots` map empty (outcomes live in the terminal event and the in-memory report)"
        );
        // The report's maps are re-expanded from the one table (split shape,
        // display-facing), and its scalars are parsed fail-closed.
        assert_eq!(report.slot_ids, vec![slot(1)]);
        assert_eq!(report.desired.len(), 1);
        assert!(report.pre_push.contains_key(&slot(1)));
        assert!(
            LedgerIntentReport::from_intent(&domain).is_ok(),
            "the verified intent's scalars parse into the report"
        );
    }

    /// STATUS → DISPOSITION: each status maps to EXACTLY ONE disposition,
    /// and a status whose payload does not match its disposition is a
    /// conversion error (fail closed) — the truth table is STRUCTURAL in the
    /// domain.
    #[test]
    fn terminal_status_maps_to_exactly_one_disposition() {
        let keys = vec![slot(1), slot(2)];
        // Successful + complete rollback → Successful { rollback }.
        let wire = agreeing_terminal(&keys, 0);
        let d = wire.into_domain().unwrap();
        assert_eq!(d.status(), DeploymentStatus::Successful);
        let TerminalDisposition::Successful { rollback } = d.disposition else {
            panic!("Successful maps to Successful {{ rollback }}");
        };
        assert_eq!(rollback.slots.len(), 2, "the complete rollback payload");

        // FailedPreflight + no outcomes → FailedPreflight (nothing).
        let wire = agreeing_terminal(&keys, 1);
        let d = wire.into_domain().unwrap();
        assert_eq!(d.disposition, TerminalDisposition::FailedPreflight);

        // FailedRolledBack → the outcome table is the compensation report.
        let wire = agreeing_terminal(&keys, 2);
        let d = wire.into_domain().unwrap();
        let TerminalDisposition::FailedRolledBack { compensation } = &d.disposition else {
            panic!("FailedRolledBack maps to FailedRolledBack {{ compensation }}");
        };
        assert_eq!(compensation.len(), 2);

        // Degraded → the non-restored outcomes ARE the remaining changes.
        let wire = agreeing_terminal(&keys, 3);
        let d = wire.into_domain().unwrap();
        let TerminalDisposition::Degraded { remaining_changes } = &d.disposition else {
            panic!("Degraded maps to Degraded {{ remaining_changes }}");
        };
        assert_eq!(remaining_changes.len(), 2);

        // PAYLOAD MISMATCHES: a status whose payload does not match its
        // disposition is a conversion error.
        let mut bad = agreeing_terminal(&keys, 0); // Successful
        bad.rollback = None;
        assert!(
            bad.into_domain().is_err(),
            "Successful without its rollback is refused"
        );
        let mut bad = agreeing_terminal(&keys, 1); // FailedPreflight
        bad.outcomes
            .insert(slot(1), outcome_for(&slot(1), ServerOutcomeKind::Activated));
        assert!(
            bad.into_domain().is_err(),
            "FailedPreflight with outcomes is refused"
        );
        let mut bad = agreeing_terminal(&keys, 1); // FailedPreflight
        bad.rollback = Some(LedgerRollbackWire {
            slots: BTreeMap::new(),
            bindings: BTreeMap::new(),
            behavior_sha256: None,
            release: None,
        });
        assert!(
            bad.into_domain().is_err(),
            "FailedPreflight carrying a rollback is refused"
        );
        let mut bad = agreeing_terminal(&keys, 3); // Degraded
        bad.outcomes = BTreeMap::new();
        assert!(
            bad.into_domain().is_err(),
            "Degraded with NO remaining change is refused"
        );
        let mut bad = agreeing_terminal(&keys, 3); // Degraded
        for r in bad.outcomes.values_mut() {
            r.outcome = ServerOutcomeKind::Restored;
        }
        assert!(
            bad.into_domain().is_err(),
            "Degraded with every slot restored is refused"
        );
        // InProgress / PendingCommit never appear on a terminal event.
        let mut bad = agreeing_terminal(&keys, 0);
        bad.status = DeploymentStatus::PendingCommit;
        assert!(
            bad.into_domain().is_err(),
            "a PendingCommit terminal is refused"
        );
    }

    /// THE ENTRY OWNS IDENTITY: the domain terminal carries no
    /// deployment_id/target; the reader verifies the wire terminal's
    /// identity against its ENTRY (the intent's) and the outcome keys
    /// against the membership — a mismatch is refused before any consumer.
    #[test]
    fn entry_owns_identity_and_refuses_cross_record_disagreements() {
        let keys = vec![slot(1), slot(2)];
        let intent = agreeing_intent(&keys);
        // A terminal claiming a DIFFERENT target than its entry.
        let mut terminal = agreeing_terminal(&keys, 0);
        terminal.target = TargetName::new("other".to_string());
        let err = pair_to_domain(&(intent.clone(), terminal))
            .expect_err("a target disagreement is refused");
        assert!(err.to_string().contains("target"), "err: {err}");
        // A terminal claiming a deployment id with no intent line.
        let mut terminal = agreeing_terminal(&keys, 0);
        terminal.deployment_id = DeploymentId::new("deploy-ghost".to_string());
        assert!(pair_to_domain(&(intent.clone(), terminal)).is_err());
        // An outcome key outside the intent's membership.
        let mut terminal = agreeing_terminal(&keys, 0);
        terminal
            .outcomes
            .insert(slot(9), outcome_for(&slot(9), ServerOutcomeKind::Activated));
        assert!(pair_to_domain(&(intent.clone(), terminal)).is_err());
        // An outcome value naming a different slot than its key.
        let mut terminal = agreeing_terminal(&keys, 0);
        terminal.outcomes.get_mut(&slot(1)).unwrap().slot_id = slot(2);
        assert!(pair_to_domain(&(intent, terminal)).is_err());
    }

    /// [`NonEmptySlotTable`] refuses the empty map; [`SlotTable`] is the
    /// possibly-empty variant (terminal outcomes are legitimately empty for
    /// a preflight failure).
    #[test]
    fn slot_tables_enforce_non_emptiness_where_the_domain_requires_it() {
        assert!(NonEmptySlotTable::<u32>::build(BTreeMap::new()).is_err());
        let ok = NonEmptySlotTable::build(BTreeMap::from([(slot(1), 7u32)])).unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[&slot(1)], 7);
        assert!(SlotTable::<u32>::new().is_empty());
    }

    /// The wire rollback payload converts into the domain rollback with the
    /// kept duplicate-projection checks (assignment own-key, bindings ⊆
    /// slotted generations, the legacy snapshot-wide release when present).
    #[test]
    fn rollback_wire_disagreement_per_duplicate_fails_closed() {
        let wire = LedgerRollbackWire {
            slots: BTreeMap::from([(slot(1), gen_ref_for(&slot(1)))]),
            bindings: BTreeMap::from([(slot(1), binding(&slot(1)))]),
            behavior_sha256: None,
            release: None,
        };
        let domain = wire.clone().into_domain().unwrap();
        assert_eq!(
            domain.releases(),
            BTreeSet::from([ReleaseId::new("rel-slot-1".to_string())])
        );
        let json = serde_json::to_string(&domain).unwrap();
        let wire2: LedgerRollbackWire = serde_json::from_str(&json).unwrap();
        let domain2 = wire2.into_domain().unwrap();
        assert_eq!(domain2.releases(), domain.releases());

        let mut bad = wire.clone();
        bad.bindings.insert(slot(2), binding(&slot(2)));
        assert!(
            bad.into_domain().is_err(),
            "a binding without a generation fails closed"
        );
        let mut bad = wire.clone();
        bad.bindings.remove(&slot(1));
        assert!(
            bad.into_domain().is_err(),
            "a slotted generation without its binding fails closed (exact binding keys)"
        );
        let mut bad = wire.clone();
        bad.slots
            .get_mut(&slot(1))
            .unwrap()
            .assignment
            .placement_slot = slot(2);
        assert!(
            bad.into_domain().is_err(),
            "an assignment naming another placement fails closed"
        );
        let mut bad = wire.clone();
        bad.release = Some(ReleaseId::new("rel-other".to_string()));
        assert!(
            bad.into_domain().is_err(),
            "a legacy release disagreeing with the derived release fails closed"
        );
        let mut good = wire.clone();
        good.release = Some(ReleaseId::new("rel-slot-1".to_string()));
        assert!(
            good.into_domain().is_ok(),
            "an agreeing legacy release passes"
        );
    }

    /// [`LedgerTerminalWire`]: an agreeing terminal converts and round-trips
    /// stably; the STATUS/ROLLBACK TRUTH TABLE (Successful ⇔ rollback
    /// present), the outcome own-key agreement, and the rollback's exact
    /// binding keys each fail closed on ONE mutation, while both truth-table
    /// variants (Successful + rollback, failed + no rollback) pass.
    #[test]
    fn terminal_wire_truth_table_and_rollback_agreement_fails_closed() {
        let rollback = || LedgerRollbackWire {
            slots: BTreeMap::from([(slot(1), gen_ref_for(&slot(1)))]),
            bindings: BTreeMap::from([(slot(1), binding(&slot(1)))]),
            behavior_sha256: None,
            release: None,
        };
        let outcome = || SlotResult {
            slot_id: slot(1),
            outcome: ServerOutcomeKind::Activated,
            generation: Some(GenerationId::new("gen-1".to_string())),
            compensated: false,
            error: None,
        };
        let wire = LedgerTerminalWire {
            deployment_id: DeploymentId::new("deploy-terminal".to_string()),
            target: TargetName::new("t1".to_string()),
            status: DeploymentStatus::Successful,
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
            outcomes: BTreeMap::from([(slot(1), outcome())]),
            rollback: Some(rollback()),
            reason: None,
        };
        let domain = wire.clone().into_domain().unwrap();
        assert_eq!(domain.status(), DeploymentStatus::Successful);
        assert!(
            matches!(&domain.disposition, TerminalDisposition::Successful { .. }),
            "Successful carries its rollback"
        );
        // The domain terminal round-trips through the wire shape; `from_domain`
        // supplies the entry-owned deployment id / target.
        let json = serde_json::to_string(&LedgerTerminalWire::from_domain(
            &DeploymentId::new("deploy-terminal".to_string()),
            &TargetName::new("t1".to_string()),
            &domain,
        ))
        .unwrap();
        let wire2: LedgerTerminalWire = serde_json::from_str(&json).unwrap();
        assert_eq!(
            wire2.into_domain().unwrap(),
            domain,
            "an agreeing terminal survives the round trip unchanged"
        );

        // TRUTH TABLE, direction 1: Successful must carry its rollback.
        let mut bad = wire.clone();
        bad.rollback = None;
        assert!(
            bad.into_domain().is_err(),
            "a Successful terminal without its rollback fails closed"
        );
        // TRUTH TABLE, direction 2: a failed status must not carry one.
        let mut bad = wire.clone();
        bad.status = DeploymentStatus::FailedRolledBack;
        assert!(
            bad.into_domain().is_err(),
            "a failed terminal carrying a rollback fails closed"
        );
        // OUTCOME OWN-KEY: an outcome naming a different placement slot.
        let mut bad = wire.clone();
        bad.outcomes.get_mut(&slot(1)).unwrap().slot_id = slot(2);
        assert!(
            bad.into_domain().is_err(),
            "an outcome naming a different placement fails closed"
        );
        // EXACT BINDING KEYS: a generation without its binding …
        let mut bad = wire.clone();
        bad.rollback.as_mut().unwrap().bindings.remove(&slot(1));
        assert!(
            bad.into_domain().is_err(),
            "a slotted generation without its binding fails closed"
        );
        // … and a binding without its generation.
        let mut bad = wire.clone();
        bad.rollback
            .as_mut()
            .unwrap()
            .bindings
            .insert(slot(2), binding(&slot(2)));
        assert!(
            bad.into_domain().is_err(),
            "a binding without a generation fails closed"
        );

        // The other truth-table variant stays VALID: a failed terminal with
        // NO rollback and NO outcomes converts fine.
        let failed = LedgerTerminalWire {
            status: DeploymentStatus::FailedRolledBack,
            outcomes: BTreeMap::new(),
            rollback: None,
            ..wire.clone()
        };
        assert!(
            failed.into_domain().is_ok(),
            "a failed terminal without a rollback stays valid"
        );
    }

    // =====================================================================
    // THE SCALAR PROPERTY: arbitrary raw scalar values convert iff the scalar
    // =====================================================================

    /// Arbitrary raw strings for a record scalar field: empty, whitespace,
    /// format-violating, RFC3339-invalid, and valid forms.
    fn arbitrary_wire_text() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(vec![
                String::new(),
                " ".to_string(),
                "canary".to_string(),
                "wave-1".to_string(),
                " x".to_string(),
                "2026-01-01T00:00:00Z".to_string(),
                "2026-01-01T00:00:00.123+02:00".to_string(),
                "yesterday".to_string(),
                "2026-01-01".to_string(),
                crate::scalar::DIGEST_TEST_HEX_1.to_string(),
                "sha256-w".to_string(),
            ]),
            prop::collection::vec(prop::char::any(), 0..8).prop_map(|v| v.into_iter().collect()),
        ]
    }

    /// A valid base intent wire for the scalar property: an agreeing
    /// membership with a canonical digest and timestamp, whose group is
    /// `None` (each mutation arms sets exactly ONE scalar field).
    fn base_intent_wire() -> LedgerIntentWire {
        let slot_ids = vec![slot(1), slot(2)];
        let desired = slot_ids
            .iter()
            .map(|k| (k.clone(), gen_ref_for(k)))
            .collect();
        let pre_push: BTreeMap<PlacementSlotId, Option<SlotAttemptState>> =
            slot_ids.iter().map(|k| (k.clone(), None)).collect();
        LedgerIntentWire {
            deployment_schema_version: crate::model::LEDGER_SCHEMA_VERSION,
            deployment_id: DeploymentId::new("deploy-scalar".to_string()),
            target: TargetName::new("t1".to_string()),
            group: None,
            slot_ids,
            behavior_sha256: crate::scalar::DIGEST_TEST_HEX_1.to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired,
            pre_push,
            slots: BTreeMap::new(),
        }
    }

    /// One records scalar-mutation case: a wire with EXACTLY ONE scalar
    /// field set to an arbitrary raw value, paired with the scalar's own
    /// parse verdict on that value.
    #[derive(Debug)]
    enum ScalarWire {
        Intent(LedgerIntentWire),
        Terminal(LedgerTerminalWire),
        Report(DeploymentIntent),
    }

    fn scalar_mutation_case() -> impl Strategy<Value = (ScalarWire, bool)> {
        prop_oneof![
            // intent attempted_at: RFC 3339 or rejected.
            (Just(base_intent_wire()), arbitrary_wire_text()).prop_map(|(mut w, v)| {
                let ok = Timestamp::parse(&v).is_ok();
                w.attempted_at = v;
                (ScalarWire::Intent(w), ok)
            }),
            // intent group: a valid group name or rejected.
            (Just(base_intent_wire()), arbitrary_wire_text()).prop_map(|(mut w, v)| {
                let ok = GroupName::parse(&v).is_ok();
                w.group = Some(v);
                (ScalarWire::Intent(w), ok)
            }),
            // terminal recorded_at: RFC3339 or rejected.
            (Just(base_intent_wire()), arbitrary_wire_text()).prop_map(|(w, v)| {
                let ok = Timestamp::parse(&v).is_ok();
                let terminal = LedgerTerminalWire {
                    deployment_id: w.deployment_id,
                    target: w.target,
                    status: DeploymentStatus::FailedRolledBack,
                    recorded_at: v,
                    outcomes: BTreeMap::new(),
                    rollback: None,
                    reason: None,
                };
                (ScalarWire::Terminal(terminal), ok)
            }),
            // report behavior digest: a sha256 digest or rejected (the
            // in-memory REPORT is the domain record that carries the digest;
            // its constructor parses it fail-closed).
            (Just(base_intent_wire()), arbitrary_wire_text()).prop_map(|(w, v)| {
                let ok = BehaviorDigest::parse(&v).is_ok();
                let domain = w.into_domain().expect("base intent converts");
                let mut with_digest = domain.clone();
                with_digest.behavior_sha256 = v;
                (ScalarWire::Report(with_digest), ok)
            }),
        ]
    }

    proptest! {
        // THE PROPERTY: over ARBITRARY raw values for each records scalar
        // field (empty, format-violating, RFC3339-invalid, valid), the
        // wire -> domain conversion accepts EXACTLY the values the scalar
        // accepts and rejects everything else with an integrity error (fail
        // closed). Bounded 16 cases, fixed seed 0x5EED_5EED per house style.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn arbitrary_record_scalars_convert_fail_closed((wire, expected) in scalar_mutation_case()) {
            let converted = match wire {
                ScalarWire::Intent(w) => w.into_domain().map(|_| ()),
                ScalarWire::Terminal(w) => w.into_domain().map(|_| ()),
                ScalarWire::Report(d) => LedgerIntentReport::from_intent(&d).map(|_| ()),
            };
            match converted {
                Ok(_) => {
                    assert!(expected, "the conversion must accept exactly the values the scalar accepts");
                }
                Err(e) => {
                    assert!(
                        !expected,
                        "the conversion must accept a value the scalar accepts, got: {e}"
                    );
                    assert!(
                        matches!(e, Error::Integrity(_)),
                        "the rejection must be an integrity error, got: {e}"
                    );
                }
            }
        }
    }
}
