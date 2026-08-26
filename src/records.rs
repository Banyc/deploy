//! Shared record structures persisted by the local store, the push engine, and
//! the deployment history / rollback subsystem.
//!
//! Assignment relationships are expressed exclusively through the canonical
//! model types ([`crate::model::ArtifactRef`],
//! [`crate::model::PlacementSlotAssignment`], [`crate::model::GenerationRef`])
//! rather than re-declared per record. Every slot→assignment map (ledger
//! intent `desired` / `pre_push`, terminal `outcomes`, the rollback payload)
//! is keyed by [`crate::model::SlotId`] — the deployment-location
//! identity — while [`crate::model::ServerId`] remains the actual-server
//! identity used for transport addressing (`ServerState`, config `ServerDef`).
//!
//! # ONE authoritative collection per record; WIRE → VERIFIED DOMAIN
//!
//! Every record keeps ONE authoritative collection and derives the rest
//! through methods (`membership()`, `releases()`, `behavior_digest()`,
//! [`LedgerTerminal::remaining_changes`], [`LedgerTerminal::compensation`]); the
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
//!   per-slot OUTCOMES (the AUTHORITATIVE per-slot facts — the disposition's
//!   per-slot projections, the Degraded remaining changes and the
//!   FailedRolledBack compensation report, are DERIVED from them, never
//!   stored twice), and — when the deployment was SUCCESSFUL — the ROLLBACK
//!   STATE ([`LedgerRollbackWire`] → verified [`LedgerRollback`], the
//!   snapshot payload: per-slot generation refs + physical bindings, the ONE
//!   fact the outcomes cannot express). Appended once, after the mutation
//!   loop, and never edited.
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
    PlacementSlotAssignment, ReleaseId, ServerId, SlotId, TargetName, TreeDigest,
};
use crate::scalar::{BehaviorDigest, RolloutGroupName, Timestamp};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::ops::Index;

// ---------------------------------------------------------------------------
// DOMAIN SLOT TABLES: the membership + per-slot data are ONE table
// ---------------------------------------------------------------------------
//
// The DOMAIN intent collapses the wire's `slot_ids` / `desired` / `pre_push`
// split into a single authoritative slot→slot-data table, so the
// exact-key-set invariant (membership == desired keys == pre_push keys, no
// duplicates) becomes STRUCTURAL: a [`NonEmptySlotTable`] is non-empty and
// its keys are unique (the ordered map has no duplicate keys), so an intent
// can never carry a member slot without its desired/pre-push entries, or an
// entry for a non-member slot. The WIRE types keep the split on-disk shape;
// the wire → domain conversion builds the table and refuses disagreements
// exactly as before.
//
// THE TABLE IS ORDERED: iteration (`keys` / `values` / `iter`) is in
// INSERTION order — the DEPLOYMENT order — never sorted by slot id. The
// wire's `slot_ids` is the authoritative deployment order (the same set the
// commit marker `slots` payload records), and the wire → domain conversion
// builds the table from that SEQUENCE, so the round trip preserves the
// exact `slot_ids` order instead of silently re-sorting it.

/// A PRIVATE ordered slot→value map: a `Vec<(SlotId, T)>` keeps the
/// INSERTION SEQUENCE (the deployment order) and a `BTreeMap<SlotId, usize>`
/// index gives O(log n) lookup. Iteration (`keys` / `values` / `iter`) is in
/// INSERTION order — the deployment order — never sorted by slot id.
/// `insert` APPENDS a new key at the end of the sequence and OVERWRITES an
/// existing key in place (its position is preserved), so the sequence is
/// exactly the order the entries were first inserted.
#[derive(Clone, Debug, PartialEq, Eq)]
struct OrderedSlotMap<T> {
    entries: Vec<(SlotId, T)>,
    index: BTreeMap<SlotId, usize>,
}

impl<T> Default for OrderedSlotMap<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            index: BTreeMap::new(),
        }
    }
}

impl<T> OrderedSlotMap<T> {
    fn new() -> Self {
        Self::default()
    }

    fn from_map(map: BTreeMap<SlotId, T>) -> Self {
        let entries: Vec<(SlotId, T)> = map.into_iter().collect();
        let index = entries
            .iter()
            .enumerate()
            .map(|(i, (k, _))| (k.clone(), i))
            .collect();
        Self { entries, index }
    }

    fn into_map(self) -> BTreeMap<SlotId, T> {
        self.entries.into_iter().collect()
    }

    fn insert(&mut self, key: SlotId, value: T) {
        if let Some(&i) = self.index.get(&key) {
            self.entries[i].1 = value;
        } else {
            self.index.insert(key.clone(), self.entries.len());
            self.entries.push((key, value));
        }
    }

    fn get(&self, key: &SlotId) -> Option<&T> {
        self.index.get(key).map(|&i| &self.entries[i].1)
    }

    fn contains_key(&self, key: &SlotId) -> bool {
        self.index.contains_key(key)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn keys(&self) -> impl Iterator<Item = &SlotId> {
        self.entries.iter().map(|(k, _)| k)
    }

    fn values(&self) -> impl Iterator<Item = &T> {
        self.entries.iter().map(|(_, v)| v)
    }

    fn iter(&self) -> impl Iterator<Item = (&SlotId, &T)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }
}

impl<T> Index<&SlotId> for OrderedSlotMap<T> {
    type Output = T;
    fn index(&self, key: &SlotId) -> &Self::Output {
        self.get(key).expect("no entry found for key")
    }
}

/// A possibly-empty ordered slot→value table keyed by
/// [`SlotId`] — the domain's keyed-by-slot collection type
/// (the possibly-empty variant of [`NonEmptySlotTable`], used for the
/// terminal's per-slot OUTCOMES, which are legitimately empty for a
/// pre-mutation failure). Uniqueness is structural (the ordered map has no
/// duplicate keys); the table carries no other invariant. Iteration
/// (`keys` / `values` / `iter`) is in INSERTION order — the deployment
/// order — never sorted by slot id.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SlotTable<T>(OrderedSlotMap<T>);

impl<T> SlotTable<T> {
    pub fn new() -> Self {
        Self(OrderedSlotMap::new())
    }

    pub fn from_map(map: BTreeMap<SlotId, T>) -> Self {
        Self(OrderedSlotMap::from_map(map))
    }

    pub fn into_map(self) -> BTreeMap<SlotId, T> {
        self.0.into_map()
    }

    /// Insert a slot→value entry, APPENDING a new key at the end of the
    /// table's sequence (the deployment order) and overwriting an existing
    /// key in place (its position is preserved).
    pub fn insert(&mut self, key: SlotId, value: T) {
        self.0.insert(key, value);
    }

    pub fn get(&self, key: &SlotId) -> Option<&T> {
        self.0.get(key)
    }

    pub fn contains_key(&self, key: &SlotId) -> bool {
        self.0.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = &SlotId> {
        self.0.keys()
    }

    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.0.values()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SlotId, &T)> {
        self.0.iter()
    }
}

impl<T> Index<&SlotId> for SlotTable<T> {
    type Output = T;
    fn index(&self, key: &SlotId) -> &Self::Output {
        &self.0[key]
    }
}

impl<T: Serialize> Serialize for SlotTable<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (k, v) in self.iter() {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for SlotTable<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct SlotTableVisitor<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for SlotTableVisitor<T> {
            type Value = SlotTable<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a slot table")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut access: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut table = OrderedSlotMap::new();
                while let Some((k, v)) = access.next_entry()? {
                    table.insert(k, v);
                }
                Ok(SlotTable(table))
            }
        }
        deserializer.deserialize_map(SlotTableVisitor(PhantomData))
    }
}

/// A NON-EMPTY ordered slot→value table keyed by [`SlotId`] — the
/// domain's authoritative membership-bearing collection type (the
/// non-empty variant of [`SlotTable`], used for the deployment intent's
/// slots and the degraded disposition's remaining changes). The domain
/// invariant is STRUCTURAL: the key set is unique (the ordered map) and
/// NON-EMPTY (the only constructor is the VERIFIED
/// [`NonEmptySlotTable::build`], which refuses the empty table — a
/// deployment that selects no slot cannot be represented). No
/// duplicate/missing-key state exists in the domain: a member slot always
/// carries its desired + pre-push entry, and no entry exists for a
/// non-member. Iteration (`keys` / `values` / `iter`) is in INSERTION
/// order — the deployment order — never sorted by slot id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonEmptySlotTable<T>(OrderedSlotMap<T>);

impl<T> NonEmptySlotTable<T> {
    /// The VERIFIED constructor: refuse the empty table (fail closed — the
    /// domain cannot represent an empty deployment membership or an empty
    /// remaining-changes set). Uniqueness needs no check (the ordered map
    /// keys are unique by construction). The table's INSERTION SEQUENCE is
    /// the entry order of `entries` — the wire's `slot_ids` order — and
    /// iteration preserves it exactly.
    pub fn build<I>(entries: I) -> Result<Self>
    where
        I: IntoIterator<Item = (SlotId, T)>,
    {
        let mut table = OrderedSlotMap::new();
        for (key, value) in entries {
            table.insert(key, value);
        }
        if table.is_empty() {
            return Err(Error::integrity(
                "a non-empty slot table cannot be empty — the domain refuses an empty deployment membership / remaining-changes set",
            ));
        }
        Ok(Self(table))
    }

    pub fn get(&self, key: &SlotId) -> Option<&T> {
        self.0.get(key)
    }

    pub fn contains_key(&self, key: &SlotId) -> bool {
        self.0.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn keys(&self) -> impl Iterator<Item = &SlotId> {
        self.0.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SlotId, &T)> {
        self.0.iter()
    }

    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.0.values()
    }

    pub fn into_map(self) -> BTreeMap<SlotId, T> {
        self.0.into_map()
    }
}

impl<T> Index<&SlotId> for NonEmptySlotTable<T> {
    type Output = T;
    fn index(&self, key: &SlotId) -> &Self::Output {
        &self.0[key]
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
pub enum SlotOutcomeKind {
    Activated,
    Failed,
    /// Reserved: never emitted today. In-process compensation (a post-swap
    /// activation/verification failure restored by the per-server pipeline,
    /// step 11) is recorded as [`SlotOutcomeKind::Failed`] with
    /// `SlotResult.compensated = true` — "record both the failure and the
    /// compensation result" — and failure-policy compensation (step 13)
    /// upgrades the slot to [`SlotOutcomeKind::Restored`].
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
    pub slot_ids: Vec<SlotId>,
    pub behavior_sha256: String,
    pub attempted_at: String,
    /// Desired per-slot assignments (what the plan intended): each slot's
    /// minted generation for its planned artifact. The key set must equal
    /// `slot_ids` EXACTLY, and each `GenerationRef`'s assignment must name
    /// its own map key.
    pub desired: BTreeMap<SlotId, GenerationRef>,
    /// Pre-push per-slot state before mutation (`None` if first deployment).
    /// The key set must equal `slot_ids` EXACTLY.
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
    /// Per-slot generation refs, keyed by [`SlotId`]. Each
    /// generation ref's assignment carries the slot's OWN artifact binding
    /// (`release`, `variant`, `tree`); the referenced releases are the set
    /// derived from these bindings ([`LedgerRollback::releases`]).
    pub slots: BTreeMap<SlotId, GenerationRef>,
    /// The complete physical binding (`{server, deploy_dir}`) each slot had
    /// at deployment time, keyed by [`SlotId`]. Every binding key
    /// must be a slotted generation (verified by the wire → domain
    /// conversion).
    #[serde(default)]
    pub bindings: BTreeMap<SlotId, PhysicalBinding>,
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
    pub slots: BTreeMap<SlotId, GenerationRef>,
    #[serde(default)]
    pub bindings: BTreeMap<SlotId, PhysicalBinding>,
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
        let slot_keys: BTreeSet<&SlotId> = self.slots.keys().collect();
        let binding_keys: BTreeSet<&SlotId> = self.bindings.keys().collect();
        if slot_keys != binding_keys {
            let missing: Vec<&SlotId> = slot_keys.difference(&binding_keys).copied().collect();
            let extra: Vec<&SlotId> = binding_keys.difference(&slot_keys).copied().collect();
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
/// (which slots were compensated back and which compensation failed). The
/// report is DERIVED from the terminal's authoritative outcomes table
/// ([`LedgerTerminal::compensation`]) — never stored as a duplicate that
/// could disagree with the outcomes.
pub type CompensationReport = SlotTable<SlotOutcome>;

/// The DISPOSITION of a deployment's terminal event — the DOMAIN replaces
/// the wire's `status: String` + optional rollback TAG-PLUS-OPTIONAL-PAYLOAD
/// shape with an ENUM whose variants carry exactly the payload their
/// disposition allows, so the STATUS/ROLLBACK TRUTH TABLE is STRUCTURAL
/// (unrepresentable-invalid states simply do not exist in the domain):
///
/// * [`TerminalDisposition::Successful`] ALWAYS carries its complete
///   rollback payload (a successful deployment always records its rollback
///   state — the generation refs + physical bindings, the ONE fact the
///   per-slot outcomes cannot express). The outcomes keys, the rollback's
///   slots keys, and the rollback's bindings keys are EXACTLY EQUAL and
///   NON-EMPTY (enforced by the conversion; the intent's membership is the
///   fourth equal set, enforced where the terminal merges into its entry).
/// * [`TerminalDisposition::FailedPreflight`] carries NOTHING — a
///   pre-mutation failure cannot carry a rollback, and no slot was touched.
/// * [`TerminalDisposition::FailedRolledBack`] carries NOTHING — its
///   COMPENSATION REPORT (the per-slot results of the compensation pass) IS
///   the terminal's authoritative outcomes table, DERIVED via
///   [`LedgerTerminal::compensation`], never stored twice.
/// * [`TerminalDisposition::Degraded`] carries NOTHING — its REMAINING
///   CHANGES (the slots that did not reach a restored state, each mapped to
///   the generation it recorded) are DERIVED from the authoritative
///   outcomes via [`LedgerTerminal::remaining_changes`], never stored twice.
///
/// STORE EACH FACT EXACTLY ONCE: the per-slot OUTCOMES are the authoritative
/// per-slot facts; the disposition carries ONLY what the outcomes cannot
/// express (the Successful rollback payload). The WIRE keeps the current
/// `status` + `rollback` shape; the wire → domain conversion maps every
/// status to EXACTLY ONE disposition and refuses a status whose payload does
/// not match its disposition (a `Successful` with no rollback, a failed
/// status carrying a rollback, a `Degraded` whose outcomes show all-restored,
/// a `Successful` whose outcomes disagree with the rollback's slots, an
/// `InProgress`/`PendingCommit` terminal — all are conversion errors, fail
/// closed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalDisposition {
    /// The deployment succeeded: the complete rollback payload (the full
    /// snapshot: per-slot generations + physical bindings — the ONE fact
    /// the per-slot outcomes cannot express; the outcomes' keys must agree
    /// with the rollback's slots, enforced by the conversion).
    Successful { rollback: CompleteRollback },
    /// The attempt failed before any slot mutation: no payload (no
    /// rollback — and the conversion also refuses outcomes, since a
    /// pre-mutation failure touched no slot).
    FailedPreflight,
    /// The attempt failed after mutating slots and was rolled back: no
    /// payload — the compensation report (each slot's per-slot result of
    /// the compensation pass: which slots were restored and which
    /// compensation failed) IS the terminal's authoritative outcomes table,
    /// derived via [`LedgerTerminal::compensation`].
    FailedRolledBack,
    /// The attempt ended degraded (some slots advanced and were not
    /// restored, or the commit could not be finalized): no payload — the
    /// REMAINING CHANGES (the slots that did not reach a restored state,
    /// each mapped to the generation it recorded) are DERIVED from the
    /// authoritative outcomes via [`LedgerTerminal::remaining_changes`]
    /// (NON-EMPTY by construction — the conversion refuses a Degraded wire
    /// whose outcomes show all-restored).
    Degraded,
}

impl TerminalDisposition {
    /// The disposition's status — the inverse of the wire's
    /// status→disposition mapping (a domain terminal derives its status
    /// from its disposition; the two are never stored side by side).
    pub fn status(&self) -> DeploymentStatus {
        match self {
            TerminalDisposition::Successful { .. } => DeploymentStatus::Successful,
            TerminalDisposition::FailedPreflight => DeploymentStatus::FailedPreflight,
            TerminalDisposition::FailedRolledBack => DeploymentStatus::FailedRolledBack,
            TerminalDisposition::Degraded => DeploymentStatus::Degraded,
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
/// — an invalid status/payload combination is unrepresentable.
///
/// STORE EACH FACT EXACTLY ONCE: the per-slot OUTCOMES are the authoritative
/// per-slot facts; the disposition carries ONLY what the outcomes cannot
/// express (the Successful rollback payload). The disposition's per-slot
/// projections — the Degraded REMAINING CHANGES and the FailedRolledBack
/// COMPENSATION REPORT — are DERIVED from the outcomes
/// ([`LedgerTerminal::remaining_changes`], [`LedgerTerminal::compensation`]),
/// never stored twice, so they can never disagree with the outcomes.
/// `reason` carries optional human context (e.g. "push completed", "recovery
/// finalized", "preflight failed") — a free-form human NOTE, not a fact: it
/// never participates in any invariant (the disposition IS the machine fact).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerTerminal {
    /// When the terminal event was recorded (RFC 3339).
    pub recorded_at: String,
    /// Actual per-slot outcomes after the mutation loop, the domain
    /// [`SlotTable`] (possibly empty — a pre-mutation failure touched no
    /// slot). THE AUTHORITATIVE per-slot facts: the disposition's per-slot
    /// projections (the Degraded remaining changes, the FailedRolledBack
    /// compensation report) are DERIVED from this table, never stored
    /// separately.
    pub outcomes: SlotTable<SlotOutcome>,
    /// HOW the attempt ended — the enum whose variants carry exactly their
    /// payload (the truth table is structural; the per-slot projections are
    /// derived from `outcomes`).
    pub disposition: TerminalDisposition,
    /// Optional human context: why this terminal event happened. A
    /// free-form NOTE, not a fact — it never participates in invariants
    /// (the disposition is the machine fact).
    pub reason: Option<String>,
}

impl LedgerTerminal {
    /// The terminal's status, DERIVED from its disposition (never stored
    /// separately — a status and a disposition can never disagree).
    pub fn status(&self) -> DeploymentStatus {
        self.disposition.status()
    }

    /// The REMAINING CHANGES of a [`TerminalDisposition::Degraded`] terminal
    /// — DERIVED from the authoritative per-slot outcomes (the slots whose
    /// outcome is non-restored, each mapped to the generation it recorded),
    /// never stored. `None` for any non-Degraded disposition. For a Degraded
    /// terminal the conversion guarantees at least one remaining change, so
    /// the derived value is always `Some` (non-empty by construction).
    pub fn remaining_changes(&self) -> Option<NonEmptySlotTable<GenerationId>> {
        if !matches!(self.disposition, TerminalDisposition::Degraded) {
            return None;
        }
        let remaining: BTreeMap<SlotId, GenerationId> = self
            .outcomes
            .iter()
            .filter(|(_, r)| r.outcome != SlotOutcomeKind::Restored && r.generation.is_some())
            .map(|(k, r)| {
                (
                    k.clone(),
                    r.generation
                        .clone()
                        .expect("a non-restored outcome whose generation is Some (filtered above)"),
                )
            })
            .collect();
        NonEmptySlotTable::build(remaining).ok()
    }

    /// The COMPENSATION REPORT of a [`TerminalDisposition::FailedRolledBack`]
    /// terminal — the authoritative per-slot outcomes table itself (the
    /// record of what the compensation pass did to each slot: which slots
    /// were restored and which compensation failed), never a stored
    /// duplicate. `None` for any other disposition.
    pub fn compensation(&self) -> Option<&CompensationReport> {
        if matches!(self.disposition, TerminalDisposition::FailedRolledBack) {
            Some(&self.outcomes)
        } else {
            None
        }
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
    pub outcomes: BTreeMap<SlotId, SlotResult>,
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
    /// status never carries one), each outcome's value must name its OWN
    /// map key (the outcome's `slot_id` is the placement slot it records),
    /// and the disposition's duplicated projections must AGREE with the
    /// authoritative outcomes, BY STATUS: a `Successful` wire's outcomes
    /// keys, rollback slots keys, and rollback bindings keys must be
    /// EXACTLY EQUAL and NON-EMPTY (every outcome must also be Activated),
    /// a `FailedPreflight` wire must carry NO outcomes (a pre-mutation
    /// failure touched no slot), and a `Degraded` wire's outcomes must
    /// derive a NON-EMPTY remaining-changes set (all-restored outcomes are
    /// refused). A disagreement → `Error::integrity`. The cross-record
    /// claims (the outcome key set vs the intent's `slot_ids` — the
    /// membership leg of the four-set equality — and the `target` field vs
    /// the read path / intent) are enforced by the ledger read that merges
    /// the intent and the terminal
    /// ([`crate::store::local::LocalStore::read_ledger`]).
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
                // THE FOUR-SET AGREEMENT (terminal-local half): the
                // outcomes keys, the rollback's slots keys, and the
                // rollback's bindings keys must be EXACTLY EQUAL and
                // NON-EMPTY — a successful deployment records a COMPLETE
                // rollback over EXACTLY the slots it reports outcomes for
                // (a missing OR extra key in any of the three
                // terminal-local sets is a disagreement; the fourth set —
                // the intent's membership — is enforced where the terminal
                // merges into its entry). The rollback's own conversion
                // already guarantees bindings == slots; the equality is
                // checked here against the outcomes so the invariant is
                // enforced in ONE place, and the NON-EMPTY refusal closes
                // the "successful with no outcomes" hole (an empty outcome
                // table can never agree with a non-empty rollback).
                let outcome_keys: BTreeSet<&SlotId> = outcomes.keys().collect();
                let rollback_slot_keys: BTreeSet<&SlotId> = rollback.slots.keys().collect();
                let rollback_binding_keys: BTreeSet<&SlotId> = rollback.bindings.keys().collect();
                if outcome_keys.is_empty() {
                    return Err(Error::integrity(format!(
                        "terminal {}: status Successful requires NON-EMPTY outcomes — a successful deployment records a complete rollback over exactly the slots it reports outcomes for",
                        self.deployment_id
                    )));
                }
                if outcome_keys != rollback_slot_keys || outcome_keys != rollback_binding_keys {
                    return Err(Error::integrity(format!(
                        "terminal {}: status Successful requires the outcomes keys, the rollback's slots keys, and the rollback's bindings keys to be EXACTLY EQUAL (outcomes {outcome_keys:?} vs rollback slots {rollback_slot_keys:?} vs rollback bindings {rollback_binding_keys:?})",
                        self.deployment_id
                    )));
                }
                // A Successful deployment implies every slot activated: a
                // non-activated outcome is a disagreement (the disposition's
                // implied state vs the recorded outcome).
                if let Some(r) = outcomes
                    .values()
                    .find(|r| r.outcome != SlotOutcomeKind::Activated)
                {
                    return Err(Error::integrity(format!(
                        "terminal {}: status Successful requires every outcome Activated — slot '{}' records {:?}",
                        self.deployment_id, r.slot_id, r.outcome
                    )));
                }
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
                // of what the compensation pass did to each slot — DERIVED
                // from the authoritative outcomes
                // ([`LedgerTerminal::compensation`]), never stored as a
                // duplicate that could disagree with them.
                TerminalDisposition::FailedRolledBack
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
                // recorded. DERIVED from the wire outcomes
                // ([`LedgerTerminal::remaining_changes`]) — never stored.
                // The derivation must be NON-EMPTY (a degraded terminal with
                // every slot restored — or with no recorded outcome — has no
                // remaining change and is refused: a status whose payload
                // does not match its disposition).
                let remaining: BTreeMap<SlotId, GenerationId> = outcomes
                    .iter()
                    .filter(|(_, r)| {
                        r.outcome != SlotOutcomeKind::Restored && r.generation.is_some()
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
                NonEmptySlotTable::build(remaining).map_err(|_| {
                    Error::integrity(format!(
                        "terminal {}: status Degraded requires at least one REMAINING change (a non-restored outcome with a recorded generation)",
                        self.deployment_id
                    ))
                })?;
                TerminalDisposition::Degraded
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
/// the retention subsystem's project-file `[[pins]]`
/// ([`crate::config::Pin`]): the checkpoint flow is store-only (it never
/// loads the caller's `deploy.toml`), so its retention anchors live in the
/// store, while retention's config pins protect the REMOTE retained set and
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
    pub slots: BTreeMap<SlotId, ObservedSlot>,
}

/// Persisted per-server local record (`servers/<id>.json`). Keyed by the
/// ACTUAL server identity ([`ServerId`], transport addressing); the
/// slot→assignment maps live in [`ObservedTarget`] keyed by
/// [`SlotId`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ServerState {
    pub id: ServerId,
    #[serde(default)]
    pub last_seen_target: Option<TargetName>,
    #[serde(default)]
    pub last_observed: Option<ObservedSlot>,
}

/// Where a plan's desired assignment comes from — the WIRE (on-disk) form
/// of the plan source. The wire keeps this shape: a `release:<id>` source
/// names the release, and the CLAIMED rebinding proof lives in the
/// separate [`DeploymentPlanWire::rebinding`] field ([`RebindingPlan`]).
/// The VERIFYING CONVERSION ([`DeploymentPlanWire::into_domain`]) recomputes
/// the proof and exposes the verified [`PlanOrigin`] on the domain — a
/// Release origin without its proof is unrepresentable there.
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
    /// slots. The rebinding this performs is EXPLICIT: the wire carries the
    /// claimed proof as [`DeploymentPlanWire::rebinding`]
    /// ([`RebindingPlan`]); the domain conversion verifies it and carries
    /// the verified proof inside [`PlanOrigin::Release`].
    ReleaseRef(ReleaseId),
}

/// The VERIFIED origin of a deployment plan — the DOMAIN form of the wire's
/// [`PlanSource`] + separate `rebinding` fields. THE SOURCE OWNS ITS
/// REQUIRED PAYLOAD: a Release origin ([`PlanOrigin::Release`]) CARRIES its
/// [`VerifiedReleaseRebinding`] (the proof) INSIDE the source — a Release
/// origin without the proof is unrepresentable; HEAD and deployment origins
/// carry none. The wire → domain conversion
/// ([`DeploymentPlanWire::into_domain`]) RECOMPUTES the proof from the
/// wire's claimed rebinding and the plan's own source/target/membership,
/// succeeding only when the claimed rebinding matches the recomputed proof
/// (a mismatch → [`crate::error::Error::integrity`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanOrigin {
    /// Materialize the currently mapped local files and assign each slot its
    /// target-configured (current) variant.
    Head,
    /// Restore the stored state of a successful deployment, keyed by its
    /// deployment id.
    Deployment(DeploymentId),
    /// Assign each current slot its variant from a named release — the
    /// release's OWN frozen topology applied onto the CURRENT physical
    /// slots. The rebinding this performs is EXPLICIT and VERIFIED: the
    /// proof ([`VerifiedReleaseRebinding`]) is carried INSIDE the source.
    Release {
        release: ReleaseId,
        rebinding: VerifiedReleaseRebinding,
    },
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

/// The WIRE (claimed) rebinding context of a direct `release:<id>` plan: the
/// historical release's frozen topology applied onto the CURRENT physical
/// slots. This is the ON-DISK shape ([`DeploymentPlanWire::rebinding`]); the
/// domain's verified form is [`VerifiedReleaseRebinding`] — the wire →
/// domain conversion RECOMPUTES the proof from this claimed shape and the
/// plan's own source/target/membership, succeeding only when the claimed
/// rebinding matches the recomputed proof (a mismatch →
/// [`crate::error::Error::integrity`]).
///
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
/// onto. Produced at plan time in the `PushRef::Release` branch; HEAD and
/// deployment-keyed plans carry `None`.
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
    pub frozen_topology: BTreeMap<SlotId, FrozenSlotTopology>,
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
    pub current_physical_slots: BTreeMap<SlotId, PhysicalBinding>,
}

/// The VERIFIED rebinding proof carried by a Release-origin plan: the
/// complete evidence that the plan's claimed rebinding is REAL — the
/// historical release, the destination target, the release's frozen
/// slot→variant/group topology, the membership PROOF (frozen == current,
/// verified), the SELECTED plan slots (the plan's membership), and the
/// current physical slots the frozen topology is bound onto. A Release
/// origin WITHOUT this proof is unrepresentable ([`PlanOrigin::Release`]
/// carries it INSIDE the source); HEAD and deployment origins carry none.
///
/// The ONLY construction path is [`VerifiedReleaseRebinding::verify`], which
/// checks that every component agrees — the frozen topology's keys equal the
/// membership's agreed slots, every selected plan slot is a member of the
/// agreed membership, and the current physical slots cover exactly the
/// selected plan slots. The wire → domain conversion
/// ([`DeploymentPlanWire::into_domain`]) RECOMPUTES the proof from the
/// wire's claimed [`RebindingPlan`] and the plan's own source/target/
/// membership, succeeding only when the claimed rebinding matches the
/// recomputed proof (a mismatch → [`crate::error::Error::integrity`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedReleaseRebinding {
    /// The historical release being rebound.
    pub release: ReleaseId,
    /// The destination target the release is rebound onto.
    pub target: TargetName,
    /// The release's frozen slot→variant/group topology, filtered to the
    /// destination target (from the release record's OWN canonical slot
    /// snapshot). Complete regardless of group selection: a `--group` push
    /// narrows the PLANNED assignments, never the recorded topology.
    pub frozen_topology: BTreeMap<SlotId, FrozenSlotTopology>,
    /// The membership PROOF that ran before planning (see
    /// [`MatchingMembership`]): `frozen == current` verified (slot IDs only;
    /// physical bindings may differ). For a group push this is the COMPLETE
    /// membership — the group narrows the planned slots, never the
    /// membership check.
    pub(crate) membership: MatchingMembership,
    /// The SELECTED plan slots: the plan's membership (the `slots` map keys)
    /// — the slots the frozen topology is actually bound onto. A group
    /// selection records exactly the selected slots (the group-filtered
    /// assignments); a full push records every member slot.
    pub selected_plan_slots: BTreeSet<SlotId>,
    /// The CURRENT physical slots the frozen topology is bound onto, per
    /// SELECTED slot: `slot -> {server, deploy_dir}` from the caller's
    /// current configuration.
    pub current_physical_slots: BTreeMap<SlotId, PhysicalBinding>,
}

impl VerifiedReleaseRebinding {
    /// The ONLY construction path: verify that the claimed rebinding
    /// components agree — the frozen topology's keys must equal the
    /// membership's agreed slots, every selected plan slot must be a member
    /// of the agreed membership, and the current physical slots must cover
    /// exactly the selected plan slots. Any disagreement →
    /// [`crate::error::Error::integrity`] (fail closed: a hand-constructed
    /// proof can never put the components out of agreement).
    pub(crate) fn verify(
        release: ReleaseId,
        target: TargetName,
        frozen_topology: BTreeMap<SlotId, FrozenSlotTopology>,
        membership: MatchingMembership,
        selected_plan_slots: BTreeSet<SlotId>,
        current_physical_slots: BTreeMap<SlotId, PhysicalBinding>,
    ) -> Result<Self> {
        let membership_slots: BTreeSet<SlotId> = membership.slots().iter().cloned().collect();
        let frozen_keys: BTreeSet<SlotId> = frozen_topology.keys().cloned().collect();
        if frozen_keys != membership_slots {
            return Err(Error::integrity(
                "rebinding proof refused: the frozen topology keys disagree with the membership's agreed slots",
            ));
        }
        for slot in &selected_plan_slots {
            if !membership_slots.contains(slot) {
                return Err(Error::integrity(format!(
                    "rebinding proof refused: selected slot '{slot}' is outside the agreed membership"
                )));
            }
        }
        let physical_keys: BTreeSet<SlotId> = current_physical_slots.keys().cloned().collect();
        if physical_keys != selected_plan_slots {
            return Err(Error::integrity(
                "rebinding proof refused: the current physical slots disagree with the selected plan slots",
            ));
        }
        Ok(VerifiedReleaseRebinding {
            release,
            target,
            frozen_topology,
            membership,
            selected_plan_slots,
            current_physical_slots,
        })
    }
}

/// Per-slot plan for one placement slot: its slot identity, the artifact it
/// should run, and the compare-and-swap preconditions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotPlan {
    pub slot_id: SlotId,
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
    pub slot_ids: Vec<SlotId>,
    pub slots: BTreeMap<SlotId, SlotPlan>,
    pub source: PlanSource,
    /// When the plan was built from a DIRECT release reference
    /// (`PlanSource::ReleaseRef`), the CLAIMED rebinding context: the
    /// historical release's frozen topology applied onto the CURRENT
    /// physical slots ([`RebindingPlan`]). `None` for HEAD and
    /// deployment-keyed plans. The VERIFYING CONVERSION recomputes the
    /// proof from this claimed shape and the plan's own
    /// source/target/membership, refusing any disagreement (a Release
    /// origin without a proof, or a non-Release origin carrying one, is
    /// refused). `#[serde(default)]` keeps deployment records written
    /// before this field loadable; `skip_serializing_if` keeps the
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
        let wire_slots: BTreeSet<&SlotId> = self.slot_ids.iter().collect();
        let keys: BTreeSet<&SlotId> = self.slots.keys().collect();
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
        // THE SOURCE OWNS ITS REQUIRED PAYLOAD: the wire's `PlanSource` +
        // separate `rebinding` field convert to the domain's [`PlanOrigin`]
        // by RECOMPUTING the proof. A Release origin must carry its
        // [`VerifiedReleaseRebinding`] (a Release source without a claimed
        // rebinding is refused — the proof is unrepresentable without it);
        // HEAD and deployment origins must carry NONE (a claimed rebinding
        // on a non-Release plan is a disagreement — the domain has no place
        // for it, so it is refused rather than silently dropped). The
        // recomputation compares the claimed rebinding against the plan's
        // own source/target/membership: the claimed release must be the
        // plan's source release AND the release its slots reference, the
        // claimed target must equal the plan's target, and the claimed
        // components must agree internally (frozen topology keys ==
        // membership, selected plan slots ⊆ membership, physical slots ==
        // selected). A mismatch → `Error::integrity` (fail closed: a
        // tampered plan can never claim a rebinding its source/release/
        // target/slots don't support).
        let source = match self.source {
            PlanSource::Head => {
                if self.rebinding.is_some() {
                    return Err(Error::integrity(format!(
                        "plan {}: a HEAD plan cannot carry a rebinding proof",
                        self.deployment_id
                    )));
                }
                PlanOrigin::Head
            }
            PlanSource::DeploymentRef(deployment_id) => {
                if self.rebinding.is_some() {
                    return Err(Error::integrity(format!(
                        "plan {}: a deployment-keyed plan cannot carry a rebinding proof",
                        self.deployment_id
                    )));
                }
                PlanOrigin::Deployment(deployment_id)
            }
            PlanSource::ReleaseRef(release) => {
                let claimed = self.rebinding.ok_or_else(|| {
                    Error::integrity(format!(
                        "plan {}: a release-origin plan must carry its rebinding proof",
                        self.deployment_id
                    ))
                })?;
                // The claimed release must be the plan's source release AND
                // the release the plan's slots reference (a release-origin
                // plan's slots all reference the release).
                if claimed.release != release {
                    return Err(Error::integrity(format!(
                        "plan {}: the claimed rebinding release {} disagrees with the plan's source release {release}",
                        self.deployment_id, claimed.release
                    )));
                }
                if claimed.target != self.target {
                    return Err(Error::integrity(format!(
                        "plan {}: the claimed rebinding target '{}' disagrees with the plan's target '{}'",
                        self.deployment_id, claimed.target, self.target
                    )));
                }
                let derived: BTreeSet<ReleaseId> = self
                    .slots
                    .values()
                    .map(|p| p.artifact.release.clone())
                    .collect();
                if derived != BTreeSet::from([release.clone()]) {
                    return Err(Error::integrity(format!(
                        "plan {}: the claimed rebinding release {release} disagrees with the releases derived from the plan's slots {derived:?}",
                        self.deployment_id
                    )));
                }
                // RECOMPUTE the proof from the claimed components and the
                // plan's own membership (the selected plan slots are the
                // plan's `slots` map keys).
                let proof = VerifiedReleaseRebinding::verify(
                    claimed.release,
                    claimed.target,
                    claimed.frozen_topology,
                    claimed.membership,
                    self.slots.keys().cloned().collect(),
                    claimed.current_physical_slots,
                )
                .map_err(|e| {
                    Error::integrity(format!(
                        "plan {}: the claimed rebinding disagrees with the recomputed proof: {e}",
                        self.deployment_id
                    ))
                })?;
                PlanOrigin::Release {
                    release,
                    rebinding: proof,
                }
            }
        };
        Ok(DeploymentPlan {
            deployment_id: self.deployment_id,
            target: self.target,
            behaviors: self.behaviors,
            slots: self.slots,
            source,
        })
    }
}

impl From<&DeploymentPlan> for DeploymentPlanWire {
    fn from(p: &DeploymentPlan) -> Self {
        // The domain's [`PlanOrigin`] re-expands into the wire's `PlanSource`
        // + separate `rebinding` shape: a Release origin carries its
        // verified proof back into the claimed [`RebindingPlan`] (the
        // selected plan slots are re-derived from the plan's membership on
        // the next read); HEAD and deployment origins carry `None`.
        let (source, rebinding) = match &p.source {
            PlanOrigin::Head => (PlanSource::Head, None),
            PlanOrigin::Deployment(deployment_id) => {
                (PlanSource::DeploymentRef(deployment_id.clone()), None)
            }
            PlanOrigin::Release { release, rebinding } => (
                PlanSource::ReleaseRef(release.clone()),
                Some(RebindingPlan {
                    release: rebinding.release.clone(),
                    target: rebinding.target.clone(),
                    frozen_topology: rebinding.frozen_topology.clone(),
                    membership: rebinding.membership.clone(),
                    current_physical_slots: rebinding.current_physical_slots.clone(),
                }),
            ),
        };
        DeploymentPlanWire {
            deployment_id: p.deployment_id.clone(),
            target: p.target.clone(),
            behavior_sha256: p.behavior_digest(),
            behaviors: p.behaviors.clone(),
            slot_ids: p.membership().cloned().collect(),
            slots: p.slots.clone(),
            source,
            rebinding,
            desired_releases: p.releases(),
        }
    }
}

/// A deployment plan, the VALIDATED DOMAIN form of [`DeploymentPlanWire`]:
/// the attempt's snapshot-wide behavior digest, the frozen per-release
/// name-keyed activation + verification contracts, and the per-slot plans.
/// ONE AUTHORITATIVE COLLECTION PER CONCEPT — `slots` (per-slot plans) is
/// the membership AND the release source; `behaviors` (the index) is the
/// behavior source; `source` ([`PlanOrigin`]) is the verified origin and
/// OWNS its required payload (a Release origin carries its
/// [`VerifiedReleaseRebinding`] proof inside the source). The `slot_ids` /
/// `desired_releases` / `behavior_sha256` members exist only in the wire
/// (the serialized `plan.json` keeps the redundant shape) and are derived
/// here through [`DeploymentPlan::membership`], [`DeploymentPlan::releases`],
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
    pub slots: BTreeMap<SlotId, SlotPlan>,
    /// THE SOURCE OWNS ITS REQUIRED PAYLOAD: a Release origin
    /// ([`PlanOrigin::Release`]) CARRIES its verified rebinding proof
    /// ([`VerifiedReleaseRebinding`]) INSIDE the source — a Release origin
    /// without the proof is unrepresentable; HEAD and deployment origins
    /// carry none. The wire's separate `rebinding` field exists only in the
    /// on-disk shape ([`DeploymentPlanWire`]) and is reconciled by the
    /// verifying conversion.
    pub source: PlanOrigin,
}

impl DeploymentPlan {
    /// The plan's membership: the selected placement slots, DERIVED from the
    /// authoritative `slots` map (its keys) — never stored separately.
    pub fn membership(&self) -> impl Iterator<Item = &SlotId> {
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
    pub slot_id: SlotId,
    pub outcome: SlotOutcomeKind,
    /// The generation this slot advanced to, or `None` if it never started.
    pub generation: Option<GenerationId>,
    pub compensated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PlacementSlotAssignment, SlotSet, VariantName};
    use crate::store::local::LocalStore;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    // ---- fixtures ----------------------------------------------------------

    fn slot(i: u32) -> SlotId {
        SlotId::new(format!("slot-{i}"))
    }

    fn slot_strategy() -> impl Strategy<Value = SlotId> {
        (0u32..6).prop_map(slot)
    }

    fn binding(sid: &SlotId) -> PhysicalBinding {
        PhysicalBinding {
            server: ServerId::new("s1".to_string()),
            deploy_dir: format!("/srv/deploy/{}", sid.as_str()),
        }
    }

    /// A generation ref whose assignment names its own key (the agreeing
    /// form); the artifact's release is derived from the slot id.
    fn gen_ref_for(key: &SlotId) -> GenerationRef {
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

    fn agreeing_intent(keys: &[SlotId]) -> LedgerIntentWire {
        let desired: BTreeMap<SlotId, GenerationRef> =
            keys.iter().map(|k| (k.clone(), gen_ref_for(k))).collect();
        let pre_push: BTreeMap<SlotId, Option<SlotAttemptState>> =
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

    fn outcome_for(key: &SlotId, kind: SlotOutcomeKind) -> SlotResult {
        let compensated = matches!(&kind, SlotOutcomeKind::Restored);
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
    fn agreeing_terminal(keys: &[SlotId], status_idx: u32) -> LedgerTerminalWire {
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
                    .map(|k| (k.clone(), outcome_for(k, SlotOutcomeKind::Activated)))
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
                    .map(|k| (k.clone(), outcome_for(k, SlotOutcomeKind::Restored)))
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
                    .map(|k| (k.clone(), outcome_for(k, SlotOutcomeKind::Skipped)))
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
                let keys: Vec<SlotId> = keys.into_iter().collect();
                (
                    agreeing_intent(keys.as_slice()),
                    agreeing_terminal(keys.as_slice(), status_idx),
                )
            },
        )
    }

    /// UNIQUE slot ids in an ARBITRARY PERMUTATION: a shuffled non-empty
    /// subset of the slot universe — the wire's `slot_ids` is the
    /// authoritative deployment order, so the ordering property must cover
    /// orders that are NOT sorted by id.
    fn slot_ids_permutation() -> impl Strategy<Value = Vec<SlotId>> {
        prop::collection::btree_set(slot_strategy(), 1..4).prop_flat_map(|set| {
            let ids: Vec<SlotId> = set.into_iter().collect();
            let n = ids.len();
            // Shuffle the selected ids by sorting random keys: every order is
            // reachable (with n ≤ 3 the key space is collision-free in
            // practice), and the strategy shrinks naturally.
            prop::collection::vec(0u32..1000, n).prop_map(move |keys| {
                let mut order: Vec<usize> = (0..n).collect();
                order.sort_by_key(|&i| keys[i]);
                order.into_iter().map(|i| ids[i].clone()).collect()
            })
        })
    }

    // ---- THE VERIFYING PAIR CONVERSION + the read_ledger consumer ---------

    /// Run the full verifying conversion of an intent + terminal pair — the
    /// SAME checks `read_ledger` runs when it merges a terminal into its
    /// entry (the entry owns identity: the terminal's id is the entry key,
    /// its target must equal the entry's, every outcome key must be a
    /// member of the intent's membership, and the outcome key set must
    /// agree with the membership BY STATUS: Successful → EXACTLY equal
    /// (the four-set equality's membership leg), FailedPreflight → empty,
    /// every other state → EXACT coverage) — returning the validated domain
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
        // STATUS-SPECIFIC OUTCOME AGREEMENT (the membership leg of the
        // four-set equality — the same rules `read_ledger` enforces when it
        // merges the terminal into its entry).
        let outcome_keys: BTreeSet<&SlotId> = terminal.outcomes.keys().collect();
        let membership: BTreeSet<&SlotId> = intent.slots.keys().collect();
        match terminal.status() {
            DeploymentStatus::Successful => {
                if outcome_keys != membership {
                    return Err(Error::integrity(format!(
                        "terminal {}: Successful outcomes {outcome_keys:?} must EXACTLY equal the intent's membership {membership:?} (the four-set equality: outcomes == rollback slots == rollback bindings == intent membership)",
                        pair.1.deployment_id
                    )));
                }
            }
            DeploymentStatus::FailedPreflight => {
                if !outcome_keys.is_empty() {
                    return Err(Error::integrity(format!(
                        "terminal {}: FailedPreflight must carry NO outcomes (a pre-mutation failure touched no slot)",
                        pair.1.deployment_id
                    )));
                }
            }
            _ => {
                if outcome_keys != membership {
                    return Err(Error::integrity(format!(
                        "terminal {}: outcomes {outcome_keys:?} must EXACTLY cover the intent's membership {membership:?} — no missing, no extra",
                        pair.1.deployment_id
                    )));
                }
            }
        }
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
        keys: &[SlotId],
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
            (TerminalDisposition::FailedRolledBack, 2) => {
                let compensation = terminal.compensation().expect(
                    "a FailedRolledBack terminal derives its compensation report from the outcomes",
                );
                assert_eq!(
                    compensation.len(),
                    keys.len(),
                    "the compensation report covers every compensated slot"
                );
                assert!(
                    compensation
                        .iter()
                        .all(|(_, r)| r.outcome == SlotOutcomeKind::Restored),
                    "the compensation records the restored slots"
                );
            }
            (TerminalDisposition::Degraded, 3) => {
                let remaining_changes = terminal
                    .remaining_changes()
                    .expect("a Degraded terminal derives its remaining changes from the outcomes");
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
                .insert(slot(0), outcome_for(&slot(9), SlotOutcomeKind::Activated));
        }
    }
    fn outcome_outside_membership(t: &mut LedgerTerminalWire) {
        t.outcomes
            .insert(slot(9), outcome_for(&slot(9), SlotOutcomeKind::Activated));
    }
    fn outcome_status_vs_disposition(t: &mut LedgerTerminalWire) {
        match &t.status {
            DeploymentStatus::Degraded => {
                // The Degraded disposition implies non-restored remaining
                // changes; an all-restored outcome table is a disagreement.
                for r in t.outcomes.values_mut() {
                    r.outcome = SlotOutcomeKind::Restored;
                }
            }
            DeploymentStatus::FailedPreflight => {
                // A pre-mutation failure touched no slot; any outcome is a
                // disagreement.
                t.outcomes
                    .insert(slot(0), outcome_for(&slot(0), SlotOutcomeKind::Activated));
            }
            DeploymentStatus::Successful => {
                // The Successful disposition implies every slot activated; a
                // failed outcome is a disagreement.
                if let Some(r) = t.outcomes.values_mut().next() {
                    r.outcome = SlotOutcomeKind::Failed;
                }
            }
            DeploymentStatus::FailedRolledBack => {
                // The compensation report IS the outcome table — no per-slot
                // status can disagree with it; the disagreement is a
                // rollback payload on a failed status.
                t.rollback = Some(LedgerRollbackWire {
                    slots: BTreeMap::new(),
                    bindings: BTreeMap::new(),
                    behavior_sha256: None,
                    release: None,
                });
            }
            other => panic!("unexpected wire status {other:?}"),
        }
    }
    fn outcome_key_vs_rollback_slots(t: &mut LedgerTerminalWire) {
        if t.status == DeploymentStatus::Successful {
            // The Successful rollback is the authoritative rollback fact; an
            // outcome key the rollback no longer covers is a disagreement.
            let Some(rb) = t.rollback.as_mut() else {
                return;
            };
            let Some(key) = rb.slots.keys().next().cloned() else {
                return;
            };
            rb.slots.remove(&key);
            rb.bindings.remove(&key);
        } else {
            // Only Successful may carry a rollback; a failed status with one
            // is a disagreement.
            t.rollback = Some(LedgerRollbackWire {
                slots: BTreeMap::new(),
                bindings: BTreeMap::new(),
                behavior_sha256: None,
                release: None,
            });
        }
    }
    fn reason_mutated(t: &mut LedgerTerminalWire) {
        // The reason is a free-form human NOTE, not a fact: it never
        // participates in invariants, so mutating it is NOT a disagreement.
        t.reason = Some("tampered note".to_string());
    }
    fn target_mismatch(t: &mut LedgerTerminalWire) {
        t.target = TargetName::new("other-target".to_string());
    }
    fn deployment_id_mismatch(t: &mut LedgerTerminalWire) {
        t.deployment_id = DeploymentId::new("deploy-other".to_string());
    }

    proptest! {
        // PROPERTY (the directive's point 4): generate VALID wire pairs
        // (intent + terminal), then mutate ONE duplicated fact at a time —
        // the status→disposition mapping, the rollback payload, an outcome
        // slot, an outcome's status vs the disposition's implied state, an
        // outcome key vs the rollback's slots, the target identity — and
        // assert EVERY disagreement fails the verifying conversion BEFORE
        // any consumer (the REAL read_ledger consumer path), while the
        // VALID pair converts to a DOMAIN whose SHAPE has no
        // duplicates/missing keys (asserted by inspection of the
        // NonEmptySlotTable / outcomes / disposition) and whose DERIVED
        // methods (`remaining_changes`, `compensation`) agree with the
        // outcomes by construction. The REASON is a free-form human note,
        // NOT a fact: mutating it never creates a disagreement — the
        // conversion succeeds and carries the note through unchanged.
        // Bounded 16 cases, fixed seed 0x5EED_5EED (house style), no
        // persistence.
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
            let keys: Vec<SlotId> = intent.slot_ids.clone();
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

            let mutations: [(&str, TerminalMutation); 9] = [
                ("status→disposition mismatch", tamper_status),
                ("rollback payload mismatch (missing on Successful / added to a failed status)", rollback_added_to_failed),
                ("rollback binding without a generation", rollback_extra_binding),
                ("outcome value naming a different slot", outcome_slot_mismatch),
                ("outcome key outside the membership", outcome_outside_membership),
                ("outcome status vs the disposition's implied state", outcome_status_vs_disposition),
                ("outcome key vs the rollback's slots", outcome_key_vs_rollback_slots),
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

            // The REASON is a free-form human note, NOT a fact: mutating it
            // never creates a disagreement — the conversion succeeds and
            // carries the note through unchanged (it never participates in
            // invariants).
            let mut noted = (intent, terminal);
            reason_mutated(&mut noted.1);
            let (_, d_terminal) =
                pair_to_domain(&noted).expect("a mutated reason is not a disagreement");
            assert_eq!(
                d_terminal.reason.as_deref(),
                Some("tampered note"),
                "the note is carried through unchanged"
            );
        }
    }

    // ---- THE FOUR-SET EQUALITY PROPERTY (Successful) -----------------------

    /// One key-set operation applied to ONE of the four sets (outcomes,
    /// rollback slots, rollback bindings, intent membership). The ops are
    /// chosen INDEPENDENTLY per set; the application is deterministic given
    /// the op (delete the first key / add the first absent slot / replace
    /// the first key with the first absent slot), so the property's
    /// "succeeds iff all four sets are identical" verdict is exact.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum KeyOp {
        Unchanged,
        Delete,
        Add,
        Replace,
    }

    fn key_op() -> impl Strategy<Value = KeyOp> {
        prop_oneof![
            Just(KeyOp::Unchanged),
            Just(KeyOp::Delete),
            Just(KeyOp::Add),
            Just(KeyOp::Replace),
        ]
    }

    /// Apply one key op to a slot set (deterministic: delete the first
    /// key, add the first slot absent from the set, replace the first key
    /// with the first absent slot).
    fn apply_key_op(set: &BTreeSet<SlotId>, op: KeyOp) -> BTreeSet<SlotId> {
        let mut out = set.clone();
        match op {
            KeyOp::Unchanged => {}
            KeyOp::Delete => {
                if let Some(k) = out.iter().next().cloned() {
                    out.remove(&k);
                }
            }
            KeyOp::Add => {
                for i in 0..6u32 {
                    let k = slot(i);
                    if !out.contains(&k) {
                        out.insert(k);
                        break;
                    }
                }
            }
            KeyOp::Replace => {
                if let Some(k) = out.iter().next().cloned() {
                    out.remove(&k);
                    for i in 0..6u32 {
                        let nk = slot(i);
                        if !out.contains(&nk) {
                            out.insert(nk);
                            break;
                        }
                    }
                }
            }
        }
        out
    }

    /// Rebuild the intent wire with a NEW membership, keeping the intent's
    /// internal agreement (slot_ids == desired == pre_push, each assignment
    /// names its own key, the wire actuals map empty).
    fn intent_with_membership(
        intent: &LedgerIntentWire,
        membership: &BTreeSet<SlotId>,
    ) -> LedgerIntentWire {
        let keys: Vec<SlotId> = membership.iter().cloned().collect();
        let desired: BTreeMap<SlotId, GenerationRef> =
            keys.iter().map(|k| (k.clone(), gen_ref_for(k))).collect();
        let pre_push: BTreeMap<SlotId, Option<SlotAttemptState>> =
            keys.iter().map(|k| (k.clone(), None)).collect();
        LedgerIntentWire {
            deployment_schema_version: intent.deployment_schema_version,
            deployment_id: intent.deployment_id.clone(),
            target: intent.target.clone(),
            group: intent.group.clone(),
            slot_ids: keys.clone(),
            behavior_sha256: intent.behavior_sha256.clone(),
            attempted_at: intent.attempted_at.clone(),
            desired,
            pre_push,
            slots: BTreeMap::new(),
        }
    }

    /// Apply the four INDEPENDENT key ops to a valid Successful pair and
    /// return the tampered pair: (a) the outcomes keys, (b) the rollback's
    /// slots keys, (c) the rollback's bindings keys, (d) the intent's
    /// membership (rebuilt so the intent stays internally agreeing).
    fn apply_four_set_tamper(
        pair: &(LedgerIntentWire, LedgerTerminalWire),
        ops: [KeyOp; 4],
    ) -> (LedgerIntentWire, LedgerTerminalWire) {
        let (intent, terminal) = pair;
        let mut terminal = terminal.clone();
        // (a) outcomes keys.
        let outcome_keys: BTreeSet<SlotId> = terminal.outcomes.keys().cloned().collect();
        let new_outcomes = apply_key_op(&outcome_keys, ops[0]);
        terminal.outcomes = new_outcomes
            .iter()
            .map(|k| (k.clone(), outcome_for(k, SlotOutcomeKind::Activated)))
            .collect();
        // (b) rollback slots keys, (c) rollback bindings keys.
        let rb = terminal
            .rollback
            .as_mut()
            .expect("a Successful terminal carries its rollback");
        let slot_keys: BTreeSet<SlotId> = rb.slots.keys().cloned().collect();
        let new_slots = apply_key_op(&slot_keys, ops[1]);
        rb.slots = new_slots
            .iter()
            .map(|k| (k.clone(), gen_ref_for(k)))
            .collect();
        let binding_keys: BTreeSet<SlotId> = rb.bindings.keys().cloned().collect();
        let new_bindings = apply_key_op(&binding_keys, ops[2]);
        rb.bindings = new_bindings
            .iter()
            .map(|k| (k.clone(), binding(k)))
            .collect();
        // (d) the intent's membership.
        let membership: BTreeSet<SlotId> = intent.slot_ids.iter().cloned().collect();
        let new_membership = apply_key_op(&membership, ops[3]);
        let intent = intent_with_membership(intent, &new_membership);
        (intent, terminal)
    }

    proptest! {
        // PROPERTY (the directive's point 4): generate a VALID
        // intent/successful-terminal pair, then INDEPENDENTLY DELETE / ADD /
        // REPLACE keys in (a) the outcomes, (b) the rollback's slots, (c)
        // the rollback's bindings — and (d) the intent's membership (the
        // fourth set, so the "a tamper happens to keep the sets equal — e.g.
        // adding the same key to all four — succeeds" direction is exercised
        // too). READING (the real `read_ledger` conversion) SUCCEEDS IFF
        // ALL FOUR SETS ARE IDENTICAL (and non-empty — the Successful
        // rule's non-emptiness): the untampered case and any tamper that
        // keeps the four sets equal succeed; any single-set divergence
        // fails. Bounded 16 cases, fixed seed 0x5EED_5EED per house style,
        // no persistence.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn successful_four_set_equality_is_necessary_and_sufficient(
            (intent, terminal) in agreeing_pair().prop_filter(
                "the property needs a Successful pair",
                |(_, t)| t.status == DeploymentStatus::Successful,
            ),
            ops in prop::array::uniform4(key_op()),
        ) {
            let (t_intent, t_terminal) = apply_four_set_tamper(&(intent, terminal), ops);
            // The four resulting sets (owned — the pair is consumed by the
            // ledger write below).
            let outcomes: BTreeSet<SlotId> = t_terminal.outcomes.keys().cloned().collect();
            let rb = t_terminal
                .rollback
                .as_ref()
                .expect("Successful carries its rollback");
            let rollback_slots: BTreeSet<SlotId> = rb.slots.keys().cloned().collect();
            let rollback_bindings: BTreeSet<SlotId> = rb.bindings.keys().cloned().collect();
            let membership: BTreeSet<SlotId> = t_intent.slot_ids.iter().cloned().collect();
            let all_identical = outcomes == rollback_slots
                && outcomes == rollback_bindings
                && outcomes == membership;
            let expect_ok = all_identical && !outcomes.is_empty();
            let read = write_pair_ledger(&(t_intent, t_terminal));
            assert_eq!(
                read.is_ok(),
                expect_ok,
                "read_ledger must succeed iff the four sets are identical and non-empty (outcomes {outcomes:?}, rollback slots {rollback_slots:?}, rollback bindings {rollback_bindings:?}, membership {membership:?}); read: {read:?}"
            );
        }
    }

    // ---- THE ORDERING PROPERTY (the ordered tables) ------------------------

    proptest! {
        // THE ORDERING PROPERTY (the user's requirement): the wire's
        // `slot_ids` is the AUTHORITATIVE deployment order, and the domain
        // table must PRESERVE it exactly — never silently re-sort by slot
        // id. Over UNIQUE slot ids in ARBITRARY PERMUTATIONS, the wire →
        // domain → wire round trip must reproduce the EXACT `slot_ids`
        // sequence (not the sorted order): the domain table iterates in the
        // wire's sequence, the domain → wire re-expansion emits the same
        // sequence, and the full JSON round trip preserves it. Bounded 16
        // cases, fixed seed 0x5EED_5EED (house style), no persistence.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn wire_slot_ids_sequence_round_trips_exactly(keys in slot_ids_permutation()) {
            let wire = agreeing_intent(&keys);
            let domain = wire
                .clone()
                .into_domain()
                .expect("the agreeing intent converts");
            // The DOMAIN table iterates in the wire's sequence order.
            assert_eq!(
                domain.membership(),
                keys,
                "the domain table must preserve the wire's slot_ids sequence (deployment order), not sort by id"
            );
            // The domain → wire re-expansion emits the SAME sequence.
            let wire2 = LedgerIntentWire::from(&domain);
            assert_eq!(
                wire2.slot_ids, keys,
                "the domain → wire re-expansion must reproduce the exact slot_ids sequence"
            );
            // The full JSON round trip (serialize → deserialize) too.
            let json = serde_json::to_string(&domain).unwrap();
            let wire3: LedgerIntentWire = serde_json::from_str(&json).unwrap();
            assert_eq!(
                wire3.slot_ids, keys,
                "the JSON round trip must preserve the exact slot_ids sequence"
            );
        }
    }

    // ---- deterministic unit tests -----------------------------------------

    /// THE FOUR-SET EQUALITY, SUFFICIENCY DIRECTION (deterministic): a
    /// tamper that happens to KEEP the four sets identical — e.g. adding
    /// the SAME key to all four (outcomes, rollback slots, rollback
    /// bindings, intent membership) — is NOT a disagreement: the read
    /// succeeds. (The necessity direction — any single-set divergence fails
    /// — is the property's verdict; this pins the sufficiency case the
    /// bounded property may not draw.)
    #[test]
    fn successful_four_set_equality_suffices_when_a_tamper_keeps_the_sets_equal() {
        let keys = vec![slot(1), slot(2)];
        let intent = agreeing_intent(&keys);
        let terminal = agreeing_terminal(&keys, 0);
        // The untampered pair reads.
        write_pair_ledger(&(intent.clone(), terminal.clone()))
            .expect("the exact-equal Successful pair reads");
        // Add the SAME key (slot-9) to all four sets: the sets stay
        // identical, so the read still succeeds.
        let mut intent = intent;
        intent.slot_ids.push(slot(9));
        intent.desired.insert(slot(9), gen_ref_for(&slot(9)));
        intent.pre_push.insert(slot(9), None);
        let mut terminal = terminal;
        terminal
            .outcomes
            .insert(slot(9), outcome_for(&slot(9), SlotOutcomeKind::Activated));
        let rb = terminal.rollback.as_mut().unwrap();
        rb.slots.insert(slot(9), gen_ref_for(&slot(9)));
        rb.bindings.insert(slot(9), binding(&slot(9)));
        let entries = write_pair_ledger(&(intent, terminal)).expect(
            "adding the same key to all four sets keeps them identical — the read succeeds",
        );
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].intent.slots.len(),
            3,
            "the intent's membership grew with the added key"
        );
    }

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

        // FailedRolledBack → the outcome table is the compensation report
        // (derived, never stored twice).
        let wire = agreeing_terminal(&keys, 2);
        let d = wire.into_domain().unwrap();
        assert_eq!(d.disposition, TerminalDisposition::FailedRolledBack);
        assert_eq!(
            d.compensation().expect("derived compensation report").len(),
            2,
            "the compensation report is the outcome table"
        );

        // Degraded → the non-restored outcomes ARE the remaining changes
        // (derived, never stored twice).
        let wire = agreeing_terminal(&keys, 3);
        let d = wire.into_domain().unwrap();
        assert_eq!(d.disposition, TerminalDisposition::Degraded);
        assert_eq!(
            d.remaining_changes()
                .expect("derived remaining changes")
                .len(),
            2
        );

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
            .insert(slot(1), outcome_for(&slot(1), SlotOutcomeKind::Activated));
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
            r.outcome = SlotOutcomeKind::Restored;
        }
        assert!(
            bad.into_domain().is_err(),
            "Degraded with every slot restored is refused"
        );
        // A Successful wire whose outcomes disagree with the rollback's
        // slots (an outcome key the rollback does not cover).
        let mut bad = agreeing_terminal(&keys, 0); // Successful
        bad.outcomes
            .insert(slot(9), outcome_for(&slot(9), SlotOutcomeKind::Activated));
        assert!(
            bad.into_domain().is_err(),
            "a Successful outcome outside the rollback's slots is refused"
        );
        // A Successful wire whose outcome status disagrees with the
        // disposition's implied state (every slot activated).
        let mut bad = agreeing_terminal(&keys, 0); // Successful
        bad.outcomes.get_mut(&slot(1)).unwrap().outcome = SlotOutcomeKind::Failed;
        assert!(
            bad.into_domain().is_err(),
            "a Successful terminal with a failed outcome is refused"
        );
        // InProgress / PendingCommit never appear on a terminal event.
        let mut bad = agreeing_terminal(&keys, 0);
        bad.status = DeploymentStatus::PendingCommit;
        assert!(
            bad.into_domain().is_err(),
            "a PendingCommit terminal is refused"
        );
    }

    /// THE STATUS-SPECIFIC OUTCOME RULES (the directive's fix, enforced BY
    /// STATUS): a `Successful` terminal's outcomes keys, rollback slots
    /// keys, and rollback bindings keys must be EXACTLY EQUAL and NON-EMPTY
    /// (a missing/extra key in ANY of the three terminal-local sets fails
    /// the conversion; the fourth set — the intent's membership — fails the
    /// pair/ledger read), a `FailedPreflight` terminal must carry NO
    /// outcomes, and every other terminal state's outcomes must EXACTLY
    /// COVER the intent's membership (no missing, no extra).
    #[test]
    fn status_specific_outcome_rules_fail_closed() {
        let keys = vec![slot(1), slot(2)];

        // THE EXACT-EQUAL SUCCESSFUL → Ok (the four sets are identical and
        // non-empty: outcomes == rollback slots == rollback bindings == the
        // intent's membership).
        let intent = agreeing_intent(&keys);
        let terminal = agreeing_terminal(&keys, 0);
        let (d_intent, d_terminal) = pair_to_domain(&(intent.clone(), terminal.clone()))
            .expect("the exact-equal Successful pair converts");
        assert_eq!(d_terminal.status(), DeploymentStatus::Successful);
        assert_eq!(
            d_terminal.outcomes.len(),
            d_intent.slots.len(),
            "the outcomes exactly cover the membership"
        );
        let TerminalDisposition::Successful { rollback } = &d_terminal.disposition else {
            panic!("Successful disposition");
        };
        assert_eq!(rollback.slots.len(), d_intent.slots.len());
        assert_eq!(rollback.bindings.len(), d_intent.slots.len());

        // SUCCESSFUL with a MISSING outcome key → Err (the outcomes no
        // longer equal the rollback's slots / the membership).
        let mut bad = terminal.clone();
        bad.outcomes.remove(&slot(1));
        assert!(
            bad.clone().into_domain().is_err(),
            "Successful with a missing outcome key fails the conversion (the three terminal-local sets diverge)"
        );
        assert!(
            pair_to_domain(&(intent.clone(), bad)).is_err(),
            "Successful with a missing outcome key fails the pair read"
        );

        // SUCCESSFUL with an EXTRA outcome key → Err (an outcome for a slot
        // the rollback does not cover).
        let mut bad = terminal.clone();
        bad.outcomes
            .insert(slot(9), outcome_for(&slot(9), SlotOutcomeKind::Activated));
        assert!(
            bad.into_domain().is_err(),
            "Successful with an extra outcome key fails the conversion"
        );

        // SUCCESSFUL with a MISSING rollback slot (and binding) → Err (the
        // rollback no longer equals the outcomes).
        let mut bad = terminal.clone();
        let rb = bad.rollback.as_mut().unwrap();
        rb.slots.remove(&slot(1));
        rb.bindings.remove(&slot(1));
        assert!(
            bad.into_domain().is_err(),
            "Successful with a missing rollback slot fails the conversion"
        );

        // SUCCESSFUL with an EXTRA rollback slot (and binding) → Err (the
        // rollback covers a slot the outcomes do not).
        let mut bad = terminal.clone();
        let rb = bad.rollback.as_mut().unwrap();
        rb.slots.insert(slot(9), gen_ref_for(&slot(9)));
        rb.bindings.insert(slot(9), binding(&slot(9)));
        assert!(
            bad.into_domain().is_err(),
            "Successful with an extra rollback slot fails the conversion"
        );

        // SUCCESSFUL with EMPTY outcomes → Err (the four sets must be
        // NON-EMPTY — a successful deployment records a complete rollback
        // over exactly the slots it reports outcomes for).
        let mut bad = terminal.clone();
        bad.outcomes = BTreeMap::new();
        assert!(
            bad.into_domain().is_err(),
            "Successful with empty outcomes fails the conversion"
        );

        // FAILEDPREFLIGHT with an outcome → Err (a pre-mutation failure
        // touched no slot).
        let mut bad = agreeing_terminal(&keys, 1);
        bad.outcomes
            .insert(slot(1), outcome_for(&slot(1), SlotOutcomeKind::Activated));
        assert!(
            bad.clone().into_domain().is_err(),
            "FailedPreflight with an outcome fails the conversion"
        );
        assert!(
            pair_to_domain(&(intent.clone(), bad)).is_err(),
            "FailedPreflight with an outcome fails the pair read"
        );

        // DEGRADED with a MISSING outcome → Err (the outcomes must EXACTLY
        // cover the membership).
        let mut bad = agreeing_terminal(&keys, 3);
        bad.outcomes.remove(&slot(1));
        assert!(
            pair_to_domain(&(intent.clone(), bad)).is_err(),
            "Degraded with a missing outcome fails the pair read (the outcomes must exactly cover the membership)"
        );

        // DEGRADED with an EXTRA outcome → Err.
        let mut bad = agreeing_terminal(&keys, 3);
        bad.outcomes
            .insert(slot(9), outcome_for(&slot(9), SlotOutcomeKind::Skipped));
        assert!(
            pair_to_domain(&(intent.clone(), bad)).is_err(),
            "Degraded with an extra outcome fails the pair read"
        );

        // FAILEDROLLEDBACK with a MISSING outcome → Err (the compensation
        // report must exactly cover the membership).
        let mut bad = agreeing_terminal(&keys, 2);
        bad.outcomes.remove(&slot(1));
        assert!(
            pair_to_domain(&(intent, bad)).is_err(),
            "FailedRolledBack with a missing outcome fails the pair read"
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
            .insert(slot(9), outcome_for(&slot(9), SlotOutcomeKind::Activated));
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

    /// The ordered tables PRESERVE INSERTION ORDER across build / get /
    /// iter / keys: a table built from a deliberately NON-sorted sequence
    /// iterates in exactly that sequence (never sorted by slot id), and
    /// `get` / `contains_key` / `len` / indexing still work.
    /// `SlotTable::insert` appends new keys and keeps an overwritten key's
    /// position.
    #[test]
    fn slot_tables_preserve_insertion_order_across_build_get_iter_keys() {
        // Deliberately NOT sorted by id: the deployment order.
        let order = vec![slot(3), slot(1), slot(5), slot(0)];
        let table = NonEmptySlotTable::build(
            order
                .iter()
                .cloned()
                .enumerate()
                .map(|(i, k)| (k, i as u32)),
        )
        .unwrap();
        assert_eq!(
            table.keys().cloned().collect::<Vec<_>>(),
            order,
            "keys() iterates in insertion order, not sorted by id"
        );
        assert_eq!(
            table.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
            order,
            "iter() iterates in insertion order"
        );
        assert_eq!(
            table.values().cloned().collect::<Vec<_>>(),
            vec![0, 1, 2, 3],
            "values() iterates in insertion order"
        );
        assert_eq!(table.len(), 4);
        assert_eq!(table.get(&slot(1)), Some(&1));
        assert!(table.contains_key(&slot(5)));
        assert!(!table.contains_key(&slot(2)));
        assert_eq!(table[&slot(0)], 3, "indexing works");

        // The possibly-empty variant preserves the same order.
        let mut empty = SlotTable::new();
        assert!(empty.is_empty());
        empty.insert(slot(2), 2u32);
        empty.insert(slot(0), 0u32);
        assert_eq!(
            empty.keys().cloned().collect::<Vec<_>>(),
            vec![slot(2), slot(0)],
            "SlotTable::insert appends in insertion order"
        );
        // Overwriting an existing key keeps its position.
        empty.insert(slot(2), 9u32);
        assert_eq!(
            empty.keys().cloned().collect::<Vec<_>>(),
            vec![slot(2), slot(0)],
            "an overwritten key keeps its original position"
        );
        assert_eq!(empty[&slot(2)], 9, "the overwritten value is visible");
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
            outcome: SlotOutcomeKind::Activated,
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
        let pre_push: BTreeMap<SlotId, Option<SlotAttemptState>> =
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
                let ok = RolloutGroupName::parse(&v).is_ok();
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

    // ---------------------------------------------------------------------
    // PLAN WIRE → DOMAIN: THE SOURCE OWNS ITS REQUIRED PAYLOAD
    // ---------------------------------------------------------------------
    //
    // The wire plan (the on-disk shape with the `source` + separate
    // `rebinding` fields) converts to the domain by RECOMPUTING the proof:
    // a Release origin must carry its [`VerifiedReleaseRebinding`] INSIDE
    // the source (a Release origin without the proof is unrepresentable),
    // HEAD/deployment origins must carry NONE, and the claimed rebinding
    // must agree with the plan's own source/target/membership — the claimed
    // release equals the plan's source release AND the release its slots
    // reference, the claimed target equals the plan's target, the frozen
    // topology keys equal the membership's agreed slots, the selected plan
    // slots are covered by the membership, and the current physical slots
    // cover exactly the selected plan slots. A disagreement →
    // `Error::integrity` (fail closed).

    /// A per-slot plan for the given key, referencing the given release.
    fn plan_for(key: &SlotId, release: &ReleaseId) -> SlotPlan {
        SlotPlan {
            slot_id: key.clone(),
            artifact: ArtifactRef {
                release: release.clone(),
                variant: VariantName::new("standard".to_string()),
                tree: TreeDigest::new(format!("tree-{}", key.as_str())),
            },
            expected_generation: None,
            expected_tree: None,
        }
    }

    /// The membership PROOF for the given keys (frozen == current verified
    /// through the ONLY construction path, [`MatchingMembership::verify`]).
    fn membership_for(keys: &[SlotId]) -> MatchingMembership {
        MatchingMembership::verify(
            SlotSet::new(keys.iter().cloned()),
            SlotSet::new(keys.iter().cloned()),
        )
        .expect("a non-empty agreeing membership verifies")
    }

    /// The frozen slot→variant/group topology for the given keys (each slot
    /// in the `standard` variant, no groups).
    fn frozen_topology_for(keys: &[SlotId]) -> BTreeMap<SlotId, FrozenSlotTopology> {
        keys.iter()
            .map(|k| {
                (
                    k.clone(),
                    FrozenSlotTopology {
                        variant: "standard".to_string(),
                        groups: Vec::new(),
                    },
                )
            })
            .collect()
    }

    /// The current physical slots for the given keys.
    fn physical_slots_for(keys: &[SlotId]) -> BTreeMap<SlotId, PhysicalBinding> {
        keys.iter().map(|k| (k.clone(), binding(k))).collect()
    }

    /// A CLAIMED rebinding AGREEING with the plan's own data: the release,
    /// the target, the frozen topology (keys == the membership's agreed
    /// slots), the membership proof, and the current physical slots (keys
    /// == the selected slots).
    fn agreeing_rebinding(
        release: &ReleaseId,
        target: &TargetName,
        keys: &[SlotId],
    ) -> RebindingPlan {
        RebindingPlan {
            release: release.clone(),
            target: target.clone(),
            frozen_topology: frozen_topology_for(keys),
            membership: membership_for(keys),
            current_physical_slots: physical_slots_for(keys),
        }
    }

    /// A VALID plan wire for the given source kind (0 Head, 1 Deployment,
    /// 2 Release): a NON-EMPTY membership K, every duplicate projection
    /// agreeing, and — for a Release source — a claimed rebinding agreeing
    /// with the plan's own source/target/membership.
    fn agreeing_plan_wire(source_kind: u32, keys: &[SlotId]) -> DeploymentPlanWire {
        let release = ReleaseId::new("rel-plan".to_string());
        let target = TargetName::new("t1".to_string());
        let slots: BTreeMap<SlotId, SlotPlan> = keys
            .iter()
            .map(|k| (k.clone(), plan_for(k, &release)))
            .collect();
        let behaviors = BehaviorIndex::new();
        let source = match source_kind {
            0 => PlanSource::Head,
            1 => PlanSource::DeploymentRef(DeploymentId::new("deploy-plan".to_string())),
            _ => PlanSource::ReleaseRef(release.clone()),
        };
        let rebinding = match source_kind {
            2 => Some(agreeing_rebinding(&release, &target, keys)),
            _ => None,
        };
        DeploymentPlanWire {
            deployment_id: DeploymentId::new("deploy-plan".to_string()),
            target,
            behavior_sha256: crate::release::behavior_index_digest(&behaviors),
            behaviors,
            slot_ids: keys.to_vec(),
            slots,
            source,
            rebinding,
            desired_releases: BTreeSet::from([release]),
        }
    }

    // ---- plan wire mutations (ONE field at a time) -----------------------

    /// source: ReleaseRef → Head (the claimed rebinding stays — a HEAD plan
    /// carrying a rebinding is a disagreement).
    fn source_to_head(w: &mut DeploymentPlanWire) {
        w.source = PlanSource::Head;
    }

    /// source: ReleaseRef → DeploymentRef (the claimed rebinding stays).
    fn source_to_deployment(w: &mut DeploymentPlanWire) {
        w.source = PlanSource::DeploymentRef(DeploymentId::new("deploy-other".to_string()));
    }

    /// source: Head/Deployment → ReleaseRef (no rebinding — a Release
    /// origin without its proof is unrepresentable).
    fn source_to_release(w: &mut DeploymentPlanWire) {
        w.source = PlanSource::ReleaseRef(ReleaseId::new("rel-plan".to_string()));
    }

    /// rebinding presence: remove the claimed rebinding from a Release
    /// plan.
    fn rebinding_removed(w: &mut DeploymentPlanWire) {
        w.rebinding = None;
    }

    /// rebinding presence: add a claimed rebinding (internally agreeing
    /// with the plan's own data) to a Head/Deployment plan.
    fn rebinding_added(w: &mut DeploymentPlanWire) {
        let release = ReleaseId::new("rel-plan".to_string());
        let target = TargetName::new("t1".to_string());
        let keys: Vec<SlotId> = w.slots.keys().cloned().collect();
        w.rebinding = Some(agreeing_rebinding(&release, &target, &keys));
    }

    /// release: change the claimed rebinding's release (disagrees with the
    /// plan's source release AND the releases derived from the slots).
    fn rebinding_release_changed(w: &mut DeploymentPlanWire) {
        let rp = w
            .rebinding
            .as_mut()
            .expect("a release plan carries a rebinding");
        rp.release = ReleaseId::new("rel-other".to_string());
    }

    /// release: change the SOURCE's release (disagrees with the claimed
    /// rebinding's release).
    fn source_release_changed(w: &mut DeploymentPlanWire) {
        w.source = PlanSource::ReleaseRef(ReleaseId::new("rel-other".to_string()));
    }

    /// target: change the claimed rebinding's target (disagrees with the
    /// plan's target).
    fn rebinding_target_changed(w: &mut DeploymentPlanWire) {
        let rp = w
            .rebinding
            .as_mut()
            .expect("a release plan carries a rebinding");
        rp.target = TargetName::new("t2".to_string());
    }

    /// membership: change the claimed membership's agreed set (remove a
    /// slot when there is more than one, else add one) — the frozen
    /// topology keys no longer equal the membership, and the selected slots
    /// are no longer covered.
    fn membership_changed(w: &mut DeploymentPlanWire) {
        let rp = w
            .rebinding
            .as_mut()
            .expect("a release plan carries a rebinding");
        let mut slots: BTreeSet<SlotId> = rp.membership.slots().iter().cloned().collect();
        if slots.len() > 1 {
            let removed = slots.iter().next().cloned().expect("non-empty membership");
            slots.remove(&removed);
        } else {
            slots.insert(slot(99));
        }
        rp.membership = MatchingMembership::verify(
            SlotSet::new(slots.iter().cloned()),
            SlotSet::new(slots.iter().cloned()),
        )
        .expect("a changed non-empty membership verifies");
    }

    /// frozen topology: remove a key (the frozen topology keys no longer
    /// equal the membership's agreed slots).
    fn frozen_topology_shrunk(w: &mut DeploymentPlanWire) {
        let rp = w
            .rebinding
            .as_mut()
            .expect("a release plan carries a rebinding");
        let removed = rp
            .frozen_topology
            .keys()
            .next()
            .cloned()
            .expect("non-empty frozen topology");
        rp.frozen_topology.remove(&removed);
    }

    /// physical-slot keys: remove a key (the current physical slots no
    /// longer cover exactly the selected plan slots).
    fn physical_slots_shrunk(w: &mut DeploymentPlanWire) {
        let rp = w
            .rebinding
            .as_mut()
            .expect("a release plan carries a rebinding");
        let removed = rp
            .current_physical_slots
            .keys()
            .next()
            .cloned()
            .expect("non-empty physical slots");
        rp.current_physical_slots.remove(&removed);
    }

    /// One plan-wire mutation: a named single-field tamper applied to a
    /// [`DeploymentPlanWire`].
    type PlanWireMutation = fn(&mut DeploymentPlanWire);

    proptest! {
        // PROPERTY (the user's requirement): generate VALID plans (all
        // three source kinds), then MUTATE ONE FIELD AT A TIME — source
        // (Head↔Deployment↔Release), rebinding presence (add/remove),
        // release, target, membership, frozen topology, physical-slot keys
        // — and assert the CONVERSION SUCCEEDS ONLY FOR THE COMPLETE TRUTH
        // TABLE: the untampered plan converts, and EVERY single-field
        // mutation that breaks the proof fails the verifying conversion
        // with an integrity error. A Release origin without its proof, a
        // non-Release origin carrying one, a claimed release/target
        // disagreeing with the plan's own, a membership/frozen-topology/
        // physical-slot disagreement — all fail closed. Bounded 16 cases,
        // fixed seed 0x5EED_5EED (house style), no persistence.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn plan_wire_rebinding_truth_table(
            source_kind in 0u32..3,
            keys in prop::collection::btree_set(slot_strategy(), 2..4),
        ) {
            let keys: Vec<SlotId> = keys.into_iter().collect();
            let wire = agreeing_plan_wire(source_kind, &keys);
            // The untampered plan converts (the truth table's Ok row).
            let domain = wire
                .clone()
                .into_domain()
                .expect("the agreeing plan converts");
            // The domain's source OWNS its payload: a Release origin
            // carries the verified proof inside the source; HEAD/deployment
            // carry none.
            match &domain.source {
                PlanOrigin::Release { release, rebinding } => {
                    assert_eq!(release.as_str(), "rel-plan");
                    assert_eq!(
                        rebinding.selected_plan_slots,
                        keys.iter().cloned().collect::<BTreeSet<_>>(),
                        "the proof carries the selected plan slots"
                    );
                    assert_eq!(
                        rebinding
                            .membership
                            .slots()
                            .iter()
                            .cloned()
                            .collect::<BTreeSet<_>>(),
                        keys.iter().cloned().collect::<BTreeSet<_>>(),
                        "the proof carries the agreed membership"
                    );
                }
                PlanOrigin::Head | PlanOrigin::Deployment(_) => {}
            }

            // The proof-breaking mutations for this plan kind: each
            // single-field mutation that breaks the proof must fail the
            // conversion (the truth table's Err rows).
            let mutations: Vec<(&str, PlanWireMutation)> = match source_kind {
                // A Release plan: every claimed-rebinding field is a fact.
                2 => vec![
                    ("source → Head (rebinding present)", source_to_head as fn(&mut DeploymentPlanWire)),
                    ("source → Deployment (rebinding present)", source_to_deployment),
                    ("rebinding removed (Release origin without its proof)", rebinding_removed),
                    ("claimed rebinding release changed", rebinding_release_changed),
                    ("source release changed", source_release_changed),
                    ("claimed rebinding target changed", rebinding_target_changed),
                    ("membership changed", membership_changed),
                    ("frozen topology key removed", frozen_topology_shrunk),
                    ("physical-slot key removed", physical_slots_shrunk),
                ],
                // HEAD / Deployment plans: no rebinding is allowed; a
                // Release source without its proof is refused.
                _ => vec![
                    ("source → Release (no rebinding)", source_to_release),
                    ("rebinding added to a non-Release plan", rebinding_added),
                ],
            };
            for (name, mutate) in mutations {
                let mut bad = wire.clone();
                mutate(&mut bad);
                let err = bad.into_domain();
                assert!(
                    err.is_err(),
                    "{name} must fail the verifying conversion"
                );
                assert!(
                    matches!(err, Err(Error::Integrity(_))),
                    "{name} must fail with an integrity error, got: {err:?}"
                );
            }
        }
    }

    // ---- deterministic unit tests per mutation class ---------------------

    /// A Release-origin plan WITHOUT its claimed rebinding is refused: the
    /// proof is unrepresentable without it (a Release origin must carry its
    /// [`VerifiedReleaseRebinding`] inside the source).
    #[test]
    fn plan_wire_release_origin_without_proof_refused() {
        let keys = vec![slot(1), slot(2)];
        let mut wire = agreeing_plan_wire(2, &keys);
        wire.rebinding = None;
        let err = wire
            .into_domain()
            .expect_err("a Release origin without its proof must refuse");
        assert!(
            matches!(err, Error::Integrity(_))
                && err.to_string().contains("must carry its rebinding proof"),
            "the refusal must be the missing-proof integrity error, got: {err}"
        );
    }

    /// A non-Release origin (HEAD / deployment) CARRYING a claimed
    /// rebinding is refused: the domain has no place for it, so it is
    /// refused rather than silently dropped.
    #[test]
    fn plan_wire_non_release_origin_with_rebinding_refused() {
        for source_kind in [0u32, 1] {
            let keys = vec![slot(1), slot(2)];
            let mut wire = agreeing_plan_wire(source_kind, &keys);
            rebinding_added(&mut wire);
            let err = wire
                .into_domain()
                .expect_err("a non-Release plan carrying a rebinding must refuse");
            assert!(
                matches!(err, Error::Integrity(_))
                    && err.to_string().contains("cannot carry a rebinding proof"),
                "the refusal must be the non-Release-with-rebinding integrity error, got: {err}"
            );
        }
    }

    /// The claimed rebinding's release must equal the plan's source release
    /// AND the release the plan's slots reference: changing either half is a
    /// disagreement.
    #[test]
    fn plan_wire_claimed_release_disagreement_refused() {
        let keys = vec![slot(1), slot(2)];
        // The claimed rebinding's release disagrees with the plan's source.
        let mut wire = agreeing_plan_wire(2, &keys);
        rebinding_release_changed(&mut wire);
        let err = wire
            .into_domain()
            .expect_err("a claimed release disagreeing with the plan's source must refuse");
        assert!(
            matches!(err, Error::Integrity(_))
                && err.to_string().contains("claimed rebinding release"),
            "the refusal must name the claimed release disagreement, got: {err}"
        );
        // The source's release disagrees with the claimed rebinding's.
        let mut wire = agreeing_plan_wire(2, &keys);
        source_release_changed(&mut wire);
        let err = wire
            .into_domain()
            .expect_err("a source release disagreeing with the claimed rebinding must refuse");
        assert!(
            matches!(err, Error::Integrity(_))
                && err.to_string().contains("claimed rebinding release"),
            "the refusal must name the claimed release disagreement, got: {err}"
        );
    }

    /// The claimed rebinding's target must equal the plan's target.
    #[test]
    fn plan_wire_claimed_target_disagreement_refused() {
        let keys = vec![slot(1), slot(2)];
        let mut wire = agreeing_plan_wire(2, &keys);
        rebinding_target_changed(&mut wire);
        let err = wire
            .into_domain()
            .expect_err("a claimed target disagreeing with the plan's target must refuse");
        assert!(
            matches!(err, Error::Integrity(_))
                && err.to_string().contains("claimed rebinding target"),
            "the refusal must name the claimed target disagreement, got: {err}"
        );
    }

    /// The claimed membership's agreed set must equal the frozen topology's
    /// keys and cover the selected plan slots: a changed agreed set is a
    /// disagreement.
    #[test]
    fn plan_wire_membership_disagreement_refused() {
        let keys = vec![slot(1), slot(2)];
        let mut wire = agreeing_plan_wire(2, &keys);
        membership_changed(&mut wire);
        let err = wire
            .into_domain()
            .expect_err("a changed membership must refuse");
        assert!(
            matches!(err, Error::Integrity(_)) && err.to_string().contains("recomputed proof"),
            "the refusal must be the recomputed-proof integrity error, got: {err}"
        );
    }

    /// The frozen topology's keys must equal the membership's agreed slots:
    /// a removed frozen key is a disagreement.
    #[test]
    fn plan_wire_frozen_topology_disagreement_refused() {
        let keys = vec![slot(1), slot(2)];
        let mut wire = agreeing_plan_wire(2, &keys);
        frozen_topology_shrunk(&mut wire);
        let err = wire
            .into_domain()
            .expect_err("a shrunk frozen topology must refuse");
        assert!(
            matches!(err, Error::Integrity(_)) && err.to_string().contains("recomputed proof"),
            "the refusal must be the recomputed-proof integrity error, got: {err}"
        );
    }

    /// The current physical slots must cover exactly the selected plan
    /// slots: a removed physical-slot key is a disagreement.
    #[test]
    fn plan_wire_physical_slots_disagreement_refused() {
        let keys = vec![slot(1), slot(2)];
        let mut wire = agreeing_plan_wire(2, &keys);
        physical_slots_shrunk(&mut wire);
        let err = wire
            .into_domain()
            .expect_err("a shrunk physical-slot set must refuse");
        assert!(
            matches!(err, Error::Integrity(_)) && err.to_string().contains("recomputed proof"),
            "the refusal must be the recomputed-proof integrity error, got: {err}"
        );
    }

    /// A Release-origin plan ROUND-TRIPS through the wire (JSON) with its
    /// proof intact: the domain serializes through the wire shape (the
    /// claimed [`RebindingPlan`]), and the next read RECOMPUTES the proof
    /// from the plan's own data — the selected plan slots are re-derived
    /// from the plan's membership, and every component agrees again.
    #[test]
    fn plan_wire_release_origin_round_trips_with_its_proof() {
        let keys = vec![slot(1), slot(2)];
        let wire = agreeing_plan_wire(2, &keys);
        let domain = wire.into_domain().expect("the agreeing plan converts");
        let json = serde_json::to_string(&domain).expect("the domain serializes through the wire");
        let back: DeploymentPlan =
            serde_json::from_str(&json).expect("the wire deserializes back into the domain");
        match &back.source {
            PlanOrigin::Release { release, rebinding } => {
                assert_eq!(release.as_str(), "rel-plan");
                assert_eq!(
                    rebinding.selected_plan_slots,
                    BTreeSet::from([slot(1), slot(2)]),
                    "the round trip re-derives the selected plan slots from the plan's membership"
                );
                assert_eq!(rebinding.frozen_topology.len(), 2);
                assert_eq!(rebinding.current_physical_slots.len(), 2);
                assert_eq!(
                    rebinding
                        .membership
                        .slots()
                        .iter()
                        .cloned()
                        .collect::<BTreeSet<_>>(),
                    BTreeSet::from([slot(1), slot(2)]),
                    "the round trip keeps the agreed membership"
                );
            }
            other => {
                panic!("a Release-origin plan must round-trip as a Release origin, got {other:?}")
            }
        }
    }
}
