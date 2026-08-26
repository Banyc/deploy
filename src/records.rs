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
//! and the rollback payload), and the verified domain [`LedgerIntent`] does
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
//!   ([`LedgerIntentWire`] → verified [`LedgerIntent`]): deployment_id,
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
    ArtifactRef, BehaviorContract, DeploymentId, GenerationId, GenerationRef, PlacementSlotId,
    ReleaseId, ServerId, TargetName, TreeDigest,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};

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
/// exposes only the validated [`LedgerIntent`] domain type.
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
    /// the observed actuals for display — the verified domain [`LedgerIntent`]
    /// does NOT carry this map, so it is not part of the intent's key-set
    /// invariant. Every key must be a member of `slot_ids`.
    pub slots: BTreeMap<PlacementSlotId, SlotAttemptState>,
}

impl LedgerIntentWire {
    /// VERIFYING CONVERSION (wire → domain): every duplicate projection must
    /// AGREE. The authoritative membership is `slot_ids`, which must be
    /// DUPLICATE-FREE, and the `desired` / `pre_push` key sets must EQUAL it
    /// EXACTLY — every member slot has exactly one desired + one pre_push
    /// entry; a missing OR extra key (and a duplicated member id) fails
    /// closed, so an incomplete authoritative projection is never read as if
    /// the maps were authoritative. Each desired
    /// [`crate::model::GenerationRef`]'s assignment must name its own map key,
    /// and every wire `slots` (actuals) key must be a member of `slot_ids`
    /// (the persisted intent keeps that map EMPTY — outcomes live in the
    /// terminal event's `outcomes` map and the in-memory report
    /// [`LedgerIntentReport`]). A disagreement is an [`Error::integrity`]
    /// error (fail closed — a hand-constructed record can never be read as
    /// whichever projection a consumer happens to use).
    pub fn into_domain(self) -> Result<LedgerIntent> {
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
        Ok(LedgerIntent {
            deployment_schema_version: self.deployment_schema_version,
            deployment_id: self.deployment_id,
            target: self.target,
            group: self.group,
            slot_ids: self.slot_ids,
            behavior_sha256: self.behavior_sha256,
            attempted_at: self.attempted_at,
            desired: self.desired,
            pre_push: self.pre_push,
        })
    }
}

/// The durable INTENT of one deployment attempt, the VALIDATED domain form of
/// [`LedgerIntentWire`]: what was planned and observed BEFORE any server
/// mutation. Appended once to the target's ledger ([`LedgerLine::Intent`])
/// BEFORE the remote mutation phase (a crash after servers advanced to new
/// generations can never lose the deployment: the intent is already durable
/// and the next push reconciles it) and never edited. The attempt's STATUS,
/// per-slot OUTCOMES and (when successful) ROLLBACK STATE come from its
/// TERMINAL EVENT ([`LedgerTerminal`]), never from this record — the verified
/// intent object carries NO outcomes map at all (the wire keeps the
/// intentionally-empty `slots` member for format stability; the in-memory
/// push REPORT [`LedgerIntentReport`] carries the observed per-slot actuals),
/// so the report's outcomes map can never weaken the intent's key-set
/// invariant.
///
/// Every slot→assignment map is keyed by [`PlacementSlotId`]; `slot_ids` is
/// the deployment's membership (mirroring the commit marker `slots`
/// payload), DUPLICATE-FREE, and the `desired` / `pre_push` key sets EQUAL it
/// EXACTLY (enforced by the wire → domain conversion). The record carries
/// `deployment_schema_version`, which must be exactly
/// [`crate::model::LEDGER_SCHEMA_VERSION`]: writers emit the
/// constant and readers (e.g. [`crate::store::local::LocalStore::read_ledger`]) refuse
/// any other version with an error naming the version (fail closed — a
/// mismatched record is never silently interpreted). The current v1 shape is
/// the canonical placement-slot-keyed form (`BTreeMap<PlacementSlotId, _>`
/// maps with nested `artifact`/`assignment` refs); an older server-keyed
/// flat-artifact shape is NOT the current schema and never loads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerIntent {
    pub deployment_schema_version: u32,
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    /// The optional rollout group this attempt selected (`deploy push
    /// <target> --group <name>`). `None` means the attempt selected every
    /// slot owned by the target. The group name is DESCRIPTIVE (later
    /// releases may change group membership); the exact selected slot IDs in
    /// `slot_ids` are the authoritative historical evidence.
    pub group: Option<String>,
    /// The placement slots participating in this deployment, in deployment
    /// order (the same set the commit marker `slots` payload records). THE
    /// AUTHORITATIVE MEMBERSHIP, DUPLICATE-FREE — the `desired` / `pre_push`
    /// key sets require it EXACTLY (enforced by the wire → domain conversion).
    pub slot_ids: Vec<PlacementSlotId>,
    /// The attempt's behavior digest (see [`LedgerIntentWire`]).
    pub behavior_sha256: String,
    pub attempted_at: String,
    /// Desired per-slot assignments (what the plan intended): each slot's
    /// minted generation for its planned artifact.
    pub desired: BTreeMap<PlacementSlotId, GenerationRef>,
    /// Pre-push per-slot state before mutation (`None` if first deployment).
    pub pre_push: BTreeMap<PlacementSlotId, Option<SlotAttemptState>>,
}

impl LedgerIntent {
    /// The deployment's membership: the AUTHORITATIVE selected placement
    /// slots (in deployment order).
    pub fn membership(&self) -> &[PlacementSlotId] {
        &self.slot_ids
    }

    /// The distinct releases referenced by the intent's per-slot desired
    /// assignments — DERIVED from the authoritative `desired` map, never
    /// stored separately (a partial snapshot can span several releases).
    pub fn releases(&self) -> BTreeSet<ReleaseId> {
        self.desired
            .values()
            .map(|g| g.assignment.artifact.release.clone())
            .collect()
    }
}

impl From<&LedgerIntent> for LedgerIntentWire {
    fn from(i: &LedgerIntent) -> Self {
        LedgerIntentWire {
            deployment_schema_version: i.deployment_schema_version,
            deployment_id: i.deployment_id.clone(),
            target: i.target.clone(),
            group: i.group.clone(),
            slot_ids: i.slot_ids.clone(),
            behavior_sha256: i.behavior_sha256.clone(),
            attempted_at: i.attempted_at.clone(),
            desired: i.desired.clone(),
            pre_push: i.pre_push.clone(),
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
/// type — rather than reusing [`LedgerIntent`] — means the verified intent
/// object never carries an outcomes map, so the intent's key-set invariant
/// (`slot_ids == desired == pre_push`) is not weakened by a report map that
/// is not part of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerIntentReport {
    pub deployment_schema_version: u32,
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    pub group: Option<String>,
    pub slot_ids: Vec<PlacementSlotId>,
    pub behavior_sha256: String,
    pub attempted_at: String,
    pub desired: BTreeMap<PlacementSlotId, GenerationRef>,
    pub pre_push: BTreeMap<PlacementSlotId, Option<SlotAttemptState>>,
    /// Actual per-slot result after the attempt, for display. The report is
    /// in-memory only — the persisted intent never carries this map.
    pub slots: BTreeMap<PlacementSlotId, SlotAttemptState>,
}

impl From<&LedgerIntent> for LedgerIntentReport {
    fn from(i: &LedgerIntent) -> Self {
        LedgerIntentReport {
            deployment_schema_version: i.deployment_schema_version,
            deployment_id: i.deployment_id.clone(),
            target: i.target.clone(),
            group: i.group.clone(),
            slot_ids: i.slot_ids.clone(),
            behavior_sha256: i.behavior_sha256.clone(),
            attempted_at: i.attempted_at.clone(),
            desired: i.desired.clone(),
            pre_push: i.pre_push.clone(),
            slots: BTreeMap::new(),
        }
    }
}

impl Serialize for LedgerIntent {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        LedgerIntentWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LedgerIntent {
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
/// deployment ran. Exact rollback maps a terminal's generations to slots by
/// SLOT, so without this map a slot that rebinds to a different server — or
/// moves to a different `deploy_dir` on the same server — in `deploy.toml`
/// would silently roll back onto the wrong host/location. A MISSING entry
/// makes the binding unverifiable: rollback refuses rather than guessing the
/// host. Kept as a separate `#[serde(default)]` field so the `slots` map and
/// its [`GenerationRef`]s stay intact and ledger lines without a bindings
/// map still deserialize (an empty map is "unverifiable", so exact rollback
/// refuses).
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
    /// its own map key, every binding belongs to a slotted generation, and
    /// the legacy snapshot-wide `release` (when present) equals the
    /// snapshot's ONE derived release. A disagreement → `Error::integrity`.
    pub fn into_domain(self) -> Result<LedgerRollback> {
        for (key, g) in &self.slots {
            if &g.assignment.placement_slot != key {
                return Err(Error::integrity(format!(
                    "rollback: generation for slot '{key}' names placement '{}'",
                    g.assignment.placement_slot
                )));
            }
        }
        for key in self.bindings.keys() {
            if !self.slots.contains_key(key) {
                return Err(Error::integrity(format!(
                    "rollback: binding for slot '{key}' has no generation entry"
                )));
            }
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

/// The TERMINAL EVENT of one deployment: the status the attempt ended with,
/// the per-slot OUTCOMES ([`SlotResult`] map), and — when the status is
/// [`DeploymentStatus::Successful`] — the ROLLBACK STATE
/// ([`LedgerRollback`]). Appended ONCE to the target's ledger after the
/// mutation loop; the entry's current status is the status of its terminal
/// event (an entry WITHOUT a terminal is the recoverable in-progress /
/// pending-commit state). `reason` carries optional human context (e.g.
/// "push completed", "recovery finalized", "preflight failed").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerTerminal {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    pub status: DeploymentStatus,
    /// When the terminal event was recorded (RFC 3339).
    pub recorded_at: String,
    /// Actual per-slot outcomes after the mutation loop (the `results`
    /// payload). Empty for a pre-mutation failure (e.g.
    /// `FailedPreflight`): no slot was touched.
    pub outcomes: BTreeMap<PlacementSlotId, SlotResult>,
    /// The rollback state, present exactly when the deployment was
    /// SUCCESSFUL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback: Option<LedgerRollback>,
    /// Optional human context: why this terminal event happened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The WIRE shape of a terminal event: identical to the domain
/// [`LedgerTerminal`] except the rollback payload is the raw
/// [`LedgerRollbackWire`] (so legacy snapshot-wide members are visible to the
/// verifying conversion). The terminal itself has no duplicated authoritative
/// projection beyond the rollback payload it carries; the conversion maps the
/// payload wire → domain.
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
    /// VERIFYING CONVERSION (wire → domain): the terminal's own members have
    /// no redundant projection; the rollback payload is converted through
    /// [`LedgerRollbackWire::into_domain`] (which fails closed on any
    /// disagreement).
    pub fn into_domain(self) -> Result<LedgerTerminal> {
        let rollback = match self.rollback {
            Some(wire) => Some(wire.into_domain()?),
            None => None,
        };
        Ok(LedgerTerminal {
            deployment_id: self.deployment_id,
            target: self.target,
            status: self.status,
            recorded_at: self.recorded_at,
            outcomes: self.outcomes,
            rollback,
            reason: self.reason,
        })
    }
}

impl From<&LedgerTerminal> for LedgerTerminalWire {
    fn from(t: &LedgerTerminal) -> Self {
        LedgerTerminalWire {
            deployment_id: t.deployment_id.clone(),
            target: t.target.clone(),
            status: t.status.clone(),
            recorded_at: t.recorded_at.clone(),
            outcomes: t.outcomes.clone(),
            rollback: t.rollback.as_ref().map(LedgerRollbackWire::from),
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
/// ([`LedgerIntent`], [`LedgerTerminal`]) live here — never raw wire shapes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerEntry {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    pub intent: LedgerIntent,
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

/// The membership check backing a historical-release rebinding: the
/// release's FROZEN slot-id membership for the destination target versus the
/// target's CURRENT slot-id membership, verified EQUAL before planning
/// proceeds. The comparison is LOGICAL membership only — slot IDs, never
/// physical bindings (server / deploy_dir) — so two sets may be identical
/// while every physical binding differs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipCheck {
    /// The membership the release record FROZE for the destination target
    /// (the union over every frozen variant of its slots whose owning target
    /// equals the destination, deduplicated by slot id).
    pub frozen: BTreeSet<String>,
    /// The destination target's CURRENT membership from the caller's current
    /// configuration (every slot whose owning target equals the target).
    pub current: BTreeSet<String>,
}

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
    /// The logical membership check that ran before planning: `frozen ==
    /// current` (slot IDs only; physical bindings may differ). For a group
    /// push this is the COMPLETE membership — the group narrows the planned
    /// slots, never the membership check.
    pub membership: MembershipCheck,
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
    use crate::config::{ActivationConfig, ActivationScope, VerificationConfig};
    use crate::model::{PlacementSlotAssignment, VariantName};
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    // ---- fixtures ----------------------------------------------------------

    fn slot(i: u32) -> PlacementSlotId {
        PlacementSlotId::new(format!("slot-{i}"))
    }

    fn release(i: u32) -> ReleaseId {
        ReleaseId::new(format!("rel-{i}"))
    }

    fn slot_strategy() -> impl Strategy<Value = PlacementSlotId> {
        (0u32..6).prop_map(slot)
    }

    fn release_strategy() -> impl Strategy<Value = ReleaseId> {
        (0u32..4).prop_map(release)
    }

    /// A constant, well-formed behavior contract. The contract VALUES do not
    /// vary across a case — digest agreement is what the property exercises,
    /// and the digest depends on the index STRUCTURE (which releases/variants
    /// are present), not on a single contract's value.
    fn contract() -> BehaviorContract {
        BehaviorContract {
            activation: ActivationConfig {
                adapter: "none".to_string(),
                scope: ActivationScope::System,
                reconcile_managed_units: true,
                units: Vec::new(),
            },
            verification: VerificationConfig {
                adapter: "check".to_string(),
                argv: Vec::new(),
                timeout_seconds: 1,
                attempts: 1,
                interval_seconds: 1,
            },
        }
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
    // Every base wire is FULLY ARBITRARY in its scalar/set members but keeps
    // every duplicate projection IN AGREEMENT; the property then mutates ONE
    // projection at a time and asserts the conversion fails closed exactly on
    // the disagreement.

    fn agreeing_gen_refs() -> impl Strategy<Value = BTreeMap<PlacementSlotId, GenerationRef>> {
        prop::collection::btree_map(slot_strategy(), release_strategy(), 0..4).prop_map(|m| {
            m.into_iter()
                .map(|(key, release)| {
                    (
                        key.clone(),
                        GenerationRef {
                            generation: GenerationId::new(format!("gen-{}", key.as_str())),
                            assignment: PlacementSlotAssignment {
                                placement_slot: key.clone(),
                                artifact: ArtifactRef {
                                    release,
                                    variant: VariantName::new("standard".to_string()),
                                    tree: TreeDigest::new(format!("tree-{}", key.as_str())),
                                },
                            },
                        },
                    )
                })
                .collect()
        })
    }

    /// A VALID intent wire: a NON-EMPTY, duplicate-free membership K;
    /// `slot_ids` = K (deployment order), `desired` = K → agreeing
    /// generation ref, `pre_push` = K → observed pre-push state, and the
    /// wire `slots` (actuals) map EMPTY (the persisted intent carries no
    /// outcomes — they live in the terminal event's `outcomes` map and the
    /// in-memory report [`LedgerIntentReport`]). The property then mutates
    /// ONE projection at a time (DELETE / ADD / DUPLICATE) and asserts the
    /// conversion fails closed on EVERY tamper while accepting the
    /// untampered record — the exact-equality + duplicate-free cases only.
    fn agreeing_intent_wire() -> impl Strategy<Value = LedgerIntentWire> {
        prop::collection::btree_set(slot_strategy(), 1..4).prop_map(|keys| {
            let slot_ids: Vec<PlacementSlotId> = keys.iter().cloned().collect();
            let desired: BTreeMap<PlacementSlotId, GenerationRef> =
                keys.iter().map(|k| (k.clone(), gen_ref_for(k))).collect();
            let pre_push: BTreeMap<PlacementSlotId, Option<SlotAttemptState>> =
                keys.iter().map(|k| (k.clone(), None)).collect();
            LedgerIntentWire {
                deployment_schema_version: crate::model::LEDGER_SCHEMA_VERSION,
                deployment_id: DeploymentId::new("deploy-w".to_string()),
                target: TargetName::new("t1".to_string()),
                group: None,
                slot_ids,
                behavior_sha256: "sha256-w".to_string(),
                attempted_at: "2026-01-01T00:00:00Z".to_string(),
                desired,
                pre_push,
                slots: BTreeMap::new(),
            }
        })
    }

    fn agreeing_rollback_wire() -> impl Strategy<Value = LedgerRollbackWire> {
        (agreeing_gen_refs(), any::<bool>()).prop_map(|(slots, with_bindings)| {
            let bindings = if with_bindings {
                slots
                    .keys()
                    .cloned()
                    .map(|k| {
                        let b = binding(&k);
                        (k, b)
                    })
                    .collect()
            } else {
                BTreeMap::new()
            };
            LedgerRollbackWire {
                slots,
                bindings,
                behavior_sha256: None,
                release: None,
            }
        })
    }

    fn agreeing_plan_wire() -> impl Strategy<Value = DeploymentPlanWire> {
        let behaviors = prop::collection::btree_map(
            release_strategy(),
            prop::collection::btree_map(
                (0u32..3).prop_map(|i| format!("variant-{i}")),
                Just(contract()),
                0..3,
            ),
            0..3,
        );
        let slots =
            prop::collection::btree_map(slot_strategy(), any::<bool>(), 0..4).prop_map(|m| {
                let plans: BTreeMap<PlacementSlotId, SlotPlan> = m
                    .into_iter()
                    .filter_map(|(key, present)| {
                        present.then(|| {
                            (
                                key.clone(),
                                SlotPlan {
                                    slot_id: key.clone(),
                                    artifact: ArtifactRef {
                                        release: ReleaseId::new(format!("rel-{}", key.as_str())),
                                        variant: VariantName::new("standard".to_string()),
                                        tree: TreeDigest::new(format!("tree-{}", key.as_str())),
                                    },
                                    expected_generation: None,
                                    expected_tree: None,
                                },
                            )
                        })
                    })
                    .collect();
                plans
            });
        (behaviors, slots).prop_map(|(behaviors, slots)| {
            let slot_ids: Vec<PlacementSlotId> = slots.keys().cloned().collect();
            let desired_releases: BTreeSet<ReleaseId> =
                slots.values().map(|p| p.artifact.release.clone()).collect();
            DeploymentPlanWire {
                deployment_id: DeploymentId::new("deploy-w".to_string()),
                target: TargetName::new("t1".to_string()),
                behavior_sha256: crate::release::behavior_index_digest(&behaviors),
                behaviors,
                slot_ids,
                slots,
                source: PlanSource::Head,
                rebinding: None,
                desired_releases,
            }
        })
    }

    #[derive(Debug, Clone)]
    enum WireCase {
        Intent(LedgerIntentWire),
        Rollback(LedgerRollbackWire),
        Plan(DeploymentPlanWire),
    }

    fn wire_case_strategy() -> impl Strategy<Value = WireCase> {
        prop_oneof![
            agreeing_intent_wire().prop_map(WireCase::Intent),
            agreeing_rollback_wire().prop_map(WireCase::Rollback),
            agreeing_plan_wire().prop_map(WireCase::Plan),
        ]
    }

    // ---- per-record assertions ---------------------------------------------

    fn check_intent_case(w: &LedgerIntentWire) {
        let domain = w
            .clone()
            .into_domain()
            .expect("a valid intent wire converts");
        // Round trip: wire → domain → serialize → deserialize (wire) →
        // convert — the derived membership and releases never change, and the
        // serialized domain keeps the wire `slots` map EMPTY (the persisted
        // intent carries no outcomes).
        let json = serde_json::to_string(&domain).unwrap();
        let wire2: LedgerIntentWire = serde_json::from_str(&json).unwrap();
        assert!(
            wire2.slots.is_empty(),
            "the persisted intent keeps the `slots` map empty (outcomes live in the terminal event and the in-memory report)"
        );
        let domain2 = wire2.into_domain().unwrap();
        assert_eq!(domain2.membership(), domain.membership());
        assert_eq!(domain2.releases(), domain.releases());
        // EVERY tamper per projection fails closed — the conversion accepts
        // EXACTLY the unique, equal-key-set (no dups) cases:
        // (a) DELETE a member from `slot_ids` (incomplete membership)
        let mut bad = w.clone();
        bad.slot_ids.pop();
        assert!(
            bad.into_domain().is_err(),
            "a deleted slot_ids member is a conversion error"
        );
        // (b) ADD a non-member to `slot_ids` (extra membership)
        let mut bad = w.clone();
        bad.slot_ids.push(slot(9));
        assert!(
            bad.into_domain().is_err(),
            "an extra slot_ids member is a conversion error"
        );
        // (c) DUPLICATE a `slot_ids` member (a duplicate weakens the
        //     membership check)
        let mut bad = w.clone();
        bad.slot_ids.push(bad.slot_ids[0].clone());
        assert!(
            bad.into_domain().is_err(),
            "a duplicate slot_ids member is a conversion error"
        );
        // (d) DELETE a desired key (incomplete desired projection)
        let mut bad = w.clone();
        let victim = bad.desired.keys().next().unwrap().clone();
        bad.desired.remove(&victim);
        assert!(
            bad.into_domain().is_err(),
            "a missing desired key is a conversion error"
        );
        // (e) ADD a non-member desired key (extra desired projection)
        let mut bad = w.clone();
        bad.desired.insert(slot(9), gen_ref_for(&slot(9)));
        assert!(
            bad.into_domain().is_err(),
            "an extra desired key is a conversion error"
        );
        // (f) DELETE a pre_push key (incomplete pre_push projection)
        let mut bad = w.clone();
        let victim = bad.pre_push.keys().next().unwrap().clone();
        bad.pre_push.remove(&victim);
        assert!(
            bad.into_domain().is_err(),
            "a missing pre_push key is a conversion error"
        );
        // (g) ADD a non-member pre_push key (extra pre_push projection)
        let mut bad = w.clone();
        bad.pre_push.insert(slot(9), None);
        assert!(
            bad.into_domain().is_err(),
            "an extra pre_push key is a conversion error"
        );
        // (h) a wire slots (actuals) key outside the membership
        let mut bad = w.clone();
        bad.slots.insert(
            slot(9),
            SlotAttemptState {
                artifact: ArtifactRef::default(),
                generation: None,
            },
        );
        assert!(
            bad.into_domain().is_err(),
            "a slots key outside slot_ids is a conversion error"
        );
        // (i) a generation assignment naming a different placement slot
        let mut bad = w.clone();
        if let Some((_, g)) = bad.desired.iter_mut().next() {
            g.assignment.placement_slot = slot(9);
            assert!(
                bad.into_domain().is_err(),
                "a generation assignment naming a different placement is a conversion error"
            );
        }
    }

    fn check_rollback_case(w: &LedgerRollbackWire) {
        let domain = w
            .clone()
            .into_domain()
            .expect("an agreeing rollback wire converts");
        // Round-trip: the derived releases never change.
        let json = serde_json::to_string(&domain).unwrap();
        let wire2: LedgerRollbackWire = serde_json::from_str(&json).unwrap();
        assert!(
            wire2.behavior_sha256.is_none() && wire2.release.is_none(),
            "the domain serializes no legacy snapshot-wide members"
        );
        let domain2 = wire2.into_domain().unwrap();
        assert_eq!(domain2.releases(), domain.releases());
        // A disagreement PER DUPLICATE fails closed.
        // (a) a binding for a slot with no generation entry
        let mut bad = w.clone();
        bad.bindings.insert(slot(9), binding(&slot(9)));
        assert!(
            bad.into_domain().is_err(),
            "a binding without a generation is a conversion error"
        );
        // (b) a generation assignment naming a different placement slot
        let mut bad = w.clone();
        if let Some((_, g)) = bad.slots.iter_mut().next() {
            g.assignment.placement_slot = slot(9);
            assert!(
                bad.into_domain().is_err(),
                "a generation assignment naming a different placement is a conversion error"
            );
        }
        // (c) a legacy snapshot-wide release disagreeing with the derived
        // snapshot releases (rel-9 is outside the generated rel-0..3 domain)
        let mut bad = w.clone();
        bad.release = Some(release(9));
        assert!(
            bad.into_domain().is_err(),
            "a legacy release outside the derived snapshot releases is a conversion error"
        );
    }

    fn check_plan_case(w: &DeploymentPlanWire) {
        let domain = w
            .clone()
            .into_domain()
            .expect("an agreeing plan wire converts");
        // Round-trip: the derived membership, releases, and behavior digest
        // never change; the serialized domain keeps the redundant wire shape.
        let json = serde_json::to_string(&domain).unwrap();
        let wire2: DeploymentPlanWire = serde_json::from_str(&json).unwrap();
        assert_eq!(
            wire2.slot_ids,
            domain.membership().cloned().collect::<Vec<_>>()
        );
        assert_eq!(wire2.desired_releases, domain.releases());
        let domain2 = wire2.into_domain().unwrap();
        assert_eq!(
            domain2.membership().collect::<Vec<_>>(),
            domain.membership().collect::<Vec<_>>()
        );
        assert_eq!(domain2.releases(), domain.releases());
        assert_eq!(domain2.behavior_digest(), domain.behavior_digest());
        // A disagreement PER DUPLICATE fails closed.
        // (a) the slot_ids set disagrees with the per-slot plan keys
        let mut bad = w.clone();
        bad.slot_ids.push(slot(9));
        assert!(
            bad.into_domain().is_err(),
            "a slot_ids set disagreeing with the plan keys is a conversion error"
        );
        // (b) a per-slot plan naming a different slot
        let mut bad = w.clone();
        if let Some((_, plan)) = bad.slots.iter_mut().next() {
            plan.slot_id = slot(9);
            assert!(
                bad.into_domain().is_err(),
                "a plan naming a different slot is a conversion error"
            );
        }
        // (c) desired_releases disagreeing with the derived releases
        let mut bad = w.clone();
        bad.desired_releases.insert(release(9));
        assert!(
            bad.into_domain().is_err(),
            "a desired_releases set disagreeing from the derived releases is a conversion error"
        );
        // (d) the stored behavior digest disagreeing with the derived digest
        let mut bad = w.clone();
        bad.behavior_sha256 = "tampered".to_string();
        assert!(
            bad.into_domain().is_err(),
            "a stored behavior digest disagreeing from the derived digest is a conversion error"
        );
    }

    proptest! {
        // PROPERTY: VALID wire intents (duplicate-free `slot_ids`, `desired`
        // and `pre_push` key sets EXACTLY equal to `slot_ids`, empty wire
        // `slots`) convert `Ok` and ROUND-TRIP (wire → domain → serialize →
        // deserialize → convert) without changing their derived membership or
        // releases, while EVERY independent tamper per projection — DELETE /
        // ADD / DUPLICATE each key of `slot_ids` / `desired` / `pre_push` —
        // is rejected: the conversion accepts EXACTLY the unique, equal-key-
        // set cases (no dups, exact equality). Bounded 16 cases, fixed seed
        // 0x5EED_5EED (house style), no persistence.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn wire_records_convert_exactly_when_duplicate_projections_agree(
            case in wire_case_strategy()
        ) {
            match case {
                WireCase::Intent(wire) => check_intent_case(&wire),
                WireCase::Rollback(wire) => check_rollback_case(&wire),
                WireCase::Plan(wire) => check_plan_case(&wire),
            }
        }
    }

    // ---- deterministic unit tests per record --------------------------------

    /// [`LedgerIntentWire`]: an agreeing record converts and round-trips
    /// stably; a disagreement per duplicate projection (desired key, pre_push
    /// key, slots key, generation assignment slot) is a conversion error.
    #[test]
    fn intent_wire_disagreement_per_duplicate_fails_closed() {
        let wire = LedgerIntentWire {
            deployment_schema_version: crate::model::LEDGER_SCHEMA_VERSION,
            deployment_id: DeploymentId::new("deploy-u".to_string()),
            target: TargetName::new("t1".to_string()),
            group: None,
            slot_ids: vec![slot(1)],
            behavior_sha256: "sha256-u".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::from([(slot(1), gen_ref_for(&slot(1)))]),
            pre_push: BTreeMap::from([(slot(1), None)]),
            slots: BTreeMap::new(),
        };
        let domain = wire.clone().into_domain().unwrap();
        assert_eq!(domain.membership(), &[slot(1)][..]);
        assert_eq!(
            domain.releases(),
            BTreeSet::from([ReleaseId::new("rel-slot-1".to_string())])
        );
        let json = serde_json::to_string(&domain).unwrap();
        let wire2: LedgerIntentWire = serde_json::from_str(&json).unwrap();
        let domain2 = wire2.into_domain().unwrap();
        assert_eq!(
            domain2, domain,
            "an agreeing intent survives the round trip unchanged"
        );

        let mut bad = wire.clone();
        bad.desired.insert(slot(2), gen_ref_for(&slot(2)));
        assert!(
            bad.into_domain().is_err(),
            "a desired key outside slot_ids fails closed"
        );
        let mut bad = wire.clone();
        bad.pre_push.insert(slot(2), None);
        assert!(
            bad.into_domain().is_err(),
            "a pre_push key outside slot_ids fails closed"
        );
        let mut bad = wire.clone();
        bad.slots.insert(
            slot(2),
            SlotAttemptState {
                artifact: ArtifactRef::default(),
                generation: None,
            },
        );
        assert!(
            bad.into_domain().is_err(),
            "a slots key outside slot_ids fails closed"
        );
        let mut bad = wire.clone();
        bad.desired
            .get_mut(&slot(1))
            .unwrap()
            .assignment
            .placement_slot = slot(2);
        assert!(
            bad.into_domain().is_err(),
            "an assignment naming a different placement fails closed"
        );
    }

    /// [`LedgerIntentWire`] EXACT-EQUALITY invariant: the conversion accepts
    /// a wire whose `slot_ids` is duplicate-free and whose `desired` /
    /// `pre_push` key sets EQUAL `slot_ids` EXACTLY, and rejects every
    /// weakening — a duplicated slot id, a missing desired key, an extra
    /// pre_push key, a missing pre_push key, an extra desired key, or a
    /// deleted member id.
    #[test]
    fn intent_requires_exact_equal_key_sets() {
        let wire = LedgerIntentWire {
            deployment_schema_version: crate::model::LEDGER_SCHEMA_VERSION,
            deployment_id: DeploymentId::new("deploy-eq".to_string()),
            target: TargetName::new("t1".to_string()),
            group: None,
            slot_ids: vec![slot(1)],
            behavior_sha256: "sha256-eq".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::from([(slot(1), gen_ref_for(&slot(1)))]),
            pre_push: BTreeMap::from([(slot(1), None)]),
            slots: BTreeMap::new(),
        };
        assert!(
            wire.clone().into_domain().is_ok(),
            "the exact-equal key-set case converts Ok"
        );

        // A DUPLICATE slot id weakens the membership: the duplicate would
        // collapse in a set and never be checked against the maps.
        let mut bad = wire.clone();
        bad.slot_ids.push(slot(1));
        assert!(
            bad.into_domain().is_err(),
            "a duplicate slot id fails closed"
        );
        // A MISSING desired key: the member slot has no desired entry.
        let mut bad = wire.clone();
        bad.desired.remove(&slot(1));
        assert!(
            bad.into_domain().is_err(),
            "a missing desired key fails closed"
        );
        // An EXTRA pre_push key: the map carries a slot the membership omits.
        let mut bad = wire.clone();
        bad.pre_push.insert(slot(2), None);
        assert!(
            bad.into_domain().is_err(),
            "an extra pre_push key fails closed"
        );
        // A MISSING pre_push key: the member has no pre-push entry.
        let mut bad = wire.clone();
        bad.pre_push.remove(&slot(1));
        assert!(
            bad.into_domain().is_err(),
            "a missing pre_push key fails closed"
        );
        // An EXTRA desired key: the member has a desired entry for a slot the
        // membership omits.
        let mut bad = wire.clone();
        bad.desired.insert(slot(2), gen_ref_for(&slot(2)));
        assert!(
            bad.into_domain().is_err(),
            "an extra desired key fails closed"
        );
        // A DELETED member: the membership omits a key the maps carry.
        let mut bad = wire.clone();
        bad.slot_ids.pop();
        assert!(
            bad.into_domain().is_err(),
            "a deleted slot_ids member fails closed"
        );
    }

    /// INTENT vs REPORT datatype split: the verified domain [`LedgerIntent`]
    /// carries NO outcomes map (the wire keeps the intentionally-empty `slots`
    /// member for format stability), while the in-memory [`LedgerIntentReport`]
    /// carries the observed per-slot actuals — the report's map is not part of
    /// the intent's key-set invariant.
    #[test]
    fn intent_report_carries_outcomes_while_persisted_intent_slots_stay_empty() {
        let domain = LedgerIntent {
            deployment_schema_version: crate::model::LEDGER_SCHEMA_VERSION,
            deployment_id: DeploymentId::new("deploy-r".to_string()),
            target: TargetName::new("t1".to_string()),
            group: None,
            slot_ids: vec![slot(1)],
            behavior_sha256: "sha256-r".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::from([(slot(1), gen_ref_for(&slot(1)))]),
            pre_push: BTreeMap::from([(slot(1), None)]),
        };
        // The REPORT carries the observed per-slot actuals for display.
        let mut report = LedgerIntentReport::from(&domain);
        report.slots.insert(
            slot(1),
            SlotAttemptState {
                artifact: ArtifactRef::default(),
                generation: Some(GenerationId::new("gen-observed".to_string())),
            },
        );
        assert_eq!(report.slot_ids, domain.slot_ids);
        assert_eq!(report.desired, domain.desired);
        assert_eq!(
            report.slots[&slot(1)]
                .generation
                .as_ref()
                .map(|g| g.as_str()),
            Some("gen-observed"),
            "the report carries the actual per-slot outcome"
        );
        // The PERSISTED (wire) intent keeps `slots` EMPTY, and the verified
        // domain object has no outcomes map at all (the report's map never
        // weakens the intent invariant).
        let wire = LedgerIntentWire::from(&domain);
        assert!(
            wire.slots.is_empty(),
            "the persisted intent keeps the `slots` map empty"
        );
        let round = wire.into_domain().unwrap();
        assert_eq!(round, domain, "the domain round-trips unchanged");
    }

    /// [`LedgerRollback`]: an agreeing record converts and round-trips
    /// stably; a disagreement per duplicate projection (binding slot, mapping
    /// assignment slot, legacy snapshot-wide release) is a conversion error,
    /// while an AGREEING legacy release and the (non-derivable) legacy
    /// behavior digest pass.
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
        assert!(
            wire2.behavior_sha256.is_none() && wire2.release.is_none(),
            "the domain serializes no legacy snapshot-wide members"
        );
        let domain2 = wire2.into_domain().unwrap();
        assert_eq!(domain2.releases(), domain.releases());

        let mut bad = wire.clone();
        bad.bindings.insert(slot(2), binding(&slot(2)));
        assert!(
            bad.into_domain().is_err(),
            "a binding without a generation fails closed"
        );
        let mut bad = wire.clone();
        bad.slots
            .get_mut(&slot(1))
            .unwrap()
            .assignment
            .placement_slot = slot(2);
        assert!(
            bad.into_domain().is_err(),
            "an assignment naming a different placement fails closed"
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
        let mut good = wire.clone();
        good.behavior_sha256 = Some("sha256-legacy".to_string());
        let d = good.into_domain().unwrap();
        assert_eq!(
            d.releases(),
            BTreeSet::from([ReleaseId::new("rel-slot-1".to_string())]),
            "the legacy behavior digest is carried for parseability, never interpreted"
        );
    }

    /// [`DeploymentPlan`]: an agreeing record converts and round-trips
    /// stably (the serialized domain keeps the redundant wire shape); a
    /// disagreement per duplicate projection (slot_ids set, per-slot plan
    /// slot, desired_releases, stored behavior digest) fails closed.
    #[test]
    fn plan_wire_disagreement_per_duplicate_fails_closed() {
        let behaviors: BehaviorIndex = BTreeMap::from([(
            release(1),
            BTreeMap::from([("standard".to_string(), contract())]),
        )]);
        let wire = DeploymentPlanWire {
            deployment_id: DeploymentId::new("deploy-p".to_string()),
            target: TargetName::new("t1".to_string()),
            behavior_sha256: crate::release::behavior_index_digest(&behaviors),
            behaviors,
            slot_ids: vec![slot(1)],
            slots: BTreeMap::from([(
                slot(1),
                SlotPlan {
                    slot_id: slot(1),
                    artifact: ArtifactRef {
                        release: ReleaseId::new("rel-slot-1".to_string()),
                        variant: VariantName::new("standard".to_string()),
                        tree: TreeDigest::new("t1".to_string()),
                    },
                    expected_generation: None,
                    expected_tree: None,
                },
            )]),
            source: PlanSource::Head,
            rebinding: None,
            desired_releases: BTreeSet::from([ReleaseId::new("rel-slot-1".to_string())]),
        };
        let domain = wire.clone().into_domain().unwrap();
        assert_eq!(domain.membership().collect::<Vec<_>>(), vec![&slot(1)]);
        assert_eq!(
            domain.releases(),
            BTreeSet::from([ReleaseId::new("rel-slot-1".to_string())])
        );
        assert_eq!(
            domain.behavior_digest(),
            crate::release::behavior_index_digest(&domain.behaviors),
            "the derived digest must equal the canonical recomputed digest"
        );
        let json = serde_json::to_string(&domain).unwrap();
        let wire2: DeploymentPlanWire = serde_json::from_str(&json).unwrap();
        assert_eq!(
            wire2.slot_ids,
            vec![slot(1)],
            "the serialized domain keeps the wire shape"
        );
        assert_eq!(wire2.desired_releases, domain.releases());
        let domain2 = wire2.into_domain().unwrap();
        assert_eq!(
            domain2, domain,
            "an agreeing plan survives the round trip unchanged"
        );

        let mut bad = wire.clone();
        bad.slot_ids.push(slot(2));
        assert!(
            bad.into_domain().is_err(),
            "a slot_ids set disagreeing from the plan keys fails closed"
        );
        let mut bad = wire.clone();
        bad.slots.get_mut(&slot(1)).unwrap().slot_id = slot(2);
        assert!(
            bad.into_domain().is_err(),
            "a per-slot plan naming a different slot fails closed"
        );
        let mut bad = wire.clone();
        bad.desired_releases
            .insert(ReleaseId::new("rel-other".to_string()));
        assert!(
            bad.into_domain().is_err(),
            "a desired_releases set disagreeing from the derived releases fails closed"
        );
        let mut bad = wire.clone();
        bad.behavior_sha256 = "tampered".to_string();
        assert!(
            bad.into_domain().is_err(),
            "a stored behavior digest disagreeing from the derived digest fails closed"
        );
    }
}
