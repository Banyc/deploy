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
//! # ONE history ledger per target
//!
//! A target's ENTIRE deployment history lives in ONE ordered, append-only
//! JSONL file: `targets/<target>/ledger.jsonl`. There are exactly two
//! physical line kinds ([`LedgerLine`]):
//!
//! * [`LedgerLine::Intent`] — the DURABLE INTENT of one deployment
//!   ([`LedgerIntent`]): deployment_id, target, behavior digest, membership,
//!   and the `desired` / `pre_push` per-slot maps. It is appended BEFORE any
//!   remote mutation (the append-attempt contract) and never edited. It
//!   carries NO status, NO outcomes, and NO rollback state.
//! * [`LedgerLine::Terminal`] — the TERMINAL EVENT of one deployment
//!   ([`LedgerTerminal`]): the status, the per-slot OUTCOMES, and — when the
//!   deployment was SUCCESSFUL — the ROLLBACK STATE ([`LedgerRollback`], the
//!   snapshot payload: per-slot generation refs + behavior digest + physical
//!   bindings + the release the generations came from). Appended once, after
//!   the mutation loop, and never edited.
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

use crate::model::{
    ArtifactRef, BehaviorContract, DeploymentId, GenerationId, GenerationRef, PlacementSlotId,
    ReleaseId, ServerId, TargetName, TreeDigest,
};

use serde::{Deserialize, Serialize};
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

/// The durable INTENT of one deployment attempt: what was planned and
/// observed BEFORE any server mutation. Appended once to the target's ledger
/// ([`LedgerLine::Intent`]) BEFORE the remote mutation phase (a crash after
/// servers advanced to new generations can never lose the deployment: the
/// intent is already durable and the next push reconciles it) and never
/// edited. The attempt's STATUS, per-slot OUTCOMES and (when successful)
/// ROLLBACK STATE come from its TERMINAL EVENT ([`LedgerTerminal`]), never
/// from this record — the persisted `slots` map is empty.
///
/// Every slot→assignment map is keyed by [`PlacementSlotId`]; `slot_ids` is
/// the deployment's membership (mirroring the commit marker `slots`
/// payload). The record carries `deployment_schema_version`, which must be
/// exactly [`crate::model::LEDGER_SCHEMA_VERSION`]: writers emit the
/// constant and readers (e.g. [`crate::store::local::LocalStore::read_ledger`]) refuse
/// any other version with an error naming the version (fail closed — a
/// mismatched record is never silently interpreted). The current v1 shape is
/// the canonical placement-slot-keyed form (`BTreeMap<PlacementSlotId, _>`
/// maps with nested `artifact`/`assignment` refs); an older server-keyed
/// flat-artifact shape is NOT the current schema and never loads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerIntent {
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
    /// order (the same set the commit marker `slots` payload records).
    pub slot_ids: Vec<PlacementSlotId>,
    pub behavior_sha256: String,
    pub attempted_at: String,
    /// Desired per-slot assignments (what the plan intended): each slot's
    /// minted generation for its planned artifact.
    pub desired: BTreeMap<PlacementSlotId, GenerationRef>,
    /// Pre-push per-slot state before mutation (`None` if first deployment).
    pub pre_push: BTreeMap<PlacementSlotId, Option<SlotAttemptState>>,
    /// Actual per-slot result after the attempt. INTENT vs OUTCOME: the
    /// persisted ledger intent keeps this map EMPTY (outcomes are recorded
    /// in the terminal event's `outcomes` map); in memory (the push report)
    /// it carries the observed actuals for display, and recovery derives
    /// outcomes from the verified desired state instead.
    pub slots: BTreeMap<PlacementSlotId, SlotAttemptState>,
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
/// deployment: the snapshot payload of the attempt — the complete per-slot
/// [`GenerationRef`]s it advanced to (a successful terminal always has a
/// generation per slot) and the physical bindings (`{server, deploy_dir}`)
/// each slot had.
///
/// THERE IS NO SNAPSHOT-WIDE RELEASE/BEHAVIOR: each slot's [`GenerationRef`]
/// carries its OWN artifact binding (`release`, `variant`, `tree`), and a
/// PARTIAL snapshot can legitimately carry slots from DIFFERENT releases
/// (group pushes over time: group A pushed release R1, group B pushed
/// release R2, and the overlay snapshot keeps each slot's own artifact). The
/// referenced releases are DERIVED from `slots` (each slot's artifact's
/// release) — never stored once per snapshot — and rollback resolves EACH
/// SLOT's behavior from ITS OWN (release, variant) binding. Legacy ledger
/// lines that still carry the old snapshot-wide `behavior_sha256`/`release`
/// fields deserialize fine (serde ignores the unknown members) and are
/// interpreted purely through the per-slot bindings.
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
    /// derived from these bindings.
    pub slots: BTreeMap<PlacementSlotId, GenerationRef>,
    /// The complete physical binding (`{server, deploy_dir}`) each slot had
    /// at deployment time, keyed by [`PlacementSlotId`].
    #[serde(default)]
    pub bindings: BTreeMap<PlacementSlotId, PhysicalBinding>,
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

/// ONE physical line of a target's deployment ledger. The ledger is an
/// append-only JSONL stream: each deployment contributes at most one
/// [`LedgerLine::Intent`] (written BEFORE any remote mutation) and at most
/// one [`LedgerLine::Terminal`] (appended when the deployment completes).
/// The line ORDER is the history order. [`crate::store::local::LocalStore::read_ledger`]
/// merges the lines into [`LedgerEntry`]s keyed by deployment id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LedgerLine {
    /// The durable intent of one deployment, written before any remote
    /// mutation (the append-attempt contract).
    Intent(LedgerIntent),
    /// The terminal event of one deployment, appended after the mutation
    /// loop.
    Terminal(LedgerTerminal),
}

/// A merged deployment entry of the target's ledger: the durable INTENT plus
/// the optional TERMINAL EVENT (absent while the deployment is in flight or
/// recoverable-pending). The append order is the history order; `seq` is the
/// position of the intent line in the ledger.
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
    /// Assign each current slot its configured variant from a named release.
    ReleaseRef(ReleaseId),
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentPlan {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    /// The attempt's snapshot-wide behavior digest: the canonical digest of
    /// the [`BehaviorIndex`] the attempt is bound to.
    pub behavior_sha256: String,
    /// The frozen, per-release name-keyed activation + verification contracts
    /// this attempt is bound to, one per declared variant per referenced
    /// release. Historical and rollback pushes carry the historical contracts
    /// here rather than the caller's current configuration.
    pub behaviors: BehaviorIndex,
    pub slot_ids: Vec<PlacementSlotId>,
    pub slots: BTreeMap<PlacementSlotId, SlotPlan>,
    pub source: PlanSource,
    /// The releases this attempt's slots reference (per-slot artifact
    /// provenance: a partial snapshot can span several releases).
    pub desired_releases: BTreeSet<ReleaseId>,
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
