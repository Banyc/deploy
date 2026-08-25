//! Shared record structures persisted by the local store, the push engine, and
//! the snapshot history / rollback subsystem.
//!
//! Assignment relationships are expressed exclusively through the canonical
//! model types ([`crate::model::ArtifactRef`],
//! [`crate::model::PlacementSlotAssignment`], [`crate::model::GenerationRef`])
//! rather than re-declared per record. Every slot→assignment map (attempt
//! `desired` / `pre_push` / `slots`, observed state, snapshots) is
//! keyed by [`crate::model::PlacementSlotId`] — the deployment-location
//! identity — while [`crate::model::ServerId`] remains the actual-server
//! identity used for transport addressing (`ServerState`, config `ServerDef`).
//!
//! The records model separates the IMMUTABLE attempt INTENT from MUTABLE
//! status and per-slot OUTCOMES, and freezes the terminal successful snapshot
//! state for rollback:
//!
//! * [`DeploymentAttempt`] — the immutable INTENT of one deployment
//!   (deployment_id, target, behavior, membership, `desired` / `pre_push`
//!   maps). It is appended once to `attempts.jsonl`, BEFORE any server
//!   mutation, and never edited. It carries NO status and NO outcomes: the
//!   actual per-slot state lives in `deployments/<id>/results.json`
//!   ([`DeploymentResults`]), and the status lifecycle lives in the
//!   per-deployment transition stream.
//! * [`DeploymentResults`] — the actual per-slot OUTCOMES of one deployment
//!   (per-slot [`ServerResult`]), written once per deployment ID
//!   (`deployments/<id>/results.json`) after the mutation loop. This is the
//!   outcomes store: snapshots and observed state are built from it (or from
//!   the verified desired state during recovery when it is absent), never
//!   from the intent record.
//! * [`DeploymentTransition`] — an append-only status event for one
//!   deployment (deployment_id, status, recorded_at, optional reason). The
//!   per-deployment transition stream (`deployments/<id>/transitions.jsonl`)
//!   is the deployment's mutable status lifecycle: the current status of an
//!   attempt is the LATEST transition.
//! * [`DeploymentSnapshot`] — a terminal successful FLEET state used for
//!   rollback, referenced as a snapshot index `sN` on the push command
//!   (e.g. `deploy push <target> sN`). Only successful deployments produce
//!   a snapshot (`refs/snapshots.jsonl` + `refs/last-successful`). It records
//!   each slot's advanced [`GenerationRef`] keyed by the DEPLOYMENT-LOCATION
//!   identity AND the complete physical binding ([`PhysicalBinding`]
//!   `{server, deploy_dir}`) each slot was bound to (`bindings`), so exact
//!   rollback can verify a slot still lives at the exact same on-host
//!   location it was deployed onto.

use crate::model::{
    ArtifactRef, BehaviorContract, DeploymentId, GenerationId, GenerationRef, PlacementSlotId,
    ReleaseId, ServerId, TargetName, TreeDigest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentStatus {
    /// A deployment attempt is currently being executed. The initial
    /// transition of every attempt is `InProgress`.
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
    /// `ServerResult.compensated = true` — "record both the failure and the
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
pub struct AttemptServer {
    pub artifact: ArtifactRef,
    /// The generation this slot actually advanced to. `None` when the slot's
    /// server was never started (e.g. skipped after an earlier failure under
    /// `stop_on_failure`).
    pub generation: Option<GenerationId>,
}

/// The immutable INTENT of one deployment attempt: what was planned and
/// observed BEFORE any server mutation. Appended once to `attempts.jsonl`
/// BEFORE the remote mutation phase (a crash after servers advanced to new
/// generations can never lose the deployment: the intent is already durable
/// and the next push reconciles it) and never edited. The attempt's STATUS
/// derives from its per-deployment transition stream (the latest
/// [`DeploymentTransition`]), never stored here; its actual per-slot OUTCOMES
/// live in `deployments/<id>/results.json` ([`DeploymentResults`]), never in
/// this record — the persisted `slots` map is empty.
///
/// Every slot→assignment map is keyed by [`PlacementSlotId`]; `slot_ids` is
/// the deployment's membership (mirroring the commit marker `slots`
/// payload). The record carries `deployment_schema_version`, which must be
/// exactly [`crate::model::SCHEMA_VERSION`]: writers emit the constant and
/// readers (e.g. [`crate::store::local::LocalStore::read_attempts`]) refuse
/// any other version with an error naming the version (fail closed — a
/// mismatched record is never silently interpreted). The current v1 shape is
/// the canonical placement-slot-keyed form (`BTreeMap<PlacementSlotId, _>`
/// maps with nested `artifact`/`assignment` refs); an older server-keyed
/// flat-artifact shape is NOT the current schema and never loads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentAttempt {
    pub deployment_schema_version: u32,
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    /// The placement slots participating in this deployment, in deployment
    /// order (the same set the commit marker `slots` payload records).
    pub slot_ids: Vec<PlacementSlotId>,
    pub behavior_sha256: String,
    pub attempted_at: String,
    /// Desired per-slot assignments (what the plan intended): each slot's
    /// minted generation for its planned artifact.
    pub desired: BTreeMap<PlacementSlotId, GenerationRef>,
    /// Pre-push per-slot state before mutation (`None` if first deployment).
    pub pre_push: BTreeMap<PlacementSlotId, Option<AttemptServer>>,
    /// Actual per-slot result after the attempt. INTENT vs OUTCOME: the
    /// `attempts.jsonl` intent record persists this map EMPTY (outcomes are
    /// recorded separately in `deployments/<id>/results.json`); in memory
    /// (the push report) it carries the observed actuals for display, and
    /// recovery reads outcomes from results.json (or the verified desired
    /// state) instead of this field.
    pub slots: BTreeMap<PlacementSlotId, AttemptServer>,
}

/// An append-only status event for one deployment. The current status of a
/// deployment is the LATEST transition; the transition stream
/// (`deployments/<id>/transitions.jsonl`) replaces the old single mutable
/// `deployments/<id>/status` file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentTransition {
    pub deployment_id: DeploymentId,
    pub status: DeploymentStatus,
    /// When the transition was recorded (RFC 3339).
    pub recorded_at: String,
    /// Optional human context: why this transition happened (e.g.
    /// "recovery finalization", "metadata phase interrupted").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A terminal successful snapshot state used for rollback, exposed as
/// The complete PHYSICAL binding of one placement slot at snapshot time: the
/// actual server ([`ServerId`]) AND the absolute `deploy_dir` on that server
/// where the slot's deployment state (objects, releases, generations,
/// `current`) lives. Together `{server, deploy_dir}` name the exact on-host
/// deployment location a snapshot's generations were advanced on.
/// Exact rollback must verify BOTH halves: a slot that keeps its server but
/// moves its `deploy_dir` would otherwise receive the historical generations
/// at the new location, silently deploying to the wrong place on the same
/// host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalBinding {
    /// The physical server the slot was bound to at snapshot time.
    pub server: ServerId,
    /// The absolute on-server directory the slot's deployment state lives
    /// in, exactly as declared in the slot's `deploy_dir` at snapshot time.
    pub deploy_dir: String,
}

/// A terminal successful snapshot state used for rollback, referenced as a
/// snapshot index `sN` on the push command (e.g. `deploy push <target> sN`).
/// Only successful deployments produce a snapshot
/// (`refs/snapshots.jsonl` + `refs/last-successful`). Each slot's entry is
/// the complete [`GenerationRef`] it advanced to (a successful snapshot always
/// has a generation per slot).
///
/// `bindings` records the COMPLETE PHYSICAL BINDING (`{server, deploy_dir}`)
/// each slot had when the snapshot was taken (the deployment-location
/// identity lives in the `slots` key; the actual on-host location lives
/// here). Exact rollback maps a snapshot's generation to a slot BY SLOT ID,
/// so without this map a slot rebound to a different server — or moved to a
/// different `deploy_dir` on the same server — in `deploy.toml` would
/// silently roll back onto the wrong host/location. A MISSING entry means
/// the binding is unverifiable (legacy pre-feature snapshots never recorded
/// it): rollback refuses rather than guessing the host. Kept as a separate
/// `#[serde(default)]` field so the `slots` map and its [`GenerationRef`]s
/// stay intact and pre-feature snapshot log lines still deserialize (the
/// old `servers` key and older lines without any binding are ignored,
/// yielding an empty map).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentSnapshot {
    pub index: u64,
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    pub behavior_sha256: String,
    pub slots: BTreeMap<PlacementSlotId, GenerationRef>,
    /// The complete physical binding (`{server, deploy_dir}`) each slot was
    /// bound to at snapshot time, keyed by [`PlacementSlotId`].
    /// `#[serde(default)]` keeps append-only legacy entries (pre-binding)
    /// readable; a missing entry is "unverifiable" and makes exact rollback
    /// refuse the slot.
    #[serde(default)]
    pub bindings: BTreeMap<PlacementSlotId, PhysicalBinding>,
}

/// A monotonic history floor for one target: the durable marker that says
/// "retained history for this target starts at this deployment".
///
/// The floor is a SMALL MARKER, deliberately NOT another deployment or
/// snapshot: the actual rollback state stays the snapshot referenced by
/// `deployment_id` (`refs/snapshots.jsonl` — see [`DeploymentSnapshot`]).
/// Once a checkpoint is established on a target, every read path
/// (`read_attempts`, `read_snapshots`, ref resolution) exposes ONLY the
/// suffix at/after the floor, and refs refuse to resolve below it.
///
/// Persisted at `targets/<target>/refs/history-floor.json`. Written FIRST
/// (durable, atomic temp+rename) before the physical compaction that
/// rewrites the jsonl logs to the suffix and deletes `deployments/<id>/`
/// directories strictly before the floor, so an interrupted compaction
/// leaves either the old physical files or the compacted files — never
/// history below the durable floor (every read path is gated by this
/// marker). `schema_version` is exactly [`crate::model::SCHEMA_VERSION`];
/// readers refuse any other version (fail closed).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryFloor {
    pub schema_version: u32,
    pub target: TargetName,
    pub deployment_id: DeploymentId,
    /// The canonical snapshot index of the snapshot the checkpoint
    /// deployment produced (the oldest rollback state; everything below it
    /// is discarded).
    pub snapshot_index: u64,
    /// When the floor was established (RFC 3339).
    pub established_at: String,
}

/// A durable debt marker for an INTERRUPTED checkpoint cleanup: the history
/// floor (the COMMIT POINT) is durable, but the post-commit physical
/// compaction did not complete. Persisted at
/// `targets/<target>/refs/cleanup-pending.json` AFTER the floor marker is
/// written, whenever any post-marker phase of the compaction fails — the
/// checkpoint TOOK EFFECT while the command reports SUCCESS with this
/// marker set. The next `deploy checkpoint <target> <deployment-id>` (the
/// same deployment) retries the cleanup and clears the marker once it
/// completes; the marker records exactly which below-floor
/// `deployments/<id>/` directories still need deletion, so a retry can
/// finish them even after the physical logs are already compacted.
/// `schema_version` is exactly [`crate::model::SCHEMA_VERSION`]; readers
/// refuse any other version (fail closed).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupPending {
    pub schema_version: u32,
    pub target: TargetName,
    pub deployment_id: DeploymentId,
    /// The snapshot index the floor sits at — the pending cleanup is the
    /// compaction FOR THIS floor.
    pub snapshot_index: u64,
    /// When the pending cleanup was recorded (RFC 3339).
    pub established_at: String,
    /// The below-floor `deployments/<id>/` directories an interrupted
    /// compaction had not yet deleted. A retry deletes exactly these (plus
    /// anything the current physical logs still name below the floor), so
    /// an interruption that finished the log rewrites but faulted before
    /// the deletions still converges.
    pub pending_deployments: Vec<String>,
}

/// Observed remote state for one placement slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ObservedServer {
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
    pub slots: BTreeMap<PlacementSlotId, ObservedServer>,
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
    pub last_observed: Option<ObservedServer>,
}

/// Where a plan's desired assignment comes from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanSource {
    /// Materialize the currently mapped local files and assign each slot its
    /// target-configured (current) variant.
    Head,
    /// Restore a historical successful snapshot by index (`sN`).
    SnapshotRef(u64),
    /// Assign each current slot its configured variant from a named release.
    ReleaseRef(ReleaseId),
}

/// Per-slot plan for one placement slot: its slot identity, the artifact it
/// should run, and the compare-and-swap preconditions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerPlan {
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
    pub behavior_sha256: String,
    /// The frozen, name-keyed activation + verification contracts this attempt
    /// is bound to, one per declared variant. Historical and rollback pushes
    /// carry the historical contracts here rather than the caller's current
    /// configuration.
    pub behaviors: BTreeMap<String, BehaviorContract>,
    pub slot_ids: Vec<PlacementSlotId>,
    pub slots: BTreeMap<PlacementSlotId, ServerPlan>,
    pub source: PlanSource,
    pub desired_release: ReleaseId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerResult {
    pub slot_id: PlacementSlotId,
    pub outcome: ServerOutcomeKind,
    /// The generation this slot advanced to, or `None` if it never started.
    pub generation: Option<GenerationId>,
    pub compensated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Per-slot deployment OUTCOMES (`deployments/<id>/results.json`), keyed by
/// [`PlacementSlotId`]. Written once per deployment ID after the mutation
/// loop: this is the outcomes store for the attempt — the source the
/// successful snapshot and observed state are built from (the immutable
/// `attempts.jsonl` record carries only intent).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentResults {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    pub slots: BTreeMap<PlacementSlotId, ServerResult>,
}
