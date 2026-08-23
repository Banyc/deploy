//! Shared record structures persisted by the local store, the push engine, and
//! the fleet history / rollback subsystem.
//!
//! Assignment relationships are expressed exclusively through the canonical
//! model types ([`crate::model::ArtifactRef`],
//! [`crate::model::PlacementSlotAssignment`], [`crate::model::GenerationRef`])
//! rather than re-declared per record. Every slot→assignment map (attempt
//! `desired` / `pre_push` / `slots`, observed state, fleet snapshots) is
//! keyed by [`crate::model::PlacementSlotId`] — the deployment-location
//! identity — while [`crate::model::ServerId`] remains the actual-server
//! identity used for transport addressing (`ServerState`, config `ServerDef`).
//!
//! The records model separates the IMMUTABLE attempt identity from MUTABLE
//! status, and freezes the terminal successful fleet state for rollback:
//!
//! * [`DeploymentAttempt`] — the immutable intent and assignments of one
//!   deployment (deployment_id, target, behavior, membership, desired /
//!   pre_push / slots maps). It carries NO status: attempts are appended
//!   once to `attempts.jsonl` and never edited.
//! * [`DeploymentTransition`] — an append-only status event for one
//!   deployment (deployment_id, status, recorded_at, optional reason). The
//!   per-deployment transition stream (`deployments/<id>/transitions.jsonl`)
//!   is the deployment's mutable status: the current status of an attempt is
//!   the LATEST transition.
//! * [`DeploymentSnapshot`] — a terminal successful FLEET state used for
//!   rollback, exposed as `<target>@fN`. Only successful deployments produce
//!   a snapshot (`refs/snapshots.jsonl` + `refs/last-successful`).

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
    /// The fleet-commit markers are not all durable yet; a later push
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

/// The immutable intent and assignments of one deployment attempt. Appended
/// once to `attempts.jsonl` and never edited; the attempt's status is derived
/// from its per-deployment transition stream (the latest
/// [`DeploymentTransition`]), never stored here.
///
/// Every slot→assignment map is keyed by [`PlacementSlotId`]; `slot_ids` is
/// the deployment's membership (mirroring the fleet-commit marker `slots`
/// payload). Schema version 2: v1 keyed these maps by server ID and stored
/// the artifact triple as flat fields; v2 rekeys to placement slots and nests
/// the artifact under `artifact` (or `assignment` for [`GenerationRef`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentAttempt {
    pub deployment_schema_version: u32,
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    /// The placement slots participating in this deployment, in deployment
    /// order (the same set the fleet-commit marker `slots` payload records).
    pub slot_ids: Vec<PlacementSlotId>,
    pub behavior_sha256: String,
    pub attempted_at: String,
    /// Desired per-slot assignments (what the plan intended): each slot's
    /// minted generation for its planned artifact.
    pub desired: BTreeMap<PlacementSlotId, GenerationRef>,
    /// Pre-push per-slot state before mutation (`None` if first deployment).
    pub pre_push: BTreeMap<PlacementSlotId, Option<AttemptServer>>,
    /// Actual per-slot result after the attempt.
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

/// A terminal successful fleet state used for rollback, exposed as
/// `<target>@fN`. Only successful deployments produce a snapshot
/// (`refs/snapshots.jsonl` + `refs/last-successful`). Each slot's entry is
/// the complete [`GenerationRef`] it advanced to (a successful snapshot always
/// has a generation per slot).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentSnapshot {
    pub index: u64,
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    pub behavior_sha256: String,
    pub slots: BTreeMap<PlacementSlotId, GenerationRef>,
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
    /// Restore a historical successful fleet snapshot by index (`@fN`).
    FleetRef(u64),
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

/// Per-slot deployment results (`results.json`), keyed by [`PlacementSlotId`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentResults {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    pub slots: BTreeMap<PlacementSlotId, ServerResult>,
}
