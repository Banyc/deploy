//! Shared record structures persisted by the local store, the push engine, and
//! the fleet history / rollback subsystem.

use crate::model::{
    BehaviorContract, DeploymentId, GenerationId, ReleaseId, ServerId, TargetName, TreeDigest,
    VariantName,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentStatus {
    Successful,
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

/// A per-server assignment snapshot (release, variant, tree, generation).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptServer {
    pub release: ReleaseId,
    pub variant: VariantName,
    pub tree: TreeDigest,
    /// The generation this server actually advanced to. `None` when the server
    /// was never started (e.g. skipped after an earlier failure under
    /// `stop_on_failure`).
    pub generation: Option<GenerationId>,
}

/// A persisted deployment attempt (also the fleet history entry).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptRecord {
    pub deployment_schema_version: u32,
    pub deployment_id: DeploymentId,
    pub status: DeploymentStatus,
    pub target: TargetName,
    pub server_ids: Vec<ServerId>,
    pub behavior_sha256: String,
    pub attempted_at: String,
    /// Desired per-server assignment (what the plan intended).
    pub desired: BTreeMap<ServerId, AttemptServer>,
    /// Pre-push per-server generation before mutation (None if first deploy).
    pub pre_push: BTreeMap<ServerId, Option<AttemptServer>>,
    /// Actual per-server result after the attempt.
    pub servers: BTreeMap<ServerId, AttemptServer>,
}

/// A fully successful fleet snapshot exposed as `<target>@fN`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReflogEntry {
    pub index: u64,
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    pub behavior_sha256: String,
    pub servers: BTreeMap<ServerId, AttemptServer>,
}

/// Observed remote state for one server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ObservedServer {
    #[serde(default)]
    pub generation: Option<GenerationId>,
    #[serde(default)]
    pub release: Option<ReleaseId>,
    #[serde(default)]
    pub variant: Option<VariantName>,
    #[serde(default)]
    pub tree: Option<TreeDigest>,
    #[serde(default)]
    pub last_deployment: Option<DeploymentId>,
}

/// Observed remote state for a whole target (`observed.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ObservedTarget {
    pub target: TargetName,
    #[serde(default)]
    pub servers: BTreeMap<ServerId, ObservedServer>,
}

/// Persisted per-server local record (`servers/<id>.json`).
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
    /// Materialize the currently mapped local files and assign each server its
    /// target-configured (current) variant.
    Head,
    /// Restore a historical successful fleet snapshot by index (`@fN`).
    FleetRef(u64),
    /// Assign each current server its configured variant from a named release.
    ReleaseRef(ReleaseId),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerPlan {
    pub server_id: ServerId,
    pub variant: VariantName,
    pub release: ReleaseId,
    pub tree: TreeDigest,
    /// Pre-push generation that must match for the compare-and-swap precondition.
    pub expected_generation: Option<GenerationId>,
    pub expected_tree: Option<TreeDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentPlan {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    pub behavior_sha256: String,
    /// The frozen activation + verification contract this attempt is bound to.
    /// Historical and rollback pushes carry the historical contract here rather
    /// than the caller's current configuration.
    pub behavior: BehaviorContract,
    pub server_ids: Vec<ServerId>,
    pub servers: BTreeMap<ServerId, ServerPlan>,
    pub source: PlanSource,
    pub desired_release: ReleaseId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerResult {
    pub server_id: ServerId,
    pub outcome: ServerOutcomeKind,
    /// The generation this server advanced to, or `None` if it never started.
    pub generation: Option<GenerationId>,
    pub compensated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentResults {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    pub servers: BTreeMap<ServerId, ServerResult>,
}
