//! Core identity types and canonical data structures.
//! The deployment core is deliberately ignorant of application semantics. It
//! understands only filesystem entries, mappings, trees, artifacts, variants,
//! releases, targets, and activation adapters. The important identities are:
//!
//! * `tree`       = immutable filesystem content, identified only by digest
//! * `variant`    = a name bound to one tree within a release
//! * `artifact`   = the release + variant + tree binding
//! * `release`    = an immutable map of every variant to a tree digest
//! * `slot`       = a named deployment location (one server + one variant)
//! * `target`     = a named group of stable deployment slots and its rollout policy
//! * `deployment` = an attempted push and its exact per-slot assignments
//! * `generation` = one slot's durable activation record for one assignment
//!
//! Deployment, operation, and generation IDs are opaque collision-resistant
//! IDs (UUIDv7 in schema version 1). They identify events and are never used
//! as content identity.
//!
//! Identity model: [`PlacementSlotId`] is the DEPLOYMENT-LOCATION identity —
//! the key of every slot→assignment relationship (plans, attempts, observed
//! state, snapshots, commit markers). [`ServerId`] is the ACTUAL SERVER
//! identity used for transport addressing (user@host lives on `ServerDef`).
//! They are distinct concepts: a server can host slots in multiple targets,
//! and a slot may be a member of several targets (each carrying its own
//! `deploy_dir`). Today one target runs at most one slot per server, so the
//! two ID spaces are interchangeable within a target, but the model keys
//! assignments by [`PlacementSlotId`] and addresses transports by
//! [`ServerId`].

use crate::config::{ActivationConfig, VerificationConfig};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// The schema version understood by this implementation.
///
/// `SCHEMA_VERSION` is the SINGLE authoritative schema version for every
/// versioned record family that uses it: the user-facing `deploy.toml`
/// configuration (`Config.schema_version`, validated in
/// [`crate::config::Config::validate`]) AND the deployment records
/// (`DeploymentAttempt.deployment_schema_version`, validated on every read
/// in [`crate::store::local::LocalStore::read_attempts`]). Every writer
/// emits exactly `SCHEMA_VERSION`; every reader refuses any other version
/// (fail closed — a mismatched record is never silently interpreted).
///
/// The current format is version 1: deployment records use the canonical
/// placement-slot-keyed shape (`BTreeMap<PlacementSlotId, _>` maps, nested
/// artifact/generation refs). A hypothetical pre-rekeying shape that keyed
/// these maps by server ID with flat artifact fields is NOT the current
/// schema and never loads.
pub const SCHEMA_VERSION: u32 = 1;

/// The canonical release identity PAYLOAD version
/// (`CanonicalReleasePayload.schema_version`), FROZEN INTO the release
/// digest: the field is part of the hashed identity payload, so its value
/// can never change without producing a new release ID. Version 2 is the
/// slots-into-identity payload: it adds the per-variant canonical slot
/// declaration digest (`slots_digest`) alongside the mapping and behavior
/// digests. Read-side enforcement is implicit and fail-closed:
/// `verify_release_identity` recomputes the digest using exactly this
/// version, so a release whose identity was derived from any other payload
/// version fails the recompute-and-verify check.
pub const RELEASE_PAYLOAD_SCHEMA_VERSION: u32 = 2;

/// The `release.json` record format version
/// (`ReleaseRecord.release_schema_version`). `build_release` emits exactly
/// this value and [`crate::release::verify_release_identity`] refuses any
/// other version (fail closed) on every write and read path.
pub const RELEASE_RECORD_SCHEMA_VERSION: u32 = 1;

/// The `tree.json` metadata format version (`TreeMetadata.tree_schema_version`).
/// [`crate::tree::canonicalize_tree`] emits exactly this value and
/// [`crate::store::local::LocalStore::read_tree_meta`] refuses any other
/// version (fail closed).
pub const TREE_SCHEMA_VERSION: u32 = 1;

/// The `cleanup-pending.json` marker format version
/// (`CleanupPending.schema_version`). The marker is a DURABLE FLAG ONLY — it
/// records that a checkpoint's post-commit cleanup is outstanding, never a
/// worklist (the deletion worklist lives in the raw logs, which the
/// delete-before-rewrite compaction order keeps intact until deletion
/// completes). Version 2 is the flag-only shape: the marker carries
/// `target` / `deployment_id` / `snapshot_index` / `established_at` for
/// integrity binding only. Version 1 was the pre-change shape that also
/// carried `pending_deployments: Vec<String>`; a v1 marker is REFUSED
/// (fail closed) rather than silently reinterpreted — the retry treats the
/// failed read as debt outstanding and re-runs the compaction from the
/// intact logs, which converges and clears the stale marker.
pub const CLEANUP_PENDING_SCHEMA_VERSION: u32 = 2;

fn new_uuid_v7() -> String {
    Uuid::now_v7().to_string()
}

macro_rules! id_newtype {
    ($name:ident) => {
        #[derive(
            Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Self {
                $name(s.into())
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                $name(s)
            }
        }

        impl std::str::FromStr for $name {
            type Err = std::convert::Infallible;
            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                Ok($name(s.to_string()))
            }
        }
    };
}

/// The canonical behavior contract (activation + verification) that fully
/// describes how an assignment is activated and verified. It is frozen into the
/// release identity and copied into every generation record so a historical
/// push restores its original behavior rather than the caller's current config.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BehaviorContract {
    pub activation: ActivationConfig,
    pub verification: VerificationConfig,
}

id_newtype!(ReleaseDigest);

/// Release identifier: `rel-sha256-<release-digest>`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReleaseId(String);

impl ReleaseId {
    pub fn new(s: impl Into<String>) -> Self {
        ReleaseId(s.into())
    }
    pub fn from_digest(d: &ReleaseDigest) -> Self {
        ReleaseId(format!("rel-sha256-{}", d.0))
    }
    /// Parse a full or prefixed release id; also accepts a bare digest.
    pub fn parse(s: &str) -> Self {
        if s.starts_with("rel-sha256-") {
            ReleaseId(s.to_string())
        } else {
            ReleaseId(format!("rel-sha256-{}", s.trim_start_matches("rel-")))
        }
    }
    pub fn digest(&self) -> ReleaseDigest {
        ReleaseDigest(self.0.trim_start_matches("rel-sha256-").to_string())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ReleaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

id_newtype!(DeploymentId);
id_newtype!(GenerationId);
id_newtype!(OperationId);
id_newtype!(ServerId);
id_newtype!(PlacementSlotId);
id_newtype!(TargetName);
id_newtype!(VariantName);
id_newtype!(TreeDigest);

impl DeploymentId {
    pub fn generate() -> Self {
        DeploymentId(format!("deploy-{}", new_uuid_v7()))
    }
}

impl GenerationId {
    pub fn generate() -> Self {
        GenerationId(format!("gen-{}", new_uuid_v7()))
    }
}

impl OperationId {
    pub fn generate() -> Self {
        OperationId(format!("op-{}", new_uuid_v7()))
    }
}

/// One entry in a canonical tree object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeEntry {
    /// NFC-normalized, UTF-8 relative path within the artifact root.
    pub path: String,
    /// `file`, `dir`, or `symlink`.
    #[serde(rename = "type")]
    pub entry_type: String,
    /// Octal mode string, e.g. `"0755"`.
    pub mode: String,
    /// For files: SHA-256 of contents. For symlinks: SHA-256 of the target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_sha256: Option<String>,
    /// For symlinks: the (relative, in-root) link target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<String>,
}

/// Canonical tree metadata (the `tree.json` payload). `tree_schema_version`
/// is [`TREE_SCHEMA_VERSION`]; readers refuse any other value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeMetadata {
    pub tree_schema_version: u32,
    pub hash_algorithm: String,
    pub tree_sha256: String,
    pub entries: Vec<TreeEntry>,
}

/// The unversioned but frozen mapping digest payload (canonical mapping form).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalMapping {
    pub mappings: serde_json::Value,
}

/// The activation + verification behavior contract (canonical form).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalBehavior {
    pub activation: serde_json::Value,
    pub verification: serde_json::Value,
}

/// One canonical slot declaration: the four identity-bearing fields of a
/// [`crate::config::SlotDef`], with `deploy_dir` reduced to a lexically
/// normalized absolute path string and `targets` SORTED (the canonical form —
/// and therefore the release identity digest — must be order-independent).
/// Server-level policy (user, address, port, capacity) is deliberately
/// absent: it is a per-server policy resolved from the caller's current
/// configuration, never part of a release identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalSlot {
    pub id: String,
    pub server: String,
    pub deploy_dir: String,
    /// The slot's target membership list, sorted so the canonical form is
    /// order-independent: `["staging", "production"]` and
    /// `["production", "staging"]` canonicalize identically.
    pub targets: Vec<String>,
}

/// The canonicalized slot declaration set of one variant: its slots sorted by
/// slot id, with ties broken deterministically by the remaining identity
/// fields (server, deploy_dir, targets) so the canonical form is a pure
/// function of the declared slot set — order-independent even for the
/// degenerate duplicate-id declarations a record that slipped past validation
/// can carry. A variant's slot declarations ARE release identity — rebinding a
/// slot to another server, moving its `deploy_dir`, or changing its target
/// membership changes the release — so this snapshot is frozen into the
/// release record and digest. It carries exactly the four [`CanonicalSlot`]
/// fields and no derived state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalSlots {
    pub slots: Vec<CanonicalSlot>,
}

/// The canonical release identity payload. It deliberately excludes the
/// resulting release ID, creation time, display name, and provenance to avoid
/// a circular hash.
///
/// The payload covers the name-sorted per-variant mapping digest, the
/// name-sorted per-variant behavior (activation + verification) digest, the
/// name-sorted per-variant slot declaration digest, and the
/// `variant -> tree digest` bindings. Slots ARE part of the release identity:
/// they are declared inside the variant files, so rebinding a slot to another
/// server, moving its `deploy_dir`, or retargeting it produces a new release.
/// Capacity is NOT part of the release identity: it is a per-server policy
/// resolved from the caller's current configuration, so a server-capacity
/// change does NOT produce a new release.
///
/// Schema version 2 ([`RELEASE_PAYLOAD_SCHEMA_VERSION`]): the identity
/// payload includes the per-variant slot declaration digest (added
/// alongside the mappings/behavior digests). The version is frozen into the
/// release digest; `verify_release_identity` recomputes it with exactly
/// this constant, so any other payload version fails verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalReleasePayload {
    pub schema_version: u32,
    pub mapping_sha256: String,
    pub behavior_sha256: String,
    /// Canonical digest of the name-sorted per-variant slot declarations.
    pub slots_digest: String,
    /// Sorted `variant -> tree digest` bindings.
    pub variants: std::collections::BTreeMap<String, String>,
}

/// Provenance captured at first materialization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_revision: Option<String>,
    pub mapping_sha256: String,
    pub behavior_sha256: String,
}

/// Immutable release record (`release.json`). `release_schema_version` is
/// [`RELEASE_RECORD_SCHEMA_VERSION`]; readers (`verify_release_identity`)
/// refuse any other version (fail closed).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRecord {
    pub release_schema_version: u32,
    pub release_id: String,
    pub release_sha256: String,
    pub created_at: String,
    pub provenance: Provenance,
    /// `variant -> tree digest`.
    pub variants: std::collections::BTreeMap<String, String>,
    /// The release's OWN canonical per-variant slot declaration snapshot
    /// (name-sorted, each variant's slots sorted by slot id). A historical or
    /// rollback push resolves slot→variant bindings from this snapshot rather
    /// than the caller's current variant files, so a historical release keeps
    /// the slot declarations it was materialized from. Written since the
    /// slots-into-identity refactor; `#[serde(default)]` keeps records written
    /// by older code loadable (the empty map falls back to the caller's
    /// current configuration for slot→variant resolution).
    #[serde(default)]
    pub slots: std::collections::BTreeMap<String, CanonicalSlots>,
}

/// Per-variant tree resolution result produced during materialization.
#[derive(Clone, Debug)]
pub struct ResolvedVariant {
    pub variant: VariantName,
    pub tree_digest: TreeDigest,
    pub tree_meta: TreeMetadata,
}

/// The canonical artifact reference: the (release, variant, tree) triple that
/// fully names one deployable artifact. This is the single reusable type for
/// the artifact relationship — plans, attempts, observed state, generation
/// records, and snapshots all express it through [`ArtifactRef`] instead
/// of re-declaring the three fields.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct ArtifactRef {
    pub release: ReleaseId,
    pub variant: VariantName,
    pub tree: TreeDigest,
}

/// The canonical slot→artifact assignment: one placement slot running one
/// artifact. Reused wherever a slot is bound to an artifact (plans,
/// [`GenerationRef`] assignments).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementSlotAssignment {
    pub placement_slot: PlacementSlotId,
    pub artifact: ArtifactRef,
}

/// One slot's durable generation for one artifact assignment: the complete,
/// non-optional record of what a slot advanced to (minted generations in an
/// attempt, and the per-slot state of a successful snapshot).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationRef {
    pub generation: GenerationId,
    pub assignment: PlacementSlotAssignment,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_id_round_trip() {
        let d = "7b278acf5041d50a9704392ac9fac4c6c02ca2cf3be9e5aee61668c8070526d2";
        let rid = ReleaseId::from_digest(&ReleaseDigest::from(d.to_string()));
        assert_eq!(rid.as_str(), format!("rel-sha256-{d}"));
        assert_eq!(
            rid,
            ReleaseId::from_digest(&ReleaseDigest::from(d.to_string()))
        );
    }

    #[test]
    fn newtypes_parse_and_eq() {
        assert_eq!(
            TreeDigest::from("a".to_string()),
            TreeDigest::from("a".to_string())
        );
        assert_ne!(
            TreeDigest::from("a".to_string()),
            TreeDigest::from("b".to_string())
        );
        assert_eq!(GenerationId::from("gen-x".to_string()).as_str(), "gen-x");
    }
}
