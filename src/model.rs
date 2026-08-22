//! Core identity types and canonical data structures.
//! The deployment core is deliberately ignorant of application semantics. It
//! understands only filesystem entries, mappings, trees, artifacts, variants,
//! releases, targets, and activation adapters. The important identities are:
//!
//! * `tree`       = immutable filesystem content, identified only by digest
//! * `variant`    = a name bound to one tree within a release
//! * `artifact`   = the release + variant + tree binding
//! * `release`    = an immutable map of every declared variant to a tree digest
//! * `target`     = a named group of stable server IDs and its rollout policy
//! * `deployment` = an attempted push and its exact per-server assignments
//! * `generation` = one server's durable activation record for one assignment
//!
//! Deployment, operation, and generation IDs are opaque collision-resistant
//! IDs (UUIDv7 in schema version 1). They identify events and are never used
//! as content identity.

use crate::config::{ActivationConfig, VerificationConfig};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// The schema version understood by this implementation.
pub const SCHEMA_VERSION: u32 = 1;

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
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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

/// Canonical tree metadata (the `tree.json` payload).
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

/// The canonical release identity payload. It deliberately excludes the
/// resulting release ID, creation time, display name, and provenance to avoid
/// a circular hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalReleasePayload {
    pub schema_version: u32,
    pub mapping_sha256: String,
    pub behavior_sha256: String,
    /// Canonical digest of the name-sorted per-variant capacity-policy
    /// snapshot. Capacity headroom is part of the release identity: a
    /// capacity-only configuration change produces a new release.
    pub policies_sha256: String,
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

/// Immutable release record (`release.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRecord {
    pub release_schema_version: u32,
    pub release_id: String,
    pub release_sha256: String,
    pub created_at: String,
    pub provenance: Provenance,
    /// `variant -> tree digest`.
    pub variants: std::collections::BTreeMap<String, String>,
}

/// Per-variant tree resolution result produced during materialization.
#[derive(Clone, Debug)]
pub struct ResolvedVariant {
    pub variant: VariantName,
    pub tree_digest: TreeDigest,
    pub tree_meta: TreeMetadata,
}

/// The artifact binding: (release ID, variant, tree digest).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactBinding {
    pub release: ReleaseId,
    pub variant: VariantName,
    pub tree: TreeDigest,
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
