//! Release identity derivation.
//!
//! The canonical release ID is derived from a versioned canonical identity
//! payload containing the frozen mapping digest, all declared
//! `variant -> tree digest` bindings, and the activation and verification
//! contract digest. It explicitly excludes the resulting release ID, creation
//! time, display name, and provenance, avoiding a circular hash.

use crate::config::{ActivationConfig, Mapping, VariantPolicy, VerificationConfig};
use crate::digest::sha256_bytes;
use crate::model::{
    BehaviorContract, CanonicalReleasePayload, Provenance, ReleaseDigest, ReleaseId, ReleaseRecord,
    TreeDigest, VariantName,
};
use chrono::Utc;
use std::collections::BTreeMap;
use std::path::Path;

/// Canonical digest of the frozen mapping set.
pub fn mapping_digest(mappings: &[Mapping]) -> String {
    let v = serde_json::to_vec(mappings).expect("mappings serialize");
    sha256_bytes(&v)
}

/// Canonical digest of the activation + verification contract.
pub fn behavior_digest(activation: &ActivationConfig, verification: &VerificationConfig) -> String {
    let act = serde_json::to_value(activation).expect("activation serializes");
    let ver = serde_json::to_value(verification).expect("verification serializes");
    let payload = serde_json::json!({ "activation": act, "verification": ver });
    sha256_bytes(&serde_json::to_vec(&payload).expect("payload serializes"))
}

/// Canonical digest of a resolved [`BehaviorContract`].
pub fn behavior_contract_digest(contract: &BehaviorContract) -> String {
    behavior_digest(&contract.activation, &contract.verification)
}

/// Reconstruct a [`BehaviorContract`] from serialized JSON bytes.
pub fn behavior_contract_from_json(
    bytes: &[u8],
) -> std::result::Result<BehaviorContract, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// Canonical digest over name-sorted per-variant mapping sets. Two releases
/// share this digest only when every declared variant materializes the same
/// mappings.
pub fn variant_mappings_digest(mappings: &BTreeMap<String, Vec<Mapping>>) -> String {
    let value = serde_json::to_vec(mappings).expect("variant mappings serialize");
    sha256_bytes(&value)
}

/// Canonical digest over name-sorted per-variant behavior contracts. Two
/// releases share this digest only when every declared variant's activation and
/// verification behavior is identical.
pub fn variant_behaviors_digest(
    contracts: &BTreeMap<String, BehaviorContract>,
) -> String {
    let value = serde_json::to_vec(contracts).expect("variant behaviors serialize");
    sha256_bytes(&value)
}

/// Reconstruct the name-keyed per-variant behavior map from serialized JSON.
pub fn behavior_contracts_from_json(
    bytes: &[u8],
) -> std::result::Result<BTreeMap<String, BehaviorContract>, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// Reconstruct the name-keyed per-variant capacity policy map from serialized
/// JSON. Older snapshots may also embed a per-variant `rotation` key; it is
/// ignored — rotation is now fleet-wide configuration in `deploy.toml`.
pub fn variant_policies_from_json(
    bytes: &[u8],
) -> std::result::Result<BTreeMap<String, VariantPolicy>, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// Derive the release digest from the canonical payload.
pub fn release_digest(
    mapping_sha: &str,
    behavior_sha: &str,
    variants: &BTreeMap<String, String>,
) -> ReleaseDigest {
    let payload = CanonicalReleasePayload {
        schema_version: 1,
        mapping_sha256: mapping_sha.to_string(),
        behavior_sha256: behavior_sha.to_string(),
        variants: variants.clone(),
    };
    let bytes = serde_json::to_vec(&payload).expect("payload serializes");
    ReleaseDigest::new(sha256_bytes(&bytes))
}

/// Compute the current Git revision of `root`, if available.
pub fn git_revision(root: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .ok()?;
    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    } else {
        None
    }
}

/// Build a complete, immutable release record for the given variant bindings.
pub fn build_release(
    mapping_sha: &str,
    behavior_sha: &str,
    variants: &BTreeMap<VariantName, TreeDigest>,
    root: &Path,
) -> ReleaseRecord {
    let bindings: BTreeMap<String, String> = variants
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.as_str().to_string()))
        .collect();
    let digest = release_digest(mapping_sha, behavior_sha, &bindings);
    let id = ReleaseId::from_digest(&digest);
    ReleaseRecord {
        release_schema_version: 1,
        release_id: id.as_str().to_string(),
        release_sha256: digest.as_str().to_string(),
        created_at: Utc::now().to_rfc3339(),
        provenance: Provenance {
            git_revision: git_revision(root),
            mapping_sha256: mapping_sha.to_string(),
            behavior_sha256: behavior_sha.to_string(),
        },
        variants: bindings,
    }
}
