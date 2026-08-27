//! The canonical payload and record types: the release identity payload
//! ([`CanonicalReleasePayload`]) and the canonical forms of the mapping,
//! behavior, slot-declaration, tree, provenance, and release-record data
//! structures.
//!
//! The release identity payload covers the name-sorted per-variant mapping
//! digest, the name-sorted per-variant behavior (activation + verification)
//! digest, the name-sorted per-variant slot declaration digest, and the
//! `variant -> tree digest` bindings. Slots ARE part of the release identity:
//! they are declared inside the variant files, so rebinding a slot to another
//! server, moving its `deploy_dir`, or retargeting it produces a new release.
//! Capacity is NOT part of the release identity: it is a per-server policy
//! resolved from the caller's current configuration, so a server-capacity
//! change does NOT produce a new release.
//!
//! NOTE: several of these types are the canonical payload shapes of their
//! OWNING areas (the tree payloads [`TreeEntry`]/[`TreeMetadata`] and the
//! artifact-relationship types [`ArtifactRef`]/[`PlacementSlotAssignment`]/
//! [`GenerationRef`]) and will be MOVED to their owning area modules in
//! later encapsulation passes; they are parked here with the identity
//! payload for now.

use crate::config::{ActivationConfig, VerificationConfig};
use crate::identity::{GenerationId, ReleaseId, SlotId, TreeDigest, VariantName};
use serde::{Deserialize, Serialize};

/// The canonical behavior contract (activation + verification) that fully
/// describes how an assignment is activated and verified. It is frozen into the
/// release identity and copied into every generation record so a historical
/// push restores its original behavior rather than the caller's current config.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BehaviorContract {
    pub activation: ActivationConfig,
    pub verification: VerificationConfig,
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

/// One canonical slot declaration: the identity-bearing fields of a
/// [`crate::config::SlotConfig`], with `deploy_dir` reduced to a lexically
/// normalized absolute path string, the ONE owning `target` kept verbatim,
/// and `groups` SORTED and DEDUPLICATED (the canonical form — and therefore
/// the release identity digest — must be order-independent). Server-level
/// policy (user, address, port, capacity) is deliberately absent: it is a
/// per-server policy resolved from the caller's current configuration, never
/// part of a release identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalSlot {
    pub id: String,
    pub server: String,
    pub deploy_dir: String,
    /// The slot's EXACTLY ONE owning target. Changing it changes the release
    /// identity.
    pub target: String,
    /// The slot's rollout groups, scoped to its owning target, sorted and
    /// deduplicated so the canonical form is order-independent:
    /// `["wave-1", "canary"]` and `["canary", "wave-1"]` canonicalize
    /// identically.
    pub groups: Vec<String>,
}

/// The canonicalized slot declaration set of one variant: its slots sorted by
/// slot id, with ties broken deterministically by the remaining identity
/// fields (server, deploy_dir, target, groups) so the canonical form is a pure
/// function of the declared slot set — order-independent even for the
/// degenerate duplicate-id declarations a record that slipped past validation
/// can carry. A variant's slot declarations ARE release identity — rebinding a
/// slot to another server, moving its `deploy_dir`, changing its owning
/// target, or changing its group membership changes the release — so this
/// snapshot is frozen into the release record and digest. It carries exactly
/// the [`CanonicalSlot`] fields and no derived state.
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
///
/// NOTE: deliberately NO `Default` — a `Default` artifact would carry an
/// EMPTY (malformed) release id, the exact gap this hardening closes. An
/// artifact can only be built from validated identities.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
    pub placement_slot: SlotId,
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
