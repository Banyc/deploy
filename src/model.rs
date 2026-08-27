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
//! Identity model: [`SlotId`] is the DEPLOYMENT-LOCATION identity —
//! the key of every slot→assignment relationship (plans, attempts, observed
//! state, snapshots, commit markers). [`ServerId`] is the ACTUAL SERVER
//! identity used for transport addressing (user@host lives on `ServerDef`).
//! They are distinct concepts: a server can host slots in multiple targets,
//! and a slot may be a member of several targets (each carrying its own
//! `deploy_dir`). Today one target runs at most one slot per server, so the
//! two ID spaces are interchangeable within a target, but the model keys
//! assignments by [`SlotId`] and addresses transports by
//! [`ServerId`].

use crate::config::{ActivationConfig, VerificationConfig};
use crate::error::{Error, Result};
use crate::scalar::valid_name;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use uuid::Uuid;

/// The configuration format version understood by this implementation
/// (`ProjectConfig.schema_version`, validated by the raw -> domain conversion in
/// [`crate::config::ProjectConfig::load`]). Every config writer emits exactly
/// `CONFIG_SCHEMA_VERSION`; the config reader refuses any other version
/// (fail closed — a `deploy.toml` from a different schema is never
/// silently interpreted). This is INDEPENDENT of [`LEDGER_SCHEMA_VERSION`]:
/// the configuration and the deployment records version themselves
/// separately, so bumping one never invalidates the other.
///
/// The current format is version 2.
pub const CONFIG_SCHEMA_VERSION: u32 = 2;

/// The deployment LEDGER format version — the version every deployment
/// record carries (`LedgerIntentWire.deployment_schema_version`, validated on
/// every read in [`crate::store::local::LocalStore::read_ledger`]). Every
/// ledger writer emits exactly `LEDGER_SCHEMA_VERSION`; every ledger reader
/// refuses any other version (fail closed — a mismatched record is never
/// silently interpreted). This is INDEPENDENT of [`CONFIG_SCHEMA_VERSION`]:
/// the deployment records version themselves separately from the
/// configuration format, so bumping one never invalidates the other.
///
/// The current format is version 2: deployment records use the canonical
/// placement-slot-keyed shape (`BTreeMap<SlotId, _>` maps, nested
/// artifact/generation refs) and carry the exclusive owning target + the
/// optional rollout group of the attempt. Version 1 records (the
/// multi-target `targets` membership shape) are REJECTED on read — no
/// compatibility fallback. A hypothetical pre-rekeying shape that keyed
/// these maps by server ID with flat artifact fields is NOT the current
/// schema and never loads.
pub const LEDGER_SCHEMA_VERSION: u32 = 2;

/// The canonical release identity PAYLOAD version
/// (`CanonicalReleasePayload.schema_version`), FROZEN INTO the release
/// digest: the field is part of the hashed identity payload, so its value
/// can never change without producing a new release ID. Version 3 is the
/// exclusive-ownership payload: the per-variant canonical slot declaration
/// digest (`slots_digest`) now carries each slot's ONE owning target and
/// its rollout groups (replacing the multi-target `targets` membership
/// list). Read-side enforcement is implicit and fail-closed:
/// `verify_release_identity` recomputes the digest using exactly this
/// version, so a release whose identity was derived from any other payload
/// version fails the recompute-and-verify check.
pub const RELEASE_PAYLOAD_SCHEMA_VERSION: u32 = 3;

/// The `release.json` record format version
/// (`ReleaseRecord.release_schema_version`). `build_release` emits exactly
/// this value and [`crate::release::verify_release_identity`] refuses any
/// other version (fail closed) on every write and read path. Version 2
/// records the exclusive-ownership canonical slot snapshot (each slot's one
/// `target` + `groups`); version 1 records (the multi-target `targets`
/// shape) are rejected on read — no compatibility fallback.
pub const RELEASE_RECORD_SCHEMA_VERSION: u32 = 2;

/// The `tree.json` metadata format version (`TreeMetadata.tree_schema_version`).
/// [`crate::tree::canonicalize_tree`] emits exactly this value and
/// [`crate::store::local::LocalStore::read_tree_meta`] refuses any other
/// version (fail closed).
pub const TREE_SCHEMA_VERSION: u32 = 1;

/// The `pins.json` record format version (`Pins.schema_version`). Pins are
/// durable, store-global retention anchors for artifact CONTENT ONLY (see
/// `crate::records::Pins`): a pin never retains or reinserts an old
/// deployment, attempt, or snapshot in history. Readers refuse any other
/// version (fail closed — a pins file from a different schema is never
/// silently interpreted).
pub const PINS_SCHEMA_VERSION: u32 = 1;
fn new_uuid_v7() -> String {
    Uuid::now_v7().to_string()
}

/// A valid `deploy-`/`gen-`/`op-` prefixed UUIDv7 identity: the exact form
/// [`new_uuid_v7`] produces (a canonical hyphenated UUIDv7 string). The
/// hyphenated shape is required (the generator never emits the simple form)
/// and the version nibble is enforced (v7 only), so a hand-written v4 UUID or
/// any other malformed suffix is rejected.
fn valid_uuid_v7_id(s: &str, prefix: &str) -> bool {
    let Some(rest) = s.strip_prefix(prefix) else {
        return false;
    };
    let b = rest.as_bytes();
    b.len() == 36
        && b[8] == b'-'
        && b[13] == b'-'
        && b[18] == b'-'
        && b[23] == b'-'
        && Uuid::parse_str(rest)
            .map(|u| u.get_version() == Some(uuid::Version::SortRand))
            .unwrap_or(false)
}

fn valid_deployment_id(s: &str) -> bool {
    valid_uuid_v7_id(s, "deploy-")
}

fn valid_generation_id(s: &str) -> bool {
    valid_uuid_v7_id(s, "gen-")
}

fn valid_operation_id(s: &str) -> bool {
    valid_uuid_v7_id(s, "op-")
}

/// A valid sha256 digest: exactly 64 lowercase hex characters (the exact form
/// [`crate::digest::sha256_bytes`] produces). Any other string — empty, short,
/// long, uppercase, non-hex, or prefixed — is rejected.
pub(crate) fn valid_hex_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The validated identity newtype: construction goes through [`parse`]
/// (or `FromStr`/`TryFrom`), which enforces the type's format rule, and the
/// serde `Deserialize` routes every wire string through the same validation
/// (an invalid wire identity fails deserialization — fail closed). The
/// UNCHECKED [`new`] constructor is `#[cfg(test)]` only: test fixtures may
/// build arbitrary ids, production never can.
///
/// `$validator` is a `fn(&str) -> bool` implementing the type's format rule.
macro_rules! id_newtype {
    ($name:ident, $validator:expr, $doc:expr) => {
        #[doc = $doc]
        // NOTE: deliberately NO `Default` — a `Default` identity would be an
        // EMPTY string, a malformed durable record constructible by anyone
        // (the exact gap this hardening closes). An identity can only be
        // built through the validated [`parse`] (or `FromStr`/`TryFrom`).
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Validate `s` against the type's format rule and construct the
            /// identity. The invariant is enforced HERE: an invalid value is
            /// rejected before a value of this type can exist.
            pub fn parse(s: &str) -> Result<$name> {
                if !$validator(s) {
                    return Err(Error::config(format!(
                        "invalid {} value {:?}",
                        stringify!($name),
                        s
                    )));
                }
                Ok($name(s.to_string()))
            }

            /// The validated identity string.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// The validated identity string, consumed.
            pub fn into_string(self) -> String {
                self.0
            }

            /// UNCHECKED constructor — TEST FIXTURES ONLY. Production code
            /// must construct through [`parse`] (or `FromStr`/`TryFrom`), so
            /// an invalid identity can never be built outside tests.
            #[cfg(test)]
            pub fn new(s: impl Into<String>) -> Self {
                $name(s.into())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = Error;
            fn from_str(s: &str) -> Result<$name> {
                $name::parse(s)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = Error;
            fn try_from(s: &str) -> Result<$name> {
                $name::parse(s)
            }
        }

        /// UNCHECKED conversion — TEST FIXTURES ONLY (mirrors [`$name::new`]).
        /// NOTE: deliberately NO `From<String>`/`From<&str>` impl — clap's
        /// value-parser inference prefers those over `FromStr`, which would
        /// silently bypass validation in test builds (and `From<&str>` would
        /// conflict with the validated `TryFrom<&str>`).

        impl<'de> Deserialize<'de> for $name {
            /// Wire strings go through the validated parse: an invalid wire
            /// identity fails deserialization (fail closed — a record that
            /// carries a malformed identity is never silently accepted).
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                $name::parse(&s).map_err(serde::de::Error::custom)
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

id_newtype!(
    ReleaseDigest,
    valid_hex_digest,
    "A release digest: exactly 64 lowercase hex characters (sha256) — the \
     exact form [`crate::digest::sha256_bytes`] produces."
);

/// Release identifier: EXACTLY `rel-sha256-<64 lowercase hex>` — the canonical
/// form [`ReleaseId::from_digest`] produces. The loose bare-digest and `rel-`
/// forms are REJECTED at the domain boundary: a `ReleaseId` can only be built
/// through the validated [`ReleaseId::parse`] (or `FromStr`/`TryFrom`/
/// `from_digest`), so a malformed release id can never exist in a durable
/// record. The CLI accepts a bare 64-hex digest as an input convenience via
/// [`crate::cli::parse_release_input`], which converts it to the full form
/// BEFORE the domain parse.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ReleaseId(String);

impl ReleaseId {
    /// UNCHECKED constructor — TEST FIXTURES ONLY (mirrors the
    /// [`id_newtype!`] contract). Production code must construct through
    /// [`ReleaseId::parse`] (or `FromStr`/`TryFrom`/`from_digest`), so an
    /// invalid release id can never be built outside tests.
    #[cfg(test)]
    pub fn new(s: impl Into<String>) -> Self {
        ReleaseId(s.into())
    }
    pub fn from_digest(d: &ReleaseDigest) -> Self {
        ReleaseId(format!("rel-sha256-{}", d.0))
    }
    /// Validate `s` against the EXACT `rel-sha256-<64 lowercase hex>` rule
    /// and construct the identity. The loose bare-digest and `rel-` forms
    /// are rejected HERE, at the domain boundary.
    pub fn parse(s: &str) -> Result<ReleaseId> {
        if let Some(rest) = s.strip_prefix("rel-sha256-")
            && valid_hex_digest(rest)
        {
            return Ok(ReleaseId(s.to_string()));
        }
        Err(Error::config(format!("invalid ReleaseId value {:?}", s)))
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

impl std::str::FromStr for ReleaseId {
    type Err = Error;
    fn from_str(s: &str) -> Result<ReleaseId> {
        ReleaseId::parse(s)
    }
}

impl TryFrom<&str> for ReleaseId {
    type Error = Error;
    fn try_from(s: &str) -> Result<ReleaseId> {
        ReleaseId::parse(s)
    }
}

impl<'de> Deserialize<'de> for ReleaseId {
    /// Wire strings go through the validated parse: an invalid wire release
    /// id fails deserialization (fail closed — a record that carries a
    /// malformed release id is never silently accepted).
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        ReleaseId::parse(&s).map_err(serde::de::Error::custom)
    }
}

id_newtype!(
    DeploymentId,
    valid_deployment_id,
    "A deployment identity: `deploy-<uuid-v7>` (the exact form \
     [`DeploymentId::generate`] produces)."
);
id_newtype!(
    GenerationId,
    valid_generation_id,
    "A generation identity: `gen-<uuid-v7>` (the exact form \
     [`GenerationId::generate`] produces)."
);
id_newtype!(
    OperationId,
    valid_operation_id,
    "An operation identity: `op-<uuid-v7>` (the exact form \
     [`OperationId::generate`] produces)."
);
id_newtype!(
    ServerId,
    valid_name,
    "A server identity: a single safe path segment (non-empty, no path \
     separators or traversal components, no surrounding whitespace or control \
     characters) — the shared segment rule from [`crate::scalar`]."
);
id_newtype!(
    SlotId,
    valid_name,
    "A slot identity: a single safe path segment (the shared \
     segment rule from [`crate::scalar`])."
);
id_newtype!(
    TargetName,
    valid_name,
    "A target name: a single safe path segment (the shared segment rule \
     from [`crate::scalar`])."
);
id_newtype!(
    VariantName,
    valid_name,
    "A variant name: a single safe path segment (the shared segment rule \
     from [`crate::scalar`])."
);
id_newtype!(
    TreeDigest,
    valid_hex_digest,
    "A tree digest: exactly 64 lowercase hex characters (sha256) — the exact \
     form [`crate::digest::sha256_bytes`] produces."
);

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

/// The "assignment unknown" sentinel artifact: a VALID artifact reference
/// marking a live assignment that could not be read (the ATTEMPT model's
/// [`crate::records::SlotAttemptState`] — the OBSERVED model uses the
/// explicit [`crate::records::Observation::Unknown`] variant instead,
/// never a sentinel). The sentinel is valid by construction (the release is
/// the canonical empty-content sha256 id, variant `unknown` is a safe
/// segment, the tree digest is a fixed valid sha256) so it round-trips the
/// wire — the old `rel-sha256-unknown` release id was NOT a valid release
/// id and failed the strict wire parse, the exact malformed-record gap this
/// hardening closes. It is never substituted for a real assignment — it
/// only ever marks "the live assignment could not be read".
pub fn unknown_artifact() -> ArtifactRef {
    ArtifactRef {
        release: ReleaseId::from_digest(
            &ReleaseDigest::parse(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )
            .expect("sentinel digest is a valid sha256"),
        ),
        variant: VariantName::parse("unknown").expect("sentinel variant is a safe segment"),
        tree: TreeDigest::parse("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .expect("sentinel digest is a valid sha256"),
    }
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

// ---------------------------------------------------------------------------
// Proof-bearing slot-set types (immutability + membership proofs)
// ---------------------------------------------------------------------------
//
// The proof-bearing resolution layer builds on two slot-set forms:
//
// * [`SlotSet`] — a plain (possibly EMPTY) slot-id set, the INPUT form of a
//   membership verification.
// * [`NonEmptySlotSet`] — the NON-EMPTY, UNIQUE slot-id set: the canonical
//   membership/set form carried by the proof types ([`MatchingMembership`],
//   and the planner's resolved selection). Compose with the sibling
//   records-shape `NonEmptySlotTable` (the map form): this is the set form
//   of the same non-empty membership invariant.
//
// [`MatchingMembership`] is the PROOF that two memberships match: the ONLY
// way to obtain one is [`MatchingMembership::verify`] (the membership gate
// produces it; the planner consumes it). The serde impls serialize the
// agreed set and deserialize only a non-empty set — the persisted-wire
// replay of an already-verified proof (the record's wire -> domain
// conversion re-checks the plan's key-set projections on read).

/// A slot-ID set (possibly EMPTY) — the INPUT form of a membership
/// verification ([`MatchingMembership::verify`]). A plain set of
/// [`SlotId`]s; emptiness is legal here (the non-empty requirement
/// applies to the PROOF result, never to the inputs being compared).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct SlotSet(BTreeSet<SlotId>);

impl SlotSet {
    /// Build a slot set from slot ids; duplicate ids collapse (a set).
    pub(crate) fn new(ids: impl IntoIterator<Item = SlotId>) -> Self {
        SlotSet(ids.into_iter().collect())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// The distinct slot ids in sorted (deterministic) order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &SlotId> {
        self.0.iter()
    }
}

/// The NON-EMPTY, UNIQUE slot-ID set: the canonical membership/slot-set
/// type carried by the proof-bearing types. Construction is gated on
/// non-emptiness ([`NonEmptySlotSet::try_new`] refuses an empty input) — a
/// target with zero slots is never a valid resolution or membership proof
/// (the raw -> domain conversion rejects targets without slots), so the
/// invariant holds by construction. This is the SET form; the sibling
/// records-shape work carries the companion [`NonEmptySlotTable`]-shaped
/// (map-keyed) non-empty tables the records use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NonEmptySlotSet(BTreeSet<SlotId>);

impl NonEmptySlotSet {
    /// Build from slot ids; `None` when the input is EMPTY (a non-empty set
    /// cannot be built from nothing). Duplicate ids are deduplicated (a set).
    pub(crate) fn try_new(ids: impl IntoIterator<Item = SlotId>) -> Option<Self> {
        let ids: BTreeSet<SlotId> = ids.into_iter().collect();
        (!ids.is_empty()).then_some(NonEmptySlotSet(ids))
    }

    /// The number of distinct slot ids.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The distinct slot ids in sorted (deterministic) order.
    pub fn iter(&self) -> impl Iterator<Item = &SlotId> {
        self.0.iter()
    }

    /// Whether the set contains the slot id.
    #[cfg(test)]
    pub fn contains(&self, id: &SlotId) -> bool {
        self.0.contains(id)
    }

    /// The backing set as a read-only view (composes with the sibling
    /// records-shape non-empty tables, which carry the same slot keys).
    pub fn as_set(&self) -> &BTreeSet<SlotId> {
        &self.0
    }
}

/// The PROOF that two slot-ID memberships match: the frozen (historical)
/// and current (live) memberships verified EXACTLY EQUAL, carrying the
/// agreed NON-EMPTY slot set. The ONLY construction path is
/// [`MatchingMembership::verify`] — the membership gate produces the proof
/// and the planner consumes it (a [`crate::records::RebindingPlan`] records
/// it as the membership check that ran). The serde impls serialize the
/// agreed set and deserialize only a NON-EMPTY set (the persisted-wire
/// replay of an already-verified proof; the record's wire -> domain
/// conversion re-checks the plan's key-set projections on read).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MatchingMembership {
    slots: NonEmptySlotSet,
}

impl MatchingMembership {
    /// Verify that the FROZEN and CURRENT slot memberships are EXACTLY
    /// EQUAL and non-empty, producing the proof. `Ok` exactly when
    /// `frozen == current` and the agreed set is non-empty (a target's
    /// membership is never empty — the raw -> domain conversion rejects
    /// targets without slots, so an empty agreement can never be a proof);
    /// `Err` on any mismatch or an empty agreement. This is the ONLY
    /// construction path: the fields are private, so a `MatchingMembership`
    /// cannot be hand-built.
    pub fn verify(frozen: SlotSet, current: SlotSet) -> Result<Self> {
        if frozen.is_empty() || current.is_empty() {
            return Err(Error::rollback(
                "membership proof refused: a membership is never empty",
            ));
        }
        if frozen != current {
            return Err(Error::rollback(
                "membership proof refused: frozen and current slot sets differ",
            ));
        }
        // `frozen == current` and both non-empty: the agreed set is non-empty.
        let slots = NonEmptySlotSet::try_new(frozen.iter().cloned()).ok_or_else(|| {
            Error::internal("verified-equal non-empty memberships yield a non-empty set")
        })?;
        Ok(MatchingMembership { slots })
    }

    /// The agreed (frozen == current) membership: the non-empty slot set
    /// the proof verifies. Read path: the wire → domain conversion
    /// re-checks the claimed proof's agreed set against the plan's own
    /// membership (the frozen topology keys must equal it, and every
    /// selected plan slot must be a member); the property suite asserts its
    /// content through this accessor.
    pub(crate) fn slots(&self) -> &NonEmptySlotSet {
        &self.slots
    }
}

impl Serialize for MatchingMembership {
    /// The persisted wire form is the agreed slot set (the frozen/current
    /// halves were verified equal at plan time; the record keeps the agreed
    /// set).
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.slots.as_set().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MatchingMembership {
    /// Wire replay of a verified proof: reconstructs the proof from the
    /// persisted agreed set, refusing an EMPTY set (the non-empty invariant
    /// holds on the wire too).
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let ids: BTreeSet<SlotId> = Deserialize::deserialize(deserializer)?;
        let slots = NonEmptySlotSet::try_new(ids).ok_or_else(|| {
            serde::de::Error::custom("a membership proof must carry a non-empty slot set")
        })?;
        Ok(MatchingMembership { slots })
    }
}

/// Deterministic canonical test identities: fixtures that ROUND-TRIP through
/// the wire (ledger/observed records) must carry format-valid ids, so these
/// helpers derive a canonical `deploy-<uuid-v7>` / `gen-<uuid-v7>` /
/// `op-<uuid-v7>` / 64-hex-digest from a fixture tag. Deterministic per tag:
/// the same tag yields the same id everywhere, so a fixture can write and
/// assert the same value.
#[cfg(test)]
pub(crate) fn test_uuid_v7(tag: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    tag.hash(&mut h);
    let r = h.finish();
    let mut bytes = [0u8; 16];
    // Fixed 48-bit timestamp (2024-01-01T00:00:00Z ≈ 0x018F_0000_0000 ms).
    let ts: u64 = 0x018F_0000_0000;
    bytes[0..6].copy_from_slice(&ts.to_be_bytes()[2..8]);
    // Version 7 nibble + rand_a (12 bits) from the tag hash.
    bytes[6] = 0x70 | ((r >> 8) & 0x0F) as u8;
    bytes[7] = (r & 0xFF) as u8;
    // Variant 10 + rand_b (58 bits) from the tag hash.
    bytes[8] = 0x80 | ((r >> 56) & 0x3F) as u8;
    bytes[9..16].copy_from_slice(&r.to_be_bytes()[1..8]);
    Uuid::from_bytes(bytes).to_string()
}

#[cfg(test)]
pub(crate) fn test_deployment_id(tag: &str) -> DeploymentId {
    DeploymentId::parse(&format!("deploy-{}", test_uuid_v7(tag))).expect("canonical test id")
}

#[cfg(test)]
pub(crate) fn test_generation_id(tag: &str) -> GenerationId {
    GenerationId::parse(&format!("gen-{}", test_uuid_v7(tag))).expect("canonical test id")
}

#[cfg(test)]
pub(crate) fn test_operation_id(tag: &str) -> OperationId {
    OperationId::parse(&format!("op-{}", test_uuid_v7(tag))).expect("canonical test id")
}

/// A deterministic 64-lowercase-hex sha256 digest derived from a tag.
#[cfg(test)]
pub(crate) fn test_sha256_hex(tag: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    tag.hash(&mut h);
    let r = h.finish();
    let mut h2 = std::collections::hash_map::DefaultHasher::new();
    (tag, r).hash(&mut h2);
    let r2 = h2.finish();
    format!("{r:016x}{r2:016x}{r:016x}{r2:016x}")
}

#[cfg(test)]
pub(crate) fn test_tree_digest(tag: &str) -> TreeDigest {
    TreeDigest::parse(&test_sha256_hex(tag)).expect("canonical test digest")
}

/// A deterministic canonical `rel-sha256-<64-hex>` release id derived from a
/// tag (the canonical form [`ReleaseId::from_digest`] produces — the only
/// form the strict [`ReleaseId::parse`] accepts).
#[cfg(test)]
pub(crate) fn test_release_id(tag: &str) -> ReleaseId {
    ReleaseId::from_digest(
        &ReleaseDigest::parse(&test_sha256_hex(tag)).expect("canonical test digest"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalar::RolloutGroupName;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn release_id_round_trip() {
        let d = "7b278acf5041d50a9704392ac9fac4c6c02ca2cf3be9e5aee61668c8070526d2";
        let rid = ReleaseId::from_digest(&ReleaseDigest::parse(d).expect("64 hex parses"));
        assert_eq!(rid.as_str(), format!("rel-sha256-{d}"));
        assert_eq!(
            rid,
            ReleaseId::from_digest(&ReleaseDigest::parse(d).expect("64 hex parses"))
        );
    }

    #[test]
    fn newtypes_parse_and_eq() {
        let a = test_tree_digest("a");
        let b = test_tree_digest("b");
        assert_eq!(a, a);
        assert_ne!(a, b);
        assert_eq!(
            test_generation_id("x").as_str(),
            format!("gen-{}", test_uuid_v7("x"))
        );
    }

    /// The canonical format of each uuid-v7 identity parses; every invalid
    /// class (empty, bare prefix, wrong prefix, malformed uuid, v4 uuid,
    /// padding, trailing junk) is rejected.
    #[test]
    fn uuid_v7_ids_accept_canonical_reject_invalid() {
        let dep = test_deployment_id("ok");
        assert_eq!(DeploymentId::parse(dep.as_str()).expect("canonical"), dep);
        let gid = test_generation_id("ok");
        assert_eq!(GenerationId::parse(gid.as_str()).expect("canonical"), gid);
        let op = test_operation_id("ok");
        assert_eq!(OperationId::parse(op.as_str()).expect("canonical"), op);
        for bad in [
            "",
            "deploy-",
            "gen-",
            "op-",
            "deploy",
            "deploy-0192a3b4c5d6e7f8a9b0c1d2e3f4a5b6", // simple form, no hyphens
            "deploy-0192a3b4-c5d6-4e7f-8a9b-0c1d2e3f4a5b6", // v4
            "deploy-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5b6 ", // trailing space
            " deploy-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5b6", // leading space
            "deploy-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5b6x", // trailing junk
            "deploy-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5", // too short
            "deploy-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5b6-7", // too long
        ] {
            DeploymentId::parse(bad).expect_err("invalid deployment id rejected");
            GenerationId::parse(bad).expect_err("invalid generation id rejected");
            OperationId::parse(bad).expect_err("invalid operation id rejected");
        }
        // A valid uuid under the WRONG prefix is rejected for that type.
        let u = test_uuid_v7("x");
        DeploymentId::parse(&format!("gen-{u}")).expect_err("wrong prefix rejected");
        GenerationId::parse(&format!("deploy-{u}")).expect_err("wrong prefix rejected");
        OperationId::parse(&format!("deploy-{u}")).expect_err("wrong prefix rejected");
    }

    /// The digest identities require exactly 64 lowercase hex characters.
    #[test]
    fn digests_require_64_lowercase_hex() {
        let d = test_tree_digest("ok");
        assert_eq!(TreeDigest::parse(d.as_str()).expect("canonical"), d);
        assert_eq!(
            ReleaseDigest::parse(d.as_str()).expect("canonical"),
            ReleaseDigest::parse(d.as_str()).expect("canonical")
        );
        for bad in [
            "",
            "abc",
            &DIGEST.to_uppercase(),
            &format!("sha256-{DIGEST}"),
            &format!("{DIGEST}ff"),
            &DIGEST[..63],
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            TreeDigest::parse(bad).expect_err("invalid tree digest rejected");
            ReleaseDigest::parse(bad).expect_err("invalid release digest rejected");
        }
    }

    /// The segment identities require a single safe path segment.
    #[test]
    fn segment_ids_require_safe_single_segment() {
        for ok in [
            "p1",
            "s1",
            "standard",
            "production",
            "wave-1",
            "α",
            "a..b",
            "a.b",
        ] {
            assert!(ServerId::parse(ok).is_ok(), "{ok:?}");
            assert!(SlotId::parse(ok).is_ok(), "{ok:?}");
            assert!(TargetName::parse(ok).is_ok(), "{ok:?}");
            assert!(RolloutGroupName::parse(ok).is_ok(), "{ok:?}");
            assert!(VariantName::parse(ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "", "   ", " x", "x ", "\u{0}", "a\nb", "a/b", "a\\b", ".", "..", "../x", "x/..",
        ] {
            ServerId::parse(bad).expect_err("invalid server id rejected");
            SlotId::parse(bad).expect_err("invalid slot id rejected");
            TargetName::parse(bad).expect_err("invalid target name rejected");
            RolloutGroupName::parse(bad).expect_err("invalid group name rejected");
            VariantName::parse(bad).expect_err("invalid variant name rejected");
        }
    }

    /// Wire strings go through the validated parse: an invalid wire identity
    /// fails deserialization, a valid one round-trips.
    #[test]
    fn deserialize_validates_wire_strings() {
        let dep = test_deployment_id("wire");
        let json = serde_json::to_string(&dep).expect("serializes");
        assert_eq!(
            serde_json::from_str::<DeploymentId>(&json).expect("valid wire parses"),
            dep
        );
        for bad in [
            "\"\"",
            "\"deploy-1\"",
            "\"gen-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5b6\"",
            "\"p1/..\"",
        ] {
            serde_json::from_str::<DeploymentId>(bad).expect_err("invalid wire rejected");
        }
        serde_json::from_str::<SlotId>("\"p1\"").expect("valid slot wire parses");
        serde_json::from_str::<SlotId>("\"../x\"").expect_err("traversal wire rejected");
        serde_json::from_str::<TreeDigest>(&format!("\"{DIGEST}\""))
            .expect("valid digest wire parses");
        serde_json::from_str::<TreeDigest>("\"t1\"").expect_err("short digest wire rejected");
    }

    // -------------------------------------------------------------------
    // THE IDENTITY PROPERTY: over ARBITRARY strings (empty, whitespace,
    // separators, wrong prefixes, wrong hex, unicode, control characters),
    // each identity's parse accepts EXACTLY its format-valid values and
    // rejects everything else, and a wire string that fails the parse fails
    // deserialization. Bounded 16 cases, fixed seed 0x5EED_5EED per house
    // style.
    // -------------------------------------------------------------------

    /// The independent characterization of the uuid-v7 id rule: the exact
    /// canonical hyphenated UUIDv7 shape under the prefix.
    fn is_valid_uuid_v7_id(s: &str, prefix: &str) -> bool {
        let Some(rest) = s.strip_prefix(prefix) else {
            return false;
        };
        let b = rest.as_bytes();
        b.len() == 36
            && b[8] == b'-'
            && b[13] == b'-'
            && b[18] == b'-'
            && b[23] == b'-'
            && b[14] == b'7'
            && matches!(b[19], b'8' | b'9' | b'a' | b'b')
            && b.iter()
                .enumerate()
                .all(|(i, c)| matches!(i, 8 | 13 | 18 | 23) || c.is_ascii_hexdigit())
    }

    fn is_valid_hex_digest(s: &str) -> bool {
        s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }

    fn is_safe_segment(s: &str) -> bool {
        !s.is_empty()
            && s.trim() == s
            && !s.chars().any(|c| c.is_control())
            && !s.contains('/')
            && !s.contains('\\')
            && s != "."
            && s != ".."
    }

    /// Arbitrary identity strings covering every invalid class: empty,
    /// whitespace, separators, wrong prefixes, malformed uuids, wrong hex,
    /// unicode, control characters, and clean canonical values.
    fn arbitrary_identity_text() -> impl Strategy<Value = String> {
        let u = test_uuid_v7("prop");
        prop_oneof![
            prop::sample::select(vec![
                String::new(),
                " ".to_string(),
                "deploy-".to_string(),
                "gen-".to_string(),
                "op-".to_string(),
                "deploy".to_string(),
                format!("deploy-{u}"),
                format!("gen-{u}"),
                format!("op-{u}"),
                format!("deploy-{}", u.to_uppercase()),
                "deploy-0192a3b4c5d6e7f8a9b0c1d2e3f4a5b6".to_string(),
                "deploy-0192a3b4-c5d6-4e7f-8a9b-0c1d2e3f4a5b6".to_string(),
                "deploy-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5b6 ".to_string(),
                " deploy-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5b6".to_string(),
                "deploy-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5b6x".to_string(),
                "t1".to_string(),
                "tree-1".to_string(),
                "abc123".to_string(),
                DIGEST.to_string(),
                format!("sha256-{DIGEST}"),
                DIGEST.to_uppercase(),
                "p1".to_string(),
                "s1".to_string(),
                "standard".to_string(),
                "a/b".to_string(),
                "a\\b".to_string(),
                "..".to_string(),
                ".".to_string(),
                "../x".to_string(),
                " x".to_string(),
                "x ".to_string(),
                "\u{0}".to_string(),
                "a\nb".to_string(),
                "α".to_string(),
            ]),
            prop::collection::vec(prop::char::any(), 0..48).prop_map(|v| v.into_iter().collect()),
        ]
    }

    proptest! {
        // THE PROPERTY: each identity's parse accepts EXACTLY its
        // format-valid values — every invalid class (empty, whitespace,
        // separators, wrong prefixes, wrong hex, unicode, control chars) is
        // rejected, every canonical value is accepted — and a wire string
        // that fails the parse fails deserialization. Bounded 16 cases,
        // fixed seed 0x5EED_5EED (house style), no failure persistence.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn identity_parses_accept_exactly_format_valid_values(s in arbitrary_identity_text()) {
            let expected_dep = is_valid_uuid_v7_id(&s, "deploy-");
            let expected_gen = is_valid_uuid_v7_id(&s, "gen-");
            let expected_op = is_valid_uuid_v7_id(&s, "op-");
            let expected_digest = is_valid_hex_digest(&s);
            let expected_segment = is_safe_segment(&s);
            assert_eq!(
                DeploymentId::parse(&s).is_ok(),
                expected_dep,
                "DeploymentId: {s:?}"
            );
            assert_eq!(
                GenerationId::parse(&s).is_ok(),
                expected_gen,
                "GenerationId: {s:?}"
            );
            assert_eq!(
                OperationId::parse(&s).is_ok(),
                expected_op,
                "OperationId: {s:?}"
            );
            assert_eq!(
                TreeDigest::parse(&s).is_ok(),
                expected_digest,
                "TreeDigest: {s:?}"
            );
            assert_eq!(
                ReleaseDigest::parse(&s).is_ok(),
                expected_digest,
                "ReleaseDigest: {s:?}"
            );
            assert_eq!(
                ServerId::parse(&s).is_ok(),
                expected_segment,
                "ServerId: {s:?}"
            );
            assert_eq!(
                SlotId::parse(&s).is_ok(),
                expected_segment,
                "SlotId: {s:?}"
            );
            assert_eq!(
                TargetName::parse(&s).is_ok(),
                expected_segment,
                "TargetName: {s:?}"
            );
            assert_eq!(
                RolloutGroupName::parse(&s).is_ok(),
                expected_segment,
                "RolloutGroupName: {s:?}"
            );
            assert_eq!(
                VariantName::parse(&s).is_ok(),
                expected_segment,
                "VariantName: {s:?}"
            );
            // A wire string that fails the parse fails deserialization.
            let json = serde_json::to_string(&s).expect("string serializes");
            assert_eq!(
                serde_json::from_str::<DeploymentId>(&json).is_ok(),
                expected_dep,
                "DeploymentId wire: {s:?}"
            );
            assert_eq!(
                serde_json::from_str::<TreeDigest>(&json).is_ok(),
                expected_digest,
                "TreeDigest wire: {s:?}"
            );
            assert_eq!(
                serde_json::from_str::<SlotId>(&json).is_ok(),
                expected_segment,
                "SlotId wire: {s:?}"
            );
        }
    }
}
