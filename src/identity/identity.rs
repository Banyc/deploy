//! THE IDENTITY TYPES — one cohesive feature: the validated identity and
//! value types that name releases, events, digests, segments, and scalars.
//!
//! * Release ids ([`ReleaseId`]): EXACTLY `rel-sha256-<64 lowercase hex>`;
//!   the loose bare-digest and `rel-` forms are rejected at the domain
//!   boundary (the CLI accepts a bare 64-hex digest, converted first via
//!   [`crate::cli::parse_release_input`]).
//! * Deployment/generation/operation ids ([`DeploymentId`]/
//!   [`GenerationId`]/[`OperationId`]): `deploy-`/`gen-`/`op-` + a canonical
//!   hyphenated UUIDv7 (version nibble enforced; v4 rejected).
//! * Digests ([`TreeDigest`]/[`ReleaseDigest`]): exactly 64 lowercase hex.
//! * Segment ids ([`SlotId`], [`ServerId`], [`TargetName`], [`VariantName`]):
//!   a single safe path segment.
//! * Scalars ([`Identifier`], [`ApplicationStoreKey`], [`BatchSize`],
//!   [`CapacityPercent`], [`AbsoluteDeployDir`], [`BehaviorDigest`],
//!   [`Timestamp`], [`RolloutGroupName`], [`Host`], [`SshUser`]): the
//!   validated scalar value types.
//!
//! Deployment, operation, and generation IDs are opaque collision-resistant
//! IDs (UUIDv7 in schema version 1). They identify events and are never used
//! as content identity.
//!
//! Identities deliberately carry NO `Default` (an empty identity would be a
//! malformed durable record constructible by anyone — the exact gap this
//! hardening closes). An identity can only be built through the validated
//! [`parse`]-style constructors (`parse` / `FromStr` / `TryFrom`); the serde
//! `Deserialize` impls route every wire string through the same validation
//! (an invalid wire identity fails deserialization — fail closed).

use super::id_newtype;
use crate::error::{Error, Result};
use jiff::Timestamp as JiffTimestamp;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use uuid::Uuid;

// ---- release ids ----

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
        ReleaseId(format!("rel-sha256-{}", d.as_str()))
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
        ReleaseDigest::from_validated_string(self.0.trim_start_matches("rel-sha256-").to_string())
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

/// A deterministic canonical `rel-sha256-<64-hex>` release id derived from a
/// tag (the canonical form [`ReleaseId::from_digest`] produces — the only
/// form the strict [`ReleaseId::parse`] accepts).
#[cfg(test)]
pub(crate) fn test_release_id(tag: &str) -> ReleaseId {
    ReleaseId::from_digest(
        &ReleaseDigest::parse(&test_sha256_hex(tag)).expect("canonical test digest"),
    )
}

// ---- deployment/generation/operation ids ----

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

// ---- digests ----

/// A valid sha256 digest: exactly 64 lowercase hex characters (the exact form
/// [`crate::digest::sha256_bytes`] produces). Any other string — empty, short,
/// long, uppercase, non-hex, or prefixed — is rejected.
pub(crate) fn valid_hex_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

id_newtype!(
    ReleaseDigest,
    valid_hex_digest,
    "A release digest: exactly 64 lowercase hex characters (sha256) — the \
     exact form [`crate::digest::sha256_bytes`] produces."
);

id_newtype!(
    TreeDigest,
    valid_hex_digest,
    "A tree digest: exactly 64 lowercase hex characters (sha256) — the exact \
     form [`crate::digest::sha256_bytes`] produces."
);

impl ReleaseDigest {
    /// Raw constructor from an ALREADY-VALIDATED digest string — identity
    /// internal only: [`ReleaseId::digest`]
    /// rebuilds the digest from a string stripped off a valid release id
    /// (which is, by construction, exactly 64 lowercase hex). Production
    /// code must construct through the validated [`parse`].
    pub(crate) fn from_validated_string(s: String) -> Self {
        ReleaseDigest(s)
    }
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

// ---- segment ids ----

id_newtype!(
    ServerId,
    valid_name,
    "A server identity: a single safe path segment (non-empty, no path \
     separators or traversal components, no surrounding whitespace or control \
     characters) — the shared segment rule from [`crate::identity`]."
);
id_newtype!(
    SlotId,
    valid_name,
    "A slot identity: a single safe path segment (the shared \
     segment rule from [`crate::identity`])."
);
id_newtype!(
    TargetName,
    valid_name,
    "A target name: a single safe path segment (the shared segment rule \
     from [`crate::identity`])."
);
id_newtype!(
    VariantName,
    valid_name,
    "A variant name: a single safe path segment (the shared segment rule \
     from [`crate::identity`])."
);

// ---- scalars ----

/// A valid 64-lowercase-hex sha256 digest, shared by test fixtures that need
/// a well-formed behavior digest.
#[cfg(test)]
pub(crate) const DIGEST_TEST_HEX_1: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The name rule shared by the identifier-like scalars AND the identity
/// newtypes in this module (ServerId, SlotId, TargetName,
/// VariantName): non-empty after trimming, no surrounding
/// whitespace (a name is exactly what was written, never silently trimmed),
/// no control characters, and no path separators or traversal components — a
/// name is a SINGLE safe path segment. Names become directory components on a
/// server (the per-server remote directory is named by the server id), so a
/// name must never smuggle a separator (`/`, `\`) or a `.`/`..` traversal
/// component out of the forced namespace.
pub(crate) fn valid_name(s: &str) -> bool {
    !s.trim().is_empty()
        && s.trim() == s
        && !s.chars().any(|c| c.is_control())
        && !s.contains('/')
        && !s.contains('\\')
        && s != "."
        && s != ".."
}

macro_rules! name_scalar {
    ($name:ident, $doc:expr, $rule:expr) => {
        #[doc = $doc]
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// Validate `s` and construct the scalar. The invariant is
            /// enforced HERE: any invalid value is rejected before a value
            /// of this type can exist.
            pub fn parse(s: &str) -> Result<$name> {
                if !$rule(s) {
                    return Err(Error::config(format!(
                        "invalid {} value {:?}",
                        stringify!($name),
                        s
                    )));
                }
                Ok($name(s.to_string()))
            }

            /// The validated value.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = Error;
            fn from_str(s: &str) -> Result<$name> {
                $name::parse(s)
            }
        }
    };
}

impl AsRef<std::path::Path> for Identifier {
    /// Identifiers are used directly as filesystem path segments (the
    /// per-server remote directory is named by the server id), so a
    /// validated identifier doubles as a path segment.
    fn as_ref(&self) -> &std::path::Path {
        std::path::Path::new(&self.0)
    }
}

name_scalar!(
    Identifier,
    "A validated identifier (a server, slot, target, or variant name): \
     non-empty, no surrounding whitespace, no control characters. Used for \
     the id-bearing domain fields that have no dedicated id type; fields \
     with a dedicated type (DeploymentId, SlotId, ServerId, \
     ReleaseId, ...) keep it.",
    valid_name
);

name_scalar!(
    Host,
    "A validated SSH host: the address of an SSH server. Non-empty, no \
    surrounding whitespace, no control characters, and no path separators or \
    traversal components — a host is a single safe token (a DNS name, an IP, \
    or a bracketed IPv6 literal), never a path. The `local://` endpoint form \
    is NOT a host: it is the separate [`crate::config::ServerConnection::Local`] \
    connection form, so a host can never smuggle a path out of the SSH \
    namespace.",
    valid_name
);

name_scalar!(
    SshUser,
    "A validated SSH deployment account: the `user` of an SSH connection. \
    Non-empty, no surrounding whitespace, no control characters, and no path \
    separators or traversal components — a user is a single safe token, never \
    a path.",
    valid_name
);

name_scalar!(
    ApplicationStoreKey,
    "The application identifier: THE single safe name from the config's \
    `application` field, used for BOTH display (messages and rendering) and \
    storage (the single filesystem component that names the application's \
    local store directory, `<data>/simple-deploy/<key>`). EXACTLY ONE \
    NORMAL FILESYSTEM COMPONENT: non-empty, no `/` or `\\`, not `.`/`..`, \
    no surrounding whitespace or control characters — the same \
    single-safe-segment rule as the other path-segment scalars. The store \
    path is built ONLY from a validated key ([`crate::store::local::LocalStore::new`] \
    takes the key, never a raw string), so an application name can never \
    escape the store base.",
    valid_name
);

impl AsRef<std::path::Path> for ApplicationStoreKey {
    /// The store key is used directly as the single filesystem component of
    /// the store path (`<data>/simple-deploy/<key>`), so a validated store
    /// key doubles as a path segment.
    fn as_ref(&self) -> &std::path::Path {
        std::path::Path::new(&self.0)
    }
}

name_scalar!(
    RolloutGroupName,
    "A rollout group name, validated per the config rules: non-empty and \
    well-formed (no surrounding whitespace, no control characters). \
    DUPLICATE group names are a separate STRUCTURAL rule enforced by the \
    config conversion (a duplicate adds no membership yet would change the \
    release identity), not by this scalar.",
    valid_name
);

/// A sha256 behavior digest: exactly 64 lowercase hex characters (the exact
/// form [`crate::digest::sha256_bytes`] produces). Any other string — empty,
/// short, long, uppercase, non-hex, or prefixed — is rejected.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BehaviorDigest(String);

impl BehaviorDigest {
    /// Validate `s` as a sha256 digest and construct a [`BehaviorDigest`].
    pub fn parse(s: &str) -> Result<BehaviorDigest> {
        let ok = s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !ok {
            return Err(Error::config(format!(
                "invalid behavior digest {:?}: expected 64 lowercase hex characters",
                s
            )));
        }
        Ok(BehaviorDigest(s.to_string()))
    }

    /// The validated digest.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BehaviorDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for BehaviorDigest {
    type Err = Error;
    fn from_str(s: &str) -> Result<BehaviorDigest> {
        BehaviorDigest::parse(s)
    }
}

/// An ABSOLUTE on-server directory. Construction requires an absolute,
/// TRAVERSAL-FREE path with AT LEAST ONE NORMAL COMPONENT below the root:
/// a relative or empty path is rejected (the scheduler never deploys into a
/// location relative to an unspecified working directory), so is ANY path
/// with a `.` or `..` component at any position (a traversal component
/// could escape the intended namespace), and so is the FILESYSTEM ROOT
/// itself (`/`, or any form that normalizes to it — `//`, `/./`, `/../`) —
/// a deploy_dir of `/` would make the deployment cleanup (rotation/
/// retention deleting stale generations, the GC sweep) operate on the
/// system root. The canonical form is NORMALIZED: rebuilt from the path
/// components, so doubled separators and a trailing slash are folded away.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AbsoluteDeployDir(std::path::PathBuf);

impl AbsoluteDeployDir {
    /// Validate that `s` is an absolute, traversal-free path with at least
    /// one normal component below the root, and construct an
    /// [`AbsoluteDeployDir`] holding the normalized canonical form.
    pub fn parse(s: &str) -> Result<AbsoluteDeployDir> {
        let path = Path::new(s);
        if !path.is_absolute() {
            return Err(Error::config(format!(
                "invalid deploy_dir {:?}: must be an absolute path on the server",
                s
            )));
        }
        // Reject ANY traversal component (`.` or `..`) at ANY position, then
        // rebuild the canonical form from the raw `/`-separated segments
        // (empty segments — doubled separators, a trailing slash — are
        // normalized away). `Path::components()` skips `.` segments, so the
        // raw split is used to catch them.
        let mut canonical = std::path::PathBuf::from("/");
        let mut normal_components = 0usize;
        for segment in s.split('/') {
            match segment {
                "" => {}
                "." | ".." => {
                    return Err(Error::config(format!(
                        "invalid deploy_dir {:?}: traversal components (`.`/`..`) are not allowed",
                        s
                    )));
                }
                _ => {
                    canonical.push(segment);
                    normal_components += 1;
                }
            }
        }
        // The FILESYSTEM ROOT is rejected: a deploy_dir of `/` (or any form
        // that normalizes to it — `//`, `/./`, `/../`) would make the
        // deployment cleanup (rotation/retention deleting stale generations,
        // the GC sweep) operate on the system root. The deploy_dir must have
        // at least one normal path component below the root.
        if normal_components == 0 {
            return Err(Error::config(format!(
                "invalid deploy_dir {:?}: the deploy_dir must have at least one normal path component below the root",
                s
            )));
        }
        Ok(AbsoluteDeployDir(canonical))
    }

    /// The validated absolute path.
    pub fn as_path(&self) -> &std::path::Path {
        &self.0
    }
}

impl fmt::Display for AbsoluteDeployDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_string_lossy())
    }
}

impl FromStr for AbsoluteDeployDir {
    type Err = Error;
    fn from_str(s: &str) -> Result<AbsoluteDeployDir> {
        AbsoluteDeployDir::parse(s)
    }
}

/// A NONZERO rollout batch size: how many slots a target advances per
/// rollout batch. Zero is rejected — a zero batch would stall the rollout
/// without ever progressing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BatchSize(u64);

impl BatchSize {
    /// Construct a batch size, rejecting zero (the only invalid value).
    pub fn new(v: u64) -> Result<BatchSize> {
        if v == 0 {
            return Err(Error::config(
                "invalid batch size 0: a rollout batch must advance at least one slot",
            ));
        }
        Ok(BatchSize(v))
    }

    /// The nonzero batch size.
    pub fn get(&self) -> u64 {
        self.0
    }
}

impl Default for BatchSize {
    fn default() -> Self {
        BatchSize(1)
    }
}

impl fmt::Display for BatchSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for BatchSize {
    type Err = Error;
    fn from_str(s: &str) -> Result<BatchSize> {
        let v: u64 = s.parse().map_err(|_| {
            Error::config(format!(
                "invalid batch size {s:?}: expected a nonzero integer"
            ))
        })?;
        BatchSize::new(v)
    }
}

/// A validated capacity percentage: the percent of the destination
/// filesystem's TOTAL size a deployment must keep free (0..=100).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct CapacityPercent(u8);

impl CapacityPercent {
    /// Construct a capacity percent, rejecting any value outside 0..=100.
    pub fn new(v: u8) -> Result<CapacityPercent> {
        if v > 100 {
            return Err(Error::config(format!(
                "invalid capacity percent {v}: must be within 0..=100"
            )));
        }
        Ok(CapacityPercent(v))
    }

    /// The validated percentage (0..=100).
    pub fn get(&self) -> u8 {
        self.0
    }
}

impl fmt::Display for CapacityPercent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for CapacityPercent {
    type Err = Error;
    fn from_str(s: &str) -> Result<CapacityPercent> {
        let v: u8 = s.parse().map_err(|_| {
            Error::config(format!(
                "invalid capacity percent {s:?}: expected an integer"
            ))
        })?;
        CapacityPercent::new(v)
    }
}

/// A parsed RFC3339 timestamp ([`jiff::Timestamp`]): the canonical form for
/// every recorded moment (`attempted_at`, `recorded_at`). Construction
/// parses the string strictly, so an unparseable timestamp can never enter
/// the domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Timestamp(JiffTimestamp);

impl Timestamp {
    /// Parse `s` as an RFC3339 timestamp and construct a [`Timestamp`].
    /// Uses the merged jiff parser (`jiff::Timestamp::from_str`), so any
    /// RFC3339 form — `2026-01-01T00:00:00Z`, offsets, fractional seconds —
    /// is accepted and anything else is rejected.
    pub fn parse(s: &str) -> Result<Timestamp> {
        let t = JiffTimestamp::from_str(s)
            .map_err(|_| Error::config(format!("invalid RFC3339 timestamp {s:?}")))?;
        Ok(Timestamp(t))
    }

    /// The parsed jiff timestamp.
    pub fn inner(&self) -> &JiffTimestamp {
        &self.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Timestamp {
    type Err = Error;
    fn from_str(s: &str) -> Result<Timestamp> {
        Timestamp::parse(s)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::remote::transport::LocalTransport;
    use crate::store::local::{LocalStore, default_base};
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

    #[test]
    fn identifier_accepts_valid_rejects_invalid() {
        for ok in ["s1", "production", "wave-1", "α", "x y", "a", "a..b", "a.b"] {
            let id = Identifier::parse(ok).expect("valid identifier parses");
            assert_eq!(id.as_str(), ok);
            assert_eq!(id.to_string(), ok);
            assert_eq!(ok.parse::<Identifier>().expect("from_str"), id);
        }
        for bad in [
            "", "   ", " x", "x ", "\u{0}", "a\nb", "a/b", "a\\b", ".", "..", "../x", "x/..",
        ] {
            Identifier::parse(bad).expect_err("invalid identifier must be rejected");
            assert!(bad.parse::<Identifier>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn application_store_key_requires_safe_single_segment() {
        for ok in ["app", "my app", "α", "a..b"] {
            let name = ApplicationStoreKey::parse(ok).expect("safe name parses");
            assert_eq!(name.as_str(), ok);
        }
        for bad in [
            "", "   ", "\n", " x", "x ", "a/b", "a\\b", ".", "..", "\u{0}",
        ] {
            ApplicationStoreKey::parse(bad).expect_err("unsafe application store key rejected");
        }
    }

    #[test]
    fn rollout_group_name_accepts_valid_rejects_invalid() {
        for ok in ["canary", "wave-1", "α", "a..b"] {
            let g = RolloutGroupName::parse(ok).expect("valid group parses");
            assert_eq!(g.as_str(), ok);
        }
        for bad in [
            "", "   ", " x", "x ", "\u{0}", "a/b", "a\\b", ".", "..", "../x",
        ] {
            RolloutGroupName::parse(bad).expect_err("invalid group name rejected");
        }
    }

    #[test]
    fn behavior_digest_requires_64_lowercase_hex() {
        let d = BehaviorDigest::parse(DIGEST).expect("64 lowercase hex parses");
        assert_eq!(d.as_str(), DIGEST);
        assert_eq!(d.to_string(), DIGEST);
        // Every invalid class: wrong length, uppercase, non-hex, empty,
        // prefixed.
        for bad in [
            "",
            DIGEST.trim_end_matches('5'),
            &format!("{DIGEST}ff"),
            &DIGEST.to_uppercase(),
            &format!("sha256-{DIGEST}"),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", // 65
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            BehaviorDigest::parse(bad).expect_err("invalid digest rejected");
        }
    }

    #[test]
    fn absolute_deploy_dir_requires_absolute_traversal_free_path() {
        for ok in ["/srv/p1", "/srv", "/srv/deploy/app"] {
            let d = AbsoluteDeployDir::parse(ok).expect("absolute path parses");
            assert!(d.as_path().is_absolute());
            assert_eq!(d.as_path(), std::path::Path::new(ok));
        }
        // A trailing slash is harmless but normalized away; the canonical
        // form is a parse fixed point.
        let d = AbsoluteDeployDir::parse("/srv/").expect("trailing slash normalizes");
        assert_eq!(d.as_path(), std::path::Path::new("/srv"));
        assert_eq!(
            AbsoluteDeployDir::parse("/srv").expect("canonical re-parses"),
            d
        );
        let d = AbsoluteDeployDir::parse("/srv/app/").expect("trailing slash normalizes");
        assert_eq!(d.as_path(), std::path::Path::new("/srv/app"));
        for bad in [
            "",
            "srv/p1",
            "relative",
            "./x",
            "../x",
            "/srv/../etc",
            "/srv/./x",
            "/../etc",
            "/etc/..",
            "/./x",
            "/srv/..",
            // The filesystem root (and any form that normalizes to it) is
            // rejected: a deploy_dir must have at least one normal
            // component below the root, so deployment cleanup can never
            // operate on `/`.
            "/",
            "//",
            "/./",
            "/../",
        ] {
            AbsoluteDeployDir::parse(bad)
                .expect_err("traversal, relative, or root deploy_dir rejected");
        }
    }

    #[test]
    fn batch_size_requires_nonzero() {
        for ok in [1u64, 42, u64::MAX] {
            let b = BatchSize::new(ok).expect("nonzero batch parses");
            assert_eq!(b.get(), ok);
            assert_eq!(ok.to_string().parse::<BatchSize>().expect("valid"), b);
        }
        assert_eq!(BatchSize::default().get(), 1);
        for bad in ["0", "-1", "abc"] {
            assert!(bad.parse::<BatchSize>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn capacity_percent_requires_0_to_100() {
        for ok in [0u8, 42, 100] {
            let c = CapacityPercent::new(ok).expect("in-range percent parses");
            assert_eq!(c.get(), ok);
            assert_eq!(ok.to_string().parse::<CapacityPercent>().expect("valid"), c);
        }
        assert_eq!(CapacityPercent::default().get(), 0);
        for bad in [101u8, 200, u8::MAX] {
            CapacityPercent::new(bad).expect_err("out-of-range percent rejected");
        }
        for bad in ["101", "-1", "abc"] {
            assert!(bad.parse::<CapacityPercent>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn timestamp_parses_rfc3339_and_rejects_invalid() {
        for ok in [
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00.123+02:00",
            "2024-02-29T12:00:00Z",
        ] {
            let t = Timestamp::parse(ok).expect("RFC3339 parses");
            // jiff normalizes offset forms to their canonical UTC instant;
            // the canonical form must itself re-parse (round-trip stable).
            let canonical = t.inner().to_string();
            Timestamp::parse(&canonical).expect("canonical form re-parses");
        }
        for bad in [
            "",
            "yesterday",
            "2026-01-01",
            "2026-01-01T00:00:00",
            "not-a-time",
            "2026-13-01T00:00:00Z",
        ] {
            Timestamp::parse(bad).expect_err("unparseable timestamp rejected");
        }
    }

    // -------------------------------------------------------------------
    // THE TRAVERSAL PROPERTY: over ARBITRARY name/path values (with `..`,
    // `.`, `/`, `\`, empty, whitespace, control characters, unicode, and
    // absolute/relative mixes), each scalar accepts EXACTLY the
    // traversal-free, single-segment values and rejects everything else.
    // Bounded 16 cases, fixed seed 0x5EED_5EED per house style.
    // -------------------------------------------------------------------

    /// Arbitrary name/path-segment values covering every traversal class:
    /// `..`, `.`, `/`, `\`, empty, whitespace, control characters, unicode,
    /// and clean single segments.
    fn arbitrary_segment_text() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(vec![
                String::new(),
                ".".to_string(),
                "..".to_string(),
                "...".to_string(),
                "/".to_string(),
                "\\".to_string(),
                "a/b".to_string(),
                "a\\b".to_string(),
                "../x".to_string(),
                "x/..".to_string(),
                "./x".to_string(),
                "x/.".to_string(),
                " x".to_string(),
                "x ".to_string(),
                "x y".to_string(),
                "\u{0}".to_string(),
                "a\nb".to_string(),
                "α".to_string(),
                "s1".to_string(),
                "wave-1".to_string(),
                "a..b".to_string(),
                "a.b".to_string(),
            ]),
            prop::collection::vec(prop::char::any(), 0..12).prop_map(|v| v.into_iter().collect()),
        ]
    }

    proptest! {
        // THE PROPERTY: the three name scalars (Identifier, RolloutGroupName,
        // ApplicationStoreKey) accept EXACTLY the safe single-segment values —
        // every traversal class (`..`, `.`, `/`, `\`, padding, control
        // chars) is rejected, every clean single segment is accepted.
        // Bounded 16 cases, fixed seed 0x5EED_5EED (house style), no
        // failure persistence — the identical vectors on every run.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn name_scalars_accept_exactly_safe_single_segments(s in arbitrary_segment_text()) {
            let expected = is_safe_segment(&s);
            assert_eq!(
                Identifier::parse(&s).is_ok(),
                expected,
                "Identifier must accept exactly safe single segments: {s:?}"
            );
            assert_eq!(
                RolloutGroupName::parse(&s).is_ok(),
                expected,
                "RolloutGroupName must accept exactly safe single segments: {s:?}"
            );
            assert_eq!(
                ApplicationStoreKey::parse(&s).is_ok(),
                expected,
                "ApplicationStoreKey must accept exactly safe single segments: {s:?}"
            );
        }
    }

    // -------------------------------------------------------------------
    // THE STORE-KEY PROPERTY: over ARBITRARY application-name strings (with
    // `/`, `\`, `..`, `.`, empty, whitespace, unicode, and control
    // characters), the store-key parse accepts EXACTLY the single-normal-
    // component values; `LocalStore::new` with a valid key places the store
    // under `<base>/<key>/` (exactly ONE component appended). The key IS
    // the config's application identifier (one safe name for display and
    // storage), so an unsafe application name can never reach the store
    // construction. Bounded 16 cases, fixed seed 0x5EED_5EED per house
    // style.
    // -------------------------------------------------------------------

    #[test]
    fn store_key_property_places_store_under_base_plus_single_component() {
        // The property constructs REAL stores via `LocalStore::new`, so the
        // process-global `$TMPDIR` is pointed at a hermetic temp root
        // for the whole run (ENV_LOCK serializes against every other
        // env-mutating test; the closure-form proptest runs all 16 cases in
        // this thread).
        let _lock = crate::testutil::ENV_LOCK.lock().unwrap();
        let store_root = crate::testutil::hermetic_tmpdir_root();
        unsafe { std::env::set_var("TMPDIR", &store_root) };
        proptest!(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        }, |(s in arbitrary_segment_text())| {
            let expected = is_safe_segment(&s);
            assert_eq!(
                ApplicationStoreKey::parse(&s).is_ok(),
                expected,
                "ApplicationStoreKey must accept exactly safe single segments: {s:?}"
            );
            if let Ok(key) = ApplicationStoreKey::parse(&s) {
                // The store path is default_base().join(key): EXACTLY ONE
                // component appended — the key is a single safe segment, so
                // the store can never escape the base. A safe-but-
                // filesystem-incompatible key (a character the local
                // filesystem refuses, e.g. some unicode) fails the store
                // open with a STORE error — fail closed, never an escape.
                match LocalStore::new(&key) {
                    Ok(store) => {
                        assert_eq!(
                            store.base().parent(),
                            Some(default_base().as_path()),
                            "the store must sit directly under the base: {s:?}"
                        );
                        assert_eq!(
                            store.base().file_name(),
                            Some(std::ffi::OsStr::new(key.as_str())),
                            "exactly one component (the key) is appended: {s:?}"
                        );
                    }
                    Err(e) => assert!(
                        matches!(e, Error::Store(_)),
                        "a safe key's store open failure must be a store error, never an escape: {e}"
                    ),
                }
            }
        });
        unsafe { std::env::remove_var("TMPDIR") };
        let _ = std::fs::remove_dir_all(store_root.join("deploy-test"));
    }

    /// The independent characterization of the deploy_dir rule: an absolute
    /// path whose every non-empty `/`-separated segment is a normal name
    /// (no `.`/`..` component at any position) AND that has at least one
    /// normal component below the root (the filesystem root itself is not a
    /// valid deploy_dir — deployment cleanup must never operate on `/`).
    fn is_valid_deploy_dir(s: &str) -> bool {
        Path::new(s).is_absolute()
            && s.split('/')
                .all(|seg| seg.is_empty() || (seg != "." && seg != ".."))
            && s.split('/')
                .any(|seg| !seg.is_empty() && seg != "." && seg != "..")
    }

    /// Arbitrary path values covering every traversal class: absolute with
    /// `..`/`.` at any position, doubled separators, trailing slashes, the
    /// root, relative paths, empty, whitespace, and unicode.
    fn arbitrary_path_text() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(vec![
                "/srv/p1".to_string(),
                "/".to_string(),
                "//".to_string(),
                "/./".to_string(),
                "/../".to_string(),
                "/srv/".to_string(),
                "//srv//deploy//".to_string(),
                "/srv/../etc".to_string(),
                "/srv/./x".to_string(),
                "/../etc".to_string(),
                "/etc/..".to_string(),
                "/./x".to_string(),
                "/srv/..".to_string(),
                "/srv/deploy/app".to_string(),
                "srv/p1".to_string(),
                "relative".to_string(),
                "./x".to_string(),
                "../x".to_string(),
                String::new(),
                " ".to_string(),
            ]),
            prop::collection::vec(prop::char::any(), 0..12).prop_map(|v| v.into_iter().collect()),
        ]
    }

    proptest! {
        // THE PROPERTY: AbsoluteDeployDir accepts EXACTLY the
        // traversal-free absolute paths with at least one normal component
        // below the root — every `.`/`..` component at any position, every
        // relative/empty path, and the filesystem root itself (including
        // forms that normalize to it) are rejected, and the accepted
        // canonical form is normalized (no trailing slash, no doubled
        // separators) and a parse fixed point. The transport construction
        // refuses the root too (defense in depth). Bounded 16 cases, fixed
        // seed 0x5EED_5EED (house style), no failure persistence — the
        // identical vectors on every run.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn absolute_deploy_dir_accepts_exactly_traversal_free_absolute_paths(
            s in arbitrary_path_text(),
        ) {
            let expected = is_valid_deploy_dir(&s);
            assert_eq!(
                AbsoluteDeployDir::parse(&s).is_ok(),
                expected,
                "AbsoluteDeployDir must accept exactly traversal-free absolute paths with ≥1 normal component below the root: {s:?}"
            );
            if let Ok(dir) = AbsoluteDeployDir::parse(&s) {
                let canonical = dir.as_path().to_string_lossy();
                assert!(
                    !canonical.ends_with('/'),
                    "canonical form must not carry a trailing slash: {canonical:?}"
                );
                assert_eq!(
                    AbsoluteDeployDir::parse(&canonical).expect("canonical form re-parses"),
                    dir,
                    "the canonical form must be a parse fixed point: {canonical:?}"
                );
            }
            // Defense in depth: the transport construction refuses the root
            // too — a transport whose root has no normal component below
            // the root (the filesystem root) can never be built, so
            // deployment cleanup can never operate on `/` even if the
            // scalar check were bypassed.
            let root_only = !Path::new(&s)
                .components()
                .any(|c| matches!(c, std::path::Component::Normal(_)));
            assert_eq!(
                LocalTransport::new(std::path::PathBuf::from(&s)).is_ok(),
                !root_only,
                "LocalTransport must refuse a root deploy_dir: {s:?}"
            );
        }
    }
}
