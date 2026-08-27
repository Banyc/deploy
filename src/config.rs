//! Declarative deployment configuration (`deploy.toml`, schema version 1).
//!
//! The config layer is split into TWO layers with a total-fail-closed
//! conversion between them:
//!
//! 1. [`raw`] — the raw SERDE shapes: [`raw::RawConfig`] (the `deploy.toml`
//!    manifest), [`raw::RawServer`] (one `[[servers]]` entry), and
//!    [`raw::RawVariant`] (one variant file). These types hold exactly what
//!    the file says — `known_hosts` and `host_key_fingerprint` as a plain
//!    `Option` pair, activation as a bare `adapter` string — and refuse
//!    unknown fields (`deny_unknown_fields`). They are crate-internal: the
//!    only entry point into a validated configuration is [`ProjectConfig::load`]
//!    (parse -> convert) or the crate-internal conversion
//!    [`ProjectConfig::from_raw_parts`].
//! 2. [`ProjectConfig`] (`DomainConfig`) — the VALIDATED domain model, public but
//!    privately constructed: the conversion performs every validity rule
//!    (identifier validity, reference resolution, exactly-one host identity,
//!    the activation adapter space, mapping collision rules, the schema
//!    version gate), so a hand-built invalid domain is impossible. The
//!    option spaces are typed enums instead of `Option` pairs:
//!    [`Activation`] (`None` | `Systemd(SystemdActivation)`), and
//!    [`HostIdentity`] (`Local` | `KnownHosts(PathBuf)` |
//!    `Fingerprint(Fingerprint)`) — a server's identity is exactly one form
//!    by construction.
//!
//! The project file structure is forced: `deploy.toml` names the active release
//! (`release: <name>`), and every regular `*.toml` file directly inside
//! `<project>/releases/<name>/` is discovered as a variant named by its file
//! stem. Each variant file owns its artifact mappings, its deployment policies
//! (activation, verification), AND its deployment slots: the `[[slots]]`
//! entries of the variant file are the slot declarations, the declaring file
//! is the slot's variant binding, and each slot's `target` field binds it to
//! exactly one top-level target. Artifact sources conventionally live beneath
//! `releases/<name>/artifacts/`. Capacity is a per-server policy declared on
//! the server entry. Servers and targets are declared once at the top level of
//! `deploy.toml`; targets carry ROLLOUT only, and their member slots are
//! DERIVED from the slots' `target` fields. Retention is owned by
//! the SLOT, resolved from the slot's OWNING VARIANT file (the `*.toml` that
//! declares the slot's `[[slots]]` entry) — one policy per slot, never a
//! per-target policy union.
//!
//! The same local inputs always produce one target-independent release identity
//! (see `model::ReleaseDigest`): the name-sorted per-variant mappings, the
//! name-sorted per-variant behavior contracts, the name-sorted per-variant
//! slot declarations (each variant's `[[slots]]` canonicalized and sorted by
//! slot id), and every declared variant's tree binding.

use crate::error::{Error, Result};
use crate::model::{CONFIG_SCHEMA_VERSION, ReleaseId, ServerId, SlotId};
use crate::records::PhysicalBinding;
use crate::scalar::{
    AbsoluteDeployDir, ApplicationStoreKey, BatchSize, CapacityPercent, Host, Identifier,
    RolloutGroupName, SshUser,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::num::NonZeroU16;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use unicode_normalization::UnicodeNormalization;

/// Reject any path that is absolute or contains a parent/root/prefix component,
/// so a mapping destination cannot escape the artifact-relative namespace.
///
/// `PackageRelativePath`/`Mapping.to` values must stay beneath the staging root.
pub fn validate_relative_path(path: &Path) -> Result<()> {
    if path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(Error::path("path must remain artifact-relative"));
    }
    Ok(())
}

/// A mapping's destination-collision policy. Strict semantics: a collision is
/// ALWAYS an error. `keep`/`replace` behavior is intentionally not offered —
/// overlapping destinations are rejected before any staging write, and the
/// staging tree itself is a disposable cache that is cleared and rebuilt, so
/// re-materializing the same push is an idempotent no-op. Because this is the
/// only variant, any other `conflict = "..."` value is rejected at config
/// parse.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicy {
    #[default]
    Error,
}

/// Normalize a mapping destination for comparison: NFC, forward slashes,
/// trailing `/` stripped — a trailing slash only selects the directory-merge
/// semantics, so `app/` and `app` name the same destination tree.
pub fn normalize_destination(to: &str) -> String {
    let s = to.nfc().collect::<String>().replace('\\', "/");
    s.trim_end_matches('/').to_string()
}

/// Whether two mapping destinations overlap: identical, or one is a
/// component-wise prefix of the other (a nested `to` descending into another
/// mapping's `to` tree). An empty destination (the entry lands at the staging
/// root) is a prefix of every destination. Overlapping destinations would make
/// the materialized tree depend on declaration order, so they are rejected.
pub fn destinations_overlap(a: &str, b: &str) -> bool {
    let a_norm = normalize_destination(a);
    let b_norm = normalize_destination(b);
    let ac: Vec<_> = Path::new(&a_norm).components().collect();
    let bc: Vec<_> = Path::new(&b_norm).components().collect();
    let (short, long) = if ac.len() <= bc.len() {
        (&ac, &bc)
    } else {
        (&bc, &ac)
    };
    short == &long[..short.len()]
}

// ---------------------------------------------------------------------------
// Shared leaf types — the well-typed value records both layers use unchanged
// (they have no option-space ambiguity; validation happens at the graph
// level during the raw -> domain conversion).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Mapping {
    /// Source path relative to the release directory (`releases/<release>/`),
    /// where the convention is `artifacts/...`. The path is rendered with the
    /// template module (`crate::template`): `{{ variant }}` is available at
    /// materialization; slot-level variables such as `deploy_dir` are not
    /// (trees are content-addressed and shared across slots) and referencing
    /// them fails loudly.
    pub from: String,
    /// Artifact-relative destination path.
    pub to: String,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub conflict: ConflictPolicy,
    /// `preserve` or an explicit octal mode such as `"0644"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactConfig {
    pub mappings: Vec<Mapping>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnitDef {
    pub name: String,
    pub artifact_path: String,
    #[serde(default = "default_true")]
    pub enable: bool,
    #[serde(default = "default_true")]
    pub restart: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ActivationScope {
    #[default]
    User,
    System,
}

/// The serialized activation-contract shape (adapter name + policy), used as
/// the RAW deserialization shape of a variant's `[activation]` table AND as
/// the canonical contract record carried by release behavior records. The
/// domain model consumes the typed [`Activation`] enum instead; the
/// [`From<Activation>`] conversion always produces the canonical contract.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ActivationConfig {
    #[serde(default = "default_adapter_none")]
    pub adapter: String,
    #[serde(default)]
    pub scope: ActivationScope,
    #[serde(default = "default_true")]
    pub reconcile_managed_units: bool,
    #[serde(default)]
    pub units: Vec<UnitDef>,
}

fn default_adapter_none() -> String {
    "none".to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct VerificationConfig {
    pub adapter: String,
    pub argv: Vec<String>,
    pub timeout_seconds: u64,
    #[serde(default = "default_attempts")]
    pub attempts: u32,
    #[serde(default = "default_interval")]
    pub interval_seconds: u64,
}

fn default_attempts() -> u32 {
    1
}
fn default_interval() -> u64 {
    0
}

/// A server's capacity headroom policy, declared once per `[[servers]]` entry
/// and shared by every deployment slot on that server. It is LIVE
/// configuration resolved from the caller's current `deploy.toml` at preflight
/// time — servers have no per-release history — and it is NOT part of the
/// release identity: changing a server's capacity never produces a new release
/// and never touches any stored snapshot.
///
/// The DOMAIN form: `reserve_percent` is a validated [`CapacityPercent`]
/// (0..=100). Built ONLY by the raw -> domain conversion; the raw
/// serialization shape is [`raw::RawCapacityConfig`] (bare integer percent).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CapacityConfig {
    /// Keep at least this many bytes free on the server after an upload.
    pub reserve_bytes: u64,
    /// Keep at least this percentage of the destination filesystem's TOTAL
    /// size free after an upload (0..=100). A VALIDATED [`CapacityPercent`]:
    /// the raw `reserve_percent` integer is parsed by the raw -> domain
    /// conversion, which rejects any value outside 0..=100, so a domain
    /// capacity percent is in range by construction.
    pub reserve_percent: CapacityPercent,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct PerServerRetention {
    #[serde(default = "default_keep_distinct")]
    pub keep_distinct_artifacts: u32,
    #[serde(default = "default_keep_days")]
    pub keep_days: u64,
    #[serde(default = "default_true")]
    pub protect_previous: bool,
}

fn default_keep_distinct() -> u32 {
    5
}
fn default_keep_days() -> u64 {
    14
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct DeploymentRetention {
    #[serde(default)]
    pub protect_deployments: u32,
}

/// The slot's ONE retention policy: `per_server` (distinct-artifact count,
/// age window, previous protection) plus the `deployment` snapshot window.
/// OWNED BY THE SLOT — declared inside the variant file that declares the
/// slot (the slot's owning variant), so a slot has exactly one policy no
/// matter how many targets it is a member of, and membership changes never
/// change retention.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfig {
    #[serde(default)]
    pub per_server: PerServerRetention,
    #[serde(default)]
    pub deployment: DeploymentRetention,
}

/// Durable protection for one whole release: every variant's artifact in the
/// pinned release is retained forever; retention never sweeps it.
///
/// The DOMAIN shape: `release` carries the TYPED [`ReleaseId`], so a pin can
/// only name a release that satisfies the exact `rel-sha256-<64 lowercase
/// hex>` grammar — a loaded configuration can never carry a pin whose
/// release would later fail [`ReleaseId::parse`] (the consumers that used to
/// parse the raw string late now receive the typed id by construction). The
/// raw WIRE shape is [`raw::RawPin`] (a plain string); the raw -> domain
/// conversion validates every pin during load via `TryFrom<raw::RawPin>`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub release: ReleaseId,
    pub reason: String,
}

/// Raw -> domain conversion for ONE pin: the raw wire `release` string is
/// parsed into the typed [`ReleaseId`]. A pin string that does not satisfy
/// the exact `rel-sha256-<64 lowercase hex>` grammar fails the WHOLE config
/// load (fail closed, like every sibling raw -> domain gate), so a
/// successfully loaded configuration can never produce a later release-id
/// syntax error.
impl TryFrom<raw::RawPin> for Pin {
    type Error = Error;
    fn try_from(raw: raw::RawPin) -> Result<Pin> {
        Ok(Pin {
            release: ReleaseId::parse(&raw.release)?,
            reason: raw.reason,
        })
    }
}

/// The active release: the name of a directory directly beneath `releases/` in
/// the project root. The project structure is forced to
/// `<project>/releases/<name>/<variant>.toml`; there is no configurable path.
/// The name carries the single-directory-component invariant
/// ([`ReleaseName::parse`] is the production constructor; the raw
/// deserialization path is re-validated by the raw -> domain conversion and by
/// [`ProjectConfig::load_release`], so an invalid name can never enter a validated
/// [`ProjectConfig`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ReleaseName(String);

impl ReleaseName {
    /// Parse and validate a release name: exactly ONE directory component
    /// (the forced structure is `<project>/releases/<name>/`), so the name
    /// can never escape the release directory. This is the PRODUCTION
    /// constructor for a validated release name; the deserialization path
    /// stays raw and the conversion / [`ProjectConfig::load_release`] re-validate.
    pub fn parse(s: &str) -> Result<ReleaseName> {
        validate_release_name(s)?;
        Ok(ReleaseName(s.to_string()))
    }

    /// Build a release name for the crate-internal raw layer (the conversion
    /// re-checks that it is a single directory component).
    #[cfg(test)]
    pub(crate) fn new(s: impl Into<String>) -> Self {
        ReleaseName(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ReleaseName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A release name must be exactly ONE directory component (the forced
/// structure is `<project>/releases/<name>/<variant>.toml`), so it can never
/// escape the release directory. Shared by the raw -> domain conversion
/// ([`ProjectConfig::try_from`]), [`ReleaseName::parse`], and the validated
/// release-switch operation [`ProjectConfig::load_release`].
fn validate_release_name(name: &str) -> Result<()> {
    let single_component = matches!(
        Path::new(name).components().collect::<Vec<_>>().as_slice(),
        [Component::Normal(c)] if *c == std::ffi::OsStr::new(name)
    );
    if !single_component {
        return Err(Error::config(format!(
            "release '{name}' must be a single directory name (the release directory is forced to `releases/<name>/`)"
        )));
    }
    Ok(())
}

impl<'de> Deserialize<'de> for ReleaseName {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ReleaseNameVisitor;
        impl<'d> serde::de::Visitor<'d> for ReleaseNameVisitor {
            type Value = ReleaseName;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(
                    "a release name like `release: v1` (the release directory is forced to `releases/<name>/`)",
                )
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<ReleaseName, E> {
                Ok(ReleaseName(v.to_string()))
            }

            fn visit_map<A>(self, _map: A) -> std::result::Result<ReleaseName, A::Error>
            where
                A: serde::de::MapAccess<'d>,
            {
                Err(serde::de::Error::custom(
                    "schema v1 forces the project structure `<project>/releases/<name>/<variant>.toml`: \
                     set `release: <name>` and drop the release.path/release.variants map",
                ))
            }
        }
        deserializer.deserialize_any(ReleaseNameVisitor)
    }
}

/// A target's batch-failure policy: what happens to the servers whose batches
/// already ADVANCED when a LATER batch fails. STRICT typed enum replacing the
/// old loose `String` field: an unknown `failure_policy` spelling used to
/// silently behave as "leave changed" (fail-open — an operator typo kept the
/// changed servers in their new state instead of rolling back). The raw
/// string is consumed by the STRICT parse below during the merged raw ->
/// domain conversion (the config layers are merged, so the typed parse runs
/// when the manifest is deserialized), and ANY unsupported spelling is
/// rejected with a config error naming the valid options. The default stays
/// [`FailurePolicy::RollbackChanged`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum FailurePolicy {
    /// `failure_policy = "rollback_changed"`: when a later batch fails, every
    /// server whose batch already advanced is COMPENSATED back to its
    /// pre-push generation (compare-and-swap). The attempt ends
    /// `failed_rolled_back` when every advanced server is compensated, else
    /// `degraded`. The default.
    #[default]
    RollbackChanged,
    /// `failure_policy = "leave_changed"`: a later batch failing RETAINS the
    /// already-advanced servers deliberately — no compensation pass runs and
    /// the attempt ends `degraded` with the mixed per-server state retained.
    LeaveChanged,
}

impl FailurePolicy {
    /// The exact supported config spellings, in documentation order (also the
    /// error message's "valid options" list).
    pub const SPELLINGS: [&'static str; 2] = ["rollback_changed", "leave_changed"];

    /// The canonical config spelling of this policy.
    pub fn as_str(&self) -> &'static str {
        match self {
            FailurePolicy::RollbackChanged => "rollback_changed",
            FailurePolicy::LeaveChanged => "leave_changed",
        }
    }
}

impl fmt::Display for FailurePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FailurePolicy {
    type Err = Error;

    /// STRICT EXACT parse — the conversion's ONLY entry from the raw
    /// `failure_policy` string. The two supported spellings
    /// ([`FailurePolicy::SPELLINGS`], matching the existing docs) parse;
    /// EVERYTHING else — case variants, whitespace, dashes, typos, the empty
    /// string — is REJECTED with a config error naming the valid options, so
    /// an unsupported spelling can never silently mean "leave changed".
    fn from_str(s: &str) -> Result<FailurePolicy> {
        match s {
            "rollback_changed" => Ok(FailurePolicy::RollbackChanged),
            "leave_changed" => Ok(FailurePolicy::LeaveChanged),
            other => Err(Error::config(format!(
                "unsupported failure_policy '{other}' (valid: {})",
                FailurePolicy::SPELLINGS.join(", ")
            ))),
        }
    }
}

impl Serialize for FailurePolicy {
    /// The canonical spelling is the serialized form (`failure_policy =
    /// "rollback_changed"`), so a scaffolded/round-tripped config carries
    /// exactly what the strict parse accepts.
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for FailurePolicy {
    /// Deserialization IS the raw -> domain parse (the layers are merged: a
    /// `RolloutConfig` is both the raw serde shape and the domain record, so
    /// the string is consumed exactly here). Delegates to the strict
    /// [`FailurePolicy::from_str`] so unsupported spellings fail closed with
    /// the same config error naming the valid options.
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FailurePolicyVisitor;
        impl<'d> serde::de::Visitor<'d> for FailurePolicyVisitor {
            type Value = FailurePolicy;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    f,
                    "a failure_policy string (valid: {})",
                    FailurePolicy::SPELLINGS.join(", ")
                )
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<FailurePolicy, E>
            where
                E: serde::de::Error,
            {
                v.parse::<FailurePolicy>().map_err(E::custom)
            }
        }
        deserializer.deserialize_str(FailurePolicyVisitor)
    }
}

/// The DOMAIN rollout policy of one target. Built ONLY by the raw -> domain
/// conversion: `batch_size` is a validated NONZERO [`BatchSize`] (the raw
/// integer is parsed by the conversion, which rejects zero), `failure_policy`
/// is the closed typed enum. The raw serialization shape is
/// [`raw::RawRolloutConfig`] (bare integer batch size); this domain type is
/// never deserialized from the file directly.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RolloutConfig {
    /// How many slots a rollout advances per batch. NONZERO by construction:
    /// a zero batch would stall the rollout without ever progressing.
    pub batch_size: BatchSize,
    pub stop_on_failure: bool,
    /// The batch-failure policy as the TYPED [`FailurePolicy`] enum (never a
    /// loose string): the raw `failure_policy` spelling is parsed strictly
    /// during deserialization, so an unsupported spelling fails the config
    /// load instead of silently behaving as "leave changed".
    pub failure_policy: FailurePolicy,
}

fn default_failure_policy() -> FailurePolicy {
    FailurePolicy::RollbackChanged
}
fn default_ssh_port() -> u16 {
    22
}

/// A deployment slot: binds one server to one workload under an ID, with an
/// absolute `deploy_dir` on the server, and belongs to EXACTLY ONE owning
/// target. The connection details live on the top-level `[[servers]]`
/// entry; the workload choice, its on-server location, its owning target,
/// and its rollout groups live here. Slots are declared INSIDE the variant
/// file that owns the workload: the `[[slots]]` entries of
/// `<release>/<variant>.toml` are the slot declarations, the declaring
/// variant file IS the slot's variant binding (there is no `variant` field
/// — it is the enclosing file), and the slot's `target` field is what binds
/// it to its ONE top-level target. A target's members are DERIVED by
/// scanning every variant's slots for its name.
///
/// This is both the raw serialization shape of a slot and the domain record:
/// its validity (id non-empty/unique, references resolvable, groups clean,
/// location unique) is enforced by the raw -> domain conversion; a slot can
/// never enter a [`ProjectConfig`] graph except through that conversion.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SlotConfig {
    pub id: String,
    /// The ID of the top-level server this slot deploys onto.
    pub server: String,
    /// Absolute directory on the server where this slot's deployment state
    /// (objects, releases, generations, `current`) lives. INVARIANT-BEARING
    /// (must be an absolute path on the server) — private, read through
    /// [`SlotConfig::deploy_dir`]; the absoluteness rule is enforced by the
    /// raw -> domain conversion and re-checked by every validated rebuild
    /// operation, so an invalid deploy_dir can never enter a validated
    /// [`ProjectConfig`].
    deploy_dir: PathBuf,
    /// The slot's EXACTLY ONE owning target: a physical slot has one owner
    /// that governs its history, checkpoints, observed state, rollout
    /// policy, and retention policy. Required and must reference an existing
    /// top-level `[targets.<name>]` key. TOML form: `target = "production"`.
    pub target: String,
    /// The rollout groups this slot belongs to, scoped to its owning target:
    /// groups only SELECT a subset of the target's slots (`deploy push
    /// <target> --group <name>`); they never own state, policy, history, or
    /// checkpoints. Defaults to empty (a slot in no group is selected only by
    /// an omitting `--group` push). A name must not appear twice (a
    /// duplicate adds no membership yet would change the release identity,
    /// so it is rejected at validation). TOML form: `groups = ["canary",
    /// "wave-1"]`.
    #[serde(default)]
    pub groups: Vec<String>,
}

impl SlotConfig {
    /// Build a slot from its raw parts. The graph-level rules (identifier
    /// validity, reference resolution, deploy_dir absoluteness, location
    /// uniqueness) are enforced when the slot enters a [`ProjectConfig`]: the
    /// raw -> domain conversion and every validated rebuild operation
    /// re-validate the whole graph, so an invalid slot can never enter a
    /// validated config.
    pub fn new(
        id: impl Into<String>,
        server: impl Into<String>,
        deploy_dir: impl Into<PathBuf>,
        target: impl Into<String>,
        groups: Vec<String>,
    ) -> SlotConfig {
        SlotConfig {
            id: id.into(),
            server: server.into(),
            deploy_dir: deploy_dir.into(),
            target: target.into(),
            groups,
        }
    }

    /// The absolute on-server directory this slot's deployment state lives
    /// in (read-only).
    pub fn deploy_dir(&self) -> &Path {
        &self.deploy_dir
    }
}

/// The DOMAIN target: ROLLOUT behavior only (batch_size, stop_on_failure,
/// failure_policy). Retention is NOT a target surface: a slot's retention
/// comes from its owning variant (see [`VariantConfig::retention`]), so a
/// target that shares a slot with other targets can never change that slot's
/// policy. Built ONLY by the raw -> domain conversion; the raw serialization
/// shape is [`raw::RawTargetConfig`] (bare integer batch size).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetConfig {
    pub rollout: RolloutConfig,
}

// ---------------------------------------------------------------------------
// The RAW layer: exactly the serialized shapes, nothing else.
// `deny_unknown_fields` makes the parse gate fail closed, and the conversion
// makes the domain gate fail closed. These types are crate-internal: callers
// reach the validated domain through [`ProjectConfig::load`].
// ---------------------------------------------------------------------------

pub(crate) mod raw {
    use super::*;

    /// The raw `deploy.toml` manifest shape. Holds whatever the file says —
    /// `known_hosts`/`host_key_fingerprint` as a plain option pair, no
    /// validation, unknown fields refused at parse. Converted to the
    /// validated [`DomainConfig`] by [`super::ProjectConfig::from_raw_parts`].
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct RawConfig {
        pub schema_version: u32,
        pub application: String,
        pub release: ReleaseName,
        #[serde(default)]
        pub pins: Vec<RawPin>,
        pub servers: Vec<RawServer>,
        pub targets: BTreeMap<String, RawTargetConfig>,
    }

    /// One raw `[[pins]]` entry: the pin's release as a PLAIN string (exactly
    /// what the file says). The domain conversion parses the string into the
    /// typed [`super::Pin::release`] [`super::ReleaseId`] — a malformed pin
    /// string fails the whole load (fail closed, at the raw -> domain
    /// conversion) — so the raw shape keeps the bare string for the
    /// fail-closed property.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct RawPin {
        pub release: String,
        pub reason: String,
    }

    /// One raw `[[servers]]` entry: the raw host-identity option PAIR. The
    /// domain conversion collapses the pair into the single typed
    /// [`HostIdentity`] enum (exactly one form for an SSH address).
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct RawServer {
        pub id: String,
        pub address: String,
        pub user: String,
        #[serde(default = "super::default_ssh_port")]
        pub port: u16,
        #[serde(default)]
        pub known_hosts: Option<PathBuf>,
        #[serde(default)]
        pub host_key_fingerprint: Option<String>,
        #[serde(default)]
        pub capacity: RawCapacityConfig,
    }

    /// The raw per-server capacity shape: exactly what the file says. The
    /// conversion parses `reserve_percent` into the validated
    /// [`super::CapacityPercent`] (0..=100) and builds the domain
    /// [`super::CapacityConfig`]; this raw type keeps the bare integer so
    /// arbitrary out-of-range values remain constructible for the fail-closed
    /// property.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct RawCapacityConfig {
        #[serde(default)]
        pub reserve_bytes: u64,
        #[serde(default)]
        pub reserve_percent: u8,
    }

    /// The raw `[targets.<name>]` entry: rollout with a BARE integer
    /// `batch_size`. The conversion parses it into the validated NONZERO
    /// [`super::BatchSize`] and builds the domain [`super::TargetConfig`]; the
    /// raw shape keeps the bare integer so an arbitrary (including zero)
    /// value remains constructible for the fail-closed property.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct RawTargetConfig {
        #[serde(default)]
        pub rollout: RawRolloutConfig,
    }

    /// The raw rollout shape: a bare integer `batch_size` (any value the
    /// file says — the nonzero rule is enforced by the conversion).
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct RawRolloutConfig {
        #[serde(default = "raw_default_batch_size")]
        pub batch_size: u32,
        #[serde(default = "super::default_true")]
        pub stop_on_failure: bool,
        #[serde(default = "super::default_failure_policy")]
        pub failure_policy: FailurePolicy,
    }

    fn raw_default_batch_size() -> u32 {
        1
    }

    impl Default for RawRolloutConfig {
        fn default() -> Self {
            RawRolloutConfig {
                batch_size: raw_default_batch_size(),
                stop_on_failure: true,
                failure_policy: FailurePolicy::RollbackChanged,
            }
        }
    }

    /// One raw variant file (`releases/<name>/<variant>.toml`): the raw
    /// activation table (a bare `adapter` string) and the raw slot
    /// declarations. The conversion replaces `activation` with the typed
    /// [`Activation`] enum and validates every slot.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct RawVariant {
        #[serde(default)]
        pub description: Option<String>,
        pub artifact: ArtifactConfig,
        #[serde(default)]
        pub activation: ActivationConfig,
        pub verification: VerificationConfig,
        #[serde(default)]
        pub slots: Vec<SlotConfig>,
        #[serde(default)]
        pub retention: RetentionConfig,
    }

    impl RawConfig {
        /// Discover variant files inside the release directory. The project
        /// structure is forced: every regular, non-hidden `*.toml` file
        /// directly inside `<project>/releases/<release>/` is a variant named
        /// by its file stem, parsed into the raw layer. Other entries (such
        /// as the `artifacts/` directory) are ignored.
        pub(crate) fn load_variant_files(
            &self,
            config_path: &Path,
        ) -> Result<BTreeMap<String, RawVariant>> {
            let project_root = config_path
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("."));
            let project_root = project_root.canonicalize().map_err(|e| {
                Error::config(format!("canonicalize project root for deploy.toml: {e}"))
            })?;
            let release_root = project_root.join("releases").join(self.release.as_str());
            let canonical_release = release_root.canonicalize().map_err(|_| {
                Error::config(format!(
                    "release directory '{}' not found; the project structure is forced: \
                     <project>/releases/{}/<variant>.toml",
                    release_root.display(),
                    self.release
                ))
            })?;
            if !canonical_release.is_dir() {
                return Err(Error::config(format!(
                    "release '{}' is not a directory ({})",
                    self.release,
                    release_root.display()
                )));
            }
            let mut variant_files: Vec<(String, PathBuf)> = Vec::new();
            let entries = std::fs::read_dir(&canonical_release).map_err(|e| {
                Error::config(format!(
                    "reading release directory '{}': {e}",
                    canonical_release.display()
                ))
            })?;
            for entry in entries {
                let entry = entry
                    .map_err(|e| Error::config(format!("reading release directory entry: {e}")))?;
                let file_name = entry.file_name();
                let Some(file_name) = file_name.to_str() else {
                    continue; // non-UTF-8 names are never variants
                };
                if file_name.starts_with('.') {
                    continue; // hidden files are never variants
                }
                let Some(stem) = file_name.strip_suffix(".toml") else {
                    continue; // only *.toml files declare variants
                };
                if stem.trim().is_empty() {
                    return Err(Error::config(format!(
                        "variant file '{file_name}' in '{}' has an empty variant name",
                        canonical_release.display()
                    )));
                }
                if !entry.file_type().is_ok_and(|t| t.is_file()) {
                    return Err(Error::config(format!(
                        "variant '{stem}' config '{file_name}' must be a regular file inside the release directory"
                    )));
                }
                variant_files.push((stem.to_string(), entry.path()));
            }
            variant_files.sort_by(|a, b| a.0.cmp(&b.0));
            if variant_files.is_empty() {
                return Err(Error::config(format!(
                    "release directory '{}' declares no variants (expected at least one <variant>.toml file)",
                    release_root.display()
                )));
            }
            let mut variants = BTreeMap::new();
            for (vname, path) in variant_files {
                let text = std::fs::read_to_string(&path).map_err(|e| {
                    Error::config(format!(
                        "reading variant '{vname}' config '{}': {e}",
                        path.display()
                    ))
                })?;
                let variant: RawVariant = toml::from_str(&text).map_err(|e| {
                    Error::config(format!(
                        "parsing variant '{vname}' config '{}': {e}",
                        path.display()
                    ))
                })?;
                variants.insert(vname, variant);
            }
            Ok(variants)
        }
    }
}

// ---------------------------------------------------------------------------
// Domain model: typed option spaces + validated graph
// ---------------------------------------------------------------------------

/// A validated host-key fingerprint (e.g. `SHA256:...`). Construction is
/// gated on the `SHA256:` format rule, so an invalid fingerprint cannot
/// exist in a domain server's identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// Parse and validate a `SHA256:...` host-key fingerprint.
    pub fn parse(s: &str) -> Result<Fingerprint> {
        if !s.starts_with("SHA256:") {
            return Err(Error::config(
                "host_key_fingerprint must be a SHA256:... value",
            ));
        }
        Ok(Fingerprint(s.to_string()))
    }

    /// The canonical `SHA256:...` string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A server's EXACTLY ONE host-identity form, replacing the raw
/// `known_hosts`/`host_key_fingerprint` option pair: `Local` for a
/// `local://` endpoint (which never performs host verification), a dedicated
/// `known_hosts` file, or a pre-verified `SHA256:` fingerprint. By
/// construction a server can never hold both or neither identity — the
/// domain conversion collapses the raw pair into exactly one variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostIdentity {
    /// A `local://` endpoint; no host verification is ever performed.
    Local,
    /// A dedicated `known_hosts` file used with `StrictHostKeyChecking=yes`.
    KnownHosts(PathBuf),
    /// A pre-verified host-key fingerprint the host key is pinned against on
    /// first contact.
    Fingerprint(Fingerprint),
}

/// A variant's activation policy as a closed enum: no activation adapter
/// (a no-op), or a `systemd` activation carrying its scope, reconciliation,
/// and units. The raw `adapter` string is consumed by the conversion, so an
/// unknown adapter cannot exist in a domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Activation {
    /// `adapter = "none"`: no activation step runs.
    None,
    /// `adapter = "systemd"`: activate via systemd with the given scope and
    /// units. The conversion requires at least one unit.
    Systemd(SystemdActivation),
}

/// The systemd activation policy: the unit scope, whether managed units are
/// reconciled, and the unit definitions to install.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemdActivation {
    pub scope: ActivationScope,
    pub reconcile_managed_units: bool,
    pub units: Vec<UnitDef>,
}

impl From<Activation> for ActivationConfig {
    /// The canonical serialized contract for an [`Activation`]: `None`
    /// becomes the default "none" contract (scope/units of a none-variant are
    /// not part of the domain), `Systemd` becomes the systemd contract. This
    /// is the ONLY path from the domain to the contract records, so the
    /// behavior digest is deterministic.
    fn from(a: Activation) -> ActivationConfig {
        match a {
            Activation::None => ActivationConfig {
                adapter: "none".to_string(),
                scope: ActivationScope::default(),
                reconcile_managed_units: true,
                units: Vec::new(),
            },
            Activation::Systemd(sa) => ActivationConfig {
                adapter: "systemd".to_string(),
                scope: sa.scope,
                reconcile_managed_units: sa.reconcile_managed_units,
                units: sa.units,
            },
        }
    }
}

/// A server's EXACTLY ONE connection form, consolidating the raw
/// `address`/`user`/`port`/identity fields: `Local` for a `local://`
/// endpoint (the transport is rooted at the path after the prefix; no host
/// verification is ever performed), or `Ssh` carrying the validated host,
/// deployment account, nonzero port, and the EXACTLY ONE host-identity
/// form. By construction a server is either local or SSH — never both,
/// never neither. The raw/wire layer keeps the separate fields; the
/// conversion builds this enum, so the connection form is exactly-one by
/// construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerConnection {
    /// A `local://` endpoint: `address` is the full `local://<absolute-path>`
    /// form (the transport is rooted at the path after the prefix; no host
    /// verification is ever performed). The identity is ALWAYS
    /// [`HostIdentity::Local`] by construction (the conversion builds it so;
    /// the validated rebuild operations re-check it).
    Local {
        address: String,
        identity: HostIdentity,
    },
    /// An SSH connection: the validated host, deployment account, nonzero
    /// port, and the EXACTLY ONE host-identity form ([`HostIdentity::KnownHosts`]
    /// or [`HostIdentity::Fingerprint`] — never `Local`).
    Ssh {
        address: Host,
        user: SshUser,
        port: NonZeroU16,
        identity: HostIdentity,
    },
}

/// A validated server: the validated identifier plus the EXACTLY ONE
/// connection form ([`ServerConnection`] — local or SSH, never both/neither
/// by construction). The connection is PRIVATE: a server is only built by
/// the raw -> domain conversion or the validated rebuild operations, so an
/// inconsistent connection (an SSH form with a `Local` identity, a
/// `local://` address that is not absolute) can never enter a validated
/// [`ProjectConfig`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerDef {
    /// The server's validated identifier (non-empty, well-formed): parsed by
    /// the raw -> domain conversion, so an invalid server id cannot exist in
    /// a domain server.
    pub id: Identifier,
    /// The server's EXACTLY ONE connection form. Private: read through
    /// [`ServerDef::connection`] and the wire-view accessors
    /// ([`ServerDef::address`], [`ServerDef::user`], [`ServerDef::port`],
    /// [`ServerDef::identity`]); changed only through the validated rebuild
    /// operations, which re-validate the whole graph.
    connection: ServerConnection,
    /// Per-server capacity headroom policy (defaults to 0/0 when omitted),
    /// shared by every deployment slot on this server and resolved from the
    /// caller's current configuration at preflight time. Not part of the
    /// release identity.
    pub capacity: CapacityConfig,
}

impl ServerDef {
    /// Build a server from its validated parts. The connection's
    /// well-formedness (a `local://` address that is absolute, an SSH form
    /// with a `KnownHosts`/`Fingerprint` identity) is enforced when the
    /// server enters a [`ProjectConfig`]: the conversion and every validated
    /// rebuild operation re-validate the whole graph.
    pub fn new(
        id: Identifier,
        connection: ServerConnection,
        capacity: CapacityConfig,
    ) -> ServerDef {
        ServerDef {
            id,
            connection,
            capacity,
        }
    }

    /// The server's EXACTLY ONE connection form.
    pub fn connection(&self) -> &ServerConnection {
        &self.connection
    }

    /// The connection address: the full `local://<path>` endpoint for a
    /// local server, the SSH host for an SSH server.
    pub fn address(&self) -> &str {
        match &self.connection {
            ServerConnection::Local { address, .. } => address,
            ServerConnection::Ssh { address, .. } => address.as_str(),
        }
    }

    /// The SSH deployment account; empty for a local server (a local
    /// endpoint has no SSH user).
    pub fn user(&self) -> &str {
        match &self.connection {
            ServerConnection::Local { .. } => "",
            ServerConnection::Ssh { user, .. } => user.as_str(),
        }
    }

    /// The SSH port (default 22); 22 for a local server (a local endpoint
    /// has no SSH port).
    pub fn port(&self) -> u16 {
        match &self.connection {
            ServerConnection::Local { .. } => 22,
            ServerConnection::Ssh { port, .. } => port.get(),
        }
    }

    /// The server's validated, single host-identity form: ALWAYS
    /// [`HostIdentity::Local`] for a local server, the exactly-one
    /// `KnownHosts`/`Fingerprint` form for an SSH server.
    pub fn identity(&self) -> &HostIdentity {
        match &self.connection {
            ServerConnection::Local { identity, .. } => identity,
            ServerConnection::Ssh { identity, .. } => identity,
        }
    }
}

/// A validated per-variant deployment policy: artifact mappings, the typed
/// activation enum, verification, the variant's slot declarations, and its
/// slot-owned retention policy. Obtained only through the raw -> domain
/// conversion (or [`ProjectConfig::variant`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariantConfig {
    pub description: Option<String>,
    pub artifact: ArtifactConfig,
    /// The variant's typed activation policy ([`Activation`]); the raw
    /// `adapter` string has already been consumed by the conversion.
    pub activation: Activation,
    pub verification: VerificationConfig,
    /// This variant's deployment slots, declared inside its own file. The
    /// declaring variant file is the slot's variant binding.
    pub slots: Vec<SlotConfig>,
    /// The retention policy applied on every retention pass of EVERY slot this
    /// variant file declares. A slot's owning variant is its SINGLE retention
    /// source.
    pub retention: RetentionConfig,
}

// ---------------------------------------------------------------------------
// The validated domain model
// ---------------------------------------------------------------------------

/// The validated domain configuration. Privately constructed: the ONLY ways
/// to obtain a [`ProjectConfig`] are [`ProjectConfig::load`] (parse + discover + convert)
/// and the crate-internal conversion [`ProjectConfig::from_raw_parts`], both of
/// which run the full validation and fail closed on any invalid input.
///
/// IMMUTABLE VALIDATED DOMAIN: EVERY field is private and read-only — the
/// graph is exposed through read-only accessors and iterators
/// ([`ProjectConfig::application`], [`ProjectConfig::pins`], [`ProjectConfig::servers`],
/// [`ProjectConfig::targets`], [`ProjectConfig::server`], [`ProjectConfig::target`],
/// [`ProjectConfig::slot_defs`], [`ProjectConfig::slot_retention`], ...). The ONLY
/// mutation path is a VALIDATED operation returning a NEW [`ProjectConfig`] —
/// [`ProjectConfig::load_release`] (a fresh validated load switching the
/// release), [`ProjectConfig::with_server`], [`ProjectConfig::with_target`],
/// [`ProjectConfig::with_pin`], ... — each of which re-validates the whole
/// graph (references resolve, no impossible combos) and returns `Err` with
/// the ORIGINAL untouched on any violation. A hand-built invalid graph cannot
/// enter the domain, and no code can mutate a validated graph into an invalid
/// state.
///
/// The name [`DomainConfig`] aliases this type (the two-layer story: raw
/// serde shapes -> validated domain).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectConfig {
    /// The configuration format version this config was validated as: ALWAYS
    /// [`CONFIG_SCHEMA_VERSION`] by construction (the raw -> domain
    /// conversion refuses any other value). Private + read-only
    /// ([`ProjectConfig::schema_version`]): the format identity is invariant.
    schema_version: u32,
    /// The deployment application identifier: a validated single safe
    /// path segment ([`crate::scalar::ApplicationStoreKey`]) parsed by the
    /// raw -> domain conversion (an application name that is not a safe
    /// store key — empty, control-bearing, `/`/`\`-separated, `.`/`..`, or
    /// padded — is rejected AT THE LOAD, fail closed). ONE safe
    /// application identifier is used for BOTH display (messages and
    /// rendering) and storage: the store directory key is the SAME value
    /// ([`crate::store::local::LocalStore::new`] takes it directly, with
    /// no further conversion), so a successfully loaded config always
    /// constructs its store. Private + read-only
    /// ([`ProjectConfig::application`]).
    application: ApplicationStoreKey,
    /// The active release: the name of a directory directly beneath
    /// `releases/` in the project root (`release: v1` -> `releases/v1/`).
    /// INVARIANT-BEARING (a single directory component) — private and
    /// read-only ([`ProjectConfig::release`]); switch it through the validated
    /// [`ProjectConfig::load_release`] operation (a fresh load), never by
    /// assignment.
    release: ReleaseName,
    /// Durable retention pins applied on every retention pass. Private +
    /// read-only ([`ProjectConfig::pins`]); changed only through the
    /// validated [`ProjectConfig::with_pin`] / [`ProjectConfig::without_pin`]
    /// operations.
    pins: Vec<Pin>,
    /// Every validated server; a server's connection is exactly one form by
    /// construction ([`ServerDef::connection`]). Private + read-only
    /// ([`ProjectConfig::servers`] iterator, [`ProjectConfig::server`]);
    /// changed only through the validated rebuild operations.
    servers: Vec<ServerDef>,
    /// Every validated target, keyed by name. Private + read-only
    /// ([`ProjectConfig::targets`] iterator, [`ProjectConfig::target`]);
    /// changed only through the validated rebuild operations.
    targets: BTreeMap<String, TargetConfig>,
    /// Validated variants, keyed by name. Private: the domain graph cannot
    /// be hand-built — variants only enter through the conversion.
    variants: BTreeMap<String, VariantConfig>,
}

/// The validated domain model (alias of [`ProjectConfig`]): the public name of the
/// layer that the engine, planner, retention, and mapper consume.
pub type DomainConfig = ProjectConfig;

impl ProjectConfig {
    /// Load and validate a configuration from a `deploy.toml` path. The
    /// project root is the directory containing the file. Variant files are
    /// discovered inside `<project>/releases/<release>/` (the release
    /// directory named by `release:`), parsed into the raw layer, and the
    /// whole raw input is converted into the validated domain — any invalid
    /// identifier, reference, or option combination fails the load.
    pub fn load(path: &Path) -> Result<ProjectConfig> {
        let manifest = Self::read_manifest(path)?;
        let variants = manifest.load_variant_files(path)?;
        ProjectConfig::from_raw_parts(manifest, variants)
    }

    /// Read + parse the raw `deploy.toml` manifest at `path` (the raw layer:
    /// whatever the file says, unknown fields refused at parse). Shared by
    /// [`ProjectConfig::load`] and [`ProjectConfig::load_release`].
    fn read_manifest(path: &Path) -> Result<raw::RawConfig> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::config(format!("reading {}: {e}", path.display())))?;
        toml::from_str(&text).map_err(|e| Error::config(format!("parsing deploy.toml: {e}")))
    }

    /// Total-fail-closed conversion of the raw deserialized input: every
    /// validity rule (schema version gate, identifier validity and
    /// uniqueness, slot->server/slot->target reference resolution, group
    /// scoping, exactly-one host identity, the activation enum, mapping
    /// collision detection) is checked here and ANY violation rejects the
    /// conversion. Crate-internal: the raw layer is private, so the public
    /// entry to a validated domain is [`ProjectConfig::load`].
    pub(crate) fn from_raw_parts(
        manifest: raw::RawConfig,
        variants: BTreeMap<String, raw::RawVariant>,
    ) -> Result<ProjectConfig> {
        ProjectConfig::try_from(RawProject { manifest, variants })
    }

    pub fn project_root(&self, config_path: &Path) -> PathBuf {
        config_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
    }

    /// The schema version this configuration was validated as — ALWAYS
    /// [`CONFIG_SCHEMA_VERSION`] by construction (the conversion refuses any
    /// other value). Read-only accessor: the schema identity of a loaded
    /// config is immutable.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// The active release: the name of a directory directly beneath
    /// `releases/` in the project root. Read-only accessor: the release is
    /// an invariant-bearing field (a single directory component); switch it
    /// through the validated [`ProjectConfig::load_release`] operation (a fresh
    /// load), never by assignment.
    pub fn release(&self) -> &ReleaseName {
        &self.release
    }

    /// The deployment application identifier (read-only): ONE safe name
    /// used for both display and storage — the store is constructed
    /// directly from it ([`crate::store::local::LocalStore::new`]), with
    /// no further conversion.
    pub fn application(&self) -> &ApplicationStoreKey {
        &self.application
    }

    /// The durable retention pins applied on every retention pass
    /// (read-only).
    pub fn pins(&self) -> &[Pin] {
        &self.pins
    }

    /// Every validated server, in declaration order (read-only iterator).
    pub fn servers(&self) -> std::slice::Iter<'_, ServerDef> {
        self.servers.iter()
    }

    /// Every validated target, in name order (read-only iterator).
    pub fn targets(&self) -> impl Iterator<Item = (&str, &TargetConfig)> + '_ {
        self.targets
            .iter()
            .map(|(name, target)| (name.as_str(), target))
    }

    /// Look up one validated server by id.
    pub fn server(&self, id: &str) -> Option<&ServerDef> {
        self.servers.iter().find(|s| s.id.as_str() == id)
    }

    /// Look up one validated target by name.
    pub fn target(&self, name: &str) -> Option<&TargetConfig> {
        self.targets.get(name)
    }

    /// The VALIDATED release-switch operation: a FRESH LOAD of the project at
    /// `path` with `release` selected. The deploy.toml is re-read, the release
    /// field is overridden with `release` (whose name is re-validated —
    /// exactly one directory component; otherwise `Err`), and THAT release's
    /// variant files are re-discovered and re-validated by the raw -> domain
    /// conversion: a missing or invalid release's variant files fail the
    /// whole load, so the result is a complete, freshly-validated
    /// [`ProjectConfig`] for the new release — never a partially-switched
    /// config.
    pub fn load_release(path: &Path, release: ReleaseName) -> Result<ProjectConfig> {
        validate_release_name(release.as_str())?;
        let mut manifest = Self::read_manifest(path)?;
        manifest.release = release;
        let variants = manifest.load_variant_files(path)?;
        ProjectConfig::from_raw_parts(manifest, variants)
    }

    /// Re-validate the WHOLE graph: every reference resolves, ids are valid
    /// and unique, no impossible combos, and the connection enum is
    /// well-formed. This is the single gate every validated rebuild
    /// operation runs after mutating a clone; the raw -> domain conversion
    /// runs the same rules inline (with raw-layer context for the error
    /// messages).
    fn validate_graph(&self) -> Result<()> {
        // Server ids are validated [`Identifier`]s by construction; the graph
        // rule is uniqueness. The connection enum must be well-formed: a
        // local form carries a `local://` address whose path is absolute and
        // a `Local` identity; an SSH form carries a `KnownHosts`/`Fingerprint`
        // identity (never `Local`) with an absolute `known_hosts`.
        let mut server_ids = HashSet::new();
        for s in &self.servers {
            if !server_ids.insert(s.id.as_str()) {
                return Err(Error::config(format!(
                    "duplicate server id '{}' in top-level servers",
                    s.id
                )));
            }
            match s.connection() {
                ServerConnection::Local { address, identity } => {
                    if identity != &HostIdentity::Local {
                        return Err(Error::config(format!(
                            "server '{}': a local connection must carry a Local identity",
                            s.id
                        )));
                    }
                    let Some(path) = address.strip_prefix("local://") else {
                        return Err(Error::config(format!(
                            "server '{}': a local connection must carry a local:// address",
                            s.id
                        )));
                    };
                    if !Path::new(path).is_absolute() {
                        return Err(Error::config(format!(
                            "server '{}': local:// endpoint must be an absolute path",
                            s.id
                        )));
                    }
                }
                ServerConnection::Ssh { identity, .. } => match identity {
                    HostIdentity::Local => {
                        return Err(Error::config(format!(
                            "server '{}': an SSH connection cannot carry a Local identity",
                            s.id
                        )));
                    }
                    HostIdentity::KnownHosts(p) => {
                        if !p.is_absolute() {
                            return Err(Error::config(format!(
                                "server '{}': known_hosts must be an absolute path",
                                s.id
                            )));
                        }
                    }
                    HostIdentity::Fingerprint(_) => {}
                },
            }
        }

        // Variant names are valid identifiers (the map is keyed by them) and
        // the typed activation enum is well-formed (systemd requires units).
        let mut variant_names = HashSet::new();
        for name in self.variants.keys() {
            Identifier::parse(name).map_err(|_| {
                Error::config(format!(
                    "variant name '{name}' must be a non-empty, well-formed identifier"
                ))
            })?;
            if !variant_names.insert(name) {
                return Err(Error::config(format!("duplicate variant name '{name}'")));
            }
            if let Activation::Systemd(sa) = &self.variants[name].activation
                && sa.units.is_empty()
            {
                return Err(Error::config(format!(
                    "variant '{name}': systemd activation requires at least one unit"
                )));
            }
        }
        if variant_names.is_empty() {
            return Err(Error::config(
                "at least one release variant must be declared",
            ));
        }

        // Slots: ids valid + unique across variants, references resolve,
        // groups clean, deploy_dir absolute, locations unique.
        let mut slot_ids = HashSet::new();
        let mut bound_locations: BTreeMap<(&str, &Path), &str> = BTreeMap::new();
        for (vname, variant) in &self.variants {
            for p in &variant.slots {
                Identifier::parse(&p.id).map_err(|_| {
                    Error::config(format!(
                        "variant '{vname}': slot id '{}' must be a non-empty, well-formed identifier",
                        p.id
                    ))
                })?;
                Identifier::parse(&p.server).map_err(|_| {
                    Error::config(format!(
                        "variant '{vname}': slot '{}' server '{}' must be a non-empty, well-formed identifier",
                        p.id, p.server
                    ))
                })?;
                Identifier::parse(&p.target).map_err(|_| {
                    Error::config(format!(
                        "variant '{vname}': slot '{}' target '{}' must be a non-empty, well-formed identifier",
                        p.id, p.target
                    ))
                })?;
                if !slot_ids.insert(p.id.clone()) {
                    return Err(Error::config(format!(
                        "duplicate slot id '{}' (declared by variant '{vname}')",
                        p.id
                    )));
                }
                if !server_ids.contains(p.server.as_str()) {
                    return Err(Error::config(format!(
                        "variant '{vname}': slot '{}' references unknown server '{}'",
                        p.id, p.server
                    )));
                }
                if !self.targets.contains_key(&p.target) {
                    return Err(Error::config(format!(
                        "variant '{vname}': slot '{}' references unknown target '{}'",
                        p.id, p.target
                    )));
                }
                let mut seen_groups = HashSet::new();
                for g in &p.groups {
                    RolloutGroupName::parse(g).map_err(|_| {
                        Error::config(format!(
                            "variant '{vname}': slot '{}' declares an invalid group name {g:?}",
                            p.id
                        ))
                    })?;
                    if !seen_groups.insert(g) {
                        return Err(Error::config(format!(
                            "variant '{vname}': slot '{}' declares duplicate group '{}'",
                            p.id, g
                        )));
                    }
                }
                if !p.deploy_dir.is_absolute() {
                    return Err(Error::config(format!(
                        "variant '{vname}': slot '{}' deploy_dir must be an absolute path on the server",
                        p.id
                    )));
                }
                if let Some(existing) =
                    bound_locations.get(&(p.server.as_str(), p.deploy_dir.as_path()))
                {
                    return Err(Error::config(format!(
                        "slots '{existing}' and '{}' bind the same location (server '{}', deploy_dir '{}'); each server+deploy_dir pair must belong to exactly one slot",
                        p.id,
                        p.server,
                        p.deploy_dir.display()
                    )));
                }
                bound_locations.insert((p.server.as_str(), p.deploy_dir.as_path()), &p.id);
            }
        }

        // Targets: names valid, each has at least one member slot, one slot
        // per server per target.
        if self.targets.is_empty() {
            return Err(Error::config("at least one target must be declared"));
        }
        for tname in self.targets.keys() {
            Identifier::parse(tname).map_err(|_| {
                Error::config(format!(
                    "target name '{tname}' must be a non-empty, well-formed identifier"
                ))
            })?;
            let mut used_servers = HashSet::new();
            let mut members = 0;
            for slot in self.variants.values().flat_map(|v| v.slots.iter()) {
                if slot.target != *tname {
                    continue;
                }
                members += 1;
                if !used_servers.insert(slot.server.as_str()) {
                    return Err(Error::config(format!(
                        "target '{tname}' has multiple slots on server '{}'",
                        slot.server
                    )));
                }
            }
            if members == 0 {
                return Err(Error::config(format!("target '{tname}' has no slots")));
            }
        }
        Ok(())
    }

    /// Add or replace a server (keyed by its id). Re-validates the whole
    /// graph: a duplicate id, a slot reference left dangling, or an
    /// ill-formed connection fails the operation and the ORIGINAL is
    /// untouched (the operation never mutates).
    pub fn with_server(&self, server: ServerDef) -> Result<ProjectConfig> {
        let mut next = self.clone();
        if let Some(existing) = next.servers.iter_mut().find(|s| s.id == server.id) {
            *existing = server;
        } else {
            next.servers.push(server);
        }
        next.validate_graph()?;
        Ok(next)
    }

    /// Remove a server. Fails if any slot references it (the graph would
    /// dangle); the ORIGINAL is untouched.
    pub fn without_server(&self, id: &str) -> Result<ProjectConfig> {
        let mut next = self.clone();
        let Some(pos) = next.servers.iter().position(|s| s.id.as_str() == id) else {
            return Err(Error::not_found(format!("server '{id}'")));
        };
        next.servers.remove(pos);
        next.validate_graph()?;
        Ok(next)
    }

    /// Rename a server, rewriting every slot reference. Fails if the new id
    /// collides with an existing server; the ORIGINAL is untouched.
    pub fn rename_server(&self, old: &str, new: &str) -> Result<ProjectConfig> {
        let new_id = Identifier::parse(new).map_err(|_| {
            Error::config(format!(
                "server id '{new}' must be a non-empty, well-formed identifier"
            ))
        })?;
        let mut next = self.clone();
        if !next.servers.iter().any(|s| s.id.as_str() == old) {
            return Err(Error::not_found(format!("server '{old}'")));
        }
        if next.servers.iter().any(|s| s.id.as_str() == new) {
            return Err(Error::config(format!("duplicate server id '{new}'")));
        }
        for server in &mut next.servers {
            if server.id.as_str() == old {
                server.id = new_id.clone();
            }
        }
        for variant in next.variants.values_mut() {
            for slot in &mut variant.slots {
                if slot.server == old {
                    slot.server = new.to_string();
                }
            }
        }
        next.validate_graph()?;
        Ok(next)
    }

    /// Add or replace a target (keyed by its name). A NEW target must already
    /// have at least one member slot (the per-target non-empty rule is
    /// re-validated), so adding a target with no slots fails; the ORIGINAL is
    /// untouched.
    pub fn with_target(&self, name: &str, target: TargetConfig) -> Result<ProjectConfig> {
        Identifier::parse(name).map_err(|_| {
            Error::config(format!(
                "target name '{name}' must be a non-empty, well-formed identifier"
            ))
        })?;
        let mut next = self.clone();
        next.targets.insert(name.to_string(), target);
        next.validate_graph()?;
        Ok(next)
    }

    /// Remove a target. Fails if any slot references it (the graph would
    /// dangle); the ORIGINAL is untouched.
    pub fn without_target(&self, name: &str) -> Result<ProjectConfig> {
        let mut next = self.clone();
        if next.targets.remove(name).is_none() {
            return Err(Error::not_found(format!("target '{name}'")));
        }
        next.validate_graph()?;
        Ok(next)
    }

    /// Rename a target, rewriting every slot reference. Fails if the new
    /// name collides with an existing target; the ORIGINAL is untouched.
    pub fn rename_target(&self, old: &str, new: &str) -> Result<ProjectConfig> {
        Identifier::parse(new).map_err(|_| {
            Error::config(format!(
                "target name '{new}' must be a non-empty, well-formed identifier"
            ))
        })?;
        let mut next = self.clone();
        let Some(target) = next.targets.remove(old) else {
            return Err(Error::not_found(format!("target '{old}'")));
        };
        if next.targets.contains_key(new) {
            return Err(Error::config(format!("duplicate target name '{new}'")));
        }
        next.targets.insert(new.to_string(), target);
        for variant in next.variants.values_mut() {
            for slot in &mut variant.slots {
                if slot.target == old {
                    slot.target = new.to_string();
                }
            }
        }
        next.validate_graph()?;
        Ok(next)
    }

    /// Add a durable retention pin. Pins carry no graph invariants, but the
    /// whole graph is still re-validated; the ORIGINAL is untouched.
    pub fn with_pin(&self, pin: Pin) -> Result<ProjectConfig> {
        let mut next = self.clone();
        next.pins.push(pin);
        next.validate_graph()?;
        Ok(next)
    }

    /// Remove every pin naming the given release. Fails if no pin names it;
    /// the ORIGINAL is untouched. The release is a typed [`ReleaseId`] (valid
    /// by construction), so a removed pin always names a grammar-valid
    /// release.
    pub fn without_pin(&self, release: &ReleaseId) -> Result<ProjectConfig> {
        let mut next = self.clone();
        let before = next.pins.len();
        next.pins.retain(|p| p.release != *release);
        if next.pins.len() == before {
            return Err(Error::not_found(format!("pin for release '{release}'")));
        }
        next.validate_graph()?;
        Ok(next)
    }

    /// Rename every pin naming `old` to name `new`. Fails if no pin names
    /// `old`; the ORIGINAL is untouched. Both ids are typed [`ReleaseId`]s, so
    /// `new` is valid by construction — the renamed pin always names a
    /// grammar-valid release.
    pub fn rename_pin(&self, old: &ReleaseId, new: &ReleaseId) -> Result<ProjectConfig> {
        let mut next = self.clone();
        let mut renamed = false;
        for pin in &mut next.pins {
            if pin.release == *old {
                pin.release = new.clone();
                renamed = true;
            }
        }
        if !renamed {
            return Err(Error::not_found(format!("pin for release '{old}'")));
        }
        next.validate_graph()?;
        Ok(next)
    }

    /// Add or replace a slot inside a variant (keyed by slot id).
    /// Re-validates the whole graph: a duplicate slot id, an unresolvable
    /// server/target reference, a relative deploy_dir, a shared location, or
    /// a target left without members fails the operation and the ORIGINAL is
    /// untouched.
    pub fn with_slot(&self, variant: &str, slot: SlotConfig) -> Result<ProjectConfig> {
        let mut next = self.clone();
        let Some(v) = next.variants.get_mut(variant) else {
            return Err(Error::not_found(format!("variant '{variant}'")));
        };
        if let Some(existing) = v.slots.iter_mut().find(|s| s.id == slot.id) {
            *existing = slot;
        } else {
            v.slots.push(slot);
        }
        next.validate_graph()?;
        Ok(next)
    }

    /// Remove a slot from a variant. Fails if the slot does not exist or its
    /// target would be left without members; the ORIGINAL is untouched.
    pub fn without_slot(&self, variant: &str, slot_id: &str) -> Result<ProjectConfig> {
        let mut next = self.clone();
        let Some(v) = next.variants.get_mut(variant) else {
            return Err(Error::not_found(format!("variant '{variant}'")));
        };
        let before = v.slots.len();
        v.slots.retain(|s| s.id != slot_id);
        if v.slots.len() == before {
            return Err(Error::not_found(format!(
                "slot '{slot_id}' in variant '{variant}'"
            )));
        }
        next.validate_graph()?;
        Ok(next)
    }

    /// Rename a slot inside a variant. Fails if the slot does not exist or
    /// the new id collides; the ORIGINAL is untouched.
    pub fn rename_slot(&self, variant: &str, old: &str, new: &str) -> Result<ProjectConfig> {
        let mut next = self.clone();
        let Some(v) = next.variants.get_mut(variant) else {
            return Err(Error::not_found(format!("variant '{variant}'")));
        };
        let mut renamed = false;
        for slot in &mut v.slots {
            if slot.id == old {
                slot.id = new.to_string();
                renamed = true;
            }
        }
        if !renamed {
            return Err(Error::not_found(format!(
                "slot '{old}' in variant '{variant}'"
            )));
        }
        next.validate_graph()?;
        Ok(next)
    }

    /// Replace a server's EXACTLY ONE connection form. Re-validates the
    /// whole graph (the connection enum must be well-formed); the ORIGINAL is
    /// untouched.
    pub fn with_server_connection(
        &self,
        id: &str,
        connection: ServerConnection,
    ) -> Result<ProjectConfig> {
        let mut next = self.clone();
        let Some(server) = next.servers.iter_mut().find(|s| s.id.as_str() == id) else {
            return Err(Error::not_found(format!("server '{id}'")));
        };
        server.connection = connection;
        next.validate_graph()?;
        Ok(next)
    }

    /// Replace a server's capacity headroom policy. Re-validates the whole
    /// graph; the ORIGINAL is untouched.
    pub fn with_server_capacity(
        &self,
        id: &str,
        capacity: CapacityConfig,
    ) -> Result<ProjectConfig> {
        let mut next = self.clone();
        let Some(server) = next.servers.iter_mut().find(|s| s.id.as_str() == id) else {
            return Err(Error::not_found(format!("server '{id}'")));
        };
        server.capacity = capacity;
        next.validate_graph()?;
        Ok(next)
    }

    /// Absolute release directory: forced to `<project>/releases/<release>`.
    pub fn release_root(&self, config_path: &Path) -> PathBuf {
        self.project_root(config_path)
            .join("releases")
            .join(self.release.as_str())
    }

    pub fn variant_names(&self) -> Vec<String> {
        self.variants.keys().cloned().collect()
    }

    pub fn variant(&self, name: &str) -> Result<&VariantConfig> {
        self.variants
            .get(name)
            .ok_or_else(|| Error::config(format!("unknown release variant '{name}'")))
    }

    /// Mutable access to one loaded variant (test-only: the engine resolves
    /// retention from the caller's current config, and tests that strengthen
    /// a slot's owning-variant policy need to mutate it in place).
    #[cfg(test)]
    pub(crate) fn variant_mut(&mut self, name: &str) -> Option<&mut VariantConfig> {
        self.variants.get_mut(name)
    }

    /// The aggregated slot declarations of every variant: each variant's
    /// `[[slots]]` entries in deterministic order — variants in name order
    /// (the `BTreeMap` is already sorted), then each variant's slots in file
    /// order.
    pub fn slot_defs(&self) -> Vec<&SlotConfig> {
        self.variants
            .values()
            .flat_map(|v| v.slots.iter())
            .collect()
    }

    /// The variant whose file declares the given slot: slots are declared
    /// inside a variant's file, so the declaring file IS the slot's variant
    /// binding.
    pub fn slot_variant(&self, slot_id: &str) -> Result<&str> {
        for (name, variant) in &self.variants {
            if variant.slots.iter().any(|s| s.id == slot_id) {
                return Ok(name);
            }
        }
        Err(Error::config(format!(
            "slot '{slot_id}' is not declared by any variant"
        )))
    }

    /// The slot's ONE retention policy: the retention config of the slot's
    /// OWNING VARIANT (the file that declares the slot). Retention is
    /// slot-owned — a shared slot's policy is resolved here, from a single
    /// source, regardless of how many targets the slot is a member of, so
    /// membership changes never change retention.
    pub fn slot_retention(&self, slot_id: &str) -> Result<&RetentionConfig> {
        let variant_name = self.slot_variant(slot_id)?;
        Ok(&self.variant(variant_name)?.retention)
    }

    /// Resolve a target's member slots, pairing each slot with its declared
    /// server. Membership is DERIVED from the slots' declared `target` field
    /// (targets do not list their slots): every slot whose ONE owning
    /// `target` equals `target_name`, in deterministic order — variants in
    /// name order, then each variant's slots in file order.
    pub fn target_slots(&self, target_name: &str) -> Result<Vec<(&SlotConfig, &ServerDef)>> {
        self.targets
            .get(target_name)
            .ok_or_else(|| Error::not_found(format!("target '{target_name}'")))?;
        let mut out = Vec::new();
        for slot in self.slot_defs() {
            if slot.target != target_name {
                continue;
            }
            let server = self
                .servers
                .iter()
                .find(|s| s.id.as_str() == slot.server)
                .ok_or_else(|| {
                    Error::config(format!(
                        "slot '{}' references unknown server '{}'",
                        slot.id, slot.server
                    ))
                })?;
            out.push((slot, server));
        }
        Ok(out)
    }

    /// Resolve the slots of `target_name` selected by a rollout group: every
    /// slot whose ONE owning `target` equals `target_name` AND whose `groups`
    /// list contains `group`, in the same deterministic order as
    /// [`ProjectConfig::target_slots`]. An unknown group, or a group selecting zero
    /// slots, is a configuration error (the caller's current configuration is
    /// the selection source, including for historical references).
    pub fn target_group_slots(
        &self,
        target_name: &str,
        group: &str,
    ) -> Result<Vec<(&SlotConfig, &ServerDef)>> {
        let all = self.target_slots(target_name)?;
        let selected: Vec<(&SlotConfig, &ServerDef)> = all
            .into_iter()
            .filter(|(slot, _)| slot.groups.iter().any(|g| g == group))
            .collect();
        if selected.is_empty() {
            return Err(Error::config(format!(
                "group '{group}' selects no slots of target '{target_name}'"
            )));
        }
        Ok(selected)
    }

    /// The slot IDs of a target's members, in the same deterministic order as
    /// [`ProjectConfig::target_slots`].
    pub fn target_slot_ids(&self, target_name: &str) -> Result<Vec<String>> {
        Ok(self
            .target_slots(target_name)?
            .into_iter()
            .map(|(slot, _)| slot.id.clone())
            .collect())
    }

    /// The slot→physical-binding map for a target, keyed by placement slot
    /// ID: the complete `{server, deploy_dir}` binding ([`PhysicalBinding`])
    /// each slot currently has in the configuration — the physical server
    /// AND the absolute on-server directory its deployment state lives in.
    /// Used to record (and later verify) the exact physical location a
    /// deployment snapshot's slots were deployed onto: exact rollback must
    /// see BOTH halves unchanged, because a slot that keeps its server but
    /// moves its `deploy_dir` would otherwise roll back onto the new
    /// location.
    pub fn target_slot_bindings(
        &self,
        target_name: &str,
    ) -> Result<BTreeMap<SlotId, PhysicalBinding>> {
        Ok(self
            .target_slots(target_name)?
            .into_iter()
            .map(|(slot, server)| {
                (
                    SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment"),
                    PhysicalBinding {
                        server: ServerId::parse(server.id.as_str())
                            .expect("validated server id is a safe segment"),
                        deploy_dir: slot.deploy_dir.to_string_lossy().into_owned(),
                    },
                )
            })
            .collect())
    }
}

/// The complete raw deserialized input of one project: the manifest plus the
/// discovered variant files. This is what the conversion validates.
#[derive(Clone, Debug)]
pub(crate) struct RawProject {
    pub manifest: raw::RawConfig,
    pub variants: BTreeMap<String, raw::RawVariant>,
}

/// An identifier is valid when it is non-empty after trimming (any Unicode
/// content is allowed; an empty or whitespace-only identifier cannot name a
/// server, slot, target, or variant). Kept for the test-side domain invariant
/// assertions; the CONVERSION gates identifiers through the stricter
/// [`crate::scalar::Identifier`] parse (which additionally rejects surrounding
/// whitespace and control characters).
#[cfg(test)]
fn valid_identifier(id: &str) -> bool {
    !id.trim().is_empty()
}

/// The total-fail-closed raw -> domain conversion. ANY violation rejects the
/// whole conversion:
///
/// * the schema-version gate,
/// * identifier validity (non-empty, unique where uniqueness is required),
/// * reference resolution: slot -> server, slot -> target, variant names,
/// * the activation enum (unknown adapters rejected, systemd needs units),
/// * exactly-one host identity per SSH server (plus the format rules for
///   each identity source),
/// * group names (non-empty, unique per slot), deploy_dir absoluteness,
/// * one-slot-per-server-per-target, a target without slots, duplicate
///   (server, deploy_dir) locations, mapping destination collisions.
impl TryFrom<RawProject> for ProjectConfig {
    type Error = Error;

    fn try_from(project: RawProject) -> Result<ProjectConfig> {
        let RawProject { manifest, variants } = project;

        // The schema version is a hard gate: an unrecognized version is
        // never interpreted.
        if manifest.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(Error::config(format!(
                "unsupported schema_version {} (expected {CONFIG_SCHEMA_VERSION})",
                manifest.schema_version
            )));
        }

        // Every pin's release must satisfy the EXACT `rel-sha256-<64
        // lowercase hex>` grammar: the raw wire string is parsed into the
        // typed [`ReleaseId`] HERE, at the load — a malformed pin string
        // fails the WHOLE conversion (fail closed, like the sibling
        // identifier gates), stopping at the FIRST bad pin. A successfully
        // loaded configuration therefore can never carry a pin whose
        // release would later fail [`ReleaseId::parse`].
        let pins = manifest
            .pins
            .into_iter()
            .map(Pin::try_from)
            .collect::<Result<Vec<_>>>()?;

        // The release name must be exactly one directory component so it
        // cannot escape the forced `releases/` directory.
        validate_release_name(manifest.release.as_str())?;
        if variants.is_empty() {
            return Err(Error::config(
                "at least one release variant must be declared",
            ));
        }
        if manifest.targets.is_empty() {
            return Err(Error::config("at least one target must be declared"));
        }

        // The application name is parsed into the validated single safe
        // path segment [`crate::scalar::ApplicationStoreKey`]: an
        // application name that is not a safe store key (empty,
        // control-bearing, `/`/`\`-separated, `.`/`..`, or padded) is
        // rejected HERE — at the LOAD, fail closed — so a successfully
        // loaded config always constructs its store. ONE safe application
        // identifier is used for both display and storage.
        let application = ApplicationStoreKey::parse(&manifest.application).map_err(|_| {
            Error::config(
                "application must be a single safe name (no '/', '\\', '.', '..', or whitespace)",
            )
        })?;

        // Each loaded variant carries its own artifact/activation/verification
        // policy; validate each one and build the domain variant (the raw
        // `adapter` string becomes the typed [`Activation`] enum).
        let mut domain_variants = BTreeMap::new();
        for (vname, variant) in &variants {
            Identifier::parse(vname).map_err(|_| {
                Error::config(format!(
                    "variant name '{vname}' must be a non-empty, well-formed identifier"
                ))
            })?;
            let activation = match variant.activation.adapter.as_str() {
                "none" => Activation::None,
                "systemd" => {
                    if variant.activation.units.is_empty() {
                        return Err(Error::config(format!(
                            "variant '{vname}': systemd activation requires at least one unit"
                        )));
                    }
                    Activation::Systemd(SystemdActivation {
                        scope: variant.activation.scope.clone(),
                        reconcile_managed_units: variant.activation.reconcile_managed_units,
                        units: variant.activation.units.clone(),
                    })
                }
                other => {
                    return Err(Error::config(format!(
                        "variant '{vname}': unknown activation adapter '{other}'"
                    )));
                }
            };
            if variant.verification.adapter != "command" {
                return Err(Error::config(format!(
                    "variant '{vname}': unsupported verification adapter '{}'",
                    variant.verification.adapter
                )));
            }
            if variant.verification.argv.is_empty() {
                return Err(Error::config(format!(
                    "variant '{vname}': verification argv must not be empty"
                )));
            }

            // Validate mapping modes and artifact-relative destinations.
            for (i, m) in variant.artifact.mappings.iter().enumerate() {
                if let Some(mode) = &m.mode
                    && mode != "preserve"
                {
                    parse_octal_mode(mode).map_err(|e| {
                        Error::config(format!("variant '{vname}' mapping[{i}] mode: {e}"))
                    })?;
                }
                if m.from.trim().is_empty() || m.to.trim().is_empty() {
                    return Err(Error::config(format!(
                        "variant '{vname}' mapping[{i}] requires non-empty from/to"
                    )));
                }
                validate_relative_path(Path::new(&m.to)).map_err(|e| {
                    Error::config(format!("variant '{vname}' mapping[{i}] to: {e}"))
                })?;
            }

            // No overlapping destinations: identical `to` values, or one
            // destination nested beneath another mapping's destination, would
            // make the materialized tree declaration-order-dependent.
            let mappings = &variant.artifact.mappings;
            for i in 0..mappings.len() {
                for j in (i + 1)..mappings.len() {
                    if destinations_overlap(&mappings[i].to, &mappings[j].to) {
                        return Err(Error::config(format!(
                            "variant '{vname}' mapping destinations overlap: \
                             mappings[{i}] '{}' and mappings[{j}] '{}'",
                            mappings[i].to, mappings[j].to
                        )));
                    }
                }
            }

            domain_variants.insert(
                vname.clone(),
                VariantConfig {
                    description: variant.description.clone(),
                    artifact: variant.artifact.clone(),
                    activation,
                    verification: variant.verification.clone(),
                    slots: variant.slots.clone(),
                    retention: variant.retention.clone(),
                },
            );
        }

        // Server declarations are unique and well-formed; capacity is a
        // per-server policy, so its validation lives here.
        let mut all_server_ids: HashSet<String> = HashSet::new();
        let mut domain_servers = Vec::with_capacity(manifest.servers.len());
        for s in &manifest.servers {
            // The server id is parsed into the validated [`Identifier`]
            // scalar (non-empty, well-formed) and STORED as the scalar in
            // the domain server.
            let id = Identifier::parse(&s.id).map_err(|_| {
                Error::config(format!(
                    "server id '{}' must be a non-empty, well-formed identifier",
                    s.id
                ))
            })?;
            if !all_server_ids.insert(id.as_str().to_string()) {
                return Err(Error::config(format!(
                    "duplicate server id '{}' in top-level servers",
                    s.id
                )));
            }
            // The capacity percent is parsed into the validated 0..=100
            // [`CapacityPercent`] scalar (replacing the bare out-of-range
            // check with the scalar's own gate).
            let reserve_percent =
                CapacityPercent::new(s.capacity.reserve_percent).map_err(|_| {
                    Error::config(format!(
                        "server '{}': reserve_percent must be within 0..=100",
                        s.id
                    ))
                })?;
            // Collapse the raw identity pair into the ONE validated form
            // (the per-source format checks apply to every server; the
            // exactly-one rule is scoped to SSH addresses).
            let identity = validate_server_identity(s)?;
            // Build the EXACTLY ONE connection form: a `local://` address
            // becomes `Local` (the path after the prefix must be absolute —
            // the transport is rooted there), an SSH address becomes `Ssh`
            // with the validated host/user/nonzero port and the exactly-one
            // host identity.
            let connection = if s.address.starts_with("local://") {
                let path = s.address.trim_start_matches("local://");
                if !Path::new(path).is_absolute() {
                    return Err(Error::config(format!(
                        "server '{}': local:// endpoint must be an absolute path",
                        s.id
                    )));
                }
                ServerConnection::Local {
                    address: s.address.clone(),
                    identity,
                }
            } else {
                let address = Host::parse(&s.address).map_err(|_| {
                    Error::config(format!(
                        "server '{}': address '{}' must be a well-formed SSH host",
                        s.id, s.address
                    ))
                })?;
                let user = SshUser::parse(&s.user).map_err(|_| {
                    Error::config(format!(
                        "server '{}': user '{}' must be a well-formed SSH user",
                        s.id, s.user
                    ))
                })?;
                let port = NonZeroU16::new(s.port).ok_or_else(|| {
                    Error::config(format!(
                        "server '{}': port must be nonzero (got {})",
                        s.id, s.port
                    ))
                })?;
                ServerConnection::Ssh {
                    address,
                    user,
                    port,
                    identity,
                }
            };
            domain_servers.push(ServerDef {
                id,
                connection,
                capacity: CapacityConfig {
                    reserve_bytes: s.capacity.reserve_bytes,
                    reserve_percent,
                },
            });
        }

        // Slots are declared INSIDE each variant's file (the declaring file
        // is the slot's variant binding), so they are aggregated across every
        // variant: IDs are unique across ALL variants, each slot's server must
        // exist among the top-level `[[servers]]` entries, each slot's ONE
        // owning `target` must exist among the top-level `[targets.<name>]`
        // keys, each group name must be non-empty and not repeated (a
        // duplicate adds no membership yet would change release identity),
        // and a (server, deploy_dir) pair names one on-server deployment
        // location that exactly one slot may own.
        let mut slot_ids = HashSet::new();
        let mut bound_locations: BTreeMap<(&str, &Path), &str> = BTreeMap::new();
        for (vname, variant) in &domain_variants {
            for p in &variant.slots {
                // The slot's id-bearing fields are parsed into the validated
                // [`Identifier`] scalar (non-empty, well-formed) before any
                // graph rule runs.
                Identifier::parse(&p.id).map_err(|_| {
                    Error::config(format!(
                        "variant '{vname}': slot id '{}' must be a non-empty, well-formed identifier",
                        p.id
                    ))
                })?;
                Identifier::parse(&p.server).map_err(|_| {
                    Error::config(format!(
                        "variant '{vname}': slot '{}' server '{}' must be a non-empty, well-formed identifier",
                        p.id, p.server
                    ))
                })?;
                Identifier::parse(&p.target).map_err(|_| {
                    Error::config(format!(
                        "variant '{vname}': slot '{}' target '{}' must be a non-empty, well-formed identifier",
                        p.id, p.target
                    ))
                })?;
                if !slot_ids.insert(p.id.clone()) {
                    return Err(Error::config(format!(
                        "duplicate slot id '{}' (declared by variant '{vname}')",
                        p.id
                    )));
                }
                if !all_server_ids.contains(p.server.as_str()) {
                    return Err(Error::config(format!(
                        "variant '{vname}': slot '{}' references unknown server '{}'",
                        p.id, p.server
                    )));
                }
                if !manifest.targets.contains_key(&p.target) {
                    return Err(Error::config(format!(
                        "variant '{vname}': slot '{}' references unknown target '{}'",
                        p.id, p.target
                    )));
                }
                let mut seen_groups = HashSet::new();
                for g in &p.groups {
                    // Each group name is parsed into the validated
                    // [`RolloutGroupName`] scalar (non-empty, well-formed); the
                    // DUPLICATE rule is structural and stays here (a
                    // duplicate adds no membership yet would change the
                    // release identity).
                    RolloutGroupName::parse(g).map_err(|_| {
                        Error::config(format!(
                            "variant '{vname}': slot '{}' declares an invalid group name {g:?}",
                            p.id
                        ))
                    })?;
                    if !seen_groups.insert(g) {
                        return Err(Error::config(format!(
                            "variant '{vname}': slot '{}' declares duplicate group '{}'",
                            p.id, g
                        )));
                    }
                }
                // The deploy_dir is validated by the [`AbsoluteDeployDir`]
                // scalar (absolute path on the server).
                AbsoluteDeployDir::parse(&p.deploy_dir.to_string_lossy()).map_err(|_| {
                    Error::config(format!(
                        "variant '{vname}': slot '{}' deploy_dir must be an absolute path on the server",
                        p.id
                    ))
                })?;
                if let Some(existing) =
                    bound_locations.get(&(p.server.as_str(), p.deploy_dir.as_path()))
                {
                    return Err(Error::config(format!(
                        "slots '{existing}' and '{}' bind the same location (server '{}', deploy_dir '{}'); each server+deploy_dir pair must belong to exactly one slot",
                        p.id,
                        p.server,
                        p.deploy_dir.display()
                    )));
                }
                bound_locations.insert((p.server.as_str(), p.deploy_dir.as_path()), &p.id);
            }
        }

        // Targets carry ROLLOUT behavior only. Each target name is parsed
        // into the validated [`Identifier`] scalar, and each target's raw
        // integer `batch_size` is parsed into the validated NONZERO
        // [`BatchSize`] scalar (a zero batch would stall the rollout without
        // ever progressing — a NEW fail-closed gate the raw shape allows).
        let mut domain_targets = BTreeMap::new();
        for (tname, raw_target) in &manifest.targets {
            Identifier::parse(tname).map_err(|_| {
                Error::config(format!(
                    "target name '{tname}' must be a non-empty, well-formed identifier"
                ))
            })?;
            let batch_size =
                BatchSize::new(u64::from(raw_target.rollout.batch_size)).map_err(|_| {
                    Error::config(format!(
                        "target '{tname}': batch_size must be a nonzero integer (got {})",
                        raw_target.rollout.batch_size
                    ))
                })?;
            domain_targets.insert(
                tname.clone(),
                TargetConfig {
                    rollout: RolloutConfig {
                        batch_size,
                        stop_on_failure: raw_target.rollout.stop_on_failure,
                        failure_policy: raw_target.rollout.failure_policy,
                    },
                },
            );
        }

        // A target's members are DERIVED by scanning every variant's slots for
        // the target name. One server runs exactly one generation, so two
        // member slots of the same target can never share a server — and a
        // target must have at least one member. A slot has EXACTLY ONE owning
        // target, so the per-target checks run once per slot (its owner) and
        // the same two slots can never share a server in DIFFERENT targets.
        for tname in manifest.targets.keys() {
            let mut used_servers = HashSet::new();
            let mut members = 0;
            for slot in domain_variants.values().flat_map(|v| v.slots.iter()) {
                if slot.target != *tname {
                    continue;
                }
                members += 1;
                if !used_servers.insert(slot.server.as_str()) {
                    return Err(Error::config(format!(
                        "target '{tname}' has multiple slots on server '{}'",
                        slot.server
                    )));
                }
            }
            if members == 0 {
                return Err(Error::config(format!("target '{tname}' has no slots")));
            }
        }

        Ok(ProjectConfig {
            schema_version: manifest.schema_version,
            application,
            release: manifest.release,
            pins,
            servers: domain_servers,
            targets: domain_targets,
            variants: domain_variants,
        })
    }
}

/// Resolve one raw server's identity pair into the single validated
/// [`HostIdentity`] form. The per-source well-formedness checks (absolute
/// `known_hosts`, `SHA256:` fingerprint) apply to every server; the
/// exactly-one rule applies to SSH addresses only — a `local://` endpoint
/// never performs host verification, so its identity is always `Local`.
fn validate_server_identity(server: &raw::RawServer) -> Result<HostIdentity> {
    if let Some(kh) = &server.known_hosts
        && !kh.is_absolute()
    {
        return Err(Error::config(format!(
            "server '{}' known_hosts must be an absolute path",
            server.id
        )));
    }
    if let Some(fp) = &server.host_key_fingerprint
        && !fp.starts_with("SHA256:")
    {
        return Err(Error::config(format!(
            "server '{}' host_key_fingerprint must be a SHA256:... value",
            server.id
        )));
    }
    if server.address.starts_with("local://") {
        return Ok(HostIdentity::Local);
    }
    match (&server.known_hosts, &server.host_key_fingerprint) {
        (Some(_), Some(_)) => Err(Error::config(format!(
            "server '{}': known_hosts and host_key_fingerprint are mutually exclusive; configure exactly one",
            server.id
        ))),
        (None, None) => Err(Error::config(format!(
            "server '{}': exactly one of known_hosts or host_key_fingerprint must be configured for an SSH address (trust-on-first-use is disabled)",
            server.id
        ))),
        (Some(kh), None) => Ok(HostIdentity::KnownHosts(kh.clone())),
        (None, Some(fp)) => Ok(HostIdentity::Fingerprint(Fingerprint::parse(fp)?)),
    }
}

/// Parse an octal mode string such as `"0644"` into a `u32`.
pub fn parse_octal_mode(s: &str) -> Result<u32> {
    let s = s.trim();
    let digits: String = s.chars().filter(|c| *c != '_').collect();
    u32::from_str_radix(&digits, 8).map_err(|_| Error::config(format!("invalid octal mode '{s}'")))
}

/// Resolve an activation mode override, returning `None` when `preserve`.
pub fn resolved_mode(mode: &Option<String>) -> Result<Option<u32>> {
    match mode {
        None => Ok(None),
        Some(m) if m == "preserve" => Ok(None),
        Some(m) => Ok(Some(parse_octal_mode(m)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ArtifactRef, LEDGER_SCHEMA_VERSION, TargetName, VariantName, test_deployment_id,
        test_generation_id, test_tree_digest,
    };
    use crate::records::{
        DeploymentIntent, DesiredGeneration, IntentSlot, LedgerIntentWire, LedgerLine,
        NonEmptySlotTable,
    };
    use crate::store::local::LocalStore;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::path::Path;

    #[test]
    fn relative_path_validation() {
        assert!(validate_relative_path(Path::new("app/server")).is_ok());
        assert!(validate_relative_path(Path::new("nested/deep/file.conf")).is_ok());
        // Absolute paths are rejected.
        assert!(validate_relative_path(Path::new("/etc/passwd")).is_err());
        // Single-level parent escape is rejected.
        assert!(validate_relative_path(Path::new("../escape")).is_err());
        // Nested escapes are rejected.
        assert!(validate_relative_path(Path::new("nested/../../escape")).is_err());
    }

    #[test]
    fn mapping_to_must_be_artifact_relative() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        let variant_toml = r#"
description = "escaping"

[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/esc"

[[artifact.mappings]]
from = "build/output/"
to = "../escape"
recursive = true

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
        std::fs::write(release_dir.join("standard.toml"), variant_toml).unwrap();
        let deploy_toml = r#"
schema_version = 2
application = "esc"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml).unwrap();
        assert!(
            ProjectConfig::load(&p).is_err(),
            "escaping mapping `to` must be rejected"
        );
    }

    #[test]
    fn overlapping_mapping_destinations_are_rejected_at_load() {
        // Two mappings whose destinations overlap (identical, or one nested
        // beneath the other) are rejected at config load: the materialized
        // tree would depend on declaration order.
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        let deploy_toml = r#"
schema_version = 2
application = "ovl"
release = "v1"


[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml).unwrap();

        // Identical destinations (with and without the trailing slash).
        std::fs::write(
            release_dir.join("standard.toml"),
            "[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/ovl\"\n\n\
             [[artifact.mappings]]\nfrom = \"a/\"\nto = \"app/\"\nrecursive = true\n\n\
             [[artifact.mappings]]\nfrom = \"b/\"\nto = \"app\"\nrecursive = true\n\n\
             [activation]\nadapter = \"none\"\n\n\
             [verification]\nadapter = \"command\"\nargv = [\"true\"]\ntimeout_seconds = 5\nattempts = 1\ninterval_seconds = 0\n",
        )
        .unwrap();
        let err = ProjectConfig::load(&p).expect_err("identical destinations must be rejected");
        assert!(
            err.to_string().contains("overlap"),
            "error must name the overlap, got: {err}"
        );

        // A nested `to` descending into another mapping's `to` tree.
        std::fs::write(
            release_dir.join("standard.toml"),
            "[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/ovl\"\n\n[[artifact.mappings]]\nfrom = \"a/\"\nto = \"app/\"\nrecursive = true\n\n\
             [[artifact.mappings]]\nfrom = \"b/\"\nto = \"app/nested/\"\nrecursive = true\n\n\
             [activation]\nadapter = \"none\"\n\n\
             [verification]\nadapter = \"command\"\nargv = [\"true\"]\ntimeout_seconds = 5\nattempts = 1\ninterval_seconds = 0\n",
        )
        .unwrap();
        let err = ProjectConfig::load(&p).expect_err("nested destinations must be rejected");
        assert!(
            err.to_string().contains("overlap"),
            "error must name the overlap, got: {err}"
        );

        // Non-overlapping destinations still load.
        std::fs::write(
            release_dir.join("standard.toml"),
            "[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/ovl\"\n\n[[artifact.mappings]]\nfrom = \"a/\"\nto = \"app/\"\nrecursive = true\n\n\
             [[artifact.mappings]]\nfrom = \"b/\"\nto = \"other/\"\nrecursive = true\n\n\
             [activation]\nadapter = \"none\"\n\n\
             [verification]\nadapter = \"command\"\nargv = [\"true\"]\ntimeout_seconds = 5\nattempts = 1\ninterval_seconds = 0\n",
        )
        .unwrap();
        ProjectConfig::load(&p).expect("non-overlapping destinations load");
    }

    #[test]
    fn loads_variant_config_from_release_directory() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();

        let standard_toml = r#"
description = "Standard deployment"

[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/example"

[[artifact.mappings]]
from = "build/output/"
to = "app/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[retention.deployment]
protect_deployments = 2

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
        let hc_toml = r#"
description = "High capacity deployment"

[[artifact.mappings]]
from = "build/output/"
to = "app/"
recursive = true

[activation]
adapter = "systemd"
scope = "user"
units = [{ name = "x.service", artifact_path = "integration/systemd/x.service", enable = true, restart = true }]

[verification]
adapter = "command"
argv = ["false"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
        std::fs::write(release_dir.join("standard.toml"), standard_toml).unwrap();
        std::fs::write(release_dir.join("high-capacity.toml"), hc_toml).unwrap();

        let deploy_toml = r#"
schema_version = 2
application = "example"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"
capacity = { reserve_bytes = 1073741824, reserve_percent = 5 }

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml).unwrap();

        let cfg = ProjectConfig::load(&p).expect("config loads with sibling variant files");
        // Retention is SLOT-OWNED: the policy lives on the owning variant
        // (`standard` declares slot `p1`), never on the target.
        assert_eq!(
            cfg.variant("standard")
                .unwrap()
                .retention
                .per_server
                .keep_distinct_artifacts,
            5
        );
        assert_eq!(
            cfg.variant("standard")
                .unwrap()
                .retention
                .deployment
                .protect_deployments,
            2
        );
        assert_eq!(
            cfg.slot_retention("p1")
                .unwrap()
                .per_server
                .keep_distinct_artifacts,
            5,
            "slot_retention resolves the owning variant's policy"
        );
        let names = cfg.variant_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"standard".to_string()));
        assert!(names.contains(&"high-capacity".to_string()));

        let std = cfg.variant("standard").expect("standard variant present");
        assert_eq!(std.verification.argv, vec!["true".to_string()]);
        assert_eq!(std.activation, Activation::None);

        let hc = cfg
            .variant("high-capacity")
            .expect("high-capacity variant present");
        assert_eq!(hc.verification.argv, vec!["false".to_string()]);
        let Activation::Systemd(hc_act) = &hc.activation else {
            panic!("high-capacity variant must carry the systemd activation");
        };
        assert!(!hc_act.units.is_empty());

        // Capacity is per-server, not per-variant: the single server carries
        // the policy and the variant files parse without any `[capacity]` block.
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].capacity.reserve_bytes, 1073741824);
        assert_eq!(cfg.servers[0].capacity.reserve_percent.get(), 5);
        assert_eq!(cfg.variant("standard").unwrap().artifact.mappings.len(), 1);

        // Unknown variant name is rejected.
        assert!(cfg.variant("missing").is_err());
    }

    const MINIMAL_VARIANT: &str = r#"
[artifact]
mappings = []

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

    /// The default slot body appended to the `standard` variant file used by
    /// the tests below: `p1` on server `s1`, belonging to target `t1`. Slots
    /// are declared inside the variant file that owns the workload and bind
    /// themselves to targets with the `targets` list; a target's members are
    /// derived from these declarations.
    const STANDARD_SLOTS: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/forced"
"#;

    /// The `standard` variant's retention policy — the single retention
    /// source for its declared slot `p1` (a slot's owning variant owns its
    /// policy; targets carry rollout only).
    const STANDARD_ROTATION: &str = r#"
[retention.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[retention.deployment]
protect_deployments = 1
"#;

    fn deploy_toml(release_value: &str) -> String {
        format!(
            r#"
schema_version = 2
application = "forced"
release = "{release_value}"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }}
"#
        )
    }

    fn write_standard_release(project: &Path, release: &str) {
        let release_dir = project.join("releases").join(release);
        std::fs::create_dir_all(&release_dir).unwrap();
        // The standard variant file declares the `p1` slot the `deploy_toml()`
        // target references AND owns its retention policy (retention lives in
        // the variant file, not on the target).
        std::fs::write(
            release_dir.join("standard.toml"),
            format!("{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n{STANDARD_ROTATION}"),
        )
        .unwrap();
    }

    #[test]
    fn forced_structure_discovers_variant_files() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        // Non-variant entries inside the release directory are ignored.
        std::fs::create_dir_all(project.join("releases/v1/artifacts")).unwrap();
        std::fs::write(project.join("releases/v1/README.md"), "notes").unwrap();
        std::fs::write(project.join("releases/v1/.hidden.toml"), MINIMAL_VARIANT).unwrap();
        std::fs::write(project.join("releases/v1/other.yml"), MINIMAL_VARIANT).unwrap();
        std::fs::write(
            project.join("releases/v1/high-capacity.toml"),
            MINIMAL_VARIANT,
        )
        .unwrap();

        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml("v1")).unwrap();
        let cfg = ProjectConfig::load(&p).expect("config loads from the forced structure");
        assert_eq!(cfg.release().as_str(), "v1");
        assert_eq!(
            cfg.variant_names(),
            vec!["high-capacity".to_string(), "standard".to_string()],
            "every *.toml file stem is a variant; other entries are ignored"
        );
        assert_eq!(cfg.release_root(&p), project.join("releases").join("v1"));
    }

    #[test]
    fn release_name_map_form_is_rejected_with_migration_hint() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        // The pre-forcing deploy.toml shape (release as a map) must not parse
        // silently.
        let legacy_toml = r#"
schema_version = 2
application = "legacy"
release = { path = "releases/v1", variants = { standard = "standard.toml" } }

[[servers]]
id = "s1"
address = "a"
user = "u"

[[slots]]
id = "p1"
server = "s1"
variant = "standard"
deploy_dir = "/srv/legacy"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
slots = ["p1"]
"#;
        let p = project.join("deploy.toml");
        std::fs::write(&p, legacy_toml).unwrap();
        let err = ProjectConfig::load(&p).expect_err("old release map form must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("release: <name>"),
            "error must explain the forced structure, got: {msg}"
        );
    }

    #[test]
    fn release_name_must_be_a_single_directory_component() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        for bad in ["../v1", "a/b", ".", "..", "/abs"] {
            let p = project.join("deploy.toml");
            std::fs::write(&p, deploy_toml(bad)).unwrap();
            assert!(
                ProjectConfig::load(&p).is_err(),
                "release name '{bad}' must be rejected"
            );
        }
    }

    #[test]
    fn missing_release_directory_errors_with_structure_hint() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml("v9")).unwrap();
        let err = ProjectConfig::load(&p).expect_err("missing release dir must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("releases/v9") || msg.contains("releases") && msg.contains("v9"),
            "error must point at the forced release directory, got: {msg}"
        );
    }

    #[test]
    fn release_directory_without_variants_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(project.join("releases/v1")).unwrap();
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml("v1")).unwrap();
        let err = ProjectConfig::load(&p).expect_err("empty release dir must fail");
        assert!(
            err.to_string().contains("no variants"),
            "error must mention the missing variant files, got: {err}"
        );
    }

    /// Every target named in a slot's `targets` list must be a top-level
    /// `[targets.<name>]` key: membership is derived from the slot
    /// declarations, so a slot bound to an undeclared target is a
    /// configuration error.
    #[test]
    fn slot_target_must_reference_declared_target() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml("v1")).unwrap();
        let bad_variant = format!(
            "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntarget = \"ghost\"\ndeploy_dir = \"/srv/forced\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), bad_variant).unwrap();
        let err = ProjectConfig::load(&p).expect_err("unknown target reference must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("references unknown target 'ghost'") && msg.contains("variant 'standard'"),
            "error must name the unknown target and the declaring variant, got: {msg}"
        );
    }

    /// A slot may be a member of SEVERAL targets: membership is a `targets`
    /// list, and each target's members are DERIVED by scanning the slots for
    /// its name. A slot in two targets is valid and both targets derive it;
    /// a target with no member slot is still rejected.
    #[test]
    fn slots_declare_their_target_membership() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let p = project.join("deploy.toml");

        // A second slot, declared in the same variant file, belongs to a
        // second target (disjoint targets, disjoint memberships).
        let standard_toml = format!(
            "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntarget = \"t2\"\ndeploy_dir = \"/srv/forced-2\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), standard_toml).unwrap();
        let t2 = "\n[targets.t2]\nrollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }\n";
        std::fs::write(&p, format!("{}{}", deploy_toml("v1"), t2)).unwrap();
        let cfg = ProjectConfig::load(&p).expect("slots spread across targets are valid");
        assert_eq!(cfg.targets.len(), 2);
        assert_eq!(cfg.slot_defs().len(), 2);
        // Membership is derived from each slot's declared targets list.
        assert_eq!(cfg.target_slot_ids("t1").unwrap(), vec!["p1"]);
        assert_eq!(cfg.target_slot_ids("t2").unwrap(), vec!["p2"]);

        // A slot has EXACTLY ONE owning target; a rollout group selects a
        // subset of the target's slots (`deploy push t1 --group <name>`).
        let grouped = format!(
            "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntarget = \"t1\"\ngroups = [\"canary\"]\ndeploy_dir = \"/srv/forced\"\n\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntarget = \"t2\"\ndeploy_dir = \"/srv/forced-2\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), grouped).unwrap();
        let cfg = ProjectConfig::load(&p).expect("a slot with a rollout group is valid");
        assert_eq!(cfg.target_slot_ids("t1").unwrap(), vec!["p1"]);
        assert_eq!(
            cfg.target_group_slots("t1", "canary").unwrap().len(),
            1,
            "the group selects the slot"
        );
        assert!(
            cfg.target_group_slots("t1", "missing").is_err(),
            "an unknown group is a configuration error"
        );

        // A target with NO member slot is rejected.
        let t3 = "\n[targets.t3]\nrollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }\n";
        std::fs::write(&p, format!("{}{}{}", deploy_toml("v1"), t2, t3)).unwrap();
        let err = ProjectConfig::load(&p).expect_err("target without slots must fail");
        assert!(
            err.to_string().contains("target 't3' has no slots"),
            "error must name the empty target, got: {err}"
        );
    }

    /// A slot with an EMPTY `targets` list belongs to no target and is
    /// useless (mirroring the rule that a target must have at least one
    /// member), so it is rejected at validation.
    #[test]
    fn slot_with_no_targets_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml("v1")).unwrap();
        // The `target` key is omitted entirely: it is REQUIRED (a slot has
        // exactly one owning target), so the parse fails closed.
        let no_target = format!(
            "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ndeploy_dir = \"/srv/forced\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), no_target).unwrap();
        let err = ProjectConfig::load(&p).expect_err("slot without a target must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("missing field `target`") && msg.contains("variant 'standard'"),
            "error must name the missing target and the slot's variant, got: {msg}"
        );
    }

    /// Slots are declared inside the variant files, so the server reference of
    /// a variant's slot must resolve against the top-level `[[servers]]` list
    /// — reported against the declaring variant — and the slot's variant
    /// binding IS the declaring file.
    #[test]
    fn slots_must_reference_known_servers() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");

        // A slot bound to a server that does not exist (declared in the
        // variant file, reported with the variant context).
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml("v1")).unwrap();
        let bad_variant = format!(
            "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p1\"\nserver = \"ghost\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/forced\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), bad_variant).unwrap();
        let err = ProjectConfig::load(&p).expect_err("slot with unknown server must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("references unknown server 'ghost'") && msg.contains("variant 'standard'"),
            "error must name the unknown server and the declaring variant, got: {msg}"
        );

        // The declaring file is the slot's variant binding: `slot_variant`
        // resolves the slot to the file that declares it.
        std::fs::write(
            project.join("releases/v1/standard.toml"),
            format!("{MINIMAL_VARIANT}\n{STANDARD_SLOTS}"),
        )
        .unwrap();
        let cfg = ProjectConfig::load(&p).unwrap();
        assert_eq!(cfg.slot_variant("p1").unwrap(), "standard");
        assert!(cfg.slot_variant("ghost-slot").is_err());
    }

    #[test]
    fn duplicate_slot_ids_across_variants_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        // A second variant declares a slot with the SAME id: the id must be
        // unique across every variant's slots.
        let dup = format!("{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n");
        std::fs::write(project.join("releases/v1/high-capacity.toml"), dup).unwrap();
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml("v1")).unwrap();
        let err = ProjectConfig::load(&p).expect_err("duplicate slot id across variants must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("duplicate slot id 'p1'") && msg.contains("variant 'standard'"),
            "error must name the duplicate id and the variant where the collision was found, got: {msg}"
        );
    }

    #[test]
    fn duplicate_target_names_in_a_slot_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        // A slot declaring the same group twice: the duplicate adds no
        // membership yet would change release identity, so it is rejected.
        let dup = format!(
            "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntarget = \"t1\"\ngroups = [\"canary\", \"canary\"]\ndeploy_dir = \"/srv/forced\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), dup).unwrap();
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml("v1")).unwrap();
        let err = ProjectConfig::load(&p).expect_err("duplicate group name in a slot must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("duplicate group 'canary'") && msg.contains("slot 'p1'"),
            "error must name the duplicate group and the slot, got: {msg}"
        );
    }

    #[test]
    fn slots_on_the_same_server_never_share_a_deploy_dir() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let p = project.join("deploy.toml");

        // Second slot in the same variant file, same server, SAME deploy_dir:
        // rejected (the location collision fires regardless of target).
        let dup = format!(
            "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/forced\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), dup).unwrap();
        std::fs::write(&p, deploy_toml("v1")).unwrap();
        let err = ProjectConfig::load(&p).expect_err("shared server+deploy_dir must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("same location") && msg.contains("p1") && msg.contains("p2"),
            "error must name the colliding slots, got: {msg}"
        );

        // A DIFFERENT variant file declares p2 with a DIFFERENT deploy_dir on
        // the same server for a DIFFERENT target: accepted (the uniqueness
        // rule spans all variants' slots; two slots may share one server in
        // different targets).
        std::fs::write(
            project.join("releases/v1/standard.toml"),
            format!("{MINIMAL_VARIANT}\n{STANDARD_SLOTS}"),
        )
        .unwrap();
        let other = format!(
            "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntarget = \"t2\"\ndeploy_dir = \"/srv/other\"\n"
        );
        std::fs::write(project.join("releases/v1/other.toml"), other).unwrap();
        let t2 = "\n[targets.t2]\nrollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }\n";
        std::fs::write(&p, format!("{}{}", deploy_toml("v1"), t2)).unwrap();
        let cfg = ProjectConfig::load(&p).expect("distinct deploy_dir on the same server is valid");
        assert_eq!(cfg.slot_defs().len(), 2);
    }

    #[test]
    fn duplicate_top_level_server_ids_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let mut toml = deploy_toml("v1");
        // Insert a second [[servers]] entry with the same ID before [targets.t1].
        let dup = "[[servers]]\nid = \"s1\"\naddress = \"a2\"\nuser = \"u\"\n\n";
        toml = toml.replacen("[targets.t1]", &format!("{dup}[targets.t1]"), 1);
        let p = project.join("deploy.toml");
        std::fs::write(&p, toml).unwrap();
        let err = ProjectConfig::load(&p).expect_err("duplicate server id must fail");
        assert!(
            err.to_string().contains("duplicate server id 's1'"),
            "error must name the duplicated id, got: {err}"
        );
    }

    #[test]
    fn server_capacity_is_validated_and_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let p = project.join("deploy.toml");

        // Omitted capacity defaults to 0/0.
        std::fs::write(&p, deploy_toml("v1")).unwrap();
        let cfg = ProjectConfig::load(&p).expect("server without capacity loads");
        assert_eq!(cfg.servers[0].capacity, CapacityConfig::default());

        // reserve_percent above 100 is rejected at load time.
        let bad = deploy_toml("v1").replace(
            "user = \"u\"",
            "user = \"u\"\ncapacity = { reserve_bytes = 1, reserve_percent = 101 }",
        );
        std::fs::write(&p, bad).unwrap();
        let err = ProjectConfig::load(&p).expect_err("reserve_percent > 100 must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("reserve_percent must be within 0..=100") && msg.contains("server 's1'"),
            "error must name the server and the violation, got: {msg}"
        );

        // A valid inline capacity table parses into the server policy.
        let ok = deploy_toml("v1").replace(
            "user = \"u\"\nhost_key_fingerprint",
            "user = \"u\"\ncapacity = { reserve_bytes = 4096, reserve_percent = 10 }\nhost_key_fingerprint",
        );
        std::fs::write(&p, ok).unwrap();
        let cfg = ProjectConfig::load(&p).expect("inline server capacity parses");
        assert_eq!(cfg.servers[0].capacity.reserve_bytes, 4096);
        assert_eq!(cfg.servers[0].capacity.reserve_percent.get(), 10);
    }

    /// SSH addresses require EXACTLY ONE host-identity source; `local://`
    /// addresses are exempt. Neither (would-be trust-on-first-use) and both
    /// (ambiguous) are rejected at load time, naming the server.
    #[test]
    fn ssh_identity_requires_exactly_one_source() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let p = project.join("deploy.toml");

        // SSH address + neither identity source: rejected (no trust-on-first-use).
        std::fs::write(
            &p,
            deploy_toml("v1").replace("host_key_fingerprint = \"SHA256:test\"\n", ""),
        )
        .unwrap();
        let err = ProjectConfig::load(&p).expect_err("SSH address without identity must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("server 's1'")
                && msg.contains("exactly one of known_hosts or host_key_fingerprint")
                && msg.contains("trust-on-first-use is disabled"),
            "error must name the server and the missing identity, got: {msg}"
        );

        // SSH address + BOTH sources: rejected as ambiguous.
        let both = deploy_toml("v1").replace(
            "host_key_fingerprint = \"SHA256:test\"",
            "host_key_fingerprint = \"SHA256:test\"\nknown_hosts = \"/etc/ssh/known_hosts\"",
        );
        std::fs::write(&p, both).unwrap();
        let err = ProjectConfig::load(&p).expect_err("SSH address with both identities must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("server 's1'")
                && msg.contains("mutually exclusive")
                && msg.contains("configure exactly one"),
            "error must name the server and the ambiguity, got: {msg}"
        );

        // local:// address + neither source: fine (no host verification).
        let local = deploy_toml("v1")
            .replace("address = \"a\"", "address = \"local:///srv/forced\"")
            .replace("host_key_fingerprint = \"SHA256:test\"\n", "");
        std::fs::write(&p, local).unwrap();
        let cfg = ProjectConfig::load(&p).expect("local:// address needs no identity");
        assert!(cfg.server("s1").unwrap().address().starts_with("local://"));

        // SSH address + exactly one source: valid.
        std::fs::write(&p, deploy_toml("v1")).unwrap();
        let cfg = ProjectConfig::load(&p).expect("SSH address with exactly one identity is valid");
        assert_eq!(
            match cfg.server("s1").unwrap().identity() {
                HostIdentity::Fingerprint(f) => Some(f.as_str()),
                _ => None,
            },
            Some("SHA256:test")
        );
        let kh_only = deploy_toml("v1").replace(
            "host_key_fingerprint = \"SHA256:test\"",
            "known_hosts = \"/etc/ssh/known_hosts\"",
        );
        std::fs::write(&p, kh_only).unwrap();
        let cfg = ProjectConfig::load(&p).expect("known_hosts-only SSH address is valid");
        assert_eq!(
            match cfg.server("s1").unwrap().identity() {
                HostIdentity::KnownHosts(p) => Some(p.as_path()),
                _ => None,
            },
            Some(Path::new("/etc/ssh/known_hosts"))
        );
        assert!(!matches!(
            cfg.server("s1").unwrap().identity(),
            HostIdentity::Fingerprint(_)
        ));
    }

    /// `local://` addresses never perform host verification, so their domain
    /// identity is ALWAYS [`HostIdentity::Local`] — the raw identity fields
    /// (whatever the file says) are collapsed by the conversion, and a local
    /// server can never carry a `KnownHosts`/`Fingerprint` form. The old
    /// exemption allowed a local endpoint to declare identity fields; the
    /// typed enum makes the option space total: `Local` is the ONE form for
    /// a local endpoint, exactly-one by construction.
    #[test]
    fn local_address_identity_collapses_to_local() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let p = project.join("deploy.toml");
        let local = deploy_toml("v1")
            .replace("address = \"a\"", "address = \"local:///srv/forced\"")
            .replace("host_key_fingerprint = \"SHA256:test\"\n", "");

        // local:// with no identity: Local.
        std::fs::write(&p, local.clone()).unwrap();
        let cfg = ProjectConfig::load(&p).expect("local:// without identity loads");
        assert!(cfg.server("s1").unwrap().address().starts_with("local://"));
        assert_eq!(cfg.server("s1").unwrap().identity(), &HostIdentity::Local);

        // local:// + known_hosts: the file may say it, but the domain
        // identity is still Local (a local endpoint never verifies a host).
        let with_kh = local.replace(
            "user = \"u\"",
            "user = \"u\"\nknown_hosts = \"/etc/ssh/known_hosts\"",
        );
        std::fs::write(&p, with_kh).unwrap();
        let cfg = ProjectConfig::load(&p).expect("local:// + known_hosts is allowed");
        assert_eq!(cfg.server("s1").unwrap().identity(), &HostIdentity::Local);

        // local:// + host_key_fingerprint: allowed, still Local.
        let with_fp = local.replace(
            "user = \"u\"",
            "user = \"u\"\nhost_key_fingerprint = \"SHA256:test\"",
        );
        std::fs::write(&p, with_fp).unwrap();
        let cfg = ProjectConfig::load(&p).expect("local:// + fingerprint is allowed");
        assert_eq!(cfg.server("s1").unwrap().identity(), &HostIdentity::Local);

        // local:// + BOTH identity sources: still allowed — the ambiguity
        // rule is scoped to SSH addresses only (the exact same pair is
        // rejected above for an SSH address), and the domain collapses to
        // Local either way.
        let with_both = deploy_toml("v1")
            .replace("address = \"a\"", "address = \"local:///srv/forced\"")
            .replace(
                "host_key_fingerprint = \"SHA256:test\"",
                "host_key_fingerprint = \"SHA256:test\"\nknown_hosts = \"/etc/ssh/known_hosts\"",
            );
        std::fs::write(&p, with_both).unwrap();
        let cfg = ProjectConfig::load(&p).expect("local:// + both identities is allowed");
        assert_eq!(cfg.server("s1").unwrap().identity(), &HostIdentity::Local);
    }

    /// Every user-written config surface is strict: an unknown key fails at
    /// load time with serde's standard wording instead of being silently
    /// ignored (`deny_unknown_fields` on every config struct).
    #[test]
    fn unknown_fields_are_rejected_across_all_config_surfaces() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let p = project.join("deploy.toml");
        let base = deploy_toml("v1");

        // Unknown top-level key in deploy.toml.
        std::fs::write(
            &p,
            base.replace(
                "schema_version = 2",
                "schema_version = 2\nadapterr = \"none\"",
            ),
        )
        .unwrap();
        let err = ProjectConfig::load(&p).expect_err("unknown top-level key must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("adapterr") && msg.contains("unknown field"),
            "error must name the unknown top-level field, got: {msg}"
        );

        // Unknown field inside a [[servers]] entry.
        std::fs::write(
            &p,
            base.replace("user = \"u\"", "user = \"u\"\nreserve_byts = 1"),
        )
        .unwrap();
        let err = ProjectConfig::load(&p).expect_err("unknown server field must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("reserve_byts") && msg.contains("unknown field"),
            "error must name the unknown server field, got: {msg}"
        );

        // Unknown field inside a variant's [activation] table.
        let bad_variant =
            MINIMAL_VARIANT.replace("adapter = \"none\"", "adapter = \"none\"\nreserve_byts = 1");
        std::fs::write(project.join("releases/v1/standard.toml"), bad_variant).unwrap();
        let err = ProjectConfig::load(&p).expect_err("unknown activation field must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("reserve_byts") && msg.contains("unknown field"),
            "error must name the unknown activation field, got: {msg}"
        );

        // Unknown field inside a variant's [[slots]] entry (slots are declared
        // in the variant files, and every struct stays strict there too).
        let bad_slot_variant = format!(
            "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\nreserve_byts = 1\ndeploy_dir = \"/srv/forced\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), bad_slot_variant).unwrap();
        let err = ProjectConfig::load(&p).expect_err("unknown slot field must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("reserve_byts") && msg.contains("unknown field"),
            "error must name the unknown slot field, got: {msg}"
        );

        // Slots moved INTO the variant files: a top-level `[[slots]]` block in
        // deploy.toml is now an unknown field on the manifest.
        let with_top_slots = format!(
            "{base}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ndeploy_dir = \"/srv/forced\"\n"
        );
        std::fs::write(&p, with_top_slots).unwrap();
        let err = ProjectConfig::load(&p).expect_err("top-level [[slots]] must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("slots") && msg.contains("unknown field"),
            "error must name the unknown top-level slots field, got: {msg}"
        );

        // Enums reject unknown variants by default (no attribute needed).
        let err = toml::from_str::<Mapping>("from = \"a\"\nto = \"b\"\nconflict = \"nope\"")
            .expect_err("unknown conflict variant must fail");
        assert!(err.to_string().contains("unknown variant"), "got: {err}");

        // Strict mapping semantics: only `conflict = \"error\"` is valid —
        // `replace` and `keep` are rejected at parse (they no longer exist),
        // and `optional` was removed (deny_unknown_fields refuses it).
        for rejected in ["replace", "keep"] {
            let err = toml::from_str::<Mapping>(&format!(
                "from = \"a\"\nto = \"b\"\nconflict = \"{rejected}\""
            ))
            .expect_err("non-error conflict policies must be rejected");
            assert!(
                err.to_string().contains("unknown variant"),
                "conflict = \"{rejected}\" must fail at parse, got: {err}"
            );
        }
        let err = toml::from_str::<Mapping>("from = \"a\"\nto = \"b\"\noptional = true")
            .expect_err("optional sources must be rejected");
        assert!(
            err.to_string().contains("unknown field"),
            "optional = true must fail at parse, got: {err}"
        );

        // The known-good fixtures still load under the strict rules.
        let fixture = project.join("deploy.toml");
        std::fs::write(&fixture, base).unwrap();
        std::fs::write(
            project.join("releases/v1/standard.toml"),
            format!("{MINIMAL_VARIANT}\n{STANDARD_SLOTS}"),
        )
        .unwrap();
        ProjectConfig::load(&fixture).expect("known-good config still loads");
    }

    /// One server runs exactly one generation, so two member slots of the same
    /// target can never share a server: a target with multiple slots on the
    /// same server is rejected (the per-target `current` pointer names a
    /// single generation).
    #[test]
    fn target_may_not_have_multiple_slots_on_one_server() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        // A second slot in the SAME target on the SAME server.
        let dup = format!(
            "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/forced-2\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), dup).unwrap();
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml("v1")).unwrap();
        let err =
            ProjectConfig::load(&p).expect_err("two slots of one target on one server must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("target 't1' has multiple slots on server 's1'"),
            "error must name the target and the shared server, got: {msg}"
        );

        // The same two slots split across TWO servers is valid.
        let ok = format!(
            "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[[slots]]\nid = \"p2\"\nserver = \"s2\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/forced-2\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), ok).unwrap();
        let two_servers = deploy_toml("v1").replacen(
            "[targets.t1]",
            "[[servers]]\nid = \"s2\"\naddress = \"b\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n[targets.t1]",
            1,
        );
        std::fs::write(&p, two_servers).unwrap();
        let cfg = ProjectConfig::load(&p).expect("two slots on distinct servers are valid");
        assert_eq!(cfg.target_slot_ids("t1").unwrap(), vec!["p1", "p2"]);
    }

    /// The per-target one-server rule is scoped to a SINGLE target: two slots
    /// on one server in the SAME target are rejected, but the same two slots
    /// may share that server when they belong to DIFFERENT targets (each
    /// target's per-server uniqueness is checked independently).
    #[test]
    fn same_server_in_different_targets_is_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let p = project.join("deploy.toml");
        let t2 = "\n[targets.t2]\nrollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }\n";
        std::fs::write(&p, format!("{}{}", deploy_toml("v1"), t2)).unwrap();

        // p1 (t1) and p2 (t2) on the SAME server s1: each target has exactly
        // one slot on s1, so the config is valid — the one-server rule is
        // per-target, not global.
        let split = format!(
            "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntarget = \"t2\"\ndeploy_dir = \"/srv/forced-2\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), split).unwrap();
        let cfg = ProjectConfig::load(&p)
            .expect("two slots on one server in different targets are valid");
        assert_eq!(cfg.target_slot_ids("t1").unwrap(), vec!["p1"]);
        assert_eq!(cfg.target_slot_ids("t2").unwrap(), vec!["p2"]);

        // The same two slots BOTH in t1 (same server) is rejected — the
        // per-target check fires.
        let same = format!(
            "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/forced-2\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), same).unwrap();
        let err =
            ProjectConfig::load(&p).expect_err("two slots of one target on one server must fail");
        assert!(
            err.to_string()
                .contains("target 't1' has multiple slots on server 's1'"),
            "error must name the target and the shared server, got: {err}"
        );

        // Two slots on the SAME server, each owned by a DIFFERENT target, is
        // valid: each target has one slot per server, and the (server,
        // deploy_dir) locations are unique.
        let two = format!(
            "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/forced\"\n\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntarget = \"t2\"\ndeploy_dir = \"/srv/forced-2\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), two).unwrap();
        let cfg =
            ProjectConfig::load(&p).expect("two slots on one server in different targets is valid");
        assert_eq!(cfg.target_slot_ids("t1").unwrap(), vec!["p1"]);
        assert_eq!(cfg.target_slot_ids("t2").unwrap(), vec!["p2"]);
    }

    /// Capacity is a per-SERVER policy: a `[capacity]` table inside a variant
    /// file is an unknown field on the variant surface and must be rejected by
    /// `deny_unknown_fields` (it is NOT per-variant configuration).
    #[test]
    fn variant_file_capacity_block_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let bad = format!("{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[capacity]\nreserve_bytes = 1\n");
        std::fs::write(project.join("releases/v1/standard.toml"), bad).unwrap();
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml("v1")).unwrap();
        let err = ProjectConfig::load(&p).expect_err("[capacity] inside a variant must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("capacity") && msg.contains("unknown field"),
            "error must name the unknown capacity table, got: {msg}"
        );
    }

    /// The SSH port defaults to 22 and is NOT a host-identity source: a server
    /// with only a `port` (no known_hosts / no fingerprint) is still rejected
    /// under the exactly-one rule.
    #[test]
    fn server_port_defaults_to_22_and_is_not_an_identity_source() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let p = project.join("deploy.toml");

        // Omitted port defaults to 22.
        std::fs::write(&p, deploy_toml("v1")).unwrap();
        let cfg = ProjectConfig::load(&p).expect("config loads");
        assert_eq!(
            cfg.server("s1").unwrap().port(),
            22,
            "default SSH port is 22"
        );

        // `port` alone does not satisfy the exactly-one identity rule.
        let port_only = deploy_toml("v1")
            .replace("host_key_fingerprint = \"SHA256:test\"\n", "")
            .replace("user = \"u\"", "user = \"u\"\nport = 2200");
        std::fs::write(&p, port_only).unwrap();
        let err = ProjectConfig::load(&p).expect_err("port-only server must still be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("exactly one of known_hosts or host_key_fingerprint"),
            "port must not count as an identity source, got: {msg}"
        );

        // An explicit port WITH exactly one identity loads and is carried.
        let with_port = deploy_toml("v1").replace("user = \"u\"", "user = \"u\"\nport = 2200");
        std::fs::write(&p, with_port).unwrap();
        let cfg = ProjectConfig::load(&p).expect("explicit port with one identity is valid");
        assert_eq!(cfg.server("s1").unwrap().port(), 2200);
    }

    /// `deny_unknown_fields` extends to the remaining user-written surfaces:
    /// the variant's `[verification]` table, the top-level `[targets.t1.rollout]`
    /// table, a variant's `[[artifact.mappings]]` entries, and the retention
    /// policy tables.
    #[test]
    fn unknown_fields_rejected_in_verification_rollout_mapping_and_retention() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let p = project.join("deploy.toml");
        let base = deploy_toml("v1");

        // Unknown field inside a variant's [verification] table.
        let bad_ver = MINIMAL_VARIANT.replace(
            "adapter = \"command\"",
            "adapter = \"command\"\nretries = 3",
        );
        std::fs::write(project.join("releases/v1/standard.toml"), bad_ver).unwrap();
        std::fs::write(&p, base.clone()).unwrap();
        let err = ProjectConfig::load(&p).expect_err("unknown verification field must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("retries") && msg.contains("unknown field"),
            "error must name the unknown verification field, got: {msg}"
        );

        // Unknown field inside a top-level [targets.t1.rollout] table.
        let bad_rollout = base.replace(
            "rollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }",
            "rollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\", max_parallel = 4 }",
        );
        std::fs::write(project.join("releases/v1/standard.toml"), MINIMAL_VARIANT).unwrap();
        std::fs::write(&p, bad_rollout).unwrap();
        let err = ProjectConfig::load(&p).expect_err("unknown rollout field must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("max_parallel") && msg.contains("unknown field"),
            "error must name the unknown rollout field, got: {msg}"
        );

        // Unknown field inside a variant's [[artifact.mappings]] entry.
        let mapping_variant = r#"
[[artifact.mappings]]
from = "a"
to = "b"
conflic = "replace"

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
        std::fs::write(project.join("releases/v1/standard.toml"), mapping_variant).unwrap();
        std::fs::write(&p, base).unwrap();
        let err = ProjectConfig::load(&p).expect_err("unknown mapping field must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("conflic") && msg.contains("unknown field"),
            "error must name the unknown mapping field, got: {msg}"
        );

        // Unknown field inside the variant's [retention] tables (retention is
        // slot-owned — it lives in the slot's owning variant file).
        let bad_retention = format!("{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n{STANDARD_ROTATION}")
            .replacen(
                "[retention.per_server]",
                "[retention]\nprotect_nothing = 1\n\n[retention.per_server]",
                1,
            );
        std::fs::write(project.join("releases/v1/standard.toml"), bad_retention).unwrap();
        std::fs::write(&p, deploy_toml("v1")).unwrap();
        let err = ProjectConfig::load(&p).expect_err("unknown retention field must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("protect_nothing") && msg.contains("unknown field"),
            "error must name the unknown retention field, got: {msg}"
        );
    }

    // ---- config vs ledger schema-version independence --------------------

    /// The full candidate set the cross-version property ranges over: BOTH
    /// supported versions (`CONFIG_SCHEMA_VERSION`, `LEDGER_SCHEMA_VERSION`),
    /// each ±1, zero, and `u32::MAX`.
    fn schema_version_candidates() -> Vec<u32> {
        let mut v = vec![
            CONFIG_SCHEMA_VERSION,
            LEDGER_SCHEMA_VERSION,
            CONFIG_SCHEMA_VERSION.wrapping_sub(1),
            CONFIG_SCHEMA_VERSION.wrapping_add(1),
            LEDGER_SCHEMA_VERSION.wrapping_sub(1),
            LEDGER_SCHEMA_VERSION.wrapping_add(1),
            0,
            u32::MAX,
        ];
        v.sort_unstable();
        v.dedup();
        v
    }

    fn schema_version_candidate() -> impl Strategy<Value = u32> {
        prop::sample::select(schema_version_candidates())
    }

    /// A minimal but VALID ledger intent for target `t1` (EXACT key-set
    /// equality: `slot_ids == desired.keys() == pre_push.keys()`).
    fn intended_intent(dep: &str) -> DeploymentIntent {
        let p1 = SlotId::new("p1".to_string());
        // ONE slot table (the membership + desired/pre-push entries).
        let slots = std::collections::BTreeMap::from([(
            p1.clone(),
            IntentSlot {
                desired: DesiredGeneration {
                    generation: test_generation_id("gen-1"),
                    artifact: ArtifactRef {
                        release: crate::model::test_release_id("rel-1"),
                        variant: VariantName::new("standard".to_string()),
                        tree: test_tree_digest("tree-1"),
                    },
                },
                pre_push: None,
            },
        )]);
        DeploymentIntent {
            deployment_id: test_deployment_id(dep),
            target: TargetName::new("t1".to_string()),
            group: None,
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            slots: NonEmptySlotTable::build(slots)
                .expect("a fixture intent always has at least one slot"),
        }
    }

    /// The supported versions load together: a project config at
    /// `CONFIG_SCHEMA_VERSION` and the same store's ledger at
    /// `LEDGER_SCHEMA_VERSION` both decode.
    #[test]
    fn config_at_config_schema_and_ledger_at_ledger_schema_load() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml("v1")).unwrap();
        ProjectConfig::load(&p).expect("a config at CONFIG_SCHEMA_VERSION must load");

        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let line = serde_json::to_string(&LedgerLine::Intent(LedgerIntentWire::from(
            &intended_intent("deploy-ok"),
        )))
        .unwrap();
        let lp = store.ledger_path("t1");
        std::fs::create_dir_all(lp.parent().unwrap()).unwrap();
        std::fs::write(&lp, format!("{line}\n")).unwrap();
        let entries = store
            .read_ledger("t1")
            .expect("a ledger at LEDGER_SCHEMA_VERSION must read");
        assert_eq!(entries.len(), 1);
    }

    /// Swapping the versions on either side fails THAT SIDE ONLY: a config
    /// carrying a foreign `schema_version` fails the config reader while the
    /// same store's ledger at `LEDGER_SCHEMA_VERSION` still decodes, and a
    /// ledger carrying a foreign `deployment_schema_version` fails the
    /// ledger reader while the config at `CONFIG_SCHEMA_VERSION` still
    /// loads. The two gates are independent: tampering one side never
    /// affects the other.
    #[test]
    fn schema_version_swap_fails_only_the_swapped_side() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let p = project.join("deploy.toml");
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // CONFIG side tampered (a foreign version on the config field): the
        // config reader fails closed ...
        std::fs::write(
            &p,
            deploy_toml("v1").replace(
                "schema_version = 2",
                &format!("schema_version = {}", CONFIG_SCHEMA_VERSION.wrapping_add(1)),
            ),
        )
        .unwrap();
        let err =
            ProjectConfig::load(&p).expect_err("a foreign config schema_version must fail closed");
        assert!(
            err.to_string().contains("schema_version"),
            "the config error must name the version field, got: {err}"
        );
        // ... while the SAME store's ledger at LEDGER_SCHEMA_VERSION is
        // untouched by the config tamper and still decodes.
        let line = serde_json::to_string(&LedgerLine::Intent(LedgerIntentWire::from(
            &intended_intent("deploy-a"),
        )))
        .unwrap();
        let lp = store.ledger_path("t1");
        std::fs::create_dir_all(lp.parent().unwrap()).unwrap();
        std::fs::write(&lp, format!("{line}\n")).unwrap();
        assert_eq!(
            store.read_ledger("t1").unwrap().len(),
            1,
            "a config-side version tamper must not affect ledger decoding"
        );

        // Restore the config at CONFIG_SCHEMA_VERSION ...
        std::fs::write(&p, deploy_toml("v1")).unwrap();
        ProjectConfig::load(&p).expect("the config at CONFIG_SCHEMA_VERSION still loads");
        // ... and tamper ONLY the ledger line: the ledger reader fails
        // closed, naming the version ... (the version is a WIRE member — the
        // domain no longer carries it, so the tamper sets it on the wire
        // form).
        let foreign = intended_intent("deploy-b");
        let mut wire = LedgerIntentWire::from(&foreign);
        wire.deployment_schema_version = LEDGER_SCHEMA_VERSION.wrapping_add(1);
        let line = serde_json::to_string(&LedgerLine::Intent(wire)).unwrap();
        std::fs::write(&lp, format!("{line}\n")).unwrap();
        let err = store
            .read_ledger("t1")
            .expect_err("a foreign deployment_schema_version must fail closed");
        assert!(
            err.to_string().contains("deployment_schema_version"),
            "the ledger error must name the version field, got: {err}"
        );
        // ... and the CONFIG is untouched by the ledger tamper.
        ProjectConfig::load(&p).expect("the config still loads after the ledger-side tamper");
    }

    proptest! {
        // THE CROSS-VERSION INDEPENDENCE PROPERTY: the configuration and
        // the deployment ledger version themselves on INDEPENDENT axes. For
        // every (config_version, ledger_version) combination — ranging over
        // BOTH supported values, each ±1, zero, and u32::MAX — each reader
        // decodes exactly by its OWN constant: the config reader accepts the
        // config iff `schema_version == CONFIG_SCHEMA_VERSION`, and the
        // ledger reader accepts the ledger iff
        // `deployment_schema_version == LEDGER_SCHEMA_VERSION`. Changing one
        // side's version never affects the other side's decoding.
        //
        // Bounded 16 cases, fixed seed 0x5EED_5EED (house style), no
        // failure persistence — the identical vectors on every run.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn config_and_ledger_schema_versions_decode_independently(
            config_version in schema_version_candidate(),
            ledger_version in schema_version_candidate(),
        ) {
            let dir = tempfile::tempdir().unwrap();
            let project = dir.path().join("proj");
            std::fs::create_dir_all(&project).unwrap();
            write_standard_release(&project, "v1");
            let p = project.join("deploy.toml");
            std::fs::write(
                &p,
                deploy_toml("v1").replace(
                    "schema_version = 2",
                    &format!("schema_version = {config_version}"),
                ),
            )
            .unwrap();

            // The config reader accepts exactly CONFIG_SCHEMA_VERSION — a
            // foreign value (including LEDGER_SCHEMA_VERSION once the two
            // constants diverge) is refused, independently of the ledger.
            let config_accepted = ProjectConfig::load(&p).is_ok();
            assert_eq!(
                config_accepted,
                config_version == CONFIG_SCHEMA_VERSION,
                "config schema_version {config_version} must load iff it equals CONFIG_SCHEMA_VERSION"
            );

            // The ledger reader accepts exactly LEDGER_SCHEMA_VERSION on the
            // intent line — a foreign value is refused, independently of the
            // config.
            let store = LocalStore::with_base(dir.path().join("store")).unwrap();
            let intent = intended_intent("deploy-x");
            let mut wire = LedgerIntentWire::from(&intent);
            wire.deployment_schema_version = ledger_version;
            let line = serde_json::to_string(&LedgerLine::Intent(wire)).unwrap();
            let lp = store.ledger_path("t1");
            std::fs::create_dir_all(lp.parent().unwrap()).unwrap();
            std::fs::write(&lp, format!("{line}\n")).unwrap();
            let ledger_accepted = store.read_ledger("t1").is_ok();
            assert_eq!(
                ledger_accepted,
                ledger_version == LEDGER_SCHEMA_VERSION,
                "ledger deployment_schema_version {ledger_version} must read iff it equals LEDGER_SCHEMA_VERSION"
            );
        }
    }

    // =====================================================================
    // RawConfig -> DomainConfig conversion: total-fail-closed
    // =====================================================================
    //
    // The deterministic per-rule tests below drive the raw -> domain
    // conversion DIRECTLY (no filesystem): each invalid input class must be
    // rejected with a conversion error, and each valid minimal input must
    // produce a domain whose invariants hold — asserted by INSPECTING the
    // DomainConfig (the typed enums, the resolved references), never by
    // re-running the validation.

    /// The minimal VALID raw project: local server `s1`, one target `t1`,
    /// one variant `standard` (adapter none, command verification) declaring
    /// slot `p1` on `s1` bound to `t1`.
    fn minimal_raw_project() -> RawProject {
        RawProject {
            manifest: raw::RawConfig {
                schema_version: CONFIG_SCHEMA_VERSION,
                application: "app".to_string(),
                release: ReleaseName::new("v1"),
                pins: Vec::new(),
                servers: vec![raw::RawServer {
                    id: "s1".to_string(),
                    address: "local:///srv".to_string(),
                    user: "u".to_string(),
                    port: 22,
                    known_hosts: None,
                    host_key_fingerprint: None,
                    capacity: raw::RawCapacityConfig::default(),
                }],
                targets: BTreeMap::from([(
                    "t1".to_string(),
                    raw::RawTargetConfig {
                        rollout: raw::RawRolloutConfig::default(),
                    },
                )]),
            },
            variants: BTreeMap::from([("standard".to_string(), minimal_raw_variant())]),
        }
    }

    fn minimal_raw_variant() -> raw::RawVariant {
        raw::RawVariant {
            description: None,
            artifact: ArtifactConfig {
                mappings: Vec::new(),
            },
            activation: ActivationConfig {
                adapter: "none".to_string(),
                scope: ActivationScope::User,
                reconcile_managed_units: true,
                units: Vec::new(),
            },
            verification: VerificationConfig {
                adapter: "command".to_string(),
                argv: vec!["true".to_string()],
                timeout_seconds: 5,
                attempts: 1,
                interval_seconds: 0,
            },
            slots: vec![SlotConfig {
                id: "p1".to_string(),
                server: "s1".to_string(),
                deploy_dir: PathBuf::from("/srv/p1"),
                target: "t1".to_string(),
                groups: Vec::new(),
            }],
            retention: RetentionConfig::default(),
        }
    }

    /// Mutate the minimal project and require the conversion to fail.
    fn expect_conversion_err(project: RawProject, rule: &str) {
        let err =
            ProjectConfig::from_raw_parts(project.manifest, project.variants).expect_err(rule);
        assert!(
            !err.to_string().is_empty(),
            "conversion error must carry a message for {rule}"
        );
    }

    #[test]
    fn conversion_rejects_wrong_schema_version() {
        let mut p = minimal_raw_project();
        p.manifest.schema_version = CONFIG_SCHEMA_VERSION + 1;
        expect_conversion_err(p, "wrong schema version");
    }

    #[test]
    fn conversion_rejects_invalid_identifiers() {
        // Empty/whitespace-only identifiers are never valid names.
        for id in ["", "   "] {
            let mut p = minimal_raw_project();
            p.manifest.servers[0].id = id.to_string();
            expect_conversion_err(p, "empty server id");

            let mut p = minimal_raw_project();
            p.variants.get_mut("standard").unwrap().slots[0].id = id.to_string();
            expect_conversion_err(p, "empty slot id");

            let mut p = minimal_raw_project();
            p.manifest.targets = BTreeMap::from([(
                id.to_string(),
                raw::RawTargetConfig {
                    rollout: raw::RawRolloutConfig::default(),
                },
            )]);
            p.variants.get_mut("standard").unwrap().slots[0].target = id.to_string();
            expect_conversion_err(p, "empty target name");

            let mut p = minimal_raw_project();
            p.variants = BTreeMap::from([(id.to_string(), minimal_raw_variant())]);
            expect_conversion_err(p, "empty variant name");

            let mut p = minimal_raw_project();
            p.variants.get_mut("standard").unwrap().slots[0].groups = vec![id.to_string()];
            expect_conversion_err(p, "empty group name");
        }
    }

    #[test]
    fn conversion_rejects_duplicate_identifiers() {
        // Duplicate server ids.
        let mut p = minimal_raw_project();
        p.manifest.servers.push(raw::RawServer {
            id: "s1".to_string(),
            address: "local:///srv-2".to_string(),
            user: "u".to_string(),
            port: 22,
            known_hosts: None,
            host_key_fingerprint: None,
            capacity: raw::RawCapacityConfig::default(),
        });
        expect_conversion_err(p, "duplicate server id");

        // Duplicate slot ids across two variants.
        let mut p = minimal_raw_project();
        p.variants
            .insert("other".to_string(), minimal_raw_variant());
        expect_conversion_err(p, "duplicate slot id across variants");

        // Duplicate group names inside one slot.
        let mut p = minimal_raw_project();
        p.variants.get_mut("standard").unwrap().slots[0].groups =
            vec!["canary".to_string(), "canary".to_string()];
        expect_conversion_err(p, "duplicate group name");
    }

    #[test]
    fn conversion_rejects_unresolved_references() {
        // Slot -> unknown server.
        let mut p = minimal_raw_project();
        p.variants.get_mut("standard").unwrap().slots[0].server = "ghost".to_string();
        expect_conversion_err(p, "slot references unknown server");

        // Slot -> unknown target.
        let mut p = minimal_raw_project();
        p.variants.get_mut("standard").unwrap().slots[0].target = "ghost".to_string();
        expect_conversion_err(p, "slot references unknown target");
    }

    #[test]
    fn conversion_rejects_impossible_identity_combinations() {
        // SSH address with BOTH identity forms.
        let mut p = minimal_raw_project();
        p.manifest.servers[0].address = "db.example.com".to_string();
        p.manifest.servers[0].known_hosts = Some(PathBuf::from("/etc/ssh/known_hosts"));
        p.manifest.servers[0].host_key_fingerprint = Some("SHA256:test".to_string());
        expect_conversion_err(p, "SSH address with both identities");

        // SSH address with NEITHER identity form (no trust-on-first-use).
        let mut p = minimal_raw_project();
        p.manifest.servers[0].address = "db.example.com".to_string();
        expect_conversion_err(p, "SSH address without identity");

        // A relative known_hosts is rejected for every server (local too).
        let mut p = minimal_raw_project();
        p.manifest.servers[0].known_hosts = Some(PathBuf::from("relative/known_hosts"));
        expect_conversion_err(p, "relative known_hosts");

        // A non-SHA256 fingerprint is rejected for every server (local too).
        let mut p = minimal_raw_project();
        p.manifest.servers[0].host_key_fingerprint = Some("md5:deadbeef".to_string());
        expect_conversion_err(p, "malformed fingerprint");

        // Capacity outside its domain is rejected.
        let mut p = minimal_raw_project();
        p.manifest.servers[0].capacity.reserve_percent = 101;
        expect_conversion_err(p, "reserve_percent over 100");
    }

    #[test]
    fn conversion_rejects_impossible_activation_and_verification() {
        // Unknown activation adapter.
        let mut p = minimal_raw_project();
        p.variants.get_mut("standard").unwrap().activation.adapter = "docker".to_string();
        expect_conversion_err(p, "unknown activation adapter");

        // systemd activation without units.
        let mut p = minimal_raw_project();
        p.variants.get_mut("standard").unwrap().activation = ActivationConfig {
            adapter: "systemd".to_string(),
            scope: ActivationScope::System,
            reconcile_managed_units: true,
            units: Vec::new(),
        };
        expect_conversion_err(p, "systemd without units");

        // Unsupported verification adapter.
        let mut p = minimal_raw_project();
        p.variants.get_mut("standard").unwrap().verification.adapter = "systemctl".to_string();
        expect_conversion_err(p, "unsupported verification adapter");

        // Empty verification argv.
        let mut p = minimal_raw_project();
        p.variants
            .get_mut("standard")
            .unwrap()
            .verification
            .argv
            .clear();
        expect_conversion_err(p, "empty verification argv");
    }

    #[test]
    fn conversion_rejects_unsafe_mappings() {
        // Overlapping destinations.
        let mut p = minimal_raw_project();
        p.variants.get_mut("standard").unwrap().artifact = ArtifactConfig {
            mappings: vec![
                Mapping {
                    from: "a/".to_string(),
                    to: "app/".to_string(),
                    recursive: true,
                    conflict: ConflictPolicy::Error,
                    mode: None,
                },
                Mapping {
                    from: "b/".to_string(),
                    to: "app".to_string(),
                    recursive: true,
                    conflict: ConflictPolicy::Error,
                    mode: None,
                },
            ],
        };
        expect_conversion_err(p, "overlapping mapping destinations");

        // A destination escaping the artifact-relative namespace.
        let mut p = minimal_raw_project();
        p.variants.get_mut("standard").unwrap().artifact = ArtifactConfig {
            mappings: vec![Mapping {
                from: "a/".to_string(),
                to: "../escape".to_string(),
                recursive: true,
                conflict: ConflictPolicy::Error,
                mode: None,
            }],
        };
        expect_conversion_err(p, "escaping mapping destination");

        // An invalid octal mode.
        let mut p = minimal_raw_project();
        p.variants.get_mut("standard").unwrap().artifact = ArtifactConfig {
            mappings: vec![Mapping {
                from: "a/".to_string(),
                to: "app/".to_string(),
                recursive: true,
                conflict: ConflictPolicy::Error,
                mode: Some("0999".to_string()),
            }],
        };
        expect_conversion_err(p, "invalid octal mode");
    }

    #[test]
    fn conversion_rejects_graph_violations() {
        // No variants.
        let mut p = minimal_raw_project();
        p.variants.clear();
        expect_conversion_err(p, "no variants");

        // No targets.
        let mut p = minimal_raw_project();
        p.manifest.targets.clear();
        expect_conversion_err(p, "no targets");

        // Release name escaping the forced releases/<name>/ layout.
        let mut p = minimal_raw_project();
        p.manifest.release = ReleaseName::new("../v1");
        expect_conversion_err(p, "escaping release name");

        // A target with no member slots.
        let mut p = minimal_raw_project();
        p.manifest.targets.insert(
            "empty".to_string(),
            raw::RawTargetConfig {
                rollout: raw::RawRolloutConfig::default(),
            },
        );
        expect_conversion_err(p, "target without slots");

        // Two slots of one target on one server.
        let mut p = minimal_raw_project();
        p.variants
            .get_mut("standard")
            .unwrap()
            .slots
            .push(SlotConfig {
                id: "p2".to_string(),
                server: "s1".to_string(),
                deploy_dir: PathBuf::from("/srv/p2"),
                target: "t1".to_string(),
                groups: Vec::new(),
            });
        expect_conversion_err(p, "two slots of one target on one server");

        // Two slots bound to the same (server, deploy_dir) location.
        let mut p = minimal_raw_project();
        p.variants
            .get_mut("standard")
            .unwrap()
            .slots
            .push(SlotConfig {
                id: "p2".to_string(),
                server: "s1".to_string(),
                deploy_dir: PathBuf::from("/srv/p1"),
                target: "t2".to_string(),
                groups: Vec::new(),
            });
        p.manifest.targets.insert(
            "t2".to_string(),
            raw::RawTargetConfig {
                rollout: raw::RawRolloutConfig::default(),
            },
        );
        expect_conversion_err(p, "duplicate server+deploy_dir location");

        // A relative deploy_dir.
        let mut p = minimal_raw_project();
        p.variants.get_mut("standard").unwrap().slots[0].deploy_dir = PathBuf::from("srv/p1");
        expect_conversion_err(p, "relative deploy_dir");
    }

    /// The minimal valid input converts to a domain whose invariants ALL
    /// hold — asserted by inspecting the DomainConfig itself: the typed
    /// identity enum, the resolved references, the slot->variant binding, the
    /// deterministic membership derivation.
    #[test]
    fn conversion_accepts_minimal_and_invariants_hold() {
        let p = minimal_raw_project();
        let cfg = ProjectConfig::from_raw_parts(p.manifest, p.variants)
            .expect("minimal project converts");

        // The manifest surface is carried through.
        assert_eq!(cfg.schema_version, CONFIG_SCHEMA_VERSION);
        assert_eq!(cfg.application().as_str(), "app");
        assert_eq!(cfg.release().as_str(), "v1");
        assert_eq!(cfg.targets().count(), 1);

        // A local:// server's identity is EXACTLY ONE form: Local.
        assert_eq!(cfg.servers().count(), 1);
        assert_eq!(cfg.server("s1").unwrap().identity(), &HostIdentity::Local);
        assert!(cfg.server("s1").unwrap().address().starts_with("local://"));

        // The variant carries the typed activation enum (none here), its
        // slot, and its slot-owned retention.
        assert_eq!(cfg.variant_names(), vec!["standard"]);
        assert_eq!(
            cfg.variant("standard").unwrap().activation,
            Activation::None
        );
        assert_eq!(cfg.slot_defs().len(), 1);

        // Every reference resolves and ownership is derived, not repeated:
        // the declaring variant owns the slot and the slot owns its target.
        assert_eq!(cfg.slot_variant("p1").unwrap(), "standard");
        assert!(cfg.slot_variant("ghost").is_err());
        assert_eq!(
            cfg.slot_retention("p1").unwrap(),
            &RetentionConfig::default()
        );
        assert_eq!(cfg.target_slot_ids("t1").unwrap(), vec!["p1"]);
        let (slot, server) = cfg.target_slots("t1").unwrap()[0];
        assert_eq!(slot.id, "p1");
        assert_eq!(server.id.as_str(), "s1");
        assert_eq!(cfg.target_slot_bindings("t1").unwrap().len(), 1);
    }

    /// An SSH server with a fingerprint identity converts to the typed
    /// [`HostIdentity::Fingerprint`] carrying the validated [`Fingerprint`]
    /// value; the transport-view field derives from it.
    #[test]
    fn conversion_maps_fingerprint_identity_to_typed_enum() {
        let mut p = minimal_raw_project();
        p.manifest.servers[0].address = "db.example.com".to_string();
        p.manifest.servers[0].host_key_fingerprint = Some("SHA256:abc".to_string());
        let cfg = ProjectConfig::from_raw_parts(p.manifest, p.variants)
            .expect("fingerprint server converts");
        let HostIdentity::Fingerprint(fp) = cfg.server("s1").unwrap().identity() else {
            panic!("SSH + fingerprint must produce HostIdentity::Fingerprint");
        };
        assert_eq!(fp.as_str(), "SHA256:abc");
        assert_eq!(
            match cfg.server("s1").unwrap().identity() {
                HostIdentity::Fingerprint(f) => Some(f.as_str()),
                _ => None,
            },
            Some("SHA256:abc")
        );
        assert!(!matches!(
            cfg.server("s1").unwrap().identity(),
            HostIdentity::KnownHosts(_)
        ));
    }

    /// An SSH server with a dedicated known_hosts file resolves to
    /// `HostIdentity::KnownHosts`, never to a fingerprint.
    #[test]
    fn conversion_maps_known_hosts_identity_to_typed_enum() {
        let mut p = minimal_raw_project();
        p.manifest.servers[0].address = "db.example.com".to_string();
        p.manifest.servers[0].known_hosts = Some(PathBuf::from("/etc/ssh/known_hosts"));
        let cfg = ProjectConfig::from_raw_parts(p.manifest, p.variants)
            .expect("known_hosts identity converts");
        assert_eq!(
            cfg.server("s1").unwrap().identity(),
            &HostIdentity::KnownHosts(PathBuf::from("/etc/ssh/known_hosts"))
        );
        assert_eq!(
            match cfg.server("s1").unwrap().identity() {
                HostIdentity::KnownHosts(p) => Some(p.as_path()),
                _ => None,
            },
            Some(Path::new("/etc/ssh/known_hosts"))
        );
        assert!(!matches!(
            cfg.server("s1").unwrap().identity(),
            HostIdentity::Fingerprint(_)
        ));
    }

    /// A systemd variant converts to the typed `Activation::Systemd` with its
    /// scope/units, and the domain -> contract conversion reproduces the
    /// canonical serialized activation contract.
    #[test]
    fn conversion_maps_systemd_activation_to_typed_enum() {
        let mut p = minimal_raw_project();
        p.variants.get_mut("standard").unwrap().activation = ActivationConfig {
            adapter: "systemd".to_string(),
            scope: ActivationScope::System,
            reconcile_managed_units: true,
            units: vec![UnitDef {
                name: "app.service".to_string(),
                artifact_path: "app.service".to_string(),
                enable: true,
                restart: true,
            }],
        };
        let cfg = ProjectConfig::from_raw_parts(p.manifest, p.variants)
            .expect("systemd variant converts");
        let Activation::Systemd(sa) = &cfg.variant("standard").unwrap().activation else {
            panic!("systemd adapter must convert to Activation::Systemd");
        };
        assert_eq!(sa.scope, ActivationScope::System);
        assert_eq!(sa.units.len(), 1);
        assert_eq!(sa.units[0].name, "app.service");

        // The domain -> contract conversion is the ONLY path and is
        // canonical: the serialized contract has adapter systemd + the
        // carried scope/units (this is what the behavior digest hashes).
        let contract = ActivationConfig::from(Activation::Systemd(SystemdActivation {
            scope: ActivationScope::System,
            reconcile_managed_units: true,
            units: vec![UnitDef {
                name: "app.service".to_string(),
                artifact_path: "app.service".to_string(),
                enable: true,
                restart: true,
            }],
        }));
        assert_eq!(contract.adapter, "systemd");
        assert_eq!(contract.scope, ActivationScope::System);
        assert_eq!(contract.units.len(), 1);

        // None -> the canonical "none" contract (adapter none, no units).
        let none = ActivationConfig::from(Activation::None);
        assert_eq!(none.adapter, "none");
        assert!(none.units.is_empty());
    }

    /// `deny_unknown_fields` is a parse-level gate on the raw layer: an
    /// unknown key anywhere in the manifest or a variant file is refused at
    /// parse, before the conversion ever runs.
    #[test]
    fn raw_layer_denies_unknown_fields_at_parse() {
        let err = toml::from_str::<raw::RawConfig>(
            "schema_version = 2\napplication = \"a\"\nrelease = \"v1\"\nadapterr = \"x\"\n",
        )
        .expect_err("unknown manifest key must fail parse");
        assert!(err.to_string().contains("unknown field"), "got: {err}");

        let err =
            toml::from_str::<raw::RawVariant>("[activation]\nadapter = \"none\"\nadptr = \"x\"\n")
                .expect_err("unknown activation key must fail parse");
        assert!(err.to_string().contains("unknown field"), "got: {err}");
    }

    // =====================================================================
    // The property: ARBITRARY raw input is total-fail-closed
    // =====================================================================

    /// Arbitrary identifier strings: empty, whitespace, duplicates-friendly
    /// small alphabets, and arbitrary Unicode.
    fn arbitrary_identifier() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(vec![
                String::new(),
                " ".to_string(),
                "s".to_string(),
                "s1".to_string(),
                "α".to_string(),
                "x y".to_string(),
            ]),
            prop::collection::vec(prop::char::any(), 0..6).prop_map(|v| v.into_iter().collect()),
        ]
    }

    /// A VALID release id — the exact `rel-sha256-<64 lowercase hex>` form
    /// [`ReleaseId::parse`] accepts, built from 64 generated hex digits. The
    /// typed mutation APIs only accept typed ids, so every update-op payload
    /// is valid by construction; the rebuild-op property is about invariants
    /// after successful ops (an op that does not apply simply fails).
    fn arbitrary_release_id() -> impl Strategy<Value = ReleaseId> {
        prop::collection::vec(prop::sample::select(b"0123456789abcdef".to_vec()), 64).prop_map(
            |hex| {
                ReleaseId::parse(&format!("rel-sha256-{}", String::from_utf8(hex).unwrap()))
                    .expect("64 lowercase hex chars form a canonical release id")
            },
        )
    }

    fn arbitrary_path() -> impl Strategy<Value = PathBuf> {
        prop::sample::select(vec![
            PathBuf::from("/etc/ssh/known_hosts"),
            PathBuf::from("/srv/deploy/p1"),
            PathBuf::from("relative/x"),
            PathBuf::new(),
        ])
    }

    fn arbitrary_identity_pair() -> impl Strategy<Value = (Option<PathBuf>, Option<String>)> {
        prop_oneof![
            Just((None, None)),
            Just((None, Some("SHA256:test".to_string()))),
            Just((Some(PathBuf::from("/etc/ssh/known_hosts")), None)),
            Just((Some(PathBuf::from("relative/kh")), None)),
            Just((None, Some("md5:x".to_string()))),
            Just((
                Some(PathBuf::from("/etc/ssh/known_hosts")),
                Some("SHA256:test".to_string()),
            )),
        ]
    }

    fn arbitrary_server() -> impl Strategy<Value = raw::RawServer> {
        (
            arbitrary_identifier(),
            prop_oneof![
                Just("local:///srv".to_string()),
                Just("db.example.com".to_string()),
                arbitrary_identifier(),
            ],
            arbitrary_identifier(),
            any::<u16>(),
            arbitrary_identity_pair(),
            arbitrary_capacity(),
        )
            .prop_map(
                |(id, address, user, port, (known_hosts, host_key_fingerprint), capacity)| {
                    raw::RawServer {
                        id,
                        address,
                        user,
                        port,
                        known_hosts,
                        host_key_fingerprint,
                        capacity,
                    }
                },
            )
    }

    fn arbitrary_capacity() -> impl Strategy<Value = raw::RawCapacityConfig> {
        (any::<u64>(), 0u8..200).prop_map(|(reserve_bytes, reserve_percent)| {
            raw::RawCapacityConfig {
                reserve_bytes,
                reserve_percent,
            }
        })
    }

    fn arbitrary_activation() -> impl Strategy<Value = ActivationConfig> {
        (
            prop::sample::select(vec![
                "none".to_string(),
                "systemd".to_string(),
                "bogus".to_string(),
                "".to_string(),
            ]),
            any::<bool>(),
            prop::collection::vec(
                (
                    arbitrary_identifier(),
                    arbitrary_identifier(),
                    any::<bool>(),
                    any::<bool>(),
                )
                    .prop_map(|(name, artifact_path, enable, restart)| UnitDef {
                        name,
                        artifact_path,
                        enable,
                        restart,
                    }),
                0..2,
            ),
        )
            .prop_map(
                |(adapter, reconcile_managed_units, units)| ActivationConfig {
                    adapter,
                    scope: ActivationScope::System,
                    reconcile_managed_units,
                    units,
                },
            )
    }

    fn arbitrary_verification() -> impl Strategy<Value = VerificationConfig> {
        (
            prop::sample::select(vec![
                "command".to_string(),
                "systemctl".to_string(),
                "".to_string(),
            ]),
            prop::collection::vec(arbitrary_identifier(), 0..2),
            any::<u64>(),
            any::<u32>(),
            any::<u64>(),
        )
            .prop_map(
                |(adapter, argv, timeout_seconds, attempts, interval_seconds)| VerificationConfig {
                    adapter,
                    argv,
                    timeout_seconds,
                    attempts,
                    interval_seconds,
                },
            )
    }

    fn arbitrary_mapping() -> impl Strategy<Value = Mapping> {
        (
            arbitrary_identifier(),
            arbitrary_identifier(),
            any::<bool>(),
        )
            .prop_map(|(from, to, recursive)| Mapping {
                from,
                to,
                recursive,
                conflict: ConflictPolicy::Error,
                mode: None,
            })
    }

    fn arbitrary_slot() -> impl Strategy<Value = SlotConfig> {
        (
            arbitrary_identifier(),
            arbitrary_identifier(),
            arbitrary_path(),
            arbitrary_identifier(),
            prop::collection::vec(arbitrary_identifier(), 0..2),
        )
            .prop_map(|(id, server, deploy_dir, target, groups)| SlotConfig {
                id,
                server,
                deploy_dir,
                target,
                groups,
            })
    }

    fn arbitrary_raw_variant() -> impl Strategy<Value = raw::RawVariant> {
        (
            prop::option::of(arbitrary_identifier()),
            prop::collection::vec(arbitrary_mapping(), 0..2),
            arbitrary_activation(),
            arbitrary_verification(),
            prop::collection::vec(arbitrary_slot(), 0..3),
            any::<u64>(),
            any::<u32>(),
        )
            .prop_map(
                |(
                    description,
                    mappings,
                    activation,
                    verification,
                    slots,
                    keep_days,
                    keep_distinct,
                )| {
                    raw::RawVariant {
                        description,
                        artifact: ArtifactConfig { mappings },
                        activation,
                        verification,
                        slots,
                        retention: RetentionConfig {
                            per_server: PerServerRetention {
                                keep_distinct_artifacts: keep_distinct,
                                keep_days,
                                protect_previous: true,
                            },
                            deployment: DeploymentRetention {
                                protect_deployments: 0,
                            },
                        },
                    }
                },
            )
    }

    fn arbitrary_target() -> impl Strategy<Value = raw::RawTargetConfig> {
        (any::<u32>(), any::<bool>(), arbitrary_failure_policy()).prop_map(
            |(batch_size, stop_on_failure, failure_policy)| raw::RawTargetConfig {
                rollout: raw::RawRolloutConfig {
                    batch_size,
                    stop_on_failure,
                    failure_policy,
                },
            },
        )
    }

    /// Both supported policies: the failure-policy dimension of the arbitrary
    /// project. The STRICTNESS itself (an unsupported spelling is rejected)
    /// is pinned by the parse-table unit test and the arbitrary-strings
    /// property below — an arbitrary project cannot carry a policy outside
    /// the closed enum, so the conversion's failure-policy gate can only
    /// reject at parse time, never by constructing an invalid domain.
    fn arbitrary_failure_policy() -> impl Strategy<Value = FailurePolicy> {
        prop_oneof![
            Just(FailurePolicy::RollbackChanged),
            Just(FailurePolicy::LeaveChanged),
        ]
    }

    /// A fully arbitrary raw project: wrong schema versions, arbitrary ids
    /// (empty/duplicate/Unicode), arbitrary references, both/neither
    /// identity forms, arbitrary group lists, arbitrary targets and variants.
    fn arbitrary_raw_project() -> impl Strategy<Value = RawProject> {
        prop_oneof![
            // Fully arbitrary: explores the entire invalid space.
            (
                prop::collection::vec(arbitrary_server(), 0..3),
                prop::collection::btree_map(arbitrary_identifier(), arbitrary_target(), 0..3),
                prop_oneof![Just(CONFIG_SCHEMA_VERSION), any::<u32>()],
                prop_oneof![Just("v1".to_string()), arbitrary_identifier()],
                prop::collection::vec((arbitrary_identifier(), arbitrary_raw_variant()), 0..3,),
            )
                .prop_map(|(servers, targets, schema_version, release, variants)| {
                    RawProject {
                        manifest: raw::RawConfig {
                            schema_version,
                            application: "app".to_string(),
                            release: ReleaseName::new(release),
                            pins: Vec::new(),
                            servers,
                            targets,
                        },
                        variants: variants.into_iter().collect(),
                    }
                }),
            // The guaranteed-valid minimal project: some cases always reach
            // the domain so the invariants of every Ok conversion are
            // asserted (bounded seed makes the mix deterministic).
            Just(minimal_raw_project()),
        ]
    }

    /// Assert the invariants every successful conversion (and every
    /// successful validated rebuild operation) must produce: valid + unique
    /// identifiers, every reference resolves (slot->server, slot->target,
    /// slot->variant, group names), the connection enum is well-formed (a
    /// local form carries a `local://` absolute address and a `Local`
    /// identity; an SSH form carries a `KnownHosts`/`Fingerprint` identity
    /// with an absolute `known_hosts`), the activation enum covers the
    /// space, and the per-target graph rules hold. This inspects the
    /// DomainConfig itself — it never re-runs the validation.
    fn assert_domain_invariants(cfg: &ProjectConfig) {
        let mut server_ids = HashSet::new();
        for s in cfg.servers() {
            assert!(
                valid_identifier(s.id.as_str()),
                "server id must be valid: {:?}",
                s.id
            );
            assert!(
                server_ids.insert(s.id.as_str()),
                "server ids must be unique"
            );
            match s.connection() {
                ServerConnection::Local { address, identity } => {
                    assert_eq!(
                        identity,
                        &HostIdentity::Local,
                        "a local connection must carry a Local identity"
                    );
                    assert!(
                        address.starts_with("local://"),
                        "a local connection must carry a local:// address"
                    );
                    let path = address.trim_start_matches("local://");
                    assert!(
                        Path::new(path).is_absolute(),
                        "a local:// endpoint must be an absolute path"
                    );
                }
                ServerConnection::Ssh {
                    address,
                    user,
                    port,
                    identity,
                } => {
                    assert!(
                        valid_identifier(address.as_str()),
                        "SSH host must be valid: {:?}",
                        address
                    );
                    assert!(
                        valid_identifier(user.as_str()),
                        "SSH user must be valid: {:?}",
                        user
                    );
                    assert!(port.get() > 0, "SSH port must be nonzero");
                    match identity {
                        HostIdentity::Local => {
                            panic!("an SSH connection cannot carry a Local identity");
                        }
                        HostIdentity::KnownHosts(p) => {
                            assert!(p.is_absolute(), "known_hosts must be absolute");
                        }
                        HostIdentity::Fingerprint(fp) => {
                            assert!(
                                fp.as_str().starts_with("SHA256:"),
                                "fingerprints are format-checked"
                            );
                        }
                    }
                }
            }
        }

        let mut variant_names = HashSet::new();
        for name in cfg.variant_names() {
            assert!(
                valid_identifier(&name),
                "variant name must be valid: {name:?}"
            );
            assert!(variant_names.insert(name.clone()), "variant names unique");
            match &cfg.variant(&name).unwrap().activation {
                Activation::None => {}
                Activation::Systemd(sa) => {
                    assert!(!sa.units.is_empty(), "systemd requires at least one unit")
                }
            }
        }
        assert!(!variant_names.is_empty(), "at least one variant");

        let mut slot_ids = HashSet::new();
        for slot in cfg.slot_defs() {
            assert!(valid_identifier(&slot.id), "slot id must be valid");
            assert!(
                slot_ids.insert(slot.id.as_str()),
                "slot ids unique across variants"
            );
            assert!(
                cfg.servers().any(|s| s.id.as_str() == slot.server),
                "slot '{}' server must resolve",
                slot.id
            );
            assert!(
                cfg.target(slot.target.as_str()).is_some(),
                "slot '{}' target must resolve",
                slot.id
            );
            assert!(
                slot.deploy_dir().is_absolute(),
                "deploy_dir must be absolute"
            );
            let mut seen_groups = HashSet::new();
            for g in &slot.groups {
                assert!(!g.trim().is_empty(), "group names must be non-empty");
                assert!(seen_groups.insert(g), "group names unique per slot");
            }
            assert!(
                cfg.slot_variant(&slot.id).is_ok(),
                "every slot resolves to its declaring variant"
            );
        }

        for (tname, _) in cfg.targets() {
            assert!(valid_identifier(tname), "target name must be valid");
            let slots = cfg.target_slots(tname).expect("target exists");
            assert!(!slots.is_empty(), "a target must have at least one slot");
            let mut used_servers = HashSet::new();
            for (slot, _) in &slots {
                assert!(
                    used_servers.insert(slot.server.as_str()),
                    "one slot per server per target"
                );
            }
            // The failure policy is a closed typed enum by construction: the
            // raw string was consumed by the strict parse during the raw ->
            // domain conversion, so every domain target carries EXACTLY one
            // supported policy — an unsupported spelling can never enter a
            // domain (it fails the conversion instead).
            match cfg.target(tname).unwrap().rollout.failure_policy {
                FailurePolicy::RollbackChanged => {}
                FailurePolicy::LeaveChanged => {}
            }
        }
    }

    proptest! {
        // THE property: arbitrary deserialized raw input must EITHER fail the
        // raw -> domain conversion (any invalid identifier, unresolvable
        // reference, impossible option combination, or schema/unknown-field
        // issue rejects it) OR produce a domain graph whose invariants all
        // hold. Bounded 16 cases, fixed seed 0x5EED_5EED per house style;
        // the generation is pure (no filesystem), so the property stays fast.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn arbitrary_raw_config_converts_fail_closed(project in arbitrary_raw_project()) {
            if let Ok(cfg) = ProjectConfig::from_raw_parts(project.manifest, project.variants) {
                assert_domain_invariants(&cfg);
            }
            // fail-closed: rejection is a valid outcome for arbitrary input
        }
    }

    // =====================================================================
    // THE PIN-STRING PROPERTY: config load gates EXACTLY on the release-id
    // grammar
    // =====================================================================
    //
    // THE USER'S REQUIREMENT: strict `ReleaseId` validation must cover
    // configuration pins. The raw wire `[[pins]]` entry carries a plain
    // string; the raw -> domain conversion parses EVERY pin's release into
    // the typed [`ReleaseId`], so a config loads exactly when every pin
    // satisfies the `rel-sha256-<64 lowercase hex>` grammar — and a loaded
    // config can never produce a later release-id syntax error (the
    // consumers that used to parse the raw string late now receive the
    // typed id by construction).

    /// Arbitrary RAW pin release strings: canonical valid ids (generated via
    /// hex chars) plus every near-miss class the grammar must reject — wrong
    /// prefix, non-hex / non-64 / non-lowercase suffix, the bare-digest and
    /// `rel-` forms, empty, garbage, Unicode. (The garbage arm may
    /// accidentally produce a valid string — the property asserts the
    /// equivalence against [`ReleaseId::parse`] itself, so that is fine.)
    fn arbitrary_raw_pin_release() -> impl Strategy<Value = String> {
        let digest = crate::model::test_tree_digest("prop").as_str().to_string();
        prop_oneof![
            // The canonical VALID form: `rel-sha256-` + 64 lowercase hex.
            prop::collection::vec(prop::sample::select(b"0123456789abcdef".to_vec()), 64)
                .prop_map(|hex| { format!("rel-sha256-{}", String::from_utf8(hex).unwrap()) }),
            // Near-misses.
            prop::sample::select(vec![
                String::new(),
                "rel-sha256-".to_string(),
                "rel-sha256".to_string(),
                format!("rel-sha256-{}", &digest[..63]),
                format!("rel-sha256-{}", digest.to_uppercase()),
                format!("rel-sha256-{}", "z".repeat(64)),
                format!("rel-sha256-{}", "0".repeat(63)),
                format!("rel-{digest}"),
                digest.clone(),
                format!("rel-sha256-{digest} "),
                "rel-sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
                "rel-sha256-α".to_string(),
                "rel-sha256-0x".to_string(),
                "rel-sha256----".to_string(),
            ]),
            // Arbitrary garbage / Unicode.
            prop::collection::vec(prop::char::any(), 0..80).prop_map(|v| v.into_iter().collect()),
        ]
    }

    proptest! {
        // THE PROPERTY: over ARBITRARY raw pin-string lists (canonical valid
        // ids, every near-miss class, garbage, Unicode) with arbitrary
        // reasons, config loading succeeds EXACTLY when every pin satisfies
        // the release-id grammar (an invalid pin — the FIRST one — fails the
        // WHOLE load), and every successfully loaded configuration carries
        // typed release ids: for every pin, the parse the consumers used to
        // perform late can never fail. Bounded 16 cases, fixed seed
        // 0x5EED_5EED per house style; generation is pure (no filesystem).
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn raw_pin_strings_gate_config_load_exactly(
            pins in prop::collection::vec(
                (arbitrary_raw_pin_release(), arbitrary_identifier()),
                0..6,
            ),
        ) {
            let mut project = minimal_raw_project();
            project.manifest.pins = pins
                .iter()
                .map(|(release, reason)| raw::RawPin {
                    release: release.clone(),
                    reason: reason.clone(),
                })
                .collect();
            let every_pin_valid = pins.iter().all(|(r, _)| ReleaseId::parse(r).is_ok());
            let converted = ProjectConfig::from_raw_parts(project.manifest, project.variants);
            assert_eq!(
                converted.is_ok(),
                every_pin_valid,
                "config load must succeed exactly when every pin satisfies the \
                 release-id grammar (pins: {pins:?})"
            );
            match converted {
                Ok(cfg) => {
                    assert_eq!(cfg.pins().len(), pins.len());
                    // THE never-a-later-error guarantee: every pin carries
                    // the typed id by construction — the exact statement the
                    // late-parsing consumers (history_floor / retention) made
                    // can never fail.
                    for pin in cfg.pins() {
                        let rid = pin.release.clone();
                        assert_eq!(ReleaseId::parse(rid.as_str()).unwrap(), rid);
                    }
                    assert_domain_invariants(&cfg);
                }
                Err(err) => {
                    // The exactly-direction: a bad pin is present, the load
                    // failed closed, and the error names the FIRST bad pin
                    // (the conversion stops at the first [`ReleaseId::parse`]
                    // failure).
                    assert!(!every_pin_valid);
                    let (first_bad, _) = pins
                        .iter()
                        .find(|(r, _)| ReleaseId::parse(r).is_err())
                        .expect("at least one bad pin when the load fails");
                    let msg = err.to_string();
                    assert!(
                        msg.contains(&format!("invalid ReleaseId value {first_bad:?}")),
                        "the load must fail on the FIRST bad pin (message: {msg})"
                    );
                }
            }
        }
    }

    // =====================================================================
    // THE REBUILD-OP PROPERTY: validated graph-rebuilding operations
    // =====================================================================
    //
    // THE USER'S REQUIREMENT: the domain graph is IMMUTABLE — every mutation
    // is a VALIDATED operation returning a NEW [`ProjectConfig`] (or `Err`
    // with the ORIGINAL untouched). The property generates VALID
    // configurations plus ARBITRARY update operations (add/remove/rename a
    // server, a target, a pin, a slot; change a connection field); every
    // SUCCESSFUL result must satisfy the ONE central
    // [`assert_domain_invariants`], and every INVALID update must FAIL and
    // PRESERVE the original (its accessors are unchanged).

    /// A server template: (id, address, user, known_hosts, fingerprint).
    type ServerTemplate = (
        &'static str,
        &'static str,
        &'static str,
        Option<&'static str>,
        Option<&'static str>,
    );

    /// A valid raw project by construction: 1..=2 servers from a pool of
    /// valid templates, 1..=2 targets, and slots that reference the chosen
    /// servers/targets with unique ids and deploy_dirs (one slot per server
    /// per target). The conversion always succeeds.
    fn valid_raw_project() -> impl Strategy<Value = RawProject> {
        let server_templates: Vec<ServerTemplate> = vec![
            ("s1", "local:///srv/s1", "u", None, None),
            (
                "s2",
                "db.example.com",
                "ops",
                Some("/etc/ssh/known_hosts"),
                None,
            ),
            ("s3", "web.example.com", "deploy", None, Some("SHA256:test")),
        ];
        let target_names: Vec<&str> = vec!["t1", "t2", "t3"];
        prop::sample::subsequence(server_templates, 1..=2).prop_flat_map(move |servers| {
            let n_servers = servers.len();
            prop::sample::subsequence(target_names.clone(), 1..=2).prop_flat_map(move |targets| {
                // One plan per target: distinct server indices (the
                // per-target one-server rule holds by construction).
                let plan = prop::collection::vec(
                    prop::sample::subsequence((0..n_servers).collect::<Vec<_>>(), 1..=n_servers),
                    targets.len(),
                );
                let servers = servers.clone();
                let targets = targets.clone();
                plan.prop_map(move |plans| {
                    let mut raw_servers = Vec::new();
                    for (id, address, user, kh, fp) in &servers {
                        raw_servers.push(raw::RawServer {
                            id: id.to_string(),
                            address: address.to_string(),
                            user: user.to_string(),
                            port: 22,
                            known_hosts: kh.map(PathBuf::from),
                            host_key_fingerprint: fp.map(|s| s.to_string()),
                            capacity: raw::RawCapacityConfig::default(),
                        });
                    }
                    let mut raw_targets = BTreeMap::new();
                    for t in &targets {
                        raw_targets.insert(
                            t.to_string(),
                            raw::RawTargetConfig {
                                rollout: raw::RawRolloutConfig::default(),
                            },
                        );
                    }
                    let mut slots = Vec::new();
                    for (t, plan) in targets.iter().zip(&plans) {
                        for (i, &server_idx) in plan.iter().enumerate() {
                            let slot_id = format!("{t}-{i}");
                            slots.push(SlotConfig::new(
                                slot_id.clone(),
                                servers[server_idx].0.to_string(),
                                PathBuf::from(format!("/srv/{slot_id}")),
                                t.to_string(),
                                Vec::new(),
                            ));
                        }
                    }
                    let mut variant = minimal_raw_variant();
                    variant.slots = slots;
                    RawProject {
                        manifest: raw::RawConfig {
                            schema_version: CONFIG_SCHEMA_VERSION,
                            application: "app".to_string(),
                            release: ReleaseName::new("v1"),
                            pins: Vec::new(),
                            servers: raw_servers,
                            targets: raw_targets,
                        },
                        variants: BTreeMap::from([("standard".to_string(), variant)]),
                    }
                })
            })
        })
    }

    /// One arbitrary update operation: add/remove/rename a server, a target,
    /// a pin, or a slot, or change a server's connection. The payloads are
    /// arbitrary (valid or not); the operation either succeeds (the result
    /// must satisfy the domain invariants) or fails (the original is
    /// untouched).
    #[derive(Clone, Debug)]
    enum UpdateOp {
        AddServer(ServerDef),
        RemoveServer(String),
        RenameServer(String, String),
        AddTarget(String, TargetConfig),
        RemoveTarget(String),
        RenameTarget(String, String),
        AddPin(Pin),
        RemovePin(ReleaseId),
        RenamePin(ReleaseId, ReleaseId),
        AddSlot(String, SlotConfig),
        RemoveSlot(String, String),
        RenameSlot(String, String, String),
        SetConnection(String, ServerConnection),
    }

    impl UpdateOp {
        fn apply(&self, config: &ProjectConfig) -> Result<ProjectConfig> {
            match self {
                UpdateOp::AddServer(s) => config.with_server(s.clone()),
                UpdateOp::RemoveServer(id) => config.without_server(id),
                UpdateOp::RenameServer(a, b) => config.rename_server(a, b),
                UpdateOp::AddTarget(n, t) => config.with_target(n, t.clone()),
                UpdateOp::RemoveTarget(n) => config.without_target(n),
                UpdateOp::RenameTarget(a, b) => config.rename_target(a, b),
                UpdateOp::AddPin(p) => config.with_pin(p.clone()),
                UpdateOp::RemovePin(r) => config.without_pin(r),
                UpdateOp::RenamePin(a, b) => config.rename_pin(a, b),
                UpdateOp::AddSlot(v, s) => config.with_slot(v, s.clone()),
                UpdateOp::RemoveSlot(v, s) => config.without_slot(v, s),
                UpdateOp::RenameSlot(v, a, b) => config.rename_slot(v, a, b),
                UpdateOp::SetConnection(id, c) => config.with_server_connection(id, c.clone()),
            }
        }
    }

    /// An arbitrary host identity: any form, including the impossible
    /// combinations the connection well-formedness rule must reject (a
    /// `Local` identity inside an SSH connection, a relative `known_hosts`).
    fn arbitrary_identity() -> impl Strategy<Value = HostIdentity> {
        prop_oneof![
            Just(HostIdentity::Local),
            prop::sample::select(vec![
                PathBuf::from("/etc/ssh/known_hosts"),
                PathBuf::from("relative/kh"),
            ])
            .prop_map(HostIdentity::KnownHosts),
            Just(HostIdentity::Fingerprint(
                Fingerprint::parse("SHA256:test").unwrap()
            )),
        ]
    }

    /// An arbitrary connection: a local form with an arbitrary address (valid
    /// or not), or an SSH form with arbitrary host/user/port/identity (the
    /// identity may be any form, including the impossible `Local` inside an
    /// SSH connection).
    fn arbitrary_connection() -> impl Strategy<Value = ServerConnection> {
        prop_oneof![
            arbitrary_identifier().prop_map(|address| ServerConnection::Local {
                address,
                identity: HostIdentity::Local,
            }),
            (
                prop::sample::select(vec!["host", "db.example.com", "x y", ""]),
                prop::sample::select(vec!["user", "ops", "x y", ""]),
                any::<u16>(),
                arbitrary_identity(),
            )
                .prop_map(|(address, user, port, identity)| ServerConnection::Ssh {
                    address: Host::parse(address).unwrap_or_else(|_| Host::parse("host").unwrap()),
                    user: SshUser::parse(user).unwrap_or_else(|_| SshUser::parse("user").unwrap()),
                    port: NonZeroU16::new(port).unwrap_or(NonZeroU16::new(1).unwrap()),
                    identity,
                }),
        ]
    }

    /// An arbitrary domain server: a valid id (the scalar is validated by
    /// construction) with an arbitrary connection and capacity.
    fn arbitrary_server_def() -> impl Strategy<Value = ServerDef> {
        (
            prop::sample::select(vec!["s1", "s2", "s3", "s4", "new-server"]),
            arbitrary_connection(),
            arbitrary_capacity_domain(),
        )
            .prop_map(|(id, connection, capacity)| {
                ServerDef::new(Identifier::parse(id).unwrap(), connection, capacity)
            })
    }

    /// An arbitrary domain capacity policy (the percent is validated by
    /// construction).
    fn arbitrary_capacity_domain() -> impl Strategy<Value = CapacityConfig> {
        (any::<u64>(), 0u8..=100).prop_map(|(reserve_bytes, reserve_percent)| CapacityConfig {
            reserve_bytes,
            reserve_percent: CapacityPercent::new(reserve_percent).unwrap(),
        })
    }

    /// An arbitrary domain target (the batch size is validated by
    /// construction).
    fn arbitrary_target_domain() -> impl Strategy<Value = TargetConfig> {
        (any::<u32>(), any::<bool>(), arbitrary_failure_policy()).prop_map(
            |(batch_size, stop_on_failure, failure_policy)| TargetConfig {
                rollout: RolloutConfig {
                    batch_size: BatchSize::new(u64::from(batch_size))
                        .unwrap_or(BatchSize::new(1).unwrap()),
                    stop_on_failure,
                    failure_policy,
                },
            },
        )
    }

    /// An arbitrary update operation over the whole op space.
    fn arbitrary_op() -> impl Strategy<Value = UpdateOp> {
        prop_oneof![
            arbitrary_server_def().prop_map(UpdateOp::AddServer),
            arbitrary_identifier().prop_map(UpdateOp::RemoveServer),
            (arbitrary_identifier(), arbitrary_identifier())
                .prop_map(|(a, b)| UpdateOp::RenameServer(a, b)),
            (arbitrary_identifier(), arbitrary_target_domain())
                .prop_map(|(n, t)| UpdateOp::AddTarget(n, t)),
            arbitrary_identifier().prop_map(UpdateOp::RemoveTarget),
            (arbitrary_identifier(), arbitrary_identifier())
                .prop_map(|(a, b)| UpdateOp::RenameTarget(a, b)),
            (arbitrary_release_id(), arbitrary_identifier())
                .prop_map(|(release, reason)| UpdateOp::AddPin(Pin { release, reason })),
            arbitrary_release_id().prop_map(UpdateOp::RemovePin),
            (arbitrary_release_id(), arbitrary_release_id())
                .prop_map(|(a, b)| UpdateOp::RenamePin(a, b)),
            (arbitrary_identifier(), arbitrary_slot()).prop_map(|(v, s)| UpdateOp::AddSlot(v, s)),
            (arbitrary_identifier(), arbitrary_identifier())
                .prop_map(|(v, s)| UpdateOp::RemoveSlot(v, s)),
            (
                arbitrary_identifier(),
                arbitrary_identifier(),
                arbitrary_identifier()
            )
                .prop_map(|(v, a, b)| UpdateOp::RenameSlot(v, a, b)),
            (arbitrary_identifier(), arbitrary_connection())
                .prop_map(|(id, c)| UpdateOp::SetConnection(id, c)),
        ]
    }

    proptest! {
        // THE PROPERTY: over VALID configurations (generated by construction)
        // plus ARBITRARY update operations, every SUCCESSFUL result satisfies
        // the ONE central [`assert_domain_invariants`] (every reference
        // resolves, ids valid, no impossible combos, the connection enum is
        // well-formed), and every INVALID update FAILS and PRESERVES the
        // original (its accessors are unchanged). Bounded 16 cases, fixed
        // seed 0x5EED_5EED per house style, no failure persistence; the
        // generation is pure (no filesystem), so the property stays fast.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn validated_rebuild_ops_preserve_invariants(
            project in valid_raw_project(),
            ops in prop::collection::vec(arbitrary_op(), 0..8),
        ) {
            let config = ProjectConfig::from_raw_parts(project.manifest, project.variants)
                .expect("the generated project is valid by construction");
            assert_domain_invariants(&config);
            let mut current = config;
            for op in &ops {
                let original = current.clone();
                match op.apply(&current) {
                    Ok(next) => {
                        assert_domain_invariants(&next);
                        current = next;
                    }
                    Err(_) => {
                        assert_eq!(
                            current, original,
                            "a failed update must leave the original untouched"
                        );
                    }
                }
            }
        }
    }

    // ---- deterministic unit tests per update class ----------------------

    /// The minimal valid config used by the per-class unit tests.
    fn unit_config() -> ProjectConfig {
        let p = minimal_raw_project();
        ProjectConfig::from_raw_parts(p.manifest, p.variants).expect("minimal project converts")
    }

    fn ssh_connection() -> ServerConnection {
        ServerConnection::Ssh {
            address: Host::parse("db.example.com").unwrap(),
            user: SshUser::parse("ops").unwrap(),
            port: NonZeroU16::new(2222).unwrap(),
            identity: HostIdentity::Fingerprint(Fingerprint::parse("SHA256:test").unwrap()),
        }
    }

    #[test]
    fn with_server_adds_and_replaces() {
        let cfg = unit_config();
        // Add a new server: succeeds, the graph stays valid.
        let added = cfg
            .with_server(ServerDef::new(
                Identifier::parse("s2").unwrap(),
                ssh_connection(),
                CapacityConfig::default(),
            ))
            .unwrap();
        assert_eq!(added.servers().count(), 2);
        assert_domain_invariants(&added);
        // The original is untouched.
        assert_eq!(cfg.servers().count(), 1);

        // Replace an existing server: succeeds.
        let replaced = added
            .with_server(ServerDef::new(
                Identifier::parse("s1").unwrap(),
                ServerConnection::Local {
                    address: "local:///srv/other".to_string(),
                    identity: HostIdentity::Local,
                },
                CapacityConfig::default(),
            ))
            .unwrap();
        assert_eq!(replaced.servers().count(), 2);
        assert_domain_invariants(&replaced);

        // An ill-formed connection (SSH with a Local identity) is rejected
        // and the original is untouched.
        let bad = cfg.with_server(ServerDef::new(
            Identifier::parse("s2").unwrap(),
            ServerConnection::Ssh {
                address: Host::parse("db.example.com").unwrap(),
                user: SshUser::parse("ops").unwrap(),
                port: NonZeroU16::new(2222).unwrap(),
                identity: HostIdentity::Local,
            },
            CapacityConfig::default(),
        ));
        assert!(bad.is_err());
        assert_eq!(cfg.servers().count(), 1);
    }

    #[test]
    fn without_server_fails_when_referenced() {
        let cfg = unit_config();
        // s1 is referenced by slot p1: removing it must fail (the graph
        // would dangle); the original is untouched.
        assert!(cfg.without_server("s1").is_err());
        assert_eq!(cfg.servers().count(), 1);
        // An unknown server fails.
        assert!(cfg.without_server("ghost").is_err());
    }

    #[test]
    fn rename_server_rewrites_slot_references() {
        let cfg = unit_config();
        let renamed = cfg.rename_server("s1", "s1b").unwrap();
        assert!(renamed.server("s1").is_none());
        assert!(renamed.server("s1b").is_some());
        // The slot reference was rewritten.
        let (slot, server) = renamed.target_slots("t1").unwrap()[0];
        assert_eq!(slot.server, "s1b");
        assert_eq!(server.id.as_str(), "s1b");
        assert_domain_invariants(&renamed);
        // Renaming onto an existing id fails.
        assert!(cfg.rename_server("s1", "s1").is_err());
    }

    #[test]
    fn with_target_replaces_and_rejects_empty() {
        let cfg = unit_config();
        // Replacing an existing target's rollout succeeds.
        let replaced = cfg
            .with_target(
                "t1",
                TargetConfig {
                    rollout: RolloutConfig::default(),
                },
            )
            .unwrap();
        assert_domain_invariants(&replaced);
        // A NEW target with no member slots fails (the per-target non-empty
        // rule is re-validated); the original is untouched.
        assert!(
            cfg.with_target(
                "t2",
                TargetConfig {
                    rollout: RolloutConfig::default()
                }
            )
            .is_err()
        );
        assert!(cfg.target("t2").is_none());
    }

    #[test]
    fn without_target_fails_when_referenced() {
        let cfg = unit_config();
        // t1 is referenced by slot p1: removing it must fail; the original
        // is untouched.
        assert!(cfg.without_target("t1").is_err());
        assert!(cfg.target("t1").is_some());
        // An unknown target fails.
        assert!(cfg.without_target("ghost").is_err());
    }

    #[test]
    fn rename_target_rewrites_slot_references() {
        let cfg = unit_config();
        let renamed = cfg.rename_target("t1", "t1b").unwrap();
        assert!(renamed.target("t1").is_none());
        assert!(renamed.target("t1b").is_some());
        let (slot, _) = renamed.target_slots("t1b").unwrap()[0];
        assert_eq!(slot.target, "t1b");
        assert_domain_invariants(&renamed);
        // Renaming to the same name is a valid no-op.
        let same = cfg.rename_target("t1", "t1").unwrap();
        assert_eq!(same.target_slot_ids("t1").unwrap(), vec!["p1"]);
    }

    #[test]
    fn pin_ops_add_remove_rename() {
        let cfg = unit_config();
        let pin = Pin {
            release: crate::model::test_release_id("rel-1"),
            reason: "known-good".to_string(),
        };
        let added = cfg.with_pin(pin.clone()).unwrap();
        assert_eq!(added.pins().len(), 1);
        assert_eq!(added.pins()[0].release, pin.release);
        // Removing a pin that is not present fails.
        assert!(cfg.without_pin(&pin.release).is_err());
        let removed = added.without_pin(&pin.release).unwrap();
        assert!(removed.pins().is_empty());
        // Renaming rewrites the release (both ids are typed, so the new
        // release is valid by construction).
        let other = crate::model::test_release_id("rel-2");
        let renamed = added.rename_pin(&pin.release, &other).unwrap();
        assert_eq!(renamed.pins()[0].release, other);
        assert!(
            added
                .rename_pin(
                    &crate::model::test_release_id("rel-9"),
                    &crate::model::test_release_id("rel-3")
                )
                .is_err()
        );
    }

    #[test]
    fn with_slot_adds_and_rejects_invalid() {
        let cfg = unit_config();
        // Add a second server, then a slot on it for t1.
        let two = cfg
            .with_server(ServerDef::new(
                Identifier::parse("s2").unwrap(),
                ServerConnection::Local {
                    address: "local:///srv/s2".to_string(),
                    identity: HostIdentity::Local,
                },
                CapacityConfig::default(),
            ))
            .unwrap();
        let added = two
            .with_slot(
                "standard",
                SlotConfig::new("p2", "s2", "/srv/p2", "t1", Vec::new()),
            )
            .unwrap();
        assert_eq!(added.slot_defs().len(), 2);
        assert_domain_invariants(&added);

        // A slot referencing an unknown server is rejected; the original is
        // untouched.
        assert!(
            two.with_slot(
                "standard",
                SlotConfig::new("p2", "ghost", "/srv/p2", "t1", Vec::new())
            )
            .is_err()
        );
        assert_eq!(two.slot_defs().len(), 1);

        // A relative deploy_dir is rejected.
        assert!(
            two.with_slot(
                "standard",
                SlotConfig::new("p2", "s2", "srv/p2", "t1", Vec::new())
            )
            .is_err()
        );

        // Replacing an existing slot (keyed by id) is a valid update.
        let replaced = two
            .with_slot(
                "standard",
                SlotConfig::new("p1", "s2", "/srv/p2", "t1", Vec::new()),
            )
            .unwrap();
        assert_eq!(replaced.slot_defs().len(), 1);
        assert_eq!(replaced.slot_defs()[0].server, "s2");
        assert_domain_invariants(&replaced);

        // An unknown variant is rejected.
        assert!(
            two.with_slot(
                "ghost",
                SlotConfig::new("p2", "s2", "/srv/p2", "t1", Vec::new())
            )
            .is_err()
        );
    }

    #[test]
    fn without_slot_fails_when_target_loses_all_members() {
        let cfg = unit_config();
        // Removing the only slot of t1 leaves t1 without members: rejected;
        // the original is untouched.
        assert!(cfg.without_slot("standard", "p1").is_err());
        assert_eq!(cfg.slot_defs().len(), 1);
        // An unknown slot fails.
        assert!(cfg.without_slot("standard", "ghost").is_err());
    }

    #[test]
    fn rename_slot_rewrites_the_id() {
        let cfg = unit_config();
        let renamed = cfg.rename_slot("standard", "p1", "p1b").unwrap();
        assert_eq!(renamed.target_slot_ids("t1").unwrap(), vec!["p1b"]);
        assert_domain_invariants(&renamed);
        assert!(cfg.rename_slot("standard", "ghost", "p9").is_err());
    }

    #[test]
    fn with_server_connection_validates_the_enum() {
        let cfg = unit_config();
        // A valid SSH connection replaces the local one.
        let ssh = cfg.with_server_connection("s1", ssh_connection()).unwrap();
        assert!(matches!(
            ssh.server("s1").unwrap().connection(),
            ServerConnection::Ssh { .. }
        ));
        assert_domain_invariants(&ssh);

        // An SSH connection with a Local identity is rejected; the original
        // is untouched.
        let bad = cfg.with_server_connection(
            "s1",
            ServerConnection::Ssh {
                address: Host::parse("db.example.com").unwrap(),
                user: SshUser::parse("ops").unwrap(),
                port: NonZeroU16::new(2222).unwrap(),
                identity: HostIdentity::Local,
            },
        );
        assert!(bad.is_err());
        assert!(matches!(
            cfg.server("s1").unwrap().connection(),
            ServerConnection::Local { .. }
        ));

        // A local connection with a non-local address is rejected.
        let bad = cfg.with_server_connection(
            "s1",
            ServerConnection::Local {
                address: "not-local".to_string(),
                identity: HostIdentity::Local,
            },
        );
        assert!(bad.is_err());

        // An unknown server fails.
        assert!(
            cfg.with_server_connection(
                "ghost",
                ServerConnection::Local {
                    address: "local:///x".to_string(),
                    identity: HostIdentity::Local,
                },
            )
            .is_err()
        );
    }

    // =====================================================================
    // failure_policy: the strict FailurePolicy enum
    // =====================================================================
    //
    // THE BUG this pins: an unknown `failure_policy` spelling used to parse
    // into a loose String and silently behave as "leave changed" (fail-open:
    // an operator typo kept changed servers in their new state instead of
    // rolling back). The policy is now a typed enum whose parse is STRICT
    // EXACT — the parse-table test below pins every supported spelling, the
    // load-level test pins the fail-closed rejection through the real
    // `ProjectConfig::load` path, and the arbitrary-strings property pins the
    // accept-only-the-supported-spellings contract over the whole space.

    /// The STRICT parse table: the exact supported spellings
    /// (`rollback_changed`, `leave_changed`) parse to their variants; every
    /// OTHER spelling — case variants, whitespace, dashes, typos, the empty
    /// string — is rejected with a config error naming the valid options.
    #[test]
    fn failure_policy_parse_table_is_strict_exact() {
        // The two supported spellings (matching the existing docs).
        assert_eq!(
            "rollback_changed".parse::<FailurePolicy>().unwrap(),
            FailurePolicy::RollbackChanged
        );
        assert_eq!(
            "leave_changed".parse::<FailurePolicy>().unwrap(),
            FailurePolicy::LeaveChanged
        );
        // The canonical spellings round-trip through Display/as_str.
        assert_eq!(FailurePolicy::RollbackChanged.as_str(), "rollback_changed");
        assert_eq!(FailurePolicy::LeaveChanged.as_str(), "leave_changed");
        assert_eq!(
            FailurePolicy::RollbackChanged.to_string(),
            "rollback_changed"
        );

        // Everything else is REJECTED — exact match, no normalization, no
        // case folding, no whitespace trimming, no aliases.
        for bad in [
            "",
            "rollback",
            "leave",
            "leave-changed",
            "rollback-changed",
            "ROLLBACK_CHANGED",
            "RollbackChanged",
            "Rollback_Changed",
            " rollback_changed",
            "rollback_changed ",
            "rollbackchanged",
            "frobnicate",
            "none",
            "roll back changed",
            "rollback_changed\n",
        ] {
            let err = bad
                .parse::<FailurePolicy>()
                .expect_err("unsupported spelling must be rejected");
            let msg = err.to_string();
            assert!(
                msg.contains("failure_policy") && msg.contains(&format!("'{bad}'")),
                "error must name the rejected spelling, got: {msg}"
            );
            assert!(
                msg.contains("rollback_changed") && msg.contains("leave_changed"),
                "error must name the valid options, got: {msg}"
            );
        }
    }

    /// THE BUG end-to-end: an unknown `failure_policy` spelling in a real
    /// `deploy.toml` is rejected at `ProjectConfig::load` (the merged raw -> domain
    /// conversion) with a config error naming the valid options — it can
    /// NEVER silently behave as "leave changed".
    #[test]
    fn unknown_failure_policy_spelling_is_rejected_at_load() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let p = project.join("deploy.toml");
        // Every valid spelling loads; every unsupported spelling fails the
        // whole load with the strict parse error.
        for ok in ["rollback_changed", "leave_changed"] {
            std::fs::write(&p, deploy_toml("v1").replace("rollback_changed", ok)).unwrap();
            ProjectConfig::load(&p).expect("supported spelling loads");
        }
        for bad in ["rollback", "leave", "RollbackChanged", "ROLLBACK"] {
            std::fs::write(&p, deploy_toml("v1").replace("rollback_changed", bad)).unwrap();
            let err = ProjectConfig::load(&p).expect_err("unsupported spelling must fail the load");
            let msg = err.to_string();
            assert!(
                msg.contains("failure_policy") && msg.contains(bad),
                "error must name the rejected spelling, got: {msg}"
            );
            assert!(
                msg.contains("rollback_changed") && msg.contains("leave_changed"),
                "error must name the valid options, got: {msg}"
            );
        }
    }

    /// The default stays `RollbackChanged` — an omitted `failure_policy` is
    /// the safe fail-closed default, never "leave changed".
    #[test]
    fn failure_policy_defaults_to_rollback_changed() {
        assert_eq!(
            RolloutConfig::default().failure_policy,
            FailurePolicy::RollbackChanged
        );
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let p = project.join("deploy.toml");
        // Drop the failure_policy key entirely (defaults to rollback_changed).
        let minimal_rollout =
            deploy_toml("v1").replace(", failure_policy = \"rollback_changed\" }", " }");
        std::fs::write(&p, minimal_rollout).unwrap();
        let cfg = ProjectConfig::load(&p).expect("omitted failure_policy defaults");
        assert_eq!(
            cfg.targets["t1"].rollout.failure_policy,
            FailurePolicy::RollbackChanged
        );
    }

    proptest! {
        // THE STRICT-PARSE PROPERTY: over ARBITRARY strings the failure
        // policy parses iff the string is EXACTLY one of the two supported
        // spellings, and every rejection carries a config error naming the
        // valid options. Bounded 16 cases, fixed seed 0x5EED_5EED (house
        // style), no persistence — the identical vectors on every run. This
        // is the property half of the user's requirement: parsing must be
        // success-only-for-supported-spellings, never an implicit fallback.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn failure_policy_arbitrary_strings_parse_only_supported_spellings(s in any::<String>()) {
            let parsed = FailurePolicy::from_str(&s);
            match parsed {
                Ok(policy) => {
                    assert!(
                        s == "rollback_changed" || s == "leave_changed",
                        "a non-supported string must not parse: {s:?} -> {policy:?}"
                    );
                    // The parse round-trips to the exact spelling.
                    assert_eq!(policy.as_str(), s);
                }
                Err(e) => {
                    assert!(
                        s != "rollback_changed" && s != "leave_changed",
                        "the supported spellings must always parse: {s:?}"
                    );
                    let msg = e.to_string();
                    assert!(
                        msg.contains("rollback_changed") && msg.contains("leave_changed"),
                        "the rejection must name the valid options, got: {msg}"
                    );
                }
            }
        }
    }

    // =====================================================================
    // THE SCALAR PROPERTY: arbitrary raw scalar values convert iff the scalar
    // =====================================================================

    /// Arbitrary raw strings for a config scalar field: empty, whitespace,
    /// format-violating, out-of-range, and valid forms.
    fn arbitrary_scalar_text() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(vec![
                String::new(),
                " ".to_string(),
                "s1".to_string(),
                "production".to_string(),
                "wave-1".to_string(),
                " x".to_string(),
                "x ".to_string(),
                "x y".to_string(),
                "α".to_string(),
                "a\nb".to_string(),
                "/srv/p1".to_string(),
                "/srv/deploy/app".to_string(),
                "srv/relative".to_string(),
            ]),
            prop::collection::vec(prop::char::any(), 0..8).prop_map(|v| v.into_iter().collect()),
        ]
    }

    /// One scalar-mutation case: the minimal valid raw project with EXACTLY
    /// ONE scalar field set to an arbitrary raw value, paired with the
    /// scalar's own parse verdict on that value. Each mutation is isolated:
    /// no other conversion gate can fire, so the conversion outcome is the
    /// scalar outcome exactly.
    fn scalar_mutation_project() -> impl Strategy<Value = (RawProject, bool)> {
        prop_oneof![
            // application: ApplicationStoreKey (single safe segment).
            arbitrary_scalar_text().prop_map(|v| {
                let mut p = minimal_raw_project();
                p.manifest.application = v.clone();
                (p, ApplicationStoreKey::parse(&v).is_ok())
            }),
            // slot id: Identifier.
            arbitrary_scalar_text().prop_map(|v| {
                let mut p = minimal_raw_project();
                p.variants.get_mut("standard").unwrap().slots[0].id = v.clone();
                (p, Identifier::parse(&v).is_ok())
            }),
            // variant name: Identifier.
            arbitrary_scalar_text().prop_map(|v| {
                let mut p = minimal_raw_project();
                p.variants = BTreeMap::from([(v.clone(), minimal_raw_variant())]);
                (p, Identifier::parse(&v).is_ok())
            }),
            // slot group (single element: the duplicate rule cannot fire):
            // RolloutGroupName.
            arbitrary_scalar_text().prop_map(|v| {
                let mut p = minimal_raw_project();
                p.variants.get_mut("standard").unwrap().slots[0].groups = vec![v.clone()];
                (p, RolloutGroupName::parse(&v).is_ok())
            }),
            // slot deploy_dir (single slot: the location-uniqueness rule
            // cannot fire): AbsoluteDeployDir.
            arbitrary_scalar_text().prop_map(|v| {
                let mut p = minimal_raw_project();
                p.variants.get_mut("standard").unwrap().slots[0].deploy_dir = PathBuf::from(&v);
                (p, AbsoluteDeployDir::parse(&v).is_ok())
            }),
            // batch_size (any u32, including zero): BatchSize.
            any::<u32>().prop_map(|v| {
                let mut p = minimal_raw_project();
                p.manifest.targets.get_mut("t1").unwrap().rollout.batch_size = v;
                (p, BatchSize::new(u64::from(v)).is_ok())
            }),
            // capacity reserve_percent (any u8, including 101..):
            // CapacityPercent.
            any::<u8>().prop_map(|v| {
                let mut p = minimal_raw_project();
                p.manifest.servers[0].capacity.reserve_percent = v;
                (p, CapacityPercent::new(v).is_ok())
            }),
        ]
    }

    proptest! {
        // THE PROPERTY: over ARBITRARY raw values for each config scalar
        // field (empty, format-violating, out-of-range, invalid), the raw ->
        // domain conversion accepts EXACTLY the values the scalar accepts
        // (non-empty/format for names and the digest, absolute for
        // deploy_dir, nonzero for batch_size, 0..=100 for capacity percent)
        // and rejects everything else with a config error (fail closed).
        // Bounded 16 cases, fixed seed 0x5EED_5EED per house style.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn arbitrary_scalar_values_convert_fail_closed((project, expected) in scalar_mutation_project()) {
            match ProjectConfig::from_raw_parts(project.manifest, project.variants) {
                Ok(cfg) => {
                    assert!(
                        expected,
                        "the conversion must accept exactly the values the scalar accepts"
                    );
                    // The accepted scalar is carried into the domain.
                    assert_domain_invariants(&cfg);
                }
                Err(e) => {
                    assert!(
                        !expected,
                        "the conversion must accept a value the scalar accepts, got: {e}"
                    );
                    assert!(
                        matches!(e, Error::Config(_)),
                        "the rejection must be a config error, got: {e}"
                    );
                }
            }
        }
    }

    // =====================================================================
    // application: ONE safe identifier for display AND storage
    // =====================================================================
    //
    // The config's `application` field IS the store key
    // ([`crate::scalar::ApplicationStoreKey`]): a single safe path segment
    // used for both display and storage. The raw -> domain conversion
    // parses it AS the store key, so a display name that is not a safe key
    // FAILS THE LOAD (fail closed at load, not at the store boundary), and
    // a successfully loaded config constructs its LocalStore directly from
    // `config.application()` — no fallible identity conversion remains.

    #[test]
    fn application_name_is_the_store_key_load_and_store() {
        // A SAFE application name LOADS and constructs the store: the
        // config's `application` IS the store key, so the load implies the
        // store construction with no further fallible identity conversion.
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let p = project.join("deploy.toml");
        std::fs::write(
            &p,
            deploy_toml("v1").replace("application = \"forced\"", "application = \"my-app\""),
        )
        .unwrap();
        let cfg = ProjectConfig::load(&p).expect("a safe application name loads");
        assert_eq!(cfg.application().as_str(), "my-app");
        // The store is constructed DIRECTLY from the config's application
        // (the field IS the key): `LocalStore::new(&config.application())`.
        let _lock = crate::testutil::ENV_LOCK.lock().unwrap();
        let store_root = crate::testutil::hermetic_tmpdir_root();
        unsafe { std::env::set_var("TMPDIR", &store_root) };
        let store = LocalStore::new(cfg.application())
            .expect("a loaded config must construct its LocalStore");
        assert_eq!(
            store.base().file_name(),
            Some(std::ffi::OsStr::new("my-app")),
            "the store sits under <base>/<application>"
        );
        unsafe { std::env::remove_var("TMPDIR") };
        let _ = std::fs::remove_dir_all(store_root.join("deploy-test"));

        // An UNSAFE application name (a path separator, a traversal
        // component, or padding) FAILS THE LOAD — fail closed at load, not
        // at the store boundary.
        for bad in ["a/b", "a\\b", "..", ".", "../x", "x/..", " x", "x "] {
            let mut raw = minimal_raw_project();
            raw.manifest.application = bad.to_string();
            let err = ProjectConfig::from_raw_parts(raw.manifest, raw.variants)
                .expect_err("an unsafe application name must fail the load");
            assert!(
                matches!(err, Error::Config(_)),
                "the rejection must be a config error, got: {err}"
            );
        }
    }

    // -------------------------------------------------------------------
    // THE LOAD-IMPLIES-STORE PROPERTY: over ARBITRARY application names
    // (empty, `/`/`\`-separated, `.`/`..` traversal, padded, control,
    // unicode, and clean single segments), EVERY configuration the raw ->
    // domain conversion ACCEPTS must ALSO construct its LocalStore — the
    // config's `application` IS the store key (one safe identifier for
    // display and storage), so the load implies the store construction
    // with NO further fallible identity conversion; and a config whose
    // application is not a safe key FAILS THE LOAD (fail closed at load,
    // not at the store boundary). The generated alphabet is
    // FILESYSTEM-SAFE (every accepted name is encodable on the local
    // filesystem), so the store construction is asserted to SUCCEED for
    // every accepted config; the full arbitrary space — including
    // filesystem-incompatible unicode, which fails the store open with a
    // STORE error (fail closed, never an escape) — is pinned by the
    // scalar-level store-key property. Bounded 16 cases, fixed seed
    // 0x5EED_5EED per house style.
    // -------------------------------------------------------------------

    /// Arbitrary application-name text over a FILESYSTEM-SAFE alphabet:
    /// every identity-relevant class (empty, separators, traversal
    /// components, padding, control characters, unicode, clean segments)
    /// plus random strings over ASCII printable (minus `/`) and a safe
    /// unicode letter — every generated name is encodable on the local
    /// filesystem, so a name the conversion accepts ALWAYS constructs its
    /// store.
    fn arbitrary_application_text() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(vec![
                String::new(),
                " ".to_string(),
                "s1".to_string(),
                "production".to_string(),
                "wave-1".to_string(),
                " x".to_string(),
                "x ".to_string(),
                "x y".to_string(),
                "α".to_string(),
                "a\nb".to_string(),
                "/srv/p1".to_string(),
                "/srv/deploy/app".to_string(),
                "srv/relative".to_string(),
                "..".to_string(),
                ".".to_string(),
                "../x".to_string(),
                "x/..".to_string(),
                "a..b".to_string(),
                "a.b".to_string(),
            ]),
            prop::collection::vec(
                prop::sample::select(vec!['a', 'b', 'c', '1', '2', '-', '_', '.', ' ', 'α']),
                0..8,
            )
            .prop_map(|v| v.into_iter().collect()),
        ]
    }

    /// One application-mutation case: the minimal valid raw project with
    /// ONLY the `application` field set to an arbitrary raw value, paired
    /// with the store-key parse verdict on that value. No other conversion
    /// gate can fire, so the conversion outcome is the application outcome
    /// exactly.
    fn application_mutation_project() -> impl Strategy<Value = (RawProject, bool)> {
        arbitrary_application_text().prop_map(|v| {
            let mut p = minimal_raw_project();
            p.manifest.application = v.clone();
            (p, ApplicationStoreKey::parse(&v).is_ok())
        })
    }

    #[test]
    fn loaded_config_always_constructs_its_store() {
        // The property constructs REAL stores via `LocalStore::new`, so the
        // process-global `$TMPDIR` is pointed at a hermetic temp root for
        // the whole run (ENV_LOCK serializes against every other
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
        }, |((project, expected) in application_mutation_project())| {
            match ProjectConfig::from_raw_parts(project.manifest, project.variants) {
                Ok(cfg) => {
                    assert!(
                        expected,
                        "the conversion must accept exactly the values the store key accepts"
                    );
                    // THE LOAD IMPLIES THE STORE: the config's application
                    // IS the store key — no fallible identity conversion
                    // remains between a loaded config and its store.
                    LocalStore::new(cfg.application())
                        .expect("a loaded config must construct its LocalStore");
                }
                Err(e) => {
                    assert!(
                        !expected,
                        "the conversion must accept a value the store key accepts, got: {e}"
                    );
                    assert!(
                        matches!(e, Error::Config(_)),
                        "the rejection must be a config error, got: {e}"
                    );
                }
            }
        });
        unsafe { std::env::remove_var("TMPDIR") };
        let _ = std::fs::remove_dir_all(store_root.join("deploy-test"));
    }

    // =====================================================================
    // load_release: the validated release-switch (a FRESH load)
    // =====================================================================
    //
    // [`ProjectConfig::load_release`] replaces the old in-memory `with_release`
    // mutation: the release switch is a FRESH LOAD of the project with the
    // new release selected — the deploy.toml is re-read, the release field is
    // overridden, and THAT release's variant files are re-discovered and
    // re-validated by the raw -> domain conversion. The property below pins
    // the contract: `load_release(path, R)` EQUALS a fresh `ProjectConfig::load`
    // of a project configured with R (identical variants, policies, and
    // scalars), and a MISSING or INVALID R fails the WHOLE load — no
    // partially-switched config can escape.

    /// Write a two-release project: `release_a` and `release_b` with
    /// DIFFERENT variant files and DIFFERENT policies. Release A declares
    /// the single `standard` variant (slot `p1`, retention
    /// `keep_distinct_artifacts = keep_a`); release B declares `standard`
    /// (slot `p1`, retention `keep_distinct_artifacts = keep_b`) PLUS the
    /// extra `extra` variant (no slots) — so the two releases differ in
    /// BOTH their variant sets and their retention policies. The shared
    /// deploy.toml carries the generated rollout (`batch_size`). Returns
    /// the `deploy.toml` path.
    fn write_two_release_project(
        project: &Path,
        release_a: &str,
        release_b: &str,
        keep_a: u32,
        keep_b: u32,
        batch_size: u32,
    ) -> PathBuf {
        let release_a_dir = project.join("releases").join(release_a);
        let release_b_dir = project.join("releases").join(release_b);
        std::fs::create_dir_all(&release_a_dir).unwrap();
        std::fs::create_dir_all(&release_b_dir).unwrap();
        std::fs::write(
            release_a_dir.join("standard.toml"),
            format!(
                "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[retention.per_server]\nkeep_distinct_artifacts = {keep_a}\n"
            ),
        )
        .unwrap();
        std::fs::write(
            release_b_dir.join("standard.toml"),
            format!(
                "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[retention.per_server]\nkeep_distinct_artifacts = {keep_b}\n"
            ),
        )
        .unwrap();
        // The extra variant (no slots) makes release B's variant set
        // strictly larger than release A's.
        std::fs::write(release_b_dir.join("extra.toml"), MINIMAL_VARIANT).unwrap();
        let p = project.join("deploy.toml");
        std::fs::write(
            &p,
            deploy_toml(release_a).replace("batch_size = 1", &format!("batch_size = {batch_size}")),
        )
        .unwrap();
        p
    }

    proptest! {
        // THE RELEASE-SWITCH PROPERTY: `load_release(path, R)` is a FRESH,
        // fully-validated load of the project with R selected — it EQUALS a
        // fresh `ProjectConfig::load` of a project configured with R (the two
        // configs are identical: same variants, same policies, same scalars),
        // and a MISSING or INVALID R (no variant files, or a variant file
        // that fails validation) fails the WHOLE load — the Err is a full
        // load failure, no partially-switched config escapes. Bounded 16
        // cases, fixed seed 0x5EED_5EED per house style.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn load_release_equals_fresh_load_and_fails_closed(
            release_a in "[a-z]{1,4}",
            release_b in "[a-z]{1,4}",
            keep_a in 1u32..=3,
            keep_b in 1u32..=3,
            batch_size in 1u32..=3,
        ) {
            // The two releases must be distinct directories (a rejected case
            // is regenerated by proptest).
            prop_assume!(release_a != release_b);
            let dir = tempfile::tempdir().unwrap();
            let project = dir.path().join("proj");
            std::fs::create_dir_all(&project).unwrap();
            let p = write_two_release_project(
                &project, &release_a, &release_b, keep_a, keep_b, batch_size,
            );

            // `load_release(path, R)` EQUALS a fresh `ProjectConfig::load` of
            // a project configured with R: the oracle deploy.toml names R and
            // the two configs are identical (variants, policies, scalars).
            for (release, keep) in [(&release_a, keep_a), (&release_b, keep_b)] {
                std::fs::write(
                    &p,
                    deploy_toml(release).replace(
                        "batch_size = 1",
                        &format!("batch_size = {batch_size}"),
                    ),
                )
                .unwrap();
                let oracle = ProjectConfig::load(&p).expect("the oracle project loads");
                let switched = ProjectConfig::load_release(
                    &p,
                    ReleaseName::parse(release).expect("a single-component release name parses"),
                )
                .expect("load_release loads the existing release");
                assert_eq!(
                    switched, oracle,
                    "load_release({release}) must equal a fresh load of a project configured with {release}"
                );
                assert_eq!(switched.release().as_str(), release);
                assert_eq!(
                    switched
                        .variant("standard")
                        .unwrap()
                        .retention
                        .per_server
                        .keep_distinct_artifacts,
                    keep,
                    "the release's own retention policy is loaded"
                );
                assert_eq!(
                    switched.targets["t1"].rollout.batch_size.get(),
                    u64::from(batch_size),
                    "the rollout scalar is carried identically"
                );
            }

            // The two releases genuinely differ: release B has the extra
            // variant and a different retention policy.
            let a = ProjectConfig::load_release(
                &p,
                ReleaseName::parse(&release_a).expect("a single-component release name parses"),
            )
            .expect("release A loads");
            let b = ProjectConfig::load_release(
                &p,
                ReleaseName::parse(&release_b).expect("a single-component release name parses"),
            )
            .expect("release B loads");
            assert_ne!(a, b, "the two releases' configs must differ");
            assert_eq!(a.variant_names(), vec!["standard".to_string()]);
            assert_eq!(
                b.variant_names(),
                vec!["extra".to_string(), "standard".to_string()]
            );

            // A MISSING release (no variant files) fails the WHOLE load: the
            // Err is a full load failure — no config object escapes.
            let err = ProjectConfig::load_release(
                &p,
                ReleaseName::parse("missing").expect("a single-component release name parses"),
            )
            .expect_err("a release with no variant files must fail the load");
            assert!(
                !err.to_string().is_empty(),
                "the load failure must carry a message"
            );

            // An INVALID release (a variant file that fails validation) fails
            // the WHOLE load: the raw -> domain conversion rejects it.
            let invalid_dir = project.join("releases").join("invalid");
            std::fs::create_dir_all(&invalid_dir).unwrap();
            std::fs::write(
                invalid_dir.join("bad.toml"),
                MINIMAL_VARIANT.replace("adapter = \"none\"", "adapter = \"bogus\""),
            )
            .unwrap();
            let err = ProjectConfig::load_release(
                &p,
                ReleaseName::parse("invalid").expect("a single-component release name parses"),
            )
            .expect_err("a release whose variant file fails validation must fail the load");
            assert!(
                !err.to_string().is_empty(),
                "the load failure must carry a message"
            );
        }
    }

    #[test]
    fn load_release_switches_between_two_releases() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let p = write_two_release_project(&project, "v1", "v2", 1, 5, 2);

        // The oracle: a fresh load of a project configured with each release.
        std::fs::write(
            &p,
            deploy_toml("v1").replace("batch_size = 1", "batch_size = 2"),
        )
        .unwrap();
        let oracle_v1 = ProjectConfig::load(&p).unwrap();
        std::fs::write(
            &p,
            deploy_toml("v2").replace("batch_size = 1", "batch_size = 2"),
        )
        .unwrap();
        let oracle_v2 = ProjectConfig::load(&p).unwrap();

        // load_release(path, R) equals the fresh load of a project configured
        // with R — the switch is a full re-validation, never a partial switch.
        let v1 = ProjectConfig::load_release(&p, ReleaseName::parse("v1").unwrap()).unwrap();
        let v2 = ProjectConfig::load_release(&p, ReleaseName::parse("v2").unwrap()).unwrap();
        assert_eq!(v1, oracle_v1);
        assert_eq!(v2, oracle_v2);
        assert_eq!(v1.release().as_str(), "v1");
        assert_eq!(v2.release().as_str(), "v2");

        // The two releases differ in variants and policies.
        assert_ne!(v1, v2);
        assert_eq!(v1.variant_names(), vec!["standard".to_string()]);
        assert_eq!(
            v2.variant_names(),
            vec!["extra".to_string(), "standard".to_string()]
        );
        assert_eq!(
            v1.variant("standard")
                .unwrap()
                .retention
                .per_server
                .keep_distinct_artifacts,
            1
        );
        assert_eq!(
            v2.variant("standard")
                .unwrap()
                .retention
                .per_server
                .keep_distinct_artifacts,
            5
        );
    }

    #[test]
    fn load_release_missing_release_fails_the_load() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        // A release directory with NO variant files also fails the load.
        std::fs::create_dir_all(project.join("releases").join("empty")).unwrap();
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml("v1")).unwrap();

        // A release with no directory (and no variant files) fails the WHOLE
        // load: the Err is a full load failure — no config object escapes.
        let err = ProjectConfig::load_release(&p, ReleaseName::parse("missing").unwrap())
            .expect_err("a missing release must fail the load");
        assert!(!err.to_string().is_empty());

        // An EMPTY release directory (no variant files) fails the same way.
        let err = ProjectConfig::load_release(&p, ReleaseName::parse("empty").unwrap())
            .expect_err("a release with no variant files must fail the load");
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn load_release_invalid_variant_fails_the_load() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        // A release whose variant file fails validation (unknown activation
        // adapter) fails the WHOLE load: the raw -> domain conversion rejects
        // it — no partially-switched config can escape.
        let bad_dir = project.join("releases").join("bad");
        std::fs::create_dir_all(&bad_dir).unwrap();
        std::fs::write(
            bad_dir.join("bad.toml"),
            MINIMAL_VARIANT.replace("adapter = \"none\"", "adapter = \"bogus\""),
        )
        .unwrap();
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml("v1")).unwrap();

        let err = ProjectConfig::load_release(&p, ReleaseName::parse("bad").unwrap())
            .expect_err("a release with an invalid variant must fail the load");
        let msg = err.to_string();
        assert!(
            msg.contains("bogus"),
            "the load failure must name the invalid adapter, got: {msg}"
        );
    }
}
