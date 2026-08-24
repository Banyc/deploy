//! Declarative deployment configuration (`deploy.toml`, schema version 1).
//!
//! The project file structure is forced: `deploy.toml` names the active release
//! (`release: <name>`), and every regular `*.toml` file directly inside
//! `<project>/releases/<name>/` is discovered as a variant named by its file
//! stem. Each variant file owns its artifact mappings, its deployment policies
//! (activation, verification), AND its deployment slots: the `[[slots]]`
//! entries of the variant file are the slot declarations, the declaring file
//! is the slot's variant binding, and each slot's `targets` list binds it to
//! one or more top-level targets. Artifact sources conventionally live beneath
//! `releases/<name>/artifacts/`. Capacity is a per-server policy declared on
//! the server entry. Servers and targets are declared once at the top level of
//! `deploy.toml`; targets carry rollout + rotation only, and their member
//! slots are DERIVED from the slots' `targets` lists.
//!
//! The same local inputs always produce one target-independent release identity
//! (see `model::ReleaseDigest`): the name-sorted per-variant mappings, the
//! name-sorted per-variant behavior contracts, the name-sorted per-variant
//! slot declarations (each variant's `[[slots]]` canonicalized and sorted by
//! slot id), and every declared variant's tree binding.

use crate::error::{Error, Result};
use crate::model::{PlacementSlotId, SCHEMA_VERSION, ServerId};
use crate::records::PhysicalBinding;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Component, Path, PathBuf};

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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicy {
    #[default]
    Error,
    Replace,
    Keep,
}

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
    #[serde(default)]
    pub optional: bool,
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
/// TOML form (inline table under `[[servers]]`; the field defaults to 0/0 when
/// omitted):
///
/// ```toml
/// [[servers]]
/// id = "server-01"
/// capacity = { reserve_bytes = 0, reserve_percent = 0 }
/// ```
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct CapacityConfig {
    /// Keep at least this many bytes free on the server after an upload.
    #[serde(default)]
    pub reserve_bytes: u64,
    /// Keep at least this percentage of the destination filesystem's TOTAL
    /// size free after an upload (0..=100).
    #[serde(default)]
    pub reserve_percent: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct PerServerRotation {
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
pub struct FleetRotation {
    #[serde(default)]
    pub protect_deployments: u32,
}

/// Fleet-wide retention policy, declared once at the top level of
/// `deploy.toml` (not per variant). Applied on every rotation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct RotationConfig {
    #[serde(default)]
    pub per_server: PerServerRotation,
    #[serde(default)]
    pub fleet: FleetRotation,
}

/// A per-release variant's own artifact, deployment, and slot policy. Each
/// variant is described by a `*.toml` file directly inside the release
/// directory named by `deploy.toml` (`releases/<name>/<variant>.toml`).
/// Rotation is not per-variant: it lives at the top level of `deploy.toml`.
/// Capacity is not per-variant either: it is a per-server policy declared on
/// the server entry and resolved from the caller's current configuration.
/// Slots ARE per-variant: the `[[slots]]` entries of this file declare the
/// variant's deployment slots, and the declaring file is each slot's variant
/// binding.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VariantConfig {
    #[serde(default)]
    pub description: Option<String>,
    pub artifact: ArtifactConfig,
    #[serde(default)]
    pub activation: ActivationConfig,
    pub verification: VerificationConfig,
    /// This variant's deployment slots, declared inside its own file. The
    /// declaring variant file is the slot's variant binding: there is no
    /// `variant` field on [`SlotDef`].
    #[serde(default)]
    pub slots: Vec<SlotDef>,
}

/// Durable protection for one whole release: every variant's artifact in the
/// pinned release is retained forever; rotation never sweeps it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub release: String,
    pub reason: String,
}

/// The active release: the name of a directory directly beneath `releases/` in
/// the project root. The project structure is forced to
/// `<project>/releases/<name>/<variant>.toml`; there is no configurable path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ReleaseName(String);

impl ReleaseName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ReleaseName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct RolloutConfig {
    #[serde(default = "default_batch_size")]
    pub batch_size: u32,
    #[serde(default = "default_true")]
    pub stop_on_failure: bool,
    #[serde(default = "default_failure_policy")]
    pub failure_policy: String,
}

fn default_batch_size() -> u32 {
    1
}
fn default_failure_policy() -> String {
    "rollback_changed".to_string()
}
fn default_ssh_port() -> u16 {
    22
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerDef {
    pub id: String,
    pub address: String,
    pub user: String,
    /// SSH port used to reach the server (default 22). Passed to both `ssh -p`
    /// and `ssh-keyscan -p`.
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    /// Dedicated `known_hosts` file used with `StrictHostKeyChecking=yes` for
    /// this server. Exactly one of this and `host_key_fingerprint` must be
    /// configured for an SSH address (both together are ambiguous, neither
    /// means trust-on-first-use, which is disabled); `local://` addresses are
    /// exempt.
    #[serde(default)]
    pub known_hosts: Option<PathBuf>,
    /// Pre-verified host-key fingerprint (e.g. `SHA256:...`). When set without a
    /// `known_hosts` file, the host key is fetched and pinned on first contact
    /// only if its fingerprint matches this value. Exactly one of this and
    /// `known_hosts` must be configured for an SSH address.
    #[serde(default)]
    pub host_key_fingerprint: Option<String>,
    /// Per-server capacity headroom policy (defaults to 0/0 when omitted),
    /// shared by every deployment slot on this server and resolved from the
    /// caller's current configuration at preflight time. Not part of the
    /// release identity. TOML form: `capacity = { reserve_bytes = 0,
    /// reserve_percent = 0 }`.
    #[serde(default)]
    pub capacity: CapacityConfig,
}

/// A deployment slot: binds one server to one workload under an ID, with an
/// absolute `deploy_dir` on the server, and may be a member of SEVERAL
/// targets. The connection details live on the top-level `[[servers]]`
/// entry; the workload choice, its on-server location, and its target
/// membership live here. Slots are declared INSIDE the variant file that owns
/// the workload: the `[[slots]]` entries of `<release>/<variant>.toml` are
/// the slot declarations, the declaring variant file IS the slot's variant
/// binding (there is no `variant` field — it is the enclosing file), and the
/// slot's `targets` list is what binds it to top-level targets. A target's
/// members are DERIVED by scanning every variant's slots for its name.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SlotDef {
    pub id: String,
    /// The ID of the top-level server this slot deploys onto.
    pub server: String,
    /// Absolute directory on the server where this slot's deployment state
    /// (objects, releases, generations, `current`) lives.
    pub deploy_dir: PathBuf,
    /// The targets this slot belongs to. A slot may be a member of several
    /// targets (its on-server `deploy_dir` state is shared across them), so
    /// this is a membership list: each target's member slots are derived by
    /// scanning every variant's slots for its name. A slot with an empty list
    /// belongs to no target and is rejected at validation (mirroring the
    /// rule that a target must have at least one member). A name must not
    /// appear twice: a duplicate adds no membership yet would change the
    /// release identity, so it is rejected at validation (the canonical form
    /// additionally dedups defensively). TOML form:
    /// `targets = ["production", "staging"]`.
    #[serde(default)]
    pub targets: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TargetDef {
    #[serde(default)]
    pub rollout: RolloutConfig,
    /// Retention policy applied to this target's servers on every rotation.
    #[serde(default)]
    pub rotation: RotationConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub application: String,
    /// The active release: the name of a directory directly beneath
    /// `releases/` in the project root (`release: v1` -> `releases/v1/`).
    pub release: ReleaseName,
    /// Durable retention pins applied on every rotation.
    #[serde(default)]
    pub pins: Vec<Pin>,
    /// Every deployable server, declared once at the top level of
    /// `deploy.toml`; slots reference these by ID.
    pub servers: Vec<ServerDef>,
    pub targets: BTreeMap<String, TargetDef>,
    #[serde(skip)]
    variants: BTreeMap<String, VariantConfig>,
}

impl Config {
    /// Load and validate a configuration from a `deploy.toml` path. The project
    /// root is the directory containing the file. Variant files are discovered
    /// inside `<project>/releases/<release>/` (the release directory named by
    /// `release:`).
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::config(format!("reading {}: {e}", path.display())))?;
        let mut cfg: Config = toml::from_str(&text)
            .map_err(|e| Error::config(format!("parsing deploy.toml: {e}")))?;
        cfg.load_variants(path)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn project_root(&self, config_path: &Path) -> PathBuf {
        config_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
    }

    /// Absolute release directory: forced to `<project>/releases/<release>`.
    pub fn release_root(&self, config_path: &Path) -> PathBuf {
        self.project_root(config_path)
            .join("releases")
            .join(self.release.as_str())
    }

    /// Validate the configuration per schema version 1 rules.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(Error::config(format!(
                "unsupported schema_version {} (expected {SCHEMA_VERSION})",
                self.schema_version
            )));
        }
        // The release name must be exactly one directory component so it cannot
        // escape the forced `releases/` directory.
        let name = self.release.as_str();
        let single_component = matches!(
            Path::new(name).components().collect::<Vec<_>>().as_slice(),
            [Component::Normal(c)] if *c == std::ffi::OsStr::new(name)
        );
        if !single_component {
            return Err(Error::config(format!(
                "release '{name}' must be a single directory name (the release directory is forced to `releases/<name>/`)"
            )));
        }
        if self.variants.is_empty() {
            return Err(Error::config(
                "at least one release variant must be declared",
            ));
        }
        if self.targets.is_empty() {
            return Err(Error::config("at least one target must be declared"));
        }

        // Each loaded variant carries its own artifact/activation/verification
        // policy; validate each one.
        for (name, variant) in &self.variants {
            self.validate_variant(name, variant)?;
        }

        // Server declarations are unique and well-formed; capacity is a
        // per-server policy, so its validation lives here.
        let mut all_server_ids = std::collections::HashSet::new();
        for s in &self.servers {
            if !all_server_ids.insert(s.id.clone()) {
                return Err(Error::config(format!(
                    "duplicate server id '{}' in top-level servers",
                    s.id
                )));
            }
            if s.capacity.reserve_percent > 100 {
                return Err(Error::config(format!(
                    "server '{}': reserve_percent must not exceed 100",
                    s.id
                )));
            }
            // When an identity source is provided it must be well-formed.
            if let Some(kh) = &s.known_hosts
                && !kh.is_absolute()
            {
                return Err(Error::config(format!(
                    "server '{}' known_hosts must be an absolute path",
                    s.id
                )));
            }
            if let Some(fp) = &s.host_key_fingerprint
                && !fp.starts_with("SHA256:")
            {
                return Err(Error::config(format!(
                    "server '{}' host_key_fingerprint must be a SHA256:... value",
                    s.id
                )));
            }
            // An SSH address requires EXACTLY ONE host-identity source. With
            // neither, the transport would have to fall back to
            // trust-on-first-use (refused); with both, the choice is ambiguous
            // (the transport would silently prefer `known_hosts` and ignore the
            // fingerprint). `local://` endpoints never perform host
            // verification, so they are exempt.
            let is_local = s.address.starts_with("local://");
            let has_known_hosts = s.known_hosts.is_some();
            let has_fingerprint = s.host_key_fingerprint.is_some();
            if !is_local && !has_known_hosts && !has_fingerprint {
                return Err(Error::config(format!(
                    "server '{}': exactly one of known_hosts or host_key_fingerprint must be configured for an SSH address (trust-on-first-use is disabled)",
                    s.id
                )));
            }
            if !is_local && has_known_hosts && has_fingerprint {
                return Err(Error::config(format!(
                    "server '{}': known_hosts and host_key_fingerprint are mutually exclusive; configure exactly one",
                    s.id
                )));
            }
        }

        // Slots are declared INSIDE each variant's file (the declaring file is
        // the slot's variant binding), so they are aggregated across every
        // variant: IDs are unique across ALL variants, each slot's server must
        // exist among the top-level `[[servers]]` entries, each declared target
        // in a slot's `targets` list must exist among the top-level
        // `[targets.<name>]` keys (and the list must be non-empty — a slot in
        // no target is useless — and must not repeat a name: a duplicate would
        // change release identity without changing membership), and a
        // (server, deploy_dir) pair names one on-server deployment location
        // that exactly one slot may own.
        let mut slot_ids = std::collections::HashSet::new();
        let mut bound_locations: std::collections::BTreeMap<(&str, &Path), &str> =
            std::collections::BTreeMap::new();
        for (vname, variant) in &self.variants {
            for p in &variant.slots {
                if !slot_ids.insert(p.id.clone()) {
                    return Err(Error::config(format!(
                        "duplicate slot id '{}' (declared by variant '{vname}')",
                        p.id
                    )));
                }
                if !all_server_ids.contains(&p.server) {
                    return Err(Error::config(format!(
                        "variant '{vname}': slot '{}' references unknown server '{}'",
                        p.id, p.server
                    )));
                }
                if p.targets.is_empty() {
                    return Err(Error::config(format!(
                        "variant '{vname}': slot '{}' must declare at least one target",
                        p.id
                    )));
                }
                let mut seen_targets = std::collections::HashSet::new();
                for t in &p.targets {
                    if !seen_targets.insert(t) {
                        return Err(Error::config(format!(
                            "variant '{vname}': slot '{}' declares duplicate target '{}'",
                            p.id, t
                        )));
                    }
                    if !self.targets.contains_key(t) {
                        return Err(Error::config(format!(
                            "variant '{vname}': slot '{}' references unknown target '{}'",
                            p.id, t
                        )));
                    }
                }
                if p.deploy_dir.is_relative() {
                    return Err(Error::config(format!(
                        "variant '{vname}': slot '{}' deploy_dir must be an absolute path on the server",
                        p.id
                    )));
                }
                // A (server, deploy_dir) pair names one on-server deployment
                // location: its objects, releases, generations, and `current`.
                // Two slots bound there would race over the same state.
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

        // A target's members are DERIVED by scanning every variant's slots for
        // the target name (targets no longer list their slots). One server runs
        // exactly one generation, so two member slots of the same target can
        // never share a server — and a target must have at least one member.
        // A slot may be a member of several targets: the per-target checks run
        // independently for each target the slot declares, so the same two
        // slots may share one server in DIFFERENT targets (each target's
        // per-server uniqueness is scoped to that target alone).
        for (tname, _target) in &self.targets {
            let mut used_servers = std::collections::HashSet::new();
            let mut members = 0;
            for slot in self.slot_defs() {
                if !slot.targets.iter().any(|t| t == tname) {
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

    /// Validate a single loaded variant's artifact mappings and deployment
    /// policies, prefixing every error with the variant name.
    fn validate_variant(&self, name: &str, variant: &VariantConfig) -> Result<()> {
        if variant.activation.adapter != "none" && variant.activation.adapter != "systemd" {
            return Err(Error::config(format!(
                "variant '{name}': unknown activation adapter '{}'",
                variant.activation.adapter
            )));
        }
        if variant.verification.adapter != "command" {
            return Err(Error::config(format!(
                "variant '{name}': unsupported verification adapter '{}'",
                variant.verification.adapter
            )));
        }
        if variant.verification.argv.is_empty() {
            return Err(Error::config(format!(
                "variant '{name}': verification argv must not be empty"
            )));
        }
        if variant.activation.adapter == "systemd" && variant.activation.units.is_empty() {
            return Err(Error::config(format!(
                "variant '{name}': systemd activation requires at least one unit"
            )));
        }

        // Validate mapping modes and artifact-relative destinations.
        for (i, m) in variant.artifact.mappings.iter().enumerate() {
            if let Some(mode) = &m.mode
                && mode != "preserve"
            {
                parse_octal_mode(mode).map_err(|e| {
                    Error::config(format!("variant '{name}' mapping[{i}] mode: {e}"))
                })?;
            }
            if m.from.trim().is_empty() || m.to.trim().is_empty() {
                return Err(Error::config(format!(
                    "variant '{name}' mapping[{i}] requires non-empty from/to"
                )));
            }
            validate_relative_path(Path::new(&m.to))
                .map_err(|e| Error::config(format!("variant '{name}' mapping[{i}] to: {e}")))?;
        }
        Ok(())
    }

    pub fn variant_names(&self) -> Vec<String> {
        self.variants.keys().cloned().collect()
    }

    pub fn variant(&self, name: &str) -> Result<&VariantConfig> {
        self.variants
            .get(name)
            .ok_or_else(|| Error::config(format!("unknown release variant '{name}'")))
    }

    /// The aggregated slot declarations of every variant: each variant's
    /// `[[slots]]` entries in deterministic order — variants in name order
    /// (the `BTreeMap` is already sorted), then each variant's slots in file
    /// order.
    pub fn slot_defs(&self) -> Vec<&SlotDef> {
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

    /// Resolve a target's member slots, pairing each slot with its declared
    /// server. Membership is DERIVED from the slots' declared `targets` list
    /// (targets no longer list their slots): every slot whose `targets`
    /// contains `target_name`, in deterministic order — variants in name
    /// order, then each variant's slots in file order.
    pub fn target_slots(&self, target_name: &str) -> Result<Vec<(&SlotDef, &ServerDef)>> {
        self.targets
            .get(target_name)
            .ok_or_else(|| Error::not_found(format!("target '{target_name}'")))?;
        let mut out = Vec::new();
        for slot in self.slot_defs() {
            if !slot.targets.iter().any(|t| t == target_name) {
                continue;
            }
            let server = self
                .servers
                .iter()
                .find(|s| s.id == slot.server)
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

    /// The slot IDs of a target's members, in the same deterministic order as
    /// [`Config::target_slots`].
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
    /// Used to record (and later verify) the exact physical location a fleet
    /// snapshot's slots were deployed onto: exact rollback must see BOTH
    /// halves unchanged, because a slot that keeps its server but moves its
    /// `deploy_dir` would otherwise roll back onto the new location.
    pub fn target_slot_bindings(
        &self,
        target_name: &str,
    ) -> Result<BTreeMap<PlacementSlotId, PhysicalBinding>> {
        Ok(self
            .target_slots(target_name)?
            .into_iter()
            .map(|(slot, server)| {
                (
                    PlacementSlotId::new(slot.id.clone()),
                    PhysicalBinding {
                        server: ServerId::new(server.id.clone()),
                        deploy_dir: slot.deploy_dir.to_string_lossy().into_owned(),
                    },
                )
            })
            .collect())
    }

    /// Discover variant files inside the release directory. The project
    /// structure is forced: every regular, non-hidden `*.toml` file directly
    /// inside `<project>/releases/<release>/` is a variant named by its file
    /// stem. Other entries (such as the `artifacts/` directory) are ignored.
    fn load_variants(&mut self, config_path: &Path) -> Result<()> {
        let project_root = self.project_root(config_path).canonicalize().map_err(|e| {
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
        for (name, path) in variant_files {
            let text = std::fs::read_to_string(&path).map_err(|e| {
                Error::config(format!(
                    "reading variant '{name}' config '{}': {e}",
                    path.display()
                ))
            })?;
            let variant: VariantConfig = toml::from_str(&text).map_err(|e| {
                Error::config(format!(
                    "parsing variant '{name}' config '{}': {e}",
                    path.display()
                ))
            })?;
            variants.insert(name, variant);
        }
        self.variants = variants;
        Ok(())
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
targets = ["t1"]
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
schema_version = 1
application = "esc"
release = "v1"

[targets.t1.rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[targets.t1.rotation.fleet]
protect_deployments = 1

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
            Config::load(&p).is_err(),
            "escaping mapping `to` must be rejected"
        );
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
targets = ["t1"]
deploy_dir = "/srv/example"

[[artifact.mappings]]
from = "build/output/"
to = "app/"
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
schema_version = 1
application = "example"
release = "v1"

[targets.t1.rotation.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[targets.t1.rotation.fleet]
protect_deployments = 2

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

        let cfg = Config::load(&p).expect("config loads with sibling variant files");
        assert_eq!(
            cfg.targets["t1"]
                .rotation
                .per_server
                .keep_distinct_artifacts,
            5
        );
        assert_eq!(cfg.targets["t1"].rotation.fleet.protect_deployments, 2);
        let names = cfg.variant_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"standard".to_string()));
        assert!(names.contains(&"high-capacity".to_string()));

        let std = cfg.variant("standard").expect("standard variant present");
        assert_eq!(std.verification.argv, vec!["true".to_string()]);
        assert_eq!(std.activation.adapter, "none");

        let hc = cfg
            .variant("high-capacity")
            .expect("high-capacity variant present");
        assert_eq!(hc.verification.argv, vec!["false".to_string()]);
        assert_eq!(hc.activation.adapter, "systemd");
        assert!(!hc.activation.units.is_empty());

        // Capacity is per-server, not per-variant: the single server carries
        // the policy and the variant files parse without any `[capacity]` block.
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].capacity.reserve_bytes, 1073741824);
        assert_eq!(cfg.servers[0].capacity.reserve_percent, 5);
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
targets = ["t1"]
deploy_dir = "/srv/forced"
"#;

    fn deploy_toml(release_value: &str) -> String {
        format!(
            r#"
schema_version = 1
application = "forced"
release = "{release_value}"

[targets.t1.rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[targets.t1.rotation.fleet]
protect_deployments = 1

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
        // target references.
        std::fs::write(
            release_dir.join("standard.toml"),
            format!("{MINIMAL_VARIANT}\n{STANDARD_SLOTS}"),
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
        let cfg = Config::load(&p).expect("config loads from the forced structure");
        assert_eq!(cfg.release.as_str(), "v1");
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
schema_version = 1
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
        let err = Config::load(&p).expect_err("old release map form must be rejected");
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
                Config::load(&p).is_err(),
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
        let err = Config::load(&p).expect_err("missing release dir must fail");
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
        let err = Config::load(&p).expect_err("empty release dir must fail");
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
            "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntargets = [\"ghost\"]\ndeploy_dir = \"/srv/forced\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), bad_variant).unwrap();
        let err = Config::load(&p).expect_err("unknown target reference must fail");
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
            "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntargets = [\"t2\"]\ndeploy_dir = \"/srv/forced-2\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), standard_toml).unwrap();
        let t2 = "\n[targets.t2]\nrollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }\n";
        std::fs::write(&p, format!("{}{}", deploy_toml("v1"), t2)).unwrap();
        let cfg = Config::load(&p).expect("slots spread across targets are valid");
        assert_eq!(cfg.targets.len(), 2);
        assert_eq!(cfg.slot_defs().len(), 2);
        // Membership is derived from each slot's declared targets list.
        assert_eq!(cfg.target_slot_ids("t1").unwrap(), vec!["p1"]);
        assert_eq!(cfg.target_slot_ids("t2").unwrap(), vec!["p2"]);

        // A slot declared with `targets = ["t1", "t2"]` is a member of BOTH
        // targets: the one-target-per-slot restriction is gone, and each
        // target derives the slot independently.
        let multi = format!(
            "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntargets = [\"t1\", \"t2\"]\ndeploy_dir = \"/srv/forced\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), multi).unwrap();
        let cfg = Config::load(&p).expect("a slot in two targets is valid");
        assert_eq!(cfg.target_slot_ids("t1").unwrap(), vec!["p1"]);
        assert_eq!(cfg.target_slot_ids("t2").unwrap(), vec!["p1"]);

        // A target with NO member slot is rejected.
        let t3 = "\n[targets.t3]\nrollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }\n";
        std::fs::write(&p, format!("{}{}{}", deploy_toml("v1"), t2, t3)).unwrap();
        let err = Config::load(&p).expect_err("target without slots must fail");
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
        // The `targets` key is omitted entirely: `#[serde(default)]` yields an
        // empty list, which validation rejects.
        let no_targets = format!(
            "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ndeploy_dir = \"/srv/forced\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), no_targets).unwrap();
        let err = Config::load(&p).expect_err("slot without targets must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("must declare at least one target") && msg.contains("variant 'standard'"),
            "error must name the slot's variant and the empty membership, got: {msg}"
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
            "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p1\"\nserver = \"ghost\"\ntargets = [\"t1\"]\ndeploy_dir = \"/srv/forced\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), bad_variant).unwrap();
        let err = Config::load(&p).expect_err("slot with unknown server must fail");
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
        let cfg = Config::load(&p).unwrap();
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
        let err = Config::load(&p).expect_err("duplicate slot id across variants must fail");
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
        // A slot declaring the same target twice: the duplicate adds no
        // membership yet would change release identity, so it is rejected.
        let dup = format!(
            "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntargets = [\"t1\", \"t1\"]\ndeploy_dir = \"/srv/forced\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), dup).unwrap();
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml("v1")).unwrap();
        let err = Config::load(&p).expect_err("duplicate target name in a slot must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("duplicate target 't1'") && msg.contains("slot 'p1'"),
            "error must name the duplicate target and the slot, got: {msg}"
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
            "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntargets = [\"t1\"]\ndeploy_dir = \"/srv/forced\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), dup).unwrap();
        std::fs::write(&p, deploy_toml("v1")).unwrap();
        let err = Config::load(&p).expect_err("shared server+deploy_dir must fail");
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
            "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntargets = [\"t2\"]\ndeploy_dir = \"/srv/other\"\n"
        );
        std::fs::write(project.join("releases/v1/other.toml"), other).unwrap();
        let t2 = "\n[targets.t2]\nrollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }\n";
        std::fs::write(&p, format!("{}{}", deploy_toml("v1"), t2)).unwrap();
        let cfg = Config::load(&p).expect("distinct deploy_dir on the same server is valid");
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
        let err = Config::load(&p).expect_err("duplicate server id must fail");
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
        let cfg = Config::load(&p).expect("server without capacity loads");
        assert_eq!(cfg.servers[0].capacity, CapacityConfig::default());

        // reserve_percent above 100 is rejected at load time.
        let bad = deploy_toml("v1").replace(
            "user = \"u\"",
            "user = \"u\"\ncapacity = { reserve_bytes = 1, reserve_percent = 101 }",
        );
        std::fs::write(&p, bad).unwrap();
        let err = Config::load(&p).expect_err("reserve_percent > 100 must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("reserve_percent must not exceed 100") && msg.contains("server 's1'"),
            "error must name the server and the violation, got: {msg}"
        );

        // A valid inline capacity table parses into the server policy.
        let ok = deploy_toml("v1").replace(
            "user = \"u\"\nhost_key_fingerprint",
            "user = \"u\"\ncapacity = { reserve_bytes = 4096, reserve_percent = 10 }\nhost_key_fingerprint",
        );
        std::fs::write(&p, ok).unwrap();
        let cfg = Config::load(&p).expect("inline server capacity parses");
        assert_eq!(cfg.servers[0].capacity.reserve_bytes, 4096);
        assert_eq!(cfg.servers[0].capacity.reserve_percent, 10);
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
        let err = Config::load(&p).expect_err("SSH address without identity must fail");
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
        let err = Config::load(&p).expect_err("SSH address with both identities must fail");
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
        let cfg = Config::load(&p).expect("local:// address needs no identity");
        assert!(cfg.servers[0].address.starts_with("local://"));

        // SSH address + exactly one source: valid.
        std::fs::write(&p, deploy_toml("v1")).unwrap();
        let cfg = Config::load(&p).expect("SSH address with exactly one identity is valid");
        assert_eq!(
            cfg.servers[0].host_key_fingerprint.as_deref(),
            Some("SHA256:test")
        );
        let kh_only = deploy_toml("v1").replace(
            "host_key_fingerprint = \"SHA256:test\"",
            "known_hosts = \"/etc/ssh/known_hosts\"",
        );
        std::fs::write(&p, kh_only).unwrap();
        let cfg = Config::load(&p).expect("known_hosts-only SSH address is valid");
        assert_eq!(
            cfg.servers[0].known_hosts.as_deref(),
            Some(Path::new("/etc/ssh/known_hosts"))
        );
        assert!(cfg.servers[0].host_key_fingerprint.is_none());
    }

    /// `local://` addresses never perform host verification, so they are
    /// EXEMPT from the exactly-one host-identity rule in BOTH directions:
    /// an identity source may be absent (already pinned above) or present.
    /// A local endpoint with `known_hosts`, `host_key_fingerprint`, or BOTH
    /// configured still loads — the local exemption applies regardless of
    /// what identity fields the server entry carries.
    #[test]
    fn local_address_with_identity_configured_is_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let p = project.join("deploy.toml");
        let local = deploy_toml("v1")
            .replace("address = \"a\"", "address = \"local:///srv/forced\"")
            .replace("host_key_fingerprint = \"SHA256:test\"\n", "");

        // local:// + known_hosts: allowed (the local exemption swallows the
        // otherwise-valid identity source).
        let with_kh = local.replace(
            "user = \"u\"",
            "user = \"u\"\nknown_hosts = \"/etc/ssh/known_hosts\"",
        );
        std::fs::write(&p, with_kh).unwrap();
        let cfg = Config::load(&p).expect("local:// + known_hosts is allowed");
        assert!(cfg.servers[0].address.starts_with("local://"));
        assert!(cfg.servers[0].known_hosts.is_some());

        // local:// + host_key_fingerprint: allowed.
        let with_fp = local.replace(
            "user = \"u\"",
            "user = \"u\"\nhost_key_fingerprint = \"SHA256:test\"",
        );
        std::fs::write(&p, with_fp).unwrap();
        let cfg = Config::load(&p).expect("local:// + fingerprint is allowed");
        assert!(cfg.servers[0].host_key_fingerprint.is_some());

        // local:// + BOTH: still allowed — the ambiguity rule is scoped to
        // SSH addresses only (the exact same pair is rejected above for an
        // SSH address).
        let with_both = deploy_toml("v1")
            .replace("address = \"a\"", "address = \"local:///srv/forced\"")
            .replace(
                "host_key_fingerprint = \"SHA256:test\"",
                "host_key_fingerprint = \"SHA256:test\"\nknown_hosts = \"/etc/ssh/known_hosts\"",
            );
        std::fs::write(&p, with_both).unwrap();
        let cfg = Config::load(&p).expect("local:// + both identities is allowed");
        assert!(cfg.servers[0].known_hosts.is_some());
        assert!(cfg.servers[0].host_key_fingerprint.is_some());
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
                "schema_version = 1",
                "schema_version = 1\nadapterr = \"none\"",
            ),
        )
        .unwrap();
        let err = Config::load(&p).expect_err("unknown top-level key must fail");
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
        let err = Config::load(&p).expect_err("unknown server field must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("reserve_byts") && msg.contains("unknown field"),
            "error must name the unknown server field, got: {msg}"
        );

        // Unknown field inside a variant's [activation] table.
        let bad_variant =
            MINIMAL_VARIANT.replace("adapter = \"none\"", "adapter = \"none\"\nreserve_byts = 1");
        std::fs::write(project.join("releases/v1/standard.toml"), bad_variant).unwrap();
        let err = Config::load(&p).expect_err("unknown activation field must fail");
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
        let err = Config::load(&p).expect_err("unknown slot field must fail");
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
        let err = Config::load(&p).expect_err("top-level [[slots]] must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("slots") && msg.contains("unknown field"),
            "error must name the unknown top-level slots field, got: {msg}"
        );

        // Enums reject unknown variants by default (no attribute needed).
        let err = toml::from_str::<Mapping>("from = \"a\"\nto = \"b\"\nconflict = \"nope\"")
            .expect_err("unknown conflict variant must fail");
        assert!(err.to_string().contains("unknown variant"), "got: {err}");

        // The known-good fixtures still load under the strict rules.
        let fixture = project.join("deploy.toml");
        std::fs::write(&fixture, base).unwrap();
        std::fs::write(
            project.join("releases/v1/standard.toml"),
            format!("{MINIMAL_VARIANT}\n{STANDARD_SLOTS}"),
        )
        .unwrap();
        Config::load(&fixture).expect("known-good config still loads");
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
            "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntargets = [\"t1\"]\ndeploy_dir = \"/srv/forced-2\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), dup).unwrap();
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml("v1")).unwrap();
        let err = Config::load(&p).expect_err("two slots of one target on one server must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("target 't1' has multiple slots on server 's1'"),
            "error must name the target and the shared server, got: {msg}"
        );

        // The same two slots split across TWO servers is valid.
        let ok = format!(
            "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[[slots]]\nid = \"p2\"\nserver = \"s2\"\ntargets = [\"t1\"]\ndeploy_dir = \"/srv/forced-2\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), ok).unwrap();
        let two_servers = deploy_toml("v1").replacen(
            "[targets.t1]",
            "[[servers]]\nid = \"s2\"\naddress = \"b\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n[targets.t1]",
            1,
        );
        std::fs::write(&p, two_servers).unwrap();
        let cfg = Config::load(&p).expect("two slots on distinct servers are valid");
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
            "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntargets = [\"t2\"]\ndeploy_dir = \"/srv/forced-2\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), split).unwrap();
        let cfg = Config::load(&p).expect("two slots on one server in different targets are valid");
        assert_eq!(cfg.target_slot_ids("t1").unwrap(), vec!["p1"]);
        assert_eq!(cfg.target_slot_ids("t2").unwrap(), vec!["p2"]);

        // The same two slots BOTH in t1 (same server) is rejected — the
        // per-target check fires.
        let same = format!(
            "{MINIMAL_VARIANT}\n{STANDARD_SLOTS}\n[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntargets = [\"t1\"]\ndeploy_dir = \"/srv/forced-2\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), same).unwrap();
        let err = Config::load(&p).expect_err("two slots of one target on one server must fail");
        assert!(
            err.to_string()
                .contains("target 't1' has multiple slots on server 's1'"),
            "error must name the target and the shared server, got: {err}"
        );

        // A single slot in BOTH t1 and t2 on s1 is valid: it is one slot per
        // server per target, and the (server, deploy_dir) location is unique.
        let multi = format!(
            "{MINIMAL_VARIANT}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntargets = [\"t1\", \"t2\"]\ndeploy_dir = \"/srv/forced\"\n"
        );
        std::fs::write(project.join("releases/v1/standard.toml"), multi).unwrap();
        let cfg = Config::load(&p).expect("one slot in two targets on one server is valid");
        assert_eq!(cfg.target_slot_ids("t1").unwrap(), vec!["p1"]);
        assert_eq!(cfg.target_slot_ids("t2").unwrap(), vec!["p1"]);
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
        let err = Config::load(&p).expect_err("[capacity] inside a variant must fail");
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
        let cfg = Config::load(&p).expect("config loads");
        assert_eq!(cfg.servers[0].port, 22, "default SSH port is 22");

        // `port` alone does not satisfy the exactly-one identity rule.
        let port_only = deploy_toml("v1")
            .replace("host_key_fingerprint = \"SHA256:test\"\n", "")
            .replace("user = \"u\"", "user = \"u\"\nport = 2200");
        std::fs::write(&p, port_only).unwrap();
        let err = Config::load(&p).expect_err("port-only server must still be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("exactly one of known_hosts or host_key_fingerprint"),
            "port must not count as an identity source, got: {msg}"
        );

        // An explicit port WITH exactly one identity loads and is carried.
        let with_port = deploy_toml("v1").replace("user = \"u\"", "user = \"u\"\nport = 2200");
        std::fs::write(&p, with_port).unwrap();
        let cfg = Config::load(&p).expect("explicit port with one identity is valid");
        assert_eq!(cfg.servers[0].port, 2200);
    }

    /// `deny_unknown_fields` extends to the remaining user-written surfaces:
    /// the variant's `[verification]` table, the top-level `[targets.t1.rollout]`
    /// table, a variant's `[[artifact.mappings]]` entries, and the rotation
    /// policy tables.
    #[test]
    fn unknown_fields_rejected_in_verification_rollout_mapping_and_rotation() {
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
        let err = Config::load(&p).expect_err("unknown verification field must fail");
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
        let err = Config::load(&p).expect_err("unknown rollout field must fail");
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
        let err = Config::load(&p).expect_err("unknown mapping field must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("conflic") && msg.contains("unknown field"),
            "error must name the unknown mapping field, got: {msg}"
        );

        // Unknown field inside the [targets.t1.rotation] tables.
        let bad_rotation = deploy_toml("v1").replacen(
            "[targets.t1.rotation.per_server]",
            "[targets.t1.rotation]\nprotect_nothing = 1\n\n[targets.t1.rotation.per_server]",
            1,
        );
        std::fs::write(project.join("releases/v1/standard.toml"), MINIMAL_VARIANT).unwrap();
        std::fs::write(&p, bad_rotation).unwrap();
        let err = Config::load(&p).expect_err("unknown rotation field must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("protect_nothing") && msg.contains("unknown field"),
            "error must name the unknown rotation field, got: {msg}"
        );
    }
}
