//! Declarative deployment configuration (`deploy.toml`, schema version 1).
//!
//! The project file structure is forced: `deploy.toml` names the active release
//! (`release: <name>`), and every regular `*.toml` file directly inside
//! `<project>/releases/<name>/` is discovered as a variant named by its file
//! stem. Each variant file owns its own artifact mappings and deployment
//! policies (activation, verification, capacity); artifact sources
//! conventionally live beneath `releases/<name>/artifacts/`. Servers are
//! declared once at the top level; a pod binds one server to one variant under
//! an ID, and targets contain their rollout policy, references to member pods
//! by ID, and their own retention (`rotation`) policy.
//!
//! The same local inputs always produce one target-independent release identity
//! (see `model::ReleaseDigest`): the name-sorted per-variant mappings, the
//! name-sorted per-variant behavior contracts, and every declared variant's
//! tree binding.

use crate::error::{Error, Result};
use crate::model::SCHEMA_VERSION;
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
pub struct Mapping {
    /// Source path relative to the release directory (`releases/<release>/`),
    /// where the convention is `artifacts/...`. `{{ variant }}` is the only
    /// allowed interpolation variable.
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
pub struct ArtifactConfig {
    pub mappings: Vec<Mapping>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CapacityConfig {
    #[serde(default)]
    pub reserve_bytes: u64,
    #[serde(default)]
    pub reserve_percent: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
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
pub struct FleetRotation {
    #[serde(default)]
    pub protect_deployments: u32,
}

/// Fleet-wide retention policy, declared once at the top level of
/// `deploy.toml` (not per variant). Applied on every rotation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RotationConfig {
    #[serde(default)]
    pub per_server: PerServerRotation,
    #[serde(default)]
    pub fleet: FleetRotation,
}

/// A variant's capacity policy. This is persisted alongside the immutable
/// release record so historical deployments (fleet and release rollbacks)
/// resolve capacity headroom from the release snapshot rather than the caller's
/// current configuration, where the variant may since have been renamed or
/// removed. Rotation is not snapshotted per variant: it is fleet-wide
/// configuration declared once in `deploy.toml` and read from there.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct VariantPolicy {
    #[serde(default)]
    pub capacity: CapacityConfig,
}

/// A per-release variant's own artifact and deployment policy. Each variant is
/// described by a `*.toml` file directly inside the release directory named by
/// `deploy.toml` (`releases/<name>/<variant>.toml`). Rotation is not
/// per-variant: it lives at the top level of `deploy.toml`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VariantConfig {
    #[serde(default)]
    pub description: Option<String>,
    pub artifact: ArtifactConfig,
    #[serde(default)]
    pub activation: ActivationConfig,
    pub verification: VerificationConfig,
    #[serde(default)]
    pub capacity: CapacityConfig,
}

impl From<&VariantConfig> for VariantPolicy {
    fn from(v: &VariantConfig) -> Self {
        VariantPolicy {
            capacity: v.capacity.clone(),
        }
    }
}

/// Durable protection for one whole release: every variant's artifact in the
/// pinned release is retained forever; rotation never sweeps it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
pub struct ServerDef {
    pub id: String,
    pub address: String,
    pub user: String,
    /// SSH port used to reach the server (default 22). Passed to both `ssh -p`
    /// and `ssh-keyscan -p`.
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    /// Dedicated `known_hosts` file used with `StrictHostKeyChecking=yes` for
    /// this server. Either this or `host_key_fingerprint` must be configured;
    /// trust-on-first-use is disabled.
    #[serde(default)]
    pub known_hosts: Option<PathBuf>,
    /// Pre-verified host-key fingerprint (e.g. `SHA256:...`). When set without a
    /// `known_hosts` file, the host key is fetched and pinned on first contact
    /// only if its fingerprint matches this value.
    #[serde(default)]
    pub host_key_fingerprint: Option<String>,
}

/// Binds one server to one variant under an ID. The connection details live on
/// the top-level `[[servers]]` entry; the workload choice and its on-server
/// location live here. Targets reference pods by ID.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PodDef {
    pub id: String,
    /// The ID of the top-level server this pod deploys onto.
    pub server: String,
    pub variant: String,
    /// Absolute directory on the server where this pod's deployment state
    /// (objects, releases, generations, `current`) lives.
    pub deploy_dir: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetDef {
    #[serde(default)]
    pub rollout: RolloutConfig,
    /// The IDs of this target's member pods, in deployment order. Each ID must
    /// reference a top-level `[[pods]]` declaration.
    pub pods: Vec<String>,
    /// Retention policy applied to this target's servers on every rotation.
    #[serde(default)]
    pub rotation: RotationConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
    /// `deploy.toml`; pods reference these by ID.
    pub servers: Vec<ServerDef>,
    /// Workload bindings: one pod = one server + one variant, under an ID.
    /// Targets reference pods by ID.
    pub pods: Vec<PodDef>,
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
            return Err(Error::config("at least one release variant must be declared"));
        }
        if self.targets.is_empty() {
            return Err(Error::config("at least one target must be declared"));
        }

        // Each loaded variant carries its own artifact/activation/verification/
        // capacity policy; validate each one.
        for (name, variant) in &self.variants {
            self.validate_variant(name, variant)?;
        }

        // Server declarations are unique and well-formed.
        let mut all_server_ids = std::collections::HashSet::new();
        for s in &self.servers {
            if !all_server_ids.insert(s.id.clone()) {
                return Err(Error::config(format!(
                    "duplicate server id '{}' in top-level servers",
                    s.id
                )));
            }
            // When an identity source is provided it must be well-formed. The
            // actual enforcement (refusing trust-on-first-use) happens in the
            // SSH transport, so a missing source is not rejected here — local
            // and `local://` transports never perform host verification.
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
        }

        // Pods bind one declared server to one declared variant, under a unique
        // ID.
        let mut pod_by_id = std::collections::BTreeMap::new();
        let mut bound_locations: std::collections::BTreeMap<(&str, &Path), &str> =
            std::collections::BTreeMap::new();
        for p in &self.pods {
            if pod_by_id.insert(p.id.clone(), p).is_some() {
                return Err(Error::config(format!(
                    "duplicate pod id '{}' in top-level pods",
                    p.id
                )));
            }
            if !all_server_ids.contains(&p.server) {
                return Err(Error::config(format!(
                    "pod '{}' references unknown server '{}'",
                    p.id, p.server
                )));
            }
            if !self.variants.contains_key(&p.variant) {
                return Err(Error::config(format!(
                    "pod '{}' references unknown variant '{}'",
                    p.id, p.variant
                )));
            }
            if p.deploy_dir.is_relative() {
                return Err(Error::config(format!(
                    "pod '{}' deploy_dir must be an absolute path on the server",
                    p.id
                )));
            }
            // A (server, deploy_dir) pair names one on-server deployment
            // location: its objects, releases, generations, and `current`. Two
            // pods bound there would race over the same state.
            if let Some(existing) =
                bound_locations.get(&(p.server.as_str(), p.deploy_dir.as_path()))
            {
                return Err(Error::config(format!(
                    "pods '{existing}' and '{}' bind the same location (server '{}', deploy_dir '{}'); each server+deploy_dir pair must belong to exactly one pod",
                    p.id, p.server, p.deploy_dir.display()
                )));
            }
            bound_locations.insert((p.server.as_str(), p.deploy_dir.as_path()), &p.id);
        }

        for (tname, target) in &self.targets {
            if target.pods.is_empty() {
                return Err(Error::config(format!("target '{tname}' has no pods")));
            }
            // One server runs exactly one generation, so two member pods of the
            // same target can never share a server.
            let mut used_servers = std::collections::HashSet::new();
            for pid in &target.pods {
                let Some(pod) = pod_by_id.get(pid) else {
                    return Err(Error::config(format!(
                        "target '{tname}' references unknown pod '{pid}'"
                    )));
                };
                if !used_servers.insert(pod.server.as_str()) {
                    return Err(Error::config(format!(
                        "target '{tname}' has multiple pods on server '{}'",
                        pod.server
                    )));
                }
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
        if variant.capacity.reserve_percent > 100 {
            return Err(Error::config(format!(
                "variant '{name}': reserve_percent must not exceed 100"
            )));
        }

        // Validate mapping modes and artifact-relative destinations.
        for (i, m) in variant.artifact.mappings.iter().enumerate() {
            if let Some(mode) = &m.mode
                && mode != "preserve"
            {
                parse_octal_mode(mode)
                    .map_err(|e| Error::config(format!("variant '{name}' mapping[{i}] mode: {e}")))?;
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

    /// Resolve a target's member pods in the order they are listed, pairing
    /// each pod with its declared server. References are validated at load
    /// time, so a miss here is a configuration error.
    pub fn target_pods(&self, target_name: &str) -> Result<Vec<(&PodDef, &ServerDef)>> {
        let target = self
            .targets
            .get(target_name)
            .ok_or_else(|| Error::not_found(format!("target '{target_name}'")))?;
        let mut out = Vec::with_capacity(target.pods.len());
        for pid in &target.pods {
            let pod = self
                .pods
                .iter()
                .find(|p| &p.id == pid)
                .ok_or_else(|| {
                    Error::config(format!(
                        "target '{target_name}' references unknown pod '{pid}'"
                    ))
                })?;
            let server =
                self.servers
                    .iter()
                    .find(|s| s.id == pod.server)
                    .ok_or_else(|| {
                        Error::config(format!(
                            "pod '{}' references unknown server '{}'",
                            pod.id, pod.server
                        ))
                    })?;
            out.push((pod, server));
        }
        Ok(out)
    }

    /// Discover variant files inside the release directory. The project
    /// structure is forced: every regular, non-hidden `*.toml` file directly
    /// inside `<project>/releases/<release>/` is a variant named by its file
    /// stem. Other entries (such as the `artifacts/` directory) are ignored.
    fn load_variants(&mut self, config_path: &Path) -> Result<()> {
        let project_root = self
            .project_root(config_path)
            .canonicalize()
            .map_err(|e| Error::config(format!("canonicalize project root for deploy.toml: {e}")))?;
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

[capacity]
reserve_bytes = 0
reserve_percent = 0
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

[[pods]]
id = "p1"
server = "s1"
variant = "standard"
deploy_dir = "/srv/esc"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
pods = ["p1"]
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

[capacity]
reserve_bytes = 0
reserve_percent = 0
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

[capacity]
reserve_bytes = 1073741824
reserve_percent = 5
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

[[pods]]
id = "p1"
server = "s1"
variant = "standard"
deploy_dir = "/srv/example"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
pods = ["p1"]
"#;
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml).unwrap();

        let cfg = Config::load(&p).expect("config loads with sibling variant files");
        assert_eq!(cfg.targets["t1"].rotation.per_server.keep_distinct_artifacts, 5);
        assert_eq!(cfg.targets["t1"].rotation.fleet.protect_deployments, 2);
        let names = cfg.variant_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"standard".to_string()));
        assert!(names.contains(&"high-capacity".to_string()));

        let std = cfg.variant("standard").expect("standard variant present");
        assert_eq!(std.verification.argv, vec!["true".to_string()]);
        assert_eq!(std.activation.adapter, "none");
        assert_eq!(std.capacity.reserve_percent, 0);

        let hc = cfg.variant("high-capacity").expect("high-capacity variant present");
        assert_eq!(hc.verification.argv, vec!["false".to_string()]);
        assert_eq!(hc.activation.adapter, "systemd");
        assert!(!hc.activation.units.is_empty());
        assert_eq!(hc.capacity.reserve_bytes, 1073741824);

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

[capacity]
reserve_bytes = 0
reserve_percent = 0
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

[[pods]]
id = "p1"
server = "s1"
variant = "standard"
deploy_dir = "/srv/forced"

[targets.t1]
rollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }}
pods = ["p1"]
"#
        )
    }

    fn write_standard_release(project: &Path, release: &str) {
        let release_dir = project.join("releases").join(release);
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), MINIMAL_VARIANT).unwrap();
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
        assert_eq!(
            cfg.release_root(&p),
            project.join("releases").join("v1")
        );
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

[[pods]]
id = "p1"
server = "s1"
variant = "standard"
deploy_dir = "/srv/legacy"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
pods = ["p1"]
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

    #[test]
    fn targets_must_reference_declared_pods() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        // The target references `ghost`, which no [[pods]] entry declares.
        let p = project.join("deploy.toml");
        std::fs::write(
            &p,
            deploy_toml("v1").replace("pods = [\"p1\"]", "pods = [\"ghost\"]"),
        )
        .unwrap();
        let err = Config::load(&p).expect_err("unknown pod reference must fail");
        assert!(
            err.to_string().contains("unknown pod 'ghost'"),
            "error must name the unknown pod reference, got: {err}"
        );
    }

    #[test]
    fn pods_must_reference_known_servers_and_variants() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");

        // A pod bound to a server that does not exist.
        let p = project.join("deploy.toml");
        std::fs::write(
            &p,
            deploy_toml("v1").replace("server = \"s1\"", "server = \"ghost\""),
        )
        .unwrap();
        let err = Config::load(&p).expect_err("pod with unknown server must fail");
        assert!(
            err.to_string().contains("references unknown server 'ghost'"),
            "got: {err}"
        );

        // A pod bound to a variant the release directory does not declare.
        std::fs::write(
            &p,
            deploy_toml("v1").replace("variant = \"standard\"", "variant = \"ghost\""),
        )
        .unwrap();
        let err = Config::load(&p).expect_err("pod with unknown variant must fail");
        assert!(
            err.to_string().contains("references unknown variant 'ghost'"),
            "got: {err}"
        );
    }

    #[test]
    fn pods_on_the_same_server_never_share_a_deploy_dir() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let p = project.join("deploy.toml");

        // Second pod, same server, SAME deploy_dir: rejected.
        let dup = "\n[[pods]]\nid = \"p2\"\nserver = \"s1\"\nvariant = \"standard\"\ndeploy_dir = \"/srv/forced\"\n\n[targets.t1]";
        std::fs::write(
            &p,
            deploy_toml("v1").replace("\n[targets.t1]", dup),
        )
        .unwrap();
        let err = Config::load(&p).expect_err("shared server+deploy_dir must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("same location") && msg.contains("p1") && msg.contains("p2"),
            "error must name the colliding pods, got: {msg}"
        );

        // Second pod, same server, DIFFERENT deploy_dir: accepted.
        let ok = "\n[[pods]]\nid = \"p2\"\nserver = \"s1\"\nvariant = \"standard\"\ndeploy_dir = \"/srv/other\"\n\n[targets.t1]";
        std::fs::write(
            &p,
            deploy_toml("v1").replace("\n[targets.t1]", ok),
        )
        .unwrap();
        let cfg = Config::load(&p).expect("distinct deploy_dir on the same server is valid");
        assert_eq!(cfg.pods.len(), 2);
    }

    #[test]
    fn duplicate_top_level_server_ids_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        write_standard_release(&project, "v1");
        let mut toml = deploy_toml("v1");
        // Insert a second [[servers]] entry with the same ID before [targets.t1].
        let dup = "[[servers]]\nid = \"s1\"\naddress = \"a2\"\nuser = \"u\"\nvariant = \"standard\"\n\n";
        toml = toml.replacen("[targets.t1]", &format!("{dup}[targets.t1]"), 1);
        let p = project.join("deploy.toml");
        std::fs::write(&p, toml).unwrap();
        let err = Config::load(&p).expect_err("duplicate server id must fail");
        assert!(
            err.to_string().contains("duplicate server id 's1'"),
            "error must name the duplicated id, got: {err}"
        );
    }
}
