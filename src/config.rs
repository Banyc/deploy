//! Declarative deployment configuration (`deploy.yaml`, schema version 1).
//!
//! Mapping, activation, verification, capacity, rotation, and pins are project
//! level so that the same local inputs always produce one target-independent
//! release identity (see `model::ReleaseDigest`). Targets contain only their
//! rollout policy and their stable server membership with per-server variant
//! assignment.

use crate::error::{Error, Result};
use crate::model::SCHEMA_VERSION;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PinVariants {
    #[default]
    All,
    Some(Vec<String>),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VariantDef {
    /// Reserved for future per-variant mapping overrides.
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Mapping {
    /// Source path relative to the project root. `{{ variant }}` is the only
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RotationConfig {
    #[serde(default)]
    pub per_server: PerServerRotation,
    #[serde(default)]
    pub fleet: FleetRotation,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pin {
    pub release: String,
    #[serde(default)]
    pub variants: PinVariants,
    pub reason: String,
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
    pub variant: String,
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetDef {
    #[serde(default)]
    pub rollout: RolloutConfig,
    pub servers: Vec<ServerDef>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub schema_version: u32,
    pub application: String,
    pub remote_root: PathBuf,
    #[serde(default)]
    pub variants: BTreeMap<String, VariantDef>,
    pub artifact: ArtifactConfig,
    #[serde(default)]
    pub activation: ActivationConfig,
    pub verification: VerificationConfig,
    #[serde(default)]
    pub capacity: CapacityConfig,
    #[serde(default)]
    pub rotation: RotationConfig,
    #[serde(default)]
    pub pins: Vec<Pin>,
    pub targets: BTreeMap<String, TargetDef>,
}

impl Config {
    /// Load and validate a configuration from a `deploy.yaml` path. The project
    /// root is the directory containing the file.
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::config(format!("reading {}: {e}", path.display())))?;
        let cfg: Config = serde_yaml::from_str(&text)
            .map_err(|e| Error::config(format!("parsing deploy.yaml: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn project_root(&self, config_path: &Path) -> PathBuf {
        config_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
    }

    /// Validate the configuration per schema version 1 rules.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(Error::config(format!(
                "unsupported schema_version {} (expected {SCHEMA_VERSION})",
                self.schema_version
            )));
        }
        if self.variants.is_empty() {
            return Err(Error::config("at least one variant must be declared"));
        }
        if self.targets.is_empty() {
            return Err(Error::config("at least one target must be declared"));
        }
        if self.activation.adapter != "none" && self.activation.adapter != "systemd" {
            return Err(Error::config(format!(
                "unknown activation adapter '{}'",
                self.activation.adapter
            )));
        }
        if self.verification.adapter != "command" {
            return Err(Error::config(format!(
                "unsupported verification adapter '{}'",
                self.verification.adapter
            )));
        }
        if self.verification.argv.is_empty() {
            return Err(Error::config("verification argv must not be empty"));
        }

        // Variant names must be known.
        let mut all_ids = std::collections::HashSet::new();
        for (tname, target) in &self.targets {
            if target.servers.is_empty() {
                return Err(Error::config(format!("target '{tname}' has no servers")));
            }
            for s in &target.servers {
                if !all_ids.insert(s.id.clone()) {
                    return Err(Error::config(format!(
                        "duplicate server id '{}' across targets",
                        s.id
                    )));
                }
                if !self.variants.contains_key(&s.variant) {
                    return Err(Error::config(format!(
                        "server '{}' references unknown variant '{}'",
                        s.id, s.variant
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
            if self.activation.adapter == "systemd" && self.activation.units.is_empty() {
                return Err(Error::config(
                    "systemd activation requires at least one unit",
                ));
            }
        }

        // Validate mapping modes and artifact-relative destinations.
        for (i, m) in self.artifact.mappings.iter().enumerate() {
            if let Some(mode) = &m.mode
                && mode != "preserve"
            {
                parse_octal_mode(mode)
                    .map_err(|e| Error::config(format!("mapping[{i}] mode: {e}")))?;
            }
            if m.from.trim().is_empty() || m.to.trim().is_empty() {
                return Err(Error::config(format!(
                    "mapping[{i}] requires non-empty from/to"
                )));
            }
            validate_relative_path(Path::new(&m.to))
                .map_err(|e| Error::config(format!("mapping[{i}] to: {e}")))?;
        }
        Ok(())
    }

    pub fn variant_names(&self) -> Vec<String> {
        self.variants.keys().cloned().collect()
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
        let yaml = r#"
        schema_version: 1
        application: esc
        remote_root: /srv/esc
        variants: { standard: {} }
        artifact:
          mappings:
            - from: build/output/
              to: ../escape
              recursive: true
        activation: { adapter: none }
        verification: { adapter: command, argv: ["true"], timeout_seconds: 5, attempts: 1, interval_seconds: 0 }
        capacity: { reserve_bytes: 0, reserve_percent: 0 }
        rotation: { per_server: { keep_distinct_artifacts: 1, keep_days: 0, protect_previous: true }, fleet: { protect_deployments: 1 } }
        targets:
          t1:
            rollout: { batch_size: 1, stop_on_failure: true, failure_policy: rollback_changed }
            servers:
              - id: s1
                address: a
                user: u
                variant: standard
        "#;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("deploy.yaml");
        std::fs::write(&p, yaml).unwrap();
        assert!(
            Config::load(&p).is_err(),
            "escaping mapping `to` must be rejected"
        );
    }
}
