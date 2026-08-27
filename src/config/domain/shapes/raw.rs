//! The raw SERDE shapes: exactly what the file says (`deny_unknown_fields`
//! refuses unknown fields at parse), plus the config schema version gate the
//! raw -> domain conversion enforces.

use super::mapping::ArtifactConfig;
use crate::config::activation::{ActivationConfig, default_true};
use crate::config::release_name::ReleaseName;
use crate::config::retention::RetentionConfig;
use crate::config::rollout::{FailurePolicy, default_failure_policy};
use crate::config::servers::default_ssh_port;
use crate::config::slots::SlotConfig;
use crate::config::verification::VerificationConfig;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The deploy.toml configuration format version. The config layer owns its
/// schema identity: the raw -> domain conversion refuses any manifest whose
/// `schema_version` differs, so a loaded [`crate::config::domain::ProjectConfig`] is ALWAYS
/// validated at this version by construction.
pub(crate) const CONFIG_SCHEMA_VERSION: u32 = 2;

// ---------------------------------------------------------------------------
// The RAW layer: exactly the serialized shapes, nothing else.
// `deny_unknown_fields` makes the parse gate fail closed, and the conversion
// makes the domain gate fail closed. These types are crate-internal: callers
// reach the validated domain through [`ProjectConfig::load`].
// ---------------------------------------------------------------------------

/// The raw `deploy.toml` manifest shape. Holds whatever the file says —
/// `known_hosts`/`host_key_fingerprint` as a plain option pair, no
/// validation, unknown fields refused at parse. Converted to the
/// validated [`DomainConfig`] by [`crate::config::domain::ProjectConfig::from_raw_parts`].
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
/// typed [`crate::config::domain::Pin::release`] [`crate::config::domain::ReleaseId`] — a malformed pin
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
    #[serde(default = "default_ssh_port")]
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
/// [`crate::config::domain::CapacityPercent`] (0..=100) and builds the domain
/// [`crate::config::domain::CapacityConfig`]; this raw type keeps the bare integer so
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
/// [`crate::config::domain::BatchSize`] and builds the domain [`crate::config::domain::TargetConfig`]; the
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
    #[serde(default = "default_true")]
    pub stop_on_failure: bool,
    #[serde(default = "default_failure_policy")]
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
