//! The validated domain model: [`ProjectConfig`] (the immutable validated
//! graph), the total-fail-closed raw -> domain conversion, the load /
//! validated-mutation operations, and the artifact-mapping leaf types the
//! conversion validates.

use crate::config::activation::{Activation, SystemdActivation};
use crate::config::capacity::CapacityConfig;
use crate::config::pins::Pin;
use crate::config::raw::{CONFIG_SCHEMA_VERSION, RawConfig, RawVariant};
use crate::config::release_name::{ReleaseName, validate_release_name};
use crate::config::retention::RetentionConfig;
use crate::config::rollout::RolloutConfig;
use crate::config::servers::{HostIdentity, ServerConnection, ServerDef, validate_server_identity};
use crate::config::slots::SlotConfig;
use crate::config::verification::VerificationConfig;
use crate::error::{Error, Result};
use crate::identity::{
    AbsoluteDeployDir, ApplicationStoreKey, BatchSize, CapacityPercent, Host, Identifier,
    RolloutGroupName, SshUser,
};
use crate::identity::{ReleaseId, ServerId, SlotId};
use crate::ledger::PhysicalBinding;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::num::NonZeroU16;
use std::path::{Component, Path, PathBuf};
use unicode_normalization::UnicodeNormalization;

// ---------------------------------------------------------------------------
// Artifact mappings — the leaf types both layers use unchanged, validated by
// the raw -> domain conversion below.
// ---------------------------------------------------------------------------

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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Mapping {
    /// Source path relative to the release directory (`releases/<release>/`),
    /// where the convention is `artifacts/...`. The path is rendered with the
    /// template module (`crate::remote::materialize`): `{{ variant }}` is available at
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
    /// path segment ([`crate::identity::ApplicationStoreKey`]) parsed by the
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
    fn read_manifest(path: &Path) -> Result<RawConfig> {
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
        manifest: RawConfig,
        variants: BTreeMap<String, RawVariant>,
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

    /// The raw `servers` slice (test-only): the read-only
    /// [`ProjectConfig::servers`] accessor is the iterator; direct slice
    /// access (indexing, `len`) is test-internal.
    #[cfg(test)]
    pub(crate) fn servers_ref(&self) -> &[ServerDef] {
        &self.servers
    }

    /// The raw `targets` map (test-only): the read-only
    /// [`ProjectConfig::targets`] accessor is the iterator; direct map access
    /// (indexing, `len`) is test-internal.
    #[cfg(test)]
    pub(crate) fn targets_ref(&self) -> &BTreeMap<String, TargetConfig> {
        &self.targets
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
                if !p.deploy_dir().is_absolute() {
                    return Err(Error::config(format!(
                        "variant '{vname}': slot '{}' deploy_dir must be an absolute path on the server",
                        p.id
                    )));
                }
                if let Some(existing) = bound_locations.get(&(p.server.as_str(), p.deploy_dir())) {
                    return Err(Error::config(format!(
                        "slots '{existing}' and '{}' bind the same location (server '{}', deploy_dir '{}'); each server+deploy_dir pair must belong to exactly one slot",
                        p.id,
                        p.server,
                        p.deploy_dir().display()
                    )));
                }
                bound_locations.insert((p.server.as_str(), p.deploy_dir()), &p.id);
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
        *server = ServerDef::new(server.id.clone(), connection, server.capacity.clone());
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
                        deploy_dir: slot.deploy_dir().to_string_lossy().into_owned(),
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
    pub manifest: RawConfig,
    pub variants: BTreeMap<String, RawVariant>,
}

/// An identifier is valid when it is non-empty after trimming (any Unicode
/// content is allowed; an empty or whitespace-only identifier cannot name a
/// server, slot, target, or variant). Kept for the test-side domain invariant
/// assertions; the CONVERSION gates identifiers through the stricter
/// [`crate::identity::Identifier`] parse (which additionally rejects surrounding
/// whitespace and control characters).
#[cfg(test)]
pub(crate) fn valid_identifier(id: &str) -> bool {
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
        // path segment [`crate::identity::ApplicationStoreKey`]: an
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
            domain_servers.push(ServerDef::new(
                id,
                connection,
                CapacityConfig {
                    reserve_bytes: s.capacity.reserve_bytes,
                    reserve_percent,
                },
            ));
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
                AbsoluteDeployDir::parse(&p.deploy_dir().to_string_lossy()).map_err(|_| {
                    Error::config(format!(
                        "variant '{vname}': slot '{}' deploy_dir must be an absolute path on the server",
                        p.id
                    ))
                })?;
                if let Some(existing) = bound_locations.get(&(p.server.as_str(), p.deploy_dir())) {
                    return Err(Error::config(format!(
                        "slots '{existing}' and '{}' bind the same location (server '{}', deploy_dir '{}'); each server+deploy_dir pair must belong to exactly one slot",
                        p.id,
                        p.server,
                        p.deploy_dir().display()
                    )));
                }
                bound_locations.insert((p.server.as_str(), p.deploy_dir()), &p.id);
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
