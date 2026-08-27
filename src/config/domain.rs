//! The validated domain model: [`ProjectConfig`] (the immutable validated
//! graph), the total-fail-closed raw -> domain conversion, and the load /
//! read-only surface. The graph record lives here with its constructor
//! ([`ProjectConfig::load`], the crate-internal
//! [`ProjectConfig::from_raw_parts`] + the [`TryFrom`] conversion, and the
//! test-side [`RawProject`]) and its core read accessors
//! (application / release / pins / servers / targets / variants,
//! [`ProjectConfig::variant`], [`ProjectConfig::release_root`], ...).
//!
//! The MUTATION surface is split out: the validated graph-rebuild
//! operations (with_pin / without_pin / rename_pin / rename_target /
//! load_release / the validated rebuilds + `validate_graph`) live in
//! [`crate::config::ops`], and the DERIVED slot/target resolutions
//! ([`ProjectConfig::target_slots`], [`ProjectConfig::slot_retention`],
//! [`ProjectConfig::target_slot_bindings`], ...) live in
//! [`crate::config::derived`]. The artifact-mapping leaf types and the
//! path/mode helpers live in [`crate::config::mapping`].
//!
//! IMMUTABLE VALIDATED DOMAIN: EVERY field is crate-private and read-only —
//! the graph is exposed through read-only accessors and iterators
//! ([`ProjectConfig::application`], [`ProjectConfig::pins`], [`ProjectConfig::servers`],
//! [`ProjectConfig::targets`], [`ProjectConfig::server`], [`ProjectConfig::target`],
//! [`ProjectConfig::slot_defs`], [`ProjectConfig::slot_retention`], ...). The ONLY
//! mutation path is a VALIDATED operation returning a NEW [`ProjectConfig`]
//! (see [`crate::config::ops`]) — [`ProjectConfig::load_release`] (a fresh
//! validated load switching the release), [`ProjectConfig::with_server`],
//! [`ProjectConfig::with_target`], [`ProjectConfig::with_pin`], ... — each of
//! which re-validates the whole graph (references resolve, no impossible
//! combos) and returns `Err` with the ORIGINAL untouched on any violation.
//! A hand-built invalid graph cannot enter the domain, and no code can
//! mutate a validated graph into an invalid state.
//!
//! The name [`DomainConfig`] aliases this type (the two-layer story: raw
//! serde shapes -> validated domain).

use crate::config::activation::{Activation, SystemdActivation};
use crate::config::capacity::CapacityConfig;
use crate::config::mapping::{
    ArtifactConfig, destinations_overlap, parse_octal_mode, validate_relative_path,
};
use crate::config::pins::Pin;
use crate::config::raw::{CONFIG_SCHEMA_VERSION, RawConfig, RawVariant};
use crate::config::release_name::{ReleaseName, validate_release_name};
use crate::config::retention::RetentionConfig;
use crate::config::rollout::RolloutConfig;
use crate::config::servers::{ServerConnection, ServerDef, validate_server_identity};
use crate::config::slots::SlotConfig;
use crate::config::verification::VerificationConfig;
use crate::error::{Error, Result};
use crate::identity::{
    AbsoluteDeployDir, ApplicationStoreKey, BatchSize, CapacityPercent, Host, Identifier,
    RolloutGroupName, SshUser,
};
use std::collections::{BTreeMap, HashSet};
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};

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
    pub(crate) schema_version: u32,
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
    pub(crate) application: ApplicationStoreKey,
    /// The active release: the name of a directory directly beneath
    /// `releases/` in the project root (`release: v1` -> `releases/v1/`).
    /// INVARIANT-BEARING (a single directory component) — private and
    /// read-only ([`ProjectConfig::release`]); switch it through the validated
    /// [`ProjectConfig::load_release`] operation (a fresh load), never by
    /// assignment.
    pub(crate) release: ReleaseName,
    /// Durable retention pins applied on every retention pass. Private +
    /// read-only ([`ProjectConfig::pins`]); changed only through the
    /// validated [`ProjectConfig::with_pin`] / [`ProjectConfig::without_pin`]
    /// operations.
    pub(crate) pins: Vec<Pin>,
    /// Every validated server; a server's connection is exactly one form by
    /// construction ([`ServerDef::connection`]). Private + read-only
    /// ([`ProjectConfig::servers`] iterator, [`ProjectConfig::server`]);
    /// changed only through the validated rebuild operations.
    pub(crate) servers: Vec<ServerDef>,
    /// Every validated target, keyed by name. Private + read-only
    /// ([`ProjectConfig::targets`] iterator, [`ProjectConfig::target`]);
    /// changed only through the validated rebuild operations.
    pub(crate) targets: BTreeMap<String, TargetConfig>,
    /// Validated variants, keyed by name. Private: the domain graph cannot
    /// be hand-built — variants only enter through the conversion.
    pub(crate) variants: BTreeMap<String, VariantConfig>,
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
    pub(crate) fn read_manifest(path: &Path) -> Result<RawConfig> {
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
}

impl ProjectConfig {
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
