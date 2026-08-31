//! THE CONFIG CORE: declarative deployment configuration (`deploy.toml`).
//!
//! One feature — config loading / validation / mutation — organized as a
//! directory of single-concern modules:
//!
//! * [`shapes`] — the serialization shapes both layers share unchanged:
//!   [`raw`] (the raw WIRE shapes, re-exported here so `crate::config::raw::X`
//!   keeps resolving) and the artifact-mapping leaf types + path/mode helpers.
//! * this module — the validated [`ProjectConfig`] graph record (the
//!   immutable validated domain: EVERY field crate-private and read-only),
//!   the load / read accessors, and the total-fail-closed raw -> domain
//!   conversion.
//! * [`ops`] — the validated mutation / graph-rebuild operations, with their
//!   property-test suite (`ops::tests`).
//! * `tests` (`#[cfg(test)]`, `tests.rs`) — the config test suite.
//!
//! IMMUTABLE VALIDATED DOMAIN: EVERY field is crate-private and read-only —
//! the graph is exposed through read-only accessors and iterators
//! ([`ProjectConfig::application`], [`ProjectConfig::pins`],
//! [`ProjectConfig::servers`], [`ProjectConfig::targets`],
//! [`ProjectConfig::server`], [`ProjectConfig::target`],
//! [`ProjectConfig::slot_defs`], [`ProjectConfig::slot_retention`], ...). The
//! ONLY mutation path is a VALIDATED operation returning a NEW
//! [`ProjectConfig`] ([`ProjectConfig::load_release`] (a fresh validated load
//! switching the release), [`ProjectConfig::with_server`],
//! [`ProjectConfig::with_target`], [`ProjectConfig::with_pin`], ...) — each
//! of which re-validates the whole graph (references resolve, no impossible
//! combos) and returns `Err` with the ORIGINAL untouched on any violation. A
//! hand-built invalid graph cannot enter the domain, and no code can mutate a
//! validated graph into an invalid state. Loading and every mutation end in
//! the SAME single graph gate [`ProjectConfig::try_build`] (canonicalize all
//! leaves, validate the complete graph), so there is exactly ONE validator.
//!
//! The name [`DomainConfig`] aliases the validated graph type (the two-layer
//! story: raw serde shapes -> validated domain).

use crate::config::activation::Activation;
use crate::config::capacity::CapacityConfig;
use crate::config::pins::Pin;
use crate::config::raw::{CONFIG_SCHEMA_VERSION, RawConfig, RawVariant};
#[cfg(test)]
use crate::config::raw::{RawCapacityConfig, RawPin, RawRolloutConfig, RawServer, RawTargetConfig};
use crate::config::release_name::{ReleaseName, validate_release_name};
use crate::config::retention::RetentionConfig;
use crate::config::rollout::RolloutConfig;
use crate::config::servers::{
    HostIdentity, LOCAL_ADDRESS_MARKER, ServerConnection, ServerDef, is_legacy_local_endpoint,
    is_local_address, validate_server_identity,
};
use crate::config::slots::SlotConfig;
use crate::config::verification::Verification;
use crate::error::{Error, Result};
use crate::identity::{
    AbsoluteDeployDir, ApplicationStoreKey, BatchSize, CapacityPercent, Host, Identifier,
    RolloutGroupName, ServerId, SlotId, SshUser,
};
use crate::ledger::PhysicalBinding;
use std::collections::{BTreeMap, HashSet};
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};

mod ops;
mod shapes;
#[cfg(test)]
mod tests;

pub use shapes::mapping::{
    ArtifactConfig, ConflictPolicy, Mapping, destinations_overlap, normalize_destination,
    parse_octal_mode, resolved_mode, validate_relative_path,
};
pub(crate) use shapes::raw;

/// The DOMAIN target: ROLLOUT behavior only — `TargetConfig` is EXACTLY
/// `{ rollout: RolloutConfig }`. It MUST NOT (and does not) contain slots,
/// retention, history, deploy directories, or storage policy: a slot carries
/// its own `target`, deploy_dir, and groups; retention is slot-owned (the
/// slot's OWNING VARIANT's policy, see [`VariantConfig::retention`]); the
/// ledger files (`targets/<target>/ledger.jsonl`) live on disk, never in the
/// config. A target's member slots are DERIVED from the slots' `target`
/// fields at query time ([`ProjectConfig::target_slots`] /
/// [`ProjectConfig::target_group_slots`]), never stored here — the raw
/// `[targets.<name>]` shape (`deny_unknown_fields`) refuses a target that
/// tries to carry `slots`/`retention`/`storage` (see the config test
/// `targets_carry_rollout_only_and_refuse_slot_policy_members`). Built ONLY
/// by the raw -> domain conversion; the raw serialization
/// shape is `raw::RawTargetConfig` (bare integer batch size).
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
    /// The variant's typed verification policy ([`Verification`] — ALWAYS
    /// [`Verification::Command`]); the raw `adapter` string has already been
    /// consumed by the conversion, and the payload is fully validated
    /// (non-empty argv, nonzero attempts/timeout, known template variables).
    pub verification: Verification,
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
/// and the crate-internal conversion `ProjectConfig::from_raw_parts`, both of
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
/// state. Loading and every mutation end in the SAME single graph gate
/// [`ProjectConfig::try_build`] (canonicalize all leaves, validate the
/// complete graph), so there is exactly ONE validator.
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

    /// Total-fail-closed conversion of the raw deserialized input: the raw
    /// -> typed LEAF conversion (raw strings -> typed enums/scalars, mapping
    /// validation, the schema-version gate) runs here, and the candidate
    /// graph ends in the SINGLE graph gate [`ProjectConfig::try_build`] — the
    /// SAME gate every validated `with_*` rebuild operation runs, so loading
    /// and mutation share ONE validator. ANY violation rejects the
    /// conversion. Crate-internal: the raw layer is private, so the public
    /// entry to a validated domain is [`ProjectConfig::load`].
    pub(crate) fn from_raw_parts(
        manifest: RawConfig,
        variants: BTreeMap<String, RawVariant>,
    ) -> Result<ProjectConfig> {
        ProjectConfig::try_from(RawProject { manifest, variants })
    }

    /// THE single graph gate: canonicalizes every leaf and validates the
    /// COMPLETE graph. Operates on the domain graph — a freshly-converted
    /// candidate (the raw -> domain conversion ends here) or a mutated clone
    /// (every validated `with_*` rebuild operation ends here) — so loading and
    /// mutation share ONE validator. Every slot's deploy_dir is canonicalized
    /// through [`SlotConfig::with_canonical_deploy_dir`] / the
    /// [`crate::identity::AbsoluteDeployDir`] scalar (a relative,
    /// traversal-carrying, or root deploy_dir is rejected HERE), and the
    /// complete graph is validated with the SAME rules the load conversion
    /// applies: the schema-version gate, the release-name
    /// single-directory-component rule, identifier validity and uniqueness,
    /// reference resolution (slot -> server, slot -> target), group names,
    /// the connection enum well-formedness, the per-target membership rules,
    /// and the PHYSICAL-LOCATION INJECTION rule (the location key is the
    /// server's PHYSICAL ENDPOINT — `user@address` or the `local` marker —
    /// plus the EFFECTIVE deploy_dir, NOT the ServerId). Returns the
    /// canonicalized graph, or `Err` (the caller's ORIGINAL is untouched).
    pub(crate) fn try_build(mut self) -> Result<ProjectConfig> {
        // The schema version is a hard gate: an unrecognized version is
        // never interpreted.
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(Error::config(format!(
                "unsupported schema_version {} (expected {CONFIG_SCHEMA_VERSION})",
                self.schema_version
            )));
        }

        // The release name must be exactly one directory component so it
        // cannot escape the forced `releases/` directory.
        validate_release_name(self.release.as_str())?;

        // Canonicalize EVERY slot's deploy_dir: the raw spelling is
        // normalized through the `AbsoluteDeployDir` scalar — a relative,
        // traversal-carrying, or root deploy_dir is rejected HERE, and the
        // location-uniqueness rules below compare EFFECTIVE ROOTS, not mere
        // spellings (`/srv/a` and `/srv//a/` are the SAME effective root).
        for (vname, variant) in &mut self.variants {
            for slot in &mut variant.slots {
                *slot = slot.with_canonical_deploy_dir().map_err(|e| {
                    Error::config(format!(
                        "variant '{vname}': slot '{}' deploy_dir is invalid: {e}",
                        slot.id
                    ))
                })?;
            }
        }

        // Server ids are validated [`Identifier`]s by construction; the graph
        // rule is uniqueness. The connection enum must be well-formed: a
        // local form carries a `Local` identity (it carries NO root path —
        // the slot's deploy_dir is the sole physical root); an SSH form
        // carries a `KnownHosts`/`Fingerprint` identity (never `Local`) with
        // an absolute `known_hosts`.
        let mut server_ids = HashSet::new();
        for s in &self.servers {
            if !server_ids.insert(s.id.as_str()) {
                return Err(Error::config(format!(
                    "duplicate server id '{}' in top-level servers",
                    s.id
                )));
            }
            match s.connection() {
                ServerConnection::Local { identity } => {
                    if identity != &HostIdentity::Local {
                        return Err(Error::config(format!(
                            "server '{}': a local connection must carry a Local identity",
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
                && sa.units().is_empty()
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

        // Slots are declared INSIDE each variant's file (the declaring file
        // is the slot's variant binding), so they are aggregated across every
        // variant: IDs are unique across ALL variants, each slot's server must
        // exist among the top-level `[[servers]]` entries, each slot's ONE
        // owning `target` must exist among the top-level `[targets.<name>]`
        // keys, each group name must be non-empty and not repeated (a
        // duplicate adds no membership yet would change release identity),
        // and a (ENDPOINT, deploy_dir) pair names one on-host deployment
        // location that exactly one slot may own.
        //
        // THE PHYSICAL-LOCATION INJECTION RULE: the location key is the
        // PHYSICAL (endpoint, deploy_dir) pair — the endpoint is the server's
        // `user@address` (or the `local` marker), NOT the ServerId, so two
        // slots whose servers are DIFFERENT ServerIds but name the SAME
        // physical host+dir are REFUSED: a duplicate physical location is a
        // config error, never two silent authorities. This subsumes the old
        // per-server (server, deploy_dir) rule AND the local-root rule (every
        // local server shares the `local` endpoint, so two local slots on the
        // same directory collide regardless of their server ids).
        let mut slot_ids = HashSet::new();
        let mut bound_locations: BTreeMap<(String, &Path), &str> = BTreeMap::new();
        for (vname, variant) in &self.variants {
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
                // The deploy_dir is validated by the `AbsoluteDeployDir`
                // scalar (absolute path on the server). The slots entered the
                // graph already in their CANONICAL form (canonicalized
                // above), so this parse re-checks the gate and the
                // location-uniqueness rules below compare EFFECTIVE ROOTS, not
                // raw spellings.
                AbsoluteDeployDir::parse(&p.deploy_dir().to_string_lossy()).map_err(|_| {
                    Error::config(format!(
                        "variant '{vname}': slot '{}' deploy_dir must be an absolute path on the server",
                        p.id
                    ))
                })?;
                // INJECTIVE PHYSICAL LOCATIONS: the location key is the
                // server's PHYSICAL ENDPOINT (`user@address` — not the
                // ServerId) plus the effective deploy_dir. Two slots whose
                // servers name the SAME host with the SAME directory — even
                // under DIFFERENT ServerIds — are ONE physical location and
                // are refused here (fail closed): the two would otherwise be
                // silent authorities over the same deployment state. Local
                // servers all share the `local` endpoint, so two local slots
                // on the same directory collide regardless of server id.
                let server = self
                    .servers
                    .iter()
                    .find(|s| s.id.as_str() == p.server.as_str())
                    .expect("slot server existence was validated above");
                let endpoint = server.endpoint();
                if let Some(existing) = bound_locations.get(&(endpoint.clone(), p.deploy_dir())) {
                    return Err(Error::config(format!(
                        "slots '{existing}' and '{}' bind the same physical location (endpoint '{endpoint}', deploy_dir '{}'); each physical host+deploy_dir pair must belong to exactly one slot",
                        p.id,
                        p.deploy_dir().display()
                    )));
                }
                bound_locations.insert((endpoint, p.deploy_dir()), &p.id);
            }
        }

        // Targets carry ROLLOUT behavior only. Each target name is parsed
        // into the validated [`Identifier`] scalar. A target's members are
        // DERIVED by scanning every variant's slots for the target name. One
        // server runs exactly one generation, so two member slots of the same
        // target can never share a server — and a target must have at least
        // one member. A slot has EXACTLY ONE owning target, so the per-target
        // checks run once per slot (its owner) and the same two slots can
        // never share a server in DIFFERENT targets.
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

        Ok(self)
    }

    pub fn project_root(&self, config_path: &Path) -> PathBuf {
        config_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
    }

    /// The schema version this configuration was validated as — ALWAYS
    /// `CONFIG_SCHEMA_VERSION` by construction (the conversion refuses any
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

    /// The domain -> raw conversion (test-only): serialize the validated
    /// graph back to the raw wire shapes ([`RawProject`]). The raw shapes
    /// are crate-internal and the domain fields are crate-private, so the
    /// round trip lives inside the crate. Used by the serialize/reload
    /// property: a config built by successful `with_*` ops must survive
    /// `to_raw_parts` -> `from_raw_parts` (the SAME constructor, ending in
    /// [`ProjectConfig::try_build`]) unchanged — the typed leaves serialize
    /// to their canonical raw forms and re-parse to the same typed values,
    /// and the canonical deploy_dirs are a canonicalization fixed point.
    #[cfg(test)]
    pub(crate) fn to_raw_parts(&self) -> RawProject {
        RawProject {
            manifest: RawConfig {
                schema_version: self.schema_version,
                application: self.application.as_str().to_string(),
                release: self.release.clone(),
                pins: self
                    .pins
                    .iter()
                    .map(|p| RawPin {
                        release: p.release.as_str().to_string(),
                        reason: p.reason.clone(),
                    })
                    .collect(),
                servers: self
                    .servers
                    .iter()
                    .map(|s| RawServer {
                        id: s.id.as_str().to_string(),
                        address: s.address().to_string(),
                        user: s.user().to_string(),
                        port: s.port(),
                        known_hosts: match s.identity() {
                            HostIdentity::KnownHosts(p) => Some(p.clone()),
                            _ => None,
                        },
                        host_key_fingerprint: match s.identity() {
                            HostIdentity::Fingerprint(f) => Some(f.as_str().to_string()),
                            _ => None,
                        },
                        capacity: RawCapacityConfig {
                            reserve_bytes: s.capacity.reserve_bytes,
                            reserve_percent: s.capacity.reserve_percent.get(),
                        },
                    })
                    .collect(),
                targets: self
                    .targets
                    .iter()
                    .map(|(name, t)| {
                        (
                            name.clone(),
                            RawTargetConfig {
                                rollout: RawRolloutConfig {
                                    batch_size: u32::try_from(t.rollout.batch_size.get()).expect(
                                        "a config-validated batch size fits the raw u32 wire form",
                                    ),
                                    stop_on_failure: t.rollout.stop_on_failure,
                                    failure_policy: t.rollout.failure_policy,
                                },
                            },
                        )
                    })
                    .collect(),
            },
            variants: self
                .variants
                .iter()
                .map(|(name, v)| {
                    (
                        name.clone(),
                        RawVariant {
                            description: v.description.clone(),
                            artifact: v.artifact.clone(),
                            activation: v.activation.to_config(),
                            verification: v.verification.to_config(),
                            slots: v.slots.clone(),
                            retention: v.retention.clone(),
                        },
                    )
                })
                .collect(),
        }
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

/// The total-fail-closed raw -> domain conversion: the raw -> typed LEAF
/// conversion (raw strings -> typed enums/scalars, mapping validation) runs
/// here, and the candidate graph ends in the SINGLE graph gate
/// [`ProjectConfig::try_build`] — the SAME gate every validated `with_*`
/// rebuild operation runs, so loading and mutation share ONE validator. ANY
/// violation rejects the whole conversion:
///
/// * the schema-version gate,
/// * the activation/verification enums (unknown adapters rejected, systemd
///   needs units, empty argv / zero attempts / zero timeout refused),
/// * exactly-one host identity per SSH server (plus the format rules for
///   each identity source),
/// * mapping destination collisions,
/// * and — through [`ProjectConfig::try_build`] — identifier validity and
///   uniqueness, reference resolution (slot -> server, slot -> target),
///   group names, deploy_dir canonicalization, the physical-location
///   injection rule, and the per-target membership rules.
impl TryFrom<RawProject> for ProjectConfig {
    type Error = Error;

    fn try_from(project: RawProject) -> Result<ProjectConfig> {
        let RawProject { manifest, variants } = project;

        // Every pin's release must satisfy the EXACT `rel-sha256-<64
        // lowercase hex>` grammar: the raw wire string is parsed into the
        // typed [`crate::identity::ReleaseId`] HERE, at the load — a malformed
        // pin string fails the WHOLE conversion (fail closed, like the
        // sibling identifier gates), stopping at the FIRST bad pin. A
        // successfully loaded configuration therefore can never carry a pin
        // whose release would later fail [`crate::identity::ReleaseId::parse`].
        let pins = manifest
            .pins
            .into_iter()
            .map(Pin::try_from)
            .collect::<Result<Vec<_>>>()?;

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
        // `adapter` string becomes the typed [`Activation`] enum). The slots
        // enter the candidate graph UNCANONICALIZED — the single graph gate
        // ([`ProjectConfig::try_build`]) canonicalizes every deploy_dir and
        // validates the complete graph.
        let mut domain_variants = BTreeMap::new();
        for (vname, variant) in &variants {
            // The activation and verification ADAPTER STRINGS are consumed
            // here through the CLOSED enums: an unknown/unsupported adapter
            // (or an invalid payload — systemd without units, an invalid
            // unit name/artifact path, empty argv, zero attempts, zero
            // timeout, an unknown template variable, irrelevant fields) is a
            // REFUSAL at the load, never a silent no-op later.
            let activation = Activation::try_from(&variant.activation)
                .map_err(|e| Error::config(format!("variant '{vname}': {e}")))?;
            let verification = Verification::try_from(&variant.verification)
                .map_err(|e| Error::config(format!("variant '{vname}': {e}")))?;

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
                    verification: verification.clone(),
                    slots: variant.slots.clone(),
                    retention: variant.retention.clone(),
                },
            );
        }

        // Server declarations: the id is parsed into the validated
        // [`Identifier`] scalar, the capacity percent into the validated
        // 0..=100 [`CapacityPercent`] scalar, and the raw identity pair is
        // collapsed into the ONE validated [`HostIdentity`] form (the
        // per-source format checks apply to every server; the exactly-one
        // rule is scoped to SSH addresses). The connection is built as the
        // EXACTLY ONE form: the `local` marker becomes `Local` — a PATHLESS
        // connection kind whose sole physical root is the referencing slot's
        // typed deploy_dir (the transport is rooted there, never at a
        // server-side endpoint). A legacy `local://<path>` address is
        // REJECTED here, at the load: the connection carries no root path, so
        // a `local://` endpoint could only silently diverge from (or be
        // ignored in favor of) the slot's deploy_dir — the mismatch class
        // this design eliminates. An SSH address becomes `Ssh` with the
        // validated host/user/nonzero port and the exactly-one host identity.
        //
        // Server-id UNIQUENESS is re-checked here, BEFORE the per-server
        // leaf validation of the later duplicate: a duplicate id is the
        // clearer failure to report (the later duplicate may itself carry an
        // invalid identity, which would otherwise shadow the duplicate). The
        // single graph gate [`ProjectConfig::try_build`] re-enforces the rule
        // on the complete graph.
        let mut all_server_ids: HashSet<String> = HashSet::new();
        let mut domain_servers = Vec::with_capacity(manifest.servers.len());
        for s in &manifest.servers {
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
            let reserve_percent =
                CapacityPercent::new(s.capacity.reserve_percent).map_err(|_| {
                    Error::config(format!(
                        "server '{}': reserve_percent must be within 0..=100",
                        s.id
                    ))
                })?;
            let identity = validate_server_identity(s)?;
            let connection = if is_local_address(&s.address) {
                ServerConnection::Local { identity }
            } else if is_legacy_local_endpoint(&s.address) {
                return Err(Error::config(format!(
                    "server '{}': address '{}' is the legacy local:// endpoint form; \
                     a local connection no longer carries a path — use address = \"{}\" \
                     (the slot's deploy_dir is the sole physical root, so a local:// path \
                     could silently diverge from the slot's recorded directory)",
                    s.id, s.address, LOCAL_ADDRESS_MARKER
                )));
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

        // Targets carry ROLLOUT behavior only. Each target's raw integer
        // `batch_size` is parsed into the validated NONZERO [`BatchSize`]
        // scalar (a zero batch would stall the rollout without ever
        // progressing — a NEW fail-closed gate the raw shape allows).
        let mut domain_targets = BTreeMap::new();
        for (tname, raw_target) in &manifest.targets {
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

        // THE SINGLE GRAPH GATE: the candidate graph (typed leaves, raw slot
        // spellings) is canonicalized (every slot's deploy_dir) and validated
        // as a COMPLETE graph by [`ProjectConfig::try_build`] — the SAME gate
        // every validated `with_*` rebuild operation runs, so loading and
        // mutation share ONE validator.
        ProjectConfig {
            schema_version: manifest.schema_version,
            application,
            release: manifest.release,
            pins,
            servers: domain_servers,
            targets: domain_targets,
            variants: domain_variants,
        }
        .try_build()
    }
}

// The DERIVED views of the validated graph: everything a caller asks a
// [`ProjectConfig`] to RESOLVE rather than to store. Slot membership is
// never stored on targets — a target's member slots are DERIVED by
// scanning every variant's `[[slots]]` declarations for the target name —
// and a slot's owning variant (the file that declares it) is its SINGLE
// source for retention and its slot-variant binding. These read-only
// resolutions ([`ProjectConfig::slot_defs`], [`ProjectConfig::slot_variant`],
// [`ProjectConfig::slot_retention`], [`ProjectConfig::target_slots`],
// [`ProjectConfig::target_group_slots`], [`ProjectConfig::target_slot_ids`],
// [`ProjectConfig::target_slot_bindings`]) live here, away from the graph
// record itself.

impl ProjectConfig {
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
    /// slot-owned — a slot's policy is resolved here, from a single source,
    /// regardless of which rollout group (or owning target) a push selects it
    /// under, so membership changes never change retention.
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
    /// The bindings are CONFIG-DERIVED ([`PhysicalBinding::from_config`]):
    /// their receiver UUID (the deploy_dir's PHYSICAL identity) is a
    /// runtime fact read from the provisioned remote during preflight and
    /// filled in by [`PhysicalBinding::with_receiver_uuid`] there — the
    /// config itself cannot know it. Used to record (and later verify) the
    /// exact physical location a deployment snapshot's slots were deployed
    /// onto: exact rollback must see the receiver UUID unchanged, because a
    /// slot that keeps its server but moves its `deploy_dir` (or whose
    /// physical receiver changed under the same ServerId/path) would
    /// otherwise roll back onto the new location.
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
                    PhysicalBinding::from_config(
                        ServerId::parse(server.id.as_str())
                            .expect("validated server id is a safe segment"),
                        slot.deploy_dir(),
                    )
                    .expect("a config-validated deploy_dir is absolute and traversal-free"),
                )
            })
            .collect())
    }
}
