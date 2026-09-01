//! Declarative deployment configuration (`deploy.toml`, schema version 1).
//!
//! The config layer is split into TWO layers with a total-fail-closed
//! conversion between them:
//!
//! 1. `raw` — the raw SERDE shapes: `raw::RawConfig` (the `deploy.toml`
//!    manifest), `raw::RawServer` (one `[[servers]]` entry), and
//!    `raw::RawVariant` (one variant file). These types hold exactly what
//!    the file says — `known_hosts` and `host_key_fingerprint` as a plain
//!    `Option` pair, activation as a bare `adapter` string — and refuse
//!    unknown fields (`deny_unknown_fields`). They are crate-internal: the
//!    only entry point into a validated configuration is [`ProjectConfig::load`]
//!    (parse -> convert) or the crate-internal conversion
//!    `ProjectConfig::from_raw_parts`.
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
//!
//! The module is organized by feature. `domain` is THE CONFIG CORE — a
//! directory of single-concern modules: the serialization shapes (`raw` —
//! the raw wire shapes, re-exported here — and the artifact-mapping leaf
//! types + path/mode helpers), the validated [`ProjectConfig`] graph record,
//! the total-fail-closed raw -> domain conversion, the derived slot/target
//! resolution views, the validated mutation / graph-rebuild operations, and
//! the config test suite. The per-surface policy leaf modules (`pins`,
//! `slots`, `rollout`, `retention`, `activation`, `verification`,
//! `servers`, `capacity`, `release_name`) are grouped under the
//! `policies` directory and re-exported at their original paths: each is a
//! distinct, independently-validated config surface.
//!
//! The crate-facing surface is re-exported here: `crate::config::Pin`,
//! `crate::config::ProjectConfig`, `crate::config::raw::RawConfig`, ...
//! resolve exactly as they did when the whole config surface lived in
//! `src/config.rs`.

pub(crate) use domain::raw;
pub(crate) use policies::{
    activation, capacity, pins, release_name, retention, rollout, servers, slots, verification,
};

mod domain;
mod policies;

pub use activation::{
    Activation, ActivationConfig, ActivationScope, UnitDef, UnitName, ValidatedSystemd,
};
pub use capacity::CapacityConfig;
pub use domain::{
    ArtifactConfig, ConflictPolicy, DomainConfig, Mapping, ProjectConfig, TargetConfig,
    VariantConfig, destinations_overlap, normalize_destination, parse_octal_mode, resolved_mode,
    validate_relative_path,
};
pub use pins::Pin;
pub use release_name::ReleaseName;
pub use retention::{DeploymentRetention, PerServerRetention, RetentionConfig};
pub use rollout::{FailurePolicy, RolloutConfig};
pub use servers::{Fingerprint, HostIdentity, ServerConnection, ServerDef};
pub use slots::SlotConfig;
pub use verification::{ValidatedCommand, Verification, VerificationConfig};
