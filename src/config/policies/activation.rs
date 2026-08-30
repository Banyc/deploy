//! Activation policy: the typed [`Activation`] enum (`None` | `Systemd`).
//!
//! The CLOSED domain enum [`Activation`] is the only consumer-facing form:
//! an unsupported activation adapter string can never become an
//! [`Activation`] — the conversion (`TryFrom<&ActivationConfig>`) and the
//! serde `Deserialize` impl both REFUSE it (fail closed), so a frozen
//! release record whose `activation.adapter` names an adapter the tool
//! cannot run is rejected at the record boundary instead of becoming a
//! silent no-op during activation. [`Activation::Systemd`] carries the
//! fully validated payload [`ValidatedSystemd`] (every unit's name and
//! artifact path validated, at least one unit required).

use crate::config::validate_relative_path;
use crate::error::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::path::Path;

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

pub(crate) fn default_true() -> bool {
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
/// canonical [`ActivationConfig`] form of a domain [`Activation`] is always
/// produced through [`ActivationConfig::from`] / [`Activation::to_config`].
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

/// A variant's activation policy as a closed enum: no activation adapter
/// (a deliberate no-op), or a `systemd` activation carrying its scope,
/// reconciliation, and FULLY VALIDATED units. The raw `adapter` string is
/// consumed by the conversion, so an unknown adapter cannot exist in a
/// domain value — a frozen record carrying `adapter = "bogus"` is REFUSED
/// here, never silently no-op'd.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Activation {
    /// `adapter = "none"`: no activation step runs. The other wire fields
    /// must be their canonical defaults — a `none` contract carrying units
    /// or a non-default scope/reconciliation is an irrelevant-field refusal.
    None,
    /// `adapter = "systemd"`: activate via systemd with the given scope and
    /// validated units. The conversion requires at least one unit, each with
    /// a valid single-filename name and an artifact-relative path.
    Systemd(ValidatedSystemd),
}

/// The systemd activation policy: the unit scope, whether managed units are
/// reconciled, and the unit definitions to install. Constructed only through
/// the [`Activation`] conversions (which validate every unit), never
/// hand-built by production code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedSystemd {
    pub scope: ActivationScope,
    pub reconcile_managed_units: bool,
    pub units: Vec<UnitDef>,
}

/// Reject a unit name that could escape the systemd/user directory
/// (absolute paths, parent-dir components, or empty names).
pub(crate) fn validate_unit_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::config("systemd unit name must not be empty"));
    }
    if Path::new(name).is_absolute() {
        return Err(Error::config(format!(
            "systemd unit name '{}' must not be an absolute path",
            name
        )));
    }
    let dangerous = name
        .split('/')
        .any(|c| c == ".." || c == "." || c.is_empty());
    if dangerous {
        return Err(Error::config(format!(
            "systemd unit name '{}' must be a single filename",
            name
        )));
    }
    Ok(())
}

impl Activation {
    /// The canonical wire form of this closed value (the serialized record
    /// contract, byte-stable with the raw shape).
    pub fn to_config(&self) -> ActivationConfig {
        ActivationConfig::from(self)
    }
}

impl TryFrom<&ActivationConfig> for Activation {
    type Error = Error;

    fn try_from(wire: &ActivationConfig) -> Result<Activation> {
        match wire.adapter.as_str() {
            "none" => {
                // A `none` contract carries NO activation policy: any of the
                // policy fields would be irrelevant (and silently dropped by
                // the canonical form), so they are refused (fail closed).
                if !wire.units.is_empty() || wire.scope != ActivationScope::User {
                    return Err(Error::config(
                        "activation adapter 'none' must not carry units or a non-default scope (irrelevant fields refused)",
                    ));
                }
                Ok(Activation::None)
            }
            "systemd" => {
                if wire.units.is_empty() {
                    return Err(Error::config(
                        "systemd activation requires at least one unit",
                    ));
                }
                for u in &wire.units {
                    validate_unit_name(&u.name)?;
                    validate_relative_path(Path::new(&u.artifact_path)).map_err(|e| {
                        Error::config(format!(
                            "systemd unit '{}' artifact path invalid: {e}",
                            u.name
                        ))
                    })?;
                }
                Ok(Activation::Systemd(ValidatedSystemd {
                    scope: wire.scope.clone(),
                    reconcile_managed_units: wire.reconcile_managed_units,
                    units: wire.units.clone(),
                }))
            }
            other => Err(Error::config(format!(
                "unknown activation adapter '{other}' (supported: none, systemd) — an unsupported adapter is refused, never silently skipped"
            ))),
        }
    }
}

impl TryFrom<ActivationConfig> for Activation {
    type Error = Error;
    fn try_from(wire: ActivationConfig) -> Result<Activation> {
        Activation::try_from(&wire)
    }
}

impl From<&Activation> for ActivationConfig {
    /// The canonical serialized contract for an [`Activation`]: `None`
    /// becomes the default "none" contract (scope/units of a none-variant are
    /// not part of the domain), `Systemd` becomes the systemd contract. This
    /// is the ONLY path from the domain to the contract records, so the
    /// behavior digest is deterministic and byte-stable.
    fn from(a: &Activation) -> ActivationConfig {
        match a {
            Activation::None => ActivationConfig {
                adapter: "none".to_string(),
                scope: ActivationScope::default(),
                reconcile_managed_units: true,
                units: Vec::new(),
            },
            Activation::Systemd(sa) => ActivationConfig {
                adapter: "systemd".to_string(),
                scope: sa.scope.clone(),
                reconcile_managed_units: sa.reconcile_managed_units,
                units: sa.units.clone(),
            },
        }
    }
}

impl From<Activation> for ActivationConfig {
    fn from(a: Activation) -> ActivationConfig {
        ActivationConfig::from(&a)
    }
}

impl Serialize for Activation {
    /// Serializes to the canonical wire bytes (identical to the raw
    /// [`ActivationConfig`] shape), so digests over the contract stay stable
    /// whether the record was built from the domain or round-tripped.
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        ActivationConfig::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Activation {
    /// The wire form is parsed through the closed enum: the raw shape
    /// (with `deny_unknown_fields`) is deserialized first, then the
    /// conversion rules run — an unknown adapter, a systemd contract
    /// without units, an invalid unit name/artifact path, an irrelevant
    /// field on a `none` contract, or any unknown field is REFUSED at
    /// deserialization (fail closed).
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let wire = ActivationConfig::deserialize(deserializer)?;
        Activation::try_from(&wire).map_err(serde::de::Error::custom)
    }
}
