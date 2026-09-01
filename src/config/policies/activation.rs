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
//!
//! THE UNIT SET IS TYPED: [`ValidatedSystemd`] holds its units in a
//! [`BTreeMap`] keyed by the unit IDENTITY — the unit NAME (systemd
//! installs units BY NAME into the systemd directory, so two units with
//! the same name would silently overwrite each other). A duplicate
//! identity is UNREPRESENTABLE in the type: the conversion and the
//! validated constructor build the set and REFUSE a duplicate (fail
//! closed), so a wire config carrying two units with the same name is
//! rejected at the record boundary, never silently collapsed.

use crate::config::validate_relative_path;
use crate::error::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::str::FromStr;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnitDef {
    name: UnitName,
    artifact_path: String,
    #[serde(default = "default_true")]
    enable: bool,
    #[serde(default = "default_true")]
    restart: bool,
}

impl UnitDef {
    /// The validated constructor: enforces the SAME rules the conversion
    /// enforces — a single-filename unit name (`validate_unit_name`) and an
    /// artifact-relative path (`validate_relative_path`). Any violation is
    /// refused (fail closed) before a value of this type can exist. The
    /// serde `Deserialize` impl stays a RAW wire parse (a frozen record can
    /// carry an invalid unit; the [`Activation`] conversion refuses it at
    /// the record boundary).
    pub fn new(
        name: String,
        artifact_path: String,
        enable: bool,
        restart: bool,
    ) -> Result<UnitDef> {
        let name = UnitName::parse(&name)?;
        validate_relative_path(Path::new(&artifact_path)).map_err(|e| {
            Error::config(format!("systemd unit '{name}' artifact path invalid: {e}"))
        })?;
        Ok(UnitDef {
            name,
            artifact_path,
            enable,
            restart,
        })
    }

    /// The validated single-filename unit name.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// The unit IDENTITY — the validated name, the key of the typed unit
    /// set ([`ValidatedSystemd`]). systemd installs units by name, so the
    /// name is the identity: two units with the same name would silently
    /// overwrite each other, which the set makes unrepresentable.
    pub fn name_identity(&self) -> &UnitName {
        &self.name
    }

    /// The validated artifact-relative path of the unit file.
    pub fn artifact_path(&self) -> &str {
        &self.artifact_path
    }

    /// Whether the unit is enabled on activation.
    pub fn enable(&self) -> bool {
        self.enable
    }

    /// Whether the unit is restarted on activation.
    pub fn restart(&self) -> bool {
        self.restart
    }
}

/// The systemd unit IDENTITY: the unit NAME (a single-filename name such as
/// `example.service`). systemd installs units BY NAME into the systemd
/// directory, so the name is the identity — two units with the same name
/// would silently overwrite each other. The typed unit set
/// ([`ValidatedSystemd`]) is keyed by this identity, so a duplicate is
/// unrepresentable by construction.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct UnitName(String);

impl UnitName {
    /// Validate `s` as a single-filename unit name and construct a
    /// [`UnitName`]. This is the PRODUCTION constructor; the raw
    /// deserialization path stays raw and the [`Activation`] conversion
    /// re-validates it via [`UnitDef::new`] at the record boundary.
    pub fn parse(s: &str) -> Result<UnitName> {
        validate_unit_name(s)?;
        Ok(UnitName(s.to_string()))
    }

    /// The validated unit name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UnitName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for UnitName {
    type Err = Error;
    fn from_str(s: &str) -> Result<UnitName> {
        UnitName::parse(s)
    }
}

/// The raw wire deserialization stays RAW (a frozen record can carry an
/// invalid unit name; the [`Activation`] conversion re-validates it via
/// [`UnitDef::new`] at the record boundary — the same pattern as
/// [`crate::config::ReleaseName`]).
impl<'de> Deserialize<'de> for UnitName {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(UnitName(s))
    }
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
/// reconciled, and the unit definitions to install. The units are a TYPED
/// SET — a [`BTreeMap`] keyed by the unit IDENTITY ([`UnitName`], the
/// systemd name) — so two units with the same identity CANNOT coexist in
/// the type: a duplicate would silently overwrite when systemd installs
/// them, and the set makes that unrepresentable. The fields are PRIVATE:
/// a value can only be built through the validated
/// [`ValidatedSystemd::new`] constructor or the [`Activation`] conversions
/// (which validate every unit and refuse a duplicate identity), never
/// hand-built by production code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedSystemd {
    scope: ActivationScope,
    reconcile_managed_units: bool,
    units: BTreeMap<UnitName, UnitDef>,
}

impl ValidatedSystemd {
    /// The validated constructor: enforces the SAME rules the conversion
    /// enforces — at least one unit, each already validated by
    /// [`UnitDef::new`], and DISTINCT identities (the set is keyed by the
    /// unit name, so a duplicate identity is refused, never silently
    /// collapsed). Any violation is refused (fail closed) before a value of
    /// this type can exist.
    pub fn new(
        scope: ActivationScope,
        reconcile_managed_units: bool,
        units: Vec<UnitDef>,
    ) -> Result<ValidatedSystemd> {
        if units.is_empty() {
            return Err(Error::config(
                "systemd activation requires at least one unit",
            ));
        }
        let mut by_identity = BTreeMap::new();
        for u in units {
            let identity = u.name_identity().clone();
            if let Some(prev) = by_identity.insert(identity, u) {
                return Err(Error::config(format!(
                    "duplicate systemd unit identity '{}' — a unit name is the systemd identity, and two units with the same name would silently overwrite each other when systemd installs them",
                    prev.name()
                )));
            }
        }
        Ok(ValidatedSystemd {
            scope,
            reconcile_managed_units,
            units: by_identity,
        })
    }

    /// The unit scope (user or system).
    pub fn scope(&self) -> &ActivationScope {
        &self.scope
    }

    /// Whether managed units are reconciled on activation.
    pub fn reconcile_managed_units(&self) -> bool {
        self.reconcile_managed_units
    }

    /// The validated unit definitions (at least one), in DETERMINISTIC
    /// identity-sorted order (the [`BTreeMap`] key order).
    pub fn units(&self) -> impl Iterator<Item = &UnitDef> + '_ {
        self.units.values()
    }
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
                let mut units = Vec::with_capacity(wire.units.len());
                for u in &wire.units {
                    // The validated unit constructor enforces the SAME rules
                    // the conversion always enforced: a single-filename name
                    // and an artifact-relative path.
                    units.push(UnitDef::new(
                        u.name.as_str().to_string(),
                        u.artifact_path.clone(),
                        u.enable,
                        u.restart,
                    )?);
                }
                // `ValidatedSystemd::new` builds the TYPED SET keyed by the
                // unit identity: a wire config carrying two units with the
                // same name is REFUSED here (fail closed), never silently
                // collapsed.
                Ok(Activation::Systemd(ValidatedSystemd::new(
                    wire.scope.clone(),
                    wire.reconcile_managed_units,
                    units,
                )?))
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
                scope: sa.scope().clone(),
                reconcile_managed_units: sa.reconcile_managed_units(),
                units: sa.units().cloned().collect(),
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
