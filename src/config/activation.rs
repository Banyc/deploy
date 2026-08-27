//! Activation policy: the typed [`Activation`] enum (`None` | `Systemd`),
//! the systemd shape, and the raw serialized [`ActivationConfig`] contract.

use serde::{Deserialize, Serialize};

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
/// [`From<Activation>`] conversion always produces the canonical contract.
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
/// (a no-op), or a `systemd` activation carrying its scope, reconciliation,
/// and units. The raw `adapter` string is consumed by the conversion, so an
/// unknown adapter cannot exist in a domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Activation {
    /// `adapter = "none"`: no activation step runs.
    None,
    /// `adapter = "systemd"`: activate via systemd with the given scope and
    /// units. The conversion requires at least one unit.
    Systemd(SystemdActivation),
}

/// The systemd activation policy: the unit scope, whether managed units are
/// reconciled, and the unit definitions to install.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemdActivation {
    pub scope: ActivationScope,
    pub reconcile_managed_units: bool,
    pub units: Vec<UnitDef>,
}

impl From<Activation> for ActivationConfig {
    /// The canonical serialized contract for an [`Activation`]: `None`
    /// becomes the default "none" contract (scope/units of a none-variant are
    /// not part of the domain), `Systemd` becomes the systemd contract. This
    /// is the ONLY path from the domain to the contract records, so the
    /// behavior digest is deterministic.
    fn from(a: Activation) -> ActivationConfig {
        match a {
            Activation::None => ActivationConfig {
                adapter: "none".to_string(),
                scope: ActivationScope::default(),
                reconcile_managed_units: true,
                units: Vec::new(),
            },
            Activation::Systemd(sa) => ActivationConfig {
                adapter: "systemd".to_string(),
                scope: sa.scope,
                reconcile_managed_units: sa.reconcile_managed_units,
                units: sa.units,
            },
        }
    }
}
