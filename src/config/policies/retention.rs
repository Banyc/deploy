//! Retention policies: the slot's ONE [`RetentionConfig`] (per-server
//! distinct-artifact/age/protection window plus the deployment snapshot
//! window) and its defaults.

use crate::config::activation::default_true;
use crate::identity::KeepDays;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PerServerRetention {
    #[serde(default = "default_keep_distinct")]
    pub keep_distinct_artifacts: u32,
    #[serde(default = "default_keep_days")]
    pub keep_days: KeepDays,
    #[serde(default = "default_true")]
    pub protect_previous: bool,
}

fn default_keep_distinct() -> u32 {
    5
}
fn default_keep_days() -> KeepDays {
    KeepDays::default()
}

/// The default per-server retention — the value the blanket `Default`
/// derive used to fabricate (zero distinct-artifact count, the explicit
/// [`KeepDays`] default window, no previous protection). Named explicitly
/// so a missing `per_server` table keeps the exact same wire value.
pub(crate) fn default_per_server() -> PerServerRetention {
    PerServerRetention {
        keep_distinct_artifacts: 0,
        keep_days: KeepDays::default(),
        protect_previous: false,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentRetention {
    #[serde(default = "default_protect_deployments")]
    pub protect_deployments: u32,
}

/// The default deployment-snapshot protection count — zero (the value the
/// blanket `Default` derive used to fabricate). Named explicitly so a
/// missing field keeps the exact same wire value.
pub(crate) fn default_protect_deployments() -> u32 {
    0
}

/// The default deployment retention — the value the blanket `Default`
/// derive used to fabricate (no protected snapshots). Named explicitly so
/// a missing `deployment` table keeps the exact same wire value.
pub(crate) fn default_deployment() -> DeploymentRetention {
    DeploymentRetention {
        protect_deployments: default_protect_deployments(),
    }
}

/// The slot's ONE retention policy: `per_server` (distinct-artifact count,
/// age window, previous protection) plus the `deployment` snapshot window.
/// OWNED BY THE SLOT — declared inside the variant file that declares the
/// slot (the slot's owning variant), so a slot has exactly one policy no
/// matter how many targets it is a member of, and membership changes never
/// change retention.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfig {
    #[serde(default = "default_per_server")]
    pub per_server: PerServerRetention,
    #[serde(default = "default_deployment")]
    pub deployment: DeploymentRetention,
}

impl RetentionConfig {
    /// The empty retention policy — the value the blanket `Default` derive
    /// used to fabricate (the default per-server window, no protection).
    /// Constructed explicitly so an undeclared policy is a DELIBERATE
    /// choice.
    pub(crate) fn empty() -> Self {
        RetentionConfig {
            per_server: default_per_server(),
            deployment: default_deployment(),
        }
    }
}

/// The default retention policy — the value the blanket `Default` derive
/// used to fabricate. Named explicitly so a missing `[retention]` table
/// keeps the exact same wire value.
pub(crate) fn default_retention() -> RetentionConfig {
    RetentionConfig::empty()
}
