//! Retention policies: the slot's ONE [`RetentionConfig`] (per-server
//! distinct-artifact/age/protection window plus the deployment snapshot
//! window) and its defaults.

use crate::config::activation::default_true;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct PerServerRetention {
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
#[serde(deny_unknown_fields)]
pub struct DeploymentRetention {
    #[serde(default)]
    pub protect_deployments: u32,
}

/// The slot's ONE retention policy: `per_server` (distinct-artifact count,
/// age window, previous protection) plus the `deployment` snapshot window.
/// OWNED BY THE SLOT — declared inside the variant file that declares the
/// slot (the slot's owning variant), so a slot has exactly one policy no
/// matter how many targets it is a member of, and membership changes never
/// change retention.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfig {
    #[serde(default)]
    pub per_server: PerServerRetention,
    #[serde(default)]
    pub deployment: DeploymentRetention,
}
