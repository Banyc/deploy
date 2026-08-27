//! Per-target rollout policy: the DOMAIN [`RolloutConfig`] (non-zero
//! [`crate::scalar::BatchSize`], stop-on-failure, the strict
//! [`FailurePolicy`] enum) and the strict exact-spelling [`FailurePolicy`]
//! parse the raw `failure_policy` string goes through.

use crate::error::{Error, Result};
use crate::scalar::BatchSize;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// A target's batch-failure policy: what happens to the servers whose batches
/// already ADVANCED when a LATER batch fails. STRICT typed enum replacing the
/// old loose `String` field: an unknown `failure_policy` spelling used to
/// silently behave as "leave changed" (fail-open — an operator typo kept the
/// changed servers in their new state instead of rolling back). The raw
/// string is consumed by the STRICT parse below during the merged raw ->
/// domain conversion (the config layers are merged, so the typed parse runs
/// when the manifest is deserialized), and ANY unsupported spelling is
/// rejected with a config error naming the valid options. The default stays
/// [`FailurePolicy::RollbackChanged`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum FailurePolicy {
    /// `failure_policy = "rollback_changed"`: when a later batch fails, every
    /// server whose batch already advanced is COMPENSATED back to its
    /// pre-push generation (compare-and-swap). The attempt ends
    /// `failed_rolled_back` when every advanced server is compensated, else
    /// `degraded`. The default.
    #[default]
    RollbackChanged,
    /// `failure_policy = "leave_changed"`: a later batch failing RETAINS the
    /// already-advanced servers deliberately — no compensation pass runs and
    /// the attempt ends `degraded` with the mixed per-server state retained.
    LeaveChanged,
}

impl FailurePolicy {
    /// The exact supported config spellings, in documentation order (also the
    /// error message's "valid options" list).
    pub const SPELLINGS: [&'static str; 2] = ["rollback_changed", "leave_changed"];

    /// The canonical config spelling of this policy.
    pub fn as_str(&self) -> &'static str {
        match self {
            FailurePolicy::RollbackChanged => "rollback_changed",
            FailurePolicy::LeaveChanged => "leave_changed",
        }
    }
}

impl fmt::Display for FailurePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FailurePolicy {
    type Err = Error;

    /// STRICT EXACT parse — the conversion's ONLY entry from the raw
    /// `failure_policy` string. The two supported spellings
    /// ([`FailurePolicy::SPELLINGS`], matching the existing docs) parse;
    /// EVERYTHING else — case variants, whitespace, dashes, typos, the empty
    /// string — is REJECTED with a config error naming the valid options, so
    /// an unsupported spelling can never silently mean "leave changed".
    fn from_str(s: &str) -> Result<FailurePolicy> {
        match s {
            "rollback_changed" => Ok(FailurePolicy::RollbackChanged),
            "leave_changed" => Ok(FailurePolicy::LeaveChanged),
            other => Err(Error::config(format!(
                "unsupported failure_policy '{other}' (valid: {})",
                FailurePolicy::SPELLINGS.join(", ")
            ))),
        }
    }
}

impl Serialize for FailurePolicy {
    /// The canonical spelling is the serialized form (`failure_policy =
    /// "rollback_changed"`), so a scaffolded/round-tripped config carries
    /// exactly what the strict parse accepts.
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for FailurePolicy {
    /// Deserialization IS the raw -> domain parse (the layers are merged: a
    /// `RolloutConfig` is both the raw serde shape and the domain record, so
    /// the string is consumed exactly here). Delegates to the strict
    /// [`FailurePolicy::from_str`] so unsupported spellings fail closed with
    /// the same config error naming the valid options.
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FailurePolicyVisitor;
        impl<'d> serde::de::Visitor<'d> for FailurePolicyVisitor {
            type Value = FailurePolicy;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    f,
                    "a failure_policy string (valid: {})",
                    FailurePolicy::SPELLINGS.join(", ")
                )
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<FailurePolicy, E>
            where
                E: serde::de::Error,
            {
                v.parse::<FailurePolicy>().map_err(E::custom)
            }
        }
        deserializer.deserialize_str(FailurePolicyVisitor)
    }
}

/// The DOMAIN rollout policy of one target. Built ONLY by the raw -> domain
/// conversion: `batch_size` is a validated NONZERO [`BatchSize`] (the raw
/// integer is parsed by the conversion, which rejects zero), `failure_policy`
/// is the closed typed enum. The raw serialization shape is
/// [`raw::RawRolloutConfig`] (bare integer batch size); this domain type is
/// never deserialized from the file directly.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RolloutConfig {
    /// How many slots a rollout advances per batch. NONZERO by construction:
    /// a zero batch would stall the rollout without ever progressing.
    pub batch_size: BatchSize,
    pub stop_on_failure: bool,
    /// The batch-failure policy as the TYPED [`FailurePolicy`] enum (never a
    /// loose string): the raw `failure_policy` spelling is parsed strictly
    /// during deserialization, so an unsupported spelling fails the config
    /// load instead of silently behaving as "leave changed".
    pub failure_policy: FailurePolicy,
}

pub(crate) fn default_failure_policy() -> FailurePolicy {
    FailurePolicy::RollbackChanged
}
