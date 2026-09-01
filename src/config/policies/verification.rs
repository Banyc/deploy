//! The verification contract: the raw serialized [`VerificationConfig`]
//! shape (what the TOML and the frozen behavior records carry) and the
//! CLOSED validated domain enum [`Verification`] whose only variant is
//! [`Command`](Verification::Command) holding a fully validated
//! [`ValidatedCommand`] payload.
//!
//! The closed enum is the ONLY consumer-facing form: an unsupported
//! verification adapter string can never become a [`Verification`] — the
//! conversion (`TryFrom<&VerificationConfig>`) and the serde `Deserialize`
//! impl both refuse it (fail closed), so a frozen record whose
//! `verification.adapter` is anything but `command` is rejected at the
//! record boundary instead of being silently ignored by the command
//! adapter.

use crate::error::{Error, Result};
use crate::identity::{Attempts, TimeoutSeconds};
use crate::remote::canonical::validate_template_variables;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationConfig {
    pub adapter: String,
    pub argv: Vec<String>,
    pub timeout_seconds: u64,
    #[serde(default = "default_attempts")]
    pub attempts: u32,
    #[serde(default = "default_interval")]
    pub interval_seconds: u64,
}

fn default_attempts() -> u32 {
    1
}
fn default_interval() -> u64 {
    0
}

/// The FULLY VALIDATED command-verification payload: a non-empty argv whose
/// template variables are all known (`validate_template_variables`), a
/// NONZERO timeout ([`TimeoutSeconds`]), and NONZERO attempts
/// ([`Attempts`]) — a zero attempt count or zero timeout could never
/// verify (the rules the conversion enforces). The fields are PRIVATE: a
/// value can only be built through the validated [`ValidatedCommand::new`]
/// constructor or the serde `Deserialize` impl (which routes through the
/// same validation), so an invalid payload (empty argv, zero timeout, zero
/// attempts, an unknown template variable) is unrepresentable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedCommand {
    argv: Vec<String>,
    timeout_seconds: TimeoutSeconds,
    attempts: Attempts,
    interval_seconds: u64,
}

impl ValidatedCommand {
    /// The validated constructor: enforces the SAME rules the conversion
    /// enforces — a non-empty argv whose template variables are all known
    /// (`validate_template_variables`), a NONZERO timeout, and NONZERO
    /// attempts. Any violation is refused (fail closed) before a value of
    /// this type can exist.
    pub fn new(
        argv: Vec<String>,
        timeout_seconds: u64,
        attempts: u32,
        interval_seconds: u64,
    ) -> Result<ValidatedCommand> {
        if argv.is_empty() {
            return Err(Error::config(
                "verification argv must not be empty (fail closed)",
            ));
        }
        for a in &argv {
            validate_template_variables(a)?;
        }
        Ok(ValidatedCommand {
            argv,
            timeout_seconds: TimeoutSeconds::new(timeout_seconds)?,
            attempts: Attempts::new(attempts)?,
            interval_seconds,
        })
    }

    /// The validated argv of the command verification.
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    /// The validated per-attempt timeout in seconds (nonzero).
    pub fn timeout_seconds(&self) -> TimeoutSeconds {
        self.timeout_seconds
    }

    /// The validated attempt count (nonzero).
    pub fn attempts(&self) -> Attempts {
        self.attempts
    }

    /// The validated sleep between attempts in seconds (0 = no sleep).
    pub fn interval_seconds(&self) -> u64 {
        self.interval_seconds
    }
}

/// A variant's verification policy as a CLOSED enum: exactly
/// [`Command`](Verification::Command) (there is no other supported
/// verification adapter). The raw `adapter` string is consumed by the
/// conversion, so any unsupported adapter name is refused BEFORE a value of
/// this type can exist — a record/config carrying `adapter = "..."` other
/// than `command` is never silently no-op'd.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verification {
    /// `adapter = "command"`: execute the validated argv directly, with the
    /// validated nonzero timeout/attempts.
    Command(ValidatedCommand),
}

impl Verification {
    /// The canonical wire form of this closed value (the serialized record
    /// contract, byte-stable with the raw shape): `adapter` is always
    /// `"command"`, argv/timeout/attempts/interval carried verbatim.
    pub fn to_config(&self) -> VerificationConfig {
        VerificationConfig::from(self)
    }

    /// The validated argv of the command verification.
    pub fn argv(&self) -> &[String] {
        match self {
            Verification::Command(vc) => vc.argv(),
        }
    }

    /// The validated per-attempt timeout in seconds (nonzero).
    pub fn timeout_seconds(&self) -> TimeoutSeconds {
        match self {
            Verification::Command(vc) => vc.timeout_seconds(),
        }
    }

    /// The validated attempt count (nonzero).
    pub fn attempts(&self) -> Attempts {
        match self {
            Verification::Command(vc) => vc.attempts(),
        }
    }

    /// The validated sleep between attempts in seconds (0 = no sleep).
    pub fn interval_seconds(&self) -> u64 {
        match self {
            Verification::Command(vc) => vc.interval_seconds(),
        }
    }
}

impl TryFrom<&VerificationConfig> for Verification {
    type Error = Error;

    fn try_from(wire: &VerificationConfig) -> Result<Verification> {
        if wire.adapter != "command" {
            return Err(Error::config(format!(
                "unsupported verification adapter '{}': only 'command' is supported (fail closed)",
                wire.adapter
            )));
        }
        // The validated constructor enforces the SAME rules the conversion
        // always enforced: non-empty argv, known template variables, nonzero
        // attempts, nonzero timeout.
        Ok(Verification::Command(ValidatedCommand::new(
            wire.argv.clone(),
            wire.timeout_seconds,
            wire.attempts,
            wire.interval_seconds,
        )?))
    }
}

impl From<&Verification> for VerificationConfig {
    /// The canonical serialized contract for a [`Verification`] — the ONLY
    /// path from the domain to the contract records, so the behavior digest
    /// is deterministic and byte-stable.
    fn from(v: &Verification) -> VerificationConfig {
        match v {
            Verification::Command(vc) => VerificationConfig {
                adapter: "command".to_string(),
                argv: vc.argv().to_vec(),
                timeout_seconds: vc.timeout_seconds().get(),
                attempts: vc.attempts().get(),
                interval_seconds: vc.interval_seconds(),
            },
        }
    }
}

impl Serialize for Verification {
    /// Serializes to the canonical wire bytes (identical to the raw
    /// [`VerificationConfig`] shape), so digests over the contract stay
    /// stable whether the record was built from the domain or round-tripped.
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        VerificationConfig::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Verification {
    /// The wire form is parsed through the closed enum: the raw shape
    /// (with `deny_unknown_fields`) is deserialized first, then the
    /// conversion rules run — an unsupported adapter, empty argv, zero
    /// attempts, zero timeout, an unknown template variable, or an
    /// irrelevant field is REFUSED at deserialization (fail closed).
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let wire = VerificationConfig::deserialize(deserializer)?;
        Verification::try_from(&wire).map_err(serde::de::Error::custom)
    }
}
