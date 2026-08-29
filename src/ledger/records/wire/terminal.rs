//! The TERMINAL records of the deployment ledger (feature area A2 "two line
//! kinds — terminal"): the terminal WIRE shape ([`LedgerTerminalWire`]) and
//! the DOMAIN terminal (owned by the semantic kernel,
//! [`crate::kernel::terminal`]).
//!
//! Schema v9: a successful terminal is PAYLOAD-FREE — it only says "the
//! intent's planned result was achieved" — and binds itself to its intent
//! by `intent_digest` (the sha256 of the intent's canonical wire bytes, a
//! validated scalar). The old duplicates are GONE: no rollback payload, no
//! outcomes map on success, no `selected_membership`/`full_membership`.

use crate::error::{Error, Result};
use crate::identity::{DeploymentId, SlotId, TargetName};
use crate::kernel;
use crate::kernel::terminal::{DegradedTerminal, FailedRolledBackTerminal, LedgerTerminal};
use crate::ledger::records::{
    DeploymentStatus, NonEmptySlotTable, SlotOutcome, SlotResult, SlotTable,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The WIRE shape of a terminal event — the RAW serde form the ledger's
/// JSONL carries: the `status` tag + the per-slot `outcomes` payload only.
/// A SUCCESSFUL terminal carries NO outcomes and NO rollback — its
/// `intent_digest` binds it to the exact canonical intent whose planned
/// result was achieved (the resulting snapshot resolves from the intent,
/// never from the terminal). The failed dispositions own their outcome
/// tables. `deployment_id`/`target` are the wire's keying members (the
/// ENTRY owns identity in the domain; the reader verifies them equal to the
/// enclosing entry's).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerTerminalWire {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    pub status: DeploymentStatus,
    pub recorded_at: String,
    /// The INTENT DIGEST — the sha256 of the intent's canonical wire bytes
    /// ([`crate::kernel::terminal::intent_digest`]). REQUIRED (no serde
    /// default — an old-shape terminal line fails deserialization fail
    /// closed). The store enforces `terminal.intent_digest ==
    /// digest(entry.intent)` before every append and on every read.
    pub intent_digest: String,
    /// Per-slot outcomes. `Successful` / `FailedPreflight` carry NONE; the
    /// failed dispositions carry their own outcome table.
    #[serde(default)]
    pub outcomes: BTreeMap<SlotId, SlotResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl LedgerTerminalWire {
    /// VERIFYING CONVERSION (wire → domain): scalar-gate the recorded
    /// timestamp + the intent digest, map `status` to exactly one
    /// disposition whose payload matches (a `Successful` terminal carries
    /// NO outcomes; a `FailedPreflight` carries NO outcomes; the failed
    /// dispositions validate their outcome payloads through the kernel's
    /// validated constructors), and construct the domain terminal through
    /// the kernel's digest-enforcing constructor. The CROSS-RECORD
    /// `intent_digest` equality + the outcome-coverage agreement with the
    /// entry's intent are enforced by the ledger event state machine
    /// ([`crate::kernel::transition::apply_event`]) where the terminal
    /// merges into its entry.
    pub fn into_domain(self) -> Result<LedgerTerminal> {
        let recorded_at = crate::identity::Timestamp::parse(&self.recorded_at).map_err(|_| {
            Error::integrity(format!(
                "terminal {}: recorded_at {:?} is not an RFC 3339 timestamp",
                self.deployment_id, self.recorded_at
            ))
        })?;
        let intent_digest =
            kernel::terminal::IntentDigest::parse(&self.intent_digest).map_err(|e| {
                Error::integrity(format!(
                    "terminal {}: intent_digest {:?} is not a valid sha256 digest ({})",
                    self.deployment_id, self.intent_digest, e
                ))
            })?;
        // OUTCOME OWN-KEY AGREEMENT: each wire outcome's value names ITS OWN
        // map key (the domain value carries no slot).
        for (key, result) in &self.outcomes {
            if &result.slot_id != key {
                return Err(Error::integrity(format!(
                    "terminal {}: outcome for slot '{key}' names placement '{}'",
                    self.deployment_id, result.slot_id
                )));
            }
        }
        let outcomes: SlotTable<SlotOutcome> = SlotTable::from_map(
            self.outcomes
                .into_iter()
                .map(|(key, result)| Ok((key, SlotOutcome::from_wire(result)?)))
                .collect::<Result<BTreeMap<SlotId, SlotOutcome>>>()?,
        );
        // STATUS → DISPOSITION: each status maps to exactly one disposition,
        // and a status whose payload does not match its disposition is a
        // conversion error (fail closed).
        let disposition = match (&self.status, outcomes.is_empty()) {
            (DeploymentStatus::Successful, true) => {
                kernel::terminal::TerminalDisposition::Successful
            }
            (DeploymentStatus::Successful, false) => {
                return Err(Error::integrity(format!(
                    "terminal {}: status Successful must carry NO outcomes — the terminal only says the intent's planned result was achieved (the per-slot facts resolve from the intent)",
                    self.deployment_id
                )));
            }
            (DeploymentStatus::FailedPreflight, true) => {
                kernel::terminal::TerminalDisposition::FailedPreflight
            }
            (DeploymentStatus::FailedPreflight, false) => {
                return Err(Error::integrity(format!(
                    "terminal {}: status FailedPreflight must carry NO outcomes (a pre-mutation failure touched no slot)",
                    self.deployment_id
                )));
            }
            (DeploymentStatus::FailedRolledBack, _) => {
                let payload = FailedRolledBackTerminal::try_new(outcomes).map_err(|e| {
                    Error::integrity(format!(
                        "terminal {}: status FailedRolledBack refuses its outcome payload: {e}",
                        self.deployment_id
                    ))
                })?;
                kernel::terminal::TerminalDisposition::FailedRolledBack(payload)
            }
            (DeploymentStatus::Degraded, _) => {
                let non_empty =
                    NonEmptySlotTable::build(outcomes.iter().map(|(k, v)| (k.clone(), v.clone())))
                        .map_err(|e| {
                            Error::integrity(format!(
                                "terminal {}: status Degraded requires at least one outcome: {e}",
                                self.deployment_id
                            ))
                        })?;
                let payload = DegradedTerminal::try_new(non_empty).map_err(|e| {
                    Error::integrity(format!(
                        "terminal {}: status Degraded refuses its outcome payload: {e}",
                        self.deployment_id
                    ))
                })?;
                kernel::terminal::TerminalDisposition::Degraded(payload)
            }
        };
        kernel::terminal::terminal_with_digest(recorded_at, intent_digest, disposition, self.reason)
            .map_err(|e| Error::integrity(format!("terminal wire refused: {e}")))
    }

    /// Build the WIRE form of a domain terminal for a given (deployment,
    /// target) identity — the enclosing entry owns the identity, so the
    /// wire's `deployment_id`/`target` come from the CALLER (the append
    /// path), never from the domain terminal. The domain is already
    /// validated by construction, so this is infallible.
    pub fn to_wire(deployment_id: &DeploymentId, target: &TargetName, t: &LedgerTerminal) -> Self {
        let outcomes: BTreeMap<SlotId, SlotResult> = t
            .outcomes()
            .iter()
            .map(|(k, o)| (k.clone(), SlotResult::from_outcome(k, o)))
            .collect();
        LedgerTerminalWire {
            deployment_id: deployment_id.clone(),
            target: target.clone(),
            status: t.status(),
            recorded_at: t.recorded_at().to_string(),
            intent_digest: t.intent_digest().as_str().to_string(),
            outcomes,
            reason: t.reason().map(str::to_string),
        }
    }
}
