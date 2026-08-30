//! The TERMINAL records of the deployment ledger (feature area A2 "two line
//! kinds — terminal"): the terminal WIRE shape ([`LedgerTerminalWire`]) and
//! the DOMAIN terminal (owned by the semantic kernel,
//! [`crate::kernel::terminal`]).
//!
//! Schema v11: a successful terminal is PAYLOAD-FREE — it only says "the
//! intent's planned result was achieved" — and binds itself to its intent
//! by `intent_digest` (the sha256 of the intent's canonical wire bytes, a
//! validated scalar). The old duplicates are GONE: no rollback payload, no
//! outcomes object on success (the failed dispositions carry their outcome
//! ROW ARRAY), no `target` member — the ENCLOSING ENTRY owns target, so the
//! wire no longer duplicates the entry's identity and the reader's
//! target-equality check went away with it. The failed dispositions' per-slot
//! outcomes are the STRUCTURAL v11 rows ([`SlotOutcomeRowWire`] — each row
//! owns its slot id + its execution-state body).

use crate::error::{Error, Result};
use crate::identity::DeploymentId;
use crate::kernel;
use crate::kernel::terminal::{
    DegradedTerminal, FailedRolledBackTerminal, LedgerTerminal, NonSuccessfulDisposition,
};
use crate::ledger::records::{
    DeploymentStatus, NonEmptySlotTable, SlotOutcome, SlotOutcomeRowWire, SlotTable,
};
use serde::{Deserialize, Serialize};

/// The WIRE shape of a terminal event — the RAW serde form the ledger's
/// JSONL carries: the `status` tag + the per-slot `outcomes` ROW ARRAY
/// only. A SUCCESSFUL terminal carries NO outcomes and NO rollback — its
/// `intent_digest` binds it to the exact canonical intent whose planned
/// result was achieved (the resulting snapshot resolves from the intent,
/// never from the terminal). The failed dispositions own their outcome
/// tables. `deployment_id` is the wire's keying member (the ENTRY owns
/// identity in the domain; the reader verifies it equals the enclosing
/// entry's). The redundant `target` member is GONE: the enclosing entry
/// owns target. `deny_unknown_fields`: a line with stray/unknown members
/// is refused on deserialization, never silently accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerTerminalWire {
    pub deployment_id: DeploymentId,
    pub status: DeploymentStatus,
    pub recorded_at: String,
    /// THE INTENT DIGEST — the sha256 of the intent's canonical wire bytes
    /// ([`crate::kernel::terminal::intent_digest`]). REQUIRED (no serde
    /// default — an old-shape terminal line fails deserialization fail
    /// closed). The store enforces `terminal.intent_digest ==
    /// digest(entry.intent)` before every append and on every read.
    pub intent_digest: String,
    /// Per-slot outcomes IN DEPLOYMENT ORDER (a ROW ARRAY — each row
    /// [`SlotOutcomeRowWire`] OWNS its slot id; the row order preserves the
    /// domain's insertion order, never sorted by id). `Successful` /
    /// `FailedPreflight` carry NONE; the failed dispositions carry their
    /// own outcome table. REQUIRED DUPLICATE-FREE: the wire → domain
    /// conversion refuses a duplicate slot row explicitly (never last-wins).
    #[serde(default)]
    pub outcomes: Vec<SlotOutcomeRowWire>,
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
    /// the kernel's digest-enforcing constructor. The outcome ROW ARRAY is
    /// folded in FILE ORDER (order-preserving) into the ordered domain
    /// table, REFUSING a duplicate slot row with an integrity error naming
    /// it (ambiguous JSON is never last-wins). The CROSS-RECORD
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
        // THE OUTCOME ROW-ARRAY FOLD (order-preserving +
        // duplicate-rejecting): each row OWNS its slot id (there is no map
        // key to agree with — the redundant-key agreement is structural
        // now); rows fold in FILE ORDER into the ordered domain table
        // (insert APPENDS at the end) and a duplicate slot id is REFUSED
        // with an integrity-class error naming it.
        let mut seen = std::collections::BTreeSet::new();
        let mut outcomes: SlotTable<SlotOutcome> = SlotTable::new();
        for row in self.outcomes {
            if !seen.insert(row.slot_id.clone()) {
                return Err(Error::integrity(format!(
                    "terminal {}: duplicate outcome for slot '{}' in the wire rows — the outcome table must be duplicate-free (the wire never last-wins ambiguous JSON)",
                    self.deployment_id, row.slot_id
                )));
            }
            let slot_id = row.slot_id.clone();
            outcomes.insert(slot_id, SlotOutcome::from_wire(row)?);
        }
        // STATUS → DISPOSITION: each status maps to exactly one disposition,
        // and a status whose payload does not match its disposition is a
        // conversion error (fail closed). The READ PATH constructs the
        // domain terminal DIRECTLY: a `Successful` terminal is a PERSISTED
        // FACT (it was only ever written with the sealed
        // [`crate::kernel::terminal::VerifiedExecution`] proof) — the
        // internal read-path constructor re-reads it; the non-Successful
        // dispositions go through [`LedgerTerminal::new`] (whose type
        // excludes `Successful` by construction).
        let terminal = match (&self.status, outcomes.is_empty()) {
            (DeploymentStatus::Successful, true) => {
                LedgerTerminal::successful_unchecked(recorded_at, intent_digest, self.reason)
            }
            (DeploymentStatus::Successful, false) => {
                return Err(Error::integrity(format!(
                    "terminal {}: status Successful must carry NO outcomes — the terminal only says the intent's planned result was achieved (the per-slot facts resolve from the intent)",
                    self.deployment_id
                )));
            }
            (DeploymentStatus::FailedPreflight, true) => LedgerTerminal::new(
                recorded_at,
                intent_digest,
                NonSuccessfulDisposition::FailedPreflight,
                self.reason,
            ),
            (DeploymentStatus::FailedPreflight, false) => {
                return Err(Error::integrity(format!(
                    "terminal {}: status FailedPreflight must carry NO outcomes (a pre-mutation failure touched no slot)",
                    self.deployment_id
                )));
            }
            (DeploymentStatus::FailedRolledBack, _) => {
                // The reader has NO intent at deserialization time, so the
                // intent-dependent delta validation (every slot's
                // [`crate::kernel::terminal::SlotDelta`] `Unchanged`) is
                // enforced by the cross-record terminal agreement
                // ([`crate::kernel::transition::validate_terminal_vs_intent`])
                // where the entry's intent exists — on the read fold AND the
                // append path — never by a second rule here. The unchecked
                // constructor carries the wire rows over.
                let payload = FailedRolledBackTerminal::new_unchecked(outcomes);
                LedgerTerminal::new(
                    recorded_at,
                    intent_digest,
                    NonSuccessfulDisposition::FailedRolledBack(payload),
                    self.reason,
                )
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
                // See the FailedRolledBack arm: the intent-dependent
                // delta validation (at least one
                // `Desired`/`Diverged`/`Unknown` delta) is enforced by
                // [`crate::kernel::transition::validate_terminal_vs_intent`].
                let payload = DegradedTerminal::new_unchecked(non_empty);
                LedgerTerminal::new(
                    recorded_at,
                    intent_digest,
                    NonSuccessfulDisposition::Degraded(payload),
                    self.reason,
                )
            }
        };
        Ok(terminal)
    }

    /// Build the WIRE form of a domain terminal for a given deployment
    /// identity — the ENCLOSING ENTRY owns the identity, so the wire's
    /// `deployment_id` comes from the CALLER (the append path); the
    /// redundant `target` member is GONE. The domain is already validated
    /// by construction, so this is infallible. The outcome rows are emitted
    /// in the DOMAIN's insertion order (`outcomes().iter()` — deployment
    /// order, never sorted by id), each row owning its slot id.
    pub fn to_wire(deployment_id: &DeploymentId, t: &LedgerTerminal) -> Self {
        let outcomes: Vec<SlotOutcomeRowWire> = t
            .outcomes()
            .iter()
            .map(|(k, o)| SlotOutcomeRowWire::from_outcome(k, o))
            .collect();
        LedgerTerminalWire {
            deployment_id: deployment_id.clone(),
            status: t.status(),
            recorded_at: t.recorded_at().to_string(),
            intent_digest: t.intent_digest().as_str().to_string(),
            outcomes,
            reason: t.reason().map(str::to_string),
        }
    }
}
