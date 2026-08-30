//! THE TERMINAL FACET of the semantic kernel (feature area: the pure
//! deployment semantic kernel) — the terminal event domain with
//! STRUCTURAL dispositions and the `intent_digest` binding.
//!
//! # Stop storing rollback state in successful terminals
//!
//! The successful disposition is PAYLOAD-FREE: the terminal only says "the
//! intent's planned result was achieved". A successful deployment's rollback
//! state IS `entry.intent.resulting_snapshot()`
//! ([`crate::kernel::snapshot::resolve_snapshot`]) — never a second stored
//! copy. The [`LedgerTerminal::intent_digest`] (a validated scalar: the
//! sha256 of the intent's canonical wire bytes) binds the terminal to the
//! EXACT canonical intent without duplicating every snapshot field; the
//! store enforces `terminal.intent_digest == digest(entry.intent)`.
//!
//! # Terminal states are structural (private validated payloads)
//!
//! * Successful — selected slots were verified at their planned result (no
//!   payload);
//! * FailedPreflight — no mutation outcomes;
//! * FailedRolledBack ([`FailedRolledBackTerminal`]) — every attempted
//!   mutation is restored or never advanced;
//! * Degraded ([`DegradedTerminal`]) — nonempty outcomes with at least one
//!   non-restored/unknown result.

use crate::identity::Timestamp;
use crate::kernel::error::{ConflictError, IntegrityError, KernelError, KernelResult};
use crate::kernel::intent::DeploymentIntent;
use crate::ledger::NonEmptySlotTable;
use crate::ledger::records::{Observation, SlotOutcome, SlotTable};

/// THE COMPENSATION REPORT / outcome payload of a fully-rolled-back
/// deployment: every attempted mutation is restored or never advanced. The
/// constructor is the ONE validator of that fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailedRolledBackTerminal {
    outcomes: SlotTable<SlotOutcome>,
}

impl FailedRolledBackTerminal {
    /// VALIDATE "every attempted mutation restored or never advanced": no
    /// outcome may show a slot PROVABLY ON the new state (a DERIVED
    /// `Advanced` transition — [`SlotOutcome::transition`] — a slot still
    /// on the deployed generation is never a rolled-back slot). A pre-swap
    /// failure (an uncompensated failure — the attempt never advanced the
    /// slot) and a restored slot are both legitimate members of a rolled-
    /// back terminal.
    pub fn try_new(outcomes: SlotTable<SlotOutcome>) -> KernelResult<Self> {
        for (slot, o) in outcomes.iter() {
            if o.transition() == crate::ledger::records::SlotTransition::Advanced {
                return Err(KernelError::Integrity(IntegrityError::Message(format!(
                    "a FailedRolledBack terminal cannot carry slot '{slot}' with an Advanced outcome — every attempted mutation must be restored or never advanced"
                ))));
            }
        }
        Ok(Self { outcomes })
    }
    pub fn outcomes(&self) -> &SlotTable<SlotOutcome> {
        &self.outcomes
    }
}

/// THE outcome payload of a DEGRADED deployment: nonempty outcomes with at
/// least one non-restored/unknown result. The constructor is the ONE
/// validator of that fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DegradedTerminal {
    outcomes: NonEmptySlotTable<SlotOutcome>,
}

impl DegradedTerminal {
    /// VALIDATE "nonempty, at least one non-restored/unknown result": the
    /// table is non-empty by TYPE, and at least one outcome is NOT a clean
    /// restoration — an outcome variant other than
    /// [`SlotOutcome::Restored`] (a slot still changed or with an unknown
    /// advance outcome), or an `Unknown` observation (a failed post-mutation
    /// read is uncertain, so it is always a remaining change). An
    /// all-restored outcome set is a `FailedRolledBack`, never a
    /// `Degraded`.
    pub fn try_new(outcomes: NonEmptySlotTable<SlotOutcome>) -> KernelResult<Self> {
        let has_remaining = outcomes.iter().any(|(_, o)| {
            !matches!(o, crate::ledger::records::SlotOutcome::Restored { .. })
                || matches!(o.observation(), Observation::Unknown(_))
        });
        if !has_remaining {
            return Err(KernelError::Integrity(IntegrityError::Message(
                "a Degraded terminal requires at least one non-restored/unknown result — an all-restored attempt is FailedRolledBack, never Degraded"
                    .to_string(),
            )));
        }
        Ok(Self { outcomes })
    }
    pub fn outcomes(&self) -> &NonEmptySlotTable<SlotOutcome> {
        &self.outcomes
    }
}

/// THE DISPOSITION of a deployment's terminal event — an enum whose variants
/// carry EXACTLY the payload their disposition allows, so the
/// status/rollback TRUTH TABLE is STRUCTURAL (unrepresentable-invalid
/// combinations do not exist). The validated payloads are constructed ONLY
/// through [`FailedRolledBackTerminal::try_new`] /
/// [`DegradedTerminal::try_new`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalDisposition {
    /// The deployment succeeded: the selected slots were verified at their
    /// planned result. PAYLOAD-FREE — the terminal only says "the intent's
    /// planned result was achieved"; the resulting snapshot resolves from
    /// the intent (`resolve_snapshot`).
    Successful,
    /// The attempt failed before any slot mutation: no payload, no
    /// outcomes.
    FailedPreflight,
    /// The attempt failed after mutating slots and every attempted mutation
    /// was restored or never advanced: the disposition's OWN per-slot
    /// outcomes — the compensation report.
    FailedRolledBack(FailedRolledBackTerminal),
    /// The attempt ended degraded: at least one slot remains changed or
    /// unknown. The disposition's OWN per-slot outcomes — the remaining
    /// changes are derived from it.
    Degraded(DegradedTerminal),
}

impl TerminalDisposition {
    /// The disposition's STATUS — the inverse of the wire's status →
    /// disposition mapping; the two are never stored side by side.
    pub fn status(&self) -> crate::ledger::records::DeploymentStatus {
        match self {
            TerminalDisposition::Successful => crate::ledger::records::DeploymentStatus::Successful,
            TerminalDisposition::FailedPreflight => {
                crate::ledger::records::DeploymentStatus::FailedPreflight
            }
            TerminalDisposition::FailedRolledBack(_) => {
                crate::ledger::records::DeploymentStatus::FailedRolledBack
            }
            TerminalDisposition::Degraded(_) => crate::ledger::records::DeploymentStatus::Degraded,
        }
    }
    pub fn is_successful(&self) -> bool {
        matches!(self, TerminalDisposition::Successful)
    }
    /// The disposition's OWN outcome table: `Successful` and
    /// `FailedPreflight` carry none (the empty table).
    pub fn outcomes(&self) -> SlotTable<SlotOutcome> {
        match self {
            TerminalDisposition::Successful | TerminalDisposition::FailedPreflight => {
                SlotTable::new()
            }
            TerminalDisposition::FailedRolledBack(fr) => fr.outcomes().clone(),
            TerminalDisposition::Degraded(d) => {
                SlotTable::from_map(d.outcomes().clone().into_map())
            }
        }
    }
}

/// An INTENT DIGEST: the validated scalar that binds a terminal event to
/// the EXACT canonical intent — the sha256 of the intent's canonical wire
/// bytes. Validated on every read (`terminal.intent_digest ==
/// digest(entry.intent)`); only [`intent_digest`] constructs it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IntentDigest(String);

impl IntentDigest {
    pub fn parse(s: &str) -> KernelResult<IntentDigest> {
        let ok = s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !ok {
            return Err(KernelError::input(format!(
                "invalid intent digest {s:?}: expected 64 lowercase hex characters"
            )));
        }
        Ok(IntentDigest(s.to_string()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for IntentDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// THE CANONICAL INTENT DIGEST: the sha256 of the intent's canonical wire
/// bytes. This is the ONE definition of the digest — the store enforces
/// `terminal.intent_digest == intent_digest(entry.intent)` on every read
/// and before every terminal append.
pub fn intent_digest(intent: &DeploymentIntent) -> IntentDigest {
    let bytes = intent.canonical_wire_bytes();
    let digest = crate::digest::sha256_bytes(&bytes);
    IntentDigest(digest)
}

/// THE TERMINAL EVENT of one deployment — the VALIDATED DOMAIN form. The
/// terminal binds itself to its intent via `intent_digest` (a validated
/// scalar) and carries its structural disposition. Appended ONCE after the
/// mutation loop; an intent WITHOUT a terminal IS the pending state (the
/// terminal status enum carries no in-progress/pending-commit statuses).
/// `reason` is optional human context — a free-form NOTE, not a fact: it
/// never participates in any invariant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerTerminal {
    recorded_at: Timestamp,
    intent_digest: IntentDigest,
    disposition: TerminalDisposition,
    reason: Option<String>,
}

impl LedgerTerminal {
    pub fn new(
        recorded_at: Timestamp,
        intent_digest: IntentDigest,
        disposition: TerminalDisposition,
        reason: Option<String>,
    ) -> Self {
        Self {
            recorded_at,
            intent_digest,
            disposition,
            reason,
        }
    }
    pub fn recorded_at(&self) -> &Timestamp {
        &self.recorded_at
    }
    pub fn intent_digest(&self) -> &IntentDigest {
        &self.intent_digest
    }
    pub fn disposition(&self) -> &TerminalDisposition {
        &self.disposition
    }
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// The terminal's status, DERIVED from its disposition (never stored
    /// separately).
    pub fn status(&self) -> crate::ledger::records::DeploymentStatus {
        self.disposition.status()
    }

    /// The terminal's per-slot outcomes — the disposition's OWN table
    /// (Successful/FailedPreflight carry none → empty).
    pub fn outcomes(&self) -> SlotTable<SlotOutcome> {
        self.disposition.outcomes()
    }

    /// THE COMPENSATION REPORT of a rolled-back terminal: the disposition's
    /// OWN outcome table.
    pub fn compensation(&self) -> Option<&SlotTable<SlotOutcome>> {
        match &self.disposition {
            TerminalDisposition::FailedRolledBack(fr) => Some(fr.outcomes()),
            _ => None,
        }
    }

    /// THE REMAINING CHANGES of a [`TerminalDisposition::Degraded`]
    /// terminal — DERIVED from the disposition's OWN per-slot outcomes (the
    /// slots whose FINAL OBSERVED STATE differs from their pre-push state,
    /// each mapped to its THREE-STATE OBSERVATION), never stored. `None` for
    /// any non-Degraded disposition.
    ///
    /// THE DERIVATION IS THE TRANSITION STATE, NOT THE OUTCOME'S GENERATION
    /// FIELD: each slot's [`SlotTransition`] classifies it — a
    /// `NeverAdvanced` slot (skipped) and a `Restored` slot (compensated
    /// back) are back at their pre-push state (never remaining changes); an
    /// `Advanced` slot is at the desired state (always a remaining change);
    /// an `AdvanceUnknown` slot (a pre-swap failure — the advance outcome is
    /// unknown) is a remaining change iff its OBSERVED state (the outcome's
    /// observation, which the engine records as the actual post-state, never
    /// the desired one) differs from the intent's pre-push observation of
    /// that slot. An `Unknown` observation (the post-mutation status read
    /// failed) is UNCERTAIN — never unchanged.
    pub fn remaining_changes(
        &self,
        intent: &DeploymentIntent,
    ) -> Option<
        crate::ledger::records::SlotTable<
            crate::ledger::records::Observation<crate::ledger::records::ObservedGeneration>,
        >,
    > {
        let TerminalDisposition::Degraded(dt) = &self.disposition else {
            return None;
        };
        let mut remaining: crate::ledger::records::SlotTable<
            crate::ledger::records::Observation<crate::ledger::records::ObservedGeneration>,
        > = crate::ledger::records::SlotTable::new();
        for (sid, r) in dt.outcomes().iter() {
            let is_change = match r.transition() {
                crate::ledger::records::SlotTransition::NeverAdvanced
                | crate::ledger::records::SlotTransition::Restored => false,
                crate::ledger::records::SlotTransition::Advanced => true,
                crate::ledger::records::SlotTransition::AdvanceUnknown => {
                    let pre = intent.pre_push(sid).and_then(|p| match p {
                        crate::ledger::records::Observation::Known(prev) => {
                            Some(prev.generation.clone())
                        }
                        _ => None,
                    });
                    match r.observation() {
                        crate::ledger::records::Observation::Known(og) => {
                            let obs = og.generation.clone();
                            match (Some(obs), pre) {
                                (Some(obs), Some(pre_gen)) => obs != pre_gen,
                                (Some(_), None) => true,
                                _ => false,
                            }
                        }
                        crate::ledger::records::Observation::KnownAbsent => pre.is_some(),
                        crate::ledger::records::Observation::Unknown(_) => true,
                    }
                }
            };
            if is_change {
                remaining.insert(sid.clone(), r.observation().clone());
            }
        }
        Some(remaining)
    }
}

/// THE DIGEST-ENFORCING CONSTRUCTOR for the wire path: validate the digest
/// scalar and construct the terminal.
pub fn terminal_with_digest(
    recorded_at: Timestamp,
    intent_digest: IntentDigest,
    disposition: TerminalDisposition,
    reason: Option<String>,
) -> KernelResult<LedgerTerminal> {
    // The digest was already parsed by the wire conversion; the constructor
    // keeps the domain uncorruptible (private fields).
    Ok(LedgerTerminal::new(
        recorded_at,
        intent_digest,
        disposition,
        reason,
    ))
}

/// THE PARENT == HEAD CHECK — `intent.parent == current successful
/// head`. Under the STRICTLY-LINEAR model the authoritative lineage gate
/// lives at INTENT-APPEND time inside [`crate::kernel::transition::
/// apply_event`] (one pending at a time, parent == head at intent append);
/// this helper enforces the SAME equality at the WRITE boundaries: the
/// plan-time gate ([`crate::deploy::push::preflight`] before mutation) and
/// the finalizer's explicit pre-check ([
/// crate::ledger::finalize::finalize_successful_locked`] ALWAYS requires
/// it, no flag, no bypass — recovery included). A drifted head means the
/// plan was computed against a snapshot that is no longer the head — refuse
/// with [`KernelError::Conflict`] (StalePlan) — never reconcile implicitly,
/// never let a stale plan append `Successful`.
pub fn assert_parent_is_head(
    intent: &DeploymentIntent,
    current_head: Option<&crate::identity::DeploymentId>,
) -> KernelResult<()> {
    let parent = intent.parent();
    if parent.is_some() != current_head.is_some() || parent != current_head {
        return Err(KernelError::Conflict(ConflictError::ParentMismatch {
            deployment: intent.deployment_id().clone(),
            recorded_parent: parent.cloned(),
            actual_head: current_head.cloned(),
        }));
    }
    Ok(())
}
