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
//!   mutation is back at its pre-push state (every slot's
//!   [`SlotDelta`] is `Unchanged`);
//! * Degraded ([`DegradedTerminal`]) — nonempty outcomes with at least one
//!   remaining change (at least one slot's [`SlotDelta`] is
//!   `Desired`/`Diverged`/`Unknown`).
//!
//! # One per-slot classifier for every terminal decision
//!
//! Every terminal decision derives from the outcome's post-mutation
//! OBSERVATION against the intent's pre-push and DESIRED generations,
//! through the ONE classifier [`classify_slot_delta`] / [`SlotDelta`]:
//! `FailedRolledBack` requires EVERY slot `Unchanged`; `Degraded` requires
//! AT LEAST ONE `Desired`/`Diverged`/`Unknown` slot (nonempty deltas);
//! [`LedgerTerminal::remaining_changes`] contains exactly the
//! `Desired`/`Diverged`/`Unknown` slots. The old rule — a rolled-back
//! decision from the outcome's derived TRANSITION, a different rule than
//! `remaining_changes`' state comparison — could classify an uncompensated
//! failure that happened AFTER the slot advanced as rolled back (its
//! transition was `AdvanceUnknown`), with the still-changed slot invisible
//! to the decision: the P1 finding this taxonomy fixes.

use crate::identity::Timestamp;
use crate::kernel::error::{ConflictError, IntegrityError, KernelError, KernelResult};
use crate::kernel::intent::DeploymentIntent;
use crate::ledger::NonEmptySlotTable;
use crate::ledger::records::{Observation, ObservedGeneration, SlotOutcome, SlotTable};

/// THE ONE PER-SLOT DELTA CLASSIFICATION — the SINGLE semantic value every
/// terminal decision derives from (the review's `SlotDelta`): each selected
/// slot's observed post-state against the intent's pre-push and DESIRED
/// generations. [`classify_slot_delta`] is the ONE classifier: the
/// disposition decision ([`crate::kernel::transition::decide_terminal`]),
/// the disposition payload validators ([`FailedRolledBackTerminal::try_new`]
/// / [`DegradedTerminal::try_new`]), the cross-record terminal agreement
/// ([`crate::kernel::transition::validate_terminal_vs_intent`]), and the
/// remaining-changes derivation ([`LedgerTerminal::remaining_changes`]) all
/// classify through it — never through an independently-stored transition
/// state that could disagree with the outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotDelta {
    /// The observed post-state equals the intent's pre-push state (or the
    /// slot is absent with no known prior state): the slot is back where it
    /// started — never a remaining change.
    Unchanged,
    /// The observed post-state equals the intent's DESIRED generation (the
    /// slot is on the state the deployment planned — a remaining change).
    Desired,
    /// The observed post-state is a THIRD state (neither desired nor
    /// pre-push) or vanished while a prior state was known: a remaining
    /// change.
    Diverged,
    /// The observation read failed (the outcome's observation is
    /// `Unknown`): NEVER evidence of "unchanged" — a remaining change.
    Unknown,
}

/// THE ONE PER-SLOT CLASSIFIER: the observed post-state vs the intent's
/// DESIRED and PRE-PUSH generations —
///
/// * observed == desired → [`SlotDelta::Desired`];
/// * observed == pre-push → [`SlotDelta::Unchanged`];
/// * observed else (a third state / vanished prior state) →
///   [`SlotDelta::Diverged`];
/// * the observation read failed (`Unknown`) → [`SlotDelta::Unknown`].
///
/// `pre_push` is `None` when the intent records no known prior generation
/// (a `KnownAbsent` or failed pre-push observation) — an absent observed
/// state with no known prior is `Unchanged`, with a known prior it is
/// `Diverged` (the state vanished). Every terminal decision and the
/// remaining-changes derivation classify through this ONE function.
pub fn classify_slot_delta(
    observation: &Observation<ObservedGeneration>,
    desired: &crate::identity::GenerationId,
    pre_push: Option<&crate::identity::GenerationId>,
) -> SlotDelta {
    match observation {
        Observation::Unknown(_) => SlotDelta::Unknown,
        Observation::KnownAbsent => {
            if pre_push.is_none() {
                SlotDelta::Unchanged
            } else {
                SlotDelta::Diverged
            }
        }
        Observation::Known(obs) => {
            if &obs.generation == desired {
                SlotDelta::Desired
            } else if Some(&obs.generation) == pre_push {
                SlotDelta::Unchanged
            } else {
                SlotDelta::Diverged
            }
        }
    }
}

/// The per-slot delta of one of the intent's SELECTED outcomes — the
/// outcome's observation vs the intent's DESIRED (the slot's planned
/// result generation — always present for a selected slot) and PRE-PUSH
/// generations. Shared by the payload validators, the cross-record
/// terminal agreement, and [`LedgerTerminal::remaining_changes`].
pub(crate) fn outcome_slot_delta(
    intent: &DeploymentIntent,
    sid: &crate::identity::SlotId,
    o: &SlotOutcome,
) -> SlotDelta {
    // The resulting snapshot is a DERIVED VIEW of the intent's slot table
    // (materialized here — never a second stored fact).
    let snapshot = intent.resulting_snapshot();
    let desired = snapshot
        .get(sid)
        .map(|e| e.generation())
        .expect("a selected outcome names a slot with a planned result");
    let pre_push = intent.pre_push(sid).and_then(|p| match p {
        Observation::Known(prev) => Some(&prev.generation),
        _ => None,
    });
    classify_slot_delta(o.observation(), desired, pre_push)
}

/// THE COMPENSATION REPORT / outcome payload of a fully-rolled-back
/// deployment: every attempted mutation is back at its pre-push state. The
/// constructor is the ONE validator of that fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailedRolledBackTerminal {
    outcomes: SlotTable<SlotOutcome>,
}

impl FailedRolledBackTerminal {
    /// VALIDATE "every slot's [`SlotDelta`] is `Unchanged`": under the ONE
    /// classifier ([`classify_slot_delta`]), a slot whose observed post-state
    /// is Desired/Diverged/Unknown (a slot PROVABLY ON the deployed state, or
    /// a third/unknown state) is NEVER a rolled-back slot — a pre-swap
    /// failure still at its pre-push state and a restored slot are the only
    /// legitimate members. The intent binds the classification (its
    /// pre-push and DESIRED generations per slot).
    pub fn try_new(
        outcomes: SlotTable<SlotOutcome>,
        intent: &DeploymentIntent,
    ) -> KernelResult<Self> {
        for (slot, o) in outcomes.iter() {
            if outcome_slot_delta(intent, slot, o) != SlotDelta::Unchanged {
                return Err(KernelError::Integrity(IntegrityError::Message(format!(
                    "a FailedRolledBack terminal cannot carry slot '{slot}' with a non-Unchanged delta ({:?}) — every attempted mutation must be back at its pre-push state",
                    outcome_slot_delta(intent, slot, o)
                ))));
            }
        }
        Ok(Self { outcomes })
    }

    /// The WIRE-READ constructor (no intent available at deserialization):
    /// builds the payload from the wire rows WITHOUT the intent-dependent
    /// delta validation — the cross-record terminal agreement
    /// ([`crate::kernel::transition::validate_terminal_vs_intent`], where
    /// the entry's intent exists) enforces the all-Unchanged invariant on
    /// BOTH the read fold and the append path before any consumer sees the
    /// terminal, so an invalid record is refused fail-closed either way.
    pub(crate) fn new_unchecked(outcomes: SlotTable<SlotOutcome>) -> Self {
        Self { outcomes }
    }
    pub fn outcomes(&self) -> &SlotTable<SlotOutcome> {
        &self.outcomes
    }
}

/// THE outcome payload of a DEGRADED deployment: nonempty outcomes with at
/// least one remaining change (a slot whose [`SlotDelta`] is `Desired` /
/// `Diverged` / `Unknown`). The constructor is the ONE validator of that
/// fact — the review's nonempty-deltas invariant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DegradedTerminal {
    outcomes: NonEmptySlotTable<SlotOutcome>,
}

impl DegradedTerminal {
    /// VALIDATE "nonempty, at least one Desired/Diverged/Unknown delta":
    /// the table is non-empty by TYPE, and at least one outcome's delta
    /// (under the ONE classifier [`classify_slot_delta`], bound by the
    /// intent's pre-push and DESIRED generations) is NOT `Unchanged` — the
    /// review's exact requirement (a Degraded terminal with NO remaining
    /// change is unrepresentable). An all-Unchanged outcome set is a
    /// `FailedRolledBack`, never a `Degraded`.
    pub fn try_new(
        outcomes: NonEmptySlotTable<SlotOutcome>,
        intent: &DeploymentIntent,
    ) -> KernelResult<Self> {
        let has_remaining = outcomes
            .iter()
            .any(|(sid, o)| outcome_slot_delta(intent, sid, o) != SlotDelta::Unchanged);
        if !has_remaining {
            return Err(KernelError::Integrity(IntegrityError::Message(
                "a Degraded terminal requires at least one remaining change — every slot is at its pre-push state, so the attempt is FailedRolledBack, never Degraded"
                    .to_string(),
            )));
        }
        Ok(Self { outcomes })
    }

    /// The WIRE-READ constructor (no intent available at deserialization):
    /// builds the payload from the wire rows WITHOUT the intent-dependent
    /// delta validation — the cross-record terminal agreement
    /// ([`crate::kernel::transition::validate_terminal_vs_intent`], where
    /// the entry's intent exists) enforces the nonempty-deltas invariant on
    /// BOTH the read fold and the append path before any consumer sees the
    /// terminal.
    pub(crate) fn new_unchecked(outcomes: NonEmptySlotTable<SlotOutcome>) -> Self {
        Self { outcomes }
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

/// THE SEALED PROOF OF VERIFIED EXECUTION — the ONLY way a
/// [`TerminalDisposition::Successful`] terminal may be constructed
/// ([`LedgerTerminal::successful`]). A library caller CANNOT fabricate
/// success: the proof has no public constructor (its field is private
/// `_sealed`), so a `Successful` terminal is constructible ONLY inside the
/// crate, at the verified-execution evidence point — the finalizer's
/// lock-verified observation ([`crate::ledger::finalize::
/// finalize_successful_locked`]'s `LockedObservation::Verified`) / the
/// kernel's [`crate::kernel::transition::ExecutionReport::Verified`]
/// report.
///
/// The sealed `_sealed: ()` shape mirrors the merged
/// `VerifiedAdapterRestoration` pattern: the type is `pub` (so a caller
/// can NAME the proof and pass it around) but has NO free constructor —
/// the proof's only mint is `pub(crate)` and lives on the evidence path,
/// never reachable by an external caller. There is NO
/// `#[cfg(test)]`-gated production constructor: the private constructor is
/// always present (only the crate's trusted paths call it); the test mint
/// (`for_tests`) is a separate `#[cfg(test)]` helper for the fixtures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedExecution {
    _sealed: (),
}

impl VerifiedExecution {
    /// MINT the proof at the verified-execution evidence point — the ONLY
    /// production mint. Reachable only inside the crate (the successful
    /// finalizer's `LockedObservation::Verified` path); a library caller
    /// cannot construct the sealed type, so it cannot fabricate a
    /// `Successful` terminal.
    pub(crate) fn from_verified_report() -> Self {
        VerifiedExecution { _sealed: () }
    }

    /// TEST-ONLY mint for the fixtures / unit tests. Never compiled into a
    /// production build; an external caller (integration test / library
    /// user) sees only the sealed type with no constructor.
    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        VerifiedExecution { _sealed: () }
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

/// The terminal dispositions [`LedgerTerminal::new`] accepts — EVERYTHING
/// except `Successful`. A `Successful` terminal is UNREPRESENTABLE here:
/// it requires the sealed [`VerifiedExecution`] proof and the dedicated
/// [`LedgerTerminal::successful`] constructor (the kernel's
/// verified-execution evidence path). A library caller passing
/// `TerminalDisposition::Successful` to `LedgerTerminal::new` is a
/// COMPILE ERROR — success cannot be fabricated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NonSuccessfulDisposition {
    /// The attempt failed before any slot mutation: no payload, no
    /// outcomes.
    FailedPreflight,
    /// The attempt failed after mutating slots and every attempted
    /// mutation was restored or never advanced.
    FailedRolledBack(FailedRolledBackTerminal),
    /// The attempt ended degraded: at least one slot remains changed or
    /// unknown.
    Degraded(DegradedTerminal),
}

impl NonSuccessfulDisposition {
    /// The disposition's STATUS (the non-Successful subset of
    /// [`TerminalDisposition::status`]).
    pub fn status(&self) -> crate::ledger::records::DeploymentStatus {
        match self {
            NonSuccessfulDisposition::FailedPreflight => {
                crate::ledger::records::DeploymentStatus::FailedPreflight
            }
            NonSuccessfulDisposition::FailedRolledBack(_) => {
                crate::ledger::records::DeploymentStatus::FailedRolledBack
            }
            NonSuccessfulDisposition::Degraded(_) => {
                crate::ledger::records::DeploymentStatus::Degraded
            }
        }
    }

    /// Convert a NON-VERIFIED execution decision to the constructor's
    /// disposition: the kernel's truth table
    /// ([`crate::kernel::transition::decide_terminal`]) yields
    /// `Successful` ONLY from [`crate::kernel::transition::
    /// ExecutionReport::Verified`], so a failure/preflight decision never
    /// is `Successful` here — the sealed-proof gate is the kernel's, and
    /// reaching the `unreachable!` would expose a kernel truth-table bug,
    /// never a caller error.
    pub fn from_decision(disposition: TerminalDisposition) -> Self {
        match disposition {
            TerminalDisposition::FailedPreflight => Self::FailedPreflight,
            TerminalDisposition::FailedRolledBack(payload) => Self::FailedRolledBack(payload),
            TerminalDisposition::Degraded(payload) => Self::Degraded(payload),
            TerminalDisposition::Successful => unreachable!(
                "a Successful disposition is mintable only from ExecutionReport::Verified \
                 (the sealed VerifiedExecution proof) — a non-verified decision never yields it"
            ),
        }
    }
}

impl From<NonSuccessfulDisposition> for TerminalDisposition {
    fn from(d: NonSuccessfulDisposition) -> Self {
        match d {
            NonSuccessfulDisposition::FailedPreflight => TerminalDisposition::FailedPreflight,
            NonSuccessfulDisposition::FailedRolledBack(p) => {
                TerminalDisposition::FailedRolledBack(p)
            }
            NonSuccessfulDisposition::Degraded(p) => TerminalDisposition::Degraded(p),
        }
    }
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
    /// Construct a NON-SUCCESSFUL terminal (`FailedPreflight` /
    /// `FailedRolledBack` / `Degraded`). The `Successful` disposition is
    /// NOT a parameter — it is UNREPRESENTABLE here: a Successful terminal
    /// requires the sealed [`VerifiedExecution`] proof and the dedicated
    /// [`LedgerTerminal::successful`] constructor (the kernel's
    /// verified-execution evidence path). A library caller CANNOT
    /// fabricate success: `LedgerTerminal::new(...,
    /// TerminalDisposition::Successful, ...)` does not compile.
    pub fn new(
        recorded_at: Timestamp,
        intent_digest: IntentDigest,
        disposition: NonSuccessfulDisposition,
        reason: Option<String>,
    ) -> Self {
        Self {
            recorded_at,
            intent_digest,
            disposition: disposition.into(),
            reason,
        }
    }

    /// Construct the SUCCESSFUL terminal: requires the sealed
    /// [`VerifiedExecution`] proof, minted ONLY at the verified-execution
    /// evidence point (the successful finalizer's `LockedObservation::Verified`
    /// / the kernel's [`crate::kernel::transition::ExecutionReport::Verified`]).
    /// The proof is consumed by value — it cannot be reused to fabricate a
    /// second success.
    pub fn successful(
        _proof: VerifiedExecution,
        recorded_at: Timestamp,
        intent_digest: IntentDigest,
        reason: Option<String>,
    ) -> Self {
        Self {
            recorded_at,
            intent_digest,
            disposition: TerminalDisposition::Successful,
            reason,
        }
    }

    /// THE READ-PATH constructor (wire deserialization): reconstruct the
    /// domain form of a PERSISTED `Successful` terminal. NOT fabrication —
    /// a Successful terminal was only ever WRITTEN with the sealed proof
    /// (the txn's append gate) or by the validated suffix replacement; this
    /// crate-internal path re-reads that persisted fact. `pub(crate)`: an
    /// external caller cannot reach it.
    pub(crate) fn successful_unchecked(
        recorded_at: Timestamp,
        intent_digest: IntentDigest,
        reason: Option<String>,
    ) -> Self {
        Self {
            recorded_at,
            intent_digest,
            disposition: TerminalDisposition::Successful,
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
    /// terminal — DERIVED from the disposition's OWN per-slot outcomes
    /// through the ONE per-slot classifier
    /// ([`classify_slot_delta`] / [`SlotDelta`]): the slots whose delta is
    /// `Desired`/`Diverged`/`Unknown` — NOT `Unchanged` — each mapped to
    /// its THREE-STATE OBSERVATION. This is the SAME classification the
    /// disposition decision and the payload validators use — never a second
    /// rule (the old derivation coupled the outcome's derived transition to
    /// an observation-vs-pre_push comparison that could disagree with the
    /// disposition decision). `None` for any non-Degraded disposition.
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
            if outcome_slot_delta(intent, sid, r) != SlotDelta::Unchanged {
                remaining.insert(sid.clone(), r.observation().clone());
            }
        }
        Some(remaining)
    }
}

/// THE PARENT == HEAD CHECK — `intent.parent == current successful
/// head`. Under the STRICTLY-LINEAR model the authoritative lineage gate
/// lives at INTENT-APPEND time inside [`crate::kernel::transition::
/// apply_event`] (one pending at a time, parent == head at intent append);
/// this helper enforces the SAME equality at the WRITE boundaries: the
/// plan-time gate (`crate::deploy::push::preflight` before mutation) and
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
