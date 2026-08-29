//! The TERMINAL records of the deployment ledger (feature area A2 "two line
//! kinds — terminal"): the terminal wire/domain pair ([`LedgerTerminalWire`]
//! / [`LedgerTerminal`]) with the VERIFYING CONVERSION, the
//! [`TerminalDisposition`] enum (each disposition OWNS its per-slot outcome
//! table), and the status accessor. The outcome DERIVATIONS
//! ([`LedgerTerminal::remaining_changes`], [`LedgerTerminal::compensation`])
//! live with the per-slot outcomes ([`crate::ledger::records::wire::outcomes`]);
//! the physical [`crate::ledger::finalize::LedgerLine::Terminal`] line lives in
//! [`crate::ledger::finalize`].

use crate::error::{Error, Result};
use crate::identity::{DeploymentId, NonEmptySlotSet, SlotId, TargetName, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::super::observation::{Observation, ObservedGeneration};
use super::super::{
    CompleteRollback, DeploymentStatus, NonEmptySlotTable, SlotTable, TargetSnapshot,
};
use super::outcomes::{SlotOutcome, SlotOutcomeKind, SlotResult, SlotTransition};
/// The DISPOSITION of a deployment's terminal event — the DOMAIN replaces
/// the wire's `status: String` + optional rollback TAG-PLUS-OPTIONAL-PAYLOAD
/// shape with an ENUM whose variants carry exactly the payload their
/// disposition allows, so the STATUS/ROLLBACK TRUTH TABLE is STRUCTURAL
/// (unrepresentable-invalid states simply do not exist in the domain):
///
/// * [`TerminalDisposition::Successful`] ALWAYS carries its complete
///   rollback payload (a successful deployment always records its rollback
///   state — the generation refs + physical bindings, THE single source of
///   truth for each slot's generation/artifact facts) AND THE ACTIVATED
///   SLOT-ID SET (the non-empty set of slots the push activated — the
///   per-slot generation/artifact facts are NOT stored again: the wire's
///   per-slot outcome claims are validated against the rollback and then
///   DISCARDED, and every consumer derives each slot's facts from the
///   rollback) AND THE TWO PERSISTED MEMBERSHIPS — `activated` (the slots
///   the push actually deployed, EQUAL to the wire's selected_membership)
///   and `full_membership` (the COMPLETE target membership at terminal
///   time, EQUAL to the rollback's slots) — so the record PROVES the
///   membership equations instead of implying them. The rollback is the
///   COMPLETE resulting target snapshot: for a GROUP push the base-overlay
///   carries the unselected slots forward, so the rollback's slots ⊇ the
///   activated set (the outcomes cover the SELECTED slots; for a FULL push
///   the terminal's own memberships satisfy selected == full — enforced
///   where the terminal merges into its entry, via the intent's `group`).
/// * [`TerminalDisposition::FailedPreflight`] carries NOTHING — a
///   pre-mutation failure cannot carry a rollback, and no slot was touched
///   (the conversion refuses outcomes).
/// * [`TerminalDisposition::FailedRolledBack`] carries its OWN per-slot
///   outcomes table — the COMPENSATION REPORT (the per-slot results of the
///   compensation pass) IS that table, exposed via
///   [`LedgerTerminal::compensation`], never stored twice.
/// * [`TerminalDisposition::Degraded`] carries its OWN per-slot outcomes
///   table — its REMAINING CHANGES (the slots that did not reach a restored
///   state, each mapped to the generation it recorded) are DERIVED from that
///   table via [`LedgerTerminal::remaining_changes`], never stored twice
///   (NON-EMPTY by construction — the conversion refuses a Degraded wire
///   whose outcomes show all-restored).
///
/// LET EACH DISPOSITION OWN ITS OUTCOME TABLE: the per-slot OUTCOMES are
/// the authoritative per-slot facts and they live ONCE, INSIDE the
/// disposition — there is no separate `LedgerTerminal.outcomes` field to
/// disagree with. For a SUCCESSFUL terminal the per-slot facts live ONCE in
/// the ROLLBACK (the single source of truth): the disposition keeps only
/// the ACTIVATED SLOT-ID SET, and the per-slot outcome view is DERIVED from
/// the rollback ([`LedgerTerminal::outcomes`]) — never stored/trusted
/// separately, so a successful terminal can never contradict its rollback.
/// The disposition carries ONLY what the activated set + rollback cannot
/// express (the memberships). The WIRE keeps the current `status` +
/// `rollback` + per-slot `outcomes` shape; the wire → domain conversion maps
/// every status to EXACTLY ONE disposition and refuses a status whose
/// payload does not match its disposition (a `Successful` with no rollback,
/// a failed status carrying a rollback, a `Degraded` whose outcomes show
/// all-restored, a `Successful` whose outcome contradicts the rollback — a
/// non-Known observation, a mismatched generation, an operation error, or a
/// compensated slot — an `InProgress`/`PendingCommit` terminal — all are
/// conversion errors, fail closed).
/// The VALIDATED successful terminal payload: the complete rollback
/// (`rollback` — the full snapshot), the ACTIVATED slot-id set
/// (`activated` — non-empty by TYPE via [`NonEmptySlotSet`]), and the
/// FULL membership (`full_membership` — the complete target membership at
/// terminal time). INVARIANTS enforced by CONSTRUCTION via
/// [`SuccessfulTerminal::try_new`]: `activated` is non-empty by TYPE
/// (`NonEmptySlotSet`), `activated ⊆ full_membership` by CONSTRUCTION,
/// `full_membership == rollback.keys()` by CONSTRUCTION. Wire conversion
/// calls `try_new`; any violation returns `Error::Integrity`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuccessfulTerminal {
    rollback: CompleteRollback,
    activated: NonEmptySlotSet,
}

impl SuccessfulTerminal {
    pub fn try_new(rollback: CompleteRollback, activated: NonEmptySlotSet) -> Result<Self> {
        let rollback_slots: BTreeSet<SlotId> = rollback.keys().cloned().collect();
        if !activated.is_subset_of(&rollback_slots) {
            return Err(Error::integrity(format!(
                "SuccessfulTerminal: activated must be a SUBSET of rollback keys (activated {activated:?} vs rollback {rollback_slots:?})"
            )));
        }
        Ok(Self {
            rollback,
            activated,
        })
    }
    pub fn rollback(&self) -> &CompleteRollback {
        &self.rollback
    }
    pub fn activated(&self) -> &NonEmptySlotSet {
        &self.activated
    }
    #[allow(dead_code)]
    pub fn full_membership(&self) -> BTreeSet<SlotId> {
        self.rollback.keys().cloned().collect()
    }
    #[cfg(test)]
    pub fn new_unchecked(rollback: CompleteRollback, activated: NonEmptySlotSet) -> Self {
        Self {
            rollback,
            activated,
        }
    }
    #[cfg(test)]
    pub fn new_unchecked_with_full(
        rollback: CompleteRollback,
        activated: NonEmptySlotSet,
        _full: BTreeSet<SlotId>,
    ) -> Self {
        Self {
            rollback,
            activated,
        }
    }
    pub fn try_new_with_full(
        rollback: CompleteRollback,
        activated: NonEmptySlotSet,
        _full: BTreeSet<SlotId>,
    ) -> Result<Self> {
        Self::try_new(rollback, activated)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DegradedTerminal {
    outcomes: NonEmptySlotTable<SlotOutcome>,
}

impl DegradedTerminal {
    pub fn try_new(outcomes: NonEmptySlotTable<SlotOutcome>) -> Result<Self> {
        if outcomes
            .values()
            .all(|r| r.outcome == SlotOutcomeKind::Restored)
        {
            return Err(Error::integrity(
                "a fully restored attempt is FailedRolledBack, not Degraded",
            ));
        }
        Ok(Self { outcomes })
    }
    pub fn outcomes(&self) -> &NonEmptySlotTable<SlotOutcome> {
        &self.outcomes
    }
    #[cfg(test)]
    pub fn new_unchecked(outcomes: NonEmptySlotTable<SlotOutcome>) -> Self {
        Self { outcomes }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalDisposition {
    /// The deployment succeeded: the complete rollback payload (the full
    /// snapshot: per-slot generations + physical bindings — THE single
    /// source of truth for each slot's generation/artifact facts), THE
    /// ACTIVATED SLOT-ID SET (the non-empty set of slots the push
    /// activated — `NonEmptySlotSet` by TYPE, so emptiness is
    /// unrepresentable — the per-slot generation/artifact facts are NOT
    /// stored again; every consumer derives them from the rollback via
    /// [`LedgerTerminal::outcomes`]), and the TWO PERSISTED MEMBERSHIPS
    /// that PROVE the membership equations: `activated` (the slots the push
    /// actually deployed — EQUAL to the wire's `selected_membership`,
    /// enforced by the conversion) and `full_membership` (the COMPLETE
    /// target membership at terminal time — EQUAL to the rollback's slots,
    /// enforced by the conversion). `activated ⊆ full_membership` by
    /// CONSTRUCTION via [`SuccessfulTerminal::try_new`];
    /// `full_membership == rollback.keys()` by CONSTRUCTION;
    /// `activated` non-empty by TYPE (`NonEmptySlotSet`); the FULL-push
    /// equality `activated == full_membership` is enforced where the
    /// terminal merges into its entry (the mode — group vs full — lives in
    /// the intent's `group`). The rollback is the COMPLETE resulting target
    /// snapshot: for a GROUP push the base-overlay carries the unselected
    /// slots forward, so the rollback's slots ⊇ the activated set (the
    /// outcomes cover the SELECTED slots; for a FULL push the terminal's own
    /// memberships satisfy selected == full — enforced where the terminal
    /// merges into its entry, via the intent's `group`). The validated
    /// payload is constructed ONLY via [`SuccessfulTerminal::try_new`], so
    /// an inconsistent shape (e.g. activated ⊄ full, full ≠ rollback
    /// slots) is UNCONSTRUCTIBLE.
    Successful(SuccessfulTerminal),
    /// The attempt failed before any slot mutation: no payload (no
    /// rollback — and the conversion also refuses outcomes, since a
    /// pre-mutation failure touched no slot).
    FailedPreflight,
    /// The attempt failed after mutating slots and was rolled back: the
    /// disposition's OWN per-slot outcomes table — the compensation report
    /// (each slot's per-slot result of the compensation pass: which slots
    /// were restored and which compensation failed) IS that table, exposed
    /// via [`LedgerTerminal::compensation`].
    FailedRolledBack { outcomes: SlotTable<SlotOutcome> },
    /// The attempt ended degraded (some slots advanced and were not
    /// restored, or the commit could not be finalized): the disposition's
    /// OWN per-slot outcomes table — the REMAINING CHANGES (the slots that
    /// did not reach a restored state, each mapped to the generation it
    /// recorded) are DERIVED from that table via
    /// [`LedgerTerminal::remaining_changes`] (NON-EMPTY by construction —
    /// the conversion refuses a Degraded wire whose outcomes show
    /// all-restored). The payload is validated by [`DegradedTerminal::try_new`]
    /// (non-empty by TYPE via [`NonEmptySlotTable`] and at least one
    /// non-`Restored` outcome).
    Degraded(DegradedTerminal),
}

impl TerminalDisposition {
    /// The disposition's status — the inverse of the wire's
    /// status→disposition mapping (a domain terminal derives its status
    /// from its disposition; the two are never stored side by side).
    pub fn status(&self) -> DeploymentStatus {
        match self {
            TerminalDisposition::Successful(_) => DeploymentStatus::Successful,
            TerminalDisposition::FailedPreflight => DeploymentStatus::FailedPreflight,
            TerminalDisposition::FailedRolledBack { .. } => DeploymentStatus::FailedRolledBack,
            TerminalDisposition::Degraded(_) => DeploymentStatus::Degraded,
        }
    }

    pub fn is_successful(&self) -> bool {
        matches!(self, TerminalDisposition::Successful(_))
    }
}

/// The TERMINAL EVENT of one deployment, the VALIDATED DOMAIN form of
/// [`LedgerTerminalWire`]. Appended ONCE to the target's ledger after the
/// mutation loop; the entry's current status is the status of its terminal
/// event (an entry WITHOUT a terminal is the recoverable in-progress /
/// pending-commit state).
///
/// LET THE ENCLOSING OBJECT OWN IDENTITY: the domain terminal does NOT carry
/// `deployment_id` / `target` — the merged [`crate::ledger::finalize::LedgerEntry`] owns them (the
/// intent's, verified equal by the reader when the terminal merges into its
/// entry). The terminal's own shape is the disposition enum: the
/// status/rollback TRUTH TABLE is STRUCTURAL (see [`TerminalDisposition`])
/// — an invalid status/payload combination is unrepresentable.
///
/// LET EACH DISPOSITION OWN ITS OUTCOME TABLE: the per-slot OUTCOMES are
/// the authoritative per-slot facts and they live ONCE, INSIDE the
/// disposition ([`TerminalDisposition`]) — there is NO separate
/// `LedgerTerminal.outcomes` field to disagree with. The disposition's
/// per-slot projections — the Degraded REMAINING CHANGES and the
/// FailedRolledBack COMPENSATION REPORT — are DERIVED from the
/// disposition's OWN table ([`LedgerTerminal::remaining_changes`],
/// [`LedgerTerminal::compensation`]), never stored twice, so they can never
/// disagree with the outcomes. `reason` carries optional human context
/// (e.g. "push completed", "recovery finalized", "preflight failed") — a
/// free-form human NOTE, not a fact: it never participates in any invariant
/// (the disposition IS the machine fact).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerTerminal {
    /// When the terminal event was recorded (RFC 3339).
    pub recorded_at: String,
    /// HOW the attempt ended — the enum whose variants carry exactly their
    /// payload: each disposition OWNS its per-slot outcomes table (the
    /// truth table is structural; the per-slot projections are derived from
    /// the disposition's OWN table). A [`TerminalDisposition::Successful`]
    /// terminal instead owns THE ACTIVATED SLOT-ID SET + the rollback: its
    /// per-slot outcome facts are the DERIVED VIEW over the rollback (the
    /// single source of truth), so the disposition's payload never carries
    /// duplicated per-slot state that could contradict the rollback.
    pub disposition: TerminalDisposition,
    /// Optional human context: why this terminal event happened. A
    /// free-form NOTE, not a fact — it never participates in invariants
    /// (the disposition is the machine fact).
    pub reason: Option<String>,
}

impl LedgerTerminal {
    /// The terminal's status, DERIVED from its disposition (never stored
    /// separately — a status and a disposition can never disagree).
    pub fn status(&self) -> DeploymentStatus {
        self.disposition.status()
    }

    /// The terminal's per-slot outcomes — the disposition's OWN table
    /// ([`TerminalDisposition::FailedPreflight`] carries none, so the
    /// accessor yields an empty table). For a SUCCESSFUL terminal the
    /// per-slot facts are the DERIVED VIEW over the rollback — the single
    /// source of truth (each activated slot's outcome IS the rollback's
    /// authoritative generation for that slot; the wire → domain conversion
    /// enforced the complete equality predicate and then DISCARDED the
    /// wire's per-slot claims): the per-slot generation/artifact facts are
    /// never stored/trusted separately, so a successful terminal can never
    /// contradict its rollback. The table is MATERIALIZED on demand (the
    /// value is owned); the successful view is deterministic — Activated /
    /// Known(rollback generation) / error None / compensated false.
    pub fn outcomes(&self) -> SlotTable<SlotOutcome> {
        match &self.disposition {
            TerminalDisposition::Successful(st) => {
                // THE DERIVED VIEW: every activated slot's per-slot outcome
                // facts ARE the rollback's authoritative generation — never
                // stored/trusted separately. Every activated slot is a
                // rollback slot (the constructor enforces activated ⊆ full ==
                // rollback slots, so the lookup is infallible).
                let map: BTreeMap<SlotId, SlotOutcome> = st
                    .activated()
                    .iter()
                    .map(|sid| {
                        let rb = st.rollback().get(sid).unwrap();
                        (
                            sid.clone(),
                            SlotOutcome {
                                outcome: SlotOutcomeKind::Activated,
                                observation: Observation::Known(ObservedGeneration {
                                    generation: rb.generation().clone(),
                                }),
                                compensated: false,
                                error: None,
                                transition: SlotTransition::Advanced,
                            },
                        )
                    })
                    .collect();
                SlotTable::from_map(map)
            }
            TerminalDisposition::FailedPreflight => SlotTable::new(),
            TerminalDisposition::FailedRolledBack { outcomes } => outcomes.clone(),
            TerminalDisposition::Degraded(dt) => {
                SlotTable::from_map(dt.outcomes().clone().into_map())
            }
        }
    }

    /// The terminal's SELECTED MEMBERSHIP — the slots this deployment
    /// actually selected / deployed, i.e. THE ACTIVATED SET (for a group
    /// push the group's slots; for a full push every target slot; every
    /// selected slot was activated — the conversion enforces the equality).
    /// PERSISTED in the record and EQUAL to the wire's
    /// `selected_membership` by construction (the wire → domain conversion
    /// refuses a disagreement), so a consumer can display or prove which
    /// slots the push selected WITHOUT re-deriving it from the intent.
    /// `None` for every non-Successful disposition (a failed attempt never
    /// proves a membership).
    pub fn selected_membership(&self) -> Option<BTreeSet<SlotId>> {
        match &self.disposition {
            TerminalDisposition::Successful(st) => Some(st.activated().as_set().clone()),
            _ => None,
        }
    }

    pub fn full_membership(&self) -> Option<BTreeSet<SlotId>> {
        match &self.disposition {
            TerminalDisposition::Successful(st) => Some(st.full_membership()),
            _ => None,
        }
    }
}

/// The WIRE shape of a terminal event — the RAW serde form the ledger's
/// JSONL carries: the current `status` + optional `rollback`
/// tag-plus-optional-payload shape, plus the deployment/target identity the
/// ENTRY owns in the domain (the wire keeps them; the conversion and the
/// reader verify they equal the enclosing entry's). A SUCCESSFUL terminal
/// additionally persists BOTH memberships (`selected_membership` /
/// `full_membership`) — REQUIRED fields since schema v3 (no serde default,
/// so an old-shape terminal line fails deserialization fail-closed) — so
/// the record PROVES the membership equations instead of implying them. The
/// terminal's own duplicates — the STATUS/ROLLBACK TRUTH TABLE
/// (`Successful` ⇔ rollback present), each outcome's value naming its own
/// key, and the membership equations (outcomes == selected_membership,
/// rollback slots == full_membership, selected ⊆ full) — are verified by
/// the conversion; the CROSS-RECORD agreement (every outcome key a member
/// of the intent's `slot_ids`, the FULL-push selected == full equality via
/// the intent's `group`, the `target` field vs the read path and the
/// intent) is enforced where the intent and terminal merge
/// ([`crate::store::local::LocalStore::read_ledger`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerTerminalWire {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    pub status: DeploymentStatus,
    pub recorded_at: String,
    pub outcomes: BTreeMap<SlotId, SlotResult>,
    #[serde(
        default,
        deserialize_with = "crate::ledger::records::deserialize_opt_strict_rollback",
        skip_serializing_if = "Option::is_none"
    )]
    pub rollback: Option<TargetSnapshot>,
    /// The SELECTED membership — the slots this deployment actually
    /// selected / deployed (the outcomes' keys; a group push's group
    /// slots; a full push's every target slot). REQUIRED since schema v3
    /// (no serde default — an old-shape terminal line fails
    /// deserialization fail-closed): the wire → domain conversion requires
    /// it DUPLICATE-FREE and — for a `Successful` status — NON-EMPTY and
    /// EXACTLY EQUAL to the outcomes' keys, so the record PROVES which
    /// slots were selected.
    pub selected_membership: Vec<SlotId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub full_membership: Vec<SlotId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Validate ONE wire membership list ([`LedgerTerminalWire::selected_membership`]
/// / [`LedgerTerminalWire::full_membership`]): DUPLICATE-FREE and converted to
/// the SORTED UNIQUE SET the domain carries ([`BTreeSet`]). A duplicated
/// member would silently weaken the set equations (the set collapses the
/// duplicate, so the duplicated id would never be checked against the
/// outcomes / rollback) — a duplicate fails closed, like the intent's
/// `slot_ids`. The equations themselves are enforced by the caller
/// ([`LedgerTerminalWire::into_domain`]).
fn membership_wire_to_set(
    deployment_id: &DeploymentId,
    what: &str,
    wire: Vec<SlotId>,
) -> Result<BTreeSet<SlotId>> {
    let mut set: BTreeSet<SlotId> = BTreeSet::new();
    for sid in wire {
        if !set.insert(sid.clone()) {
            return Err(Error::integrity(format!(
                "terminal {deployment_id}: {what} carries duplicate slot '{sid}' — the membership must be unique"
            )));
        }
    }
    Ok(set)
}

impl LedgerTerminalWire {
    /// VERIFYING CONVERSION (wire → domain): the rollback payload is
    /// converted through [`TargetSnapshotWire::into_domain`] (which fails
    /// closed on any disagreement), the STATUS/ROLLBACK TRUTH TABLE is
    /// enforced (`Successful` always records its rollback state; every other
    /// status never carries one), each wire outcome's value must name its OWN
    /// map key (the outcome's `slot_id` is the placement slot it records —
    /// the redundant slot is then DROPPED into the key, since the domain
    /// value carries no slot), and the disposition's duplicated projections
    /// must AGREE with the authoritative outcomes, BY STATUS. A `Successful`
    /// wire must additionally carry NON-EMPTY, DUPLICATE-FREE
    /// `selected_membership` / `full_membership` lists satisfying THE
    /// MEMBERSHIP EQUATIONS (the terminal-local half): outcomes ==
    /// selected_membership (the outcomes are the selected slots' results),
    /// rollback slots == full_membership (the rollback is the COMPLETE
    /// resulting snapshot), and selected_membership ⊆ full_membership (a
    /// group push's selected set is a subset of the full target; the
    /// FULL-push EQUALITY — selected == full — is the cross-record leg
    /// enforced by the ledger read, where the intent's `group` carries the
    /// mode). Every other status must carry NO memberships (only a
    /// Successful terminal proves them — a failed status with memberships is
    /// a disagreement, refused). A `FailedPreflight` wire must carry NO
    /// outcomes (a pre-mutation failure touched no slot), and a `Degraded`
    /// wire's outcomes must derive a NON-EMPTY remaining-changes set
    /// (all-restored outcomes are refused). A disagreement →
    /// `Error::integrity`. The cross-record claims (every outcome key a
    /// member of the intent's `slot_ids`, the FULL-push selected == full
    /// equality via the intent's `group`, and the `target` field vs the read
    /// path / intent) are enforced by the ledger read that merges the intent
    /// and the terminal ([`crate::store::local::LocalStore::read_ledger`]).
    pub fn into_domain(self) -> Result<LedgerTerminal> {
        // The recorded timestamp must parse as RFC 3339 (fail closed).
        Timestamp::parse(&self.recorded_at).map_err(|_| {
            Error::integrity(format!(
                "terminal {}: recorded_at {:?} is not an RFC 3339 timestamp",
                self.deployment_id, self.recorded_at
            ))
        })?;
        // THE MEMBERSHIPS ARE VALIDATED FIRST: each wire membership list must
        // be DUPLICATE-FREE — a duplicated member would silently weaken the
        // set equations below (the set collapses the duplicate, so the
        // duplicated id would never be checked against the outcomes /
        // rollback). The validated form is the SORTED UNIQUE SET
        // ([`BTreeSet`]) the domain carries.
        let selected_membership = membership_wire_to_set(
            &self.deployment_id,
            "selected_membership",
            self.selected_membership,
        )?;

        // Only a Successful terminal proves a membership: a failed status
        // carrying memberships is dead, unenforced data — refused (fail
        // closed), never silently dropped.
        if self.status != DeploymentStatus::Successful && !selected_membership.is_empty() {
            return Err(Error::integrity(format!(
                "terminal {}: status {:?} must carry NO memberships — only a Successful terminal records its selected membership",
                self.deployment_id, self.status
            )));
        }
        let rollback = self.rollback;
        // OUTCOME OWN-KEY AGREEMENT (self-contained half): each wire
        // outcome's value names ITS OWN map key — an outcome for a different
        // slot is a disagreement. (The other half — the outcome KEY SET vs
        // the intent's authoritative membership — is cross-record and lives
        // in the ledger read that merges intent + terminal.)
        for (key, result) in &self.outcomes {
            if &result.slot_id != key {
                return Err(Error::integrity(format!(
                    "terminal {}: outcome for slot '{key}' names placement '{}'",
                    self.deployment_id, result.slot_id
                )));
            }
        }
        // The wire outcomes are converted to the DOMAIN outcomes, deriving
        // each slot's TRANSITION STATE from the wire's status/outcome fields
        // ([`SlotOutcome::from_wire`], FAIL CLOSED — the strict wire
        // observation converts to the domain observation; a wire value that
        // is not representable is refused here) and DROPPING the wire
        // outcome's redundant `slot_id` into the key (the domain value
        // carries no slot — the table key owns identity; the own-key
        // agreement above verified the wire's claim before the drop).
        let outcomes: SlotTable<SlotOutcome> = SlotTable::from_map(
            self.outcomes
                .into_iter()
                .map(|(key, result)| Ok((key, SlotOutcome::from_wire(result)?)))
                .collect::<Result<BTreeMap<SlotId, SlotOutcome>>>()?,
        );
        // STATUS → DISPOSITION: each status maps to exactly one disposition,
        // and a status whose payload does not match its disposition is a
        // conversion error (fail closed).
        let disposition = match (&self.status, rollback) {
            (DeploymentStatus::Successful, Some(rollback)) => {
                // THE SUCCESSFUL SNAPSHOT RULE (terminal-local half): the
                // outcomes are the SELECTED slots' results, the rollback is
                // the COMPLETE resulting target snapshot (for a GROUP push
                // the rollback carries the unselected slots forward from the
                // base), and the PERSISTED MEMBERSHIPS PROVE the equations:
                // outcomes == selected_membership, rollback slots ==
                // full_membership, and selected_membership ⊆
                // full_membership. The rollback's own conversion already
                // guarantees bindings == slots; the FULL-push EQUALITY
                // (selected == full) is the cross-record leg enforced where
                // the terminal merges into its entry (the mode — group vs
                // full — lives in the intent's `group`). A successful
                // deployment always records non-empty outcomes and both
                // memberships NON-EMPTY (a successful deployment selected
                // and covered at least one slot).
                let outcome_keys: BTreeSet<SlotId> = outcomes.keys().cloned().collect();
                let rollback_slot_keys: BTreeSet<SlotId> = rollback.keys().cloned().collect();
                // THE MEMBERSHIP EQUATIONS (terminal-local half) are enforced
                // by the SHARED helper in [`crate::ledger::records`]:
                // outcomes == selected_membership, rollback slots ==
                // full_membership, and selected_membership ⊆
                // full_membership (plus the non-empty guards — a successful
                // deployment always records non-empty outcomes and both
                // memberships). The FULL-push EQUALITY (selected == full) is
                // the cross-record leg enforced where the terminal merges
                // into its entry (the mode — group vs full — lives in the
                // intent's `group`).
                crate::ledger::records::verify_successful_membership_equations(
                    &self.deployment_id,
                    &outcome_keys,
                    &rollback_slot_keys,
                    &selected_membership,
                )?;
                // A Successful deployment implies every slot activated: a
                // non-activated outcome is a disagreement (the disposition's
                // implied state vs the recorded outcome).
                if let Some((key, r)) = outcomes
                    .iter()
                    .find(|(_, r)| r.outcome != SlotOutcomeKind::Activated)
                {
                    return Err(Error::integrity(format!(
                        "terminal {}: status Successful requires every outcome Activated — slot '{key}' records {:?}",
                        self.deployment_id, r.outcome
                    )));
                }
                // THE COMPLETE EQUALITY PREDICATE (the user's requirement):
                // a successful slot's wire outcome must AGREE with the
                // rollback — the rollback is the AUTHORITATIVE per-slot
                // fact, and an outcome that contradicts it is a
                // SELF-CONTRADICTING SUCCESS, refused (fail closed). Each
                // selected slot must carry:
                //   * Known(g) — a successful slot's state is Known, never
                //     KnownAbsent/Unknown (a successful slot was deployed);
                //   * g == rollback.get(slot).unwrap().generation() — the OBSERVED
                //     generation EQUALS the rollback's authoritative
                //     generation for that slot (the outcome can never claim
                //     a generation the rollback did not actually advance);
                //   * error == None — a successful outcome carries no
                //     operation error;
                //   * compensated == false — a successful slot was not
                //     compensated.
                // Any violation → `Error::integrity` naming the slot and the
                // offending leg. The wire's per-slot claims are then
                // DISCARDED — the domain stores only the ACTIVATED SLOT-ID
                // SET, deriving each slot's generation/artifact facts from
                // the rollback (the single source of truth) via
                // [`LedgerTerminal::outcomes`].
                for (key, r) in outcomes.iter() {
                    // Every outcome key is a rollback slot (rollback == full
                    // ⊇ outcomes == selected — enforced above).
                    let rb_gen = rollback
                        .get(key)
                        .expect("rollback covers outcome key")
                        .generation();
                    let mut violations: Vec<String> = Vec::new();
                    match &r.observation {
                        Observation::Known(og) => {
                            if &og.generation != rb_gen {
                                violations.push(format!(
                                    "observed generation {:?} != the rollback's generation {rb_gen:?}",
                                    og.generation
                                ));
                            }
                        }
                        other => violations.push(format!(
                            "observation {other:?} is not Known(g) — a successful slot's state must be Known"
                        )),
                    }
                    if r.error.is_some() {
                        violations.push("carries an operation error".to_string());
                    }
                    if r.compensated {
                        violations.push("is compensated".to_string());
                    }
                    if !violations.is_empty() {
                        return Err(Error::integrity(format!(
                            "terminal {}: status Successful outcome for slot '{key}' contradicts the rollback — the outcome's per-slot facts must EQUAL the rollback's (Known(g), g == rollback.get('{key}').unwrap().generation(), error == None, compensated == false); violated: {}",
                            self.deployment_id,
                            violations.join("; ")
                        )));
                    }
                }
                // SUCCESS IS A NON-EMPTY SET OF ACTIVATED SLOT IDS: the
                // per-slot wire claims have been validated against the
                // rollback and DISCARDED — the domain keeps the activated
                // set + the rollback (the facts source) + the memberships.
                // FINAL BACKSTOP: construct through the validated
                // `SuccessfulTerminal::try_new` (non-empty by TYPE,
                // activated ⊆ full, full == rollback.keys).
                let activated_set = NonEmptySlotSet::try_new(outcome_keys.clone()).ok_or_else(|| {
                    Error::integrity(format!(
                        "terminal {}: activated must be non-empty (SuccessfulTerminal requires NonEmptySlotSet)",
                        self.deployment_id
                    ))
                })?;
                let st = SuccessfulTerminal::try_new(rollback, activated_set)?;
                TerminalDisposition::Successful(st)
            }
            (DeploymentStatus::Successful, None) => {
                return Err(Error::integrity(format!(
                    "terminal {}: status Successful requires the complete rollback payload — a successful deployment always records its rollback state",
                    self.deployment_id
                )));
            }
            (DeploymentStatus::FailedPreflight, None) => {
                if !outcomes.is_empty() {
                    return Err(Error::integrity(format!(
                        "terminal {}: status FailedPreflight must carry NO outcomes (a pre-mutation failure touched no slot)",
                        self.deployment_id
                    )));
                }
                TerminalDisposition::FailedPreflight
            }
            (DeploymentStatus::FailedPreflight, Some(_)) => {
                return Err(Error::integrity(format!(
                    "terminal {}: status FailedPreflight must not carry a rollback payload (only Successful does)",
                    self.deployment_id
                )));
            }
            (DeploymentStatus::FailedRolledBack, None) => {
                // The compensation report IS the disposition's outcome table:
                // the record of what the compensation pass did to each slot
                // — exposed via [`LedgerTerminal::compensation`], never
                // stored as a duplicate that could disagree with them.
                TerminalDisposition::FailedRolledBack { outcomes }
            }
            (DeploymentStatus::FailedRolledBack, Some(_)) => {
                return Err(Error::integrity(format!(
                    "terminal {}: status FailedRolledBack must not carry a rollback payload (only Successful does)",
                    self.deployment_id
                )));
            }
            (DeploymentStatus::Degraded, None) => {
                // REMAINING CHANGES: the slots whose FINAL OBSERVED STATE
                // differs from their pre_push state, each mapped to the
                // generation it is on. DERIVED from the wire outcomes
                // ([`LedgerTerminal::remaining_changes`]) — never stored.
                // The conversion refuses a Degraded wire whose outcomes are
                // ALL restored (a fully-compensated attempt must be
                // `FailedRolledBack`, never `Degraded` — and an EMPTY
                // outcome table is vacuously all-restored, so a Degraded
                // terminal with no outcomes is refused too). A Degraded
                // terminal whose outcomes are all never-advanced (e.g. a
                // `leave_changed` failure that advanced nothing) is
                // legitimate: the policy marks the attempt Degraded even
                // though no slot changed, and the derived remaining-changes
                // set is empty.
                let non_empty = NonEmptySlotTable::build(
                    outcomes.iter().map(|(k, v)| (k.clone(), v.clone())),
                )
                .map_err(|e| {
                    Error::integrity(format!(
                        "terminal {}: status Degraded requires at least one non-restored outcome (an all-restored attempt is FailedRolledBack, never Degraded): {e}",
                        self.deployment_id
                    ))
                })?;
                let dt = DegradedTerminal::try_new(non_empty).map_err(|e| {
                    Error::integrity(format!(
                        "terminal {}: status Degraded requires at least one non-restored outcome (an all-restored attempt is FailedRolledBack, never Degraded): {e}",
                        self.deployment_id
                    ))
                })?;
                TerminalDisposition::Degraded(dt)
            }
            (DeploymentStatus::Degraded, Some(_)) => {
                return Err(Error::integrity(format!(
                    "terminal {}: status Degraded must not carry a rollback payload (only Successful does)",
                    self.deployment_id
                )));
            }
            (DeploymentStatus::InProgress | DeploymentStatus::PendingCommit, _) => {
                return Err(Error::integrity(format!(
                    "terminal {}: status {:?} never appears on a terminal event (it is the recoverable intent-only state)",
                    self.deployment_id, self.status
                )));
            }
        };
        Ok(LedgerTerminal {
            recorded_at: self.recorded_at,
            disposition,
            reason: self.reason,
        })
    }

    /// Build the WIRE form of a domain terminal for a given (deployment,
    /// target) identity — the enclosing [`crate::ledger::finalize::LedgerEntry`] owns the identity,
    /// so the wire's `deployment_id` / `target` come from the CALLER (the
    /// append path), never from the domain terminal. A Successful terminal's
    /// two memberships are emitted from the disposition (the activated set
    /// re-expands as the wire's `selected_membership`); every other
    /// disposition emits EMPTY memberships (only a Successful terminal
    /// records them — the conversion refuses a failed status carrying any).
    /// The Successful wire OUTCOMES are DERIVED from the rollback (via
    /// [`LedgerTerminal::outcomes`] — the per-slot facts are never stored
    /// separately), reproducing the exact consistent shape the engine
    /// writes; the next read's complete equality predicate accepts it
    /// unchanged.
    pub fn try_from_domain(
        deployment_id: &DeploymentId,
        target: &TargetName,
        t: &LedgerTerminal,
    ) -> Result<Self> {
        // VALIDATE the domain's memberships BEFORE materializing `outcomes`
        // — on the invalid shape return `Error::integrity`, NO panic path.
        if let TerminalDisposition::Successful(st) = &t.disposition {
            let activated = NonEmptySlotSet::try_new(st.activated().iter().cloned()).ok_or_else(|| {
                Error::integrity(format!(
                    "terminal {}: activated must be non-empty (SuccessfulTerminal requires NonEmptySlotSet)",
                    deployment_id
                ))
            })?;
            SuccessfulTerminal::try_new(st.rollback().clone(), activated)?;
        }
        if let TerminalDisposition::Degraded(dt) = &t.disposition {
            // Validate the Degraded payload so the emitted wire can never be
            // refused by `into_domain` (non-empty by TYPE and at least one
            // non-Restored outcome).
            DegradedTerminal::try_new(dt.outcomes().clone())?;
        }
        let rollback = match &t.disposition {
            TerminalDisposition::Successful(st) => Some(st.rollback().clone()),
            _ => None,
        };
        let selected_membership = match &t.disposition {
            TerminalDisposition::Successful(st) => st.activated().iter().cloned().collect(),
            _ => Vec::new(),
        };
        Ok(LedgerTerminalWire {
            deployment_id: deployment_id.clone(),
            target: target.clone(),
            status: t.disposition.status(),
            recorded_at: t.recorded_at.clone(),
            // The WIRE keeps the current on-disk shape: the domain outcomes'
            // transition state is a DOMAIN fact and is dropped here, and each
            // outcome's table key is re-attached as the wire value's
            // `slot_id` (the domain value carries no slot).
            outcomes: t
                .outcomes()
                .iter()
                .map(|(k, o)| (k.clone(), SlotResult::from_outcome(k, o)))
                .collect(),
            rollback,
            selected_membership,
            full_membership: vec![],
            reason: t.reason.clone(),
        })
    }
}

#[cfg(test)]
mod tests_terminal {
    use super::*;
    use crate::identity::ServerId;
    use crate::identity::{
        DeploymentId, SlotId, TargetName, test_generation_id, test_release_id, test_tree_digest,
    };
    use crate::ledger::records::{PhysicalBinding, SnapshotEntry, TargetSnapshot};
    use proptest::prelude::*;
    #[cfg(test)]
    use proptest::test_runner::RngSeed;
    use std::collections::{BTreeMap, BTreeSet};

    fn slot(i: u32) -> SlotId {
        SlotId::new(format!("slot-{i}"))
    }

    fn arb_slot_set() -> impl Strategy<Value = BTreeSet<SlotId>> {
        prop::collection::btree_set((0u32..4).prop_map(slot), 0..=4)
    }

    fn arb_rollback() -> impl Strategy<Value = TargetSnapshot> {
        prop::collection::btree_set((0u32..4).prop_map(slot), 0..=4).prop_map(|slots| {
            let mut entries = BTreeMap::new();
            for sid in slots {
                let generation = test_generation_id(sid.as_str());
                let artifact = crate::identity::ArtifactRef {
                    release: test_release_id(sid.as_str()),
                    variant: crate::identity::VariantName::parse("standard").unwrap(),
                    tree: test_tree_digest(sid.as_str()),
                };
                let binding = PhysicalBinding {
                    server: ServerId::parse("s1").unwrap(),
                    deploy_dir: format!("/srv/deploy/{}", sid.as_str()),
                };
                entries.insert(
                    sid.clone(),
                    SnapshotEntry::new(generation, artifact, binding),
                );
            }
            TargetSnapshot::from_entries(entries)
        })
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: crate::testutil::proptest_cases(64),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..Default::default()
        })]
        #[test]
        fn successful_terminal_protected_constructor(
            rollback in arb_rollback(),
            activated_raw in arb_slot_set(),
        ) {
            let rollback_keys: BTreeSet<SlotId> = rollback.keys().cloned().collect();
            let activated_opt = crate::identity::NonEmptySlotSet::try_new(activated_raw.clone());
            // The 2-arg constructor's ONLY obligation: activated non-empty
            // (by TYPE) and activated ⊆ rollback keys — the FULL membership
            // is DERIVED from the rollback (there is no separate full
            // argument).
            let should_succeed =
                !activated_raw.is_empty() && activated_raw.is_subset(&rollback_keys);
            match activated_opt {
                None => {
                    prop_assert!(!should_succeed, "empty activated should not succeed");
                }
                Some(activated) => {
                    let res = SuccessfulTerminal::try_new(rollback.clone(), activated.clone());
                    if should_succeed {
                        prop_assert!(res.is_ok(), "try_new should succeed for valid shape, got {res:?}");
                        let st = res.unwrap();
                        // The derived full membership equals the rollback's
                        // keys; the rollback is kept exact.
                        prop_assert_eq!(
                            st.full_membership(),
                            rollback_keys,
                            "the full membership is derived as the rollback's keys"
                        );
                        prop_assert_eq!(st.rollback(), &rollback);
                        // For every Ok, call outcomes() and serialization directly — any panic fails the property
                        let term = LedgerTerminal {
                            recorded_at: "2026-01-01T00:00:00Z".to_string(),
                            disposition: TerminalDisposition::Successful(st),
                            reason: None,
                        };
                        let _outcomes = term.outcomes();
                        let wire_res = LedgerTerminalWire::try_from_domain(
                            &DeploymentId::new("deploy-00000000-0000-7000-8000-000000000001".to_string()),
                            &TargetName::parse("t1").unwrap(),
                            &term,
                        );
                        prop_assert!(wire_res.is_ok(), "try_from_domain should succeed for valid terminal");
                    } else {
                        prop_assert!(res.is_err(), "try_new should fail for invalid shape");
                        prop_assert!(matches!(res.unwrap_err(), crate::error::Error::Integrity(_)));
                    }
                }
            }
        }
    }

    #[test]
    fn successful_terminal_deterministic_cases() {
        let mk_rollback = |slots: Vec<SlotId>| {
            let mut entries = BTreeMap::new();
            for sid in slots.clone() {
                let generation = test_generation_id(sid.as_str());
                let artifact = crate::identity::ArtifactRef {
                    release: test_release_id(sid.as_str()),
                    variant: crate::identity::VariantName::parse("standard").unwrap(),
                    tree: test_tree_digest(sid.as_str()),
                };
                let binding = PhysicalBinding {
                    server: ServerId::parse("s1").unwrap(),
                    deploy_dir: format!("/srv/deploy/{}", sid.as_str()),
                };
                entries.insert(sid, SnapshotEntry::new(generation, artifact, binding));
            }
            TargetSnapshot::from_entries(entries)
        };
        let s1 = slot(1);
        let s2 = slot(2);
        // Case 1: empty activated -> None -> try_new cannot be called, should be considered Err
        let _rb = mk_rollback(vec![s1.clone()]);
        let activated_empty: BTreeSet<SlotId> = BTreeSet::new();
        assert!(crate::identity::NonEmptySlotSet::try_new(activated_empty).is_none());
        // Case 2: activated ⊄ rollback keys -> Err (the 2-arg constructor's
        // obligation is activated ⊆ rollback keys).
        let rb2 = mk_rollback(vec![s1.clone()]);
        let activated =
            crate::identity::NonEmptySlotSet::try_new(vec![s1.clone(), s2.clone()]).unwrap();
        assert!(matches!(
            SuccessfulTerminal::try_new(rb2, activated),
            Err(crate::error::Error::Integrity(_))
        ));
        // Case 3: activated ⊆ rollback keys -> Ok — the FULL membership is
        // DERIVED from the rollback (there is no separate full argument): a
        // subset activated over a superset rollback is the group shape, not
        // a disagreement, and the derived full membership equals the
        // rollback's keys.
        let rb3 = mk_rollback(vec![s1.clone(), s2.clone()]);
        let activated3 = crate::identity::NonEmptySlotSet::try_new(vec![s1.clone()]).unwrap();
        let st3 = SuccessfulTerminal::try_new(rb3.clone(), activated3).unwrap();
        assert_eq!(
            st3.rollback(),
            &rb3,
            "the constructor keeps the rollback exact"
        );
        assert_eq!(
            st3.full_membership(),
            BTreeSet::from([s1.clone(), s2.clone()]),
            "the full membership is derived as the rollback's keys"
        );
        // Case 4: valid combos -> Ok and outcomes/serialization succeed without panic
        let rb4 = mk_rollback(vec![s1.clone(), s2.clone()]);
        let activated4 = crate::identity::NonEmptySlotSet::try_new(vec![s1.clone()]).unwrap();
        let st = SuccessfulTerminal::try_new(rb4, activated4).unwrap();
        let term = LedgerTerminal {
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
            disposition: TerminalDisposition::Successful(st),
            reason: None,
        };
        let _ = term.outcomes();
        let _ = LedgerTerminalWire::try_from_domain(
            &DeploymentId::new("deploy-00000000-0000-7000-8000-000000000001".to_string()),
            &TargetName::parse("t1").unwrap(),
            &term,
        )
        .unwrap();
        // Case 5: activated == rollback keys -> Ok (exact-equal)
        let rb5 = mk_rollback(vec![s1.clone()]);
        let activated5 = crate::identity::NonEmptySlotSet::try_new(vec![s1.clone()]).unwrap();
        let st5 = SuccessfulTerminal::try_new(rb5, activated5).unwrap();
        let term5 = LedgerTerminal {
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
            disposition: TerminalDisposition::Successful(st5),
            reason: None,
        };
        let _ = term5.outcomes();
        let _ = LedgerTerminalWire::try_from_domain(
            &DeploymentId::new("deploy-00000000-0000-7000-8000-000000000001".to_string()),
            &TargetName::parse("t1").unwrap(),
            &term5,
        )
        .unwrap();
    }

    fn arb_slot_outcome() -> impl Strategy<Value = crate::ledger::records::SlotOutcome> {
        (
            prop_oneof![
                Just(crate::ledger::records::SlotOutcomeKind::Activated),
                Just(crate::ledger::records::SlotOutcomeKind::Failed),
                Just(crate::ledger::records::SlotOutcomeKind::Restored),
                Just(crate::ledger::records::SlotOutcomeKind::Skipped),
                Just(crate::ledger::records::SlotOutcomeKind::Compensated),
            ],
            any::<bool>(),
            prop::option::of("boom".prop_map(|s: String| s)),
        )
            .prop_map(|(kind, compensated, error)| {
                let transition = match &kind {
                    crate::ledger::records::SlotOutcomeKind::Restored => {
                        crate::ledger::records::SlotTransition::Restored
                    }
                    crate::ledger::records::SlotOutcomeKind::Skipped => {
                        crate::ledger::records::SlotTransition::NeverAdvanced
                    }
                    crate::ledger::records::SlotOutcomeKind::Activated => {
                        crate::ledger::records::SlotTransition::Advanced
                    }
                    crate::ledger::records::SlotOutcomeKind::Failed => {
                        if compensated {
                            crate::ledger::records::SlotTransition::Restored
                        } else {
                            crate::ledger::records::SlotTransition::AdvanceUnknown
                        }
                    }
                    crate::ledger::records::SlotOutcomeKind::Compensated => {
                        crate::ledger::records::SlotTransition::Restored
                    }
                };
                crate::ledger::records::SlotOutcome {
                    outcome: kind,
                    observation: crate::ledger::records::Observation::Known(
                        crate::ledger::records::ObservedGeneration {
                            generation: test_generation_id("gen-1"),
                        },
                    ),
                    compensated,
                    error,
                    transition,
                }
            })
    }

    fn arb_outcome_table()
    -> impl Strategy<Value = BTreeMap<SlotId, crate::ledger::records::SlotOutcome>> {
        prop::collection::btree_map((0u32..4).prop_map(slot), arb_slot_outcome(), 0..4)
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: crate::testutil::proptest_cases(64),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..Default::default()
        })]
        #[test]
        fn degraded_terminal_protected_constructor(
            outcomes_map in arb_outcome_table()
        ) {
            let is_empty = outcomes_map.is_empty();
            let all_restored = !is_empty && outcomes_map.values().all(|r| r.outcome == crate::ledger::records::SlotOutcomeKind::Restored);
            let has_non_restored = outcomes_map.values().any(|r| r.outcome != crate::ledger::records::SlotOutcomeKind::Restored);
            let non_empty_res = crate::ledger::records::NonEmptySlotTable::build(
                outcomes_map.clone().into_iter()
            );
            if is_empty {
                prop_assert!(non_empty_res.is_err(), "empty table must fail NonEmptySlotTable::build");
            } else {
                prop_assert!(non_empty_res.is_ok(), "non-empty table must build");
                let ne = non_empty_res.unwrap();
                let res = DegradedTerminal::try_new(ne);
                if all_restored {
                    prop_assert!(res.is_err(), "all-restored must be rejected");
                    prop_assert!(matches!(res.unwrap_err(), crate::error::Error::Integrity(_)));
                } else if has_non_restored {
                    prop_assert!(res.is_ok(), "non-empty with >=1 non-restored must be accepted");
                } else {
                    prop_assert!(res.is_err());
                }
            }
        }
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: crate::testutil::proptest_cases(64),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..Default::default()
        })]
        #[test]
        fn terminal_wire_round_trip(
            rollback in arb_rollback(),
            outcomes_map in arb_outcome_table(),
            degraded_map in arb_outcome_table(),
            status_choice in 0u32..4,
        ) {
            let deployment_id = DeploymentId::new("deploy-00000000-0000-7000-8000-000000000001".to_string());
            let target = TargetName::new("t1".to_string());
            let terminal_opt: Option<LedgerTerminal> = match status_choice {
                0 => {
                    let rollback_keys: BTreeSet<SlotId> = rollback.keys().cloned().collect();
                    if rollback_keys.is_empty() {
                        None
                    } else {
                        let activated = crate::identity::NonEmptySlotSet::try_new(rollback_keys.clone()).unwrap();
                        let st = SuccessfulTerminal::try_new(rollback.clone(), activated);
                        st.ok().map(|st| LedgerTerminal {
                            recorded_at: "2026-01-01T00:00:00Z".to_string(),
                            disposition: TerminalDisposition::Successful(st),
                            reason: None,
                        })
                    }
                }
                1 => Some(LedgerTerminal {
                    recorded_at: "2026-01-01T00:00:00Z".to_string(),
                    disposition: TerminalDisposition::FailedPreflight,
                    reason: None,
                }),
                2 => Some(LedgerTerminal {
                    recorded_at: "2026-01-01T00:00:00Z".to_string(),
                    disposition: TerminalDisposition::FailedRolledBack {
                        outcomes: crate::ledger::records::SlotTable::from_map(outcomes_map.clone()),
                    },
                    reason: None,
                }),
                _ => {
                    if degraded_map.is_empty() || degraded_map.values().all(|r| r.outcome == crate::ledger::records::SlotOutcomeKind::Restored) {
                        None
                    } else {
                        let ne = crate::ledger::records::NonEmptySlotTable::build(degraded_map.clone().into_iter()).ok();
                        match ne.and_then(|t| DegradedTerminal::try_new(t).ok()) {
                            Some(dt) => Some(LedgerTerminal {
                                recorded_at: "2026-01-01T00:00:00Z".to_string(),
                                disposition: TerminalDisposition::Degraded(dt),
                                reason: None,
                            }),
                            None => None,
                        }
                    }
                }
            };
            if let Some(terminal) = terminal_opt {
                let wire = LedgerTerminalWire::try_from_domain(&deployment_id, &target, &terminal).expect("try_from_domain must succeed for valid terminal");
                let json = serde_json::to_string(&wire).unwrap();
                let wire2: LedgerTerminalWire = serde_json::from_str(&json).unwrap();
                let back = wire2.into_domain().expect("into_domain must succeed for wire produced by try_from_domain");
                prop_assert_eq!(back, terminal);
            }
        }
    }
}
