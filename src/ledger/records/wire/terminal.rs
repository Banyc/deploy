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
use crate::identity::{DeploymentId, SlotId, TargetName, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::super::observation::{Observation, ObservedGeneration};
use super::super::{CompleteRollback, DeploymentStatus, LedgerRollback, SlotTable};
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalDisposition {
    /// The deployment succeeded: the complete rollback payload (the full
    /// snapshot: per-slot generations + physical bindings — THE single
    /// source of truth for each slot's generation/artifact facts), THE
    /// ACTIVATED SLOT-ID SET (the non-empty set of slots the push
    /// activated — the per-slot generation/artifact facts are NOT stored
    /// again; every consumer derives them from the rollback via
    /// [`LedgerTerminal::outcomes`]), and the TWO PERSISTED MEMBERSHIPS
    /// that PROVE the membership equations: `activated` (the slots the push
    /// actually deployed — EQUAL to the wire's `selected_membership`,
    /// enforced by the conversion) and `full_membership` (the COMPLETE
    /// target membership at terminal time — EQUAL to the rollback's slots,
    /// enforced by the conversion). `activated ⊆ full_membership` is
    /// enforced by the conversion; the FULL-push equality `activated ==
    /// full_membership` is enforced where the terminal merges into its
    /// entry (the mode — group vs full — lives in the intent's `group`).
    /// The rollback is the COMPLETE resulting target snapshot: for a GROUP
    /// push the base-overlay carries the unselected slots forward, so the
    /// rollback's slots ⊇ the activated set (the outcomes cover the
    /// SELECTED slots; the full-push EQUALITY activated == full applies
    /// only to a FULL push, enforced where the terminal merges into its
    /// entry (the mode lives in the intent's `group`).
    Successful {
        rollback: CompleteRollback,
        /// THE ACTIVATED SLOTS — the NON-EMPTY set of slot ids this push
        /// activated (the outcomes' keys; a group push's group slots; a
        /// full push's every target slot). THE SUCCESS REPRESENTATION: the
        /// per-slot GENERATION/ARTIFACT facts are NOT stored here — they
        /// are DERIVED from the rollback (the single source of truth,
        /// [`LedgerTerminal::outcomes`]): the wire → domain conversion
        /// enforces the COMPLETE EQUALITY PREDICATE per activated slot
        /// (Known(g), g == the rollback's generation, error == None,
        /// compensated == false) and then DISCARDS the wire's per-slot
        /// claims. EQUAL to the wire's `selected_membership` by
        /// construction — the conversion refuses a disagreement, so the
        /// record PROVES which slots were selected (every selected slot was
        /// activated).
        activated: BTreeSet<SlotId>,
        /// The FULL membership: the COMPLETE target membership at terminal
        /// time — the rollback's key set (the intent's FROZEN full
        /// membership the terminal REPRODUCES). EQUAL to the rollback's
        /// slots by construction — the conversion refuses a disagreement,
        /// so the record PROVES the complete membership the rollback
        /// snapshot covers.
        full_membership: BTreeSet<SlotId>,
    },
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
    /// all-restored).
    Degraded { outcomes: SlotTable<SlotOutcome> },
}

impl TerminalDisposition {
    /// The disposition's status — the inverse of the wire's
    /// status→disposition mapping (a domain terminal derives its status
    /// from its disposition; the two are never stored side by side).
    pub fn status(&self) -> DeploymentStatus {
        match self {
            TerminalDisposition::Successful { .. } => DeploymentStatus::Successful,
            TerminalDisposition::FailedPreflight => DeploymentStatus::FailedPreflight,
            TerminalDisposition::FailedRolledBack { .. } => DeploymentStatus::FailedRolledBack,
            TerminalDisposition::Degraded { .. } => DeploymentStatus::Degraded,
        }
    }

    pub fn is_successful(&self) -> bool {
        matches!(self, TerminalDisposition::Successful { .. })
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
            TerminalDisposition::Successful {
                rollback,
                activated,
                ..
            } => {
                // THE DERIVED VIEW: every activated slot's per-slot outcome
                // facts ARE the rollback's authoritative generation — never
                // stored/trusted separately. Every activated slot is a
                // rollback slot (the conversion enforced activated ==
                // selected ⊆ full == the rollback's slots).
                let map: BTreeMap<SlotId, SlotOutcome> = activated
                    .iter()
                    .map(|sid| {
                        let rb = rollback.get(sid).expect(
                            "a Successful terminal's activated slots are always covered by its rollback — the conversion enforces activated ⊆ rollback == full",
                        );
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
            TerminalDisposition::FailedRolledBack { outcomes }
            | TerminalDisposition::Degraded { outcomes } => outcomes.clone(),
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
    pub fn selected_membership(&self) -> Option<&BTreeSet<SlotId>> {
        match &self.disposition {
            TerminalDisposition::Successful { activated, .. } => Some(activated),
            _ => None,
        }
    }

    /// The terminal's FULL MEMBERSHIP — the COMPLETE target membership at
    /// terminal time (the intent's FROZEN full membership the terminal
    /// REPRODUCES; the rollback's key set). PERSISTED in the record and
    /// EQUAL to the rollback's slots by construction (the wire → domain
    /// conversion refuses a disagreement), so a consumer can display or
    /// prove the complete membership the rollback snapshot covers WITHOUT
    /// re-deriving it from the current configuration. `None` for every
    /// non-Successful disposition.
    pub fn full_membership(&self) -> Option<&BTreeSet<SlotId>> {
        match &self.disposition {
            TerminalDisposition::Successful {
                full_membership, ..
            } => Some(full_membership),
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
    pub rollback: Option<LedgerRollback>,
    /// The SELECTED membership — the slots this deployment actually
    /// selected / deployed (the outcomes' keys; a group push's group
    /// slots; a full push's every target slot). REQUIRED since schema v3
    /// (no serde default — an old-shape terminal line fails
    /// deserialization fail-closed): the wire → domain conversion requires
    /// it DUPLICATE-FREE and — for a `Successful` status — NON-EMPTY and
    /// EXACTLY EQUAL to the outcomes' keys, so the record PROVES which
    /// slots were selected.
    pub selected_membership: Vec<SlotId>,
    /// The FULL membership — the COMPLETE target membership at terminal
    /// time (the intent's FROZEN full membership the terminal REPRODUCES).
    /// REQUIRED since schema v3 (no serde default): the wire → domain
    /// conversion requires it DUPLICATE-FREE and — for a `Successful`
    /// status — NON-EMPTY and EXACTLY EQUAL to the rollback's slots, so
    /// the record PROVES the complete membership the rollback snapshot
    /// covers.
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
    /// converted through [`LedgerRollbackWire::into_domain`] (which fails
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
        let full_membership =
            membership_wire_to_set(&self.deployment_id, "full_membership", self.full_membership)?;
        // Only a Successful terminal proves a membership: a failed status
        // carrying memberships is dead, unenforced data — refused (fail
        // closed), never silently dropped.
        if self.status != DeploymentStatus::Successful
            && (!selected_membership.is_empty() || !full_membership.is_empty())
        {
            return Err(Error::integrity(format!(
                "terminal {}: status {:?} must carry NO memberships — only a Successful terminal records its selected/full membership (the memberships prove the push)",
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
                    &full_membership,
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
                TerminalDisposition::Successful {
                    rollback,
                    activated: outcome_keys,
                    full_membership,
                }
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
                if outcomes
                    .values()
                    .all(|r| r.outcome == SlotOutcomeKind::Restored)
                {
                    return Err(Error::integrity(format!(
                        "terminal {}: status Degraded requires at least one non-restored outcome (an all-restored attempt is FailedRolledBack, never Degraded)",
                        self.deployment_id
                    )));
                }
                TerminalDisposition::Degraded { outcomes }
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
    pub fn from_domain(
        deployment_id: &DeploymentId,
        target: &TargetName,
        t: &LedgerTerminal,
    ) -> Self {
        let rollback = match &t.disposition {
            TerminalDisposition::Successful { rollback, .. } => Some(rollback.clone()),
            _ => None,
        };
        let (selected_membership, full_membership) = match &t.disposition {
            TerminalDisposition::Successful {
                activated,
                full_membership,
                ..
            } => (
                activated.iter().cloned().collect(),
                full_membership.iter().cloned().collect(),
            ),
            _ => (Vec::new(), Vec::new()),
        };
        LedgerTerminalWire {
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
            full_membership,
            reason: t.reason.clone(),
        }
    }
}
