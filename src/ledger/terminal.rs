//! The TERMINAL records of the deployment ledger (feature area A2 "two line
//! kinds — terminal"): the terminal wire/domain pair ([`LedgerTerminalWire`]
//! / [`LedgerTerminal`]) with the VERIFYING CONVERSION, the
//! [`TerminalDisposition`] enum (each disposition OWNS its per-slot outcome
//! table), and the status accessor. The outcome DERIVATIONS
//! ([`LedgerTerminal::remaining_changes`], [`LedgerTerminal::compensation`])
//! live in [`crate::ledger::outcomes`]; the physical
//! [`crate::ledger::append::LedgerLine::Terminal`] line lives in
//! [`crate::ledger::append`].

use crate::error::{Error, Result};
use crate::identity::{DeploymentId, SlotId, TargetName, Timestamp};
use crate::ledger::outcomes::{SlotOutcome, SlotOutcomeKind};
use crate::ledger::records::{
    CompleteRollback, DeploymentStatus, LedgerRollbackWire, SlotResult, SlotTable,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The DISPOSITION of a deployment's terminal event — the DOMAIN replaces
/// the wire's `status: String` + optional rollback TAG-PLUS-OPTIONAL-PAYLOAD
/// shape with an ENUM whose variants carry exactly the payload their
/// disposition allows, so the STATUS/ROLLBACK TRUTH TABLE is STRUCTURAL
/// (unrepresentable-invalid states simply do not exist in the domain):
///
/// * [`TerminalDisposition::Successful`] ALWAYS carries its complete
///   rollback payload (a successful deployment always records its rollback
///   state — the generation refs + physical bindings, the ONE fact the
///   per-slot outcomes cannot express) AND its OWN per-slot outcomes table
///   (every outcome Activated) AND the TWO PERSISTED MEMBERSHIPS —
///   `selected_membership` (the slots the push actually deployed, EQUAL to
///   the outcomes' keys) and `full_membership` (the COMPLETE target
///   membership at terminal time, EQUAL to the rollback's slots) — so the
///   record PROVES the membership equations instead of implying them. The
///   rollback is the COMPLETE resulting target snapshot: for a GROUP push
///   the base-overlay carries the unselected slots forward, so the
///   rollback's slots ⊇ the outcomes' keys (the outcomes cover the
///   SELECTED slots; for a FULL push the terminal's own memberships satisfy
///   selected == full — enforced where the terminal merges into its entry,
///   via the intent's `group`).
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
/// disagree with. The disposition carries ONLY what the outcomes cannot
/// express (the Successful rollback payload). The WIRE keeps the current
/// `status` + `rollback` shape; the wire → domain conversion maps every
/// status to EXACTLY ONE disposition and refuses a status whose payload does
/// not match its disposition (a `Successful` with no rollback, a failed
/// status carrying a rollback, a `Degraded` whose outcomes show all-restored,
/// a `Successful` whose outcomes disagree with the rollback's slots, an
/// `InProgress`/`PendingCommit` terminal — all are conversion errors, fail
/// closed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalDisposition {
    /// The deployment succeeded: the complete rollback payload (the full
    /// snapshot: per-slot generations + physical bindings — the ONE fact
    /// the per-slot outcomes cannot express), the disposition's OWN
    /// per-slot outcomes table (every outcome Activated — enforced by the
    /// conversion), and the TWO PERSISTED MEMBERSHIPS that PROVE the
    /// membership equations: `selected_membership` (the slots the push
    /// actually deployed — EQUAL to the outcomes' keys, enforced by the
    /// conversion) and `full_membership` (the COMPLETE target membership
    /// at terminal time — EQUAL to the rollback's slots, enforced by the
    /// conversion). `selected_membership ⊆ full_membership` is enforced by
    /// the conversion; the FULL-push equality `selected_membership ==
    /// full_membership` is enforced where the terminal merges into its
    /// entry (the mode — group vs full — lives in the intent's `group`).
    /// The rollback is the COMPLETE resulting target snapshot: for a GROUP
    /// push the base-overlay carries the unselected slots forward, so the
    /// rollback's slots ⊇ the outcomes' keys (the outcomes cover the
    /// SELECTED slots; the full-push EQUALITY selected == full applies only
    /// to a FULL push, enforced where the terminal merges into its entry
    /// (the mode lives in the intent's `group`).
    Successful {
        rollback: CompleteRollback,
        outcomes: SlotTable<SlotOutcome>,
        /// The SELECTED membership: the slots this deployment actually
        /// selected / deployed — the outcomes' keys (a group push's group
        /// slots; a full push's every target slot). EQUAL to the outcomes'
        /// keys by construction — the conversion refuses a disagreement,
        /// so the record PROVES which slots were selected.
        selected_membership: BTreeSet<SlotId>,
        /// The FULL membership: the COMPLETE target membership at terminal
        /// time — the rollback's key set (the `current_slot_ids` the
        /// engine computes). EQUAL to the rollback's slots by construction
        /// — the conversion refuses a disagreement, so the record PROVES
        /// the complete membership the rollback snapshot covers.
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
/// `deployment_id` / `target` — the merged [`crate::ledger::append::LedgerEntry`] owns them (the
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
    /// the disposition's OWN table).
    pub disposition: TerminalDisposition,
    /// Optional human context: why this terminal event happened. A
    /// free-form NOTE, not a fact — it never participates in invariants
    /// (the disposition is the machine fact).
    pub reason: Option<String>,
}

/// The empty outcomes table a [`TerminalDisposition::FailedPreflight`]
/// terminal yields through [`LedgerTerminal::outcomes`] — the disposition
/// carries NO outcomes (a pre-mutation failure touched no slot), so the
/// accessor yields an empty table rather than `None`.
static EMPTY_OUTCOMES: SlotTable<SlotOutcome> = SlotTable::new();

impl LedgerTerminal {
    /// The terminal's status, DERIVED from its disposition (never stored
    /// separately — a status and a disposition can never disagree).
    pub fn status(&self) -> DeploymentStatus {
        self.disposition.status()
    }

    /// The terminal's per-slot outcomes — the disposition's OWN table (each
    /// disposition carries its outcomes; a
    /// [`TerminalDisposition::FailedPreflight`] terminal carries none, so
    /// the accessor yields an empty table). THE AUTHORITATIVE per-slot
    /// facts live ONCE, inside the disposition — there is no separate
    /// outcomes field to disagree with.
    pub fn outcomes(&self) -> &SlotTable<SlotOutcome> {
        match &self.disposition {
            TerminalDisposition::Successful { outcomes, .. } => outcomes,
            TerminalDisposition::FailedPreflight => &EMPTY_OUTCOMES,
            TerminalDisposition::FailedRolledBack { outcomes } => outcomes,
            TerminalDisposition::Degraded { outcomes } => outcomes,
        }
    }

    /// The terminal's SELECTED MEMBERSHIP — the slots this deployment
    /// actually selected / deployed (the outcomes' keys; for a group push
    /// the group's slots; for a full push every target slot). PERSISTED in
    /// the record and EQUAL to the outcomes' keys by construction (the
    /// wire → domain conversion refuses a disagreement), so a consumer can
    /// display or prove which slots the push selected WITHOUT re-deriving
    /// it from the intent. `None` for every non-Successful disposition
    /// (a failed attempt never proves a membership).
    pub fn selected_membership(&self) -> Option<&BTreeSet<SlotId>> {
        match &self.disposition {
            TerminalDisposition::Successful {
                selected_membership,
                ..
            } => Some(selected_membership),
            _ => None,
        }
    }

    /// The terminal's FULL MEMBERSHIP — the COMPLETE target membership at
    /// terminal time (the `current_slot_ids` the engine computed; the
    /// rollback's key set). PERSISTED in the record and EQUAL to the
    /// rollback's slots by construction (the wire → domain conversion
    /// refuses a disagreement), so a consumer can display or prove the
    /// complete membership the rollback snapshot covers WITHOUT
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback: Option<LedgerRollbackWire>,
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
    /// time (the `current_slot_ids` the engine computes). REQUIRED since
    /// schema v3 (no serde default): the wire → domain conversion requires
    /// it DUPLICATE-FREE and — for a `Successful` status — NON-EMPTY and
    /// EXACTLY EQUAL to the rollback's slots, so the record PROVES the
    /// complete membership the rollback snapshot covers.
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
        let rollback = match self.rollback {
            Some(wire) => Some(wire.into_domain()?),
            None => None,
        };
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
        // ([`SlotOutcome::from_wire`]) and DROPPING the wire outcome's
        // redundant `slot_id` into the key (the domain value carries no slot
        // — the table key owns identity; the own-key agreement above
        // verified the wire's claim before the drop).
        let outcomes: SlotTable<SlotOutcome> = SlotTable::from_map(self.outcomes);
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
                let rollback_slot_keys: BTreeSet<SlotId> = rollback.slots.keys().cloned().collect();
                // THE MEMBERSHIP EQUATIONS (terminal-local half) are enforced
                // by the SHARED helper in [`crate::ledger::membership`]:
                // outcomes == selected_membership, rollback slots ==
                // full_membership, and selected_membership ⊆
                // full_membership (plus the non-empty guards — a successful
                // deployment always records non-empty outcomes and both
                // memberships). The FULL-push EQUALITY (selected == full) is
                // the cross-record leg enforced where the terminal merges
                // into its entry (the mode — group vs full — lives in the
                // intent's `group`).
                crate::ledger::membership::verify_successful_membership_equations(
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
                TerminalDisposition::Successful {
                    rollback,
                    outcomes,
                    selected_membership,
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
    /// target) identity — the enclosing [`crate::ledger::append::LedgerEntry`] owns the identity,
    /// so the wire's `deployment_id` / `target` come from the CALLER (the
    /// append path), never from the domain terminal. A Successful terminal's
    /// two memberships are emitted from the disposition; every other
    /// disposition emits EMPTY memberships (only a Successful terminal
    /// records them — the conversion refuses a failed status carrying any).
    pub fn from_domain(
        deployment_id: &DeploymentId,
        target: &TargetName,
        t: &LedgerTerminal,
    ) -> Self {
        let rollback = match &t.disposition {
            TerminalDisposition::Successful { rollback, .. } => {
                Some(LedgerRollbackWire::from(rollback))
            }
            _ => None,
        };
        let (selected_membership, full_membership) = match &t.disposition {
            TerminalDisposition::Successful {
                selected_membership,
                full_membership,
                ..
            } => (
                selected_membership.iter().cloned().collect(),
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
