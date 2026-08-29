//! THE TRANSITION FACET of the semantic kernel (feature area: the pure
//! deployment semantic kernel) — the ONE pure state machine all ledger
//! transitions go through.
//!
//! [`apply_event`] owns the complete acceptance rules of the deployment
//! ledger as a pure function over a [`DeploymentState`] and a
//! [`LedgerEvent`]. The LEDGER LAYER (the store) is reduced to a strict
//! event store — strict parsing, duplicate-key rejection, event ordering,
//! one intent per deployment, at most one terminal per intent, terminal
//! `intent_digest` equality, durable append — and delegates the SEMANTIC
//! validation of every accepted event transition to THIS machine. The
//! deployment ENGINE gathers evidence; it never constructs terminal
//! variants itself ([`decide_terminal`] owns the complete truth table).
//!
//! [`Checkpoint`](LedgerEvent::Checkpoint) events are accepted only as the
//! FIRST event of a ledger state (the atomic suffix replacement writes the
//! checkpoint event as the new ledger's first line, recording the discarded
//! prefix).

use crate::identity::{DeploymentId, SlotId, TargetName, Timestamp};
use crate::kernel::error::{KernelError, KernelResult};
use crate::kernel::intent::DeploymentIntent;
use crate::kernel::terminal::{LedgerTerminal, TerminalDisposition};
use crate::ledger::LedgerEntry;
use crate::ledger::records::DeploymentStatus;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// ONE ledger event — the pure, domain-validated form of the wire's
/// [`crate::ledger::LedgerEventWire`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerEvent {
    Intent(IntentEvent),
    Terminal(TerminalEvent),
    Checkpoint(CheckpointEvent),
}

/// The intent event: the durable intent line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntentEvent {
    pub intent: DeploymentIntent,
}

/// The terminal event: the terminal line bound to its intent by digest. The
/// DEPLOYMENT ID is the wire's keying identity (the enclosing entry owns
/// identity — the DOMAIN terminal carries none); the kernel verifies the
/// digest binds the terminal to exactly that entry's intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalEvent {
    pub deployment_id: DeploymentId,
    pub terminal: LedgerTerminal,
}

/// The checkpoint event: the ledger was atomically replaced by its retained
/// suffix — this event is the new ledger's FIRST line, recording which
/// deployment the retained suffix starts at and how many entries were
/// discarded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointEvent {
    /// The deployment the retained suffix starts at (the checkpoint
    /// deployment).
    pub retained_from: DeploymentId,
    /// How many ledger entries were discarded by the compaction.
    pub discarded: u64,
    pub recorded_at: Timestamp,
}

/// THE PURE LEDGER STATE: one deployment target's accepted event sequence,
/// merged into ordered entries. `apply_event` is the ONLY way to grow it.
#[derive(Clone, Debug)]
pub struct DeploymentState {
    target: TargetName,
    entries: Vec<LedgerEntry>,
    by_id: BTreeMap<DeploymentId, usize>,
    checkpoint: Option<CheckpointEvent>,
    /// The number of PHYSICAL lines accepted so far (the checkpoint counts
    /// as line 0): an entry's `seq` is its intent line's physical position.
    lines: u64,
}

impl DeploymentState {
    /// The empty state for ONE deployment target — every event's intent
    /// must name this target (an event for another target is refused).
    pub fn new(target: TargetName) -> Self {
        Self {
            target,
            entries: Vec::new(),
            by_id: BTreeMap::new(),
            checkpoint: None,
            lines: 0,
        }
    }

    pub fn target(&self) -> &TargetName {
        &self.target
    }

    /// The accepted entries, in appends order (the state's history). A
    /// leading checkpoint event is NOT an entry — it is state metadata.
    pub fn entries(&self) -> &[LedgerEntry] {
        &self.entries
    }

    pub fn into_entries(self) -> Vec<LedgerEntry> {
        self.entries
    }

    /// The recorded checkpoint compaction, if the ledger began with one.
    pub fn checkpoint(&self) -> Option<&CheckpointEvent> {
        self.checkpoint.as_ref()
    }

    /// The ledger-position assigned to the NEXT intent line: the physical
    /// line position (a leading checkpoint event occupies line 0 when
    /// present).
    pub fn next_seq(&self) -> u64 {
        self.lines
    }

    /// The deployment id of the current successful head (the newest
    /// successful entry), derived from the state — never stored.
    pub fn successful_head(&self) -> Option<&DeploymentId> {
        self.entries
            .iter()
            .rev()
            .find(|e| {
                e.terminal
                    .as_ref()
                    .is_some_and(|t| t.status() == DeploymentStatus::Successful)
            })
            .map(|e| &e.deployment_id)
    }
}

/// THE ONE accepted-event machine: fold one event into the state, refusing
/// every impossible transition (fail closed — [`KernelError::Integrity`]
/// for impossible persisted sequences, [`KernelError::Conflict`] for
/// stale/concurrent plans).
pub fn apply_event(
    mut state: DeploymentState,
    event: LedgerEvent,
) -> KernelResult<DeploymentState> {
    match event {
        LedgerEvent::Checkpoint(cp) => {
            // A checkpoint event is accepted ONLY as the first event of a
            // ledger (the atomic suffix replacement produces a ledger whose
            // first line is the checkpoint event).
            if !state.entries.is_empty() || state.checkpoint.is_some() {
                return Err(KernelError::integrity(format!(
                    "a checkpoint event must be the first event of a ledger — deployment '{}' retained at position {}",
                    cp.retained_from,
                    state.entries.len()
                )));
            }
            state.checkpoint = Some(cp);
            state.lines += 1;
            Ok(state)
        }
        LedgerEvent::Intent(IntentEvent { intent }) => {
            // ONE INTENT PER DEPLOYMENT (event-store rule).
            if intent.target() != &state.target {
                return Err(KernelError::integrity(format!(
                    "an intent for deployment '{}' names target '{}' but the ledger is for target '{}'",
                    intent.deployment_id(),
                    intent.target(),
                    state.target
                )));
            }
            if state.by_id.contains_key(intent.deployment_id()) {
                return Err(KernelError::integrity(format!(
                    "two intent events for deployment '{}' — the ledger is keyed by deployment id (one intent per deployment)",
                    intent.deployment_id()
                )));
            }
            let entry = LedgerEntry {
                deployment_id: intent.deployment_id().clone(),
                target: state.target.clone(),
                intent,
                terminal: None,
                seq: state.next_seq(),
            };
            state
                .by_id
                .insert(entry.deployment_id.clone(), state.entries.len());
            state.lines += 1;
            state.entries.push(entry);
            Ok(state)
        }
        LedgerEvent::Terminal(TerminalEvent {
            deployment_id,
            terminal,
        }) => {
            // The terminal event comes AFTER its intent; the intent's
            // canonical digest is the binding key (THE STORE'S intent_digest
            // equality rule, validated HERE as the semantic transition).
            let digest = terminal.intent_digest().clone();
            let pos = state.by_id.get(&deployment_id).copied().ok_or_else(|| {
                KernelError::integrity(format!(
                    "a terminal event for deployment '{deployment_id}' has no intent line — a terminal requires its durable intent"
                ))
            })?;
            let entry = &state.entries[pos];
            if crate::kernel::terminal::intent_digest(&entry.intent) != digest {
                return Err(KernelError::integrity(format!(
                    "terminal for deployment '{deployment_id}' binds intent digest {digest} but the intent's canonical digest is {} — a terminal must bind the EXACT canonical intent",
                    crate::kernel::terminal::intent_digest(&entry.intent)
                )));
            }
            // AT MOST ONE TERMINAL PER INTENT (event-store rule).
            if entry.terminal.is_some() {
                return Err(KernelError::integrity(format!(
                    "two terminal events for deployment '{deployment_id}' — the terminal event is written exactly once"
                )));
            }
            validate_terminal_vs_intent(entry, &terminal)?;
            let mut entry = state.entries[pos].clone();
            entry.terminal = Some(terminal);
            state.entries[pos] = entry;
            state.lines += 1;
            Ok(state)
        }
    }
}

/// THE CROSS-RECORD TERMINAL AGREEMENT (the semantics the event store
/// delegates to the kernel): the terminal's disposition must agree with its
/// intent —
///
/// * outcome keys ⊆ the intent's SELECTED (Deploy) slots — a terminal never
///   reports a slot the deployment did not select;
/// * status-specific coverage: `Successful` and `FailedPreflight` carry no
///   outcomes; `FailedRolledBack` / `Degraded` outcomes EXACTLY cover the
///   selected membership.
pub fn validate_terminal_vs_intent(
    entry: &LedgerEntry,
    terminal: &LedgerTerminal,
) -> KernelResult<()> {
    let selected: BTreeSet<SlotId> = entry.intent.selected_membership();
    let outcome_keys: BTreeSet<SlotId> = terminal.outcomes().keys().cloned().collect();
    for key in &outcome_keys {
        if !selected.contains(key) {
            return Err(KernelError::integrity(format!(
                "terminal for deployment '{}' records an outcome for slot '{key}' outside the intent's selected membership — every outcome must name a selected slot",
                entry.deployment_id
            )));
        }
    }
    match terminal.disposition() {
        TerminalDisposition::Successful | TerminalDisposition::FailedPreflight => {
            if !outcome_keys.is_empty() {
                return Err(KernelError::integrity(format!(
                    "terminal {:?} for deployment '{}' carries outcomes for slots {outcome_keys:?} — a payload-free disposition records none",
                    terminal.status(),
                    entry.deployment_id
                )));
            }
        }
        TerminalDisposition::FailedRolledBack(_) | TerminalDisposition::Degraded(_) => {
            if outcome_keys != selected {
                return Err(KernelError::integrity(format!(
                    "terminal {:?} for deployment '{}' carries outcomes for slots {outcome_keys:?} but its intent's selected membership is {selected:?} — every selected slot has exactly one outcome, no extras",
                    terminal.status(),
                    entry.deployment_id
                )));
            }
        }
    }
    Ok(())
}

/// The engine's gathered evidence, handed to [`decide_terminal`]: the
/// engine GATHERS EVIDENCE (did preflight fail? were the selected slots
/// verified at their planned result? on a failure, was every attempted
/// mutation restored or never advanced? what per-slot outcomes remain?)
/// and the kernel OWNS the truth table.
#[derive(Clone, Debug)]
pub struct ExecutionReport {
    /// The attempt's preflight failed before any slot mutation.
    pub preflight_failed: bool,
    /// Execution succeeded AND the selected slots were verified at their
    /// planned result.
    pub verified: bool,
    /// On a failed execution: every attempted mutation was restored or
    /// never advanced (the engine's failure-policy evidence; `leave_changed`
    /// retentions and failed compensations leave something changed).
    pub all_restored: bool,
    /// The per-slot outcomes of a failed execution (restored /
    /// never-advanced / remaining changes).
    pub outcomes: crate::ledger::records::SlotTable<crate::ledger::records::SlotOutcome>,
}

/// THE COMPLETE TRUTH TABLE of the terminal decision — the ONLY place a
/// terminal disposition is decided:
///
/// * preflight failed                → `FailedPreflight`
/// * execution succeeded AND verified → `Successful`
/// * failure and everything restored  → `FailedRolledBack`
/// * anything remains changed/unknown → `Degraded`
///
/// The outcome payloads are constructed ONLY through the validated
/// constructors, so an impossible combination (a rolled-back terminal with
/// an Advanced slot; a Degraded terminal with all-restored outcomes) is
/// unrepresentable.
pub fn decide_terminal(
    _intent: &DeploymentIntent,
    report: ExecutionReport,
) -> KernelResult<TerminalDisposition> {
    if report.preflight_failed {
        return Ok(TerminalDisposition::FailedPreflight);
    }
    if report.verified {
        return Ok(TerminalDisposition::Successful);
    }
    // Failed execution: everything restored or never advanced → rolled back;
    // anything remaining → degraded.
    if report.all_restored {
        let payload = crate::kernel::terminal::FailedRolledBackTerminal::try_new(report.outcomes)?;
        Ok(TerminalDisposition::FailedRolledBack(payload))
    } else {
        let non_empty = crate::ledger::NonEmptySlotTable::build(
            report.outcomes.iter().map(|(k, v)| (k.clone(), v.clone())),
        )
        .map_err(|e| {
            KernelError::invariant(format!(
                "a degraded decision requires at least one outcome: {e}"
            ))
        })?;
        let payload = crate::kernel::terminal::DegradedTerminal::try_new(non_empty)?;
        Ok(TerminalDisposition::Degraded(payload))
    }
}
