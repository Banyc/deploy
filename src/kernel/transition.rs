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
//! # THE ONE-PARENT RULE lives HERE
//!
//! The `Intent-only → Successful` transition (a [`LedgerEvent::Terminal`]
//! carrying a [`TerminalDisposition::Successful`] for an intent whose entry
//! has no terminal yet) enforces AT MOST ONE `Successful` PER PARENT within
//! the observable window — enforced in [`apply_event`] itself, with NO
//! bypass: recovery is a CALLER of the same transition, not a second
//! authority. Within the observable window that IS the lineage invariant
//! `intent.parent == current successful head` (a parent that is present is
//! a successful head, and it may have produced only one child); the
//! checkpoint-retained boundary entry's parent lies OUTSIDE the window but
//! was validated at its original append, and it can never be duplicated
//! in-window. The parent/head check and the append are atomic under the
//! ledger's single-writer authority (the target lock the append already
//! holds), so for any given parent at most ONE plan can ever append
//! `Successful`; the second one to finalize observes a drifted head and is
//! REFUSED with [`KernelError::Conflict`] (StalePlan) — never reconciled
//! implicitly, never successful. This makes the lineage invariant
//! STRUCTURAL: every Successful entry's parent equals its predecessor head
//! (as validated at append time), so
//! [`crate::kernel::snapshot::resolve_snapshot`] always derives from a head
//! whose inherited entries were valid at append time.
//!
//! [`Checkpoint`](LedgerEvent::Checkpoint) events are accepted only as the
//! FIRST event of a ledger state (the atomic suffix replacement writes the
//! checkpoint event as the new ledger's first line, recording the discarded
//! prefix).
//!
//! # THE STRICT-LINEAR MODEL (the lineage gates live HERE)
//!
//! The spec feature is STRICTLY LINEAR successful history: at most ONE
//! unresolved (pending) intent exists at any time; every ORDINARY intent's
//! parent must equal the current successful head AT INTENT-APPEND TIME; a
//! terminal must belong to the pending intent; and a push that cannot
//! finish a previous pending attempt is REFUSED with a [`Conflict`](KernelError::Conflict)
//! (KernelError::Conflict) — never planning a second intent on top (even
//! for disjoint groups). [`apply_event`] owns the accept/reject decisions:
//!
//! * an ORDINARY intent is refused with
//!   [`Integrity`](KernelError::Integrity) when a pending attempt already
//!   exists ([`LineageViolation::PendingAttemptExists`](crate::kernel::lineage::LineageViolation::PendingAttemptExists)) or when its parent
//!   is not the successful head ([`LineageViolation::ParentMismatch`](crate::kernel::lineage::LineageViolation::ParentMismatch)),
//!   and when an inherited slot disagrees with the head's snapshot
//!   ([`validate_inherited_slots`]);
//! * a TERMINAL must belong to the pending intent — ANY terminal clears the
//!   pending attempt, only a `Successful` terminal advances the successful
//!   head;
//! * the CHECKPOINT ANCHOR is the model's ONE exception: a checkpointed
//!   ledger's first intent must be the checkpoint deployment itself, may
//!   reference a parent OUTSIDE the retained suffix (its parent-equality
//!   and inherited-slot checks are skipped), and must be finalized
//!   `Successful` — every later intent follows the ordinary linear rule
//!   (its parent must equal the head, which starts as the anchor).
//!
//! The one-parent scan on a `Successful` terminal remains as a DEFENSIVE
//! re-check (subsumed by the intent-append gates — with one pending at a
//! time and a terminal-must-be-pending, a `Successful` terminal's parent is
//! the head by construction), and it still guards the checkpoint window.

use crate::identity::{DeploymentId, SlotId, TargetName, Timestamp};
use crate::kernel::error::{ConflictError, IntegrityError, KernelError, KernelResult};
use crate::kernel::intent::DeploymentIntent;
use crate::kernel::terminal::{
    DegradedTerminal, FailedRolledBackTerminal, LedgerTerminal, SlotDelta, TerminalDisposition,
};
use crate::ledger::LedgerEntry;
use crate::ledger::records::DeploymentStatus;
use crate::ledger::records::{NonEmptySlotTable, SlotOutcome, SlotTable};
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
///
/// THE STRICT-LINEAR FIELDS: [`successful_head`](Self::successful_head) is
/// the current successful head (MAINTAINED, never derived — it replaces
/// the old backwards scan) and [`pending`](Self::pending) is the ONE
/// unresolved (terminal-less) intent, if any. Both are updated exclusively
/// inside [`apply_event`]: an intent (ordinary) becomes the pending attempt
/// (refused when one already exists or its parent is not the head); a
/// terminal must belong to the pending attempt, ANY terminal clears it,
/// and only a `Successful` terminal advances the head. The checkpoint
/// anchor of a checkpointed ledger is the model's one exception (see
/// [`apply_event`]).
#[derive(Clone, Debug)]
pub struct DeploymentState {
    target: TargetName,
    entries: Vec<LedgerEntry>,
    by_id: BTreeMap<DeploymentId, usize>,
    checkpoint: Option<CheckpointEvent>,
    /// The number of PHYSICAL lines accepted so far (the checkpoint counts
    /// as line 0): an entry's `seq` is its intent line's physical position.
    lines: u64,
    /// The current successful head — the newest `Successful` entry's
    /// deployment id (MAINTAINED by [`apply_event`], never derived).
    successful_head: Option<DeploymentId>,
    /// The ONE unresolved (terminal-less) intent, if any. An intent without
    /// a terminal IS the pending state; at most ONE may exist at a time.
    pending: Option<DeploymentId>,
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
            successful_head: None,
            pending: None,
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
    /// successful entry) — MAINTAINED by [`apply_event`] (a `Successful`
    /// terminal advances it), never derived by a scan. `None` on a ledger
    /// with no successful entry yet (the checkpoint anchor's `Successful`
    /// terminal is the one exception that establishes it).
    pub fn successful_head(&self) -> Option<&DeploymentId> {
        self.successful_head.as_ref()
    }

    /// The ONE unresolved (terminal-less) intent: an intent WITHOUT a
    /// terminal IS the pending state. At most ONE pending attempt may exist
    /// at a time (the strictly-linear model) — an ordinary intent is
    /// refused while this is `Some`.
    pub fn pending(&self) -> Option<&DeploymentId> {
        self.pending.as_ref()
    }

    /// The current successful head's RESOLVED RESULTING SNAPSHOT (the
    /// overlay base every ordinary intent's inherited slots must reproduce;
    /// `None` when the ledger has no successful head yet — there are no
    /// inherited slots to check against). Resolves from the head entry via
    /// [`crate::kernel::snapshot::resolve_snapshot`] (the head is
    /// `Successful` by construction, so the resolution cannot fail for a
    /// maintained state).
    pub fn successful_snapshot(&self) -> KernelResult<Option<crate::ledger::TargetSnapshot>> {
        let Some(head) = &self.successful_head else {
            return Ok(None);
        };
        let pos = self.by_id.get(head).ok_or_else(|| {
            KernelError::Integrity(IntegrityError::Message(format!(
                "the maintained successful head '{head}' has no entry in the state — the state machine invariant is broken"
            )))
        })?;
        crate::kernel::snapshot::resolve_snapshot(&self.entries[*pos]).map(Some)
    }

    /// STRUCTURAL COMPLETENESS of a fully-read ledger (called after the
    /// whole event fold, e.g. from the store's `read_ledger`): a ledger
    /// that began with a CHECKPOINT event must carry its SUCCESSFUL ANCHOR —
    /// the checkpoint's `retained_from` entry must exist AND have been
    /// finalized `Successful` (the retained suffix starts at the checkpoint
    /// deployment). Also rejects a structurally incomplete checkpoint
    /// prefix (a checkpoint event with no following anchor at all, or an
    /// anchor that never reached its `Successful` terminal). A non-
    /// checkpointed ledger passes trivially.
    pub fn finish(&self) -> KernelResult<()> {
        let Some(cp) = &self.checkpoint else {
            return Ok(());
        };
        let Some(&pos) = self.by_id.get(&cp.retained_from) else {
            return Err(KernelError::Integrity(
                IntegrityError::CheckpointAnchorMismatch {
                    retained_from: cp.retained_from.clone(),
                    first_intent: None,
                },
            ));
        };
        let entry = &self.entries[pos];
        let success = entry
            .terminal
            .as_ref()
            .is_some_and(|t| t.status() == DeploymentStatus::Successful);
        if !success {
            return Err(KernelError::Integrity(
                IntegrityError::CheckpointAnchorMismatch {
                    retained_from: cp.retained_from.clone(),
                    first_intent: Some(entry.deployment_id.clone()),
                },
            ));
        }
        Ok(())
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
                return Err(KernelError::Integrity(IntegrityError::Message(format!(
                    "a checkpoint event must be the first event of a ledger — deployment '{}' retained at position {}",
                    cp.retained_from,
                    state.entries.len()
                ))));
            }
            state.checkpoint = Some(cp);
            state.lines += 1;
            Ok(state)
        }
        LedgerEvent::Intent(IntentEvent { intent }) => {
            // ONE INTENT PER DEPLOYMENT (event-store rule).
            if intent.target() != &state.target {
                return Err(KernelError::Integrity(IntegrityError::Message(format!(
                    "an intent for deployment '{}' names target '{}' but the ledger is for target '{}'",
                    intent.deployment_id(),
                    intent.target(),
                    state.target
                ))));
            }
            if let Some(&first_pos) = state.by_id.get(intent.deployment_id()) {
                return Err(KernelError::Integrity(IntegrityError::DuplicateIntent {
                    deployment: intent.deployment_id().clone(),
                    first_line: state.entries[first_pos].seq as usize + 1,
                    duplicate_line: state.next_seq() as usize + 1,
                }));
            }
            // THE STRICT-LINEAR LINEAGE GATE (intent-append time — the
            // spec's authoritative check; the terminal-time one-parent scan
            // below is now only a defensive re-check).
            let deployment_id = intent.deployment_id().clone();
            // The checkpoint ANCHOR: a checkpointed ledger's first intent
            // must be the checkpoint deployment itself, and it MAY reference
            // a parent OUTSIDE the retained suffix — its parent-equality and
            // inherited-slot checks are SKIPPED (item 7 of the spec).
            let anchor = state
                .checkpoint
                .as_ref()
                .is_some_and(|cp| cp.retained_from == deployment_id);
            if anchor {
                // The anchor is the FIRST intent of the retained suffix.
                if !state.entries.is_empty() {
                    return Err(KernelError::Integrity(IntegrityError::Message(format!(
                        "the checkpoint anchor deployment '{deployment_id}' must be the first intent of the retained suffix — the checkpointed ledger's history starts at it"
                    ))));
                }
            } else {
                // The first intent after a checkpoint MUST be the anchor
                // (the retained suffix starts at the checkpoint deployment).
                if let Some(cp) = &state.checkpoint
                    && state.entries.is_empty()
                {
                    return Err(KernelError::Integrity(IntegrityError::Message(format!(
                        "the first intent after a checkpoint must be the checkpoint deployment '{retained}' (retained_from) — the retained suffix starts at it, got deployment '{deployment_id}'",
                        retained = cp.retained_from
                    ))));
                }
                // AT MOST ONE PENDING ATTEMPT AT ANY TIME: an unresolved
                // (terminal-less) intent exists — an ordinary intent is
                // refused (item 4 of the spec). A push that cannot finish
                // the previous pending attempt NEVER plans a second intent
                // on top, even for disjoint groups.
                if let Some(pending) = &state.pending {
                    return Err(KernelError::Integrity(IntegrityError::Message(format!(
                        "intent for deployment '{}' of target '{}' refused: {:?} — a pending deployment '{pending}' already exists with no terminal; the successful history is strictly linear (at most one unresolved intent at a time)",
                        deployment_id,
                        state.target,
                        crate::kernel::LineageViolation::PendingAttemptExists,
                    ))));
                }
                // THE PARENT MUST BE THE CURRENT SUCCESSFUL HEAD AT INTENT-
                // APPEND TIME (item 4 of the spec). `None == None` for a
                // fresh target's first intent.
                if intent.parent() != state.successful_head.as_ref() {
                    return Err(KernelError::Integrity(
                        IntegrityError::ParentLineageMismatch {
                            deployment: deployment_id.clone(),
                            parent: intent.parent().cloned(),
                            expected_head: state.successful_head.clone(),
                        },
                    ));
                }
                // INHERITED-SLOT CONGRUENCE (item 4 of the spec): every
                // slot NOT in the intent's selected membership must equal the
                // successful head's snapshot entry for that slot — the
                // intent's inherited entries must match the head it claims.
                // Skipped when there is no successful head yet (no inherited
                // slots to check against).
                if let Some(head_snapshot) = state.successful_snapshot()? {
                    validate_inherited_slots(&intent, &head_snapshot)?;
                }
            }
            let entry = LedgerEntry {
                deployment_id: deployment_id.clone(),
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
            // The new intent IS the one unresolved (pending) attempt.
            state.pending = Some(deployment_id);
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
                KernelError::Integrity(IntegrityError::TerminalWithoutIntent {
                    deployment: deployment_id.clone(),
                    line: state.next_seq() as usize + 1,
                })
            })?;
            let entry = &state.entries[pos];
            if crate::kernel::terminal::intent_digest(&entry.intent) != digest {
                return Err(KernelError::Integrity(
                    IntegrityError::IntentDigestMismatch {
                        deployment: deployment_id.clone(),
                        expected: crate::kernel::terminal::intent_digest(&entry.intent),
                        recorded: digest,
                    },
                ));
            }
            // AT MOST ONE TERMINAL PER INTENT (event-store rule).
            if entry.terminal.is_some() {
                return Err(KernelError::Integrity(IntegrityError::DuplicateTerminal {
                    deployment: deployment_id.clone(),
                    first_line: entry.seq as usize + 2,
                    duplicate_line: state.next_seq() as usize + 1,
                }));
            }
            validate_terminal_vs_intent(entry, &terminal)?;
            // THE TERMINAL MUST BELONG TO THE PENDING ATTEMPT (item 5 of the
            // spec): a terminal event is the settlement of the ONE
            // unresolved intent — its deployment id must be `state.pending`. A
            // terminal for any other deployment is corruption (a strictly
            // linear ledger settles exactly the pending attempt).
            if state.pending.as_ref() != Some(&deployment_id) {
                return Err(KernelError::Integrity(IntegrityError::Message(format!(
                    "terminal for deployment '{deployment_id}' does not belong to the outstanding pending attempt ({:?}) — the successful history is strictly linear: a terminal must settle the one pending intent",
                    state.pending
                ))));
            }
            // THE CHECKPOINT ANCHOR MUST BE FINALIZED `Successful` (item 7
            // of the spec): a checkpointed ledger's retained suffix starts at
            // the checkpoint deployment, and the checkpoint requires its
            // anchor to be a successful deployment — a non-Successful anchor
            // terminal is corruption.
            if state
                .checkpoint
                .as_ref()
                .is_some_and(|cp| cp.retained_from == deployment_id)
                && !terminal.disposition().is_successful()
            {
                return Err(KernelError::Integrity(
                    IntegrityError::CheckpointAnchorMismatch {
                        retained_from: deployment_id.clone(),
                        first_intent: Some(deployment_id.clone()),
                    },
                ));
            }
            // THE ONE-PARENT RULE (the state machine's `Successful` gate —
            // now a DEFENSIVE re-check, subsumed by the intent-append gates
            // above: with at most one pending intent and a terminal-must-be-
            // pending, a `Successful` terminal's parent is the head by
            // construction (ordinary case) or the checkpoint anchor
            // (exception). Kept where it still guards — no bypass, recovery
            // included — so ANY entry that somehow carries a Successful
            // terminal for an already-successful parent is refused as a
            // stale plan.
            if terminal.disposition().is_successful() {
                let parent = entry.intent.parent().cloned();
                let already = state.entries.iter().any(|e| {
                    e.deployment_id != deployment_id
                        && e.terminal.as_ref().is_some_and(|t| {
                            t.status() == DeploymentStatus::Successful
                                && e.intent.parent() == parent.as_ref()
                        })
                });
                if already {
                    return Err(KernelError::Conflict(ConflictError::ParentMismatch {
                        deployment: entry.deployment_id.clone(),
                        recorded_parent: parent,
                        actual_head: state.successful_head.clone(),
                    }));
                }
            }
            let mut entry = state.entries[pos].clone();
            entry.terminal = Some(terminal);
            state.entries[pos] = entry;
            // ANY terminal clears the pending attempt (the intent has
            // reached its terminal); ONLY a `Successful` terminal advances
            // the successful head (item 5 of the spec). For the checkpoint
            // anchor's Successful terminal, allow the advance even though
            // `successful_head` was None — it is the exception: the anchor's
            // parent lies outside the retained window, and the head starts
            // as the anchor.
            state.pending = None;
            if state.entries[pos]
                .terminal
                .as_ref()
                .is_some_and(|t| t.status() == DeploymentStatus::Successful)
            {
                state.successful_head = Some(deployment_id);
            }
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
///   selected membership;
/// * the disposition's delta invariant (the review's P1 rule, through the
///   ONE classifier [`crate::kernel::terminal::classify_slot_delta`]):
///   `FailedRolledBack` requires EVERY slot's delta `Unchanged`; `Degraded`
///   requires AT LEAST ONE `Desired`/`Diverged`/`Unknown` slot. Enforced
///   here (where the entry's intent exists) on the terminal-append path AND
///   the read fold.
pub fn validate_terminal_vs_intent(
    entry: &LedgerEntry,
    terminal: &LedgerTerminal,
) -> KernelResult<()> {
    let selected: BTreeSet<SlotId> = entry.intent.selected_membership();
    let outcome_keys: BTreeSet<SlotId> = terminal.outcomes().keys().cloned().collect();
    for key in &outcome_keys {
        if !selected.contains(key) {
            return Err(KernelError::Integrity(IntegrityError::Message(format!(
                "terminal for deployment '{}' records an outcome for slot '{key}' outside the intent's selected membership — every outcome must name a selected slot",
                entry.deployment_id
            ))));
        }
    }
    match terminal.disposition() {
        TerminalDisposition::Successful | TerminalDisposition::FailedPreflight => {
            if !outcome_keys.is_empty() {
                return Err(KernelError::Integrity(IntegrityError::Message(format!(
                    "terminal {:?} for deployment '{}' carries outcomes for slots {outcome_keys:?} — a payload-free disposition records none",
                    terminal.status(),
                    entry.deployment_id
                ))));
            }
        }
        TerminalDisposition::FailedRolledBack(_) | TerminalDisposition::Degraded(_) => {
            if outcome_keys != selected {
                return Err(KernelError::Integrity(IntegrityError::Message(format!(
                    "terminal {:?} for deployment '{}' carries outcomes for slots {outcome_keys:?} but its intent's selected membership is {selected:?} — every selected slot has exactly one outcome, no extras",
                    terminal.status(),
                    entry.deployment_id
                ))));
            }
            // THE DELTA INVARIANT (the ONE classifier — the same rule the
            // decision-time constructors enforce): a rolled-back terminal
            // must be all-Unchanged, a degraded terminal must carry at least
            // one remaining change. A persisted disposition that contradicts
            // its intent's pre-push/desired evidence is corruption (fail
            // closed — never a Degraded with no remaining changes).
            match terminal.disposition() {
                TerminalDisposition::FailedRolledBack(_) => {
                    for (sid, outcome) in terminal.outcomes().iter() {
                        let delta = crate::kernel::terminal::outcome_slot_delta(
                            &entry.intent,
                            sid,
                            outcome,
                        );
                        if delta != SlotDelta::Unchanged {
                            return Err(KernelError::Integrity(IntegrityError::Message(format!(
                                "terminal FailedRolledBack for deployment '{}' carries slot '{sid}' with delta {delta:?} — every attempted mutation must be back at its pre-push state",
                                entry.deployment_id
                            ))));
                        }
                    }
                }
                TerminalDisposition::Degraded(_) => {
                    let has_remaining = terminal.outcomes().iter().any(|(sid, outcome)| {
                        crate::kernel::terminal::outcome_slot_delta(&entry.intent, sid, outcome)
                            != SlotDelta::Unchanged
                    });
                    if !has_remaining {
                        return Err(KernelError::Integrity(IntegrityError::Message(format!(
                            "terminal Degraded for deployment '{}' has NO remaining change — every slot is at its pre-push state, so the attempt is FailedRolledBack, never Degraded",
                            entry.deployment_id
                        ))));
                    }
                }
                _ => unreachable!("the disposition was matched above"),
            }
        }
    }
    Ok(())
}

/// THE INHERITED-SLOT CONGRUENCE (item 4 of the spec — the intent-append
/// lineage check): every slot of the intent's resulting snapshot that is
/// NOT in its selected membership (an `Inherit` slot) must EXACTLY equal
/// the successful head's snapshot entry for that slot (generation +
/// artifact + binding) — the intent's inherited entries must match the
/// head it claims. A disagreement means the intent was planned over a
/// DIFFERENT snapshot than the head it names (a tampered wire or a stale
/// plan) and is refused — fail closed on any mismatch.
///
/// Called for ORDINARY intents only (the checkpoint anchor of a
/// checkpointed ledger is the exception: its parent snapshot lies outside
/// the retained window, so there is nothing to check against). Skipped when
/// the ledger has no successful head yet (no inherited slots exist).
pub fn validate_inherited_slots(
    intent: &DeploymentIntent,
    head_snapshot: &crate::ledger::TargetSnapshot,
) -> KernelResult<()> {
    let selected: BTreeSet<SlotId> = intent.selected_membership();
    let resulting = intent.resulting_snapshot();
    for slot in intent.full_membership() {
        if selected.contains(&slot) {
            continue;
        }
        let inherited = resulting.get(&slot).ok_or_else(|| {
            KernelError::Integrity(IntegrityError::Message(format!(
                "intent for deployment '{}' carries no resulting entry for inherited slot '{slot}' — the resulting snapshot must cover its full membership",
                intent.deployment_id()
            )))
        })?;
        let head_entry = head_snapshot.get(&slot).ok_or_else(|| {
            KernelError::Integrity(IntegrityError::Message(format!(
                "intent for deployment '{}' inherits slot '{slot}' but the successful head's snapshot has no entry for it — an inherited slot must reproduce an existing head entry",
                intent.deployment_id()
            )))
        })?;
        if inherited != head_entry {
            return Err(KernelError::Integrity(
                IntegrityError::InheritedSnapshotMismatch {
                    deployment: intent.deployment_id().clone(),
                    slot,
                },
            ));
        }
    }
    Ok(())
}

/// The engine's gathered evidence, handed to [`decide_terminal`]: the
/// engine GATHERS EVIDENCE (did preflight fail? were the selected slots
/// verified at their planned result? what per-slot outcomes remain on a
/// failure?) and the kernel OWNS the truth table. The mutually exclusive
/// execution states are ENUM VARIANTS — never combinations of booleans
/// (`{preflight_failed: true, verified: true}` was representable):
/// `PreflightFailed` (no slot was touched), `Verified` (the selected slots
/// were verified at their planned result), or `Failed { outcomes }` (the
/// per-slot outcomes of a failed execution; NON-EMPTY — the failure
/// outcomes always cover the selected membership).
#[derive(Clone, Debug)]
pub enum ExecutionReport {
    /// The attempt's preflight failed before any slot mutation.
    PreflightFailed,
    /// Execution succeeded AND the selected slots were verified at their
    /// planned result.
    Verified,
    /// The attempt failed after mutating slots: the per-slot outcomes
    /// (restored / never-advanced / remaining changes) PLUS the
    /// ADAPTER-RESTORATION EVIDENCE (the review's P1 fix): the slots whose
    /// ADAPTER side effects were VERIFIED restored, keyed by slot and
    /// carrying the sealed proof (produced only by a successful adapter
    /// `verify_restored` read-back). The outcome keys must EXACTLY equal the
    /// intent's selected membership (the kernel validates that at decision
    /// time); the disposition is DERIVED from the outcomes' OBSERVATIONS
    /// against the intent's pre-push and DESIRED generations through the
    /// ONE per-slot classifier ([`SlotDelta`] /
    /// [`crate::kernel::terminal::classify_slot_delta`]). A `Restored`
    /// outcome WITHOUT its adapter-restoration evidence is refused by the
    /// rolled-back derivation — the generation delta alone cannot see the
    /// unit file left in the new state.
    Failed {
        outcomes: NonEmptySlotTable<SlotOutcome>,
        /// THE VERIFIED-ADAPTER-RESTORATION EVIDENCE: the slots whose
        /// adapter side effects were VERIFIED restored (the sealed proof
        /// [`crate::verify::adapters::transaction::VerifiedAdapterRestoration`]
        /// — only a successful `verify_restored` read-back produces it). The
        /// rolled-back derivation requires it for every `Restored` outcome.
        adapter_restored: std::collections::BTreeMap<
            crate::identity::SlotId,
            crate::verify::adapters::transaction::VerifiedAdapterRestoration,
        >,
    },
}

/// THE COMPLETE TRUTH TABLE of the terminal decision — the ONLY place a
/// terminal disposition is decided:
///
/// * preflight failed                → `FailedPreflight`
/// * execution succeeded AND verified → `Successful`
/// * failure with EVERY slot's [`SlotDelta`] `Unchanged` (no remaining
///   change — every attempted mutation is back at its pre-push state) →
///   `FailedRolledBack`
/// * failure with AT LEAST ONE `Desired`/`Diverged`/`Unknown` delta →
///   `Degraded`
///
/// The disposition is DERIVED from the outcomes' OBSERVATIONS against the
/// intent's pre-push and DESIRED generations, through the ONE classifier
/// [`classify_slot_delta`](crate::kernel::terminal::classify_slot_delta) —
/// the review's P1 fix: a USED class of failures (a slot advanced and NOT
/// restored — the outcome [`SlotOutcome::FailedAfterAdvance`], whose
/// recorded observation is the advanced generation) is NEVER rolled back
/// even when an old transition-based rule saw "no slot PROVABLY ON the new
/// state". The intent is USED: the failed outcomes' keys must EXACTLY equal
/// the intent's selected membership (a mismatch is an integrity refusal —
/// the kernel owns this check at decision time; the existing
/// [`validate_terminal_vs_intent`] stays as a terminal-append re-check,
/// including the same delta invariants). The outcome payloads are
/// constructed ONLY through the validated constructors, so an impossible
/// combination (a rolled-back terminal with a remaining change; a Degraded
/// terminal with all-Unchanged deltas) is unrepresentable.
pub fn decide_terminal(
    intent: &DeploymentIntent,
    report: ExecutionReport,
) -> KernelResult<TerminalDisposition> {
    match report {
        ExecutionReport::PreflightFailed => Ok(TerminalDisposition::FailedPreflight),
        ExecutionReport::Verified => Ok(TerminalDisposition::Successful),
        ExecutionReport::Failed {
            outcomes,
            adapter_restored,
        } => {
            // 1. THE KERNEL OWNS THE KEY-SET CHECK at decision time: the
            // failed outcome keys must EXACTLY equal the intent's selected
            // membership. (The existing [`validate_terminal_vs_intent`]
            // stays as a terminal-append re-check.)
            let selected: BTreeSet<SlotId> = intent.selected_membership();
            let keys: BTreeSet<SlotId> = outcomes.keys().cloned().collect();
            if keys != selected {
                return Err(KernelError::Integrity(IntegrityError::Message(format!(
                    "the failure outcomes cover slots {keys:?} but the intent's selected membership is {selected:?} — the failed evidence must EXACTLY cover the selected membership"
                ))));
            }
            // 2. DERIVE the disposition from THE ONE per-slot classifier:
            // rolled-back iff EVERY slot's delta is `Unchanged` (a slot
            // Desired/Diverged/Unknown — PROVABLY ON the deployed state, on
            // a third state, or unknown — is NOT rolled back); otherwise
            // degraded (which therefore carries ≥1 non-Unchanged delta).
            let rolled_back = outcomes.iter().all(|(sid, o)| {
                crate::kernel::terminal::outcome_slot_delta(intent, sid, o) == SlotDelta::Unchanged
            });
            if rolled_back {
                // THE ADAPTER-RESTORATION GATE (the review's P1 fix — the
                // review: "FailedRolledBack must require verified adapter
                // restoration IN ADDITION to the generation delta being
                // unchanged"): a slot whose GENERATION is back (delta
                // `Unchanged`) but whose ADAPTER side effect was NOT
                // VERIFIED restored (e.g. the unit file left in the new
                // state, the new unit still enabled) is NOT rolled back. The
                // sealed [`VerifiedAdapterRestoration`] proof cannot be
                // fabricated outside the adapter verification, so an
                // unverified `Restored` outcome here is a hand-crafted
                // report or an engine bug — REFUSE as integrity, never
                // silently produce `FailedRolledBack`.
                for (sid, o) in outcomes.iter() {
                    if matches!(o, SlotOutcome::Restored { .. })
                        && !adapter_restored.contains_key(sid)
                    {
                        return Err(KernelError::Integrity(IntegrityError::Message(format!(
                            "the rolled-back decision cannot include slot '{sid}': its adapter restoration is NOT verified — a Restored slot is rolled-back-eligible only with a verified adapter restoration"
                        ))));
                    }
                }
                let payload = FailedRolledBackTerminal::try_new(
                    SlotTable::from_map(outcomes.clone().into_map()),
                    intent,
                )?;
                Ok(TerminalDisposition::FailedRolledBack(payload))
            } else {
                let payload = DegradedTerminal::try_new(outcomes, intent)?;
                Ok(TerminalDisposition::Degraded(payload))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! THE STRICT-LINEAR REFERENCE-MODEL PROPERTY (spec item 9): an
    //! INDEPENDENT tiny reference model of the strictly-linear success
    //! ledger — written from the SPEC's invariants (one pending at a time,
    //! parent == the preceding successful head at intent-append time,
    //! inherited entries == the head's snapshot, terminal belongs to the
    //! pending, only a Successful terminal advances the head, checkpoint
    //! anchor exception) in its OWN structure — is driven against
    //! [`apply_event`] with arbitrary VALID-DOMAIN events. The two must
    //! agree on EVERY event (both accept or both refuse), and after every
    //! ACCEPTED event the property asserts:
    //!
    //! * pending_count ≤ 1 (the single `pending` Option);
    //! * every ordinary intent's parent == the preceding successful head;
    //! * every inherited (non-selected) slot == the parent snapshot's entry;
    //! * the resolved successful head snapshot == the modeled slot snapshot.
    //!
    //! The generator materializes VALID domain events (deployment ids
    //! unique, target matching, digests binding, terminals with valid
    //! dispositions incl. the checkpoint-anchor case) that may or may not be
    //! linearly acceptable — the reference and the state machine both
    //! decide.

    use super::*;
    use crate::identity::test_deployment_id;
    use crate::identity::test_generation_id;
    use crate::kernel::intent::{PlanInput, PlannedDeploy};
    use crate::kernel::snapshot::SnapshotSlot;
    use crate::ledger::{Observation, TargetSnapshot};
    use crate::testutil::fixtures;
    use crate::verify::adapters::transaction::VerifiedAdapterRestoration;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::collections::{BTreeMap, BTreeSet};

    fn p1() -> SlotId {
        SlotId::new("p1".to_string())
    }
    fn p2() -> SlotId {
        SlotId::new("p2".to_string())
    }
    fn target() -> TargetName {
        TargetName::parse("prop-t").expect("a test target")
    }
    fn outside_parent() -> DeploymentId {
        test_deployment_id("deploy-outside")
    }
    fn anchor_id() -> DeploymentId {
        test_deployment_id("deploy-anchor")
    }

    /// THE INDEPENDENT REFERENCE MODEL. Its fields are its OWN (a modeled
    /// head/slots/pending/terminated registry, not `DeploymentState`), and
    /// its acceptance logic is written from the spec's invariants in its own
    /// structure — the property cross-checks two independent
    /// implementations.
    #[derive(Clone, Debug)]
    struct Reference {
        target: TargetName,
        /// The modeled successful head (deployment id) — the parent every
        /// ordinary intent must equal at intent-append time.
        head: Option<DeploymentId>,
        /// The modeled head's resulting snapshot (None before the first
        /// success) — the base every inherited slot must reproduce.
        slots: Option<TargetSnapshot>,
        /// The ONE unresolved (terminal-less) intent, if any.
        pending: Option<DeploymentId>,
        /// The pending intent itself (for building its terminal events).
        pending_intent: Option<DeploymentIntent>,
        /// The NEWEST successful intent (the model's head entry).
        head_intent: Option<DeploymentIntent>,
        /// The checkpoint prefix, if the ledger began with one.
        checkpoint: Option<CheckpointEvent>,
        /// Every ACCEPTED intent, keyed by deployment id.
        intents: BTreeMap<DeploymentId, DeploymentIntent>,
        /// Accepted ids in append order (the model's history).
        order: Vec<DeploymentId>,
        /// Ids that reached a terminal (at-most-one gate).
        terminated: BTreeSet<DeploymentId>,
        /// Ids that reached a `Successful` terminal.
        successful: BTreeSet<DeploymentId>,
        /// The successful parents already seen (the one-parent defensive
        /// gate, mirrored).
        success_parents: BTreeSet<Option<DeploymentId>>,
        /// Per accepted intent: the head at its accept time — the
        /// "preceding successful head" the parent-assertion checks.
        head_at_accept: BTreeMap<DeploymentId, Option<DeploymentId>>,
        /// Per accepted intent: the base snapshot at its accept time.
        base_at_accept: BTreeMap<DeploymentId, Option<TargetSnapshot>>,
        /// The checkpoint anchor ids (their lineage checks are skipped).
        anchors: BTreeSet<DeploymentId>,
    }

    impl Reference {
        fn new() -> Self {
            Reference {
                target: target(),
                head: None,
                slots: None,
                pending: None,
                pending_intent: None,
                head_intent: None,
                checkpoint: None,
                intents: BTreeMap::new(),
                order: Vec::new(),
                terminated: BTreeSet::new(),
                successful: BTreeSet::new(),
                success_parents: BTreeSet::new(),
                head_at_accept: BTreeMap::new(),
                base_at_accept: BTreeMap::new(),
                anchors: BTreeSet::new(),
            }
        }

        /// The modeled acceptance of one event. `true` — accept — exactly
        /// when the strictly-linear spec permits it; [`apply_event`] must
        /// agree on EVERY event.
        fn accepts(&mut self, event: &LedgerEvent) -> bool {
            match event {
                LedgerEvent::Checkpoint(cp) => {
                    if !self.order.is_empty() || self.checkpoint.is_some() {
                        return false;
                    }
                    self.checkpoint = Some(cp.clone());
                    true
                }
                LedgerEvent::Intent(ev) => {
                    let intent = &ev.intent;
                    if intent.target() != &self.target {
                        return false;
                    }
                    let dep = intent.deployment_id().clone();
                    if self.intents.contains_key(&dep) {
                        return false;
                    }
                    let anchor = self
                        .checkpoint
                        .as_ref()
                        .is_some_and(|c| c.retained_from == dep);
                    if anchor {
                        if !self.order.is_empty() {
                            return false;
                        }
                    } else {
                        if self.checkpoint.is_some() && self.order.is_empty() {
                            return false;
                        }
                        // AT MOST ONE PENDING (PendingAttemptExists).
                        if self.pending.is_some() {
                            return false;
                        }
                        // ParentMismatch: parent == the modeled head.
                        if intent.parent() != self.head.as_ref() {
                            return false;
                        }
                        // Inherited slots must reproduce the modeled head
                        // snapshot.
                        if let Some(slots) = &self.slots
                            && !self.inherited_ok(intent, slots)
                        {
                            return false;
                        }
                    }
                    self.intents.insert(dep.clone(), intent.clone());
                    self.head_at_accept.insert(dep.clone(), self.head.clone());
                    self.base_at_accept.insert(dep.clone(), self.slots.clone());
                    if anchor {
                        self.anchors.insert(dep.clone());
                    }
                    self.order.push(dep.clone());
                    self.pending = Some(dep.clone());
                    self.pending_intent = Some(intent.clone());
                    true
                }
                LedgerEvent::Terminal(ev) => {
                    let Some(intent) = self.intents.get(&ev.deployment_id) else {
                        return false;
                    };
                    if self.terminated.contains(&ev.deployment_id) {
                        return false;
                    }
                    if ev.terminal.intent_digest().as_str()
                        != crate::kernel::terminal::intent_digest(intent).as_str()
                    {
                        return false;
                    }
                    if !self.terminal_ok(intent, &ev.terminal) {
                        return false;
                    }
                    // The terminal must belong to the ONE pending attempt.
                    if self.pending.as_ref() != Some(&ev.deployment_id) {
                        return false;
                    }
                    // The checkpoint anchor must be Successful.
                    if self
                        .checkpoint
                        .as_ref()
                        .is_some_and(|c| c.retained_from == ev.deployment_id)
                        && !ev.terminal.disposition().is_successful()
                    {
                        return false;
                    }
                    // The one-parent defensive gate: a Successful terminal's
                    // parent may not already have produced a success.
                    if ev.terminal.disposition().is_successful() {
                        let parent = intent.parent().cloned();
                        if self.success_parents.contains(&parent) {
                            return false;
                        }
                        self.success_parents.insert(parent);
                    }
                    self.terminated.insert(ev.deployment_id.clone());
                    if ev.terminal.disposition().is_successful() {
                        self.successful.insert(ev.deployment_id.clone());
                        self.head = Some(ev.deployment_id.clone());
                        self.slots = Some(intent.resulting_snapshot());
                        self.head_intent = Some(intent.clone());
                    }
                    self.pending = None;
                    self.pending_intent = None;
                    true
                }
            }
        }

        /// The inherited-slot congruence, modeled independently: every slot
        /// of the intent's resulting snapshot that is NOT selected must
        /// equal the modeled head snapshot's entry for that slot.
        fn inherited_ok(&self, intent: &DeploymentIntent, slots: &TargetSnapshot) -> bool {
            let selected = intent.selected_membership();
            let resulting = intent.resulting_snapshot();
            for slot in intent.full_membership() {
                if selected.contains(&slot) {
                    continue;
                }
                match (resulting.get(&slot), slots.get(&slot)) {
                    (Some(inherited), Some(head_entry)) if inherited == head_entry => {}
                    _ => return false,
                }
            }
            true
        }

        /// The disposition-vs-intent agreement, modeled independently.
        fn terminal_ok(&self, intent: &DeploymentIntent, terminal: &LedgerTerminal) -> bool {
            let selected = intent.selected_membership();
            let outcome_keys: BTreeSet<SlotId> = terminal.outcomes().keys().cloned().collect();
            match terminal.disposition() {
                TerminalDisposition::Successful | TerminalDisposition::FailedPreflight => {
                    outcome_keys.is_empty()
                }
                TerminalDisposition::FailedRolledBack(_) | TerminalDisposition::Degraded(_) => {
                    outcome_keys == selected
                }
            }
        }

        /// The structural-completeness predicate mirroring [`DeploymentState::finish`]:
        /// a checkpointed ledger must carry its SUCCESSFUL anchor.
        fn finish_ok(&self) -> bool {
            let Some(cp) = &self.checkpoint else {
                return true;
            };
            self.successful.contains(&cp.retained_from)
        }
    }

    /// A next fresh generated id tag (unique per materialization).
    fn next_tag(counter: &mut usize) -> String {
        let idx = *counter;
        *counter += 1;
        format!("deploy-{}", (b'a' + (idx % 26) as u8) as char)
    }

    /// A full-push intent (parent == the given head, or None on a fresh
    /// target) over both slots.
    fn full_intent_over(tag: &str, head: Option<&DeploymentIntent>) -> DeploymentIntent {
        let (parent, parent_snapshot) = match head {
            Some(h) => (
                Some(h.deployment_id().clone()),
                Some(h.resulting_snapshot()),
            ),
            None => (None, None),
        };
        let planned: Vec<PlannedDeploy> = [p1(), p2()]
            .into_iter()
            .map(|sid| PlannedDeploy {
                slot: sid.clone(),
                result: crate::testutil::fixtures::snapshot_slot(&sid),
                pre_push: Observation::KnownAbsent,
            })
            .collect();
        crate::kernel::intent::plan(PlanInput {
            deployment_id: test_deployment_id(tag),
            target: target(),
            parent,
            parent_snapshot,
            group: None,
            selection: vec![p1(), p2()],
            planned,
            behavior_digest: crate::testutil::fixtures::behavior_digest(),
            attempted_at: crate::identity::Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        })
        .expect("a valid full intent plans")
    }

    /// A group intent over the head: deploys p1, INHERITS p2 (the
    /// inherited-slot checks are exercised on every accept).
    fn group_intent_over(tag: &str, head: &DeploymentIntent) -> DeploymentIntent {
        crate::testutil::fixtures::group_intent(
            tag,
            "prop-t",
            "g",
            head.deployment_id(),
            &head.resulting_snapshot(),
            &[p1(), p2()],
            &[p1()],
        )
    }

    /// A group intent over the head whose INHERITED p2 entry disagrees with
    /// the head's actual snapshot (a tampered base) — refused by the
    /// inherited-slot congruence.
    fn tampered_group_intent(tag: &str, head: &DeploymentIntent) -> DeploymentIntent {
        let mut entries = head.resulting_snapshot().into_entries();
        let p2e = entries.get(&p2()).cloned().expect("the head covers p2");
        let tampered = SnapshotSlot::new(
            test_generation_id("tampered-p2"),
            p2e.artifact().clone(),
            p2e.binding().clone(),
        );
        entries.insert(p2(), tampered);
        let base = TargetSnapshot::from_entries(entries);
        crate::testutil::fixtures::group_intent(
            tag,
            "prop-t",
            "g",
            head.deployment_id(),
            &base,
            &[p1(), p2()],
            &[p1()],
        )
    }

    /// The checkpoint ANCHOR intent: the checkpoint deployment itself, whose
    /// parent MAY lie OUTSIDE the retained suffix (any parent value is
    /// accepted — the lineage checks are skipped for it). The parent
    /// snapshot is a coherent placeholder (a full push — no inherited slots
    /// — so the base is never consulted).
    fn anchor_intent() -> DeploymentIntent {
        let fake_snapshot = TargetSnapshot::from_entries(BTreeMap::from([
            (p1(), crate::testutil::fixtures::snapshot_slot(&p1())),
            (p2(), crate::testutil::fixtures::snapshot_slot(&p2())),
        ]));
        crate::kernel::intent::plan(PlanInput {
            deployment_id: anchor_id(),
            target: target(),
            parent: Some(outside_parent()),
            parent_snapshot: Some(fake_snapshot),
            group: None,
            selection: vec![p1(), p2()],
            planned: vec![
                PlannedDeploy {
                    slot: p1(),
                    result: crate::testutil::fixtures::snapshot_slot(&p1()),
                    pre_push: Observation::KnownAbsent,
                },
                PlannedDeploy {
                    slot: p2(),
                    result: crate::testutil::fixtures::snapshot_slot(&p2()),
                    pre_push: Observation::KnownAbsent,
                },
            ],
            behavior_digest: crate::testutil::fixtures::behavior_digest(),
            attempted_at: crate::identity::Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        })
        .expect("the anchor intent plans (its self-contained rules)")
    }

    fn checkpoint_event() -> CheckpointEvent {
        CheckpointEvent {
            retained_from: anchor_id(),
            discarded: 1,
            recorded_at: crate::remote::helper::now_rfc3339_ts(),
        }
    }

    /// An ORPHAN terminal: a valid-looking terminal for a deployment id with
    /// NO intent — refused by both (the always-safe fallback for steps that
    /// cannot be built meaningfully from the current state).
    fn orphan_terminal() -> LedgerEvent {
        let intent = fixtures::full_intent("deploy-orphan", "prop-t", &[p1()], &[]);
        LedgerEvent::Terminal(TerminalEvent {
            deployment_id: intent.deployment_id().clone(),
            terminal: fixtures::successful_terminal(&intent),
        })
    }

    /// Materialize ONE step into a concrete VALID-DOMAIN event, derived
    /// from the current reference state. The event's LINEAR acceptance is
    /// decided by the reference AND [`apply_event`] (the materializer never
    /// pre-decides it); steps that cannot be built meaningfully from the
    /// current state fall back to a guaranteed-refused (orphan) or
    /// guaranteed-valid (first intent) event.
    fn materialize(step: Step, r: &Reference, counter: &mut usize) -> LedgerEvent {
        match step {
            Step::Checkpoint | Step::CheckpointMiddle => {
                LedgerEvent::Checkpoint(checkpoint_event())
            }
            Step::FirstFullIntent => LedgerEvent::Intent(IntentEvent {
                intent: full_intent_over(&next_tag(counter), None),
            }),
            Step::FullIntentOverHead => LedgerEvent::Intent(IntentEvent {
                intent: full_intent_over(&next_tag(counter), r.head_intent.as_ref()),
            }),
            Step::GroupIntentOverHead => match &r.head_intent {
                Some(head) => LedgerEvent::Intent(IntentEvent {
                    intent: group_intent_over(&next_tag(counter), head),
                }),
                None => LedgerEvent::Intent(IntentEvent {
                    intent: full_intent_over(&next_tag(counter), None),
                }),
            },
            Step::AnchorIntent => LedgerEvent::Intent(IntentEvent {
                intent: anchor_intent(),
            }),
            Step::WrongParentIntent => {
                // A parent that NEVER matches the modeled head: None while a
                // head exists, an outside id on a fresh target. The parent
                // snapshot stays COHERENT with the parent (both or neither).
                let (parent, parent_snapshot) = match &r.head_intent {
                    Some(_) => (None, None),
                    None => {
                        let fake = TargetSnapshot::from_entries(BTreeMap::from([
                            (p1(), crate::testutil::fixtures::snapshot_slot(&p1())),
                            (p2(), crate::testutil::fixtures::snapshot_slot(&p2())),
                        ]));
                        (Some(outside_parent()), Some(fake))
                    }
                };
                let planned: Vec<PlannedDeploy> = [p1(), p2()]
                    .into_iter()
                    .map(|sid| PlannedDeploy {
                        slot: sid.clone(),
                        result: crate::testutil::fixtures::snapshot_slot(&sid),
                        pre_push: Observation::KnownAbsent,
                    })
                    .collect();
                let intent = crate::kernel::intent::plan(PlanInput {
                    deployment_id: test_deployment_id(&next_tag(counter)),
                    target: target(),
                    parent,
                    parent_snapshot,
                    group: None,
                    selection: vec![p1(), p2()],
                    planned,
                    behavior_digest: crate::testutil::fixtures::behavior_digest(),
                    attempted_at: crate::identity::Timestamp::parse("2026-01-01T00:00:00Z")
                        .unwrap(),
                })
                .expect("a valid-domain wrong-parent intent plans");
                LedgerEvent::Intent(IntentEvent { intent })
            }
            Step::SecondWhilePending => LedgerEvent::Intent(IntentEvent {
                intent: full_intent_over(&next_tag(counter), r.head_intent.as_ref()),
            }),
            Step::DuplicateIntent => {
                let tag = match r.order.first() {
                    Some(first) => first.as_str().to_string(),
                    None => next_tag(counter),
                };
                LedgerEvent::Intent(IntentEvent {
                    intent: full_intent_over(&tag, r.head_intent.as_ref()),
                })
            }
            Step::TamperedInherit => match &r.head_intent {
                Some(head) => LedgerEvent::Intent(IntentEvent {
                    intent: tampered_group_intent(&next_tag(counter), head),
                }),
                None => LedgerEvent::Intent(IntentEvent {
                    intent: full_intent_over(&next_tag(counter), None),
                }),
            },
            Step::TerminalSuccessful => match &r.pending_intent {
                Some(pending) => LedgerEvent::Terminal(TerminalEvent {
                    deployment_id: pending.deployment_id().clone(),
                    terminal: fixtures::successful_terminal(pending),
                }),
                None => orphan_terminal(),
            },
            Step::TerminalFailedPreflight => match &r.pending_intent {
                Some(pending) => LedgerEvent::Terminal(TerminalEvent {
                    deployment_id: pending.deployment_id().clone(),
                    terminal: fixtures::failed_preflight_terminal(pending),
                }),
                None => orphan_terminal(),
            },
            Step::TerminalDegraded => match &r.pending_intent {
                Some(pending) => {
                    let selected: Vec<SlotId> = pending.selected_membership().into_iter().collect();
                    LedgerEvent::Terminal(TerminalEvent {
                        deployment_id: pending.deployment_id().clone(),
                        terminal: fixtures::degraded_terminal(pending, &selected),
                    })
                }
                None => orphan_terminal(),
            },
            Step::TerminalForHead => {
                // A terminal for a NON-pending id: the existing head (when it
                // is not the pending attempt), else an orphan.
                match (r.head.as_ref(), r.pending.as_ref()) {
                    (Some(head_id), Some(pending)) if head_id != pending => {
                        let head_intent = r.intents.get(head_id).expect("the head intent");
                        LedgerEvent::Terminal(TerminalEvent {
                            deployment_id: head_id.clone(),
                            terminal: fixtures::successful_terminal(head_intent),
                        })
                    }
                    _ => orphan_terminal(),
                }
            }
            Step::TerminalWrongDigest => match &r.pending_intent {
                Some(pending) => {
                    // The terminal binds a DIFFERENT (valid) intent's digest.
                    let other =
                        fixtures::full_intent(&next_tag(counter), "prop-t", &[p1(), p2()], &[]);
                    LedgerEvent::Terminal(TerminalEvent {
                        deployment_id: pending.deployment_id().clone(),
                        terminal: fixtures::successful_terminal(&other),
                    })
                }
                None => orphan_terminal(),
            },
            Step::TerminalAnchorDegraded => {
                // The anchor finalized non-Successful: refuse it while the
                // anchor is the pending attempt (else orphan).
                let is_anchor_pending = match (r.checkpoint.as_ref(), r.pending.as_ref()) {
                    (Some(c), Some(p)) => c.retained_from == *p,
                    _ => false,
                };
                if is_anchor_pending {
                    let anchor = r.intents.get(&anchor_id()).expect("the anchor intent");
                    let selected: Vec<SlotId> = anchor.selected_membership().into_iter().collect();
                    LedgerEvent::Terminal(TerminalEvent {
                        deployment_id: anchor_id(),
                        terminal: fixtures::degraded_terminal(anchor, &selected),
                    })
                } else {
                    orphan_terminal()
                }
            }
        }
    }

    /// THE PROPERTY: drive both implementations over a generated step
    /// sequence; assert acceptance agreement on every event and the spec's
    /// post-conditions after every ACCEPTED event. Panic-based assertions
    /// (house style — the semantic-invariants property uses the same
    /// pattern): proptest catches the panic and reports the failing seed.
    fn run_case(steps: Vec<Step>) {
        let mut state = DeploymentState::new(target());
        let mut r = Reference::new();
        let mut counter = 0usize;
        for step in steps {
            let event = materialize(step, &r, &mut counter);
            let expected_accept = r.accepts(&event);
            let outcome = apply_event(state.clone(), event.clone());
            match expected_accept {
                true => {
                    let accepted = outcome.expect("apply_event must accept what the model accepts");
                    // (1) pending_count <= 1: the single pending Option agrees.
                    assert_eq!(
                        accepted.pending(),
                        r.pending.as_ref(),
                        "the pending attempt must agree"
                    );
                    // (2) successful head agrees.
                    assert_eq!(
                        accepted.successful_head(),
                        r.head.as_ref(),
                        "the successful head must agree"
                    );
                    // (4) the resolved head snapshot agrees with the model.
                    assert_eq!(
                        accepted.successful_snapshot().unwrap(),
                        r.slots.clone(),
                        "the resolved head snapshot must equal the modeled snapshot"
                    );
                    // (2)(3) per-entry lineage: every ORDINARY intent's
                    // parent == the preceding successful head, and every
                    // inherited slot == the base snapshot's entry.
                    for entry in accepted.entries() {
                        let dep = &entry.deployment_id;
                        let is_anchor = accepted
                            .checkpoint()
                            .is_some_and(|c| c.retained_from == *dep);
                        if is_anchor {
                            continue;
                        }
                        assert_eq!(
                            entry.intent.parent(),
                            r.head_at_accept.get(dep).and_then(|h| h.as_ref()),
                            "every ordinary intent's parent equals the preceding successful head"
                        );
                        if let Some(base) = r.base_at_accept.get(dep).and_then(|b| b.as_ref()) {
                            let selected = entry.intent.selected_membership();
                            let resulting = entry.intent.resulting_snapshot();
                            for slot in entry.intent.full_membership() {
                                if selected.contains(&slot) {
                                    continue;
                                }
                                assert_eq!(
                                    resulting.get(&slot),
                                    base.get(&slot),
                                    "every inherited slot equals the parent snapshot's entry"
                                );
                            }
                        }
                    }
                    state = accepted;
                }
                false => {
                    assert!(
                        outcome.is_err(),
                        "the model refused but apply_event accepted: {event:?}"
                    );
                }
            }
        }
        // The structural-completeness gate agrees (a checkpointed ledger must
        // carry its Successful anchor).
        assert!(
            state.finish().is_ok() == r.finish_ok(),
            "finish() must reject exactly the incomplete checkpoint prefixes"
        );
    }

    /// The generated step mix: valid moves (intents over the head, group
    /// intents, terminals with every disposition, the checkpoint anchor) AND
    /// deliberately refused moves (a second intent while pending, a wrong
    /// parent, a duplicate id, a tampered inherit, a terminal for a
    /// non-pending id, a mismatched digest, a non-Successful anchor).
    #[derive(Clone, Copy, Debug)]
    enum Step {
        Checkpoint,
        CheckpointMiddle,
        FirstFullIntent,
        FullIntentOverHead,
        GroupIntentOverHead,
        AnchorIntent,
        WrongParentIntent,
        SecondWhilePending,
        DuplicateIntent,
        TamperedInherit,
        TerminalSuccessful,
        TerminalFailedPreflight,
        TerminalDegraded,
        TerminalForHead,
        TerminalWrongDigest,
        TerminalAnchorDegraded,
    }

    fn step_strategy() -> impl Strategy<Value = Step> {
        prop_oneof![
            2 => Just(Step::Checkpoint),
            1 => Just(Step::CheckpointMiddle),
            2 => Just(Step::FirstFullIntent),
            2 => Just(Step::FullIntentOverHead),
            2 => Just(Step::GroupIntentOverHead),
            2 => Just(Step::AnchorIntent),
            1 => Just(Step::WrongParentIntent),
            1 => Just(Step::SecondWhilePending),
            1 => Just(Step::DuplicateIntent),
            1 => Just(Step::TamperedInherit),
            2 => Just(Step::TerminalSuccessful),
            1 => Just(Step::TerminalFailedPreflight),
            1 => Just(Step::TerminalDegraded),
            1 => Just(Step::TerminalForHead),
            1 => Just(Step::TerminalWrongDigest),
            1 => Just(Step::TerminalAnchorDegraded),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(24),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// THE STRICT-LINEAR REFERENCE-MODEL PROPERTY (spec item 9): the
        /// generated event stream is folded through the independent
        /// reference model and [`apply_event`] in lockstep; both must agree
        /// on every event, and every accepted state must satisfy the
        /// strictly-linear post-conditions (one pending at a time, parents
        /// == the preceding successful head, inherited entries == the head
        /// snapshot, resolved head snapshot == the model).
        #[test]
        fn strict_linear_ledger_matches_the_reference_model(steps in prop::collection::vec(step_strategy(), 1..=30)) {
            run_case(steps)
        }
    }

    // ---- THE KERNEL DECISION PROPERTY (spec item 2 — the DECISION-TIME
    // gate) ----------------------------------------------------------------
    //
    // Independent generators for the DECISION property: an arbitrary
    // intent (arbitrary selected membership) and every constructible
    // [`ExecutionReport`] shape — `PreflightFailed`, `Verified`, and
    // `Failed { outcomes }` over exact-selected keys AND over mismatched
    // keys. For every CONSTRUCTIBLE (accepted) report, [`decide_terminal`]
    // produces EXACTLY ONE terminal whose disposition's outcome keys
    // EXACTLY equal the intent's selected membership (the payload-free
    // dispositions carry none, the failed dispositions carry exactly the
    // selected set); mismatched-key failure reports are REFUSED with an
    // integrity error.

    /// An arbitrary NON-EMPTY selected membership (the intent's Deploy set).
    fn selected_slots() -> impl Strategy<Value = Vec<SlotId>> {
        prop::collection::btree_set((0u32..4).prop_map(|i| SlotId::new(format!("p{i}"))), 1..=3)
            .prop_map(|s| s.into_iter().collect())
    }

    /// An arbitrary THREE-STATE post-mutation observation.
    fn arbitrary_observation()
    -> impl Strategy<Value = crate::ledger::Observation<crate::ledger::records::ObservedGeneration>>
    {
        prop_oneof![
            Just(crate::ledger::Observation::KnownAbsent),
            (0u32..3).prop_map(|i| crate::ledger::Observation::Known(
                crate::ledger::records::ObservedGeneration {
                    generation: test_generation_id(&format!("g-{i}")),
                }
            )),
            prop::sample::select(vec![
                "status read failed: boom".to_string(),
                "assignment read failed: boom".to_string(),
            ])
            .prop_map(|m| crate::ledger::Observation::Unknown(
                crate::ledger::records::ObservationError { message: m }
            )),
        ]
    }

    /// An arbitrary STRUCTURAL outcome: every variant of the SIX-state
    /// taxonomy (incl. with/without an operation error on the failed
    /// variants).
    fn arbitrary_outcome() -> impl Strategy<Value = SlotOutcome> {
        (
            prop_oneof![
                2 => Just(0u8), // Activated
                2 => Just(1u8), // Restored
                2 => Just(2u8), // Skipped
                1 => Just(3u8), // FailedBeforeAdvance
                1 => Just(4u8), // FailedAfterAdvance
                1 => Just(5u8), // Indeterminate
            ],
            arbitrary_observation(),
            prop::bool::ANY,
        )
            .prop_map(|(kind, observation, has_error)| {
                let error = has_error.then(|| "boom".to_string());
                match kind {
                    0 => SlotOutcome::Activated { observation },
                    1 => SlotOutcome::Restored { observation },
                    2 => SlotOutcome::Skipped { observation },
                    3 => SlotOutcome::FailedBeforeAdvance { observation, error },
                    4 => SlotOutcome::FailedAfterAdvance { observation, error },
                    _ => SlotOutcome::Indeterminate { observation, error },
                }
            })
    }

    /// An arbitrary NON-EMPTY outcome table over an arbitrary key set (the
    /// `Failed` report's evidence — generated INDEPENDENTLY of the selected
    /// membership, so both exact-keys and mismatched-keys reports are
    /// constructible).
    fn arbitrary_outcome_table() -> impl Strategy<Value = BTreeMap<SlotId, SlotOutcome>> {
        prop::collection::btree_set((0u32..4).prop_map(|i| SlotId::new(format!("p{i}"))), 1..=3)
            .prop_flat_map(|keys| {
                let n = keys.len();
                prop::collection::vec(arbitrary_outcome(), n)
                    .prop_map(move |outcomes| keys.iter().cloned().zip(outcomes).collect())
            })
    }

    /// An arbitrary ADAPTER-RESTORATION EVIDENCE map over ALL generated
    /// slots (the review's P1 fix): the sealed [`VerifiedAdapterRestoration`]
    /// proof the engine carries for every VERIFIED restored slot. Generated
    /// independently of the outcome table (a random subset of all slots), so
    /// a `Restored` outcome appears both WITH and WITHOUT its evidence — the
    /// property asserts the rolled-back refusal for the unverified half.
    fn arbitrary_adapter_evidence()
    -> impl Strategy<Value = BTreeMap<SlotId, VerifiedAdapterRestoration>> {
        prop::collection::vec(prop::bool::ANY, 4).prop_map(|flags| {
            (0u32..4)
                .zip(flags)
                .filter(|(_, f)| *f)
                .map(|(i, _)| {
                    (
                        SlotId::new(format!("p{i}")),
                        VerifiedAdapterRestoration::verified(),
                    )
                })
                .collect()
        })
    }

    /// A FULL-PUSH intent over the given selected membership (fresh target,
    /// group None — the selected set is the entire membership, so the
    /// intent is valid for ANY non-empty selection).
    fn full_intent(tag: &str, selected: &[SlotId]) -> DeploymentIntent {
        let planned: Vec<PlannedDeploy> = selected
            .iter()
            .map(|sid| PlannedDeploy {
                slot: sid.clone(),
                result: crate::testutil::fixtures::snapshot_slot(sid),
                pre_push: crate::ledger::Observation::KnownAbsent,
            })
            .collect();
        crate::kernel::intent::plan(PlanInput {
            deployment_id: test_deployment_id(tag),
            target: target(),
            parent: None,
            parent_snapshot: None,
            group: None,
            selection: selected.to_vec(),
            planned,
            behavior_digest: crate::testutil::fixtures::behavior_digest(),
            attempted_at: crate::identity::Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        })
        .expect("a valid full-push intent plans over an arbitrary selection")
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(32),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]
        #[test]
        fn decide_terminal_uses_the_intent_and_derives_the_disposition(
            selected in selected_slots(),
            outcome_table in arbitrary_outcome_table(),
            adapter_restored in arbitrary_adapter_evidence(),
            shape in 0u8..3,
        ) {
            let intent = full_intent("deploy-decide", &selected);
            let selected_set: BTreeSet<SlotId> = selected.iter().cloned().collect();
            match shape {
                0 => {
                    // PreflightFailed → FailedPreflight, payload-free.
                    let d = decide_terminal(&intent, ExecutionReport::PreflightFailed).unwrap();
                    prop_assert!(d.outcomes().is_empty());
                    prop_assert_eq!(d, TerminalDisposition::FailedPreflight);
                }
                1 => {
                    // Verified → Successful, payload-free.
                    let d = decide_terminal(&intent, ExecutionReport::Verified).unwrap();
                    prop_assert!(d.outcomes().is_empty());
                    prop_assert_eq!(d, TerminalDisposition::Successful);
                }
                _ => {
                    // Failed { outcomes }: exact selected keys are ACCEPTED
                    // (the disposition's outcome keys EXACTLY equal the
                    // selected membership); mismatched keys are REFUSED.
                    let keys: BTreeSet<SlotId> = outcome_table.keys().cloned().collect();
                    let table = NonEmptySlotTable::build(outcome_table).expect("non-empty table");
                    if keys == selected_set {
                        let all_unchanged = table.iter().all(|(sid, o)| {
                            crate::kernel::terminal::outcome_slot_delta(&intent, sid, o)
                                == SlotDelta::Unchanged
                        });
                        let unverified_restored = table.iter().any(|(sid, o)| {
                            matches!(o, SlotOutcome::Restored { .. })
                                && !adapter_restored.contains_key(sid)
                        });
                        match decide_terminal(
                            &intent,
                            ExecutionReport::Failed {
                                outcomes: table,
                                adapter_restored: adapter_restored.clone(),
                            },
                        ) {
                            Ok(d) => {
                                let dkeys: BTreeSet<SlotId> =
                                    d.outcomes().keys().cloned().collect();
                                prop_assert_eq!(
                                    dkeys, selected_set,
                                    "the decided terminal's outcome keys must EXACTLY equal the intent's selected membership"
                                );
                                // THE ADAPTER-RESTORATION GATE: an accepted
                                // rolled-back terminal NEVER contains a
                                // `Restored` outcome without its verified
                                // adapter restoration.
                                if all_unchanged {
                                    prop_assert!(
                                        !unverified_restored,
                                        "an all-Unchanged table with an UNVERIFIED Restored slot must be refused — never silently FailedRolledBack"
                                    );
                                }
                            }
                            Err(_) => {
                                // The ONLY refusal left on an exact-keys
                                // report is the ADAPTER-RESTORATION GATE: an
                                // all-Unchanged table with a `Restored`
                                // outcome whose adapter restoration is
                                // UNVERIFIED is refused as integrity (the
                                // review: MUST NOT silently produce
                                // FailedRolledBack).
                                prop_assert!(
                                    all_unchanged && unverified_restored,
                                    "the rolled-back refusal fires exactly when every delta is Unchanged but some Restored slot lacks its verified adapter restoration"
                                );
                            }
                        }
                    } else {
                        prop_assert!(
                            decide_terminal(
                                &intent,
                                ExecutionReport::Failed {
                                    outcomes: table,
                                    adapter_restored,
                                },
                            )
                            .is_err(),
                            "a failure report whose outcome keys do not exactly match the selected membership must be refused with an integrity error"
                        );
                    }
                }
            }
        }

        /// THE TERMINAL-STATE INVARIANTS PROPERTY (the review's P1 /
        /// acceptance item 2): for every generated intent/outcome/
        /// observation/ADAPTER-EVIDENCE combination over the selected
        /// membership — including an UNCOMPENSATED failure AFTER the slot
        /// advanced (an outcome whose state is `FailedAfterAdvance` with the
        /// desired-generation observation — the old rule could call it
        /// rolled back) and a `Restored` outcome WITH/WITHOUT its verified
        /// adapter restoration — the decision is EXACTLY ONE terminal (or
        /// the adapter-evidence integrity refusal), and:
        ///
        /// * `FailedRolledBack` ⇒ EVERY slot's [`SlotDelta`] is `Unchanged`
        ///   AND every `Restored` slot carries its verified adapter
        ///   restoration (the review's P1 fix: the generation delta alone
        ///   cannot see the unit file left in the new state);
        /// * `Degraded` ⇒ AT LEAST ONE `Desired`/`Diverged`/`Unknown` delta;
        /// * `remaining_changes` contains EXACTLY the
        ///   `Desired`/`Diverged`/`Unknown` slots.
        #[test]
        fn terminal_state_invariants_review_p1(
            selected in selected_slots(),
            outcome_table in arbitrary_outcome_table(),
            adapter_restored in arbitrary_adapter_evidence(),
        ) {
            let intent = full_intent("deploy-inv", &selected);
            let selected_set: BTreeSet<SlotId> = selected.iter().cloned().collect();
            let keys: BTreeSet<SlotId> = outcome_table.keys().cloned().collect();
            if keys != selected_set {
                return Ok(()); // mismatched-key reports are refused (covered above)
            }
            let table = NonEmptySlotTable::build(outcome_table).expect("non-empty table");
            let all_unchanged = table.iter().all(|(sid, o)| {
                crate::kernel::terminal::outcome_slot_delta(&intent, sid, o)
                    == SlotDelta::Unchanged
            });
            let unverified_restored = table.iter().any(|(sid, o)| {
                matches!(o, SlotOutcome::Restored { .. }) && !adapter_restored.contains_key(sid)
            });
            // THE ADAPTER-RESTORATION GATE: an all-Unchanged table with an
            // UNVERIFIED `Restored` slot is REFUSED (integrity) — never
            // silently FailedRolledBack (the review's P1 fix).
            if all_unchanged && unverified_restored {
                prop_assert!(
                    decide_terminal(
                        &intent,
                        ExecutionReport::Failed {
                            outcomes: table,
                            adapter_restored,
                        },
                    )
                    .is_err(),
                    "an all-Unchanged table with an UNVERIFIED Restored slot must be refused — never FailedRolledBack"
                );
                return Ok(());
            }
            let d = decide_terminal(
                &intent,
                ExecutionReport::Failed {
                    outcomes: table,
                    adapter_restored,
                },
            )
            .unwrap();
            let deltas: Vec<(SlotId, SlotDelta)> = d
                .outcomes()
                .iter()
                .map(|(sid, o)| {
                    (
                        sid.clone(),
                        crate::kernel::terminal::outcome_slot_delta(&intent, sid, o),
                    )
                })
                .collect();
            let remaining_keys: std::collections::BTreeSet<SlotId> = deltas
                .iter()
                .filter(|(_, delta)| *delta != SlotDelta::Unchanged)
                .map(|(sid, _)| sid.clone())
                .collect();
            // The terminal-level derivation under test: remaining_changes
            // (the same classifier) must equal EXACTLY the deltas' set.
            let terminal = LedgerTerminal::new(
                crate::identity::Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
                crate::kernel::terminal::intent_digest(&intent),
                d.clone(),
                None,
            );
            match &d {
                TerminalDisposition::FailedRolledBack(_) => {
                    prop_assert!(
                        all_unchanged,
                        "FailedRolledBack requires EVERY slot's delta to be Unchanged (the review's P1 rule)"
                    );
                    prop_assert!(
                        !unverified_restored,
                        "FailedRolledBack requires EVERY Restored slot's adapter restoration to be VERIFIED (the review's P1 fix)"
                    );
                    prop_assert!(
                        terminal.remaining_changes(&intent).is_none(),
                        "a rolled-back terminal derives no remaining changes"
                    );
                }
                TerminalDisposition::Degraded(_) => {
                    prop_assert!(
                        !all_unchanged,
                        "Degraded requires AT LEAST ONE Desired/Diverged/Unknown slot (nonempty deltas)"
                    );
                    let remaining = terminal
                        .remaining_changes(&intent)
                        .expect("a Degraded terminal derives remaining changes");
                    prop_assert_eq!(
                        remaining.keys().cloned().collect::<std::collections::BTreeSet<_>>(),
                        remaining_keys,
                        "remaining_changes contains EXACTLY the Desired/Diverged/Unknown slots"
                    );
                }
                _ => {
                    prop_assert!(
                        false,
                        "a Failed{{outcomes}} report decides EXACTLY ONE terminal: rolled-back or degraded"
                    );
                }
            }
        }
    }
}
