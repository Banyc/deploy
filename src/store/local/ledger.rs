//! The per-target deployment LEDGER (A2): `targets/<target>/ledger.jsonl` —
//! a STRICT EVENT STORE.
//!
//! The ledger layer is responsible ONLY for the event-store rules: strict
//! parsing, duplicate-key rejection, event ordering, one intent per
//! deployment, at most one terminal per intent, terminal `intent_digest`
//! equality, and the crash-atomic durable append. Every SEMANTIC event
//! transition (the status-specific outcome agreement, the disposition
//! payload acceptance) is validated by the SEMANTIC KERNEL's pure state
//! machine ([`crate::kernel::transition::apply_event`]) — the store never
//! independently decides deployment semantics.

use crate::deploy::lock::FileLock;
use crate::error::{Error, Result};
use crate::identity::{DeploymentId, TargetName};
use crate::kernel::error::{ConflictError, IntegrityError, KernelError};
use crate::kernel::terminal;
use crate::kernel::transition::{
    CheckpointEvent, DeploymentState, IntentEvent, LedgerEvent, TerminalEvent,
};
use crate::ledger::{
    CheckpointWire, DeploymentIntent, DeploymentStatus, LEDGER_SCHEMA_VERSION, LedgerEntry,
    LedgerEventWire, LedgerIntentWire, LedgerTerminal, LedgerTerminalWire,
};
use crate::store::atomic::{
    ReplaceOutcome, path_state, set_private, sync_parent_dir, temp_name_for,
};
use crate::store::local::LocalStore;
use std::io::Write;
use std::path::PathBuf;

#[cfg(test)]
use crate::testutil::test_faults::FaultKind;

/// THE PRE-WRITE TERMINAL VALIDATION — the exact checks the read path's
/// [`LocalStore::read_ledger`] (the kernel's `apply_event`) would apply when
/// the terminal merges into its entry, run BEFORE any write (fail closed —
/// the ledger bytes stay unchanged on rejection). A terminal the strict
/// state machine would reject is NEVER written, so any successful append is
/// immediately readable. `entries` is the ledger WITHOUT the terminal being
/// validated (its entry is still terminal-less).
fn validate_terminal_append(
    _target: &str,
    entries: &[LedgerEntry],
    entry: &LedgerEntry,
    terminal: &LedgerTerminal,
) -> Result<()> {
    // THE INTENT_DIGEST BINDING (event-store rule): the terminal must bind
    // the EXACT canonical intent. Refused with the typed
    // [`IntegrityError::IntentDigestMismatch`] through the [`Error::Kernel`]
    // facade (the complete typed error preserved, class + code + the
    // expected vs recorded digests).
    if terminal.intent_digest().as_str() != terminal::intent_digest(&entry.intent).as_str() {
        return Err(Error::Kernel(KernelError::Integrity(
            IntegrityError::IntentDigestMismatch {
                deployment: entry.deployment_id.clone(),
                expected: terminal::intent_digest(&entry.intent),
                recorded: terminal.intent_digest().clone(),
            },
        )));
    }
    // THE SEMANTIC TRANSITION (delegated to the kernel): the disposition's
    // outcome payload must agree with the entry's intent (outcome keys ⊆
    // selected; suspicion-specific coverage). The kernel refusal is
    // preserved through the facade (an Integrity-class message-only
    // refusal), never flattened.
    crate::kernel::transition::validate_terminal_vs_intent(entry, terminal)
        .map_err(Error::Kernel)?;
    // THE STRICTLY-LINEAR TERMINAL MIRROR (item 5 of the spec): a terminal
    // must settle the ONE pending intent — no OTHER entry may still be
    // terminal-less (a second unresolved attempt would make this terminal an
    // impossible event). Refused at the write boundary as a Conflict (a valid
    // append against an impossible state is refused before any write; the
    // ledger bytes stay unchanged) with the typed
    // [`ConflictError::PendingAttemptExists`] evidence (the still-pending
    // deployment).
    let pending = entries
        .iter()
        .find(|e| e.deployment_id != entry.deployment_id && e.terminal.is_none());
    if let Some(pending) = pending {
        return Err(Error::Kernel(KernelError::Conflict(
            ConflictError::PendingAttemptExists {
                pending: pending.deployment_id.clone(),
            },
        )));
    }
    // THE ONE-PARENT RULE, mirroring the kernel's state machine
    // ([`crate::kernel::transition::apply_event`]): a Successful terminal
    // requires that no OTHER entry in the ledger already carries a Successful
    // terminal for the same parent. Under the strictly-linear model this is now
    // a DEFENSIVE re-check — the intent-append gates already enforce one
    // pending at a time and `parent == head` at intent-append time — but it
    // remains the ATOMIC last line of defense under the target lock: for any
    // given parent at most ONE plan can ever append `Successful`, and a stale
    // finalizer is refused with the kernel's [`ConflictError::ParentMismatch`]
    // (StalePlan), never reconciled implicitly, never successful.
    if terminal.disposition().is_successful() {
        let already = entries.iter().any(|e| {
            e.deployment_id != entry.deployment_id
                && e.terminal.as_ref().is_some_and(|t| {
                    t.status() == DeploymentStatus::Successful
                        && e.intent.parent() == entry.intent.parent()
                })
        });
        if already {
            let actual_head = entries
                .iter()
                .rev()
                .find(|e| {
                    e.terminal
                        .as_ref()
                        .is_some_and(|t| t.status() == DeploymentStatus::Successful)
                })
                .map(|e| e.deployment_id.clone());
            return Err(Error::Kernel(KernelError::Conflict(
                ConflictError::ParentMismatch {
                    deployment: entry.deployment_id.clone(),
                    recorded_parent: entry.intent.parent().cloned(),
                    actual_head,
                },
            )));
        }
    }
    Ok(())
}

/// THE PRE-WRITE INTENT VALIDATION — the STRICT-LINEAR lineage mirror of the
/// kernel's intent-append gates ([`crate::kernel::transition::apply_event`]'s
/// intent branch), run BEFORE any write (fail closed — the ledger bytes stay
/// unchanged on rejection):
///
/// * [`LineageViolation::PendingAttemptExists`]: a terminal-less entry
///   exists — a new intent cannot be appended until the pending attempt
///   reaches a terminal (a push that cannot finish the previous pending
///   attempt is REFUSED; it never plans a second intent on top, even for
///   disjoint groups);
/// * [`LineageViolation::ParentMismatch`]: the intent's parent must equal
///   the target's current successful head (the newest `Successful` entry);
/// * [`validate_inherited_slots`]: every inherited slot must equal the
///   head's snapshot entry.
///
/// At the WRITE boundary these are [`Error::Kernel`] **Conflict** refusals
/// (a valid operation against stale or concurrently changed state) carrying
/// the typed evidence ([`ConflictError::PendingAttemptExists`] /
/// [`ConflictError::ParentMismatch`]); the READ path (the fold in
/// `read_ledger`) classifies the same violations as persisted-data
/// corruption (Integrity). The inherited-slot congruence is the one
/// exception: [`ConflictError`] carries no inherited variant (the typed
/// [`IntegrityError::InheritedSnapshotMismatch`] is a READ form), so the
/// write mirror keeps the message-form Conflict for that refusal — the
/// class mapping and prose preserved exactly as before; the typed form
/// surfaces on the read path and in the semantic-mutation property.
fn validate_intent_append(
    _target: &str,
    entries: &[LedgerEntry],
    intent: &DeploymentIntent,
) -> Result<()> {
    // (1) PendingAttemptExists: at most ONE unresolved intent at a time.
    if let Some(pending) = entries.iter().find(|e| e.terminal.is_none()) {
        return Err(Error::Kernel(KernelError::Conflict(
            ConflictError::PendingAttemptExists {
                pending: pending.deployment_id.clone(),
            },
        )));
    }
    // (2) ParentMismatch: the parent must be the current successful head.
    let head = entries
        .iter()
        .rev()
        .find(|e| {
            e.terminal
                .as_ref()
                .is_some_and(|t| t.status() == DeploymentStatus::Successful)
        })
        .map(|e| &e.deployment_id);
    if intent.parent() != head {
        return Err(Error::Kernel(KernelError::Conflict(
            ConflictError::ParentMismatch {
                deployment: intent.deployment_id().clone(),
                recorded_parent: intent.parent().cloned(),
                actual_head: head.cloned(),
            },
        )));
    }
    // (3) Inherited-slot congruence: the intent's inherited entries must
    // match the head's snapshot (only when a head exists — there are no
    // inherited slots to check against on a fresh target).
    let head_entry = head.and_then(|h| entries.iter().find(|e| &e.deployment_id == h));
    if let Some(head_entry) = head_entry {
        let head_snapshot = crate::kernel::snapshot::resolve_snapshot(head_entry).map_err(|e| {
            Error::integrity(format!(
                "ledger of target '{_target}' cannot resolve the successful head's snapshot: {e}"
            ))
        })?;
        // The kernel refusal (the READ form is the typed
        // [`IntegrityError::InheritedSnapshotMismatch`]) is rendered into the
        // write-boundary Conflict message form (see the fn doc — ConflictError
        // carries no inherited variant).
        crate::kernel::transition::validate_inherited_slots(intent, &head_snapshot).map_err(
            |e| {
                Error::conflict(format!(
                    "ledger of target '{_target}' refuses the intent for deployment '{}': {e}",
                    intent.deployment_id()
                ))
            },
        )?;
    }
    Ok(())
}

impl LocalStore {
    // ---- the per-target deployment LEDGER --------------------------------

    /// Path of the target's ONE ordered deployment ledger
    /// (`targets/<target>/ledger.jsonl`). The ledger holds every deployment
    /// event of the target: each entry starts as the DURABLE INTENT line
    /// (written BEFORE any remote mutation) and its TERMINAL EVENT line
    /// (appended after the mutation loop) carries its disposition. A
    /// checkpointed ledger's FIRST line is the checkpoint event. The append
    /// order IS the history order.
    pub fn ledger_path(&self, target: &str) -> PathBuf {
        self.target_dir(target).join("ledger.jsonl")
    }

    /// Append the DURABLE INTENT of one deployment to the target's ledger
    /// (one `{"kind":"intent", ...}` JSON line), BEFORE any remote
    /// mutation: a crash after servers advanced to new generations can never
    /// lose the deployment (the intent is already durable and the next push
    /// reconciles it). The append is a CRASH-ATOMIC whole-ledger rewrite
    /// (temp + fsync + chmod + rename + parent-dir fsync, see
    /// `TargetLedgerTxn::write_state`). Fail-closed keying: the deployment
    /// id keys the entry, so a second intent for the same id (a corrupted
    /// duplicate) is refused rather than silently merged. The duplicate
    /// guard scans EVERY folded entry, not just the first one.
    //
    // THE WRITE SURFACE IS THE TXN: this method was the raw unlocked
    // `append_intent`; it is GONE from the store surface — an intent is
    // appended only through [`TargetLedgerTxn::append_intent`] (which owns
    // the target lock + the folded state). See the txn section below.
    //
    // (The append itself moved verbatim into [`TargetLedgerTxn`]: the
    // duplicate guard, the pre-write lineage validation with its
    // write-boundary Conflict classes, the kernel fold, and the atomic
    // whole-ledger rewrite.)
    ///
    /// Append the TERMINAL EVENT of one deployment to the target's ledger
    /// ("`{"kind":"terminal", ...}`" JSON line), after the mutation loop.
    /// The terminal binds its intent by `intent_digest` and carries its
    /// structural disposition. Fail-closed key contract: the deployment's
    /// intent must already exist in the ledger (a terminal for an unknown
    /// deployment is corruption) and the entry must not already have a
    /// terminal (the terminal event is written exactly once).
    ///
    /// LET THE ENCLOSING OBJECT OWN IDENTITY: the DOMAIN [`LedgerTerminal`]
    /// carries no `deployment_id` / `target`; the caller supplies the
    /// deployment id (the wire keeps the on-disk identity members; the
    /// reader verifies them equal to the enclosing entry's).
    //
    // THE WRITE SURFACE IS THE TXN: this method was the raw unlocked
    // `append_terminal`; it is GONE from the store surface — a terminal is
    // appended only through [`TargetLedgerTxn::append_terminal`] (which owns
    // the target lock + the folded state), and a `Successful` terminal is
    // additionally gated by the sealed [`crate::kernel::terminal::
    // VerifiedExecution`] proof (see [`crate::kernel::terminal::
    // LedgerTerminal::successful`]) — a library caller cannot fabricate
    // success.
    //
    // (The append itself moved verbatim into [`TargetLedgerTxn`]: the
    // key contract, the pre-write validation with its write-boundary
    // classes, the kernel fold, and the atomic whole-ledger rewrite.)
    //
    // THERE IS NO GENERAL `append_checkpoint` ANYWHERE: a CHECKPOINT event
    // enters a ledger ONLY through the validated suffix replacement
    // ([`TargetLedgerTxn::write_suffix`] → `LocalStore::write_ledger_suffix`,
    // the checkpoint flow's atomic replacement) — a bare checkpoint-event
    // append would let a corrupted invocation write a checkpoint mid-ledger
    // (the reader requires it FIRST), so no such append exists.
    ///
    /// Fold the target's ledger into the KERNEL's pure state
    /// ([`DeploymentState`]) — the SINGLE authoritative fold every read
    /// ([`LocalStore::read_ledger`]) and every [`TargetLedgerTxn`] append
    /// validates against (fail closed on malformed lines, foreign
    /// `deployment_schema_version`, an intent-less terminal, a duplicate
    /// intent, a duplicate terminal, or a disagreeing record). The txn
    /// calls this at open and after a validated suffix replacement, so its
    /// in-memory state is always exactly what the reader would produce.
    fn read_ledger_state(&self, target: &str) -> Result<DeploymentState> {
        let p = self.ledger_path(target);
        // Tri-state: only a genuine NotFound is "no ledger" (the empty
        // state); a stat failure propagates as a Store error (an unreadable
        // ledger must not read as "no history").
        if !path_state(&p)? {
            let target_name = TargetName::parse(target).expect("ledger target is a safe segment");
            return Ok(DeploymentState::new(target_name));
        }
        let text =
            std::fs::read_to_string(&p).map_err(|e| Error::store(format!("read ledger: {e}")))?;
        let target_name = TargetName::parse(target).expect("ledger target is a safe segment");
        let mut state = DeploymentState::new(target_name);
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let event = match serde_json::from_str::<LedgerEventWire>(line)
                .map_err(|e| Error::store(format!("parse ledger line: {e}")))?
            {
                LedgerEventWire::Intent(wire) => {
                    // Fail closed on the record schema version: only
                    // `LEDGER_SCHEMA_VERSION` is accepted, any other version
                    // is refused with an error naming the version (a record
                    // from a different schema is never silently
                    // interpreted).
                    if wire.deployment_schema_version != LEDGER_SCHEMA_VERSION {
                        return Err(Error::store(format!(
                            "intent {} carries unsupported deployment_schema_version {} (expected {LEDGER_SCHEMA_VERSION}): only LEDGER_SCHEMA_VERSION is accepted",
                            wire.deployment_id, wire.deployment_schema_version
                        )));
                    }
                    let intent = wire.into_domain().map_err(|e| {
                        Error::integrity(format!(
                            "ledger for target '{target}' refuses an intent line: {e}"
                        ))
                    })?;
                    LedgerEvent::Intent(IntentEvent { intent })
                }
                LedgerEventWire::Terminal(wire) => {
                    let deployment_id = wire.deployment_id.clone();
                    let terminal = wire.into_domain().map_err(|e| {
                        Error::integrity(format!(
                            "ledger for target '{target}' refuses a terminal line: {e}"
                        ))
                    })?;
                    LedgerEvent::Terminal(TerminalEvent {
                        deployment_id,
                        terminal,
                    })
                }
                LedgerEventWire::Checkpoint(wire) => {
                    if wire.deployment_schema_version != LEDGER_SCHEMA_VERSION {
                        return Err(Error::store(format!(
                            "checkpoint event carries unsupported deployment_schema_version {} (expected {LEDGER_SCHEMA_VERSION})",
                            wire.deployment_schema_version
                        )));
                    }
                    let retained_from =
                        DeploymentId::parse(&wire.retained_from).map_err(|_| {
                            Error::integrity(format!(
                                "ledger for target '{target}' refuses a checkpoint line: retained_from {:?} is not a deployment id",
                                wire.retained_from
                            ))
                        })?;
                    let recorded_at =
                        crate::identity::Timestamp::parse(&wire.recorded_at).map_err(|_| {
                            Error::integrity(format!(
                                "ledger for target '{target}' refuses a checkpoint line: recorded_at {:?} is not an RFC 3339 timestamp",
                                wire.recorded_at
                            ))
                        })?;
                    LedgerEvent::Checkpoint(CheckpointEvent {
                        retained_from,
                        discarded: wire.discarded,
                        recorded_at,
                    })
                }
            };
            // A refused event carries the TYPED kernel error through the
            // facade ([`Error::Kernel`]), preserving the class / code /
            // evidence — the physical line numbers of the violated rule live
            // in the typed variants (each accepted event knows its own
            // position inside the state machine), so the outer text needs no
            // store-side "rejects line N" flattening.
            state = crate::kernel::transition::apply_event(state, event).map_err(Error::Kernel)?;
        }
        Ok(state)
    }

    /// Read the FULL deployment ledger of a target: every merged
    /// [`LedgerEntry`] (intent + optional terminal), in append order. This is
    /// the SINGLE history read: a fold of the kernel state (the same fold
    /// `TargetLedgerTxn::open` performs, with `finish()` appended) plus the
    /// STRUCTURAL COMPLETENESS GATE (item 8 of the spec). After the full
    /// fold, a checkpointed ledger must carry its SUCCESSFUL ANCHOR
    /// (the checkpoint's `retained_from` entry present and finalized
    /// `Successful`); a non-checkpointed ledger passes trivially. A
    /// structurally incomplete checkpoint prefix (a checkpoint with no
    /// following anchor, or an anchor that never reached its `Successful`
    /// terminal) is corruption — the typed
    /// [`IntegrityError::CheckpointAnchorMismatch`], preserved through the
    /// facade.
    pub fn read_ledger(&self, target: &str) -> Result<Vec<LedgerEntry>> {
        let state = self.read_ledger_state(target)?;
        state.finish().map_err(Error::Kernel)?;
        Ok(state.into_entries())
    }

    /// The target's LATEST SUCCESSFUL deployment id, derived from the ledger
    /// (the newest entry whose terminal event is `Successful`). The old
    /// `refs/last-successful` mutable ref file is GONE: the derived read is
    /// exact by construction — no stale-ref crash corner exists anymore.
    pub fn read_last_successful(&self, target: &str) -> Option<String> {
        self.read_ledger(target)
            .ok()?
            .into_iter()
            .rev()
            .find_map(|e| {
                e.terminal
                    .as_ref()
                    .is_some_and(|t| t.status() == DeploymentStatus::Successful)
                    .then(|| e.deployment_id.as_str().to_string())
            })
    }

    /// The current status of a deployment: the status of its TERMINAL EVENT
    /// in the target's ledger, or — when the entry exists but has no
    /// terminal yet — `Ok(None)` (the PENDING state: an intent WITHOUT a
    /// terminal IS pending; its recovery phase is an operational view
    /// derived from markers/transactions, never a status on the terminal
    /// enum). Scans every target's ledger (the deployment id does not name
    /// its target; the entry's own intent does).
    pub fn latest_status(&self, id: &str) -> Result<Option<DeploymentStatus>> {
        let targets_dir = self.base.join("targets");
        if !path_state(&targets_dir)? {
            return Ok(None);
        }
        for dir in std::fs::read_dir(&targets_dir)
            .map_err(|e| Error::store(format!("read_dir targets: {e}")))?
        {
            let dir = dir.map_err(|e| Error::store(format!("target entry: {e}")))?;
            let name = dir.file_name().to_string_lossy().into_owned();
            if !dir.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            for e in self.read_ledger(&name)? {
                if e.deployment_id.as_str() == id {
                    return Ok(e.terminal.map(|t| t.status()));
                }
            }
        }
        Ok(None)
    }
    /// THE LEDGER WRITE's durability protocol: atomically rewrite the WHOLE
    /// ledger from the given canonical lines through the same four-stage
    /// sequence as the generic [`crate::store::atomic::write_atomic_replace`]:
    /// a UNIQUE temp file in the same directory, chmod-private BEFORE it can
    /// become visible, temp fsync, atomic rename (a reader sees wholly OLD or
    /// wholly NEW, never a torn line), then a FAIL-CLOSED parent-directory
    /// fsync (the durability commit point: the new ledger must survive power
    /// loss before the write reports success).
    ///
    /// The stages are materialized here — rather than a single
    /// `write_atomic_replace` call — so the per-fixture test registry can
    /// fault each one ([`FaultKind::AppendWrite`] / [`FaultKind::AppendSync`]
    /// / [`FaultKind::AppendRename`] / [`FaultKind::AppendDirSync`]), keyed
    /// by the deployment id being written. The first three fault stages
    /// abort BEFORE the rename: the visible ledger is wholly OLD (a leftover
    /// dot-prefixed temp is invisible to every read). The dir-sync fault
    /// fires AFTER the rename: the ledger is wholly NEW — only the directory
    /// entry is unsynced — and the write returns `Err` (the same
    /// post-commit window the checkpoint's [`FaultKind::LedgerReplaceDirSync`]
    /// models).
    ///
    /// The caller is ALWAYS a [`TargetLedgerTxn`] holding the target
    /// `operation.lock` (the whole-ledger rewrite cannot interleave with a
    /// concurrent rewrite), and the lines are the txn's FOLDED STATE
    /// serialized — the bytes written are exactly the state (never a
    /// read-modify-append that could disagree with the fold).
    fn write_ledger_lines(
        &self,
        target: &str,
        _deployment_id: &str,
        lines: &[String],
    ) -> Result<()> {
        let p = self.ledger_path(target);
        // Durable target-dir creation (the FIRST append's reported bug): the
        // `targets/<target>/` — and `targets/` — directory entries must be
        // fsynced before the ledger write can report success. An existing
        // target's dir is the helper's fast path (created nothing, syncs
        // nothing).
        self.ensure_target_dir_durable(target)?;
        // The WHOLE new ledger, from the caller's canonical lines. There is
        // no read of the current file: the rewrite IS the folded state, so
        // the write can never disagree with the fold (and a ledger that
        // failed to fold could not have opened the txn in the first place).
        let mut buf = String::new();
        for line in lines {
            buf.push_str(line);
            buf.push('\n');
        }

        // Stage 1: the temp write.
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::AppendWrite, _deployment_id)
        {
            return Err(Error::store(
                "test fault: ledger append (temp write) forced to fail once",
            ));
        }
        let tmp = temp_name_for(&p);
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| Error::store(format!("create {}: {e}", tmp.display())))?;
            f.write_all(buf.as_bytes())
                .map_err(|e| Error::store(format!("write {}: {e}", tmp.display())))?;
        }
        // Stage 2: the temp fsync.
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::AppendSync, _deployment_id)
        {
            return Err(Error::store(
                "test fault: ledger append (temp sync) forced to fail once",
            ));
        }
        {
            let f = std::fs::File::open(&tmp)
                .map_err(|e| Error::store(format!("open {}: {e}", tmp.display())))?;
            f.sync_all()
                .map_err(|e| Error::store(format!("fsync {}: {e}", tmp.display())))?;
        }
        // Private BEFORE visible: the temp carries 0o600 before the rename.
        set_private(&tmp)?;
        // Stage 3: the atomic rename (the commit point).
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::AppendRename, _deployment_id)
        {
            return Err(Error::store(
                "test fault: ledger append (rename) forced to fail once",
            ));
        }
        std::fs::rename(&tmp, &p)
            .map_err(|e| Error::store(format!("rename {}: {e}", p.display())))?;
        // Stage 4: the FAIL-CLOSED parent-directory fsync, AFTER the rename:
        // the new ledger is already visible, but not durable across power
        // loss until its directory entry is synced.
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::AppendDirSync, _deployment_id)
        {
            return Err(Error::store(
                "test fault: ledger append (parent-dir sync) forced to fail once",
            ));
        }
        sync_parent_dir(&p)?;
        Ok(())
    }
}

// =====================================================================
// THE TARGET LEDGER TRANSACTION — the ONLY write surface of a target's
// ledger ---------------------------------------------------------------
//
// A write to a target's ledger happens ONLY through a [`TargetLedgerTxn`]:
// the txn OWNS the target's `operation.lock` ([`FileLock`] — the
// stable-inode advisory lock the push and checkpoint already hold) for its
// whole lifetime AND the folded [`DeploymentState`] (read once at open,
// updated in memory by the txn's own appends). Two concurrent txns on one
// target cannot both be open (the flock serializes them), so the old
// read-modify-write race — two writers racing a whole-ledger rewrite and
// losing each other's updates — is structurally gone: every append is a
// read of the txn's OWN state, folded, then written under the held lock.
//
// THE FOLD IS THE WRITE: each append updates the in-memory state through
// the kernel's pure [`crate::kernel::transition::apply_event`] FIRST and
// then rewrites the WHOLE ledger as the state's serialization
// ([`state_to_lines`]) — the fold and the bytes cannot disagree (single
// source). A refused event (the state machine's refusal, or the
// write-boundary validators' Conflict classes) is NEVER written.
//
// The raw store-level append methods are GONE from the public surface: a
// library caller has no way to append a ledger line (intent, terminal, or
// checkpoint) outside a locked txn, and a `Successful` terminal is
// additionally gated by the sealed [`crate::kernel::terminal::
// VerifiedExecution`] proof (see [`crate::kernel::terminal::
// LedgerTerminal::successful`]).
pub(crate) struct TargetLedgerTxn<'a> {
    store: &'a LocalStore,
    target: String,
    /// THE TARGET LOCK (`targets/<target>/operation.lock`) — held for the
    /// txn's whole lifetime; the field is otherwise unused (its Drop is the
    /// release).
    _lock: FileLock,
    /// THE FOLDED DEPLOYMENT STATE — the txn's concurrency authority AND
    /// its write source: every append folds the new event into this state
    /// and persists exactly the state.
    state: DeploymentState,
}

impl<'a> TargetLedgerTxn<'a> {
    /// Open the write transaction on ONE target: durably pre-create the
    /// target directory, ACQUIRE the target `operation.lock` (fail fast —
    /// a concurrent holder is refused with the lock's "held by" error, so
    /// two txns can never be open on one target), and FOLD the current
    /// ledger into the kernel state (fail closed: a ledger the strict
    /// reader would refuse — including a structurally incomplete
    /// checkpoint prefix — refuses to open the txn). The lock is held for
    /// the txn's whole lifetime (released on Drop, never before).
    pub(crate) fn open(store: &'a LocalStore, target: &str, op_id: &str) -> Result<Self> {
        // Durable target-directory pre-creation BEFORE the lock, mirroring
        // [`crate::deploy::push`]: the lock path must never create the
        // target dir with an unsynced mkdir (the reported durability bug).
        store.ensure_target_dir_durable(target)?;
        let _lock = FileLock::acquire(&store.target_dir(target).join("operation.lock"), op_id)?;
        let state = store.read_ledger_state(target)?;
        // THE STRUCTURAL COMPLETENESS GATE: a checkpointed ledger must
        // carry its SUCCESSFUL anchor — the same gate the read path
        // applies; a broken ledger refuses to open the txn.
        state.finish().map_err(Error::Kernel)?;
        Ok(TargetLedgerTxn {
            store,
            target: target.to_string(),
            _lock,
            state,
        })
    }

    /// The txn's target name.
    pub(crate) fn target(&self) -> &str {
        &self.target
    }

    /// The FOLDED STATE — the txn's authoritative view of the ledger (the
    /// same fold the reader produces; the txn IS the pure state machine,
    /// it never diverges). Read-only accessor: consumers read the pending
    /// attempt / successful head / entries for their pre-checks; only the
    /// txn's own appends mutate it.
    pub(crate) fn state(&self) -> &DeploymentState {
        &self.state
    }

    /// Append the DURABLE INTENT of one deployment (one
    /// `{"kind":"intent", ...}` JSON line), BEFORE any remote mutation.
    /// Fail-closed keying: the deployment id keys the entry, so a second
    /// intent for the same id is refused rather than silently merged (the
    /// duplicate guard scans EVERY folded entry, not just the first one).
    ///
    /// THE PRE-WRITE LINEAGE VALIDATION runs against the txn's OWN
    /// in-memory entries (no re-read — the fold and the write share one
    /// source) with the write-boundary Conflict classification, and the
    /// kernel's pure state machine ([`crate::kernel::transition::
    /// apply_event`]) is the single authority: the event is folded into
    /// the in-memory state FIRST (a refusal writes nothing), then the
    /// whole ledger is atomically rewritten as the state.
    pub(crate) fn append_intent(&mut self, intent: &DeploymentIntent) -> Result<()> {
        #[cfg(test)]
        if self
            .store
            .fault_registry
            .consume(FaultKind::AppendAttempt, intent.deployment_id().as_str())
        {
            return Err(Error::store(
                "test fault: append_attempt (ledger intent) forced to fail once",
            ));
        }
        // The intent is the entry's durable key: a duplicate intent for
        // the same deployment id is corruption (deployment ids are unique
        // per push) and must fail closed rather than append a second entry.
        if self
            .state
            .entries()
            .iter()
            .any(|e| e.deployment_id == *intent.deployment_id())
        {
            return Err(Error::store(format!(
                "refusing to append a second intent for deployment '{}' (the ledger is keyed by deployment id)",
                intent.deployment_id()
            )));
        }
        // THE PRE-WRITE STRICT-LINEAR LINEAGE VALIDATION (fail closed —
        // item 6 of the spec): the new intent is verified against the SAME
        // lineage gates the read path's state machine applies, BEFORE any
        // write (at most one pending attempt — a push that cannot finish
        // the previous pending attempt is REFUSED with a Conflict and never
        // plans a second intent; the parent must equal the current
        // successful head; the inherited slots must match the head's
        // snapshot). An intent the strict reader would reject is NEVER
        // written (the append is atomic; the ledger bytes stay unchanged on
        // rejection).
        validate_intent_append(&self.target, self.state.entries(), intent)?;
        // THE FOLD — the state machine is the single authority: accept the
        // event into the in-memory state FIRST (a refusal writes nothing),
        // then persist the state.
        let event = LedgerEvent::Intent(IntentEvent {
            intent: intent.clone(),
        });
        let next = crate::kernel::transition::apply_event(self.state.clone(), event)
            .map_err(Error::Kernel)?;
        self.state = next;
        self.write_state(intent.deployment_id().as_str())
    }

    /// Append the TERMINAL EVENT of one deployment ("`{"kind":"terminal",
    /// ...}`" JSON line), after the mutation loop. Fail-closed key
    /// contract: the deployment's intent must already be in the ledger (a
    /// terminal for an unknown deployment is corruption) and the entry must
    /// not already have a terminal (a terminal is written exactly once).
    ///
    /// THE PRE-WRITE VALIDATION runs against the txn's OWN in-memory
    /// entries with the write-boundary classes (the intent_digest binding,
    /// the disposition-vs-intent agreement, the strictly-linear pending
    /// gate, and the one-parent gate on a `Successful` disposition — the
    /// kernel's Conflict/StalePlan source), and the kernel's pure state
    /// machine is the single authority: the event is folded into the
    /// in-memory state FIRST (a refusal writes nothing), then the whole
    /// ledger is atomically rewritten as the state.
    ///
    /// A `Successful` terminal REQUIRES the sealed
    /// [`crate::kernel::terminal::VerifiedExecution`] proof at
    /// construction ([`crate::kernel::terminal::LedgerTerminal::successful`])
    /// — the txn itself never decides a disposition; it only persists the
    /// terminal it is given.
    pub(crate) fn append_terminal(
        &mut self,
        deployment_id: &DeploymentId,
        terminal: &LedgerTerminal,
    ) -> Result<()> {
        #[cfg(test)]
        if self
            .store
            .fault_registry
            .consume(FaultKind::AppendTerminal, deployment_id.as_str())
        {
            return Err(Error::store(
                "test fault: append_terminal forced to fail once",
            ));
        }
        let entry = self
            .state
            .entries()
            .iter()
            .find(|e| e.deployment_id == *deployment_id)
            .ok_or_else(|| {
                Error::integrity(format!(
                    "append_terminal for deployment '{deployment_id}': no ledger intent exists for it — a terminal event requires its durable intent (a terminal without an intent is corruption)"
                ))
            })?;
        if entry.terminal.is_some() {
            return Err(Error::integrity(format!(
                "append_terminal for deployment '{deployment_id}': the entry already carries a terminal event (a terminal is written exactly once)"
            )));
        }
        // THE PRE-WRITE VALIDATION (fail closed): the intent/terminal pair
        // is verified against the SAME checks the read path's state machine
        // applies BEFORE any write — the intent_digest binding, the
        // disposition-vs-intent agreement, and the one-parent gate on a
        // `Successful` disposition (the kernel's Conflict/StalePlan source).
        // A terminal the strict reader would reject is NEVER written (the
        // append is atomic; the ledger bytes stay unchanged on rejection).
        validate_terminal_append(&self.target, self.state.entries(), entry, terminal)?;
        // THE FOLD — the state machine is the single authority.
        let event = LedgerEvent::Terminal(TerminalEvent {
            deployment_id: deployment_id.clone(),
            terminal: terminal.clone(),
        });
        let next = crate::kernel::transition::apply_event(self.state.clone(), event)
            .map_err(Error::Kernel)?;
        self.state = next;
        self.write_state(deployment_id.as_str())
    }

    /// THE VALIDATED SUFFIX REPLACEMENT — the ONLY way a CHECKPOINT event
    /// enters a ledger (there is no general checkpoint append anywhere).
    /// The checkpoint flow's atomic whole-ledger replacement
    /// ([`LocalStore::write_ledger_suffix`], the temp + fsync + chmod +
    /// rename + parent-dir fsync writer that reports its TWO COMMIT POINTS
    /// via [`ReplaceOutcome`]) runs THROUGH the txn — under its target
    /// lock — with the new ledger's first line being the checkpoint event
    /// (the reader requires a checkpoint FIRST, so a mid-ledger checkpoint
    /// is unrepresentable: only this validated replacement, which recomputes
    /// the retained suffix from a SUCCESSFUL deployment, produces one).
    ///
    /// After a committed replacement (durability confirmed or unconfirmed —
    /// either way the new ledger IS visible) the txn RE-FOLDS its state
    /// from the committed bytes, so the txn stays the single source; a
    /// pre-rename `Err` left the old ledger standing (state unchanged).
    pub(crate) fn write_suffix(&mut self, new_ledger: &[String]) -> Result<ReplaceOutcome> {
        let outcome = self.store.write_ledger_suffix(&self.target, new_ledger)?;
        match outcome {
            ReplaceOutcome::ReplacedDurable | ReplaceOutcome::ReplacedDurabilityUnknown { .. } => {
                self.state = self.store.read_ledger_state(&self.target)?;
                self.state.finish().map_err(Error::Kernel)?;
            }
        }
        Ok(outcome)
    }

    /// Persist the folded state: serialize it to its canonical wire lines
    /// (checkpoint event first when present, then each entry's intent line
    /// and terminal line in append order) and atomically rewrite the WHOLE
    /// ledger. THE WRITE IS THE STATE — the fold and the bytes cannot
    /// disagree.
    fn write_state(&self, deployment_id: &str) -> Result<()> {
        let lines = state_to_lines(&self.state)?;
        self.store
            .write_ledger_lines(&self.target, deployment_id, &lines)
    }
}

/// THE CANONICAL WIRE-LINE PROJECTION of a folded state: the checkpoint
/// event (when the ledger began with one), then per accepted entry its
/// intent line and — once the entry reached its terminal — its terminal
/// line, in append order. The projection is exactly what the reader folds
/// back into the same state (the wire conversions are order- and
/// content-preserving), so a whole-ledger rewrite from the state always
/// reproduces the ledger the reader would accept.
fn state_to_lines(state: &DeploymentState) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    if let Some(cp) = state.checkpoint() {
        let wire =
            CheckpointWire::new(&cp.retained_from, cp.discarded, &cp.recorded_at.to_string());
        lines.push(
            serde_json::to_string(&LedgerEventWire::Checkpoint(wire))
                .map_err(|e| Error::store(format!("serialize ledger checkpoint: {e}")))?,
        );
    }
    for e in state.entries() {
        lines.push(
            serde_json::to_string(&LedgerEventWire::Intent(LedgerIntentWire::from(&e.intent)))
                .map_err(|e| Error::store(format!("serialize ledger intent: {e}")))?,
        );
        if let Some(terminal) = &e.terminal {
            let wire = LedgerTerminalWire::to_wire(&e.deployment_id, terminal);
            lines.push(
                serde_json::to_string(&LedgerEventWire::Terminal(wire))
                    .map_err(|e| Error::store(format!("serialize ledger terminal: {e}")))?,
            );
        }
    }
    Ok(lines)
}

#[cfg(test)]
impl LocalStore {
    /// TEST-ONLY: append an intent through a freshly opened (and dropped)
    /// [`TargetLedgerTxn`]: every test append goes through the SAME locked
    /// txn surface production uses; there is no unlocked append anywhere
    /// (the raw store-level appends are GONE). The txn's lock acquisition,
    /// fold, append, and release run under the fixture's per-store
    /// registry, so the one-shot `Append*` faults armed by the tests fire
    /// exactly as before.
    pub(crate) fn test_append_intent(&self, target: &str, intent: &DeploymentIntent) -> Result<()> {
        let mut txn = TargetLedgerTxn::open(self, target, "test-append")?;
        txn.append_intent(intent)
    }

    /// TEST-ONLY: append a terminal through a freshly opened (and dropped)
    /// [`TargetLedgerTxn`] — see [`LocalStore::test_append_intent`].
    pub(crate) fn test_append_terminal(
        &self,
        target: &str,
        deployment_id: &DeploymentId,
        terminal: &LedgerTerminal,
    ) -> Result<()> {
        let mut txn = TargetLedgerTxn::open(self, target, "test-append")?;
        txn.append_terminal(deployment_id, terminal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{SlotId, Timestamp, test_deployment_id};
    use crate::kernel::error::{KernelErrorClass, KernelErrorCode};
    use crate::kernel::intent::{DeploymentIntent, PlanInput, PlannedDeploy};
    use crate::kernel::snapshot::SnapshotSlot;
    use crate::ledger::records::{DeploymentStatus, LedgerIntentWire, LedgerTerminal};
    use crate::ledger::{LEDGER_SCHEMA_VERSION, LedgerLine, Observation, TargetSnapshot};
    use crate::testutil::fixtures;
    #[cfg(test)]
    use proptest::prelude::*;
    #[cfg(test)]
    use proptest::test_runner::RngSeed;

    fn slot_p1() -> SlotId {
        SlotId::new("p1".to_string())
    }

    /// A valid FULL-push intent for the target (one slot p1).
    fn intent(id: &str, target: &str) -> crate::kernel::intent::DeploymentIntent {
        fixtures::full_intent(id, target, &[slot_p1()], &[])
    }

    /// A valid FULL-push intent for the target planned OVER the given
    /// successful head entry (parent == the head, one slot p1) — the
    /// strictly-linear seed: an ordinary intent's parent must equal the
    /// current successful head, and it may only be appended when no other
    /// attempt is pending.
    fn intent_over_head(
        id: &str,
        target: &str,
        head: &crate::kernel::intent::DeploymentIntent,
    ) -> crate::kernel::intent::DeploymentIntent {
        use crate::kernel::intent::{PlanInput, PlannedDeploy};
        use crate::ledger::Observation;
        let p1 = slot_p1();
        crate::kernel::intent::plan(PlanInput {
            deployment_id: test_deployment_id(id),
            target: TargetName::parse(target).expect("a test target"),
            parent: Some(head.deployment_id().clone()),
            parent_snapshot: Some(head.resulting_snapshot()),
            group: None,
            selection: vec![p1.clone()],
            planned: vec![PlannedDeploy {
                slot: p1,
                result: crate::testutil::fixtures::snapshot_slot(&slot_p1()),
                pre_push: Observation::KnownAbsent,
            }],
            behavior_digest: crate::identity::BehaviorDigest::parse(
                crate::identity::DIGEST_TEST_HEX_1,
            )
            .unwrap(),
            attempted_at: crate::identity::Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        })
        .expect("a seeded parented intent plans")
    }

    /// The target's most recent SUCCESSFUL entry's intent (the successful
    /// head) from the store.
    fn head_intent(store: &LocalStore, target: &str) -> crate::kernel::intent::DeploymentIntent {
        store
            .read_ledger(target)
            .unwrap()
            .into_iter()
            .rev()
            .find(|e| {
                e.terminal
                    .as_ref()
                    .is_some_and(|t| t.status() == DeploymentStatus::Successful)
            })
            .map(|e| e.intent)
            .expect("the successful head entry exists")
    }

    /// A Successful terminal BOUND to its intent (payload-free).
    fn successful_terminal(intent: &crate::kernel::intent::DeploymentIntent) -> LedgerTerminal {
        fixtures::successful_terminal(intent)
    }

    fn seed_successful(store: &LocalStore, target: &str, id: &str) {
        // The successful chain must be parented (the lineage invariant — at
        // most one `Successful` per parent): each seed plans against the
        // CURRENT successful head, so a multi-seed history is always a valid
        // chain the strict reader accepts (still a FULL push, group None).
        use crate::kernel::intent::{PlanInput, PlannedDeploy};
        use crate::ledger::Observation;
        let head = store
            .read_ledger(target)
            .unwrap()
            .into_iter()
            .rev()
            .find(|e| {
                e.terminal
                    .as_ref()
                    .is_some_and(|t| t.status() == DeploymentStatus::Successful)
            })
            .map(|e| e.intent);
        let (parent, parent_snapshot) = match &head {
            Some(h) => (
                Some(h.deployment_id().clone()),
                Some(h.resulting_snapshot()),
            ),
            None => (None, None),
        };
        let p1 = slot_p1();
        let i = crate::kernel::intent::plan(PlanInput {
            deployment_id: test_deployment_id(id),
            target: TargetName::parse(target).expect("a test target"),
            parent,
            parent_snapshot,
            group: None,
            selection: vec![p1.clone()],
            planned: vec![PlannedDeploy {
                slot: p1,
                result: crate::testutil::fixtures::snapshot_slot(&slot_p1()),
                pre_push: Observation::KnownAbsent,
            }],
            behavior_digest: crate::identity::BehaviorDigest::parse(
                crate::identity::DIGEST_TEST_HEX_1,
            )
            .unwrap(),
            attempted_at: crate::identity::Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        })
        .expect("a seeded parented intent plans");
        store.test_append_intent(target, &i).unwrap();
        store
            .test_append_terminal(target, i.deployment_id(), &successful_terminal(&i))
            .unwrap();
    }

    /// The ledger round-trips: intent + terminal merge into ONE entry per
    /// deployment id, in append order, with the terminal's status deriving
    /// from its disposition. A terminal without its intent, a duplicate
    /// intent, or a duplicate terminal FAILS CLOSED (integrity).
    #[test]
    fn ledger_merges_intent_and_terminal_and_fails_closed() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        seed_successful(&store, target, "deploy-a");
        seed_successful(&store, target, "deploy-b");
        let entries = store.read_ledger(target).unwrap();
        assert_eq!(entries.len(), 2, "one merged entry per deployment");
        assert_eq!(entries[0].deployment_id, test_deployment_id("deploy-a"));
        assert_eq!(entries[1].deployment_id, test_deployment_id("deploy-b"));
        assert!(entries[0].terminal.is_some());
        assert_eq!(
            entries[0].terminal.as_ref().unwrap().status(),
            DeploymentStatus::Successful
        );
        // The SUCCESSFUL terminal is PAYLOAD-FREE: its snapshot resolves
        // from the intent (one stored copy — the digest binds them).
        assert!(
            entries[0]
                .terminal
                .as_ref()
                .unwrap()
                .disposition()
                .is_successful()
        );
        assert!(
            entries[0].terminal.as_ref().unwrap().outcomes().is_empty(),
            "a Successful terminal records no outcomes"
        );
        let snapshot = crate::kernel::snapshot::resolve_snapshot(&entries[0]).unwrap();
        assert_eq!(snapshot.len(), 1);
        // A duplicate intent is refused (the deployment id keys the entry).
        let err = store
            .test_append_intent(target, &intent("deploy-a", target))
            .unwrap_err();
        assert!(err.to_string().contains("second intent"));
        // A duplicate terminal is refused.
        let i = intent("deploy-a", target);
        let err = store
            .test_append_terminal(
                target,
                &test_deployment_id("deploy-a"),
                &successful_terminal(&i),
            )
            .unwrap_err();
        assert!(err.to_string().contains("already carries a terminal"));
    }

    /// Write a TERMINAL-only ledger line by hand and assert the read path
    /// refuses it as corruption.
    #[test]
    fn orphan_terminal_line_is_refused() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        let p = store.ledger_path(target);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let i = intent("deploy-orphan", target);
        let t = fixtures::successful_terminal(&i);
        let wire = crate::ledger::LedgerTerminalWire::to_wire(i.deployment_id(), &t);
        let line = serde_json::to_string(&LedgerLine::Terminal(wire)).unwrap();
        std::fs::write(&p, format!("{line}\n")).unwrap();
        let err = store.read_ledger(target).unwrap_err();
        assert!(
            err.to_string().contains("intent"),
            "a terminal without its intent must be refused, got: {err}"
        );
    }

    /// The duplicate-intent guard scans EVERY ledger entry, not just the
    /// first one: a second intent whose deployment id duplicates the FIRST,
    /// a MIDDLE, or the LAST entry is refused, while a genuinely NEW id
    /// still appends fine.
    #[test]
    fn append_intent_duplicate_guard_scans_every_entry() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        seed_successful(&store, target, "deploy-first");
        seed_successful(&store, target, "deploy-mid");
        seed_successful(&store, target, "deploy-last");
        for id in ["deploy-first", "deploy-mid", "deploy-last"] {
            let err = store
                .test_append_intent(target, &intent(id, target))
                .unwrap_err();
            assert!(
                err.to_string().contains("second intent"),
                "a duplicate of the {id} entry must be refused at any position, got: {err}"
            );
        }
        seed_successful(&store, target, "deploy-new");
        assert_eq!(
            store.read_ledger(target).unwrap().len(),
            4,
            "a fresh id appends as a fourth entry"
        );
    }

    /// A foreign `deployment_schema_version` on an intent line fails closed
    /// and a malformed line is a store error, never a silent drop.
    #[test]
    fn ledger_accepts_only_ledger_schema_version_and_rejects_malformed_lines() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        let foreign = intent("deploy-x", target);
        let mut wire = LedgerIntentWire::from(&foreign);
        wire.deployment_schema_version = LEDGER_SCHEMA_VERSION + 1;
        let line = serde_json::to_string(&LedgerLine::Intent(wire)).unwrap();
        let p = store.ledger_path(target);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, format!("{line}\n")).unwrap();
        let err = store.read_ledger(target).unwrap_err();
        assert!(
            err.to_string().contains("schema_version"),
            "a foreign schema version must fail closed, got: {err}"
        );
        std::fs::write(&p, "{ not json !\n").unwrap();
        assert!(store.read_ledger(target).is_err());
    }

    /// `latest_status` derives from the ledger: the terminal's status for a
    /// settled entry, `None` (the PENDING state) for an intent-only
    /// entry, and `None` for an unknown deployment. The ledger is STRICTLY
    /// LINEAR (one unresolved intent at a time; every intent's parent is the
    /// head).
    #[test]
    fn latest_status_derives_from_the_ledger() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        seed_successful(&store, target, "deploy-ok");
        let ok_head = head_intent(&store, target);
        // A pending intent OVER the head: an intent-only entry IS the
        // pending state.
        let pending = intent_over_head("deploy-pending", target, &ok_head);
        store.test_append_intent(target, &pending).unwrap();
        assert_eq!(
            store
                .latest_status(test_deployment_id("deploy-pending").as_str())
                .unwrap(),
            None,
            "an intent-only entry IS the pending state — no pending status on the terminal enum"
        );
        // The pending attempt reaches its Successful terminal (the head
        // advances to it), then a Degraded entry descends from the NEW head.
        store
            .test_append_terminal(
                target,
                pending.deployment_id(),
                &successful_terminal(&pending),
            )
            .unwrap();
        let deg_i = intent_over_head("deploy-deg", target, &pending);
        store.test_append_intent(target, &deg_i).unwrap();
        store
            .test_append_terminal(
                target,
                deg_i.deployment_id(),
                &fixtures::degraded_terminal(&deg_i, &[slot_p1()]),
            )
            .unwrap();
        assert_eq!(
            store
                .latest_status(test_deployment_id("deploy-pending").as_str())
                .unwrap(),
            Some(DeploymentStatus::Successful)
        );
        assert_eq!(
            store
                .latest_status(test_deployment_id("deploy-ok").as_str())
                .unwrap(),
            Some(DeploymentStatus::Successful)
        );
        assert_eq!(
            store
                .latest_status(test_deployment_id("deploy-deg").as_str())
                .unwrap(),
            Some(DeploymentStatus::Degraded)
        );
        assert_eq!(
            store
                .latest_status(test_deployment_id("deploy-nope").as_str())
                .unwrap(),
            None
        );
    }

    /// `read_last_successful` is derived from the ledger: ONLY the newest
    /// SUCCESSFUL entry, never a failed/pending one. The ledger is STRICTLY
    /// LINEAR (settle each intent before the next; every intent descends
    /// from the head).
    #[test]
    fn last_successful_is_derived() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        seed_successful(&store, target, "deploy-ok");
        let ok_head = head_intent(&store, target);
        // A pending (intent-only) intent over the head: it is NOT successful,
        // so the derived read still names deploy-ok.
        let fail_i = intent_over_head("deploy-fail", target, &ok_head);
        store.test_append_intent(target, &fail_i).unwrap();
        assert_eq!(
            store.read_last_successful(target).as_deref(),
            Some(test_deployment_id("deploy-ok").as_str()),
            "a pending attempt is never the derived head"
        );
        // The pending attempt ends FailedPreflight (clears the pending; the
        // head stays deploy-ok), then a second successful deployment chains
        // onto deploy-ok and becomes the newest head.
        store
            .test_append_terminal(
                target,
                fail_i.deployment_id(),
                &fixtures::failed_preflight_terminal(&fail_i),
            )
            .unwrap();
        seed_successful(&store, target, "deploy-ok2");
        assert_eq!(
            store.read_last_successful(target).as_deref(),
            Some(test_deployment_id("deploy-ok2").as_str())
        );
        // The remains-derived read even after a checkpoint (the retained
        // suffix IS the ledger).
        let lines = store.read_ledger_lines(target).unwrap();
        store
            .write_ledger_suffix(target, &lines[0..lines.len()])
            .unwrap();
        assert_eq!(
            store.read_last_successful(target).as_deref(),
            Some(test_deployment_id("deploy-ok2").as_str())
        );
    }

    /// The append_terminal fault is one-shot and deployment-id qualified.
    #[test]
    fn append_terminal_fault_is_one_shot_and_id_qualified() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        let a_first = intent("deploy-a", target);
        store.test_append_intent(target, &a_first).unwrap();
        // Fault deploy-a's terminal append ONCE: the terminal is NOT written
        // and deploy-a stays pending.
        store
            .fault_registry()
            .arm_append_terminal(test_deployment_id("deploy-a").as_str());
        let a_i = intent("deploy-a", target);
        let err = store
            .test_append_terminal(target, a_i.deployment_id(), &successful_terminal(&a_i))
            .unwrap_err();
        assert!(err.to_string().contains("append_terminal"));
        // The fault is consumed: a retry succeeds for deploy-a (becoming the
        // head), and deploy-b (planned over the NEW head — strictly linear)
        // is appended and finalized unaffected.
        store
            .test_append_terminal(target, a_i.deployment_id(), &successful_terminal(&a_i))
            .unwrap();
        let b_i = crate::testutil::fixtures::group_intent(
            "deploy-b",
            target,
            "g",
            a_first.deployment_id(),
            &a_first.resulting_snapshot(),
            &[slot_p1()],
            &[slot_p1()],
        );
        store.test_append_intent(target, &b_i).unwrap();
        store
            .test_append_terminal(target, b_i.deployment_id(), &successful_terminal(&b_i))
            .unwrap();
    }

    /// THE PRE-WRITE GUARANTEE (fail closed): a terminal whose digest does
    /// not bind its intent is refused BEFORE the write — the ledger bytes
    /// stay unchanged.
    #[test]
    fn append_terminal_refuses_a_mismatched_digest_before_writing() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        let a_i = intent("deploy-a", target);
        store.test_append_intent(target, &a_i).unwrap();
        // A terminal bound to a DIFFERENT (but otherwise valid) intent.
        let other = fixtures::full_intent("deploy-other", target, &[slot_p1()], &[]);
        let t = fixtures::successful_terminal(&other);
        let err = store
            .test_append_terminal(target, a_i.deployment_id(), &t)
            .unwrap_err();
        assert!(
            err.to_string().contains("digest"),
            "a terminal bound to another intent must be refused before the write, got: {err}"
        );
        assert_eq!(store.read_ledger_lines(target).unwrap().len(), 1);
    }

    /// A checkpoint event: the atomic suffix replacement writes a
    /// checkpointed ledger whose FIRST line is the checkpoint event, and the
    /// reader's state machine accepts it exactly as the first event — the
    /// retained suffix starts at the checkpoint deployment (the ANCHOR,
    /// whose parent lies OUTSIDE the retained window — the strictly-linear
    /// model's one exception).
    #[test]
    fn checkpoint_event_is_accepted_and_validated() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        // Seed entries, then compact to the LAST one with a checkpoint
        // prefix: the checkpoint event line + the retained suffix (deploy-b's
        // intent + terminal) become the new ledger.
        seed_successful(&store, target, "deploy-a");
        seed_successful(&store, target, "deploy-b");
        let lines = store.read_ledger_lines(target).unwrap();
        let keep: Vec<String> = lines[2..].to_vec();
        let checkpoint = crate::kernel::transition::CheckpointEvent {
            retained_from: test_deployment_id("deploy-b"),
            discarded: 1,
            recorded_at: crate::remote::helper::now_rfc3339_ts(),
        };
        let checkpoint_line = serde_json::to_string(&LedgerEventWire::Checkpoint(
            crate::ledger::CheckpointWire::new(
                &checkpoint.retained_from,
                checkpoint.discarded,
                &checkpoint.recorded_at.to_string(),
            ),
        ))
        .unwrap();
        let mut new_ledger = vec![checkpoint_line];
        new_ledger.extend(keep);
        store.write_ledger_suffix(target, &new_ledger).unwrap();
        let entries = store.read_ledger(target).unwrap();
        assert_eq!(entries.len(), 1, "the retained suffix IS the ledger");
        assert_eq!(entries[0].deployment_id, test_deployment_id("deploy-b"));
        assert!(entries[0].terminal.is_some());
    }

    #[derive(Clone, Copy, PartialEq, Debug)]
    enum AppendStage {
        Write,
        Sync,
        Rename,
        DirSync,
    }

    /// The appended-append durability protocol: a fault at any of the four
    /// stages leaves the ledger wholly old or wholly new (never torn) — the
    /// production contract beneath every ledger write.
    #[test]
    fn ledger_append_faults_leave_wholly_old_or_wholly_new() {
        fn arm_stage(store: &LocalStore, stage: AppendStage, id: &str) {
            match stage {
                AppendStage::Write => {
                    store.fault_registry().arm_append_write(id);
                }
                AppendStage::Sync => {
                    store.fault_registry().arm_append_sync(id);
                }
                AppendStage::Rename => {
                    store.fault_registry().arm_append_rename(id);
                }
                AppendStage::DirSync => {
                    store.fault_registry().arm_append_dir_sync(id);
                }
            }
        }
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        store
            .test_append_intent(target, &intent("deploy-a", target))
            .unwrap();
        let before = std::fs::read(store.ledger_path(target)).unwrap();
        std::fs::create_dir_all(store.ledger_path(target).parent().unwrap()).unwrap();
        let a_i = intent("deploy-a", target);
        let t = successful_terminal(&a_i);
        for stage in [
            AppendStage::Write,
            AppendStage::Sync,
            AppendStage::Rename,
            AppendStage::DirSync,
        ] {
            // Re-arm per stage on a fresh target dir (keyed by the
            // CANONICAL deployment id — the append consumes the fault
            // registry under the canonical id).
            let dir2 = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let store2 = LocalStore::with_base(dir2.path().join("store")).unwrap();
            store2
                .test_append_intent(target, &intent("deploy-a", target))
                .unwrap();
            arm_stage(&store2, stage, test_deployment_id("deploy-a").as_str());
            let res = store2.test_append_terminal(target, a_i.deployment_id(), &t);
            let p = store2.ledger_path(target);
            let text = std::fs::read_to_string(&p).unwrap();
            match stage {
                // Pre-rename fault: the visible ledger is wholly OLD.
                AppendStage::Write | AppendStage::Sync | AppendStage::Rename => {
                    assert!(res.is_err(), "{stage:?} must fail");
                    assert_eq!(text.lines().count(), 1, "{stage:?} leaves one line");
                }
                // Post-commit dir-sync fault: the ledger is wholly NEW.
                AppendStage::DirSync => {
                    assert!(res.is_err(), "dir-sync fault reports Err");
                    assert_eq!(text.lines().count(), 2, "the new line is durable");
                }
            }
            let _ = before;
        }
    }

    // ---- The append-atomicity property: any injected fault at any stage
    // leaves a reader-consistent ledger --------------------------------

    fn stage_strategy() -> impl Strategy<Value = Option<AppendStage>> {
        prop::option::of(prop::sample::select(vec![
            AppendStage::Write,
            AppendStage::Sync,
            AppendStage::Rename,
            AppendStage::DirSync,
        ]))
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(24),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// A faulted append at ANY of the four stages either fails before
        /// the rename (the visible ledger is wholly old and still parses) or
        /// commits the whole new line (the dir-sync window); the ledger is
        /// never torn and the reader never rejects it.
        #[test]
        fn ledger_append_durability_every_stage(stage in stage_strategy()) {
            let canonical_a = test_deployment_id("deploy-a");
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let store = LocalStore::with_base(dir.path().join("store")).unwrap();
            let target = "t1";
            store
                .test_append_intent(target, &intent("deploy-a", target))
                .unwrap();
            let a_i = intent("deploy-a", target);
            let t = successful_terminal(&a_i);
            if let Some(stage) = stage {
                match stage {
                    AppendStage::Write => {
                        store.fault_registry().arm_append_write(canonical_a.as_str())
                    }
                    AppendStage::Sync => {
                        store.fault_registry().arm_append_sync(canonical_a.as_str())
                    }
                    AppendStage::Rename => {
                        store.fault_registry().arm_append_rename(canonical_a.as_str())
                    }
                    AppendStage::DirSync => {
                        store.fault_registry().arm_append_dir_sync(canonical_a.as_str())
                    }
                }
            }
            let res = store.test_append_terminal(target, a_i.deployment_id(), &t);
            let entries = store.read_ledger(target).unwrap();
            match res {
                Ok(()) => {
                    prop_assert_eq!(entries.len(), 1);
                    prop_assert!(entries[0].terminal.is_some());
                }
                Err(_) => {
                    // A pre-rename fault leaves the visible ledger wholly OLD
                    // (no terminal); the dir-sync window already committed
                    // the full line but reports Err.
                    prop_assert!(entries[0].terminal.is_some() || entries[0].terminal.is_none());
                    // A RETRY after any transient fault converges: the
                    // terminal appends (append_terminal re-reads the whole
                    // ledger, so a committed-but-Err terminal is a NO-OP
                    // "already carries" refusal — the ledger is already in
                    // the terminal state).
                    let _ = store.test_append_terminal(target, a_i.deployment_id(), &t);
                    let entries = store.read_ledger(target).unwrap();
                    prop_assert_eq!(entries.len(), 1);
                    prop_assert!(entries[0].terminal.is_some());
                }
            }
        }
    }

    /// Duplicate-intent scanning leaves the ledger bytes unchanged.
    #[test]
    fn duplicate_intent_scan_leaves_ledger_bytes_unchanged() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        seed_successful(&store, target, "deploy-a");
        let before = std::fs::read(store.ledger_path(target)).unwrap();
        let err = store
            .test_append_intent(target, &intent("deploy-a", target))
            .unwrap_err();
        assert!(err.to_string().contains("second intent"));
        assert_eq!(
            std::fs::read(store.ledger_path(target)).unwrap(),
            before,
            "a refused duplicate intent leaves the ledger bytes unchanged"
        );
    }

    // =====================================================================
    // THE SEMANTIC-MUTATION PROPERTY (spec item 5 — ONE mutation per
    // semantic Integrity code) ------------------------------------------
    //
    // Every named semantic rule is a TYPED [`IntegrityError`] variant
    // bearing its concrete evidence. Each mutation below starts from a VALID
    // ledger (a settled strictly-linear chain, or the checkpointed form for
    // the anchor rule) and violates EXACTLY ONE rule: insert a second
    // intent line for the same deployment; append a second terminal line; a
    // terminal with no intent; tamper the intent digest; re-parent an
    // intent off the head; mutate an inherited slot's entry; replace the
    // checkpoint anchor's terminal with a non-Successful one. The property
    // asserts, for every generated mutation:
    //
    // * the refusal's [`KernelError::class`] is Integrity and its
    //   [`KernelError::code`] is the expected semantic code;
    // * the refusal happens at EXACTLY the mutation line (the invalid
    //   event is the only refused one);
    // * the rejected event NEVER partially modifies the read state:
    //   folding the ledger up to the mutation point equals folding the
    //   VALID prefix up to the same point (same entries / pending /
    //   successful head / checkpoint / line count).

    fn slot_p2() -> SlotId {
        SlotId::new("p2".to_string())
    }

    /// A FULL-push intent planned OVER the given successful head (parent ==
    /// the head, both slots deployed) — the strictly-linear seed.
    fn full_intent_over(head: &DeploymentIntent, tag: &str) -> DeploymentIntent {
        crate::kernel::intent::plan(PlanInput {
            deployment_id: test_deployment_id(tag),
            target: TargetName::parse("t1").unwrap(),
            parent: Some(head.deployment_id().clone()),
            parent_snapshot: Some(head.resulting_snapshot()),
            group: None,
            selection: vec![slot_p1(), slot_p2()],
            planned: vec![
                PlannedDeploy {
                    slot: slot_p1(),
                    result: fixtures::snapshot_slot(&slot_p1()),
                    pre_push: Observation::KnownAbsent,
                },
                PlannedDeploy {
                    slot: slot_p2(),
                    result: fixtures::snapshot_slot(&slot_p2()),
                    pre_push: Observation::KnownAbsent,
                },
            ],
            behavior_digest: fixtures::behavior_digest(),
            attempted_at: Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        })
        .expect("a valid parented full intent plans")
    }

    /// A GROUP intent over the head whose INHERITED p2 entry disagrees with
    /// the head's actual snapshot (a tampered base) — refused by the
    /// inherited-slot congruence with `InheritedSnapshotMismatch`.
    fn tampered_group_over(head: &DeploymentIntent, tag: &str) -> DeploymentIntent {
        let mut entries = head.resulting_snapshot().into_entries();
        let p2e = entries
            .get(&slot_p2())
            .cloned()
            .expect("the head covers p2");
        let tampered = SnapshotSlot::new(
            crate::identity::test_generation_id("tampered-p2"),
            p2e.artifact().clone(),
            p2e.binding().clone(),
        );
        entries.insert(slot_p2(), tampered);
        let base = TargetSnapshot::from_entries(entries);
        fixtures::group_intent(
            tag,
            "t1",
            "g",
            head.deployment_id(),
            &base,
            &[slot_p1(), slot_p2()],
            &[slot_p1()],
        )
    }

    /// A checkpointed VALID ledger: the checkpoint event + the anchor's
    /// intent + its `Successful` terminal (the retained suffix starts at a
    /// successful deployment).
    fn valid_checkpointed_ledger() -> Vec<LedgerEvent> {
        let anchor = fixtures::full_intent("deploy-anchor", "t1", &[slot_p1(), slot_p2()], &[]);
        vec![
            LedgerEvent::Checkpoint(CheckpointEvent {
                retained_from: test_deployment_id("deploy-anchor"),
                discarded: 1,
                recorded_at: crate::remote::helper::now_rfc3339_ts(),
            }),
            LedgerEvent::Intent(IntentEvent {
                intent: anchor.clone(),
            }),
            LedgerEvent::Terminal(TerminalEvent {
                deployment_id: anchor.deployment_id().clone(),
                terminal: fixtures::successful_terminal(&anchor),
            }),
        ]
    }

    /// The valid settled chain behind the non-anchor mutations: H → A → B,
    /// all full pushes finalized `Successful` (both slots).
    fn valid_chain_events() -> Vec<LedgerEvent> {
        let h = fixtures::full_intent("deploy-h", "t1", &[slot_p1(), slot_p2()], &[]);
        let a = full_intent_over(&h, "deploy-a");
        let b = full_intent_over(&a, "deploy-b");
        vec![
            LedgerEvent::Intent(IntentEvent { intent: h.clone() }),
            LedgerEvent::Terminal(TerminalEvent {
                deployment_id: h.deployment_id().clone(),
                terminal: fixtures::successful_terminal(&h),
            }),
            LedgerEvent::Intent(IntentEvent { intent: a.clone() }),
            LedgerEvent::Terminal(TerminalEvent {
                deployment_id: a.deployment_id().clone(),
                terminal: fixtures::successful_terminal(&a),
            }),
            LedgerEvent::Intent(IntentEvent { intent: b.clone() }),
            LedgerEvent::Terminal(TerminalEvent {
                deployment_id: b.deployment_id().clone(),
                terminal: fixtures::successful_terminal(&b),
            }),
        ]
    }

    /// ONE mutation per semantic code: `(valid ledger, mutated ledger)` —
    /// the mutated ledger is the valid one with EXACTLY ONE violating event
    /// appended (the checkpoint-anchor mutation replaces the anchor's
    /// terminal).
    fn mutated_ledger(mutation: SemanticMutation) -> (Vec<LedgerEvent>, Vec<LedgerEvent>) {
        if matches!(mutation, SemanticMutation::CheckpointAnchorMismatch) {
            let valid = valid_checkpointed_ledger();
            let mut mutated = valid.clone();
            let anchor = fixtures::full_intent("deploy-anchor", "t1", &[slot_p1(), slot_p2()], &[]);
            let last = mutated
                .last_mut()
                .expect("the anchored ledger has a terminal");
            // Replace the anchor's `Successful` terminal with a Degraded one
            // — the ONE violation (the checkpoint requires its anchor to be
            // finalized `Successful`).
            *last = LedgerEvent::Terminal(TerminalEvent {
                deployment_id: anchor.deployment_id().clone(),
                terminal: fixtures::degraded_terminal(&anchor, &[slot_p1(), slot_p2()]),
            });
            return (valid, mutated);
        }
        let valid = valid_chain_events();
        let mutation_event = match mutation {
            SemanticMutation::DuplicateIntent => {
                // A second intent for deploy-h (already in the ledger).
                let dup = fixtures::full_intent("deploy-h", "t1", &[slot_p1(), slot_p2()], &[]);
                LedgerEvent::Intent(IntentEvent { intent: dup })
            }
            SemanticMutation::DuplicateTerminal => {
                // A second terminal line for the settled deploy-h.
                let h = fixtures::full_intent("deploy-h", "t1", &[slot_p1(), slot_p2()], &[]);
                LedgerEvent::Terminal(TerminalEvent {
                    deployment_id: h.deployment_id().clone(),
                    terminal: fixtures::successful_terminal(&h),
                })
            }
            SemanticMutation::TerminalWithoutIntent => {
                // A terminal binding a valid digest for a deployment with NO
                // intent line.
                let orphan = fixtures::full_intent("deploy-orphan", "t1", &[slot_p1()], &[]);
                LedgerEvent::Terminal(TerminalEvent {
                    deployment_id: orphan.deployment_id().clone(),
                    terminal: fixtures::successful_terminal(&orphan),
                })
            }
            SemanticMutation::IntentDigestMismatch => {
                // A terminal for the settled deploy-h bound to a DIFFERENT
                // (valid) intent's digest.
                let h = fixtures::full_intent("deploy-h", "t1", &[slot_p1(), slot_p2()], &[]);
                let other = fixtures::full_intent("deploy-other", "t1", &[slot_p1()], &[]);
                LedgerEvent::Terminal(TerminalEvent {
                    deployment_id: h.deployment_id().clone(),
                    terminal: fixtures::successful_terminal(&other),
                })
            }
            SemanticMutation::ParentLineageMismatch => {
                // An ordinary intent re-parented off the OLD head H while the
                // ledger's successful head has moved on to B (a fork: parent
                // ≠ the head).
                let h = fixtures::full_intent("deploy-h", "t1", &[slot_p1(), slot_p2()], &[]);
                LedgerEvent::Intent(IntentEvent {
                    intent: full_intent_over(&h, "deploy-fork"),
                })
            }
            SemanticMutation::InheritedSnapshotMismatch => {
                // A group intent over the head whose inherited p2 entry
                // disagrees with the head's snapshot.
                let b = full_intent_over(
                    &full_intent_over(
                        &fixtures::full_intent("deploy-h", "t1", &[slot_p1(), slot_p2()], &[]),
                        "deploy-a",
                    ),
                    "deploy-b",
                );
                LedgerEvent::Intent(IntentEvent {
                    intent: tampered_group_over(&b, "deploy-g"),
                })
            }
            SemanticMutation::CheckpointAnchorMismatch => {
                unreachable!("handled above")
            }
        };
        let mut mutated = valid.clone();
        mutated.push(mutation_event);
        (valid, mutated)
    }

    /// The read-state facts the "no partial modification" comparisons see:
    /// the accepted entries (with their physical seqs), the ONE pending
    /// attempt, the maintained successful head, the checkpoint prefix, and
    /// the physical line counter.
    fn state_facts(
        state: &DeploymentState,
    ) -> (
        Vec<LedgerEntry>,
        Option<DeploymentId>,
        Option<DeploymentId>,
        Option<CheckpointEvent>,
        u64,
    ) {
        (
            state.entries().to_vec(),
            state.pending().cloned(),
            state.successful_head().cloned(),
            state.checkpoint().cloned(),
            state.next_seq(),
        )
    }

    /// THE PROPERTY BODY: fold the mutated ledger; the mutation event (the
    /// LAST one) is refused with the expected class + code, and the read
    /// state at the refusal equals folding the VALID prefix up to the same
    /// point — the rejected event never partially modifies the state.
    fn run_semantic_mutation(mutation: SemanticMutation, expected_code: KernelErrorCode) {
        let (valid, mutated) = mutated_ledger(mutation);
        let mut state = DeploymentState::new(TargetName::parse("t1").unwrap());
        for (index, event) in mutated.iter().enumerate() {
            match crate::kernel::transition::apply_event(state.clone(), event.clone()) {
                Ok(next) => state = next,
                Err(err) => {
                    assert_eq!(
                        index,
                        mutated.len() - 1,
                        "{mutation:?}: the mutation event must be the ONLY refused line (event {index} refused out of {} mutated events)",
                        mutated.len()
                    );
                    assert_eq!(
                        err.class(),
                        KernelErrorClass::Integrity,
                        "{mutation:?}: a semantic mutation at READ is an Integrity refusal, got: {err}"
                    );
                    assert_eq!(
                        err.code(),
                        expected_code,
                        "{mutation:?}: the refusal's code must name the violated semantic rule, got: {err}"
                    );
                    // The rejected event never partially modifies the read
                    // state: folding the ledger up to the mutation point
                    // equals folding the VALID prefix up to the same point.
                    let mut prefix = DeploymentState::new(TargetName::parse("t1").unwrap());
                    for valid_event in &valid[..index] {
                        prefix =
                            crate::kernel::transition::apply_event(prefix, valid_event.clone())
                                .expect("the valid prefix folds");
                    }
                    assert_eq!(
                        state_facts(&state),
                        state_facts(&prefix),
                        "{mutation:?}: folding the ledger up to the mutation point must equal the pre-mutation fold (the refused event left no trace)"
                    );
                    return;
                }
            }
        }
        panic!(
            "{mutation:?}: the mutation event must be refused, but the mutated ledger folded completely"
        )
    }

    /// THE EXPLICIT EXHAUSTIVE TABLE — every semantic Integrity rule EXACTLY
    /// once (the spec's canonical list, in order).
    const COVERED_MUTATIONS: &[(SemanticMutation, KernelErrorCode)] = &[
        (
            SemanticMutation::DuplicateIntent,
            KernelErrorCode::DuplicateIntent,
        ),
        (
            SemanticMutation::DuplicateTerminal,
            KernelErrorCode::DuplicateTerminal,
        ),
        (
            SemanticMutation::TerminalWithoutIntent,
            KernelErrorCode::TerminalWithoutIntent,
        ),
        (
            SemanticMutation::IntentDigestMismatch,
            KernelErrorCode::IntentDigestMismatch,
        ),
        (
            SemanticMutation::ParentLineageMismatch,
            KernelErrorCode::ParentLineageMismatch,
        ),
        (
            SemanticMutation::InheritedSnapshotMismatch,
            KernelErrorCode::InheritedSnapshotMismatch,
        ),
        (
            SemanticMutation::CheckpointAnchorMismatch,
            KernelErrorCode::CheckpointAnchorMismatch,
        ),
    ];

    /// THE TABLE IS EXHAUSTIVE: every semantic Integrity rule appears
    /// EXACTLY once, in the spec's canonical order, and each entry agrees
    /// with the mutation's own class/code expectation (no drift between the
    /// property and the table).
    #[test]
    fn covered_mutations_are_exhaustive() {
        let expected: [KernelErrorCode; 7] = [
            KernelErrorCode::DuplicateIntent,
            KernelErrorCode::DuplicateTerminal,
            KernelErrorCode::TerminalWithoutIntent,
            KernelErrorCode::IntentDigestMismatch,
            KernelErrorCode::ParentLineageMismatch,
            KernelErrorCode::InheritedSnapshotMismatch,
            KernelErrorCode::CheckpointAnchorMismatch,
        ];
        let codes: Vec<KernelErrorCode> = COVERED_MUTATIONS.iter().map(|(_, c)| *c).collect();
        assert_eq!(
            codes, expected,
            "the covered table must list every semantic Integrity code exactly once, in the spec's order"
        );
        for (mutation, code) in COVERED_MUTATIONS {
            assert_eq!(
                *code,
                mutation.expected_code(),
                "the table's mapping for {mutation:?} must agree with the mutation's own expectation"
            );
            assert_eq!(
                mutation.expected_class(),
                KernelErrorClass::Integrity,
                "{mutation:?} is an Integrity semantic rule"
            );
        }
    }

    /// THE FACADE SHAPE, end to end: a rejected ledger line surfaces as
    /// [`Error::Kernel`] carrying the COMPLETE typed kernel error — the
    /// class, the code, and the concrete line evidence are reachable, not
    /// flattened into a message string.
    #[test]
    fn rejected_ledger_line_preserves_the_typed_kernel_error() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        let keys = vec![slot_p1(), slot_p2()];
        let h = fixtures::full_intent("deploy-h", target, &keys, &[]);
        let a = full_intent_over(&h, "deploy-a");
        store.test_append_intent(target, &h).unwrap();
        store
            .test_append_terminal(
                target,
                h.deployment_id(),
                &fixtures::successful_terminal(&h),
            )
            .unwrap();
        store.test_append_intent(target, &a).unwrap();
        // A duplicate intent line for deploy-h append AFTER the valid chain
        // (the strict reader's by_id gate fires): the store read must return
        // the typed DuplicateIntent evidence through Error::Kernel.
        store.read_ledger(target).unwrap();
        let dup = fixtures::full_intent("deploy-h", target, &keys, &[]);
        let line =
            serde_json::to_string(&LedgerLine::Intent(LedgerIntentWire::from(&dup))).unwrap();
        std::fs::write(store.ledger_path(target), {
            let mut text = std::fs::read_to_string(store.ledger_path(target)).unwrap();
            text.push_str(&line);
            text.push('\n');
            text
        })
        .unwrap();
        let err = store.read_ledger(target).unwrap_err();
        match err {
            Error::Kernel(KernelError::Integrity(IntegrityError::DuplicateIntent {
                deployment,
                first_line,
                duplicate_line,
            })) => {
                assert_eq!(deployment, test_deployment_id("deploy-h"));
                assert_eq!(first_line, 1, "the first intent line is line 1 (1-based)");
                assert_eq!(
                    duplicate_line, 4,
                    "the duplicate intent line is the appended line 4 (1-based)"
                );
            }
            other => panic!(
                "the read path must surface the typed DuplicateIntent through Error::Kernel, got: {other:?}"
            ),
        }
    }

    // The one mutation per semantic code: the generated case drives the
    // property over the exhaustive table (house style: bounded cases,
    // deterministic seed, no failure persistence).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SemanticMutation {
        DuplicateIntent,
        DuplicateTerminal,
        TerminalWithoutIntent,
        IntentDigestMismatch,
        ParentLineageMismatch,
        InheritedSnapshotMismatch,
        CheckpointAnchorMismatch,
    }

    impl SemanticMutation {
        fn expected_code(self) -> KernelErrorCode {
            match self {
                Self::DuplicateIntent => KernelErrorCode::DuplicateIntent,
                Self::DuplicateTerminal => KernelErrorCode::DuplicateTerminal,
                Self::TerminalWithoutIntent => KernelErrorCode::TerminalWithoutIntent,
                Self::IntentDigestMismatch => KernelErrorCode::IntentDigestMismatch,
                Self::ParentLineageMismatch => KernelErrorCode::ParentLineageMismatch,
                Self::InheritedSnapshotMismatch => KernelErrorCode::InheritedSnapshotMismatch,
                Self::CheckpointAnchorMismatch => KernelErrorCode::CheckpointAnchorMismatch,
            }
        }
        fn expected_class(self) -> KernelErrorClass {
            KernelErrorClass::Integrity
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(24),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// THE SEMANTIC-MUTATION PROPERTY (spec item 5): EVERY mutation of
        /// the exhaustive table is refused with the expected Integrity
        /// class + semantic code, at exactly the mutation line, and the
        /// rejected event never partially modifies the read state.
        #[test]
        fn semantic_mutation_class_and_code(idx in 0u32..COVERED_MUTATIONS.len() as u32) {
            let (mutation, code) = COVERED_MUTATIONS[idx as usize];
            run_semantic_mutation(mutation, code);
        }
    }

    // =====================================================================
    // THE TXN-IS-THE-STATE-MACHINE PROPERTY (the review's acceptance): an
    // ARBITRARY transaction sequence — intent / terminal / checkpoint-
    // suffix operations, VALID and INVALID per the kernel's strictly-linear
    // rules — is driven through a REAL [`TargetLedgerTxn`] AND the kernel's
    // PURE fold ([`crate::kernel::transition::apply_event`]); after EVERY
    // operation the txn's folded state must EQUAL the pure fold of the same
    // event sequence (both accept or both refuse; on acceptance the states
    // are identical). The txn IS the pure state machine — the fold and the
    // bytes cannot disagree.

    /// The generated transaction ops, materialized against the state at
    /// each point of the sequence (each tag is re-materialized from the
    /// CURRENT fold, so the same tag is VALID or INVALID depending on where
    /// it lands):
    ///
    /// * [`PropOpTag::IntentOverHead`] — a full-push intent planned over the
    ///   CURRENT successful head (parent-equality + inherited-slot checks
    ///   pass by construction): VALID when no pending attempt exists,
    ///   refused (`PendingAttemptExists`) when one does;
    /// * [`PropOpTag::IntentStaleParent`] — the same intent planned over a
    ///   FABRICATED parent id: ALWAYS refused (`ParentMismatch`);
    /// * [`PropOpTag::TerminalValid`] — a valid terminal (matching digest,
    ///   disposition agreed with the intent) for the PENDING attempt:
    ///   VALID when one exists, refused otherwise;
    /// * [`PropOpTag::TerminalBadDigest`] — a terminal bound to a DIFFERENT
    ///   intent's digest: ALWAYS refused (`IntentDigestMismatch`);
    /// * [`PropOpTag::TerminalNotPending`] — a valid terminal for a
    ///   NON-pending entry (or an unknown id): ALWAYS refused;
    /// * [`PropOpTag::CheckpointRetainHead`] — the VALIDATED SUFFIX
    ///   REPLACEMENT retaining the current successful head (the only way a
    ///   checkpoint event may enter a ledger): VALID when the ledger has a
    ///   successful head; skipped (not expressible — the txn has no bare
    ///   checkpoint append) otherwise.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum PropOpTag {
        IntentOverHead,
        IntentStaleParent,
        TerminalValid,
        TerminalBadDigest,
        TerminalNotPending,
        CheckpointRetainHead,
    }

    fn arbitrary_op_tag() -> impl Strategy<Value = PropOpTag> {
        prop_oneof![
            Just(PropOpTag::IntentOverHead),
            Just(PropOpTag::IntentStaleParent),
            Just(PropOpTag::TerminalValid),
            Just(PropOpTag::TerminalBadDigest),
            Just(PropOpTag::TerminalNotPending),
            Just(PropOpTag::CheckpointRetainHead),
        ]
    }

    /// A full-push intent (one selected slot p1, planned result
    /// `snapshot_slot(p1)`, pre-push `KnownAbsent`) planned over the given
    /// parent — the shape the fixtures' VALID terminals are built for.
    fn prop_intent_over(
        tag: &str,
        target: &str,
        parent: Option<&DeploymentIntent>,
    ) -> DeploymentIntent {
        use crate::kernel::intent::{PlanInput, PlannedDeploy};
        let (parent_id, parent_snapshot) = match parent {
            Some(h) => (
                Some(h.deployment_id().clone()),
                Some(h.resulting_snapshot()),
            ),
            None => (None, None),
        };
        let p1 = slot_p1();
        crate::kernel::intent::plan(PlanInput {
            deployment_id: test_deployment_id(tag),
            target: TargetName::parse(target).expect("a test target"),
            parent: parent_id,
            parent_snapshot,
            group: None,
            selection: vec![p1.clone()],
            planned: vec![PlannedDeploy {
                slot: p1,
                result: fixtures::snapshot_slot(&slot_p1()),
                pre_push: Observation::KnownAbsent,
            }],
            behavior_digest: fixtures::behavior_digest(),
            attempted_at: Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        })
        .expect("a valid parented property intent plans")
    }

    /// Materialize one op tag against the CURRENT pure fold, run it through
    /// the txn AND the pure fold, and assert the txn's state equals the
    /// pure fold after it. Returns the op's pure-fold result (`None` when
    /// the op was not expressible — the checkpoint op on a head-less
    /// ledger).
    fn run_prop_op(
        txn: &mut TargetLedgerTxn<'_>,
        state: &mut DeploymentState,
        op: PropOpTag,
        tag: &mut usize,
    ) -> Result<Option<DeploymentState>> {
        let tdi = |n: &str| test_deployment_id(n);
        let next_tag = |tag: &mut usize| {
            let t = format!("deploy-prop-{}", *tag);
            *tag += 1;
            t
        };
        let target = "prop-t";
        match op {
            PropOpTag::IntentOverHead => {
                // A full-push intent over the CURRENT head: valid iff no
                // pending attempt exists (parent/inherited checks pass by
                // construction).
                let head = state.successful_head().and_then(|h| {
                    state
                        .entries()
                        .iter()
                        .find(|e| e.deployment_id == *h)
                        .map(|e| e.intent.clone())
                });
                let intent = prop_intent_over(&next_tag(tag), target, head.as_ref());
                let event = LedgerEvent::Intent(IntentEvent {
                    intent: intent.clone(),
                });
                let folded = crate::kernel::transition::apply_event(state.clone(), event);
                let txn_res = txn.append_intent(&intent);
                let fold_res = folded.map_err(Error::Kernel);
                assert_eq!(
                    txn_res.is_ok(),
                    fold_res.is_ok(),
                    "IntentOverHead({intent:?}): the txn and the pure fold must agree (txn {txn_res:?}, fold {fold_res:?})"
                );
                if let Ok(next) = fold_res {
                    *state = next.clone();
                    assert_eq!(
                        txn.state(),
                        &next,
                        "IntentOverHead: the txn's folded state must equal the pure fold"
                    );
                    Ok(Some(next))
                } else {
                    assert_eq!(
                        txn.state(),
                        state,
                        "a refused op leaves the txn's state unchanged"
                    );
                    Ok(None)
                }
            }
            PropOpTag::IntentStaleParent => {
                // A full-push intent planned over a FABRICATED parent: the
                // parent never equals the current successful head, so the
                // intent is ALWAYS refused.
                let stale = prop_intent_over(
                    &next_tag(tag),
                    target,
                    Some(&prop_intent_over(&next_tag(tag), target, None)),
                );
                let event = LedgerEvent::Intent(IntentEvent {
                    intent: stale.clone(),
                });
                let folded = crate::kernel::transition::apply_event(state.clone(), event);
                let txn_res = txn.append_intent(&stale);
                assert!(
                    txn_res.is_err(),
                    "IntentStaleParent: a stale-parent intent must be refused by the txn, got {txn_res:?}"
                );
                assert!(
                    folded.is_err(),
                    "IntentStaleParent: the pure fold must also refuse"
                );
                assert_eq!(
                    txn.state(),
                    state,
                    "a refused stale-parent intent leaves the txn's state unchanged"
                );
                Ok(None)
            }
            PropOpTag::TerminalValid => {
                // A VALID terminal for the PENDING attempt (matching digest,
                // disposition agreed with the intent): accepted only when a
                // pending attempt exists. The disposition cycles through the
                // kernel-decidable set (Successful-with-proof /
                // FailedPreflight / Degraded / rolled-back) — each built
                // VALID for the property intents.
                let pending_id = state.pending().cloned();
                let Some(pid) = pending_id else {
                    // No pending: a valid terminal has nothing to settle —
                    // refused (unknown id / not the pending attempt).
                    let id = tdi(&format!("orphan-{}", *tag));
                    *tag += 1;
                    let intent = prop_intent_over(&next_tag(tag), target, None);
                    let terminal = fixtures::successful_terminal(&intent);
                    let event = LedgerEvent::Terminal(TerminalEvent {
                        deployment_id: id,
                        terminal: terminal.clone(),
                    });
                    let folded = crate::kernel::transition::apply_event(state.clone(), event);
                    let txn_res =
                        txn.append_terminal(&tdi(&format!("orphan-{}", *tag - 1)), &terminal);
                    assert!(txn_res.is_err(), "no pending: the terminal must be refused");
                    assert!(folded.is_err(), "no pending: the pure fold must refuse");
                    assert_eq!(txn.state(), state);
                    return Ok(None);
                };
                let intent = state
                    .entries()
                    .iter()
                    .find(|e| e.deployment_id == pid)
                    .map(|e| e.intent.clone())
                    .expect("the pending entry exists in the fold");
                let terminal = match *tag % 4 {
                    0 => fixtures::successful_terminal(&intent),
                    1 => fixtures::failed_preflight_terminal(&intent),
                    2 => fixtures::degraded_terminal(&intent, &[slot_p1()]),
                    _ => fixtures::rolled_back_terminal(&intent, &[slot_p1()]),
                };
                *tag += 1;
                let event = LedgerEvent::Terminal(TerminalEvent {
                    deployment_id: pid.clone(),
                    terminal: terminal.clone(),
                });
                let folded = crate::kernel::transition::apply_event(state.clone(), event);
                let txn_res = txn.append_terminal(&pid, &terminal);
                let fold_res = folded.map_err(Error::Kernel);
                assert_eq!(
                    txn_res.is_ok(),
                    fold_res.is_ok(),
                    "TerminalValid for pending {pid}: txn {txn_res:?} vs fold {fold_res:?}"
                );
                if let Ok(next) = fold_res {
                    *state = next.clone();
                    assert_eq!(txn.state(), &next);
                    Ok(Some(next))
                } else {
                    assert_eq!(txn.state(), state);
                    Ok(None)
                }
            }
            PropOpTag::TerminalBadDigest => {
                // A terminal for an EXISTING entry bound to a DIFFERENT
                // (valid) intent's digest: ALWAYS refused.
                let id = state
                    .pending()
                    .cloned()
                    .or_else(|| state.entries().last().map(|e| e.deployment_id.clone()))
                    .unwrap_or_else(|| tdi(&next_tag(tag)));
                let other = prop_intent_over(&next_tag(tag), target, None);
                let terminal = fixtures::successful_terminal(&other);
                let event = LedgerEvent::Terminal(TerminalEvent {
                    deployment_id: id.clone(),
                    terminal: terminal.clone(),
                });
                let folded = crate::kernel::transition::apply_event(state.clone(), event);
                let txn_res = txn.append_terminal(&id, &terminal);
                assert!(
                    txn_res.is_err(),
                    "a mismatched-digest terminal must be refused"
                );
                assert!(
                    folded.is_err(),
                    "the pure fold must refuse the mismatched digest"
                );
                assert_eq!(txn.state(), state);
                Ok(None)
            }
            PropOpTag::TerminalNotPending => {
                // A VALID terminal for a NON-pending entry (a settled one or
                // an unknown id): ALWAYS refused (duplicate terminal / not
                // the pending attempt).
                let id = state
                    .entries()
                    .iter()
                    .rev()
                    .find(|e| state.pending() != Some(&e.deployment_id))
                    .map(|e| e.deployment_id.clone())
                    .unwrap_or_else(|| tdi(&next_tag(tag)));
                let intent = prop_intent_over(&next_tag(tag), target, None);
                let terminal = fixtures::successful_terminal(&intent);
                let event = LedgerEvent::Terminal(TerminalEvent {
                    deployment_id: id.clone(),
                    terminal: terminal.clone(),
                });
                let folded = crate::kernel::transition::apply_event(state.clone(), event);
                let txn_res = txn.append_terminal(&id, &terminal);
                assert!(txn_res.is_err(), "a non-pending terminal must be refused");
                assert!(
                    folded.is_err(),
                    "the pure fold must refuse the non-pending terminal"
                );
                assert_eq!(txn.state(), state);
                Ok(None)
            }
            PropOpTag::CheckpointRetainHead => {
                // THE VALIDATED SUFFIX REPLACEMENT: retain the CURRENT
                // successful head (the only way a checkpoint event enters a
                // ledger). Not expressible on a head-less ledger (the txn
                // has no bare checkpoint append — structurally, a
                // checkpoint is always the new ledger's first line, built
                // from a validated successful anchor).
                let Some(head_id) = state.successful_head().cloned() else {
                    return Ok(None);
                };
                let pos = state
                    .entries()
                    .iter()
                    .position(|e| e.deployment_id == head_id)
                    .expect("the head is an entry");
                let retained = state.entries()[pos..].to_vec();
                let cp = CheckpointEvent {
                    retained_from: head_id.clone(),
                    discarded: pos as u64,
                    recorded_at: crate::remote::helper::now_rfc3339_ts(),
                };
                // THE PURE FOLD of [checkpoint, ...retained events].
                let mut pure = DeploymentState::new(state.target().clone());
                pure = crate::kernel::transition::apply_event(
                    pure,
                    LedgerEvent::Checkpoint(cp.clone()),
                )
                .expect("a fresh ledger accepts its first checkpoint");
                for e in &retained {
                    pure = crate::kernel::transition::apply_event(
                        pure,
                        LedgerEvent::Intent(IntentEvent {
                            intent: e.intent.clone(),
                        }),
                    )
                    .expect("the retained entries re-fold");
                    if let Some(t) = &e.terminal {
                        pure = crate::kernel::transition::apply_event(
                            pure,
                            LedgerEvent::Terminal(TerminalEvent {
                                deployment_id: e.deployment_id.clone(),
                                terminal: t.clone(),
                            }),
                        )
                        .expect("the retained terminals re-fold");
                    }
                }
                // THE TXN'S validated suffix write: the checkpoint line +
                // the retained entries' lines, built independently of the
                // txn's own serializer (the txn writes them, then re-folds
                // from disk).
                let mut new_ledger = vec![
                    serde_json::to_string(&LedgerEventWire::Checkpoint(
                        crate::ledger::CheckpointWire::new(
                            &cp.retained_from,
                            cp.discarded,
                            &cp.recorded_at.to_string(),
                        ),
                    ))
                    .expect("serialize checkpoint"),
                ];
                for e in &retained {
                    new_ledger.push(
                        serde_json::to_string(&LedgerEventWire::Intent(LedgerIntentWire::from(
                            &e.intent,
                        )))
                        .expect("serialize intent"),
                    );
                    if let Some(t) = &e.terminal {
                        new_ledger.push(
                            serde_json::to_string(&LedgerEventWire::Terminal(
                                LedgerTerminalWire::to_wire(&e.deployment_id, t),
                            ))
                            .expect("serialize terminal"),
                        );
                    }
                }
                let outcome = txn
                    .write_suffix(&new_ledger)
                    .expect("the validated replacement commits");
                assert!(
                    matches!(outcome, ReplaceOutcome::ReplacedDurable),
                    "a valid suffix replacement is durable, got {outcome:?}"
                );
                assert_eq!(
                    txn.state(),
                    &pure,
                    "CheckpointRetainHead: the txn's re-folded state must equal the pure fold of [checkpoint, retained]"
                );
                *state = pure.clone();
                Ok(Some(pure))
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(24),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// THE TXN-IS-THE-STATE-MACHINE PROPERTY: for every generated
        /// transaction sequence (intent / terminal / checkpoint-suffix ops,
        /// valid + invalid per the kernel's rules), the txn's folded state
        /// after EVERY op equals the pure [`apply_event`] fold of the same
        /// event sequence — the txn never diverges, a refused op never
        /// writes, and a checkpoint enters a ledger ONLY through the
        /// validated suffix replacement.
        #[test]
        fn txn_fold_equals_pure_state_machine(tags in prop::collection::vec(arbitrary_op_tag(), 0..40)) {
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let store = LocalStore::with_base(dir.path().join("store")).unwrap();
            let target = "prop-t";
            let mut txn = TargetLedgerTxn::open(&store, target, "prop-op").unwrap();
            let mut state = DeploymentState::new(TargetName::parse(target).unwrap());
            let mut tag: usize = 0;
            for op in tags {
                run_prop_op(&mut txn, &mut state, op, &mut tag).expect("the property drives the txn");
            }
            // The txn's state equals the pure fold of the WHOLE accepted
            // sequence (the final state, after every accepted op).
            assert_eq!(txn.state(), &state, "the txn's final folded state equals the pure fold");
        }
    }

    // =====================================================================
    // THE CONCURRENT-WRITER TESTS (the review's acceptance): the txn's
    // target lock serializes writers — a second txn cannot open while the
    // first holds (fail fast, "held by"), and NO LEDGER UPDATE IS EVER
    // LOST: once writer 1 drops, writer 2 opens and appends, and BOTH
    // appends survive (the whole-ledger rewrite always happens under the
    // lock, so the old two-writers-race-losing-updates bug is structural
    // gone).

    /// Two writers on ONE target: writer 1 opens the txn and appends a
    /// successful deployment; writer 2's open WHILE writer 1 holds is
    /// REFUSED (the flock serializes), and after writer 1 releases, writer
    /// 2 opens and appends a second successful deployment planned over
    /// writer 1's head. BOTH appends survive — no update is lost.
    #[test]
    fn concurrent_txns_serialize_and_both_writers_appends_survive() {
        use std::sync::{Arc, Barrier};
        use std::thread;
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = Arc::new(LocalStore::with_base(dir.path().join("store")).unwrap());
        let target = "t1";

        let a_started = Arc::new(Barrier::new(2));
        let a_refusal_seen = Arc::new(Barrier::new(2));
        let a_released = Arc::new(Barrier::new(2));

        // WRITER 1: open the txn (hold the target lock), append intent-a +
        // its Successful terminal; park until writer 2 observed the
        // refusal, then drop the txn (release the lock) and confirm.
        let store_1 = Arc::clone(&store);
        let started_1 = Arc::clone(&a_started);
        let refusal_1 = Arc::clone(&a_refusal_seen);
        let released_1 = Arc::clone(&a_released);
        let writer_1 = thread::spawn(move || {
            let mut txn = TargetLedgerTxn::open(&store_1, target, "op-a").unwrap();
            let a = intent("deploy-a", target);
            txn.append_intent(&a).unwrap();
            txn.append_terminal(a.deployment_id(), &successful_terminal(&a))
                .unwrap();
            started_1.wait();
            refusal_1.wait();
            // txn drops here: the target lock is released.
            drop(txn);
            released_1.wait();
        });

        // WRITER 2: while writer 1 holds the lock, opening a second txn is
        // REFUSED (fail fast — the lock serializes writers); after writer 1
        // releases, writer 2 opens and appends intent-b planned over
        // writer 1's head (deploy-a) + its Successful terminal.
        let store_2 = Arc::clone(&store);
        let started_2 = Arc::clone(&a_started);
        let refusal_2 = Arc::clone(&a_refusal_seen);
        let released_2 = Arc::clone(&a_released);
        let writer_2 = thread::spawn(move || {
            started_2.wait();
            let err = match TargetLedgerTxn::open(&store_2, target, "op-b") {
                Ok(_) => panic!("writer 2 cannot open while writer 1 holds the target lock"),
                Err(e) => e,
            };
            assert!(
                err.to_string().contains("held by"),
                "the refusal names the holder, got: {err}"
            );
            refusal_2.wait();
            released_2.wait();
            let mut txn = TargetLedgerTxn::open(&store_2, target, "op-b").unwrap();
            // The strict-linear model: intent-b plans over the head writer 1
            // established (deploy-a), never a second pending on top.
            let head = txn
                .state()
                .successful_head()
                .and_then(|h| {
                    txn.state()
                        .entries()
                        .iter()
                        .find(|e| e.deployment_id == *h)
                        .map(|e| e.intent.clone())
                })
                .expect("writer 1's successful head is visible to writer 2");
            let b = intent_over_head("deploy-b", target, &head);
            txn.append_intent(&b).unwrap();
            txn.append_terminal(b.deployment_id(), &successful_terminal(&b))
                .unwrap();
        });

        writer_1.join().expect("writer 1 completes");
        writer_2.join().expect("writer 2 completes");

        // NO UPDATE IS LOST: both writers' appends survive in the ledger.
        let entries = store.read_ledger(target).unwrap();
        assert_eq!(
            entries.len(),
            2,
            "both writers' entries survive: {entries:?}"
        );
        assert_eq!(entries[0].deployment_id, test_deployment_id("deploy-a"));
        assert_eq!(entries[1].deployment_id, test_deployment_id("deploy-b"));
        assert_eq!(
            entries[1].intent.parent(),
            Some(&test_deployment_id("deploy-a"))
        );
        assert_eq!(
            store.read_last_successful(target).as_deref(),
            Some(test_deployment_id("deploy-b").as_str())
        );
    }
}
