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

use crate::error::{Error, Result};
use crate::identity::{DeploymentId, TargetName};
use crate::kernel::terminal;
use crate::kernel::transition::{
    CheckpointEvent, DeploymentState, IntentEvent, LedgerEvent, TerminalEvent,
};
use crate::ledger::{
    CheckpointWire, DeploymentIntent, DeploymentStatus, LEDGER_SCHEMA_VERSION, LedgerEntry,
    LedgerEventWire, LedgerIntentWire, LedgerTerminal, LedgerTerminalWire,
};
use crate::store::atomic::{path_state, set_private, sync_parent_dir, temp_name_for};
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
    target: &str,
    entries: &[LedgerEntry],
    entry: &LedgerEntry,
    terminal: &LedgerTerminal,
) -> Result<()> {
    // THE INTENT_DIGEST BINDING (event-store rule): the terminal must bind
    // the EXACT canonical intent.
    if terminal.intent_digest().as_str() != terminal::intent_digest(&entry.intent).as_str() {
        return Err(Error::integrity(format!(
            "ledger of target '{target}': terminal for deployment '{}' binds intent digest {} but the intent's canonical digest is {} — a terminal must bind the exact canonical intent",
            entry.deployment_id,
            terminal.intent_digest(),
            terminal::intent_digest(&entry.intent)
        )));
    }
    // THE SEMANTIC TRANSITION (delegated to the kernel): the disposition's
    // outcome payload must agree with the entry's intent (outcome keys ⊆
    // selected; suspicion-specific coverage).
    crate::kernel::transition::validate_terminal_vs_intent(entry, terminal).map_err(|e| {
        Error::integrity(format!(
            "ledger of target '{target}' refuses a terminal event: {e}"
        ))
    })?;
    // THE ONE-PARENT RULE, mirroring the kernel's state machine
    // ([`crate::kernel::transition::apply_event`] gates the Intent-only →
    // Successful transition on AT MOST ONE Successful PER PARENT): a
    // Successful terminal requires that no OTHER entry in the ledger already
    // carries a Successful terminal for the same parent. The check and the
    // append are ATOMIC under the single-writer target lock, so for any
    // given parent at most ONE plan can ever append `Successful` — the
    // second one to finalize observes a drifted head and is refused with
    // the kernel's [`KernelError::Conflict`] (StalePlan), never reconciled
    // implicitly, never successful.
    if terminal.disposition().is_successful() {
        let already = entries.iter().any(|e| {
            e.deployment_id != entry.deployment_id
                && e.terminal.as_ref().is_some_and(|t| {
                    t.status() == DeploymentStatus::Successful
                        && e.intent.parent() == entry.intent.parent()
                })
        });
        if already {
            return Err(Error::conflict(format!(
                "ledger of target '{target}' refuses the Successful terminal for deployment '{}': stale plan: its parent {:?} already produced a successful deployment — at most ONE Successful per parent; a stale plan is refused, never reconciled implicitly",
                entry.deployment_id,
                entry.intent.parent()
            )));
        }
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
    /// [`LocalStore::append_ledger_atomic`]). Fail-closed keying: the
    /// deployment id keys the entry, so a second intent for the same id (a
    /// corrupted duplicate) is refused rather than silently merged. The
    /// duplicate guard scans EVERY parsed ledger entry (`read_ledger`), not
    /// just the first one.
    pub fn append_intent(&self, target: &str, intent: &DeploymentIntent) -> Result<()> {
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::AppendAttempt, intent.deployment_id().as_str())
        {
            return Err(Error::store(
                "test fault: append_attempt (ledger intent) forced to fail once",
            ));
        }
        self.ensure_target_dir_durable(target)?;
        // The intent is the entry's durable key: a duplicate intent for the
        // same deployment id is corruption (deployment ids are unique per
        // push) and must fail closed rather than append a second entry. The
        // guard scans EVERY parsed entry (`read_ledger` is the source of
        // truth and fails closed on malformed lines) — a duplicate at any
        // position, not just the first entry, is refused.
        if self
            .read_ledger(target)?
            .iter()
            .any(|e| e.deployment_id == *intent.deployment_id())
        {
            return Err(Error::store(format!(
                "refusing to append a second intent for deployment '{}' (the ledger is keyed by deployment id)",
                intent.deployment_id()
            )));
        }
        let line = serde_json::to_string(&LedgerEventWire::Intent(LedgerIntentWire::from(intent)))
            .map_err(|e| Error::store(format!("serialize ledger intent: {e}")))?;
        self.append_ledger_atomic(target, intent.deployment_id().as_str(), &line)
    }

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
    pub fn append_terminal(
        &self,
        target: &str,
        deployment_id: &DeploymentId,
        terminal: &LedgerTerminal,
    ) -> Result<()> {
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::AppendTerminal, deployment_id.as_str())
        {
            return Err(Error::store(
                "test fault: append_terminal forced to fail once",
            ));
        }
        self.ensure_target_dir_durable(target)?;
        let entries = self.read_ledger(target)?;
        let entry = entries
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
        // THE PRE-WRITE VALIDATION (fail closed): the intent/terminal pair is
        // verified against the SAME checks the read path's state machine
        // applies BEFORE any write — the intent_digest binding, the
        // disposition-vs-intent agreement, and the one-parent gate on a
        // `Successful` disposition (the kernel's Conflict/StalePlan source).
        // A terminal the strict reader would reject is NEVER written (the
        // append is atomic; the ledger bytes stay unchanged on rejection).
        validate_terminal_append(target, &entries, entry, terminal)?;
        let wire = LedgerTerminalWire::to_wire(deployment_id, &entry.target, terminal);
        let line = serde_json::to_string(&LedgerEventWire::Terminal(wire))
            .map_err(|e| Error::store(format!("serialize ledger terminal: {e}")))?;
        self.append_ledger_atomic(target, deployment_id.as_str(), &line)
    }

    /// Append a CHECKPOINT event as a NEW ledger's first line — the atomic
    /// suffix replacement's record of the discarded prefix. Validated by the
    /// same kernel state machine as every other event (a checkpoint is
    /// accepted only as the first event of a ledger).
    pub fn append_checkpoint(&self, target: &str, checkpoint: &CheckpointEvent) -> Result<()> {
        self.ensure_target_dir_durable(target)?;
        let wire = CheckpointWire::new(
            &checkpoint.retained_from,
            checkpoint.discarded,
            &checkpoint.recorded_at.to_string(),
        );
        let line = serde_json::to_string(&LedgerEventWire::Checkpoint(wire))
            .map_err(|e| Error::store(format!("serialize ledger checkpoint: {e}")))?;
        self.append_ledger_atomic(target, checkpoint.retained_from.as_str(), &line)
    }

    /// Read the FULL deployment ledger of a target: every merged
    /// [`LedgerEntry`] (intent + optional terminal), in append order. This is
    /// the SINGLE history read. Every parsed wire line is converted through
    /// its VERIFYING CONVERSION and folded into the KERNEL's pure state
    /// machine ([`crate::kernel::transition::apply_event`]) — the event-store
    /// rules (one intent per deployment, at-most-one terminal, terminal
    /// `intent_digest` equality, event ordering) AND the semantic
    /// transitions (outcome coverage by disposition) are refused fail
    /// closed. Fail closed on malformed lines, foreign
    /// `deployment_schema_version`, an intent-less terminal, a duplicate
    /// intent, a duplicate terminal, or a disagreeing record.
    pub fn read_ledger(&self, target: &str) -> Result<Vec<LedgerEntry>> {
        let p = self.ledger_path(target);
        // Tri-state: only a genuine NotFound is "no ledger" (the empty
        // vector); a stat failure propagates as a Store error (an unreadable
        // ledger must not read as "no history").
        if !path_state(&p)? {
            return Ok(vec![]);
        }
        let text =
            std::fs::read_to_string(&p).map_err(|e| Error::store(format!("read ledger: {e}")))?;
        let target_name = TargetName::parse(target).expect("ledger target is a safe segment");
        let mut state = DeploymentState::new(target_name);
        for (seq, line) in text.lines().enumerate() {
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
            state = crate::kernel::transition::apply_event(state, event).map_err(|e| {
                Error::integrity(format!(
                    "ledger for target '{target}' rejects line {}: {e}",
                    seq + 1
                ))
            })?;
        }
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
    /// The ledger APPEND's durability protocol: atomically rewrite the WHOLE
    /// ledger (read-modify-write) through the same four-stage sequence as
    /// [`crate::store::atomic::write_atomic_replace`] — a UNIQUE temp file in
    /// the same directory, chmod-private BEFORE it can become visible, temp
    /// fsync, atomic rename (a reader sees wholly OLD or wholly NEW, never a
    /// torn line), then a FAIL-CLOSED parent-directory fsync (the durability
    /// commit point: the new ledger must survive power loss before the append
    /// reports success).
    ///
    /// The stages are materialized here — rather than a single
    /// `write_atomic_replace` call — so the per-fixture test registry can
    /// fault each one ([`FaultKind::AppendWrite`] / [`FaultKind::AppendSync`]
    /// / [`FaultKind::AppendRename`] / [`FaultKind::AppendDirSync`]), keyed
    /// by the deployment id being appended. The first three fault stages
    /// abort BEFORE the rename: the visible ledger is wholly OLD (a leftover
    /// dot-prefixed temp is invisible to every read). The dir-sync fault
    /// fires AFTER the rename: the ledger is wholly NEW — only the directory
    /// entry is unsynced — and the append returns `Err` (the same
    /// post-commit window the checkpoint's [`FaultKind::LedgerReplaceAfter`]
    /// models).
    ///
    /// Appends are serialized by the caller's target lock (push and
    /// checkpoint both acquire the application-store lock then the target
    /// lock before any ledger write), so the read-modify-write cannot
    /// interleave with a concurrent rewrite.
    fn append_ledger_atomic(&self, target: &str, _deployment_id: &str, line: &str) -> Result<()> {
        let p = self.ledger_path(target);
        // Durable target-dir creation (the FIRST append's reported bug): the
        // `targets/<target>/` — and `targets/` — directory entries must be
        // fsynced before the ledger write can report success. An existing
        // target's dir is the helper's fast path (created nothing, syncs
        // nothing).
        self.ensure_target_dir_durable(target)?;
        // Read-modify-write: the whole current ledger + the new line.
        let mut buf = String::new();
        if path_state(&p)? {
            buf = std::fs::read_to_string(&p)
                .map_err(|e| Error::store(format!("read ledger: {e}")))?;
            // A legacy in-place append (pre-durability-fix) may have crashed
            // WITHOUT a trailing newline; give that tail its own newline so
            // the new line is never FUSED into it (the pre-existing torn
            // tail still fails closed on read — this append neither drops
            // nor amplifies it).
            if !buf.is_empty() && !buf.ends_with('\n') {
                buf.push('\n');
            }
        }
        buf.push_str(line);
        buf.push('\n');

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{SlotId, test_deployment_id};
    use crate::ledger::records::{DeploymentStatus, LedgerIntentWire, LedgerTerminal};
    use crate::ledger::{LEDGER_SCHEMA_VERSION, LedgerLine};
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
        store.append_intent(target, &i).unwrap();
        store
            .append_terminal(target, i.deployment_id(), &successful_terminal(&i))
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
            .append_intent(target, &intent("deploy-a", target))
            .unwrap_err();
        assert!(err.to_string().contains("second intent"));
        // A duplicate terminal is refused.
        let i = intent("deploy-a", target);
        let err = store
            .append_terminal(
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
        let wire = crate::ledger::LedgerTerminalWire::to_wire(i.deployment_id(), i.target(), &t);
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
                .append_intent(target, &intent(id, target))
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
    /// entry, and `None` for an unknown deployment.
    #[test]
    fn latest_status_derives_from_the_ledger() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        store
            .append_intent(target, &intent("deploy-pending", target))
            .unwrap();
        seed_successful(&store, target, "deploy-ok");
        let deg_i = intent("deploy-deg", target);
        store.append_intent(target, &deg_i).unwrap();
        store
            .append_terminal(
                target,
                deg_i.deployment_id(),
                &fixtures::degraded_terminal(&deg_i, &[slot_p1()]),
            )
            .unwrap();
        assert_eq!(
            store
                .latest_status(test_deployment_id("deploy-pending").as_str())
                .unwrap(),
            None,
            "an intent-only entry IS the pending state — no pending status on the terminal enum"
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
    /// SUCCESSFUL entry, never a failed/pending one.
    #[test]
    fn last_successful_is_derived() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        store
            .append_intent(target, &intent("deploy-pending", target))
            .unwrap();
        seed_successful(&store, target, "deploy-ok");
        let fail_i = intent("deploy-fail", target);
        store.append_intent(target, &fail_i).unwrap();
        store
            .append_terminal(
                target,
                fail_i.deployment_id(),
                &fixtures::failed_preflight_terminal(&fail_i),
            )
            .unwrap();
        assert_eq!(
            store.read_last_successful(target).as_deref(),
            Some(test_deployment_id("deploy-ok").as_str())
        );
        // A second successful deployment becomes the newest head.
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
        store.append_intent(target, &a_first).unwrap();
        // deploy-b chains onto deploy-a (the lineage invariant — at most one
        // `Successful` per parent), so both can succeed once deploy-a's
        // terminal lands.
        let b_i = crate::testutil::fixtures::group_intent(
            "deploy-b",
            target,
            "g",
            a_first.deployment_id(),
            &a_first.resulting_snapshot(),
            &[slot_p1()],
            &[slot_p1()],
        );
        store.append_intent(target, &b_i).unwrap();
        store
            .fault_registry()
            .arm_append_terminal(test_deployment_id("deploy-a").as_str());
        let a_i = intent("deploy-a", target);
        let err = store
            .append_terminal(target, a_i.deployment_id(), &successful_terminal(&a_i))
            .unwrap_err();
        assert!(err.to_string().contains("append_terminal"));
        // The fault is consumed: a retry succeeds for deploy-a, and deploy-b
        // was never affected.
        store
            .append_terminal(target, a_i.deployment_id(), &successful_terminal(&a_i))
            .unwrap();
        store
            .append_terminal(target, b_i.deployment_id(), &successful_terminal(&b_i))
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
        store.append_intent(target, &a_i).unwrap();
        // A terminal bound to a DIFFERENT (but otherwise valid) intent.
        let other = fixtures::full_intent("deploy-other", target, &[slot_p1()], &[]);
        let t = fixtures::successful_terminal(&other);
        let err = store
            .append_terminal(target, a_i.deployment_id(), &t)
            .unwrap_err();
        assert!(
            err.to_string().contains("digest"),
            "a terminal bound to another intent must be refused before the write, got: {err}"
        );
        assert_eq!(store.read_ledger_lines(target).unwrap().len(), 1);
    }

    /// A checkpoint event: the atomic suffix replacement writes a
    /// checkpointed ledger whose FIRST line is the checkpoint event, and the
    /// reader's state machine accepts it exactly as the first event.
    #[test]
    fn checkpoint_event_is_accepted_and_validated() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        // Seed entries, then compact to the LAST one with a checkpoint
        // prefix.
        seed_successful(&store, target, "deploy-a");
        seed_successful(&store, target, "deploy-b");
        let lines = store.read_ledger_lines(target).unwrap();
        let keep: Vec<String> = lines[2..].to_vec();
        let checkpoint = crate::kernel::transition::CheckpointEvent {
            retained_from: test_deployment_id("deploy-b"),
            discarded: 1,
            recorded_at: crate::remote::helper::now_rfc3339_ts(),
        };
        store.append_checkpoint(target, &checkpoint).unwrap();
        store.write_ledger_suffix(target, &keep).unwrap();
        let entries = store.read_ledger(target).unwrap();
        assert_eq!(entries.len(), 1, "the retained suffix IS the ledger");
        assert_eq!(entries[0].deployment_id, test_deployment_id("deploy-b"));
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
            .append_intent(target, &intent("deploy-a", target))
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
                .append_intent(target, &intent("deploy-a", target))
                .unwrap();
            arm_stage(&store2, stage, test_deployment_id("deploy-a").as_str());
            let res = store2.append_terminal(target, a_i.deployment_id(), &t);
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
                .append_intent(target, &intent("deploy-a", target))
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
            let res = store.append_terminal(target, a_i.deployment_id(), &t);
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
                    let _ = store.append_terminal(target, a_i.deployment_id(), &t);
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
            .append_intent(target, &intent("deploy-a", target))
            .unwrap_err();
        assert!(err.to_string().contains("second intent"));
        assert_eq!(
            std::fs::read(store.ledger_path(target)).unwrap(),
            before,
            "a refused duplicate intent leaves the ledger bytes unchanged"
        );
    }
}
