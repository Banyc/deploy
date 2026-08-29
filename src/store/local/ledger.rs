//! The per-target deployment LEDGER (A2): `targets/<target>/ledger.jsonl`
//! — the durable intent / terminal-event appends, the deployment-id-keyed
//! duplicate guards, the intent+terminal merge with its cross-record
//! invariants, and the crash-atomic whole-ledger rewrite
//! (`LocalStore::append_ledger_atomic`).

use crate::error::{Error, Result};
use crate::identity::{DeploymentId, SlotId};
use crate::ledger::records::validate_successful_rollback_against_intent;
use crate::ledger::{
    DeploymentIntent, DeploymentStatus, LEDGER_SCHEMA_VERSION, LedgerEntry, LedgerIntentWire,
    LedgerLine, LedgerTerminal, LedgerTerminalWire, TerminalDisposition,
};
use crate::store::atomic::{path_state, set_private, sync_parent_dir, temp_name_for};
use crate::store::local::LocalStore;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;

#[cfg(test)]
use crate::testutil::test_faults::FaultKind;

/// THE STRICT READER'S TERMINAL LEG — the terminal-vs-entry verification
/// [`LocalStore::read_ledger`] applies when a terminal wire merges into its
/// durable entry, factored out so the WRITE path ([`LocalStore::append_terminal`])
/// runs the SAME predicates BEFORE an append. The checks are exactly the
/// read path's: the wire's `target` must EQUAL the entry's, every outcome
/// key must be a MEMBER of the intent's authoritative membership, the
/// VERIFYING CONVERSION ([`LedgerTerminalWire::into_domain`] — the rollback's
/// exact binding-key equality, the membership equations, the complete
/// equality predicate: a Successful slot's outcome is Known(g) with
/// g == rollback.slots[slot].generation, error None, uncompensated) must
/// accept the wire, and the STATUS-SPECIFIC legs (a Successful terminal
/// must REPRODUCE the intent's FROZEN selected/full memberships + the
/// full-push selected == full equality AND the rollback-vs-intent facts
/// (generation/artifact/physical binding per activated slot via
/// [`crate::ledger::records::validate_successful_rollback_against_intent`] after wire conversion);
/// a FailedPreflight terminal must
/// carry NO outcomes; every other terminal's outcomes must EXACTLY cover
/// the membership) must hold. A disagreement → `Error::integrity`. Corrupted
/// historical records whose rollback drifts from its intent fail closed during every read.
///
/// THE PRE-WRITE GUARANTEE: [`LocalStore::append_terminal`] runs this on the
/// CONSTRUCTED pair (the deployment's durable intent + the terminal about
/// to be written) BEFORE any write — a terminal the strict reader would
/// reject is NEVER written (the append is atomic; the ledger bytes stay
/// UNCHANGED on rejection), so any successful append is IMMEDIATELY
/// READABLE.
fn verify_terminal_against_entry(
    target: &str,
    entry: &LedgerEntry,
    wire: LedgerTerminalWire,
) -> Result<LedgerTerminal> {
    // TARGET EQUALITY (cross-record invariant, terminal leg): the wire's
    // `target` must EQUAL the entry's (the intent's) — the domain terminal
    // carries no identity (the enclosing entry owns it).
    if wire.target != entry.target {
        return Err(Error::integrity(format!(
            "ledger of target '{target}': terminal {} claims target '{}' but its entry (intent) is for target '{}' — the enclosing entry owns identity",
            wire.deployment_id, wire.target, entry.target
        )));
    }
    // OUTCOME AGREEMENT (cross-record half): every outcome key must be a
    // MEMBER of the intent's authoritative membership — an outcome for a
    // slot outside the deployment is a disagreement (a slot the deployment
    // never touched cannot report a result). KEPT for ALL statuses:
    // combined with the terminal-local outcomes == selected_membership
    // equality, it makes selected_membership ⊆ the intent's slot_ids (the
    // intent's membership IS the frozen selected set). The EXACT equality
    // intent.slot_ids == selected_membership is the INTENT-BINDING leg
    // below (the intent FREEZES both memberships at plan time; the
    // terminal must REPRODUCE them — the verification is a PURE function of
    // the persisted sets + mode, and never consults the live configuration
    // for these equations).
    for key in wire.outcomes.keys().cloned().collect::<Vec<_>>() {
        if !entry.intent.slots.contains_key(&key) {
            return Err(Error::integrity(format!(
                "ledger of target '{target}': terminal {} records an outcome for slot '{key}' outside the intent's membership — every outcome must name a member slot",
                wire.deployment_id
            )));
        }
    }
    // VERIFYING CONVERSION (wire → domain): the rollback payload's
    // duplicate projections (each generation assignment's slot, the
    // bindings' slot set — the exact key-set equality the single-map
    // construction guarantees —, the legacy snapshot-wide release) must
    // agree, the status must map to exactly one disposition whose payload
    // matches, and each outcome's value must name its own key — a
    // disagreeing record is refused.
    let terminal = wire.into_domain().map_err(|e| {
        Error::integrity(format!(
            "ledger for target '{target}' refuses a terminal line: {e}"
        ))
    })?;
    // OUTCOME KEY SET AGREEMENT (cross-record invariant, outcome leg), BY
    // STATUS: the terminal's outcome key set must agree with the intent's
    // AUTHORITATIVE membership — the outcomes are the disposition's OWN
    // table ([`LedgerTerminal::outcomes`] — a FailedPreflight terminal
    // yields an empty table):
    // - Successful: every outcome key is a member of the intent (checked
    //   above), and the terminal carries its OWN proven memberships (the
    //   conversion enforced outcomes == selected_membership, rollback slots
    //   == full_membership, selected ⊆ full — the record is self-proving),
    //   so the Successful legs are the INTENT-BINDING legs below (the
    //   terminal must REPRODUCE the intent's frozen selected/full) plus the
    //   FULL-push equality (the mode lives in the intent's `group`). The
    //   intent's `slot_ids` is NOT compared to the terminal's memberships
    //   EXCEPT through the frozen binding: the intent's OWN frozen selected
    //   (== its table keys) and full are the AUTHORITATIVE facts, and a
    //   terminal whose memberships diverge is refused.
    // - FailedPreflight: outcomes EMPTY (a pre-mutation failure touched no
    //   slot).
    // - every other terminal state (FailedRolledBack, Degraded): the
    //   outcomes EXACTLY COVER the membership — every member slot has one
    //   outcome, no extras, no missing.
    // THE MATERIALIZED DERIVED VIEW: for a Successful terminal
    // [`LedgerTerminal::outcomes`] re-derives the per-slot facts from the
    // rollback (the accessor is owned), so the key set is copied out by
    // value here.
    let outcome_keys: BTreeSet<SlotId> = terminal.outcomes().keys().cloned().collect();
    let membership: BTreeSet<SlotId> = entry.intent.slots.keys().cloned().collect();
    match terminal.status() {
        DeploymentStatus::Successful => {
            // THE SUCCESSFUL SNAPSHOT RULE (membership leg), BY INTENT
            // GROUP: the terminal's OWN proven memberships satisfy the
            // terminal-local equations (outcomes == selected, rollback ==
            // full, selected ⊆ full — enforced by the conversion).
            // THE INTENT-BINDING LEGS: the terminal's memberships must
            // REPRODUCE the intent's FROZEN values — the intent is the
            // IMMUTABLE record that froze selected (its table keys) and
            // full (the complete target membership at plan time), and a
            // terminal whose memberships diverge from it is refused
            // (integrity error), so the terminal can never be re-derived
            // from the live configuration. The FULL-push EQUALITY: a FULL
            // push (no group) selects every target slot, so the ACTIVATED
            // set (== the wire's selected_membership, the outcomes' keys)
            // must EQUAL full_membership. A GROUP push allows a proper
            // subset (activated ⊆ full is already enforced by the
            // conversion).
            let (rollback, activated, selected, full) = match &terminal.disposition {
                TerminalDisposition::Successful(st) => (
                    st.rollback(),
                    st.activated().as_set(),
                    st.activated().as_set(),
                    st.full_membership(),
                ),
                _ => unreachable!(
                    "a Successful terminal carries its rollback + activated set + memberships"
                ),
            };
            // THE ROLLBACK-VS-INTENT LEG: a Successful rollback must REPRODUCE the durable intent's frozen facts for every activated slot — generation, artifact, and physical binding.
            validate_successful_rollback_against_intent(&entry.intent, rollback, activated)?;
            if selected != &entry.intent.selected_membership() {
                return Err(Error::integrity(format!(
                    "ledger of target '{target}': Successful terminal for deployment '{}' records selected membership {selected:?} but the intent froze selected membership {:?} — the terminal must REPRODUCE the immutable intent's frozen selected membership (never the live configuration)",
                    entry.deployment_id,
                    entry.intent.selected_membership()
                )));
            }
            if full != entry.intent.full_membership() {
                return Err(Error::integrity(format!(
                    "ledger of target '{target}': Successful terminal for deployment '{}' records full membership {full:?} but the intent froze full membership {:?} — the terminal must REPRODUCE the immutable intent's frozen full membership (the complete target membership at plan time, never the live configuration)",
                    entry.deployment_id,
                    entry.intent.full_membership()
                )));
            }
            if entry.intent.group.is_none() && selected != full {
                return Err(Error::integrity(format!(
                    "ledger of target '{target}': Successful terminal for deployment '{}' records selected membership {selected:?} and full membership {full:?} — a FULL push (no group) selects every target slot, so its selected membership must EXACTLY equal its full membership",
                    entry.deployment_id
                )));
            }
        }
        DeploymentStatus::FailedPreflight => {
            if !outcome_keys.is_empty() {
                return Err(Error::integrity(format!(
                    "ledger of target '{target}': FailedPreflight terminal for deployment '{}' carries outcomes for slots {outcome_keys:?} — a pre-mutation failure touched no slot",
                    entry.deployment_id
                )));
            }
        }
        _ => {
            if outcome_keys != membership {
                return Err(Error::integrity(format!(
                    "ledger of target '{target}': terminal for deployment '{}' carries outcomes for slots {outcome_keys:?} but its intent's slot_ids are {membership:?} — every member slot has exactly one outcome, no extras",
                    entry.deployment_id
                )));
            }
        }
    }
    Ok(terminal)
}

impl LocalStore {
    // ---- the per-target deployment LEDGER --------------------------------

    /// Path of the target's ONE ordered deployment ledger
    /// (`targets/<target>/ledger.jsonl`). The ledger holds every deployment
    /// event of the target: each entry starts as the DURABLE INTENT line
    /// (written BEFORE any remote mutation) and its TERMINAL EVENT line
    /// (appended after the mutation loop) carries the status, outcomes, and
    /// — when successful — the rollback state. The append order IS the
    /// history order; there is no separate floor marker, snapshot op log,
    /// or per-deployment results/transition stream.
    pub fn ledger_path(&self, target: &str) -> PathBuf {
        self.target_dir(target).join("ledger.jsonl")
    }

    /// Append the DURABLE INTENT of one deployment to the target's ledger
    /// (one `{"kind":"intent", ...}` JSON line), BEFORE any remote
    /// mutation: a crash after servers advanced to new generations can never
    /// lose the deployment (the intent is already durable and the next push
    /// reconciles it). The append is a CRASH-ATOMIC whole-ledger rewrite
    /// (temp + fsync + chmod + rename + parent-dir fsync, see
    /// `LocalStore::append_ledger_atomic`): a successful append is durable
    /// and a crash can never leave a torn line. Fail-closed keying: the
    /// deployment id keys the entry, so a second intent for the same id (a
    /// corrupted duplicate) is refused rather than silently merged. The
    /// duplicate guard scans EVERY parsed ledger entry (`read_ledger`), not
    /// just the first one.
    pub fn append_intent(&self, target: &str, intent: &DeploymentIntent) -> Result<()> {
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::AppendAttempt, intent.deployment_id.as_str())
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
            .any(|e| e.deployment_id == intent.deployment_id)
        {
            return Err(Error::store(format!(
                "refusing to append a second intent for deployment '{}' (the ledger is keyed by deployment id)",
                intent.deployment_id
            )));
        }
        let line = serde_json::to_string(&LedgerLine::Intent(LedgerIntentWire::from(intent)))
            .map_err(|e| Error::store(format!("serialize ledger intent: {e}")))?;
        self.append_ledger_atomic(target, intent.deployment_id.as_str(), &line)
    }

    /// Append the TERMINAL EVENT of one deployment to the target's ledger
    /// ("`{"kind":"terminal", ...}`" JSON line), after the mutation loop.
    /// The terminal carries the status, the per-slot outcomes, and — when
    /// successful — the rollback state. Like the intent it is appended via
    /// the crash-atomic whole-ledger rewrite (see
    /// `LocalStore::append_ledger_atomic`). Fail-closed key contract: the
    /// deployment's intent must already exist in the ledger (a terminal for
    /// an unknown deployment is corruption) and the entry must not already
    /// have a terminal (the terminal event is written exactly once;
    /// replay-safety is handled by the finalizer checking the entry first).
    /// Append the TERMINAL EVENT of one deployment to the target's ledger
    /// ("`{"kind":"terminal", ...}`" JSON line), after the mutation loop.
    /// The terminal carries the disposition (status), the per-slot outcomes,
    /// and — when successful — the rollback state. Like the intent it is
    /// appended via the crash-atomic whole-ledger rewrite (see
    /// `LocalStore::append_ledger_atomic`). Fail-closed key contract: the
    /// deployment's intent must already exist in the ledger (a terminal for
    /// an unknown deployment is corruption) and the entry must not already
    /// have a terminal (the terminal event is written exactly once;
    /// replay-safety is handled by the finalizer checking the entry first).
    ///
    /// LET THE ENCLOSING OBJECT OWN IDENTITY: the DOMAIN [`LedgerTerminal`]
    /// carries no `deployment_id` / `target` — the caller supplies the
    /// deployment id (the wire record keeps the on-disk identity members;
    /// the reader verifies them equal to the enclosing entry's).
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
        // THE PRE-WRITE VALIDATION (fail closed — the hard guarantee): the
        // INTENT/TERMINAL PAIR is verified against the STRICT READER'S OWN
        // legs BEFORE any write — the same terminal-vs-entry verification
        // `read_ledger` applies when the terminal merges into its entry
        // ([`verify_terminal_against_entry`]: the wire's target, every
        // outcome key inside the intent's membership, the VERIFYING
        // CONVERSION — the rollback's exact binding-key equality, the
        // membership equations, the complete equality predicate — and the
        // status-specific legs, including a Successful terminal reproducing
        // the intent's FROZEN memberships). A terminal the strict reader
        // would reject — a divergent rollback (bindings key set ≠ slots key
        // set: MISSING / EXTRA / RENAMED bindings), a membership that does
        // not reproduce the intent's frozen values, a Successful terminal
        // without its rollback — ABORTS here, and the append is atomic (the
        // ledger bytes stay UNCHANGED): a rejected pair NEVER writes, so
        // any successful append is IMMEDIATELY READABLE.
        // For the single-map shape, `activated` must be subset of `rollback`
        // — a successful terminal whose activated slots are not covered by
        // its rollback is structurally inconsistent and is refused here
        // before `from_domain` would panic when deriving `outcomes`.
        if let crate::ledger::records::TerminalDisposition::Successful(st) = &terminal.disposition {
            for sid in st.activated().iter() {
                if st.rollback().get(sid).is_none() {
                    return Err(crate::error::Error::integrity(format!(
                        "terminal {}: activated slot '{}' not covered by rollback — the successful terminal's activated slots must be subset of its rollback (the single-map shape)",
                        deployment_id, sid
                    )));
                }
            }
        }
        let wire = LedgerTerminalWire::from_domain(deployment_id, &entry.target, terminal);
        verify_terminal_against_entry(target, entry, wire.clone())?;
        let line = serde_json::to_string(&LedgerLine::Terminal(wire))
            .map_err(|e| Error::store(format!("serialize ledger terminal: {e}")))?;
        self.append_ledger_atomic(target, deployment_id.as_str(), &line)
    }

    /// Read the FULL deployment ledger of a target: every merged
    /// [`LedgerEntry`] (intent + optional terminal), in append order. This is
    /// the SINGLE history read — it replaces the old `read_attempts` /
    /// `read_snapshots` pair (and their raw variants): there is no floor to
    /// gate (the checkpoint replaced the ledger with the retained suffix
    /// atomically) and no separate snapshot log. Every parsed wire line is
    /// converted through the VERIFYING CONVERSION
    /// ([`LedgerIntentWire::into_domain`] / [`LedgerTerminalWire::into_domain`])
    /// and the CROSS-RECORD invariants are enforced where the intent and the
    /// terminal merge: a record whose duplicate projections disagree (e.g. a
    /// `desired` key outside the authoritative `slot_ids` membership, a
    /// rollback whose legacy release disagrees with the derived releases, a
    /// Successful terminal without its rollback, an outcome whose value
    /// names a different slot, a rollback whose binding keys are not exactly
    /// its generation keys, a Successful terminal whose outcomes ≠ its
    /// selected_membership, whose rollback slots ≠ its full_membership, or
    /// whose selected_membership ⊄ full_membership), or whose cross-record
    /// claims disagree (the terminal's target vs the read path / its intent,
    /// every outcome key vs the intent's `slot_ids` membership, and — BY
    /// INTENT GROUP — the FULL-push Successful terminal's
    /// selected_membership == full_membership equality AND THE INTENT-BINDING
    /// legs (a Successful terminal's `selected_membership` must EQUAL the
    /// intent's FROZEN `selected_membership` and its `full_membership` must
    /// EQUAL the intent's FROZEN `full_membership` — the terminal REPRODUCES
    /// the immutable intent, never the live configuration; a GROUP push's
    /// Successful terminal carries its OWN proven memberships and needs no
    /// membership leg beyond the terminal-local equations + the intent
    /// binding; a FailedPreflight
    /// terminal must carry NO outcomes, and every other terminal state's
    /// outcomes must EXACTLY cover the membership), is REFUSED with an
    /// integrity error — a hand-constructed or tampered record is never read
    /// as whichever projection a consumer happens to use. Fail closed on
    /// malformed lines, foreign `deployment_schema_version`, an intent-less
    /// terminal, a duplicate intent, a duplicate terminal, or a disagreeing
    /// record.
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
        let mut out: Vec<LedgerEntry> = Vec::new();
        let mut index: BTreeMap<String, usize> = BTreeMap::new();
        for (seq, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<LedgerLine>(line)
                .map_err(|e| Error::store(format!("parse ledger line: {e}")))?
            {
                LedgerLine::Intent(wire) => {
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
                    // VERIFYING CONVERSION (wire → domain): every duplicate
                    // projection (desired/pre_push/slots key sets vs the
                    // authoritative `slot_ids`, each generation assignment's
                    // slot) must agree — a disagreement is refused (fail
                    // closed) rather than read as whichever projection a
                    // consumer happens to use.
                    let intent = wire.into_domain().map_err(|e| {
                        Error::integrity(format!(
                            "ledger for target '{target}' refuses an intent line: {e}"
                        ))
                    })?;
                    // TARGET EQUALITY (cross-record invariant, intent leg):
                    // the intent's own `target` must equal the ledger path it
                    // was read from — a record written into the wrong
                    // target's ledger would otherwise be rendered and swept
                    // under the wrong target's history.
                    if intent.target.as_str() != target {
                        return Err(Error::integrity(format!(
                            "ledger for target '{target}' refuses an intent line: deployment '{}' names target '{}'",
                            intent.deployment_id, intent.target
                        )));
                    }
                    let id = intent.deployment_id.as_str().to_string();
                    if index.contains_key(&id) {
                        return Err(Error::integrity(format!(
                            "ledger for target '{target}' has two intent lines for deployment '{id}' — the ledger is keyed by deployment id (one intent per entry)"
                        )));
                    }
                    index.insert(id.clone(), out.len());
                    out.push(LedgerEntry {
                        deployment_id: intent.deployment_id.clone(),
                        target: intent.target.clone(),
                        intent,
                        terminal: None,
                        seq: seq as u64,
                    });
                }
                LedgerLine::Terminal(wire) => {
                    // LET THE ENCLOSING OBJECT OWN IDENTITY: the terminal
                    // wire's `deployment_id` is the ENTRY KEY (the terminal
                    // merges into the entry that carries that id — a
                    // terminal whose id matches no intent is corruption),
                    // and its `target` must EQUAL the entry's target (the
                    // intent's). The terminal-vs-entry verification — the
                    // target equality, the outcome-key agreement, the
                    // VERIFYING CONVERSION, and the status-specific legs —
                    // is the SHARED STRICT-READER TERMINAL LEG
                    // ([`verify_terminal_against_entry`], factored out so
                    // the WRITE path runs the SAME predicates before an
                    // append).
                    let id = wire.deployment_id.clone();
                    let pos = index.get(id.as_str()).copied().ok_or_else(|| {
                        Error::integrity(format!(
                            "ledger of target '{target}': a terminal event for deployment '{id}' has no intent line — a terminal event requires its durable intent (a closed-DB corruption)"
                        ))
                    })?;
                    let terminal = verify_terminal_against_entry(target, &out[pos], wire)?;
                    let entry = &mut out[pos];
                    if entry.terminal.is_some() {
                        return Err(Error::integrity(format!(
                            "ledger of target '{target}': two terminal events for deployment '{id}' — a terminal event is written exactly once"
                        )));
                    }
                    entry.terminal = Some(terminal);
                }
            }
        }
        Ok(out)
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
    /// terminal yet — `Some(PendingCommit)` (the recoverable in-progress /
    /// pending-commit state: the intent is durable, the finalization never
    /// completed). `None` when no ledger entry carries the deployment id at
    /// all. Scans every target's ledger (the deployment id does not name its
    /// target; the entry's own intent does).
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
                    return Ok(e
                        .terminal
                        .map(|t| t.status())
                        .or(Some(DeploymentStatus::PendingCommit)));
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
    use crate::config::ProjectConfig;
    use crate::deploy::lock::FileLock;
    use crate::identity::{
        ArtifactRef, GenerationRef, PlacementSlotAssignment, ServerId, SlotId, TargetName,
        VariantName, test_deployment_id, test_generation_id, test_tree_digest,
    };
    use crate::ledger::{
        DeploymentIntent, DesiredGeneration, IntentSlot, LedgerIntentWire, LedgerLine,
        LedgerTerminal, LedgerTerminalWire, NonEmptySlotTable, Observation, ObservedGeneration,
        PhysicalBinding, PreviousGeneration, SlotOutcome, SlotOutcomeKind, SlotTable,
        SlotTransition, TargetSnapshot, TerminalDisposition,
    };
    use proptest::prelude::*;
    use proptest::test_runner::{FileFailurePersistence, RngSeed};
    fn intent(id: &str, target: &str) -> DeploymentIntent {
        let p1 = SlotId::new("p1".to_string());
        // ONE slot table: the membership AND the desired/pre-push entries
        // (the exact-key-set invariant is structural in the domain).
        let slots = BTreeMap::from([(
            p1.clone(),
            IntentSlot {
                desired: DesiredGeneration {
                    generation: test_generation_id("1"),
                    artifact: ArtifactRef {
                        release: crate::identity::test_release_id("rel-1"),
                        variant: VariantName::new("standard".to_string()),
                        tree: test_tree_digest("1"),
                    },
                },
                pre_push: None,
                // The FROZEN plan-time physical binding (schema v6): the
                // fixture's single slot is bound to server s1 at
                // /srv/deploy/p1.
                binding: crate::ledger::PhysicalBinding {
                    server: ServerId::new("s1".to_string()),
                    deploy_dir: "/srv/deploy/p1".to_string(),
                },
            },
        )]);
        DeploymentIntent {
            deployment_id: test_deployment_id(id),
            target: TargetName::parse(target).expect("target name is a safe segment"),
            group: None,
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            slots: NonEmptySlotTable::build(slots)
                .expect("a seeded deployment always has at least one slot"),
            full_membership: BTreeSet::from([SlotId::new("p1".to_string())]),
        }
    }

    fn successful_terminal() -> LedgerTerminal {
        let rollback = {
            let __slots: BTreeMap<crate::identity::SlotId, crate::identity::GenerationRef> =
                BTreeMap::from([(
                    SlotId::new("p1".to_string()),
                    GenerationRef {
                        generation: test_generation_id("1"),
                        assignment: PlacementSlotAssignment {
                            placement_slot: SlotId::new("p1".to_string()),
                            artifact: ArtifactRef {
                                release: crate::identity::test_release_id("rel-1"),
                                variant: VariantName::new("standard".to_string()),
                                tree: test_tree_digest("1"),
                            },
                        },
                    },
                )]);
            let __bindings: BTreeMap<
                crate::identity::SlotId,
                crate::ledger::records::PhysicalBinding,
            > = BTreeMap::from([(
                SlotId::new("p1".to_string()),
                crate::ledger::PhysicalBinding {
                    server: crate::identity::ServerId::new("s1".to_string()),
                    deploy_dir: "/srv/deploy/p1".to_string(),
                },
            )]);
            let mut __entries: BTreeMap<
                crate::identity::SlotId,
                crate::ledger::records::SnapshotEntry,
            > = BTreeMap::new();
            for (k, v) in __slots.clone() {
                let b = __bindings.get(&k).cloned().unwrap_or(
                    crate::ledger::records::PhysicalBinding {
                        server: crate::identity::ServerId::new("s1"),
                        deploy_dir: format!("/srv/deploy/{}", k.as_str()),
                    },
                );
                __entries.insert(
                    k.clone(),
                    crate::ledger::records::SnapshotEntry::new(
                        v.generation.clone(),
                        v.assignment.artifact.clone(),
                        b,
                    ),
                );
            }
            for (k, b) in __bindings.clone() {
                __entries.entry(k.clone()).or_insert_with(|| {
                    crate::ledger::records::SnapshotEntry::new(
                        crate::identity::GenerationId::new("gen-missing".to_string()),
                        crate::identity::ArtifactRef {
                            release: crate::identity::test_release_id("rel-missing"),
                            variant: crate::identity::VariantName::new("standard".to_string()),
                            tree: crate::identity::test_tree_digest("missing"),
                        },
                        b.clone(),
                    )
                });
            }
            TargetSnapshot::from_entries(__entries)
        };
        let activated = crate::identity::NonEmptySlotSet::try_new(BTreeSet::from([SlotId::new(
            "p1".to_string(),
        )]))
        .unwrap();
        let full_membership = BTreeSet::from([SlotId::new("p1".to_string())]);
        let st = crate::ledger::SuccessfulTerminal::try_new(rollback, activated, full_membership)
            .unwrap();
        LedgerTerminal {
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
            // A Successful disposition ALWAYS carries its complete rollback
            // payload (the truth table is structural in the domain) AND its
            // OWN outcomes table (every outcome Activated, each key covered
            // by the rollback's slots).
            disposition: TerminalDisposition::Successful(st),
            reason: None,
        }
    }

    fn seed_successful(store: &LocalStore, target: &str, id: &str) {
        store.append_intent(target, &intent(id, target)).unwrap();
        store
            .append_terminal(target, &test_deployment_id(id), &successful_terminal())
            .unwrap();
    }

    /// The ledger round-trips: intent + terminal merge into ONE entry per
    /// deployment id, in append order, with the terminal carrying status,
    /// outcomes, and the rollback state. A terminal without its intent, a
    /// duplicate intent, or a duplicate terminal FAILS CLOSED (integrity).
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
        assert_eq!(
            entries[0].terminal.as_ref().unwrap().outcomes()[&SlotId::new("p1")].outcome,
            SlotOutcomeKind::Activated
        );
        assert_eq!(
            match &entries[0].terminal.as_ref().unwrap().disposition {
                TerminalDisposition::Successful(st) => st.rollback(),
                _ => panic!("the successful terminal carries its rollback"),
            }
            .get(&SlotId::new("p1"))
            .unwrap()
            .artifact()
            .release
            .as_str(),
            crate::identity::test_release_id("rel-1").as_str()
        );
        // A terminal without its intent is refused (fail closed).
        let err = store
            .append_terminal(
                target,
                &test_deployment_id("deploy-ghost"),
                &successful_terminal(),
            )
            .unwrap_err();
        assert!(err.to_string().contains("no ledger intent"));
        // A duplicate intent is refused (the deployment id keys the entry).
        let err = store
            .append_intent(target, &intent("deploy-a", target))
            .unwrap_err();
        assert!(err.to_string().contains("second intent"));
        // A duplicate terminal is refused.
        let err = store
            .append_terminal(
                target,
                &test_deployment_id("deploy-a"),
                &successful_terminal(),
            )
            .unwrap_err();
        assert!(err.to_string().contains("already carries a terminal"));
    }

    /// The duplicate-intent guard scans EVERY ledger entry, not just the
    /// first one: a second intent whose deployment id duplicates the FIRST,
    /// a MIDDLE, or the LAST entry is refused (the deployment id keys the
    /// ledger), while a genuinely NEW id still appends fine.
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
        // A NEW unique id still appends fine (the guard rejects only
        // duplicates, never over-rejects).
        seed_successful(&store, target, "deploy-new");
        assert_eq!(
            store.read_ledger(target).unwrap().len(),
            4,
            "a fresh id appends as a fourth entry"
        );
    }

    /// A foreign `deployment_schema_version` on an intent line fails closed
    /// (only `LEDGER_SCHEMA_VERSION` is accepted), and a malformed line is a store
    /// error, never a silent drop.
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
        // Malformed bytes are a store error, never silently dropped.
        std::fs::write(&p, "{ not json !\n").unwrap();
        assert!(store.read_ledger(target).is_err());
    }

    /// The read path runs the VERIFYING CONVERSION: a ledger line whose
    /// duplicate projections disagree (e.g. a `desired` key outside the
    /// authoritative `slot_ids` membership) is REFUSED with an integrity
    /// error rather than read as whichever projection a consumer happens to
    /// use; the same record with an AGREEING membership reads fine.
    #[test]
    fn read_ledger_refuses_disagreeing_records() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        let p = store.ledger_path(target);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();

        // A DISAGREEING intent: `desired` names a slot the membership omits.
        let mut wire = LedgerIntentWire::from(&intent("deploy-x", target));
        wire.desired.insert(
            SlotId::new("not-a-member".to_string()),
            GenerationRef {
                generation: test_generation_id("1"),
                assignment: PlacementSlotAssignment {
                    placement_slot: SlotId::new("not-a-member".to_string()),
                    artifact: ArtifactRef {
                        release: crate::identity::test_release_id("rel-1"),
                        variant: VariantName::new("standard".to_string()),
                        tree: test_tree_digest("1"),
                    },
                },
            },
        );
        let line = serde_json::to_string(&LedgerLine::Intent(wire)).unwrap();
        std::fs::write(&p, format!("{line}\n")).unwrap();
        let err = store.read_ledger(target).unwrap_err();
        assert!(
            err.to_string().contains("refuses"),
            "a disagreeing intent line must be refused, got: {err}"
        );

        // The same record with an AGREEING membership reads fine: the extra
        // slot joins slot_ids AND both per-slot maps (EXACT key-set equality
        // — every member slot has exactly one desired + one pre_push entry).
        let mut wire = LedgerIntentWire::from(&intent("deploy-x", target));
        let extra = SlotId::new("not-a-member".to_string());
        wire.slot_ids.push(extra.clone());
        wire.selected_membership.push(extra.clone());
        wire.full_membership.push(extra.clone());
        wire.desired.insert(
            extra.clone(),
            GenerationRef {
                generation: test_generation_id("2"),
                assignment: PlacementSlotAssignment {
                    placement_slot: extra.clone(),
                    artifact: ArtifactRef {
                        release: crate::identity::test_release_id("rel-2"),
                        variant: VariantName::new("standard".to_string()),
                        tree: test_tree_digest("2"),
                    },
                },
            },
        );
        wire.pre_push.insert(extra.clone(), None);
        // The FROZEN PHYSICAL BINDINGS follow the membership (schema v6):
        // the extra member also freezes its plan-time binding, so the
        // binding keys keep agreeing with the slot table keys.
        wire.bindings.insert(extra.clone(), binding_for(&extra));
        let line = serde_json::to_string(&LedgerLine::Intent(wire)).unwrap();
        std::fs::write(&p, format!("{line}\n")).unwrap();
        let entries = store.read_ledger(target).unwrap();
        assert_eq!(entries.len(), 1, "the agreeing line loads");
        assert_eq!(entries[0].intent.membership().len(), 2);
    }

    /// `latest_status` derives from the ledger: the terminal's status for a
    /// settled entry, `PendingCommit` for an intent-only (recoverable) entry,
    /// and `None` for an unknown deployment.
    #[test]
    fn latest_status_derives_from_the_ledger() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        store
            .append_intent(target, &intent("deploy-pending", target))
            .unwrap();
        seed_successful(&store, target, "deploy-ok");
        store
            .append_intent(target, &intent("deploy-deg", target))
            .unwrap();
        store
            .append_terminal(
                target,
                &test_deployment_id("deploy-deg"),
                &LedgerTerminal {
                    recorded_at: "2026-01-01T00:00:00Z".to_string(),
                    // The degraded terminal records the slot that REMAINS
                    // changed (never restored): the conversion derives the
                    // Degraded disposition's non-empty remaining changes
                    // from the disposition's OWN outcomes.
                    disposition: TerminalDisposition::Degraded {
                        outcomes: SlotTable::from_map(BTreeMap::from([(
                            SlotId::new("p1".to_string()),
                            SlotOutcome {
                                outcome: SlotOutcomeKind::Skipped,
                                observation: Observation::Known(ObservedGeneration {
                                    generation: test_generation_id("1"),
                                }),
                                compensated: false,
                                error: None,
                                transition: SlotTransition::NeverAdvanced,
                            },
                        )])),
                    },
                    reason: Some("boom".to_string()),
                },
            )
            .unwrap();
        assert_eq!(
            store
                .latest_status(test_deployment_id("deploy-pending").as_str())
                .unwrap(),
            Some(DeploymentStatus::PendingCommit),
            "an intent-only entry is the recoverable pending state"
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

    /// `read_last_successful` is DERIVED from the ledger (the newest
    /// `Successful` terminal) — no separate ref file exists anymore.
    #[test]
    fn last_successful_is_derived() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        assert_eq!(store.read_last_successful(target), None);
        seed_successful(&store, target, "deploy-a");
        seed_successful(&store, target, "deploy-b");
        assert_eq!(
            store.read_last_successful(target).as_deref(),
            Some(test_deployment_id("deploy-b").as_str()),
            "the newest successful entry is the derived last-successful"
        );
        // A later failed deployment does not move the pointer.
        store
            .append_intent(target, &intent("deploy-fail", target))
            .unwrap();
        store
            .append_terminal(
                target,
                &test_deployment_id("deploy-fail"),
                &LedgerTerminal {
                    recorded_at: "2026-01-01T00:00:00Z".to_string(),
                    // The FailedRolledBack compensation report IS the outcome
                    // table — it must EXACTLY cover the membership (the
                    // status-specific outcome rule).
                    disposition: TerminalDisposition::FailedRolledBack {
                        outcomes: SlotTable::from_map(BTreeMap::from([(
                            SlotId::new("p1".to_string()),
                            SlotOutcome {
                                outcome: SlotOutcomeKind::Restored,
                                observation: Observation::Known(ObservedGeneration {
                                    generation: test_generation_id("gen-1"),
                                }),
                                compensated: true,
                                error: None,
                                transition: SlotTransition::Restored,
                            },
                        )])),
                    },
                    reason: None,
                },
            )
            .unwrap();
        assert_eq!(
            store.read_last_successful(target).as_deref(),
            Some(test_deployment_id("deploy-b").as_str())
        );
    }

    /// One-shot faults are status-qualified and consumed exactly once (the
    /// terminal append fault fires on the matching deployment id only).
    #[test]
    fn append_terminal_fault_is_one_shot_and_id_qualified() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        store
            .append_intent(target, &intent("deploy-a", target))
            .unwrap();
        store
            .append_intent(target, &intent("deploy-b", target))
            .unwrap();
        store
            .fault_registry()
            .arm_append_terminal(test_deployment_id("deploy-a").as_str());
        // The fault fires exactly once on the matching id...
        store
            .append_terminal(
                target,
                &test_deployment_id("deploy-a"),
                &successful_terminal(),
            )
            .expect_err("the armed terminal fault fires");
        // ...before any append (the entry is still intent-only) and is then
        // disarmed: the retry succeeds.
        store
            .append_terminal(
                target,
                &test_deployment_id("deploy-a"),
                &successful_terminal(),
            )
            .expect("the disarmed retry appends the terminal");
        // A second terminal for the SAME deployment is refused (exactly-once).
        store
            .append_terminal(
                target,
                &test_deployment_id("deploy-a"),
                &successful_terminal(),
            )
            .expect_err("a second terminal is refused (exactly-once contract)");
        // A different deployment is never faulted.
        store
            .append_terminal(
                target,
                &test_deployment_id("deploy-b"),
                &successful_terminal(),
            )
            .expect("a different deployment's terminal passes");
    }

    /// Two fixtures' fault registries are structurally isolated: an arm on
    /// one store can never be consumed by another store.
    #[test]
    fn arming_one_fixture_cannot_be_consumed_by_another_fixtures_store() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let s1 = LocalStore::with_base(dir.path().join("s1")).unwrap();
        let s2 = LocalStore::with_base(dir.path().join("s2")).unwrap();
        s1.fault_registry()
            .arm_append_terminal(test_deployment_id("deploy-a").as_str());
        s2.fault_registry()
            .arm_append_terminal(test_deployment_id("deploy-b").as_str());
        for t in ["t1", "t2"] {
            for s in [&s1, &s2] {
                s.append_intent(t, &intent("deploy-a", t)).unwrap();
                s.append_intent(t, &intent("deploy-b", t)).unwrap();
            }
        }
        // The s1 arm fires on s1's deploy-a terminal...
        s1.append_terminal(
            "t1",
            &test_deployment_id("deploy-a"),
            &successful_terminal(),
        )
        .expect_err("s1's own arm fires");
        // ...and never leaks into s2 (its deploy-b arm is untouched).
        s2.append_terminal(
            "t1",
            &test_deployment_id("deploy-b"),
            &successful_terminal(),
        )
        .expect_err("s2's own arm fires");
    }

    // ---------------------------------------------------------------------
    // Ledger append durability (crash-atomic whole-ledger rewrite)
    // ---------------------------------------------------------------------

    /// A fault at ANY of the four atomic-append stages leaves the visible
    /// ledger wholly OLD (pre-append) or wholly NEW (post-append): the
    /// atomic rename means no crash window can ever leave a torn partial
    /// line. The pre-rename stages ([`FaultKind::AppendWrite`] /
    /// [`FaultKind::AppendSync`] / [`FaultKind::AppendRename`]) abort
    /// BEFORE the rename: wholly OLD. The [`FaultKind::AppendDirSync`] fault
    /// fires AFTER the rename: the ledger is wholly NEW (only the directory
    /// entry is unsynced) and the append returns `Err`.
    #[test]
    fn ledger_append_faults_leave_wholly_old_or_wholly_new() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        store
            .append_intent(target, &intent("deploy-a", target))
            .unwrap();
        store
            .append_terminal(
                target,
                &test_deployment_id("deploy-a"),
                &successful_terminal(),
            )
            .unwrap();
        for (i, (stage, kind, landed)) in [
            ("temp write", FaultKind::AppendWrite, false),
            ("temp sync", FaultKind::AppendSync, false),
            ("rename", FaultKind::AppendRename, false),
            ("dir sync", FaultKind::AppendDirSync, true),
        ]
        .into_iter()
        .enumerate()
        {
            let id = format!("deploy-fault-{i}");
            store.append_intent(target, &intent(&id, target)).unwrap();
            let before = store.read_ledger_lines(target).unwrap();
            store
                .fault_registry()
                .arm(kind, test_deployment_id(&id).as_str());
            let err = store
                .append_terminal(target, &test_deployment_id(&id), &successful_terminal())
                .expect_err("the armed stage fault fires");
            assert!(
                err.to_string().contains("test fault"),
                "the fault must fail the append, got: {err}"
            );
            let after = store.read_ledger_lines(target).unwrap();
            if landed {
                assert_eq!(
                    after.len(),
                    before.len() + 1,
                    "{stage}: the dir-sync fault leaves the wholly NEW ledger (the rename landed)"
                );
                assert_eq!(
                    after[..before.len()],
                    before,
                    "{stage}: the wholly-new ledger extends the old content in order"
                );
                assert_eq!(
                    after.last().unwrap(),
                    &serde_json::to_string(&LedgerLine::Terminal(LedgerTerminalWire::from_domain(
                        &test_deployment_id(&id),
                        &TargetName::parse(target).expect("target name is a safe segment"),
                        &successful_terminal(),
                    ),))
                    .unwrap(),
                    "{stage}: the wholly-new ledger's last line is the appended terminal"
                );
            } else {
                assert_eq!(
                    after, before,
                    "{stage}: a pre-rename fault leaves the wholly OLD ledger"
                );
            }
            // Every line of the visible ledger parses (never torn).
            store.read_ledger(target).unwrap();
        }
    }

    /// The append-intent guard FAILS CLOSED on a crafted torn trailing line
    /// (a crash from the OLD in-place append protocol): `read_ledger` — the
    /// guard's source of truth — refuses the malformed ledger, so the
    /// append returns the parse error and the file bytes stay EXACTLY the
    /// crafted torn tail: never fused, never appended over, never mutated.
    #[test]
    fn append_guard_fails_closed_on_a_crafted_torn_tail() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        let p = store.ledger_path(target);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        // A crafted torn trailing line — exactly what the old in-place
        // append could leave behind after a crash mid-write.
        let torn = r#"{"kind":"intent","deployment_id":"deploy-torn""#;
        std::fs::write(&p, torn).unwrap();
        // The append fails closed at the guard (the ledger does not parse)
        // and the file bytes are untouched — the corruption is surfaced,
        // never silently fused or amplified.
        let err = store
            .append_intent(target, &intent("deploy-fresh", target))
            .unwrap_err();
        assert!(
            err.to_string().contains("parse ledger line"),
            "the guard must propagate the parse failure, got: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            torn,
            "a refused append must leave the crafted torn ledger byte-identical"
        );
    }

    /// A SUCCESSFUL ledger append is durable: after appends (including an
    /// append that FAILED at the dir-sync stage — the rename already landed
    /// — and one that failed at a pre-rename stage), a FRESH store over the
    /// same base reads exactly the committed lines: every append that
    /// returned `Ok` is visible, in order, and no torn line exists.
    #[test]
    fn successful_ledger_appends_are_visible_after_reopen() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let base = dir.path().join("store");
        let store = LocalStore::with_base(base.clone()).unwrap();
        let target = "t1";
        store
            .append_intent(target, &intent("deploy-a", target))
            .unwrap();
        store
            .append_terminal(
                target,
                &test_deployment_id("deploy-a"),
                &successful_terminal(),
            )
            .unwrap();
        store
            .append_intent(target, &intent("deploy-b", target))
            .unwrap();
        // A pre-rename fault: the intent of deploy-c never lands.
        store
            .fault_registry()
            .arm_append_rename(test_deployment_id("deploy-c").as_str());
        store
            .append_intent(target, &intent("deploy-c", target))
            .expect_err("the armed rename fault aborts before the rename");
        // The dir-sync fault on deploy-d's terminal: the rename DOES land
        // (the ledger is wholly new) though the append returns `Err`.
        store
            .append_intent(target, &intent("deploy-d", target))
            .unwrap();
        store
            .fault_registry()
            .arm_append_dir_sync(test_deployment_id("deploy-d").as_str());
        store
            .append_terminal(
                target,
                &test_deployment_id("deploy-d"),
                &successful_terminal(),
            )
            .expect_err("the armed dir-sync fault still leaves the ledger wholly new");
        drop(store);
        let reopened = LocalStore::with_base(base).unwrap();
        let visible = reopened.read_ledger_lines(target).unwrap();
        assert_eq!(visible.len(), 5);
        assert_eq!(
            visible[0],
            serde_json::to_string(&LedgerLine::Intent(LedgerIntentWire::from(&intent(
                "deploy-a", target
            ))))
            .unwrap()
        );
        assert_eq!(
            visible[1],
            serde_json::to_string(&LedgerLine::Terminal(LedgerTerminalWire::from_domain(
                &test_deployment_id("deploy-a"),
                &TargetName::parse(target).expect("target name is a safe segment"),
                &successful_terminal(),
            )))
            .unwrap()
        );
        assert_eq!(
            visible[2],
            serde_json::to_string(&LedgerLine::Intent(LedgerIntentWire::from(&intent(
                "deploy-b", target
            ))))
            .unwrap()
        );
        assert_eq!(
            visible[3],
            serde_json::to_string(&LedgerLine::Intent(LedgerIntentWire::from(&intent(
                "deploy-d", target
            ))))
            .unwrap()
        );
        assert_eq!(
            visible[4],
            serde_json::to_string(&LedgerLine::Terminal(LedgerTerminalWire::from_domain(
                &test_deployment_id("deploy-d"),
                &TargetName::parse(target).expect("target name is a safe segment"),
                &successful_terminal(),
            )))
            .unwrap()
        );
        // Every line parses and merges into consistent entries.
        let entries = reopened.read_ledger(target).unwrap();
        assert_eq!(entries.len(), 3);
        assert!(
            entries
                .iter()
                .any(|e| e.deployment_id == test_deployment_id("deploy-a") && e.terminal.is_some())
        );
        assert!(
            entries
                .iter()
                .any(|e| e.deployment_id == test_deployment_id("deploy-b") && e.terminal.is_none())
        );
        assert!(
            entries
                .iter()
                .any(|e| e.deployment_id == test_deployment_id("deploy-d") && e.terminal.is_some())
        );
    }

    // ---- the reopen durability property -------------------------------

    /// One generated ledger-history operation: the INTENT of a fresh
    /// deployment (`Intent`), the terminal of the OLDEST still-open
    /// deployment (`CloseOldest`), or the NEWEST (`CloseNewest`). The paired
    /// [`AppendStage`] selects the single atomic-append stage fault armed for
    /// that operation (`None` = no fault).
    #[derive(Clone, Copy, Debug)]
    enum LedgerOp {
        Intent,
        CloseOldest,
        CloseNewest,
    }

    /// The four atomic-append rewrite stages a fault can be injected at.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum AppendStage {
        Write,
        Sync,
        Rename,
        DirSync,
    }

    fn ledger_history_strategy() -> impl Strategy<Value = Vec<(LedgerOp, Option<AppendStage>)>> {
        prop::collection::vec(
            (
                prop::sample::select(vec![
                    LedgerOp::Intent,
                    LedgerOp::CloseOldest,
                    LedgerOp::CloseNewest,
                ]),
                prop::sample::select(vec![
                    None,
                    Some(AppendStage::Write),
                    Some(AppendStage::Sync),
                    Some(AppendStage::Rename),
                    Some(AppendStage::DirSync),
                ]),
            ),
            0..=6,
        )
    }

    /// Arm the generated stage fault on the fixture's per-fixture registry,
    /// keyed by the deployment id of the append under test.
    fn arm_append_stage(store: &LocalStore, stage: AppendStage, id: &str) {
        let canonical = test_deployment_id(id);
        match stage {
            AppendStage::Write => store.fault_registry().arm_append_write(canonical.as_str()),
            AppendStage::Sync => store.fault_registry().arm_append_sync(canonical.as_str()),
            AppendStage::Rename => store.fault_registry().arm_append_rename(canonical.as_str()),
            AppendStage::DirSync => store
                .fault_registry()
                .arm_append_dir_sync(canonical.as_str()),
        }
    }

    /// Replay one generated history against a FRESH fixture, then REOPEN
    /// with a fresh store over the same base and assert the durability
    /// contract:
    ///
    /// * the reopened ledger is EXACTLY the lines of the appends whose
    ///   atomic rename LANDED, in order — a whole file of whole lines: no
    ///   append can leave a torn/partial line, every line parses, and the
    ///   intent/terminal structure is consistent;
    /// * a SUCCESSFUL append (one that returned `Ok`) is ALWAYS present
    ///   after the reopen, regardless of what failed afterward.
    ///
    /// Each operation arms ONE stage fault (keyed by the deployment id)
    /// when its generated spec says so. The fault fires once at that stage:
    /// `Write`/`Sync`/`Rename` abort before the rename (wholly OLD);
    /// [`AppendStage::DirSync`] fires after the rename (wholly NEW — the
    /// error returns but the new ledger is already durable).
    fn run_ledger_durability_history(history: &[(LedgerOp, Option<AppendStage>)]) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let base = dir.path().join("store");
        let store = LocalStore::with_base(base.clone()).unwrap();
        let target = "t1";
        // The committed model: the ledger lines whose append's rename
        // landed, in order; the still-open (intent-only) deployment ids; and
        // every append that returned `Ok` (the visibility contract).
        let mut committed: Vec<String> = Vec::new();
        let mut open: Vec<String> = Vec::new();
        let mut ok_appends: Vec<(String, bool)> = Vec::new();
        let mut seq = 0u64;
        for (op, stage) in history {
            match op {
                LedgerOp::Intent => {
                    let id = format!("dep-{seq}");
                    seq += 1;
                    let intent = intent(&id, target);
                    let line = serde_json::to_string(&LedgerLine::Intent(LedgerIntentWire::from(
                        &intent.clone(),
                    )))
                    .unwrap();
                    if let Some(stage) = stage {
                        arm_append_stage(&store, *stage, &id);
                    }
                    match store.append_intent(target, &intent) {
                        Ok(()) => {
                            committed.push(line);
                            open.push(id.clone());
                            ok_appends.push((id, true));
                        }
                        Err(e) if e.to_string().contains("test fault") => {
                            // The faulted append: committed ONLY when the
                            // rename already landed (the dir-sync stage).
                            if matches!(stage, Some(AppendStage::DirSync)) {
                                committed.push(line);
                                open.push(id);
                            }
                        }
                        Err(e) => panic!("unexpected append_intent error for {id}: {e}"),
                    }
                }
                LedgerOp::CloseOldest | LedgerOp::CloseNewest => {
                    let Some(id) = (if matches!(op, LedgerOp::CloseOldest) {
                        open.first()
                    } else {
                        open.last()
                    })
                    .cloned() else {
                        continue; // nothing open: the op is a valid no-op
                    };
                    let terminal = successful_terminal();
                    let deployment_id = test_deployment_id(&id);
                    let line = serde_json::to_string(&LedgerLine::Terminal(
                        LedgerTerminalWire::from_domain(
                            &deployment_id,
                            &TargetName::parse(target).expect("target name is a safe segment"),
                            &terminal,
                        ),
                    ))
                    .unwrap();
                    if let Some(stage) = stage {
                        arm_append_stage(&store, *stage, &id);
                    }
                    match store.append_terminal(target, &deployment_id, &terminal) {
                        Ok(()) => {
                            committed.push(line);
                            open.retain(|o| o != &id);
                            ok_appends.push((id, false));
                        }
                        Err(e) if e.to_string().contains("test fault") => {
                            if matches!(stage, Some(AppendStage::DirSync)) {
                                committed.push(line);
                                open.retain(|o| o != &id);
                            }
                        }
                        Err(e) => panic!("unexpected append_terminal error for {id}: {e}"),
                    }
                }
            }
        }
        // After REOPENING, the ledger is the wholly-written committed model:
        // never a torn line, and the successful appends are all visible.
        drop(store);
        let reopened = LocalStore::with_base(base).unwrap();
        assert_eq!(
            reopened.read_ledger_lines(target).unwrap(),
            committed,
            "the reopened ledger is exactly the committed lines in order — every append is whole or absent, never torn"
        );
        let entries = reopened.read_ledger(target).unwrap();
        for (id, is_intent) in &ok_appends {
            let entry = entries
                .iter()
                .find(|e| e.deployment_id.as_str() == test_deployment_id(id).as_str())
                .unwrap_or_else(|| panic!("a successful append for {id} is missing after reopen"));
            if !is_intent {
                assert!(
                    entry.terminal.is_some(),
                    "a successful terminal append for {id} is visible after reopen"
                );
            }
        }
    }

    // ---- the first-append durable dir-creation (the reported bug) ------

    /// The reported durability bug: the FIRST `append_intent` for a NEW target
    /// created `targets/<target>/` — and the store open's `targets/` — WITHOUT
    /// syncing their directory entries, so a power loss right after a
    /// reported-successful first append could lose the new directories
    /// entirely (crash recovery would find NEITHER the new ledger NOR the
    /// prior state). The fix routes the append path through
    /// [`crate::store::atomic::ensure_private_dir_durable`]: every directory
    /// entry the creation makes is fsynced before the ledger write. This test
    /// pins the boundary contract per sync: with EACH of the two dir-sync
    /// faults armed (and both), the first append reports `Err` and crash
    /// recovery finds the PRIOR STATE — the target directory exists (created
    /// before the sync boundary) but no ledger was written — and the
    /// prior-state case then re-appends cleanly on the same base. With no
    /// fault, the append reports success and the complete new ledger is
    /// retained.
    #[test]
    fn first_append_dir_sync_fault_leaves_prior_state_or_full_durable() {
        let cases: &[&[FaultKind]] = &[
            &[],
            &[FaultKind::SyncNewTargetDir],
            &[FaultKind::SyncTargetsDir],
            &[FaultKind::SyncNewTargetDir, FaultKind::SyncTargetsDir],
        ];
        for kinds in cases {
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let base = dir.path().join("store");
            let store = LocalStore::with_base(base.clone()).unwrap();
            let target = "t1";
            for kind in *kinds {
                store.fault_registry().arm(*kind, target);
            }
            let result = store.append_intent(target, &intent("dep-x", target));
            drop(store);
            let reopened = LocalStore::with_base(base.clone()).unwrap();
            assert!(
                reopened.target_dir(target).exists(),
                "the first append creates the target dir BEFORE any sync — it is never missing (kinds: {kinds:?})"
            );
            let entries = reopened.read_ledger(target).unwrap();
            if kinds.is_empty() {
                assert!(result.is_ok(), "an un-faulted first append reports success");
                assert_eq!(
                    entries.len(),
                    1,
                    "a reported success retains the complete new ledger"
                );
            } else {
                assert!(
                    result.is_err(),
                    "a faulted dir-sync must fail the first append (kinds: {kinds:?})"
                );
                assert!(
                    entries.is_empty(),
                    "a faulted dir-sync leaves the PRIOR STATE — the append did not commit (kinds: {kinds:?})"
                );
                // The prior-state case re-appends cleanly (crash recovery +
                // retry over the same base).
                let store2 = LocalStore::with_base(base.clone()).unwrap();
                store2
                    .append_intent(target, &intent("dep-x", target))
                    .unwrap();
                assert_eq!(
                    store2.read_ledger(target).unwrap().len(),
                    1,
                    "the prior-state case re-appends cleanly"
                );
            }
        }
    }

    /// Run one model case of the first-append dir-sync property: a fresh
    /// fixture, optionally pre-seeded as an EXISTING target (its dir + first
    /// ledger entry already written), with the per-target dir-sync faults
    /// armed per the vector; then ONE `append_intent`, a fresh-store reopen
    /// over the same base, and the coherent-state assertions:
    ///
    /// * the target directory is NEVER missing after a reported success;
    /// * an EXISTING target's append creates no directory, so the dir-sync
    ///   arms never fire — the append reports success and retains the new
    ///   entry;
    /// * a FIRST target's faulted sync returns `Err` and recovery finds the
    ///   PRIOR STATE (the dir was created, no ledger — the append did not
    ///   commit);
    /// * a FIRST target's un-faulted append reports success and recovery
    ///   retains the complete new ledger.
    fn run_first_append_dir_sync_model(
        existing_target: bool,
        sync_new_target_dir: bool,
        sync_targets_dir: bool,
    ) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let base = dir.path().join("store");
        let store = LocalStore::with_base(base.clone()).unwrap();
        let target = "t1";
        if existing_target {
            // The EXISTING-target model: the target dir and a first ledger
            // entry exist before the append under test.
            store
                .append_intent(target, &intent("dep-0", target))
                .unwrap();
        }
        if sync_new_target_dir {
            store.fault_registry().arm_sync_new_target_dir(target);
        }
        if sync_targets_dir {
            store.fault_registry().arm_sync_targets_dir(target);
        }
        let id = if existing_target { "dep-1" } else { "dep-0" };
        let result = store.append_intent(target, &intent(id, target));
        drop(store);
        let reopened = LocalStore::with_base(base.clone()).unwrap();
        assert!(
            reopened.target_dir(target).exists(),
            "the target directory is never missing (existing={existing_target}, new_target_sync={sync_new_target_dir}, targets_sync={sync_targets_dir})"
        );
        let entries = reopened.read_ledger(target).unwrap();
        if existing_target {
            // No durable creation happens (the dir exists): the dir-sync
            // arms cannot fire, the append reports success and the new
            // entry is retained beside the seeded one.
            assert!(
                result.is_ok(),
                "an existing target's append creates no dir, so the dir-sync arms never fire (sync_new={sync_new_target_dir}, sync_targets={sync_targets_dir})"
            );
            assert_eq!(entries.len(), 2);
            assert!(
                entries
                    .iter()
                    .any(|e| e.deployment_id.as_str() == test_deployment_id(id).as_str())
            );
        } else if sync_new_target_dir || sync_targets_dir {
            // A FIRST target with a faulted dir-sync boundary: the append
            // reports `Err` and recovery finds the prior state — the target
            // dir exists (created before the boundary), but the append did
            // not commit, so the ledger is absent.
            assert!(
                result.is_err(),
                "a faulted dir-sync must fail the first append"
            );
            assert!(
                entries.is_empty(),
                "a faulted first append did not commit — no ledger"
            );
            // The prior-state case re-appends cleanly on the same base.
            let store2 = LocalStore::with_base(base.clone()).unwrap();
            store2.append_intent(target, &intent(id, target)).unwrap();
            assert!(
                store2
                    .read_ledger(target)
                    .unwrap()
                    .iter()
                    .any(|e| e.deployment_id.as_str() == test_deployment_id(id).as_str())
            );
        } else {
            // A REPORTED SUCCESS for the first append: recovery retains the
            // complete new ledger and the target directory is present.
            assert!(result.is_ok(), "an un-faulted first append reports success");
            assert_eq!(entries.len(), 1);
            assert!(
                entries
                    .iter()
                    .any(|e| e.deployment_id.as_str() == test_deployment_id(id).as_str())
            );
        }
    }

    proptest! {
        // The main property split into PARALLEL SUBTESTS: the harness runs
        // each test in its own thread, but proptest runs a test's cases
        // sequentially in that one thread — so the randomized-with-
        // persistence leg (8 cases) is SPLIT into four subtests of
        // `cases: 8/4 = 2` each with DISTINCT FIXED seeds. The four
        // subtests run concurrently on different harness threads, dividing
        // this leg's wall time, while the fixed seeds keep every subtest
        // deterministic (CI-reproducible). FAILURE PERSISTENCE stays on
        // THIS subtest only: the shared `proptest-regressions/local.txt`
        // is keyed per source FILE, so every subtest with persistence
        // would replay ALL persisted vectors — duplicating the replay K
        // times — so only `_0` carries the persistence (any persisted
        // vectors replay exactly once, in `_0`), while `_1`..`_3` run the
        // same generator + assertions under their fixed seeds. The
        // deterministic fixed-seed leg below stays ONE test (the
        // deterministic floor).
        #![proptest_config(ProptestConfig {
            cases: 2,
            rng_seed: RngSeed::Fixed(0x5EED_0011),
            failure_persistence: Some(Box::new(FileFailurePersistence::default())),
            ..ProptestConfig::default()
        })]

        #[test]
        fn ledger_append_durability_0(history in ledger_history_strategy()) {
            run_ledger_durability_history(&history);
        }
    }

    proptest! {
        // The second slice of the split randomized leg: the same generator
        // + assertions under a DISTINCT fixed seed (deterministic; no
        // persistence — the fixed seed makes any failure reproducible).
        #![proptest_config(ProptestConfig {
            cases: 2,
            rng_seed: RngSeed::Fixed(0x5EED_0012),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn ledger_append_durability_1(history in ledger_history_strategy()) {
            run_ledger_durability_history(&history);
        }
    }

    proptest! {
        // The third slice of the split randomized ledger, distinct seed.
        #![proptest_config(ProptestConfig {
            cases: 2,
            rng_seed: RngSeed::Fixed(0x5EED_0013),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn ledger_append_durability_2(history in ledger_history_strategy()) {
            run_ledger_durability_history(&history);
        }
    }

    proptest! {
        // The fourth slice of the split randomized ledger, distinct seed.
        #![proptest_config(ProptestConfig {
            cases: 2,
            rng_seed: RngSeed::Fixed(0x5EED_0014),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn ledger_append_durability_3(history in ledger_history_strategy()) {
            run_ledger_durability_history(&history);
        }
    }

    proptest! {
        // FIXED-SEED REGRESSION: the deterministic floor for CI. The same
        // generator under the pinned 0x5EED_5EED seed with no persistence
        // runs the IDENTICAL vectors on every invocation, so the suite stays
        // reproducible even when no failure has ever been persisted by the
        // main test. The case count is bounded so the suite stays fast.
        #![proptest_config(ProptestConfig {
            cases: 4,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn ledger_append_durability_fixed_seed_regression(history in ledger_history_strategy()) {
            run_ledger_durability_history(&history);
        }
    }

    proptest! {
        // FIXED-SEED PROPERTY for the FIRST-append durable dir-creation
        // (the reported bug): model FIRST vs EXISTING targets with a fault
        // at each dir-sync boundary. A REPORTED SUCCESS must imply that
        // crash recovery (a fresh store over the same base) retains the
        // complete new ledger with the target directory present — NEVER a
        // missing target directory after a reported success; a faulted
        // sync returns `Err` (prior state: the target dir was created, no
        // ledger — the append did not commit) and the prior-state case
        // re-appends cleanly. EXISTING targets create nothing (the durable
        // helper's fast path), so their dir-sync arms never fire and the
        // append always reports success. The pinned 0x5EED_5EED seed with
        // no persistence runs the IDENTICAL 16 vectors on every invocation;
        // the case count is bounded so the suite stays fast.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn first_append_dir_sync_durability(
            (existing, sync_new, sync_targets) in (any::<bool>(), any::<bool>(), any::<bool>()),
        ) {
            run_first_append_dir_sync_model(existing, sync_new, sync_targets);
        }
    }

    // ---- the lock-path target-dir creation (the reported lock bypass) --

    /// The crashable boundary of the COMPLETE first-push sequence — store
    /// open → target lock acquisition → intent append — that the property
    /// below injects a fault at. The lock-path mkdir boundary
    /// ([`LockPathBoundary::LockMkdir`]) and the two durable dir-sync
    /// boundaries ([`LockPathBoundary::SyncNewTargetDir`] /
    /// [`LockPathBoundary::SyncTargetsDir`]) fire on the target-dir creation
    /// the engine/checkpoint run BEFORE the target lock; the four atomic-
    /// append stage boundaries fire on the ledger write inside the append.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum LockPathBoundary {
        /// No fault: the sequence reports success.
        None,
        /// The LOCK-PATH mkdir step: the durable pre-creation crashes
        /// before it creates anything — recovery finds NO target directory
        /// (a first target) and no ledger.
        LockMkdir,
        /// The sync of the NEW TARGET DIR's entry (`targets/`), on the
        /// lock-path pre-creation: the dir exists, no ledger.
        SyncNewTargetDir,
        /// The sync of `targets/`'s OWN entry (the store base), on the
        /// lock-path pre-creation: the dir exists, no ledger.
        SyncTargetsDir,
        /// The ledger append's TEMP-WRITE stage: the visible ledger is
        /// wholly prior.
        AppendWrite,
        /// The ledger append's TEMP-SYNC stage: wholly prior.
        AppendSync,
        /// The ledger append's RENAME stage: wholly prior.
        AppendRename,
        /// The ledger append's PARENT-DIR-SYNC stage: the rename already
        /// landed — the ledger is wholly new, though the append returns
        /// `Err`.
        AppendDirSync,
    }

    /// The eight crash boundaries of the complete sequence, for the
    /// deterministic unit test and the fixed-seed property generator.
    fn lock_path_boundaries() -> Vec<LockPathBoundary> {
        vec![
            LockPathBoundary::None,
            LockPathBoundary::LockMkdir,
            LockPathBoundary::SyncNewTargetDir,
            LockPathBoundary::SyncTargetsDir,
            LockPathBoundary::AppendWrite,
            LockPathBoundary::AppendSync,
            LockPathBoundary::AppendRename,
            LockPathBoundary::AppendDirSync,
        ]
    }

    /// Run one model case of the lock-path durability property: a fresh
    /// fixture, optionally pre-seeded as an EXISTING target (its dir + first
    /// ledger entry already written), with the boundary fault armed per the
    /// spec; then the COMPLETE SEQUENCE — store open, the durable target-dir
    /// pre-creation + target lock acquisition exactly as the engine's lock
    /// block runs it ([`crate::deploy::push`]: local lock, then
    /// `ensure_target_dir_durable`, then the target lock), then the intent
    /// append — a fresh-store reopen over the same base, and the durability
    /// contract:
    ///
    /// * a REPORTED SUCCESS recovers with the COMPLETE ledger AND the target
    ///   directory present — never a missing target directory after an `Ok`;
    /// * a faulted boundary returns `Err` and recovery finds the PRIOR
    ///   STATE: the `LockMkdir` crash leaves NO target dir (the pre-creation
    ///   never ran, for a first target); every later boundary leaves the
    ///   target dir present with the prior ledger (or the wholly-new
    ///   committed ledger when the append's rename already landed);
    /// * the prior-state cases re-append cleanly on the same base (the
    ///   landed dir-sync case is fail-closed: the recovered ledger already
    ///   holds the entry and the duplicate guard refuses the replay).
    fn run_lock_path_durability_model(existing: bool, boundary: LockPathBoundary) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let base = dir.path().join("store");
        let store = LocalStore::with_base(base.clone()).unwrap(); // store open
        let target = "t1";
        if existing {
            store
                .append_intent(target, &intent("dep-0", target))
                .unwrap();
        }
        let id = if existing { "dep-1" } else { "dep-0" };
        // Arm the boundary fault: the dir-creation kinds key by target (the
        // lock-path pre-creation and the append's `ensure_target_dir_durable`
        // consume them); the append-stage kinds key by deployment id.
        match boundary {
            LockPathBoundary::None => {}
            LockPathBoundary::LockMkdir => store.fault_registry().arm_lock_mkdir(target),
            LockPathBoundary::SyncNewTargetDir => {
                store.fault_registry().arm_sync_new_target_dir(target)
            }
            LockPathBoundary::SyncTargetsDir => store.fault_registry().arm_sync_targets_dir(target),
            LockPathBoundary::AppendWrite => store.fault_registry().arm_append_write(id),
            LockPathBoundary::AppendSync => store.fault_registry().arm_append_sync(id),
            LockPathBoundary::AppendRename => store.fault_registry().arm_append_rename(id),
            LockPathBoundary::AppendDirSync => store.fault_registry().arm_append_dir_sync(id),
        }
        // THE COMPLETE SEQUENCE: store open → target lock acquisition →
        // intent append, mirroring the engine's lock block exactly (local
        // store lock first, then the durable target-dir pre-creation, then
        // the target lock, then the append).
        let result = (|| -> Result<()> {
            let local = FileLock::acquire(&store.base().join("operation.lock"), "op-1")?;
            store.ensure_target_dir_durable(target)?;
            let target_lock =
                FileLock::acquire(&store.target_dir(target).join("operation.lock"), "op-1")?;
            store.append_intent(target, &intent(id, target))?;
            drop(target_lock);
            drop(local);
            Ok(())
        })();
        drop(store);
        let reopened = LocalStore::with_base(base.clone()).unwrap();
        let entries = reopened.read_ledger(target).unwrap();
        let id_present = entries
            .iter()
            .any(|e| e.deployment_id.as_str() == test_deployment_id(id).as_str());
        if result.is_ok() {
            assert!(
                reopened.target_dir(target).exists(),
                "a reported success never loses the target directory (existing={existing}, boundary={boundary:?})"
            );
            assert!(
                id_present,
                "a reported success always retains the complete ledger (existing={existing}, boundary={boundary:?})"
            );
        } else {
            // The faulted boundary's contract, per crash point.
            match boundary {
                LockPathBoundary::LockMkdir => {
                    // The crash hit BEFORE the durable helper created
                    // anything: a FIRST target recovers with NO target
                    // directory; an existing one keeps its pre-existing dir.
                    // Either way the ledger is the prior one.
                    if existing {
                        assert!(reopened.target_dir(target).exists());
                        assert_eq!(entries.len(), 1, "the prior ledger is intact");
                    } else {
                        assert!(
                            !reopened.target_dir(target).exists(),
                            "the crashed lock-path mkdir leaves NO target dir (boundary={boundary:?})"
                        );
                        assert!(entries.is_empty());
                    }
                }
                LockPathBoundary::AppendDirSync => {
                    // The append's rename already landed: the ledger is
                    // wholly NEW (the committed entry is present) even
                    // though the append reported `Err`.
                    assert!(reopened.target_dir(target).exists());
                    assert!(id_present, "the landed rename is wholly new");
                }
                _ => {
                    // A dir-sync or pre-rename boundary: the target dir was
                    // durably created before any crashable boundary (present)
                    // and the ledger is the PRIOR one (the append did not
                    // commit).
                    assert!(reopened.target_dir(target).exists());
                    assert!(!id_present, "the append did not commit ({boundary:?})");
                }
            }
            // A faulted step recovers to a re-appendable state: a fresh
            // store over the same base re-appends the same intent cleanly
            // when the entry did not land; when the rename already landed
            // (dir-sync), the recovered ledger already holds the entry and
            // the fail-closed duplicate guard refuses the replay.
            let retry = LocalStore::with_base(base.clone()).unwrap();
            if id_present {
                let err = retry
                    .append_intent(target, &intent(id, target))
                    .unwrap_err();
                assert!(
                    err.to_string().contains("second intent"),
                    "a landed entry is fail-closed against a duplicate replay ({boundary:?})"
                );
            } else {
                retry.append_intent(target, &intent(id, target)).unwrap();
                assert!(
                    retry
                        .read_ledger(target)
                        .unwrap()
                        .iter()
                        .any(|e| e.deployment_id.as_str() == test_deployment_id(id).as_str())
                );
            }
        }
    }

    /// The DETERMINISTIC unit test of the complete sequence: every crash
    /// boundary faulted, on a first AND an existing target. This is the exact
    /// sequence the reported bug bypassed — store open → target lock
    /// acquisition → intent append — with each boundary faulted in turn, and
    /// the durability contract above (a reported success recovers with the
    /// complete ledger AND the target directory present; a faulted step
    /// returns `Err` with the prior state; a retry re-appends cleanly).
    #[test]
    fn lock_path_dir_creation_each_boundary_faulted() {
        for existing in [false, true] {
            for boundary in lock_path_boundaries() {
                run_lock_path_durability_model(existing, boundary);
            }
        }
    }

    proptest! {
        // FIXED-SEED PROPERTY for the lock-path target-dir creation (the
        // reported bug): the COMPLETE sequence — store open → target lock
        // acquisition → intent append — is faulted at EVERY mkdir / fsync /
        // rename boundary (the durable-dir kinds
        // [`FaultKind::SyncNewTargetDir`] / [`FaultKind::SyncTargetsDir`], the
        // lock-path mkdir kind [`FaultKind::LockMkdir`], and the four
        // atomic-append stages), on first AND existing targets. Every
        // REPORTED SUCCESS must recover (a fresh store over the same base)
        // with the COMPLETE ledger AND the target directory present — NEVER a
        // missing target directory after a reported success; a faulted step
        // returns `Err` with the prior state (no target dir or the prior
        // ledger) and a retry re-appends cleanly. The pinned 0x5EED_5EED seed
        // with no persistence runs the IDENTICAL vectors on every invocation;
        // the case count is bounded so the suite stays fast.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn lock_path_dir_creation_durability(
            (existing, boundary) in (any::<bool>(), prop::sample::select(lock_path_boundaries())),
        ) {
            run_lock_path_durability_model(existing, boundary);
        }
    }

    // ---- the duplicate-intent guard property ---------------------------

    /// Generate a NONEMPTY deployment sequence of UNIQUE ids (`dep-0` ..
    /// `dep-{N-1}`, the ledger's N intents) together with a position in
    /// `0..=N`: an IN-ledger position (`0` = first, middles, `N-1` = last)
    /// or the position JUST BEYOND the last entry (`N`). The ids are unique
    /// by construction (derived from distinct indices).
    fn unique_ledger_strategy() -> impl Strategy<Value = (Vec<String>, usize)> {
        (1usize..=4, 0usize..=4)
            .prop_map(|(n, pos)| ((0..n).map(|i| format!("dep-{i}")).collect(), pos.min(n)))
    }

    proptest! {
        // FIXED-SEED REGRESSION for the duplicate guard: the guard must
        // scan EVERY parsed ledger entry, so re-appending the id of ANY
        // in-ledger position (first, middle, last) is refused and the ledger
        // file BYTES are EXACTLY unchanged (no torn/partial append, no
        // mutation). The id JUST BEYOND the last entry — a genuinely fresh
        // id — still appends one whole line; appending it AGAIN is then a
        // duplicate and is refused with bytes unchanged. The pinned
        // 0x5EED_5EED seed with no persistence runs the IDENTICAL vectors on
        // every invocation; the case count is bounded so the suite stays
        // fast.
        #![proptest_config(ProptestConfig {
            cases: 4,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn duplicate_intent_scan_leaves_ledger_bytes_unchanged(ledger in unique_ledger_strategy()) {
            let (ids, pos) = ledger;
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let store = LocalStore::with_base(dir.path().join("store")).unwrap();
            let target = "t1";
            for id in &ids {
                store.append_intent(target, &intent(id, target)).unwrap();
            }
            let p = store.ledger_path(target);
            let before = std::fs::read(&p).unwrap();
            if pos == ids.len() {
                // The position JUST BEYOND the last entry: the fresh id is
                // not in the ledger, so the first append SUCCEEDS — one
                // whole line appended after the existing newline-terminated
                // content (atomic, never torn) — proving the every-entry
                // scan does not over-reject a new id.
                let fresh = format!("dep-{}", ids.len());
                let line =
                    serde_json::to_string(&LedgerLine::Intent(LedgerIntentWire::from(&intent(
                        &fresh, target,
                    ))))
                    .unwrap();
                store.append_intent(target, &intent(&fresh, target)).unwrap();
                let mut after = before.clone();
                after.extend_from_slice(format!("{line}\n").as_bytes());
                assert_eq!(
                    std::fs::read(&p).unwrap(),
                    after,
                    "a fresh id appends exactly one whole line, never torn"
                );
                // Appending the fresh id AGAIN is now a duplicate at the NEW
                // last position: refused, bytes unchanged.
                let err = store
                    .append_intent(target, &intent(&fresh, target))
                    .unwrap_err();
                assert!(err.to_string().contains("second intent"));
                assert_eq!(std::fs::read(&p).unwrap(), after);
            } else {
                // An IN-ledger position (first, any middle, last): the id is
                // a duplicate — the append must FAIL and leave the ledger
                // bytes IDENTICAL (no torn/partial append, no mutation).
                let err = store
                    .append_intent(target, &intent(&ids[pos], target))
                    .unwrap_err();
                assert!(err.to_string().contains("second intent"));
                assert_eq!(
                    std::fs::read(&p).unwrap(),
                    before,
                    "a refused duplicate must leave the ledger bytes untouched"
                );
            }
        }
    }

    // ---- terminal cross-field / cross-record invariants -------------------

    /// A canonical generation ref whose assignment names its own map key.
    fn gen_ref(slot: &SlotId) -> GenerationRef {
        GenerationRef {
            generation: test_generation_id(slot.as_str()),
            assignment: PlacementSlotAssignment {
                placement_slot: slot.clone(),
                artifact: ArtifactRef {
                    release: crate::identity::test_release_id(slot.as_str()),
                    variant: VariantName::new("standard".to_string()),
                    tree: test_tree_digest(slot.as_str()),
                },
            },
        }
    }

    /// A binding for a slot (server `s1`, the canonical deploy dir).
    fn binding_for(slot: &SlotId) -> PhysicalBinding {
        PhysicalBinding {
            server: ServerId::new("s1".to_string()),
            deploy_dir: format!("/srv/eng/{}", slot.as_str()),
        }
    }

    /// An EXACT intent (the domain's ONE slot table — the membership AND
    /// the desired/pre-push entries are the same [`NonEmptySlotTable`], so
    /// the exact-key-set invariant is STRUCTURAL): `slot_count` members,
    /// every member desired + pre-push.
    fn exact_intent(id: &str, target: &str, slot_count: u32) -> DeploymentIntent {
        let slot_ids: Vec<SlotId> = (0..slot_count)
            .map(|i| SlotId::new(format!("slot-{i}")))
            .collect();
        let slots: Vec<(SlotId, IntentSlot)> = slot_ids
            .iter()
            .map(|k| {
                (
                    k.clone(),
                    IntentSlot {
                        desired: DesiredGeneration {
                            generation: test_generation_id(k.as_str()),
                            artifact: ArtifactRef {
                                release: crate::identity::test_release_id(k.as_str()),
                                variant: VariantName::new("standard".to_string()),
                                tree: test_tree_digest(k.as_str()),
                            },
                        },
                        pre_push: Some(PreviousGeneration {
                            artifact: Observation::Known(ArtifactRef {
                                release: crate::identity::test_release_id(k.as_str()),
                                variant: VariantName::new("standard".to_string()),
                                tree: test_tree_digest(k.as_str()),
                            }),
                            generation: Some(test_generation_id("0")),
                        }),
                        // The FROZEN plan-time physical binding (schema v6)
                        // — the fixture's canonical binding for the slot.
                        binding: binding_for(k),
                    },
                )
            })
            .collect();
        DeploymentIntent {
            deployment_id: test_deployment_id(id),
            target: TargetName::parse(target).expect("target name is a safe segment"),
            group: None,
            behavior_sha256: "sha256-pair".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            slots: NonEmptySlotTable::build(slots)
                .expect("a seeded deployment always has at least one slot"),
            full_membership: slot_ids.iter().cloned().collect(),
        }
    }

    /// The terminal for an attempt: FULL per-slot outcomes (every member
    /// slot has one outcome, each value naming its own key) and — when
    /// `successful` — a `Successful` disposition carrying the ACTIVATED
    /// SLOT-ID SET (the per-slot facts are DERIVED from the rollback, never
    /// stored/trusted separately) and a rollback whose bindings key its
    /// slotted generations EXACTLY; otherwise a `FailedRolledBack`
    /// disposition carrying the outcome table as its compensation report.
    fn terminal_for_intent(
        intent: &DeploymentIntent,
        id: &str,
        successful: bool,
    ) -> LedgerTerminal {
        let outcomes: BTreeMap<SlotId, SlotOutcome> = intent
            .slots
            .keys()
            .cloned()
            .map(|k| {
                (
                    k,
                    SlotOutcome {
                        outcome: SlotOutcomeKind::Activated,
                        observation: Observation::Known(ObservedGeneration {
                            generation: test_generation_id(id),
                        }),
                        compensated: false,
                        error: None,
                        transition: SlotTransition::Advanced,
                    },
                )
            })
            .collect();
        let outcomes = SlotTable::from_map(outcomes);
        // THE EXACT-EQUAL MEMBERSHIPS: activated == full == the intent's
        // membership (the rollback's slots) — the proven shape the
        // conversion + read require (valid in BOTH modes: a group intent's
        // activated == full is a legal subset).
        let membership: BTreeSet<SlotId> = intent.slots.keys().cloned().collect();
        let disposition = if successful {
            let rollback = {
                let __slots: BTreeMap<crate::identity::SlotId, crate::identity::GenerationRef> =
                    intent
                        .slots
                        .keys()
                        .map(|k| (k.clone(), gen_ref(k)))
                        .collect();
                let __bindings: BTreeMap<
                    crate::identity::SlotId,
                    crate::ledger::records::PhysicalBinding,
                > = intent
                    .slots
                    .keys()
                    .map(|k| (k.clone(), binding_for(k)))
                    .collect();
                let mut __entries: BTreeMap<
                    crate::identity::SlotId,
                    crate::ledger::records::SnapshotEntry,
                > = BTreeMap::new();
                for (k, v) in __slots.clone() {
                    let b = __bindings.get(&k).cloned().unwrap_or(
                        crate::ledger::records::PhysicalBinding {
                            server: crate::identity::ServerId::new("s1"),
                            deploy_dir: format!("/srv/deploy/{}", k.as_str()),
                        },
                    );
                    __entries.insert(
                        k.clone(),
                        crate::ledger::records::SnapshotEntry::new(
                            v.generation.clone(),
                            v.assignment.artifact.clone(),
                            b,
                        ),
                    );
                }
                for (k, b) in __bindings.clone() {
                    __entries.entry(k.clone()).or_insert_with(|| {
                        crate::ledger::records::SnapshotEntry::new(
                            crate::identity::GenerationId::new("gen-missing".to_string()),
                            crate::identity::ArtifactRef {
                                release: crate::identity::test_release_id("rel-missing"),
                                variant: crate::identity::VariantName::new("standard".to_string()),
                                tree: crate::identity::test_tree_digest("missing"),
                            },
                            b.clone(),
                        )
                    });
                }
                TargetSnapshot::from_entries(__entries)
            };
            let activated = crate::identity::NonEmptySlotSet::try_new(membership.clone()).unwrap();
            TerminalDisposition::Successful(
                crate::ledger::SuccessfulTerminal::try_new(rollback, activated, membership.clone())
                    .unwrap(),
            )
        } else {
            TerminalDisposition::FailedRolledBack { outcomes }
        };
        LedgerTerminal {
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
            disposition,
            reason: None,
        }
    }

    /// Append a valid pair (intent + terminal) to a fresh ledger. The
    /// terminal's wire identity (deployment id / target) comes from the
    /// ENTRY (the append path supplies the intent's identity — the domain
    /// terminal carries none).
    fn append_pair(
        store: &LocalStore,
        target: &str,
        intent: &DeploymentIntent,
        terminal: &LedgerTerminal,
    ) {
        store.append_intent(target, intent).unwrap();
        store
            .append_terminal(target, &intent.deployment_id, terminal)
            .unwrap();
    }

    /// Write an intent + terminal WIRE pair directly to the ledger file: the
    /// append API only accepts DOMAIN objects, so wire-level violations that
    /// are UNREPRESENTABLE in the domain (the status→disposition truth
    /// table, the terminal's wire target) are crafted at the wire and must
    /// still be refused by the read path.
    fn write_wire_pair(
        store: &LocalStore,
        target: &str,
        intent: &LedgerIntentWire,
        terminal: &LedgerTerminalWire,
    ) {
        let p = store.ledger_path(target);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let line1 = serde_json::to_string(&LedgerLine::Intent(intent.clone())).unwrap();
        let line2 = serde_json::to_string(&LedgerLine::Terminal(terminal.clone())).unwrap();
        std::fs::write(&p, format!("{line1}\n{line2}\n")).unwrap();
    }

    /// The minimal project config the consumer checks need (the GC
    /// reachability scan reads `config.pins` — an empty pin set here). One
    /// config per test case; every store of the case reuses it.
    fn consumer_config(base: &std::path::Path) -> ProjectConfig {
        let project = base.join("proj");
        std::fs::create_dir_all(project.join("releases").join("v1")).unwrap();
        std::fs::write(
            project.join("releases").join("v1").join("standard.toml"),
            "[artifact]\nmappings = []\n\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntarget = \"t1\"\ngroups = []\ndeploy_dir = \"/srv\"\n\n[retention.per_server]\nkeep_distinct_artifacts = 1\nkeep_days = 0\nprotect_previous = true\n\n[retention.deployment]\nprotect_deployments = 1\n\n[activation]\nadapter = \"none\"\n\n[verification]\nadapter = \"command\"\nargv = [\"true\"]\ntimeout_seconds = 5\nattempts = 1\ninterval_seconds = 0\n",        )
        .unwrap();
        std::fs::write(
            project.join("deploy.toml"),
            "schema_version = 2\napplication = \"store-tests\"\nrelease = \"v1\"\n\n\
             [[servers]]\nid = \"s1\"\naddress = \"a\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n\
             [targets.t1]\nrollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }\n",
        )
        .unwrap();
        ProjectConfig::load(&project.join("deploy.toml")).unwrap()
    }

    /// Every consumer of a target's ledger goes through the SAME read
    /// ([`LocalStore::read_ledger`]), so a conversion-time refusal precedes
    /// ALL of them: the direct read, a rollback resolve
    /// ([`crate::ledger::resolve_deployment`]), and the GC reachability
    /// scan ([`LocalStore::reachable_set`]). `why` names the mutation for
    /// the failure messages.
    fn assert_consumers_refuse_with_integrity(
        store: &LocalStore,
        config: &ProjectConfig,
        target: &str,
        id: &str,
        why: &str,
    ) {
        let err = store.read_ledger(target).unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "{why}: read_ledger must refuse with an integrity error before any consumer sees the line, got: {err}"
        );
        let err = crate::ledger::resolve_deployment(
            store,
            &TargetName::parse(target).expect("target name is a safe segment"),
            &test_deployment_id(id),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "{why}: a rollback resolve must refuse with the same integrity error before resolving, got: {err}"
        );
        let err = store.reachable_set(config, None).unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "{why}: the GC reachability scan must refuse with the same integrity error before sweeping, got: {err}"
        );
    }

    /// ONE-FIELD mutations of a valid terminal, expressed on the DOMAIN
    /// object (the truth-table and identity states are STRUCTURAL in the
    /// domain — they cannot be constructed — so those refusals are crafted
    /// at the WIRE in the deterministic test below): a BINDING key
    /// (add / remove / rename), or an OUTCOME key (rename — the value keeps
    /// naming its old slot — or an extra key outside the membership).
    /// Returns the mutated terminal + a reason naming the mutated field.
    fn one_field_mutations(terminal: &LedgerTerminal) -> Vec<(LedgerTerminal, String)> {
        let mut out: Vec<(LedgerTerminal, String)> = Vec::new();
        // (1) BINDING KEY — add one, remove one, move (rename) one. Only
        // meaningful when the disposition carries a rollback.
        if let TerminalDisposition::Successful(st) = &terminal.disposition {
            let first = st.rollback().keys().next().cloned().unwrap();
            // (1a) an EXTRA binding key (no generation for it)
            let mut t = terminal.clone();
            if let TerminalDisposition::Successful(st2) = &t.disposition {
                let mut entries = st2.rollback().clone().into_entries();
                entries.insert(
                    SlotId::new("ghost-slot".to_string()),
                    crate::ledger::records::SnapshotEntry::new(
                        crate::identity::test_generation_id("gen-ghost"),
                        crate::identity::ArtifactRef {
                            release: crate::identity::test_release_id("rel-ghost"),
                            variant: crate::identity::VariantName::new("standard".to_string()),
                            tree: crate::identity::test_tree_digest("ghost"),
                        },
                        crate::ledger::records::PhysicalBinding {
                            server: crate::identity::ServerId::new("s9".to_string()),
                            deploy_dir: "/srv/ghost".to_string(),
                        },
                    ),
                );
                let new_rollback = crate::ledger::records::TargetSnapshot::from_entries(entries);
                let new_st = crate::ledger::SuccessfulTerminal::new_unchecked(
                    new_rollback,
                    st2.activated().clone(),
                    st2.full_membership().clone(),
                );
                t.disposition = TerminalDisposition::Successful(new_st);
            }
            out.push((
                t,
                "binding key ADDED (extra binding, no generation) — now extra entry".to_string(),
            ));
            // (1b) a MISSING binding key (a generation without its binding)
            let mut t = terminal.clone();
            if let TerminalDisposition::Successful(st2) = &t.disposition {
                let mut entries = st2.rollback().clone().into_entries();
                entries.remove(&first);
                let new_rollback = crate::ledger::records::TargetSnapshot::from_entries(entries);
                let new_st = crate::ledger::SuccessfulTerminal::new_unchecked(
                    new_rollback,
                    st2.activated().clone(),
                    st2.full_membership().clone(),
                );
                t.disposition = TerminalDisposition::Successful(new_st);
            }
            out.push((
                t,
                "binding key REMOVED (a generation without its binding) — now missing entry"
                    .to_string(),
            ));
            // (1c) a binding key RENAMED (moved out of the slot set)
            let mut t = terminal.clone();
            if let TerminalDisposition::Successful(st2) = &t.disposition {
                let mut entries = st2.rollback().clone().into_entries();
                let value = entries.remove(&first).unwrap();
                entries.insert(SlotId::new("renamed-slot".to_string()), value);
                let new_rollback = crate::ledger::records::TargetSnapshot::from_entries(entries);
                let new_st = crate::ledger::SuccessfulTerminal::new_unchecked(
                    new_rollback,
                    st2.activated().clone(),
                    st2.full_membership().clone(),
                );
                t.disposition = TerminalDisposition::Successful(new_st);
            }
            out.push((
                t,
                "binding key RENAMED (missing + extra pair) — now renamed entry".to_string(),
            ));
        }
        // (2) OUTCOME KEY — rename an outcome's KEY. The domain value
        // carries no slot (the table key owns identity), so the renamed key
        // is re-attached as the wire outcome's `slot_id` on serialization;
        // the refusal comes from the CROSS-RECORD agreement — the renamed
        // key is no longer a member of the intent's membership. For a
        // Successful terminal the per-slot facts are DERIVED from the
        // rollback (the disposition stores only the activated slot-id set),
        // so the rename is expressed ACROSS the success facts — the
        // activated set AND the rollback's slots + bindings (the derived
        // view must stay consistent): the renamed slot is then outside the
        // intent's membership, and every consumer refuses.
        if let Some((key, _)) = terminal.outcomes().iter().next() {
            let mut t = terminal.clone();
            let renamed = SlotId::new("renamed-outcome".to_string());
            match &mut t.disposition {
                TerminalDisposition::Successful(st) => {
                    let mut act_set: BTreeSet<SlotId> = st.activated().as_set().clone();
                    act_set.remove(key);
                    act_set.insert(renamed.clone());
                    let new_activated = crate::identity::NonEmptySlotSet::try_new(act_set).unwrap();
                    let mut entries = st.rollback().clone().into_entries();
                    if let Some(e) = entries.remove(key) {
                        entries.insert(renamed.clone(), e);
                    }
                    let new_rollback =
                        crate::ledger::records::TargetSnapshot::from_entries(entries);
                    let new_st = crate::ledger::SuccessfulTerminal::new_unchecked(
                        new_rollback,
                        new_activated,
                        st.full_membership().clone(),
                    );
                    *st = new_st;
                }
                TerminalDisposition::FailedRolledBack { outcomes: o }
                | TerminalDisposition::Degraded { outcomes: o } => {
                    let mut map = o.clone().into_map();
                    let result = map.remove(key).unwrap();
                    map.insert(renamed, result);
                    *o = SlotTable::from_map(map);
                }
                TerminalDisposition::FailedPreflight => {
                    unreachable!("a preflight terminal carries no outcomes to rename")
                }
            }
            out.push((
                t,
                "outcome key RENAMED (outside the intent's membership)".to_string(),
            ));
        }
        out
    }

    /// THE USER'S PROPERTY: VALID LEDGER PAIRS (an EXACT intent + a
    /// SUCCESSFUL and a NON-SUCCESSFUL terminal derived from it) load and
    /// every consumer accepts them; mutating ONE FIELD at a time — a binding
    /// key (add/remove/rename) or an outcome key (rename) — makes EVERY
    /// consumer refuse the line with `Error::integrity` BEFORE any consumer
    /// logic runs: the direct read, a rollback resolve, and the GC
    /// reachability scan all fail on the SAME refusal.
    /// Bounded 2 cases, fixed seed 0x5EED_5EED (house style), no
    /// persistence.
    fn ledger_pair_mutation_case(intent: &DeploymentIntent) {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let config = consumer_config(tmp.path());
        let target = intent.target.as_str();
        for (variant, successful) in [("successful", true), ("failed", false)] {
            let terminal = terminal_for_intent(intent, "deploy-pair", successful);
            // THE VALID PAIR: the store loads and every consumer accepts it.
            let store =
                LocalStore::with_base(tmp.path().join(format!("store-{variant}-valid"))).unwrap();
            append_pair(&store, target, intent, &terminal);
            assert_eq!(
                store.read_ledger(target).unwrap().len(),
                1,
                "the valid pair merges into one entry"
            );
            store.reachable_set(&config, None).unwrap();
            let resolved = crate::ledger::resolve_deployment(
                &store,
                &TargetName::parse(target).expect("target name is a safe segment"),
                &test_deployment_id("deploy-pair"),
            );
            match successful {
                true => {
                    resolved.expect("a Successful pair resolves to its rollback");
                }
                false => {
                    assert!(
                        matches!(resolved, Err(Error::Ref(_))),
                        "a FailedRolledBack pair never resolves as a deployment ref (a ref refusal, not a record refusal)"
                    );
                }
            }
            // ONE mutation at a time — EVERY mutation must be refused: the
            // PRE-WRITE VALIDATION ([`LocalStore::append_terminal`]) refuses
            // the divergent intent/terminal pair at the APPEND (fail closed —
            // a terminal the strict reader would reject is never written;
            // the ledger bytes stay UNCHANGED), and the READ path still
            // refuses a DIRECTLY-WRITTEN copy of the same mutation (the
            // reader's refusal is independent of the writer — every
            // consumer fails on the SAME integrity error).
            for (n, (mutated, why)) in one_field_mutations(&terminal).into_iter().enumerate() {
                let store =
                    LocalStore::with_base(tmp.path().join(format!("store-{variant}-mut-{n}")))
                        .unwrap();
                store.append_intent(target, intent).unwrap();
                let before = std::fs::read(store.ledger_path(target)).unwrap();
                let err = store
                    .append_terminal(target, &intent.deployment_id, &mutated)
                    .unwrap_err();
                assert!(
                    matches!(err, Error::Integrity(_)),
                    "{why}: the writer must refuse the divergent terminal before any write, got: {err}"
                );
                let after = std::fs::read(store.ledger_path(target)).unwrap();
                assert_eq!(
                    before, after,
                    "{why}: a rejected terminal NEVER writes — the ledger bytes are unchanged"
                );
                // The READ path's refusal: invalid wire data must return `Error::Integrity`,
                // and invalid domain data is now unconstructible via `try_new`. For the
                // mutated domain (constructed via `new_unchecked`), `try_from_domain`
                // validates and returns `Integrity` — no panic is involved.
                let wire_res = LedgerTerminalWire::try_from_domain(
                    &intent.deployment_id,
                    &TargetName::parse(target).expect("target name is a safe segment"),
                    &mutated,
                );
                match wire_res {
                    Err(Error::Integrity(_)) => {
                        // For Successful invalid shapes, try_from_domain correctly refuses
                    }
                    Ok(wire) => {
                        // For non-Successful dispositions (e.g., FailedRolledBack), wire conversion
                        // succeeds but the ledger read must still refuse the cross-record mismatch
                        write_wire_pair(&store, target, &LedgerIntentWire::from(intent), &wire);
                        assert_consumers_refuse_with_integrity(
                            &store,
                            &config,
                            target,
                            "deploy-pair",
                            &why,
                        );
                    }
                    Err(e) => panic!(
                        "{why}: try_from_domain should return Integrity for invalid shape, got: {e:?}"
                    ),
                }
                // Also verify the wire-level mutation is refused at read time:
                // build a valid wire then apply a single-leg mutation to its
                // public memberships/rollback and assert `into_domain` returns Integrity.
                let valid_wire = LedgerTerminalWire::try_from_domain(
                    &intent.deployment_id,
                    &TargetName::parse(target).expect("target name is a safe segment"),
                    &terminal,
                )
                .unwrap();
                assert!(valid_wire.clone().into_domain().is_ok());
                let mut bad_wire = valid_wire.clone();
                bad_wire
                    .selected_membership
                    .push(crate::identity::SlotId::new("ghost-wire".to_string()));
                assert!(matches!(
                    bad_wire.clone().into_domain(),
                    Err(Error::Integrity(_))
                ));
                write_wire_pair(&store, target, &LedgerIntentWire::from(intent), &bad_wire);
                assert_consumers_refuse_with_integrity(
                    &store,
                    &config,
                    target,
                    "deploy-pair",
                    &why,
                );
            }
        }
    }

    proptest! {
        // THE USER'S PROPERTY: valid ledger pairs load; ONE-FIELD mutations
        // of the terminal — a binding key (add/remove/rename) or an outcome
        // key (rename) — are ALL refused with `Error::integrity` at the
        // WRITE (the pre-write validation in
        // [`LocalStore::append_terminal`] runs the strict reader's legs on
        // the intent/terminal pair BEFORE the append — a rejected pair
        // leaves the ledger bytes UNCHANGED), and a DIRECTLY-WRITTEN copy
        // of the same mutation is refused by read_ledger, a rollback
        // resolve, and the GC reachability scan at conversion time. Bounded
        // `proptest_cases(16)` (full 16 with `DEPLOY_FULL_TESTS=1`, fast
        // default), fixed seed 0x5EED_5EED (house style), no persistence.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn ledger_pair_one_field_mutations_are_refused_at_conversion(
            slot_count in 1u32..4,
        ) {
            let intent = exact_intent("deploy-pair", "t1", slot_count);
            ledger_pair_mutation_case(&intent);
        }
    }

    /// The CROSS-RECORD invariants, deterministically: a valid pair loads;
    /// ONE mutation per invariant — the truth table (both directions) and
    /// the terminal target equality, crafted at the WIRE (states the DOMAIN
    /// cannot represent — the domain enforces them structurally), plus the
    /// exact binding keys, the outcome key set vs the intent's membership,
    /// the outcome own-key rule, and the intent-leg target equality — is
    /// refused with `Error::integrity` by the read path.
    #[test]
    fn read_ledger_refuses_terminal_cross_field_and_cross_record_violations() {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let config = consumer_config(tmp.path());
        let intent = exact_intent("deploy-unit", "t1", 2);
        let terminal = terminal_for_intent(&intent, "deploy-unit", true);
        let id = "deploy-unit";
        let target = "t1";

        // THE VALID PAIR loads; the resolve and the GC scan accept it.
        let store = LocalStore::with_base(tmp.path().join("store-valid")).unwrap();
        append_pair(&store, target, &intent, &terminal);
        assert_eq!(store.read_ledger(target).unwrap().len(), 1);
        crate::ledger::resolve_deployment(
            &store,
            &TargetName::parse(target).expect("target name is a safe segment"),
            &test_deployment_id(id),
        )
        .unwrap();
        store.reachable_set(&config, None).unwrap();

        // (a) TRUTH TABLE, direction 1 (wire): a Successful terminal
        // without its rollback payload.
        let mut bad = LedgerTerminalWire::from_domain(
            &test_deployment_id(id),
            &TargetName::parse(target).expect("target name is a safe segment"),
            &terminal,
        );
        bad.rollback = None;
        assert_wire_terminal_refused(&tmp, target, &intent, &bad, "a");
        // (b) TRUTH TABLE, direction 2 (wire): a failed status carrying a
        // rollback.
        let mut bad = LedgerTerminalWire::from_domain(
            &test_deployment_id(id),
            &TargetName::parse(target).expect("target name is a safe segment"),
            &terminal,
        );
        bad.status = DeploymentStatus::Degraded;
        assert_wire_terminal_refused(&tmp, target, &intent, &bad, "b");
        // (c) TARGET EQUALITY, terminal leg (wire): the terminal names a
        // different target than the path and its entry.
        let mut bad = LedgerTerminalWire::from_domain(
            &test_deployment_id(id),
            &TargetName::parse(target).expect("target name is a safe segment"),
            &terminal,
        );
        bad.target = TargetName::new("other-target".to_string());
        assert_wire_terminal_refused(&tmp, target, &intent, &bad, "c");
        // (d) EXACT BINDING KEYS: a generation without its binding.
        let mut bad = terminal.clone();
        let first = match &bad.disposition {
            TerminalDisposition::Successful(st) => st.rollback().keys().next().cloned().unwrap(),
            _ => unreachable!("the fixture terminal is Successful"),
        };
        if let TerminalDisposition::Successful(st) = &mut bad.disposition {
            let mut entries = st.rollback().clone().into_entries();
            entries.remove(&first);
            let new_rollback = crate::ledger::records::TargetSnapshot::from_entries(entries);
            let new_st = crate::ledger::SuccessfulTerminal::new_unchecked(
                new_rollback,
                st.activated().clone(),
                st.full_membership().clone(),
            );
            *st = new_st;
        }
        assert_terminal_refused(&tmp, target, &intent, &bad, "d");
        // (e) OUTCOME KEY SET == membership: an outcome for a non-member
        // slot (extra). The Successful disposition stores ONLY the
        // activated slot-id set (the per-slot facts are DERIVED from the
        // rollback), so the extra slot is expressed ACROSS the success
        // facts — activated + rollback slots + bindings + full (the derived
        // view must stay consistent): the extra slot is outside the
        // intent's membership, and the read refuses (every outcome must
        // name a member slot).
        let mut bad = terminal.clone();
        let extra = SlotId::new("extra-slot".to_string());
        if let TerminalDisposition::Successful(st) = &mut bad.disposition {
            let mut act_set = st.activated().as_set().clone();
            act_set.insert(extra.clone());
            let new_activated = crate::identity::NonEmptySlotSet::try_new(act_set).unwrap();
            let mut entries = st.rollback().clone().into_entries();
            let gr = gen_ref(&extra);
            entries.insert(
                extra.clone(),
                crate::ledger::records::SnapshotEntry::new(
                    gr.generation,
                    gr.assignment.artifact,
                    binding_for(&extra),
                ),
            );
            let new_rollback = crate::ledger::records::TargetSnapshot::from_entries(entries);
            let mut new_full = st.full_membership().clone();
            new_full.insert(extra.clone());
            let new_st = crate::ledger::SuccessfulTerminal::new_unchecked(
                new_rollback,
                new_activated,
                new_full,
            );
            *st = new_st;
        }
        assert_terminal_refused(&tmp, target, &intent, &bad, "e");
        // (f) OUTCOME KEY RENAMED: the domain value carries no slot (the
        // table key owns identity), so an own-key violation is
        // UNREPRESENTABLE in the domain — the renamed key is re-attached as
        // the wire outcome's `slot_id` on serialization, and the refusal
        // comes from the cross-record agreement (the renamed key is no
        // longer a member of the intent's membership). For a Successful
        // terminal the rename is expressed ACROSS the success facts
        // (activated + rollback slots + bindings + full — the derived view
        // must stay consistent).
        let mut bad = terminal.clone();
        let first = bad
            .selected_membership()
            .expect("Successful")
            .iter()
            .next()
            .cloned()
            .unwrap();
        let renamed = SlotId::new("renamed-outcome".to_string());
        if let TerminalDisposition::Successful(st) = &mut bad.disposition {
            let mut act_set = st.activated().as_set().clone();
            act_set.remove(&first);
            act_set.insert(renamed.clone());
            let new_activated = crate::identity::NonEmptySlotSet::try_new(act_set).unwrap();
            let mut entries = st.rollback().clone().into_entries();
            if let Some(e) = entries.remove(&first) {
                entries.insert(renamed.clone(), e);
            }
            let new_rollback = crate::ledger::records::TargetSnapshot::from_entries(entries);
            let mut new_full = st.full_membership().clone();
            new_full.remove(&first);
            new_full.insert(renamed.clone());
            let new_st2 = crate::ledger::SuccessfulTerminal::new_unchecked(
                new_rollback,
                new_activated,
                new_full,
            );
            *st = new_st2;
        }
        assert_terminal_refused(&tmp, target, &intent, &bad, "f");
        // (g) TARGET EQUALITY, intent leg: the intent names a different
        // target than the path.
        let mut bad_intent = intent.clone();
        bad_intent.target = TargetName::new("other-target".to_string());
        assert_intent_refused(&tmp, target, &bad_intent);
    }

    /// Append a valid intent + a MUTATED terminal to a fresh store and
    /// assert the divergent intent/terminal PAIR is refused — TWICE over:
    /// the WRITER refuses it before any write (the pre-write validation in
    /// [`LocalStore::append_terminal`] — the ledger bytes stay UNCHANGED),
    /// and the READ path refuses a directly-written copy of the same pair
    /// (every consumer fails with the same integrity error). `tag` keeps
    /// each mutation's store directory unique.
    fn assert_terminal_refused(
        tmp: &tempfile::TempDir,
        target: &str,
        intent: &DeploymentIntent,
        mutated: &LedgerTerminal,
        tag: &str,
    ) {
        let store = LocalStore::with_base(tmp.path().join(format!("refuse-t-{tag}"))).unwrap();
        // THE WRITER REFUSES (fail closed — the hard guarantee): a
        // terminal the strict reader would reject is never written; the
        // ledger bytes are byte-identical before/after the rejected append.
        store.append_intent(target, intent).unwrap();
        let before = std::fs::read(store.ledger_path(target)).unwrap();
        let err = store
            .append_terminal(target, &intent.deployment_id, mutated)
            .unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "the writer must refuse the divergent terminal before any write, got: {err}"
        );
        let after = std::fs::read(store.ledger_path(target)).unwrap();
        assert_eq!(
            before, after,
            "a rejected terminal never writes — the ledger bytes are unchanged"
        );
        // THE READER STILL REFUSES a directly-written copy of the same
        // divergent pair (the read path's refusal is independent of the
        // writer). Invalid domain data is now unconstructible via `try_new`;
        // wire conversion returns `Error::Integrity` — no panic is involved.
        let wire_res = LedgerTerminalWire::try_from_domain(
            &intent.deployment_id,
            &TargetName::parse(target).expect("target name is a safe segment"),
            mutated,
        );
        match wire_res {
            Ok(wire) => {
                write_wire_pair(&store, target, &LedgerIntentWire::from(intent), &wire);
                let err = store.read_ledger(target).unwrap_err();
                assert!(
                    matches!(err, Error::Integrity(_)),
                    "a terminal violating the invariants must be refused with an integrity error, got: {err}"
                );
            }
            Err(Error::Integrity(_)) => {
                // try_from_domain correctly refused the structurally inconsistent shape
                // (e.g., activated ⊄ rollback) — this is the expected Integrity rejection.
            }
            Err(e) => {
                panic!("try_from_domain should return Integrity for invalid shape, got: {e:?}")
            }
        }
    }

    /// Write a valid intent wire + a MUTATED terminal wire to a fresh store
    /// and assert the store refuses with an integrity error.
    fn assert_wire_terminal_refused(
        tmp: &tempfile::TempDir,
        target: &str,
        intent: &DeploymentIntent,
        mutated: &LedgerTerminalWire,
        tag: &str,
    ) {
        let store = LocalStore::with_base(tmp.path().join(format!("refuse-w-{tag}"))).unwrap();
        write_wire_pair(&store, target, &LedgerIntentWire::from(intent), mutated);
        let err = store.read_ledger(target).unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "a terminal violating the invariants must be refused with an integrity error, got: {err}"
        );
    }

    /// Append a MUTATED intent to a fresh store and assert the store refuses
    /// with an integrity error. The refusal fires on the intent line itself
    /// (before any terminal is appended).
    fn assert_intent_refused(tmp: &tempfile::TempDir, target: &str, mutated: &DeploymentIntent) {
        let store = LocalStore::with_base(tmp.path().join("refuse-i")).unwrap();
        store.append_intent(target, mutated).unwrap();
        let err = store.read_ledger(target).unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "an intent violating the target equality must be refused with an integrity error, got: {err}"
        );
    }
}
