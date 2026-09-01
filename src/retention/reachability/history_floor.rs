//! Checkpoint persistence: the store side of the ONE per-target ledger.
//!
//! Moved from `crate::store::history_floor` during the encapsulation
//! restructure; the checkpoint command orchestration lives in
//! [`crate::retention::checkpoint`], the pin honoring in
//! [`crate::retention::pins`], and the artifact reclamation in
//! [`super::gc`].
//!
//! A target's entire deployment history is ONE ordered, append-only JSONL
//! ledger (`targets/<target>/ledger.jsonl`, see [`crate::ledger`]): each
//! entry starts as the DURABLE INTENT (written BEFORE any remote mutation)
//! and its TERMINAL EVENT carries the status, the per-slot outcomes, and —
//! when successful — the rollback state ([`crate::ledger::TargetSnapshot`]).
//! There is NO history-floor marker, NO snapshot op log, NO per-deployment
//! results/transition stream, and NO cleanup-pending debt flag: the old
//! multi-file model (and with it the transactional floor-advance backup
//! machinery — `history-floor.json.prev.*` backups, restore/recovery, the
//! torn-advance guard and the tri-state marker discovery) is GONE. The ONE
//! maintenance debt that remains is the SWEEP-DEBT marker
//! (`<base>/sweep-debt.json`, see [`LocalStore::read_sweep_debt`]): the
//! checkpoint's best-effort global sweep is POST-COMMIT MAINTENANCE, so an
//! incomplete sweep records a durable TYPED marker — and EVERY push (real
//! and no-op) and checkpoint runs the sweep RECONCILIATION regardless of
//! any marker. The marker is TRIAGE-ONLY: it decides HOW the next
//! reconciliation proceeds, never WHETHER it runs — a missing or failed
//! marker write can never cause the owed maintenance to be skipped
//! forever — see `crate::deploy::retry_pending_sweep`. The marker is
//! TWO-STATE ([`crate::store::local::debt::SweepDebt`]):
//! [`crate::store::local::debt::SweepDebt::Ready`] when the
//! checkpoint's ledger replace is durable (the sweep may run), and
//! [`crate::store::local::debt::SweepDebt::AwaitingCheckpointDurability`] when the replace is visible
//! but its durability is unconfirmed (only the durability-confirming
//! rewrite may run; the sweep must NOT run until a durability-confirming
//! rewrite transitions the marker).
//!
//! A checkpoint (`deploy checkpoint <target> <deployment-id>`) is exactly
//! three steps:
//!
//! 1. CALCULATE THE RETAINED SUFFIX — everything at/after the checkpoint
//!    deployment's position in the target's ledger (`LocalStore::ledger_suffix`).
//!    The floor is IMPLICIT: the ledger's first entry is the oldest retained
//!    rollback state; no separate floor marker exists.
//! 2. ATOMICALLY REPLACE the ledger with that suffix (`LocalStore::write_ledger_suffix`
//!    — temp + fsync + chmod-private + rename + parent-directory fsync; the
//!    replace's TWO COMMIT POINTS — the rename (new ledger VISIBLE) and the
//!    parent-directory fsync (new ledger DURABLE) — are reported explicitly
//!    as [`ReplaceOutcome`]). This is the checkpoint's ONLY logical commit; a
//!    reader never observes a torn ledger (wholly old or wholly new). IF THE
//!    RENAME NEVER SUCCEEDED, NO DELETION HAPPENS: the checkpoint is a plain
//!    `Err` and the full history stands untouched. IF THE RENAME SUCCEEDED
//!    BUT THE PARENT-DIRECTORY FSYNC FAILED, the checkpoint is NOT an `Err`
//!    (the new suffix IS visibly the ledger) — it is a STRUCTURED report
//!    with the ledger established, the durability unconfirmed (a warning),
//!    and the sweep DEFERRED (never against an unconfirmed floor): see
//!    [`crate::retention::checkpoint`].
//! 3. BEST-EFFORT GLOBAL SWEEP of unreachable deployment directories
//!    (`deployments/<id>/`), release records (`releases/<release-id>/`), and
//!    tree objects (`objects/sha256/<digest>/`). The sweep builds ONE
//!    LOCKED [`ReachabilitySnapshot`] — every root source read ONCE under
//!    the caller's lock and FROZEN: every target's CURRENT ledger (post any
//!    suffix the checkpoint is about to install), each entry's deployment
//!    id and intent/rollback artifacts, pending (terminal-less) intents,
//!    configured pins, observed assignments, and in-flight deployment
//!    dirs — and every deletion stage (deployment dirs, release records,
//!    tree objects) consumes ONLY that snapshot's retained sets: no stage
//!    re-reads a source that could drift. Everything reachable from
//!    another target's ledger, the CURRENT / INCOMPLETE state (observed
//!    artifacts, pending intent-only entries, in-flight deployment dirs),
//!    or a PIN is kept; everything else is unreachable and swept. A
//!    checkpoint sweep scans the checkpointed target's ledger AS-IF the
//!    suffix replacement ALREADY happened — the retained-suffix
//!    `LedgerOverride` — so the pre-checkpoint history's
//!    releases/trees/deployment dirs are unreachable the moment the ledger
//!    is shortened, and the DRY-RUN PREVIEW computes its deletion sets with
//!    the SAME override the real execution uses: the previewed deletions
//!    exactly equal the real ones. A failed sweep is retried by RECOMPUTING
//!    reachability — no persisted deletion worklist, no debt marker, no
//!    backup — and EVERY push and checkpoint runs the reconciliation
//!    regardless of any debt marker. The report carries at most: the
//!    logical commit status + sweep completed / retry-required.
//!
//! Because the atomic replacement is the only logical commit, a failed
//! checkpoint leaves EXACTLY the pre-call state; a failed sweep leaves the
//! ledger compacted (the commit stands) with the sweep retry-required, and
//! the next same-deployment checkpoint recomputes the same suffix (identical
//! — the ledger already IS the suffix) and re-runs the sweep to convergence.
//! Sweeps are best-effort and are NOT secure erasure.

use crate::config::ProjectConfig;
use crate::error::{Error, Result};
// KEEP-BOTH (merge): the gc side's `ReleaseId` (pins honored by name in the
// reachability scan) and the preview side's `LedgerEntry` (the override
// carries parsed entries) are both live imports — keep both.
use super::gc::SweepStageStats;
use crate::identity::DeploymentId;
use crate::ledger::{LedgerEntry, ObservedAssignment};
use crate::store::atomic::ReplaceStage;
use crate::store::atomic::{ReplaceOutcome, path_state, write_atomic_replace};
use crate::store::local::LocalStore;
use std::collections::BTreeSet;

#[cfg(test)]
use crate::identity::SlotId;
#[cfg(test)]
use crate::ledger::{DeploymentIntent, DeploymentStatus, LedgerTerminal, SlotResult};
#[cfg(test)]
use crate::testutil::test_faults::FaultKind;
#[cfg(test)]
use std::collections::BTreeMap;

/// The exact set a checkpoint discards on one target: the retained-suffix
/// replacement's dropped entries plus the global sweep's would-be /
/// performed deletions. The dry-run preview enumerates precisely this; the
/// real checkpoint replaces the ledger with the retained suffix and then
/// sweeps exactly the `sweep_*` sets.
///
/// # Planned vs removed
///
/// The `sweep_*` lists are the PLANNED candidate sets (what a dry-run
/// preview reports — the sweep's enumeration). The `removed_*` counters are
/// the counts ACTUALLY unlinked — incremented only after a successful
/// `remove_dir_all` — so `sweep_*.len() - removed_*` is the PENDING
/// remainder (candidates identified but not removed: an aborted stage, or a
/// stage that never ran because an earlier stage failed). A candidate is
/// never counted as removed unless the filesystem unlink succeeded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LedgerDiscards {
    /// Deployment ids whose entries were dropped from the ledger
    /// (everything strictly BEFORE the checkpoint deployment's position).
    pub discarded_entries: Vec<String>,
    /// Deployment ids whose `deployments/<id>/` directories the sweep
    /// identified for deletion — the PLANNED set (unreachable: not in any
    /// retained ledger, not observed as current, not an in-flight pending
    /// entry). The actually-unlinked count is `removed_deployments`.
    pub sweep_deployments: Vec<String>,
    /// Release ids whose `releases/<id>/` directories the sweep identified
    /// for deletion — the planned set. The actually-unlinked count is
    /// `removed_releases`.
    pub sweep_releases: Vec<String>,
    /// Tree digests whose `objects/sha256/<digest>/` directories the sweep
    /// identified for deletion — the planned set. The actually-unlinked
    /// count is `removed_objects`.
    pub sweep_objects: Vec<String>,
    /// Deployment dirs ACTUALLY unlinked (only successful unlinks count).
    /// Zero on a dry-run preview — the preview reports the planned sets
    /// only.
    pub removed_deployments: usize,
    /// Release records actually unlinked (successful unlinks only).
    pub removed_releases: usize,
    /// Tree objects actually unlinked (successful unlinks only).
    pub removed_objects: usize,
}

/// A HYPOTHETICAL LEDGER OVERRIDE for ONE target, consumed by the sweep's
/// reachability scan: the target's ledger AS-IF the checkpoint's atomic
/// suffix replacement had ALREADY happened (the retained suffix — the
/// checkpoint deployment's entry onward — IS the ledger after the commit).
///
/// The checkpoint flow computes the retained suffix ONCE
/// ([`LocalStore::ledger_suffix`]) and passes the parsed suffix as this
/// override to BOTH the dry-run preview and the real execution, so the two
/// paths share the SAME reachability calculation: the artifacts that become
/// unreachable ONLY when the ledger is shortened (the pre-checkpoint
/// history's releases, trees, and deployment dirs) are enumerated by the
/// preview EXACTLY as the real sweep deletes them. Every OTHER target's
/// ledger is read as-is.
#[derive(Clone, Debug)]
pub(crate) struct LedgerOverride {
    /// The target whose ledger the override replaces.
    pub target: String,
    /// The retained-suffix entries — the target's ledger as-if the suffix
    /// replacement already happened (the checkpoint's own entry onward, in
    /// ledger order).
    pub entries: Vec<LedgerEntry>,
}

impl LocalStore {
    // ---- the retained-suffix computation (step 1) -------------------------

    /// Compute the target's RETAINED LEDGER SUFFIX at the checkpoint
    /// deployment: every physical ledger line from the checkpoint entry's
    /// intent line onward (the checkpoint's own intent + terminal and every
    /// later entry — an in-flight pending entry at/after the checkpoint is
    /// retained with it). Returns the raw suffix lines AND the ids of the
    /// entries strictly before the checkpoint (the discards).
    ///
    /// FAIL CLOSED: the checkpoint deployment must be an entry of the
    /// target's CURRENT ledger (a deployment discarded by an earlier
    /// checkpoint is absent and cannot be re-established — the checkpoint
    /// can never move backward because the history is gone) and must have
    /// produced a SUCCESSFUL terminal event with a rollback state (the
    /// ledger's first retained entry is the oldest rollback state).
    ///
    /// Returns the physical suffix LINES (for the atomic replacement), the
    /// SAME suffix parsed as [`LedgerEntry`]s (the as-if ledger the sweep's
    /// reachability uses via [`LedgerOverride`] — physical line order IS the
    /// parsed entry order, so the two views agree), and the ids of the
    /// entries strictly before the checkpoint (the discards).
    pub(crate) fn ledger_suffix(
        &self,
        target: &str,
        checkpoint_id: &DeploymentId,
    ) -> Result<(Vec<String>, Vec<LedgerEntry>, Vec<String>)> {
        let lines = self.read_ledger_lines(target)?;
        let entries = self.read_ledger(target)?;
        let pos = entries
            .iter()
            .position(|e| e.deployment_id == *checkpoint_id)
            .ok_or_else(|| {
                Error::r#ref(format!(
                    "checkpoint requires a recorded deployment: deployment '{checkpoint_id}' is not in the ledger of target '{target}' (an earlier checkpoint may already have discarded it)"
                ))
            })?;
        let entry = &entries[pos];
        let terminal = entry.terminal.as_ref().ok_or_else(|| {
            Error::r#ref(format!(
                "checkpoint requires a SUCCESSFUL deployment: deployment '{checkpoint_id}' on target '{target}' has no terminal event (the deployment is still in flight or pending)"
            ))
        })?;
        if !terminal.disposition().is_successful() {
            return Err(Error::r#ref(format!(
                "checkpoint requires a successful deployment: deployment '{checkpoint_id}' on target '{target}' ended {:?} — only successful deployments carry a snapshot",
                terminal.status()
            )));
        }
        let keep_from = entry.seq as usize;
        let discarded: Vec<String> = entries[..pos]
            .iter()
            .map(|e| e.deployment_id.as_str().to_string())
            .collect();
        Ok((
            lines[keep_from..].to_vec(),
            entries[pos..].to_vec(),
            discarded,
        ))
    }

    /// Read the ledger's raw physical lines (one string per line, in file
    /// order), tri-state absent — the empty vector for no ledger.
    pub(crate) fn read_ledger_lines(&self, target: &str) -> Result<Vec<String>> {
        let p = self.ledger_path(target);
        if !path_state(&p)? {
            return Ok(vec![]);
        }
        let text =
            std::fs::read_to_string(&p).map_err(|e| Error::store(format!("read ledger: {e}")))?;
        let mut out = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            out.push(line.to_string());
        }
        Ok(out)
    }

    // ---- the atomic ledger replacement (step 2 — the ONLY logical commit) -

    /// ATOMICALLY replace the target's ledger with the retained suffix (the
    /// checkpoint's ONLY logical commit): write the suffix lines to a UNIQUE
    /// temp file in the same directory, fsync, chmod private BEFORE it can
    /// become visible, rename over the ledger (atomic on POSIX — a reader
    /// sees wholly-old or wholly-new, never torn), then fsync the parent
    /// directory. The replace's TWO COMMIT POINTS are reported explicitly as
    /// a [`ReplaceOutcome`] (see [`write_atomic_replace`]): the rename is
    /// commit point 1 (the new suffix becomes VISIBLE), the parent-directory
    /// fsync is commit point 2 (the rename becomes DURABLE).
    ///
    /// FAILURE MODEL (TRI-STATE): a failure at any PRE-RENAME stage — the
    /// injected [`FaultKind::LedgerReplaceWrite`] / `LedgerReplaceSync` /
    /// `LedgerReplaceRename` faults, or a real temp/sync/rename error —
    /// returns `Err` and leaves the PREVIOUS ledger visible — no deletion,
    /// no partial history. A failure of the PARENT-DIRECTORY open/fsync
    /// AFTER the rename — the injected [`FaultKind::LedgerReplaceDirSync`]
    /// fault or a real dir-sync error — returns
    /// [`ReplaceOutcome::ReplacedDurabilityUnknown`]: the NEW suffix IS
    /// visible under its final name (the ledger commit stands) but its
    /// durability is UNCONFIRMED. The caller must NEITHER delete against it
    /// (the sweep is deferred — a floor whose durability is unconfirmed
    /// must never be swept) NOR report the checkpoint as a plain `Err`
    /// (that would falsely claim the rename never happened while the
    /// shortened ledger visibly stands).
    pub(crate) fn write_ledger_suffix(
        &self,
        target: &str,
        suffix_lines: &[String],
    ) -> Result<ReplaceOutcome> {
        let path = self.ledger_path(target);
        let mut buf = String::new();
        for line in suffix_lines {
            buf.push_str(line);
            buf.push('\n');
        }
        // THE SINGLE REPLACEMENT PATH: the per-stage fault hook is a no-op
        // when no fault is armed ([`LocalStore::ledger_replace_hook`]), so
        // production and the fault-injection tests share the SAME
        // [`write_atomic_replace`] call — the production path is exercised
        // in test builds too.
        let mut hook = self.ledger_replace_hook(target);
        write_atomic_replace(&path, buf.as_bytes(), &mut hook)
    }

    /// The per-stage fault hook for the ledger-suffix replacement
    /// ([`LocalStore::write_ledger_suffix`]): consumes from THIS fixture's
    /// own registry (never a process-global slot), mapping each
    /// [`ReplaceStage`] to the checkpoint's [`FaultKind::LedgerReplace*`]
    /// family keyed by the target. A no-op when no fault is armed — so the
    /// production path (no faults ever armed) and the test path share the
    /// SAME [`write_atomic_replace`] call.
    #[cfg(test)]
    fn ledger_replace_hook(&self, target: &str) -> impl FnMut(ReplaceStage) -> Option<Error> + '_ {
        let reg = std::sync::Arc::clone(self.fault_registry());
        let key = target.to_string();
        move |stage| {
            let kind = match stage {
                ReplaceStage::Write => FaultKind::LedgerReplaceWrite,
                ReplaceStage::Sync => FaultKind::LedgerReplaceSync,
                ReplaceStage::Rename => FaultKind::LedgerReplaceRename,
                ReplaceStage::DirSync => FaultKind::LedgerReplaceDirSync,
            };
            if reg.consume(kind, &key) {
                Some(Error::store(format!(
                    "test fault: ledger suffix replacement faulted at the {stage:?} stage"
                )))
            } else {
                None
            }
        }
    }

    /// The production hook: no fault is ever armed outside tests, so the
    /// hook is a no-op — the SAME [`write_atomic_replace`] call the test
    /// path uses.
    #[cfg(not(test))]
    fn ledger_replace_hook(&self, _target: &str) -> impl FnMut(ReplaceStage) -> Option<Error> + '_ {
        |_stage| None
    }

    // ---- the global reachability sweep (step 3 — best-effort) -------------

    /// Build the ONE LOCKED REACHABILITY SNAPSHOT for a sweep: everything
    /// the sweep must keep, computed ONCE under the caller's lock from ALL
    /// ROOT SOURCES and FROZEN data —
    ///
    /// * EVERY target's CURRENT ledger (after a checkpoint the retained
    ///   suffix IS the ledger, so this is "or its retained suffix"): each
    ///   entry's deployment id (its `deployments/<id>/` dir), the artifacts
    ///   referenced by its intent (`desired` + `pre_push` — the pre-push
    ///   assignment is an [`Observation`], and an `Unknown` pre-push
    ///   assignment fails the snapshot closed, exactly like an `Unknown`
    ///   observed slot), and its terminal rollback's release + per-slot
    ///   trees,
    /// * the CURRENT/INCOMPLETE state: every target's `observed.json`
    ///   artifacts (release + tree) and `last_deployment` ids, plus
    ///   in-flight pending entries (intent without a terminal — their
    ///   `deployments/<id>/` dirs stay),
    /// * every configured PIN: a release pin marks the WHOLE release (its
    ///   record and every variant tree in it).
    ///
    /// Bindings are `(release_id, variant, tree_digest)`; a pin marks every
    /// variant/tree of its release. `deployments/<id>/` dirs of the
    /// retained ledger entries AND observed `last_deployment`s are reachable.
    ///
    /// THE SINGLE DELETION AUTHORITY: ONLY values derived from THIS snapshot
    /// may be deleted — the sweep's three deletion stages (deployment dirs,
    /// release records, tree objects) all consume this snapshot's retained
    /// sets or the planned sets enumerated from it ([`LocalStore::run_sweep`]
    /// builds it once and passes it to every stage). A separately-read source
    /// that could drift from the snapshot is never consulted by a deletion
    /// stage.
    ///
    /// FAIL CLOSED on EVERY retention anchor (no half-state): a
    /// PRESENT-but-unreadable anchor — an unreadable ledger, an unreadable
    /// observed record, an unreadable or malformed pins file, or a release
    /// record a pin names — is an ERROR, never ABSENCE. An anchor that
    /// reads as absent shrinks the retained set and the sweep would delete
    /// content the failed read might have protected; a snapshot that fails
    /// to build must abort the pass BEFORE any unlink (extra garbage on
    /// disk is safe, a partial retained set is not). (KEEP-BOTH merge: the
    /// gc side's fail-closed anchor docs + the preview side's override docs
    /// + parameter — both compose.)
    ///
    /// `ledger_override` — the checkpoint's retained-suffix override: when
    /// `Some`, the named target's ledger is scanned as the OVERRIDE entries
    /// (the as-if ledger after the suffix replacement), never the on-disk
    /// ledger; every other target's ledger is read as-is. The preview and
    /// the real execution pass the SAME override, so the two compute the
    /// identical retained set.
    pub(crate) fn reachability_snapshot(
        &self,
        config: &ProjectConfig,
        ledger_override: Option<&LedgerOverride>,
    ) -> Result<ReachabilitySnapshot> {
        let mut out = ReachabilitySnapshot::default();
        let targets_dir = self.base().join("targets");
        let mut target_names: Vec<String> = Vec::new();
        if path_state(&targets_dir)? {
            for dir in std::fs::read_dir(&targets_dir)
                .map_err(|e| Error::store(format!("read_dir targets: {e}")))?
            {
                let dir = dir.map_err(|e| Error::store(format!("target entry: {e}")))?;
                if dir
                    .file_type()
                    .map_err(|e| Error::store(format!("file_type {}: {e}", dir.path().display())))?
                    .is_dir()
                {
                    target_names.push(dir.file_name().to_string_lossy().into_owned());
                }
            }
        }
        target_names.sort();
        // The CURRENT OBSERVED artifacts + last deployments — the ONE global
        // physical slot map (`slots/<slot-id>/observed.json`), read ONCE (it
        // is store-global, not per-target; the per-target views are selection
        // filters over it). Fail closed: an unreadable observed record must
        // never read as "no observed state" — the scan would then drop the
        // artifact a target is CURRENTLY running from the retained set and
        // delete it.
        let observed = self.read_global_observed()?;
        for name in &target_names {
            // THE LEDGER OVERRIDE: when the sweep runs for a checkpoint, the
            // checkpointed target's ledger is scanned AS-IF the atomic suffix
            // replacement already happened — the retained suffix IS the
            // ledger — so the PRE-CHECKPOINT history's releases, trees, and
            // deployment dirs are unreachable and swept. The override is the
            // SAME parsed suffix the preview and the real execution share;
            // every OTHER target's ledger is read as-is.
            let entries = match ledger_override {
                Some(o) if o.target == *name => o.entries.clone(),
                _ => self.read_ledger(name)?,
            };
            for entry in &entries {
                // The entry's deployment dir (an in-flight entry without a
                // terminal is the CURRENT/INCOMPLETE state — its dir stays).
                out.deployments
                    .insert(entry.deployment_id.as_str().to_string());
                // Intent-referenced artifacts (desired + pre-push): the ONE
                // authoritative slot table carries both. The DESIRED artifact
                // is always `Known` (a planned artifact); the PRE-PUSH
                // assignment is an [`Observation`] — a `Known` artifact
                // contributes its release + tree, `KnownAbsent` contributes
                // nothing, and an `Unknown` assignment FAILS CLOSED below
                // (the sweep cannot verify what the slot ran before the
                // attempt, so reachability would be incomplete).
                // Intent-referenced artifacts: the ONE authoritative slot
                // table carries every slot's RESULT artifact (planned /
                // inherited — a successful deployment's snapshot resolves
                // from it) plus the Deploy slots' observed PRE-PUSH
                // artifacts. A `Known` pre-push artifact contributes its
                // release + tree, `KnownAbsent` contributes nothing, and an
                // `Unknown` assignment FAILS CLOSED below (the sweep cannot
                // verify what the slot ran before the attempt, so
                // reachability would be incomplete).
                let slot_snapshot = entry.intent.resulting_snapshot();
                for (sid, _p) in entry.intent.slots().iter() {
                    let snap_entry = slot_snapshot.get(sid).expect("slot in snapshot");
                    out.releases
                        .insert(snap_entry.artifact().release.as_str().to_string());
                    out.trees
                        .insert(snap_entry.artifact().tree.as_str().to_string());
                    if let Some(pre) = entry.intent.pre_push(sid) {
                        match pre {
                            crate::ledger::Observation::Known(prev) => {
                                out.releases
                                    .insert(prev.artifact.release.as_str().to_string());
                                out.trees.insert(prev.artifact.tree.as_str().to_string());
                            }
                            crate::ledger::Observation::Unknown(e) => {
                                return Err(Error::integrity(format!(
                                    "reachability sweep for target '{name}': deployment '{}' slot '{sid}' has an Unknown pre-push assignment ({}) — the sweep cannot verify what the slot ran before the attempt",
                                    entry.deployment_id, e.message
                                )));
                            }
                            crate::ledger::Observation::KnownAbsent => {}
                        }
                    }
                }
            }
        }
        for slot in observed.values() {
            match &slot.assignment {
                ObservedAssignment::Known {
                    artifact,
                    last_deployment,
                    ..
                } => {
                    out.deployments.insert(last_deployment.as_str().to_string());
                    out.releases.insert(artifact.release.as_str().to_string());
                    out.trees.insert(artifact.tree.as_str().to_string());
                }
                // FAIL CLOSED: an UNKNOWN or ASSIGNMENT-UNKNOWN observation
                // means the slot's live assignment could not be fully
                // verified — the GC cannot verify what the slot is running,
                // so it must NOT delete anything it cannot verify. The sweep
                // aborts (an integrity error) BEFORE any deletion; the
                // uncertainty contributes nothing to the retained set.
                ObservedAssignment::AssignmentUnknown { .. }
                | ObservedAssignment::Unknown { .. } => {
                    return Err(Error::integrity(
                        "an observed slot records an UNKNOWN or ASSIGNMENT-UNKNOWN assignment \
                         (its live assignment could not be read): the GC cannot verify what \
                         the slot is running, so the sweep aborts before any deletion",
                    ));
                }
                ObservedAssignment::Absent => {}
            }
        }
        // Durable pins: a pin marks the WHOLE release — its record and every
        // variant's tree. ProjectConfig pins (`deploy.toml` `[[pins]]`) AND the
        // store-level pins (`pins.json` — [`crate::ledger::Pins`]) are both
        // retention anchors: the checkpoint is store-only by construction, but
        // the CLI accepts both surfaces. FAIL CLOSED: a pin that names a
        // release with no record on disk, or whose record cannot be read or
        // verified, is an INTEGRITY error (see [`LocalStore::honor_release_pin`])
        // — the pin cannot be honored, so reachability is incomplete and the
        // sweep must abort before any deletion.
        for pin in config.pins() {
            // The pin's release is the TYPED [`crate::identity::ReleaseId`]: the
            // raw -> domain conversion validated every pin's release at load,
            // so this id is already the canonical `rel-sha256-<64 lowercase
            // hex>` form — no late parse can fail.
            let rid = pin.release.clone();
            self.honor_release_pin(&mut out, &rid, true)?;
        }
        // Store-level pins (`pins.json`): a MISSING file is the empty pin set
        // (tri-state absent) — a PRESENT-but-unreadable or malformed pins
        // file is an error, never "no pins" (a failed read must never shrink
        // the retained set).
        let pins = self.read_pins()?;
        for rid in pins.releases() {
            self.honor_release_pin(&mut out, rid, true)?;
        }
        for b in pins.bindings() {
            // An exact-binding pin names a release too: the pin cannot be
            // honored unless that release's record exists and reads clean
            // (the binding's own (release, tree) is kept regardless).
            self.honor_release_pin(&mut out, &b.release, false)?;
            out.releases.insert(b.release.as_str().to_string());
            out.trees.insert(b.tree.as_str().to_string());
        }
        Ok(out)
    }

    /// Enumerate the unreachable deployment dirs, release dirs, and object
    /// dirs a sweep would delete (or deleted): the difference between what
    /// EXISTS under `deployments/`, `releases/`, `objects/sha256/` and the
    /// reachable set. Pure read — the dry-run preview and the real sweep
    /// share it, so the preview enumerates EXACTLY what the sweep removes.
    /// `ledger_override` — the checkpoint passes its retained-suffix override
    /// so the preview and the real sweep delete from the SAME reachability:
    /// the preview never under-reports the artifacts that become unreachable
    /// only after the suffix replacement.
    ///
    /// THE ONE-SCAN PATH: builds the single locked [`ReachabilitySnapshot`]
    /// (every root source read ONCE and frozen) and enumerates from it; the
    /// real sweep ([`LocalStore::run_sweep`]) builds the snapshot once and
    /// reuses the SAME enumeration
    /// ([`LocalStore::sweep_discards_from_snapshot`]), so the previewed
    /// deletion sets are exactly the snapshot-derived sets the deletion
    /// stages consume.
    pub(crate) fn sweep_discards(
        &self,
        config: &ProjectConfig,
        ledger_override: Option<&LedgerOverride>,
    ) -> Result<LedgerDiscards> {
        // POST-COMMIT SWEEP READ FAULT HOOK (test-only, global key): the
        // REACHABILITY-SCAN stage fails — the sweep aborts before any
        // enumeration or deletion. The checkpoint's explicit post-commit
        // boundary converts this `Err` into a warning (the ledger commit
        // stands; the sweep is retry-required) — it must never surface as a
        // checkpoint `Err` after the irreversible replacement. The real
        // sweep's entry ([`LocalStore::run_sweep`]) fires the same hook
        // before its own snapshot build, so both paths fail closed identically.
        #[cfg(test)]
        if self.fault_registry().consume(FaultKind::SweepScan, "") {
            return Err(Error::store(
                "test fault: checkpoint sweep reachability scan forced to fail once",
            ));
        }
        // ONE locked snapshot, then enumerate from it. A snapshot that fails
        // to build aborts the enumeration before ANY candidate is listed —
        // a partial retained set must never produce a deletion list.
        let snapshot = self.reachability_snapshot(config, ledger_override)?;
        self.sweep_discards_from_snapshot(&snapshot)
    }

    /// Enumerate the discard candidates from an ALREADY-BUILT
    /// [`ReachabilitySnapshot`] — the difference between what EXISTS under
    /// `deployments/`, `releases/`, `objects/sha256/` and the snapshot's
    /// retained sets. Pure read: the preview ([`LocalStore::sweep_discards`])
    /// and the real sweep ([`LocalStore::run_sweep`]) share it, so every
    /// pass enumerates FROM THE SAME FROZEN SNAPSHOT the deletion stages
    /// consume — never a separately-read source that could drift.
    pub(crate) fn sweep_discards_from_snapshot(
        &self,
        snapshot: &ReachabilitySnapshot,
    ) -> Result<LedgerDiscards> {
        // POST-COMMIT SWEEP ENUMERATION FAULT HOOK (test-only, global key):
        // the directory-ENUMERATION stage fails after the scan succeeded —
        // nothing is listed, nothing is deleted. Same conversion contract as
        // the scan fault: the checkpoint reports the sweep retry-required
        // (warning), never `Err`.
        #[cfg(test)]
        if self.fault_registry().consume(FaultKind::SweepEnumerate, "") {
            return Err(Error::store(
                "test fault: checkpoint sweep directory enumeration forced to fail once",
            ));
        }
        let mut discards = LedgerDiscards::default();
        let depl_root = self.base().join("deployments");
        if path_state(&depl_root)? {
            let mut names: Vec<String> = std::fs::read_dir(&depl_root)
                .map_err(|e| Error::store(format!("read_dir deployments: {e}")))?
                .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
                .collect::<std::io::Result<_>>()
                .map_err(|e| Error::store(format!("deployments entry: {e}")))?;
            names.sort();
            for n in names {
                if !snapshot.deployments.contains(&n) {
                    discards.sweep_deployments.push(n);
                }
            }
        }
        let rel_root = self.base().join(crate::remote::layout::RELEASES);
        if path_state(&rel_root)? {
            let mut names: Vec<String> = std::fs::read_dir(&rel_root)
                .map_err(|e| Error::store(format!("read_dir releases: {e}")))?
                .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
                .collect::<std::io::Result<Vec<_>>>()
                .map_err(|e| Error::store(format!("releases entry: {e}")))?;
            names.sort();
            for n in names {
                if !snapshot.releases.contains(&n) {
                    discards.sweep_releases.push(n);
                }
            }
        }
        let obj_root = self.base().join(crate::remote::layout::objects());
        if path_state(&obj_root)? {
            let mut names: Vec<String> = std::fs::read_dir(&obj_root)
                .map_err(|e| Error::store(format!("read_dir objects: {e}")))?
                .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
                .collect::<std::io::Result<Vec<_>>>()
                .map_err(|e| Error::store(format!("objects entry: {e}")))?;
            names.sort();
            for n in names {
                if !snapshot.trees.contains(&n) {
                    discards.sweep_objects.push(n);
                }
            }
        }
        Ok(discards)
    }

    /// Run the best-effort GLOBAL SWEEP: delete every unreachable deployment
    /// directory, release record, and tree object. Each stage is
    /// independently fault-injectable: the deployment stage
    /// ([`FaultKind::SweepDeployments`]), the release stage
    /// ([`FaultKind::SweepReleases`]) and the object stage
    /// ([`FaultKind::SweepObjects`]) each fire at the stage's entry, so a
    /// faulted stage deletes nothing and the report says sweep
    /// retry-required. The release-record and tree-object stages are performed
    /// by the GLOBAL ARTIFACT GC ([`super::gc::LocalStore::gc_artifacts`])
    /// — its own faults ([`FaultKind::GcScan`] / [`FaultKind::GcDeleteReleases`]
    /// / [`FaultKind::GcDeleteTrees`]) fire before/inside the pass, and its
    /// per-candidate unlink faults ([`FaultKind::GcUnlinkReleases`] /
    /// [`FaultKind::GcUnlinkTrees`], armed with
    /// [`crate::testutil::test_faults::FaultRegistry::arm_release_unlink_after`]
    /// / `arm_tree_unlink_after`) fail the k-th unlink MID-stage. Deletions
    /// are tri-state (`path_state`): an already-removed target is skipped; ANY
    /// other stat or removal error stops the stage. FAIL CLOSED: a failed (or
    /// faulted) stage stops the sweep — the later stages stay PENDING (their
    /// candidates are planned, nothing removed). Returns the sweep's
    /// PLANNED candidate sets plus the counts ACTUALLY unlinked per category
    /// (only successful unlinks — see [`LedgerDiscards`]) and whether EVERY
    /// stage ran clean.
    /// `ledger_override` — the checkpoint's retained-suffix override, fed to
    /// the ONE snapshot so the sweep deletes on the SAME reachability the
    /// dry-run preview reported; `None` for the push-side reconciliation
    /// (current ledgers as-is).
    ///
    /// THE ONE LOCKED SNAPSHOT — THE SINGLE DELETION AUTHORITY: the sweep
    /// builds ONE frozen [`ReachabilitySnapshot`] ([`LocalStore::reachability_snapshot`])
    /// — every root source read ONCE under the caller's lock — and every
    /// deletion stage consumes ONLY that snapshot: the deployment-dir stage
    /// deletes the planned set enumerated from it
    /// ([`LocalStore::sweep_discards_from_snapshot`]), and the artifact GC
    /// unlinks releases/trees against its retained sets. No stage re-reads a
    /// source that could drift from the snapshot. Building is fail-closed
    /// (no half-state): an unreadable anchor aborts the sweep BEFORE any
    /// deletion — exactly today's behavior.
    pub(crate) fn run_sweep(
        &self,
        config: &ProjectConfig,
        anchor: &str,
        ledger_override: Option<&LedgerOverride>,
    ) -> Result<(LedgerDiscards, bool)> {
        // POST-COMMIT SWEEP READ FAULT HOOK (test-only, global key): the
        // REACHABILITY-SCAN stage fails — the sweep aborts before any
        // enumeration or deletion. Same conversion contract as the
        // `sweep_discards` hook: the checkpoint reports the sweep
        // retry-required (warning), never `Err`.
        #[cfg(test)]
        if self.fault_registry().consume(FaultKind::SweepScan, "") {
            return Err(Error::store(
                "test fault: checkpoint sweep reachability scan forced to fail once",
            ));
        }
        // THE ONE LOCKED SNAPSHOT — THE SINGLE DELETION AUTHORITY: built
        // ONCE here, frozen (fail closed — no half-state: an unreadable
        // anchor aborts the sweep before ANY deletion), and consumed by
        // every deletion stage below.
        let snapshot = self.reachability_snapshot(config, ledger_override)?;
        // `anchor` is the test-only fault-registry key (the `GcScan` consume
        // below); in production builds the sweep has no per-fixture key.
        #[cfg(not(test))]
        let _ = anchor;
        let mut discards = self.sweep_discards_from_snapshot(&snapshot)?;
        let mut complete = true;
        // Stage 1: deployment directories. The deployment stage's own
        // per-candidate unlink fault (`SweepDeploymentsNth`) fires INSIDE
        // `delete_dirs`; the `SweepDeployments` entry fault skips the stage.
        #[cfg(test)]
        let depl_faulted = self
            .fault_registry()
            .consume(FaultKind::SweepDeployments, "");
        #[cfg(not(test))]
        let depl_faulted = false;
        if depl_faulted {
            complete = false;
        } else {
            let depl = self.delete_dirs(&discards.sweep_deployments);
            discards.removed_deployments = depl.removed;
            if !depl.completed {
                complete = false;
            }
        }
        // Stages 2+3: unreachable release records and tree objects — the
        // artifact GC unlinks the releases/objects the SNAPSHOT's retained
        // sets exclude (NO second scan: the snapshot built above is the
        // single authority — a separately-read source could drift from it).
        // The `SweepReleases` / `SweepObjects` stage faults and the GC's
        // `GcScan` fault each block the whole artifact pass BEFORE any
        // deletion; the GC's own faults (`GcDeleteReleases` / `GcDeleteTrees`
        // / the per-candidate `GcUnlinkReleases` / `GcUnlinkTrees`) fire
        // inside it. FAIL CLOSED: when an earlier stage failed or faulted
        // (`complete` already false) the artifact stages stay PENDING —
        // nothing is removed and the retry recomputes a fresh snapshot.
        #[cfg(test)]
        let gc_faulted = complete
            && (self.fault_registry().consume(FaultKind::SweepReleases, "")
                || self.fault_registry().consume(FaultKind::SweepObjects, "")
                || self.fault_registry().consume(FaultKind::GcScan, anchor));
        #[cfg(not(test))]
        let gc_faulted = false;
        if gc_faulted {
            complete = false;
        } else if complete {
            #[cfg(test)]
            let gc = self.gc_artifacts(anchor, &snapshot);
            #[cfg(not(test))]
            let gc = self.gc_artifacts(&snapshot);
            match gc {
                Ok(gc) => {
                    discards.removed_releases = gc.removed_releases;
                    discards.removed_objects = gc.removed_trees;
                    if !gc.completed {
                        complete = false;
                    }
                }
                Err(_e) => {
                    complete = false;
                }
            }
        }
        Ok((discards, complete))
    }

    /// Remove the DEPLOYMENT-DIR stage's directory set, tri-state skip for
    /// already-removed dirs; any stat/removal failure stops the stage (fail
    /// closed — no further deletions, the remaining candidates stay
    /// pending). Returns the planned candidate count and the count ACTUALLY
    /// unlinked (only successful unlinks) plus whether the stage ran clean.
    fn delete_dirs(&self, names: &[String]) -> SweepStageStats {
        let planned = names.len();
        let mut removed = 0usize;
        for name in names {
            let dir = self.deployment_dir_named(name);
            // Test-only per-candidate fault hook: the K-TH deployment-dir
            // unlink fails — the stage aborts (fail closed), the count
            // stays at the successful unlinks so far, and the remaining
            // candidates stay pending.
            #[cfg(test)]
            if self
                .fault_registry()
                .consume_unlink(FaultKind::SweepDeploymentsNth, "")
            {
                return SweepStageStats {
                    planned,
                    removed,
                    completed: false,
                };
            }
            let present = match path_state(&dir) {
                Ok(p) => p,
                Err(_) => {
                    return SweepStageStats {
                        planned,
                        removed,
                        completed: false,
                    };
                }
            };
            if !present {
                continue;
            }
            if std::fs::remove_dir_all(&dir).is_err() {
                // FAIL CLOSED: stop the stage; only the successful unlinks
                // count as removed.
                return SweepStageStats {
                    planned,
                    removed,
                    completed: false,
                };
            }
            removed += 1;
        }
        SweepStageStats {
            planned,
            removed,
            completed: true,
        }
    }
}

// ---------------------------------------------------------------------------
// TEST-ONLY LEDGER ADAPTERS
//
// The old multi-file model exposed `read_attempts` / `read_snapshots` /
// `append_transition` / `read_results` / `read_transitions` and friends.
// PRODUCTION now reads the ONE ledger via [`LocalStore::read_ledger`]; these
// `#[cfg(test)]` adapters re-derive the OLD TEST-FACING SHAPES from the
// ledger so the fixture and engine suites keep their structure (the
// semantic oracle and the engine tests are driven by the API surface, and
// the task forbids touching their logic beyond it). They are test-only by
// construction and never part of the production surface.
#[cfg(test)]
impl LocalStore {
    /// TEST-ONLY: the ledger's SUCCESSFUL entries in order (the old
    /// `read_snapshots`). The entry position in this slice IS the `sN`
    /// snapshot index.
    pub fn read_snapshots(&self, target: &str) -> Result<Vec<LedgerEntry>> {
        Ok(self
            .read_ledger(target)?
            .into_iter()
            .filter(|e| {
                e.terminal
                    .as_ref()
                    .is_some_and(|t| t.status() == DeploymentStatus::Successful)
            })
            .collect())
    }

    /// TEST-ONLY: the ledger's FULL entry list (the old `read_attempts`).
    pub fn read_attempts(&self, target: &str) -> Result<Vec<LedgerEntry>> {
        self.read_ledger(target)
    }

    /// TEST-ONLY: append the durable intent (the old `append_attempt`),
    /// through a freshly opened
    /// [`crate::store::local::ledger::TargetLedgerTxn`] — every ledger write
    /// goes through the locked txn (there is no unlocked append anywhere).
    /// `#[cfg(test)]`: an external caller sees no such write method at all.
    #[cfg(test)]
    pub(crate) fn append_attempt(&self, target: &str, intent: &DeploymentIntent) -> Result<()> {
        let mut txn = crate::store::local::ledger::TargetLedgerTxn::open(self, target, "test")?;
        txn.append_intent(intent)
    }

    /// TEST-ONLY: the ledger's raw PHYSICAL lines (the old raw readers).
    pub fn read_attempts_raw(&self, target: &str) -> Result<Vec<LedgerEntry>> {
        self.read_ledger(target)
    }

    pub fn read_snapshots_raw(&self, target: &str) -> Result<Vec<LedgerEntry>> {
        self.read_snapshots(target)
    }

    /// TEST-ONLY: the terminal events recorded for a deployment (the old
    /// per-deployment transition stream — at most one today).
    pub fn read_transitions(&self, id: &str) -> Result<Vec<LedgerTerminal>> {
        for target in self.target_names()? {
            for e in self.read_ledger(&target)? {
                if e.deployment_id.as_str() == id {
                    return Ok(e.terminal.into_iter().collect());
                }
            }
        }
        Ok(vec![])
    }

    /// TEST-ONLY: the latest terminal of a deployment (the old
    /// `latest_transition`).
    pub fn latest_transition(&self, id: &str) -> Result<Option<LedgerTerminal>> {
        Ok(self.read_transitions(id)?.pop())
    }

    /// TEST-ONLY: the per-slot outcomes of a deployment's terminal event (the
    /// old `deployments/<id>/results.json`). An absent terminal is an error
    /// (the outcomes store never existed for it), mirroring the old read.
    /// The domain outcomes carry no slot (the table key owns identity), so
    /// the wire shape is re-attached here (each outcome's `slot_id` is its
    /// table key).
    pub fn read_results(&self, id: &str) -> Result<BTreeMap<SlotId, SlotResult>> {
        self.latest_transition(id)?
            .map(|t| {
                t.outcomes()
                    .iter()
                    .map(|(k, o)| (k.clone(), SlotResult::from_outcome(k, o)))
                    .collect()
            })
            .ok_or_else(|| Error::store(format!("no results for deployment '{id}'")))
    }

    /// TEST-ONLY: every target directory name under `targets/`.
    fn target_names(&self) -> Result<Vec<String>> {
        let targets_dir = self.base().join("targets");
        if !path_state(&targets_dir)? {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        for dir in std::fs::read_dir(&targets_dir)
            .map_err(|e| Error::store(format!("read_dir targets: {e}")))?
        {
            let dir = dir.map_err(|e| Error::store(format!("target entry: {e}")))?;
            if dir.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                out.push(dir.file_name().to_string_lossy().into_owned());
            }
        }
        out.sort();
        Ok(out)
    }
}

/// THE ONE LOCKED REACHABILITY SNAPSHOT — the sweep's SINGLE DELETION
/// AUTHORITY: the frozen union of everything the sweep must keep, computed
/// ONCE under the caller's lock in a single scan
/// (`LocalStore::reachability_snapshot`) from EVERY ROOT SOURCE — every
/// target's CURRENT ledger (post any retained-suffix override the
/// checkpoint is about to install), each entry's deployment id (its
/// `deployments/<id>/` dir) and its intent/rollback artifacts, pending
/// (terminal-less) intents with their in-flight deployment dirs, every
/// slot's observed assignment (artifact + `last_deployment`), and every
/// configured pin (store-level + `deploy.toml`).
///
/// ONLY values computed from THIS snapshot may be deleted: the sweep's
/// three deletion stages — deployment dirs, release records, tree objects —
/// all consume this snapshot's retained sets (or the planned sets
/// enumerated from them), never a separately-read source that could drift
/// from it. Building is fail-closed (no half-state): an unreadable anchor —
/// an unreadable ledger, observed record, pins file, or release record a
/// pin names — or an unverifiable assignment (an UNKNOWN pre-push /
/// observed assignment) aborts the computation with an ERROR, and no
/// deletion may happen from a failed build.
#[derive(Clone, Debug, Default)]
pub struct ReachabilitySnapshot {
    /// Deployment ids reachable (their `deployments/<id>/` dirs stay).
    pub deployments: BTreeSet<String>,
    /// Release ids reachable (their `releases/<id>/` dirs stay).
    pub releases: BTreeSet<String>,
    /// Tree digests reachable (their `objects/sha256/<digest>/` dirs stay).
    pub trees: BTreeSet<String>,
}
