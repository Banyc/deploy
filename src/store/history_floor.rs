//! Checkpoint persistence: the store side of the ONE per-target ledger.
//!
//! A target's entire deployment history is ONE ordered, append-only JSONL
//! ledger (`targets/<target>/ledger.jsonl`, see [`crate::records`]): each
//! entry starts as the DURABLE INTENT (written BEFORE any remote mutation)
//! and its TERMINAL EVENT carries the status, the per-slot outcomes, and —
//! when successful — the rollback state ([`crate::records::LedgerRollback`]).
//! There is NO history-floor marker, NO snapshot op log, NO per-deployment
//! results/transition stream, and NO cleanup-pending debt flag: the old
//! multi-file model (and with it the transactional floor-advance backup
//! machinery — `history-floor.json.prev.*` backups, restore/recovery, the
//! torn-advance guard and the tri-state marker discovery) is GONE. The ONE
//! maintenance debt that remains is the SWEEP-DEBT marker
//! (`<base>/sweep-debt.json`, see [`LocalStore::read_sweep_debt`]): the
//! checkpoint's best-effort global sweep is POST-COMMIT MAINTENANCE, so an
//! incomplete sweep records a durable marker and the NEXT PUSH (not just the
//! next checkpoint) retries the sweep and clears it — see
//! [`crate::push::engine::retry_pending_sweep`].
//!
//! A checkpoint (`deploy checkpoint <target> <deployment-id>`) is exactly
//! three steps:
//!
//! 1. CALCULATE THE RETAINED SUFFIX — everything at/after the checkpoint
//!    deployment's position in the target's ledger ([`LocalStore::ledger_suffix`]).
//!    The floor is IMPLICIT: the ledger's first entry is the oldest retained
//!    rollback state; no separate floor marker exists.
//! 2. ATOMICALLY REPLACE the ledger with that suffix ([`LocalStore::write_ledger_suffix`]
//!    — temp + fsync + chmod-private + rename + parent-directory fsync). This
//!    is the checkpoint's ONLY logical commit; a reader never observes a torn
//!    ledger (wholly old or wholly new). IF THE REPLACEMENT FAILS, NO
//!    DELETION HAPPENS: the checkpoint is a plain `Err` and the full history
//!    stands untouched.
//! 3. BEST-EFFORT GLOBAL SWEEP of unreachable deployment directories
//!    (`deployments/<id>/`), release records (`releases/<release-id>/`), and
//!    tree objects (`objects/sha256/<digest>/`). The reachability scan
//!    ([`LocalStore::sweep_discards`]) is recomputed FRESH on every retry:
//!    everything reachable from ANOTHER target's ledger, the CURRENT /
//!    INCOMPLETE state (observed artifacts, pending intent-only entries,
//!    in-flight deployment dirs), or a PIN is kept; everything else is
//!    unreachable and swept. A checkpoint sweep scans the checkpointed
//!    target's ledger AS-IF the suffix replacement ALREADY happened — the
//!    retained-suffix [`LedgerOverride`] — so the pre-checkpoint history's
//!    releases/trees/deployment dirs are unreachable the moment the ledger
//!    is shortened, and the DRY-RUN PREVIEW computes its deletion sets with
//!    the SAME override the real execution uses: the previewed deletions
//!    exactly equal the real ones. A failed sweep is retried by RECOMPUTING
//!    reachability — no persisted deletion worklist, no debt marker, no
//!    backup. The report carries at most: the logical commit status + sweep
//!    completed / retry-required.
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
use crate::model::{DeploymentId, ReleaseId};
use crate::records::{LedgerEntry, TerminalDisposition};
use crate::store::atomic::{path_state, write_atomic_replace};
use crate::store::gc::SweepStageStats;
use crate::store::local::LocalStore;
use std::collections::BTreeSet;

#[cfg(test)]
use crate::model::SlotId;
#[cfg(test)]
use crate::records::{
    DeploymentIntent, DeploymentStatus, LedgerRollback, LedgerTerminal, SlotResult, SlotTable,
};
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
        if !matches!(terminal.disposition, TerminalDisposition::Successful { .. }) {
            return Err(Error::r#ref(format!(
                "checkpoint requires a successful deployment: deployment '{checkpoint_id}' on target '{target}' ended {:?} — only successful deployments carry a rollback state",
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
    /// directory WITH ERRORS PROPAGATED (the durability commit point).
    ///
    /// FAILURE MODEL: a failure at ANY stage (the injected
    /// [`FaultKind::LedgerReplaceBefore`] fault, a real temp/sync/rename
    /// error, the parent-sync failure) returns `Err` and leaves the PREVIOUS
    /// ledger durable — no deletion, no partial history. The
    /// [`FaultKind::LedgerReplaceAfter`] fault fires AFTER the commit (the
    /// new suffix IS durable) so a test can assert the visible ledger is
    /// wholly new and the sweep is reported retry-required.
    pub(crate) fn write_ledger_suffix(&self, target: &str, suffix_lines: &[String]) -> Result<()> {
        #[cfg(test)]
        if self
            .fault_registry()
            .consume(FaultKind::LedgerReplaceBefore, target)
        {
            return Err(Error::store(
                "test fault: ledger suffix replacement forced to fail before the replace",
            ));
        }
        let path = self.ledger_path(target);
        let mut buf = String::new();
        for line in suffix_lines {
            buf.push_str(line);
            buf.push('\n');
        }
        write_atomic_replace(&path, buf.as_bytes())?;
        #[cfg(test)]
        if self
            .fault_registry()
            .consume(FaultKind::LedgerReplaceAfter, target)
        {
            return Err(Error::store(
                "test fault: ledger suffix replacement forced to fail after the replace",
            ));
        }
        Ok(())
    }

    // ---- the global reachability sweep (step 3 — best-effort) -------------

    /// Compute the LOCAL store's reachable set for a sweep: everything the
    /// sweep must keep —
    ///
    /// * EVERY target's CURRENT ledger (after a checkpoint the retained
    ///   suffix IS the ledger, so this is "or its retained suffix"): each
    ///   entry's deployment id (its `deployments/<id>/` dir), the artifacts
    ///   referenced by its intent (`desired` + `pre_push`), and its terminal
    ///   rollback's release + per-slot trees,
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
    /// FAIL CLOSED on EVERY retention anchor: a PRESENT-but-unreadable
    /// anchor — an unreadable ledger, an unreadable observed record, an
    /// unreadable or malformed pins file, or a release record a pin names —
    /// is an ERROR, never ABSENCE. An anchor that reads as absent shrinks
    /// the retained set and the sweep would delete content the failed read
    /// might have protected; the failed scan must abort the pass BEFORE any
    /// unlink (extra garbage on disk is safe, a partial retained set is
    /// not). (KEEP-BOTH merge: the gc side's fail-closed anchor docs + the
    /// preview side's override docs + parameter — both compose.)
    ///
    /// `ledger_override` — the checkpoint's retained-suffix override: when
    /// `Some`, the named target's ledger is scanned as the OVERRIDE entries
    /// (the as-if ledger after the suffix replacement), never the on-disk
    /// ledger; every other target's ledger is read as-is. The preview and
    /// the real execution pass the SAME override, so the two compute the
    /// identical retained set.
    pub(crate) fn reachable_set(
        &self,
        config: &ProjectConfig,
        ledger_override: Option<&LedgerOverride>,
    ) -> Result<ReachableSet> {
        let mut out = ReachableSet::default();
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
                // authoritative slot table carries both.
                for s in entry.intent.slots.values() {
                    out.releases
                        .insert(s.desired.artifact.release.as_str().to_string());
                    out.trees
                        .insert(s.desired.artifact.tree.as_str().to_string());
                    if let Some(p) = &s.pre_push {
                        out.releases.insert(p.artifact.release.as_str().to_string());
                        out.trees.insert(p.artifact.tree.as_str().to_string());
                    }
                }
                // The terminal's rollback payload: every slot's OWN artifact
                // binding (release + tree). A partial snapshot can carry
                // several releases, so reachability is derived per slot —
                // there is no snapshot-wide release.
                if let Some(t) = entry.terminal.as_ref()
                    && let TerminalDisposition::Successful { rollback } = &t.disposition
                {
                    for g in rollback.slots.values() {
                        out.releases
                            .insert(g.assignment.artifact.release.as_str().to_string());
                        out.trees
                            .insert(g.assignment.artifact.tree.as_str().to_string());
                    }
                }
            }
            for slot in observed.values() {
                if let Some(d) = &slot.last_deployment {
                    out.deployments.insert(d.as_str().to_string());
                }
                if let Some(a) = &slot.artifact {
                    out.releases.insert(a.release.as_str().to_string());
                    out.trees.insert(a.tree.as_str().to_string());
                }
            }
        }
        // Durable pins: a pin marks the WHOLE release — its record and every
        // variant's tree. ProjectConfig pins (`deploy.toml` `[[pins]]`) AND the
        // store-level pins (`pins.json` — [`crate::records::Pins`]) are both
        // retention anchors: the checkpoint is store-only by construction, but
        // the CLI accepts both surfaces. FAIL CLOSED: a pin that names a
        // release with no record on disk, or whose record cannot be read or
        // verified, is an INTEGRITY error (see [`LocalStore::honor_release_pin`])
        // — the pin cannot be honored, so reachability is incomplete and the
        // sweep must abort before any deletion.
        for pin in config.pins() {
            let rid = crate::model::ReleaseId::parse(&pin.release);
            self.honor_release_pin(&mut out, &rid, true)?;
        }
        // Store-level pins (`pins.json`): a MISSING file is the empty pin set
        // (tri-state absent) — a PRESENT-but-unreadable or malformed pins
        // file is an error, never "no pins" (a failed read must never shrink
        // the retained set).
        let pins = self.read_pins()?;
        for rid in &pins.releases {
            self.honor_release_pin(&mut out, rid, true)?;
        }
        for b in &pins.bindings {
            // An exact-binding pin names a release too: the pin cannot be
            // honored unless that release's record exists and reads clean
            // (the binding's own (release, tree) is kept regardless).
            self.honor_release_pin(&mut out, &b.release, false)?;
            out.releases.insert(b.release.as_str().to_string());
            out.trees.insert(b.tree.as_str().to_string());
        }
        Ok(out)
    }

    /// Honor ONE release pin: verify the named release's record exists and
    /// reads clean (identity-verified via [`LocalStore::read_release`]), then
    /// retain the record; when `expand_variants` (a WHOLE-RELEASE pin) also
    /// retain every variant's tree from the record's `variants` map. An
    /// EXACT-BINDING pin (`expand_variants = false`) keeps its own
    /// (release, tree) at the call site.
    ///
    /// FAIL CLOSED — a pin-abort, before any deletion: a pin that names a
    /// release with NO record on disk, or whose record cannot be read or
    /// identity-verified, is an [`Error::integrity`] error. An un-honorable
    /// pin means the reachability computation cannot expand the content the
    /// pin protects, so the retained set is incomplete — the sweep must
    /// abort rather than delete against it. (A missing record is tri-state
    /// DETECTED here: a genuine NotFound on the record file is not "absent
    /// pin" — it is a pin naming nothing on disk, an integrity violation.)
    fn honor_release_pin(
        &self,
        out: &mut ReachableSet,
        rid: &ReleaseId,
        expand_release_variants: bool,
    ) -> Result<()> {
        let rec_path = self.release_dir(rid).join("release.json");
        if !path_state(&rec_path)? {
            return Err(Error::integrity(format!(
                "pin names release {rid} which has no release record on disk: the pin cannot be honored, so reachability is incomplete — aborting the artifact sweep before any deletion"
            )));
        }
        // Read + identity-verify the record; ANY failure (an unreadable
        // file, malformed content, an identity mismatch) is an un-honorable
        // pin and is normalized to [`Error::integrity`] (the underlying
        // cause stays embedded in the message) — requirement: a pin that
        // cannot be honored aborts the sweep with an integrity error
        // whether the record is missing, unreadable, or unverifiable.
        let rec = self.read_release(rid).map_err(|e| {
            Error::integrity(format!(
                "pin names release {rid} whose record cannot be read or verified ({e}): the pin cannot be honored, so reachability is incomplete — aborting the artifact GC before any deletion"
            ))
        })?;
        out.releases.insert(rec.release_id.clone());
        if expand_release_variants {
            for tree in rec.variants.values() {
                out.trees.insert(tree.clone());
            }
        }
        Ok(())
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
        // checkpoint `Err` after the irreversible replacement.
        #[cfg(test)]
        if self.fault_registry().consume(FaultKind::SweepScan, "") {
            return Err(Error::store(
                "test fault: checkpoint sweep reachability scan forced to fail once",
            ));
        }
        let reachable = self.reachable_set(config, ledger_override)?;
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
                if !reachable.deployments.contains(&n) {
                    discards.sweep_deployments.push(n);
                }
            }
        }
        let rel_root = self.base().join(crate::layout::RELEASES);
        if path_state(&rel_root)? {
            let mut names: Vec<String> = std::fs::read_dir(&rel_root)
                .map_err(|e| Error::store(format!("read_dir releases: {e}")))?
                .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
                .collect::<std::io::Result<Vec<_>>>()
                .map_err(|e| Error::store(format!("releases entry: {e}")))?;
            names.sort();
            for n in names {
                if !reachable.releases.contains(&n) {
                    discards.sweep_releases.push(n);
                }
            }
        }
        let obj_root = self.base().join(crate::layout::objects());
        if path_state(&obj_root)? {
            let mut names: Vec<String> = std::fs::read_dir(&obj_root)
                .map_err(|e| Error::store(format!("read_dir objects: {e}")))?
                .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
                .collect::<std::io::Result<Vec<_>>>()
                .map_err(|e| Error::store(format!("objects entry: {e}")))?;
            names.sort();
            for n in names {
                if !reachable.trees.contains(&n) {
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
    /// by the GLOBAL ARTIFACT GC ([`crate::store::gc::LocalStore::gc_artifacts`])
    /// — its own faults ([`FaultKind::GcScan`] / [`FaultKind::GcDeleteReleases`]
    /// / [`FaultKind::GcDeleteTrees`]) fire inside the pass, and its
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
    /// `ledger_override` — the checkpoint's retained-suffix override, passed
    /// to BOTH the discard enumeration and the artifact GC so the sweep
    /// stays on the SAME reachability the dry-run preview reported; `None`
    /// for the push-side debt retry (current ledgers as-is).
    pub(crate) fn run_sweep(
        &self,
        config: &ProjectConfig,
        anchor: &str,
        ledger_override: Option<&LedgerOverride>,
    ) -> Result<(LedgerDiscards, bool)> {
        let mut discards = self.sweep_discards(config, ledger_override)?;
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
        // artifact GC recomputes the retained set from the ledgers (each
        // target's ledger / retained suffix), the observed slot state, the
        // pending entries, and the pins, then unlinks the unreachable
        // releases and objects. The `SweepReleases` / `SweepObjects` stage
        // faults each block the whole artifact pass BEFORE any deletion; the
        // GC's own faults (`GcScan` / `GcDeleteReleases` / `GcDeleteTrees` /
        // the per-candidate `GcUnlinkReleases` / `GcUnlinkTrees`) fire
        // inside it. FAIL CLOSED: when an earlier stage failed or faulted
        // (`complete` already false) the artifact stages stay PENDING —
        // nothing is removed and the retry recomputes reachability fresh.
        #[cfg(test)]
        let gc_faulted = complete
            && (self.fault_registry().consume(FaultKind::SweepReleases, "")
                || self.fault_registry().consume(FaultKind::SweepObjects, ""));
        #[cfg(not(test))]
        let gc_faulted = false;
        if gc_faulted {
            complete = false;
        } else if complete {
            match self.gc_artifacts(anchor, config, ledger_override) {
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
            let dir = self.deployment_dir(name);
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

    /// TEST-ONLY: append the durable intent (the old `append_attempt`).
    pub fn append_attempt(&self, target: &str, intent: &DeploymentIntent) -> Result<()> {
        self.append_intent(target, intent)
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
    pub fn read_results(&self, id: &str) -> Result<BTreeMap<SlotId, SlotResult>> {
        self.latest_transition(id)?
            .map(|t| {
                t.outcomes
                    .into_map()
                    .into_iter()
                    .map(|(k, r)| (k, SlotResult::from(r)))
                    .collect()
            })
            .ok_or_else(|| Error::store(format!("no results for deployment '{id}'")))
    }

    /// TEST-ONLY: append a terminal event for a deployment (the old
    /// `append_transition`). Outcomes are empty (status-only append).
    pub fn append_transition(
        &self,
        id: &str,
        status: &DeploymentStatus,
        reason: Option<&str>,
    ) -> Result<()> {
        let target = self.target_for(id)?;
        // The TEST adapter appends a status-only terminal; map the status to
        // its DISPOSITION (the domain truth table is structural — a
        // `Successful` terminal always carries its rollback payload, and a
        // `Degraded` one needs its remaining changes, which a status-only
        // append cannot supply).
        let disposition = match status {
            DeploymentStatus::Successful => TerminalDisposition::Successful {
                rollback: LedgerRollback {
                    slots: BTreeMap::new(),
                    bindings: BTreeMap::new(),
                },
            },
            DeploymentStatus::FailedPreflight => TerminalDisposition::FailedPreflight,
            DeploymentStatus::FailedRolledBack => TerminalDisposition::FailedRolledBack,
            other => {
                return Err(Error::store(format!(
                    "append_transition cannot record status {other:?} as a status-only terminal"
                )));
            }
        };
        self.append_terminal(
            &target,
            &DeploymentId::new(id.to_string()),
            &LedgerTerminal {
                recorded_at: crate::remote::helper::now_rfc3339(),
                outcomes: SlotTable::new(),
                disposition,
                reason: reason.map(str::to_string),
            },
        )
    }

    /// TEST-ONLY: the target whose ledger holds a deployment id.
    fn target_for(&self, id: &str) -> Result<String> {
        for dir in self.target_names()? {
            for e in self.read_ledger(&dir)? {
                if e.deployment_id.as_str() == id {
                    return Ok(dir);
                }
            }
        }
        Err(Error::store(format!(
            "no ledger entry for deployment '{id}'"
        )))
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

/// The LOCAL store's reachable set for a checkpoint sweep: the union of
/// everything the sweep must keep (retained ledgers, current/incomplete
/// state, pins). See [`LocalStore::reachable_set`].
#[derive(Clone, Debug, Default)]
pub struct ReachableSet {
    /// Deployment ids reachable (their `deployments/<id>/` dirs stay).
    pub deployments: BTreeSet<String>,
    /// Release ids reachable (their `releases/<id>/` dirs stay).
    pub releases: BTreeSet<String>,
    /// Tree digests reachable (their `objects/sha256/<digest>/` dirs stay).
    pub trees: BTreeSet<String>,
}
