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
//!    unreachable and swept. A failed sweep is retried by RECOMPUTING
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

use crate::config::Config;
use crate::error::{Error, Result};
use crate::model::DeploymentId;
use crate::records::DeploymentStatus;
use crate::store::atomic::{path_state, write_atomic_replace};
use crate::store::local::LocalStore;
use std::collections::BTreeSet;

#[cfg(test)]
use crate::model::{PlacementSlotId, TargetName};
#[cfg(test)]
use crate::records::{LedgerEntry, LedgerIntent};
#[cfg(test)]
use crate::records::{LedgerTerminal, ServerResult};
#[cfg(test)]
use crate::testutil::test_faults::FaultKind;
#[cfg(test)]
use std::collections::BTreeMap;

/// The exact set a checkpoint discards on one target: the retained-suffix
/// replacement's dropped entries plus the global sweep's would-be /
/// performed deletions. The dry-run preview enumerates precisely this; the
/// real checkpoint replaces the ledger with the retained suffix and then
/// sweeps exactly the `sweep_*` sets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LedgerDiscards {
    /// Deployment ids whose entries were dropped from the ledger
    /// (everything strictly BEFORE the checkpoint deployment's position).
    pub discarded_entries: Vec<String>,
    /// Deployment ids whose `deployments/<id>/` directories the sweep
    /// deleted (unreachable: not in any retained ledger, not observed as
    /// current, not an in-flight pending entry).
    pub sweep_deployments: Vec<String>,
    /// Release ids whose `releases/<id>/` directories the sweep deleted.
    pub sweep_releases: Vec<String>,
    /// Tree digests whose `objects/sha256/<digest>/` directories the sweep
    /// deleted.
    pub sweep_objects: Vec<String>,
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
    pub(crate) fn ledger_suffix(
        &self,
        target: &str,
        checkpoint_id: &DeploymentId,
    ) -> Result<(Vec<String>, Vec<String>)> {
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
        if terminal.status != DeploymentStatus::Successful || terminal.rollback.is_none() {
            return Err(Error::r#ref(format!(
                "checkpoint requires a successful deployment: deployment '{checkpoint_id}' on target '{target}' ended {status:?} — only successful deployments carry a rollback state",
                status = terminal.status
            )));
        }
        let keep_from = entry.seq as usize;
        let discarded: Vec<String> = entries[..pos]
            .iter()
            .map(|e| e.deployment_id.as_str().to_string())
            .collect();
        Ok((lines[keep_from..].to_vec(), discarded))
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
    pub(crate) fn reachable_set(&self, config: &Config) -> Result<ReachableSet> {
        let mut out = ReachableSet::default();
        let targets_dir = self.base().join("targets");
        let mut target_names: Vec<String> = Vec::new();
        if path_state(&targets_dir)? {
            for dir in std::fs::read_dir(&targets_dir)
                .map_err(|e| Error::store(format!("read_dir targets: {e}")))?
            {
                let dir = dir.map_err(|e| Error::store(format!("target entry: {e}")))?;
                if dir.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    target_names.push(dir.file_name().to_string_lossy().into_owned());
                }
            }
        }
        target_names.sort();
        for name in &target_names {
            for entry in self.read_ledger(name)? {
                // The entry's deployment dir (an in-flight entry without a
                // terminal is the CURRENT/INCOMPLETE state — its dir stays).
                out.deployments
                    .insert(entry.deployment_id.as_str().to_string());
                // Intent-referenced artifacts (desired + pre-push).
                for g in entry.intent.desired.values() {
                    out.releases
                        .insert(g.assignment.artifact.release.as_str().to_string());
                    out.trees
                        .insert(g.assignment.artifact.tree.as_str().to_string());
                }
                for s in entry.intent.pre_push.values().flatten() {
                    out.releases.insert(s.artifact.release.as_str().to_string());
                    out.trees.insert(s.artifact.tree.as_str().to_string());
                }
                // The terminal's rollback payload (release + per-slot trees).
                if let Some(rollback) = entry.terminal.as_ref().and_then(|t| t.rollback.clone()) {
                    out.releases.insert(rollback.release.as_str().to_string());
                    for g in rollback.slots.values() {
                        out.releases
                            .insert(g.assignment.artifact.release.as_str().to_string());
                        out.trees
                            .insert(g.assignment.artifact.tree.as_str().to_string());
                    }
                }
            }
            // The current OBSERVED artifacts + last deployments.
            if let Ok(observed) = self.read_global_observed() {
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
        }
        // Durable pins: a pin marks the WHOLE release — its record and every
        // variant's tree. Config pins (`deploy.toml` `[[pins]]`) AND the
        // store-level pins (`pins.json` — [`crate::records::Pins`]) are both
        // retention anchors: the checkpoint is store-only by construction, but
        // the CLI accepts both surfaces.
        for pin in &config.pins {
            let rid = crate::model::ReleaseId::parse(&pin.release);
            if let Ok(rec) = self.read_release(&rid) {
                out.releases.insert(rec.release_id.clone());
                for tree in rec.variants.values() {
                    out.trees.insert(tree.clone());
                }
            }
        }
        if let Ok(pins) = self.read_pins() {
            for rid in &pins.releases {
                out.releases.insert(rid.as_str().to_string());
                if let Ok(rec) = self.read_release(rid) {
                    for tree in rec.variants.values() {
                        out.trees.insert(tree.clone());
                    }
                }
            }
            for b in &pins.bindings {
                out.releases.insert(b.release.as_str().to_string());
                out.trees.insert(b.tree.as_str().to_string());
            }
        }
        Ok(out)
    }

    /// Enumerate the unreachable deployment dirs, release dirs, and object
    /// dirs a sweep would delete (or deleted): the difference between what
    /// EXISTS under `deployments/`, `releases/`, `objects/sha256/` and the
    /// reachable set. Pure read — the dry-run preview and the real sweep
    /// share it, so the preview enumerates EXACTLY what the sweep removes.
    pub(crate) fn sweep_discards(&self, config: &Config) -> Result<LedgerDiscards> {
        let reachable = self.reachable_set(config)?;
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
    /// / [`FaultKind::GcDeleteTrees`]) fire inside the pass. Deletions are
    /// tri-state (`path_state`): an already-removed target is skipped; ANY
    /// other stat or removal error stops the stage. Returns the performed
    /// deletions and whether EVERY stage ran clean.
    pub(crate) fn run_sweep(
        &self,
        config: &Config,
        anchor: &str,
    ) -> Result<(LedgerDiscards, bool)> {
        let discards = self.sweep_discards(config)?;
        let mut complete = true;
        // Stage 1: deployment directories.
        #[cfg(test)]
        if self
            .fault_registry()
            .consume(FaultKind::SweepDeployments, "")
        {
            complete = false;
        } else if let Err(e) = self.delete_dirs(&discards.sweep_deployments, "deployment") {
            complete = false;
            let _ = e;
        }
        #[cfg(not(test))]
        if let Err(_e) = self.delete_dirs(&discards.sweep_deployments, "deployment") {
            complete = false;
        }
        // Stages 2+3: unreachable release records and tree objects — the
        // artifact GC recomputes the retained set from the ledgers (each
        // target's ledger / retained suffix), the observed slot state, the
        // pending entries, and the pins, then unlinks the unreachable
        // releases and objects. The `SweepReleases` / `SweepObjects` stage
        // faults each block the whole artifact pass BEFORE any deletion; the
        // GC's own faults (`GcScan` / `GcDeleteReleases` / `GcDeleteTrees`)
        // fire inside it.
        #[cfg(test)]
        if self.fault_registry().consume(FaultKind::SweepReleases, "")
            || self.fault_registry().consume(FaultKind::SweepObjects, "")
        {
            complete = false;
        } else if let Err(e) = self.gc_artifacts(anchor, config) {
            complete = false;
            let _ = e;
        }
        #[cfg(not(test))]
        if let Err(_e) = self.gc_artifacts(anchor, config) {
            complete = false;
        }
        Ok((discards, complete))
    }

    /// Remove one stage's directory set (all under the same root), tri-state
    /// skip for already-removed dirs; any stat/removal failure aborts the
    /// stage.
    fn delete_dirs(&self, names: &[String], kind: &str) -> Result<()> {
        for name in names {
            let dir = match kind {
                "deployment" => self.deployment_dir(name),
                "release" => self.base().join(crate::layout::RELEASES).join(name),
                _ => self.base().join(crate::layout::objects()).join(name),
            };
            if path_state(&dir)? {
                std::fs::remove_dir_all(&dir).map_err(|e| {
                    Error::store(format!("sweep {} dir {}: {e}", kind, dir.display()))
                })?;
            }
        }
        Ok(())
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
                e.terminal.as_ref().is_some_and(|t| {
                    t.status == DeploymentStatus::Successful && t.rollback.is_some()
                })
            })
            .collect())
    }

    /// TEST-ONLY: the ledger's FULL entry list (the old `read_attempts`).
    pub fn read_attempts(&self, target: &str) -> Result<Vec<LedgerEntry>> {
        self.read_ledger(target)
    }

    /// TEST-ONLY: append the durable intent (the old `append_attempt`).
    pub fn append_attempt(&self, target: &str, intent: &LedgerIntent) -> Result<()> {
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
    pub fn read_results(&self, id: &str) -> Result<BTreeMap<PlacementSlotId, ServerResult>> {
        self.latest_transition(id)?
            .map(|t| t.outcomes)
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
        self.append_terminal(
            &target,
            &LedgerTerminal {
                deployment_id: DeploymentId::new(id.to_string()),
                target: TargetName::new(target.clone()),
                status: status.clone(),
                recorded_at: crate::remote::helper::now_rfc3339(),
                outcomes: BTreeMap::new(),
                rollback: None,
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
