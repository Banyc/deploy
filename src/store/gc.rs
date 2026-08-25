//! Global best-effort artifact garbage collection (the physical reclamation
//! half of a checkpoint's sweep).
//!
//! A checkpoint atomically replaces the target's ONE deployment LEDGER with
//! the retained suffix (the only logical commit — the floor is implicit: the
//! ledger's first entry is the oldest retained rollback state) and then
//! runs the best-effort global sweep. THIS module is the release-record and
//! tree-object half of that sweep: it reclaims the FILESYSTEM SPACE of the
//! artifact store — release records (`releases/<release-id>/`) and tree
//! objects (`objects/sha256/<digest>/`) that are no longer REACHABLE from
//! any target's ledger (after a checkpoint, the retained suffix IS the
//! ledger), any target's current observed artifact, any pending /
//! terminal-less ledger entry, or any pin.
//!
//! # GC is GLOBAL
//!
//! Release records and tree objects are CONTENT-ADDRESSED and SHARED: the
//! same release (or tree) can be referenced by many targets, so the
//! retained set cannot be computed per target. Before deleting anything the
//! collector scans the WHOLE store and constructs the retained set of
//! artifact bindings (`release_id, variant, tree_digest`) from:
//!
//! 1. **Every target's ledger** — each entry's intent references (`desired` +
//!    `pre_push`) and its terminal's rollback payload (release + per-slot
//!    trees); a terminal-less entry (pending / in-progress) is retained WITH
//!    its intent references, since the deployment is recoverable and its
//!    artifacts must stay.
//! 2. **Every target's CURRENT OBSERVED state** (`slots/<id>/observed.json`
//!    — the ONE physical observed record per slot; target views are a
//!    selection over it): the observed artifact (release + tree) and the
//!    observed `last_deployment` id.
//! 3. **Every pin** ([`crate::records::Pins`], `<base>/pins.json`, and the
//!    caller's `deploy.toml` `[[pins]]`): a RELEASE pin marks every
//!    variant/tree in that release record; an exact-binding entry keeps
//!    `(release, variant, tree)`. Pins retain ARTIFACT CONTENT ONLY — a pin
//!    never keeps or reinserts an old deployment in history, and it never
//!    extends a ledger's retained suffix.
//! 4. **Recovery-required local state** — the release records and tree
//!    objects the above name. Anything else the store writes — server
//!    records (`servers/`), the staging area (`staging/`, rebuildable),
//!    `deployments/<id>/` (swept by the deployment stage of the sweep) — is
//!    outside GC scope and never deleted here.
//!
//! Retaining a binding keeps BOTH its release record and its tree object:
//! `retained releases` ⊇ the releases of every retained binding and every
//! pinned release; `retained trees` ⊇ the tree of every retained binding
//! PLUS the FULL variant tree set of every PINNED release.
//!
//! # Post-commit best-effort maintenance
//!
//! The GC runs as part of the checkpoint's post-commit sweep (the release /
//! object stages of [`crate::store::history_floor::LocalStore::run_sweep`]).
//! Its failure model is best-effort with retry-by-recompute: a GC failure
//! NEVER deletes anything in the retained set — the run aborts (fail
//! closed) before any unlink it cannot prove safe, the checkpoint report
//! says the sweep is RETRY-REQUIRED, and the next
//! `deploy checkpoint <target> <deployment-id>` re-runs the SAME pass.
//!
//! There is NO persisted deletion worklist: reachability is RECOMPUTED from
//! the store on every run, so a crash mid-GC converges on retry (already
//! removed dirs are skipped via the tri-state check; a dir a previous run
//! failed to remove is simply found again and retried).
//!
//! # "Disk cleanup" = unlink + fsync, not secure erasure
//!
//! Reclaiming space means unlinking the unreachable `releases/<id>/` and
//! `objects/sha256/<digest>/` directories and fsyncing the affected parent
//! directories so the unlink is durable and space can actually be reused.
//! This is NOT secure physical erasure: SSD firmware, copy-on-write
//! filesystems, snapshots, journals, and backups may retain old blocks after
//! the unlink. The GC never claims otherwise.
//!
//! # Fail-closed scan
//!
//! The retained-set computation is a pure read over the WHOLE store and
//! EVERY read failure aborts the pass BEFORE any deletion: an unreadable
//! ledger, observed record, pins file, or release record (a pin whose
//! release record is missing or unverifiable cannot be expanded) must never
//! produce a PARTIAL retained set — deleting against one could destroy
//! content the failed read might have protected. A failed pass leaves extra
//! garbage on disk (never less), which the retry reclaims once the store is
//! readable again.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::layout;
use crate::model::ReleaseId;
use crate::store::atomic::{path_state, sync_parent_dir};
use crate::store::history_floor::ReachableSet;
use crate::store::local::LocalStore;
use std::path::Path;

#[cfg(test)]
use crate::testutil::test_faults::FaultKind;

/// The outcome of one artifact garbage-collection pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GcOutcome {
    /// True when the FULL scan + unlink pass ran to completion; false when
    /// the pass aborted (fail closed — see the module docs) or was not
    /// attempted because an earlier sweep stage faulted.
    pub completed: bool,
    /// Number of unreachable release records (`releases/<id>/` dirs) removed.
    pub removed_releases: usize,
    /// Number of unreachable tree objects (`objects/sha256/<digest>/` dirs)
    /// removed.
    pub removed_trees: usize,
}

/// Enumerate the store's targets (every directory under `targets/`), sorted
/// for determinism. An empty store (no `targets/` dir yet) is the empty
/// list; ANY other enumeration failure propagates (an unreadable targets
/// directory must never read as "no targets" — the retained set would then
/// be computed without the targets' history).
fn enumerate_dirs(root: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    match std::fs::read_dir(root) {
        Ok(rd) => {
            for entry in rd {
                let entry =
                    entry.map_err(|e| Error::store(format!("read_dir {}: {e}", root.display())))?;
                if entry
                    .file_type()
                    .map_err(|e| {
                        Error::store(format!("file_type {}: {e}", entry.path().display()))
                    })?
                    .is_dir()
                {
                    out.push(entry.file_name().to_string_lossy().into_owned());
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::store(format!("read_dir {}: {e}", root.display()))),
    }
    out.sort();
    Ok(out)
}

impl LocalStore {
    /// Run the global artifact garbage collection: scan the WHOLE store,
    /// compute the retained set, and unlink every unreachable release record
    /// and tree object. See the module docs for the reachability model, the
    /// failure model, and the durability protocol.
    ///
    /// `anchor` names the triggering checkpoint's deployment id: it is used
    /// ONLY as the per-fixture fault-injection key — production behavior
    /// never depends on it.
    pub(crate) fn gc_artifacts(&self, anchor: &str, config: &Config) -> Result<GcOutcome> {
        // Fault hook: the SCAN itself aborts before any deletion (a failed
        // reachability pass must never unlink anything). The sweep is
        // reported retry-required and the retry recomputes reachability
        // fresh — no deletion worklist is ever persisted.
        #[cfg(test)]
        if self.fault_registry().consume(FaultKind::GcScan, anchor) {
            return Err(Error::store(
                "test fault: artifact GC scan forced to fail once",
            ));
        }
        let retained = self.reachable_set(config).map_err(|e| {
            Error::store(format!(
                "artifact GC (triggered by checkpoint {anchor}): {e}"
            ))
        })?;
        let removed_releases = self.delete_unretained_releases(anchor, &retained)?;
        let removed_trees = self.delete_unretained_trees(anchor, &retained)?;
        Ok(GcOutcome {
            completed: true,
            removed_releases,
            removed_trees,
        })
    }

    /// Unlink every release record NOT in the retained set, then fsync the
    /// `releases/` parent so the unlinks are durable. A deletion is TRI-STATE:
    /// an already-removed dir (a previous interrupted pass) is a skip; ANY
    /// other stat or deletion error PROPAGATES (fail closed — a deletion
    /// pass that cannot remove one dir must not silently end early).
    fn delete_unretained_releases(&self, anchor: &str, retained: &ReachableSet) -> Result<usize> {
        // Fault hook (test-only, keyed by the checkpoint deployment id):
        // the release-deletion phase fails BEFORE any release is removed —
        // the extra garbage stays and the retry reclaims it.
        #[cfg(test)]
        if self
            .fault_registry()
            .consume(FaultKind::GcDeleteReleases, anchor)
        {
            return Err(Error::store(
                "test fault: artifact GC release deletion forced to fail once",
            ));
        }
        let root = self.base().join(layout::RELEASES);
        let mut removed = 0usize;
        for name in enumerate_dirs(&root)? {
            if retained.releases.contains(&name) {
                continue;
            }
            let dir = self.release_dir(&ReleaseId::new(name.clone()));
            if path_state(&dir)? {
                std::fs::remove_dir_all(&dir).map_err(|e| {
                    Error::store(format!(
                        "artifact GC (triggered by checkpoint {anchor}): remove release dir {}: {e}",
                        dir.display()
                    ))
                })?;
                removed += 1;
            }
        }
        // Durable unlink: without the parent fsync the removal may not
        // survive power loss and the space is not reclaimed.
        sync_parent_dir(&root)?;
        Ok(removed)
    }

    /// Unlink every tree object NOT in the retained tree set, then fsync
    /// the `objects/sha256/` parent. Same tri-state and fail-closed rules as
    /// the release phase.
    fn delete_unretained_trees(&self, anchor: &str, retained: &ReachableSet) -> Result<usize> {
        // Fault hook (test-only): the tree-deletion phase fails before any
        // removal.
        #[cfg(test)]
        if self
            .fault_registry()
            .consume(FaultKind::GcDeleteTrees, anchor)
        {
            return Err(Error::store(
                "test fault: artifact GC tree deletion forced to fail once",
            ));
        }
        let root = self.base().join(layout::objects());
        let mut removed = 0usize;
        for name in enumerate_dirs(&root)? {
            if retained.trees.contains(&name) {
                continue;
            }
            // The digest directory itself (`objects/sha256/<digest>/`),
            // holding `root/` and `tree.json`.
            let dir = self.base().join(layout::objects()).join(name);
            if path_state(&dir)? {
                std::fs::remove_dir_all(&dir).map_err(|e| {
                    Error::store(format!(
                        "artifact GC (triggered by checkpoint {anchor}): remove object dir {}: {e}",
                        dir.display()
                    ))
                })?;
                removed += 1;
            }
        }
        sync_parent_dir(&root)?;
        Ok(removed)
    }
}
