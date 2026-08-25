//! Global best-effort artifact garbage collection (the physical reclamation
//! half of a checkpoint).
//!
//! The checkpoint's history floor + compaction (see
//! [`crate::store::history_floor`]) establish the retained ROLLBACK HISTORY
//! and delete the discarded `deployments/<id>/` directories. THIS module
//! reclaims the FILESYSTEM SPACE of the artifact store: release records
//! (`releases/<release-id>/`) and tree objects
//! (`objects/sha256/<digest>/`) that are no longer REACHABLE from any
//! retained history, any target's current observed artifact, any retained
//! deployment record, or any configured pin.
//!
//! # GC is GLOBAL
//!
//! Release records and tree objects are CONTENT-ADDRESSED and SHARED: the
//! same release (or tree) can be referenced by many targets, so the
//! retained set cannot be computed per target. Before deleting anything the
//! collector scans the WHOLE store and constructs the retained set of
//! complete artifact bindings (`release_id, variant, tree_digest`) from:
//!
//! 1. **Every snapshot at/above every target's history floor** — and, for
//!    a target WITHOUT a floor, its complete history (`read_snapshots_raw`
//!    filtered by `index >= floor.snapshot_index`, or the full log).
//! 2. **Every attempt in the same retained suffix** (its `desired`
//!    assignments) — the immutable intent records reference artifacts too.
//! 3. **Every retained deployment record, including unfinished operations**
//!    — every `deployments/<id>/` directory the retained history names (and
//!    every orphaned/torn directory no log names at all), whose
//!    `plan.json` carries the per-slot [`ArtifactRef`]s, the
//!    `desired_release`, and the plan source. A pending/in-progress
//!    operation whose deployment is retained must stay recoverable: its
//!    plan's references are retained with it.
//! 4. **Every target's CURRENT OBSERVED artifact** (`observed.json` slot
//!    artifacts) — the live assignment on every server.
//! 5. **Every configured pin** ([`crate::records::Pins`], `<base>/pins.json`):
//!    a RELEASE pin marks every variant/tree in that release record; an
//!    exact-binding entry keeps `(release, variant, tree)`. Pins retain
//!    ARTIFACT CONTENT ONLY — a pin never keeps or reinserts an old
//!    deployment, attempt, or snapshot in history, and it never raises or
//!    removes a history floor. These STORE-LEVEL pins are the checkpoint
//!    GC's retention anchors and are DISTINCT from the rotation subsystem's
//!    project-file `[[pins]]` ([`crate::config::Pin`], which protect the
//!    REMOTE rotation retained set and are evaluated only by rotation, never
//!    by the local GC): the checkpoint flow is store-only (it never loads
//!    the caller's `deploy.toml`), so its pins live in the store.
//! 6. **Recovery-required local state** — every store record a recovery
//!    path reads: retained deployment plans (covered by 3), the current
//!    observed artifacts (covered by 4), and the release records + tree
//!    objects they name. Anything else the store writes — server records
//!    (`servers/`), the staging area (`staging/`, rebuildable), refs, debt
//!    and floor markers — is outside GC scope and never deleted.
//!
//! Retaining a binding keeps BOTH its release record and its tree object:
//! `retained releases` ⊇ the releases of every retained binding, every
//! retained plan's `desired_release`/release ref, and every pinned release;
//! `retained trees` ⊇ the tree of every retained binding PLUS the FULL
//! variant tree set of every PINNED release (a release pin marks every
//! variant/tree in that record; an ordinary binding only pins its own tree).
//!
//! # Post-commit best-effort maintenance
//!
//! The GC runs AFTER the checkpoint's history compaction, as part of the
//! checkpoint's post-commit maintenance pass (the `finish_cleanup` half of
//! [`crate::push::checkpoint`]). Its failure model is
//! identical to the compaction's: a GC failure NEVER moves or removes the
//! established floor and NEVER deletes anything in the retained set — the
//! run aborts (fail-closed) before any unlink it cannot prove safe, the
//! checkpoint reports SUCCESS with the durable [`crate::records::CleanupPending`]
//! debt flag set ("cleanup incomplete; retry required"), and the next
//! `deploy checkpoint <target> <deployment-id>` re-runs the SAME pass.
//!
//! There is NO persisted deletion worklist: reachability is RECOMPUTED from
//! the store on every run, so a crash mid-GC converges on retry (already
//! removed dirs are skipped via the tri-state check; a dir a previous run
//! failed to remove is simply found again and retried). The debt flag is a
//! flag only — it never records what to delete.
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
//! floor, log, observed record, plan, pins file, or release record (a pin
//! whose release record is missing or unverifiable cannot be expanded) must
//! never produce a PARTIAL retained set — deleting against one could
//! destroy content the failed read might have protected. A failed pass
//! leaves extra garbage on disk (never less), which the retry reclaims once
//! the store is readable again.

use crate::error::{Error, Result};
use crate::layout;
use crate::model::{ArtifactRef, ReleaseId, TreeDigest, VariantName};
use crate::records::{DeploymentPlan, Pins, PlanSource};
use crate::store::atomic::{path_state, sync_parent_dir};
use crate::store::local::LocalStore;
use std::collections::BTreeSet;
use std::path::Path;

#[cfg(test)]
use crate::testutil::test_faults::FaultKind;

/// The outcome of one artifact garbage-collection pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GcOutcome {
    /// True when the FULL scan + unlink pass ran to completion; false when
    /// the pass was not attempted (the history compaction failed first) or
    /// aborted (fail closed — see the module docs).
    pub completed: bool,
    /// Number of unreachable release records (`releases/<id>/` dirs) removed.
    pub removed_releases: usize,
    /// Number of unreachable tree objects (`objects/sha256/<digest>/` dirs)
    /// removed.
    pub removed_trees: usize,
}

/// The RETAINED SET of one GC pass: every artifact binding, release record,
/// and tree object the pass must never delete.
#[derive(Debug, Default)]
struct Retained {
    /// Complete artifact bindings (release, variant, tree) reachable from
    /// the retained history, deployment plans, observed state, and pins.
    bindings: BTreeSet<ArtifactRef>,
    /// Release records whose content must survive: every binding's release,
    /// every retained plan's `desired_release` / release ref, every pinned
    /// release.
    releases: BTreeSet<ReleaseId>,
    /// Tree objects that must survive: every retained binding's tree, plus
    /// the FULL variant tree set of every PINNED release.
    trees: BTreeSet<TreeDigest>,
}

impl Retained {
    fn add_binding(&mut self, binding: &ArtifactRef) {
        self.bindings.insert(binding.clone());
    }
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
    /// ONLY as the per-fixture fault-injection key (mirroring the compaction
    /// phases, which are keyed by the checkpoint deployment id) — production
    /// behavior never depends on it.
    pub(crate) fn gc_artifacts(&self, anchor: &str) -> Result<GcOutcome> {
        // Fault hook: the SCAN itself aborts before any deletion (a failed
        // reachability pass must never unlink anything). The debt flag
        // records the pending cleanup and the retry recomputes reachability
        // fresh — no deletion worklist is ever persisted.
        #[cfg(test)]
        if self.fault_registry().consume(FaultKind::GcScan, anchor) {
            return Err(Error::store(
                "test fault: artifact GC scan forced to fail once",
            ));
        }
        let retained = self.compute_retained().map_err(|e| {
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

    /// The retained set of the whole store: the complete artifact bindings
    /// reachable from (1) every target's retained history (snapshots at/above
    /// the floor + the full history for targets without a floor, and the
    /// retained attempts suffix), (2) every retained deployment plan (plus
    /// every orphaned deployment dir, never discarded by any floor),
    /// (3) every target's current observed artifact, (4) every pin, and
    /// (5) the release records + tree objects those sources reference.
    ///
    /// FAIL-CLOSED: every read error propagates — a store that cannot be
    /// fully read has an unknown retained set, and the GC must not delete
    /// against a partial one.
    fn compute_retained(&self) -> Result<Retained> {
        let mut retained = Retained::default();
        // Deployment ids referenced by RETAINED history (the retained
        // deployment records whose plans contribute artifact refs).
        let mut retained_deployments: BTreeSet<String> = BTreeSet::new();
        // Deployment ids referenced by ANY target's attempts log (the
        // provenance check for orphaned dirs: an id NO log names at all has
        // never been discarded by any floor and is retained).
        let mut named_deployments: BTreeSet<String> = BTreeSet::new();

        // Every slot's CURRENT OBSERVED artifact: the global physical map —
        // ONE record per slot (targets are views over it, so the union of
        // all target views IS this map — no per-target replication).
        let global_observed = self.read_global_observed()?;
        for slot in global_observed.values() {
            if let Some(artifact) = &slot.artifact {
                retained.add_binding(artifact);
            }
        }

        // (1)(3) Per-target retained history + observed state.
        for target in enumerate_dirs(&self.base().join("targets"))? {
            // The floor gates every read: the retained history is the suffix
            // at/after it. A floor READ FAILURE is fatal — a corrupted or
            // unreadable floor must never let the scan treat the target as
            // floorless (which would retain MORE — safe — nor as a floor
            // boundary at a guess — which could retain LESS).
            let floor = self.read_history_floor(&target)?;
            let attempts = self.read_attempts_raw(&target)?;
            let snapshots = self.read_snapshots_raw(&target)?;
            // The retained attempts suffix begins at the floor's own attempt
            // (a floor always names a deployment in the attempts log — the
            // floor's integrity binding guarantees it; fail closed if that
            // ever changes).
            let keep_from = match &floor {
                Some(f) => attempts
                    .iter()
                    .position(|a| a.deployment_id == f.deployment_id)
                    .ok_or_else(|| {
                        Error::integrity(format!(
                            "artifact GC: history floor for target '{target}' names deployment '{}' but no attempt with that id exists in targets/{target}/attempts.jsonl — refusing to compute reachability against an unbound floor",
                            f.deployment_id
                        ))
                    })?,
                None => 0,
            };
            for attempt in attempts.iter().skip(keep_from) {
                retained_deployments.insert(attempt.deployment_id.as_str().to_string());
                for generation in attempt.desired.values() {
                    retained.add_binding(&generation.assignment.artifact);
                }
            }
            for attempt in &attempts {
                named_deployments.insert(attempt.deployment_id.as_str().to_string());
            }
            // Retained snapshots: at/above the floor (or the full log when
            // no floor exists).
            for snap in snapshots
                .iter()
                .filter(|s| floor.as_ref().is_none_or(|f| s.index >= f.snapshot_index))
            {
                retained_deployments.insert(snap.deployment_id.as_str().to_string());
                for generation in snap.slots.values() {
                    retained.add_binding(&generation.assignment.artifact);
                }
            }
        }

        // (2) Retained deployment records: the `deployments/<id>/` dirs the
        // retained history references (unfinished/pending operations
        // included) plus every ORPHANED dir no attempts log names at all.
        // Their plan.json records the per-slot artifacts, the
        // `desired_release`, and the plan source — the recovery-required
        // references of the retained deployments. A dir whose id is ONLY
        // named by BELOW-floor history is discarded material (its dir is
        // deleted by the compaction; its artifacts are garbage). A MISSING
        // plan (a torn dir with no record) contributes nothing; an
        // UNREADABLE plan of a retained deployment is a closed failure —
        // its references are unknown and might be about to be deleted.
        for id in enumerate_dirs(&self.base().join("deployments"))? {
            let retained_or_orphan =
                retained_deployments.contains(&id) || !named_deployments.contains(&id);
            if retained_or_orphan && let Some(plan) = self.read_plan_if_present(&id)? {
                for sp in plan.slots.values() {
                    retained.add_binding(&sp.artifact);
                }
                retained.releases.insert(plan.desired_release.clone());
                if let PlanSource::ReleaseRef(r) = &plan.source {
                    retained.releases.insert(r.clone());
                }
            }
        }

        // (4) Pins: a release pin expands to EVERY variant/tree in the
        // release record (the record must be readable — a missing or
        // unverifiable record closes the pass: the pin cannot be expanded,
        // and content it might protect is never deleted); an exact binding
        // pin keeps its (release, variant, tree) directly.
        let pins: Pins = self.read_pins()?;
        for rid in &pins.releases {
            retained.releases.insert(rid.clone());
            let rec = self.read_release(rid)?;
            for (variant, tree) in &rec.variants {
                retained.add_binding(&ArtifactRef {
                    release: rid.clone(),
                    variant: VariantName::new(variant.as_str()),
                    tree: TreeDigest::new(tree.as_str()),
                });
                retained.trees.insert(TreeDigest::new(tree.as_str()));
            }
        }
        for binding in &pins.bindings {
            retained.add_binding(binding);
        }

        // Close the set: retaining a binding keeps both its release record
        // and its tree object.
        for binding in &retained.bindings {
            retained.releases.insert(binding.release.clone());
            retained.trees.insert(binding.tree.clone());
        }
        Ok(retained)
    }

    /// Read a retained deployment record's plan, treating a GENUINELY
    /// missing `plan.json` as "no plan" (no artifact references — e.g. an
    /// empty test fixture dir); ANY other failure propagates (a plan that
    /// cannot be read might reference artifacts that the GC would delete).
    fn read_plan_if_present(&self, id: &str) -> Result<Option<DeploymentPlan>> {
        let p = self.deployment_dir(id).join("plan.json");
        if path_state(&p)? {
            Ok(Some(self.read_plan(id)?))
        } else {
            Ok(None)
        }
    }

    /// Unlink every release record NOT in the retained set, then fsync the
    /// `releases/` parent so the unlinks are durable. A deletion is TRI-STATE:
    /// an already-removed dir (a previous interrupted pass) is a skip; ANY
    /// other stat or deletion error PROPAGATES (fail closed — a deletion
    /// pass that cannot remove one dir must not silently end early).
    fn delete_unretained_releases(&self, anchor: &str, retained: &Retained) -> Result<usize> {
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
            let id = ReleaseId::new(name.clone());
            if retained.releases.contains(&id) {
                continue;
            }
            let dir = self.release_dir(&id);
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
    fn delete_unretained_trees(&self, anchor: &str, retained: &Retained) -> Result<usize> {
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
            let digest = TreeDigest::new(name.clone());
            if retained.trees.contains(&digest) {
                continue;
            }
            // The digest directory itself (`objects/sha256/<digest>/`),
            // holding `root/` and `tree.json`.
            let dir = self.base().join(layout::objects()).join(digest.as_str());
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
