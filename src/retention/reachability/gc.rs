//! Global best-effort artifact garbage collection (the physical reclamation
//! half of a checkpoint's sweep).
//!
//! Moved from `crate::store::gc` during the encapsulation restructure; the
//! reachability model and the retained-suffix ledger override live in
//! [`super::history_floor`].
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
//!    artifacts must stay. When the GC runs for a CHECKPOINT, the
//!    checkpointed target's ledger is scanned AS-IF the atomic suffix
//!    replacement already happened — the retained-suffix
//!    `LedgerOverride` — so the pre-checkpoint history's artifacts are
//!    unreachable and swept, and the dry-run preview uses the SAME override
//!    (previewed deletions == real deletions).
//! 2. **Every target's CURRENT OBSERVED state** (`slots/<id>/observed.json`
//!    — the ONE physical observed record per slot; target views are a
//!    selection over it): the observed artifact (release + tree) and the
//!    observed `last_deployment` id. An observed slot whose observation
//!    is `Unknown` ([`crate::ledger::Observation::Unknown`]; its live
//!    assignment could not be read) is treated CONSERVATIVELY: the GC
//!    cannot verify what the slot runs, so it must NOT delete anything it
//!    cannot verify — the sweep aborts with an integrity error before any
//!    deletion (never silently sweeping an unknown slot's content).
//! 3. **Every pin** ([`crate::ledger::Pins`], `<base>/pins.json`, and the
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
//! object stages of `super::history_floor::LocalStore::run_sweep`).
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

use super::history_floor::ReachabilitySnapshot;
#[cfg(test)]
use crate::config::ProjectConfig;
use crate::error::{Error, Result};
use crate::identity::{ReleaseId, TreeDigest};
use crate::remote::layout;
use crate::store::atomic::{path_state, sync_parent_dir};
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
    /// Number of unreachable release records (`releases/<id>/` dirs) the
    /// pass IDENTIFIED as deletion candidates — the PLANNED set (includes
    /// the already-removed ones).
    pub planned_releases: usize,
    /// Number of unreachable tree objects (`objects/sha256/<digest>/` dirs)
    /// identified as candidates — the planned set.
    pub planned_trees: usize,
    /// Number of unreachable release records ACTUALLY UNLINKED — only
    /// successful `remove_dir_all` calls count. A candidate whose unlink
    /// failed mid-stage (or whose stage never ran) is NEVER counted here;
    /// it stays in the planned set as PENDING.
    pub removed_releases: usize,
    /// Number of unreachable tree objects actually unlinked (successful
    /// unlinks only).
    pub removed_trees: usize,
}

/// ONE deletion stage's outcome (deployment dirs / release records / tree
/// objects): how many candidates were identified (`planned`), how many were
/// ACTUALLY unlinked (`removed` — incremented only after a successful
/// `remove_dir_all`), and whether the stage ran clean (`completed`). A
/// mid-stage failure STOPS the stage (fail closed — no further unlinks):
/// the removed count reflects exactly the successful unlinks and the
/// remaining candidates stay PENDING (`planned - removed`), never reported
/// as removed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SweepStageStats {
    pub planned: usize,
    pub removed: usize,
    pub completed: bool,
}

/// The semantic kind of the entries under an enumerated GC root: a release
/// record directory (`releases/<id>/`) or a tree object directory
/// (`objects/sha256/<digest>/`). The kind determines which VALIDATED identity
/// an entry name is parsed into — a raw filesystem string is never consumed
/// as a semantic identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EntryKind {
    /// `releases/` — every directory names a release record.
    Release,
    /// `objects/sha256/` — every directory names a tree object.
    Tree,
}

/// ONE enumerated directory entry, as an OPAQUE handle: the raw filesystem
/// name is never exposed as a semantic string. An entry is either a
/// RECOGNIZED semantic kind carrying its VALIDATED identity (a release
/// record or a tree object) or an UNRECOGNIZED entry (a stray file, a
/// dotfile, a malformed name) that is never compared against the retained
/// sets as a semantic identity — but is still an unreachable filesystem
/// entry GC may reclaim (the retained sets only ever contain VALIDATED
/// identities, so an unrecognized name can never be retained).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EnumeratedEntry {
    /// A release record directory (`releases/<id>/`): the validated
    /// [`ReleaseId`] the directory names.
    Release(ReleaseId),
    /// A tree object directory (`objects/sha256/<digest>/`): the validated
    /// [`TreeDigest`] the directory names.
    Tree(TreeDigest),
    /// An entry that is not a recognized semantic kind: never treated as a
    /// semantic identity (never compared against the retained sets), but
    /// still an unreachable filesystem entry GC may reclaim. The raw name
    /// is carried ONLY for deletion-path construction.
    Other(String),
}

impl EnumeratedEntry {
    /// The VALIDATED identity string of a recognized entry (for retained-set
    /// membership checks); `None` for an unrecognized entry. The raw
    /// filesystem name is never exposed — only the parsed identity.
    pub(crate) fn identity(&self) -> Option<&str> {
        match self {
            EnumeratedEntry::Release(id) => Some(id.as_str()),
            EnumeratedEntry::Tree(digest) => Some(digest.as_str()),
            EnumeratedEntry::Other(_) => None,
        }
    }
}

/// Enumerate the store's targets (every directory under `targets/`), sorted
/// for determinism. An empty store (no `targets/` dir yet) is the empty
/// list; ANY other enumeration failure propagates (an unreadable targets
/// directory must never read as "no targets" — the retained set would then
/// be computed without the targets' history).
///
/// Every directory entry is returned as an OPAQUE [`EnumeratedEntry`]
/// handle: the raw name is parsed into the VALIDATED identity of the
/// requested [`EntryKind`] (a malformed name is an [`EnumeratedEntry::Other`]
/// — never a semantic identity, never a deletion candidate).
fn enumerate_dirs(root: &Path, kind: EntryKind) -> Result<Vec<EnumeratedEntry>> {
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
                    let name = entry.file_name().to_string_lossy().into_owned();
                    let parsed = match kind {
                        EntryKind::Release => ReleaseId::parse(&name).map(EnumeratedEntry::Release),
                        EntryKind::Tree => TreeDigest::parse(&name).map(EnumeratedEntry::Tree),
                    };
                    out.push(parsed.unwrap_or(EnumeratedEntry::Other(name)));
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::store(format!("read_dir {}: {e}", root.display()))),
    }
    // Sort by the raw name for determinism (the deletion order is the sorted
    // enumeration).
    out.sort_by(|a, b| a.identity().cmp(&b.identity()));
    Ok(out)
}

impl LocalStore {
    /// Run the global artifact garbage collection against an ALREADY-BUILT
    /// locked [`ReachabilitySnapshot`]: unlink every release record and tree
    /// object the SNAPSHOT's retained sets exclude. See the module docs for
    /// the reachability model, the failure model, and the durability
    /// protocol.
    ///
    /// THERE IS NO SCAN HERE — and there CANNOT be: the caller's ONE locked
    /// snapshot ([`LocalStore::reachability_snapshot`], built by
    /// [`LocalStore::run_sweep`]) is the single deletion authority, and this
    /// pass consumes ONLY its retained sets. A separately-read source that
    /// could drift from the snapshot is never consulted by a deletion stage.
    ///
    /// `anchor` names the triggering checkpoint's deployment id: it is used
    /// ONLY as the per-fixture fault-injection key — production behavior
    /// never depends on it.
    pub(crate) fn gc_artifacts(
        &self,
        #[cfg(test)] anchor: &str,
        snapshot: &ReachabilitySnapshot,
    ) -> Result<GcOutcome> {
        // `anchor` is the test-only fault-registry key (see the deletion
        // functions) — the argument exists only under `#[cfg(test)]`.
        #[cfg(test)]
        let releases = self.delete_unretained_releases(anchor, snapshot)?;
        #[cfg(not(test))]
        let releases = self.delete_unretained_releases(snapshot)?;
        // FAIL CLOSED: a failed release stage stops the artifact pass — the
        // tree stage stays PENDING (its candidates are planned, nothing
        // removed). The tree candidates are still enumerated so the planned
        // count is exact (against the SAME snapshot's retained trees).
        let trees = if releases.completed {
            #[cfg(test)]
            let trees = self.delete_unretained_trees(anchor, snapshot)?;
            #[cfg(not(test))]
            let trees = self.delete_unretained_trees(snapshot)?;
            trees
        } else {
            let planned =
                match enumerate_dirs(&self.base().join(layout::objects()), EntryKind::Tree) {
                    Ok(entries) => entries
                        .iter()
                        .filter(|e| match e.identity() {
                            Some(id) => !snapshot.trees.contains(id),
                            // An unrecognized entry is never in the retained set
                            // (which only contains validated identities) — it is
                            // unreachable garbage.
                            None => true,
                        })
                        .count(),
                    Err(_) => 0,
                };
            SweepStageStats {
                planned,
                removed: 0,
                completed: false,
            }
        };
        Ok(GcOutcome {
            completed: releases.completed && trees.completed,
            planned_releases: releases.planned,
            planned_trees: trees.planned,
            removed_releases: releases.removed,
            removed_trees: trees.removed,
        })
    }

    /// Unlink every release record NOT in the snapshot's retained set, then
    /// fsync the `releases/` parent so the unlinks are durable. A deletion is
    /// TRI-STATE: an already-removed dir (a previous interrupted pass) is a
    /// skip. FAIL CLOSED: ANY stat, unlink, or fsync failure STOPS the
    /// stage — the removed count reports exactly the successful unlinks and
    /// the remaining candidates stay PENDING (planned, never reported as
    /// removed). The ONLY `Err` here is a root-enumeration read failure,
    /// which aborts the pass BEFORE any deletion. The retained set comes
    /// from the caller's ONE locked snapshot — no re-read that could drift.
    ///
    /// `anchor` is TEST-ONLY: the per-fixture fault registry's key (the
    /// triggering checkpoint's deployment id); production never depends on
    /// it.
    fn delete_unretained_releases(
        &self,
        #[cfg(test)] anchor: &str,
        snapshot: &ReachabilitySnapshot,
    ) -> Result<SweepStageStats> {
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
        let mut candidates = enumerate_dirs(&root, EntryKind::Release)?;
        // Keep the deletion candidates: a RECOGNIZED release record NOT in
        // the retained set, or an UNRECOGNIZED entry (a stray file, a
        // malformed name) — never compared against the retained sets as a
        // semantic identity, but still unreachable garbage (the retained
        // sets only contain validated identities).
        candidates.retain(|e| match e.identity() {
            Some(id) => !snapshot.releases.contains(id),
            None => true,
        });
        let planned = candidates.len();
        let mut removed = 0usize;
        for entry in &candidates {
            let dir = match entry {
                EnumeratedEntry::Release(id) => self.release_dir(id),
                EnumeratedEntry::Other(name) => self.base().join(layout::RELEASES).join(name),
                EnumeratedEntry::Tree(_) => {
                    unreachable!("a tree entry is never a release candidate")
                }
            };
            // TRI-STATE: an already-removed dir (a previous interrupted
            // pass) is a skip — it is neither removed now nor pending. ANY
            // other stat failure stops the stage (fail closed) with the
            // successful-unlink count so far.
            let present = match path_state(&dir) {
                Ok(p) => p,
                Err(_) => {
                    return Ok(SweepStageStats {
                        planned,
                        removed,
                        completed: false,
                    });
                }
            };
            if !present {
                continue;
            }
            // Test-only per-candidate fault hook: the K-TH release unlink
            // fails — the stage aborts (fail closed), the count stays at the
            // successful unlinks so far, and the remaining candidates stay
            // pending.
            #[cfg(test)]
            if self
                .fault_registry()
                .consume_unlink(FaultKind::GcUnlinkReleases, anchor)
            {
                return Ok(SweepStageStats {
                    planned,
                    removed,
                    completed: false,
                });
            }
            if std::fs::remove_dir_all(&dir).is_err() {
                // FAIL CLOSED: the unlink failed — stop the stage. The
                // failed candidate and everything after it stay pending;
                // only the successful unlinks count as removed.
                return Ok(SweepStageStats {
                    planned,
                    removed,
                    completed: false,
                });
            }
            removed += 1;
        }
        // Durable unlink: without the parent fsync the removal may not
        // survive power loss and the space is not reclaimed. A failed fsync
        // leaves the stage incomplete (the unlinks are not yet durable) —
        // the counts still report exactly what was unlinked.
        if sync_parent_dir(&root).is_err() {
            return Ok(SweepStageStats {
                planned,
                removed,
                completed: false,
            });
        }
        Ok(SweepStageStats {
            planned,
            removed,
            completed: true,
        })
    }

    /// Unlink every tree object NOT in the snapshot's retained tree set,
    /// then fsync the `objects/sha256/` parent. Same tri-state and fail-closed
    /// rules as the release phase: a failure stops the stage and the
    /// remaining candidates stay pending (planned, never reported as
    /// removed). The retained set comes from the caller's ONE locked
    /// snapshot — no re-read that could drift. `anchor` is TEST-ONLY (the
    /// fault registry's key, like the release stage's).
    fn delete_unretained_trees(
        &self,
        #[cfg(test)] anchor: &str,
        snapshot: &ReachabilitySnapshot,
    ) -> Result<SweepStageStats> {
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
        let mut candidates = enumerate_dirs(&root, EntryKind::Tree)?;
        // Keep the deletion candidates: a RECOGNIZED tree object NOT in the
        // retained set, or an UNRECOGNIZED entry (never compared against the
        // retained sets as a semantic identity, but still unreachable
        // garbage).
        candidates.retain(|e| match e.identity() {
            Some(id) => !snapshot.trees.contains(id),
            None => true,
        });
        let planned = candidates.len();
        let mut removed = 0usize;
        for entry in &candidates {
            let dir = match entry {
                EnumeratedEntry::Tree(digest) => {
                    // The digest directory itself (`objects/sha256/<digest>/`),
                    // holding `root/` and `tree.json`.
                    self.base().join(layout::objects()).join(digest.as_str())
                }
                EnumeratedEntry::Other(name) => self.base().join(layout::objects()).join(name),
                EnumeratedEntry::Release(_) => {
                    unreachable!("a release entry is never a tree candidate")
                }
            };
            let present = match path_state(&dir) {
                Ok(p) => p,
                Err(_) => {
                    return Ok(SweepStageStats {
                        planned,
                        removed,
                        completed: false,
                    });
                }
            };
            if !present {
                continue;
            }
            // Test-only per-candidate fault hook: the K-TH tree unlink
            // fails — the stage aborts (fail closed), the count stays at the
            // successful unlinks so far, and the remaining candidates stay
            // pending.
            #[cfg(test)]
            if self
                .fault_registry()
                .consume_unlink(FaultKind::GcUnlinkTrees, anchor)
            {
                return Ok(SweepStageStats {
                    planned,
                    removed,
                    completed: false,
                });
            }
            if std::fs::remove_dir_all(&dir).is_err() {
                // FAIL CLOSED: the unlink failed — stop the stage. The
                // failed candidate and everything after it stay pending;
                // only the successful unlinks count as removed.
                return Ok(SweepStageStats {
                    planned,
                    removed,
                    completed: false,
                });
            }
            removed += 1;
        }
        // Durable unlink (see the release stage).
        if sync_parent_dir(&root).is_err() {
            return Ok(SweepStageStats {
                planned,
                removed,
                completed: false,
            });
        }
        Ok(SweepStageStats {
            planned,
            removed,
            completed: true,
        })
    }
}

// ---------------------------------------------------------------------------
// FAIL-CLOSED ANCHOR TESTS
//
// The user-reported bug: "GC treats unreadable retention anchors as absent".
// A PRESENT-but-unreadable anchor (a permission error, corrupt content, a
// torn record) must be an ERROR — never ABSENCE — because an anchor that
// reads as absent shrinks the retained set and the sweep then deletes
// REACHABLE artifacts (data loss). The tests below corrupt EACH retention
// anchor class INDEPENDENTLY and assert: corrupt → the sweep errors with
// ZERO deletions (the pre-sweep artifact inventory is byte-identical);
// repair → the retry deletes EXACTLY the unreachable set (the
// retained/garbage partition matches the oracle). The property generates
// the retained+garbage partitions (bounded 16 cases, house fixed seed); the
// unit tests pin each class deterministically.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SlotConfig;
    use crate::identity::{
        ArtifactRef, ServerId, SlotId, TargetName, TreeDigest, VariantName, test_deployment_id,
        test_generation_id, test_tree_digest,
    };
    use crate::ledger::{
        DeploymentIntent, LedgerTerminal, Observation, ObservationError, ObservedAssignment,
        ObservedSlot, Pins, PreviousGeneration,
    };
    #[cfg(test)]
    use proptest::prelude::*;
    #[cfg(test)]
    use proptest::test_runner::RngSeed;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    const TARGET: &str = "t1";
    const SLOT: &str = "p1";

    /// A minimal but VALID variant file (the config loader requires a real
    /// variant: mappings, activation, verification, and the slot's ONE
    /// retention policy).
    const VARIANT_TOML: &str = r#"
[artifact]
mappings = []

[[slots]]
id = "p1"
server = "s1"
target = "t1"
groups = []
deploy_dir = "/srv"

[retention.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[retention.deployment]
protect_deployments = 1

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

    /// The project file for the fixtures: one server, one target, and —
    /// when `pinned` is given — a durable `[[pins]]` entry naming a release.
    fn config_with_pin(base: &std::path::Path, pinned: Option<&ReleaseId>) -> ProjectConfig {
        let project = base.join("proj");
        std::fs::create_dir_all(project.join("releases").join("v1")).unwrap();
        std::fs::write(
            project.join("releases").join("v1").join("standard.toml"),
            VARIANT_TOML,
        )
        .unwrap();
        let mut deploy = format!(
            "schema_version = 2\napplication = \"gc\"\nrelease = \"v1\"\n\n\
             [[servers]]\nid = \"s1\"\naddress = \"a\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n\
             [targets.{TARGET}]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n"
        );
        if let Some(p) = pinned {
            deploy.push_str(&format!(
                "\n[[pins]]\nrelease = \"{p}\"\nreason = \"keep\"\n"
            ));
        }
        std::fs::write(project.join("deploy.toml"), deploy).unwrap();
        ProjectConfig::load(&project.join("deploy.toml")).unwrap()
    }

    /// Write a REAL release record (content-derived id) with one variant
    /// tree `tree-pinned-<tag>`, and return the id it actually got — pins
    /// must reference the id the record got.
    fn seed_real_release(store: &LocalStore, tag: &str) -> ReleaseId {
        let rec = crate::verify::release::build_release(
            "gc",
            "sha256-aa",
            &BTreeMap::from([(
                VariantName::parse("standard").unwrap(),
                test_tree_digest(&format!("tree-pinned-{tag}")),
            )]),
            &BTreeMap::from([(
                "standard".to_string(),
                vec![SlotConfig::new(
                    SLOT.to_string(),
                    "s1".to_string(),
                    PathBuf::from("/srv/deploy/p1"),
                    TARGET.to_string(),
                    Vec::new(),
                )],
            )]),
            std::path::Path::new("."),
        );
        let id = ReleaseId::new(rec.release_id.clone());
        store.write_release(&rec).unwrap();
        id
    }

    /// A deployment's LEDGER record: intent + SUCCESSFUL terminal whose
    /// rollback references `release` / `tree`.
    /// A deployment's LEDGER record: intent + SUCCESSFUL terminal whose
    /// rollback references `release` / `tree`. The intent satisfies EXACT
    /// key-set equality (`slot_ids == desired == pre_push`).
    #[allow(dead_code)]
    fn intent(id: &str) -> DeploymentIntent {
        intent_full(
            id,
            "rel-1",
            "tree-1",
            "/srv/deploy/p1",
            crate::ledger::Observation::KnownAbsent,
        )
    }

    /// A single-slot (`p1`) VALID intent: the frozen snapshot entry
    /// (generation gen-1, the given artifact release/tree, plan-time
    /// physical binding at the given deploy dir) + the optional KNOWN
    /// pre-push state. The snapshot's desired facts MATCH the rollback
    /// `terminal_for` builds (the new shared validator requires the match).
    fn intent_full(
        id: &str,
        release: &str,
        tree: &str,
        deploy_dir: &str,
        pre_push: crate::ledger::Observation<PreviousGeneration>,
    ) -> DeploymentIntent {
        intent_full_over(id, release, tree, deploy_dir, pre_push, None)
    }

    /// [`intent_full`] planned against a parent (the current successful head)
    /// — the lineage invariant (at most one `Successful` per parent) requires
    /// every seeded successful to chain onto the previous one.
    fn intent_full_over(
        id: &str,
        release: &str,
        tree: &str,
        deploy_dir: &str,
        pre_push: crate::ledger::Observation<PreviousGeneration>,
        head: Option<&DeploymentIntent>,
    ) -> DeploymentIntent {
        use crate::kernel::intent::{PlanInput, PlannedDeploy};
        use crate::kernel::snapshot::SnapshotSlot;
        let p1 = SlotId::new(SLOT.to_string());
        crate::kernel::intent::plan(PlanInput {
            deployment_id: test_deployment_id(id),
            target: TargetName::new(TARGET.to_string()),
            parent: head.map(|h| h.deployment_id().clone()),
            parent_snapshot: head.map(|h| h.resulting_snapshot()),
            group: None,
            selection: vec![p1.clone()],
            planned: vec![PlannedDeploy {
                slot: p1.clone(),
                result: SnapshotSlot::new(
                    test_generation_id("gen-1"),
                    ArtifactRef {
                        release: crate::identity::test_release_id(release),
                        variant: VariantName::parse("standard").unwrap(),
                        tree: test_tree_digest(tree),
                    },
                    crate::ledger::PhysicalBinding::from_config(
                        ServerId::parse("s1").unwrap(),
                        deploy_dir,
                    )
                    .expect("test binding is absolute and traversal-free"),
                ),
                pre_push,
            }],
            behavior_digest: crate::identity::BehaviorDigest::parse(
                crate::identity::DIGEST_TEST_HEX_1,
            )
            .unwrap(),
            attempted_at: crate::identity::Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        })
        .expect("fixture intent always plans")
    }

    /// An ARBITRARY but VALID artifact: canonical `rel-sha256-<64hex>`
    /// release and `<64hex>` tree digest (the strict parsers accept exactly
    /// the generated forms), fixed variant. Used as the `Known` payload of a
    /// generated pre-push assignment observation.
    fn arbitrary_artifact() -> impl Strategy<Value = ArtifactRef> {
        ("[a-f0-9]{64}", "[a-f0-9]{64}").prop_map(|(rel, tree)| ArtifactRef {
            release: ReleaseId::parse(&format!("rel-sha256-{rel}"))
                .expect("generated hex is a canonical release id"),
            variant: VariantName::parse("standard").unwrap(),
            tree: TreeDigest::parse(&tree).expect("generated hex is a valid tree digest"),
        })
    }

    /// The GENERATED ASSIGNMENT-READ space: `Unknown(error)` with an
    /// arbitrary message (the read FAILED — the user's requirement), plus
    /// `KnownAbsent` (never deployed) and `Known(arbitrary artifact)` (a
    /// successful read — the positive control). This is exactly the value
    /// space the engine's pre-push/refresh fallback produces.
    fn arbitrary_assignment_observation() -> impl Strategy<Value = Observation<ArtifactRef>> {
        prop_oneof![
            prop::collection::vec(any::<char>(), 0..64)
                .prop_map(|v| v.into_iter().collect::<String>())
                .prop_map(|message| Observation::Unknown(ObservationError { message })),
            Just(Observation::KnownAbsent),
            arbitrary_artifact().prop_map(Observation::Known),
        ]
    }

    #[allow(dead_code)]
    fn arbitrary_pre_push() -> impl Strategy<Value = crate::ledger::Observation<PreviousGeneration>>
    {
        use crate::kernel::snapshot::PreviousGeneration;
        arbitrary_assignment_observation().prop_map(|obs| match obs {
            Observation::Known(a) => crate::ledger::Observation::Known(PreviousGeneration {
                generation: test_generation_id("gen-pre"),
                artifact: a,
            }),
            Observation::Unknown(e) => crate::ledger::Observation::Unknown(e),
            Observation::KnownAbsent => crate::ledger::Observation::KnownAbsent,
        })
    }

    fn intent_with_pre_push(
        pre_push: crate::ledger::Observation<PreviousGeneration>,
    ) -> DeploymentIntent {
        intent_full(
            "deploy-prop-unknown",
            "desired-rel",
            "tree-desired",
            "/srv/deploy/p1",
            pre_push,
        )
    }

    /// A SUCCESSFUL terminal BOUND to the given intent (payload-free; the
    /// snapshot resolves from the intent's slot table).
    fn terminal_for(intent: &DeploymentIntent) -> LedgerTerminal {
        crate::testutil::fixtures::successful_terminal(intent)
    }

    fn seed_named_release(store: &LocalStore, name: &str) {
        let dir = store.release_dir(&ReleaseId::new(name.to_string()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("release.json"), "{}").unwrap();
    }

    /// Create a tree object directory under the given digest.
    fn seed_object(store: &LocalStore, tree: &str) {
        let dir = store.object_root(&TreeDigest::new(tree.to_string()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("file"), "x").unwrap();
    }

    /// Create a deployment record dir (`deployments/<id>/plan.json`).
    fn seed_deployment_dir(store: &LocalStore, id: &str) {
        let dir = store.deployment_dir_named(id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plan.json"), "{}").unwrap();
    }

    /// The five retention anchor classes, corrupted INDEPENDENTLY.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum AnchorClass {
        /// Target's whole LEDGER becomes unreadable (garbage bytes replace
        /// the deployment history).
        Ledger,
        /// The OBSERVED slot record (`slots/<slot>/observed.json`) becomes
        /// unreadable (garbage bytes).
        Observed,
        /// The store PINS file (`pins.json`) becomes unreadable/malformed.
        PinsJson,
        /// A release record a PIN names becomes unreadable (garbage bytes).
        PinnedRelease,
        /// A deployment record in the ledger is TORN (a partial trailing
        /// line — the documented crash-mid-append corruption).
        DeploymentRecord,
    }

    const ANCHOR_CLASSES: [AnchorClass; 5] = [
        AnchorClass::Ledger,
        AnchorClass::Observed,
        AnchorClass::PinsJson,
        AnchorClass::PinnedRelease,
        AnchorClass::DeploymentRecord,
    ];

    /// One generated partition + the physical anchor bytes a case needs to
    /// CORRUPT each anchor class and then REPAIR it.
    struct Fixture {
        store: LocalStore,
        config: ProjectConfig,
        /// The release the deploy.toml pin names (real record on disk).
        cfg_pin: ReleaseId,
        /// The release pins.json pins (real record on disk).
        store_pin: ReleaseId,
        retained_releases: Vec<String>,
        retained_trees: Vec<String>,
        garbage_releases: Vec<String>,
        garbage_trees: Vec<String>,
        retained_deployments: Vec<String>,
        ghost_deployment: String,
        observed_bytes: Vec<u8>,
        pins_bytes: Vec<u8>,
        pinned_bytes: Vec<u8>,
        ledger_text: String,
    }

    fn build_fixture(base: &std::path::Path, retained: usize, garbage: usize) -> Fixture {
        let store = LocalStore::with_base(base.join("store")).unwrap();
        let cfg_pin = seed_real_release(&store, "cfg");
        let store_pin = seed_real_release(&store, "store");
        let config = config_with_pin(base, Some(&cfg_pin));

        // The target's ledger: `retained` successful deployment records,
        // each rolling back to `rel-sha256-ret-<i>` / `tree-ret-<i>`. The
        // ledger ids and tree digests are the CANONICAL (validated) forms.
        let mut retained_deployments = Vec::new();
        let mut head: Option<DeploymentIntent> = None;
        for i in 0..retained {
            let id = format!("deploy-ret-{i}");
            let canonical = test_deployment_id(&id);
            // Build a matching intent whose frozen snapshot
            // generation/artifact/binding equals the terminal's rollback,
            // chaining onto the CURRENT successful head (the lineage
            // invariant — at most one `Successful` per parent).
            let matching_intent = intent_full_over(
                &id,
                &format!("ret-{i}"),
                &format!("tree-ret-{i}"),
                "/srv/eng",
                crate::ledger::Observation::KnownAbsent,
                head.as_ref(),
            );
            store.test_append_intent(TARGET, &matching_intent).unwrap();
            store
                .test_append_terminal(TARGET, &canonical, &terminal_for(&matching_intent))
                .unwrap();
            retained_deployments.push(canonical.as_str().to_string());
            head = Some(matching_intent);
        }
        let ledger_text = std::fs::read_to_string(store.ledger_path(TARGET)).unwrap_or_default();

        // The observed slot state (the ONE physical observed record).
        let observed = ObservedSlot {
            slot: SlotId::new(SLOT.to_string()),
            assignment: ObservedAssignment::Known {
                generation: test_generation_id("gen-obs"),
                artifact: ArtifactRef {
                    release: crate::identity::test_release_id("rel-sha256-obs"),
                    variant: VariantName::parse("standard").unwrap(),
                    tree: test_tree_digest("tree-obs"),
                },
                last_deployment: test_deployment_id("deploy-obs"),
                owner: Some(crate::remote::helper::test_owner("test-app", "s1")),
                version: Some("2026-01-01T00:00:00Z".to_string()),
            },
        };
        store
            .write_slot_observed(&SlotId::new(SLOT.to_string()), &observed)
            .unwrap();
        let observed_path = store.slot_observed_path(&SlotId::new(SLOT.to_string()));
        let observed_bytes = std::fs::read(&observed_path).unwrap();

        // Store-level pins: a whole-release pin on `store_pin` AND an exact
        // binding pin on the same release's `tree-pinned-store` tree.
        let pins = Pins::empty()
            .with_release(store_pin.clone())
            .with_binding(ArtifactRef {
                release: store_pin.clone(),
                variant: VariantName::parse("standard").unwrap(),
                tree: test_tree_digest("tree-pinned-store"),
            });
        store.write_pins(&pins).unwrap();
        let pins_bytes = std::fs::read(store.pins_path()).unwrap();
        let pinned_bytes = std::fs::read(store.release_dir(&cfg_pin).join("release.json")).unwrap();

        // Physical dirs for every retained reference. The pinned releases'
        // dirs already exist (written by `write_release`); the rest get
        // junk-named dirs (kept/swept by NAME — only pinned records are
        // read). Every name here is the CANONICAL form the ledger/observed
        // record/pin references (the observed slot references
        // `test_release_id("rel-sha256-obs")`, so its dir carries the same
        // canonical id).
        let mut retained_releases = vec![
            crate::identity::test_release_id("rel-sha256-obs")
                .as_str()
                .to_string(),
        ];
        let mut retained_trees = vec![test_tree_digest("tree-obs").as_str().to_string()];
        for i in 0..retained {
            retained_releases.push(
                crate::identity::test_release_id(&format!("ret-{i}"))
                    .as_str()
                    .to_string(),
            );
            retained_trees.push(
                test_tree_digest(&format!("tree-ret-{i}"))
                    .as_str()
                    .to_string(),
            );
        }
        retained_releases.push(cfg_pin.as_str().to_string());
        retained_trees.push(test_tree_digest("tree-pinned-cfg").as_str().to_string());
        retained_releases.push(store_pin.as_str().to_string());
        retained_trees.push(test_tree_digest("tree-pinned-store").as_str().to_string());
        for r in &retained_releases {
            if r == cfg_pin.as_str() || r == store_pin.as_str() {
                continue;
            }
            seed_named_release(&store, r);
        }
        for t in &retained_trees {
            seed_object(&store, t);
        }

        // The garbage partition (referenced by NOTHING).
        let mut garbage_releases = Vec::new();
        let mut garbage_trees = Vec::new();
        for i in 0..garbage {
            let r = crate::identity::test_release_id(&format!("garbage-{i}"))
                .as_str()
                .to_string();
            let t = test_tree_digest(&format!("tree-garbage-{i}"))
                .as_str()
                .to_string();
            seed_named_release(&store, &r);
            seed_object(&store, &t);
            garbage_releases.push(r);
            garbage_trees.push(t);
        }
        // The sweep's discard lists are SORTED (deletion order is the sorted
        // enumeration), so the oracle lists must be sorted too.
        garbage_releases.sort();
        garbage_trees.sort();
        retained_trees.sort();

        // Deployment dirs: the reachable ones + the ghost (canonical ids —
        // the ledger references the validated forms).
        for id in &retained_deployments {
            seed_deployment_dir(&store, id);
        }
        seed_deployment_dir(&store, test_deployment_id("deploy-obs").as_str());
        let ghost_deployment = test_deployment_id("deploy-ghost").as_str().to_string();
        seed_deployment_dir(&store, &ghost_deployment);

        Fixture {
            store,
            config,
            cfg_pin,
            store_pin,
            retained_releases,
            retained_trees,
            garbage_releases,
            garbage_trees,
            retained_deployments,
            ghost_deployment,
            observed_bytes,
            pins_bytes,
            pinned_bytes,
            ledger_text,
        }
    }

    /// The byte-level artifact inventory of the three sweep roots
    /// (`deployments/`, `releases/`, `objects/sha256/`): every relative path
    /// with its bytes. A corrupt-anchor pass must leave this EXACTLY
    /// unchanged (zero deletions).
    fn inventory(store: &LocalStore) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        for (rel_root, abs) in [
            ("deployments", store.base().join("deployments")),
            (
                "releases",
                store.base().join(crate::remote::layout::RELEASES),
            ),
            (
                "objects/sha256",
                store.base().join(crate::remote::layout::objects()),
            ),
        ] {
            if abs.exists() {
                collect_files(&abs, rel_root, &mut out);
            }
        }
        out.sort();
        out
    }

    fn collect_files(dir: &std::path::Path, rel: &str, out: &mut Vec<(String, Vec<u8>)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let child_rel = format!("{rel}/{}", entry.file_name().to_string_lossy());
            if path.is_dir() {
                collect_files(&path, &child_rel, out);
            } else {
                out.push((child_rel, std::fs::read(&path).unwrap()));
            }
        }
    }

    /// Corrupt ONE anchor class (present-but-unreadable, never absent).
    fn corrupt(f: &Fixture, class: AnchorClass) {
        match class {
            AnchorClass::Ledger => {
                // The whole deployment history becomes unreadable.
                std::fs::write(f.store.ledger_path(TARGET), "{ not json !\n").unwrap();
            }
            AnchorClass::Observed => {
                let p = f.store.slot_observed_path(&SlotId::new(SLOT.to_string()));
                std::fs::write(&p, "{ not json !\n").unwrap();
            }
            AnchorClass::PinsJson => {
                std::fs::write(f.store.pins_path(), "{ not json !\n").unwrap();
            }
            AnchorClass::PinnedRelease => {
                let p = f.store.release_dir(&f.cfg_pin).join("release.json");
                std::fs::write(&p, "{ not json !\n").unwrap();
            }
            AnchorClass::DeploymentRecord => {
                // A deployment record is TORN (a partial trailing line — the
                // documented crash-mid-append corruption).
                let mut text = std::fs::read_to_string(f.store.ledger_path(TARGET)).unwrap();
                text.push_str("{\"kind\":\"terminal\",\"deployment_id\":\"deploy-");
                std::fs::write(f.store.ledger_path(TARGET), text).unwrap();
            }
        }
    }

    /// Repair the anchor so the retry recomputes reachability fresh.
    fn repair(f: &Fixture, class: AnchorClass) {
        match class {
            AnchorClass::Ledger | AnchorClass::DeploymentRecord => {
                std::fs::write(f.store.ledger_path(TARGET), &f.ledger_text).unwrap();
            }
            AnchorClass::Observed => {
                let p = f.store.slot_observed_path(&SlotId::new(SLOT.to_string()));
                std::fs::write(&p, &f.observed_bytes).unwrap();
            }
            AnchorClass::PinsJson => {
                std::fs::write(f.store.pins_path(), &f.pins_bytes).unwrap();
            }
            AnchorClass::PinnedRelease => {
                let p = f.store.release_dir(&f.cfg_pin).join("release.json");
                std::fs::write(&p, &f.pinned_bytes).unwrap();
            }
        }
    }

    /// One corrupt → zero-deletions → repair → exact-retry cycle for one
    /// anchor class over one generated partition.
    fn run_anchor_case(class: AnchorClass, retained: usize, garbage: usize) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let f = build_fixture(dir.path(), retained, garbage);

        // CORRUPT the anchor: the sweep must FAIL before any deletion — the
        // pre-sweep artifact inventory stays byte-identical.
        corrupt(&f, class);
        let before = inventory(&f.store);
        let err = f.store.run_sweep(&f.config, "anchor", None).unwrap_err();
        match class {
            // Requirement 2: a pin that cannot be honored aborts the sweep
            // with an INTEGRITY error before any deletion.
            AnchorClass::PinnedRelease => {
                assert!(
                    matches!(err, Error::Integrity(_)),
                    "an un-honorable pinned release must abort the sweep with an integrity error, got: {err}"
                );
            }
            _ => assert!(
                err.to_string().contains("ledger")
                    || err.to_string().contains("observed")
                    || err.to_string().contains("pins"),
                "the sweep must fail on the corrupted {class:?} anchor, got: {err}"
            ),
        }
        assert_eq!(
            inventory(&f.store),
            before,
            "corrupt {class:?}: the sweep must perform ZERO deletions"
        );

        // REPAIR the anchor: the retry recomputes reachability and deletes
        // EXACTLY the unreachable set — the retained/garbage partition
        // matches the oracle.
        repair(&f, class);
        let (discards, complete) = f.store.run_sweep(&f.config, "anchor", None).unwrap();
        assert!(complete, "the repaired sweep completes");
        assert_eq!(
            discards.sweep_deployments,
            vec![f.ghost_deployment.clone()],
            "exactly the ghost deployment dir is swept"
        );
        assert_eq!(
            discards.sweep_releases, f.garbage_releases,
            "exactly the garbage release records are swept"
        );
        assert_eq!(
            discards.sweep_objects, f.garbage_trees,
            "exactly the garbage tree objects are swept"
        );
        for id in &f.retained_deployments {
            assert!(
                f.store.deployment_dir_named(id).exists(),
                "retained deployment {id} must survive"
            );
        }
        assert!(
            f.store
                .deployment_dir(&test_deployment_id("deploy-obs"))
                .exists(),
            "the observed last deployment survives"
        );
        assert!(
            !f.store.deployment_dir_named(&f.ghost_deployment).exists(),
            "the ghost deployment dir is gone"
        );
        for r in &f.garbage_releases {
            assert!(
                !f.store.release_dir(&ReleaseId::new(r.clone())).exists(),
                "garbage release {r} must be swept"
            );
        }
        for t in &f.garbage_trees {
            assert!(
                !f.store.object_root(&TreeDigest::new(t.clone())).exists(),
                "garbage tree {t} must be swept"
            );
        }
        for r in &f.retained_releases {
            assert!(
                f.store.release_dir(&ReleaseId::new(r.clone())).exists(),
                "retained release {r} must survive"
            );
        }
        for t in &f.retained_trees {
            assert!(
                f.store.object_root(&TreeDigest::new(t.clone())).exists(),
                "retained tree {t} must survive"
            );
        }
        assert!(
            f.store.release_dir(&f.store_pin).exists(),
            "the store-pinned release survives"
        );
    }

    // ---- the property ------------------------------------------------------

    proptest! {
        // THE PROPERTY: for a GENERATED retained+garbage partition, corrupt
        // EACH anchor class independently: the sweep errors with ZERO
        // deletions, and after REPAIRING the anchor the retry deletes
        // EXACTLY the unreachable set. Bounded `proptest_cases(4)` (full 4
        // with `DEPLOY_FULL_TESTS=1`, fast default) + fixed seed per
        // house style (each case builds 5 small fixtures — one per anchor
        // class — so the bound keeps the suite fast).
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(4),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn gc_unreadable_anchors_fail_closed_and_recover_exactly(
            retained in 1usize..=3,
            garbage in 1usize..=3,
        ) {
            for class in ANCHOR_CLASSES {
                run_anchor_case(class, retained, garbage);
            }
        }
    }

    // ---- THE USER'S PROPERTY: an assignment-read failure is a distinct
    // ---- THE USER'S PROPERTY: an assignment-read failure is a distinct
    // value, never an artifact, and never a reachability anchor -------------

    /// Run ONE generated pre-push assignment observation through the REAL
    /// collection logic: the intent is appended to a REAL store and the REAL
    /// [`LocalStore::reachability_snapshot`] scan reads it back through the wire
    /// (append_intent → read_ledger → into_domain) and collects the
    /// reachability entries. This is the production code path the sweep and
    /// the checkpoint preview share — not a copy of its logic.
    fn run_assignment_observation_case(pre_push: crate::ledger::Observation<PreviousGeneration>) {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let config = config_with_pin(tmp.path(), None);
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let intent = intent_with_pre_push(pre_push.clone());
        store.test_append_intent(TARGET, &intent).unwrap();

        // ---- 1. The pre-push state round-trips EXACTLY through the wire —
        // the observation is the frozen fact (Known prior state,
        // KnownAbsent, or the preserved Unknown read failure).
        let entries = store.read_ledger(TARGET).unwrap();
        let read_back = entries[0].intent.pre_push(&SlotId::new(SLOT.to_string()));
        assert_eq!(
            read_back,
            Some(&pre_push),
            "the pre-push state must round-trip the wire EXACTLY — \
             no prior state contributes nothing, a known state never changes"
        );

        // ---- 2. The reachability effect, through the REAL collection logic:
        // `KnownAbsent` (no prior state) contributes NOTHING beyond the
        // desired artifact; a KNOWN pre-push DOES contribute its release +
        // tree; an UNKNOWN pre-push (the read failed) FAILS the sweep
        // closed (the sweep cannot verify what the slot ran before the
        // attempt, so reachability would be incomplete).
        match &pre_push {
            crate::ledger::Observation::KnownAbsent => {
                let retained = store.reachability_snapshot(&config, None).unwrap();
                assert_eq!(
                    retained.releases.len(),
                    1,
                    "no prior state contributes nothing: only the desired release is retained, got {retained:?}"
                );
                assert_eq!(
                    retained.trees.len(),
                    1,
                    "no prior state contributes nothing: only the desired tree is retained, got {retained:?}"
                );
                assert!(
                    retained
                        .releases
                        .contains(crate::identity::test_release_id("desired-rel").as_str())
                );
                assert!(
                    retained
                        .trees
                        .contains(test_tree_digest("tree-desired").as_str())
                );
            }
            crate::ledger::Observation::Known(prev) => {
                let retained = store.reachability_snapshot(&config, None).unwrap();
                assert!(
                    retained.releases.contains(prev.artifact.release.as_str()),
                    "a Known pre-push artifact retains its release, got {retained:?}"
                );
                assert!(
                    retained.trees.contains(prev.artifact.tree.as_str()),
                    "a Known pre-push artifact retains its tree, got {retained:?}"
                );
            }
            crate::ledger::Observation::Unknown(_) => {
                let err = store.reachability_snapshot(&config, None).unwrap_err();
                assert!(
                    err.to_string().contains("pre-push"),
                    "an Unknown pre-push MUST fail the reachability sweep closed, got: {err}"
                );
            }
        }

        // ---- 3. NO domain value simultaneously means "unknown" and "known
        // artifact": the only carrier of an `ArtifactRef` is the `Known`
        // variant — `Unknown` holds ONLY an `ObservationError` and
        // `KnownAbsent` holds nothing, so neither can ever be mistaken for a
        // known artifact. An `ArtifactRef` born from the domain pre-push is
        // real and known.
        if let crate::ledger::Observation::Known(prev) = &pre_push {
            assert!(prev.artifact.release.as_str().starts_with("rel-sha256-"));
            assert!(prev.artifact.tree.as_str().len() == 64);
        }
    }

    proptest! {
        // THE USER'S PROPERTY: GENERATED pre-push observations (no prior
        // state / arbitrary KNOWN artifacts / preserved read failures) must
        // round-trip EXACTLY through the real wire and never leak an
        // invented artifact into reachability (a `Known` prior state reaches
        // what it names; `KnownAbsent` contributes nothing; an `Unknown`
        // pre-push fails the sweep closed). Bounded
        // `proptest_cases(16)` (full 16 with `DEPLOY_FULL_TESTS=1`), fixed
        // seed 0x5EED_5EED (house style), no persistence.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn pre_push_round_trips_exactly_and_reaches_what_it_names(
            pre_push in arbitrary_pre_push(),
        ) {
            run_assignment_observation_case(pre_push);
        }
    }

    /// The DETERMINISTIC companion: the pre-push observation FREEZES the
    /// preserved read failure as an `Unknown` (a distinct value that never
    /// looks like an artifact) — a successful read showing no state is
    /// `KnownAbsent` (never deployed) — and neither can ever be re-read as
    /// a known `GenerationRef`: the only carrier of an `ArtifactRef` is the
    /// `Known` variant, and the reachability sweep fails closed on the
    /// `Unknown` (see part 2 above).
    #[test]
    fn unreadable_pre_push_wire_fails_closed() {
        let intent = intent_with_pre_push(crate::ledger::Observation::Unknown(ObservationError {
            message: "assignment read failed: fixture corruption".to_string(),
        }));
        store_round_trip_keeps_unknown(intent);
    }

    /// Round-trip helper: the unknown pre-push observation survives the wire
    /// EXACTLY (it is a frozen fact, never a fabricated known artifact) and
    /// the sweep refuses it (fail closed — an unreadable pre-push means the
    /// sweep cannot verify reachability).
    fn store_round_trip_keeps_unknown(intent: DeploymentIntent) {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let config = config_with_pin(tmp.path(), None);
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        store.test_append_intent(TARGET, &intent).unwrap();
        let entries = store.read_ledger(TARGET).unwrap();
        let read_back = entries[0].intent.pre_push(&SlotId::new(SLOT.to_string()));
        assert!(
            matches!(read_back, Some(crate::ledger::Observation::Unknown(_))),
            "the unknown pre-push must survive the wire as Unknown, got: {read_back:?}"
        );
        let err = store.reachability_snapshot(&config, None).unwrap_err();
        assert!(
            err.to_string().contains("pre-push"),
            "an Unknown pre-push MUST fail the reachability sweep closed, got: {err}"
        );
    }

    // ---- the deterministic unit tests, one per anchor class ----------------

    #[test]
    fn unreadable_ledger_fails_closed_then_recovers() {
        run_anchor_case(AnchorClass::Ledger, 2, 2);
    }

    #[test]
    fn unreadable_observed_record_fails_closed_then_recovers() {
        run_anchor_case(AnchorClass::Observed, 2, 2);
    }

    #[test]
    fn unreadable_pins_json_fails_closed_then_recovers() {
        run_anchor_case(AnchorClass::PinsJson, 2, 2);
    }

    #[test]
    fn unreadable_pinned_release_record_fails_closed_then_recovers() {
        run_anchor_case(AnchorClass::PinnedRelease, 2, 2);
    }

    #[test]
    fn corrupt_deployment_record_fails_closed_then_recovers() {
        run_anchor_case(AnchorClass::DeploymentRecord, 2, 2);
    }

    // ---- requirement 2: a pin that cannot be honored is an integrity abort --

    /// A CONFIG pin that names a release with NO record on disk aborts the
    /// sweep with an integrity error before any deletion (missing on disk).
    #[test]
    fn config_pin_naming_missing_release_aborts_with_integrity() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let missing = crate::identity::test_release_id("rel-sha256-missing");
        let config = config_with_pin(dir.path(), Some(&missing));
        seed_named_release(
            &store,
            crate::identity::test_release_id("rel-sha256-garbage").as_str(),
        );
        seed_object(&store, test_tree_digest("tree-garbage").as_str());
        let err = store.run_sweep(&config, "anchor", None).unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "a missing pinned release must abort with an integrity error, got: {err}"
        );
        assert!(
            err.to_string().contains("has no release record on disk"),
            "got: {err}"
        );
        assert!(
            store
                .release_dir(&crate::identity::test_release_id("rel-sha256-garbage"))
                .exists(),
            "zero deletions: the garbage release survives"
        );
        assert!(
            store
                .object_root(&test_tree_digest("tree-garbage"))
                .exists(),
            "zero deletions: the garbage tree survives"
        );
        // The ONE-SCAN path preserves the integrity class too: the single
        // locked snapshot fails closed before ANY deletion, exactly like the
        // sweep entry point that builds it (`run_sweep`).
        let err = store.reachability_snapshot(&config, None).unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "reachability_snapshot must preserve the pin-abort class, got: {err}"
        );
    }

    /// A STORE whole-release pin whose record is unverifiable (its content
    /// was edited, so the recomputed identity no longer matches) aborts the
    /// sweep with an integrity error before any deletion.
    #[test]
    fn store_pin_release_record_unverifiable_aborts_with_integrity() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let store_pin = seed_real_release(&store, "cfg");
        store
            .write_pins(&Pins::empty().with_release(store_pin.clone()))
            .unwrap();
        // Tamper the stored record's content (its slot declaration) while
        // leaving the digest fields: recompute-and-verify fails.
        let mut rec = store.read_release(&store_pin).unwrap();
        rec.slots.get_mut("standard").unwrap().slots[0].deploy_dir = "/srv/elsewhere".to_string();
        std::fs::write(
            store.release_dir(&store_pin).join("release.json"),
            serde_json::to_vec_pretty(&rec).unwrap(),
        )
        .unwrap();
        seed_named_release(
            &store,
            crate::identity::test_release_id("rel-sha256-garbage").as_str(),
        );
        seed_object(&store, test_tree_digest("tree-garbage").as_str());
        let config = config_with_pin(dir.path(), None);
        let err = store.run_sweep(&config, "anchor", None).unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "an unverifiable pinned release must abort with an integrity error, got: {err}"
        );
        assert!(err.to_string().contains("pin"), "got: {err}");
        assert!(
            store
                .release_dir(&crate::identity::test_release_id("rel-sha256-garbage"))
                .exists(),
            "zero deletions: the garbage release survives"
        );
        assert!(
            store
                .object_root(&test_tree_digest("tree-garbage"))
                .exists(),
            "zero deletions: the garbage tree survives"
        );
    }

    /// An EXACT-BINDING pin that names a release with no record on disk
    /// aborts with an integrity error (requirement 2 covers exact bindings:
    /// the pin names a release that cannot be honored).
    #[test]
    fn exact_binding_pin_naming_missing_release_aborts_with_integrity() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let missing = crate::identity::test_release_id("rel-sha256-missing");
        store
            .write_pins(&Pins::empty().with_binding(ArtifactRef {
                release: missing.clone(),
                variant: VariantName::parse("standard").unwrap(),
                tree: test_tree_digest("tree-x"),
            }))
            .unwrap();
        seed_named_release(
            &store,
            crate::identity::test_release_id("rel-sha256-garbage").as_str(),
        );
        seed_object(&store, test_tree_digest("tree-garbage").as_str());
        let config = config_with_pin(dir.path(), None);
        let err = store.run_sweep(&config, "anchor", None).unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "an exact-binding pin naming a missing release must abort with an integrity error, got: {err}"
        );
        assert!(
            store
                .release_dir(&crate::identity::test_release_id("rel-sha256-garbage"))
                .exists(),
            "zero deletions: the garbage release survives"
        );
        assert!(
            store
                .object_root(&test_tree_digest("tree-garbage"))
                .exists(),
            "zero deletions: the garbage tree survives"
        );
    }

    // -----------------------------------------------------------------------
    // PLANNED vs REMOVED — THE COUNTING FIX
    //
    // The user-reported bug: "checkpoint output can claim candidate files
    // were deleted when deletion failed". The fix splits PLANNED (the
    // candidates the sweep identified — the preview reports these) from
    // REMOVED (only successful filesystem unlinks — the execution reports
    // these plus the PENDING remainder). A candidate is NEVER counted as
    // removed unless the unlink succeeded: a failure AFTER the k-th
    // deletion aborts the stage (fail closed) with exactly k removed and
    // the rest PENDING (planned, still on disk); stages after the aborted
    // one stay pending too. The property generates inventories (deployment
    // dirs / release records / tree objects), injects the k-th unlink
    // failure in EVERY stage (the per-fixture FaultRegistry's per-candidate
    // sequence-counter kinds — [`FaultKind::SweepDeploymentsNth`] /
    // [`FaultKind::GcUnlinkReleases`] / [`FaultKind::GcUnlinkTrees`]), and
    // asserts the REPORTED REMOVALS EQUAL THE FILESYSTEM DELTA, the
    // remaining candidates stay PENDING (reported and still on disk), and
    // RETRY CONVERGES (the next sweep removes exactly the still-present
    // candidates). Bounded `proptest_cases(16)` (full 16 with
    // `DEPLOY_FULL_TESTS=1`, fast default), house fixed seed; the unit test
    // pins the user's deterministic case.

    /// The filesystem-delta oracle: the number of immediate subdirectories
    /// under `root` (0 when the root does not exist).
    fn count_dir_entries(root: &std::path::Path) -> usize {
        std::fs::read_dir(root).map(|rd| rd.count()).unwrap_or(0)
    }

    /// Run ONE planned-vs-removed case: `stage` (0 = deployment dirs, 1 =
    /// release records, 2 = tree objects) gets the failure injected AFTER
    /// its k-th deletion; every candidate is unreachable (no pins, no
    /// ledger). Asserts the full contract — reported removals == real
    /// unlinks, pending candidates stay on disk, retry converges.
    fn run_planned_vs_removed_case(
        n_deployments: usize,
        n_releases: usize,
        n_trees: usize,
        k: usize,
        stage: usize,
    ) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let config = config_with_pin(dir.path(), None);
        let deploys: Vec<String> = (0..n_deployments)
            .map(|i| format!("deploy-c-{i}"))
            .collect();
        let rels: Vec<String> = (0..n_releases).map(|i| format!("rel-c-{i}")).collect();
        let trees: Vec<String> = (0..n_trees).map(|i| format!("tree-c-{i}")).collect();
        for d in &deploys {
            seed_deployment_dir(&store, d);
        }
        for r in &rels {
            seed_named_release(&store, r);
        }
        for t in &trees {
            seed_object(&store, t);
        }
        // The k-th unlink arm: the failure must fire strictly inside the
        // stage's candidate set, so k is clamped to a valid "after k
        // deletions" point for the faulted stage.
        let max_k = match stage {
            0 => n_deployments,
            1 => n_releases,
            _ => n_trees,
        };
        let k = k % max_k;
        let reg = store.fault_registry();
        match stage {
            0 => reg.arm_deployment_unlink_after(k),
            1 => reg.arm_release_unlink_after("anchor", k),
            _ => reg.arm_tree_unlink_after("anchor", k),
        }

        let (discards, complete) = store.run_sweep(&config, "anchor", None).unwrap();
        assert!(
            !complete,
            "the k-th unlink failure aborts the sweep (stage {stage}, k={k})"
        );
        // The PLANNED sets are the full candidate inventories.
        assert_eq!(discards.sweep_deployments, deploys);
        assert_eq!(discards.sweep_releases, rels);
        assert_eq!(discards.sweep_objects, trees);
        // The expected REMOVED counts: stages BEFORE the aborted one removed
        // everything they planned; the aborted stage removed exactly k (its
        // (k+1)-th unlink failed); stages AFTER it are pending (fail closed
        // — nothing removed).
        let (expected_depl, expected_rel, expected_tree) = match stage {
            0 => (k, 0, 0),
            1 => (n_deployments, k, 0),
            _ => (n_deployments, n_releases, k),
        };
        assert_eq!(
            discards.removed_deployments, expected_depl,
            "deployment removals == the real unlinks (stage {stage}, k={k})"
        );
        assert_eq!(
            discards.removed_releases, expected_rel,
            "release removals == the real unlinks (stage {stage}, k={k})"
        );
        assert_eq!(
            discards.removed_objects, expected_tree,
            "tree removals == the real unlinks (stage {stage}, k={k})"
        );
        // THE FILESYSTEM DELTA: removed + still-present == planned, per
        // category — a reported removal is a real unlink, never a candidate
        // that is still on disk.
        let depl_root = store.base().join("deployments");
        let rel_root = store.base().join(crate::remote::layout::RELEASES);
        let tree_root = store.base().join(crate::remote::layout::objects());
        assert_eq!(
            count_dir_entries(&depl_root),
            deploys.len() - discards.removed_deployments,
            "deployment dirs still on disk == planned - removed (stage {stage}, k={k})"
        );
        assert_eq!(
            count_dir_entries(&rel_root),
            rels.len() - discards.removed_releases,
            "release dirs still on disk == planned - removed (stage {stage}, k={k})"
        );
        assert_eq!(
            count_dir_entries(&tree_root),
            trees.len() - discards.removed_objects,
            "tree dirs still on disk == planned - removed (stage {stage}, k={k})"
        );
        // The pending candidates (the tail of each SORTED planned list —
        // the deletion order IS the sorted enumeration order) stay on disk.
        for d in discards
            .sweep_deployments
            .iter()
            .skip(discards.removed_deployments)
        {
            assert!(
                store.deployment_dir_named(d).exists(),
                "pending deployment {d} stays on disk"
            );
        }
        for r in discards
            .sweep_releases
            .iter()
            .skip(discards.removed_releases)
        {
            assert!(
                store.release_dir(&ReleaseId::new(r.clone())).exists(),
                "pending release {r} stays on disk"
            );
        }
        for t in discards.sweep_objects.iter().skip(discards.removed_objects) {
            assert!(
                store.object_root(&TreeDigest::new(t.clone())).exists(),
                "pending tree {t} stays on disk"
            );
        }

        // RETRY CONVERGES: the next fault-free sweep recomputes
        // reachability fresh, removes EXACTLY the still-present candidates,
        // and completes.
        let (retry, retry_complete) = store.run_sweep(&config, "anchor", None).unwrap();
        assert!(retry_complete, "the retry converges (stage {stage}, k={k})");
        assert_eq!(
            retry.removed_deployments,
            deploys.len() - expected_depl,
            "the retry removed exactly the pending deployment dirs"
        );
        assert_eq!(
            retry.removed_releases,
            rels.len() - expected_rel,
            "the retry removed exactly the pending release records"
        );
        assert_eq!(
            retry.removed_objects,
            trees.len() - expected_tree,
            "the retry removed exactly the pending tree objects"
        );
        assert_eq!(
            count_dir_entries(&depl_root),
            0,
            "no deployment dir remains"
        );
        assert_eq!(count_dir_entries(&rel_root), 0, "no release dir remains");
        assert_eq!(count_dir_entries(&tree_root), 0, "no tree dir remains");
    }

    proptest! {
        // THE PROPERTY: generated inventories (deployment dirs, release
        // records, tree objects) with a failure injected AFTER the k-th
        // deletion in EVERY sweep stage — the REPORTED REMOVALS equal the
        // FILESYSTEM DELTA, the remaining candidates stay PENDING (reported
        // as planned/pending, still on disk), and RETRY CONVERGES (the next
        // sweep removes exactly the still-present candidates). Bounded
        // `proptest_cases(16)` (full 16 with `DEPLOY_FULL_TESTS=1`, fast
        // default) + the house fixed seed.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn sweep_removed_counts_match_filesystem_and_retry_converges(
            n_deployments in 1usize..=4,
            n_releases in 1usize..=4,
            n_trees in 1usize..=4,
            k in 0usize..=4,
        ) {
            // EVERY sweep stage gets the k-th failure (a fresh fixture per
            // stage — the per-fixture arms must not interact).
            for stage in 0..3 {
                run_planned_vs_removed_case(n_deployments, n_releases, n_trees, k, stage);
            }
        }
    }

    // ---- the deterministic unit test ---------------------------------------

    /// THE USER-REQUIRED DETERMINISTIC CASE: 5 release candidates, the
    /// failure armed AFTER the k=3rd deletion — removed == 3, pending == 2,
    /// the disk holds EXACTLY the 2 pending candidates; the retry removes
    /// those 2 and completes.
    #[test]
    fn unlink_failure_after_three_counts_removed_and_pending_exactly() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let config = config_with_pin(dir.path(), None);
        let candidates: Vec<String> = (0..5).map(|i| format!("rel-u-{i}")).collect();
        for r in &candidates {
            seed_named_release(&store, r);
        }
        // Fail AFTER the 3rd deletion: rel-u-0..rel-u-2 are unlinked, the
        // rel-u-3 unlink fails, and the stage aborts.
        store.fault_registry().arm_release_unlink_after("anchor", 3);

        let (discards, complete) = store.run_sweep(&config, "anchor", None).unwrap();
        assert!(!complete, "the sweep is incomplete (retry-required)");
        assert_eq!(
            discards.sweep_releases, candidates,
            "the PLANNED set is all 5 candidates"
        );
        assert_eq!(
            discards.removed_releases, 3,
            "removed == 3: exactly the successful unlinks"
        );
        assert_eq!(
            discards.sweep_releases.len() - discards.removed_releases,
            2,
            "pending == 2: the remaining candidates are reported pending"
        );
        // THE FILESYSTEM DELTA: the disk holds EXACTLY the 2 pending
        // candidates.
        for r in &candidates[..3] {
            assert!(
                !store.release_dir(&ReleaseId::new(r.clone())).exists(),
                "{r} was really unlinked"
            );
        }
        for r in &candidates[3..] {
            assert!(
                store.release_dir(&ReleaseId::new(r.clone())).exists(),
                "{r} stays pending on disk"
            );
        }
        // RETRY CONVERGES: the next sweep removes exactly the 2
        // still-present candidates and completes.
        let (retry, retry_complete) = store.run_sweep(&config, "anchor", None).unwrap();
        assert!(retry_complete, "the retry converges");
        assert_eq!(
            retry.removed_releases, 2,
            "the retry removed exactly the 2 pending candidates"
        );
        for r in &candidates {
            assert!(
                !store.release_dir(&ReleaseId::new(r.clone())).exists(),
                "no candidate remains after the retry"
            );
        }
    }
}
