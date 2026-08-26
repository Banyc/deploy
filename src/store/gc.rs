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
//!    artifacts must stay. When the GC runs for a CHECKPOINT, the
//!    checkpointed target's ledger is scanned AS-IF the atomic suffix
//!    replacement already happened — the retained-suffix
//!    [`LedgerOverride`] — so the pre-checkpoint history's artifacts are
//!    unreachable and swept, and the dry-run preview uses the SAME override
//!    (previewed deletions == real deletions).
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
use crate::store::history_floor::{LedgerOverride, ReachableSet};
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
    /// never depends on it. `ledger_override` — the checkpoint's
    /// retained-suffix override (see [`LocalStore::reachable_set`]): the GC
    /// scans the checkpointed target's ledger as-if the replacement already
    /// happened, so the retained set here is the SAME one the dry-run
    /// preview computed — the sweep deletes exactly what the preview
    /// reported.
    pub(crate) fn gc_artifacts(
        &self,
        anchor: &str,
        config: &Config,
        ledger_override: Option<&LedgerOverride>,
    ) -> Result<GcOutcome> {
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
        let retained = match self.reachable_set(config, ledger_override) {
            Ok(rs) => rs,
            // A pin-abort (an un-honorable pinned release) is an integrity
            // error: keep its class — callers distinguish "corrupt anchor"
            // from "disk read failed", and the requirement is that a pin
            // that cannot be honored aborts the sweep with an integrity
            // error before any deletion.
            Err(e @ Error::Integrity(_)) => return Err(e),
            // Any other anchor failure is annotated with the triggering
            // checkpoint for the report.
            Err(e) => {
                return Err(Error::store(format!(
                    "artifact GC (triggered by checkpoint {anchor}): {e}"
                )));
            }
        };
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
    use crate::config::SlotDef;
    use crate::model::{
        ArtifactRef, DeploymentId, GenerationId, GenerationRef, PlacementSlotAssignment,
        PlacementSlotId, SCHEMA_VERSION, TargetName, TreeDigest, VariantName,
    };
    use crate::records::{
        DeploymentStatus, LedgerIntent, LedgerRollback, LedgerTerminal, ObservedServer, Pins,
    };
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    const TARGET: &str = "t1";
    const SLOT: &str = "p1";

    /// A minimal but VALID variant file (the config loader requires a real
    /// variant: mappings, activation, verification, and the slot's ONE
    /// rotation policy).
    const VARIANT_TOML: &str = r#"
[artifact]
mappings = []

[[slots]]
id = "p1"
server = "s1"
target = "t1"
groups = []
deploy_dir = "/srv"

[rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[rotation.deployment]
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
    fn config_with_pin(base: &std::path::Path, pinned: Option<&ReleaseId>) -> Config {
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
        Config::load(&project.join("deploy.toml")).unwrap()
    }

    /// Write a REAL release record (content-derived id) with one variant
    /// tree `tree-pinned-<tag>`, and return the id it actually got — pins
    /// must reference the id the record got.
    fn seed_real_release(store: &LocalStore, tag: &str) -> ReleaseId {
        let rec = crate::release::build_release(
            "gc",
            "sha256-aa",
            &BTreeMap::from([(
                VariantName::new("standard".to_string()),
                TreeDigest::new(format!("tree-pinned-{tag}")),
            )]),
            &BTreeMap::from([(
                "standard".to_string(),
                vec![SlotDef {
                    id: SLOT.to_string(),
                    server: "s1".to_string(),
                    deploy_dir: PathBuf::from("/srv/deploy/p1"),
                    target: TARGET.to_string(),
                    groups: Vec::new(),
                }],
            )]),
            std::path::Path::new("."),
        );
        let id = ReleaseId::new(rec.release_id.clone());
        store.write_release(&rec).unwrap();
        id
    }

    /// A deployment's LEDGER record: intent + SUCCESSFUL terminal whose
    /// rollback references `release` / `tree`.
    fn intent(id: &str) -> LedgerIntent {
        LedgerIntent {
            deployment_schema_version: SCHEMA_VERSION,
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new(TARGET.to_string()),
            group: None,
            slot_ids: vec![PlacementSlotId::new(SLOT.to_string())],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        }
    }

    fn terminal_for(id: &str, release: &str, tree: &str) -> LedgerTerminal {
        LedgerTerminal {
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new(TARGET.to_string()),
            status: DeploymentStatus::Successful,
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
            outcomes: BTreeMap::new(),
            rollback: Some(LedgerRollback {
                slots: BTreeMap::from([(
                    PlacementSlotId::new(SLOT.to_string()),
                    GenerationRef {
                        generation: GenerationId::new("gen-1".to_string()),
                        assignment: PlacementSlotAssignment {
                            placement_slot: PlacementSlotId::new(SLOT.to_string()),
                            artifact: ArtifactRef {
                                release: ReleaseId::new(release.to_string()),
                                variant: VariantName::new("standard".to_string()),
                                tree: TreeDigest::new(tree.to_string()),
                            },
                        },
                    },
                )]),
                bindings: BTreeMap::new(),
            }),
            reason: None,
        }
    }

    /// Create a release directory under the given NAME with junk content —
    /// the sweep keeps or sweeps it by NAME (only PINNED releases are read).
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
        let dir = store.deployment_dir(id);
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
        config: Config,
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
        // each rolling back to `rel-sha256-ret-<i>` / `tree-ret-<i>`.
        let mut retained_deployments = Vec::new();
        for i in 0..retained {
            let id = format!("deploy-ret-{i}");
            store.append_intent(TARGET, &intent(&id)).unwrap();
            store
                .append_terminal(
                    TARGET,
                    &terminal_for(
                        &id,
                        &format!("rel-sha256-ret-{i}"),
                        &format!("tree-ret-{i}"),
                    ),
                )
                .unwrap();
            retained_deployments.push(id);
        }
        let ledger_text = std::fs::read_to_string(store.ledger_path(TARGET)).unwrap_or_default();

        // The observed slot state (the ONE physical observed record).
        let observed = ObservedServer {
            generation: None,
            artifact: Some(ArtifactRef {
                release: ReleaseId::new("rel-sha256-obs".to_string()),
                variant: VariantName::new("standard".to_string()),
                tree: TreeDigest::new("tree-obs".to_string()),
            }),
            last_deployment: Some(DeploymentId::new("deploy-obs".to_string())),
        };
        store
            .write_slot_observed(&PlacementSlotId::new(SLOT.to_string()), &observed)
            .unwrap();
        let observed_path = store.slot_observed_path(&PlacementSlotId::new(SLOT.to_string()));
        let observed_bytes = std::fs::read(&observed_path).unwrap();

        // Store-level pins: a whole-release pin on `store_pin` AND an exact
        // binding pin on the same release's `tree-pinned-store` tree.
        let pins = Pins {
            schema_version: crate::model::PINS_SCHEMA_VERSION,
            releases: vec![store_pin.clone()],
            bindings: vec![ArtifactRef {
                release: store_pin.clone(),
                variant: VariantName::new("standard".to_string()),
                tree: TreeDigest::new("tree-pinned-store".to_string()),
            }],
        };
        store.write_pins(&pins).unwrap();
        let pins_bytes = std::fs::read(store.pins_path()).unwrap();
        let pinned_bytes = std::fs::read(store.release_dir(&cfg_pin).join("release.json")).unwrap();

        // Physical dirs for every retained reference. The pinned releases'
        // dirs already exist (written by `write_release`); the rest get
        // junk-named dirs (kept/swept by NAME — only pinned records are
        // read).
        let mut retained_releases = vec!["rel-sha256-obs".to_string()];
        let mut retained_trees = vec!["tree-obs".to_string()];
        for i in 0..retained {
            retained_releases.push(format!("rel-sha256-ret-{i}"));
            retained_trees.push(format!("tree-ret-{i}"));
        }
        retained_releases.push(cfg_pin.as_str().to_string());
        retained_trees.push("tree-pinned-cfg".to_string());
        retained_releases.push(store_pin.as_str().to_string());
        retained_trees.push("tree-pinned-store".to_string());
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
            let r = format!("rel-sha256-garbage-{i}");
            let t = format!("tree-garbage-{i}");
            seed_named_release(&store, &r);
            seed_object(&store, &t);
            garbage_releases.push(r);
            garbage_trees.push(t);
        }

        // Deployment dirs: the reachable ones + the ghost.
        for id in &retained_deployments {
            seed_deployment_dir(&store, id);
        }
        seed_deployment_dir(&store, "deploy-obs");
        let ghost_deployment = "deploy-ghost".to_string();
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
            ("releases", store.base().join(crate::layout::RELEASES)),
            (
                "objects/sha256",
                store.base().join(crate::layout::objects()),
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
                let p = f
                    .store
                    .slot_observed_path(&PlacementSlotId::new(SLOT.to_string()));
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
                let p = f
                    .store
                    .slot_observed_path(&PlacementSlotId::new(SLOT.to_string()));
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
        let dir = tempfile::tempdir().unwrap();
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
                f.store.deployment_dir(id).exists(),
                "retained deployment {id} must survive"
            );
        }
        assert!(
            f.store.deployment_dir("deploy-obs").exists(),
            "the observed last deployment survives"
        );
        assert!(
            !f.store.deployment_dir(&f.ghost_deployment).exists(),
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
        // EXACTLY the unreachable set. Bounded 16 cases + fixed seed per
        // house style (each case builds 5 small fixtures — one per anchor
        // class — so the bound keeps the suite fast).
        #![proptest_config(ProptestConfig {
            cases: 16,
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
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let missing = ReleaseId::new("rel-sha256-missing".to_string());
        let config = config_with_pin(dir.path(), Some(&missing));
        seed_named_release(&store, "rel-sha256-garbage");
        seed_object(&store, "tree-garbage");
        let err = store.run_sweep(&config, "anchor", None).unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "a missing pinned release must abort with an integrity error, got: {err}"
        );
        assert!(err.to_string().contains("missing"), "got: {err}");
        assert!(
            store
                .release_dir(&ReleaseId::new("rel-sha256-garbage"))
                .exists(),
            "zero deletions: the garbage release survives"
        );
        assert!(
            store.object_root(&TreeDigest::new("tree-garbage")).exists(),
            "zero deletions: the garbage tree survives"
        );
        // The gc's own entry point preserves the integrity class too.
        let err = store.gc_artifacts("anchor", &config, None).unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "gc_artifacts must preserve the pin-abort class, got: {err}"
        );
    }

    /// A STORE whole-release pin whose record is unverifiable (its content
    /// was edited, so the recomputed identity no longer matches) aborts the
    /// sweep with an integrity error before any deletion.
    #[test]
    fn store_pin_release_record_unverifiable_aborts_with_integrity() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let store_pin = seed_real_release(&store, "cfg");
        store
            .write_pins(&Pins {
                schema_version: crate::model::PINS_SCHEMA_VERSION,
                releases: vec![store_pin.clone()],
                bindings: Vec::new(),
            })
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
        seed_named_release(&store, "rel-sha256-garbage");
        seed_object(&store, "tree-garbage");
        let config = config_with_pin(dir.path(), None);
        let err = store.run_sweep(&config, "anchor", None).unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "an unverifiable pinned release must abort with an integrity error, got: {err}"
        );
        assert!(err.to_string().contains("pin"), "got: {err}");
        assert!(
            store
                .release_dir(&ReleaseId::new("rel-sha256-garbage"))
                .exists(),
            "zero deletions: the garbage release survives"
        );
        assert!(
            store.object_root(&TreeDigest::new("tree-garbage")).exists(),
            "zero deletions: the garbage tree survives"
        );
    }

    /// An EXACT-BINDING pin that names a release with no record on disk
    /// aborts with an integrity error (requirement 2 covers exact bindings:
    /// the pin names a release that cannot be honored).
    #[test]
    fn exact_binding_pin_naming_missing_release_aborts_with_integrity() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let missing = ReleaseId::new("rel-sha256-missing".to_string());
        store
            .write_pins(&Pins {
                schema_version: crate::model::PINS_SCHEMA_VERSION,
                releases: Vec::new(),
                bindings: vec![ArtifactRef {
                    release: missing.clone(),
                    variant: VariantName::new("standard".to_string()),
                    tree: TreeDigest::new("tree-x".to_string()),
                }],
            })
            .unwrap();
        seed_named_release(&store, "rel-sha256-garbage");
        seed_object(&store, "tree-garbage");
        let config = config_with_pin(dir.path(), None);
        let err = store.run_sweep(&config, "anchor", None).unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "an exact-binding pin naming a missing release must abort with an integrity error, got: {err}"
        );
        assert!(
            store
                .release_dir(&ReleaseId::new("rel-sha256-garbage"))
                .exists(),
            "zero deletions: the garbage release survives"
        );
        assert!(
            store.object_root(&TreeDigest::new("tree-garbage")).exists(),
            "zero deletions: the garbage tree survives"
        );
    }
}
