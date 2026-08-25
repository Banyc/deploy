//! Checkpoint: retain one target's history suffix and sweep the unreachable
//! rest.
//!
//! `deploy checkpoint <target> <deployment-id>` compacts the target's ONE
//! deployment LEDGER (`targets/<target>/ledger.jsonl`) to the retained
//! suffix at/after the checkpoint deployment — the floor is IMPLICIT: the
//! ledger's first entry is the oldest retained rollback state, there is NO
//! separate floor marker — and then best-effort sweeps the globally
//! unreachable deployment directories, release records, and tree objects.
//! The checkpoint deployment must be a SUCCESSFUL deployment of the target
//! (its ledger entry carries a `Successful` terminal event with a rollback
//! state); its entry becomes the ledger's first (oldest) entry. Everything
//! strictly before it — older entries, failed attempts included, and their
//! `deployments/<id>/` directories — is discarded. The operation is
//! IRREVERSIBLE: the CLI requires `--yes` (or `--dry-run` to preview the
//! exact discard list) and an explicit deployment id.
//!
//! # The three steps (the only commit is the atomic replacement)
//!
//! 1. CALCULATE THE RETAINED SUFFIX ([`LocalStore::ledger_suffix`]): every
//!    physical ledger line from the checkpoint entry's intent line onward.
//! 2. ATOMICALLY REPLACE the ledger with that suffix
//!    ([`LocalStore::write_ledger_suffix`]: temp + fsync + chmod-private +
//!    rename + parent-dir fsync). THIS is the checkpoint's ONLY logical
//!    commit: a reader never observes a torn ledger (wholly old or wholly
//!    new). IF THE REPLACEMENT FAILS, NO DELETION HAPPENS — the checkpoint
//!    is a plain `Err` and the full history stands untouched.
//! 3. BEST-EFFORT GLOBAL SWEEP ([`LocalStore::run_sweep`]) of unreachable
//!    deployment directories (`deployments/<id>/`), release records
//!    (`releases/<release-id>/`), and tree objects
//!    (`objects/sha256/<digest>/`). The reachability scan
//!    ([`LocalStore::reachable_set`]) is recomputed FRESH on every retry and
//!    keeps everything reachable from ANOTHER target's ledger, the
//!    current/incomplete state (observed artifacts, pending intent-only
//!    entries, in-flight deployment dirs), or a PIN. A failed sweep is
//!    retried by RECOMPUTING reachability — no persisted deletion worklist,
//!    no cleanup-pending debt marker, no backup. Sweeps are best-effort and
//!    NOT secure erasure.
//!
//! The old multi-file checkpoint machinery — the `history-floor.json` marker,
//! the transactional floor ADVANCE with its tagged `.prev.<tag>` backups,
//! restore/recovery of torn advances, the tri-state marker discovery, and
//! the `cleanup-pending.json` debt flag with its three report flags — is
//! GONE: the atomic ledger replacement is the only logical commit, and the
//! report carries at most the commit status + sweep completed /
//! retry-required.
//!
//! # Concurrency
//!
//! The real operation runs under the SAME lock discipline as pushes
//! ([`crate::push::lock::FileLock`]): the application-store lock then the
//! target lock, both advisory (flock) and released on drop. The checkpoint
//! itself NEVER opens a remote: it is local-only by construction. A
//! `--dry-run` preview takes NO locks, writes NOTHING, and enumerates
//! exactly what the replacement + sweep would discard.

use crate::config::Config;
use crate::error::Result;
use crate::model::{DeploymentId, OperationId};
use crate::push::lock::FileLock;
use crate::store::history_floor::LedgerDiscards;
use crate::store::local::LocalStore;

/// The outcome of one checkpoint invocation (preview or real).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointReport {
    pub target: String,
    /// THE KEY: the checkpoint deployment. Its POSITION in the ledger
    /// (derived, never stored) is the retained suffix's start — the floor is
    /// implicit: everything strictly before it is discarded.
    pub deployment_id: DeploymentId,
    /// Exactly what was / would be discarded: the entries dropped from the
    /// ledger by the suffix replacement plus the deployment dirs, release
    /// records, and tree objects the global sweep deleted (or would delete).
    pub discards: LedgerDiscards,
    /// True when this call performed the LOGICAL COMMIT (the atomic ledger
    /// replacement); false for dry-run previews.
    pub established: bool,
    /// True when the best-effort sweep ran all three stages clean; false
    /// means the sweep is RETRY-REQUIRED — re-running the same checkpoint
    /// recomputes reachability fresh and finishes it.
    pub sweep_completed: bool,
    /// True when the operation ran read-only (`--dry-run`): no locks, no
    /// writes, no replacement, no sweep.
    pub dry_run: bool,
}

/// Establish (or preview) a checkpoint on `target` at `deployment_id`: the
/// ledger is atomically replaced with the retained suffix (the only logical
/// commit), then the global unreachable-content sweep runs best-effort.
pub fn run_checkpoint(
    store: &LocalStore,
    config: &Config,
    target: &str,
    deployment_id: &DeploymentId,
    dry_run: bool,
) -> Result<CheckpointReport> {
    if dry_run {
        return preview_checkpoint(store, config, target, deployment_id);
    }
    let op_id = OperationId::generate();
    let local_guard = FileLock::acquire(&store.base().join("operation.lock"), op_id.as_str())?;
    let target_guard = {
        let p = store.target_dir(target).join("operation.lock");
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        FileLock::acquire(&p, op_id.as_str())?
    };
    let result = checkpoint_inner(store, config, target, deployment_id);
    // The guards drop here, releasing both advisory locks regardless of how
    // `checkpoint_inner` resolves.
    drop(target_guard);
    drop(local_guard);
    result
}

/// Test-only entry point: drive [`checkpoint_inner`] for a REAL checkpoint
/// with the advisory LOCK ACQUISITION SKIPPED — mirroring the fixture's push
/// entry points ([`crate::push::engine::push_with_id`], which skip the local
/// `FileLock` acquisition the same way). The state-machine fixture is
/// single-threaded, so the locks would only add I/O; the validation, the
/// atomic ledger replacement (the logical commit), and the full sweep path
/// run UNMODIFIED.
#[cfg(test)]
pub(crate) fn run_checkpoint_unlocked(
    store: &LocalStore,
    config: &Config,
    target: &str,
    deployment_id: &DeploymentId,
) -> Result<CheckpointReport> {
    checkpoint_inner(store, config, target, deployment_id)
}

/// The real (locked) checkpoint: compute the retained suffix, ATOMICALLY
/// replace the ledger with it (the ONLY logical commit — a failure here is a
/// plain `Err`, nothing was deleted, the full history stands), then run the
/// best-effort global sweep. A repeated checkpoint of the same deployment
/// recomputes the SAME suffix (the ledger already IS it — the replacement is
/// an identical rewrite) and re-runs the sweep to convergence.
fn checkpoint_inner(
    store: &LocalStore,
    config: &Config,
    target: &str,
    deployment_id: &DeploymentId,
) -> Result<CheckpointReport> {
    // 1. Calculate the retained suffix + the entries it discards.
    let (suffix, discarded_entries) = store.ledger_suffix(target, deployment_id)?;
    // 2. THE LOGICAL COMMIT: atomically replace the ledger with the suffix.
    //    If this fails, NO DELETION HAPPENS — the previous ledger stands.
    store.write_ledger_suffix(target, &suffix)?;
    // 3. Best-effort global sweep of unreachable deployments / releases /
    //    objects (retry-required on a failed stage: the next same-deployment
    //    checkpoint recomputes reachability fresh and finishes it).
    let (sweep, complete) = store.run_sweep(config, deployment_id.as_str())?;
    Ok(CheckpointReport {
        target: target.to_string(),
        deployment_id: deployment_id.clone(),
        discards: LedgerDiscards {
            discarded_entries,
            ..sweep
        },
        established: true,
        sweep_completed: complete,
        dry_run: false,
    })
}

/// The read-only preview (`--dry-run`): the same validation (successful
/// deployment in the ledger) plus the exact replacement + sweep enumeration —
/// and nothing else. No locks, no replacement, no sweep, no remote.
fn preview_checkpoint(
    store: &LocalStore,
    config: &Config,
    target: &str,
    deployment_id: &DeploymentId,
) -> Result<CheckpointReport> {
    let (suffix, discarded_entries) = store.ledger_suffix(target, deployment_id)?;
    let _ = suffix;
    let sweep = store.sweep_discards(config)?;
    Ok(CheckpointReport {
        target: target.to_string(),
        deployment_id: deployment_id.clone(),
        discards: LedgerDiscards {
            discarded_entries,
            ..sweep
        },
        established: false,
        sweep_completed: false,
        dry_run: true,
    })
}

/// Render a checkpoint report for the CLI: a dry-run preview enumerates what
/// WOULD be discarded; a real checkpoint reports what WAS. The CLI prints
/// exactly these lines; the unit tests assert on them directly.
pub fn render_checkpoint_report(report: &CheckpointReport) -> Vec<String> {
    let mut lines = Vec::new();
    let verb = if report.dry_run {
        "would discard"
    } else {
        "discarded"
    };
    let head = if report.dry_run {
        format!(
            "dry-run: checkpoint at deployment {} of target {}",
            report.deployment_id, report.target
        )
    } else {
        format!(
            "checkpoint established: retained history starts at deployment {} of target {}",
            report.deployment_id, report.target
        )
    };
    lines.push(head);
    lines.push(format!(
        "{verb} {} ledger entr{} below the checkpoint",
        report.discards.discarded_entries.len(),
        plural(report.discards.discarded_entries.len())
    ));
    lines.push(format!(
        "{verb} {} deployment director{} (unreachable)",
        report.discards.sweep_deployments.len(),
        plural(report.discards.sweep_deployments.len())
    ));
    lines.push(format!(
        "{verb} {} release record{} (unreachable)",
        report.discards.sweep_releases.len(),
        plural(report.discards.sweep_releases.len())
    ));
    lines.push(format!(
        "{verb} {} tree object{} (unreachable)",
        report.discards.sweep_objects.len(),
        plural(report.discards.sweep_objects.len())
    ));
    if !report.dry_run && !report.sweep_completed {
        lines.push(format!(
            "warning: sweep did not complete — re-run `deploy checkpoint {} {}` to recompute reachability and finish it",
            report.target, report.deployment_id
        ));
    }
    lines
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::model::{
        ArtifactRef, GenerationRef, PlacementSlotAssignment, PlacementSlotId, ReleaseId,
        SCHEMA_VERSION, ServerId, TargetName, TreeDigest, VariantName,
    };
    use crate::records::{LedgerIntent, LedgerRollback, LedgerTerminal};
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::collections::BTreeMap;

    const TARGET: &str = "t1";

    fn intent(id: &str, target: &str) -> LedgerIntent {
        LedgerIntent {
            deployment_schema_version: SCHEMA_VERSION,
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new(target.to_string()),
            slot_ids: vec![PlacementSlotId::new("p1".to_string())],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        }
    }

    fn rollback_for(release: &str) -> LedgerRollback {
        LedgerRollback {
            behavior_sha256: "sha256-aa".to_string(),
            release: ReleaseId::new(release.to_string()),
            slots: BTreeMap::from([(
                PlacementSlotId::new("p1".to_string()),
                GenerationRef {
                    generation: crate::model::GenerationId::new("gen-1".to_string()),
                    assignment: PlacementSlotAssignment {
                        placement_slot: PlacementSlotId::new("p1".to_string()),
                        artifact: ArtifactRef {
                            release: ReleaseId::new(release.to_string()),
                            variant: VariantName::new("standard".to_string()),
                            tree: TreeDigest::new("tree-1".to_string()),
                        },
                    },
                },
            )]),
            bindings: BTreeMap::from([(
                PlacementSlotId::new("p1".to_string()),
                crate::records::PhysicalBinding {
                    server: ServerId::new("s1".to_string()),
                    deploy_dir: "/srv/deploy/p1".to_string(),
                },
            )]),
        }
    }

    fn terminal_for(id: &str, target: &str, release: &str) -> LedgerTerminal {
        LedgerTerminal {
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new(target.to_string()),
            status: crate::records::DeploymentStatus::Successful,
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
            outcomes: BTreeMap::new(),
            rollback: Some(rollback_for(release)),
            reason: None,
        }
    }

    /// Seed a target's ledger with a history of `history[i]`-shaped entries:
    /// `true` = successful (intent + Successful terminal with rollback),
    /// `false` = failed (intent + a `FailedRolledBack` terminal — no
    /// rollback). Returns the successful deployment ids in order.
    fn seed_history(
        store: &LocalStore,
        target: &str,
        prefix: &str,
        history: &[bool],
    ) -> Vec<String> {
        let mut successful = Vec::new();
        for (i, ok) in history.iter().enumerate() {
            let id = format!("{prefix}-{i}");
            store.append_intent(target, &intent(&id, target)).unwrap();
            if *ok {
                let rel = format!("rel-sha256-{id}");
                store
                    .append_terminal(target, &terminal_for(&id, target, &rel))
                    .unwrap();
                successful.push(id);
            } else {
                store
                    .append_terminal(
                        target,
                        &LedgerTerminal {
                            deployment_id: DeploymentId::new(id.clone()),
                            target: TargetName::new(target.to_string()),
                            status: crate::records::DeploymentStatus::FailedRolledBack,
                            recorded_at: "2026-01-01T00:00:00Z".to_string(),
                            outcomes: BTreeMap::new(),
                            rollback: None,
                            reason: None,
                        },
                    )
                    .unwrap();
            }
        }
        successful
    }

    /// A minimal but VALID variant file (the config loader requires a real
    /// variant: mappings, activation, verification).
    const VARIANT_TOML: &str = r#"
[[slots]]
id = "p1"
server = "s1"
targets = ["t1"]
deploy_dir = "/srv/eng"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

    fn config_for(dir: &tempfile::TempDir) -> Config {
        let project = dir.path().join("proj");
        std::fs::create_dir_all(project.join("releases").join("v1")).unwrap();
        std::fs::write(
            project.join("releases").join("v1").join("standard.toml"),
            VARIANT_TOML,
        )
        .unwrap();
        std::fs::write(
            project.join("deploy.toml"),
            format!(
                "schema_version = 1\napplication = \"cp\"\nrelease = \"v1\"\n\n\
                 [[servers]]\nid = \"s1\"\naddress = \"a\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n\
                 [targets.{TARGET}]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n"
            ),
        )
        .unwrap();
        Config::load(&project.join("deploy.toml")).unwrap()
    }

    /// Seed an UNREACHABLE deployment dir + release record + object dir (not
    /// referenced by any ledger, observed state, or pin): the sweep must
    /// delete it.
    fn seed_unreachable(store: &LocalStore, deployment: &str, release: &str, tree: &str) {
        let dir = store.deployment_dir(deployment);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plan.json"), "{}").unwrap();
        let rel_dir = store.release_dir(&ReleaseId::new(release.to_string()));
        std::fs::create_dir_all(&rel_dir).unwrap();
        std::fs::write(rel_dir.join("release.json"), "{}").unwrap();
        let obj_dir = store.object_root(&TreeDigest::new(tree.to_string()));
        std::fs::create_dir_all(&obj_dir).unwrap();
        std::fs::write(obj_dir.join("file"), "x").unwrap();
    }

    /// Write a REAL release record for the pin tests and return its
    /// content-derived id (release ids are derived from content, so the pin
    /// must reference the id the record actually got).
    fn seed_real_release(store: &LocalStore) -> ReleaseId {
        let rec = crate::release::build_release(
            "cp",
            "sha256-aa",
            &BTreeMap::from([(
                VariantName::new("standard".to_string()),
                TreeDigest::new("tree-pinned".to_string()),
            )]),
            &BTreeMap::from([(
                "standard".to_string(),
                vec![crate::config::SlotDef {
                    id: "p1".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: std::path::PathBuf::from("/srv/deploy/p1"),
                    targets: vec![TARGET.to_string()],
                }],
            )]),
            std::path::Path::new("."),
        );
        let id = ReleaseId::new(rec.release_id.clone());
        store.write_release(&rec).unwrap();
        id
    }

    /// Create a release directory under the given NAME (junk content) — the
    /// sweep keeps or sweeps it by NAME (the reachability set carries the
    /// names the ledgers/observations reference; only pinned releases need a
    /// verifiable record).
    fn seed_named_release(store: &LocalStore, name: &str) {
        let dir = store.release_dir(&ReleaseId::new(name.to_string()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("release.json"), "{}").unwrap();
    }

    /// The checkpoint compacts the ledger to the suffix at the checkpoint
    /// deployment and sweeps the unreachable content.
    #[test]
    fn checkpoint_compacts_ledger_to_the_suffix_and_sweeps() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let cfg = config_for(&dir);
        // History: deploy-0 (successful, rel-a/tree-a), deploy-1 (FAILED),
        // deploy-2 (successful). Plus UNREACHABLE ghost content.
        let ids = seed_history(&store, TARGET, "deploy", &[true, false, true]);
        seed_unreachable(&store, "ghost-deploy", "rel-sha256-ghost", "tree-ghost");
        let checkpoint = &ids[1]; // the second successful = deploy-2
        let rep = run_checkpoint_unlocked(&store, &cfg, TARGET, &DeploymentId::new(checkpoint))
            .expect("checkpoint succeeds");
        assert!(rep.established);
        assert!(rep.sweep_completed);
        // The ledger now holds exactly the checkpoint entry onward
        // (deploy-0 and deploy-1 — before deploy-2 — are gone).
        let entries = store.read_ledger(TARGET).unwrap();
        assert_eq!(entries.len(), 1, "only the checkpoint entry is retained");
        assert_eq!(entries[0].deployment_id.as_str(), *checkpoint);
        // The unreachable ghost content was swept.
        assert!(!store.deployment_dir("ghost-deploy").exists());
        assert!(
            !store
                .release_dir(&ReleaseId::new("rel-sha256-ghost"))
                .exists()
        );
        assert!(!store.object_root(&TreeDigest::new("tree-ghost")).exists());
    }

    /// A failed ledger replacement deletes NOTHING: the checkpoint fails
    /// cleanly with the full history intact.
    #[test]
    fn checkpoint_fails_cleanly_when_replacement_faults() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let cfg = config_for(&dir);
        let ids = seed_history(&store, TARGET, "deploy", &[true, true, true]);
        let before = store.read_ledger(TARGET).unwrap();
        store.fault_registry().arm_ledger_replace_before(TARGET);
        let err = run_checkpoint_unlocked(&store, &cfg, TARGET, &DeploymentId::new(&ids[1]))
            .expect_err("the pre-replace fault fails the checkpoint");
        assert!(err.to_string().contains("ledger"));
        assert_eq!(
            store.read_ledger(TARGET).unwrap(),
            before,
            "the visible ledger is wholly OLD after a failed replacement"
        );
    }

    /// The sweep keeps everything reachable from another target or a pin:
    /// only the unreachable content is swept.
    #[test]
    fn checkpoint_keeps_other_target_and_pinned_content() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        // A pin keeps a release that is NOT in any ledger (retained by the
        // PIN only). The release id is content-derived, so the pin must
        // reference the id the real record got.
        let pinned = seed_real_release(&store);
        let project = dir.path().join("proj");
        std::fs::create_dir_all(project.join("releases").join("v1")).unwrap();
        std::fs::write(
            project.join("releases").join("v1").join("standard.toml"),
            VARIANT_TOML,
        )
        .unwrap();
        std::fs::write(
            project.join("deploy.toml"),
            format!(
                "schema_version = 1\napplication = \"cp\"\nrelease = \"v1\"\n\n\
                 [[servers]]\nid = \"s1\"\naddress = \"a\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n\
                 [[pins]]\nrelease = \"{pinned}\"\nreason = \"keep\"\n\n\
                 [targets.{TARGET}]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n"
            ),
        )
        .unwrap();
        let cfg = Config::load(&project.join("deploy.toml")).unwrap();

        // t1's ledger references rel-sha256-a; t2's ledger references
        // rel-sha256-other (reachable from ANOTHER target's ledger).
        seed_history(&store, TARGET, "deploy", &[true]);
        seed_history(&store, "t2", "dep2", &[true]);
        // The referenced release dirs (kept by NAME: the ledgers reference
        // them).
        seed_named_release(&store, "rel-sha256-deploy-0");
        seed_named_release(&store, "rel-sha256-dep2-0");
        // Unreachable ghost release.
        seed_named_release(&store, "rel-sha256-ghost");

        let id0 = store.read_ledger(TARGET).unwrap()[0].deployment_id.clone();
        let rep = run_checkpoint_unlocked(&store, &cfg, TARGET, &id0)
            .expect("checkpoint at the first entry succeeds");
        assert!(rep.established);
        assert!(rep.sweep_completed);
        // Reachable content survives: the t1 retained release, the t2
        // ledger's release, and the pinned release.
        assert!(
            store
                .release_dir(&ReleaseId::new("rel-sha256-deploy-0"))
                .exists()
        );
        assert!(
            store
                .release_dir(&ReleaseId::new("rel-sha256-dep2-0"))
                .exists()
        );
        assert!(store.release_dir(&pinned).exists());
        // The ghost release was swept.
        assert!(
            !store
                .release_dir(&ReleaseId::new("rel-sha256-ghost"))
                .exists()
        );
    }

    // ---------------------------------------------------------------------
    // THE PROPERTY: inject a failure before/after the ledger replacement and
    // at every sweep stage; the visible ledger is always WHOLY OLD or WHOLY
    // NEW (the atomic replace), retained and pinned content survives every
    // failure, and retries converge (repeating the checkpoint recomputes
    // reachability fresh and finishes the sweep).
    // ---------------------------------------------------------------------

    /// The fault slots of the property: BEFORE/AFTER the atomic ledger
    /// replacement, and each sweep stage (deployment dirs / release records /
    /// tree objects).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CheckpointFault {
        LedgerReplaceBefore,
        LedgerReplaceAfter,
        SweepDeployments,
        SweepReleases,
        SweepObjects,
    }

    fn arm_fault(store: &LocalStore, fault: CheckpointFault) {
        let reg = store.fault_registry();
        match fault {
            CheckpointFault::LedgerReplaceBefore => reg.arm_ledger_replace_before(TARGET),
            CheckpointFault::LedgerReplaceAfter => reg.arm_ledger_replace_after(TARGET),
            CheckpointFault::SweepDeployments => reg.arm_sweep_deployments(TARGET),
            CheckpointFault::SweepReleases => reg.arm_sweep_releases(TARGET),
            CheckpointFault::SweepObjects => reg.arm_sweep_objects(TARGET),
        }
    }

    /// Run ONE property case: seed a history (a successful checkpoint
    /// deployment at `checkpoint_at`, later successes after it), seed
    /// unreachable + pinned content, inject `fault` at the checkpoint, then
    /// RETRY the checkpoint (no fault) until it converges. Asserts:
    ///
    /// * the visible ledger after the fault is WHOLLY OLD or WHOLLY NEW —
    ///   never torn (the atomic replace): it either contains every seeded
    ///   entry (old) or is EXACTLY the suffix at the checkpoint (new);
    /// * retained and pinned content survives every failure (the checkpoint
    ///   deployment's own rollback release/tree and the pinned release);
    /// * the retry converges: it finishes the sweep and the report says
    ///   `sweep_completed`.
    fn run_fault_case(at: usize, fault: CheckpointFault) {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        config_for(&dir);
        // A pin keeps a release that is NOT in any ledger (retained by the
        // PIN only). The release id is content-derived, so the pin references
        // the id the real record got.
        let pinned = seed_real_release(&store);
        let pinned_rel = pinned.as_str().to_string();
        // Rebuild the config WITH the pin (the property asserts pinned
        // content survives every failure).
        let project = dir.path().join("proj");
        std::fs::write(
            project.join("deploy.toml"),
            format!(
                "schema_version = 1\napplication = \"cp\"\nrelease = \"v1\"\n\n\
                 [[servers]]\nid = \"s1\"\naddress = \"a\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n\
                 [[pins]]\nrelease = \"{pinned}\"\nreason = \"keep\"\n\n\
                 [targets.{TARGET}]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n"
            ),
        )
        .unwrap();
        let cfg = Config::load(&project.join("deploy.toml")).unwrap();
        // History: successful deployments deploy-0..deploy-5; checkpoint at
        // index `at`. Unreachable ghost content to sweep.
        let ids = seed_history(&store, TARGET, "deploy", &[true; 6]);
        seed_unreachable(&store, "ghost-deploy", "rel-sha256-ghost", "tree-ghost");
        let checkpoint_id = &ids[at];

        let expected_suffix = {
            let entries = store.read_ledger(TARGET).unwrap();
            entries[at..]
                .iter()
                .map(|e| e.deployment_id.as_str().to_string())
                .collect::<Vec<_>>()
        };

        // The faulted checkpoint (may Err at the fault slot; the ledger must
        // still be wholly old or wholly new).
        arm_fault(&store, fault);
        let _ = run_checkpoint_unlocked(&store, &cfg, TARGET, &DeploymentId::new(checkpoint_id));

        // INVARIANT 1: the visible ledger is WHOLY OLD or WHOLY NEW — never
        // torn. Old = every seeded entry in order; New = exactly the
        // expected suffix (the checkpoint's own entry onward, in order).
        let visible: Vec<String> = store
            .read_ledger(TARGET)
            .unwrap()
            .iter()
            .map(|e| e.deployment_id.as_str().to_string())
            .collect();
        let wholly_old = visible == ids.clone();
        let wholly_new = visible == expected_suffix;
        assert!(
            wholly_old || wholly_new,
            "fault {fault:?}: the visible ledger must be wholly old or wholly new, got {visible:?}"
        );
        // INVARIANT 2: retained and pinned content survive every failure.
        assert!(
            store.release_dir(&ReleaseId::new(&pinned_rel)).exists(),
            "fault {fault:?}: the pinned release must survive"
        );
        // The retained suffix survives in ORDER — in the wholly-NEW case the
        // visible ledger IS exactly the checkpoint's own entry onward; in the
        // wholly-OLD case the full history stands (nothing discarded).
        let checkpoint_suffix = expected_suffix.clone();
        if wholly_new {
            let visible: Vec<String> = store
                .read_ledger(TARGET)
                .unwrap()
                .iter()
                .map(|e| e.deployment_id.as_str().to_string())
                .collect();
            assert_eq!(
                visible, checkpoint_suffix,
                "fault {fault:?}: the wholly-new ledger is exactly the retained suffix in order"
            );
        }

        // RETRY CONVERGES: repeat the checkpoint without a fault — the
        // suffix is recomputed (identical) and the sweep finishes.
        let retry =
            run_checkpoint_unlocked(&store, &cfg, TARGET, &DeploymentId::new(checkpoint_id))
                .expect("the retry checkpoint succeeds");
        assert!(
            retry.sweep_completed,
            "fault {fault:?}: the retry must finish the sweep (converged)"
        );
        assert_eq!(
            store
                .read_ledger(TARGET)
                .unwrap()
                .iter()
                .map(|e| e.deployment_id.as_str().to_string())
                .collect::<Vec<_>>(),
            expected_suffix,
            "fault {fault:?}: the converged ledger is the retained suffix"
        );
        assert!(
            !store.deployment_dir("ghost-deploy").exists(),
            "fault {fault:?}: the converged sweep deleted the unreachable deployment dir"
        );
        assert!(
            store.release_dir(&ReleaseId::new(&pinned_rel)).exists(),
            "fault {fault:?}: the pinned release survives the converged sweep"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            // Bounded 4 cases, fixed seed per house style.
            cases: 4,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn checkpoint_faults_never_torn_and_retries_converge(
            at in 0usize..=5,
            fault in prop_oneof![
                Just(CheckpointFault::LedgerReplaceBefore),
                Just(CheckpointFault::LedgerReplaceAfter),
                Just(CheckpointFault::SweepDeployments),
                Just(CheckpointFault::SweepReleases),
                Just(CheckpointFault::SweepObjects),
            ],
        ) {
            run_fault_case(at, fault);
        }
    }
}
