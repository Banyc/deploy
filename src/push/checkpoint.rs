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
//!    is a plain `Err` and the full history stands untouched. ONCE THE
//!    REPLACEMENT SUCCEEDS THE CHECKPOINT IS IRREVERSIBLY COMMITTED: that
//!    moment is the EXPLICIT COMMIT BOUNDARY — from it on, no post-commit
//!    sweep failure (scan, enumeration, deletion, or the debt-marker write)
//!    may surface as an `Err`; each is converted into a report with
//!    `established: true`, `sweep_completed: false`, and a warning (see
//!    step 3).
//! 3. BEST-EFFORT GLOBAL SWEEP ([`LocalStore::run_sweep`]) of unreachable
//!    deployment directories (`deployments/<id>/`), release records
//!    (`releases/<release-id>/`), and tree objects
//!    (`objects/sha256/<digest>/`). The reachability scan
//!    ([`LocalStore::reachable_set`]) is recomputed FRESH on every retry and
//!    keeps everything reachable from ANOTHER target's ledger, the
//!    current/incomplete state (observed artifacts, pending intent-only
//!    entries, in-flight deployment dirs), or a PIN. A failed sweep is
//!    retried by RECOMPUTING reachability — no persisted deletion worklist,
//!    no backup — and an incomplete sweep records a DURABLE SWEEP-DEBT
//!    marker (`<base>/sweep-debt.json`) so the NEXT PUSH (not just the next
//!    checkpoint) retries it. Sweeps are best-effort and NOT secure erasure.
//!
//! # Preview == execution (the ledger override)
//!
//! The sweep's reachability is computed against the checkpointed target's
//! ledger AS-IF the suffix replacement ALREADY happened ([`LedgerOverride`]):
//! the pre-checkpoint history's releases, trees, and deployment dirs are
//! unreachable the MOMENT the ledger is shortened. The flow computes the
//! retained suffix ONCE and feeds the parsed suffix as the override to BOTH
//! the dry-run preview and the real execution — the preview (touch nothing)
//! and the real command (atomic replacement + sweep) share the SAME
//! reachability calculation, so the previewed deletion sets EXACTLY match
//! what the real command deletes. (Without the override the preview would
//! scan the CURRENT ledger, where the pre-checkpoint entries are still
//! present, and under-report the artifacts that only become garbage after
//! the replacement.)
//!
//! The old multi-file checkpoint machinery — the `history-floor.json` marker,
//! the transactional floor ADVANCE with its tagged `.prev.<tag>` backups,
//! restore/recovery of torn advances, the tri-state marker discovery, and
//! the `cleanup-pending.json` debt flag with its three report flags — is
//! GONE: the atomic ledger replacement is the only logical commit, and the
//! report carries at most the commit status + sweep completed /
//! retry-required (plus the sweep-debt warning when the marker could not be
//! persisted).
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
use crate::store::history_floor::{LedgerDiscards, LedgerOverride};
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
    /// means the sweep is RETRY-REQUIRED — a durable sweep-debt marker was
    /// recorded and the next push (or a re-run of the same checkpoint)
    /// recomputes reachability fresh and finishes it.
    pub sweep_completed: bool,
    /// THE EXPLICIT POST-COMMIT BOUNDARY WARNING: a sweep READ/DELETION
    /// failure that surfaced AFTER the irreversible ledger replacement
    /// committed (the reachable-set scan, the directory enumeration, or a
    /// deletion stage) is converted into this warning — `established` stays
    /// `true`, `sweep_completed` is `false`, and the sweep is retry-required
    /// (the durable sweep-debt marker records it; the next push — or a
    /// re-run — recomputes reachability fresh). The checkpoint NEVER returns
    /// `Err` for a post-commit sweep failure; this field carries the reason.
    /// `None` when the sweep ran without a post-commit error (a
    /// merely-incomplete sweep is reported via `sweep_completed` + the
    /// renderer's retry line, not here).
    pub sweep_warning: Option<String>,
    /// Warning about the sweep-debt marker I/O when the sweep did not
    /// complete (the marker could not be persisted). Post-commit
    /// maintenance: a debt write failure is a warning, never an `Err` — the
    /// checkpoint's logical commit stands either way. `None` when the sweep
    /// completed or the marker was recorded cleanly.
    pub sweep_debt_warning: Option<String>,
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
///
/// # The EXPLICIT COMMIT BOUNDARY
///
/// The moment [`LocalStore::write_ledger_suffix`] returns `Ok`, the
/// checkpoint is IRREVERSIBLY committed — the pre-checkpoint history is
/// gone forever. From that exact point on the checkpoint CANNOT return
/// `Err`: the sweep (the reachable-set scan, the directory enumeration, the
/// three deletion stages) and the sweep-debt marker are POST-COMMIT
/// MAINTENANCE, and every failure of theirs is converted into a report with
/// `established: true`, `sweep_completed: false`, and a warning (see
/// [`CheckpointReport::sweep_warning`]). Only failures BEFORE the boundary —
/// the suffix computation and the ledger replacement itself — return `Err`
/// (nothing was committed).
fn checkpoint_inner(
    store: &LocalStore,
    config: &Config,
    target: &str,
    deployment_id: &DeploymentId,
) -> Result<CheckpointReport> {
    // 1. Calculate the retained suffix (the physical LINES for the atomic
    //    replacement + the SAME suffix parsed as entries) and the entries it
    //    discards.
    let (suffix, suffix_entries, discarded_entries) = store.ledger_suffix(target, deployment_id)?;
    // THE SHARED LEDGER OVERRIDE: the checkpointed target's ledger as-if the
    // suffix replacement already happened. Computed ONCE here and fed to the
    // sweep in BOTH paths — the dry-run preview and this real execution use
    // the SAME reachability, so the previewed deletion sets are exactly the
    // real ones (the artifacts that become garbage only when the ledger is
    // shortened are enumerated by the preview too).
    let ledger_override = LedgerOverride {
        target: target.to_string(),
        entries: suffix_entries,
    };
    // 2. THE LOGICAL COMMIT: atomically replace the ledger with the suffix.
    //    If this fails, NO DELETION HAPPENS — the previous ledger stands.
    //    `?` is correct here: a failed replacement is a PRE-COMMIT failure
    //    and the checkpoint returns a plain `Err`.
    store.write_ledger_suffix(target, &suffix)?;
    //
    // ==================== THE EXPLICIT COMMIT BOUNDARY ====================
    // `write_ledger_suffix` returned Ok: the checkpoint is IRREVERSIBLY
    // committed — the pre-checkpoint history is gone. From this line on the
    // checkpoint CANNOT return `Err`. Everything below — the sweep (the
    // reachable-set scan, the directory enumeration, the deployment-dir /
    // release / tree-object deletion stages) and the sweep-debt marker — is
    // POST-COMMIT MAINTENANCE: every failure is converted into a report
    // with `established: true`, `sweep_completed: false`, and a warning
    // surfaced on the report (`sweep_warning` / `sweep_debt_warning`). The
    // durable sweep-debt marker records the pending sweep so the NEXT PUSH
    // (not just a re-run) recomputes reachability FRESH (no persisted
    // deletion worklist) and finishes it.
    //
    // 3. Best-effort global sweep of unreachable deployments / releases /
    //    objects — computed with the SAME override the preview used (after
    //    the atomic replacement the on-disk ledger IS the suffix, so the
    //    override and the current ledger agree; passing it keeps the sweep
    //    structurally identical to the preview's calculation). The sweep's
    //    DELETION stages are internally absorbed into `complete = false` by
    //    `run_sweep` itself (stage faults and deletion errors); its READ
    //    stages — the reachable-set scan and the directory enumeration —
    //    escape `run_sweep` as `Err` and are converted HERE into a warning:
    //    the committed ledger stands, the sweep is retry-required.
    let (sweep, complete, sweep_failed) =
        match store.run_sweep(config, deployment_id.as_str(), Some(&ledger_override)) {
            Ok((sweep, complete)) => (sweep, complete, None),
            Err(e) => (
                LedgerDiscards::default(),
                false,
                Some(format!(
                    "checkpoint sweep failed after the ledger commit ({e}); the sweep is \
                 retry-required — the next push recomputes reachability fresh and finishes it"
                )),
            ),
        };
    // The DURABLE sweep-debt marker: an incomplete OR failed sweep records
    // retry-required so the next push (or a re-run of the same checkpoint)
    // retries it; a COMPLETED sweep clears any stale marker a prior
    // incomplete sweep left (this re-run just serviced it — convergence).
    // The marker write/clear is itself non-fallible maintenance: a failure
    // is a warning on the report, never an `Err`.
    let debt_reason = match &sweep_failed {
        Some(failed) => failed.clone(),
        None => "checkpoint sweep did not complete; the next push retries it".to_string(),
    };
    let sweep_debt_warning = if complete {
        // The sweep ran clean: clear the pending-sweep marker (a prior
        // incomplete sweep left it; it is serviced now).
        match store.write_sweep_debt(None) {
            Ok(()) => None,
            Err(e) => Some(format!(
                "sweep debt maintenance deferred: failed to clear sweep debt: {e}"
            )),
        }
    } else {
        match store.write_sweep_debt(Some(&debt_reason)) {
            Ok(()) => None,
            Err(e) => Some(format!(
                "sweep debt maintenance deferred: failed to write sweep debt: {e}"
            )),
        }
    };
    Ok(CheckpointReport {
        target: target.to_string(),
        deployment_id: deployment_id.clone(),
        discards: LedgerDiscards {
            discarded_entries,
            ..sweep
        },
        established: true,
        sweep_completed: complete,
        sweep_warning: sweep_failed,
        sweep_debt_warning,
        dry_run: false,
    })
}

/// The read-only preview (`--dry-run`): the same validation (successful
/// deployment in the ledger) plus the exact replacement + sweep enumeration —
/// and nothing else. No locks, no replacement, no sweep, no remote.
///
/// THE PARITY FIX: the preview computes the deletion sets with the SAME
/// [`LedgerOverride`] the real execution uses — the checkpointed target's
/// ledger as-if the suffix replacement already happened — so the preview
/// enumerates EXACTLY what the real command deletes (including the
/// artifacts that become unreachable only when the ledger is shortened).
fn preview_checkpoint(
    store: &LocalStore,
    config: &Config,
    target: &str,
    deployment_id: &DeploymentId,
) -> Result<CheckpointReport> {
    let (suffix, suffix_entries, discarded_entries) = store.ledger_suffix(target, deployment_id)?;
    // The shared override (see [`checkpoint_inner`]): the preview scans the
    // checkpointed target's ledger as-if the atomic replacement already
    // happened, so the pre-checkpoint history's releases/trees/deployment
    // dirs — garbage the moment the ledger is shortened — are enumerated
    // here, exactly as the real sweep deletes them. `suffix` (the raw lines)
    // is unused in the preview: it is the replacement payload only.
    let _ = suffix;
    let ledger_override = LedgerOverride {
        target: target.to_string(),
        entries: suffix_entries,
    };
    let sweep = store.sweep_discards(config, Some(&ledger_override))?;
    Ok(CheckpointReport {
        target: target.to_string(),
        deployment_id: deployment_id.clone(),
        discards: LedgerDiscards {
            discarded_entries,
            ..sweep
        },
        established: false,
        sweep_completed: false,
        sweep_warning: None,
        sweep_debt_warning: None,
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
            "warning: sweep did not complete — the next push retries it; re-run `deploy checkpoint {} {}` to finish it now",
            report.target, report.deployment_id
        ));
    }
    if let Some(w) = &report.sweep_warning {
        lines.push(format!("warning: {w}"));
    }
    if let Some(w) = &report.sweep_debt_warning {
        lines.push(format!("warning: {w}"));
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
    use crate::records::{LedgerIntent, LedgerRollback, LedgerTerminal, ObservedServer, Pins};
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::collections::BTreeMap;

    const TARGET: &str = "t1";

    fn intent(id: &str, target: &str) -> LedgerIntent {
        LedgerIntent {
            deployment_schema_version: SCHEMA_VERSION,
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new(target.to_string()),
            group: None,
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
target = "t1"
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
                "schema_version = 2\napplication = \"cp\"\nrelease = \"v1\"\n\n\
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

    /// Build a REAL release record and return its content-DERIVED id (release
    /// ids are derived from content, so a pin must reference the id the
    /// record actually got — `store.write_release` binds the record to its
    /// derived read path, and the pin expansion's `record.release_id == read
    /// path` check then holds; a record at a differently-named dir would be
    /// refused). `tag` differentiates the record's variant tree so distinct
    /// seeds produce distinct ids.
    fn seed_named_release(store: &LocalStore, tag: &str) -> ReleaseId {
        let rec = crate::release::build_release(
            "sw",
            "sha256-aa",
            &std::collections::BTreeMap::from([(
                crate::model::VariantName::new("standard".to_string()),
                crate::model::TreeDigest::new(format!("tree-pinned-{tag}")),
            )]),
            &std::collections::BTreeMap::from([(
                "standard".to_string(),
                vec![crate::config::SlotDef {
                    id: "p1".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: std::path::PathBuf::from("/srv/deploy/p1"),
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

    /// Create a release directory under the given NAME with junk content —
    /// the sweep keeps or sweeps it by NAME (the reachability set carries the
    /// names the ledgers/observations reference; only PINNED releases are
    /// read, and they need a real record seeded via [`seed_named_release`]).
    fn seed_named_release_dir(store: &LocalStore, name: &str) {
        let dir = store.release_dir(&ReleaseId::new(name.to_string()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("release.json"), "{}").unwrap();
    }

    /// Create a deployment directory under the given id (junk content) — the
    /// sweep enumerates `deployments/` and sweeps the unreachable dirs.
    fn seed_deployment_dir(store: &LocalStore, id: &str) {
        let dir = store.deployment_dir(id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plan.json"), "{}").unwrap();
    }

    /// Create a tree object directory under the given digest name (junk
    /// content) — the sweep enumerates `objects/sha256/` and sweeps the
    /// unreachable digests.
    fn seed_tree_dir(store: &LocalStore, tree: &str) {
        let dir = store.object_root(&TreeDigest::new(tree.to_string()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("file"), "x").unwrap();
    }

    /// Seed ONE successful deployment whose rollback references the caller's
    /// EXACT release + tree (the shared `seed_history` helper always rolls
    /// back to the same tree digest, so the pre-suffix-unique-artifact cases
    /// need a custom entry).
    fn seed_success(store: &LocalStore, target: &str, id: &str, release: &str, tree: &str) {
        store.append_intent(target, &intent(id, target)).unwrap();
        let mut term = terminal_for(id, target, release);
        // Rewrite the rollback's per-slot tree to the caller's tree.
        let rollback = term.rollback.as_mut().unwrap();
        for g in rollback.slots.values_mut() {
            g.assignment.artifact.tree = TreeDigest::new(tree.to_string());
        }
        store.append_terminal(target, &term).unwrap();
    }

    /// THE PARITY FIX (deterministic regression): a checkpoint whose
    /// PRE-SUFFIX history references artifacts UNIQUE to it — the dry-run
    /// preview MUST enumerate them. With the ledger override the
    /// pre-checkpoint releases / trees / deployment dirs are unreachable the
    /// moment the suffix replacement happens, so the preview lists them;
    /// WITHOUT the override the preview scans the CURRENT ledger (where the
    /// pre-checkpoint entries are still present) and misses them — the
    /// under-report this fix removes.
    #[test]
    fn preview_lists_artifacts_that_become_unreachable_only_after_the_suffix_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let cfg = config_for(&dir);
        // Three successful deployments, each with a UNIQUE release + tree
        // (rel-sha256-old/tree-old, rel-sha256-mid/tree-mid,
        // rel-sha256-new/tree-new).
        seed_success(&store, TARGET, "deploy-0", "rel-sha256-old", "tree-old");
        seed_success(&store, TARGET, "deploy-1", "rel-sha256-mid", "tree-mid");
        seed_success(&store, TARGET, "deploy-2", "rel-sha256-new", "tree-new");
        // Materialize the deployment dirs / release dirs / object dirs for
        // all three entries (the sweep only enumerates what exists).
        for id in ["deploy-0", "deploy-1", "deploy-2"] {
            seed_deployment_dir(&store, id);
        }
        for rel in ["rel-sha256-old", "rel-sha256-mid", "rel-sha256-new"] {
            seed_named_release_dir(&store, rel);
        }
        for tree in ["tree-old", "tree-mid", "tree-new"] {
            seed_tree_dir(&store, tree);
        }
        // Checkpoint at deploy-1: deploy-0 is strictly BEFORE it — its
        // release, tree, and deployment dir are reachable only from the
        // pre-suffix ledger that the replacement discards.
        let preview = run_checkpoint(&store, &cfg, TARGET, &DeploymentId::new("deploy-1"), true)
            .expect("the dry-run preview succeeds");
        assert!(preview.dry_run);
        assert!(!preview.established);
        assert_eq!(
            preview.discards.discarded_entries,
            vec!["deploy-0".to_string()],
            "exactly the entries strictly before the checkpoint are discarded"
        );
        // THE FIX: the preview lists the pre-suffix-only content (reachable
        // only from the discarded history).
        assert!(
            preview
                .discards
                .sweep_deployments
                .contains(&"deploy-0".to_string()),
            "the pre-suffix deployment dir must be previewed for deletion"
        );
        assert!(
            preview
                .discards
                .sweep_releases
                .contains(&"rel-sha256-old".to_string()),
            "the pre-suffix release must be previewed for deletion"
        );
        assert!(
            preview
                .discards
                .sweep_objects
                .contains(&"tree-old".to_string()),
            "the pre-suffix tree must be previewed for deletion"
        );
        // The retained suffix's own content is NOT previewed for deletion.
        assert!(
            !preview
                .discards
                .sweep_deployments
                .contains(&"deploy-1".to_string())
        );
        assert!(
            !preview
                .discards
                .sweep_releases
                .contains(&"rel-sha256-mid".to_string())
        );
        assert!(
            !preview
                .discards
                .sweep_objects
                .contains(&"tree-mid".to_string())
        );
        // COUNTERFACTUAL: WITHOUT the ledger override the preview scans the
        // CURRENT ledger — deploy-0's entry is still present, so its unique
        // content is NOT listed (and nothing else is unreachable either).
        // This is the under-report the bug describes.
        let no_override = store.sweep_discards(&cfg, None).unwrap();
        assert!(no_override.sweep_deployments.is_empty());
        assert!(no_override.sweep_releases.is_empty());
        assert!(no_override.sweep_objects.is_empty());
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
                "schema_version = 2\napplication = \"cp\"\nrelease = \"v1\"\n\n\
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
        seed_named_release_dir(&store, "rel-sha256-deploy-0");
        seed_named_release_dir(&store, "rel-sha256-dep2-0");
        // Unreachable ghost release.
        seed_named_release_dir(&store, "rel-sha256-ghost");

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
    /// replacement (the PRE-COMMIT boundary — these may return `Err`), and
    /// EVERY POST-COMMIT sweep stage: the reachability read/scan
    /// ([`FaultKind::SweepScan`]), the directory enumeration
    /// ([`FaultKind::SweepEnumerate`]), the three deletion stages
    /// (deployment dirs / release records / tree objects), and the
    /// sweep-debt marker write. Once the ledger replacement has committed,
    /// a fault at ANY of these stages must be CONVERTED into an established
    /// report (never `Err`) — the explicit commit boundary.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CheckpointFault {
        LedgerReplaceBefore,
        LedgerReplaceAfter,
        SweepScan,
        SweepEnumerate,
        SweepDeployments,
        SweepReleases,
        SweepObjects,
        SweepDebtWrite,
    }

    fn arm_fault(store: &LocalStore, fault: CheckpointFault) {
        let reg = store.fault_registry();
        match fault {
            CheckpointFault::LedgerReplaceBefore => reg.arm_ledger_replace_before(TARGET),
            CheckpointFault::LedgerReplaceAfter => reg.arm_ledger_replace_after(TARGET),
            CheckpointFault::SweepScan => reg.arm_sweep_scan(),
            CheckpointFault::SweepEnumerate => reg.arm_sweep_enumerate(),
            CheckpointFault::SweepDeployments => reg.arm_sweep_deployments(),
            CheckpointFault::SweepReleases => reg.arm_sweep_releases(),
            CheckpointFault::SweepObjects => reg.arm_sweep_objects(),
            // The debt-write fault fires only when the sweep is INCOMPLETE
            // (the marker write is reached): arm a sweep-stage fault too, so
            // the debt write is actually attempted.
            CheckpointFault::SweepDebtWrite => {
                reg.arm_sweep_deployments();
                reg.arm_write_sweep_debt();
            }
        }
    }

    /// Run ONE property case: seed a history (a successful checkpoint
    /// deployment at `checkpoint_at`, later successes after it), seed
    /// unreachable + pinned content, inject `fault` at the checkpoint, then
    /// RETRY the checkpoint (no fault) until it converges. Asserts:
    ///
    /// * THE EXPLICIT COMMIT BOUNDARY: a PRE-commit fault (the replacement
    ///   itself — `LedgerReplaceBefore` / `LedgerReplaceAfter`) is a plain
    ///   `Err`; a POST-commit fault (EVERY sweep stage — the reachability
    ///   scan, the enumeration, the three deletion stages, the debt-marker
    ///   write) is CONVERTED into an established report with
    ///   `sweep_completed: false` and a warning — NEVER an `Err`;
    /// * the visible ledger is always WHOLY OLD or WHOLY NEW — never torn
    ///   (the atomic replace): wholly OLD only for `LedgerReplaceBefore`
    ///   (nothing committed); wholly NEW — EXACTLY the retained suffix — for
    ///   every post-replacement fault (the commit stands);
    /// * retained and pinned content survives every failure;
    /// * the retry converges: `sweep_completed: true`, the ledger matches
    ///   the retained suffix, the unreachable content is gone, the sweep
    ///   debt is cleared.
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
                "schema_version = 2\napplication = \"cp\"\nrelease = \"v1\"\n\n\
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

        // THE FAULTED CHECKPOINT + THE EXPLICIT COMMIT BOUNDARY. The ledger
        // is always WHOLY OLD or WHOLY NEW (the atomic replace, never torn),
        // and the fault's CLASS decides which:
        arm_fault(&store, fault);
        let faulted =
            run_checkpoint_unlocked(&store, &cfg, TARGET, &DeploymentId::new(checkpoint_id));
        let visible: Vec<String> = store
            .read_ledger(TARGET)
            .unwrap()
            .iter()
            .map(|e| e.deployment_id.as_str().to_string())
            .collect();
        match fault {
            // ---- the PRE-COMMIT boundary: a failed replacement is a plain
            // `Err` (nothing was committed / the replacement itself did not
            // return Ok), never a report ----
            CheckpointFault::LedgerReplaceBefore => {
                assert!(
                    faulted.is_err(),
                    "fault {fault:?}: a pre-replacement fault must fail the checkpoint with Err"
                );
                assert_eq!(
                    visible, ids,
                    "fault {fault:?}: a pre-replacement fault leaves the ledger wholly OLD"
                );
            }
            CheckpointFault::LedgerReplaceAfter => {
                assert!(
                    faulted.is_err(),
                    "fault {fault:?}: a failed replacement still returns Err"
                );
                assert_eq!(
                    visible, expected_suffix,
                    "fault {fault:?}: the after-rename durability hook leaves the wholly-NEW suffix durable"
                );
            }
            // ---- THE POST-COMMIT BOUNDARY: the replacement succeeded, so
            // EVERY sweep-stage fault is CONVERTED into an established report
            // (never Err); the retained suffix is preserved (the ledger = the
            // suffix, wholly new) ----
            _ => {
                let rep = faulted.unwrap_or_else(|e| {
                    panic!(
                        "fault {fault:?}: a post-commit sweep failure must NEVER be an Err, got {e}"
                    )
                });
                assert!(
                    rep.established,
                    "fault {fault:?}: the ledger commit stands (established)"
                );
                assert!(
                    !rep.sweep_completed,
                    "fault {fault:?}: the sweep is reported retry-required"
                );
                assert_eq!(
                    visible, expected_suffix,
                    "fault {fault:?}: the committed ledger is EXACTLY the retained suffix, wholly new"
                );
                match fault {
                    // The sweep READ/scan + enumeration failures: the reason
                    // surfaces as the report's sweep warning; the durable
                    // debt marker records the pending sweep.
                    CheckpointFault::SweepScan | CheckpointFault::SweepEnumerate => {
                        assert!(
                            rep.sweep_warning.is_some(),
                            "fault {fault:?}: a sweep read failure must surface a warning on the report"
                        );
                        assert!(
                            rep.sweep_debt_warning.is_none(),
                            "fault {fault:?}: the debt marker itself wrote cleanly"
                        );
                        assert!(
                            store.read_sweep_debt().unwrap().is_some(),
                            "fault {fault:?}: the pending sweep is recorded as durable debt"
                        );
                    }
                    // The debt-marker WRITE failure: the report carries the
                    // debt warning and no marker is left on disk.
                    CheckpointFault::SweepDebtWrite => {
                        assert!(
                            rep.sweep_warning.is_none(),
                            "fault {fault:?}: the sweep itself did not error"
                        );
                        assert!(
                            rep.sweep_debt_warning.is_some(),
                            "fault {fault:?}: the failed debt write is a warning, never an Err"
                        );
                        assert!(
                            store.read_sweep_debt().unwrap().is_none(),
                            "fault {fault:?}: the failed marker write leaves no marker on disk"
                        );
                    }
                    // The deletion stages: internally absorbed by `run_sweep`
                    // into `sweep_completed: false` + a cleanly-recorded
                    // debt marker.
                    _ => {
                        assert!(
                            rep.sweep_warning.is_none(),
                            "fault {fault:?}: a deletion-stage fault is absorbed, not an error"
                        );
                        assert!(
                            rep.sweep_debt_warning.is_none(),
                            "fault {fault:?}: the debt marker recorded cleanly"
                        );
                        assert!(
                            store.read_sweep_debt().unwrap().is_some(),
                            "fault {fault:?}: a pending sweep records durable debt"
                        );
                    }
                }
            }
        }
        // INVARIANT: retained and pinned content survives every failure.
        assert!(
            store.release_dir(&ReleaseId::new(&pinned_rel)).exists(),
            "fault {fault:?}: the pinned release must survive"
        );

        // RETRY CONVERGES: repeat the checkpoint without a fault — the
        // suffix is recomputed (identical) and the sweep finishes (the debt
        // marker is cleared).
        let retry =
            run_checkpoint_unlocked(&store, &cfg, TARGET, &DeploymentId::new(checkpoint_id))
                .expect("the retry checkpoint succeeds");
        assert!(
            retry.sweep_completed,
            "fault {fault:?}: the retry must finish the sweep (converged)"
        );
        assert!(
            retry.sweep_warning.is_none() && retry.sweep_debt_warning.is_none(),
            "fault {fault:?}: the converged retry has no warnings"
        );
        assert!(
            store.read_sweep_debt().unwrap().is_none(),
            "fault {fault:?}: the converged sweep cleared the debt"
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
            // Bounded 16 cases, fixed seed per house style.
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// THE EXPLICIT COMMIT BOUNDARY PROPERTY: a fault BEFORE the ledger
        /// replacement (`LedgerReplaceBefore` / `LedgerReplaceAfter`) is a
        /// plain `Err`; a fault at EVERY POST-REPLACEMENT sweep stage — the
        /// reachability scan, the directory enumeration, the three deletion
        /// stages (deployment dirs / release records / tree objects), and
        /// the sweep-debt write — is CONVERTED into an established report
        /// (never `Err`), the retained suffix is preserved (the ledger = the
        /// suffix, wholly new), and a repeat of the same checkpoint
        /// converges (`sweep_completed`, debt cleared).
        #[test]
        fn checkpoint_faults_never_torn_and_retries_converge(
            at in 0usize..=5,
            fault in prop_oneof![
                Just(CheckpointFault::LedgerReplaceBefore),
                Just(CheckpointFault::LedgerReplaceAfter),
                Just(CheckpointFault::SweepScan),
                Just(CheckpointFault::SweepEnumerate),
                Just(CheckpointFault::SweepDeployments),
                Just(CheckpointFault::SweepReleases),
                Just(CheckpointFault::SweepObjects),
                Just(CheckpointFault::SweepDebtWrite),
            ],
        ) {
            run_fault_case(at, fault);
        }
    }

    // ---- the deterministic unit tests, one per sweep stage ----------------
    // Each pins ONE stage's conversion at the explicit commit boundary: the
    // faulted checkpoint returns an ESTABLISHED report (never `Err`), the
    // retained suffix is preserved (the ledger = the suffix, wholly new),
    // and the re-run of the same checkpoint converges (`sweep_completed`,
    // debt cleared).
    #[test]
    fn sweep_scan_fault_never_fails_the_committed_checkpoint() {
        run_fault_case(2, CheckpointFault::SweepScan);
    }

    #[test]
    fn sweep_enumeration_fault_never_fails_the_committed_checkpoint() {
        run_fault_case(2, CheckpointFault::SweepEnumerate);
    }

    #[test]
    fn sweep_deployment_deletion_fault_never_fails_the_committed_checkpoint() {
        run_fault_case(2, CheckpointFault::SweepDeployments);
    }

    #[test]
    fn sweep_release_deletion_fault_never_fails_the_committed_checkpoint() {
        run_fault_case(2, CheckpointFault::SweepReleases);
    }

    #[test]
    fn sweep_object_deletion_fault_never_fails_the_committed_checkpoint() {
        run_fault_case(2, CheckpointFault::SweepObjects);
    }

    #[test]
    fn sweep_debt_write_fault_never_fails_the_committed_checkpoint() {
        run_fault_case(2, CheckpointFault::SweepDebtWrite);
    }

    // ---------------------------------------------------------------------
    // THE PREVIEW == EXECUTION PARITY PROPERTY: multi-target stores with a
    // shared release/tree pool, observed state, and pins — the dry-run
    // preview of a checkpoint on ONE target must enumerate EXACTLY the
    // deletion sets the same checkpoint performs on a CLONED store (the
    // previewed inventory == the real deletions), including the artifacts
    // that become unreachable only AFTER the suffix replacement.
    // ---------------------------------------------------------------------

    /// The artifact pools of the parity property. Index 3 is RESERVED for
    /// t1's entry-0 (the pre-suffix-only pair every case discards at the
    /// checkpoint); indices 0..=2 are the pool the ledger entries draw from.
    /// The observed state and the pins reference their OWN content-derived
    /// release ids (see [`seed_named_release`]) — a pin must name the id the
    /// record actually got.
    const PROPERTY_RELEASES: [&str; 4] = [
        "rel-sha256-p0",
        "rel-sha256-p1",
        "rel-sha256-p2",
        "rel-sha256-p3",
    ];
    const PROPERTY_TREES: [&str; 4] = ["tree-p0", "tree-p1", "tree-p2", "tree-p3"];

    /// Config for the parity property: TWO targets (t1 + t2), each with its
    /// own slot (the loader requires every declared target to have at least
    /// one member slot). No config `[[pins]]` — the property pins via the
    /// store-level `pins.json` surface instead.
    fn config_for_property(dir: &tempfile::TempDir) -> Config {
        let project = dir.path().join("proj");
        std::fs::create_dir_all(project.join("releases").join("v1")).unwrap();
        std::fs::write(
            project.join("releases").join("v1").join("standard.toml"),
            r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/eng"

[[slots]]
id = "p2"
server = "s1"
target = "t2"
deploy_dir = "/srv/eng2"

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
"#,
        )
        .unwrap();
        std::fs::write(
            project.join("deploy.toml"),
            r#"schema_version = 2
application = "cp"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }

[targets.t2]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#,
        )
        .unwrap();
        Config::load(&project.join("deploy.toml")).unwrap()
    }

    /// Run ONE parity case: seed two targets' histories (t1's entry 0 always
    /// carries the UNIQUE pre-suffix-only pair (p3, p3); every other entry
    /// draws from the pool shared with the observed state and the pins),
    /// add observed state + pins + ghost content, PREVIEW the checkpoint on
    /// the original store (touches nothing), CLONE the base and EXECUTE the
    /// same checkpoint on the clone, and assert the previewed deletion
    /// inventory EXACTLY equals the real one — and that the real sweep
    /// actually removed what it reported.
    fn run_preview_parity_case(
        t1_len: usize,
        t2_len: usize,
        at: usize,
        t1_rest: &[(usize, usize)],
        t2_hist: &[(usize, usize)],
    ) {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let cfg = config_for_property(&dir);

        // t1's full history: entry 0 carries the UNIQUE pre-suffix-only
        // artifact (p3) — the checkpoint at `at >= 1` discards it, so every
        // case exercises the parity fix (content unreachable only after the
        // suffix replacement). The rest of t1 (and all of t2) draw from the
        // pool shared with the observed state and the pins (p0..p2).
        let mut t1_specs: Vec<(usize, usize)> = vec![(3, 3)];
        t1_specs.extend_from_slice(t1_rest);
        for (i, &(r, t)) in t1_specs.iter().enumerate() {
            let id = format!("dep-t1-{i}");
            seed_success(&store, "t1", &id, PROPERTY_RELEASES[r], PROPERTY_TREES[t]);
            seed_unreachable(&store, &id, PROPERTY_RELEASES[r], PROPERTY_TREES[t]);
        }
        for (i, &(r, t)) in t2_hist.iter().enumerate() {
            let id = format!("dep-t2-{i}");
            seed_success(&store, "t2", &id, PROPERTY_RELEASES[r], PROPERTY_TREES[t]);
            seed_unreachable(&store, &id, PROPERTY_RELEASES[r], PROPERTY_TREES[t]);
        }
        // Ghost content unreachable from ANY ledger, observation, or pin.
        seed_unreachable(&store, "dep-ghost", "rel-sha256-ghost", "tree-ghost");
        // OBSERVED state: the slot observed the (obs_rel) artifact, with its
        // last deployment the CHECKPOINTED deployment (dep-t1-{at}) — the
        // observed release + tree and that deployment dir are retained. The
        // observed release is a content-derived id seeded as a REAL record
        // (the sweep keeps the observed release by the id the record got).
        let obs_rel = seed_named_release(&store, "obs");
        store
            .write_slot_observed(
                &PlacementSlotId::new("s-obs".to_string()),
                &ObservedServer {
                    generation: None,
                    artifact: Some(ArtifactRef {
                        release: obs_rel.clone(),
                        variant: VariantName::new("standard".to_string()),
                        tree: TreeDigest::new(PROPERTY_TREES[0].to_string()),
                    }),
                    last_deployment: Some(DeploymentId::new(format!("dep-t1-{at}"))),
                },
            )
            .unwrap();
        seed_tree_dir(&store, PROPERTY_TREES[0]);
        // PINS — REAL, verifiable records. KEEP-BOTH with the gc side's
        // fail-closed pin handling (a pinned release's record is read +
        // identity-verified, so a junk-named dir can never be a pin target):
        // the property pins a genuine content-derived record instead — a
        // WHOLE-RELEASE pin (keeps the record + its variant trees) AND an
        // EXACT-BINDING pin on the SAME record ((release, tree) kept). The
        // pin-retained content is asserted below via the record's real id.
        let pinned = seed_real_release(&store);
        let pinned_tree = "tree-pinned".to_string();
        seed_tree_dir(&store, &pinned_tree);

        store
            .write_pins(&Pins {
                schema_version: crate::model::PINS_SCHEMA_VERSION,
                releases: vec![pinned.clone()],
                bindings: vec![ArtifactRef {
                    release: pinned.clone(),
                    variant: VariantName::new("standard".to_string()),
                    tree: TreeDigest::new(pinned_tree.clone()),
                }],
            })
            .unwrap();

        let checkpoint_id = DeploymentId::new(format!("dep-t1-{at}"));
        // PREVIEW on the ORIGINAL store (read-only: no locks, no writes).
        let preview = run_checkpoint(&store, &cfg, "t1", &checkpoint_id, true)
            .expect("the dry-run preview succeeds");
        assert!(preview.dry_run);
        assert!(!preview.established);

        // CLONE the base (the preview touched nothing) and EXECUTE the same
        // checkpoint on the clone.
        let clone_base = dir.path().join("clone");
        crate::store::atomic::copy_dir_recursive(store.base(), &clone_base)
            .expect("the store base clones");
        let clone = LocalStore::with_base(clone_base).unwrap();
        let executed = run_checkpoint_unlocked(&clone, &cfg, "t1", &checkpoint_id)
            .expect("the real checkpoint on the cloned store succeeds");
        assert!(executed.established);
        assert!(executed.sweep_completed);

        // THE PARITY: the previewed deletion inventory (deployment dirs,
        // releases, trees, ledger entries) EXACTLY equals the real one.
        assert_eq!(
            preview.discards, executed.discards,
            "the dry-run preview must enumerate EXACTLY the deletions the real checkpoint performs (t1_len={t1_len}, t2_len={t2_len}, at={at})"
        );
        // The pre-suffix-only artifact MUST be in both (the fix).
        assert!(
            executed
                .discards
                .sweep_releases
                .contains(&PROPERTY_RELEASES[3].to_string()),
            "the pre-suffix-only release must be deleted (t1_len={t1_len}, at={at})"
        );
        assert!(
            executed
                .discards
                .sweep_objects
                .contains(&PROPERTY_TREES[3].to_string()),
            "the pre-suffix-only tree must be deleted (t1_len={t1_len}, at={at})"
        );

        // The real store removed exactly what it reported.
        for d in &executed.discards.sweep_deployments {
            assert!(
                !clone.deployment_dir(d).exists(),
                "deployment dir {d} must be deleted"
            );
        }
        for r in &executed.discards.sweep_releases {
            assert!(
                !clone.release_dir(&ReleaseId::new(r.clone())).exists(),
                "release dir {r} must be deleted"
            );
        }
        for t in &executed.discards.sweep_objects {
            assert!(
                !clone.object_root(&TreeDigest::new(t.clone())).exists(),
                "tree object {t} must be deleted"
            );
        }
        // Retained content survives: the observed REAL record (obs_rel, per
        // the master's observed seeding) + its observed tree, the pinned
        // REAL record + its tree, and every t2 ledger entry's content. (The
        // pool names p0..p2 survive only when a retained ledger or the
        // observed state references them — an unreferenced pool dir is
        // correctly swept; only the pin-/observed-retained records are
        // asserted unconditionally.)
        assert!(
            clone.release_dir(&obs_rel).exists(),
            "the observed release record survives"
        );
        assert!(
            clone.release_dir(&pinned).exists(),
            "the pinned release record survives"
        );
        assert!(
            clone
                .object_root(&TreeDigest::new(PROPERTY_TREES[0].to_string()))
                .exists()
        );
        assert!(
            clone
                .object_root(&TreeDigest::new(pinned_tree.clone()))
                .exists(),
            "the pinned record's variant tree survives"
        );
        assert!(clone.deployment_dir(&format!("dep-t1-{at}")).exists());
        for (i, &(r, t)) in t2_hist.iter().enumerate() {
            assert!(clone.deployment_dir(&format!("dep-t2-{i}")).exists());
            assert!(
                clone
                    .release_dir(&ReleaseId::new(PROPERTY_RELEASES[r].to_string()))
                    .exists()
            );
            assert!(
                clone
                    .object_root(&TreeDigest::new(PROPERTY_TREES[t].to_string()))
                    .exists()
            );
        }
    }

    /// One parity case's generated shape: t1_len, t2_len, the checkpoint
    /// index into t1's history, and the per-entry artifact pool indices
    /// (release, tree) for t1's entries 1.. and for all of t2's entries
    /// (t1's entry 0 is the reserved pre-suffix-only pair, not generated).
    type ParityCase = (
        usize,
        usize,
        usize,
        Vec<(usize, usize)>,
        Vec<(usize, usize)>,
    );

    /// The parity case generator: t1_len >= 2, the checkpoint index `at` in
    /// 1..t1_len (the checkpoint always has pre-suffix content), t2_len >= 1,
    /// and the entry artifact refs (pool indices 0..3) for t1's entries
    /// 1.. and all of t2's entries (t1's entry 0 is the reserved (3, 3)
    /// pre-suffix-only pair).
    fn parity_case_strategy() -> impl Strategy<Value = ParityCase> {
        (2usize..=4usize)
            .prop_flat_map(|t1_len| (Just(t1_len), 1usize..t1_len, 1usize..=4usize))
            .prop_flat_map(|(t1_len, at, t2_len)| {
                (
                    Just(t1_len),
                    Just(at),
                    Just(t2_len),
                    proptest::collection::vec((0usize..3usize, 0usize..3usize), t1_len - 1),
                    proptest::collection::vec((0usize..3usize, 0usize..3usize), t2_len),
                )
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            // Bounded 16 cases, fixed seed per house style.
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// MULTI-TARGET PREVIEW == EXECUTION PARITY: for every generated
        /// two-target store (shared release/tree pool, observed state, pins,
        /// ghost content), the dry-run preview of a checkpoint on t1 must
        /// enumerate EXACTLY the deletion sets the same checkpoint performs
        /// on a cloned store.
        #[test]
        fn checkpoint_preview_deletions_exactly_match_execution(
            (t1_len, at, t2_len, t1_rest, t2_hist) in parity_case_strategy(),
        ) {
            run_preview_parity_case(t1_len, t2_len, at, &t1_rest, &t2_hist);
        }
    }
}
