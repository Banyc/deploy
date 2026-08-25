//! Checkpoint: model a target's retained history as a monotonic floor.
//!
//! `deploy checkpoint <target> <deployment-id>` establishes a durable
//! HISTORY FLOOR on the target: the checkpoint deployment must be a
//! SUCCESSFUL deployment (it must have a snapshot in the target's op log),
//! and its snapshot becomes the OLDEST ROLLBACK STATE. Everything before it
//! — older snapshots, older attempts (failed attempts included), and their
//! `deployments/<id>/` directories — is discarded; the checkpoint
//! deployment and everything after it is retained. The operation is
//! IRREVERSIBLE: the CLI requires `--yes` (or `--dry-run` to preview the
//! exact discard list) and an explicit deployment id.
//!
//! The checkpoint ALSO runs LOCAL HISTORY COMPACTION + ARTIFACT GARBAGE
//! COLLECTION as its post-commit best-effort maintenance:
//!
//! 1. **History compaction** ([`LocalStore::checkpoint_compact`]): delete
//!    the discarded `deployments/<id>/` dirs and atomically rewrite
//!    `attempts.jsonl` / `snapshots.jsonl` to the retained suffix.
//! 2. **Global artifact GC** ([`crate::store::gc`]): after the compaction
//!    succeeds, scan the WHOLE store, compute the RETAINED SET of artifact
//!    bindings (release, variant, tree) from every target's retained
//!    history, every retained deployment record (unfinished operations
//!    included), every target's current observed artifact, every pin
//!    ([`crate::records::Pins`], `pins.json` — which retain artifact
//!    CONTENT ONLY, never history), and the release records/trees they
//!    reference — then unlink the unreachable `releases/<id>/` and
//!    `objects/sha256/<digest>/` dirs. Reachability is recomputed fresh on
//!    EVERY run: there is no persisted deletion worklist.
//!
//! Both maintenance passes are post-commit best-effort: a failure NEVER
//! moves or removes the established floor and NEVER deletes anything in the
//! retained set — the report says "cleanup incomplete" and the next
//! checkpoint of the same deployment retries (and converges).
//!
//! "Disk cleanup" means unlinking unreachable files/directories and syncing
//! the affected directories so filesystem space can be reclaimed — NOT
//! secure physical erasure: SSD firmware, copy-on-write filesystems,
//! snapshots, journals, and backups may retain old blocks. The checkpoint
//! never contacts servers; remote artifact cleanup remains rotation's
//! responsibility.
//!
//! # Why a marker, not another snapshot
//!
//! The floor is the small [`crate::records::HistoryFloor`] marker at
//! `targets/<target>/refs/history-floor.json` — NOT another deployment or
//! snapshot. The snapshot referenced by `deployment_id` remains the actual
//! rollback state. Establishing a floor does not deploy anything, does not
//! contact any remote server, and does not create another snapshot.
//!
//! # Durability ordering (the crash-safety crux)
//!
//! 1. The floor marker is written FIRST, durably (atomic temp+rename +
//!    directory fsync in [`LocalStore::write_history_floor`]). THIS is the
//!    COMMIT POINT: the instant it is durable the checkpoint took effect.
//! 2. THEN the physical compaction runs ([`LocalStore::checkpoint_compact`]):
//!    delete the `deployments/<id>/` dirs strictly before the floor, then
//!    atomically rewrite `attempts.jsonl` and `snapshots.jsonl` to the
//!    suffix at/after the floor.
//!
//! Because the floor is durable-before-delete and EVERY read path is gated by
//! it ([`LocalStore::read_attempts`], [`LocalStore::read_snapshots`], and
//! ref resolution in [`crate::history::resolve_ref_expr`]), an interrupted
//! compaction leaves either the old physical files or the compacted files —
//! never visible history below the durable floor. The floor is the
//! ENFORCEMENT point; the physical cleanup is best-effort. The deletion runs
//! BEFORE the log rewrites so its worklist stays re-derivable from the logs:
//! a retry after an interruption recomputes the same discard set from the
//! still-intact (or already-rewritten) logs and converges — the deletion
//! worklist is never lost to an interrupted rewrite. Re-running the same
//! checkpoint after an interruption finishes the compaction; re-running it
//! on an already-compacted target is a pure idempotent no-op.
//!
//! # The failure model: the floor write is the commit point
//!
//! `run_checkpoint` propagates a failure ONLY from the floor-marker write
//! (the commit point): a failed marker write is an ordinary `Err` and
//! leaves the PREVIOUS state — no floor on a first-ever checkpoint; on an
//! ADVANCE the replacement is TRANSACTIONAL
//! ([`LocalStore::write_history_floor`]): the backup slot is RECONCILED
//! first (leftover `history-floor.json.prev*` backups of other
//! transactions are durably removed), B's marker is staged, the current
//! floor A is moved aside to a durable, TRANSACTION-TAGGED backup
//! (`history-floor.json.prev.<B-id>`), B is renamed into place, and the
//! parent-directory fsync is B's durability commit point. A failure at ANY
//! stage before that commit point RESTORES A — only from THIS transaction's
//! tagged backup, verified to carry the tag AND to parse and equal the
//! pre-advance floor A (a stale backup from another transaction can never
//! roll the floor backward) — so a failed advancement leaves EXACTLY the
//! pre-advance state (floor A durable, the same visible suffix, no
//! compaction side effects) — advancing a checkpoint can never erase the
//! previously durable floor. If the restore of A itself ALSO fails, the
//! marker may be left absent while the tagged backup
//! (`history-floor.json.prev.<B-id>`) holds A — a TORN ADVANCE. The reader
//! NEVER treats this as "no floor" (which would expose the below-floor
//! prefix): it VALIDATES the durable backup against the SAME integrity
//! binding as the marker and treats a valid backup as the ACTIVE floor
//! (reads see A), failing closed only when the backup itself fails
//! validation. RECOVERY is the ATOMIC RESTORE of the backup — rename the
//! tagged backup back over the marker name + parent-dir fsync
//! ([`LocalStore::recover_history_floor_backup`]): the backup is the ONLY
//! valid floor in a torn state and is NEVER deleted (deleting it would
//! erase the floor and re-expose discarded history). The NEXT CHECKPOINT
//! repairs the torn state AUTOMATICALLY: `checkpoint_inner` restores the
//! validated backup (rename + parent-dir fsync) at its entry, before it
//! plans or writes anything, so a torn advance self-heals through the
//! PRODUCTION path (a re-checkpoint of A first restores the marker, then
//! proceeds through the idempotency branch; an advance to B first restores
//! the marker, then advances normally). Every advance's pre-start
//! reconciliation composes with that: it removes leftover backups ONLY
//! when the floor marker EXISTS — a marker ABSENT alongside a VALIDATED
//! backup is the torn state (the backup is the ONLY valid floor) and is
//! RESTORED, never deleted.
//!
//! EVERY failure AFTER the marker write — enumerating the discards or any
//! compaction phase, on the fresh path or the idempotency-repair path — is
//! POST-COMMIT MAINTENANCE: the checkpoint already took effect, so the
//! command reports SUCCESS with an explicit, DURABLE [`CleanupPending`] debt
//! (`targets/<target>/refs/cleanup-pending.json`, mirroring the
//! rotation-debt discipline) and `CheckpointReport::cleanup_pending` set,
//! NEVER an `Err`. The marker is a flag ONLY — it never carries a deletion
//! worklist: the compaction deletes below-floor dirs BEFORE rewriting the
//! logs, so the raw logs retain the worklist whenever a deletion fails and
//! the retry recomputes the exact delete set from them via
//! [`LocalStore::checkpoint_discards`]. The next checkpoint of the SAME
//! deployment retries the cleanup (the idempotency-repair path); once it
//! completes, the debt marker clears and the report shows no
//! `cleanup_pending`.
//!
//! TRUTHFUL REPORTING: the debt marker's OWN persistence is itself
//! post-commit maintenance. When [`LocalStore::write_cleanup_pending`]
//! fails, the cleanup debt could NOT be made durable — the report must not
//! claim durable debt that a crash/restart would lose — so it sets
//! `CheckpointReport::cleanup_persistence_failed` (the CLI prints an
//! explicit warning) while keeping `cleanup_pending` as the in-memory
//! warning; a re-run recomputes the worklist from the intact logs and
//! converges regardless of the marker. Marker removal is DURABLE too
//! ([`LocalStore::clear_cleanup_pending`]: remove + parent-directory
//! fsync, so a crash can never resurrect the marker); a clear failure
//! leaves a STALE marker — harmless, the retry re-clears it — surfaced
//! truthfully as `CheckpointReport::cleanup_clear_failed`. The SAME
//! computation runs on the idempotent retry path: an already-compacted
//! re-checkpoint still runs the post-commit maintenance, so a maintenance
//! step that fails on the no-op path is reported as a warning exactly like
//! a fresh run — an idempotent retry NEVER suppresses a cleanup warning
//! behind a clean "nothing to discard" claim.
//!
//! # Concurrency
//!
//! The real operation runs under the SAME lock discipline as pushes
//! ([`crate::push::lock::FileLock`]): the application-store lock then the
//! target lock, both advisory (flock) and released on drop. The checkpoint
//! itself NEVER opens a remote: it is local-only by construction (no
//! `RemoteFactory`, no helper map), so it cannot deploy, cannot reconcile
//! against servers, and cannot be affected by a broken or unreachable
//! remote. (A pending-commit attempt whose history lies BELOW the new floor
//! is discarded with the rest of the below-floor history; one at or above it
//! stays and is finalized by the next push exactly as before.) A `--dry-run`
//! preview takes NO locks, writes NOTHING, and enumerates exactly the
//! discard set the compaction would remove ([`LocalStore::checkpoint_discards`]).

use crate::error::{Error, Result};
use crate::model::{
    CLEANUP_PENDING_SCHEMA_VERSION, DeploymentId, OperationId, SCHEMA_VERSION, TargetName,
};
use crate::push::lock::FileLock;
use crate::records::{CleanupPending, HistoryFloor};
use crate::store::gc::GcOutcome;
use crate::store::history_floor::FloorDiscards;
use crate::store::local::LocalStore;

/// The outcome of one checkpoint invocation (preview or real).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointReport {
    pub target: String,
    pub deployment_id: DeploymentId,
    /// The snapshot index the floor sits at (the checkpoint deployment's own
    /// snapshot — the oldest rollback state).
    pub snapshot_index: u64,
    /// Exactly what would be / was discarded (attempts lines, snapshot
    /// entries, deployment directories).
    pub discards: FloorDiscards,
    /// True when this call established (or advanced / repaired) the floor;
    /// false for a pure idempotent no-op and for dry-run previews.
    pub established: bool,
    /// True when the checkpoint's HISTORY COMPACTION ran to completion
    /// (this invocation): the physical attempt/snapshot logs are rewritten
    /// to the suffix at/after the floor. True even on the idempotent
    /// no-op path (the compaction maintenance always runs, and a no-op
    /// leaves the logs already at the suffix); false when the compaction
    /// itself failed and on dry-run previews.
    pub history_compacted: bool,
    /// True when the checkpoint TOOK EFFECT (the durable floor was written)
    /// but the post-commit physical maintenance did not complete: the
    /// history compaction and/or the artifact garbage collection (see
    /// [`CheckpointReport::gc`]) is still pending. The command reports
    /// SUCCESS with this warning set, a durable [`CleanupPending`] debt
    /// marker records the pending cleanup, and the next checkpoint of the
    /// same deployment retries it (retry recomputes both the compaction
    /// discard set from the logs and the artifact reachability set from the
    /// whole store — no deletion worklist is persisted). The maintenance
    /// runs on EVERY path — an idempotent retry computes the same flags as
    /// a fresh run, so a maintenance failure on the no-op path is never
    /// suppressed. False when the cleanup completed, on a pure idempotent
    /// no-op whose maintenance ran clean, and on dry-run previews.
    pub cleanup_pending: bool,
    /// True when the durable [`CleanupPending`] debt marker could NOT be
    /// written — the pending cleanup could not be made durable. This is
    /// TRUTHFUL REPORTING: the report must never claim durable debt that a
    /// crash/restart would lose, so when the marker's own persistence fails
    /// this flag is set explicitly (`cleanup_pending` keeps its in-memory
    /// warning semantics). The retry recomputes the cleanup worklist from
    /// the intact logs and converges regardless. False when the marker was
    /// written, when no marker was needed, and on dry-run previews.
    pub cleanup_persistence_failed: bool,
    /// True when the post-commit cleanup COMPLETED but the debt marker
    /// could not be CLEARED: a stale (harmless — every read is keyed on the
    /// floor, never this marker) marker remains on disk, and the next
    /// same-deployment checkpoint re-clears it. False when the clear
    /// succeeded, when no clear was needed, and on dry-run previews.
    pub cleanup_clear_failed: bool,
    /// The artifact garbage collection outcome of this invocation's
    /// post-commit pass: whether the global scan + unlink ran to completion
    /// and how much unreachable artifact content was removed. The GC is
    /// POST-COMMIT MAINTENANCE (see [`crate::store::gc`]): it never moves
    /// or removes the established floor and never deletes anything in the
    /// retained set. When `gc.completed` is false the report warns
    /// "cleanup incomplete" and the next same-deployment checkpoint retries
    /// the pass (reachability is recomputed fresh — no persisted deletion
    /// worklist). Dry-run previews report the default (not attempted).
    pub gc: GcOutcome,
    /// True when the operation ran read-only (`--dry-run`): no locks, no
    /// writes, no compaction.
    pub dry_run: bool,
}

/// Establish (or preview) a checkpoint history floor on `target` at
/// `deployment_id`.
///
/// `dry_run` runs the full validation and computes the exact discard set but
/// touches NOTHING (no locks, no marker write, no compaction, no remote). The
/// real path takes the application-store + target locks exactly like a push,
/// validates, writes the floor marker durably FIRST, then compacts the
/// physical logs.
pub fn run_checkpoint(
    store: &LocalStore,
    target: &str,
    deployment_id: &DeploymentId,
    dry_run: bool,
) -> Result<CheckpointReport> {
    if dry_run {
        return preview_checkpoint(store, target, deployment_id);
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
    let result = checkpoint_inner(store, target, deployment_id);
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
/// durable floor write (the commit point), and the full
/// `checkpoint_discards` / `checkpoint_compact` path run UNMODIFIED.
#[cfg(test)]
pub(crate) fn run_checkpoint_unlocked(
    store: &LocalStore,
    target: &str,
    deployment_id: &DeploymentId,
) -> Result<CheckpointReport> {
    checkpoint_inner(store, target, deployment_id)
}

/// Shared validation: the checkpoint deployment must have produced a
/// snapshot (i.e. be a successful deployment of this target), and the target
/// must not already sit at an equal-or-newer floor for a DIFFERENT deployment
/// (a checkpoint can never move backward). Returns the planned floor marker.
fn plan_floor(
    store: &LocalStore,
    target: &str,
    deployment_id: &DeploymentId,
) -> Result<HistoryFloor> {
    // The raw (physical) op log: the requested deployment must have a
    // snapshot — i.e. be a SUCCESSFUL deployment — with a canonical index.
    let snapshots = store.read_snapshots_raw(target)?;
    let snapshot = match snapshots.iter().find(|s| s.deployment_id == *deployment_id) {
        Some(s) => s,
        None => {
            let hint = match store.read_history_floor(target)? {
                Some(f) => format!(
                    " (the target's history floor is already at s{} — checkpoint {} — so history before it has been discarded)",
                    f.snapshot_index, f.deployment_id
                ),
                None => String::new(),
            };
            return Err(Error::r#ref(format!(
                "checkpoint requires a successful deployment: no snapshot for deployment '{deployment_id}' \
                 on target '{target}'{hint} — only successful deployments produce a snapshot"
            )));
        }
    };
    let floor = HistoryFloor {
        schema_version: SCHEMA_VERSION,
        target: TargetName::new(target.to_string()),
        deployment_id: deployment_id.clone(),
        snapshot_index: snapshot.index,
        established_at: crate::remote::helper::now_rfc3339(),
    };
    // Backward check against the CURRENT durable floor (a different
    // deployment at an equal-or-newer index can never be re-established).
    if let Some(current) = store.read_history_floor(target)?
        && current.deployment_id != floor.deployment_id
        && current.snapshot_index >= floor.snapshot_index
    {
        return Err(Error::conflict(format!(
            "cannot move backward: target '{target}' already has a history floor at snapshot s{} \
             (checkpoint {}); a checkpoint can never move backward after older history has been discarded",
            current.snapshot_index, current.deployment_id
        )));
    }
    Ok(floor)
}

/// The real (locked) checkpoint: write the durable floor marker FIRST (the
/// COMMIT POINT), then run the post-commit cleanup. An interrupted cleanup
/// (fault/crash) is self-healing: a repeated checkpoint of the same
/// deployment finishes the pending physical compaction.
fn checkpoint_inner(
    store: &LocalStore,
    target: &str,
    deployment_id: &DeploymentId,
) -> Result<CheckpointReport> {
    // PRODUCTION AUTO-REPAIR of a torn floor advance: when a previous
    // advance A→B failed AND its restore of A also failed, the marker may
    // be ABSENT while the durable, TRANSACTION-TAGGED backup
    // (`history-floor.json.prev.<B-id>`) still holds A — the ONLY valid
    // floor. The readers already return A via the validated-backup
    // fallback (never "no floor"); THIS call repairs the torn state
    // BEFORE anything else runs: the validated backup is RESTORED as the
    // marker (rename + parent-dir fsync — the SAME atomic restore a failed
    // advance performs; never a delete). A no-op when the marker exists or
    // nothing is left over; FAILS CLOSED (Err) when the marker is absent
    // but leftovers exist and none validates — an unvalidatable backup is
    // never restored, never deleted, and never silently ignored. After the
    // repair the checkpoint proceeds normally: a re-checkpoint of the
    // original floor A hits the idempotency branch (and may finish a
    // pending cleanup); an advance to B is a clean transactional advance
    // from the durable marker A.
    store.recover_history_floor_backup(target)?;

    let floor = plan_floor(store, target, deployment_id)?;

    // Idempotency: re-checkpointing the SAME deployment id is a no-op when
    // the physical logs are already compacted, and finishes an interrupted
    // cleanup otherwise (the floor marker already bounds every read). The
    // floor for this deployment is ALREADY durable here, so every failure
    // below is post-commit maintenance (committed-with-warning, never Err).
    if let Some(current) = store.read_history_floor(target)?
        && current.deployment_id == floor.deployment_id
    {
        return finish_cleanup(store, target, &floor, false);
    }

    // THE COMMIT POINT: the durable floor marker is written FIRST (atomic
    // temp+rename). The checkpoint takes effect HERE — a failure of this
    // exact write is an ordinary `Err`, and the atomic write leaves NO
    // floor (nothing was discarded, nothing is retryable).
    store.write_history_floor(target, &floor)?;

    // Everything after the commit point is post-commit maintenance: a
    // failure NEVER `Err`s — the floor is already durable, so the
    // checkpoint took effect — it records the durable cleanup-pending debt
    // marker and the report carries the warning (retry converges).
    finish_cleanup(store, target, &floor, true)
}

/// The post-commit half of a checkpoint: enumerate the discards, run (or
/// finish) the physical compaction, and produce the report. The floor
/// marker — the COMMIT POINT — is ALREADY durable when this runs (this call
/// site is reached only after [`LocalStore::write_history_floor`], or when
/// the same-deployment floor already exists from an earlier run).
///
/// FAILURE MODEL: every failure here is POST-COMMIT MAINTENANCE. The
/// checkpoint took effect the instant the floor marker was durable, so this
/// function NEVER returns `Err` from a cleanup failure: a post-marker
/// failure records the durable [`CleanupPending`] debt marker (mirroring the
/// rotation-debt discipline elsewhere in the codebase) and returns SUCCESS
/// with `CheckpointReport::cleanup_pending` set. The next checkpoint of the
/// same deployment retries the cleanup through this same function (the
/// idempotency-repair path); once it completes, the debt marker clears and
/// the report shows no `cleanup_pending`.
///
/// THE NO-OP PATH IS NOT A SKIP: the post-commit maintenance (the
/// compaction, and the debt-marker clear on success / write on failure)
/// runs on EVERY path — including the true no-op path where nothing needs
/// repair — so an idempotent retry computes the SAME warning flags as a
/// fresh post-commit run and can never suppress a maintenance failure
/// behind a clean "nothing to discard" report. The clean no-op report is
/// returned only when nothing needed repair AND every warning flag is
/// false.
fn finish_cleanup(
    store: &LocalStore,
    target: &str,
    floor: &HistoryFloor,
    established: bool,
) -> Result<CheckpointReport> {
    // The pending-cleanup debt from an interrupted run, if any — read
    // INTEGRITY-BOUND to this floor (a corrupted/tampered marker with an
    // arbitrary target/anchor/deployment id fails closed). A read failure
    // is treated as debt outstanding: the repair re-runs the compaction
    // from the intact logs and self-heals (a stale or corrupted marker is
    // then cleared).
    let (pending, pending_read_failed) = match store.read_cleanup_pending(target, Some(floor)) {
        Ok(p) => (p, false),
        Err(_) => (None, true),
    };

    // Post-marker failure point #1: enumerating the discards is a pure read
    // over the physical logs; a failure is committed-with-warning too. The
    // debt-marker write itself is ALSO post-commit maintenance: when it
    // fails, the report must NOT claim durable debt — it exposes
    // `cleanup_persistence_failed` instead (the retry recomputes the
    // worklist from the intact logs and converges regardless).
    let discards = match store.checkpoint_discards(target, floor) {
        Ok(d) => d,
        Err(_) => {
            let persist_failed = record_cleanup_pending(store, target, floor).is_err();
            return Ok(cleanup_report(
                target,
                floor,
                FloorDiscards::default(),
                PostCommit {
                    established: established || pending_read_failed || pending.is_some(),
                    history_compacted: false,
                    gc: GcOutcome::default(),
                    cleanup_pending: true,
                    cleanup_persistence_failed: persist_failed,
                    cleanup_clear_failed: false,
                },
            ));
        }
    };

    let needed_repair = pending_read_failed
        || pending.is_some()
        || !discards.discarded_attempts.is_empty()
        || !discards.discarded_snapshots.is_empty()
        || !discards.discarded_deployments.is_empty();

    // Post-marker failure point #2: the compaction itself. It runs on EVERY
    // path — the repair path AND the true no-op path — so an idempotent
    // retry computes the SAME warning flags as a fresh post-commit run: a
    // maintenance step that fails on the no-op path is NEVER suppressed
    // behind a clean "nothing to do" claim. On failure the floor stands;
    // record the debt durably (the marker is a flag only — the logs retain
    // the worklist) and report the warning. The debt marker's OWN
    // persistence is the last failure surface: if it cannot be written, the
    // report exposes `cleanup_persistence_failed` (truthful reporting — a
    // crash/restart would lose the debt) instead of claiming durable debt.
    //
    // Post-marker failure point #3: the ARTIFACT GARBAGE COLLECTION, which
    // runs AFTER the compaction succeeds (a compaction failure leaves the
    // below-floor worklist in the raw logs and the GC must not run on a
    // half-compacted store). It is the same post-commit best-effort
    // maintenance with the same failure contract: a GC failure NEVER moves
    // or removes the established floor and NEVER deletes anything in the
    // retained set (it aborts before any unlink — see
    // [`crate::store::gc`]), it records the SAME durable debt flag (the
    // marker is a flag only — reachability is recomputed fresh on retry, no
    // deletion worklist is ever persisted), and the report warns "cleanup
    // incomplete". The GC runs on EVERY path (including the idempotent
    // no-op), so a GC failure on the no-op path is never suppressed.
    let (cleanup_pending, persist_failed, clear_failed, gc, history_compacted) =
        match store.checkpoint_compact(target, floor) {
            Ok(()) => {
                // The history compaction completed: the physical logs are
                // rewritten to the retained suffix. Now the artifact GC
                // runs its global scan + unlink; both are post-commit
                // maintenance.
                match store.gc_artifacts(floor.deployment_id.as_str()) {
                    Ok(outcome) => {
                        // The physical cleanup completed (history compacted
                        // AND artifact GC done): the debt marker clears
                        // DURABLY (remove + parent-dir fsync). A clear
                        // failure is itself post-commit maintenance — the
                        // STALE marker (harmless: every read is keyed on
                        // the floor, never the debt marker) is retried by
                        // the next same-deployment checkpoint — and is
                        // surfaced truthfully as `cleanup_clear_failed` so
                        // the report never claims a clean converged state
                        // while a stale marker is on disk.
                        let clear_failed = store.clear_cleanup_pending(target).is_err();
                        (false, false, clear_failed, outcome, true)
                    }
                    Err(_) => {
                        let persist_failed = record_cleanup_pending(store, target, floor).is_err();
                        (true, persist_failed, false, GcOutcome::default(), true)
                    }
                }
            }
            Err(_) => {
                let persist_failed = record_cleanup_pending(store, target, floor).is_err();
                (true, persist_failed, false, GcOutcome::default(), false)
            }
        };

    // A TRUE no-op: nothing needed repair AND the post-commit maintenance
    // ran clean (every warning flag false, GC completed). ONLY this
    // combination returns the clean no-op report — an idempotent retry
    // whose maintenance step failed (or whose stale debt marker could not
    // be cleared) falls through to the report below and surfaces the
    // warnings exactly like a fresh post-commit run. `established` is the
    // caller's truth: a FRESH path established the floor even when there
    // was nothing below it to discard; the same-deployment retry path is a
    // no-op (not established).
    if !needed_repair && !cleanup_pending && !persist_failed && !clear_failed && gc.completed {
        return Ok(cleanup_report(
            target,
            floor,
            FloorDiscards::default(),
            PostCommit {
                established,
                history_compacted,
                gc,
                cleanup_pending: false,
                cleanup_persistence_failed: false,
                cleanup_clear_failed: false,
            },
        ));
    }

    Ok(cleanup_report(
        target,
        floor,
        discards,
        PostCommit {
            established: established || needed_repair,
            history_compacted,
            gc,
            cleanup_pending,
            cleanup_persistence_failed: persist_failed,
            cleanup_clear_failed: clear_failed,
        },
    ))
}

/// The post-commit outcome bits one real checkpoint run accumulates: which
/// maintenance completed (history compaction + artifact GC), which warning
/// flags fired, and whether the floor was established/repaired. Bundled so
/// [`cleanup_report`] stays a small pure constructor (and the report's
/// truthful dimensions stay decidable in one place).
#[derive(Debug)]
struct PostCommit {
    established: bool,
    history_compacted: bool,
    gc: GcOutcome,
    cleanup_pending: bool,
    cleanup_persistence_failed: bool,
    cleanup_clear_failed: bool,
}

/// Build the report for one real (non-preview) checkpoint run.
fn cleanup_report(
    target: &str,
    floor: &HistoryFloor,
    discards: FloorDiscards,
    post: PostCommit,
) -> CheckpointReport {
    CheckpointReport {
        target: target.to_string(),
        deployment_id: floor.deployment_id.clone(),
        snapshot_index: floor.snapshot_index,
        discards,
        established: post.established,
        history_compacted: post.history_compacted,
        cleanup_pending: post.cleanup_pending,
        cleanup_persistence_failed: post.cleanup_persistence_failed,
        cleanup_clear_failed: post.cleanup_clear_failed,
        gc: post.gc,
        dry_run: false,
    }
}

/// Record (or refresh) the durable cleanup-pending debt FLAG. This is
/// itself POST-COMMIT MAINTENANCE: a marker-write failure must never turn
/// the checkpoint into an `Err` (the floor already stands, and the next
/// same-deployment checkpoint re-runs the cleanup from the physical logs
/// regardless of the marker), so the caller maps a write failure to
/// `CheckpointReport::cleanup_persistence_failed` — the report must NOT
/// claim durable debt that a crash/restart would lose. The marker is a
/// FLAG ONLY — it carries no deletion worklist (the logs retain it; see
/// [`crate::store::local::LocalStore::checkpoint_compact`]) — its
/// `target`/`deployment_id`/`snapshot_index` fields exist purely for the
/// integrity binding on read.
fn record_cleanup_pending(store: &LocalStore, target: &str, floor: &HistoryFloor) -> Result<()> {
    let pending = CleanupPending {
        schema_version: CLEANUP_PENDING_SCHEMA_VERSION,
        target: TargetName::new(target.to_string()),
        deployment_id: floor.deployment_id.clone(),
        snapshot_index: floor.snapshot_index,
        established_at: crate::remote::helper::now_rfc3339(),
    };
    store.write_cleanup_pending(target, &pending)
}

/// The read-only preview (`--dry-run`): the same validation (successful
/// deployment, no backward move) plus the exact discard enumeration — and
/// nothing else. No locks, no marker write, no compaction, no remote.
fn preview_checkpoint(
    store: &LocalStore,
    target: &str,
    deployment_id: &DeploymentId,
) -> Result<CheckpointReport> {
    let floor = plan_floor(store, target, deployment_id)?;
    let discards = store.checkpoint_discards(target, &floor)?;
    Ok(CheckpointReport {
        target: target.to_string(),
        deployment_id: deployment_id.clone(),
        snapshot_index: floor.snapshot_index,
        discards,
        established: false,
        history_compacted: false,
        cleanup_pending: false,
        cleanup_persistence_failed: false,
        cleanup_clear_failed: false,
        gc: GcOutcome::default(),
        dry_run: true,
    })
}

/// Render a checkpoint report for the CLI: a dry-run preview enumerates what
/// WOULD be discarded; an established floor reports what WAS discarded; a
/// pure idempotent no-op says so. The CLI prints exactly these lines; the
/// unit tests assert on them directly.
///
/// The four report dimensions are each distinguishable in the output:
///
/// (a) LOGICAL CHECKPOINT ESTABLISHED — the head line names the durable
///     history floor (or the dry-run preview / no-op state);
/// (b) HISTORY FILES COMPACTED — the discard enumeration plus the explicit
///     "history files compacted" line (printed iff the compaction ran to
///     completion, i.e. [`CheckpointReport::history_compacted`]);
/// (c) ARTIFACT GARBAGE COLLECTION COMPLETED — the explicit GC line with
///     the removed release/tree counts (printed iff
///     [`CheckpointReport::gc`].completed);
/// (d) CLEANUP INCOMPLETE AND RETRY REQUIRED — the `warning:` lines
///     (cleanup_pending / cleanup_persistence_failed /
///     cleanup_clear_failed).
///
/// The "nothing to discard" no-op claim is gated on ALL warning flags FALSE:
/// when a maintenance step failed on the idempotent path the report must
/// never print a clean/discard-free statement — the warning lines below are
/// the truth about the non-converged cleanup.
pub fn render_checkpoint_report(report: &CheckpointReport) -> Vec<String> {
    let mut lines = Vec::new();
    let clean_no_op = !report.cleanup_pending
        && !report.cleanup_persistence_failed
        && !report.cleanup_clear_failed;
    let head = if report.dry_run {
        format!(
            "dry-run: checkpoint at snapshot s{} (deployment {}) of target {}",
            report.snapshot_index, report.deployment_id, report.target
        )
    } else if report.established {
        format!(
            "checkpoint established: history floor at snapshot s{} (deployment {}) of target {}",
            report.snapshot_index, report.deployment_id, report.target
        )
    } else if clean_no_op {
        format!(
            "checkpoint already established: history floor at snapshot s{} (deployment {}) of target {} — nothing to discard",
            report.snapshot_index, report.deployment_id, report.target
        )
    } else {
        format!(
            "checkpoint already established: history floor at snapshot s{} (deployment {}) of target {} — cleanup did not converge",
            report.snapshot_index, report.deployment_id, report.target
        )
    };
    lines.push(head);
    // A pure idempotent no-op has nothing to enumerate — but the
    // maintenance status lines (history compaction / artifact GC) and the
    // warning lines must STILL print when they carry truth (the head
    // already dropped the "nothing to discard" claim when a maintenance
    // step failed).
    if !report.dry_run && !report.established {
        if report.history_compacted {
            lines.push(history_compacted_line());
        }
        push_gc_line(&mut lines, report);
        push_checkpoint_warnings(&mut lines, report);
        return lines;
    }
    let verb = if report.dry_run {
        "would discard"
    } else {
        "discarded"
    };
    lines.push(format!(
        "{verb} {} snapshot{}: {}",
        report.discards.discarded_snapshots.len(),
        plural(report.discards.discarded_snapshots.len()),
        report
            .discards
            .discarded_snapshots
            .iter()
            .map(|i| format!("s{i}"))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    lines.push(format!(
        "{verb} {} attempt{}: {}",
        report.discards.discarded_attempts.len(),
        plural(report.discards.discarded_attempts.len()),
        report.discards.discarded_attempts.join(", ")
    ));
    let deletes = if report.dry_run {
        "would delete"
    } else {
        "deleted"
    };
    lines.push(format!(
        "{deletes} {} deployment director{}: {}",
        report.discards.discarded_deployments.len(),
        plural(report.discards.discarded_deployments.len()),
        report.discards.discarded_deployments.join(", ")
    ));
    // (b) history files compacted: printed iff the compaction ran to
    // completion (never on a dry-run preview, never when the compaction
    // itself failed).
    if !report.dry_run && report.history_compacted {
        lines.push(history_compacted_line());
    }
    // (c) artifact garbage collection: printed iff the global GC completed.
    push_gc_line(&mut lines, report);
    push_checkpoint_warnings(&mut lines, report);
    lines
}

/// The dimension-(b) line: the physical history compaction completed.
fn history_compacted_line() -> String {
    "history files compacted: attempts.jsonl and snapshots.jsonl rewritten to the suffix at/after the checkpoint".to_string()
}

/// The dimension-(c) line: the artifact garbage collection completed (the
/// global reachability-based reclamation). Only ever printed when
/// `gc.completed` — a failed/aborted pass is never claimed as completed;
/// its truth lives in the warning lines instead.
fn push_gc_line(lines: &mut Vec<String>, report: &CheckpointReport) {
    if report.dry_run {
        return;
    }
    if !report.gc.completed {
        return;
    }
    if report.gc.removed_releases == 0 && report.gc.removed_trees == 0 {
        lines.push(
            "artifact garbage collection completed: no unreachable artifact content to remove"
                .to_string(),
        );
    } else {
        lines.push(format!(
            "artifact garbage collection completed: removed {} release record{} and {} tree object{}",
            report.gc.removed_releases,
            plural(report.gc.removed_releases),
            report.gc.removed_trees,
            plural(report.gc.removed_trees),
        ));
    }
}

/// The checkpoint warning lines, each printed IFF its flag is set (the CLI
/// prints exactly these lines; the unit tests assert on them directly).
/// Every flag produces its OWN warning — a flagged report never renders as a
/// clean no-op.
fn push_checkpoint_warnings(lines: &mut Vec<String>, report: &CheckpointReport) {
    // Dimension (d): a post-marker maintenance failure (the history
    // compaction and/or the artifact GC) leaves the checkpoint committed
    // but the physical cleanup unfinished: the CLI prints the explicit
    // "cleanup incomplete; retry required" warning (and exits SUCCESS — the
    // checkpoint took effect) and a re-run of the same checkpoint
    // converges. The "cleanup pending" phrasing is retained for the
    // durable-debt semantics: the flag is the same debt flag the compaction
    // failures record.
    if report.cleanup_pending {
        lines.push(format!(
            "warning: cleanup incomplete — history compaction and/or artifact garbage collection did not complete (cleanup pending); re-run `deploy checkpoint {} {}` to retry and converge",
            report.target, report.deployment_id
        ));
    }
    // The debt marker's OWN persistence failed: the report must NOT claim
    // durable debt — this line is the explicit, truthful signal that a
    // crash/restart would lose the pending-cleanup state (the retry
    // recomputes it from the logs / store and converges).
    if report.cleanup_persistence_failed {
        lines.push(format!(
            "warning: cleanup incomplete but the debt marker could not be persisted — re-run `deploy checkpoint {} {}` to converge",
            report.target, report.deployment_id
        ));
    }
    // The cleanup completed but the debt-marker CLEAR failed: a stale
    // (harmless) marker remains on disk; the retry re-clears it.
    if report.cleanup_clear_failed {
        lines.push(format!(
            "warning: cleanup completed but the pending-cleanup marker could not be cleared (a stale marker remains) — re-run `deploy checkpoint {} {}` to converge",
            report.target, report.deployment_id
        ));
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::{self, PushRef};
    use crate::model::{
        ArtifactRef, DeploymentId, GenerationId, GenerationRef, PlacementSlotAssignment,
        PlacementSlotId, ReleaseId, SCHEMA_VERSION, TargetName, TreeDigest, VariantName,
    };
    use crate::records::{
        DeploymentAttempt, DeploymentPlan, DeploymentSnapshot, DeploymentStatus, ObservedServer,
        Pins, PlanSource, ServerPlan,
    };
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    const TARGET: &str = "production";

    fn attempt(id: &str, target: &str) -> DeploymentAttempt {
        DeploymentAttempt {
            deployment_schema_version: SCHEMA_VERSION,
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new(target.to_string()),
            slot_ids: vec![],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: format!("2026-01-01T00:00:00Z-{id}"),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        }
    }

    fn snapshot_entry(index: u64, id: &str, target: &str) -> DeploymentSnapshot {
        DeploymentSnapshot {
            index,
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new(target.to_string()),
            behavior_sha256: "sha256-aa".to_string(),
            slots: BTreeMap::new(),
            bindings: BTreeMap::new(),
        }
    }

    /// Seed a target with a history of `(attempt_ok, ...)` flags: every
    /// attempt gets a `deployments/<id>/` directory (the compaction deletes
    /// exactly the below-floor ones); every successful attempt appends a
    /// snapshot with the next unique index.
    fn seed_history(store: &LocalStore, target: &str, prefix: &str, history: &[bool]) {
        let mut next = 0u64;
        for (n, ok) in history.iter().enumerate() {
            let id = format!("{prefix}-{n:04}");
            store.append_attempt(target, &attempt(&id, target)).unwrap();
            std::fs::create_dir_all(store.deployment_dir(&id)).unwrap();
            if *ok {
                store
                    .append_snapshot(target, &snapshot_entry(next, &id, target))
                    .unwrap();
                next += 1;
            }
        }
    }

    /// Seed the never-delete guard rails: a VALID release record + its tree
    /// object, PINNED via the store's pins API (a release pin — every
    /// variant/tree in the record is retained — plus the exact binding), and
    /// a server state file. These must survive every checkpoint: the pins
    /// retain the artifact CONTENT and the GC never touches servers. The
    /// never-delete fixtures double as the pins contract test: the seeded
    /// release/tree are referenced by NOTHING in any history, so they would
    /// be reclaimed by the artifact GC — only the pins keep them.
    fn seed_never_delete(store: &LocalStore) -> (ReleaseId, TreeDigest, String) {
        let tree = TreeDigest::new("tree-never-delete".to_string());
        let variant = "standard";
        // A real, content-verified release record (write_release verifies;
        // read_release re-verifies at pin-expansion time).
        let variants = BTreeMap::from([(VariantName::new(variant), tree.clone())]);
        let slots: BTreeMap<String, Vec<crate::config::SlotDef>> = BTreeMap::from([(
            variant.to_string(),
            vec![crate::config::SlotDef {
                id: "p1".to_string(),
                server: "s1".to_string(),
                deploy_dir: Path::new("/srv/deploy/p1").to_path_buf(),
                targets: vec!["t1".to_string()],
            }],
        )]);
        let rec = crate::release::build_release(
            "map-never",
            "behavior-never",
            &variants,
            &slots,
            Path::new("."),
        );
        let rel = ReleaseId::new(rec.release_id.clone());
        store.write_release(&rec).unwrap();
        // The tree object dir (GC keys retention on the digest dir name).
        let root = store.object_root(&tree);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("x"), b"x").unwrap();
        // PIN the content: a release pin (marks every variant/tree in the
        // record) AND the exact binding pin.
        let pins = Pins {
            schema_version: crate::model::PINS_SCHEMA_VERSION,
            releases: vec![rel.clone()],
            bindings: vec![ArtifactRef {
                release: rel.clone(),
                variant: VariantName::new(variant),
                tree: tree.clone(),
            }],
        };
        store.write_pins(&pins).unwrap();
        let server = store.base().join("servers").join("s-never.json");
        std::fs::write(&server, b"{}").unwrap();
        (rel, tree, server.to_string_lossy().into_owned())
    }

    fn assert_never_delete(store: &LocalStore, rel: &ReleaseId, tree: &TreeDigest, server: &str) {
        assert!(
            store.release_dir(rel).join("release.json").exists(),
            "pinned release records are never deleted"
        );
        assert!(
            store.object_root(tree).join("x").exists(),
            "pinned tree objects are never deleted"
        );
        assert!(
            Path::new(server).exists(),
            "server records are never deleted"
        );
    }

    /// The checkpoint compaction's discard set: attempts below the
    /// checkpoint's own attempt, snapshots below the floor, and the union of
    /// their deployment dirs.
    #[test]
    fn checkpoint_compacts_history_to_the_suffix() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        // A0 ok (s0), A1 failed, A2 ok (s1), A3 ok (s2).
        seed_history(&store, TARGET, "deploy", &[true, false, true, true]);
        let target_deploy = DeploymentId::new("deploy-0002".to_string());

        let rep = run_checkpoint(&store, TARGET, &target_deploy, false).unwrap();
        assert!(rep.established);
        assert_eq!(rep.snapshot_index, 1);
        assert_eq!(
            rep.discards.discarded_snapshots,
            vec![0],
            "s0 (deploy-0000) is discarded"
        );
        assert_eq!(
            rep.discards.discarded_attempts,
            vec!["deploy-0000".to_string(), "deploy-0001".to_string()],
            "the successful attempt below the floor AND the failed attempt between snapshots are discarded"
        );
        assert_eq!(
            rep.discards.discarded_deployments,
            vec!["deploy-0000".to_string(), "deploy-0001".to_string()]
        );

        // The durable marker sits at the checkpoint snapshot's index.
        let marker = store.read_history_floor(TARGET).unwrap().unwrap();
        assert_eq!(marker.deployment_id, target_deploy);
        assert_eq!(marker.snapshot_index, 1);
        assert_eq!(marker.schema_version, SCHEMA_VERSION);
        assert_eq!(marker.target, TargetName::new(TARGET.to_string()));
        assert!(!marker.established_at.is_empty());

        // Physical logs compacted to the suffix.
        let snaps = store.read_snapshots_raw(TARGET).unwrap();
        assert_eq!(
            snaps.iter().map(|s| s.index).collect::<Vec<_>>(),
            vec![1, 2]
        );
        let attempts = store.read_attempts_raw(TARGET).unwrap();
        assert_eq!(
            attempts
                .iter()
                .map(|a| a.deployment_id.as_str())
                .collect::<Vec<_>>(),
            vec!["deploy-0002", "deploy-0003"]
        );
        // Below-floor deployment directories deleted; the checkpoint and
        // everything after it kept.
        assert!(!store.deployment_dir("deploy-0000").exists());
        assert!(!store.deployment_dir("deploy-0001").exists());
        assert!(store.deployment_dir("deploy-0002").exists());
        assert!(store.deployment_dir("deploy-0003").exists());
    }

    /// The visible history is exactly the suffix: `deploy log` (read_attempts)
    /// shows only the checkpoint attempt onward; read_snapshots only the
    /// floor index onward; the checkpoint snapshot stays the oldest rollback.
    #[test]
    fn visible_history_is_the_suffix_from_the_checkpoint() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        seed_history(&store, TARGET, "deploy", &[true, false, true, true]);
        run_checkpoint(
            &store,
            TARGET,
            &DeploymentId::new("deploy-0002".to_string()),
            false,
        )
        .unwrap();

        let attempts = store.read_attempts(TARGET).unwrap();
        assert_eq!(
            attempts
                .iter()
                .map(|a| a.deployment_id.as_str())
                .collect::<Vec<_>>(),
            vec!["deploy-0002", "deploy-0003"]
        );
        let snaps = store.read_snapshots(TARGET).unwrap();
        assert_eq!(
            snaps.iter().map(|s| s.index).collect::<Vec<_>>(),
            vec![1, 2]
        );

        // Ref resolution: the checkpoint snapshot resolves; below it fails
        // closed with a history-floor error.
        let target = TargetName::new(TARGET.to_string());
        assert_eq!(
            history::resolve_ref_expr(&history::parse_ref_expr("s1").unwrap(), TARGET, &store)
                .unwrap(),
            PushRef::Snapshot {
                target: target.clone(),
                index: 1
            }
        );
        let err =
            history::resolve_ref_expr(&history::parse_ref_expr("s0").unwrap(), TARGET, &store)
                .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("history floor") && msg.contains("deploy-0002"),
            "below-floor ref must name the history floor, got: {msg}"
        );
        // @- on the floored chain [s1, s2]: latest - 1 = s1 (the floor, fine);
        // walking one more (parent(s2, 2)) is below the floor.
        let err = history::resolve_ref_expr(
            &history::parse_ref_expr("parent(s2, 2)").unwrap(),
            TARGET,
            &store,
        )
        .unwrap_err();
        assert!(err.to_string().contains("history floor"), "{err}");
    }

    /// `deploy checkpoint <target> <id> --dry-run` enumerates the discard set
    /// and touches NOTHING (no marker, no compaction, no lock files, no
    /// below-floor deletions) — and the same report lines drive the CLI.
    #[test]
    fn dry_run_previews_discards_without_writing() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        seed_history(&store, TARGET, "deploy", &[true, true, true]);
        let (rel, tree, server) = seed_never_delete(&store);
        let target_deploy = DeploymentId::new("deploy-0001".to_string());

        let rep = run_checkpoint(&store, TARGET, &target_deploy, true).unwrap();
        assert!(rep.dry_run);
        assert!(!rep.established);
        assert_eq!(rep.discards.discarded_snapshots, vec![0]);
        let lines = render_checkpoint_report(&rep);
        assert_eq!(
            lines[0],
            "dry-run: checkpoint at snapshot s1 (deployment deploy-0001) of target production"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("would discard 1 snapshot: s0"))
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("would discard 1 attempt: deploy-0000"))
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("would delete 1 deployment director"))
        );

        // Touches NOTHING: no floor marker, no lock files, history and
        // never-delete files intact, no snapshot/attempt change.
        assert!(store.read_history_floor(TARGET).unwrap().is_none());
        assert_eq!(store.read_snapshots_raw(TARGET).unwrap().len(), 3);
        assert_eq!(store.read_attempts_raw(TARGET).unwrap().len(), 3);
        assert!(!store.target_dir(TARGET).join("operation.lock").exists());
        assert!(!store.base().join("operation.lock").exists());
        assert_never_delete(&store, &rel, &tree, &server);
    }

    /// Repeating the same checkpoint is idempotent: the second call reports
    /// a no-op, changes nothing, and the visible history stays the suffix.
    #[test]
    fn checkpoint_repeat_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        seed_history(&store, TARGET, "deploy", &[true, false, true, true]);
        let dep = DeploymentId::new("deploy-0002".to_string());
        let first = run_checkpoint(&store, TARGET, &dep, false).unwrap();
        assert!(first.established);
        let floor1 = store.read_history_floor(TARGET).unwrap().unwrap();

        let second = run_checkpoint(&store, TARGET, &dep, false).unwrap();
        assert!(!second.established, "a repeated checkpoint is a no-op");
        assert!(second.discards.discarded_attempts.is_empty());
        let floor2 = store.read_history_floor(TARGET).unwrap().unwrap();
        assert_eq!(floor1, floor2, "the durable floor is untouched");
        let lines = render_checkpoint_report(&second);
        assert!(
            lines[0].contains("checkpoint already established"),
            "{lines:?}"
        );
    }

    /// Advancing the checkpoint twice equals checkpointing directly at the
    /// later deployment: same durable floor, same visible history, same
    /// physical files (the compaction is idempotent).
    #[test]
    fn advance_twice_equals_checkpoint_directly_at_later() {
        let build = || {
            let tmp = tempfile::tempdir().unwrap();
            let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
            seed_history(&store, TARGET, "deploy", &[true, true, true, true]);
            (tmp, store)
        };

        // Two-step advance: s0 (deploy-0000) then s2 (deploy-0002).
        let (_t1, s1) = build();
        run_checkpoint(
            &s1,
            TARGET,
            &DeploymentId::new("deploy-0000".to_string()),
            false,
        )
        .unwrap();
        run_checkpoint(
            &s1,
            TARGET,
            &DeploymentId::new("deploy-0002".to_string()),
            false,
        )
        .unwrap();

        // Directly at s2.
        let (_t2, s2) = build();
        run_checkpoint(
            &s2,
            TARGET,
            &DeploymentId::new("deploy-0002".to_string()),
            false,
        )
        .unwrap();

        let f1 = s1.read_history_floor(TARGET).unwrap().unwrap();
        let f2 = s2.read_history_floor(TARGET).unwrap().unwrap();
        assert_eq!(f1.snapshot_index, 2);
        assert_eq!(f2.snapshot_index, 2);
        assert_eq!(
            s1.read_snapshots(TARGET).unwrap(),
            s2.read_snapshots(TARGET).unwrap()
        );
        assert_eq!(
            s1.read_attempts(TARGET).unwrap(),
            s2.read_attempts(TARGET).unwrap()
        );
        assert_eq!(
            std::fs::read(s1.target_dir(TARGET).join("attempts.jsonl")).unwrap(),
            std::fs::read(s2.target_dir(TARGET).join("attempts.jsonl")).unwrap(),
            "the physical attempt log must be byte-identical"
        );
        assert_eq!(
            std::fs::read(s1.refs_dir(TARGET).join("snapshots.jsonl")).unwrap(),
            std::fs::read(s2.refs_dir(TARGET).join("snapshots.jsonl")).unwrap(),
            "the physical snapshot log must be byte-identical"
        );
    }

    /// A checkpoint can never move backward: once the floor sits at s2,
    /// checkpointing s0 is refused with "cannot move backward" while the
    /// below-floor snapshot is still physically present (an interrupted
    /// compaction), and the already-compacted case still fails closed with
    /// the floor hint.
    #[test]
    fn checkpoint_cannot_move_backward() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        seed_history(&store, TARGET, "deploy", &[true, true, true]);
        run_checkpoint(
            &store,
            TARGET,
            &DeploymentId::new("deploy-0001".to_string()),
            false,
        )
        .unwrap();

        // Normal (compacted) state: the earlier snapshot is physically gone,
        // the request still fails closed and points at the floor.
        let err = run_checkpoint(
            &store,
            TARGET,
            &DeploymentId::new("deploy-0000".to_string()),
            false,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("checkpoint requires a successful deployment")
                && msg.contains("history floor")
                && msg.contains("deploy-0001"),
            "compacted backward request must fail closed naming the floor, got: {msg}"
        );

        // Interrupted state (compaction attempts-rewrite phase faulted): the
        // floor is durable at s1 while s0's snapshot is still physically
        // present — the explicit backward guard fires with "cannot move
        // backward". The fault fires AFTER the floor (the commit point), so
        // the checkpoint is a committed-with-warning success, never an Err.
        let s2 = LocalStore::with_base(tmp.path().join("s2")).unwrap();
        seed_history(&s2, TARGET, "deploy", &[true, true, true]);
        s2.fault_registry().arm_compact_attempts("deploy-0001");
        let rep = run_checkpoint(
            &s2,
            TARGET,
            &DeploymentId::new("deploy-0001".to_string()),
            false,
        )
        .expect("a post-marker compaction fault is committed-with-warning, never an Err");
        assert!(
            rep.cleanup_pending,
            "the armed compaction fault is surfaced as cleanup_pending"
        );
        assert!(rep.established);
        let err = run_checkpoint(
            &s2,
            TARGET,
            &DeploymentId::new("deploy-0000".to_string()),
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("cannot move backward"),
            "interrupted backward request must be refused, got: {err}"
        );
    }

    /// A failed/never-successful deployment can never be checkpointed.
    #[test]
    fn checkpoint_requires_successful_deployment() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        seed_history(&store, TARGET, "deploy", &[true, false, false]);
        for id in ["deploy-0001", "deploy-0002", "deploy-9999"] {
            let err = run_checkpoint(&store, TARGET, &DeploymentId::new(id.to_string()), false)
                .unwrap_err();
            assert!(
                err.to_string()
                    .contains("checkpoint requires a successful deployment"),
                "{id} must be refused, got: {err}"
            );
        }
        assert!(store.read_history_floor(TARGET).unwrap().is_none());
    }

    /// A fault on the FLOOR-MARKER WRITE fails the checkpoint cleanly
    /// BEFORE anything is durable: no floor, no compaction — the full
    /// history stays intact and a retry succeeds.
    #[test]
    fn checkpoint_fails_cleanly_when_floor_write_faults() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        seed_history(&store, TARGET, "deploy", &[true, true, true]);
        store
            .fault_registry()
            .arm_write_history_floor("deploy-0001");
        let err = run_checkpoint(
            &store,
            TARGET,
            &DeploymentId::new("deploy-0001".to_string()),
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("test fault"));
        // Nothing became durable and nothing was compacted.
        assert!(store.read_history_floor(TARGET).unwrap().is_none());
        assert_eq!(store.read_snapshots_raw(TARGET).unwrap().len(), 3);
        assert_eq!(store.read_attempts_raw(TARGET).unwrap().len(), 3);
        assert!(store.deployment_dir("deploy-0000").exists());

        // The retry (fault disarmed) succeeds normally.
        let rep = run_checkpoint(
            &store,
            TARGET,
            &DeploymentId::new("deploy-0001".to_string()),
            false,
        )
        .unwrap();
        assert!(rep.established);
        assert_eq!(rep.snapshot_index, 1);
        assert!(!store.deployment_dir("deploy-0000").exists());
    }

    /// Checkpointing one target never changes another target's history.
    #[test]
    fn checkpoint_is_per_target_isolated() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        seed_history(&store, "staging", "stage", &[true, false, true]);
        seed_history(&store, TARGET, "deploy", &[true, true, true]);
        run_checkpoint(
            &store,
            TARGET,
            &DeploymentId::new("deploy-0001".to_string()),
            false,
        )
        .unwrap();

        // The other target keeps its FULL history, its own deployment dirs,
        // and no floor.
        assert!(store.read_history_floor("staging").unwrap().is_none());
        assert_eq!(store.read_attempts("staging").unwrap().len(), 3);
        assert_eq!(store.read_snapshots("staging").unwrap().len(), 2);
        assert!(store.deployment_dir("stage-0000").exists());
        assert!(store.deployment_dir("stage-0001").exists());
        assert!(store.deployment_dir("stage-0002").exists());
        // The checkpointed target keeps its floor deployment and everything
        // after it (deploy-0000 is below the floor and deleted — its
        // staging-side namesakes never were).
        assert!(store.deployment_dir("deploy-0001").exists());
        assert!(store.deployment_dir("deploy-0002").exists());
    }

    /// Appending after compaction mints the next UNIQUE index from the raw
    /// physical log (never a reused one): a compacted [s2, s3] chain appends
    /// s4.
    #[test]
    fn append_after_compaction_produces_unique_increasing_index() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        // A0(s0) A1(s1) A2(failed) A3(s2) A4(s3).
        seed_history(&store, TARGET, "deploy", &[true, true, false, true, true]);
        run_checkpoint(
            &store,
            TARGET,
            &DeploymentId::new("deploy-0003".to_string()),
            false,
        )
        .unwrap();
        assert_eq!(
            store
                .read_snapshots_raw(TARGET)
                .unwrap()
                .iter()
                .map(|s| s.index)
                .collect::<Vec<_>>(),
            vec![2, 3],
            "physical chain after compaction: [s2, s3]"
        );

        // A new successful attempt after the checkpoint: `ensure_snapshot`
        // (the REAL index-minting path) must mint 4, never 2 (len) or 0.
        let new_id = "deploy-0100";
        store
            .append_attempt(TARGET, &attempt(new_id, TARGET))
            .unwrap();
        let idx = history::ensure_snapshot(
            &store,
            &TargetName::new(TARGET.to_string()),
            &attempt(new_id, TARGET),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(idx, 4, "the next index is max + 1, never a reused index");
        let snaps = store.read_snapshots_raw(TARGET).unwrap();
        let indices: Vec<u64> = snaps.iter().map(|s| s.index).collect();
        assert_eq!(indices, vec![2, 3, 4], "no index is ever reused");
        assert_eq!(store.read_snapshots(TARGET).unwrap().len(), 3);
    }

    /// Release records, objects, and server records are never deleted by a
    /// checkpoint (only `deployments/<id>/` dirs strictly before the floor
    /// are).
    #[test]
    fn checkpoint_never_deletes_releases_objects_servers() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        seed_history(&store, TARGET, "deploy", &[true, true, true]);
        let (rel, tree, server) = seed_never_delete(&store);
        run_checkpoint(
            &store,
            TARGET,
            &DeploymentId::new("deploy-0001".to_string()),
            false,
        )
        .unwrap();
        assert_never_delete(&store, &rel, &tree, &server);
        // The floor deployment and the one after it keep their dirs.
        assert!(store.deployment_dir("deploy-0001").exists());
        assert!(store.deployment_dir("deploy-0002").exists());
    }

    // -------------------------------------------------------------------
    // Property tests (bounded, fixed seed for the deterministic floor)
    // -------------------------------------------------------------------

    #[derive(Debug, Clone)]
    enum FloorOp {
        Deploy {
            ok: bool,
        },
        /// Checkpoint the deployment whose snapshot index is `k % (number
        /// of snapshots so far)` — randomly at, below, or above the current
        /// floor, and sometimes missing entirely (empty chain).
        Checkpoint {
            k: u64,
        },
    }

    fn floor_op_strategy() -> impl Strategy<Value = FloorOp> {
        prop_oneof![
            any::<bool>().prop_map(|ok| FloorOp::Deploy { ok }),
            (0u64..16).prop_map(|k| FloorOp::Checkpoint { k }),
        ]
    }

    fn floor_op_vec() -> impl Strategy<Value = Vec<FloorOp>> {
        prop::collection::vec(floor_op_strategy(), 0..14)
    }

    /// The invariant bundle asserted after every op: the visible history is
    /// exactly the suffix at/after the oracle floor; the checkpoint snapshot
    /// resolves; no ref resolves below it; raw indices are strictly
    /// increasing/unique; the marker is readable.
    fn assert_floor_invariants(
        store: &LocalStore,
        all_attempts: &[(String, bool)],
        all_snaps: &[(u64, String)],
        floor: &Option<(String, u64)>,
    ) {
        // 1. Visible snapshots == the suffix at/after the floor.
        let expected: Vec<u64> = match floor {
            Some((_, fidx)) => all_snaps
                .iter()
                .filter(|(i, _)| *i >= *fidx)
                .map(|(i, _)| *i)
                .collect(),
            None => all_snaps.iter().map(|(i, _)| *i).collect(),
        };
        let got: Vec<u64> = store
            .read_snapshots(TARGET)
            .unwrap()
            .iter()
            .map(|s| s.index)
            .collect();
        assert_eq!(
            got, expected,
            "visible snapshots must be the floored suffix"
        );

        // Visible attempts == the suffix from the checkpoint's own attempt.
        let expected_attempts: Vec<String> = match floor {
            Some((fid, _)) => {
                let pos = all_attempts
                    .iter()
                    .position(|(id, _)| id == fid)
                    .expect("floor deployment has an attempt");
                all_attempts[pos..]
                    .iter()
                    .map(|(id, _)| id.clone())
                    .collect()
            }
            None => all_attempts.iter().map(|(id, _)| id.clone()).collect(),
        };
        let got_attempts: Vec<String> = store
            .read_attempts(TARGET)
            .unwrap()
            .iter()
            .map(|a| a.deployment_id.as_str().to_string())
            .collect();
        assert_eq!(
            got_attempts, expected_attempts,
            "visible attempts must be the suffix from the checkpoint's own attempt"
        );

        // The floor marker is readable and consistent.
        if let Some((fid, fidx)) = floor {
            let marker = store.read_history_floor(TARGET).unwrap().unwrap();
            assert_eq!(marker.deployment_id.as_str(), fid);
            assert_eq!(marker.snapshot_index, *fidx);

            // 2. The checkpoint snapshot always resolves.
            let resolved = history::resolve_ref_expr(
                &history::parse_ref_expr(&format!("s{fidx}")).unwrap(),
                TARGET,
                store,
            )
            .unwrap();
            assert_eq!(
                resolved,
                PushRef::Snapshot {
                    target: TargetName::new(TARGET.to_string()),
                    index: *fidx
                }
            );

            // 3. No reference resolves below the checkpoint.
            for k in 0..*fidx {
                let err = history::resolve_ref_expr(
                    &history::parse_ref_expr(&format!("s{k}")).unwrap(),
                    TARGET,
                    store,
                )
                .unwrap_err();
                let msg = err.to_string();
                assert!(
                    msg.contains("history floor") || msg.contains("no snapshot"),
                    "below-floor s{k} must fail closed, got: {msg}"
                );
            }
        }

        // 4. Raw snapshot indices are strictly increasing and unique (a
        //    compaction that reused an index would break this).
        let raw: Vec<u64> = store
            .read_snapshots_raw(TARGET)
            .unwrap()
            .iter()
            .map(|s| s.index)
            .collect();
        let mut sorted = raw.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(raw, sorted, "raw indices must be unique and in order");
        assert!(raw.windows(2).all(|w| w[0] < w[1]));
    }

    fn run_floor_case(ops: Vec<FloorOp>) {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        // Cross-target isolation guard: `staging` gets a fixed history and
        // must never change (5. checkpointing one target never changes
        // another).
        seed_history(&store, "staging", "stage", &[true, false, true]);
        let (rel, tree, server) = seed_never_delete(&store);

        let mut all_attempts: Vec<(String, bool)> = Vec::new();
        let mut all_snaps: Vec<(u64, String)> = Vec::new();
        let mut floor: Option<(String, u64)> = None;
        let mut seq = 0u64;

        for op in ops {
            match op {
                FloorOp::Deploy { ok } => {
                    let id = format!("deploy-t{seq:03}");
                    seq += 1;
                    store.append_attempt(TARGET, &attempt(&id, TARGET)).unwrap();
                    std::fs::create_dir_all(store.deployment_dir(&id)).unwrap();
                    all_attempts.push((id.clone(), ok));
                    if ok {
                        // The REAL index-minting path (max + 1 over the raw
                        // log) — a compacted chain must never reuse an index.
                        let idx = history::ensure_snapshot(
                            &store,
                            &TargetName::new(TARGET.to_string()),
                            &attempt(&id, TARGET),
                            &BTreeMap::new(),
                            &BTreeMap::new(),
                        )
                        .unwrap();
                        assert!(
                            !all_snaps.iter().any(|(i, _)| *i == idx),
                            "appending after compaction always produces a unique, increasing index"
                        );
                        all_snaps.push((idx, id));
                    }
                }
                FloorOp::Checkpoint { k } => {
                    let s = all_snaps.len();
                    if s == 0 {
                        // No snapshots yet: any deployment id fails closed.
                        let err = run_checkpoint(
                            &store,
                            TARGET,
                            &DeploymentId::new("deploy-missing-0"),
                            false,
                        )
                        .unwrap_err();
                        assert!(
                            err.to_string()
                                .contains("checkpoint requires a successful deployment"),
                            "empty-chain checkpoint must fail, got: {err}"
                        );
                        continue;
                    }
                    let (target_idx, target_id) = all_snaps[k as usize % s].clone();
                    let res = run_checkpoint(
                        &store,
                        TARGET,
                        &DeploymentId::new(target_id.clone()),
                        false,
                    );
                    match &floor {
                        None => {
                            let rep = res.expect("first checkpoint establishes the floor");
                            assert!(rep.established);
                            floor = Some((target_id, target_idx));
                        }
                        Some((fid, fidx)) => {
                            if target_idx < *fidx {
                                // 6. A checkpoint can never move backward.
                                let err = res.expect_err("backward checkpoint must fail");
                                let msg = err.to_string();
                                assert!(
                                    msg.contains("cannot move backward")
                                        || msg.contains(
                                            "checkpoint requires a successful deployment"
                                        )
                                        || msg.contains("history floor"),
                                    "backward checkpoint must fail closed, got: {msg}"
                                );
                            } else if target_idx == *fidx {
                                // 4. Repeating the same checkpoint is idempotent.
                                assert_eq!(target_id, *fid);
                                let out = res.unwrap();
                                assert!(
                                    !out.established,
                                    "the same checkpoint is idempotent (no-op)"
                                );
                            } else {
                                let out = res.unwrap();
                                assert!(
                                    out.established,
                                    "advancing to a later deployment updates the floor"
                                );
                                floor = Some((target_id, target_idx));
                            }
                        }
                    }
                }
            }
            assert_floor_invariants(&store, &all_attempts, &all_snaps, &floor);
        }

        // 5. Checkpointing one target never changes another target.
        assert!(store.read_history_floor("staging").unwrap().is_none());
        assert_eq!(store.read_attempts("staging").unwrap().len(), 3);
        assert_eq!(
            store
                .read_snapshots("staging")
                .unwrap()
                .iter()
                .map(|s| s.index)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        // 10. Release records, objects, and pinned artifacts are never deleted.
        assert_never_delete(&store, &rel, &tree, &server);
    }

    proptest! {
        // Deterministic floor: the SAME generator under the pinned
        // 0x5EED_5EED seed runs identical vectors on every invocation
        // (bounded cases keep the suite fast; each case drives a fresh
        // fixture).
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn history_floor_properties(ops in floor_op_vec()) {
            run_floor_case(ops);
        }
    }

    proptest! {
        // The COMMIT-POINT property: the floor marker write is the commit
        // point — a failure there is an ordinary `Err` with NO floor; EVERY
        // post-marker failure (the three compaction phases) is a
        // committed-with-warning success (floor durable, cleanup_pending
        // marker written, visible history never below the floor); and after
        // the one-shot fault disarms, re-running the SAME checkpoint
        // converges (no cleanup_pending, debt marker cleared, physical logs
        // compacted to the suffix, no below-floor deployment dirs).
        // The seeded history always includes a FAILED attempt (a deployment
        // dir with NO snapshot) below any non-zero floor, so the retry must
        // also converge to delete the failed-without-snapshot dirs from the
        // ORIGINAL worklist.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn post_marker_failure_commits_with_warning_and_converges(
            history in prop::collection::vec(any::<bool>(), 3..7),
            checkpoint_at in 0usize..8,
            phase in 0usize..4,
        ) {
            run_commit_point_case(&history, checkpoint_at, phase);
        }
    }

    fn run_commit_point_case(history_in: &[bool], checkpoint_at: usize, phase: usize) {
        // Prepend a guaranteed success (so the checkpoint always has a
        // successful deployment to target) followed by a guaranteed FAILED
        // attempt: a `deployments/<id>/` dir with NO snapshot line. The
        // failed attempt sits strictly below any non-zero floor, so every
        // case that discards anything genuinely exercises the
        // failed-attempt-without-snapshot dir cleanup (only its
        // attempts.jsonl line names such a dir — nothing else can
        // re-enumerate it once the log is rewritten).
        let mut history = vec![true, false];
        history.extend_from_slice(history_in);
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        seed_history(&store, TARGET, "deploy", &history);
        let ok_ids: Vec<String> = history
            .iter()
            .enumerate()
            .filter(|(_, ok)| **ok)
            .map(|(n, _)| format!("deploy-{n:04}"))
            .collect();
        assert!(
            !ok_ids.is_empty(),
            "a checkpoint needs at least one success"
        );
        let target_id = ok_ids[checkpoint_at % ok_ids.len()].clone();
        let floor_index = ok_ids.iter().position(|id| *id == target_id).unwrap() as u64;
        // The position of the checkpoint attempt in the FULL history: every
        // attempt (successful or failed) before it owns a below-floor
        // `deployments/<id>/` directory.
        let target_pos = history
            .iter()
            .enumerate()
            .find(|(n, _)| format!("deploy-{n:04}") == target_id)
            .unwrap()
            .0;
        let below_floor_ids: Vec<String> = history
            .iter()
            .enumerate()
            .take(target_pos)
            .map(|(n, _)| format!("deploy-{n:04}"))
            .collect();

        // The ORIGINAL discard worklist, enumerated from the still-intact
        // seeded logs exactly as the compaction's first call does — this is
        // the deletion list an interruption must never lose. Captured before
        // any fault, so the retry assertions can demand every one of these
        // dirs (including the failed-without-snapshot ones) is absent.
        let floor = plan_floor(&store, TARGET, &DeploymentId::new(target_id.clone()))
            .expect("the checkpoint deployment is a success, so it has a snapshot");
        let original = store
            .checkpoint_discards(TARGET, &floor)
            .expect("the pre-compaction logs enumerate the full discard worklist");
        if floor_index > 0 {
            assert!(
                original
                    .discarded_deployments
                    .iter()
                    .any(|id| id == "deploy-0001"),
                "the failed-without-snapshot attempt below the floor is in the original worklist"
            );
        }

        // Arm the fault for the phase under test (keyed by the checkpoint
        // deployment id). Phase 0 is the floor-marker WRITE (the commit
        // point); phases 1-3 are the three post-marker compaction phases.
        match phase {
            0 => store.fault_registry().arm_write_history_floor(&target_id),
            1 => store.fault_registry().arm_compact_attempts(&target_id),
            2 => store.fault_registry().arm_compact_snapshots(&target_id),
            _ => store.fault_registry().arm_compact_deployments(&target_id),
        }
        let res = run_checkpoint(&store, TARGET, &DeploymentId::new(target_id.clone()), false);

        if phase == 0 {
            // (a) The FLOOR WRITE is the COMMIT POINT: a failure here is an
            // ordinary `Err`, and NO floor exists (the atomic write leaves
            // nothing) — nothing was discarded and nothing is retryable.
            let err = res.expect_err("a floor-write failure is an ordinary Err");
            assert!(err.to_string().contains("test fault"));
            assert!(
                store.read_history_floor(TARGET).unwrap().is_none(),
                "a failed floor write must leave NO floor"
            );
            assert!(
                store.read_cleanup_pending(TARGET, None).unwrap().is_none(),
                "no cleanup-pending debt marker without a durable floor"
            );
            // Nothing was discarded or compacted: full history intact.
            assert_eq!(
                store.read_attempts_raw(TARGET).unwrap().len(),
                history.len()
            );
            assert_eq!(
                store.read_snapshots_raw(TARGET).unwrap().len(),
                ok_ids.len()
            );
            for id in &below_floor_ids {
                assert!(
                    store.deployment_dir(id).exists(),
                    "nothing below a nonexistent floor is ever deleted: {id}"
                );
            }
            return;
        }

        // (b) EVERY post-marker failure is COMMITTED WITH A WARNING: the
        // checkpoint took effect while the cleanup could not complete, so
        // the command reports SUCCESS with cleanup_pending set — never Err.
        let rep = res.expect("a post-marker failure is committed-with-warning, never an Err");
        assert!(rep.established);
        assert_eq!(rep.snapshot_index, floor_index);

        // The floor is DURABLE and the readers never expose history below
        // it — the core property.
        let marker = store.read_history_floor(TARGET).unwrap().unwrap();
        assert_eq!(marker.snapshot_index, floor_index);
        assert_eq!(marker.deployment_id.as_str(), target_id);
        let visible = store.read_snapshots(TARGET).unwrap();
        assert!(
            visible.iter().all(|s| s.index >= floor_index),
            "interrupted cleanup must never expose history below the durable floor"
        );
        assert_eq!(
            visible[0].index, floor_index,
            "the checkpoint snapshot stays the oldest visible"
        );
        let attempts = store.read_attempts(TARGET).unwrap();
        assert_eq!(
            attempts[0].deployment_id.as_str(),
            target_id,
            "the visible attempts start at the checkpoint's own attempt"
        );
        // Below-floor refs refused; the checkpoint itself resolves.
        history::resolve_ref_expr(
            &history::parse_ref_expr(&format!("s{floor_index}")).unwrap(),
            TARGET,
            &store,
        )
        .expect("the checkpoint snapshot always remains resolvable");
        if floor_index > 0 {
            let err = history::resolve_ref_expr(
                &history::parse_ref_expr(&format!("s{}", floor_index - 1)).unwrap(),
                TARGET,
                &store,
            )
            .unwrap_err();
            assert!(
                err.to_string().contains("history floor")
                    || err.to_string().contains("no snapshot"),
                "below-floor ref must stay refused, got: {err}"
            );
        }

        // Boundary case: the checkpoint sits at the very FIRST attempt (the
        // floor is at index 0 with nothing below it). The post-commit
        // maintenance still RUNS (the no-op path computes the SAME flags as
        // the real path), so the armed post-marker fault fires and the
        // checkpoint reports committed-with-warning exactly like any
        // post-marker failure: cleanup pending, durable debt marker.
        if below_floor_ids.is_empty() {
            assert!(
                rep.cleanup_pending,
                "the armed post-marker fault fires on the no-op maintenance path too"
            );
            assert!(
                store
                    .read_cleanup_pending(TARGET, Some(&floor))
                    .unwrap()
                    .is_some(),
                "the durable debt flag records the pended maintenance"
            );
            // The re-run (fault disarmed) converges: no pending, no debt
            // marker.
            let retry =
                run_checkpoint(&store, TARGET, &DeploymentId::new(target_id.clone()), false)
                    .expect("the repeated checkpoint converges");
            assert!(
                !retry.cleanup_pending
                    && !retry.cleanup_persistence_failed
                    && !retry.cleanup_clear_failed,
                "the re-run clears the pended maintenance"
            );
            assert!(
                store
                    .read_cleanup_pending(TARGET, Some(&floor))
                    .unwrap()
                    .is_none(),
                "the debt marker clears once the re-run converges"
            );
            return;
        }

        // The DURABLE debt FLAG records the pending cleanup and the CLI
        // render includes the explicit warning line. The marker is a flag
        // only: it carries NO deletion worklist (the logs retain it), so its
        // only content assertions are the integrity-binding fields.
        assert!(
            rep.cleanup_pending,
            "the armed compaction is surfaced as cleanup_pending"
        );
        let pending = store
            .read_cleanup_pending(TARGET, Some(&floor))
            .unwrap()
            .expect("a durable cleanup-pending FLAG records the debt");
        assert_eq!(pending.schema_version, CLEANUP_PENDING_SCHEMA_VERSION);
        assert_eq!(pending.target, TargetName::new(TARGET.to_string()));
        assert_eq!(pending.deployment_id.as_str(), target_id);
        assert_eq!(pending.snapshot_index, floor_index);
        assert!(!pending.established_at.is_empty());
        let lines = render_checkpoint_report(&rep);
        assert!(
            lines.iter().any(|l| l.contains("cleanup pending")),
            "the render must warn about pending cleanup, got: {lines:?}"
        );

        // (c) The fault is one-shot (now disarmed): re-running the SAME
        // checkpoint converges — Ok, no cleanup_pending, the debt marker
        // clears, and the physical logs are compacted to the suffix with no
        // below-floor deployment dirs/files left.
        let retry = run_checkpoint(&store, TARGET, &DeploymentId::new(target_id.clone()), false)
            .expect("a repeated checkpoint after interruption must succeed");
        assert!(
            !retry.cleanup_pending,
            "converged: no cleanup pending on the re-run"
        );
        assert!(
            store
                .read_cleanup_pending(TARGET, Some(&floor))
                .unwrap()
                .is_none(),
            "the debt marker clears once the cleanup completes"
        );
        let marker_after = store.read_history_floor(TARGET).unwrap().unwrap();
        assert_eq!(marker_after.snapshot_index, floor_index);
        let visible_after = store.read_snapshots(TARGET).unwrap();
        assert!(visible_after.iter().all(|s| s.index >= floor_index));
        assert_eq!(visible_after[0].index, floor_index);
        // Physical convergence: the RAW logs hold only the suffix and every
        // below-floor deployment dir is deleted (the at/above-floor ones
        // remain).
        let raw_snaps = store.read_snapshots_raw(TARGET).unwrap();
        assert!(
            raw_snaps.iter().all(|s| s.index >= floor_index),
            "no below-floor snapshot lines remain after convergence"
        );
        let raw_attempts = store.read_attempts_raw(TARGET).unwrap();
        let keep_from = raw_attempts
            .iter()
            .position(|a| a.deployment_id.as_str() == target_id)
            .expect("the checkpoint's own attempt is retained");
        assert!(
            raw_attempts[..keep_from].is_empty(),
            "no below-floor attempt lines remain after convergence"
        );
        for (n, _) in history.iter().enumerate() {
            let id = format!("deploy-{n:04}");
            if n < target_pos {
                assert!(
                    !store.deployment_dir(&id).exists(),
                    "below-floor dir {id} must be deleted on convergence"
                );
            } else {
                assert!(
                    store.deployment_dir(&id).exists(),
                    "at/above-floor dir {id} must remain"
                );
            }
        }

        if floor_index > 0 {
            assert!(
                retry.established,
                "an interruption in every compaction phase is repaired by the repeat"
            );
        }
        // The retry converges the compaction: every dir in the ORIGINAL
        // discard worklist is gone from disk (explicitly including the
        // failed-without-snapshot dirs, which only the attempts log names)
        // and both logs end compacted to the suffix — the deletion worklist
        // was never lost to the interrupted run.
        for id in &original.discarded_deployments {
            assert!(
                !store.deployment_dir(id).exists(),
                "originally-discarded deployment dir {id} must be absent after the retry"
            );
        }
        let attempts_after = store.read_attempts_raw(TARGET).unwrap();
        assert_eq!(
            attempts_after[0].deployment_id.as_str(),
            target_id,
            "the retry converges the attempts log to the checkpoint suffix"
        );
        let snaps_after = store.read_snapshots_raw(TARGET).unwrap();
        assert!(
            snaps_after.iter().all(|s| s.index >= floor_index),
            "the retry converges the snapshots log to the floor suffix"
        );
    }

    // ---------------------------------------------------------------------
    // DURABLE-DEBT TRUTHFULNESS (the persistence-failure property)
    // ---------------------------------------------------------------------

    /// One durable-debt truthfulness case: the FULL matrix over (cleanup
    /// outcome: SUCCESS | a compaction phase FAILS → pending) × (debt-marker
    /// WRITE failure | success) × (debt-marker CLEAR failure | success),
    /// with a REOPEN — after the run, a FRESH [`LocalStore`] is constructed
    /// over the SAME base dir (simulating a crash/restart) and the durable
    /// state is re-read.
    ///
    /// THE CLEAR PATH NEEDS A MARKER: a fresh run's success path clears a
    /// marker that was never written, so the clear-failure cells first seed
    /// the durable-debt state — an earlier interrupted checkpoint (a
    /// compaction fault with a fault-free marker write) — exactly the state
    /// a crash/restart would reopen into, and then run the matrix cell.
    ///
    /// THE INVARIANT: a run that claims cleanup debt (or reports a
    /// marker-write/clear failure) must be TRUTHFUL — EITHER the durable
    /// debt survives the reopen (`read_cleanup_pending` finds the marker /
    /// `cleanup_pending_path` exists) OR the report explicitly says the
    /// marker could not be persisted (`cleanup_persistence_failed`). The
    /// one all-clean cell claims nothing and owes nothing. AND a RETRY
    /// always converges: re-running the checkpoint on the reopened store
    /// (faults disarmed — a fresh store has an empty per-fixture registry)
    /// ends with the marker gone, the logs compacted to the suffix, and no
    /// below-floor exposure at any point.
    fn run_debt_truthfulness_case(
        history_in: &[bool],
        checkpoint_at: usize,
        cleanup_fails: bool,
        write_fails: bool,
        clear_fails: bool,
    ) {
        // Seeded prefix (mirroring the commit-point test): a guaranteed
        // success then a guaranteed FAILED attempt — a `deployments/<id>/`
        // dir with NO snapshot line — so every case has below-floor material
        // (the failed attempt's dir is named only by its attempts.jsonl
        // line, the worklist the logs must retain).
        let mut history = vec![true, false];
        history.extend_from_slice(history_in);
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        seed_history(&store, TARGET, "deploy", &history);
        let ok_ids: Vec<String> = history
            .iter()
            .enumerate()
            .filter(|(_, ok)| **ok)
            .map(|(n, _)| format!("deploy-{n:04}"))
            .collect();
        assert!(
            ok_ids.len() >= 2,
            "the seeded prefix plus the filtered history guarantee >= 2 successes"
        );
        // Never the FIRST success: every case has a real below-floor prefix,
        // so the compaction genuinely runs and the armed cleanup/clear
        // faults are reachable.
        let target_id = ok_ids[1 + checkpoint_at % (ok_ids.len() - 1)].clone();
        let floor_index = ok_ids.iter().position(|id| *id == target_id).unwrap() as u64;
        let target_pos = history
            .iter()
            .enumerate()
            .find(|(n, _)| format!("deploy-{n:04}") == target_id)
            .unwrap()
            .0;
        assert!(floor_index > 0, "the checkpoint is never the first success");

        // SEED the durable-debt state when the cell faults the CLEAR: the
        // clear is only reachable when a marker exists on disk, so first
        // replay an EARLIER interrupted checkpoint — a compaction fault with
        // a fault-free marker write — leaving the durable debt marker (plus
        // intact logs and below-floor dirs already deleted) exactly as a
        // crash/restart would find it. The one-shot compact fault is then
        // re-armed below for the matrix cell.
        if clear_fails {
            store.fault_registry().arm_compact_attempts(&target_id);
            let p1 = run_checkpoint(&store, TARGET, &DeploymentId::new(target_id.clone()), false)
                .expect("the seeding run commits with a warning, never an Err");
            assert!(p1.cleanup_pending, "the seeding run leaves cleanup pending");
            assert!(
                !p1.cleanup_persistence_failed,
                "the seeding run persists the debt"
            );
            assert!(
                !p1.cleanup_clear_failed,
                "the seeding run has no clear failure"
            );
            assert!(
                store.read_cleanup_pending(TARGET, None).unwrap().is_some(),
                "the seeding run leaves the durable debt marker"
            );
        }

        // Arm EXACTLY the matrix cell's faults: a compaction phase
        // (cleanup_fails), the debt-marker write (write_fails — only reached
        // when the cleanup fails), and the debt-marker clear (clear_fails —
        // only reached when the cleanup succeeds on a marker-bearing
        // fixture). Unreachable arms simply stay in this fixture's registry
        // and never fire (the reopen uses a fresh store with an empty
        // registry).
        if cleanup_fails {
            store.fault_registry().arm_compact_attempts(&target_id);
        }
        if write_fails {
            store.fault_registry().arm_write_cleanup_pending(&target_id);
        }
        if clear_fails {
            store.fault_registry().arm_clear_cleanup_pending(TARGET);
        }
        let rep = run_checkpoint(&store, TARGET, &DeploymentId::new(target_id.clone()), false)
            .expect("post-commit maintenance failures are committed-with-warning, never an Err");
        assert!(rep.established);
        assert_eq!(rep.snapshot_index, floor_index);

        // The report's flags EXACTLY match the matrix cell (truthful
        // reporting in both directions — no phantom pending, no silently
        // absorbed persistence/clear failure).
        assert_eq!(
            rep.cleanup_pending, cleanup_fails,
            "cleanup_pending must reflect the compaction outcome"
        );
        assert_eq!(
            rep.cleanup_persistence_failed,
            cleanup_fails && write_fails,
            "the persistence-failure flag is set iff the debt-marker write faulted"
        );
        assert_eq!(
            rep.cleanup_clear_failed,
            !cleanup_fails && clear_fails,
            "the clear-failure flag is set iff the debt-marker clear faulted on the success path"
        );

        // The CLI render carries the explicit truthfulness lines: the
        // persistence failure warns that the marker could not be made
        // durable, and the clear failure warns that a stale marker remains.
        let lines = render_checkpoint_report(&rep);
        if rep.cleanup_persistence_failed {
            assert!(
                lines.iter().any(|l| l.contains("could not be persisted")),
                "the render must expose the persistence failure, got: {lines:?}"
            );
        }
        if rep.cleanup_clear_failed {
            assert!(
                lines.iter().any(|l| l.contains("stale marker")),
                "the render must expose the clear failure, got: {lines:?}"
            );
        }

        // REOPEN: a FRESH LocalStore over the SAME base dir — simulating a
        // crash/restart. Its per-fixture fault registry is EMPTY, so the
        // retry below runs fault-free by construction.
        let reopened = LocalStore::with_base(store.base().to_path_buf()).unwrap();
        let durable_debt = reopened
            .read_cleanup_pending(TARGET, None)
            .unwrap()
            .is_some()
            || reopened.cleanup_pending_path(TARGET).exists();

        // THE INVARIANT: whenever the run claims debt (or reports a
        // marker-write/clear failure), the durable state after a
        // crash/restart agrees — EITHER the durable debt survives the
        // reopen OR the report explicitly says the marker could not be
        // persisted. A run that reports a fully clean outcome claims
        // nothing and owes nothing.
        if rep.cleanup_pending || rep.cleanup_clear_failed || rep.cleanup_persistence_failed {
            assert!(
                durable_debt || rep.cleanup_persistence_failed,
                "matrix cell (cleanup_fails={cleanup_fails}, write_fails={write_fails}, \
                 clear_fails={clear_fails}): the report claims cleanup debt/failure but neither \
                 durable debt survived the reopen nor did the report say persistence failed"
            );
        }

        // NO BELOW-FLOOR EXPOSURE AT ANY POINT: even in the write-failure
        // cell (no debt marker on disk) the DURABLE FLOOR gates every read
        // — the reopened store exposes exactly the suffix and refuses
        // below-floor refs.
        let visible = reopened.read_snapshots(TARGET).unwrap();
        assert!(
            visible.iter().all(|s| s.index >= floor_index),
            "the reopened store never exposes history below the durable floor"
        );
        assert_eq!(visible[0].index, floor_index);
        let attempts = reopened.read_attempts(TARGET).unwrap();
        assert_eq!(
            attempts[0].deployment_id.as_str(),
            target_id,
            "the reopened store shows the suffix from the checkpoint's own attempt"
        );
        let err = history::resolve_ref_expr(
            &history::parse_ref_expr(&format!("s{}", floor_index - 1)).unwrap(),
            TARGET,
            &reopened,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("history floor") || err.to_string().contains("no snapshot"),
            "below-floor refs stay refused after the reopen, got: {err}"
        );

        // RETRY (faults disarmed): re-running the SAME checkpoint on the
        // reopened store ALWAYS converges — Ok, no pending, no
        // persistence/clear failure, the debt marker gone, and the physical
        // logs compacted to the suffix.
        let retry = run_checkpoint(
            &reopened,
            TARGET,
            &DeploymentId::new(target_id.clone()),
            false,
        )
        .expect("the retry converges, never an Err");
        assert!(!retry.cleanup_pending, "converged: no cleanup pending");
        assert!(
            !retry.cleanup_persistence_failed,
            "converged: no persistence failure on the retry"
        );
        assert!(
            !retry.cleanup_clear_failed,
            "converged: no clear failure on the retry"
        );
        // A converged retry that had to REPAIR anything (a faulted first run
        // or a stale marker to re-clear) reports established; the all-clean
        // cell's retry is a pure idempotent no-op.
        assert_eq!(retry.established, cleanup_fails || clear_fails);
        assert!(
            reopened
                .read_cleanup_pending(TARGET, None)
                .unwrap()
                .is_none(),
            "converged: no durable debt after the retry"
        );
        assert!(
            !reopened.cleanup_pending_path(TARGET).exists(),
            "converged: the debt marker file is gone"
        );
        let raw_attempts = reopened.read_attempts_raw(TARGET).unwrap();
        assert_eq!(
            raw_attempts[0].deployment_id.as_str(),
            target_id,
            "converged: attempts.jsonl is compacted to the checkpoint suffix"
        );
        let raw_snaps = reopened.read_snapshots_raw(TARGET).unwrap();
        assert!(
            raw_snaps.iter().all(|s| s.index >= floor_index),
            "converged: snapshots.jsonl is compacted to the floor suffix"
        );
        for (n, _) in history.iter().enumerate() {
            let id = format!("deploy-{n:04}");
            if n < target_pos {
                assert!(
                    !reopened.deployment_dir(&id).exists(),
                    "converged: below-floor dir {id} is deleted"
                );
            } else {
                assert!(
                    reopened.deployment_dir(&id).exists(),
                    "converged: at/above-floor dir {id} is retained"
                );
            }
        }
    }

    proptest! {
        // DURABLE-DEBT TRUTHFULNESS: the bounded, fixed-seed matrix over
        // (cleanup outcome: SUCCESS | a compaction phase FAILS → pending) ×
        // (debt-marker WRITE failure | success) × (debt-marker CLEAR
        // failure | success), each case followed by a REOPEN (a fresh
        // LocalStore over the same base dir — simulating a crash/restart).
        // THE INVARIANT: whenever the run claims cleanup debt (or reports a
        // marker-write/clear failure), EITHER the durable debt survives the
        // reopen OR the report explicitly says the marker could not be
        // persisted (`cleanup_persistence_failed`) — the report never
        // claims durable debt that a crash would lose — AND a retry always
        // converges: re-running the checkpoint (faults disarmed) ends with
        // the marker gone, the logs compacted to the suffix, and no
        // below-floor exposure at any point.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn cleanup_debt_reporting_is_truthful_and_retry_converges(
            history in prop::collection::vec(any::<bool>(), 2..5)
                .prop_filter(
                    "the seeded prefix plus the filtered history needs >= 2 successes",
                    |v| v.iter().filter(|ok| **ok).count() >= 1,
                ),
            checkpoint_at in 0usize..8,
            cleanup_fails in any::<bool>(),
            write_fails in any::<bool>(),
            clear_fails in any::<bool>(),
        ) {
            run_debt_truthfulness_case(
                &history,
                checkpoint_at,
                cleanup_fails,
                write_fails,
                clear_fails,
            );
        }
    }

    /// EXHAUSTIVE matrix coverage: every one of the 2×2×2 cells runs
    /// against a FRESH fixture (deterministic, independent of the proptest
    /// seed), so a single broken cell — a phantom debt claim, a silently
    /// absorbed persistence failure, or a retry that fails to converge — is
    /// always caught even if the bounded 16-case sample never drew that
    /// combination (mirrors `every_floor_mutation_fails_closed_exhaustively`).
    #[test]
    fn every_debt_matrix_cell_is_truthful_and_converges_exhaustively() {
        for cleanup_fails in [false, true] {
            for write_fails in [false, true] {
                for clear_fails in [false, true] {
                    run_debt_truthfulness_case(
                        &[true, false, true],
                        1,
                        cleanup_fails,
                        write_fails,
                        clear_fails,
                    );
                }
            }
        }
    }

    // -------------------------------------------------------------------
    // IDEMPOTENT-RETRY TRUTHFULNESS (the retry path's matrix)
    // -------------------------------------------------------------------

    /// One idempotent-retry warning case: the FULL 2^3 matrix over (retry
    /// compaction FAILS → cleanup_pending) × (debt-marker WRITE failure →
    /// cleanup_persistence_failed) × (debt-marker CLEAR failure →
    /// cleanup_clear_failed), driven through the IDEMPOTENT re-checkpoint of
    /// the same deployment — the retry path whose floor is ALREADY durable
    /// (`established=false`). The debt-truthfulness property above covers
    /// the FRESH path's matrix; this targets the retry path specifically:
    /// an idempotent re-run must compute the SAME warning flags as a fresh
    /// post-commit run — a maintenance step that fails on the no-op path
    /// must NEVER be suppressed behind a clean "nothing to discard" report.
    ///
    /// Reuses the debt-truthfulness fixtures: the pending-debt SEEDING (an
    /// earlier interrupted checkpoint leaving the durable marker) arms the
    /// CLEAR cells — the clear fault only fires when a marker exists — and
    /// the fault kinds are exactly the property's (`WriteCleanupPending` for
    /// the persistence cell, `ClearCleanupPending` for the clear cell, a
    /// compaction phase for the pending cell).
    fn run_idempotent_retry_warning_case(
        cleanup_fails: bool,
        write_fails: bool,
        clear_fails: bool,
    ) {
        // Seeded prefix (mirroring the debt-truthfulness fixture): a
        // guaranteed success then a guaranteed FAILED attempt, so the FIRST
        // (fresh) checkpoint has genuine below-floor material to compact.
        let history = vec![true, false, true, false, true];
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        seed_history(&store, TARGET, "deploy", &history);
        // Checkpoint the SECOND success (s1, deploy-0002): the fresh run has
        // a real below-floor prefix (deploy-0000 + the failed deploy-0001),
        // so the first checkpoint genuinely compacts and converges; the
        // re-run below is then the pure same-deployment retry path.
        let dep = DeploymentId::new("deploy-0002".to_string());

        // The CLEAR cells need a marker on disk: the clear fault only fires
        // when a marker exists, so seed the durable-debt state via an
        // interrupted run (mirroring the debt-truthfulness seeding) — a
        // compaction fault with a fault-free marker write, leaving the debt
        // marker exactly as a crash/restart would find it.
        if clear_fails {
            store.fault_registry().arm_compact_attempts("deploy-0002");
            let seeded = run_checkpoint(&store, TARGET, &dep, false)
                .expect("the seeding run commits with a warning, never an Err");
            assert!(
                seeded.cleanup_pending,
                "the seeding run leaves cleanup pending"
            );
            assert!(
                !seeded.cleanup_persistence_failed && !seeded.cleanup_clear_failed,
                "the seeding run persists the debt and clears nothing"
            );
            assert!(
                store.read_cleanup_pending(TARGET, None).unwrap().is_some(),
                "the seeding run leaves the durable debt marker"
            );
        } else {
            // A fault-free first run: the floor is established and the
            // cleanup converges, so the re-run below is the PURE idempotent
            // no-op path.
            let first = run_checkpoint(&store, TARGET, &dep, false)
                .expect("the clean first run establishes the floor");
            assert!(first.established, "the first run establishes the floor");
            assert!(
                !first.cleanup_pending
                    && !first.cleanup_persistence_failed
                    && !first.cleanup_clear_failed,
                "the first run converges cleanly"
            );
            assert!(
                store.read_cleanup_pending(TARGET, None).unwrap().is_none(),
                "no debt marker after a converged first run"
            );
        }

        // Arm EXACTLY the matrix cell's faults on the RETRY: the compaction
        // (cleanup_fails — the maintenance runs even on the no-op path, so
        // the fault fires), the debt-marker write (write_fails — only
        // reached when the compaction fails), and the debt-marker clear
        // (clear_fails — only reached when the compaction succeeds on a
        // marker-bearing fixture). Unreachable arms simply stay in this
        // fixture's registry and never fire.
        if cleanup_fails {
            store.fault_registry().arm_compact_attempts("deploy-0002");
        }
        if write_fails {
            store
                .fault_registry()
                .arm_write_cleanup_pending("deploy-0002");
        }
        if clear_fails {
            store.fault_registry().arm_clear_cleanup_pending(TARGET);
        }
        let retry = run_checkpoint(&store, TARGET, &dep, false)
            .expect("post-commit maintenance failures are committed-with-warning, never an Err");

        // The idempotent re-run's established value: the floor was
        // established by the earlier run, so the re-run reports established
        // only when it REPAIRED the seeded pending debt.
        assert_eq!(
            retry.established, clear_fails,
            "the idempotent re-run reports established iff it repaired the seeded debt"
        );

        // THE MATRIX: every set flag produces its CORRESPONDING report flag
        // — exactly the formulas of the fresh path's debt-truthfulness
        // matrix, now on the idempotent retry path.
        assert_eq!(
            retry.cleanup_pending, cleanup_fails,
            "cleanup_pending must reflect the retry's compaction outcome"
        );
        assert_eq!(
            retry.cleanup_persistence_failed,
            cleanup_fails && write_fails,
            "the persistence-failure flag is set iff the retry's debt-marker write faulted"
        );
        assert_eq!(
            retry.cleanup_clear_failed,
            !cleanup_fails && clear_fails,
            "the clear-failure flag is set iff the retry's debt-marker clear faulted on the success path"
        );

        // The CLI render: the warning line prints IFF its flag is set, and
        // the "nothing to discard" no-op wording is gated on ALL flags
        // false.
        let lines = render_checkpoint_report(&retry);
        assert_eq!(
            lines.iter().any(|l| l.contains("cleanup pending")),
            retry.cleanup_pending,
            "the pending warning line prints IFF cleanup_pending, got: {lines:?}"
        );
        assert_eq!(
            lines.iter().any(|l| l.contains("could not be persisted")),
            retry.cleanup_persistence_failed,
            "the persistence warning line prints IFF cleanup_persistence_failed, got: {lines:?}"
        );
        assert_eq!(
            lines.iter().any(|l| l.contains("stale marker")),
            retry.cleanup_clear_failed,
            "the clear warning line prints IFF cleanup_clear_failed, got: {lines:?}"
        );
        let clean_no_op = !retry.cleanup_pending
            && !retry.cleanup_persistence_failed
            && !retry.cleanup_clear_failed;
        assert_eq!(
            lines.iter().any(|l| l.contains("nothing to discard")),
            clean_no_op && !retry.established,
            "the clean no-op wording appears ONLY when all flags are false, got: {lines:?}"
        );
        // The no-op path is ONLY clean when all flags are false: a clean
        // report (and no warnings) is possible only in the no-warning cells
        // of the matrix (the unreachable write fault alone — no compaction
        // failure — stays clean); every other cell must warn.
        assert_eq!(
            clean_no_op,
            !cleanup_fails && !clear_fails,
            "the report is clean iff the matrix cell expects no warning"
        );
        if clean_no_op {
            assert!(
                !lines.iter().any(|l| l.starts_with("warning:")),
                "a clean report renders no warning lines, got: {lines:?}"
            );
        } else {
            assert!(
                lines.iter().any(|l| l.starts_with("warning:")),
                "a flagged report must render its warning line(s), got: {lines:?}"
            );
        }
    }

    proptest! {
        // IDEMPOTENT-RETRY TRUTHFULNESS: the bounded, fixed-seed 2^3 matrix
        // over (retry compaction FAILS → cleanup_pending) × (debt-marker
        // WRITE failure → cleanup_persistence_failed) × (debt-marker CLEAR
        // failure → cleanup_clear_failed), each cell driven through the
        // IDEMPOTENT re-checkpoint of the same deployment (the retry path
        // — the floor is already durable, established=false). THE
        // INVARIANT: every set flag produces its CORRESPONDING report flag
        // AND its CLI warning line (each warning prints IFF its flag is
        // set), and the clean "nothing to discard" no-op report appears
        // only when ALL flags are false — an idempotent retry never
        // suppresses a maintenance failure behind a clean no-op claim. The
        // debt-truthfulness property covers the FRESH path's matrix; this
        // targets the established=false retry path specifically.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn idempotent_retry_never_suppresses_cleanup_warnings(
            cleanup_fails in any::<bool>(),
            write_fails in any::<bool>(),
            clear_fails in any::<bool>(),
        ) {
            run_idempotent_retry_warning_case(cleanup_fails, write_fails, clear_fails);
        }
    }

    /// EXHAUSTIVE complement: all 8 cells of the idempotent-retry matrix
    /// run against FRESH fixtures (deterministic, independent of the proptest
    /// seed), so a suppressed warning on the retry path is always caught
    /// even if the bounded 16-cell sample never drew that combination
    /// (mirrors `every_debt_matrix_cell_is_truthful_and_converges_exhaustively`).
    #[test]
    fn every_idempotent_retry_warning_cell_is_truthful_exhaustively() {
        for cleanup_fails in [false, true] {
            for write_fails in [false, true] {
                for clear_fails in [false, true] {
                    run_idempotent_retry_warning_case(cleanup_fails, write_fails, clear_fails);
                }
            }
        }
    }

    proptest! {
        // The checkpoint's durability stages are fail-closed and ORDERED:
        // faulting ANY stage — the entry-point write (0), the temp-file
        // fsync (1), the rename (2), or the parent-directory fsync (3) —
        // must fail the checkpoint BEFORE any compaction. The parent-sync
        // fault is the durability commit point: the marker may already be
        // renamed into place, so the store unlinks it and no floor exists.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn durability_stage_fault_blocks_compaction(
            history in prop::collection::vec(any::<bool>(), 3..7),
            checkpoint_at in 0usize..8,
            stage in 0usize..4,
        ) {
            run_durability_stage_case(&history, checkpoint_at, stage);
        }
    }

    /// One durability-stage-fault case: seed a history, checkpoint the
    /// `checkpoint_at`-th successful deployment with exactly ONE stage fault
    /// armed, and assert the fail-closed contract — `Err` from the
    /// checkpoint, NO floor (the parent-sync case included: the marker was
    /// unlinked), the physical below-floor files UNTOUCHED (full jsonl
    /// prefixes, below-floor deployment dirs present), and compaction
    /// UNREACHABLE. Then the SAME checkpoint with no fault armed succeeds:
    /// floor present, compaction done.
    fn run_durability_stage_case(history_in: &[bool], checkpoint_at: usize, stage: usize) {
        // Prepend a guaranteed success so the checkpoint always has a
        // successful deployment to target.
        let mut history = vec![true];
        history.extend_from_slice(history_in);
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        seed_history(&store, TARGET, "deploy", &history);
        let ok_ids: Vec<String> = history
            .iter()
            .enumerate()
            .filter(|(_, ok)| **ok)
            .map(|(n, _)| format!("deploy-{n:04}"))
            .collect();
        assert!(
            !ok_ids.is_empty(),
            "a checkpoint needs at least one success"
        );
        let target_id = ok_ids[checkpoint_at % ok_ids.len()].clone();
        let floor_index = ok_ids.iter().position(|id| *id == target_id).unwrap() as u64;

        // Arm EXACTLY ONE durability-stage fault, keyed by the checkpoint
        // deployment id (each fault consumes at its own stage).
        match stage {
            0 => store.fault_registry().arm_write_history_floor(&target_id),
            1 => store.fault_registry().arm_sync_floor_temp(&target_id),
            2 => store.fault_registry().arm_rename_floor(&target_id),
            _ => store.fault_registry().arm_sync_floor_parent(&target_id),
        }
        let err = run_checkpoint(&store, TARGET, &DeploymentId::new(target_id.clone()), false)
            .expect_err("a durability-stage fault must fail the checkpoint before compaction");
        assert!(err.to_string().contains("test fault"));

        // NO floor — including the parent-sync stage: the marker was
        // renamed into place but the store unlinked it (the durability
        // commit point is fail-closed).
        assert!(
            store.read_history_floor(TARGET).unwrap().is_none(),
            "stage {stage}: a durability-stage failure must leave no floor"
        );
        assert!(
            !store.history_floor_path(TARGET).exists(),
            "stage {stage}: the marker file itself must not exist"
        );

        // The below-floor physical state is UNTOUCHED: no compaction ran.
        assert_eq!(
            store.read_attempts_raw(TARGET).unwrap().len(),
            history.len(),
            "stage {stage}: attempts.jsonl keeps its full prefix"
        );
        let ok_count = history.iter().filter(|ok| **ok).count();
        assert_eq!(
            store.read_snapshots_raw(TARGET).unwrap().len(),
            ok_count,
            "stage {stage}: snapshots.jsonl keeps its full prefix"
        );
        for id in ok_ids.iter().take(floor_index as usize) {
            assert!(
                store.deployment_dir(id).exists(),
                "stage {stage}: below-floor deployment dir {id} must survive"
            );
        }

        // The control: with NO fault armed (the one-shot was consumed), the
        // SAME checkpoint succeeds — floor present, compaction done. This is
        // the deterministic "compaction is unreachable unless the marker's
        // durability stage succeeds" property.
        let rep = run_checkpoint(&store, TARGET, &DeploymentId::new(target_id.clone()), false)
            .expect("with the fault consumed, the same checkpoint succeeds");
        assert!(
            rep.established,
            "stage {stage}: the retry establishes the floor"
        );
        let marker = store.read_history_floor(TARGET).unwrap().unwrap();
        assert_eq!(marker.deployment_id.as_str(), target_id);
        assert_eq!(marker.snapshot_index, floor_index);
        for id in ok_ids.iter().take(floor_index as usize) {
            assert!(
                !store.deployment_dir(id).exists(),
                "stage {stage}: the successful retry compacts, deleting below-floor dir {id}"
            );
        }
    }

    // ---------------------------------------------------------------------
    // TRANSACTIONAL FLOOR REPLACEMENT (the state-machine property)
    // ---------------------------------------------------------------------

    /// One durability stage of a floor ADVANCE (A → B). Faulting it while
    /// advancing must leave the PRE-ADVANCE state: floor A durable, the
    /// visible suffix EXACTLY unchanged, no compaction side effects. The
    /// RESTORE stage is the double-fault exception: the restore is only
    /// attempted when an EARLIER stage already failed, so the property
    /// double-faults it (the parent-sync stage + the restore — "if IT also
    /// fails") and asserts the TORN STATE never exposes below-A history:
    /// the marker is left absent while the tagged backup
    /// (`history-floor.json.prev.<B-id>`) holds A, the VALIDATED backup
    /// reads as the ACTIVE floor A (never None, never an error, never a
    /// below-floor exposure), and the documented recovery — ATOMICALLY
    /// RESTORING the backup (rename + parent-dir fsync, never deleting
    /// it) — returns the target to EXACTLY the pre-advance state.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum AdvanceStage {
        Entry,
        TempSync,
        BackupRename,
        Rename,
        ParentSync,
        Restore,
    }

    /// Every durability stage of the transactional advance, in firing
    /// order: entry → temp-sync → backup-rename → rename → parent-sync →
    /// restore (the restore only fires after an earlier stage failed).
    const ALL_ADVANCE_STAGES: [AdvanceStage; 6] = [
        AdvanceStage::Entry,
        AdvanceStage::TempSync,
        AdvanceStage::BackupRename,
        AdvanceStage::Rename,
        AdvanceStage::ParentSync,
        AdvanceStage::Restore,
    ];

    fn advance_stage_strategy() -> impl Strategy<Value = AdvanceStage> {
        (0usize..ALL_ADVANCE_STAGES.len()).prop_map(|i| ALL_ADVANCE_STAGES[i])
    }

    /// Arm the fault(s) for one advance stage, keyed by the checkpoint
    /// deployment id (B). The RESTORE stage is a DOUBLE fault: the
    /// parent-sync stage (the deepest pre-commit stage — B's marker may
    /// already be renamed into place) fails first, which forces the restore
    /// attempt; the restore fault then makes the restore itself fail too.
    fn arm_advance_stage(store: &LocalStore, stage: AdvanceStage, deployment_id: &str) {
        match stage {
            AdvanceStage::Entry => store
                .fault_registry()
                .arm_write_history_floor(deployment_id),
            AdvanceStage::TempSync => store.fault_registry().arm_sync_floor_temp(deployment_id),
            AdvanceStage::BackupRename => store
                .fault_registry()
                .arm_rename_floor_backup(deployment_id),
            AdvanceStage::Rename => store.fault_registry().arm_rename_floor(deployment_id),
            AdvanceStage::ParentSync => store.fault_registry().arm_sync_floor_parent(deployment_id),
            AdvanceStage::Restore => {
                store.fault_registry().arm_sync_floor_parent(deployment_id);
                store.fault_registry().arm_restore_floor(deployment_id);
            }
        }
    }

    /// The ENTIRE visible state of `target` under the floor: the gated
    /// snapshot/attempt lists, the floor's own (deployment, index), and the
    /// below-floor ref refusal. A failed ADVANCE must leave this EXACTLY
    /// unchanged (identical lists, the same below-floor refs refused) — the
    /// "exactly the same visible suffix" half of the transactional
    /// replacement invariant.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct VisibleState {
        floor: Option<(String, u64)>,
        snapshots: Vec<(u64, String)>,
        attempts: Vec<String>,
        below_floor_ref_err: Option<String>,
    }

    fn capture_visible(
        store: &LocalStore,
        target: &str,
        floor: &Option<crate::records::HistoryFloor>,
    ) -> VisibleState {
        // The ref just below the floor must be REFUSED (never a resolved
        // below-floor snapshot); capture the exact refusal message so the
        // post-advance state can be compared byte-for-byte.
        let below_floor_ref_err = match floor {
            Some(f) if f.snapshot_index > 0 => {
                let expr = history::parse_ref_expr(&format!("s{}", f.snapshot_index - 1)).unwrap();
                Some(
                    history::resolve_ref_expr(&expr, target, store)
                        .unwrap_err()
                        .to_string(),
                )
            }
            _ => None,
        };
        VisibleState {
            floor: floor
                .as_ref()
                .map(|f| (f.deployment_id.as_str().to_string(), f.snapshot_index)),
            snapshots: store
                .read_snapshots(target)
                .unwrap()
                .iter()
                .map(|s| (s.index, s.deployment_id.as_str().to_string()))
                .collect(),
            attempts: store
                .read_attempts(target)
                .unwrap()
                .iter()
                .map(|a| a.deployment_id.as_str().to_string())
                .collect(),
            below_floor_ref_err,
        }
    }

    /// Establish floor A on a seeded fixture (clean OR with an INTERRUPTED
    /// cleanup — the debt marker + leftover below-A dirs, replaying the
    /// commit-point test's seeding) and capture the EXACT pre-advance
    /// visible and physical state: the baseline a failed ADVANCE and its
    /// RECOVERY must leave untouched. B is the guaranteed FINAL success —
    /// always a strictly-later deployment than A.
    struct FloorAFixture {
        _tmp: tempfile::TempDir,
        store: LocalStore,
        /// The full seeded history (the deployment-dir inventory derives
        /// from it).
        history: Vec<bool>,
        /// A's deployment id (the ORIGINAL floor).
        a_id: String,
        /// A's snapshot index.
        a_index: u64,
        /// A's position in the FULL history (everything before it owns a
        /// below-A `deployments/<id>/` directory — the material an
        /// interrupted A cleanup leaves behind).
        a_attempt_pos: usize,
        /// The established floor A marker.
        a_floor: HistoryFloor,
        /// B's deployment id (the never-committed advance target).
        b_id: String,
        /// B's snapshot index.
        b_index: u64,
        /// The pre-advance visible suffix under floor A.
        pre: VisibleState,
        /// The pre-advance raw attempts-log line count.
        pre_raw_attempts: usize,
        /// The pre-advance raw snapshots-log entry count.
        pre_raw_snaps: usize,
        /// The pre-advance deployment-dir inventory (ids with a dir on
        /// disk).
        pre_dirs: Vec<String>,
    }

    /// Seed a fresh fixture and establish floor A, then capture the exact
    /// pre-advance state — see [`FloorAFixture`]. Shared by the
    /// transactional-advance cases and the recovery property, so both run
    /// the same seeding (the commit-point test's fixtures: a guaranteed
    /// early success, a guaranteed FAILED attempt, the randomized history,
    /// and a guaranteed FINAL success).
    fn seed_floor_a(
        history_in: &[bool],
        a_at: usize,
        a_cleanup_interrupted: bool,
    ) -> FloorAFixture {
        // Seeding (replaying the commit-point test): a guaranteed early
        // success, a guaranteed FAILED attempt (a `deployments/<id>/` dir
        // with no snapshot — below-floor dir material for A's interrupted
        // cleanup), the randomized history, and a guaranteed FINAL success
        // so B is always a strictly-later successful deployment.
        let mut history = vec![true, false];
        history.extend_from_slice(history_in);
        history.push(true);
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        seed_history(&store, TARGET, "deploy", &history);
        let ok_ids: Vec<String> = history
            .iter()
            .enumerate()
            .filter(|(_, ok)| **ok)
            .map(|(n, _)| format!("deploy-{n:04}"))
            .collect();
        assert!(
            ok_ids.len() >= 2,
            "A and B both need a successful deployment"
        );

        // A: the `a_at`-th successful deployment (never the last — B owns
        // the last success, so B is STRICTLY LATER than A). Its snapshot
        // index is its position among the successes (snapshots are minted
        // in order).
        let a_id = ok_ids[a_at % (ok_ids.len() - 1)].clone();
        let a_index = ok_ids.iter().position(|id| *id == a_id).unwrap() as u64;
        // The position of A's attempt in the FULL history: everything
        // before it owns a below-floor `deployments/<id>/` directory (the
        // material an interrupted A cleanup leaves behind).
        let a_attempt_pos = history
            .iter()
            .enumerate()
            .find(|(n, _)| format!("deploy-{n:04}") == a_id)
            .unwrap()
            .0;
        let b_id = ok_ids.last().unwrap().clone();
        assert_ne!(a_id, b_id, "B must be a later deployment than A");
        let b_index = (ok_ids.len() - 1) as u64;

        // Establish A. When `a_cleanup_interrupted` AND there is material
        // below A, arm a compaction fault (keyed by A's id) so A's
        // checkpoint COMMITS with cleanup_pending: the durable floor A
        // stands with leftover below-floor dirs + the debt marker (A's
        // state is clean OR pending — replaying the commit-point test's
        // seeding). A at the very first attempt has nothing below it, so
        // the armed fault is unreachable and A is legitimately clean.
        if a_cleanup_interrupted && a_attempt_pos > 0 {
            store.fault_registry().arm_compact_deployments(&a_id);
        }
        let rep_a = run_checkpoint(&store, TARGET, &DeploymentId::new(a_id.clone()), false)
            .expect("establishing A always succeeds");
        assert!(rep_a.established, "A is established");
        let a_floor = store.read_history_floor(TARGET).unwrap().unwrap();
        assert_eq!(a_floor.deployment_id.as_str(), a_id);
        assert_eq!(a_floor.snapshot_index, a_index);
        if a_cleanup_interrupted && a_attempt_pos > 0 {
            assert!(rep_a.cleanup_pending, "A's interrupted cleanup is pending");
            assert!(
                store.read_cleanup_pending(TARGET, None).unwrap().is_some(),
                "A's interrupted cleanup records the durable debt marker"
            );
        } else {
            assert!(!rep_a.cleanup_pending, "A is clean");
        }

        // PRE-ADVANCE state: the exact visible suffix under floor A.
        let pre = capture_visible(&store, TARGET, &Some(a_floor.clone()));
        // PRE-ADVANCE PHYSICAL state (the "no compaction side effects"
        // half): the raw logs and the deployment-dir set must be UNCHANGED
        // by a failed advancement AND by the recovery. (A's OWN
        // establishment may already have compacted the raw logs and deleted
        // below-A dirs — that is the pre-advance baseline, not a side
        // effect of the failed B advance.)
        let pre_raw_attempts = store.read_attempts_raw(TARGET).unwrap().len();
        let pre_raw_snaps = store.read_snapshots_raw(TARGET).unwrap().len();
        let pre_dirs: Vec<String> = history
            .iter()
            .enumerate()
            .filter(|(n, _)| store.deployment_dir(&format!("deploy-{n:04}")).exists())
            .map(|(n, _)| format!("deploy-{n:04}"))
            .collect();
        FloorAFixture {
            _tmp: tmp,
            store,
            history,
            a_id,
            a_index,
            a_attempt_pos,
            a_floor,
            b_id,
            b_index,
            pre,
            pre_raw_attempts,
            pre_raw_snaps,
            pre_dirs,
        }
    }

    /// One transactional-advance case: establish floor A (clean OR with an
    /// INTERRUPTED cleanup — leftover debt + below-floor dirs, replaying the
    /// commit-point test's seeding), capture the exact pre-advance visible
    /// state, then fault EVERY durability stage while advancing A → B. Each
    /// faulted advancement must return `Err` and retain A — the ORIGINAL
    /// floor (same deployment_id + snapshot_index), never None, never B —
    /// with the visible suffix EXACTLY unchanged (the restore stage is the
    /// double-fault exception: the restore ALSO fails, so the marker is
    /// left ABSENT while the durable backup holds A — the VALIDATED backup
    /// then reads as the ACTIVE floor A and the documented recovery
    /// atomically restores it, never deleting it). Then the controls: a
    /// fault-free advancement to B succeeds (floor = B), and A's
    /// interrupted cleanup converges after the failed advances.
    fn run_transactional_advance_case(
        history_in: &[bool],
        a_at: usize,
        a_cleanup_interrupted: bool,
        stage: AdvanceStage,
    ) {
        let fx = seed_floor_a(history_in, a_at, a_cleanup_interrupted);
        let store = &fx.store;
        let a_id = fx.a_id.as_str();
        let a_index = fx.a_index;
        let b_id = fx.b_id.as_str();
        let pre = &fx.pre;

        // ---- FAULTED ADVANCE: the durability stage under test ------------
        // Fault the stage while advancing A → B; the advancement MUST fail
        // before B's durability commit point, and the PRE-ADVANCE state
        // must survive EXACTLY (floor A, same visible suffix, same
        // below-floor ref refusals, no compaction side effects) — except
        // the RESTORE stage, whose restore ALSO fails: the marker is left
        // ABSENT while the durable backup holds A, and the VALIDATED backup
        // reads as the ACTIVE floor A (the recovery below restores it
        // atomically — never "no floor", never a below-A exposure).
        arm_advance_stage(store, stage, b_id);
        let err = run_checkpoint(store, TARGET, &DeploymentId::new(b_id.to_string()), false)
            .expect_err("a durability-stage fault must fail the advance before B commits");
        assert!(
            err.to_string().contains("test fault"),
            "the fault is the failure cause, got: {err}"
        );

        if stage == AdvanceStage::Restore {
            // The DOUBLE FAULT (the restore of A ALSO failed): the previous
            // floor A stays in the durable backup and the marker was left
            // ABSENT (B's marker was unlinked). The torn state is NEVER "no
            // floor" (which would expose the below-floor prefix): the
            // VALIDATED backup IS the active floor — every read sees A (the
            // ORIGINAL floor — same deployment_id + snapshot_index, never
            // None, never an error), the visible suffix is EXACTLY
            // unchanged, and every below-A ref stays refused.
            assert!(
                !store.history_floor_path(TARGET).exists(),
                "the double fault leaves the marker absent"
            );
            assert!(
                store
                    .refs_dir(TARGET)
                    .join(format!("history-floor.json.prev.{b_id}"))
                    .exists(),
                "the double fault leaves the durable backup holding A"
            );
            let torn = store.read_history_floor(TARGET).unwrap();
            let f = torn
                .as_ref()
                .expect("a torn advance reads floor A through the validated backup — never None");
            assert_eq!(
                f.deployment_id.as_str(),
                a_id,
                "the torn read returns the ORIGINAL floor A"
            );
            assert_eq!(
                f.snapshot_index, a_index,
                "the torn read returns the ORIGINAL floor index"
            );
            let torn_post = capture_visible(store, TARGET, &torn);
            assert_eq!(
                torn_post.snapshots, pre.snapshots,
                "the torn read exposes exactly the pre-advance snapshot suffix"
            );
            assert_eq!(
                torn_post.attempts, pre.attempts,
                "the torn read exposes exactly the pre-advance attempts suffix"
            );
            assert_eq!(
                torn_post.below_floor_ref_err, pre.below_floor_ref_err,
                "the same below-A refs stay refused during the torn state"
            );
            // No compaction side effects from the failed advance: the raw
            // logs and the deployment-dir set are EXACTLY the pre-advance
            // physical state.
            assert_eq!(
                store.read_snapshots_raw(TARGET).unwrap().len(),
                fx.pre_raw_snaps,
                "the failed advance never touches the raw snapshot log"
            );
            assert_eq!(
                store.read_attempts_raw(TARGET).unwrap().len(),
                fx.pre_raw_attempts,
                "the failed advance never touches the raw attempts log"
            );
            let dirs: Vec<String> = fx
                .history
                .iter()
                .enumerate()
                .filter(|(n, _)| store.deployment_dir(&format!("deploy-{n:04}")).exists())
                .map(|(n, _)| format!("deploy-{n:04}"))
                .collect();
            assert_eq!(
                dirs, fx.pre_dirs,
                "the failed advance never deletes or creates a deployment dir"
            );
            // RECOVERY (the documented recovery INVERTED): ATOMICALLY
            // RESTORE the durable backup as the marker — rename the tagged
            // backup `history-floor.json.prev.<b_id>` back + parent-dir
            // fsync (the SAME operation a failed advance's restore
            // performs; the backup is the ONLY valid floor in the torn
            // state and is NEVER deleted — deleting it would erase the
            // floor and re-expose the below-floor history). After recovery
            // the floor is STILL A and the visible history is EXACTLY
            // unchanged — no recovery transition produced None.
            store
                .recover_history_floor_backup(TARGET)
                .expect("recovery atomically restores the durable backup");
            assert!(
                store.history_floor_path(TARGET).exists(),
                "recovery restores the marker file"
            );
            assert!(
                !store
                    .refs_dir(TARGET)
                    .join(format!("history-floor.json.prev.{b_id}"))
                    .exists(),
                "recovery consumes the tagged backup: no stale .prev.<b_id> remains"
            );
            let recovered = store.read_history_floor(TARGET).unwrap();
            let f = recovered
                .as_ref()
                .expect("post-recovery the floor is A — never None");
            assert_eq!(
                f.deployment_id.as_str(),
                a_id,
                "recovery restores the ORIGINAL floor A (same deployment_id)"
            );
            assert_eq!(
                f.snapshot_index, a_index,
                "recovery restores the ORIGINAL floor A (same snapshot_index)"
            );
            let recovered_post = capture_visible(store, TARGET, &recovered);
            assert_eq!(
                recovered_post.snapshots, pre.snapshots,
                "visible history is EXACTLY unchanged after recovery"
            );
            assert_eq!(
                recovered_post.attempts, pre.attempts,
                "the visible attempts suffix is EXACTLY unchanged after recovery"
            );
            assert_eq!(
                recovered_post.below_floor_ref_err, pre.below_floor_ref_err,
                "every below-A ref stays refused after recovery"
            );
            // Physical state still EXACTLY the pre-advance state after
            // recovery: same raw logs, same deployment dirs (the recovery
            // only renames the backup into the marker name — it compacts
            // nothing).
            assert_eq!(
                store.read_snapshots_raw(TARGET).unwrap().len(),
                fx.pre_raw_snaps,
                "recovery never touches the raw snapshot log"
            );
            assert_eq!(
                store.read_attempts_raw(TARGET).unwrap().len(),
                fx.pre_raw_attempts,
                "recovery never touches the raw attempts log"
            );
            let dirs_after: Vec<String> = fx
                .history
                .iter()
                .enumerate()
                .filter(|(n, _)| store.deployment_dir(&format!("deploy-{n:04}")).exists())
                .map(|(n, _)| format!("deploy-{n:04}"))
                .collect();
            assert_eq!(
                dirs_after, fx.pre_dirs,
                "recovery never deletes or creates a deployment dir"
            );
            assert!(
                torn.is_some() && recovered.is_some(),
                "no recovery transition produced None: the torn read AND the post-recovery read both see floor A"
            );
        } else {
            // The failed advancement left EXACTLY the pre-advance state:
            // floor A (the ORIGINAL floor — same deployment_id +
            // snapshot_index; never None, never B) and an identical visible
            // suffix.
            let floor = store.read_history_floor(TARGET).unwrap();
            let f = floor
                .as_ref()
                .expect("a failed advance must retain floor A — never None");
            assert_eq!(
                f.deployment_id.as_str(),
                a_id,
                "the ORIGINAL floor deployment A survives the failed {stage:?} advance"
            );
            assert_eq!(
                f.snapshot_index, a_index,
                "the ORIGINAL floor index survives the failed {stage:?} advance"
            );
            let post = capture_visible(store, TARGET, &floor);
            assert_eq!(
                post.snapshots, pre.snapshots,
                "{stage:?}: the visible snapshot suffix is exactly unchanged"
            );
            assert_eq!(
                post.attempts, pre.attempts,
                "{stage:?}: the visible attempts suffix is exactly unchanged"
            );
            assert_eq!(
                post.below_floor_ref_err, pre.below_floor_ref_err,
                "{stage:?}: the same below-floor refs stay refused"
            );

            // CONTROL: when A's cleanup was interrupted, re-checkpointing A
            // after the failed advances CONVERGES the pending cleanup (the
            // durable debt clears, the below-floor dirs are deleted).
            if a_cleanup_interrupted && fx.a_attempt_pos > 0 {
                let retry = run_checkpoint(
                    store,
                    TARGET,
                    &DeploymentId::new(fx.a_id.clone()),
                    false,
                )
                .expect(
                    "re-checkpointing A after the failed advances converges its pending cleanup",
                );
                assert!(
                    !retry.cleanup_pending,
                    "{stage:?}: A's interrupted cleanup converges after the failed advances"
                );
                assert!(
                    store.read_cleanup_pending(TARGET, None).unwrap().is_none(),
                    "{stage:?}: the debt marker clears once A's cleanup completes"
                );
                for (n, _) in fx.history.iter().enumerate().take(fx.a_attempt_pos) {
                    assert!(
                        !store.deployment_dir(&format!("deploy-{n:04}")).exists(),
                        "{stage:?}: below-A dir {n} is deleted by the converged cleanup"
                    );
                }
            }
        }

        // CONTROL: a fault-free advancement to B SUCCEEDS (floor = B, the
        // advancement commits). For the restore stage this runs on the
        // RECOVERED fixture (the marker holds A again — the advancement is
        // a normal transactional advance).
        let rep_b = run_checkpoint(store, TARGET, &DeploymentId::new(b_id.to_string()), false)
            .expect("a fault-free advancement to B succeeds");
        assert!(rep_b.established, "the advancement to B establishes B");
        let floor_b = store.read_history_floor(TARGET).unwrap().unwrap();
        assert_eq!(floor_b.deployment_id.as_str(), b_id);
        assert_eq!(floor_b.snapshot_index, fx.b_index);
        assert!(
            floor_backup_leftovers(store).is_empty(),
            "a committed advance leaves no backup behind"
        );
    }

    proptest! {
        // The state-machine property for TRANSACTIONAL FLOOR REPLACEMENT:
        // over (history shape, A's checkpoint position, whether A's cleanup
        // was INTERRUPTED — clean OR pending, B = a strictly-later
        // deployment), fault EVERY durability stage while advancing A → B
        // and assert the failed advancement retains A — the ORIGINAL floor
        // (same deployment_id + snapshot_index), never None, never B — and
        // exposes EXACTLY the same visible suffix (identical gated lists,
        // the same below-floor refs refused); the RESTORE-stage double
        // fault instead asserts the torn state reads the VALIDATED backup
        // as the ACTIVE floor A (never None, never an error, never a
        // below-A exposure) and that the documented recovery — ATOMICALLY
        // restoring the backup, never deleting it — returns the target to
        // EXACTLY the pre-advance state. Then the controls: a fault-free
        // advancement to B succeeds (floor = B) and A's pending cleanup
        // converges after the failed advances. Fixed seed 0x5EED_5EED +
        // bounded cases — the same vectors run on every invocation.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn failed_advance_retains_floor_a_and_visible_suffix(
            history in prop::collection::vec(any::<bool>(), 3..7),
            a_at in 0usize..8,
            a_cleanup_interrupted in any::<bool>(),
            stage in advance_stage_strategy(),
        ) {
            run_transactional_advance_case(&history, a_at, a_cleanup_interrupted, stage);
        }
    }

    /// EXHAUSTIVE stage coverage: EVERY durability stage of a transactional
    /// advance is faulted against two FIXED scenarios — one with A's
    /// cleanup INTERRUPTED (pending debt + below-floor dirs) and one with A
    /// at the very first attempt (clean, nothing below) — so a single
    /// broken stage is always caught even if the bounded 16-case proptest
    /// sample never drew that stage (mirrors
    /// `every_floor_mutation_fails_closed_exhaustively`).
    #[test]
    fn every_advance_stage_fails_closed_exhaustively() {
        for stage in ALL_ADVANCE_STAGES {
            // A with an INTERRUPTED cleanup (pending debt + leftover
            // below-floor dirs): every stage leaves floor A durable and the
            // visible suffix exactly unchanged (the restore stage
            // double-faults: the validated backup reads as A and the
            // recovery restores it); the pending cleanup converges after
            // the failed advances, then a fault-free advance to B succeeds.
            run_transactional_advance_case(&[true, false, true], 1, true, stage);
            // A at the very first attempt (clean, nothing below it): the
            // interrupted-control is moot; every stage still retains A.
            run_transactional_advance_case(&[false, false], 0, false, stage);
        }
    }

    // ---------------------------------------------------------------------
    // STALE BACKUPS CAN NEVER ROLL THE FLOOR BACKWARD (the state-machine
    // property)
    // ---------------------------------------------------------------------

    /// Every leftover `history-floor.json.prev*` sibling of the target's
    /// floor marker (the transaction-tagged backups of the advance scheme,
    /// plus any legacy untagged leftover), sorted. The tagged scheme leaves
    /// NO backup behind after a committed advance (or after the next
    /// advance's pre-start reconciliation), so an empty list is the
    /// expected steady state.
    fn floor_backup_leftovers(store: &LocalStore) -> Vec<std::path::PathBuf> {
        let mut out: Vec<std::path::PathBuf> = std::fs::read_dir(store.refs_dir(TARGET))
            .map(|rd| {
                rd.flatten()
                    .filter(|e| {
                        e.file_name()
                            .to_string_lossy()
                            .starts_with("history-floor.json.prev")
                    })
                    .map(|e| e.path())
                    .collect()
            })
            .unwrap_or_default();
        out.sort();
        out
    }

    /// One stale-backup case: COMMIT A→B while RETAINING the stale tagged
    /// backup (B's success-path backup cleanup is FAULTED, so
    /// `.prev.<B-id>` holding A stays on disk — the exact "stale backup
    /// left behind by a committed advance" state the fixed-name scheme got
    /// wrong), then FAIL the ACTUAL B→backup rename during the B→C advance
    /// (the [`crate::testutil::test_faults::FaultKind::RenameFloorBackup`]
    /// stage fault keyed by C — the B→C advance target) and assert the
    /// advance Errs with the floor REMAINING B (never A, never None — via
    /// [`LocalStore::read_history_floor`]); then re-run B→C fault-free and
    /// assert the floor reaches C. After EVERY transition the floor can
    /// never regress to A: the stale A backup is reconciled away by the
    /// next advance's pre-start cleanup — never restored (the restore only
    /// ever renames the CURRENT transaction's tagged, content-verified
    /// backup).
    fn run_stale_backup_never_rolls_case(history_in: &[bool], a_at: usize) {
        // Seeding: a guaranteed early success, a guaranteed FAILED attempt
        // (a `deployments/<id>/` dir with no snapshot), the randomized
        // history, a second guaranteed success, and a guaranteed FINAL
        // success — so there are ALWAYS at least three strictly-later
        // successful deployments A < B < C (C = the last success, B = the
        // second-to-last).
        let mut history = vec![true, false, true];
        history.extend_from_slice(history_in);
        history.push(true);
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        seed_history(&store, TARGET, "deploy", &history);
        let ok_ids: Vec<String> = history
            .iter()
            .enumerate()
            .filter(|(_, ok)| **ok)
            .map(|(n, _)| format!("deploy-{n:04}"))
            .collect();
        assert!(ok_ids.len() >= 3, "the seeding guarantees A < B < C");
        let c_id = ok_ids.last().unwrap().clone();
        let b_id = ok_ids[ok_ids.len() - 2].clone();
        let a_id = ok_ids[a_at % (ok_ids.len() - 2)].clone();
        assert_ne!(a_id, b_id, "A and B are distinct successes");
        assert_ne!(b_id, c_id, "B and C are distinct successes");

        // The regression guard: from the moment B is COMMITTED onward, the
        // durable floor can NEVER regress to A — checked after every
        // transition.
        let assert_never_a = |store: &LocalStore, context: &str| {
            let floor = store.read_history_floor(TARGET).unwrap();
            let f = floor
                .as_ref()
                .expect("a committed floor must never regress to None");
            assert_ne!(
                f.deployment_id.as_str(),
                a_id,
                "{context}: the floor can never regress to A (currently '{}' at snapshot s{})",
                f.deployment_id,
                f.snapshot_index
            );
        };

        // ---- (1) A is established, then A→B COMMITS retaining stale A ---
        run_checkpoint(&store, TARGET, &DeploymentId::new(a_id.clone()), false)
            .expect("establishing A always succeeds");
        // B's success-path backup cleanup is faulted: the A→B advance still
        // COMMITS (the cleanup is best-effort and its failure is absorbed),
        // leaving the TAGGED backup `.prev.<B>` holding A on disk.
        store.fault_registry().arm_remove_floor_backup(&b_id);
        let rep_b = run_checkpoint(&store, TARGET, &DeploymentId::new(b_id.clone()), false)
            .expect("the A→B advance commits (the cleanup fault is best-effort, absorbed)");
        assert!(rep_b.established, "B is established");
        let floor_b = store.read_history_floor(TARGET).unwrap().unwrap();
        assert_eq!(floor_b.deployment_id.as_str(), b_id, "the floor is B");
        assert_never_a(&store, "after committing B with the faulted cleanup");
        // The stale TAGGED backup (holding A) survives the faulted cleanup
        // — this is the state the old fixed-name scheme mishandled.
        let stale = store
            .refs_dir(TARGET)
            .join(format!("history-floor.json.prev.{b_id}"));
        assert!(
            stale.exists(),
            "the faulted cleanup leaves the tagged A backup on disk"
        );
        assert_eq!(
            floor_backup_leftovers(&store),
            vec![stale.clone()],
            "exactly the stale tagged A backup is left behind"
        );

        // ---- (2) the B→C advance FAILS the actual B→backup rename -------
        // Keyed by C (the B→C advance target). The advance's PRE-START
        // reconciliation has already durably removed the stale A backup, so
        // when the backup-rename fault fires (B never moved aside) there is
        // NOTHING to restore — the floor must remain B, never A, never
        // None.
        store.fault_registry().arm_rename_floor_backup(&c_id);
        let err = run_checkpoint(&store, TARGET, &DeploymentId::new(c_id.clone()), false)
            .expect_err("the faulted B→C backup rename must fail the advance");
        assert!(
            err.to_string().contains("test fault"),
            "the fault is the failure cause, got: {err}"
        );
        let floor = store.read_history_floor(TARGET).unwrap();
        let f = floor.as_ref().expect(
            "the failed B→C advance retains a floor — never None (a stale A must never be treated as 'no floor')",
        );
        assert_eq!(
            f.deployment_id.as_str(),
            b_id,
            "the floor REMAINS B after the failed B→C backup rename — never A (a stale backup must never roll the floor backward)"
        );
        assert_eq!(
            f.snapshot_index, floor_b.snapshot_index,
            "the floor stays at B's exact snapshot"
        );
        assert_never_a(&store, "after the failed B→C advance");
        // The stale A backup was reconciled away BEFORE the advance started:
        // it is gone, so it can never be restored over B.
        assert!(
            floor_backup_leftovers(&store).is_empty(),
            "the B→C advance reconciled the stale A backup before it started"
        );

        // ---- (3) any further transition can never regress to A ----------
        // Re-run B→C fault-free: the floor advances to C (the tagged scheme
        // changes nothing for the happy path).
        let rep_c = run_checkpoint(&store, TARGET, &DeploymentId::new(c_id.clone()), false)
            .expect("the fault-free B→C retry succeeds");
        assert!(rep_c.established, "C is established");
        let floor_c = store.read_history_floor(TARGET).unwrap().unwrap();
        assert_eq!(floor_c.deployment_id.as_str(), c_id, "the floor is C");
        assert_never_a(&store, "after the fault-free B→C retry");
        // The committed C advance cleaned up its own tagged backup.
        assert!(
            floor_backup_leftovers(&store).is_empty(),
            "the committed B→C advance leaves no backup behind"
        );
    }

    proptest! {
        // The state-machine property for TAGGED floor backups: over
        // (history shape, A's position), COMMIT A→B while RETAINING the
        // stale tagged A backup (B's success-path cleanup is faulted), then
        // FAIL the actual B→backup rename during the B→C advance (the
        // `RenameFloorBackup` stage fault keyed by C) — the advance must
        // Err and the floor must REMAIN B (never A, never None); across the
        // fault-free B→C retry the floor must reach C, and after EVERY
        // transition `read_history_floor` must never regress to A. The
        // stale A backup is reconciled away by the next advance's pre-start
        // cleanup — never restored. Fixed seed 0x5EED_5EED + bounded cases
        // (16): the same vectors run on every invocation.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn stale_backup_never_rolls_the_floor_backward(
            history in prop::collection::vec(any::<bool>(), 3..7),
            a_at in 0usize..8,
        ) {
            run_stale_backup_never_rolls_case(&history, a_at);
        }
    }

    /// CONTROL: a normal A→B→C fault-free chain leaves the floor at C with
    /// no backup leftovers — the tagged backup scheme changes nothing for
    /// the happy path.
    #[test]
    fn control_fault_free_chain_leaves_floor_at_c() {
        let mut history = vec![true, false, true, false, true];
        history.push(true);
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        seed_history(&store, TARGET, "deploy", &history);
        let ok_ids: Vec<String> = history
            .iter()
            .enumerate()
            .filter(|(_, ok)| **ok)
            .map(|(n, _)| format!("deploy-{n:04}"))
            .collect();
        let a_id = ok_ids[0].clone();
        let b_id = ok_ids[ok_ids.len() - 2].clone();
        let c_id = ok_ids.last().unwrap().clone();
        for id in [&a_id, &b_id, &c_id] {
            run_checkpoint(&store, TARGET, &DeploymentId::new(id.clone()), false)
                .expect("a fault-free advance commits");
        }
        let floor = store.read_history_floor(TARGET).unwrap().unwrap();
        assert_eq!(
            floor.deployment_id.as_str(),
            c_id,
            "the fault-free A→B→C chain leaves the floor at C"
        );
        assert!(
            floor_backup_leftovers(&store).is_empty(),
            "a fault-free chain leaves no backup leftovers"
        );
    }

    // ---------------------------------------------------------------------
    // RECOVERY OF A TORN ADVANCE (the property test)
    // ---------------------------------------------------------------------

    /// One recovery case (the property's body): establish floor A (clean
    /// OR with an INTERRUPTED cleanup — the debt marker + leftover below-A
    /// dirs, replaying the commit-point test's seeding), DOUBLE-FAULT the
    /// advance A→B (B's parent-sync commit-point fault AND the restore
    /// fault — the transactional-advance property's fixture shows the fault
    /// arming), assert the TORN reads see floor A through the
    /// validated-backup fallback — never None, never an error, never a
    /// below-A exposure, with the visible suffix EXACTLY unchanged, the
    /// raw logs/dirs unchanged, and every below-A ref refused — then
    /// RECOVER by ATOMICALLY RESTORING the backup (rename + parent-dir
    /// fsync, never deleting it) and assert the floor remains A (same
    /// deployment_id + snapshot_index), the visible history is EXACTLY
    /// unchanged, and every ref below A remains rejected — no recovery
    /// transition produced None. The CONTROL: a backup that FAILS
    /// validation (corrupted backup) still fails closed (no below-A
    /// exposure) — the unvalidatable backup is never "no floor" — while
    /// the restored intact backup reads as A again. Then the fault-free
    /// advance control: advancing to B succeeds on the recovered fixture.
    fn run_recovery_case(history_in: &[bool], a_at: usize, a_cleanup_interrupted: bool) {
        let fx = seed_floor_a(history_in, a_at, a_cleanup_interrupted);
        let store = &fx.store;
        let a_id = fx.a_id.as_str();
        let a_index = fx.a_index;
        let b_id = fx.b_id.as_str();
        let pre = &fx.pre;

        // ---- DOUBLE FAULT: A → B fails at B's durability commit point
        // AND the restore of A also fails (arm B's parent-sync fault AND
        // the RestoreFloor fault, keyed by B's deployment id): the marker
        // is left ABSENT while the durable backup holds A.
        store.fault_registry().arm_sync_floor_parent(b_id);
        store.fault_registry().arm_restore_floor(b_id);
        let err = run_checkpoint(store, TARGET, &DeploymentId::new(b_id.to_string()), false)
            .expect_err("the double fault must fail the advance before B commits");
        assert!(
            err.to_string().contains("test fault"),
            "the fault is the failure cause, got: {err}"
        );

        // ---- TORN STATE: the validated backup IS the active floor -------
        // The marker is absent but the tagged backup `.prev.<b_id>` holds A. Every
        // read must see A
        // (the ORIGINAL floor — same deployment_id + snapshot_index, never
        // None, never an error) — a reader during the torn state sees
        // EXACTLY the pre-advance state, never the below-A prefix.
        assert!(
            !store.history_floor_path(TARGET).exists(),
            "the double fault leaves the marker absent"
        );
        assert!(
            store
                .refs_dir(TARGET)
                .join(format!("history-floor.json.prev.{b_id}"))
                .exists(),
            "the double fault leaves the durable backup holding A"
        );
        let torn = store.read_history_floor(TARGET).unwrap();
        let f = torn
            .as_ref()
            .expect("the torn state reads floor A through the validated backup — never None");
        assert_eq!(
            f.deployment_id.as_str(),
            a_id,
            "the torn read returns the ORIGINAL floor A (same deployment_id)"
        );
        assert_eq!(
            f.snapshot_index, a_index,
            "the torn read returns the ORIGINAL floor A (same snapshot_index)"
        );
        let torn_post = capture_visible(store, TARGET, &torn);
        assert_eq!(
            torn_post.snapshots, pre.snapshots,
            "the torn read exposes exactly the pre-advance snapshot suffix"
        );
        assert_eq!(
            torn_post.attempts, pre.attempts,
            "the torn read exposes exactly the pre-advance attempts suffix"
        );
        assert_eq!(
            torn_post.below_floor_ref_err, pre.below_floor_ref_err,
            "the same below-A refs stay refused during the torn state"
        );
        // Physical state unchanged: same raw logs, same deployment dirs.
        assert_eq!(
            store.read_snapshots_raw(TARGET).unwrap().len(),
            fx.pre_raw_snaps,
            "the torn state never touches the raw snapshot log"
        );
        assert_eq!(
            store.read_attempts_raw(TARGET).unwrap().len(),
            fx.pre_raw_attempts,
            "the torn state never touches the raw attempts log"
        );
        let dirs: Vec<String> = fx
            .history
            .iter()
            .enumerate()
            .filter(|(n, _)| store.deployment_dir(&format!("deploy-{n:04}")).exists())
            .map(|(n, _)| format!("deploy-{n:04}"))
            .collect();
        assert_eq!(
            dirs, fx.pre_dirs,
            "the torn state changes no deployment dir"
        );

        // ---- CONTROL: a backup that FAILS validation fails closed ------
        // Corrupt the backup (a valid floor retargeted to a foreign target
        // — breaks the target binding): the unvalidatable backup is NOT
        // trusted — every read fails closed with an integrity error, never
        // None (which would expose the full below-floor prefix). Restoring
        // the INTACT A floor to the tagged backup makes the fallback read A again.
        let backup_path = store
            .refs_dir(TARGET)
            .join(format!("history-floor.json.prev.{b_id}"));
        let mut retargeted = fx.a_floor.clone();
        retargeted.target = TargetName::new("staging".to_string());
        std::fs::write(
            &backup_path,
            serde_json::to_vec_pretty(&retargeted).unwrap(),
        )
        .unwrap();
        let e = store.read_history_floor(TARGET).unwrap_err();
        assert!(
            e.to_string().contains("integrity"),
            "an unvalidatable backup fails closed from the loader, got: {e}"
        );
        let e = store.read_snapshots(TARGET).unwrap_err();
        assert!(
            e.to_string().contains("integrity"),
            "read_snapshots propagates the unvalidatable-backup error, got: {e}"
        );
        let e = store.read_attempts(TARGET).unwrap_err();
        assert!(
            e.to_string().contains("integrity"),
            "read_attempts propagates the unvalidatable-backup error, got: {e}"
        );
        for tok in ["s0", "s1", "s2"] {
            let expr = history::parse_ref_expr(tok).unwrap();
            let e = history::resolve_ref_expr(&expr, TARGET, store).unwrap_err();
            assert!(
                e.to_string().contains("integrity"),
                "resolve '{tok}' fails closed after the backup corruption, got: {e}"
            );
        }
        // Restore the INTACT A floor to the backup: the fallback reads A
        // again — never None at ANY step of the torn state.
        std::fs::write(
            &backup_path,
            serde_json::to_vec_pretty(&fx.a_floor).unwrap(),
        )
        .unwrap();
        let intact_again = store.read_history_floor(TARGET).unwrap();
        assert!(
            intact_again.is_some(),
            "the restored intact backup reads as the active floor again — never None"
        );

        // ---- RECOVERY: ATOMIC RESTORE of the durable backup -------------
        // The documented recovery restores the tagged backup as the marker (rename +
        // parent-dir fsync — the SAME operation a failed advance's restore
        // performs via [`LocalStore::restore_floor_backup`]). The backup is
        // the ONLY valid floor in the torn state and is NEVER deleted
        // (deleting it would erase the floor and re-expose the below-floor
        // history). No recovery transition produced None: torn reads A,
        // the restored-backup read sees A, post-recovery reads A.
        store
            .recover_history_floor_backup(TARGET)
            .expect("recovery atomically restores the durable backup");
        assert!(
            store.history_floor_path(TARGET).exists(),
            "recovery restores the marker file"
        );
        assert!(
            floor_backup_leftovers(store).is_empty(),
            "recovery consumes the tagged backup: no stale .prev.<b_id> remains"
        );
        let recovered = store.read_history_floor(TARGET).unwrap();
        let f = recovered
            .as_ref()
            .expect("post-recovery the floor is A — never None");
        assert_eq!(
            f.deployment_id.as_str(),
            a_id,
            "recovery restores the ORIGINAL floor A (same deployment_id)"
        );
        assert_eq!(
            f.snapshot_index, a_index,
            "recovery restores the ORIGINAL floor A (same snapshot_index)"
        );
        let recovered_post = capture_visible(store, TARGET, &recovered);
        assert_eq!(
            recovered_post.snapshots, pre.snapshots,
            "visible history is EXACTLY unchanged after recovery"
        );
        assert_eq!(
            recovered_post.attempts, pre.attempts,
            "the visible attempts suffix is EXACTLY unchanged after recovery"
        );
        assert_eq!(
            recovered_post.below_floor_ref_err, pre.below_floor_ref_err,
            "every below-A ref stays refused after recovery"
        );
        // Physical state still EXACTLY the pre-advance state after
        // recovery: same raw logs, same deployment dirs (the recovery only
        // renames the backup into the marker name — it compacts nothing).
        assert_eq!(
            store.read_snapshots_raw(TARGET).unwrap().len(),
            fx.pre_raw_snaps,
            "recovery never touches the raw snapshot log"
        );
        assert_eq!(
            store.read_attempts_raw(TARGET).unwrap().len(),
            fx.pre_raw_attempts,
            "recovery never touches the raw attempts log"
        );
        let dirs_after: Vec<String> = fx
            .history
            .iter()
            .enumerate()
            .filter(|(n, _)| store.deployment_dir(&format!("deploy-{n:04}")).exists())
            .map(|(n, _)| format!("deploy-{n:04}"))
            .collect();
        assert_eq!(
            dirs_after, fx.pre_dirs,
            "recovery never deletes or creates a deployment dir"
        );
        assert!(
            torn.is_some() && intact_again.is_some() && recovered.is_some(),
            "no recovery transition produced None: torn, restored-backup, and post-recovery reads all see floor A"
        );

        // CONTROL: a fault-free advancement to B SUCCEEDS from the recovered
        // fixture (floor A is durable again; the advancement commits B).
        let rep_b = run_checkpoint(store, TARGET, &DeploymentId::new(b_id.to_string()), false)
            .expect("a fault-free advancement to B succeeds after recovery");
        assert!(rep_b.established, "the advancement to B establishes B");
        let floor_b = store.read_history_floor(TARGET).unwrap().unwrap();
        assert_eq!(floor_b.deployment_id.as_str(), b_id);
        assert_eq!(floor_b.snapshot_index, fx.b_index);
        assert!(
            floor_backup_leftovers(store).is_empty(),
            "a committed advance leaves no backup behind"
        );
    }

    proptest! {
        // RECOVERY of a TORN floor ADVANCE: over (history shape, A's
        // checkpoint position, whether A's cleanup was INTERRUPTED — clean
        // OR pending), DOUBLE-FAULT the advance A → B (B's parent-sync
        // commit-point fault + the restore fault, so the marker is left
        // ABSENT while the durable backup holds A), then assert the TORN
        // reads see floor A through the validated-backup fallback — never
        // None, never an error, never a below-A exposure, with the visible
        // suffix EXACTLY unchanged and every below-A ref refused — recover
        // by ATOMICALLY RESTORING the backup (rename + parent-dir fsync,
        // never deleting it), and assert the floor remains A (same
        // deployment_id + snapshot_index), the visible history is EXACTLY
        // unchanged, and every ref below A remains rejected — no recovery
        // transition produced None (torn reads A, post-recovery reads A).
        // The control: a backup that FAILS validation (corrupted backup)
        // still fails closed (no below-A exposure). Fixed seed 0x5EED_5EED
        // + bounded cases — the same vectors run on every invocation.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn recovery_restores_the_durable_backup(
            history in prop::collection::vec(any::<bool>(), 3..7),
            a_at in 0usize..8,
            a_cleanup_interrupted in any::<bool>(),
        ) {
            run_recovery_case(&history, a_at, a_cleanup_interrupted);
        }
    }

    // ---------------------------------------------------------------------
    // PRODUCTION AUTO-REPAIR OF A TORN ADVANCE (the property test)
    // ---------------------------------------------------------------------

    /// One production-repair case (the property's body): establish floor A
    /// (clean OR with an INTERRUPTED cleanup — the debt marker + leftover
    /// below-A dirs, replaying the commit-point test's seeding), DOUBLE-
    /// FAULT the advance A→B (B's parent-sync commit-point fault AND the
    /// restore fault — the same arming the transactional-advance property
    /// uses), assert EVERY torn read sees floor A — `read_history_floor`
    /// (never None, never B), the visible suffix EXACTLY unchanged, and
    /// every below-A ref rejected via `resolve_ref_expr` — then run THE
    /// PRODUCTION REPAIR: the NEXT CHECKPOINT invocation (a re-checkpoint
    /// of A through the checkpoint flow itself, `run_checkpoint` — never
    /// the test-only recovery call) restores the validated backup as the
    /// marker (rename + parent fsync) at its entry, then proceeds through
    /// the idempotency branch. After the repair every read STILL sees
    /// floor A (never None, never B), the visible suffix is EXACTLY
    /// unchanged, every below-A ref stays refused, and the tagged backup
    /// is consumed. The control: a fault-free advance to B SUCCEEDS from
    /// the repaired fixture — the advance moves on cleanly.
    fn run_production_repair_case(history_in: &[bool], a_at: usize, a_cleanup_interrupted: bool) {
        let fx = seed_floor_a(history_in, a_at, a_cleanup_interrupted);
        let store = &fx.store;
        let a_id = fx.a_id.as_str();
        let a_index = fx.a_index;
        let b_id = fx.b_id.as_str();
        let pre = &fx.pre;

        // ---- DOUBLE FAULT: A → B fails at B's durability commit point
        // AND the restore of A also fails (arm B's parent-sync fault AND
        // the RestoreFloor fault, keyed by B's deployment id — the
        // transactional-advance fixtures' arming): the marker is left
        // ABSENT while the durable tagged backup `.prev.<b_id>` holds A.
        store.fault_registry().arm_sync_floor_parent(b_id);
        store.fault_registry().arm_restore_floor(b_id);
        let err = run_checkpoint(store, TARGET, &DeploymentId::new(b_id.to_string()), false)
            .expect_err("the double fault must fail the advance before B commits");
        assert!(
            err.to_string().contains("test fault"),
            "the fault is the failure cause, got: {err}"
        );

        // ---- TORN STATE, BEFORE the repair: every read sees floor A ----
        assert!(
            !store.history_floor_path(TARGET).exists(),
            "the double fault leaves the marker absent"
        );
        assert!(
            store
                .refs_dir(TARGET)
                .join(format!("history-floor.json.prev.{b_id}"))
                .exists(),
            "the double fault leaves the durable backup holding A"
        );
        let torn = store.read_history_floor(TARGET).unwrap();
        let f = torn
            .as_ref()
            .expect("the torn state reads floor A through the validated backup — never None");
        assert_eq!(
            f.deployment_id.as_str(),
            a_id,
            "the torn read returns the ORIGINAL floor A (same deployment_id)"
        );
        assert_eq!(
            f.snapshot_index, a_index,
            "the torn read returns the ORIGINAL floor A (same snapshot_index)"
        );
        let torn_post = capture_visible(store, TARGET, &torn);
        assert_eq!(
            torn_post.snapshots, pre.snapshots,
            "the torn read exposes exactly the pre-advance snapshot suffix"
        );
        assert_eq!(
            torn_post.attempts, pre.attempts,
            "the torn read exposes exactly the pre-advance attempts suffix"
        );
        assert_eq!(
            torn_post.below_floor_ref_err, pre.below_floor_ref_err,
            "the same below-A refs stay refused during the torn state"
        );
        for n in 0..a_index {
            let expr = history::parse_ref_expr(&format!("s{n}")).unwrap();
            let e = history::resolve_ref_expr(&expr, TARGET, store).unwrap_err();
            assert!(
                e.to_string().contains("floor"),
                "the below-A ref s{n} stays rejected during the torn state, got: {e}"
            );
        }

        // ---- THE PRODUCTION REPAIR: the next CHECKPOINT invocation ----
        // Re-checkpointing A runs the FULL checkpoint flow (locks + the
        // checkpoint entry — the PRODUCTION path, never the test-only
        // recovery fn). The entry FIRST restores the validated backup as
        // the marker (rename + parent-dir fsync), THEN the idempotency
        // branch sees the restored floor A and finishes (a pending cleanup
        // converges; a clean A is a pure no-op). No repair transition
        // produced None: the torn read saw A, the post-repair read sees A.
        let rep_a = run_checkpoint(store, TARGET, &DeploymentId::new(a_id.to_string()), false)
            .expect("the next checkpoint repairs the torn state and succeeds");
        assert!(
            store.history_floor_path(TARGET).exists(),
            "the checkpoint entry restored the validated backup as the marker"
        );
        assert!(
            floor_backup_leftovers(store).is_empty(),
            "the production repair consumed the tagged backup: no stale .prev.<b_id> remains"
        );
        let repaired = store.read_history_floor(TARGET).unwrap();
        let f = repaired
            .as_ref()
            .expect("post-repair the floor is A — never None");
        assert_eq!(
            f.deployment_id.as_str(),
            a_id,
            "the production repair restored the ORIGINAL floor A (same deployment_id)"
        );
        assert_eq!(
            f.snapshot_index, a_index,
            "the production repair restored the ORIGINAL floor A (same snapshot_index)"
        );
        let repaired_post = capture_visible(store, TARGET, &repaired);
        assert_eq!(
            repaired_post.snapshots, pre.snapshots,
            "visible history is EXACTLY unchanged after the production repair"
        );
        assert_eq!(
            repaired_post.attempts, pre.attempts,
            "the visible attempts suffix is EXACTLY unchanged after the production repair"
        );
        assert_eq!(
            repaired_post.below_floor_ref_err, pre.below_floor_ref_err,
            "every below-A ref stays rejected after the production repair"
        );
        for n in 0..a_index {
            let expr = history::parse_ref_expr(&format!("s{n}")).unwrap();
            let e = history::resolve_ref_expr(&expr, TARGET, store).unwrap_err();
            assert!(
                e.to_string().contains("floor"),
                "the below-A ref s{n} stays rejected after the production repair, got: {e}"
            );
        }
        // The repair may also converge A's interrupted cleanup (the
        // idempotency branch runs the post-commit maintenance): the debt
        // clears and the report carries no warning.
        if a_cleanup_interrupted && fx.a_attempt_pos > 0 {
            assert!(
                !rep_a.cleanup_pending,
                "the repair converges A's interrupted cleanup"
            );
            assert!(
                store.read_cleanup_pending(TARGET, None).unwrap().is_none(),
                "the debt marker clears once the repair converges A's cleanup"
            );
        }
        assert!(
            torn.is_some() && repaired.is_some(),
            "no repair transition produced None: the torn read AND the post-repair read both see floor A"
        );

        // ---- THE ADVANCE MOVES ON CLEANLY: a fault-free checkpoint of B
        // SUCCEEDS from the repaired fixture (floor A is the durable marker
        // again; the advance commits B).
        let rep_b = run_checkpoint(store, TARGET, &DeploymentId::new(b_id.to_string()), false)
            .expect("a fault-free advancement to B succeeds after the production repair");
        assert!(rep_b.established, "the advancement to B establishes B");
        let floor_b = store.read_history_floor(TARGET).unwrap().unwrap();
        assert_eq!(floor_b.deployment_id.as_str(), b_id);
        assert_eq!(floor_b.snapshot_index, fx.b_index);
        assert!(
            floor_backup_leftovers(store).is_empty(),
            "a committed advance leaves no backup behind"
        );
    }

    proptest! {
        // THE PROPERTY (the user's requirement): through the PRODUCTION
        // path — the checkpoint flow itself, never the test-only recovery
        // call — a DOUBLE-FAULTED advance A → B (B's commit-point
        // parent-sync fault + the restore fault) leaves a TORN state whose
        // every transition (reads of read_history_floor, the visible
        // suffix, and ref resolution BEFORE repair, during, and after)
        // retains floor A — never None, never B — with every below-A ref
        // still rejected; the next CHECKPOINT invocation (re-checkpointing
        // A) repairs the torn state automatically at its entry (restores
        // the validated backup, rename + parent-dir fsync, before
        // proceeding) and the subsequent fault-free advance to B moves on
        // cleanly. Fixed seed 0x5EED_5EED + bounded cases — the same
        // vectors run on every invocation.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn production_checkpoint_repairs_torn_advance(
            history in prop::collection::vec(any::<bool>(), 3..7),
            a_at in 0usize..8,
            a_cleanup_interrupted in any::<bool>(),
        ) {
            run_production_repair_case(&history, a_at, a_cleanup_interrupted);
        }
    }

    // ---------------------------------------------------------------------
    // Floor-marker INTEGRITY BINDING (the property test)
    // ---------------------------------------------------------------------

    /// One corruption/tampering of the floor marker. Every variant breaks at
    /// least one binding the loader verifies
    /// ([`crate::store::local::LocalStore::read_history_floor`]): the
    /// target-name binding, the exact snapshot-pair binding, or the attempt
    /// binding — so a mutated marker must NEVER be silently treated as
    /// "no floor" (which would expose the below-floor prefix).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FloorMutation {
        /// (1) Retarget the marker to a different target name.
        Retarget,
        /// (2a) `snapshot_index` BELOW the real one.
        IndexBelow,
        /// (2b) `snapshot_index` ABOVE the real one.
        IndexAbove,
        /// (3a) `deployment_id` → a deployment that never existed.
        ForeignDeployment,
        /// (3b) `deployment_id` → another EXISTING deployment (its snapshot
        /// lives at a different index, so the exact snapshot pair still
        /// fails — the id alone is never enough).
        ExistingDeployment,
        /// (4) Delete the anchor snapshot (the exact entry the marker
        /// names).
        DeleteAnchorSnapshot,
        /// (5) Delete the matching attempt (the marker's own deployment).
        DeleteAnchorAttempt,
    }

    fn floor_mutation_strategy() -> impl Strategy<Value = FloorMutation> {
        prop_oneof![
            1 => Just(FloorMutation::Retarget),
            1 => Just(FloorMutation::IndexBelow),
            1 => Just(FloorMutation::IndexAbove),
            1 => Just(FloorMutation::ForeignDeployment),
            1 => Just(FloorMutation::ExistingDeployment),
            1 => Just(FloorMutation::DeleteAnchorSnapshot),
            1 => Just(FloorMutation::DeleteAnchorAttempt),
        ]
    }

    /// Rewrite the marker file to a mutated form of the INTACT floor (each
    /// mutation is a fresh corruption derived from the intact marker, never
    /// from an already-corrupt file — a sequence of mutations stays a
    /// sequence of independent corruptions), or physically delete the named
    /// anchor record for the anchor-deletion mutations.
    fn apply_floor_mutation(store: &LocalStore, intact: &HistoryFloor, mutation: FloorMutation) {
        match mutation {
            FloorMutation::DeleteAnchorSnapshot => {
                // Physically remove the snapshot entry the marker names
                // (index AND deployment id — the exact pair).
                let keep: Vec<DeploymentSnapshot> = store
                    .read_snapshots_raw(TARGET)
                    .unwrap()
                    .into_iter()
                    .filter(|s| {
                        !(s.index == intact.snapshot_index
                            && s.deployment_id == intact.deployment_id)
                    })
                    .collect();
                let body = keep
                    .iter()
                    .map(|s| serde_json::to_string(s).unwrap())
                    .collect::<Vec<_>>()
                    .join("\n");
                std::fs::write(
                    store.refs_dir(TARGET).join("snapshots.jsonl"),
                    if body.is_empty() {
                        String::new()
                    } else {
                        body + "\n"
                    },
                )
                .unwrap();
            }
            FloorMutation::DeleteAnchorAttempt => {
                // Physically remove the attempt of the marker's deployment.
                let keep: Vec<DeploymentAttempt> = store
                    .read_attempts_raw(TARGET)
                    .unwrap()
                    .into_iter()
                    .filter(|a| a.deployment_id != intact.deployment_id)
                    .collect();
                let body = keep
                    .iter()
                    .map(|a| serde_json::to_string(a).unwrap())
                    .collect::<Vec<_>>()
                    .join("\n");
                std::fs::write(
                    store.target_dir(TARGET).join("attempts.jsonl"),
                    if body.is_empty() {
                        String::new()
                    } else {
                        body + "\n"
                    },
                )
                .unwrap();
            }
            _ => {
                let mut m = intact.clone();
                match mutation {
                    FloorMutation::Retarget => {
                        m.target = TargetName::new("staging".to_string());
                    }
                    FloorMutation::IndexBelow => {
                        m.snapshot_index = intact.snapshot_index.saturating_sub(1);
                    }
                    FloorMutation::IndexAbove => {
                        m.snapshot_index = intact.snapshot_index + 1;
                    }
                    FloorMutation::ForeignDeployment => {
                        m.deployment_id = DeploymentId::new("deploy-foreign".to_string());
                    }
                    FloorMutation::ExistingDeployment => {
                        m.deployment_id = DeploymentId::new("deploy-0000".to_string());
                    }
                    _ => unreachable!("the anchor-deletion variants are handled above"),
                }
                std::fs::write(
                    store.history_floor_path(TARGET),
                    serde_json::to_vec_pretty(&m).unwrap(),
                )
                .unwrap();
            }
        }
    }

    /// Assert that NO PUBLIC reader exposes a below-floor prefix after a
    /// mutation: the loader fails closed with an integrity error, and every
    /// gated public reader propagates it (`read_attempts`, `read_snapshots`,
    /// ref resolution, the log render). A corrupted marker is NEVER silently
    /// downgraded to "no floor" (full exposure) and never yields a partial
    /// suffix.
    fn assert_mutated_floor_fails_closed(store: &LocalStore, mutation: FloorMutation) {
        // The loader itself: integrity error, never `None` (a `None` would
        // make the gated readers expose the FULL history — the danger).
        let err = store.read_history_floor(TARGET).unwrap_err();
        assert!(
            err.to_string().contains("integrity"),
            "{mutation:?} must fail closed with an integrity error from the loader, got: {err}"
        );
        // `read_attempts` (the `deploy log` source): propagates the error.
        let err = store.read_attempts(TARGET).unwrap_err();
        assert!(
            err.to_string().contains("integrity"),
            "read_attempts must propagate the integrity error after {mutation:?}, got: {err}"
        );
        // `read_snapshots` (the rollback-refs source): propagates the error.
        let err = store.read_snapshots(TARGET).unwrap_err();
        assert!(
            err.to_string().contains("integrity"),
            "read_snapshots must propagate the integrity error after {mutation:?}, got: {err}"
        );
        // Ref resolution reads the gated snapshot chain: the below-floor ref
        // AND the checkpoint ref both fail (never a resolved below-floor
        // snapshot).
        for token in ["s0", "s1", "s2"] {
            let expr = history::parse_ref_expr(token).unwrap();
            let err = history::resolve_ref_expr(&expr, TARGET, store).unwrap_err();
            assert!(
                err.to_string().contains("integrity"),
                "resolve '{token}' must fail with the integrity error after {mutation:?}, got: {err}"
            );
        }
        // The log render (`deploy log`) is read_attempts-gated.
        let err = crate::cli::render_log(store, TARGET, &[]).unwrap_err();
        assert!(
            err.to_string().contains("integrity"),
            "the log render must fail with the integrity error after {mutation:?}, got: {err}"
        );
    }

    fn run_floor_mutation_case(mutations: &[FloorMutation]) {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        // History: s0 (deploy-0000), s1 (deploy-0001), a FAILED attempt
        // (deploy-0002 — below-floor prefix material), the checkpoint
        // deploy-0003 at s2, then a failed deploy-0004 ABOVE the floor (the
        // retained suffix must never shrink). Floor at s2 / deploy-0003:
        // below-floor prefix = [s0, s1] + attempts [deploy-0000..deploy-0002];
        // the suffix = [s2] + attempts [deploy-0003, deploy-0004].
        seed_history(&store, TARGET, "deploy", &[true, true, false, true, false]);
        let anchor_id = "deploy-0003";
        run_checkpoint(
            &store,
            TARGET,
            &DeploymentId::new(anchor_id.to_string()),
            false,
        )
        .expect("the control checkpoint establishes a valid, integrity-bound floor");

        // ---- CONTROL: the INTACT marker reads fine and the public readers
        // expose exactly the at/above-floor suffix (the property's baseline).
        let intact = store.read_history_floor(TARGET).unwrap().unwrap();
        assert_eq!(intact.deployment_id.as_str(), anchor_id);
        assert_eq!(intact.snapshot_index, 2);
        let snaps = store.read_snapshots(TARGET).unwrap();
        assert_eq!(
            snaps.iter().map(|s| s.index).collect::<Vec<_>>(),
            vec![2],
            "intact floor exposes exactly the at/above suffix"
        );
        let attempts = store.read_attempts(TARGET).unwrap();
        assert_eq!(
            attempts
                .iter()
                .map(|a| a.deployment_id.as_str())
                .collect::<Vec<_>>(),
            vec!["deploy-0003", "deploy-0004"],
            "intact floor exposes the suffix from the checkpoint's own attempt"
        );
        history::resolve_ref_expr(&history::parse_ref_expr("s2").unwrap(), TARGET, &store)
            .expect("the checkpoint snapshot resolves on the intact floor");
        let err =
            history::resolve_ref_expr(&history::parse_ref_expr("s0").unwrap(), TARGET, &store)
                .unwrap_err();
        assert!(
            err.to_string().contains("history floor") || err.to_string().contains("no snapshot"),
            "a below-floor ref stays refused on the intact floor, got: {err}"
        );
        let lines = crate::cli::render_log(&store, TARGET, &attempts).unwrap();
        assert_eq!(
            lines.len(),
            2,
            "the intact log render shows exactly the suffix"
        );
        assert!(
            lines[0].starts_with("s2  "),
            "first rendered line carries the checkpoint's snapshot prefix, got: {}",
            lines[0]
        );

        // ---- MUTATIONS: every corruption of the marker must fail closed —
        // no public reader ever exposes a below-floor prefix.
        for &mutation in mutations {
            apply_floor_mutation(&store, &intact, mutation);
            assert_mutated_floor_fails_closed(&store, mutation);
        }
    }

    /// EXHAUSTIVE coverage: every mutation is exercised against a FRESH
    /// fixture (deterministic, independent of the proptest seed), so a
    /// single broken binding is always caught even if the randomized
    /// sequence never sampled that variant.
    #[test]
    fn every_floor_mutation_fails_closed_exhaustively() {
        for mutation in [
            FloorMutation::Retarget,
            FloorMutation::IndexBelow,
            FloorMutation::IndexAbove,
            FloorMutation::ForeignDeployment,
            FloorMutation::ExistingDeployment,
            FloorMutation::DeleteAnchorSnapshot,
            FloorMutation::DeleteAnchorAttempt,
        ] {
            run_floor_mutation_case(&[mutation]);
        }
    }

    proptest! {
        // Floor-marker integrity: each case runs a deterministic sequence of
        // mutations over a FRESH fixture (fixed seed 0x5EED_5EED + bounded
        // cases — the same vectors run on every invocation). Every mutated
        // marker fails closed with an integrity error from the loader and
        // every PUBLIC reader propagates it: a corrupted marker is never
        // silently downgraded to "no floor" (full exposure) and never
        // exposes a below-floor prefix.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn floor_marker_integrity_binding(
            mutations in prop::collection::vec(floor_mutation_strategy(), 0..7),
        ) {
            run_floor_mutation_case(&mutations);
        }
    }

    // ---------------------------------------------------------------------
    // Cleanup-marker FLAG-ONLY + INTEGRITY BINDING (the property test)
    // ---------------------------------------------------------------------

    /// One corruption/tampering of the cleanup-pending FLAG marker. With the
    /// `pending_deployments` worklist removed by construction (the logs
    /// retain the worklist), every mutation targets the marker's REMAINING
    /// fields — the target name, the deployment id, the snapshot anchor — or
    /// rewrites a legacy-shaped / foreign-version marker. Every variant
    /// breaks at least one check the reader verifies
    /// ([`crate::store::local::LocalStore::read_cleanup_pending`]): the
    /// version gate, the target-name binding, or the floor-anchor binding —
    /// so a corrupted marker is never trusted for the pending/repair
    /// decision and can never widen the log-derived deletion set.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CleanupMutation {
        /// (1) Retarget the marker to a different (unrelated) target name.
        Retarget,
        /// (2a) `snapshot_index` BELOW the floor's real anchor.
        IndexBelow,
        /// (2b) `snapshot_index` ABOVE the floor's real anchor.
        IndexAbove,
        /// (3a) `deployment_id` → a deployment that never existed.
        ForeignDeployment,
        /// (3b) `deployment_id` → a REAL RETAINED at/above-floor deployment
        /// (the corruption that must never cause its dir to be deleted).
        ExistingDeployment,
        /// (4) The legacy v1 shape carrying the REMOVED `pending_deployments`
        /// worklist (stray deployment ids) — the version gate must refuse
        /// it, never silently reinterpret it.
        LegacyShape,
        /// (5) A foreign marker schema version.
        ForeignVersion,
    }

    fn cleanup_mutation_strategy() -> impl Strategy<Value = CleanupMutation> {
        prop_oneof![
            1 => Just(CleanupMutation::Retarget),
            1 => Just(CleanupMutation::IndexBelow),
            1 => Just(CleanupMutation::IndexAbove),
            1 => Just(CleanupMutation::ForeignDeployment),
            1 => Just(CleanupMutation::ExistingDeployment),
            1 => Just(CleanupMutation::LegacyShape),
            1 => Just(CleanupMutation::ForeignVersion),
        ]
    }

    /// The pieces of one interrupted-cleanup fixture.
    struct CleanupFixture {
        /// The checkpoint deployment id (the floor's own deployment).
        target_id: String,
        /// The planned floor for that deployment.
        floor: HistoryFloor,
        /// `checkpoint_discards` from the STILL-INTACT logs: the EXACT set
        /// the compaction may delete (the property's oracle).
        ground_truth: FloorDiscards,
        /// Every seeded deployment id NOT in the discard set (retained
        /// at/above-floor dirs) plus the unrelated target's deployment dir.
        retained_ids: Vec<String>,
        /// The never-delete guard-rail identities (releases/objects/servers).
        never: (ReleaseId, TreeDigest, String),
    }

    /// Seed a fresh fixture into the INTERRUPTED-CLEANUP debt state: a valid
    /// checkpoint whose FIRST compaction phase (deployment-dir deletion)
    /// faulted — the durable floor stands, the flag marker is present, and
    /// the raw logs are still intact (delete-first ordering: the fault fires
    /// BEFORE any deletion or rewrite, so the logs still name the full
    /// worklist). `checkpoint_at` never selects the first success (so a real
    /// below-floor prefix exists) nor the last one (so a retained
    /// at/above-floor deployment exists to corrupt the marker into).
    fn seed_interrupted_cleanup(
        store: &LocalStore,
        history: &[bool],
        checkpoint_at: usize,
    ) -> CleanupFixture {
        seed_history(store, TARGET, "deploy", history);
        // Guard rails that must survive EVERY cleanup: release/object/server
        // stores plus an UNRELATED target's deployment directory.
        let never = seed_never_delete(store);
        let unrelated = "unrelated-target-0000";
        std::fs::create_dir_all(store.deployment_dir(unrelated)).unwrap();

        let ok_ids: Vec<String> = history
            .iter()
            .enumerate()
            .filter(|(_, ok)| **ok)
            .map(|(n, _)| format!("deploy-{n:04}"))
            .collect();
        assert!(
            ok_ids.len() >= 3,
            "the seeded prefix plus the filtered history guarantee >= 3 successes"
        );
        let pick = 1 + checkpoint_at % (ok_ids.len() - 2);
        let target_id = ok_ids[pick].clone();
        let floor = plan_floor(store, TARGET, &DeploymentId::new(target_id.clone()))
            .expect("the checkpoint deployment is a success, so it has a snapshot");
        let ground_truth = store
            .checkpoint_discards(TARGET, &floor)
            .expect("the intact logs enumerate the full discard worklist");
        assert!(
            !ground_truth.discarded_deployments.is_empty(),
            "the checkpoint is never the first success, so something is discarded"
        );
        let retained_ids: Vec<String> = history
            .iter()
            .enumerate()
            .map(|(n, _)| format!("deploy-{n:04}"))
            .filter(|id| !ground_truth.discarded_deployments.contains(id))
            .chain(std::iter::once(unrelated.to_string()))
            .collect();

        // Establish the checkpoint with the FIRST compaction phase faulted:
        // the durable floor + flag marker stand, the logs stay intact, and
        // NOTHING below the floor is deleted yet (the fault fires before the
        // deletion loop).
        store.fault_registry().arm_compact_deployments(&target_id);
        let rep = run_checkpoint(store, TARGET, &DeploymentId::new(target_id.clone()), false)
            .expect("an interrupted compaction is committed-with-warning, never an Err");
        assert!(rep.cleanup_pending);
        let pending = store
            .read_cleanup_pending(TARGET, Some(&floor))
            .unwrap()
            .expect("the durable flag marker records the debt");
        assert_eq!(pending.deployment_id.as_str(), target_id);
        assert_eq!(pending.snapshot_index, floor.snapshot_index);
        // The debt state: floor present, logs intact, all below-floor dirs
        // still on disk.
        assert!(store.read_history_floor(TARGET).unwrap().is_some());
        assert_eq!(
            store.read_attempts_raw(TARGET).unwrap().len(),
            history.len()
        );
        assert_eq!(
            store.read_snapshots_raw(TARGET).unwrap().len(),
            ok_ids.len()
        );
        for id in &ground_truth.discarded_deployments {
            assert!(
                store.deployment_dir(id).exists(),
                "debt state: below-floor dir {id} still exists"
            );
        }
        CleanupFixture {
            target_id,
            floor,
            ground_truth,
            retained_ids,
            never,
        }
    }

    /// Every retained sentinel survives: at/above-floor deployment dirs, the
    /// unrelated target's deployment dir, `releases/`, `objects/`, `servers/`.
    fn assert_cleanup_sentinels(store: &LocalStore, fx: &CleanupFixture) {
        for id in &fx.retained_ids {
            assert!(
                store.deployment_dir(id).exists(),
                "retained deployment dir {id} must survive the cleanup"
            );
        }
        assert_never_delete(store, &fx.never.0, &fx.never.1, &fx.never.2);
    }

    /// Rewrite the flag marker to a corrupted form derived from the INTACT
    /// marker (each mutation is a fresh corruption of the intact marker,
    /// never of a previous corruption).
    fn apply_cleanup_mutation(
        store: &LocalStore,
        fx: &CleanupFixture,
        mutation: CleanupMutation,
        retained_anchor: &str,
    ) {
        match mutation {
            CleanupMutation::LegacyShape => {
                // The pre-change v1 shape: still carries the REMOVED
                // `pending_deployments` worklist (stray deployment ids) under
                // the old shared schema version — serde would silently drop
                // the extra field, so the version gate must refuse it.
                let legacy = serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "target": TARGET,
                    "deployment_id": fx.target_id,
                    "snapshot_index": fx.floor.snapshot_index,
                    "established_at": "2026-01-01T00:00:00Z",
                    "pending_deployments": ["deploy-0000", "stray-foreign"],
                });
                std::fs::write(
                    store.cleanup_pending_path(TARGET),
                    serde_json::to_vec_pretty(&legacy).unwrap(),
                )
                .unwrap();
            }
            _ => {
                let mut m = store
                    .read_cleanup_pending(TARGET, Some(&fx.floor))
                    .unwrap()
                    .expect("the intact flag marker reads");
                match mutation {
                    CleanupMutation::Retarget => {
                        m.target = TargetName::new("staging".to_string());
                    }
                    CleanupMutation::IndexBelow => {
                        m.snapshot_index = fx.floor.snapshot_index.saturating_sub(1);
                    }
                    CleanupMutation::IndexAbove => {
                        m.snapshot_index = fx.floor.snapshot_index + 1;
                    }
                    CleanupMutation::ForeignDeployment => {
                        m.deployment_id = DeploymentId::new("deploy-foreign".to_string());
                    }
                    CleanupMutation::ExistingDeployment => {
                        m.deployment_id = DeploymentId::new(retained_anchor.to_string());
                    }
                    CleanupMutation::ForeignVersion => {
                        m.schema_version = CLEANUP_PENDING_SCHEMA_VERSION + 1;
                    }
                    CleanupMutation::LegacyShape => unreachable!("handled above"),
                }
                std::fs::write(
                    store.cleanup_pending_path(TARGET),
                    serde_json::to_vec_pretty(&m).unwrap(),
                )
                .unwrap();
            }
        }
    }

    /// The corrupted marker must FAIL CLOSED wherever the binding applies: a
    /// target/anchor corruption is an integrity error; a legacy/foreign
    /// version is a schema-version error. A `None` would be the danger — the
    /// marker silently ignored could still gate (or clear) without scrutiny;
    /// an `Err` forces the retry onto the log-derived worklist.
    fn assert_cleanup_read_fails_closed(
        store: &LocalStore,
        fx: &CleanupFixture,
        mutation: CleanupMutation,
    ) {
        let err = store
            .read_cleanup_pending(TARGET, Some(&fx.floor))
            .unwrap_err();
        match mutation {
            CleanupMutation::LegacyShape | CleanupMutation::ForeignVersion => {
                assert!(
                    err.to_string().contains("schema_version"),
                    "{mutation:?} must fail closed on the schema version, got: {err}"
                );
            }
            _ => {
                assert!(
                    err.to_string().contains("integrity"),
                    "{mutation:?} must fail closed with an integrity error, got: {err}"
                );
            }
        }
    }

    fn run_cleanup_marker_mutation_case(
        history_in: &[bool],
        checkpoint_at: usize,
        mutation: CleanupMutation,
    ) {
        // The seeded prefix: a guaranteed success then a guaranteed FAILED
        // attempt below any non-zero floor (a `deployments/<id>/` dir with
        // NO snapshot line — only its attempts.jsonl line names such a dir,
        // the worklist the logs must retain).
        let mut history = vec![true, false];
        history.extend_from_slice(history_in);
        assert!(
            history.iter().filter(|ok| **ok).count() >= 3,
            "the fixture needs >= 3 successes for a floor that is neither first nor last"
        );

        // ---- CONTROL (c): the INTACT-marker retry converges — marker
        // cleared, logs compacted to the suffix, exactly the log-derived
        // discard set deleted, every retained sentinel intact.
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let fx = seed_interrupted_cleanup(&store, &history, checkpoint_at);
        let retry = run_checkpoint(
            &store,
            TARGET,
            &DeploymentId::new(fx.target_id.clone()),
            false,
        )
        .expect("the intact-marker control retry converges");
        assert!(!retry.cleanup_pending, "control: converged");
        assert!(
            store
                .read_cleanup_pending(TARGET, Some(&fx.floor))
                .unwrap()
                .is_none(),
            "control: the flag marker clears once the cleanup completes"
        );
        let attempts = store.read_attempts_raw(TARGET).unwrap();
        assert_eq!(attempts[0].deployment_id.as_str(), fx.target_id);
        let snaps = store.read_snapshots_raw(TARGET).unwrap();
        assert!(snaps.iter().all(|s| s.index >= fx.floor.snapshot_index));
        for id in &fx.ground_truth.discarded_deployments {
            assert!(
                !store.deployment_dir(id).exists(),
                "control: below-floor dir {id} is deleted"
            );
        }
        assert_cleanup_sentinels(&store, &fx);

        // ---- MUTATION: a FRESH fixture in the same debt state, with the
        // marker corrupted BEFORE the retry.
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let fx = seed_interrupted_cleanup(&store, &history, checkpoint_at);
        // A retained at/above-floor deployment id — the corruption target
        // that must never be deleted (the marker is never the floor's own id:
        // the checkpoint is never the last attempt).
        let retained_anchor = fx
            .retained_ids
            .iter()
            .find(|id| id.starts_with("deploy-") && **id != fx.target_id)
            .expect("a retained at/above-floor deployment exists")
            .clone();
        // The pre-retry physical deployment-dir inventory.
        let before: Vec<String> = std::fs::read_dir(store.base().join("deployments"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        apply_cleanup_mutation(&store, &fx, mutation, &retained_anchor);
        assert_cleanup_read_fails_closed(&store, &fx, mutation);

        // The retry (faults disarmed) must still converge — and the ACTUAL
        // physical deletion set is EXACTLY A SUBSET of the log-derived
        // discard set: nothing retained, unrelated, or out-of-worklist was
        // removed.
        let retry = run_checkpoint(
            &store,
            TARGET,
            &DeploymentId::new(fx.target_id.clone()),
            false,
        )
        .expect("a corrupted marker must never turn the retry into an Err");
        assert!(
            !retry.cleanup_pending,
            "the corrupted-marker retry converges (marker cleared)"
        );
        assert!(
            store
                .read_cleanup_pending(TARGET, Some(&fx.floor))
                .unwrap()
                .is_none(),
            "the corrupted/stale marker is cleared by the converging retry"
        );
        let after: Vec<String> = std::fs::read_dir(store.base().join("deployments"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        for gone in before.iter().filter(|id| !after.contains(id)) {
            assert!(
                fx.ground_truth.discarded_deployments.contains(gone),
                "the actual deletion set must be a SUBSET of checkpoint_discards: '{gone}' was deleted but is not in the log-derived discard set"
            );
        }
        // (b) Every retained sentinel survives across the mutation.
        assert_cleanup_sentinels(&store, &fx);
        // Convergence: the logs compact to the suffix and every below-floor
        // dir named by the intact logs is gone (the worklist came from the
        // logs, never the marker).
        let attempts = store.read_attempts_raw(TARGET).unwrap();
        assert_eq!(attempts[0].deployment_id.as_str(), fx.target_id);
        let snaps = store.read_snapshots_raw(TARGET).unwrap();
        assert!(snaps.iter().all(|s| s.index >= fx.floor.snapshot_index));
        for id in &fx.ground_truth.discarded_deployments {
            assert!(
                !store.deployment_dir(id).exists(),
                "below-floor dir {id} converges away"
            );
        }
    }

    proptest! {
        // The CLEANUP-MARKER property: a corrupted/tampered cleanup marker
        // can NEVER widen the deletion set. Each case establishes a valid
        // checkpoint whose compaction FAILED (durable floor + flag marker
        // present, logs still intact), then (c) runs the intact-marker
        // CONTROL retry — it converges (marker cleared, logs compacted to
        // the suffix) — and injects an ARBITRARY marker mutation (foreign
        // target name, arbitrary snapshot-index anchors, foreign or retained
        // deployment ids, a legacy v1 marker with the removed
        // pending_deployments worklist, a foreign schema version): the
        // corrupted read fails closed where the binding applies, and the
        // retry's ACTUAL physical deletion set is EXACTLY A SUBSET of
        // `checkpoint_discards(target, floor).discarded_deployments`, with
        // every retained sentinel surviving (at/above-floor deployment dirs,
        // an unrelated target's deployment dir, releases/, objects/,
        // servers/) — the deleted worklist lives in the logs, never in the
        // marker.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn corrupted_cleanup_marker_never_widens_the_deletion_set(
            history in prop::collection::vec(any::<bool>(), 3..7)
                .prop_filter(
                    "the seeded prefix plus the filtered history needs >= 3 successes",
                    |v| v.iter().filter(|ok| **ok).count() >= 2,
                ),
            checkpoint_at in 0usize..8,
            mutation in cleanup_mutation_strategy(),
        ) {
            run_cleanup_marker_mutation_case(&history, checkpoint_at, mutation);
        }
    }

    /// EXHAUSTIVE coverage: every marker corruption runs against a FRESH
    /// fixture (deterministic, independent of the proptest seed), so a
    /// single broken binding or a single widening of the deletion set is
    /// always caught even if the randomized sequence never sampled that
    /// variant.
    #[test]
    fn every_cleanup_marker_mutation_fails_closed_exhaustively() {
        for mutation in [
            CleanupMutation::Retarget,
            CleanupMutation::IndexBelow,
            CleanupMutation::IndexAbove,
            CleanupMutation::ForeignDeployment,
            CleanupMutation::ExistingDeployment,
            CleanupMutation::LegacyShape,
            CleanupMutation::ForeignVersion,
        ] {
            run_cleanup_marker_mutation_case(&[true, true, false, true], 1, mutation);
        }
    }
    // -------------------------------------------------------------------
    // GLOBAL ARTIFACT GARBAGE COLLECTION (the property test)
    // -------------------------------------------------------------------
    //
    // The checkpoint's post-commit pass now ends with a GLOBAL,
    // reachability-based artifact GC (`crate::store::gc`). The property
    // family below drives the whole path — generated targets, per-target
    // histories, SHARED releases and SHARED trees, pins, incomplete
    // (pending) operations, and injected GC faults — and asserts the eight
    // invariants:
    //
    // 1. no reachable or pinned artifact is ever deleted;
    // 2. a pin never keeps pre-floor history visible;
    // 3. another target's references protect shared content;
    // 4. without faults, every unreachable release/tree is removed;
    // 5. with faults, extra garbage may remain but required content never
    //    disappears;
    // 6. repeating cleanup converges;
    // 7. repeating a completed checkpoint is idempotent;
    // 8. advancing one target never truncates another target's history.
    //
    // The ORACLE mirrors the collector's reachability sources over the
    // floor-gated reads (the well-tested enforcement point): the retained
    // binding set = retained attempts' + snapshots' slot artifacts, every
    // retained deployment record's plan (unfinished operations included),
    // every target's observed artifact, and every pin; releases = the
    // bindings' releases + plan `desired_release`s + pins; trees = the
    // bindings' trees + every pinned release's variant trees.

    /// One generated attempt step: `ok` (produces a snapshot), a release
    /// index, and a variant index. The tree of `(rel, variant)` comes from
    /// the release's OWN variant map, and the maps are built so trees are
    /// SHARED across releases and targets (trees[(2*rel+variant) % n]).
    #[derive(Debug, Clone)]
    struct GcStep {
        ok: bool,
        rel: usize,
        variant: usize,
    }

    /// One generated GC case.
    #[derive(Debug, Clone)]
    struct GcCase {
        n_trees: usize,
        n_releases: usize,
        t0_steps: Vec<GcStep>,
        t1_steps: Vec<GcStep>,
        /// Checkpoint index into t0's successful steps (0..4; modulo the
        /// success count).
        t0_ck: usize,
        /// Optional checkpoint index into t1's successful steps.
        t1_ck: Option<usize>,
        /// Optional whole-release pin (release index).
        pin_release: Option<usize>,
        /// Also pin the exact (release, v0, tree) binding.
        pin_binding: bool,
        /// t0's LAST attempt is an INCOMPLETE operation (its latest
        /// transition stays `InProgress` — no terminal transition).
        incomplete: bool,
        /// 0 = no fault; 1 = the GC SCAN fails; 2 = the release deletion
        /// phase fails; 3 = the tree deletion phase fails.
        fault: u8,
        /// Checkpoint t0 a SECOND time at a STRICTLY LATER success.
        advance: bool,
    }

    fn gc_step_strategy() -> impl Strategy<Value = GcStep> {
        (any::<bool>(), 0usize..4, 0usize..2).prop_map(|(ok, rel, variant)| GcStep {
            ok,
            rel,
            variant,
        })
    }

    fn gc_case_strategy() -> impl Strategy<Value = GcCase> {
        (
            1usize..=3,
            1usize..=3,
            prop::collection::vec(gc_step_strategy(), 0..8),
            prop::collection::vec(gc_step_strategy(), 0..8),
            0usize..4,
            prop::option::of(0usize..4),
            prop::option::of(0usize..4),
            any::<bool>(),
            any::<bool>(),
            0u8..4,
            any::<bool>(),
        )
            .prop_map(
                |(
                    n_trees,
                    n_releases,
                    t0_steps,
                    t1_steps,
                    t0_ck,
                    t1_ck,
                    pin_release,
                    pin_binding,
                    incomplete,
                    fault,
                    advance,
                )| {
                    GcCase {
                        n_trees,
                        n_releases,
                        t0_steps,
                        t1_steps,
                        t0_ck,
                        t1_ck,
                        pin_release,
                        pin_binding,
                        incomplete,
                        fault,
                        advance,
                    }
                },
            )
    }

    /// The artifact-reference carrier records the fixture writes: an
    /// attempt (`desired` map), a snapshot (`slots` map), and the
    /// deployment plan (per-slot artifacts + `desired_release`).
    fn gc_binding(release: &ReleaseId, variant: usize, tree: &TreeDigest) -> ArtifactRef {
        ArtifactRef {
            release: release.clone(),
            variant: VariantName::new(if variant == 0 { "v0" } else { "v1" }),
            tree: tree.clone(),
        }
    }

    fn gc_attempt(target: &str, id: &str, binding: &ArtifactRef) -> DeploymentAttempt {
        DeploymentAttempt {
            deployment_schema_version: SCHEMA_VERSION,
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new(target.to_string()),
            slot_ids: vec![PlacementSlotId::new("p1")],
            behavior_sha256: "sha256-gc".to_string(),
            attempted_at: format!("2026-01-01T00:00:00Z-{id}"),
            desired: BTreeMap::from([(
                PlacementSlotId::new("p1"),
                GenerationRef {
                    generation: GenerationId::new(format!("gen-{id}")),
                    assignment: PlacementSlotAssignment {
                        placement_slot: PlacementSlotId::new("p1"),
                        artifact: binding.clone(),
                    },
                },
            )]),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        }
    }

    fn gc_snapshot(
        index: u64,
        id: &str,
        target: &str,
        binding: &ArtifactRef,
    ) -> DeploymentSnapshot {
        DeploymentSnapshot {
            index,
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new(target.to_string()),
            behavior_sha256: "sha256-gc".to_string(),
            slots: BTreeMap::from([(
                PlacementSlotId::new("p1"),
                GenerationRef {
                    generation: GenerationId::new(format!("gen-{id}")),
                    assignment: PlacementSlotAssignment {
                        placement_slot: PlacementSlotId::new("p1"),
                        artifact: binding.clone(),
                    },
                },
            )]),
            bindings: BTreeMap::new(),
        }
    }

    fn gc_plan(target: &str, id: &str, binding: &ArtifactRef) -> DeploymentPlan {
        DeploymentPlan {
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new(target.to_string()),
            behavior_sha256: "sha256-gc".to_string(),
            behaviors: BTreeMap::new(),
            slot_ids: vec![PlacementSlotId::new("p1")],
            slots: BTreeMap::from([(
                PlacementSlotId::new("p1"),
                ServerPlan {
                    slot_id: PlacementSlotId::new("p1"),
                    artifact: binding.clone(),
                    expected_generation: None,
                    expected_tree: None,
                },
            )]),
            source: PlanSource::Head,
            desired_release: binding.release.clone(),
        }
    }

    /// The retained-set ORACLE, mirrored from the collector's sources via
    /// the floor-gated reads (the enforcement point): retained attempts +
    /// snapshots per floor, retained deployment plans (unfinished included),
    /// observed state, and pins. Returns (bindings, releases, trees).
    fn gc_oracle(
        store: &LocalStore,
        targets: &[&str],
    ) -> (
        BTreeSet<ArtifactRef>,
        BTreeSet<ReleaseId>,
        BTreeSet<TreeDigest>,
    ) {
        let mut bindings: BTreeSet<ArtifactRef> = BTreeSet::new();
        let mut releases: BTreeSet<ReleaseId> = BTreeSet::new();
        let mut trees: BTreeSet<TreeDigest> = BTreeSet::new();
        let mut retained_dirs: BTreeSet<String> = BTreeSet::new();
        let mut named_dirs: BTreeSet<String> = BTreeSet::new();
        for target in targets {
            for a in store.read_attempts(target).unwrap() {
                for g in a.desired.values() {
                    bindings.insert(g.assignment.artifact.clone());
                }
                retained_dirs.insert(a.deployment_id.as_str().to_string());
            }
            for a in store.read_attempts_raw(target).unwrap() {
                named_dirs.insert(a.deployment_id.as_str().to_string());
            }
            for s in store.read_snapshots(target).unwrap() {
                for g in s.slots.values() {
                    bindings.insert(g.assignment.artifact.clone());
                }
                retained_dirs.insert(s.deployment_id.as_str().to_string());
            }
            let observed = store.read_global_observed().unwrap();
            for slot in observed.values() {
                if let Some(a) = &slot.artifact {
                    bindings.insert(a.clone());
                }
            }
        }
        for entry in std::fs::read_dir(store.base().join("deployments"))
            .unwrap()
            .flatten()
        {
            let id = entry.file_name().to_string_lossy().into_owned();
            let retained_or_orphan = retained_dirs.contains(&id) || !named_dirs.contains(&id);
            if retained_or_orphan && let Ok(plan) = store.read_plan(&id) {
                for sp in plan.slots.values() {
                    bindings.insert(sp.artifact.clone());
                }
                releases.insert(plan.desired_release.clone());
                if let PlanSource::ReleaseRef(r) = &plan.source {
                    releases.insert(r.clone());
                }
            }
        }
        let pins = store.read_pins().unwrap();
        for rid in &pins.releases {
            releases.insert(rid.clone());
            let rec = store.read_release(rid).unwrap();
            for (variant, tree) in &rec.variants {
                bindings.insert(ArtifactRef {
                    release: rid.clone(),
                    variant: VariantName::new(variant.as_str()),
                    tree: TreeDigest::new(tree.as_str()),
                });
                trees.insert(TreeDigest::new(tree.as_str()));
            }
        }
        for b in &pins.bindings {
            bindings.insert(b.clone());
        }
        for b in &bindings {
            releases.insert(b.release.clone());
            trees.insert(b.tree.clone());
        }
        (bindings, releases, trees)
    }

    fn store_release_ids(store: &LocalStore) -> BTreeSet<ReleaseId> {
        let root = store.base().join(crate::layout::RELEASES);
        std::fs::read_dir(&root)
            .map(|rd| {
                rd.flatten()
                    .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                    .map(|e| ReleaseId::new(e.file_name().to_string_lossy().into_owned()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn store_tree_ids(store: &LocalStore) -> BTreeSet<TreeDigest> {
        let root = store.base().join(crate::layout::objects());
        std::fs::read_dir(&root)
            .map(|rd| {
                rd.flatten()
                    .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                    .map(|e| TreeDigest::new(e.file_name().to_string_lossy().into_owned()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Assert the ENTIRE retained-set + reclamation contract of one
    /// CONVERGED fixture. `case` supplies the expected visible history (the
    /// floors the runner established) for the pin-never-keeps-history
    /// invariant.
    fn assert_gc_converged(store: &LocalStore, case: &GcCase, floors: &[Option<(String, u64)>]) {
        let (bindings, releases, trees) = gc_oracle(store, &["t0", "t1"]);

        // 1. NO REACHABLE OR PINNED ARTIFACT IS EVER DELETED: every
        //    retained binding's release record + tree object exist.
        for b in &bindings {
            assert!(
                store.release_dir(&b.release).join("release.json").exists(),
                "reachable/pinned binding {}|{}|{} was deleted",
                b.release,
                b.variant,
                b.tree
            );
            assert!(
                store
                    .base()
                    .join(crate::layout::objects())
                    .join(b.tree.as_str())
                    .exists(),
                "reachable/pinned tree {} was deleted",
                b.tree
            );
        }
        for rid in &releases {
            assert!(
                store.release_dir(rid).join("release.json").exists(),
                "retained release record {rid} was deleted"
            );
        }
        for t in &trees {
            assert!(
                store
                    .base()
                    .join(crate::layout::objects())
                    .join(t.as_str())
                    .exists(),
                "retained tree object {t} was deleted"
            );
        }

        // 2. PINS NEVER KEEP PRE-FLOOR HISTORY VISIBLE: the visible history
        //    is EXACTLY the floored suffix (computed from the fixture data,
        //    INDEPENDENT of the pins) — a pin retains artifact content only
        //    and never reinserts a discarded attempt/snapshot.
        for (target, floor) in [("t0", &floors[0]), ("t1", &floors[1])] {
            let steps: &[GcStep] = if target == "t0" {
                &case.t0_steps
            } else {
                &case.t1_steps
            };
            let successes: Vec<usize> = steps
                .iter()
                .enumerate()
                .filter(|(_, s)| s.ok)
                .map(|(i, _)| i)
                .collect();
            let floor_step = match floor {
                Some((_id, ord)) => successes.get(*ord as usize).copied(),
                None => None,
            };
            let expected_attempts: Vec<String> = (floor_step.unwrap_or(0)..steps.len())
                .map(|i| format!("{target}-{i:03}"))
                .collect();
            let got_attempts: Vec<String> = store
                .read_attempts(target)
                .unwrap()
                .iter()
                .map(|a| a.deployment_id.as_str().to_string())
                .collect();
            assert_eq!(
                got_attempts, expected_attempts,
                "pins must never keep pre-floor attempts visible on {target}"
            );
            let expected_snaps: Vec<u64> = match floor {
                Some((_, ord)) => (*ord..successes.len() as u64).collect(),
                None => (0..successes.len() as u64).collect(),
            };
            let got_snaps: Vec<u64> = store
                .read_snapshots(target)
                .unwrap()
                .iter()
                .map(|s| s.index)
                .collect();
            assert_eq!(
                got_snaps, expected_snaps,
                "pins never keep pre-floor snapshots visible on {target}"
            );
            if let Some((_, ord)) = floor
                && *ord > 0
            {
                let err = history::resolve_ref_expr(
                    &history::parse_ref_expr(&format!("s{}", ord - 1)).unwrap(),
                    target,
                    store,
                )
                .unwrap_err();
                assert!(
                    err.to_string().contains("history floor")
                        || err.to_string().contains("no snapshot"),
                    "below-floor s{} stays refused on {target}, got: {err}",
                    ord - 1
                );
            }
        }

        // 3. ANOTHER TARGET'S REFERENCES PROTECT SHARED CONTENT: covered by
        //    assertion 1 (every retained binding from EVERY target survives)
        //    — a release/tree referenced by t1's retained history survives
        //    even when t0's floor discarded its own references to it.

        // 4/6. WITHOUT FAULTS (or after the converging retry), EVERY
        //      UNREACHABLE RELEASE/TREE IS REMOVED: the on-disk inventory
        //      equals the oracle EXACTLY.
        assert_eq!(
            store_release_ids(store),
            releases,
            "without faults, no unreachable release record may remain"
        );
        assert_eq!(
            store_tree_ids(store),
            trees,
            "without faults, no unreachable tree object may remain"
        );

        // The incomplete operation's deployment record stays retained (its
        // plan's artifacts are in the oracle above): when t0's last attempt
        // is incomplete and NOT below the floor, its dir survives.
        if case.incomplete && !case.t0_steps.is_empty() {
            let last_id = format!("t0-{:03}", case.t0_steps.len() - 1);
            let floor = &floors[0];
            let retained = match floor {
                Some((fid, _ord)) => {
                    // The incomplete op is retained iff it is at/above the
                    // floor's step.
                    let step_of = |id: &str| {
                        case.t0_steps
                            .iter()
                            .enumerate()
                            .find(|(n, _)| format!("t0-{n:03}") == id)
                            .map(|(i, _)| i)
                    };
                    let fstep = step_of(fid).unwrap();
                    let lstep = case.t0_steps.len() - 1;
                    lstep >= fstep
                }
                None => true,
            };
            if retained {
                assert!(
                    store.deployment_dir(&last_id).exists(),
                    "an unfinished operation at/above the floor is retained"
                );
            }
        }
    }

    /// One generated GC case body (see [`GcCase`]). Seeds the store, runs
    /// the checkpoints (with the optional injected GC fault on the first
    /// one), converges the fault retry, and asserts all eight invariants.
    fn run_gc_case(case: &GcCase) {
        let n_trees = case.n_trees.max(1);
        let n_rel = case.n_releases.max(1);
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();

        // ---- SHARED tree pool + unreachable spare content ---------------
        let trees: Vec<TreeDigest> = (0..n_trees)
            .map(|i| TreeDigest::new(format!("tree-gc-{i}")))
            .collect();
        for t in &trees {
            let root = store.object_root(t);
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(root.join("x"), b"x").unwrap();
        }
        // A spare tree object NO release or history ever references: the
        // baseline unreachable content that must be reclaimed (invariant 4).
        let spare_tree = TreeDigest::new("tree-gc-spare");
        std::fs::create_dir_all(store.object_root(&spare_tree)).unwrap();
        std::fs::write(store.object_root(&spare_tree).join("x"), b"x").unwrap();

        // ---- releases (trees SHARED across releases) --------------------
        let mut releases: Vec<ReleaseId> = Vec::new();
        for i in 0..n_rel {
            let v0 = trees[(2 * i) % n_trees].clone();
            let v1 = trees[(2 * i + 1) % n_trees].clone();
            let variants = BTreeMap::from([
                (VariantName::new("v0"), v0.clone()),
                (VariantName::new("v1"), v1.clone()),
            ]);
            let slots: BTreeMap<String, Vec<crate::config::SlotDef>> = variants
                .keys()
                .map(|v| {
                    (
                        v.as_str().to_string(),
                        vec![crate::config::SlotDef {
                            id: format!("p1-{}", v.as_str()),
                            server: "s1".to_string(),
                            deploy_dir: Path::new("/srv/deploy/p1").to_path_buf(),
                            targets: vec!["t1".to_string()],
                        }],
                    )
                })
                .collect();
            let rec = crate::release::build_release(
                &format!("map-gc-{i}"),
                &format!("bh-gc-{i}"),
                &variants,
                &slots,
                Path::new("."),
            );
            let id = ReleaseId::new(rec.release_id.clone());
            store.write_release(&rec).unwrap();
            releases.push(id);
        }
        // A spare RELEASE record (with its own unique tree) no binding ever
        // references: unreachable from the start (invariant 4).
        let spare_variants =
            BTreeMap::from([(VariantName::new("v0"), TreeDigest::new("tree-gc-spare2"))]);
        let spare_slots: BTreeMap<String, Vec<crate::config::SlotDef>> = BTreeMap::from([(
            "v0".to_string(),
            vec![crate::config::SlotDef {
                id: "p1-v0".to_string(),
                server: "s1".to_string(),
                deploy_dir: Path::new("/srv/deploy/p1").to_path_buf(),
                targets: vec!["t1".to_string()],
            }],
        )]);
        let spare_rec = crate::release::build_release(
            "map-gc-spare",
            "bh-gc-spare",
            &spare_variants,
            &spare_slots,
            Path::new("."),
        );
        store.write_release(&spare_rec).unwrap();
        let spare_tree2 = TreeDigest::new("tree-gc-spare2");
        std::fs::create_dir_all(store.object_root(&spare_tree2)).unwrap();
        std::fs::write(store.object_root(&spare_tree2).join("x"), b"x").unwrap();

        let variant_tree =
            |rel: usize, variant: usize| trees[(2 * (rel % n_rel) + variant) % n_trees].clone();

        // ---- pins --------------------------------------------------------
        let mut pins = Pins {
            schema_version: crate::model::PINS_SCHEMA_VERSION,
            releases: Vec::new(),
            bindings: Vec::new(),
        };
        if let Some(p) = case.pin_release {
            let rid = releases[p % n_rel].clone();
            pins.releases.push(rid.clone());
            if case.pin_binding {
                pins.bindings.push(gc_binding(&rid, 0, &variant_tree(p, 0)));
            }
        }
        store.write_pins(&pins).unwrap();

        // ---- seed the two targets ----------------------------------------
        let seed = |target: &str,
                    steps: &[GcStep],
                    incomplete: bool|
         -> Vec<(String, bool, ArtifactRef)> {
            let mut facts: Vec<(String, bool, ArtifactRef)> = Vec::new();
            let mut next_index = 0u64;
            let mut last_success: Option<ArtifactRef> = None;
            for (n, s) in steps.iter().enumerate() {
                let id = format!("{target}-{n:03}");
                let binding = gc_binding(
                    &releases[s.rel % n_rel],
                    s.variant,
                    &variant_tree(s.rel, s.variant),
                );
                store
                    .append_attempt(target, &gc_attempt(target, &id, &binding))
                    .unwrap();
                std::fs::create_dir_all(store.deployment_dir(&id)).unwrap();
                store
                    .write_plan(&id, &gc_plan(target, &id, &binding))
                    .unwrap();
                store
                    .append_transition(&id, &DeploymentStatus::InProgress, None)
                    .unwrap();
                let is_last = n + 1 == steps.len();
                if s.ok {
                    store
                        .append_snapshot(target, &gc_snapshot(next_index, &id, target, &binding))
                        .unwrap();
                    next_index += 1;
                    if !(incomplete && is_last) {
                        store
                            .append_transition(&id, &DeploymentStatus::Successful, None)
                            .unwrap();
                    }
                    last_success = Some(binding.clone());
                } else if !(incomplete && is_last) {
                    store
                        .append_transition(&id, &DeploymentStatus::FailedRolledBack, None)
                        .unwrap();
                }
                facts.push((id, s.ok, binding));
            }
            store
                .write_slot_observed(
                    &PlacementSlotId::new("p1"),
                    &ObservedServer {
                        generation: None,
                        artifact: last_success,
                        last_deployment: None,
                    },
                )
                .unwrap();
            facts
        };
        let f0 = seed("t0", &case.t0_steps, case.incomplete);
        let f1 = seed("t1", &case.t1_steps, false);

        let s0: Vec<String> = f0.iter().filter(|f| f.1).map(|f| f.0.clone()).collect();
        let s1: Vec<String> = f1.iter().filter(|f| f.1).map(|f| f.0.clone()).collect();

        // The floors the runner establishes, per target: (deployment id,
        // snapshot ordinal).
        let mut floor0: Option<(String, u64)> = None;
        let mut floor1: Option<(String, u64)> = None;
        let mut fault_armed = case.fault != 0;
        let mut ran_any_checkpoint = false;
        let mut last_ck: Option<(String, String)> = None;

        // t0's checkpoint (the first GC trigger).
        if !s0.is_empty() {
            let pos = case.t0_ck % s0.len();
            let id = s0[pos].clone();
            if fault_armed {
                match case.fault {
                    1 => store.fault_registry().arm_gc_scan(&id),
                    2 => store.fault_registry().arm_gc_delete_releases(&id),
                    _ => store.fault_registry().arm_gc_delete_trees(&id),
                }
            }
            let rep = run_checkpoint(&store, "t0", &DeploymentId::new(id.clone()), false).expect(
                "the checkpoint commits (post-commit GC failure is committed-with-warning)",
            );
            assert!(rep.established, "t0's checkpoint establishes the floor");
            floor0 = Some((id.clone(), pos as u64));
            ran_any_checkpoint = true;
            last_ck = Some(("t0".to_string(), id.clone()));
            if fault_armed {
                fault_armed = false;
                // 5. WITH FAULTS, EXTRA GARBAGE MAY REMAIN but required
                // content never disappears: the GC failure is surfaced as
                // cleanup_pending (never an Err), the floor stands, and
                // nothing was deleted (the spare tree is still on disk).
                assert!(
                    rep.cleanup_pending,
                    "the injected GC fault is surfaced as cleanup_pending"
                );
                assert!(!rep.gc.completed, "the faulted GC did not complete");
                // The floor stands: it never moved and the visible history
                // is already the floored suffix.
                assert_eq!(
                    store
                        .read_history_floor("t0")
                        .unwrap()
                        .unwrap()
                        .deployment_id
                        .as_str(),
                    id
                );
                assert!(
                    store.object_root(&spare_tree).join("x").exists(),
                    "with a fault, extra garbage may remain — nothing was deleted"
                );
                // 6. REPEATING CLEANUP CONVERGES: the one-shot fault is
                // disarmed, so re-running the SAME checkpoint recomputes
                // reachability fresh and finishes the reclamation.
                let retry = run_checkpoint(&store, "t0", &DeploymentId::new(id.clone()), false)
                    .expect("the retry converges");
                assert!(
                    !retry.cleanup_pending && retry.gc.completed,
                    "repeating the same checkpoint after a GC fault converges"
                );
            }
            // 8. ADVANCING one target never truncates another target's
            // history: capture t1's local state, advance t0 to a strictly
            // later success, and assert t1 is byte-for-byte untouched.
            if case.advance && pos + 1 < s0.len() {
                let id2 = s0[pos + 1].clone();
                let t1_before_attempts = store.read_attempts_raw("t1").unwrap().len();
                let t1_before_snaps = store.read_snapshots_raw("t1").unwrap().len();
                let t1_before_dirs: Vec<String> = f1
                    .iter()
                    .map(|(id, _, _)| id.clone())
                    .filter(|id| store.deployment_dir(id).exists())
                    .collect();
                let t1_before_releases = store_release_ids(&store);
                let rep2 = run_checkpoint(&store, "t0", &DeploymentId::new(id2.clone()), false)
                    .expect("the advancement to a later deployment commits");
                assert!(
                    rep2.established,
                    "the t0 advance establishes the later floor"
                );
                floor0 = Some((id2.clone(), pos as u64 + 1));
                last_ck = Some(("t0".to_string(), id2));
                assert_eq!(
                    store.read_attempts_raw("t1").unwrap().len(),
                    t1_before_attempts,
                    "advancing t0 never truncates t1's attempts"
                );
                assert_eq!(
                    store.read_snapshots_raw("t1").unwrap().len(),
                    t1_before_snaps,
                    "advancing t0 never truncates t1's snapshots"
                );
                for id in t1_before_dirs {
                    assert!(
                        store.deployment_dir(&id).exists(),
                        "advancing t0 never deletes t1's deployment dir {id}"
                    );
                }
                // t1's retained ARTIFACT content survives t0's advance + GC
                // (shared-content protection across targets).
                let after = store_release_ids(&store);
                for rid in &t1_before_releases {
                    if gc_oracle(&store, &["t1"]).1.contains(rid) {
                        assert!(
                            after.contains(rid),
                            "advancing t0 must not delete t1's retained release {rid}"
                        );
                    }
                }
            }
        }

        // t1's checkpoint (if any).
        if let (Some(ck), false) = (&case.t1_ck, s1.is_empty()) {
            let pos = ck % s1.len();
            let id = s1[pos].clone();
            let rep = run_checkpoint(&store, "t1", &DeploymentId::new(id.clone()), false)
                .expect("t1's checkpoint commits");
            assert!(rep.established, "t1's checkpoint establishes the floor");
            assert!(
                !rep.cleanup_pending && rep.gc.completed,
                "t1's post-commit pass converges"
            );
            floor1 = Some((id.clone(), pos as u64));
            ran_any_checkpoint = true;
            last_ck = Some(("t1".to_string(), id));
        }

        // When NOTHING could run a checkpoint (both targets have no
        // successful deployment), drive the GC directly so the reclamation
        // invariants still hold (the fault, if any, is injected the same
        // way — one-shot, keyed by an anchor, converged by the retry).
        if !ran_any_checkpoint {
            if fault_armed {
                match case.fault {
                    1 => store.fault_registry().arm_gc_scan("fault-direct"),
                    2 => store
                        .fault_registry()
                        .arm_gc_delete_releases("fault-direct"),
                    _ => store.fault_registry().arm_gc_delete_trees("fault-direct"),
                }
                let err = store
                    .gc_artifacts("fault-direct")
                    .expect_err("the injected GC fault aborts the pass");
                assert!(
                    err.to_string().contains("test fault"),
                    "the injected GC fault aborts, got: {err}"
                );
                assert!(
                    store.object_root(&spare_tree).join("x").exists(),
                    "with faults, extra garbage may remain"
                );
                let out = store
                    .gc_artifacts("fault-direct")
                    .expect("the retry recomputes reachability and converges");
                assert!(out.completed, "the retried pass completes");
            } else {
                store
                    .gc_artifacts("test-direct")
                    .expect("the direct pass converges");
            }
        }

        // The CONVERGED state: assert the retained/reclaimed contract and
        // the visible history (invariants 1-4, 6).
        let floors0 = [floor0.clone(), floor1.clone()];
        assert_gc_converged(&store, case, &floors0);

        // 7. REPEATING A COMPLETED CHECKPOINT IS IDEMPOTENT: re-running
        // the last checkpoint reports a no-op, leaves the durable floor
        // untouched, and deletes nothing new (the re-run's own GC finds the
        // same retained set).
        if let Some((t, id)) = &last_ck {
            let floor_before = store.read_history_floor(t).unwrap();
            let releases_before = store_release_ids(&store);
            let trees_before = store_tree_ids(&store);
            let rep = run_checkpoint(&store, t, &DeploymentId::new(id.clone()), false)
                .expect("repeating a completed checkpoint succeeds");
            assert!(
                !rep.established,
                "repeating a completed checkpoint is an idempotent no-op"
            );
            assert!(
                !rep.cleanup_pending && rep.gc.completed,
                "the idempotent repeat stays converged"
            );
            assert_eq!(
                store.read_history_floor(t).unwrap(),
                floor_before,
                "the durable floor is untouched by the repeat"
            );
            assert_eq!(
                store_release_ids(&store),
                releases_before,
                "the idempotent repeat deletes no release record"
            );
            assert_eq!(
                store_tree_ids(&store),
                trees_before,
                "the idempotent repeat deletes no tree object"
            );
        }
    }

    proptest! {
        // THE GC PROPERTY FAMILY: over generated (targets, per-target
        // histories, SHARED releases, SHARED trees, pins, incomplete
        // operations, injected GC faults), asserting all eight invariants —
        // no reachable/pinned artifact ever deleted; a pin never keeps
        // pre-floor history visible; another target's references protect
        // shared content; without faults every unreachable release/tree is
        // removed; with faults extra garbage may remain but required
        // content never disappears; repeating cleanup converges; repeating a
        // completed checkpoint is idempotent; advancing one target never
        // truncates another target's history. Fixed seed 0x5EED_5EED +
        // bounded cases — the same vectors run on every invocation.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn artifact_gc_properties(case in gc_case_strategy()) {
            run_gc_case(&case);
        }
    }
    /// A minimal hand-built release with variants `{v0: v0_tree, v1:
    /// v1_tree}` — a valid, content-verified record. The caller creates the
    /// object dirs for the trees itself.
    fn gc_simple_release(
        store: &LocalStore,
        label: &str,
        v0_tree: &TreeDigest,
        v1_tree: &TreeDigest,
    ) -> ReleaseId {
        let variants = BTreeMap::from([
            (VariantName::new("v0"), v0_tree.clone()),
            (VariantName::new("v1"), v1_tree.clone()),
        ]);
        let slots: BTreeMap<String, Vec<crate::config::SlotDef>> = variants
            .keys()
            .map(|v| {
                (
                    v.as_str().to_string(),
                    vec![crate::config::SlotDef {
                        id: format!("p1-{}", v.as_str()),
                        server: "s1".to_string(),
                        deploy_dir: Path::new("/srv/deploy/p1").to_path_buf(),
                        targets: vec!["t1".to_string()],
                    }],
                )
            })
            .collect();
        let rec = crate::release::build_release(
            &format!("map-gc-{label}"),
            &format!("bh-gc-{label}"),
            &variants,
            &slots,
            Path::new("."),
        );
        let id = ReleaseId::new(rec.release_id.clone());
        store.write_release(&rec).unwrap();
        id
    }

    /// Seed one attempt on `target` (attempt + deployment dir + plan +
    /// snapshot on success + transitions), tracking the target's snapshot
    /// index counter and the observed artifact (`observed` is set to the
    /// LAST SUCCESSFUL binding — the fixture's observed state).
    fn gc_seed_attempt(
        store: &LocalStore,
        target: &str,
        id: &str,
        ok: bool,
        binding: &ArtifactRef,
        next_index: &mut u64,
        observed: &mut Option<ArtifactRef>,
    ) {
        store
            .append_attempt(target, &gc_attempt(target, id, binding))
            .unwrap();
        std::fs::create_dir_all(store.deployment_dir(id)).unwrap();
        store.write_plan(id, &gc_plan(target, id, binding)).unwrap();
        store
            .append_transition(id, &DeploymentStatus::InProgress, None)
            .unwrap();
        if ok {
            store
                .append_snapshot(target, &gc_snapshot(*next_index, id, target, binding))
                .unwrap();
            *next_index += 1;
            store
                .append_transition(id, &DeploymentStatus::Successful, None)
                .unwrap();
            *observed = Some(binding.clone());
        } else {
            store
                .append_transition(id, &DeploymentStatus::FailedRolledBack, None)
                .unwrap();
        }
    }

    /// Write a target's observed.json from the tracked `observed` artifact.
    fn gc_write_observed(store: &LocalStore, _target: &str, observed: &Option<ArtifactRef>) {
        store
            .write_slot_observed(
                &PlacementSlotId::new("p1"),
                    &ObservedServer {
                    generation: None,
                    artifact: observed.clone(),
                    last_deployment: None,
                },
            )
            .unwrap();
    }

    /// INVARIANT 2 (deterministic): a PIN retains artifact content ONLY. A
    /// whole-release pin on a release whose ONLY history reference is below
    /// the new floor keeps the release record and EVERY variant tree — but
    /// the pre-floor attempt/snapshot STAYS discarded: the floor-gated reads
    /// expose only the suffix, the below-floor ref stays refused, and the
    /// pin never reinserts or resurrects history.
    #[test]
    fn gc_pin_never_keeps_prefloor_history_visible() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        // Trees T0,T1,T2; R0 {v0:T0, v1:T1}; R1 {v0:T1, v1:T2}.
        let trees = [
            TreeDigest::new("t0".to_string()),
            TreeDigest::new("t1".to_string()),
            TreeDigest::new("t2".to_string()),
        ];
        for t in &trees {
            let root = store.object_root(t);
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(root.join("x"), b"x").unwrap();
        }
        let r0 = gc_simple_release(&store, "0", &trees[0], &trees[1]);
        let r1 = gc_simple_release(&store, "1", &trees[1], &trees[2]);
        // t0 history: attempt t0-00 = R1/v1 (T2) → s0; attempt t0-01 =
        // R0/v0 (T0) → s1. Checkpoint at s1: R1's ONLY reference (t0-00)
        // lies BELOW the floor and is discarded.
        let mut next = 0u64;
        let mut observed: Option<ArtifactRef> = None;
        gc_seed_attempt(
            &store,
            "t0",
            "t0-00",
            true,
            &gc_binding(&r1, 1, &trees[2]),
            &mut next,
            &mut observed,
        );
        gc_seed_attempt(
            &store,
            "t0",
            "t0-01",
            true,
            &gc_binding(&r0, 0, &trees[0]),
            &mut next,
            &mut observed,
        );
        gc_write_observed(&store, "t0", &observed);
        // PIN R1: its record and EVERY variant tree (T1, T2) must survive
        // the GC even though its only history reference is discarded.
        store
            .write_pins(&Pins {
                schema_version: crate::model::PINS_SCHEMA_VERSION,
                releases: vec![r1.clone()],
                bindings: Vec::new(),
            })
            .unwrap();

        let rep = run_checkpoint(&store, "t0", &DeploymentId::new("t0-01".to_string()), false)
            .expect("the checkpoint commits");
        assert!(rep.established);
        assert!(
            !rep.cleanup_pending && rep.gc.completed,
            "the pass converges"
        );

        // HISTORY: only the suffix (s1) is visible; s0 refuses; the pinned
        // pre-floor deployment is gone from the raw logs too (the pin never
        // resurrects it).
        let snaps = store.read_snapshots("t0").unwrap();
        assert_eq!(
            snaps.iter().map(|s| s.index).collect::<Vec<_>>(),
            vec![1],
            "only the checkpoint snapshot stays visible"
        );
        assert_eq!(
            store.read_attempts("t0").unwrap()[0].deployment_id.as_str(),
            "t0-01",
            "the visible attempts start at the checkpoint attempt"
        );
        let err = history::resolve_ref_expr(&history::parse_ref_expr("s0").unwrap(), "t0", &store)
            .unwrap_err();
        assert!(
            err.to_string().contains("history floor"),
            "below-floor s0 stays refused even though a pin names its release, got: {err}"
        );
        assert!(
            !store.deployment_dir("t0-00").exists(),
            "the below-floor deployment dir is deleted despite the pin"
        );
        let raw = store.read_attempts_raw("t0").unwrap();
        assert!(
            !raw.iter().any(|a| a.deployment_id.as_str() == "t0-00"),
            "the pinned release never reinserts the below-floor attempt"
        );
        // CONTENT: the pinned release record + every variant tree survive.
        assert!(store.release_dir(&r1).join("release.json").exists());
        for t in [&trees[1], &trees[2]] {
            assert!(
                store
                    .base()
                    .join(crate::layout::objects())
                    .join(t.as_str())
                    .exists(),
                "a release pin retains every variant tree, got {t} missing"
            );
        }
        // The release record R0 (retained via the floor attempt's binding)
        // survives; T0 survives (its binding is retained).
        assert!(store.release_dir(&r0).join("release.json").exists());
        assert!(
            store
                .base()
                .join(crate::layout::objects())
                .join("t0")
                .exists()
        );
    }

    /// INVARIANT 3 (deterministic): another target's references protect
    /// SHARED content. t0's checkpoint discards its own references to R1
    /// and its tree; t1's (floor-less, fully retained) history references
    /// R1/T2, so R1 and T2 survive the global GC. A release referenced by
    /// NOBODY (R2) and the tree nobody binds (T1 — only named by release
    /// variant maps, never by a binding or pin) are reclaimed.
    #[test]
    fn gc_shared_content_protected_across_targets() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let trees = [
            TreeDigest::new("t0".to_string()),
            TreeDigest::new("t1".to_string()),
            TreeDigest::new("t2".to_string()),
        ];
        for t in &trees {
            let root = store.object_root(t);
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(root.join("x"), b"x").unwrap();
        }
        // R0 {v0:T0, v1:T1}; R1 {v0:T1, v1:T2}; R2 {v0:T0, v1:T2} (never
        // referenced by any history).
        let r0 = gc_simple_release(&store, "0", &trees[0], &trees[1]);
        let r1 = gc_simple_release(&store, "1", &trees[1], &trees[2]);
        let r2 = gc_simple_release(&store, "2", &trees[0], &trees[2]);
        // t0: [ok R1/v1 (s0), ok R0/v0 (s1)] — checkpoint at s1 discards the
        // R1 reference. t1: [ok R1/v1] — full history (no floor) retains it.
        let mut next0 = 0u64;
        let mut obs0: Option<ArtifactRef> = None;
        gc_seed_attempt(
            &store,
            "t0",
            "t0-00",
            true,
            &gc_binding(&r1, 1, &trees[2]),
            &mut next0,
            &mut obs0,
        );
        gc_seed_attempt(
            &store,
            "t0",
            "t0-01",
            true,
            &gc_binding(&r0, 0, &trees[0]),
            &mut next0,
            &mut obs0,
        );
        gc_write_observed(&store, "t0", &obs0);
        let mut next1 = 0u64;
        let mut obs1: Option<ArtifactRef> = None;
        gc_seed_attempt(
            &store,
            "t1",
            "t1-00",
            true,
            &gc_binding(&r1, 1, &trees[2]),
            &mut next1,
            &mut obs1,
        );
        gc_write_observed(&store, "t1", &obs1);

        let rep = run_checkpoint(&store, "t0", &DeploymentId::new("t0-01".to_string()), false)
            .expect("the checkpoint commits");
        assert!(rep.established && !rep.cleanup_pending && rep.gc.completed);

        // R1 + T2 survive (t1 references them); R2 (referenced by nobody)
        // and T1 (bound by no retained binding — only release maps) are
        // reclaimed; R0 + T0 survive (t0's floor attempt references them).
        assert!(store.release_dir(&r0).join("release.json").exists());
        assert!(
            store.release_dir(&r1).join("release.json").exists(),
            "t1's references protect shared release R1"
        );
        assert!(
            !store.release_dir(&r2).join("release.json").exists(),
            "R2 is unreachable and reclaimed"
        );
        for (t, present) in [(&trees[0], true), (&trees[1], false), (&trees[2], true)] {
            let exists = store
                .base()
                .join(crate::layout::objects())
                .join(t.as_str())
                .exists();
            assert_eq!(
                exists,
                present,
                "tree {} must {} after the GC",
                t,
                if present { "survive" } else { "be reclaimed" }
            );
        }
        // t1's history is untouched (no floor on t1).
        assert!(store.read_history_floor("t1").unwrap().is_none());
        assert_eq!(store.read_snapshots("t1").unwrap().len(), 1);
    }

    /// INVARIANTS 5 + 6 (deterministic, exhaustive over the three GC fault
    /// kinds): with a fault, the GC aborts fail-closed — the checkpoint
    /// reports cleanup_pending (never an Err), the floor stands, NOTHING
    /// required is deleted, and the unreachable spare content REMAINS
    /// (extra garbage). Repeating the SAME checkpoint (the one-shot fault
    /// disarmed) recomputes reachability fresh and CONVERGES: the spare
    /// content is reclaimed and the required content is untouched.
    #[test]
    fn every_gc_fault_keeps_required_content_and_retry_converges_exhaustively() {
        for fault in [1u8, 2, 3] {
            let tmp = tempfile::tempdir().unwrap();
            let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
            let trees = [
                TreeDigest::new("t0".to_string()),
                TreeDigest::new("t1".to_string()),
            ];
            for t in &trees {
                let root = store.object_root(t);
                std::fs::create_dir_all(&root).unwrap();
                std::fs::write(root.join("x"), b"x").unwrap();
            }
            // Spare tree: unreachable from the start.
            let spare = TreeDigest::new("spare".to_string());
            std::fs::create_dir_all(store.object_root(&spare)).unwrap();
            std::fs::write(store.object_root(&spare).join("x"), b"x").unwrap();
            let r0 = gc_simple_release(&store, "0", &trees[0], &trees[1]);
            // t0: [ok R0/v0 (s0), ok R0/v0 (s1)] — checkpoint at s1; the
            // RETAINED content is R0 + T0 (the floor attempt's binding).
            let mut next = 0u64;
            let mut obs: Option<ArtifactRef> = None;
            gc_seed_attempt(
                &store,
                "t0",
                "t0-00",
                true,
                &gc_binding(&r0, 0, &trees[0]),
                &mut next,
                &mut obs,
            );
            gc_seed_attempt(
                &store,
                "t0",
                "t0-01",
                true,
                &gc_binding(&r0, 0, &trees[0]),
                &mut next,
                &mut obs,
            );
            gc_write_observed(&store, "t0", &obs);

            match fault {
                1 => store.fault_registry().arm_gc_scan("t0-01"),
                2 => store.fault_registry().arm_gc_delete_releases("t0-01"),
                _ => store.fault_registry().arm_gc_delete_trees("t0-01"),
            }
            let rep = run_checkpoint(&store, "t0", &DeploymentId::new("t0-01".to_string()), false)
                .expect("a post-commit GC fault is committed-with-warning, never an Err");
            assert!(rep.established, "the floor stands through the fault");
            assert!(
                rep.cleanup_pending && !rep.gc.completed,
                "fault {fault}: the GC failure is surfaced as cleanup_pending"
            );
            // REQUIRED content never disappears.
            assert!(store.release_dir(&r0).join("release.json").exists());
            assert!(
                store
                    .base()
                    .join(crate::layout::objects())
                    .join("t0")
                    .exists()
            );
            // EXTRA garbage may remain (nothing was deleted).
            assert!(
                store.object_root(&spare).join("x").exists(),
                "fault {fault}: extra garbage may remain — the spare tree is untouched"
            );
            // The visible history is already the floored suffix (the floor
            // is the enforcement point even mid-GC-failure).
            assert_eq!(store.read_snapshots("t0").unwrap().len(), 1);
            assert_eq!(store.read_snapshots_raw("t0").unwrap().len(), 1);

            // RETRY: the one-shot fault is disarmed; the same checkpoint
            // recomputes reachability fresh and converges.
            let retry =
                run_checkpoint(&store, "t0", &DeploymentId::new("t0-01".to_string()), false)
                    .expect("the retry converges");
            assert!(
                !retry.cleanup_pending && retry.gc.completed,
                "fault {fault}: the repeated checkpoint converges"
            );
            assert!(
                !store.object_root(&spare).exists(),
                "fault {fault}: the converged retry reclaims the spare tree"
            );
            assert!(store.release_dir(&r0).join("release.json").exists());
            assert!(
                store
                    .base()
                    .join(crate::layout::objects())
                    .join("t0")
                    .exists()
            );
        }
    }

    /// INVARIANTS 7 + 8 (deterministic): repeating a completed checkpoint is
    /// idempotent (no-op, floor untouched, no new deletions) and advancing
    /// one target never truncates the other target's history or artifact
    /// content. Both are asserted inside [`run_gc_case`] too; these fixed
    /// scenarios guarantee the flags always exercise them.
    #[test]
    fn gc_idempotent_repeat_and_advance_deterministic() {
        // A two-success, two-target case with a SHARED release, an advance
        // on t0, and no faults: exercises convergence + idempotency (the
        // final repeat) + cross-target protection (the advance).
        run_gc_case(&GcCase {
            n_trees: 2,
            n_releases: 2,
            t0_steps: vec![
                GcStep {
                    ok: true,
                    rel: 0,
                    variant: 0,
                },
                GcStep {
                    ok: true,
                    rel: 1,
                    variant: 1,
                },
                GcStep {
                    ok: true,
                    rel: 0,
                    variant: 1,
                },
            ],
            t1_steps: vec![
                GcStep {
                    ok: true,
                    rel: 1,
                    variant: 1,
                },
                GcStep {
                    ok: true,
                    rel: 1,
                    variant: 0,
                },
            ],
            t0_ck: 0,
            t1_ck: None,
            pin_release: None,
            pin_binding: false,
            incomplete: true,
            fault: 0,
            advance: true,
        });
        // A fault case with BOTH targets checkpointed: the faulted retry
        // converges, t1's checkpoint converges, and the final repeat (of
        // t1) is idempotent.
        run_gc_case(&GcCase {
            n_trees: 3,
            n_releases: 2,
            t0_steps: vec![
                GcStep {
                    ok: true,
                    rel: 0,
                    variant: 1,
                },
                GcStep {
                    ok: false,
                    rel: 1,
                    variant: 0,
                },
                GcStep {
                    ok: true,
                    rel: 1,
                    variant: 1,
                },
            ],
            t1_steps: vec![GcStep {
                ok: true,
                rel: 0,
                variant: 0,
            }],
            t0_ck: 2,
            t1_ck: Some(0),
            pin_release: Some(1),
            pin_binding: true,
            incomplete: false,
            fault: 3,
            advance: false,
        });
    }
}
