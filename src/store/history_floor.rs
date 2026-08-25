//! Checkpoint persistence: the store side of the history floor.
//!
//! The rollback history is the append-only OP LOG (`refs/snapshots.jsonl` +
//! `refs/last-successful`) — the term is "op log", never "reflog". A
//! checkpoint (`deploy checkpoint <target> <deployment-id>`) establishes a
//! monotonic HISTORY FLOOR (`refs/history-floor.json`, see
//! [`crate::records::HistoryFloor`]) for a target: the floor marker is
//! written FIRST, durably and FAIL-CLOSED (private temp → fsync → rename →
//! parent-dir fsync with errors propagated — any stage failure leaves NO
//! floor on a first-ever checkpoint; ADVANCING an existing floor A to a
//! later deployment B is TRANSACTIONAL — A is moved aside to a durable
//! backup (`history-floor.json.prev.<B-id>`, TAGGED by the advance target,
//! so a stale backup from another transaction is a different file) and
//! restored if B fails before its
//! commit point, so a failed advancement never erases the previously
//! durable floor, see [`LocalStore::write_history_floor`]), then physical
//! compaction rewrites the jsonl logs to the suffix at/after the floor and
//! deletes `deployments/<id>/` dirs strictly before it. EVERY read path in
//! this module is gated by the floor ([`LocalStore::read_attempts`],
//! [`LocalStore::read_snapshots`]), so an interrupted compaction never
//! exposes history below the durable floor;
//! the raw readers ([`LocalStore::read_attempts_raw`],
//! [`LocalStore::read_snapshots_raw`]) are the internal index-minting view
//! (never a below-floor escape hatch — index allocation uses them so
//! compaction can never reuse an index).
//!
//! The floor marker is the checkpoint's COMMIT POINT: once it is durable
//! the checkpoint took effect, so a failure of any LATER phase is
//! post-commit maintenance — it records the durable
//! `refs/cleanup-pending.json` debt FLAG
//! ([`crate::records::CleanupPending`], via
//! [`LocalStore::write_cleanup_pending`]) and the command reports SUCCESS
//! with a warning instead of an `Err`; the next same-deployment checkpoint
//! retries the cleanup until it completes (then clears the marker). The
//! marker is a flag ONLY — it never records a deletion worklist: the
//! delete-before-rewrite compaction order keeps the below-floor worklist in
//! the raw logs until deletion finishes, so a retry recomputes the exact
//! delete set from the logs via
//! [`LocalStore::checkpoint_discards`] and converges regardless of the
//! marker.
//!
//! The marker is INTEGRITY-BOUND at read time ([`LocalStore::read_history_floor`]):
//! it must name the target it was read from AND an exact snapshot-pair
//! target's logs — any violation fails closed with an integrity error, so a
//! corrupted or tampered marker is never silently treated as "no floor"
//! (which would expose the below-floor prefix).
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
//! Because the floor is durable-before-delete and EVERY read path is gated
//! by it ([`LocalStore::read_attempts`], [`LocalStore::read_snapshots`],
//! and ref resolution in [`crate::history::resolve_ref_expr`]), an
//! interrupted compaction leaves either the old physical files or the
//! compacted files — never visible history below the durable floor. The
//! floor is the ENFORCEMENT point; the physical cleanup is best-effort.
//! The deletion runs BEFORE the log rewrites so its worklist stays
//! re-derivable from the logs: a retry after an interruption recomputes
//! the same discard set from the still-intact (or already-rewritten) logs
//! and converges — the deletion worklist is never lost to an interrupted
//! rewrite.
//!
//! # The failure model: the floor write is the commit point
//!
//! A failure propagates as `Err` ONLY from the floor-marker write (the
//! commit point): a failed marker write leaves the PREVIOUS state — no
//! floor on a first-ever checkpoint; on an ADVANCE the replacement is
//! TRANSACTIONAL ([`LocalStore::write_history_floor`]): the backup slot is
//! RECONCILED first (leftover `history-floor.json.prev*` backups of other
//! transactions are durably removed), B's marker is staged, the current
//! floor A is moved aside to a durable backup
//! (`history-floor.json.prev.<B-id>`, tagged by the advance target), B is
//! renamed into place, and the parent-directory fsync is B's durability
//! commit point. A failure at ANY stage after A was moved aside — an
//! injected fault or a REAL filesystem error alike, INCLUDING a real
//! B-temp→marker rename failure — routes through ONE cleanup-and-restore
//! handler ([`LocalStore::cleanup_and_restore`]): A is renamed back from
//! THIS transaction's tagged backup — verified to carry the tag AND to
//! parse and equal the pre-advance floor A, so a stale backup from another
//! transaction can never roll the floor backward — B's temp artifact is
//! removed, and the ORIGINAL error propagates, so a failed advancement
//! leaves EXACTLY the pre-advance state (floor A durable, the same visible
//! suffix, no compaction side effects, no temporary transaction files) —
//! advancing a checkpoint can never erase the previously durable floor, not
//! even when the actual temp→marker rename fails after A was backed up. If
//! the restore of A itself ALSO fails, the marker may be left absent while
//! the tagged backup (`history-floor.json.prev.<B-id>`) holds A — a TORN
//! ADVANCE. The reader NEVER treats this as "no floor" (which would expose
//! the below-floor prefix): it VALIDATES the durable backup against the
//! SAME integrity binding as the marker and treats a valid backup as the
//! ACTIVE floor (reads see A), failing closed only when the backup itself
//! fails validation. RECOVERY is the ATOMIC RESTORE of the backup — rename
//! the tagged backup back over the marker name + parent-dir fsync
//! ([`LocalStore::recover_history_floor_backup`]): the backup is the ONLY
//! valid floor in a torn state and is NEVER deleted (deleting it would
//! erase the floor and re-expose discarded history) — and every subsequent
//! ADVANCE reconciles leftover backups automatically before it starts.
//!
//! EVERY failure AFTER the marker write — enumerating the discards or any
//! compaction phase — is POST-COMMIT MAINTENANCE: the checkpoint already
//! took effect, so the durable [`crate::records::CleanupPending`] debt
//! flag (`targets/<target>/refs/cleanup-pending.json`,
//! [`LocalStore::write_cleanup_pending`]) records the pending cleanup and
//! the command reports SUCCESS with a warning, NEVER an `Err`. The marker
//! is a flag ONLY — it never carries a deletion worklist: the compaction
//! deletes below-floor dirs BEFORE rewriting the logs, so the raw logs
//! retain the worklist whenever a deletion fails and the retry recomputes
//! the exact delete set from them via [`LocalStore::checkpoint_discards`].
//! The next checkpoint of the SAME deployment retries the cleanup; once it
//! completes, the debt marker clears ([`LocalStore::clear_cleanup_pending`]).
//!
//! TRUTHFUL REPORTING: the debt marker's OWN persistence is the last
//! post-commit failure surface. When [`LocalStore::write_cleanup_pending`]
//! fails, the cleanup debt could NOT be made durable — the checkpoint flow
//! must not claim durable debt that a crash/restart would lose, so it sets
//! `CheckpointReport::cleanup_persistence_failed` while keeping the
//! in-memory warning; the retry recomputes the worklist from the intact
//! logs and converges regardless. The clear
//! ([`LocalStore::clear_cleanup_pending`]) is DURABLE (remove +
//! parent-directory fsync, so a crash can never resurrect the marker), and
//! a clear failure is surfaced as `CheckpointReport::cleanup_clear_failed`:
//! the stale marker stays on disk — harmless, since every read is keyed on
//! the history floor, never this flag — and the next same-deployment
//! checkpoint re-clears it.
//!
//! The durability primitives (temp naming, the fail-closed parent-dir
//! fsync, atomic marker/JSONL replacement, parse-sensitive marker reads)
//! live in [`crate::store::atomic`]; this module implements the
//! checkpoint-specific sequence on top of them, plus the integrity-bound
//! readers and the compaction.

use crate::error::{Error, Result};
use crate::model::{CLEANUP_PENDING_SCHEMA_VERSION, SCHEMA_VERSION};
use crate::records::{CleanupPending, DeploymentSnapshot, HistoryFloor};
use crate::store::atomic::{
    read_json_marker, set_private, sync_parent_dir, temp_name_for, write_atomic_replace,
    write_jsonl_atomic,
};
use crate::store::local::LocalStore;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(test)]
use crate::testutil::test_faults::FaultKind;

/// The durable backup name of a history-floor marker under a TRANSACTIONAL
/// floor ADVANCE: the marker name with a `.prev.<tag>` suffix, in the SAME
/// directory, where `tag` is the ADVANCE TARGET's deployment id (the new
/// floor B being installed). TAGGED BY TRANSACTION: during A→B the backup
/// is `history-floor.json.prev.<B-id>` holding A; during a later B→C it is
/// `history-floor.json.prev.<C-id>` holding B. A backup is therefore bound
/// to the ONE transaction that created it — a stale `.prev.<B>` left by a
/// committed A→B (whose success-path cleanup was faulted) is a DIFFERENT
/// file from the next transaction's `.prev.<C>`, so a failure in B→C can
/// never consult, let alone restore, another transaction's backup. The
/// restore ([`LocalStore::restore_floor_backup`]) verifies the tag AND the
/// content before it ever renames a backup over the marker; when the
/// marker is ABSENT but this backup exists (a torn advance: A was moved
/// aside, its restore failed), the reader
/// ([`LocalStore::read_history_floor`]) VALIDATES the backup and treats it
/// as the ACTIVE floor — never "no floor", which would expose the
/// below-floor prefix — and recovery
/// ([`LocalStore::recover_history_floor_backup`]) restores it atomically,
/// never deleting it.
fn floor_backup_path(path: &Path, tag: &str) -> PathBuf {
    path.with_file_name(format!(
        "{}.prev.{tag}",
        path.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default()
    ))
}

/// Every leftover backup sibling of a history-floor marker in the same
/// directory, sorted: the legacy untagged `history-floor.json.prev` and
/// every tagged `history-floor.json.prev.<tag>` (the current scheme). An
/// ADVANCE reconciles all of them durably before it starts (the backup slot
/// starts clean), and the reader
/// ([`LocalStore::read_history_floor`]) treats ANY of them alongside a
/// missing marker as a torn advance (never "no floor", which would expose
/// the below-floor prefix). The staged temp files carry the `.tmp.` infix,
/// so they never match the `.prev` prefix. The list is empty when the
/// parent directory is missing or unreadable (the reader then simply sees
/// no marker and no backup).
fn floor_backup_siblings(path: &Path) -> Vec<PathBuf> {
    let parent = match path.parent() {
        Some(p) => p,
        None => return Vec::new(),
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let prefix = format!("{name}.prev");
    let mut out: Vec<PathBuf> = std::fs::read_dir(parent)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// INJECTABLE FILESYSTEM-OPERATION BOUNDARY for the floor transaction
/// (test-only seam): the ACTUAL renames of the transactional advance route
/// through [`floor_fs_rename`], which consults this per-thread slot when a
/// test installed a seam. The point of the seam is to fail the REAL
/// temp→marker rename AFTER A was backed up — a genuine `rename(2)` error
/// on the actual call, the failure mode the injected
/// [`FaultKind::RenameFloor`] fault (which fires BEFORE the rename I/O)
/// cannot reproduce. Production never installs a seam: [`floor_fs_rename`]
/// falls through to [`std::fs::rename`].
///
/// The seam is PER-THREAD (not per-store like the fault registry — the
/// store struct lives in `src/store/local.rs`, which this module does not
/// modify), so two fixtures in different test threads can never interfere;
/// [`FloorFsSeamGuard`] scopes one installation to one test case.
#[cfg(test)]
pub(crate) trait FloorFsOps: Send + Sync {
    /// The ACTUAL rename call. A test impl matches `(src, dst)` to fail
    /// exactly the call it wants — e.g. src's filename starting with the
    /// temp prefix AND dst == the marker path — while every other rename
    /// (the A→backup rename, the restore's rename) passes through to the
    /// real filesystem.
    fn rename(&self, src: &Path, dst: &Path) -> std::io::Result<()>;
}

// The installed seam for the current thread ([`FloorFsOps`]). `None` in
// production and in tests that did not install one — the floor writes then
// perform the REAL filesystem calls.
#[cfg(test)]
thread_local! {
    static FLOOR_FS_OPS: std::cell::RefCell<Option<std::sync::Arc<dyn FloorFsOps>>> =
        const { std::cell::RefCell::new(None) };
}

/// Route a floor-transaction rename through the INJECTABLE filesystem
/// boundary: production always performs the REAL [`std::fs::rename`]; a
/// test that installed a seam (via [`FloorFsSeamGuard`]) performs the
/// seam's rename instead — so a test can fail the ACTUAL temp→marker
/// rename after A was backed up (a real fs error on the real call, not a
/// pre-I/O fault).
fn floor_fs_rename(src: &Path, dst: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if let Some(ops) = FLOOR_FS_OPS.with(|s| s.borrow().clone()) {
        return ops.rename(src, dst);
    }
    std::fs::rename(src, dst)
}

/// Test-only RAII guard scoping a [`FloorFsOps`] seam to one floor
/// transaction case: installs the seam for the CURRENT thread and restores
/// the previous seam on drop, so a proptest case cannot leak its arming
/// into the next case (or another test on the same thread).
#[cfg(test)]
pub(crate) struct FloorFsSeamGuard(Option<std::sync::Arc<dyn FloorFsOps>>);

#[cfg(test)]
impl FloorFsSeamGuard {
    pub(crate) fn install(ops: std::sync::Arc<dyn FloorFsOps>) -> Self {
        // `Option::replace` swaps the value in place and returns the
        // previous one (the seam the guard restores on drop).
        let previous = FLOOR_FS_OPS.with(|s| s.borrow_mut().replace(ops));
        FloorFsSeamGuard(previous)
    }
}

#[cfg(test)]
impl Drop for FloorFsSeamGuard {
    fn drop(&mut self) {
        FLOOR_FS_OPS.with(|s| *s.borrow_mut() = self.0.take());
    }
}

/// Test impl of [`FloorFsOps`]: performs the REAL filesystem calls while
/// recording every rename it observed, and can be ARMED to fail ONE rename
/// whose `(src, dst)` matches a predicate — the seam the real-B-temp-rename
/// property uses to fail the ACTUAL temp→marker rename after A was backed
/// up. One-shot: the first matching rename fails with a permission error
/// and disarms, so the restore's rename (and any later transaction) passes
/// through to the real filesystem.
///
/// The armed one-shot failure predicate decides, per `(src, dst)`, whether
/// the rename must fail (factored into a `type` alias so the field type
/// stays readable).
#[cfg(test)]
type FailRenamePred = dyn Fn(&Path, &Path) -> bool + Send + Sync;

#[cfg(test)]
pub(crate) struct TestFloorFsOps {
    fail_rename: std::sync::Mutex<Option<std::sync::Arc<FailRenamePred>>>,
    renames: std::sync::Mutex<Vec<(PathBuf, PathBuf)>>,
}

#[cfg(test)]
impl TestFloorFsOps {
    pub(crate) fn new() -> Self {
        TestFloorFsOps {
            fail_rename: std::sync::Mutex::new(None),
            renames: std::sync::Mutex::new(Vec::new()), // rename log (call order)
        }
    }

    /// Arm the seam: the NEXT rename whose `(src, dst)` satisfies `pred`
    /// fails with `PermissionDenied` (one-shot).
    pub(crate) fn fail_rename_once(
        &self,
        pred: impl Fn(&Path, &Path) -> bool + Send + Sync + 'static,
    ) {
        *self.fail_rename.lock().unwrap() = Some(std::sync::Arc::new(pred));
    }

    /// Every rename observed by the seam, in call order — a test asserts
    /// the seam fired on the REAL temp→marker call AFTER the backup rename.
    pub(crate) fn renames(&self) -> Vec<(PathBuf, PathBuf)> {
        self.renames.lock().unwrap().clone()
    }
}

#[cfg(test)]
impl Default for TestFloorFsOps {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl FloorFsOps for TestFloorFsOps {
    fn rename(&self, src: &Path, dst: &Path) -> std::io::Result<()> {
        self.renames
            .lock()
            .unwrap()
            .push((src.to_path_buf(), dst.to_path_buf()));
        // Check the armed predicate WITHOUT consuming it: the arming must
        // survive every non-matching rename (e.g. the A→backup rename) and
        // fire only on the exact call it was armed for (the temp→marker
        // rename), then disarm.
        let should_fail = self
            .fail_rename
            .lock()
            .unwrap()
            .as_ref()
            .map(|pred| pred(src, dst))
            .unwrap_or(false);
        if should_fail {
            self.fail_rename.lock().unwrap().take();
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "test fault: real floor rename forced to fail once",
            ));
        }
        std::fs::rename(src, dst)
    }
}
/// The exact set a checkpoint floor discards on one target (the dry-run
/// preview enumerates precisely this; the compaction deletes precisely this).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FloorDiscards {
    /// Deployment ids of the attempts.jsonl lines removed (the checkpoint's
    /// own attempt and everything after it stay).
    pub discarded_attempts: Vec<String>,
    /// Snapshot indices removed from snapshots.jsonl (index < floor).
    pub discarded_snapshots: Vec<u64>,
    /// Deployment ids whose `deployments/<id>/` directories are deleted
    /// (the union of the two sets above, deduplicated).
    pub discarded_deployments: Vec<String>,
}

impl LocalStore {
    // ---- checkpoint history floor --------------------------------------

    /// Path of the target's durable history-floor marker
    /// (`refs/history-floor.json`). The marker is written FIRST (durable)
    /// before the physical compaction, and every read path in this module is
    /// gated by it — see [`LocalStore::read_attempts`] /
    /// [`LocalStore::read_snapshots`]. Crate-private: the marker is an
    /// internal enforcement point, never a public API.
    pub(crate) fn history_floor_path(&self, target: &str) -> PathBuf {
        self.refs_dir(target).join("history-floor.json")
    }

    /// Write the target's history floor marker with the checkpoint's
    /// FAIL-CLOSED durability protocol (its OWN sequence, not the shared
    /// [`write_atomic_replace`](crate::store::atomic::write_atomic_replace) — the per-stage fault slots must fire
    /// between the steps). The FIRST floor (no existing marker) follows the
    /// original sequence:
    ///
    /// 1. write the marker bytes to a UNIQUE temp file in the same
    ///    directory,
    /// 2. chmod the TEMP file private (0o600) — before it can ever become
    ///    visible under its final name,
    /// 3. fsync the temp file,
    /// 4. rename it into place (atomic on POSIX),
    /// 5. DURABLY fsync the parent directory, errors PROPAGATED.
    ///
    /// ADVANCING the floor (an existing marker A is replaced by a later
    /// deployment B) is TRANSACTIONAL — a failed advancement must NEVER
    /// erase the previously durable floor A, and must NEVER roll it
    /// BACKWARD (a stale backup from an earlier transaction is never
    /// restored over a newer floor):
    ///
    /// 0. RECONCILE the backup slot: durably remove every leftover
    ///    `history-floor.json.prev*` sibling (tagged backups of OTHER
    ///    transactions whose success-path cleanup was faulted, plus any
    ///    legacy untagged `.prev`) and fsync the parent — the backup slot
    ///    starts CLEAN, so this transaction's backup can never be confused
    ///    with a stale one (a stale A can never be restored over B),
    /// 1. entry fault → `Err`, A untouched,
    /// 2. stage B's temp (write + chmod private + fsync); a fault → `Err`,
    ///    A untouched (no rename has happened yet),
    /// 3. move A aside to the durable, TRANSACTION-TAGGED backup
    ///    `history-floor.json.prev.<B-id>` in the same directory, then
    ///    fsync the parent so the BACKUP is durable BEFORE B can overwrite
    ///    the marker name; a fault or a real
    ///    backup-sync error → `Err` through the ONE cleanup-and-restore
    ///    handler,
    /// 4. rename B's temp into place (atomic); a fault OR a REAL rename
    ///    failure (the actual `rename(2)` call, routed through the
    ///    injectable filesystem boundary) → `Err` through the SAME
    ///    handler,
    /// 5. fsync the parent directory — B's DURABILITY COMMIT POINT — errors
    ///    PROPAGATED; a fault or a real sync error (the marker may already
    ///    be renamed into place) → `Err` through the SAME handler: B never
    ///    committed, A is durable again,
    /// 6. committed: remove THIS transaction's tagged backup (best-effort —
    ///    a leftover is harmless: it carries B's tag, so no other
    ///    transaction ever restores it, and the NEXT advance's step-0
    ///    reconciliation removes it durably), then fsync the parent so the
    ///    removal is durable.
    ///
    /// The RESTORE ([`LocalStore::restore_floor_backup`]) is the
    /// fail-closed half, and it NEVER restores a backup it did not create
    /// and verify: the backup must carry the CURRENT advance's tag AND its
    /// content must parse and equal the pre-advance floor A (read at the
    /// start of the transaction) — a stale or foreign backup is REFUSED,
    /// never renamed over the marker. EVERY post-backup failure — injected
    /// fault or real filesystem error alike, INCLUDING a real B-temp→marker
    /// rename failure — routes through the ONE handler
    /// ([`LocalStore::cleanup_and_restore`]): it best-effort removes B's
    /// temp artifact, restores A from the backup via
    /// [`LocalStore::restore_floor_backup`], and propagates the ORIGINAL
    /// error. A restore failure leaves the marker
    /// absent while the tagged backup still holds A — a TORN ADVANCE the
    /// readers survive via the validated-backup fallback
    /// ([`LocalStore::read_history_floor`]: a VALIDATED tagged backup with
    /// no marker IS the active floor A, never "no floor", which would
    /// expose the below-floor prefix) and that recovery repairs by
    /// atomically restoring the backup
    /// ([`LocalStore::recover_history_floor_backup`]). Every stage error
    /// is returned from THIS method (PRE-commit): B is never reported
    /// established unless its parent-dir sync succeeded.
    pub(crate) fn write_history_floor(&self, target: &str, floor: &HistoryFloor) -> Result<()> {
        // Entry-point fault (existing): fired BEFORE any durability I/O, so
        // a failure here leaves no marker, no temp, no backup, no
        // compaction — the previous floor A (if any) is untouched.
        #[cfg(test)]
        if self
            .fault_registry()
            .consume(FaultKind::WriteHistoryFloor, floor.deployment_id.as_str())
        {
            return Err(Error::store(
                "test fault: write_history_floor forced to fail once",
            ));
        }
        let bytes = serde_json::to_vec_pretty(floor)
            .map_err(|e| Error::store(format!("serialize history floor: {e}")))?;
        let path = self.history_floor_path(target);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::store(format!("mkdir {}: {e}", parent.display())))?;
        }
        // The durable backup of the CURRENT floor (if any), in the same
        // directory, TAGGED BY THE ADVANCE TARGET: during A→B the backup
        // is `history-floor.json.prev.<B-id>` holding A. An ADVANCE moves
        // A here before B can overwrite the marker name, so a failed
        // advancement can always rename A back; the tag binds the backup
        // to THIS transaction — a stale backup from another transaction is
        // a DIFFERENT file and can never be consulted or restored here.
        let backup = floor_backup_path(&path, floor.deployment_id.as_str());
        let had_floor = path.exists();
        // PRE-ADVANCE FLOOR (the restore-verification anchor): the floor
        // this advance moves aside. The RESTORE only ever restores a
        // backup whose content parses and EQUALS this floor — a backup
        // holding anything else (a stale or foreign floor that somehow
        // carried this transaction's tag, or a corrupted file) is REFUSED,
        // never renamed over the marker. Parse-sensitive
        // (read_json_marker): a malformed current marker is semantic
        // corruption and the advance fails closed rather than guess.
        let previous_floor: Option<HistoryFloor> = if had_floor {
            Some(read_json_marker(&path)?)
        } else {
            None
        };
        let tmp = temp_name_for(&path);
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| Error::store(format!("create {}: {e}", tmp.display())))?;
            f.write_all(&bytes)
                .map_err(|e| Error::store(format!("write {}: {e}", tmp.display())))?;
            // Private BEFORE visible: the temp carries 0o600 from this
            // point, so the marker is never observed with default perms
            // (the shared helper's old post-rename chmod opened a window).
            set_private(&tmp)?;
            // Stage fault: the temp-file fsync (B's temp — no rename has
            // happened yet, so the existing floor A is untouched).
            #[cfg(test)]
            if self
                .fault_registry()
                .consume(FaultKind::SyncFloorTemp, floor.deployment_id.as_str())
            {
                let _ = std::fs::remove_file(&tmp);
                return Err(Error::store(
                    "test fault: history-floor temp sync forced to fail once",
                ));
            }
            f.sync_all()
                .map_err(|e| Error::store(format!("fsync {}: {e}", tmp.display())))?;
        }

        if had_floor {
            // ---- TRANSACTIONAL ADVANCE, stage 0: RECONCILE ----------------
            // Durably remove every leftover `history-floor.json.prev*`
            // sibling BEFORE this advance starts — the tagged backup of an
            // EARLIER transaction (e.g. a `.prev.<B>` holding A left by a
            // committed A→B whose success-path cleanup was faulted) plus any
            // legacy untagged `.prev`. The backup slot starts CLEAN, so a
            // stale backup from another transaction can never be confused
            // with this transaction's backup (the fixed-name hazard: a
            // failure in a later transaction consulting the shared `.prev`
            // would find the STALE A and could restore it over a newer
            // floor, rolling the floor BACKWARD). The removal is durable
            // (parent fsync) BEFORE this transaction creates its own
            // backup.
            self.reconcile_floor_backups(&path)?;

            // ---- TRANSACTIONAL ADVANCE, stage 1: BACKUP A ----------------
            // Move the current floor A aside to the durable, tagged backup
            // BEFORE B can overwrite the marker name, and make the backup
            // durable (parent fsync) first: from here on, any failure can
            // rename A back — the pre-advance state is never lost. The
            // fault fires BEFORE the rename (A still in place); a real
            // rename or sync failure restores A (only from THIS
            // transaction's tagged backup) and fails the advance.
            #[cfg(test)]
            if self
                .fault_registry()
                .consume(FaultKind::RenameFloorBackup, floor.deployment_id.as_str())
            {
                // A never moved (the fault fires before the rename): there
                // is nothing to restore — drop B's staged temp and fail.
                // The previous floor A stands untouched.
                let _ = std::fs::remove_file(&tmp);
                return Err(Error::store(
                    "test fault: history-floor backup rename forced to fail once",
                ));
            }
            // The REAL backup rename (A → the durable, TRANSACTION-TAGGED
            // backup), routed through the injectable filesystem boundary so
            // a test can fail the ACTUAL call BEFORE A moves. A real
            // failure leaves A at the marker name (rename is atomic — the
            // backup does not exist): the cleanup-and-restore handler's
            // `path` guard (`backup.exists() || !had_floor`) keeps A at the
            // marker name and drops only B's staged temp — a failed backup
            // can never erase the previous floor.
            floor_fs_rename(&path, &backup).map_err(|e| {
                self.cleanup_and_restore(
                    &path,
                    &backup,
                    &tmp,
                    true,
                    previous_floor.as_ref(),
                    floor.deployment_id.as_str(),
                    Error::store(format!("rename floor {}: {e}", path.display())),
                )
            })?;
            // The BACKUP must be durable before B can overwrite the marker
            // name: without this sync, a later failure could leave the
            // marker name empty with A only in a not-yet-durable backup. A
            // real sync failure is POST-BACKUP (A already moved): the ONE
            // cleanup-and-restore handler restores A and propagates the
            // original error.
            if let Err(e) = sync_parent_dir(&path) {
                return Err(self.cleanup_and_restore(
                    &path,
                    &backup,
                    &tmp,
                    true,
                    previous_floor.as_ref(),
                    floor.deployment_id.as_str(),
                    e,
                ));
            }
        }

        // ---- TRANSACTIONAL ADVANCE, stage 2: B's rename + commit point ----
        // From here on EVERY failure is POST-BACKUP (A sits in the durable
        // backup): the injected [`FaultKind::RenameFloor`] fault, a REAL
        // temp→marker rename error (the ACTUAL fs call, routed through the
        // injectable filesystem boundary [`floor_fs_rename`]), the injected
        // [`FaultKind::SyncFloorParent`] fault, and a REAL parent-sync
        // error ALL route through the ONE cleanup-and-restore handler
        // ([`LocalStore::cleanup_and_restore`]) — restoring A from the
        // backup, removing B's temp artifact, and propagating the ORIGINAL
        // error. A real rename failure is NOT special-cased: without the
        // handler it would leave the marker absent, B never installed, and
        // A in the backup — NO floor (discarded history re-exposed).
        #[cfg(test)]
        if self
            .fault_registry()
            .consume(FaultKind::RenameFloor, floor.deployment_id.as_str())
        {
            return Err(self.cleanup_and_restore(
                &path,
                &backup,
                &tmp,
                had_floor,
                previous_floor.as_ref(),
                floor.deployment_id.as_str(),
                Error::store("test fault: history-floor rename forced to fail once"),
            ));
        }
        // The REAL temp→marker rename, through the injectable filesystem
        // boundary: a test seam fails the ACTUAL call — after A was backed
        // up — and the REAL error routes through the SAME
        // cleanup-and-restore handler as the injected faults.
        floor_fs_rename(&tmp, &path).map_err(|e| {
            self.cleanup_and_restore(
                &path,
                &backup,
                &tmp,
                had_floor,
                previous_floor.as_ref(),
                floor.deployment_id.as_str(),
                Error::store(format!("rename {}: {e}", path.display())),
            )
        })?;

        // Stage fault: B's commit-point parent fsync (the durability
        // COMMIT POINT — B's marker may already be renamed into place when
        // this fires). Fail-closed: B never committed — the ONE
        // cleanup-and-restore handler removes B's artifact at the marker
        // name and restores A from the backup, so the failed advancement
        // leaves EXACTLY the pre-advance state (floor A durable, same
        // visible suffix, no compaction side effects).
        #[cfg(test)]
        if self
            .fault_registry()
            .consume(FaultKind::SyncFloorParent, floor.deployment_id.as_str())
        {
            // B may already be renamed into place: the handler removes
            // B's marker so no B exists, then restores A from the tagged
            // backup (the marker name reverts to the pre-advance floor). If
            // the restore ITSELF fails, the marker is left absent while the
            // tagged backup holds A — a torn state every read fails closed
            // on.
            return Err(self.cleanup_and_restore(
                &path,
                &backup,
                &tmp,
                had_floor,
                previous_floor.as_ref(),
                floor.deployment_id.as_str(),
                Error::store("test fault: history-floor parent sync forced to fail once"),
            ));
        }
        // The parent-directory fsync is B's DURABILITY COMMIT POINT: it is
        // what makes B's rename survive power loss. Fail-closed — a real
        // sync failure means B never committed, so the ONE
        // cleanup-and-restore handler removes B's marker and restores A
        // from the backup (mirror the torn-record cleanup).
        if let Err(e) = sync_parent_dir(&path) {
            return Err(self.cleanup_and_restore(
                &path,
                &backup,
                &tmp,
                had_floor,
                previous_floor.as_ref(),
                floor.deployment_id.as_str(),
                e,
            ));
        }
        // COMMITTED: B is durable. Remove THIS transaction's tagged backup
        // — best-effort (a leftover `.prev.<B>` holding A is harmless: it
        // carries B's tag, so no OTHER transaction ever restores it, and
        // every read is keyed on the marker, never the backup), then fsync
        // the parent so the removal itself is durable. A removal failure is
        // absorbed: the NEXT advance's pre-start reconciliation removes the
        // leftover durably.
        #[cfg(test)]
        if self
            .fault_registry()
            .consume(FaultKind::RemoveFloorBackup, floor.deployment_id.as_str())
        {
            // Test fault: the success-path backup removal is FORCED to fail
            // (the tagged backup — holding the PRE-advance floor A — stays
            // on disk). Harmless by design: the next advance's pre-start
            // reconciliation removes it durably, and no other transaction
            // ever restores it.
        } else if had_floor && std::fs::remove_file(&backup).is_ok() {
            let _ = sync_parent_dir(&path);
        }
        Ok(())
    }

    /// Durably remove every leftover backup sibling of the floor marker
    /// (`history-floor.json.prev*` — the tagged backups of OTHER
    /// transactions whose success-path cleanup was faulted, plus any legacy
    /// untagged `.prev`), then fsync the parent so the removal is durable.
    /// Runs at the START of an ADVANCE, BEFORE the current floor is moved
    /// aside ([`LocalStore::write_history_floor`]): the backup slot starts
    /// CLEAN, so a stale backup from another transaction can never be
    /// confused with this transaction's backup — and can never be restored
    /// over a newer floor (a stale A is never treated as the active floor).
    /// Removal errors PROPAGATE (fail-closed: an advance must not proceed
    /// while a leftover backup that a later failure could mistake for its
    /// own still sits in the directory).
    fn reconcile_floor_backups(&self, path: &Path) -> Result<()> {
        for leftover in floor_backup_siblings(path) {
            std::fs::remove_file(&leftover).map_err(|e| {
                Error::store(format!(
                    "reconcile stale history-floor backup {}: {e}",
                    leftover.display()
                ))
            })?;
        }
        // Make the removal durable BEFORE this transaction creates its own
        // backup (the parent fsync is what makes a removal/rename survive
        // power loss).
        sync_parent_dir(path)
    }

    /// The ONE cleanup-and-restore handler for a failed transactional
    /// ADVANCE (A → B). Runs on EVERY failure after the advance started
    /// touching the marker — the REAL backup-rename error (A may or may not
    /// have moved), the injected [`FaultKind::RenameFloor`] fault, a REAL
    /// temp→marker rename error (the ACTUAL fs call, routed through the
    /// injectable filesystem boundary [`floor_fs_rename`]), the injected
    /// [`FaultKind::SyncFloorParent`] fault, and a REAL parent-sync error.
    ///
    /// The handler restores the pre-advance state and propagates the
    /// ORIGINAL error:
    ///
    /// 1. best-effort remove B's STAGED TEMP (`tmp`) — it exists at the
    ///    pre-rename stages (a fault, a failed temp→marker rename) and is
    ///    gone once B's rename succeeded (a no-op then),
    /// 2. best-effort remove B's artifact at the MARKER NAME (`path`) — the
    ///    half-installed B marker after B's rename succeeded — but ONLY
    ///    when removing it cannot erase the previous floor: after A moved
    ///    aside (`backup` exists, so `path` is absent or B's marker), or on
    ///    a first-ever write (`had_floor == false`; `path` is absent or B's
    ///    marker — A never lived there). A failed BACKUP rename on an
    ///    ADVANCE (`had_floor == true`, no `backup`) leaves A at `path` —
    ///    that file is A and must NOT be removed,
    /// 3. restore A from the tagged backup via
    ///    [`LocalStore::restore_floor_backup`] (atomic rename over the
    ///    marker name + parent fsync — a no-op when the advance failed
    ///    before A moved; the restore is TAG- AND CONTENT-VERIFIED and
    ///    FAIL-CLOSED when it itself fails),
    /// 4. propagate the ORIGINAL error — wrapped ONLY when the restore also
    ///    failed, naming it (a double failure leaves a torn state — marker
    ///    absent, the tagged backup holds A — every read fails closed on).
    #[allow(clippy::too_many_arguments)]
    fn cleanup_and_restore(
        &self,
        path: &Path,
        backup: &Path,
        tmp: &Path,
        had_floor: bool,
        previous_floor: Option<&HistoryFloor>,
        deployment_id: &str,
        original: Error,
    ) -> Error {
        // 1. B's staged temp (pre-rename stages only; a no-op after B's
        //    rename succeeded — the temp no longer exists).
        let _ = std::fs::remove_file(tmp);
        // 2. B's marker-name artifact — never A (see the doc above for the
        //    guard: the failed-backup-rename case keeps A at `path`).
        if backup.exists() || !had_floor {
            let _ = std::fs::remove_file(path);
        }
        // 3. + 4. Restore A (tag- and content-verified) and propagate the
        //    original error (wrapped only when the restore itself failed).
        match self.restore_floor_backup(path, backup, previous_floor, deployment_id) {
            Ok(()) => original,
            Err(re) => Error::store(format!(
                "{original}; restore of the previous floor failed ({re}) — the marker is left in a torn state and every read fails closed"
            )),
        }
    }
    /// Restore the PRE-ADVANCE floor A after a failed ADVANCE (A → B):
    /// rename the durable, TRANSACTION-TAGGED backup
    /// `history-floor.json.prev.<B-id>` back over the marker name (atomic on
    /// POSIX — it overwrites any half-installed B marker) and fsync the
    /// parent so the restore is durable. A no-op when no backup exists (the
    /// advance failed before A was ever moved aside — A is still the
    /// durable marker). THE DOCUMENTED RECOVERY of a torn advance IS THIS
    /// OPERATION — the backup is the only valid floor and is restored,
    /// never deleted (see [`LocalStore::recover_history_floor_backup`]).
    ///
    /// NEVER RESTORES A FOREIGN BACKUP: the restore verifies the backup
    /// name carries the CURRENT advance's tag (`deployment_id`) AND that
    /// its content parses and equals `previous_floor` — the pre-advance
    /// floor the transaction moved aside, read at the start of the
    /// transaction ([`LocalStore::write_history_floor`]). A backup that
    /// fails either check is REFUSED (integrity error) and NEVER renamed
    /// over the marker: a stale backup from another transaction — which
    /// could roll the durable floor BACKWARD and re-expose the discarded
    /// below-floor history — can never be restored. (The caller always
    /// passes this transaction's tagged path, so the name check is
    /// defense-in-depth; the content check is the belt-and-braces against
    /// any stale or foreign backup that somehow reached the tagged slot.)
    ///
    /// FAIL-CLOSED: the [`FaultKind::RestoreFloor`](crate::testutil::test_faults::FaultKind::RestoreFloor) fault (and any real
    /// rename/sync error) makes the restore itself fail: A stays in the
    /// backup and the marker keeps the failed stage's state — possibly
    /// ABSENT. The readers ([`LocalStore::read_history_floor`]) then treat
    /// a VALIDATED backup as the active floor A (a torn advance is never
    /// "no floor" — which would expose the below-floor prefix) and fail
    /// closed only when the backup itself fails validation, so a double
    /// failure can never expose history below A.
    fn restore_floor_backup(
        &self,
        path: &Path,
        backup: &Path,
        previous_floor: Option<&HistoryFloor>,
        deployment_id: &str,
    ) -> Result<()> {
        // Stage fault: the RESTORE itself (keyed by the checkpoint
        // deployment id, matching every other floor stage). Fires BEFORE
        // any restore I/O — the restore could not even begin, so the tagged
        // backup still holds A and the marker keeps whatever state the
        // failed stage left.
        #[cfg(test)]
        if self
            .fault_registry()
            .consume(FaultKind::RestoreFloor, deployment_id)
        {
            return Err(Error::store(
                "test fault: history-floor restore forced to fail once",
            ));
        }
        if !backup.exists() {
            // The advance failed before the current floor was moved aside:
            // the floor is still the durable marker — nothing to restore. A
            // stale backup from ANOTHER transaction is a DIFFERENT tagged
            // file and is never considered here.
            return Ok(());
        }
        // NEVER RESTORE A FOREIGN BACKUP (name check): the backup must be
        // THIS advance's tagged backup. The caller always passes the tagged
        // path, so this is defense-in-depth against a caller bug or a
        // future code path pointing the restore at another transaction's
        // backup.
        if *backup != floor_backup_path(path, deployment_id) {
            return Err(Error::integrity(format!(
                "refusing to restore history-floor backup {}: the backup does not carry the current advance's tag '{deployment_id}' — only the backup created and verified by the CURRENT transaction may be restored",
                backup.display()
            )));
        }
        // BELT-AND-BRACES CONTENT VERIFICATION: the backup must parse and
        // equal the floor this transaction moved aside (read at the start
        // of the advance). A backup holding anything else — a stale A that
        // somehow survived into this tagged slot, a corrupted file, a
        // foreign floor — is REFUSED: restoring it could roll the durable
        // floor BACKWARD (re-exposing the discarded below-floor history).
        // The marker is left untouched (still the current floor), never
        // overwritten by an unverified backup.
        let content: HistoryFloor = read_json_marker(backup)?;
        if previous_floor != Some(&content) {
            return Err(Error::integrity(format!(
                "refusing to restore history-floor backup {}: its content (deployment '{}', snapshot s{}) does not match the floor this advance moved aside (deployment '{}', snapshot s{}) — only the backup created and verified by the CURRENT transaction may be restored",
                backup.display(),
                content.deployment_id,
                content.snapshot_index,
                previous_floor
                    .map(|f| f.deployment_id.as_str())
                    .unwrap_or("<none>"),
                previous_floor.map(|f| f.snapshot_index).unwrap_or(0),
            )));
        }
        std::fs::rename(backup, path)
            .map_err(|e| Error::store(format!("restore floor {}: {e}", path.display())))?;
        sync_parent_dir(path)
    }

    /// The newest leftover backup sibling of the floor marker whose content
    /// VALIDATES as the floor — parses AND passes the full integrity
    /// binding of [`LocalStore::validate_history_floor`] (schema version,
    /// target binding, exact snapshot pair, matching attempt), the SAME
    /// binding the marker path enforces — or `None` when no backup
    /// validates. The reader's torn-advance fallback
    /// ([`LocalStore::read_history_floor`]) and the recovery
    /// ([`LocalStore::recover_history_floor_backup`]) share it: a leftover
    /// backup is only ever trusted — as the ACTIVE floor or as the restore
    /// source — when it validates; a backup that fails validation is NEVER
    /// treated as the floor and NEVER restored (an unvalidatable backup is
    /// not "no floor" either — the callers fail closed).
    fn validated_backup(&self, target: &str, path: &Path) -> Option<(PathBuf, HistoryFloor)> {
        floor_backup_siblings(path)
            .into_iter()
            .rev()
            .find_map(|backup| {
                let floor = read_json_marker(&backup).ok()?;
                self.validate_history_floor(target, &backup, &floor).ok()?;
                Some((backup, floor))
            })
    }

    /// RECOVER a torn floor ADVANCE ([`LocalStore::read_history_floor`]'s
    /// validated-backup fallback): atomically restore the durable,
    /// VALIDATED tagged backup (`history-floor.json.prev.<tag>`) as the
    /// marker (`history-floor.json`) — the SAME rename + parent-dir fsync
    /// [`LocalStore::restore_floor_backup`] performs when a failed advance
    /// restores the previous floor. In a torn state (the marker ABSENT, the
    /// backup holding the pre-advance floor A) the backup is the ONLY valid
    /// floor — deleting it would erase the floor and re-expose the
    /// below-floor history — so the documented recovery restores it and
    /// NEVER deletes it. The recovery is a MANUAL REPAIR without a
    /// transaction context, so it restores A VALIDATED backup — any
    /// leftover `.prev*` sibling whose content passes the full integrity
    /// binding, preferring the newest — and NEVER an unvalidated one. A
    /// no-op when the marker already exists (a present marker is
    /// authoritative: there is nothing to recover, and restoring the backup
    /// over it could overwrite a NEWER committed floor) or when no backup
    /// exists. Fails closed (`Err`) when leftover backups exist but none
    /// validates (an unvalidatable backup is never restored over the
    /// marker) or when the restore cannot be made durable.
    #[cfg(test)]
    pub(crate) fn recover_history_floor_backup(&self, target: &str) -> Result<()> {
        let p = self.history_floor_path(target);
        if p.exists() {
            return Ok(());
        }
        let Some((backup, _)) = self.validated_backup(target, &p) else {
            // No VALIDATED backup to restore: no-op when nothing is left
            // over; fail closed when leftovers exist but none validates.
            let leftovers = floor_backup_siblings(&p);
            return if leftovers.is_empty() {
                Ok(())
            } else {
                Err(Error::integrity(format!(
                    "recover history floor for target '{target}': the durable backup {} exists but does not pass the floor integrity binding — refusing to restore an unvalidated backup over the marker",
                    leftovers[0].display()
                )))
            };
        };
        std::fs::rename(&backup, &p)
            .map_err(|e| Error::store(format!("recover floor {}: {e}", backup.display())))?;
        sync_parent_dir(&p)
    }

    /// Read the target's history-floor marker, or `None` when no checkpoint
    /// has been established. FAILS CLOSED on every integrity violation:
    ///
    /// * `schema_version` must be exactly [`SCHEMA_VERSION`]; any other
    ///   version fails with an error naming the version (a floor written by
    ///   a different schema is never silently interpreted).
    /// * a PRESENT but MALFORMED marker (truncated JSON, wrong field types,
    ///   missing fields) is a parse failure — also [`Error::integrity`]
    ///   via [`read_json_marker`]. [`Error::store`] is reserved for
    ///   mechanical filesystem I/O (open/read failures) so a caller can
    ///   always distinguish "this marker is corrupt" from "disk read
    ///   failed".
    /// * (a) the marker's `target` must match the path it was read from
    ///   (`marker.target == target`): a marker is bound to the target
    ///   directory it lives in, so a marker smuggled into another target's
    ///   `refs/` can never gate (or leak into) that target's history.
    /// * (b) a snapshot must exist with EXACTLY `index == snapshot_index`
    ///   AND `deployment_id == marker.deployment_id` — the exact snapshot
    ///   pair, never the index alone (a floor must name a real rollback
    ///   state that still exists).
    /// * (c) an attempt must exist with `deployment_id ==
    ///   marker.deployment_id` (the floor's own deployment must be in the
    ///   target's attempts log).
    /// * (d) TORN ADVANCE (validated-backup fallback): when the marker is
    ///   ABSENT but a leftover backup sibling (`history-floor.json.prev.<tag>`
    ///   — the current, transaction-tagged scheme — or a legacy untagged
    ///   `history-floor.json.prev`) exists, an ADVANCE was interrupted
    ///   mid-flight and its restore of the previous floor A failed. This
    ///   state is NEVER treated as "no floor" (which would expose the
    ///   below-floor prefix): the backup is VALIDATED against the SAME
    ///   integrity binding as the marker — schema version, target binding,
    ///   the exact snapshot pair, and the matching attempt, checks (a)–(c)
    ///   above — and, when valid, IS the ACTIVE floor: the read returns A,
    ///   exactly as if A were still the marker (a reader during a torn
    ///   state sees the pre-advance floor, never None, never an error). A
    ///   backup that FAILS validation is NOT trusted: the read fails closed
    ///   with an integrity error (an unvalidatable backup is never "no
    ///   floor" either). Recovery of the torn state is
    ///   [`LocalStore::recover_history_floor_backup`] — the ATOMIC RESTORE
    ///   of the backup (rename + parent-dir fsync), never its deletion.
    ///   (A marker PRESENT alongside a leftover backup is fine — the
    ///   success path removes the backup best-effort, and reads prefer the
    ///   marker, never the backup.)
    ///
    /// Each violation is an [`Error::integrity`] error, so a corrupted or
    /// tampered marker is NEVER silently treated as "no floor" (which would
    /// expose the below-floor prefix): the gated readers
    /// ([`LocalStore::read_attempts`] / [`LocalStore::read_snapshots`])
    /// propagate the error. Crate-private: non-crate consumers use the
    /// gated readers, never the marker directly.
    pub(crate) fn read_history_floor(&self, target: &str) -> Result<Option<HistoryFloor>> {
        let p = self.history_floor_path(target);
        // TORN-ADVANCE VALIDATED-BACKUP FALLBACK (the
        // transactional-replacement counterpart): when an ADVANCE (A → B)
        // failed before B's durability commit point AND the restore of A
        // also failed, the marker may be left ABSENT while the pre-advance
        // floor A still sits in a durable backup sibling (a tagged
        // `history-floor.json.prev.<tag>` or a legacy untagged
        // `history-floor.json.prev`). ANY leftover backup with no marker
        // means an advance was interrupted mid-flight and its restore
        // failed — this is NEVER "no floor" (which would expose the
        // below-floor prefix): the backup is VALIDATED against the SAME
        // integrity binding as the marker (schema version, target binding,
        // exact snapshot pair, matching attempt) and, when valid, IS the
        // active floor — the read returns A, so a reader during a torn
        // state sees exactly the pre-advance floor (never None, never an
        // error). A backup that FAILS validation is NOT trusted: the read
        // fails closed with an integrity error (an unvalidatable backup is
        // never "no floor" either). A marker PRESENT alongside a leftover
        // backup is fine: the success path removes the backup best-effort,
        // and reads prefer the marker, never the backup.
        if !p.exists() {
            // The validated-backup fallback: a VALIDATED leftover backup IS
            // the active floor A — the torn state is read as the
            // pre-advance floor (never None, never an error).
            if let Some((_, floor)) = self.validated_backup(target, &p) {
                return Ok(Some(floor));
            }
            let leftovers = floor_backup_siblings(&p);
            if !leftovers.is_empty() {
                // Leftovers exist but NONE validates: fail closed (an
                // unvalidatable backup is never "no floor" either).
                return Err(Error::integrity(format!(
                    "history floor for target '{target}' is missing but its durable backup {} exists: a floor ADVANCE was interrupted and its restore failed — refusing to treat this as 'no floor' (which would expose the below-floor prefix)",
                    leftovers[0].display()
                )));
            }
            return Ok(None);
        }
        // Parse-sensitive read: a present-but-malformed marker (truncation,
        // wrong types, missing fields) is semantic corruption → Integrity;
        // only an actual filesystem read failure is Store.
        let floor: HistoryFloor = read_json_marker(&p)?;
        self.validate_history_floor(target, &p, &floor)?;
        Ok(Some(floor))
    }

    /// The floor's INTEGRITY BINDING, shared by the marker
    /// ([`LocalStore::read_history_floor`]'s present-marker path) and the
    /// validated-backup fallback (a torn advance with the marker ABSENT):
    /// `floor` read from `source` (the marker path or the durable backup)
    /// must pass the same checks —
    ///
    /// * `schema_version` must be exactly [`SCHEMA_VERSION`]; any other
    ///   version fails with an error naming the version (a floor written by
    ///   a different schema is never silently interpreted).
    /// * the floor's `target` must match the path it was read from
    ///   (`floor.target == target`): a floor is bound to the target
    ///   directory it lives in, so a floor smuggled into another target's
    ///   `refs/` can never gate (or leak into) that target's history.
    /// * a snapshot must exist with EXACTLY `index == snapshot_index` AND
    ///   `deployment_id == floor.deployment_id` — the exact snapshot pair,
    ///   never the index alone (a floor must name a real rollback state
    ///   that still exists).
    /// * an attempt must exist with `deployment_id == floor.deployment_id`
    ///   (the floor's own deployment must be in the target's attempts
    ///   log).
    ///
    /// Every violation is an [`Error::integrity`] error, so a corrupted or
    /// tampered floor — marker OR backup — is NEVER silently treated as
    /// "no floor" (which would expose the below-floor prefix).
    fn validate_history_floor(
        &self,
        target: &str,
        source: &Path,
        floor: &HistoryFloor,
    ) -> Result<()> {
        if floor.schema_version != SCHEMA_VERSION {
            return Err(Error::integrity(format!(
                "history floor at {} carries unsupported schema_version {} (expected {SCHEMA_VERSION}): only SCHEMA_VERSION is accepted",
                source.display(),
                floor.schema_version
            )));
        }
        // BINDING (a): the floor must name the target directory it lives
        // in. A floor with a foreign `target` is a tampered/corrupted floor
        // — it is refused, not interpreted as a floor for either the path
        // target or the named target.
        if floor.target.as_str() != target {
            return Err(Error::integrity(format!(
                "history floor at {} is not bound to its path: floor.target = '{}' but the floor was read for target '{target}' (a floor must name the target directory it lives in)",
                source.display(),
                floor.target
            )));
        }
        // (b) SNAPSHOT-PAIR BINDING: a snapshot must exist with EXACTLY
        // `index == floor.snapshot_index` AND `deployment_id ==
        // floor.deployment_id` — the exact pair, never the index alone (the
        // checkpoint snapshot is the oldest rollback state; if it no longer
        // exists the floor points at nothing).
        let snapshots = self.read_snapshots_raw(target)?;
        let bound_snapshot = snapshots
            .iter()
            .any(|s| s.index == floor.snapshot_index && s.deployment_id == floor.deployment_id);
        if !bound_snapshot {
            return Err(Error::integrity(format!(
                "history floor for target '{target}' is not bound to a snapshot: no snapshot has EXACTLY index s{} AND deployment '{}' (the exact snapshot pair the floor names does not exist in refs/snapshots.jsonl)",
                floor.snapshot_index, floor.deployment_id
            )));
        }
        // (c) ATTEMPT BINDING: the floor's own deployment must exist in the
        // target's attempts log (a floor whose attempt was deleted is
        // refused, so the checkpoint's own attempt can never be discarded
        // behind the readers' backs).
        let attempts = self.read_attempts_raw(target)?;
        let bound_attempt = attempts
            .iter()
            .any(|a| a.deployment_id == floor.deployment_id);
        if !bound_attempt {
            return Err(Error::integrity(format!(
                "history floor for target '{target}' is not bound to an attempt: no attempt with deployment '{}' exists in targets/{target}/attempts.jsonl (the floor's own deployment must be in the target's attempts log)",
                floor.deployment_id
            )));
        }
        Ok(())
    }

    /// Path of the target's pending-checkpoint-cleanup marker
    /// (`refs/cleanup-pending.json`). Written AFTER the history floor is
    /// durable (the checkpoint's commit point) when the post-commit
    /// compaction could not finish: the checkpoint took effect, the cleanup
    /// is recorded as durable debt. Cleared once the cleanup completes.
    pub fn cleanup_pending_path(&self, target: &str) -> PathBuf {
        self.refs_dir(target).join("cleanup-pending.json")
    }

    /// Read the target's pending-checkpoint-cleanup FLAG marker, or `None`
    /// when no cleanup is pending. FAILS CLOSED on every integrity
    /// violation, mirroring [`LocalStore::read_history_floor`]:
    ///
    /// * `schema_version` must be exactly
    ///   [`CLEANUP_PENDING_SCHEMA_VERSION`]; any other version fails with an
    ///   error naming the version — including the legacy version-1 shape
    ///   that carried `pending_deployments` (serde would otherwise silently
    ///   drop the removed field, so the version gate is what refuses it).
    /// * the marker's `target` must match the path it was read from
    ///   (`marker.target == target`): a marker smuggled into another
    ///   target's `refs/` can never gate (or leak into) that target's
    ///   cleanup decision.
    /// * when `floor` is present, the marker's `deployment_id` and
    ///   `snapshot_index` must EXACTLY match the floor's — the marker is the
    ///   pending-cleanup flag FOR THAT floor, and a corrupted/tampered
    ///   marker (arbitrary target/anchor/deployment ids) must never be
    ///   trusted for the pending/repair decision.
    ///
    /// Each violation is an [`Error::integrity`] error (a schema-version
    /// violation is an [`Error::store`] error naming the version, mirroring
    /// the floor), so a corrupted marker is NEVER silently treated as "no
    /// pending cleanup". The checkpoint retry treats a failed read as debt
    /// outstanding: it recomputes the discards from the intact logs and
    /// converges regardless, so the worst case is a self-healing re-run.
    pub fn read_cleanup_pending(
        &self,
        target: &str,
        floor: Option<&HistoryFloor>,
    ) -> Result<Option<CleanupPending>> {
        let p = self.cleanup_pending_path(target);
        if !p.exists() {
            return Ok(None);
        }
        // Parse-sensitive read: malformed CONTENT is Integrity, filesystem
        // I/O failure is Store (same class split as the history floor).
        let pending: CleanupPending = read_json_marker(&p)?;
        if pending.schema_version != CLEANUP_PENDING_SCHEMA_VERSION {
            return Err(Error::integrity(format!(
                "cleanup-pending marker for target '{target}' carries unsupported schema_version {} (expected {CLEANUP_PENDING_SCHEMA_VERSION}): only CLEANUP_PENDING_SCHEMA_VERSION is accepted (the legacy version-1 shape with pending_deployments is refused, never reinterpreted)",
                pending.schema_version
            )));
        }
        // BINDING (a): the marker must name the target directory it lives in
        // — a marker with a foreign `target` is a tampered/corrupted marker
        // and is refused, not interpreted for either path.
        if pending.target.as_str() != target {
            return Err(Error::integrity(format!(
                "cleanup-pending marker at {} is not bound to its path: marker.target = '{}' but the marker was read for target '{target}' (a cleanup marker must name the target directory it lives in)",
                p.display(),
                pending.target
            )));
        }
        // BINDING (b): when a floor is present, the marker must name EXACTLY
        // that floor's deployment + snapshot index — the marker is the
        // pending-cleanup flag for the floor it accompanies, and a corrupted
        // anchor must never be trusted for the pending/repair decision.
        if let Some(floor) = floor
            && (pending.deployment_id != floor.deployment_id
                || pending.snapshot_index != floor.snapshot_index)
        {
            return Err(Error::integrity(format!(
                "cleanup-pending marker for target '{target}' is not bound to the history floor: marker names deployment '{}' at snapshot s{} but the floor names deployment '{}' at snapshot s{} (a cleanup marker must name exactly the floor it accompanies)",
                pending.deployment_id,
                pending.snapshot_index,
                floor.deployment_id,
                floor.snapshot_index
            )));
        }
        Ok(Some(pending))
    }

    /// Record the target's pending-checkpoint-cleanup debt durably (atomic
    /// temp+rename, mirroring [`LocalStore::write_history_floor`]). The
    /// write is itself POST-COMMIT MAINTENANCE, so a failure must NEVER
    /// turn the checkpoint into an `Err` — the caller decides how to
    /// surface it (the checkpoint flow sets
    /// `CheckpointReport::cleanup_persistence_failed`: the report must NOT
    /// claim durable debt that a crash/restart would lose). The error is
    /// PROPAGATED here so the caller can tell a durable debt from a lost
    /// one.
    pub fn write_cleanup_pending(&self, target: &str, pending: &CleanupPending) -> Result<()> {
        // Fault hook (keyed by the floor's deployment id — the marker's
        // own anchor), fired BEFORE any I/O: a failure here means the debt
        // could not be made durable.
        #[cfg(test)]
        if self.fault_registry().consume(
            FaultKind::WriteCleanupPending,
            pending.deployment_id.as_str(),
        ) {
            return Err(Error::store(
                "test fault: cleanup-pending marker write forced to fail once",
            ));
        }
        let bytes = serde_json::to_vec_pretty(pending)
            .map_err(|e| Error::store(format!("serialize cleanup-pending: {e}")))?;
        write_atomic_replace(&self.cleanup_pending_path(target), &bytes)
    }

    /// Clear the target's pending-checkpoint-cleanup marker once the
    /// physical compaction completed. DURABLE removal: the file is removed
    /// AND the parent directory is fsynced ([`sync_parent_dir`]) — without
    /// the directory fsync a crash can RESURRECT the marker (the removal
    /// is not durable until the directory entry is synced). A no-op when
    /// no marker exists.
    ///
    /// A clear failure is itself POST-COMMIT MAINTENANCE: the stale marker
    /// stays on disk (harmless — every read is keyed on the history floor,
    /// never this flag) and the next same-deployment checkpoint re-clears
    /// it; the checkpoint flow surfaces the failure truthfully as
    /// `CheckpointReport::cleanup_clear_failed`. The error is PROPAGATED
    /// here so the caller can distinguish a converged clear from a stale
    /// marker.
    pub fn clear_cleanup_pending(&self, target: &str) -> Result<()> {
        let p = self.cleanup_pending_path(target);
        if p.exists() {
            // Fault hook (keyed by TARGET — the marker lives under
            // `targets/<target>/refs/`, mirroring the rotation-debt kinds),
            // fired BEFORE any I/O: a failure here leaves the marker in
            // place (stale but harmless).
            #[cfg(test)]
            if self
                .fault_registry()
                .consume(FaultKind::ClearCleanupPending, target)
            {
                return Err(Error::store(
                    "test fault: cleanup-pending marker clear forced to fail once",
                ));
            }
            std::fs::remove_file(&p).map_err(|e| {
                Error::store(format!(
                    "remove cleanup-pending marker {}: {e}",
                    p.display()
                ))
            })?;
            // DURABLE removal: propagate the parent-dir sync error exactly
            // like every other durability commit point in this module — a
            // crash must never resurrect the marker.
            sync_parent_dir(&p)
        } else {
            Ok(())
        }
    }

    /// The exact discard set a checkpoint floor applies on `target`: the
    /// attempts before the checkpoint's own attempt, the snapshots with
    /// `index < floor.snapshot_index`, and the union of their deployment ids
    /// (the `deployments/<id>/` directories the compaction deletes). Pure
    /// read over the physical logs; the dry-run preview and the compaction
    /// itself share it, so the preview enumerates EXACTLY what the
    /// compaction removes. Crate-private: only the checkpoint flow (and the
    /// in-crate integrity tests) computes discards.
    pub(crate) fn checkpoint_discards(
        &self,
        target: &str,
        floor: &HistoryFloor,
    ) -> Result<FloorDiscards> {
        let attempts = self.read_attempts_raw(target)?;
        let snapshots = self.read_snapshots_raw(target)?;
        // FAIL CLOSED: the floor's deployment MUST be in the target's
        // attempts log. The old `unwrap_or(0)` fallback silently discarded
        // EVERYTHING before the checkpoint (including the checkpoint's own
        // attempt) when the id was missing; with the read-time binding this
        // is unreachable via the public flow, but the raw path must still
        // refuse rather than guess.
        let keep_from = attempts
            .iter()
            .position(|a| a.deployment_id == floor.deployment_id)
            .ok_or_else(|| {
                Error::integrity(format!(
                    "checkpoint discard computation for target '{target}': the floor's deployment '{}' does not exist in the target's attempts log — refusing to enumerate discards for an unbound floor",
                    floor.deployment_id
                ))
            })?;
        let discarded_attempts: Vec<String> = attempts
            .iter()
            .take(keep_from)
            .map(|a| a.deployment_id.as_str().to_string())
            .collect();
        let discarded_snapshots: Vec<u64> = snapshots
            .iter()
            .filter(|s| s.index < floor.snapshot_index)
            .map(|s| s.index)
            .collect();
        // Deployment dirs strictly before the floor: every snapshot
        // deployment below the floor plus every failed attempt before the
        // checkpoint's own attempt (failed attempts carry no snapshot entry
        // but still own a `deployments/<id>/` directory). Deduplicated in a
        // deterministic order: snapshot-derived ids first (by snapshot
        // index), then attempt-derived ids not already listed.
        let mut discarded_deployments: Vec<String> = Vec::new();
        for s in snapshots.iter().filter(|s| s.index < floor.snapshot_index) {
            let id = s.deployment_id.as_str().to_string();
            if !discarded_deployments.contains(&id) {
                discarded_deployments.push(id);
            }
        }
        for a in attempts.iter().take(keep_from) {
            let id = a.deployment_id.as_str().to_string();
            if !discarded_deployments.contains(&id) {
                discarded_deployments.push(id);
            }
        }
        Ok(FloorDiscards {
            discarded_attempts,
            discarded_snapshots,
            discarded_deployments,
        })
    }

    /// Physically compact the target's history to the suffix at/after
    /// `floor` (the compaction half of a checkpoint; the floor marker must
    /// already be durable — [`LocalStore::write_history_floor`] first):
    ///
    /// 1. Delete every `deployments/<id>/` directory strictly before the
    ///    floor.
    /// 2. Atomically rewrite `attempts.jsonl` to the checkpoint's own
    ///    attempt and everything after it.
    /// 3. Atomically rewrite `snapshots.jsonl` to `index >= floor.snapshot_index`.
    ///
    /// The deletion runs FIRST because it is the only phase whose worklist
    /// lives solely in memory: [`LocalStore::checkpoint_discards`] derives
    /// it from the RAW logs at the start of THIS call. Deleting before the
    /// log rewrites keeps that derivation source intact, so an interruption
    /// at ANY point (and any subsequent retry) recomputes the same list from
    /// the still-intact — or already-rewritten — logs and converges:
    /// already-removed dirs are skipped by `dir.exists()`, and the
    /// temp+rename rewrites leave old-or-new logs. Reversing the order would
    /// lose the worklist permanently: once the logs are compacted the
    /// discarded ids are gone from them, so a retry could never re-enumerate
    /// — let alone delete — the below-floor directories (failed attempts own
    /// a `deployments/<id>/` dir but NO snapshot line, so nothing else names
    /// them). Delete-first is safe because the durable floor already gates
    /// every read path (`read_attempts`/`read_snapshots`/ref resolution),
    /// so deleting first can never expose discarded history.
    ///
    /// Each rewrite is a temp+rename so a reader never sees a torn log, and
    /// the floor marker already gates every read path — an interruption at
    /// any point leaves the durable floor bounding the visible history (old
    /// physical files remain but are invisible below the floor). The delete
    /// set is EXACTLY [`LocalStore::checkpoint_discards`]'s
    /// `discarded_deployments`, recomputed from the CURRENT logs on every
    /// call — the cleanup-pending debt FLAG
    /// ([`LocalStore::read_cleanup_pending`]) is never consulted for the
    /// worklist (a corrupted/tampered marker could otherwise name retained
    /// or unrelated deployment dirs): delete-first ordering guarantees the
    /// logs still name the worklist whenever deletion runs, so a retry
    /// recomputes the same list and converges (the marker only carries the
    /// durable pending-flag / needs-repair signal, decided by
    /// [`LocalStore::read_cleanup_pending`] in the checkpoint flow).
    pub(crate) fn checkpoint_compact(&self, target: &str, floor: &HistoryFloor) -> Result<()> {
        // Recomputed from the CURRENT (still-intact or already-rewritten)
        // logs on every call — this is what makes an interrupted compaction
        // converge on retry, so it must run BEFORE any log rewrite below.
        let discards = self.checkpoint_discards(target, floor)?;

        // 1. Delete deployment dirs strictly below the floor (ONLY the
        //    deployment ids the target's own history names — never a
        //    directory of another target, never releases/objects/servers,
        //    never a retained at/above-floor dir). First, while the logs
        //    still name every discarded id; a retry recomputes this same
        //    worklist from the intact logs and `dir.exists()` skips the
        //    dirs an interrupted pass removed. The delete set is exactly
        //    the log-derived discard set — a corrupted cleanup marker must
        //    never widen it.
        let dirs_to_delete = discards.discarded_deployments.clone();
        #[cfg(test)]
        if self
            .fault_registry()
            .consume(FaultKind::CompactDeployments, floor.deployment_id.as_str())
        {
            return Err(Error::store(
                "test fault: checkpoint deployment dir deletion forced to fail once",
            ));
        }
        for id in &dirs_to_delete {
            let dir = self.deployment_dir(id);
            if dir.exists() {
                std::fs::remove_dir_all(&dir).map_err(|e| {
                    Error::store(format!("remove deployment dir {}: {e}", dir.display()))
                })?;
            }
        }

        // 2. attempts.jsonl → the suffix from the checkpoint's own attempt.
        #[cfg(test)]
        if self
            .fault_registry()
            .consume(FaultKind::CompactAttempts, floor.deployment_id.as_str())
        {
            return Err(Error::store(
                "test fault: checkpoint attempts rewrite forced to fail once",
            ));
        }
        let attempts = self.read_attempts_raw(target)?;
        // FAIL CLOSED: the floor's deployment id must be in the target's
        // attempts log. The old `unwrap_or(&attempts[..])` silently KEPT ALL
        // attempts when the id was absent (the opposite of the discard
        // fallback's silent discard-everything); both must be errors, and
        // with the raw-time binding this is unreachable via the public flow.
        let pos = attempts
            .iter()
            .position(|a| a.deployment_id == floor.deployment_id)
            .ok_or_else(|| {
                Error::integrity(format!(
                    "checkpoint compaction for target '{target}': the floor's deployment '{}' does not exist in the target's attempts log — refusing to compact against an unbound floor",
                    floor.deployment_id
                ))
            })?;
        let keep = &attempts[pos..];
        write_jsonl_atomic(&self.target_dir(target).join("attempts.jsonl"), keep)?;

        // 3. snapshots.jsonl → the suffix at/after the floor.
        #[cfg(test)]
        if self
            .fault_registry()
            .consume(FaultKind::CompactSnapshots, floor.deployment_id.as_str())
        {
            return Err(Error::store(
                "test fault: checkpoint snapshots rewrite forced to fail once",
            ));
        }
        let snapshots = self.read_snapshots_raw(target)?;
        let keep_snaps: Vec<DeploymentSnapshot> = snapshots
            .iter()
            .filter(|s| s.index >= floor.snapshot_index)
            .cloned()
            .collect();
        write_jsonl_atomic(&self.refs_dir(target).join("snapshots.jsonl"), &keep_snaps)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history;
    use crate::model::{DeploymentId, TargetName};
    use crate::records::DeploymentAttempt;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::collections::BTreeMap;
    use std::sync::Arc;

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
    /// attempt gets a `deployments/<id>/` directory; every successful
    /// attempt appends a snapshot with the next unique index (mirroring the
    /// checkpoint suite's seeding).
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

    /// A floor marker naming `id` at snapshot `index` (the seeded history
    /// already carries the bound attempt + snapshot, so the marker reads
    /// back bound to the exact snapshot pair).
    fn floor_for(target: &str, id: &str, snapshot_index: u64) -> HistoryFloor {
        HistoryFloor {
            schema_version: SCHEMA_VERSION,
            target: TargetName::new(target.to_string()),
            deployment_id: DeploymentId::new(id.to_string()),
            snapshot_index,
            established_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    /// The ENTIRE visible state of `target` under `floor`: the gated
    /// snapshot/attempt lists and the below-floor ref refusal. A failed
    /// ADVANCE must leave this EXACTLY unchanged (identical lists, the same
    /// below-A refs refused).
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct VisibleState {
        snapshots: Vec<(u64, String)>,
        attempts: Vec<String>,
        below_floor_ref_err: Option<String>,
    }

    fn capture_visible(store: &LocalStore, floor: &HistoryFloor) -> VisibleState {
        // The ref just below the floor must be REFUSED (never a resolved
        // below-floor snapshot); capture the exact refusal message so the
        // post-advance state can be compared byte-for-byte.
        let below_floor_ref_err = if floor.snapshot_index > 0 {
            let expr = history::parse_ref_expr(&format!("s{}", floor.snapshot_index - 1)).unwrap();
            Some(
                history::resolve_ref_expr(&expr, TARGET, store)
                    .unwrap_err()
                    .to_string(),
            )
        } else {
            None
        };
        VisibleState {
            snapshots: store
                .read_snapshots(TARGET)
                .unwrap()
                .iter()
                .map(|s| (s.index, s.deployment_id.as_str().to_string()))
                .collect(),
            attempts: store
                .read_attempts(TARGET)
                .unwrap()
                .iter()
                .map(|a| a.deployment_id.as_str().to_string())
                .collect(),
            below_floor_ref_err,
        }
    }

    /// NO TEMPORARY TRANSACTION FILES may survive a failed advance: the
    /// marker is the restored A, the ONLY file in `refs/` beyond the
    /// durable op log (`snapshots.jsonl`) — no B temp
    /// (`.history-floor.json.tmp.<pid>.<n>`), no leftover `.prev` backup.
    /// (A tagged-backup sibling may rename the backup artifact at merge
    /// time; this asserts the ABSENCE of any temp/backup, not a specific
    /// backup name.)
    fn assert_no_transaction_artifacts(store: &LocalStore) {
        let refs = store.refs_dir(TARGET);
        assert!(
            refs.join("history-floor.json").exists(),
            "the restored A marker is present"
        );
        let mut entries: Vec<String> = std::fs::read_dir(&refs)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        let expected: Vec<String> = ["history-floor.json", "snapshots.jsonl"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            entries, expected,
            "refs/ holds EXACTLY the durable op log and the restored A marker — no temp file, no leftover backup, got: {entries:?}"
        );
    }

    proptest! {
        // THE REAL-B-TEMP-RENAME-FAILURE PROPERTY: a genuine filesystem
        // error on the ACTUAL temp→marker rename — the seam fails the real
        // rename(2) call AFTER A was backed up — routes through the SAME
        // cleanup-and-restore handler as the injected faults: the advance
        // returns `Err` and leaves EXACTLY the pre-advance state (floor A
        // installed, the visible suffix unchanged, below-A refs still
        // refused, no temporary transaction files). Deterministic: the SAME
        // generator under the pinned 0x5EED_5EED seed runs identical
        // vectors on every invocation (bounded cases keep the suite fast;
        // each case drives a fresh fixture).
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn real_b_temp_rename_failure_restores_a(
            history in prop::collection::vec(any::<bool>(), 3..6),
            a_at in 0usize..8,
        ) {
            run_real_b_temp_rename_failure_case(&history, a_at);
        }
    }

    /// One REAL-B-TEMP-RENAME-FAILURE case: establish floor A over a seeded
    /// history, arm the injectable filesystem boundary ([`TestFloorFsOps`])
    /// to fail the ACTUAL temp→marker rename (after A was backed up), drive
    /// the advance A → B, and assert:
    ///
    /// * the advance returns `Err` (the REAL rename error, not the injected
    ///   fault),
    /// * A REMAINS INSTALLED — `read_history_floor(target)` == A (same
    ///   deployment_id/snapshot_index, never None),
    /// * the VISIBLE SUFFIX is exactly unchanged (read_snapshots/
    ///   read_attempts identical to before the attempt; the below-A ref is
    ///   still refused),
    /// * NO TEMPORARY TRANSACTION FILES remain (no B temp, no leftover
    ///   backup — refs/ holds exactly the restored A marker + the op log).
    ///
    /// Then the fault-free CONTROL: the same fixture advances to B and
    /// reads back as B.
    fn run_real_b_temp_rename_failure_case(history_in: &[bool], a_at: usize) {
        // Seeding (mirroring the checkpoint suite): a guaranteed early
        // success, a guaranteed FAILED attempt, the randomized history, and
        // a guaranteed FINAL success so B is always a strictly-later
        // successful deployment.
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
        // the last success). Its snapshot index is its position among the
        // successes (snapshots are minted in order).
        let a_id = ok_ids[a_at % (ok_ids.len() - 1)].clone();
        let a_index = ok_ids.iter().position(|id| *id == a_id).unwrap() as u64;
        let b_id = ok_ids.last().unwrap().clone();
        let b_index = (ok_ids.len() - 1) as u64;
        assert_ne!(a_id, b_id, "B must be a later deployment than A");

        // Establish floor A (direct marker write — the seeded history
        // already carries A's attempt + snapshot, so the marker reads back
        // bound to the exact snapshot pair).
        let floor_a = floor_for(TARGET, &a_id, a_index);
        store.write_history_floor(TARGET, &floor_a).unwrap();
        let a_floor = store.read_history_floor(TARGET).unwrap().unwrap();
        assert_eq!(a_floor.deployment_id.as_str(), a_id);
        assert_eq!(a_floor.snapshot_index, a_index);

        // PRE-ADVANCE visible state: floor A, the gated suffix, and the
        // below-A ref refusal.
        let pre = capture_visible(&store, &a_floor);

        // ARM THE INJECTABLE FILESYSTEM BOUNDARY: fail the REAL
        // temp→marker rename — the ACTUAL rename(2) call AFTER A was backed
        // up — matched by (src = the staged temp name, dst = the marker
        // path), so the A→backup rename and the restore's rename pass
        // through to the real filesystem. The seam also RECORDS every
        // rename, so the case can prove the failure fired after A moved.
        let seam = Arc::new(TestFloorFsOps::new());
        let marker = store.history_floor_path(TARGET);
        let fail_marker = marker.clone();
        let fail_prefix = format!(".{}.tmp.", marker.file_name().unwrap().to_string_lossy());
        seam.fail_rename_once(move |src, dst| {
            src.file_name()
                .map(|n| n.to_string_lossy().starts_with(&fail_prefix))
                .unwrap_or(false)
                && dst == fail_marker.as_path()
        });
        let _guard = FloorFsSeamGuard::install(seam.clone());

        // DRIVE THE ADVANCE A → B: the real temp→marker rename FAILS (a
        // genuine fs error on the actual call, after A was moved aside to
        // the durable backup).
        let floor_b = floor_for(TARGET, &b_id, b_index);
        let err = store
            .write_history_floor(TARGET, &floor_b)
            .expect_err("the real temp→marker rename failure must fail the advance");
        assert!(
            err.to_string()
                .contains("test fault: real floor rename forced to fail once"),
            "the REAL rename error (through the fs boundary) is the cause, got: {err}"
        );
        assert!(
            !err.to_string()
                .contains("test fault: history-floor rename forced to fail once"),
            "the injected fault must NOT be the cause — the seam failed the actual fs call, got: {err}"
        );
        // The seam observed the REAL backup rename (A moved aside) BEFORE
        // the failing temp→marker rename — the failure happened after A was
        // backed up.
        let renames = seam.renames();
        assert!(
            renames.len() >= 2
                && renames[0] == (marker.clone(), floor_backup_path(&marker, &b_id))
                && renames[1].1 == marker,
            "the seam must observe the REAL backup rename followed by the failing temp→marker rename, got: {renames:?}"
        );

        // A REMAINS INSTALLED — the ORIGINAL floor, never None, never B.
        let floor = store.read_history_floor(TARGET).unwrap();
        let f = floor
            .as_ref()
            .expect("a real temp→marker rename failure must retain floor A — never None");
        assert_eq!(
            f.deployment_id.as_str(),
            a_id,
            "the ORIGINAL floor deployment A survives the real rename failure"
        );
        assert_eq!(
            f.snapshot_index, a_index,
            "the ORIGINAL floor index survives the real rename failure"
        );

        // THE VISIBLE SUFFIX IS EXACTLY UNCHANGED: identical gated
        // snapshots/attempts, and the same below-A refs still refused.
        let post = capture_visible(&store, f);
        assert_eq!(
            post.snapshots, pre.snapshots,
            "the visible snapshot suffix is exactly unchanged"
        );
        assert_eq!(
            post.attempts, pre.attempts,
            "the visible attempts suffix is exactly unchanged"
        );
        assert_eq!(
            post.below_floor_ref_err, pre.below_floor_ref_err,
            "the same below-A refs stay refused"
        );

        // NO TEMPORARY TRANSACTION FILES remain: the marker is the restored
        // A — no B temp file, no leftover backup (refs/ holds exactly the
        // restored marker + the op log).
        assert_no_transaction_artifacts(&store);

        // CONTROL: the fault-free advance to B SUCCEEDS on the same fixture
        // (the failed attempt left the store fully usable) and reads back
        // as B.
        store
            .write_history_floor(TARGET, &floor_b)
            .expect("the fault-free advance to B succeeds");
        let b_floor = store.read_history_floor(TARGET).unwrap().unwrap();
        assert_eq!(b_floor.deployment_id.as_str(), b_id);
        assert_eq!(b_floor.snapshot_index, b_index);
    }

    /// CONTROL: the injected [`FaultKind::RenameFloor`] fault (fires BEFORE
    /// the rename I/O) still routes through the SAME cleanup-and-restore
    /// handler — A is restored, the visible suffix is unchanged, and no
    /// transaction artifacts remain (regression guard for the unified
    /// handler).
    #[test]
    fn rename_floor_fault_still_restores_a() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        seed_history(&store, TARGET, "deploy", &[true, true]);
        let a_id = "deploy-0000".to_string();
        let b_id = "deploy-0001".to_string();
        let floor_a = floor_for(TARGET, &a_id, 0);
        store.write_history_floor(TARGET, &floor_a).unwrap();
        let a_floor = store.read_history_floor(TARGET).unwrap().unwrap();
        let pre = capture_visible(&store, &a_floor);

        let floor_b = floor_for(TARGET, &b_id, 1);
        store.fault_registry().arm_rename_floor(&b_id);
        let err = store
            .write_history_floor(TARGET, &floor_b)
            .expect_err("the RenameFloor fault fails the advance");
        assert!(
            err.to_string()
                .contains("test fault: history-floor rename forced to fail once"),
            "the injected fault is the cause, got: {err}"
        );

        // A remains installed (never None, never B) and the visible suffix
        // is exactly unchanged.
        let floor = store.read_history_floor(TARGET).unwrap();
        let f = floor
            .as_ref()
            .expect("the injected RenameFloor fault must retain floor A — never None");
        assert_eq!(f.deployment_id.as_str(), a_id);
        assert_eq!(f.snapshot_index, 0);
        let post = capture_visible(&store, f);
        assert_eq!(post.snapshots, pre.snapshots);
        assert_eq!(post.attempts, pre.attempts);
        assert_eq!(post.below_floor_ref_err, pre.below_floor_ref_err);
        assert_no_transaction_artifacts(&store);
    }

    /// CONTROL: a REAL rename failure BEFORE A was backed up (the actual
    /// A→backup rename errors through the seam) leaves A untouched at the
    /// marker name — the cleanup-and-restore handler's `path` guard keeps
    /// the previous floor when no backup exists (`had_floor == true`, no
    /// `.prev`), and drops only B's staged temp.
    #[test]
    fn real_rename_failure_before_backup_leaves_a_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        seed_history(&store, TARGET, "deploy", &[true, true]);
        let a_id = "deploy-0000".to_string();
        let b_id = "deploy-0001".to_string();
        let floor_a = floor_for(TARGET, &a_id, 0);
        store.write_history_floor(TARGET, &floor_a).unwrap();

        // Arm the seam to fail the REAL A→backup rename (src = the marker
        // path, dst = the backup path) — BEFORE A was moved aside.
        let seam = Arc::new(TestFloorFsOps::new());
        let marker = store.history_floor_path(TARGET);
        let fail_marker = marker.clone();
        let fail_backup = floor_backup_path(&marker, &b_id);
        seam.fail_rename_once(move |src, dst| {
            src == fail_marker.as_path() && dst == fail_backup.as_path()
        });
        let _guard = FloorFsSeamGuard::install(seam);

        let floor_b = floor_for(TARGET, &b_id, 1);
        let err = store
            .write_history_floor(TARGET, &floor_b)
            .expect_err("the real backup-rename failure fails the advance");
        assert!(
            err.to_string().contains("rename floor"),
            "the real backup-rename error propagates, got: {err}"
        );

        // A is STILL at the marker name (never moved, never removed): the
        // failed advance leaves the previous floor untouched.
        let floor = store.read_history_floor(TARGET).unwrap().unwrap();
        assert_eq!(floor.deployment_id.as_str(), a_id);
        assert_eq!(floor.snapshot_index, 0);
        assert!(marker.exists(), "A's marker is never removed");
        assert!(
            !floor_backup_path(&marker, &b_id).exists(),
            "no backup was ever created by the failed backup rename"
        );
        // The handler still dropped B's staged temp.
        assert_no_transaction_artifacts(&store);
    }
}
