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
//! backup (`history-floor.json.prev`) and restored if B fails before its
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
//! TRANSACTIONAL ([`LocalStore::write_history_floor`]): B's marker is
//! staged, the current floor A is moved aside to a durable backup
//! (`history-floor.json.prev`), B is renamed into place, and the
//! parent-directory fsync is B's durability commit point. A failure at ANY
//! stage before that commit point RESTORES A from the backup, so a failed
//! advancement leaves EXACTLY the pre-advance state (floor A durable, the
//! same visible suffix, no compaction side effects) — advancing a
//! checkpoint can never erase the previously durable floor. If the restore
//! of A itself ALSO fails, the marker may be left absent while `.prev`
//! holds A: every read fails closed with an integrity error (a torn
//! advance is never treated as "no floor", which would expose the
//! below-floor prefix); recovery is to remove the stale `.prev` (reads
//! then report no floor, and the next checkpoint re-establishes one).
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

/// The durable backup name of a history-floor marker: the marker name with
/// a `.prev` suffix, in the SAME directory. A TRANSACTIONAL floor ADVANCE
/// ([`LocalStore::write_history_floor`]) moves the current floor A here
/// BEFORE B's marker can overwrite the marker name, and a failed advance
/// renames it back; the reader ([`LocalStore::read_history_floor`]) fails
/// closed when the marker is ABSENT but this backup exists (a torn
/// advance: A was moved aside, its restore failed — never "no floor",
/// which would expose the below-floor prefix).
fn floor_backup_path(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        "{}.prev",
        path.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default()
    ))
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
    /// erase the previously durable floor A:
    ///
    /// 1. entry fault → `Err`, A untouched,
    /// 2. stage B's temp (write + chmod private + fsync); a fault → `Err`,
    ///    A untouched (no rename has happened yet),
    /// 3. move A aside to the durable backup `history-floor.json.prev` in
    ///    the same directory, then fsync the parent so the BACKUP is
    ///    durable BEFORE B can overwrite the marker name; a fault or a real
    ///    backup-sync error → restore A from the backup + `Err`,
    /// 4. rename B's temp into place (atomic); a fault → restore A + `Err`,
    /// 5. fsync the parent directory — B's DURABILITY COMMIT POINT — errors
    ///    PROPAGATED; a fault (the marker may already be renamed into
    ///    place) → unlink B's marker, restore A from the backup, and
    ///    `Err`: B never committed, A is durable again,
    /// 6. committed: remove the backup (best-effort — a stale `.prev` is
    ///    harmless: every read is keyed on the marker, never the backup),
    ///    then fsync the parent so the removal is durable.
    ///
    /// The RESTORE ([`LocalStore::restore_floor_backup`]) is the
    /// fail-closed half: a restore failure leaves the marker absent while
    /// `.prev` still holds A — the readers
    /// ([`LocalStore::read_history_floor`]) then fail closed (a `.prev`
    /// with no marker is a torn advance, never "no floor", which would
    /// expose the below-floor prefix). Every stage error is returned from
    /// THIS method (PRE-commit): B is never reported established unless its
    /// parent-dir sync succeeded.
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
        // directory. An ADVANCE moves A here before B can overwrite the
        // marker name, so a failed advancement can always rename A back:
        // the previously durable floor is never erased by an advance B
        // cannot finish.
        let backup = floor_backup_path(&path);
        let had_floor = path.exists();
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
            // ---- TRANSACTIONAL ADVANCE, stage 1: BACKUP A ----------------
            // Move the current floor A aside to the durable backup BEFORE B
            // can overwrite the marker name, and make the backup durable
            // (parent fsync) first: from here on, any failure can rename A
            // back — the pre-advance state is never lost. The fault fires
            // BEFORE the rename (A still in place); a real rename or sync
            // failure restores A and fails the advance.
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
            std::fs::rename(&path, &backup).map_err(|e| {
                // A may or may not have moved; attempt the restore either
                // way so the failed advance leaves the pre-advance state
                // (floor A durable — or, if the restore itself fails, a
                // torn state every read fails closed on).
                let restore =
                    self.restore_floor_backup(&path, &backup, floor.deployment_id.as_str());
                match restore {
                    Ok(()) => Error::store(format!("rename floor {}: {e}", path.display())),
                    Err(re) => Error::store(format!(
                        "rename floor {}: {e}; restore of the previous floor failed ({re}) — the marker is left in a torn state and every read fails closed",
                        path.display()
                    )),
                }
            })?;
            // The BACKUP must be durable before B can overwrite the marker
            // name: without this sync, a later failure could leave the
            // marker name empty with A only in a not-yet-durable backup.
            if let Err(e) = sync_parent_dir(&path) {
                let restore =
                    self.restore_floor_backup(&path, &backup, floor.deployment_id.as_str());
                return Err(match restore {
                    Ok(()) => e,
                    Err(re) => Error::store(format!(
                        "history-floor advance: backup parent sync failed ({e}); restore of the previous floor failed ({re}) — the marker is left in a torn state and every read fails closed"
                    )),
                });
            }
        }

        // Stage fault: the rename into place (B's temp → the marker name).
        // Fires BEFORE the rename; A is safe at the backup, so the failed
        // advance restores A and fails.
        #[cfg(test)]
        if self
            .fault_registry()
            .consume(FaultKind::RenameFloor, floor.deployment_id.as_str())
        {
            let _ = std::fs::remove_file(&tmp);
            let restore = self.restore_floor_backup(&path, &backup, floor.deployment_id.as_str());
            return Err(match restore {
                Ok(()) => Error::store("test fault: history-floor rename forced to fail once"),
                Err(re) => Error::store(format!(
                    "test fault: history-floor rename forced to fail once; restore of the previous floor failed ({re}) — the marker is left in a torn state and every read fails closed"
                )),
            });
        }
        std::fs::rename(&tmp, &path)
            .map_err(|e| Error::store(format!("rename {}: {e}", path.display())))?;

        // Stage fault: B's commit-point parent fsync (the durability
        // COMMIT POINT — B's marker may already be renamed into place when
        // this fires). Fail-closed: B never committed, so B's marker is
        // unlinked and A is restored from the backup — the failed
        // advancement leaves EXACTLY the pre-advance state (floor A
        // durable, same visible suffix, no compaction side effects).
        #[cfg(test)]
        if self
            .fault_registry()
            .consume(FaultKind::SyncFloorParent, floor.deployment_id.as_str())
        {
            // B may already be renamed into place: remove B's marker so no
            // B exists, then restore A from the backup (the marker name
            // reverts to the pre-advance floor). If the restore ITSELF
            // fails, the marker is left absent while `.prev` holds A — a
            // torn state every read fails closed on.
            let _ = std::fs::remove_file(&path);
            let restore = self.restore_floor_backup(&path, &backup, floor.deployment_id.as_str());
            return Err(match restore {
                Ok(()) => Error::store("test fault: history-floor parent sync forced to fail once"),
                Err(re) => Error::store(format!(
                    "test fault: history-floor parent sync forced to fail once; restore of the previous floor failed ({re}) — the marker is left in a torn state and every read fails closed"
                )),
            });
        }
        // The parent-directory fsync is B's DURABILITY COMMIT POINT: it is
        // what makes B's rename survive power loss. Fail-closed — a real
        // sync failure means B never committed, so B's marker is unlinked
        // and A is restored from the backup (mirror the torn-record
        // cleanup).
        if let Err(e) = sync_parent_dir(&path) {
            let _ = std::fs::remove_file(&path);
            let restore = self.restore_floor_backup(&path, &backup, floor.deployment_id.as_str());
            return Err(match restore {
                Ok(()) => e,
                Err(re) => Error::store(format!(
                    "history-floor advance: parent sync failed ({e}); restore of the previous floor failed ({re}) — the marker is left in a torn state and every read fails closed"
                )),
            });
        }
        // COMMITTED: B is durable. Remove the backup — best-effort (a stale
        // `.prev` is harmless: every read is keyed on the marker, never the
        // backup), then fsync the parent so the removal itself is durable.
        // A removal failure is absorbed: the next advance overwrites any
        // stale `.prev` when it moves the new floor aside.
        if had_floor && std::fs::remove_file(&backup).is_ok() {
            let _ = sync_parent_dir(&path);
        }
        Ok(())
    }

    /// Restore the PRE-ADVANCE floor A after a failed ADVANCE (A → B):
    /// rename the durable backup `history-floor.json.prev` back over the
    /// marker name (atomic on POSIX — it overwrites any half-installed B
    /// marker) and fsync the parent so the restore is durable. A no-op when
    /// no backup exists (the advance failed before A was ever moved aside —
    /// A is still the durable marker).
    ///
    /// FAIL-CLOSED: the [`FaultKind::RestoreFloor`](crate::testutil::test_faults::FaultKind::RestoreFloor) fault (and any real
    /// rename/sync error) makes the restore itself fail: A stays in the
    /// backup and the marker keeps the failed stage's state — possibly
    /// ABSENT. The readers ([`LocalStore::read_history_floor`]) then fail
    /// closed with an integrity error (a `.prev` with no marker is a torn
    /// advance, never "no floor" — which would expose the below-floor
    /// prefix), so a double failure can never expose history below A.
    fn restore_floor_backup(&self, path: &Path, backup: &Path, _deployment_id: &str) -> Result<()> {
        // Stage fault: the RESTORE itself (keyed by the checkpoint
        // deployment id, matching every other floor stage). Fires BEFORE
        // any restore I/O — the restore could not even begin, so `.prev`
        // still holds A and the marker keeps whatever state the failed
        // stage left.
        #[cfg(test)]
        if self
            .fault_registry()
            .consume(FaultKind::RestoreFloor, _deployment_id)
        {
            return Err(Error::store(
                "test fault: history-floor restore forced to fail once",
            ));
        }
        if !backup.exists() {
            // The advance failed before A was moved aside: A is still the
            // durable marker — nothing to restore.
            return Ok(());
        }
        std::fs::rename(backup, path)
            .map_err(|e| Error::store(format!("restore floor {}: {e}", path.display())))?;
        sync_parent_dir(path)
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
    /// * (d) TORN ADVANCE: when the marker is ABSENT but its durable backup
    ///   (`history-floor.json.prev`, the transactional-advance artifact of
    ///   [`LocalStore::write_history_floor`]) exists, an ADVANCE was
    ///   interrupted mid-flight and its restore of the previous floor A
    ///   failed — the marker cannot be trusted. This state is NEVER treated
    ///   as "no floor" (which would expose the below-floor prefix): it
    ///   fails closed with an integrity error. (A marker PRESENT alongside
    ///   a stale `.prev` is fine — the success path removes the backup
    ///   best-effort, and reads are keyed on the marker, never the
    ///   backup.)
    ///
    /// Each violation is an [`Error::integrity`] error, so a corrupted or
    /// tampered marker is NEVER silently treated as "no floor" (which would
    /// expose the below-floor prefix): the gated readers
    /// ([`LocalStore::read_attempts`] / [`LocalStore::read_snapshots`])
    /// propagate the error. Crate-private: non-crate consumers use the
    /// gated readers, never the marker directly.
    pub(crate) fn read_history_floor(&self, target: &str) -> Result<Option<HistoryFloor>> {
        let p = self.history_floor_path(target);
        // TORN-ADVANCE FAIL-CLOSED CHECK (the transactional-replacement
        // counterpart): when an ADVANCE (A → B) failed before B's durability
        // commit point AND the restore of A also failed, the marker may be
        // left ABSENT while the pre-advance floor A still sits in the
        // durable backup. The backup's presence with no marker means an
        // advance was interrupted mid-flight and the marker cannot be
        // trusted — fail closed (never "no floor", which would expose the
        // below-floor prefix). A marker PRESENT alongside a stale `.prev` is
        // fine: the success path removes the backup best-effort, and reads
        // are keyed on the marker, never the backup.
        if !p.exists() && floor_backup_path(&p).exists() {
            return Err(Error::integrity(format!(
                "history floor for target '{target}' is missing but its durable backup {} exists: a floor ADVANCE was interrupted and its restore failed — refusing to treat this as 'no floor' (which would expose the below-floor prefix)",
                floor_backup_path(&p).display()
            )));
        }
        if !p.exists() {
            return Ok(None);
        }
        // Parse-sensitive read: a present-but-malformed marker (truncation,
        // wrong types, missing fields) is semantic corruption → Integrity;
        // only an actual filesystem read failure is Store.
        let floor: HistoryFloor = read_json_marker(&p)?;
        if floor.schema_version != SCHEMA_VERSION {
            return Err(Error::integrity(format!(
                "history floor for target '{target}' carries unsupported schema_version {} (expected {SCHEMA_VERSION}): only SCHEMA_VERSION is accepted",
                floor.schema_version
            )));
        }

        // from. A marker with a foreign `target` is a tampered/corrupted
        // marker — it is refused, not interpreted as a floor for either the
        // path target or the named target.
        if floor.target.as_str() != target {
            return Err(Error::integrity(format!(
                "history floor marker at {} is not bound to its path: marker.target = '{}' but the marker was read for target '{target}' (a floor marker must name the target directory it lives in)",
                p.display(),
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
                "history floor for target '{target}' is not bound to a snapshot: no snapshot has EXACTLY index s{} AND deployment '{}' (the exact snapshot pair the marker names does not exist in refs/snapshots.jsonl)",
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
        Ok(Some(floor))
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
    /// temp+rename, mirroring [`LocalStore::write_history_floor`]).
    pub fn write_cleanup_pending(&self, target: &str, pending: &CleanupPending) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(pending)
            .map_err(|e| Error::store(format!("serialize cleanup-pending: {e}")))?;
        write_atomic_replace(&self.cleanup_pending_path(target), &bytes)
    }

    /// Clear the target's pending-checkpoint-cleanup marker once the
    /// physical compaction completed. A no-op when no marker exists.
    pub fn clear_cleanup_pending(&self, target: &str) -> Result<()> {
        let p = self.cleanup_pending_path(target);
        if p.exists() {
            std::fs::remove_file(&p).map_err(|e| {
                Error::store(format!(
                    "remove cleanup-pending marker {}: {e}",
                    p.display()
                ))
            })?;
        }
        Ok(())
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
