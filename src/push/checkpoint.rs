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
//!    directory fsync in [`LocalStore::write_history_floor`]).
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
//! # Concurrency
//!
//! The real operation runs under the SAME lock discipline as pushes
//! ([`crate::push::engine::FileLock`]): the application-store lock then the
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
use crate::model::{DeploymentId, OperationId, SCHEMA_VERSION, TargetName};
use crate::push::engine::FileLock;
use crate::records::HistoryFloor;
use crate::store::local::{FloorDiscards, LocalStore};

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

/// The real (locked) checkpoint: write the durable floor marker FIRST, then
/// compact. An interrupted compaction (fault/crash) is self-healing: a
/// repeated checkpoint of the same deployment finishes the pending physical
/// compaction.
fn checkpoint_inner(
    store: &LocalStore,
    target: &str,
    deployment_id: &DeploymentId,
) -> Result<CheckpointReport> {
    let floor = plan_floor(store, target, deployment_id)?;

    // Idempotency: re-checkpointing the SAME deployment id is a no-op when
    // the physical logs are already compacted, and finishes an interrupted
    // compaction otherwise (the floor marker already bounds every read).
    if let Some(current) = store.read_history_floor(target)?
        && current.deployment_id == floor.deployment_id
    {
        let discards = store.checkpoint_discards(target, &floor)?;
        let needs_repair = !discards.discarded_attempts.is_empty()
            || !discards.discarded_snapshots.is_empty()
            || !discards.discarded_deployments.is_empty();
        if needs_repair {
            store.checkpoint_compact(target, &floor)?;
            return Ok(CheckpointReport {
                target: target.to_string(),
                deployment_id: deployment_id.clone(),
                snapshot_index: floor.snapshot_index,
                discards,
                established: true,
                dry_run: false,
            });
        }
        return Ok(CheckpointReport {
            target: target.to_string(),
            deployment_id: deployment_id.clone(),
            snapshot_index: floor.snapshot_index,
            discards: FloorDiscards::default(),
            established: false,
            dry_run: false,
        });
    }

    // Durability ordering: the marker is durable BEFORE anything is
    // discarded, then the physical compaction rewrites the logs and deletes
    // the below-floor deployment directories.
    store.write_history_floor(target, &floor)?;
    let discards = store.checkpoint_discards(target, &floor)?;
    store.checkpoint_compact(target, &floor)?;
    Ok(CheckpointReport {
        target: target.to_string(),
        deployment_id: deployment_id.clone(),
        snapshot_index: floor.snapshot_index,
        discards,
        established: true,
        dry_run: false,
    })
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
        dry_run: true,
    })
}

/// Render a checkpoint report for the CLI: a dry-run preview enumerates what
/// WOULD be discarded; an established floor reports what WAS discarded; a
/// pure idempotent no-op says so. The CLI prints exactly these lines; the
/// unit tests assert on them directly.
pub fn render_checkpoint_report(report: &CheckpointReport) -> Vec<String> {
    let mut lines = Vec::new();
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
    } else {
        format!(
            "checkpoint already established: history floor at snapshot s{} (deployment {}) of target {} — nothing to discard",
            report.snapshot_index, report.deployment_id, report.target
        )
    };
    lines.push(head);
    // A pure idempotent no-op has nothing to enumerate.
    if !report.dry_run && !report.established {
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
    lines
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::{self, PushRef};
    use crate::model::{DeploymentId, ReleaseId, SCHEMA_VERSION, TargetName, TreeDigest};
    use crate::records::{DeploymentAttempt, DeploymentSnapshot};
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::collections::BTreeMap;
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

    /// Seed the never-delete guard rails: a release record + aux, a tree
    /// object, and a server state file. These must survive every checkpoint.
    fn seed_never_delete(store: &LocalStore) -> (ReleaseId, TreeDigest, String) {
        let rel = ReleaseId::new("rel-sha256-checkpoint-never".to_string());
        let dir = store.release_dir(&rel);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("release.json"), b"{}").unwrap();
        let tree = TreeDigest::new("tree-never-delete".to_string());
        let root = store.object_root(&tree);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("x"), b"x").unwrap();
        let server = store.base().join("servers").join("s-never.json");
        std::fs::write(&server, b"{}").unwrap();
        (rel, tree, server.to_string_lossy().into_owned())
    }

    fn assert_never_delete(store: &LocalStore, rel: &ReleaseId, tree: &TreeDigest, server: &str) {
        assert!(
            store.release_dir(rel).join("release.json").exists(),
            "release records are never deleted"
        );
        assert!(
            store.object_root(tree).join("x").exists(),
            "objects are never deleted"
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
        // backward".
        let s2 = LocalStore::with_base(tmp.path().join("s2")).unwrap();
        seed_history(&s2, TARGET, "deploy", &[true, true, true]);
        s2.fault_registry().arm_compact_attempts("deploy-0001");
        run_checkpoint(
            &s2,
            TARGET,
            &DeploymentId::new("deploy-0001".to_string()),
            false,
        )
        .expect_err("the delete-phase fault interrupts the compaction");
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
        // Interrupted cleanup: the compaction is faulted mid-way (deletion
        // or rewrite phase) AFTER the floor marker is durable. The visible
        // history must NEVER dip below the durable floor, the checkpoint
        // snapshot stays resolvable, and the below-floor refs stay refused.
        // The seeded history always includes a FAILED attempt (a deployment
        // dir with NO snapshot) below any non-zero floor, so the retry must
        // also converge to delete the failed-without-snapshot dirs from the
        // ORIGINAL worklist.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_1D57),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn interrupted_cleanup_never_exposes_below_the_floor(
            history in prop::collection::vec(any::<bool>(), 3..7),
            checkpoint_at in 0usize..8,
            phase in 0usize..3,
        ) {
            run_interrupted_cleanup_case(&history, checkpoint_at, phase);
        }
    }

    fn run_interrupted_cleanup_case(history_in: &[bool], checkpoint_at: usize, phase: usize) {
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

        // Arm the compaction fault for the phase under test (keyed by the
        // checkpoint deployment id).
        match phase {
            0 => store.fault_registry().arm_compact_attempts(&target_id),
            1 => store.fault_registry().arm_compact_snapshots(&target_id),
            _ => store.fault_registry().arm_compact_deployments(&target_id),
        }
        let err = run_checkpoint(&store, TARGET, &DeploymentId::new(target_id.clone()), false)
            .expect_err("the armed compaction fault interrupts the checkpoint");
        assert!(err.to_string().contains("test fault"));

        // The floor marker is DURABLE and the readers never expose history
        // below it — the core property.
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

        // Repeating the same checkpoint either finishes the interrupted
        // compaction or is a clean no-op — never an error, never a backward
        // move. Because the reordered compaction deletes FIRST, an
        // interruption in ANY phase leaves the worklist re-derivable from
        // the (intact or already-rewritten) logs; a floor at index 0 has
        // nothing below it to repair, everything else is repaired by the
        // repeat.
        let retry = run_checkpoint(&store, TARGET, &DeploymentId::new(target_id.clone()), false)
            .expect("a repeated checkpoint after interruption must succeed");
        let marker_after = store.read_history_floor(TARGET).unwrap().unwrap();
        assert_eq!(marker_after.snapshot_index, floor_index);
        let visible_after = store.read_snapshots(TARGET).unwrap();
        assert!(visible_after.iter().all(|s| s.index >= floor_index));
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
}
