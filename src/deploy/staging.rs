//! Disposable staging lifecycle and cleanup.
//!
//! The dry-run staging guard ([`StagingCleanup`]), the explicit fallible
//! dry-run cleanup ([`cleanup_dry_run_staging`]), the shared
//! restore-owner-write + remove helpers ([`restore_owner_write_recursive`],
//! [`remove_tree_restoring_write`]) used by both the dry-run cleanup and
//! recovery-temp removal, and the A7 abandoned-incoming cleanup
//! ([`cleanup_abandoned_incoming`]: the pre-mutation removal of OTHER
//! deployments' leftover incoming staging trees). Extracted from
//! `push::engine`.

use crate::error::{Error, Result};
use crate::identity::DeploymentId;
use crate::remote::helper::RemoteHelper;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Restore owner-write permission (u+w, mode bit 0o200) on every directory and
/// file under `root` that lacks it, leaving all other mode bits untouched.
/// Materialized dry-run staging trees can contain read-only entries — artifact
/// source modes are preserved by [`crate::remote::materialize::materialize_variant`] — and
/// POSIX `remove_dir_all` needs write permission on every directory it enters,
/// so a read-only subdirectory makes the whole removal fail with EACCES.
/// Symlinks are never followed or modified.
fn restore_owner_write_recursive(root: &Path) -> std::io::Result<()> {
    fn walk(dir: &Path) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let ft = entry.file_type()?;
            if ft.is_dir() {
                walk(&path)?;
            } else if ft.is_symlink() {
                continue;
            }
            let mode = entry.metadata()?.permissions().mode();
            if mode & 0o200 == 0 {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode | 0o200))?;
            }
        }
        Ok(())
    }
    walk(root)?;
    let mode = std::fs::metadata(root)?.permissions().mode();
    if mode & 0o200 == 0 {
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(mode | 0o200))?;
    }
    Ok(())
}

/// Remove a directory tree, restoring owner-write permission on read-only
/// entries inside it first, then removing the whole tree. A missing tree is a
/// no-op. `remove_dir_all` needs write permission on every directory it enters
/// AND on the tree's parent; restoring u+w inside the tree fixes read-only
/// entries preserved from artifact source modes, but never the parent (that is
/// outside the tree's responsibility). Failures map to [`Error::transport`]
/// with `what` and the path in the message, so every caller (dry-run staging
/// cleanup, recovery temp removal) fails visibly instead of silently leaking
/// the tree.
pub(crate) fn remove_tree_restoring_write(root: &Path, what: &str) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    restore_owner_write_recursive(root)
        .map_err(|e| Error::transport(format!("{what} {}: {e}", root.display())))?;
    std::fs::remove_dir_all(root)
        .map_err(|e| Error::transport(format!("{what} {}: {e}", root.display())))?;
    Ok(())
}

/// Remove a dry-run's staging tree, propagating failures. Restores owner-write
/// permission on read-only entries inside the tree first (the tree cannot fix
/// permissions on its own parent), then removes the whole tree. A missing tree
/// is a no-op. Failures map to [`Error::transport`] with the path in the
/// message, so a dry run whose staging could not be cleaned fails visibly
/// instead of silently leaving `staging/dry-<id>` behind forever.
pub(crate) fn cleanup_dry_run_staging(root: &Path) -> Result<()> {
    remove_tree_restoring_write(root, "remove dry-run staging")
}

/// The A7 abandoned-incoming cleanup: before THIS deployment mutates a server,
/// remove every OTHER deployment's leftover `incoming/<id>` staging tree still
/// pending on that server (a crashed controller's abandoned staging). The
/// deployment's own id is never removed — its incoming was just staged by the
/// preflight and is still in use. Each removal is fallible and aborts the
/// push: an incoming tree that cannot be removed is a remote mutation that
/// would interleave with the abandoned staging. Extracted from the `push_inner`
/// mutating-remote phase (A7 hidden semantics).
pub(crate) fn cleanup_abandoned_incoming(
    helper: &RemoteHelper,
    pending_incoming: &[String],
    deployment_id: &DeploymentId,
) -> Result<()> {
    for pend in pending_incoming {
        if pend != deployment_id.as_str() {
            helper.remove_incoming(pend)?;
        }
    }
    Ok(())
}

/// Removes the disposable dry-run staging tree on drop (error, panic, or
/// normal exit), so an interrupted dry run never leaves state behind. This is
/// only a FALLBACK: the normal dry-run path runs the explicit fallible
/// [`cleanup_dry_run_staging`] and empties the guard first, so cleanup failures
/// surface as a push error rather than being silently swallowed. The Drop
/// performs the same permission-restore + remove best-effort (still silent),
/// so even panic/unwind paths clean read-only trees when they can.
pub(crate) struct StagingCleanup(pub(crate) Option<std::path::PathBuf>);
impl Drop for StagingCleanup {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = cleanup_dry_run_staging(&p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_cleanup_drop_removes_tree_take_prevents_removal() {
        let base = tempfile::tempdir().unwrap();

        // Drop removes the whole staging tree.
        let p = base.path().join("dry-a");
        std::fs::create_dir_all(p.join("nested")).unwrap();
        std::fs::write(p.join("nested/f"), b"x").unwrap();
        {
            let _g = StagingCleanup(Some(p.clone()));
            assert!(p.exists(), "tree survives while the guard is held");
        }
        assert!(!p.exists(), "drop must remove the staging tree");

        // Dropping a None guard is a no-op (non-dry-run path).
        drop(StagingCleanup(None));

        // take() hands ownership out: dropping the emptied guard keeps the
        // tree, dropping the taken value removes it.
        let q = base.path().join("dry-b");
        std::fs::create_dir_all(&q).unwrap();
        let mut g = StagingCleanup(Some(q.clone()));
        let taken = g.0.take();
        assert!(taken.is_some(), "take must yield the guarded path");
        drop(g);
        assert!(q.exists(), "emptied guard's drop must not remove anything");
        // Responsibility was handed out with take(): whoever re-wraps the path
        // into a guard gets cleanup on their own drop.
        drop(StagingCleanup(taken));
        assert!(!q.exists(), "the re-wrapped taken value cleans up on drop");
    }

    #[test]
    fn dry_run_cleanup_failure_is_reported() {
        // Injection: removing the staging root requires write permission on its
        // PARENT directory, and the cleanup only restores permissions INSIDE
        // its own tree (it must not touch anything outside). So a read-only
        // parent makes remove_dir_all fail with EACCES, and that failure must
        // surface as an Err — not a silent success that leaves the tree behind.
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("dry-x");
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("nested/f"), b"x").unwrap();
        // Parent becomes read-only AFTER the tree is built. This parent-side
        // injection is not reachable through a real materialize-then-push: a
        // push needs to CREATE the dry-<id> root inside staging, which requires
        // write on the parent at materialize time. So the failure injection is
        // unit-level, against the exact routine the dry-run branch calls;
        // the engine-level read-only-restore path is covered by
        // `dry_run_removes_readonly_staging_tree`.
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o555)).unwrap();

        let err = cleanup_dry_run_staging(&root).unwrap_err();
        assert!(
            matches!(err, Error::Transport(_)),
            "cleanup failure must be a transport error, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("remove dry-run staging") && msg.contains("dry-x"),
            "error must name the staging root, got: {msg}"
        );
        // The tree was NOT silently swallowed: it is still present, and the
        // dry-run branch propagates this Err instead of returning Ok.
        assert!(
            root.exists(),
            "failed cleanup must not silently remove the tree"
        );

        // Restore the parent so the tempdir can clean up after the test.
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

        // The fallback Drop still removes read-only trees best-effort when it
        // CAN (read-only entries INSIDE the tree): u+w is restored and the
        // whole tree is removed silently on drop.
        let p = base.path().join("dry-ro");
        std::fs::create_dir_all(p.join("sub")).unwrap();
        std::fs::write(p.join("sub/f"), b"y").unwrap();
        std::fs::set_permissions(p.join("sub"), std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::set_permissions(p.join("sub/f"), std::fs::Permissions::from_mode(0o444)).unwrap();
        {
            let _g = StagingCleanup(Some(p.clone()));
        }
        assert!(!p.exists(), "fallback Drop must clean a read-only tree");
    }

    #[test]
    fn remove_tree_restoring_write_reports_removal_failure() {
        // Injection: removing the temp root requires write permission on its
        // PARENT directory, and the helper only restores permissions INSIDE
        // its own tree (it must not touch anything outside). So a read-only
        // parent makes remove_dir_all fail with EACCES even after the
        // owner-write restore, and that failure must surface as an Err naming
        // the path — never a silent swallow that lets a mixed tree be stored.
        // Mirrors `dry_run_cleanup_failure_is_reported`.
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("recover-x");
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("nested/f"), b"x").unwrap();
        // Read-only entries INSIDE the tree are fixed by the helper; only the
        // parent-side injection breaks removal.
        std::fs::set_permissions(root.join("nested"), std::fs::Permissions::from_mode(0o555))
            .unwrap();
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o555)).unwrap();

        let err = remove_tree_restoring_write(&root, "remove stale recovery temp").unwrap_err();
        assert!(
            matches!(err, Error::Transport(_)),
            "removal failure must be a transport error, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("remove stale recovery temp") && msg.contains("recover-x"),
            "error must name the tree path, got: {msg}"
        );
        assert!(
            root.exists(),
            "failed removal must not silently remove the tree"
        );

        // Restore the parent so the tempdir can clean up after the test.
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}
