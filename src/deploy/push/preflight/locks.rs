//! Advisory-lock acquisition for a push: [`acquire_locks`] durably creates
//! the target's lock directory and takes the local + target `FileLock`s,
//! keyed by the operation id.

use crate::deploy::lock::FileLock;
use crate::error::Result;
use crate::identity::OperationId;
use crate::store::local::LocalStore;

/// Acquire the local application-store lock then the target lock (in that
/// order), held as advisory (flock) locks on open file descriptors
/// ([`push`] step 2). An advisory lock is released by
/// the kernel when the owning process dies, so a stale lock from a crashed
/// controller can never be double-owned; two contenders for the same lock
/// can never both believe they hold it. Dry-run never acquires a persistent
/// lock (local or remote). The target lock's directory is DURABLY
/// pre-created before the target lock is acquired (see the caller's comment:
/// the lock's own parent creation must find the directory existing, or a
/// reported-successful first push could recover with the target directory
/// missing after power loss).
pub(crate) fn acquire_locks(
    store: &LocalStore,
    target_name: &str,
    op_id: &OperationId,
    dry_run: bool,
) -> Result<(Option<FileLock>, Option<FileLock>)> {
    let local_guard = if dry_run {
        None
    } else {
        Some(FileLock::acquire(
            &store.base().join("operation.lock"),
            op_id.as_str(),
        )?)
    };
    let target_guard = if dry_run {
        None
    } else {
        store.ensure_target_dir_durable(target_name)?;
        Some(FileLock::acquire(
            &store.target_dir(target_name).join("operation.lock"),
            op_id.as_str(),
        )?)
    };
    Ok((local_guard, target_guard))
}
