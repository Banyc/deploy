//! Advisory-lock acquisition for a push: [`acquire_locks`] durably creates
//! the target's lock directory and takes the local + target `FileLock`s,
//! keyed by the operation id.

use crate::deploy::lock::FileLock;
use crate::error::Result;
use crate::identity::OperationId;
use crate::store::local::LocalStore;
use crate::store::local::ledger::TargetLedgerTxn;

/// Acquire the local application-store lock then the TARGET LEDGER
/// TRANSACTION (in that order — the txn's `open` acquires the target
/// `operation.lock` + folds the ledger state), held for the whole push
/// ([`push`] step 2). The txn is the target-lock owner AND the ONLY ledger
/// write surface: every intent/terminal write of the push happens through
/// it, so the target lock is held for exactly the txn's lifetime. An
/// advisory lock is released by the kernel when the owning process dies, so
/// a stale lock from a crashed controller can never be double-owned; two
/// contenders for the same lock can never both believe they hold it.
/// Dry-run never acquires a persistent lock (local or remote) and opens no
/// txn. The target lock's directory is DURABLY pre-created before the
/// target lock is acquired (see [`TargetLedgerTxn::open`]: the lock's own
/// parent creation must find the directory existing, or a
/// reported-successful first push could recover with the target directory
/// missing after power loss).
pub(crate) fn acquire_locks<'a>(
    store: &'a LocalStore,
    target_name: &str,
    op_id: &OperationId,
    dry_run: bool,
) -> Result<(Option<FileLock>, Option<TargetLedgerTxn<'a>>)> {
    let local_guard = if dry_run {
        None
    } else {
        Some(FileLock::acquire(
            &store.base().join("operation.lock"),
            op_id.as_str(),
        )?)
    };
    let txn = if dry_run {
        None
    } else {
        Some(TargetLedgerTxn::open(store, target_name, op_id.as_str())?)
    };
    Ok((local_guard, txn))
}
