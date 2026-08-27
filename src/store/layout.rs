//! The store directory layout (A3): the hermetic test / `$XDG_DATA_HOME`
//! base ([`default_base`]), the per-target path plumbing
//! ([`LocalStore::target_dir`]), and the durable first-creation of a
//! target's directory on the ledger-append path (A7
//! [`LocalStore::ensure_target_dir_durable`]).

use crate::error::Result;
use crate::store::atomic::ensure_private_dir_durable;
use crate::store::local::{LocalStore, sanitize};
use std::path::PathBuf;

#[cfg(test)]
use crate::error::Error;
#[cfg(test)]
use crate::testutil::test_faults::FaultKind;

pub(crate) fn default_base() -> PathBuf {
    #[cfg(test)]
    {
        let tmp = std::env::var("TMPDIR")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        tmp.join("deploy-test")
    }
    #[cfg(not(test))]
    {
        let data = std::env::var("XDG_DATA_HOME")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("HOME").ok())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        data.join("simple-deploy")
    }
}

impl LocalStore {
    // ---- targets ----------------------------------------------------------

    pub fn target_dir(&self, target: &str) -> PathBuf {
        self.base.join("targets").join(sanitize(target))
    }

    /// DURABLE creation of a target's directory on the LEDGER-APPEND path
    /// (the reported durability bug: the FIRST `append_intent` for a new
    /// target created `targets/<target>/` — and the store open's `targets/` —
    /// WITHOUT syncing their directory entries, so a power loss right after a
    /// reported-successful first append could lose the new directories
    /// entirely). The pure creation + syncs live in
    /// [`ensure_private_dir_durable`](crate::store::atomic::ensure_private_dir_durable):
    /// every component this call created gets a parent-directory fsync — at
    /// minimum `targets/` (the new target dir's entry) and the store base
    /// (the `targets/` entry) — before the ledger write below. The helper's
    /// created flag feeds the test-only fault surface below: the per-target
    /// dir-sync boundaries fire ONLY on the creation path (an EXISTING
    /// target's append creates and syncs nothing, so the arms never fire
    /// there).
    ///
    /// The engine and checkpoint ALSO call this BEFORE acquiring the target
    /// lock ([`crate::deploy::push`], [`crate::retention::checkpoint`]): the
    /// lock file lives INSIDE the target dir, so the lock path used to create
    /// it with a plain unsynced mkdir that bypassed this helper — the
    /// lock-path pre-creation makes the directory durable BEFORE the lock is
    /// taken (the lock's own parent creation then no-ops), and the append's
    /// later call finds it existing. The [`FaultKind::LockMkdir`] arm below
    /// models a crash at that lock-path mkdir step: it fires BEFORE the
    /// helper runs, leaving the prior state with NO target directory.
    pub(crate) fn ensure_target_dir_durable(&self, target: &str) -> Result<()> {
        // Test-only: the LOCK-PATH dir-creation boundary (the durable
        // pre-creation the engine/checkpoint run before the target lock) —
        // fires BEFORE the durable helper creates anything, modeling a crash
        // at the mkdir step: recovery finds the PRIOR STATE with no target
        // directory (a first target) and no ledger.
        #[cfg(test)]
        if self.fault_registry.consume(FaultKind::LockMkdir, target) {
            return Err(Error::store(
                "test fault: the lock-path target-dir creation forced to fail once",
            ));
        }
        let created = ensure_private_dir_durable(&self.target_dir(target))?;
        // Test-only: the two dir-sync boundaries of a FIRST append, keyed by
        // target. They fire after the durable helper returned (the directory
        // entries ARE created and synced — the modeled loss is the boundary
        // between the dir syncs and the ledger write: the append reports `Err`
        // and crash recovery finds the PRIOR STATE, never a reported success
        // with the target directory missing).
        #[cfg(test)]
        if created
            && self
                .fault_registry
                .consume(FaultKind::SyncNewTargetDir, target)
        {
            return Err(Error::store(
                "test fault: the new target dir's entry sync forced to fail once",
            ));
        }
        #[cfg(test)]
        if created
            && self
                .fault_registry
                .consume(FaultKind::SyncTargetsDir, target)
        {
            return Err(Error::store(
                "test fault: the targets dir's entry sync forced to fail once",
            ));
        }
        #[cfg(not(test))]
        let _ = created;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ApplicationStoreKey;
    use std::path::PathBuf;
    /// The store path is `default_base().join(key)`: a clean store key
    /// places the store DIRECTLY under the base with exactly ONE component
    /// appended (no traversal), and every escape class is rejected at the
    /// key parse — an invalid name can never reach the store construction
    /// (the key type is the only way in).
    #[test]
    fn new_places_store_under_base_plus_single_component() {
        // Hermetic store base: `LocalStore::new` resolves `default_base()`
        // from the process-global `$TMPDIR`, so it is pointed at a
        // temp root under ENV_LOCK (the house env-mutation invariant).
        let _lock = crate::testutil::ENV_LOCK.lock().unwrap();
        let store_root = crate::testutil::hermetic_tmpdir_root();
        unsafe { std::env::set_var("TMPDIR", &store_root) };

        // A clean name → Ok, and the store path is `<base>/<name>` with no
        // traversal: exactly ONE component (the key) appended.
        let key = ApplicationStoreKey::parse("my-app").expect("clean name parses");
        let store = LocalStore::new(&key).expect("a valid store key constructs a store");
        assert_eq!(store.base().parent(), Some(default_base().as_path()));
        assert_eq!(
            store.base().file_name(),
            Some(std::ffi::OsStr::new("my-app"))
        );
        assert_eq!(store.base(), default_base().join("my-app"));

        // Every escape class is rejected at the KEY parse — the store
        // construction takes the key type, so an invalid name can never
        // reach it.
        for bad in [
            "a/b", "a\\b", "..", ".", "../x", "x/..", " x", "x ", "", "\u{0}",
        ] {
            ApplicationStoreKey::parse(bad).expect_err("unsafe store key rejected");
        }

        unsafe { std::env::remove_var("TMPDIR") };
        let _ = std::fs::remove_dir_all(store_root.join("deploy-test"));
    }

    /// The test-mode `default_base()` is hermetic: it resolves under
    /// `$TMPDIR` (or `/tmp` when unset) — never `$XDG_DATA_HOME`/`$HOME` —
    /// and `$TMPDIR` overrides the root explicitly.
    #[test]
    fn test_mode_default_base_is_hermetic() {
        let _lock = crate::testutil::ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("TMPDIR") };
        assert_eq!(
            default_base(),
            PathBuf::from("/tmp").join("deploy-test"),
            "with TMPDIR unset the test-mode base must be /tmp/deploy-test"
        );
        // The override root is a fixed, never-deleted path under the real
        // temp dir: while TMPDIR is redirected, other tests' tempdirs may
        // land inside it, so it must never be deleted (their own drops
        // clean them).
        let override_root = std::env::temp_dir().join("deploy-test-override");
        unsafe { std::env::set_var("TMPDIR", &override_root) };
        assert_eq!(
            default_base(),
            override_root.join("deploy-test"),
            "with TMPDIR set the test-mode base must be $TMPDIR/deploy-test"
        );
        unsafe { std::env::remove_var("TMPDIR") };
    }
}
