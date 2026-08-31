//! The store directory layout (A3): the store base resolution
//! (`default_base` — pure, from the environment snapshot), the per-target
//! path plumbing ([`LocalStore::target_dir`]), and the durable
//! first-creation of a target's directory on the ledger-append path (A7
//! `LocalStore::ensure_target_dir_durable`).

use crate::env::SysEnv;
use crate::error::Result;
use crate::store::local::{LocalStore, sanitize};
use std::path::PathBuf;

#[cfg(test)]
use crate::error::Error;
#[cfg(test)]
use crate::testutil::test_faults::FaultKind;

/// The store base for `env`: `<data home>/simple-deploy` (the user data
/// home is `XDG_DATA_HOME`, else `$HOME`, else `.` — resolved by
/// [`SysEnv::data_home`]). Pure: reads NOTHING from the process environment;
/// the caller passes the snapshot taken at the process boundary. The old
/// test-mode `$TMPDIR/deploy-test` branch is gone: tests build a hermetic
/// `SysEnv::from_map` and resolve the base from it like any caller.
pub(crate) fn default_base(env: &SysEnv) -> PathBuf {
    env.data_home().join("simple-deploy")
}

impl LocalStore {
    // ---- targets ----------------------------------------------------------

    pub fn target_dir(&self, target: &str) -> PathBuf {
        // RAW-string entry point: the caller holds a validated target name
        // (the config/CLI target — the valid grammar is ASCII-safe and
        // `sanitize` is the identity on it), but the value arrives as a
        // plain string here, so the sanitize confinement stays for any
        // non-grammar input (a valid name passes through UNCHANGED — the
        // store stores valid names verbatim).
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
        let created = self.ensure_private_dir_durable_at(&self.target_dir(target))?;
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
    use std::collections::BTreeMap;
    use std::ffi::{OsStr, OsString};
    use std::path::PathBuf;

    /// Build a hermetic snapshot with `XDG_DATA_HOME` pointing under a fresh
    /// temp root (the environment the store tests resolve their base from —
    /// never the process env, never a global mutation).
    fn store_env(root: &std::path::Path) -> SysEnv {
        SysEnv::from_map(BTreeMap::from([(
            OsString::from("XDG_DATA_HOME"),
            root.to_path_buf().into_os_string(),
        )]))
    }

    /// The store path is `default_base(env).join(key)`: a clean store key
    /// places the store DIRECTLY under the base with exactly ONE component
    /// appended (no traversal), and every escape class is rejected at the
    /// key parse — an invalid name can never reach the store construction
    /// (the key type is the only way in).
    #[test]
    fn new_places_store_under_base_plus_single_component() {
        // Hermetic store base: `LocalStore::new_in` resolves `default_base`
        // from the SNAPSHOT (never the process env) — the test points the
        // snapshot's `XDG_DATA_HOME` at a fresh temp root.
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let env = store_env(&dir.path().join("store-root"));

        // A clean name → Ok, and the store path is `<base>/<name>` with no
        // traversal: exactly ONE component (the key) appended. The store's
        // base is the CANONICAL form of `<base>/<name>` (the sealed
        // [`OwnedRoot`] is constructed from a canonical directory), so the
        // comparison canonicalizes the expected path (a temp root under a
        // symlinked `TMPDIR` canonicalizes to the real directory).
        let key = ApplicationStoreKey::parse("my-app").expect("clean name parses");
        let store = LocalStore::new_in(&env, &key).expect("a valid store key constructs a store");
        let expected = std::fs::canonicalize(default_base(&env).join("my-app"))
            .expect("the store base exists (new_in created it)");
        assert_eq!(store.base(), expected);
        assert_eq!(store.base().parent(), expected.parent());
        assert_eq!(store.base().file_name(), Some(OsStr::new("my-app")));

        // Every escape class is rejected at the KEY parse — the store
        // construction takes the key type, so an invalid name can never
        // reach it.
        for bad in [
            "a/b", "a\\b", "..", ".", "../x", "x/..", " x", "x ", "", "\u{0}",
        ] {
            ApplicationStoreKey::parse(bad).expect_err("unsafe store key rejected");
        }
    }

    /// `default_base` is a pure function of the SNAPSHOT: `XDG_DATA_HOME`
    /// wins, `$HOME` falls back, and neither yields `.` — the data-home
    /// resolution lives in [`SysEnv::data_home`], never in a process read.
    #[test]
    fn default_base_resolves_from_snapshot() {
        let xdg = SysEnv::from_map(BTreeMap::from([
            (OsString::from("XDG_DATA_HOME"), OsString::from("/x/data")),
            (OsString::from("HOME"), OsString::from("/h")),
        ]));
        assert_eq!(default_base(&xdg), PathBuf::from("/x/data/simple-deploy"));

        // HOME falls back.
        let home = SysEnv::from_map(BTreeMap::from([(
            OsString::from("HOME"),
            OsString::from("/h"),
        )]));
        assert_eq!(default_base(&home), PathBuf::from("/h/simple-deploy"));

        // Neither -> `./simple-deploy` (data_home falls back to `.`).
        let none = SysEnv::from_map(BTreeMap::new());
        assert_eq!(default_base(&none), PathBuf::from("./simple-deploy"));
    }
}
