//! Advisory locking for push transactions.
//!
//! [`FileLock`] is the `storekit::lock` advisory lock held by an open file
//! descriptor — `flock` on Unix, `LockFileEx` on Windows. While the guard is
//! alive the kernel prevents any other process from acquiring the same lock,
//! and the lock is released automatically if the owning process dies — so a
//! stale lock from a crashed controller can never be double-owned, and two
//! live contenders can never both win the acquisition. Locks are taken in a
//! fixed local-then-target order — the application-store `operation.lock`
//! first, then the target lock — so the whole push pipeline, including
//! [`crate::retention::checkpoint`], runs under the same discipline as
//! [`crate::deploy::push::push`].
//!
//! # The substrate swap (`storekit::lock`)
//!
//! This module was `deploy`'s own advisory lock (`mod.rs`/`unix.rs`/
//! `windows.rs`, the source `storekit` was extracted from). [`FileLock`] and
//! [`AdministrativeRecoveryGuard`] are now the crate's, re-exported
//! `pub(crate)` (every item `deploy` exposed was `pub(crate)`; the crate
//! exports them `pub` for its own consumers, so a `pub use` would WIDEN
//! `deploy`'s surface — the same form as the `digest`/`platform`/`trace` and
//! `store::atomic` swaps). The crate's `acquire` is STRICTER than the one
//! this module used to carry:
//!
//! * **A symlink at the record path is refused** (`O_NOFOLLOW` on Unix, the
//!   Windows analogue), and a symlinked PARENT directory is refused too, so a
//!   record path that is a symlink can no longer redirect the `set_len(0)` +
//!   op-id write into an arbitrary victim file. `deploy`'s own `acquire`
//!   followed the link and TRUNCATED the victim (see
//!   `deploy::lock::tests::symlink_at_record_path_cannot_truncate_a_victim`,
//!   which failed against the pre-swap lock and passes against the crate's).
//! * **The op-id record is PRIVATE (`0o600`)** — requested at creation AND
//!   re-applied on every acquisition.
//! * **Contention is the TYPED [`storekit::Error::LockContended`]** (mapped
//!   to [`crate::error::Error::LockContended`] by the facade bridge) rather
//!   than the `Preflight` string class.
//!
//! The durability helper and the whole stable-inode discipline moved with it:
//! the crate's `acquire` durably creates the record's parent
//! (`atomic::ensure_private_dir_durable`) and never unlinks the record on
//! release. The slice-B adaptation `ensure_private_dir_durable_confined` is
//! gone — resolving the anchor directory and parsing the relative chain is
//! now the crate's business.
//!
//! # The sidecar platform flock triple was RETIRED with the sidecar
//!
//! `try_lock`, `unlock`, `contended_errno` and `LockAttempt` used to live
//! here for [`crate::remote::transport`]'s operation-lock sidecar. The crate
//! now exposes
//! [`storekit::transport::with_operation_lock_sidecar`] publicly (the SAME
//! record, the SAME 2 s/5 ms blocking-with-deadline policy, an RAII hold),
//! so the transport takes its sidecar from the crate and the deploy-local
//! triple and its two platform modules (`unix.rs`/`windows.rs`) are deleted.
//! The crate owns that mechanism; `deploy` no longer has a second copy.

/// The crate's advisory `FileLock`, re-exported `pub(crate)`.
///
/// The crate's `acquire` durably creates the record's parent, refuses a
/// symlink at the record path (`O_NOFOLLOW`) and a symlinked parent, makes the
/// record private (`0o600`), and reports contention as the typed
/// [`storekit::Error::LockContended`]. Its `Drop` releases the advisory lock
/// (unlock + close, never unlink — the same stable-inode discipline).
pub(crate) use storekit::lock::FileLock;

/// The crate's typed ADMINISTRATIVE capability (see its module docs): owns the
/// local application-store lock for the duration of an explicit remote-lock
/// recovery. `recover_lock` accepts only `&AdministrativeRecoveryGuard`, and
/// the guard is constructible only by actually acquiring the local `FileLock`.
pub(crate) use storekit::lock::AdministrativeRecoveryGuard;

#[cfg(unix)]
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::os::unix::io::AsRawFd;
    use std::sync::{Arc, Barrier};
    use std::thread;

    /// The (device, inode) identity of the file `path` — the inode the
    /// advisory flock is attached to. Two opens of the same path yield the
    /// same pair iff no unlink+recreate happened between them; with the
    /// stable-inode discipline the pair NEVER changes for the lifetime of
    /// the lock path.
    fn inode_id(path: &std::path::Path) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(path).expect("the lock file must exist");
        (m.dev(), m.ino())
    }

    /// The delete-window shape is gone: a release NEVER removes the lock
    /// file (unlock → unlink is the old inode-split window), a re-acquire
    /// reuses the SAME inode (never a recreated one), and the durable
    /// directory machinery is untouched (the persistent file changes nothing
    /// for a first append's directory-creation detection).
    #[test]
    fn release_never_removes_the_lock_file() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let path = dir.path().join("operation.lock");
        let first_inode = {
            let _guard = FileLock::acquire(&path, "op-1").expect("acquire 1");
            inode_id(&path)
        };
        // The file PERSISTS after the release.
        assert!(
            path.exists(),
            "the lock file must never be removed on release (stable inode)"
        );
        // A re-acquire reuses the SAME inode — a contender can never race a
        // new inode into existence between an unlock and an unlink.
        let guard2 = FileLock::acquire(&path, "op-2").expect("re-acquire");
        assert_eq!(
            first_inode,
            inode_id(&path),
            "re-acquisition must flock the SAME inode — never a recreated one"
        );
        drop(guard2);
        assert!(
            path.exists(),
            "the lock file still persists after the second release"
        );
    }

    /// EAGAIN handling is preserved: while a guard is alive a second acquire
    /// of the same path fails with the explicit "held by" message (the flock
    /// is exclusive on the single inode, so any contender is refused).
    #[test]
    fn contention_is_refused_with_holder_message() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let path = dir.path().join("operation.lock");
        let _a = FileLock::acquire(&path, "op-A").expect("A acquires");
        let err = match FileLock::acquire(&path, "op-B") {
            Err(e) => e,
            Ok(_) => panic!("B must be refused while A holds the lock"),
        };
        // TIGHTENING (the crate's lock): contention is now the TYPED
        // `storekit::Error::LockContended` (mapped to
        // `crate::error::Error::LockContended` by the facade bridge), not the
        // `Preflight` string class `deploy`'s own lock returned.
        assert!(
            matches!(err, storekit::Error::LockContended(_)),
            "contention must be the TYPED signal, not a string-matching target: {err:?}"
        );
        assert!(
            err.to_string().contains("held by 'op-A'"),
            "the refusal must name the holder: {err}"
        );
    }

    /// THE SYMLINK-AT-RECORD HARDENING (the arbitrary-file truncation): a
    /// symlink planted at the lock record's spelling must NOT be followed —
    /// the acquisition refuses BEFORE any `set_len(0)`/write can be
    /// redirected through the link, so a victim file the link names is
    /// neither truncated nor overwritten. The victim's bytes after the
    /// attempt are quoted so a regression (a follow-through that truncates
    /// the victim) is legible in the failure.
    #[test]
    fn symlink_at_record_path_cannot_truncate_a_victim() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let victim = dir.path().join("victim.txt");
        let original = "VICTIM-MUST-SURVIVE\n";
        std::fs::write(&victim, original).unwrap();
        let record = dir.path().join("operation.lock");
        std::os::unix::fs::symlink(&victim, &record).unwrap();

        let res = FileLock::acquire(&record, "op-symlink");
        let after =
            std::fs::read_to_string(&victim).unwrap_or_else(|e| format!("<unreadable: {e}>"));

        assert!(
            res.is_err(),
            "a symlink at the lock record must be REFUSED, never followed; \
             victim content after the attempt = {after:?}"
        );
        assert_eq!(
            after, original,
            "the victim file must be untouched (no truncation, no op-id overwrite)"
        );
        assert!(
            std::fs::symlink_metadata(&record)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the record path must still be the symlink — never replaced"
        );
    }

    /// THE SYMLINKED-PARENT HARDENING: a symlink at the record's PARENT
    /// directory would redirect the whole record (and every subsequent open)
    /// elsewhere, so it is refused BEFORE the record is opened — the redirect
    /// target gains no record and a file there is untouched. The record
    /// itself is a plain (missing) spelling, so this test isolates the PARENT
    /// check: the record-path `O_NOFOLLOW` refusal is not in play.
    #[test]
    fn symlinked_parent_dir_cannot_redirect_the_record() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("keep.txt");
        let original = "PARENT-VICTIM-MUST-SURVIVE\n";
        std::fs::write(&victim, original).unwrap();
        // The record is spelled through a symlinked parent; the redirect
        // target holds no `operation.lock` of its own.
        let link = dir.path().join("link-parent");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let record = link.join("operation.lock");
        let redirected = outside.join("operation.lock");

        let res = FileLock::acquire(&record, "op-parent-symlink");
        let after =
            std::fs::read_to_string(&victim).unwrap_or_else(|e| format!("<unreadable: {e}>"));

        assert!(
            res.is_err(),
            "a symlinked parent directory must be REFUSED before any record is opened"
        );
        assert!(
            !redirected.exists(),
            "the redirect target must gain no record; it holds {:?}",
            std::fs::read_to_string(&redirected).ok()
        );
        assert_eq!(
            after, original,
            "the file through the symlinked parent must be untouched"
        );
    }

    // ---------------------------------------------------------------------
    // THE THREE-CONTENDER INTERLEAVING PROPERTY (the review's acceptance):
    // contender A unlocks/drops, contender B tries to acquire, contender C
    // tries to acquire — at NO point may two contenders both hold the flock.
    // With the stable-inode release this is structural (there is no unlink,
    // so no old-inode/new-inode split is reachable), but the property pins
    // the invariant across the interleaving SHAPES of the old delete-window
    // design:
    //
    //   * unlock→unlink               — covered structurally by
    //                                   [release_never_removes_the_lock_file]:
    //                                   a release has NO unlink; the file and
    //                                   its inode persist after every drop.
    //   * unlock→reacquire-on-old-inode — A drops; B and C race to re-lock
    //                                   the SAME persistent inode (schedules
    //                                   1 and 2 order their go-signals); the
    //                                   flock is exclusive, so exactly one
    //                                   wins and the other is refused.
    //   * re-create-new-inode         — a fresh open of the path after the
    //                                   race still yields the ORIGINAL inode
    //                                   (the file was never unlinked); no
    //                                   second inode can be spun up to split
    //                                   the lock.
    //
    // The property drives REAL flock operations. Threads of one process that
    // open the same path separately DO contend — flock locks are attached to
    // open file descriptions, not to processes — so B and C's race is real.
    // Each proptest case draws a schedule (the barrier order that re-enacts
    // one interleaving shape) and asserts:
    //   * exactly ONE contender holds the flock after A's drop (XOR);
    //   * the loser failed with EAGAIN;
    //   * the persistent inode is unchanged, so no split is possible;
    //   * while the winner holds, a fresh acquisition is refused.
    // ---------------------------------------------------------------------

    /// One proptest case of the three-contender schedule model: a REAL
    /// release of A while B and C race the flock, under the barrier schedule
    /// `schedule` (0 = simultaneous race; 1 = B signaled first, then C;
    /// 2 = C signaled first, then B).
    fn run_three_contender_case(schedule: u8) -> proptest::test_runner::TestCaseResult {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env())
            .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
        let path = dir.path().join("operation.lock");

        // A acquires first: the persistent inode is created exactly once.
        let guard_a = FileLock::acquire(&path, "op-A")
            .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
        let inode_a = inode_id(&path);

        // B and C open their fds BEFORE A drops: both land on the SAME
        // persistent inode (a fresh open can never produce a second inode —
        // the file is never unlinked). They flock when the schedule signals.
        let fd_b = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
        let fd_c = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;

        // Every thread parks on `start` first so A's drop and the contenders
        // are all registered; the per-contender `go` barriers then admit the
        // flock attempts in the schedule's order. A thread that wins returns
        // its open File so the flock STAYS held until the case drops it; a
        // loser returns Err(EAGAIN).
        let start = Arc::new(Barrier::new(3));
        let go_b = Arc::new(Barrier::new(2));
        let go_c = Arc::new(Barrier::new(2));

        let b_start = Arc::clone(&start);
        let b_go = Arc::clone(&go_b);
        let b_handle = thread::spawn(move || {
            b_start.wait();
            b_go.wait();
            let ret = unsafe { libc::flock(fd_b.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if ret == 0 {
                Ok(fd_b)
            } else {
                Err(std::io::Error::last_os_error())
            }
        });

        let c_start = Arc::clone(&start);
        let c_go = Arc::clone(&go_c);
        let c_handle = thread::spawn(move || {
            c_start.wait();
            c_go.wait();
            let ret = unsafe { libc::flock(fd_c.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if ret == 0 {
                Ok(fd_c)
            } else {
                Err(std::io::Error::last_os_error())
            }
        });

        // All three are registered; execute the schedule's interleaving. In
        // every schedule A's release (unlock + close) completes BEFORE any
        // contender attempts the flock, so the flock is free when B and C
        // race it — exactly one must win.
        start.wait();
        match schedule {
            // Schedule 0: A drops; both contenders are released together
            // (the genuine race over the persistent inode).
            0 => {
                drop(guard_a);
                go_b.wait();
                go_c.wait();
            }
            // Schedule 1: A drops; B is released first, C follows after a
            // short bias (unlock->reacquire-on-old-inode with B first).
            1 => {
                drop(guard_a);
                go_b.wait();
                std::thread::sleep(std::time::Duration::from_millis(2));
                go_c.wait();
            }
            // Schedule 2: the mirror of schedule 1 (C first).
            2 => {
                drop(guard_a);
                go_c.wait();
                std::thread::sleep(std::time::Duration::from_millis(2));
                go_b.wait();
            }
            _ => unreachable!("three-contender schedule tags are 0..=2"),
        }

        let b_res = b_handle
            .join()
            .map_err(|_| proptest::test_runner::TestCaseError::fail("B thread panicked"))?;
        let c_res = c_handle
            .join()
            .map_err(|_| proptest::test_runner::TestCaseError::fail("C thread panicked"))?;
        let b_won = b_res.is_ok();
        let c_won = c_res.is_ok();

        // THE INVARIANT: flock is exclusive per inode, and BOTH contenders
        // flocked the SAME persistent inode — at most one can hold it. Since
        // A released before they raced and the flock is exclusive, exactly
        // one wins (XOR); the loser must have been refused with EAGAIN.
        prop_assert!(
            b_won != c_won,
            "two contenders must never BOTH hold the flock (inode split), and one must win after the release (b_won={b_won}, c_won={c_won})"
        );
        for (name, res) in [("B", &b_res), ("C", &c_res)] {
            if let Err(e) = res {
                prop_assert!(
                    matches!(
                        e.raw_os_error(),
                        Some(c) if c == libc::EWOULDBLOCK || c == libc::EAGAIN
                    ),
                    "the losing contender {name} must fail with EAGAIN, got: {e:?}"
                );
            }
        }
        // Keep the winner's fd alive (holding the flock) while probing below.
        let _b_hold = b_res.ok();
        let _c_hold = c_res.ok();

        // The re-create-new-inode shape is structurally impossible: a fresh
        // open of the path still yields the ORIGINAL inode, so a third
        // process can never spin up a second inode to split the lock.
        prop_assert_eq!(
            inode_a,
            inode_id(&path),
            "the lock file must keep its single stable inode across the whole race (no unlink, no recreate)"
        );
        prop_assert!(path.exists(), "the lock file persists after the race");

        // While the winner holds the flock, a fresh acquisition on the SAME
        // inode is refused (flock exclusion), and after the winner's fd
        // closes the lock returns to the free state on the SAME inode.
        {
            let probe = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
            let ret = unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            prop_assert!(
                ret != 0,
                "a fresh acquisition while a contender holds must be refused (flock is exclusive on the single inode)"
            );
        }
        drop(_b_hold);
        drop(_c_hold);
        // The flock may be TRANSIENTLY held by a forked child of a parallel
        // test: a child spawned (fork+exec) while the winner's fd was open
        // inherits the fd during its fork→exec window, and the flock
        // persists until the child's exec closes it (O_CLOEXEC). The
        // discipline under test — the lock returns to the free state on the
        // SAME inode once the winner's fd closes — is unaffected; only the
        // instant at which it is observable is. Wait (bounded) for the free
        // state instead of asserting it is immediate.
        let last = (0..50)
            .find_map(|_| match FileLock::acquire(&path, "op-last") {
                Ok(lock) => Some(lock),
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    None
                }
            })
            .ok_or_else(|| {
                proptest::test_runner::TestCaseError::fail(
                    "the lock must return to the free state after the winner's fd closes",
                )
            })?;
        prop_assert_eq!(
            inode_a,
            inode_id(&path),
            "the stable inode survives the full acquire/release cycle"
        );
        drop(last);

        Ok(())
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: crate::testutil::proptest_cases(64),
            max_shrink_iters: 10000,
            rng_seed: proptest::test_runner::RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..proptest::test_runner::Config::default()
        })]
        /// The three-contender no-split property: for every schedule of the
        /// old delete-window shapes around a real release, at no observable
        /// point do two contenders both hold the flock, and the stable inode
        /// is never recreated.
        #[test]
        fn no_two_contenders_hold_the_flock(schedule in 0u8..3u8) {
            run_three_contender_case(schedule)?;
        }
    }
}
