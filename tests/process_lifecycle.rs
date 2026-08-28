//! THE SEPARATELY SERIALIZED REAL-PROCESS LIFECYCLE TARGET.
//!
//! The real-process lifecycle property tests live HERE, never in the lib
//! suite: they must genuinely spawn children (quick-exit, slow, TERM-ignoring,
//! grandchild-spawning, detached-grandchild-leaving, late-marker-writing)
//! and drive them through the production [`ChildRunner`] under injected kill
//! faults — real processes, real process groups, real pids. Running them in
//! the in-process `cargo test --lib` harness (or at nextest's full
//! parallelism) made the suite load-sensitive and racy (the pid-reuse race
//! the runner's containment contract fixes). As a dedicated integration
//! binary it is serialized by `nextest.toml` (`test-threads = 1` for this
//! binary), so the lifecycle cases never run CONCURRENTLY with each other or
//! with the deterministic deployment/state-machine properties (which drive a
//! scripted fake exec and spawn nothing).
//!
//! Coordination is by BARRIER (the grandchildren's `ready` files) and
//! bounded poll-waits, never "must finish within N ms": the child scripts
//! write a `ready` file once their setup (the `setsid` escape, the fd close)
//! is COMPLETE and the parent waits for the file; pid-gone probes poll
//! `kill(pid, 0)` to a deadline; the no-post-return-fs probes sleep a wide
//! LOAD-TOLERANT window past the runner's return.
//!
//! The property observes the PRODUCTION outcome — what the runner actually
//! left behind — BEFORE any test cleanup: the containment assertions (process
//! liveness + marker behavior) run on the state AS THE RUNNER RETURNED IT,
//! and only afterwards does the emergency cleanup fire (the group kill + the
//! escaped-grandchild pid kill, for the cases the runner could not contain).
//! The containment invariant is satisfied by the RUNNER's own termination,
//! never by the harness. The setsid-ESCAPE cases (SetsidInherit/
//! SetsidClose) are EXPLICITLY EXCLUDED from the foreground containment
//! invariant — a descendant that `setsid`'d is outside the guarantee (the
//! runner can DETECT a pipe-holding escapee and error, but cannot TERMINATE
//! an escaped process without cgroups/subreaper or a remote supervisor) — so
//! the property asserts the escaped grandchild is STILL ALIVE after the
//! runner returned (unsupported daemonization cases never satisfy the
//! invariant), never a false zero-live claim; the emergency cleanup then
//! kills the escapee by pid so the test leaks nothing.

use deploy::env::SysEnv;
use deploy::remote::transport::{
    ChildRunner, KillSeam, RunOutcome, RunnerConfig, kill_process_group,
};
use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::process::Child;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// `true` when the FULL proptest budgets are requested (`DEPLOY_FULL_TESTS=1`).
fn full_proptest_suites() -> bool {
    std::env::var_os("DEPLOY_FULL_TESTS").is_some_and(|v| v != "0")
}

/// The proptest `cases:` budget (mirrors `deploy::testutil::proptest_cases`,
/// which is `#[cfg(test)]` crate-internal and therefore unavailable here).
fn proptest_cases(full: u32) -> u32 {
    if full_proptest_suites() {
        full
    } else {
        (full / 4).max(2)
    }
}

/// A fresh tempdir under the snapshot's `TMPDIR` (never the process env).
fn fixture_tmpdir(env: &SysEnv) -> tempfile::TempDir {
    tempfile::Builder::new()
        .tempdir_in(env.temp_dir())
        .expect("tempdir for the child's markers")
}

/// The runner deadline for every generated case: LONG enough that a
/// quick-exit child — including the setsid cases' READINESS barrier (the sh
/// waits for the grandchild's `ready` file, which arrives after python3's
/// interpreter startup, ~50-300ms under parallel load) — finishes in time,
/// while every genuinely timed-out case stays bounded. The late-marker child
/// writes its marker after 1.2s — past this deadline — so a leaked
/// (returned-while-still-alive) child would be caught writing AFTER the
/// outcome. Coordination is by BARRIER (the ready file), never by "must
/// finish within N ms".
const TEST_TIMEOUT: Duration = Duration::from_secs(1);

/// The child behaviour each generated case exhibits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChildKind {
    /// Exits 0 immediately (finishes before the timeout).
    Quick,
    /// Exits 7 immediately.
    NonZero,
    /// Sleeps 60s: dies on the group TERM.
    Slow,
    /// Ignores TERM, loops forever: needs the KILL escalation.
    IgnoreTerm,
    /// Spawns a background GRANDCHILD and waits: the group must die.
    Grandchild,
    /// Exits ZERO immediately after forking a background GRANDCHILD that
    /// sleeps 0.4s then would write a marker file: the FOREGROUND-ONLY
    /// detection must catch the leftover group member, terminate it, and
    /// return the "left background processes" error — never a successful
    /// exit-0 outcome — leaving no live process and no post-return fs effect.
    DetachedGrandchild,
    /// Exits ZERO immediately after forking a grandchild that CALLS `setsid`
    /// (escaping the process group — a `killpg` can never reach it) but KEEPS
    /// the inherited stdio pipes open, sleeps 0.9s, then would write a
    /// marker: the group enumeration finds nothing (it escaped), so the
    /// PIPE-EOF containment must catch the pipe-holding escapee at the drain
    /// bound and return the "left processes holding its output pipes" error —
    /// never a successful outcome. EXCLUDED from the foreground containment
    /// invariant: the runner DETECTS the escapee but cannot TERMINATE an
    /// escaped process, so the property asserts the escapee is STILL ALIVE
    /// after the runner returned (never a false zero-live claim) and the
    /// test's own cleanup kills it by pid.
    SetsidInherit,
    /// Exits ZERO immediately after forking a grandchild that FULLY
    /// DAEMONIZES: `setsid` AND closes every inherited descriptor (the
    /// canonical daemon recipe), sleeps 0.9s, then writes a marker. This is
    /// the ONE documented contract exclusion — no portable detection exists
    /// without cgroups/subreaper (Linux) or a remote supervisor (ssh) — so
    /// the runner returns SUCCESS (the narrowed contract: commands must not
    /// daemonize). EXCLUDED from the foreground containment invariant like
    /// every setsid escape: the property asserts the escapee is STILL ALIVE
    /// after the runner returned (the invariant does not hold for it) and
    /// the test's own cleanup kills it by pid.
    SetsidClose,
    /// Sleeps 0.25s then would write a marker file: the probe for
    /// post-return filesystem effects.
    LateMarker,
}

impl ChildKind {
    /// Contract: does this kind spawn a grandchild whose PID is published via `gcpid`?
    fn spawns_grandchild(&self) -> bool {
        matches!(
            self,
            ChildKind::Grandchild
                | ChildKind::DetachedGrandchild
                | ChildKind::SetsidInherit
                | ChildKind::SetsidClose
        )
    }

    /// Declared descendant count: 1 for grandchild-spawning kinds, 0 otherwise.
    fn declared_descendants(&self) -> usize {
        if self.spawns_grandchild() { 1 } else { 0 }
    }
}

/// The injected kill fault. The runner uses `killpg(2)` directly (no external
/// `kill` binary), so the "missing kill" fault is a syscall-level failure
/// (ENOENT — what a missing external binary would surface as), EPERM a
/// permission failure, ESRCH an unreachable group, and Inert a kill that
/// "succeeds" but signals nothing — the only way to force the reap bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KillFault {
    /// Real `killpg`/`Child::kill`.
    Real,
    /// Every group kill fails with ENOENT (the kill binary unavailable).
    Missing,
    /// Every group kill fails with EPERM (the group cannot be killed).
    Denied,
    /// Every group kill fails with ESRCH (the group is unreachable).
    Esrch,
    /// Every kill (group AND owned) returns Ok but signals nothing: the
    /// termination cannot take effect → the reap bound fires.
    Inert,
}

/// The injectable kill seam: records every group-kill attempt (for the
/// escalation assertion) and applies the injected fault.
struct FaultSeam {
    fault: KillFault,
    group_kills: AtomicUsize,
}

impl KillSeam for FaultSeam {
    fn kill_group(&self, pgid: i32, sig: i32) -> std::io::Result<()> {
        self.group_kills.fetch_add(1, Ordering::SeqCst);
        match self.fault {
            KillFault::Real => kill_process_group(pgid, sig),
            KillFault::Missing => Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
            KillFault::Denied => Err(std::io::Error::from_raw_os_error(libc::EPERM)),
            KillFault::Esrch => Err(std::io::Error::from_raw_os_error(libc::ESRCH)),
            KillFault::Inert => Ok(()),
        }
    }
    fn kill_owned(&self, child: &mut Child) -> std::io::Result<()> {
        match self.fault {
            // The Inert fault makes even the owned-handle kill a no-op:
            // only then can the child survive to the reap bound.
            KillFault::Inert => Ok(()),
            _ => child.kill(),
        }
    }
}

/// The `sh -c` script for a child kind, writing its marker/pid files under
/// `dir`.
fn script_for(kind: ChildKind, dir: &Path) -> Vec<String> {
    match kind {
        ChildKind::Quick => vec!["sh".into(), "-c".into(), "exit 0".into()],
        ChildKind::NonZero => vec!["sh".into(), "-c".into(), "exit 7".into()],
        ChildKind::Slow => vec!["sh".into(), "-c".into(), "sleep 60".into()],
        ChildKind::IgnoreTerm => vec![
            "sh".into(),
            "-c".into(),
            "trap '' TERM; while :; do sleep 1; done".into(),
        ],
        ChildKind::Grandchild => vec![
            "sh".into(),
            "-c".into(),
            format!(
                "sh -c 'sleep 60; touch {}' & echo $! > {}; wait",
                dir.join("gc-marker").display(),
                dir.join("gcpid").display()
            ),
        ],
        // The parent exits 0 IMMEDIATELY after forking the grandchild (the
        // pidfile is written before the exit, so the parent-side
        // `read_gc_pid` never races): the runner's wait reaps the child, and
        // the FOREGROUND-ONLY probe must find the sleeping grandchild still
        // in the group, terminate it before its 0.4s marker write, and error.
        ChildKind::DetachedGrandchild => vec![
            "sh".into(),
            "-c".into(),
            format!(
                "sh -c 'sleep 0.4; touch {}' & echo $! > {}; exit 0",
                dir.join("marker").display(),
                dir.join("gcpid").display()
            ),
        ],
        // The grandchild ESCAPES the process group via `setsid` (so the
        // group enumeration finds nothing and `killpg` cannot reach it) but
        // KEEPS the inherited stdout/stderr write ends (python3's fds 1/2) —
        // the pipes stay open after the direct child is reaped, so the
        // PIPE-EOF containment at the drain bound detects it and errors.
        // READINESS PROTOCOL: the grandchild writes a `ready` file AFTER
        // `setsid` and the parent waits for it before exiting — the escape is
        // COMPLETE before the runner's check, so the enumeration genuinely
        // sees an empty group (a bare `&` would race python3's interpreter
        // startup, which delays `setsid` past the check). `python3` is the
        // portable `setsid` provider on both macOS (dev) and Linux (CI).
        ChildKind::SetsidInherit => vec![
            "sh".into(),
            "-c".into(),
            format!(
                "python3 -c 'import os,time; os.setsid(); open(\"{}\",\"w\").close(); time.sleep(0.9); open(\"{}\",\"w\").close()' & while [ ! -e {} ]; do :; done; echo $! > {}; exit 0",
                dir.join("ready").display(),
                dir.join("marker").display(),
                dir.join("ready").display(),
                dir.join("gcpid").display()
            ),
        ],
        // The grandchild FULLY DAEMONIZES: `setsid` AND closes its
        // descriptors (0/1/2) — the pipes EOF immediately, no group member,
        // no pipe-holder: the ONE documented contract exclusion. Same
        // READINESS PROTOCOL: the escape (setsid + fd close) is complete
        // before the parent exits, and the ready-poll busy-waits with shell
        // BUILTINS ONLY (`:` — no external `sleep` subprocess, which would
        // be a transient GROUP MEMBER the runner would legitimately flag).
        // The delayed marker is at 0.9s — the property does NOT assert it
        // absent for this excluded case (an escaped process may write it
        // later — the documented exclusion); the test's emergency cleanup
        // kills the escapee by pid right after the production observations,
        // so no process leaks.
        ChildKind::SetsidClose => vec![
            "sh".into(),
            "-c".into(),
            format!(
                "python3 -c 'import os,time; os.setsid(); os.close(0); os.close(1); os.close(2); open(\"{}\",\"w\").close(); time.sleep(0.9); open(\"{}\",\"w\").close()' & while [ ! -e {} ]; do :; done; echo $! > {}; exit 0",
                dir.join("ready").display(),
                dir.join("marker").display(),
                dir.join("ready").display(),
                dir.join("gcpid").display()
            ),
        ],
        ChildKind::LateMarker => vec![
            "sh".into(),
            "-c".into(),
            format!("sleep 1.2; touch {}", dir.join("marker").display()),
        ],
    }
}

/// Poll `kill(pid, 0)` until the process is GONE: ESRCH is returned only for
/// a process that no longer exists — a zombie still answers, so "gone" is the
/// REAPED proof, not merely "signalled".
fn assert_pid_gone(pid: u32, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        // SAFETY: `kill(pid, 0)` only probes existence; it sends no signal.
        let rc = unsafe { libc::kill(pid as i32, 0) };
        if rc != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{label}: pid {pid} still exists 5s after the outcome (an un-reaped zombie would also exist)"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Assert the process STILL EXISTS: `kill(pid, 0)` SUCCEEDS (the process is
/// live, not merely a zombie). This is the HONEST production observation for
/// the EXCLUDED setsid-escape cases (and the injected-fault survivors): the
/// process the runner could not terminate is still alive after the return —
/// the containment invariant does NOT hold for it, and the property asserts
/// exactly that, never a false zero-live claim.
fn assert_pid_alive(pid: u32, label: &str) {
    // SAFETY: `kill(pid, 0)` only probes existence; it sends no signal.
    let rc = unsafe { libc::kill(pid as i32, 0) };
    assert!(
        rc == 0,
        "{label}: pid {pid} must still be alive (the containment exclusion / injected-fault survivor), kill-0 rc {rc}, errno {}",
        std::io::Error::last_os_error()
    );
}

/// The grandchild pid, from the pidfile the child writes IMMEDIATELY at
/// spawn (`echo $! > gcpid`) — written ~1ms in, far before the 200ms
/// deadline, so no child-written-pidfile race. A read that catches the file
/// mid-write (the `>` truncate before the `echo`) or a non-numeric parse is
/// RETRIED — never a premature `None` that would skip the cleanup kill of an
/// escaped grandchild.
fn read_gc_pid(path: &Path) -> Option<u32> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(pid) = std::fs::read_to_string(path)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
        {
            return Some(pid);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Drive ONE generated (child kind × kill fault) case through the real runner
/// and assert the lifecycle contract for the returned outcome.
fn run_one_case(kind: ChildKind, fault: KillFault) {
    let env = SysEnv::from_map(BTreeMap::from([(
        OsString::from("PATH"),
        OsString::from("/bin:/usr/bin"),
    )]));
    let dir = fixture_tmpdir(&env);
    let argv = script_for(kind, dir.path());
    let spawned = std::sync::Arc::new(Mutex::new(Vec::<u32>::new()));
    let runner_reaps = std::sync::Arc::new(AtomicUsize::new(0));
    let seam = std::sync::Arc::new(FaultSeam {
        fault,
        group_kills: AtomicUsize::new(0),
    });
    let config = RunnerConfig {
        term_to_kill_grace: Duration::from_millis(25),
        reap_bound: Duration::from_millis(100),
        kill: seam.clone(),
        spawn_observer: Some(std::sync::Arc::new({
            let spawned = spawned.clone();
            move |pid| spawned.lock().unwrap().push(pid)
        })),
        reap_observer: Some(std::sync::Arc::new({
            let runner_reaps = runner_reaps.clone();
            move |_pid| {
                runner_reaps.fetch_add(1, Ordering::SeqCst);
            }
        })),
    };
    let runner = ChildRunner::new(&env, dir.path().to_path_buf(), config);
    let outcome = runner.exec(&argv, TEST_TIMEOUT);
    // The spawn observer recorded the pid in the PARENT synchronously at
    // spawn — always available, nothing to race.
    let child_pid = *spawned
        .lock()
        .unwrap()
        .first()
        .expect("the spawn observer must record the child pid at spawn time");
    let gc_pid =
        if kind.spawns_grandchild() {
            Some(read_gc_pid(&dir.path().join("gcpid")).unwrap_or_else(|| {
                panic!("{kind:?}: grandchild-producing case must publish its PID")
            }))
        } else {
            None
        };

    let times_out = matches!(
        kind,
        ChildKind::Slow | ChildKind::IgnoreTerm | ChildKind::Grandchild | ChildKind::LateMarker
    );

    // ---- outcome classification ----
    match (&outcome, times_out, fault) {
        // DetachedGrandchild: the child exits ZERO immediately but a
        // grandchild remains — the FOREGROUND-ONLY violation. The outcome
        // must be an ERROR naming the left-behind background processes,
        // never a successful exit-0 outcome (zero-live and no-post-return
        // fs are asserted below).
        (Err(e), false, _) if kind == ChildKind::DetachedGrandchild => {
            assert!(
                e.to_string().contains("left background processes"),
                "{kind:?} × {fault:?}: the violation error must name the background processes, got {e}"
            );
        }
        (Ok(_), false, _) if kind == ChildKind::DetachedGrandchild => {
            panic!(
                "{kind:?} × {fault:?}: a command that left a background grandchild must error, got {outcome:?}"
            );
        }
        // SetsidInherit: the grandchild escaped the group but KEEPS the
        // inherited pipes — the PIPE-EOF containment must error (never
        // success), even though the runner cannot TERMINATE the escapee
        // (excluded from the containment invariant — the production phase
        // asserts it still-alive and the test's cleanup kills it by pid).
        (Err(e), false, _) if kind == ChildKind::SetsidInherit => {
            assert!(
                e.to_string().contains("foreground-only"),
                "{kind:?} × {fault:?}: the pipe-holding escapee must error as a foreground-only violation, got {e}"
            );
        }
        (Ok(_), false, _) if kind == ChildKind::SetsidInherit => {
            panic!(
                "{kind:?} × {fault:?}: a pipe-holding escaped grandchild must error (never success), got {outcome:?}"
            );
        }
        // SetsidClose: the FULLY daemonized grandchild (`setsid` AND closed
        // descriptors) is the ONE documented contract exclusion — undetectable
        // without cgroups/subreaper or a remote supervisor. The runner returns
        // SUCCESS per the narrowed contract (commands must not daemonize); the
        // test pins that boundary, asserts the escapee STILL ALIVE in the
        // production phase (the invariant does not hold for it), and its own
        // cleanup kills it by pid.
        (Ok(RunOutcome::Exited { exit_code, .. }), false, _) if kind == ChildKind::SetsidClose => {
            assert_eq!(
                *exit_code, 0,
                "{kind:?} × {fault:?}: the contract boundary is a clean exit-0 success (the fully daemonized escapee is outside containment)"
            );
        }
        (Err(e), false, _) if kind == ChildKind::SetsidClose => {
            panic!(
                "{kind:?} × {fault:?}: per the narrowed contract the runner must succeed (the daemonizer is outside containment), got {e}"
            );
        }
        (Ok(RunOutcome::Exited { exit_code, .. }), false, _) => {
            let expect = if kind == ChildKind::NonZero { 7 } else { 0 };
            assert_eq!(
                *exit_code, expect,
                "{kind:?} × {fault:?}: a child finishing before the timeout must report its exit code"
            );
        }
        (Ok(RunOutcome::TimedOut { .. }), false, _) => {
            panic!(
                "{kind:?} × {fault:?}: a fast child must finish before the timeout, got a timeout outcome"
            );
        }
        (Ok(RunOutcome::TimedOut { stderr }), true, KillFault::Real | KillFault::Inert) => {
            // The timeout outcome keeps its exact shape — but only after the
            // group was proven dead AND reaped (asserted below).
            assert_eq!(
                *stderr,
                format!("timed out after {TEST_TIMEOUT:?}"),
                "{kind:?} × {fault:?}: the timeout outcome must keep its message"
            );
        }
        (Ok(RunOutcome::TimedOut { .. }), true, _) => {
            panic!(
                "{kind:?} × {fault:?}: a kill failure must be an error, never a successful timeout outcome"
            );
        }
        (
            Err(_),
            true,
            KillFault::Missing | KillFault::Denied | KillFault::Esrch | KillFault::Inert,
        ) => {
            // Kill/reap failure surfaces as an error (the spec's contract).
        }
        (Err(e), true, KillFault::Real) => {
            panic!("{kind:?} × {fault:?}: a real kill must never fail, got {e}")
        }
        (Ok(_), true, _) => {
            panic!("{kind:?} × {fault:?}: a slow child must time out, got {outcome:?}")
        }
        (Err(e), false, _) => {
            panic!("{kind:?} × {fault:?}: a fast child must not fail, got {e}")
        }
    }

    // ---- the KILL escalation really fired for a TERM-ignoring child ----
    if kind == ChildKind::IgnoreTerm {
        assert!(
            seam.group_kills.load(Ordering::SeqCst) >= 2,
            "a TERM-ignoring child must be escalated to a group KILL ({fault:?})"
        );
    }

    // ---- EXACTLY ONE REAP ----
    let runner_reaps = runner_reaps.load(Ordering::SeqCst);
    match &outcome {
        Ok(_) => assert_eq!(
            runner_reaps, 1,
            "{kind:?} × {fault:?}: every completed lifecycle must reap the child exactly once"
        ),
        Err(_) => assert_eq!(
            runner_reaps,
            // DetachedGrandchild and SetsidInherit exit ZERO on their own
            // (no kill involved — the Inert fault only affects kills), so
            // even under the inert fault the runner's wait reaps them
            // exactly once; every other error outcome reaps only when its
            // kills were effective (the inert fault IS the kill not
            // working — nothing to reap).
            if fault == KillFault::Inert
                && !matches!(
                    kind,
                    ChildKind::DetachedGrandchild | ChildKind::SetsidInherit
                )
            {
                0
            } else {
                1
            },
            "{kind:?} × {fault:?}: an error outcome must reap once when its kills were effective, and never fake a reap it did not do"
        ),
    }

    // The setsid-escape cases are EXPLICITLY EXCLUDED from the foreground
    // containment invariant: a descendant that `setsid`'d is outside the
    // guarantee (the runner can DETECT a pipe-holding escapee and error, but
    // it cannot TERMINATE an escaped process — no portable way exists without
    // cgroups/subreaper or a remote supervisor). Their production
    // observations differ from the contained cases' — handled separately
    // below.
    let escaped = matches!(kind, ChildKind::SetsidInherit | ChildKind::SetsidClose);

    // ---- (c) PRODUCTION-STATE assertions: what the RUNNER left behind,
    // BEFORE any test kill ----
    // The property observes the production outcome — process liveness and
    // marker behavior AS THE RUNNER RETURNED THEM — and only afterwards runs
    // the emergency cleanup. The containment invariant is satisfied by the
    // RUNNER's own termination, never by the harness.
    if escaped {
        // EXCLUDED cases: the escaped grandchild is STILL ALIVE after the
        // runner returned (`kill(gc, 0)` SUCCEEDS — the honest production
        // observation). Unsupported daemonization cases NEVER satisfy the
        // foreground containment invariant; the property asserts exactly
        // that, never a false "zero live processes" claim. The direct child
        // is gone (the runner reaped it). The marker is NOT asserted absent —
        // the escaped process may write it later (that is the documented
        // exclusion).
        if kind.spawns_grandchild() {
            let gc = gc_pid.unwrap_or_else(|| {
                panic!("{kind:?} × {fault:?}: grandchild-producing case must publish its PID for escaped liveness assertion")
            });
            assert_pid_alive(gc, &format!("{kind:?} × {fault:?} escaped grandchild"));
        }
        assert_pid_gone(child_pid, &format!("{kind:?} × {fault:?} child"));
    } else {
        // The runner's own termination CONTAINS only where the kill was
        // effective: the real seam for every contained kind; the
        // owned-handle SIGKILL for a timed-out direct child under
        // Missing/Denied/Esrch (which still dies); and the self-exiting
        // children (Quick/NonZero) under every fault. An injected INERT kill
        // is the kill not working — the runner honestly reports a reap
        // failure and the survivors are asserted below, never a zero-live
        // claim.
        let termination_contained = match fault {
            KillFault::Real => true,
            KillFault::Missing | KillFault::Denied | KillFault::Esrch => matches!(
                kind,
                ChildKind::Quick
                    | ChildKind::NonZero
                    | ChildKind::Slow
                    | ChildKind::IgnoreTerm
                    | ChildKind::LateMarker
            ),
            KillFault::Inert => matches!(kind, ChildKind::Quick | ChildKind::NonZero),
        };
        if termination_contained {
            // CONTAINED cases: ZERO LIVE PROCESSES and NO POST-RETURN
            // FILESYSTEM EFFECTS as the runner left them — WITHOUT any test
            // kill. The runner's own termination (the timeout group kill,
            // the foreground-only group termination, the clean exit) already
            // left zero live processes; this is what the property actually
            // proves.
            assert_pid_gone(child_pid, &format!("{kind:?} × {fault:?} child"));
            if kind.spawns_grandchild() {
                let gc = gc_pid.unwrap_or_else(|| {
                    panic!("{kind:?} × {fault:?}: grandchild-producing case must publish its PID for containment assertion")
                });
                assert_pid_gone(gc, &format!("{kind:?} × {fault:?} grandchild"));
            }
            // The no-post-return-fs probe runs BEFORE any cleanup: the window
            // lets any write a (buggy) still-alive descendant would attempt
            // after the outcome land and be caught — the marker scripts write
            // 1.2s in (LateMarker/Grandchild — killed by the 1s deadline) or
            // 0.4s in (DetachedGrandchild — terminated by the foreground-only
            // group kill), and the probe outlives each with a wide
            // LOAD-TOLERANT margin. A contained case's marker must never
            // appear because the runner killed everything before returning.
            if matches!(kind, ChildKind::LateMarker | ChildKind::Grandchild) {
                std::thread::sleep(Duration::from_millis(300));
            } else if kind == ChildKind::DetachedGrandchild {
                std::thread::sleep(Duration::from_millis(500));
            }
            assert!(
                !dir.path().join("marker").exists(),
                "{kind:?} × {fault:?}: the child wrote a file after the runner returned"
            );
            assert!(
                !dir.path().join("gc-marker").exists(),
                "{kind:?} × {fault:?}: the grandchild wrote a file after the runner returned"
            );
        } else {
            // HONEST-FAILURE cases: the injected kill fault IS the kill not
            // working, so the runner could not contain — and honestly
            // surfaced an error (asserted in the outcome classification,
            // never a fake success). The production observation mirrors the
            // error: the SURVIVOR is still alive — the direct child under an
            // inert timeout kill, the background grandchild under a failed or
            // inert group kill. The marker is NOT asserted absent for these
            // cases (the survivor may write it before the cleanup).
            if matches!(fault, KillFault::Inert) && times_out {
                assert_pid_alive(
                    child_pid,
                    &format!("{kind:?} × {fault:?} child (reap-failure survivor)"),
                );
            }
            if kind.spawns_grandchild() {
                let gc = gc_pid.unwrap_or_else(|| {
                    panic!("{kind:?} × {fault:?}: grandchild-producing case must publish its PID for survivor assertion")
                });
                assert_pid_alive(
                    gc,
                    &format!("{kind:?} × {fault:?} grandchild (group-kill-failure survivor)"),
                );
            }
        }
    }

    // ---- (d) EMERGENCY cleanup: only now, AFTER the production
    // observations ----
    // The injected fault IS the kill not working: the runner surfaced an
    // error (never a fake timeout success) and cleaned up what it could; the
    // test now kills the leftover group and reaps the direct child — the
    // single cleanup reap — so the test leaks nothing. A setsid-ESCAPED
    // grandchild (SetsidInherit/SetsidClose) is outside the group — the
    // runner could not reach it — so the test kills it BY PID (its pid is
    // live, so the kill is safe from pid reuse). For the contained cases the
    // cleanup is a no-op (nothing left to kill).
    if outcome.is_err() {
        // SAFETY: kill(-pgid) == killpg on the group THIS test spawned (the
        // child is the group leader, pgid == its pid).
        unsafe { libc::kill(-(child_pid as i32), libc::SIGKILL) };
        // SAFETY: waitpid on our own child; it died on SIGKILL; ECHILD is
        // harmless when the runner already reaped it.
        unsafe { libc::waitpid(child_pid as i32, std::ptr::null_mut(), 0) };
    }
    if escaped && kind.spawns_grandchild() {
        let gc = gc_pid.unwrap_or_else(|| {
            panic!("{kind:?} × {fault:?}: grandchild-producing case must publish its PID for escaped cleanup")
        });
        // SAFETY: the escaped grandchild is a LIVE process of this test (its
        // pid is allocated — no reuse); SIGKILL lands.
        unsafe { libc::kill(gc as i32, libc::SIGKILL) };
    }

    // ---- NO LEAK after the cleanup: the test itself leaves nothing behind.
    // For the contained cases this re-verifies what the production phase
    // already proved; for the excluded and honest-failure cases it proves
    // the emergency cleanup landed. ----
    assert_pid_gone(child_pid, &format!("{kind:?} × {fault:?} child"));
    if kind.spawns_grandchild() {
        let gc = gc_pid.unwrap_or_else(|| {
            panic!("{kind:?} × {fault:?}: grandchild-producing case must publish its PID for leak check")
        });
        assert_pid_gone(gc, &format!("{kind:?} × {fault:?} grandchild"));
    }
}

fn child_strategy() -> impl Strategy<Value = ChildKind> {
    prop_oneof![
        Just(ChildKind::Quick),
        Just(ChildKind::NonZero),
        Just(ChildKind::Slow),
        Just(ChildKind::IgnoreTerm),
        Just(ChildKind::Grandchild),
        Just(ChildKind::DetachedGrandchild),
        Just(ChildKind::SetsidInherit),
        Just(ChildKind::SetsidClose),
        Just(ChildKind::LateMarker),
    ]
}

fn fault_strategy() -> impl Strategy<Value = KillFault> {
    prop_oneof![
        Just(KillFault::Real),
        Just(KillFault::Missing),
        Just(KillFault::Denied),
        Just(KillFault::Esrch),
        Just(KillFault::Inert),
    ]
}

proptest! {
    // The lifecycle property: every generated (child kind × kill fault) pair
    // must honor the ONE-runner contract. Quick/non-zero children complete
    // with their exit code; slow, TERM-ignoring, grandchild-spawning, and
    // late-marker children time out — and a timeout outcome appears ONLY
    // after the child and its group were proven dead (kill-0 → ESRCH, the
    // reaped proof, for the child AND any grandchild) and the child was
    // reaped exactly once. A command that EXITS but leaves a background
    // grandchild in its process group (DetachedGrandchild) is a FOREGROUND-
    // ONLY violation: the runner terminates the group and errors — never a
    // successful exit-0 outcome. A grandchild that ESCAPES the group via
    // `setsid` but keeps the inherited stdio pipes (SetsidInherit) is caught
    // by the PIPE-EOF containment — an error, never success. A FULLY
    // daemonized grandchild (`setsid` AND closed descriptors, SetsidClose) is
    // the ONE documented contract exclusion — no portable detection exists —
    // and the runner returns success (commands must not daemonize). BOTH
    // setsid-escape cases are EXPLICITLY EXCLUDED from the foreground
    // containment invariant — a setsid-escaped descendant is outside the
    // guarantee (the runner can DETECT a pipe-holding escapee and error, but
    // cannot TERMINATE an escaped process) — so the property asserts the
    // escapee is STILL ALIVE after the runner returned (unsupported
    // daemonization cases never satisfy the invariant), never a false
    // zero-live claim. The property observes the PRODUCTION outcome — process
    // liveness and marker behavior AS THE RUNNER LEFT THEM — BEFORE any test
    // cleanup: the containment invariant is satisfied by the RUNNER's own
    // termination, never by the harness; the emergency cleanup (the group
    // kill + the escaped-grandchild pid kill) runs only afterwards, for the
    // excluded escapees and the injected-fault survivors. A kill failure
    // (missing binary, EPERM, unreachable group) or an ineffective kill
    // surfaces as an ERROR — never a successful `timed out` outcome — and a
    // TERM-ignoring child is escalated to a group KILL. A CONTAINED case's
    // child or grandchild never writes a file after the runner returned (the
    // marker-absence probe runs before any cleanup); for the excluded
    // escapees and the injected-fault survivors the marker is NOT asserted
    // absent (documented). FIXED SEED 0x5EED_5EED (repo style) + bounded cases
    // keep the
    // suite deterministic. This target is SERIALIZED by `nextest.toml`
    // (`test-threads = 1`): the real-process lifecycle never runs
    // concurrently with the deterministic deployment/state-machine
    // properties.
    #![proptest_config(ProptestConfig {
        cases: proptest_cases(16),
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn every_outcome_leaves_zero_live_processes_one_reap_and_no_fs_effects(
        pairs in prop::collection::vec((child_strategy(), fault_strategy()), 1..=3)
    ) {
        for (kind, fault) in pairs {
            run_one_case(kind, fault);
        }
    }
}

/// Helper for the declared-descendants property: drives ONE ChildKind through
/// the real runner (Real kill) and asserts observed descendant count ==
/// declared_descendants(). The observed count is 1 iff a grandchild pid was
/// published (gcpid exists and parses), 0 otherwise. This is contract-driven:
/// a declared-1 kind MUST publish its PID (loud expect), a declared-0 kind
/// MUST NOT have published one.
fn run_declared_descendants_case(kind: ChildKind) {
    let env = SysEnv::from_map(BTreeMap::from([(
        OsString::from("PATH"),
        OsString::from("/bin:/usr/bin"),
    )]));
    let dir = fixture_tmpdir(&env);
    let argv = script_for(kind, dir.path());
    let spawned = std::sync::Arc::new(Mutex::new(Vec::<u32>::new()));
    let runner_reaps = std::sync::Arc::new(AtomicUsize::new(0));
    let seam = std::sync::Arc::new(FaultSeam {
        fault: KillFault::Real,
        group_kills: AtomicUsize::new(0),
    });
    let config = RunnerConfig {
        term_to_kill_grace: Duration::from_millis(25),
        reap_bound: Duration::from_millis(100),
        kill: seam.clone(),
        spawn_observer: Some(std::sync::Arc::new({
            let spawned = spawned.clone();
            move |pid| spawned.lock().unwrap().push(pid)
        })),
        reap_observer: Some(std::sync::Arc::new({
            let runner_reaps = runner_reaps.clone();
            move |_pid| {
                runner_reaps.fetch_add(1, Ordering::SeqCst);
            }
        })),
    };
    let runner = ChildRunner::new(&env, dir.path().to_path_buf(), config);
    let outcome = runner.exec(&argv, TEST_TIMEOUT);
    let child_pid = *spawned
        .lock()
        .unwrap()
        .first()
        .expect("the spawn observer must record the child pid at spawn time");
    let gcpid_path = dir.path().join("gcpid");
    let declared = kind.declared_descendants();
    let (observed, gc_pid_opt) = if kind.spawns_grandchild() {
        let pid = read_gc_pid(&gcpid_path)
            .unwrap_or_else(|| panic!("{kind:?}: grandchild-producing case must publish its PID"));
        (1usize, Some(pid))
    } else {
        let maybe = std::fs::read_to_string(&gcpid_path)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok());
        assert!(
            maybe.is_none(),
            "{kind:?}: declared-0 kind must NOT have published a gcpid, but found pid {maybe:?}"
        );
        (0usize, None)
    };
    assert_eq!(
        observed, declared,
        "{kind:?}: observed descendant count {observed} != declared {declared}"
    );
    // Emergency cleanup so the property never leaks, mirroring run_one_case's
    // post-observation cleanup (group kill + escaped pid kill).
    let escaped = matches!(kind, ChildKind::SetsidInherit | ChildKind::SetsidClose);
    if outcome.is_err() {
        unsafe { libc::kill(-(child_pid as i32), libc::SIGKILL) };
        unsafe { libc::waitpid(child_pid as i32, std::ptr::null_mut(), 0) };
    }
    if escaped && let Some(gc) = gc_pid_opt {
        unsafe { libc::kill(gc as i32, libc::SIGKILL) };
    }
    assert_pid_gone(
        child_pid,
        &format!("{kind:?} child (descendant-count cleanup)"),
    );
    if let Some(gc) = gc_pid_opt {
        assert_pid_gone(
            gc,
            &format!("{kind:?} grandchild (descendant-count cleanup)"),
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: proptest_cases(16),
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn declared_descendants_matches_observed(kind in child_strategy()) {
        run_declared_descendants_case(kind);
    }
}
