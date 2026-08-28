//! THE shared bounded child-runner for local command execution: the ONE owner
//! of every local command child, from spawn to the mandatory reap.
//!
//! # The lifecycle contract
//!
//! `LocalTransport::exec` used to split the child between the caller and a
//! DETACHED reaping thread and, on timeout, fire-and-forget an external
//! `kill -9 <pid>` and return a SUCCESSFUL timeout outcome — before the child
//! was proven dead and reaped, with a kill failure silently ignored and only
//! the direct child (never its process GROUP) signalled. This runner replaces
//! that with a bounded lifecycle:
//!
//! * **Synchronized child ownership** — the runner (via [`OwnedChild`]) owns
//!   the `Child` handle exclusively from spawn until the single reap. There is
//!   no detached thread that can outlive the call, and no path that drops the
//!   handle un-reaped: [`OwnedChild::drop`] kills the group + owned child and
//!   waits (bounded) as a final backstop, so a live child is never abandoned
//!   even on an error path that cannot complete the reap itself.
//! * **Process-group termination** — the child is spawned into its OWN process
//!   group (`process_group(0)` — the child becomes the group leader, pgid ==
//!   pid), so a timeout terminates the WHOLE group (`killpg` SIGTERM, then —
//!   after a short grace — SIGKILL) and GRANDCHILDREN die with it.
//! * **Mandatory wait/join before returning** — every returned outcome
//!   (success, timeout, error) happens only after the child was REAPED: the
//!   runner waits synchronously on its owned handle, `try_wait` consumes the
//!   exit status exactly once, and "proven dead" means the wait returned.
//! * **A timeout-kill failure is an ERROR** — if the group kill fails (a real
//!   failure, not the benign ESRCH of a group that is already gone), or the
//!   escalated kill fails, or the reap cannot be confirmed within the bound,
//!   the runner returns `Err` — NEVER a successful `exit_code: -1,
//!   "timed out"` outcome. Only a confirmed terminated-and-reaped group yields
//!   the timeout outcome.
//! * **Bounded** — the lifecycle is bounded: per-exec, no leaked threads
//!   (there are none), no leaked handles, no live processes across calls, and
//!   every kill/reap wait is bounded by a configurable deadline.
//!
//! The kill path is a [`KillSeam`] (a kill-function seam): production uses
//! [`RealKill`] (`killpg(2)` — no shell, no external `kill` binary), and the
//! property test injects syscall-level faults (a missing/unavailable kill,
//! EPERM, ESRCH, an inert kill) without any subprocess fakery. The process
//! group + escalation primitives are shared with the SSH runner's real seam
//! ([`kill_process_group`], [`TERM_TO_KILL_GRACE`]), so both transports
//! terminate process groups, not bare pids.

use crate::env::SysEnv;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Grace between the group SIGTERM and the escalated group SIGKILL: a child
/// (or grandchild) that handles TERM gracefully gets a chance to clean up,
/// one that ignores it is force-killed. Shared with the SSH runner's real
/// seam so both transports use the same termination policy.
pub(crate) const TERM_TO_KILL_GRACE: Duration = Duration::from_millis(200);

/// Bound on the post-termination reap: after the escalation, the child must
/// be collected within this window or the runner reports a reap failure. A
/// SIGKILL'd child dies in microseconds; this bound only guards the
/// pathological cases (an ineffective kill), so it is generous in production
/// and tiny in tests (see [`RunnerConfig::reap_bound`]).
pub(crate) const KILL_REAP_BOUND: Duration = Duration::from_secs(2);

/// The [`OwnedChild::drop`] backstop's bounded wait: after killing the group
/// and the owned child, drop waits this long for the reap before giving up —
/// long enough for a real SIGKILL to land (microseconds), short enough that a
/// test-injected inert kill cannot stall a suite.
const DROP_REAP_BOUND: Duration = Duration::from_millis(100);

/// Send `sig` to the whole process group `pgid` via `killpg(2)`: `pgid` is
/// the group the runner created at spawn (`process_group(0)`), so the child
/// is its leader and every member (including grandchildren that did not start
/// a new session) receives the signal. The result is surfaced — a kill that
/// cannot be delivered must never be silently ignored.
pub(crate) fn kill_process_group(pgid: i32, sig: i32) -> std::io::Result<()> {
    // SAFETY: `killpg` on a process group this runner created for its own
    // child; `pgid` is the child's pid (positive) and `sig` is a valid libc
    // signal constant.
    let rc = unsafe { libc::killpg(pgid, sig) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// The kill seam behind [`ChildRunner`]: the syscall-level termination
/// surface, injectable for tests (a kill-function pointer seam). The runner
/// reports a kill failure as an error only when the seam says the signal
/// could not be delivered; an inert seam (returns `Ok` without signalling) is
/// caught by the reap bound instead.
pub(crate) trait KillSeam: Send + Sync {
    /// Signal the whole process group `pgid`.
    fn kill_group(&self, pgid: i32, sig: i32) -> std::io::Result<()>;
    /// Signal the OWNED child directly (`Child::kill`): the last-resort rung
    /// that catches a child which escaped its group (e.g. `setsid`), where
    /// the group kill reports the group unreachable. A kill through the owned
    /// handle can never hit a pid the OS recycled: the handle is consumed by
    /// the single reap and nothing is signalled after it.
    fn kill_owned(&self, child: &mut Child) -> std::io::Result<()>;
}

/// Production seam: `killpg(2)` for the group, the owned `Child::kill`
/// (SIGKILL on the owned handle) as the last resort.
pub(crate) struct RealKill;

impl KillSeam for RealKill {
    fn kill_group(&self, pgid: i32, sig: i32) -> std::io::Result<()> {
        kill_process_group(pgid, sig)
    }
    fn kill_owned(&self, child: &mut Child) -> std::io::Result<()> {
        child.kill()
    }
}

/// The runner's policy knobs: termination timing, the reap bound, the kill
/// seam, and (tests only) the spawn/reap observers that record the lifecycle
/// in the parent. Construct via [`RunnerConfig::production`]; tests build
/// their own with injected faults and tiny bounds.
pub(crate) struct RunnerConfig {
    /// Grace between the group SIGTERM and the escalated group SIGKILL.
    pub(crate) term_to_kill_grace: Duration,
    /// Bound on the post-termination reap: if the child is still alive this
    /// long after the timeout fired, the termination is ineffective and the
    /// runner reports a reap failure (never a fake timeout success).
    pub(crate) reap_bound: Duration,
    /// The kill seam (production: [`RealKill`]; tests: injected faults).
    pub(crate) kill: Arc<dyn KillSeam>,
    /// Test-only spawn observer: called synchronously in the parent right
    /// after a successful spawn with the child's pid — before the timeout
    /// clock starts — so a test can assert the pid is gone afterwards without
    /// any child-written pidfile (which would race the deadline kill).
    #[cfg(test)]
    pub(crate) spawn_observer: Option<Arc<dyn Fn(u32) + Send + Sync>>,
    /// Test-only reap observer: called exactly once, at the single reap.
    #[cfg(test)]
    pub(crate) reap_observer: Option<Arc<dyn Fn(u32) + Send + Sync>>,
}

impl RunnerConfig {
    /// The production configuration: 200ms TERM→KILL grace, a 2s reap bound,
    /// and the real `killpg`/`Child::kill` seam.
    pub(crate) fn production() -> Self {
        RunnerConfig {
            term_to_kill_grace: TERM_TO_KILL_GRACE,
            reap_bound: KILL_REAP_BOUND,
            kill: Arc::new(RealKill),
            #[cfg(test)]
            spawn_observer: None,
            #[cfg(test)]
            reap_observer: None,
        }
    }
}

/// How a runner invocation ended, before the transport maps it to its own
/// outcome shape. The timeout variant exists ONLY after the child (and its
/// group) was proven dead and reaped.
#[derive(Debug)]
pub(crate) enum RunOutcome {
    /// The child exited (or was killed by a signal) before the timeout fired.
    Exited {
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    /// The timeout fired; the child and its group were terminated AND reaped.
    TimedOut { stderr: String },
}

/// How a runner invocation failed. Every variant is returned only AFTER the
/// runner cleaned up the child (kill + reap where possible) — an error can
/// never leave a live, un-reaped child behind by contract (the [`OwnedChild`]
/// drop backstop covers the paths where even that is impossible).
#[derive(Debug)]
pub(crate) enum RunError {
    /// The child could not be spawned.
    Spawn(String),
    /// Waiting on the child failed (wait error, pipe read error).
    Wait(String),
    /// A timeout-termination signal could not be delivered (kill failure).
    Kill(String),
    /// The child was not collected within the reap bound after termination.
    Reap(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Spawn(m) => write!(f, "{m}"),
            RunError::Wait(m) => write!(f, "{m}"),
            RunError::Kill(m) => write!(f, "kill failure: {m}"),
            RunError::Reap(m) => write!(f, "reap failure: {m}"),
        }
    }
}

/// The child the runner OWNS from spawn until the single reap. A drop without
/// a reap is a contract violation, so [`OwnedChild::drop`] kills the group
/// and the owned child and waits (bounded) — the backstop that makes
/// "abandon a live child" impossible by construction, even on an error path
/// whose reap could not complete.
struct OwnedChild {
    child: Child,
    kill: Arc<dyn KillSeam>,
    /// Set by the single successful `try_wait`: from then on the exit status
    /// is consumed and nothing may signal anything (a pid the OS recycled
    /// after the reap can never be hit — the drop backstop returns early).
    reaped: bool,
}

impl OwnedChild {
    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        match self.child.try_wait()? {
            Some(st) => {
                self.reaped = true;
                Ok(Some(st))
            }
            None => Ok(None),
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // Final backstop: never abandon a live child. Kill the whole group,
        // then the owned handle, then wait (bounded) for the reap. Under the
        // production seam a real SIGKILL lands in microseconds; under an
        // injected inert kill the bound expires and the child is left to the
        // test's own cleanup (the fault is exactly the kill not working).
        let pgid = self.child.id() as i32;
        let _ = self.kill.kill_group(pgid, libc::SIGKILL);
        let _ = self.kill.kill_owned(&mut self.child);
        let budget = Instant::now() + DROP_REAP_BOUND;
        while Instant::now() < budget {
            if let Ok(Some(_)) = self.child.try_wait() {
                self.reaped = true;
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// THE shared bounded child-runner for local command execution: spawn the
/// child into its OWN process group with piped stdout/stderr, wait with the
/// caller's timeout, on timeout terminate the GROUP (TERM, grace, KILL) and
/// escalate to the owned handle, and return every outcome — success, timeout,
/// error — only after the child was REAPED exactly once. A timeout-kill or
/// reap failure is an ERROR, never a successful timeout outcome.
///
/// The runner is per-exec and owns nothing between calls: the child lives in
/// [`OwnedChild`] inside [`ChildRunner::exec`] and is collected before the
/// call returns, so there are no leaked threads, handles, or processes across
/// calls — the lifecycle is bounded.
pub(crate) struct ChildRunner {
    /// The child environment snapshot: every spawned child receives THIS
    /// snapshot as its ENTIRE environment ([`SysEnv::apply_to_command`]:
    /// `env_clear` first, then the snapshot's variables) — deterministic and
    /// hermetic, never whatever the parent env looks like at spawn time.
    env: SysEnv,
    /// The child's working directory (the transport root).
    cwd: PathBuf,
    config: RunnerConfig,
}

impl ChildRunner {
    /// Build a runner that spawns children with the environment snapshot
    /// `env` in working directory `cwd` under the policy `config`.
    pub(crate) fn new(env: &SysEnv, cwd: PathBuf, config: RunnerConfig) -> Self {
        ChildRunner {
            env: env.clone(),
            cwd,
            config,
        }
    }

    /// Execute `argv` (no shell) bounded by `timeout`. Returns
    /// [`RunOutcome::Exited`] when the child finishes in time (exit code +
    /// captured stdout/stderr), [`RunOutcome::TimedOut`] ONLY after the child
    /// and its process group were terminated AND the child was reaped, or an
    /// error when the spawn, the wait, the termination kill, or the reap
    /// failed — a failed timeout kill never yields a successful timeout
    /// outcome.
    pub(crate) fn exec(
        &self,
        argv: &[String],
        timeout: Duration,
    ) -> std::result::Result<RunOutcome, RunError> {
        let mut cmd = std::process::Command::new(&argv[0]);
        self.env.apply_to_command(&mut cmd);
        cmd.args(&argv[1..]);
        cmd.current_dir(&self.cwd);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        // The child becomes its OWN process-group leader (pgid == pid):
        // timeout termination signals the WHOLE group, so grandchildren die
        // with it. Unix-only crate; `process_group` is the std Unix API.
        cmd.process_group(0);
        let child = cmd
            .spawn()
            .map_err(|e| RunError::Spawn(format!("spawn {argv:?}: {e}")))?;
        let mut owned = OwnedChild {
            child,
            kill: self.config.kill.clone(),
            reaped: false,
        };
        let pid = owned.child.id();
        let pgid = pid as i32;
        // The parent records the pid synchronously at spawn time — before the
        // timeout clock starts — so tests can assert the pid is gone after
        // the outcome without a child-written pidfile (which would race the
        // deadline kill).
        #[cfg(test)]
        if let Some(observer) = &self.config.spawn_observer {
            observer(pid);
        }
        // Non-blocking pipe read ends: the wait loop drains without blocking
        // and the post-reap EOF drain is bounded — a grandchild that keeps a
        // pipe open can never hang the outcome.
        set_nonblocking(&mut owned.child.stdout).map_err(|e| RunError::Wait(e.to_string()))?;
        set_nonblocking(&mut owned.child.stderr).map_err(|e| RunError::Wait(e.to_string()))?;

        let deadline = Instant::now() + timeout;
        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();
        let mut timed_out = false;
        let mut term_started = Instant::now();
        let mut sent_kill = false;
        let mut sent_owned = false;
        let mut kill_error: Option<String> = None;

        let status = loop {
            drain_available(&mut owned.child.stdout, &mut stdout)
                .map_err(|e| RunError::Wait(e.to_string()))?;
            drain_available(&mut owned.child.stderr, &mut stderr)
                .map_err(|e| RunError::Wait(e.to_string()))?;
            match owned.try_wait() {
                Ok(Some(st)) => break st,
                Ok(None) => {}
                Err(e) => {
                    return Err(RunError::Wait(format!("wait {argv:?}: {e}")));
                }
            }
            let now = Instant::now();
            if !timed_out && now >= deadline {
                timed_out = true;
                term_started = now;
                // Graceful TERM of the WHOLE process group.
                if let Err(e) = self.config.kill.kill_group(pgid, libc::SIGTERM) {
                    // ESRCH is benign only when the child itself is already
                    // gone (it exited as the deadline fired — the wait reaps
                    // it next); a live child behind an unreachable group is a
                    // real termination failure.
                    let alive = matches!(owned.try_wait(), Ok(None));
                    if alive {
                        kill_error = Some(format!("TERM group {pgid}: {e}"));
                    }
                }
            }
            if timed_out {
                let since = now.duration_since(term_started);
                if since >= self.config.term_to_kill_grace && !sent_kill {
                    sent_kill = true;
                    // Escalate to KILL on the whole group: a child that
                    // ignores TERM must still die.
                    if let Err(e) = self.config.kill.kill_group(pgid, libc::SIGKILL) {
                        let alive = matches!(owned.try_wait(), Ok(None));
                        if alive {
                            kill_error = Some(format!("KILL group {pgid}: {e}"));
                        }
                    }
                }
                if since >= self.config.term_to_kill_grace * 2 && !sent_owned {
                    sent_owned = true;
                    // Last-resort direct kill on the OWNED handle: catches a
                    // child that escaped its group (e.g. setsid).
                    if let Err(e) = self.config.kill.kill_owned(&mut owned.child) {
                        kill_error = Some(format!("kill child {pid}: {e}"));
                    }
                }
                if since >= self.config.reap_bound {
                    // The child is STILL alive after every termination
                    // attempt: the kill did not take effect. This is a reap
                    // failure — NEVER a successful timeout outcome.
                    return Err(RunError::Reap(format!(
                        "child {pid} still alive {:?} after the timeout termination",
                        self.config.reap_bound
                    )));
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        };

        // REAPED: `try_wait` consumed the exit status exactly once (a second
        // wait would ECHILD). From here on nothing signals anything.
        #[cfg(test)]
        if let Some(observer) = &self.config.reap_observer {
            observer(pid);
        }
        // Bounded drain to EOF: the child is dead and its pipes hold the
        // remaining output. A grandchild that keeps a pipe open cannot hang
        // the outcome — the drain gives up after the reap bound.
        let drain_bound = self.config.reap_bound;
        drain_to_eof(&mut owned.child.stdout, &mut stdout, drain_bound)
            .map_err(|e| RunError::Wait(e.to_string()))?;
        drain_to_eof(&mut owned.child.stderr, &mut stderr, drain_bound)
            .map_err(|e| RunError::Wait(e.to_string()))?;

        if timed_out {
            // A timeout outcome is legitimate ONLY when the termination was
            // effective: a kill failure is an ERROR, never a fake timeout.
            if let Some(e) = kill_error {
                return Err(RunError::Kill(format!("timeout termination failed: {e}")));
            }
            return Ok(RunOutcome::TimedOut {
                stderr: format!("timed out after {timeout:?}"),
            });
        }
        Ok(RunOutcome::Exited {
            exit_code: status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }
}

/// Put a child pipe read end into non-blocking mode, so reads never block and
/// the bounded drain controls all waiting.
fn set_nonblocking<R: AsRawFd>(stream: &mut Option<R>) -> std::io::Result<()> {
    let Some(stream) = stream.as_mut() else {
        return Ok(());
    };
    let fd = stream.as_raw_fd();
    // SAFETY: fcntl on a pipe read end this runner opened for its own child.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above; O_NONBLOCK only changes the read blocking semantics.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Drain whatever bytes a running child currently has buffered in a pipe
/// WITHOUT blocking: `poll(2)` with a zero timeout reports readability first,
/// then a single `read`, so the wait loop never parks on a pipe while the
/// child is still running — a child that produces a lot of output is drained
/// while running instead of filling its pipe and stalling.
fn drain_available<R>(stream: &mut Option<R>, buf: &mut Vec<u8>) -> std::io::Result<()>
where
    R: Read + AsRawFd,
{
    let Some(stream) = stream.as_mut() else {
        return Ok(());
    };
    let mut pfd = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `poll` with a zero timeout on a real pipe read end this runner
    // opened for its own child; the fd is always valid here and never blocks.
    if unsafe { libc::poll(&mut pfd, 1, 0) } <= 0 {
        return Ok(());
    }
    let mut chunk = [0u8; 8192];
    match stream.read(&mut chunk) {
        Ok(0) => Ok(()),
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
        Err(e) => Err(e),
    }
}

/// Drain a child pipe to EOF, bounded: reads never block (non-blocking read
/// ends), and between reads `poll` waits only up to `bound` — a grandchild
/// that outlives the direct child and keeps a pipe open cannot hang the
/// outcome; the drain returns what it collected when the bound expires.
fn drain_to_eof<R>(
    stream: &mut Option<R>,
    buf: &mut Vec<u8>,
    bound: Duration,
) -> std::io::Result<()>
where
    R: Read + AsRawFd,
{
    let Some(stream) = stream.as_mut() else {
        return Ok(());
    };
    let deadline = Instant::now() + bound;
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Ok(());
                }
                let ms = remaining.as_millis().min(i32::MAX as u128) as i32;
                let mut pfd = libc::pollfd {
                    fd: stream.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: `poll` on a real pipe read end this runner owns.
                let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
                if rc < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if rc == 0 {
                    return Ok(());
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// Property test for the lifecycle contract: real children (quick-exit,
/// slow, TERM-ignoring, grandchild-spawning, late-marker-writing) driven
/// through [`ChildRunner::exec`] under injected kill faults (missing kill,
/// EPERM, ESRCH, an inert kill), asserting for EVERY returned outcome: ZERO
/// live processes (no child or grandchild of the spawned group remains — a
/// process that merely received a signal but was not reaped, a zombie, still
/// answers `kill(pid, 0)`), EXACTLY ONE reap (the runner's single
/// `try_wait`, tracked via the reap observer; only the injected-unkillable
/// fault lets the test's own cleanup be that one reap), and NO post-return
/// filesystem effects (a child/grandchild that would write a marker after
/// its "timeout" must never get the chance — the group is proven dead before
/// the outcome escapes).
#[cfg(test)]
mod runner_property_tests {
    use super::*;
    use crate::testutil::{fixture_tmpdir, proptest_cases};
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::path::Path;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The runner deadline for every generated case: long enough that a
    /// quick-exit child finishes in time, short enough that every timed-out
    /// case stays fast. The late-marker child writes its marker after 0.25s —
    /// past this deadline — so a leaked (returned-while-still-alive) child
    /// would be caught writing AFTER the outcome.
    const TEST_TIMEOUT: Duration = Duration::from_millis(200);

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
        /// Sleeps 0.25s then would write a marker file: the probe for
        /// post-return filesystem effects.
        LateMarker,
    }

    /// The injected kill fault. The runner uses `killpg(2)` directly (no
    /// external `kill` binary), so the "missing kill" fault is a syscall-level
    /// failure (ENOENT — what a missing external binary would surface as),
    /// EPERM a permission failure, ESRCH an unreachable group, and Inert a
    /// kill that "succeeds" but signals nothing — the only way to force the
    /// reap bound.
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

    /// The `sh -c` script for a child kind, writing its marker/pid files
    /// under `dir`.
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
            ChildKind::LateMarker => vec![
                "sh".into(),
                "-c".into(),
                format!("sleep 0.25; touch {}", dir.join("marker").display()),
            ],
        }
    }

    /// Poll `kill(pid, 0)` until the process is GONE: ESRCH is returned only
    /// for a process that no longer exists — a zombie still answers, so
    /// "gone" is the REAPED proof, not merely "signalled".
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

    /// The grandchild pid, from the pidfile the child writes IMMEDIATELY at
    /// spawn (`echo $! > gcpid`) — written ~1ms in, far before the 200ms
    /// deadline, so no child-written-pidfile race.
    fn read_gc_pid(path: &Path) -> Option<u32> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(s) = std::fs::read_to_string(path) {
                return s.trim().parse::<u32>().ok();
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Drive ONE generated (child kind × kill fault) case through the real
    /// runner and assert the lifecycle contract for the returned outcome.
    fn run_one_case(kind: ChildKind, fault: KillFault) {
        let env = SysEnv::from_map(BTreeMap::from([(
            OsString::from("PATH"),
            OsString::from("/bin:/usr/bin"),
        )]));
        let dir = fixture_tmpdir(&env).expect("tempdir for the child's markers");
        let argv = script_for(kind, dir.path());
        let spawned: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let runner_reaps = Arc::new(AtomicUsize::new(0));
        let seam = Arc::new(FaultSeam {
            fault,
            group_kills: AtomicUsize::new(0),
        });
        let config = RunnerConfig {
            term_to_kill_grace: Duration::from_millis(25),
            reap_bound: Duration::from_millis(100),
            kill: seam.clone(),
            spawn_observer: Some(Arc::new({
                let spawned = spawned.clone();
                move |pid| spawned.lock().unwrap().push(pid)
            })),
            reap_observer: Some(Arc::new({
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
        let gc_pid = (kind == ChildKind::Grandchild)
            .then(|| read_gc_pid(&dir.path().join("gcpid")))
            .flatten();

        let times_out = matches!(
            kind,
            ChildKind::Slow | ChildKind::IgnoreTerm | ChildKind::Grandchild | ChildKind::LateMarker
        );

        // ---- outcome classification ----
        match (&outcome, times_out, fault) {
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
                // The timeout outcome keeps its exact shape — but only after
                // the group was proven dead AND reaped (asserted below).
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
                if fault == KillFault::Inert { 0 } else { 1 },
                "{kind:?} × {fault:?}: an error outcome must reap once when its kills were effective, and never fake a reap it did not do"
            ),
        }

        // ---- cleanup under an injected kill/reap failure ----
        // The injected fault IS the kill not working: the runner surfaced an
        // error (never a fake timeout success) and cleaned up what it could;
        // the test now kills the leftover group and reaps the direct child —
        // the single cleanup reap — so the zero-live assertion is meaningful.
        if outcome.is_err() {
            // SAFETY: kill(-pgid) == killpg on the group THIS test spawned
            // (the child is the group leader, pgid == its pid).
            unsafe { libc::kill(-(child_pid as i32), libc::SIGKILL) };
            // SAFETY: waitpid on our own child; it died on SIGKILL; ECHILD is
            // harmless when the runner already reaped it.
            unsafe { libc::waitpid(child_pid as i32, std::ptr::null_mut(), 0) };
        }

        // ---- ZERO LIVE PROCESSES ----
        assert_pid_gone(child_pid, &format!("{kind:?} × {fault:?} child"));
        if let Some(gc) = gc_pid {
            assert_pid_gone(gc, &format!("{kind:?} × {fault:?} grandchild"));
        }

        // ---- NO POST-RETURN FILESYSTEM EFFECTS ----
        // The probe window lets any write that a (buggy) still-alive child or
        // grandchild would attempt after the outcome land and be caught: the
        // marker scripts write 0.25s in, the probe outlives that.
        if matches!(kind, ChildKind::LateMarker | ChildKind::Grandchild) {
            std::thread::sleep(Duration::from_millis(300));
        }
        assert!(
            !dir.path().join("marker").exists(),
            "{kind:?} × {fault:?}: the child wrote a file after the runner returned"
        );
        assert!(
            !dir.path().join("gc-marker").exists(),
            "{kind:?} × {fault:?}: the grandchild wrote a file after the runner returned"
        );
    }

    fn child_strategy() -> impl Strategy<Value = ChildKind> {
        prop_oneof![
            Just(ChildKind::Quick),
            Just(ChildKind::NonZero),
            Just(ChildKind::Slow),
            Just(ChildKind::IgnoreTerm),
            Just(ChildKind::Grandchild),
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
        // The lifecycle property: every generated (child kind × kill fault)
        // pair must honor the ONE-runner contract. Quick/non-zero children
        // complete with their exit code; slow, TERM-ignoring, grandchild-
        // spawning, and late-marker children time out — and a timeout outcome
        // appears ONLY after the child and its group were proven dead (kill-0
        // → ESRCH, the reaped proof, for the child AND any grandchild) and
        // the child was reaped exactly once. A kill failure (missing binary,
        // EPERM, unreachable group) or an ineffective kill surfaces as an
        // ERROR — never a successful `timed out` outcome — and a TERM-
        // ignoring child is escalated to a group KILL. No child or grandchild
        // ever writes a file after the runner returned. FIXED SEED 0x5EED_5EED
        // (repo style) + bounded cases keep the suite deterministic.
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
}
