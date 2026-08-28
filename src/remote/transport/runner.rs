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
//! * **Foreground-only** — commands must not daemonize. After the direct
//!   child exits, the runner checks its process group for LIVE leftover
//!   members (a background descendant the command left behind). The check is
//!   race-free by construction: the child is held as an UNREAPED ZOMBIE for
//!   its duration (`waitid(2)` with `WNOWAIT` — a zombie holds its pid, and
//!   therefore its process-group id (the child is the group leader, pgid ==
//!   pid), allocated until reaped, so a `killpg` in that window can never
//!   hit a pid the OS recycled for an unrelated process), the group is
//!   ENUMERATED (Linux: a `/proc/*/stat` scan; macOS: `proc_listpgrp`) with
//!   our own zombie excluded, and any LIVE leftover member triggers the
//!   termination (TERM, grace, KILL — the timeout path's escalation) plus an
//!   ERROR — a command that leaves background processes is a contract
//!   violation, NEVER a successful outcome. Containment ALSO covers a
//!   descendant that ESCAPED the group via `setsid` but kept the inherited
//!   stdio pipes: the pipes EOF exactly when the last holder dies, so a pipe
//!   still open at the drain bound is a provable violation → error. The ONE
//!   documented exclusion: a FULLY daemonized descendant (`setsid` AND
//!   closed descriptors) is outside the contract — no portable detection
//!   exists without cgroups/subreaper support (Linux) or a remote supervisor
//!   (ssh); commands must not daemonize. A CLEAN command (no live members —
//!   the common case) pays one enumeration and its exit code and captured
//!   output are exactly as before.
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

/// True when the direct child has EXITED but has NOT been reaped yet
/// (`waitid(2)` with `WNOHANG | WNOWAIT | WEXITED`): the child remains a
/// ZOMBIE, and a zombie holds its pid — and therefore its process-group id
/// (the child is the group leader, pgid == pid) — allocated until reaped.
/// The foreground-only check runs between this peek and the reap, so a
/// `killpg(pgid, ...)` in that window can never race a pid the OS recycled
/// for an unrelated process: the group being signalled is provably ours.
/// ECHILD (the child is gone — reaped or never ours) is treated as exited so
/// the caller proceeds to the reap instead of spinning.
fn child_exited_unreaped(pid: u32) -> std::io::Result<bool> {
    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `waitid` on our own child (a positive pid, the direct child of
    // this process); `WNOWAIT` leaves it waitable for the subsequent reap;
    // `WNOHANG` never blocks; `WEXITED` reports the exited transition; the
    // zero-initialized siginfo is written by the kernel only on success.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as _,
            &mut si,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ECHILD) {
            return Ok(true);
        }
        return Err(e);
    }
    Ok(si.si_pid != 0)
}

/// The LIVE (non-zombie) members of the process group `pgid`, excluding the
/// runner's own child `exclude_pid`. This is the FOREGROUND-ONLY detection:
/// after the direct child exits (held as a zombie), any remaining live member
/// is a background descendant the command left behind. The enumeration never
/// uses the fault-injected [`KillSeam`] — it is a pure detection primitive,
/// so an injected kill fault cannot turn a clean group into a false
/// "leftover". A scan error (a vanished/EPERM process mid-scan) skips that
/// entry; only a fully failed scan degrades to an empty list.
#[cfg(target_os = "linux")]
fn live_group_members(pgid: i32, exclude_pid: u32) -> Vec<i32> {
    let mut members = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return members;
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str() else {
            continue;
        };
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };
        if pid == exclude_pid as i32 {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // Format: `pid (comm) state ppid pgrp session ...` — `comm` may
        // contain spaces AND ')' — anchor on the LAST ')'.
        let Some(rest) = stat.rsplit_once(')') else {
            continue;
        };
        let mut fields = rest.1.split_whitespace();
        let state = fields.next().unwrap_or("");
        let _ppid = fields.next();
        let pgrp: i32 = fields.next().and_then(|s| s.parse().ok()).unwrap_or(-1);
        if pgrp == pgid && !state.starts_with('Z') {
            members.push(pid);
        }
    }
    members
}

#[cfg(target_os = "macos")]
fn live_group_members(pgid: i32, exclude_pid: u32) -> Vec<i32> {
    // `proc_listpgrppids(3)`: the pids of every process in the group —
    // ZOMBIES INCLUDED (a killed descendant that launchd has not yet reaped
    // is still listed). A zombie is NOT live, so every member's state is
    // read via `proc_pidinfo(PROC_PIDTBSDINFO)` (the `pbi_status` field at
    // byte offset 4; `SZOMB` = 5) and zombies are excluded — otherwise a
    // command whose descendants were killed would be falsely reported as
    // having left background processes. Our own zombie child is excluded by
    // pid (it is the group leader, still waitable until we reap it). A
    // member whose state cannot be read has vanished (reaped) in the window
    // between the enumeration and the read — it is not live, so it is
    // excluded too.
    let mut buf = [0i32; 4096]; // room for up to 4096 group members
    let n = unsafe { proc_listpgrppids(pgid, buf.as_mut_ptr().cast(), (buf.len() * 4) as i32) };
    if n <= 0 {
        return Vec::new();
    }
    let n = (n as usize).min(buf.len());
    buf[..n]
        .iter()
        .copied()
        .filter(|p| *p != exclude_pid as i32 && !macos_is_not_live(*p))
        .collect()
}

/// Whether the member is NOT live — a zombie (`SZOMB` = 5) or already
/// vanished (reaped in the window between the enumeration and the read,
/// which makes `proc_pidinfo` fail): either way it must be EXCLUDED from
/// the live-members list, or a command whose descendants were killed would
/// be falsely reported as having left background processes.
#[cfg(target_os = "macos")]
fn macos_is_not_live(pid: i32) -> bool {
    // The first 8 bytes of `struct proc_bsdinfo` are `pbi_flags` (offset 0)
    // and `pbi_status` (offset 4, a uint32 copy of the process state); the
    // full struct (with rusage) is ~136 bytes on modern macOS, so the buffer
    // must be at least that large for `proc_pidinfo` to write anything. A
    // zombie (`SZOMB` = 5 from sys/proc.h) is not live. A failed read means
    // the process has vanished — not live either.
    const PROC_PIDTBSDINFO: i32 = 3;
    const SZOMB: u32 = 5;
    let mut bsd = [0u8; 256];
    let n = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            bsd.as_mut_ptr().cast(),
            bsd.len() as i32,
        )
    };
    if n < 8 {
        return true; // gone (or unreadable) — not a live member
    }
    u32::from_le_bytes([bsd[4], bsd[5], bsd[6], bsd[7]]) == SZOMB
}

#[cfg(target_os = "macos")]
#[link(name = "proc")]
unsafe extern "C" {
    fn proc_listpgrppids(pid: i32, buffer: *mut std::ffi::c_void, buffersize: i32) -> i32;
    fn proc_pidinfo(
        pid: i32,
        flavor: i32,
        arg: u64,
        buffer: *mut std::ffi::c_void,
        buffersize: i32,
    ) -> i32;
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn live_group_members(_pgid: i32, _exclude_pid: u32) -> Vec<i32> {
    compile_error!("live group-member enumeration is implemented for Linux and macOS only");
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
    /// The command exited but left members of its process group alive — a
    /// background descendant the command spawned outlived it. The group was
    /// terminated (TERM → KILL) and the violation is reported as an error:
    /// commands are FOREGROUND-ONLY, a command that leaves background
    /// processes is never a successful outcome.
    Background(String),
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
            RunError::Background(m) => write!(f, "{m}"),
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
    /// Reap the child (a blocking wait on an already-exited zombie returns
    /// immediately with its status) and mark the handle reaped: from here on
    /// nothing may signal anything — the pid is released by this call.
    fn wait(&mut self) -> std::io::Result<ExitStatus> {
        let st = self.child.wait()?;
        self.reaped = true;
        Ok(st)
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
    /// captured stdout/stderr) AND left no members of its process group
    /// behind (commands are FOREGROUND-ONLY), [`RunOutcome::TimedOut`] ONLY
    /// after the child and its process group were terminated AND the child
    /// was reaped, or an error when the spawn, the wait, the termination
    /// kill, or the reap failed — a failed timeout kill never yields a
    /// successful timeout outcome, and a command that exited but left
    /// background processes in its group is a violation, never a successful
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

        // Wait loop: detect the child's exit WITHOUT reaping it (`waitid`
        // WNOWAIT peek — the child becomes a ZOMBIE and stays waitable,
        // holding its pid/pgid allocated for the foreground-only check
        // that follows the loop). On timeout, terminate the group and
        // escalate exactly as before; every kill failure is recorded.
        loop {
            drain_available(&mut owned.child.stdout, &mut stdout)
                .map_err(|e| RunError::Wait(e.to_string()))?;
            drain_available(&mut owned.child.stderr, &mut stderr)
                .map_err(|e| RunError::Wait(e.to_string()))?;
            if child_exited_unreaped(pid)
                .map_err(|e| RunError::Wait(format!("wait {argv:?}: {e}")))?
            {
                break;
            }
            let now = Instant::now();
            if !timed_out && now >= deadline {
                timed_out = true;
                term_started = now;
                // Graceful TERM of the WHOLE process group.
                if let Err(e) = self.config.kill.kill_group(pgid, libc::SIGTERM) {
                    // ESRCH is benign only when the child itself is already
                    // gone (it exited as the deadline fired — the peek
                    // reports it next); a live child behind an unreachable
                    // group is a real termination failure. The liveness
                    // check must NOT reap: the child stays a zombie until
                    // the post-loop foreground check.
                    let alive = child_exited_unreaped(pid)
                        .map(|exited| !exited)
                        .unwrap_or(false);
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
                        let alive = child_exited_unreaped(pid)
                            .map(|exited| !exited)
                            .unwrap_or(false);
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
        }

        // The child has EXITED but is still a ZOMBIE: the `waitid` WNOWAIT
        // peek above left it waitable, so its pid — and therefore its
        // process-group id (the child is the group leader, pgid == pid) — is
        // still allocated. Every foreground-only check and group termination
        // below happens while the zombie holds the pgid, so a `killpg` can
        // NEVER race a pid the OS recycled for an unrelated process (the
        // failure mode that made a probe-after-reap racy under parallel
        // execution).
        //
        // FOREGROUND-ONLY: enumerate the LIVE members of the child's process
        // group (our zombie excluded). If any remain, the command left a
        // background descendant: terminate the WHOLE group (TERM → grace →
        // KILL, the timeout path's escalation) and report the violation as
        // an ERROR, never a successful outcome; the essential contract — no
        // live process of the group after the return — is enforced BEFORE
        // the outcome escapes. A CLEAN command (no live members — the common
        // case) pays one enumeration and proceeds exactly as before.
        let live = live_group_members(pgid, pid);
        if !live.is_empty() {
            // Terminate the whole group; a kill failure is surfaced inside
            // the violation error (the leftover member must not survive even
            // when a kill fails — the fault-injected paths that cannot land
            // a kill are covered by the caller's own cleanup, and the drop
            // backstop remains the final resort for the owned child).
            let mut term_error: Option<String> = None;
            if let Err(e) = self.config.kill.kill_group(pgid, libc::SIGTERM) {
                term_error = Some(format!("TERM group {pgid}: {e}"));
            }
            std::thread::sleep(self.config.term_to_kill_grace);
            if let Err(e) = self.config.kill.kill_group(pgid, libc::SIGKILL)
                && term_error.is_none()
            {
                term_error = Some(format!("KILL group {pgid}: {e}"));
            }
            // Confirm the group is gone (bounded): a killed descendant is
            // reparented to init and reaped there; the poll covers the
            // transient zombie window. On expiry (an injected inert kill) the
            // error still names the violation — the fault IS the kill not
            // working.
            let verify_deadline = Instant::now() + self.config.reap_bound;
            while !live_group_members(pgid, pid).is_empty() && Instant::now() < verify_deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            // Reap the direct child (a zombie — the wait returns immediately,
            // releasing the pid) BEFORE the error escapes.
            owned
                .wait()
                .map_err(|e| RunError::Wait(format!("wait {argv:?}: {e}")))?;
            #[cfg(test)]
            if let Some(observer) = &self.config.reap_observer {
                observer(pid);
            }
            let detail = term_error.map(|e| format!(" ({e})")).unwrap_or_default();
            let leftover = live
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",");
            return Err(RunError::Background(format!(
                "command {argv:?} left background processes in its process group \
                 (live members: {leftover}); commands are foreground-only{detail}"
            )));
        }

        // The direct child is the only group member: reap it — the SINGLE
        // reap, releasing the pid. From here on nothing signals anything.
        let status = owned
            .wait()
            .map_err(|e| RunError::Wait(format!("wait {argv:?}: {e}")))?;
        #[cfg(test)]
        if let Some(observer) = &self.config.reap_observer {
            observer(pid);
        }
        // Bounded drain to EOF: the child is dead and its pipes hold the
        // remaining output. A grandchild that keeps a pipe open cannot hang
        // the outcome — the drain gives up after the reap bound.
        // PIPE-EOF CONTAINMENT: the direct child is reaped (its descriptors
        // closed by the kernel); the inherited stdout/stderr write ends EOF
        // exactly when the LAST holder — the child or any descendant that
        // kept the pipes — dies. EOF within the bound proves no pipe-holding
        // descendant lives (the clean path stays clean); a pipe still open
        // at the bound proves a live descendant HOLDS it — a descendant that
        // escaped the group via `setsid` but kept the inherited pipes is
        // still DETECTED here, and the violation is reported as an ERROR,
        // never a successful outcome. Only a FULLY daemonized descendant
        // (`setsid` AND closed descriptors) is outside the contract (see the
        // module doc) — commands must not daemonize.
        let drain_bound = self.config.reap_bound;
        let stdout_drain = drain_to_eof(&mut owned.child.stdout, &mut stdout, drain_bound)
            .map_err(|e| RunError::Wait(e.to_string()))?;
        if matches!(stdout_drain, DrainState::BoundExpired) {
            return Err(RunError::Background(format!(
                "command {argv:?} left processes holding its output pipes open; \
                 commands are foreground-only"
            )));
        }
        let stderr_drain = drain_to_eof(&mut owned.child.stderr, &mut stderr, drain_bound)
            .map_err(|e| RunError::Wait(e.to_string()))?;
        if matches!(stderr_drain, DrainState::BoundExpired) {
            return Err(RunError::Background(format!(
                "command {argv:?} left processes holding its error pipes open; \
                 commands are foreground-only"
            )));
        }

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

/// The outcome of a bounded post-exit drain: EOF proves the pipe's last
/// writer closed (no live descendant holds it); a bound expiry proves a
/// live writer STILL holds it (a descendant that escaped the group but kept
/// the inherited stdio pipes — the pipe-EOF containment signal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainState {
    /// `read` returned 0: every write end closed — no pipe-holding
    /// descendant remains.
    Eof,
    /// The drain bound expired with the pipe still open (poll timed out or
    /// the deadline passed between reads): a live writer holds the pipe.
    BoundExpired,
}

/// Drain a child pipe to EOF, bounded: reads never block (non-blocking read
/// ends), and between reads `poll` waits only up to `bound` — a grandchild
/// that outlives the direct child and keeps a pipe open cannot hang the
/// outcome. Returns [`DrainState::Eof`] when the pipe reached EOF within the
/// bound (no live holder remains) and [`DrainState::BoundExpired`] when the
/// bound expired with the pipe still open (a live holder — a contract
/// violation the caller reports, never a silent clean outcome).
fn drain_to_eof<R>(
    stream: &mut Option<R>,
    buf: &mut Vec<u8>,
    bound: Duration,
) -> std::io::Result<DrainState>
where
    R: Read + AsRawFd,
{
    let Some(stream) = stream.as_mut() else {
        return Ok(DrainState::Eof);
    };
    let deadline = Instant::now() + bound;
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(DrainState::Eof),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Ok(DrainState::BoundExpired);
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
                    return Ok(DrainState::BoundExpired);
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// Property test for the lifecycle contract: real children (quick-exit,
/// slow, TERM-ignoring, grandchild-spawning, detached-grandchild-leaving,
/// late-marker-writing) driven through [`ChildRunner::exec`] under injected
/// kill faults (missing kill, EPERM, ESRCH, an inert kill), asserting for
/// EVERY returned outcome: ZERO live processes (no child or grandchild of
/// the spawned group remains — a process that merely received a signal but
/// was not reaped, a zombie, still answers `kill(pid, 0)`), EXACTLY ONE reap
/// (the runner's single `try_wait`, tracked via the reap observer; only the
/// injected-unkillable fault lets the test's own cleanup be that one reap),
/// and NO post-return filesystem effects (a child/grandchild that would
/// write a marker after its "timeout" — or after a normal exit that left it
/// behind — must never get the chance — the group is proven dead before the
/// outcome escapes).
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

    /// The runner deadline for every generated case: LONG enough that a
    /// quick-exit child — including the setsid cases' READINESS barrier
    /// (the sh waits for the grandchild's `ready` file, which arrives after
    /// python3's interpreter startup, ~50-300ms under parallel load) —
    /// finishes in time, while every genuinely timed-out case stays bounded.
    /// The late-marker child writes its marker after 1.2s — past this
    /// deadline — so a leaked (returned-while-still-alive) child would be
    /// caught writing AFTER the outcome. Coordination is by BARRIER (the
    /// ready file), never by "must finish within N ms".
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
        /// exit-0 outcome — leaving no live process and no post-return fs
        /// effect.
        DetachedGrandchild,
        /// Exits ZERO immediately after forking a grandchild that CALLS
        /// `setsid` (escaping the process group — a `killpg` can never reach
        /// it) but KEEPS the inherited stdio pipes open, sleeps 0.4s, then
        /// would write a marker: the group enumeration finds nothing (it
        /// escaped), so the PIPE-EOF containment must catch the pipe-holding
        /// escapee at the drain bound and return the "left processes holding
        /// its output pipes" error — never a successful outcome. The test's
        /// cleanup kills the escapee by pid (the runner cannot reach it).
        SetsidInherit,
        /// Exits ZERO immediately after forking a grandchild that FULLY
        /// DAEMONIZES: `setsid` AND closes every inherited descriptor (the
        /// canonical daemon recipe), sleeps 0.4s, then writes a marker. This
        /// is the ONE documented contract exclusion — no portable detection
        /// exists without cgroups/subreaper (Linux) or a remote supervisor
        /// (ssh) — so the runner returns SUCCESS (the narrowed contract:
        /// commands must not daemonize). The test pins that boundary and
        /// enforces the no-post-return-fs property with its own cleanup kill.
        SetsidClose,
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
            // The parent exits 0 IMMEDIATELY after forking the grandchild
            // (the pidfile is written before the exit, so the parent-side
            // `read_gc_pid` never races): the runner's wait reaps the child,
            // and the FOREGROUND-ONLY probe must find the sleeping grandchild
            // still in the group, terminate it before its 0.4s marker write,
            // and error.
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
            // group enumeration finds nothing and `killpg` cannot reach it)
            // but KEEPS the inherited stdout/stderr write ends (python3's
            // fds 1/2) — the pipes stay open after the direct child is
            // reaped, so the PIPE-EOF containment at the drain bound detects
            // it and errors. READINESS PROTOCOL: the grandchild writes a
            // `ready` file AFTER `setsid` and the parent waits for it before
            // exiting — the escape is COMPLETE before the runner's check, so
            // the enumeration genuinely sees an empty group (a bare `&` would
            // race python3's interpreter startup, which delays `setsid` past
            // the check). `python3` is the portable `setsid` provider on both
            // macOS (dev) and Linux (CI).
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
            // descriptors (0/1/2) — the pipes EOF immediately, no group
            // member, no pipe-holder: the ONE documented contract exclusion.
            // Same READINESS PROTOCOL: the escape (setsid + fd close) is
            // complete before the parent exits, and the ready-poll busy-waits
            // with shell BUILTINS ONLY (`:` — no external `sleep` subprocess,
            // which would be a transient GROUP MEMBER the runner would
            // legitimately flag). The delayed marker is at 0.9s — far past
            // the test's cleanup kill (issued right after the runner
            // returns) — so the no-post-return-fs assertion measures the
            // CONTRACT boundary, not a cleanup race under parallel load.
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
    /// deadline, so no child-written-pidfile race. A read that catches the
    /// file mid-write (the `>` truncate before the `echo`) or a non-numeric
    /// parse is RETRIED — never a premature `None` that would skip the
    /// cleanup kill of an escaped grandchild.
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
        let gc_pid = matches!(
            kind,
            ChildKind::Grandchild
                | ChildKind::DetachedGrandchild
                | ChildKind::SetsidInherit
                | ChildKind::SetsidClose
        )
        .then(|| read_gc_pid(&dir.path().join("gcpid")))
        .flatten();

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
            // success), even though the runner cannot kill the escapee (the
            // test's cleanup does, by pid).
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
            // SetsidClose: the FULLY daemonized grandchild (`setsid` AND
            // closed descriptors) is the ONE documented contract exclusion —
            // undetectable without cgroups/subreaper or a remote supervisor.
            // The runner returns SUCCESS per the narrowed contract (commands
            // must not daemonize); the test pins that boundary and its own
            // cleanup enforces zero-live + no-post-return-fs below.
            (Ok(RunOutcome::Exited { exit_code, .. }), false, _)
                if kind == ChildKind::SetsidClose =>
            {
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

        // ---- cleanup under an injected kill/reap failure OR an escaped
        // grandchild ----
        // The injected fault IS the kill not working: the runner surfaced an
        // error (never a fake timeout success) and cleaned up what it could;
        // the test now kills the leftover group and reaps the direct child —
        // the single cleanup reap — so the zero-live assertion is meaningful.
        // A setsid-ESCAPED grandchild (SetsidInherit/SetsidClose) is outside
        // the group — the runner could not reach it — so the test kills it
        // BY PID (its pid is live, so the kill is safe from pid reuse).
        if outcome.is_err() {
            // SAFETY: kill(-pgid) == killpg on the group THIS test spawned
            // (the child is the group leader, pgid == its pid).
            unsafe { libc::kill(-(child_pid as i32), libc::SIGKILL) };
            // SAFETY: waitpid on our own child; it died on SIGKILL; ECHILD is
            // harmless when the runner already reaped it.
            unsafe { libc::waitpid(child_pid as i32, std::ptr::null_mut(), 0) };
        }
        if matches!(kind, ChildKind::SetsidInherit | ChildKind::SetsidClose)
            && let Some(gc) = gc_pid
        {
            // SAFETY: the escaped grandchild is a LIVE process of this test
            // (its pid is allocated — no reuse); SIGKILL lands.
            unsafe { libc::kill(gc as i32, libc::SIGKILL) };
        }

        // ---- ZERO LIVE PROCESSES ----
        assert_pid_gone(child_pid, &format!("{kind:?} × {fault:?} child"));
        if let Some(gc) = gc_pid {
            assert_pid_gone(gc, &format!("{kind:?} × {fault:?} grandchild"));
        }

        // ---- NO POST-RETURN FILESYSTEM EFFECTS ----
        // The probe window lets any write that a (buggy) still-alive child or
        // grandchild would attempt after the outcome land and be caught: the
        // marker scripts write 1.2s in (LateMarker/Grandchild — killed by the
        // 1s deadline), 0.4s in (DetachedGrandchild), or 0.9s in (the setsid
        // escapees — killed by the TEST's cleanup kill, since a setsid'd
        // escapee is outside the runner's reach by contract), and the probe
        // outlives each — a buggy runner that returned while the descendant
        // still lived would be caught writing AFTER the outcome.
        if matches!(kind, ChildKind::LateMarker | ChildKind::Grandchild) {
            std::thread::sleep(Duration::from_millis(300));
        } else if kind == ChildKind::DetachedGrandchild {
            std::thread::sleep(Duration::from_millis(500));
        } else if matches!(kind, ChildKind::SetsidInherit | ChildKind::SetsidClose) {
            // The setsid escapees' markers fire at 0.9s — far past the
            // cleanup kill (~150ms after the runner returned) — so the
            // probe window outlives the marker delay with a wide margin,
            // even under heavy parallel load.
            std::thread::sleep(Duration::from_millis(1000));
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
        // The lifecycle property: every generated (child kind × kill fault)
        // pair must honor the ONE-runner contract. Quick/non-zero children
        // complete with their exit code; slow, TERM-ignoring, grandchild-
        // spawning, and late-marker children time out — and a timeout outcome
        // appears ONLY after the child and its group were proven dead (kill-0
        // → ESRCH, the reaped proof, for the child AND any grandchild) and
        // the child was reaped exactly once. A command that EXITS but leaves
        // a background grandchild in its process group (DetachedGrandchild)
        // is a FOREGROUND-ONLY violation: the runner terminates the group and
        // errors — never a successful exit-0 outcome. A grandchild that
        // ESCAPES the group via `setsid` but keeps the inherited stdio pipes
        // (SetsidInherit) is caught by the PIPE-EOF containment — an error,
        // never success. A FULLY daemonized grandchild (`setsid` AND closed
        // descriptors, SetsidClose) is the ONE documented contract exclusion
        // — no portable detection exists — and the runner returns success
        // (commands must not daemonize); the test pins the boundary and its
        // own cleanup enforces zero-live and no-post-return-fs. A kill
        // failure (missing
        // binary, EPERM, unreachable group) or an ineffective kill surfaces
        // as an ERROR — never a successful `timed out` outcome — and a TERM-
        // ignoring child is escalated to a group KILL. No child or grandchild
        // ever writes a file after the runner returned. FIXED SEED
        // 0x5EED_5EED (repo style) + bounded cases keep the suite
        // deterministic.
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
