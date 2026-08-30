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
//!   violation, NEVER a successful outcome. The foreground containment
//!   INVARIANT (no live process after the return) covers IN-GROUP descendants
//!   only. A descendant that ESCAPED the group via `setsid` is OUTSIDE the
//!   guarantee: the runner can DETECT a pipe-holding escapee — the inherited
//!   stdio pipes EOF exactly when the last holder dies, so a pipe still open
//!   at the drain bound is a provable violation → error — but it CANNOT
//!   TERMINATE an escaped process, because no portable way to signal a
//!   process outside its group exists without cgroups/subreaper support
//!   (Linux) or a remote supervisor (ssh). The ONE documented exclusion
//!   covers BOTH setsid flavors: the pipe-holding escapee (detected →
//!   error, but not terminated) and the FULLY daemonized descendant
//!   (`setsid` AND closed descriptors — not even detectable); commands must
//!   not daemonize. A CLEAN command (no live members —
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
pub fn kill_process_group(pgid: i32, sig: i32) -> std::io::Result<()> {
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
///
/// Public so the serialized real-process lifecycle integration target
/// (`tests/process_lifecycle.rs`) can drive the runner under injected kill
/// faults.
pub trait KillSeam: Send + Sync {
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
pub struct RealKill;

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
pub struct RunnerConfig {
    /// Grace between the group SIGTERM and the escalated group SIGKILL.
    pub term_to_kill_grace: Duration,
    /// Bound on the post-termination reap: if the child is still alive this
    /// long after the timeout fired, the termination is ineffective and the
    /// runner reports a reap failure (never a fake timeout success).
    pub reap_bound: Duration,
    /// The kill seam (production: [`RealKill`]; tests: injected faults).
    pub kill: Arc<dyn KillSeam>,
    /// Spawn observer: called synchronously in the parent right
    /// after a successful spawn with the child's pid — before the timeout
    /// clock starts — so a test can assert the pid is gone afterwards without
    /// any child-written pidfile (which would race the deadline kill).
    pub spawn_observer: Option<Arc<dyn Fn(u32) + Send + Sync>>,
    /// Reap observer: called exactly once, at the single reap.
    pub reap_observer: Option<Arc<dyn Fn(u32) + Send + Sync>>,
}

impl RunnerConfig {
    /// The production configuration: 200ms TERM→KILL grace, a 2s reap bound,
    /// and the real `killpg`/`Child::kill` seam.
    pub fn production() -> Self {
        RunnerConfig {
            term_to_kill_grace: TERM_TO_KILL_GRACE,
            reap_bound: KILL_REAP_BOUND,
            kill: Arc::new(RealKill),
            spawn_observer: None,
            reap_observer: None,
        }
    }
}

/// How a runner invocation ended, before the transport maps it to its own
/// outcome shape. The timeout variant exists ONLY after the child (and its
/// group) was proven dead and reaped.
#[derive(Debug)]
pub enum RunOutcome {
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
/// never leave a live, un-reaped child behind by contract (the `OwnedChild`
/// drop backstop covers the paths where even that is impossible).
#[derive(Debug)]
pub enum RunError {
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
/// `OwnedChild` inside [`ChildRunner::exec`] and is collected before the
/// call returns, so there are no leaked threads, handles, or processes across
/// calls — the lifecycle is bounded.
pub struct ChildRunner {
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
    pub fn new(env: &SysEnv, cwd: PathBuf, config: RunnerConfig) -> Self {
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
    /// outcome. A setsid-escaped descendant is OUTSIDE the containment
    /// guarantee: the runner can DETECT a pipe-holding escapee and error,
    /// but cannot TERMINATE an escaped process (see the module doc).
    pub fn exec(
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
