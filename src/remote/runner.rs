//! THE bounded subprocess runner behind every ssh operation.
//!
//! EVERY ssh operation runs through ONE bounded subprocess runner
//! ([`SshRunner`]): the runner spawns the child, waits with a HARD deadline,
//! on deadline KILLS the child (SIGKILL) and then REAPS it (joins the wait
//! thread that owns the child) before returning a Timeout. Nothing is
//! unbounded: `-o ConnectTimeout=N` in the fixed `ssh` arguments bounds only
//! the CONNECTION phase, so the runner's deadline bounds every operation
//! AFTER connection establishment — a remote that hangs mid-command, mid-
//! upload, mid-keyscan, or mid-`exec` fails fast instead of hanging the whole
//! push. The kill-then-reap ordering is deterministic: the wait thread owns
//! the child, and the deadline path kills and then JOINS that thread, so the
//! child is always collected before the runner returns (no kill-vs-wait race,
//! no zombies, no return-before-reap). A stdin-write failure is held to the
//! same rule: the wait closure saves the write error, ALWAYS runs
//! `wait_with_output` (drains and collects the child — after the deadline kill
//! this returns the killed status promptly), and only then returns the saved
//! error, so a write error can never leave an uncollected child either.
//!
//! Deadline policy: the connect-bound `ssh-keyscan` pin keeps
//! [`SSH_CONNECT_TIMEOUT_SECS`] (it IS a connection-establishment probe);
//! every other ssh operation runs under [`SSH_COMMAND_TIMEOUT_SECS`]
//! (deliberately distinct from the connection bound: a slow-but-healthy
//! remote legitimately needs longer than connection establishment once
//! connected), and `Remote::exec` keeps its caller-supplied timeout.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

// Connect timeout in seconds applied to every `ssh` connection (`-o
// ConnectTimeout=N`) and to the `ssh-keyscan` key-pin step (native `-T N`
// plus the runner's process-level deadline, see [`SshRunner`] and
// [`SshTransport::pin_known_hosts`]). A dead or unreachable host must fail
// fast instead of hanging the transport indefinitely; 10s bounds the
// connection phase while leaving slow but reachable hosts (cold VPN routes,
// slow DNS) enough headroom.
pub(crate) const SSH_CONNECT_TIMEOUT_SECS: u64 = 10;

// Deadline in seconds applied by [`SshRunner`] to every ssh operation AFTER
// connection establishment: remote commands ([`SshTransport::run_remote`] /
// [`SshTransport::run_remote_ok`]) and uploads. `-o ConnectTimeout=N` bounds
// ONLY the connection phase, so without this bound a remote command on a hung
// host (stuck filesystem, wedged service) would run indefinitely and hang the
// whole push. 60s is deliberately DISTINCT from the 10s connection bound: a
// slow-but-healthy remote (large upload over a slow link, cold NFS) legitimately
// needs longer than connection establishment once connected. The `ssh-keyscan`
// pin keeps `SSH_CONNECT_TIMEOUT_SECS` (it IS a connection-establishment
// probe), and `Remote::exec` keeps its caller-supplied timeout.
pub(crate) const SSH_COMMAND_TIMEOUT_SECS: u64 = 60;

/// The kind of ssh operation the runner is executing. The property test
/// generates these × stall points through an injected fake seam (see the
/// `runner_property_tests` module) and asserts the deadline/kill/reap contract
/// for every one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpKind {
    /// `run_remote`: a plain remote shell command (output returned, status not
    /// checked by the caller).
    Remote,
    /// `run_remote_ok`: a remote shell command that must exit 0.
    RemoteOk,
    /// The upload path (`ssh` with a stdin payload piped to the remote `cat`).
    Upload,
    /// The `ssh-keyscan` key-pin step.
    KeyscanPin,
    /// `Remote::exec` (caller-supplied timeout).
    Exec,
}

/// How a runner invocation failed. Timeout is distinct so each caller can map
/// it to its own outcome shape: `exec` returns an `ExecOutcome` with
/// `exit_code = -1` and `stderr = "timed out after …"` (existing callers
/// depend on it), every other operation returns a `Result` error.
#[derive(Debug)]
pub(crate) enum RunError {
    /// The child could not be spawned.
    Spawn(String),
    /// The stdin payload write failed (e.g. EPIPE after the deadline kill
    /// closed the pipe). Returned only AFTER the child was reaped: the wait
    /// closure always runs `wait_with_output` before surfacing a saved write
    /// error.
    StdinWrite(String),
    /// Waiting on the child failed (wait error, read error, …).
    Wait(String),
    /// The hard deadline fired; the child was killed and reaped.
    Timeout { after: Duration },
}

/// A spawned child owned by the runner: the runner keeps the pid (for the
/// deadline kill) and a reaping closure that the wait thread runs. The closure
/// returns once the child exits — including after [`SshRunnerSeam::kill`] — so
/// the runner's join is a deterministic reap.
struct SpawnedChild {
    pid: u32,
    /// Drain stdout/stderr and wait for the child; must return promptly once
    /// the child exits (or is killed). ALWAYS reaps the child before returning
    /// an error: a saved stdin-write error is surfaced only AFTER
    /// `wait_with_output` has run, so an error can never leave the child
    /// uncollected (no return-before-reap).
    wait: Box<dyn FnOnce() -> std::result::Result<std::process::Output, RunError> + Send>,
}

/// The subprocess seam behind [`SshRunner`]. The production implementation
/// spawns real `ssh` / `ssh-keyscan` processes; tests inject a fake that
/// RECORDS every operation (`spawn(kind, argv)`, `kill`, `reap`) and simulates
/// the stall points, so the runner's deadline logic is driven without any real
/// subprocess or sleep.
trait SshRunnerSeam: Send + Sync {
    /// Spawn `argv[0]` with the remaining arguments. When `stdin` is `Some`,
    /// those bytes are piped to the child's stdin as part of the wait, so a
    /// child that stops reading is covered by the same deadline. Returns a
    /// handle whose `wait` drains the child and returns once it exits.
    fn spawn(
        &self,
        op: OpKind,
        argv: &[String],
        stdin: Option<Vec<u8>>,
    ) -> std::io::Result<SpawnedChild>;
    /// Force-kill `pid` (SIGKILL).
    fn kill(&self, pid: u32) -> std::io::Result<()>;
}

/// Production seam: real `ssh` / `ssh-keyscan` subprocesses.
struct RealRunner;

impl SshRunnerSeam for RealRunner {
    fn spawn(
        &self,
        _op: OpKind,
        argv: &[String],
        stdin: Option<Vec<u8>>,
    ) -> std::io::Result<SpawnedChild> {
        let mut cmd = std::process::Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        if stdin.is_some() {
            cmd.stdin(Stdio::piped());
        }
        let mut child = cmd.spawn()?;
        let pid = child.id();
        // The stdin payload is written from INSIDE the wait closure (which the
        // runner's deadline bounds): a remote that stops reading stdin mid-
        // upload blocks this write, the deadline fires, the kill closes the
        // pipe, and the write fails with EPIPE (SIGPIPE is ignored by the Rust
        // runtime). Without this, a >pipe-buffer upload to a hung remote would
        // hang the write indefinitely.
        let wait: Box<dyn FnOnce() -> std::result::Result<std::process::Output, RunError> + Send> =
            Box::new(move || {
                // Write the payload FIRST, saving any error: `?` here would
                // return BEFORE the child is collected — a write error (EPIPE
                // after the deadline kill, or a hung-remote pipe) would leave
                // an un-reaped child. The error is therefore saved, and
                // `wait_with_output` ALWAYS runs (it drains the child's pipes
                // and collects it; after the deadline kill this returns the
                // killed status promptly). The saved write error is returned
                // only AFTER the child has been reaped.
                use std::io::Write;
                let write_res = if let Some(data) = stdin
                    && let Some(mut sin) = child.stdin.take()
                {
                    sin.write_all(&data)
                } else {
                    Ok(())
                };
                let wait_res = child.wait_with_output();
                match write_res {
                    Err(e) => Err(RunError::StdinWrite(format!("stdin write: {e}"))),
                    Ok(()) => wait_res.map_err(|e| RunError::Wait(format!("wait: {e}"))),
                }
            });
        Ok(SpawnedChild { pid, wait })
    }

    fn kill(&self, pid: u32) -> std::io::Result<()> {
        // SAFETY: `pid` is a pid the runner spawned (and holds a child for), so
        // the target is a child process of ours; SIGKILL cannot be blocked.
        let _ = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        Ok(())
    }
}

/// THE single subprocess runner for every ssh operation: spawn the child, wait
/// with a hard deadline, on deadline KILL (-9) then REAP — join the wait
/// thread that owns the child, so the child is deterministically collected
/// before the runner returns (no kill-vs-wait race, no zombie, no
/// return-before-reap). On success the `Output` is returned; spawn/wait
/// failures and the deadline map to [`RunError`].
///
/// The deadline policy: `exec` uses its caller-supplied timeout; the
/// `ssh-keyscan` pin uses the connect deadline; every other operation uses the
/// command deadline. Both deadlines are owned here so the property test can
/// inject tiny ones through [`SshRunner::with_seam`].
pub(crate) struct SshRunner {
    seam: Arc<dyn SshRunnerSeam>,
    /// Deadline for the connect-bound `ssh-keyscan` pin.
    connect_deadline: Duration,
    /// Deadline for post-connect remote command/upload operations.
    command_deadline: Duration,
}

impl SshRunner {
    pub(crate) fn new() -> Self {
        SshRunner {
            seam: Arc::new(RealRunner),
            connect_deadline: Duration::from_secs(SSH_CONNECT_TIMEOUT_SECS),
            command_deadline: Duration::from_secs(SSH_COMMAND_TIMEOUT_SECS),
        }
    }

    /// Test-only constructor with an injected seam and (tiny) deadlines, so the
    /// property test can drive the deadline/kill/reap logic against a fake
    /// without any real subprocess or wall-clock waits.
    #[cfg(test)]
    fn with_seam(
        seam: Arc<dyn SshRunnerSeam>,
        connect_deadline: Duration,
        command_deadline: Duration,
    ) -> Self {
        SshRunner {
            seam,
            connect_deadline,
            command_deadline,
        }
    }

    /// Run `op` with `argv`, bounding the whole wait by a hard deadline: the
    /// runner's policy for the op kind, unless `timeout` is `Some` (`exec`'s
    /// caller-supplied bound). On deadline the child is killed and the wait
    /// thread joined (deterministic reap) BEFORE the Timeout is returned.
    pub(crate) fn run(
        &self,
        op: OpKind,
        argv: &[String],
        stdin: Option<&[u8]>,
        timeout: Option<Duration>,
    ) -> std::result::Result<std::process::Output, RunError> {
        let deadline = match timeout {
            Some(t) => t,
            None => match op {
                OpKind::KeyscanPin => self.connect_deadline,
                _ => self.command_deadline,
            },
        };
        let child = self
            .seam
            .spawn(op, argv, stdin.map(<[u8]>::to_vec))
            .map_err(|e| RunError::Spawn(format!("spawn {:?}: {e}", argv)))?;
        let pid = child.pid;
        let (tx, rx) = std::sync::mpsc::channel();
        let wait = child.wait;
        let handle = std::thread::spawn(move || {
            let res = wait();
            let _ = tx.send(res);
        });
        match rx.recv_timeout(deadline) {
            Ok(Ok(out)) => {
                // Success: the wait thread reaped the child (wait_with_output
                // collects it) and sent the output. Join so the thread — and
                // therefore the child's collection — is complete before we
                // return.
                let _ = handle.join();
                Ok(out)
            }
            Ok(Err(e)) => {
                // The wait closure already reaped the child before returning
                // the error (a saved stdin-write error is surfaced only after
                // `wait_with_output` ran), and the join collects the thread —
                // so an error path never leaves an uncollected child either.
                let _ = handle.join();
                Err(e)
            }
            Err(_) => {
                // HARD DEADLINE: kill, then reap. The SIGKILL makes the child
                // exit; the join collects the wait thread that owns the child
                // (its `wait` returns promptly after the kill). Both complete
                // before this function returns, so the child is determinis-
                // tically collected — no zombie, no kill-vs-wait race, and the
                // caller can never observe a returned Timeout with the child
                // still un-reaped.
                let _ = self.seam.kill(pid);
                let _ = handle.join();
                Err(RunError::Timeout { after: deadline })
            }
        }
    }
}

/// Property test for the runner contract: EVERY ssh operation (run_remote,
/// run_remote_ok, upload, keyscan-pin, exec) must go through the ONE bounded
/// runner, and the runner must kill + deterministically reap every stalled
/// child. The generated operations are driven through the REAL transport entry
/// points with an INJECTED fake seam (via `SshTransport::with_runner`), so the
/// runner's deadline logic is exercised end to end while the fake simulates
/// the stall points at the spawn boundary and RECORDS the full
/// spawn/kill/reap call log.
#[cfg(test)]
mod runner_property_tests {
    use super::*;
    use crate::error::Error;
    use crate::remote::ssh::SshTransport;
    use crate::remote::transport::Remote;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::os::unix::process::ExitStatusExt;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    /// The stall point each generated operation must exhibit.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Stall {
        /// The child hangs forever (until the runner kills it at the deadline).
        Hang,
        /// The child exits 0 promptly.
        Complete,
        /// The child cannot be spawned at all.
        SpawnError,
        /// The child exits non-zero promptly.
        NonZero,
        /// The stdin payload write fails (EPIPE) — but the wait closure STILL
        /// reaps the child (runs `wait_with_output`) before returning the saved
        /// write error: no return-before-reap on the write-error path. Vacuous
        /// (completes normally) for ops that pipe no stdin.
        StdinWriteError,
        /// The wait itself (`wait_with_output`) fails, after the reap attempt.
        WaitError,
    }

    /// Every operation the fake seam records, in order.
    #[derive(Clone, Debug)]
    enum LogEntry {
        Spawn {
            op: OpKind,
            argv: Vec<String>,
            pid: u32,
        },
        Kill {
            pid: u32,
        },
        Reap {
            pid: u32,
        },
    }

    #[derive(Default)]
    struct FakeState {
        log: Mutex<Vec<LogEntry>>,
        /// Number of fake wait closures still running (children not yet
        /// reaped). Zero after an operation returns proves the runner joined
        /// every wait thread — the thread-level half of "no zombie".
        live_waiters: AtomicUsize,
    }

    impl FakeState {
        fn push(&self, entry: LogEntry) {
            self.log.lock().unwrap().push(entry);
        }
        fn spawn(&self) -> (OpKind, Vec<String>, u32) {
            let log = self.log.lock().unwrap();
            match log.iter().find_map(|e| match e {
                LogEntry::Spawn { op, argv, pid } => Some((*op, argv.clone(), *pid)),
                _ => None,
            }) {
                Some(s) => s,
                None => panic!("no spawn recorded"),
            }
        }
        fn kill_pids(&self) -> Vec<u32> {
            self.pids(|e| matches!(e, LogEntry::Kill { .. }))
        }
        fn reap_pids(&self) -> Vec<u32> {
            self.pids(|e| matches!(e, LogEntry::Reap { .. }))
        }
        fn pids(&self, kind: fn(&LogEntry) -> bool) -> Vec<u32> {
            let log = self.log.lock().unwrap();
            log.iter()
                .filter(|e| kind(e))
                .filter_map(|e| match e {
                    LogEntry::Kill { pid } | LogEntry::Reap { pid } => Some(*pid),
                    _ => None,
                })
                .collect()
        }
        /// True when the first Kill precedes the first Reap (kill-then-reap).
        fn kill_precedes_reap(&self) -> bool {
            let log = self.log.lock().unwrap();
            let kpos = log.iter().position(|e| matches!(e, LogEntry::Kill { .. }));
            let rpos = log.iter().position(|e| matches!(e, LogEntry::Reap { .. }));
            match (kpos, rpos) {
                (Some(k), Some(r)) => k < r,
                _ => false,
            }
        }
        fn live_waiters(&self) -> usize {
            self.live_waiters.load(Ordering::SeqCst)
        }
    }

    /// Per-child control block: the fake wait polls `killed`; the runner's
    /// deadline path calls [`FakeSeam::kill`], which sets it, so the blocked
    /// wait unblocks and records the reap — reproducing exactly the real
    /// child's kill-then-reap lifecycle without any subprocess.
    struct ChildCtl {
        pid: u32,
        killed: AtomicBool,
        stall: Stall,
        /// Whether the op pipes a stdin payload: the write-error stall is
        /// meaningful only when there is something to write (the upload op).
        has_stdin: bool,
        /// Real host-key line the fake keyscan emits on Complete, so the pin
        /// path succeeds end-to-end (fingerprint verified with real ssh-keygen).
        keyscan_line: Option<String>,
        state: Arc<FakeState>,
    }

    impl ChildCtl {
        /// The wait closure body: finish immediately (Complete / NonZero /
        /// vacuous StdinWriteError), block until killed (Hang), or fail AFTER
        /// recording the reap (StdinWriteError with a payload / WaitError);
        /// record the reap, return the stubbed output or error.
        fn wait(&self) -> std::result::Result<std::process::Output, RunError> {
            self.state.live_waiters.fetch_add(1, Ordering::SeqCst);
            let res = self.wait_inner();
            self.state.live_waiters.fetch_sub(1, Ordering::SeqCst);
            res
        }

        fn wait_inner(&self) -> std::result::Result<std::process::Output, RunError> {
            // Raw Unix wait status for an exit code: `code << 8` (WEXITSTATUS).
            let exit = |code: i32| std::process::ExitStatus::from_raw(code << 8);
            let output = |code: i32| -> std::process::Output {
                let mut out = std::process::Output {
                    status: exit(code),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                };
                if let Some(line) = &self.keyscan_line {
                    out.stdout = line.as_bytes().to_vec();
                }
                out
            };
            match self.stall {
                Stall::Complete => {
                    let res = output(0);
                    self.state.push(LogEntry::Reap { pid: self.pid });
                    Ok(res)
                }
                Stall::NonZero => {
                    let res = output(1);
                    self.state.push(LogEntry::Reap { pid: self.pid });
                    Ok(res)
                }
                Stall::Hang => {
                    // Block until the runner kills us at the deadline. A bounded
                    // backstop turns a broken runner (one that never kills) into
                    // a loud assertion failure instead of a suite-wide hang.
                    let budget = Instant::now() + Duration::from_secs(5);
                    while !self.killed.load(Ordering::SeqCst) && Instant::now() < budget {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    assert!(
                        self.killed.load(Ordering::SeqCst),
                        "stalled child {} was never killed: the runner must kill then reap on deadline",
                        self.pid
                    );
                    self.state.push(LogEntry::Reap { pid: self.pid });
                    Ok(output(0))
                }
                Stall::StdinWriteError => {
                    if self.has_stdin {
                        // The stdin write fails — but the closure STILL reaps
                        // (wait_with_output runs; recorded as Reap) and only
                        // THEN returns the saved write error: a
                        // return-before-reap on this path would show up as a
                        // missing Reap.
                        self.state.push(LogEntry::Reap { pid: self.pid });
                        Err(RunError::StdinWrite(
                            "simulated stdin write failure".to_string(),
                        ))
                    } else {
                        // No stdin payload: there is nothing to write, so the
                        // stall is vacuous and the child completes normally.
                        let res = output(0);
                        self.state.push(LogEntry::Reap { pid: self.pid });
                        Ok(res)
                    }
                }
                Stall::WaitError => {
                    // The reap is ATTEMPTED (wait_with_output runs; recorded as
                    // Reap) but the wait itself fails: surfaces as a wait error
                    // after the reap attempt.
                    self.state.push(LogEntry::Reap { pid: self.pid });
                    Err(RunError::Wait("simulated wait failure".to_string()))
                }
                Stall::SpawnError => unreachable!("spawn errors never yield a child"),
            }
        }
    }

    /// The injected fake seam: records every spawn (kind + argv), kill, and
    /// reap, and simulates the generated stall point.
    struct FakeSeam {
        state: Arc<FakeState>,
        stall: Stall,
        next_pid: AtomicU32,
        children: Mutex<Vec<Arc<ChildCtl>>>,
        keyscan_line: Option<String>,
    }

    impl FakeSeam {
        fn new(stall: Stall, keyscan_line: Option<String>) -> (Arc<Self>, Arc<FakeState>) {
            let state = Arc::new(FakeState::default());
            let seam = FakeSeam {
                state: state.clone(),
                stall,
                next_pid: AtomicU32::new(1),
                children: Mutex::new(Vec::new()),
                keyscan_line,
            };
            (Arc::new(seam), state)
        }
    }

    impl SshRunnerSeam for FakeSeam {
        fn spawn(
            &self,
            op: OpKind,
            argv: &[String],
            stdin: Option<Vec<u8>>,
        ) -> std::io::Result<SpawnedChild> {
            let pid = self.next_pid.fetch_add(1, Ordering::SeqCst);
            self.state.push(LogEntry::Spawn {
                op,
                argv: argv.to_vec(),
                pid,
            });
            if self.stall == Stall::SpawnError {
                return Err(std::io::Error::other("simulated spawn failure"));
            }
            let ctl = Arc::new(ChildCtl {
                pid,
                killed: AtomicBool::new(false),
                stall: self.stall,
                has_stdin: stdin.is_some(),
                keyscan_line: self.keyscan_line.clone(),
                state: self.state.clone(),
            });
            self.children.lock().unwrap().push(ctl.clone());
            let wait: Box<
                dyn FnOnce() -> std::result::Result<std::process::Output, RunError> + Send,
            > = Box::new(move || ctl.wait());
            Ok(SpawnedChild { pid, wait })
        }

        fn kill(&self, pid: u32) -> std::io::Result<()> {
            let children = self.children.lock().unwrap();
            let ctl = children
                .iter()
                .find(|c| c.pid == pid)
                .expect("kill of an unknown pid: the runner must only kill children it spawned");
            self.state.push(LogEntry::Kill { pid });
            ctl.killed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    /// The per-operation outcome, normalised so one assertion function can
    /// check every generated kind.
    #[derive(Debug)]
    enum PairOutcome {
        Ok,
        Remote(std::process::Output),
        Err(String),
        Exec(std::result::Result<crate::remote::transport::ExecOutcome, Error>),
    }

    /// A real ed25519 host key (never a hardcoded fake), generated once per
    /// test binary: the keyscan "completes" with this key line, so the pin path
    /// verifies it with real `ssh-keygen` and succeeds end-to-end.
    fn host_key() -> (String, String) {
        static KEY: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();
        KEY.get_or_init(|| {
            let dir = tempfile::tempdir().unwrap();
            let keyfile = dir.path().join("hostkey");
            let out = std::process::Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-N", "", "-f"])
                .arg(&keyfile)
                .output()
                .expect("ssh-keygen must be available");
            assert!(
                out.status.success(),
                "ssh-keygen failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let pubkey = std::fs::read_to_string(keyfile.with_extension("pub"))
                .expect("read generated pubkey")
                .trim()
                .to_string();
            let fp = std::process::Command::new("ssh-keygen")
                .args([
                    "-lf",
                    keyfile.with_extension("pub").to_str().unwrap(),
                    "-E",
                    "sha256",
                ])
                .output()
                .expect("ssh-keygen -lf must run");
            let fingerprint = String::from_utf8_lossy(&fp.stdout)
                .split_whitespace()
                .nth(1)
                .expect("fingerprint field")
                .to_string();
            (pubkey, fingerprint)
        })
        .clone()
    }

    fn transport_for(kind: OpKind, fingerprint: &str, runner: SshRunner) -> SshTransport {
        match kind {
            // The pin path requires a configured fingerprint (it reads
            // `self.host_key_fingerprint`), and must never have a known_hosts
            // file or it skips the keyscan entirely.
            OpKind::KeyscanPin => SshTransport::with_runner(
                "deploy",
                "runner-prop.test",
                2222,
                Path::new("/srv/app"),
                None,
                Some(fingerprint),
                runner,
            )
            .unwrap(),
            // Every other op needs a resolvable identity to build `ssh_args`.
            _ => SshTransport::with_runner(
                "deploy",
                "runner-prop.test",
                2222,
                Path::new("/srv/app"),
                Some(Path::new("/dev/null")),
                None,
                runner,
            )
            .unwrap(),
        }
    }

    /// Drive ONE generated (kind × stall) pair through the real transport entry
    /// point with the fake runner injected, then assert the contract.
    fn run_one_pair(kind: OpKind, stall: Stall) {
        let deadline = Duration::from_millis(25);
        let (pubkey, fingerprint) = host_key();
        let (seam, state) = FakeSeam::new(stall, Some(pubkey));
        let runner = SshRunner::with_seam(seam, deadline, deadline);
        let t = transport_for(kind, &fingerprint, runner);

        // The env-lock invariant (crate::testutil): every env-mutating test in
        // this binary serializes on ENV_LOCK. The keyscan pin writes its cache
        // under DEPLOY_SSH_KNOWNHOSTS_DIR; pointing it at a fresh per-pair temp
        // dir guarantees the pin always performs the keyscan SPAWN (a reused
        // cache file would skip the runner call entirely).
        let _guard = crate::testutil::ENV_LOCK.lock().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let old_cache = std::env::var_os("DEPLOY_SSH_KNOWNHOSTS_DIR");
        unsafe {
            std::env::set_var("DEPLOY_SSH_KNOWNHOSTS_DIR", cache.path());
        }
        let outcome = match kind {
            OpKind::Remote => match t.run_remote("printf ok") {
                Ok(out) => PairOutcome::Remote(out),
                Err(e) => PairOutcome::Err(e.to_string()),
            },
            OpKind::RemoteOk => match t.run_remote_ok("true") {
                Ok(()) => PairOutcome::Ok,
                Err(e) => PairOutcome::Err(e.to_string()),
            },
            OpKind::Upload => match t.upload_bytes(Path::new("files/app"), b"payload", 0) {
                Ok(()) => PairOutcome::Ok,
                Err(e) => PairOutcome::Err(e.to_string()),
            },
            OpKind::KeyscanPin => match t.pin_known_hosts() {
                Ok(()) => PairOutcome::Ok,
                Err(e) => PairOutcome::Err(e.to_string()),
            },
            OpKind::Exec => PairOutcome::Exec(t.exec(&["true".into()], deadline)),
        };
        match old_cache {
            Some(v) => unsafe {
                std::env::set_var("DEPLOY_SSH_KNOWNHOSTS_DIR", v);
            },
            None => unsafe {
                std::env::remove_var("DEPLOY_SSH_KNOWNHOSTS_DIR");
            },
        }
        drop(_guard);

        assert_pair(kind, stall, deadline, &state, outcome);
    }

    /// The property's assertions for one pair. `state` is the fake's full call
    /// log + live-waiter count.
    fn assert_pair(
        kind: OpKind,
        stall: Stall,
        deadline: Duration,
        state: &FakeState,
        outcome: PairOutcome,
    ) {
        let (spawn_op, spawn_argv, spawn_pid) = state.spawn();
        assert_eq!(
            spawn_op, kind,
            "the recorded spawn kind must match the operation"
        );
        // argv[0] is the binary: `ssh-keyscan` for the pin, `ssh` for every
        // other operation.
        let expect_bin = if kind == OpKind::KeyscanPin {
            "ssh-keyscan"
        } else {
            "ssh"
        };
        assert_eq!(
            spawn_argv.first().map(String::as_str),
            Some(expect_bin),
            "spawn argv must start with the right binary"
        );

        match stall {
            Stall::Hang => {
                // Every stalled child terminates as Timeout: `exec` keeps its
                // ExecOutcome shape (exit_code -1, stderr "timed out after …"),
                // every other op returns a transport error.
                match &outcome {
                    PairOutcome::Exec(res) => {
                        let o = res
                            .as_ref()
                            .expect("exec on a stalled child must return a Timeout ExecOutcome");
                        assert_eq!(o.exit_code, -1, "timeout exec exit_code must be -1");
                        assert_eq!(
                            o.stderr,
                            format!("timed out after {deadline:?}"),
                            "timeout exec stderr must keep the existing shape"
                        );
                    }
                    _ => {
                        let msg = match &outcome {
                            PairOutcome::Err(m) => m,
                            _ => {
                                panic!("stalled op must fail with a timeout error, got {outcome:?}")
                            }
                        };
                        assert!(
                            msg.contains("timed out after"),
                            "stalled op must report the timeout, got: {msg}"
                        );
                    }
                }
                // … and is REAPED: exactly one kill, then exactly one reap, of
                // THE SAME pid, in that order, after the spawn — no kill-vs-
                // wait race, no zombie, no return-before-reap.
                assert_eq!(
                    state.kill_pids(),
                    vec![spawn_pid],
                    "stalled child must be killed exactly once"
                );
                assert_eq!(
                    state.reap_pids(),
                    vec![spawn_pid],
                    "stalled child must be reaped exactly once"
                );
                assert!(
                    state.kill_precedes_reap(),
                    "kill must precede reap for a stalled child"
                );
            }
            Stall::Complete => {
                match kind {
                    OpKind::Exec => {
                        let o = match outcome {
                            PairOutcome::Exec(Ok(o)) => o,
                            _ => panic!("exec on a completed child must succeed, got {outcome:?}"),
                        };
                        assert_eq!(o.exit_code, 0);
                    }
                    OpKind::Remote => {
                        let o = match outcome {
                            PairOutcome::Remote(o) => o,
                            _ => panic!(
                                "run_remote on a completed child must succeed, got {outcome:?}"
                            ),
                        };
                        assert!(o.status.success());
                    }
                    _ => assert!(
                        matches!(outcome, PairOutcome::Ok),
                        "completed child must succeed, got {outcome:?}"
                    ),
                }
                assert_eq!(
                    state.kill_pids(),
                    Vec::<u32>::new(),
                    "a completed child must never be killed"
                );
                assert_eq!(
                    state.reap_pids(),
                    vec![spawn_pid],
                    "a completed child is reaped by the normal wait"
                );
            }
            Stall::SpawnError => {
                let msg = match &outcome {
                    PairOutcome::Err(m) => m.clone(),
                    PairOutcome::Exec(Err(e)) => e.to_string(),
                    _ => panic!("spawn failure must surface as a transport error, got {outcome:?}"),
                };
                assert!(
                    msg.contains("spawn"),
                    "spawn failure must surface as a spawn error, got: {msg}"
                );
                assert_eq!(
                    state.kill_pids(),
                    Vec::<u32>::new(),
                    "a failed spawn has nothing to kill"
                );
                assert_eq!(
                    state.reap_pids(),
                    Vec::<u32>::new(),
                    "a failed spawn has nothing to reap"
                );
            }
            Stall::NonZero => {
                match kind {
                    OpKind::Remote => {
                        let o = match outcome {
                            PairOutcome::Remote(o) => o,
                            _ => panic!("run_remote returns the raw output, got {outcome:?}"),
                        };
                        assert!(!o.status.success(), "non-zero exit must be reported");
                    }
                    OpKind::Exec => {
                        let o = match outcome {
                            PairOutcome::Exec(Ok(o)) => o,
                            _ => panic!("exec returns the raw outcome, got {outcome:?}"),
                        };
                        assert_eq!(o.exit_code, 1);
                    }
                    _ => {
                        let msg = match &outcome {
                            PairOutcome::Err(m) => m,
                            _ => panic!("non-zero exit must surface as an error, got {outcome:?}"),
                        };
                        assert!(msg.contains("failed"), "got: {msg}");
                    }
                }
                assert_eq!(
                    state.kill_pids(),
                    Vec::<u32>::new(),
                    "a non-zero exit is a normal wait, not a kill"
                );
                assert_eq!(
                    state.reap_pids(),
                    vec![spawn_pid],
                    "a non-zero child is reaped by the normal wait"
                );
            }
            Stall::StdinWriteError => {
                if kind == OpKind::Upload {
                    // The stdin write fails, but the closure ALWAYS reaps first
                    // (wait_with_output runs; the fake records the Reap) and
                    // only then returns the saved write error — no
                    // return-before-reap — and the error surfaces (not a
                    // Timeout) after the reap.
                    let msg = match &outcome {
                        PairOutcome::Err(m) => m,
                        _ => {
                            panic!(
                                "a stdin-write failure must surface as an error, got {outcome:?}"
                            )
                        }
                    };
                    assert!(
                        msg.contains("stdin write"),
                        "a stdin-write failure must surface the write error, got: {msg}"
                    );
                    assert_eq!(
                        state.kill_pids(),
                        Vec::<u32>::new(),
                        "a stdin-write error surfaces before the deadline: nothing to kill"
                    );
                    assert_eq!(
                        state.reap_pids(),
                        vec![spawn_pid],
                        "the child must be reaped even on a stdin-write error"
                    );
                } else {
                    // No stdin payload: nothing is written, so the stall is
                    // vacuous and the child completes normally.
                    match kind {
                        OpKind::Exec => {
                            let o = match outcome {
                                PairOutcome::Exec(Ok(o)) => o,
                                _ => panic!(
                                    "exec with a vacuous write-error stall must succeed, got {outcome:?}"
                                ),
                            };
                            assert_eq!(o.exit_code, 0);
                        }
                        OpKind::Remote => {
                            let o = match outcome {
                                PairOutcome::Remote(o) => o,
                                _ => panic!(
                                    "run_remote with a vacuous write-error stall must succeed, got {outcome:?}"
                                ),
                            };
                            assert!(o.status.success());
                        }
                        _ => assert!(
                            matches!(outcome, PairOutcome::Ok),
                            "a vacuous write-error stall must succeed, got {outcome:?}"
                        ),
                    }
                    assert_eq!(
                        state.kill_pids(),
                        Vec::<u32>::new(),
                        "a vacuous write-error stall is a normal wait, not a kill"
                    );
                    assert_eq!(
                        state.reap_pids(),
                        vec![spawn_pid],
                        "a vacuous write-error child is reaped by the normal wait"
                    );
                }
            }
            Stall::WaitError => {
                // The wait fails AFTER the reap attempt, and the wait error
                // surfaces (not a Timeout); the child is still recorded as
                // reaped — never a return-before-reap.
                let msg = match &outcome {
                    PairOutcome::Err(m) => m.clone(),
                    PairOutcome::Exec(Err(e)) => e.to_string(),
                    _ => panic!("a wait failure must surface as an error, got {outcome:?}"),
                };
                assert!(
                    msg.contains("wait"),
                    "a wait failure must surface as a wait error, got: {msg}"
                );
                assert_eq!(
                    state.kill_pids(),
                    Vec::<u32>::new(),
                    "a wait error is a normal wait, not a kill"
                );
                assert_eq!(
                    state.reap_pids(),
                    vec![spawn_pid],
                    "the child must be reaped even on a wait error (the reap attempt is recorded)"
                );
            }
        }

        assert_eq!(
            state.live_waiters(),
            0,
            "every wait thread must be joined (reaped) before the operation returns"
        );
    }

    fn op_strategy() -> impl Strategy<Value = OpKind> {
        prop_oneof![
            Just(OpKind::Remote),
            Just(OpKind::RemoteOk),
            Just(OpKind::Upload),
            Just(OpKind::KeyscanPin),
            Just(OpKind::Exec),
        ]
    }

    /// Real-runner sanity check: a REAL subprocess that stalls must be killed
    /// at the deadline AND reaped — the pid must be gone afterwards, because an
    /// un-reaped zombie would still answer `kill(pid, 0)` with success.
    #[test]
    fn real_runner_kills_and_reaps_a_stalled_child() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("child.pid");
        // The child records its own pid to a file, then execs `sleep` (so the
        // recorded pid IS the process the runner must kill and reap).
        let argv = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("echo $$ > {}; exec sleep 30", pidfile.display()),
        ];
        let runner = SshRunner::new();
        let deadline = Duration::from_millis(100);
        let start = Instant::now();
        let res = runner.run(OpKind::Exec, &argv, None, Some(deadline));
        assert!(matches!(res, Err(RunError::Timeout { after }) if after == deadline));
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "a stalled child must be killed at the deadline, not after it"
        );
        let pid: i32 = std::fs::read_to_string(&pidfile)
            .expect("child must have recorded its pid before stalling")
            .trim()
            .parse()
            .unwrap();
        // SAFETY: `kill(pid, 0)` only probes existence; it sends no signal.
        let still_exists = unsafe { libc::kill(pid, 0) } == 0;
        assert!(
            !still_exists,
            "child {pid} must be reaped (a zombie would still exist)"
        );
    }

    /// THE timed-out-upload guarantee: a real child that RECORDS ITS PID but
    /// NEVER reads stdin, with a payload larger than the pipe buffer (1 MiB » a
    /// 16–64 KiB pipe), blocks the wait closure's stdin write until the tiny
    /// deadline fires; the child is then KILLED — and the recorded PID must be
    /// GONE afterwards, proving the timed-out upload was not only killed but
    /// also REAPED (an uncollected zombie would still answer `kill(pid, 0)`).
    #[test]
    fn real_runner_kills_and_reaps_a_timed_out_upload() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("child.pid");
        // The child records its own pid, then execs `sleep` WITHOUT ever
        // reading stdin: the piped payload fills the pipe buffer and the write
        // blocks until the deadline kill closes the pipe.
        let argv = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("echo $$ > {}; exec sleep 30", pidfile.display()),
        ];
        let runner = SshRunner::with_seam(
            Arc::new(RealRunner),
            Duration::from_millis(50),
            Duration::from_millis(50),
        );
        let payload: Vec<u8> = vec![0x5A; 1024 * 1024]; // 1 MiB » pipe buffer
        let start = Instant::now();
        let res = runner.run(OpKind::Upload, &argv, Some(&payload), None);
        assert!(
            matches!(res, Err(RunError::Timeout { after }) if after == Duration::from_millis(50))
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "a timed-out upload must be killed at the deadline, not after it"
        );
        let pid: i32 = std::fs::read_to_string(&pidfile)
            .expect("child must have recorded its pid before stalling")
            .trim()
            .parse()
            .unwrap();
        // SAFETY: `kill(pid, 0)` only probes existence; it sends no signal.
        let still_exists = unsafe { libc::kill(pid, 0) } == 0;
        assert!(
            !still_exists,
            "timed-out upload child {pid} must be reaped (a zombie would still exist)"
        );
    }

    /// Real-runner sanity check: a promptly-completing child returns its output
    /// (no kill, no timeout), and a spawn failure surfaces as a spawn error.
    #[test]
    fn real_runner_completes_and_surfaces_spawn_errors() {
        let runner = SshRunner::new();
        let out = runner
            .run(
                OpKind::Exec,
                &["true".to_string()],
                None,
                Some(Duration::from_secs(5)),
            )
            .expect("a completing child must succeed");
        assert!(out.status.success());
        let err = runner
            .run(
                OpKind::Exec,
                &["/definitely/not/a/real/binary".to_string()],
                None,
                Some(Duration::from_secs(5)),
            )
            .expect_err("a missing binary must fail at spawn");
        assert!(matches!(err, RunError::Spawn(_)));
    }

    fn stall_strategy() -> impl Strategy<Value = Stall> {
        prop_oneof![
            Just(Stall::Hang),
            Just(Stall::Complete),
            Just(Stall::SpawnError),
            Just(Stall::NonZero),
            Just(Stall::StdinWriteError),
            Just(Stall::WaitError),
        ]
    }

    /// The extended seam's new outcomes, driven deterministically: the property
    /// also draws them (6 stalls × 5 ops), but the fixed seed may not pair them
    /// with the upload op in every run. A stdin-write error is returned only
    /// AFTER the child was reaped, and a wait error surfaces after the reap
    /// attempt — never a return-before-reap.
    #[test]
    fn stdin_write_error_is_returned_after_the_reap() {
        run_one_pair(OpKind::Upload, Stall::StdinWriteError);
    }

    #[test]
    fn wait_error_is_returned_after_the_reap() {
        run_one_pair(OpKind::Upload, Stall::WaitError);
    }

    proptest! {
        // The runner contract property: every generated (operation kind × stall
        // point) pair must honor the ONE-runner deadline/kill/reap semantics —
        // stalled children terminate as Timeout AND are reaped (exactly one
        // kill, then exactly one reap, kill before reap), completed/non-zero
        // children are never killed, spawn failures surface as transport errors
        // with nothing to kill or reap, and stdin-write/wait failures surface
        // their error (not a Timeout) only AFTER the child was reaped — the
        // reap count per pid is 1 for EVERY outcome, so no path ever returns
        // before reaping. FIXED SEED 0x5EED_5EED (repo style) + bounded cases
        // keep the suite deterministic and fast: the fake blocks only until the
        // tiny injected deadline, so no case ever sleeps more than ~25ms.
        #![proptest_config(ProptestConfig {
            cases: 16,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn every_ssh_operation_is_deadline_killed_and_reaped(
            pairs in prop::collection::vec((op_strategy(), stall_strategy()), 2..=6)
        ) {
            for (kind, stall) in pairs {
                run_one_pair(kind, stall);
            }
        }
    }
}
