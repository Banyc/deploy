//! The production SSH transport group: the [`SshTransport`] over `ssh`/`scp`,
//! host-identity verification and pinning ([`hostkey`]), and the ONE bounded
//! subprocess runner every ssh operation goes through ([`runner`]) — hard
//! deadline, kill, and deterministic reap.
//!
//! Transport setup is split into two phases: [`Remote::prepare_identity`]
//! (verify/pin the host key) runs before ANY remote request — including a dry
//! run's status inspection — while [`Remote::provision_layout`] (create the
//! deployment-directory layout) runs only behind the push engine's
//! non-dry-run gate.
//!
//! # Submodules
//!
//! * [`hostkey`] — host-identity verification and pinning.
//! * [`runner`] — the bounded subprocess runner.

mod hostkey;
mod runner;

use crate::env::SysEnv;
use crate::error::{Error, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{
    ContentEquivalence, CreateNewVerdict, FsBytes, IMMUTABLE_RECORD_MODE, Remote, RemoteEntry,
    RemoteMeta, RemoveIfVerdict, has_normal_component_below_root, verified_to_verdict,
    verify_existing,
};
use hostkey::pin_known_hosts;
use runner::{OpKind, RunError, SSH_CONNECT_TIMEOUT_SECS, SshRunner};

/// The framed ssh-lstat absence protocol (see [`SshTransport::metadata_opt`]):
/// ONE remote exec runs a small perl `lstat` helper that prints a single
/// TAB-separated frame on stdout — the FRAME is the signal (exit 0 for every
/// outcome, because an exit code carries no errno):
///
/// * `P\t<size>\t<rawmode_hex>` — the entry EXISTS (`lstat` succeeded);
///   `<size>` is decimal and `<rawmode>` is hex, the `stat -c '%s %f'`-
///   equivalent format, so the [`RemoteMeta`] parse is unchanged.
/// * `A\t<errno>` — `lstat` FAILED with a CONFIRMED-ABSENCE errno: ENOENT
///   or ENOTDIR (the ONLY errnos that mean "no such entry").
/// * `E\t<errno>` — `lstat` FAILED with any OTHER errno (EACCES, EIO,
///   ELOOP, ...).
///
/// `metadata_opt` maps ONLY the `A` frame with errno ENOENT/ENOTDIR to
/// `Ok(None)`; every other outcome — EACCES/EIO frames, malformed frames, a
/// signal-killed command, a nonzero exit, a transport failure — is an error.
/// The frames carry the actual errno, which a shell boolean (`[ ! -e ]`)
/// cannot: a permission failure is an ERROR, never absence. The errno
/// numbers are identical on Linux and macOS (POSIX): ENOENT = 2,
/// ENOTDIR = 20.
const LSTAT_ERRNO_ENOENT: i32 = 2;
const LSTAT_ERRNO_ENOTDIR: i32 = 20;

/// The reserved exit code the remote `try_write_new` script (`write_new_cmd`)
/// exits with when the no-clobber publish (perl `link(2)`) hit an EXISTING
/// destination — the conflict/verdict decision point. It is the ONLY nonzero
/// exit the transport
/// maps to a verdict; every other nonzero exit (a failed pre-install step OR
/// the final parent-directory sync) is a propagated error. `17` cannot collide
/// with the pre-install steps' own failures (each exits nonzero, but the
/// transport distinguishes the verdict by code, never by `exists`-sniffing),
/// and it is deliberately distinct from [`SSH_TWRITE_PREINSTALL_EXIT`].
/// `17` is also EEXIST (POSIX, identical on Linux and macOS) — the raw
/// `link(2)` errno the script maps directly to this code.
pub const SSH_TWRITE_CONFLICT_EXIT: i32 = 17;

/// The exit code the remote `write_new_cmd` script uses for a PRE-INSTALL
/// failure — any failure BEFORE the no-clobber publish: the parent `mkdir`,
/// the `mktemp` allocation, the payload write, the final `chmod`, the file
/// `sync`, or a non-EEXIST `link(2)` failure. Such a failure means the
/// operation never reached the publish
/// decision point, so it is a propagated Error, NEVER a verdict — the
/// transport refuses to guess the destination's state. Deliberately distinct
/// from [`SSH_TWRITE_CONFLICT_EXIT`] so the script can tell "the install never
/// happened" from "the destination already existed".
pub const SSH_TWRITE_PREINSTALL_EXIT: i32 = 1;

/// A transport that drives a real remote host over SSH.
pub struct SshTransport {
    /// `user@address` passed to `ssh` as the connection target.
    target: String,
    /// Bare host/address (no `user@` prefix) passed to `ssh-keyscan`, which
    /// expects a hostname/address, not a `user@host` connection string.
    address: String,
    /// Configured SSH port (passed to both `ssh -p` and `ssh-keyscan -p`).
    port: u16,
    root: PathBuf,
    /// Dedicated known-hosts file used with `StrictHostKeyChecking=yes`.
    known_hosts: Option<PathBuf>,
    /// Pre-verified host-key fingerprint (e.g. `SHA256:...`) used to pin the
    /// host key the first time we contact it.
    host_key_fingerprint: Option<String>,
    /// Managed known-hosts file holding the pinned key (used when only a
    /// fingerprint was configured). Set only by [`SshTransport::prepare_identity`],
    /// never at construction, so building the transport has no side effects.
    pinned_known_hosts: std::sync::Mutex<Option<PathBuf>>,
    /// The RESOLVED pin-cache directory for the managed known-hosts file
    /// (the snapshot's `DEPLOY_SSH_KNOWNHOSTS_DIR`, else
    /// `<temp_dir>/deploy-ssh-knownhosts`) — resolved ONCE at the
    /// construction boundary, never read from the process env.
    known_hosts_cache_dir: PathBuf,
    /// The environment snapshot (owned): the pin path's `ssh-keygen`
    /// fingerprint-verification child receives its variables.
    env: SysEnv,
    /// THE bounded subprocess runner every ssh operation goes through
    /// ([`SshRunner`]): hard deadline, kill, and deterministic reap, so no
    /// operation can run unbounded after connection establishment.
    runner: SshRunner,
}

impl SshTransport {
    /// Build a transport for `user@address` (connecting on `port`), whose
    /// application root is the absolute `deploy_dir` path on that host — a
    /// path with at least one normal component below the root (the
    /// filesystem root itself is refused, mirroring the
    /// [`crate::identity::AbsoluteDeployDir`] parse rule: a transport rooted
    /// at `/` would make the deployment cleanup operate on the system
    /// root).
    ///
    /// Host identity must be configured with EXACTLY ONE source: pass a
    /// `known_hosts` file OR a `host_key_fingerprint`. If neither is provided
    /// the transport refuses to connect (no trust-on-first-use); if both are
    /// provided the choice is ambiguous (the ssh arguments would silently
    /// prefer `known_hosts`), so the construction is rejected.
    ///
    /// `known_hosts_cache_dir` is the RESOLVED pin-cache directory for the
    /// managed known-hosts file (from the environment snapshot at the
    /// boundary), and `env` is that snapshot: every child this transport
    /// spawns (ssh, ssh-keyscan, ssh-keygen) receives its variables.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user: &str,
        address: &str,
        port: u16,
        deploy_dir: &Path,
        known_hosts: Option<&Path>,
        host_key_fingerprint: Option<&str>,
        known_hosts_cache_dir: &Path,
        env: &SysEnv,
    ) -> Result<Self> {
        if user.is_empty() || address.is_empty() {
            return Err(Error::transport(
                "ssh transport requires a non-empty user and address",
            ));
        }
        if deploy_dir.is_relative() {
            return Err(Error::transport("ssh deploy_dir must be an absolute path"));
        }
        if !has_normal_component_below_root(deploy_dir) {
            return Err(Error::transport(
                "ssh deploy_dir must have at least one normal path component below the root (the filesystem root is not a valid deploy_dir)",
            ));
        }
        // Defensive rejection of ambiguous or unusable identity states, even
        // when the config validation was bypassed (e.g. a direct caller):
        // exactly one of known_hosts / host_key_fingerprint may be set.
        match (known_hosts, host_key_fingerprint) {
            (Some(_), Some(_)) => {
                return Err(Error::transport(
                    "ssh host identity is ambiguous: exactly one of known_hosts or \
                     host_key_fingerprint must be configured (both are set)",
                ));
            }
            (None, None) => {
                return Err(Error::transport(
                    "ssh host identity is not configured: exactly one of `known_hosts` or \
                     `host_key_fingerprint` must be provided (trust-on-first-use is disabled)",
                ));
            }
            _ => {}
        }
        let t = SshTransport {
            target: format!("{user}@{address}"),
            address: address.to_string(),
            port,
            root: deploy_dir.to_path_buf(),
            known_hosts: known_hosts.map(|p| p.to_path_buf()),
            host_key_fingerprint: host_key_fingerprint.map(|s| s.to_string()),
            pinned_known_hosts: std::sync::Mutex::new(None),
            known_hosts_cache_dir: known_hosts_cache_dir.to_path_buf(),
            env: env.clone(),
            runner: SshRunner::new(env),
        };
        // NOTE: construction is side-effect-free. When a fingerprint was
        // supplied without an explicit known-hosts file, the host key is
        // verified and pinned by `prepare_identity` (before the first remote
        // request), not here — a dry run must never touch the network or disk.
        Ok(t)
    }

    /// Test-only constructor: same validation as [`SshTransport::new`], but with
    /// an injected runner (fake seam + tiny deadlines), so the property test can
    /// drive the deadline/kill/reap contract through the real entry points
    /// without any real subprocess.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_runner(
        user: &str,
        address: &str,
        port: u16,
        deploy_dir: &Path,
        known_hosts: Option<&Path>,
        host_key_fingerprint: Option<&str>,
        known_hosts_cache_dir: &Path,
        env: &SysEnv,
        runner: SshRunner,
    ) -> Result<Self> {
        let mut t = Self::new(
            user,
            address,
            port,
            deploy_dir,
            known_hosts,
            host_key_fingerprint,
            known_hosts_cache_dir,
            env,
        )?;
        t.runner = runner;
        Ok(t)
    }

    /// Build the fixed `ssh` arguments (options + target). Errors if no host
    /// identity has been configured, so the caller cannot accidentally fall back
    /// to trust-on-first-use.
    fn ssh_args(&self) -> Result<Vec<String>> {
        let mut args: Vec<String> = vec![
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "PreferredAuthentications=publickey".into(),
            "-o".into(),
            format!("ConnectTimeout={SSH_CONNECT_TIMEOUT_SECS}"),
            "-p".into(),
            self.port.to_string(),
        ];
        // Read the pinned path through the lock; it is set only by
        // `prepare_identity`.
        let pinned = self.pinned_known_hosts.lock().ok().and_then(|g| g.clone());
        match (&self.known_hosts, &pinned) {
            (Some(kh), _) => {
                args.push("-o".into());
                args.push(format!("UserKnownHostsFile={}", kh.display()));
                args.push("-o".into());
                args.push("StrictHostKeyChecking=yes".into());
            }
            (None, Some(pinned)) => {
                args.push("-o".into());
                args.push(format!("UserKnownHostsFile={}", pinned.display()));
                args.push("-o".into());
                args.push("StrictHostKeyChecking=yes".into());
            }
            (None, None) => {
                return Err(Error::transport(
                    "ssh host identity is not configured: provide `known_hosts` or \
                     `host_key_fingerprint` (trust-on-first-use is disabled)",
                ));
            }
        }
        args.push(self.target.clone());
        Ok(args)
    }

    /// Verify the remote host key against the configured fingerprint and pin
    /// it in a managed known-hosts file (see [`pin_known_hosts`]).
    /// Fails closed if the key cannot be fetched or does not match. Takes
    /// `&self`: the pinned path is stored through the interior-mutability
    /// lock; the verification/cache logic itself lives in `pin_known_hosts`.
    pub(crate) fn pin_known_hosts(&self) -> Result<()> {
        let fingerprint = self
            .host_key_fingerprint
            .clone()
            .ok_or_else(|| Error::transport("host_key_fingerprint required for pinning"))?;
        let pinned = pin_known_hosts(
            &fingerprint,
            &self.target,
            &self.address,
            self.port,
            &self.known_hosts_cache_dir,
            &self.env,
            &self.runner,
        )?;
        if let Ok(mut g) = self.pinned_known_hosts.lock() {
            *g = Some(pinned);
        }
        Ok(())
    }

    /// Run a single remote shell command (already fully quoted) and return its
    /// stdout/stderr/status. The command is passed as one `ssh` argument after
    /// `--`, so OpenSSH cannot interpret any part of our data as options or as
    /// the connection target. Runs through the shared bounded runner: once
    /// connected, a remote command that hangs is killed after
    /// `SSH_COMMAND_TIMEOUT_SECS` (nothing is unbounded after connection
    /// establishment).
    pub(crate) fn run_remote(&self, command: &str) -> Result<std::process::Output> {
        self.run_remote_op(OpKind::Remote, command)
    }

    pub(crate) fn run_remote_ok(&self, command: &str) -> Result<()> {
        let out = self.run_remote_op(OpKind::RemoteOk, command)?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh command failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(())
    }

    /// Shared implementation of the single-command ssh operations: build the
    /// `ssh <args> -- <command>` vector and run it through the runner under the
    /// command deadline. `run_remote` and `run_remote_ok` differ only in the
    /// recorded operation kind and in whether they check the exit status.
    fn run_remote_op(&self, op: OpKind, command: &str) -> Result<std::process::Output> {
        let mut argv = vec!["ssh".to_string()];
        argv.extend(self.ssh_args()?);
        argv.push("--".into());
        argv.push(command.to_string());
        self.runner.run(op, &argv, None, None).map_err(|e| match e {
            RunError::Spawn(m) => Error::transport(format!("ssh {command}: {m}")),
            RunError::StdinWrite(m) => Error::transport(format!("ssh {command}: {m}")),
            RunError::Wait(m) => Error::transport(format!("ssh {command}: {m}")),
            RunError::Timeout { after } => {
                Error::transport(format!("ssh command timed out after {after:?}: {command}"))
            }
        })
    }

    /// Build a remote shell command string from an `argv`, quoting every
    /// argument so the remote shell re-tokenizes it back into exactly `argv`.
    /// Build the remote `mv` command for an atomic path replacement.
    ///
    /// `-T` (no-target-directory) is REQUIRED: without it GNU mv treats a
    /// destination that is a symlink to a directory as the directory itself
    /// and moves `from` INTO it instead of replacing the symlink. The
    /// `current` swap depends on replacing a symlink-to-directory in place
    /// (the atomic per-slot commit point), and a bare `mv` silently pollutes
    /// the object store with the temp link.
    fn rename_cmd(root: &Path, from: &Path, to: &Path) -> String {
        let f = root.join(from).to_string_lossy().into_owned();
        let t = root.join(to).to_string_lossy().into_owned();
        let parent = Path::new(&t)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());
        format!(
            "mkdir -p {parent} && mv -T {f} {t}",
            parent = shell_quote(&parent),
            f = shell_quote(&f),
            t = shell_quote(&t),
        )
    }

    fn argv_cmd(argv: &[String]) -> String {
        argv.iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Upload raw bytes to a remote path (creating parent dirs). Runs through
    /// the shared bounded runner: the stdin payload is written as part of the
    /// bounded wait, so an upload to a remote that stops reading (hung remote
    /// mid-`cat`) times out after `SSH_COMMAND_TIMEOUT_SECS` instead of
    /// blocking the push indefinitely.
    pub(crate) fn upload_bytes(&self, rel: &Path, data: &[u8], mode: u32) -> Result<()> {
        let remote_path = self.root.join(rel);
        let remote_path_str = remote_path.to_string_lossy().into_owned();
        let script = format!(
            "mkdir -p $(dirname {p}) && cat > {p}",
            p = shell_quote(&remote_path_str)
        );
        let mut argv = vec!["ssh".to_string()];
        argv.extend(self.ssh_args()?);
        argv.push("--".into());
        argv.push(script);
        let out = self
            .runner
            .run(OpKind::Upload, &argv, Some(data), None)
            .map_err(|e| match e {
                RunError::Spawn(m) => Error::transport(format!("ssh upload spawn: {m}")),
                RunError::StdinWrite(m) => Error::transport(format!("ssh upload stdin write: {m}")),
                RunError::Wait(m) => Error::transport(format!("ssh upload wait: {m}")),
                RunError::Timeout { after } => {
                    Error::transport(format!("ssh upload timed out after {after:?}"))
                }
            })?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh upload failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        if mode != 0 {
            self.run_remote_ok(&Self::argv_cmd(&[
                "chmod".into(),
                format!("{:o}", mode & 0o7777),
                remote_path_str,
            ]))?;
        }
        Ok(())
    }

    fn download_bytes(&self, rel: &Path) -> Result<Vec<u8>> {
        let remote_path = self.root.join(rel);
        let remote_path_str = remote_path.to_string_lossy().into_owned();
        // Read the file contents with `cat`; the path is quoted so a path that
        // happens to contain shell metacharacters (or an executable-bit path) is
        // never executed.
        let out = self.run_remote(&format!("cat {}", shell_quote(&remote_path_str)))?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh download failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(out.stdout)
    }
}

/// Single-quote a string for safe inclusion in a remote shell token. A `'` is
/// escaped as `'\''` (close-quote, escaped quote, reopen-quote).
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

impl SshTransport {
    /// Build the remote shell command implementing the durability protocol
    /// for an immutable record at `root.join(rel)` — the remote realization
    /// of the ONE canonical create-new primitive (`durable_create_new` in
    /// the parent module), with the IDENTICAL seven-step sequence:
    ///
    /// 1. Allocate the temporary file REMOTELY with `mktemp` (exclusive
    ///    create, O_EXCL), so the name cannot collide with another
    ///    controller's temp no matter its pid or host: no two invocations
    ///    are ever handed the same name, and a stale temp left behind by a
    ///    crashed controller is never selected — and therefore never
    ///    truncated. The name is dot-prefixed and lives INSIDE the
    ///    destination's parent directory, so a concurrent reader never sees
    ///    a partial record and listing-based observers skip the temp name.
    /// 2. Write the payload — the RAW BYTES arrive on the command's STDIN
    ///    (the transport pipes them to the ssh child; the remote `cat`
    ///    redirects them into the temp with `cat > "$tmp"`). The payload is
    ///    NEVER embedded in the command string — no shell escaping, no
    ///    quoting — so ARBITRARY bytes (NULs, non-UTF8, control chars,
    ///    quotes, shell metacharacters, long payloads) round-trip exactly:
    ///    this is the byte-preservation contract of [`Remote::try_write_new`].
    /// 3. Apply the FINAL MODE with `chmod` BEFORE the file fsync — the
    ///    published inode carries the caller's mode, never the remote umask.
    /// 4. `sync "$tmp"` — the file is durable.
    /// 5. Install atomically WITHOUT replacement via perl's raw `link(2)`
    ///    (the same interpreter the framed `lstat` helper relies on) — it
    ///    FAILS if the destination exists in ANY form (a regular file, a
    ///    directory, a symlink — never linked-inside or dereferenced the way
    ///    a shell `ln` would), so no loser can clobber a winner. The loser's
    ///    failure is reported through the reserved `SSH_TWRITE_CONFLICT_EXIT`
    ///    exit code, NEVER by replacing the winner.
    /// 6. Remove only the temporary file THIS invocation created (the
    ///    cleanup runs on the conflict path too — the `rc` capture keeps it
    ///    outside the `&&` chain).
    /// 7. `sync <parent>` — the PARENT-DIRECTORY fsync whose failure
    ///    PROPAGATES (the old script swallowed it with `2>/dev/null`): a
    ///    failed sync is a failed install, never a silent success.
    ///
    /// The parent directory is created first (the remote layout is not
    /// provisioned by SSH the way LocalTransport does it), so a fresh remote
    /// root still allows the first lock acquisition. The PRE-INSTALL chain
    /// (`mkdir` .. `sync "$tmp"`) is `&&`-connected and its exit status is
    /// captured separately: if ANY pre-install step fails, the command exits
    /// [`SSH_TWRITE_PREINSTALL_EXIT`] WITHOUT installing anything (fail
    /// closed) — a pre-install failure is a propagated ERROR, never the
    /// conflict verdict, because the operation never reached the publish
    /// decision point. The publish is perl `link(2)` — RAW link semantics,
    /// so a destination that exists in ANY form (a regular file, a DIRECTORY
    /// — which a shell `ln` would silently link INSIDE — or a symlink) is
    /// EEXIST, never dereferenced and never linked-into; EEXIST (17, the
    /// same value as [`SSH_TWRITE_CONFLICT_EXIT`]) exits the reserved
    /// conflict code directly, any other link failure is the pre-install
    /// exit. Only a nonzero publish exit whose destination is then PRESENT
    /// (`[ -e ]`/`[ -L ]`) is the confirmed-EEXIST verdict
    /// [`SSH_TWRITE_CONFLICT_EXIT`] (the winner is never replaced; the
    /// transport verifies it and decides AlreadyPresent vs Conflict); a
    /// nonzero publish exit with the destination ABSENT is a real publish
    /// failure, again the pre-install exit (an error). The final `sync
    /// <parent>` runs ONLY on the install-success path, and its exit status
    /// is the command's exit status — a real `sync <dir>`/fsync, never a
    /// best-effort swallow. (The
    /// AlreadyPresent retry's parent sync runs in the TRANSPORT — see
    /// [`SshTransport::try_write_new`] — mirroring the local primitive's
    /// "parent fsync on Created AND AlreadyPresent, never on Conflict".)
    //
    // Portability notes: `mktemp TEMPLATE` accepts a template argument on
    // both GNU and BSD/macOS, provided `XXXXXX` ends the final component
    // (kept here), and `sync FILE` fsyncs the path on Linux (coreutils
    // >= 8.24) and macOS (forces pending writes); the parent-dir sync is the
    // real `sync <dir>` whose failure propagates. The payload write is a
    // bare `cat > "$tmp"`: `cat` is POSIX, reads stdin to EOF, and the
    // redirect opens the temp — no quoting of data anywhere.
    fn write_new_cmd(root: &Path, rel: &Path, mode: u32) -> String {
        let remote_path = root.join(rel);
        let remote_path_str = remote_path.to_string_lossy().into_owned();
        let parent = Path::new(&remote_path_str)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());
        // Durability protocol — the seven-step sequence is documented on
        // this function; the comment here only notes the pieces that are
        // invisible in the final string: the pre-install chain fails closed
        // with the PRE-INSTALL exit (distinct from the conflict verdict), the
        // publish is perl `link(2)` (raw link semantics — a destination that
        // exists in ANY form is EEXIST and exits the reserved conflict code
        // directly, never linked-inside or dereferenced the way a shell `ln`
        // would), the confirmed-EEXIST fallback decision is made by checking
        // the destination's PRESENCE after a failed publish (never by
        // swallowing every publish failure as a verdict), the `rc` capture
        // keeps the temp cleanup outside the chain so it runs on the
        // conflict path too, and the
        // parent-dir sync runs ONLY after a successful install and its
        // failure is the command's exit status.
        let basename = Path::new(&remote_path_str)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "record".to_string());
        // The temp lives INSIDE the destination's parent directory and is
        // dot-prefixed, exactly like LocalTransport's durable_create_new. A
        // sibling name (`{parent}.{basename}.tmp...`) would escape the
        // managed remote root whenever the destination's parent IS the
        // deployment root. The `XXXXXX` suffix is the mktemp template; it
        // must survive shell quoting verbatim (single quotes are fine) so GNU
        // and BSD mktemp both accept it.
        let tmp_template = format!("{}/.{}.tmp.XXXXXX", parent.trim_end_matches('/'), basename,);
        let mode_str = format!("{:o}", mode & 0o7777);
        // The publish step: perl's raw `link(2)` (perl ships with every
        // reasonable remote — the same interpreter the framed `lstat` helper
        // already relies on). A shell `ln` would silently place the link
        // INSIDE an existing directory destination (or follow a symlink);
        // `link(2)` fails with EEXIST whenever the destination name exists in
        // ANY form — a regular file, a directory, a symlink — so the
        // immutable-record destination can never be silently created over a
        // non-file entry. EEXIST is 17 on both Linux and macOS (POSIX),
        // identical to the reserved [`SSH_TWRITE_CONFLICT_EXIT`]; any other
        // link failure is the pre-install exit (a real publish error).
        format!(
            "mkdir -p {p} && tmp=$(mktemp {tpl}) && cat > \"$tmp\" && chmod {mode} \"$tmp\" && sync \"$tmp\"; pre=$?; if [ \"$pre\" -ne 0 ]; then rm -f \"$tmp\"; exit {preinst}; fi; perl -e 'exit 0 if link($ARGV[0], $ARGV[1]); exit(($! + 0) == 17 ? {conflict} : {preinst})' \"$tmp\" {d}; rc=$?; rm -f \"$tmp\"; if [ \"$rc\" -eq 0 ]; then sync {parent}; exit $?; fi; if [ -e {d} ] || [ -L {d} ]; then exit {conflict}; fi; exit {preinst}",
            p = shell_quote(&parent),
            tpl = shell_quote(&tmp_template),
            mode = mode_str,
            d = shell_quote(&remote_path_str),
            conflict = SSH_TWRITE_CONFLICT_EXIT,
            preinst = SSH_TWRITE_PREINSTALL_EXIT,
            parent = shell_quote(&parent),
        )
    }

    /// Build the remote `list` script for `rel`. The glob intentionally covers
    /// hidden entries but excludes the `.` and `..` self/parent directories,
    /// and each entry's real mode is fetched with `stat -c '%f'` (raw mode in
    /// hex) so the caller can faithfully reconstruct permissions and types.
    fn list_script(&self, rel: &Path) -> String {
        let p = shell_quote(&self.root.join(rel).to_string_lossy());
        format!(
            "for e in {p}/* {p}/.[!.]* {p}/..?*; do case \"$e\" in {p}/.|{p}/..) continue;; esac; [ -e \"$e\" ] || continue; n=$(basename \"$e\"); if [ -L \"$e\" ]; then t=l; elif [ -d \"$e\" ]; then t=d; else t=f; fi; m=$(stat -c '%f' \"$e\"); printf '%s\\t%s\\t%s\\n' \"$n\" \"$t\" \"$m\"; done"
        )
    }

    /// Build the remote shell command implementing the atomic compare-and-
    /// delete (the ssh mirror of `LocalTransport::remove_file_if`): CLAIM the
    /// entry with `mv` to a mktemp-allocated same-directory name (the lock is
    /// always a regular file, so plain `mv` — portable GNU and BSD — moves it
    /// without the `-T` the symlink-to-directory `current` swap needs; only
    /// ONE contender can win the claim; a failed mv with the destination
    /// still present is a Mismatch verdict, with the destination absent an
    /// Absent verdict), VERIFY with `cmp`, then either DELETE the claim
    /// (match → frame `R`) or RESTORE it no-replace with `ln` (mismatch →
    /// frame `M`; a concurrent install makes `ln` fail — the winner is never
    /// replaced and the claim is discarded). The single stdout frame is
    /// parsed strictly; a malformed frame is an error, never a silent
    /// verdict.
    fn remove_file_if_cmd(root: &Path, rel: &Path, expected: &[u8]) -> String {
        let remote_path_str = root.join(rel).to_string_lossy().into_owned();
        let parent = Path::new(&remote_path_str)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());
        let basename = Path::new(&remote_path_str)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "record".to_string());
        // The claim temp lives INSIDE the destination's parent directory and
        // is dot-prefixed, exactly like write_new_cmd's temp.
        let tmp_template = format!(
            "{}/.{}.claim.XXXXXX",
            parent.trim_end_matches('/'),
            basename
        );
        let expected_str = String::from_utf8_lossy(expected).into_owned();
        format!(
            "mkdir -p {p} && tmp=$(mktemp {tpl}) && rm -f \"$tmp\" && if mv {d} \"$tmp\" 2>/dev/null; then if printf '%s' {exp} | cmp -s \"$tmp\" -; then rm -f \"$tmp\"; printf 'R'; else ln \"$tmp\" {d} 2>/dev/null; rm -f \"$tmp\"; printf 'M'; fi; else if [ -e {d} ] || [ -L {d} ]; then printf 'M'; else printf 'A'; fi; fi",
            p = shell_quote(&parent),
            tpl = shell_quote(&tmp_template),
            d = shell_quote(&remote_path_str),
            exp = shell_quote(&expected_str),
        )
    }

    /// Build the remote framed `lstat` helper for `rel`: ONE remote exec
    /// whose single stdout frame reports the OUTCOME WITH THE ERRNO (see the
    /// [`LSTAT_ERRNO_ENOENT`] protocol doc on this module). The helper is a
    /// `perl -e` one-liner (perl ships with every reasonable Linux/macOS
    /// remote — the same interpreter the test fixtures already use) that
    /// performs a REAL `lstat` and prints `P`/`A`/`E` frames, exiting 0 for
    /// all three outcomes — the FRAME is the signal, an exit code carries no
    /// errno. The path is passed as a positional argument after `--` (already
    /// single-quoted), so the shell and perl both see it verbatim.
    fn lstat_script(&self, rel: &Path) -> String {
        let p = shell_quote(&self.root.join(rel).to_string_lossy());
        format!(
            "perl -e 'my @s = lstat($ARGV[0]); if (@s) {{ printf \"P\\t%s\\t%x\\n\", $s[7], $s[2] & 0xffff; exit 0; }} my $e = $! + 0; print(($e == 2 || $e == 20) ? \"A\\t$e\\n\" : \"E\\t$e\\n\");' -- {p}"
        )
    }

    /// Parse the ONE-LINE framed record produced by [`SshTransport::lstat_script`]
    /// (see the module doc): a `P` frame parses strictly into a [`RemoteMeta`]
    /// (exactly two TAB-separated payload fields — decimal size, hex raw
    /// mode), an `A` frame with errno ENOENT/ENOTDIR is the ONLY `Ok(None)`
    /// (confirmed absence), an `A` frame with any other errno and every `E`
    /// frame are errors (a permission/IO failure is NEVER absence), and
    /// anything malformed — garbage, missing fields, wrong prefix, extra
    /// fields, extra lines — is an error, never a silent default.
    fn parse_lstat_frame(stdout: &str) -> Result<Option<RemoteMeta>> {
        let lines: Vec<&str> = stdout.lines().collect();
        let [line] = lines.as_slice() else {
            return Err(Error::transport(format!(
                "ssh lstat: malformed frame: expected exactly one line, got {lines:?}"
            )));
        };
        let mut it = line.split('\t');
        match it.next() {
            // Present: strictly parse `size` (decimal) + `rawmode` (hex).
            Some("P") => {
                let size = it
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
                    .ok_or_else(|| {
                        Error::transport(format!("ssh lstat: malformed present frame: {line:?}"))
                    })?;
                let raw = it
                    .next()
                    .and_then(|s| u32::from_str_radix(s, 16).ok())
                    .ok_or_else(|| {
                        Error::transport(format!("ssh lstat: malformed present frame: {line:?}"))
                    })?;
                if it.next().is_some() {
                    return Err(Error::transport(format!(
                        "ssh lstat: malformed present frame: {line:?}"
                    )));
                }
                let mode = raw & 0o7777;
                let is_symlink = (raw & 0o170000) == 0o120000;
                let is_dir = (raw & 0o170000) == 0o040000;
                let is_file = !is_symlink && !is_dir;
                Ok(Some(RemoteMeta {
                    is_dir,
                    is_symlink,
                    is_file,
                    size,
                    mode,
                }))
            }
            // Absent: ONLY ENOENT/ENOTDIR are confirmed absence; an `A` frame
            // carrying any other errno is a helper bug/mismatch -> error.
            Some("A") => {
                let errno = it.next().and_then(Self::parse_lstat_errno).ok_or_else(|| {
                    Error::transport(format!("ssh lstat: malformed absent frame: {line:?}"))
                })?;
                if it.next().is_some() {
                    return Err(Error::transport(format!(
                        "ssh lstat: malformed absent frame: {line:?}"
                    )));
                }
                match errno {
                    LSTAT_ERRNO_ENOENT | LSTAT_ERRNO_ENOTDIR => Ok(None),
                    other => Err(Error::transport(format!(
                        "ssh lstat: absent frame with non-absence errno {other}: {line:?}"
                    ))),
                }
            }
            // Error: ANY errno here is an error — EACCES/EIO/... are never
            // absence.
            Some("E") => {
                let errno = it.next().and_then(Self::parse_lstat_errno).ok_or_else(|| {
                    Error::transport(format!("ssh lstat: malformed error frame: {line:?}"))
                })?;
                if it.next().is_some() {
                    return Err(Error::transport(format!(
                        "ssh lstat: malformed error frame: {line:?}"
                    )));
                }
                Err(Error::transport(format!(
                    "ssh lstat failed (errno {errno}): {line:?}"
                )))
            }
            _ => Err(Error::transport(format!(
                "ssh lstat: malformed frame: {line:?}"
            ))),
        }
    }

    /// Parse an `<errno>` frame field: a decimal errno NUMBER (cross-platform
    /// — ENOENT=2 and ENOTDIR=20 are identical on Linux and macOS), or the
    /// POSIX name (`ENOENT`/`ENOTDIR`). Anything else is malformed.
    fn parse_lstat_errno(s: &str) -> Option<i32> {
        if let Ok(n) = s.parse::<i32>() {
            return Some(n);
        }
        match s {
            "ENOENT" => Some(LSTAT_ERRNO_ENOENT),
            "ENOTDIR" => Some(LSTAT_ERRNO_ENOTDIR),
            _ => None,
        }
    }

    /// Parse the tab-delimited output produced by [`SshTransport::list_script`].
    /// Each line is `name<TAB>type<TAB>rawmode_hex`; `.` and `..` are never
    /// emitted by the script, but are skipped here defensively.
    fn parse_list_output(stdout: &str) -> Vec<RemoteEntry> {
        let mut entries = Vec::new();
        for line in stdout.lines() {
            let mut it = line.split('\t');
            let name = match it.next() {
                Some(n) if !n.is_empty() => n.to_string(),
                _ => continue,
            };
            if name == "." || name == ".." {
                continue;
            }
            let t = it.next().unwrap_or("f");
            let raw = it
                .next()
                .and_then(|s| u32::from_str_radix(s, 16).ok())
                .unwrap_or(0);
            let mode = raw & 0o7777;
            let is_dir = t == "d";
            let is_symlink = t == "l";
            entries.push(RemoteEntry {
                name,
                is_dir,
                is_symlink,
                size: 0,
                mode,
            });
        }
        entries
    }
}

impl Remote for SshTransport {
    fn root(&self) -> &Path {
        &self.root
    }

    fn prepare_identity(&self) -> Result<()> {
        // If a fingerprint was supplied without an explicit known-hosts file,
        // verify the host key and pin it in a managed file BEFORE any remote
        // request — including a dry run's status inspection, which still
        // connects over ssh and therefore needs the pinned key.
        if self.known_hosts.is_none() && self.host_key_fingerprint.is_some() {
            self.pin_known_hosts()?;
        }
        Ok(())
    }

    fn provision_layout(&self) -> Result<()> {
        // Create the deployment-directory layout on the remote host. The set of
        // bootstrap directories is owned by `crate::remote::layout::bootstrap_dirs` —
        // the same list LocalTransport provisions — and every path is
        // single-quoted by `argv_cmd`/`shell_quote` so it reaches `mkdir`
        // verbatim. This runs only after the push engine's non-dry-run gate.
        let mut argv: Vec<String> = vec!["mkdir".into(), "-p".into()];
        argv.extend(
            crate::remote::layout::bootstrap_dirs()
                .iter()
                .map(|d| self.root.join(d).to_string_lossy().into_owned()),
        );
        self.run_remote_ok(&Self::argv_cmd(&argv))
    }

    fn read(&self, rel: &Path) -> Result<Vec<u8>> {
        self.download_bytes(rel)
    }

    fn write(&self, rel: &Path, data: &[u8], mode: u32) -> Result<()> {
        self.upload_bytes(rel, data, mode)
    }

    fn create_dir(&self, rel: &Path) -> Result<()> {
        let p = self.root.join(rel).to_string_lossy().into_owned();
        self.run_remote_ok(&Self::argv_cmd(&["mkdir".into(), p]))
    }

    fn create_dir_all(&self, rel: &Path) -> Result<()> {
        let p = self.root.join(rel).to_string_lossy().into_owned();
        self.run_remote_ok(&Self::argv_cmd(&["mkdir".into(), "-p".into(), p]))
    }

    fn set_mode(&self, rel: &Path, mode: u32) -> Result<()> {
        let p = self.root.join(rel).to_string_lossy().into_owned();
        self.run_remote_ok(&Self::argv_cmd(&[
            "chmod".into(),
            format!("{:o}", mode & 0o7777),
            p,
        ]))
    }

    fn list(&self, rel: &Path) -> Result<Vec<RemoteEntry>> {
        let out = self.run_remote(&self.list_script(rel))?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh list failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(Self::parse_list_output(&String::from_utf8_lossy(
            &out.stdout,
        )))
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        self.run_remote_ok(&SshTransport::rename_cmd(&self.root, from, to))
    }

    fn symlink(&self, target: &Path, link: &Path) -> Result<()> {
        let t = target.to_string_lossy().into_owned();
        let l = self.root.join(link).to_string_lossy().into_owned();
        let parent = Path::new(&l)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());
        let cmd = format!(
            "mkdir -p {parent} && ln -sfn {t} {l}",
            parent = shell_quote(&parent),
            t = shell_quote(&t),
            l = shell_quote(&l),
        );
        self.run_remote_ok(&cmd)
    }

    fn read_link(&self, rel: &Path) -> Result<PathBuf> {
        let p = self.root.join(rel).to_string_lossy().into_owned();
        let out = self.run_remote(&Self::argv_cmd(&["readlink".into(), p]))?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh readlink failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        let target = String::from_utf8_lossy(&out.stdout).trim().to_string();
        Ok(PathBuf::from(target))
    }

    fn remove_file(&self, rel: &Path) -> Result<()> {
        let p = self.root.join(rel).to_string_lossy().into_owned();
        // Ignore "not found".
        let out = self.run_remote(&Self::argv_cmd(&["rm".into(), "-f".into(), p]))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !stderr.contains("No such file") && !stderr.contains("No such") {
                return Err(Error::transport(format!("ssh rm failed: {stderr}")));
            }
        }
        Ok(())
    }

    fn remove_file_if(&self, rel: &Path, expected: &[u8]) -> Result<RemoveIfVerdict> {
        let cmd = Self::remove_file_if_cmd(&self.root, rel, expected);
        let out = self.run_remote(&cmd)?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh remove_file_if failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        match String::from_utf8_lossy(&out.stdout).trim() {
            "R" => Ok(RemoveIfVerdict::Removed),
            "M" => Ok(RemoveIfVerdict::Mismatch),
            "A" => Ok(RemoveIfVerdict::Absent),
            other => Err(Error::transport(format!(
                "ssh remove_file_if: malformed verdict frame {other:?}"
            ))),
        }
    }

    fn remove_dir_all(&self, rel: &Path) -> Result<()> {
        let p = self.root.join(rel).to_string_lossy().into_owned();
        self.run_remote_ok(&Self::argv_cmd(&["rm".into(), "-rf".into(), p]))
    }

    fn exists(&self, rel: &Path) -> bool {
        let p = self.root.join(rel).to_string_lossy().into_owned();
        let out = self.run_remote(&Self::argv_cmd(&["test".into(), "-e".into(), p]));
        matches!(out, Ok(o) if o.status.success())
    }

    fn metadata(&self, rel: &Path) -> Result<RemoteMeta> {
        self.metadata_opt(rel)?.ok_or_else(|| {
            Error::NotFound(format!(
                "ssh stat {}: no such entry",
                self.root.join(rel).to_string_lossy()
            ))
        })
    }

    fn metadata_opt(&self, rel: &Path) -> Result<Option<RemoteMeta>> {
        // ONE remote exec: the framed perl `lstat` helper reports the OUTCOME
        // WITH THE ERRNO (a `P`/`A`/`E` frame on stdout, exit 0 for every
        // outcome). The frame is the signal — no shell booleans, no reserved
        // exit code — so a permission failure (EACCES) can never be mistaken
        // for absence. A transport failure, a signal-killed command, or any
        // nonzero exit is an error; the single stdout frame is parsed
        // strictly (malformed output is never a silent default).
        let out = self.run_remote(&self.lstat_script(rel))?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh lstat failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Self::parse_lstat_frame(&String::from_utf8_lossy(&out.stdout))
    }

    fn exec(
        &self,
        argv: &[String],
        timeout: Duration,
    ) -> Result<crate::remote::transport::ExecOutcome> {
        if argv.is_empty() {
            return Err(Error::transport("empty command"));
        }
        // Preserve argv boundaries: quote every argument and run them via `exec`
        // so the program receives exactly `argv` and the remote shell cannot
        // reinterpret spaces/metacharacters inside an argument.
        let command = format!("exec {}", Self::argv_cmd(argv));
        let mut full = vec!["ssh".to_string()];
        full.extend(self.ssh_args()?);
        full.push("--".into());
        full.push(command);
        // Runs through THE shared runner with the caller-supplied timeout: on
        // deadline the child is killed and reaped (deterministically) before the
        // Timeout outcome is returned, so `exec` can never hang the push either.
        match self.runner.run(OpKind::Exec, &full, None, Some(timeout)) {
            Ok(out) => Ok(crate::remote::transport::ExecOutcome {
                exit_code: out.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            }),
            Err(RunError::Spawn(m)) => Err(Error::transport(m)),
            Err(RunError::StdinWrite(m)) => Err(Error::transport(m)),
            Err(RunError::Wait(m)) => Err(Error::transport(m)),
            Err(RunError::Timeout { after }) => Ok(crate::remote::transport::ExecOutcome {
                exit_code: -1,
                stdout: String::new(),
                stderr: format!("timed out after {after:?}"),
            }),
        }
    }

    fn filesystem_bytes(&self) -> Result<FsBytes> {
        let p = self.root.to_string_lossy().into_owned();
        let out = self.run_remote(&Self::argv_cmd(&["df".into(), "-kP".into(), p]))?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh df failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let line = text
            .lines()
            .nth(1)
            .ok_or_else(|| Error::transport("unexpected ssh df output".to_string()))?;
        let cols: Vec<&str> = line.split_whitespace().collect();
        // blocks is the 2nd column and avail the 4th (1-indexed) on both
        // macOS and Linux; both are in 1024-byte units.
        let total_kb = cols
            .get(1)
            .and_then(|c| c.parse::<u64>().ok())
            .ok_or_else(|| Error::transport("could not parse ssh df blocks".to_string()))?;
        let avail_kb = cols
            .get(3)
            .and_then(|c| c.parse::<u64>().ok())
            .ok_or_else(|| Error::transport("could not parse ssh df avail".to_string()))?;
        Ok(FsBytes {
            total: total_kb * 1024,
            available: avail_kb * 1024,
        })
    }

    fn try_write_new(&self, rel: &Path, data: &[u8]) -> Result<CreateNewVerdict> {
        self.try_write_new_with(rel, data, ContentEquivalence::Exact)
    }

    fn try_write_new_with(
        &self,
        rel: &Path,
        data: &[u8],
        equivalence: ContentEquivalence,
    ) -> Result<CreateNewVerdict> {
        let cmd = Self::write_new_cmd(&self.root, rel, IMMUTABLE_RECORD_MODE);
        let mut argv = vec!["ssh".to_string()];
        argv.extend(self.ssh_args()?);
        argv.push("--".into());
        argv.push(cmd);
        // The payload travels through the runner's STDIN — never through the
        // command string (see `write_new_cmd`): the raw `data` bytes are
        // piped to the remote `cat > "$tmp"` exactly, so arbitrary `Vec<u8>`
        // (NULs, non-UTF8, quotes, shell metacharacters, long payloads)
        // round-trips byte-for-byte through the ssh transport — the same
        // byte-preserving contract the LOCAL transport delivers via
        // `durable_create_new`. The runner pipes the payload as part of the
        // bounded wait, so a remote that stops reading stdin is killed at the
        // command deadline like any other stalled operation.
        let out = self
            .runner
            .run(OpKind::Upload, &argv, Some(data), None)
            .map_err(|e| match e {
                RunError::Spawn(m) => Error::transport(format!("ssh try_write_new spawn: {m}")),
                RunError::StdinWrite(m) => {
                    Error::transport(format!("ssh try_write_new stdin write: {m}"))
                }
                RunError::Wait(m) => Error::transport(format!("ssh try_write_new wait: {m}")),
                RunError::Timeout { after } => {
                    Error::transport(format!("ssh try_write_new timed out after {after:?}"))
                }
            })?;
        if out.status.success() {
            // All seven steps completed: the record is installed with the
            // final mode and a parent-directory-sync'd durable entry.
            return Ok(CreateNewVerdict::Created);
        }
        // A pre-install failure (the temp allocation, the payload write, the
        // final chmod, or the file fsync) or the final parent-dir sync failure
        // exits with a code other than the reserved conflict code: the
        // operation never reached (or never finished) the publish decision
        // point, so this is a propagated ERROR — never a verdict. The
        // transport never guesses the destination's state from a failed
        // pre-install.
        if out.status.code() != Some(SSH_TWRITE_CONFLICT_EXIT) {
            return Err(Error::transport(format!(
                "ssh try_write_new failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        // CONFIRMED EEXIST: the no-clobber publish (perl `link(2)`) found
        // the destination already present — the verdict decision point. The
        // winner is NEVER replaced.
        // VERIFY the existing entry through THE ONE CENTRALIZED lstat-based
        // verification ([`crate::remote::transport::verify_existing`] — the
        // `metadata_opt` perl-lstat protocol is the symlink-safe `lstat` form,
        // so a symlink is never followed): a regular file with the EXACT
        // required mode and the caller's accepted content equivalence →
        // AlreadyPresent (and the PARENT DIRECTORY is synced here, so the
        // convergent retry returns with a durable entry — the same
        // parent-sync guarantee a fresh Created install gets); every other
        // outcome → Conflict carrying the TYPED reason (a different-content
        // winner, a mode mismatch, a directory/symlink/other entry, an
        // unreadable entry — never an undifferentiated conflict).
        let verified = verify_existing(
            || self.metadata_opt(rel),
            || self.read(rel),
            data,
            IMMUTABLE_RECORD_MODE,
            equivalence,
        )?;
        let verdict = verified_to_verdict(verified);
        if let CreateNewVerdict::AlreadyPresent = &verdict {
            let remote_path_str = self.root.join(rel).to_string_lossy().into_owned();
            let parent = Path::new(&remote_path_str)
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| ".".to_string());
            self.run_remote_ok(&format!("sync {}", shell_quote(&parent)))?;
            return Ok(CreateNewVerdict::AlreadyPresent);
        }
        Ok(verdict)
    }
}

#[cfg(test)]
mod tests_ssh {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    /// The unit tests construct transports with a dummy cache dir + a process
    /// snapshot: they never pin (a known_hosts file is always configured), so
    /// neither the cache path nor the snapshot's contents matter.
    fn test_env() -> SysEnv {
        SysEnv::from_process()
    }

    fn transport() -> SshTransport {
        // Use a (dummy) known_hosts file so `new` does not attempt a live
        // ssh-keyscan pin; the unit tests below only exercise command
        // construction and list parsing, not real key pinning.
        SshTransport::new(
            "deploy",
            "db.example.com",
            2222,
            Path::new("/srv/app"),
            Some(Path::new("/dev/null")),
            None,
            Path::new("/tmp/deploy-ssh-knownhosts-unit"),
            &test_env(),
        )
        .unwrap()
    }

    // Host identity must be EXACTLY ONE source: both set is ambiguous, neither
    // set is trust-on-first-use (disabled). Construction fails closed on both.
    #[test]
    fn new_rejects_root_deploy_dir() {
        // The filesystem root is refused at construction (defense in depth,
        // mirroring the AbsoluteDeployDir parse rule): a transport rooted
        // at `/` would make the deployment cleanup operate on the system
        // root.
        let err = SshTransport::new(
            "deploy",
            "db.example.com",
            2222,
            Path::new("/"),
            Some(Path::new("/dev/null")),
            None,
            Path::new("/tmp/deploy-ssh-knownhosts-unit"),
            &test_env(),
        )
        .err()
        .expect("the filesystem root must be refused as a deploy_dir");
        assert!(
            err.to_string()
                .contains("at least one normal path component"),
            "error must name the rule, got: {err}"
        );
    }

    #[test]
    fn new_rejects_both_identity_sources() {
        let err = SshTransport::new(
            "deploy",
            "db.example.com",
            2222,
            Path::new("/srv/app"),
            Some(Path::new("/etc/ssh/known_hosts")),
            Some("SHA256:abc"),
            Path::new("/tmp/deploy-ssh-knownhosts-unit"),
            &test_env(),
        )
        .err()
        .expect("both identity sources must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("exactly one of known_hosts or host_key_fingerprint")
                && msg.contains("both are set"),
            "error must explain the ambiguity, got: {msg}"
        );
    }

    #[test]
    fn new_rejects_missing_identity() {
        let err = SshTransport::new(
            "deploy",
            "db.example.com",
            2222,
            Path::new("/srv/app"),
            None,
            None,
            Path::new("/tmp/deploy-ssh-knownhosts-unit"),
            &test_env(),
        )
        .err()
        .expect("missing identity must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("exactly one of `known_hosts` or `host_key_fingerprint`")
                && msg.contains("trust-on-first-use is disabled"),
            "error must refuse trust-on-first-use, got: {msg}"
        );
    }

    #[test]
    fn ssh_args_carries_port() {
        let t = transport();
        let args = t.ssh_args().unwrap();
        let p = args.iter().position(|a| a == "-p").unwrap();
        assert_eq!(args[p + 1], "2222");
        // The ssh connection target keeps the user@host form.
        assert!(args.iter().any(|a| a == "deploy@db.example.com"));
    }

    // The fixed ssh arguments must bound the connection phase: a dead or
    // unreachable host aborts after `SSH_CONNECT_TIMEOUT_SECS` instead of
    // hanging the transport indefinitely.
    #[test]
    fn ssh_args_carries_connect_timeout() {
        let t = transport();
        let args = t.ssh_args().unwrap();
        assert!(
            args.windows(2).any(|w| {
                w[0] == "-o" && w[1] == format!("ConnectTimeout={SSH_CONNECT_TIMEOUT_SECS}")
            }),
            "ssh args must carry -o ConnectTimeout={}, got: {args:?}",
            SSH_CONNECT_TIMEOUT_SECS
        );
    }

    // Finding 3: `.` and `..` are excluded, and real modes are preserved.
    #[test]
    fn list_excludes_dot_entries_and_keeps_modes() {
        // name<TAB>type<TAB>rawmode_hex; 0o81ed = 100755 (executable), 0o81a4 = 100644.
        let out = "app\tfff\t81ed\n.\td\t41ed\n..\td\t41ed\nhidden\tl\t41ed\nreadme\tf\t81a4\n";
        let entries = SshTransport::parse_list_output(out);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(!names.contains(&"."), ". must be excluded");
        assert!(!names.contains(&".."), ".. must be excluded");
        assert!(names.contains(&"app"));
        assert!(names.contains(&"hidden"));
        assert!(names.contains(&"readme"));

        let app = entries.iter().find(|e| e.name == "app").unwrap();
        assert!(!app.is_dir && !app.is_symlink);
        assert_eq!(app.mode, 0o755, "executable mode preserved");
        let readme = entries.iter().find(|e| e.name == "readme").unwrap();
        assert_eq!(readme.mode, 0o644, "file mode preserved");
        let hidden = entries.iter().find(|e| e.name == "hidden").unwrap();
        assert!(hidden.is_symlink, "symlink type preserved");
    }

    // Finding 3: the list script covers hidden files/executables/symlinks and
    // never emits `.`/`..`.
    #[test]
    fn list_script_excludes_self_and_parent() {
        let t = transport();
        let script = t.list_script(Path::new("objects/sha256/abc/root"));
        assert!(script.contains(".[!.]*"), "hidden entries covered");
        assert!(script.contains("..?*"), "dot-dot-prefixed entries covered");
        // The self/parent directors are explicitly skipped.
        assert!(script.contains("continue"), "skip guard present");
    }

    // Finding 4: try_write_new creates the parent directory before the
    // noclobber install, so a fresh remote root can host the first lock.
    #[test]
    fn try_write_new_creates_parent_dir() {
        let t = transport();
        let cmd = SshTransport::write_new_cmd(
            t.root(),
            &crate::remote::layout::operation_lock(),
            IMMUTABLE_RECORD_MODE,
        );
        assert!(
            cmd.starts_with("mkdir -p '/srv/app/state'"),
            "parent directory is created first, got: {cmd}"
        );
        // ... and the remote allocation happens only after the parent exists.
        let mkdir_end = cmd.find("&&").unwrap();
        assert!(
            cmd[mkdir_end..].contains("mktemp"),
            "mktemp allocation must follow mkdir -p, got: {cmd}"
        );
    }

    // The `current` swap replaces a symlink-to-directory in place; GNU mv
    // would otherwise treat that destination as the directory itself and move
    // the temp link INTO it (silently polluting the object store). `-T` is
    // mandatory.
    #[test]
    fn rename_uses_no_target_directory_flag() {
        let t = transport();
        let cmd = SshTransport::rename_cmd(
            t.root(),
            Path::new(".current.tmp.op-x"),
            crate::remote::layout::current(),
        );
        assert!(
            cmd.contains("mv -T"),
            "rename must use mv -T (no-target-directory) so a symlink-to-dir destination is replaced, got: {cmd}"
        );
        assert!(
            cmd.ends_with("'/srv/app/current'"),
            "destination is the deployment root's `current` symlink, got: {cmd}"
        );
    }

    /// The remote compare-and-delete script (`remove_file_if_cmd`), executed
    /// locally with `sh -c`: it CLAIMS the entry with `mv`, deletes it on a
    /// byte match (frame `R`), RESTORES it no-replace on mismatch (frame `M`
    /// — the winner survives byte-for-byte), and reports genuine absence
    /// (frame `A`).
    #[test]
    fn remove_file_if_script_frames() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let root = dir.path().join("remote");
        let rel = Path::new("state/operation.lock");
        let payload = "{\"owner\":\"a\",\"token\":1,\"expires_at_ms\":1700000000000}";

        // Genuinely absent: the Absent frame.
        let cmd = SshTransport::remove_file_if_cmd(&root, rel, payload.as_bytes());
        let out = run_sh_stdin(&cmd, &[]);
        assert!(out.status.success(), "script must exit 0: {out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "A");

        // Install the record, then remove on a byte match: the Removed frame
        // and the entry is gone.
        std::fs::create_dir_all(root.join("state")).unwrap();
        std::fs::write(root.join(rel), payload).unwrap();
        let out = run_sh_stdin(&cmd, &[]);
        assert!(out.status.success(), "script must exit 0: {out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "R");
        assert!(
            !root.join(rel).exists(),
            "the matched entry must be removed"
        );

        // Reinstall, then compare against a DIFFERENT expected record: the
        // Mismatch frame and the entry is restored byte-for-byte.
        std::fs::write(root.join(rel), payload).unwrap();
        let cmd2 = SshTransport::remove_file_if_cmd(&root, rel, b"{\"owner\":\"b\",\"token\":2}");
        let out = run_sh_stdin(&cmd2, &[]);
        assert!(out.status.success(), "script must exit 0: {out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "M");
        assert_eq!(
            std::fs::read(root.join(rel)).unwrap(),
            payload.as_bytes(),
            "the mismatch must restore the winner byte-for-byte"
        );
    }

    // The unique temp file for the durability protocol must live INSIDE the
    // destination's parent directory and be dot-prefixed (mirroring
    // LocalTransport), never a sibling of the parent: a sibling name would
    // escape the managed remote root whenever the destination's parent IS the
    // deployment root. The name is allocated remotely by `mktemp`, so the
    // XXXXXX template suffix must survive quoting verbatim.
    #[test]
    fn try_write_new_temp_is_dot_prefixed_inside_destination_parent() {
        let t = transport();
        let cmd = SshTransport::write_new_cmd(
            t.root(),
            &crate::remote::layout::operation_lock(),
            IMMUTABLE_RECORD_MODE,
        );
        assert!(
            cmd.contains("mktemp '/srv/app/state/.operation.lock.tmp.XXXXXX'"),
            "temp must be inside the destination parent, dot-prefixed, and mktemp-allocated, got: {cmd}"
        );
        assert!(
            !cmd.contains("/srv/app.state.operation.lock"),
            "temp must not be a dot-sibling of the destination parent, got: {cmd}"
        );
        assert!(
            !cmd.contains("/srv/app/.state.operation.lock"),
            "temp must not leak above the destination parent, got: {cmd}"
        );
        assert!(
            cmd.contains(".tmp.XXXXXX"),
            "mktemp template must carry XXXXXX at the end of the last component, got: {cmd}"
        );
    }

    // Regression: when the destination sits directly in the deployment root,
    // the old sibling naming (`{root}.{basename}.tmp...`) placed the temp OUTSIDE
    // the managed root entirely.
    #[test]
    fn try_write_new_temp_stays_inside_root_for_root_level_dest() {
        let t = transport();
        let cmd = SshTransport::write_new_cmd(t.root(), Path::new("files"), IMMUTABLE_RECORD_MODE);
        assert!(
            cmd.contains("mktemp '/srv/app/.files.tmp.XXXXXX'"),
            "temp for a root-level destination must stay inside the root, got: {cmd}"
        );
        assert!(
            !cmd.contains("/srv.files.tmp."),
            "temp must not escape the managed root, got: {cmd}"
        );
    }

    /// Execute `sh -c "$command"` with `stdin` piped to the shell — the
    /// payload the remote script's `cat > "$tmp"` consumes, exactly as the
    /// transport pipes it through the ssh child (never embedded in the
    /// command string).
    fn run_sh_stdin(command: &str, stdin: &[u8]) -> std::process::Output {
        use std::io::Write;
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn sh -c");
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(stdin)
            .expect("write payload");
        child.wait_with_output().expect("wait sh -c")
    }

    // The old temp name derived from the LOCAL pid + a per-process counter, so
    // two controllers on different hosts could share a pid and collide on the
    // same remote temp name; `printf ... > tmp` then truncated the collided
    // path, and the no-clobber publish could install the WRONG payload. With
    // remote `mktemp` allocation, concurrent controllers can never be handed
    // the same name: exactly one install wins, every loser reports failure,
    // and no reader ever observes torn/mixed content.
    #[test]
    fn try_write_new_concurrent_controllers_never_collide() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let root = dir.path().to_path_buf();
        let rel = Path::new("state/op.json");
        let dest = root.join(rel);
        let payloads: Vec<String> = (0..8)
            .map(|i| format!("payload-{i}:{}", "x".repeat(64 + i * 7)))
            .collect();

        std::thread::scope(|s| {
            let done = Arc::new(AtomicBool::new(false));

            // Writers: every controller runs the exact generated command for
            // the same destination with a different payload.
            let mut writers = Vec::new();
            for payload in &payloads {
                let cmd = SshTransport::write_new_cmd(&root, rel, IMMUTABLE_RECORD_MODE);
                let payload = payload.clone();
                writers.push(s.spawn(move || run_sh_stdin(&cmd, payload.as_bytes())));
            }

            // Readers: while the writers race, any observation of the
            // destination must be a complete payload — never torn, empty, or
            // mixed. Dot-prefixed temp names are what listing-based observers
            // skip, exactly as in LocalTransport::try_write_new.
            let done2 = done.clone();
            let parent = dest.parent().unwrap().to_path_buf();
            let payloads2 = payloads.clone();
            let dest3 = dest.clone();
            s.spawn(move || {
                while !done2.load(Ordering::SeqCst) {
                    let Ok(entries) = std::fs::read_dir(&parent) else {
                        continue;
                    };
                    for e in entries.flatten() {
                        let name = e.file_name().to_string_lossy().into_owned();
                        if name != "op.json" {
                            assert!(
                                name.starts_with('.'),
                                "observer must only ever see the final name or dot-prefixed temps, got {name}"
                            );
                            continue;
                        }
                        let data = std::fs::read(&dest3).unwrap_or_default();
                        assert!(
                            payloads2.iter().any(|p| p.as_bytes() == data),
                            "reader observed a torn/mixed/partial record: {:?}",
                            String::from_utf8_lossy(&data)
                        );
                    }
                }
            });

            let results: Vec<std::process::Output> =
                writers.into_iter().map(|h| h.join().unwrap()).collect();
            done.store(true, Ordering::SeqCst);

            // Exactly one controller installs; every other reports failure.
            let wins = results.iter().filter(|r| r.status.success()).count();
            assert_eq!(
                wins, 1,
                "exactly one concurrent controller must win the no-clobber install"
            );
            let data = std::fs::read(&dest).unwrap();
            assert!(
                payloads.iter().any(|p| p.as_bytes() == data),
                "installed content must be one complete payload, got {:?}",
                String::from_utf8_lossy(&data)
            );
        });
    }

    // Recovery: a controller crashed AFTER `ln` but BEFORE `rm -f "$tmp"`,
    // leaving the destination installed plus a stale hard-linked temp (nlink
    // 2) in the same name space. A fresh invocation must allocate a DIFFERENT
    // temp name, never touch the stale temp or the installed destination, and
    // remove only its own temp.
    #[test]
    fn try_write_new_recovers_from_stale_hardlinked_temp() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let root = dir.path().to_path_buf();
        let rel = Path::new("state/op.json");
        let dest = root.join(rel);
        let parent = dest.parent().unwrap();

        // First invocation: installs the record and cleans up its own temp.
        let cmd1 = SshTransport::write_new_cmd(&root, rel, IMMUTABLE_RECORD_MODE);
        let out1 = run_sh_stdin(&cmd1, b"gen-1");
        assert!(
            out1.status.success(),
            "first install failed: {}",
            String::from_utf8_lossy(&out1.stderr)
        );
        assert_eq!(std::fs::read(&dest).unwrap(), b"gen-1");
        let temps = || {
            std::fs::read_dir(parent)
                .unwrap()
                .flatten()
                .filter(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    n != "op.json"
                })
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        assert!(temps().is_empty(), "first invocation left temps behind");

        // Crash AFTER `ln` but BEFORE `rm -f "$tmp"`: the stale temp is a
        // second hard link to the installed inode (nlink 2), sitting in the
        // same name space a future mktemp draws from.
        let stale = parent.join(".op.json.tmp.crashed");
        std::fs::hard_link(&dest, &stale).unwrap();
        let stale_meta = std::fs::metadata(&stale).unwrap();
        assert_eq!(
            stale_meta.nlink(),
            2,
            "stale temp must hard-link the installed inode"
        );

        // Fresh invocation with a different payload: must fail (already
        // exists), leave dest and stale untouched, and clean up its own temp.
        let cmd2 = SshTransport::write_new_cmd(&root, rel, IMMUTABLE_RECORD_MODE);
        let out2 = run_sh_stdin(&cmd2, b"gen-2");
        assert_eq!(
            out2.status.code(),
            Some(SSH_TWRITE_CONFLICT_EXIT),
            "reinstall after a winner must exit the reserved conflict code"
        );
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"gen-1",
            "installed destination must stay intact"
        );
        let stale_after = std::fs::metadata(&stale).unwrap();
        assert_eq!(
            stale_after.nlink(),
            2,
            "stale temp must not have been truncated or removed"
        );
        assert_eq!(
            std::fs::read(&stale).unwrap(),
            b"gen-1",
            "stale temp content must be untouched"
        );
        let left = temps();
        assert_eq!(
            left,
            vec![stale.file_name().unwrap().to_string_lossy().into_owned()],
            "only the stale temp may remain; the fresh invocation's own temp must be removed"
        );
    }

    /// The remote script implements the canonical seven-step sequence: the
    /// FINAL MODE is chmod'd onto the temp BEFORE the file fsync and the
    /// no-clobber install, and the PARENT-DIRECTORY sync is a real
    /// `sync <dir>` whose failure is never swallowed (`2>/dev/null` is gone).
    #[test]
    fn try_write_new_cmd_final_chmod_and_real_parent_sync() {
        let t = transport();
        let cmd =
            SshTransport::write_new_cmd(t.root(), &crate::remote::layout::operation_lock(), 0o640);
        // Step 3 (final chmod) BEFORE step 4 (file fsync) BEFORE step 5
        // (no-replace install): the published inode carries the caller's
        // mode, never the remote umask.
        let chmod_pos = cmd
            .find("chmod 640 \"$tmp\"")
            .expect("the final chmod step must be present");
        let fsync_pos = cmd
            .find("sync \"$tmp\"")
            .expect("the file fsync step must be present");
        let publish_pos = cmd
            .find("link($ARGV[0], $ARGV[1])")
            .expect("the no-replace install must be present");
        assert!(
            chmod_pos < fsync_pos && fsync_pos < publish_pos,
            "step order must be chmod -> file fsync -> install, got: {cmd}"
        );
        // Step 7: a real `sync <dir>` — and no `2>/dev/null` swallow.
        assert!(
            cmd.contains("sync '/srv/app/state'"),
            "the parent-dir sync must be a real sync <dir>, got: {cmd}"
        );
        assert!(
            !cmd.contains("2>/dev/null"),
            "the parent-dir sync failure must never be swallowed, got: {cmd}"
        );
    }

    /// The final chmod step is EXECUTED before the install: under a
    /// restrictive umask the published record still carries the intended
    /// mode, never the umask-derived one.
    #[test]
    fn try_write_new_installs_final_mode_not_umask() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let root = dir.path().to_path_buf();
        let rel = Path::new("state/op.json");
        let cmd = SshTransport::write_new_cmd(&root, rel, 0o644);
        // `mktemp` under umask 077 creates the temp 0600; without the chmod
        // step the installed record would keep 0600. The final chmod must
        // make it 0644 before the install. The payload is piped on stdin,
        // exactly as the transport delivers it.
        let out = run_sh_stdin(&format!("umask 077; {cmd}"), b"payload-data");
        assert!(
            out.status.success(),
            "install failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let meta = std::fs::metadata(root.join(rel)).unwrap();
        assert_eq!(
            meta.mode() & 0o7777,
            0o644,
            "the published record must carry the intended final mode, not the umask"
        );
        assert_eq!(std::fs::read(root.join(rel)).unwrap(), b"payload-data");
    }

    /// The parent-directory sync failure PROPAGATES: a fake `sync` on PATH
    /// that fsyncs regular files but fails on directories lets the file fsync
    /// (step 4) pass, then the parent-dir sync (step 7) fails — the command
    /// exits with the fake sync's status, never a swallowed success. The old
    /// `sync 2>/dev/null` was exactly this bug.
    #[test]
    fn try_write_new_parent_sync_failure_propagates() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let root = dir.path().to_path_buf();
        let rel = Path::new("state/op.json");
        let cmd = SshTransport::write_new_cmd(&root, rel, IMMUTABLE_RECORD_MODE);
        let fakebin = dir.path().join("fakebin");
        std::fs::create_dir_all(&fakebin).unwrap();
        std::fs::write(
            fakebin.join("sync"),
            "#!/bin/sh\nif [ -d \"$1\" ]; then echo 'sync: dir sync failed' >&2; exit 9; fi\nexit 0\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(fakebin.join("sync"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        let out = run_sh_stdin(
            &format!(
                "PATH={fake}:$PATH; {cmd}",
                fake = shell_quote(&fakebin.to_string_lossy())
            ),
            b"payload-data",
        );
        assert_eq!(
            out.status.code(),
            Some(9),
            "the parent-dir sync failure must propagate (never swallowed)"
        );
        // The install itself succeeded (ln ran) — the propagated failure is
        // EXACTLY the final durability step, and the record is complete.
        assert_eq!(
            std::fs::read(root.join(rel)).unwrap(),
            b"payload-data",
            "the record must be fully installed before the parent-dir sync"
        );
    }

    /// The no-clobber conflict is reported through the reserved exit code and
    /// NEVER replaces the winner: a second invocation with different content
    /// exits `SSH_TWRITE_CONFLICT_EXIT` and the winner's bytes stay intact.
    #[test]
    fn try_write_new_conflict_exits_reserved_code_and_never_replaces() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let root = dir.path().to_path_buf();
        let rel = Path::new("state/op.json");
        let cmd1 = SshTransport::write_new_cmd(&root, rel, IMMUTABLE_RECORD_MODE);
        let out1 = run_sh_stdin(&cmd1, b"gen-1");
        assert!(
            out1.status.success(),
            "first install failed: {}",
            String::from_utf8_lossy(&out1.stderr)
        );
        let cmd2 = SshTransport::write_new_cmd(&root, rel, IMMUTABLE_RECORD_MODE);
        let out2 = run_sh_stdin(&cmd2, b"gen-2");
        assert_eq!(
            out2.status.code(),
            Some(SSH_TWRITE_CONFLICT_EXIT),
            "a loser must exit the reserved conflict code"
        );
        assert_eq!(
            std::fs::read(root.join(rel)).unwrap(),
            b"gen-1",
            "the conflict must NEVER replace the winner"
        );
    }

    /// The stage-failure dimension of the ssh protocol: a failure at EVERY
    /// script-failable stage must exit with a code that is NEITHER 0 NOR the
    /// reserved conflict verdict — a pre-install failure or a real publish/
    /// sync failure is a propagated ERROR, never a verdict (the verdict is
    /// ONLY a CONFIRMED EEXIST at the no-clobber publish). `Unlink` is not
    /// script-failable (`rm -f` is best-effort cleanup by design); that crash
    /// point is covered by the local primitive's `FailAt(Unlink)` case and by
    /// `try_write_new_recovers_from_stale_hardlinked_temp`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SshStageFailure {
        /// `mktemp` fails — the temp allocation (step 1).
        CreateTemp,
        /// The payload write fails — a fake `mktemp` hands back an unwritable
        /// path so the `cat > "$tmp"` redirect fails to open (step 2; the
        /// redirect is a shell-level error, so a PATH fake cannot shadow it —
        /// `cat` never runs).
        Write,
        /// `chmod` fails (step 3).
        Chmod,
        /// `sync "$tmp"` fails (step 4).
        FileFsync,
        /// `ln` fails for a reason OTHER than EEXIST (step 5) — with the
        /// destination ABSENT, so the script must NOT call it a verdict. The
        /// publish is perl `link(2)`, so the stage is faulted by a fake
        /// `perl` that exits 1.
        Publish,
        /// `sync <dir>` fails (step 7) — the file sync passes, the
        /// parent-dir sync is the propagated failure.
        ParentFsync,
    }

    fn ssh_stage_failure() -> impl Strategy<Value = SshStageFailure> {
        prop_oneof![
            Just(SshStageFailure::CreateTemp),
            Just(SshStageFailure::Write),
            Just(SshStageFailure::Chmod),
            Just(SshStageFailure::FileFsync),
            Just(SshStageFailure::Publish),
            Just(SshStageFailure::ParentFsync),
        ]
    }

    proptest! {
        // Bounded cases, fixed seed 0x5EED_5EED (house style), no persistence.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn write_new_cmd_stage_failures_propagate(stage in ssh_stage_failure()) {
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let root = dir.path().to_path_buf();
            let rel = Path::new("state/op.json");
            let dest = root.join(rel);
            let cmd = SshTransport::write_new_cmd(&root, rel, IMMUTABLE_RECORD_MODE);
            let fakebin = dir.path().join("fakebin");
            std::fs::create_dir_all(&fakebin).unwrap();

            let (name, body) = match stage {
                SshStageFailure::CreateTemp => ("mktemp", "#!/bin/sh\nexit 1\n"),
                SshStageFailure::Write => (
                    "mktemp",
                    "#!/bin/sh\nprintf '%s\\n' '/definitely/unwritable/.op.json.tmp.XXXXXX'\n",
                ),
                SshStageFailure::Chmod => ("chmod", "#!/bin/sh\nexit 1\n"),
                SshStageFailure::FileFsync => ("sync", "#!/bin/sh\nexit 1\n"),
                SshStageFailure::Publish => ("perl", "#!/bin/sh\nexit 1\n"),
                SshStageFailure::ParentFsync => (
                    "sync",
                    "#!/bin/sh\nif [ -d \"$1\" ]; then echo 'sync: dir sync failed' >&2; exit 9; fi\nexit 0\n",
                ),
            };
            let p = fakebin.join(name);
            std::fs::write(&p, body).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();

            let out = run_sh_stdin(
                &format!(
                    "PATH={fake}:$PATH; {cmd}",
                    fake = shell_quote(&fakebin.to_string_lossy())
                ),
                b"payload-data",
            );
            prop_assert_ne!(
                out.status.code(),
                Some(0),
                "the faulted stage must fail the attempt"
            );
            prop_assert_ne!(
                out.status.code(),
                Some(SSH_TWRITE_CONFLICT_EXIT),
                "a stage failure is NEVER the conflict verdict — the verdict is ONLY a confirmed EEXIST, got: {:?}",
                out.status.code()
            );
            match stage {
                SshStageFailure::ParentFsync => {
                    // The install completed; the failure is EXACTLY the final
                    // durability step, and the record is fully written.
                    prop_assert_eq!(
                        std::fs::read(&dest).unwrap(),
                        b"payload-data",
                        "the parent-sync failure must come after a fully-written install"
                    );
                }
                _ => {
                    prop_assert!(
                        !dest.exists(),
                        "a pre-install/publish failure must install nothing"
                    );
                }
            }
        }
    }
}

/// Fingerprint-only identity tests: a `host_key_fingerprint` with no
/// `known_hosts` file. These tests run the transport against fake
/// `ssh`/`ssh-keyscan`/`stat` executables that emulate a remote host on a local
/// directory, so the real pin-and-connect path is exercised end to end —
/// including the regression: the identity must be prepared BEFORE any status
/// request, otherwise a fingerprint-only transport cannot even build its ssh
/// arguments (and a dry run would be equally broken).
#[cfg(test)]
mod fingerprint_ssh_tests {
    use super::*;
    use crate::remote::helper::{ExpectedCurrent, RemoteHelper};
    use crate::remote::transport::{NotRegularFileKind, VerifiedExisting};
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    // HERMETIC SNAPSHOT: every fake-ssh test builds ONE `SysEnv::from_map`
    // carrying the fake bin dir first in `PATH` plus the fake-ssh variables
    // (`FAKE_SSH_ROOT` / `FAKE_SSH_REMOTE_PREFIX`) and the per-test pin
    // cache (`DEPLOY_SSH_KNOWNHOSTS_DIR`). The transport spawns its children
    // (ssh / ssh-keyscan / ssh-keygen / stat) with that snapshot's variables
    // (`SysEnv::apply_to_command`: env_clear + the snapshot's vars), so the
    // fake binaries resolve and their
    // inputs ride the same child env — the process-global environment is
    // NEVER touched (no lock, no set_var, no cross-test interference).

    struct FakeSsh {
        bin: PathBuf,
        remote_root: PathBuf,
        fingerprint: String,
        deploy_dir: PathBuf,
        address: String,
        keyscan_log: PathBuf,
        /// Every fake-`ssh` invocation's FULL argv (one argument per line, a
        /// `---` separator between invocations) — recorded so a test can
        /// prove a given payload never entered the transmitted command (the
        /// write invocation's argv is byte-for-byte the payload-INDEPENDENT
        /// command string).
        argv_log: PathBuf,
    }

    impl FakeSsh {
        /// Generate a REAL ed25519 host key (never a hardcoded fake), compute
        /// its SHA256 fingerprint, and write fake `ssh`/`ssh-keyscan`/`stat`
        /// executables into `bin` that emulate a remote host rooted at
        /// `remote_root`.
        fn new(bin: PathBuf, remote_root: PathBuf, address: &str, deploy_dir: &Path) -> FakeSsh {
            std::fs::create_dir_all(&bin).unwrap();
            let keyfile = bin.join("hostkey");
            let out = std::process::Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-N", "", "-f"])
                .arg(&keyfile)
                .output()
                .expect("ssh-keygen must be available");
            assert!(out.status.success(), "ssh-keygen failed");
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
            assert!(fp.status.success());
            let fingerprint = String::from_utf8_lossy(&fp.stdout)
                .split_whitespace()
                .nth(1)
                .expect("fingerprint field")
                .to_string();

            let keyscan_log = bin.join("keyscan.log");
            let argv_log = bin.join("ssh-argv.log");

            // Fake `ssh`: parse `-o`/`-p`/`--` like OpenSSH, remap every
            // occurrence of the configured remote deploy dir to the local
            // emulation root, and run the single (fully shell-quoted) remote
            // command with `sh -c`. Every invocation's FULL argv is recorded
            // to `argv_log` (one argument per line, `---` separator) so a
            // test can prove the payload never enters the command string —
            // the recorded argv must be byte-for-byte the payload-INDEPENDENT
            // reference command. The recording block reads no stdin, so the
            // piped payload flows through this shim untouched into the remote
            // `cat > "$tmp"` (the shell execs the command with stdin intact).
            std::fs::write(
                bin.join("ssh"),
                format!(
                    r##"#!/bin/sh
# Fake `ssh` for tests: emulates a remote host whose filesystem is a local
# directory. `FAKE_SSH_ROOT` is the local dir; `FAKE_SSH_REMOTE_PREFIX` is the
# configured remote deploy dir (e.g. /srv/deploy/app). Every occurrence of the
# remote prefix in the (fully shell-quoted) remote command is remapped to
# $FAKE_SSH_ROOT$FAKE_SSH_REMOTE_PREFIX, then the command runs with `sh -c`.
# The piped stdin payload is inherited untouched (no -n, no stdin reads here).
FAKE_ROOT="${{FAKE_SSH_ROOT:?FAKE_SSH_ROOT not set}}"
REMOTE_PREFIX="${{FAKE_SSH_REMOTE_PREFIX:?FAKE_SSH_REMOTE_PREFIX not set}}"
{{
  printf '%s\n' "$0"
  for a in "$@"; do
    printf '%s\n' "$a"
  done
  printf '%s\n' '---'
}} >> '{argv_log}'
cmd=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) shift 2 ;;
    -p) shift 2 ;;
    --) shift; cmd="$*"; break ;;
    *) shift ;;
  esac
done
[ -n "$cmd" ] || exit 0
remapped=$(printf '%s' "$cmd" | awk -v old="$REMOTE_PREFIX" -v new="$FAKE_ROOT$REMOTE_PREFIX" '{{ gsub(old, new); printf "%s", $0 }}')
exec sh -c "$remapped"
"##,
                    argv_log = argv_log.display(),
                ),
            )
            .unwrap();

            // Fake ssh-keyscan: record every invocation (so tests can prove the
            // cached pin is reused) and answer with the generated host key.
            std::fs::write(
                bin.join("ssh-keyscan"),
                format!(
                    r#"#!/bin/sh
printf 'keyscan\n' >> '{log}'
host=""
while [ $# -gt 0 ]; do
  case "$1" in
    -p) shift 2 ;;
    -T) shift 2 ;;
    -t) shift 2 ;;
    -*) shift ;;
    *) host="$1"; shift ;;
  esac
done
[ -n "$host" ] || host='{address}'
printf '%s %s\n' "$host" '{pubkey}'
"#,
                    log = keyscan_log.display(),
                    address = address,
                    pubkey = pubkey,
                ),
            )
            .unwrap();

            // Fake `stat` emulating GNU coreutils `-c` (macOS stat lacks it):
            // the transport's list script uses `stat -c '%f'` (raw mode in
            // hex). The metadata path no longer calls `stat` at all — it runs
            // the framed perl `lstat` helper directly — so the shim's `%s %f`
            // branch implements the SAME framed protocol (P/A/E frames from a
            // REAL lstat errno; a missing path reports `A\t2`), keeping the
            // fixture faithful for any caller that still formats through
            // `stat`. `/usr/bin/perl` (absolute) is used so an injected fake
            // `perl` in the test bin dir never shadows the shim's interpreter.
            std::fs::write(
                bin.join("stat"),
                r#"#!/bin/sh
fmt=""
while [ $# -gt 0 ]; do
  case "$1" in
    -c) fmt="$2"; shift 2 ;;
    -L) shift ;;
    -*) shift ;;
    *) break ;;
  esac
done
case "$fmt" in
  "%f")
    /usr/bin/perl -e 'my @s = lstat($ARGV[0]); printf "%x\n", $s[2] & 0xffff;' "$1"
    ;;
  "%s %f")
    /usr/bin/perl -e 'my @s = lstat($ARGV[0]); if (@s) { printf "P\t%s\t%x\n", $s[7], $s[2] & 0xffff; exit 0; } my $e = $! + 0; print(($e == 2 || $e == 20) ? "A\t$e\n" : "E\t$e\n");' "$1"
    ;;
  *)
    exec /usr/bin/stat "$@"
    ;;
esac
"#,
            )
            .unwrap();

            // Fake `mv` emulating GNU coreutils `mv -T` (no-target-directory):
            // macOS BSD mv lacks `-T` and, like GNU mv without `-T`, treats a
            // destination that is a symlink to a directory as the directory
            // itself and moves the source INTO it. The deploy tool's `current`
            // swap depends on GNU `-T` semantics, so strip the flag and remove
            // any existing destination first.
            std::fs::write(
                bin.join("mv"),
                r#"#!/bin/sh
if [ "$1" = "-T" ]; then
  shift
  src="$1"; dst="$2"
  if [ -n "$src" ] && [ -n "$dst" ]; then
    rm -f -- "$dst"
  fi
  exec /bin/mv -- "$src" "$dst"
fi
exec /bin/mv "$@"
"#,
            )
            .unwrap();

            use std::os::unix::fs::PermissionsExt;
            for name in ["ssh", "ssh-keyscan", "stat", "mv"] {
                let p = bin.join(name);
                let mut perms = std::fs::metadata(&p).unwrap().permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&p, perms).unwrap();
            }

            FakeSsh {
                bin,
                remote_root,
                fingerprint,
                deploy_dir: deploy_dir.to_path_buf(),
                address: address.to_string(),
                keyscan_log,
                argv_log,
            }
        }

        /// A fingerprint-only `SshTransport` (no `known_hosts`) rooted at
        /// `self.deploy_dir`, pinning into the per-test `cache` dir with the
        /// hermetic snapshot `env` (the fake ssh binaries resolve from its
        /// `PATH`).
        fn transport(&self, cache: &Path, env: &SysEnv) -> SshTransport {
            SshTransport::new(
                "deploy",
                &self.address,
                2222,
                &self.deploy_dir,
                None,
                Some(self.fingerprint.as_str()),
                cache,
                env,
            )
            .unwrap()
        }
    }

    /// Build the hermetic fake-ssh snapshot: `bin` prepended to the ambient
    /// `PATH`, the per-test pin `cache`, and the fake-ssh variables. The
    /// transport's children receive exactly these variables — the process
    /// env is never mutated, so no two tests (in any binary) can interfere.
    fn fake_env(bin: &Path, cache: &Path, root: &Path, prefix: &str) -> SysEnv {
        let base = crate::testutil::fixture_env();
        let mut vars: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> =
            base.child_env().into_iter().collect();
        let mut paths: Vec<_> = base
            .path()
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default();
        paths.insert(0, bin.to_path_buf());
        let joined = std::env::join_paths(paths).unwrap();
        vars.insert(OsString::from("PATH"), joined);
        vars.extend(std::collections::BTreeMap::from([
            (
                OsString::from("DEPLOY_SSH_KNOWNHOSTS_DIR"),
                cache.as_os_str().to_owned(),
            ),
            (OsString::from("FAKE_SSH_ROOT"), root.as_os_str().to_owned()),
            (
                OsString::from("FAKE_SSH_REMOTE_PREFIX"),
                OsString::from(prefix),
            ),
        ]));
        SysEnv::from_map(vars)
    }

    /// Overwrite a protocol-faithful fake binary (written by [`FakeSsh::new`])
    /// with a custom script for a single focused test — the transport resolves
    /// every binary (`ssh`, `perl`, `stat`, ...) from the fake bin dir's
    /// `PATH`, so the override is picked up by every remote command. Kept
    /// executable like the originals.
    fn write_fake_bin(bin: &Path, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let p = bin.join(name);
        std::fs::write(&p, body).unwrap();
        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&p, perms).unwrap();
    }

    /// Overwrite the fake `perl` so the transport's framed `lstat` helper
    /// resolves to a script that emits `stdout` verbatim (or performs the
    /// injected process-level behavior). The fake shim runs the helper as
    /// `perl -e '…' -- <path>`, so a `perl` in the fake bin shadows the real
    /// interpreter for metadata reads while every other binary is untouched.
    fn write_fake_lstat(bin: &Path, stdout: &str) {
        write_fake_bin(bin, "perl", &format!("#!/bin/sh\nprintf '{stdout}\n'\n"));
    }

    /// Read the fake ssh's recorded invocations (see `FakeSsh::new`): each
    /// invocation is one argv vector (the recorded arguments verbatim, in
    /// order), separated by the `---` marker line.
    fn read_ssh_argv_log(log: &Path) -> Vec<Vec<String>> {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        let mut invocations = Vec::new();
        let mut current = Vec::new();
        for line in text.lines() {
            if line == "---" {
                invocations.push(std::mem::take(&mut current));
            } else {
                current.push(line.to_string());
            }
        }
        if !current.is_empty() {
            invocations.push(current);
        }
        invocations
    }

    // Scenario (a): a fingerprint-only configuration can make a STATUS request
    // once the identity has been prepared. Before preparation it cannot even
    // build its ssh arguments — the exact regression this feature fixes.
    #[test]
    fn status_succeeds_with_fingerprint_only_config() {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let fake = FakeSsh::new(
            tmp.path().join("bin"),
            tmp.path().join("remote"),
            "status-unit.test",
            Path::new("/srv/deploy/status-unit"),
        );
        let cache = tmp.path().join("knownhosts");
        let env = fake_env(
            &fake.bin,
            &cache,
            &fake.remote_root,
            "/srv/deploy/status-unit",
        );
        let t = fake.transport(&cache, &env);
        // Regression: without prepare_identity the transport refuses to
        // build ssh arguments (no pinned key yet).
        let err = t.ssh_args().unwrap_err();
        assert!(
            err.to_string().contains("host identity is not configured"),
            "got: {err}"
        );
        t.prepare_identity().unwrap();
        let args = t.ssh_args().unwrap();
        assert!(
            args.iter().any(|a| a.starts_with("UserKnownHostsFile=")),
            "pinned known-hosts file must be used after prepare_identity"
        );
        // A status request now succeeds (the fake remote is empty).
        let helper = RemoteHelper::new(&t);
        let status = helper.status().unwrap();
        assert!(status.current_generation.is_none());
        assert!(status.inventory.is_empty());
        assert!(status.lock.is_none());
        // The pinned cache file was created on the LOCAL host.
        let pinned = t.pinned_known_hosts.lock().unwrap().clone().unwrap();
        assert!(pinned.exists(), "pinned file must exist");
    }

    /// Pinning is idempotent: a second `prepare_identity` validates the cached
    /// pinned file against the configured fingerprint and reuses it WITHOUT
    /// re-running `ssh-keyscan`; a tampered cache is dropped and re-fetched.
    #[test]
    fn fingerprint_pin_is_validated_and_reused() {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let fake = FakeSsh::new(
            tmp.path().join("bin"),
            tmp.path().join("remote-root"),
            "pin-unit.test",
            Path::new("/srv/deploy/pin-unit"),
        );
        let cache = tmp.path().join("knownhosts");
        let env = fake_env(&fake.bin, &cache, &fake.remote_root, "/srv/deploy/pin-unit");
        let t = fake.transport(&cache, &env);
        t.prepare_identity().unwrap();
        t.prepare_identity().unwrap();
        let calls = std::fs::read_to_string(&fake.keyscan_log)
            .unwrap_or_default()
            .lines()
            .count();
        assert_eq!(calls, 1, "cached pin must be reused without re-keyscan");
        // A tampered cache is not trusted: dropped and re-pinned.
        let pinned = t.pinned_known_hosts.lock().unwrap().clone().unwrap();
        std::fs::write(&pinned, "evil.example.com ssh-ed25519 AAAA\n").unwrap();
        t.prepare_identity().unwrap();
        let calls = std::fs::read_to_string(&fake.keyscan_log)
            .unwrap_or_default()
            .lines()
            .count();
        assert_eq!(calls, 2, "tampered pin must be re-fetched");
        let text = std::fs::read_to_string(&pinned).unwrap();
        assert!(
            text.contains("ssh-ed25519"),
            "repinned file must hold a valid key line"
        );
    }

    /// The framed absence protocol: `metadata_opt` runs the perl `lstat`
    /// helper — whose frames carry the ACTUAL errno — and maps ONLY the
    /// confirmed-absence frames (`A` with ENOENT/ENOTDIR) to `Ok(None)`;
    /// every other outcome (error frames, malformed frames, nonzero exit) is
    /// an error, never absence. The happy path (present entries) is
    /// unchanged: the type bits still decode from the raw mode into
    /// is_symlink/is_dir/is_file.
    #[test]
    fn metadata_opt_structured_absence_protocol() {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let fake = FakeSsh::new(
            tmp.path().join("bin"),
            tmp.path().join("remote"),
            "meta-unit.test",
            Path::new("/srv/deploy/meta-unit"),
        );
        let cache = tmp.path().join("knownhosts");
        let env = fake_env(
            &fake.bin,
            &cache,
            &fake.remote_root,
            "/srv/deploy/meta-unit",
        );
        let t = fake.transport(&cache, &env);
        t.prepare_identity().unwrap();

        use std::os::unix::fs::PermissionsExt;
        let remote_deploy = fake.remote_root.join("srv/deploy/meta-unit");
        std::fs::create_dir_all(&remote_deploy).unwrap();
        let file = remote_deploy.join("app.txt");
        std::fs::write(&file, b"hello").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink("app.txt", remote_deploy.join("link")).unwrap();
        std::os::unix::fs::symlink("missing-target", remote_deploy.join("dangling")).unwrap();

        // Present regular file: strictly parsed `size` + `rawmode`.
        let meta = t
            .metadata_opt(Path::new("app.txt"))
            .unwrap()
            .expect("present file must be Some");
        assert!(meta.is_file && !meta.is_dir && !meta.is_symlink);
        assert_eq!(meta.size, 5);
        assert_eq!(meta.mode, 0o644);

        // Present symlink and DANGLING symlink: lstat semantics decode the
        // symlink type bits (the helper lstats the link itself, so a dangling
        // link is still PRESENT).
        for rel in ["link", "dangling"] {
            let m = t
                .metadata_opt(Path::new(rel))
                .unwrap()
                .expect("present symlink must be Some");
            assert!(m.is_symlink && !m.is_file && !m.is_dir, "{rel}");
        }

        // Confirmed absence: the helper's real lstat fails with ENOENT (2)
        // for a missing final component and for a missing ancestor -> `A`
        // frames -> None.
        assert!(t.metadata_opt(Path::new("absent.txt")).unwrap().is_none());
        assert!(
            t.metadata_opt(Path::new("missing/dir/entry"))
                .unwrap()
                .is_none(),
            "a missing parent is also a confirmed absence"
        );

        // `metadata()` keeps delegating: confirmed absence -> NotFound.
        let err = t.metadata(Path::new("absent.txt")).unwrap_err();
        assert!(
            matches!(err, Error::NotFound(_)),
            "metadata() must map confirmed absence to NotFound, got: {err}"
        );
    }

    /// THE absence-vs-permission regression: a remote `lstat` that fails with
    /// EACCES (permission denied) is an `E` frame with errno 13 — an ERROR,
    /// never absence. The old shell-boolean guard (`[ ! -e ]` succeeds on
    /// EACCES just like on ENOENT) reported permission failures as absent;
    /// the frame carries the errno so the parser cannot confuse them.
    #[test]
    fn metadata_opt_eacces_is_an_error_never_absence() {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let fake = FakeSsh::new(
            tmp.path().join("bin"),
            tmp.path().join("remote"),
            "meta-eacces.test",
            Path::new("/srv/deploy/meta-eacces"),
        );
        let cache = tmp.path().join("knownhosts");
        let env = fake_env(
            &fake.bin,
            &cache,
            &fake.remote_root,
            "/srv/deploy/meta-eacces",
        );
        let t = fake.transport(&cache, &env);
        t.prepare_identity().unwrap();

        let remote_deploy = fake.remote_root.join("srv/deploy/meta-eacces");
        std::fs::create_dir_all(&remote_deploy).unwrap();
        std::fs::write(remote_deploy.join("app.txt"), b"x").unwrap();

        // A fake `perl` whose lstat fails with EACCES: `E\t13` on stdout,
        // exit 0 (the FRAME is the signal).
        write_fake_lstat(&fake.bin, "E\t13");
        let err = t.metadata_opt(Path::new("app.txt")).unwrap_err();
        assert!(
            err.to_string().contains("errno 13"),
            "EACCES must be an error naming the errno, got: {err}"
        );

        // Restore the real helper (drop the fake `perl`): confirmed absence
        // still resolves to None through the REAL errno.
        std::fs::remove_file(fake.bin.join("perl")).unwrap();
        assert!(t.metadata_opt(Path::new("absent.txt")).unwrap().is_none());
    }

    /// Malformed frames (exit 0 with garbage) are errors — every frame is
    /// parsed strictly, with no lenient fallback: wrong prefix, missing
    /// fields, extra fields, and extra lines are all rejected.
    #[test]
    fn metadata_opt_rejects_malformed_frames() {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let fake = FakeSsh::new(
            tmp.path().join("bin"),
            tmp.path().join("remote"),
            "meta-mal.test",
            Path::new("/srv/deploy/meta-mal"),
        );
        let cache = tmp.path().join("knownhosts");
        let env = fake_env(&fake.bin, &cache, &fake.remote_root, "/srv/deploy/meta-mal");
        let t = fake.transport(&cache, &env);
        t.prepare_identity().unwrap();

        let remote_deploy = fake.remote_root.join("srv/deploy/meta-mal");
        std::fs::create_dir_all(&remote_deploy).unwrap();
        std::fs::write(remote_deploy.join("app.txt"), b"x").unwrap();

        // Garbage (no prefix at all).
        write_fake_lstat(&fake.bin, "garbage");
        let err = t.metadata_opt(Path::new("app.txt")).unwrap_err();
        assert!(
            err.to_string().contains("malformed"),
            "garbage stdout must be malformed, got: {err}"
        );

        // Wrong prefix.
        write_fake_lstat(&fake.bin, "X\t2");
        let err = t.metadata_opt(Path::new("app.txt")).unwrap_err();
        assert!(
            err.to_string().contains("malformed"),
            "wrong prefix must be malformed, got: {err}"
        );

        // Present frame with the mode field missing.
        write_fake_lstat(&fake.bin, "P\t5");
        let err = t.metadata_opt(Path::new("app.txt")).unwrap_err();
        assert!(
            err.to_string().contains("malformed"),
            "missing mode field must be malformed, got: {err}"
        );

        // Absent frame with the errno field missing.
        write_fake_lstat(&fake.bin, "A");
        let err = t.metadata_opt(Path::new("app.txt")).unwrap_err();
        assert!(
            err.to_string().contains("malformed"),
            "missing errno field must be malformed, got: {err}"
        );

        // Present frame plus a stray extra field.
        write_fake_lstat(&fake.bin, "P\t5\t81a4\textra");
        let err = t.metadata_opt(Path::new("app.txt")).unwrap_err();
        assert!(
            err.to_string().contains("malformed"),
            "extra field must be malformed, got: {err}"
        );

        // More than one frame line.
        write_fake_lstat(&fake.bin, "P\t5\t81a4\nE\t13");
        let err = t.metadata_opt(Path::new("app.txt")).unwrap_err();
        assert!(
            err.to_string().contains("malformed"),
            "extra lines must be malformed, got: {err}"
        );
    }

    /// Byte-identical snapshot of a directory tree (sorted relative paths +
    /// kind/content digests), so a test can assert ZERO deletions.
    fn snapshot_tree(root: &Path) -> Vec<(String, String)> {
        fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
            let mut entries: Vec<_> = std::fs::read_dir(dir)
                .map(|rd| rd.flatten().map(|e| e.path()).collect())
                .unwrap_or_default();
            entries.sort();
            for p in entries {
                let rel = p
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                let ft = std::fs::symlink_metadata(&p).unwrap().file_type();
                if ft.is_symlink() {
                    out.push((
                        rel,
                        format!(
                            "symlink:{}",
                            std::fs::read_link(&p).unwrap().to_string_lossy()
                        ),
                    ));
                } else if ft.is_dir() {
                    out.push((rel, "dir".to_string()));
                    walk(root, &p, out);
                } else {
                    let data = std::fs::read(&p).unwrap_or_default();
                    out.push((rel, format!("file:{}", crate::digest::sha256_bytes(&data))));
                }
            }
        }
        let mut out = Vec::new();
        if root.exists() {
            walk(root, root, &mut out);
        }
        out
    }

    /// The lstat outcomes the fake remote can be told to emit. The property
    /// dimension: ONLY the absence errnos (ENOENT/ENOTDIR) may produce
    /// `Ok(None)`; every other outcome — EACCES, EIO, malformed frames,
    /// signal-killed commands, transport failures — is an error.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum LstatOutcome {
        Present,
        AbsentEnoent,
        AbsentEnotdir,
        ErrorEacces,
        ErrorEio,
        MalformedGarbage,
        MalformedWrongPrefix,
        MalformedTruncated,
        MalformedMissingErrno,
        MalformedExtraField,
        MalformedTwoLines,
        SignalKilled,
        TransportSpawnFailure,
    }

    impl LstatOutcome {
        /// The frame the fake `perl` must emit for this outcome; `None` when
        /// the outcome is injected at the process level (signal-killed
        /// command, spawn failure).
        fn frame(self) -> Option<&'static str> {
            match self {
                LstatOutcome::Present => Some("P\t5\t81a4"),
                LstatOutcome::AbsentEnoent => Some("A\t2"),
                LstatOutcome::AbsentEnotdir => Some("A\t20"),
                LstatOutcome::ErrorEacces => Some("E\t13"),
                LstatOutcome::ErrorEio => Some("E\t5"),
                LstatOutcome::MalformedGarbage => Some("garbage"),
                LstatOutcome::MalformedWrongPrefix => Some("X\t2"),
                LstatOutcome::MalformedTruncated => Some("P\t5"),
                LstatOutcome::MalformedMissingErrno => Some("A"),
                LstatOutcome::MalformedExtraField => Some("P\t5\t81a4\textra"),
                LstatOutcome::MalformedTwoLines => Some("P\t5\t81a4\nE\t13"),
                LstatOutcome::SignalKilled | LstatOutcome::TransportSpawnFailure => None,
            }
        }

        /// Only the absence errnos (ENOENT/ENOTDIR) are confirmed absence.
        fn is_absence(self) -> bool {
            matches!(
                self,
                LstatOutcome::AbsentEnoent | LstatOutcome::AbsentEnotdir
            )
        }

        /// Every non-absence outcome must be an error.
        fn is_error(self) -> bool {
            !matches!(
                self,
                LstatOutcome::Present | LstatOutcome::AbsentEnoent | LstatOutcome::AbsentEnotdir
            )
        }
    }

    fn all_lstat_outcomes() -> Vec<LstatOutcome> {
        vec![
            LstatOutcome::Present,
            LstatOutcome::AbsentEnoent,
            LstatOutcome::AbsentEnotdir,
            LstatOutcome::ErrorEacces,
            LstatOutcome::ErrorEio,
            LstatOutcome::MalformedGarbage,
            LstatOutcome::MalformedWrongPrefix,
            LstatOutcome::MalformedTruncated,
            LstatOutcome::MalformedMissingErrno,
            LstatOutcome::MalformedExtraField,
            LstatOutcome::MalformedTwoLines,
            LstatOutcome::SignalKilled,
            LstatOutcome::TransportSpawnFailure,
        ]
    }

    proptest! {
        // FIXED-SEED property (0x5EED_5EED, per house style), bounded cases:
        // the lstat OUTCOME is injected through a fake `perl` (frames) or a
        // fake `ssh` (signal-killed command / spawn failure) and driven
        // through the REAL transport + parser. ONLY the absence errnos
        // (ENOENT/ENOTDIR) return `Ok(None)`; every other outcome returns
        // `Err`, and for the error cases the caller-level gate
        // (`swap_current`) also errors and leaves the `current` link
        // byte-identical — a failed lstat is never absence, so it can never
        // drive a swap/removal (the same fail-closed rule retention relies
        // on: zero deletions on a failed read).
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn lstat_outcome_injection(outcome in prop::sample::select(all_lstat_outcomes())) {
            let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let fake = FakeSsh::new(
                tmp.path().join("bin"),
                tmp.path().join("remote"),
                "lstat-prop.test",
                Path::new("/srv/deploy/lstat-prop"),
            );
            let cache = tmp.path().join("knownhosts");
            let env = fake_env(
                &fake.bin,
                &cache,
                &fake.remote_root,
                "/srv/deploy/lstat-prop",
            );
            let t = fake.transport(&cache, &env);
            t.prepare_identity().unwrap();
            let remote_deploy = fake.remote_root.join("srv/deploy/lstat-prop");
            std::fs::create_dir_all(&remote_deploy).unwrap();

            // Inject the outcome BEFORE the first remote metadata read.
            match outcome {
                LstatOutcome::SignalKilled => {
                    // The remote command is killed by a signal: the runner's
                    // direct child dies by SIGTERM, so its exit status carries
                    // no code (never a success).
                    write_fake_bin(&fake.bin, "ssh", "#!/bin/sh\nkill -TERM $$\n");
                }
                LstatOutcome::TransportSpawnFailure => {
                    // The transport cannot even spawn the remote command (a
                    // real dead/broken ssh surfaces the same class of failure
                    // as a `run_remote` error).
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(
                        fake.bin.join("ssh"),
                        std::fs::Permissions::from_mode(0o000),
                    )
                    .unwrap();
                }
                _ => {
                    write_fake_lstat(&fake.bin, outcome.frame().unwrap());
                }
            }

            // FRAME-LEVEL: the real transport parses the injected outcome.
            let result = t.metadata_opt(Path::new("probe"));
            match result {
                Ok(Some(meta)) => {
                    // ONLY the Present outcome may be `Some`.
                    assert_eq!(
                        outcome,
                        LstatOutcome::Present,
                        "{outcome:?} must not be Some"
                    );
                    assert!(meta.is_file && !meta.is_dir && !meta.is_symlink);
                    assert_eq!(meta.size, 5);
                    assert_eq!(meta.mode, 0o644);
                }
                Ok(None) => {
                    // ONLY the absence errnos (ENOENT/ENOTDIR) may be `None`.
                    assert!(outcome.is_absence(), "{outcome:?} must not be None");
                }
                Err(e) => {
                    assert!(
                        outcome.is_error(),
                        "{outcome:?} must not error, got: {e}"
                    );
                    let msg = e.to_string();
                    match outcome {
                        LstatOutcome::ErrorEacces => {
                            assert!(msg.contains("errno 13"), "{outcome:?}: {msg}")
                        }
                        LstatOutcome::ErrorEio => {
                            assert!(msg.contains("errno 5"), "{outcome:?}: {msg}")
                        }
                        LstatOutcome::MalformedGarbage
                        | LstatOutcome::MalformedWrongPrefix
                        | LstatOutcome::MalformedTruncated
                        | LstatOutcome::MalformedMissingErrno
                        | LstatOutcome::MalformedExtraField
                        | LstatOutcome::MalformedTwoLines => {
                            assert!(msg.contains("malformed"), "{outcome:?}: {msg}")
                        }
                        LstatOutcome::SignalKilled => {
                            assert!(msg.contains("ssh lstat failed"), "{outcome:?}: {msg}")
                        }
                        LstatOutcome::TransportSpawnFailure => {
                            assert!(msg.contains("ssh"), "{outcome:?}: {msg}")
                        }
                        _ => unreachable!(),
                    }
                }
            }

            // CALLER-LEVEL (error outcomes only): the current gate reads the
            // `current` link through `metadata_opt`; a FAILED lstat must
            // propagate (never be read as absence), so `swap_current` errors
            // and leaves the link byte-identical — a failed read can never
            // drive a swap/removal (the same fail-closed rule retention
            // relies on: zero deletions on a failed read).
            if outcome.is_error() {
                use std::os::unix::fs::PermissionsExt;
                let link = remote_deploy.join("current");
                std::os::unix::fs::symlink("generations/gen-gate/root", &link).unwrap();
                let before = (
                    std::fs::symlink_metadata(&link).unwrap().permissions().mode(),
                    std::fs::read_link(&link).unwrap(),
                );
                let helper = RemoteHelper::new(&t);
                let err = helper
                    .swap_current(&ExpectedCurrent::Absent, "gen-gate", "op")
                    .unwrap_err();
                assert!(
                    err.to_string().contains("ssh"),
                    "{outcome:?}: a failed lstat must propagate, got: {err}"
                );
                let after = (
                    std::fs::symlink_metadata(&link).unwrap().permissions().mode(),
                    std::fs::read_link(&link).unwrap(),
                );
                assert_eq!(
                    after, before,
                    "{outcome:?}: a failed lstat must leave the current link byte-identical"
                );
            }
        }
    }

    /// The retention fail-closed property, end to end over ssh: a remote
    /// whose `lstat` fails with EACCES (permission denied) on the
    /// generations root must ABORT `compute_retained` with an error — EACCES
    /// is never absence — leaving the remote state byte-identical with ZERO
    /// retention deletions. The old shell-boolean guard mapped this very
    /// failure to absence, so retention saw an empty history and swept
    /// everything.
    #[test]
    fn lstat_eacces_aborts_retention_with_zero_deletions() {
        use crate::config::{DeploymentRetention, PerServerRetention, RetentionConfig};
        use crate::identity::{
            ArtifactRef, VariantName, test_deployment_id, test_generation_id, test_release_id,
            test_tree_digest,
        };
        use crate::remote::helper::GenerationAssignment;
        use crate::retention::policy::compute_retained;
        use crate::store::local::LocalStore;

        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let fake = FakeSsh::new(
            tmp.path().join("bin"),
            tmp.path().join("remote"),
            "ret-eacces.test",
            Path::new("/srv/deploy/ret-eacces"),
        );
        let cache = tmp.path().join("knownhosts");
        let env = fake_env(
            &fake.bin,
            &cache,
            &fake.remote_root,
            "/srv/deploy/ret-eacces",
        );
        let t = fake.transport(&cache, &env);
        t.prepare_identity().unwrap();
        let helper = RemoteHelper::new(&t);
        let remote_deploy = fake.remote_root.join("srv/deploy/ret-eacces");

        // Two generations + a garbage tree, written through the REAL transport
        // (the fake ssh shim runs the real perl lstat helper for reads).
        let created = jiff::Timestamp::now();
        let g1 = test_generation_id("g1");
        let g2 = test_generation_id("g2");
        let mk = |gid: &crate::identity::GenerationId, tree: &str| GenerationAssignment {
            deployment_id: test_deployment_id("d1"),
            generation_id: gid.clone(),
            artifact: ArtifactRef {
                release: test_release_id("rel-sha256-x"),
                variant: VariantName::new("standard"),
                tree: test_tree_digest(tree),
            },
            behavior_sha256: "b".into(),
            prior_generation: None,
            created_at: created.to_string(),
            target: None,
        };
        helper.create_generation("op", &mk(&g1, "t1")).unwrap();
        helper.create_generation("op", &mk(&g2, "t2")).unwrap();
        for tree in ["t1", "t2"] {
            let d = test_tree_digest(tree);
            helper
                .remote()
                .create_dir_all(&crate::remote::layout::tree_root(d.as_str()))
                .unwrap();
        }
        helper
            .swap_current(&ExpectedCurrent::Absent, g2.as_str(), "op")
            .unwrap();
        let garbage = test_tree_digest("garbage");
        helper
            .remote()
            .create_dir_all(&crate::remote::layout::tree_root(garbage.as_str()))
            .unwrap();

        // Inject EACCES ONLY on the generations-root lstat; every other
        // metadata read (the `current` gate, status validation) delegates to
        // the real perl helper, so the fault fires exactly where retention
        // loads its inventory.
        write_fake_bin(
            &fake.bin,
            "perl",
            "#!/bin/sh\nfor last; do :; done\ncase \"$last\" in\n  */generations) printf 'E\\t13\\n'; exit 0 ;;\nesac\nexec /usr/bin/perl \"$@\"\n",
        );

        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let policy = RetentionConfig {
            per_server: PerServerRetention {
                keep_distinct_artifacts: 5,
                keep_days: 14,
                protect_previous: true,
            },
            deployment: DeploymentRetention {
                protect_deployments: 2,
            },
        };
        let before = snapshot_tree(&remote_deploy);
        let err = compute_retained(&helper, &[], &store, &policy).unwrap_err();
        assert!(
            err.to_string().contains("errno 13"),
            "EACCES on the generations root must abort retention naming the errno, got: {err}"
        );

        // ZERO DELETIONS: the remote state is byte-identical and every tree —
        // both history trees AND the garbage — survives.
        assert_eq!(
            snapshot_tree(&remote_deploy),
            before,
            "the failed retention must leave the remote state byte-identical"
        );
        for tree in ["t1", "t2"] {
            let d = test_tree_digest(tree);
            assert!(
                helper
                    .remote()
                    .exists(&crate::remote::layout::tree_root(d.as_str())),
                "history tree {d} must survive the failed retention"
            );
        }
        assert!(
            helper
                .remote()
                .exists(&crate::remote::layout::tree_root(garbage.as_str())),
            "the garbage tree must survive the failed retention"
        );
    }

    /// The transport maps a PRE-INSTALL failure to an ERROR, never a verdict:
    /// with a fake `mktemp` that fails, `try_write_new` returns `Err` — the
    /// operation never reached the publish decision point, so it must not be
    /// misread as `AlreadyPresent`/`Conflict` (the old script collapsed every
    /// `ln` failure into the conflict code, so a pre-install failure was
    /// indistinguishable from a confirmed EEXIST).
    #[test]
    fn try_write_new_preinstall_failure_is_an_error_never_a_verdict() {
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let fake = FakeSsh::new(
            tmp.path().join("bin"),
            tmp.path().join("remote"),
            "preinst-ssh.test",
            Path::new("/srv/deploy/preinst-ssh"),
        );
        let cache = tmp.path().join("knownhosts");
        let env = fake_env(
            &fake.bin,
            &cache,
            &fake.remote_root,
            "/srv/deploy/preinst-ssh",
        );
        let t = fake.transport(&cache, &env);
        t.prepare_identity().unwrap();
        let remote_deploy = fake.remote_root.join("srv/deploy/preinst-ssh");
        std::fs::create_dir_all(&remote_deploy).unwrap();

        // The temp allocation fails remotely: the script exits the reserved
        // PRE-INSTALL code (never the conflict verdict), and the transport
        // propagates the error.
        write_fake_bin(&fake.bin, "mktemp", "#!/bin/sh\nexit 1\n");
        let err = t
            .try_write_new(Path::new("state/op.json"), b"payload")
            .unwrap_err();
        assert!(
            err.to_string().contains("ssh try_write_new failed"),
            "a pre-install failure must be a propagated error, got: {err}"
        );
        assert!(
            !remote_deploy.join("state/op.json").exists(),
            "a pre-install failure must install nothing"
        );
    }

    /// The transport-level verdict matrix over the fake ssh remote: the TYPED
    /// verdict survives the ssh transport boundary. A fake `sync` logger in
    /// the fake bin dir records every sync the remote script (and the
    /// transport's AlreadyPresent retry) performs, so the parent-durability
    /// property is OBSERVABLE: the parent sync runs for `Created` AND for
    /// `AlreadyPresent` (an identical retry establishes the parent's
    /// durability — the fix for the old script, which only synced on the
    /// fresh-install path), and NOT for `Conflict` (a different winner is not
    /// ours to bless). A mode mismatch over identical bytes stays `Conflict`.
    #[derive(Clone, Copy, Debug)]
    enum SshVerdictState {
        Fresh,
        ExactExisting,
        DifferentBytes,
        DifferentMode,
        PublishedBeforeParentSync,
    }

    fn ssh_verdict_state() -> impl Strategy<Value = SshVerdictState> {
        prop_oneof![
            Just(SshVerdictState::Fresh),
            Just(SshVerdictState::ExactExisting),
            Just(SshVerdictState::DifferentBytes),
            Just(SshVerdictState::DifferentMode),
            Just(SshVerdictState::PublishedBeforeParentSync),
        ]
    }

    proptest! {
        // Bounded cases, fixed seed 0x5EED_5EED (house style), no persistence.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn try_write_new_verdicts_over_ssh(
            payload in prop::collection::vec(prop::char::range('a', 'z'), 1..32),
            state in ssh_verdict_state(),
        ) {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};

            let payload: String = payload.into_iter().collect();
            let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let fake = FakeSsh::new(
                tmp.path().join("bin"),
                tmp.path().join("remote"),
                "verdict-ssh.test",
                Path::new("/srv/deploy/verdict-ssh"),
            );
            let cache = tmp.path().join("knownhosts");
            let env = fake_env(
                &fake.bin,
                &cache,
                &fake.remote_root,
                "/srv/deploy/verdict-ssh",
            );
            let t = fake.transport(&cache, &env);
            t.prepare_identity().unwrap();
            let remote_deploy = fake.remote_root.join("srv/deploy/verdict-ssh");
            std::fs::create_dir_all(&remote_deploy).unwrap();

            // A fake `sync` that records every invocation and exits 0 — the
            // remote script's file fsync AND parent-dir sync AND the
            // transport's retry sync all land here, so the test can prove
            // WHICH branch synced (the durable-entry claim).
            let sync_log = tmp.path().join("sync.log");
            write_fake_bin(
                &fake.bin,
                "sync",
                &format!(
                    "#!/bin/sh\nprintf 'sync:%s\\n' \"$*\" >> '{log}'\n",
                    log = sync_log.display(),
                ),
            );

            let rel = Path::new("state/record.json");
            let dest = remote_deploy.join(rel);
            let parent = dest.parent().unwrap().to_path_buf();
            let data = payload.as_bytes();
            let final_mode = IMMUTABLE_RECORD_MODE & 0o7777;

            match state {
                SshVerdictState::Fresh => {
                    let verdict = t
                        .try_write_new(rel, data)
                        .expect("the fresh ssh install must succeed");
                    prop_assert_eq!(verdict, CreateNewVerdict::Created);
                    prop_assert_eq!(
                        std::fs::read(&dest).unwrap(),
                        data,
                        "Ok(Created) must imply exact bytes"
                    );
                    let meta = std::fs::metadata(&dest).unwrap();
                    prop_assert_eq!(
                        meta.mode() & 0o7777,
                        final_mode,
                        "Ok(Created) must imply the final mode"
                    );
                    let log = std::fs::read_to_string(&sync_log).unwrap_or_default();
                    prop_assert!(
                        log.lines().any(|l| l == format!("sync:{}", parent.display())),
                        "Created must sync the parent directory, log: {log:?}"
                    );
                }
                SshVerdictState::ExactExisting => {
                    // An EXACT existing entry (bytes AND mode identical): the
                    // identical retry converges — AlreadyPresent, and the
                    // retry ESTABLISHES the parent durability (the transport
                    // syncs the parent on this branch too).
                    std::fs::create_dir_all(&parent).unwrap();
                    std::fs::write(&dest, data).unwrap();
                    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(final_mode))
                        .unwrap();
                    let verdict = t
                        .try_write_new(rel, data)
                        .expect("an identical retry must converge, not error");
                    prop_assert_eq!(verdict, CreateNewVerdict::AlreadyPresent);
                    prop_assert_eq!(
                        std::fs::read(&dest).unwrap(),
                        data,
                        "the identical retry must not touch the winner"
                    );
                    let log = std::fs::read_to_string(&sync_log).unwrap_or_default();
                    prop_assert!(
                        log.lines().any(|l| l == format!("sync:{}", parent.display())),
                        "AlreadyPresent must sync the parent directory, log: {log:?}"
                    );
                }
                SshVerdictState::DifferentBytes => {
                    // A winner with DIFFERENT bytes: Conflict, never replaced,
                    // and NOT synced (a foreign winner is not ours to bless).
                    std::fs::create_dir_all(&parent).unwrap();
                    std::fs::write(&dest, b"foreign-winner").unwrap();
                    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(final_mode))
                        .unwrap();
                    let verdict = t
                        .try_write_new(rel, data)
                        .expect("a different-content winner is a verdict, not an I/O error");
                    let is_content_mismatch = matches!(
                        verdict,
                        CreateNewVerdict::Conflict(VerifiedExisting::ContentMismatch)
                    );
                    prop_assert!(is_content_mismatch);
                    prop_assert_eq!(
                        std::fs::read(&dest).unwrap(),
                        b"foreign-winner",
                        "the conflict must NEVER replace the winner"
                    );
                    let log = std::fs::read_to_string(&sync_log).unwrap_or_default();
                    prop_assert!(
                        !log.lines().any(|l| l == format!("sync:{}", parent.display())),
                        "Conflict must not sync the foreign winner's parent, log: {log:?}"
                    );
                }
                SshVerdictState::DifferentMode => {
                    // Identical bytes but a DIFFERENT mode: still Conflict —
                    // the mode is part of the record (the spec: "a mode
                    // mismatch must remain Conflict"), never blessed.
                    std::fs::create_dir_all(&parent).unwrap();
                    std::fs::write(&dest, data).unwrap();
                    let other_mode = if final_mode == 0o600 { 0o640 } else { 0o600 };
                    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(other_mode))
                        .unwrap();
                    let verdict = t
                        .try_write_new(rel, data)
                        .expect("a mode mismatch is a verdict, not an I/O error");
                    let is_mode_mismatch = matches!(
                        verdict,
                        CreateNewVerdict::Conflict(VerifiedExisting::ModeMismatch { .. })
                    );
                    prop_assert!(is_mode_mismatch);
                    let meta = std::fs::metadata(&dest).unwrap();
                    prop_assert_eq!(
                        meta.mode() & 0o7777,
                        other_mode,
                        "the mode mismatch must never be replaced"
                    );
                    let log = std::fs::read_to_string(&sync_log).unwrap_or_default();
                    prop_assert!(
                        !log.lines().any(|l| l == format!("sync:{}", parent.display())),
                        "a mode-mismatch Conflict must not sync, log: {log:?}"
                    );
                }
                SshVerdictState::PublishedBeforeParentSync => {
                    // A crash-simulated state: the entry EXISTS with the
                    // intended bytes and mode, but its parent was never synced.
                    // The retry verifies it as AlreadyPresent AND establishes
                    // the parent durability.
                    std::fs::create_dir_all(&parent).unwrap();
                    std::fs::write(&dest, data).unwrap();
                    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(final_mode))
                        .unwrap();
                    let verdict = t
                        .try_write_new(rel, data)
                        .expect("the retry over a published-before-parent-sync entry must converge");
                    prop_assert_eq!(verdict, CreateNewVerdict::AlreadyPresent);
                    prop_assert_eq!(
                        std::fs::read(&dest).unwrap(),
                        data,
                        "the winner must stay intact"
                    );
                    let log = std::fs::read_to_string(&sync_log).unwrap_or_default();
                    prop_assert!(
                        log.lines().any(|l| l == format!("sync:{}", parent.display())),
                        "the AlreadyPresent retry must establish the parent durability, log: {log:?}"
                    );
                }
            }
        }
    }

    /// Arbitrary bytes for the byte-preservation property: EVERY byte class
    /// the old lossy stringification mangled — NULs, non-UTF8, control
    /// chars, quotes, backslashes, shell metacharacters — plus long payloads
    /// that straddle the pipe buffer (the stdin payload is written by the
    /// runner's wait closure, so a payload larger than the pipe must still
    /// flow through the remote `cat` exactly).
    fn arbitrary_bytes() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            prop::collection::vec(any::<u8>(), 0..4096),
            // A dedicated long-payload leg: 16–64 KiB, around the 16–64 KiB
            // pipe-buffer boundary, so the write blocks on the pipe and the
            // remote `cat` must drain it to complete the install.
            prop::collection::vec(any::<u8>(), 16_384..65_536),
        ]
    }

    proptest! {
        // THE BYTE-PRESERVATION PROPERTY (the create-new fix): `try_write_new`
        // is a BYTE API, so ARBITRARY `Vec<u8>` must round-trip EXACTLY —
        // `try_write_new(rel, data)` then `read(rel)` == `data` byte-for-byte
        // — through the ssh transport (over the fake remote) AND the local
        // transport. The ssh side proves the payload travels on the runner's
        // STDIN: the fake ssh recorded every invocation's argv, and the write
        // invocation's argv equals the payload-INDEPENDENT reference command
        // built by `write_new_cmd` — the payload never enters the command
        // string. (A naive "payload is not a substring of the command" check
        // would be unsound: a payload like `cat` legitimately appears inside
        // the fixed script text — exact argv equality is the real proof.)
        // Bounded cases, fixed seed 0x5EED_5EED (house style), no persistence.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn try_write_new_arbitrary_bytes_roundtrip(data in arbitrary_bytes()) {
            let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let fake = FakeSsh::new(
                tmp.path().join("bin"),
                tmp.path().join("remote"),
                "bytes-prop.test",
                Path::new("/srv/deploy/bytes-prop"),
            );
            let cache = tmp.path().join("knownhosts");
            let env = fake_env(
                &fake.bin,
                &cache,
                &fake.remote_root,
                "/srv/deploy/bytes-prop",
            );
            let t = fake.transport(&cache, &env);
            t.prepare_identity().unwrap();

            let rel = Path::new("state/record.bin");
            let verdict = t
                .try_write_new(rel, &data)
                .expect("the fresh byte install must succeed");
            prop_assert_eq!(verdict, CreateNewVerdict::Created);
            let read_back = t.read(rel).expect("read back over ssh");
            prop_assert_eq!(
                read_back.as_slice(),
                data.as_slice(),
                "arbitrary bytes must round-trip EXACTLY through the ssh transport"
            );

            // The payload never enters the transmitted command: the fake ssh
            // recorded the write invocation's argv, and it must equal the
            // payload-INDEPENDENT reference command (the fixed script text) —
            // the payload travels via stdin, so no byte of it can be in argv.
            let mut expected = vec!["ssh".to_string()];
            expected.extend(t.ssh_args().expect("prepared identity"));
            expected.push("--".into());
            expected.push(SshTransport::write_new_cmd(
                t.root(),
                rel,
                IMMUTABLE_RECORD_MODE,
            ));
            let invocations = read_ssh_argv_log(&fake.argv_log);
            let write_inv = invocations
                .first()
                .expect("the write ssh invocation must be recorded");
            // Skip argv[0]: the OS rewrites it to the resolved fake-ssh path
            // (an exec detail, not the transport's data). The transmitted
            // ARGS — identity options, `--`, and the payload-INDEPENDENT
            // command — are what the assertion is about: the payload never
            // enters the command string.
            prop_assert_eq!(
                &write_inv[1..],
                &expected[1..],
                "the write invocation's args must be the payload-independent command"
            );

            // The LOCAL transport is byte-preserving too: the same arbitrary
            // bytes round-trip exactly through the canonical primitive
            // (`durable_create_new`), so the byte API is meaningful on both
            // sides of the transport split.
            let local = crate::remote::transport::LocalTransport::new(
                &crate::testutil::fixture_env(),
                tmp.path().join("local"),
            )
            .expect("local transport");
            let local_rel = Path::new("state/record.bin");
            let local_verdict = local
                .try_write_new(local_rel, &data)
                .expect("the fresh local byte install must succeed");
            prop_assert_eq!(local_verdict, CreateNewVerdict::Created);
            let local_read_back = local.read(local_rel).expect("local read back");
            prop_assert_eq!(
                local_read_back.as_slice(),
                data.as_slice(),
                "arbitrary bytes must round-trip EXACTLY through the local transport"
            );
        }
    }

    // The cross-product create-new verification matrix — the central
    // verification contract, property-tested over the FULL product:
    // TRANSPORT (Local + Ssh-with-fake) × ENTRY TYPE (absent / regular /
    // DIRECTORY / SYMLINK / other-fifo) × MODE (exact / wrong) × CONTENT
    // (exact / semantically-equal / different) × the caller's CONTENT
    // EQUIVALENCE (Exact / Semantic). `Created` ONLY for absent;
    // `AlreadyPresent` ONLY for a REGULAR FILE with the REQUIRED MODE and an
    // ACCEPTED content equivalence; every other combination is `Conflict`
    // carrying the CORRECT typed reason — a directory → NotRegularFile, a
    // SYMLINK → NotRegularFile and NEVER FOLLOWED (the symlink points at a
    // matching regular file, so a following stat would wrongly accept it), a
    // wrong mode → ModeMismatch, different content → ContentMismatch. The
    // `Other` (fifo) kind is generated only for the LOCAL leg: the ssh
    // perl-lstat's THREE-way classification (dir/symlink/file) cannot
    // express a fifo — it reports as a file, and reading it with `cat`
    // would block the transport.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum XTransport {
        Local,
        Ssh,
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum XEntry {
        Absent,
        Regular,
        Directory,
        Symlink,
        Other,
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum XMode {
        Exact,
        Wrong,
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum XContent {
        Exact,
        Semantic,
        Different,
    }

    fn x_entry_strategy(transport: XTransport) -> BoxedStrategy<XEntry> {
        let all = prop_oneof![
            Just(XEntry::Absent),
            Just(XEntry::Regular),
            Just(XEntry::Directory),
            Just(XEntry::Symlink),
            Just(XEntry::Other),
        ]
        .boxed();
        match transport {
            XTransport::Local => all,
            // The ssh perl-lstat classifies dir/symlink/file only: a fifo
            // reports as a file and its `cat` read would block, so the Ssh
            // leg filters the inexpressible fifo kind out of the same
            // strategy.
            XTransport::Ssh => all
                .prop_filter("fifo is not expressible over the ssh lstat", |e| {
                    *e != XEntry::Other
                })
                .boxed(),
        }
    }

    proptest! {
        // Bounded cases (house style), fixed seed 0x5EED_5EED, no failure
        // persistence, and every case drives its OWN fixture (per-fixture
        // isolation — a fifo or symlink in one case can never leak into
        // another).
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(64),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn try_write_new_verification_cross_product(
            (transport, entry, mode, content, equivalence) in prop_oneof![
                Just(XTransport::Local),
                Just(XTransport::Ssh),
            ]
            .prop_flat_map(|t| {
                (
                    Just(t),
                    x_entry_strategy(t),
                    prop_oneof![Just(XMode::Exact), Just(XMode::Wrong)],
                    prop_oneof![
                        Just(XContent::Exact),
                        Just(XContent::Semantic),
                        Just(XContent::Different),
                    ],
                    prop_oneof![
                        Just(ContentEquivalence::Exact),
                        Just(ContentEquivalence::Semantic),
                    ],
                )
            }),
        ) {
            use crate::remote::transport::LocalTransport;
            use std::ffi::CString;
            use std::os::unix::fs::PermissionsExt;

            // The immutable-record intent: a JSON payload whose key order can
            // be re-arranged without changing its value.
            let intent: &[u8] = br#"{"a":1,"b":2}"#;
            let required_mode = IMMUTABLE_RECORD_MODE & 0o7777;
            let wrong_mode = if required_mode == 0o600 { 0o640 } else { 0o600 };
            let rel = Path::new("state/record.json");
            let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();

            // Each case drives its OWN transport fixture: LocalTransport
            // rooted at a fresh dir, or the fake-ssh transport rooted at a
            // fresh emulated remote. The fake-ssh leg installs a no-op `sync`
            // (the write_new_cmd runs `sync` on the temp AND the parent; the
            // real /sbin/sync must never run inside a test).
            let (handle, dest): (Box<dyn Remote>, std::path::PathBuf) = match transport {
                XTransport::Local => {
                    let t = LocalTransport::new(
                        &crate::testutil::fixture_env(),
                        tmp.path().join("r"),
                    )
                    .unwrap();
                    let dest = t.root().join(rel);
                    (Box::new(t), dest)
                }
                XTransport::Ssh => {
                    let fake = FakeSsh::new(
                        tmp.path().join("bin"),
                        tmp.path().join("remote"),
                        "xprod-ssh.test",
                        Path::new("/srv/deploy/xprod-ssh"),
                    );
                    let cache = tmp.path().join("knownhosts");
                    let env = fake_env(
                        &fake.bin,
                        &cache,
                        &fake.remote_root,
                        "/srv/deploy/xprod-ssh",
                    );
                    let t = fake.transport(&cache, &env);
                    t.prepare_identity().unwrap();
                    write_fake_bin(&fake.bin, "sync", "#!/bin/sh\nexit 0\n");
                    let dest = fake.remote_root.join("srv/deploy/xprod-ssh").join(rel);
                    (Box::new(t), dest)
                }
            };

            // Stage the EXISTING entry per (entry, mode, content). A symlink
            // points AT a matching regular file (intent bytes, required mode)
            // — a FOLLOWING stat would accept it, the lstat must not (the
            // symlink-never-followed guarantee).
            std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
            let existing_bytes: &[u8] = match content {
                XContent::Exact => intent,
                XContent::Semantic => br#"{"b":2,"a":1}"#,
                XContent::Different => br#"{"a":9,"b":9}"#,
            };
            let entry_mode = match mode {
                XMode::Exact => required_mode,
                XMode::Wrong => wrong_mode,
            };
            match entry {
                XEntry::Absent => {}
                XEntry::Regular => {
                    std::fs::write(&dest, existing_bytes).unwrap();
                    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(entry_mode))
                        .unwrap();
                }
                XEntry::Directory => std::fs::create_dir(&dest).unwrap(),
                XEntry::Symlink => {
                    let target = dest.with_file_name("target.json");
                    std::fs::write(&target, intent).unwrap();
                    std::fs::set_permissions(
                        &target,
                        std::fs::Permissions::from_mode(required_mode),
                    )
                    .unwrap();
                    std::os::unix::fs::symlink(&target, &dest).unwrap();
                }
                XEntry::Other => {
                    // Local-only: the strategy never generates Other for Ssh.
                    prop_assert_eq!(transport, XTransport::Local, "fifo is local-only");
                    let c = CString::new(dest.as_os_str().as_encoded_bytes()).unwrap();
                    let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o644) };
                    prop_assert_eq!(
                        rc,
                        0,
                        "mkfifo {} must succeed: {}",
                        dest.display(),
                        std::io::Error::last_os_error()
                    );
                }
            }

            let verdict = handle
                .try_write_new_with(rel, intent, equivalence)
                .expect("a create-new attempt must return a verdict, never hang");

            // The CROSS-PRODUCT expectation: `Created` ONLY for absent;
            // `AlreadyPresent` ONLY for a regular file with the required mode
            // and an accepted content equivalence; every other combination is
            // `Conflict` with the correct typed reason.
            let expected = match entry {
                XEntry::Absent => CreateNewVerdict::Created,
                XEntry::Directory => CreateNewVerdict::Conflict(VerifiedExisting::NotRegularFile {
                    kind: NotRegularFileKind::Directory,
                }),
                XEntry::Symlink => CreateNewVerdict::Conflict(VerifiedExisting::NotRegularFile {
                    kind: NotRegularFileKind::Symlink,
                }),
                XEntry::Other => CreateNewVerdict::Conflict(VerifiedExisting::NotRegularFile {
                    kind: NotRegularFileKind::Other,
                }),
                XEntry::Regular => match mode {
                    XMode::Wrong => CreateNewVerdict::Conflict(VerifiedExisting::ModeMismatch {
                        actual: wrong_mode,
                        required: required_mode,
                    }),
                    XMode::Exact => match content {
                        XContent::Exact => CreateNewVerdict::AlreadyPresent,
                        XContent::Different => {
                            CreateNewVerdict::Conflict(VerifiedExisting::ContentMismatch)
                        }
                        XContent::Semantic => match equivalence {
                            ContentEquivalence::Semantic => CreateNewVerdict::AlreadyPresent,
                            ContentEquivalence::Exact => {
                                CreateNewVerdict::Conflict(VerifiedExisting::ContentMismatch)
                            }
                        },
                    },
                },
            };
            prop_assert_eq!(
                verdict,
                expected,
                "cross-product mismatch: transport={:?} entry={:?} mode={:?} content={:?} equivalence={:?}",
                transport,
                entry,
                mode,
                content,
                equivalence
            );
        }
    }
}
