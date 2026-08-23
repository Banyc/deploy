//! SSH transport over `ssh`/`scp` with configured host-identity verification.
//!
//! This is the production transport. It authenticates the server against a
//! *configured* identity: either a pre-provisioned `known_hosts` file used with
//! `StrictHostKeyChecking=yes`, or a pinned `host_key_fingerprint` that is
//! verified out-of-band before first contact (the host key is fetched with
//! `ssh-keyscan` and its fingerprint compared to the configured value, then
//! pinned in a managed known-hosts file). It never falls back to
//! trust-on-first-use: if no host identity is configured the transport refuses
//! to connect.
//!
//! Every operation is performed by sending a single, fully shell-quoted remote
//! command string. Because OpenSSH joins the arguments it is given into one
//! space-separated string and the remote login shell re-tokenizes that string,
//! passing discrete local `Command` arguments does *not* preserve
//! argument-vector boundaries. We therefore build the remote command as a single
//! string in which every argument is single-quoted, so the remote shell
//! re-tokenizes it back into exactly the intended `argv` — spaces and
//! metacharacters in arguments are preserved and never interpreted as shell
//! syntax.

use crate::error::{Error, Result};
use crate::remote::transport::{Remote, RemoteEntry, RemoteMeta};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

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
    /// fingerprint was configured). Set only by [`SshTransport::provision`],
    /// never at construction, so building the transport has no side effects.
    pinned_known_hosts: std::sync::Mutex<Option<PathBuf>>,
}

impl SshTransport {
    /// Build a transport for `user@address` (connecting on `port`), whose
    /// application root is the absolute `deploy_dir` path on that host.
    ///
    /// Host identity must be configured: pass a `known_hosts` file and/or a
    /// `host_key_fingerprint`. If neither is provided the transport refuses to
    /// connect (no trust-on-first-use).
    pub fn new(
        user: &str,
        address: &str,
        port: u16,
        deploy_dir: &Path,
        known_hosts: Option<&Path>,
        host_key_fingerprint: Option<&str>,
    ) -> Result<Self> {
        if user.is_empty() || address.is_empty() {
            return Err(Error::transport(
                "ssh transport requires a non-empty user and address",
            ));
        }
        if deploy_dir.is_relative() {
            return Err(Error::transport("ssh deploy_dir must be an absolute path"));
        }
        let t = SshTransport {
            target: format!("{user}@{address}"),
            address: address.to_string(),
            port,
            root: deploy_dir.to_path_buf(),
            known_hosts: known_hosts.map(|p| p.to_path_buf()),
            host_key_fingerprint: host_key_fingerprint.map(|s| s.to_string()),
            pinned_known_hosts: std::sync::Mutex::new(None),
        };
        // NOTE: construction is side-effect-free. When a fingerprint was
        // supplied without an explicit known-hosts file, the host key is
        // verified and pinned by `provision` (before the first mutation), not
        // here — a dry run must never touch the network or disk.
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
            "-p".into(),
            self.port.to_string(),
        ];
        // Read the pinned path through the lock; it is set only by `provision`.
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

    /// Build the `ssh-keyscan` argument vector (port, key types, bare host).
    /// The bare address is used (not `user@address`) because `ssh-keyscan`
    /// expects a hostname/address, and the configured port is passed via `-p`.
    fn keyscan_args(&self) -> Vec<String> {
        vec![
            "-p".into(),
            self.port.to_string(),
            "-t".into(),
            "ed25519,ecdsa,rsa".into(),
            self.address.clone(),
        ]
    }

    /// Verify the remote host key against the configured fingerprint and pin it
    /// in a managed known-hosts file. Fails closed if the key cannot be fetched
    /// or does not match. Takes `&self`: the pinned path is stored through the
    /// interior-mutability lock.
    fn pin_known_hosts(&self) -> Result<()> {
        let expected = self
            .host_key_fingerprint
            .clone()
            .ok_or_else(|| Error::transport("host_key_fingerprint required for pinning"))?;
        let expected = expected.trim().to_lowercase();

        // Pinned keys live in a private (0700) cache directory owned by this
        // user, rather than a predictable world-readable temp file name, so a
        // locally pre-created file cannot be trusted blindly.
        let cache_dir = std::env::temp_dir().join("deploy-ssh-knownhosts");
        std::fs::create_dir_all(&cache_dir).map_err(|e| {
            Error::transport(format!(
                "create known_hosts cache {}: {e}",
                cache_dir.display()
            ))
        })?;
        std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o700)).map_err(
            |e| {
                Error::transport(format!(
                    "chmod known_hosts cache {}: {e}",
                    cache_dir.display()
                ))
            },
        )?;
        let path = cache_dir.join(format!("knownhosts-{}.txt", simple_hash(&self.target)));

        // Validate any existing cached file against the configured fingerprint
        // before reusing it: a changed key (or a locally pre-created file) is
        // never trusted without re-verification.
        if path.exists()
            && let Ok(text) = std::fs::read_to_string(&path)
            && Self::fingerprints_match(&text, &expected)
        {
            if let Ok(mut g) = self.pinned_known_hosts.lock() {
                *g = Some(path);
            }
            return Ok(());
        }
        if path.exists() {
            // Stale, unreadable, or mismatched cache: drop and re-pin below.
            let _ = std::fs::remove_file(&path);
        }

        // Fetch the host keys using the bare address and configured port.
        let scan = Command::new("ssh-keyscan")
            .args(self.keyscan_args())
            .output()
            .map_err(|e| Error::transport(format!("ssh-keyscan {} failed: {e}", self.address)))?;
        if !scan.status.success() {
            return Err(Error::transport(format!(
                "ssh-keyscan {} failed: {}",
                self.address,
                String::from_utf8_lossy(&scan.stderr)
            )));
        }
        let text = String::from_utf8_lossy(&scan.stdout);

        // For each fetched key, compute its fingerprint and keep the ones whose
        // fingerprint matches the configured value.
        let mut matched: Vec<String> = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if Self::key_matches_fingerprint(line, &expected) {
                matched.push(line.to_string());
            }
        }

        if matched.is_empty() {
            return Err(Error::transport(format!(
                "no host key for {} matched configured fingerprint {}",
                self.address, expected
            )));
        }

        // Exclusive (O_EXCL) creation with 0600 permissions so a concurrent or
        // pre-existing file cannot be silently overwritten or read by others.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| {
                Error::transport(format!("create pinned known_hosts {}: {e}", path.display()))
            })?;
        use std::io::Write;
        f.write_all(matched.join("\n").trim_end().as_bytes())
            .and_then(|_| f.write_all(b"\n"))
            .map_err(|e| Error::transport(format!("write known_hosts {}: {e}", path.display())))?;
        drop(f);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::transport(format!("chmod known_hosts {}: {e}", path.display())))?;
        if let Ok(mut g) = self.pinned_known_hosts.lock() {
            *g = Some(path);
        }
        Ok(())
    }

    /// Pipe a single key line into `ssh-keygen -lf` and return whether its
    /// fingerprint (the second whitespace-separated field) matches `expected`.
    fn key_matches_fingerprint(line: &str, expected: &str) -> bool {
        let mut keygen = match Command::new("ssh-keygen")
            .arg("-lf")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(k) => k,
            Err(_) => return false,
        };
        use std::io::Write;
        if keygen
            .stdin
            .as_mut()
            .unwrap()
            .write_all(line.as_bytes())
            .is_err()
        {
            return false;
        }
        let out = match keygen.wait_with_output() {
            Ok(o) => o,
            Err(_) => return false,
        };
        if !out.status.success() {
            return false;
        }
        let fp = String::from_utf8_lossy(&out.stdout);
        let fp_field = fp.split_whitespace().nth(1).unwrap_or("").to_lowercase();
        fp_field == expected
    }

    /// Return true if any key line in `text` matches `expected` fingerprint.
    fn fingerprints_match(text: &str, expected: &str) -> bool {
        text.lines().any(|line| {
            let line = line.trim();
            !line.is_empty()
                && !line.starts_with('#')
                && Self::key_matches_fingerprint(line, expected)
        })
    }

    /// Run a single remote shell command (already fully quoted) and return its
    /// stdout/stderr/status. The command is passed as one `ssh` argument after
    /// `--`, so OpenSSH cannot interpret any part of our data as options or as
    /// the connection target.
    fn run_remote(&self, command: &str) -> Result<std::process::Output> {
        let args = self.ssh_args()?;
        let mut cmd = Command::new("ssh");
        cmd.args(&args);
        cmd.arg("--");
        cmd.arg(command);
        cmd.output()
            .map_err(|e| Error::transport(format!("ssh {}: {e}", command)))
    }

    fn run_remote_ok(&self, command: &str) -> Result<()> {
        let out = self.run_remote(command)?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh command failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(())
    }

    /// Build a remote shell command string from an `argv`, quoting every
    /// argument so the remote shell re-tokenizes it back into exactly `argv`.
    fn argv_cmd(argv: &[String]) -> String {
        argv.iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Upload raw bytes to a remote path (creating parent dirs).
    fn upload_bytes(&self, rel: &Path, data: &[u8], mode: u32) -> Result<()> {
        let remote_path = self.root.join(rel);
        let remote_path_str = remote_path.to_string_lossy().into_owned();
        let script = format!(
            "mkdir -p $(dirname {p}) && cat > {p}",
            p = shell_quote(&remote_path_str)
        );
        let mut cmd = Command::new("ssh");
        cmd.args(self.ssh_args()?);
        cmd.arg("--");
        cmd.arg(&script);
        cmd.stdin(Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|e| Error::transport(format!("ssh upload spawn: {e}")))?;
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(data)
            .map_err(|e| Error::transport(format!("ssh upload write: {e}")))?;
        let out = child
            .wait_with_output()
            .map_err(|e| Error::transport(format!("ssh upload wait: {e}")))?;
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

/// Stable, filesystem-safe hash of a string for building temp-file names.
fn simple_hash(s: &str) -> String {
    let mut h: u64 = 1469598103934665603; // FNV-1a offset basis
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    format!("{h:016x}")
}

impl SshTransport {
    /// Build the remote shell command implementing the durability protocol
    /// for an immutable record at `root.join(rel)`. Extracted so tests can
    /// assert on the exact command shape without spawning ssh.
    fn write_new_cmd(root: &Path, rel: &Path, payload: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

        let remote_path = root.join(rel);
        let remote_path_str = remote_path.to_string_lossy().into_owned();
        let parent = Path::new(&remote_path_str)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());
        // Durability protocol (mirrors LocalTransport::try_write_new):
        //
        // 1. Write the payload into a UNIQUE, dot-prefixed temporary file in
        //    the destination directory, so a concurrent reader never sees a
        //    partial record and listing-based observers skip the temp name.
        // 2. Install atomically WITHOUT replacement via `ln` -- it fails if
        //    the destination exists, so no loser can clobber a winner.
        // 3. Remove the temporary name and best-effort `sync` so the
        //    installation survives a crash.
        //
        // The parent directory is created first (the remote layout is not
        // provisioned by SSH the way LocalTransport does it), so a fresh remote
        // root still allows the first lock acquisition.
        let basename = Path::new(&remote_path_str)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "record".to_string());
        // The temp lives INSIDE the destination's parent directory and is
        // dot-prefixed, exactly like LocalTransport::try_write_new. A sibling
        // name (`{parent}.{basename}.tmp...`) would escape the managed remote
        // root whenever the destination's parent IS the deployment root.
        let tmp = format!(
            "{}/.{}.tmp.{}.{}",
            parent.trim_end_matches('/'),
            basename,
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed),
        );
        format!(
            "mkdir -p {p} && printf '%s' {payload} > {tmp} && ln {tmp} {d}; rc=$?; rm -f {tmp}; test \"$rc\" -eq 0 && sync 2>/dev/null || true; exit $rc",
            p = shell_quote(&parent),
            payload = shell_quote(payload),
            tmp = shell_quote(&tmp),
            d = shell_quote(&remote_path_str),
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

    fn provision(&self) -> Result<()> {
        // Create the deployment-directory layout on the remote host. The set of
        // bootstrap directories is owned by `crate::layout::bootstrap_dirs` —
        // the same list LocalTransport provisions — and every path is
        // single-quoted by `argv_cmd`/`shell_quote` so it reaches `mkdir`
        // verbatim. This runs only after the push engine's non-dry-run gate.
        let mut argv: Vec<String> = vec!["mkdir".into(), "-p".into()];
        argv.extend(
            crate::layout::bootstrap_dirs()
                .iter()
                .map(|d| self.root.join(d).to_string_lossy().into_owned()),
        );
        self.run_remote_ok(&Self::argv_cmd(&argv))?;

        // If a fingerprint was supplied without an explicit known-hosts file,
        // verify the host key and pin it in a managed file before any mutation.
        if self.known_hosts.is_none() && self.host_key_fingerprint.is_some() {
            self.pin_known_hosts()?;
        }
        Ok(())
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
        let f = self.root.join(from).to_string_lossy().into_owned();
        let t = self.root.join(to).to_string_lossy().into_owned();
        let parent = Path::new(&t)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());
        let cmd = format!(
            "mkdir -p {parent} && mv {f} {t}",
            parent = shell_quote(&parent),
            f = shell_quote(&f),
            t = shell_quote(&t),
        );
        self.run_remote_ok(&cmd)
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
        let p = self.root.join(rel).to_string_lossy().into_owned();
        // `%s %f` is a SINGLE format argument; it is single-quoted by
        // `argv_cmd` so the remote shell keeps the space inside one token and
        // `stat` receives "-c" "%s %f" "<path>" exactly.
        let out = self.run_remote(&Self::argv_cmd(&[
            "stat".into(),
            "-c".into(),
            "%s %f".into(),
            p,
        ]))?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh stat failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let mut parts = text.split_whitespace();
        let size = parts
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let raw = parts
            .next()
            .and_then(|s| u32::from_str_radix(s, 16).ok())
            .unwrap_or(0);
        let mode = raw & 0o7777;
        let is_symlink = (raw & 0o170000) == 0o120000;
        let is_dir = (raw & 0o170000) == 0o040000;
        let is_file = !is_symlink && !is_dir;
        Ok(RemoteMeta {
            is_dir,
            is_symlink,
            is_file,
            size,
            mode,
        })
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
        let args = self.ssh_args()?;
        let mut cmd = Command::new("ssh");
        cmd.args(&args);
        cmd.arg("--");
        cmd.arg(&command);
        let child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::transport(format!("ssh spawn {:?}: {e}", argv)))?;
        let pid = child.id();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let res = child.wait_with_output();
            let _ = tx.send(res);
        });
        let out = match rx.recv_timeout(timeout) {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                return Err(Error::transport(format!("ssh wait {:?}: {e}", argv)));
            }
            Err(_) => {
                let _ = std::process::Command::new("kill")
                    .arg("-9")
                    .arg(pid.to_string())
                    .status();
                return Ok(crate::remote::transport::ExecOutcome {
                    exit_code: -1,
                    stdout: String::new(),
                    stderr: format!("timed out after {timeout:?}"),
                });
            }
        };
        Ok(crate::remote::transport::ExecOutcome {
            exit_code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    fn available_bytes(&self) -> Result<u64> {
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
        let avail_kb = cols
            .get(3)
            .and_then(|c| c.parse::<u64>().ok())
            .ok_or_else(|| Error::transport("could not parse ssh df avail".to_string()))?;
        Ok(avail_kb * 1024)
    }

    fn try_write_new(&self, rel: &Path, data: &[u8]) -> Result<bool> {
        let payload = String::from_utf8_lossy(data).into_owned();
        let cmd = Self::write_new_cmd(&self.root, rel, &payload);
        let out = self.run_remote(&cmd)?;
        if out.status.success() {
            Ok(true)
        } else if self.exists(rel) {
            // Already present: treat as a lost race rather than a hard error.
            Ok(false)
        } else {
            Err(Error::transport(format!(
                "ssh try_write_new failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

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
        )
        .unwrap()
    }

    // Finding 1: the configured port is propagated to ssh, and ssh-keyscan
    // receives the bare host (not `user@address`).
    #[test]
    fn keyscan_uses_bare_host_and_port() {
        let t = transport();
        let args = t.keyscan_args();
        assert_eq!(args[0], "-p");
        assert_eq!(args[1], "2222");
        assert!(args.contains(&"db.example.com".to_string()));
        // The connection target (`user@host`) must NOT be passed to ssh-keyscan.
        assert!(!args.iter().any(|a| a.contains('@')));
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
        let cmd =
            SshTransport::write_new_cmd(t.root(), &crate::layout::operation_lock(), "op-proc");
        assert!(
            cmd.starts_with("mkdir -p '/srv/app/state'"),
            "parent directory is created first, got: {cmd}"
        );
    }

    // The unique temp file for the durability protocol must live INSIDE the
    // destination's parent directory and be dot-prefixed (mirroring
    // LocalTransport), never a sibling of the parent: a sibling name would
    // escape the managed remote root whenever the destination's parent IS the
    // deployment root.
    #[test]
    fn try_write_new_temp_is_dot_prefixed_inside_destination_parent() {
        let t = transport();
        let cmd =
            SshTransport::write_new_cmd(t.root(), &crate::layout::operation_lock(), "op-proc");
        assert!(
            cmd.contains("/srv/app/state/.operation.lock.tmp."),
            "temp must be inside the destination parent and dot-prefixed, got: {cmd}"
        );
        assert!(
            !cmd.contains("/srv/app.state.operation.lock"),
            "temp must not be a dot-sibling of the destination parent, got: {cmd}"
        );
        assert!(
            !cmd.contains("/srv/app/.state.operation.lock"),
            "temp must not leak above the destination parent, got: {cmd}"
        );
    }

    // Regression: when the destination sits directly in the deployment root,
    // the old sibling naming (`{root}.{basename}.tmp...`) placed the temp OUTSIDE
    // the managed root entirely.
    #[test]
    fn try_write_new_temp_stays_inside_root_for_root_level_dest() {
        let t = transport();
        let cmd = SshTransport::write_new_cmd(t.root(), Path::new("files"), "payload-data");
        assert!(
            cmd.contains("/srv/app/.files.tmp."),
            "temp for a root-level destination must stay inside the root, got: {cmd}"
        );
        assert!(
            !cmd.contains("/srv.files.tmp."),
            "temp must not escape the managed root, got: {cmd}"
        );
    }
}
