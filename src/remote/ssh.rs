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
//! Host-identity setup is split from layout setup: [`SshTransport::prepare_identity`]
//! verifies and pins the host key BEFORE any remote request (a dry run still
//! connects to inspect status, so it needs the pinned key too), while
//! [`SshTransport::provision_layout`] creates the remote deployment-directory
//! layout and runs only for non-dry pushes.
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
    /// fingerprint was configured). Set only by [`SshTransport::prepare_identity`],
    /// never at construction, so building the transport has no side effects.
    pinned_known_hosts: std::sync::Mutex<Option<PathBuf>>,
}

impl SshTransport {
    /// Build a transport for `user@address` (connecting on `port`), whose
    /// application root is the absolute `deploy_dir` path on that host.
    ///
    /// Host identity must be configured with EXACTLY ONE source: pass a
    /// `known_hosts` file OR a `host_key_fingerprint`. If neither is provided
    /// the transport refuses to connect (no trust-on-first-use); if both are
    /// provided the choice is ambiguous (the ssh arguments would silently
    /// prefer `known_hosts`), so the construction is rejected.
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
        };
        // NOTE: construction is side-effect-free. When a fingerprint was
        // supplied without an explicit known-hosts file, the host key is
        // verified and pinned by `prepare_identity` (before the first remote
        // request), not here — a dry run must never touch the network or disk.
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
        // locally pre-created file cannot be trusted blindly. Tests may
        // override the cache root via `DEPLOY_SSH_KNOWNHOSTS_DIR` to give each
        // test its own isolated cache; production deployments leave it unset
        // and use the default `$TMPDIR/deploy-ssh-knownhosts`.
        let cache_dir = std::env::var_os("DEPLOY_SSH_KNOWNHOSTS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("deploy-ssh-knownhosts"));
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
        let remote_path = root.join(rel);
        let remote_path_str = remote_path.to_string_lossy().into_owned();
        let parent = Path::new(&remote_path_str)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());
        // Durability protocol (mirrors LocalTransport::try_write_new):
        //
        // 1. Allocate the temporary file REMOTELY with `mktemp` (exclusive
        //    create, O_EXCL), so the name cannot collide with another
        //    controller's temp no matter its pid or host: no two invocations
        //    are ever handed the same name, and a stale temp left behind by a
        //    crashed controller is never selected — and therefore never
        //    truncated. The name is dot-prefixed and lives INSIDE the
        //    destination's parent directory, so a concurrent reader never sees
        //    a partial record and listing-based observers skip the temp name.
        // 2. Write the payload, sync the file, then install atomically WITHOUT
        //    replacement via `ln` — it fails if the destination exists, so no
        //    loser can clobber a winner. Syncing BEFORE the install means a
        //    reader can never observe an empty/partial hard link.
        // 3. Remove only the temporary file THIS invocation created, then
        //    best-effort `sync` so the installation survives a crash.
        //
        // The parent directory is created first (the remote layout is not
        // provisioned by SSH the way LocalTransport does it), so a fresh remote
        // root still allows the first lock acquisition. The whole chain is
        // `&&`-connected: if `mktemp` (or anything else) fails, the command
        // exits non-zero without installing anything (fail closed).
        //
        // Portability notes: `mktemp TEMPLATE` accepts a template argument on
        // both GNU and BSD/macOS, provided `XXXXXX` ends the final component
        // (kept here), and `sync FILE` is accepted on Linux (coreutils >= 8.24
        // fsyncs that file) and macOS (forces pending writes); the trailing
        // bare `sync 2>/dev/null` remains the best-effort directory sync, bare
        // because `sync <dir>` is not portable.
        let basename = Path::new(&remote_path_str)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "record".to_string());
        // The temp lives INSIDE the destination's parent directory and is
        // dot-prefixed, exactly like LocalTransport::try_write_new. A sibling
        // name (`{parent}.{basename}.tmp...`) would escape the managed remote
        // root whenever the destination's parent IS the deployment root. The
        // `XXXXXX` suffix is the mktemp template; it must survive shell quoting
        // verbatim (single quotes are fine) so GNU and BSD mktemp both accept it.
        let tmp_template = format!("{}/.{}.tmp.XXXXXX", parent.trim_end_matches('/'), basename,);
        format!(
            "mkdir -p {p} && tmp=$(mktemp {tpl}) && printf '%s' {payload} > \"$tmp\" && sync \"$tmp\" && ln \"$tmp\" {d}; rc=$?; rm -f \"$tmp\"; test \"$rc\" -eq 0 && sync 2>/dev/null || true; exit $rc",
            p = shell_quote(&parent),
            tpl = shell_quote(&tmp_template),
            payload = shell_quote(payload),
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
    use std::os::unix::fs::MetadataExt;
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

    // Host identity must be EXACTLY ONE source: both set is ambiguous, neither
    // set is trust-on-first-use (disabled). Construction fails closed on both.
    #[test]
    fn new_rejects_both_identity_sources() {
        let err = SshTransport::new(
            "deploy",
            "db.example.com",
            2222,
            Path::new("/srv/app"),
            Some(Path::new("/etc/ssh/known_hosts")),
            Some("SHA256:abc"),
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
        // ... and the remote allocation happens only after the parent exists.
        let mkdir_end = cmd.find("&&").unwrap();
        assert!(
            cmd[mkdir_end..].contains("mktemp"),
            "mktemp allocation must follow mkdir -p, got: {cmd}"
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
        let cmd =
            SshTransport::write_new_cmd(t.root(), &crate::layout::operation_lock(), "op-proc");
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
        let cmd = SshTransport::write_new_cmd(t.root(), Path::new("files"), "payload-data");
        assert!(
            cmd.contains("mktemp '/srv/app/.files.tmp.XXXXXX'"),
            "temp for a root-level destination must stay inside the root, got: {cmd}"
        );
        assert!(
            !cmd.contains("/srv.files.tmp."),
            "temp must not escape the managed root, got: {cmd}"
        );
    }

    /// Execute a generated `write_new_cmd` string locally with `sh -c`. The
    /// command is self-contained shell operating on absolute paths, so running
    /// it against a local temp dir is a faithful execution of the remote
    /// protocol (the remote login shell would run the same bytes).
    fn run_sh(cmd: &str) -> std::process::Output {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .expect("spawn sh -c")
    }

    // The old temp name derived from the LOCAL pid + a per-process counter, so
    // two controllers on different hosts could share a pid and collide on the
    // same remote temp name; `printf ... > tmp` then truncated the collided
    // path, and the no-clobber `ln` could install the WRONG payload. With
    // remote `mktemp` allocation, concurrent controllers can never be handed
    // the same name: exactly one install wins, every loser reports failure,
    // and no reader ever observes torn/mixed content.
    #[test]
    fn try_write_new_concurrent_controllers_never_collide() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = tempfile::tempdir().unwrap();
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
                let cmd = SshTransport::write_new_cmd(&root, rel, payload);
                writers.push(s.spawn(move || run_sh(&cmd)));
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
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let rel = Path::new("state/op.json");
        let dest = root.join(rel);
        let parent = dest.parent().unwrap();

        // First invocation: installs the record and cleans up its own temp.
        let cmd1 = SshTransport::write_new_cmd(&root, rel, "gen-1");
        let out1 = run_sh(&cmd1);
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
        let cmd2 = SshTransport::write_new_cmd(&root, rel, "gen-2");
        let out2 = run_sh(&cmd2);
        assert!(
            !out2.status.success(),
            "reinstall after a winner must report already-exists"
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
    use crate::remote::helper::RemoteHelper;
    use crate::testutil::ENV_LOCK;
    use std::path::{Path, PathBuf};

    // THE single shared env lock (see `crate::testutil`): every test that
    // mutates the process-global environment — this fake-ssh suite (PATH,
    // DEPLOY_SSH_KNOWNHOSTS_DIR, FAKE_SSH_ROOT/FAKE_SSH_REMOTE_PREFIX) and the
    // systemd fake-`systemctl` suite (PATH, XDG_CONFIG_HOME) — holds this one
    // lock, so a fake `ssh-keyscan` can never race a fake `systemctl`
    // rewriting the same global PATH. Per-test `DEPLOY_SSH_KNOWNHOSTS_DIR`
    // temp dirs keep the pin cache isolated as before.

    struct FakeSsh {
        bin: PathBuf,
        remote_root: PathBuf,
        fingerprint: String,
        deploy_dir: PathBuf,
        address: String,
        keyscan_log: PathBuf,
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

            // Fake `ssh`: parse `-o`/`-p`/`--` like OpenSSH, remap every
            // occurrence of the configured remote deploy dir to the local
            // emulation root, and run the single (fully shell-quoted) remote
            // command with `sh -c`.
            std::fs::write(
                bin.join("ssh"),
                r#"#!/bin/sh
# Fake `ssh` for tests: emulates a remote host whose filesystem is a local
# directory. `FAKE_SSH_ROOT` is the local dir; `FAKE_SSH_REMOTE_PREFIX` is the
# configured remote deploy dir (e.g. /srv/deploy/app). Every occurrence of the
# remote prefix in the (fully shell-quoted) remote command is remapped to
# $FAKE_SSH_ROOT$FAKE_SSH_REMOTE_PREFIX, then the command runs with `sh -c`.
FAKE_ROOT="${FAKE_SSH_ROOT:?FAKE_SSH_ROOT not set}"
REMOTE_PREFIX="${FAKE_SSH_REMOTE_PREFIX:?FAKE_SSH_REMOTE_PREFIX not set}"
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
remapped=$(printf '%s' "$cmd" | awk -v old="$REMOTE_PREFIX" -v new="$FAKE_ROOT$REMOTE_PREFIX" '{ gsub(old, new); printf "%s", $0 }')
exec sh -c "$remapped"
"#,
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
    -t) shift 2 ;;
    *) host="$1" ;;
  esac
  shift
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
            // the transport's list/metadata scripts use `stat -c '%f'` (raw
            // mode in hex) and `stat -c '%s %f'` (size + raw mode hex).
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
    perl -e 'my @s = lstat($ARGV[0]); printf "%x\n", $s[2] & 0xffff;' "$1"
    ;;
  "%s %f")
    perl -e 'my @s = lstat($ARGV[0]); printf "%s %x\n", $s[7], $s[2] & 0xffff;' "$1"
    ;;
  *)
    exec /usr/bin/stat "$@"
    ;;
esac
"#,
            )
            .unwrap();

            use std::os::unix::fs::PermissionsExt;
            for name in ["ssh", "ssh-keyscan", "stat"] {
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
            }
        }

        /// A fingerprint-only `SshTransport` (no `known_hosts`) rooted at
        /// `self.deploy_dir`.
        fn transport(&self) -> SshTransport {
            SshTransport::new(
                "deploy",
                &self.address,
                2222,
                &self.deploy_dir,
                None,
                Some(self.fingerprint.as_str()),
            )
            .unwrap()
        }
    }

    /// Run `f` with `bin` prepended to `PATH` and `DEPLOY_SSH_KNOWNHOSTS_DIR`
    /// pointing at `cache` (both restored afterwards). Pointing the pin cache
    /// at a per-test dir isolates it from every other fake-ssh test in any
    /// binary — no two tests ever share cache state, so concurrent runs of
    /// the lib and integration suites cannot interfere.
    fn with_fake_path<T>(bin: &Path, cache: &Path, f: impl FnOnce() -> T) -> T {
        let old_path = std::env::var_os("PATH").unwrap_or_default();
        let old_cache = std::env::var_os("DEPLOY_SSH_KNOWNHOSTS_DIR");
        let mut paths: Vec<_> = std::env::split_paths(&old_path).collect();
        paths.insert(0, bin.to_path_buf());
        let joined = std::env::join_paths(paths).unwrap();
        // SAFETY: edition 2024 marks `set_var` unsafe. The caller holds the
        // single shared `ENV_LOCK` (crate::testutil), so no other
        // env-mutating test can overlap and swap PATH out from under a
        // spawned fake binary.
        unsafe {
            std::env::set_var("PATH", &joined);
            std::env::set_var("DEPLOY_SSH_KNOWNHOSTS_DIR", cache);
        }
        let result = f();
        match old_cache {
            Some(v) => unsafe {
                std::env::set_var("DEPLOY_SSH_KNOWNHOSTS_DIR", v);
            },
            None => unsafe {
                std::env::remove_var("DEPLOY_SSH_KNOWNHOSTS_DIR");
            },
        }
        unsafe {
            std::env::set_var("PATH", &old_path);
        }
        result
    }

    /// Set the fake-ssh environment (`FAKE_SSH_ROOT` / `FAKE_SSH_REMOTE_PREFIX`)
    /// for the duration of `f`.
    fn with_fake_root<T>(root: &Path, prefix: &str, f: impl FnOnce() -> T) -> T {
        unsafe {
            std::env::set_var("FAKE_SSH_ROOT", root);
            std::env::set_var("FAKE_SSH_REMOTE_PREFIX", prefix);
        }
        let result = f();
        unsafe {
            std::env::remove_var("FAKE_SSH_ROOT");
            std::env::remove_var("FAKE_SSH_REMOTE_PREFIX");
        }
        result
    }

    // Scenario (a): a fingerprint-only configuration can make a STATUS request
    // once the identity has been prepared. Before preparation it cannot even
    // build its ssh arguments — the exact regression this feature fixes.
    #[test]
    fn status_succeeds_with_fingerprint_only_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeSsh::new(
            tmp.path().join("bin"),
            tmp.path().join("remote"),
            "status-unit.test",
            Path::new("/srv/deploy/status-unit"),
        );
        with_fake_path(&fake.bin, &tmp.path().join("knownhosts"), || {
            with_fake_root(&fake.remote_root, "/srv/deploy/status-unit", || {
                let t = fake.transport();
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
            });
        });
    }

    /// Pinning is idempotent: a second `prepare_identity` validates the cached
    /// pinned file against the configured fingerprint and reuses it WITHOUT
    /// re-running `ssh-keyscan`; a tampered cache is dropped and re-fetched.
    #[test]
    fn fingerprint_pin_is_validated_and_reused() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let fake = FakeSsh::new(
            tmp.path().join("bin"),
            tmp.path().join("remote-root"),
            "pin-unit.test",
            Path::new("/srv/deploy/pin-unit"),
        );
        with_fake_path(&fake.bin, &tmp.path().join("knownhosts"), || {
            with_fake_root(&fake.remote_root, "/srv/deploy/pin-unit", || {
                let t = fake.transport();
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
            });
        });
    }
}
