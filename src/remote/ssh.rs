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
use crate::remote::transport::PROTOCOL_VERSION;
use crate::remote::transport::{Remote, RemoteEntry, RemoteMeta};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// A transport that drives a real remote host over SSH.
pub struct SshTransport {
    target: String,
    root: PathBuf,
    /// Dedicated known-hosts file used with `StrictHostKeyChecking=yes`.
    known_hosts: Option<PathBuf>,
    /// Pre-verified host-key fingerprint (e.g. `SHA256:...`) used to pin the
    /// host key the first time we contact it.
    host_key_fingerprint: Option<String>,
    /// Managed known-hosts file holding the pinned key (used when only a
    /// fingerprint was configured).
    pinned_known_hosts: Option<PathBuf>,
}

impl SshTransport {
    /// Build a transport for `user@address`, whose application root is the
    /// absolute `remote_root` path on that host.
    ///
    /// Host identity must be configured: pass a `known_hosts` file and/or a
    /// `host_key_fingerprint`. If neither is provided the transport refuses to
    /// connect (no trust-on-first-use).
    pub fn new(
        user: &str,
        address: &str,
        remote_root: &Path,
        known_hosts: Option<&Path>,
        host_key_fingerprint: Option<&str>,
    ) -> Result<Self> {
        if user.is_empty() || address.is_empty() {
            return Err(Error::transport(
                "ssh transport requires a non-empty user and address",
            ));
        }
        if remote_root.is_relative() {
            return Err(Error::transport("ssh remote_root must be an absolute path"));
        }
        let mut t = SshTransport {
            target: format!("{user}@{address}"),
            root: remote_root.to_path_buf(),
            known_hosts: known_hosts.map(|p| p.to_path_buf()),
            host_key_fingerprint: host_key_fingerprint.map(|s| s.to_string()),
            pinned_known_hosts: None,
        };
        // If a fingerprint was supplied without an explicit known-hosts file,
        // verify the host key and pin it in a managed file before any command.
        if t.known_hosts.is_none() && t.host_key_fingerprint.is_some() {
            t.pin_known_hosts()?;
        }
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
        ];
        match (&self.known_hosts, &self.pinned_known_hosts) {
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

    /// Verify the remote host key against the configured fingerprint and pin it
    /// in a managed known-hosts file. Fails closed if the key cannot be fetched
    /// or does not match.
    fn pin_known_hosts(&mut self) -> Result<()> {
        let expected = self
            .host_key_fingerprint
            .clone()
            .ok_or_else(|| Error::transport("host_key_fingerprint required for pinning"))?;
        let expected = expected.trim().to_lowercase();

        let path = std::env::temp_dir().join(format!(
            "deploy-knownhosts-{}.txt",
            simple_hash(&self.target)
        ));
        if path.exists() {
            // Already pinned for this target; reuse it.
            self.pinned_known_hosts = Some(path);
            return Ok(());
        }

        // Fetch the host keys.
        let scan = Command::new("ssh-keyscan")
            .arg("-t")
            .arg("ed25519,ecdsa,rsa")
            .arg(&self.target)
            .output()
            .map_err(|e| {
                Error::transport(format!("ssh-keyscan {} failed: {e}", self.target))
            })?;
        if !scan.status.success() {
            return Err(Error::transport(format!(
                "ssh-keyscan {} failed: {}",
                self.target,
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
            // Pipe the single key line into `ssh-keygen -lf` to obtain its
            // fingerprint (e.g. "256 SHA256:xxxx comment (ED25519)").
            let keygen = Command::new("ssh-keygen")
                .arg("-lf")
                .arg("-")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| Error::transport(format!("ssh-keygen spawn: {e}")))?;
            use std::io::Write;
            keygen
                .stdin
                .as_ref()
                .unwrap()
                .write_all(line.as_bytes())
                .map_err(|e| Error::transport(format!("ssh-keygen stdin: {e}")))?;
            let out = keygen
                .wait_with_output()
                .map_err(|e| Error::transport(format!("ssh-keygen wait: {e}")))?;
            if !out.status.success() {
                continue;
            }
            let fp = String::from_utf8_lossy(&out.stdout);
            // The fingerprint is the second whitespace-separated field.
            let fp_field = fp.split_whitespace().nth(1).unwrap_or("").to_lowercase();
            if fp_field == expected {
                matched.push(line.to_string());
            }
        }

        if matched.is_empty() {
            return Err(Error::transport(format!(
                "no host key for {} matched configured fingerprint {}",
                self.target, expected
            )));
        }

        std::fs::write(&path, matched.join("\n").trim_end().to_string() + "\n")
            .map_err(|e| Error::transport(format!("write known_hosts: {e}")))?;
        self.pinned_known_hosts = Some(path);
        Ok(())
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
        argv
            .iter()
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

impl Remote for SshTransport {
    fn root(&self) -> &Path {
        &self.root
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
        let p = self.root.join(rel);
        // Print one line per entry: name<TAB>type<NEWLINE>
        // type: f, d, or l
        let script = format!(
            "for e in {p}/* {p}/.*; do [ -e \"$e\" ] || continue; n=$(basename \"$e\"); if [ -L \"$e\" ]; then t=l; elif [ -d \"$e\" ]; then t=d; else t=f; fi; printf '%s\\t%s\\n' \"$n\" \"$t\"; done",
            p = shell_quote(&p.to_string_lossy())
        );
        let out = self.run_remote(&script)?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh list failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        let mut entries = Vec::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let mut it = line.split('\t');
            let name = match it.next() {
                Some(n) if !n.is_empty() => n.to_string(),
                _ => continue,
            };
            let t = it.next().unwrap_or("f");
            let is_dir = t == "d";
            let is_symlink = t == "l";
            entries.push(RemoteEntry {
                name,
                is_dir,
                is_symlink,
                size: 0,
                mode: 0,
            });
        }
        Ok(entries)
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
        self.run_remote_ok(&Self::argv_cmd(&[
            "rm".into(),
            "-rf".into(),
            p,
        ]))
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
        let remote_path = self.root.join(rel);
        let remote_path_str = remote_path.to_string_lossy().into_owned();
        let payload = String::from_utf8_lossy(data).into_owned();
        // `set -C` enables the noclobber option so the `>` redirection fails if
        // the file already exists, giving an atomic create-if-absent (O_EXCL) on
        // the remote. Both the payload and the path are single-quoted so they
        // cannot be reinterpreted.
        let cmd = format!(
            "set -C; printf '%s' {} > {}",
            shell_quote(&payload),
            shell_quote(&remote_path_str),
        );
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

/// Confirm the transport can negotiate with the host. Host identity must be
/// configured (see [`SshTransport::new`]); this refuses trust-on-first-use.
pub fn handshake_probe(
    target: &str,
    known_hosts: Option<&Path>,
    host_key_fingerprint: Option<&str>,
) -> Result<u32> {
    let (user, address) = match target.split_once('@') {
        Some((u, a)) if !u.is_empty() && !a.is_empty() => (u.to_string(), a.to_string()),
        _ => {
            return Err(Error::transport(format!(
                "ssh handshake probe: target '{target}' must be 'user@address'"
            )))
        }
    };
    let probe = SshTransport::new(
        &user,
        &address,
        Path::new("/"),
        known_hosts,
        host_key_fingerprint,
    )?;
    let out = probe.run_remote("true")?;
    if out.status.success() {
        Ok(PROTOCOL_VERSION)
    } else {
        Err(Error::transport(format!(
            "ssh handshake probe to {target} failed"
        )))
    }
}
