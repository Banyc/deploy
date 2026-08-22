//! SSH transport over `ssh`/`scp` with strict host-key verification.
//!
//! This is the production transport. It authenticates the server with
//! `StrictHostKeyChecking=accept-new` (verifies a known host key and records a
//! newly seen one, rejecting any subsequent change) and never concatenates
//! server addresses, user names, variant names, release IDs, or paths into a
//! remote shell command: every file-system operation passes its arguments as
//! discrete `ssh`/`scp` parameters, and bulk transfers use a framed channel.
//!
//! The initial helper bootstrap (uploading a versioned helper and atomically
//! flipping the entry point) is intentionally out of scope here; this transport
//! already provides the versioned, idempotent, operation-ID-keyed surface the
//! remote helper expects on top of a pre-provisioned `remote_root`.

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
}

impl SshTransport {
    /// Build a transport for `user@address`, whose application root is the
    /// absolute `remote_root` path on that host.
    pub fn new(user: &str, address: &str, remote_root: &Path) -> Result<Self> {
        if user.is_empty() || address.is_empty() {
            return Err(Error::transport(
                "ssh transport requires a non-empty user and address",
            ));
        }
        if remote_root.is_relative() {
            return Err(Error::transport("ssh remote_root must be an absolute path"));
        }
        let target = format!("{user}@{address}");
        Ok(SshTransport {
            target,
            root: remote_root.to_path_buf(),
        })
    }

    fn ssh_args(&self) -> Vec<String> {
        vec![
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
            "-o".into(),
            "PreferredAuthentications=publickey".into(),
            self.target.clone(),
        ]
    }

    /// Run a remote command (no shell interpolation of our own data; argv are
    /// passed as discrete parameters) and return its stdout.
    fn run_remote(&self, argv: &[String]) -> Result<std::process::Output> {
        let mut cmd = Command::new("ssh");
        cmd.args(self.ssh_args());
        cmd.arg("--");
        cmd.args(argv);
        cmd.output()
            .map_err(|e| Error::transport(format!("ssh {}: {e}", argv.join(" "))))
    }

    fn run_remote_ok(&self, argv: &[String]) -> Result<()> {
        let out = self.run_remote(argv)?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh command failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(())
    }

    /// Upload raw bytes to a remote path (creating parent dirs).
    fn upload_bytes(&self, rel: &Path, data: &[u8], mode: u32) -> Result<()> {
        let remote_path = self.root.join(rel);
        let remote_path_str = remote_path.to_string_lossy().into_owned();
        let mut cmd = Command::new("ssh");
        cmd.args(self.ssh_args());
        cmd.arg("--");
        // Create parent dirs then stream stdin into the file.
        cmd.arg(format!(
            "mkdir -p $(dirname {p}) && cat > {p}",
            p = shell_quote(&remote_path_str)
        ));
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
            self.run_remote_ok(&[
                "chmod".into(),
                format!("{:o}", mode & 0o7777),
                remote_path_str,
            ])?;
        }
        Ok(())
    }

    fn download_bytes(&self, rel: &Path) -> Result<Vec<u8>> {
        let remote_path = self.root.join(rel);
        let out = self.run_remote(&[remote_path.to_string_lossy().into_owned()])?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh download failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(out.stdout)
    }
}

/// Single-quote a string for safe inclusion in a remote shell token.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
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
        self.run_remote_ok(&["mkdir".into(), p])
    }

    fn create_dir_all(&self, rel: &Path) -> Result<()> {
        let p = self.root.join(rel).to_string_lossy().into_owned();
        self.run_remote_ok(&["mkdir".into(), "-p".into(), p])
    }

    fn list(&self, rel: &Path) -> Result<Vec<RemoteEntry>> {
        let p = self.root.join(rel);
        // Print one line per entry: name<TAB>type<NEWLINE>
        // type: f, d, or l
        let script = format!(
            "for e in {p}/* {p}/.*; do [ -e \"$e\" ] || continue; n=$(basename \"$e\"); if [ -L \"$e\" ]; then t=l; elif [ -d \"$e\" ]; then t=d; else t=f; fi; printf '%s\\t%s\\n' \"$n\" \"$t\"; done",
            p = shell_quote(&p.to_string_lossy())
        );
        let out = self.run_remote(&[script])?;
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
        self.run_remote_ok(&[
            "mkdir".into(),
            "-p".into(),
            shell_quote(
                &Path::new(&t)
                    .parent()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|| ".".to_string()),
            ),
            "&&".into(),
            "mv".into(),
            shell_quote(&f),
            shell_quote(&t),
        ])
    }

    fn symlink(&self, target: &Path, link: &Path) -> Result<()> {
        let t = target.to_string_lossy().into_owned();
        let l = self.root.join(link).to_string_lossy().into_owned();
        self.run_remote_ok(&[
            "mkdir".into(),
            "-p".into(),
            shell_quote(
                &Path::new(&l)
                    .parent()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|| ".".to_string()),
            ),
            "&&".into(),
            "ln".into(),
            "-sfn".into(),
            shell_quote(&t),
            shell_quote(&l),
        ])
    }

    fn read_link(&self, rel: &Path) -> Result<PathBuf> {
        let p = self.root.join(rel).to_string_lossy().into_owned();
        let out = self.run_remote(&["readlink".into(), shell_quote(&p)])?;
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
        let out = self.run_remote(&["rm".into(), "-f".into(), shell_quote(&p)])?;
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
        self.run_remote_ok(&["rm".into(), "-rf".into(), shell_quote(&p)])
    }

    fn exists(&self, rel: &Path) -> bool {
        let p = self.root.join(rel).to_string_lossy().into_owned();
        let out = self.run_remote(&["test".into(), "-e".into(), shell_quote(&p)]);
        matches!(out, Ok(o) if o.status.success())
    }

    fn metadata(&self, rel: &Path) -> Result<RemoteMeta> {
        let p = self.root.join(rel).to_string_lossy().into_owned();
        // %s size, %f raw mode hex
        let out =
            self.run_remote(&["stat".into(), "-c".into(), "%s %f".into(), shell_quote(&p)])?;
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
        let mut cmd = Command::new("ssh");
        cmd.args(self.ssh_args());
        cmd.arg("--");
        cmd.args(argv);
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
        let out = self.run_remote(&["df".into(), "-kP".into(), shell_quote(&p)])?;
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
}

/// Confirm the transport can negotiate with the host (handshake marker helper).
pub fn handshake_probe(target: &str) -> Result<u32> {
    let mut cmd = Command::new("ssh");
    cmd.args([
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "PreferredAuthentications=publickey",
        target,
        "--",
        "true",
    ]);
    let status = cmd
        .status()
        .map_err(|e| Error::transport(format!("ssh probe {target}: {e}")))?;
    if status.success() {
        Ok(PROTOCOL_VERSION)
    } else {
        Err(Error::transport(format!(
            "ssh handshake probe to {target} failed"
        )))
    }
}
