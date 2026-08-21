//! Transport abstraction over a server's remote root.
//!
//! The remote helper owns status inspection, locking, object publication,
//! generation switching, transaction recovery, adapter invocation, and
//! rotation. It performs a protocol-version handshake before mutation and every
//! mutating request carries an operation ID and is idempotent.
//!
//! `LocalTransport` implements the same surface against a local directory so
//! the full push transaction can run end-to-end without SSH, faithfully
//! mirroring the remote layout.

use crate::error::{Error, Result};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Clone, Debug)]
pub struct RemoteEntry {
    pub name: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub mode: u32,
}

#[derive(Clone, Debug)]
pub struct RemoteMeta {
    pub is_dir: bool,
    pub is_symlink: bool,
    pub is_file: bool,
    pub size: u64,
    pub mode: u32,
}

#[derive(Clone, Debug)]
pub struct ExecOutcome {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl ExecOutcome {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// Filesystem + execution surface for one server's remote root.
pub trait Remote {
    fn root(&self) -> &Path;
    fn read(&self, rel: &Path) -> Result<Vec<u8>>;
    fn write(&self, rel: &Path, data: &[u8], mode: u32) -> Result<()>;
    fn create_dir(&self, rel: &Path) -> Result<()>;
    fn create_dir_all(&self, rel: &Path) -> Result<()>;
    fn list(&self, rel: &Path) -> Result<Vec<RemoteEntry>>;
    fn rename(&self, from: &Path, to: &Path) -> Result<()>;
    fn symlink(&self, target: &Path, link: &Path) -> Result<()>;
    fn read_link(&self, rel: &Path) -> Result<PathBuf>;
    fn remove_file(&self, rel: &Path) -> Result<()>;
    fn remove_dir_all(&self, rel: &Path) -> Result<()>;
    fn exists(&self, rel: &Path) -> bool;
    fn metadata(&self, rel: &Path) -> Result<RemoteMeta>;
    /// Execute a command vector (no shell). Returns the outcome.
    fn exec(&self, argv: &[String], timeout: Duration) -> Result<ExecOutcome>;
    /// Available bytes on the filesystem backing the remote root.
    fn available_bytes(&self) -> Result<u64>;
}

fn join(root: &Path, rel: &Path) -> PathBuf {
    if rel.as_os_str().is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel)
    }
}

fn meta_to_remote(m: &std::fs::Metadata) -> RemoteMeta {
    RemoteMeta {
        is_dir: m.is_dir(),
        is_symlink: m.file_type().is_symlink(),
        is_file: m.is_file(),
        size: m.len(),
        mode: m.mode(),
    }
}

/// A transport that operates on a local directory, executing commands on the
/// host. It mirrors the SSH remote layout exactly.
pub struct LocalTransport {
    base: PathBuf,
}

impl LocalTransport {
    pub fn new(base: PathBuf) -> Result<Self> {
        if !base.exists() {
            std::fs::create_dir_all(&base)
                .map_err(|e| Error::transport(format!("mkdir {}: {e}", base.display())))?;
        }
        // Provision the expected top-level layout.
        for d in [
            "control",
            "helpers",
            "objects/sha256",
            "releases",
            "generations",
            "incoming",
            "state",
            "adapters",
            "transactions",
        ] {
            let p = base.join(d);
            if !p.exists() {
                std::fs::create_dir_all(&p)
                    .map_err(|e| Error::transport(format!("mkdir {}: {e}", p.display())))?;
            }
        }
        Ok(LocalTransport { base })
    }
}

impl Remote for LocalTransport {
    fn root(&self) -> &Path {
        &self.base
    }

    fn read(&self, rel: &Path) -> Result<Vec<u8>> {
        std::fs::read(join(&self.base, rel))
            .map_err(|e| Error::transport(format!("read {}: {e}", rel.display())))
    }

    fn write(&self, rel: &Path, data: &[u8], mode: u32) -> Result<()> {
        let p = join(&self.base, rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::transport(format!("mkdir {}: {e}", parent.display())))?;
        }
        std::fs::write(&p, data)
            .map_err(|e| Error::transport(format!("write {}: {e}", p.display())))?;
        if mode != 0 {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode))
                .map_err(|e| Error::transport(format!("chmod {}: {e}", p.display())))?;
        }
        Ok(())
    }

    fn create_dir(&self, rel: &Path) -> Result<()> {
        std::fs::create_dir(join(&self.base, rel))
            .map_err(|e| Error::transport(format!("mkdir {}: {e}", rel.display())))
    }

    fn create_dir_all(&self, rel: &Path) -> Result<()> {
        std::fs::create_dir_all(join(&self.base, rel))
            .map_err(|e| Error::transport(format!("mkdir {}: {e}", rel.display())))
    }

    fn list(&self, rel: &Path) -> Result<Vec<RemoteEntry>> {
        let dir = join(&self.base, rel);
        let mut out = Vec::new();
        for e in std::fs::read_dir(&dir)
            .map_err(|e| Error::transport(format!("read_dir {}: {e}", dir.display())))?
        {
            let e = e.map_err(|e| Error::transport(format!("entry: {e}")))?;
            let m = e
                .metadata()
                .map_err(|e| Error::transport(format!("meta: {e}")))?;
            out.push(RemoteEntry {
                name: e.file_name().to_string_lossy().into_owned(),
                is_dir: m.is_dir(),
                is_symlink: m.file_type().is_symlink(),
                size: m.len(),
                mode: m.mode(),
            });
        }
        Ok(out)
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        let f = join(&self.base, from);
        let t = join(&self.base, to);
        if let Some(parent) = t.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::rename(&f, &t)
            .map_err(|e| Error::transport(format!("rename {} -> {}: {e}", f.display(), t.display())))
    }

    fn symlink(&self, target: &Path, link: &Path) -> Result<()> {
        let l = join(&self.base, link);
        if let Some(parent) = l.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let _ = std::fs::remove_file(&l);
        let res = std::os::unix::fs::symlink(target, &l);
        res.map_err(|e| Error::transport(format!("symlink {} -> {}: {e}", l.display(), target.display())))
    }

    fn read_link(&self, rel: &Path) -> Result<PathBuf> {
        let p = join(&self.base, rel);
        std::fs::read_link(&p)
            .map_err(|e| Error::transport(format!("readlink {}: {e}", p.display())))
    }

    fn remove_file(&self, rel: &Path) -> Result<()> {
        let p = join(&self.base, rel);
        std::fs::remove_file(&p)
            .or_else(|e| if e.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(e) })
            .map_err(|e| Error::transport(format!("remove {}: {e}", p.display())))
    }

    fn remove_dir_all(&self, rel: &Path) -> Result<()> {
        let p = join(&self.base, rel);
        std::fs::remove_dir_all(&p)
            .or_else(|e| if e.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(e) })
            .map_err(|e| Error::transport(format!("rmdir {}: {e}", p.display())))
    }

    fn exists(&self, rel: &Path) -> bool {
        join(&self.base, rel).exists()
    }

    fn metadata(&self, rel: &Path) -> Result<RemoteMeta> {
        let p = join(&self.base, rel);
        let m = std::fs::symlink_metadata(&p)
            .map_err(|e| Error::transport(format!("stat {}: {e}", p.display())))?;
        Ok(meta_to_remote(&m))
    }

    fn exec(&self, argv: &[String], timeout: Duration) -> Result<ExecOutcome> {
        if argv.is_empty() {
            return Err(Error::transport("empty command"));
        }
        let mut cmd = std::process::Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        cmd.current_dir(&self.base);
        let child = cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Error::transport(format!("spawn {:?}: {e}", argv)))?;
        let pid = child.id();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let res = child.wait_with_output();
            let _ = tx.send(res);
        });
        let out = match rx.recv_timeout(timeout) {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                return Err(Error::transport(format!("wait {:?}: {e}", argv)));
            }
            Err(_) => {
                // Timed out: kill the child.
                let _ = std::process::Command::new("kill")
                    .arg("-9")
                    .arg(pid.to_string())
                    .status();
                return Ok(ExecOutcome {
                    exit_code: -1,
                    stdout: String::new(),
                    stderr: format!("timed out after {timeout:?}"),
                });
            }
        };
        Ok(ExecOutcome {
            exit_code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    fn available_bytes(&self) -> Result<u64> {
        let out = std::process::Command::new("df")
            .args(["-k", self.base.to_string_lossy().as_ref()])
            .output()
            .map_err(|e| Error::transport(format!("df: {e}")))?;
        let text = String::from_utf8_lossy(&out.stdout);
        // Second line: Filesystem  blocks  used  avail  capacity  mount
        let line = text.lines().nth(1).ok_or_else(|| {
            Error::transport("unexpected df output".to_string())
        })?;
        let cols: Vec<&str> = line.split_whitespace().collect();
        // avail is the 4th column (1-indexed) on both macOS and Linux.
        let avail_kb = cols
            .get(3)
            .and_then(|c| c.parse::<u64>().ok())
            .ok_or_else(|| Error::transport("could not parse df avail".to_string()))?;
        Ok(avail_kb * 1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn symlink_rename_exists() {
        let dir = tempfile::tempdir().unwrap();
        let t = LocalTransport::new(dir.path().join("r")).unwrap();
        t.create_dir_all(Path::new("generations/gen1")).unwrap();
        t.symlink(Path::new("generations/gen1"), Path::new(".tmp.x")).unwrap();
        assert!(t.exists(Path::new(".tmp.x")), "symlink should exist");
        t.rename(Path::new(".tmp.x"), Path::new("current")).unwrap();
        assert!(t.exists(Path::new("current")), "current should exist after rename");
        let target = t.read_link(Path::new("current")).unwrap();
        assert_eq!(target, Path::new("generations/gen1"));
    }
}
