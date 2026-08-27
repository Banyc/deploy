//! The transport stack: connectivity to one server's remote root.
//!
//! One feature, one module: the [`Remote`] trait plus the in-process
//! [`LocalTransport`], the production [`SshTransport`] over `ssh`/`scp`,
//! host-identity verification and pinning (a strict known-hosts file or a
//! pre-verified fingerprint, never trust-on-first-use), and the ONE bounded
//! subprocess runner every ssh operation goes through — hard deadline, kill,
//! and deterministic reap.
//!
//! Transport setup is split into two phases: [`Remote::prepare_identity`]
//! (verify/pin the host key) runs before ANY remote request — including a dry
//! run's status inspection — while [`Remote::provision_layout`] (create the
//! deployment-directory layout) runs only behind the push engine's
//! non-dry-run gate.

use crate::error::{Error, Result};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ---- Remote trait + transports ----
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

/// Total and available bytes on the filesystem backing a remote root, as
/// reported by `df`. `total` is the filesystem's full size; `available` is
/// the free space a new upload can consume. Both are in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsBytes {
    pub total: u64,
    pub available: u64,
}

/// Filesystem + execution surface for one server's remote root.
pub trait Remote {
    fn root(&self) -> &Path;
    fn read(&self, rel: &Path) -> Result<Vec<u8>>;
    fn write(&self, rel: &Path, data: &[u8], mode: u32) -> Result<()>;
    /// Atomically create `rel` with `data` only if it does not already exist.
    /// Returns `Ok(true)` if the file was created, `Ok(false)` if it already
    /// existed (the existing content is left untouched), or `Err` on other
    /// failures. This is the non-racy primitive used for lock acquisition:
    /// `exists`-then-`write` would let two controllers both observe "no lock"
    /// and both proceed.
    fn try_write_new(&self, rel: &Path, data: &[u8]) -> Result<bool>;
    fn create_dir(&self, rel: &Path) -> Result<()>;
    fn create_dir_all(&self, rel: &Path) -> Result<()>;
    /// Apply a permission mode to an existing remote entry (file or directory).
    /// Uploads must preserve the canonical tree's modes exactly, or the
    /// post-upload integrity re-hash diverges on hosts with a permissive umask
    /// (a bare `mkdir`/`cat` inherits the remote umask, so modes must be
    /// applied explicitly).
    fn set_mode(&self, rel: &Path, mode: u32) -> Result<()>;
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
    /// Total and available bytes on the filesystem backing the remote root.
    /// `total` is the filesystem's full size; `available` is the free space a
    /// new upload can consume. Capacity preflight needs both: the percent
    /// reserve is a percentage of the TOTAL size, while the fit check
    /// compares against the AVAILABLE space.
    fn filesystem_bytes(&self) -> Result<FsBytes>;

    /// Prepare the host identity (verify/pin the host key) before ANY remote
    /// request, including read-only status inspection in a dry run. A dry run
    /// still connects over the transport to inspect status, so the identity
    /// must be prepared first. Construction is side-effect-free; identity
    /// preparation happens before the first request that needs to connect.
    /// Default: no-op (transports without a host-identity concept, like
    /// `LocalTransport`).
    fn prepare_identity(&self) -> Result<()> {
        let _ = self;
        Ok(())
    }

    /// Create the deployment-directory layout before the first mutation.
    /// Construction is side-effect-free; layout provisioning happens only after
    /// the push engine's non-dry-run gate.
    fn provision_layout(&self) -> Result<()> {
        let _ = self;
        Ok(())
    }
}

fn join(root: &Path, rel: &Path) -> PathBuf {
    if rel.as_os_str().is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel)
    }
}

/// True when `p` has at least one NORMAL path component below the root —
/// i.e. `p` is not the filesystem root (nor a root-with-only-dots form that
/// normalizes to it, like `//` or `/./`). A transport must never operate on
/// `/`: deployment cleanup (rotation/retention deleting stale generations,
/// the GC sweep) would otherwise run against system-level directories.
pub(crate) fn has_normal_component_below_root(p: &Path) -> bool {
    p.components()
        .any(|c| matches!(c, std::path::Component::Normal(_)))
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
    /// Build a transport rooted at `base`. Construction is side-effect-free:
    /// no directories are created and nothing is touched on disk. Call
    /// [`Remote::provision_layout`] to create the deployment layout before the
    /// first mutation (the push engine does this behind its non-dry-run gate).
    ///
    /// The FILESYSTEM ROOT is refused (defense in depth, mirroring the
    /// [`crate::identity::AbsoluteDeployDir`] parse rule): a transport rooted at
    /// `/` would make the deployment cleanup (rotation/retention deleting
    /// stale generations, the GC sweep) operate on the system root, so the
    /// base must have at least one normal path component below the root.
    pub fn new(base: PathBuf) -> Result<Self> {
        if !has_normal_component_below_root(&base) {
            return Err(Error::transport(format!(
                "deploy_dir {:?} must have at least one normal path component below the root (the filesystem root is not a valid deploy_dir)",
                base
            )));
        }
        Ok(LocalTransport { base })
    }
}

impl Remote for LocalTransport {
    fn root(&self) -> &Path {
        &self.base
    }

    fn provision_layout(&self) -> Result<()> {
        if !self.base.exists() {
            std::fs::create_dir_all(&self.base)
                .map_err(|e| Error::transport(format!("mkdir {}: {e}", self.base.display())))?;
        }
        // Provision the expected top-level layout (owned by `crate::remote::layout`).
        for d in crate::remote::layout::bootstrap_dirs() {
            let p = self.base.join(d);
            if !p.exists() {
                std::fs::create_dir_all(&p)
                    .map_err(|e| Error::transport(format!("mkdir {}: {e}", p.display())))?;
            }
        }
        Ok(())
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

    fn set_mode(&self, rel: &Path, mode: u32) -> Result<()> {
        std::fs::set_permissions(
            join(&self.base, rel),
            std::fs::Permissions::from_mode(mode & 0o7777),
        )
        .map_err(|e| Error::transport(format!("chmod {}: {e}", rel.display())))
    }

    fn list(&self, rel: &Path) -> Result<Vec<RemoteEntry>> {
        let dir = join(&self.base, rel);
        // An unprovisioned remote root has no directories yet; report an empty
        // listing rather than erroring so read-only inspection stays valid.
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(Error::transport(format!("read_dir {}: {e}", dir.display())));
            }
        };
        let mut out = Vec::new();
        for e in rd {
            let e = e.map_err(|e| Error::transport(format!("entry: {e}")))?;
            // `symlink_metadata` (not `metadata`) so a symlink is reported as a
            // symlink with its own mode rather than being followed to its target.
            let m = std::fs::symlink_metadata(e.path())
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
        std::fs::rename(&f, &t).map_err(|e| {
            Error::transport(format!("rename {} -> {}: {e}", f.display(), t.display()))
        })
    }

    fn symlink(&self, target: &Path, link: &Path) -> Result<()> {
        let l = join(&self.base, link);
        if let Some(parent) = l.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let _ = std::fs::remove_file(&l);
        let res = std::os::unix::fs::symlink(target, &l);
        res.map_err(|e| {
            Error::transport(format!(
                "symlink {} -> {}: {e}",
                l.display(),
                target.display()
            ))
        })
    }

    fn read_link(&self, rel: &Path) -> Result<PathBuf> {
        let p = join(&self.base, rel);
        std::fs::read_link(&p)
            .map_err(|e| Error::transport(format!("readlink {}: {e}", p.display())))
    }

    fn remove_file(&self, rel: &Path) -> Result<()> {
        let p = join(&self.base, rel);
        std::fs::remove_file(&p)
            .or_else(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(e)
                }
            })
            .map_err(|e| Error::transport(format!("remove {}: {e}", p.display())))
    }

    fn try_write_new(&self, rel: &Path, data: &[u8]) -> Result<bool> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

        let p = join(&self.base, rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::transport(format!("mkdir {}: {e}", parent.display())))?;
        }
        // Durability protocol for immutable records:
        //
        // 1. Write into a UNIQUE temporary file in the destination directory,
        //    then fsync it. A concurrent reader observing the filesystem at
        //    this point sees no destination file at all — never a partial one.
        // 2. Install atomically WITHOUT replacement: link(2) publishes the
        //    fully written inode under the final name and fails with EEXIST if
        //    another writer won, so no reader can ever observe a torn record
        //    and no loser can clobber a winner.
        // 3. Unlink the temporary name and fsync the parent directory so the
        //    installation survives a crash.
        let tmp = p.with_file_name(format!(
            ".{}.tmp.{}.{}",
            p.file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default(),
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        {
            use std::io::Write;
            let mut f = match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
            {
                Ok(f) => f,
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(Error::transport(format!("create {}: {e}", tmp.display())));
                }
            };
            f.write_all(data)
                .map_err(|e| Error::transport(format!("write {}: {e}", tmp.display())))?;
            f.sync_all()
                .map_err(|e| Error::transport(format!("fsync {}: {e}", tmp.display())))?;
        }
        let installed = match std::fs::hard_link(&tmp, &p) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(Error::transport(format!("install {}: {e}", p.display())));
            }
        };
        let _ = std::fs::remove_file(&tmp);
        if installed
            && let Some(parent) = p.parent()
            && let Ok(dir) = std::fs::File::open(parent)
        {
            let _ = dir.sync_all();
        }
        Ok(installed)
    }

    fn remove_dir_all(&self, rel: &Path) -> Result<()> {
        let p = join(&self.base, rel);
        std::fs::remove_dir_all(&p)
            .or_else(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(e)
                }
            })
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

    fn filesystem_bytes(&self) -> Result<FsBytes> {
        let out = std::process::Command::new("df")
            .args(["-k", self.base.to_string_lossy().as_ref()])
            .output()
            .map_err(|e| Error::transport(format!("df: {e}")))?;
        let text = String::from_utf8_lossy(&out.stdout);
        // Second line: Filesystem  blocks  used  avail  capacity  mount
        let line = text
            .lines()
            .nth(1)
            .ok_or_else(|| Error::transport("unexpected df output".to_string()))?;
        let cols: Vec<&str> = line.split_whitespace().collect();
        // blocks is the 2nd column and avail the 4th (1-indexed) on both
        // macOS and Linux; both are in 1024-byte units.
        let total_kb = cols
            .get(1)
            .and_then(|c| c.parse::<u64>().ok())
            .ok_or_else(|| Error::transport("could not parse df blocks".to_string()))?;
        let avail_kb = cols
            .get(3)
            .and_then(|c| c.parse::<u64>().ok())
            .ok_or_else(|| Error::transport("could not parse df avail".to_string()))?;
        Ok(FsBytes {
            total: total_kb * 1024,
            available: avail_kb * 1024,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Concurrent readers must only ever observe the destination file fully
    /// written: installs happen by hard-linking a synced, complete temporary
    /// inode, so a partial record is unrepresentable.
    #[test]
    fn try_write_new_concurrent_readers_never_observe_partial_content() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().unwrap();
        let t = LocalTransport::new(dir.path().join("r")).unwrap();
        let markers = dir.path().join("r/markers");
        const PAYLOAD: &str =
            r#"{"committed":true,"generation":"gen-1","servers":["server-01","server-02"]}"#;

        // Set even if the writer panics (Drop runs during unwind), so the
        // readers always terminate instead of hanging the test binary.
        struct DoneGuard(Arc<AtomicBool>);
        impl Drop for DoneGuard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        std::thread::scope(|s| {
            let done = Arc::new(AtomicBool::new(false));
            let writer_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

            {
                let done = done.clone();
                let writer_error = writer_error.clone();
                s.spawn(move || {
                    let _done = DoneGuard(done);
                    for i in 0..100 {
                        let rel = Path::new("markers").join(format!("m{i}.json"));
                        if let Err(e) = t.try_write_new(&rel, PAYLOAD.as_bytes()) {
                            *writer_error.lock().unwrap() = Some(e.to_string());
                            return;
                        }
                    }
                });
            }
            for _ in 0..2 {
                let done = done.clone();
                let markers = markers.clone();
                s.spawn(move || {
                    while !done.load(Ordering::SeqCst) {
                        let Ok(entries) = std::fs::read_dir(&markers) else {
                            continue;
                        };
                        for e in entries.flatten() {
                            // Temporary files are dot-prefixed precisely so that
                            // listing-based observers can skip them; a real
                            // reader of a marker path never touches them.
                            if e.file_name().to_string_lossy().starts_with('.') {
                                continue;
                            }
                            let data = std::fs::read(e.path()).unwrap_or_default();
                            assert_eq!(
                                String::from_utf8_lossy(&data).as_ref(),
                                PAYLOAD,
                                "partial marker observed by concurrent reader"
                            );
                        }
                    }
                });
            }

            // The writer must have completed every install successfully.
            assert_eq!(
                writer_error.lock().unwrap().as_deref(),
                None,
                "writer failed to install all markers"
            );
        });

        // Every marker installed exactly once with full content.
        for i in 0..100 {
            let data = std::fs::read(markers.join(format!("m{i}.json"))).unwrap();
            assert_eq!(String::from_utf8_lossy(&data).as_ref(), PAYLOAD);
        }
    }

    #[test]
    fn new_refuses_root_deploy_dir() {
        // The filesystem root (and any form that normalizes to it) is
        // refused at construction: a transport rooted at `/` would make the
        // deployment cleanup operate on the system root.
        for bad in ["/", "//", "/./", "/../"] {
            let err = LocalTransport::new(std::path::PathBuf::from(bad))
                .err()
                .unwrap_or_else(|| panic!("root deploy_dir {bad:?} must be refused"));
            assert!(
                err.to_string()
                    .contains("at least one normal path component"),
                "error must name the rule, got: {err}"
            );
        }
        // A deploy_dir with at least one normal component below the root is
        // accepted (construction stays side-effect-free).
        for ok in ["/srv", "/srv/app/", "/srv//app"] {
            LocalTransport::new(std::path::PathBuf::from(ok))
                .expect("a deploy_dir with a normal component below the root is accepted");
        }
    }

    #[test]
    fn symlink_rename_exists() {
        let dir = tempfile::tempdir().unwrap();
        let t = LocalTransport::new(dir.path().join("r")).unwrap();
        t.create_dir_all(Path::new("generations/gen1")).unwrap();
        t.symlink(Path::new("generations/gen1"), Path::new(".tmp.x"))
            .unwrap();
        assert!(t.exists(Path::new(".tmp.x")), "symlink should exist");
        t.rename(Path::new(".tmp.x"), Path::new("current")).unwrap();
        assert!(
            t.exists(Path::new("current")),
            "current should exist after rename"
        );
        let target = t.read_link(Path::new("current")).unwrap();
        assert_eq!(target, Path::new("generations/gen1"));
    }
}

// ---- SSH transport ----
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
            runner: SshRunner::new(),
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
    pub(crate) fn with_runner(
        user: &str,
        address: &str,
        port: u16,
        deploy_dir: &Path,
        known_hosts: Option<&Path>,
        host_key_fingerprint: Option<&str>,
        runner: SshRunner,
    ) -> Result<Self> {
        let mut t = Self::new(
            user,
            address,
            port,
            deploy_dir,
            known_hosts,
            host_key_fingerprint,
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
mod tests_ssh {
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
            "op-proc",
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
            "op-proc",
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

// ---- host identity pinning ----
/// Build the `ssh-keyscan` argument vector (port, connect timeout, key
/// types, bare host). The bare address is used (not `user@address`) because
/// `ssh-keyscan` expects a hostname/address, and the configured port is
/// passed via `-p`. `-T N` is the canonical ssh-keyscan connection timeout:
/// it is supported by both OpenSSH (Linux) and the LibreSSL/macOS build
/// (which REJECTS the nonexistent `-O timeout=` variant — `-O` only
/// carries `hashalg=`). [`pin_known_hosts`] additionally
/// enforces the same N-second bound at the process level, so a keyscan
/// implementation that ignores `-T` still cannot hang the pin step.
pub(crate) fn keyscan_args(port: u16, address: &str) -> Vec<String> {
    vec![
        "-p".into(),
        port.to_string(),
        "-T".into(),
        SSH_CONNECT_TIMEOUT_SECS.to_string(),
        "-t".into(),
        "ed25519,ecdsa,rsa".into(),
        address.to_string(),
    ]
}

/// Pin the host key for `target` (the `user@host` connection string) in a
/// managed known-hosts file under the private cache directory, verifying it
/// against the configured `fingerprint` (fetched from `address` on `port`
/// via `ssh-keyscan`). Fails closed if the key cannot be fetched or does
/// not match. Returns the pinned file's path; the transport stores it for
/// use as `UserKnownHostsFile` in later ssh invocations.
pub(crate) fn pin_known_hosts(
    fingerprint: &str,
    target: &str,
    address: &str,
    port: u16,
    runner: &SshRunner,
) -> Result<PathBuf> {
    let expected = fingerprint.trim().to_lowercase();

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
    std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        Error::transport(format!(
            "chmod known_hosts cache {}: {e}",
            cache_dir.display()
        ))
    })?;
    let path = cache_dir.join(format!("knownhosts-{}.txt", simple_hash(target)));

    // Validate any existing cached file against the configured fingerprint
    // before reusing it: a changed key (or a locally pre-created file) is
    // never trusted without re-verification.
    if path.exists()
        && let Ok(text) = std::fs::read_to_string(&path)
        && fingerprints_match(&text, &expected)
    {
        return Ok(path);
    }
    if path.exists() {
        // Stale, unreadable, or mismatched cache: drop and re-pin below.
        let _ = std::fs::remove_file(&path);
    }

    // Fetch the host keys using the bare address and configured port. The
    // spawn runs through THE shared runner ([`SshRunner`]): the keyscan is
    // bounded at the process level by the runner's connect deadline (the
    // same `SSH_CONNECT_TIMEOUT_SECS` as the native `-T` option), and on
    // deadline the child is killed and reaped — a dead or unresponsive host
    // fails the pin step fast even if the local `ssh-keyscan` ignores its
    // native `-T` option.
    let mut argv = vec!["ssh-keyscan".to_string()];
    argv.extend(keyscan_args(port, address));
    let scan = runner
        .run(OpKind::KeyscanPin, &argv, None, None)
        .map_err(|e| match e {
            RunError::Spawn(m) => Error::transport(format!("ssh-keyscan {} spawn: {m}", address)),
            RunError::StdinWrite(m) => {
                Error::transport(format!("ssh-keyscan {} stdin write: {m}", address))
            }
            RunError::Wait(m) => Error::transport(format!("ssh-keyscan {} wait: {m}", address)),
            RunError::Timeout { after } => Error::transport(format!(
                "ssh-keyscan {} timed out after {after:?} (host unreachable?)",
                address
            )),
        })?;
    if !scan.status.success() {
        return Err(Error::transport(format!(
            "ssh-keyscan {} failed: {}",
            address,
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
        if key_matches_fingerprint(line, &expected) {
            matched.push(line.to_string());
        }
    }

    if matched.is_empty() {
        return Err(Error::transport(format!(
            "no host key for {} matched configured fingerprint {}",
            address, expected
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
    Ok(path)
}

/// Pipe a single key line into `ssh-keygen -lf` and return whether its
/// fingerprint (the second whitespace-separated field) matches `expected`.
pub(crate) fn key_matches_fingerprint(line: &str, expected: &str) -> bool {
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
pub(crate) fn fingerprints_match(text: &str, expected: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        !line.is_empty() && !line.starts_with('#') && key_matches_fingerprint(line, expected)
    })
}

/// Stable, filesystem-safe hash of a string for building temp-file names.
pub(crate) fn simple_hash(s: &str) -> String {
    let mut h: u64 = 1469598103934665603; // FNV-1a offset basis
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    format!("{h:016x}")
}

#[cfg(test)]
mod tests_hostkey {
    use super::*;

    // Finding 1: the configured port is propagated to ssh-keyscan, and the
    // bare host is passed (not `user@address`).
    #[test]
    fn keyscan_uses_bare_host_and_port() {
        let args = keyscan_args(2222, "db.example.com");
        assert_eq!(args[0], "-p");
        assert_eq!(args[1], "2222");
        assert!(args.contains(&"db.example.com".to_string()));
        // The connection target (`user@host`) must NOT be passed to ssh-keyscan.
        assert!(!args.iter().any(|a| a.contains('@')));
        // The keyscan carries the same connect timeout as ssh. `-T N` is the
        // canonical ssh-keyscan connection timeout (OpenSSH and the
        // LibreSSL/macOS build both support it; `-O timeout=` does not exist).
        assert!(
            args.windows(2)
                .any(|w| w[0] == "-T" && w[1] == SSH_CONNECT_TIMEOUT_SECS.to_string()),
            "keyscan args must carry -T {SSH_CONNECT_TIMEOUT_SECS}, got: {args:?}"
        );
    }
}

// ---- execution runner ----
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
    /// closure always collects the child before surfacing a saved write
    /// error.
    StdinWrite(String),
    /// Waiting on the child failed (wait error, read error, …).
    Wait(String),
    /// The hard deadline fired; the child was killed and reaped.
    Timeout { after: Duration },
}

/// A spawned child owned by one supervisor. The runner keeps the EXCLUSIVE
/// handle to the live child — its `kill` requests the kill on the OWNED
/// [`std::process::Child`] (never a detached pid) — and a reaping closure the
/// wait thread runs. The closure returns once the child exits — including
/// after a kill request — so the runner's join is a deterministic reap. Once
/// the wait thread has reaped the child the handle is CONSUMED: a kill on it
/// is a no-op by construction, so a pid the OS recycled to an unrelated
/// process can never be signalled.
struct SpawnedChild {
    /// The child's pid, known to the PARENT synchronously at spawn time: the
    /// real seam reads it off the owned [`std::process::Child`] immediately
    /// after spawn (the fake generates its own), and the runner surfaces it
    /// through the test-only spawn observer — so a test asserts the pid is
    /// gone after the deadline kill WITHOUT the child ever writing its own
    /// pid to a file (a child-written pidfile races the kill: the child can
    /// be killed before it writes).
    pid: u32,
    /// Request the force-kill of the live child (SIGKILL on the owned
    /// handle). A no-op once the wait thread has reaped the child. The real
    /// seam locks the child slot shared with the wait thread and calls
    /// [`std::process::Child::kill`]; the fake seam records the Kill event
    /// against its own per-child control block.
    kill: Box<dyn Fn() -> std::io::Result<()> + Send>,
    /// Drain stdout/stderr and wait for the child; must return promptly once
    /// the child exits (or is killed). ALWAYS reaps the child before
    /// returning an error: a saved stdin-write error is surfaced only AFTER
    /// the child was collected, so an error can never leave the child
    /// uncollected (no return-before-reap).
    wait: Box<dyn FnOnce() -> std::result::Result<std::process::Output, RunError> + Send>,
}

/// The subprocess seam behind [`SshRunner`]. The production implementation
/// spawns real `ssh` / `ssh-keyscan` processes; tests inject a fake that
/// RECORDS every operation (`spawn(kind, argv)`, and per-handle kills and
/// reaps) and simulates the stall points, so the runner's deadline logic is
/// driven without any real subprocess or sleep.
trait SshRunnerSeam: Send + Sync {
    /// Spawn `argv[0]` with the remaining arguments. When `stdin` is `Some`,
    /// those bytes are piped to the child's stdin as part of the wait, so a
    /// child that stops reading is covered by the same deadline. Returns a
    /// handle whose `kill` requests the kill on the OWNED child and whose
    /// `wait` drains the child and returns once it exits.
    fn spawn(
        &self,
        op: OpKind,
        argv: &[String],
        stdin: Option<Vec<u8>>,
    ) -> std::io::Result<SpawnedChild>;
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
        let child = cmd.spawn()?;
        // The parent reads the pid synchronously at spawn time and surfaces it
        // through the runner's spawn observer: the child never needs to write
        // its own pid to a file.
        let pid = child.id();
        // The child is shared EXCLUSIVELY between the runner's deadline path
        // and the wait thread through this slot: the wait thread polls the
        // child (`try_wait`) with the slot locked and CONSUMES it on exit
        // (the slot becomes None), the deadline path locks the same slot and
        // calls `Child::kill` on the OWNED handle — never a detached pid. A
        // kill on a slot the wait thread already reaped (None) is a no-op by
        // construction: a consumed handle cannot signal anything, so a pid
        // the OS recycled to an unrelated process can never be hit.
        let child: Arc<Mutex<Option<std::process::Child>>> = Arc::new(Mutex::new(Some(child)));
        let kill_child = child.clone();
        let kill: Box<dyn Fn() -> std::io::Result<()> + Send> = Box::new(move || {
            match kill_child.lock().unwrap().as_mut() {
                // SAFETY is provided by std: `Child::kill` SIGKILLs the
                // process this runner spawned and owns.
                Some(child) => child.kill(),
                None => Ok(()),
            }
        });
        let wait_child = child.clone();
        // The stdin payload is written from INSIDE the wait closure (which
        // the runner's deadline bounds) but WITHOUT holding the child slot:
        // the payload pipe is taken out of the child, the slot is released,
        // and the blocking write is interrupted by the deadline kill (the
        // child's read end closes on death, the write fails with EPIPE —
        // SIGPIPE is ignored by the Rust runtime). A remote that stops
        // reading stdin mid-upload therefore blocks only until the deadline,
        // never indefinitely, and — crucially — the blocked write does not
        // pin the child out of the slot, so the deadline can still kill it.
        let wait: Box<dyn FnOnce() -> std::result::Result<std::process::Output, RunError> + Send> =
            Box::new(move || {
                use std::io::Write;
                let mut stdin_pipe = wait_child
                    .lock()
                    .unwrap()
                    .as_mut()
                    .and_then(|c| c.stdin.take());
                // Write the payload FIRST, saving any error: `?` here would
                // return BEFORE the child is collected — a write error (EPIPE
                // after the deadline kill, or a hung-remote pipe) would leave
                // an un-reaped child. The error is therefore saved, and the
                // poll loop below ALWAYS collects the child before the saved
                // write error is surfaced.
                let write_res = match (&stdin, stdin_pipe.as_mut()) {
                    (Some(data), Some(sin)) => sin.write_all(data),
                    _ => Ok(()),
                };
                drop(stdin_pipe);
                // Poll loop: the child lives in the shared slot; every pass
                // drains its pipes (non-blocking) so a large output can never
                // fill a pipe and stall the child, then `try_wait`. Between
                // passes the slot is released so the runner's deadline kill
                // can grab it — each pass is short, so a kill never blocks
                // long. When the child exits the slot is consumed (reaped)
                // and the remaining output drained to EOF.
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                let wait_res = loop {
                    let mut exited: Option<(std::process::Child, std::process::ExitStatus)> = None;
                    {
                        let mut guard = wait_child.lock().unwrap();
                        let c = guard
                            .as_mut()
                            .expect("the wait thread is the sole consumer of the child slot");
                        drain_available(&mut c.stdout, &mut stdout)?;
                        drain_available(&mut c.stderr, &mut stderr)?;
                        match c.try_wait() {
                            Ok(Some(status)) => {
                                exited = guard.take().map(|c| (c, status));
                            }
                            Ok(None) => {}
                            Err(e) => return Err(RunError::Wait(format!("wait: {e}"))),
                        }
                    }
                    if let Some((mut c, status)) = exited {
                        drain_to_eof(&mut c.stdout, &mut stdout)?;
                        drain_to_eof(&mut c.stderr, &mut stderr)?;
                        break Ok(std::process::Output {
                            status,
                            stdout,
                            stderr,
                        });
                    }
                    std::thread::sleep(Duration::from_millis(1));
                };
                // The saved stdin-write error is surfaced only AFTER the
                // child was collected.
                match write_res {
                    Err(e) => Err(RunError::StdinWrite(format!("stdin write: {e}"))),
                    Ok(()) => wait_res,
                }
            });
        Ok(SpawnedChild { pid, kill, wait })
    }
}

/// Drain whatever bytes a running child currently has buffered in a pipe
/// WITHOUT blocking: `poll(2)` with a zero timeout reports readability first,
/// then a single `read` (a pipe that became readable stays readable for the
/// immediate read, and at EOF the read returns 0), so the wait thread's poll
/// loop never parks on a pipe while the child is still running — the
/// non-blocking equivalent of the concurrent drain `wait_with_output` used to
/// perform, so a child that produces a lot of output is drained while running
/// instead of filling its pipe and stalling.
fn drain_available<R>(
    stream: &mut Option<R>,
    buf: &mut Vec<u8>,
) -> std::result::Result<(), RunError>
where
    R: std::io::Read + std::os::fd::AsFd,
{
    let Some(stream) = stream.as_mut() else {
        return Ok(());
    };
    let mut pfd = libc::pollfd {
        fd: stream.as_fd().as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `poll` on a real pipe read end this runner opened for its own
    // child; a zero timeout never blocks and the fd is always valid here.
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
        Err(e) => Err(RunError::Wait(format!("read: {e}"))),
    }
}

/// Drain a child pipe to EOF. Called only AFTER the child exited, when its
/// write ends are closed: the reads return the buffered data then 0, never
/// blocking — collecting the child's full output.
fn drain_to_eof<R: std::io::Read>(
    stream: &mut Option<R>,
    buf: &mut Vec<u8>,
) -> std::result::Result<(), RunError> {
    let Some(stream) = stream.as_mut() else {
        return Ok(());
    };
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(RunError::Wait(format!("read: {e}"))),
        }
    }
}

/// THE single subprocess runner for every ssh operation: spawn the child, wait
/// with a hard deadline, on deadline KILL (-9) through the OWNED child handle
/// then REAP — join the wait thread that owns the child, so the child is
/// deterministically collected before the runner returns (no kill-vs-wait race,
/// no zombie, no return-before-reap). On success the `Output` is returned;
/// spawn/wait failures and the deadline map to [`RunError`].
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
    /// Test-only spawn observer: records each spawned child's pid in the
    /// PARENT at spawn time (called synchronously right after a successful
    /// spawn, before the deadline clock starts). Production installs nothing;
    /// a test installs a recording closure via
    /// [`SshRunner::with_spawn_observer`] and afterwards asserts the recorded
    /// pid is gone — the parent-side replacement for a child-written pidfile,
    /// which races the deadline kill (the child can be killed before it
    /// writes its own pid).
    spawn_observer: Option<Arc<dyn Fn(u32) + Send + Sync>>,
}

impl SshRunner {
    pub(crate) fn new() -> Self {
        SshRunner {
            seam: Arc::new(RealRunner),
            connect_deadline: Duration::from_secs(SSH_CONNECT_TIMEOUT_SECS),
            command_deadline: Duration::from_secs(SSH_COMMAND_TIMEOUT_SECS),
            spawn_observer: None,
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
            spawn_observer: None,
        }
    }

    /// Test-only spawn observer: install a closure that records each spawned
    /// child's pid in the PARENT at spawn time (synchronously, before the
    /// deadline clock starts) — the parent-side replacement for a
    /// child-written pidfile, which races the deadline kill.
    #[cfg(test)]
    fn with_spawn_observer(mut self, observer: Arc<dyn Fn(u32) + Send + Sync>) -> Self {
        self.spawn_observer = Some(observer);
        self
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
        // Split the owned handle into the kill request (the deadline path)
        // and the wait closure (the wait thread). The kill and the wait share
        // the child EXCLUSIVELY through the seam's handle, so the deadline
        // path can kill while the wait thread is mid-wait and a kill after
        // the wait has reaped the child is a no-op by construction.
        let SpawnedChild { pid, kill, wait } = child;
        // The test-only spawn observer records the pid in the PARENT here,
        // synchronously, immediately after spawn — before the deadline clock
        // starts — so a test can assert the pid is gone after the deadline
        // kill without the child ever writing its own pid to a file (a
        // child-written pidfile races the kill: the child can be killed
        // before it writes). Only tests install an observer; production runs
        // with None, so this is a no-op.
        if let Some(observer) = &self.spawn_observer {
            observer(pid);
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let res = wait();
            let _ = tx.send(res);
        });
        match rx.recv_timeout(deadline) {
            Ok(Ok(out)) => {
                // Success: the wait thread reaped the child (its poll loop
                // collected it) and sent the output. Join so the thread — and
                // therefore the child's collection — is complete before we
                // return.
                let _ = handle.join();
                Ok(out)
            }
            Ok(Err(e)) => {
                // The wait closure already reaped the child before returning
                // the error (a saved stdin-write error is surfaced only after
                // the child was collected), and the join collects the thread —
                // so an error path never leaves an uncollected child either.
                let _ = handle.join();
                Err(e)
            }
            Err(_) => {
                // HARD DEADLINE: request a kill through the OWNED child handle
                // — never a libc::kill of a detached pid — then reap by
                // joining the wait thread that owns the child (its `wait`
                // returns promptly after the kill). Both complete before this
                // function returns, so the child is deterministically
                // collected — no zombie, no kill-vs-wait race, no
                // return-before-reap — and a pid the OS recycled after the
                // reap can never be signalled: a kill on a consumed handle is
                // a no-op by construction.
                let _ = kill();
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

    /// Where an injected delay blocks inside the fake seam. The
    /// scheduler-delay property generates these × a delay duration and asserts
    /// the runner's invariants still hold under every interleaving: the
    /// delays perturb the thread schedule around the spawn/deadline/kill/wait
    /// lifecycle instead of delaying everything uniformly, so both the
    /// kill-before-join and join-before-kill orderings are exercised (the
    /// after-reap placement is the delay-driven mirror of the pid-reuse
    /// barrier).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DelayAt {
        /// The fake's `spawn` blocks BEFORE returning the handle: the child is
        /// conceptually live but the runner does not yet hold it.
        Spawn,
        /// The fake's kill closure blocks BEFORE recording the kill and
        /// arming the killed flag: the runner has decided to kill but the
        /// wait thread keeps polling — a kill-before-join with the kill held
        /// open.
        Kill,
        /// The fake's wait closure blocks BEFORE its first wait: the wait
        /// thread is a live waiter while the deadline races it.
        Wait,
        /// The fake's wait closure blocks AFTER recording its reap and BEFORE
        /// returning the completion: a deadline kill in this window finds the
        /// reaped handle consumed and is a no-op — join-before-kill, the
        /// barrier property's window reached via delay injection.
        AfterReap,
    }

    /// How long the injected delay blocks, relative to the runner's deadline:
    /// Tiny stays well inside the deadline (the wait finishes first and the
    /// runner joins without killing), Past crosses it (the deadline fires
    /// while the wait is still blocked and the runner must kill-then-reap).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DelaySize {
        /// No delay: the case runs unperturbed.
        None,
        /// An order of magnitude under the deadline: a scheduling
        /// perturbation, not a deadline crossing.
        Tiny,
        /// Past the deadline by a small margin: the wait is guaranteed to
        /// outlive the deadline.
        Past,
    }

    impl DelaySize {
        /// The wall-clock delay for a runner deadline of `deadline`.
        fn delay_for(self, deadline: Duration) -> Duration {
            match self {
                DelaySize::None => Duration::ZERO,
                DelaySize::Tiny => deadline / 10,
                DelaySize::Past => deadline + Duration::from_millis(3),
            }
        }
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
        /// Set the instant the wait has collected the child: from then on a
        /// kill request on this handle is a NO-OP — the fake's mirror of the
        /// real runner's consumed `Child` handle.
        reaped: AtomicBool,
        stall: Stall,
        /// Whether the op pipes a stdin payload: the write-error stall is
        /// meaningful only when there is something to write (the upload op).
        has_stdin: bool,
        /// Real host-key line the fake keyscan emits on Complete, so the pin
        /// path succeeds end-to-end (fingerprint verified with real ssh-keygen).
        keyscan_line: Option<String>,
        /// Test-only barrier for the pid-reuse property: the wait parks on it
        /// AFTER recording its reap and BEFORE returning, exposing the
        /// reaped-but-not-yet-completed window in which a detached-pid kill
        /// would be catastrophic.
        after_reap_barrier: Option<Arc<std::sync::Barrier>>,
        /// Injected scheduler delay (stage + duration) for this child: the
        /// fake blocks for `delay` at `delay_at` — the delay-injection points
        /// of the scheduler-delay property. `Duration::ZERO` disables it.
        delay_at: DelayAt,
        delay: Duration,
        state: Arc<FakeState>,
    }

    impl ChildCtl {
        /// The wait closure body: finish immediately (Complete / NonZero /
        /// vacuous StdinWriteError), block until killed (Hang), or fail AFTER
        /// the reap (StdinWriteError with a payload / WaitError); the caller
        /// records the single reap and returns the stubbed output or error.
        fn wait(&self) -> std::result::Result<std::process::Output, RunError> {
            self.state.live_waiters.fetch_add(1, Ordering::SeqCst);
            // Injected scheduler delay at the WAIT stage: the wait thread is a
            // live waiter while the deadline races it — a delay inside the
            // deadline leaves the completion first (join-before-kill), a
            // delay past it leaves the kill first (kill-before-join).
            if self.delay_at == DelayAt::Wait {
                std::thread::sleep(self.delay);
            }
            let res = self.wait_inner();
            // The child is fully reaped now — and the reaped flag is armed
            // BEFORE the Reap becomes observable, so from the moment the log
            // shows the reap a kill request on this handle is a no-op (the
            // real runner's consumed-handle no-op). The barrier parks the wait
            // AFTER the reap but BEFORE the completion notification — the
            // window the pid-reuse test exploits; only that test sets it.
            self.reaped.store(true, Ordering::SeqCst);
            self.state.push(LogEntry::Reap { pid: self.pid });
            // Injected scheduler delay at the AFTER-REAP stage: the child is
            // reaped but the completion has not been delivered — a deadline
            // reached in this window makes the runner's kill a no-op on the
            // consumed handle (join-before-kill), the delay-probe mirror of
            // the pid-reuse barrier.
            if self.delay_at == DelayAt::AfterReap {
                std::thread::sleep(self.delay);
            }
            self.state.live_waiters.fetch_sub(1, Ordering::SeqCst);
            if let Some(barrier) = &self.after_reap_barrier {
                barrier.wait();
            }
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
                Stall::Complete => Ok(output(0)),
                Stall::NonZero => Ok(output(1)),
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
                    Ok(output(0))
                }
                Stall::StdinWriteError => {
                    if self.has_stdin {
                        // The stdin write fails — but the closure STILL reaps
                        // (the caller records the Reap) and only THEN returns
                        // the saved write error: a return-before-reap on this
                        // path would show up as a missing Reap.
                        Err(RunError::StdinWrite(
                            "simulated stdin write failure".to_string(),
                        ))
                    } else {
                        // No stdin payload: there is nothing to write, so the
                        // stall is vacuous and the child completes normally.
                        Ok(output(0))
                    }
                }
                Stall::WaitError => {
                    // The reap is ATTEMPTED (the caller records the Reap) but
                    // the wait itself fails: surfaces as a wait error after
                    // the reap attempt.
                    Err(RunError::Wait("simulated wait failure".to_string()))
                }
                Stall::SpawnError => unreachable!("spawn errors never yield a child"),
            }
        }
    }

    /// The injected fake seam: records every spawn (kind + argv), and the
    /// per-handle kills and reaps, and simulates the generated stall point.
    struct FakeSeam {
        state: Arc<FakeState>,
        stall: Stall,
        next_pid: AtomicU32,
        keyscan_line: Option<String>,
        /// Test-only barrier for the pid-reuse property: the NEXT spawned
        /// child's wait parks on it AFTER recording its reap and BEFORE
        /// returning, exposing the reaped-but-not-yet-completed window in
        /// which a detached-pid kill would be catastrophic.
        after_reap_barrier: Option<Arc<std::sync::Barrier>>,
        /// Injected scheduler delay (stage + duration) applied to this seam's
        /// spawn/kill/wait closures: the delay-injection points of the
        /// scheduler-delay property.
        delay_at: DelayAt,
        delay: Duration,
    }

    impl FakeSeam {
        fn new(stall: Stall, keyscan_line: Option<String>) -> (Arc<Self>, Arc<FakeState>) {
            Self::with_delays(stall, keyscan_line, DelayAt::Wait, Duration::ZERO)
        }

        /// The fake seam with an injected scheduler delay: every spawned
        /// child's spawn/kill/wait closures block for `delay` at the `at`
        /// stage, deliberately perturbing the thread schedule so the
        /// scheduler-delay property races the deadline around the
        /// kill/wait boundary.
        fn with_delays(
            stall: Stall,
            keyscan_line: Option<String>,
            at: DelayAt,
            delay: Duration,
        ) -> (Arc<Self>, Arc<FakeState>) {
            let state = Arc::new(FakeState::default());
            let seam = FakeSeam {
                state: state.clone(),
                stall,
                next_pid: AtomicU32::new(1),
                keyscan_line,
                after_reap_barrier: None,
                delay_at: at,
                delay,
            };
            (Arc::new(seam), state)
        }

        /// The pid-reuse simulation: spawn a fresh UNRELATED child that
        /// recycles `pid` — the pid a real OS hands to a new process the
        /// instant the original child is reaped. The spawn is recorded in the
        /// log so the reuse is observable; the returned control block lets the
        /// caller assert the unrelated child was never killed (its wait is
        /// never invoked — only its kill flag is inspected).
        fn spawn_reused_pid(&self, pid: u32, op: OpKind, argv: &[String]) -> Arc<ChildCtl> {
            self.state.push(LogEntry::Spawn {
                op,
                argv: argv.to_vec(),
                pid,
            });
            Arc::new(ChildCtl {
                pid,
                killed: AtomicBool::new(false),
                reaped: AtomicBool::new(false),
                // Benign: the reused child's wait never runs in the test.
                stall: Stall::Complete,
                has_stdin: false,
                keyscan_line: None,
                after_reap_barrier: None,
                delay_at: DelayAt::Wait,
                delay: Duration::ZERO,
                state: self.state.clone(),
            })
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
            // Injected scheduler delay at the SPAWN stage: the child is
            // conceptually live but the runner does not yet hold the handle —
            // the launch skew the scheduler-delay property perturbs.
            if self.delay_at == DelayAt::Spawn {
                std::thread::sleep(self.delay);
            }
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
                reaped: AtomicBool::new(false),
                stall: self.stall,
                has_stdin: stdin.is_some(),
                keyscan_line: self.keyscan_line.clone(),
                after_reap_barrier: self.after_reap_barrier.clone(),
                delay_at: self.delay_at,
                delay: self.delay,
                state: self.state.clone(),
            });
            // The kill handle: the runner's deadline path requests the kill
            // through THIS handle — never through a detached pid — and the
            // fake records it against the same child the wait reaps. On a
            // child the wait already reaped (its reaped flag is armed) it is
            // a NO-OP: nothing is recorded, so the log stays proof that a
            // reaped child is never killed.
            let kill_ctl = ctl.clone();
            let kill: Box<dyn Fn() -> std::io::Result<()> + Send> = Box::new(move || {
                if kill_ctl.reaped.load(Ordering::SeqCst) {
                    return Ok(());
                }
                // Injected scheduler delay at the KILL stage: the runner has
                // decided to kill but the child has not been told — the wait
                // thread keeps polling while the deadline path is held open.
                if kill_ctl.delay_at == DelayAt::Kill {
                    std::thread::sleep(kill_ctl.delay);
                }
                kill_ctl.state.push(LogEntry::Kill { pid: kill_ctl.pid });
                kill_ctl.killed.store(true, Ordering::SeqCst);
                Ok(())
            });
            let wait_ctl = ctl;
            let wait: Box<
                dyn FnOnce() -> std::result::Result<std::process::Output, RunError> + Send,
            > = Box::new(move || wait_ctl.wait());
            Ok(SpawnedChild { pid, kill, wait })
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
    /// un-reaped zombie would still answer `kill(pid, 0)` with success. The
    /// pid comes from the test-only spawn observer: the PARENT records it
    /// synchronously at spawn time, so no child-written pidfile can race the
    /// deadline kill.
    #[test]
    fn real_runner_kills_and_reaps_a_stalled_child() {
        let spawned = Arc::new(Mutex::new(None));
        let runner = SshRunner::new().with_spawn_observer({
            let spawned = spawned.clone();
            Arc::new(move |pid: u32| *spawned.lock().unwrap() = Some(pid))
        });
        // The child execs `sleep`, so the observed pid IS the process the
        // runner must kill and reap.
        let argv = vec![
            "sh".to_string(),
            "-c".to_string(),
            "exec sleep 30".to_string(),
        ];
        let deadline = Duration::from_millis(100);
        let start = Instant::now();
        let res = runner.run(OpKind::Exec, &argv, None, Some(deadline));
        assert!(matches!(res, Err(RunError::Timeout { after }) if after == deadline));
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "a stalled child must be killed at the deadline, not after it"
        );
        // The observer recorded the pid before the deadline clock started, so
        // it is always available after `run` returns — nothing to race.
        let pid: i32 = spawned
            .lock()
            .unwrap()
            .expect("the spawn observer must record the child pid in the parent at spawn time")
            as i32;
        // SAFETY: `kill(pid, 0)` only probes existence; it sends no signal.
        let still_exists = unsafe { libc::kill(pid, 0) } == 0;
        assert!(
            !still_exists,
            "child {pid} must be reaped (a zombie would still exist)"
        );
    }

    /// THE timed-out-upload guarantee: a real child that NEVER reads stdin,
    /// with a payload larger than the pipe buffer (1 MiB » a 16–64 KiB pipe),
    /// blocks the wait closure's stdin write until the tiny deadline fires;
    /// the child is then KILLED — and its pid must be GONE afterwards,
    /// proving the timed-out upload was not only killed but also REAPED (an
    /// uncollected zombie would still answer `kill(pid, 0)`). The pid is
    /// recorded by the test-only spawn observer in the PARENT at spawn time:
    /// the OLD form asked the child to write its own pid to a file, which
    /// RACED the deadline kill (the child can be killed before it writes) —
    /// that was the flaky-test bug.
    #[test]
    fn real_runner_kills_and_reaps_a_timed_out_upload() {
        let spawned = Arc::new(Mutex::new(None));
        let runner = SshRunner::with_seam(
            Arc::new(RealRunner),
            Duration::from_millis(50),
            Duration::from_millis(50),
        )
        .with_spawn_observer({
            let spawned = spawned.clone();
            Arc::new(move |pid: u32| *spawned.lock().unwrap() = Some(pid))
        });
        // The child execs `sleep` WITHOUT ever reading stdin: the piped
        // payload fills the pipe buffer and the write blocks until the
        // deadline kill closes the pipe.
        let argv = vec![
            "sh".to_string(),
            "-c".to_string(),
            "exec sleep 30".to_string(),
        ];
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
        // The observer recorded the pid before the deadline clock started, so
        // it is always present after `run` returns.
        let pid: i32 = spawned
            .lock()
            .unwrap()
            .expect("the spawn observer must record the child pid in the parent at spawn time")
            as i32;
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

    /// Real-runner check for the consumed-handle contract: a kill request on
    /// a child whose wait ALREADY reaped it must not raise an error and —
    /// where observable from this side of the child — must not signal
    /// anything: the pid is gone (the process was collected), and because the
    /// kill goes through the OWNED handle (never a detached pid), it can
    /// never land on a process the OS recycled the pid to.
    #[test]
    fn kill_after_reap_does_not_raise_or_signal() {
        let seam = Arc::new(RealRunner);
        let child = seam
            .spawn(
                OpKind::Exec,
                &["sh".to_string(), "-c".to_string(), "exit 7".to_string()],
                None,
            )
            .expect("spawn must succeed");
        // The pid comes from the PARENT: the seam reads it synchronously at
        // spawn time (`Child::id`) and returns it on the handle — no
        // child-written pidfile.
        let SpawnedChild { pid, kill, wait } = child;
        let out = std::thread::spawn(wait)
            .join()
            .unwrap()
            .expect("a promptly-completing child must reap normally");
        assert_eq!(
            out.status.code(),
            Some(7),
            "the child's exit status must be preserved"
        );
        // The child was REAPED (the wait consumed the handle): a kill request
        // now must be a no-op that raises no error.
        let kill_res = kill();
        assert!(
            kill_res.is_ok(),
            "a kill after the reap must not raise an error, got: {kill_res:?}"
        );
        // Where observable: nothing was signalled — the pid is gone (reaped,
        // not a zombie), so the kill cannot land on an unrelated process.
        let pid: i32 = pid as i32;
        // SAFETY: `kill(pid, 0)` only probes existence; it sends no signal.
        let still_exists = unsafe { libc::kill(pid, 0) } == 0;
        assert!(!still_exists, "reaped child {pid} must be gone");
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

    fn delay_at_strategy() -> impl Strategy<Value = DelayAt> {
        prop_oneof![
            Just(DelayAt::Spawn),
            Just(DelayAt::Kill),
            Just(DelayAt::Wait),
            Just(DelayAt::AfterReap),
        ]
    }

    fn delay_size_strategy() -> impl Strategy<Value = DelaySize> {
        prop_oneof![
            Just(DelaySize::None),
            Just(DelaySize::Tiny),
            Just(DelaySize::Past),
        ]
    }

    /// Drive one generated (kind × stall × delay placement × delay size) case
    /// through the runner's deadline logic against the fake seam with the
    /// injected scheduler delay, then assert the invariants that must hold
    /// for EVERY returned outcome.
    fn run_one_delayed(kind: OpKind, stall: Stall, at: DelayAt, size: DelaySize) {
        // A 2ms deadline keeps the injected delays (and therefore the whole
        // property) sub-millisecond-ish: the delay buckets are fractions of
        // it, so the suite stays fast while the cases still race the deadline
        // around the kill/wait boundary.
        let deadline = Duration::from_millis(2);
        let delay = size.delay_for(deadline);
        let (seam, state) = FakeSeam::with_delays(stall, None, at, delay);
        let runner = SshRunner::with_seam(seam, deadline, deadline);
        let argv = vec!["ssh".to_string(), "runner-delay.test".to_string()];
        let stdin = (kind == OpKind::Upload).then(|| vec![0x5A; 4096]);
        let timeout = (kind == OpKind::Exec).then_some(deadline);
        let outcome = runner.run(kind, &argv, stdin.as_deref(), timeout);
        assert_delayed_invariants(kind, stall, at, size, &state, outcome);
    }

    /// Whether a generated (stall × delay) pair actually CROSSES the past
    /// deadline: a self-completing child whose wait is blocked past the
    /// deadline cannot finish before the deadline fires, so the runner must
    /// kill-then-reap a still-live wait — the race the delay is meant to
    /// provoke. Pairs that do not cross (a tiny delay, a spawn-stage delay, a
    /// hang that ends at the kill) exercise the opposite interleavings
    /// instead, so both sides of the deadline are covered across the cases.
    fn crosses_deadline(stall: Stall, at: DelayAt, size: DelaySize) -> bool {
        size == DelaySize::Past
            && matches!(at, DelayAt::Wait | DelayAt::AfterReap)
            && matches!(
                stall,
                Stall::Complete | Stall::NonZero | Stall::StdinWriteError | Stall::WaitError
            )
    }

    /// The scheduler-delay property's assertions: for EVERY returned outcome
    /// (timeout, success, write error, wait error, spawn error) zero live
    /// waiters must remain — the runner joined every wait thread before
    /// returning — and the spawned child must have been reaped exactly once
    /// (a failed spawn has no child: zero reaps).
    fn assert_delayed_invariants(
        kind: OpKind,
        stall: Stall,
        at: DelayAt,
        size: DelaySize,
        state: &FakeState,
        outcome: std::result::Result<std::process::Output, RunError>,
    ) {
        let label = format!("{kind:?} × {stall:?} × {at:?} {size:?}");
        assert_eq!(
            state.live_waiters(),
            0,
            "every returned outcome must leave zero live waiters ({label}): {} waiters still live",
            state.live_waiters()
        );
        if stall == Stall::SpawnError {
            assert_eq!(
                state.kill_pids(),
                Vec::<u32>::new(),
                "a failed spawn has nothing to kill ({label})"
            );
            assert_eq!(
                state.reap_pids(),
                Vec::<u32>::new(),
                "a failed spawn has nothing to reap ({label})"
            );
            return;
        }
        let (_, _, pid) = state.spawn();
        assert_eq!(
            state.reap_pids(),
            vec![pid],
            "the spawned child must be reaped exactly once ({label})"
        );
        // The delay must actually CROSS the deadline, not merely delay
        // everything: a self-completing child whose wait is blocked past the
        // deadline must surface as a Timeout — the deadline fired while the
        // wait thread was still live (the wait's own completion can only
        // arrive after the delay, which is past the deadline).
        if crosses_deadline(stall, at, size) {
            assert!(
                matches!(outcome, Err(RunError::Timeout { .. })),
                "a past-deadline wait delay must let the deadline win ({label}), got: {outcome:?}"
            );
        }
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

    /// THE reused-PID property: the fake reaps the child, then — the barrier
    /// parks the wait AFTER the reap but BEFORE the completion notification —
    /// the OS recycles the child's pid to a fresh UNRELATED child, exactly
    /// what a real OS does the moment a pid is reaped. A kill request made in
    /// that window (the old code would libc::kill the DETACHED pid and murder
    /// the unrelated process) must be a NO-OP on the consumed handle: no Kill
    /// is recorded after the reap, and the unrelated child holding the
    /// recycled pid is never killed.
    #[test]
    fn kill_after_reap_is_a_noop_even_when_the_pid_is_reused() {
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let state = Arc::new(FakeState::default());
        let seam = Arc::new(FakeSeam {
            state: state.clone(),
            stall: Stall::Hang,
            next_pid: AtomicU32::new(1),
            keyscan_line: None,
            after_reap_barrier: Some(barrier.clone()),
            delay_at: DelayAt::Wait,
            delay: Duration::ZERO,
        });
        let argv = vec!["ssh".to_string(), "true".to_string()];
        let child = seam
            .spawn(OpKind::Exec, &argv, None)
            .expect("the fake must spawn the stalling child");
        // Split the handle exactly as the runner does: the kill request (the
        // deadline path) and the wait closure (the wait thread). The pid is
        // the parent's own, read synchronously at spawn.
        let SpawnedChild { pid, kill, wait } = child;

        // The runner's deadline path: request the kill through the OWNED
        // handle.
        kill().expect("killing a live child must succeed");

        // The wait thread reaps the child, then parks on the barrier (reaped
        // but not yet completed).
        let waiter = std::thread::spawn(wait);
        let budget = Instant::now() + Duration::from_secs(5);
        while !state.reap_pids().contains(&pid) && Instant::now() < budget {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            state.reap_pids().contains(&pid),
            "the fake must reap the child before parking on the barrier"
        );

        // PID REUSE: the OS hands the just-reaped pid to an unrelated process.
        let reused = seam.spawn_reused_pid(pid, OpKind::Exec, &argv);

        // An attempted timeout kill on the CONSUMED handle — exactly what the
        // old detached-pid kill could still do — must be a NO-OP: no error,
        // nothing recorded, nothing signalled.
        kill().expect("a kill after the reap must not raise an error");
        assert!(
            !reused.killed.load(Ordering::SeqCst),
            "the unrelated process holding the recycled pid must never be killed"
        );

        // The log: exactly one kill of the reaped child, before its single
        // reap, and NOTHING after the reap can target the pid again — not
        // even once the pid was recycled to the unrelated child.
        assert_eq!(
            state.kill_pids(),
            vec![pid],
            "the reaped child must be killed exactly once"
        );
        assert_eq!(
            state.reap_pids(),
            vec![pid],
            "the reaped child must be reaped exactly once"
        );
        let log = state.log.lock().unwrap();
        let kill_pos = log
            .iter()
            .position(|e| matches!(e, LogEntry::Kill { .. }))
            .expect("the kill must be recorded");
        let reap_pos = log
            .iter()
            .position(|e| matches!(e, LogEntry::Reap { .. }))
            .expect("the reap must be recorded");
        assert!(kill_pos < reap_pos, "kill must precede reap");
        assert!(
            !log[reap_pos + 1..]
                .iter()
                .any(|e| matches!(e, LogEntry::Kill { pid: p } if *p == pid)),
            "no kill may target the reaped child's pid after its reap"
        );
        assert!(
            matches!(log.last(), Some(LogEntry::Spawn { pid: p, .. }) if *p == pid),
            "the reused-pid spawn must be the last recorded event"
        );

        // Release the reaped waiter and collect it.
        barrier.wait();
        waiter
            .join()
            .expect("the wait thread must finish")
            .expect("the reaped child returns its output");
        assert_eq!(state.live_waiters(), 0);
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
        // tiny injected deadline, so no case ever sleeps more than ~25ms. The
        // scheduler-delay test below injects delays (spawn/kill/wait stages ×
        // sub-deadline/past-deadline durations) and asserts EVERY outcome —
        // Timeout, success, write error, wait error, spawn error — leaves
        // zero live waiters and the spawned child reaped exactly once.
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

        // The scheduler-delay property: the fake seam's spawn/kill/wait
        // closures inject a controllable delay (placement × duration, both
        // relative to the tiny injected deadline) so the deadline races the
        // kill and wait paths — a self-completing child delayed past the
        // deadline must still be killed and reaped, a delayed kill must not
        // lose the reap, and a reap that lands before the kill must make the
        // kill a no-op. EVERY returned outcome must leave ZERO live waiters
        // and the spawned child reaped exactly once.
        #[test]
        fn every_outcome_leaves_zero_live_waiters_and_a_reaped_child(
            random_cases in prop::collection::vec(
                (op_strategy(), stall_strategy(), delay_at_strategy(), delay_size_strategy()),
                1..=5,
            )
        ) {
            // Every generated vector PREPENDS one guaranteed deadline-crossing
            // pair (a self-completing child whose wait is delayed past the
            // deadline): the property therefore provokes a kill-before-join
            // race in every single run — the injected delays cannot degenerate
            // into merely delaying everything — while the random legs cover
            // the complementary inside-the-deadline and kill-stage
            // interleavings (the join-before-kill reap side is also exercised
            // directly by the pid-reuse barrier test).
            let mut cases =
                vec![(OpKind::Upload, Stall::Complete, DelayAt::Wait, DelaySize::Past)];
            cases.extend(random_cases);
            for (kind, stall, at, size) in cases {
                run_one_delayed(kind, stall, at, size);
            }
        }
    }
}
