//! The transport stack: connectivity to one server's remote root.
//!
//! The [`Remote`] trait plus the in-process [`LocalTransport`] lead this
//! module; the production SSH transport over `ssh`/`scp`, host-identity
//! verification and pinning (a strict known-hosts file or a pre-verified
//! fingerprint, never trust-on-first-use), and the ONE bounded subprocess
//! runner every ssh operation goes through live in the `ssh` submodule group.
//!
//! Transport setup is split into two phases: [`Remote::prepare_identity`]
//! (verify/pin the host key) runs before ANY remote request — including a dry
//! run's status inspection — while [`Remote::provision_layout`] (create the
//! deployment-directory layout) runs only behind the push engine's
//! non-dry-run gate.
//!
//! # Submodules
//!
//! * `ssh` — the SSH transport group: the [`SshTransport`] itself plus
//!   host-key verification (`ssh::hostkey`) and the bounded subprocess
//!   runner (`ssh::runner`).

mod ssh;

pub use ssh::SshTransport;

use crate::env::SysEnv;
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
    /// Atomically create `rel` with `data` only if it does not already exist,
    /// and make the install DURABLE before returning: the create-new
    /// primitive (`durable_create_new`) writes a unique temp inside the
    /// destination directory, applies the FINAL MODE, fsyncs the file,
    /// publishes WITHOUT replacement (a concurrent winner is never replaced),
    /// removes the temp, and fsyncs the PARENT DIRECTORY — every failure
    /// propagates. Returns `Ok(true)` if the file was created, `Ok(false)` if
    /// it already existed (the existing content is left untouched; an
    /// identical retry converges — the existing entry is verified
    /// byte-and-mode identical — while a different winner is a conflict the
    /// caller's read-back comparison decides), or `Err` on other failures.
    /// This is the non-racy primitive used for lock acquisition:
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
    /// The TYPED replacement for the `exists`/`metadata` pair: `Ok(Some(meta))`
    /// when the entry exists, `Ok(None)` ONLY for a CONFIRMED `NotFound`, and
    /// `Err` for every other failure (permission, transport fault, ...). A
    /// failed read is NEVER indistinguishable from absence — callers must
    /// never consult `exists` (a `bool` that swallows errors) to disambiguate.
    fn metadata_opt(&self, rel: &Path) -> Result<Option<RemoteMeta>> {
        match self.metadata(rel) {
            Ok(m) => Ok(Some(m)),
            Err(crate::error::Error::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
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

/// The canonical FINAL MODE for immutable records installed through
/// [`Remote::try_write_new`]: the same `0o644` every sibling JSON record is
/// written with (the inventory, transactions, and the force-path lock rewrite
/// all use `Remote::write(..., 0o644)`). The published inode must carry THIS
/// mode — never the process umask the temp was created with — or the record's
/// permissions would silently depend on the caller's umask.
pub(crate) const IMMUTABLE_RECORD_MODE: u32 = 0o644;

/// The verdict of one canonical create-new attempt ([`durable_create_new`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CreateNewVerdict {
    /// The record was durably installed: exact bytes, the final mode, and a
    /// parent-directory-fsync'd directory entry all hold.
    Created,
    /// The destination already existed with IDENTICAL bytes and final mode:
    /// the identical retry converges — no error, no replace.
    AlreadyPresent,
    /// The destination already existed with DIFFERENT bytes or mode: a real
    /// conflict. The winner is NEVER replaced or modified; the caller's
    /// read-back comparison (every `try_write_new` caller performs one)
    /// decides the semantic verdict — a same-operation retry converges, a
    /// foreign winner is a genuine conflict.
    Conflict,
}

/// The seven stages of the canonical create-new sequence — the crash/failure
/// model's injection points. Test-only in practice (the proptest arms exactly
/// one stage), but plain `pub(crate)` so the primitive can consult it in both
/// build profiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CreateNewStep {
    CreateTemp,
    Write,
    Chmod,
    FileFsync,
    Publish,
    Unlink,
    ParentFsync,
}

/// One-shot stage failure injection for [`durable_create_new`]: armed for
/// EXACTLY ONE step, fires ONCE (then disarms), per-fixture (never a
/// process-global slot — two fixtures' faults can never consume each other).
/// Production code never arms one (the `None` options path); the durability
/// proptest arms exactly one stage to model a crash at that point.
#[derive(Debug)]
pub(crate) struct CreateNewFault {
    step: CreateNewStep,
    armed: std::sync::atomic::AtomicBool,
}

impl CreateNewFault {
    /// Arm a one-shot fault for `step`. Test-only (production never arms a
    /// fault); the type itself stays plain `pub(crate)` because the
    /// primitive's options carry it in both build profiles.
    #[cfg(test)]
    pub(crate) fn new(step: CreateNewStep) -> Self {
        Self {
            step,
            armed: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// Consume the fault: fire exactly once when `step` matches the armed
    /// stage (and never again).
    pub(crate) fn consume(&self, step: CreateNewStep) -> bool {
        use std::sync::atomic::Ordering;
        self.step == step && self.armed.swap(false, Ordering::SeqCst)
    }
}

/// Settings for one [`durable_create_new`] attempt: the FINAL MODE the
/// published inode must carry, and (test-only) the one-shot stage fault.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CreateNewOptions<'a> {
    pub(crate) mode: u32,
    pub(crate) fault: Option<&'a CreateNewFault>,
}

/// THE ONE CANONICAL CREATE-NEW PRIMITIVE — the durable install protocol for
/// immutable records (commit markers, locks, the protocol marker, assignment
/// and release records). Realized by [`LocalTransport::try_write_new`] on
/// this host and by the `SshTransport` remote script (`write_new_cmd`) with
/// the IDENTICAL seven-step sequence:
///
/// 1. **create temp** — a unique, dot-prefixed temp name INSIDE the
///    destination directory (so the no-replace publish is atomic within the
///    same directory), created with create-new semantics;
/// 2. **write** — all bytes;
/// 3. **final chmod** — the caller's FINAL MODE is applied to the temp
///    BEFORE the fsync, so the published inode carries the exact mode, never
///    the process umask;
/// 4. **file fsync** — the temp file is durable;
/// 5. **no-replace publish** — `link(2)` under the final name: `EEXIST` is
///    the conflict verdict (the winner is NEVER replaced), every other
///    failure propagates;
/// 6. **unlink temp** — the temp name is removed (best-effort cleanup — the
///    ERROR path propagates the REAL failure);
/// 7. **parent-directory fsync** — the PARENT DIRECTORY is fsync'd (the step
///    the old code claimed but never performed) so the directory entry is
///    durable; a FAILED parent fsync is a propagated error.
///
/// Every state failure in every step PROPAGATES as an error — `Ok(Created)`
/// therefore implies exact bytes (the fully-written inode), the final mode,
/// and a DURABLE directory entry. On a conflict (step 5's `EEXIST`) the
/// existing entry is read back and compared byte-and-mode to the intended
/// content: identical → [`CreateNewVerdict::AlreadyPresent`] (the identical
/// retry converges — no error, no replace); different →
/// [`CreateNewVerdict::Conflict`] (a genuine conflict — never replaced).
/// `Ok(AlreadyPresent)` runs the parent fsync too, so the convergent path
/// still returns with a durable entry.
pub(crate) fn durable_create_new(
    base: &Path,
    rel: &Path,
    data: &[u8],
    options: CreateNewOptions<'_>,
) -> Result<CreateNewVerdict> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    let p = join(base, rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::transport(format!("mkdir {}: {e}", parent.display())))?;
    }
    // 1. create temp: a unique dot-prefixed name inside the destination
    //    directory, with create-new semantics (never truncates a stale temp
    //    a crashed controller left behind).
    let tmp = p.with_file_name(format!(
        ".{}.tmp.{}.{}",
        p.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default(),
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed),
    ));
    let fail = |step: CreateNewStep| options.fault.is_some_and(|f| f.consume(step));
    if fail(CreateNewStep::CreateTemp) {
        return Err(Error::transport(format!(
            "test fault: create-new step {step:?} forced to fail (once)",
            step = CreateNewStep::CreateTemp
        )));
    }
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
    // 2. write — all bytes.
    if fail(CreateNewStep::Write) {
        return Err(Error::transport(format!(
            "test fault: create-new step {step:?} forced to fail (once)",
            step = CreateNewStep::Write
        )));
    }
    f.write_all(data)
        .map_err(|e| Error::transport(format!("write {}: {e}", tmp.display())))?;
    // 3. final chmod — the FINAL MODE is applied to the temp BEFORE the
    //    fsync, so the published inode carries the caller's mode, never the
    //    process umask.
    if fail(CreateNewStep::Chmod) {
        return Err(Error::transport(format!(
            "test fault: create-new step {step:?} forced to fail (once)",
            step = CreateNewStep::Chmod
        )));
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(options.mode & 0o7777))
        .map_err(|e| Error::transport(format!("chmod {}: {e}", tmp.display())))?;
    // 4. file fsync — the temp file is durable.
    if fail(CreateNewStep::FileFsync) {
        return Err(Error::transport(format!(
            "test fault: create-new step {step:?} forced to fail (once)",
            step = CreateNewStep::FileFsync
        )));
    }
    f.sync_all()
        .map_err(|e| Error::transport(format!("fsync {}: {e}", tmp.display())))?;
    drop(f);
    // 5. no-replace publish — link(2) fails with EEXIST when a concurrent
    //    writer won; the winner is NEVER replaced. On EEXIST the existing
    //    entry is VERIFIED (verify-on-retry): byte-and-mode identical →
    //    AlreadyPresent (the identical retry converges), anything else →
    //    Conflict (a genuine conflict).
    if fail(CreateNewStep::Publish) {
        return Err(Error::transport(format!(
            "test fault: create-new step {step:?} forced to fail (once)",
            step = CreateNewStep::Publish
        )));
    }
    let verdict = match std::fs::hard_link(&tmp, &p) {
        Ok(()) => CreateNewVerdict::Created,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let verify = (|| -> Result<CreateNewVerdict> {
                let existing = std::fs::read(&p)
                    .map_err(|e| Error::transport(format!("verify read {}: {e}", p.display())))?;
                let meta = std::fs::metadata(&p)
                    .map_err(|e| Error::transport(format!("verify stat {}: {e}", p.display())))?;
                if existing == data && (meta.mode() & 0o7777) == (options.mode & 0o7777) {
                    Ok(CreateNewVerdict::AlreadyPresent)
                } else {
                    Ok(CreateNewVerdict::Conflict)
                }
            })();
            match verify {
                Ok(v) => v,
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e);
                }
            }
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::transport(format!("install {}: {e}", p.display())));
        }
    };
    // 6. unlink temp — remove ONLY the temp this invocation created
    //    (best-effort cleanup; the REAL failure above already propagated).
    if fail(CreateNewStep::Unlink) {
        return Err(Error::transport(format!(
            "test fault: create-new step {step:?} forced to fail (once)",
            step = CreateNewStep::Unlink
        )));
    }
    let _ = std::fs::remove_file(&tmp);
    // 7. parent-directory fsync — the step the old code CLAIMED but never
    //    performed: fsync the PARENT DIRECTORY so the published directory
    //    entry survives a crash. FAIL-CLOSED: a failed open OR a failed
    //    fsync is a propagated error (never swallowed). Runs for a Created
    //    install AND for an AlreadyPresent retry (the convergent entry is
    //    made durable too); a Conflict's entry is not ours to bless — it is
    //    only ever read, never modified.
    if matches!(
        verdict,
        CreateNewVerdict::Created | CreateNewVerdict::AlreadyPresent
    ) && let Some(parent) = p.parent()
    {
        if fail(CreateNewStep::ParentFsync) {
            return Err(Error::transport(format!(
                "test fault: create-new step {step:?} forced to fail (once)",
                step = CreateNewStep::ParentFsync
            )));
        }
        let dir = std::fs::File::open(parent)
            .map_err(|e| Error::transport(format!("open dir {}: {e}", parent.display())))?;
        dir.sync_all()
            .map_err(|e| Error::transport(format!("fsync dir {}: {e}", parent.display())))?;
    }
    Ok(verdict)
}

/// A transport that operates on a local directory, executing commands on the
/// host. It mirrors the SSH remote layout exactly.
pub struct LocalTransport {
    base: PathBuf,
    /// The child environment snapshot: every spawned child (`exec`, `df`, the
    /// timeout `kill`) receives THIS snapshot as its ENTIRE environment
    /// ([`SysEnv::apply_to_command`]: `env_clear` first, then the snapshot's
    /// variables) — a deterministic HERMETIC environment resolved at the
    /// construction boundary, never whatever the parent env looks like at
    /// spawn time, and nothing else.
    env: SysEnv,
}

impl LocalTransport {
    /// Build a transport rooted at `base` whose children run with the
    /// environment snapshot `env` (see [`SysEnv::apply_to_command`]) as their
    /// ENTIRE environment. Construction
    /// is side-effect-free: no directories are created and nothing is
    /// touched on disk. Call [`Remote::provision_layout`] to create the
    /// deployment layout before the first mutation (the push engine does
    /// this behind its non-dry-run gate).
    ///
    /// The FILESYSTEM ROOT is refused (defense in depth, mirroring the
    /// [`crate::identity::AbsoluteDeployDir`] parse rule): a transport rooted at
    /// `/` would make the deployment cleanup (rotation/retention deleting
    /// stale generations, the GC sweep) operate on the system root, so the
    /// base must have at least one normal path component below the root.
    pub fn new(env: &SysEnv, base: PathBuf) -> Result<Self> {
        if !has_normal_component_below_root(&base) {
            return Err(Error::transport(format!(
                "deploy_dir {:?} must have at least one normal path component below the root (the filesystem root is not a valid deploy_dir)",
                base
            )));
        }
        Ok(LocalTransport {
            base,
            env: env.clone(),
        })
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
        // The ONE canonical create-new primitive (see `durable_create_new`):
        // temp -> write -> final chmod -> file fsync -> no-replace publish ->
        // unlink temp -> parent-directory fsync, every failure propagated, and
        // verify-on-retry. The immutable records this installs carry the
        // canonical final mode (`IMMUTABLE_RECORD_MODE`), never the umask.
        match durable_create_new(
            &self.base,
            rel,
            data,
            CreateNewOptions {
                mode: IMMUTABLE_RECORD_MODE,
                fault: None,
            },
        )? {
            CreateNewVerdict::Created => Ok(true),
            CreateNewVerdict::AlreadyPresent | CreateNewVerdict::Conflict => Ok(false),
        }
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
        self.metadata_opt(rel)?.ok_or_else(|| {
            Error::NotFound(format!(
                "stat {}: not found",
                join(&self.base, rel).display()
            ))
        })
    }

    fn metadata_opt(&self, rel: &Path) -> Result<Option<RemoteMeta>> {
        let p = join(&self.base, rel);
        match std::fs::symlink_metadata(&p) {
            Ok(m) => Ok(Some(meta_to_remote(&m))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::transport(format!("stat {}: {e}", p.display()))),
        }
    }

    fn exec(&self, argv: &[String], timeout: Duration) -> Result<ExecOutcome> {
        if argv.is_empty() {
            return Err(Error::transport("empty command"));
        }
        let mut cmd = std::process::Command::new(&argv[0]);
        self.env.apply_to_command(&mut cmd);
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
                let mut kill_cmd = std::process::Command::new("kill");
                self.env.apply_to_command(&mut kill_cmd);
                let _ = kill_cmd.arg("-9").arg(pid.to_string()).status();
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
        let mut cmd = std::process::Command::new("df");
        self.env.apply_to_command(&mut cmd);
        let out = cmd
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

        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let t = LocalTransport::new(&SysEnv::from_process(), dir.path().join("r")).unwrap();
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
            let err = LocalTransport::new(&SysEnv::from_process(), std::path::PathBuf::from(bad))
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
            LocalTransport::new(&SysEnv::from_process(), std::path::PathBuf::from(ok))
                .expect("a deploy_dir with a normal component below the root is accepted");
        }
    }

    #[test]
    fn symlink_rename_exists() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let t = LocalTransport::new(&SysEnv::from_process(), dir.path().join("r")).unwrap();
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

    /// The transport-level contract of the shared primitive: `try_write_new`
    /// reports `Ok(true)` for a fresh DURABLE install, `Ok(false)` for an
    /// identical retry (convergent — the winner is verified byte-and-mode
    /// identical, never replaced), and `Ok(false)` for a different-content
    /// conflict (the winner is never touched; the caller's read-back
    /// comparison decides the semantic verdict). The installed record carries
    /// the canonical final mode, not the process umask.
    #[test]
    fn try_write_new_durable_install_and_conflict_contract() {
        use std::os::unix::fs::MetadataExt;

        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let t = LocalTransport::new(&SysEnv::from_process(), dir.path().join("r")).unwrap();
        let rel = Path::new("state/op.json");
        let data = b"{\"op\":\"1\"}";

        assert!(t.try_write_new(rel, data).unwrap(), "a fresh install wins");
        let p = t.root().join(rel);
        assert_eq!(std::fs::read(&p).unwrap(), data, "exact bytes installed");
        assert_eq!(
            std::fs::metadata(&p).unwrap().mode() & 0o7777,
            IMMUTABLE_RECORD_MODE & 0o7777,
            "the record must carry the canonical final mode"
        );
        // Identical retry: convergent — Ok(false), no error, no replace.
        assert!(
            !t.try_write_new(rel, data).unwrap(),
            "an identical retry converges to already-present"
        );
        assert_eq!(
            std::fs::read(&p).unwrap(),
            data,
            "the identical retry must not touch the winner"
        );
        // Different content: the conflict verdict — Ok(false), never replaced.
        assert!(
            !t.try_write_new(rel, b"other").unwrap(),
            "a different-content conflict is the verdict"
        );
        assert_eq!(
            std::fs::read(&p).unwrap(),
            data,
            "the conflict must NEVER replace the winner"
        );
    }

    /// The durability property's scenario dimension: the healthy install, a
    /// one-shot crash/failure at one of the SEVEN stages, and the two
    /// pre-existing-winner retry cases (identical / different).
    #[derive(Clone, Copy, Debug)]
    enum CreateNewScenario {
        Healthy,
        FailAt(CreateNewStep),
        PreExistingIdentical,
        PreExistingDifferent,
        PreExistingDifferentMode,
    }

    fn create_new_scenario() -> impl Strategy<Value = CreateNewScenario> {
        prop_oneof![
            Just(CreateNewScenario::Healthy),
            Just(CreateNewScenario::PreExistingIdentical),
            Just(CreateNewScenario::PreExistingDifferent),
            Just(CreateNewScenario::PreExistingDifferentMode),
            Just(CreateNewScenario::FailAt(CreateNewStep::CreateTemp)),
            Just(CreateNewScenario::FailAt(CreateNewStep::Write)),
            Just(CreateNewScenario::FailAt(CreateNewStep::Chmod)),
            Just(CreateNewScenario::FailAt(CreateNewStep::FileFsync)),
            Just(CreateNewScenario::FailAt(CreateNewStep::Publish)),
            Just(CreateNewScenario::FailAt(CreateNewStep::Unlink)),
            Just(CreateNewScenario::FailAt(CreateNewStep::ParentFsync)),
        ]
    }

    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    proptest! {
        // THE DURABILITY CRASH/FAILURE MODEL — one property, every case:
        //
        // * `Ok(Created)` implies EXACT BYTES, the FINAL MODE, and a DURABLE
        //   DIRECTORY ENTRY — a fresh read of the destination directory (a
        //   simulated crash-after-return) still sees the entry, because the
        //   parent fsync established it;
        // * CONFLICT NEVER REPLACES: a destination pre-existing with
        //   DIFFERENT bytes (or a different mode over identical bytes) is
        //   never modified — the primitive returns the conflict verdict and
        //   the winner stays intact;
        // * RETRIES CONVERGE: after a one-shot failure at ANY of the seven
        //   stages, an IDENTICAL retry succeeds and leaves the destination
        //   EITHER the fully-written identical content OR absent — never a
        //   partial/torn record;
        // * FAILURE PROPAGATION: the faulted attempt is an `Err` naming the
        //   injected stage — never a swallowed `Ok` that claims durability.
        //
        // Bounded cases (full budget under `DEPLOY_FULL_TESTS=1`, fast
        // default), fixed seed 0x5EED_5EED (house style), no persistence, and
        // each case drives its OWN fixture (per-fixture one-shot fault,
        // structurally isolated).
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(64),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn durable_create_new_crash_failure_model(
            content in prop::collection::vec(any::<u8>(), 0..128),
            mode in prop_oneof![
                Just(0o600u32),
                Just(0o644u32),
                Just(0o755u32),
                Just(0o640u32),
            ],
            scenario in create_new_scenario(),
        ) {
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let root = dir.path().to_path_buf();
            let rel = Path::new("state/record.bin");
            let dest = root.join(rel);
            let dest_name = rel.file_name().unwrap().to_string_lossy().into_owned();

            match scenario {
                CreateNewScenario::Healthy => {
                    let verdict = durable_create_new(
                        &root,
                        rel,
                        &content,
                        CreateNewOptions { mode, fault: None },
                    )
                    .expect("the healthy install must succeed");
                    prop_assert_eq!(verdict, CreateNewVerdict::Created);
                    // Ok(Created) implies EXACT BYTES ...
                    prop_assert_eq!(
                        std::fs::read(&dest).expect("installed record must be readable"),
                        content,
                        "Ok(Created) must imply exact bytes"
                    );
                    // ... the FINAL MODE (never the process umask) ...
                    let meta = std::fs::metadata(&dest).expect("installed record must exist");
                    prop_assert_eq!(
                        meta.mode() & 0o7777,
                        mode & 0o7777,
                        "Ok(Created) must imply the final mode"
                    );
                    // ... and a DURABLE DIRECTORY ENTRY: the parent fsync
                    // established it, so a fresh directory read (a simulated
                    // crash-after-return) still sees the entry.
                    let names: Vec<String> = std::fs::read_dir(dest.parent().unwrap())
                        .expect("the parent must be readable")
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect();
                    prop_assert!(
                        names.contains(&dest_name),
                        "the parent fsync must have established the directory entry, dir has: {names:?}"
                    );
                }
                CreateNewScenario::FailAt(step) => {
                    let fault = CreateNewFault::new(step);
                    // FAILURE PROPAGATION: the faulted attempt is an Err
                    // naming the injected stage — never a swallowed Ok.
                    let err = durable_create_new(
                        &root,
                        rel,
                        &content,
                        CreateNewOptions { mode, fault: Some(&fault) },
                    )
                    .expect_err("a failure at every stage must propagate as Err");
                    prop_assert!(
                        err.to_string().contains("forced to fail (once)"),
                        "the injected fault must be the propagated failure, got: {err}"
                    );
                    // RETRIES CONVERGE: an identical retry (the fault is
                    // one-shot, already consumed) must succeed and leave the
                    // destination EITHER the fully-written identical content
                    // OR absent — never a partial/torn file.
                    let retry = durable_create_new(
                        &root,
                        rel,
                        &content,
                        CreateNewOptions { mode, fault: None },
                    )
                    .expect("the identical retry must converge");
                    prop_assert!(
                        matches!(
                            retry,
                            CreateNewVerdict::Created | CreateNewVerdict::AlreadyPresent
                        ),
                        "the identical retry must converge, got: {retry:?}"
                    );
                    if dest.exists() {
                        prop_assert_eq!(
                            std::fs::read(&dest).expect("installed record must be readable"),
                            content,
                            "the destination must be the fully-written identical content, never partial"
                        );
                        let meta = std::fs::metadata(&dest).expect("installed record must exist");
                        prop_assert_eq!(
                            meta.mode() & 0o7777,
                            mode & 0o7777,
                            "the converged record must carry the intended final mode"
                        );
                    }
                }
                CreateNewScenario::PreExistingIdentical => {
                    // A previous successful publish (identical bytes + mode):
                    // the identical retry converges — AlreadyPresent, no
                    // error, no replace.
                    durable_create_new(&root, rel, &content, CreateNewOptions { mode, fault: None })
                        .expect("the first install must succeed");
                    let verdict =
                        durable_create_new(&root, rel, &content, CreateNewOptions { mode, fault: None })
                            .expect("an identical retry must converge, not error");
                    prop_assert_eq!(verdict, CreateNewVerdict::AlreadyPresent);
                    prop_assert_eq!(
                        std::fs::read(&dest).unwrap(),
                        content,
                        "the identical retry must not touch the winner"
                    );
                }
                CreateNewScenario::PreExistingDifferent => {
                    // A concurrent winner with DIFFERENT content: a genuine
                    // conflict — the verdict, never a replace, and the
                    // winner's bytes stay intact.
                    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                    let other: Vec<u8> = if content.is_empty() {
                        vec![0u8]
                    } else {
                        content.iter().map(|b| b.wrapping_add(1)).collect()
                    };
                    prop_assert_ne!(&other, &content, "the winner must differ from the intent");
                    std::fs::write(&dest, &other).unwrap();
                    let verdict = durable_create_new(
                        &root,
                        rel,
                        &content,
                        CreateNewOptions { mode, fault: None },
                    )
                    .expect("a conflict is a verdict, not an I/O error");
                    prop_assert_eq!(verdict, CreateNewVerdict::Conflict);
                    prop_assert_eq!(
                        std::fs::read(&dest).unwrap(),
                        other,
                        "the conflict must NEVER replace the winner"
                    );
                }
                CreateNewScenario::PreExistingDifferentMode => {
                    // Identical bytes but a DIFFERENT mode: still a genuine
                    // conflict (the mode is part of the record) — the verdict,
                    // never a replace.
                    durable_create_new(&root, rel, &content, CreateNewOptions { mode, fault: None })
                        .expect("the first install must succeed");
                    let other_mode = if (mode & 0o7777) == 0o600 { 0o644 } else { 0o600 };
                    std::fs::set_permissions(
                        &dest,
                        std::fs::Permissions::from_mode(other_mode),
                    )
                    .unwrap();
                    let verdict =
                        durable_create_new(&root, rel, &content, CreateNewOptions { mode, fault: None })
                            .expect("a mode mismatch is a verdict, not an I/O error");
                    prop_assert_eq!(verdict, CreateNewVerdict::Conflict);
                    let meta = std::fs::metadata(&dest).unwrap();
                    prop_assert_eq!(
                        meta.mode() & 0o7777,
                        other_mode,
                        "the mode mismatch must never be replaced"
                    );
                }
            }
        }
    }
}
