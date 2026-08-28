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
//! * `runner` — the shared bounded child-runner: synchronized child
//!   ownership, process-group termination, and mandatory wait/reap before
//!   every returned outcome (used by [`LocalTransport::exec`]).
//! * `scripted` — the deterministic fake exec the deployment/state-machine
//!   property tests inject (test-only): scripted outcomes keyed by argv, no
//!   subprocess, no wall-clock — the parallel-safety seam.
//! * `ssh` — the SSH transport group: the [`SshTransport`] itself plus
//!   host-key verification (`ssh::hostkey`) and the bounded subprocess
//!   runner (`ssh::runner`).

mod runner;
#[cfg(test)]
pub(crate) mod scripted;
mod ssh;

pub use runner::{
    ChildRunner, KillSeam, RealKill, RunError, RunOutcome, RunnerConfig, kill_process_group,
};
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

/// THE command-execution seam behind [`LocalTransport::exec`]. Production
/// uses [`ChildRunner`] (the bounded real runner: spawn into an own process
/// group, bounded wait, group termination, mandatory reap before every
/// outcome); the deterministic deployment/state-machine properties inject a
/// scripted fake (`ScriptedExec`, test-only: scripted outcomes keyed by argv
/// — no subprocess, no wall-clock). The seam is what makes the property
/// suites parallel-safe: the deterministic tests exercise the SAME logic
/// branches (verification success/failure, activation, compensation) without
/// spawning real processes or contending for the pid space.
pub trait Exec: Send + Sync {
    /// Execute `argv` (no shell) bounded by `timeout`, returning the
    /// outcome. A conforming implementation never leaves a live process
    /// behind and never blocks past `timeout`.
    fn exec(&self, argv: &[String], timeout: Duration) -> Result<ExecOutcome>;
}

/// The REAL exec: [`ChildRunner`] through the outcome mapping the transport
/// always applied (a timed-out child surfaces as `exit_code: -1` with the
/// runner's stderr; a kill/reap failure is an error, never a fake success).
impl Exec for ChildRunner {
    fn exec(&self, argv: &[String], timeout: Duration) -> Result<ExecOutcome> {
        match ChildRunner::exec(self, argv, timeout) {
            Ok(RunOutcome::Exited {
                exit_code,
                stdout,
                stderr,
            }) => Ok(ExecOutcome {
                exit_code,
                stdout,
                stderr,
            }),
            Ok(RunOutcome::TimedOut { stderr }) => Ok(ExecOutcome {
                exit_code: -1,
                stdout: String::new(),
                stderr,
            }),
            Err(e) => Err(Error::transport(e.to_string())),
        }
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
    /// propagates. Returns the TYPED [`CreateNewVerdict`]: `Created` when the
    /// record was durably installed by this call; `AlreadyPresent` ONLY when
    /// the destination already existed and VERIFIED as an identical entry —
    /// an `lstat`, a REGULAR FILE, the EXACT final mode, and byte-identical
    /// content (the identical retry converges — the parent directory is
    /// synced here too, so the retry returns with a durable entry);
    /// `Conflict` carrying the TYPED [`VerifiedExisting`] reason when it
    /// existed but did NOT verify (different bytes, a MODE MISMATCH, a
    /// directory/symlink/other entry — a symlink is never followed — or an
    /// unreadable entry; the winner is NEVER replaced or modified, and the
    /// caller receives the typed reason, never an undifferentiated conflict
    /// it can reinterpret); or `Err` on every other failure (a pre-install
    /// failure, a failed parent-dir sync, a transport fault — never a
    /// verdict). This is
    /// the non-racy primitive used for lock acquisition:
    /// `exists`-then-`write` would let two controllers both observe "no lock"
    /// and both proceed.
    fn try_write_new(&self, rel: &Path, data: &[u8]) -> Result<CreateNewVerdict>;
    /// [`Remote::try_write_new`] with a CALLER-CHOSEN content equivalence for
    /// the EEXIST verification: `Semantic` (JSON parse-equal, byte-exact
    /// fallback) is used by the release-file publisher whose idempotent
    /// re-publication legitimately re-serializes the same contract with
    /// different key order/whitespace. Transports whose centralized
    /// verification can apply the equivalence directly (LocalTransport,
    /// SshTransport) override this; the default performs the byte-exact
    /// [`Remote::try_write_new`] and, for `Semantic`, re-reads and
    /// semantically compares a `ContentMismatch` conflict — the identical
    /// outcome a direct application would produce.
    fn try_write_new_with(
        &self,
        rel: &Path,
        data: &[u8],
        equivalence: ContentEquivalence,
    ) -> Result<CreateNewVerdict> {
        let verdict = self.try_write_new(rel, data)?;
        if equivalence != ContentEquivalence::Semantic {
            return Ok(verdict);
        }
        match verdict {
            CreateNewVerdict::Conflict(VerifiedExisting::ContentMismatch) => {
                // The transport's Exact verification reported a content
                // mismatch; the caller's SEMANTIC equivalence may still
                // accept the winner (JSON key order/whitespace are not part
                // of the contract). Type and mode were already verified
                // (that is why the reason is ContentMismatch, not
                // NotRegularFile/ModeMismatch), so only the content needs
                // re-comparing.
                let existing = self.read(rel)?;
                if content_equivalent(&existing, data, ContentEquivalence::Semantic) {
                    Ok(CreateNewVerdict::AlreadyPresent)
                } else {
                    Ok(CreateNewVerdict::Conflict(
                        VerifiedExisting::ContentMismatch,
                    ))
                }
            }
            v => Ok(v),
        }
    }
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
    /// Atomically remove `rel` ONLY IF its content is byte-identical to
    /// `expected` — the compare-and-delete primitive that makes stale
    /// releases and expired-lease breaks safe. Returns the TYPED verdict
    /// ([`RemoveIfVerdict`]); every transport failure propagates as `Err`
    /// (never a fabricated verdict, never a silent no-op). The production
    /// transports ([`LocalTransport`], [`SshTransport`]) realize it
    /// ATOMICALLY: the entry is CLAIMED by an atomic rename to a unique
    /// same-directory temp (only one contender can win), verified against
    /// `expected`, and either deleted (match) or RESTORED no-replace
    /// (mismatch — a successor's lock is never removed, never replaced).
    /// The DEFAULT implementation is the NON-ATOMIC read-compare-remove
    /// fallback: adequate for single-process test wrappers that never race
    /// the lock, and only those; production must override it.
    fn remove_file_if(&self, rel: &Path, expected: &[u8]) -> Result<RemoveIfVerdict> {
        // Typed absence probe first: a transport failure is an `Err`, never
        // a silent `Absent`.
        let Some(_) = self.metadata_opt(rel)? else {
            return Ok(RemoveIfVerdict::Absent);
        };
        let cur = self.read(rel)?;
        if cur == expected {
            self.remove_file(rel)?;
            Ok(RemoveIfVerdict::Removed)
        } else {
            Ok(RemoveIfVerdict::Mismatch)
        }
    }
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

/// The verdict of one atomic compare-and-delete attempt
/// ([`Remote::remove_file_if`]): the entry was removed because it carried
/// EXACTLY the expected bytes ([`RemoveIfVerdict::Removed`]), the entry
/// existed but did NOT match ([`RemoveIfVerdict::Mismatch`] — it is never
/// removed, and a no-replace restore put it back), or the entry was
/// GENUINELY absent ([`RemoveIfVerdict::Absent`]). `pub` because it crosses
/// the [`Remote`] trait boundary: every transport's `remove_file_if` returns
/// it, and every caller (and external test crate) branches on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoveIfVerdict {
    /// The entry existed with content byte-identical to `expected` and was
    /// removed: the slot is now free.
    Removed,
    /// The entry existed but its content differed from `expected`: it was
    /// restored (or left as the winner's), NEVER removed. A stale release or
    /// a stale break lands here — the successor's lock survives.
    Mismatch,
    /// The entry was genuinely absent: nothing to remove (an idempotent
    /// success for a release, a free slot for an acquire).
    Absent,
}

/// The verdict of one canonical create-new attempt ([`durable_create_new`]).
/// `pub` because it crosses the [`Remote`] trait boundary: every transport's
/// `try_write_new` returns it, and every caller (and external test crate)
/// branches on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreateNewVerdict {
    /// The record was durably installed: exact bytes, the final mode, and a
    /// parent-directory-fsync'd directory entry all hold.
    Created,
    /// The destination already existed and VERIFIED as an identical entry:
    /// the `lstat` succeeded, the entry is a REGULAR FILE, its mode matched
    /// EXACTLY, and its content matched per the caller's requested
    /// equivalence — the identical retry converges, no error, no replace.
    AlreadyPresent,
    /// The destination already existed but did NOT verify as an identical
    /// entry: the TYPED [`VerifiedExisting`] reason says why (not a regular
    /// file — directory/symlink/other, never followed; a MODE MISMATCH; a
    /// CONTENT MISMATCH per the caller's equivalence; unreadable; or
    /// vanished). The winner is NEVER replaced or modified, and the caller
    /// receives the typed reason — it can never reinterpret an
    /// undifferentiated conflict as "already present, fine".
    Conflict(VerifiedExisting),
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

/// The caller-chosen content-equivalence relation applied to an EXISTING
/// entry during create-new verification: the create-new EEXIST path verifies
/// the existing entry and the CALLER decides whether byte-exact equality is
/// required or whether a semantic (JSON parse-equal) relation is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentEquivalence {
    /// Byte-exact: the existing entry's bytes must equal the intended bytes.
    /// Every immutable record's identical retry (markers, locks, the protocol
    /// marker, assignment records) converges under this relation.
    Exact,
    /// Semantic: JSON parse-equal (object key order and whitespace are not
    /// part of the contract), falling back to byte-exact when either side is
    /// not JSON. Used by the release-file publisher whose idempotent
    /// re-publication legitimately re-serializes the same contract with
    /// different key order/whitespace.
    Semantic,
}

/// WHY an existing create-new destination is not a clean identical retry —
/// the typed companion of [`CreateNewVerdict::Conflict`]. Every reason is a
/// distinct variant: a caller can never reinterpret an undifferentiated
/// conflict (a directory, a symlink, a mode mismatch, or unreadable entry
/// can never be silently accepted as "already present, fine").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotRegularFileKind {
    /// A directory occupies the destination path.
    Directory,
    /// A symlink occupies the destination path — reported from the `lstat`
    /// itself, NEVER followed (a symlink pointing at a matching regular file
    /// is still a conflict, never an accepted retry).
    Symlink,
    /// Any other non-regular kind: a fifo, socket, device, ...
    Other,
}

/// The TYPED result of verifying an EXISTING create-new destination against
/// the intended content — the single lstat-based verification shared by BOTH
/// transports (the local [`durable_create_new`] verify-on-retry and the SSH
/// transport's EEXIST verification). `Ok` is reached ONLY when the `lstat`
/// succeeded AND the entry is a REGULAR FILE AND its content was read; every
/// other outcome is one of the explicit reasons below. The verdict
/// [`CreateNewVerdict::AlreadyPresent`] is produced ONLY when this is
/// [`VerifiedExisting::Ok`] with `mode_ok` true (the mode matched EXACTLY)
/// and the content matched per the caller's requested equivalence; EVERY
/// other variant is [`CreateNewVerdict::Conflict`] carrying this reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifiedExisting {
    /// The `lstat` succeeded, the entry is a REGULAR FILE, and its content
    /// was read. `mode_ok` records whether the entry's mode matched the
    /// required mode EXACTLY (a mismatch is reported as
    /// [`VerifiedExisting::ModeMismatch`]; `mode_ok` stays a first-class
    /// dimension so the verdict constructor must consult it — an entry is
    /// only ever [`CreateNewVerdict::AlreadyPresent`] when it is true) and
    /// `content` records the caller's requested content equivalence, which
    /// HELD (a failed comparison is [`VerifiedExisting::ContentMismatch`]).
    Ok {
        mode_ok: bool,
        content: ContentEquivalence,
    },
    /// The `lstat` reported the destination absent. Should not happen on the
    /// EEXIST-confirmed path (the no-clobber publish observed the
    /// destination), but typed rather than assumed.
    NotFound,
    /// The `lstat` succeeded but the entry is NOT a regular file: a
    /// directory, a symlink (never followed), or another kind.
    NotRegularFile { kind: NotRegularFileKind },
    /// The entry is a regular file whose mode does NOT match the required
    /// mode EXACTLY — the mode is part of the immutable record, so a mode
    /// mismatch is a real conflict, never an accepted retry.
    ModeMismatch { actual: u32, required: u32 },
    /// The entry is a regular file with the EXACT required mode, but its
    /// content did NOT match per the caller's requested equivalence.
    ContentMismatch,
    /// The entry exists (and is a regular file) but its content could not be
    /// read during verification (permission, I/O fault): a real failure, never
    /// a fabricated verdict. The payload carries the errno-bearing error text.
    Unreadable(String),
}

/// Settings for one [`durable_create_new`] attempt: the FINAL MODE the
/// published inode must carry, the caller-chosen CONTENT EQUIVALENCE the
/// EEXIST verification applies to the existing entry, and (test-only) the
/// one-shot stage fault.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CreateNewOptions<'a> {
    pub(crate) mode: u32,
    pub(crate) content: ContentEquivalence,
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
/// existing entry is VERIFIED through the ONE centralized lstat-based
/// verification ([`verify_existing`]): only a regular file whose mode matched
/// EXACTLY and whose content matched per the caller's requested equivalence
/// → [`CreateNewVerdict::AlreadyPresent`] (the identical retry converges —
/// no error, no replace); EVERY other outcome →
/// [`CreateNewVerdict::Conflict`] carrying the TYPED [`VerifiedExisting`]
/// reason (never an undifferentiated conflict — a directory, a symlink that
/// is never followed, a mode mismatch, or an unreadable entry is a real
/// conflict). `Ok(AlreadyPresent)` runs the parent fsync too, so the
/// convergent path still returns with a durable entry.
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
    //    entry is VERIFIED (verify-on-retry) through THE ONE CENTRALIZED
    //    lstat-based verification ([`verify_existing`] — a regular file with
    //    the EXACT required mode and the caller's accepted content
    //    equivalence → AlreadyPresent, the identical retry converges; every
    //    other outcome → Conflict carrying the TYPED reason).
    if fail(CreateNewStep::Publish) {
        return Err(Error::transport(format!(
            "test fault: create-new step {step:?} forced to fail (once)",
            step = CreateNewStep::Publish
        )));
    }
    let verdict = match std::fs::hard_link(&tmp, &p) {
        Ok(()) => CreateNewVerdict::Created,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // The lstat-based verification (the LOCAL side MUST use the
            // symlink-safe `symlink_metadata` form — never `metadata`, which
            // follows a symlink — so a symlink is never mistaken for a
            // regular file) and the shared verdict construction.
            let p2 = p.clone();
            let verified = verify_existing(
                || match std::fs::symlink_metadata(&p2) {
                    Ok(m) => Ok(Some(meta_to_remote(&m))),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(Error::transport(format!(
                        "verify stat {}: {e}",
                        p2.display()
                    ))),
                },
                || {
                    std::fs::read(&p2)
                        .map_err(|e| Error::transport(format!("verify read {}: {e}", p2.display())))
                },
                data,
                options.mode,
                options.content,
            );
            match verified {
                Ok(v) => verified_to_verdict(v),
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

/// Compare two byte slices under the caller's requested content equivalence:
/// `Exact` is byte equality; `Semantic` is JSON parse-equality (object key
/// order and whitespace are not part of the contract), falling back to byte
/// equality when either side does not parse as JSON. The ONE content
/// comparison used by the centralized verification ([`verify_existing`]) and
/// by the trait's default [`Remote::try_write_new_with`] semantic fallback.
pub(crate) fn content_equivalent(a: &[u8], b: &[u8], equivalence: ContentEquivalence) -> bool {
    match equivalence {
        ContentEquivalence::Exact => a == b,
        ContentEquivalence::Semantic => {
            if a == b {
                return true;
            }
            match (
                serde_json::from_slice::<serde_json::Value>(a),
                serde_json::from_slice::<serde_json::Value>(b),
            ) {
                (Ok(va), Ok(vb)) => va == vb,
                _ => false,
            }
        }
    }
}

/// THE ONE CENTRALIZED verification of an EXISTING create-new destination —
/// used by BOTH transports (the local [`durable_create_new`] verify-on-retry
/// and the SSH transport's EEXIST verification), so the two can never drift.
/// The checks run IN ORDER and the FIRST failure is the typed reason:
///
/// 1. **lstat** (`meta_opt` must be the symlink-safe `lstat` form — the
///    local `symlink_metadata` / the ssh `metadata_opt` perl-lstat protocol —
///    so a symlink is NEVER followed and mistaken for a regular file);
/// 2. **regular-file type** (a directory/symlink/other is
///    [`VerifiedExisting::NotRegularFile`]);
/// 3. **read** the existing content (a read failure is
///    [`VerifiedExisting::Unreadable`] — never a fabricated verdict);
/// 4. **exact mode** (the required mode, masked to `0o7777`);
/// 5. **the caller's content equivalence** ([`ContentEquivalence`]: exact
///    bytes or semantic JSON equality, per the caller's request).
///
/// `Ok` — and therefore [`CreateNewVerdict::AlreadyPresent`] via
/// [`verified_to_verdict`] — is produced ONLY when every check held.
pub(crate) fn verify_existing(
    meta_opt: impl FnOnce() -> Result<Option<RemoteMeta>>,
    read: impl FnOnce() -> Result<Vec<u8>>,
    intended: &[u8],
    required_mode: u32,
    equivalence: ContentEquivalence,
) -> Result<VerifiedExisting> {
    // 1. lstat — the symlink-safe stat, so a symlink is never followed.
    let Some(meta) = meta_opt()? else {
        return Ok(VerifiedExisting::NotFound);
    };
    // 2. regular-file type. The lstat already settled the kind: a symlink is
    //    reported as a symlink with its OWN metadata — the lstat guarantee.
    let kind = if meta.is_dir {
        NotRegularFileKind::Directory
    } else if meta.is_symlink {
        NotRegularFileKind::Symlink
    } else if meta.is_file {
        // 3. read — a read failure is the Unreadable reason, never a
        //    fabricated verdict.
        match read() {
            Ok(existing) => {
                // 4. exact mode — the mode is part of the immutable record.
                let actual = meta.mode & 0o7777;
                let required = required_mode & 0o7777;
                if actual != required {
                    return Ok(VerifiedExisting::ModeMismatch { actual, required });
                }
                // 5. the caller's content equivalence.
                if content_equivalent(&existing, intended, equivalence) {
                    return Ok(VerifiedExisting::Ok {
                        mode_ok: true,
                        content: equivalence,
                    });
                }
                return Ok(VerifiedExisting::ContentMismatch);
            }
            Err(e) => {
                return Ok(VerifiedExisting::Unreadable(format!("verify read: {e}")));
            }
        }
    } else {
        NotRegularFileKind::Other
    };
    Ok(VerifiedExisting::NotRegularFile { kind })
}

/// The ONE verdict-construction path: [`CreateNewVerdict::AlreadyPresent`]
/// ONLY when the typed verification is `Ok` WITH the mode check held (the
/// entry was a regular file whose mode matched EXACTLY — `content` already
/// held by construction); EVERY other reason is
/// [`CreateNewVerdict::Conflict`] carrying the typed reason. Callers receive
/// the typed reason and can never reinterpret an undifferentiated conflict.
pub(crate) fn verified_to_verdict(v: VerifiedExisting) -> CreateNewVerdict {
    match v {
        VerifiedExisting::Ok { mode_ok: true, .. } => CreateNewVerdict::AlreadyPresent,
        v => CreateNewVerdict::Conflict(v),
    }
}

/// A transport that operates on a local directory, executing commands on the
/// host. It mirrors the SSH remote layout exactly.
pub struct LocalTransport {
    base: PathBuf,
    /// The child environment snapshot: every spawned child (`df`)
    /// receives THIS snapshot as its ENTIRE environment
    /// ([`SysEnv::apply_to_command`]: `env_clear` first, then the snapshot's
    /// variables) — a deterministic HERMETIC environment resolved at the
    /// construction boundary, never whatever the parent env looks like at
    /// spawn time, and nothing else.
    env: SysEnv,
    /// THE command-execution seam every `exec` goes through: production uses
    /// [`ChildRunner`] (the bounded real runner: owns the child from spawn
    /// to the mandatory reap, terminates the whole process GROUP on timeout
    /// (TERM, grace, KILL), and returns every outcome — success, timeout,
    /// error — only after the child was reaped; a timeout-kill failure is an
    /// error, never a successful timeout outcome); the deterministic
    /// properties inject a scripted fake (no subprocess, no wall-clock).
    exec: Box<dyn Exec>,
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
        Self::with_exec(
            env,
            base.clone(),
            ChildRunner::new(env, base, RunnerConfig::production()),
        )
    }

    /// Build a transport whose `exec` calls are handled by `exec` instead of
    /// the production [`ChildRunner`]. Construction stays side-effect-free
    /// (no directories created, nothing spawned). Test-support seam: the
    /// deterministic deployment/state-machine properties inject a scripted
    /// fake so the push LOGIC (verification/activation outcomes) is exercised
    /// without spawning real processes.
    pub fn with_exec(env: &SysEnv, base: PathBuf, exec: impl Exec + 'static) -> Result<Self> {
        if !has_normal_component_below_root(&base) {
            return Err(Error::transport(format!(
                "deploy_dir {:?} must have at least one normal path component below the root (the filesystem root is not a valid deploy_dir)",
                base
            )));
        }
        Ok(LocalTransport {
            base,
            env: env.clone(),
            exec: Box::new(exec),
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

    fn remove_file_if(&self, rel: &Path, expected: &[u8]) -> Result<RemoveIfVerdict> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CLAIM_COUNTER: AtomicU64 = AtomicU64::new(0);

        let p = join(&self.base, rel);
        // The atomic CLAIM target: a unique dot-prefixed name INSIDE the
        // destination's parent directory (same filesystem, same directory
        // namespace as the lock), exactly like durable_create_new's temps.
        let tmp = p.with_file_name(format!(
            ".{}.claim.{}.{}",
            p.file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default(),
            std::process::id(),
            CLAIM_COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        // CLAIM: rename the entry to the temp — atomic, so only ONE
        // contender can ever win the claim; every other breaker's rename
        // fails with NotFound (the slot was already claimed or free).
        match std::fs::rename(&p, &tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RemoveIfVerdict::Absent);
            }
            Err(e) => {
                return Err(Error::transport(format!("claim {}: {e}", p.display())));
            }
        }
        // VERIFY the claimed entry against the expectation.
        let content = match std::fs::read(&tmp) {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(Error::transport(format!("verify {}: {e}", tmp.display())));
            }
        };
        if content == expected {
            // MATCH: the claimed entry was EXACTLY the expected record —
            // delete it; the slot is now free.
            let _ = std::fs::remove_file(&tmp);
            return Ok(RemoveIfVerdict::Removed);
        }
        // MISMATCH: the entry changed under the reader (a successor's newer
        // generation). RESTORE it no-replace — the moved record is
        // re-created with the canonical final mode only while the path is
        // still free; a CONCURRENT install is never replaced (Conflict) and
        // the moved claim is discarded, never destroying the winner. Either
        // way a successor's lock survives untouched.
        let restored = durable_create_new(
            &self.base,
            rel,
            &content,
            CreateNewOptions {
                mode: IMMUTABLE_RECORD_MODE,
                content: ContentEquivalence::Exact,
                fault: None,
            },
        );
        let _ = std::fs::remove_file(&tmp);
        match restored {
            // Created (restored), AlreadyPresent (a concurrent identical
            // restore), or Conflict (a different winner is in place): the
            // lock is intact — the compare failed, never a delete.
            Ok(_) => Ok(RemoveIfVerdict::Mismatch),
            // A transport failure on the no-replace restore propagates
            // EXPLICITLY (the moved claim was the only thing lost; the slot
            // is not blocked — the lease is the backstop).
            Err(e) => Err(e),
        }
    }

    fn try_write_new(&self, rel: &Path, data: &[u8]) -> Result<CreateNewVerdict> {
        // The ONE canonical create-new primitive (see `durable_create_new`):
        // temp -> write -> final chmod -> file fsync -> no-replace publish ->
        // unlink temp -> parent-directory fsync, every failure propagated, and
        // verify-on-retry. The immutable records this installs carry the
        // canonical final mode (`IMMUTABLE_RECORD_MODE`), never the umask.
        // The TYPED verdict survives this trait boundary untouched — Created
        // for a fresh durable install, AlreadyPresent for an identical retry
        // (parent-sync'd too), Conflict carrying the typed reason for any
        // other winner.
        self.try_write_new_with(rel, data, ContentEquivalence::Exact)
    }

    fn try_write_new_with(
        &self,
        rel: &Path,
        data: &[u8],
        equivalence: ContentEquivalence,
    ) -> Result<CreateNewVerdict> {
        durable_create_new(
            &self.base,
            rel,
            data,
            CreateNewOptions {
                mode: IMMUTABLE_RECORD_MODE,
                content: equivalence,
                fault: None,
            },
        )
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
        // THE command-execution seam: production is the bounded child-runner
        // (spawn into an OWN process group, bounded wait, group termination,
        // mandatory reap before any outcome escapes); the deterministic
        // properties inject a scripted fake — same trait surface, no process.
        self.exec.exec(argv, timeout)
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
    /// reports `Ok(Created)` for a fresh DURABLE install, `Ok(AlreadyPresent)`
    /// for an identical retry (convergent — the winner is verified
    /// byte-and-mode identical, never replaced), and `Ok(Conflict)` for a
    /// different-content OR different-mode winner (the winner is never
    /// touched; the caller's read-back comparison decides the semantic
    /// verdict). The TYPED verdict survives the trait boundary — no bool
    /// collapse. The installed record carries the canonical final mode, not
    /// the process umask.
    #[test]
    fn try_write_new_durable_install_and_conflict_contract() {
        use std::os::unix::fs::MetadataExt;

        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let t = LocalTransport::new(&SysEnv::from_process(), dir.path().join("r")).unwrap();
        let rel = Path::new("state/op.json");
        let data = b"{\"op\":\"1\"}";

        assert_eq!(
            t.try_write_new(rel, data).unwrap(),
            CreateNewVerdict::Created,
            "a fresh install wins"
        );
        let p = t.root().join(rel);
        assert_eq!(std::fs::read(&p).unwrap(), data, "exact bytes installed");
        assert_eq!(
            std::fs::metadata(&p).unwrap().mode() & 0o7777,
            IMMUTABLE_RECORD_MODE & 0o7777,
            "the record must carry the canonical final mode"
        );
        // Identical retry: convergent — AlreadyPresent, no error, no replace.
        assert_eq!(
            t.try_write_new(rel, data).unwrap(),
            CreateNewVerdict::AlreadyPresent,
            "an identical retry converges to already-present"
        );
        assert_eq!(
            std::fs::read(&p).unwrap(),
            data,
            "the identical retry must not touch the winner"
        );
        // Different content: the conflict verdict — never replaced.
        assert!(
            matches!(
                t.try_write_new(rel, b"other").unwrap(),
                CreateNewVerdict::Conflict(VerifiedExisting::ContentMismatch)
            ),
            "a different-content conflict is the verdict"
        );
        assert_eq!(
            std::fs::read(&p).unwrap(),
            data,
            "the conflict must NEVER replace the winner"
        );
    }

    /// The compare-and-delete primitive's contract: `Removed` for a
    /// byte-identical match (the entry is gone), `Mismatch` for different
    /// content (the winner is RESTORED — never removed, never replaced),
    /// and `Absent` for genuine absence. This is the primitive the mutation
    /// lock's stale-release/expired-break safety rests on.
    #[test]
    fn remove_file_if_compare_and_delete_verdicts() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let t = LocalTransport::new(&SysEnv::from_process(), dir.path().join("r")).unwrap();
        let rel = Path::new("state/op.lock");
        let data = b"{\"owner\":\"a\",\"token\":1}";

        // Absent: nothing to remove — the idempotent verdict.
        assert_eq!(
            t.remove_file_if(rel, data).unwrap(),
            RemoveIfVerdict::Absent,
            "a genuinely absent entry is Absent, never an error"
        );
        // Match: the entry carried EXACTLY the expected bytes — removed.
        t.try_write_new(rel, data).unwrap();
        assert_eq!(
            t.remove_file_if(rel, data).unwrap(),
            RemoveIfVerdict::Removed,
            "a byte-identical match is removed"
        );
        assert!(
            t.metadata_opt(rel).unwrap().is_none(),
            "the matched entry must be gone"
        );
        // Mismatch: different content — the winner is restored untouched,
        // NEVER removed, NEVER replaced.
        t.try_write_new(rel, data).unwrap();
        assert_eq!(
            t.remove_file_if(rel, b"{\"owner\":\"b\",\"token\":2}")
                .unwrap(),
            RemoveIfVerdict::Mismatch,
            "different content is a Mismatch, never a delete"
        );
        assert_eq!(
            t.read(rel).unwrap(),
            data,
            "the mismatch must restore the winner byte-for-byte"
        );
    }

    /// The durability property's scenario dimension: the healthy install, a
    /// one-shot crash/failure at one of the SEVEN stages, and the
    /// pre-existing-winner retry cases (identical / different content /
    /// different mode / published-before-parent-sync / the retry's parent
    /// fsync faulted).
    #[derive(Clone, Copy, Debug)]
    enum CreateNewScenario {
        Healthy,
        FailAt(CreateNewStep),
        PreExistingIdentical,
        PreExistingDifferent,
        PreExistingDifferentMode,
        /// A crash-simulated state: the entry EXISTS with the intended bytes
        /// and mode, but its parent directory was never fsync'd (a crash
        /// after publish, before the parent fsync).
        PublishedBeforeParentSync,
        /// The retry over an identical existing entry arms a one-shot
        /// ParentFsync fault: the AlreadyPresent branch must RUN the parent
        /// fsync, so the faulted retry propagates an error instead of
        /// claiming durability.
        IdenticalRetryParentFsyncFault,
    }

    fn create_new_scenario() -> impl Strategy<Value = CreateNewScenario> {
        prop_oneof![
            Just(CreateNewScenario::Healthy),
            Just(CreateNewScenario::PreExistingIdentical),
            Just(CreateNewScenario::PreExistingDifferent),
            Just(CreateNewScenario::PreExistingDifferentMode),
            Just(CreateNewScenario::PublishedBeforeParentSync),
            Just(CreateNewScenario::IdenticalRetryParentFsyncFault),
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
                        CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None },
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
                        CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: Some(&fault) },
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
                        CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None },
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
                    durable_create_new(&root, rel, &content, CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None })
                        .expect("the first install must succeed");
                    let verdict =
                        durable_create_new(&root, rel, &content, CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None })
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
                        CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None },
                    )
                    .expect("a conflict is a verdict, not an I/O error");
                    prop_assert!(matches!(
                        verdict,
                        CreateNewVerdict::Conflict(VerifiedExisting::ContentMismatch)
                    ));
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
                    durable_create_new(&root, rel, &content, CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None })
                        .expect("the first install must succeed");
                    let other_mode = if (mode & 0o7777) == 0o600 { 0o644 } else { 0o600 };
                    std::fs::set_permissions(
                        &dest,
                        std::fs::Permissions::from_mode(other_mode),
                    )
                    .unwrap();
                    let verdict =
                        durable_create_new(&root, rel, &content, CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None })
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
                }
                CreateNewScenario::PublishedBeforeParentSync => {
                    // A crash-simulated state: the entry EXISTS with the
                    // intended bytes and mode but its parent directory was
                    // NEVER fsync'd (a crash after publish, before the parent
                    // fsync). The identical retry must verify it as
                    // AlreadyPresent — and ESTABLISH the parent durability:
                    // the AlreadyPresent branch runs the parent fsync, so a
                    // fresh directory read (a simulated crash-after-return)
                    // still sees the entry.
                    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                    std::fs::write(&dest, &content).unwrap();
                    std::fs::set_permissions(
                        &dest,
                        std::fs::Permissions::from_mode(mode & 0o7777),
                    )
                    .unwrap();
                    let verdict = durable_create_new(
                        &root,
                        rel,
                        &content,
                        CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None },
                    )
                    .expect("the identical retry over a published-before-parent-sync entry must converge");
                    prop_assert_eq!(verdict, CreateNewVerdict::AlreadyPresent);
                    prop_assert_eq!(
                        std::fs::read(&dest).unwrap(),
                        content,
                        "the winner must stay intact"
                    );
                    let meta = std::fs::metadata(&dest).unwrap();
                    prop_assert_eq!(
                        meta.mode() & 0o7777,
                        mode & 0o7777,
                        "the winner's mode must stay intact"
                    );
                    let names: Vec<String> = std::fs::read_dir(dest.parent().unwrap())
                        .expect("the parent must be readable")
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect();
                    prop_assert!(
                        names.contains(&dest_name),
                        "the AlreadyPresent retry must have established the parent durability, dir has: {names:?}"
                    );
                }
                CreateNewScenario::IdenticalRetryParentFsyncFault => {
                    // The retry's AlreadyPresent branch RUNS the parent fsync:
                    // arm the one-shot ParentFsync fault for a retry over an
                    // identical existing entry — the retry must return Err
                    // (the faulted parent fsync), never a false
                    // Ok(AlreadyPresent) that claims durability.
                    durable_create_new(&root, rel, &content, CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None })
                        .expect("the first install must succeed");
                    let fault = CreateNewFault::new(CreateNewStep::ParentFsync);
                    let err = durable_create_new(
                        &root,
                        rel,
                        &content,
                        CreateNewOptions {
                            mode,
                            content: ContentEquivalence::Exact,
                            fault: Some(&fault),
                        },
                    )
                    .expect_err(
                        "the AlreadyPresent retry must run — and propagate the failure of — the parent fsync",
                    );
                    prop_assert!(
                        err.to_string().contains("forced to fail (once)"),
                        "the faulted parent fsync must be the propagated failure, got: {err}"
                    );
                }
            }
        }
    }

    /// A `Remote` wrapper that arms ONE one-shot stage fault inside
    /// `try_write_new` — the trait-level stage-failure model for
    /// `LocalTransport` (production `LocalTransport` never arms one; the
    /// fault is the same `CreateNewFault` the primitive proptest uses). Every
    /// other method delegates to the inner transport untouched.
    struct FaultyLocalRemote {
        inner: LocalTransport,
        fault: CreateNewFault,
    }

    impl Remote for FaultyLocalRemote {
        fn root(&self) -> &Path {
            self.inner.root()
        }
        fn read(&self, rel: &Path) -> Result<Vec<u8>> {
            self.inner.read(rel)
        }
        fn write(&self, rel: &Path, data: &[u8], mode: u32) -> Result<()> {
            self.inner.write(rel, data, mode)
        }
        fn try_write_new(&self, rel: &Path, data: &[u8]) -> Result<CreateNewVerdict> {
            durable_create_new(
                self.inner.root(),
                rel,
                data,
                CreateNewOptions {
                    mode: IMMUTABLE_RECORD_MODE,
                    content: ContentEquivalence::Exact,
                    fault: Some(&self.fault),
                },
            )
        }
        fn create_dir(&self, rel: &Path) -> Result<()> {
            self.inner.create_dir(rel)
        }
        fn create_dir_all(&self, rel: &Path) -> Result<()> {
            self.inner.create_dir_all(rel)
        }
        fn set_mode(&self, rel: &Path, mode: u32) -> Result<()> {
            self.inner.set_mode(rel, mode)
        }
        fn list(&self, rel: &Path) -> Result<Vec<RemoteEntry>> {
            self.inner.list(rel)
        }
        fn rename(&self, from: &Path, to: &Path) -> Result<()> {
            self.inner.rename(from, to)
        }
        fn symlink(&self, target: &Path, link: &Path) -> Result<()> {
            self.inner.symlink(target, link)
        }
        fn read_link(&self, rel: &Path) -> Result<PathBuf> {
            self.inner.read_link(rel)
        }
        fn remove_file(&self, rel: &Path) -> Result<()> {
            self.inner.remove_file(rel)
        }
        fn remove_dir_all(&self, rel: &Path) -> Result<()> {
            self.inner.remove_dir_all(rel)
        }
        fn exists(&self, rel: &Path) -> bool {
            self.inner.exists(rel)
        }
        fn metadata(&self, rel: &Path) -> Result<RemoteMeta> {
            self.inner.metadata(rel)
        }
        fn exec(&self, argv: &[String], timeout: Duration) -> Result<ExecOutcome> {
            self.inner.exec(argv, timeout)
        }
        fn filesystem_bytes(&self) -> Result<FsBytes> {
            self.inner.filesystem_bytes()
        }
    }

    /// The trait-level verdict matrix for [`Remote::try_write_new`] on
    /// `LocalTransport` — the typed verdict survives the trait boundary, no
    /// bool collapse:
    ///
    /// * `Created` for a FRESH write (exact bytes, final mode, durable entry);
    /// * `AlreadyPresent` for an EXACT existing entry — the identical retry —
    ///   which must ESTABLISH the parent durability (the parent fsync runs on
    ///   the AlreadyPresent branch; a fresh directory read still sees the
    ///   entry);
    /// * `Conflict` for DIFFERENT BYTES and for a MODE MISMATCH over identical
    ///   bytes (the spec: "a mode mismatch must remain Conflict") — the
    ///   winner is never replaced or modified;
    /// * published-before-parent-sync: an existing entry whose parent was
    ///   never synced is verified as `AlreadyPresent` (bytes+mode match) and
    ///   the retry establishes the parent durability;
    /// * every STAGE FAILURE (via the one-shot fault through the trait)
    ///   propagates as an `Err` naming the injected stage — never a false
    ///   verdict — and the identical retry converges.
    #[derive(Clone, Copy, Debug)]
    enum TransportVerdictState {
        Fresh,
        ExactExisting,
        DifferentBytes,
        DifferentMode,
        PublishedBeforeParentSync,
        FailAt(CreateNewStep),
    }

    fn transport_verdict_state() -> impl Strategy<Value = TransportVerdictState> {
        prop_oneof![
            Just(TransportVerdictState::Fresh),
            Just(TransportVerdictState::ExactExisting),
            Just(TransportVerdictState::DifferentBytes),
            Just(TransportVerdictState::DifferentMode),
            Just(TransportVerdictState::PublishedBeforeParentSync),
            Just(TransportVerdictState::FailAt(CreateNewStep::CreateTemp)),
            Just(TransportVerdictState::FailAt(CreateNewStep::Write)),
            Just(TransportVerdictState::FailAt(CreateNewStep::Chmod)),
            Just(TransportVerdictState::FailAt(CreateNewStep::FileFsync)),
            Just(TransportVerdictState::FailAt(CreateNewStep::Publish)),
            Just(TransportVerdictState::FailAt(CreateNewStep::Unlink)),
            Just(TransportVerdictState::FailAt(CreateNewStep::ParentFsync)),
        ]
    }

    proptest! {
        // Bounded cases, fixed seed 0x5EED_5EED (house style), no persistence.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(64),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn try_write_new_verdict_matrix(
            content in prop::collection::vec(any::<u8>(), 0..128),
            state in transport_verdict_state(),
        ) {
            use std::os::unix::fs::PermissionsExt;

            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let t = LocalTransport::new(&SysEnv::from_process(), dir.path().join("r")).unwrap();
            let rel = Path::new("state/record.bin");
            let dest = t.root().join(rel);
            let dest_name = rel.file_name().unwrap().to_string_lossy().into_owned();
            let final_mode = IMMUTABLE_RECORD_MODE & 0o7777;

            match state {
                TransportVerdictState::Fresh => {
                    let verdict = t
                        .try_write_new(rel, &content)
                        .expect("the fresh install must succeed");
                    prop_assert_eq!(verdict, CreateNewVerdict::Created);
                    prop_assert_eq!(
                        std::fs::read(&dest).unwrap(),
                        content,
                        "Ok(Created) must imply exact bytes"
                    );
                    let meta = std::fs::metadata(&dest).unwrap();
                    prop_assert_eq!(
                        meta.mode() & 0o7777,
                        final_mode,
                        "Ok(Created) must imply the final mode"
                    );
                    let names: Vec<String> = std::fs::read_dir(dest.parent().unwrap())
                        .unwrap()
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect();
                    prop_assert!(
                        names.contains(&dest_name),
                        "Ok(Created) must imply a durable directory entry, dir has: {names:?}"
                    );
                }
                TransportVerdictState::ExactExisting => {
                    // An EXACT existing entry (bytes AND mode identical): the
                    // identical retry converges — AlreadyPresent, and the
                    // parent durability is established (the parent fsync runs
                    // on this branch).
                    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                    std::fs::write(&dest, &content).unwrap();
                    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(final_mode))
                        .unwrap();
                    let verdict = t
                        .try_write_new(rel, &content)
                        .expect("an identical retry must converge, not error");
                    prop_assert!(matches!(verdict, CreateNewVerdict::AlreadyPresent));
                    prop_assert_eq!(
                        std::fs::read(&dest).unwrap(),
                        content,
                        "the identical retry must not touch the winner"
                    );
                    let names: Vec<String> = std::fs::read_dir(dest.parent().unwrap())
                        .unwrap()
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect();
                    prop_assert!(
                        names.contains(&dest_name),
                        "the AlreadyPresent retry must leave the durable entry, dir has: {names:?}"
                    );
                }
                TransportVerdictState::DifferentBytes => {
                    // A winner with DIFFERENT bytes: Conflict, never replaced.
                    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                    let other: Vec<u8> = if content.is_empty() {
                        vec![0u8]
                    } else {
                        content.iter().map(|b| b.wrapping_add(1)).collect()
                    };
                    prop_assert_ne!(&other, &content, "the winner must differ from the intent");
                    std::fs::write(&dest, &other).unwrap();
                    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(final_mode))
                        .unwrap();
                    let verdict = t
                        .try_write_new(rel, &content)
                        .expect("a different-content winner is a verdict, not an I/O error");
                    prop_assert!(matches!(
                        verdict,
                        CreateNewVerdict::Conflict(VerifiedExisting::ContentMismatch)
                    ));
                    prop_assert_eq!(
                        std::fs::read(&dest).unwrap(),
                        other,
                        "the conflict must NEVER replace the winner"
                    );
                }
                TransportVerdictState::DifferentMode => {
                    // Identical bytes but a DIFFERENT mode: still Conflict —
                    // the mode is part of the record, and a mode mismatch must
                    // remain Conflict (never a convergent AlreadyPresent).
                    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                    std::fs::write(&dest, &content).unwrap();
                    let other_mode = if final_mode == 0o600 { 0o640 } else { 0o600 };
                    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(other_mode))
                        .unwrap();
                    let verdict = t
                        .try_write_new(rel, &content)
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
                }
                TransportVerdictState::PublishedBeforeParentSync => {
                    // A crash-simulated state: the entry EXISTS with the
                    // intended bytes and mode, but its parent was never synced.
                    // The retry verifies it as AlreadyPresent AND establishes
                    // the parent durability.
                    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                    std::fs::write(&dest, &content).unwrap();
                    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(final_mode))
                        .unwrap();
                    let verdict = t
                        .try_write_new(rel, &content)
                        .expect("the retry over a published-before-parent-sync entry must converge");
                    prop_assert_eq!(verdict, CreateNewVerdict::AlreadyPresent);
                    prop_assert_eq!(
                        std::fs::read(&dest).unwrap(),
                        content,
                        "the winner must stay intact"
                    );
                    let names: Vec<String> = std::fs::read_dir(dest.parent().unwrap())
                        .unwrap()
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect();
                    prop_assert!(
                        names.contains(&dest_name),
                        "the AlreadyPresent retry must establish the parent durability, dir has: {names:?}"
                    );
                }
                TransportVerdictState::FailAt(step) => {
                    // EVERY STAGE FAILURE through the trait boundary: the
                    // faulted attempt propagates as Err naming the injected
                    // stage — never a false verdict — and the one-shot fault
                    // being consumed, the identical retry converges.
                    let w = FaultyLocalRemote {
                        inner: t,
                        fault: CreateNewFault::new(step),
                    };
                    let err = w
                        .try_write_new(rel, &content)
                        .expect_err("a failure at every stage must propagate as Err");
                    prop_assert!(
                        err.to_string().contains("forced to fail (once)"),
                        "the injected fault must be the propagated failure, got: {err}"
                    );
                    let retry = w
                        .try_write_new(rel, &content)
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
                            std::fs::read(&dest).unwrap(),
                            content,
                            "the destination must be the fully-written identical content, never partial"
                        );
                    }
                }
            }
        }
    }
}
