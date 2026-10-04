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

pub(crate) mod receiver_marker;
#[cfg(test)]
mod rooted;
#[cfg(test)]
pub(crate) mod scripted;
// The SSH transport group and the shared bounded child-runner are now the
// SUBSTRATE's (`storekit::transport::{SshTransport, runner}`): `deploy`'s two
// copies are deleted, and the substrate runner/crate tests carry their
// coverage. The transport types are re-exported below so every existing
// `crate::remote::transport::{...}` spelling keeps resolving.
//
// The source audit in `deploy`
// (`every_remote_impl_carries_an_explicit_provisioning_override`) loses
// exactly one counted `impl Remote for` block — the deleted
// `impl Remote for SshTransport` — so its observed count falls 34 -> 33 and
// its `checked >= 31` floor still holds with margin; the re-exported
// substrate `SshTransport` provisions its receiver marker in the crate, where
// that audit does not look.
#[cfg(test)]
mod ssh_fake_endpoint_tests;

// `deploy`'s LEGACY receiver-identity reads and the provisioning writer are
// DOMAIN code (they parse and create `recv-<uuid-v7>`, which the crate
// deliberately does not know — see the [`receiver_marker`] module), so they
// live there with the crate-format adoption path they drive. Re-exported here
// so every existing cross-module spelling
// (`crate::remote::transport::{read_receiver_uuid_opt, peek_receiver_uuid_opt,
// provision_receiver_uuid}`) keeps resolving; `read_receiver_uuid` and the
// adoption writer are reached through the module itself.
pub(crate) use receiver_marker::{
    peek_receiver_uuid_opt, provision_receiver_uuid, read_receiver_uuid_opt,
};
// The validated root-relative path is now the crate's type — the ONE spelling
// authority for a root-relative path. `deploy`'s own `rooted` module (266
// lines, the source `storekit::relpath` was extracted from) is deleted: its
// public API is byte-for-byte the crate's (`parse`/`as_path`/`join`/
// `file_name`/`parent`/`with_file_name`/`display` + `AsRef<Path>`/`Display`),
// so every `crate::remote::transport::RootedRelativePath` call site keeps
// resolving without change. The crate's internal `from_validated` constructor
// is `pub(crate)` (deliberately unspellable by a consumer), so `deploy`'s
// layout builders construct through the fallible `parse` (see
// [`crate::remote::layout`]). The adaptation is behaviour-identical on the
// accepted set; where the crate is stricter is named in the layout module.
pub use storekit::relpath::RootedRelativePath;
pub use storekit::transport::SshTransport;
pub use storekit::transport::{
    ChildRunner, KillSeam, RealKill, RunError, RunOutcome, RunnerConfig,
};

use crate::env::SysEnv;
use std::path::{Path, PathBuf};
use std::time::Duration;
use storekit::error::{Error, Result};
use walkdir::WalkDir;

/// The remote-state protocol version. Bumped 1 -> 2 when the remote
/// generation record (`generations/<gen>/assignment.json`) gained the OWNER
/// MARKER (`application`/`slot`): a protocol-1 client would parse a
/// protocol-2 record WITHOUT the owner fields (serde ignores unknown
/// fields) and drive state whose ownership it cannot verify, so the
/// handshake must refuse a version mismatch in either direction (an old
/// client can never drive a state directory written by a newer one, and
/// vice versa). The protocol-2 read path additionally fails closed on a
/// record WITHOUT the owner marker (a required-field parse failure — a
/// legacy/transplanted record is never read as a valid deployment).
pub const PROTOCOL_VERSION: u32 = 2;

// The shared transport vocabulary is the crate's. Each type below is
// byte-for-byte identical to `deploy`'s former definition (same derives, same
// fields/variants), so re-exporting it is behaviour-identical and gives the
// verdict/wire vocabulary ONE authority — the crate the transport trait comes
// from. `ExecOutcome` now carries the crate's typed `timeout_cause`, which the
// crate's `Exec` trait already produces; `deploy`'s local runner maps its
// `TimedOut` outcome to `TimeoutCause::CommandStillRunning` (its only timeout
// cause — its post-exit drain reports a background descendant as an error, so
// `OutputDrainGaveUp` is never produced).
pub use storekit::transport::{
    ContentEquivalence, CreateNewVerdict, Exec, ExecOutcome, FarSideLockSession, FsBytes,
    NotRegularFileKind, RemoteEntry, RemoteMeta, RemoveIfVerdict, TimeoutCause, VerifiedExisting,
};

/// The SUBSTRATE error type (and result alias) every [`Remote`] method returns.
/// Re-exported so an out-of-crate `Remote` implementor can spell its method
/// signatures; `deploy`'s own domain error stays [`crate::error::Error`], and
/// domain code converts at the boundary with the existing
/// `From<storekit::Error>` impl.
pub use storekit::error::{Error as SubstrateError, Result as SubstrateResult};

// The REAL exec mapping for [`ChildRunner`] (`RunOutcome::TimedOut` →
// `exit_code: -1` + [`TimeoutCause::CommandStillRunning`]) is the SUBSTRATE's
// `impl Exec for ChildRunner`; a local copy here would be a second, incoherent
// impl of the crate's trait for the crate's type.

/// Filesystem + execution surface for one server's remote root — the
/// substrate's trait, re-exported as [`crate::remote::transport::Remote`].
///
/// Every path a transport operation receives is a validated
/// [`RootedRelativePath`]: relative to the deployment root, never absolute,
/// never traversal-bearing — so `root.join(rel)` inside a transport is safe
/// by construction and a caller can never escape the deployment root.
///
/// The trait's vocabulary is the substrate's throughout: every method's
/// failure is a [`SubstrateError`] (the deploy domain error stays
/// [`crate::error::Error`], converted at the boundary by the
/// `From<storekit::Error>` impl), the exec outcome carries the substrate's
/// typed `timeout_cause`, and the layout-aware provisioning plus the
/// residue/lock methods are the substrate's.
pub use storekit::transport::Remote;

/// Provision the deploy_dir's IMMUTABLE receiver-UUID marker through
/// `remote`'s OWN methods, so a wrapper that records or injects a fault on
/// those calls still sees them. This is the marker-only provisioning a
/// `Remote` implementor wants when it builds no layout of its own; the
/// production transports ([`LocalTransport`], [`SshTransport`]) provision
/// the full layout and then call this too.
///
/// PUBLIC because an out-of-crate `Remote` implementor — a test fixture
/// built on the public fixture API — reaches provisioning only through a
/// public entry point. It grants no capability the caller did not already
/// have: every effect goes through the caller's own [`Remote`] methods.
pub fn provision_receiver_marker<R: Remote + ?Sized>(remote: &R) -> Result<()> {
    provision_receiver_uuid(remote)?;
    Ok(())
}

fn join(root: &Path, rel: &RootedRelativePath) -> PathBuf {
    root.join(rel.as_path())
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
        mode: crate::platform::metadata_mode(m),
    }
}

/// The canonical FINAL MODE for immutable records installed through
/// [`Remote::try_write_new`]: the same `0o644` every sibling JSON record is
/// written with (the inventory, transactions, and the force-path lock rewrite
/// all use `Remote::write(..., 0o644)`). The published inode must carry THIS
/// mode — never the process umask the temp was created with — or the record's
/// permissions would silently depend on the caller's umask.
pub(crate) const IMMUTABLE_RECORD_MODE: u32 = 0o644;

// The operation-lock sidecar critical section is the CRATE's
// ([`storekit::transport::with_operation_lock_sidecar`]): the SAME record
// (`layout::operation_lock_sidecar()`), the SAME `create_new` + fsync
// durability, the SAME 2 s deadline / 5 ms retry policy, and an RAII hold
// that releases the flock and the re-entrancy depth on every exit path
// including a panic unwind. `deploy` no longer carries the flock triple
// (`try_lock`/`unlock`/`contended_errno`), the wait loop, or the constants.
//
// What `deploy` still observes locally is RE-ENTRANCY, for its own
// `remove_file_if_inner`: while this thread is inside the sidecar, a
// serialized compare-and-delete keeps the lock record CONTINUOUSLY VISIBLE
// (no claim-aside rename window) instead of taking the atomic claim path.
// The crate owns its own depth for locking; this counter is only that
// observer, and it is raised for the duration of the crate's critical
// section.
thread_local! {
    static SIDECAR_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Run `f` inside the crate's operation-lock sidecar, recording on this
/// thread that the sidecar is held. The lock itself — acquisition, wait
/// policy, re-entrancy and RAII release — is entirely the crate's.
fn with_observed_operation_lock<R>(base: &Path, f: impl FnOnce() -> Result<R>) -> Result<R> {
    let prev_depth = SIDECAR_DEPTH.with(|c| c.get());
    let _hold = SidecarObservation::new(prev_depth);
    storekit::transport::with_operation_lock_sidecar(
        base,
        &crate::remote::layout::operation_lock_sidecar(),
        || Ok(f()),
    )?
}

/// The RAII observer for [`with_observed_operation_lock`]: raises the
/// thread-local depth on construction and restores it on drop, so a panic
/// unwinding through the critical section cannot leak the observation.
struct SidecarObservation {
    prev_depth: usize,
}

impl SidecarObservation {
    fn new(prev_depth: usize) -> Self {
        SIDECAR_DEPTH.with(|c| c.set(prev_depth + 1));
        SidecarObservation { prev_depth }
    }
}

impl Drop for SidecarObservation {
    fn drop(&mut self) {
        SIDECAR_DEPTH.with(|c| c.set(self.prev_depth));
    }
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
/// existing entry is VERIFIED through the ONE centralized DESCRIPTOR-BOUND
/// verification ([`verify_existing`] — the local [`open_verify_local`]
/// opens with `O_NOFOLLOW` and fstats + reads through the SAME opened
/// descriptor, so the metadata and the content provably come from the same
/// opened inode): only a regular file whose mode matched
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
    rel: &RootedRelativePath,
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
    crate::platform::chmod(&tmp, options.mode & 0o7777)
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
            // The DESCRIPTOR-BOUND verification (the LOCAL side opens with
            // `O_NOFOLLOW` — a symlink at the destination makes the open
            // fail with ELOOP → NotRegularFile{Symlink}, so a symlink is
            // NEVER followed, even when it points at a matching regular
            // file — then fstats and reads through the SAME opened
            // descriptor, so the metadata and the content provably come
            // from the same opened inode) and the shared verdict
            // construction.
            let p2 = p.clone();
            let verified = verify_existing(
                || {
                    open_verify_local(
                        &p2,
                        #[cfg(test)]
                        None,
                    )
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
/// The verification is DESCRIPTOR-BOUND: the single `open` closure performs
/// the ONE open→fstat→read sequence on a SINGLE opened inode
/// ([`OpenedExisting::Entry`] carries the metadata from the fstat of the
/// OPENED descriptor AND the content read THROUGH THE SAME descriptor), so a
/// concurrent actor that swaps the entry at the path between the checks can
/// never mix two inodes' observations — a swap AFTER the open is irrelevant
/// (the descriptor pins the inode; the checks observe the pinned inode
/// consistently), and a swap BEFORE the open merely changes WHAT was opened
/// (the checks then run on the swapped inode consistently). The checks run
/// IN ORDER and the FIRST APPLICABLE class WINS — this first-failure
/// precedence IS the source of truth the create-new verification ORACLE
/// mirrors (the cross-product proptest in the ssh test module computes its
/// expected [`VerifiedExisting`] class from THIS order, never from ad-hoc
/// per-cell logic):
///
/// 1. **open** — the transport's `O_NOFOLLOW` open (the local
///    [`open_verify_local`] / the ssh framed helper), the FIRST check: an
///    ABSENT destination (ENOENT/ENOTDIR) → [`VerifiedExisting::NotFound`];
///    a SYMLINK → `NotRegularFile`{Symlink} (the `O_NOFOLLOW` open's ELOOP —
///    NEVER followed, even a symlink pointing at a matching regular file);
///    an UNREADABLE entry (EACCES/EPERM/EIO on the open/fstat/read) →
///    [`VerifiedExisting::Unreadable`]; a DIRECTORY → `NotRegularFile`
///    {Directory};
/// 2. **regular-file type** — from the OPENED descriptor's fstat: a
///    directory/symlink/other is [`VerifiedExisting::NotRegularFile`]. The
///    type check runs BEFORE readability, mode, and content: an unreadable or
///    wrong-mode DIRECTORY is still `NotRegularFile`, never `Unreadable` or
///    `ModeMismatch`;
/// 3. **readability** — the content read happens BEFORE the mode check: a
///    regular file whose content cannot be read is
///    [`VerifiedExisting::Unreadable`] (never a fabricated verdict) even
///    when its mode is wrong;
/// 4. **exact mode** — a regular file whose mode (masked to `0o7777`) does
///    not match the required mode is [`VerifiedExisting::ModeMismatch`],
///    decided BEFORE the content comparison;
/// 5. **the caller's content equivalence** ([`ContentEquivalence`]: exact
///    bytes or semantic JSON equality, per the caller's request) — the LAST
///    check: only a readable, mode-exact regular file is ever compared, and
///    a failed comparison is [`VerifiedExisting::ContentMismatch`].
///
/// `Ok` — and therefore [`CreateNewVerdict::AlreadyPresent`] via
/// [`verified_to_verdict`] — is produced ONLY when EVERY check held on the
/// ONE opened inode.
pub(crate) fn verify_existing(
    open: impl FnOnce() -> Result<OpenedExisting>,
    intended: &[u8],
    required_mode: u32,
    equivalence: ContentEquivalence,
) -> Result<VerifiedExisting> {
    // 1. open — the descriptor-bound open→fstat→read sequence (one inode).
    let opened = open()?;
    let OpenedExisting::Entry(entry) = opened else {
        return Ok(match opened {
            OpenedExisting::NotFound => VerifiedExisting::NotFound,
            OpenedExisting::NotRegular { kind } => VerifiedExisting::NotRegularFile { kind },
            OpenedExisting::Unreadable(m) => VerifiedExisting::Unreadable(m),
            OpenedExisting::Entry(_) => unreachable!(),
        });
    };
    let meta = entry.meta;
    // 2. regular-file type — from the OPENED descriptor's fstat (a symlink
    //    is unrepresentable here — the `O_NOFOLLOW` open never opened one —
    //    but kept for defense in depth).
    let kind = if meta.is_dir {
        NotRegularFileKind::Directory
    } else if meta.is_symlink {
        NotRegularFileKind::Symlink
    } else if meta.is_file {
        // 3. exact mode — the mode is part of the immutable record.
        let actual = meta.mode & 0o7777;
        let required = required_mode & 0o7777;
        if actual != required {
            return Ok(VerifiedExisting::ModeMismatch { actual, required });
        }
        // 4. the caller's content equivalence.
        if content_equivalent(&entry.content, intended, equivalence) {
            return Ok(VerifiedExisting::Ok {
                mode_ok: true,
                content: equivalence,
            });
        }
        return Ok(VerifiedExisting::ContentMismatch);
    } else {
        NotRegularFileKind::Other
    };
    Ok(VerifiedExisting::NotRegularFile { kind })
}

/// The descriptor-bound observation of an EXISTING create-new destination:
/// the type/mode (from `fstat` on the OPENED descriptor) and the content
/// (read THROUGH THE SAME descriptor). Metadata and content provably come
/// from the SAME OPENED INODE — the property that closes the
/// check-then-use (TOCTOU) hole: a concurrent actor that swaps the entry at
/// the path AFTER the open is irrelevant, because the descriptor pins the
/// inode.
#[derive(Clone, Debug)]
pub(crate) struct OpenedEntry {
    pub(crate) meta: RemoteMeta,
    pub(crate) content: Vec<u8>,
}

/// The OUTCOME of the descriptor-bound open — [`verify_existing`]'s single
/// `open` step (the LOCAL [`open_verify_local`] / the ssh framed helper):
/// the entry was opened with `O_NOFOLLOW` and its metadata + content were
/// observed through the SAME opened descriptor ([`OpenedExisting::Entry`]),
/// or the open/fstat/read failed with a TYPED reason — absent
/// (ENOENT/ENOTDIR → [`OpenedExisting::NotFound`]), a symlink (the
/// `O_NOFOLLOW` open's ELOOP — NEVER followed, even when the symlink points
/// at a matching regular file), a directory (EISDIR from the open, or the
/// opened inode's own type), or unreadable (EACCES/EPERM/EIO/... — a real
/// failure, never a fabricated verdict).
#[derive(Clone, Debug)]
pub(crate) enum OpenedExisting {
    /// The opened inode's metadata (fstat) AND content (read through the
    /// same descriptor): the checks run on ONE consistent inode.
    Entry(OpenedEntry),
    /// The `O_NOFOLLOW` open reported the destination absent (ENOENT/ENOTDIR).
    NotFound,
    /// The opened (or fstat'd) inode is NOT a regular file: a directory, a
    /// symlink (never followed), or another kind.
    NotRegular { kind: NotRegularFileKind },
    /// The entry could not be opened/fstat'd/read (EACCES/EPERM/EIO/...): a
    /// real failure, never a fabricated verdict.
    Unreadable(String),
}

/// The boundary of [`verify_existing`]'s descriptor-bound sequence at which a
/// one-shot test swap fires: BEFORE the `O_NOFOLLOW` open (the swap changes
/// WHAT is opened), or AFTER the open / AFTER the fstat (the swap changes the
/// PATH while the descriptor keeps pinning the ORIGINAL inode — the
/// fd-bound property under test).
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VerifySwapBoundary {
    BeforeOpen,
    AfterOpen,
    AfterFstat,
}

/// The one-shot test-only entry a [`VerifySwap`] places at the destination
/// (originally a REGULAR file): a SYMLINK (pointing at the pre-staged
/// `swap_target` regular file — a following open would ACCEPT it, the
/// `O_NOFOLLOW` open must reject it), a DIRECTORY, or a DIFFERENT-INODE
/// regular file (the pre-staged `swap_target`, moved onto the destination).
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VerifySwapKind {
    Symlink,
    Directory,
    DifferentInode,
}

/// One-shot swap injection for [`verify_existing`]'s descriptor-bound
/// sequence: at the chosen [`VerifySwapBoundary`], replaces the destination
/// with a [`VerifySwapKind`] entry (the original is moved aside, so the
/// fd-pinned inode stays observable). Fires EXACTLY ONCE, per fixture
/// (never a process-global slot — two fixtures' swaps can never consume each
/// other). Test-only (production never arms one); the swap-at-every-boundary
/// proptest arms exactly one.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct VerifySwap {
    boundary: VerifySwapBoundary,
    kind: VerifySwapKind,
    /// The pre-staged SWAP entry: the symlink target (a regular file) or the
    /// different-inode regular file (the directory swap ignores it).
    swap_target: PathBuf,
    armed: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl VerifySwap {
    pub(crate) fn new(
        boundary: VerifySwapBoundary,
        kind: VerifySwapKind,
        swap_target: &Path,
    ) -> Self {
        Self {
            boundary,
            kind,
            swap_target: swap_target.to_path_buf(),
            armed: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// Fire the swap exactly once when the boundary matches; `true` when it
    /// fired (the destination was replaced with the swap entry).
    pub(crate) fn fire(&self, boundary: VerifySwapBoundary, p: &Path) -> bool {
        use std::sync::atomic::Ordering;
        if self.boundary != boundary || !self.armed.swap(false, Ordering::SeqCst) {
            return false;
        }
        self.swap(p);
        true
    }

    fn swap(&self, p: &Path) {
        // Move the ORIGINAL entry aside (its inode survives for identity
        // checks — and for the post-open boundaries, the opened descriptor
        // keeps pinning it), then place the swap entry at the destination.
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let backup = p.with_file_name(format!(".{name}.swap-orig"));
        let _ = std::fs::rename(p, &backup);
        match self.kind {
            VerifySwapKind::Symlink => {
                let _ = std::os::unix::fs::symlink(&self.swap_target, p);
            }
            VerifySwapKind::Directory => {
                let _ = std::fs::create_dir(p);
            }
            VerifySwapKind::DifferentInode => {
                let _ = std::fs::rename(&self.swap_target, p);
            }
        }
    }
}

/// Open `p` with `O_NOFOLLOW` (a symlink at the path → ELOOP →
/// [`OpenedExisting::NotRegular`]{Symlink} — NEVER followed, even when it
/// points at a matching regular file), `fstat` the SAME descriptor, and read
/// THROUGH THE SAME descriptor — the LOCAL realization of the descriptor-
/// bound sequence [`verify_existing`] requires (the ssh transport's framed
/// helper performs the SAME sequence in ONE remote exec). `O_NONBLOCK`
/// keeps the open from blocking on a fifo/device (the entry is then
/// classified by its `fstat` type, never read). A swap at the path AFTER the
/// open is irrelevant — the descriptor pins the inode.
fn open_verify_local(p: &Path, #[cfg(test)] swap: Option<&VerifySwap>) -> Result<OpenedExisting> {
    use std::io::Read;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(test)]
    if swap.is_some_and(|s| s.fire(VerifySwapBoundary::BeforeOpen, p)) {
        // The swap consumed: the destination was replaced BEFORE the open,
        // so the open observes the SWAPPED entry.
    }
    let mut f = match opts.open(p) {
        Ok(f) => f,
        Err(e) => return Ok(local_open_err(p, e)),
    };
    #[cfg(test)]
    if swap.is_some_and(|s| s.fire(VerifySwapBoundary::AfterOpen, p)) {
        // The swap consumed: the PATH was replaced AFTER the open — the fd
        // pins the ORIGINAL inode, so the fstat and read below still
        // observe it (the swap is harmless).
    }
    let meta = match f.metadata() {
        Ok(m) => meta_to_remote(&m),
        Err(e) => {
            return Ok(OpenedExisting::Unreadable(format!(
                "verify fstat {}: {e}",
                p.display()
            )));
        }
    };
    #[cfg(test)]
    if swap.is_some_and(|s| s.fire(VerifySwapBoundary::AfterFstat, p)) {
        // The swap consumed: the PATH was replaced AFTER the fstat — the fd
        // still pins the ORIGINAL inode, so the read below observes it.
    }
    if meta.is_dir {
        return Ok(OpenedExisting::NotRegular {
            kind: NotRegularFileKind::Directory,
        });
    }
    if meta.is_symlink {
        return Ok(OpenedExisting::NotRegular {
            kind: NotRegularFileKind::Symlink,
        });
    }
    if !meta.is_file {
        return Ok(OpenedExisting::NotRegular {
            kind: NotRegularFileKind::Other,
        });
    }
    let mut content = Vec::new();
    if let Err(e) = f.read_to_end(&mut content) {
        return Ok(OpenedExisting::Unreadable(format!(
            "verify read {}: {e}",
            p.display()
        )));
    }
    Ok(OpenedExisting::Entry(OpenedEntry { meta, content }))
}

/// Map a failed `O_NOFOLLOW` open to the TYPED reason in the
/// [`VerifiedExisting`] first-failure order: ENOENT/ENOTDIR → NotFound; ELOOP
/// → NotRegularFile{Symlink} (the open NEVER follows a symlink — even one
/// pointing at a matching regular file); EISDIR → NotRegularFile{Directory};
/// every other errno (EACCES/EPERM/EIO/...) → Unreadable (a real failure,
/// never a fabricated verdict).
fn local_open_err(p: &Path, e: std::io::Error) -> OpenedExisting {
    match e.raw_os_error() {
        Some(libc::ENOENT) | Some(libc::ENOTDIR) => OpenedExisting::NotFound,
        Some(libc::ELOOP) => OpenedExisting::NotRegular {
            kind: NotRegularFileKind::Symlink,
        },
        Some(libc::EISDIR) => OpenedExisting::NotRegular {
            kind: NotRegularFileKind::Directory,
        },
        _ => OpenedExisting::Unreadable(format!("verify open {}: {e}", p.display())),
    }
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

    fn is_local(&self) -> bool {
        true
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
        // The deploy_dir's IMMUTABLE receiver-UUID marker: the PHYSICAL
        // identity of this deploy_dir, created ONCE at provisioning and
        // never changed (a re-provisioning adopts the existing marker).
        provision_receiver_uuid(self)?;
        Ok(())
    }

    fn read(&self, rel: &RootedRelativePath) -> Result<Vec<u8>> {
        std::fs::read(join(&self.base, rel))
            .map_err(|e| Error::transport(format!("read {}: {e}", rel.display())))
    }

    fn write(&self, rel: &RootedRelativePath, data: &[u8], mode: u32) -> Result<()> {
        let p = join(&self.base, rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::transport(format!("mkdir {}: {e}", parent.display())))?;
        }
        std::fs::write(&p, data)
            .map_err(|e| Error::transport(format!("write {}: {e}", p.display())))?;
        if mode != 0 {
            crate::platform::chmod(&p, mode)
                .map_err(|e| Error::transport(format!("chmod {}: {e}", p.display())))?;
        }
        Ok(())
    }

    fn create_dir(&self, rel: &RootedRelativePath) -> Result<()> {
        std::fs::create_dir(join(&self.base, rel))
            .map_err(|e| Error::transport(format!("mkdir {}: {e}", rel.display())))
    }

    fn create_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
        std::fs::create_dir_all(join(&self.base, rel))
            .map_err(|e| Error::transport(format!("mkdir {}: {e}", rel.display())))
    }

    fn set_mode(&self, rel: &RootedRelativePath, mode: u32) -> Result<()> {
        crate::platform::chmod(&join(&self.base, rel), mode & 0o7777)
            .map_err(|e| Error::transport(format!("chmod {}: {e}", rel.display())))
    }

    fn list(&self, rel: &RootedRelativePath) -> Result<Vec<RemoteEntry>> {
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
                mode: crate::platform::metadata_mode(&m),
            });
        }
        Ok(out)
    }

    fn rename(&self, from: &RootedRelativePath, to: &RootedRelativePath) -> Result<()> {
        let f = join(&self.base, from);
        let t = join(&self.base, to);
        if let Some(parent) = t.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::rename(&f, &t).map_err(|e| {
            Error::transport(format!("rename {} -> {}: {e}", f.display(), t.display()))
        })
    }

    fn symlink(&self, target: &Path, link: &RootedRelativePath) -> Result<()> {
        let l = join(&self.base, link);
        if let Some(parent) = l.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let _ = std::fs::remove_file(&l);
        let res = crate::platform::symlink(target, &l);
        res.map_err(|e| {
            Error::transport(format!(
                "symlink {} -> {}: {e}",
                l.display(),
                target.display()
            ))
        })
    }

    fn read_link(&self, rel: &RootedRelativePath) -> Result<PathBuf> {
        let p = join(&self.base, rel);
        std::fs::read_link(&p)
            .map_err(|e| Error::transport(format!("readlink {}: {e}", p.display())))
    }

    fn remove_file(&self, rel: &RootedRelativePath) -> Result<()> {
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

    fn remove_file_if(&self, rel: &RootedRelativePath, expected: &[u8]) -> Result<RemoveIfVerdict> {
        // If this is the lock path, serialize through the sidecar mutex so
        // the compare-then-delete becomes operation-atomic: a contender's
        // create-if-absent cannot win the freed path mid-operation.
        if rel.as_path() == crate::remote::layout::operation_lock().as_path() {
            return with_observed_operation_lock(&self.base, || {
                self.remove_file_if_inner(rel, expected)
            });
        }
        self.remove_file_if_inner(rel, expected)
    }

    fn try_write_new(&self, rel: &RootedRelativePath, data: &[u8]) -> Result<CreateNewVerdict> {
        if rel.as_path() == crate::remote::layout::operation_lock().as_path() {
            return with_observed_operation_lock(&self.base, || {
                self.try_write_new_inner(rel, data)
            });
        }
        self.try_write_new_inner(rel, data)
    }

    fn try_write_new_with(
        &self,
        rel: &RootedRelativePath,
        data: &[u8],
        equivalence: ContentEquivalence,
    ) -> Result<CreateNewVerdict> {
        if rel.as_path() == crate::remote::layout::operation_lock().as_path() {
            return with_observed_operation_lock(&self.base, || {
                self.try_write_new_with_inner(rel, data, equivalence)
            });
        }
        self.try_write_new_with_inner(rel, data, equivalence)
    }

    fn remove_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
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

    fn fsync_tree(&self, rel: &RootedRelativePath) -> Result<()> {
        let root = join(&self.base, rel);
        // Every file is fsynced; directories are collected and fsynced
        // DEEPEST-FIRST (a parent's fsync runs only after every child's), so
        // the whole tree is durable before the atomic install rename.
        let mut dirs: Vec<PathBuf> = Vec::new();
        for entry in WalkDir::new(&root).into_iter() {
            let entry = entry.map_err(|e| Error::transport(format!("walk: {e}")))?;
            let p = entry.path();
            let meta = std::fs::symlink_metadata(p)
                .map_err(|e| Error::transport(format!("stat {}: {e}", p.display())))?;
            if meta.is_dir() {
                dirs.push(p.to_path_buf());
            } else if meta.is_file() {
                let f = std::fs::File::open(p)
                    .map_err(|e| Error::transport(format!("open {}: {e}", p.display())))?;
                f.sync_all()
                    .map_err(|e| Error::transport(format!("fsync {}: {e}", p.display())))?;
            }
        }
        dirs.sort_by_key(|d| std::cmp::Reverse(d.components().count()));
        for d in dirs {
            let f = std::fs::File::open(&d)
                .map_err(|e| Error::transport(format!("open dir {}: {e}", d.display())))?;
            f.sync_all()
                .map_err(|e| Error::transport(format!("fsync dir {}: {e}", d.display())))?;
        }
        Ok(())
    }

    fn fsync_parent(&self, rel: &RootedRelativePath) -> Result<()> {
        let p = join(&self.base, rel);
        let parent = p.parent().ok_or_else(|| {
            Error::transport(format!(
                "fsync parent of {}: no parent directory",
                p.display()
            ))
        })?;
        let dir = std::fs::File::open(parent)
            .map_err(|e| Error::transport(format!("open parent dir {}: {e}", parent.display())))?;
        dir.sync_all()
            .map_err(|e| Error::transport(format!("fsync parent dir {}: {e}", parent.display())))
    }

    fn exists(&self, rel: &RootedRelativePath) -> bool {
        join(&self.base, rel).exists()
    }

    fn metadata(&self, rel: &RootedRelativePath) -> Result<RemoteMeta> {
        self.metadata_opt(rel)?.ok_or_else(|| {
            Error::NotFound(format!(
                "stat {}: not found",
                join(&self.base, rel).display()
            ))
        })
    }

    fn metadata_opt(&self, rel: &RootedRelativePath) -> Result<Option<RemoteMeta>> {
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

impl LocalTransport {
    fn remove_file_if_inner(
        &self,
        rel: &RootedRelativePath,
        expected: &[u8],
    ) -> Result<RemoveIfVerdict> {
        let p = join(&self.base, rel);
        // When already holding the sidecar (we are inside the crate's
        // with_operation_lock_sidecar), the mutation is already serialized, so a simple read-compare-unlink
        // keeps the record continuously visible for a mismatched remove (no
        // transient absence) and is safe from TOCTOU.
        if SIDECAR_DEPTH.with(|c| c.get() > 0) {
            let cur = match std::fs::read(&p) {
                Ok(c) => c,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(RemoveIfVerdict::Absent);
                }
                Err(e) => return Err(Error::transport(format!("read {}: {e}", p.display()))),
            };
            if cur == expected {
                match std::fs::remove_file(&p) {
                    Ok(()) => return Ok(RemoveIfVerdict::Removed),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(RemoveIfVerdict::Absent);
                    }
                    Err(e) => return Err(Error::transport(format!("remove {}: {e}", p.display()))),
                }
            } else {
                return Ok(RemoveIfVerdict::Mismatch);
            }
        }
        use std::sync::atomic::{AtomicU64, Ordering};
        static CLAIM_COUNTER: AtomicU64 = AtomicU64::new(0);

        // Fallback claim path (when not under sidecar, e.g. non-lock paths
        // or direct calls): atomic rename claim, verify, delete or restore.
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

    fn try_write_new_inner(
        &self,
        rel: &RootedRelativePath,
        data: &[u8],
    ) -> Result<CreateNewVerdict> {
        self.try_write_new_with_inner(rel, data, ContentEquivalence::Exact)
    }

    fn try_write_new_with_inner(
        &self,
        rel: &RootedRelativePath,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;

    /// A delegating wrapper used to pin the provisioning contract. With
    /// `provision == true` it carries the SAME explicit `provision_layout`
    /// override every test wrapper in the transport subsystem carries; with
    /// `provision == false` it mirrors the substrate trait's default (a
    /// no-op), reproducing a wrapper that stopped provisioning.
    struct ProvisionProbe {
        inner: LocalTransport,
        provision: bool,
    }

    impl Remote for ProvisionProbe {
        fn root(&self) -> &Path {
            self.inner.root()
        }
        fn is_local(&self) -> bool {
            self.inner.is_local()
        }
        fn provision_layout(&self) -> Result<()> {
            if self.provision {
                provision_receiver_marker(self)
            } else {
                Ok(())
            }
        }
        fn read(&self, rel: &RootedRelativePath) -> Result<Vec<u8>> {
            self.inner.read(rel)
        }
        fn write(&self, rel: &RootedRelativePath, data: &[u8], mode: u32) -> Result<()> {
            self.inner.write(rel, data, mode)
        }
        fn try_write_new(&self, rel: &RootedRelativePath, data: &[u8]) -> Result<CreateNewVerdict> {
            self.inner.try_write_new(rel, data)
        }
        fn create_dir(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.create_dir(rel)
        }
        fn create_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.create_dir_all(rel)
        }
        fn set_mode(&self, rel: &RootedRelativePath, mode: u32) -> Result<()> {
            self.inner.set_mode(rel, mode)
        }
        fn list(&self, rel: &RootedRelativePath) -> Result<Vec<RemoteEntry>> {
            self.inner.list(rel)
        }
        fn rename(&self, from: &RootedRelativePath, to: &RootedRelativePath) -> Result<()> {
            self.inner.rename(from, to)
        }
        fn symlink(&self, target: &Path, link: &RootedRelativePath) -> Result<()> {
            self.inner.symlink(target, link)
        }
        fn read_link(&self, rel: &RootedRelativePath) -> Result<PathBuf> {
            self.inner.read_link(rel)
        }
        fn remove_file(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.remove_file(rel)
        }
        fn remove_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.remove_dir_all(rel)
        }
        fn exists(&self, rel: &RootedRelativePath) -> bool {
            self.inner.exists(rel)
        }
        fn metadata(&self, rel: &RootedRelativePath) -> Result<RemoteMeta> {
            self.inner.metadata(rel)
        }
        fn exec(&self, argv: &[String], timeout: Duration) -> Result<ExecOutcome> {
            self.inner.exec(argv, timeout)
        }
        fn filesystem_bytes(&self) -> Result<FsBytes> {
            self.inner.filesystem_bytes()
        }
    }

    /// The marker-only provisioning path every wrapper override runs: it goes
    /// through the wrapper's OWN `Remote` methods and leaves the deploy_dir's
    /// immutable receiver marker behind.
    #[test]
    fn provision_receiver_marker_creates_the_marker_through_the_remote() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let base = dir.path().join("explicit");
        let probe = ProvisionProbe {
            inner: LocalTransport::new(&SysEnv::from_process(), base).unwrap(),
            provision: true,
        };
        let marker = crate::remote::layout::receiver_uuid();
        assert!(
            !probe.inner.exists(&marker),
            "construction alone does not provision: the marker must be absent before"
        );
        probe.provision_layout().unwrap();
        assert!(
            probe.inner.exists(&marker),
            "the explicit override provisions the receiver marker"
        );
    }

    /// The control: a wrapper that falls through to the substrate default
    /// provisions NOTHING. This is why every wrapper needs the explicit
    /// override above — without it the marker is silently absent.
    #[test]
    fn a_wrapper_without_the_override_provisions_nothing() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let base = dir.path().join("default");
        let probe = ProvisionProbe {
            inner: LocalTransport::new(&SysEnv::from_process(), base).unwrap(),
            provision: false,
        };
        probe.provision_layout().unwrap();
        assert!(
            !probe.inner.exists(&crate::remote::layout::receiver_uuid()),
            "the substrate `provision_layout` default is a no-op: a wrapper that does not \
             override it leaves the receiver marker absent"
        );
    }

    /// Every `impl ... Remote for` block in the crate's own sources and in the
    /// integration tests must carry an explicit `provision_layout` that
    /// provisions. The substrate trait's default is a no-op, so a wrapper that
    /// relied on `deploy`'s marker-creating default would silently stop
    /// provisioning when the trait is swapped. The wrappers are private test
    /// types spread across a dozen modules with no runtime registry, so the
    /// one check that can see all of them is a source-shape check.
    #[test]
    fn every_remote_impl_carries_an_explicit_provisioning_override() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut checked = 0usize;
        let mut offenders: Vec<String> = Vec::new();
        for sub in ["src", "tests"] {
            for entry in walkdir::WalkDir::new(root.join(sub))
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                // `tests/ui/*` are trybuild compile-fail fixtures and
                // `src-tmp-check.rs` is a stray, undeclared file — neither is
                // compiled into the crate.
                if path.components().any(|c| c.as_os_str() == "ui")
                    || path.file_name().and_then(|n| n.to_str()) == Some("src-tmp-check.rs")
                {
                    continue;
                }
                let text = std::fs::read_to_string(path).expect("a source file reads");
                for (header, body) in remote_impl_blocks(&text) {
                    checked += 1;
                    let provisioned = body.contains("provision_receiver_marker(")
                        || body.contains("provision_receiver_uuid(")
                        || body.contains("inner.provision_layout(");
                    if !provisioned {
                        offenders.push(format!("{}: {header}", path.display()));
                    }
                }
            }
        }
        assert!(
            checked >= 31,
            "the scan should see every `Remote` impl, saw {checked}"
        );
        assert!(
            offenders.is_empty(),
            "these `Remote` impls do not provision the receiver marker and would fall \
             through to the substrate no-op default: {offenders:#?}"
        );
    }

    /// The `(header, body)` of every `impl ... Remote for ...` block in
    /// `text`, found by INDENTATION: every impl body in this codebase closes
    /// with a `}` at the impl's own indentation.
    fn remote_impl_blocks(text: &str) -> Vec<(String, String)> {
        let lines: Vec<&str> = text.lines().collect();
        let mut blocks = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if !trimmed.starts_with("impl") || !trimmed.contains("Remote for") {
                continue;
            }
            let indent = line.len() - trimmed.len();
            let mut body = String::new();
            for l in &lines[i + 1..] {
                if l.trim() == "}" && (l.len() - l.trim_start().len()) == indent {
                    break;
                }
                body.push_str(l);
                body.push('\n');
            }
            blocks.push((trimmed.to_string(), body));
        }
        blocks
    }

    /// The deploy_dir's IMMUTABLE receiver-UUID marker: `provision_layout`
    /// creates it ONCE, a re-provisioning adopts the SAME identity (never a
    /// new one), and `read_receiver_uuid` reads it back — the PHYSICAL
    /// identity exact rollback compares.
    #[test]
    fn provision_layout_creates_immutable_receiver_uuid() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let t = LocalTransport::new(&SysEnv::from_process(), dir.path().join("r")).unwrap();
        t.provision_layout().unwrap();
        let marker = crate::remote::layout::receiver_uuid();
        assert!(
            t.exists(&marker),
            "provisioning creates the receiver-UUID marker"
        );
        let first = receiver_marker::read_receiver_uuid(&t).expect("the marker reads back");
        assert!(
            first.as_str().starts_with("recv-"),
            "the marker carries a receiver UUID, got {:?}",
            first.as_str()
        );
        // Re-provisioning (a second push to the same deploy_dir) adopts the
        // SAME immutable identity — never a new one.
        t.provision_layout().unwrap();
        let second = receiver_marker::read_receiver_uuid(&t).expect("the marker reads back");
        assert_eq!(
            first, second,
            "the receiver UUID is IMMUTABLE: re-provisioning adopts the existing marker"
        );
        // A pre-existing marker with DIFFERENT content is adopted too (the
        // first writer wins — the physical identity is whatever was created
        // first), and a malformed marker fails closed.
        let t2 = LocalTransport::new(&SysEnv::from_process(), dir.path().join("r2")).unwrap();
        t2.provision_layout().unwrap();
        let foreign = crate::identity::ReceiverUuid::generate();
        t2.write(&marker, foreign.as_str().as_bytes(), 0o644)
            .unwrap();
        t2.provision_layout().unwrap();
        assert_eq!(
            receiver_marker::read_receiver_uuid(&t2).expect("the existing marker is adopted"),
            foreign,
            "a re-provisioning never replaces the existing marker"
        );
        let t3 = LocalTransport::new(&SysEnv::from_process(), dir.path().join("r3")).unwrap();
        t3.provision_layout().unwrap();
        t3.write(&marker, b"not-a-uuid", 0o644).unwrap();
        receiver_marker::read_receiver_uuid(&t3).expect_err("a malformed marker fails closed");
    }

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
                        let rel = RootedRelativePath::parse(
                            &Path::new("markers").join(format!("m{i}.json")),
                        )
                        .unwrap();
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
        t.create_dir_all(&RootedRelativePath::parse(Path::new("generations/gen1")).unwrap())
            .unwrap();
        t.symlink(
            Path::new("generations/gen1"),
            &RootedRelativePath::parse(Path::new(".tmp.x")).unwrap(),
        )
        .unwrap();
        assert!(
            t.exists(&RootedRelativePath::parse(Path::new(".tmp.x")).unwrap()),
            "symlink should exist"
        );
        t.rename(
            &RootedRelativePath::parse(Path::new(".tmp.x")).unwrap(),
            &RootedRelativePath::parse(Path::new("current")).unwrap(),
        )
        .unwrap();
        assert!(
            t.exists(&RootedRelativePath::parse(Path::new("current")).unwrap()),
            "current should exist after rename"
        );
        let target = t
            .read_link(&RootedRelativePath::parse(Path::new("current")).unwrap())
            .unwrap();
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
        let rel = RootedRelativePath::parse(Path::new("state/op.json")).unwrap();
        let data = b"{\"op\":\"1\"}";

        assert_eq!(
            t.try_write_new(&rel, data).unwrap(),
            CreateNewVerdict::Created,
            "a fresh install wins"
        );
        let p = t.root().join(rel.as_path());
        assert_eq!(std::fs::read(&p).unwrap(), data, "exact bytes installed");
        assert_eq!(
            std::fs::metadata(&p).unwrap().mode() & 0o7777,
            IMMUTABLE_RECORD_MODE & 0o7777,
            "the record must carry the canonical final mode"
        );
        // Identical retry: convergent — AlreadyPresent, no error, no replace.
        assert_eq!(
            t.try_write_new(&rel, data).unwrap(),
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
                t.try_write_new(&rel, b"other").unwrap(),
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
        let rel = RootedRelativePath::parse(Path::new("state/op.lock")).unwrap();
        let data = b"{\"owner\":\"a\",\"token\":1}";

        // Absent: nothing to remove — the idempotent verdict.
        assert_eq!(
            t.remove_file_if(&rel, data).unwrap(),
            RemoveIfVerdict::Absent,
            "a genuinely absent entry is Absent, never an error"
        );
        // Match: the entry carried EXACTLY the expected bytes — removed.
        t.try_write_new(&rel, data).unwrap();
        assert_eq!(
            t.remove_file_if(&rel, data).unwrap(),
            RemoveIfVerdict::Removed,
            "a byte-identical match is removed"
        );
        assert!(
            t.metadata_opt(&rel).unwrap().is_none(),
            "the matched entry must be gone"
        );
        // Mismatch: different content — the winner is restored untouched,
        // NEVER removed, NEVER replaced.
        t.try_write_new(&rel, data).unwrap();
        assert_eq!(
            t.remove_file_if(&rel, b"{\"owner\":\"b\",\"token\":2}")
                .unwrap(),
            RemoveIfVerdict::Mismatch,
            "different content is a Mismatch, never a delete"
        );
        assert_eq!(
            t.read(&rel).unwrap(),
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

    #[cfg(test)]
    use proptest::prelude::*;
    #[cfg(test)]
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
            let rel = RootedRelativePath::parse(Path::new("state/record.bin")).unwrap();
            let dest = root.join(rel.as_path());
            let dest_name = rel.file_name().unwrap().to_string_lossy().into_owned();

            match scenario {
                CreateNewScenario::Healthy => {
                    let verdict = durable_create_new(
                        &root,
                        &rel,
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
                        &rel,
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
                        &rel,
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
                    durable_create_new(&root, &rel, &content, CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None })
                        .expect("the first install must succeed");
                    let verdict =
                        durable_create_new(&root, &rel, &content, CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None })
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
                    // winner's bytes stay intact. The winner is pre-created
                    // WITH THE INTENDED MODE: the verification's
                    // first-failure precedence checks the mode BEFORE the
                    // content (see [`verify_existing`] step 4 before step 5),
                    // so a winner left at `std::fs::write`'s umask-default
                    // mode would be reported as a MODE mismatch — this cell
                    // tests a CONTENT-only mismatch, where content must be
                    // the ONLY difference.
                    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                    let other: Vec<u8> = if content.is_empty() {
                        vec![0u8]
                    } else {
                        content.iter().map(|b| b.wrapping_add(1)).collect()
                    };
                    prop_assert_ne!(&other, &content, "the winner must differ from the intent");
                    std::fs::write(&dest, &other).unwrap();
                    std::fs::set_permissions(
                        &dest,
                        std::fs::Permissions::from_mode(mode & 0o7777),
                    )
                    .unwrap();
                    let verdict = durable_create_new(
                        &root,
                        &rel,
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
                    durable_create_new(&root, &rel, &content, CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None })
                        .expect("the first install must succeed");
                    let other_mode = if (mode & 0o7777) == 0o600 { 0o644 } else { 0o600 };
                    std::fs::set_permissions(
                        &dest,
                        std::fs::Permissions::from_mode(other_mode),
                    )
                    .unwrap();
                    let verdict =
                        durable_create_new(&root, &rel, &content, CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None })
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
                        &rel,
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
                    durable_create_new(&root, &rel, &content, CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None })
                        .expect("the first install must succeed");
                    let fault = CreateNewFault::new(CreateNewStep::ParentFsync);
                    let err = durable_create_new(
                        &root,
                        &rel,
                        &content,
                        CreateNewOptions {
                            mode,
                            content: ContentEquivalence::Exact,
                            fault: Some(&fault)},
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

        fn is_local(&self) -> bool {
            true
        }

        fn provision_layout(&self) -> Result<()> {
            crate::remote::transport::provision_receiver_marker(self)?;
            Ok(())
        }

        fn read(&self, rel: &RootedRelativePath) -> Result<Vec<u8>> {
            self.inner.read(rel)
        }
        fn write(&self, rel: &RootedRelativePath, data: &[u8], mode: u32) -> Result<()> {
            self.inner.write(rel, data, mode)
        }
        fn try_write_new(&self, rel: &RootedRelativePath, data: &[u8]) -> Result<CreateNewVerdict> {
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
        fn create_dir(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.create_dir(rel)
        }
        fn create_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.create_dir_all(rel)
        }
        fn set_mode(&self, rel: &RootedRelativePath, mode: u32) -> Result<()> {
            self.inner.set_mode(rel, mode)
        }
        fn list(&self, rel: &RootedRelativePath) -> Result<Vec<RemoteEntry>> {
            self.inner.list(rel)
        }
        fn rename(&self, from: &RootedRelativePath, to: &RootedRelativePath) -> Result<()> {
            self.inner.rename(from, to)
        }
        fn symlink(&self, target: &Path, link: &RootedRelativePath) -> Result<()> {
            self.inner.symlink(target, link)
        }
        fn read_link(&self, rel: &RootedRelativePath) -> Result<PathBuf> {
            self.inner.read_link(rel)
        }
        fn remove_file(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.remove_file(rel)
        }
        fn remove_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.remove_dir_all(rel)
        }
        fn exists(&self, rel: &RootedRelativePath) -> bool {
            self.inner.exists(rel)
        }
        fn metadata(&self, rel: &RootedRelativePath) -> Result<RemoteMeta> {
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
            let rel = RootedRelativePath::parse(Path::new("state/record.bin")).unwrap();
            let dest = t.root().join(rel.as_path());
            let dest_name = rel.file_name().unwrap().to_string_lossy().into_owned();
            let final_mode = IMMUTABLE_RECORD_MODE & 0o7777;

            match state {
                TransportVerdictState::Fresh => {
                    let verdict = t
                        .try_write_new(&rel, &content)
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
                        .try_write_new(&rel, &content)
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
                        .try_write_new(&rel, &content)
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
                        .try_write_new(&rel, &content)
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
                        .try_write_new(&rel, &content)
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
                        fault: CreateNewFault::new(step)};
                    let err = w
                        .try_write_new(&rel, &content)
                        .expect_err("a failure at every stage must propagate as Err");
                    prop_assert!(
                        err.to_string().contains("forced to fail (once)"),
                        "the injected fault must be the propagated failure, got: {err}"
                    );
                    let retry = w
                        .try_write_new(&rel, &content)
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

    /// The swap-at-every-boundary property of the descriptor-bound
    /// verification (the LOCAL leg): a REGULAR→SYMLINK / REGULAR→DIRECTORY /
    /// REGULAR→DIFFERENT-INODE swap is injected at EVERY boundary of the
    /// open→fstat→read sequence — BEFORE the `O_NOFOLLOW` open, BETWEEN the
    /// open and the fstat, BETWEEN the fstat and the read — and the verdict
    /// must NEVER mix two inodes' observations:
    ///
    /// * a swap BEFORE the open changes WHAT is opened: the verdict reflects
    ///   the SWAPPED entry consistently — a symlink →
    ///   NotRegularFile{Symlink} (the `O_NOFOLLOW` open NEVER follows, even
    ///   a symlink pointing at a regular file whose bytes+mode match the
    ///   intent), a directory → NotRegularFile{Directory}, a different-inode
    ///   regular file (mode AND content both differing from the intent) →
    ///   ModeMismatch naming the SWAPPED inode's mode — a REJECTION;
    /// * a swap AFTER the open (between open/fstat or fstat/read) is
    ///   HARMLESS: the descriptor pins the ORIGINAL inode, so the verdict is
    ///   AlreadyPresent with the ORIGINAL inode's mode AND content (the
    ///   symlink target / the different inode carry DIFFERENT content and
    ///   the directory is unreadable as a file — a path-following read or a
    ///   re-open would NOT yield AlreadyPresent, so the assertion catches
    ///   any metadata/content mix).
    ///
    /// Bounded cases, fixed seed 0x5EED_5EED (house style), no persistence.
    fn swap_case() -> impl Strategy<Value = (VerifySwapBoundary, VerifySwapKind)> {
        prop_oneof![
            Just((VerifySwapBoundary::BeforeOpen, VerifySwapKind::Symlink)),
            Just((VerifySwapBoundary::BeforeOpen, VerifySwapKind::Directory)),
            Just((
                VerifySwapBoundary::BeforeOpen,
                VerifySwapKind::DifferentInode
            )),
            Just((VerifySwapBoundary::AfterOpen, VerifySwapKind::Symlink)),
            Just((VerifySwapBoundary::AfterOpen, VerifySwapKind::Directory)),
            Just((
                VerifySwapBoundary::AfterOpen,
                VerifySwapKind::DifferentInode
            )),
            Just((VerifySwapBoundary::AfterFstat, VerifySwapKind::Symlink)),
            Just((VerifySwapBoundary::AfterFstat, VerifySwapKind::Directory)),
            Just((
                VerifySwapBoundary::AfterFstat,
                VerifySwapKind::DifferentInode
            )),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(64),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn verify_existing_swap_at_every_boundary(
            (boundary, kind) in swap_case(),
        ) {
            use std::os::unix::fs::PermissionsExt;

            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let root = dir.path().to_path_buf();
            let rel = RootedRelativePath::parse(Path::new("state/record.json")).unwrap();
            let dest = root.join(rel.as_path());
            let required = IMMUTABLE_RECORD_MODE & 0o7777;
            let wrong_mode = if required == 0o600 { 0o640 } else { 0o600 };
            let intended: &[u8] = br#"{"a":1,"b":2}"#;
            // The swapped-in observations differ from the original's: a
            // path-following read (or a metadata/content mix) is therefore
            // detectable — only the SAME-inode verdict passes the table.
            let swapped_content: &[u8] = br#"{"a":9,"b":9}"#;

            std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
            // The ORIGINAL entry: a regular file matching the intent (bytes
            // AND mode) — a no-swap verification would accept it.
            std::fs::write(&dest, intended).unwrap();
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(required)).unwrap();
            // The pre-staged swap entry: the symlink target AND the
            // different-inode regular file (a fresh inode with mode + content
            // both differing from the intent).
            let target = dest.with_file_name("record.json.swap-target");
            std::fs::write(&target, swapped_content).unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(wrong_mode)).unwrap();

            let swap = VerifySwap::new(boundary, kind, &target);
            let verified = verify_existing(
                || open_verify_local(&dest, Some(&swap)),
                intended,
                required,
                ContentEquivalence::Exact,
            )
            .expect("the descriptor-bound verification is a verdict, not an I/O error");
            let verdict = verified_to_verdict(verified);

            // THE INVARIANT: success (AlreadyPresent) ONLY when the metadata
            // AND the content came from the SAME OPENED INODE — the
            // fd-pinned ORIGINAL for a post-open swap, the SWAPPED entry
            // (consistently, as a rejection) for a pre-open swap.
            match boundary {
                VerifySwapBoundary::BeforeOpen => match kind {
                    VerifySwapKind::Symlink => prop_assert_eq!(
                        verdict,
                        CreateNewVerdict::Conflict(VerifiedExisting::NotRegularFile {
                            kind: NotRegularFileKind::Symlink}),
                        "a pre-open symlink swap must be rejected — the O_NOFOLLOW open never follows"
                    ),
                    VerifySwapKind::Directory => prop_assert_eq!(
                        verdict,
                        CreateNewVerdict::Conflict(VerifiedExisting::NotRegularFile {
                            kind: NotRegularFileKind::Directory}),
                        "a pre-open directory swap must be rejected"
                    ),
                    VerifySwapKind::DifferentInode => prop_assert_eq!(
                        verdict,
                        CreateNewVerdict::Conflict(VerifiedExisting::ModeMismatch {
                            actual: wrong_mode & 0o7777,
                            required}),
                        "a pre-open different-inode swap must be rejected with the SWAPPED inode's mode"
                    )},
                VerifySwapBoundary::AfterOpen | VerifySwapBoundary::AfterFstat => {
                    prop_assert_eq!(
                        verdict,
                        CreateNewVerdict::AlreadyPresent,
                        "a post-open swap is harmless: the descriptor pins the ORIGINAL inode, so the verdict must reflect ITS metadata AND content — never a mix"
                    );
                }
            }
        }
    }

    /// The operation-lock sidecar is now the CRATE's
    /// ([`storekit::transport::with_operation_lock_sidecar`]): the same
    /// `layout::operation_lock_sidecar()` record, the same
    /// blocking-with-deadline policy (2 s deadline, 5 ms retries), opened
    /// read-only and never unlinked. This test holds that record's flock
    /// directly and proves a lock mutation on the transport waits the full
    /// deadline and then fails with the contention message — never hangs,
    /// never silently proceeds — and that the SAME transport then succeeds on
    /// the SAME record once the hold is released. The wait-loop arithmetic
    /// itself (interval bounding, EINTR retry, non-contention immediate
    /// failure) is pinned by the crate's own `wait_for_sidecar_flock` tests,
    /// since the loop is now the crate's. The three deploy unit tests that
    /// duplicated the clock-injected loop were replaced by these four
    /// crate-backed behaviour tests, which pin the policy, the record, the
    /// wait, and the stable inode from deploy's side.
    #[cfg(unix)]
    #[test]
    fn crate_backed_sidecar_waits_the_deadline_then_fails_typed() {
        use std::os::unix::io::AsRawFd;
        use std::time::Instant;
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let base = dir.path().join("remote");
        let transport = LocalTransport::new(&crate::testutil::fixture_env(), base.clone()).unwrap();

        // The SAME record the crate's sidecar names.
        let sidecar = base.join(crate::remote::layout::operation_lock_sidecar().as_path());
        std::fs::create_dir_all(sidecar.parent().unwrap()).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&sidecar)
            .expect("create the sidecar record once");

        // Hold the sidecar flock on a read-only descriptor, exactly as the
        // crate's critical section does.
        let held = std::fs::OpenOptions::new()
            .read(true)
            .open(&sidecar)
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0,
            "the test must hold the sidecar flock"
        );

        let start = Instant::now();
        let res = transport.try_write_new(&crate::remote::layout::operation_lock(), b"held\n");
        let elapsed = start.elapsed();
        let err = res.expect_err("a held sidecar must refuse the lock mutation");
        assert!(
            err.to_string().contains("remained contended for"),
            "the timeout must be the sidecar-wait refusal, got: {err}"
        );
        assert!(
            elapsed >= Duration::from_secs(2),
            "the wait must run to the 2 s deadline, elapsed {elapsed:?}"
        );
        assert!(
            elapsed <= Duration::from_secs(4),
            "the wait must not hang past the deadline: elapsed {elapsed:?}"
        );

        // Release, and the SAME transport now succeeds on the SAME record.
        assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_UN) }, 0);
        let verdict = transport
            .try_write_new(&crate::remote::layout::operation_lock(), b"held\n")
            .unwrap();
        assert!(matches!(
            verdict,
            CreateNewVerdict::Created | CreateNewVerdict::AlreadyPresent
        ));
    }

    /// The sidecar policy `deploy` now relies on is the crate's, and its
    /// values are pinned: a 2 s monotonic deadline with 5 ms retries. A drift
    /// in either constant changes the observable wait, so it is asserted here
    /// as well as in the crate.
    #[test]
    fn crate_sidecar_policy_is_the_2s_5ms_deadline() {
        assert_eq!(
            storekit::transport::SIDECAR_WAIT_TIMEOUT,
            Duration::from_secs(2),
            "the sidecar deadline is 2 s"
        );
        assert_eq!(
            storekit::transport::SIDECAR_RETRY_INTERVAL,
            Duration::from_millis(5),
            "the sidecar retry interval is 5 ms"
        );
    }

    /// A holder that RELEASES before the deadline is WAITED for and then
    /// admitted: the crate-backed critical section is a blocking mutex, not an
    /// immediate refusal. The call must return well inside the 2 s deadline.
    #[cfg(unix)]
    #[test]
    fn crate_backed_sidecar_admits_a_holder_released_before_the_deadline() {
        use std::os::unix::io::AsRawFd;
        use std::time::Instant;
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let base = dir.path().join("remote");
        let transport = LocalTransport::new(&crate::testutil::fixture_env(), base.clone()).unwrap();
        let sidecar = base.join(crate::remote::layout::operation_lock_sidecar().as_path());
        std::fs::create_dir_all(sidecar.parent().unwrap()).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&sidecar)
            .expect("create the sidecar record once");
        let held = std::fs::OpenOptions::new()
            .read(true)
            .open(&sidecar)
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_UN) };
        });
        let start = Instant::now();
        let verdict = transport
            .try_write_new(&crate::remote::layout::operation_lock(), b"admitted\n")
            .expect("a holder released before the deadline must be admitted");
        let elapsed = start.elapsed();
        releaser.join().unwrap();
        assert!(matches!(
            verdict,
            CreateNewVerdict::Created | CreateNewVerdict::AlreadyPresent
        ));
        assert!(
            elapsed >= Duration::from_millis(100),
            "the call must actually have waited for the live holder: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "the call must have been admitted by the release, not the deadline: {elapsed:?}"
        );
    }

    /// The crate-owned sidecar record has a STABLE inode: created once, never
    /// unlinked or recreated by a mutation, so every participant flocks the
    /// same file. Pinned by (dev, ino) via `MetadataExt`.
    #[cfg(unix)]
    #[test]
    fn crate_backed_sidecar_record_is_never_unlinked() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let base = dir.path().join("remote");
        let transport = LocalTransport::new(&crate::testutil::fixture_env(), base.clone()).unwrap();
        let lock = crate::remote::layout::operation_lock();
        transport.try_write_new(&lock, b"a\n").unwrap();
        let sidecar = base.join(crate::remote::layout::operation_lock_sidecar().as_path());
        let first = std::fs::metadata(&sidecar).unwrap();
        transport.remove_file_if(&lock, b"a\n").unwrap();
        transport.try_write_new(&lock, b"b\n").unwrap();
        let second = std::fs::metadata(&sidecar).unwrap();
        assert_eq!(
            (first.dev(), first.ino()),
            (second.dev(), second.ino()),
            "the sidecar inode must be stable: never unlinked or recreated"
        );
    }
}
