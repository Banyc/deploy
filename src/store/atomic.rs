//! Durable atomic filesystem I/O for the store.
//!
//! The atomic-replace protocol this module implements is the store's
//! durability machinery: write a UNIQUE temp file in the same directory,
//! chmod it private (0o600) BEFORE it can become visible under its final
//! name, fsync it, rename it into place (atomic on POSIX — a reader never
//! sees a torn record), then fsync the parent directory. The replace has
//! TWO DISTINCT COMMIT POINTS and `write_atomic_replace` reports them
//! EXPLICITLY ([`ReplaceOutcome`]): the RENAME is commit point 1 (the new
//! content becomes VISIBLE under its final name), and the PARENT-DIRECTORY
//! FSYNC is commit point 2 (the rename becomes DURABLE across power loss).
//! A failure before the rename is an `Err` — the OLD content is still
//! visible. A failure of the parent-directory open/fsync AFTER the rename
//! is [`ReplaceOutcome::ReplacedDurabilityUnknown`] — the NEW content IS
//! visible but its durability is UNCONFIRMED — never a bare `Err` (a bare
//! `Err` would conflate "the rename never happened" with "the rename
//! happened but the durability commit could not be verified"). The
//! durability of these writes is the checkpoint's ordering guarantee — the
//! floor marker must be durable BEFORE the compaction deletes anything, so
//! an interrupted compaction can never expose history below the floor; the
//! checkpoint's per-stage sequence (the transactional ADVANCE and its
//! restore) lives in [`crate::retention::history_floor`] on top of these
//! primitives.
//!
//! The helpers here are the shared plumbing — `pub(crate)` free functions
//! imported by [`crate::store::local`] and [`crate::retention::history_floor`]:
//! the tri-state existence check (`path_state`), the fail-closed
//! parent-dir fsync (`sync_parent_dir`), unique temp naming
//! (`temp_name_for`), the atomic marker/JSONL rewrites
//! (`write_atomic_replace`, `write_jsonl_atomic`), private permissions
//! (`set_private`, `ensure_private_dir`), the tree-object directory
//! copy (`copy_dir_recursive`), and the JSON readers.
//!
//! Parse-sensitive marker reads: a PRESENT-but-malformed marker CONTENT is
//! semantic CORRUPTION and maps to [`Error::integrity`] via
//! `read_json_marker` (the file exists, it is just not a valid marker),
//! while a mechanical filesystem I/O failure (open/read/rename/fsync)
//! stays [`Error::store`] — the class split a caller can always
//! distinguish "this marker is corrupt" from "disk read failed".
//! `read_json` folds both into [`Error::store`], which is correct for
//! its non-marker callers (observed.json, retention-debt.json, tree
//! metadata, ...); callers of `read_json_marker` must still perform
//! their own schema-version check after a successful parse (also
//! [`Error::integrity`]): an unsupported `schema_version` is a
//! marker-format violation, not an I/O failure.

use crate::error::{Error, Result};
use std::ffi::{CStr, CString, OsStr};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub(crate) fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes =
        std::fs::read(path).map_err(|e| Error::store(format!("read {}: {e}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::store(format!("deserialize {}: {e}", path.display())))
}
/// TRI-STATE existence check for marker/backup/log DISCOVERY: is `path`
/// present? A genuine [`std::io::ErrorKind::NotFound`] from
/// [`std::fs::symlink_metadata`] is the ONE outcome that reads as ABSENCE
/// (`Ok(false)`); EVERY other filesystem error (EACCES, EIO, ENOTDIR, ...)
/// is a real failure → [`Error::store`], NEVER treated as absence. This is
/// the fail-closed replacement for the boolean `.exists()` checks that
/// silently read a permission/I/O error on the marker directory as "no
/// floor" / "no pending cleanup" / "no backups".
///
/// The store's WRITE-path open-or-create checks (`append_attempt`,
/// `append_snapshot`, `write_atomic_cas`) are deliberately NOT converted:
/// there a swallowed `exists()` error lands in the subsequent open/create
/// call, which fails and propagates anyway — no silent absence is possible.
///
/// Under `#[cfg(test)]` the check routes through the injectable
/// [`MarkerIoOps`] seam when a test installed one, so the tri-state
/// property can force each outcome on the marker path.
pub(crate) fn path_state(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) => absent_or_store(e, path),
    }
}

/// Classify a metadata error tri-state: ONLY a genuine
/// [`std::io::ErrorKind::NotFound`] is absence (`Ok(false)`); any other io
/// error is [`Error::store`] (a permission/read failure is never "no
/// marker").
fn absent_or_store(e: std::io::Error, path: &Path) -> Result<bool> {
    if e.kind() == std::io::ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(Error::store(format!("stat {}: {e}", path.display())))
    }
}

pub(crate) fn set_private(path: &Path) -> Result<()> {
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)
        .map_err(|e| Error::store(format!("chmod {}: {e}", path.display())))
}
/// Unique temp-file name for an atomic replace of `path`: same directory,
/// hidden dot-prefixed name carrying the process id and a process-scoped
/// counter, so concurrent atomic writes on one store stay collision-free.
pub(crate) fn temp_name_for(path: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    path.with_file_name(format!(
        ".{}.tmp.{}.{}",
        path.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default(),
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed),
    ))
}
/// The explicit outcome of an atomic replace: the two commit points
/// (the rename — new content VISIBLE — and the parent-directory fsync —
/// new content DURABLE) are reported distinctly, so a caller can always
/// tell "the rename never happened" from "the rename happened but
/// durability is unconfirmed" (see `write_atomic_replace`).
#[derive(Debug)]
pub enum ReplaceOutcome {
    /// BOTH commit points confirmed: the new content is visible under its
    /// final name AND the parent-directory fsync succeeded — the replace
    /// is durable across power loss.
    ReplacedDurable,
    /// ONLY the rename (commit point 1) is confirmed: the new content IS
    /// visible under its final name, but the parent-directory open/fsync
    /// (commit point 2) failed AFTER the rename — durability is
    /// UNCONFIRMED and the failure is carried. NEVER a bare `Err`: `Err`
    /// means the rename never happened (the old content is still visible).
    ReplacedDurabilityUnknown { error: Error },
}

/// The [`write_atomic_replace`] stage a test-injected fault fires at. The
/// hook is [`write_atomic_replace`]'s own `fault` parameter, so a
/// per-fixture registry can fault each atomic-replacement stage exactly as
/// the append path's [`crate::testutil::test_faults::FaultKind::AppendWrite`]
/// family does; production passes a no-op hook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplaceStage {
    /// The temp-file CREATE/WRITE stage (before any I/O on the temp): the
    /// visible target is wholly OLD; a fault here is an `Err`.
    Write,
    /// The temp-file FSYNC stage (after the write, before the chmod): an
    /// invisible dot-prefixed temp exists; the visible target is wholly
    /// OLD; a fault here is an `Err`.
    Sync,
    /// The RENAME stage (after the chmod, before the atomic rename): the
    /// visible target is wholly OLD; a fault here is an `Err`.
    Rename,
    /// The PARENT-DIRECTORY open/fsync stage, AFTER the rename: the new
    /// content IS visible under its final name but its durability is
    /// unconfirmed — reported as
    /// [`ReplaceOutcome::ReplacedDurabilityUnknown`], never an `Err`.
    DirSync,
}

/// Durably replace a mutable marker file (the history floor): write a
/// UNIQUE temp file in the same directory, chmod it private, fsync it,
/// rename over the target (atomic on POSIX — a reader never sees a torn
/// record), then fsync the parent directory. The durability of this write
/// is the checkpoint's ordering guarantee — the floor marker must be
/// durable BEFORE the compaction deletes anything, so an interrupted
/// compaction can never expose history below the floor.
///
/// # The TWO COMMIT POINTS — the tri-state contract
///
/// * `Err` — the rename NEVER succeeded: a failure at any PRE-RENAME
///   stage (temp create/write, temp fsync, chmod, rename) propagates as
///   `Err` and the OLD content remains visible.
/// * [`ReplaceOutcome::ReplacedDurable`] — the new content is visible AND
///   the parent-directory fsync was confirmed: the replace is durable
///   across power loss.
/// * [`ReplaceOutcome::ReplacedDurabilityUnknown`] — the new content IS
///   visible under its final name (the rename — commit point 1 —
///   happened), but durability is UNCONFIRMED: the parent-directory
///   `File::open` or `sync_all` (commit point 2) failed after the rename
///   and the failure is carried. The fail-closed behaviour is preserved —
///   the unconfirmed durability is never reported as success — but it
///   surfaces as the EXPLICIT unknown-durability outcome, never an
///   ambiguous `Err`.
///
/// Ordering: the temp file is chmodded 0o600 BEFORE the rename, so the
/// marker never becomes visible under its final name with default
/// permissions.
///
/// # The per-stage fault hook
///
/// `fault` is invoked at each stage's entry and may inject a failure at
/// EVERY atomic-replacement stage ([`ReplaceStage`]): the hook returns the
/// faulted error for the stage it wants to fail (`None` passes the stage
/// through). The pre-rename stages (write / sync / rename) propagate a hook
/// error as `Err` — the old content is still visible; the post-rename
/// parent-directory stage converts a hook error (or a real open/fsync
/// failure) into [`ReplaceOutcome::ReplacedDurabilityUnknown`] with the
/// error carried. The hook is the caller's closure over ITS OWN fixture
/// registry, so fault isolation stays per-fixture (never process-global
/// state); a no-op hook (`|_| None`) is the plain production path — the
/// SAME function is exercised in test builds with the registry-backed hook.
pub(crate) fn write_atomic_replace(
    path: &Path,
    bytes: &[u8],
    fault: &mut dyn FnMut(ReplaceStage) -> Option<Error>,
) -> Result<ReplaceOutcome> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::store(format!("mkdir {}: {e}", parent.display())))?;
    }
    let tmp = temp_name_for(path);
    // Stage 1: the temp create/write. A failure (or an injected
    // [`ReplaceStage::Write`] fault) is a PRE-RENAME `Err`: the visible
    // target is wholly OLD.
    if let Some(e) = fault(ReplaceStage::Write) {
        return Err(e);
    }
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| Error::store(format!("create {}: {e}", tmp.display())))?;
        f.write_all(bytes)
            .map_err(|e| Error::store(format!("write {}: {e}", tmp.display())))?;
    }
    // Stage 2: the temp fsync. A failure (or an injected
    // [`ReplaceStage::Sync`] fault) is a PRE-RENAME `Err`: only an
    // invisible dot-prefixed temp exists.
    if let Some(e) = fault(ReplaceStage::Sync) {
        return Err(e);
    }
    {
        let f = std::fs::File::open(&tmp)
            .map_err(|e| Error::store(format!("open {}: {e}", tmp.display())))?;
        f.sync_all()
            .map_err(|e| Error::store(format!("fsync {}: {e}", tmp.display())))?;
    }
    // Private BEFORE visible: the temp carries 0o600 before the rename, so
    // no reader ever observes the marker with default permissions.
    set_private(&tmp)?;
    // Stage 3: the atomic rename — COMMIT POINT 1. A failure (or an
    // injected [`ReplaceStage::Rename`] fault) is a PRE-RENAME `Err`: the
    // visible target is wholly OLD.
    if let Some(e) = fault(ReplaceStage::Rename) {
        return Err(e);
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| Error::store(format!("rename {}: {e}", path.display())))?;
    // Stage 4: the parent-directory open + fsync — COMMIT POINT 2, AFTER
    // the rename. FAIL-CLOSED but EXPLICIT: a failed open, a failed sync,
    // or an injected [`ReplaceStage::DirSync`] fault means the NEW content
    // is visible but its durability is unconfirmed — returned as
    // [`ReplaceOutcome::ReplacedDurabilityUnknown`] carrying the original
    // error, NEVER a bare `Err` (an `Err` would falsely report that the
    // rename never happened, while the ledger commit visibly stands).
    if let Some(e) = fault(ReplaceStage::DirSync) {
        return Ok(ReplaceOutcome::ReplacedDurabilityUnknown { error: e });
    }
    if let Some(parent) = path.parent() {
        let dir = match std::fs::File::open(parent) {
            Ok(dir) => dir,
            Err(e) => {
                return Ok(ReplaceOutcome::ReplacedDurabilityUnknown {
                    error: Error::store(format!("open dir {}: {e}", parent.display())),
                });
            }
        };
        if let Err(e) = dir.sync_all() {
            return Ok(ReplaceOutcome::ReplacedDurabilityUnknown {
                error: Error::store(format!("fsync dir {}: {e}", parent.display())),
            });
        }
    }
    Ok(ReplaceOutcome::ReplacedDurable)
}
/// Durable directory sync: fsync the parent directory of `path` so a
/// rename/removal inside it survives power loss. Errors PROPAGATE (a
/// failed dir sync means the change may not be durable).
pub(crate) fn sync_parent_dir(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::store(format!("sync parent of {}: no parent", path.display())))?;
    let dir = std::fs::File::open(parent)
        .map_err(|e| Error::store(format!("open parent dir {}: {e}", parent.display())))?;
    dir.sync_all()
        .map_err(|e| Error::store(format!("fsync parent dir {}: {e}", parent.display())))
}

pub(crate) fn ensure_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .map_err(|e| Error::store(format!("mkdir {}: {e}", path.display())))?;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(path, perms)
        .map_err(|e| Error::store(format!("chmod {}: {e}", path.display())))
}

/// DURABLE private directory creation: create `path` (and every missing
/// ancestor) with the same private chmod as [`ensure_private_dir`], then make
/// EVERY newly created directory entry durable BEFORE the call returns — fsync
/// the parent directory of each component this call created (deepest first), and
/// then the parent of the new path's own parent (the entry that names the
/// directory HOLDING the new path). The store case this exists for is the FIRST
/// ledger append on a NEW target: the walk creates `targets/<target>/` while
/// `targets/` itself was already created (UNSYNCED) by the store open's
/// [`ensure_private_dir`], so the append must fsync BOTH the `targets/<target>/`
/// entry (inside `targets/`) AND the `targets/` entry (inside the base) before
/// it reports success — otherwise a power loss could lose the directories while
/// the reported ledger survives.
///
/// The helper knows what it created by creating COMPONENT-BY-COMPONENT (walk
/// up from `path` to the deepest existing ancestor, create the missing chain
/// top-down, chmod each) instead of `create_dir_all`, which cannot report what
/// it created. Syncing an already-existing ancestor is always safe (the fsync
/// only forces the entries created below it), so the extra parent-of-parent
/// sync is the harmless, conservative "sync the ancestor chain" choice.
///
/// Returns `true` when this call created at least one directory (and therefore
/// ran the syncs), `false` when everything already existed (the fast path of
/// every later append: nothing created, nothing to sync).
pub(crate) fn ensure_private_dir_durable(path: &Path) -> Result<bool> {
    // Walk from `path` up to the deepest ancestor that already exists,
    // collecting the MISSING chain (pushed deepest-first).
    let mut missing: Vec<PathBuf> = Vec::new();
    let mut cur: &Path = path;
    loop {
        match std::fs::symlink_metadata(cur) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                missing.push(cur.to_path_buf());
                match cur.parent() {
                    Some(parent) if !parent.as_os_str().is_empty() => cur = parent,
                    _ => break,
                }
            }
            Err(e) => return Err(Error::store(format!("stat {}: {e}", cur.display()))),
        }
    }
    if missing.is_empty() {
        return Ok(false);
    }
    // Create the chain TOP-DOWN (parents before their children) with the
    // private 0o700 chmod, exactly as `create_dir_all` + `ensure_private_dir`
    // would — one component at a time so the caller knows what was created. A
    // racing creation of an ancestor is tolerated (it exists; the chmod is
    // idempotent). NOTE: the chmod must be 0o700 (never [`set_private`]'s
    // 0o600) — a directory without its execute bit denies every subsequent
    // stat of its children.
    for component in missing.iter().rev() {
        match std::fs::create_dir(component) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(Error::store(format!("mkdir {}: {e}", component.display())));
            }
        }
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(component, perms)
            .map_err(|e| Error::store(format!("chmod {}: {e}", component.display())))?;
    }
    // Durable commit of every NEW directory entry: fsync the parent of each
    // created component (deepest first — the new dir's own entry), and then
    // the parent of the new path's PARENT — the `targets/` entry inside the
    // base — which an earlier UNSYNCED creation (the store open) may have
    // made: the first append is the first chance to make it durable.
    for component in missing.iter().rev() {
        sync_parent_dir(component)?;
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        sync_parent_dir(parent)?;
    }
    Ok(true)
}

/// TEST-ONLY path-based recursive tree copy: the store's OWN object staging
/// now uses the descriptor-relative [`copy_dir_recursive_fd`]; this path
/// variant survives for the retention checkpoint's test-only store clone
/// (which copies a whole store base to a fresh path and holds no root
/// descriptor).
#[cfg(test)]
pub(crate) fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)
        .map_err(|e| Error::store(format!("mkdir {}: {e}", dst.display())))?;
    for entry in std::fs::read_dir(src)
        .map_err(|e| Error::store(format!("read_dir {}: {e}", src.display())))?
    {
        let entry = entry.map_err(|e| Error::store(format!("entry: {e}")))?;
        let path = entry.path();
        let ft = entry
            .file_type()
            .map_err(|e| Error::store(format!("file_type: {e}")))?;
        let target = dst.join(entry.file_name());
        if ft.is_dir() {
            copy_dir_recursive(&path, &target)?;
        } else if ft.is_symlink() {
            let link = std::fs::read_link(&path)
                .map_err(|e| Error::store(format!("readlink {}: {e}", path.display())))?;
            let _ = std::fs::remove_file(&target);
            std::os::unix::fs::symlink(&link, &target)
                .map_err(|e| Error::store(format!("symlink {}: {e}", target.display())))?;
        } else {
            std::fs::copy(&path, &target)
                .map_err(|e| Error::store(format!("copy {}: {e}", path.display())))?;
        }
    }
    Ok(())
}

// =====================================================================
// DESCRIPTOR-RELATIVE I/O (the owned-root confinement)
// ---------------------------------------------------------------------
// The store's mutations resolve paths relative to the owned root's open
// directory descriptor, COMPONENT-WISE with `openat(O_NOFOLLOW)`: every
// intermediate component is opened as a directory with `O_DIRECTORY |
// O_NOFOLLOW` (a symlink at ANY component → ELOOP → refused), and the
// final component is opened with `O_NOFOLLOW`. A symlink injected into a
// path component can never redirect a mutation outside the owned root —
// the descriptor pins the root, and no component is ever followed. The
// path-based free functions above stay for the retention machinery (which
// operates on paths under a store base it does not hold a descriptor
// for); the store's OWN mutations route through the `_fd` variants below.
// =====================================================================

/// Open `rel` relative to `dir_fd` COMPONENT-WISE with `O_NOFOLLOW`: every
/// intermediate component is opened as a directory (`O_RDONLY | O_DIRECTORY
/// | O_NOFOLLOW | O_CLOEXEC`), and the final component is opened with
/// `flags` plus `O_NOFOLLOW | O_CLOEXEC`. A symlink injected at ANY
/// component is refused (ELOOP) — a mutation can never be redirected
/// outside the root the descriptor pins. `mode` is used only when `flags`
/// includes `O_CREAT`. The raw `_io` variant returns the underlying io
/// error (so a caller can distinguish a genuine NotFound from a symlink
/// refusal); [`openat_no_follow`] wraps it with the path context.
pub(crate) fn openat_no_follow_io(
    dir_fd: &OwnedFd,
    rel: &Path,
    flags: i32,
    mode: u32,
) -> std::io::Result<OwnedFd> {
    let mut cur: OwnedFd = dir_fd.try_clone()?;
    let comps: Vec<&[u8]> = rel.components().map(|c| c.as_os_str().as_bytes()).collect();
    for (i, comp) in comps.iter().enumerate() {
        let is_last = i == comps.len() - 1;
        let f = if is_last {
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
        };
        let c = CString::new(*comp).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path component with NUL")
        })?;
        let fd = unsafe { libc::openat(cur.as_raw_fd(), c.as_ptr(), f, mode) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        cur = unsafe { OwnedFd::from_raw_fd(fd) };
    }
    Ok(cur)
}

/// [`openat_no_follow_io`] with the path context folded into the store
/// error.
pub(crate) fn openat_no_follow(
    dir_fd: &OwnedFd,
    rel: &Path,
    flags: i32,
    mode: u32,
) -> Result<OwnedFd> {
    openat_no_follow_io(dir_fd, rel, flags, mode)
        .map_err(|e| Error::store(format!("openat {}: {e}", rel.display())))
}

/// The unique temp FILE NAME for an atomic replace of a file named
/// `file_name`: hidden dot-prefixed, carrying the process id and a
/// process-scoped counter (the same naming as [`temp_name_for`], but for
/// the descriptor-relative writers that need just the name).
pub(crate) fn temp_file_name(file_name: &OsStr) -> std::ffi::OsString {
    use std::sync::atomic::{AtomicU64, Ordering};
    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    std::ffi::OsString::from(format!(
        ".{}.tmp.{}.{}",
        file_name.to_string_lossy(),
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed),
    ))
}

/// Open the parent directory of `rel` relative to `root` (component-wise
/// with O_NOFOLLOW), returning the parent fd and the final file name.
fn parent_fd_of<'a>(root: &OwnedFd, rel: &'a Path) -> Result<(OwnedFd, &'a OsStr)> {
    let parent_rel = rel.parent().unwrap_or(Path::new(""));
    let parent_fd = if parent_rel.as_os_str().is_empty() {
        root.try_clone()
            .map_err(|e| Error::store(format!("dup root dir: {e}")))?
    } else {
        openat_no_follow(root, parent_rel, libc::O_RDONLY | libc::O_DIRECTORY, 0)?
    };
    let file_name = rel
        .file_name()
        .ok_or_else(|| Error::store(format!("{} has no file name", rel.display())))?;
    Ok((parent_fd, file_name))
}

/// fsync a directory fd (the descriptor-relative parent-dir sync).
pub(crate) fn fsync_dir_fd(fd: &OwnedFd) -> Result<()> {
    let f = std::fs::File::from(
        fd.try_clone()
            .map_err(|e| Error::store(format!("dup dir: {e}")))?,
    );
    f.sync_all()
        .map_err(|e| Error::store(format!("fsync dir: {e}")))
}

/// renameat between two names in (possibly different) directory fds.
pub(crate) fn renameat_fd(
    dir_fd: &OwnedFd,
    from: &OsStr,
    to_dir: &OwnedFd,
    to: &OsStr,
) -> Result<()> {
    let from_c =
        CString::new(from.as_bytes()).map_err(|_| Error::store("rename source with NUL"))?;
    let to_c = CString::new(to.as_bytes()).map_err(|_| Error::store("rename target with NUL"))?;
    let r = unsafe {
        libc::renameat(
            dir_fd.as_raw_fd(),
            from_c.as_ptr(),
            to_dir.as_raw_fd(),
            to_c.as_ptr(),
        )
    };
    if r < 0 {
        return Err(Error::store(format!(
            "renameat: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// linkat (no AT_SYMLINK_FOLLOW — a hard link to the entry itself, never
/// to a symlink's target). Returns the raw io error so a caller can
/// distinguish the EEXIST race from a real failure.
fn linkat_fd(dir_fd: &OwnedFd, from: &OsStr, to_dir: &OwnedFd, to: &OsStr) -> std::io::Result<()> {
    let from_c = CString::new(from.as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "link source with NUL")
    })?;
    let to_c = CString::new(to.as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "link target with NUL")
    })?;
    let r = unsafe {
        libc::linkat(
            dir_fd.as_raw_fd(),
            from_c.as_ptr(),
            to_dir.as_raw_fd(),
            to_c.as_ptr(),
            0,
        )
    };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// unlinkat (no AT_REMOVEDIR — a file or symlink; the symlink itself is
/// removed, never its target).
fn unlinkat_fd(dir_fd: &OwnedFd, name: &OsStr) -> Result<()> {
    let c = CString::new(name.as_bytes()).map_err(|_| Error::store("unlink name with NUL"))?;
    let r = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), c.as_ptr(), 0) };
    if r < 0 {
        return Err(Error::store(format!(
            "unlinkat: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Open-or-create a directory component relative to `cur` (O_DIRECTORY |
/// O_NOFOLLOW; created with 0o700 when missing, tolerating a racing
/// creation). A symlink at the component is refused (ELOOP); a
/// non-directory is refused (ENOTDIR).
fn open_or_create_dir(cur: &OwnedFd, comp: &[u8]) -> Result<OwnedFd> {
    let c = CString::new(comp).map_err(|_| Error::store("path component with NUL"))?;
    let fd = unsafe {
        libc::openat(
            cur.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
    };
    if fd >= 0 {
        return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    let e = std::io::Error::last_os_error();
    if e.kind() != std::io::ErrorKind::NotFound {
        return Err(Error::store(format!("openat: {e}")));
    }
    let r = unsafe { libc::mkdirat(cur.as_raw_fd(), c.as_ptr(), 0o700) };
    if r < 0 {
        let e2 = std::io::Error::last_os_error();
        if e2.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(Error::store(format!("mkdirat: {e2}")));
        }
    }
    let fd2 = unsafe {
        libc::openat(
            cur.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
    };
    if fd2 < 0 {
        return Err(Error::store(format!(
            "openat: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd2) })
}

/// Read a whole file through an already-open descriptor.
fn read_fd_to_end(fd: &OwnedFd) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::from(
        fd.try_clone()
            .map_err(|e| Error::store(format!("dup fd: {e}")))?,
    );
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .map_err(|e| Error::store(format!("read: {e}")))?;
    Ok(buf)
}

/// Iterate the entries of the directory `dir_fd` (via `fdopendir`),
/// calling `f` with each entry's name (excluding `.` and `..`). The fd is
/// NOT consumed (a clone is passed to fdopendir).
fn for_each_dir_entry(dir_fd: &OwnedFd, mut f: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
    // `fdopendir` TAKES OWNERSHIP of the fd: transfer the clone's raw fd
    // (never drop the OwnedFd — that would double-close the fd the
    // directory stream owns).
    let clone = dir_fd
        .try_clone()
        .map_err(|e| Error::store(format!("dup dir: {e}")))?;
    let dir = unsafe { libc::fdopendir(clone.into_raw_fd()) };
    if dir.is_null() {
        return Err(Error::store(format!(
            "fdopendir: {}",
            std::io::Error::last_os_error()
        )));
    }
    loop {
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let name = name.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        f(name)?;
    }
    unsafe { libc::closedir(dir) };
    Ok(())
}

/// The descriptor-relative atomic replace: the same four-stage protocol as
/// [`write_atomic_replace`], but every path resolves COMPONENT-WISE
/// relative to `root` with `openat(O_NOFOLLOW)` — a symlink injected into
/// any path component is refused (ELOOP), never followed. The parent
/// directory must already exist (the store creates it via
/// [`ensure_private_dir_fd`] before the write).
pub(crate) fn write_atomic_replace_fd(
    root: &OwnedFd,
    rel: &Path,
    bytes: &[u8],
    fault: &mut dyn FnMut(ReplaceStage) -> Option<Error>,
) -> Result<ReplaceOutcome> {
    // The parent directory is created if missing — the same
    // `create_dir_all(parent)` the path-based protocol runs first —
    // component-wise with O_NOFOLLOW (a symlink injected into any parent
    // component is refused).
    let parent_rel = rel.parent().unwrap_or(Path::new(""));
    if !parent_rel.as_os_str().is_empty() {
        ensure_private_dir_fd(root, parent_rel)?;
    }
    let (parent_fd, file_name) = parent_fd_of(root, rel)?;
    let tmp_name = temp_file_name(file_name);
    // Stage 1: the temp create/write. A failure (or an injected
    // [`ReplaceStage::Write`] fault) is a PRE-RENAME `Err`: the visible
    // target is wholly OLD.
    if let Some(e) = fault(ReplaceStage::Write) {
        return Err(e);
    }
    {
        let tmp_fd = openat_no_follow(
            &parent_fd,
            Path::new(&tmp_name),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        let mut f = std::fs::File::from(tmp_fd);
        f.write_all(bytes)
            .map_err(|e| Error::store(format!("write {}: {e}", rel.display())))?;
    }
    // Stage 2: the temp fsync. A failure (or an injected
    // [`ReplaceStage::Sync`] fault) is a PRE-RENAME `Err`: only an
    // invisible dot-prefixed temp exists.
    if let Some(e) = fault(ReplaceStage::Sync) {
        return Err(e);
    }
    {
        let f = std::fs::File::from(openat_no_follow(
            &parent_fd,
            Path::new(&tmp_name),
            libc::O_RDONLY,
            0,
        )?);
        f.sync_all()
            .map_err(|e| Error::store(format!("fsync {}: {e}", rel.display())))?;
    }
    // Private BEFORE visible: the temp carries 0o600 before the rename, so
    // no reader ever observes the marker with default permissions.
    {
        let f = std::fs::File::from(openat_no_follow(
            &parent_fd,
            Path::new(&tmp_name),
            libc::O_RDONLY,
            0,
        )?);
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::store(format!("chmod {}: {e}", rel.display())))?;
    }
    // Stage 3: the atomic rename — COMMIT POINT 1. A failure (or an
    // injected [`ReplaceStage::Rename`] fault) is a PRE-RENAME `Err`: the
    // visible target is wholly OLD.
    if let Some(e) = fault(ReplaceStage::Rename) {
        return Err(e);
    }
    renameat_fd(&parent_fd, &tmp_name, &parent_fd, file_name)?;
    // Stage 4: the parent-directory open + fsync — COMMIT POINT 2, AFTER
    // the rename. FAIL-CLOSED but EXPLICIT (see [`write_atomic_replace`]).
    if let Some(e) = fault(ReplaceStage::DirSync) {
        return Ok(ReplaceOutcome::ReplacedDurabilityUnknown { error: e });
    }
    if let Err(e) = fsync_dir_fd(&parent_fd) {
        return Ok(ReplaceOutcome::ReplacedDurabilityUnknown { error: e });
    }
    Ok(ReplaceOutcome::ReplacedDurable)
}

/// The descriptor-relative create-or-compare CAS: the same protocol as
/// [`write_atomic_cas`], but every path resolves COMPONENT-WISE relative to
/// `root` with `openat(O_NOFOLLOW)`. A symlink injected at the final
/// component is REFUSED (ELOOP) — never followed, never compared against
/// its target.
pub(crate) fn write_atomic_cas_fd(root: &OwnedFd, rel: &Path, bytes: &[u8]) -> Result<()> {
    let (parent_fd, file_name) = parent_fd_of(root, rel)?;
    // If the file exists, its content must be byte-identical (an identical
    // rewrite is an idempotent success; a symlink at the final component is
    // refused by the O_NOFOLLOW open — never followed).
    match openat_no_follow_io(&parent_fd, Path::new(file_name), libc::O_RDONLY, 0) {
        Ok(f) => {
            let existing = read_fd_to_end(&f)?;
            if existing == bytes {
                return Ok(());
            }
            return Err(Error::store(format!(
                "refusing to replace existing {} with different content",
                rel.display()
            )));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(Error::store(format!("open {}: {e}", rel.display())));
        }
    }
    // The file is absent: write a unique temp, install WITHOUT replacement
    // (linkat fails on EEXIST, so a racing loser can never clobber a winner
    // and no reader ever sees a torn record), unlink the temp name, then
    // fsync the parent directory.
    let tmp_name = temp_file_name(file_name);
    {
        let tmp_fd = openat_no_follow(
            &parent_fd,
            Path::new(&tmp_name),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        let mut f = std::fs::File::from(tmp_fd);
        f.write_all(bytes)
            .map_err(|e| Error::store(format!("write {}: {e}", rel.display())))?;
        f.sync_all()
            .map_err(|e| Error::store(format!("fsync {}: {e}", rel.display())))?;
    }
    let installed = match linkat_fd(&parent_fd, &tmp_name, &parent_fd, file_name) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(e) => {
            let _ = unlinkat_fd(&parent_fd, &tmp_name);
            return Err(Error::store(format!("install {}: {e}", rel.display())));
        }
    };
    let _ = unlinkat_fd(&parent_fd, &tmp_name);
    if !installed {
        // Lost the race: the winner's content must match ours or refuse.
        let f = openat_no_follow(&parent_fd, Path::new(file_name), libc::O_RDONLY, 0)?;
        let existing = read_fd_to_end(&f)?;
        if existing != bytes {
            return Err(Error::store(format!(
                "refusing to replace existing {} with different content",
                rel.display()
            )));
        }
        return Ok(());
    }
    // Private BEFORE visible: chmod the installed file, then fsync the
    // parent directory (THE DURABILITY COMMIT POINT — fail closed, see
    // [`write_atomic_cas`]).
    {
        let f = std::fs::File::from(openat_no_follow(
            &parent_fd,
            Path::new(file_name),
            libc::O_RDONLY,
            0,
        )?);
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::store(format!("chmod {}: {e}", rel.display())))?;
    }
    fsync_dir_fd(&parent_fd)?;
    Ok(())
}

/// The descriptor-relative private-directory creation: create `rel` (and
/// every missing ancestor) component-wise relative to `root` with
/// `mkdirat`/`openat(O_NOFOLLOW)`, chmodding the FINAL directory to 0o700
/// (the same contract as [`ensure_private_dir`]). A symlink at any
/// component is refused (ELOOP) — never followed.
pub(crate) fn ensure_private_dir_fd(root: &OwnedFd, rel: &Path) -> Result<()> {
    let mut cur: OwnedFd = root
        .try_clone()
        .map_err(|e| Error::store(format!("dup root dir: {e}")))?;
    let comps: Vec<&[u8]> = rel.components().map(|c| c.as_os_str().as_bytes()).collect();
    for (i, comp) in comps.iter().enumerate() {
        let is_last = i == comps.len() - 1;
        let dir = open_or_create_dir(&cur, comp)?;
        if is_last {
            let f = std::fs::File::from(
                dir.try_clone()
                    .map_err(|e| Error::store(format!("dup dir: {e}")))?,
            );
            f.set_permissions(std::fs::Permissions::from_mode(0o700))
                .map_err(|e| Error::store(format!("chmod {}: {e}", rel.display())))?;
        }
        cur = dir;
    }
    Ok(())
}

/// The descriptor-relative DURABLE private-directory creation: the same
/// component-by-component creation + per-component 0o700 chmod as
/// [`ensure_private_dir_durable`], then the same durable commit — fsync the
/// parent of each created component (deepest first), then the parent of the
/// new path's own parent — all through directory fds. Returns `true` when
/// this call created at least one directory.
pub(crate) fn ensure_private_dir_durable_fd(root: &OwnedFd, rel: &Path) -> Result<bool> {
    let comps: Vec<&[u8]> = rel.components().map(|c| c.as_os_str().as_bytes()).collect();
    let mut dirs: Vec<OwnedFd> = Vec::with_capacity(comps.len());
    let mut cur: OwnedFd = root
        .try_clone()
        .map_err(|e| Error::store(format!("dup root dir: {e}")))?;
    let mut created: Vec<usize> = Vec::new();
    for (i, comp) in comps.iter().enumerate() {
        let c = CString::new(*comp).map_err(|_| Error::store("path component with NUL"))?;
        let fd = unsafe {
            libc::openat(
                cur.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
            )
        };
        if fd >= 0 {
            cur = unsafe { OwnedFd::from_raw_fd(fd) };
        } else {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(Error::store(format!("openat {}: {e}", rel.display())));
            }
            let r = unsafe { libc::mkdirat(cur.as_raw_fd(), c.as_ptr(), 0o700) };
            if r < 0 {
                let e2 = std::io::Error::last_os_error();
                if e2.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(Error::store(format!("mkdirat {}: {e2}", rel.display())));
                }
            }
            let fd2 = unsafe {
                libc::openat(
                    cur.as_raw_fd(),
                    c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0,
                )
            };
            if fd2 < 0 {
                return Err(Error::store(format!(
                    "openat {}: {}",
                    rel.display(),
                    std::io::Error::last_os_error()
                )));
            }
            let dir = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd2) });
            dir.set_permissions(std::fs::Permissions::from_mode(0o700))
                .map_err(|e| Error::store(format!("chmod {}: {e}", rel.display())))?;
            cur = dir.into();
            created.push(i);
        }
        dirs.push(
            cur.try_clone()
                .map_err(|e| Error::store(format!("dup dir: {e}")))?,
        );
    }
    if created.is_empty() {
        return Ok(false);
    }
    // Durable commit of every NEW directory entry: fsync the parent of each
    // created component (deepest first), then the parent of the new path's
    // own parent (the entry that names the directory HOLDING the new path).
    for &i in created.iter().rev() {
        let parent = if i == 0 { root } else { &dirs[i - 1] };
        fsync_dir_fd(parent)?;
    }
    if comps.len() >= 2 {
        let parent_of_parent = if comps.len() >= 3 {
            &dirs[comps.len() - 3]
        } else {
            root
        };
        fsync_dir_fd(parent_of_parent)?;
    }
    Ok(true)
}

/// The descriptor-relative parent-directory fsync: fsync the directory
/// holding `rel` (the durability commit of a rename/removal inside it).
pub(crate) fn sync_parent_dir_fd(root: &OwnedFd, rel: &Path) -> Result<()> {
    let parent_rel = rel.parent().unwrap_or(Path::new(""));
    let parent_fd = if parent_rel.as_os_str().is_empty() {
        root.try_clone()
            .map_err(|e| Error::store(format!("dup root dir: {e}")))?
    } else {
        openat_no_follow(root, parent_rel, libc::O_RDONLY | libc::O_DIRECTORY, 0)?
    };
    fsync_dir_fd(&parent_fd)
}

/// The descriptor-relative private chmod (0o600) of a file under the root.
pub(crate) fn set_private_fd(root: &OwnedFd, rel: &Path) -> Result<()> {
    let (parent_fd, name) = parent_fd_of(root, rel)?;
    let f = std::fs::File::from(openat_no_follow(
        &parent_fd,
        Path::new(name),
        libc::O_RDONLY,
        0,
    )?);
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::store(format!("chmod {}: {e}", rel.display())))
}

/// The descriptor-relative remove of a single file (or symlink — the
/// symlink itself is removed, never its target).
pub(crate) fn remove_file_fd(root: &OwnedFd, rel: &Path) -> Result<()> {
    let (parent_fd, name) = parent_fd_of(root, rel)?;
    unlinkat_fd(&parent_fd, name)
}

/// The descriptor-relative rename of a path under the root to another path
/// under the root (both parents resolved component-wise with O_NOFOLLOW).
pub(crate) fn renameat_paths(root: &OwnedFd, from: &Path, to: &Path) -> Result<()> {
    let (from_fd, from_name) = parent_fd_of(root, from)?;
    let (to_fd, to_name) = parent_fd_of(root, to)?;
    renameat_fd(&from_fd, from_name, &to_fd, to_name)
}

/// The descriptor-relative recursive removal of a directory tree: every
/// entry is classified with `fstatat(AT_SYMLINK_NOFOLLOW)` (a symlink is
/// removed as the entry itself, never followed), subdirectories are
/// recursed into, and the tree root is removed last. A symlink injected at
/// any component is refused (ELOOP) — never followed.
pub(crate) fn remove_dir_all_fd(root: &OwnedFd, rel: &Path) -> Result<()> {
    let (parent_fd, name) = parent_fd_of(root, rel)?;
    let dir_fd = openat_no_follow(
        &parent_fd,
        Path::new(name),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    remove_dir_contents_fd(&dir_fd, rel)?;
    let c = CString::new(name.as_bytes()).map_err(|_| Error::store("rmdir name with NUL"))?;
    let r = unsafe { libc::unlinkat(parent_fd.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) };
    if r < 0 {
        return Err(Error::store(format!(
            "rmdir {}: {}",
            rel.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Remove the CONTENTS of the directory `dir_fd` (recursively), leaving the
/// directory itself in place.
fn remove_dir_contents_fd(dir_fd: &OwnedFd, rel: &Path) -> Result<()> {
    for_each_dir_entry(dir_fd, |name| {
        let child_rel = rel.join(Path::new(std::ffi::OsStr::from_bytes(name)));
        let c = CString::new(name).map_err(|_| Error::store("path component with NUL"))?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::fstatat(
                dir_fd.as_raw_fd(),
                c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if r < 0 {
            return Err(Error::store(format!(
                "fstatat {}: {}",
                child_rel.display(),
                std::io::Error::last_os_error()
            )));
        }
        if (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            let sub = openat_no_follow(
                dir_fd,
                Path::new(std::ffi::OsStr::from_bytes(name)),
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            remove_dir_contents_fd(&sub, &child_rel)?;
            let r = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) };
            if r < 0 {
                return Err(Error::store(format!(
                    "rmdir {}: {}",
                    child_rel.display(),
                    std::io::Error::last_os_error()
                )));
            }
        } else {
            // A file or symlink: unlinkat removes the entry itself (a
            // symlink is removed, never its target).
            unlinkat_fd(dir_fd, std::ffi::OsStr::from_bytes(name))?;
        }
        Ok(())
    })
}

/// The descriptor-relative recursive tree copy: the DESTINATION resolves
/// component-wise relative to `root` with O_NOFOLLOW (a symlink injected
/// into a destination component is refused); the SOURCE is read from its
/// absolute path (a read, never a mutation). Directory and file modes are
/// copied EXACTLY from the source (the tree digest includes modes — a
/// mode-shifted copy would fail the staged-object verification).
pub(crate) fn copy_dir_recursive_fd(root: &OwnedFd, src: &Path, dst_rel: &Path) -> Result<()> {
    // Create the destination directory with the SOURCE directory's mode
    // (the digest includes modes; the copy must preserve them exactly).
    let src_mode = std::fs::metadata(src)
        .map_err(|e| Error::store(format!("stat {}: {e}", src.display())))?
        .permissions()
        .mode();
    create_dir_chain_fd(root, dst_rel, src_mode)?;
    let dst_fd = openat_no_follow(root, dst_rel, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    for entry in std::fs::read_dir(src)
        .map_err(|e| Error::store(format!("read_dir {}: {e}", src.display())))?
    {
        let entry = entry.map_err(|e| Error::store(format!("entry: {e}")))?;
        let name = entry.file_name();
        let ft = entry
            .file_type()
            .map_err(|e| Error::store(format!("file_type: {e}")))?;
        let child_rel = dst_rel.join(&name);
        if ft.is_dir() {
            copy_dir_recursive_fd(root, &entry.path(), &child_rel)?;
        } else if ft.is_symlink() {
            let link = std::fs::read_link(entry.path())
                .map_err(|e| Error::store(format!("readlink {}: {e}", entry.path().display())))?;
            // Remove any existing entry at the target (the original removes
            // the target before symlinking), then symlinkat.
            let _ = unlinkat_fd(&dst_fd, &name);
            let name_c =
                CString::new(name.as_bytes()).map_err(|_| Error::store("symlink name with NUL"))?;
            let target_c = CString::new(link.as_os_str().as_bytes())
                .map_err(|_| Error::store("symlink target with NUL"))?;
            let r =
                unsafe { libc::symlinkat(target_c.as_ptr(), dst_fd.as_raw_fd(), name_c.as_ptr()) };
            if r < 0 {
                return Err(Error::store(format!(
                    "symlinkat {}: {}",
                    child_rel.display(),
                    std::io::Error::last_os_error()
                )));
            }
        } else {
            let src_f = std::fs::File::open(entry.path())
                .map_err(|e| Error::store(format!("open {}: {e}", entry.path().display())))?;
            let mode = src_f
                .metadata()
                .map_err(|e| Error::store(format!("fstat {}: {e}", entry.path().display())))?
                .permissions()
                .mode();
            let dst_f = openat_no_follow(
                &dst_fd,
                Path::new(&name),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                mode,
            )?;
            let mut dst_f = std::fs::File::from(dst_f);
            std::io::copy(&mut &src_f, &mut dst_f)
                .map_err(|e| Error::store(format!("copy {}: {e}", entry.path().display())))?;
            dst_f
                .set_permissions(std::fs::Permissions::from_mode(mode))
                .map_err(|e| Error::store(format!("chmod {}: {e}", child_rel.display())))?;
        }
    }
    Ok(())
}

/// Create the directory chain `rel` relative to `root` component-wise with
/// O_NOFOLLOW, chmodding the FINAL directory to `mode` (the intermediate
/// components are outside the tree root, so their modes do not affect the
/// tree digest).
fn create_dir_chain_fd(root: &OwnedFd, rel: &Path, mode: u32) -> Result<()> {
    let mut cur: OwnedFd = root
        .try_clone()
        .map_err(|e| Error::store(format!("dup root dir: {e}")))?;
    let comps: Vec<&[u8]> = rel.components().map(|c| c.as_os_str().as_bytes()).collect();
    for (i, comp) in comps.iter().enumerate() {
        let is_last = i == comps.len() - 1;
        let dir = open_or_create_dir(&cur, comp)?;
        if is_last {
            let f = std::fs::File::from(
                dir.try_clone()
                    .map_err(|e| Error::store(format!("dup dir: {e}")))?,
            );
            f.set_permissions(std::fs::Permissions::from_mode(mode))
                .map_err(|e| Error::store(format!("chmod {}: {e}", rel.display())))?;
        }
        cur = dir;
    }
    Ok(())
}

/// The descriptor-relative recursive tree fsync: the same deepest-first
/// protocol as [`fsync_tree_recursive`], but every entry is classified with
/// `fstatat(AT_SYMLINK_NOFOLLOW)` and opened relative to the root's
/// descriptor — a symlink injected into any component is refused (ELOOP),
/// never followed. Symlinks are SKIPPED (their durability is their
/// directory entry, covered by the parent-dir fsync).
pub(crate) fn fsync_tree_recursive_fd(root: &OwnedFd, rel: &Path) -> Result<()> {
    let dir_fd = openat_no_follow(root, rel, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    for_each_dir_entry(&dir_fd, |name| {
        let child_rel = rel.join(Path::new(std::ffi::OsStr::from_bytes(name)));
        let c = CString::new(name).map_err(|_| Error::store("path component with NUL"))?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::fstatat(
                dir_fd.as_raw_fd(),
                c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if r < 0 {
            return Err(Error::store(format!(
                "fstatat {}: {}",
                child_rel.display(),
                std::io::Error::last_os_error()
            )));
        }
        if (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            fsync_tree_recursive_fd(root, &child_rel)?;
        } else if (st.st_mode & libc::S_IFMT) == libc::S_IFREG {
            let f = std::fs::File::from(openat_no_follow(
                &dir_fd,
                Path::new(std::ffi::OsStr::from_bytes(name)),
                libc::O_RDONLY | libc::O_NOFOLLOW,
                0,
            )?);
            f.sync_all()
                .map_err(|e| Error::store(format!("fsync {}: {e}", child_rel.display())))?;
        }
        // Symlinks and other entries are SKIPPED (their durability is their
        // directory entry, covered by the parent-dir fsync).
        Ok(())
    })?;
    fsync_dir_fd(&dir_fd)
}

/// The descriptor-relative plain file write (create-or-truncate, 0o600):
/// used for the staged object's `tree.json` metadata (the staged tree is
/// fsynced as a whole by [`fsync_tree_recursive_fd`] before the publish).
pub(crate) fn write_file_fd(root: &OwnedFd, rel: &Path, bytes: &[u8]) -> Result<()> {
    let (parent_fd, name) = parent_fd_of(root, rel)?;
    let f = openat_no_follow(
        &parent_fd,
        Path::new(name),
        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
        0o600,
    )?;
    let mut f = std::fs::File::from(f);
    f.write_all(bytes)
        .map_err(|e| Error::store(format!("write {}: {e}", rel.display())))
}
