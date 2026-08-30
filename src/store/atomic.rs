//! Durable atomic filesystem I/O for the store.
//!
//! The atomic-replace protocol this module implements is the store's
//! durability machinery: write a UNIQUE temp file in the same directory,
//! chmod it private (0o600) BEFORE it can become visible under its final
//! name, fsync it, rename it into place (atomic on POSIX — a reader never
//! sees a torn record), then fsync the parent directory. The replace has
//! TWO DISTINCT COMMIT POINTS and [`write_atomic_replace`] reports them
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
use std::io::Write;
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
/// durability is unconfirmed" (see [`write_atomic_replace`]).
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
/// seam lives in [`write_atomic_replace_impl`]'s hook so a per-fixture
/// registry can fault each atomic-replacement stage exactly as the append
/// path's [`crate::testutil::test_faults::FaultKind::AppendWrite`] family
/// does; production builds pass a no-op hook.
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
pub(crate) fn write_atomic_replace(path: &Path, bytes: &[u8]) -> Result<ReplaceOutcome> {
    write_atomic_replace_impl(path, bytes, &mut |_stage| None)
}

/// TEST-ONLY seam: the same replacement as [`write_atomic_replace`] with a
/// per-stage fault hook, so a per-fixture registry can inject a failure at
/// EVERY atomic-replacement stage ([`ReplaceStage`]) and assert the
/// stage→outcome mapping. The hook returns the faulted error for the stage
/// it wants to fail (`None` passes the stage through). Not part of the
/// production surface — [`write_atomic_replace`] keeps its exact
/// production signature `(path, &[u8]) -> Result<ReplaceOutcome>`.
///
/// The fault hook is the caller's closure over ITS OWN fixture registry, so
/// fault isolation stays per-fixture (never process-global state).
#[cfg(test)]
pub(crate) fn write_atomic_replace_seam(
    path: &Path,
    bytes: &[u8],
    fault: &mut dyn FnMut(ReplaceStage) -> Option<Error>,
) -> Result<ReplaceOutcome> {
    write_atomic_replace_impl(path, bytes, fault)
}

/// The shared replacement body: the four stages with a fault-injection
/// hook invoked at each stage's entry (production passes a no-op hook; the
/// test seam passes the fixture's registry-backed closure). The pre-rename
/// stages (write / sync / rename) propagate a hook error as `Err` — the
/// old content is still visible; the post-rename parent-directory stage
/// converts a hook error (or a real open/fsync failure) into
/// [`ReplaceOutcome::ReplacedDurabilityUnknown`] with the error carried.
fn write_atomic_replace_impl(
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
