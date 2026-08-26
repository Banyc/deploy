//! Durable atomic filesystem I/O for the store.
//!
//! The atomic-replace protocol this module implements is the store's
//! durability machinery: write a UNIQUE temp file in the same directory,
//! chmod it private (0o600) BEFORE it can become visible under its final
//! name, fsync it, rename it into place (atomic on POSIX — a reader never
//! sees a torn record), then fsync the parent directory WITH ERRORS
//! PROPAGATED (fail-closed: a rename is not durable until its directory
//! entry is synced, so swallowing a parent-sync error could let a
//! checkpoint report success for a floor that can disappear). The
//! durability of these writes is the checkpoint's ordering guarantee — the
//! floor marker must be durable BEFORE the compaction deletes anything, so
//! an interrupted compaction can never expose history below the floor; the
//! checkpoint's per-stage sequence (the transactional ADVANCE and its
//! restore) lives in [`crate::store::history_floor`] on top of these
//! primitives.
//!
//! The helpers here are the shared plumbing — `pub(crate)` free functions
//! imported by [`crate::store::local`] and [`crate::store::history_floor`]:
//! the tri-state existence check ([`path_state`]), the fail-closed
//! parent-dir fsync ([`sync_parent_dir`]), unique temp naming
//! ([`temp_name_for`]), the atomic marker/JSONL rewrites
//! ([`write_atomic_replace`], [`write_jsonl_atomic`]), private permissions
//! ([`set_private`], [`ensure_private_dir`]), the tree-object directory
//! copy ([`copy_dir_recursive`]), and the JSON readers.
//!
//! Parse-sensitive marker reads: a PRESENT-but-malformed marker CONTENT is
//! semantic CORRUPTION and maps to [`Error::integrity`] via
//! [`read_json_marker`] (the file exists, it is just not a valid marker),
//! while a mechanical filesystem I/O failure (open/read/rename/fsync)
//! stays [`Error::store`] — the class split a caller can always
//! distinguish "this marker is corrupt" from "disk read failed".
//! [`read_json`] folds both into [`Error::store`], which is correct for
//! its non-marker callers (observed.json, retention-debt.json, tree
//! metadata, ...); callers of [`read_json_marker`] must still perform
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
/// Durably replace a mutable marker file (the history floor): write a
/// UNIQUE temp file in the same directory, chmod it private, fsync it,
/// rename over the target (atomic on POSIX — a reader never sees a torn
/// record), then fsync the parent directory WITH ERRORS PROPAGATED. The
/// durability of this write is the checkpoint's ordering guarantee — the
/// floor marker must be durable BEFORE the compaction deletes anything, so
/// an interrupted compaction can never expose history below the floor.
///
/// Ordering: the temp file is chmodded 0o600 BEFORE the rename, so the
/// marker never becomes visible under its final name with default
/// permissions; and the parent-directory fsync is FAIL-CLOSED — a failed
/// `File::open` OR a failed `sync_all` is an error (the rename may not
/// survive power loss without the directory fsync, so swallowing it would
/// let a checkpoint report success for a floor that can disappear).
pub(crate) fn write_atomic_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::store(format!("mkdir {}: {e}", parent.display())))?;
    }
    let tmp = temp_name_for(path);
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| Error::store(format!("create {}: {e}", tmp.display())))?;
        f.write_all(bytes)
            .map_err(|e| Error::store(format!("write {}: {e}", tmp.display())))?;
        f.sync_all()
            .map_err(|e| Error::store(format!("fsync {}: {e}", tmp.display())))?;
    }
    // Private BEFORE visible: the temp carries 0o600 before the rename, so
    // no reader ever observes the marker with default permissions.
    set_private(&tmp)?;
    std::fs::rename(&tmp, path)
        .map_err(|e| Error::store(format!("rename {}: {e}", path.display())))?;
    // Durable parent sync, FAIL-CLOSED: a failed open or a failed fsync is
    // an error — the rename may not survive power loss without it.
    if let Some(parent) = path.parent() {
        let dir = std::fs::File::open(parent)
            .map_err(|e| Error::store(format!("open dir {}: {e}", parent.display())))?;
        dir.sync_all()
            .map_err(|e| Error::store(format!("fsync dir {}: {e}", parent.display())))?;
    }
    Ok(())
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
