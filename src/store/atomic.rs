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
//! the fail-closed parent-dir fsync ([`sync_parent_dir`]), unique temp
//! naming ([`temp_name_for`]), the atomic marker/JSONL rewrites
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
//! its non-marker callers (observed.json, rotation-debt.json, tree
//! metadata, ...); callers of [`read_json_marker`] must still perform
//! their own schema-version check after a successful parse (also
//! [`Error::integrity`]): an unsupported `schema_version` is a
//! marker-format violation, not an I/O failure.

use crate::error::{Error, Result};
use serde::Serialize;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub(crate) fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes =
        std::fs::read(path).map_err(|e| Error::store(format!("read {}: {e}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::store(format!("deserialize {}: {e}", path.display())))
}
/// Parse-sensitive variant of [`read_json`] for CHECKPOINT MARKERS only.
///
/// The class split this feature enforces: [`Error::store`] is reserved for
/// mechanical FILESYSTEM I/O (open/read/rename/fsync failures), while a
/// PRESENT file whose CONTENT fails to deserialize is semantic CORRUPTION
/// and maps to [`Error::integrity`] — the file exists, it is just not a
/// valid marker. [`read_json`] folds both into [`Error::store`], which is
/// correct for its other callers (observed.json, rotation-debt.json, tree
/// metadata, ...) but would let callers mistake "this marker is corrupt"
/// for "disk read failed".
///
/// Callers must still perform their own schema-version check after a
/// successful parse (also [`Error::integrity`]): an unsupported
/// `schema_version` is a marker-format violation, not an I/O failure.
pub(crate) fn read_json_marker<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    // Filesystem read failure: mechanical I/O → Store (unchanged class).
    let bytes =
        std::fs::read(path).map_err(|e| Error::store(format!("read {}: {e}", path.display())))?;
    // Present-but-malformed content: semantic corruption → Integrity. The
    // file EXISTS (the read above succeeded) but its bytes are not a valid
    // marker — truncation, wrong field types, or missing fields all land
    // here and MUST NOT be reported as a store/IO error.
    serde_json::from_slice(&bytes).map_err(|e| {
        Error::integrity(format!(
            "marker at {} is malformed (the file exists but its content is not a valid marker): {e}",
            path.display()
        ))
    })
}
pub(crate) fn set_private(path: &Path) -> Result<()> {
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)
        .map_err(|e| Error::store(format!("chmod {}: {e}", path.display())))
}
/// DURABLY fsync the parent directory of `path` (open + sync_all, errors
/// PROPAGATED). A rename is not durable until its directory entry is
/// synced, so this is the commit point of every atomic marker replace in
/// [`LocalStore::write_history_floor`](crate::store::local::LocalStore::write_history_floor): B's commit point, the backup's
/// durability, and the restore's durability all sync through here.
pub(crate) fn sync_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        let dir = std::fs::File::open(parent)
            .map_err(|e| Error::store(format!("open dir {}: {e}", parent.display())))?;
        dir.sync_all()
            .map_err(|e| Error::store(format!("fsync dir {}: {e}", parent.display())))?;
    }
    Ok(())
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
/// Atomically rewrite a JSONL file with the serialized lines of `entries`
/// (temp + fsync + rename + dir fsync; see [`write_atomic_replace`]). The
/// checkpoint compaction uses this so a reader never observes a torn log:
/// an interrupted compaction leaves either the old jsonl or the compacted
/// jsonl, never a half-written one.
pub(crate) fn write_jsonl_atomic<T: Serialize>(path: &Path, entries: &[T]) -> Result<()> {
    let mut buf = Vec::new();
    for e in entries {
        let line = serde_json::to_string(e)
            .map_err(|e| Error::store(format!("serialize {}: {e}", path.display())))?;
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
    }
    write_atomic_replace(path, &buf)
}
pub(crate) fn ensure_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .map_err(|e| Error::store(format!("mkdir {}: {e}", path.display())))?;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(path, perms)
        .map_err(|e| Error::store(format!("chmod {}: {e}", path.display())))
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
