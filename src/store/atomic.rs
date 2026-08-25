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
    #[cfg(test)]
    if let Some(ops) = MARKER_IO_OPS.with(|s| s.borrow().clone()) {
        return match ops.exists(path) {
            Ok(present) => Ok(present),
            Err(e) => absent_or_store(e, path),
        };
    }
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

/// INJECTABLE FILESYSTEM-IO BOUNDARY for marker discovery (test-only
/// seam): the tri-state existence check ([`path_state`]), the refs-dir
/// backup-sibling enumeration
/// ([`crate::store::history_floor::floor_backup_siblings`]), and the
/// backup read
/// ([`crate::store::history_floor::LocalStore::validated_backup`]) route
/// through this slot when a test installed a seam — so the tri-state
/// property can force each outcome (NotFound vs EACCES vs EIO) at the
/// marker path's metadata, the refs-dir `read_dir`, and the backup read,
/// and assert the fail-closed class. Production never installs a seam: the
/// routed helpers fall through to the REAL filesystem. The seam is
/// PER-THREAD (mirroring the floor-transaction [`FloorFsOps`](crate::store::history_floor::FloorFsOps) seam), so
/// two fixtures in different test threads can never interfere;
/// [`MarkerIoSeamGuard`] scopes one installation to one test case.
#[cfg(test)]
pub(crate) trait MarkerIoOps: Send + Sync {
    /// The marker path's existence stat: `Ok(true)` present, `Ok(false)`
    /// absent, `Err(io)` for a forced/real failure.
    fn exists(&self, path: &Path) -> std::io::Result<bool>;
    /// Enumerate a directory (the refs dir holding the backup siblings).
    fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>>;
    /// Read a backup/marker file's bytes.
    fn read(&self, path: &Path) -> std::io::Result<Vec<u8>>;
}

// The installed seam for the current thread ([`MarkerIoOps`]). `None` in
// production and in tests that did not install one — discovery then
// performs the REAL filesystem calls.
#[cfg(test)]
thread_local! {
    static MARKER_IO_OPS: std::cell::RefCell<Option<std::sync::Arc<dyn MarkerIoOps>>> =
        const { std::cell::RefCell::new(None) };
}

/// Route a directory enumeration for marker/backup discovery through the
/// injectable filesystem boundary: production performs the REAL
/// [`std::fs::read_dir`] (with per-entry errors PROPAGATED — an entry that
/// cannot be read is never silently dropped from the list); a test that
/// installed a seam performs the seam's enumeration instead.
pub(crate) fn routed_read_dir(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    #[cfg(test)]
    if let Some(ops) = MARKER_IO_OPS.with(|s| s.borrow().clone()) {
        return ops.read_dir(path);
    }
    std::fs::read_dir(path)?
        .map(|e| e.map(|e| e.path()))
        .collect()
}

/// Route a marker/backup read through the [`MarkerIoOps`] boundary
/// (production: the REAL [`std::fs::read`]).
pub(crate) fn routed_read_bytes(path: &Path) -> std::io::Result<Vec<u8>> {
    #[cfg(test)]
    if let Some(ops) = MARKER_IO_OPS.with(|s| s.borrow().clone()) {
        return ops.read(path);
    }
    std::fs::read(path)
}

/// Test-only RAII guard scoping a [`MarkerIoOps`] seam to one marker
/// discovery case: installs the seam for the CURRENT thread and restores
/// the previous seam on drop, so a proptest case cannot leak its arming
/// into the next case (or another test on the same thread).
#[cfg(test)]
pub(crate) struct MarkerIoSeamGuard(Option<std::sync::Arc<dyn MarkerIoOps>>);

#[cfg(test)]
impl MarkerIoSeamGuard {
    pub(crate) fn install(ops: std::sync::Arc<dyn MarkerIoOps>) -> Self {
        // `Option::replace` swaps the value in place and returns the
        // previous one (the seam the guard restores on drop).
        let previous = MARKER_IO_OPS.with(|s| s.borrow_mut().replace(ops));
        MarkerIoSeamGuard(previous)
    }
}

#[cfg(test)]
impl Drop for MarkerIoSeamGuard {
    fn drop(&mut self) {
        MARKER_IO_OPS.with(|s| *s.borrow_mut() = self.0.take());
    }
}

/// The I/O outcome a test forces at one marker-discovery site: the ONE
/// `NotFound` outcome may be absence; `Eacc` (EACCES) and `Eio` (EIO) are
/// the filesystem failures that must surface as [`Error::store`] — never a
/// silent None/empty. `Genuine` is a generator-side value meaning "do NOT
/// force — perform the real filesystem operation" (it is never stored in
/// the force map).
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IoOutcome {
    /// The operation reports genuine absence (`ENOENT`).
    NotFound,
    /// The operation fails with a permission error (`EACCES`).
    Eacc,
    /// The operation fails with an I/O error (`EIO`).
    Eio,
    /// Perform the REAL filesystem operation (no forcing).
    Genuine,
}

#[cfg(test)]
fn forced_io_err(o: IoOutcome) -> std::io::Error {
    // Raw errnos keep the injected kinds REAL (`e.kind()` reports NotFound
    // for ENOENT, PermissionDenied for EACCES, Uncategorized for EIO).
    match o {
        IoOutcome::NotFound => std::io::Error::from_raw_os_error(2), // ENOENT
        IoOutcome::Eacc => std::io::Error::from_raw_os_error(13),    // EACCES
        IoOutcome::Eio => std::io::Error::from_raw_os_error(5),      // EIO
        IoOutcome::Genuine => unreachable!("Genuine is never a forced error"),
    }
}

/// Test impl of [`MarkerIoOps`]: performs the REAL filesystem calls for
/// paths without a forced outcome, and returns the forced error otherwise.
/// Per-path and STATELESS — the same forced outcome repeats on every call,
/// so the property can drive the same read through several APIs.
#[cfg(test)]
pub(crate) struct TestMarkerIoOps {
    forced: std::sync::Mutex<std::collections::BTreeMap<PathBuf, IoOutcome>>,
}

#[cfg(test)]
impl TestMarkerIoOps {
    pub(crate) fn new() -> Self {
        TestMarkerIoOps {
            forced: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    /// Replace the per-path force map: every `path` present in `forced`
    /// reports `outcome` on the matching operation; every other path
    /// performs the REAL filesystem call (genuine behavior).
    pub(crate) fn force(&self, forced: std::collections::BTreeMap<PathBuf, IoOutcome>) {
        *self.forced.lock().unwrap() = forced;
    }
}

#[cfg(test)]
impl MarkerIoOps for TestMarkerIoOps {
    fn exists(&self, path: &Path) -> std::io::Result<bool> {
        match self.forced.lock().unwrap().get(path).copied() {
            Some(IoOutcome::Genuine) | None => std::fs::symlink_metadata(path).map(|_| true),
            Some(o) => Err(forced_io_err(o)),
        }
    }

    fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
        match self.forced.lock().unwrap().get(path).copied() {
            Some(IoOutcome::Genuine) | None => std::fs::read_dir(path)?
                .map(|e| e.map(|e| e.path()))
                .collect(),
            Some(o) => Err(forced_io_err(o)),
        }
    }

    fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        match self.forced.lock().unwrap().get(path).copied() {
            Some(IoOutcome::Genuine) | None => std::fs::read(path),
            Some(o) => Err(forced_io_err(o)),
        }
    }
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
