//! Advisory locking for push transactions.
//!
//! `FileLock` is an advisory (flock) lock held by an open file descriptor.
//! While the guard is alive the kernel prevents any other process from
//! acquiring the same lock, and the lock is released automatically if the
//! owning process dies — so a stale lock from a crashed controller can never
//! be double-owned, and two live contenders can never both win the
//! acquisition. Locks are taken in a fixed local-then-target order — the
//! application-store `operation.lock` first, then the target lock — so the
//! whole push pipeline, including [`crate::retention::checkpoint`], runs under the
//! same discipline as [`crate::deploy::push::push`].

use crate::error::{Error, Result};
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// An advisory (flock) lock held by an open file descriptor. While the guard
/// is alive the kernel prevents any other process from acquiring the same lock,
/// and the lock is released automatically if the owning process dies. This
/// makes the stale-lock double-ownership race impossible: a dead controller's
/// lock is released by the kernel rather than lingering, and two live
/// contenders can never both win the acquisition.
///
/// `pub(crate)` so the checkpoint command ([`crate::retention::checkpoint`]) runs
/// under the SAME lock discipline as pushes: the application-store lock then
/// the target lock, exactly like [`crate::deploy::push`].
pub(crate) struct FileLock {
    file: std::fs::File,
    path: std::path::PathBuf,
}

impl FileLock {
    pub(crate) fn acquire(path: &Path, op_id: &str) -> Result<Self> {
        // DURABLE parent creation: the lock file's parent directory is
        // created with EVERY newly created directory entry fsynced (see
        // [`crate::store::atomic::ensure_private_dir_durable`]) BEFORE the
        // lock is taken. A lock acquisition that creates a directory must
        // never do so with a plain unsynced mkdir — the engine's first
        // push used to let the lock path create `targets/<target>/` that
        // way, bypassing the durable first-append helper (the target dir
        // already existed when the append's creation detection ran, so no
        // parent sync happened) and a reported-successful first push could
        // recover with the target directory missing after power loss. The
        // engine also durably pre-creates the target directory before
        // locking (see [`crate::deploy::push`]); this helper makes
        // the lock path itself durable for every caller.
        if let Some(parent) = path.parent() {
            crate::store::atomic::ensure_private_dir_durable(parent)
                .map_err(|e| Error::preflight(format!("mkdir {}: {e}", parent.display())))?;
        }
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|e| Error::preflight(format!("open lock {}: {e}", path.display())))?;
        let fd = file.as_raw_fd();
        // Exclusive, non-blocking advisory lock. Only one holder at a time.
        let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => {
                    let held = std::fs::read_to_string(path).unwrap_or_default();
                    return Err(Error::preflight(format!(
                        "local lock {} held by '{}'",
                        path.display(),
                        held.trim()
                    )));
                }
                _ => {
                    return Err(Error::preflight(format!("flock {}: {err}", path.display())));
                }
            }
        }
        // We hold the lock: record our operation id for diagnostics.
        use std::io::Write;
        file.set_len(0)
            .and_then(|_| file.write_all(op_id.as_bytes()))
            .map_err(|e| Error::preflight(format!("write lock {}: {e}", path.display())))?;
        Ok(FileLock {
            file,
            path: path.to_path_buf(),
        })
    }
}

impl std::ops::Drop for FileLock {
    fn drop(&mut self) {
        // Release the advisory lock, then remove the (now-unlocked) file.
        // Best-effort by design, like the other Drop fallbacks: this runs on
        // every return path (including panic/unwind), so a failure must not
        // surface, and a stale lock file is re-acquired harmlessly next time
        // (the flock itself is released by the kernel when the fd drops).
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
        let _ = std::fs::remove_file(&self.path);
    }
}
