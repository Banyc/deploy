//! Remote helper: server-side operations over a [`Remote`] transport.
//!
//! The [`RemoteHelper`] struct and its constructor, plus the core read/status
//! plumbing everything shares: the status/record types, behavior-contract
//! reads, the server mutation lock (and its RAII guard), and inventory
//! writes. Per-feature method groups live in their owning modules: the
//! generation record in [`crate::remote::assignment`], the `current` symlink
//! chain in [`crate::remote::current`], commit markers in [`crate::remote::markers`],
//! transaction records in [`crate::remote::transactions`], object-store
//! publication in [`crate::remote::publish`], receiver rotation in
//! [`crate::remote::rotate`], and the protocol handshake in
//! [`crate::remote::protocol`]. Every mutating operation is keyed by an
//! operation ID and is idempotent.

use crate::error::{Error, Result};
use crate::identity::{BehaviorContract, GenerationId, ReleaseId, ReleaseRecord};
use crate::remote::layout;
use crate::remote::transport::Remote;

// Re-export so pre-extraction paths (`crate::remote::helper::GenerationAssignment`)
// keep compiling unchanged.
pub use crate::remote::assignment::GenerationAssignment;

#[derive(Clone, Debug, Default)]
pub struct RemoteStatus {
    /// The validated identity of the generation the `current` symlink names.
    /// `None` ONLY when there is no `current` link at all (genuine absence).
    /// Any PRESENT `current` must name the EXACT canonical
    /// `generations/<gen-id>/root` target and the whole chain behind it must
    /// validate; every deviation (non-canonical target, missing/corrupt
    /// assignment, mismatched generation id, missing/wrong generation `root`
    /// link, missing tree object) fails `status()` with an integrity error —
    /// never a fabricated `None` and never a panic.
    pub current_generation: Option<GenerationId>,
    pub current_tree: Option<String>,
    pub inventory: Vec<String>,
    pub lock: Option<String>,
    pub pending_incoming: Vec<String>,
}

pub struct RemoteHelper<'a> {
    pub(crate) remote: &'a dyn Remote,
}

impl<'a> RemoteHelper<'a> {
    pub fn new(remote: &'a dyn Remote) -> Self {
        RemoteHelper { remote }
    }

    pub fn remote(&self) -> &dyn Remote {
        self.remote
    }

    /// Read the behavior contract for a specific variant of a release. The
    /// release's `behavior.json` stores one contract per declared variant; the
    /// assigned variant is selected explicitly rather than falling back to the
    /// caller's current configuration.
    ///
    /// The published release record is read and identity-verified FIRST (its
    /// canonical digest is recomputed from its own content); its provenance
    /// `behavior_sha256` is then the digest the remote `behavior.json` must
    /// match. A tampered behavior document fails closed with an integrity
    /// error — the historical contract is never returned unverified.
    pub fn read_behavior(&self, release_id: &ReleaseId, variant: &str) -> Result<BehaviorContract> {
        let p = layout::remote_release(release_id.as_str()).join("behavior.json");
        let data = self.remote.read(&p)?;
        // Verify the published release record (its own identity is recomputed
        // from its content) and bind it to the requested release path; its
        // provenance `behavior_sha256` is the canonical digest the behavior
        // snapshot must match.
        let rec: ReleaseRecord = serde_json::from_slice(
            &self
                .remote
                .read(&layout::remote_release(release_id.as_str()).join("release.json"))?,
        )
        .map_err(|e| Error::integrity(format!("malformed release record for {release_id}: {e}")))?;
        crate::verify::release::verify_release_identity(&rec)?;
        if rec.release_id != release_id.as_str() {
            return Err(Error::integrity(format!(
                "release record identity {} does not match the read path {release_id}",
                rec.release_id
            )));
        }
        let behaviors = crate::verify::release::verify_behavior_json(
            &data,
            &rec.release_id,
            &rec.provenance.behavior_sha256,
        )?;
        behaviors.get(variant).cloned().ok_or_else(|| {
            Error::remote(format!(
                "release {release_id} has no behavior for variant '{variant}'"
            ))
        })
    }

    /// Acquire the server mutation lock. `force` overrides a held lock (used
    /// only during recovery). Returns true if the lock is now owned by `op_id`.
    pub fn acquire_lock(&self, op_id: &str, force: bool) -> Result<bool> {
        let p = &layout::operation_lock();
        // Atomic create-if-absent: only one caller wins the race for a free lock.
        match self.remote.try_write_new(p, op_id.as_bytes())? {
            true => Ok(true),
            false => {
                // The lock already existed. Read who holds it.
                let held = self.remote.read(p)?;
                let held = String::from_utf8_lossy(&held).trim().to_string();
                if held == op_id {
                    return Ok(true);
                }
                if !force {
                    return Err(Error::remote(format!(
                        "remote mutation lock held by '{held}', not '{op_id}'"
                    )));
                }
                // Force path: overwrite the holder. (Used only during recovery.)
                self.remote.write(p, op_id.as_bytes(), 0o644)?;
                Ok(true)
            }
        }
    }

    pub fn release_lock(&self, op_id: &str) -> Result<()> {
        let p = &layout::operation_lock();
        if self.remote.exists(p) {
            let held = self.remote.read(p)?;
            if String::from_utf8_lossy(&held).trim() == op_id {
                self.remote.remove_file(p)?;
            }
        }
        Ok(())
    }

    /// Acquire the server mutation lock and return a guard that releases it on
    /// drop, so every return path (including early errors) releases the lock.
    /// Returns an error only if the lock is held by a different operation.
    pub fn acquire_lock_guard(&self, op_id: &str) -> Result<LockGuard<'_>> {
        self.acquire_lock(op_id, false)?;
        Ok(LockGuard {
            helper: self,
            op_id: op_id.to_string(),
            active: true,
        })
    }

    /// Recompute and write `state/inventory.json`.
    pub fn write_inventory(&self) -> Result<()> {
        let mut inv = Vec::new();
        let obj_root = layout::objects();
        if self.remote.exists(obj_root) {
            for e in self.remote.list(obj_root)? {
                if e.is_dir {
                    inv.push(e.name);
                }
            }
        }
        inv.sort();
        let json = serde_json::to_vec_pretty(&inv)
            .map_err(|e| Error::remote(format!("serialize inventory: {e}")))?;
        self.remote.write(&layout::inventory(), &json, 0o644)?;
        Ok(())
    }
}

/// when [`LockGuard::release`] is called explicitly.
pub struct LockGuard<'a> {
    helper: &'a RemoteHelper<'a>,
    op_id: String,
    active: bool,
}

impl<'a> LockGuard<'a> {
    /// Release the lock early (idempotent).
    pub fn release(mut self) {
        if self.active {
            let _ = self.helper.release_lock(&self.op_id);
            self.active = false;
        }
    }
}

impl<'a> Drop for LockGuard<'a> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.helper.release_lock(&self.op_id);
        }
    }
}

pub fn now_rfc3339() -> String {
    jiff::Timestamp::now().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::transport::LocalTransport;

    /// The RAII lock guard releases the server mutation lock on drop, even
    /// when the guarded block exits through an error path (no explicit
    /// release): after the guard drops, a fresh operation can acquire the
    /// lock again and the lock file is gone. This is the property the two
    /// retention paths rely on — a manual acquire/release pair would leak the
    /// lock on a `?` error and strand every later operation on the slot.
    #[test]
    fn lock_guard_releases_on_drop_after_error() {
        let dir = tempfile::tempdir().unwrap();
        let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
        let helper = RemoteHelper::new(&remote);

        {
            let _guard = helper.acquire_lock_guard("op-1").expect("lock acquired");
            // While the guard is alive the lock is held: a second operation
            // cannot acquire it.
            assert!(
                helper.acquire_lock("op-2", false).is_err(),
                "a second operation must not acquire a held lock"
            );
            // Simulate an error path: the guard drops here (scope exit)
            // without any explicit release.
        }

        // After the guard dropped, the lock file is gone and another
        // operation can acquire the lock.
        assert!(
            !remote.exists(&layout::operation_lock()),
            "the lock file must be removed on drop"
        );
        assert!(
            helper.acquire_lock("op-2", false).is_ok(),
            "the lock must be released when the guard drops"
        );
    }
}
