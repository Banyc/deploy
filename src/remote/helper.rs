//! Remote helper: server-side operations over a [`Remote`] transport.
//!
//! The [`RemoteHelper`] struct and its constructor, plus the core read/status
//! plumbing everything shares: the status/assignment/record types, assignment
//! and behavior-contract reads, the server mutation lock (and its RAII
//! guard), generation-record creation, and inventory writes. Per-feature
//! method groups live in their owning modules: the `current` symlink chain in
//! [`crate::remote::current`], commit markers in [`crate::remote::markers`],
//! transaction records in [`crate::remote::transactions`], object-store
//! publication in [`crate::remote::publish`], receiver rotation in
//! [`crate::remote::rotate`], and the protocol handshake in
//! [`crate::remote::protocol`]. Every mutating operation is keyed by an
//! operation ID and is idempotent.

use crate::error::{Error, Result};
use crate::identity::{
    ArtifactRef, BehaviorContract, DeploymentId, GenerationId, ReleaseId, ReleaseRecord, TargetName,
};
use crate::remote::layout;
use crate::remote::transport::Remote;
use serde::{Deserialize, Serialize};

/// The remote generation record (`generations/<gen>/assignment.json`). The
/// artifact relationship is expressed via the canonical [`ArtifactRef`]; the
/// ID fields are the (string-shaped on the wire) typed newtypes so the JSON
/// stays `{deployment_id, generation_id, artifact: {release, variant, tree},
/// behavior_sha256, prior_generation, created_at, target}`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenerationAssignment {
    pub deployment_id: DeploymentId,
    pub generation_id: GenerationId,
    pub artifact: ArtifactRef,
    pub behavior_sha256: String,
    #[serde(default)]
    pub prior_generation: Option<GenerationId>,
    pub created_at: String,
    /// The target whose push created this generation record. Retention on a
    /// slot shared between several targets is attributed per originating
    /// target; `None` marks a LEGACY record written before this field existed
    /// (retained conservatively under every member policy).
    #[serde(default)]
    pub target: Option<TargetName>,
}

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

    pub fn read_assignment(&self, gen_id: &str) -> Result<GenerationAssignment> {
        let p = layout::generation(gen_id).join("assignment.json");
        let data = self.remote.read(&p)?;
        serde_json::from_slice(&data).map_err(|e| Error::remote(format!("parse assignment: {e}")))
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

    /// Create a generation record and its `root` symlink. Does not move
    /// `current`.
    ///
    /// The assignment record is immutable and installed with create-or-compare
    /// semantics: a generation ID colliding with different content fails
    /// integrity instead of silently rewriting history. Generation IDs are
    /// fresh UUIDv7 values minted under the operation lock, so this can only
    /// fire on corruption or retry-after-crash with divergent state.
    pub fn create_generation(&self, op_id: &str, assignment: &GenerationAssignment) -> Result<()> {
        let gen_dir = layout::generation(assignment.generation_id.as_str());
        self.remote.create_dir_all(&gen_dir)?;
        let json = serde_json::to_vec_pretty(assignment)
            .map_err(|e| Error::remote(format!("serialize assignment: {e}")))?;
        let assignment_path = gen_dir.join("assignment.json");
        if !self.remote.try_write_new(&assignment_path, &json)? {
            let existing = self.remote.read(&assignment_path)?;
            if existing != json {
                return Err(Error::integrity(format!(
                    "generation {} already exists with different content",
                    assignment.generation_id
                )));
            }
        }
        // The `root` symlink lives inside `generations/<gen>/`, so it must be
        // relative to that directory (../../objects/...). Its target is derived
        // deterministically from the (now-verified) assignment, so recreating
        // it after a crash is safe.
        let root_link_path = gen_dir.join("root");
        if !self.remote.exists(&root_link_path) {
            let root_link = layout::generation_root_link(assignment.artifact.tree.as_str());
            self.remote.symlink(&root_link, &root_link_path)?;
        }
        let _ = op_id;
        Ok(())
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
    use crate::identity::{test_deployment_id, test_generation_id, test_tree_digest};
    use crate::remote::transport::LocalTransport;

    fn assignment(gen_id: &str, tree: &str) -> GenerationAssignment {
        GenerationAssignment {
            deployment_id: test_deployment_id("deploy-1"),
            generation_id: test_generation_id(gen_id),
            artifact: ArtifactRef {
                release: crate::identity::test_release_id("rel-sha256-x"),
                variant: crate::identity::VariantName::new("standard".to_string()),
                tree: crate::identity::test_tree_digest(tree),
            },
            behavior_sha256: "b".to_string(),
            prior_generation: None,
            created_at: "2020-01-01T00:00:00Z".to_string(),
            target: Some(TargetName::new("t1")),
        }
    }

    /// A generation record is immutable: installed with create-or-compare, so
    /// an ID collision with divergent content fails integrity instead of
    /// rewriting history, and the original record survives untouched.
    #[test]
    fn generation_assignment_is_create_or_compare() {
        let dir = tempfile::tempdir().unwrap();
        let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
        let helper = RemoteHelper::new(&remote);

        helper
            .create_generation("op", &assignment("gen-1", "tree-a"))
            .expect("first create");
        // Identical recreation (retry after crash) is idempotent.
        helper
            .create_generation("op", &assignment("gen-1", "tree-a"))
            .expect("identical recreation is idempotent");

        // Divergent content for the same generation ID fails integrity...
        let err = helper
            .create_generation("op", &assignment("gen-1", "tree-TAMPERED"))
            .expect_err("divergent generation rewrite must fail");
        assert!(
            err.to_string().contains("different content"),
            "error must name the immutability violation, got: {err}"
        );

        // ...and the original record survives. (The `root` symlink may dangle
        // here — no object was published in this test — so assert on the link
        // itself rather than its resolved target.)
        let a = helper
            .read_assignment(test_generation_id("gen-1").as_str())
            .unwrap();
        assert_eq!(
            a.artifact.tree.as_str(),
            test_tree_digest("tree-a").as_str()
        );
        assert!(
            std::fs::symlink_metadata(
                remote
                    .root()
                    .join(format!("generations/{}/root", test_generation_id("gen-1")))
            )
            .is_ok(),
            "generation root symlink must exist"
        );
    }

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
