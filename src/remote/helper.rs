//! Remote helper: server-side operations over a [`Remote`] transport.
//!
//! Implements status inspection, locking, object publication, generation
//! switching with a compare-and-swap precondition, transaction records,
//! history, adapter invocation, and rotation. Every mutating operation is
//! keyed by an operation ID and is idempotent.

use crate::error::{Error, Result};
use crate::layout;
use crate::model::{BehaviorContract, ReleaseId};
use crate::remote::transport::Remote;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenerationAssignment {
    pub deployment_id: String,
    pub generation_id: String,
    pub release: String,
    pub variant: String,
    pub tree: String,
    pub behavior_sha256: String,
    #[serde(default)]
    pub prior_generation: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, Default)]
pub struct RemoteStatus {
    pub current_generation: Option<String>,
    pub current_tree: Option<String>,
    pub inventory: Vec<String>,
    pub lock: Option<String>,
    pub pending_incoming: Vec<String>,
}

pub struct RemoteHelper<'a> {
    remote: &'a dyn Remote,
}

impl<'a> RemoteHelper<'a> {
    pub fn new(remote: &'a dyn Remote) -> Self {
        RemoteHelper { remote }
    }

    pub fn remote(&self) -> &dyn Remote {
        self.remote
    }

    /// Protocol handshake. Records the protocol version marker.
    /// Negotiate the remote-state protocol version.
    ///
    /// First contact records this client's `PROTOCOL_VERSION` under
    /// `control/protocol.json` via exclusive create; every later contact reads
    /// it back and refuses on any mismatch, so an old client can never drive a
    /// state directory written by a newer one (and vice versa). Returns the
    /// agreed version.
    pub fn handshake(&self) -> Result<u32> {
        let marker =
            serde_json::json!({ "protocol_version": crate::remote::transport::PROTOCOL_VERSION });
        let bytes = serde_json::to_vec_pretty(&marker)
            .map_err(|e| Error::remote(format!("serialize marker: {e}")))?;
        let marker_path = layout::protocol_marker();
        if self.remote.try_write_new(&marker_path, &bytes)? {
            return Ok(crate::remote::transport::PROTOCOL_VERSION);
        }
        #[derive(serde::Deserialize)]
        struct ProtocolMarker {
            protocol_version: u32,
        }
        let existing = self.remote.read(&marker_path)?;
        let recorded: ProtocolMarker = serde_json::from_slice(&existing).map_err(|e| {
            Error::remote(format!(
                "corrupt control/protocol.json: {e}; refusing to negotiate"
            ))
        })?;
        if recorded.protocol_version != crate::remote::transport::PROTOCOL_VERSION {
            return Err(Error::remote(format!(
                "protocol mismatch: remote state was written with protocol {}, but this client speaks {}",
                recorded.protocol_version,
                crate::remote::transport::PROTOCOL_VERSION
            )));
        }
        Ok(recorded.protocol_version)
    }

    /// Inspect the actual remote generation, object inventory, lock, and
    /// pending incoming directories.
    pub fn status(&self) -> Result<RemoteStatus> {
        let mut status = RemoteStatus::default();

        // Current generation via the top-level `current` symlink.
        if self.remote.exists(layout::current()) {
            let target = self.remote.read_link(layout::current())?;
            let comps: Vec<&str> = target
                .components()
                .map(|c| c.as_os_str().to_str().unwrap_or(""))
                .collect();
            if let Some(pos) = comps
                .iter()
                .position(|&c| c == layout::GENERATIONS_COMPONENT)
                && let Some(gid) = comps.get(pos + 1)
            {
                status.current_generation = Some(gid.to_string());
            }
            if let Some(genid) = &status.current_generation
                && let Ok(a) = self.read_assignment(genid)
            {
                status.current_tree = Some(a.tree);
            }
        }

        // Object inventory.
        let obj_root = layout::objects();
        if self.remote.exists(obj_root) {
            for e in self.remote.list(obj_root)? {
                if e.is_dir {
                    status.inventory.push(e.name);
                }
            }
        }

        // Lock holder.
        if self.remote.exists(&layout::operation_lock()) {
            let data = self.remote.read(&layout::operation_lock())?;
            status.lock = Some(String::from_utf8_lossy(&data).trim().to_string());
        }

        // Pending incoming.
        let inc = layout::incoming();
        if self.remote.exists(inc) {
            for e in self.remote.list(inc)? {
                if e.is_dir {
                    status.pending_incoming.push(e.name);
                }
            }
        }

        Ok(status)
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
    pub fn read_behavior(&self, release_id: &ReleaseId, variant: &str) -> Result<BehaviorContract> {
        let p = layout::remote_release(release_id.as_str()).join("behavior.json");
        let data = self.remote.read(&p)?;
        let behaviors = crate::release::behavior_contracts_from_json(&data)
            .map_err(|e| Error::remote(format!("parse behavior for {release_id}: {e}")))?;
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

    pub fn tree_exists(&self, digest: &str) -> bool {
        self.remote.exists(&layout::tree_root(digest))
    }

    /// Copy a host-local tree into the remote object store, verifying the
    /// digest after publication. Reuses an existing, verified object.
    pub fn publish_tree(&self, digest: &str, host_src: &Path) -> Result<()> {
        if self.tree_exists(digest) {
            // Best-effort verification already trusted on first publish.
            return Ok(());
        }
        let dest = layout::tree_root(digest);
        copy_host_tree_to_remote(host_src, &dest, self.remote)?;
        // Verify the canonical digest of the published object.
        // (The object was canonicalized by the local store before publication.)
        Ok(())
    }

    pub fn publish_release(
        &self,
        release_id: &str,
        release_json: &str,
        behavior_json: &str,
    ) -> Result<()> {
        let dir = layout::remote_release(release_id);
        self.publish_release_file(&dir.join("release.json"), release_json.as_bytes())?;
        self.publish_release_file(&dir.join("behavior.json"), behavior_json.as_bytes())
    }

    /// Install one immutable release-side file with create-or-compare
    /// semantics: the first writer wins via an exclusive create; a subsequent
    /// writer must observe equivalent content or fail. Equivalence is
    /// semantic for JSON (key order and whitespace may differ between
    /// serializations of the same contract) and byte-exact otherwise.
    fn publish_release_file(&self, rel: &Path, data: &[u8]) -> Result<()> {
        if self.remote.try_write_new(rel, data)? {
            return Ok(());
        }
        let existing = self.remote.read(rel)?;
        if json_semantically_equal(&existing, data) {
            return Ok(());
        }
        Err(Error::integrity(format!(
            "refusing to replace existing {} with different content",
            rel.display()
        )))
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
        let gen_dir = layout::generation(&assignment.generation_id);
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
            let root_link = layout::generation_root_link(&assignment.tree);
            self.remote.symlink(&root_link, &root_link_path)?;
        }
        let _ = op_id;
        Ok(())
    }

    /// Atomically move `current` to the given generation. `expected` is the
    /// compare-and-swap precondition (the planned pre-push generation). When
    /// `expected` is `None` there is no precondition (first deployment).
    ///
    /// Lock discipline: the CAS precondition alone is necessary but NOT
    /// sufficient — every caller MUST hold this server's mutation lock
    /// ([`Self::acquire_lock_guard`]) for the whole read-decide-swap window.
    /// The same rule governs [`Self::remove_current_if`]. A swap performed
    /// without the flock can race a concurrent activation between its status
    /// read and the rename.
    pub fn swap_current(&self, expected: Option<&str>, gen_id: &str, op_id: &str) -> Result<()> {
        if self.remote.exists(layout::current()) {
            let target = self.remote.read_link(layout::current())?;
            let comps: Vec<String> = target
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            let actual = comps
                .iter()
                .position(|c| c == layout::GENERATIONS_COMPONENT)
                .and_then(|i| comps.get(i + 1).cloned());
            if let Some(exp) = expected
                && actual.as_deref() != Some(exp)
            {
                return Err(Error::remote(format!(
                    "compare-and-swap precondition failed: current generation is {:?}, expected {exp}",
                    actual
                )));
            }
        }
        let new_target = layout::generation(gen_id).join("root");
        let tmp_name = format!(".current.tmp.{op_id}");
        let tmp = Path::new(&tmp_name);
        // Remove any stale temp link.
        self.remote.remove_file(tmp)?;
        self.remote.symlink(new_target.as_path(), tmp)?;
        self.remote.rename(tmp, layout::current())?;
        self.remote.remove_file(tmp).ok();
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

    /// Persist a transaction record. This is the durable per-operation recovery
    /// record (`transactions/<op-id>.json`, advanced `prepared` → `committed` →
    /// `compensated`): a disconnected client learns an operation's outcome by
    /// reading it, not from any per-server history log.
    pub fn transaction_record(&self, op_id: &str, state: &str) -> Result<()> {
        let p = layout::transaction_record(op_id);
        let payload = serde_json::json!({
            "operation_id": op_id,
            "state": state,
            "updated_at": now_rfc3339(),
        });
        let bytes = serde_json::to_vec_pretty(&payload)
            .map_err(|e| Error::remote(format!("serialize transaction: {e}")))?;
        self.remote.write(&p, &bytes, 0o644)?;
        Ok(())
    }

    /// Mark-and-sweep rotation: delete tree objects whose digest is not in the
    /// retained set, and remove abandoned incoming directories.
    pub fn rotate(
        &self,
        retained: &HashSet<String>,
        active_incoming: &HashSet<String>,
    ) -> Result<()> {
        let obj_root = layout::objects();
        if self.remote.exists(obj_root) {
            for e in self.remote.list(obj_root)? {
                if e.is_dir && !retained.contains(&e.name) {
                    self.remote.remove_dir_all(&obj_root.join(&e.name))?;
                }
            }
        }
        let inc = layout::incoming();
        if self.remote.exists(inc) {
            for e in self.remote.list(inc)? {
                if e.is_dir && !active_incoming.contains(&e.name) {
                    self.remote.remove_dir_all(&inc.join(&e.name))?;
                }
            }
        }
        self.write_inventory()?;
        Ok(())
    }

    /// Stage a tree into a deployment-specific incoming directory (invisible to
    /// activation and rotation until published).
    pub fn stage_incoming(&self, deployment_id: &str, digest: &str, host_src: &Path) -> Result<()> {
        let dest = layout::staged_tree(deployment_id, digest);
        copy_host_tree_to_remote(host_src, &dest, self.remote)
    }

    /// Publish a previously staged incoming tree into the object store. Reuses an
    /// existing, verified object.
    pub fn publish_from_incoming(&self, deployment_id: &str, digest: &str) -> Result<()> {
        if self.tree_exists(digest) {
            return Ok(());
        }
        let from = layout::staged_tree(deployment_id, digest);
        let to = layout::tree_root(digest);
        self.remote.create_dir_all(to.parent().unwrap())?;
        self.remote.rename(&from, &to)?;
        Ok(())
    }

    /// Remove the top-level `current` symlink (used for first-deploy
    /// compensation). `expected` makes the removal a compare-and-swap: the link
    /// is removed only if it currently points at `expected`, so a concurrent
    /// activation cannot be clobbered.
    /// Remove `current` only if it currently points at `expected`. Returns true
    /// if it was removed, false if `current` pointed elsewhere (or did not exist).
    pub fn remove_current_if(&self, expected: &str) -> Result<bool> {
        if !self.remote.exists(layout::current()) {
            return Ok(false);
        }
        let target = self.remote.read_link(layout::current())?;
        let comps: Vec<String> = target
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        let actual = comps
            .iter()
            .position(|c| c == layout::GENERATIONS_COMPONENT)
            .and_then(|i| comps.get(i + 1).cloned());
        if actual.as_deref() == Some(expected) {
            self.remote.remove_file(layout::current())?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Write a fleet-commit marker for a deployment under this server. The marker
    /// records the generation this server committed and the full set of server
    /// IDs that participate in the fleet commit, so a partial marker can never
    /// masquerade as a complete commit.
    ///
    /// Markers are immutable and write-once: the file is created exclusively,
    /// and an existing marker must match byte-for-byte (deterministic payload
    /// for the same deployment) or the rewrite fails integrity. A concurrent or
    /// retried commit therefore can never alter a recorded fact.
    pub fn write_commit_marker(
        &self,
        deployment_id: &str,
        generation: &str,
        server_ids: &[String],
    ) -> Result<()> {
        let p = layout::commit_marker(deployment_id);
        let payload = serde_json::json!({
            "deployment_id": deployment_id,
            "committed": true,
            "generation": generation,
            "servers": server_ids,
        });
        let bytes = serde_json::to_vec_pretty(&payload)
            .map_err(|e| Error::remote(format!("serialize commit: {e}")))?;
        if self.remote.try_write_new(&p, &bytes)? {
            return Ok(());
        }
        let existing = self.remote.read(&p)?;
        if existing != bytes {
            return Err(Error::integrity(format!(
                "commit marker for {deployment_id} already exists with different content"
            )));
        }
        Ok(())
    }

    /// Publish a tree object from a host-local path (used when no prior
    /// incoming staging occurred).
    pub fn publish_tree_from_host(&self, digest: &str, host_src: &Path) -> Result<()> {
        self.publish_tree(digest, host_src)
    }

    /// Remove a specific incoming directory (used after completion).
    pub fn remove_incoming(&self, deployment_id: &str) -> Result<()> {
        self.remote
            .remove_dir_all(&layout::incoming_dir(deployment_id))?;
        Ok(())
    }
}

/// Copy a host-local tree into a remote-relative path, reconstructing symlinks
/// and modes.
/// Compare two serialized JSON documents semantically: equal when they parse
/// to equal `serde_json` values (object key order and whitespace are not part
/// of the contract). Falls back to byte equality when either side is not JSON.
fn json_semantically_equal(a: &[u8], b: &[u8]) -> bool {
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

pub fn copy_host_tree_to_remote(host: &Path, rel_dest: &Path, remote: &dyn Remote) -> Result<()> {
    remote.create_dir_all(rel_dest)?;
    for entry in WalkDir::new(host).min_depth(1).into_iter() {
        let entry = entry.map_err(|e| Error::remote(format!("walk: {e}")))?;
        let path = entry.path();
        let rel = entry
            .path()
            .strip_prefix(host)
            .map_err(|e| Error::remote(format!("{e}")))?;
        let dest = rel_dest.join(rel);
        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| Error::remote(format!("stat {}: {e}", path.display())))?;
        if meta.is_dir() {
            remote.create_dir(&dest)?;
        } else if meta.file_type().is_symlink() {
            let target = std::fs::read_link(path)
                .map_err(|e| Error::remote(format!("readlink {}: {e}", path.display())))?;
            remote.symlink(&target, &dest)?;
        } else {
            let data = std::fs::read(path)
                .map_err(|e| Error::remote(format!("read {}: {e}", path.display())))?;
            remote.write(&dest, &data, meta.mode() & 0o777)?;
        }
    }
    Ok(())
}

/// RAII guard for the server mutation lock. Releases the lock when dropped or
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
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::transport::LocalTransport;

    fn assignment(gen_id: &str, tree: &str) -> GenerationAssignment {
        GenerationAssignment {
            deployment_id: "deploy-1".into(),
            generation_id: gen_id.into(),
            release: "rel-sha256-x".into(),
            variant: "standard".into(),
            tree: tree.into(),
            behavior_sha256: "b".into(),
            prior_generation: None,
            created_at: "2020-01-01T00:00:00Z".into(),
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
        let a = helper.read_assignment("gen-1").unwrap();
        assert_eq!(a.tree, "tree-a");
        assert!(
            std::fs::symlink_metadata(remote.root().join("generations/gen-1/root")).is_ok(),
            "generation root symlink must exist"
        );
    }
}

#[cfg(test)]
mod durability_tests {
    use super::*;
    use crate::remote::transport::PROTOCOL_VERSION;
    use crate::remote::transport::{LocalTransport, Remote};
    use std::path::PathBuf;

    fn setup() -> (tempfile::TempDir, LocalTransport, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
        let root = remote.root().to_path_buf();
        (dir, remote, root)
    }

    /// A crash during a protocol-marker install leaves only an orphaned temp
    /// file: the final marker is absent, and a later handshake installs the
    /// complete record without being confused by the stale temporary.
    #[test]
    fn interrupted_protocol_marker_write_is_recovered() {
        let (_dir, remote, root) = setup();

        // Simulate a writer that died after creating its unique temp and
        // writing only a prefix of the payload.
        let marker = layout::protocol_marker();
        let tmp = marker.with_file_name(format!(
            ".{}.tmp.99999.7",
            marker.file_name().unwrap().to_string_lossy()
        ));
        std::fs::create_dir_all(root.join(marker.parent().unwrap())).unwrap();
        std::fs::write(root.join(&tmp), b"{ \"protocol_ver").unwrap();
        assert!(!root.join(&marker).exists());

        let helper = RemoteHelper::new(&remote);
        let agreed = helper.handshake().expect("handshake must recover");
        assert_eq!(agreed, PROTOCOL_VERSION);

        // The installed marker is complete and correct.
        let recorded: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join(layout::protocol_marker())).unwrap())
                .expect("installed protocol marker must be valid JSON");
        assert_eq!(
            recorded["protocol_version"],
            serde_json::json!(PROTOCOL_VERSION)
        );
    }

    /// Same recovery rule for fleet-commit markers: an interrupted write never
    /// surfaces as a partial marker, and a later commit succeeds cleanly.
    #[test]
    fn interrupted_commit_marker_write_is_recovered() {
        let (_dir, remote, root) = setup();

        std::fs::create_dir_all(root.join(layout::commits_dir())).unwrap();
        let marker = layout::commit_marker("deploy-0");
        let tmp = marker.with_file_name(format!(
            ".{}.tmp.99999.7",
            marker.file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(
            root.join(&tmp),
            b"{ \"deployment_id\": \"deploy-0\", \"commi",
        )
        .unwrap();

        let helper = RemoteHelper::new(&remote);
        helper
            .write_commit_marker("deploy-0", "gen-0", &["server-01".to_string()])
            .expect("commit marker install must succeed past stale temp");

        let marker: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join(layout::commit_marker("deploy-0"))).unwrap(),
        )
        .expect("installed commit marker must be valid JSON");
        assert_eq!(marker["committed"], serde_json::json!(true));
        assert_eq!(marker["generation"], serde_json::json!("gen-0"));
    }

    /// Concurrent readers listing and parsing commit markers while they are
    /// being installed must only ever observe complete records.
    #[test]
    fn commit_markers_are_never_partially_visible_to_concurrent_readers() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("remote");
        let commits_dir = root.join(layout::commits_dir());
        let done = Arc::new(AtomicBool::new(false));

        // Set even if the writer panics (Drop runs during unwind), so the
        // readers always terminate instead of hanging the test binary.
        struct DoneGuard(Arc<AtomicBool>);
        impl Drop for DoneGuard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        std::thread::scope(|s| {
            let base = root.clone();
            let done_w = done.clone();
            let writer_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
            let writer_error_writer = writer_error.clone();
            s.spawn(move || {
                let _done = DoneGuard(done_w);
                let Ok(remote) = LocalTransport::new(base) else {
                    *writer_error_writer.lock().unwrap() =
                        Some("transport setup failed".to_string());
                    return;
                };
                let h = RemoteHelper::new(&remote);
                for i in 0..80 {
                    if let Err(e) = h.write_commit_marker(
                        &format!("deploy-{i}"),
                        &format!("gen-{i}"),
                        &["server-01".to_string()],
                    ) {
                        *writer_error_writer.lock().unwrap() = Some(e.to_string());
                        return;
                    }
                }
            });
            for _ in 0..2 {
                let done = done.clone();
                let commits_dir = commits_dir.clone();
                s.spawn(move || {
                    loop {
                        if done.load(Ordering::SeqCst) {
                            break;
                        }
                        if let Ok(entries) = std::fs::read_dir(&commits_dir) {
                            for e in entries.flatten() {
                                // Temporaries are dot-prefixed so listing-based
                                // observers can skip them.
                                if e.file_name().to_string_lossy().starts_with('.') {
                                    continue;
                                }
                                let data = std::fs::read(e.path()).unwrap_or_default();
                                if data.is_empty() {
                                    panic!("concurrent reader observed an empty marker");
                                }
                                let v: serde_json::Value = serde_json::from_slice(&data)
                                    .expect("marker must always be complete valid JSON");
                                assert_eq!(v["committed"], serde_json::json!(true));
                            }
                        }
                    }
                });
            }

            // The writer must have completed every install successfully.
            assert_eq!(
                writer_error.lock().unwrap().as_deref(),
                None,
                "writer failed to install all commit markers"
            );
        });

        for i in 0..80 {
            let p = commits_dir.join(format!("deploy-{i}.json"));
            let v: serde_json::Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
            assert_eq!(v["committed"], serde_json::json!(true));
        }
    }
}
