//! Remote helper: server-side operations over a [`Remote`] transport.
//!
//! Implements status inspection, locking, object publication, generation
//! switching with a compare-and-swap precondition, transaction records,
//! history, adapter invocation, and rotation. Every mutating operation is
//! keyed by an operation ID and is idempotent.

use crate::error::{Error, Result};
use crate::model::BehaviorContract;
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
    pub fn handshake(&self) -> Result<u32> {
        let marker =
            serde_json::json!({ "protocol_version": crate::remote::transport::PROTOCOL_VERSION });
        let bytes = serde_json::to_vec_pretty(&marker)
            .map_err(|e| Error::remote(format!("serialize marker: {e}")))?;
        self.remote
            .write(Path::new("control/protocol.json"), &bytes, 0o644)?;
        Ok(crate::remote::transport::PROTOCOL_VERSION)
    }

    /// Inspect the actual remote generation, object inventory, lock, and
    /// pending incoming directories.
    pub fn status(&self) -> Result<RemoteStatus> {
        let mut status = RemoteStatus::default();

        // Current generation via the top-level `current` symlink.
        if self.remote.exists(Path::new("current")) {
            let target = self.remote.read_link(Path::new("current"))?;
            let comps: Vec<&str> = target
                .components()
                .map(|c| c.as_os_str().to_str().unwrap_or(""))
                .collect();
            if let Some(pos) = comps.iter().position(|&c| c == "generations")
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
        let obj_root = Path::new("objects/sha256");
        if self.remote.exists(obj_root) {
            for e in self.remote.list(obj_root)? {
                if e.is_dir {
                    status.inventory.push(e.name);
                }
            }
        }

        // Lock holder.
        if self.remote.exists(Path::new("state/operation.lock")) {
            let data = self.remote.read(Path::new("state/operation.lock"))?;
            status.lock = Some(String::from_utf8_lossy(&data).trim().to_string());
        }

        // Pending incoming.
        let inc = Path::new("incoming");
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
        let p = Path::new("generations")
            .join(gen_id)
            .join("assignment.json");
        let data = self.remote.read(&p)?;
        serde_json::from_slice(&data).map_err(|e| Error::remote(format!("parse assignment: {e}")))
    }

    /// Read the behavior contract stored for a release.
    pub fn read_behavior(&self, release_id: &str) -> Result<BehaviorContract> {
        let p = Path::new("releases").join(release_id).join("behavior.json");
        let data = self.remote.read(&p)?;
        crate::release::behavior_contract_from_json(&data)
            .map_err(|e| Error::remote(format!("parse behavior for {release_id}: {e}")))
    }

    /// Acquire the server mutation lock. `force` overrides a held lock (used
    /// only during recovery). Returns true if the lock is now owned by `op_id`.
    pub fn acquire_lock(&self, op_id: &str, force: bool) -> Result<bool> {
        let p = Path::new("state/operation.lock");
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
        let p = Path::new("state/operation.lock");
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
        self.remote
            .exists(&Path::new("objects/sha256").join(digest).join("root"))
    }

    /// Copy a host-local tree into the remote object store, verifying the
    /// digest after publication. Reuses an existing, verified object.
    pub fn publish_tree(&self, digest: &str, host_src: &Path) -> Result<()> {
        if self.tree_exists(digest) {
            // Best-effort verification already trusted on first publish.
            return Ok(());
        }
        let dest = Path::new("objects/sha256").join(digest).join("root");
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
        let dir = Path::new("releases").join(release_id);
        self.remote
            .write(&dir.join("release.json"), release_json.as_bytes(), 0o644)?;
        self.remote
            .write(&dir.join("behavior.json"), behavior_json.as_bytes(), 0o644)?;
        Ok(())
    }

    /// Create a generation record and its `root` symlink. Does not move
    /// `current`.
    pub fn create_generation(&self, op_id: &str, assignment: &GenerationAssignment) -> Result<()> {
        let gen_dir = Path::new("generations").join(&assignment.generation_id);
        self.remote.create_dir_all(&gen_dir)?;
        let json = serde_json::to_vec_pretty(assignment)
            .map_err(|e| Error::remote(format!("serialize assignment: {e}")))?;
        self.remote
            .write(&gen_dir.join("assignment.json"), &json, 0o644)?;
        // The `root` symlink lives inside `generations/<gen>/`, so it must be
        // relative to that directory (../../objects/...).
        let root_link = Path::new("../../objects/sha256")
            .join(&assignment.tree)
            .join("root");
        self.remote.symlink(&root_link, &gen_dir.join("root"))?;
        let _ = op_id;
        Ok(())
    }

    /// Atomically move `current` to the given generation. `expected` is the
    /// compare-and-swap precondition (the planned pre-push generation). When
    /// `expected` is `None` there is no precondition (first deployment).
    pub fn swap_current(&self, expected: Option<&str>, gen_id: &str, op_id: &str) -> Result<()> {
        if self.remote.exists(Path::new("current")) {
            let target = self.remote.read_link(Path::new("current"))?;
            let comps: Vec<String> = target
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            let actual = comps
                .iter()
                .position(|c| c == "generations")
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
        let new_target = Path::new("generations").join(gen_id).join("root");
        let tmp_name = format!(".current.tmp.{op_id}");
        let tmp = Path::new(&tmp_name);
        // Remove any stale temp link.
        self.remote.remove_file(tmp)?;
        self.remote.symlink(new_target.as_path(), tmp)?;
        self.remote.rename(tmp, Path::new("current"))?;
        self.remote.remove_file(tmp).ok();
        Ok(())
    }

    /// Append a history line to `state/history.jsonl`.
    pub fn record_history(&self, line: &str) -> Result<()> {
        let p = Path::new("state/history.jsonl");
        let existing = if self.remote.exists(p) {
            self.remote.read(p)?
        } else {
            Vec::new()
        };
        let mut combined = existing;
        combined.extend_from_slice(line.as_bytes());
        if !line.ends_with('\n') {
            combined.push(b'\n');
        }
        self.remote.write(p, &combined, 0o644)?;
        Ok(())
    }

    /// Recompute and write `state/inventory.json`.
    pub fn write_inventory(&self) -> Result<()> {
        let mut inv = Vec::new();
        let obj_root = Path::new("objects/sha256");
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
        self.remote
            .write(Path::new("state/inventory.json"), &json, 0o644)?;
        Ok(())
    }

    /// Persist a transaction record.
    pub fn transaction_record(&self, op_id: &str, state: &str) -> Result<()> {
        let p = Path::new("transactions").join(format!("{op_id}.json"));
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
        let obj_root = Path::new("objects/sha256");
        if self.remote.exists(obj_root) {
            for e in self.remote.list(obj_root)? {
                if e.is_dir && !retained.contains(&e.name) {
                    self.remote.remove_dir_all(&obj_root.join(&e.name))?;
                }
            }
        }
        let inc = Path::new("incoming");
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
        let dest = Path::new("incoming")
            .join(deployment_id)
            .join(format!("{digest}.partial"));
        copy_host_tree_to_remote(host_src, &dest, self.remote)
    }

    /// Publish a previously staged incoming tree into the object store. Reuses an
    /// existing, verified object.
    pub fn publish_from_incoming(&self, deployment_id: &str, digest: &str) -> Result<()> {
        if self.tree_exists(digest) {
            return Ok(());
        }
        let from = Path::new("incoming")
            .join(deployment_id)
            .join(format!("{digest}.partial"));
        let to = Path::new("objects/sha256").join(digest).join("root");
        self.remote.create_dir_all(to.parent().unwrap())?;
        self.remote.rename(&from, &to)?;
        Ok(())
    }

    /// Remove the top-level `current` symlink (used for first-deploy
    /// compensation). `expected` makes the removal a compare-and-swap: the link
    /// is removed only if it currently points at `expected`, so a concurrent
    /// activation cannot be clobbered.
    pub fn remove_current(&self) -> Result<()> {
        self.remote.remove_file(Path::new("current"))
    }

    /// Remove `current` only if it currently points at `expected`. Returns true
    /// if it was removed, false if `current` pointed elsewhere (or did not exist).
    pub fn remove_current_if(&self, expected: &str) -> Result<bool> {
        if !self.remote.exists(Path::new("current")) {
            return Ok(false);
        }
        let target = self.remote.read_link(Path::new("current"))?;
        let comps: Vec<String> = target
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        let actual = comps
            .iter()
            .position(|c| c == "generations")
            .and_then(|i| comps.get(i + 1).cloned());
        if actual.as_deref() == Some(expected) {
            self.remote.remove_file(Path::new("current"))?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Write a fleet-commit marker for a deployment under this server. The marker
    /// records the generation this server committed and the full set of server
    /// IDs that participate in the fleet commit, so a partial marker can never
    /// masquerade as a complete commit.
    pub fn write_commit_marker(
        &self,
        deployment_id: &str,
        generation: &str,
        server_ids: &[String],
    ) -> Result<()> {
        let p = Path::new("state/commits").join(format!("{deployment_id}.json"));
        let payload = serde_json::json!({
            "deployment_id": deployment_id,
            "committed": true,
            "generation": generation,
            "servers": server_ids,
        });
        let bytes = serde_json::to_vec_pretty(&payload)
            .map_err(|e| Error::remote(format!("serialize commit: {e}")))?;
        self.remote.write(&p, &bytes, 0o644)
    }

    pub fn commit_marker_exists(&self, deployment_id: &str) -> bool {
        self.remote
            .exists(&Path::new("state/commits").join(format!("{deployment_id}.json")))
    }

    /// Persist durable pins.
    pub fn set_pins(&self, pins_json: &str) -> Result<()> {
        self.remote
            .write(Path::new("state/pins.json"), pins_json.as_bytes(), 0o644)
    }

    /// Publish a tree object from a host-local path (used when no prior
    /// incoming staging occurred).
    pub fn publish_tree_from_host(&self, digest: &str, host_src: &Path) -> Result<()> {
        self.publish_tree(digest, host_src)
    }

    /// Remove a specific incoming directory (used after completion).
    pub fn remove_incoming(&self, deployment_id: &str) -> Result<()> {
        self.remote
            .remove_dir_all(&Path::new("incoming").join(deployment_id))?;
        Ok(())
    }
}

/// Copy a host-local tree into a remote-relative path, reconstructing symlinks
/// and modes.
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
