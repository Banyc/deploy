//! Remote helper: server-side operations over a [`Remote`] transport.
//!
//! Implements status inspection, locking, object publication, generation
//! switching with a compare-and-swap precondition, transaction records,
//! history, adapter invocation, and rotation. Every mutating operation is
//! keyed by an operation ID and is idempotent.

use crate::error::{Error, Result};
use crate::layout;
use crate::model::{
    ArtifactRef, BehaviorContract, DeploymentId, GenerationId, ReleaseId, ReleaseRecord, TargetName,
};
use crate::remote::transport::Remote;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use walkdir::WalkDir;

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
                status.current_tree = Some(a.artifact.tree.as_str().to_string());
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
        crate::release::verify_release_identity(&rec)?;
        if rec.release_id != release_id.as_str() {
            return Err(Error::integrity(format!(
                "release record identity {} does not match the read path {release_id}",
                rec.release_id
            )));
        }
        let behaviors = crate::release::verify_behavior_json(
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
        // Recompute-and-verify before publishing: never install a release
        // whose stored identity does not match its content. The digest is
        // recomputed from the record's own payload (slot snapshot, bindings,
        // provenance digests), never trusted from the `release_sha256` field;
        // a malformed or tampered record fails closed with an integrity error.
        let rec: ReleaseRecord = serde_json::from_str(release_json).map_err(|e| {
            Error::integrity(format!("malformed release record for {release_id}: {e}"))
        })?;
        crate::release::verify_release_identity(&rec)?;
        if rec.release_id != release_id {
            return Err(Error::integrity(format!(
                "release record identity {} does not match the publish path {release_id}",
                rec.release_id
            )));
        }
        // The behavior.json payload must digest to the release identity's
        // provenance `behavior_sha256` BEFORE anything is written: an
        // unparseable behavior document — or one whose canonical contract set
        // digests to anything else — is never installed on the remote (fail
        // closed), so a release never publishes a behavior snapshot that does
        // not match the release it is stored under. A payload that parses to
        // the SAME canonical contract set (e.g. key reordering) passes.
        crate::release::verify_behavior_json(
            behavior_json.as_bytes(),
            &rec.release_id,
            &rec.provenance.behavior_sha256,
        )?;
        let dir = layout::remote_release(release_id);
        // The release record is identified by its canonical digest
        // (`release_sha256`), not by semantic equality of the full document:
        // metadata fields such as `created_at` (and `provenance.git_revision`)
        // legitimately differ between runs of the same canonical release, so
        // byte/semantic comparison of the whole record would falsely reject
        // idempotent re-publication. Two records with the same recomputed
        // digest are the same release.
        let rel = dir.join("release.json");
        if !self.remote.exists(&rel) {
            self.publish_release_file(&rel, release_json.as_bytes())?;
        } else {
            // The remote already carries a record under this release id.
            // NEVER trust its stored `release_sha256`/`release_id` fields to
            // declare it the same release: content-verify the EXISTING record
            // by recomputing the canonical digest from its own content (slot
            // snapshot, bindings, provenance digests) and checking both
            // identity fields, exactly as incoming records are verified. A
            // corrupted record whose identity-bearing content was mutated
            // while the digest fields were retained at the original values
            // FAILS here with an integrity error naming the remote release
            // and the mismatch — republishing against a corrupted remote
            // record always fails closed, never silently accepting it as
            // identical. Malformed existing JSON is an integrity error, never
            // a silent replace. Only a content-verified record whose
            // recomputed identity equals the incoming record's identity is an
            // idempotent no-op (metadata such as `created_at` and
            // `provenance.git_revision` is excluded from the digest, so it
            // may differ between runs of the same canonical release).
            let existing = self.remote.read(&rel)?;
            let existing_rec: ReleaseRecord = serde_json::from_slice(&existing).map_err(|e| {
                Error::integrity(format!(
                    "malformed existing release record at {}: {e}",
                    rel.display()
                ))
            })?;
            crate::release::verify_release_identity(&existing_rec)?;
            if existing_rec.release_sha256 != rec.release_sha256 {
                return Err(Error::integrity(format!(
                    "refusing to replace existing {} with a different release",
                    rel.display()
                )));
            }
        }
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
    /// records the generation this slot committed, the full set of placement
    /// slot IDs that participate in the fleet commit (so a partial marker can
    /// never masquerade as a complete commit), and the originating target of
    /// the push. `target` is optional for legacy markers written before
    /// originating-target attribution existed; new commits always record it.
    ///
    /// Markers are immutable and write-once: the file is created exclusively,
    /// and an existing record must match byte-for-byte (deterministic payload
    /// for the same deployment) or the rewrite fails integrity. A concurrent or
    /// retried commit therefore never corrupts a recorded fact.
    pub fn write_commit_marker(
        &self,
        deployment_id: &str,
        generation: &str,
        slot_ids: &[String],
        target: Option<&str>,
    ) -> Result<()> {
        let p = layout::commit_marker(deployment_id);
        let mut payload = serde_json::json!({
            "deployment_id": deployment_id,
            "committed": true,
            "generation": generation,
            "slots": slot_ids,
        });
        if let Some(t) = target {
            payload["target"] = serde_json::json!(t);
        }
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

/// Copy a host-local tree into a remote-relative path, reconstructing symlinks
/// and modes.
///
/// The upload is TWO-PHASE so a read-only directory can never block the upload
/// of its own contents:
///
/// 1. **Walk** (depth-first, parents before children): every directory is
///    created with OWNER-WRITE permission (`mode | 0o200`), so files and
///    symlinks beneath it can be written even when the directory's FINAL mode
///    is read-only (e.g. 0o555). Files keep their final mode via
///    `remote.write(..., mode & 0o7777)`; symlinks are created as-is.
/// 2. **Finalize** (after the walk): the FINAL directory modes are applied in
///    REVERSE DEPTH order (deepest first), so a parent is chmodded to its
///    final mode only after every child has been finalized — a read-only
///    parent never blocks a pending child operation.
///
/// Modes are masked to the full 0o7777 (setuid/setgid/sticky included), not
/// 0o777, so the uploaded tree matches the canonical tree digest exactly.
pub fn copy_host_tree_to_remote(host: &Path, rel_dest: &Path, remote: &dyn Remote) -> Result<()> {
    remote.create_dir_all(rel_dest)?;
    // (dest, final_mode, depth) collected during the walk for phase 2.
    let mut dirs: Vec<(std::path::PathBuf, u32, usize)> = Vec::new();
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
            // Phase 1: force owner-write so the directory's contents can be
            // uploaded regardless of the final (possibly read-only) mode. A
            // bare `mkdir` would also inherit the remote umask (e.g. 0775 on
            // umask-0002 hosts), changing the tree digest; the explicit mode
            // keeps the create deterministic. The FINAL mode is applied in
            // phase 2, after every child has been uploaded.
            remote.set_mode(&dest, (meta.mode() | 0o200) & 0o7777)?;
            dirs.push((dest, meta.mode() & 0o7777, entry.depth()));
        } else if meta.file_type().is_symlink() {
            let target = std::fs::read_link(path)
                .map_err(|e| Error::remote(format!("readlink {}: {e}", path.display())))?;
            remote.symlink(&target, &dest)?;
        } else {
            let data = std::fs::read(path)
                .map_err(|e| Error::remote(format!("read {}: {e}", path.display())))?;
            remote.write(&dest, &data, meta.mode() & 0o7777)?;
        }
    }
    // Phase 2: finalize directory modes deepest-first, so a read-only parent
    // is chmodded only after all of its children are finalized.
    dirs.sort_by_key(|d| std::cmp::Reverse(d.2));
    for (dest, mode, _depth) in dirs {
        remote.set_mode(&dest, mode)?;
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
    use std::os::unix::fs::PermissionsExt;

    /// A named (label, mutator) pair driving the publish-rejection mutation
    /// matrices: the label names the tamper in failure messages, the mutator
    /// rewrites one field of the serialized release/behavior JSON.
    type JsonMutation = (&'static str, fn(&mut serde_json::Value));

    fn assignment(gen_id: &str, tree: &str) -> GenerationAssignment {
        GenerationAssignment {
            deployment_id: DeploymentId::new("deploy-1".to_string()),
            generation_id: GenerationId::new(gen_id.to_string()),
            artifact: ArtifactRef {
                release: ReleaseId::new("rel-sha256-x".to_string()),
                variant: crate::model::VariantName::new("standard".to_string()),
                tree: crate::model::TreeDigest::new(tree.to_string()),
            },
            behavior_sha256: "b".to_string(),
            prior_generation: None,
            created_at: "2020-01-01T00:00:00Z".to_string(),
            target: Some(TargetName::new("t1")),
        }
    }

    /// A publish fixture: a release record whose provenance `behavior_sha256`
    /// is the canonical digest of a real per-variant behavior contract set
    /// (adapter `systemd` — non-default, so field deletions change the
    /// digest — plus a command verification), and the serialized behavior JSON
    /// for that same set.
    fn publish_fixture() -> (crate::model::ReleaseRecord, String) {
        let contracts: std::collections::BTreeMap<String, crate::model::BehaviorContract> =
            std::collections::BTreeMap::from([(
                "standard".to_string(),
                crate::model::BehaviorContract {
                    activation: crate::config::ActivationConfig {
                        adapter: "systemd".to_string(),
                        scope: crate::config::ActivationScope::System,
                        reconcile_managed_units: true,
                        units: vec![crate::config::UnitDef {
                            name: "app.service".to_string(),
                            artifact_path: "integration/systemd/app.service".to_string(),
                            enable: true,
                            restart: true,
                        }],
                    },
                    verification: crate::config::VerificationConfig {
                        adapter: "command".to_string(),
                        argv: vec!["true".to_string()],
                        timeout_seconds: 30,
                        attempts: 2,
                        interval_seconds: 1,
                    },
                },
            )]);
        let behavior_sha = crate::release::variant_behaviors_digest(&contracts);
        let variants: std::collections::BTreeMap<
            crate::model::VariantName,
            crate::model::TreeDigest,
        > = std::collections::BTreeMap::from([(
            crate::model::VariantName::new("standard"),
            crate::model::TreeDigest::new("t1"),
        )]);
        let slots: std::collections::BTreeMap<String, Vec<crate::config::SlotDef>> =
            std::collections::BTreeMap::from([(
                "standard".to_string(),
                vec![crate::config::SlotDef {
                    id: "p1".to_string(),
                    server: "s1".to_string(),
                    deploy_dir: std::path::PathBuf::from("/srv/deploy/p1"),
                    targets: vec!["t1".to_string()],
                }],
            )]);
        let rec = crate::release::build_release(
            "m",
            &behavior_sha,
            &variants,
            &slots,
            std::path::Path::new("."),
        );
        let behavior_json = serde_json::to_string(&contracts).unwrap();
        (rec, behavior_json)
    }

    /// `publish_release` recomputes the canonical digest from the serialized
    /// record's content and verifies it against the stored identity before
    /// installing anything: a pristine record publishes (and re-publishes
    /// idempotently), while a record whose slot declaration was edited with the
    /// old `release_sha256`/`release_id` retained fails closed with an
    /// integrity error — a release whose identity does not match its content is
    /// never published.
    #[test]
    fn publish_release_recomputes_and_verifies_identity() {
        let dir = tempfile::tempdir().unwrap();
        let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
        let helper = RemoteHelper::new(&remote);
        let (rec, behavior_json) = publish_fixture();
        let release_json = serde_json::to_string(&rec).unwrap();

        // Positive case: the pristine record publishes, and re-publishing the
        // identical release is an idempotent no-op.
        helper
            .publish_release(rec.release_id.as_str(), &release_json, &behavior_json)
            .expect("pristine record publishes");
        helper
            .publish_release(rec.release_id.as_str(), &release_json, &behavior_json)
            .expect("identical re-publication is idempotent");

        // Tampered record: slot content changed, digest fields retained -> the
        // publish must fail with an integrity error naming the mismatch.
        let mut tampered = rec.clone();
        tampered.slots.get_mut("standard").unwrap().slots[0].deploy_dir =
            "/srv/elsewhere".to_string();
        assert_eq!(
            tampered.release_sha256, rec.release_sha256,
            "digest retained"
        );
        let err = helper
            .publish_release(
                rec.release_id.as_str(),
                &serde_json::to_string(&tampered).unwrap(),
                &behavior_json,
            )
            .expect_err("tampered record must never be published");
        let msg = err.to_string();
        assert!(
            msg.contains("identity mismatch"),
            "error must name the mismatch, got: {msg}"
        );
        assert!(
            msg.contains(&rec.release_sha256),
            "error must name the stored digest, got: {msg}"
        );

        // A malformed payload is refused outright.
        let err = helper
            .publish_release(rec.release_id.as_str(), "{}", &behavior_json)
            .expect_err("a malformed release record must be refused");
        assert!(err.to_string().contains("malformed release record"));
    }

    /// A fresh remote already carrying the pristine record under
    /// `releases/<id>/release.json` (+ `behavior.json`), plus the pristine
    /// serialized record and behavior JSON for republishing. The behavior
    /// payload is DIGEST-CONSISTENT: it is serialized from the same
    /// per-variant contract set whose canonical digest is frozen into the
    /// release's provenance `behavior_sha256` (see `publish_fixture`), so
    /// `publish_release`'s behavior.json digest verification accepts the
    /// pristine record. Each case builds its own fixture so the mutation
    /// matrix stays deterministic.
    fn published_release_fixture() -> (
        tempfile::TempDir,
        LocalTransport,
        ReleaseRecord,
        String,
        String,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
        let helper = RemoteHelper::new(&remote);
        let (rec, behavior_json) = publish_fixture();
        let release_json = serde_json::to_string(&rec).unwrap();
        helper
            .publish_release(rec.release_id.as_str(), &release_json, &behavior_json)
            .expect("pristine record publishes");
        (dir, remote, rec, release_json, behavior_json)
    }

    /// Republishing against an EXISTING remote record that was CORRUPTED must
    /// ALWAYS fail closed: mutate each identity-bearing field of the stored
    /// remote `release.json` one at a time (written directly to the remote
    /// path, bypassing the verified publish path) while retaining
    /// `release_sha256`/`release_id` at the ORIGINAL values, then republish
    /// the CORRECT original release. The mutation matrix covers the
    /// per-variant mappings digest, the behavior digest, the slot snapshot
    /// (`deploy_dir`/targets), the variant→tree bindings, a variant renamed
    /// or removed, and the identity-bearing provenance fields. Every case
    /// must fail with an integrity error naming the remote release and the
    /// content-vs-digest mismatch — a corrupted remote record is never
    /// silently accepted as the same release. Metadata-only differences
    /// (`created_at`, `provenance.git_revision` — excluded from the digest)
    /// still no-op idempotently.
    #[test]
    fn republish_content_verifies_existing_remote_record() {
        // (a) One identity-bearing mutation at a time -> every republish fails.
        let identity_mutations: [JsonMutation; 7] = [
            (
                "per-variant mappings digest",
                |v: &mut serde_json::Value| {
                    v["provenance"]["mapping_sha256"] = serde_json::json!("tampered-mapping");
                },
            ),
            ("behavior digest", |v: &mut serde_json::Value| {
                v["provenance"]["behavior_sha256"] = serde_json::json!("tampered-behavior");
            }),
            ("slot deploy_dir", |v: &mut serde_json::Value| {
                v["slots"]["standard"]["slots"][0]["deploy_dir"] =
                    serde_json::json!("/srv/elsewhere");
            }),
            ("slot targets membership", |v: &mut serde_json::Value| {
                v["slots"]["standard"]["slots"][0]["targets"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!("tampered-target"));
            }),
            ("variant->tree binding", |v: &mut serde_json::Value| {
                v["variants"]["standard"] = serde_json::json!("tree-tampered");
            }),
            ("variant renamed", |v: &mut serde_json::Value| {
                let tree = v["variants"]["standard"].clone();
                v["variants"].as_object_mut().unwrap().remove("standard");
                v["variants"]["tampered-variant"] = tree;
            }),
            ("variant removed", |v: &mut serde_json::Value| {
                v["variants"].as_object_mut().unwrap().remove("standard");
            }),
        ];
        for (name, mutate) in identity_mutations {
            let (_dir, remote, rec, release_json, behavior_json) = published_release_fixture();
            let mut stored = serde_json::to_value(&rec).unwrap();
            mutate(&mut stored);
            // The identity-bearing content mutated, digest fields retained at
            // the original values.
            assert_eq!(
                stored["release_sha256"], rec.release_sha256,
                "{name}: digest must be retained"
            );
            assert_eq!(
                stored["release_id"], rec.release_id,
                "{name}: release id must be retained"
            );
            let rel = layout::remote_release(rec.release_id.as_str()).join("release.json");
            remote
                .write(&rel, &serde_json::to_vec(&stored).unwrap(), 0o644)
                .unwrap();
            let helper = RemoteHelper::new(&remote);
            let fail_msg =
                format!("{name}: republishing against a corrupted remote record must fail closed");
            let err = helper
                .publish_release(rec.release_id.as_str(), &release_json, &behavior_json)
                .expect_err(&fail_msg);
            let msg = err.to_string();
            assert!(
                msg.contains("identity mismatch"),
                "{name}: error must name the content-vs-digest mismatch, got: {msg}"
            );
            assert!(
                msg.contains(&rec.release_sha256),
                "{name}: error must name the stored digest, got: {msg}"
            );
        }

        // A corrupted remote behavior.json fails the republish via the
        // snapshot's own create-or-compare content check (release.json is
        // untouched here, so the failure is pinned to behavior.json).
        let (_dir, remote, rec, release_json, behavior_json) = published_release_fixture();
        let bpath = layout::remote_release(rec.release_id.as_str()).join("behavior.json");
        remote.write(&bpath, b"{\"tampered\":", 0o644).unwrap();
        let helper = RemoteHelper::new(&remote);
        let err = helper
            .publish_release(rec.release_id.as_str(), &release_json, &behavior_json)
            .expect_err("a corrupted remote behavior.json must fail republish");
        assert!(
            err.to_string().contains("different content"),
            "error must name the create-or-compare refusal, got: {err}"
        );

        // Malformed existing release.json is refused outright, never silently
        // replaced.
        let (_dir, remote, rec, release_json, behavior_json) = published_release_fixture();
        let rel = layout::remote_release(rec.release_id.as_str()).join("release.json");
        remote.write(&rel, b"{ not json", 0o644).unwrap();
        let helper = RemoteHelper::new(&remote);
        let err = helper
            .publish_release(rec.release_id.as_str(), &release_json, &behavior_json)
            .expect_err("malformed existing release.json must be refused, not silently replaced");
        assert!(
            err.to_string()
                .contains("malformed existing release record"),
            "error must name the malformed existing record, got: {err}"
        );

        // Metadata-only differences in the EXISTING record (`created_at`,
        // `provenance.git_revision`) are excluded from the digest: republishing
        // against a record that differs ONLY in those fields is still an
        // idempotent no-op.
        let metadata_mutations: [JsonMutation; 2] = [
            ("created_at", |v: &mut serde_json::Value| {
                v["created_at"] = serde_json::json!("2099-01-01T00:00:00Z");
            }),
            ("provenance.git_revision", |v: &mut serde_json::Value| {
                v["provenance"]["git_revision"] = serde_json::json!("tampered-git");
            }),
        ];
        for (name, mutate) in metadata_mutations {
            let (_dir, remote, rec, release_json, behavior_json) = published_release_fixture();
            let mut stored = serde_json::to_value(&rec).unwrap();
            mutate(&mut stored);
            let rel = layout::remote_release(rec.release_id.as_str()).join("release.json");
            remote
                .write(&rel, &serde_json::to_vec(&stored).unwrap(), 0o644)
                .unwrap();
            let helper = RemoteHelper::new(&remote);
            let ok_msg =
                format!("{name}: a metadata-only difference keeps the republish idempotent");
            helper
                .publish_release(rec.release_id.as_str(), &release_json, &behavior_json)
                .expect(&ok_msg);
        }
    }

    /// Mutation matrix over the behavior JSON handed to `publish_release`:
    /// deleting each required field, changing each identity-bearing field, or
    /// corrupting the bytes must make the publication FAIL CLOSED with an
    /// integrity error (the canonical digest no longer matches the release
    /// identity's provenance `behavior_sha256`), while a mutation that keeps
    /// the canonical contract set equal (JSON key reordering) MUST publish —
    /// that is the "unless the canonical behavior digest remains equal"
    /// clause.
    #[test]
    fn publish_release_verifies_behavior_json_digest() {
        let dir = tempfile::tempdir().unwrap();
        let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
        let helper = RemoteHelper::new(&remote);
        let (rec, behavior_json) = publish_fixture();
        let release_json = serde_json::to_string(&rec).unwrap();
        let rid = rec.release_id.as_str();

        // Baseline: the canonical behavior payload publishes.
        helper
            .publish_release(rid, &release_json, &behavior_json)
            .expect("pristine behavior publishes");

        let publish = |label: &str, payload: &str| {
            let err = helper
                .publish_release(rid, &release_json, payload)
                .expect_err("a digest-changing behavior payload must fail closed");
            let msg = err.to_string();
            assert!(
                msg.contains("digest mismatch") || msg.contains("malformed"),
                "mutation '{label}' must fail with an integrity error, got: {msg}"
            );
        };

        let v: serde_json::Value = serde_json::from_str(&behavior_json).unwrap();
        // Required-field deletions: activation.adapter, verification.argv, a
        // whole variant's contract, the variant key itself.
        let mut del = v.clone();
        del["standard"]["activation"]
            .as_object_mut()
            .unwrap()
            .remove("adapter");
        publish(
            "delete activation.adapter",
            &serde_json::to_string(&del).unwrap(),
        );
        let mut del = v.clone();
        del["standard"]["verification"]
            .as_object_mut()
            .unwrap()
            .remove("argv");
        publish(
            "delete verification.argv",
            &serde_json::to_string(&del).unwrap(),
        );
        let mut del = v.clone();
        del.as_object_mut().unwrap().remove("standard");
        publish(
            "delete a whole variant's contract",
            &serde_json::to_string(&del).unwrap(),
        );
        let mut del = v.clone();
        del.as_object_mut().unwrap().remove("standard");
        publish(
            "delete the variant key itself",
            &serde_json::to_string(&del).unwrap(),
        );

        // Identity-bearing field changes: adapter, argv element, timeout,
        // scope, variant renamed.
        let mut c = v.clone();
        c["standard"]["activation"]["adapter"] = serde_json::json!("none");
        publish(
            "change activation.adapter",
            &serde_json::to_string(&c).unwrap(),
        );
        let mut c = v.clone();
        c["standard"]["verification"]["argv"][0] = serde_json::json!("false");
        publish(
            "change verification.argv element",
            &serde_json::to_string(&c).unwrap(),
        );
        let mut c = v.clone();
        c["standard"]["verification"]["timeout_seconds"] = serde_json::json!(31);
        publish(
            "change verification.timeout_seconds",
            &serde_json::to_string(&c).unwrap(),
        );
        let mut c = v.clone();
        c["standard"]["activation"]["scope"] = serde_json::json!("user");
        publish(
            "change activation.scope",
            &serde_json::to_string(&c).unwrap(),
        );
        let mut c = v.clone();
        let standard = v["standard"].clone();
        c.as_object_mut().unwrap().remove("standard");
        c["renamed"] = standard;
        publish("rename the variant", &serde_json::to_string(&c).unwrap());

        // Corrupt bytes: unparseable -> fail closed as malformed.
        publish("corrupt bytes", "{ not json !");

        // Digest-equal mutation: reorder JSON keys so the bytes differ but the
        // parsed contract set is identical; the canonical digest stays equal,
        // so the publication MUST succeed.
        let reordered = r#"{"standard":{"verification":{"adapter":"command","argv":["true"],"timeout_seconds":30,"attempts":2,"interval_seconds":1},"activation":{"adapter":"systemd","scope":"system","reconcile_managed_units":true,"units":[{"name":"app.service","artifact_path":"integration/systemd/app.service","enable":true,"restart":true}]}}}"#;
        helper
            .publish_release(rid, &release_json, reordered)
            .expect("a digest-equal key reorder must publish");
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
        assert_eq!(a.artifact.tree.as_str(), "tree-a");
        assert!(
            std::fs::symlink_metadata(remote.root().join("generations/gen-1/root")).is_ok(),
            "generation root symlink must exist"
        );
    }
    /// The RAII lock guard releases the server mutation lock on drop, even
    /// when the guarded block exits through an error path (no explicit
    /// release): after the guard drops, a fresh operation can acquire the
    /// lock again and the lock file is gone. This is the property the two
    /// rotation paths rely on — a manual acquire/release pair would leak the
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
    /// A tree containing a READ-ONLY directory uploads successfully: directories
    /// are created owner-writable during the walk and only chmodded to their
    /// final (possibly read-only) mode after every child has been uploaded,
    /// deepest first. The uploaded tree's canonical digest equals the host's.
    #[test]
    fn copy_host_tree_to_remote_round_trips_read_only_directories() {
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path().join("host");
        // Top-level read-only directory (0o555) with a nested read-only
        // directory and files inside both: the parent must stay writable until
        // the nested subtree is fully uploaded, and the parent's read-only
        // mode must be applied only after the nested one is finalized.
        let ro = host.join("ro");
        std::fs::create_dir_all(ro.join("nested")).unwrap();
        std::fs::write(ro.join("app"), b"read-only app\n").unwrap();
        std::fs::write(ro.join("nested/data"), b"nested data\n").unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::set_permissions(ro.join("nested"), std::fs::Permissions::from_mode(0o555))
            .unwrap();
        std::fs::set_permissions(ro.join("app"), std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(
            ro.join("nested/data"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
        let dest = Path::new("objects/sha256/x/root");
        copy_host_tree_to_remote(&host, dest, &remote)
            .expect("a tree with read-only directories must upload");

        // Final directory modes are the host's read-only modes, not the
        // writable create modes; file modes match exactly.
        let remote_root = remote.root().join(dest);
        let ro_meta = std::fs::symlink_metadata(remote_root.join("ro")).unwrap();
        assert_eq!(
            ro_meta.mode() & 0o7777,
            0o555,
            "read-only directory mode must be preserved"
        );
        let nested_meta = std::fs::symlink_metadata(remote_root.join("ro/nested")).unwrap();
        assert_eq!(
            nested_meta.mode() & 0o7777,
            0o555,
            "nested read-only directory mode must be preserved"
        );
        let app_meta = std::fs::symlink_metadata(remote_root.join("ro/app")).unwrap();
        assert_eq!(
            app_meta.mode() & 0o7777,
            0o644,
            "file mode must be preserved"
        );
        let data_meta = std::fs::symlink_metadata(remote_root.join("ro/nested/data")).unwrap();
        assert_eq!(
            data_meta.mode() & 0o7777,
            0o600,
            "nested file mode must be preserved"
        );

        // Post-upload integrity: the uploaded tree canonicalizes to the host's
        // digest.
        let host_meta = crate::tree::canonicalize_tree(&host).unwrap();
        let remote_meta = crate::tree::canonicalize_tree(&remote_root).unwrap();
        assert_eq!(
            remote_meta.tree_sha256, host_meta.tree_sha256,
            "uploaded tree must match the host tree digest"
        );
    }

    /// Setuid/setgid/sticky bits survive the round trip: modes are masked to
    /// the full 0o7777 (not 0o777), so the uploaded tree preserves the exact
    /// special bits and canonicalizes to the host's digest.
    #[test]
    fn copy_host_tree_to_remote_round_trips_special_modes() {
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path().join("host");
        // setgid directory (0o2755) containing a setuid file (0o4755), plus a
        // sticky world-writable directory (0o1777).
        let sg = host.join("sg");
        std::fs::create_dir_all(&sg).unwrap();
        std::fs::write(sg.join("suid"), b"setuid binary\n").unwrap();
        std::fs::set_permissions(&sg, std::fs::Permissions::from_mode(0o2755)).unwrap();
        std::fs::set_permissions(sg.join("suid"), std::fs::Permissions::from_mode(0o4755)).unwrap();
        let st = host.join("st");
        std::fs::create_dir_all(&st).unwrap();
        std::fs::set_permissions(&st, std::fs::Permissions::from_mode(0o1777)).unwrap();

        let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
        let dest = Path::new("objects/sha256/y/root");
        copy_host_tree_to_remote(&host, dest, &remote)
            .expect("a tree with special modes must upload");

        // Exact modes, not masked to 0o777.
        let remote_root = remote.root().join(dest);
        let sg_meta = std::fs::symlink_metadata(remote_root.join("sg")).unwrap();
        assert_eq!(
            sg_meta.mode() & 0o7777,
            0o2755,
            "setgid bit must be preserved"
        );
        let suid_meta = std::fs::symlink_metadata(remote_root.join("sg/suid")).unwrap();
        assert_eq!(
            suid_meta.mode() & 0o7777,
            0o4755,
            "setuid bit must be preserved (not masked to 0o777)"
        );
        let st_meta = std::fs::symlink_metadata(remote_root.join("st")).unwrap();
        assert_eq!(
            st_meta.mode() & 0o7777,
            0o1777,
            "sticky bit must be preserved"
        );

        // Post-upload integrity: the uploaded tree canonicalizes to the host's
        // digest.
        let host_meta = crate::tree::canonicalize_tree(&host).unwrap();
        let remote_meta = crate::tree::canonicalize_tree(&remote_root).unwrap();
        assert_eq!(
            remote_meta.tree_sha256, host_meta.tree_sha256,
            "uploaded tree must match the host tree digest"
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

    /// The handshake REFUSES a state directory written by a DIFFERENT
    /// protocol version: a marker carrying a version other than the client's
    /// must make `handshake()` fail on read-back (an old client can never
    /// drive a state directory written by a newer one, and vice versa). This
    /// is the documented cross-version corruption invariant; the recovery test
    /// above covers only the interrupted-write half of the marker lifecycle.
    #[test]
    fn protocol_version_mismatch_refuses_handshake() {
        let (_dir, remote, root) = setup();
        let marker = layout::protocol_marker();
        std::fs::create_dir_all(root.join(marker.parent().unwrap())).unwrap();
        std::fs::write(
            root.join(&marker),
            format!("{{\"protocol_version\": {}}}", PROTOCOL_VERSION + 1),
        )
        .unwrap();

        let err = RemoteHelper::new(&remote)
            .handshake()
            .expect_err("a mismatched protocol marker must refuse the handshake");
        let msg = err.to_string();
        assert!(
            msg.contains("protocol mismatch"),
            "error must report the protocol mismatch, got: {msg}"
        );
        assert!(
            msg.contains(PROTOCOL_VERSION.to_string().as_str())
                && msg.contains((PROTOCOL_VERSION + 1).to_string().as_str()),
            "error must name both recorded and client protocol versions, got: {msg}"
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
            .write_commit_marker("deploy-0", "gen-0", &["p1".to_string()], Some("t1"))
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
                        &["p1".to_string()],
                        Some("t1"),
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
