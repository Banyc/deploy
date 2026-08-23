//! Filesystem-backed local store.
//!
//! Record contract: `targets/<target>/attempts.jsonl` holds the IMMUTABLE
//! attempt INTENT (persisted before any remote mutation; no status, no
//! outcomes); `deployments/<id>/results.json` holds the per-slot OUTCOMES
//! (written once after the mutation loop); `deployments/<id>/transitions.jsonl`
//! is the append-only STATUS lifecycle (the latest transition is the current
//! status).
//!
//! ```text
//! <base>/
//!   objects/sha256/<digest>/root/ , tree.json
//!   releases/<release-id>/mapping.toml, behavior.json, release.json
//!   targets/<target>/observed.json, attempts.jsonl, refs/last-successful, refs/snapshots.jsonl
//!   servers/<server-id>.json
//!   deployments/<deployment-id>/plan.json, results.json, transitions.jsonl
//! ```

use crate::error::{Error, Result};
use crate::layout;
use crate::model::{
    BehaviorContract, DeploymentId, ReleaseId, ReleaseRecord, TreeDigest, TreeMetadata,
};
use crate::records::{
    DeploymentAttempt, DeploymentResults, DeploymentSnapshot, DeploymentStatus,
    DeploymentTransition, ObservedTarget, ServerState,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[cfg(test)]
use crate::testutil::test_faults;

fn default_base() -> PathBuf {
    let data = std::env::var("XDG_DATA_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOME").ok())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    data.join("simple-deploy")
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::store(format!("mkdir {}: {e}", parent.display())))?;
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| Error::store(format!("serialize {}: {e}", path.display())))?;
    let mut f = std::fs::File::create(path)
        .map_err(|e| Error::store(format!("create {}: {e}", path.display())))?;
    f.write_all(&bytes)
        .map_err(|e| Error::store(format!("write {}: {e}", path.display())))?;
    drop(f);
    set_private(path)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes =
        std::fs::read(path).map_err(|e| Error::store(format!("read {}: {e}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::store(format!("deserialize {}: {e}", path.display())))
}

fn set_private(path: &Path) -> Result<()> {
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)
        .map_err(|e| Error::store(format!("chmod {}: {e}", path.display())))
}

/// Install immutable content-addressed file bytes (release records, mapping,
/// and behavior snapshots) with create-or-compare semantics.
///
/// * If the file does not exist yet, the bytes are written to a temporary file
///   in the same directory and atomically renamed into place, so a reader never
///   observes a partially written snapshot.
/// * If the file already exists, its contents must be byte-identical: an
///   identical rewrite is an idempotent success, and any attempt to replace the
///   existing snapshot with different content fails. Snapshots are bound to
///   release identity by digest; they are never mutable in place.
///
/// Callers serialize writes per store with the application-store lock; the
/// temporary name additionally carries the process id to stay collision-free.
fn write_atomic_cas(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    if path.exists() {
        let existing = std::fs::read(path)
            .map_err(|e| Error::store(format!("read {}: {e}", path.display())))?;
        if existing == bytes {
            return Ok(());
        }
        return Err(Error::store(format!(
            "refusing to replace existing {} with different content",
            path.display()
        )));
    }
    // Durability protocol for immutable records: write + fsync a UNIQUE temp
    // file, install atomically WITHOUT replacement (link(2) fails on EEXIST,
    // so a racing loser can never clobber a winner and no reader ever sees a
    // torn record), unlink the temp name, then fsync the parent directory.
    let tmp = path.with_file_name(format!(
        ".{}.tmp.{}.{}",
        path.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default(),
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed),
    ));
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
    let installed = match std::fs::hard_link(&tmp, path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::store(format!("install {}: {e}", path.display())));
        }
    };
    let _ = std::fs::remove_file(&tmp);
    if !installed {
        // Lost the race: the winner's content must match ours or refuse.
        let existing = std::fs::read(path)
            .map_err(|e| Error::store(format!("read {}: {e}", path.display())))?;
        if existing != bytes {
            return Err(Error::store(format!(
                "refusing to replace existing {} with different content",
                path.display()
            )));
        }
        return Ok(());
    }
    set_private(path)?;
    if let Some(parent) = path.parent()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .map_err(|e| Error::store(format!("mkdir {}: {e}", path.display())))?;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(path, perms)
        .map_err(|e| Error::store(format!("chmod {}: {e}", path.display())))
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
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

pub struct LocalStore {
    base: PathBuf,
}

impl LocalStore {
    /// Create a store rooted at `<data>/simple-deploy/<application>` with private
    /// permissions, creating the directory tree if needed.
    pub fn new(application: &str) -> Result<LocalStore> {
        let base = default_base().join(application);
        Self::with_base(base)
    }

    /// Create a store rooted at an explicit base (used in tests).
    pub fn with_base(base: PathBuf) -> Result<LocalStore> {
        ensure_private_dir(&base)?;
        ensure_private_dir(&base.join(layout::objects()))?;
        ensure_private_dir(&base.join(layout::RELEASES))?;
        ensure_private_dir(&base.join("targets"))?;
        ensure_private_dir(&base.join("servers"))?;
        ensure_private_dir(&base.join("deployments"))?;
        ensure_private_dir(&base.join("staging"))?;
        Ok(LocalStore { base })
    }

    pub fn base(&self) -> &Path {
        &self.base
    }

    pub fn staging_dir(&self) -> PathBuf {
        self.base.join("staging")
    }

    // ---- objects ----------------------------------------------------------

    pub fn object_root(&self, digest: &TreeDigest) -> PathBuf {
        self.base
            .join(layout::objects())
            .join(digest.as_str())
            .join("root")
    }

    pub fn object_tree_json(&self, digest: &TreeDigest) -> PathBuf {
        self.base
            .join(layout::objects())
            .join(digest.as_str())
            .join("tree.json")
    }

    pub fn object_exists(&self, digest: &TreeDigest) -> bool {
        self.object_root(digest).exists()
    }

    /// Store (or reuse) a tree object. Verifies the digest after copy. Reusing an
    /// existing object requires its contents to verify.
    pub fn store_object(&self, digest: &TreeDigest, src_root: &Path) -> Result<()> {
        let root = self.object_root(digest);
        if root.exists() {
            // Verify existing object integrity before reuse.
            let existing = std::fs::read_dir(&root)
                .map_err(|e| Error::integrity(format!("read object {}: {e}", digest.as_str())))?;
            if existing.count() > 0 {
                let meta = crate::tree::canonicalize_tree(&root)?;
                if meta.tree_sha256 != digest.as_str() {
                    return Err(Error::integrity(format!(
                        "existing object {} failed verification",
                        digest.as_str()
                    )));
                }
                return Ok(()); // reuse
            }
        }
        copy_dir_recursive(src_root, &root)?;
        let meta = crate::tree::canonicalize_tree(&root)?;
        if meta.tree_sha256 != digest.as_str() {
            let _ = std::fs::remove_dir_all(&root);
            return Err(Error::integrity(format!(
                "stored object digest mismatch for {}",
                digest.as_str()
            )));
        }
        write_atomic_cas(
            &self.object_tree_json(digest),
            &serde_json::to_vec(&meta)
                .map_err(|e| Error::store(format!("serialize tree.json: {e}")))?,
        )?;
        Ok(())
    }

    pub fn read_tree_meta(&self, digest: &TreeDigest) -> Result<TreeMetadata> {
        read_json(&self.object_tree_json(digest))
    }

    // ---- releases ---------------------------------------------------------

    pub fn release_dir(&self, id: &ReleaseId) -> PathBuf {
        self.base.join(layout::RELEASES).join(sanitize(id.as_str()))
    }

    pub fn release_exists(&self, id: &ReleaseId) -> bool {
        self.release_dir(id).join("release.json").exists()
    }

    /// Write an immutable release record. Replacing an existing ID with
    /// different content fails.
    pub fn write_release(&self, rec: &ReleaseRecord) -> Result<()> {
        let dir = self.release_dir(&ReleaseId::new(rec.release_id.clone()));
        if dir.exists() {
            let existing: ReleaseRecord = read_json(&dir.join("release.json"))?;
            if existing.release_sha256 != rec.release_sha256 {
                return Err(Error::store(format!(
                    "release {} already exists with different content",
                    rec.release_id
                )));
            }
            return Ok(()); // idempotent
        }
        ensure_private_dir(&dir)?;
        let bytes = serde_json::to_vec_pretty(rec)
            .map_err(|e| Error::store(format!("serialize release: {e}")))?;
        write_atomic_cas(&dir.join("release.json"), &bytes)
    }

    pub fn read_release(&self, id: &ReleaseId) -> Result<ReleaseRecord> {
        read_json(&self.release_dir(id).join("release.json"))
    }

    pub fn write_release_aux(
        &self,
        id: &ReleaseId,
        mapping_toml: &str,
        behavior_json: &serde_json::Value,
    ) -> Result<()> {
        let dir = self.release_dir(id);
        ensure_private_dir(&dir)?;
        write_atomic_cas(&dir.join("mapping.toml"), mapping_toml.as_bytes())?;
        let bytes = serde_json::to_vec_pretty(behavior_json)
            .map_err(|e| Error::store(format!("serialize behavior: {e}")))?;
        write_atomic_cas(&dir.join("behavior.json"), &bytes)?;
        Ok(())
    }

    /// Read the name-keyed per-variant behavior contracts stored alongside a
    /// release record.
    pub fn read_release_behaviors(
        &self,
        id: &ReleaseId,
    ) -> Result<BTreeMap<String, BehaviorContract>> {
        let p = self.release_dir(id).join("behavior.json");
        let bytes = std::fs::read(&p)
            .map_err(|e| Error::store(format!("read behavior {}: {e}", p.display())))?;
        crate::release::behavior_contracts_from_json(&bytes)
            .map_err(|e| Error::store(format!("parse behavior {}: {e}", p.display())))
    }

    // ---- targets ----------------------------------------------------------

    pub fn target_dir(&self, target: &str) -> PathBuf {
        self.base.join("targets").join(sanitize(target))
    }

    pub fn write_observed(&self, target: &str, observed: &ObservedTarget) -> Result<()> {
        let dir = self.target_dir(target);
        ensure_private_dir(&dir)?;
        write_json(&dir.join("observed.json"), observed)
    }

    pub fn read_observed(&self, target: &str) -> Result<ObservedTarget> {
        let p = self.target_dir(target).join("observed.json");
        if p.exists() {
            read_json(&p)
        } else {
            Ok(ObservedTarget {
                target: crate::model::TargetName::new(target.to_string()),
                slots: Default::default(),
            })
        }
    }

    pub fn append_attempt(&self, target: &str, attempt: &DeploymentAttempt) -> Result<()> {
        #[cfg(test)]
        if test_faults::consume(
            &test_faults::FAIL_APPEND_ATTEMPT,
            attempt.deployment_id.as_str(),
        ) {
            return Err(Error::store(
                "test fault: append_attempt forced to fail once",
            ));
        }
        let dir = self.target_dir(target);
        ensure_private_dir(&dir)?;
        let p = dir.join("attempts.jsonl");
        let mut f = if p.exists() {
            std::fs::OpenOptions::new().append(true).open(&p)
        } else {
            std::fs::File::create(&p)
        }
        .map_err(|e| Error::store(format!("open attempts: {e}")))?;
        let line = serde_json::to_string(attempt)
            .map_err(|e| Error::store(format!("serialize attempt: {e}")))?;
        writeln!(f, "{line}").map_err(|e| Error::store(format!("write attempt: {e}")))?;
        drop(f);
        set_private(&p)
    }

    pub fn read_attempts(&self, target: &str) -> Result<Vec<DeploymentAttempt>> {
        let p = self.target_dir(target).join("attempts.jsonl");
        if !p.exists() {
            return Ok(vec![]);
        }
        let text =
            std::fs::read_to_string(&p).map_err(|e| Error::store(format!("read attempts: {e}")))?;
        let mut out = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            out.push(
                serde_json::from_str::<DeploymentAttempt>(line)
                    .map_err(|e| Error::store(format!("parse attempt: {e}")))?,
            );
        }
        Ok(out)
    }

    // ---- rollback snapshots (refs) --------------------------------------

    fn refs_dir(&self, target: &str) -> PathBuf {
        self.target_dir(target).join("refs")
    }

    pub fn write_last_successful(&self, target: &str, deployment_id: &str) -> Result<()> {
        #[cfg(test)]
        if test_faults::consume(&test_faults::FAIL_WRITE_LAST_SUCCESSFUL, deployment_id) {
            return Err(Error::store(
                "test fault: write_last_successful forced to fail once",
            ));
        }
        let dir = self.refs_dir(target);
        ensure_private_dir(&dir)?;
        let p = dir.join("last-successful");
        std::fs::write(&p, deployment_id)
            .map_err(|e| Error::store(format!("write last-successful: {e}")))?;
        set_private(&p)
    }

    pub fn read_last_successful(&self, target: &str) -> Option<String> {
        let p = self.refs_dir(target).join("last-successful");
        std::fs::read_to_string(p)
            .ok()
            .filter(|s| !s.trim().is_empty())
    }

    /// Append a terminal successful fleet snapshot (`refs/snapshots.jsonl`),
    /// one JSON line per entry. Snapshots are the immutable rollback source
    /// (`<target>@fN`); only successful deployments produce them.
    pub fn append_snapshot(&self, target: &str, entry: &DeploymentSnapshot) -> Result<()> {
        #[cfg(test)]
        if test_faults::consume(
            &test_faults::FAIL_APPEND_SNAPSHOT,
            entry.deployment_id.as_str(),
        ) {
            return Err(Error::store(
                "test fault: append_snapshot forced to fail once",
            ));
        }
        let dir = self.refs_dir(target);
        ensure_private_dir(&dir)?;
        let p = dir.join("snapshots.jsonl");
        let mut f = if p.exists() {
            std::fs::OpenOptions::new().append(true).open(&p)
        } else {
            std::fs::File::create(&p)
        }
        .map_err(|e| Error::store(format!("open snapshots: {e}")))?;
        let line = serde_json::to_string(entry)
            .map_err(|e| Error::store(format!("serialize snapshot: {e}")))?;
        writeln!(f, "{line}").map_err(|e| Error::store(format!("write snapshot: {e}")))?;
        drop(f);
        set_private(&p)
    }

    pub fn read_snapshots(&self, target: &str) -> Result<Vec<DeploymentSnapshot>> {
        let p = self.refs_dir(target).join("snapshots.jsonl");
        if !p.exists() {
            return Ok(vec![]);
        }
        let text = std::fs::read_to_string(&p)
            .map_err(|e| Error::store(format!("read snapshots: {e}")))?;
        let mut out = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            out.push(
                serde_json::from_str::<DeploymentSnapshot>(line)
                    .map_err(|e| Error::store(format!("parse snapshot: {e}")))?,
            );
        }
        Ok(out)
    }

    // ---- servers ----------------------------------------------------------

    pub fn write_server(&self, state: &ServerState) -> Result<()> {
        let p = self
            .base
            .join("servers")
            .join(format!("{}.json", sanitize(state.id.as_str())));
        write_json(&p, state)
    }

    pub fn read_server(&self, id: &str) -> Result<ServerState> {
        let p = self
            .base
            .join("servers")
            .join(format!("{id}.json", id = sanitize(id)));
        read_json(&p)
    }

    pub fn server_exists(&self, id: &str) -> bool {
        self.base
            .join("servers")
            .join(format!("{}.json", sanitize(id)))
            .exists()
    }

    // ---- deployments ------------------------------------------------------

    pub fn deployment_dir(&self, id: &str) -> PathBuf {
        self.base.join("deployments").join(sanitize(id))
    }

    pub fn write_plan<T: Serialize>(&self, id: &str, plan: &T) -> Result<()> {
        let dir = self.deployment_dir(id);
        ensure_private_dir(&dir)?;
        // The recorded plan of an attempt is immutable: deployment IDs are
        // unique, so a conflicting same-ID rewrite is corruption and must fail
        // rather than silently rewrite history.
        let bytes = serde_json::to_vec_pretty(plan)
            .map_err(|e| Error::store(format!("serialize plan: {e}")))?;
        write_atomic_cas(&dir.join("plan.json"), &bytes)
    }

    pub fn write_results(&self, id: &str, results: &DeploymentResults) -> Result<()> {
        #[cfg(test)]
        if test_faults::consume(&test_faults::FAIL_WRITE_RESULTS, id) {
            return Err(Error::store(
                "test fault: write_results forced to fail once",
            ));
        }
        let dir = self.deployment_dir(id);
        ensure_private_dir(&dir)?;
        // Same immutability rule as the plan: recorded once per deployment ID.
        let bytes = serde_json::to_vec_pretty(results)
            .map_err(|e| Error::store(format!("serialize results: {e}")))?;
        write_atomic_cas(&dir.join("results.json"), &bytes)
    }

    pub fn read_results(&self, id: &str) -> Result<DeploymentResults> {
        let p = self.deployment_dir(id).join("results.json");
        read_json(&p)
    }

    /// Append one status event to the deployment's append-only transition
    /// stream (`deployments/<id>/transitions.jsonl`). The current status of a
    /// deployment is the LATEST transition; this replaces the old single
    /// mutable `deployments/<id>/status` file. `reason` carries optional
    /// human context (e.g. "recovery finalization", "metadata phase
    /// interrupted").
    pub fn append_transition(
        &self,
        id: &str,
        status: &DeploymentStatus,
        reason: Option<&str>,
    ) -> Result<()> {
        #[cfg(test)]
        if test_faults::consume(&test_faults::FAIL_APPEND_TRANSITION, id) {
            return Err(Error::store(
                "test fault: append_transition forced to fail once",
            ));
        }
        #[cfg(test)]
        if status == &DeploymentStatus::Successful
            && test_faults::consume(&test_faults::FAIL_APPEND_TRANSITION_SUCCESSFUL, id)
        {
            return Err(Error::store(
                "test fault: append_transition(Successful) forced to fail once",
            ));
        }
        #[cfg(test)]
        if status == &DeploymentStatus::PendingCommit
            && test_faults::consume(&test_faults::FAIL_APPEND_TRANSITION_PENDING, id)
        {
            return Err(Error::store(
                "test fault: append_transition(PendingCommit) forced to fail once",
            ));
        }
        let dir = self.deployment_dir(id);
        ensure_private_dir(&dir)?;
        let p = dir.join("transitions.jsonl");
        let transition = DeploymentTransition {
            deployment_id: DeploymentId::new(id.to_string()),
            status: status.clone(),
            recorded_at: crate::remote::helper::now_rfc3339(),
            reason: reason.map(str::to_string),
        };
        let mut f = if p.exists() {
            std::fs::OpenOptions::new().append(true).open(&p)
        } else {
            std::fs::File::create(&p)
        }
        .map_err(|e| Error::store(format!("open transitions: {e}")))?;
        let line = serde_json::to_string(&transition)
            .map_err(|e| Error::store(format!("serialize transition: {e}")))?;
        writeln!(f, "{line}").map_err(|e| Error::store(format!("write transition: {e}")))?;
        drop(f);
        set_private(&p)
    }

    /// Read the full append-only transition stream for a deployment.
    pub fn read_transitions(&self, id: &str) -> Result<Vec<DeploymentTransition>> {
        let p = self.deployment_dir(id).join("transitions.jsonl");
        if !p.exists() {
            return Ok(vec![]);
        }
        let text = std::fs::read_to_string(&p)
            .map_err(|e| Error::store(format!("read transitions: {e}")))?;
        let mut out = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            out.push(
                serde_json::from_str::<DeploymentTransition>(line)
                    .map_err(|e| Error::store(format!("parse transition: {e}")))?,
            );
        }
        Ok(out)
    }

    /// The latest transition of a deployment, or `None` when no transition
    /// has been recorded yet.
    pub fn latest_transition(&self, id: &str) -> Result<Option<DeploymentTransition>> {
        Ok(self.read_transitions(id)?.pop())
    }

    /// The current status of a deployment: the status of its LATEST
    /// transition, or `None` when no transition has been recorded yet.
    pub fn latest_status(&self, id: &str) -> Result<Option<DeploymentStatus>> {
        Ok(self.latest_transition(id)?.map(|t| t.status))
    }
}
/// Sanitize a name for use as a directory/file component.
pub fn sanitize(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push('_');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DeploymentId, TargetName};

    #[test]
    fn release_aux_snapshots_are_immutable_and_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let id = ReleaseId::new("rel-sha256-aa".to_string());
        let behavior = serde_json::json!({
            "standard": {
                "activation": {
                    "adapter": "none",
                    "scope": "user",
                    "reconcile_managed_units": true,
                    "units": []
                },
                "verification": {
                    "adapter": "command",
                    "argv": ["true"],
                    "timeout_seconds": 5,
                    "attempts": 1,
                    "interval_seconds": 0
                }
            }
        });

        store
            .write_release_aux(&id, "mapping", &behavior)
            .expect("first write creates the snapshot");

        // Identical rewrite is an idempotent success.
        store
            .write_release_aux(&id, "mapping", &behavior)
            .expect("identical rewrite must succeed");

        // Replacing the behavior snapshot with different content fails...
        let conflicting = serde_json::json!({
            "standard": {
                "activation": { "adapter": "systemd", "scope": "user", "reconcile_managed_units": true, "units": [] },
                "verification": {
                    "adapter": "command",
                    "argv": ["true"],
                    "timeout_seconds": 5,
                    "attempts": 1,
                    "interval_seconds": 0
                }
            }
        });
        let err = store
            .write_release_aux(&id, "mapping", &conflicting)
            .expect_err("conflicting rewrite must fail");
        assert!(
            err.to_string().contains("different content"),
            "error must name the immutability violation, got: {err}"
        );

        // ...and the stored snapshot is untouched (no torn write).
        let read = store.read_release_behaviors(&id).expect("snapshot exists");
        assert_eq!(read["standard"].activation.adapter, "none");
    }

    /// A recorded attempt's plan and results are immutable: deployment IDs are
    /// unique, so a same-ID rewrite with different content is corruption and
    /// must fail instead of silently rewriting history.
    #[test]
    fn recorded_plan_and_results_are_immutable() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        let plan = serde_json::json!({ "target": "t1" });
        store
            .write_plan("deploy-1", &plan)
            .expect("first plan write");
        store
            .write_plan("deploy-1", &plan)
            .expect("identical rewrite is idempotent");
        let err = store
            .write_plan("deploy-1", &serde_json::json!({ "target": "t2" }))
            .expect_err("conflicting plan rewrite must fail");
        assert!(err.to_string().contains("different content"));

        let results = DeploymentResults {
            deployment_id: DeploymentId::from("deploy-1".to_string()),
            target: TargetName::from("t1".to_string()),
            slots: Default::default(),
        };
        store
            .write_results("deploy-1", &results)
            .expect("first results");
        let conflicting = DeploymentResults {
            deployment_id: DeploymentId::from("deploy-1".to_string()),
            target: TargetName::from("t2".to_string()),
            slots: Default::default(),
        };
        assert!(store.write_results("deploy-1", &conflicting).is_err());
    }

    /// The one-shot intent/outcomes faults are deployment-id keyed and
    /// status-qualified: `arm_append_attempt` fails the NEXT `append_attempt`
    /// for that id exactly once; `arm_write_results` fails the next
    /// `write_results`; `arm_append_transition_pending` fails ONLY the first
    /// `PendingCommit` transition append (the recoverable finalize marker) —
    /// an earlier `InProgress` (or any other status) append passes through.
    #[test]
    fn new_fault_arms_are_one_shot_and_status_qualified() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        let id = "deploy-fault-arms";
        let attempt = DeploymentAttempt {
            deployment_schema_version: 2,
            deployment_id: DeploymentId::new(id.to_string()),
            target: TargetName::new(target.to_string()),
            slot_ids: vec![],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        };

        // arm_append_attempt: one-shot, fails once, then passes.
        test_faults::arm_append_attempt(id);
        let err = store.append_attempt(target, &attempt).unwrap_err();
        assert!(err.to_string().contains("append_attempt"));
        store.append_attempt(target, &attempt).expect("disarmed");

        // arm_write_results: one-shot.
        test_faults::arm_write_results(id);
        let results = DeploymentResults {
            deployment_id: DeploymentId::from(id.to_string()),
            target: TargetName::from(target.to_string()),
            slots: Default::default(),
        };
        let err = store.write_results(id, &results).unwrap_err();
        assert!(err.to_string().contains("write_results"));
        store.write_results(id, &results).expect("disarmed");

        // arm_append_transition_pending: status-qualified — an InProgress
        // append passes through; the first PendingCommit append fails once.
        test_faults::arm_append_transition_pending(id);
        store
            .append_transition(id, &DeploymentStatus::InProgress, Some("attempt started"))
            .expect("InProgress append passes through untouched");
        let err = store
            .append_transition(
                id,
                &DeploymentStatus::PendingCommit,
                Some("finalization started"),
            )
            .unwrap_err();
        assert!(err.to_string().contains("append_transition"));
        store
            .append_transition(id, &DeploymentStatus::PendingCommit, None)
            .expect("disarmed");
    }

    /// The transition stream is append-only JSONL: every appended event is
    /// preserved in order, the LATEST event is the deployment's current
    /// status, and the `reason` is carried (or omitted) as recorded.
    #[test]
    fn transition_stream_is_append_only_and_latest_wins() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let id = "deploy-transitions";

        assert_eq!(store.latest_status(id).unwrap(), None, "no transitions yet");
        assert_eq!(store.read_transitions(id).unwrap().len(), 0);

        store
            .append_transition(id, &DeploymentStatus::InProgress, Some("attempt started"))
            .unwrap();
        store
            .append_transition(id, &DeploymentStatus::Successful, None)
            .unwrap();

        // Append-only: both events survive, in order.
        let transitions = store.read_transitions(id).unwrap();
        assert_eq!(transitions.len(), 2);
        assert_eq!(transitions[0].status, DeploymentStatus::InProgress);
        assert_eq!(transitions[0].reason.as_deref(), Some("attempt started"));
        assert_eq!(transitions[1].status, DeploymentStatus::Successful);
        assert_eq!(transitions[1].reason, None);
        assert_eq!(
            transitions[0].deployment_id,
            DeploymentId::new(id.to_string())
        );
        assert!(!transitions[1].recorded_at.is_empty());

        // Latest transition wins: an append overlays, never rewrites history.
        assert_eq!(
            store.latest_status(id).unwrap(),
            Some(DeploymentStatus::Successful)
        );
        store
            .append_transition(
                id,
                &DeploymentStatus::Degraded,
                Some("marker integrity conflict"),
            )
            .unwrap();
        assert_eq!(
            store.latest_status(id).unwrap(),
            Some(DeploymentStatus::Degraded)
        );
        assert_eq!(store.read_transitions(id).unwrap().len(), 3);
    }

    /// The attempts stream is append-only: appending a SECOND record with the
    /// SAME deployment id (the engine never does — ids are minted fresh)
    /// appends rather than replacing, so the log always preserves every
    /// recorded intent. Deployment IDs are unique by construction, so the
    /// duplicate case exercises corruption-tolerant append semantics, not a
    /// rewrite.
    #[test]
    fn attempts_stream_is_append_only_for_duplicate_ids() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        let attempt = DeploymentAttempt {
            deployment_schema_version: 2,
            deployment_id: DeploymentId::new("deploy-dup".to_string()),
            target: TargetName::new(target.to_string()),
            slot_ids: vec![],
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            desired: BTreeMap::new(),
            pre_push: BTreeMap::new(),
            slots: BTreeMap::new(),
        };
        store.append_attempt(target, &attempt).unwrap();
        let second = DeploymentAttempt {
            attempted_at: "2026-01-02T00:00:00Z".to_string(),
            ..attempt.clone()
        };
        store.append_attempt(target, &second).unwrap();

        let attempts = store.read_attempts(target).unwrap();
        assert_eq!(
            attempts.len(),
            2,
            "append-only: a duplicate id appends a second record, never replaces"
        );
        assert_eq!(attempts[0].deployment_id, attempts[1].deployment_id);
        assert_eq!(attempts[0].attempted_at, "2026-01-01T00:00:00Z");
        assert_eq!(attempts[1].attempted_at, "2026-01-02T00:00:00Z");
    }

    /// `arm_append_transition_successful` is status-qualified and one-shot:
    /// non-`Successful` appends (the recoverable `PendingCommit` marker, an
    /// `InProgress` overlay) pass through untouched, the FIRST `Successful`
    /// append fails, and a later `Successful` append passes.
    #[test]
    fn transition_successful_fault_is_status_qualified_and_one_shot() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let id = "deploy-txn-success-fault";

        test_faults::arm_append_transition_successful(id);
        // The recoverable finalize marker passes through (status-qualified).
        store
            .append_transition(
                id,
                &DeploymentStatus::PendingCommit,
                Some("finalization started"),
            )
            .expect("PendingCommit append passes through untouched");
        // The FIRST Successful append fires the fault.
        let err = store
            .append_transition(id, &DeploymentStatus::Successful, None)
            .unwrap_err();
        assert!(err.to_string().contains("append_transition"));
        // A later Successful append passes (one-shot, disarmed).
        store
            .append_transition(id, &DeploymentStatus::Successful, None)
            .expect("disarmed");

        // Re-arm: an InProgress overlay must not consume the arm.
        test_faults::arm_append_transition_successful(id);
        store
            .append_transition(id, &DeploymentStatus::InProgress, None)
            .expect("InProgress append does not consume the arm");
        store
            .append_transition(id, &DeploymentStatus::Successful, None)
            .expect_err("first Successful append fires again");
        store
            .append_transition(id, &DeploymentStatus::Successful, None)
            .expect("disarmed again");
    }
}
