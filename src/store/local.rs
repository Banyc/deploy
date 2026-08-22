//! Filesystem-backed local store.
//!
//! ```text
//! <base>/
//!   objects/sha256/<digest>/root/ , tree.json
//!   releases/<release-id>/mapping.toml, behavior.json, policies.json, release.json
//!   targets/<target>/observed.json, attempts.jsonl, refs/last-successful, refs/reflog.jsonl
//!   servers/<server-id>.json
//!   deployments/<deployment-id>/plan.json, results.json, status
//! ```

use crate::config::VariantPolicy;
use crate::error::{Error, Result};
use crate::model::{BehaviorContract, ReleaseId, ReleaseRecord, TreeDigest, TreeMetadata};
use crate::records::{AttemptRecord, DeploymentResults, ObservedTarget, ReflogEntry, ServerState};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

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
/// behavior, and policy snapshots) with create-or-compare semantics.
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
    let mut tmp_name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    let tmp = path.with_file_name(tmp_name);
    let _ = std::fs::remove_file(&tmp);
    {
        let mut f = std::fs::File::create(&tmp)
            .map_err(|e| Error::store(format!("create {}: {e}", tmp.display())))?;
        f.write_all(bytes)
            .map_err(|e| Error::store(format!("write {}: {e}", tmp.display())))?;
    }
    set_private(&tmp)?;
    std::fs::rename(&tmp, path)
        .map_err(|e| Error::store(format!("rename {}: {e}", path.display())))?;
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
        ensure_private_dir(&base.join("objects/sha256"))?;
        ensure_private_dir(&base.join("releases"))?;
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
            .join("objects/sha256")
            .join(digest.as_str())
            .join("root")
    }

    pub fn object_tree_json(&self, digest: &TreeDigest) -> PathBuf {
        self.base
            .join("objects/sha256")
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
        write_json(&self.object_tree_json(digest), &meta)?;
        Ok(())
    }

    pub fn read_tree_meta(&self, digest: &TreeDigest) -> Result<TreeMetadata> {
        read_json(&self.object_tree_json(digest))
    }

    // ---- releases ---------------------------------------------------------

    pub fn release_dir(&self, id: &ReleaseId) -> PathBuf {
        self.base.join("releases").join(sanitize(id.as_str()))
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
        policies_json: &serde_json::Value,
    ) -> Result<()> {
        let dir = self.release_dir(id);
        ensure_private_dir(&dir)?;
        write_atomic_cas(&dir.join("mapping.toml"), mapping_toml.as_bytes())?;
        let bytes = serde_json::to_vec_pretty(behavior_json)
            .map_err(|e| Error::store(format!("serialize behavior: {e}")))?;
        write_atomic_cas(&dir.join("behavior.json"), &bytes)?;
        // Persist each variant's capacity policy with the release. A historical
        // deployment must resolve it from this snapshot, because the caller's
        // current configuration may have renamed or removed the variant since
        // the release was created. The snapshot is immutable (create-or-compare
        // via `write_atomic_cas`) and its canonical digest is part of the
        // release identity, so it can never be rewritten in place. (Rotation is
        // target-level configuration and is not part of the snapshot.)
        let bytes = serde_json::to_vec_pretty(policies_json)
            .map_err(|e| Error::store(format!("serialize policies: {e}")))?;
        write_atomic_cas(&dir.join("policies.json"), &bytes)?;
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

    /// Read the name-keyed per-variant capacity policies stored alongside a
    /// release record. Returns `None` when the release predates
    /// policy persistence; callers then fall back to the current configuration
    /// for variants that still exist there.
    pub fn read_release_policies(
        &self,
        id: &ReleaseId,
    ) -> Result<Option<BTreeMap<String, VariantPolicy>>> {
        let p = self.release_dir(id).join("policies.json");
        if !p.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&p)
            .map_err(|e| Error::store(format!("read policies {}: {e}", p.display())))?;
        let map = crate::release::variant_policies_from_json(&bytes)
            .map_err(|e| Error::store(format!("parse policies {}: {e}", p.display())))?;
        Ok(Some(map))
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
                servers: Default::default(),
            })
        }
    }

    pub fn append_attempt(&self, target: &str, attempt: &AttemptRecord) -> Result<()> {
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

    pub fn read_attempts(&self, target: &str) -> Result<Vec<AttemptRecord>> {
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
                serde_json::from_str::<AttemptRecord>(line)
                    .map_err(|e| Error::store(format!("parse attempt: {e}")))?,
            );
        }
        Ok(out)
    }

    // ---- refs -------------------------------------------------------------

    fn refs_dir(&self, target: &str) -> PathBuf {
        self.target_dir(target).join("refs")
    }

    pub fn write_last_successful(&self, target: &str, deployment_id: &str) -> Result<()> {
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

    pub fn append_reflog(&self, target: &str, entry: &ReflogEntry) -> Result<()> {
        let dir = self.refs_dir(target);
        ensure_private_dir(&dir)?;
        let p = dir.join("reflog.jsonl");
        let mut f = if p.exists() {
            std::fs::OpenOptions::new().append(true).open(&p)
        } else {
            std::fs::File::create(&p)
        }
        .map_err(|e| Error::store(format!("open reflog: {e}")))?;
        let line = serde_json::to_string(entry)
            .map_err(|e| Error::store(format!("serialize reflog: {e}")))?;
        writeln!(f, "{line}").map_err(|e| Error::store(format!("write reflog: {e}")))?;
        drop(f);
        set_private(&p)
    }

    pub fn read_reflog(&self, target: &str) -> Result<Vec<ReflogEntry>> {
        let p = self.refs_dir(target).join("reflog.jsonl");
        if !p.exists() {
            return Ok(vec![]);
        }
        let text =
            std::fs::read_to_string(&p).map_err(|e| Error::store(format!("read reflog: {e}")))?;
        let mut out = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            out.push(
                serde_json::from_str::<ReflogEntry>(line)
                    .map_err(|e| Error::store(format!("parse reflog: {e}")))?,
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
        write_json(&dir.join("plan.json"), plan)
    }

    pub fn write_results(&self, id: &str, results: &DeploymentResults) -> Result<()> {
        let dir = self.deployment_dir(id);
        ensure_private_dir(&dir)?;
        write_json(&dir.join("results.json"), results)
    }

    pub fn read_results(&self, id: &str) -> Result<DeploymentResults> {
        let p = self.deployment_dir(id).join("results.json");
        read_json(&p)
    }

    pub fn write_status(&self, id: &str, status: &str) -> Result<()> {
        let dir = self.deployment_dir(id);
        ensure_private_dir(&dir)?;
        let p = dir.join("status");
        std::fs::write(&p, status).map_err(|e| Error::store(format!("write status: {e}")))?;
        set_private(&p)
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

    #[test]
    fn release_aux_snapshots_are_immutable_and_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let id = ReleaseId::new("rel-sha256-aa".to_string());
        let behavior = serde_json::json!({});
        let policies = serde_json::json!({
            "standard": { "capacity": { "reserve_bytes": 1, "reserve_percent": 0 } }
        });

        store
            .write_release_aux(&id, "mapping", &behavior, &policies)
            .expect("first write creates the snapshot");

        // Identical rewrite is an idempotent success.
        store
            .write_release_aux(&id, "mapping", &behavior, &policies)
            .expect("identical rewrite must succeed");

        // Replacing the policy snapshot with different content fails...
        let conflicting = serde_json::json!({
            "standard": { "capacity": { "reserve_bytes": 2, "reserve_percent": 0 } }
        });
        let err = store
            .write_release_aux(&id, "mapping", &behavior, &conflicting)
            .expect_err("conflicting rewrite must fail");
        assert!(
            err.to_string().contains("different content"),
            "error must name the immutability violation, got: {err}"
        );

        // ...and the stored snapshot is untouched (no torn write).
        let read = store
            .read_release_policies(&id)
            .unwrap()
            .expect("snapshot exists");
        assert_eq!(read["standard"].capacity.reserve_bytes, 1);
    }
}
