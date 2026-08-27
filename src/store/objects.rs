//! The content-addressed object store (A3): tree objects under
//! `objects/sha256/<digest>/root/` + `tree.json`, with store-or-reuse,
//! read-time verification, and digest-bound tree metadata reads — plus the
//! A3 local-object recovery ([`LocalStore::recover_if_missing`]: download a
//! missing digest from a retaining server).

use crate::error::{Error, Result};
use crate::identity::{TreeDigest, TreeMetadata};
use crate::remote::canonical::TREE_SCHEMA_VERSION;
use crate::remote::layout;
use crate::remote::transport::Remote;
use crate::store::atomic::{copy_dir_recursive, read_json};
use crate::store::local::{LocalStore, write_atomic_cas};
use std::path::{Path, PathBuf};

impl LocalStore {
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

    /// A3 local object recovery: download a tree from a retaining server into
    /// the local object store if the digest is missing locally. The remote
    /// tree (`objects/sha256/<digest>/root/` on the server) is the source of
    /// truth for a digest the local store never saw (e.g. a rollback to a
    /// generation whose tree was never materialized locally); when the server
    /// no longer retains it either, recovery is a no-op and the later
    /// verification/staging steps surface the missing tree.
    pub fn recover_if_missing(&self, remote: &dyn Remote, digest: &TreeDigest) -> Result<()> {
        if self.object_exists(digest) {
            return Ok(());
        }
        let root_rel = layout::tree_root(digest.as_str());
        if !remote.exists(&root_rel) {
            return Ok(());
        }
        let tmp = self
            .staging_dir()
            .join(format!("recover-{}", digest.as_str()));
        // A stale `recover-<digest>` dir can survive an interrupted earlier
        // recovery, and downloaded trees carry remote file modes (read-only
        // dirs/files), so removal can fail with EACCES. Removal is EXPLICIT and
        // FALLIBLE: restore owner-write inside the stale tree, then remove it. A
        // stale temp that cannot be removed aborts the recovery loudly instead of
        // letting `download_tree_to_host` write INTO the stale dir and
        // `store.store_object` persist a mixed (stale leftovers + fresh content)
        // tree under the digest. A missing temp is a no-op.
        if tmp.exists() {
            crate::deploy::staging::remove_tree_restoring_write(
                &tmp,
                "remove stale recovery temp",
            )?;
        }
        crate::deploy::server::download_tree_to_host(remote, &root_rel, &tmp)?;
        self.store_object(digest, &tmp)?;
        // Explicit FALLIBLE cleanup of the disposable download temp before
        // returning, so a successful recovery never leaves `recover-<digest>`
        // behind (a leftover that a later recovery would treat as stale and that
        // could accumulate read-only content). `store_object` copies, so the temp
        // is no longer needed; a cleanup failure surfaces as an error naming the
        // path, mirroring the dry-run staging cleanup.
        crate::deploy::staging::remove_tree_restoring_write(&tmp, "remove recovery temp")?;
        Ok(())
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
                let meta = crate::remote::canonical::canonicalize_tree(&root)?;
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
        let meta = crate::remote::canonical::canonicalize_tree(&root)?;
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
        let meta: TreeMetadata = read_json(&self.object_tree_json(digest))?;
        // Fail closed on the tree metadata format version: only
        // `TREE_SCHEMA_VERSION` is accepted, any other version is refused
        // (a tree.json written by a different schema is never interpreted).
        if meta.tree_schema_version != TREE_SCHEMA_VERSION {
            return Err(Error::integrity(format!(
                "tree {} carries unsupported tree_schema_version {} (expected {TREE_SCHEMA_VERSION}): only TREE_SCHEMA_VERSION is accepted",
                digest.as_str(),
                meta.tree_schema_version
            )));
        }
        Ok(meta)
    }
}
