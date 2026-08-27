//! The content-addressed object store (A3): tree objects under
//! `objects/sha256/<digest>/root/` + `tree.json`, with store-or-reuse,
//! read-time verification, and digest-bound tree metadata reads.

use crate::error::{Error, Result};
use crate::identity::{TreeDigest, TreeMetadata};
use crate::remote::canonical::TREE_SCHEMA_VERSION;
use crate::remote::layout;
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
