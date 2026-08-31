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
use crate::store::atomic::{
    copy_dir_recursive, fsync_tree_recursive, path_state, read_json, sync_parent_dir, temp_name_for,
};
use crate::store::local::{LocalStore, read_keyed_json};
use std::path::{Path, PathBuf};

#[cfg(test)]
use crate::testutil::test_faults::FaultKind;

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
        let root_rel = layout::tree_root(digest);
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
            crate::deploy::plan::remove_tree_restoring_write(&tmp, "remove stale recovery temp")?;
        }
        crate::deploy::rollout::download_tree_to_host(remote, &root_rel, &tmp)?;
        self.store_object(digest, &tmp)?;
        // Explicit FALLIBLE cleanup of the disposable download temp before
        // returning, so a successful recovery never leaves `recover-<digest>`
        // behind (a leftover that a later recovery would treat as stale and that
        // could accumulate read-only content). `store_object` copies, so the temp
        // is no longer needed; a cleanup failure surfaces as an error naming the
        // path, mirroring the dry-run staging cleanup.
        crate::deploy::plan::remove_tree_restoring_write(&tmp, "remove recovery temp")?;
        Ok(())
    }

    /// Store (or reuse) a tree object. Verifies the digest after copy. Reusing an
    /// existing object requires its contents to verify.
    ///
    /// # The staged-tree publish protocol (crash consistency)
    ///
    /// The COMPLETE object — the `root/` tree AND its `tree.json` metadata —
    /// is built in a UNIQUE staging directory (a dot-prefixed sibling of the
    /// final `objects/sha256/<digest>/` location, never the final dir), the
    /// whole staged tree is VERIFIED (the root canonicalizes to the digest
    /// and the metadata parses) and RECURSIVELY FSYNCED, then the staging
    /// dir is ATOMICALLY RENAMED into the final location, and the PARENT
    /// directory is fsynced. A crash at any pre-rename stage leaves the
    /// final location WHOLLY ABSENT (at most a disposable dot-prefixed
    /// staging dir, invisible to every read and swept as unreachable); a
    /// crash after the rename leaves it WHOLLY PRESENT. The final location
    /// is NEVER partial — a retry after a crash re-stages cleanly and never
    /// finds a torn object to refuse.
    ///
    /// REUSE verifies the WHOLE object (root + metadata). A present final
    /// object that does NOT verify is not a valid object at all — a legacy
    /// partial from the pre-staged protocol, or garbage — and is REPAIRED:
    /// removed and re-staged, never refused (the content-addressed store's
    /// contract: after `store_object` returns `Ok`, the object at
    /// `objects/sha256/<digest>/` verifies as `<digest>`).
    pub fn store_object(&self, digest: &TreeDigest, src_root: &Path) -> Result<()> {
        let obj_dir = self.base.join(layout::objects()).join(digest.as_str());
        // The final object is wholly absent or wholly present (the staged
        // publish renames the COMPLETE object dir into place atomically), so
        // reuse only needs to verify the whole object — there is no partial
        // dir to refuse.
        if path_state(&obj_dir)? {
            if self.verify_object(digest, &obj_dir).is_ok() {
                return Ok(()); // reuse
            }
            // A present-but-unverifiable object is a legacy partial or
            // garbage: REPAIR by re-staging (never refuse — the digest names
            // the content, and the final location must end wholly present
            // with the right content).
            std::fs::remove_dir_all(&obj_dir).map_err(|e| {
                Error::store(format!("remove stale object {}: {e}", obj_dir.display()))
            })?;
            sync_parent_dir(&obj_dir)?;
        }
        self.publish_object_staged(digest, &obj_dir, src_root)
    }

    /// Verify a WHOLE present object: the `root/` tree canonicalizes to
    /// `digest` AND the `tree.json` metadata parses and carries the digest
    /// and the canonical schema version. A partial/garbage object fails
    /// (the caller repairs it); a verified object is reusable as-is.
    pub(crate) fn verify_object(&self, digest: &TreeDigest, obj_dir: &Path) -> Result<()> {
        let root = obj_dir.join("root");
        let meta = crate::remote::canonical::canonicalize_tree(&root).map_err(|e| {
            Error::integrity(format!(
                "existing object {} cannot be canonicalized: {e}",
                digest.as_str()
            ))
        })?;
        if meta.tree_sha256 != digest.as_str() {
            return Err(Error::integrity(format!(
                "existing object {} failed verification",
                digest.as_str()
            )));
        }
        let stored: TreeMetadata = read_json(&obj_dir.join("tree.json"))?;
        if stored.tree_sha256 != digest.as_str() {
            return Err(Error::integrity(format!(
                "existing object {} metadata failed verification",
                digest.as_str()
            )));
        }
        if stored.tree_schema_version != TREE_SCHEMA_VERSION {
            return Err(Error::integrity(format!(
                "existing object {} carries unsupported tree_schema_version {} (expected {TREE_SCHEMA_VERSION})",
                digest.as_str(),
                stored.tree_schema_version
            )));
        }
        Ok(())
    }

    /// THE STAGED-TREE PUBLISH: build the complete object in a UNIQUE
    /// staging dir, verify + recursively fsync it, atomically publish it by
    /// renaming the whole staging dir into the final location, then fsync
    /// the parent directory. Fault-injectable per stage (test-only, keyed
    /// by the digest) so the crash-consistency property can force every
    /// filesystem boundary.
    fn publish_object_staged(
        &self,
        digest: &TreeDigest,
        obj_dir: &Path,
        src_root: &Path,
    ) -> Result<()> {
        // A UNIQUE staging dir — a dot-prefixed sibling of the final object
        // location (never the final dir itself, never a reused name: a stale
        // staging dir from a crashed publish can never collide with or be
        // confused for a fresh attempt).
        let staging = temp_name_for(obj_dir);
        let staged_root = staging.join("root");
        // Stage 1: copy the complete source tree into staging. A fault here
        // (or a real copy failure) leaves the final location wholly ABSENT.
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::StoreObjectCopy, digest.as_str())
        {
            return Err(Error::store(
                "test fault: store_object (staging copy) forced to fail once",
            ));
        }
        let copy = (|| -> Result<()> {
            copy_dir_recursive(src_root, &staged_root)?;
            // VERIFY the complete staged tree BEFORE anything is published:
            // a tree that does not canonicalize to its digest is never made
            // visible under its digest name.
            let meta = crate::remote::canonical::canonicalize_tree(&staged_root)?;
            if meta.tree_sha256 != digest.as_str() {
                return Err(Error::integrity(format!(
                    "staged object digest mismatch for {}",
                    digest.as_str()
                )));
            }
            // The object's metadata record lives INSIDE the staged object
            // (published atomically with the tree — never a separate write
            // that could leave a tree without its metadata).
            let bytes = serde_json::to_vec(&meta)
                .map_err(|e| Error::store(format!("serialize tree.json: {e}")))?;
            std::fs::write(staging.join("tree.json"), &bytes).map_err(|e| {
                Error::store(format!(
                    "write {}: {e}",
                    staging.join("tree.json").display()
                ))
            })?;
            crate::store::atomic::set_private(&staging.join("tree.json"))?;
            Ok(())
        })();
        if let Err(e) = copy {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e);
        }
        // Stage 2: recursively fsync the COMPLETE staged tree (every file's
        // content and every directory's entries) BEFORE the rename, so a
        // published object is fully durable the moment it becomes visible. A
        // fault here leaves the final location wholly ABSENT.
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::StoreObjectSync, digest.as_str())
        {
            return Err(Error::store(
                "test fault: store_object (staged tree sync) forced to fail once",
            ));
        }
        fsync_tree_recursive(&staging)?;
        // Stage 3: ATOMICALLY PUBLISH — rename the whole staging dir into
        // the final location (atomic on POSIX: the object appears wholly or
        // not at all; a crash between copy and rename leaves only the
        // disposable staging dir). A fault here leaves the final location
        // wholly ABSENT.
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::StoreObjectRename, digest.as_str())
        {
            return Err(Error::store(
                "test fault: store_object (publish rename) forced to fail once",
            ));
        }
        std::fs::rename(&staging, obj_dir)
            .map_err(|e| Error::store(format!("publish object {}: {e}", obj_dir.display())))?;
        // Stage 4: the PARENT-DIRECTORY fsync — the publish's durability
        // commit point, AFTER the rename (the object IS visible; its
        // durability is unconfirmed until the directory entry is synced).
        // FAIL CLOSED: a dir-sync failure PROPAGATES (never report durable
        // success for an unsynced directory entry); a retry sees the whole
        // published object and reuses it.
        #[cfg(test)]
        if self
            .fault_registry
            .consume(FaultKind::StoreObjectDirSync, digest.as_str())
        {
            return Err(Error::store(
                "test fault: store_object (publish parent-dir sync) forced to fail once",
            ));
        }
        sync_parent_dir(obj_dir)?;
        Ok(())
    }

    pub fn read_tree_meta(&self, digest: &TreeDigest) -> Result<TreeMetadata> {
        // THE EMBEDDED-IDENTITY BINDING (read side): the stored metadata's
        // own `tree_sha256` must equal the requested `digest` (the path key
        // — `objects/sha256/<digest>/tree.json`) — a metadata record swapped
        // into the wrong digest's directory is refused with an integrity
        // error naming both digests, never returned as if it were `digest`.
        let meta: TreeMetadata = read_keyed_json(
            &self.object_tree_json(digest),
            digest.as_str(),
            |m: &TreeMetadata| m.tree_sha256.as_str(),
        )?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::test_faults::FaultKind;

    /// Build a small materialized tree (one deterministic file) and return
    /// its canonical digest.
    fn make_tree(root: &Path, tag: &str) -> String {
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(root.join("file.txt"), format!("content-{tag}")).unwrap();
        crate::remote::canonical::canonicalize_tree(root)
            .unwrap()
            .tree_sha256
    }

    /// THE STAGED-PUBLISH ATOMICITY (the review's acceptance for immutable
    /// trees): a fault at ANY staged-publish stage leaves the final object
    /// location WHOLLY ABSENT (pre-publish: the staging copy / the staged
    /// tree fsync / the publish rename) or WHOLLY PRESENT (post-publish: the
    /// parent-directory sync — the object IS visible, only the directory
    /// entry is unsynced, and the publish PROPAGATES the failure — never
    /// reports durable success) — NEVER partial. A retry after any fault
    /// re-stages (or reuses the already-published whole object) and
    /// converges.
    #[test]
    fn staged_publish_faults_leave_object_wholly_absent_or_wholly_present() {
        for stage in [
            FaultKind::StoreObjectCopy,
            FaultKind::StoreObjectSync,
            FaultKind::StoreObjectRename,
            FaultKind::StoreObjectDirSync,
        ] {
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let store = LocalStore::with_base(dir.path().join("store")).unwrap();
            let tree_dir = dir.path().join("tree");
            let tree = make_tree(&tree_dir, "content");
            let obj_dir = store
                .base
                .join(crate::remote::layout::objects())
                .join(&tree);
            store.fault_registry().arm(stage, tree.as_str());
            let res = store.store_object(&TreeDigest::new(tree.clone()), &tree_dir);
            assert!(res.is_err(), "{stage:?} must fail at its boundary");
            match stage {
                FaultKind::StoreObjectDirSync => {
                    // The publish rename HAPPENED — the final object is
                    // wholly PRESENT (only the directory entry is unsynced).
                    assert!(
                        std::fs::symlink_metadata(&obj_dir).is_ok(),
                        "{stage:?}: the object must be wholly present after the publish rename"
                    );
                    store
                        .verify_object(&TreeDigest::new(tree.clone()), &obj_dir)
                        .expect("the published object must be WHOLE (never a half-copied tree)");
                }
                _ => {
                    // Pre-publish fault: the final location is wholly ABSENT
                    // (at most a disposable dot-prefixed staging dir,
                    // invisible to every read).
                    assert!(
                        !std::fs::symlink_metadata(&obj_dir).is_ok(),
                        "{stage:?}: the final object must be wholly ABSENT before the publish"
                    );
                }
            }
            // A RETRY after any transient fault converges: a pre-publish
            // fault re-stages (a fresh unique staging dir), a post-publish
            // fault reuses the whole object.
            store
                .store_object(&TreeDigest::new(tree.clone()), &tree_dir)
                .expect("a retry after any staged-publish fault converges");
            store
                .verify_object(&TreeDigest::new(tree.clone()), &obj_dir)
                .expect("the converged object is whole");
        }
    }

    /// The OLD direct-copy protocol could leave a PARTIAL object in the
    /// final location, and a later retry REFUSED it ("existing object failed
    /// verification"). The staged-publish store never creates a partial
    /// final object (the rename is atomic — wholly absent or wholly
    /// present), and a present-but-unverifiable object — a legacy partial
    /// from the old protocol, or garbage — is REPAIRED (removed and
    /// re-staged), never refused: after `store_object` returns, the object
    /// at `objects/sha256/<digest>/` verifies as `<digest>`.
    #[test]
    fn partial_legacy_object_is_repaired_not_refused() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let tree_dir = dir.path().join("tree");
        let tree = make_tree(&tree_dir, "content");
        // Plant a PARTIAL legacy object: a `root/` with the WRONG content (a
        // half-copied tree) and no `tree.json`.
        let obj_dir = store
            .base
            .join(crate::remote::layout::objects())
            .join(&tree);
        std::fs::create_dir_all(obj_dir.join("root")).unwrap();
        std::fs::write(obj_dir.join("root").join("junk.bin"), b"half-copied").unwrap();
        // A retry must NOT refuse: it repairs (removes and re-stages) and
        // converges.
        store
            .store_object(&TreeDigest::new(tree.clone()), &tree_dir)
            .expect("a partial legacy object is repaired, never refused");
        store
            .verify_object(&TreeDigest::new(tree.clone()), &obj_dir)
            .expect("after repair the object is whole and verifies");
    }

    /// Reuse: a second `store_object` of an already-verified object is an
    /// idempotent reuse, and the object stays whole.
    #[test]
    fn store_object_reuses_a_verified_object() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let tree_dir = dir.path().join("tree");
        let tree = make_tree(&tree_dir, "content");
        store
            .store_object(&TreeDigest::new(tree.clone()), &tree_dir)
            .unwrap();
        store
            .store_object(&TreeDigest::new(tree.clone()), &tree_dir)
            .unwrap();
        store
            .verify_object(
                &TreeDigest::new(tree.clone()),
                &store
                    .base
                    .join(crate::remote::layout::objects())
                    .join(&tree),
            )
            .unwrap();
    }
}
