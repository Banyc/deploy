//! Object-store publication and staging: tree/release publication
//! ([`HeldSlotLock::publish_tree`], [`HeldSlotLock::publish_from_incoming`],
//! [`HeldSlotLock::publish_release`]), incoming staging, and the two-phase
//! host-tree upload ([`copy_host_tree_to_remote`]).
//!
//! # The staged-publish protocol (remote tree objects)
//!
//! A remote tree object NEVER becomes visible at its digest path
//! (`objects/sha256/<digest>/root`) with unverified content. The complete
//! object is assembled in a staging directory (a `.partial`-suffixed path
//! under `incoming/`), canonicalized THERE and compared against the required
//! digest, and only then ATOMICALLY published by renaming the whole staging
//! directory into the final digest path — the digest path is either absent or
//! contains exactly the verified canonical tree, never a partial/corrupt
//! object. On REUSE, an existing object is re-canonicalized and compared
//! against the required digest before it is trusted; invalid content is
//! QUARANTINED (moved aside, never deleted) and REPAIRED by re-publishing the
//! verified staged tree — all while holding the slot lock (the publish
//! operations are [`HeldSlotLock`] methods).
//!
//! # The aggregate release publish ([`HeldSlotLock::publish_release`])
//!
//! A release is published as ONE AGGREGATE BUNDLE
//! ([`crate::verify::release::ValidatedReleaseBundle`]), never as
//! independent files: every member of the release directory (`release.json`,
//! `behavior.json`) is written into a UNIQUE SIBLING staging directory
//! (`releases/<id>.partial-<nonce>`), the WHOLE bundle is verified there,
//! fsynced, and then ATOMICALLY INSTALLED by renaming the staging directory
//! into the final release directory — the final release directory is either
//! wholly absent or complete and readable, never a partial directory (a
//! crash or fault at any stage leaves at most a disposable staging
//! sibling).

use crate::error::{Error, Result};
use crate::identity::{DeploymentId, ReleaseRecord, TreeDigest};
use crate::remote::layout;
use crate::remote::transport::{IMMUTABLE_RECORD_MODE, Remote, RootedRelativePath};
use crate::verify::release::ValidatedReleaseBundle;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use walkdir::WalkDir;

use super::super::RemoteHelper;

impl<'a> RemoteHelper<'a> {
    /// Whether the tree object exists on the remote — a typed probe: a
    /// transport failure is an `Err`, never a silent false (the boolean
    /// `exists` collapses NotFound and errors into one false and could mask
    /// a real failure).
    pub fn tree_exists(&self, digest: &TreeDigest) -> Result<bool> {
        Ok(self
            .remote
            .metadata_opt(&layout::tree_root(digest))?
            .is_some())
    }

    /// Verify that the remote tree at `rel` canonicalizes to `digest`.
    ///
    /// `Ok(true)` — the tree verifies (its canonical digest equals the
    /// required one). `Ok(false)` — the tree is PRESENT but does NOT verify:
    /// a digest mismatch, uncanonicalizable content (escaping/absolute
    /// symlink, hard link, device, ...), or unreadable content (a mode
    /// mutation that removed read permission) — invalid content that must
    /// never be served under the digest name. `Err` — the tree is MISSING (a
    /// caller error: the caller checks existence first) or the transport
    /// itself failed.
    ///
    /// The remote tree is materialized into a host temp directory and
    /// canonicalized THERE: the canonical digest is computed from a directory
    /// ([`crate::remote::canonical::canonicalize_tree`]), so the remote bytes
    /// are downloaded and re-hashed with the SAME machinery every other
    /// verifier uses.
    fn verify_remote_tree(&self, rel: &RootedRelativePath, digest: &TreeDigest) -> Result<bool> {
        if self.remote.metadata_opt(rel)?.is_none() {
            return Err(Error::integrity(format!(
                "tree {} is missing; cannot verify",
                rel.display()
            )));
        }
        let tmp = tempfile::tempdir()
            .map_err(|e| Error::remote(format!("tempdir for tree verification: {e}")))?;
        // A download failure (unreadable content) means the content is
        // INVALID — never trusted, never served. Only a missing tree (above)
        // or a transport failure on the existence probe is an `Err`.
        if crate::deploy::rollout::download_tree_to_host(self.remote, rel, tmp.path()).is_err() {
            return Ok(false);
        }
        match crate::remote::canonical::canonicalize_tree(tmp.path()) {
            Ok(meta) => Ok(meta.tree_sha256 == digest.as_str()),
            Err(_) => Ok(false),
        }
    }

    /// Remove a remote directory tree, restoring owner-write on read-only
    /// directories first (a stale staging/quarantine tree may contain
    /// read-only — or even 0o000 — directories whose removal would otherwise
    /// fail with EACCES). A missing tree is a no-op.
    pub(crate) fn remove_remote_tree_restoring_write(
        &self,
        rel: &RootedRelativePath,
    ) -> Result<()> {
        // Phase 1: make every directory owner-traversable, deepest first, so
        // the whole tree can be listed and removed regardless of its modes.
        fn restore_write(remote: &dyn Remote, rel: &RootedRelativePath) -> Result<()> {
            if let Some(meta) = remote.metadata_opt(rel)?
                && meta.is_dir
            {
                remote.set_mode(rel, (meta.mode & 0o7777) | 0o700)?;
            }
            for e in remote.list(rel)? {
                if e.is_dir {
                    restore_write(remote, &rel.join(&e.name)?)?;
                }
            }
            Ok(())
        }
        restore_write(self.remote, rel)?;
        self.remote.remove_dir_all(rel)
    }

    /// Stage a tree into a deployment-specific incoming directory (invisible to
    /// activation and retention until published). A stale staging dir from a
    /// crashed earlier attempt is removed first (restoring write perms), so a
    /// retry re-stages cleanly instead of mixing stale and fresh content.
    pub fn stage_incoming(
        &self,
        deployment_id: &DeploymentId,
        digest: &TreeDigest,
        host_src: &Path,
    ) -> Result<()> {
        let dest = layout::staged_tree(deployment_id, digest);
        if self.remote.metadata_opt(&dest)?.is_some() {
            self.remove_remote_tree_restoring_write(&dest)?;
        }
        copy_host_tree_to_remote(host_src, &dest, self.remote)
    }
}

impl<'a> crate::remote::helper::HeldSlotLock<'a> {
    /// Publish a release as ONE AGGREGATE BUNDLE
    /// ([`crate::verify::release::ValidatedReleaseBundle`]) — never as
    /// independent files. Requires the slot-mutation capability — the
    /// receiver is the guard; the helper is the guard's own.
    ///
    /// The bundle is COMPLETE BY CONSTRUCTION
    /// ([`crate::verify::release::ValidatedReleaseBundle::from_validated`]):
    /// the members are derived from the ONE validated release, so the
    /// publish never receives a `release.json` that disagrees with the
    /// `behavior.json` (or with the release identity). The staged content is
    /// STILL re-verified member-by-member before the install (defense in
    /// depth: a fault between a write and its verify must never install
    /// unverified content), and an EXISTING release directory is verified
    /// as the WHOLE bundle before it is trusted (idempotent re-publication)
    /// — a corrupted or partial existing directory fails closed, never
    /// silently replaced.
    ///
    /// The publication protocol:
    ///
    /// 1. **Reuse verifies**: an existing release directory is verified as
    ///    the WHOLE bundle (each member's content — the release record
    ///    identity recomputed from its own content, the behavior digest
    ///    against the record provenance — and each member's immutable mode)
    ///    before it is trusted; a corrupted or partial existing directory
    ///    fails closed with an integrity error, never silently replaced.
    /// 2. **Stage**: ALL members are written into a UNIQUE SIBLING staging
    ///    directory (`releases/<id>.partial-<nonce>`), so a crash or fault
    ///    at any member write leaves at most a disposable staging sibling.
    /// 3. **Staged verify**: the WHOLE bundle is verified in the staging
    ///    directory BEFORE anything becomes visible — the release record
    ///    identity and the behavior digest against the record provenance.
    /// 4. **Fsync**: the whole staged bundle is made durable.
    /// 5. **Atomic install**: the verified, fsynced staging directory is
    ///    renamed into the final release directory — the final release
    ///    directory is either wholly absent or complete and readable, never
    ///    a partial directory.
    /// 6. **Fsync the changed parent directory**: the PARENT of the final
    ///    release directory (`releases/`) is fsynced so the renamed
    ///    directory entry survives power loss — the durability commit point.
    ///    FAIL-CLOSED: a failed parent fsync is a propagated `Err`, never a
    ///    reported success.
    ///
    /// Returns the [`DurableRelease`] EVIDENCE of the durably published
    /// release (the sealed witness — never a bare `()`).
    pub fn durable_publish_release(
        &self,
        bundle: &ValidatedReleaseBundle,
    ) -> Result<crate::remote::helper::DurableRelease> {
        let release_id = bundle.release_id();
        let dir = layout::remote_release(release_id);
        // Reuse: an existing release directory is verified as the WHOLE
        // bundle before it is trusted (idempotent re-publication). A
        // corrupted or partial existing directory fails closed — never
        // silently replaced.
        if self.helper.remote.metadata_opt(&dir)?.is_some() {
            self.verify_installed_bundle(bundle, &dir)?;
            return Ok(crate::remote::helper::DurableRelease::published(
                release_id.clone(),
            ));
        }
        // Stage: write ALL members into a unique sibling directory.
        let nonce = uuid::Uuid::now_v7().to_string();
        let staging = layout::staged_release(release_id, &nonce);
        // A stale staging dir from a crashed earlier attempt is removed first
        // (restoring write perms), so a retry re-stages cleanly instead of
        // mixing stale and fresh content.
        if self.helper.remote.metadata_opt(&staging)?.is_some() {
            self.helper.remove_remote_tree_restoring_write(&staging)?;
        }
        self.helper.remote.create_dir_all(&staging)?;
        self.helper.remote.write(
            &staging.join("release.json")?,
            bundle.release_json(),
            IMMUTABLE_RECORD_MODE,
        )?;
        self.helper.remote.write(
            &staging.join("behavior.json")?,
            bundle.behavior_json(),
            IMMUTABLE_RECORD_MODE,
        )?;
        // Verify the WHOLE bundle in the staging directory BEFORE anything
        // becomes visible: the release record identity and the behavior
        // digest against the record provenance.
        self.verify_staged_bundle(bundle, &staging)?;
        // Fsync the whole staged bundle, then atomically install the
        // directory: the final release directory is either wholly absent or
        // complete and readable, never partial.
        self.helper.remote.fsync_tree(&staging)?;
        self.helper.remote.rename(&staging, &dir)?;
        // Fsync the changed parent directory (`releases/`): the renamed
        // directory entry survives power loss. FAIL-CLOSED: a failed parent
        // fsync is a propagated error, never a reported success.
        self.helper.remote.fsync_parent(&dir)?;
        Ok(crate::remote::helper::DurableRelease::published(
            release_id.clone(),
        ))
    }

    /// Publish a release as ONE AGGREGATE BUNDLE
    /// ([`crate::verify::release::ValidatedReleaseBundle`]) — the durable
    /// publication protocol ([`Self::durable_publish_release`]). Requires
    /// the slot-mutation capability — the receiver is the guard; the helper
    /// is the guard's own. Returns the [`DurableRelease`] EVIDENCE of the
    /// durably published release.
    pub fn publish_release(
        &self,
        bundle: &ValidatedReleaseBundle,
    ) -> Result<crate::remote::helper::DurableRelease> {
        self.durable_publish_release(bundle)
    }

    /// Verify the WHOLE bundle in an EXISTING release directory (the
    /// idempotent re-publication path): each member must be a REGULAR FILE
    /// with the immutable record mode, the release record's identity must
    /// recompute from its own content and equal the bundle's record
    /// identity, and the behavior snapshot must digest to the record's
    /// provenance `behavior_sha256`. A corrupted or partial existing
    /// directory fails closed with an integrity error — never silently
    /// replaced.
    fn verify_installed_bundle(
        &self,
        bundle: &ValidatedReleaseBundle,
        dir: &RootedRelativePath,
    ) -> Result<()> {
        // 1. The release record member: a regular file with the immutable
        //    mode whose identity recomputes from its own content and equals
        //    the bundle's record identity (metadata such as `created_at` is
        //    excluded from the digest, so it may differ between runs of the
        //    same canonical release).
        let rel = dir.join("release.json")?;
        self.verify_installed_member_shape(&rel)?;
        let existing = self.helper.remote.read(&rel)?;
        let existing_rec: ReleaseRecord = serde_json::from_slice(&existing).map_err(|e| {
            Error::integrity(format!(
                "malformed existing release record at {}: {e}",
                rel.display()
            ))
        })?;
        crate::verify::release::verify_release_identity(&existing_rec)?;
        if existing_rec.release_id != bundle.release_id().as_str() {
            return Err(Error::integrity(format!(
                "release record identity {} does not match the publish path {}",
                existing_rec.release_id,
                bundle.release_id()
            )));
        }
        if existing_rec.release_sha256 != bundle.release().record().release_sha256 {
            return Err(Error::integrity(format!(
                "refusing to replace existing {} with a different release",
                rel.display()
            )));
        }
        // 2. The behavior snapshot member: a regular file with the immutable
        //    mode whose canonical contract set digests to the record's
        //    provenance `behavior_sha256`.
        let bpath = dir.join("behavior.json")?;
        self.verify_installed_member_shape(&bpath)?;
        let bdata = self.helper.remote.read(&bpath)?;
        crate::verify::release::verify_behavior_json(
            &bdata,
            &existing_rec.release_id,
            &existing_rec.provenance.behavior_sha256,
        )?;
        Ok(())
    }

    /// Verify the SHAPE of one installed member of the release directory: a
    /// REGULAR FILE with the immutable record mode (the mode is part of the
    /// immutable record). The member's CONTENT is verified by the caller
    /// (the release record's identity recompute / the behavior digest against
    /// the record provenance), so a metadata-only difference in the record
    /// (`created_at` — excluded from the digest) stays an idempotent no-op.
    fn verify_installed_member_shape(&self, rel: &RootedRelativePath) -> Result<()> {
        let meta = self.helper.remote.metadata_opt(rel)?.ok_or_else(|| {
            Error::integrity(format!(
                "release member {} is missing; the release directory is incomplete",
                rel.display()
            ))
        })?;
        if !meta.is_file {
            return Err(Error::integrity(format!(
                "release member {} is a {} entry, not a regular file",
                rel.display(),
                if meta.is_dir {
                    "directory"
                } else if meta.is_symlink {
                    "symlink"
                } else {
                    "non-file"
                }
            )));
        }
        if meta.mode & 0o7777 != IMMUTABLE_RECORD_MODE & 0o7777 {
            return Err(Error::integrity(format!(
                "release member {} carries mode {:o}, expected {:o}",
                rel.display(),
                meta.mode & 0o7777,
                IMMUTABLE_RECORD_MODE & 0o7777
            )));
        }
        Ok(())
    }

    /// Verify the WHOLE bundle in the STAGING directory BEFORE anything
    /// becomes visible: the release record's identity must recompute from its
    /// own content and equal the bundle's record identity, and the behavior
    /// snapshot must digest to the record's provenance `behavior_sha256`.
    /// A fault between a member write and its verify can never install
    /// unverified content.
    fn verify_staged_bundle(
        &self,
        bundle: &ValidatedReleaseBundle,
        staging: &RootedRelativePath,
    ) -> Result<()> {
        let rel = staging.join("release.json")?;
        let data = self.helper.remote.read(&rel)?;
        let rec: ReleaseRecord = serde_json::from_slice(&data).map_err(|e| {
            Error::integrity(format!(
                "malformed staged release record at {}: {e}",
                rel.display()
            ))
        })?;
        crate::verify::release::verify_release_identity(&rec)?;
        if rec.release_id != bundle.release_id().as_str() {
            return Err(Error::integrity(format!(
                "staged release record identity {} does not match the publish path {}",
                rec.release_id,
                bundle.release_id()
            )));
        }
        if rec.release_sha256 != bundle.release().record().release_sha256 {
            return Err(Error::integrity(format!(
                "staged release record {} does not match the bundle",
                rel.display()
            )));
        }
        let bpath = staging.join("behavior.json")?;
        let bdata = self.helper.remote.read(&bpath)?;
        crate::verify::release::verify_behavior_json(
            &bdata,
            &rec.release_id,
            &rec.provenance.behavior_sha256,
        )?;
        Ok(())
    }

    /// Publish a previously staged incoming tree into the object store.
    /// Requires the slot-mutation capability — the receiver is the guard; the
    /// helper is the guard's own.
    ///
    /// The digest path is NEVER made visible with unverified content:
    ///
    /// 1. **Reuse verifies**: an existing object at the digest path is
    ///    re-canonicalized and compared against the required digest before it
    ///    is trusted. Invalid content (a digest mismatch, uncanonicalizable or
    ///    unreadable content) is QUARANTINED (moved aside, never deleted) and
    ///    REPAIRED by re-publishing the verified staged tree — all while
    ///    holding the slot lock.
    /// 2. **Staged verify**: the complete staged tree is canonicalized and
    ///    compared against the required digest BEFORE anything becomes
    ///    visible.
    /// 3. **Atomic publish**: the verified staging directory is renamed into
    ///    the final digest path — the digest path is either absent or contains
    ///    exactly the verified canonical tree, never a partial/corrupt object.
    ///
    /// Returns the [`DurableObject`] EVIDENCE of the durably published
    /// object (the sealed witness — never a bare `()`).
    pub fn publish_from_incoming(
        &self,
        deployment_id: &DeploymentId,
        digest: &TreeDigest,
    ) -> Result<crate::remote::helper::DurableObject> {
        let from = layout::staged_tree(deployment_id, digest);
        let to = layout::tree_root(digest);
        // Reuse: verify the existing object; quarantine + repair invalid
        // content (under the slot lock).
        if self.helper.tree_exists(digest)? {
            if self.helper.verify_remote_tree(&to, digest)? {
                return Ok(crate::remote::helper::DurableObject::published(
                    digest.clone(),
                ));
            }
            self.quarantine_object(digest)?;
        }
        // The staged tree must be present and verify BEFORE it becomes
        // visible.
        if self.helper.remote.metadata_opt(&from)?.is_none() {
            return Err(Error::integrity(format!(
                "staged tree {} is missing; nothing to publish",
                from.display()
            )));
        }
        self.publish_staged_tree(digest, &from)
    }

    /// Publish a host-local tree into the object store — the DURABLE
    /// publication protocol (stage → fsync contents → rename → fsync every
    /// changed parent directory). Requires the slot-mutation capability. The
    /// complete remote object is assembled in a deployment-independent
    /// staging directory, verified there, fsynced, and atomically published;
    /// an existing object is verified before reuse and invalid content is
    /// quarantined and repaired (under the slot lock). Success is reported
    /// only after the parent-directory fsync succeeds (fail closed: a failed
    /// parent fsync is an `Err`, never a reported success). Returns the
    /// [`DurableObject`] EVIDENCE of the durably published object.
    pub fn durable_publish_tree(
        &self,
        digest: &TreeDigest,
        host_src: &Path,
    ) -> Result<crate::remote::helper::DurableObject> {
        let to = layout::tree_root(digest);
        // Reuse: verify the existing object; quarantine + repair invalid
        // content (under the slot lock).
        if self.helper.tree_exists(digest)? {
            if self.helper.verify_remote_tree(&to, digest)? {
                return Ok(crate::remote::helper::DurableObject::published(
                    digest.clone(),
                ));
            }
            self.quarantine_object(digest)?;
        }
        // Stage the host tree into a deployment-independent staging dir
        // (removing a stale staging dir from a crashed earlier attempt).
        let staging = layout::staged_tree_global(digest);
        if self.helper.remote.metadata_opt(&staging)?.is_some() {
            self.helper.remove_remote_tree_restoring_write(&staging)?;
        }
        copy_host_tree_to_remote(host_src, &staging, self.helper.remote)?;
        let res = self.publish_staged_tree(digest, &staging);
        if res.is_err() {
            // Best-effort cleanup of the disposable staging dir (a failed
            // publish never leaves a partial object behind).
            let _ = self.helper.remove_remote_tree_restoring_write(&staging);
        }
        res
    }

    /// Publish a host-local tree into the object store — the durable
    /// publication protocol ([`Self::durable_publish_tree`]). Requires the
    /// slot-mutation capability. Returns the [`DurableObject`] EVIDENCE of
    /// the durably published object.
    pub fn publish_tree(
        &self,
        digest: &TreeDigest,
        host_src: &Path,
    ) -> Result<crate::remote::helper::DurableObject> {
        self.durable_publish_tree(digest, host_src)
    }

    /// Publish a tree object from a host-local path (used when no prior
    /// incoming staging occurred). Requires the slot-mutation capability.
    /// Returns the [`DurableObject`] EVIDENCE of the durably published
    /// object.
    pub fn publish_tree_from_host(
        &self,
        digest: &TreeDigest,
        host_src: &Path,
    ) -> Result<crate::remote::helper::DurableObject> {
        self.publish_tree(digest, host_src)
    }

    /// Quarantine an invalid object at the digest path: move it aside (never
    /// delete), so the digest path is absent while the invalid content is
    /// preserved for inspection. A stale quarantine from a crashed earlier
    /// repair is removed first (restoring write perms), so the rename cannot
    /// collide.
    fn quarantine_object(&self, digest: &TreeDigest) -> Result<()> {
        let to = layout::tree_root(digest);
        let q = layout::quarantined_tree(digest);
        if self.helper.remote.metadata_opt(&q)?.is_some() {
            self.helper.remove_remote_tree_restoring_write(&q)?;
        }
        self.helper.remote.rename(&to, &q)?;
        Ok(())
    }

    /// Atomically publish a verified staged tree into the final digest path —
    /// the DURABLE staged-publish protocol (stage → fsync contents → rename
    /// → fsync every changed parent directory): the staged tree is
    /// canonicalized and compared against the required digest BEFORE the
    /// rename, the whole staged tree is fsynced, and the digest path is
    /// either absent or contains exactly the verified canonical tree — never
    /// a partial or corrupt object. After the rename, EVERY changed parent
    /// directory is fsynced (the digest directory — the rename target's
    /// parent — and its own parent, whose `<digest>` entry the
    /// `create_dir_all` above may have just created), so the published
    /// directory entry survives power loss. FAIL-CLOSED: a failed parent
    /// fsync is a propagated `Err`, never a reported success.
    fn publish_staged_tree(
        &self,
        digest: &TreeDigest,
        staging: &RootedRelativePath,
    ) -> Result<crate::remote::helper::DurableObject> {
        let to = layout::tree_root(digest);
        if !self.helper.verify_remote_tree(staging, digest)? {
            return Err(Error::integrity(format!(
                "staged tree {} does not canonicalize to {}; refusing to publish",
                staging.display(),
                digest.as_str()
            )));
        }
        // Fsync the whole staged tree before it becomes visible.
        self.helper.remote.fsync_tree(staging)?;
        self.helper.remote.create_dir_all(&to.parent().unwrap())?;
        self.helper.remote.rename(staging, &to)?;
        // Fsync every changed parent directory: the digest directory (the
        // rename target's parent) and its own parent (the `<digest>` entry
        // may have been created by the `create_dir_all` above).
        self.helper.remote.fsync_parent(&to)?;
        self.helper.remote.fsync_parent(&to.parent().unwrap())?;
        Ok(crate::remote::helper::DurableObject::published(
            digest.clone(),
        ))
    }
}

impl<'a> RemoteHelper<'a> {
    /// Remove a specific incoming directory (used after completion).
    pub fn remove_incoming(&self, deployment_id: &DeploymentId) -> Result<()> {
        self.remote
            .remove_dir_all(&layout::incoming_dir(deployment_id))?;
        Ok(())
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
pub(crate) fn copy_host_tree_to_remote(
    host: &Path,
    rel_dest: &RootedRelativePath,
    remote: &dyn Remote,
) -> Result<()> {
    remote.create_dir_all(rel_dest)?;
    // (dest, final_mode, depth) collected during the walk for phase 2.
    let mut dirs: Vec<(RootedRelativePath, u32, usize)> = Vec::new();
    for entry in WalkDir::new(host).min_depth(1).into_iter() {
        let entry = entry.map_err(|e| Error::remote(format!("walk: {e}")))?;
        let path = entry.path();
        let rel = entry
            .path()
            .strip_prefix(host)
            .map_err(|e| Error::remote(format!("{e}")))?;
        let dest = rel_dest.join(rel)?;
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

#[cfg(test)]
pub(crate) mod tests_publish {
    use super::*;
    use crate::remote::transport::{
        CreateNewVerdict, ExecOutcome, FsBytes, LocalTransport, RemoteEntry, RemoteMeta,
    };
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::os::unix::fs::PermissionsExt;

    /// A named (label, mutator) pair driving the publish-rejection mutation
    /// matrices: the label names the tamper in failure messages, the mutator
    /// rewrites one field of the serialized release/behavior JSON.
    type JsonMutation = (&'static str, fn(&mut serde_json::Value));

    /// A publish fixture: a release record whose provenance `behavior_sha256`
    /// is the canonical digest of a real per-variant behavior contract set
    /// (adapter `systemd` — non-default, so field deletions change the
    /// digest — plus a command verification), and the serialized behavior JSON
    /// for that same set.
    pub(crate) fn publish_fixture() -> (crate::identity::ReleaseRecord, String) {
        let contracts: std::collections::BTreeMap<String, crate::identity::BehaviorContract> =
            std::collections::BTreeMap::from([(
                "standard".to_string(),
                crate::identity::BehaviorContract::new(
                    crate::config::Activation::Systemd(
                        crate::config::ValidatedSystemd::new(
                            crate::config::ActivationScope::System,
                            true,
                            vec![
                                crate::config::UnitDef::new(
                                    "app.service".to_string(),
                                    "integration/systemd/app.service".to_string(),
                                    true,
                                    true,
                                )
                                .expect("validated unit"),
                            ],
                        )
                        .expect("validated systemd"),
                    ),
                    crate::config::Verification::Command(
                        crate::config::ValidatedCommand::new(vec!["true".to_string()], 30, 2, 1)
                            .expect("validated command"),
                    ),
                ),
            )]);
        let behavior_sha = crate::verify::release::variant_behaviors_digest(&contracts);
        let variants: std::collections::BTreeMap<
            crate::identity::VariantName,
            crate::identity::TreeDigest,
        > = std::collections::BTreeMap::from([(
            crate::identity::VariantName::new("standard"),
            crate::identity::test_tree_digest("t1"),
        )]);
        let slots: std::collections::BTreeMap<String, Vec<crate::config::SlotConfig>> =
            std::collections::BTreeMap::from([(
                "standard".to_string(),
                vec![crate::config::SlotConfig::new(
                    "p1".to_string(),
                    "s1".to_string(),
                    std::path::PathBuf::from("/srv/deploy/p1"),
                    "t1".to_string(),
                    Vec::new(),
                )],
            )]);
        let rec = crate::verify::release::build_release(
            "m",
            &behavior_sha,
            &variants,
            &slots,
            std::path::Path::new("."),
        );
        let behavior_json = serde_json::to_string(&contracts).unwrap();
        (rec, behavior_json)
    }

    /// The server set the fixture's slots bind (the fixture declares one
    /// slot on server "s1").
    pub(crate) fn fixture_servers() -> std::collections::BTreeSet<String> {
        std::collections::BTreeSet::from(["s1".to_string()])
    }

    /// Build the COMPLETE publication bundle from the fixture: the record +
    /// behavior contracts validated into a [`ValidatedRelease`] (the
    /// bundle's validated constructor), then the bundle itself.
    pub(crate) fn publish_fixture_bundle() -> ValidatedReleaseBundle {
        let (rec, behavior_json) = publish_fixture();
        let behaviors: std::collections::BTreeMap<String, crate::identity::BehaviorContract> =
            serde_json::from_str(&behavior_json).unwrap();
        let vr =
            crate::verify::release::ValidatedRelease::try_new(rec, behaviors, &fixture_servers())
                .expect("the fixture release graph validates");
        ValidatedReleaseBundle::from_validated(vr).expect("the fixture bundle builds")
    }

    /// Publish a bundle under the slot mutation lock (the guard is dropped
    /// after the publish, releasing the lock).
    fn publish_bundle(helper: &RemoteHelper, bundle: &ValidatedReleaseBundle) -> Result<()> {
        let held = crate::remote::helper::SlotRemote::new(
            helper,
            crate::remote::helper::test_owner("test-app", "s1"),
        )
        .acquire_lock_guard(&crate::identity::test_operation_id("op-1"))
        .expect("lock acquired");
        let res = held.publish_release(bundle).map(|_| ());
        drop(held);
        res
    }

    /// The aggregate publish installs the WHOLE bundle: a pristine bundle
    /// publishes (and re-publishes idempotently), while a record whose
    /// identity does not match its content can never become a bundle — the
    /// validated constructor ([`ValidatedRelease::try_new`]) fails closed
    /// with an integrity error naming the mismatch, so a release whose
    /// identity does not match its content is never published. A malformed
    /// payload is refused outright (it cannot even parse into a
    /// [`ReleaseRecord`]).
    #[test]
    fn publish_release_recomputes_and_verifies_identity() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let helper = RemoteHelper::new(&remote);
        let bundle = publish_fixture_bundle();

        // Positive case: the pristine bundle publishes, and re-publishing the
        // identical release is an idempotent no-op (the existing release
        // directory verifies as the WHOLE bundle).
        publish_bundle(&helper, &bundle).expect("pristine bundle publishes");
        publish_bundle(&helper, &bundle).expect("identical re-publication is idempotent");

        // Tampered record: slot content changed, digest fields retained -> the
        // bundle's validated constructor fails with an integrity error naming
        // the mismatch — a release whose identity does not match its content
        // can never become a bundle, so it is never published.
        let (rec, behavior_json) = publish_fixture();
        let mut tampered = rec.clone();
        tampered.slots.get_mut("standard").unwrap().slots[0].deploy_dir =
            "/srv/elsewhere".to_string();
        assert_eq!(
            tampered.release_sha256, rec.release_sha256,
            "digest retained"
        );
        let behaviors: std::collections::BTreeMap<String, crate::identity::BehaviorContract> =
            serde_json::from_str(&behavior_json).unwrap();
        let err = crate::verify::release::ValidatedRelease::try_new(
            tampered,
            behaviors,
            &fixture_servers(),
        )
        .expect_err("a tampered record must never validate into a bundle");
        let msg = err.to_string();
        assert!(
            msg.contains("identity mismatch"),
            "error must name the mismatch, got: {msg}"
        );
        assert!(
            msg.contains(&rec.release_sha256),
            "error must name the stored digest, got: {msg}"
        );

        // A malformed payload is refused outright: it cannot even parse into
        // a ReleaseRecord, so it can never reach the validated constructor.
        let err = serde_json::from_str::<ReleaseRecord>("{}")
            .expect_err("a malformed release record must be refused");
        assert!(
            err.to_string().contains("missing field"),
            "error must name the missing field, got: {err}"
        );
    }

    /// A fresh remote already carrying the pristine bundle under
    /// `releases/<id>/` (release.json + behavior.json), plus the pristine
    /// bundle for republishing. Each case builds its own fixture so the
    /// mutation matrix stays deterministic.
    fn published_release_fixture() -> (tempfile::TempDir, LocalTransport, ValidatedReleaseBundle) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let helper = RemoteHelper::new(&remote);
        let bundle = publish_fixture_bundle();
        publish_bundle(&helper, &bundle).expect("pristine bundle publishes");
        (dir, remote, bundle)
    }

    /// Republishing against an EXISTING remote release directory that was
    /// CORRUPTED must ALWAYS fail closed: mutate each identity-bearing field
    /// of the stored remote `release.json` one at a time (written directly to
    /// the remote path, bypassing the verified publish path) while retaining
    /// `release_sha256`/`release_id` at the ORIGINAL values, then republish
    /// the CORRECT original release. The mutation matrix covers the
    /// per-variant mappings digest, the behavior digest, the slot snapshot
    /// (`deploy_dir`/targets), the variant→tree bindings, a variant renamed
    /// or removed, and the identity-bearing provenance fields. Every case
    /// must fail with an integrity error naming the remote release and the
    /// content-vs-digest mismatch — a corrupted remote record is never
    /// silently accepted as the same release. Metadata-only differences
    /// (`created_at` — excluded from the digest)
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
            ("slot owning target", |v: &mut serde_json::Value| {
                v["slots"]["standard"]["slots"][0]["target"] = serde_json::json!("tampered-target");
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
            let (_dir, remote, bundle) = published_release_fixture();
            let mut stored = serde_json::to_value(bundle.release().record()).unwrap();
            mutate(&mut stored);
            // The identity-bearing content mutated, digest fields retained at
            // the original values.
            assert_eq!(
                stored["release_sha256"],
                bundle.release().record().release_sha256,
                "{name}: digest must be retained"
            );
            assert_eq!(
                stored["release_id"],
                bundle.release().record().release_id,
                "{name}: release id must be retained"
            );
            let rel = layout::remote_release(bundle.release_id())
                .join("release.json")
                .unwrap();
            remote
                .write(&rel, &serde_json::to_vec(&stored).unwrap(), 0o644)
                .unwrap();
            let helper = RemoteHelper::new(&remote);
            let fail_msg =
                format!("{name}: republishing against a corrupted remote record must fail closed");
            let err = publish_bundle(&helper, &bundle).expect_err(&fail_msg);
            let msg = err.to_string();
            assert!(
                msg.contains("identity mismatch"),
                "{name}: error must name the content-vs-digest mismatch, got: {msg}"
            );
            assert!(
                msg.contains(&bundle.release().record().release_sha256),
                "{name}: error must name the stored digest, got: {msg}"
            );
        }

        // A corrupted remote behavior.json fails the republish via the
        // whole-bundle verify (release.json is untouched here, so the failure
        // is pinned to behavior.json).
        let (_dir, remote, bundle) = published_release_fixture();
        let bpath = layout::remote_release(bundle.release_id())
            .join("behavior.json")
            .unwrap();
        remote.write(&bpath, b"{\"tampered\":", 0o644).unwrap();
        let helper = RemoteHelper::new(&remote);
        let err = publish_bundle(&helper, &bundle)
            .expect_err("a corrupted remote behavior.json must fail republish");
        assert!(
            err.to_string().contains("malformed") || err.to_string().contains("digest mismatch"),
            "error must name the behavior verification refusal, got: {err}"
        );

        // Malformed existing release.json is refused outright, never silently
        // replaced.
        let (_dir, remote, bundle) = published_release_fixture();
        let rel = layout::remote_release(bundle.release_id())
            .join("release.json")
            .unwrap();
        remote.write(&rel, b"{ not json", 0o644).unwrap();
        let helper = RemoteHelper::new(&remote);
        let err = publish_bundle(&helper, &bundle)
            .expect_err("malformed existing release.json must be refused, not silently replaced");
        assert!(
            err.to_string()
                .contains("malformed existing release record"),
            "error must name the malformed existing record, got: {err}"
        );

        // Metadata-only differences in the EXISTING record (`created_at`) are
        // excluded from the digest: republishing
        // against a record that differs ONLY in those fields is still an
        // idempotent no-op.
        let metadata_mutations: [JsonMutation; 1] =
            [("created_at", |v: &mut serde_json::Value| {
                v["created_at"] = serde_json::json!("2099-01-01T00:00:00Z");
            })];
        for (name, mutate) in metadata_mutations {
            let (_dir, remote, bundle) = published_release_fixture();
            let mut stored = serde_json::to_value(bundle.release().record()).unwrap();
            mutate(&mut stored);
            let rel = layout::remote_release(bundle.release_id())
                .join("release.json")
                .unwrap();
            remote
                .write(&rel, &serde_json::to_vec(&stored).unwrap(), 0o644)
                .unwrap();
            let helper = RemoteHelper::new(&remote);
            let ok_msg =
                format!("{name}: a metadata-only difference keeps the republish idempotent");
            publish_bundle(&helper, &bundle).expect(&ok_msg);
        }
    }

    /// The staged behavior.json is verified against the record's provenance
    /// BEFORE the install: a CORRUPTED staged behavior member (a fault
    /// between the write and the verify) fails the publish closed with an
    /// integrity error and the final release directory stays wholly absent —
    /// a release never publishes a behavior snapshot that does not match the
    /// release it is stored under. The digest-changing behavior payloads
    /// themselves are refused EARLIER, at the bundle's validated constructor
    /// ([`ValidatedRelease::try_new`] — the behavior graph must agree with
    /// the record provenance), which the release verification tests cover.
    #[test]
    fn publish_release_verifies_staged_behavior_json_digest() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote = FaultOnceReleaseRemote::new(
            &crate::testutil::fixture_env(),
            dir.path().join("remote"),
            ReleasePublishFault::CorruptBehaviorWrite,
        )
        .unwrap();
        let helper = RemoteHelper::new(&remote);
        let bundle = publish_fixture_bundle();

        // The corrupted staged behavior member fails the staged verify.
        let err = publish_bundle(&helper, &bundle)
            .expect_err("a corrupted staged behavior.json must fail closed");
        let msg = err.to_string();
        assert!(
            msg.contains("malformed") || msg.contains("digest mismatch"),
            "error must name the behavior verification refusal, got: {msg}"
        );
        // The final release directory is wholly absent — never a partial
        // directory.
        assert!(
            remote
                .metadata_opt(&layout::remote_release(bundle.release_id()))
                .unwrap()
                .is_none(),
            "a failed publish must leave the final release directory wholly absent"
        );
    }

    /// A MODE-MISMATCHED existing release file is a REAL conflict for the
    /// whole-bundle verify too: the mode is part of the immutable record, so
    /// a mode-mismatched-but-content-equivalent winner fails the republish
    /// closed.
    #[test]
    fn publish_release_file_mode_mismatch_is_a_real_conflict() {
        let (_dir, remote, bundle) = published_release_fixture();
        // Corrupt ONLY the mode of the existing behavior.json (content stays
        // the pristine payload).
        let bpath = layout::remote_release(bundle.release_id())
            .join("behavior.json")
            .unwrap();
        let other_mode = if crate::remote::transport::IMMUTABLE_RECORD_MODE & 0o7777 == 0o600 {
            0o640
        } else {
            0o600
        };
        remote.set_mode(&bpath, other_mode).unwrap();
        let helper = RemoteHelper::new(&remote);
        let err = publish_bundle(&helper, &bundle).expect_err(
            "a mode-mismatched existing release file must fail the republish, never be silently accepted",
        );
        let msg = err.to_string();
        assert!(
            msg.contains("mode"),
            "error must name the mode mismatch, got: {msg}"
        );
        // The winner stays untouched (content AND mode).
        let meta = remote.metadata(&bpath).unwrap();
        assert_eq!(
            meta.mode & 0o7777,
            other_mode,
            "the mode mismatch must never be replaced"
        );
    }

    /// A tree containing a READ-ONLY directory uploads successfully: directories
    /// are created owner-writable during the walk and only chmodded to their
    /// final (possibly read-only) mode after every child has been uploaded,
    /// deepest first. The uploaded tree's canonical digest equals the host's.
    #[test]
    fn copy_host_tree_to_remote_round_trips_read_only_directories() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
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

        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let dest = Path::new("objects/sha256/x/root");
        copy_host_tree_to_remote(&host, &RootedRelativePath::parse(dest).unwrap(), &remote)
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
        let host_meta = crate::remote::canonical::canonicalize_tree(&host).unwrap();
        let remote_meta = crate::remote::canonical::canonicalize_tree(&remote_root).unwrap();
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
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
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

        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let dest = Path::new("objects/sha256/y/root");
        copy_host_tree_to_remote(&host, &RootedRelativePath::parse(dest).unwrap(), &remote)
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
        let host_meta = crate::remote::canonical::canonicalize_tree(&host).unwrap();
        let remote_meta = crate::remote::canonical::canonicalize_tree(&remote_root).unwrap();
        assert_eq!(
            remote_meta.tree_sha256, host_meta.tree_sha256,
            "uploaded tree must match the host tree digest"
        );
    }

    // ---- THE AGGREGATE-RELEASE-PUBLISH ATOMICITY PROPERTY ----
    //
    // A release is published as ONE aggregate bundle: every member is
    // written into a UNIQUE SIBLING staging directory, the whole bundle is
    // verified there, fsynced, and then ATOMICALLY INSTALLED by renaming the
    // staging directory into the final release directory. The property:
    // after a publish under a fault at ANY publication stage (each member
    // write, the staged verify, the staged fsync, the atomic install
    // rename), the final release directory is either WHOLLY ABSENT or
    // COMPLETE AND READABLE — never a partial directory.

    /// The publication stage to fault: each member write, the staged verify
    /// read, the staged fsync, or the atomic install rename. The fault is
    /// armed for EXACTLY ONE matching operation and fires ONCE (then
    /// disarms), per-fixture (owned by the wrapper, never a process-global
    /// slot — two fixtures' faults can never interact).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ReleasePublishFault {
        /// Fail the write of `release.json` into the staging directory.
        WriteReleaseJson,
        /// Fail the write of `behavior.json` into the staging directory.
        WriteBehaviorJson,
        /// CORRUPT the write of `behavior.json` into the staging directory
        /// (write garbage instead of the intended bytes): the staged verify
        /// must catch it — a release never publishes a behavior snapshot
        /// that does not match the release it is stored under.
        CorruptBehaviorWrite,
        /// Fail the first read from the staging directory (the staged
        /// verify).
        VerifyRead,
        /// Fail the fsync of the staged directory.
        StagingFsync,
        /// Fail the atomic install rename of the staging directory into the
        /// final release directory.
        InstallRename,
    }

    /// A transport wrapper that fails (or corrupts) EXACTLY ONE matching
    /// publication operation once, letting the release-publish proptest fault
    /// every publication stage deterministically. The fault is per-fixture
    /// (owned by the wrapper, never a process-global slot); a non-matching
    /// call passes through untouched.
    struct FaultOnceReleaseRemote {
        inner: LocalTransport,
        fault: std::sync::Mutex<Option<ReleasePublishFault>>,
    }

    impl FaultOnceReleaseRemote {
        fn new(
            env: &crate::env::SysEnv,
            base: std::path::PathBuf,
            fault: ReleasePublishFault,
        ) -> Result<Self> {
            Ok(FaultOnceReleaseRemote {
                inner: LocalTransport::new(env, base)?,
                fault: std::sync::Mutex::new(Some(fault)),
            })
        }

        /// Consume the fault if it matches `pred`; returns `true` when it
        /// fired (and disarmed).
        fn consume(&self, pred: impl Fn(ReleasePublishFault) -> bool) -> bool {
            let mut f = self.fault.lock().unwrap();
            match f.as_ref() {
                Some(kind) if pred(*kind) => {
                    *f = None;
                    true
                }
                _ => false,
            }
        }

        /// Whether `rel` is inside a release staging directory (a
        /// `.partial-`-suffixed sibling of the final release directory).
        fn is_staging(rel: &RootedRelativePath) -> bool {
            rel.as_path().to_string_lossy().contains(".partial-")
        }
    }

    impl Remote for FaultOnceReleaseRemote {
        fn root(&self) -> &std::path::Path {
            self.inner.root()
        }
        fn read(&self, rel: &RootedRelativePath) -> Result<Vec<u8>> {
            if Self::is_staging(rel) && self.consume(|f| f == ReleasePublishFault::VerifyRead) {
                return Err(Error::remote(
                    "FaultOnceReleaseRemote: staged verify read forced to fail (once)",
                ));
            }
            self.inner.read(rel)
        }
        fn write(&self, rel: &RootedRelativePath, data: &[u8], mode: u32) -> Result<()> {
            if Self::is_staging(rel) {
                let name = rel.as_path().to_string_lossy();
                if name.ends_with("release.json")
                    && self.consume(|f| f == ReleasePublishFault::WriteReleaseJson)
                {
                    return Err(Error::remote(
                        "FaultOnceReleaseRemote: staged release.json write forced to fail (once)",
                    ));
                }
                if name.ends_with("behavior.json")
                    && self.consume(|f| f == ReleasePublishFault::WriteBehaviorJson)
                {
                    return Err(Error::remote(
                        "FaultOnceReleaseRemote: staged behavior.json write forced to fail (once)",
                    ));
                }
                if name.ends_with("behavior.json")
                    && self.consume(|f| f == ReleasePublishFault::CorruptBehaviorWrite)
                {
                    return self.inner.write(rel, b"{\"tampered\":", mode);
                }
            }
            self.inner.write(rel, data, mode)
        }
        fn try_write_new(&self, rel: &RootedRelativePath, data: &[u8]) -> Result<CreateNewVerdict> {
            self.inner.try_write_new(rel, data)
        }
        fn create_dir(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.create_dir(rel)
        }
        fn create_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.create_dir_all(rel)
        }
        fn set_mode(&self, rel: &RootedRelativePath, mode: u32) -> Result<()> {
            self.inner.set_mode(rel, mode)
        }
        fn list(&self, rel: &RootedRelativePath) -> Result<Vec<RemoteEntry>> {
            self.inner.list(rel)
        }
        fn rename(&self, from: &RootedRelativePath, to: &RootedRelativePath) -> Result<()> {
            if Self::is_staging(from) && self.consume(|f| f == ReleasePublishFault::InstallRename) {
                return Err(Error::remote(
                    "FaultOnceReleaseRemote: atomic install rename forced to fail (once)",
                ));
            }
            self.inner.rename(from, to)
        }
        fn symlink(&self, target: &std::path::Path, link: &RootedRelativePath) -> Result<()> {
            self.inner.symlink(target, link)
        }
        fn read_link(&self, rel: &RootedRelativePath) -> Result<std::path::PathBuf> {
            self.inner.read_link(rel)
        }
        fn remove_file(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.remove_file(rel)
        }
        fn remove_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.remove_dir_all(rel)
        }
        fn exists(&self, rel: &RootedRelativePath) -> bool {
            self.inner.exists(rel)
        }
        fn metadata(&self, rel: &RootedRelativePath) -> Result<RemoteMeta> {
            self.inner.metadata(rel)
        }
        fn exec(&self, argv: &[String], timeout: std::time::Duration) -> Result<ExecOutcome> {
            self.inner.exec(argv, timeout)
        }
        fn filesystem_bytes(&self) -> Result<FsBytes> {
            self.inner.filesystem_bytes()
        }
        fn fsync_tree(&self, rel: &RootedRelativePath) -> Result<()> {
            if Self::is_staging(rel) && self.consume(|f| f == ReleasePublishFault::StagingFsync) {
                return Err(Error::remote(
                    "FaultOnceReleaseRemote: staged fsync forced to fail (once)",
                ));
            }
            self.inner.fsync_tree(rel)
        }
    }

    /// The publication-stage fault strategy: every member write, the staged
    /// verify read, the staged fsync, and the atomic install rename.
    fn release_publish_fault() -> impl Strategy<Value = ReleasePublishFault> {
        prop_oneof![
            Just(ReleasePublishFault::WriteReleaseJson),
            Just(ReleasePublishFault::WriteBehaviorJson),
            Just(ReleasePublishFault::CorruptBehaviorWrite),
            Just(ReleasePublishFault::VerifyRead),
            Just(ReleasePublishFault::StagingFsync),
            Just(ReleasePublishFault::InstallRename),
        ]
    }

    proptest! {
        // THE AGGREGATE-RELEASE-PUBLISH ATOMICITY PROPERTY: fault EVERY
        // publication stage (each member write, the staged verify, the staged
        // fsync, the atomic install rename); the final release directory must
        // be WHOLLY ABSENT or COMPLETE AND READABLE — never a partial
        // directory. Bounded 16 cases, fixed seed 0x5EED_5EED (house style),
        // no failure persistence.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn publish_never_leaves_a_partial_release_directory(
            fault in release_publish_fault(),
        ) {
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let remote = FaultOnceReleaseRemote::new(
                &crate::testutil::fixture_env(),
                dir.path().join("remote"),
                fault,
            )
            .unwrap();
            let helper = RemoteHelper::new(&remote);
            let bundle = publish_fixture_bundle();

            // Publish under the fault: the operation may fail (the fault
            // fired) or succeed (the fault never matched — e.g. the operation
            // completed before the fault point).
            let held = crate::remote::helper::SlotRemote::new(
                &helper,
                crate::remote::helper::test_owner("test-app", "s1"),
            )
            .acquire_lock_guard(&crate::identity::test_operation_id("op-1"))
            .unwrap();
            let _ = held.publish_release(&bundle);
            drop(held);

            // THE PROPERTY: the final release directory is either wholly
            // absent or complete and readable — never a partial directory.
            let final_path = remote.root().join(layout::remote_release(bundle.release_id()));
            match std::fs::symlink_metadata(&final_path) {
                Err(_) => {}
                Ok(_) => {
                    // Complete and readable: both members present, the record
                    // identity verifies, the behavior digests to the
                    // provenance.
                    let release_json = std::fs::read(final_path.join("release.json"))
                        .expect("a present release directory must carry a readable release.json");
                    let rec: ReleaseRecord = serde_json::from_slice(&release_json).expect(
                        "a present release directory must carry a parseable release.json",
                    );
                    crate::verify::release::verify_release_identity(&rec).expect(
                        "a present release directory must carry an identity-verified record",
                    );
                    let behavior_json = std::fs::read(final_path.join("behavior.json")).expect(
                        "a present release directory must carry a readable behavior.json",
                    );
                    crate::verify::release::verify_behavior_json(
                        &behavior_json,
                        &rec.release_id,
                        &rec.provenance.behavior_sha256,
                    )
                    .expect(
                        "a present release directory must carry a digest-consistent behavior.json",
                    );
                }
            }
        }
    }

    // ---- THE STAGED-PUBLISH ATOMICITY PROPERTY (remote tree objects) ----
    //
    // A remote tree object NEVER becomes visible at its digest path with
    // unverified content. The property: after a publish — fresh, or reuse
    // against a MUTATED existing object, or against a MUTATED staged tree —
    // the final digest path is either ABSENT or contains EXACTLY the required
    // canonical tree, never a partial/corrupt object. Mutations cover bytes,
    // modes, symlinks, and paths, applied to either the staged tree (before
    // publish) or the existing object (before reuse).

    /// One entry of a small deterministic tree (fixed shape, random content).
    #[derive(Debug, Clone)]
    enum EntrySpec {
        File {
            path: &'static str,
            data: Vec<u8>,
            mode: u32,
        },
        Dir {
            path: &'static str,
            mode: u32,
        },
        Symlink {
            path: &'static str,
            target: String,
        },
    }

    /// A mutation applied to a staged/existing tree before the publish.
    #[derive(Debug, Clone)]
    enum Mutation {
        /// Overwrite a file's bytes.
        MutateBytes { path: &'static str, data: Vec<u8> },
        /// Change an entry's mode (may remove read permission).
        MutateMode { path: &'static str, mode: u32 },
        /// Retarget the symlink (relative, escaping, or absolute).
        MutateSymlink { target: String },
        /// Rename an entry to a new path.
        MutatePath {
            path: &'static str,
            new_path: String,
        },
        /// Add a new file.
        AddFile { path: String, data: Vec<u8> },
        /// Remove an entry.
        RemoveEntry { path: &'static str },
    }

    /// The fixed tree shape: two files, a subdir with a file, a symlink.
    fn arbitrary_tree() -> impl Strategy<Value = Vec<EntrySpec>> {
        (
            any::<Vec<u8>>(), // a: file bytes
            0o600u32..=0o777, // a: mode
            any::<Vec<u8>>(), // b: file bytes
            0o600u32..=0o777, // b: mode
            any::<Vec<u8>>(), // sub/c: file bytes
            0o600u32..=0o777, // sub/c: mode
            "[a-z]{1,4}",     // link: symlink target
        )
            .prop_map(|(a, am, b, bm, c, cm, t)| {
                vec![
                    EntrySpec::File {
                        path: "a",
                        data: a,
                        mode: am,
                    },
                    EntrySpec::File {
                        path: "b",
                        data: b,
                        mode: bm,
                    },
                    EntrySpec::Dir {
                        path: "sub",
                        mode: 0o755,
                    },
                    EntrySpec::File {
                        path: "sub/c",
                        data: c,
                        mode: cm,
                    },
                    EntrySpec::Symlink {
                        path: "link",
                        target: t,
                    },
                ]
            })
    }

    /// A mutation over the fixed tree shape: bytes, modes, symlinks, and
    /// paths. Symlink targets include relative, escaping (`../`), and
    /// absolute forms; modes include unreadable ones (0o000).
    fn arbitrary_mutation() -> impl Strategy<Value = Mutation> {
        prop_oneof![
            (
                prop::sample::select(vec!["a", "b", "sub/c"]),
                any::<Vec<u8>>()
            )
                .prop_map(|(path, data)| Mutation::MutateBytes { path, data }),
            (
                prop::sample::select(vec!["a", "b", "sub", "sub/c"]),
                0o000u32..=0o777
            )
                .prop_map(|(path, mode)| Mutation::MutateMode { path, mode }),
            prop_oneof![
                "[a-z]{1,4}",
                Just("../escape".to_string()),
                Just("/abs".to_string()),
            ]
            .prop_map(|target| Mutation::MutateSymlink { target }),
            (
                prop::sample::select(vec!["a", "b", "sub", "sub/c", "link"]),
                "[a-z]{1,4}"
            )
                .prop_map(|(path, new_path)| Mutation::MutatePath { path, new_path }),
            ("[a-z]{1,4}", any::<Vec<u8>>())
                .prop_map(|(path, data)| Mutation::AddFile { path, data }),
            prop::sample::select(vec!["a", "b", "sub", "sub/c", "link"])
                .prop_map(|path| Mutation::RemoveEntry { path }),
        ]
    }

    /// Build the tree on the host filesystem.
    fn build_tree(root: &Path, specs: &[EntrySpec]) {
        for s in specs {
            match s {
                EntrySpec::File { path, data, mode } => {
                    let p = root.join(path);
                    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                    std::fs::write(&p, data).unwrap();
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(*mode)).unwrap();
                }
                EntrySpec::Dir { path, mode } => {
                    let p = root.join(path);
                    std::fs::create_dir_all(&p).unwrap();
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(*mode)).unwrap();
                }
                EntrySpec::Symlink { path, target } => {
                    let p = root.join(path);
                    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                    std::os::unix::fs::symlink(target, &p).unwrap();
                }
            }
        }
    }

    /// Apply a mutation to a tree on the host filesystem (the remote tree is
    /// materialized under the LocalTransport root). A mutation that cannot
    /// apply (e.g. a rename onto an existing path) is a no-op — the property
    /// holds either way.
    fn apply_mutation(root: &Path, m: &Mutation) {
        match m {
            Mutation::MutateBytes { path, data } => {
                let p = root.join(path);
                if p.exists() {
                    std::fs::write(&p, data).unwrap();
                }
            }
            Mutation::MutateMode { path, mode } => {
                let p = root.join(path);
                if p.exists() {
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(*mode)).unwrap();
                }
            }
            Mutation::MutateSymlink { target } => {
                let p = root.join("link");
                if p.exists() {
                    std::fs::remove_file(&p).unwrap();
                    std::os::unix::fs::symlink(target, &p).unwrap();
                }
            }
            Mutation::MutatePath { path, new_path } => {
                let p = root.join(path);
                let np = root.join(new_path);
                if p.exists() && !np.exists() {
                    std::fs::rename(&p, &np).unwrap();
                }
            }
            Mutation::AddFile { path, data } => {
                let p = root.join(path);
                if !p.exists() {
                    std::fs::write(&p, data).unwrap();
                }
            }
            Mutation::RemoveEntry { path } => {
                let p = root.join(path);
                if p.exists() {
                    if p.is_dir() {
                        std::fs::remove_dir_all(&p).unwrap();
                    } else {
                        std::fs::remove_file(&p).unwrap();
                    }
                }
            }
        }
    }

    /// The publish scenario under test: which tree (staged or existing) is
    /// mutated, and through which publish path the mutation is confronted.
    #[derive(Clone, Copy, Debug)]
    enum PublishScenario {
        /// Stage, mutate the STAGED tree, publish from incoming.
        Staged,
        /// Publish from host, mutate the EXISTING object, re-publish from
        /// host (the repair re-stages from the host).
        ExistingHost,
        /// Publish from incoming, mutate the EXISTING object, re-stage,
        /// re-publish from incoming (the repair re-publishes the staged
        /// tree).
        ExistingIncoming,
    }

    proptest! {
        // THE STAGED-PUBLISH ATOMICITY PROPERTY: mutate staged/existing
        // bytes, modes, symlinks, and paths; the final digest path must be
        // either ABSENT or contain EXACTLY the required canonical tree —
        // never a partial/corrupt object. Bounded 16 cases, fixed seed
        // 0x5EED_5EED (house style), no failure persistence.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn publish_never_serves_invalid_content(
            tree in arbitrary_tree(),
            mutation in arbitrary_mutation(),
            scenario in prop_oneof![
                Just(PublishScenario::Staged),
                Just(PublishScenario::ExistingHost),
                Just(PublishScenario::ExistingIncoming),
            ],
        ) {
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let remote = LocalTransport::new(
                &crate::testutil::fixture_env(),
                dir.path().join("remote"),
            )
            .unwrap();
            let helper = RemoteHelper::new(&remote);
            let host = dir.path().join("host");
            build_tree(&host, &tree);
            let digest = crate::remote::canonical::canonicalize_tree(&host)
                .unwrap()
                .tree_sha256;
            let digest = TreeDigest::parse(&digest).expect("canonical digest");
            let dep = crate::identity::test_deployment_id("dep");

            match scenario {
                PublishScenario::Staged => {
                    // Stage, then mutate the STAGED tree before publishing.
                    helper.stage_incoming(&dep, &digest, &host).unwrap();
                    let staged_path = remote.root().join(layout::staged_tree(&dep, &digest));
                    apply_mutation(&staged_path, &mutation);
                    let held = crate::remote::helper::SlotRemote::new(&helper, crate::remote::helper::test_owner("test-app", "s1"))
                        .acquire_lock_guard(&crate::identity::test_operation_id("op-1"))
                        .unwrap();
                    let _ = held.publish_from_incoming(&dep, &digest);
                    drop(held);
                }
                PublishScenario::ExistingHost => {
                    // Publish cleanly first (`publish_tree` re-stages from
                    // the host each time, so the repair always has a source),
                    // then mutate the EXISTING object at the final digest
                    // path and re-publish.
                    let held = crate::remote::helper::SlotRemote::new(&helper, crate::remote::helper::test_owner("test-app", "s1"))
                        .acquire_lock_guard(&crate::identity::test_operation_id("op-1"))
                        .unwrap();
                    held.publish_tree(&digest, &host).unwrap();
                    drop(held);
                    let final_path = remote.root().join(layout::tree_root(&digest));
                    apply_mutation(&final_path, &mutation);
                    let held = crate::remote::helper::SlotRemote::new(&helper, crate::remote::helper::test_owner("test-app", "s1"))
                        .acquire_lock_guard(&crate::identity::test_operation_id("op-2"))
                        .unwrap();
                    let _ = held.publish_tree(&digest, &host);
                    drop(held);
                }
                PublishScenario::ExistingIncoming => {
                    // Publish from incoming (the staged tree is consumed by
                    // the rename), mutate the EXISTING object, re-stage, and
                    // re-publish from incoming: the repair re-publishes the
                    // verified staged tree.
                    helper.stage_incoming(&dep, &digest, &host).unwrap();
                    let held = crate::remote::helper::SlotRemote::new(&helper, crate::remote::helper::test_owner("test-app", "s1"))
                        .acquire_lock_guard(&crate::identity::test_operation_id("op-1"))
                        .unwrap();
                    held.publish_from_incoming(&dep, &digest).unwrap();
                    drop(held);
                    let final_path = remote.root().join(layout::tree_root(&digest));
                    apply_mutation(&final_path, &mutation);
                    helper.stage_incoming(&dep, &digest, &host).unwrap();
                    let held = crate::remote::helper::SlotRemote::new(&helper, crate::remote::helper::test_owner("test-app", "s1"))
                        .acquire_lock_guard(&crate::identity::test_operation_id("op-2"))
                        .unwrap();
                    let _ = held.publish_from_incoming(&dep, &digest);
                    drop(held);
                }
            }

            // THE PROPERTY: the final digest path is either absent or
            // contains exactly the required canonical tree.
            let final_path = remote.root().join(layout::tree_root(&digest));
            match std::fs::symlink_metadata(&final_path) {
                Err(_) => {}
                Ok(_) => {
                    let meta = crate::remote::canonical::canonicalize_tree(&final_path)
                        .expect("a present digest path must canonicalize");
                    prop_assert_eq!(
                        meta.tree_sha256,
                        digest.as_str(),
                        "the digest path must contain exactly the required canonical tree"
                    );
                }
            }
        }
    }
}
