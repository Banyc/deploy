//! Object-store publication and staging: tree/release publication
//! ([`HeldSlotLock::publish_tree`], [`HeldSlotLock::publish_from_incoming`],
//! [`RemoteHelper::publish_release`]), incoming staging, and the two-phase
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

use crate::error::{Error, Result};
use crate::identity::{DeploymentId, ReleaseId, ReleaseRecord, TreeDigest};
use crate::remote::layout;
use crate::remote::transport::{
    ContentEquivalence, CreateNewVerdict, Remote, RootedRelativePath, VerifiedExisting,
};
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
    fn remove_remote_tree_restoring_write(&self, rel: &RootedRelativePath) -> Result<()> {
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

    pub fn publish_release(
        &self,
        release_id: &ReleaseId,
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
        crate::verify::release::verify_release_identity(&rec)?;
        if rec.release_id != release_id.as_str() {
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
        crate::verify::release::verify_behavior_json(
            behavior_json.as_bytes(),
            &rec.release_id,
            &rec.provenance.behavior_sha256,
        )?;
        let dir = layout::remote_release(release_id);
        // The release record is identified by its canonical digest
        // (`release_sha256`), not by semantic equality of the full document:
        // metadata fields such as `created_at`
        // legitimately differ between runs of the same canonical release, so
        // byte/semantic comparison of the whole record would falsely reject
        // idempotent re-publication. Two records with the same recomputed
        // digest are the same release.
        let rel = dir.join("release.json")?;
        if self.remote.metadata_opt(&rel)?.is_none() {
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
            // `created_at` is excluded from the digest, so it
            // may differ between runs of the same canonical release).
            let existing = self.remote.read(&rel)?;
            let existing_rec: ReleaseRecord = serde_json::from_slice(&existing).map_err(|e| {
                Error::integrity(format!(
                    "malformed existing release record at {}: {e}",
                    rel.display()
                ))
            })?;
            crate::verify::release::verify_release_identity(&existing_rec)?;
            if existing_rec.release_sha256 != rec.release_sha256 {
                return Err(Error::integrity(format!(
                    "refusing to replace existing {} with a different release",
                    rel.display()
                )));
            }
        }
        self.publish_release_file(&dir.join("behavior.json")?, behavior_json.as_bytes())
    }

    /// Install one immutable release-side file with create-or-compare
    /// semantics: the first writer wins via an exclusive create; a subsequent
    /// writer must observe equivalent content or fail. Equivalence is
    /// SEMANTIC for JSON (key order and whitespace may differ between
    /// serializations of the same contract) and byte-exact otherwise — the
    /// caller's requested [`ContentEquivalence::Semantic`] is passed INTO the
    /// transport, so the centralized verification applies it directly.
    fn publish_release_file(&self, rel: &RootedRelativePath, data: &[u8]) -> Result<()> {
        // The TYPED verdict: `Created`/`AlreadyPresent` (the existing entry
        // verified as a regular file with the exact mode and SEMANTICALLY
        // equivalent content — the idempotent re-publication) are success;
        // a `Conflict` carries the TYPED reason: only a CONTENT mismatch
        // keeps the caller-layer semantic read-back (for transports whose
        // default `try_write_new_with` could not apply the equivalence
        // directly), while a METADATA conflict — a directory/symlink where
        // the immutable record should be, a mode mismatch, an unreadable
        // entry — is a REAL conflict, never silently accepted as equivalent.
        match self
            .remote
            .try_write_new_with(rel, data, ContentEquivalence::Semantic)?
        {
            CreateNewVerdict::Created | CreateNewVerdict::AlreadyPresent => Ok(()),
            CreateNewVerdict::Conflict(reason) => match reason {
                VerifiedExisting::ContentMismatch => {
                    // Type and mode were verified; only the content differs.
                    // The caller's semantic equivalence decides: JSON-equal is
                    // the same contract re-serialized (accepted); anything
                    // else is an integrity conflict.
                    let existing = self.remote.read(rel)?;
                    if json_semantically_equal(&existing, data) {
                        return Ok(());
                    }
                    Err(Error::integrity(format!(
                        "refusing to replace existing {} with different content",
                        rel.display()
                    )))
                }
                VerifiedExisting::ModeMismatch { actual, required } => {
                    Err(Error::integrity(format!(
                        "refusing to replace existing {} with a different mode ({actual:o} != {required:o})",
                        rel.display()
                    )))
                }
                VerifiedExisting::NotRegularFile { kind } => Err(Error::integrity(format!(
                    "refusing to replace existing {} with a {kind:?} entry",
                    rel.display()
                ))),
                VerifiedExisting::Unreadable(e) => Err(Error::integrity(format!(
                    "existing {} is unreadable: {e}",
                    rel.display()
                ))),
                VerifiedExisting::NotFound => Err(Error::integrity(format!(
                    "existing {} vanished during verification",
                    rel.display()
                ))),
                VerifiedExisting::Ok { .. } => {
                    unreachable!("a verified-ok entry is AlreadyPresent, never Conflict")
                }
            },
        }
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
    pub fn publish_from_incoming(
        &self,
        deployment_id: &DeploymentId,
        digest: &TreeDigest,
    ) -> Result<()> {
        let from = layout::staged_tree(deployment_id, digest);
        let to = layout::tree_root(digest);
        // Reuse: verify the existing object; quarantine + repair invalid
        // content (under the slot lock).
        if self.helper.tree_exists(digest)? {
            if self.helper.verify_remote_tree(&to, digest)? {
                return Ok(());
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

    /// Publish a host-local tree into the object store. Requires the
    /// slot-mutation capability. The complete remote object is assembled in a
    /// deployment-independent staging directory, verified there, and
    /// atomically published; an existing object is verified before reuse and
    /// invalid content is quarantined and repaired (under the slot lock).
    pub fn publish_tree(&self, digest: &TreeDigest, host_src: &Path) -> Result<()> {
        let to = layout::tree_root(digest);
        // Reuse: verify the existing object; quarantine + repair invalid
        // content (under the slot lock).
        if self.helper.tree_exists(digest)? {
            if self.helper.verify_remote_tree(&to, digest)? {
                return Ok(());
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

    /// Publish a tree object from a host-local path (used when no prior
    /// incoming staging occurred). Requires the slot-mutation capability.
    pub fn publish_tree_from_host(&self, digest: &TreeDigest, host_src: &Path) -> Result<()> {
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

    /// Atomically publish a verified staged tree into the final digest path:
    /// the staged tree is canonicalized and compared against the required
    /// digest BEFORE the rename, so the digest path is either absent or
    /// contains exactly the verified canonical tree — never a partial or
    /// corrupt object.
    fn publish_staged_tree(&self, digest: &TreeDigest, staging: &RootedRelativePath) -> Result<()> {
        let to = layout::tree_root(digest);
        if !self.helper.verify_remote_tree(staging, digest)? {
            return Err(Error::integrity(format!(
                "staged tree {} does not canonicalize to {}; refusing to publish",
                staging.display(),
                digest.as_str()
            )));
        }
        self.helper.remote.create_dir_all(&to.parent().unwrap())?;
        self.helper.remote.rename(staging, &to)?;
        Ok(())
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

/// Compare two serialized JSON documents semantically: equal when they parse
/// to equal `serde_json` values (object key order and whitespace are not part
/// of the contract). Falls back to byte equality when either side is not JSON.
/// Delegates to THE centralized comparison
/// ([`crate::remote::transport::content_equivalent`]) so the transport's
/// verification and the caller-layer fallback can never drift.
fn json_semantically_equal(a: &[u8], b: &[u8]) -> bool {
    crate::remote::transport::content_equivalent(a, b, ContentEquivalence::Semantic)
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
pub fn copy_host_tree_to_remote(
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
mod tests_publish {
    use super::*;
    use crate::remote::transport::LocalTransport;
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
    fn publish_fixture() -> (crate::identity::ReleaseRecord, String) {
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

    /// `publish_release` recomputes the canonical digest from the serialized
    /// record's content and verifies it against the stored identity before
    /// installing anything: a pristine record publishes (and re-publishes
    /// idempotently), while a record whose slot declaration was edited with the
    /// old `release_sha256`/`release_id` retained fails closed with an
    /// integrity error — a release whose identity does not match its content is
    /// never published.
    #[test]
    fn publish_release_recomputes_and_verifies_identity() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let helper = RemoteHelper::new(&remote);
        let (rec, behavior_json) = publish_fixture();
        let release_json = serde_json::to_string(&rec).unwrap();

        // Positive case: the pristine record publishes, and re-publishing the
        // identical release is an idempotent no-op.
        helper
            .publish_release(
                &ReleaseId::parse(&rec.release_id).expect("fixture release id"),
                &release_json,
                &behavior_json,
            )
            .expect("pristine record publishes");
        helper
            .publish_release(
                &ReleaseId::parse(&rec.release_id).expect("fixture release id"),
                &release_json,
                &behavior_json,
            )
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
                &ReleaseId::parse(&rec.release_id).expect("fixture release id"),
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
            .publish_release(
                &ReleaseId::parse(&rec.release_id).expect("fixture release id"),
                "{}",
                &behavior_json,
            )
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
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let helper = RemoteHelper::new(&remote);
        let (rec, behavior_json) = publish_fixture();
        let release_json = serde_json::to_string(&rec).unwrap();
        helper
            .publish_release(
                &ReleaseId::parse(&rec.release_id).expect("fixture release id"),
                &release_json,
                &behavior_json,
            )
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
            let rel = layout::remote_release(
                &ReleaseId::parse(&rec.release_id).expect("fixture release id"),
            )
            .join("release.json")
            .unwrap();
            remote
                .write(&rel, &serde_json::to_vec(&stored).unwrap(), 0o644)
                .unwrap();
            let helper = RemoteHelper::new(&remote);
            let fail_msg =
                format!("{name}: republishing against a corrupted remote record must fail closed");
            let err = helper
                .publish_release(
                    &ReleaseId::parse(&rec.release_id).expect("fixture release id"),
                    &release_json,
                    &behavior_json,
                )
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
        let bpath =
            layout::remote_release(&ReleaseId::parse(&rec.release_id).expect("fixture release id"))
                .join("behavior.json")
                .unwrap();
        remote.write(&bpath, b"{\"tampered\":", 0o644).unwrap();
        let helper = RemoteHelper::new(&remote);
        let err = helper
            .publish_release(
                &ReleaseId::parse(&rec.release_id).expect("fixture release id"),
                &release_json,
                &behavior_json,
            )
            .expect_err("a corrupted remote behavior.json must fail republish");
        assert!(
            err.to_string().contains("different content"),
            "error must name the create-or-compare refusal, got: {err}"
        );

        // Malformed existing release.json is refused outright, never silently
        // replaced.
        let (_dir, remote, rec, release_json, behavior_json) = published_release_fixture();
        let rel =
            layout::remote_release(&ReleaseId::parse(&rec.release_id).expect("fixture release id"))
                .join("release.json")
                .unwrap();
        remote.write(&rel, b"{ not json", 0o644).unwrap();
        let helper = RemoteHelper::new(&remote);
        let err = helper
            .publish_release(
                &ReleaseId::parse(&rec.release_id).expect("fixture release id"),
                &release_json,
                &behavior_json,
            )
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
            let (_dir, remote, rec, release_json, behavior_json) = published_release_fixture();
            let mut stored = serde_json::to_value(&rec).unwrap();
            mutate(&mut stored);
            let rel = layout::remote_release(
                &ReleaseId::parse(&rec.release_id).expect("fixture release id"),
            )
            .join("release.json")
            .unwrap();
            remote
                .write(&rel, &serde_json::to_vec(&stored).unwrap(), 0o644)
                .unwrap();
            let helper = RemoteHelper::new(&remote);
            let ok_msg =
                format!("{name}: a metadata-only difference keeps the republish idempotent");
            helper
                .publish_release(
                    &ReleaseId::parse(&rec.release_id).expect("fixture release id"),
                    &release_json,
                    &behavior_json,
                )
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
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let helper = RemoteHelper::new(&remote);
        let (rec, behavior_json) = publish_fixture();
        let release_json = serde_json::to_string(&rec).unwrap();
        let rid = rec.release_id.as_str();

        // Baseline: the canonical behavior payload publishes.
        helper
            .publish_release(
                &ReleaseId::parse(rid).expect("fixture release id"),
                &release_json,
                &behavior_json,
            )
            .expect("pristine behavior publishes");

        let publish = |label: &str, payload: &str| {
            let err = helper
                .publish_release(
                    &ReleaseId::parse(rid).expect("fixture release id"),
                    &release_json,
                    payload,
                )
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
            .publish_release(
                &ReleaseId::parse(rid).expect("fixture release id"),
                &release_json,
                reordered,
            )
            .expect("a digest-equal key reorder must publish");
    }

    /// A MODE-MISMATCHED existing release file is a REAL conflict for the
    /// SEMANTIC caller too — the old read-back comparison only checked
    /// content, so a mode-mismatched-but-content-equivalent winner was
    /// silently accepted as "already present, fine". The typed
    /// `ModeMismatch` reason now fails the republish closed: the mode is
    /// part of the immutable record.
    #[test]
    fn publish_release_file_mode_mismatch_is_a_real_conflict() {
        let (_dir, remote, rec, release_json, behavior_json) = published_release_fixture();
        // Corrupt ONLY the mode of the existing behavior.json (content stays
        // the semantically-equal pristine payload).
        let bpath =
            layout::remote_release(&ReleaseId::parse(&rec.release_id).expect("fixture release id"))
                .join("behavior.json")
                .unwrap();
        let other_mode = if crate::remote::transport::IMMUTABLE_RECORD_MODE & 0o7777 == 0o600 {
            0o640
        } else {
            0o600
        };
        remote.set_mode(&bpath, other_mode).unwrap();
        let helper = RemoteHelper::new(&remote);
        let err = helper
            .publish_release(
                &ReleaseId::parse(&rec.release_id).expect("fixture release id"),
                &release_json,
                &behavior_json,
            )
            .expect_err(
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
