//! The generation assignment record ([`GenerationAssignment`]): the immutable
//! `generations/<gen>/assignment.json` read/create operations.

use crate::error::{Error, Result};
use crate::identity::{ArtifactRef, DeploymentId, GenerationId, TargetName};
use crate::remote::layout;
use crate::remote::transport::{CreateNewVerdict, VerifiedExisting};
use serde::{Deserialize, Serialize};

use super::super::RemoteHelper;

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

impl<'a> RemoteHelper<'a> {
    pub fn read_assignment(&self, gen_id: &str) -> Result<GenerationAssignment> {
        let p = layout::generation(gen_id).join("assignment.json");
        let data = self.remote.read(&p)?;
        serde_json::from_slice(&data).map_err(|e| Error::remote(format!("parse assignment: {e}")))
    }

    /// Create a generation record and its `root` symlink. Does not move
    /// `current`. Requires the slot-mutation capability — only callable via
    /// `HeldSlotLock::create_generation` (the receiver is the guard; the helper
    /// is the guard's own — a guard can only mutate the slot it was acquired
    /// from; there is no API parameter through which a guard from server A can
    /// authorize a mutation on server B).
    ///
    /// The assignment record is immutable and installed with create-or-compare
    /// semantics: a generation ID colliding with different content fails
    /// integrity instead of silently rewriting history. Generation IDs are
    /// fresh UUIDv7 values minted while holding the slot lock, so this can
    /// only fire on corruption or retry-after-crash with divergent state.
    pub(crate) fn create_generation_locked(&self, assignment: &GenerationAssignment) -> Result<()> {
        let gen_dir = layout::generation(assignment.generation_id.as_str());
        self.remote.create_dir_all(&gen_dir)?;
        let json = serde_json::to_vec_pretty(assignment)
            .map_err(|e| Error::remote(format!("serialize assignment: {e}")))?;
        let assignment_path = gen_dir.join("assignment.json");
        // The TYPED verdict: `Created`/`AlreadyPresent` (the identical retry)
        // skip the read-back; a `Conflict` carries the TYPED reason — the
        // winner is never replaced, and a metadata conflict (a
        // directory/symlink where the record should be, a mode mismatch, an
        // unreadable entry) is a REAL conflict, never accepted as "already
        // present, fine".
        match self.remote.try_write_new(&assignment_path, &json)? {
            CreateNewVerdict::Created | CreateNewVerdict::AlreadyPresent => {}
            CreateNewVerdict::Conflict(reason) => match reason {
                VerifiedExisting::ContentMismatch => {
                    return Err(Error::integrity(format!(
                        "generation {} already exists with different content",
                        assignment.generation_id
                    )));
                }
                VerifiedExisting::ModeMismatch { actual, required } => {
                    return Err(Error::integrity(format!(
                        "generation {} already exists with mode {actual:o} (required {required:o})",
                        assignment.generation_id
                    )));
                }
                VerifiedExisting::NotRegularFile { kind } => {
                    return Err(Error::integrity(format!(
                        "generation {} already exists as a {kind:?} entry, not a regular file",
                        assignment.generation_id
                    )));
                }
                VerifiedExisting::Unreadable(e) => {
                    return Err(Error::integrity(format!(
                        "generation {} already exists but could not be verified: {e}",
                        assignment.generation_id
                    )));
                }
                VerifiedExisting::NotFound => {
                    return Err(Error::integrity(format!(
                        "generation {} vanished during verification",
                        assignment.generation_id
                    )));
                }
                VerifiedExisting::Ok { .. } => {
                    unreachable!("a verified-ok entry is AlreadyPresent, never Conflict")
                }
            },
        }
        // The `root` symlink lives inside `generations/<gen>/`, so it must be
        // relative to that directory (../../objects/...). Its target is derived
        // deterministically from the (now-verified) assignment, so recreating
        // it after a crash is safe.
        let root_link_path = gen_dir.join("root");
        if self.remote.metadata_opt(&root_link_path)?.is_none() {
            let root_link = layout::generation_root_link(assignment.artifact.tree.as_str());
            self.remote.symlink(&root_link, &root_link_path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests_assignment {
    use super::*;
    use crate::identity::{test_deployment_id, test_generation_id, test_tree_digest};
    use crate::remote::transport::{LocalTransport, Remote};

    fn assignment(gen_id: &str, tree: &str) -> GenerationAssignment {
        GenerationAssignment {
            deployment_id: test_deployment_id("deploy-1"),
            generation_id: test_generation_id(gen_id),
            artifact: ArtifactRef {
                release: crate::identity::test_release_id("rel-sha256-x"),
                variant: crate::identity::VariantName::new("standard".to_string()),
                tree: crate::identity::test_tree_digest(tree),
            },
            behavior_sha256: "b".to_string(),
            prior_generation: None,
            created_at: "2020-01-01T00:00:00Z".to_string(),
            target: Some(TargetName::new("t1")),
        }
    }

    /// A generation record is immutable: installed with create-or-compare, so
    /// an ID collision with divergent content fails integrity instead of
    /// rewriting history, and the original record survives untouched.
    #[test]
    fn generation_assignment_is_create_or_compare() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let helper = RemoteHelper::new(&remote);
        let _guard = helper
            .acquire_lock_guard(&crate::identity::OperationId::new("op".to_string()))
            .unwrap();

        _guard
            .create_generation(&assignment("gen-1", "tree-a"))
            .expect("first create");
        // Identical recreation (retry after crash) is idempotent.
        _guard
            .create_generation(&assignment("gen-1", "tree-a"))
            .expect("identical recreation is idempotent");

        // Divergent content for the same generation ID fails integrity...
        let err = _guard
            .create_generation(&assignment("gen-1", "tree-TAMPERED"))
            .expect_err("divergent generation rewrite must fail");
        assert!(
            err.to_string().contains("different content"),
            "error must name the immutability violation, got: {err}"
        );

        // ...and the original record survives. (The `root` symlink may dangle
        // here — no object was published in this test — so assert on the link
        // itself rather than its resolved target.)
        let a = helper
            .read_assignment(test_generation_id("gen-1").as_str())
            .unwrap();
        assert_eq!(
            a.artifact.tree.as_str(),
            test_tree_digest("tree-a").as_str()
        );
        assert!(
            std::fs::symlink_metadata(
                remote
                    .root()
                    .join(format!("generations/{}/root", test_generation_id("gen-1")))
            )
            .is_ok(),
            "generation root symlink must exist"
        );
    }
}
