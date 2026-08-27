//! The generation assignment record ([`GenerationAssignment`]): the immutable
//! `generations/<gen>/assignment.json` read/create operations.

use crate::error::{Error, Result};
use crate::identity::{ArtifactRef, DeploymentId, GenerationId, TargetName};
use crate::remote::layout;
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
