//! The generation assignment record ([`GenerationAssignment`]): the immutable
//! `generations/<gen>/assignment.json` read/create operations, and the
//! immutable OWNER MARKER every read verifies.

use crate::error::{Error, Result};
use crate::identity::{
    ApplicationStoreKey, ArtifactRef, DeploymentId, GenerationId, SlotId, TargetName,
};
use crate::remote::layout;
use crate::remote::transport::{CreateNewVerdict, VerifiedExisting};
use serde::{Deserialize, Serialize};

use super::super::{GenerationOwner, HeldSlotLock, RemoteHelper};

/// The remote generation record (`generations/<gen>/assignment.json`). The
/// artifact relationship is expressed via the canonical [`ArtifactRef`]; the
/// ID fields are the (string-shaped on the wire) typed newtypes so the JSON
/// stays `{deployment_id, generation_id, artifact: {release, variant, tree},
/// behavior_sha256, prior_generation, created_at, application, slot,
/// target}`.
///
/// ## The immutable owner marker
///
/// `application` + `slot` are the generation's OWNER MARKER: the immutable
/// identity of the application + placement slot the generation was created
/// for, written at generation-creation time and verified by EVERY read
/// ([`RemoteHelper::read_assignment`] and [`RemoteHelper::status`] require
/// the caller's expected [`GenerationOwner`] to match). A generation record
/// whose owner marker disagrees — transplanted/copied state from another
/// application or slot — is REFUSED (fail closed), never read as a valid
/// deployment. The fields are REQUIRED on the wire: a legacy record written
/// before the marker existed fails deserialization (fail closed — a record
/// without the marker is invalid, never silently accepted).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenerationAssignment {
    pub deployment_id: DeploymentId,
    pub generation_id: GenerationId,
    pub artifact: ArtifactRef,
    pub behavior_sha256: String,
    #[serde(default)]
    pub prior_generation: Option<GenerationId>,
    pub created_at: String,
    /// THE OWNER MARKER, application half: the application whose store this
    /// generation belongs to. Required (no `#[serde(default)]`): a record
    /// without it is invalid and fails closed at every read.
    pub application: ApplicationStoreKey,
    /// THE OWNER MARKER, slot half: the placement slot this generation was
    /// created for. Required (no `#[serde(default)]`): a record without it is
    /// invalid and fails closed at every read.
    pub slot: SlotId,
    /// The target whose push created this generation record: a generation is
    /// attributed to the target whose push created it (each slot belongs to
    /// exactly one owning target, so that target is also the slot's owner);
    /// `None` marks a LEGACY record written before this field existed
    /// (retained conservatively — unlike the application/slot owner marker,
    /// the target is not required).
    #[serde(default)]
    pub target: Option<TargetName>,
}

impl<'a> RemoteHelper<'a> {
    /// Read a generation's assignment record AND VERIFY ITS OWNER MARKER:
    /// the record's `application`/`slot` must match the caller's expected
    /// [`GenerationOwner`] exactly — a generation whose owner marker
    /// disagrees (transplanted/copied state) is REFUSED with an integrity
    /// error, never returned as a valid assignment. A record that cannot be
    /// parsed (including a legacy record WITHOUT the owner fields) fails
    /// closed the same way.
    pub fn read_assignment(
        &self,
        gen_id: &str,
        owner: &GenerationOwner,
    ) -> Result<GenerationAssignment> {
        let p = layout::generation(gen_id).join("assignment.json");
        let data = self.remote.read(&p)?;
        let assignment: GenerationAssignment = serde_json::from_slice(&data).map_err(|e| {
            Error::integrity(format!(
                "generation {gen_id} has a malformed or ownerless assignment (parse assignment: {e}; a legacy record without the owner marker is refused)"
            ))
        })?;
        Self::verify_owner(&assignment, owner)?;
        Ok(assignment)
    }

    /// Verify a generation assignment's OWNER MARKER against the expected
    /// owner: the record's `application`/`slot` must equal the expected
    /// application/slot exactly. A mismatch is an integrity error (fail
    /// closed): a generation transplanted from another application or slot
    /// is never read as a valid deployment.
    pub(crate) fn verify_owner(
        assignment: &GenerationAssignment,
        owner: &GenerationOwner,
    ) -> Result<()> {
        if assignment.application != owner.application || assignment.slot != owner.slot {
            return Err(Error::integrity(format!(
                "generation {} owner marker mismatch: the record belongs to application '{}' slot '{}', but the expected owner is application '{}' slot '{}' (transplanted/copied state is refused)",
                assignment.generation_id,
                assignment.application,
                assignment.slot,
                owner.application,
                owner.slot,
            )));
        }
        Ok(())
    }
}

impl<'a> HeldSlotLock<'a> {
    /// Create a generation record and its `root` symlink. Does not move
    /// `current`. Requires the slot-mutation capability — the receiver is the
    /// guard; the helper is the guard's own.
    ///
    /// The assignment record is immutable and installed with create-or-compare
    /// semantics: a generation ID colliding with different content fails
    /// integrity instead of silently rewriting history. Generation IDs are
    /// fresh UUIDv7 values minted while holding the slot lock, so this can
    /// only fire on corruption or retry-after-crash with divergent state.
    pub fn create_generation(&self, assignment: &GenerationAssignment) -> Result<()> {
        let gen_dir = layout::generation(assignment.generation_id.as_str());
        self.helper.remote.create_dir_all(&gen_dir)?;
        let json = serde_json::to_vec_pretty(assignment)
            .map_err(|e| Error::remote(format!("serialize assignment: {e}")))?;
        let assignment_path = gen_dir.join("assignment.json");
        // The TYPED verdict: `Created`/`AlreadyPresent` (the identical retry)
        // skip the read-back; a `Conflict` carries the TYPED reason — the
        // winner is never replaced, and a metadata conflict (a
        // directory/symlink where the record should be, a mode mismatch, an
        // unreadable entry) is a REAL conflict, never accepted as "already
        // present, fine".
        match self.helper.remote.try_write_new(&assignment_path, &json)? {
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
        if self.helper.remote.metadata_opt(&root_link_path)?.is_none() {
            let root_link = layout::generation_root_link(assignment.artifact.tree.as_str());
            self.helper.remote.symlink(&root_link, &root_link_path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests_assignment {
    use super::*;
    use crate::identity::{test_deployment_id, test_generation_id, test_tree_digest};
    use crate::remote::transport::{LocalTransport, Remote};
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    fn assignment(gen_id: &str, tree: &str) -> GenerationAssignment {
        GenerationAssignment {
            deployment_id: test_deployment_id("deploy-1"),
            generation_id: test_generation_id(gen_id),
            artifact: ArtifactRef {
                release: crate::identity::test_release_id("rel-sha256-x"),
                variant: crate::identity::VariantName::parse("standard").unwrap(),
                tree: crate::identity::test_tree_digest(tree),
            },
            behavior_sha256: "b".to_string(),
            prior_generation: None,
            created_at: "2020-01-01T00:00:00Z".to_string(),
            application: crate::identity::ApplicationStoreKey::parse("test-app").unwrap(),
            slot: crate::identity::SlotId::parse("s1").unwrap(),
            target: Some(TargetName::new("t1")),
        }
    }

    /// The expected owner of the fixture assignments: application `test-app`,
    /// slot `s1`.
    fn owner() -> GenerationOwner {
        crate::remote::helper::test_owner("test-app", "s1")
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
        let owner = crate::remote::helper::test_owner("test-app", "s1");
        let a = helper
            .read_assignment(test_generation_id("gen-1").as_str(), &owner)
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

    // -------------------------------------------------------------------
    // THE OWNER-MARKER PROPERTY (the review's acceptance): generate a VALID
    // generation record plus a TAMPER mode (0 = exact match, 1 = wrong
    // application, 2 = wrong slot, 3 = missing owner marker) and assert
    // every read REFUSES the mismatch (fail closed — `read_assignment` and
    // `status` both error) and ACCEPTS the exact match. Bounded 64 cases
    // (16 fast, 64 with DEPLOY_FULL_TESTS=1), fixed seed 0x5EED_5EED per
    // house style.
    // -------------------------------------------------------------------
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(64),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn owner_marker_agreement_refuses_mismatch(
            tag in "[a-z0-9]{1,8}",
            tamper in 0u8..4,
        ) {
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let remote =
                LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                    .unwrap();
            let helper = RemoteHelper::new(&remote);

            // Build the record bytes, then apply the tamper class.
            let asn = assignment(&tag, "tree-a");
            let mut value = serde_json::to_value(&asn).unwrap();
            let tampered = match tamper {
                0 => None,
                1 => {
                    // Wrong APPLICATION: the record was transplanted from
                    // another application.
                    value["application"] = serde_json::json!("other-app");
                    Some("owner marker mismatch")
                }
                2 => {
                    // Wrong SLOT: the record was transplanted from another
                    // slot.
                    value["slot"] = serde_json::json!("other-slot");
                    Some("owner marker mismatch")
                }
                _ => {
                    // MISSING owner marker: a legacy record written before
                    // the marker existed is invalid (fail closed).
                    let obj = value.as_object_mut().unwrap();
                    obj.remove("application");
                    obj.remove("slot");
                    Some("malformed or ownerless")
                }
            };
            let bytes = serde_json::to_vec_pretty(&value).unwrap();
            let gen_id = test_generation_id(&tag);
            let p = crate::remote::layout::generation(gen_id.as_str()).join("assignment.json");
            remote.create_dir_all(p.parent().unwrap()).unwrap();
            remote.write(&p, &bytes, 0o600).unwrap();

            // read_assignment: ACCEPT the exact match, REFUSE every tamper.
            let read = helper.read_assignment(gen_id.as_str(), &owner());
            match tampered {
                None => assert!(
                    read.is_ok(),
                    "an exact owner match must read: {read:?}"
                ),
                Some(expected) => {
                    let err = read.expect_err("a mismatched owner must be refused");
                    assert!(
                        err.to_string().contains(expected),
                        "the refusal must name the owner class ({expected:?}), got: {err}"
                    );
                }
            }

            // status(): the same fail-closed contract over the whole chain —
            // but status also needs the tree object + root symlink to
            // succeed, so for the ACCEPT case install the full canonical
            // chain and assert status reports the generation; for the REFUSE
            // cases the owner failure fires at the assignment read, before
            // the tree check.
            let gen_dir = crate::remote::layout::generation(gen_id.as_str());
            if tamper == 0 {
                remote
                    .create_dir_all(&crate::remote::layout::tree_root(
                        asn.artifact.tree.as_str(),
                    ))
                    .unwrap();
                let root_link =
                    crate::remote::layout::generation_root_link(asn.artifact.tree.as_str());
                remote.symlink(&root_link, &gen_dir.join("root")).unwrap();
                remote
                    .symlink(
                        &gen_dir.join("root"),
                        crate::remote::layout::current(),
                    )
                    .unwrap();
                let st = helper
                    .status(&owner())
                    .expect("an exact owner match must status the generation");
                assert_eq!(st.current_generation(), Some(&gen_id));
            } else {
                remote
                    .create_dir_all(&crate::remote::layout::tree_root(
                        asn.artifact.tree.as_str(),
                    ))
                    .unwrap();
                let root_link =
                    crate::remote::layout::generation_root_link(asn.artifact.tree.as_str());
                remote.symlink(&root_link, &gen_dir.join("root")).unwrap();
                remote
                    .symlink(
                        &gen_dir.join("root"),
                        crate::remote::layout::current(),
                    )
                    .unwrap();
                let err = helper
                    .status(&owner())
                    .expect_err("a mismatched owner must fail status closed");
                assert!(
                    err.to_string().contains("integrity"),
                    "the status failure must be an integrity error, got: {err}"
                );
            }
        }
    }
}
