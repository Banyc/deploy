//! The generation assignment record ([`GenerationAssignment`]): the immutable
//! `generations/<gen>/assignment.json` read/create operations, and the
//! immutable OWNER MARKER every read verifies.

use crate::error::{Error, Result};
use crate::identity::{
    ApplicationStoreKey, ArtifactRef, BehaviorDigest, DeploymentId, GenerationId, SlotId,
    TargetName, Timestamp,
};
use crate::remote::layout;
use crate::remote::transport::CreateNewVerdict;
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
    /// The typed behavior digest (exactly 64 lowercase hex — the wire string
    /// routes through [`crate::identity::BehaviorDigest::parse`] on read, so
    /// a record carrying a non-digest is refused fail-closed: the known
    /// state fact is typed, never a loose string).
    pub behavior_sha256: BehaviorDigest,
    #[serde(default)]
    pub prior_generation: Option<GenerationId>,
    /// The typed creation timestamp (canonical RFC 3339 on the wire, parsed
    /// via [`crate::identity::Timestamp::parse`] on read — a malformed
    /// timestamp is refused fail-closed).
    pub created_at: Timestamp,
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
        gen_id: &GenerationId,
        owner: &GenerationOwner,
    ) -> Result<GenerationAssignment> {
        let p = layout::generation(gen_id).join("assignment.json")?;
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

/// The NON-OWNER fields of a generation assignment: the caller supplies the
/// deployment/generation/artifact/behavior/prior/target, and the OWNER
/// (application + slot) is bound by the [`HeldSlotLock`] guard at creation
/// time ([`HeldSlotLock::create_generation`]) — an assignment can never name
/// a different slot than the guard authorizes. The owner is the resource
/// identity the guard was acquired for; a caller cannot pass it as a free
/// parameter.
#[derive(Clone, Debug)]
/// TYPED mutation input (the structural verdict's point 4): a generation
/// install consumes validated values only — a typed [`BehaviorDigest`], a
/// typed [`Timestamp`], and a MANDATORY [`TargetName`]. A caller cannot pass
/// a loose behavior-digest or timestamp string (they are sealed validated
/// types) or omit the owning target (no `Option`): the invalid mutation is
/// unrepresentable. Use is capability-gated: the install methods are on the
/// [`HeldSlotLock`] guard.
pub struct GenerationSpec {
    pub deployment_id: DeploymentId,
    pub generation_id: GenerationId,
    pub artifact: ArtifactRef,
    pub behavior_sha256: BehaviorDigest,
    pub prior_generation: Option<GenerationId>,
    pub created_at: Timestamp,
    pub target: TargetName,
}

impl GenerationSpec {
    /// Build the full assignment, binding the OWNER from the guard: the
    /// record's `application`/`slot` are ALWAYS the guard's owner — never a
    /// caller-supplied value that could name a different slot.
    pub(crate) fn into_assignment(self, owner: &GenerationOwner) -> GenerationAssignment {
        GenerationAssignment {
            deployment_id: self.deployment_id,
            generation_id: self.generation_id,
            artifact: self.artifact,
            behavior_sha256: self.behavior_sha256,
            prior_generation: self.prior_generation,
            created_at: self.created_at,
            application: owner.application.clone(),
            slot: owner.slot.clone(),
            target: Some(self.target),
        }
    }
}

impl GenerationAssignment {
    /// The NON-OWNER fields as a [`GenerationSpec`]: the owner (application +
    /// slot) is bound by the guard at creation time
    /// ([`HeldSlotLock::create_generation`]) — an assignment can never name
    /// a different slot than the guard authorizes. Used by fixtures that
    /// keep the full record for repair/read-back while creating it through
    /// the guard.
    #[cfg(test)]
    pub(crate) fn spec(&self) -> Result<GenerationSpec> {
        // The assignment's known-state facts are TYPED by construction
        // (behavior_sha256/created_at cannot be loose). The target is the
        // one legacy-optional wire field: a spec for a legacy record
        // without a target is refused (the mutation input requires a
        // mandatory owning target — a legacy record cannot drive a new
        // generation-install mutation).
        let target = self.target.as_ref().cloned().ok_or_else(|| {
            Error::integrity(format!(
                "generation {} carries no owning target (a legacy record cannot be re-committed as a generation-install mutation)",
                self.generation_id
            ))
        })?;
        Ok(GenerationSpec {
            deployment_id: self.deployment_id.clone(),
            generation_id: self.generation_id.clone(),
            artifact: self.artifact.clone(),
            behavior_sha256: self.behavior_sha256.clone(),
            prior_generation: self.prior_generation.clone(),
            created_at: self.created_at,
            target,
        })
    }
}

impl<'a> HeldSlotLock<'a> {
    /// Create a generation record and its `root` symlink — the DURABLE
    /// generation-install protocol (stage → fsync contents → rename → fsync
    /// every changed parent directory). Does not move `current`. Requires the
    /// slot-mutation capability — the receiver is the guard; the helper is
    /// the guard's own.
    ///
    /// The assignment is constructed INTERNALLY from the guard's OWNER
    /// ([`GenerationSpec::into_assignment`]): the caller supplies the
    /// non-owner fields (deployment, generation, artifact, behavior, prior,
    /// target) and the record's `application`/`slot` owner marker is ALWAYS
    /// the guard's owner — an assignment can never name a different slot than
    /// the guard authorizes.
    ///
    /// The generation is installed with create-or-compare semantics: a
    /// generation ID colliding with different content fails integrity
    /// instead of silently rewriting history. Generation IDs are fresh
    /// UUIDv7 values minted while holding the slot lock, so this can only
    /// fire on corruption or retry-after-crash with divergent state.
    ///
    /// The install protocol:
    ///
    /// 1. **Create-or-compare**: an EXISTING generation directory is
    ///    verified — the assignment must be byte-identical (the identical
    ///    retry converges; divergent content fails integrity, never
    ///    rewritten) and the `root` symlink is recreated if missing — and
    ///    the changed parent directories are fsynced (idempotent durability
    ///    repair).
    /// 2. **Stage**: the assignment record and the `root` symlink are
    ///    written into a UNIQUE SIBLING staging directory
    ///    (`generations/<gen>.partial-<nonce>`), so a crash or fault at any
    ///    member write leaves at most a disposable staging sibling.
    /// 3. **Staged verify**: the staged assignment is re-read and compared
    ///    against the intended bytes BEFORE anything becomes visible (a
    ///    fault between a write and its verify must never install unverified
    ///    content).
    /// 4. **Fsync**: the whole staged generation is made durable.
    /// 5. **Atomic install**: the verified, fsynced staging directory is
    ///    renamed into the final generation directory — the final generation
    ///    directory is either wholly absent or complete and readable, never
    ///    partial.
    /// 6. **Fsync the changed parent directory**: the PARENT of the final
    ///    generation directory (`generations/`) is fsynced so the renamed
    ///    directory entry survives power loss — the durability commit point.
    ///    FAIL-CLOSED: a failed parent fsync is a propagated `Err`, never a
    ///    reported success.
    ///
    /// Returns the [`DurableGeneration`] EVIDENCE of the durably installed
    /// generation (the sealed witness — the only way a caller can learn the
    /// install succeeded; never a bare `()`).
    pub fn durable_generation_install(
        &self,
        spec: &GenerationSpec,
    ) -> Result<crate::remote::helper::DurableGeneration> {
        let assignment = spec.clone().into_assignment(&self.owner);
        let gen_dir = layout::generation(&assignment.generation_id);
        let json = serde_json::to_vec_pretty(&assignment)
            .map_err(|e| Error::remote(format!("serialize assignment: {e}")))?;
        let assignment_path = gen_dir.join("assignment.json")?;
        let root_link_path = gen_dir.join("root")?;
        let root_link = layout::generation_root_link(&assignment.artifact.tree);

        // 1. Create-or-compare: an EXISTING generation directory is verified
        //    (the identical retry converges; divergent content fails
        //    integrity — history is never rewritten), the `root` symlink is
        //    recreated if missing, and the changed parent directories are
        //    fsynced (idempotent durability repair).
        if self.helper.remote.metadata_opt(&gen_dir)?.is_some() {
            if self.helper.remote.metadata_opt(&assignment_path)?.is_some() {
                let existing = self.helper.remote.read(&assignment_path)?;
                if existing != json {
                    return Err(Error::integrity(format!(
                        "generation {} already exists with different content",
                        assignment.generation_id
                    )));
                }
                // The `root` symlink lives inside `generations/<gen>/`, so it
                // must be relative to that directory (../../objects/...). Its
                // target is derived deterministically from the (now-verified)
                // assignment, so recreating it after a crash is safe.
                if self.helper.remote.metadata_opt(&root_link_path)?.is_none() {
                    self.helper.remote.symlink(&root_link, &root_link_path)?;
                }
                // Fsync the changed parent directories: `generations/` (the
                // `<gen>` entry) and `generations/<gen>/` (the `root` entry,
                // if it was just recreated).
                self.helper.remote.fsync_parent(&gen_dir)?;
                self.helper.remote.fsync_parent(&root_link_path)?;
                return Ok(crate::remote::helper::DurableGeneration::installed(
                    assignment.generation_id,
                ));
            }
            // The generation directory exists but the assignment is missing:
            // a stale empty dir from a crashed earlier attempt. Remove it
            // (restoring write perms) and reinstall cleanly.
            self.helper.remove_remote_tree_restoring_write(&gen_dir)?;
        }

        // 2. Stage: write the assignment + `root` symlink into a unique
        //    sibling directory. The staged assignment is installed with the
        //    durable create-new primitive (`try_write_new` — temp + fsync +
        //    link + parent fsync), the same immutable-record install the old
        //    direct path used, now into the staging directory.
        let nonce = uuid::Uuid::now_v7().to_string();
        let staging = layout::staged_generation(&assignment.generation_id, &nonce);
        // A stale staging dir from a crashed earlier attempt is removed first
        // (restoring write perms), so a retry re-stages cleanly instead of
        // mixing stale and fresh content.
        if self.helper.remote.metadata_opt(&staging)?.is_some() {
            self.helper.remove_remote_tree_restoring_write(&staging)?;
        }
        let res = (|| -> Result<crate::remote::helper::DurableGeneration> {
            self.helper.remote.create_dir_all(&staging)?;
            match self
                .helper
                .remote
                .try_write_new(&staging.join("assignment.json")?, &json)?
            {
                CreateNewVerdict::Created | CreateNewVerdict::AlreadyPresent => {}
                CreateNewVerdict::Conflict(_) => {
                    return Err(Error::integrity(format!(
                        "staged assignment for generation {} conflicts with an existing entry",
                        assignment.generation_id
                    )));
                }
            }
            self.helper
                .remote
                .symlink(&root_link, &staging.join("root")?)?;
            // 3. Staged verify: the staged assignment is re-read and compared
            //    against the intended bytes BEFORE anything becomes visible (a
            //    fault between a write and its verify must never install
            //    unverified content).
            let staged = self.helper.remote.read(&staging.join("assignment.json")?)?;
            if staged != json {
                return Err(Error::integrity(format!(
                    "staged assignment for generation {} does not match the intended record; refusing to install",
                    assignment.generation_id
                )));
            }
            // 4. Fsync the whole staged generation, then 5. atomically install
            //    the directory: the final generation directory is either wholly
            //    absent or complete and readable, never partial.
            self.helper.remote.fsync_tree(&staging)?;
            self.helper.remote.rename(&staging, &gen_dir)?;
            // 6. Fsync the changed parent directory (`generations/`): the
            //    renamed directory entry survives power loss. FAIL-CLOSED: a
            //    failed parent fsync is a propagated error, never a reported
            //    success.
            self.helper.remote.fsync_parent(&gen_dir)?;
            Ok(crate::remote::helper::DurableGeneration::installed(
                assignment.generation_id,
            ))
        })();
        if res.is_err() {
            // Best-effort cleanup of the disposable staging dir (a failed
            // install never leaves a partial generation behind).
            let _ = self.helper.remove_remote_tree_restoring_write(&staging);
        }
        res
    }

    /// Create a generation record and its `root` symlink — the durable
    /// generation-install protocol ([`Self::durable_generation_install`]).
    /// Does not move `current`. Requires the slot-mutation capability — the
    /// receiver is the guard; the helper is the guard's own. Returns the
    /// [`DurableGeneration`] EVIDENCE of the durably installed generation.
    pub fn create_generation(
        &self,
        spec: &GenerationSpec,
    ) -> Result<crate::remote::helper::DurableGeneration> {
        self.durable_generation_install(spec)
    }
}

#[cfg(test)]
mod tests_assignment {
    use super::*;
    use crate::identity::{test_deployment_id, test_generation_id, test_tree_digest};
    use crate::remote::transport::{LocalTransport, Remote};
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    fn assignment(gen_id: &str, tree: &str) -> GenerationSpec {
        GenerationSpec {
            deployment_id: test_deployment_id("deploy-1"),
            generation_id: test_generation_id(gen_id),
            artifact: ArtifactRef {
                release: crate::identity::test_release_id("rel-sha256-x"),
                variant: crate::identity::VariantName::parse("standard").unwrap(),
                tree: crate::identity::test_tree_digest(tree),
            },
            behavior_sha256: crate::identity::test_behavior_digest("b"),
            prior_generation: None,
            created_at: crate::identity::Timestamp::parse("2020-01-01T00:00:00Z").unwrap(),
            target: TargetName::new("t1"),
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
        let slot = crate::remote::helper::SlotRemote::new(&helper, owner());
        let _guard = slot
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
            .read_assignment(&test_generation_id("gen-1"), &owner)
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

            // Build the record bytes, then apply the tamper class. The
            // record is the FULL assignment (owner bound from the fixture
            // owner — the same owner the reads verify against).
            let asn = assignment(&tag, "tree-a").into_assignment(&owner());
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
            let p = crate::remote::layout::generation(&gen_id).join("assignment.json").unwrap();
            remote.create_dir_all(&p.parent().unwrap()).unwrap();
            remote.write(&p, &bytes, 0o600).unwrap();

            // read_assignment: ACCEPT the exact match, REFUSE every tamper.
            let read = helper.read_assignment(&gen_id, &owner());
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
            let gen_dir = crate::remote::layout::generation(&gen_id);
            if tamper == 0 {
                remote
                    .create_dir_all(&crate::remote::layout::tree_root(&asn.artifact.tree))
                    .unwrap();
                let root_link =
                    crate::remote::layout::generation_root_link(&asn.artifact.tree);
                remote.symlink(&root_link, &gen_dir.join("root").unwrap()).unwrap();
                remote
                    .symlink(
                        gen_dir.join("root").unwrap().as_path(),
                        crate::remote::layout::current(),
                    )
                    .unwrap();
                let st = helper
                    .status(&owner())
                    .expect("an exact owner match must status the generation");
                assert_eq!(st.current_generation(), Some(&gen_id));
            } else {
                remote
                    .create_dir_all(&crate::remote::layout::tree_root(&asn.artifact.tree))
                    .unwrap();
                let root_link =
                    crate::remote::layout::generation_root_link(&asn.artifact.tree);
                remote.symlink(&root_link, &gen_dir.join("root").unwrap()).unwrap();
                remote
                    .symlink(
                        gen_dir.join("root").unwrap().as_path(),
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
