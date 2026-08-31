//! THE ONE PROOF-BEARING SLOT MUTATION (the structural verdict's point 4):
//! every slot mutation consumes ONE [`PreparedSlotMutation`] value — the
//! complete, typed, validated intent of one slot's publication — through the
//! ONE mutation entry point [`commit`], which returns the sealed
//! [`SlotCommitProof`]. No mutation method accepts loose generation IDs,
//! strings, slot lists, targets, timestamps, or behavior digests: the
//! mutation carries the typed [`BehaviorDigest`] and [`Timestamp`], the
//! typed [`TargetName`], the typed [`ExpectedCurrent`] (the verified
//! current state), the validated release bundle, and the verified tree
//! digest.
//!
//! The mutation is DERIVED from the validated release
//! ([`ValidatedReleaseBundle`]), the verified tree (the canonicalized
//! [`TreeDigest`]), the verified current state (the status read's
//! [`ExpectedCurrent`]), and the persisted intent (the deployment's
//! [`DeploymentIntent`] projections — the artifact, the minted generation,
//! the behavior digest). The fields are PRIVATE and the ONLY construction
//! path ([`PreparedSlotMutation::new`]) validates every relationship, so a
//! mutation whose parts could disagree with the persisted intent is
//! unrepresentable.
//!
//! [`commit`] performs the four durable slot mutations in the ONE order
//! (publish the release bundle → install the generation → record the
//! transaction → swap `current`) and returns the [`SlotCommitProof`] — the
//! sealed witness carrying the [`DurableRelease`], [`DurableGeneration`],
//! and [`DurableCurrent`] evidence of the durable effects. A caller cannot
//! fabricate the proof: it can only be obtained by successfully committing
//! the mutation.

use crate::error::Result;
use crate::identity::{
    ArtifactRef, BehaviorDigest, DeploymentId, GenerationId, OperationId, TargetName, Timestamp,
};
use crate::remote::helper::HeldSlotLock;
use crate::remote::helper::{DurableCurrent, DurableGeneration, DurableRelease, ExpectedCurrent};
use crate::verify::release::ValidatedReleaseBundle;

/// THE ONE PROOF-BEARING SLOT MUTATION: the complete, typed, validated
/// intent of one slot's publication. Private fields; the ONLY construction
/// path ([`PreparedSlotMutation::new`]) validates every relationship, so a
/// mutation whose parts could disagree with the persisted intent is
/// unrepresentable. Every field is a TYPED identity or validated value —
/// no loose generation IDs, strings, targets, timestamps, or behavior
/// digests.
#[derive(Clone, Debug)]
pub(crate) struct PreparedSlotMutation {
    /// The operation this mutation belongs to (the transaction record's
    /// key and the swap's temp-name nonce).
    op_id: OperationId,
    /// The deployment this mutation belongs to (the persisted intent's
    /// identity).
    deployment_id: DeploymentId,
    /// The freshly minted generation this mutation installs.
    generation_id: GenerationId,
    /// The artifact this mutation deploys (the intent's planned result).
    artifact: ArtifactRef,
    /// The TYPED behavior digest of the slot's frozen behavior contract
    /// (the intent's `behavior_digest` — never a loose string).
    behavior_digest: BehaviorDigest,
    /// The compare-and-swap expected pre-push generation (the verified
    /// current state — `Absent` for a first deployment).
    prior_generation: Option<GenerationId>,
    /// The TYPED recorded time of the generation record (never a loose
    /// string).
    created_at: Timestamp,
    /// The TYPED owning target of the slot (never a loose string).
    target: TargetName,
    /// The VERIFIED current state the swap's compare-and-swap precondition
    /// must match.
    expected: ExpectedCurrent,
    /// The VALIDATED release bundle this mutation publishes (the release
    /// the artifact references — complete by construction).
    release: ValidatedReleaseBundle,
    /// The VERIFIED tree digest of the artifact (canonicalized before the
    /// mutation).
    tree: crate::identity::TreeDigest,
}

impl PreparedSlotMutation {
    /// THE ONLY CONSTRUCTION PATH: every field is a typed, validated value
    /// derived from the validated release, the verified tree, and the
    /// persisted intent — the mutation is built from the intent's OWN
    /// per-slot execution projection ([`ExecutionRequest`]: the artifact,
    /// the minted generation, the compare-and-swap expected pre-push
    /// generation, the frozen behavior contract + its typed digest), the
    /// typed owning target (from the validated project's topology), and the
    /// VERIFIED evidence (the validated release bundle, the re-canonicalized
    /// tree). The constructor validates the relationships that make the
    /// mutation coherent:
    ///
    /// * the release bundle's identity equals the artifact's release;
    /// * the verified tree digest equals the artifact's tree;
    /// * the expected current state is DERIVED from the request's prior
    ///   generation, so a disagreement is unrepresentable by construction.
    pub(crate) fn new(
        op_id: OperationId,
        deployment_id: DeploymentId,
        request: &crate::deploy::push::ExecutionRequest,
        created_at: Timestamp,
        target: TargetName,
        release: ValidatedReleaseBundle,
        tree: crate::identity::TreeDigest,
    ) -> Result<Self> {
        let artifact = request.artifact.clone();
        if release.release_id() != &artifact.release {
            return Err(crate::error::Error::integrity(format!(
                "prepared slot mutation: the release bundle {} does not match the artifact's release {}",
                release.release_id(),
                artifact.release
            )));
        }
        if tree != artifact.tree {
            return Err(crate::error::Error::integrity(format!(
                "prepared slot mutation: the verified tree {} does not match the artifact's tree {}",
                tree, artifact.tree
            )));
        }
        // The expected current state is DERIVED from the request's prior
        // generation (`Absent` for a first deployment) — the constructor can
        // never receive a pair that disagrees.
        let prior_generation = request.expected_generation.clone();
        let expected = match &prior_generation {
            Some(g) => ExpectedCurrent::Generation(g.clone()),
            None => ExpectedCurrent::Absent,
        };
        Ok(PreparedSlotMutation {
            op_id,
            deployment_id,
            generation_id: request.generation.clone(),
            artifact,
            behavior_digest: request.behavior_digest.clone(),
            prior_generation,
            created_at,
            target,
            expected,
            release,
            tree,
        })
    }

    /// The operation this mutation belongs to.
    pub(crate) fn op_id(&self) -> &OperationId {
        &self.op_id
    }
    /// The deployment this mutation belongs to.
    pub(crate) fn deployment_id(&self) -> &DeploymentId {
        &self.deployment_id
    }
    /// The freshly minted generation this mutation installs.
    pub(crate) fn generation_id(&self) -> &GenerationId {
        &self.generation_id
    }
    /// The artifact this mutation deploys.
    pub(crate) fn artifact(&self) -> &ArtifactRef {
        &self.artifact
    }
    /// The TYPED behavior digest of the slot's frozen behavior contract.
    pub(crate) fn behavior_digest(&self) -> &BehaviorDigest {
        &self.behavior_digest
    }
    /// The compare-and-swap expected pre-push generation.
    pub(crate) fn prior_generation(&self) -> Option<&GenerationId> {
        self.prior_generation.as_ref()
    }
    /// The TYPED recorded time of the generation record.
    pub(crate) fn created_at(&self) -> &Timestamp {
        &self.created_at
    }
    /// The TYPED owning target of the slot.
    pub(crate) fn target(&self) -> &TargetName {
        &self.target
    }
    /// The VERIFIED current state the swap's compare-and-swap precondition
    /// must match.
    pub(crate) fn expected(&self) -> &ExpectedCurrent {
        &self.expected
    }
    /// The VALIDATED release bundle this mutation publishes.
    pub(crate) fn release(&self) -> &ValidatedReleaseBundle {
        &self.release
    }
    /// The VERIFIED tree digest of the artifact.
    pub(crate) fn tree(&self) -> &crate::identity::TreeDigest {
        &self.tree
    }
}

/// THE SEALED PROOF OF A COMMITTED SLOT MUTATION: the witness that the
/// four durable slot mutations (release publish, generation install,
/// transaction record, `current` swap) all succeeded, carrying the
/// [`DurableRelease`], [`DurableGeneration`], and [`DurableCurrent`]
/// evidence of the durable effects. The fields are private and the ONLY
/// mint is [`commit`] — a caller cannot fabricate the proof; it can only
/// be obtained by successfully committing the mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SlotCommitProof {
    release: DurableRelease,
    generation: DurableGeneration,
    current: DurableCurrent,
}

impl SlotCommitProof {
    /// The durably published release evidence.
    pub(crate) fn release(&self) -> &DurableRelease {
        &self.release
    }
    /// The durably installed generation evidence.
    pub(crate) fn generation(&self) -> &DurableGeneration {
        &self.generation
    }
    /// The durably swapped `current` evidence.
    pub(crate) fn current(&self) -> &DurableCurrent {
        &self.current
    }
}

/// THE ONE SLOT-MUTATION ENTRY POINT: consumes the proof-bearing
/// [`PreparedSlotMutation`] under the held slot lock and performs the four
/// durable slot mutations in the ONE order:
///
/// 1. **Publish the release** as ONE aggregate bundle
///    ([`HeldSlotLock::publish_release`]) → [`DurableRelease`];
/// 2. **Install the generation** ([`HeldSlotLock::durable_generation_install`])
///    → [`DurableGeneration`];
/// 3. **Record the transaction** (`prepared` — the durable per-operation
///    recovery record);
/// 4. **Swap `current`** ([`HeldSlotLock::swap_current`]) under the
///    mutation's verified [`ExpectedCurrent`] compare-and-swap precondition
///    → [`DurableCurrent`].
///
/// Returns the sealed [`SlotCommitProof`] carrying the three evidence
/// values — the ONLY way a caller can learn the slot was committed. The
/// lock is the capability (borrowed — the caller keeps it for the
/// activation/verification/compensation that follow the swap); the
/// mutation is the proof-bearing value (consumed).
pub(crate) fn commit(
    lock: &HeldSlotLock<'_>,
    mutation: PreparedSlotMutation,
) -> Result<SlotCommitProof> {
    // 1. Publish the release as ONE aggregate bundle (idempotent). The
    //    bundle is complete by construction (built from the validated
    //    release), so the publish never receives a release.json that
    //    disagrees with the behavior.json (or with the release identity).
    let release = lock.publish_release(mutation.release())?;
    // 2. Install the generation record + its `root` symlink. The
    //    assignment's OWNER MARKER (application + slot) is bound by the
    //    guard itself — an assignment can never name a different slot than
    //    the guard authorizes; the non-owner fields come from the mutation
    //    (typed identities only — the typed [`BehaviorDigest`] and
    //    [`Timestamp`], never loose strings).
    let generation = lock.durable_generation_install(&crate::remote::helper::GenerationSpec {
        deployment_id: mutation.deployment_id().clone(),
        generation_id: mutation.generation_id().clone(),
        artifact: ArtifactRef {
            release: mutation.artifact().release.clone(),
            variant: mutation.artifact().variant.clone(),
            tree: mutation.tree().clone(),
        },
        behavior_sha256: mutation.behavior_digest().as_str().to_string(),
        prior_generation: mutation.prior_generation().cloned(),
        created_at: mutation.created_at().to_string(),
        target: Some(mutation.target().clone()),
    })?;
    // 3. Record the transaction (`prepared` — the durable per-operation
    //    recovery record).
    lock.transaction_record(mutation.op_id(), "prepared")?;
    // 4. Swap `current` under the mutation's verified compare-and-swap
    //    precondition.
    let current = lock.swap_current(
        mutation.expected(),
        mutation.generation_id(),
        mutation.op_id().as_str(),
    )?;
    Ok(SlotCommitProof {
        release,
        generation,
        current,
    })
}
