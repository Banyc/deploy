//! THE EVIDENCE TYPES — the proof-bearing return values of the durable
//! effects (the structural verdict's point 5). Every durable mutation
//! returns the EVIDENCE of what it durably installed — never `()` and never
//! a `bool` — so a caller can only proceed to the next step (or construct
//! a terminal) from the required proofs. A successful terminal can only be
//! constructed from the required proofs: the sealed [`VerifiedExecution`]
//! mint sits at the verified-execution evidence point, and the per-slot
//! commit evidence ([`crate::deploy::rollout::server::SlotCommitProof`])
//! is the proof-bearing value the mutation loop consumes.
//!
//! Each evidence value is a SEALED, typed witness: the fields are private
//! and the ONLY construction paths are the durable effects themselves
//! ([`HeldSlotLock::durable_publish_tree`] →
//! [`DurableObject`], [`HeldSlotLock::durable_publish_release`] →
//! [`DurableRelease`], [`HeldSlotLock::durable_generation_install`] →
//! [`DurableGeneration`], [`HeldSlotLock::durable_symlink_swap`] →
//! [`DurableCurrent`]) and the compensation path
//! ([`crate::deploy::rollout::server::compensate_server_locked`] →
//! [`RestorationProof`]). A caller cannot fabricate an evidence value: it
//! can only be obtained by successfully performing the durable effect.

use crate::identity::{GenerationId, ReleaseId, TreeDigest};

/// Evidence that a tree object was durably published at its digest path
/// (`objects/sha256/<digest>/root`): the digest path is either wholly absent
/// or contains EXACTLY the verified canonical tree — never a partial or
/// corrupt object. Produced ONLY by the durable tree publication
/// ([`HeldSlotLock::durable_publish_tree`] /
/// [`HeldSlotLock::publish_from_incoming`]); the sealed digest is the
/// object's content identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableObject {
    digest: TreeDigest,
}

impl DurableObject {
    /// The durably published object's content digest.
    pub fn digest(&self) -> &TreeDigest {
        &self.digest
    }

    /// CRATE-INTERNAL mint: the durable tree publication's evidence point
    /// ([`HeldSlotLock::durable_publish_tree`] / `publish_from_incoming`).
    /// A library caller cannot fabricate the evidence — it can only be
    /// obtained by successfully performing the durable effect.
    pub(crate) fn published(digest: TreeDigest) -> Self {
        DurableObject { digest }
    }
}

/// Evidence that a release was durably published as ONE AGGREGATE BUNDLE
/// (`releases/<id>/`): the final release directory is either wholly absent
/// or complete and readable — never a partial directory. Produced ONLY by
/// the durable aggregate release publication
/// ([`HeldSlotLock::durable_publish_release`]); the sealed release id is
/// the bundle's identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableRelease {
    release_id: ReleaseId,
}

impl DurableRelease {
    /// The durably published release's identity.
    pub fn release_id(&self) -> &ReleaseId {
        &self.release_id
    }

    /// CRATE-INTERNAL mint: the durable aggregate release publication's
    /// evidence point ([`HeldSlotLock::durable_publish_release`]). A
    /// library caller cannot fabricate the evidence.
    pub(crate) fn published(release_id: ReleaseId) -> Self {
        DurableRelease { release_id }
    }
}

/// Evidence that a generation was durably installed
/// (`generations/<gen>/assignment.json` + the `root` symlink): the final
/// generation directory is either wholly absent or complete and readable —
/// never a partial generation. Produced ONLY by the durable generation
/// install ([`HeldSlotLock::durable_generation_install`]); the sealed
/// generation id is the installed record's identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableGeneration {
    generation_id: GenerationId,
}

impl DurableGeneration {
    /// The durably installed generation's identity.
    pub fn generation_id(&self) -> &GenerationId {
        &self.generation_id
    }

    /// CRATE-INTERNAL mint: the durable generation install's evidence point
    /// ([`HeldSlotLock::durable_generation_install`]). A library caller
    /// cannot fabricate the evidence.
    pub(crate) fn installed(generation_id: GenerationId) -> Self {
        DurableGeneration { generation_id }
    }
}

/// Evidence that the `current` symlink was durably swapped to a generation:
/// `current` is either absent (the complete old state) or points at the
/// EXACT canonical target of the new generation (the complete new state) —
/// never a torn/partial link. Produced ONLY by the durable symlink swap
/// ([`HeldSlotLock::durable_symlink_swap`]); the sealed generation id is
/// the generation `current` now names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableCurrent {
    generation_id: GenerationId,
}

impl DurableCurrent {
    /// The generation the durably swapped `current` now names.
    pub fn generation_id(&self) -> &GenerationId {
        &self.generation_id
    }

    /// CRATE-INTERNAL mint: the durable symlink swap's evidence point
    /// ([`HeldSlotLock::durable_symlink_swap`]). A library caller cannot
    /// fabricate the evidence.
    pub(crate) fn swapped(generation_id: GenerationId) -> Self {
        DurableCurrent { generation_id }
    }
}

/// Evidence that a slot was restored to its pre-push state: the generation
/// compensation (CAS back to the prior generation, or removal of `current`
/// on a first deploy) succeeded AND the mutating adapter's side effects
/// were VERIFIED restored by a read-back. Produced ONLY by the compensation
/// path ([`crate::deploy::rollout::server::compensate_server_locked`]); the
/// sealed restored generation is `None` for a first-deploy restoration
/// (removal of `current`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestorationProof {
    restored_generation: Option<GenerationId>,
}

impl RestorationProof {
    /// The generation the slot was restored to (`None` for a first-deploy
    /// restoration — `current` was removed).
    pub fn restored_generation(&self) -> Option<&GenerationId> {
        self.restored_generation.as_ref()
    }

    /// CRATE-INTERNAL mint: the compensation path's evidence point
    /// ([`crate::deploy::rollout::server::compensate_server_locked`]). A
    /// library caller cannot fabricate the evidence.
    pub(crate) fn restored(restored_generation: Option<GenerationId>) -> Self {
        RestorationProof {
            restored_generation,
        }
    }
}
