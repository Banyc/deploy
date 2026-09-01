//! Receiver rotation ([`HeldSlotLock::rotate`]): mark-and-sweep retention
//! deleting tree objects and abandoned incoming directories not in the
//! retained set. Rotation is a DESTRUCTIVE operation and therefore a
//! [`HeldSlotLock`] method — there is no unguarded `RemoteHelper::rotate`
//! entry point (a caller must HOLD the slot's mutation lock to sweep it).
//!
//! THE ACTIVE TREE IS STRUCTURALLY PROTECTED: the rotation derives the
//! active tree — the tree the `current` symlink points at — from the
//! VERIFIED CURRENT STATE ([`RemoteHelper::status`] — the owner-verified
//! read of the current assignment, which validates the complete symlink
//! chain) and sweeps through a TYPED DELETABLE SET ([`DeletableSet`]) that
//! excludes the active tree BY CONSTRUCTION. The rotation never trusts a
//! loose digest set for the active tree's protection: a retained set that
//! omits the active tree cannot cause its deletion, because the deletable
//! set is built from the verified current state and the active tree can
//! never be a member of it.

use crate::error::{Error, Result};
use crate::identity::{GenerationId, TreeDigest};
use crate::remote::layout;
use crate::remote::transport::RemoteEntry;
use crate::retention::RetainedSet;
use std::collections::HashSet;

use super::super::HeldSlotLock;

impl<'a> HeldSlotLock<'a> {
    /// Mark-and-sweep retention: delete tree objects whose digest is not in the
    /// retained set, and remove abandoned incoming directories. Requires the
    /// slot-mutation capability — the receiver is the guard; the helper is the
    /// guard's own.
    ///
    /// THE GENERATION INVENTORY IS VERIFIED BEFORE ANY DELETION: every
    /// generation record on this remote must carry THIS guard's owner marker
    /// ([`crate::remote::helper::RemoteHelper::read_assignment`] — the
    /// owner-verified read). A foreign/transplanted generation — state that
    /// belongs to a different application/slot — ABORTS rotation with ZERO
    /// deletions (fail closed): it is never swept as if it were ours, and its
    /// trees are never deleted by a guard that does not own them.
    ///
    /// THE ACTIVE TREE IS STRUCTURALLY PROTECTED: the rotation derives the
    /// active tree from the VERIFIED CURRENT STATE ([`RemoteHelper::status`]
    /// — the owner-verified read of the current assignment, which validates
    /// the complete symlink chain) and sweeps through a TYPED DELETABLE SET
    /// ([`DeletableSet`]) that excludes the active tree BY CONSTRUCTION — the
    /// active tree can never be a member of the deletable set, so the
    /// deletion cannot touch it, whatever the retained set contains. The
    /// retained set is the PROOF-BEARING [`RetainedSet`] the caller must
    /// produce (its active tree is structurally a member); the rotation
    /// verifies the proof against the verified current state — a disagreement
    /// is an integrity error, fail closed, nothing swept.
    ///
    /// CRATE-PRIVATE (the structural verdict's point 7 taken to its
    /// conclusion): the mutation primitives are NOT on the library's public
    /// surface — the ONLY public mutation path is
    /// [`crate::deploy::rollout::commit`] with a
    /// [`crate::deploy::rollout::PreparedSlotMutation`].
    pub(crate) fn rotate(
        &self,
        retained: &RetainedSet,
        active_incoming: &HashSet<String>,
    ) -> Result<()> {
        self.verify_generation_inventory()?;

        // THE VERIFIED CURRENT STATE: the owner-verified read of `current`
        // (validates the complete symlink chain AND the owner marker). The
        // ACTIVE TREE is derived from it — the rotation never trusts the
        // caller's retained set for the active tree's protection.
        let status = self.helper.status(&self.owner)?;
        let active_tree = status.current_tree();

        // VERIFY THE PROOF: the retained set's active tree must equal the
        // verified current state's active tree. A disagreement — a retained
        // set computed against a different current state (a stale read or a
        // race) — is an integrity error: fail closed, nothing swept.
        if retained.active_tree() != active_tree {
            return Err(Error::integrity(format!(
                "rotation refused: the retained set's active tree {} does not match the verified current state's active tree {}",
                retained
                    .active_tree()
                    .map(|t| t.as_str())
                    .unwrap_or("<none>"),
                active_tree.map(|t| t.as_str()).unwrap_or("<none>"),
            )));
        }

        let obj_root = layout::objects();
        if self.helper.remote.metadata_opt(obj_root)?.is_some() {
            // THE DELETABLE SET: every enumerated tree object minus the
            // retained set minus the active tree. The active tree is
            // excluded BY CONSTRUCTION — the deletable set is built from the
            // verified current state, so the active tree can never be a
            // member of it. The rotation deletes ONLY members of the
            // deletable set; deleting the active tree is unrepresentable.
            let deletable =
                DeletableSet::new(self.helper.remote.list(obj_root)?, retained, active_tree)?;
            for digest in deletable.iter() {
                self.helper
                    .remote
                    .remove_dir_all(&obj_root.join(digest.as_str())?)?;
            }
        }
        let inc = layout::incoming();
        if self.helper.remote.metadata_opt(inc)?.is_some() {
            for e in self.helper.remote.list(inc)? {
                if e.is_dir && !active_incoming.contains(&e.name) {
                    self.helper.remote.remove_dir_all(&inc.join(&e.name)?)?;
                }
            }
        }
        self.helper.write_inventory()?;
        Ok(())
    }

    /// Verify the generation inventory against THIS guard's owner before
    /// sweeping: every generation record on this remote must carry the
    /// guard's owner marker — a foreign/transplanted generation aborts
    /// rotation with zero deletions (never swept as if it were ours). A
    /// malformed/ownerless record fails closed the same way (the same
    /// fail-closed rule the retained-set computation honors).
    fn verify_generation_inventory(&self) -> Result<()> {
        let gen_root = layout::generations();
        if self.helper.remote.metadata_opt(gen_root)?.is_none() {
            return Ok(());
        }
        for entry in self.helper.remote.list(gen_root)? {
            if !entry.is_dir {
                continue;
            }
            let dir_gen = GenerationId::parse(&entry.name).map_err(|err| {
                Error::integrity(format!(
                    "generation directory {} names an invalid generation id: {err}",
                    entry.name
                ))
            })?;
            let a = self
                .helper
                .read_assignment(&dir_gen, &self.owner)
                .map_err(|err| {
                    Error::integrity(format!(
                        "rotation refused: generation {} is not owned by this slot (application '{}', slot '{}'): {err}",
                        entry.name, self.owner.application, self.owner.slot
                    ))
                })?;
            if a.generation_id != dir_gen {
                return Err(Error::integrity(format!(
                    "generation {} assignment names generation {}, not its directory",
                    entry.name, a.generation_id
                )));
            }
        }
        Ok(())
    }
}

/// THE TYPED DELETABLE SET: the tree objects the rotation may delete. Built
/// from the enumerated object store MINUS the retained set MINUS the active
/// tree — the active tree is excluded BY CONSTRUCTION (the constructor
/// removes it), so the active tree can never be a member of the deletable
/// set. The rotation deletes ONLY members of this set; deleting the active
/// tree is unrepresentable.
struct DeletableSet {
    trees: HashSet<TreeDigest>,
}

impl DeletableSet {
    /// Build the deletable set from the enumerated object-store entries, the
    /// proof-bearing retained set, and the ACTIVE TREE derived from the
    /// verified current state. Every entry name is parsed into the TYPED
    /// [`TreeDigest`] identity — a non-digest name is an integrity error
    /// (fail closed: an unparseable object is never silently deleted or
    /// kept). The active tree is excluded BY CONSTRUCTION: whatever the
    /// retained set contains, the active tree can never be a member of the
    /// deletable set.
    fn new(
        entries: Vec<RemoteEntry>,
        retained: &RetainedSet,
        active_tree: Option<&TreeDigest>,
    ) -> Result<Self> {
        let mut trees: HashSet<TreeDigest> = HashSet::new();
        for e in entries {
            if !e.is_dir {
                continue;
            }
            let digest = TreeDigest::parse(&e.name).map_err(|err| {
                Error::integrity(format!(
                    "object store entry {} names an invalid tree digest: {err}",
                    e.name
                ))
            })?;
            if retained.contains(&e.name) {
                continue;
            }
            // THE ACTIVE TREE IS EXCLUDED BY CONSTRUCTION: the deletable set
            // is built from the verified current state, so the active tree
            // can never be a member of it.
            if active_tree.is_some_and(|t| t == &digest) {
                continue;
            }
            trees.insert(digest);
        }
        Ok(DeletableSet { trees })
    }

    /// The deletable tree digests.
    fn iter(&self) -> impl Iterator<Item = &TreeDigest> {
        self.trees.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{
        ArtifactRef, TargetName, VariantName, test_behavior_digest, test_deployment_id,
        test_generation_id, test_release_id, test_tree_digest,
    };
    use crate::remote::helper::{ExpectedCurrent, GenerationSpec, RemoteHelper, SlotRemote};
    use crate::remote::layout;
    use crate::remote::transport::LocalTransport;
    use crate::retention::RetainedSet;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::collections::HashSet;

    // THE ACTIVE-TREE PROTECTION PROPERTY: whatever the retained set
    // contains — including a retained set whose policy trees OMIT the
    // active tree — the rotation NEVER deletes the active tree. The
    // rotation derives the active tree from the verified current state and
    // sweeps through a typed deletable set that excludes it by
    // construction; a retained set whose active tree disagrees with the
    // verified current state is REFUSED (fail closed — nothing swept).
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn active_tree_is_never_deleted_whatever_the_retained_set_contains(
            n_objects in 0usize..=6,
            omit_active in proptest::bool::ANY,
            n_retained in 0usize..=4,
            scenario in 0u8..=2,
        ) {
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let remote = LocalTransport::new(
                &crate::testutil::fixture_env(),
                dir.path().join("remote"),
            )
            .unwrap();
            let helper = RemoteHelper::new(&remote);
            let owner = crate::remote::helper::test_owner("rot", "p1");

            // The ACTIVE tree: the tree the `current` symlink points at.
            let active = test_tree_digest("active");
            // Arbitrary other tree objects on the remote.
            let mut objects: Vec<TreeDigest> = (0..n_objects)
                .map(|i| test_tree_digest(&format!("obj-{i}")))
                .collect();
            objects.push(active.clone());
            for t in &objects {
                helper.remote().create_dir_all(&layout::tree_root(t)).unwrap();
            }

            // Install the current state: one generation record + `current`.
            let guard = SlotRemote::new(&helper, owner.clone())
                .acquire_lock_guard(&crate::identity::OperationId::new("op".to_string()))
                .unwrap();
            guard
                .create_generation(&GenerationSpec {
                    deployment_id: test_deployment_id("d1"),
                    generation_id: test_generation_id("g1"),
                    artifact: ArtifactRef {
                        release: test_release_id("r"),
                        variant: VariantName::new("standard"),
                        tree: active.clone(),
                    },
                    behavior_sha256: test_behavior_digest("b"),
                    prior_generation: None,
                    created_at: crate::identity::Timestamp::parse("2020-01-01T00:00:00Z")
                        .unwrap(),
                    target: TargetName::new("t1"),
                })
                .unwrap();
            guard
                .swap_current(&ExpectedCurrent::Absent, &test_generation_id("g1"), "op")
                .unwrap();

            // The retained set: the active tree (matching the verified
            // current state) plus arbitrary policy-retained trees.
            // `omit_active` controls whether the policy trees omit the
            // active tree — the structural member still carries it.
            let mut retained_trees: HashSet<String> = (0..n_retained)
                .map(|i| test_tree_digest(&format!("ret-{i}")).as_str().to_string())
                .collect();
            if !omit_active {
                retained_trees.insert(active.as_str().to_string());
            }
            // `scenario` controls the retained set's ACTIVE TREE: 0 = the
            // verified current state's active tree (the proof matches — the
            // rotation sweeps), 1 = a DIFFERENT tree (the proof is refused),
            // 2 = `None` while the current state HAS an active tree (the
            // proof is refused).
            let retained_active = match scenario {
                0 => Some(active.clone()),
                1 => Some(test_tree_digest("other")),
                _ => None,
            };
            let retained = RetainedSet::new(retained_active, retained_trees);

            // The rotation: with a matching active tree it sweeps; with a
            // mismatched active tree it is REFUSED (fail closed — nothing
            // swept). Either way the active tree survives.
            let result = guard.rotate(&retained, &HashSet::new());
            if scenario == 0 {
                result.unwrap();
                // The sweep ran: every non-active object is gone, the
                // active tree survives.
                for t in &objects {
                    if t != &active {
                        prop_assert!(
                            !helper.remote().exists(&layout::tree_root(t)),
                            "a non-active object must be swept by the rotation"
                        );
                    }
                }
            } else {
                prop_assert!(
                    result.is_err(),
                    "a retained set whose active tree disagrees with the verified current state must be refused"
                );
            }
            prop_assert!(
                helper.remote().exists(&layout::tree_root(&active)),
                "the active tree must survive whatever the retained set contains"
            );
        }
    }
}
