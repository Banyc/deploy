//! The ROLLBACK PAYLOAD semantics (feature area A2: Ledger semantics).
//!
//! [`build_rollback`] builds the rollback state of a successful deployment
//! from the VERIFIED per-slot [`GenerationRef`]s — the values the
//! LOCK-VERIFIED finalizer ([`crate::ledger::finalize::finalize_successful_locked`])
//! re-observed under the selected-slot mutation locks and proved EXACTLY
//! equal to the frozen desired assignment (never from the engine's earlier
//! observation records, which a concurrent controller can make stale, and
//! never from the intent record itself). The payload is the COMPLETE target
//! snapshot (a [`crate::ledger::records::LedgerRollback`]: per-slot
//! generation refs + COMPLETE physical bindings), so EXACT ROLLBACK is
//! possible: `deploy push <target> <deployment-id>` restores exactly that
//! deployment's stored state, verified by the binding map (a missing
//! binding entry is "unverifiable" and makes exact rollback refuse the
//! slot). Every verified ref is COMPLETE by construction (a full
//! generation + artifact read under the locks), so the builder is
//! INFALLIBLE — there is no unknown/absent observation an input could
//! carry.
//!
//! The wire/domain RECORDS themselves ([`crate::ledger::records::LedgerRollback`],
//! [`crate::ledger::records::LedgerRollbackWire`],
//! [`crate::ledger::records::PhysicalBinding`]) live in the shared core
//! ([`crate::ledger::records`]).

use crate::identity::{GenerationRef, SlotId};
use std::collections::BTreeMap;

use super::super::{LedgerRollback, PhysicalBinding};
/// Build the rollback state of a successful deployment from the VERIFIED
/// per-slot [`GenerationRef`]s (`verified`: the values the lock-verified
/// finalizer re-observed under the selected-slot mutation locks and proved
/// EXACTLY equal to the frozen desired assignment — never the engine's
/// earlier observation records, which a concurrent controller can make
/// stale, and never the intent record itself). A successful deployment
/// carries one complete [`GenerationRef`] per selected slot; every verified
/// ref is COMPLETE by construction (a full generation + artifact read under
/// the locks), so the builder is INFALLIBLE. `bindings` records the
/// COMPLETE physical binding (`{server, deploy_dir}`) each slot had when
/// the deployment ran; a missing entry is "unverifiable" and makes exact
/// rollback refuse the slot.
///
/// PARTIAL-ROLLOUT OVERLAY: the result is the COMPLETE target snapshot — the
/// latest successful snapshot (`base`) with the SELECTED slots (the
/// `verified` map's keys) replaced by their verified assignments and current
/// bindings, unselected slots carried forward unchanged, and slots absent
/// from `current_slot_ids` (the caller's coverage set — the FROZEN FULL
/// membership of the finalizing attempt, the complete target membership at
/// PLAN TIME, never the live configuration) omitted. A full-target attempt
/// replaces every slot, so the base is irrelevant. There is NO snapshot-wide
/// release/behavior: each slot's
/// `GenerationRef` carries its OWN artifact (release/variant/tree), so a
/// partial snapshot can span several releases (group pushes over time) and
/// the referenced releases are the set derived from the per-slot bindings.
pub fn build_rollback(
    verified: &BTreeMap<SlotId, GenerationRef>,
    bindings: &BTreeMap<SlotId, PhysicalBinding>,
    base: Option<&LedgerRollback>,
    current_slot_ids: &[SlotId],
) -> LedgerRollback {
    // Start from the base (or empty): unselected slots are carried forward
    // unchanged.
    let mut slots: BTreeMap<SlotId, GenerationRef> =
        base.map(|b| b.slots.clone()).unwrap_or_default();
    let mut out_bindings: BTreeMap<SlotId, PhysicalBinding> =
        base.map(|b| b.bindings.clone()).unwrap_or_default();
    // Replace the SELECTED slots with their VERIFIED assignments (the
    // complete GenerationRefs the lock-verified finalizer re-observed under
    // the locks and proved equal to the frozen desired) and their current
    // physical bindings.
    for (slot, gr) in verified {
        slots.insert(slot.clone(), gr.clone());
        if let Some(b) = bindings.get(slot) {
            out_bindings.insert(slot.clone(), b.clone());
        }
    }
    // Omit slots removed from the current target configuration.
    let current: std::collections::HashSet<&str> =
        current_slot_ids.iter().map(|s| s.as_str()).collect();
    slots.retain(|k, _| current.contains(k.as_str()));
    out_bindings.retain(|k, _| current.contains(k.as_str()));
    LedgerRollback {
        slots,
        bindings: out_bindings,
    }
}

#[cfg(test)]
mod tests_rollback {
    use super::*;
    use crate::identity::{
        ArtifactRef, GenerationRef, PlacementSlotAssignment, ServerId, SlotId, VariantName,
        test_deployment_id, test_generation_id, test_tree_digest,
    };
    use std::collections::BTreeMap;

    /// A verified generation ref whose assignment names its own slot key (the
    /// agreeing form the lock-verified finalizer observes under the locks).
    fn verified_ref_for(key: &SlotId, gen_id: &str, rel: &str, tree: &str) -> GenerationRef {
        GenerationRef {
            generation: test_generation_id(gen_id),
            assignment: PlacementSlotAssignment {
                placement_slot: key.clone(),
                artifact: ArtifactRef {
                    release: crate::identity::test_release_id(rel),
                    variant: VariantName::new("standard".to_string()),
                    tree: test_tree_digest(tree),
                },
            },
        }
    }

    /// `build_rollback` records each slot's complete physical binding AND
    /// inserts the VERIFIED generation ref intact (generation AND artifact —
    /// the ref is the complete `GenerationRef` the lock-verified finalizer
    /// re-observed under the locks, never a rebuilt observation).
    #[test]
    fn build_rollback_records_each_slots_physical_binding() {
        let slot = SlotId::new("p1".to_string());
        let verified = BTreeMap::from([(
            slot.clone(),
            verified_ref_for(&slot, "gen-x", "rel-1", "tree-1"),
        )]);
        let bindings: BTreeMap<SlotId, PhysicalBinding> = BTreeMap::from([(
            slot.clone(),
            PhysicalBinding {
                server: ServerId::new("server-01"),
                deploy_dir: "/srv/deploy/p1".to_string(),
            },
        )]);

        let rollback = build_rollback(&verified, &bindings, None, std::slice::from_ref(&slot));
        assert_eq!(
            rollback.bindings.get(&slot),
            Some(&PhysicalBinding {
                server: ServerId::new("server-01"),
                deploy_dir: "/srv/deploy/p1".to_string(),
            }),
            "the rollback must record the slot's complete physical binding (server AND deploy_dir)"
        );
        assert_eq!(rollback.slots.len(), 1, "generation refs preserved intact");
        assert_eq!(rollback.bindings.len(), 1);
        assert_eq!(
            rollback.slots.get(&slot),
            Some(&verified_ref_for(&slot, "gen-x", "rel-1", "tree-1")),
            "the verified GenerationRef (generation AND artifact) is inserted exactly as observed"
        );
    }

    /// The PARTIAL-ROLLOUT OVERLAY: the result is the COMPLETE target
    /// snapshot — the latest successful base with the SELECTED slots (the
    /// `verified` map's keys) replaced by their verified refs, unselected
    /// slots carried forward unchanged, and slots outside the caller's
    /// coverage set (the frozen full membership) omitted. The VERIFIED refs
    /// are the complete `GenerationRef`s observed under the locks — the
    /// overlay can never fabricate an entry (every verified ref is complete
    /// by construction, so the builder is infallible).
    #[test]
    fn build_rollback_overlays_verified_refs_over_the_base() {
        let selected = SlotId::new("p1".to_string());
        let unselected = SlotId::new("p2".to_string());
        let outside = SlotId::new("p3".to_string());
        let bindings: BTreeMap<SlotId, PhysicalBinding> = BTreeMap::from([
            (
                selected.clone(),
                PhysicalBinding {
                    server: ServerId::new("s1"),
                    deploy_dir: "/srv/deploy/p1".to_string(),
                },
            ),
            (
                unselected.clone(),
                PhysicalBinding {
                    server: ServerId::new("s2"),
                    deploy_dir: "/srv/deploy/p2".to_string(),
                },
            ),
        ]);
        // The base: a previous successful snapshot covering p1 + p2 + p3.
        let base = LedgerRollback {
            slots: BTreeMap::from([
                (
                    selected.clone(),
                    verified_ref_for(&selected, "gen-old-1", "rel-old", "tree-old-1"),
                ),
                (
                    unselected.clone(),
                    verified_ref_for(&unselected, "gen-old-2", "rel-old", "tree-old-2"),
                ),
                (
                    outside.clone(),
                    verified_ref_for(&outside, "gen-old-3", "rel-old", "tree-old-3"),
                ),
            ]),
            bindings: bindings.clone(),
        };
        // The SELECTED slot's VERIFIED ref (observed under the locks, proved
        // equal to the frozen desired) replaces the base's old entry; p2 is
        // carried forward; p3 is omitted (outside the frozen membership).
        let verified = BTreeMap::from([(
            selected.clone(),
            verified_ref_for(&selected, "gen-new", "rel-new", "tree-new"),
        )]);
        let coverage = [selected.clone(), unselected.clone()];

        let rollback = build_rollback(&verified, &bindings, Some(&base), &coverage);
        assert_eq!(
            rollback.slots.get(&selected),
            Some(&verified_ref_for(
                &selected, "gen-new", "rel-new", "tree-new"
            )),
            "the selected slot's verified ref replaces the base entry"
        );
        assert_eq!(
            rollback.slots.get(&unselected),
            Some(&verified_ref_for(
                &unselected,
                "gen-old-2",
                "rel-old",
                "tree-old-2"
            )),
            "an unselected slot is carried forward unchanged from the base"
        );
        assert!(
            !rollback.slots.contains_key(&outside),
            "a slot outside the frozen membership is omitted from the complete snapshot"
        );
        assert!(
            !rollback.bindings.contains_key(&outside),
            "a slot outside the frozen membership is omitted from the bindings too"
        );
    }

    /// A legacy LEDGER LINE whose rollback has no `bindings` key must still
    /// deserialize; its `bindings` map defaults to empty, which rollback
    /// treats as unverifiable rather than guessing the host/location. The
    /// line ALSO carries the OLD snapshot-wide `behavior_sha256`/`release`
    /// members — serde ignores the unknown fields, and the rollback payload
    /// is interpreted purely through the per-slot bindings (legacy lines stay
    /// readable after the snapshot-wide fields were removed). The line is
    /// otherwise in the CURRENT v3 shape — it carries the REQUIRED
    /// `selected_membership` / `full_membership` members (empty here) so the
    /// legacy aspect under test is the rollback's missing `bindings` and the
    /// snapshot-wide members, not the membership fields. A line WITHOUT the
    /// v3 membership members is an OLD-SHAPE record and fails
    /// DESERIALIZATION fail-closed (the fields are REQUIRED — no serde
    /// default), pinned below.
    #[test]
    fn legacy_rollback_without_bindings_deserializes_with_empty_map() {
        // The id must be a canonical (validated) deployment id — the legacy
        // aspect under test is the missing `bindings` key and the
        // snapshot-wide members, not the id format.
        let did = test_deployment_id("deploy-old");
        let rel = crate::identity::test_release_id("old");
        let line = format!(
            r#"{{"kind":"terminal","deployment_id":"{did}","target":"production","status":"successful","recorded_at":"2026-01-01T00:00:00Z","outcomes":{{}},"selected_membership":[],"full_membership":[],"rollback":{{"behavior_sha256":"sha256-aa","release":"{rel}","slots":{{}}}}}}"#
        );
        // The legacy line PARSES at the wire level (the legacy snapshot-wide
        // members are tolerated by serde — unknown members are skipped), and
        // the domain conversion REFUSES it (fail closed): the legacy
        // `release` disagrees with the snapshot's derived releases (the
        // per-slot bindings — empty here — are the authoritative source).
        let wire: crate::ledger::records::LedgerTerminalWire = serde_json::from_str(&line).unwrap();
        let err = wire.into_domain().expect_err(
            "a legacy release that disagrees with the derived snapshot releases fails closed",
        );
        assert!(err.to_string().contains("release"), "error: {err}");

        // AN OLD-SHAPE TERMINAL LINE (no `selected_membership` /
        // `full_membership` members — the v2 shape) fails DESERIALIZATION
        // fail-closed: the v3 membership fields are REQUIRED (no serde
        // default), so a pre-v3 record can never be read as if it carried
        // proven memberships (the intent-line `deployment_schema_version`
        // check refuses its intent the same way).
        let old_line = format!(
            r#"{{"kind":"terminal","deployment_id":"{did}","target":"production","status":"successful","recorded_at":"2026-01-01T00:00:00Z","outcomes":{{}},"rollback":{{"slots":{{}}}}}}"#
        );
        let err = serde_json::from_str::<crate::ledger::records::LedgerTerminalWire>(&old_line)
            .expect_err("an old-shape terminal line without the v3 memberships must fail deserialization fail-closed");
        assert!(
            err.to_string().contains("selected_membership")
                || err.to_string().contains("full_membership"),
            "the deserialization error must name the missing REQUIRED membership field, got: {err}"
        );
    }
}
