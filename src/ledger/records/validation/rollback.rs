//! The ROLLBACK PAYLOAD semantics (feature area A2: Ledger semantics).
//!
//! [`build_rollback`] builds the rollback state of a successful deployment
//! from THE ONE PRIVATE VALIDATED MAP ([`BoundGeneration`] keyed by
//! [`SlotId`]) — the construction input that pairs EVERY slot's VERIFIED
//! [`GenerationRef`] with its COMPLETE physical binding in a SINGLE map, so
//! there are NO parallel maps to drift (the old two-map input — the per-slot
//! rollback entries AND a separate `bindings` map — could DIVERGE: a slot
//! present in one but not the other, and the appended terminal made the
//! ledger unreadable immediately after a SUCCESSFUL finalization; the
//! strict reader refuses a key-set mismatch). The values are the ones the
//! LOCK-VERIFIED finalizer
//! ([`crate::ledger::finalize::finalize_successful_locked`]) re-observed
//! under the selected-slot mutation locks and proved EXACTLY equal to the
//! frozen desired assignment (never from the engine's earlier observation
//! records, which a concurrent controller can make stale, and never from
//! the intent record itself). The payload is the COMPLETE target snapshot (a
//! [`crate::ledger::records::LedgerRollback`]: per-slot generation refs +
//! COMPLETE physical bindings), so EXACT ROLLBACK is possible:
//! `deploy push <target> <deployment-id>` restores exactly that
//! deployment's stored state, verified by the binding map (a missing
//! binding entry is "unverifiable" and makes exact rollback refuse the
//! slot).
//!
//! THE BUILDER IS FALLIBLE (fail closed): the construction VERIFIES its own
//! result before returning — the rollback's `slots` key set must EXACTLY
//! equal its `bindings` key set (every slotted generation has a physical
//! binding and vice versa — the EXACT equality the strict reader enforces
//! at conversion time) and every `GenerationRef`'s assignment must name its
//! own map key. A divergence → [`crate::error::Error::integrity`] — the
//! finalization refuses, never appends a terminal the reader would reject.
//!
//! The wire/domain RECORDS themselves ([`crate::ledger::records::LedgerRollback`],
//! [`crate::ledger::records::LedgerRollbackWire`],
//! [`crate::ledger::records::PhysicalBinding`]) live in the shared core
//! ([`crate::ledger::records`]).

use crate::error::{Error, Result};
use crate::identity::{GenerationRef, SlotId};
use std::collections::{BTreeMap, BTreeSet};

use super::super::{LedgerRollback, PhysicalBinding};

/// THE ONE PRIVATE VALIDATED MAP VALUE — the complete per-slot rollback
/// fact: a slot's VERIFIED [`GenerationRef`] (generation AND artifact)
/// TOGETHER with its COMPLETE physical binding (`{server, deploy_dir}`).
/// The successful finalizer merges its two inputs — the lock-verified
/// observed `GenerationRef`s and the intent's FROZEN physical bindings —
/// into ONE `BTreeMap<SlotId, BoundGeneration>` BEFORE building the
/// rollback, so the construction has NO parallel maps to drift: the map's
/// key set IS the selected-slot set, and every key carries both halves of
/// the payload. A slot missing its binding (or a binding keyed under a
/// different slot) is a construction ERROR — the merge refuses it — never
/// a silently-dropped entry that would make the appended terminal
/// unreadable. PRIVATE to the crate (the wire/domain never carry it — the
/// rollback payload is built from it and the two wire fields are filled
/// from this ONE source).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BoundGeneration {
    /// The slot's VERIFIED generation ref (the complete ref observed under
    /// the locks and proved equal to the frozen desired).
    pub(crate) generation: GenerationRef,
    /// The slot's COMPLETE physical binding at deployment time (the frozen
    /// plan-time `{server, deploy_dir}`).
    pub(crate) binding: PhysicalBinding,
}

/// Build the rollback state of a successful deployment from THE ONE
/// PRIVATE VALIDATED MAP (`verified`: `SlotId -> BoundGeneration` — every
/// selected slot's verified [`GenerationRef`] paired with its physical
/// binding in a single map; the values the lock-verified finalizer
/// re-observed under the selected-slot mutation locks and proved EXACTLY
/// equal to the frozen desired assignment — never the engine's earlier
/// observation records, which a concurrent controller can make stale, and
/// never the intent record itself). A successful deployment carries one
/// complete [`GenerationRef`] per selected slot.
///
/// PARTIAL-ROLLOUT OVERLAY: the result is the COMPLETE target snapshot — the
/// latest successful snapshot (`base`) with the SELECTED slots (the
/// `verified` map's keys) replaced by their verified assignments and
/// bindings, unselected slots carried forward unchanged, and slots absent
/// from `current_slot_ids` (the caller's coverage set — the FROZEN FULL
/// membership of the finalizing attempt, the complete target membership at
/// PLAN TIME, never the live configuration) omitted. A full-target attempt
/// replaces every slot, so the base is irrelevant. There is NO snapshot-wide
/// release/behavior: each slot's
/// `GenerationRef` carries its OWN artifact (release/variant/tree), so a
/// partial snapshot can span several releases (group pushes over time) and
/// the referenced releases are the set derived from the per-slot bindings.
///
/// FALLIBLE (fail closed): the result's `slots` key set must EXACTLY equal
/// its `bindings` key set (both are filled from the SAME iteration of the
/// single map, so a divergent `base` — the only other source — surfaces as
/// an error here rather than as a written-but-unreadable terminal) and each
/// `GenerationRef`'s assignment must name its own map key — the same
/// predicates the strict reader enforces at conversion time. A divergence
/// → [`crate::error::Error::integrity`].
pub fn build_rollback(
    verified: &BTreeMap<SlotId, BoundGeneration>,
    base: Option<&LedgerRollback>,
    current_slot_ids: &[SlotId],
) -> Result<LedgerRollback> {
    // Start from the base (or empty): unselected slots are carried forward
    // unchanged.
    let mut slots: BTreeMap<SlotId, GenerationRef> =
        base.map(|b| b.slots.clone()).unwrap_or_default();
    let mut out_bindings: BTreeMap<SlotId, PhysicalBinding> =
        base.map(|b| b.bindings.clone()).unwrap_or_default();
    // Replace the SELECTED slots with their VERIFIED assignments and their
    // physical bindings — BOTH filled from the SAME iteration of the ONE
    // map, so the two wire fields cannot diverge (the key set is inherently
    // consistent: every key carries its generation AND its binding).
    for (slot, bg) in verified {
        slots.insert(slot.clone(), bg.generation.clone());
        out_bindings.insert(slot.clone(), bg.binding.clone());
    }
    // Omit slots removed from the current target configuration.
    let current: std::collections::HashSet<&str> =
        current_slot_ids.iter().map(|s| s.as_str()).collect();
    slots.retain(|k, _| current.contains(k.as_str()));
    out_bindings.retain(|k, _| current.contains(k.as_str()));
    // THE WRITER'S EXACT-EQUALITY VERIFICATION (fail closed): the result's
    // key sets must EXACTLY equal (the strict reader refuses a mismatch — a
    // missing binding is "unverifiable", an extra binding names a slot with
    // no generation). Filled from one iteration, the only way they diverge
    // is an inconsistent `base` — refuse it here rather than persist a
    // terminal the reader would reject.
    let slot_keys: BTreeSet<&SlotId> = slots.keys().collect();
    let binding_keys: BTreeSet<&SlotId> = out_bindings.keys().collect();
    if slot_keys != binding_keys {
        let missing: Vec<&SlotId> = slot_keys.difference(&binding_keys).copied().collect();
        let extra: Vec<&SlotId> = binding_keys.difference(&slot_keys).copied().collect();
        return Err(Error::integrity(format!(
            "build_rollback: the constructed rollback's bindings must key EXACTLY the slotted generations (missing bindings for {missing:?}; extra bindings for {extra:?}) — refusing to build a payload the strict reader would reject"
        )));
    }
    for (key, g) in &slots {
        if &g.assignment.placement_slot != key {
            return Err(Error::integrity(format!(
                "build_rollback: generation for slot '{key}' names placement '{}' — every GenerationRef must name its own map key",
                g.assignment.placement_slot
            )));
        }
    }
    Ok(LedgerRollback {
        slots,
        bindings: out_bindings,
    })
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

    /// A `BoundGeneration` for a slot: the verified ref paired with a
    /// fixture binding — the ONE-map value the builder consumes.
    fn bound(key: &SlotId, gen_id: &str, rel: &str, tree: &str) -> BoundGeneration {
        BoundGeneration {
            generation: verified_ref_for(key, gen_id, rel, tree),
            binding: PhysicalBinding {
                server: ServerId::new("s1".to_string()),
                deploy_dir: format!("/srv/deploy/{}", key.as_str()),
            },
        }
    }

    /// `build_rollback` records each slot's complete physical binding AND
    /// inserts the VERIFIED generation ref intact (generation AND artifact —
    /// the ref is the complete `GenerationRef` the lock-verified finalizer
    /// re-observed under the locks, never a rebuilt observation), both from
    /// the ONE validated map.
    #[test]
    fn build_rollback_records_each_slots_physical_binding() {
        let slot = SlotId::new("p1".to_string());
        let verified = BTreeMap::from([(slot.clone(), bound(&slot, "gen-x", "rel-1", "tree-1"))]);

        let rollback = build_rollback(&verified, None, std::slice::from_ref(&slot))
            .expect("the single map is consistent");
        assert_eq!(
            rollback.bindings.get(&slot),
            Some(&PhysicalBinding {
                server: ServerId::new("s1"),
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
        // The ONE validated map pairs the verified ref with the slot's
        // binding — the builder consumes a single map, never two.
        let verified = BTreeMap::from([(
            selected.clone(),
            bound(&selected, "gen-new", "rel-new", "tree-new"),
        )]);
        let coverage = [selected.clone(), unselected.clone()];

        let rollback = build_rollback(&verified, Some(&base), &coverage)
            .expect("the single map is consistent");
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

    /// THE FALLIBLE BUILDER (fail closed): the construction VERIFIES its own
    /// result — the `slots` key set must EXACTLY equal the `bindings` key
    /// set (the strict reader's exact-equality predicate) and every
    /// `GenerationRef`'s assignment must name its own map key. A divergence
    /// → `Error::integrity`: the builder REFUSES to produce a payload the
    /// reader would reject (never a written-but-unreadable terminal). The
    /// healthy single map passes; a base whose bindings diverge from its
    /// slots (the only other source — the selected entries are filled from
    /// the ONE map's own iteration) and a ref naming a DIFFERENT slot are
    /// both refused.
    #[test]
    fn build_rollback_refuses_a_divergent_payload() {
        let p1 = SlotId::new("p1".to_string());
        let p2 = SlotId::new("p2".to_string());
        let healthy = BTreeMap::from([(p1.clone(), bound(&p1, "gen-new", "rel-new", "tree-new"))]);
        build_rollback(&healthy, None, std::slice::from_ref(&p1))
            .expect("the healthy single map builds");

        // A base whose bindings key set diverges from its slots key set
        // (a slot present in one map but not the other) — the exact
        // divergence the strict reader refuses. The UNSELECTED slot p2 is
        // carried forward from the base unchanged, so the overlay keeps the
        // inconsistent pair (p2's slot entry has NO binding) — and the
        // builder REFUSES it (fail closed) instead of persisting a payload
        // the reader would reject.
        let divergent_base = LedgerRollback {
            slots: BTreeMap::from([
                (
                    p1.clone(),
                    verified_ref_for(&p1, "gen-old-1", "rel-old", "tree-old-1"),
                ),
                (
                    p2.clone(),
                    verified_ref_for(&p2, "gen-old-2", "rel-old", "tree-old-2"),
                ),
            ]),
            bindings: BTreeMap::from([(
                p1.clone(),
                PhysicalBinding {
                    server: ServerId::new("s1"),
                    deploy_dir: "/srv/deploy/p1".to_string(),
                },
            )]),
        };
        let err = build_rollback(&healthy, Some(&divergent_base), &[p1.clone(), p2.clone()])
            .expect_err(
                "a base whose bindings diverge from its slots must refuse the construction",
            );
        assert!(
            err.to_string().contains("EXACTLY the slotted generations"),
            "the error names the key-set divergence, got: {err}"
        );

        // A GenerationRef naming a DIFFERENT slot than its map key — the
        // strict reader's own-key agreement, enforced at construction.
        let renamed = BTreeMap::from([(
            p1.clone(),
            BoundGeneration {
                generation: verified_ref_for(&p2, "gen-new", "rel-new", "tree-new"),
                binding: PhysicalBinding {
                    server: ServerId::new("s1"),
                    deploy_dir: "/srv/deploy/p1".to_string(),
                },
            },
        )]);
        let err = build_rollback(&renamed, None, std::slice::from_ref(&p1))
            .expect_err("a GenerationRef that names another slot must refuse the construction");
        assert!(
            err.to_string().contains("names placement"),
            "the error names the own-key violation, got: {err}"
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
