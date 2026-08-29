//! The ROLLBACK PAYLOAD semantics (feature area A2: Ledger semantics).
//!
//! [`build_rollback`] builds the rollback state of a successful deployment
//! from THE ONE PRIVATE VALIDATED MAP ([`BoundGeneration`] keyed by
//! [`SlotId`]) — the construction input that pairs EVERY slot's VERIFIED
//! [`GenerationRef`] with its COMPLETE physical binding in a SINGLE map, so
//! there are NO parallel maps to drift.
//! The values are the ones the
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
//! The wire/domain RECORDS themselves ([`crate::ledger::records::LedgerRollback`],
//! [`crate::ledger::records::PhysicalBinding`]) live in the shared core
//! ([`crate::ledger::records`]).

use crate::error::Result;
use crate::identity::{GenerationRef, SlotId};
use std::collections::BTreeMap;

use super::super::{LedgerRollback, PhysicalBinding, RollbackEntry};

/// THE ONE PRIVATE VALIDATED MAP VALUE — the complete per-slot rollback
/// fact: a slot's VERIFIED [`GenerationRef`] (generation AND artifact)
/// TOGETHER with its COMPLETE physical binding (`{server, deploy_dir}`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BoundGeneration {
    pub(crate) generation: GenerationRef,
    pub(crate) binding: PhysicalBinding,
}

pub fn build_rollback(
    verified: &BTreeMap<SlotId, BoundGeneration>,
    base: Option<&LedgerRollback>,
    current_slot_ids: &[SlotId],
) -> Result<LedgerRollback> {
    let mut entries: BTreeMap<SlotId, RollbackEntry> =
        base.map(|b| b.clone().into_entries()).unwrap_or_default();
    for (slot, bg) in verified {
        entries.insert(
            slot.clone(),
            RollbackEntry::new(
                bg.generation.generation.clone(),
                bg.generation.assignment.artifact.clone(),
                bg.binding.clone(),
            ),
        );
    }
    let current: std::collections::HashSet<&str> =
        current_slot_ids.iter().map(|s| s.as_str()).collect();
    entries.retain(|k, _| current.contains(k.as_str()));
    Ok(LedgerRollback::from_entries(entries))
}

#[cfg(test)]
mod tests_rollback {
    use super::*;
    use crate::identity::{
        ArtifactRef, GenerationRef, PlacementSlotAssignment, ServerId, SlotId, VariantName,
        test_deployment_id, test_generation_id, test_tree_digest,
    };
    use proptest::prelude::*;
    use std::collections::BTreeMap;

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
    fn bound(key: &SlotId, gen_id: &str, rel: &str, tree: &str) -> BoundGeneration {
        BoundGeneration {
            generation: verified_ref_for(key, gen_id, rel, tree),
            binding: PhysicalBinding {
                server: ServerId::new("s1".to_string()),
                deploy_dir: format!("/srv/deploy/{}", key.as_str()),
            },
        }
    }
    #[test]
    fn build_rollback_records_each_slots_physical_binding() {
        let slot = SlotId::new("p1".to_string());
        let verified = BTreeMap::from([(slot.clone(), bound(&slot, "gen-x", "rel-1", "tree-1"))]);
        let rollback = build_rollback(&verified, None, std::slice::from_ref(&slot))
            .expect("the single map is consistent");
        let e = rollback.get(&slot).expect("entry present");
        assert_eq!(
            e.binding(),
            &PhysicalBinding {
                server: ServerId::new("s1"),
                deploy_dir: "/srv/deploy/p1".to_string()
            }
        );
        assert_eq!(rollback.len(), 1);
        let expected = verified_ref_for(&slot, "gen-x", "rel-1", "tree-1");
        assert_eq!(e.generation(), &expected.generation);
        assert_eq!(e.artifact(), &expected.assignment.artifact);
    }
    #[test]
    fn build_rollback_overlays_verified_refs_over_the_base() {
        let selected = SlotId::new("p1".to_string());
        let unselected = SlotId::new("p2".to_string());
        let outside = SlotId::new("p3".to_string());
        let base = LedgerRollback::from_entries(BTreeMap::from([
            (selected.clone(), {
                let r = verified_ref_for(&selected, "gen-old-1", "rel-old", "tree-old-1");
                RollbackEntry::new(
                    r.generation,
                    r.assignment.artifact,
                    PhysicalBinding {
                        server: ServerId::new("s1"),
                        deploy_dir: "/srv/deploy/p1".to_string(),
                    },
                )
            }),
            (unselected.clone(), {
                let r = verified_ref_for(&unselected, "gen-old-2", "rel-old", "tree-old-2");
                RollbackEntry::new(
                    r.generation,
                    r.assignment.artifact,
                    PhysicalBinding {
                        server: ServerId::new("s2"),
                        deploy_dir: "/srv/deploy/p2".to_string(),
                    },
                )
            }),
            (outside.clone(), {
                let r = verified_ref_for(&outside, "gen-old-3", "rel-old", "tree-old-3");
                RollbackEntry::new(
                    r.generation,
                    r.assignment.artifact,
                    PhysicalBinding {
                        server: ServerId::new("s1"),
                        deploy_dir: "/srv/deploy/p3".to_string(),
                    },
                )
            }),
        ]));
        let verified = BTreeMap::from([(
            selected.clone(),
            bound(&selected, "gen-new", "rel-new", "tree-new"),
        )]);
        let coverage = [selected.clone(), unselected.clone()];
        let rollback = build_rollback(&verified, Some(&base), &coverage)
            .expect("the single map is consistent");
        let e_sel = rollback.get(&selected).expect("selected present");
        let expected_new = verified_ref_for(&selected, "gen-new", "rel-new", "tree-new");
        assert_eq!(e_sel.generation(), &expected_new.generation);
        assert_eq!(e_sel.artifact(), &expected_new.assignment.artifact);
        let e_unsel = rollback.get(&unselected).expect("unselected present");
        let expected_old = verified_ref_for(&unselected, "gen-old-2", "rel-old", "tree-old-2");
        assert_eq!(e_unsel.generation(), &expected_old.generation);
        assert_eq!(e_unsel.artifact(), &expected_old.assignment.artifact);
        assert!(rollback.get(&outside).is_none());
    }
    #[test]
    fn build_rollback_overlays_replaces_per_slot_entries() {
        let p1 = SlotId::new("p1".to_string());
        let p2 = SlotId::new("p2".to_string());
        let healthy = BTreeMap::from([(p1.clone(), bound(&p1, "gen-new", "rel-new", "tree-new"))]);
        build_rollback(&healthy, None, std::slice::from_ref(&p1))
            .expect("the healthy single map builds");
        let base = LedgerRollback::from_entries(BTreeMap::from([
            (p1.clone(), {
                let r = verified_ref_for(&p1, "gen-old-1", "rel-old", "tree-old-1");
                RollbackEntry::new(
                    r.generation,
                    r.assignment.artifact,
                    PhysicalBinding {
                        server: ServerId::new("s1"),
                        deploy_dir: "/srv/deploy/p1".to_string(),
                    },
                )
            }),
            (p2.clone(), {
                let r = verified_ref_for(&p2, "gen-old-2", "rel-old", "tree-old-2");
                RollbackEntry::new(
                    r.generation,
                    r.assignment.artifact,
                    PhysicalBinding {
                        server: ServerId::new("s2"),
                        deploy_dir: "/srv/deploy/p2".to_string(),
                    },
                )
            }),
        ]));
        let rb = build_rollback(&healthy, Some(&base), &[p1.clone(), p2.clone()])
            .expect("overlay succeeds");
        let e = rb.get(&p1).unwrap();
        let expected = verified_ref_for(&p1, "gen-new", "rel-new", "tree-new");
        assert_eq!(e.generation(), &expected.generation);
        assert!(rb.get(&p2).is_some());
    }
    fn fixture_rollback() -> LedgerRollback {
        let mut m = BTreeMap::new();
        m.insert(
            SlotId::new("slot-1".to_string()),
            RollbackEntry::new(
                test_generation_id("gen-1"),
                ArtifactRef {
                    release: crate::identity::test_release_id("rel-1"),
                    variant: VariantName::new("standard".to_string()),
                    tree: test_tree_digest("t1"),
                },
                PhysicalBinding {
                    server: ServerId::new("s1"),
                    deploy_dir: "/srv/deploy/slot-1".to_string(),
                },
            ),
        );
        m.insert(
            SlotId::new("slot-2".to_string()),
            RollbackEntry::new(
                test_generation_id("gen-2"),
                ArtifactRef {
                    release: crate::identity::test_release_id("rel-2"),
                    variant: VariantName::new("standard".to_string()),
                    tree: test_tree_digest("t2"),
                },
                PhysicalBinding {
                    server: ServerId::new("s2"),
                    deploy_dir: "/srv/deploy/slot-2".to_string(),
                },
            ),
        );
        LedgerRollback::from_entries(m)
    }

    fn entry_json(slot: &str, gen_id: &str, rel: &str, tree: &str, server: &str) -> String {
        let e = RollbackEntry::new(
            test_generation_id(gen_id),
            ArtifactRef {
                release: crate::identity::test_release_id(rel),
                variant: VariantName::new("standard".to_string()),
                tree: test_tree_digest(tree),
            },
            PhysicalBinding {
                server: ServerId::new(server),
                deploy_dir: format!("/srv/deploy/{slot}"),
            },
        );
        serde_json::to_string(&e).unwrap()
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config { cases: 64, rng_seed: proptest::test_runner::RngSeed::Fixed(0x5EED_5EED), failure_persistence: None, ..proptest::test_runner::Config::default() })]
        #[test]
        fn prop_rollback_strict_raw_string_requires_entries_and_unique_slots(_dummy in proptest::strategy::Just(())) {
            // VALID rollback JSON STRING — deterministic fixture via Serialize.
            let rb = fixture_rollback();
            let valid = serde_json::to_string(&rb).unwrap();
            let parsed: crate::ledger::records::LedgerRollbackWire = serde_json::from_str(&valid).unwrap();
            let domain: LedgerRollback = parsed.into();
            prop_assert_eq!(domain, rb);

            // (a) DUPLICATE slot key inside entries — second occurrence of slot-1 with different entry.
            let dup_entry = entry_json("slot-1", "gen-9", "rel-9", "t9", "s9");
            // valid is {"entries":{"slot-1":{...},"slot-2":{...}}} — add ,"slot-1":<dup> inside entries.
            let dup_json = {
                let base = &valid[..valid.len() - 2];
                format!("{},\"slot-1\":{}}}", base, dup_entry)
            };
            let err = serde_json::from_str::<crate::ledger::records::LedgerRollbackWire>(&dup_json).unwrap_err();
            prop_assert!(err.to_string().contains("duplicate rollback slot"), "expected duplicate error, got: {err} / dup_json={dup_json}");

            // (b) MISSING entries member entirely.
            let missing = "{}".to_string();
            prop_assert!(serde_json::from_str::<crate::ledger::records::LedgerRollbackWire>(&missing).is_err());
            let missing2 = r#"{"slots":{"p1":"old-format-data"}}"#;
            prop_assert!(serde_json::from_str::<crate::ledger::records::LedgerRollbackWire>(missing2).is_err());

            // (c) UNKNOWN top-level field added (old "slots" shape).
            let unknown = {
                let inner = &valid[1..valid.len() - 1];
                format!("{{{},\"slots\":{{\"p1\":\"old-format-data\"}}}}", inner)
            };
            prop_assert!(serde_json::from_str::<crate::ledger::records::LedgerRollbackWire>(&unknown).is_err());

            // (d) DUPLICATE top-level "entries" member — two "entries" keys.
            let entries_value = serde_json::to_string(&serde_json::json!({"entries": {"slot-1": serde_json::from_str::<serde_json::Value>(&entry_json("slot-1", "gen-1", "rel-1", "t1", "s1")).unwrap()}})).unwrap();
            // Build {"entries":{...},"entries":{...}}
            let dup_top = format!("{{\"entries\":{{\"slot-1\":{}}},\"entries\":{{\"slot-2\":{}}}}}", entry_json("slot-1", "gen-1", "rel-1", "t1", "s1"), entry_json("slot-2", "gen-2", "rel-2", "t2", "s2"));
            let _ = entries_value; // keep binding used
            prop_assert!(serde_json::from_str::<crate::ledger::records::LedgerRollbackWire>(&dup_top).is_err());

            // Deterministic type-level refusals.
            let bad_gen_as_number = r#"{"entries":{"slot-1":{"generation":123,"artifact":{"release":"rel-sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","variant":"standard","tree":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"binding":{"server":"s1","deploy_dir":"/srv/deploy/slot-1"}}}}"#;
            prop_assert!(serde_json::from_str::<crate::ledger::records::LedgerRollbackWire>(bad_gen_as_number).is_err());
            let bad_artifact_as_string = r#"{"entries":{"slot-1":{"generation":"gen-1","artifact":"not-an-object","binding":{"server":"s1","deploy_dir":"/srv/deploy/slot-1"}}}}"#;
            prop_assert!(serde_json::from_str::<crate::ledger::records::LedgerRollbackWire>(bad_artifact_as_string).is_err());
            let bad_binding_as_array = r#"{"entries":{"slot-1":{"generation":"gen-1","artifact":{"release":"rel-sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","variant":"standard","tree":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"binding":[]}}}"#;
            prop_assert!(serde_json::from_str::<crate::ledger::records::LedgerRollbackWire>(bad_binding_as_array).is_err());
            let bad_entries_as_array = r#"{"entries":[]}"#;
            prop_assert!(serde_json::from_str::<crate::ledger::records::LedgerRollbackWire>(bad_entries_as_array).is_err());
        }
    }
    #[test]
    fn rollback_two_entries_round_trip() {
        let rb = fixture_rollback();
        let json = serde_json::to_string(&rb).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("entries").is_some());
        assert_eq!(v.get("entries").unwrap().as_object().unwrap().len(), 2);
        let back: crate::ledger::records::LedgerRollbackWire = serde_json::from_str(&json).unwrap();
        let back: LedgerRollback = back.into();
        assert_eq!(back, rb);
    }
    #[test]
    fn rollback_entries_shape_round_trips_and_old_shape_rejected() {
        let slot = SlotId::new("p1".to_string());
        let rb = LedgerRollback::from_entries(BTreeMap::from([(
            slot.clone(),
            RollbackEntry::new(
                test_generation_id("g1"),
                ArtifactRef {
                    release: crate::identity::test_release_id("rel-1"),
                    variant: VariantName::new("standard".to_string()),
                    tree: test_tree_digest("t1"),
                },
                PhysicalBinding {
                    server: ServerId::new("s1"),
                    deploy_dir: "/srv/deploy/p1".to_string(),
                },
            ),
        )]));
        let json_str = serde_json::to_string(&rb).unwrap();
        let json: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(json.get("entries").is_some());
        assert!(json.get("slots").is_none());
        let wire: crate::ledger::records::LedgerRollbackWire =
            serde_json::from_str(&json_str).unwrap();
        let back: LedgerRollback = wire.into();
        assert_eq!(back, rb);
        let did = test_deployment_id("deploy-old");
        let old_line = format!(
            r#"{{"kind":"terminal","deployment_id":"{did}","target":"production","status":"successful","recorded_at":"2026-01-01T00:00:00Z","outcomes":{{}},"rollback":{{"entries":{{}}}}}}"#
        );
        let err = serde_json::from_str::<crate::ledger::records::LedgerTerminalWire>(&old_line).expect_err("an old-shape terminal line without the v3 memberships must fail deserialization fail-closed");
        assert!(
            err.to_string().contains("selected_membership")
                || err.to_string().contains("full_membership")
        );
    }
}
