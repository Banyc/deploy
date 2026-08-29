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
//! [`crate::ledger::records::TargetSnapshot`]: per-slot generation refs +
//! COMPLETE physical bindings), so EXACT ROLLBACK is possible:
//! `deploy push <target> <deployment-id>` restores exactly that
//! deployment's stored state, verified by the binding map (a missing
//! binding entry is "unverifiable" and makes exact rollback refuse the
//! slot).
//!
//! The wire/domain RECORDS themselves ([`crate::ledger::records::TargetSnapshot`],
//! [`crate::ledger::records::PhysicalBinding`]) live in the shared core
//! ([`crate::ledger::records`]).
//!
//! The SHARED VALIDATOR ([`validate_successful_rollback_against_intent`])
//! enforces that a Successful rollback REPRODUCES the durable intent's
//! frozen facts for every ACTIVATED slot — generation, artifact, and
//! physical binding — and is called from BOTH the writer pre-append guard
//! ([`crate::ledger::finalize::finalize_successful_locked`]) and the ledger
//! read ([`crate::store::local::LocalStore::read_ledger`] via
//! `verify_terminal_against_entry`): a rollback that drifts from its own
//! intent fails closed with `Error::integrity` naming the slot and the
//! diverging leg.

use crate::error::{Error, Result};
use crate::identity::{GenerationRef, SlotId};
use std::collections::{BTreeMap, BTreeSet};

use super::super::{DeploymentIntent, PhysicalBinding, SnapshotEntry, TargetSnapshot};

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
    base: Option<&TargetSnapshot>,
    current_slot_ids: &[SlotId],
) -> Result<TargetSnapshot> {
    let mut entries: BTreeMap<SlotId, SnapshotEntry> =
        base.map(|b| b.clone().into_entries()).unwrap_or_default();
    for (slot, bg) in verified {
        entries.insert(
            slot.clone(),
            SnapshotEntry::new(
                bg.generation.generation.clone(),
                bg.generation.assignment.artifact.clone(),
                bg.binding.clone(),
            ),
        );
    }
    let current: std::collections::HashSet<&str> =
        current_slot_ids.iter().map(|s| s.as_str()).collect();
    entries.retain(|k, _| current.contains(k.as_str()));
    Ok(TargetSnapshot::from_entries(entries))
}

/// ONE shared validator: a Successful rollback must EXACTLY EQUAL the
/// intent's frozen `resulting_snapshot` (complete snapshot equality) AND
/// `activated` must EXACTLY equal the intent's `selected` keys.
pub(crate) fn validate_successful_rollback_against_intent(
    intent: &DeploymentIntent,
    rollback: &TargetSnapshot,
    activated: &BTreeSet<SlotId>,
) -> Result<()> {
    if rollback != &intent.resulting_snapshot {
        return Err(Error::integrity(format!(
            "rollback-vs-intent: the rollback snapshot diverges from the intent's frozen resulting_snapshot — the terminal's rollback must EXACTLY equal the intent's frozen snapshot (full equality over ALL slots)"
        )));
    }
    let selected = intent.selected_membership();
    if activated != &selected {
        return Err(Error::integrity(format!(
            "rollback-vs-intent: activated {activated:?} != intent selected {selected:?} — the terminal's activated set must EXACTLY equal the intent's selected slots"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests_rollback {
    use super::*;
    use crate::identity::{
        ArtifactRef, GenerationRef, PlacementSlotAssignment, ServerId, SlotId, TargetName,
        VariantName, test_deployment_id, test_generation_id, test_tree_digest,
    };
    #[cfg(test)]
    use proptest::prelude::*;
    use std::collections::{BTreeMap, BTreeSet};

    fn verified_ref_for(key: &SlotId, gen_id: &str, rel: &str, tree: &str) -> GenerationRef {
        GenerationRef {
            generation: test_generation_id(gen_id),
            assignment: PlacementSlotAssignment {
                placement_slot: key.clone(),
                artifact: ArtifactRef {
                    release: crate::identity::test_release_id(rel),
                    variant: VariantName::parse("standard").unwrap(),
                    tree: test_tree_digest(tree),
                },
            },
        }
    }
    fn bound(key: &SlotId, gen_id: &str, rel: &str, tree: &str) -> BoundGeneration {
        BoundGeneration {
            generation: verified_ref_for(key, gen_id, rel, tree),
            binding: PhysicalBinding {
                server: ServerId::parse("s1").unwrap(),
                deploy_dir: format!("/srv/deploy/{}", key.as_str()),
            },
        }
    }
    #[test]
    fn build_rollback_records_each_slots_physical_binding() {
        let slot = SlotId::parse("p1").unwrap();
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
        let selected = SlotId::parse("p1").unwrap();
        let unselected = SlotId::parse("p2").unwrap();
        let outside = SlotId::parse("p3").unwrap();
        let base = TargetSnapshot::from_entries(BTreeMap::from([
            (selected.clone(), {
                let r = verified_ref_for(&selected, "gen-old-1", "rel-old", "tree-old-1");
                SnapshotEntry::new(
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
                SnapshotEntry::new(
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
                SnapshotEntry::new(
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
        let p1 = SlotId::parse("p1").unwrap();
        let p2 = SlotId::parse("p2").unwrap();
        let healthy = BTreeMap::from([(p1.clone(), bound(&p1, "gen-new", "rel-new", "tree-new"))]);
        build_rollback(&healthy, None, std::slice::from_ref(&p1))
            .expect("the healthy single map builds");
        let base = TargetSnapshot::from_entries(BTreeMap::from([
            (p1.clone(), {
                let r = verified_ref_for(&p1, "gen-old-1", "rel-old", "tree-old-1");
                SnapshotEntry::new(
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
                SnapshotEntry::new(
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
    fn fixture_rollback() -> TargetSnapshot {
        let mut m = BTreeMap::new();
        m.insert(
            SlotId::parse("slot-1").unwrap(),
            SnapshotEntry::new(
                test_generation_id("gen-1"),
                ArtifactRef {
                    release: crate::identity::test_release_id("rel-1"),
                    variant: VariantName::parse("standard").unwrap(),
                    tree: test_tree_digest("t1"),
                },
                PhysicalBinding {
                    server: ServerId::new("s1"),
                    deploy_dir: "/srv/deploy/slot-1".to_string(),
                },
            ),
        );
        m.insert(
            SlotId::parse("slot-2").unwrap(),
            SnapshotEntry::new(
                test_generation_id("gen-2"),
                ArtifactRef {
                    release: crate::identity::test_release_id("rel-2"),
                    variant: VariantName::parse("standard").unwrap(),
                    tree: test_tree_digest("t2"),
                },
                PhysicalBinding {
                    server: ServerId::new("s2"),
                    deploy_dir: "/srv/deploy/slot-2".to_string(),
                },
            ),
        );
        TargetSnapshot::from_entries(m)
    }

    fn entry_json(slot: &str, gen_id: &str, rel: &str, tree: &str, server: &str) -> String {
        let e = SnapshotEntry::new(
            test_generation_id(gen_id),
            ArtifactRef {
                release: crate::identity::test_release_id(rel),
                variant: VariantName::parse("standard").unwrap(),
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
            let parsed: crate::ledger::records::TargetSnapshotWire = serde_json::from_str(&valid).unwrap();
            let domain: TargetSnapshot = parsed.into();
            prop_assert_eq!(domain, rb);

            // (a) DUPLICATE slot key inside entries — second occurrence of slot-1 with different entry.
            let dup_entry = entry_json("slot-1", "gen-9", "rel-9", "t9", "s9");
            // valid is {"entries":{"slot-1":{...},"slot-2":{...}}} — add ,"slot-1":<dup> inside entries.
            let dup_json = {
                let base = &valid[..valid.len() - 2];
                format!("{},\"slot-1\":{}}}", base, dup_entry)
            };
            let err = serde_json::from_str::<crate::ledger::records::TargetSnapshotWire>(&dup_json).unwrap_err();
            prop_assert!(err.to_string().contains("duplicate rollback slot"), "expected duplicate error, got: {err} / dup_json={dup_json}");

            // (b) MISSING entries member entirely.
            let missing = "{}".to_string();
            prop_assert!(serde_json::from_str::<crate::ledger::records::TargetSnapshotWire>(&missing).is_err());
            let missing2 = r#"{"slots":{"p1":"old-format-data"}}"#;
            prop_assert!(serde_json::from_str::<crate::ledger::records::TargetSnapshotWire>(missing2).is_err());

            // (c) UNKNOWN top-level field added (old "slots" shape).
            let unknown = {
                let inner = &valid[1..valid.len() - 1];
                format!("{{{},\"slots\":{{\"p1\":\"old-format-data\"}}}}", inner)
            };
            prop_assert!(serde_json::from_str::<crate::ledger::records::TargetSnapshotWire>(&unknown).is_err());

            // (d) DUPLICATE top-level "entries" member — two "entries" keys.
            let entries_value = serde_json::to_string(&serde_json::json!({"entries": {"slot-1": serde_json::from_str::<serde_json::Value>(&entry_json("slot-1", "gen-1", "rel-1", "t1", "s1")).unwrap()}})).unwrap();
            // Build {"entries":{...},"entries":{...}}
            let dup_top = format!("{{\"entries\":{{\"slot-1\":{}}},\"entries\":{{\"slot-2\":{}}}}}", entry_json("slot-1", "gen-1", "rel-1", "t1", "s1"), entry_json("slot-2", "gen-2", "rel-2", "t2", "s2"));
            let _ = entries_value; // keep binding used
            prop_assert!(serde_json::from_str::<crate::ledger::records::TargetSnapshotWire>(&dup_top).is_err());

            // Deterministic type-level refusals.
            let bad_gen_as_number = r#"{"entries":{"slot-1":{"generation":123,"artifact":{"release":"rel-sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","variant":"standard","tree":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"binding":{"server":"s1","deploy_dir":"/srv/deploy/slot-1"}}}}"#;
            prop_assert!(serde_json::from_str::<crate::ledger::records::TargetSnapshotWire>(bad_gen_as_number).is_err());
            let bad_artifact_as_string = r#"{"entries":{"slot-1":{"generation":"gen-1","artifact":"not-an-object","binding":{"server":"s1","deploy_dir":"/srv/deploy/slot-1"}}}}"#;
            prop_assert!(serde_json::from_str::<crate::ledger::records::TargetSnapshotWire>(bad_artifact_as_string).is_err());
            let bad_binding_as_array = r#"{"entries":{"slot-1":{"generation":"gen-1","artifact":{"release":"rel-sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","variant":"standard","tree":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"binding":[]}}}"#;
            prop_assert!(serde_json::from_str::<crate::ledger::records::TargetSnapshotWire>(bad_binding_as_array).is_err());
            let bad_entries_as_array = r#"{"entries":[]}"#;
            prop_assert!(serde_json::from_str::<crate::ledger::records::TargetSnapshotWire>(bad_entries_as_array).is_err());
        }
    }
    #[test]
    fn rollback_two_entries_round_trip() {
        let rb = fixture_rollback();
        let json = serde_json::to_string(&rb).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("entries").is_some());
        assert_eq!(v.get("entries").unwrap().as_object().unwrap().len(), 2);
        let back: crate::ledger::records::TargetSnapshotWire = serde_json::from_str(&json).unwrap();
        let back: TargetSnapshot = back.into();
        assert_eq!(back, rb);
    }
    #[test]
    fn rollback_entries_shape_round_trips_and_old_shape_rejected() {
        let slot = SlotId::parse("p1").unwrap();
        let rb = TargetSnapshot::from_entries(BTreeMap::from([(
            slot.clone(),
            SnapshotEntry::new(
                test_generation_id("g1"),
                ArtifactRef {
                    release: crate::identity::test_release_id("rel-1"),
                    variant: VariantName::parse("standard").unwrap(),
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
        let wire: crate::ledger::records::TargetSnapshotWire =
            serde_json::from_str(&json_str).unwrap();
        let back: TargetSnapshot = wire.into();
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

    // ---- SHARED VALIDATOR: ROLLBACK VS INTENT (the user's contract) ----
    // Build a VALID intent/terminal pair from fixtures and mutate ONE leg.
    // The terminal stays INTERNALLY self-consistent (memberships, outcomes
    // keys, rollback keys untouched except the mutated entry) — the mismatch
    // is ONLY against the intent, so the record is self-consistent yet
    // contradicts its intent. Both writer and read paths must fail closed.
    //
    // THE FIXTURE IS A GROUP PUSH (`group: Some("g1")`): the resulting
    // snapshot FREEZES the FULL membership (the SELECTED `p1` at its minted
    // generation + the UNSELECTED `p2` carried forward), and the intent
    // SELECTS only `p1` (`activated == selected == {p1}`). The rollback-vs-
    // intent validator demands FULL equality (rollback == the intent's
    // resulting_snapshot over ALL slots) — so mutating either the SELECTED
    // slot's snapshot entry (legs 0-5) or the UNSELECTED slot's entry (leg
    // 6) diverges the full snapshot and must fail closed.
    fn valid_intent_rollback_activated() -> (
        crate::ledger::records::DeploymentIntent,
        TargetSnapshot,
        BTreeSet<SlotId>,
    ) {
        let selected = SlotId::parse("p1").unwrap();
        let unselected = SlotId::parse("p2").unwrap();
        let gen_id = test_generation_id("gen-1");
        let artifact = ArtifactRef {
            release: crate::identity::test_release_id("rel-1"),
            variant: VariantName::parse("standard").unwrap(),
            tree: test_tree_digest("tree-1"),
        };
        let binding = PhysicalBinding {
            server: ServerId::parse("s1").unwrap(),
            deploy_dir: "/srv/deploy/p1".to_string(),
        };
        let mut entries = BTreeMap::new();
        entries.insert(
            selected.clone(),
            SnapshotEntry::new(gen_id.clone(), artifact.clone(), binding.clone()),
        );
        // The UNSELECTED slot the group push carries forward in the frozen
        // snapshot (its own generation/artifact/binding).
        entries.insert(
            unselected.clone(),
            SnapshotEntry::new(
                test_generation_id("gen-unsel"),
                ArtifactRef {
                    release: crate::identity::test_release_id("rel-unsel"),
                    variant: VariantName::parse("standard").unwrap(),
                    tree: test_tree_digest("tree-unsel"),
                },
                PhysicalBinding {
                    server: ServerId::parse("s1").unwrap(),
                    deploy_dir: "/srv/deploy/p2".to_string(),
                },
            ),
        );
        let snapshot = TargetSnapshot::from_entries(entries);
        let intent = crate::ledger::records::DeploymentIntent {
            deployment_id: test_deployment_id("deploy-valid"),
            target: TargetName::parse("production").unwrap(),
            group: Some(crate::identity::RolloutGroupName::parse("g1").unwrap()),
            resulting_snapshot: snapshot.clone(),
            selected: crate::ledger::tables::NonEmptySlotTable::build(BTreeMap::from([(
                selected.clone(),
                crate::ledger::records::SelectedSlotIntent {
                    pre_push: None,
                    ..Default::default()
                },
            )]))
            .unwrap(),
            behavior_sha256: crate::identity::BehaviorDigest::parse(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )
            .unwrap(),
            attempted_at: crate::identity::Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        };
        let rollback = snapshot;
        let activated = BTreeSet::from([selected]);
        (intent, rollback, activated)
    }

    fn mutate_rollback_for_leg(
        rollback: TargetSnapshot,
        slot: &SlotId,
        leg: u32,
    ) -> TargetSnapshot {
        let entry = rollback.get(slot).unwrap().clone();
        let mutated = match leg {
            0 => SnapshotEntry::new(
                test_generation_id("gen-other"),
                entry.artifact().clone(),
                entry.binding().clone(),
            ),
            1 => SnapshotEntry::new(
                entry.generation().clone(),
                ArtifactRef {
                    release: crate::identity::test_release_id("rel-other"),
                    variant: entry.artifact().variant.clone(),
                    tree: entry.artifact().tree.clone(),
                },
                entry.binding().clone(),
            ),
            2 => SnapshotEntry::new(
                entry.generation().clone(),
                ArtifactRef {
                    release: entry.artifact().release.clone(),
                    variant: VariantName::parse("other-variant").unwrap(),
                    tree: entry.artifact().tree.clone(),
                },
                entry.binding().clone(),
            ),
            3 => SnapshotEntry::new(
                entry.generation().clone(),
                ArtifactRef {
                    release: entry.artifact().release.clone(),
                    variant: entry.artifact().variant.clone(),
                    tree: test_tree_digest("other-tree"),
                },
                entry.binding().clone(),
            ),
            4 => SnapshotEntry::new(
                entry.generation().clone(),
                entry.artifact().clone(),
                PhysicalBinding {
                    server: ServerId::parse("s-other").unwrap(),
                    deploy_dir: entry.binding().deploy_dir.clone(),
                },
            ),
            5 => SnapshotEntry::new(
                entry.generation().clone(),
                entry.artifact().clone(),
                PhysicalBinding {
                    server: entry.binding().server.clone(),
                    deploy_dir: "/srv/other/deploy".to_string(),
                },
            ),
            6 => SnapshotEntry::new(
                test_generation_id("gen-unsel-other"),
                entry.artifact().clone(),
                entry.binding().clone(),
            ),
            _ => unreachable!(),
        };
        let mut map = rollback.into_entries();
        map.insert(slot.clone(), mutated);
        TargetSnapshot::from_entries(map)
    }

    fn assert_leg_fails_closed(leg: u32) {
        let (intent, base_rollback, activated) = valid_intent_rollback_activated();
        // Legs 0-5 mutate the SELECTED slot's snapshot entry (its generation
        // / release / variant / tree / server / deploy_dir); leg 6 mutates
        // the UNSELECTED slot's snapshot entry — the validator demands FULL
        // equality (rollback == intent.resulting_snapshot over ALL slots), so
        // both a selected-entry mutation and an unselected-entry mutation
        // diverge the full snapshot and fail.
        let selected = SlotId::parse("p1").unwrap();
        let unselected = SlotId::parse("p2").unwrap();
        let slot = if leg == 6 { unselected } else { selected };
        let mutated_rollback = mutate_rollback_for_leg(base_rollback, &slot, leg);
        // (a) writer direct validator
        let res =
            validate_successful_rollback_against_intent(&intent, &mutated_rollback, &activated);
        assert!(res.is_err(), "writer validator must fail for leg {leg}");
        assert!(
            res.err()
                .unwrap()
                .to_string()
                .contains("rollback-vs-intent"),
            "err must contain rollback-vs-intent"
        );
        // (a) store append refuses (via verify_terminal_against_entry)
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = crate::store::local::LocalStore::with_base(tmp.path().join("store")).unwrap();
        store
            .append_intent(intent.target.as_str(), &intent)
            .unwrap();
        let mutated_terminal = crate::ledger::records::LedgerTerminal {
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
            disposition: crate::ledger::records::TerminalDisposition::Successful(
                crate::ledger::SuccessfulTerminal::try_new(
                    mutated_rollback.clone(),
                    crate::identity::NonEmptySlotSet::try_new(activated.clone()).unwrap(),
                )
                .unwrap(),
            ),
            reason: None,
        };
        let append_res = store.append_terminal(
            intent.target.as_str(),
            &intent.deployment_id,
            &mutated_terminal,
        );
        assert!(append_res.is_err(), "store append must fail for leg {leg}");
        let append_err = append_res.unwrap_err().to_string();
        assert!(
            append_err.contains("rollback-vs-intent") || append_err.contains("integrity"),
            "append err must be integrity/rollback-vs-intent, got: {append_err}"
        );
        // (b) read path fails closed (direct ledger file with mutated wire)
        let tmp2 = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let read_store =
            crate::store::local::LocalStore::with_base(tmp2.path().join("store")).unwrap();
        let intent_wire = crate::ledger::records::LedgerIntentWire::from(&intent);
        let terminal_wire = crate::ledger::records::LedgerTerminalWire::try_from_domain(
            &intent.deployment_id,
            &intent.target,
            &mutated_terminal,
        )
        .unwrap();
        let line1 =
            serde_json::to_string(&crate::ledger::finalize::LedgerLine::Intent(intent_wire))
                .unwrap();
        let line2 = serde_json::to_string(&crate::ledger::finalize::LedgerLine::Terminal(
            terminal_wire,
        ))
        .unwrap();
        let p = read_store.ledger_path(intent.target.as_str());
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, format!("{line1}\n{line2}\n")).unwrap();
        let read_res = read_store.read_ledger(intent.target.as_str());
        assert!(read_res.is_err(), "read_ledger must fail for leg {leg}");
        assert!(
            read_res
                .unwrap_err()
                .to_string()
                .contains("rollback-vs-intent"),
            "read err must contain rollback-vs-intent"
        );
    }

    #[test]
    fn rollback_vs_intent_deterministic_legs() {
        for leg in 0..=6 {
            assert_leg_fails_closed(leg);
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config { cases: 64, rng_seed: proptest::test_runner::RngSeed::Fixed(0x5EED_5EED), failure_persistence: None, ..proptest::test_runner::Config::default() })]
        #[test]
        fn prop_rollback_vs_intent_fails_closed_on_every_leg(leg in 0..=6u32) {
            assert_leg_fails_closed(leg);
        }
    }
}
