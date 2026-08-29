//! REPLAY-SAFE, LOCK-VERIFIED FINALIZATION of a successful deployment

use crate::error::{Error, Result};
use crate::identity::{
    GenerationRef, NonEmptySlotSet, OperationId, PlacementSlotAssignment, SlotId,
};
pub use crate::ledger::records::{
    DeploymentIntent, LedgerEntry, LedgerIntentWire, LedgerTerminal, LedgerTerminalWire,
    PhysicalBinding, TargetSnapshot, TerminalDisposition,
};
use crate::ledger::records::{SuccessfulTerminal, validate_successful_rollback_against_intent};
use crate::remote::helper::{HeldSlotLock, RemoteHelper};
use crate::store::local::LocalStore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub fn finalize_successful_locked(
    store: &LocalStore,
    attempt: &DeploymentIntent,
    helpers: &HashMap<SlotId, RemoteHelper>,
    settings: &FinalizeSettings<'_>,
) -> Result<FinalizeOutcome> {
    let FinalizeSettings { reason, op_id } = settings;
    let entries = store.read_ledger(attempt.target.as_str())?;
    if let Some(e) = entries
        .iter()
        .find(|e| e.deployment_id == attempt.deployment_id)
        && e.terminal.is_some()
    {
        return Ok(FinalizeOutcome::Finalized);
    }
    let mut selected: Vec<&SlotId> = attempt.selected.keys().collect();
    selected.sort();
    let mut guards: Vec<HeldSlotLock<'_>> = Vec::with_capacity(selected.len());
    for sid in &selected {
        let Some(helper) = helpers.get(sid) else {
            return Ok(FinalizeOutcome::Refused {
                reason: "state diverged",
                slot: (*sid).clone(),
            });
        };
        match helper.acquire_lock_guard(op_id) {
            Ok(guard) => guards.push(guard),
            Err(_) => return Ok(FinalizeOutcome::Pending),
        }
    }
    match verify_selected_locked(helpers, attempt)? {
        LockedObservation::Diverged(slot) => {
            return Ok(FinalizeOutcome::Refused {
                reason: "state diverged",
                slot,
            });
        }
        LockedObservation::Verified(_) => {}
    }
    let slot_ids: Vec<String> = attempt
        .selected
        .keys()
        .map(|s| s.as_str().to_string())
        .collect();
    for (idx, sid) in selected.iter().enumerate() {
        let guard = &guards[idx];
        let entry = attempt
            .resulting_snapshot
            .get(sid)
            .expect("selected in snapshot");
        match guard.write_commit_marker(
            attempt.deployment_id.as_str(),
            entry.generation().as_str(),
            &slot_ids,
            Some(attempt.target.as_str()),
        ) {
            Err(Error::Integrity(_)) => {
                return Ok(FinalizeOutcome::Refused {
                    reason: "marker integrity conflict",
                    slot: (*sid).clone(),
                });
            }
            Err(_) => return Ok(FinalizeOutcome::Pending),
            Ok(_) => {}
        }
    }
    let observed = match verify_selected_locked(helpers, attempt)? {
        LockedObservation::Verified(o) => o,
        LockedObservation::Diverged(slot) => {
            return Ok(FinalizeOutcome::Refused {
                reason: "state diverged",
                slot,
            });
        }
    };
    let _ = observed;
    let rollback = attempt.resulting_snapshot.clone();
    let selected_set: BTreeSet<SlotId> = selected.iter().map(|sid| (*sid).clone()).collect();
    validate_successful_rollback_against_intent(attempt, &rollback, &selected_set)?;
    let activated_set = NonEmptySlotSet::try_new(selected.iter().map(|sid| (*sid).clone()))
        .ok_or_else(|| {
            Error::integrity(format!(
                "finalize {}: activated must be non-empty",
                attempt.deployment_id
            ))
        })?;
    let st = SuccessfulTerminal::try_new(rollback, activated_set)?;
    let terminal = LedgerTerminal {
        recorded_at: crate::remote::helper::now_rfc3339(),
        disposition: TerminalDisposition::Successful(st),
        reason: Some(reason.to_string()),
    };
    store.append_terminal(attempt.target.as_str(), &attempt.deployment_id, &terminal)?;
    Ok(FinalizeOutcome::Finalized)
}

pub struct FinalizeSettings<'a> {
    pub reason: &'a str,
    pub op_id: &'a OperationId,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FinalizeOutcome {
    Finalized,
    Pending,
    Refused { reason: &'static str, slot: SlotId },
}
enum LockedObservation {
    Verified(BTreeMap<SlotId, GenerationRef>),
    Diverged(SlotId),
}
fn verify_selected_locked(
    helpers: &HashMap<SlotId, RemoteHelper>,
    attempt: &DeploymentIntent,
) -> Result<LockedObservation> {
    let mut observed: BTreeMap<SlotId, GenerationRef> = BTreeMap::new();
    let mut selected: Vec<&SlotId> = attempt.selected.keys().collect();
    selected.sort();
    for sid in selected {
        let entry = attempt
            .resulting_snapshot
            .get(sid)
            .expect("selected in snapshot");
        let Some(helper) = helpers.get(sid) else {
            return Ok(LockedObservation::Diverged(sid.clone()));
        };
        let st1 = helper.status()?;
        let Some(live_gen) = st1.current_generation else {
            return Ok(LockedObservation::Diverged(sid.clone()));
        };
        let asn = helper.read_assignment(live_gen.as_str())?;
        let st2 = helper.status()?;
        if st2.current_generation.as_ref() != Some(&live_gen)
            || live_gen != *entry.generation()
            || asn.artifact != *entry.artifact()
        {
            return Ok(LockedObservation::Diverged(sid.clone()));
        }
        observed.insert(
            sid.clone(),
            GenerationRef {
                generation: live_gen,
                assignment: PlacementSlotAssignment {
                    placement_slot: sid.clone(),
                    artifact: asn.artifact,
                },
            },
        );
    }
    Ok(LockedObservation::Verified(observed))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LedgerLine {
    Intent(LedgerIntentWire),
    Terminal(LedgerTerminalWire),
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{
        ArtifactRef, ServerId, SlotId, TargetName, VariantName, test_deployment_id,
        test_generation_id, test_tree_digest,
    };
    use crate::ledger::records::{DeploymentIntent, SelectedSlotIntent};
    use crate::ledger::records::{
        DeploymentStatus, NonEmptySlotTable, SnapshotEntry, TargetSnapshot,
    };
    use std::collections::BTreeMap;
    fn intent(dep: &str) -> DeploymentIntent {
        let p1 = SlotId::parse("p1").unwrap();
        let artifact = ArtifactRef {
            release: crate::identity::test_release_id("rel-1"),
            variant: VariantName::parse("standard").unwrap(),
            tree: test_tree_digest("tree-1"),
        };
        let binding = crate::ledger::PhysicalBinding {
            server: ServerId::parse("s1").unwrap(),
            deploy_dir: "/srv/deploy/p1".to_string(),
        };
        let entries = BTreeMap::from([(
            p1.clone(),
            SnapshotEntry::new(test_generation_id("gen-1"), artifact.clone(), binding),
        )]);
        let snapshot = TargetSnapshot::from_entries(entries);
        DeploymentIntent {
            deployment_id: test_deployment_id(dep),
            target: TargetName::parse("production").unwrap(),
            group: None,
            resulting_snapshot: snapshot,
            selected: NonEmptySlotTable::build(BTreeMap::from([(
                p1,
                SelectedSlotIntent { pre_push: None },
            )]))
            .expect("fixture"),
            behavior_sha256: crate::identity::BehaviorDigest::parse(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )
            .unwrap(),
            attempted_at: crate::identity::Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        }
    }
    #[test]
    fn finalize_is_idempotent_by_deployment_id() {
        use crate::identity::OperationId;
        use crate::remote::helper::{ExpectedCurrent, RemoteHelper};
        use crate::remote::transport::{LocalTransport, Remote};
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let target = TargetName::parse("production").unwrap();
        let attempt = intent("deploy-idempotent");
        store.append_intent(target.as_str(), &attempt).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), tmp.path().join("remote"))
                .unwrap();
        let helper = RemoteHelper::new(&remote);
        remote
            .create_dir_all(&crate::remote::layout::tree_root(
                test_tree_digest("tree-1").as_str(),
            ))
            .unwrap();
        helper
            .acquire_lock_guard(&crate::identity::OperationId::new("op-seed".to_string()))
            .unwrap()
            .create_generation(&crate::remote::helper::GenerationAssignment {
                deployment_id: attempt.deployment_id.clone(),
                generation_id: test_generation_id("gen-1"),
                artifact: ArtifactRef {
                    release: crate::identity::test_release_id("rel-1"),
                    variant: VariantName::new("standard".to_string()),
                    tree: test_tree_digest("tree-1"),
                },
                behavior_sha256: "sha256-aa".to_string(),
                prior_generation: None,
                created_at: "2026-01-01T00:00:00Z".to_string(),
                target: Some(target.clone()),
            })
            .unwrap();
        helper
            .acquire_lock_guard(&crate::identity::OperationId::new("op-seed".to_string()))
            .unwrap()
            .swap_current(
                &ExpectedCurrent::Absent,
                test_generation_id("gen-1").as_str(),
                "op-seed",
            )
            .unwrap();
        let helpers = HashMap::from([(SlotId::new("p1"), helper)]);
        let settings = FinalizeSettings {
            reason: "push completed",
            op_id: &OperationId::new("op-finalize-test".to_string()),
        };
        assert_eq!(
            finalize_successful_locked(&store, &attempt, &helpers, &settings).unwrap(),
            FinalizeOutcome::Finalized
        );
        let entries = store.read_ledger(target.as_str()).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].terminal.is_some());
        assert_eq!(
            store
                .latest_status(test_deployment_id("deploy-idempotent").as_str())
                .unwrap(),
            Some(DeploymentStatus::Successful)
        );
        assert_eq!(
            finalize_successful_locked(&store, &attempt, &helpers, &settings).unwrap(),
            FinalizeOutcome::Finalized
        );
        let entries = store.read_ledger(target.as_str()).unwrap();
        assert_eq!(entries.len(), 1);
    }
    #[test]
    fn finalize_payload_ignores_stale_observed_values() {
        use crate::identity::OperationId;
        use crate::remote::helper::{ExpectedCurrent, RemoteHelper};
        use crate::remote::transport::{LocalTransport, Remote};
        let tmp = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let target = TargetName::parse("production").unwrap();
        let attempt = intent("deploy-stale-observed");
        store.append_intent(target.as_str(), &attempt).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), tmp.path().join("remote"))
                .unwrap();
        let helper = RemoteHelper::new(&remote);
        remote
            .create_dir_all(&crate::remote::layout::tree_root(
                test_tree_digest("tree-1").as_str(),
            ))
            .unwrap();
        helper
            .acquire_lock_guard(&crate::identity::OperationId::new("op-seed".to_string()))
            .unwrap()
            .create_generation(&crate::remote::helper::GenerationAssignment {
                deployment_id: attempt.deployment_id.clone(),
                generation_id: test_generation_id("gen-1"),
                artifact: ArtifactRef {
                    release: crate::identity::test_release_id("rel-1"),
                    variant: VariantName::new("standard".to_string()),
                    tree: test_tree_digest("tree-1"),
                },
                behavior_sha256: "sha256-aa".to_string(),
                prior_generation: None,
                created_at: "2026-01-01T00:00:00Z".to_string(),
                target: Some(target.clone()),
            })
            .unwrap();
        helper
            .acquire_lock_guard(&crate::identity::OperationId::new("op-seed".to_string()))
            .unwrap()
            .swap_current(
                &ExpectedCurrent::Absent,
                test_generation_id("gen-1").as_str(),
                "op-seed",
            )
            .unwrap();
        let helpers = HashMap::from([(SlotId::new("p1"), helper)]);
        let settings = FinalizeSettings {
            reason: "push completed",
            op_id: &OperationId::new("op-stale-test".to_string()),
        };
        assert_eq!(
            finalize_successful_locked(&store, &attempt, &helpers, &settings).unwrap(),
            FinalizeOutcome::Finalized
        );
        let entries = store.read_ledger(target.as_str()).unwrap();
        let terminal = entries[0].terminal.as_ref().expect("terminal");
        let TerminalDisposition::Successful(st) = &terminal.disposition else {
            panic!()
        };
        assert_eq!(
            st.activated().as_set(),
            &BTreeSet::from([SlotId::new("p1")])
        );
    }
    #[test]
    fn rollback_desired_guard_refuses_diverged_payload() {
        use crate::ledger::records::validate_successful_rollback_against_intent;
        let attempt = intent("deploy-guard");
        let sid = SlotId::parse("p1").unwrap();
        let matching = attempt.resulting_snapshot.clone();
        let activated: BTreeSet<SlotId> = attempt.selected.keys().cloned().collect();
        validate_successful_rollback_against_intent(&attempt, &matching, &activated)
            .expect("matching passes");
        let mut diverged_entries = matching.clone().into_entries();
        diverged_entries.insert(
            sid.clone(),
            SnapshotEntry::new(
                test_generation_id("gen-stale"),
                ArtifactRef {
                    release: crate::identity::test_release_id("rel-stale"),
                    variant: VariantName::parse("standard").unwrap(),
                    tree: test_tree_digest("tree-stale"),
                },
                crate::ledger::PhysicalBinding {
                    server: ServerId::parse("s-other").unwrap(),
                    deploy_dir: "/srv/other".to_string(),
                },
            ),
        );
        let diverged = TargetSnapshot::from_entries(diverged_entries);
        assert!(
            validate_successful_rollback_against_intent(&attempt, &diverged, &activated).is_err()
        );
    }
}
