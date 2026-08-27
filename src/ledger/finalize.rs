//! REPLAY-SAFE FINALIZATION of a successful deployment (feature area A2:
//! Ledger semantics).
//!
//! [`finalize_successful_attempt`] is the SINGLE shared terminal path used
//! by BOTH the normal push success path and recovery
//! ([`crate::ledger::recovery::reconcile_pending_commits`]): it APPENDS the
//! TERMINAL EVENT (status `Successful`, the per-slot `outcomes`, and the
//! rollback state built from `actuals`) to the target's ledger — ONE atomic
//! line append, the only commit of the finalize. Replay idempotency: a
//! crash after the append can never duplicate the terminal (a repeated
//! finalize for the same deployment id is a no-op; the store refuses
//! duplicate appends). The rollback payload itself is built by
//! [`crate::ledger::rollback::build_rollback`] (the complete-snapshot
//! overlay + exact-rollback verification semantics).
//!
//! [`recovery_outcomes`] derives the per-slot outcomes + actuals used to
//! finalize a PENDING deployment when the engine no longer has the live
//! outcomes at hand (recovery has already verified each slot's live
//! generation equals the desired generation, so the outcomes ARE the
//! desired assignments).
//!
use crate::error::{Error, Result};
use crate::ledger::records::{
    DeploymentIntent, LedgerTerminal, PhysicalBinding, SlotAttemptState, SlotOutcome, SlotResult,
    SlotTable, TerminalDisposition,
};
use crate::ledger::rollback::build_rollback;
use crate::model::SlotId;
use crate::store::local::LocalStore;
use std::collections::{BTreeMap, BTreeSet};

/// Finalize a successful deployment replay-safely: the SINGLE shared
/// terminal path used by BOTH the normal push success path and recovery
/// ([`crate::push::reconcile::reconcile_pending_commits`]). Appends the
/// TERMINAL EVENT (status `Successful`, the per-slot `outcomes`, and the
/// rollback state built from `actuals`) to the target's ledger — ONE atomic
/// line append, the only commit of the finalize.
///
/// Replay idempotency: if the entry already carries a terminal event, every
/// durable step already happened and this call is a no-op — a crash after
/// the append can never duplicate the terminal ([`LocalStore::append_terminal`]
/// refuses duplicates).
///
/// The rollback is built from the attempt's OUTCOMES (`actuals`: per-slot
/// actual state observed by the engine — live actuals on the main path, the
/// verified desired state during recovery), never from the intent record
/// itself (the persisted intent is the immutable intent; its `slots` map is
/// empty).
///
/// PARTIAL-ROLLOUT SNAPSHOT SEMANTICS: every successful deployment —
/// including a group deployment — produces a COMPLETE snapshot of the
/// target's resulting state. The base is the latest successful snapshot
/// BEFORE this attempt; the SELECTED slots (the attempt's `slot_ids`) are
/// replaced with their actual successful assignments and current physical
/// bindings, unselected slots are carried forward unchanged, and slots
/// removed from the current target configuration (`current_slot_ids`) are
/// omitted.
///
/// THE PERSISTED MEMBERSHIPS: the terminal records BOTH memberships so the
/// record PROVES the membership equations — `selected_membership` = the
/// outcome keys (the slots this attempt actually deployed; ==
/// `attempt.membership()` on the happy path — the outcomes are the ground
/// truth the conversion verifies against) and `full_membership` =
/// `current_slot_ids` (the COMPLETE target membership at terminal time).
/// The writer also VERIFIES `build_rollback`'s result key set EQUALS
/// `current_slot_ids` (fail closed): the read side rejects a mismatch
/// (rollback slots == full_membership), so the writer must produce
/// equality — by construction the overlay covers exactly the current slots
/// (unselected slots carried forward from the base, removed slots omitted,
/// and the partial-rollout guards in [`crate::push::plan::validate_partial_rollout`]
/// refuse any current slot without a base entry), and this check pins it.
pub fn finalize_successful_attempt(
    store: &LocalStore,
    attempt: &DeploymentIntent,
    outcomes: &BTreeMap<SlotId, SlotResult>,
    actuals: &BTreeMap<SlotId, SlotAttemptState>,
    reason: &str,
    bindings: &BTreeMap<SlotId, PhysicalBinding>,
    current_slot_ids: &[SlotId],
) -> Result<()> {
    let entries = store.read_ledger(attempt.target.as_str())?;
    if let Some(e) = entries
        .iter()
        .find(|e| e.deployment_id == attempt.deployment_id)
        && e.terminal.is_some()
    {
        return Ok(());
    }
    // The base for the complete snapshot: the latest successful snapshot
    // BEFORE this attempt (this attempt's terminal is not yet appended).
    let base = crate::push::plan::latest_successful_rollback(store, attempt.target.as_str())?;
    let rollback = build_rollback(actuals, bindings, base.as_ref(), current_slot_ids)?;
    // THE WRITER'S EQUALITY (fail closed): the rollback's key set must
    // EXACTLY equal the full membership (`current_slot_ids`) — the read
    // path rejects a mismatch (rollback slots == full_membership), so the
    // writer must produce equality. By construction the overlay covers
    // exactly the current slots; this check pins the invariant at the
    // WRITER so a drift surfaces as a clear error here rather than as a
    // ledger that can never be read again.
    let rollback_keys: BTreeSet<SlotId> = rollback.slots.keys().cloned().collect();
    let current: BTreeSet<SlotId> = current_slot_ids.iter().cloned().collect();
    if rollback_keys != current {
        return Err(Error::integrity(format!(
            "finalize {}: the rollback snapshot covers slots {rollback_keys:?} but the current target membership is {current:?} — the complete snapshot must cover exactly the current slots (unselected slots are carried forward from the base; slots removed from the configuration are omitted)",
            attempt.deployment_id
        )));
    }
    let terminal = LedgerTerminal {
        recorded_at: crate::remote::helper::now_rfc3339(),
        // The Successful disposition ALWAYS carries the complete rollback
        // payload (the truth table is structural in the domain) AND its OWN
        // outcomes table (the wire-shaped outcomes' redundant `slot_id` is
        // dropped into the key — the domain value carries no slot) AND the
        // TWO PERSISTED MEMBERSHIPS: `selected_membership` = the outcome
        // keys (the slots this attempt actually deployed) and
        // `full_membership` = `current_slot_ids` (the complete target
        // membership at terminal time) — the record PROVES the membership
        // equations (outcomes == selected, rollback == full, selected ⊆
        // full, full-push selected == full).
        disposition: TerminalDisposition::Successful {
            rollback,
            outcomes: SlotTable::from_map(
                outcomes
                    .iter()
                    .map(|(k, r)| (k.clone(), SlotOutcome::from(r.clone())))
                    .collect(),
            ),
            selected_membership: outcomes.keys().cloned().collect(),
            full_membership: current,
        },
        reason: Some(reason.to_string()),
    };
    store.append_terminal(attempt.target.as_str(), &attempt.deployment_id, &terminal)
}
/// Resolve the per-slot OUTCOMES used to finalize a pending deployment when
/// the engine no longer has the live outcomes at hand (recovery): recovery
/// already verified each slot's live generation equals the desired
/// generation, so the outcomes ARE the desired assignments (the old
/// `deployments/<id>/results.json` outcomes store is GONE — the ledger
/// terminal carries outcomes, and a terminal-less entry has none by
/// construction). Returns the per-slot `SlotResult` outcomes AND the
/// per-slot actuals ([`SlotAttemptState`]) for the rollback, built from the
/// attempt's desired assignments.
pub fn recovery_outcomes(
    attempt: &DeploymentIntent,
) -> (
    BTreeMap<SlotId, SlotResult>,
    BTreeMap<SlotId, SlotAttemptState>,
) {
    let mut outcomes = BTreeMap::new();
    let mut actuals = BTreeMap::new();
    // Iterate the ONE authoritative slot table (the membership AND the
    // desired entries are the same table in the domain).
    for (sid, slot) in attempt.slots.iter() {
        outcomes.insert(
            sid.clone(),
            SlotResult {
                slot_id: sid.clone(),
                outcome: crate::ledger::records::SlotOutcomeKind::Activated,
                generation: Some(slot.desired.generation.clone()),
                compensated: false,
                error: None,
                observation_error: None,
            },
        );
        actuals.insert(
            sid.clone(),
            SlotAttemptState {
                artifact: crate::ledger::records::Observation::Known(slot.desired.artifact.clone()),
                generation: Some(slot.desired.generation.clone()),
            },
        );
    }
    (outcomes, actuals)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::records::{
        DeploymentIntent, DeploymentStatus, DesiredGeneration, IntentSlot, NonEmptySlotTable,
        Observation,
    };
    use crate::model::{
        ArtifactRef, ServerId, SlotId, TargetName, VariantName, test_deployment_id,
        test_generation_id, test_tree_digest,
    };
    use std::collections::BTreeMap;

    /// A minimal but VALID intent for the target (EXACT key-set equality:
    /// `slot_ids == desired.keys() == pre_push.keys()`).
    fn intent(dep: &str) -> DeploymentIntent {
        let p1 = SlotId::new("p1".to_string());
        // ONE slot table (the membership + desired/pre-push entries).
        let slots = BTreeMap::from([(
            p1.clone(),
            IntentSlot {
                desired: DesiredGeneration {
                    generation: test_generation_id("gen-1"),
                    artifact: ArtifactRef {
                        release: crate::model::test_release_id("rel-1"),
                        variant: VariantName::new("standard".to_string()),
                        tree: test_tree_digest("tree-1"),
                    },
                },
                pre_push: None,
            },
        )]);
        DeploymentIntent {
            deployment_id: test_deployment_id(dep),
            target: TargetName::new("production".to_string()),
            group: None,
            behavior_sha256: "sha256-aa".to_string(),
            attempted_at: "2026-01-01T00:00:00Z".to_string(),
            slots: NonEmptySlotTable::build(slots)
                .expect("a fixture intent always has at least one slot"),
        }
    }

    /// Finalization appends the terminal event exactly once (replay-safe by
    /// deployment id): a repeated finalize for the same attempt is a no-op.
    #[test]
    fn finalize_is_idempotent_by_deployment_id() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalStore::with_base(tmp.path().join("store")).unwrap();
        let target = TargetName::new("production".to_string());
        let bindings: BTreeMap<SlotId, PhysicalBinding> = BTreeMap::from([(
            SlotId::new("p1"),
            PhysicalBinding {
                server: ServerId::new("server-01"),
                deploy_dir: "/srv/deploy/p1".to_string(),
            },
        )]);
        let attempt = intent("deploy-idempotent");
        store.append_intent(target.as_str(), &attempt).unwrap();
        let actuals = BTreeMap::from([(
            SlotId::new("p1".to_string()),
            SlotAttemptState {
                artifact: Observation::Known(ArtifactRef {
                    release: crate::model::test_release_id("rel-1"),
                    variant: VariantName::new("standard".to_string()),
                    tree: test_tree_digest("tree-1"),
                }),
                generation: Some(test_generation_id("gen-1")),
            },
        )]);
        let outcomes = BTreeMap::from([(
            SlotId::new("p1".to_string()),
            SlotResult {
                slot_id: SlotId::new("p1".to_string()),
                outcome: crate::records::SlotOutcomeKind::Activated,
                generation: Some(test_generation_id("gen-1")),
                compensated: false,
                error: None,
                observation_error: None,
            },
        )]);

        finalize_successful_attempt(
            &store,
            &attempt,
            &outcomes,
            &actuals,
            "push completed",
            &bindings,
            &[SlotId::new("p1".to_string())],
        )
        .unwrap();
        let entries = store.read_ledger(target.as_str()).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].terminal.is_some());
        assert_eq!(
            store
                .latest_status(test_deployment_id("deploy-idempotent").as_str())
                .unwrap(),
            Some(DeploymentStatus::Successful)
        );

        // Repeated finalize with the same deployment ID is a no-op: same
        // key, no duplicate terminal.
        finalize_successful_attempt(
            &store,
            &attempt,
            &outcomes,
            &actuals,
            "push completed",
            &bindings,
            &[SlotId::new("p1".to_string())],
        )
        .unwrap();
        let entries = store.read_ledger(target.as_str()).unwrap();
        assert_eq!(entries.len(), 1, "no duplicate terminal event");
    }
}
