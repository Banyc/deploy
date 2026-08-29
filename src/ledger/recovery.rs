//! Pending-attempt reconciliation (feature area A2: Ledger semantics — the
//! RECOVERY / RECONCILIATION of intent-only ledger entries).
//!
//! Recovery is a CALLER of the one kernel transition, not a second
//! authority: it completes a recorded attempt `Successful` ONLY through the
//! same replay-safe finalizer as the main success path, which appends
//! through the PURE STATE MACHINE's one-parent gate (no recovery bypass). A
//! recovered attempt whose parent is no longer the successful head — a
//! later deployment already succeeded on that parent — is finalized
//! `Degraded` (a non-empty Degraded terminal with the stale-plan source as
//! its reason), never `Successful`: it can never become the head or overlay
//! a newer head's inherited state.

use crate::config::ProjectConfig;
use crate::error::{Error, Result};
use crate::identity::{OperationId, SlotId};
use crate::kernel;
use crate::ledger::finalize::{FinalizeOutcome, FinalizeSettings, finalize_successful_locked};
use crate::ledger::records::{
    DegradedTerminal, DeploymentIntent, LedgerTerminal, NonEmptySlotTable, Observation,
    ObservedGeneration, SlotOutcome, SlotOutcomeKind, SlotTable, SlotTransition,
    TerminalDisposition,
};
use crate::remote::helper::RemoteHelper;
use crate::store::local::LocalStore;
use std::collections::{BTreeMap, HashMap, HashSet};

pub(crate) fn reconcile_pending_commits(
    store: &LocalStore,
    config: &ProjectConfig,
    target_name: &str,
    op_id: &OperationId,
    helpers: &HashMap<SlotId, RemoteHelper>,
) -> Result<()> {
    let mut pending: Vec<DeploymentIntent> = Vec::new();
    for entry in store.read_ledger(target_name)? {
        if entry.terminal.is_none() {
            pending.push(entry.intent);
        }
    }
    if pending.is_empty() {
        return Ok(());
    }

    let members: HashSet<String> = config
        .target_slots(target_name)?
        .iter()
        .map(|(slot, _)| slot.id.clone())
        .collect();
    let live_bindings = config.target_slot_bindings(target_name)?;

    for attempt in pending {
        let membership_ok = attempt
            .selected_membership()
            .iter()
            .all(|sid| members.contains(sid.as_str()));
        if !membership_ok {
            append_degraded(store, target_name, &attempt, "membership mismatch")?;
            continue;
        }

        let mut bindings_equal = true;
        let snapshot = attempt.resulting_snapshot();
        for sid in attempt.selected_membership() {
            let frozen_binding = snapshot.get(&sid).expect("selected in snapshot").binding();
            let equal = live_bindings.get(&sid) == Some(frozen_binding);
            bindings_equal &= equal;
        }
        if !bindings_equal {
            append_degraded(store, target_name, &attempt, "binding drift")?;
            continue;
        }

        // RECOVERY COMPLETES THE RECORDED ATTEMPT through the SAME
        // replay-safe finalizer as the main success path — with NO one-parent
        // carve-out: the state machine gates the Intent-only → Successful
        // transition on `intent.parent == current successful head` REGARDLESS
        // of caller (recovery is a caller of the same transition, not a
        // second authority). If a later deployment already succeeded on this
        // attempt's parent (the head drifted), the finalizer is refused with
        // the kernel's Conflict (StalePlan) and the attempt is finalized
        // `Degraded` below — it can never overlay a newer head's inherited
        // state on the logical history.
        match finalize_successful_locked(
            store,
            &attempt,
            helpers,
            &FinalizeSettings {
                reason: "recovery finalized",
                op_id,
            },
        )? {
            FinalizeOutcome::Finalized => {}
            FinalizeOutcome::Pending => {
                continue;
            }
            FinalizeOutcome::Refused { reason, .. } => {
                append_degraded(store, target_name, &attempt, reason.as_str())?;
            }
        }
    }
    Ok(())
}

fn append_degraded(
    store: &LocalStore,
    target_name: &str,
    attempt: &DeploymentIntent,
    reason: &str,
) -> Result<()> {
    let snapshot = attempt.resulting_snapshot();
    let outcomes: BTreeMap<SlotId, SlotOutcome> = attempt
        .selected()
        .map(|(sid, _)| {
            let entry = snapshot.get(&sid).expect("selected in snapshot");
            (
                sid.clone(),
                SlotOutcome {
                    outcome: SlotOutcomeKind::Failed,
                    observation: Observation::Known(ObservedGeneration {
                        generation: entry.generation().clone(),
                    }),
                    compensated: false,
                    error: None,
                    transition: SlotTransition::AdvanceUnknown,
                },
            )
        })
        .collect();
    let outcomes: SlotTable<SlotOutcome> = SlotTable::from_map(outcomes);
    let non_empty = NonEmptySlotTable::build(outcomes.iter().map(|(k, v)| (k.clone(), v.clone())))
        .map_err(|e| Error::integrity(format!("recovery degraded outcomes: {e}")))?;
    let dt = DegradedTerminal::try_new(non_empty)
        .map_err(|e| Error::integrity(format!("recovery degraded terminal: {e}")))?;
    let terminal = LedgerTerminal::new(
        crate::remote::helper::now_rfc3339_ts(),
        kernel::terminal::intent_digest(attempt),
        TerminalDisposition::Degraded(dt),
        Some(reason.to_string()),
    );
    store.append_terminal(target_name, attempt.deployment_id(), &terminal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::testsupport::TwoSlotHarness;
    use crate::identity::{
        ArtifactRef, BehaviorDigest, DeploymentId, GenerationId, RolloutGroupName, TargetName,
        Timestamp, VariantName, test_deployment_id, test_generation_id, test_release_id,
        test_tree_digest,
    };
    use crate::kernel::intent::{PlanInput, PlannedDeploy};
    use crate::kernel::snapshot::SnapshotSlot;
    use crate::ledger::{DeploymentStatus, PhysicalBinding};
    use crate::remote::helper::{ExpectedCurrent, GenerationAssignment, RemoteHelper};
    use crate::remote::transport::{LocalTransport, Remote};
    use crate::store::local::LocalStore;

    fn p1() -> SlotId {
        SlotId::parse("p1").unwrap()
    }
    fn p2() -> SlotId {
        SlotId::parse("p2").unwrap()
    }

    fn art(tag: &str) -> ArtifactRef {
        ArtifactRef {
            release: test_release_id(tag),
            variant: VariantName::parse("standard").unwrap(),
            tree: test_tree_digest(tag),
        }
    }

    /// Seed the head H: a FULL-push intent over p1 (generation h-p1) and p2
    /// (generation h-p2), appended with its PAYLOAD-FREE Successful terminal
    /// (parent None — the first successful deployment of the target).
    fn seed_head(h: &TwoSlotHarness) -> crate::kernel::intent::DeploymentIntent {
        let bindings = h.config.target_slot_bindings("t1").unwrap();
        let head = crate::kernel::intent::plan(PlanInput {
            deployment_id: test_deployment_id("deploy-h"),
            target: TargetName::parse("t1").unwrap(),
            parent: None,
            parent_snapshot: None,
            group: None,
            selection: vec![p1(), p2()],
            planned: vec![
                PlannedDeploy {
                    slot: p1(),
                    result: SnapshotSlot::new(
                        test_generation_id("h-p1"),
                        art("rel-h"),
                        bindings.get(&p1()).cloned().expect("p1 binds"),
                    ),
                    pre_push: Observation::KnownAbsent,
                },
                PlannedDeploy {
                    slot: p2(),
                    result: SnapshotSlot::new(
                        test_generation_id("h-p2"),
                        art("rel-h"),
                        bindings.get(&p2()).cloned().expect("p2 binds"),
                    ),
                    pre_push: Observation::KnownAbsent,
                },
            ],
            behavior_digest: BehaviorDigest::parse(crate::identity::DIGEST_TEST_HEX_1).unwrap(),
            attempted_at: Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        })
        .expect("the head intent plans");
        h.store
            .append_attempt("t1", &head)
            .expect("the head intent appends");
        h.store
            .append_terminal(
                "t1",
                head.deployment_id(),
                &crate::testutil::fixtures::successful_terminal(&head),
            )
            .expect("the head succeeds (parent None == head None)");
        head
    }

    /// A GROUP intent over the head `base`: the given slot is deployed at
    /// its own generation, the other target slot is INHERITED from the
    /// head's snapshot (the overlay pattern of a partial push).
    fn group_over_head(
        dep: &str,
        group: &str,
        base: &crate::kernel::intent::DeploymentIntent,
        bindings: &std::collections::BTreeMap<SlotId, PhysicalBinding>,
        deploy_slot: SlotId,
        new_gen: &str,
        artifact: ArtifactRef,
    ) -> crate::kernel::intent::DeploymentIntent {
        crate::kernel::intent::plan(PlanInput {
            deployment_id: test_deployment_id(dep),
            target: TargetName::parse("t1").unwrap(),
            parent: Some(base.deployment_id().clone()),
            parent_snapshot: Some(base.resulting_snapshot()),
            group: Some(RolloutGroupName::parse(group).unwrap()),
            selection: vec![p1(), p2()],
            planned: vec![PlannedDeploy {
                slot: deploy_slot.clone(),
                result: SnapshotSlot::new(
                    test_generation_id(new_gen),
                    artifact,
                    bindings
                        .get(&deploy_slot)
                        .cloned()
                        .expect("a selected slot binds"),
                ),
                pre_push: Observation::KnownAbsent,
            }],
            behavior_digest: BehaviorDigest::parse(crate::identity::DIGEST_TEST_HEX_1).unwrap(),
            attempted_at: Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        })
        .expect("a valid group intent plans")
    }

    /// Mint a slot's LIVE state on its remote: a real
    /// `generations/<gen>/root` chain (`create_generation` + the tree
    /// object) with `current` pointing at the given generation — exactly the
    /// state a deployment leaves behind while the attempt stays intent-only
    /// (a PENDING attempt whose remote state is the frozen desired).
    fn mint_live_slot(
        h: &TwoSlotHarness,
        server: &str,
        generation: &GenerationId,
        artifact: &ArtifactRef,
        deployment_id: &DeploymentId,
    ) {
        let base = h.remotes_base.join(server);
        let remote = LocalTransport::new(&crate::testutil::fixture_env(), base).unwrap();
        remote
            .create_dir_all(&crate::remote::layout::tree_root(artifact.tree.as_str()))
            .unwrap();
        let helper = RemoteHelper::new(&remote);
        helper
            .acquire_lock_guard(&crate::identity::OperationId::new("op-mint".to_string()))
            .unwrap()
            .create_generation(&GenerationAssignment {
                deployment_id: deployment_id.clone(),
                generation_id: generation.clone(),
                artifact: artifact.clone(),
                behavior_sha256: crate::identity::DIGEST_TEST_HEX_1.to_string(),
                prior_generation: None,
                created_at: "2026-01-01T00:00:00Z".to_string(),
                target: Some(TargetName::parse("t1").unwrap()),
            })
            .unwrap();
        helper
            .acquire_lock_guard(&crate::identity::OperationId::new("op-mint".to_string()))
            .unwrap()
            .swap_current(&ExpectedCurrent::Absent, generation.as_str(), "op-mint")
            .unwrap();
    }

    /// The live per-slot helpers; the boxed remotes stay alive for the
    /// helpers' lifetime (the `RemoteHelper` borrows them).
    fn live_helpers<'a>(
        _h: &TwoSlotHarness,
        r1: &'a dyn Remote,
        r2: &'a dyn Remote,
    ) -> HashMap<SlotId, RemoteHelper<'a>> {
        let mut helpers = HashMap::new();
        helpers.insert(p1(), RemoteHelper::new(r1));
        helpers.insert(p2(), RemoteHelper::new(r2));
        helpers
    }

    fn resolved_of(store: &LocalStore, dep: &DeploymentId) -> crate::ledger::TargetSnapshot {
        let entries = store.read_ledger("t1").unwrap();
        let entry = entries
            .iter()
            .find(|e| e.deployment_id == *dep)
            .expect("the entry exists");
        crate::kernel::snapshot::resolve_snapshot(entry).expect("a Successful entry resolves")
    }

    fn degraded_reason(store: &LocalStore, dep: &DeploymentId) -> String {
        let entries = store.read_ledger("t1").unwrap();
        let entry = entries
            .iter()
            .find(|e| e.deployment_id == *dep)
            .expect("the entry exists");
        entry
            .terminal
            .as_ref()
            .expect("a terminal was appended")
            .reason()
            .expect("a reason")
            .to_string()
    }

    /// ORDERING (a): a PENDING attempt A (parent H) whose SIBLING B (parent
    /// H) already SUCCEEDED first must NEVER recover `Successful`. The
    /// recovery of A is refused by the state machine's one-parent gate (the
    /// head is B, not H) and A is finalized `Degraded` — so B REMAINS the
    /// head and B's inherited entries survive `resolve_snapshot` (a
    /// recovered A can never overlay B's advances from logical history).
    #[test]
    fn recovery_after_a_sibling_succeeded_first_finalizes_degraded_and_keeps_the_sibling_head() {
        let h = TwoSlotHarness::new();
        let head = seed_head(&h);
        let bindings = h.config.target_slot_bindings("t1").unwrap();

        // A (parent H): deploys p1 (generation a-p1), inherits p2 from H.
        let a = group_over_head(
            "deploy-a",
            "group-a",
            &head,
            &bindings,
            p1(),
            "a-p1",
            art("rel-a"),
        );
        // B (parent H): deploys p2 (generation b-p2), inherits p1 from H.
        let b = group_over_head(
            "deploy-b",
            "group-b",
            &head,
            &bindings,
            p2(),
            "b-p2",
            art("rel-b"),
        );
        h.store.append_attempt("t1", &a).unwrap();
        h.store.append_attempt("t1", &b).unwrap();

        // Live state after both mutations ran: p1 at A's generation, p2 at
        // B's generation.
        mint_live_slot(
            &h,
            "s1",
            &test_generation_id("a-p1"),
            &art("rel-a"),
            a.deployment_id(),
        );
        mint_live_slot(
            &h,
            "s2",
            &test_generation_id("b-p2"),
            &art("rel-b"),
            b.deployment_id(),
        );

        // B'S PUSH COMPLETES FIRST: its Successful terminal is appended
        // while the head is still H (B's parent) — allowed.
        h.store
            .append_terminal(
                "t1",
                b.deployment_id(),
                &crate::testutil::fixtures::successful_terminal(&b),
            )
            .unwrap();
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(b.deployment_id().as_str()),
            "B is the head after its Successful append"
        );

        // RECOVERY OF A runs later: the finalizer verifies A's selected slot
        // (p1 at a-p1), then the state machine REFUSES A's Successful
        // terminal (the head is B, not H) — recovery finalizes A `Degraded`.
        // The live per-slot helpers (the minted generations above); the
        // boxed remotes outlive the helpers that borrow them.
        let env = crate::testutil::fixture_env();
        let r1: Box<dyn Remote> =
            Box::new(LocalTransport::new(&env, h.remotes_base.join("s1")).unwrap());
        let r2: Box<dyn Remote> =
            Box::new(LocalTransport::new(&env, h.remotes_base.join("s2")).unwrap());
        let op_id = crate::identity::OperationId::new("op-order-a".to_string());
        reconcile_pending_commits(
            &h.store,
            &h.config,
            "t1",
            &op_id,
            &live_helpers(&h, r1.as_ref(), r2.as_ref()),
        )
        .unwrap();

        assert_eq!(
            h.store.latest_status(a.deployment_id().as_str()).unwrap(),
            Some(DeploymentStatus::Degraded),
            "A must finalize Degraded — a stale-parent recovery can NEVER produce Successful"
        );
        assert!(
            degraded_reason(&h.store, a.deployment_id()).contains("stale plan"),
            "the Degraded terminal's reason carries the stale-plan source (Conflict/StalePlan), got: {}",
            degraded_reason(&h.store, a.deployment_id())
        );
        assert!(
            h.store
                .read_snapshots("t1")
                .unwrap()
                .iter()
                .all(|e| e.deployment_id != *a.deployment_id()),
            "A is NEVER a successful snapshot — it can never become the head"
        );
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(b.deployment_id().as_str()),
            "B remains the head after A's degraded recovery"
        );
        // B'S INHERITED ENTRY SURVIVES: B inherited p1 from H (h-p1) — a
        // successful A would have overlaid a-p1 on B's logical history; the
        // resolved snapshot of the head (B) still carries H's p1 entry.
        let b_snapshot = resolved_of(&h.store, b.deployment_id());
        assert_eq!(
            b_snapshot.get(&p1()).map(|e| e.generation()),
            Some(&test_generation_id("h-p1")),
            "B's inherited p1 is preserved — the degraded A never overlaid it"
        );
        assert_eq!(b_snapshot, b.resulting_snapshot());
    }

    /// ORDERING (b): A pending with parent H and a second pending B (parent
    /// H) — A RECOVERS FIRST (`Successful`, head = A); then B (parent H)
    /// finalizes and is REFUSED (the head is A, not H) and finalized
    /// `Degraded`. A remains the head; B's inherited entry never lands on
    /// A's logical history.
    #[test]
    fn stale_sibling_finalizes_degraded_when_the_older_pending_recovered_first() {
        let h = TwoSlotHarness::new();
        let head = seed_head(&h);
        let bindings = h.config.target_slot_bindings("t1").unwrap();

        // A (parent H): deploys p1 (generation a-p1), inherits p2 from H.
        let a = group_over_head(
            "deploy-a",
            "group-a",
            &head,
            &bindings,
            p1(),
            "a-p1",
            art("rel-a"),
        );
        // B (parent H): deploys p2 (generation b-p2), inherits p1 from H.
        let b = group_over_head(
            "deploy-b",
            "group-b",
            &head,
            &bindings,
            p2(),
            "b-p2",
            art("rel-b"),
        );
        h.store.append_attempt("t1", &a).unwrap();
        h.store.append_attempt("t1", &b).unwrap();

        // Live state after both mutations ran: p1 at A's generation, p2 at
        // B's generation.
        mint_live_slot(
            &h,
            "s1",
            &test_generation_id("a-p1"),
            &art("rel-a"),
            a.deployment_id(),
        );
        mint_live_slot(
            &h,
            "s2",
            &test_generation_id("b-p2"),
            &art("rel-b"),
            b.deployment_id(),
        );

        // RECONCILIATION (oldest first): A recovers first — `Successful`
        // (its parent H is still the head) — then B's recovery is REFUSED
        // (the head is now A) and B is finalized `Degraded`.
        // The live per-slot helpers (the minted generations above); the
        // boxed remotes outlive the helpers that borrow them.
        let env = crate::testutil::fixture_env();
        let r1: Box<dyn Remote> =
            Box::new(LocalTransport::new(&env, h.remotes_base.join("s1")).unwrap());
        let r2: Box<dyn Remote> =
            Box::new(LocalTransport::new(&env, h.remotes_base.join("s2")).unwrap());
        let op_id = crate::identity::OperationId::new("op-order-b".to_string());
        reconcile_pending_commits(
            &h.store,
            &h.config,
            "t1",
            &op_id,
            &live_helpers(&h, r1.as_ref(), r2.as_ref()),
        )
        .unwrap();

        assert_eq!(
            h.store.latest_status(a.deployment_id().as_str()).unwrap(),
            Some(DeploymentStatus::Successful),
            "A (older, parent still the head at its append) recovers Successful"
        );
        assert_eq!(
            h.store.latest_status(b.deployment_id().as_str()).unwrap(),
            Some(DeploymentStatus::Degraded),
            "B must finalize Degraded — at most ONE Successful per parent"
        );
        assert!(
            degraded_reason(&h.store, b.deployment_id()).contains("stale plan"),
            "B's Degraded terminal's reason carries the stale-plan source (Conflict/StalePlan), got: {}",
            degraded_reason(&h.store, b.deployment_id())
        );
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(a.deployment_id().as_str()),
            "A remains the head after B's refused finalization"
        );
        // A'S INHERITED ENTRY SURVIVES: A inherited p2 from H (h-p2) — a
        // successful B would have overlaid b-p2 on A's logical history; the
        // resolved snapshot of the head (A) still carries H's p2 entry.
        let a_snapshot = resolved_of(&h.store, a.deployment_id());
        assert_eq!(
            a_snapshot.get(&p2()).map(|e| e.generation()),
            Some(&test_generation_id("h-p2")),
            "A's inherited p2 is preserved — the refused B never overlaid it"
        );
        assert_eq!(a_snapshot, a.resulting_snapshot());
        assert!(
            h.store
                .read_snapshots("t1")
                .unwrap()
                .iter()
                .all(|e| e.deployment_id != *b.deployment_id()),
            "B is NEVER a successful snapshot"
        );
    }
}
