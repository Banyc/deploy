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
    ObservedGeneration, SlotOutcome, SlotTable, TerminalDisposition,
};
use crate::remote::helper::RemoteHelper;
use crate::store::local::LocalStore;
use std::collections::{BTreeMap, HashMap, HashSet};

/// The per-attempt outcome of the recovery step — one pending attempt is
/// reconciled to EXACTLY one of these (under the strictly-linear model at
/// most ONE pending intent can exist at a time, so a call returns at most
/// one outcome). The preflight consumes it to decide whether the push may
/// plan a new intent: only [`Finalized`](RecoveryOutcome::Finalized) or
/// [`Degraded`](RecoveryOutcome::Degraded) release the push to continue;
/// [`StillPending`](RecoveryOutcome::StillPending) (the finalizer could not
/// finish right now — locks contended / live state not finalizable) makes
/// the push REFUSE (it can never plan a second intent on top of an
/// unresolved one, even for disjoint groups).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryOutcome {
    /// The pending attempt was finalized `Successful` by the shared
    /// replay-safe finalizer (its parent was still the successful head).
    Finalized,
    /// The pending attempt could not finalize on the live state (membership
    /// mismatch, binding drift, or a state-diverged / stale finalizer
    /// refusal) and was finalized `Degraded` — never stranded, never
    /// silently ignored, never `Successful`.
    Degraded,
    /// The finalizer could not finish RIGHT NOW (locks contended / live
    /// state not finalizable — a TRANSIENT non-finalization): the attempt
    /// remains intent-only (pending). The push REFUSES to plan a new intent
    /// on top.
    StillPending,
}

/// Reconcile the target's pending (intent-only) attempts — at most ONE
/// exists under the strictly-linear model — reporting the per-attempt
/// outcome (`None` when no pending attempt exists). Recovery is a CALLER of
/// the one kernel state machine, not a second authority: it completes a
/// recorded attempt `Successful` ONLY through the same replay-safe
/// finalizer as the main success path. A recovered attempt that can no
/// longer finalize `Successful` on the live state (membership mismatch,
/// binding drift, or a drifted head — the finalizer's `Refused`) is
/// finalized `Degraded` (a non-empty Degraded terminal with the refusal
/// source as its reason), never `Successful`: it can never become the head
/// or overlay a newer head's inherited state. ONLY a TRANSIENT
/// non-finalization (the finalizer's [`FinalizeOutcome::Pending`]) yields
/// [`RecoveryOutcome::StillPending`] — the caller (preflight) then REFUSES
/// the push: a push that cannot finish the previous pending attempt never
/// plans a second intent on top.
pub(crate) fn reconcile_pending_commits(
    store: &LocalStore,
    config: &ProjectConfig,
    target_name: &str,
    op_id: &OperationId,
    helpers: &HashMap<SlotId, RemoteHelper>,
) -> Result<Option<RecoveryOutcome>> {
    let mut pending: Vec<DeploymentIntent> = Vec::new();
    for entry in store.read_ledger(target_name)? {
        if entry.terminal.is_none() {
            pending.push(entry.intent);
        }
    }
    if pending.is_empty() {
        return Ok(None);
    }

    let members: HashSet<String> = config
        .target_slots(target_name)?
        .iter()
        .map(|(slot, _)| slot.id.clone())
        .collect();
    let live_bindings = config.target_slot_bindings(target_name)?;

    // At most ONE pending attempt exists under the strictly-linear model
    // (the store's read path refuses a second unresolved intent); the loop
    // stays to keep the oldest-first reconciliation order structural.
    let mut outcome: Option<RecoveryOutcome> = None;
    for attempt in pending {
        let membership_ok = attempt
            .selected_membership()
            .iter()
            .all(|sid| members.contains(sid.as_str()));
        if !membership_ok {
            append_degraded(store, target_name, &attempt, "membership mismatch")?;
            outcome = Some(RecoveryOutcome::Degraded);
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
            outcome = Some(RecoveryOutcome::Degraded);
            continue;
        }

        // RECOVERY COMPLETES THE RECORDED ATTEMPT through the SAME
        // replay-safe finalizer as the main success path — with NO lineage
        // carve-out: the finalizer requires `intent.parent == current
        // successful head` (a drifted head is REFUSED and the attempt is
        // finalized `Degraded` below — it can never overlay a newer head's
        // inherited state on the logical history). A TRANSIENT
        // non-finalization (locks contended / live state not finalizable
        // right now) reports [`RecoveryOutcome::StillPending`] — the
        // attempt stays intent-only and the push REFUSES to plan on top.
        match finalize_successful_locked(
            store,
            &attempt,
            helpers,
            &FinalizeSettings {
                reason: "recovery finalized",
                op_id,
            },
        )? {
            FinalizeOutcome::Finalized => {
                outcome = Some(RecoveryOutcome::Finalized);
            }
            FinalizeOutcome::Pending => {
                outcome = Some(RecoveryOutcome::StillPending);
            }
            FinalizeOutcome::Refused { reason, .. } => {
                append_degraded(store, target_name, &attempt, reason.as_str())?;
                outcome = Some(RecoveryOutcome::Degraded);
            }
        }
    }
    Ok(outcome)
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
                SlotOutcome::Failed {
                    observation: Observation::Known(ObservedGeneration {
                        generation: entry.generation().clone(),
                    }),
                    compensated: false,
                    error: None,
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
    use crate::deploy::testsupport::{RefExpr, TwoSlotHarness, known_generation, two_slot_push};
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

    fn resolved_of(store: &LocalStore, dep: &DeploymentId) -> crate::ledger::TargetSnapshot {
        let entries = store.read_ledger("t1").unwrap();
        let entry = entries
            .iter()
            .find(|e| e.deployment_id == *dep)
            .expect("the entry exists");
        crate::kernel::snapshot::resolve_snapshot(entry).expect("a Successful entry resolves")
    }

    /// THE STRICT-LINEAR INTEGRATION PROPERTY (spec items 6 + 9): force
    /// group A to remain PENDING (its finalizer cannot finish RIGHT NOW —
    /// its slot's mutation lock is held by a foreign operation, so
    /// [`finalize_successful_locked`] returns `Pending`), then attempt
    /// group B (a DISJOINT selection, deploys p2): the push is REFUSED with
    /// a Conflict ("a previous deployment is still pending") WITHOUT
    /// appending B's intent — a push that cannot finish the previous
    /// pending attempt NEVER plans a second intent on top, even for
    /// disjoint groups. After A reaches its Successful terminal (the lock
    /// is released; the retry's recovery finalizes A over head H),
    /// RETRYING B succeeds with B's parent == A and B's inherited p1 ==
    /// A's entry — the strictly-linear chain H → A → B.
    #[test]
    fn push_refuses_group_b_while_group_a_is_unfinalized_and_repairs_on_retry() {
        let h = TwoSlotHarness::new();
        // A REAL full HEAD push establishes live state for BOTH slots (so the
        // pending A's later finalization and B's later push both verify
        // against minted remotes).
        let head_id = test_deployment_id("deploy-h");
        let r_head = two_slot_push(&h, &h.config, &RefExpr::Head, None, &head_id).unwrap();
        assert_eq!(r_head.status, Some(DeploymentStatus::Successful));
        let head = h
            .store
            .read_ledger("t1")
            .unwrap()
            .into_iter()
            .find(|e| e.deployment_id == head_id)
            .expect("the head entry exists")
            .intent;
        let bindings = h.config.target_slot_bindings("t1").unwrap();
        // The REAL head push minted p1's live generation at runtime (not a
        // test fixture id) — the prior state A's deployment advances.
        let head_p1 = known_generation(
            &r_head
                .attempt
                .as_ref()
                .expect("the head push records an attempt")
                .slots[&p1()],
        )
        .clone();

        // A (group-a): deploys p1 (generation a-p1), inherits p2 from the
        // head. PENDING (intent-only — a push that crashed after the remote
        // advanced but before the terminal landed). A's live p1 IS the frozen
        // desired (minted over the head's generation), so its finalizer
        // would SUCCEED — if it could acquire the lock.
        let a = group_over_head(
            "deploy-a",
            "group-a",
            &head,
            &bindings,
            p1(),
            "a-p1",
            art("rel-a"),
        );
        h.store.append_attempt("t1", &a).unwrap();
        advance_live_slot(
            &h,
            "s1",
            &head_p1,
            &test_generation_id("a-p1"),
            &art("rel-a"),
            a.deployment_id(),
        );

        // HOLD p1's mutation lock with a FOREIGN operation id: A's
        // finalization must acquire p1's lock, fails (a transient
        // non-finalization), and the attempt stays intent-only.
        let env = crate::testutil::fixture_env();
        let r1: Box<dyn Remote> =
            Box::new(LocalTransport::new(&env, h.remotes_base.join("s1")).unwrap());
        let helper = RemoteHelper::new(r1.as_ref());
        let _guard = helper
            .acquire_lock_guard(&OperationId::new("op-foreign-a".to_string()))
            .unwrap();

        // Attempt group B (DISJOINT: deploys p2, inherits p1 from the head)
        // through the REAL push path: preflight recovery cannot finish A, so
        // the push is REFUSED with the spec's Conflict and NO intent is
        // appended.
        let b_id = test_deployment_id("deploy-b");
        let err = two_slot_push(&h, &h.config, &RefExpr::Head, Some("group-b"), &b_id).expect_err(
            "a push cannot plan a second intent while a previous deployment is still pending",
        );
        assert!(
            err.to_string()
                .contains("a previous deployment is still pending"),
            "the refusal must carry the spec's exact conflict message, got: {err}"
        );
        assert!(
            err.to_string().contains("conflict"),
            "the still-pending refusal is a Conflict, got: {err}"
        );
        // NOTHING appended: no intent for B, A still pending, head still H.
        let entries = h.store.read_ledger("t1").unwrap();
        assert!(
            !entries.iter().any(|e| e.deployment_id == b_id),
            "B's intent must NOT be appended while A is unfinalized"
        );
        assert_eq!(
            h.store.latest_status(a.deployment_id().as_str()).unwrap(),
            None,
            "A is still pending (intent-only)"
        );
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(head_id.as_str()),
            "the head is still H"
        );

        // RELEASE the foreign lock and give the target NEW content (a
        // distinct release R2): the retry's recovery FINALIZES A
        // (`Successful` — its parent H is still the head), then B — planning
        // group-b over the NEW head — deploys the new content under R2 and
        // becomes the newest successful entry.
        drop(_guard);
        let project_root = h.config.project_root(&h.cfg_path);
        let variant_path = project_root
            .join("releases")
            .join("v1")
            .join("standard.toml");
        let v2 = std::fs::read_to_string(&variant_path)
            .unwrap()
            .replace("argv = [\"true\", \"a\"]", "argv = [\"true\", \"b\"]");
        assert_ne!(
            v2,
            std::fs::read_to_string(&variant_path).unwrap(),
            "the fixture must actually change the verification argv"
        );
        std::fs::write(&variant_path, v2).unwrap();
        std::fs::write(
            project_root
                .join("releases")
                .join("v1")
                .join("artifacts")
                .join("build/output/app/server"),
            "v2\n",
        )
        .unwrap();
        let config2 = ProjectConfig::load(&h.cfg_path).unwrap();
        let r2 = two_slot_push(&h, &config2, &RefExpr::Head, Some("group-b"), &b_id).unwrap();
        assert_eq!(r2.status, Some(DeploymentStatus::Successful));
        assert_eq!(
            h.store.latest_status(a.deployment_id().as_str()).unwrap(),
            Some(DeploymentStatus::Successful),
            "A finalized Successful on the retry's recovery"
        );
        // B USES A AS ITS PARENT: H → A → B; B's inherited p1 is A's entry.
        let entries = h.store.read_ledger("t1").unwrap();
        let b_entry = entries
            .iter()
            .find(|e| e.deployment_id == b_id)
            .expect("B is recorded");
        assert_eq!(
            b_entry.intent.parent(),
            Some(a.deployment_id()),
            "B must be planned over A (the head its recovery established)"
        );
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(b_id.as_str()),
            "B is the newest head"
        );
        let b_snapshot = resolved_of(&h.store, &b_id);
        assert_eq!(
            b_snapshot.get(&p1()).map(|e| e.generation()),
            Some(&test_generation_id("a-p1")),
            "B's inherited p1 is A's entry — the overlay is A's snapshot"
        );
        assert_eq!(
            b_snapshot.get(&p2()).map(|e| e.generation()),
            Some(known_generation(
                &r2.attempt.as_ref().expect("attempt").slots[&p2()]
            )),
            "B's deployed p2 is its own plan-minted generation"
        );
        assert_ne!(
            b_snapshot.get(&p2()).map(|e| e.generation().clone()),
            Some(
                a.resulting_snapshot()
                    .get(&p2())
                    .expect("A covers p2")
                    .generation()
                    .clone()
            ),
            "B deployed NEW p2 content over A's inherited entry"
        );
        assert_eq!(b_snapshot, b_entry.intent.resulting_snapshot());
    }

    /// Mint a slot's LIVE state on its remote OVER an existing generation
    /// (the head's): create a real `generations/<gen>/root` chain with the
    /// given prior generation and CAS `current` from the prior generation to
    /// the new one — exactly the state A's deployment leaves behind while
    /// the attempt stays intent-only.
    fn advance_live_slot(
        h: &TwoSlotHarness,
        server: &str,
        prior: &GenerationId,
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
            .acquire_lock_guard(&OperationId::new("op-mint".to_string()))
            .unwrap()
            .create_generation(&GenerationAssignment {
                deployment_id: deployment_id.clone(),
                generation_id: generation.clone(),
                artifact: artifact.clone(),
                behavior_sha256: crate::identity::DIGEST_TEST_HEX_1.to_string(),
                prior_generation: Some(prior.clone()),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                target: Some(TargetName::parse("t1").unwrap()),
            })
            .unwrap();
        helper
            .acquire_lock_guard(&OperationId::new("op-mint".to_string()))
            .unwrap()
            .swap_current(
                &ExpectedCurrent::Generation(prior.clone()),
                generation.as_str(),
                "op-mint",
            )
            .unwrap();
    }
}
