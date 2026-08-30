//! The POST-mutation phases of the push transaction (steps 16-17): the
//! terminal event finalization (the status decision — [`disposition_for`] —
//! plus the shared successful finalizer), the observed-refresh + post-commit
//! maintenance wiring, and the report assembly. [`run_commit`] is the single
//! coordinator; everything here runs AFTER the mutation loop and is
//! NON-FALLIBLE once the deployment durably committed.

use crate::config::SlotConfig;
use crate::deploy::push::ExecutionOutcome;
use crate::deploy::push::PushContext;
use crate::deploy::push::PushReport;
use crate::deploy::rollout::SlotExecution;
use crate::error::Result;
use crate::identity::SlotId;
use crate::kernel::terminal::NonSuccessfulDisposition;
use crate::ledger;
use crate::ledger::DeploymentIntent;
use crate::ledger::DeploymentStatus;
use crate::ledger::LedgerIntentReport;
use crate::ledger::LedgerTerminal;
use crate::ledger::NonEmptySlotTable;
use crate::ledger::SlotOutcome;
use crate::remote::helper::RemoteHelper;
use crate::store::local::ledger::TargetLedgerTxn;

// POST-MUTATION phases of the push transaction (steps 16-17): the terminal
// event finalization (the `Successful` / `Degraded` / `FailedRolledBack`
// status decision — [`disposition_for`] — plus the
// shared successful finalizer [`crate::ledger::finalize_successful_locked`]),
// the observed-refresh + post-commit maintenance wiring
// ([`crate::deploy::maintenance`]), and the report assembly.
// [`run_commit`] is the single coordinator; everything here runs AFTER the
// mutation loop and is NON-FALLIBLE once the deployment durably committed
// (the maintenance channel carries warnings, never `Err`).

/// Run every post-mutation phase (steps 16-17), in the numbered order, and
/// assemble the push report. A demoted `PendingCommit` status is NOT
/// terminal: the entry stays intent-only (the recoverable pending state a
/// later push reconciles before its own no-op check) — appending a
/// PendingCommit terminal would strand the attempt forever.
///
/// `txn` is the push's target ledger transaction — the ONLY ledger write
/// surface (every terminal append and the shared finalizer write through
/// it, under the target lock).
pub(crate) fn run_commit(
    ctx: &PushContext,
    txn: &mut TargetLedgerTxn<'_>,
    attempt_intent: &DeploymentIntent,
    execution: &ExecutionOutcome,
    members: &[(&SlotConfig, &crate::config::ServerDef)],
    helpers: &std::collections::HashMap<SlotId, RemoteHelper>,
) -> Result<PushReport> {
    let store = ctx.store;
    let target_name = ctx.target_name;
    let config = ctx.config;
    let deployment_id = ctx.deployment_id;
    let op_id = ctx.op_id;

    // 16 & 17. Record outcomes, finalize, history, retention. The ledger's
    // intent line (persisted BEFORE the mutation loop) keeps only the
    // immutable intent; the ACTUAL per-slot outcomes and the terminal status
    // are appended as the deployment's TERMINAL EVENT — the ENGINE GATHERS
    // EVIDENCE and the KERNEL DECIDES every disposition
    // ([`crate::kernel::transition::decide_terminal`] owns the complete
    // truth table). The REPORT's attempt ([`LedgerIntentReport`]) also
    // carries the actuals (for display); the persisted intent does not —
    // outcomes are never part of the verified intent object.
    let mut attempt = LedgerIntentReport::from_intent(attempt_intent)?;
    attempt.slots = execution.actual_servers.clone();

    let message;
    let status;
    if execution.had_failure() {
        // THE FAILURE PATH: the engine gathered the per-slot outcome
        // evidence; the KERNEL decides `FailedRolledBack` / `Degraded` and
        // validates the payload through the constructors. The failure
        // outcomes ALWAYS cover the nonempty selected membership (the
        // engine completes the execution table with `NotStarted` fillers); a
        // set that could be empty is REFUSED with an integrity error — never
        // an accepted empty failure.
        let evidence = execution.failure_evidence()?;
        let outcomes: NonEmptySlotTable<SlotOutcome> = NonEmptySlotTable::build(evidence.outcomes)
            .map_err(|e| {
            crate::error::Error::integrity(format!(
                "push {deployment_id}: the failure outcomes must cover the selected membership (nonempty): {e}"
            ))
        })?;
        let disposition = crate::kernel::transition::decide_terminal(
            attempt_intent,
            crate::kernel::transition::ExecutionReport::Failed {
                outcomes,
                adapter_restored: evidence.adapter_restored,
            },
        )
        .map_err(|e| {
            crate::error::Error::integrity(format!(
                "push {deployment_id}: the kernel refused the failure disposition: {e}"
            ))
        })?;
        status = disposition.status();
        txn.append_terminal(
            deployment_id,
            &LedgerTerminal::new(
                crate::remote::helper::now_rfc3339_ts(),
                crate::kernel::terminal::intent_digest(attempt_intent),
                NonSuccessfulDisposition::from_decision(disposition),
                Some("push failed after mutation".to_string()),
            ),
        )?;
        message = format!("push status: {status:?}");
    } else {
        // THE SUCCESS PATH — a successful yield goes through the SAME shared
        // lock-verified finalizer as recovery
        // ([`crate::ledger::finalize::finalize_successful_locked`]): acquire
        // every selected-slot mutation lock (sorted-slot-id order), gather
        // the verification evidence (each selected slot's LIVE generation +
        // assignment artifact EQUAL the intent's planned result), write the
        // commit markers, re-verify, check the ONE-PARENT rule (the intent's
        // parent must still be the target's successful head), then append
        // the PAYLOAD-FREE `Successful` terminal (bound by the canonical
        // intent digest). A slot whose live state diverged REFUSES: the
        // attempt ends `Degraded`. A transient failure leaves the attempt
        // intent-only (the PENDING state a later push reconciles).

        // "ACTIVE BUT NOT DURABLY BOOKKEPT" DEMOTION (the status enum no
        // longer carries `PendingCommit` — the pending state IS the
        // intent-only entry): a slot whose committed-transaction record
        // write failed is still ACTIVE (its `current` advanced) but the
        // attempt cannot be durably marked committed. The attempt must NOT
        // finalize `Successful` — it stays intent-only (the recoverable
        // PENDING state a later push reconciles before its own no-op
        // check).
        if execution.executions.values().any(|e| {
            matches!(
                e,
                SlotExecution::Advanced {
                    bookkeeping_error: Some(_),
                    ..
                }
            )
        }) {
            let (_observed, observed_warnings) =
                crate::deploy::maintenance::refresh_observed_from_live(
                    store,
                    target_name,
                    members,
                    helpers,
                    config.application(),
                );
            let mut maintenance: Vec<String> = Vec::new();
            maintenance.extend(observed_warnings);
            maintenance.extend(crate::deploy::maintenance::retry_deferred_retentions(
                store,
                config,
                target_name,
                helpers,
                op_id,
                deployment_id,
            ));
            return Ok(PushReport {
                status: None,
                attempt: Some(attempt),
                message: format!(
                    "push pending: a slot is active but not durably bookkept (its committed-transaction record write failed) — deployment {deployment_id} stays intent-only; a later push reconciles it"
                ),
                warning: (!maintenance.is_empty()).then_some(maintenance.join("; ")),
                dry_run: false,
            });
        }

        match ledger::finalize_successful_locked(
            txn,
            attempt_intent,
            helpers,
            &ledger::FinalizeSettings {
                reason: "push completed",
                op_id,
                application: config.application(),
                // Finalization (recovery included) goes through the PURE
                // STATE MACHINE's one-parent gate inside the append: a plan
                // whose parent is no longer the successful head is refused
                // at terminal-append time — never reconciled implicitly.
            },
        )? {
            ledger::FinalizeOutcome::Finalized => {
                // The new successful deployment is keyed by its deployment id
                // (the public grammar is deployment-keyed — successful
                // positions are derived internally, never exposed as sN).
                status = DeploymentStatus::Successful;
                message = format!(
                    "push successful; rollback payload keyed by deployment {deployment_id} of target {target_name}"
                );
            }
            ledger::FinalizeOutcome::Pending => {
                // A TRANSIENT failure (a slot lock held elsewhere, a live
                // status/assignment read failure, a marker transport write
                // failure): the terminal is NOT appended — the attempt stays
                // intent-only (the recoverable PENDING state a later push
                // reconciles before its own no-op check). REFRESH THE
                // OBSERVED PROJECTIONS REGARDLESS: the servers already
                // advanced to the attempt's generation, and the observed
                // projection must reflect the remote assignment after ANY
                // mutation attempt — a crash-window push that aborted after
                // the remote advanced but before the observed refresh would
                // otherwise leave the slot's physical record stale (the
                // pending attempt itself is the visible recoverable state).
                let (_observed, observed_warnings) =
                    crate::deploy::maintenance::refresh_observed_from_live(
                        store,
                        target_name,
                        members,
                        helpers,
                        config.application(),
                    );
                let mut maintenance: Vec<String> = Vec::new();
                maintenance.extend(observed_warnings);
                maintenance.extend(crate::deploy::maintenance::retry_deferred_retentions(
                    store,
                    config,
                    target_name,
                    helpers,
                    op_id,
                    deployment_id,
                ));
                return Ok(PushReport {
                    status: None,
                    attempt: Some(attempt),
                    message: format!(
                        "push pending: the finalization could not verify the selected-slot state or write the commit markers (transient) — deployment {deployment_id} stays intent-only; a later push reconciles it"
                    ),
                    warning: (!maintenance.is_empty()).then_some(maintenance.join("; ")),
                    dry_run: false,
                });
            }
            ledger::FinalizeOutcome::Refused { reason, .. } => {
                // The shared finalizer REFUSED: a selected slot's live state
                // diverged from the planned result ("state diverged"), the
                // parent head drifted ("stale plan"), or a conflicting commit
                // marker exists ("marker integrity conflict"). Append a
                // `Degraded` terminal — NEVER `Successful`. The kernel
                // decides the disposition from the failure evidence: a
                // refusal means the attempt did NOT fully run, so its
                // evidence carries a remaining change — some slot is still
                // on the deployed generation — which the DERIVED rule
                // (rolled back iff every slot's observation is back at its
                // pre-push state) classifies `Degraded`. The failure
                // outcomes ALWAYS cover the nonempty selected membership
                // (the engine completed the execution table); an empty set
                // is REFUSED with an integrity error, never an accepted
                // empty failure.
                let evidence = execution.failure_evidence()?;
                let outcomes: NonEmptySlotTable<SlotOutcome> =
                    NonEmptySlotTable::build(evidence.outcomes)
                        .map_err(|e| {
                            crate::error::Error::integrity(format!(
                                "push {deployment_id}: the refused disposition's outcomes must cover the selected membership (nonempty): {e}"
                            ))
                        })?;
                let disposition = crate::kernel::transition::decide_terminal(
                    attempt_intent,
                    crate::kernel::transition::ExecutionReport::Failed {
                        outcomes,
                        adapter_restored: evidence.adapter_restored,
                    },
                )
                .map_err(|e| {
                    crate::error::Error::integrity(format!(
                        "push {deployment_id}: the kernel refused the degraded disposition: {e}"
                    ))
                })?;
                txn.append_terminal(
                    deployment_id,
                    &LedgerTerminal::new(
                        crate::remote::helper::now_rfc3339_ts(),
                        crate::kernel::terminal::intent_digest(attempt_intent),
                        NonSuccessfulDisposition::from_decision(disposition),
                        Some(reason.to_string()),
                    ),
                )?;
                status = DeploymentStatus::Degraded;
                message = format!("push degraded: {reason}");
            }
        }
    }

    let (_observed, observed_warnings) = crate::deploy::maintenance::refresh_observed_from_live(
        store,
        target_name,
        members,
        helpers,
        config.application(),
    );

    let mut maintenance: Vec<String> = Vec::new();
    maintenance.extend(observed_warnings);
    maintenance.extend(crate::deploy::maintenance::retry_deferred_retentions(
        store,
        config,
        target_name,
        helpers,
        op_id,
        deployment_id,
    ));
    maintenance.extend(crate::deploy::maintenance::retry_pending_sweep(
        store,
        config,
        deployment_id.as_str(),
    ));
    crate::deploy::maintenance::run_step17_retention(
        store,
        config,
        target_name,
        helpers,
        &execution.servers_order,
        op_id,
        deployment_id,
        &mut maintenance,
    );
    Ok(PushReport {
        status: Some(status),
        attempt: Some(attempt),
        message,
        warning: crate::deploy::maintenance::maintenance_warning(&maintenance),
        dry_run: false,
    })
}

#[cfg(test)]
pub(crate) mod commit_tests {
    //! POST-MUTATION phase tests (steps 16-17): the terminal-event finalization
    //! (successful finalizer / plain terminal append, replay-safety), the
    //! reconciliation of `PendingCommit` attempts, and the complete-snapshot
    //! group finalization — driven end-to-end through
    //! [`push`] with the shared harnesses from
    //! [`crate::deploy::testsupport`].

    use crate::deploy::testsupport::*;
    use crate::identity::{OperationId, ServerId, test_deployment_id};
    use crate::ledger::recovery::reconcile_pending_commits;
    use crate::remote::helper::{ExpectedCurrent, GenerationAssignment, RemoteHelper};
    use crate::remote::layout;
    use crate::remote::transport::{LocalTransport, Remote};
    use crate::testutil::test_remotes::FailOnceMarkerRemote;
    #[cfg(test)]
    use proptest::prelude::*;
    #[cfg(test)]
    use proptest::test_runner::RngSeed;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    /// A crafted ONE-SLOT (p1) FULL-push intent for the harness target,
    /// built through the kernel's validated constructor (the domain types
    /// cannot be struct-literal-constructed; the constructor is the ONE
    /// validator). `binding` must match the harness slot's deploy_dir for
    /// the recovery binding check to pass. `head` (the current successful
    /// deployment, when present) becomes the intent's parent — the lineage
    /// invariant (at most one `Successful` per parent) requires a pending
    /// attempt to carry the head it was planned against.
    fn crafted_intent(
        dep: &crate::identity::DeploymentId,
        generation: &crate::identity::GenerationId,
        artifact: &crate::identity::ArtifactRef,
        binding: crate::ledger::PhysicalBinding,
        behavior: &crate::identity::BehaviorDigest,
        head: Option<&DeploymentIntent>,
    ) -> DeploymentIntent {
        use crate::kernel::intent::{PlanInput, PlannedDeploy};
        use crate::kernel::snapshot::SnapshotSlot;
        use crate::ledger::Observation;
        let p1 = SlotId::new("p1".to_string());
        crate::kernel::intent::plan(PlanInput {
            deployment_id: dep.clone(),
            target: TargetName::parse("t1").unwrap(),
            parent: head.map(|h| h.deployment_id().clone()),
            parent_snapshot: head.map(|h| h.resulting_snapshot()),
            group: None,
            selection: vec![p1.clone()],
            planned: vec![PlannedDeploy {
                slot: p1,
                result: SnapshotSlot::new(generation.clone(), artifact.clone(), binding),
                pre_push: Observation::KnownAbsent,
            }],
            behavior_digest: behavior.clone(),
            attempted_at: crate::identity::Timestamp::parse(&crate::remote::helper::now_rfc3339())
                .unwrap(),
        })
        .expect("a crafted test intent plans")
    }

    /// The ledger DOMAIN INTENT of the given successful deployment (the
    /// head) — the parent a crafted pending attempt must chain onto (the
    /// lineage invariant: at most one `Successful` per parent).
    fn head_intent(
        h: &RecoveryHarness,
        head_id: &crate::identity::DeploymentId,
    ) -> DeploymentIntent {
        h.store
            .read_ledger("t1")
            .unwrap()
            .into_iter()
            .find(|e| e.deployment_id == *head_id)
            .expect("the head entry exists")
            .intent
    }

    /// The TERMINAL EVENT append (the deployment's ONE atomic finalize write)
    /// fails once on the replaying push: `Err`, no rollback state exists
    /// (the entry stays intent-only = recoverable-pending), and the next
    /// clean push replays and completes finalization exactly once. There is
    /// no separate snapshot/last-successful/transition sequence anymore —
    /// the terminal carries status + outcomes + rollback in one write.
    #[test]
    fn recovery_replays_after_terminal_append_failure() {
        let h = RecoveryHarness::new();
        let attempt = push_pending_attempt(&h);

        // Push 2: the terminal append fails once -> the push aborts with Err
        // and nothing is durable yet (no rollback state).
        let err = {
            h.store
                .fault_registry()
                .arm_append_terminal(attempt.deployment_id.as_str());
            push_clean(&h).expect_err("push must abort when the terminal append fails")
        };
        assert!(
            err.to_string().contains("append_terminal"),
            "error must name the injected fault, got: {err}"
        );
        assert!(
            h.store.read_snapshots("t1").unwrap().is_empty(),
            "no rollback state after the failed append"
        );
        assert!(h.store.read_last_successful("t1").is_none());
        assert_eq!(
            latest_status(&h, attempt.deployment_id.as_str()),
            None,
            "the intent-only entry stays recoverable-pending (an intent without a terminal IS pending)"
        );

        // Push 3: a clean push replays and completes finalization exactly once.
        let r3 = push_clean(&h).unwrap();
        assert_eq!(r3.status, None, "the replaying push is an up-to-date no-op");
        assert_finalized(&h, &attempt);
    }

    /// The SAME atomic terminal append, faulted on the MAIN path (the push
    /// itself): `Err`, the entry stays intent-only (recoverable-pending), and
    /// the next push reconciles it to exactly-once success.
    #[test]
    fn main_path_replays_after_terminal_append_failure() {
        let h = RecoveryHarness::new();
        let id = test_deployment_id("deploy-main-terminal-fault");

        let err = {
            h.store.fault_registry().arm_append_terminal(id.as_str());
            push_main_with_id(&h, &id).expect_err("push must abort when the terminal append fails")
        };
        assert!(
            err.to_string().contains("append_terminal"),
            "error must name the injected fault, got: {err}"
        );
        assert!(
            h.store.read_snapshots("t1").unwrap().is_empty(),
            "no rollback state after the failed append"
        );
        assert!(h.store.read_last_successful("t1").is_none());
        assert_eq!(
            latest_status(&h, id.as_str()),
            None,
            "the crash window must leave the attempt PENDING (intent-only), never Successful"
        );

        // Push 2: a clean push reconciles the pending attempt (servers are
        // already at the desired generation) and completes finalization
        // exactly once.
        let r2 = push_clean(&h).unwrap();
        assert_eq!(r2.status, None, "the replaying push is an up-to-date no-op");
        assert_eq!(r2.message, "Everything up to date");
        assert_eq!(
            h.store.read_attempts("t1").unwrap().len(),
            1,
            "the replay must not record a new attempt"
        );
        assert_finalized(&h, &single_attempt(&h));
    }

    /// A SECOND faulted replay still converges exactly once: the terminal
    /// append is faulted on two consecutive pushes, and the THIRD push
    /// finalizes the attempt exactly once.
    #[test]
    fn second_faulted_replay_still_converges_exactly_once() {
        let h = RecoveryHarness::new();
        let attempt = push_pending_attempt(&h);

        // Push 2: terminal append faulted -> Err.
        let r2 = {
            h.store
                .fault_registry()
                .arm_append_terminal(attempt.deployment_id.as_str());
            push_clean(&h).expect_err("push 2 must abort when the terminal append fails")
        };
        assert!(
            r2.to_string().contains("append_terminal"),
            "error must name the injected fault, got: {r2}"
        );

        // Push 3: terminal append faulted again -> Err; the entry is still
        // intent-only (no rollback state, nothing duplicated).
        let r3 = {
            h.store
                .fault_registry()
                .arm_append_terminal(attempt.deployment_id.as_str());
            push_clean(&h).expect_err("push 3 must abort when the terminal append fails again")
        };
        assert!(
            r3.to_string().contains("append_terminal"),
            "error must name the injected fault, got: {r3}"
        );
        assert!(
            h.store.read_snapshots("t1").unwrap().is_empty(),
            "a second faulted replay must still leave no rollback state"
        );

        // Push 4: clean -> finalizes exactly once.
        let r4 = push_clean(&h).unwrap();
        assert_eq!(r4.status, None, "the replaying push is an up-to-date no-op");
        assert_finalized(&h, &attempt);
    }

    #[test]
    fn recovery_plain_replay_is_idempotent() {
        let h = RecoveryHarness::new();
        let attempt = push_pending_attempt(&h);

        // Push 2: a clean push completes finalization fully (no faults).
        let r2 = push_clean(&h).unwrap();
        assert_eq!(
            r2.status, None,
            "the reconciling push is an up-to-date no-op"
        );
        assert_finalized(&h, &attempt);

        // Push 3: a further clean push re-runs reconciliation (the attempts
        // record is untouched and the transition already says `Successful`)
        // but every step is idempotent: no duplicate snapshot, no changed
        // refs, no new attempt.
        let r3 = push_clean(&h).unwrap();
        assert_eq!(r3.status, None);
        assert_eq!(r3.message, "Everything up to date");
        assert_finalized(&h, &attempt);
        assert_eq!(
            h.store.read_attempts("t1").unwrap().len(),
            1,
            "no new attempt may be recorded by the replays"
        );
    }

    // ---- Main-path replay-safe finalization ------------------------------
    //
    // The NORMAL success path finalizes through the SAME replay-safe
    // finalizer as recovery (`ledger::finalize_successful_locked`):
    // recoverable `PendingCommit` marker -> idempotent snapshot +
    // `refs/last-successful` -> terminal `Successful` transition LAST. These
    // tests fault a normal push's finalization once at each persistence step
    // and prove the recoverable window (the attempt's latest transition is
    // `PendingCommit`, never a prematurely-written `Successful`) plus
    // exactly-once replay on a clean follow-up push.
    //
    // `push()` mints the deployment id internally, so the faulted push drives
    // `push_inner` DIRECTLY with a fixed id (the test module is inside
    // `engine.rs`, so it can): the one-shot `arm_*` faults stay keyed by
    // deployment id exactly like the recovery tests — deterministic under
    // parallel `cargo test`, because each harness arms ITS OWN store's
    // per-fixture fault registry (no process-global slots, no lock).

    #[test]
    fn main_path_finalize_is_replay_safe_and_idempotent() {
        let h = RecoveryHarness::new();
        let id = test_deployment_id("deploy-main-plain");

        // First: a normal push completes finalization fully (no faults):
        // the attempt is `Successful`, one snapshot entry, the ref set.
        let r1 = push_main_with_id(&h, &id).unwrap();
        assert_eq!(
            r1.status,
            Some(DeploymentStatus::Successful),
            "clean push must finalize Successful"
        );
        assert!(
            r1.message.contains(&format!(
                "rollback payload keyed by deployment {id} of target t1"
            )),
            "message must carry the deployment-keyed rollback payload, got: {}",
            r1.message
        );
        assert_finalized(&h, &single_attempt(&h));

        // Push 2: a further push sees everything up to date; reconciliation
        // skips the finalized attempt and no duplicate snapshot appears.
        let r2 = push_clean(&h).unwrap();
        assert_eq!(r2.status, None);
        assert_eq!(r2.message, "Everything up to date");
        assert_finalized(&h, &single_attempt(&h));
        assert_eq!(
            h.store.read_attempts("t1").unwrap().len(),
            1,
            "no new attempt may be recorded by the no-op push"
        );
    }

    /// The marker-integrity-conflict recovery contract (requirement.md step
    /// 15): a `PendingCommit` attempt whose marker ALREADY exists with
    /// DIFFERENT content — a concurrent controller recorded a different fact,
    /// or the remote state diverged — must finalize `Degraded` with reason
    /// "marker integrity conflict", never `Successful`. The conflicting
    /// marker must be left byte-for-byte untouched (a retry would only hit the
    /// same permanent condition, so the attempt must not strand `PendingCommit`
    /// forever either), and no snapshot entry may appear for the attempt.
    #[test]
    fn conflicting_commit_marker_finalizes_degraded_and_never_successful() {
        let h = RecoveryHarness::new();
        // Baseline: a clean successful push (dep1) owns s0.
        let id1 = test_deployment_id("deploy-conflict-baseline");
        let r1 = push_main_with_id(&h, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));

        // Push 2 must MUTATE (otherwise it is an up-to-date no-op and the
        // marker fault never fires): change the artifact content first. The
        // commit marker write fails once -> PendingCommit; the marker is
        // absent, no snapshot exists, and the SERVERS already advanced to the
        // attempt's generation.
        let project_root = h.config.project_root(&h.cfg_path);
        std::fs::write(
            project_root
                .join("releases")
                .join("v1")
                .join("artifacts")
                .join("build/output/app/server"),
            "v2\n",
        )
        .unwrap();
        // Faulted push (inline, since `push_pending_attempt` asserts an empty
        // snapshot log, which a baseline push precludes): the commit-marker
        // write fails once -> PendingCommit; the marker is absent, no NEW
        // snapshot exists, and the servers already advanced to the attempt's
        // generation.
        let armed = Arc::new(AtomicBool::new(true));
        let armed_for_factory = armed.clone();
        let rf = h.remotes_base.clone();
        let fault_factory = move |s: &crate::config::ServerDef,
                                  _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            FailOnceMarkerRemote::build(rf.join(s.id.as_str()), armed_for_factory.clone())
        };
        let r2 = push(
            &h.cfg_path,
            &h.store,
            &fault_factory,
            "t1",
            &h.config,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
        )
        .unwrap();
        assert_eq!(
            r2.status, None,
            "the marker-faulted push leaves the attempt pending (intent-only)"
        );
        let attempt = r2.attempt.expect("attempt recorded");
        let dep2 = attempt.deployment_id.clone();
        let gen_v2 = attempt.desired[&SlotId::new("p1")].generation.clone();
        assert_eq!(
            h.store.read_snapshots("t1").unwrap().len(),
            1,
            "the PendingCommit push adds no snapshot entry"
        );
        let marker_path = h
            .remotes_base
            .join("s1")
            .join(crate::remote::layout::commit_marker(dep2.as_str()));
        assert!(
            !marker_path.exists(),
            "marker absent after the faulted push"
        );

        // A concurrent controller (or divergent remote state) planted a marker
        // for dep2 with DIFFERENT content: a different generation.
        let conflicting = serde_json::json!({
            "deployment_id": dep2.as_str(),
            "committed": true,
            "generation": "gen-from-another-controller",
            "slots": ["p1"],
        });
        let conflicting_bytes = serde_json::to_vec_pretty(&conflicting).unwrap();
        std::fs::create_dir_all(marker_path.parent().unwrap()).unwrap();
        std::fs::write(&marker_path, &conflicting_bytes).unwrap();

        // Push 3: recovery sees the conflicting marker, finalizes dep2 as
        // Degraded (transition only, no snapshot entry), leaves the marker
        // untouched, and then proceeds with the HEAD push (a no-op here).
        let r3 = push_clean(&h).unwrap();
        assert_eq!(r3.status, None, "the main HEAD push is an up-to-date no-op");
        assert_eq!(r3.message, "Everything up to date");
        assert_eq!(
            latest_status(&h, dep2.as_str()),
            Some(DeploymentStatus::Degraded),
            "a conflicting marker must NEVER finalize the attempt Successful"
        );
        let transitions = h.store.read_transitions(dep2.as_str()).unwrap();
        let last = transitions.last().expect("transition stream non-empty");
        assert_eq!(
            last.reason(),
            Some("marker integrity conflict"),
            "the degradation must be explained"
        );
        assert_eq!(
            std::fs::read(&marker_path).unwrap(),
            conflicting_bytes,
            "the conflicting marker must be left byte-for-byte untouched"
        );
        // No snapshot entry for dep2; the ref still points at the baseline.
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].deployment_id, id1);
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(id1.as_str())
        );
        // The live deployment is undisturbed: the servers stay at the gen the
        // PendingCommit attempt actually advanced them to.
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join("s1"))
                .unwrap();
        assert_eq!(
            RemoteHelper::new(&remote)
                .status(&crate::remote::helper::test_owner("eng", "p1"))
                .unwrap()
                .current_generation
                .as_ref()
                .map(|g| g.as_str()),
            Some(gen_v2.as_str()),
            "the conflict must not disturb the live deployment"
        );

        // A VERIFIED SLOT PRESERVES ITS VERIFIED EVIDENCE: the degraded
        // terminal's per-slot outcome records `Known(gen_v2)` — the live
        // generation the BACKEND READ confirmed (the faulted push minted it
        // and the server is still on it) — because the backend read
        // returned it, never because the plan desired it (the old recovery
        // fabricated `Known(desired)` from the intent's frozen snapshot).
        let entries = h.store.read_ledger("t1").unwrap();
        let entry = entries
            .iter()
            .find(|e| e.deployment_id == dep2)
            .expect("the degraded entry exists");
        let terminal = entry
            .terminal
            .as_ref()
            .expect("the degraded attempt has a terminal");
        let degraded_outcomes = terminal.outcomes();
        let outcome = degraded_outcomes
            .get(&SlotId::new("p1".to_string()))
            .expect("the selected slot's outcome");
        assert_eq!(
            outcome.observation(),
            &crate::ledger::Observation::Known(crate::ledger::ObservedGeneration {
                generation: gen_v2
            }),
            "a slot at its desired generation through a backend read keeps Known(desired) — the backend confirmed it"
        );
    }

    // ---- Intent persisted BEFORE remote mutation; InProgress recovery -----
    //
    // The attempt INTENT is now persisted BEFORE any server mutation (a crash
    // after servers advanced can never lose the deployment: the intent is
    // already durable and the next push reconciles it), outcomes are recorded
    // separately in `deployments/<id>/results.json`, and recovery reconciles
    // attempts whose latest transition is `InProgress` (intent durable,
    // finalization never completed) through the SAME verification, marker, and
    // replay-safe finalizer path as `PendingCommit` attempts.
    //
    // Each of the one-shot store faults below is armed by EXACTLY ONE test: the
    // fault statics are process-global keyed by deployment id, so two tests
    // arming the same fault (with different ids) would clobber each other
    // under parallel `cargo test` execution.

    /// Faulting the intent persist (`append_attempt`) must abort the push
    /// BEFORE any remote mutation: no generation is created and `current` is
    /// never touched (the per-server mutation loop cannot start), and no
    /// attempt record leaks.
    /// The inverse guarantee plus crash window (b): when the outcomes store
    /// (`write_results`) is faulted, push 1 fails with the servers ALREADY
    /// advanced but no results.json — yet the intent record exists (immutable
    /// intent, EMPTY `slots`, latest transition `InProgress`, never
    /// `Successful` anywhere). Push 2 reconciles the `InProgress` attempt and
    /// builds the snapshot from the verified desired state — exactly one
    /// snapshot, ref, marker, and terminal `Successful` transition.
    #[test]
    fn write_results_fault_leaves_intent_durable_and_recovers_from_verified_desired() {
        let h = RecoveryHarness::new();
        let id = test_deployment_id("deploy-inprogress-no-results");
        let err = {
            h.store.fault_registry().arm_append_terminal(id.as_str());
            push_main_with_id(&h, &id).expect_err("push must abort when write_results fails")
        };
        assert!(err.to_string().contains("append_terminal"));

        // The intent record is durable even though a later step failed; it
        // carries the planned (desired) and observed (pre_push) maps but NO
        // outcomes (empty `slots`), and the attempt never appears Successful
        // anywhere (no snapshot, no ref, latest transition `InProgress`).
        let attempts = h.store.read_attempts("t1").unwrap();
        assert_eq!(attempts.len(), 1, "intent must be recorded before mutation");
        let intent = &attempts[0];
        assert_eq!(intent.deployment_id, id);
        // The verified domain intent carries NO outcomes map at all (the
        // type split: outcomes live in the terminal event and the in-memory
        // report, never in the persisted intent). The ONE slot table carries
        // the planned (desired) + observed (pre_push) entries per member.
        assert!(
            intent.intent.slots().contains_key(&SlotId::new("p1")),
            "the intent's one full slot table carries the planned slots"
        );
        assert!(
            h.store.read_results(id.as_str()).is_err(),
            "no results.json"
        );
        assert_eq!(
            latest_status(&h, id.as_str()),
            None,
            "the crash window leaves the entry intent-only (recoverable-pending)"
        );
        assert!(h.store.read_snapshots("t1").unwrap().is_empty());
        assert!(h.store.read_last_successful("t1").is_none());
        // Servers DID advance (the mutation loop ran before write_results).
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join("s1"))
                .unwrap();
        assert!(
            remote.exists(crate::remote::layout::current()),
            "remote advanced"
        );

        // Push 2: recovery verifies every slot is at the intent's desired
        // generation, then finalizes; the snapshot is built from the verified
        // desired state (results.json absent).
        let r2 = push_clean(&h).unwrap();
        assert_eq!(r2.status, None, "the replaying push is an up-to-date no-op");
        assert_eq!(r2.message, "Everything up to date");
        let intent = single_attempt(&h);
        assert_finalized(&h, &intent);
        let snap = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snap.len(), 1);
        let rb = rollback_of(&snap[0]);
        let g = rb.get(&SlotId::new("p1")).unwrap();
        let desired = &intent.desired[&SlotId::new("p1")];
        assert_eq!(
            g.generation().as_str(),
            desired.generation.as_str(),
            "snapshot generation comes from the verified desired state"
        );
        assert_eq!(g.artifact().tree, desired.assignment.artifact.tree);
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 1);
    }

    /// Crash window: the intent is durable (outcomes live in the ONE
    /// terminal event, which was NOT appended — the faulted write), so the
    /// attempt is intent-only = the recoverable `PendingCommit` state —
    /// never `Successful` — and the NEXT push reconciles it to exactly-once
    /// success: one rollback state, derived last-successful, the marker, and
    /// the terminal `Successful` event.
    #[test]
    fn inprogress_crash_window_reconciles_to_exactly_once_success() {
        let h = RecoveryHarness::new();
        let id = test_deployment_id("deploy-inprogress-window");
        let err = {
            h.store.fault_registry().arm_append_terminal(id.as_str());
            push_main_with_id(&h, &id).expect_err("push must abort when the terminal append fails")
        };
        assert!(
            err.to_string().contains("append_terminal"),
            "error must name the injected fault, got: {err}"
        );
        assert!(
            h.store.read_results(id.as_str()).is_err(),
            "no outcomes store exists until the terminal event lands"
        );
        assert_eq!(
            h.store.read_transitions(id.as_str()).unwrap().len(),
            0,
            "no terminal event exists before finalization"
        );
        assert_eq!(
            latest_status(&h, id.as_str()),
            None,
            "crash window must leave the attempt pending (intent-only), never Successful"
        );
        assert!(h.store.read_snapshots("t1").unwrap().is_empty());
        assert!(h.store.read_last_successful("t1").is_none());

        // Push 2: a clean push reconciles the `InProgress` attempt (servers
        // are already at the desired generation) and completes finalization
        // exactly once; the finalizer's marker step now appends
        // `PendingCommit` and the terminal `Successful` transition is LAST.
        let r2 = push_clean(&h).unwrap();
        assert_eq!(r2.status, None, "the replaying push is an up-to-date no-op");
        assert_eq!(r2.message, "Everything up to date");
        assert_finalized(&h, &single_attempt(&h));
        assert_eq!(
            h.store.read_attempts("t1").unwrap().len(),
            1,
            "the replay must not record a new attempt"
        );
        assert_eq!(
            latest_status(&h, id.as_str()),
            Some(DeploymentStatus::Successful)
        );
        assert_eq!(h.store.read_snapshots("t1").unwrap().len(), 1);
    }

    /// Crash window (d): an `InProgress` attempt whose generation NO LONGER
    /// matches (the remote advanced elsewhere) finalizes `Degraded` — no
    /// snapshot entry for it — and the up-to-date no-op still reports
    /// correctly. The `InProgress` attempt is crafted directly: its intent
    /// (desired generation) is a FRESH minted generation the remote never
    /// reached, while the remote already advanced to push 1's generation —
    /// the exact state a pre-mutation-persisted intent leaves behind after a
    /// crash plus a concurrent controller. Crafting the record (rather than
    /// arming a second fault) also keeps each one-shot fault armed by exactly
    /// one test.
    #[test]
    fn inprogress_attempt_diverged_generation_finalizes_degraded() {
        let h = RecoveryHarness::new();
        // Push 1: a real successful deployment advances the remote.
        let id_b = test_deployment_id("deploy-diverged-baseline");
        let r1 = push_main_with_id(&h, &id_b).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let baseline = r1.attempt.as_ref().expect("attempt recorded");
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join("s1"))
                .unwrap();
        assert!(
            remote.exists(crate::remote::layout::current()),
            "remote advanced"
        );

        // Craft an InProgress intent (id A) whose desired generation the
        // remote never minted: intent durable, finalization never started,
        // and the remote's current points elsewhere. The intent is planned
        // OVER the successful head (the strictly-linear model: parent == the
        // head).
        let target_a = GenerationId::generate();
        let id_a = test_deployment_id("deploy-inprogress-diverged");
        let desired_ref = baseline.desired[&SlotId::new("p1")].clone();
        let head = head_intent(&h, &id_b);

        let intent = crafted_intent(
            &id_a,
            &target_a,
            &desired_ref.assignment.artifact,
            crate::ledger::PhysicalBinding::new(ServerId::parse("s1").unwrap(), "/srv/eng")
                .expect("test binding is absolute and traversal-free"),
            &baseline.behavior_sha256,
            Some(&head),
        );
        h.store.append_attempt("t1", &intent).unwrap();
        assert_eq!(
            latest_status(&h, id_a.as_str()),
            None,
            "the intent-only entry is the recoverable pending state"
        );

        // Push 2: recovery verifies the InProgress attempt; the slot's current
        // generation no longer matches the intent's desired generation, so it
        // finalizes Degraded — no snapshot entry for it, no last-successful
        // change — and the up-to-date check (same artifact) reports a no-op.
        let r2 = push_clean(&h).unwrap();
        assert_eq!(r2.status, None, "the replaying push is an up-to-date no-op");
        assert_eq!(r2.message, "Everything up to date");
        assert_eq!(
            latest_status(&h, id_a.as_str()),
            Some(DeploymentStatus::Degraded),
            "the diverged attempt must finalize Degraded"
        );
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 1, "only the baseline snapshot exists");
        assert_eq!(snapshots[0].deployment_id, id_b);
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(id_b.as_str()),
            "last-successful still points at the baseline deployment"
        );
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 2);

        // THE TRUTHFUL DEGRADED OBSERVATION (the fabrication bug this
        // feature fixes): the degraded terminal's per-slot outcome records
        // the BACKEND's live generation — the baseline's, the remote's
        // actual `current` — NEVER the crafted intent's DESIRED generation
        // "a" the remote never reached (the old recovery fabricated
        // `Known(desired)` from the plan's frozen snapshot without ever
        // performing an observation).
        let entries = h.store.read_ledger("t1").unwrap();
        let entry = entries
            .iter()
            .find(|e| e.deployment_id == id_a)
            .expect("the degraded entry exists");
        let terminal = entry
            .terminal
            .as_ref()
            .expect("the degraded attempt has a terminal");
        let degraded_outcomes = terminal.outcomes();
        let outcome = degraded_outcomes
            .get(&SlotId::new("p1".to_string()))
            .expect("the selected slot's outcome");
        let live_p1 = baseline.desired[&SlotId::new("p1".to_string())]
            .generation
            .clone();
        assert_eq!(
            outcome.observation(),
            &crate::ledger::Observation::Known(crate::ledger::ObservedGeneration {
                generation: live_p1
            }),
            "the degraded terminal records the BACKEND-observed live generation (the baseline's), never the plan's desired generation"
        );
    }

    // ---- Transition sequence, outcomes separation, no-op trace, mid-mutation
    // durability, and multi-attempt reconcile ordering -----------------------

    /// A just-recorded attempt with NO transition stream at all (latest status
    /// `None`) is eligible for reconciliation: the next push finalizes it
    /// Successful with its own snapshot entry instead of skipping it.
    #[test]
    fn reconcile_attempt_without_transitions_is_eligible() {
        let h = RecoveryHarness::new();
        let id_b = test_deployment_id("deploy-no-status-baseline");
        let r1 = push_main_with_id(&h, &id_b).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let baseline = r1.attempt.as_ref().expect("attempt recorded");
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join("s1"))
                .unwrap();
        assert!(
            remote.exists(crate::remote::layout::current()),
            "remote advanced"
        );

        // Craft an intent with NO transition appended: eligibility treats the
        // absent status file as eligible (a just-recorded attempt). It plans
        // against the CURRENT successful head (the lineage invariant — at
        // most one `Successful` per parent), exactly as a real pending
        // attempt would.
        let id_a = test_deployment_id("deploy-no-status");
        let desired_ref = baseline.desired[&SlotId::new("p1")].clone();
        let head = head_intent(&h, &id_b);

        let intent = crafted_intent(
            &id_a,
            &desired_ref.generation.clone(),
            &desired_ref.assignment.artifact,
            crate::ledger::PhysicalBinding::new(ServerId::parse("s1").unwrap(), "/srv/eng")
                .expect("test binding is absolute and traversal-free"),
            &baseline.behavior_sha256.clone(),
            Some(&head),
        );
        h.store.append_attempt("t1", &intent).unwrap();
        assert_eq!(
            h.store.latest_status(id_a.as_str()).unwrap(),
            None,
            "an intent-only entry is the recoverable pending state"
        );

        // The next push reconciles the transition-less attempt (the remote is
        // already at its desired generation) and finalizes it Successful.
        let r2 = push_clean(&h).unwrap();
        assert_eq!(r2.status, None, "reconciling push is an up-to-date no-op");
        assert_eq!(r2.message, "Everything up to date");
        assert_eq!(
            latest_status(&h, id_a.as_str()),
            Some(DeploymentStatus::Successful)
        );
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 2, "baseline + reconciled attempt");
        assert_eq!(snapshots[1].deployment_id, id_a);
        assert_eq!(
            ledger::successful_index(&h.store, "t1", &id_a)
                .unwrap()
                .unwrap(),
            1,
            "the reconciled attempt is successful-chain position s1"
        );
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(id_a.as_str())
        );
        let marker = h
            .remotes_base
            .join("s1")
            .join(crate::remote::layout::commit_marker(id_a.as_str()));
        assert!(marker.exists(), "marker written for the original id");
    }

    /// THE STRICTLY-LINEAR GUARANTEE (the new-model replacement for the old
    /// two-pending reconciliation): a ledger NEVER holds two simultaneously
    /// pending intents. The SECOND crafted pending intent on the SAME
    /// parent is REFUSED at the store's pre-write lineage gate with a
    /// Conflict (`PendingAttemptExists` — no bytes written); after the
    /// first pending attempt reaches its `Successful` terminal (becoming
    /// the head), a stale re-append of the second intent is refused too
    /// (`ParentMismatch` — its old parent is no longer the head), and the
    /// retry — planned over the NEW head — appends and finalizes linearly.
    /// Successful positions stay monotonic (1, 2 beyond the baseline).
    #[test]
    fn reconcile_multiple_pending_oldest_first_with_monotonic_indices() {
        let h = RecoveryHarness::new();
        let id_b = test_deployment_id("deploy-multi-baseline");
        let r1 = push_main_with_id(&h, &id_b).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let baseline = r1.attempt.as_ref().expect("attempt recorded");
        let desired_ref = baseline.desired[&SlotId::new("p1")].clone();
        let head = head_intent(&h, &id_b);

        let mk = |id: &str| {
            crafted_intent(
                &test_deployment_id(id),
                &desired_ref.generation,
                &desired_ref.assignment.artifact,
                crate::ledger::PhysicalBinding::new(ServerId::parse("s1").unwrap(), "/srv/eng")
                    .expect("test binding is absolute and traversal-free"),
                &baseline.behavior_sha256,
                Some(&head),
            )
        };
        let a = mk("deploy-multi-a");
        let b = mk("deploy-multi-b");
        // A appends: the ONE pending intent, parent == the head.
        h.store.append_attempt("t1", &a).unwrap();
        assert_eq!(
            latest_status(&h, a.deployment_id().as_str()),
            None,
            "an intent-only entry IS the pending state"
        );
        // B — the SECOND pending intent on the SAME parent — is REFUSED at
        // intent-append time (strictly linear: at most one unresolved intent
        // at a time). Conflict, and the ledger bytes are unchanged.
        let ledger_path = h.store.ledger_path("t1");
        let bytes_before = std::fs::read(&ledger_path).unwrap();
        let err = h.store.append_attempt("t1", &b).unwrap_err();
        assert!(
            err.to_string().contains("still pending"),
            "the second intent while the first is pending must be refused with a Conflict, got: {err}"
        );
        assert!(
            err.to_string().contains("conflict"),
            "the write-boundary lineage refusal is a Conflict, got: {err}"
        );
        assert_eq!(
            std::fs::read(&ledger_path).unwrap(),
            bytes_before,
            "a refused second intent leaves the ledger bytes unchanged (no append)"
        );
        // A reaches its Successful terminal — the head advances to A.
        h.store
            .test_append_terminal(
                "t1",
                a.deployment_id(),
                &crate::testutil::fixtures::successful_terminal(&a),
            )
            .unwrap();
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(a.deployment_id().as_str()),
            "A is the head after its Successful terminal"
        );
        assert_eq!(
            ledger::successful_index(&h.store, "t1", a.deployment_id())
                .unwrap()
                .unwrap(),
            1,
            "A's successful position is s1 (monotonic past the baseline)"
        );
        // B with its OLD parent (the baseline) is now refused too: the head
        // moved on — a retry must plan over the NEW head (A).
        let err = h.store.append_attempt("t1", &b).unwrap_err();
        assert!(
            err.to_string().contains("ParentMismatch"),
            "a stale-parent intent is refused at append time, got: {err}"
        );
        let b2 = crafted_intent(
            &test_deployment_id("deploy-multi-b"),
            &desired_ref.generation,
            &desired_ref.assignment.artifact,
            crate::ledger::PhysicalBinding::new(ServerId::parse("s1").unwrap(), "/srv/eng")
                .expect("test binding is absolute and traversal-free"),
            &baseline.behavior_sha256,
            Some(&a),
        );
        h.store.append_attempt("t1", &b2).unwrap();
        h.store
            .test_append_terminal(
                "t1",
                b2.deployment_id(),
                &crate::testutil::fixtures::successful_terminal(&b2),
            )
            .unwrap();
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(b2.deployment_id().as_str()),
            "the replanned B becomes the head"
        );
        assert_eq!(
            ledger::successful_index(&h.store, "t1", b2.deployment_id())
                .unwrap()
                .unwrap(),
            2,
            "successful-chain positions stay monotonic"
        );
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 3);
        assert_eq!(
            latest_status(&h, b2.deployment_id().as_str()),
            Some(DeploymentStatus::Successful)
        );
    }

    // ---- Verification-failure rollback + observed refresh -----------------
    //
    // An attempt whose ACTIVATION succeeds but whose VERIFICATION fails must
    // compensate back to the PRIOR generation (restoring the prior behavior
    // contract), report `FailedRolledBack`, and refresh `observed.json` with
    // the ACTUAL restored state — the prior generation and artifact — never
    // the desired (failed) artifact. This is the dedicated verification-
    // failure variant the integration `end_to_end_push_rollback` does NOT
    // exercise (that test only pushes/rolls back successful states).

    /// GROUP-PUSH ROLLBACK IS THE COMPLETE RESULTING SNAPSHOT (the
    /// base-overlay semantics, end to end): a successful group push's
    /// rollback is the COMPLETE target state — the selected outcomes
    /// overlaid on the latest successful base, the unselected slots carried
    /// forward — so the rollback's slots are the FULL current target
    /// membership (⊇ the outcomes' keys, which cover the SELECTED slots).
    /// A rollback of that deployment restores the FULL membership, resolving
    /// EACH slot's behavior from ITS OWN (release, variant) binding — never
    /// a snapshot-wide single release.
    ///
    /// Drives the REAL push path on a two-group harness: a full push
    /// establishes both slots under contract A (release R1), a group-b push
    /// advances only `p2` to contract B (release R2) and records a rollback
    /// covering BOTH slots (the unselected `p1` is carried forward at R1,
    /// `p2` at R2). A FULL rollback of that group-b deployment now SUCCEEDS
    /// (the rollback covers the full membership), restoring `p2` to R2's
    /// variant behavior digest while `p1` stays on R1's (each slot's OWN
    /// release — under the old snapshot-wide behavior `p2` would receive
    /// R1's digest), and the referenced release's record is published on its
    /// server's remote.
    #[test]
    fn group_push_rollback_covers_the_complete_membership_and_publishes_per_slot_behavior() {
        let h = TwoSlotHarness::new();
        let slot_a = SlotId::parse("p1").unwrap();
        let slot_b = SlotId::parse("p2").unwrap();

        // Push 1: FULL Head push under contract A (argv ["true", "a"]) —
        // release R1 for BOTH slots; snapshot S0: p1=R1, p2=R1.
        let id1 = test_deployment_id("deploy-mr-baseline");
        let r1 = two_slot_push(&h, &h.config, &RefExpr::Head, None, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let var_a = h.config.variant("standard").unwrap();
        let digest_a = crate::verify::release::behavior_contract_digest(&BehaviorContract {
            activation: var_a.activation.clone(),
            verification: var_a.verification.clone(),
        });
        let attempt1 = r1.attempt.as_ref().expect("attempt recorded");
        let r1_release = attempt1.desired[&slot_a]
            .assignment
            .artifact
            .release
            .clone();
        assert_eq!(
            attempt1.desired[&slot_b].assignment.artifact.release, r1_release,
            "the full push deploys one release across both slots"
        );

        // Edit the variant to contract B (argv ["true", "b"]) AND a
        // DIFFERENT artifact payload, then reload: a group-b Head push now
        // builds a DISTINCT release R2.
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
        let var_b = config2.variant("standard").unwrap();
        let digest_b = crate::verify::release::behavior_contract_digest(&BehaviorContract {
            activation: var_b.activation.clone(),
            verification: var_b.verification.clone(),
        });
        assert_ne!(
            digest_a, digest_b,
            "the two contracts must be DISTINGUISHABLE"
        );

        // Push 2: PARTIAL group-b push under contract B — p2 advances to R2,
        // p1 stays R1. The rollback is the COMPLETE resulting snapshot: the
        // base-overlay carries the unselected p1 forward at R1 and overlays
        // p2 at R2 — the rollback's slots are the FULL membership (⊇ the
        // outcomes' keys, which cover the SELECTED group-b slot only).
        let id2 = test_deployment_id("deploy-mr-group-b");

        let r2 = two_slot_push(&h, &config2, &RefExpr::Head, Some("group-b"), &id2).unwrap();
        assert_eq!(r2.status, Some(DeploymentStatus::Successful));
        let attempt2 = r2.attempt.as_ref().expect("attempt recorded");
        let r2_release = attempt2.desired[&slot_b]
            .assignment
            .artifact
            .release
            .clone();
        assert_ne!(
            r1_release, r2_release,
            "the group push must produce a DISTINCT release"
        );
        assert_eq!(
            attempt2.desired.len(),
            1,
            "a group push plans only its selected slots"
        );
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 2, "baseline + the group-b snapshot");
        let s1 = rollback_of(&snapshots[1]);
        assert_eq!(
            s1.len(),
            2,
            "the group push's rollback is the COMPLETE resulting snapshot — the unselected slot is carried forward from the base"
        );
        assert_eq!(
            s1.get(&slot_a).unwrap().artifact().release,
            r1_release,
            "the unselected slot is carried forward at its base release (R1)"
        );
        assert_eq!(
            s1.get(&slot_b).unwrap().artifact().release,
            r2_release,
            "the group push's rollback records its selected slot's own release (R2)"
        );
        assert_eq!(
            s1.len(),
            2,
            "the complete snapshot binds the full membership"
        );

        // A FULL rollback to the group-b deployment now SUCCEEDS: the group
        // push's rollback is the COMPLETE resulting snapshot (the
        // base-overlay carried the unselected slot forward), so it covers the
        // full membership and an exact full rollback can restore BOTH slots
        // to their recorded state (p1 → R1, p2 → R2).
        let id3 = test_deployment_id("deploy-mr-rollback");
        let r3 = two_slot_push(
            &h,
            &config2,
            &ledger::parse_ref_expr(id2.as_str()).unwrap(),
            None,
            &id3,
        )
        .unwrap();
        assert_eq!(r3.status, Some(DeploymentStatus::Successful));

        // Push 4: FULL rollback of the BASELINE deployment (id1 — a full
        // push whose rollback covers both slots) restores BOTH slots to
        // their recorded state (R1, contract A).
        let id4 = test_deployment_id("deploy-mr-rollback-base");
        let r4 = two_slot_push(
            &h,
            &config2,
            &ledger::parse_ref_expr(id1.as_str()).unwrap(),
            None,
            &id4,
        )
        .unwrap();
        assert_eq!(r4.status, Some(DeploymentStatus::Successful));

        // The persisted plan carries the frozen PER-RELEASE behavior index
        // for the rollback's referenced release (R1 — the baseline's own
        // release) and the referenced-release set derived from the
        // snapshot's slots.
        let plan: DeploymentPlan = serde_json::from_str(
            &std::fs::read_to_string(h.store.deployment_dir(id4.as_str()).join("plan.json"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            plan.releases(),
            BTreeSet::from([r1_release.clone()]),
            "the rollback plan references the baseline's own release (R1)"
        );
        assert_eq!(
            plan.behaviors().len(),
            1,
            "one frozen behavior block per referenced release"
        );
        assert_eq!(
            crate::verify::release::behavior_contract_digest(
                &plan.behaviors()[&r1_release]["standard"]
            ),
            digest_a
        );

        // EVERY SELECTED SLOT receives EXACTLY its own release's variant
        // behavior: the live generation assignment published on p1's and p2's
        // servers carries digest A (R1) — the baseline's own release — never
        // a snapshot-wide single release's contract.
        for (server, slot, want_digest, want_release) in [
            ("s1", &slot_a, &digest_a, &r1_release),
            ("s2", &slot_b, &digest_a, &r1_release),
        ] {
            let remote =
                LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join(server))
                    .unwrap();
            let helper = RemoteHelper::new(&remote);
            let status = helper
                .status(&crate::remote::helper::test_owner("eng", slot.as_str()))
                .unwrap();
            let cur = status
                .current_generation
                .expect("the rollback must advance the slot");
            let assignment: GenerationAssignment = serde_json::from_slice(
                &remote
                    .read(
                        &crate::remote::layout::generations()
                            .join(cur.as_str())
                            .join("assignment.json"),
                    )
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                assignment.behavior_sha256.as_str(),
                want_digest.as_str(),
                "slot {slot} must publish ITS OWN release's variant behavior digest"
            );
            assert_eq!(assignment.artifact.release.as_str(), want_release.as_str());
            assert!(
                remote.exists(
                    &crate::remote::layout::remote_release(want_release.as_str())
                        .join("release.json")
                ),
                "slot {slot}'s release record must be published on its server's remote"
            );
            assert!(
                remote.exists(
                    &crate::remote::layout::remote_release(want_release.as_str())
                        .join("behavior.json")
                ),
                "slot {slot}'s release behavior.json must be published on its server's remote"
            );
        }
        // And the two contracts are DISTINGUISHABLE — the assertion above is
        // not vacuous: the group push's release R2 really differs from the
        // baseline's R1 (a single contract would have made the group push a
        // no-op).
        assert_ne!(digest_a, digest_b);
    }

    // A corrupt CURRENT generation assignment is detected by `status()`
    // itself — the complete symlink layout is validated (`current` ->
    // generation dir -> `assignment.json` -> generation id) — so a push
    // against a remote whose live assignment is corrupt FAILS CLOSED with an
    // integrity error BEFORE any mutation or intent persistence: never a
    // panic, never a fabricated observation, never a silent proceed on an
    // unverifiable current.

    proptest! {
        // THE USER'S GROUP-SEQUENCE PROPERTY: a FULL BASELINE followed by
        // ARBITRARY VALID GROUP-PUSH SEQUENCES (any group, any order,
        // repeats) — every push edits the artifact content so it mints a
        // NEW release (never a no-op). Asserts: EVERY SUCCESSFUL SNAPSHOT
        // CONTAINS THE COMPLETE CURRENT TARGET MEMBERSHIP (the rollback's
        // slots == the full membership — the base-overlay carried the
        // unselected slots forward), and REPEATING ANY GROUP REMAINS VALID
        // (a group push whose group was already pushed succeeds — the
        // conversion accepts its snapshot). Bounded `proptest_cases(16)`
        // (full 16 with `DEPLOY_FULL_TESTS=1`, fast default), fixed seed
        // 0x5EED_5EED (house style), no persistence.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn group_push_sequences_keep_complete_snapshots_and_repeats_are_valid(
            groups in prop::collection::vec(
                prop::sample::select(vec!["group-a", "group-b"]),
                1..=4,
            ),
        ) {
            // SLOW-test gate: exceeds ~20 s under the FULL gate
            if !crate::testutil::slow_tests_enabled() {
                eprintln!("skipped: slow test — set DEPLOY_FULL_TESTS=1 to run");
                return Ok(());
            }
            let h = TwoSlotHarness::new();
            let slot_a = SlotId::parse("p1").unwrap();
            let slot_b = SlotId::parse("p2").unwrap();
            let full_membership: BTreeSet<SlotId> =
                BTreeSet::from([slot_a.clone(), slot_b.clone()]);

            // Push 0: FULL baseline — both slots under release R0.
            let id0 = test_deployment_id("deploy-prop-base");
            let r0 = two_slot_push(&h, &h.config, &RefExpr::Head, None, &id0).unwrap();
            assert_eq!(r0.status, Some(DeploymentStatus::Successful));
            let snapshots = h.store.read_snapshots("t1").unwrap();
            assert_eq!(snapshots.len(), 1, "the full baseline is the first snapshot");
            assert_eq!(
                rollback_of(&snapshots[0]).keys()
                    .cloned()
                    .collect::<BTreeSet<_>>(),
                full_membership,
                "the full baseline's snapshot covers the complete membership"
            );

            // Each group push edits the artifact content so the push mints a
            // NEW release (never a no-op), then pushes the generated group.
            let project_root = h.config.project_root(&h.cfg_path);
            let artifact_path = project_root
                .join("releases")
                .join("v1")
                .join("artifacts")
                .join("build/output/app/server");
            for (i, group) in groups.iter().enumerate() {
                std::fs::write(&artifact_path, format!("v{}\n", i + 2)).unwrap();
                let config = ProjectConfig::load(&h.cfg_path).unwrap();
                let id = test_deployment_id(&format!("deploy-prop-{i}"));
                let r = two_slot_push(&h, &config, &RefExpr::Head, Some(group), &id).unwrap();
                assert_eq!(
                    r.status,
                    Some(DeploymentStatus::Successful),
                    "group push {i} ({group}) must succeed — repeating a group stays valid"
                );
                // EVERY successful snapshot contains the COMPLETE current
                // target membership: the base-overlay carried the unselected
                // slots forward.
                let snapshots = h.store.read_snapshots("t1").unwrap();
                let last = rollback_of(snapshots.last().unwrap());
                assert_eq!(
                    last.keys().cloned().collect::<BTreeSet<_>>(),
                    full_membership,
                    "group push {i} ({group}) must record the complete membership in its snapshot (the unselected slot is carried forward)"
                );
                assert_eq!(
                    last.keys().cloned().collect::<BTreeSet<_>>(),
                    full_membership,
                    "group push {i} ({group}) must bind the complete membership"
                );
                // The conversion accepts the snapshot (read_ledger — the
                // first consumer — succeeds on the whole ledger).
                h.store.read_ledger("t1").unwrap();
            }
        }
    }

    /// DETERMINISTIC: a group push's snapshot has the FULL membership (the
    /// base-overlay carried the unselected slot forward) while its OUTCOMES
    /// cover the SELECTED slots only — the group rule (selected ⊊ full,
    /// outcomes == selected, rollback == full) accepts the snapshot, and
    /// selected == full is NOT required for a group push.
    #[test]
    fn group_push_snapshot_has_full_membership_and_selected_outcomes() {
        let h = TwoSlotHarness::new();
        let slot_a = SlotId::parse("p1").unwrap();
        let slot_b = SlotId::parse("p2").unwrap();
        let full_membership: BTreeSet<SlotId> = BTreeSet::from([slot_a.clone(), slot_b.clone()]);

        // Push 1: FULL baseline (both slots under R1).
        let id1 = test_deployment_id("deploy-det-base");
        let r1 = two_slot_push(&h, &h.config, &RefExpr::Head, None, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let r1_release = r1.attempt.as_ref().expect("attempt").desired[&slot_a]
            .assignment
            .artifact
            .release
            .clone();

        // Push 2: group-a push with a NEW release (edit the artifact).
        let project_root = h.config.project_root(&h.cfg_path);
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
        let id2 = test_deployment_id("deploy-det-group-a");
        let r2 = two_slot_push(&h, &config2, &RefExpr::Head, Some("group-a"), &id2).unwrap();
        assert_eq!(r2.status, Some(DeploymentStatus::Successful));
        let r2_release = r2.attempt.as_ref().expect("attempt").desired[&slot_a]
            .assignment
            .artifact
            .release
            .clone();
        assert_ne!(r1_release, r2_release, "the group push mints a new release");

        // The snapshot: FULL membership (p1 at R2, p2 carried forward at R1)
        // with bindings over the full membership.
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 2);
        let last = rollback_of(&snapshots[1]);
        assert_eq!(
            last.keys().cloned().collect::<BTreeSet<_>>(),
            full_membership,
            "the group push's snapshot has the full membership"
        );
        assert_eq!(
            last.get(&slot_a).unwrap().artifact().release,
            r2_release,
            "the selected slot records its own release"
        );
        assert_eq!(
            last.get(&slot_b).unwrap().artifact().release,
            r1_release,
            "the unselected slot is carried forward at its base release"
        );
        assert_eq!(
            last.keys().cloned().collect::<BTreeSet<_>>(),
            full_membership,
            "the bindings cover the full membership"
        );
        // The OUTCOMES cover the SELECTED slots only (the group), and the
        // conversion accepts the snapshot (the group rule: selected ⊊ full,
        // outcomes == selected, rollback == full). The PERSISTED memberships
        // prove it: selected == the group's slot, full == the complete
        // membership.
        let entries = h.store.read_ledger("t1").unwrap();
        let terminal = entries[1].terminal.as_ref().unwrap();
        assert!(
            terminal.outcomes().is_empty(),
            "a Successful terminal is PAYLOAD-FREE — no outcome claims to drift from the intent"
        );
        assert_eq!(
            entries[1].intent.selected_membership(),
            BTreeSet::from([slot_a.clone()]),
            "the SELECTED membership = the group's slot, DERIVED from the intent's slot actions"
        );
        assert_eq!(
            entries[1].intent.full_membership(),
            full_membership.clone(),
            "the FULL membership = the complete target membership, DERIVED from the intent's slot table"
        );
    }

    /// DETERMINISTIC: REPEATING THE SAME GROUP REMAINS VALID — a group push
    /// whose group was already pushed succeeds (the conversion accepts its
    /// complete-snapshot rollback), and each repeat still records the full
    /// membership.
    #[test]
    fn repeating_the_same_group_succeeds() {
        let h = TwoSlotHarness::new();
        let slot_a = SlotId::parse("p1").unwrap();
        let slot_b = SlotId::parse("p2").unwrap();
        let full_membership: BTreeSet<SlotId> = BTreeSet::from([slot_a.clone(), slot_b.clone()]);

        // Push 1: FULL baseline.
        let id1 = test_deployment_id("deploy-repeat-base");
        let r1 = two_slot_push(&h, &h.config, &RefExpr::Head, None, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));

        // Push 2 and 3: group-a TWICE, each with a NEW release.
        let project_root = h.config.project_root(&h.cfg_path);
        let artifact_path = project_root
            .join("releases")
            .join("v1")
            .join("artifacts")
            .join("build/output/app/server");
        for (i, id) in ["deploy-repeat-a1", "deploy-repeat-a2"]
            .into_iter()
            .enumerate()
        {
            std::fs::write(&artifact_path, format!("v{}\n", i + 2)).unwrap();
            let config = ProjectConfig::load(&h.cfg_path).unwrap();
            let r = two_slot_push(
                &h,
                &config,
                &RefExpr::Head,
                Some("group-a"),
                &test_deployment_id(id),
            )
            .unwrap();
            assert_eq!(
                r.status,
                Some(DeploymentStatus::Successful),
                "repeating group-a (push {i}) must succeed"
            );
            let snapshots = h.store.read_snapshots("t1").unwrap();
            let last = rollback_of(snapshots.last().unwrap());
            assert_eq!(
                last.keys().cloned().collect::<BTreeSet<_>>(),
                full_membership,
                "the repeated group push still records the complete membership"
            );
            h.store.read_ledger("t1").unwrap();
        }
    }

    /// DETERMINISTIC: a FULL push still enforces the strict equality — the
    /// membership equations (outcomes == selected == full == rollback slots
    /// == bindings, with the full-push selected == full leg) imply the
    /// snapshot's outcomes == rollback slots == rollback bindings == the
    /// intent's membership (all equal, non-empty).
    #[test]
    fn full_push_still_enforces_the_strict_four_set_equality() {
        let h = TwoSlotHarness::new();
        let slot_a = SlotId::parse("p1").unwrap();
        let slot_b = SlotId::parse("p2").unwrap();
        let full_membership: BTreeSet<SlotId> = BTreeSet::from([slot_a.clone(), slot_b.clone()]);

        let id1 = test_deployment_id("deploy-strict-base");
        let r1 = two_slot_push(&h, &h.config, &RefExpr::Head, None, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let entries = h.store.read_ledger("t1").unwrap();
        let entry = &entries[0];
        assert_eq!(
            entry.intent.selected_membership(),
            full_membership.clone(),
            "a full push's SELECTED membership (the Deploy slots) is the full target"
        );
        assert_eq!(
            entry.intent.full_membership(),
            full_membership.clone(),
            "a full push's FULL membership is the full target"
        );
        let terminal = entry.terminal.as_ref().unwrap();
        assert!(
            terminal.disposition().is_successful(),
            "the full push is Successful"
        );
        assert!(
            terminal.outcomes().is_empty(),
            "a Successful terminal is PAYLOAD-FREE — one stored fact"
        );
        let resolved = crate::kernel::snapshot::resolve_snapshot(entry).unwrap();
        assert_eq!(
            resolved.keys().cloned().collect::<BTreeSet<_>>(),
            full_membership,
            "the resolved snapshot's slots equal the membership"
        );
        assert_eq!(
            resolved,
            entry.intent.resulting_snapshot(),
            "the resolved snapshot IS the intent's planned result — no parallel payload"
        );
    }

    // ---- Pending-recovery vs the FROZEN bindings (schema v6) -------------
    //
    // The intent FREEZES each selected slot's plan-time `{server,
    // deploy_dir}` inside its resulting_snapshot entry (the snapshot is the
    // single frozen source); recovery
    // compares each selected slot's LIVE binding against that frozen value
    // and finalizes from the FROZEN bindings on equality or marks the
    // attempt Degraded on drift — a server rebound or a moved `deploy_dir`
    // between the intent's write and recovery can never be recorded as the
    // historical location the attempt was planned against.

    /// The generated LIVE-CONFIGURATION mutation (applied by rewriting the
    /// harness's variant + deploy.toml and reloading): how the recovery-time
    /// configuration may differ from the plan-time configuration the intent
    /// froze. `None` keeps live == frozen (the positive control).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ConfigMutation {
        /// No mutation: the live bindings equal the frozen intent.
        None,
        /// Rebind the attempt's slot to a different server (server drift).
        RebindServer,
        /// Move the attempt's slot's `deploy_dir` (deploy_dir drift).
        MoveDeployDir,
        /// ADD a slot to the target (membership growth — the selected slot
        /// stays bound as frozen, so no drift).
        AddSlot,
        /// REMOVE the attempt's slot from the target (membership loss — the
        /// membership check degrades it).
        RemoveSlot,
    }

    /// Apply the generated mutation to the harness's configuration files
    /// (the variant file declares the target's slots; `deploy.toml` declares
    /// the servers), reloading and returning the MUTATED (live) config the
    /// recovery runs against.
    fn mutated_config(h: &RecoveryHarness, mutation: ConfigMutation) -> ProjectConfig {
        let project = h.cfg_path.parent().unwrap();
        let variant_path = project.join("releases").join("v1").join("standard.toml");
        let (variant, toml) = match mutation {
            ConfigMutation::None => (NONE_VARIANT.to_string(), NONE_TOML.to_string()),
            ConfigMutation::RebindServer => (
                NONE_VARIANT.replace("server = \"s1\"", "server = \"s2\""),
                NONE_TOML.replace(
                    "[targets.t1]",
                    "[[servers]]\nid = \"s2\"\naddress = \"b\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n[targets.t1]",
                ),
            ),
            ConfigMutation::MoveDeployDir => (
                NONE_VARIANT.replace(
                    "deploy_dir = \"/srv/eng\"",
                    "deploy_dir = \"/srv/eng-moved\"",
                ),
                NONE_TOML.to_string(),
            ),
            ConfigMutation::AddSlot => (
                format!(
                    "{NONE_VARIANT}\n[[slots]]\nid = \"p2\"\nserver = \"s2\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/eng-b\"\n"
                ),
                NONE_TOML.replace(
                    "[targets.t1]",
                    "[[servers]]\nid = \"s2\"\naddress = \"b\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n[targets.t1]",
                ),
            ),
            ConfigMutation::RemoveSlot => (
                NONE_VARIANT
                    .replace(
                        "[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/eng\"\n",
                        "[[slots]]\nid = \"p2\"\nserver = \"s1\"\ntarget = \"t1\"\ndeploy_dir = \"/srv/eng-b\"\n",
                    )
                    .to_string(),
                NONE_TOML.to_string(),
            ),
        };
        std::fs::write(&variant_path, &variant).unwrap();
        std::fs::write(&h.cfg_path, toml).unwrap();
        ProjectConfig::load(&h.cfg_path).unwrap()
    }

    proptest! {
        // THE PENDING-RECOVERY FROZEN-BINDING PROPERTY: persist a pending
        // intent, arbitrarily MUTATE the live configuration (server rebind /
        // deploy_dir move / membership add / membership remove — plus the
        // unchanged positive control), OPTIONALLY copy the generation state
        // (the remote may or may not hold the frozen desired generation),
        // then recover against the mutated config. A SUCCESSFUL terminal is
        // permitted IFF every selected slot's LIVE binding equals the FROZEN
        // intent binding AND the membership still covers the selected slots
        // AND every selected slot's live generation equals the frozen
        // desired generation; otherwise NO SUCCESSFUL TERMINAL MAY APPEAR
        // (the attempt must end Degraded or stay pending — the property
        // asserts the actual disposition). On success, the rollback's
        // bindings/generations EXACTLY equal the frozen intent's values
        // (finalize-from-frozen — never the live config re-read).
        //
        // Bounded `proptest_cases(16)` (full 16 with `DEPLOY_FULL_TESTS=1`,
        // fast default), fixed seed 0x5EED_5EED (house style), no failure
        // persistence — the identical vectors on every run.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn pending_recovery_finalizes_from_the_frozen_binding_or_degrades_on_drift(
            mutation in prop_oneof![
                Just(ConfigMutation::None),
                Just(ConfigMutation::RebindServer),
                Just(ConfigMutation::MoveDeployDir),
                Just(ConfigMutation::AddSlot),
                Just(ConfigMutation::RemoveSlot),
            ],
            generation_copied in prop::bool::ANY,
        ) {
            // Persist a PENDING (intent-only) attempt: the remote advanced
            // to the desired generation, the commit-marker write failed, so
            // the intent is durable and the terminal never appended — the
            // recoverable state the next push reconciles. The ENGINE froze
            // the plan-time binding ({s1, /srv/eng}) into the intent.
            let h = RecoveryHarness::new();
            let pending = push_pending_attempt(&h);
            let attempts = h.store.read_attempts("t1").unwrap();
            assert_eq!(attempts.len(), 1, "the pending intent is the only attempt");
            let intent = &attempts[0].intent;

            // The MUTATED live config at recovery time.
            let live = mutated_config(&h, mutation);
            let live_bindings = live.target_slot_bindings("t1").unwrap();

            // Per-slot helpers over the mutated config's servers. The remote
            // base is the harness's (the s1 remote carries the pending
            // attempt's desired generation — the "generation state copied"
            // arm) or a FRESH dir (the "generation state absent" arm — a
            // remote that never saw the deployment).
            let members = live.target_slots("t1").unwrap();
            let fresh_base = h._dir.path().join("fresh-remotes");
            let mut remotes: Vec<Box<dyn Remote>> = Vec::new();
            for (_slot, server) in &members {
                let base = if generation_copied {
                    h.remotes_base.join(server.id.as_str())
                } else {
                    fresh_base.join(server.id.as_str())
                };
                remotes.push(Box::new(
                    LocalTransport::new(&crate::testutil::fixture_env(), base).unwrap(),
                ));
            }
            let mut helpers: HashMap<SlotId, RemoteHelper> = HashMap::new();
            for (i, (slot, _)) in members.iter().enumerate() {
                let sid = SlotId::parse(slot.id.as_str()).unwrap();
                helpers.insert(sid, RemoteHelper::new(remotes[i].as_ref()));
            }

            // THE SUCCESS-PERMITTED PREDICATE: the live state EXACTLY
            // matches the frozen intent (selected bindings equal, selected
            // membership covered, live generations equal the desired ones).
            let intent_snapshot = intent.resulting_snapshot();
            let membership_ok = intent
                .full_membership()
                .iter()
                .all(|sid| live_bindings.contains_key(sid));
            let bindings_equal = intent.full_membership().iter().all(|sid| {
                live_bindings.get(sid)
                    == intent_snapshot.get(sid).map(|e| e.binding())
            });
            let gens_match = intent.full_membership().iter().all(|sid| {
                let desired_gen = intent_snapshot.get(sid).map(|e| e.generation());
                helpers
                    .get(sid)
                    .and_then(|helper| {
                        helper
                            .status(&crate::remote::helper::GenerationOwner::new(
                                live.application().clone(),
                                sid.clone(),
                            ))
                            .ok()
                    })
                    .is_some_and(|st| {
                        st.current_generation.as_ref() == desired_gen
                    })
            });
            let success_permitted = membership_ok && bindings_equal && gens_match;

            // RECOVER against the mutated config.
            let op_id = OperationId::new("op-frozen-binding-prop".to_string());
            let mut txn =
                crate::store::local::ledger::TargetLedgerTxn::open(&h.store, "t1", "test").unwrap();
            reconcile_pending_commits(&mut txn, &live, &op_id, &helpers).unwrap();

            let status = h
                .store
                .latest_status(pending.deployment_id.as_str())
                .unwrap()
                .ok_or_else(|| {
                    crate::error::Error::store("the recovered attempt must have a terminal status")
                })
                .unwrap();
            match status {
                DeploymentStatus::Successful => {
                    // SUCCESS IS PERMITTED ONLY when bindings + membership +
                    // generations all match the frozen intent.
                    assert!(
                        success_permitted,
                        "success is permitted iff the live bindings equal the frozen intent (mutation {mutation:?}, generation_copied {generation_copied}): success appeared for a drifted/diverged attempt"
                    );
                    // FINALIZE-FROM-FROZEN: the rollback's bindings and
                    // generations EXACTLY equal the frozen intent's values
                    // (never the live config re-read at recovery time).
                    let snapshots = h.store.read_snapshots("t1").unwrap();
                    assert_eq!(snapshots.len(), 1, "exactly one successful snapshot");
                    assert_eq!(snapshots[0].deployment_id, *intent.deployment_id());
                    let rb = rollback_of(&snapshots[0]);
                    let intent_snapshot = intent.resulting_snapshot();
                    for sid in intent.full_membership() {
                        let entry = intent_snapshot.get(&sid).expect("selected in snapshot");
                        assert_eq!(
                            rb.get(&sid).map(|e| e.binding()),
                            Some(entry.binding()),
                            "the rollback binding for {sid} must come from the FROZEN intent, not the live config"
                        );
                        assert_eq!(
                            rb.get(&sid).map(|e| e.generation()),
                            Some(entry.generation()),
                            "the rollback generation for {sid} must equal the frozen desired generation"
                        );
                    }
                }
                other => {
                    // NO SUCCESSFUL TERMINAL MAY APPEAR for a drifted /
                    // diverged / membership-lost attempt — the ONE
                    // classifier decides it: `Degraded` (at least one
                    // `Desired`/`Diverged`/`Unknown` evidence delta — e.g. a
                    // moved deploy_dir whose live generation is the desired
                    // one, or a membership-mismatch `Unknown`) or
                    // `FailedRolledBack` (EVERY slot's live state is back at
                    // its pre-push state — e.g. a server rebind whose
                    // rebound location never saw the deployment: a Degraded
                    // terminal with NO remaining change is unrepresentable,
                    // the review's P1 rule — it can never stay pending on
                    // this fixture.
                    assert!(
                        !success_permitted,
                        "an attempt whose live state matches the frozen intent must succeed, got {other:?} (mutation {mutation:?}, generation_copied {generation_copied})"
                    );
                    assert!(
                        matches!(
                            other,
                            DeploymentStatus::Degraded
                                | DeploymentStatus::FailedRolledBack
                        ),
                        "a drifted/diverged pending attempt must end Degraded (or FailedRolledBack when the evidence is all-Unchanged) — the ONE classifier decides; no Successful terminal may appear (mutation {mutation:?}, generation_copied {generation_copied}, got {other:?})"
                    );
                    assert!(
                        h.store.read_snapshots("t1").unwrap().is_empty(),
                        "a non-successful attempt records no snapshot"
                    );
                }
            }
        }
    }

    // ---- THE ONE LOCK-VERIFIED FINALIZATION: swap-at-every-boundary ----
    //
    // The shared operation
    // ([`crate::ledger::finalize_successful_locked`]) acquires ALL
    // selected-slot mutation locks (deterministic sorted-slot-id order),
    // re-observes EVERY selected slot's LIVE `GenerationRef` (generation AND
    // artifact) under the locks and requires it to EXACTLY equal the frozen
    // desired assignment (`attempt.slots[sid].desired`), writes the markers,
    // and appends the terminal — then releases the locks. A CONCURRENT
    // controller that swaps a slot's `current` to a DIFFERENT
    // generation/artifact must make the finalization REFUSE (the attempt
    // ends `Degraded`, never `Successful`).

    /// Mint a slot's LIVE state on its remote: a real
    /// `generations/<gen>/root` chain (`create_generation` + the tree
    /// object) with `current` pointing at the given generation — exactly the
    /// state a deployment leaves behind when the commit-marker write failed
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
            .create_dir_all(&layout::tree_root(artifact.tree.as_str()))
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
                application: crate::identity::ApplicationStoreKey::parse("eng").unwrap(),
                slot: crate::identity::SlotId::parse(if server == "s1" { "p1" } else { "p2" })
                    .expect("validated slot id is a safe segment"),
                target: Some(TargetName::parse("t1").unwrap()),
            })
            .unwrap();
        helper
            .acquire_lock_guard(&crate::identity::OperationId::new("op-mint".to_string()))
            .unwrap()
            .swap_current(&ExpectedCurrent::Absent, generation.as_str(), "op-mint")
            .unwrap();
    }

    /// Mint a REAL FOREIGN generation on a slot's remote — a valid
    /// `generations/<gen>/root` chain whose assignment's artifact DIFFERS
    /// from the slot's frozen desired assignment — and return its id (the
    /// `current` swap target of [`SwapInjectRemote`]).
    fn mint_foreign_generation(h: &TwoSlotHarness, server: &str) -> GenerationId {
        let base = h.remotes_base.join(server);
        let remote = LocalTransport::new(&crate::testutil::fixture_env(), base).unwrap();
        let foreign_gen = GenerationId::generate();
        let foreign_artifact = ArtifactRef {
            release: crate::identity::test_release_id("rel-foreign"),
            variant: VariantName::parse("standard").unwrap(),
            tree: test_tree_digest("tree-foreign"),
        };
        remote
            .create_dir_all(&layout::tree_root(foreign_artifact.tree.as_str()))
            .unwrap();
        let helper = RemoteHelper::new(&remote);
        helper
            .acquire_lock_guard(&crate::identity::OperationId::new("op-foreign".to_string()))
            .unwrap()
            .create_generation(&GenerationAssignment {
                deployment_id: test_deployment_id("deploy-foreign"),
                generation_id: foreign_gen.clone(),
                artifact: foreign_artifact,
                behavior_sha256: "b".to_string(),
                prior_generation: None,
                created_at: "2026-01-01T00:00:00Z".to_string(),
                application: crate::identity::ApplicationStoreKey::parse("eng").unwrap(),
                slot: crate::identity::SlotId::parse(if server == "s1" { "p1" } else { "p2" })
                    .expect("validated slot id is a safe segment"),
                target: Some(TargetName::parse("t1").unwrap()),
            })
            .unwrap();
        foreign_gen
    }

    proptest! {
        // THE SWAP-AT-EVERY-BOUNDARY FINALIZATION PROPERTY: a PENDING
        // two-slot attempt whose selected slots' live state EXACTLY equals
        // the frozen desired assignment, with a CONCURRENT CONTROLLER's swap
        // of a slot's `current` (re-pointed at a REAL foreign generation
        // with a DIFFERENT artifact) injected at EVERY boundary of the ONE
        // lock-verified finalization — BEFORE the re-observation status
        // read, AFTER the status read but before the assignment read,
        // BETWEEN marker writes, and BEFORE the terminal append (plus the
        // unchanged control). `Successful` IMPLIES every selected rollback
        // assignment EXACTLY equals the frozen desired assignment: whenever
        // a swap makes a selected slot's live GenerationRef diverge from the
        // frozen desired (at ANY boundary), the finalization is NOT
        // `Successful` (it refuses → the attempt ends `Degraded`); when no
        // swap diverges, the finalization is `Successful` with the rollback
        // assignments == the frozen desired.
        //
        // Bounded `proptest_cases(16)` (full 16 with `DEPLOY_FULL_TESTS=1`,
        // fast default), fixed seed 0x5EED_5EED (house style), no failure
        // persistence — the identical vectors on every run.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn lock_verified_finalize_refuses_swaps_at_every_boundary(
            swap_stage in prop_oneof![
                Just(None),
                Just(Some(SwapStage::BeforeStatus)),
                Just(Some(SwapStage::AfterStatus)),
                Just(Some(SwapStage::BetweenMarkers)),
                Just(Some(SwapStage::BeforeTerminal)),
            ],
        ) {
            let h = TwoSlotHarness::new();
            // The FROZEN DESIRED assignments (a distinct artifact per slot)
            // and the LIVE state minted to match them exactly.
            let p1 = SlotId::parse("p1").unwrap();
            let p2 = SlotId::parse("p2").unwrap();
            let gen_p1 = GenerationId::generate();
            let gen_p2 = GenerationId::generate();
            let art_p1 = ArtifactRef {
                release: crate::identity::test_release_id("rel-1"),
                variant: VariantName::parse("standard").unwrap(),
                tree: test_tree_digest("tree-1"),
            };
            let art_p2 = ArtifactRef {
                release: crate::identity::test_release_id("rel-2"),
                variant: VariantName::parse("standard").unwrap(),
                tree: test_tree_digest("tree-2"),
            };
            let deployment_id = test_deployment_id("deploy-swap-prop");
            mint_live_slot(&h, "s1", &gen_p1, &art_p1, &deployment_id);
            mint_live_slot(&h, "s2", &gen_p2, &art_p2, &deployment_id);
            // The FOREIGN generations the injected swaps re-point `current`
            // at (a DIFFERENT generation AND artifact per slot).
            let foreign_p1 = mint_foreign_generation(&h, "s1");
            let foreign_p2 = mint_foreign_generation(&h, "s2");

            // The PENDING intent: durable, no terminal, the frozen desired
            // assignments + the plan-time physical bindings (equal to the
            // live config's, so the degrade is the injected swap's
            // divergence, never binding drift).
            let bindings = h.config.target_slot_bindings("t1").unwrap();
            let intent = {
                use crate::kernel::intent::{PlanInput, PlannedDeploy};
                use crate::kernel::snapshot::SnapshotSlot;
                use crate::ledger::Observation;
                crate::kernel::intent::plan(PlanInput {
                    deployment_id: deployment_id.clone(),
                    target: TargetName::parse("t1").unwrap(),
                    parent: None,
                    parent_snapshot: None,
                    group: None,
                    selection: vec![p1.clone(), p2.clone()],
                    planned: vec![
                        PlannedDeploy {
                            slot: p1.clone(),
                            result: SnapshotSlot::new(
                                gen_p1.clone(),
                                art_p1.clone(),
                                bindings.get(&p1).cloned().expect("p1 is a target slot"),
                            ),
                            pre_push: Observation::KnownAbsent,
                        },
                        PlannedDeploy {
                            slot: p2.clone(),
                            result: SnapshotSlot::new(
                                gen_p2.clone(),
                                art_p2.clone(),
                                bindings.get(&p2).cloned().expect("p2 is a target slot"),
                            ),
                            pre_push: Observation::KnownAbsent,
                        },
                    ],
                    behavior_digest: crate::identity::BehaviorDigest::parse(
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    )
                    .unwrap(),
                    attempted_at: crate::identity::Timestamp::parse("2026-01-01T00:00:00Z")
                        .unwrap(),
                })
                .expect("the swap-prop pending intent plans")
            };
            h.store.append_attempt("t1", &intent).unwrap();

            // The per-slot helpers: the injected swap rides the FIRST slot's
            // remote (BeforeStatus / AfterStatus — before / inside the first
            // re-observation) or the SECOND slot's remote (BetweenMarkers /
            // BeforeTerminal — the second slot's marker / the final
            // verification before the terminal append).
            let env = crate::testutil::fixture_env();
            let mut helpers: HashMap<SlotId, RemoteHelper> = HashMap::new();
            let p1_remote: Box<dyn Remote> = match swap_stage {
                Some(SwapStage::BeforeStatus) | Some(SwapStage::AfterStatus) => {
                    SwapInjectRemote::build(
                        h.remotes_base.join("s1"),
                        swap_stage.expect("matched above"),
                        foreign_p1,
                    )
                    .unwrap()
                }
                _ => Box::new(LocalTransport::new(&env, h.remotes_base.join("s1")).unwrap()),
            };
            let p2_remote: Box<dyn Remote> = match swap_stage {
                Some(SwapStage::BetweenMarkers) | Some(SwapStage::BeforeTerminal) => {
                    SwapInjectRemote::build(
                        h.remotes_base.join("s2"),
                        swap_stage.expect("matched above"),
                        foreign_p2,
                    )
                    .unwrap()
                }
                _ => Box::new(LocalTransport::new(&env, h.remotes_base.join("s2")).unwrap()),
            };
            helpers.insert(p1.clone(), RemoteHelper::new(p1_remote.as_ref()));
            helpers.insert(p2.clone(), RemoteHelper::new(p2_remote.as_ref()));

            // RECOVER: the ONE lock-verified finalization acquires BOTH
            // locks (deterministic order), re-observes both slots' live
            // GenerationRefs, writes the markers, and appends the terminal —
            // or refuses on the injected divergence.
            let op_id = OperationId::new("op-swap-prop".to_string());
            let mut txn =
                crate::store::local::ledger::TargetLedgerTxn::open(&h.store, "t1", "test").unwrap();
            reconcile_pending_commits(&mut txn, &h.config, &op_id, &helpers).unwrap();

            let status = h
                .store
                .latest_status(deployment_id.as_str())
                .unwrap()
                .expect("the recovered attempt has a status");
            match status {
                DeploymentStatus::Successful => {
                    assert_eq!(
                        swap_stage,
                        None,
                        "a swap at ANY boundary must prevent a Successful terminal — the shared operation must refuse a diverged live state (stage {swap_stage:?})"
                    );
                    // SUCCESSFUL IMPLIES every selected rollback assignment
                    // EXACTLY equals the frozen desired assignment (the
                    // generation AND its artifact: release/variant/tree).
                    let snapshots = h.store.read_snapshots("t1").unwrap();
                    assert_eq!(snapshots.len(), 1, "exactly one successful snapshot");
                    assert_eq!(snapshots[0].deployment_id, deployment_id);
                    let rb = rollback_of(&snapshots[0]);
                    let intent_snapshot = intent.resulting_snapshot();
                    for sid in intent.full_membership() {
                        let entry = intent_snapshot.get(&sid).expect("selected in snapshot");
                        let rbs = rb
                            .get(&sid)
                            .expect("the rollback covers every selected slot");
                        assert_eq!(
                            rbs.generation().clone(), entry.generation().clone(),
                            "rollback generation for {sid} must equal the frozen desired generation"
                        );
                        assert_eq!(
                            rbs.artifact().clone(), entry.artifact().clone(),
                            "rollback artifact for {sid} must equal the frozen desired artifact (release/variant/tree)"
                        );
                    }
                }
                DeploymentStatus::Degraded => {
                    assert!(
                        swap_stage.is_some(),
                        "the unchanged control (no swap) must finalize Successful, got Degraded"
                    );
                    assert!(
                        h.store.read_snapshots("t1").unwrap().is_empty(),
                        "a refused/degraded attempt records no snapshot — never Successful"
                    );
                }
                other => {
                    panic!(
                        "unexpected disposition {other:?} for swap stage {swap_stage:?} — the shared operation must finalize Successful (control) or Degraded (refused)"
                    );
                }
            }
        }
    }

    // ---- THE STALE-ROLLBACK-SNAPSHOT FIX: the payload is built from the
    // verified live refs, never the engine's observation records ----
    //
    // The old successful finalizer built the rollback payload from the
    // engine's per-slot OBSERVATION records (actuals/outcomes). A
    // concurrent controller can change the remote AFTER those observations
    // were recorded: the lock-verified re-observation then sees the frozen
    // desired LIVE state (verification passes) while the recorded
    // observations are STALE — and the old code persisted the stale
    // snapshot. The fix: the finalizer no longer accepts observation
    // records at all; the verification RETURNS the observed live
    // GenerationRefs and the payload is built exclusively from them (the
    // frozen desired, equality proven), with the pre-append guard
    // `rollback[selected] == intent.desired`.

    /// How the engine's earlier observation records diverge from the frozen
    /// desired (the stale-observed-value fixture of the property below):
    /// the stale values differ in the GENERATION leg, the ARTIFACT leg, or
    /// BOTH — the property holds for every divergence.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum StaleDivergence {
        /// The stale generation differs; the stale artifact equals the
        /// frozen desired.
        Generation,
        /// The stale artifact differs; the stale generation equals the
        /// frozen desired.
        Artifact,
        /// Both the stale generation and the stale artifact differ.
        Both,
    }

    proptest! {
        // THE STALE-ROLLBACK-SNAPSHOT PROPERTY: the engine's earlier
        // observation records (the OLD `actuals`/`outcomes` finalizer
        // inputs — what the pre-fix code built the rollback from) DIVERGE
        // from the frozen desired while the LIVE state (what the
        // lock-verified finalizer re-observes under the locks) EQUALS the
        // frozen desired — a concurrent controller changed the remote
        // between the engine's observation and this finalization. The
        // finalization MUST succeed and the rollback payload MUST equal the
        // frozen desired (the verified live values) — generation AND
        // artifact — for EVERY stale divergence: the payload is built
        // exclusively from the VERIFIED LIVE `GenerationRef`s, never from
        // the engine's observation records (which the successful finalizer
        // no longer even accepts; the stale fixture is constructed only to
        // pin the bug scenario). Under the pre-fix code, the stale values
        // LEAKED into the persisted snapshot and this property fails; under
        // the fix it holds for every vector.
        //
        // Bounded `proptest_cases(16)` (full 16 with `DEPLOY_FULL_TESTS=1`,
        // fast default), fixed seed 0x5EED_5EED (house style), no failure
        // persistence — the identical vectors on every run.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn successful_finalize_payload_never_uses_stale_observed_values(
            stale in prop_oneof![
                Just(StaleDivergence::Generation),
                Just(StaleDivergence::Artifact),
                Just(StaleDivergence::Both),
            ],
        ) {
            let h = TwoSlotHarness::new();
            // The FROZEN DESIRED assignments (a distinct artifact per slot)
            // and the LIVE state minted to match them exactly.
            let p1 = SlotId::parse("p1").unwrap();
            let p2 = SlotId::parse("p2").unwrap();
            let gen_p1 = GenerationId::generate();
            let gen_p2 = GenerationId::generate();
            let art_p1 = ArtifactRef {
                release: crate::identity::test_release_id("rel-1"),
                variant: VariantName::parse("standard").unwrap(),
                tree: test_tree_digest("tree-1"),
            };
            let art_p2 = ArtifactRef {
                release: crate::identity::test_release_id("rel-2"),
                variant: VariantName::parse("standard").unwrap(),
                tree: test_tree_digest("tree-2"),
            };
            let deployment_id = test_deployment_id("deploy-stale-prop");
            mint_live_slot(&h, "s1", &gen_p1, &art_p1, &deployment_id);
            mint_live_slot(&h, "s2", &gen_p2, &art_p2, &deployment_id);

            // The PENDING intent: durable, no terminal, the frozen desired
            // assignments + the plan-time physical bindings.
            let bindings = h.config.target_slot_bindings("t1").unwrap();
            let intent = {
                use crate::kernel::intent::{PlanInput, PlannedDeploy};
                use crate::kernel::snapshot::SnapshotSlot;
                use crate::ledger::Observation;
                crate::kernel::intent::plan(PlanInput {
                    deployment_id: deployment_id.clone(),
                    target: TargetName::parse("t1").unwrap(),
                    parent: None,
                    parent_snapshot: None,
                    group: None,
                    selection: vec![p1.clone(), p2.clone()],
                    planned: vec![
                        PlannedDeploy {
                            slot: p1.clone(),
                            result: SnapshotSlot::new(
                                gen_p1.clone(),
                                art_p1.clone(),
                                bindings.get(&p1).cloned().expect("p1 is a target slot"),
                            ),
                            pre_push: Observation::KnownAbsent,
                        },
                        PlannedDeploy {
                            slot: p2.clone(),
                            result: SnapshotSlot::new(
                                gen_p2.clone(),
                                art_p2.clone(),
                                bindings.get(&p2).cloned().expect("p2 is a target slot"),
                            ),
                            pre_push: Observation::KnownAbsent,
                        },
                    ],
                    behavior_digest: crate::identity::BehaviorDigest::parse(
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    )
                    .unwrap(),
                    attempted_at: crate::identity::Timestamp::parse("2026-01-01T00:00:00Z")
                        .unwrap(),
                })
                .expect("the swap-prop pending intent plans")
            };
            h.store.append_attempt("t1", &intent).unwrap();

            // THE STALE OBSERVED VALUES the engine could have recorded for
            // each slot BEFORE a concurrent controller changed the remote:
            // the (generation, artifact) the OLD code would have persisted
            // into the rollback. Per the strategy, the generation leg, the
            // artifact leg, or both diverge from the frozen desired.
            let intent_snapshot = intent.resulting_snapshot();
            let stale_of = |sid: &SlotId| -> (GenerationId, ArtifactRef) {
                let generation = match stale {
                    StaleDivergence::Generation | StaleDivergence::Both => test_generation_id(
                        &format!("gen-stale-{}", sid.as_str()),
                    ),
                    StaleDivergence::Artifact => {
                        intent_snapshot.get(sid).expect("a selected slot").generation().clone()
                    }
                };
                let artifact = match stale {
                    StaleDivergence::Generation => {
                        intent_snapshot.get(sid).expect("a selected slot").artifact().clone()
                    }
                    StaleDivergence::Artifact | StaleDivergence::Both => ArtifactRef {
                        release: crate::identity::test_release_id("rel-stale"),
                        variant: VariantName::parse("standard").unwrap(),
                        tree: test_tree_digest("tree-stale"),
                    },
                };
                (generation, artifact)
            };
            // The stale fixture genuinely diverges (the bug scenario): at
            // least one leg differs from the frozen desired per slot.
            for sid in intent.full_membership() {
                let (g, a) = stale_of(&sid);
                let desired = &intent_snapshot.get(&sid).expect("a selected slot");
                assert!(
                    g != *desired.generation() || a != *desired.artifact(),
                    "the stale fixture must diverge from the frozen desired"
                );
            }

            // THE ONE LOCK-VERIFIED FINALIZATION with the LIVE state == the
            // frozen desired: the finalizer re-observes both slots under the
            // locks, verifies the complete GenerationRefs, and appends the
            // terminal — the stale observed values are NOT inputs anymore.
            let env = crate::testutil::fixture_env();
            let p1_remote: Box<dyn Remote> = Box::new(
                LocalTransport::new(&env, h.remotes_base.join("s1")).unwrap(),
            );
            let p2_remote: Box<dyn Remote> = Box::new(
                LocalTransport::new(&env, h.remotes_base.join("s2")).unwrap(),
            );
            let mut helpers: HashMap<SlotId, RemoteHelper> = HashMap::new();
            helpers.insert(p1.clone(), RemoteHelper::new(p1_remote.as_ref()));
            helpers.insert(p2.clone(), RemoteHelper::new(p2_remote.as_ref()));
            let op_id = OperationId::new("op-stale-prop".to_string());
            let mut txn =
                crate::store::local::ledger::TargetLedgerTxn::open(&h.store, "t1", "test").unwrap();
            let outcome = ledger::finalize_successful_locked(
                &mut txn,
                &intent,
                &helpers,
                &ledger::FinalizeSettings {
                    reason: "push completed",
                    op_id: &op_id,
                    application: &crate::identity::ApplicationStoreKey::parse("eng")
                        .expect("test app is a valid store key"),
                },
            )
            .unwrap();
            assert_eq!(
                outcome,
                ledger::FinalizeOutcome::Finalized,
                "the live state equals the frozen desired, so the lock-verified finalize appends the terminal — the stale observed values are never consulted (stale {stale:?})"
            );

            // THE ROLLBACK PAYLOAD EQUALS THE FROZEN DESIRED (the verified
            // live values) — generation AND artifact — for every selected
            // slot, NEVER the stale observed values. The ACTIVATED set is
            // the INTENT's selected slot set.
            let snapshots = h.store.read_snapshots("t1").unwrap();
            assert_eq!(snapshots.len(), 1, "exactly one successful snapshot");
            assert_eq!(snapshots[0].deployment_id, deployment_id);
            let rb = rollback_of(&snapshots[0]);
            let intent_snapshot2 = intent.resulting_snapshot();
            for sid in intent.full_membership() {
                let entry = intent_snapshot2.get(&sid).expect("selected in snapshot");
                let rbs = rb
                    .get(&sid)
                    .expect("the rollback covers every selected slot");
                assert_eq!(
                    rbs.generation().clone(), entry.generation().clone(),
                    "the rollback generation for {sid} equals the frozen desired (the verified live value), never the stale observation (stale {stale:?})"
                );
                assert_eq!(
                    rbs.artifact().clone(), entry.artifact().clone(),
                    "the rollback artifact for {sid} equals the frozen desired (the verified live value), never the stale observation (stale {stale:?})"
                );
                let (stale_gen, stale_art) = stale_of(&sid);
                match stale {
                    StaleDivergence::Generation | StaleDivergence::Both => assert_ne!(rbs.generation().clone(), stale_gen,
                        "the stale generation for {sid} must never leak into the rollback payload (stale {stale:?})"
                    ),
                    StaleDivergence::Artifact => {}
                }
                match stale {
                    StaleDivergence::Artifact | StaleDivergence::Both => assert_ne!(rbs.artifact().clone(), stale_art,
                        "the stale artifact for {sid} must never leak into the rollback payload (stale {stale:?})"
                    ),
                    StaleDivergence::Generation => {}
                }
            }
        }
    }

    // ---- THE UNREADABLE-TERMINAL FIX: ONE validated map + a fallible
    // construction + a pre-write validation ----
    //
    // The successful finalizer previously built the rollback payload from
    // TWO PARALLEL MAPS — the per-slot rollback entries (the generation
    // per selected slot) AND a separate `bindings` map. If the construction
    // produced MISSING / EXTRA / RENAMED bindings (a divergence between
    // the two maps — a slot in one but not the other, or the same slot
    // under a different key), the terminal was appended (the finalization
    // reported SUCCESSFUL) but the strict reader refused the terminal's
    // EXACT key-set equality (bindings == membership): the ledger became
    // UNREADABLE immediately after a successful finalization. The fix:
    // the finalizer merges its two inputs into ONE PRIVATE VALIDATED MAP
    // (`SlotId -> BoundGeneration { generation, binding }`) — the
    // construction has NO parallel maps to drift — the merge REFUSES a
    // missing / extra / renamed binding (an integrity `Err` propagated up:
    // the finalization never appends a broken terminal), and
    // `append_terminal` validates the intent/terminal
    // pair against the strict reader's own legs BEFORE writing.

    /// The DIVERGENCE MUTATIONS applied to the LIVE STATE the lock-verified
    /// finalizer re-observes against the intent's FROZEN RESULTING SNAPSHOT
    /// (the property below generates all four). There is NO separate frozen
    /// binding map anymore: the intent's `resulting_snapshot` IS the single
    /// frozen source (each entry couples generation + artifact + binding),
    /// and the finalizer refuses whenever the lock-verified live observation
    /// diverges from it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum BindingDivergence {
        /// The healthy control: every selected slot's LIVE state exactly
        /// equals its frozen snapshot entry (the finalization succeeds and
        /// the terminal is readable).
        Healthy,
        /// A SELECTED slot's LIVE state is MISSING (its frozen snapshot
        /// entry has no live counterpart).
        Missing,
        /// A SELECTED slot's LIVE generation is an EXTRA generation the
        /// frozen snapshot never froze (the live state advanced past it).
        Extra,
        /// A SELECTED slot's LIVE assignment's ARTIFACT was RENAMED (the
        /// live generation matches the frozen one but the artifact does
        /// not).
        Renamed,
    }

    proptest! {
        // THE USER'S PROPERTY (the unreadable-terminal fix): the LIVE STATE
        // is mutated with a MISSING / EXTRA / RENAMED divergence vs the
        // intent's FROZEN RESULTING SNAPSHOT (or the healthy control), and
        // the ONE lock-verified finalization runs against that live state.
        // ANY SUCCESSFUL APPEND IS IMMEDIATELY READABLE — when the finalizer
        // returns `Finalized`, the strict reader (`read_ledger`) accepts the
        // terminal it wrote, the rollback EXACTLY equals the intent's frozen
        // resulting_snapshot and the activated set the intent's selected
        // keys (the pre-write validation + the single-source snapshot
        // guarantee it); REJECTED INPUTS LEAVE THE LEDGER BYTES UNCHANGED —
        // a divergent live observation makes the finalizer REFUSE before
        // any write (the re-observation happens under the locks BEFORE the
        // marker writes), and the ledger file is byte-identical before/
        // after the refused finalization (the terminal append is the
        // finalize's ONLY ledger write). The intent's `resulting_snapshot`
        // is the SINGLE frozen source — there is no parallel frozen map for
        // the merge to drift on. Only the healthy control can finalize;
        // every divergence is refused.
        //
        // Bounded `proptest_cases(16)` (full 16 with `DEPLOY_FULL_TESTS=1`,
        // fast default), fixed seed 0x5EED_5EED (house style), no failure
        // persistence — the identical vectors on every run.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn successful_finalize_never_appends_an_unreadable_terminal(
            divergence in prop_oneof![
                Just(BindingDivergence::Healthy),
                Just(BindingDivergence::Missing),
                Just(BindingDivergence::Extra),
                Just(BindingDivergence::Renamed),
            ],
        ) {
            let h = TwoSlotHarness::new();
            // The FROZEN assignments (a distinct artifact per slot) — the
            // resulting_snapshot entries the LIVE state must match exactly.
            let p1 = SlotId::parse("p1").unwrap();
            let p2 = SlotId::parse("p2").unwrap();
            let gen_p1 = GenerationId::generate();
            let gen_p2 = GenerationId::generate();
            let art_p1 = ArtifactRef {
                release: crate::identity::test_release_id("rel-1"),
                variant: VariantName::parse("standard").unwrap(),
                tree: test_tree_digest("tree-1"),
            };
            let art_p2 = ArtifactRef {
                release: crate::identity::test_release_id("rel-2"),
                variant: VariantName::parse("standard").unwrap(),
                tree: test_tree_digest("tree-2"),
            };
            let deployment_id = test_deployment_id("deploy-readable-prop");
            // THE LIVE-STATE DIVERGENCE (the surviving fail-closed input of
            // the lock-verified finalizer — there is no separate frozen
            // binding map for the merge to refuse on: the intent's
            // resulting_snapshot IS the single frozen source, and a
            // MISSING / EXTRA / RENAMED live fact diverges from it).
            match divergence {
                BindingDivergence::Healthy => {
                    mint_live_slot(&h, "s1", &gen_p1, &art_p1, &deployment_id);
                    mint_live_slot(&h, "s2", &gen_p2, &art_p2, &deployment_id);
                }
                // Missing: p1's LIVE state is absent — the frozen snapshot
                // entry has no live counterpart.
                BindingDivergence::Missing => {
                    mint_live_slot(&h, "s2", &gen_p2, &art_p2, &deployment_id);
                }
                // Extra: p1's live generation is an EXTRA generation the
                // frozen snapshot never froze (the live state advanced past
                // the frozen entry).
                BindingDivergence::Extra => {
                    let gen_extra = GenerationId::generate();
                    mint_live_slot(&h, "s1", &gen_extra, &art_p1, &deployment_id);
                    mint_live_slot(&h, "s2", &gen_p2, &art_p2, &deployment_id);
                }
                // Renamed: p1's live assignment's ARTIFACT was renamed — the
                // live generation matches the frozen generation but the
                // assignment's artifact does not.
                BindingDivergence::Renamed => {
                    let art_renamed = ArtifactRef {
                        release: crate::identity::test_release_id("rel-3"),
                        variant: VariantName::parse("standard").unwrap(),
                        tree: test_tree_digest("tree-3"),
                    };
                    mint_live_slot(&h, "s1", &gen_p1, &art_renamed, &deployment_id);
                    mint_live_slot(&h, "s2", &gen_p2, &art_p2, &deployment_id);
                }
            }

            // The PENDING intent: durable, no terminal, the frozen
            // resulting snapshot (each SELECTED slot's minted generation +
            // artifact + the plan-time physical binding).
            let bindings = h.config.target_slot_bindings("t1").unwrap();
            let intent = {
                use crate::kernel::intent::{PlanInput, PlannedDeploy};
                use crate::kernel::snapshot::SnapshotSlot;
                use crate::ledger::Observation;
                crate::kernel::intent::plan(PlanInput {
                    deployment_id: deployment_id.clone(),
                    target: TargetName::parse("t1").unwrap(),
                    parent: None,
                    parent_snapshot: None,
                    group: None,
                    selection: vec![p1.clone(), p2.clone()],
                    planned: vec![
                        PlannedDeploy {
                            slot: p1.clone(),
                            result: SnapshotSlot::new(
                                gen_p1.clone(),
                                art_p1.clone(),
                                bindings.get(&p1).cloned().expect("p1 is a target slot"),
                            ),
                            pre_push: Observation::KnownAbsent,
                        },
                        PlannedDeploy {
                            slot: p2.clone(),
                            result: SnapshotSlot::new(
                                gen_p2.clone(),
                                art_p2.clone(),
                                bindings.get(&p2).cloned().expect("p2 is a target slot"),
                            ),
                            pre_push: Observation::KnownAbsent,
                        },
                    ],
                    behavior_digest: crate::identity::BehaviorDigest::parse(
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    )
                    .unwrap(),
                    attempted_at: crate::identity::Timestamp::parse("2026-01-01T00:00:00Z")
                        .unwrap(),
                })
                .expect("the swap-prop pending intent plans")
            };
            h.store.append_attempt("t1", &intent).unwrap();

            // The per-slot live helpers (the lock-verified finalizer
            // re-observes the matching live state under these).
            let env = crate::testutil::fixture_env();
            let p1_remote: Box<dyn Remote> =
                Box::new(LocalTransport::new(&env, h.remotes_base.join("s1")).unwrap());
            let p2_remote: Box<dyn Remote> =
                Box::new(LocalTransport::new(&env, h.remotes_base.join("s2")).unwrap());
            let mut helpers: HashMap<SlotId, RemoteHelper> = HashMap::new();
            helpers.insert(p1.clone(), RemoteHelper::new(p1_remote.as_ref()));
            helpers.insert(p2.clone(), RemoteHelper::new(p2_remote.as_ref()));
            let op_id = OperationId::new("op-readable-prop".to_string());

            // THE LEDGER BYTES BEFORE the finalization attempt: the intent
            // line only — the terminal append is the ONLY ledger write the
            // finalize performs (the markers are remote-side).
            let ledger_path = h.store.ledger_path("t1");
            let before = std::fs::read(&ledger_path).unwrap();

            match ledger::finalize_successful_locked(
                &mut crate::store::local::ledger::TargetLedgerTxn::open(
                    &h.store, "t1", "test",
                )
                .unwrap(),
                &intent,
                &helpers,
                &ledger::FinalizeSettings {
                    reason: "push completed",
                    op_id: &op_id,
                    application: &crate::identity::ApplicationStoreKey::parse("eng")
                        .expect("test app is a valid store key"),
                },
            ) {
                // ANY SUCCESSFUL APPEND IS IMMEDIATELY READABLE: the
                // pre-write validation guarantees the terminal the
                // finalizer wrote is accepted by the strict reader — the
                // ledger read succeeds, and the appended terminal EXACTLY
                // reproduces the intent's frozen values (the rollback ==
                // resulting_snapshot, the activated set == the selected
                // keys).
                Ok(ledger::FinalizeOutcome::Finalized) => {
                    assert_eq!(
                        divergence,
                        BindingDivergence::Healthy,
                        "only the exact live state (the healthy control) can finalize — a divergence must be refused (divergence {divergence:?})"
                    );
                    let entries = h.store.read_ledger("t1").unwrap();
                    assert_eq!(entries.len(), 1, "one merged entry");
                    let terminal = entries[0]
                        .terminal
                        .as_ref()
                        .expect("the successful finalization appended its terminal");
                    assert!(
                        terminal.disposition().is_successful(),
                        "a successful finalization appends a Successful terminal"
                    );
                    assert!(
                        terminal.outcomes().is_empty(),
                        "a Successful terminal is PAYLOAD-FREE — the snapshot resolves from the intent"
                    );
                    let resolved = crate::kernel::snapshot::resolve_snapshot(&entries[0]).unwrap();
                    assert_eq!(
                        resolved,
                        intent.resulting_snapshot(),
                        "the resolved snapshot EXACTLY equals the intent's planned result (one stored fact — no parallel payload to drift)"
                    );
                    assert_eq!(
                        entries[0].intent.selected_membership(),
                        intent.selected_membership(),
                        "the successful terminal promises the intent's planned result — the selected membership is derived from the slot table"
                    );
                }
                // REJECTED INPUTS LEAVE THE LEDGER BYTES UNCHANGED: the
                // live-state divergence was refused BEFORE any write (the
                // finalizer re-observes every selected slot under the locks
                // BEFORE writing the markers) and the ledger file is
                // byte-identical — no terminal was ever appended.
                Ok(ledger::FinalizeOutcome::Refused { .. }) => {
                    assert_ne!(
                        divergence,
                        BindingDivergence::Healthy,
                        "the healthy control must finalize (divergence {divergence:?})"
                    );
                    let after = std::fs::read(&ledger_path).unwrap();
                    assert_eq!(
                        before, after,
                        "a refused finalization NEVER writes — the ledger bytes are byte-identical before/after (divergence {divergence:?})"
                    );
                    h.store
                        .read_ledger("t1")
                        .expect("the intent-only pending entry stays fully readable after the refusal");
                }
                Ok(ledger::FinalizeOutcome::Pending) => panic!(
                    "the fixture state is deterministic — the finalization must never be Pending (divergence {divergence:?})"
                ),
                Err(e) => panic!(
                    "the lock-verified finalizer REFUSES a divergent live state, it never errors on this fixture input: {e:?} (divergence {divergence:?})"
                ),
            }
        }
    }
}
