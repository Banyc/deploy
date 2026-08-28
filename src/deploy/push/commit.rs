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
use crate::error::Result;
use crate::identity::SlotId;
use crate::ledger;
use crate::ledger::DeploymentIntent;
use crate::ledger::DeploymentStatus;
use crate::ledger::LedgerIntentReport;
use crate::ledger::LedgerTerminal;
use crate::ledger::SlotOutcome;
use crate::ledger::SlotResult;
use crate::ledger::SlotTable;
use crate::remote::helper::RemoteHelper;
use std::collections::BTreeMap;

// POST-MUTATION phases of the push transaction (steps 16-17): the terminal
// event finalization (the `Successful` / `Degraded` / `FailedRolledBack`
// status decision — [`disposition_for`] — plus the
// shared successful finalizer [`crate::ledger::finalize_successful_attempt`]),
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
pub(crate) fn run_commit(
    ctx: &PushContext,
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
    // are appended as the deployment's TERMINAL EVENT (the ledger's
    // `{"kind":"terminal"}` line) — the outcomes store the rollback state is
    // built from. The REPORT's attempt ([`LedgerIntentReport`]) also carries
    // the actuals (for display); the persisted intent does not — outcomes are
    // never part of the verified intent object.
    let mut attempt = LedgerIntentReport::from_intent(attempt_intent)?;
    attempt.slots = execution.actual_servers.clone();
    let outcomes_map: BTreeMap<SlotId, SlotResult> = execution.results.clone();

    // Finalize the attempt's terminal event. A SUCCESSFUL attempt goes
    // through the SAME shared finalizer as recovery
    // ([`ledger::finalize_successful_attempt`]): ONE atomic terminal append
    // carrying the `Successful` status, the per-slot outcomes, and the
    // ROLLBACK STATE (built from the actual per-slot OUTCOMES
    // (`actual_servers`), never from the intent record). A non-successful
    // final status (`Degraded` / `FailedRolledBack`) is a plain terminal
    // append carrying the status and outcomes, no rollback. A demoted
    // `PendingCommit` status (the commit markers are not all durable) is NOT
    // terminal at all: the entry stays intent-only — the recoverable pending
    // state a later push reconciles before its own no-op check.
    let mut message = format!("push status: {:?}", execution.commit_status);
    if execution.commit_status == DeploymentStatus::Successful {
        // The rollback state records each slot's COMPLETE physical binding
        // (`{server, deploy_dir}`) so an exact rollback can verify a slot
        // still lives at the exact on-host location it was deployed onto (a
        // rebound slot OR a slot whose deploy_dir moved must refuse rather
        // than deploy to the wrong host/location). The binding comes from
        // the CURRENT configuration: it is the live placement this attempt
        // actually used.
        let slot_bindings = config.target_slot_bindings(target_name)?;
        // The terminal's FULL MEMBERSHIP is the INTENT'S FROZEN value — the
        // finalizer reads `attempt.full_membership()` (the complete target
        // membership resolved AT PLAN TIME, when the immutable intent was
        // written), never recomputed from the current configuration. The
        // rollback is the COMPLETE resulting target state (the base-overlay
        // semantics): the SELECTED slots' actuals overlaid on the latest
        // successful base, unselected slots carried forward — so the
        // rollback's slots are the frozen FULL membership, never just the
        // selected slots. The terminal PERSISTS both memberships (selected =
        // the outcome keys, full = the frozen value) and the read path
        // enforces the equations: outcomes == selected, rollback == full,
        // selected ⊆ full, the INTENT-BINDING legs (the terminal must
        // REPRODUCE the intent's frozen selected/full), and — for a FULL
        // push (no group, distinguished by the intent's `group`) — selected
        // == full.
        ledger::finalize_successful_attempt(
            store,
            attempt_intent,
            &outcomes_map,
            &execution.actual_servers,
            "push completed",
            &slot_bindings,
        )?;
        // The new successful deployment is keyed by its deployment id (the
        // public grammar is deployment-keyed — successful positions are
        // derived internally, never exposed as sN).
        message = format!(
            "push successful; rollback payload keyed by deployment {deployment_id} of target {target_name}"
        );
    } else if execution.commit_status != DeploymentStatus::PendingCommit {
        // A demoted `PendingCommit` status is NOT terminal: the entry stays
        // intent-only (the recoverable pending state a later push reconciles
        // before its own no-op check) — appending a PendingCommit terminal
        // would strand the attempt forever (reconciliation only picks up
        // entries WITHOUT a terminal).
        // The wire outcomes are converted to the DOMAIN outcomes, deriving
        // each slot's TRANSITION STATE from the wire's status/outcome fields
        // and DROPPING the wire outcome's redundant `slot_id` into the key
        // (the domain value carries no slot — the table key owns identity);
        // the STATUS → DISPOSITION mapping lives in
        // [`crate::deploy::rollout::disposition_for`] (the structural domain
        // truth table: FailedPreflight carries nothing, FailedRolledBack owns
        // the outcomes as its compensation report, Degraded owns the outcomes
        // its remaining changes are derived from — and refuses an
        // all-restored Degraded wire).
        // WIRE → DOMAIN (fail closed): each wire outcome converts through
        // [`SlotOutcome::from_wire`] — deriving the per-slot TRANSITION
        // STATE and converting the strict wire observation to the domain
        // observation — and the redundant `slot_id` is DROPPED into the key.
        let outcomes: SlotTable<SlotOutcome> = SlotTable::from_map(
            outcomes_map
                .into_iter()
                .map(|(key, result)| Ok((key, SlotOutcome::from_wire(result)?)))
                .collect::<Result<BTreeMap<SlotId, SlotOutcome>>>()?,
        );
        let disposition =
            crate::deploy::rollout::disposition_for(&execution.commit_status, outcomes)?;
        store.append_terminal(
            target_name,
            deployment_id,
            &LedgerTerminal {
                recorded_at: crate::remote::helper::now_rfc3339(),
                disposition,
                reason: execution.commit_reason.map(str::to_string),
            },
        )?;
    }

    let (_observed, observed_warnings) = crate::deploy::maintenance::refresh_observed_from_live(
        store,
        target_name,
        members,
        helpers,
    );

    let mut maintenance: Vec<String> = Vec::new();
    // Observed-refresh deferrals (post-commit projection lag) ride the same
    // warning channel as retention; unlike retention there is no debt marker to
    // retry — the next real push re-projects from durable facts.
    maintenance.extend(observed_warnings);
    // Retry any debt left by earlier pushes FIRST (before this push's own
    // retention), so a marker that succeeds here is cleared without re-rotating
    // the same slot immediately after a fresh step-17 failure. The retry is
    // NON-FALLIBLE (post-commit maintenance): every debt read/write failure is
    // a warning entry in the returned vec, never an `Err` — a debt-file fault
    // must not change the outcome of a deployment that already committed.
    maintenance.extend(crate::deploy::maintenance::retry_deferred_retentions(
        store,
        config,
        target_name,
        helpers,
        op_id,
        deployment_id,
    ));
    // The store-global PENDING SWEEP (deferred by an earlier checkpoint
    // whose sweep did not complete) is likewise POST-COMMIT MAINTENANCE:
    // retry it on this push — recomputing reachability fresh, no persisted
    // worklist — and clear the marker once it completes. NON-FALLIBLE: every
    // debt read/write failure is a warning entry in the returned vec, never
    // an `Err` — a debt-file fault must not change the outcome of a
    // deployment that already committed.
    maintenance.extend(crate::deploy::maintenance::retry_pending_sweep(
        store,
        config,
        deployment_id.as_str(),
    ));
    // Step 17: per-slot retention — post-commit maintenance, never a push
    // failure (the contract is structural in
    // [`crate::deploy::maintenance::retain_slot_post_commit`]).
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
        status: Some(execution.commit_status.clone()),
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
    use crate::identity::test_deployment_id;
    use crate::ledger::SlotOutcomeKind;
    use crate::remote::helper::{GenerationAssignment, RemoteHelper};
    use crate::remote::transport::LocalTransport;
    use crate::testutil::test_remotes::FailOnceMarkerRemote;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

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
            DeploymentStatus::PendingCommit,
            "the intent-only entry stays recoverable-pending"
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
            DeploymentStatus::PendingCommit,
            "crash window must leave the attempt PendingCommit, not Successful"
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
    // finalizer as recovery (`ledger::finalize_successful_attempt`):
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
        assert_eq!(r2.status, Some(DeploymentStatus::PendingCommit));
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
            DeploymentStatus::Degraded,
            "a conflicting marker must NEVER finalize the attempt Successful"
        );
        let transitions = h.store.read_transitions(dep2.as_str()).unwrap();
        let last = transitions.last().expect("transition stream non-empty");
        assert_eq!(
            last.reason.as_deref(),
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
                .status()
                .unwrap()
                .current_generation
                .as_ref()
                .map(|g| g.as_str()),
            Some(gen_v2.as_str()),
            "the conflict must not disturb the live deployment"
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
            intent.intent.slots.contains_key(&SlotId::new("p1")),
            "the intent's one slot table carries the planned (desired) + observed (pre_push) entries"
        );
        assert!(
            h.store.read_results(id.as_str()).is_err(),
            "no results.json"
        );
        assert_eq!(
            latest_status(&h, id.as_str()),
            DeploymentStatus::PendingCommit,
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
        let g = &rollback_of(&snap[0]).slots[&SlotId::new("p1")];
        let desired = &intent.desired[&SlotId::new("p1")];
        assert_eq!(
            g.generation.as_str(),
            desired.generation.as_str(),
            "snapshot generation comes from the verified desired state"
        );
        assert_eq!(g.assignment.artifact.tree, desired.assignment.artifact.tree);
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
            DeploymentStatus::PendingCommit,
            "crash window must leave the attempt PendingCommit (intent-only), never Successful"
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
        assert_eq!(latest_status(&h, id.as_str()), DeploymentStatus::Successful);
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
        // and the remote's current points elsewhere.
        let target_a = GenerationId::generate();
        let id_a = test_deployment_id("deploy-inprogress-diverged");
        let desired_ref = baseline.desired[&SlotId::new("p1")].clone();

        let intent = DeploymentIntent {
            deployment_id: id_a.clone(),
            target: TargetName::new("t1".to_string()),
            group: None,
            behavior_sha256: baseline.behavior_sha256.as_str().to_string(),
            attempted_at: crate::remote::helper::now_rfc3339(),
            slots: NonEmptySlotTable::build(BTreeMap::from([(
                SlotId::new("p1".to_string()),
                IntentSlot {
                    desired: DesiredGeneration {
                        generation: target_a,
                        artifact: desired_ref.assignment.artifact.clone(),
                    },
                    pre_push: None,
                },
            )]))
            .expect("one member slot"),
            full_membership: BTreeSet::from([SlotId::new("p1".to_string())]),
        };
        h.store.append_attempt("t1", &intent).unwrap();
        assert_eq!(
            latest_status(&h, id_a.as_str()),
            DeploymentStatus::PendingCommit,
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
            DeploymentStatus::Degraded,
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
        // absent status file as eligible (a just-recorded attempt).
        let id_a = test_deployment_id("deploy-no-status");
        let desired_ref = baseline.desired[&SlotId::new("p1")].clone();

        let intent = DeploymentIntent {
            slots: NonEmptySlotTable::build(BTreeMap::from([(
                SlotId::new("p1".to_string()),
                IntentSlot {
                    desired: DesiredGeneration {
                        generation: desired_ref.generation.clone(),
                        artifact: desired_ref.assignment.artifact.clone(),
                    },
                    pre_push: None,
                },
            )]))
            .expect("one member slot"),
            deployment_id: id_a.clone(),
            target: TargetName::new("t1".to_string()),
            group: None,
            behavior_sha256: baseline.behavior_sha256.as_str().to_string(),
            attempted_at: crate::remote::helper::now_rfc3339(),
            full_membership: BTreeSet::from([SlotId::new("p1".to_string())]),
        };
        h.store.append_attempt("t1", &intent).unwrap();
        assert_eq!(
            h.store.latest_status(id_a.as_str()).unwrap(),
            Some(DeploymentStatus::PendingCommit),
            "an intent-only entry is the recoverable pending state"
        );

        // The next push reconciles the transition-less attempt (the remote is
        // already at its desired generation) and finalizes it Successful.
        let r2 = push_clean(&h).unwrap();
        assert_eq!(r2.status, None, "reconciling push is an up-to-date no-op");
        assert_eq!(r2.message, "Everything up to date");
        assert_eq!(
            latest_status(&h, id_a.as_str()),
            DeploymentStatus::Successful
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

    /// Multiple pending attempts are reconciled OLDEST FIRST (attempts.jsonl
    /// order) so snapshot/op-log indices stay monotonic: two crafted
    /// `InProgress` intents appended A-then-B finalize in that order with
    /// indices 1 and 2 after the baseline.
    #[test]
    fn reconcile_multiple_pending_oldest_first_with_monotonic_indices() {
        let h = RecoveryHarness::new();
        let id_b = test_deployment_id("deploy-multi-baseline");
        let r1 = push_main_with_id(&h, &id_b).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let baseline = r1.attempt.as_ref().expect("attempt recorded");
        let desired_ref = baseline.desired[&SlotId::new("p1")].clone();

        let mk = |id: &str| DeploymentIntent {
            deployment_id: test_deployment_id(id),
            target: TargetName::new("t1".to_string()),
            group: None,
            behavior_sha256: baseline.behavior_sha256.as_str().to_string(),
            attempted_at: crate::remote::helper::now_rfc3339(),
            slots: NonEmptySlotTable::build(BTreeMap::from([(
                SlotId::new("p1".to_string()),
                IntentSlot {
                    desired: DesiredGeneration {
                        generation: desired_ref.generation.clone(),
                        artifact: desired_ref.assignment.artifact.clone(),
                    },
                    pre_push: None,
                },
            )]))
            .expect("one member slot"),
            full_membership: BTreeSet::from([SlotId::new("p1".to_string())]),
        };
        let a = mk("deploy-multi-a");
        let b = mk("deploy-multi-b");
        // Two intent-only entries: eligible for reconciliation, oldest first.
        h.store.append_attempt("t1", &a).unwrap();
        h.store.append_attempt("t1", &b).unwrap();

        // One push reconciles BOTH, oldest first.
        let r2 = push_clean(&h).unwrap();
        assert_eq!(r2.message, "Everything up to date");
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 3);
        assert_eq!(snapshots[1].deployment_id, a.deployment_id);
        assert_eq!(snapshots[2].deployment_id, b.deployment_id);
        assert_eq!(
            ledger::successful_index(&h.store, "t1", &a.deployment_id)
                .unwrap()
                .unwrap(),
            1,
            "successful-chain positions stay monotonic"
        );
        assert_eq!(
            ledger::successful_index(&h.store, "t1", &b.deployment_id)
                .unwrap()
                .unwrap(),
            2
        );
        assert_eq!(
            latest_status(&h, a.deployment_id.as_str()),
            DeploymentStatus::Successful
        );
        assert_eq!(
            latest_status(&h, b.deployment_id.as_str()),
            DeploymentStatus::Successful
        );
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(b.deployment_id.as_str())
        );
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 3);
        for id in [a.deployment_id.as_str(), b.deployment_id.as_str()] {
            let marker = h
                .remotes_base
                .join("s1")
                .join(crate::remote::layout::commit_marker(id));
            assert!(marker.exists(), "marker present for {id}");
        }
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
        let slot_a = SlotId::new("p1".to_string());
        let slot_b = SlotId::new("p2".to_string());

        // Push 1: FULL Head push under contract A (argv ["true", "a"]) —
        // release R1 for BOTH slots; snapshot S0: p1=R1, p2=R1.
        let id1 = test_deployment_id("deploy-mr-baseline");
        let r1 = two_slot_push(&h, &h.config, &RefExpr::Head, None, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let var_a = h.config.variant("standard").unwrap();
        let digest_a = crate::verify::release::behavior_contract_digest(&BehaviorContract {
            activation: crate::config::ActivationConfig::from(var_a.activation.clone()),
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
            activation: crate::config::ActivationConfig::from(var_b.activation.clone()),
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
            s1.slots.len(),
            2,
            "the group push's rollback is the COMPLETE resulting snapshot — the unselected slot is carried forward from the base"
        );
        assert_eq!(
            s1.slots[&slot_a].assignment.artifact.release, r1_release,
            "the unselected slot is carried forward at its base release (R1)"
        );
        assert_eq!(
            s1.slots[&slot_b].assignment.artifact.release, r2_release,
            "the group push's rollback records its selected slot's own release (R2)"
        );
        assert_eq!(
            s1.bindings.len(),
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
            plan.behaviors.len(),
            1,
            "one frozen behavior block per referenced release"
        );
        assert_eq!(
            crate::verify::release::behavior_contract_digest(
                &plan.behaviors[&r1_release]["standard"]
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
            let status = helper.status().unwrap();
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
            let h = TwoSlotHarness::new();
            let slot_a = SlotId::new("p1".to_string());
            let slot_b = SlotId::new("p2".to_string());
            let full_membership: BTreeSet<SlotId> =
                BTreeSet::from([slot_a.clone(), slot_b.clone()]);

            // Push 0: FULL baseline — both slots under release R0.
            let id0 = test_deployment_id("deploy-prop-base");
            let r0 = two_slot_push(&h, &h.config, &RefExpr::Head, None, &id0).unwrap();
            assert_eq!(r0.status, Some(DeploymentStatus::Successful));
            let snapshots = h.store.read_snapshots("t1").unwrap();
            assert_eq!(snapshots.len(), 1, "the full baseline is the first snapshot");
            assert_eq!(
                rollback_of(&snapshots[0])
                    .slots
                    .keys()
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
                    last.slots.keys().cloned().collect::<BTreeSet<_>>(),
                    full_membership,
                    "group push {i} ({group}) must record the complete membership in its snapshot (the unselected slot is carried forward)"
                );
                assert_eq!(
                    last.bindings.keys().cloned().collect::<BTreeSet<_>>(),
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
        let slot_a = SlotId::new("p1".to_string());
        let slot_b = SlotId::new("p2".to_string());
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
            last.slots.keys().cloned().collect::<BTreeSet<_>>(),
            full_membership,
            "the group push's snapshot has the full membership"
        );
        assert_eq!(
            last.slots[&slot_a].assignment.artifact.release, r2_release,
            "the selected slot records its own release"
        );
        assert_eq!(
            last.slots[&slot_b].assignment.artifact.release, r1_release,
            "the unselected slot is carried forward at its base release"
        );
        assert_eq!(
            last.bindings.keys().cloned().collect::<BTreeSet<_>>(),
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
        assert_eq!(
            terminal.outcomes().keys().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from([slot_a.clone()]),
            "the outcomes cover the selected group slot only"
        );
        assert_eq!(
            terminal.selected_membership(),
            Some(&BTreeSet::from([slot_a.clone()])),
            "the terminal PERSISTS the selected membership (== the outcomes' keys == the group's slot)"
        );
        assert_eq!(
            terminal.full_membership(),
            Some(&full_membership),
            "the terminal PERSISTS the full membership (== the complete target membership == the rollback's slots)"
        );
        assert_eq!(
            terminal.outcomes()[&slot_a].outcome,
            SlotOutcomeKind::Activated
        );
    }

    /// DETERMINISTIC: REPEATING THE SAME GROUP REMAINS VALID — a group push
    /// whose group was already pushed succeeds (the conversion accepts its
    /// complete-snapshot rollback), and each repeat still records the full
    /// membership.
    #[test]
    fn repeating_the_same_group_succeeds() {
        let h = TwoSlotHarness::new();
        let slot_a = SlotId::new("p1".to_string());
        let slot_b = SlotId::new("p2".to_string());
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
                last.slots.keys().cloned().collect::<BTreeSet<_>>(),
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
        let slot_a = SlotId::new("p1".to_string());
        let slot_b = SlotId::new("p2".to_string());
        let full_membership: BTreeSet<SlotId> = BTreeSet::from([slot_a.clone(), slot_b.clone()]);

        let id1 = test_deployment_id("deploy-strict-base");
        let r1 = two_slot_push(&h, &h.config, &RefExpr::Head, None, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let entries = h.store.read_ledger("t1").unwrap();
        let entry = &entries[0];
        assert_eq!(
            entry.intent.slots.keys().cloned().collect::<BTreeSet<_>>(),
            full_membership,
            "the full push's intent membership is the full target"
        );
        let terminal = entry.terminal.as_ref().unwrap();
        assert_eq!(
            terminal.outcomes().keys().cloned().collect::<BTreeSet<_>>(),
            full_membership,
            "the full push's outcomes equal the membership"
        );
        assert_eq!(
            terminal.selected_membership(),
            Some(&full_membership),
            "the terminal PERSISTS the selected membership == the full membership (a full push selects every target slot)"
        );
        assert_eq!(
            terminal.full_membership(),
            Some(&full_membership),
            "the terminal PERSISTS the full membership == the complete target membership"
        );
        let TerminalDisposition::Successful { rollback, .. } = &terminal.disposition else {
            panic!("the full push is Successful");
        };
        assert_eq!(
            rollback.slots.keys().cloned().collect::<BTreeSet<_>>(),
            full_membership,
            "the full push's rollback slots equal the membership"
        );
        assert_eq!(
            rollback.bindings.keys().cloned().collect::<BTreeSet<_>>(),
            full_membership,
            "the full push's rollback bindings equal the membership"
        );
    }
}
