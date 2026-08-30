//! The MUTATION phases of the push transaction (steps 10-15): the
//! deployment-order batch loop, the failure-policy compensation +
//! attempt-status derivation, the commit-marker / status decision, and the
//! post-mutation ACTUAL observation. [`run_execution`] is the single
//! coordinator and returns the [`ExecutionOutcome`] the commit phases
//! consume.

use crate::config::SlotConfig;
use crate::deploy::push::PreflightOutcome;
use crate::deploy::push::PushContext;
use crate::deploy::rollout::BatchRun;
use crate::deploy::rollout::SlotExecution;
use crate::error::Result;
use crate::identity::SlotId;
use crate::ledger::ActualSlotState;
use crate::ledger::Observation;
use crate::ledger::ObservedGeneration;
use crate::ledger::SlotOutcome;
use crate::remote::helper::RemoteHelper;
use crate::remote::transport::Remote;
use std::collections::BTreeMap;
use std::collections::HashMap;

// MUTATION phases of the push transaction (steps 10-15): the deployment-order
// batch loop, the failure-policy compensation + attempt-status derivation,
// the commit-marker / status decision, and the post-mutation ACTUAL
// observation. [`run_execution`] is the single coordinator and returns the
// [`ExecutionOutcome`] the commit phases consume.
// Everything here runs AFTER the intent was persisted (preflight) and BEFORE
// the terminal event is finalized; the never-started slots' post-mutation
// OBSERVATION is attached when the terminal inputs are derived below.

/// The outcome of the mutation phases: the gathered EVIDENCE only — the
/// engine never decides the status (the kernel's
/// [`crate::kernel::transition::decide_terminal`] owns the complete truth
/// table). The successful path's verification evidence is gathered by the
/// shared lock-verified finalizer at commit time. The per-slot execution
/// STATE lives in ONE ordered table ([`SlotExecution`] — the review's P2
/// fix: a slot is exactly one of six mutually exclusive states, never a
/// combination of booleans/lists that could disagree); every summary
/// (`had_failure`, the failed outcomes, the display actuals) is DERIVED
/// from it.
pub(crate) struct ExecutionOutcome {
    /// The ONE per-slot execution table (every SELECTED slot).
    pub executions: BTreeMap<SlotId, SlotExecution>,
    /// The post-mutation OBSERVATION of each slot's live state (read from
    /// the remote generation it currently points at — never the desired
    /// plan values): the evidence the terminal decision's per-slot
    /// classification compares against pre_push. Attached to the
    /// observation-less executions ([`SlotExecution::NotStarted`] /
    /// `FailedBeforeAdvance` / `Indeterminate`) when the terminal outcomes
    /// are derived — the old `record_never_advanced_outcomes` wire-row
    /// fix-up moved here.
    pub(crate) actual_observations: BTreeMap<SlotId, Observation<ObservedGeneration>>,
    /// The per-slot ACTUAL final state (read from the live remote
    /// generation) — the structural [`ActualSlotState`] per member slot
    /// (a desired artifact NEVER rides an actual).
    pub(crate) actual_servers: BTreeMap<SlotId, ActualSlotState>,
    /// The deployment-order slot list (step 17's per-slot retention runs in
    /// the same order).
    pub(crate) servers_order: Vec<SlotId>,
}

impl ExecutionOutcome {
    /// Whether any slot FAILED during the mutation loop — DERIVED from the
    /// execution table (a pre-advance failure, a post-advance failure, or
    /// an indeterminate outcome). An `Advanced` slot whose bookkeeping
    /// record write failed is NOT a failure (the demotion signal lives in
    /// the execution's `bookkeeping_error`).
    pub(crate) fn had_failure(&self) -> bool {
        self.executions.iter().any(|(_, e)| e.is_failure())
    }

    /// THE FAILED TERMINAL INPUTS: the executions → the STRUCTURAL DOMAIN
    /// outcomes ([`SlotOutcome`]) the kernel's decision consumes, with the
    /// post-mutation OBSERVATION attached per state — PLUS the
    /// ADAPTER-RESTORATION EVIDENCE (the review's P1 fix): the slots whose
    /// adapter side effects were VERIFIED restored, carrying the sealed
    /// proof extracted from the `Restored` executions. The kernel refuses a
    /// rolled-back classification for a `Restored` outcome without this
    /// evidence.
    ///
    /// * `Advanced` / `Restored` / `FailedAfterAdvance` carry their RECORDED
    ///   swap-result observation (the deployment's generation / the restored
    ///   generation / the advanced generation);
    /// * `NotStarted` / `FailedBeforeAdvance` / `Indeterminate` carry the
    ///   LIVE post-mutation observation (the never-advanced rule — the
    ///   actual observed post-state, never the desired generation; a failed
    ///   read is `Unknown`, never read as "unchanged").
    pub(crate) fn failure_evidence(&self) -> Result<FailureEvidence> {
        let live = |sid: &SlotId| {
            self.actual_observations
                .get(sid)
                .cloned()
                .unwrap_or(Observation::KnownAbsent)
        };
        let mut outcomes = BTreeMap::new();
        let mut adapter_restored = BTreeMap::new();
        for (sid, e) in self.executions.iter() {
            let outcome = match e {
                SlotExecution::NotStarted => SlotOutcome::Skipped {
                    observation: live(sid),
                },
                SlotExecution::FailedBeforeAdvance { .. } => SlotOutcome::FailedBeforeAdvance {
                    observation: live(sid),
                    error: e.failed_error().map(str::to_string),
                },
                SlotExecution::Advanced { observation, .. } => SlotOutcome::Activated {
                    observation: observation.clone(),
                },
                SlotExecution::Restored {
                    observation,
                    adapter_restored: proof,
                } => {
                    // The sealed proof rides the outcome evidence: only a
                    // VERIFIED adapter restoration makes this slot
                    // rolled-back-eligible.
                    adapter_restored.insert(sid.clone(), proof.clone());
                    SlotOutcome::Restored {
                        observation: observation.clone(),
                    }
                }
                SlotExecution::FailedAfterAdvance {
                    observation, error, ..
                } => SlotOutcome::FailedAfterAdvance {
                    observation: observation.clone(),
                    error: error.clone(),
                },
                SlotExecution::Indeterminate { .. } => SlotOutcome::Indeterminate {
                    observation: live(sid),
                    error: e.failed_error().map(str::to_string),
                },
            };
            outcomes.insert(sid.clone(), outcome);
        }
        Ok(FailureEvidence {
            outcomes,
            adapter_restored,
        })
    }
}

/// THE FAILED TERMINAL EVIDENCE (the review's P1 fix): the per-slot domain
/// outcomes AND the ADAPTER-RESTORATION EVIDENCE — the slots whose adapter
/// side effects were VERIFIED restored, carrying the sealed proof
/// ([`VerifiedAdapterRestoration`]) extracted from the `Restored`
/// executions. The kernel's rolled-back decision ([`decide_terminal`])
/// refuses a `Restored` outcome without its proof: a slot whose generation
/// delta is `Unchanged` but whose adapter side effect was NOT verified
/// restored can never silently classify as rolled back.
///
/// [`decide_terminal`]: crate::kernel::transition::decide_terminal
pub(crate) struct FailureEvidence {
    pub(crate) outcomes: BTreeMap<SlotId, SlotOutcome>,
    pub(crate) adapter_restored:
        BTreeMap<SlotId, crate::verify::adapters::transaction::VerifiedAdapterRestoration>,
}

/// Run every mutation phase (steps 10-15), in the numbered order. The batch
/// loop and the never-started `Skipped` filler live in
/// [`crate::deploy::rollout`]; the failure-policy pass in
/// [`crate::deploy::rollout`]; the commit-marker / status decision in
/// [`crate::deploy::rollout`]; the post-mutation observation in
/// [`crate::deploy::rollout`].
pub(crate) fn run_execution(
    ctx: &PushContext,
    outcome: &PreflightOutcome,
    members: &[(&SlotConfig, &crate::config::ServerDef)],
    remotes: &HashMap<SlotId, Box<dyn Remote>>,
    helpers: &HashMap<SlotId, RemoteHelper>,
    statuses: &HashMap<SlotId, crate::remote::helper::RemoteStatus>,
) -> Result<ExecutionOutcome> {
    let store = ctx.store;
    let target_name = ctx.target_name;
    let config = ctx.config;
    let target = ctx.target;
    let deployment_id = ctx.deployment_id;
    let op_id = ctx.op_id;

    // 10-13. Process slots in batches. The batch size is a validated NONZERO
    // [`BatchSize`] (the raw -> domain conversion rejects zero), so the
    // `max(1)` guard is an invariant-preserving no-op kept for the batch loop.
    let batch_size = target.rollout.batch_size.get().max(1) as usize;
    // The TYPED batch-failure policy: never a loose string. It is matched
    // EXHAUSTIVELY below (step 13 compensation and step 14 status) — an
    // unsupported spelling cannot exist (the strict parse rejected it at
    // config load), so there is no implicit fallback to "leave changed".
    let failure_policy = target.rollout.failure_policy;
    let stop_on_failure = target.rollout.stop_on_failure;

    let servers_order: Vec<SlotId> = outcome
        .assignments
        .iter()
        .map(|a| a.placement_slot.clone())
        .collect();

    // The deployment-order batch loop (batch_size, stop_on_failure, the
    // `'batches` iteration) and the never-started `NotStarted` filler live
    // in [`crate::deploy::rollout`]; the outcome is the ONE per-slot
    // execution table the failure-policy pass and the terminal decision
    // derive from.
    let BatchRun { mut executions } = crate::deploy::rollout::run_batches(
        &outcome.assignments,
        &outcome.behavior_index,
        members,
        config,
        target_name,
        store,
        remotes,
        helpers,
        statuses,
        op_id,
        deployment_id,
        &outcome.plan_servers,
        &outcome.new_gen,
        &servers_order,
        batch_size,
        stop_on_failure,
    )?;

    // 13 & 14. The FAILURE-POLICY PASS lives in [`crate::deploy::rollout`]:
    // the step-13 compensation of the ADVANCE-REQUIRED set (an `Advanced`
    // or `FailedAfterAdvance` execution is flipped to `Restored` on a
    // successful compensation) — the STATUS DECISION IS THE KERNEL'S
    // ([`crate::kernel::transition::decide_terminal`] now DERIVES the
    // rolled-back-vs-degraded disposition from the per-slot outcomes'
    // observations against the intent's pre-push/desired generations); the
    // engine gathers evidence only. The commit-marker step for an
    // otherwise-successful attempt lives in the shared lock-verified
    // finalizer ([`crate::ledger::finalize::finalize_successful_locked`]) at
    // commit time.
    crate::deploy::rollout::apply_failure_policy(
        failure_policy,
        members,
        config,
        target_name,
        helpers,
        op_id,
        deployment_id,
        &outcome.plan_servers,
        &outcome.new_gen,
        &mut executions,
    )?;

    // 16 & 17. Record attempt, history, retention.
    //
    // The per-slot ACTUAL observation (each slot's *real* final state, read
    // from the remote generation it currently points at — including the
    // THREE-STATE `Observation::Unknown(error)` handling for failed reads)
    // lives in [`crate::deploy::rollout::observe_actual_servers`] (the
    // result-table shaping module). The observation map is the evidence the
    // terminal decision's per-slot classification attaches to the
    // observation-less executions (never-started / pre-swap failures /
    // indeterminate) — the old `record_never_advanced_outcomes` wire-row
    // fix-up is GONE (its role moved into [`ExecutionOutcome::failure_outcomes`]).
    let (actual_servers, actual_observations) =
        crate::deploy::rollout::observe_actual_servers(&outcome.assignments, helpers);
    // `desired` (each slot's minted generation for its planned artifact, as a
    // complete [`GenerationRef`]) was computed BEFORE the mutation loop and
    // persisted as part of the immutable intent (`attempt_intent`); it is not
    // recomputed here.

    Ok(ExecutionOutcome {
        executions,
        actual_observations,
        actual_servers,
        servers_order,
    })
}

#[cfg(test)]
pub(crate) mod execute_tests {
    //! MUTATION phase tests (steps 10-15): the deployment-order batch loop, the
    //! failure-policy compensation + status derivation, and the post-mutation
    //! observation — driven end-to-end through
    //! [`push_inner`] with the shared harnesses from
    //! [`crate::deploy::testsupport`].

    use crate::deploy::testsupport::*;
    use crate::identity::test_deployment_id;
    use crate::ledger::SlotOutcomeBodyWire;
    use crate::remote::helper::RemoteHelper;
    use crate::remote::transport::LocalTransport;
    use crate::testutil::test_remotes::FailOnceGenerationRemote;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    /// A remote failure MID-mutation (after the intent is durable, before the
    /// server's generation record — and therefore `current` — exists) leaves
    /// the intent record durable with an EMPTY outcomes map, records a failure
    /// outcome in results.json, and never advances the remote; a follow-up
    /// clean push recovers.
    #[test]
    fn mid_mutation_fault_leaves_intent_durable_without_advancing_remote() {
        let h = RecoveryHarness::new();
        let id = test_deployment_id("deploy-mid-mutation");
        let armed = Arc::new(AtomicBool::new(true));
        let armed_for_factory = armed.clone();
        let rf = h.remotes_base.clone();
        let fault_factory = move |s: &crate::config::ServerDef,
                                  _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            FailOnceGenerationRemote::build(rf.join(s.id.as_str()), armed_for_factory.clone())
        };
        let project_root = h.config.project_root(&h.cfg_path);
        let target = h.config.target("t1").expect("harness target");
        let op_id = OperationId::new(format!("op-{}", id.as_str()));
        let r = push_inner(
            &project_root,
            &h.store,
            &fault_factory,
            "t1",
            &crate::deploy::plan::SlotSelection::normalize(&h.config, "t1", None).unwrap(),
            &RefExpr::Head,
            None,
            &id,
            &op_id,
            &h.config,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
        )
        .unwrap();
        assert!(
            r.status == Some(DeploymentStatus::FailedRolledBack)
                || r.status == Some(DeploymentStatus::Degraded),
            "mid-mutation failure must be reported as a failure, got {:?}",
            r.status
        );

        // The intent record is durable with NO outcomes member (outcomes live
        // in the terminal event and the report, never in the persisted intent
        // — the domain type carries no `slots` map).
        let attempts = h.store.read_attempts("t1").unwrap();
        assert_eq!(attempts.len(), 1, "intent must be recorded before mutation");
        assert_eq!(
            latest_status(&h, id.as_str()),
            Some(DeploymentStatus::FailedRolledBack)
        );
        let results = h.store.read_results(id.as_str()).unwrap();
        assert!(matches!(
            results[&SlotId::new("p1")].result,
            SlotOutcomeBodyWire::FailedBeforeAdvance { .. }
        ));

        // The remote never advanced: no `current`, no durable generation
        // record (the mid-mutation fault fired before the assignment write, so
        // the generation dir may exist but is empty).
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join("s1"))
                .unwrap();
        assert!(
            !remote.exists(crate::remote::layout::current()),
            "no current"
        );
        for e in remote.list(crate::remote::layout::generations()).unwrap() {
            assert!(
                !remote.exists(
                    &crate::remote::layout::generations()
                        .join(&e.name)
                        .join("assignment.json")
                ),
                "no generation record may be durable ({} was never written)",
                e.name
            );
        }

        // A follow-up clean push succeeds and advances the remote.
        let r2 = push_clean(&h).unwrap();
        assert_eq!(
            r2.status,
            Some(DeploymentStatus::Successful),
            "the interrupted state must be recoverable: {}",
            r2.message
        );
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join("s1"))
                .unwrap();
        assert!(
            remote.exists(crate::remote::layout::current()),
            "remote advanced"
        );
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 2);
    }

    #[test]
    fn verification_failure_compensates_prior_and_observed_reflects_actual() {
        let h = RecoveryHarness::new();
        let id1 = test_deployment_id("deploy-verify-fail-baseline");
        let r1 = push_main_with_id(&h, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let prior =
            r1.attempt.as_ref().expect("attempt recorded").slots[&SlotId::new("p1")].clone();
        let prior_gen = known_generation(&prior).clone();
        let prior_tree = known_artifact(&prior).tree.clone();
        let prior_release = known_artifact(&prior).release.clone();
        // Behavior digest A (verification argv "true") frozen into s0.
        let var_a = h.config.variant("standard").unwrap();
        let a_digest =
            crate::verify::release::behavior_contract_digest(&crate::identity::BehaviorContract {
                activation: var_a.activation.clone(),
                verification: var_a.verification.clone(),
            });

        // v2: verification argv flips to "false" AND the artifact content
        // changes, so the desired tree + release differ from the prior state
        // and the push is not an up-to-date no-op.
        let project_root = h.config.project_root(&h.cfg_path);
        let variant_path = project_root
            .join("releases")
            .join("v1")
            .join("standard.toml");
        let new_variant = std::fs::read_to_string(&variant_path)
            .unwrap()
            .replace("argv = [\"true\"]", "argv = [\"false\"]");
        assert_ne!(new_variant, std::fs::read_to_string(&variant_path).unwrap());
        std::fs::write(&variant_path, new_variant).unwrap();
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
        let b_digest =
            crate::verify::release::behavior_contract_digest(&crate::identity::BehaviorContract {
                activation: var_b.activation.clone(),
                verification: var_b.verification.clone(),
            });
        assert_ne!(a_digest, b_digest, "behaviors must differ");

        let id2 = test_deployment_id("deploy-verify-fail");
        let target = config2.target("t1").expect("harness target");
        let op_id = OperationId::new(format!("op-{}", id2.as_str()));
        let rf = h.remotes_base.clone();
        // The verification contract flips to `false`: the deterministic fake
        // exec scripts that EXACT argv to a non-zero outcome, so the
        // compensation branch runs — no real `false` process, no wall-clock.
        let script = crate::remote::transport::scripted::ScriptedExec::default_success()
            .with_outcome(
                &["false"],
                crate::remote::transport::scripted::ScriptedOutcome::failure(
                    "scripted verification failure (the false contract)",
                ),
            );
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::with_exec(
                &crate::testutil::fixture_env(),
                rf.join(s.id.as_str()),
                script.clone(),
            )?))
        };
        let r2 = push_inner(
            &config2.project_root(&h.cfg_path),
            &h.store,
            &factory,
            "t1",
            &crate::deploy::plan::SlotSelection::normalize(&config2, "t1", None).unwrap(),
            &RefExpr::Head,
            None,
            &id2,
            &op_id,
            &config2,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
        )
        .unwrap();
        assert_eq!(
            r2.status,
            Some(DeploymentStatus::FailedRolledBack),
            "a verification failure after activation must roll the whole attempt back, got {:?}",
            r2.status
        );

        // The report's ACTUAL per-slot state reflects the restored PRIOR
        // generation and artifact, never the desired v2 tree.
        let actual = &r2.attempt.as_ref().expect("attempt recorded").slots[&SlotId::new("p1")];
        assert_eq!(known_generation(actual), &prior_gen);
        assert_eq!(
            known_artifact(actual).tree,
            prior_tree,
            "the actual artifact must be the restored prior tree, not the desired v2 tree"
        );

        // results.json records the compensation: the slot FAILED (verification)
        // and was compensated inside the per-server pipeline — the RESTORED
        // state (`Restored` is also the failure-policy-compensated Activated
        // state), at the PRIOR generation.
        let results = h.store.read_results(id2.as_str()).unwrap();
        let res = &results[&SlotId::new("p1")];
        assert!(
            matches!(res.result, SlotOutcomeBodyWire::Restored { .. }),
            "an in-process-compensated failure is the Restored execution state"
        );
        assert_eq!(
            res.result.observation(),
            &ObservationWire::Known(ObservedGenerationWire {
                generation: prior_gen.clone()
            }),
            "the wire outcome records the compensated slot's PRIOR generation"
        );

        // The remote `current` points at the PRIOR generation, whose stored
        // assignment carries the PRIOR behavior digest (A), never B: the
        // prior behavior contract was restored, not the desired one.
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join("s1"))
                .unwrap();
        let status = RemoteHelper::new(&remote).status().unwrap();
        let cur = status
            .current_generation
            .expect("compensation must restore current");
        assert_eq!(cur.as_str(), prior_gen.as_str());
        let assignment: crate::remote::helper::GenerationAssignment = serde_json::from_slice(
            &remote
                .read(
                    &crate::remote::layout::generations()
                        .join(cur.as_str())
                        .join("assignment.json"),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(assignment.behavior_sha256, a_digest);
        assert_ne!(
            assignment.behavior_sha256, b_digest,
            "the restored generation must carry the PRIOR behavior, not the desired one"
        );

        // OBSERVED REFRESH: observed.json carries the ACTUAL per-slot state —
        // the restored prior generation/artifact — with the LIVE assignment's
        // OWN minting deployment (id1 created the restored generation; the
        // failed id2 did not), never the desired (failed) v2 tree and never
        // the failed deployment re-stamped onto a generation it did not
        // create.
        let observed = h.store.read_observed("t1", &h.config).unwrap();
        let os = &observed.slots[&SlotId::new("p1")];
        let ObservedAssignment::Known {
            generation,
            artifact,
            ..
        } = &os.assignment
        else {
            panic!("observed p1 must be a successful read");
        };
        assert_eq!(generation, &prior_gen);
        let oa = artifact;
        assert_eq!(
            oa.tree, prior_tree,
            "observed tree must be the restored prior tree"
        );
        assert_eq!(oa.release, prior_release);
        let desired_tree = r2.attempt.as_ref().unwrap().desired[&SlotId::new("p1")]
            .assignment
            .artifact
            .tree
            .clone();
        assert_ne!(
            oa.tree, desired_tree,
            "observed must NOT reflect the desired (failed) v2 tree"
        );
        assert_eq!(
            os.last_deployment(),
            Some(&id1),
            "observed last_deployment must be the LIVE assignment's OWN minting deployment \
             (id1), not the failed attempt id2"
        );
        // The per-server record mirrors the observed slot state.
        let server_state = h.store.read_server("s1").unwrap();
        assert_eq!(
            server_state
                .last_observed
                .as_ref()
                .and_then(|o| match &o.assignment {
                    ObservedAssignment::Known { generation, .. } => Some(generation.clone()),
                    _ => None,
                }),
            Some(prior_gen.clone())
        );

        // The failed attempt is terminal FailedRolledBack, produced no
        // snapshot, and the s0 snapshot/ref are untouched.
        assert_eq!(
            latest_status(&h, id2.as_str()),
            Some(DeploymentStatus::FailedRolledBack)
        );
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].deployment_id, id1);
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(id1.as_str())
        );
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 2);
    }

    // ---- Batched stop_on_failure with batch_size > 1 ---------------------
    //
    // The integration `stop_on_failure_records_all_servers` test uses
    // batch_size = 1 and fails the FIRST server. Here the FIRST batch
    // advances successfully, a LATER batch fails, and stop_on_failure must
    // not start any subsequent batch — while the attempt still records EVERY
    // server (advanced, failed, and skipped alike).

    #[test]
    fn batched_stop_on_failure_stops_after_failing_batch() {
        const BATCHED_TOML: &str = r#"
schema_version = 2
application = "batched"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s2"
address = "b"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s3"
address = "c"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s4"
address = "d"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 2, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        // Variant `good` (sorts first, so its slots come first in the plan)
        // declares p1/p2 with PASSING verification; variant `z-failing`
        // declares p3/p4 with FAILING verification. BOTH own the retention
        // policy of the slots they declare (retention lives in the slot's
        // owning variant file).
        let good = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/p1"

[[slots]]
id = "p2"
server = "s2"
target = "t1"
deploy_dir = "/srv/p2"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[retention.deployment]
protect_deployments = 2

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
        let z_failing = r#"
[[slots]]
id = "p3"
server = "s3"
target = "t1"
deploy_dir = "/srv/p3"

[[slots]]
id = "p4"
server = "s4"
target = "t1"
deploy_dir = "/srv/p4"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[retention.deployment]
protect_deployments = 2

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["false"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
        std::fs::write(release_dir.join("good.toml"), good).unwrap();
        std::fs::write(release_dir.join("z-failing.toml"), z_failing).unwrap();
        let artifacts = release_dir.join("artifacts");
        std::fs::create_dir_all(artifacts.join("build/output/app")).unwrap();
        std::fs::write(artifacts.join("build/output/app/server"), "v1\n").unwrap();

        let cfg_path = project.join("deploy.toml");
        std::fs::write(&cfg_path, BATCHED_TOML).unwrap();
        let config = ProjectConfig::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();

        let id = test_deployment_id("deploy-batched-stop");
        let project_root = config.project_root(&cfg_path);
        let target = config.target("t1").expect("target t1");
        let op_id = OperationId::new(format!("op-{}", id.as_str()));
        let rf = remotes_base.clone();
        // Deterministic fake exec: `["true"]` succeeds by script while the
        // `z-failing` variant's `["false"]` contract is scripted to FAIL —
        // the same verification-outcome branch the real `false` binary
        // drove, without any subprocess.
        let script = crate::remote::transport::scripted::ScriptedExec::default_success()
            .with_outcome(
                &["false"],
                crate::remote::transport::scripted::ScriptedOutcome::failure(
                    "scripted verification failure (the z-failing contract)",
                ),
            );
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::with_exec(
                &crate::testutil::fixture_env(),
                rf.join(s.id.as_str()),
                script.clone(),
            )?))
        };
        let r = push_inner(
            &project_root,
            &store,
            &factory,
            "t1",
            &crate::deploy::plan::SlotSelection::normalize(&config, "t1", None).unwrap(),
            &RefExpr::Head,
            None,
            &id,
            &op_id,
            &config,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
        )
        .unwrap();
        assert_eq!(
            r.status,
            Some(DeploymentStatus::FailedRolledBack),
            "a failing later batch under stop_on_failure must roll the attempt back, got {:?}",
            r.status
        );

        // The attempt records ALL four servers (advanced, failed, skipped).
        let attempt = r.attempt.expect("attempt recorded on failure");
        assert_eq!(attempt.slot_ids.len(), 4);
        for sid in ["p1", "p2", "p3", "p4"] {
            assert!(
                attempt.slot_ids.iter().any(|s| s.as_str() == sid),
                "slot {sid} missing from attempt"
            );
        }
        let results = store.read_results(id.as_str()).unwrap();
        assert_eq!(results.len(), 4);
        // The first batch advanced, then compensated back (no prior state ->
        // `current` removed): Restored.
        assert!(
            matches!(
                results[&SlotId::new("p1")].result,
                SlotOutcomeBodyWire::Restored { .. }
            ),
            "p1 must be compensated back (Restored)"
        );
        assert!(
            matches!(
                results[&SlotId::new("p2")].result,
                SlotOutcomeBodyWire::Restored { .. }
            ),
            "p2 must be compensated back (Restored)"
        );
        // The failing slot of the second batch (verified then compensated
        // in-process back to its first-deploy absence): Restored.
        assert!(
            matches!(
                results[&SlotId::new("p3")].result,
                SlotOutcomeBodyWire::Restored { .. }
            ),
            "p3 failed verification and was compensated in-process (Restored)"
        );
        // The slot after the failing one in the same/later batch was never
        // started.
        assert!(
            matches!(
                results[&SlotId::new("p4")].result,
                SlotOutcomeBodyWire::Skipped { .. }
            ),
            "p4 was never started (Skipped)"
        );

        // The never-started server (p4) was left untouched: no `current`
        // pointer, no generation record.
        let remote4 =
            LocalTransport::new(&crate::testutil::fixture_env(), remotes_base.join("s4")).unwrap();
        assert!(
            !remote4.exists(crate::remote::layout::current()),
            "p4's server must never receive a current pointer"
        );
        assert_eq!(
            remote4
                .list(crate::remote::layout::generations())
                .unwrap()
                .len(),
            0,
            "p4's server must never receive a generation record"
        );
        // The failed slot's server was compensated back to no prior state.
        let remote3 =
            LocalTransport::new(&crate::testutil::fixture_env(), remotes_base.join("s3")).unwrap();
        assert!(
            !remote3.exists(crate::remote::layout::current()),
            "a compensated first-deploy slot has no current"
        );

        assert_eq!(store.read_attempts("t1").unwrap().len(), 1);
        assert_eq!(
            store.latest_status(id.as_str()).unwrap(),
            Some(DeploymentStatus::FailedRolledBack)
        );

        // OBSERVED REFRESH FOR SKIPPED/COMPENSATED SLOTS: `observed.json` is
        // refreshed for every member slot with a READABLE LIVE remote
        // assignment (or a prior observed record carried over verbatim).
        // NONE of the four slots has a live generation after the failed push
        // (the first-deploy batch was compensated back to no prior state, p3
        // failed, p4 was never started) and none has a prior record — so the
        // observed map must NOT fabricate entries: no `{generation: None,
        // artifact: desired}` lie for a slot nothing deployed to, no
        // re-stamped `last_deployment`.
        let observed = store.read_observed("t1", &config).unwrap();
        // Every member slot's projection now records its live state EXPLICITLY:
        // with no live generation and no prior record, each is `Absent` — the
        // explicit-absence projection that overwrites any stale physical
        // record — never a fabricated Known with the desired artifact.
        assert_eq!(
            observed.slots.len(),
            4,
            "all four member slots must have an explicit projection: {:?}",
            observed.slots.keys().collect::<Vec<_>>()
        );
        for (sid, slot) in &observed.slots {
            assert!(
                matches!(slot.assignment, crate::ledger::ObservedAssignment::Absent),
                "slot {sid} with no live assignment must project Absent (never the desired artifact), got: {:?}",
                slot.assignment
            );
            assert!(slot.last_deployment().is_none());
        }

        assert!(
            store.read_snapshots("t1").unwrap().is_empty(),
            "a failed attempt must produce no snapshot"
        );
    }

    // ---- Deployment order: the batching follows the plan's order ---------
    //
    // The wire's `slot_ids` is documented as "in deployment order (the same
    // set the commit marker `slots` payload records)". The plan's assignment
    // order — which drives the ROLLOUT BATCHING — is the config's
    // deterministic order (variants in name order, then each variant's slots
    // in FILE order), NOT sorted by slot id. The intent's slot table must
    // preserve that order, so the recorded `slot_ids` matches the batching
    // order exactly. Here the slots are declared in the deliberately
    // NON-sorted plan order [p3, p1, p2] and p1's verification FAILS: with
    // batch_size = 1 + stop_on_failure the batching processes p3 first
    // (advances), then p1 (fails) and stops — p2 is never started. If the
    // batching (or the recorded slot_ids) were sorted by id, p1 would fail
    // FIRST and p3 would never advance.

    #[test]
    fn batching_follows_the_deployment_order_not_sorted_slot_ids() {
        const ORDERED_TOML: &str = r#"
schema_version = 2
application = "ordered"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s2"
address = "b"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s3"
address = "c"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        // Variant `a` (sorts first) declares p3 with PASSING verification;
        // variant `b` declares p1 (FAILING verification) then p2 (passing,
        // never reached). The plan order is [p3, p1, p2] — the deployment
        // order — never the sorted [p1, p2, p3].
        let a = r#"
[[slots]]
id = "p3"
server = "s3"
target = "t1"
deploy_dir = "/srv/p3"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[retention.deployment]
protect_deployments = 2

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
        let b = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/p1"

[[slots]]
id = "p2"
server = "s2"
target = "t1"
deploy_dir = "/srv/p2"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[retention.deployment]
protect_deployments = 2

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["false"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
        std::fs::write(release_dir.join("a.toml"), a).unwrap();
        std::fs::write(release_dir.join("b.toml"), b).unwrap();
        let artifacts = release_dir.join("artifacts");
        std::fs::create_dir_all(artifacts.join("build/output/app")).unwrap();
        std::fs::write(artifacts.join("build/output/app/server"), "v1\n").unwrap();

        let cfg_path = project.join("deploy.toml");
        std::fs::write(&cfg_path, ORDERED_TOML).unwrap();
        let config = ProjectConfig::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();

        let id = test_deployment_id("deploy-ordered");
        let op_id = OperationId::new(format!("op-{}", id.as_str()));
        let rf = remotes_base.clone();
        // Deterministic fake exec: `["true"]` succeeds by script while the
        // `z-failing` variant's `["false"]` contract is scripted to FAIL —
        // the same verification-outcome branch the real `false` binary
        // drove, without any subprocess.
        let script = crate::remote::transport::scripted::ScriptedExec::default_success()
            .with_outcome(
                &["false"],
                crate::remote::transport::scripted::ScriptedOutcome::failure(
                    "scripted verification failure (the z-failing contract)",
                ),
            );
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::with_exec(
                &crate::testutil::fixture_env(),
                rf.join(s.id.as_str()),
                script.clone(),
            )?))
        };
        let r = push_inner(
            &config.project_root(&cfg_path),
            &store,
            &factory,
            "t1",
            &crate::deploy::plan::SlotSelection::normalize(&config, "t1", None).unwrap(),
            &RefExpr::Head,
            None,
            &id,
            &op_id,
            &config,
            config.target("t1").expect("target t1"),
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
        )
        .unwrap();
        assert_eq!(
            r.status,
            Some(DeploymentStatus::FailedRolledBack),
            "the failing p1 under stop_on_failure must roll the attempt back, got {:?}",
            r.status
        );

        // The recorded intent's slot_ids are the DEPLOYMENT order (the
        // batching order), never the sorted-by-id order.
        let attempt = r.attempt.expect("attempt recorded on failure");
        assert_eq!(
            attempt.slot_ids,
            vec![
                SlotId::parse("p3").unwrap(),
                SlotId::parse("p1").unwrap(),
                SlotId::parse("p2").unwrap(),
            ],
            "the wire's slot_ids must record the deployment order (the batching order), never sorted by id"
        );

        // The BATCHING order: p3 (the FIRST planned slot) advanced before
        // p1 failed; p2 (after the failing slot) was never started. Under a
        // sorted-by-id order p1 would have failed FIRST and p3 would never
        // have advanced.
        let results = store.read_results(id.as_str()).unwrap();
        assert!(
            matches!(
                results[&SlotId::new("p3")].result,
                SlotOutcomeBodyWire::Restored { .. }
            ),
            "p3 (first in the deployment order) advanced before the failure and was compensated back"
        );
        assert!(
            matches!(
                results[&SlotId::new("p1")].result,
                SlotOutcomeBodyWire::Restored { .. }
            ),
            "p1 (second in the deployment order) is the failing slot, compensated in-process back to its first-deploy absence (Restored)"
        );
        assert!(
            matches!(
                results[&SlotId::new("p2")].result,
                SlotOutcomeBodyWire::Skipped { .. }
            ),
            "p2 (after the failing slot) was never started"
        );
    }

    // ---- Snapshot-ref membership-change refusal ------------------------------
    //
    // Exact snapshot rollback requires the current target's placement-slot SET to
    // be identical to the snapshot's recorded set (in addition to each slot's
    // physical binding). When the variant file declares a DIFFERENT slot, the
    // refusal must fire in planning — before any remote connection or store
    // write — and leave every byte of store + remote state untouched.

    #[test]
    fn activation_failure_compensates_prior_and_observed_reflects_actual() {
        let env_dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let marker = env_dir.path().join("fail-restart");
        // Hermetic env: the fake systemctl and its markers ride the snapshot's
        // child env — the parent process environment is never touched.
        let env = install_fake_systemctl(env_dir.path(), &marker, true);
        let h = SysdHarness::with_env(env);

        // Push 1: baseline. The fake systemctl succeeds (no marker), so
        // activation completes; s0 records the prior generation/artifact and
        // the remote publishes the prior behavior contract.
        let id1 = test_deployment_id("deploy-act-fail-baseline");
        let r1 = h.push_head(&id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let prior = r1.attempt.as_ref().unwrap().slots[&SlotId::new("p1")].clone();
        let prior_gen = known_generation(&prior).clone();
        let prior_tree = known_artifact(&prior).tree.clone();
        let prior_release = known_artifact(&prior).release.clone();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join("s1"))
                .unwrap();
        let prior_assignment: crate::remote::helper::GenerationAssignment = serde_json::from_slice(
            &remote
                .read(
                    &crate::remote::layout::generations()
                        .join(prior_gen.as_str())
                        .join("assignment.json"),
                )
                .unwrap(),
        )
        .unwrap();
        let prior_behavior_sha = prior_assignment.behavior_sha256.clone();

        // Push 2: the artifact content changes (so the push is not a no-op)
        // and the activation-failure marker is armed. The fake systemctl fails
        // the FIRST restart (the desired generation's activation) and consumes
        // the marker, so the compensation's prior-activation restart succeeds.
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
        std::fs::write(&marker, "fail").unwrap();
        let id2 = test_deployment_id("deploy-act-fail");
        let r2 = h.push_head(&id2).unwrap();
        assert_eq!(
            r2.status,
            Some(DeploymentStatus::FailedRolledBack),
            "an activation failure after the swap with successful compensation must end FailedRolledBack, got {:?}",
            r2.status
        );
        assert!(
            !marker.exists(),
            "the one-shot marker was consumed by the desired activation's failed restart"
        );

        // The report's ACTUAL per-slot state reflects the restored PRIOR
        // generation and artifact, never the desired v2 tree.
        let actual = &r2.attempt.as_ref().expect("attempt recorded").slots[&SlotId::new("p1")];
        assert_eq!(known_generation(actual), &prior_gen);
        assert_eq!(
            known_artifact(actual).tree,
            prior_tree,
            "the actual artifact must be the restored prior tree, not the desired v2 tree"
        );

        // results.json records the compensation: the slot FAILED (activation)
        // and was compensated inside the per-server pipeline — the RESTORED
        // state — at the PRIOR generation.
        let results = h.store.read_results(id2.as_str()).unwrap();
        let res = &results[&SlotId::new("p1")];
        assert!(
            matches!(res.result, SlotOutcomeBodyWire::Restored { .. }),
            "activation failure must be compensated (Restored)"
        );
        assert_eq!(
            res.result.observation(),
            &ObservationWire::Known(ObservedGenerationWire {
                generation: prior_gen.clone()
            }),
            "the wire outcome records the compensated slot's PRIOR generation"
        );

        // The remote `current` points at the PRIOR generation, whose stored
        // assignment carries the PRIOR behavior digest: the prior behavior
        // contract was restored, not the desired one.
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join("s1"))
                .unwrap();
        let status = RemoteHelper::new(&remote).status().unwrap();
        let cur = status
            .current_generation
            .expect("compensation must restore current");
        assert_eq!(cur.as_str(), prior_gen.as_str());
        let assignment: crate::remote::helper::GenerationAssignment = serde_json::from_slice(
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
            assignment.behavior_sha256, prior_behavior_sha,
            "the restored generation must carry the PRIOR behavior contract"
        );

        // OBSERVED REFRESH: observed.json carries the ACTUAL per-slot state —
        // the restored prior generation/artifact — with the LIVE assignment's
        // OWN minting deployment (id1 created the prior generation; the
        // failed id2 did not). It must NOT reflect the desired (failed) v2
        // tree, and the failed attempt must not be re-stamped onto a slot it
        // did not leave live.
        let observed = h.store.read_observed("t1", &h.config).unwrap();
        let os = &observed.slots[&SlotId::new("p1")];
        let ObservedAssignment::Known {
            generation,
            artifact,
            ..
        } = &os.assignment
        else {
            panic!("observed p1 must be a successful read");
        };
        assert_eq!(generation, &prior_gen);
        let oa = artifact;
        assert_eq!(
            oa.tree, prior_tree,
            "observed tree must be the restored prior tree"
        );
        assert_eq!(oa.release, prior_release);
        let desired_tree = r2.attempt.as_ref().unwrap().desired[&SlotId::new("p1")]
            .assignment
            .artifact
            .tree
            .clone();
        assert_ne!(
            oa.tree, desired_tree,
            "observed must NOT reflect the desired (failed) v2 tree"
        );
        assert_eq!(
            os.last_deployment(),
            Some(&id1),
            "observed last_deployment must be the LIVE assignment's OWN minting deployment \
             (id1), not the failed attempt id2"
        );

        // The failed attempt is terminal FailedRolledBack, produced no
        // snapshot, and the s0 snapshot/ref are untouched.
        assert_eq!(
            h.store.latest_status(id2.as_str()).unwrap(),
            Some(DeploymentStatus::FailedRolledBack)
        );
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].deployment_id, id1);
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(id1.as_str())
        );
    }

    #[test]
    fn activation_failure_compensation_failure_is_degraded_and_evidences_the_change() {
        // Same scenario, but the marker is NEVER consumed (`once = false`):
        // the desired activation fails AND the compensation's prior-activation
        // restart fails too. The in-process compensation records the failure
        // WITHOUT restoring the slot — an uncompensated POST-ADVANCE failure:
        // the swap happened and was NOT restored, so the execution state is
        // `FailedAfterAdvance` (the old flat `Failed` + `compensated: false`
        // could not distinguish it from a pre-swap failure). The kernel's ONE
        // classifier
        // ([`crate::kernel::terminal::classify_slot_delta`]) sees the
        // outcome's recorded observation — the advanced desired generation —
        // against the intent's pre_push and DESIRED generations: the delta is
        // `Desired`, a REMAINING CHANGE. THE REVIEW'S P1 CASE: an
        // uncompensated failure that happened AFTER the slot advanced must
        // classify `Degraded` with a nonempty delta — the old transition-
        // based rule (rolled back iff no slot PROVABLY ON the new state,
        // which a post-swap compensation failure satisfied even though it
        // advanced) called it `FailedRolledBack`. The delta is evidenced in
        // the terminal's remaining_changes below. (The observed refresh
        // reads the ACTUAL `current`, which the compensation swap-back moved
        // to the prior generation even though the prior service could not be
        // re-activated — the physical state is mixed, which is exactly why
        // the recorded post-advance failure evidence, not a backend
        // re-read, classifies the slot: it was advanced and not restored.)
        let env_dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let marker = env_dir.path().join("fail-restart");
        // Hermetic env: the fake systemctl and its markers ride the snapshot's
        // child env — the parent process environment is never touched.
        let env = install_fake_systemctl(env_dir.path(), &marker, false);
        let h = SysdHarness::with_env(env);

        let id1 = test_deployment_id("deploy-act-compfail-baseline");
        let r1 = h.push_head(&id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        let prior_gen =
            known_generation(&r1.attempt.as_ref().unwrap().slots[&SlotId::new("p1")]).clone();
        let prior_tree = known_artifact(&r1.attempt.as_ref().unwrap().slots[&SlotId::new("p1")])
            .tree
            .clone();

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
        std::fs::write(&marker, "fail").unwrap();
        let id2 = test_deployment_id("deploy-act-compfail");
        let r2 = h.push_head(&id2).unwrap();
        assert_eq!(
            r2.status,
            Some(DeploymentStatus::Degraded),
            "an uncompensated POST-ADVANCE failure (the swap happened and was not restored) is NEVER rolled-back: the slot's recorded observation is the advanced desired generation, so its delta is Desired — a remaining change — and the attempt is Degraded, got {:?}",
            r2.status
        );
        assert!(
            marker.exists(),
            "the marker persists: every restart (desired AND compensation) failed"
        );

        // results.json records the failure WITHOUT compensation: the slot
        // stayed on the DESIRED generation (the compensation swap-back could
        // not re-activate the prior service) — the post-ADVANCE uncompensated
        // failure state `FailedAfterAdvance` (the swap happened and was not
        // restored: a remaining change, NEVER rolled-back).
        let results = h.store.read_results(id2.as_str()).unwrap();
        let res = &results[&SlotId::new("p1")];
        assert!(
            matches!(res.result, SlotOutcomeBodyWire::FailedAfterAdvance { .. }),
            "the failed compensation must be recorded as the FailedAfterAdvance execution state"
        );
        assert!(
            matches!(res.result.observation(), ObservationWire::Known(_)),
            "the outcome records the advanced (desired) generation"
        );

        // The attempt is terminal Degraded — the uncompensated post-advance
        // failure evidenced as the terminal's remaining change — and produced
        // no snapshot; s0 is untouched.
        assert_eq!(
            h.store.latest_status(id2.as_str()).unwrap(),
            Some(DeploymentStatus::Degraded)
        );
        // THE DELTA IS EVIDENCED: the Degraded terminal's remaining_changes
        // contains the slot (its recorded observation — the advanced desired
        // generation — is NOT its pre-push state).
        let entries = h.store.read_ledger("t1").unwrap();
        let entry = entries
            .iter()
            .find(|e| e.deployment_id == id2)
            .expect("the failed attempt has a ledger entry");
        let terminal = entry
            .terminal
            .as_ref()
            .expect("the failed attempt has a terminal");
        let remaining = terminal
            .remaining_changes(&entry.intent)
            .expect("a Degraded terminal derives remaining changes");
        assert!(
            remaining.contains_key(&SlotId::new("p1")),
            "the uncompensated post-advance failure is a remaining change (its delta is Desired), evidenced in the Degraded terminal"
        );
        let snapshots = h.store.read_snapshots("t1").unwrap();
        assert_eq!(snapshots.len(), 1, "only the baseline snapshot exists");
        assert_eq!(snapshots[0].deployment_id, id1);
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(id1.as_str())
        );
        // The mixed per-server state is retained, not hidden: the observed
        // refresh reads the ACTUAL `current`, which the compensation swap-back
        // moved to the prior generation even though the prior service could
        // not be re-activated.
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join("s1"))
                .unwrap();
        let status = RemoteHelper::new(&remote).status().unwrap();
        assert_eq!(
            status.current_generation.as_ref().map(|g| g.as_str()),
            Some(prior_gen.as_str()),
            "the compensation swap-back is visible on the remote current"
        );
        let observed = h.store.read_observed("t1", &h.config).unwrap();
        let os = &observed.slots[&SlotId::new("p1")];
        let ObservedAssignment::Known {
            generation,
            artifact,
            ..
        } = &os.assignment
        else {
            panic!("observed p1 must be a successful read");
        };
        assert_eq!(generation, &prior_gen);
        assert_eq!(artifact.tree, prior_tree);
    }

    // ---- First-deploy activation failure, preflight outcomes, observed
    // unknown-assignment fallback ------------------------------------------

    /// FIRST-DEPLOY activation failure: there is no prior generation to
    /// restore, so compensation removes `current` — compare-and-swap style,
    /// only while it still points at the generation this attempt advanced
    /// (`remove_current_if`) — and the attempt is `FailedRolledBack`
    /// (requirement.md step 11: "On a first deployment with no prior
    /// generation, compensation removes `current` and reverses only adapter
    /// resources created by that attempt"; step 13: "If all compensation
    /// succeeds, mark the attempt `failed_rolled_back`"). The remote is left
    /// WITHOUT a stale `current` pointing at the dead generation.
    #[test]
    fn first_deploy_activation_failure_compensates_and_removes_current() {
        let env_dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let marker = env_dir.path().join("fail-restart");
        // Hermetic env: the fake systemctl and its markers ride the snapshot's
        // child env — the parent process environment is never touched.
        let env = install_fake_systemctl(env_dir.path(), &marker, true);
        let h = SysdHarness::with_env(env);
        std::fs::write(&marker, "fail").unwrap();

        let id = test_deployment_id("deploy-first-act-fail");
        let r = h.push_head(&id).unwrap();

        assert_eq!(
            r.status,
            Some(DeploymentStatus::FailedRolledBack),
            "a compensated first-deploy activation failure must end FailedRolledBack, got {:?}",
            r.status
        );
        assert!(
            !marker.exists(),
            "the one-shot marker was consumed by the failed restart"
        );

        // The remote has NO stale `current`: the compare-and-swap removal
        // removed the link (it still pointed at the generation this attempt
        // advanced).
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join("s1"))
                .unwrap();
        assert!(
            !remote.exists(crate::remote::layout::current()),
            "first-deploy compensation must remove `current`"
        );
        let status = RemoteHelper::new(&remote).status().unwrap();
        assert!(
            status.current_generation.is_none(),
            "no current generation may remain after first-deploy compensation"
        );

        // results.json records the failure WITH compensation: the first-deploy
        // activation failure was compensated in-process (removing `current`)
        // — the RESTORED state.
        let results = h.store.read_results(id.as_str()).unwrap();
        let res = &results[&SlotId::new("p1")];
        assert!(
            matches!(res.result, SlotOutcomeBodyWire::Restored { .. }),
            "first-deploy compensation must be recorded as the Restored state"
        );
        assert_eq!(
            res.result.observation(),
            &ObservationWire::KnownAbsent,
            "a compensated first-deploy slot records the absent (restored-to) state"
        );

        // The attempt is terminal FailedRolledBack and produced no snapshot /
        // no ref — a failed FIRST deployment has nothing to roll the ref back
        // from.
        assert_eq!(
            h.store.latest_status(id.as_str()).unwrap(),
            Some(DeploymentStatus::FailedRolledBack)
        );
        assert!(
            h.store.read_snapshots("t1").unwrap().is_empty(),
            "a failed first deployment must produce no snapshot"
        );
        assert!(h.store.read_last_successful("t1").is_none());
        assert_eq!(h.store.read_attempts("t1").unwrap().len(), 1);
    }

    /// OBSERVED-REFRESH UNKNOWN-ASSIGNMENT FALLBACK: when a live generation's
    /// `assignment.json` cannot be read (missing/corrupt), the refresh must
    /// preserve the OBSERVED generation and record the assignment as
    /// `Observation::Unknown(ObservationError)` — a DISTINCT value, never a
    /// substitute of the desired/planned artifact (there is no sentinel
    /// artifact: an `ArtifactRef` always means a known artifact). BOTH the
    /// pre-push intent (`pre_push`) and the post-push observed refresh use
    /// this contract; results.json records the slot's pre-swap failure,
    /// `current` stays on the observed (corrupt) generation, and no stale
    /// snapshot/ref is produced.
    #[test]
    fn corrupt_current_assignment_fails_status_and_push_closed() {
        let h = RecoveryHarness::new();
        let id1 = test_deployment_id("deploy-obs-fallback-baseline");
        let r1 = push_main_with_id(&h, &id1).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));
        // The baseline's REAL live generation: the generation the prior
        // observed record carried (an unreadable assignment must fall back to
        // it, not to a fabricated/unknown marker).
        let gen1 =
            known_generation(&r1.attempt.as_ref().expect("attempt").slots[&SlotId::new("p1")])
                .clone();

        // Corrupt the live generation's assignment record on the remote.
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join("s1"))
                .unwrap();
        let asn_path = crate::remote::layout::generations()
            .join(gen1.as_str())
            .join("assignment.json");
        remote.write(&asn_path, b"{ corrupt json !", 0o600).unwrap();
        assert!(
            RemoteHelper::new(&remote)
                .read_assignment(gen1.as_str())
                .is_err(),
            "the assignment must be unreadable after corruption"
        );

        // `status()` validates the complete symlink layout: a corrupt
        // assignment under the current generation is a MALFORMED remote state
        // and fails closed with an integrity error — never a panic, never a
        // `None` that would let a caller proceed on an unverifiable current.
        let err = RemoteHelper::new(&remote)
            .status()
            .expect_err("a corrupt current assignment must fail status closed");
        assert!(
            err.to_string().contains("integrity"),
            "the status failure must be an integrity error, got: {err}"
        );

        // A push against the corrupt remote fails closed at the status read,
        // BEFORE any mutation or intent persistence: no new generation, no
        // attempt, no snapshot, and the baseline ref is untouched.
        let id2 = test_deployment_id("deploy-obs-fallback");
        let err = push_main_with_id(&h, &id2)
            .expect_err("a push against a corrupt current assignment must fail closed");
        assert!(
            err.to_string().contains("integrity"),
            "the push failure must be an integrity error, got: {err}"
        );
        assert_eq!(
            h.store.read_attempts("t1").unwrap().len(),
            1,
            "no attempt may be recorded for the failed push"
        );
        assert_eq!(
            h.store.read_snapshots("t1").unwrap().len(),
            1,
            "no snapshot may be recorded for the failed push"
        );
        assert_eq!(
            h.store.read_last_successful("t1").as_deref(),
            Some(id1.as_str()),
            "the baseline ref must be untouched"
        );
        // The remote `current` still points at gen1 — the failed push never
        // mutated the remote.
        assert_eq!(
            remote.read_link(crate::remote::layout::current()).unwrap(),
            crate::remote::layout::generation(gen1.as_str()).join("root"),
            "current must still point at the baseline generation"
        );
    }

    /// The `leave_changed` failure policy (requirement.md step 13: "An
    /// optional `leave_changed` policy may retain successful advances
    /// deliberately; any attempt with failures under that policy is
    /// `degraded`") must NOT compensate earlier successful batches: the
    /// advanced slots keep their `current`, the attempt ends `Degraded` (never
    /// a falsely clean `FailedRolledBack`), and the failing slot is still
    /// compensated IN-PROCESS (step 11, per-server) with its own `current`
    /// removed on first deploy.
    #[test]
    fn leave_changed_policy_retains_advances_and_reports_degraded() {
        const LEAVE_TOML: &str = r#"
schema_version = 2
application = "leave"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s2"
address = "b"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s3"
address = "c"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s4"
address = "d"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 2, stop_on_failure = true, failure_policy = "leave_changed" }
"#;
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        // Variant `good` (sorts first) declares p1/p2 with PASSING
        // verification; variant `z-failing` declares p3/p4 with FAILING
        // verification. BOTH variants own the retention policy of the slots
        // they declare (retention lives in the slot's owning variant file).
        let good = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/p1"

[[slots]]
id = "p2"
server = "s2"
target = "t1"
deploy_dir = "/srv/p2"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[retention.deployment]
protect_deployments = 2

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
        let z_failing = r#"
[[slots]]
id = "p3"
server = "s3"
target = "t1"
deploy_dir = "/srv/p3"

[[slots]]
id = "p4"
server = "s4"
target = "t1"
deploy_dir = "/srv/p4"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[retention.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[retention.deployment]
protect_deployments = 2

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["false"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
        std::fs::write(release_dir.join("good.toml"), good).unwrap();
        std::fs::write(release_dir.join("z-failing.toml"), z_failing).unwrap();
        let artifacts = release_dir.join("artifacts");
        std::fs::create_dir_all(artifacts.join("build/output/app")).unwrap();
        std::fs::write(artifacts.join("build/output/app/server"), "v1\n").unwrap();

        let cfg_path = project.join("deploy.toml");
        std::fs::write(&cfg_path, LEAVE_TOML).unwrap();
        let config = ProjectConfig::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();

        let id = test_deployment_id("deploy-leave-changed");
        let project_root = config.project_root(&cfg_path);
        let target = config.target("t1").expect("target t1");
        let op_id = OperationId::new(format!("op-{}", id.as_str()));
        let rf = remotes_base.clone();
        // Deterministic fake exec: `["true"]` succeeds by script while the
        // `z-failing` variant's `["false"]` contract is scripted to FAIL —
        // the same verification-outcome branch the real `false` binary
        // drove, without any subprocess.
        let script = crate::remote::transport::scripted::ScriptedExec::default_success()
            .with_outcome(
                &["false"],
                crate::remote::transport::scripted::ScriptedOutcome::failure(
                    "scripted verification failure (the z-failing contract)",
                ),
            );
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::with_exec(
                &crate::testutil::fixture_env(),
                rf.join(s.id.as_str()),
                script.clone(),
            )?))
        };
        let r = push_inner(
            &project_root,
            &store,
            &factory,
            "t1",
            &crate::deploy::plan::SlotSelection::normalize(&config, "t1", None).unwrap(),
            &RefExpr::Head,
            None,
            &id,
            &op_id,
            &config,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
        )
        .unwrap();
        assert_eq!(
            r.status,
            Some(DeploymentStatus::Degraded),
            "under leave_changed a failing batch must end Degraded, got {:?}",
            r.status
        );

        // The earlier successful batch is retained deliberately: p1/p2 keep
        // their live `current` (no compensation pass runs).
        for (sid, sname) in [("p1", "s1"), ("p2", "s2")] {
            let remote =
                LocalTransport::new(&crate::testutil::fixture_env(), remotes_base.join(sname))
                    .unwrap();
            assert!(
                remote.exists(crate::remote::layout::current()),
                "slot {sid} must stay advanced under leave_changed"
            );
        }
        // The FAILING slot is still compensated in-process (step 11) and its
        // first-deploy `current` was removed; the never-started slot is
        // untouched.
        let remote3 =
            LocalTransport::new(&crate::testutil::fixture_env(), remotes_base.join("s3")).unwrap();
        assert!(
            !remote3.exists(crate::remote::layout::current()),
            "the failing slot's current is removed by in-process compensation"
        );
        let remote4 =
            LocalTransport::new(&crate::testutil::fixture_env(), remotes_base.join("s4")).unwrap();
        assert!(
            !remote4.exists(crate::remote::layout::current()),
            "the never-started slot has no current"
        );

        // Per-slot outcomes: advanced, failed-then-compensated (Restored),
        // skipped.
        let results = store.read_results(id.as_str()).unwrap();
        assert!(matches!(
            results[&SlotId::new("p1")].result,
            SlotOutcomeBodyWire::Activated { .. }
        ));
        assert!(matches!(
            results[&SlotId::new("p2")].result,
            SlotOutcomeBodyWire::Activated { .. }
        ));
        assert!(
            matches!(
                results[&SlotId::new("p3")].result,
                SlotOutcomeBodyWire::Restored { .. }
            ),
            "the failing slot's in-process compensation is recorded (Restored)"
        );
        assert!(matches!(
            results[&SlotId::new("p4")].result,
            SlotOutcomeBodyWire::Skipped { .. }
        ));

        // No snapshot/ref for a degraded attempt.
        assert!(
            store.read_snapshots("t1").unwrap().is_empty(),
            "a degraded attempt must produce no snapshot"
        );
        assert!(store.read_last_successful("t1").is_none());
        assert_eq!(
            store.latest_status(id.as_str()).unwrap(),
            Some(DeploymentStatus::Degraded)
        );
    }
}
