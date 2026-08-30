//! EXECUTION SEMANTICS: the per-slot rollout machinery.
//!
//! Nested along the execution concerns: this module holds the
//! deployment-order batch loop (`run_batches`, `BatchRun`); `attempt`
//! the per-attempt outcome derivation (failure policies, result shaping,
//! status/disposition); `server` the per-server mutation pipeline and its
//! per-slot compensation.

use crate::config::ProjectConfig;
use crate::config::ServerDef;
use crate::config::SlotConfig;
use crate::deploy::plan::PlannedAssignment;
use crate::deploy::push::slot_vars;
use crate::error::Result;
use crate::identity::DeploymentId;
use crate::identity::GenerationId;
use crate::identity::OperationId;
use crate::identity::SlotId;
use crate::ledger::BehaviorIndex;
use crate::ledger::Observation;
use crate::ledger::ObservedGeneration;
use crate::ledger::SlotPlan;
use crate::remote::helper::RemoteHelper;
use crate::remote::helper::RemoteStatus;
use crate::remote::transport::Remote;
use crate::store::local::LocalStore;
use std::collections::BTreeMap;
use std::collections::HashMap;

mod attempt;
mod server;

pub(crate) use attempt::*;
pub(crate) use server::*;

/// THE ONE RECORDED PER-SLOT EXECUTION STATE of a deployment attempt (the
/// review's P2 "rollout state" fix): a slot is EXACTLY ONE of these
/// mutually exclusive states — the order'd execution table is the SINGLE
/// authority the engine derives everything from (which slots advanced /
/// compensated / never advanced / failed, the execution order, display
/// output, and the terminal-status inputs). The old competing authorities
/// (`BatchRun`'s `advanced`/`compensated`/`never_advanced` vectors, the
/// wire outcome rows mutated as the state store) are GONE — a slot can no
/// longer be recorded advanced AND never-advanced, and a post-advance
/// failure can no longer lose the fact that it advanced.
///
/// * [`NotStarted`](SlotExecution::NotStarted) — the attempt never started
///   this slot (skipped under `stop_on_failure`, or a compare-and-swap
///   precondition skip); its post-mutation observation is the LIVE backend
///   state (attached when the terminal inputs are derived).
/// * [`FailedBeforeAdvance`](SlotExecution::FailedBeforeAdvance) — a
///   PRE-SWAP failure (the attempt never mutated the slot); its
///   observation is the LIVE backend state (the never-advanced observation
///   rule — never the desired generation).
/// * [`Advanced`](SlotExecution::Advanced) — swap + activation + verification
///   succeeded; the slot is on the new generation. `bookkeeping_error` is
///   the demotion signal: an otherwise-advanced slot whose committed-
///   transaction record write FAILED is active but not durably bookkept
///   (the attempt cannot finalize `Successful`). The failure-policy pass
///   may still compensate it back (`Restored`).
/// * [`Restored`](SlotExecution::Restored) — the slot advanced then was
///   compensated back to its pre-push state (in-process, or by the
///   failure-policy pass flipping a failed-advance slot); its observation
///   is the generation restored to.
/// * [`FailedAfterAdvance`](SlotExecution::FailedAfterAdvance) — the slot
///   advanced (its `current` moved to the attempt's generation) and was
///   NOT restored: STILL ON the advanced generation — always a remaining
///   change (the review's P1 case: an uncompensated POST-ADVANCE failure
///   must classify degraded, never rolled-back). Its observation is the
///   generation the attempt advanced it to.
/// * [`Indeterminate`](SlotExecution::Indeterminate) — the post-swap
///   outcome is UNKNOWN (the backend cannot confirm whether the mutation
///   stuck): always a remaining change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SlotExecution {
    NotStarted,
    FailedBeforeAdvance {
        error: Option<String>,
    },
    Advanced {
        observation: Observation<ObservedGeneration>,
        /// The demotion signal: `Some` ONLY when the slot advanced but its
        /// committed-transaction record write failed (active, not durably
        /// bookkept) — the push stays intent-only instead of finalizing
        /// `Successful`. NEVER serialized (the wire's `Activated` carries
        /// no error): on the demotion path no terminal is appended.
        bookkeeping_error: Option<String>,
    },
    Restored {
        observation: Observation<ObservedGeneration>,
    },
    FailedAfterAdvance {
        observation: Observation<ObservedGeneration>,
        error: Option<String>,
    },
    Indeterminate {
        error: Option<String>,
    },
}

impl SlotExecution {
    /// THE ADVANCE-REQUIRED COMPENSATION SET: the states the failure-policy
    /// pass compensates (a slot this deployment advanced and did not
    /// already restore): a successful `Advanced` and a `FailedAfterAdvance`
    /// — flipped to `Restored` on a successful compensation, kept under
    /// `leave_changed` or a failed compensation.
    pub(crate) fn is_advanced(&self) -> bool {
        matches!(
            self,
            SlotExecution::Advanced { .. } | SlotExecution::FailedAfterAdvance { .. }
        )
    }

    /// The failure-policy signal: whether the mutation loop hit an error for
    /// this slot — a pre-swap failure, a post-advance failure, an
    /// indeterminate outcome, OR a slot the per-server pipeline compensated
    /// IN-PROCESS (`Restored`: in-process compensation only ever runs after
    /// an activation/verification error — the attempt's mutation failed even
    /// though the slot ended up restored). An `Advanced` slot with a
    /// bookkeeping error is NOT a mutation failure. This DERIVED signal is
    /// what routes the attempt to the failure/terminal-decision path (a
    /// fully-restored failed attempt must still decide its disposition
    /// through the kernel, not the successful finalizer — a compensated
    /// slot's live state no longer matches the planned result).
    pub(crate) fn is_failure(&self) -> bool {
        matches!(
            self,
            SlotExecution::FailedBeforeAdvance { .. }
                | SlotExecution::FailedAfterAdvance { .. }
                | SlotExecution::Indeterminate { .. }
                | SlotExecution::Restored { .. }
        )
    }

    /// Whether the slot was restored/compensated back to its pre-push
    /// state. TEST-ONLY: exercised by the execution-table partition
    /// property; no production consumer needs the summary.
    #[cfg(test)]
    pub(crate) fn is_compensated(&self) -> bool {
        matches!(self, SlotExecution::Restored { .. })
    }

    /// Whether the attempt never advanced the slot (not started, or a
    /// pre-swap failure). TEST-ONLY: exercised by the execution-table
    /// partition property; no production consumer needs the summary.
    #[cfg(test)]
    pub(crate) fn is_never_advanced(&self) -> bool {
        matches!(
            self,
            SlotExecution::NotStarted | SlotExecution::FailedBeforeAdvance { .. }
        )
    }

    /// The FAILED-variant operation error (`None` on the non-failed states).
    pub(crate) fn failed_error(&self) -> Option<&str> {
        match self {
            SlotExecution::FailedBeforeAdvance { error }
            | SlotExecution::FailedAfterAdvance { error, .. }
            | SlotExecution::Indeterminate { error } => error.as_deref(),
            _ => None,
        }
    }

    /// The RECORDED generation of the states whose observation is the swap
    /// result (the `Known` half of `Advanced` / `Restored` /
    /// `FailedAfterAdvance`): the generation the slot was advanced to /
    /// restored to / left on. TEST-ONLY: used by the compensation/rollback
    /// test assertions to compare the recorded generation.
    #[cfg(test)]
    pub(crate) fn observed_generation(&self) -> Option<&GenerationId> {
        match self {
            SlotExecution::Advanced { observation, .. }
            | SlotExecution::Restored { observation }
            | SlotExecution::FailedAfterAdvance { observation, .. } => match observation {
                Observation::Known(og) => Some(&og.generation),
                _ => None,
            },
            _ => None,
        }
    }
}

// ---- batching: deployment-order batch loop ----

// The deployment-order batch loop (A1 deployment semantics).
//
// `run_batches` executes the step-10/11/12 batch loop of the push
// transaction: the SELECTED slots are processed in `batch_size`-sized
// batches in deployment order (the plan's assignment order), each slot via
// [`process_server`], stopping the whole push after
// the first failed batch when `stop_on_failure` is set. Extracted from the
// old `push::engine` spine ([`crate::deploy::push`]); `push_inner` consumes
// the outcome and hands the failure-policy signals to
// [`apply_failure_policy`]. The never-started
// `Skipped` filler that completes the result table lives in
// [`fill_skipped_slots`] (in the results section below).

/// The outcome of one deployment-order batch run: the ordered per-slot
/// EXECUTION TABLE (every SELECTED slot appears — never-started slots are
/// filled as [`SlotExecution::NotStarted`] via [`fill_skipped_slots`]) —
/// the ONE authority the failure-policy pass, the post-observation pass,
/// the display output, and the terminal-status inputs derive from. The old
/// competing authorities (results rows + `advanced`/`compensated`/
/// `never_advanced` signal vectors) are GONE; every summary is DERIVED
/// from this table ([`SlotExecution::is_advanced`] / `is_compensated` /
/// `is_never_advanced` / `is_failure`, and `had_failure`).
pub(crate) struct BatchRun {
    pub(crate) executions: BTreeMap<SlotId, SlotExecution>,
}

// 16 parameters: one batch run is the full per-slot publication context
// (data: assignments, behavior index, plan/statuses/generations, the
// already-open remotes/helpers; policy: batch_size, stop_on_failure) plus
// the deployment identity. Bundling the policy half into one settings struct
// is a dedicated refactor (deferred: `run_batches` is a straight extraction
// of the `push_inner` batch loop — the allow documents the deliberate
// choice, mirroring `push_inner` itself).
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_batches(
    assignments: &[PlannedAssignment],
    behavior_index: &BehaviorIndex,
    members: &[(&SlotConfig, &ServerDef)],
    config: &ProjectConfig,
    target_name: &str,
    store: &LocalStore,
    remotes: &HashMap<SlotId, Box<dyn Remote>>,
    helpers: &HashMap<SlotId, RemoteHelper>,
    _statuses: &HashMap<SlotId, RemoteStatus>,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
    plan_servers: &BTreeMap<SlotId, SlotPlan>,
    new_gen: &HashMap<SlotId, GenerationId>,
    servers_order: &[SlotId],
    batch_size: usize,
    stop_on_failure: bool,
) -> Result<BatchRun> {
    let mut executions: BTreeMap<SlotId, SlotExecution> = BTreeMap::new();

    let mut idx = 0;
    'batches: while idx < servers_order.len() {
        let end = (idx + batch_size).min(servers_order.len());
        for sid in &servers_order[idx..end] {
            let a = assignments
                .iter()
                .find(|x| &x.placement_slot == sid)
                .unwrap();
            // Select the assigned slot's OWN (release, variant) frozen
            // behavior contract (never the caller's current variant file, and
            // never another release's contract) before
            // activation/verification. Coverage was validated before any
            // remote mutation, so a miss here is an internal invariant
            // violation: record a per-slot failure instead of panicking.
            let Some(variant_behavior) = behavior_index
                .get(&a.artifact.release)
                .and_then(|m| m.get(a.artifact.variant.as_str()))
            else {
                executions.insert(
                    sid.clone(),
                    SlotExecution::FailedBeforeAdvance {
                        error: Some(format!(
                            "internal: no behavior contract for variant '{}' after coverage check",
                            a.artifact.variant
                        )),
                    },
                );
                if stop_on_failure {
                    break 'batches;
                }
                continue;
            };
            let variant_behavior_sha =
                crate::verify::release::behavior_contract_digest(variant_behavior);
            let vars = slot_vars(
                members,
                config,
                target_name,
                sid,
                &a.artifact,
                Some(deployment_id),
                Some(&new_gen[sid]),
            )?;
            let outcome = process_server(
                store,
                remotes[sid].as_ref(),
                &helpers[sid],
                op_id,
                deployment_id,
                target_name,
                &a.artifact,
                &new_gen[sid],
                plan_servers[sid].expected_generation.as_ref(),
                variant_behavior,
                &variant_behavior_sha,
                &vars,
                config,
            )?;
            let ServerProc { state } = outcome;
            executions.insert(sid.clone(), state);
            if executions.get(sid).is_some_and(SlotExecution::is_failure) && stop_on_failure {
                break 'batches;
            }
        }
        idx = end;
    }

    // Any slot never started (e.g. skipped after an earlier failure under
    // stop_on_failure) still appears in the attempt's execution table as
    // `NotStarted`; its post-mutation OBSERVATION (the reconciled current
    // state) is attached when the terminal inputs are derived. The filler
    // lives in [`fill_skipped_slots`] (the result-table shaping module).
    fill_skipped_slots(&mut executions, assignments);
    Ok(BatchRun { executions })
}

#[cfg(test)]
mod tests_slot_executions {
    use super::*;
    use crate::identity::test_generation_id;
    use crate::ledger::records::{ObservationError, ObservedGeneration};
    #[cfg(test)]
    use proptest::prelude::*;
    #[cfg(test)]
    use proptest::test_runner::RngSeed;

    fn slot(i: u32) -> SlotId {
        SlotId::new(format!("slot-{i}"))
    }

    /// An arbitrary THREE-STATE observation (the recorded/live evidence the
    /// states carry or later attach).
    fn arbitrary_observation() -> impl Strategy<Value = Observation<ObservedGeneration>> {
        prop_oneof![
            (0u32..6).prop_map(|i| Observation::Known(ObservedGeneration {
                generation: test_generation_id(&format!("obs-{i}"))
            })),
            Just(Observation::KnownAbsent),
            prop::sample::select(vec![
                "status read failed: boom".to_string(),
                "assignment read failed: boom".to_string(),
            ])
            .prop_map(|e| Observation::Unknown(ObservationError { message: e })),
        ]
    }

    /// An arbitrary execution state: every one of the SIX mutually exclusive
    /// states (with/without an error on the failed states).
    fn arbitrary_execution() -> impl Strategy<Value = SlotExecution> {
        prop_oneof![
            Just(SlotExecution::NotStarted),
            prop::sample::select(vec![
                "swap failed: boom".to_string(),
                "publish failed: boom".to_string(),
            ])
            .prop_map(|e| SlotExecution::FailedBeforeAdvance { error: Some(e) }),
            arbitrary_observation().prop_map(|observation| SlotExecution::Advanced {
                observation,
                bookkeeping_error: None,
            }),
            arbitrary_observation().prop_map(|observation| SlotExecution::Restored { observation }),
            (arbitrary_observation(), prop::bool::ANY).prop_map(|(observation, has_error)| {
                SlotExecution::FailedAfterAdvance {
                    observation,
                    error: has_error.then(|| "activation failed: boom".to_string()),
                }
            }),
            prop::sample::select(vec![
                "union unknown: no current".to_string(),
                "state unknown: no assignment".to_string(),
            ])
            .prop_map(|e| SlotExecution::Indeterminate { error: Some(e) }),
        ]
    }

    /// An arbitrary ORDERED execution table: a generated slot list (each
    /// key appearing EXACTLY once) zipped with arbitrary executions.
    fn arbitrary_execution_table()
    -> impl Strategy<Value = (Vec<SlotId>, BTreeMap<SlotId, SlotExecution>)> {
        prop::collection::btree_set((0u32..6).prop_map(slot), 1..=5).prop_flat_map(|keys| {
            let keys: Vec<SlotId> = keys.into_iter().collect();
            let n = keys.len();
            prop::collection::vec(arbitrary_execution(), n)
                .prop_map(move |execs| (keys.clone(), keys.iter().cloned().zip(execs).collect()))
        })
    }

    /// THE EXECUTION-TABLE CONSISTENCY PROPERTY (the review's acceptance
    /// item 4.1): every DERIVED VIEW of the table partitions the generated
    /// slots consistently — NO OVERLAP (a slot can never be both advanced
    /// AND never-advanced) and NO OMISSION (every slot classified exactly
    /// once) — and the derived `failed`/`had_failure` sets and the
    /// order-preserving iteration agree with the states.
    fn run_execution_table_case(keys: Vec<SlotId>, table: BTreeMap<SlotId, SlotExecution>) {
        // NO OMISSION + EXACTLY ONCE: the table covers every generated
        // slot, and iterating it (the deterministic table order) yields
        // each slot exactly once.
        assert_eq!(
            table.len(),
            keys.len(),
            "every generated slot appears exactly once in the execution table"
        );
        let order: Vec<&SlotId> = table.keys().collect();
        assert_eq!(
            order
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            keys.len(),
            "the table iteration visits each slot exactly once (order-preserving)"
        );

        // THE PARTITION: each slot is in EXACTLY ONE of the four mutually
        // exclusive classes — advanced (Advanced | FailedAfterAdvance),
        // compensated (Restored), never-advanced (NotStarted |
        // FailedBeforeAdvance), indeterminate — pairwise disjoint, union =
        // every slot.
        let mut partitions: Vec<Vec<&SlotId>> =
            vec![Vec::new(), Vec::new(), Vec::new(), Vec::new()];
        let mut failed: Vec<&SlotId> = Vec::new();
        let mut had_failure = false;
        for (sid, e) in table.iter() {
            if e.is_advanced() {
                partitions[0].push(sid);
            } else if e.is_compensated() {
                partitions[1].push(sid);
            } else if e.is_never_advanced() {
                partitions[2].push(sid);
            } else {
                assert!(
                    matches!(e, SlotExecution::Indeterminate { .. }),
                    "the fourth class is exactly Indeterminate, got {e:?}"
                );
                partitions[3].push(sid);
            }
            if matches!(
                e,
                SlotExecution::FailedBeforeAdvance { .. }
                    | SlotExecution::FailedAfterAdvance { .. }
                    | SlotExecution::Indeterminate { .. }
            ) {
                failed.push(sid);
            }
            had_failure |= e.is_failure();
        }
        assert_eq!(
            partitions.iter().map(|p| p.len()).sum::<usize>(),
            table.len(),
            "every slot is classified exactly once (no omission, no overlap)"
        );
        // NO OVERLAP: the four classes are pairwise disjoint by construction
        // of the state enum — assert it for the advanced/never-advanced
        // contradiction the old vectors allowed.
        for sid in table.keys() {
            let e = &table[sid];
            assert!(
                !(e.is_advanced() && e.is_never_advanced()),
                "a slot can never be both advanced AND never-advanced: {e:?}"
            );
            assert!(
                !(e.is_advanced() && e.is_compensated()),
                "a slot can never be both advanced AND compensated: {e:?}"
            );
            assert!(
                !(e.is_never_advanced() && e.is_compensated()),
                "a slot can never be both never-advanced AND compensated: {e:?}"
            );
        }
        // The failed view is a subset of the non-compensated partition, and
        // had_failure == any failed OR compensated state (a Restored slot
        // also records a mutation failure — in-process compensation only
        // runs after an error).
        let failed_set: std::collections::BTreeSet<&SlotId> = failed.iter().cloned().collect();
        assert_eq!(
            failed_set.len(),
            failed.len(),
            "the failed view lists each slot once"
        );
        assert_eq!(
            had_failure,
            table.iter().any(|(_, e)| {
                matches!(
                    e,
                    SlotExecution::FailedBeforeAdvance { .. }
                        | SlotExecution::FailedAfterAdvance { .. }
                        | SlotExecution::Indeterminate { .. }
                        | SlotExecution::Restored { .. }
                )
            }),
            "had_failure is derived from the table: any failure OR compensated state"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 32,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]
        #[test]
        fn execution_table_derived_views_partition_consistently(
            (keys, table) in arbitrary_execution_table(),
        ) {
            run_execution_table_case(keys, table);
        }
    }
}
