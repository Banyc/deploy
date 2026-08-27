//! EXECUTION SEMANTICS: the per-slot rollout machinery.
//!
//! Nested along the execution concerns: this module holds the
//! deployment-order batch loop ([`run_batches`], [`BatchRun`]); [`attempt`]
//! the per-attempt outcome derivation (failure policies, result shaping,
//! status/disposition); [`server`] the per-server mutation pipeline and its
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
use crate::ledger::SlotOutcomeKind;
use crate::ledger::SlotPlan;
use crate::ledger::SlotResult;
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

/// The outcome of one deployment-order batch run: the per-slot results
/// (every SELECTED slot appears — never-started slots are filled as
/// `Skipped` with their reconciled current assignment via
/// [`fill_skipped_slots`]), plus the failure-policy signals: which slots this
/// deployment advanced, which compensated, which never advanced (pre-swap
/// failure or compare-and-swap skip), and whether any slot failed.
pub(crate) struct BatchRun {
    pub(crate) results: BTreeMap<SlotId, SlotResult>,
    pub(crate) advanced: Vec<SlotId>,
    pub(crate) compensated: Vec<SlotId>,
    pub(crate) never_advanced: Vec<SlotId>,
    pub(crate) had_failure: bool,
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
    statuses: &HashMap<SlotId, RemoteStatus>,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
    plan_servers: &BTreeMap<SlotId, SlotPlan>,
    new_gen: &HashMap<SlotId, GenerationId>,
    servers_order: &[SlotId],
    batch_size: usize,
    stop_on_failure: bool,
) -> Result<BatchRun> {
    let mut results: BTreeMap<SlotId, SlotResult> = BTreeMap::new();
    let mut advanced: Vec<SlotId> = Vec::new();
    let mut compensated: Vec<SlotId> = Vec::new();
    // Pre-swap failures (never advanced): the slot's outcome records the
    // ACTUAL observed generation (the post-mutation status read below),
    // never the desired one — the outcome's generation field is the observed
    // post-state the remaining-changes derivation compares against pre_push.
    let mut never_advanced: Vec<SlotId> = Vec::new();
    let mut had_failure = false;

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
                had_failure = true;
                results.insert(
                    sid.clone(),
                    SlotResult {
                        slot_id: sid.clone(),
                        outcome: SlotOutcomeKind::Failed,
                        generation: Some(new_gen[sid].clone()),
                        compensated: false,
                        error: Some(format!(
                            "internal: no behavior contract for variant '{}' after coverage check",
                            a.artifact.variant
                        )),
                        observation_error: None,
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
            let ServerProc {
                kind,
                generation,
                did_advance,
                did_compensate,
                error,
            } = outcome;
            if kind == SlotOutcomeKind::Failed {
                had_failure = true;
            }
            if did_compensate {
                compensated.push(sid.clone());
            } else if did_advance {
                // Any slot this deployment advanced — Activated, or a
                // post-swap failure whose compensation failed — remains a
                // "still-advanced" server for the failure-policy pass and the
                // status decision. Pre-swap failures (never advanced) are NOT
                // included: for them `advanced.is_empty()` correctly yields
                // `FailedRolledBack` (nothing to roll back).
                advanced.push(sid.clone());
            } else {
                // A pre-swap failure (never advanced) or a compare-and-swap
                // skip: the slot's outcome records the ACTUAL observed
                // generation (the post-mutation status read below), never the
                // desired one.
                never_advanced.push(sid.clone());
            }
            results.insert(
                sid.clone(),
                SlotResult {
                    slot_id: sid.clone(),
                    outcome: kind,
                    generation: Some(generation),
                    compensated: did_compensate,
                    error,
                    observation_error: None,
                },
            );
            if had_failure && stop_on_failure {
                break 'batches;
            }
        }
        idx = end;
    }

    // Any slot never started (e.g. skipped after an earlier failure under
    // stop_on_failure) still appears in the attempt, with its reconciled
    // current assignment rather than a generated desired generation. The
    // filler lives in [`fill_skipped_slots`] (the
    // result-table shaping module).
    fill_skipped_slots(&mut results, assignments, statuses);
    Ok(BatchRun {
        results,
        advanced,
        compensated,
        never_advanced,
        had_failure,
    })
}
