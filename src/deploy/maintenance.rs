//! Post-commit maintenance wiring shared by the real-push path (step 17)
//! and the no-op path (A4 retention/sweep semantics; A7 hidden debt wiring).
//!
//! * `retain_slot_post_commit` + `run_step17_retention` — the step-17
//!   per-slot retention contract (A4 "post-commit step-17 retention": never
//!   fails the push — a failure or a contended slot lock defers the slot as
//!   a durable debt marker + a warning, never a silent skip).
//! * `retry_deferred_retentions` / `retry_pending_sweep` — the
//!   deferred-maintenance retry + THE RECONCILIATION (A4
//!   "deferred-retention retry" + the P2 fix): later pushes — real and
//!   no-op — service the debt markers, and the global sweep reconciliation
//!   runs on EVERY push REGARDLESS of any sweep-debt marker (the marker is
//!   triage-only: it decides HOW the reconciliation proceeds, never WHETHER
//!   it runs — a missing/failed marker write can never skip the owed
//!   maintenance forever). The push report's `warning` channel surfaces
//!   what stayed deferred.
//! * `refresh_observed_from_live` / `refresh_observed` — the observed
//!   refresh projection: the real-push path feeds the actual post-mutation
//!   state, the no-op path feeds the EXISTING generation's assignment —
//!   both run the same `refresh_observed` block.
//! * `set_retention_deferred` / `clear_retention_deferred` — the
//!   durable debt-marker I/O (A7 "durable debt wiring":
//!   `retention-debt.json` / `sweep-debt.json`), NON-FALLIBLE by contract:
//!   a debt I/O failure becomes a warning entry, never an `Err`.
//!
//! The push spine ([`crate::deploy::push::push`]) wires this module into step 17
//! of `push_inner`; the no-op path ([`push`](mod@crate::deploy::push)) services the
//! same debt before reporting "Everything up to date".

use crate::config::{ProjectConfig, RetentionConfig};
use crate::error::Result;
use crate::identity::{DeploymentId, OperationId, SlotId, TargetName};
use crate::ledger::{ObservationError, ObservedAssignment, ObservedSlot};
use crate::remote::helper::RemoteHelper;
use crate::retention::compute_retained;
use crate::store::local::LocalStore;
use crate::store::local::debt::SweepDebt;
#[cfg(test)]
use crate::testutil::step17_hook::HookPhase;
use std::collections::{BTreeMap, HashMap, HashSet};

/// The step-17 per-slot retention loop the push spine runs AFTER the
/// deployment durably committed (finalization). Post-commit maintenance,
/// never a push failure — the contract is structural in
/// [`retain_slot_post_commit`] (a failure or a contended slot lock defers
/// the slot as a durable debt marker + a warning, never a silent skip).
/// The no-op path creates no records and skips step 17, so it services the
/// same debt via [`retry_deferred_retentions`] / [`retry_pending_sweep`]
/// instead.
// 8 parameters: one slot set's full step-17 maintenance context (store,
// config, target_name, helpers, servers_order, op_id, deployment_id) plus
// the shared `maintenance` warning channel; bundling them would obscure the
// per-slot-owned-policy contract, so the allow documents the deliberate
// choice (mirrors `retain_slot_post_commit` and `push_inner`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_step17_retention(
    store: &LocalStore,
    config: &ProjectConfig,
    target_name: &str,
    helpers: &HashMap<SlotId, RemoteHelper>,
    servers_order: &[SlotId],
    op_id: &OperationId,
    deployment_id: &DeploymentId,
    maintenance: &mut Vec<String>,
) {
    for sid in servers_order {
        // The slot's ONE retention policy, from its OWNING VARIANT (the
        // variant that declares the slot) — never a member-target union.
        let slot_retention = config
            .slot_retention(sid.as_str())
            .expect("every planned slot is declared by some variant");
        retain_slot_post_commit(
            store,
            config,
            target_name,
            &helpers[sid],
            sid,
            slot_retention,
            op_id,
            deployment_id,
            maintenance,
        );
        // Clean up this deployment's incoming directory. Best-effort by
        // design: the push already succeeded, so a leftover here cannot change
        // the reported outcome, and the next push's reconciliation removes
        // abandoned incoming dirs explicitly. The mutation lock itself needs
        // no cleanup here: `retain_slot_post_commit` held it through its own
        // RAII guard (released on every return path), and a stale lock file
        // is a LEASE that expires and is broken harmlessly next time — it can
        // never block the slot.
        helpers[sid].remove_incoming(deployment_id.as_str()).ok();
    }
}

/// Step-17 per-slot retention, run as POST-COMMIT maintenance: the
/// deployment already durably committed, so this NEVER fails the push — a
/// retention failure (or a contended slot lock) defers the slot as a durable
/// debt marker + a warning, never a silent skip. `slot_retention` is the
/// slot's ONE policy, already resolved by the caller from its OWNING VARIANT
/// (never a per-target union); the RAII mutation lock guards the whole block.
// The 9 parameters are one slot's full per-slot maintenance context (store,
// config, target_name, helper, sid, slot_retention, op_id, deployment_id)
// plus the shared `maintenance` warning channel; bundling them would obscure
// the slot-owned-policy contract this signature enforces, so the allow
// documents the deliberate choice rather than a band-aid (mirrors
// `push_inner`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn retain_slot_post_commit(
    store: &LocalStore,
    config: &ProjectConfig,
    target_name: &str,
    helper: &RemoteHelper,
    sid: &SlotId,
    slot_retention: &RetentionConfig,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
    maintenance: &mut Vec<String>,
) {
    // TEST-ONLY step-17 phase hook: when a test armed the barrier for
    // THIS deployment id, signal "at step-17 lock acquisition" (with the
    // FRESH-STEP-17 phase — this push's own per-slot retention, whose
    // contended else-branch defers the maintenance as a debt marker) and
    // park until the test releases the engine (the fixture holds the
    // competing guard meanwhile) — per-slot lock contention becomes
    // DETERMINISTIC, with no thread racing the lock file. A no-op in
    // production builds (both this call and the store method are
    // `#[cfg(test)]`) and in unarmed tests.
    #[cfg(test)]
    store.step17_hook_barrier(deployment_id, HookPhase::FreshStep17);
    if let Ok(_guard) = helper.acquire_lock_guard(op_id) {
        match rotate_slot_locked(helper, store, config, slot_retention, deployment_id) {
            Ok(()) => {
                maintenance.extend(clear_retention_deferred(store, target_name, sid));
            }
            Err(e) => {
                maintenance.extend(set_retention_deferred(
                    store,
                    target_name,
                    sid,
                    &e.to_string(),
                ));
                maintenance.push(format!(
                    "retention deferred for slot '{}': {e}",
                    sid.as_str()
                ));
            }
        }
    } else {
        maintenance.push(format!(
            "retention deferred for slot '{}': slot lock held by another operation",
            sid.as_str()
        ));
        maintenance.extend(set_retention_deferred(
            store,
            target_name,
            sid,
            "slot lock held by another operation",
        ));
    }
}

/// Run one slot's retention — retained-set computation plus mark-and-sweep —
/// for a caller already holding the slot's mutation lock (RAII guard). The
/// single retention block shared by step 17 and by deferred-maintenance
/// retries, so both paths apply the same retention semantics and the same
/// lock discipline. `deployment_id` marks this operation's incoming
/// directory as active so retention never sweeps a deployment currently being
/// published. `retention` is the slot's ONE policy, already resolved from its
/// OWNING VARIANT by the caller (`ProjectConfig::slot_retention`) — retention is
/// slot-owned, never a per-target surface. Pins are the config's own pins
/// (policy lives in the caller-supplied `config` settings object, never a
/// separate argument).
fn rotate_slot_locked(
    helper: &RemoteHelper,
    store: &LocalStore,
    config: &ProjectConfig,
    retention: &RetentionConfig,
    deployment_id: &DeploymentId,
) -> Result<()> {
    let retained = compute_retained(helper, config.pins(), store, retention)?;
    let active_incoming = HashSet::from([deployment_id.as_str().to_string()]);
    helper.rotate(&retained, &active_incoming)?;
    Ok(())
}

/// Record a deferred-retention debt marker for one slot (keyed by
/// target+slot). Called only when the retention failed after the deployment
/// already committed — POST-COMMIT MAINTENANCE, so this function is
/// NON-FALLIBLE: every debt I/O failure (a read or write of the marker file)
/// becomes a WARNING returned here (merged into the report's `maintenance`
/// channel by the caller), never an `Err`. On a read failure the write is
/// skipped entirely — writing a map built from scratch would silently drop
/// the OTHER slots' existing markers — and the returned warning names the
/// deferral, so the maintenance is explicitly warned even though this slot's
/// marker was not persisted.
pub(crate) fn set_retention_deferred(
    store: &LocalStore,
    target: &str,
    slot: &SlotId,
    reason: &str,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut debt = match store.read_retention_debt(target) {
        Ok(debt) => debt,
        Err(e) => {
            warnings.push(format!(
                "retention debt maintenance deferred: failed to read retention debt for \
                 '{target}': {e}"
            ));
            return warnings;
        }
    };
    debt.insert(slot.as_str().to_string(), reason.to_string());
    if let Err(e) = store.write_retention_debt(target, &debt) {
        warnings.push(format!(
            "retention debt maintenance deferred: failed to write retention debt for \
             '{target}': {e}"
        ));
    }
    warnings
}

/// Clear a slot's deferred-retention debt marker once the retention succeeded.
/// POST-COMMIT MAINTENANCE, so this is NON-FALLIBLE: a debt read failure
/// leaves the marker in place (a later push retries it) and a write/remove
/// failure keeps the stale marker — both become WARNING entries returned to
/// the caller (merged into the report's `maintenance` channel), never an
/// `Err`.
fn clear_retention_deferred(store: &LocalStore, target: &str, slot: &SlotId) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut debt = match store.read_retention_debt(target) {
        Ok(debt) => debt,
        Err(e) => {
            warnings.push(format!(
                "retention debt maintenance deferred: failed to read retention debt for \
                 '{target}': {e}"
            ));
            return warnings;
        }
    };
    if debt.remove(slot.as_str()).is_some()
        && let Err(e) = store.write_retention_debt(target, &debt)
    {
        warnings.push(format!(
            "retention debt maintenance deferred: failed to clear retention debt for \
             '{target}': {e}"
        ));
    }
    warnings
}

/// Rebuild `target_name`'s observed projection from each member slot's LIVE
/// remote assignment only (the per-slot `helpers` — never the desired plan
/// and never a deployment id: untouched slots keep the live assignment's own
/// minting deployment). Refreshes each slot's ONE physical record and returns
/// the projection with warning-only failures — NON-FALLIBLE, since the
/// deployment already durably committed (lag converges next push, no marker).
pub(crate) fn refresh_observed_from_live(
    store: &LocalStore,
    target_name: &str,
    members: &[(&crate::config::SlotConfig, &crate::config::ServerDef)],
    helpers: &HashMap<SlotId, RemoteHelper>,
) -> (BTreeMap<SlotId, ObservedSlot>, Vec<String>) {
    let mut observed_servers: BTreeMap<SlotId, ObservedSlot> = BTreeMap::new();
    for (slot, _sdef) in members {
        let slot_id = SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment");

        // The slot's LIVE remote assignment. `status` is a read; under the
        // one-shot pre-swap arm it has already fired and been consumed inside
        // `process_server`, so this read reflects the true post-mutation
        // state: the new generation for an advanced slot, the PRIOR
        // generation for a skipped/unreachable one.
        let status = helpers[&slot_id].status();
        match status {
            Ok(s) => match s.current_generation {
                Some(g) => match helpers[&slot_id].read_assignment(g.as_str()) {
                    Ok(asn) => {
                        observed_servers.insert(
                            slot_id.clone(),
                            ObservedSlot {
                                assignment: ObservedAssignment::Known {
                                    generation: asn.generation_id.clone(),
                                    artifact: asn.artifact.clone(),
                                    last_deployment: asn.deployment_id.clone(),
                                },
                            },
                        );
                    }
                    Err(_) => {
                        // The generation is observed but its assignment
                        // cannot be read (missing/corrupt): the observed
                        // state is `AssignmentUnknown` — the generation is
                        // known, the artifact is NOT (never a fabricated
                        // artifact, never a stale prior record presented as
                        // current). The error preserves the read failure.
                        let error = ObservationError {
                            message: format!("assignment read failed for {g}"),
                        };
                        observed_servers.insert(
                            slot_id.clone(),
                            ObservedSlot {
                                assignment: ObservedAssignment::AssignmentUnknown {
                                    generation: g,
                                    error,
                                },
                            },
                        );
                    }
                },
                None => {
                    // The read succeeded showing no state: the slot has no
                    // observed state (never deployed, or rotated away). A
                    // LIVE ABSENCE REPLACES a stale physical record — record
                    // `Absent` EXPLICITLY so the write path below CLOBBERS
                    // any prior generation/artifact/deployment: the slot has
                    // no state, and a stale prior record must never be
                    // presented as current.
                    observed_servers.insert(
                        slot_id.clone(),
                        ObservedSlot {
                            assignment: ObservedAssignment::Absent,
                        },
                    );
                }
            },
            Err(e) => {
                // THE OBSERVATION FAILED: a failed status read is NOT
                // evidence of no change — the slot may have changed; the
                // failure just means we cannot see it. Record
                // `Unknown(error)` (never the prior record, which would
                // claim "unchanged").
                observed_servers.insert(
                    slot_id.clone(),
                    ObservedSlot {
                        assignment: ObservedAssignment::Unknown {
                            error: ObservationError {
                                message: format!("status read failed: {e}"),
                            },
                        },
                    },
                );
            }
        }
    }
    let mut observed_warnings: Vec<String> = Vec::new();
    refresh_observed(
        store,
        target_name,
        members,
        &observed_servers,
        &mut observed_warnings,
    );
    (observed_servers, observed_warnings)
}

/// Refresh `observed.json` for `target_name`'s member slots from a
/// caller-supplied per-slot projection: each slot's ONE physical record
/// (`slots/<slot-id>/observed.json`) is written EXACTLY ONCE, never once per
/// target — targets are selection views over the global slot map, so a
/// slot's single record serves its OWNING target's `read_observed` view.
/// Every store fault is WARNING-ONLY (pushed into `observed_warnings`,
/// merged into the report's `maintenance` channel): the refresh runs after
/// the deployment durably committed, so it must never change the push's
/// reported outcome — this function NEVER returns `Err`.
///
/// The single source of truth for the observed refresh: the REAL-push path
/// (which feeds the actual post-mutation state via
/// [`refresh_observed_from_live`]) and the NO-OP path (which feeds the
/// EXISTING generation's assignment, since an up-to-date push creates no
/// records) both run this exact block, so a slot's physical record is
/// refreshed identically by whichever path last touched it. A member slot
/// with no entry in `observed_servers` keeps its prior physical record
/// untouched.
pub(crate) fn refresh_observed(
    store: &LocalStore,
    target_name: &str,
    members: &[(&crate::config::SlotConfig, &crate::config::ServerDef)],
    observed_servers: &BTreeMap<SlotId, ObservedSlot>,
    observed_warnings: &mut Vec<String>,
) {
    for (slot, sdef) in members {
        let slot_id = SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment");

        let Some(observed_server) = observed_servers.get(&slot_id) else {
            continue;
        };
        if let Err(e) = store.write_server(&crate::ledger::ServerState {
            id: crate::identity::ServerId::parse(sdef.id.as_str())
                .expect("validated server id is a safe segment"),
            last_seen_target: Some(
                TargetName::parse(target_name).expect("target name is a safe segment"),
            ),
            last_observed: Some(observed_server.clone()),
        }) {
            // The durable facts are recorded; only the per-server projection
            // is stale. Warn and continue — a later push's refresh rewrites it.
            observed_warnings.push(format!(
                "observed refresh deferred for server '{}': {e}",
                sdef.id.as_str()
            ));
        }
        // ONE physical write per slot — the slot's own observed record. A
        // slot belongs to EXACTLY ONE owning target, so the slot's record and
        // its owning target's view agree by construction — no per-target
        // propagation is needed (or possible) anymore.
        if let Err(e) = store.write_slot_observed(&slot_id, observed_server) {
            // A fault leaves only THIS slot's physical record stale — its
            // OWNING target's view of it lags. The next real push
            // re-projects from durable facts, so convergence needs no marker.
            observed_warnings.push(format!(
                "observed refresh deferred for slot '{}': {e}",
                slot_id.as_str()
            ));
        }
    }
}

/// Retry deferred post-commit retention maintenance for `target_name`: every slot
/// carrying a debt marker gets its retention re-attempted under the slot's
/// mutation lock (the same RAII-guarded block as step 17). Success clears the
/// marker; failure keeps it and refreshes its reason. Runs on later pushes —
/// before step 17 on the normal path and at the no-op return — because
/// retention is maintenance that must never change a deployment's reported
/// outcome. NON-FALLIBLE by contract: this function never returns `Err` — a
/// debt I/O failure (a read treated as empty debt, or a write/remove of the
/// marker) becomes a WARNING entry in the returned vec, so a debt-file fault
/// can never turn a push (real or no-op) into an error after the deployment
/// durably committed. Returns the slots still deferred, for the push report's
/// warning.
pub(crate) fn retry_deferred_retentions(
    store: &LocalStore,
    config: &ProjectConfig,
    target_name: &str,
    helpers: &HashMap<SlotId, RemoteHelper>,
    op_id: &OperationId,
    deployment_id: &DeploymentId,
) -> Vec<String> {
    // A debt READ failure is treated as empty debt: nothing can be serviced
    // this push, and the marker file (if any) is left untouched for a later
    // push to retry — the warning keeps the deferral explicit.
    let mut debt = match store.read_retention_debt(target_name) {
        Ok(debt) => debt,
        Err(e) => {
            return vec![format!(
                "retention debt maintenance deferred: failed to read retention debt for \
                 '{target_name}': {e}"
            )];
        }
    };
    if debt.is_empty() {
        return Vec::new();
    }
    let mut still_deferred: Vec<String> = Vec::new();
    let mut serviced: Vec<String> = Vec::new();
    for slot_str in debt.keys().cloned().collect::<Vec<_>>() {
        let sid = SlotId::parse(&slot_str).expect("rotation debt slot id is a safe segment");

        let Some(helper) = helpers.get(&sid) else {
            // The slot is no longer a member of this target, so its retention
            // cannot be serviced from here; keep the marker and say so.
            still_deferred.push(format!(
                "retention still deferred for slot '{slot_str}' (no longer a member of target \
                 '{target_name}')"
            ));
            continue;
        };
        // TEST-ONLY phase hook: the deferred-maintenance retry shares the
        // same RAII-guarded retention block as step 17, so it signals + parks
        // at the SAME barrier, tagged with the DEFERRED-RETRY phase (it runs
        // BEFORE the fresh step-17 retention and reads the debt FIRST — a test
        // that arms the debt fault only at the fresh step-17 phase therefore
        // does NOT arm it here). A test that armed the step-17 hook for this
        // deployment id gets deterministic contention at the retry too (the
        // no-op path reaches a step-17-equivalent lock acquisition only
        // here). A no-op in production builds and unarmed tests.
        #[cfg(test)]
        store.step17_hook_barrier(deployment_id, HookPhase::DeferredRetry);
        if let Ok(_guard) = helper.acquire_lock_guard(op_id) {
            // The slot's ONE retention policy, from its OWNING VARIANT
            // (resolved from the current config — retention is never a
            // member-target union).
            let slot_retention = match config.slot_retention(slot_str.as_str()) {
                Ok(retention) => retention,
                Err(e) => {
                    // The slot is no longer declared by any variant: its
                    // retention cannot be serviced from here; keep the marker
                    // and say so.
                    still_deferred.push(format!(
                        "retention still deferred for slot '{slot_str}': {e}"
                    ));
                    continue;
                }
            };
            match rotate_slot_locked(helper, store, config, slot_retention, deployment_id) {
                Ok(()) => serviced.push(slot_str.clone()),
                Err(e) => {
                    // Keep the marker with the fresh reason.
                    debt.insert(slot_str.clone(), e.to_string());
                    still_deferred.push(format!(
                        "retention still deferred for slot '{slot_str}': {e}"
                    ));
                }
            }
        } else {
            still_deferred.push(format!(
                "retention still deferred for slot '{slot_str}': slot lock held by another \
                 operation"
            ));
        }
    }
    for s in &serviced {
        debt.remove(s);
    }
    // A debt WRITE/REMOVE failure (the marker could not be persisted or
    // removed) is post-commit maintenance: warn and leave the marker file as
    // it is — the retention itself succeeded, but a later push retries and
    // converges. Never an `Err`.
    if let Err(e) = store.write_retention_debt(target_name, &debt) {
        still_deferred.push(format!(
            "retention debt maintenance deferred: failed to write retention debt for \
             '{target_name}': {e}"
        ));
    }
    still_deferred
}

/// Retry the store-global PENDING SWEEP — THE RECONCILIATION (the P2 fix):
/// runs on EVERY push — real and no-op — REGARDLESS of any debt marker. The
/// marker is TRIAGE-ONLY: it decides HOW the reconciliation proceeds — an
/// [`crate::store::local::debt::SweepDebt::AwaitingCheckpointDurability`]
/// marker confines this pass to the durability-confirming rewrite; a
/// [`crate::store::local::debt::SweepDebt::Ready`] marker (or NO marker)
/// runs the full sweep pass — never WHETHER work is attempted. A missing or
/// failed marker write can NEVER cause the owed maintenance to be skipped
/// forever: the next push reconciles again anyway.
///
/// The sweep pass recomputes reachability FRESH under ONE locked
/// [`crate::retention::reachability::history_floor::ReachabilitySnapshot`]
/// (no persisted deletion worklist, fail-closed — never against a partial
/// retained set), and the marker is written ONLY as the retry-triage record
/// (cleared once the sweep completes). On a marker WRITE failure, the
/// CURRENT call still performed the reconciliation — nothing is left
/// waiting on the marker for this push; a later push reconciles again
/// anyway. NON-FALLIBLE by contract: this function never returns `Err` — a
/// debt read failure (which STILL runs the reconciliation) or a
/// write/remove failure of the marker becomes a WARNING entry in the
/// returned vec, so a debt-file fault can never turn a push (real or no-op)
/// into an error after the deployment durably committed. Returns the
/// pending-sweep warnings for the push report's maintenance channel.
///
/// THE DURABILITY GATE (the P1 fix): the marker is TYPED, two-state.
/// [`SweepDebt::Ready`] means the triggering checkpoint's ledger replace is
/// DURABLE — the sweep may run. [`SweepDebt::AwaitingCheckpointDurability`]
/// means the ledger replace is VISIBLE but its durability is UNCONFIRMED —
/// the sweep MUST NOT run (a crash could restore an OLDER, longer ledger
/// that still references below-floor history already deleted by the sweep):
/// the ONLY thing this pass may do is the durability-confirming rewrite, and
/// the sweep is deferred to the pass that reads the marker as `Ready` (the
/// next push — which reconciles regardless of the marker).
pub(crate) fn retry_pending_sweep(
    store: &LocalStore,
    config: &ProjectConfig,
    anchor: &str,
) -> Vec<String> {
    // A debt READ failure fails closed (the marker must never read as "no
    // debt") — but the reconciliation STILL runs: only the triage is lost.
    // The warning keeps the read failure explicit.
    let pending = match store.read_sweep_debt() {
        Ok(p) => p,
        Err(e) => {
            let mut w = vec![format!(
                "sweep debt maintenance deferred: failed to read sweep debt: {e}"
            )];
            w.extend(reconcile_sweep_pass(store, config, anchor, None));
            return w;
        }
    };
    match pending {
        // NO MARKER — the reconciliation STILL runs (the marker is never
        // the trigger): the sweep pass recomputes reachability fresh (one
        // locked snapshot) and deletes the unreachable content NOW. No
        // triage marker is rewritten afterwards: nothing durable is owed
        // (the next push reconciles anyway) and an incomplete/failed pass
        // warns — the next push's own reconciliation converges it.
        None => reconcile_sweep_pass(store, config, anchor, None),
        // THE DURABILITY GATE: the triggering checkpoint's ledger replace is
        // VISIBLE but its durability is UNCONFIRMED — REFUSE to execute the
        // sweep. Run ONLY the durability-confirming retry
        // ([`crate::retention::checkpoint::confirm_checkpoint_durability`]):
        // recompute the CURRENT retained suffix (deterministic from the
        // current ledger — identical to the trigger-time suffix while the
        // ledger is unchanged, the CURRENT suffix if another push landed)
        // and rewrite it, obtaining `ReplacedDurable` (the rename + the
        // parent-directory fsync confirmed — the exact transition, never a
        // bare "fsync the current bytes" shortcut). The marker transitions
        // to `Ready` inside the confirmation; the sweep itself is deferred to
        // the pass that reads `Ready` (the next push — which reconciles
        // regardless of the marker).
        Some(SweepDebt::AwaitingCheckpointDurability {
            target,
            retained_from,
        }) => {
            match crate::retention::checkpoint::confirm_checkpoint_durability(
                store,
                &target,
                &retained_from,
            ) {
                Ok(crate::retention::checkpoint::CheckpointDurabilityOutcome::Durable {
                    debt_warning,
                }) => {
                    let mut w = vec![format!(
                        "sweep still deferred: the durability-confirming ledger rewrite for target \
                         '{target}' succeeded — the checkpoint ledger is now DURABLE — but the \
                         sweep was not run this pass; the next push sweeps"
                    )];
                    if let Some(d) = debt_warning {
                        w.push(d);
                    }
                    w
                }
                Ok(
                    crate::retention::checkpoint::CheckpointDurabilityOutcome::StillUnconfirmed {
                        warning,
                        debt_warning,
                    },
                ) => {
                    let mut w = vec![format!("sweep still deferred: {warning}")];
                    if let Some(d) = debt_warning {
                        w.push(d);
                    }
                    w
                }
                Err(e) => vec![format!(
                    "sweep still deferred: the durability-confirming checkpoint retry failed ({e}); \
                     a later push retries it"
                )],
            }
        }
        // The floor IS durable: run the sweep pass now (fresh reachability
        // under ONE locked snapshot — no persisted deletion worklist) and
        // reconcile the triage marker (clear on completion; rewrite `Ready`
        // while the sweep stays owed). Every failure stays a warning, never
        // an `Err`.
        Some(SweepDebt::Ready {
            target,
            retained_from,
        }) => reconcile_sweep_pass(
            store,
            config,
            anchor,
            Some(SweepDebt::Ready {
                target,
                retained_from,
            }),
        ),
    }
}

/// Run ONE global sweep pass — fresh reachability under ONE locked
/// [`crate::retention::reachability::history_floor::ReachabilitySnapshot`],
/// no persisted deletion worklist — and reconcile the retry-triage marker.
/// `owed` — the marker to (re)write while the sweep stays incomplete or
/// fails (`Some` on the Ready-marker path: the durable floor pair records
/// what is owed; `None` on the no-marker path: nothing durable is owed, the
/// next push reconciles anyway). On a marker WRITE failure, the CURRENT
/// call still performed the reconciliation — nothing is left waiting on the
/// marker for this push — and the warning keeps the deferral explicit.
/// NON-FALLIBLE: every failure stays a warning entry, never an `Err`.
fn reconcile_sweep_pass(
    store: &LocalStore,
    config: &ProjectConfig,
    anchor: &str,
    owed: Option<SweepDebt>,
) -> Vec<String> {
    // The push-side sweep recomputes reachability from the CURRENT ledgers
    // — NO checkpoint ledger override: the override is the checkpoint's
    // retained-suffix hypothetical and exists only while a checkpoint sweep
    // runs (see `crate::retention::checkpoint`).
    match store.run_sweep(config, anchor, None) {
        Ok((_, true)) => {
            // The sweep completed: clear the triage marker. A clear failure
            // is post-commit maintenance: warn and leave the marker as it
            // is — a later push retries and converges (it reconciles
            // regardless). Never an `Err`. Nothing to clear when no marker
            // was owed (the no-marker path read `None` and wrote nothing).
            match owed {
                None => Vec::new(),
                Some(_) => match store.write_sweep_debt(None) {
                    Ok(()) => Vec::new(),
                    Err(e) => vec![format!(
                        "sweep debt maintenance deferred: failed to clear sweep debt: {e}"
                    )],
                },
            }
        }
        Ok((_, false)) => {
            // Still incomplete: the triage marker records what is owed (when
            // one was owed — the floor stays durable; the marker's pair
            // identifies the checkpoint whose sweep stays owed). A write
            // failure is post-commit maintenance: warn and leave the marker
            // as it is — a later push reconciles anyway. Never an `Err`.
            match owed {
                Some(marker) => {
                    if let Err(e) = store.write_sweep_debt(Some(&marker)) {
                        return vec![format!(
                            "sweep debt maintenance deferred: failed to write sweep debt: {e}"
                        )];
                    }
                    vec![
                        "sweep still deferred: the global sweep did not complete; \
                         a later push retries it"
                            .to_string(),
                    ]
                }
                None => vec![
                    "sweep still deferred: the global sweep did not complete; \
                     a later push retries it"
                        .to_string(),
                ],
            }
        }
        Err(e) => {
            // The sweep failed (fail-closed: nothing was deleted against a
            // partial retained set — a snapshot that fails to build aborts
            // before any unlink). The CURRENT call still performed the
            // reconciliation; keep the triage record (when owed) and warn —
            // a later fault-free push recomputes a fresh snapshot and
            // converges.
            match owed {
                Some(marker) => {
                    if let Err(e2) = store.write_sweep_debt(Some(&marker)) {
                        return vec![format!(
                            "sweep debt maintenance deferred: failed to write sweep debt: {e2}"
                        )];
                    }
                    vec![format!("sweep still deferred: {e}")]
                }
                None => vec![format!("sweep still deferred: {e}")],
            }
        }
    }
}

/// Build the report's `warning` from deferred-maintenance entries: `None`
/// when nothing is outstanding, otherwise one message describing the deferred
/// work.
pub(crate) fn maintenance_warning(deferred: &[String]) -> Option<String> {
    if deferred.is_empty() {
        None
    } else {
        Some(format!(
            "post-commit maintenance deferred: {}",
            deferred.join("; ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::deploy::testsupport::{RecoveryHarness, engine_pin_release, push_clean};
    use crate::identity::ReleaseId;
    use crate::ledger::DeploymentStatus;
    use crate::remote::helper::RemoteHelper;
    use crate::remote::layout;
    use crate::remote::transport::LocalTransport;

    /// ENGINE-LEVEL wiring for the fail-closed pin abort: a post-commit
    /// step-17 retention whose pinned release record is unreadable must abort
    /// before ANY deletion, and the retention caller must convert the abort
    /// into the retention-debt machinery — the push still reports SUCCESS with
    /// a deferred-maintenance warning and a durable debt marker (never a hard
    /// push failure), and the NEXT push's maintenance retry services the
    /// marker once the record is repaired, deleting EXACTLY the genuinely
    /// unretained trees: the pin-only trees survive and the true garbage is
    /// removed. (All three corruption classes — missing / malformed /
    /// unverifiable — produce the SAME integrity abort and are each covered
    /// deterministically in the retention unit tests plus the 16-case
    /// property; this engine test proves the debt/warning/retry wiring with
    /// the missing-record class.)
    #[test]
    fn pin_abort_defers_retention_and_retry_after_repair_deletes_exactly() {
        let mut h = RecoveryHarness::new();

        // Push 1 (no pins yet): the first deployment establishes the
        // receiver — generation, current, tree.
        let r1 = push_clean(&h).unwrap();
        assert_eq!(r1.status, Some(DeploymentStatus::Successful));

        // The pinned release protects two pin-only trees (referenced ONLY by
        // the pin — outside every count/age window), and a garbage object is
        // referenced by nothing.
        let rec = engine_pin_release(&h.store, &["tree-pin-a", "tree-pin-b"]);
        h.config = h
            .config
            .with_pin(crate::config::Pin {
                release: ReleaseId::parse(&rec.release_id).unwrap(),
                reason: "known-good".into(),
            })
            .unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), h.remotes_base.join("s1"))
                .unwrap();
        let helper = RemoteHelper::new(&remote);
        for t in ["tree-pin-a", "tree-pin-b", "tree-garbage"] {
            helper
                .remote()
                .create_dir_all(&layout::tree_root(t))
                .unwrap();
        }

        // MISSING pinned release record: the pin names nothing on disk.
        let path = h
            .store
            .release_dir(&ReleaseId::new(rec.release_id.clone()))
            .join("release.json");
        std::fs::remove_file(&path).unwrap();

        // Push 2 (a REAL push — changed artifact content promotes a new
        // generation, so step-17 retention runs): the pin abort must NOT fail
        // the push. It is converted into retention debt + a warning, and
        // NOTHING is deleted.
        let artifacts = h
            .cfg_path
            .parent()
            .unwrap()
            .join("releases")
            .join("v1")
            .join("artifacts");
        std::fs::write(
            artifacts
                .join("build")
                .join("output")
                .join("app")
                .join("server"),
            "v2\n",
        )
        .unwrap();
        let r2 = push_clean(&h).unwrap();
        assert_eq!(
            r2.status,
            Some(DeploymentStatus::Successful),
            "the pin abort must never hard-fail the push (post-commit maintenance)"
        );
        let warning = r2
            .warning
            .as_ref()
            .expect("the push must warn about the deferred retention");
        assert!(
            warning.contains("retention deferred"),
            "the warning describes the deferred retention, got: {warning}"
        );
        let debt = h.store.read_retention_debt("t1").unwrap();
        let reason = debt
            .get("p1")
            .expect("a durable debt marker for slot p1 must be recorded");
        assert!(
            reason.contains("pin names release"),
            "the debt marker records the un-honorable pin, got: {reason}"
        );

        // ZERO DELETIONS: every pre-existing object survives push 2 (the
        // only inventory delta is the push's own new tree object).
        let inventory_after = helper.status().unwrap().inventory;
        for t in ["tree-pin-a", "tree-pin-b", "tree-garbage"] {
            assert!(
                inventory_after.contains(&t.to_string()),
                "tree {t} must survive the failed retention"
            );
        }

        // Repair the pinned release's record.
        let dir = h.store.release_dir(&ReleaseId::new(rec.release_id.clone()));
        std::fs::remove_dir_all(&dir).unwrap();
        h.store.write_release(&rec).unwrap();

        // Push 3 (up-to-date no-op): the deferred-maintenance retry
        // services the marker — the retention now succeeds, deleting
        // EXACTLY the genuinely unretained trees — and clears the marker.
        let r3 = push_clean(&h).unwrap();
        assert_eq!(r3.message, "Everything up to date");
        assert!(
            r3.warning.is_none(),
            "the retried retention succeeded: no warning remains, got {:?}",
            r3.warning
        );
        assert!(
            h.store.read_retention_debt("t1").unwrap().is_empty(),
            "the debt marker is cleared once the retry succeeds"
        );
        let inventory = helper.status().unwrap().inventory;
        for t in ["tree-pin-a", "tree-pin-b"] {
            assert!(
                inventory.contains(&t.to_string()),
                "pin-only tree {t} survives the retry"
            );
        }
        assert!(
            !inventory.contains(&"tree-garbage".to_string()),
            "the true garbage is removed by the retry"
        );
        let cur = helper
            .status()
            .unwrap()
            .current_generation
            .expect("a current generation exists");
        let live = helper
            .read_assignment(cur.as_str())
            .unwrap()
            .artifact
            .tree
            .as_str()
            .to_string();
        assert!(
            inventory.contains(&live),
            "the live tree {live} survives the retry"
        );
    }
}
