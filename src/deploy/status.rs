//! Post-mutation status / disposition decision (A7 pending-commit demotion
//! reasons).
//!
//! After the batches and the failure-policy pass
//! ([`crate::deploy::failure::apply_failure_policy`]) derived the attempt's
//! base status, this module decides the FINAL status and its terminal
//! disposition:
//!
//! * [`decide_commit_status`] — the step-15 commit-marker step for an
//!   otherwise-successful attempt. A marker that cannot be made durable
//!   demotes the attempt to `PendingCommit` ("recoverable metadata failure"),
//!   a live-generation mismatch after the swap demotes it to `Degraded`
//!   ("commit diverged"), and a conflicting existing marker (`Error::Integrity`)
//!   is a PERMANENT condition that finalizes `Degraded` ("marker integrity
//!   conflict") rather than stranding the attempt as pending forever. The
//!   same demotion applies when a slot's committed-transaction record write
//!   failed (active but not durably bookkept).
//! * [`disposition_for`] — the final status → [`TerminalDisposition`] mapping
//!   (the domain truth table is structural): `FailedPreflight` carries
//!   nothing, `FailedRolledBack` owns the outcome table as its compensation
//!   report, `Degraded` owns the outcome table its remaining changes are
//!   derived from. A `PendingCommit` status is NOT terminal at all — the
//!   entry stays intent-only, the recoverable pending state a later push's
//!   `reconcile_pending_commits` completes before its own no-op check.
//!
//! Extracted from the old `push::engine` spine ([`crate::deploy::push`]);
//! `push_inner` appends the returned disposition as the terminal event.

use crate::error::{Error, Result};
use crate::identity::{DeploymentId, GenerationId, OperationId, SlotId};
use crate::ledger::{
    DeploymentStatus, SlotOutcome, SlotOutcomeKind, SlotResult, SlotTable, TerminalDisposition,
};
use crate::remote::helper::RemoteHelper;
use std::collections::{BTreeMap, HashMap};

/// The step-15 commit-marker decision for an otherwise-successful attempt,
/// plus the "active but not durably bookkept" demotion. Returns the final
/// commit status and the demotion reason (recorded alongside the final
/// transition so `deploy log` can explain why an attempt ended up
/// `PendingCommit` or `Degraded` — e.g. "recoverable metadata failure",
/// "commit diverged", "marker integrity conflict").
#[allow(clippy::too_many_arguments)]
pub(crate) fn decide_commit_status(
    status: &DeploymentStatus,
    results: &BTreeMap<SlotId, SlotResult>,
    helpers: &HashMap<SlotId, RemoteHelper>,
    servers_order: &[SlotId],
    new_gen: &HashMap<SlotId, GenerationId>,
    deployment_id: &DeploymentId,
    target_name: &str,
    op_id: &OperationId,
) -> (DeploymentStatus, Option<&'static str>) {
    let mut commit_status = status.clone();
    let mut commit_reason: Option<&'static str> = None;
    if *status == DeploymentStatus::Successful {
        // The full placement-slot set participating in this commit.
        let slot_ids: Vec<String> = servers_order
            .iter()
            .map(|s| s.as_str().to_string())
            .collect();
        for sid in servers_order {
            let helper = &helpers[sid];
            // Hold the lock for the whole commit step so a failure cannot leak it
            // (a `?` on a manual lock would otherwise leave the lock held).
            let _guard = match helper.acquire_lock_guard(op_id.as_str()) {
                Ok(g) => g,
                Err(_) => {
                    commit_status = DeploymentStatus::PendingCommit;
                    commit_reason = Some("recoverable metadata failure");
                    continue;
                }
            };
            // Check the generation *before* writing the marker; a mismatch means
            // another controller changed `current` and this marker would be wrong.
            let cur = match helper.status() {
                Ok(s) => s.current_generation,
                Err(_) => {
                    // Recoverable metadata failure: do not abort the whole push
                    // (which would leave the attempt unrecorded); mark the
                    // commit incomplete and keep going. A later push reconciles
                    // this `PendingCommit` attempt (see
                    // `reconcile_pending_commits`) before its own no-op check.
                    commit_status = DeploymentStatus::PendingCommit;
                    commit_reason = Some("recoverable metadata failure");
                    continue;
                }
            };
            if cur.as_ref().map(|g| g.as_str()) != Some(new_gen[sid].as_str()) {
                // The live generation no longer matches what we deployed: the
                // controller's view diverged, so this marker would be wrong.
                // Report Degraded rather than a falsely successful commit.
                commit_status = DeploymentStatus::Degraded;
                commit_reason = Some("commit diverged");
                continue;
            }
            match helper.write_commit_marker(
                deployment_id.as_str(),
                new_gen[sid].as_str(),
                &slot_ids,
                Some(target_name),
            ) {
                Err(Error::Integrity(_)) => {
                    // A conflicting marker already exists with different
                    // content: a concurrent controller recorded a different
                    // fact, or the remote state diverged/corrupted. This is a
                    // PERMANENT condition — retrying will never fix it, and
                    // leaving the attempt `PendingCommit` would strand it
                    // forever (every later push re-hits the same integrity
                    // error). Finalize as `Degraded` (no snapshot entry) rather
                    // than falsely reporting `Successful`.
                    commit_status = DeploymentStatus::Degraded;
                    commit_reason = Some("marker integrity conflict");
                    continue;
                }
                Err(_) => {
                    // Recoverable metadata failure writing the marker: the
                    // attempt is recorded `PendingCommit` and a later push's
                    // `reconcile_pending_commits` completes the marker set
                    // before its no-op check.
                    commit_status = DeploymentStatus::PendingCommit;
                    continue;
                }
                Ok(_) => {}
            }
            // `_guard` drops here, releasing the lock.
        }
    }

    // A server whose committed-transaction record write failed is still active
    // but not durably bookkept. Do not report the attempt as `Successful`:
    // demote to `PendingCommit` so the metadata gap is visible.
    if commit_status == DeploymentStatus::Successful {
        for sid in servers_order {
            if let Some(r) = results.get(sid)
                && r.outcome == SlotOutcomeKind::Activated
                && r.error.is_some()
            {
                commit_status = DeploymentStatus::PendingCommit;
                commit_reason = Some("recoverable metadata failure");
                break;
            }
        }
    }
    (commit_status, commit_reason)
}

/// Map the final status to its DISPOSITION (the domain truth table is
/// structural): FailedPreflight carries nothing (no slot touched),
/// FailedRolledBack owns the outcome table as its compensation report,
/// Degraded owns the outcome table its remaining changes are derived from
/// (the slots whose FINAL OBSERVED STATE differs from their pre_push state)
/// — the same derivation the read path applies, so the domain and the wire
/// conversion stay in sync. `PendingCommit` and any other status are refused:
/// only FailedPreflight / FailedRolledBack / Degraded reach the terminal
/// append.
pub(crate) fn disposition_for(
    status: &DeploymentStatus,
    outcomes: SlotTable<SlotOutcome>,
) -> Result<TerminalDisposition> {
    let disposition = match status {
        DeploymentStatus::FailedPreflight => TerminalDisposition::FailedPreflight,
        DeploymentStatus::FailedRolledBack => TerminalDisposition::FailedRolledBack { outcomes },
        DeploymentStatus::Degraded => {
            // The Degraded disposition's remaining changes are DERIVED from
            // the outcomes (the slots whose final observed state differs from
            // their pre_push state) — never stored. The conversion refuses a
            // Degraded wire whose outcomes are ALL restored (a
            // fully-compensated attempt must be `FailedRolledBack`, never
            // `Degraded`); a Degraded terminal whose outcomes are all
            // never-advanced (e.g. a `leave_changed` failure that advanced
            // nothing) is legitimate — the policy marks the attempt Degraded
            // even though no slot changed.
            if outcomes
                .values()
                .all(|r| r.outcome == SlotOutcomeKind::Restored)
            {
                return Err(Error::store(
                    "a Degraded terminal requires at least one non-restored outcome — none recorded"
                        .to_string(),
                ));
            }
            TerminalDisposition::Degraded { outcomes }
        }
        other => {
            return Err(Error::store(format!(
                "internal: cannot append a terminal for status {other:?} — only FailedPreflight / FailedRolledBack / Degraded reach the terminal append"
            )));
        }
    };
    Ok(disposition)
}
