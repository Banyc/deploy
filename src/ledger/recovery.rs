//! Pending-attempt reconciliation (feature area A2: Ledger semantics — the
//! RECOVERY / RECONCILIATION of intent-only ledger entries).

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

        // RECOVERY COMPLETES THE RECORDED ATTEMPT: the plan was validated
        // at plan time and durably recorded before mutation, and the
        // recovery contract (requirement.md step 15) finalizes it
        // `Successful` once the LIVE state still matches — so the
        // finalize-time one-parent rule is SKIPPED here (a head that later
        // landed is never a reason to strand a verified attempt).
        match finalize_successful_locked(
            store,
            &attempt,
            helpers,
            &FinalizeSettings {
                reason: "recovery finalized",
                op_id,
                enforce_parent: false,
            },
        )? {
            FinalizeOutcome::Finalized => {}
            FinalizeOutcome::Pending => {
                continue;
            }
            FinalizeOutcome::Refused { reason, .. } => {
                append_degraded(store, target_name, &attempt, reason)?;
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
