//! Pending-attempt reconciliation (feature area A2: Ledger semantics — the
//! RECOVERY / RECONCILIATION of intent-only ledger entries).

use crate::config::ProjectConfig;
use crate::error::Result;
use crate::identity::{OperationId, SlotId};
use crate::ledger::finalize::{FinalizeOutcome, FinalizeSettings, finalize_successful_locked};
use crate::ledger::records::DegradedTerminal;
use crate::ledger::records::DeploymentIntent;
use crate::ledger::records::NonEmptySlotTable;
use crate::ledger::records::SlotTable;
use crate::ledger::records::{LedgerTerminal, TerminalDisposition};
use crate::ledger::records::{Observation, ObservedGeneration};
use crate::ledger::records::{SlotOutcome, SlotOutcomeKind, SlotTransition};
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
            .selected
            .keys()
            .all(|sid| members.contains(sid.as_str()));
        if !membership_ok {
            append_degraded(store, target_name, &attempt, "membership mismatch")?;
            continue;
        }

        let mut bindings_equal = true;
        for sid in attempt.selected.keys() {
            let frozen_binding = attempt
                .resulting_snapshot
                .get(sid)
                .expect("selected in snapshot")
                .binding();
            let equal = live_bindings.get(sid) == Some(frozen_binding);
            bindings_equal &= equal;
        }
        if !bindings_equal {
            append_degraded(store, target_name, &attempt, "binding drift")?;
            continue;
        }

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
    let outcomes: BTreeMap<SlotId, SlotOutcome> = attempt
        .selected
        .keys()
        .map(|sid| {
            let entry = attempt
                .resulting_snapshot
                .get(sid)
                .expect("selected in snapshot");
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
    let non_empty = NonEmptySlotTable::build(outcomes.iter().map(|(k, v)| (k.clone(), v.clone())))?;
    let dt = DegradedTerminal::try_new(non_empty)?;
    store.append_terminal(
        target_name,
        &attempt.deployment_id,
        &LedgerTerminal {
            recorded_at: crate::remote::helper::now_rfc3339(),
            disposition: TerminalDisposition::Degraded(dt),
            reason: Some(reason.to_string()),
        },
    )
}
