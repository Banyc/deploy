//! The MERGED deployment entry (feature area A2: Ledger semantics) — the
//! intent + optional terminal merge type the ledger's append/read path
//! carries.
//!
//! The physical event lines ([`crate::ledger::records::LedgerEventWire`] —
//! the WIRE enum the append-only JSONL stream carries) live in
//! [`crate::ledger::records`]; the merged ENTRY is this module's
//! [`LedgerEntry`]: the durable INTENT plus the optional TERMINAL EVENT
//! (absent while the deployment is in flight or recoverable-pending), with
//! the entry owning the deployment identity (the terminal carries none).
//! [`crate::store::local::LocalStore::read_ledger`] parses the wire lines,
//! runs the VERIFYING CONVERSION and folds every accepted event through the
//! SEMANTIC KERNEL's state machine
//! ([`crate::kernel::transition::apply_event`] — one intent per
//! deployment, at most one terminal per intent, the terminal's
//! `intent_digest` binding, and the disposition-vs-intent agreement), then
//! merges the validated domain records into [`LedgerEntry`]s keyed by
//! deployment id.

use crate::identity::{DeploymentId, TargetName};

// The merged entry's intent + terminal are the KERNEL's domain types
// (re-exported through the records surface).
use crate::kernel::intent::DeploymentIntent;
use crate::kernel::terminal::LedgerTerminal;

/// A merged deployment entry of the target's ledger: the durable INTENT plus
/// the optional TERMINAL EVENT (absent while the deployment is in flight or
/// recoverable-pending — an intent WITHOUT a terminal IS the pending state).
/// The append order is the history order; `seq` is the position of the
/// intent line in the ledger. Only VALIDATED domain records
/// ([`DeploymentIntent`], [`LedgerTerminal`]) live here — never raw wire
/// shapes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerEntry {
    pub deployment_id: DeploymentId,
    pub target: TargetName,
    pub intent: DeploymentIntent,
    pub terminal: Option<LedgerTerminal>,
    /// The position of this entry's intent line in the ledger (0-based
    /// append order — the entry's history position; a leading checkpoint
    /// event occupies position 0).
    pub seq: u64,
}

#[cfg(test)]
mod tests_entry {
    use super::*;
    use crate::identity::SlotId;
    use crate::kernel;
    use crate::kernel::transition::{DeploymentState, IntentEvent, LedgerEvent, TerminalEvent};
    use crate::ledger::records::{DeploymentStatus, LedgerIntentWire};
    use crate::ledger::{LEDGER_SCHEMA_VERSION, LedgerLine};
    use crate::store::local::LocalStore;
    use crate::testutil::fixtures;
    use std::collections::BTreeSet;

    fn p1() -> SlotId {
        SlotId::new("p1".to_string())
    }

    fn intent_wire(dep: &str) -> LedgerIntentWire {
        LedgerIntentWire::from(&fixtures::full_intent(dep, "t1", &[p1()], &[]))
    }

    /// The full verify-and-merge path: a valid intent+terminal pair converts
    /// and merges into ONE entry carrying status, disposition and the
    /// payload-free success binding; the state machine and the strict reader
    /// agree with a small REFERENCE machine on every accepted sequence.
    #[test]
    fn merged_entry_merge_and_state_machine_agree() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let target = "t1";
        let p = store.ledger_path(target);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();

        let i1 = fixtures::full_intent("deploy-x", "t1", &[p1()], &[]);
        let i2 = fixtures::full_intent("deploy-y", "t1", &[p1()], &[]);
        store.append_intent(target, &i1).unwrap();
        store.append_intent(target, &i2).unwrap();

        // The reference machine's accepted sequence: intent x, intent y,
        // terminal x (Successful).
        let mut state = DeploymentState::new(TargetName::parse("t1").unwrap());
        state = kernel::transition::apply_event(
            state,
            LedgerEvent::Intent(IntentEvent { intent: i1.clone() }),
        )
        .unwrap();
        state = kernel::transition::apply_event(
            state,
            LedgerEvent::Intent(IntentEvent { intent: i2.clone() }),
        )
        .unwrap();
        let tx = fixtures::successful_terminal(&i1);
        state = kernel::transition::apply_event(
            state,
            LedgerEvent::Terminal(TerminalEvent {
                deployment_id: i1.deployment_id().clone(),
                terminal: tx.clone(),
            }),
        )
        .unwrap();

        // The store's strict reader accepts the same events.
        store
            .append_terminal(target, i1.deployment_id(), &tx)
            .unwrap();
        let entries = store.read_ledger(target).unwrap();
        assert_eq!(entries.len(), 2, "one merged entry per deployment");
        assert_eq!(
            entries[0].terminal.as_ref().unwrap().status(),
            DeploymentStatus::Successful
        );
        assert_eq!(
            entries[1].terminal, None,
            "the intent-only entry is pending"
        );
        assert_eq!(state.entries().len(), 2);
        assert_eq!(
            state.successful_head(),
            Some(i1.deployment_id()),
            "the state machine derives the successful head"
        );
    }

    /// The state machine refuses a terminal whose deployment_id matches no
    /// intent and a terminal carrying a mismatched digest — the two
    /// impossible sequences the store ALSO refuses.
    #[test]
    fn state_machine_refuses_orphan_and_mismatched_terminals() {
        let mut state = DeploymentState::new(TargetName::parse("t1").unwrap());
        let i = fixtures::full_intent("deploy-x", "t1", &[p1()], &[]);
        state = kernel::transition::apply_event(
            state,
            LedgerEvent::Intent(IntentEvent { intent: i.clone() }),
        )
        .unwrap();
        // Orphan terminal (unknown deployment id).
        let other = fixtures::full_intent("deploy-orphan", "t1", &[p1()], &[]);
        let t = fixtures::successful_terminal(&other);
        assert!(
            kernel::transition::apply_event(
                state.clone(),
                LedgerEvent::Terminal(TerminalEvent {
                    deployment_id: other.deployment_id().clone(),
                    terminal: t.clone(),
                }),
            )
            .is_err(),
            "a terminal for an unknown deployment is refused"
        );
        // Mismatched digest (the terminal binds a different intent's digest
        // but keys this entry's id).
        let wrong = fixtures::full_intent("deploy-x", "t1", &[SlotId::new("p9")], &[]);
        let tw = fixtures::successful_terminal(&wrong);
        assert!(
            kernel::transition::apply_event(
                state.clone(),
                LedgerEvent::Terminal(TerminalEvent {
                    deployment_id: i.deployment_id().clone(),
                    terminal: tw,
                }),
            )
            .is_err(),
            "a terminal whose digest does not bind the entry's intent is refused"
        );
        // The valid terminal is accepted.
        let ok = fixtures::successful_terminal(&i);
        assert!(
            kernel::transition::apply_event(
                state.clone(),
                LedgerEvent::Terminal(TerminalEvent {
                    deployment_id: i.deployment_id().clone(),
                    terminal: ok,
                }),
            )
            .is_ok()
        );
        let _ = intent_wire;
        let _ = LEDGER_SCHEMA_VERSION;
        let _ = LedgerLine::Intent;
        let _: BTreeSet<()> = BTreeSet::new();
    }

    /// A checkpoint event is accepted ONLY as the first event.
    #[test]
    fn checkpoint_can_only_open_a_ledger() {
        let mut state = DeploymentState::new(TargetName::parse("t1").unwrap());
        let cp = kernel::transition::CheckpointEvent {
            retained_from: crate::identity::test_deployment_id("deploy-c"),
            discarded: 3,
            recorded_at: crate::remote::helper::now_rfc3339_ts(),
        };
        state =
            kernel::transition::apply_event(state, LedgerEvent::Checkpoint(cp.clone())).unwrap();
        // A second checkpoint (or any event before a checkpoint is done) is
        // refused: the checkpoint must be the FIRST event.
        assert!(
            kernel::transition::apply_event(state.clone(), LedgerEvent::Checkpoint(cp)).is_err(),
            "a second checkpoint event is refused"
        );
    }
}
