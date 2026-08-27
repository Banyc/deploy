//! The LEDGER area (feature inventory A2: Ledger semantics).
//!
//! A target's deployment history is ONE ordered, append-only JSONL ledger
//! (`targets/<target>/ledger.jsonl`), and every A2 capability is owned by a
//! named module here:
//!
//! * [`append`] — the two physical line kinds ([`LedgerLine`]) and the
//!   merged entry ([`LedgerEntry`]): the crash-atomic append + deployment-id
//!   keying contracts (the physical I/O stays in
//!   [`crate::store::local::LocalStore`]).
//! * [`records`] — the core wire + domain RECORDS: the intents
//!   ([`LedgerIntentWire`] / [`DeploymentIntent`]), terminals
//!   ([`LedgerTerminalWire`] / [`LedgerTerminal`] /
//!   [`TerminalDisposition`]), the rollback records
//!   ([`LedgerRollbackWire`] / [`LedgerRollback`] / [`PhysicalBinding`]),
//!   the per-slot tables ([`SlotTable`] / [`NonEmptySlotTable`]), the slot
//!   outcomes ([`SlotOutcome`] / [`SlotResult`] / [`SlotOutcomeKind`] /
//!   [`SlotTransition`]), the three-state observations ([`Observation`] and
//!   friends), the plan/report records, and the verifying wire → domain
//!   conversions.
//! * [`membership`] — the SUCCESSFUL membership-equation enforcement
//!   (outcomes == selected, rollback == full, selected ⊆ full).
//! * [`rollback`] — the rollback PAYLOAD builder ([`build_rollback`]): the
//!   complete-snapshot overlay + exact-rollback verification semantics.
//! * [`finalize`] — replay-safe finalization
//!   ([`finalize_successful_attempt`]) + recovery outcomes.
//! * [`recovery`] — pending-attempt reconciliation
//!   ([`reconcile_pending_commits`], moved from `crate::push::reconcile`).
//! * [`refs`] — reference RESOLUTION against the ledger
//!   ([`resolve_ref_expr`] + the derived successful-chain helpers; the
//!   GRAMMAR stays in [`crate::revset`]).
//!
//! Deferred modules (feature present, but the SEMANTIC TYPES do not live
//! here — noted so the inventory stays complete):
//!
//! * **deploy log** — the rendering lives in [`crate::cli`] (`render_log`),
//!   over the ledger's `LedgerEntry` stream; no log-rendering semantics live
//!   in records/history, so there is no `log` module.
//! * **commit markers** — the marker I/O lives in
//!   [`crate::remote::helper::RemoteHelper::write_commit_marker`] and the
//!   deterministic payload is built at the call sites; no marker SEMANTIC
//!   TYPES live in records.rs, so there is no `markers` module.
//! * **schema versions** — `LEDGER_SCHEMA_VERSION` stays parked in
//!   [`crate::identity::versions`] (a later pass relocates it) and the
//!   wire-version gate lives in the store reader
//!   ([`crate::store::local::LocalStore::read_ledger`]); there is no
//!   version-check logic to move here, so there is no `schema` module.
//! * **transaction records** — the `transactions/<op-id>.json` I/O lives in
//!   [`crate::remote::helper::RemoteHelper::transaction_record`]; no
//!   transaction-record SEMANTIC TYPES live in records.rs, so there is no
//!   `transactions` module.
//!
//! During the encapsulation restructure, `crate::records`, `crate::history`,
//! and `crate::push::reconcile` are RE-EXPORT SHIMS over this module; later
//! passes update call sites and remove the shims.

pub mod append;
pub mod finalize;
pub mod membership;
pub mod records;
pub mod recovery;
pub mod refs;
pub mod rollback;

pub use append::{LedgerEntry, LedgerLine};
pub use finalize::{finalize_successful_attempt, recovery_outcomes};
pub use records::{
    BehaviorIndex, CompensationReport, CompleteRollback, DeploymentIntent, DeploymentPlan,
    DeploymentPlanWire, DeploymentStatus, DesiredGeneration, FrozenSlotTopology, IntentSlot,
    LedgerIntentReport, LedgerIntentWire, LedgerRollback, LedgerRollbackWire, LedgerTerminal,
    LedgerTerminalWire, NonEmptySlotTable, Observation, ObservationError, ObservedGeneration,
    ObservedSlot, ObservedState, ObservedTarget, PhysicalBinding, Pins, PlanOrigin, PlanSource,
    PreviousGeneration, RebindingPlan, ServerState, SlotAttemptState, SlotOutcome, SlotOutcomeKind,
    SlotPlan, SlotResult, SlotTable, SlotTransition, TerminalDisposition, VerifiedReleaseRebinding,
};
pub use refs::{
    PushRef, attempt_slot_ids, deployment_index, ref_name, resolve_deployment,
    successful_deployments, successful_index,
};
pub use rollback::build_rollback;
// Crate-internal items: the reference RESOLUTION + grammar re-exports stay
// pub(crate) (the push engine / plan consume them through the `crate::history`
// shim). The membership-equation verifier and the reconciliation entry point
// are NOT re-exported at the area root: their only in-crate consumers use the
// module paths directly ([`crate::ledger::records`] / [`crate::ledger::recovery`]).
pub(crate) use refs::{RefExpr, parse_ref_expr, resolve_ref_expr};
