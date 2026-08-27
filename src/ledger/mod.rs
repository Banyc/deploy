//! The LEDGER area (feature inventory A2: Ledger semantics).
//!
//! A target's deployment history is ONE ordered, append-only JSONL ledger
//! (`targets/<target>/ledger.jsonl`), and every A2 capability is owned by a
//! named module here:
//!
//! * [`append`] — the two physical line kinds ([`LedgerLine`]) and the
//!   merged entry ([`LedgerEntry`]): the crash-atomic append + deployment-id
//!   keying contracts (the physical I/O stays in
//!   [`crate::store::local::LocalStore`]). The merged ENTRY type itself
//!   lives in [`entry`].
//! * [`entry`] — the MERGED deployment entry ([`LedgerEntry`], the intent +
//!   optional terminal merge type the append/read path carries) + the
//!   verifying pair-conversion tests.
//! * [`records`] — the SHARED core RECORDS: the deployment-record fields
//!   ([`SlotAttemptState`] / [`DeploymentStatus`]), the rollback records
//!   ([`LedgerRollbackWire`] / [`LedgerRollback`] / [`PhysicalBinding`]),
//!   the plan/report records ([`DeploymentPlanWire`] / [`DeploymentPlan`]
//!   / [`PlanSource`] / [`PlanOrigin`]), and the pins/server records
//!   ([`Pins`] / [`ServerState`]), plus the re-exports of the moved
//!   collections ([`SlotTable`] / [`NonEmptySlotTable`] from [`tables`],
//!   [`SlotResult`] from [`outcomes`]).
//! * [`tables`] — the per-slot ordered TABLES ([`SlotTable`] /
//!   [`NonEmptySlotTable`] over the private ordered map): the domain's
//!   keyed-by-slot collection types.
//! * [`intent`] — the intent records ([`LedgerIntentWire`] /
//!   [`DeploymentIntent`]) with the verifying conversion + the in-memory
//!   push report ([`LedgerIntentReport`]) (the “two line kinds — intent”
//!   half).
//! * [`log`] — the `deploy log` RENDERING ([`render_log`] + the
//!   effective-status derivation): one line per attempt, newest last,
//!   rollback-key prefix, ` group=<name>` note.
//! * [`terminal`] — the terminal records ([`LedgerTerminalWire`] /
//!   [`LedgerTerminal`] / [`TerminalDisposition`]) with the verifying
//!   conversion + status accessor (the “two line kinds — terminal” half).
//! * [`outcomes`] — the per-slot outcomes ([`SlotOutcome`] /
//!   [`SlotOutcomeKind`] / [`SlotTransition`]) + the remaining-changes /
//!   compensation derivations.
//! * [`observation`] — the three-state observations ([`Observation`] and
//!   friends).
//! * [`schema`] — the ledger/pins format-version constants
//!   ([`LEDGER_SCHEMA_VERSION`] / [`PINS_SCHEMA_VERSION`]).
//! * [`rebinding`] — the rebinding proof records ([`RebindingPlan`] /
//!   [`VerifiedReleaseRebinding`]).
//! * [`membership`] — the SUCCESSFUL membership-equation enforcement
//!   (outcomes == selected, rollback == full, selected ⊆ full).
//! * [`rollback`] — the rollback PAYLOAD builder ([`build_rollback`]): the
//!   complete-snapshot overlay + exact-rollback verification semantics.
//! * [`finalize`] — replay-safe finalization
//!   ([`finalize_successful_attempt`]) + recovery outcomes.
//! * [`recovery`] — pending-attempt reconciliation
//!   ([`reconcile_pending_commits`], moved from `crate::ledger::recovery`).
//! * [`refs`] — reference RESOLUTION against the ledger
//!   ([`resolve_ref_expr`] + the derived successful-chain helpers; the
//!   GRAMMAR stays in [`crate::deploy::refs`]).
//!
//! Deferred modules (feature present, but the SEMANTIC TYPES do not live
//! here — noted so the inventory stays complete):
//!
//! * **commit markers** — the marker I/O lives in
//!   [`crate::remote::helper::RemoteHelper::write_commit_marker`] and the
//!   deterministic payload is built at the call sites; no marker SEMANTIC
//!   TYPES live in records.rs, so there is no `markers` module.
//! * **schema versions** — `LEDGER_SCHEMA_VERSION` and `PINS_SCHEMA_VERSION`
//!   live in [`crate::ledger::schema`] (re-exported at the area root), and
//!   the wire-version gate lives in the store reader
//!   ([`crate::store::local::LocalStore::read_ledger`]).
//! * **transaction records** — the `transactions/<op-id>.json` I/O lives in
//!   [`crate::remote::helper::RemoteHelper::transaction_record`]; no
//!   transaction-record SEMANTIC TYPES live in records.rs, so there is no
//!   `transactions` module.
//!
//! During the encapsulation restructure, the old `crate::records`,
//! `crate::history`, and `crate::push::reconcile` paths were folded into
//! this area (`records`/`finalize`/`refs`/`rollback`/`recovery` here; the
//! reference GRAMMAR lives in [`crate::deploy::refs`]); the shims are gone.

pub mod append;
pub mod entry;
pub mod finalize;
pub mod intent;
pub mod log;
pub mod membership;
pub mod observation;
pub mod outcomes;
pub mod rebinding;
pub mod records;
pub mod recovery;
pub mod refs;
pub mod rollback;
pub mod schema;
pub mod tables;
pub mod terminal;

pub use append::{LedgerEntry, LedgerLine};
pub use finalize::{finalize_successful_attempt, recovery_outcomes};
pub use intent::{
    DeploymentIntent, DesiredGeneration, IntentSlot, LedgerIntentReport, LedgerIntentWire,
    PreviousGeneration,
};
pub use log::render_log;
pub use observation::{
    Observation, ObservationError, ObservedGeneration, ObservedSlot, ObservedState, ObservedTarget,
};
pub use outcomes::{CompensationReport, SlotOutcome, SlotOutcomeKind, SlotTransition};
pub use rebinding::{FrozenSlotTopology, RebindingPlan, VerifiedReleaseRebinding};
pub use records::{
    BehaviorIndex, CompleteRollback, DeploymentPlan, DeploymentPlanWire, DeploymentStatus,
    LedgerRollback, LedgerRollbackWire, NonEmptySlotTable, PhysicalBinding, Pins, PlanOrigin,
    PlanSource, ServerState, SlotAttemptState, SlotPlan, SlotResult, SlotTable,
};
pub use refs::{
    PushRef, attempt_slot_ids, deployment_index, ref_name, resolve_deployment,
    successful_deployments, successful_index,
};
pub use rollback::build_rollback;
pub use terminal::{LedgerTerminal, LedgerTerminalWire, TerminalDisposition};
// Crate-internal items: the reference RESOLUTION + grammar re-exports stay
// pub(crate) — the push engine / plan consume them through the ledger path.
// The membership-equation verifier and the reconciliation entry point
// are NOT re-exported at the area root: their only in-crate consumers use the
// module paths directly ([`crate::ledger::membership`] /
// [`crate::ledger::recovery`]).
pub(crate) use refs::{RefExpr, parse_ref_expr, resolve_ref_expr};
// The ledger/pins format-version constants (defined in [`crate::ledger::schema`]).
pub(crate) use schema::{LEDGER_SCHEMA_VERSION, PINS_SCHEMA_VERSION};
