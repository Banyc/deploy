//! The LEDGER area (feature inventory A2: Ledger semantics).
//!
//! A target's deployment history is ONE ordered, append-only JSONL ledger
//! (`targets/<target>/ledger.jsonl`), and every A2 capability is owned by a
//! named module here, regrouped into SIX cohesive feature modules:
//!
//! * [`records`] — THE LEDGER RECORD MODEL: every wire + domain record
//!   shape the ledger carries, one feature GROUP DIRECTORY recursively
//!   nested by relatedness — the shared core fields ([`SlotAttemptState`] /
//!   [`DeploymentStatus`]) and the plan/pins records live in
//!   [`crate::ledger::records`] itself; the LEDGER LINE + ENTRY facets
//!   (intent, terminal, outcomes, the merged entry) live in
//!   `crate::ledger::records::wire`; the RECORD-VALIDATION facets
//!   (rebinding proof, schema versions) live in
//!   `crate::ledger::records::validation`; the
//!   foundational three-state observation lives in
//!   `crate::ledger::records::observation`. The record names are all
//!   re-exported at [`crate::ledger::records`]: the shared core
//!   ([`SlotAttemptState`] / [`DeploymentStatus`] / [`TargetSnapshot`] /
//!   [`SnapshotEntry`] / [`PhysicalBinding`]), the plan/report records
//!   ([`DeploymentPlanWire`] / [`DeploymentPlan`] / [`PlanSource`] /
//!   [`PlanOrigin`] / [`BehaviorIndex`] / [`SlotPlan`]), the pins/server
//!   records ([`Pins`] / [`ServerState`]), the intent facet
//!   ([`LedgerIntentWire`] / [`DeploymentIntent`] / [`LedgerIntentReport`]),
//!   the terminal facet ([`LedgerTerminalWire`] / [`LedgerTerminal`] /
//!   [`TerminalDisposition`]), the per-slot outcomes ([`SlotOutcome`] /
//!   [`SlotOutcomeKind`] / [`SlotTransition`] / [`SlotResult`]), the
//!   three-state observations ([`Observation`] and friends), the merged
//!   entry ([`LedgerEntry`]), the rebinding proof ([`RebindingPlan`] /
//!   [`VerifiedReleaseRebinding`] / [`FrozenSlotTopology`]), the
//!   SEMANTIC KERNEL re-exports ([`crate::kernel::intent::DeploymentIntent`]
//!   / [`crate::kernel::terminal`]'s terminal records), and the
//!   schema-version constants (`LEDGER_SCHEMA_VERSION` /
//!   `PINS_SCHEMA_VERSION`).
//! * [`tables`] — the per-slot ordered TABLES ([`SlotTable`] /
//!   [`NonEmptySlotTable`] over the private ordered map): generic slot
//!   collection INFRASTRUCTURE shared by the record model.
//! * [`finalize`] — the ledger WRITE path: replay-safe, LOCK-VERIFIED
//!   finalization ([`finalize_successful_locked`]) and the two
//!   physical append line kinds ([`LedgerLine`] — the intent + terminal
//!   WIRE events) with the merged-entry re-export.
//! * [`recovery`] — pending-attempt RECONCILIATION
//!   (`reconcile_pending_commits`).
//! * [`refs`] — reference RESOLUTION against the ledger
//!   (`resolve_ref_expr` + the derived successful-chain helpers; the
//!   GRAMMAR stays in [`crate::deploy::refs`]).
//! * [`log`] — the `deploy log` RENDERING ([`render_log`] + the
//!   effective-status derivation): one line per attempt, newest last,
//!   rollback-key prefix, ` group=<name>` note.
//!
//! Deferred modules (feature present, but the SEMANTIC TYPES do not live
//! here — noted so the inventory stays complete):
//!
//! * **commit markers** — the marker I/O lives in
//!   [`crate::remote::helper::RemoteHelper::write_commit_marker`] and the
//!   deterministic payload is built at the call sites; no marker SEMANTIC
//!   TYPES live in records.rs, so there is no `markers` module.
//! * **schema versions** — `LEDGER_SCHEMA_VERSION` and `PINS_SCHEMA_VERSION`
//!   live in [`crate::ledger::records`] (re-exported at the area root), and
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
//! The record-model facets were regrouped into [`records`] (one feature:
//! the ledger record model) and the write-path line kinds into
//! [`finalize`].

pub mod finalize;
pub mod log;
pub mod records;
pub mod recovery;
pub mod refs;
pub mod tables;

pub use crate::kernel::intent::{PlannedSlot, SlotAction};
pub use crate::kernel::snapshot::PreviousGeneration;
pub use finalize::{
    FinalizeOutcome, FinalizeSettings, LedgerEntry, LedgerLine, finalize_successful_locked,
};
pub use log::render_log;
pub use records::{
    ArtifactRefWire, BehaviorIndex, CheckpointWire, DegradedTerminal, DeploymentIntent,
    DeploymentPlan, DeploymentPlanWire, DeploymentStatus, FrozenSlotTopology, LedgerEventWire,
    LedgerIntentReport, LedgerIntentWire, LedgerTerminal, LedgerTerminalWire, NonEmptySlotTable,
    Observation, ObservationError, ObservationWire, ObservedAssignment, ObservedGeneration,
    ObservedGenerationWire, ObservedSlot, ObservedTarget, PhysicalBinding, Pins, PlanOrigin,
    PlanSource, RebindingPlan, ServerState, SlotAttemptState, SlotOutcome, SlotOutcomeKind,
    SlotPlan, SlotResult, SlotTable, SlotTransition, SnapshotEntry, SnapshotSlotWire,
    TargetSnapshot, TerminalDisposition, VerifiedReleaseRebinding,
};
pub use refs::{
    PushRef, attempt_slot_ids, deployment_index, ref_name, resolve_deployment,
    successful_deployments, successful_index,
};
// Crate-internal items: the reference RESOLUTION + grammar re-exports stay
// pub(crate) — the push engine / plan consume them through the ledger path.
// The membership-equation verifier and the reconciliation entry point are
// NOT re-exported at the area root: their only in-crate consumers use the
// module paths directly ([`crate::ledger::records`] /
// [`crate::ledger::recovery`]).
pub(crate) use refs::{RefExpr, parse_ref_expr, resolve_ref_expr};
// The ledger/pins format-version constants (defined in [`crate::ledger::records`]).
pub(crate) use records::{LEDGER_SCHEMA_VERSION, PINS_SCHEMA_VERSION};
