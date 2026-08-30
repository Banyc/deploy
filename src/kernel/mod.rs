//! THE SEMANTIC KERNEL (feature area: the pure deployment semantic kernel)
//! — the single owner of the deployment model's INVARIANTS.
//!
//! The kernel exposes EXACTLY four operations; everything else in the crate
//! consumes them:
//!
//! * [`plan`] — build a validated deployment intent (the ONE validator of
//!   the slot-table construction rules) from plan input + the parent
//!   snapshot.
//! * [`decide_terminal`] — decide a deployment's terminal disposition from
//!   the gathered execution evidence (the ONE owner of the truth table; the
//!   engine gathers evidence, it never constructs terminal variants).
//! * [`apply_event`] — the ONE pure ledger state machine: accept an event
//!   into a deployment state or refuse the transition.
//! * [`resolve_snapshot`] — resolve a successful deployment's resulting
//!   snapshot (derived from its intent — never stored in the terminal).
//!
//! The kernel OWNS the rules:
//!
//! * **[`intent`]** — the intent domain (`DeploymentIntent` +
//!   `PlannedSlot`/`SlotAction`/`SnapshotSlot`): store the complete result
//!   ONCE in ONE slot table; memberships and the resulting snapshot are
//!   DERIVED views; [`intent::plan`] is the ONE constructor validating all
//!   six construction rules.
//! * **[`terminal`]** — successful terminals are PAYLOAD-FREE; the
//!   [`terminal::IntentDigest`] binds a terminal to the exact canonical
//!   intent; the terminal dispositions are structural (private validated
//!   payloads); [`terminal::assert_parent_is_head`] is the parent==head
//!   rule helper used by the plan-time gate and the finalizer's explicit
//!   pre-check.
//! * **[`snapshot`]** — the snapshot resolution rule: a successful
//!   deployment's snapshot IS `entry.intent.resulting_snapshot()`; there is
//!   no `SnapshotId`.
//! * **[`transition`]** — the pure ledger state machine + the terminal
//!   truth table; [`transition::apply_event`] owns the STRICTLY-LINEAR
//!   lineage gates (at most one pending intent at a time; an ordinary
//!   intent's parent must equal the current successful head at intent-append
//!   time; inherited entries must reproduce the head's snapshot; a terminal
//!   must belong to the pending attempt; only a `Successful` terminal
//!   advances the head; the checkpoint anchor is the one exception) with NO
//!   bypass — recovery is a caller of the same transition, so a stale plan
//!   can never append `Successful`.
//! * **[`error`]** — the five error classes every kernel error belongs to,
//!   the stable [`KernelErrorCode`] naming WHICH semantic rule failed, and
//!   the typed evidence fields (deployment ids, physical line numbers,
//!   digests, slot ids) each typed variant carries — class = who should
//!   react, code = which semantic rule failed, typed fields = the concrete
//!   evidence.
//!
//! The LEDGER LAYER is reduced to a strict event store (strict parsing,
//! duplicate-key rejection, event ordering, one intent per deployment, at
//! most one terminal per intent, terminal `intent_digest` equality, durable
//! append) and delegates every semantic transition to
//! [`transition::apply_event`]. The deployment ENGINE gathers evidence and
//! never decides semantics itself.

pub mod error;
pub mod intent;
pub mod lineage;
pub mod snapshot;
pub mod terminal;
pub mod transition;

pub use error::{
    ConflictError, InputError, IntegrityError, InvariantError, KernelError, KernelErrorClass,
    KernelErrorCode, KernelResult, TransportError,
};
pub use intent::{DeploymentIntent, PlanInput, PlannedDeploy, PlannedSlot, SlotAction, plan};
pub use lineage::LineageViolation;
pub use snapshot::{PreviousGeneration, SnapshotSlot, resolve_snapshot};
pub use terminal::{
    DegradedTerminal, FailedRolledBackTerminal, IntentDigest, LedgerTerminal, TerminalDisposition,
    assert_parent_is_head, intent_digest,
};
pub use transition::{
    CheckpointEvent, DeploymentState, ExecutionReport, IntentEvent, LedgerEvent, TerminalEvent,
    apply_event, decide_terminal, validate_inherited_slots, validate_terminal_vs_intent,
};
