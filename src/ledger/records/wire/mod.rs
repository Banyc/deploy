//! The LEDGER LINE + ENTRY record facets (feature area A2 "two line kinds" /
//! "merged entry"): the record shapes the ledger's append/read path carries,
//! grouped here by their wire relatedness — the durable INTENT
//! ([`intent`]'s [`LedgerIntentWire`] / [`DeploymentIntent`]), the TERMINAL
//! EVENT ([`terminal`]'s [`LedgerTerminalWire`] / [`LedgerTerminal`] /
//! [`TerminalDisposition`]), the per-slot OUTCOMES ([`outcomes`]'s
//! [`SlotOutcome`] / [`SlotResult`] — the wire outcome row the terminal line
//! carries, owned next to its domain sibling, with the terminal's
//! remaining-changes / compensation derivations), and the MERGED ENTRY
//! ([`entry`]'s [`LedgerEntry`] — the intent + optional terminal merge the
//! read path produces).
//!
//! The two physical line kinds ([`crate::ledger::finalize::LedgerLine`] —
//! the WIRE enum the append-only JSONL stream carries) live in
//! [`crate::ledger::finalize`]; the wire → domain VERIFYING CONVERSIONS live
//! with their wire records here, and the record-VALIDATION facets (rollback
//! payload builder, rebinding proof, membership equations, schema versions)
//! live in [`crate::ledger::records::validation`].

mod entry;
mod intent;
mod outcomes;
mod terminal;

pub use entry::LedgerEntry;
pub use intent::{
    DeploymentIntent, DesiredGeneration, IntentSlot, LedgerIntentReport, LedgerIntentWire,
    PreviousGeneration, SlotAttemptStateWire,
};
pub use outcomes::{CompensationReport, SlotOutcome, SlotOutcomeKind, SlotResult, SlotTransition};
pub use terminal::{LedgerTerminal, LedgerTerminalWire, TerminalDisposition};
