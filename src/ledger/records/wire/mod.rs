//! The LEDGER LINE + ENTRY record facets (feature area A2 "two line kinds" /
//! "merged entry"): the record shapes the ledger's append/read path carries,
//! grouped here by their wire relatedness — the durable INTENT
//! ([`intent`]'s [`LedgerIntentWire`]), the TERMINAL EVENT
//! ([`terminal`]'s [`LedgerTerminalWire`]), the per-slot OUTCOMES
//! ([`outcomes`]'s [`SlotOutcome`] / [`SlotOutcomeRowWire`] — the wire
//! outcome ROW the terminal line's `outcomes` ARRAY carries, owned next to
//! its domain sibling; the pre-row-array name [`SlotResult`] stays as a
//! re-export alias), and the MERGED ENTRY ([`entry`]'s [`LedgerEntry`] —
//! the intent + optional terminal merge the read path produces).
//!
//! The DOMAIN records (the intent, the terminal + its dispositions) are
//! OWNED BY THE SEMANTIC KERNEL ([`crate::kernel`]) and re-exported here;
//! the wire shapes + their VERIFYING CONVERSIONS live with their wires.
//!
//! The physical event lines ([`crate::ledger::records::LedgerEventWire`] —
//! the WIRE enum the append-only JSONL stream carries: intent / terminal /
//! checkpoint) live in [`crate::ledger::records`].

mod entry;
mod intent;
mod outcomes;
mod terminal;

pub use entry::LedgerEntry;
pub use intent::{
    LedgerIntentReport, LedgerIntentWire, PlannedSlotRowWire, PlannedSlotWire,
    PreviousGenerationWire, SlotActionWire, SnapshotSlotWire,
};
pub use outcomes::{
    CompensationReport, SlotOutcome, SlotOutcomeKind, SlotOutcomeRowWire, SlotResult,
    SlotTransition,
};
pub use terminal::LedgerTerminalWire;
