//! Shared record structures persisted by the local store, the push engine, and
//! the deployment history / rollback subsystem.
//!
//! NOTE: during the encapsulation restructure this module is a RE-EXPORT
//! SHIM — all items now live in [`crate::ledger`] (the A2: Ledger semantics
//! area: [`crate::ledger::records`] holds the core wire + domain records,
//! with the membership equations, rollback payload, append types,
//! reconciliation, finalization, and ref resolution in dedicated modules).
//! The shim keeps every existing `crate::records::*` path compiling; later
//! passes update the call sites to the new paths and remove the shim.

pub use crate::ledger::*;
