//! Pending-attempt reconciliation (intent-only ledger entries).
//!
//! NOTE: during the encapsulation restructure this file is a RE-EXPORT
//! SHIM — the implementation now lives in [`crate::ledger::recovery`] (the
//! A2: Ledger semantics area). The shim keeps the existing
//! `crate::push::reconcile::reconcile_pending_commits` path compiling; later
//! passes update the call site and remove the shim.

pub(crate) use crate::ledger::recovery::*;
