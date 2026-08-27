//! Deployment history, rollback references, and finalization over the ONE
//! per-target deployment ledger.
//!
//! NOTE: during the encapsulation restructure this module is a RE-EXPORT
//! SHIM — all items now live in [`crate::ledger`] (the A2: Ledger semantics
//! area): reference RESOLUTION in [`crate::ledger::refs`]
//! ([`crate::ledger::refs::resolve_ref_expr`] and the successful-chain
//! helpers), replay-safe finalization in [`crate::ledger::finalize`], and
//! the rollback payload builder in [`crate::ledger::rollback`]. The
//! reference GRAMMAR stays in [`crate::revset`] (owned by another pass).
//! The shim keeps every existing `crate::history::*` path compiling; later
//! passes update the call sites to the new paths and remove the shim.

pub(crate) use crate::ledger::*;
