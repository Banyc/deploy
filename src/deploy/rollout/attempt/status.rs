//! Post-mutation STATUS DECISION — REMOVED (retained as an empty module for
//! the module path).
//!
//! The terminal disposition decision is THE SEMANTIC KERNEL'S responsibility
//! ([`crate::kernel::transition::decide_terminal`] owns the COMPLETE truth
//! table: preflight failed → `FailedPreflight`, execution succeeded AND
//! verified → `Successful`, failure and everything restored → `FailedRolledBack`,
//! anything remains changed/unknown → `Degraded`). The ENGINE gathers
//! evidence only; the old commit-marker / status-selection loop lived in the
//! shared lock-verified finalizer ([`crate::ledger::finalize`]) and moved
//! there with the payload-free success binding.