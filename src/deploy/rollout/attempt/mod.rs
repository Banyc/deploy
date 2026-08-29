//! The per-attempt outcome derivation: [`failure`] (failure policies +
//! never-advanced outcome fix-up) and [`results`] (result-table shaping).
//! The STATUS / DISPOSITION DECISION is the SEMANTIC KERNEL's
//! ([`crate::kernel::transition::decide_terminal`]); the engine gathers
//! evidence only.

mod failure;
mod results;

pub(crate) use failure::*;
pub(crate) use results::*;
