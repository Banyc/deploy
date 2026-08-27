//! The per-attempt outcome derivation: [`failure`] (failure policies +
//! never-advanced outcome fix-up), [`results`] (result-table shaping),
//! [`status`] (the post-mutation status / disposition decision).

mod failure;
mod results;
mod status;

pub(crate) use failure::*;
pub(crate) use results::*;
pub(crate) use status::*;
