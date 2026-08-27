//! The post-planning pre-mutation verification gates: [`partial_rollout`]
//! (partial-rollout guards), [`exact_rollback`] (exact-rollback binding
//! verification), [`coverage`] (the behavior-coverage gate).

mod coverage;
mod exact_rollback;
mod partial_rollout;

pub(crate) use coverage::*;
pub(crate) use exact_rollback::*;
pub(crate) use partial_rollout::*;
