//! Re-export shim: the checkpoint command moved to [`crate::retention::checkpoint`].
//! Keeps `crate::push::checkpoint::*` resolving as before (`CheckpointReport`,
//! `run_checkpoint`, and `render_checkpoint_report` were `pub`;
//! `run_checkpoint_unlocked` was `pub(crate)` and test-only).

#[cfg(test)]
pub(crate) use crate::retention::checkpoint::run_checkpoint_unlocked;
pub use crate::retention::checkpoint::{
    CheckpointReport, render_checkpoint_report, run_checkpoint,
};
