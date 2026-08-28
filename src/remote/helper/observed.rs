//! Observed-state re-exports: the ledger's observed-slot records, re-exported
//! from `crate::ledger::records` for the remote layer's public surface.

pub use crate::ledger::records::{
    Observation, ObservationError, ObservedAssignment, ObservedGeneration, ObservedSlot,
    ObservedTarget,
};
