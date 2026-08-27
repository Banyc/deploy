//! Three-state remote observation types.
//!
//! The observation types (`Observation<T>`, `ObservedState`,
//! `ObservedGeneration`, `ObservedSlot`, `ObservedTarget`,
//! `ObservationError`) are owned by `crate::ledger::records` (the A2: Ledger
//! semantics area — they moved from `crate::records` during the
//! encapsulation restructure), so this module is a thin re-export keeping the
//! remote-facing observation surface reachable through
//! `crate::remote::observed`.

pub use crate::ledger::records::{
    Observation, ObservationError, ObservedGeneration, ObservedSlot, ObservedState, ObservedTarget,
};
