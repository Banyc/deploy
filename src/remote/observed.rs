//! Three-state remote observation types.
//!
//! The observation types (`Observation<T>`, `ObservedState`,
//! `ObservedGeneration`, `ObservedSlot`, `ObservedTarget`,
//! `ObservationError`) are owned by `crate::records` — a later encapsulation
//! pass moves them — so this module is a thin re-export keeping the
//! remote-facing observation surface reachable through
//! `crate::remote::observed`.

pub use crate::records::{
    Observation, ObservationError, ObservedGeneration, ObservedSlot, ObservedState, ObservedTarget,
};
