//! Local artifact and target state store.
//!
//! The [`local`] group owns every facet of the [`LocalStore`](local::LocalStore)
//! (the struct, constructors, shared I/O primitives, and the per-feature
//! record I/O as inherent impl blocks); [`atomic`] holds the generic
//! atomic-write / path-state infra used across the store and the retention
//! machinery.

pub mod atomic;
pub mod local;

// Keep the pre-nesting flat paths resolving (`crate::store::ledger::X`,
// `crate::store::layout::X`, ...) for the rest of the crate.
pub use local::{debt, deployments, layout, ledger, objects, observed, pins, releases};
