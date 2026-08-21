//! Optional activation and verification adapters. The core engine is unaware of
//! application semantics; adapters translate the canonical behavior contract
//! into concrete host operations.

pub mod systemd;
pub mod verify;
