//! Simple Deployment System — core library.
//!
//! A Git-push-style deployment system. See `requirement.md` for the full design.

pub mod cli;
pub mod config;
pub mod deploy;
pub mod digest;
pub mod error;
pub mod identity;
pub mod init;
pub mod ledger;
pub mod remote;
pub mod retention;
pub mod store;
pub mod verify;

#[cfg(test)]
pub(crate) mod semantic_invariants;
#[cfg(test)]
pub(crate) mod testutil;
