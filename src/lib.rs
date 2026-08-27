//! Simple Deployment System — core library.
//!
//! A Git-push-style deployment system. See `requirement.md` for the full design.

pub mod adapter;
pub mod cli;
pub mod config;
pub(crate) mod deploy;
pub mod digest;
pub mod error;
pub mod history;
pub mod identity;
pub mod init;
pub mod layout;
pub mod ledger;
pub mod mapper;
pub mod model;
pub mod push;
pub mod records;
pub mod release;
pub mod remote;
pub mod retention;
pub(crate) mod revset;
pub mod scalar;
pub mod store;
#[cfg(test)]
pub(crate) mod sweep;
pub mod template;
pub mod tree;
mod verify;

#[cfg(test)]
pub(crate) mod semantic_invariants;
#[cfg(test)]
pub(crate) mod testutil;
