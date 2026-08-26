//! Simple Deployment System — core library.
//!
//! A Git-push-style deployment system. See `requirement.md` for the full design.

pub mod adapter;
pub mod cli;
pub mod config;
pub mod digest;
pub mod error;
pub mod history;
pub mod init;
pub mod layout;
pub mod mapper;
pub mod model;
pub mod push;
pub mod records;
pub mod release;
pub mod remote;
pub(crate) mod revset;
pub mod rotation;
pub mod scalar;
pub mod store;
#[cfg(test)]
pub(crate) mod sweep;
pub mod template;
pub mod tree;

#[cfg(test)]
pub(crate) mod semantic_invariants;
#[cfg(test)]
pub(crate) mod testutil;
