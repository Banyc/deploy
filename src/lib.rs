//! Simple Deployment System — core library.
//!
//! A Git-push-style deployment system. See `requirement.md` for the full design.

pub mod adapter;
pub mod cli;
pub mod config;
pub mod digest;
pub mod error;
pub mod history;
pub mod layout;
pub mod mapper;
pub mod model;
pub mod push;
pub mod records;
pub mod release;
pub mod remote;
pub mod rotation;
pub mod store;
pub mod tree;
