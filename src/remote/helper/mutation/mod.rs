//! Mutation facets of the remote helper: object-store publication and
//! incoming staging, receiver rotation (mark-and-sweep retention), and the
//! durable per-operation transaction records.
//!
//! # Submodules
//!
//! * [`publish`] — tree/release publication, incoming staging, and the
//!   two-phase host-tree upload.
//! * [`rotate`] — mark-and-sweep retention.
//! * [`transactions`] — per-operation transaction records.

mod publish;
mod rotate;
mod transactions;

pub use publish::copy_host_tree_to_remote;
