//! Core identity types and canonical data structures.
//! The deployment core is deliberately ignorant of application semantics. It
//! understands only filesystem entries, mappings, trees, artifacts, variants,
//! releases, targets, and activation adapters. The important identities are:
//!
//! * `tree`       = immutable filesystem content, identified only by digest
//! * `variant`    = a name bound to one tree within a release
//! * `artifact`   = the release + variant + tree binding
//! * `release`    = an immutable map of every variant to a tree digest
//! * `slot`       = a named deployment location (one server + one variant)
//! * `target`     = a named group of stable deployment slots and its rollout policy
//! * `deployment` = an attempted push and its exact per-slot assignments
//! * `generation` = one slot's durable activation record for one assignment
//!
//! Deployment, operation, and generation IDs are opaque collision-resistant
//! IDs (UUIDv7 in schema version 1). They identify events and are never used
//! as content identity.
//!
//! Identity model: [`SlotId`] is the DEPLOYMENT-LOCATION identity —
//! the key of every slot→assignment relationship (plans, attempts, observed
//! state, snapshots, commit markers). [`ServerId`] is the ACTUAL SERVER
//! identity used for transport addressing (user@host lives on `ServerDef`).
//! They are distinct concepts: a server can host slots in multiple targets,
//! and a slot may be a member of several targets (each carrying its own
//! `deploy_dir`). Today one target runs at most one slot per server, so the
//! two ID spaces are interchangeable within a target, but the model keys
//! assignments by [`SlotId`] and addresses transports by
//! [`ServerId`].
//!
//! NOTE: during the encapsulation restructure this module is a RE-EXPORT
//! SHIM — all items now live in [`crate::identity`] (one module per identity
//! family). The shim keeps every existing `crate::model::*` path compiling;
//! later passes update the call sites to the new paths and remove the shim.

pub use crate::identity::*;
// Crate-internal items (never public in the original module): kept nameable
// at the old paths for in-crate callers until the later passes update them.
pub(crate) use crate::identity::{MatchingMembership, NonEmptySlotSet, SlotSet, valid_hex_digest};
// `#[cfg(test)]` test helpers, kept nameable at the old path for the test
// fixtures that reference `crate::model::test_*` (only the helpers actually
// referenced are re-exported; the rest live at `crate::identity::ids`/`digests`).
#[cfg(test)]
pub(crate) use crate::identity::{
    test_deployment_id, test_generation_id, test_release_id, test_sha256_hex, test_tree_digest,
    test_uuid_v7,
};
