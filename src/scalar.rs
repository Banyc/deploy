//! Validated scalar value types.
//!
//! The domain model carries a set of small values whose validity is part of
//! their meaning: an identifier must be a non-empty name, a behavior digest
//! must be a sha256 digest, an on-server `deploy_dir` must be an absolute
//! TRAVERSAL-FREE path with at least one normal component below the root,
//! a batch size must be nonzero, a capacity percent
//! must fit 0..=100, and a recorded timestamp must parse as RFC 3339. The
//! application name is ONE safe identifier ([`ApplicationStoreKey`]): a
//! single normal filesystem component used for BOTH display (messages and
//! rendering) and storage (the one filesystem component that names the
//! local store directory). Each
//! such value is
//! wrapped in a NEWTYPE whose CONSTRUCTION validates the invariant (a
//! private inner value, reachable only through [`parse`]-style constructors
//! and read-only accessors) — an invalid value cannot be constructed, so the
//! domain never has to re-check what it holds.
//!
//! The raw/wire layers keep the bare forms (strings, integers, paths) and
//! the raw -> domain / wire -> domain conversions (in `crate::config` and
//! `crate::records`) parse them into these scalars, REJECTING invalid input
//! with a config/integrity error (fail closed). A scalar is deliberately NOT
//! introduced for a plain string that carries no invariant ("do not overdo
//! one-line wrappers when they carry no invariant") — only the fields below
//! get a type.
//!
//! NOTE: during the encapsulation restructure this module is a RE-EXPORT
//! SHIM — all items now live in [`crate::identity::scalars`]. The shim keeps
//! every existing `crate::scalar::*` path compiling; later passes update the
//! call sites to the new paths and remove the shim.

pub use crate::identity::*;
// Crate-internal items (never public in the original module): kept nameable
// at the old paths for in-crate callers until the later passes update them.
// (`valid_name` is NOT re-exported: the segment identities now import it
// directly from `crate::identity::scalars`, and no in-crate caller used the
// old `crate::scalar::valid_name` path.)
#[cfg(test)]
pub(crate) use crate::identity::DIGEST_TEST_HEX_1;
