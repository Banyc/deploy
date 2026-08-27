//! THE ID FAMILY — a deeper group DIRECTORY of the format-validated
//! identity NEWTYPES (every one built through the shared [`id_newtype!`]
//! macro: the format validator + the `parse`/`FromStr`/`TryFrom`/serde
//! contract):
//!
//! * [`ids`] — the uuid-v7 EVENT identities ([`DeploymentId`],
//!   [`GenerationId`], [`OperationId`]: `deploy-`/`gen-`/`op-` + a canonical
//!   hyphenated UUIDv7 string, version nibble enforced; v4 rejected).
//! * [`digests`] — the DIGEST identities ([`TreeDigest`]/[`ReleaseDigest`]:
//!   exactly 64 lowercase hex characters, sha256).
//! * [`segments`] — the SEGMENT identities ([`SlotId`], [`ServerId`],
//!   [`TargetName`], [`VariantName`]: a single safe path segment).
//!
//! The family re-exports everything FLAT AND keeps the module paths, so
//! every identity resolves both ways: `crate::identity::SlotId` (flat) and
//! `crate::identity::id::segments::SlotId` (module path).

pub mod digests;
pub mod ids;
pub mod segments;

pub use digests::*;
pub use ids::*;
pub use segments::*;

pub(crate) use super::id_newtype;
