//! THE IDENTITY TYPES — a group DIRECTORY of the validated identity and
//! value types that name releases, events, digests, segments, and scalars,
//! nested one level deeper by family:
//!
//! * [`release_id`] — the release identity ([`ReleaseId`]): EXACTLY
//!   `rel-sha256-<64 lowercase hex>`; the loose bare-digest and `rel-`
//!   forms are rejected at the domain boundary (the CLI accepts a bare
//!   64-hex digest as an input convenience, converted first via
//!   [`crate::cli::parse_release_input`]).
//! * [`id`] — THE ID FAMILY, a deeper group of the format-validated
//!   identity NEWTYPES — the event ids ([`id::ids`]:
//!   [`DeploymentId`]/[`GenerationId`]/[`OperationId`],
//!   `deploy-`/`gen-`/`op-` + canonical hyphenated UUIDv7, version nibble
//!   enforced; v4 rejected), the digests ([`id::digests`]:
//!   [`TreeDigest`]/[`ReleaseDigest`]: exactly 64 lowercase hex), and the
//!   segment ids ([`id::segments`]: [`SlotId`], [`ServerId`],
//!   [`TargetName`], [`VariantName`]: a single safe path segment).
//! * [`scalars`] — the validated scalar value types ([`Identifier`],
//!   [`ApplicationStoreKey`], [`BatchSize`] (nonzero u64),
//!   [`CapacityPercent`] (0..=100), [`AbsoluteDeployDir`] (absolute,
//!   traversal-free), [`BehaviorDigest`], [`Timestamp`],
//!   [`RolloutGroupName`], [`Host`], [`SshUser`]).
//!
//! The group re-exports the whole surface FLAT AND keeps the module paths,
//! so every identity resolves both ways: `crate::identity::SlotId` and
//! `crate::identity::id::segments::SlotId` (and the deeper
//! `crate::identity::segments::SlotId` alias through the re-export chain).
//!
//! Deployment, operation, and generation IDs are opaque collision-resistant
//! IDs (UUIDv7 in schema version 1). They identify events and are never used
//! as content identity.
//!
//! Identities deliberately carry NO `Default` (an empty identity would be a
//! malformed durable record constructible by anyone — the exact gap this
//! hardening closes). An identity can only be built through the validated
//! [`parse`]-style constructors (`parse` / `FromStr` / `TryFrom`); the serde
//! `Deserialize` impls route every wire string through the same validation
//! (an invalid wire identity fails deserialization — fail closed).

pub mod id;
pub mod release_id;
pub mod scalars;

pub use id::*;
pub use release_id::*;
pub use scalars::*;

// The `id_newtype!` macro is defined at the AREA root (it is the shared
// identity-newtype contract); it is re-exported down through this group so
// the id-family modules can `use super::id_newtype` unchanged.
pub(crate) use super::id_newtype;
