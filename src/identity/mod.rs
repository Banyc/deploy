//! Identity and proof semantics (feature inventory A6).
//!
//! The deployment core is deliberately ignorant of application semantics. It
//! understands only filesystem entries, mappings, trees, artifacts, variants,
//! releases, targets, and activation adapters. Every identity-bearing value
//! lives in this area, TWO group directories:
//!
//! * `identity` — THE IDENTITY TYPES: a group directory of the identity
//!   modules — [`identity::release_id`] ([`ReleaseId`]: EXACT
//!   `rel-sha256-<64 lowercase hex>`; bare/`rel-` forms rejected at the
//!   domain boundary — the CLI accepts a bare 64-hex digest, converted
//!   first), [`identity::scalars`] (the validated scalar value types
//!   [`Identifier`], [`ApplicationStoreKey`], [`BatchSize`] (nonzero u64),
//!   [`CapacityPercent`] (0..=100), [`crate::identity::AbsoluteDeployDir`] (absolute,
//!   traversal-free), [`BehaviorDigest`], [`Timestamp`],
//!   [`RolloutGroupName`], [`Host`], [`SshUser`]), and the ID FAMILY
//!   [`identity::id`] — a deeper group of the format-validated identity
//!   newtypes: the event ids ([`DeploymentId`]/[`GenerationId`]/
//!   [`OperationId`]: `deploy-`/`gen-`/`op-` + canonical hyphenated UUIDv7,
//!   version nibble enforced; v4 rejected), the digests
//!   ([`TreeDigest`]/[`ReleaseDigest`]: exactly 64 lowercase hex), and the
//!   segment ids ([`SlotId`], [`ServerId`], [`TargetName`], [`VariantName`]:
//!   a single safe path segment).
//! * `proof` — THE PROOF MACHINERY: a group directory of the payload +
//!   proofs modules — `proof::payload` (the release identity payload
//!   [`CanonicalReleasePayload`]: name-sorted mapping digest + behavior
//!   digest + slot-declaration digest + variant→tree bindings; capacity
//!   excluded, slots ARE identity, plus the canonical payload/record types)
//!   and `proof::proofs` (the membership proofs
//!   `SlotSet`/`NonEmptySlotSet`/`MatchingMembership`: the ONLY
//!   construction path is `MatchingMembership::verify` (frozen ==
//!   current)).
//!
//! The area re-exports the whole surface FLAT AND keeps the module paths,
//! so every identity resolves both ways: `crate::identity::ReleaseId` and
//! `crate::identity::release_id::ReleaseId` (and the deeper
//! `crate::identity::id::segments::SlotId` / `crate::identity::segments::SlotId`
//! aliases through the re-export chain).
//!
//! Deployment, operation, and generation IDs are opaque collision-resistant
//! IDs (UUIDv7 in schema version 1). They identify events and are never used
//! as content identity.
//!
//! Identities deliberately carry NO `Default` (an empty identity would be a
//! malformed durable record constructible by anyone — the exact gap this
//! hardening closes). An identity can only be built through the validated
//! `parse`-style constructors (`parse` / `FromStr` / `TryFrom`); the serde
//! `Deserialize` impls route every wire string through the same validation
//! (an invalid wire identity fails deserialization — fail closed).

// The identity-types group: `mod identity;` inside `src/identity/mod.rs` is
// intentionally same-named — clippy::module_inception is suppressed
// deliberately. The group re-exports the whole identity surface flat, so
// both `crate::identity::ReleaseId` and `crate::identity::release_id::ReleaseId`
// (and the deeper `crate::identity::id::segments::SlotId` /
// `crate::identity::segments::SlotId` aliases) resolve.
#[allow(clippy::module_inception)]
mod identity;
// The proof-machinery group: the release identity payload + the membership
// proofs, nested together; the area re-exports the payload types flat and
// the crate-internal proof types via the pub(crate) glob.
mod proof;

pub use identity::*;
pub use proof::payload::*;
pub(crate) use proof::proofs::*;

/// The validated identity newtype: construction goes through [`parse`]
/// (or `FromStr`/`TryFrom`), which enforces the type's format rule, and the
/// serde `Deserialize` routes every wire string through the same validation
/// (an invalid wire identity fails deserialization — fail closed). The
/// UNCHECKED [`new`] constructor is `#[cfg(test)]` only: test fixtures may
/// build arbitrary ids, production never can.
///
/// `$validator` is a `fn(&str) -> bool` implementing the type's format rule.
macro_rules! id_newtype {
    ($name:ident, $validator:expr, $doc:expr) => {
        #[doc = $doc]
        // NOTE: deliberately NO `Default` — a `Default` identity would be an
        // EMPTY string, a malformed durable record constructible by anyone
        // (the exact gap this hardening closes). An identity can only be
        // built through the validated [`parse`] (or `FromStr`/`TryFrom`).
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Validate `s` against the type's format rule and construct the
            /// identity. The invariant is enforced HERE: an invalid value is
            /// rejected before a value of this type can exist.
            pub fn parse(s: &str) -> Result<$name> {
                if !$validator(s) {
                    return Err(Error::config(format!(
                        "invalid {} value {:?}",
                        stringify!($name),
                        s
                    )));
                }
                Ok($name(s.to_string()))
            }

            /// The validated identity string.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// The validated identity string, consumed.
            pub fn into_string(self) -> String {
                self.0
            }

            /// UNCHECKED constructor — TEST FIXTURES ONLY. Production code
            /// must construct through [`parse`] (or `FromStr`/`TryFrom`), so
            /// an invalid identity can never be built outside tests.
            #[cfg(test)]
            pub fn new(s: impl Into<String>) -> Self {
                $name(s.into())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = Error;
            fn from_str(s: &str) -> Result<$name> {
                $name::parse(s)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = Error;
            fn try_from(s: &str) -> Result<$name> {
                $name::parse(s)
            }
        }

        /// UNCHECKED conversion — TEST FIXTURES ONLY (mirrors `$name::new`).
        /// NOTE: deliberately NO `From<String>`/`From<&str>` impl — clap's
        /// value-parser inference prefers those over `FromStr`, which would
        /// silently bypass validation in test builds (and `From<&str>` would
        /// conflict with the validated `TryFrom<&str>`).

        impl<'de> Deserialize<'de> for $name {
            /// Wire strings go through the validated parse: an invalid wire
            /// identity fails deserialization (fail closed — a record that
            /// carries a malformed identity is never silently accepted).
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                $name::parse(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}
pub(crate) use id_newtype;
