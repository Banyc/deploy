//! Identity and proof semantics (feature inventory A6).
//!
//! The deployment core is deliberately ignorant of application semantics. It
//! understands only filesystem entries, mappings, trees, artifacts, variants,
//! releases, targets, and activation adapters. Every identity-bearing value
//! lives in this area, three modules:
//!
//! * [`identity`] — THE IDENTITY TYPES (one cohesive feature, split into
//!   sections): the release id ([`ReleaseId`]: EXACT
//!   `rel-sha256-<64 lowercase hex>`; bare/`rel-` forms rejected at the
//!   domain boundary — the CLI accepts a bare 64-hex digest, converted
//!   first), the event ids ([`DeploymentId`]/[`GenerationId`]/
//!   [`OperationId`]: `deploy-`/`gen-`/`op-` + canonical hyphenated UUIDv7,
//!   version nibble enforced; v4 rejected), the digests
//!   ([`TreeDigest`]/[`ReleaseDigest`]: exactly 64 lowercase hex), the
//!   segment ids ([`SlotId`], [`ServerId`], [`TargetName`], [`VariantName`]:
//!   a single safe path segment), and the validated scalars
//!   ([`Identifier`], [`ApplicationStoreKey`], [`BatchSize`] (nonzero u64),
//!   [`CapacityPercent`] (0..=100), [`AbsoluteDeployDir`] (absolute,
//!   traversal-free), [`BehaviorDigest`], [`Timestamp`],
//!   [`RolloutGroupName`], [`Host`], [`SshUser`]).
//! * [`payload`] — the release identity payload ([`CanonicalReleasePayload`]:
//!   name-sorted mapping digest + behavior digest + slot-declaration digest +
//!   variant→tree bindings; capacity excluded, slots ARE identity) and the
//!   canonical payload/record types.
//! * [`proofs`] — the membership proofs [`SlotSet`]/[`NonEmptySlotSet`]/
//!   [`MatchingMembership`]: the ONLY construction path is
//!   [`MatchingMembership::verify`] (frozen == current).
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

// The identity-types module: the regroup spec names the file `identity.rs`
// (the module of the identity types inside the identity area), so
// `mod identity;` inside `src/identity/mod.rs` is intentionally
// same-named — clippy::module_inception is suppressed deliberately.
#[allow(clippy::module_inception)]
mod identity;
mod payload;
mod proofs;

pub use identity::*;
pub use payload::*;
pub(crate) use proofs::*;

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

        /// UNCHECKED conversion — TEST FIXTURES ONLY (mirrors [`$name::new`]).
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
