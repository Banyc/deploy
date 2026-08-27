//! THE PROOF MACHINERY — a group DIRECTORY of the two modules that give the
//! identity its durable content and its membership proofs:
//!
//! * [`payload`] — the release identity payload
//!   ([`crate::identity::CanonicalReleasePayload`]: name-sorted mapping
//!   digest + behavior digest + slot-declaration digest + variant→tree
//!   bindings; capacity excluded, slots ARE identity) and the canonical
//!   payload/record types.
//! * [`proofs`] — the membership proofs
//!   [`crate::identity::SlotSet`]/[`crate::identity::NonEmptySlotSet`]/
//!   [`crate::identity::MatchingMembership`]: the ONLY construction path is
//!   [`crate::identity::MatchingMembership::verify`] (frozen == current).
//!
//! The area root re-exports the payload types FLAT
//! (`crate::identity::CanonicalReleasePayload`) and the crate-internal
//! proof types via the pub(crate) glob (`crate::identity::SlotSet`), and
//! the module paths resolve too (`crate::identity::proof::payload` /
//! `crate::identity::proof::proofs`).

pub mod payload;
pub mod proofs;
