//! Proof-bearing slot-set types (immutability + membership proofs).
//!
//! The proof-bearing resolution layer builds on two slot-set forms:
//!
//! * [`SlotSet`] — a plain (possibly EMPTY) slot-id set, the INPUT form of a
//!   membership verification.
//! * [`NonEmptySlotSet`] — the NON-EMPTY, UNIQUE slot-id set: the canonical
//!   membership/set form carried by the proof types ([`MatchingMembership`],
//!   and the planner's resolved selection). Compose with the sibling
//!   records-shape `NonEmptySlotTable` (the map form): this is the set form
//!   of the same non-empty membership invariant.
//!
//! [`MatchingMembership`] is the PROOF that two memberships match: the ONLY
//! way to obtain one is [`MatchingMembership::verify`] (the membership gate
//! produces it; the planner consumes it). THE PROOF IMPLEMENTS NEITHER
//! `Serialize` NOR `Deserialize` — a proof is produced ONLY by verification,
//! never parsed from the wire. The persisted wire form of an agreed
//! membership is the plain agreed slot set carried by the CLAIM
//! ([`crate::ledger::RebindingPlan`]); the wire -> domain conversion
//! RE-MINTS the proof by re-verifying the claimed set against the release
//! graph ([`crate::verify::release::ValidatedRelease`]) on read.

use crate::error::{Error, Result};
use crate::identity::SlotId;
use std::collections::BTreeSet;

/// A slot-ID set (possibly EMPTY) — the INPUT form of a membership
/// verification ([`MatchingMembership::verify`]). A plain set of
/// [`SlotId`]s; emptiness is legal here (the non-empty requirement
/// applies to the PROOF result, never to the inputs being compared).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct SlotSet(BTreeSet<SlotId>);

impl SlotSet {
    /// Build a slot set from slot ids; duplicate ids collapse (a set).
    pub(crate) fn new(ids: impl IntoIterator<Item = SlotId>) -> Self {
        SlotSet(ids.into_iter().collect())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The number of distinct slot ids (test-facing: the proof legs that
    /// used the count in production were removed with the rollback payload).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// The distinct slot ids in sorted (deterministic) order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &SlotId> {
        self.0.iter()
    }
}

/// The NON-EMPTY, UNIQUE slot-ID set: the canonical membership/slot-set
/// type carried by the proof-bearing types AND the ledger's
/// [`crate::ledger::TerminalDisposition::Successful`] activated set.
/// Construction is gated on non-emptiness ([`NonEmptySlotSet::try_new`]
/// refuses an empty input) — a target with zero slots is never a valid
/// resolution or membership proof (the raw -> domain conversion rejects
/// targets without slots), so the invariant holds by construction. This is
/// the SET form; the sibling records-shape work carries the companion
/// [`NonEmptySlotTable`]-shaped (map-keyed) non-empty tables the records
/// use. Shared by the identity proofs and the ledger's successful-chain
/// membership — the non-empty invariant is the same structural guarantee
/// (the activated set is non-empty by TYPE).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonEmptySlotSet(BTreeSet<SlotId>);

impl NonEmptySlotSet {
    /// Build from slot ids; `None` when the input is EMPTY (a non-empty set
    /// cannot be built from nothing). Duplicate ids are deduplicated (a set).
    pub(crate) fn try_new(ids: impl IntoIterator<Item = SlotId>) -> Option<Self> {
        let ids: BTreeSet<SlotId> = ids.into_iter().collect();
        (!ids.is_empty()).then_some(NonEmptySlotSet(ids))
    }

    /// The number of distinct slot ids (test-facing today: the resolved
    /// memberships' counts are asserted by the planner property tests).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The distinct slot ids in sorted (deterministic) order.
    pub fn iter(&self) -> impl Iterator<Item = &SlotId> {
        self.0.iter()
    }

    /// Whether the set contains the slot id (test-facing today: the
    /// planner's membership assertions check the resolved set contains the
    /// member slot).
    #[cfg(test)]
    pub(crate) fn contains(&self, id: &SlotId) -> bool {
        self.0.contains(id)
    }

    /// The backing set as a read-only view (composes with the sibling
    /// records-shape non-empty tables, which carry the same slot keys).
    pub fn as_set(&self) -> &BTreeSet<SlotId> {
        &self.0
    }
}

/// The PROOF that two slot-ID memberships match: the frozen (historical)
/// and current (live) memberships verified EXACTLY EQUAL, carrying the
/// agreed NON-EMPTY slot set. The ONLY construction path is
/// [`MatchingMembership::verify`] — the membership gate produces the proof
/// and the planner consumes it (a [`crate::ledger::RebindingPlan`] records
/// the AGREED SET as a claim component; the proof itself is re-minted by
/// re-verification on read). THE PROOF IMPLEMENTS NEITHER `Serialize` NOR
/// `Deserialize`: a proof is produced only by verification, never parsed
/// from the wire — the persisted wire form of the agreement is the plain
/// agreed slot set on the claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MatchingMembership {
    slots: NonEmptySlotSet,
}

impl MatchingMembership {
    /// Verify that the FROZEN and CURRENT slot memberships are EXACTLY
    /// EQUAL and non-empty, producing the proof. `Ok` exactly when
    /// `frozen == current` and the agreed set is non-empty (a target's
    /// membership is never empty — the raw -> domain conversion rejects
    /// targets without slots, so an empty agreement can never be a proof);
    /// `Err` on any mismatch or an empty agreement. This is the ONLY
    /// construction path: the fields are private, so a `MatchingMembership`
    /// cannot be hand-built.
    pub fn verify(frozen: SlotSet, current: SlotSet) -> Result<Self> {
        if frozen.is_empty() || current.is_empty() {
            return Err(Error::rollback(
                "membership proof refused: a membership is never empty",
            ));
        }
        if frozen != current {
            return Err(Error::rollback(
                "membership proof refused: frozen and current slot sets differ",
            ));
        }
        // `frozen == current` and both non-empty: the agreed set is non-empty.
        let slots = NonEmptySlotSet::try_new(frozen.iter().cloned()).ok_or_else(|| {
            Error::internal("verified-equal non-empty memberships yield a non-empty set")
        })?;
        Ok(MatchingMembership { slots })
    }

    /// The agreed (frozen == current) membership: the non-empty slot set
    /// the proof verifies. Read path: the wire → domain conversion
    /// re-checks the claimed proof's agreed set against the plan's own
    /// membership (the frozen topology keys must equal it, and every
    /// selected plan slot must be a member); the property suite asserts its
    /// content through this accessor.
    pub(crate) fn slots(&self) -> &NonEmptySlotSet {
        &self.slots
    }
}

// DELIBERATELY NO serde impls: a proof is produced ONLY by verification
// ([`MatchingMembership::verify`]), never parsed from the wire. The
// persisted wire form of an agreement is the plain agreed slot set carried
// by the CLAIM ([`crate::ledger::RebindingPlan`]); the wire -> domain
// conversion re-mints the proof by re-verifying the claimed set against the
// release graph on read.
