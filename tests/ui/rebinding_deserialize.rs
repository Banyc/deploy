//! The [`VerifiedReleaseRebinding`] proof implements NEITHER `Serialize`
//! NOR `Deserialize`: a wire string can deserialize into the CLAIM
//! [`RebindingPlan`] — never into a "verified" proof without running the
//! verification. The `TryFrom<(RebindingPlan, BTreeSet<SlotId>)>` conversion
//! is the only wire → domain path, and it recomputes the proof.
//!
//! The claims are expressed as trait bounds on a generic argument, so the
//! diagnostic points at a bound declared HERE: a bound inside another crate's
//! function (`serde_json::from_str`) renders with a snippet this file cannot
//! pin, and rustc releases disagree on it.

use deploy::ledger::{RebindingPlan, VerifiedReleaseRebinding};

/// Demands a wire deserializer for `T`. The proof has no such impl, so it can
/// never be handed to ANY deserializer.
fn requires_deserialize<T: for<'de> serde::Deserialize<'de>>() {}

/// Demands a wire serializer for `T`. A "verified" proof is never written to
/// the wire either — the persisted form is the claim.
fn requires_serialize<T: serde::Serialize>() {}

fn main() {
    // ERROR: `VerifiedReleaseRebinding` has no `Deserialize` impl — a
    // "verified" rebinding proof can never be read from a wire string.
    requires_deserialize::<VerifiedReleaseRebinding>();
    // ERROR: and no `Serialize` impl — the proof is never written out.
    requires_serialize::<VerifiedReleaseRebinding>();
    // The WIRE CLAIM does deserialize (it is the persisted form).
    let _claim: RebindingPlan = serde_json::from_str("{}").expect("the wire claim deserializes");
}
