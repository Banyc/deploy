//! The [`VerifiedReleaseRebinding`] proof implements NEITHER `Serialize`
//! NOR `Deserialize`: a wire string can deserialize into the CLAIM
//! [`RebindingPlan`] — never into a "verified" proof without running the
//! verification. The `TryFrom<(RebindingPlan, BTreeSet<SlotId>)>` conversion
//! is the only wire → domain path, and it recomputes the proof.

use deploy::ledger::{VerifiedReleaseRebinding, RebindingPlan};

fn main() {
    // ERROR: `VerifiedReleaseRebinding` has no `Deserialize` impl — a
    // "verified" rebinding proof can never be read from a wire string.
    let _deserialized: VerifiedReleaseRebinding =
        serde_json::from_str("{}").expect("this line must not compile");
    // The WIRE CLAIM does deserialize (it is the persisted form).
    let _claim: RebindingPlan = serde_json::from_str("{}").expect("the wire claim deserializes");
}
