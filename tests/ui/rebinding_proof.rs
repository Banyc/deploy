//! The [`VerifiedReleaseRebinding`] proof is SEALED: every invariant-bearing
//! field is private, and the type carries a private `_sealed` marker — a
//! library caller cannot hand-construct a "verified" rebinding proof (a
//! struct literal is impossible). The persisted/wire form is the CLAIM
//! [`RebindingPlan`]; only the verification
//! (`TryFrom<(RebindingPlan, BTreeSet<SlotId>)>`) mints the proof.

use deploy::identity::ReleaseId;
use deploy::ledger::VerifiedReleaseRebinding;

fn main() {
    let release = ReleaseId::parse(
        "rel-sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .expect("valid release id");
    // ERROR: every field (including `_sealed`) is private — a struct
    // literal cannot be written by a library caller.
    let _proof = VerifiedReleaseRebinding {
        release,
        target: todo!(),
        frozen_topology: todo!(),
        membership: todo!(),
        selected_plan_slots: todo!(),
        current_physical_slots: todo!(),
        _sealed: (),
    };
}
