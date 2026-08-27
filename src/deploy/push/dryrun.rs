//! Dry-run plan computation/rendering (A1 deployment semantics):
//! [`render_dry_run_plan`] renders the READ-ONLY dry-run report from the
//! planned assignments and the observed pre-push statuses.

use crate::deploy::plan::PlannedAssignment;
use crate::identity::GenerationId;
use crate::identity::SlotId;
use crate::remote::helper::RemoteStatus;
use crate::store::local::LocalStore;
use std::collections::HashMap;

// Dry-run plan computation/rendering (A1 deployment semantics).
//
// `render_dry_run_plan` renders the READ-ONLY dry-run report from the
// planned assignments and the observed pre-push statuses: per slot, the
// current → desired generation line (or the first-deployment line), plus
// the would-recover note when the planned tree is missing locally. The
// caller ([`crate::deploy::push`]) performs the disposable-staging cleanup
// and returns the report — the render itself touches nothing.

/// Render the dry-run plan lines: each SELECTED slot's current → desired
/// generation (or first-deployment line), plus the would-recover note for a
/// planned tree missing from the local object store. Pure plan data — no
/// store mutation, no remote access, no locks.
pub(crate) fn render_dry_run_plan(
    store: &LocalStore,
    assignments: &[PlannedAssignment],
    statuses: &HashMap<SlotId, RemoteStatus>,
    new_gen: &HashMap<SlotId, GenerationId>,
) -> String {
    let mut msg = String::new();
    for a in assignments {
        let st = statuses.get(&a.placement_slot).expect("status present");
        let cur = st.current_generation.clone();
        let want = new_gen[&a.placement_slot].as_str().to_string();
        let missing_locally = !store.object_exists(&a.artifact.tree);
        let note = match cur {
            Some(c) if c.as_str() == want => format!(
                "slot {}: already at desired generation ({})\n",
                a.placement_slot, c
            ),
            Some(c) => format!(
                "slot {}: current {} -> desired {} (tree {})\n",
                a.placement_slot, c, want, a.artifact.tree
            ),
            None => format!(
                "slot {}: first deployment (tree {})\n",
                a.placement_slot, a.artifact.tree
            ),
        };
        msg.push_str(&note);
        if missing_locally {
            msg.push_str(&format!(
                "  would recover tree {} from a retaining server\n",
                a.artifact.tree
            ));
        }
    }
    msg
}
