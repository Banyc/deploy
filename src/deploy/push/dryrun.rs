//! Dry-run plan computation/rendering (A1 deployment semantics):
//! [`render_dry_run_plan`] renders the READ-ONLY dry-run report from the
//! planned assignments and the observed pre-push statuses.

use crate::deploy::plan::PlannedAssignment;
use crate::identity::{BehaviorContract, GenerationId, SlotId};
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
    behaviors: &crate::ledger::records::BehaviorIndex,
) -> String {
    let mut msg = String::new();
    for a in assignments {
        let st = statuses.get(&a.placement_slot).expect("status present");
        let cur = st.current_generation().cloned();
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
        // The behavior contract that will run on this slot (activation +
        // verification) — so a dry run shows an agent what the push will
        // DO, not just what it will write.
        if let Some(by_variant) = behaviors.get(&a.artifact.release)
            && let Some(behavior) = by_variant.get(a.artifact.variant.as_str())
        {
            msg.push_str(&format!("  {}\n", render_behavior(behavior)));
        }
    }
    msg
}

/// Render a behavior contract (activation + verification) for the dry-run
/// plan: the activation adapter (and its units) and the verification command
/// that will run on the slot.
fn render_behavior(behavior: &BehaviorContract) -> String {
    use crate::config::{Activation, Verification};
    let activation = match behavior.activation() {
        Activation::None => "none".to_string(),
        Activation::Systemd(sa) => format!(
            "systemd (units: {})",
            sa.units().map(|u| u.name()).collect::<Vec<_>>().join(", ")
        ),
    };
    let verification = match behavior.verification() {
        Verification::Command(vc) => format!("command: {}", vc.argv().join(" ")),
    };
    format!("activation={activation} verification={verification}")
}
