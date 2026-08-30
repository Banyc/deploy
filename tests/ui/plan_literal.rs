//! The domain [`DeploymentPlan`] fields are PRIVATE: a plan is
//! constructible only through the verifying wire → domain conversion
//! (`DeploymentPlanWire::into_domain`) or the crate-internal plan builder —
//! a library caller CANNOT fabricate a plan whose `slots` / `source` /
//! `behaviors` disagree (a forged Release origin carrying a fake rebinding
//! proof is unrepresentable).

use deploy::ledger::DeploymentPlan;

fn d<T>() -> T {
    panic!("never reached")
}

fn main() {
    // ERROR: every field of `DeploymentPlan` is private; a struct literal
    // cannot be written by a library caller.
    let _plan = DeploymentPlan {
        deployment_id: d(),
        target: d(),
        behaviors: d(),
        slots: d(),
        source: d(),
    };
}
