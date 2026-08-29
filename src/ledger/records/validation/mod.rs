//! The RECORD-VALIDATION facets of the deployment ledger: the payload /
//! proof builders and the wire-format gates that VERIFY record integrity,
//! grouped here by their validation relatedness — the ROLLBACK PAYLOAD
//! builder ([`rollback`]'s [`build_rollback`]: the complete-snapshot overlay
//! with exact-binding verification semantics), the REBINDING PROOF records
//! ([`rebinding`]'s [`RebindingPlan`] / [`VerifiedReleaseRebinding`] /
//! [`FrozenSlotTopology`]), the SUCCESSFUL membership-equation enforcement
//! ([`membership`]'s [`verify_successful_membership_equations`]), and the
//! SCHEMA-VERSION constants ([`schema`]'s [`LEDGER_SCHEMA_VERSION`] /
//! [`PINS_SCHEMA_VERSION`]).
//!
//! The record SHAPES these facets validate live with their owners: the
//! rollback records ([`crate::ledger::records::TargetSnapshot`] /
//! [`crate::ledger::records::PhysicalBinding`] and [`crate::ledger::records::SnapshotEntry`]) in the shared core, the
//! plan records that carry the rebinding proof
//! ([`crate::ledger::records::DeploymentPlanWire`]) in the shared core, the
//! terminal conversion that enforces the membership equations in
//! [`crate::ledger::records::wire`].

mod membership;
mod rebinding;
mod rollback;
mod schema;

pub(crate) use membership::verify_successful_membership_equations;
pub use rebinding::{FrozenSlotTopology, RebindingPlan, VerifiedReleaseRebinding};
pub(crate) use rollback::BoundGeneration;
pub(crate) use rollback::build_rollback;
pub(crate) use rollback::validate_successful_rollback_against_intent;
pub(crate) use schema::{LEDGER_SCHEMA_VERSION, PINS_SCHEMA_VERSION};
