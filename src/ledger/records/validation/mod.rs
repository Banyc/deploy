//! The RECORD-VALIDATION facets of the deployment ledger: the proof records
//! and the wire-format gates that VERIFY record integrity — the REBINDING
//! PROOF records ([`rebinding`]'s [`RebindingPlan`] /
//! [`VerifiedReleaseRebinding`] / [`FrozenSlotTopology`]) and the
//! SCHEMA-VERSION constants ([`schema`]'s [`LEDGER_SCHEMA_VERSION`] /
//! [`PINS_SCHEMA_VERSION`]).
//!
//! The record SHAPES these facets validate live with their owners. The
//! old ROLLBACK-PAYLOAD / MEMBERSHIP-EQUATION validators
//! (`build_rollback`, `validate_successful_rollback_against_intent`,
//! `verify_successful_membership_equations`) are GONE: a successful
//! deployment's rollback state IS its intent's derived resulting snapshot
//! (one stored copy, resolved on demand — there is no second payload to
//! validate against), and the ledger's cross-record transitions are
//! validated by the SEMANTIC KERNEL ([`crate::kernel::transition`]).

mod rebinding;
mod schema;

pub use rebinding::{FrozenSlotTopology, RebindingPlan, VerifiedReleaseRebinding};
pub(crate) use schema::{LEDGER_SCHEMA_VERSION, PINS_SCHEMA_VERSION};
