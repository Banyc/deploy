//! The DIRECT-RELEASE membership gate: [`gate_direct_release_membership`]
//! rejects a `release:<id>` push whose direct-release membership drifted
//! from the current config, BEFORE any remote construction (zero remote
//! contact on mismatch, real and dry-run).

use crate::config::ProjectConfig;
use crate::error::Error;
use crate::error::Result;
use crate::identity::SlotId;
use crate::store::local::LocalStore;

/// The DIRECT-RELEASE MEMBERSHIP GATE ([`push`] step
/// 1c, both modes, immediately after the ref is parsed/resolved and BEFORE
/// any lock, any factory invocation): a `release:<id>` push deploys onto the
/// CURRENT target's slots, so the release's OWN frozen slot set must EXACTLY
/// equal the target's current membership. The check reads only the release
/// record (immutable store data) and the config — no lock, no remote — so a
/// drifting membership refuses HERE, before the remote factory inside
/// [`push_inner`](push_inner) is ever touched. For a
/// dry run the ref is already resolved; for a real push the direct form's
/// resolution (`RefExpr::Release` -> `PushRef::Release`) is store-free and
/// never touches the snapshot chain, so gating on the parsed form is exactly
/// equivalent to gating on the resolved ref. The gate compares the FULL
/// membership — `config.target_slots`, EVERY slot whose owning target equals
/// the target — never the group-filtered selection: a `release:<id>
/// --group <g>` push validates the complete set here and then plans only the
/// selected slots downstream.
pub(crate) fn gate_direct_release_membership(
    store: &LocalStore,
    config: &ProjectConfig,
    target_name: &str,
    ref_expr: &crate::ledger::RefExpr,
) -> Result<()> {
    if let crate::ledger::RefExpr::Release(release) = ref_expr {
        let rec = store
            .read_release(release)
            .map_err(|_| Error::rollback(format!("release {release} not available locally")))?;
        let current_slot_ids: Vec<SlotId> = config
            .target_slots(target_name)?
            .into_iter()
            .map(|(slot, _)| {
                SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment")
            })
            .collect();
        crate::deploy::plan::validate_direct_release_membership(
            target_name,
            release,
            &rec,
            &current_slot_ids,
        )?;
    }
    Ok(())
}
