//! READ-ONLY remote construction + status inspection: [`open_remotes`]
//! builds one transport per member slot (no bytes written), then
//! [`inspect_remotes`] prepares the host identity and reads each slot's
//! status, preserving the original spine's factory-invocation order.

use crate::deploy::push::PushContext;
use crate::error::Result;
use crate::identity::SlotId;
use crate::remote::helper::{GenerationOwner, RemoteHelper};
use crate::remote::transport::Remote;
use std::collections::HashMap;

/// Open one remote handle per slot (the READ-ONLY factory loop of the
/// remote phase): construct the transport. No remote bytes are written and
/// no status is inspected here — [`inspect_remotes`] prepares the host
/// identity and reads status next, in the SAME order the original spine
/// ran them (factory for every member slot, THEN prepare_identity + status
/// for every member slot), so a recording factory's invocation order is
/// preserved exactly.
pub(crate) fn open_remotes(
    ctx: &PushContext,
    remotes: &mut HashMap<SlotId, Box<dyn Remote>>,
) -> Result<()> {
    let factory = ctx.factory;
    let target_name = ctx.target_name;
    let config = ctx.config;
    let all_members = config.target_slots(target_name)?;
    for (slot, s) in &all_members {
        let slot_id = SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment");

        let remote = factory(s, slot)?;
        remotes.insert(slot_id, remote);
    }
    Ok(())
}

/// Prepare the host identity and inspect status per slot (the READ-ONLY
/// half of the remote phase): `prepare_identity` pins only a LOCAL cache
/// and `status` is a read, so a later plan rejection (ref failure,
/// membership, behavior) still fails before any remote mutation. It must
/// run BEFORE reconciliation (which needs live helpers to verify
/// generations and write markers) and before resolution (which must see
/// the post-reconciliation chain).
pub(crate) fn inspect_remotes<'a>(
    ctx: &PushContext,
    remotes: &'a HashMap<SlotId, Box<dyn Remote>>,
    helpers: &mut HashMap<SlotId, RemoteHelper<'a>>,
    statuses: &mut HashMap<SlotId, crate::remote::helper::RemoteStatus>,
) -> Result<()> {
    let target_name = ctx.target_name;
    let config = ctx.config;
    let all_members = config.target_slots(target_name)?;
    for (slot, _s) in &all_members {
        let slot_id = SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment");

        let r = remotes.get(&slot_id).unwrap();
        let helper = RemoteHelper::new(r.as_ref());
        // Prepare the host identity (verify/pin the host key) BEFORE any status
        // request: a fingerprint-only configuration cannot connect at all
        // without the pinned key, and a dry run still connects to inspect
        // status. Pinning writes only to a LOCAL cache, never the remote
        // layout, so the dry-run "mutates nothing remotely" guarantee holds.
        r.prepare_identity()?;
        // Every status read verifies the generation's OWNER MARKER against
        // the expected owner (this application, this slot): a remote whose
        // current generation was transplanted from another application/slot
        // is refused here, fail closed.
        let owner = GenerationOwner::new(config.application().clone(), slot_id.clone());
        let status = helper.status(&owner)?;
        helpers.insert(slot_id.clone(), helper);
        statuses.insert(slot_id.clone(), status);
    }
    Ok(())
}
