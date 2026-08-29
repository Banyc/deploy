//! Per-operation transaction records ([`RemoteHelper::transaction_record`]):
//! the durable `transactions/<op-id>.json` recovery record.

use crate::error::{Error, Result};
use crate::remote::layout;

use super::super::{RemoteHelper, now_rfc3339};

impl<'a> RemoteHelper<'a> {
    /// Persist a transaction record. Requires the slot-mutation capability — only
    /// callable via `HeldSlotLock::transaction_record` (the receiver is the guard;
    /// the helper is the guard's own — a guard can only mutate the slot it was
    /// acquired from; there is no API parameter through which a guard from server A
    /// can authorize a mutation on server B). This is the durable per-operation recovery record
    /// (`transactions/<op-id>.json`, advanced `prepared` → `committed` →
    /// `compensated`): a disconnected client learns an operation's outcome by
    /// reading it, not from any per-server history log.
    pub(crate) fn transaction_record_locked(&self, op_id: &str, state: &str) -> Result<()> {
        let p = layout::transaction_record(op_id);
        let payload = serde_json::json!({
            "operation_id": op_id,
            "state": state,
            "updated_at": now_rfc3339(),
        });
        let bytes = serde_json::to_vec_pretty(&payload)
            .map_err(|e| Error::remote(format!("serialize transaction: {e}")))?;
        self.remote.write(&p, &bytes, 0o644)?;
        Ok(())
    }
}
