//! Per-operation transaction records ([`RemoteHelper::transaction_record`]):
//! the durable `transactions/<op-id>.json` recovery record.

use crate::error::{Error, Result};
use crate::remote::layout;

use super::super::{RemoteHelper, now_rfc3339};

impl<'a> RemoteHelper<'a> {
    /// Persist a transaction record. This is the durable per-operation recovery
    /// record (`transactions/<op-id>.json`, advanced `prepared` → `committed` →
    /// `compensated`): a disconnected client learns an operation's outcome by
    /// reading it, not from any per-server history log.
    pub fn transaction_record(&self, op_id: &str, state: &str) -> Result<()> {
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
