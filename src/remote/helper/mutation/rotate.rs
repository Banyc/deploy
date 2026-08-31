//! Receiver rotation ([`HeldSlotLock::rotate`]): mark-and-sweep retention
//! deleting tree objects and abandoned incoming directories not in the
//! retained set. Rotation is a DESTRUCTIVE operation and therefore a
//! [`HeldSlotLock`] method — there is no unguarded `RemoteHelper::rotate`
//! entry point (a caller must HOLD the slot's mutation lock to sweep it).

use crate::error::{Error, Result};
use crate::identity::GenerationId;
use crate::remote::layout;
use std::collections::HashSet;

use super::super::HeldSlotLock;

impl<'a> HeldSlotLock<'a> {
    /// Mark-and-sweep retention: delete tree objects whose digest is not in the
    /// retained set, and remove abandoned incoming directories. Requires the
    /// slot-mutation capability — the receiver is the guard; the helper is the
    /// guard's own.
    ///
    /// THE GENERATION INVENTORY IS VERIFIED BEFORE ANY DELETION: every
    /// generation record on this remote must carry THIS guard's owner marker
    /// ([`crate::remote::helper::RemoteHelper::read_assignment`] — the
    /// owner-verified read). A foreign/transplanted generation — state that
    /// belongs to a different application/slot — ABORTS rotation with ZERO
    /// deletions (fail closed): it is never swept as if it were ours, and its
    /// trees are never deleted by a guard that does not own them.
    pub fn rotate(
        &self,
        retained: &HashSet<String>,
        active_incoming: &HashSet<String>,
    ) -> Result<()> {
        self.verify_generation_inventory()?;
        let obj_root = layout::objects();
        if self.helper.remote.metadata_opt(obj_root)?.is_some() {
            for e in self.helper.remote.list(obj_root)? {
                if e.is_dir && !retained.contains(&e.name) {
                    self.helper
                        .remote
                        .remove_dir_all(&obj_root.join(&e.name)?)?;
                }
            }
        }
        let inc = layout::incoming();
        if self.helper.remote.metadata_opt(inc)?.is_some() {
            for e in self.helper.remote.list(inc)? {
                if e.is_dir && !active_incoming.contains(&e.name) {
                    self.helper.remote.remove_dir_all(&inc.join(&e.name)?)?;
                }
            }
        }
        self.helper.write_inventory()?;
        Ok(())
    }

    /// Verify the generation inventory against THIS guard's owner before
    /// sweeping: every generation record on this remote must carry the
    /// guard's owner marker — a foreign/transplanted generation aborts
    /// rotation with zero deletions (never swept as if it were ours). A
    /// malformed/ownerless record fails closed the same way (the same
    /// fail-closed rule the retained-set computation honors).
    fn verify_generation_inventory(&self) -> Result<()> {
        let gen_root = layout::generations();
        if self.helper.remote.metadata_opt(gen_root)?.is_none() {
            return Ok(());
        }
        for entry in self.helper.remote.list(gen_root)? {
            if !entry.is_dir {
                continue;
            }
            let dir_gen = GenerationId::parse(&entry.name).map_err(|err| {
                Error::integrity(format!(
                    "generation directory {} names an invalid generation id: {err}",
                    entry.name
                ))
            })?;
            let a = self
                .helper
                .read_assignment(&dir_gen, &self.owner)
                .map_err(|err| {
                    Error::integrity(format!(
                        "rotation refused: generation {} is not owned by this slot (application '{}', slot '{}'): {err}",
                        entry.name, self.owner.application, self.owner.slot
                    ))
                })?;
            if a.generation_id != dir_gen {
                return Err(Error::integrity(format!(
                    "generation {} assignment names generation {}, not its directory",
                    entry.name, a.generation_id
                )));
            }
        }
        Ok(())
    }
}
