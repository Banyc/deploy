//! Receiver rotation I/O (feature area A4).
//!
//! The retention-side contract lives in [`crate::retention::rotate`] (the A4
//! area owns the semantics): the slot's owning-variant policy computes the
//! retained digest set and the active incoming set, and
//! [`RemoteHelper::rotate`] — the mark-and-sweep pass hosted here — deletes
//! every tree object not in the retained set and every abandoned incoming
//! directory, then rewrites the inventory.

use crate::error::Result;
use crate::remote::helper::RemoteHelper;
use crate::remote::layout;
use std::collections::HashSet;

impl<'a> RemoteHelper<'a> {
    /// Mark-and-sweep retention: delete tree objects whose digest is not in the
    /// retained set, and remove abandoned incoming directories.
    pub fn rotate(
        &self,
        retained: &HashSet<String>,
        active_incoming: &HashSet<String>,
    ) -> Result<()> {
        let obj_root = layout::objects();
        if self.remote.exists(obj_root) {
            for e in self.remote.list(obj_root)? {
                if e.is_dir && !retained.contains(&e.name) {
                    self.remote.remove_dir_all(&obj_root.join(&e.name))?;
                }
            }
        }
        let inc = layout::incoming();
        if self.remote.exists(inc) {
            for e in self.remote.list(inc)? {
                if e.is_dir && !active_incoming.contains(&e.name) {
                    self.remote.remove_dir_all(&inc.join(&e.name))?;
                }
            }
        }
        self.write_inventory()?;
        Ok(())
    }
}
