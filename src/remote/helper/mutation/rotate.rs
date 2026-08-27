//! Receiver rotation ([`RemoteHelper::rotate`]): mark-and-sweep retention
//! deleting tree objects and abandoned incoming directories not in the
//! retained set.

use crate::error::Result;
use crate::remote::layout;
use std::collections::HashSet;

use super::super::RemoteHelper;

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
