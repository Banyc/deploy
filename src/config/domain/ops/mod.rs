// =====================================================================
// ---- mutation ops ----
// =====================================================================
// The VALIDATED MUTATION / REBUILD operations on [`ProjectConfig`]: every
// operation clones the graph, mutates the clone, and ends in the SINGLE
// graph gate [`ProjectConfig::try_build`] (canonicalize all leaves,
// validate the complete graph — references resolve, ids valid and unique,
// no impossible combos, the connection enum well-formed, the
// physical-location injection rule), returning either a NEW
// [`ProjectConfig`] or `Err` with the ORIGINAL untouched — the only way
// an immutable validated graph can change. This includes the
// release-switch [`ProjectConfig::load_release`] (a FRESH validated load
// with a new release selected), the per-class validated rebuilds
// ([`ProjectConfig::with_server`] / [`ProjectConfig::without_server`] /
// [`ProjectConfig::rename_server`], [`ProjectConfig::with_target`] /
// [`ProjectConfig::without_target`] / [`ProjectConfig::rename_target`],
// [`ProjectConfig::with_pin`] / [`ProjectConfig::without_pin`] /
// [`ProjectConfig::rename_pin`], [`ProjectConfig::with_slot`] /
// [`ProjectConfig::without_slot`] / [`ProjectConfig::rename_slot`],
// [`ProjectConfig::with_server_connection`],
// [`ProjectConfig::with_server_capacity`]) — and the raw -> domain
// conversion ends in the SAME gate, so loading and mutation share ONE
// validator.

use super::{ProjectConfig, TargetConfig};
use crate::config::capacity::CapacityConfig;
use crate::config::pins::Pin;
use crate::config::release_name::{ReleaseName, validate_release_name};
use crate::config::servers::{ServerConnection, ServerDef};
use crate::config::slots::SlotConfig;
use crate::error::{Error, Result};
use crate::identity::{Identifier, ReleaseId};
use std::path::Path;

impl ProjectConfig {
    /// The VALIDATED release-switch operation: a FRESH LOAD of the project at
    /// `path` with `release` selected. The deploy.toml is re-read, the release
    /// field is overridden with `release` (whose name is re-validated —
    /// exactly one directory component; otherwise `Err`), and THAT release's
    /// variant files are re-discovered and re-validated by the raw -> domain
    /// conversion: a missing or invalid release's variant files fail the
    /// whole load, so the result is a complete, freshly-validated
    /// [`ProjectConfig`] for the new release — never a partially-switched
    /// config.
    pub fn load_release(path: &Path, release: ReleaseName) -> Result<ProjectConfig> {
        validate_release_name(release.as_str())?;
        let mut manifest = Self::read_manifest(path)?;
        manifest.release = release;
        let variants = manifest.load_variant_files(path)?;
        ProjectConfig::from_raw_parts(manifest, variants)
    }

    /// Add or replace a server (keyed by its id). Re-validates the whole
    /// graph: a duplicate id, a slot reference left dangling, or an
    /// ill-formed connection fails the operation and the ORIGINAL is
    /// untouched (the operation never mutates).
    pub fn with_server(&self, server: ServerDef) -> Result<ProjectConfig> {
        let mut next = self.clone();
        if let Some(existing) = next.servers.iter_mut().find(|s| s.id == server.id) {
            *existing = server;
        } else {
            next.servers.push(server);
        }
        next.try_build()
    }

    /// Remove a server. Fails if any slot references it (the graph would
    /// dangle); the ORIGINAL is untouched.
    pub fn without_server(&self, id: &str) -> Result<ProjectConfig> {
        let mut next = self.clone();
        let Some(pos) = next.servers.iter().position(|s| s.id.as_str() == id) else {
            return Err(Error::not_found(format!("server '{id}'")));
        };
        next.servers.remove(pos);
        next.try_build()
    }

    /// Rename a server, rewriting every slot reference. Fails if the new id
    /// collides with an existing server; the ORIGINAL is untouched.
    pub fn rename_server(&self, old: &str, new: &str) -> Result<ProjectConfig> {
        let new_id = Identifier::parse(new).map_err(|_| {
            Error::config(format!(
                "server id '{new}' must be a non-empty, well-formed identifier"
            ))
        })?;
        let mut next = self.clone();
        if !next.servers.iter().any(|s| s.id.as_str() == old) {
            return Err(Error::not_found(format!("server '{old}'")));
        }
        if next.servers.iter().any(|s| s.id.as_str() == new) {
            return Err(Error::config(format!("duplicate server id '{new}'")));
        }
        for server in &mut next.servers {
            if server.id.as_str() == old {
                server.id = new_id.clone();
            }
        }
        for variant in next.variants.values_mut() {
            for slot in &mut variant.slots {
                if slot.server == old {
                    slot.server = new.to_string();
                }
            }
        }
        next.try_build()
    }

    /// Add or replace a target (keyed by its name). A NEW target must already
    /// have at least one member slot (the per-target non-empty rule is
    /// re-validated), so adding a target with no slots fails; the ORIGINAL is
    /// untouched.
    pub fn with_target(&self, name: &str, target: TargetConfig) -> Result<ProjectConfig> {
        Identifier::parse(name).map_err(|_| {
            Error::config(format!(
                "target name '{name}' must be a non-empty, well-formed identifier"
            ))
        })?;
        let mut next = self.clone();
        next.targets.insert(name.to_string(), target);
        next.try_build()
    }

    /// Remove a target. Fails if any slot references it (the graph would
    /// dangle); the ORIGINAL is untouched.
    pub fn without_target(&self, name: &str) -> Result<ProjectConfig> {
        let mut next = self.clone();
        if next.targets.remove(name).is_none() {
            return Err(Error::not_found(format!("target '{name}'")));
        }
        next.try_build()
    }

    /// Rename a target, rewriting every slot reference. Fails if the new
    /// name collides with an existing target; the ORIGINAL is untouched.
    pub fn rename_target(&self, old: &str, new: &str) -> Result<ProjectConfig> {
        Identifier::parse(new).map_err(|_| {
            Error::config(format!(
                "target name '{new}' must be a non-empty, well-formed identifier"
            ))
        })?;
        let mut next = self.clone();
        let Some(target) = next.targets.remove(old) else {
            return Err(Error::not_found(format!("target '{old}'")));
        };
        if next.targets.contains_key(new) {
            return Err(Error::config(format!("duplicate target name '{new}'")));
        }
        next.targets.insert(new.to_string(), target);
        for variant in next.variants.values_mut() {
            for slot in &mut variant.slots {
                if slot.target == old {
                    slot.target = new.to_string();
                }
            }
        }
        next.try_build()
    }

    /// Add a durable retention pin. Pins carry no graph invariants, but the
    /// whole graph is still re-validated; the ORIGINAL is untouched.
    pub fn with_pin(&self, pin: Pin) -> Result<ProjectConfig> {
        let mut next = self.clone();
        next.pins.push(pin);
        next.try_build()
    }

    /// Remove every pin naming the given release. Fails if no pin names it;
    /// the ORIGINAL is untouched. The release is a typed [`ReleaseId`] (valid
    /// by construction), so a removed pin always names a grammar-valid
    /// release.
    pub fn without_pin(&self, release: &ReleaseId) -> Result<ProjectConfig> {
        let mut next = self.clone();
        let before = next.pins.len();
        next.pins.retain(|p| p.release != *release);
        if next.pins.len() == before {
            return Err(Error::not_found(format!("pin for release '{release}'")));
        }
        next.try_build()
    }

    /// Rename every pin naming `old` to name `new`. Fails if no pin names
    /// `old`; the ORIGINAL is untouched. Both ids are typed [`ReleaseId`]s, so
    /// `new` is valid by construction — the renamed pin always names a
    /// grammar-valid release.
    pub fn rename_pin(&self, old: &ReleaseId, new: &ReleaseId) -> Result<ProjectConfig> {
        let mut next = self.clone();
        let mut renamed = false;
        for pin in &mut next.pins {
            if pin.release == *old {
                pin.release = new.clone();
                renamed = true;
            }
        }
        if !renamed {
            return Err(Error::not_found(format!("pin for release '{old}'")));
        }
        next.try_build()
    }

    /// Add or replace a slot inside a variant (keyed by slot id).
    /// Re-validates the whole graph: a duplicate slot id, an unresolvable
    /// server/target reference, a relative deploy_dir, a shared location, or
    /// a target left without members fails the operation and the ORIGINAL is
    /// untouched.
    pub fn with_slot(&self, variant: &str, slot: SlotConfig) -> Result<ProjectConfig> {
        let mut next = self.clone();
        let Some(v) = next.variants.get_mut(variant) else {
            return Err(Error::not_found(format!("variant '{variant}'")));
        };
        if let Some(existing) = v.slots.iter_mut().find(|s| s.id == slot.id) {
            *existing = slot;
        } else {
            v.slots.push(slot);
        }
        next.try_build()
    }

    /// Remove a slot from a variant. Fails if the slot does not exist or its
    /// target would be left without members; the ORIGINAL is untouched.
    pub fn without_slot(&self, variant: &str, slot_id: &str) -> Result<ProjectConfig> {
        let mut next = self.clone();
        let Some(v) = next.variants.get_mut(variant) else {
            return Err(Error::not_found(format!("variant '{variant}'")));
        };
        let before = v.slots.len();
        v.slots.retain(|s| s.id != slot_id);
        if v.slots.len() == before {
            return Err(Error::not_found(format!(
                "slot '{slot_id}' in variant '{variant}'"
            )));
        }
        next.try_build()
    }

    /// Rename a slot inside a variant. Fails if the slot does not exist or
    /// the new id collides; the ORIGINAL is untouched.
    pub fn rename_slot(&self, variant: &str, old: &str, new: &str) -> Result<ProjectConfig> {
        let mut next = self.clone();
        let Some(v) = next.variants.get_mut(variant) else {
            return Err(Error::not_found(format!("variant '{variant}'")));
        };
        let mut renamed = false;
        for slot in &mut v.slots {
            if slot.id == old {
                slot.id = new.to_string();
                renamed = true;
            }
        }
        if !renamed {
            return Err(Error::not_found(format!(
                "slot '{old}' in variant '{variant}'"
            )));
        }
        next.try_build()
    }

    /// Replace a server's EXACTLY ONE connection form. Re-validates the
    /// whole graph (the connection enum must be well-formed); the ORIGINAL is
    /// untouched.
    pub fn with_server_connection(
        &self,
        id: &str,
        connection: ServerConnection,
    ) -> Result<ProjectConfig> {
        let mut next = self.clone();
        let Some(server) = next.servers.iter_mut().find(|s| s.id.as_str() == id) else {
            return Err(Error::not_found(format!("server '{id}'")));
        };
        *server = ServerDef::new(server.id.clone(), connection, server.capacity.clone());
        next.try_build()
    }

    /// Replace a server's capacity headroom policy. Re-validates the whole
    /// graph; the ORIGINAL is untouched.
    pub fn with_server_capacity(
        &self,
        id: &str,
        capacity: CapacityConfig,
    ) -> Result<ProjectConfig> {
        let mut next = self.clone();
        let Some(server) = next.servers.iter_mut().find(|s| s.id.as_str() == id) else {
            return Err(Error::not_found(format!("server '{id}'")));
        };
        server.capacity = capacity;
        next.try_build()
    }
}

#[cfg(test)]
mod tests;
