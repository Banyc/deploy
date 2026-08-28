// =====================================================================
// ---- mutation ops ----
// =====================================================================
// The VALIDATED MUTATION / REBUILD operations on [`ProjectConfig`]: every
// operation clones the graph, mutates the clone, re-validates the WHOLE
// graph (references resolve, ids valid and unique, no impossible combos,
// the connection enum well-formed), and returns either a NEW
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
// [`ProjectConfig::with_server_capacity`]), and the single graph gate
// [`ProjectConfig::validate_graph`] every rebuild runs.

use super::{ProjectConfig, TargetConfig};
use crate::config::activation::Activation;
use crate::config::capacity::CapacityConfig;
use crate::config::pins::Pin;
use crate::config::release_name::{ReleaseName, validate_release_name};
use crate::config::servers::{HostIdentity, ServerConnection, ServerDef};
use crate::config::slots::SlotConfig;
use crate::error::{Error, Result};
use crate::identity::{Identifier, ReleaseId, RolloutGroupName};
use std::collections::{BTreeMap, HashSet};
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

    /// Re-validate the WHOLE graph: every reference resolves, ids are valid
    /// and unique, no impossible combos, and the connection enum is
    /// well-formed. This is the single gate every validated rebuild
    /// operation runs after mutating a clone; the raw -> domain conversion
    /// runs the same rules inline (with raw-layer context for the error
    /// messages).
    fn validate_graph(&self) -> Result<()> {
        // Server ids are validated [`Identifier`]s by construction; the graph
        // rule is uniqueness. The connection enum must be well-formed: a
        // local form carries a `Local` identity (it carries NO root path —
        // the slot's deploy_dir is the sole physical root); an SSH form
        // carries a `KnownHosts`/`Fingerprint` identity (never `Local`) with
        // an absolute `known_hosts`.
        let mut server_ids = HashSet::new();
        for s in &self.servers {
            if !server_ids.insert(s.id.as_str()) {
                return Err(Error::config(format!(
                    "duplicate server id '{}' in top-level servers",
                    s.id
                )));
            }
            match s.connection() {
                ServerConnection::Local { identity } => {
                    if identity != &HostIdentity::Local {
                        return Err(Error::config(format!(
                            "server '{}': a local connection must carry a Local identity",
                            s.id
                        )));
                    }
                }
                ServerConnection::Ssh { identity, .. } => match identity {
                    HostIdentity::Local => {
                        return Err(Error::config(format!(
                            "server '{}': an SSH connection cannot carry a Local identity",
                            s.id
                        )));
                    }
                    HostIdentity::KnownHosts(p) => {
                        if !p.is_absolute() {
                            return Err(Error::config(format!(
                                "server '{}': known_hosts must be an absolute path",
                                s.id
                            )));
                        }
                    }
                    HostIdentity::Fingerprint(_) => {}
                },
            }
        }

        // Variant names are valid identifiers (the map is keyed by them) and
        // the typed activation enum is well-formed (systemd requires units).
        let mut variant_names = HashSet::new();
        for name in self.variants.keys() {
            Identifier::parse(name).map_err(|_| {
                Error::config(format!(
                    "variant name '{name}' must be a non-empty, well-formed identifier"
                ))
            })?;
            if !variant_names.insert(name) {
                return Err(Error::config(format!("duplicate variant name '{name}'")));
            }
            if let Activation::Systemd(sa) = &self.variants[name].activation
                && sa.units.is_empty()
            {
                return Err(Error::config(format!(
                    "variant '{name}': systemd activation requires at least one unit"
                )));
            }
        }
        if variant_names.is_empty() {
            return Err(Error::config(
                "at least one release variant must be declared",
            ));
        }

        // Slots: ids valid + unique across variants, references resolve,
        // groups clean, deploy_dir absolute, locations unique.
        let mut slot_ids = HashSet::new();
        let mut bound_locations: BTreeMap<(&str, &Path), &str> = BTreeMap::new();
        for (vname, variant) in &self.variants {
            for p in &variant.slots {
                Identifier::parse(&p.id).map_err(|_| {
                    Error::config(format!(
                        "variant '{vname}': slot id '{}' must be a non-empty, well-formed identifier",
                        p.id
                    ))
                })?;
                Identifier::parse(&p.server).map_err(|_| {
                    Error::config(format!(
                        "variant '{vname}': slot '{}' server '{}' must be a non-empty, well-formed identifier",
                        p.id, p.server
                    ))
                })?;
                Identifier::parse(&p.target).map_err(|_| {
                    Error::config(format!(
                        "variant '{vname}': slot '{}' target '{}' must be a non-empty, well-formed identifier",
                        p.id, p.target
                    ))
                })?;
                if !slot_ids.insert(p.id.clone()) {
                    return Err(Error::config(format!(
                        "duplicate slot id '{}' (declared by variant '{vname}')",
                        p.id
                    )));
                }
                if !server_ids.contains(p.server.as_str()) {
                    return Err(Error::config(format!(
                        "variant '{vname}': slot '{}' references unknown server '{}'",
                        p.id, p.server
                    )));
                }
                if !self.targets.contains_key(&p.target) {
                    return Err(Error::config(format!(
                        "variant '{vname}': slot '{}' references unknown target '{}'",
                        p.id, p.target
                    )));
                }
                let mut seen_groups = HashSet::new();
                for g in &p.groups {
                    RolloutGroupName::parse(g).map_err(|_| {
                        Error::config(format!(
                            "variant '{vname}': slot '{}' declares an invalid group name {g:?}",
                            p.id
                        ))
                    })?;
                    if !seen_groups.insert(g) {
                        return Err(Error::config(format!(
                            "variant '{vname}': slot '{}' declares duplicate group '{}'",
                            p.id, g
                        )));
                    }
                }
                if !p.deploy_dir().is_absolute() {
                    return Err(Error::config(format!(
                        "variant '{vname}': slot '{}' deploy_dir must be an absolute path on the server",
                        p.id
                    )));
                }
                if let Some(existing) = bound_locations.get(&(p.server.as_str(), p.deploy_dir())) {
                    return Err(Error::config(format!(
                        "slots '{existing}' and '{}' bind the same location (server '{}', deploy_dir '{}'); each server+deploy_dir pair must belong to exactly one slot",
                        p.id,
                        p.server,
                        p.deploy_dir().display()
                    )));
                }
                bound_locations.insert((p.server.as_str(), p.deploy_dir()), &p.id);
            }
        }

        // Targets: names valid, each has at least one member slot, one slot
        // per server per target.
        if self.targets.is_empty() {
            return Err(Error::config("at least one target must be declared"));
        }
        for tname in self.targets.keys() {
            Identifier::parse(tname).map_err(|_| {
                Error::config(format!(
                    "target name '{tname}' must be a non-empty, well-formed identifier"
                ))
            })?;
            let mut used_servers = HashSet::new();
            let mut members = 0;
            for slot in self.variants.values().flat_map(|v| v.slots.iter()) {
                if slot.target != *tname {
                    continue;
                }
                members += 1;
                if !used_servers.insert(slot.server.as_str()) {
                    return Err(Error::config(format!(
                        "target '{tname}' has multiple slots on server '{}'",
                        slot.server
                    )));
                }
            }
            if members == 0 {
                return Err(Error::config(format!("target '{tname}' has no slots")));
            }
        }
        Ok(())
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
        next.validate_graph()?;
        Ok(next)
    }

    /// Remove a server. Fails if any slot references it (the graph would
    /// dangle); the ORIGINAL is untouched.
    pub fn without_server(&self, id: &str) -> Result<ProjectConfig> {
        let mut next = self.clone();
        let Some(pos) = next.servers.iter().position(|s| s.id.as_str() == id) else {
            return Err(Error::not_found(format!("server '{id}'")));
        };
        next.servers.remove(pos);
        next.validate_graph()?;
        Ok(next)
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
        next.validate_graph()?;
        Ok(next)
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
        next.validate_graph()?;
        Ok(next)
    }

    /// Remove a target. Fails if any slot references it (the graph would
    /// dangle); the ORIGINAL is untouched.
    pub fn without_target(&self, name: &str) -> Result<ProjectConfig> {
        let mut next = self.clone();
        if next.targets.remove(name).is_none() {
            return Err(Error::not_found(format!("target '{name}'")));
        }
        next.validate_graph()?;
        Ok(next)
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
        next.validate_graph()?;
        Ok(next)
    }

    /// Add a durable retention pin. Pins carry no graph invariants, but the
    /// whole graph is still re-validated; the ORIGINAL is untouched.
    pub fn with_pin(&self, pin: Pin) -> Result<ProjectConfig> {
        let mut next = self.clone();
        next.pins.push(pin);
        next.validate_graph()?;
        Ok(next)
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
        next.validate_graph()?;
        Ok(next)
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
        next.validate_graph()?;
        Ok(next)
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
        next.validate_graph()?;
        Ok(next)
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
        next.validate_graph()?;
        Ok(next)
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
        next.validate_graph()?;
        Ok(next)
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
        next.validate_graph()?;
        Ok(next)
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
        next.validate_graph()?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests;
