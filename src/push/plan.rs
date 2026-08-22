//! Deployment planning: resolve the desired per-server assignment from a push
//! reference.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::history::{PushRef, resolve_fleet_ref};
use crate::model::{ReleaseId, ServerId, TreeDigest, VariantName};
use crate::records::PlanSource;
use crate::store::local::LocalStore;
use std::collections::{BTreeMap, BTreeSet};

pub struct PlannedAssignment {
    pub server_id: ServerId,
    pub variant: VariantName,
    pub release: ReleaseId,
    pub tree: TreeDigest,
}

/// Resolve the desired assignment for each server of `target_name` given the
/// push reference. Returns the assignments, the release the attempt is bound to,
/// and the plan source.
pub fn plan_assignments(
    config: &Config,
    target_name: &str,
    pref: &PushRef,
    local_release_id: &ReleaseId,
    variant_trees: &BTreeMap<String, TreeDigest>,
    store: &LocalStore,
) -> Result<(Vec<PlannedAssignment>, ReleaseId, PlanSource)> {
    if !config.targets.contains_key(target_name) {
        return Err(Error::not_found(format!("target '{target_name}'")));
    }
    let server_defs = config.target_servers(target_name)?;
    let server_ids: Vec<ServerId> = server_defs
        .iter()
        .map(|s| ServerId::new(s.id.clone()))
        .collect();

    match pref {
        PushRef::Head => {
            let mut out = Vec::new();
            for s in &server_defs {
                let sid = ServerId::new(s.id.clone());
                let variant = VariantName::new(s.variant.clone());
                let tree = variant_trees.get(&s.variant).cloned().ok_or_else(|| {
                    Error::plan(format!("variant '{}' not materialized", s.variant))
                })?;
                out.push(PlannedAssignment {
                    server_id: sid,
                    variant,
                    release: local_release_id.clone(),
                    tree,
                });
            }
            Ok((out, local_release_id.clone(), PlanSource::Head))
        }
        PushRef::Fleet {
            target: ft, index, ..
        } => {
            let entry = resolve_fleet_ref(store, ft, *index)?;
            let recorded: BTreeSet<String> = entry
                .servers
                .keys()
                .map(|s| s.as_str().to_string())
                .collect();
            let current: BTreeSet<String> =
                server_ids.iter().map(|s| s.as_str().to_string()).collect();
            if recorded != current {
                return Err(Error::rollback(
                    "target membership changed; exact fleet rollback requires identical stable server-ID set",
                ));
            }
            let mut out = Vec::new();
            for s in &server_defs {
                let sid = ServerId::new(s.id.clone());
                let a = entry.servers.get(&sid).ok_or_else(|| {
                    Error::rollback(format!("server {sid} missing in fleet snapshot"))
                })?;
                out.push(PlannedAssignment {
                    server_id: sid,
                    variant: a.variant.clone(),
                    release: a.release.clone(),
                    tree: a.tree.clone(),
                });
            }
            let desired = entry
                .servers
                .values()
                .next()
                .map(|a| a.release.clone())
                .unwrap_or_else(|| local_release_id.clone());
            Ok((out, desired, PlanSource::FleetRef(*index)))
        }
        PushRef::Release { release, .. } => {
            let rec = store
                .read_release(release)
                .map_err(|_| Error::rollback(format!("release {release} not available locally")))?;
            let mut out = Vec::new();
            for s in &server_defs {
                let sid = ServerId::new(s.id.clone());
                let variant = VariantName::new(s.variant.clone());
                let tree = rec.variants.get(&s.variant).cloned().ok_or_else(|| {
                    Error::rollback(format!("release {release} lacks variant '{}'", s.variant))
                })?;
                out.push(PlannedAssignment {
                    server_id: sid,
                    variant,
                    release: release.clone(),
                    tree: TreeDigest::new(tree),
                });
            }
            Ok((
                out,
                release.clone(),
                PlanSource::ReleaseRef(release.clone()),
            ))
        }
    }
}
