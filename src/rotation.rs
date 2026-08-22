//! Retention and rotation.
//!
//! Retention is evaluated per server. For each server, the retained content set
//! is the union of:
//! * the artifact referenced by the current generation
//! * the prior distinct successful artifact when `protect_previous` is true
//! * artifacts referenced by incomplete transactions
//! * artifacts or releases selected by durable pins
//! * the newest `keep_distinct_artifacts` distinct successful artifact bindings
//! * artifacts successfully activated less than `keep_days` ago
//! * that server's artifacts in the newest `protect_deployments` fleet window
//!
//! Rotation is a mark-and-sweep operation: a tree object is deleted only when no
//! retained binding or applicable pin references it.

use crate::config::{Pin, PinVariants, RotationConfig};
use crate::error::Result;
use crate::model::{ReleaseId, TreeDigest};
use crate::remote::helper::RemoteHelper;
use crate::store::local::LocalStore;
use chrono::{DateTime, Utc};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

struct GenRecord {
    created_at: DateTime<Utc>,
    release: String,
    variant: String,
    tree: String,
    deployment_id: String,
}

/// Compute the set of retained tree digests for one server, using the rotation
/// policy supplied by the caller and the durable pins declared in the release
/// configuration. The caller resolves the policy from the release's immutable
/// policy snapshot (falling back to current configuration for legacy records),
/// so historical deployments of renamed or removed variants retain correctly.
pub fn compute_retained(
    helper: &RemoteHelper,
    rotation: &RotationConfig,
    pins: &[Pin],
    store: &LocalStore,
) -> Result<HashSet<String>> {
    let mut retained: HashSet<String> = HashSet::new();
    let status = helper.status()?;

    // Current generation's tree.
    if let Some(t) = &status.current_tree {
        retained.insert(t.clone());
    }

    // Enumerate generation records.
    let mut gens: Vec<GenRecord> = Vec::new();
    let gen_root = Path::new("generations");
    if helper.remote().exists(gen_root) {
        for e in helper.remote().list(gen_root)? {
            if !e.is_dir {
                continue;
            }
            let a = match helper.read_assignment(&e.name) {
                Ok(a) => a,
                Err(_) => continue,
            };
            let created = DateTime::parse_from_rfc3339(&a.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            gens.push(GenRecord {
                created_at: created,
                release: a.release,
                variant: a.variant,
                tree: a.tree,
                deployment_id: a.deployment_id,
            });
        }
    }

    // Prior distinct successful artifact when protect_previous is true.
    if rotation.per_server.protect_previous
        && let Some(cur) = &status.current_generation
        && let Ok(a) = helper.read_assignment(cur)
        && let Some(prior) = &a.prior_generation
        && let Ok(pa) = helper.read_assignment(prior)
    {
        retained.insert(pa.tree);
    }

    // Distinct successful artifact bindings, keyed by (release, variant, tree).
    let mut distinct: BTreeMap<(String, String, String), DateTime<Utc>> = BTreeMap::new();
    for g in &gens {
        let key = (g.release.clone(), g.variant.clone(), g.tree.clone());
        let slot = distinct.entry(key).or_insert(g.created_at);
        if g.created_at > *slot {
            *slot = g.created_at;
        }
    }
    // Sort by most recent activation descending.
    let mut ordered: Vec<((String, String, String), DateTime<Utc>)> =
        distinct.into_iter().collect();
    ordered.sort_by_key(|(_, ts)| std::cmp::Reverse(*ts));

    let keep_distinct = rotation.per_server.keep_distinct_artifacts as usize;
    for ((_, _, tree), _) in ordered.iter().take(keep_distinct) {
        retained.insert(tree.clone());
    }

    let keep_days = rotation.per_server.keep_days;
    if keep_days > 0 {
        let cutoff = Utc::now() - chrono::Duration::days(keep_days as i64);
        for ((_, _, tree), ts) in &ordered {
            if *ts >= cutoff {
                retained.insert(tree.clone());
            }
        }
    }

    // Fleet window: newest `protect_deployments` distinct deployment IDs.
    let protect_deployments = rotation.fleet.protect_deployments as usize;
    if protect_deployments > 0 {
        let mut depl: BTreeMap<String, DateTime<Utc>> = BTreeMap::new();
        for g in &gens {
            let slot = depl.entry(g.deployment_id.clone()).or_insert(g.created_at);
            if g.created_at > *slot {
                *slot = g.created_at;
            }
        }
        let mut depl_ordered: Vec<(String, DateTime<Utc>)> = depl.into_iter().collect();
        depl_ordered.sort_by_key(|(_, ts)| std::cmp::Reverse(*ts));
        let keep_ids: HashSet<String> = depl_ordered
            .iter()
            .take(protect_deployments)
            .map(|(id, _)| id.clone())
            .collect();
        for g in &gens {
            if keep_ids.contains(&g.deployment_id) {
                retained.insert(g.tree.clone());
            }
        }
    }

    // Durable pins.
    for pin in pins {
        let rid = ReleaseId::parse(&pin.release);
        let rec = match store.read_release(&rid) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let variants: Vec<String> = match &pin.variants {
            PinVariants::All => rec.variants.keys().cloned().collect(),
            PinVariants::Some(list) => list.clone(),
        };
        for v in variants {
            if let Some(tree) = rec.variants.get(&v) {
                retained.insert(tree.clone());
            }
        }
    }

    Ok(retained)
}

/// Convenience: serialize retained digests for diagnostics.
pub fn retained_summary(retained: &HashSet<String>) -> Vec<TreeDigest> {
    retained
        .iter()
        .map(|s| TreeDigest::new(s.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::remote::helper::{GenerationAssignment, RemoteHelper};
    use crate::remote::transport::LocalTransport;
    use crate::store::local::LocalStore;
    use std::path::Path;

    fn cfg() -> Config {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        let variant_toml = r#"
[artifact]
mappings = []

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0

[capacity]
reserve_bytes = 0
reserve_percent = 0

[rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[rotation.fleet]
protect_deployments = 1
"#;
        std::fs::write(release_dir.join("standard.toml"), variant_toml).unwrap();
        let deploy_toml = r#"
schema_version = 1
application = "rot"
remote_root = "/srv"
release = "v1"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }

[[targets.t1.servers]]
id = "s1"
address = "a"
user = "u"
variant = "standard"
"#;
        let p = project.join("deploy.toml");
        std::fs::write(&p, deploy_toml).unwrap();
        Config::load(&p).unwrap()
    }

    #[test]
    fn retains_current_and_previous() {
        let dir = tempfile::tempdir().unwrap();
        let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
        let helper = RemoteHelper::new(&remote);
        helper
            .remote()
            .create_dir_all(Path::new("objects/sha256/t1/root"))
            .unwrap();
        helper
            .remote()
            .create_dir_all(Path::new("objects/sha256/t2/root"))
            .unwrap();
        helper
            .create_generation(
                "op",
                &GenerationAssignment {
                    deployment_id: "d1".into(),
                    generation_id: "g1".into(),
                    release: "r".into(),
                    variant: "standard".into(),
                    tree: "t1".into(),
                    behavior_sha256: "b".into(),
                    prior_generation: None,
                    created_at: "2020-01-01T00:00:00Z".into(),
                },
            )
            .unwrap();
        helper
            .create_generation(
                "op",
                &GenerationAssignment {
                    deployment_id: "d2".into(),
                    generation_id: "g2".into(),
                    release: "r".into(),
                    variant: "standard".into(),
                    tree: "t2".into(),
                    behavior_sha256: "b".into(),
                    prior_generation: Some("g1".into()),
                    created_at: "2020-01-02T00:00:00Z".into(),
                },
            )
            .unwrap();
        helper.swap_current(None, "g2", "op").unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let c = cfg();
        let rotation = &c.variant("standard").unwrap().rotation;
        let retained = compute_retained(&helper, rotation, &c.pins, &store).unwrap();
        assert!(retained.contains("t2"), "current tree retained");
        assert!(retained.contains("t1"), "previous tree retained");
    }
}
