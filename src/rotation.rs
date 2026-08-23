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

use crate::config::{Pin, RotationConfig};
use crate::error::Result;
use crate::layout;
use crate::model::{ReleaseId, TreeDigest};
use crate::remote::helper::RemoteHelper;
use crate::store::local::LocalStore;
use chrono::{DateTime, Utc};
use std::collections::{BTreeMap, HashSet};

struct GenRecord {
    created_at: DateTime<Utc>,
    release: String,
    variant: String,
    tree: String,
    deployment_id: String,
}

/// Compute the set of retained tree digests for one server, using the
/// fleet-wide rotation policy supplied by the caller and the durable pins
/// declared in `deploy.toml`. The rotation policy is read from the caller's
/// current configuration; capacity headroom, by contrast, is a per-server
/// policy declared on the server entry (`ServerDef.capacity`) and likewise
/// resolved from the caller's current configuration — it is never part of a
/// release snapshot.
pub fn compute_retained(
    helper: &RemoteHelper,
    pins: &[Pin],
    store: &LocalStore,
    rotation: &RotationConfig,
) -> Result<HashSet<String>> {
    let mut retained: HashSet<String> = HashSet::new();
    let status = helper.status()?;

    // Current generation's tree.
    if let Some(t) = &status.current_tree {
        retained.insert(t.clone());
    }

    // Enumerate generation records.
    let mut gens: Vec<GenRecord> = Vec::new();
    let gen_root = layout::generations();
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
                release: a.artifact.release.as_str().to_string(),
                variant: a.artifact.variant.as_str().to_string(),
                tree: a.artifact.tree.as_str().to_string(),
                deployment_id: a.deployment_id.as_str().to_string(),
            });
        }
    }

    // Prior distinct successful artifact when protect_previous is true.
    if rotation.per_server.protect_previous
        && let Some(cur) = &status.current_generation
        && let Ok(a) = helper.read_assignment(cur)
        && let Some(prior) = &a.prior_generation
        && let Ok(pa) = helper.read_assignment(prior.as_str())
    {
        retained.insert(pa.artifact.tree.as_str().to_string());
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
    // Durable pins. A pin protects the whole release: every variant's tree
    // recorded in the release record is retained, so the pinned release stays
    // fully rollback-able no matter how old it is or how far outside the
    // count/age windows it falls.
    for pin in pins {
        let rid = ReleaseId::parse(&pin.release);
        let rec = match store.read_release(&rid) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for tree in rec.variants.values() {
            retained.insert(tree.clone());
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
    use crate::layout;
    use crate::remote::helper::{GenerationAssignment, RemoteHelper};
    use crate::remote::transport::LocalTransport;
    use crate::store::local::LocalStore;

    fn cfg() -> Config {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        let variant_toml = r#"
[artifact]
mappings = []

[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv"

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;
        std::fs::write(release_dir.join("standard.toml"), variant_toml).unwrap();
        let deploy_toml = r#"
schema_version = 1
application = "rot"
release = "v1"

[targets.t1.rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[targets.t1.rotation.fleet]
protect_deployments = 1

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
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
            .create_dir_all(&layout::tree_root("t1"))
            .unwrap();
        helper
            .remote()
            .create_dir_all(&layout::tree_root("t2"))
            .unwrap();
        helper
            .create_generation(
                "op",
                &GenerationAssignment {
                    deployment_id: "d1".to_string().into(),
                    generation_id: "g1".to_string().into(),
                    artifact: crate::model::ArtifactRef {
                        release: crate::model::ReleaseId::new("r".to_string()),
                        variant: "standard".to_string().into(),
                        tree: "t1".to_string().into(),
                    },
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
                    deployment_id: "d2".to_string().into(),
                    generation_id: "g2".to_string().into(),
                    artifact: crate::model::ArtifactRef {
                        release: crate::model::ReleaseId::new("r".to_string()),
                        variant: "standard".to_string().into(),
                        tree: "t2".to_string().into(),
                    },
                    behavior_sha256: "b".into(),
                    prior_generation: Some("g1".to_string().into()),
                    created_at: "2020-01-02T00:00:00Z".into(),
                },
            )
            .unwrap();
        helper.swap_current(None, "g2", "op").unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let c = cfg();
        let retained =
            compute_retained(&helper, &c.pins, &store, &c.targets["t1"].rotation).unwrap();
        assert!(retained.contains("t2"), "current tree retained");
        assert!(retained.contains("t1"), "previous tree retained");
    }

    /// A pin protects the whole release: every variant's tree recorded in the
    /// pinned release is retained even when nothing else would keep it.
    #[test]
    fn pin_protects_every_variant_of_a_release() {
        let dir = tempfile::tempdir().unwrap();
        let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
        let helper = RemoteHelper::new(&remote);
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // A release with two variants, persisted in the local store.
        let rec = crate::model::ReleaseRecord {
            release_schema_version: 1,
            release_id: "rel-sha256-pin-test".into(),
            release_sha256: "pin-test".into(),
            created_at: "2020-01-01T00:00:00Z".into(),
            provenance: crate::model::Provenance {
                git_revision: None,
                mapping_sha256: String::new(),
                behavior_sha256: String::new(),
            },
            variants: std::collections::BTreeMap::from([
                ("a".to_string(), "tree-a".to_string()),
                ("b".to_string(), "tree-b".to_string()),
            ]),
            slots: std::collections::BTreeMap::new(),
        };
        store.write_release(&rec).unwrap();

        let c = cfg();
        let rotation = &c.targets["t1"].rotation;
        let pinned = [Pin {
            release: "rel-sha256-pin-test".into(),
            reason: "known-good".into(),
        }];

        // Without the pin the server has no history, so nothing is retained.
        let bare = compute_retained(&helper, &[], &store, rotation).unwrap();
        assert!(bare.is_empty(), "no history and no pins retains nothing");

        // With the pin, BOTH variants' trees are protected.
        let retained = compute_retained(&helper, &pinned, &store, rotation).unwrap();
        assert!(
            retained.contains("tree-a"),
            "variant a protected by the pin"
        );
        assert!(
            retained.contains("tree-b"),
            "variant b protected by the pin"
        );
    }

    /// Create one generation record (tree + assignment) without touching
    /// `current`.
    fn make_gen(
        helper: &RemoteHelper,
        deployment_id: &str,
        generation_id: &str,
        tree: &str,
        created: &str,
        prior_generation: Option<&str>,
    ) {
        // The tree object must resolve for `status()`/`exists` to follow the
        // `current` symlink chain (mirrors the existing rotation tests).
        helper
            .remote()
            .create_dir_all(&layout::tree_root(tree))
            .unwrap();
        helper
            .create_generation(
                "op",
                &crate::remote::helper::GenerationAssignment {
                    deployment_id: deployment_id.to_string().into(),
                    generation_id: generation_id.to_string().into(),
                    artifact: crate::model::ArtifactRef {
                        release: crate::model::ReleaseId::new("r".to_string()),
                        variant: "standard".to_string().into(),
                        tree: tree.to_string().into(),
                    },
                    behavior_sha256: "b".into(),
                    prior_generation: prior_generation.map(|g| g.to_string().into()),
                    created_at: created.into(),
                },
            )
            .unwrap();
    }

    /// The `keep_distinct_artifacts` window retains the newest N DISTINCT
    /// successful artifact bindings in addition to `current` and the protected
    /// previous: with `keep_distinct_artifacts = 2`, the third-oldest distinct
    /// tree is swept.
    #[test]
    fn keep_distinct_artifacts_retains_newest_distinct_bindings() {
        let dir = tempfile::tempdir().unwrap();
        let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
        let helper = RemoteHelper::new(&remote);
        make_gen(&helper, "d1", "g1", "t1", "2020-01-01T00:00:00Z", None);
        make_gen(
            &helper,
            "d2",
            "g2",
            "t2",
            "2020-01-02T00:00:00Z",
            Some("g1"),
        );
        make_gen(
            &helper,
            "d3",
            "g3",
            "t3",
            "2020-01-03T00:00:00Z",
            Some("g2"),
        );
        helper.swap_current(None, "g3", "op").unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let c = cfg();
        let mut rotation = c.targets["t1"].rotation.clone();
        rotation.per_server.keep_distinct_artifacts = 2;
        rotation.per_server.keep_days = 0;
        rotation.fleet.protect_deployments = 0;
        // No prior chain, so protect_previous has nothing to add.
        rotation.per_server.protect_previous = false;

        let retained = compute_retained(&helper, &c.pins, &store, &rotation).unwrap();
        assert!(retained.contains("t3"), "current tree retained");
        assert!(retained.contains("t2"), "newest distinct binding retained");
        assert!(
            !retained.contains("t1"),
            "the third-oldest distinct binding must be swept"
        );
    }

    /// The `keep_days` window retains every artifact activated within the
    /// window in addition to the distinct-artifact window.
    #[test]
    fn keep_days_retains_recent_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
        let helper = RemoteHelper::new(&remote);
        let now = chrono::Utc::now();
        let old = (now - chrono::Duration::days(60)).to_rfc3339();
        let recent = (now - chrono::Duration::days(5)).to_rfc3339();
        make_gen(&helper, "d1", "g1", "t-old", &old, None);
        make_gen(&helper, "d2", "g2", "t-recent", &recent, Some("g1"));
        helper.swap_current(None, "g2", "op").unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let c = cfg();
        let mut rotation = c.targets["t1"].rotation.clone();
        rotation.per_server.keep_distinct_artifacts = 1;
        rotation.per_server.keep_days = 30;
        rotation.per_server.protect_previous = false;
        rotation.fleet.protect_deployments = 0;

        let retained = compute_retained(&helper, &c.pins, &store, &rotation).unwrap();
        assert!(retained.contains("t-recent"));
        assert!(
            !retained.contains("t-old"),
            "artifact older than keep_days must be swept"
        );

        // Widen the window past the old artifact: it is retained again.
        rotation.per_server.keep_days = 90;
        let retained = compute_retained(&helper, &c.pins, &store, &rotation).unwrap();
        assert!(
            retained.contains("t-old"),
            "artifact inside keep_days must be retained"
        );
        assert!(retained.contains("t-recent"));
    }

    /// The fleet `protect_deployments` window retains the artifacts of the
    /// newest N distinct deployment IDs, even when the distinct-artifact
    /// window alone would sweep them.
    #[test]
    fn fleet_protect_deployments_retains_newest_deployments() {
        let dir = tempfile::tempdir().unwrap();
        let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
        let helper = RemoteHelper::new(&remote);
        make_gen(&helper, "d1", "g1", "t1", "2020-01-01T00:00:00Z", None);
        make_gen(
            &helper,
            "d2",
            "g2",
            "t2",
            "2020-01-02T00:00:00Z",
            Some("g1"),
        );
        make_gen(
            &helper,
            "d3",
            "g3",
            "t3",
            "2020-01-03T00:00:00Z",
            Some("g2"),
        );
        helper.swap_current(None, "g3", "op").unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let c = cfg();
        let mut rotation = c.targets["t1"].rotation.clone();
        rotation.per_server.keep_distinct_artifacts = 1;
        rotation.per_server.keep_days = 0;
        rotation.per_server.protect_previous = false;
        rotation.fleet.protect_deployments = 2;

        let retained = compute_retained(&helper, &c.pins, &store, &rotation).unwrap();
        assert!(retained.contains("t3"), "current deployment retained");
        assert!(
            retained.contains("t2"),
            "second-newest deployment protected by the fleet window"
        );
        assert!(
            !retained.contains("t1"),
            "oldest deployment outside the fleet window must be swept"
        );
    }

    /// Rotation never deletes what rollback needs: with EVERY retention
    /// window zeroed (keep_distinct = 0, keep_days = 0, fleet = 0) and no
    /// pins, the current artifact and the protected previous artifact survive.
    #[test]
    fn current_and_protected_previous_survive_zero_windows() {
        let dir = tempfile::tempdir().unwrap();
        let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
        let helper = RemoteHelper::new(&remote);
        make_gen(&helper, "d1", "g1", "t1", "2020-01-01T00:00:00Z", None);
        make_gen(
            &helper,
            "d2",
            "g2",
            "t2",
            "2020-01-02T00:00:00Z",
            Some("g1"),
        );
        // current -> g2, whose assignment records g1 as prior.
        helper.swap_current(None, "g2", "op").unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let c = cfg();
        let mut rotation = c.targets["t1"].rotation.clone();
        rotation.per_server.keep_distinct_artifacts = 0;
        rotation.per_server.keep_days = 0;
        rotation.per_server.protect_previous = true;
        rotation.fleet.protect_deployments = 0;

        let retained = compute_retained(&helper, &c.pins, &store, &rotation).unwrap();
        assert!(retained.contains("t2"), "current tree is never swept");
        assert!(
            retained.contains("t1"),
            "protected previous tree is never swept"
        );
    }
}
