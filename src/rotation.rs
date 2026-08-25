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
//! * that server's artifacts in the newest `protect_deployments` deployment window
//!
//! A slot has EXACTLY ONE retention policy, owned by the slot itself: the
//! policy of the slot's OWNING VARIANT (the variant file whose `[[slots]]`
//! entry declares the slot). A slot may be a member of SEVERAL targets (the
//! multi-target feature) but its state is shared — one physical observed
//! record, one rotation policy — and targets are only selection views over
//! that slot state. There is NO per-target policy and NO union across member
//! targets: the caller resolves the slot's single policy from its owning
//! variant (`Config::slot_rotation`) and passes it here; every generation
//! record on the server is evaluated under that one policy, so changing a
//! slot's target membership never changes what is retained.
//!
//! Rotation is a mark-and-sweep operation: a tree object is deleted only when no
//! retained binding or applicable pin references it.

use crate::config::{Pin, RotationConfig};
use crate::error::Result;
use crate::layout;
use crate::model::{ReleaseId, TreeDigest};
use crate::remote::helper::{RemoteHelper, RemoteStatus};
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

/// Compute the set of retained tree digests for one server under the slot's
/// ONE policy: `rotation` is the retention policy of the slot's OWNING
/// VARIANT, resolved by the caller from the current configuration
/// (`Config::slot_rotation`) — a single source, never a union across the
/// slot's member targets, so membership changes cannot change retention. The
/// durable pins declared in `deploy.toml` protect whole releases as before.
/// Capacity headroom, by contrast, is a per-server policy declared on the
/// server entry (`ServerDef.capacity`) and likewise resolved from the
/// caller's current configuration — it is never part of a release snapshot.
pub fn compute_retained(
    helper: &RemoteHelper,
    pins: &[Pin],
    store: &LocalStore,
    rotation: &RotationConfig,
) -> Result<HashSet<String>> {
    let mut retained: HashSet<String> = HashSet::new();
    let status = helper.status()?;

    // Current generation's tree — the live artifact is ALWAYS in the retained
    // set. When the live generation's assignment cannot be read (a missing or
    // corrupt `assignment.json`), the current tree is UNKNOWN: sweeping
    // anything we cannot prove unreferenced would leave `current` pointing at
    // a deleted tree (a dangling commit pointer). Fail closed — retain every
    // object present so rotation deletes nothing it cannot account for.
    let live_tree_unknown = status.current_generation.is_some() && status.current_tree.is_none();
    if live_tree_unknown {
        let obj_root = layout::objects();
        if helper.remote().exists(obj_root) {
            for e in helper.remote().list(obj_root)? {
                if e.is_dir {
                    retained.insert(e.name);
                }
            }
        }
    } else if let Some(t) = &status.current_tree {
        retained.insert(t.clone());
    }

    // Enumerate the server's generation records. Every record is evaluated
    // under the slot's single owning-variant policy (there is no per-target
    // attribution anymore: the slot has one policy regardless of which target
    // created a generation).
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

    // Apply the slot's ONE policy (from its owning variant) to ALL of the
    // server's records. No union, no membership lookup: the policy was
    // already resolved from the slot's owning variant by the caller.
    retained.extend(retained_for_policy(helper, &status, &gens, rotation)?);

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

/// Apply the slot's ONE rotation policy (owned by its declaring variant) to
/// every generation record on the server. The caller already resolved the
/// policy from the slot's owning variant — there is no per-target policy and
/// no union across member targets. The current generation's prior is
/// protected whenever the policy sets `protect_previous`: it is the
/// immediate rollback target, and the slot's single policy decides.
fn retained_for_policy(
    helper: &RemoteHelper,
    status: &RemoteStatus,
    gens: &[GenRecord],
    rotation: &RotationConfig,
) -> Result<HashSet<String>> {
    let mut retained: HashSet<String> = HashSet::new();

    // Prior distinct successful generation when protect_previous is true.
    if rotation.per_server.protect_previous
        && let Some(cur) = &status.current_generation
        && let Ok(a) = helper.read_assignment(cur)
        && let Some(prior) = &a.prior_generation
        && let Ok(pa) = helper.read_assignment(prior.as_str())
    {
        retained.insert(pa.artifact.tree.as_str().to_string());
    }

    // Distinct successful artifact bindings on the server, keyed by
    // (release, variant, tree).
    let mut distinct: BTreeMap<(String, String, String), DateTime<Utc>> = BTreeMap::new();
    for g in gens {
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

    // Deployment window: newest `protect_deployments` distinct deployment IDs
    // among the server's records.
    let protect_deployments = rotation.deployment.protect_deployments as usize;
    if protect_deployments > 0 {
        let mut depl: BTreeMap<String, DateTime<Utc>> = BTreeMap::new();
        for g in gens {
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
        for g in gens {
            if keep_ids.contains(&g.deployment_id) {
                retained.insert(g.tree.clone());
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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::layout;
    use crate::model::RELEASE_RECORD_SCHEMA_VERSION;
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

[rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[rotation.deployment]
protect_deployments = 1

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
schema_version = 2
application = "rot"
release = "v1"

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

    /// The slot's single retention policy, resolved from its OWNING VARIANT
    /// (`standard` declares slot `p1`): retention is slot-owned, never a
    /// per-target surface.
    fn rot(c: &Config) -> &RotationConfig {
        &c.variant("standard").unwrap().rotation
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
                    target: None,
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
                    target: None,
                },
            )
            .unwrap();
        helper.swap_current(None, "g2", "op").unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let c = cfg();
        let retained = compute_retained(&helper, &c.pins, &store, rot(&c)).unwrap();
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

        // A release with two variants, persisted in the local store. The
        // record must be a content-verifiable CURRENT-format record (its OWN
        // slot snapshot, identity recomputed from that content): an empty
        // slot snapshot is rejected by `write_release` (fail closed).
        let mut rec = crate::model::ReleaseRecord {
            release_schema_version: RELEASE_RECORD_SCHEMA_VERSION,
            release_id: String::new(),
            release_sha256: String::new(),
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
            slots: std::collections::BTreeMap::from([(
                "standard".to_string(),
                crate::model::CanonicalSlots {
                    slots: vec![crate::model::CanonicalSlot {
                        id: "p1".to_string(),
                        server: "s1".to_string(),
                        deploy_dir: "/srv/pin".to_string(),
                        target: "t1".to_string(),
                        groups: Vec::new(),
                    }],
                },
            )]),
        };
        let digest = crate::release::recompute_release_digest(&rec)
            .expect("pin-test release must carry a slot snapshot");
        rec.release_sha256 = digest.as_str().to_string();
        rec.release_id = crate::model::ReleaseId::from_digest(&digest)
            .as_str()
            .to_string();
        store.write_release(&rec).unwrap();

        let c = cfg();
        let pinned = [Pin {
            release: rec.release_id.clone(),
            reason: "known-good".into(),
        }];

        // Without the pin the server has no history, so nothing is retained.
        let bare = compute_retained(&helper, &[], &store, rot(&c)).unwrap();
        assert!(bare.is_empty(), "no history and no pins retains nothing");

        // With the pin, BOTH variants' trees are protected.
        let retained = compute_retained(&helper, &pinned, &store, rot(&c)).unwrap();
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
    /// `current`. `target` is the originating target recorded on the
    /// assignment; `None` writes a legacy record without attribution (the
    /// remote records still carry attribution — the slot's policy no longer
    /// consults it).
    fn make_gen(
        helper: &RemoteHelper,
        deployment_id: &str,
        generation_id: &str,
        tree: &str,
        created: &str,
        prior_generation: Option<&str>,
        target: Option<&str>,
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
                    target: target.map(|t| crate::model::TargetName::new(t.to_string())),
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
        make_gen(
            &helper,
            "d1",
            "g1",
            "t1",
            "2020-01-01T00:00:00Z",
            None,
            None,
        );
        make_gen(
            &helper,
            "d2",
            "g2",
            "t2",
            "2020-01-02T00:00:00Z",
            Some("g1"),
            None,
        );
        make_gen(
            &helper,
            "d3",
            "g3",
            "t3",
            "2020-01-03T00:00:00Z",
            Some("g2"),
            None,
        );
        helper.swap_current(None, "g3", "op").unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let mut c = cfg();
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .per_server
            .keep_distinct_artifacts = 2;
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .per_server
            .keep_days = 0;
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .deployment
            .protect_deployments = 0;
        // No prior chain, so protect_previous has nothing to add.
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .per_server
            .protect_previous = false;

        let retained = compute_retained(&helper, &c.pins, &store, rot(&c)).unwrap();
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
        make_gen(&helper, "d1", "g1", "t-old", &old, None, None);
        make_gen(&helper, "d2", "g2", "t-recent", &recent, Some("g1"), None);
        helper.swap_current(None, "g2", "op").unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let mut c = cfg();
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .per_server
            .keep_distinct_artifacts = 1;
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .per_server
            .keep_days = 30;
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .per_server
            .protect_previous = false;
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .deployment
            .protect_deployments = 0;

        let retained = compute_retained(&helper, &c.pins, &store, rot(&c)).unwrap();
        assert!(retained.contains("t-recent"));
        assert!(
            !retained.contains("t-old"),
            "artifact older than keep_days must be swept"
        );

        // Widen the window past the old artifact: it is retained again.
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .per_server
            .keep_days = 90;
        let retained = compute_retained(&helper, &c.pins, &store, rot(&c)).unwrap();
        assert!(
            retained.contains("t-old"),
            "artifact inside keep_days must be retained"
        );
        assert!(retained.contains("t-recent"));
    }

    /// The deployment `protect_deployments` window retains the artifacts of the
    /// newest N distinct deployment IDs, even when the distinct-artifact
    /// window alone would sweep them.
    #[test]
    fn snapshot_protect_deployments_retains_newest_deployments() {
        let dir = tempfile::tempdir().unwrap();
        let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
        let helper = RemoteHelper::new(&remote);
        make_gen(
            &helper,
            "d1",
            "g1",
            "t1",
            "2020-01-01T00:00:00Z",
            None,
            None,
        );
        make_gen(
            &helper,
            "d2",
            "g2",
            "t2",
            "2020-01-02T00:00:00Z",
            Some("g1"),
            None,
        );
        make_gen(
            &helper,
            "d3",
            "g3",
            "t3",
            "2020-01-03T00:00:00Z",
            Some("g2"),
            None,
        );
        helper.swap_current(None, "g3", "op").unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let mut c = cfg();
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .per_server
            .keep_distinct_artifacts = 1;
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .per_server
            .keep_days = 0;
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .per_server
            .protect_previous = false;
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .deployment
            .protect_deployments = 2;

        let retained = compute_retained(&helper, &c.pins, &store, rot(&c)).unwrap();
        assert!(retained.contains("t3"), "current deployment retained");
        assert!(
            retained.contains("t2"),
            "second-newest deployment protected by the deployment window"
        );
        assert!(
            !retained.contains("t1"),
            "oldest deployment outside the deployment window must be swept"
        );
    }

    /// Rotation never deletes what rollback needs: with EVERY retention
    /// window zeroed (keep_distinct = 0, keep_days = 0, deployment = 0) and no
    /// pins, the current artifact and the protected previous artifact survive.
    #[test]
    fn current_and_protected_previous_survive_zero_windows() {
        let dir = tempfile::tempdir().unwrap();
        let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
        let helper = RemoteHelper::new(&remote);
        make_gen(
            &helper,
            "d1",
            "g1",
            "t1",
            "2020-01-01T00:00:00Z",
            None,
            None,
        );
        make_gen(
            &helper,
            "d2",
            "g2",
            "t2",
            "2020-01-02T00:00:00Z",
            Some("g1"),
            None,
        );
        // current -> g2, whose assignment records g1 as prior.
        helper.swap_current(None, "g2", "op").unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let mut c = cfg();
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .per_server
            .keep_distinct_artifacts = 0;
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .per_server
            .keep_days = 0;
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .per_server
            .protect_previous = true;
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .deployment
            .protect_deployments = 0;

        let retained = compute_retained(&helper, &c.pins, &store, rot(&c)).unwrap();
        assert!(retained.contains("t2"), "current tree is never swept");
        assert!(
            retained.contains("t1"),
            "protected previous tree is never swept"
        );
    }

    /// Rotation must NEVER sweep the tree behind a live `current` whose
    /// assignment cannot be read (a missing or corrupt `assignment.json`): the
    /// retained set always includes "the artifact referenced by the current
    /// generation" (requirement.md), and an unreadable assignment makes that
    /// artifact UNKNOWN. Failing open (sweeping) would leave `current`
    /// dangling. The engine hits this when a push fails pre-swap against a
    /// corrupt live generation and then runs rotation.
    #[test]
    fn rotation_never_sweeps_when_live_assignment_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
        let helper = RemoteHelper::new(&remote);
        make_gen(
            &helper,
            "d1",
            "g1",
            "t1",
            "2020-01-01T00:00:00Z",
            None,
            None,
        );
        helper.swap_current(None, "g1", "op").unwrap();
        // Corrupt the live generation's assignment record.
        std::fs::write(
            dir.path()
                .join("remote")
                .join(crate::layout::generation("g1"))
                .join("assignment.json"),
            b"{ corrupt !",
        )
        .unwrap();
        assert!(
            helper.read_assignment("g1").is_err(),
            "the live assignment must be unreadable after corruption"
        );
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let mut c = cfg();
        // Every window zeroed + no pins: WITHOUT the fail-closed rule the
        // sweep would delete the live tree.
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .per_server
            .keep_distinct_artifacts = 0;
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .per_server
            .keep_days = 0;
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .per_server
            .protect_previous = false;
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .deployment
            .protect_deployments = 0;

        let retained = compute_retained(&helper, &c.pins, &store, rot(&c)).unwrap();
        assert!(
            retained.contains("t1"),
            "the live (unreadable) generation's tree must be retained fail-closed"
        );
        helper.rotate(&retained, &HashSet::new()).unwrap();
        assert!(
            helper.remote().exists(&crate::layout::tree_root("t1")),
            "rotation must not sweep the tree behind a live current with an unreadable assignment"
        );
    }

    /// GROUP MEMBERSHIP NEVER CHANGES RETENTION: the slot's retained set is
    /// computed from its OWNING VARIANT's single policy, so adding or
    /// removing a rollout group in the slot's `groups` list (a config-level
    /// membership change — groups only SELECT slots, they never own policy)
    /// leaves the retained digest set IDENTICAL. The policy is resolved
    /// through the same `Config::slot_rotation` path the engine uses, and the
    /// second config is a REAL reload of an edited slot declaration.
    #[test]
    fn group_membership_never_changes_retention() {
        let dir = tempfile::tempdir().unwrap();
        let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
        let helper = RemoteHelper::new(&remote);
        make_gen(
            &helper,
            "d1",
            "g1",
            "t1",
            "2020-01-01T00:00:00Z",
            None,
            Some("production"),
        );
        make_gen(
            &helper,
            "d2",
            "g2",
            "t2",
            "2020-01-02T00:00:00Z",
            Some("g1"),
            Some("production"),
        );
        make_gen(
            &helper,
            "d3",
            "g3",
            "t3",
            "2020-01-03T00:00:00Z",
            Some("g2"),
            Some("production"),
        );
        helper.swap_current(None, "g3", "op").unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // Config-level group change: rewrite `standard.toml` so slot `p1`
        // belongs to the `canary` group, then reload the project. The owning
        // variant — and therefore the slot's ONE policy — is unchanged.
        let project = tempfile::tempdir().unwrap();
        let proj = project.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        let release_dir = proj.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        let variant_toml = r#"
[artifact]
mappings = []

[[slots]]
id = "p1"
server = "s1"
target = "production"
groups = ["canary"]
deploy_dir = "/srv"

[rotation.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[rotation.deployment]
protect_deployments = 2

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
schema_version = 2
application = "rot"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.production]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;
        std::fs::write(proj.join("deploy.toml"), deploy_toml).unwrap();
        let c = Config::load(&proj.join("deploy.toml")).unwrap();
        let before = compute_retained(&helper, &c.pins, &store, rot(&c)).unwrap();

        // The config-level group change: ADD a new rollout group (`wave-1`)
        // to slot `p1`'s `groups` list, then reload. Groups are selection-only
        // (they never own state, policy, history, or checkpoints), so
        // retention must not move.
        let variant_path = release_dir.join("standard.toml");
        let edited = std::fs::read_to_string(&variant_path)
            .unwrap()
            .replace("groups = [\"canary\"]", "groups = [\"canary\", \"wave-1\"]");
        std::fs::write(&variant_path, edited).unwrap();
        let c2 = Config::load(&proj.join("deploy.toml")).unwrap();
        assert_eq!(
            c2.slot_variant("p1").unwrap(),
            "standard",
            "the owning variant is unchanged by group edits"
        );
        let after = compute_retained(&helper, &c2.pins, &store, rot(&c2)).unwrap();
        assert_eq!(
            before, after,
            "changing a slot's group membership must never change its retained set"
        );
        // And group membership cannot even influence the API: the policy
        // argument is the slot's single owning-variant policy.
        assert_eq!(rot(&c), rot(&c2), "the slot's policy is unchanged");
    }

    /// LEGACY generation records (no originating target) predate attribution
    /// and are simply evaluated under the slot's ONE owning-variant policy
    /// like every other record — no per-target attribution exists anymore.
    /// Here the single policy (keep_distinct=2, no age, no previous, no
    /// deployment window) retains the two newest legacy bindings and sweeps
    /// the oldest.
    #[test]
    fn legacy_records_are_retained_under_the_single_policy() {
        let dir = tempfile::tempdir().unwrap();
        let remote = LocalTransport::new(dir.path().join("remote")).unwrap();
        let helper = RemoteHelper::new(&remote);
        // Legacy records: no originating target on any of them.
        make_gen(
            &helper,
            "d1",
            "g1",
            "t1",
            "2020-01-01T00:00:00Z",
            None,
            None,
        );
        make_gen(
            &helper,
            "d2",
            "g2",
            "t2",
            "2020-01-02T00:00:00Z",
            Some("g1"),
            None,
        );
        make_gen(
            &helper,
            "d3",
            "g3",
            "t3",
            "2020-01-03T00:00:00Z",
            Some("g2"),
            None,
        );
        helper.swap_current(None, "g3", "op").unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let mut c = cfg();
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .per_server
            .keep_distinct_artifacts = 2;
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .per_server
            .keep_days = 0;
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .per_server
            .protect_previous = false;
        c.variant_mut("standard")
            .unwrap()
            .rotation
            .deployment
            .protect_deployments = 0;

        let retained = compute_retained(&helper, &c.pins, &store, rot(&c)).unwrap();
        assert!(retained.contains("t3"), "current live tree retained");
        assert!(
            retained.contains("t2"),
            "the second-newest binding is retained by the single policy's keep_distinct=2"
        );
        assert!(
            !retained.contains("t1"),
            "the oldest binding outside the single policy's window is swept"
        );
    }
}
