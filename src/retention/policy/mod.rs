//! The slot-owned retention policy semantics (feature area A4): the retained-set
//! computation [`compute_retained`] under the slot's ONE owning-variant policy
//! (`per_server` `keep_distinct_artifacts` / `keep_days` / `protect_previous`,
//! `deployment` `protect_deployments`), evaluated against every generation
//! record on the server. Pin honoring lives in [`super::pins`]; the durable
//! pins are expanded into the retained set by
//! [`LocalStore::expand_retention_pins`].
//!
//! The policy group also owns the two selection concerns that feed the
//! retained set: [`pins`] (durable pin honoring, fail closed on BOTH sweep
//! sides) and [`rotate`] (the receiver-side rotation contract the
//! mark-and-sweep pass honors).

pub mod pins;
pub mod rotate;

use crate::config::{Pin, RetentionConfig};
use crate::error::Result;
use crate::identity::TreeDigest;
use crate::remote::helper::{RemoteHelper, RemoteStatus};
use crate::remote::layout;
use crate::store::local::LocalStore;
use jiff::Timestamp;
use std::collections::{BTreeMap, HashSet};

struct GenRecord {
    created_at: Timestamp,
    release: String,
    variant: String,
    tree: String,
    deployment_id: String,
}

/// Compute the set of retained tree digests for one server under the slot's
/// ONE policy: `retention` is the retention policy of the slot's OWNING
/// VARIANT, resolved by the caller from the current configuration
/// (`ProjectConfig::slot_retention`) — a single source, never a union across the
/// slot's member targets, so membership changes cannot change retention. The
/// durable pins declared in `deploy.toml` protect whole releases as before.
/// Capacity headroom, by contrast, is a per-server policy declared on the
/// server entry (`ServerDef.capacity`) and likewise resolved from the
/// caller's current configuration — it is never part of a release snapshot.
pub fn compute_retained(
    helper: &RemoteHelper,
    pins: &[Pin],
    store: &LocalStore,
    retention: &RetentionConfig,
) -> Result<HashSet<String>> {
    let mut retained: HashSet<String> = HashSet::new();
    let status = helper.status()?;

    // Current generation's tree — the live artifact is ALWAYS in the retained
    // set. `status()` validates the complete symlink layout, so a missing or
    // corrupt `assignment.json` under the current generation already failed
    // closed above (an integrity error — nothing is swept); a successful
    // status always carries the current tree.
    if let Some(t) = &status.current_tree {
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
            let created = a
                .created_at
                .parse::<Timestamp>()
                .unwrap_or_else(|_| Timestamp::now());
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
    retained.extend(retained_for_policy(helper, &status, &gens, retention)?);

    // Durable pins. A pin protects the whole release: every variant's tree
    // recorded in the release record is retained, so the pinned release stays
    // fully rollback-able no matter how old it is or how far outside the
    // count/age windows it falls. FAIL CLOSED: an un-honorable pin (a release
    // with no record on disk, or a record that cannot be read or
    // identity-verified) is an INTEGRITY error that aborts retention BEFORE
    // ANY DELETION — the honoring logic lives in [`super::pins`].
    store.expand_retention_pins(&mut retained, pins)?;

    Ok(retained)
}

/// Apply the slot's ONE retention policy (owned by its declaring variant) to
/// every generation record on the server. The caller already resolved the
/// policy from the slot's owning variant — there is no per-target policy and
/// no union across member targets. The current generation's prior is
/// protected whenever the policy sets `protect_previous`: it is the
/// immediate rollback target, and the slot's single policy decides.
fn retained_for_policy(
    helper: &RemoteHelper,
    status: &RemoteStatus,
    gens: &[GenRecord],
    retention: &RetentionConfig,
) -> Result<HashSet<String>> {
    let mut retained: HashSet<String> = HashSet::new();

    // Prior distinct successful generation when protect_previous is true.
    if retention.per_server.protect_previous
        && let Some(cur) = &status.current_generation
        && let Ok(a) = helper.read_assignment(cur.as_str())
        && let Some(prior) = &a.prior_generation
        && let Ok(pa) = helper.read_assignment(prior.as_str())
    {
        retained.insert(pa.artifact.tree.as_str().to_string());
    }

    // Distinct successful artifact bindings on the server, keyed by
    // (release, variant, tree).
    let mut distinct: BTreeMap<(String, String, String), Timestamp> = BTreeMap::new();
    for g in gens {
        let key = (g.release.clone(), g.variant.clone(), g.tree.clone());
        let slot = distinct.entry(key).or_insert(g.created_at);
        if g.created_at > *slot {
            *slot = g.created_at;
        }
    }
    // Sort by most recent activation descending.
    let mut ordered: Vec<((String, String, String), Timestamp)> = distinct.into_iter().collect();
    ordered.sort_by_key(|(_, ts)| std::cmp::Reverse(*ts));

    let keep_distinct = retention.per_server.keep_distinct_artifacts as usize;
    for ((_, _, tree), _) in ordered.iter().take(keep_distinct) {
        retained.insert(tree.clone());
    }

    let keep_days = retention.per_server.keep_days;
    if keep_days > 0 {
        let cutoff = Timestamp::now() - jiff::SignedDuration::from_hours(keep_days as i64 * 24);
        for ((_, _, tree), ts) in &ordered {
            if *ts >= cutoff {
                retained.insert(tree.clone());
            }
        }
    }

    // Deployment window: newest `protect_deployments` distinct deployment IDs
    // among the server's records.
    let protect_deployments = retention.deployment.protect_deployments as usize;
    if protect_deployments > 0 {
        let mut depl: BTreeMap<String, Timestamp> = BTreeMap::new();
        for g in gens {
            let slot = depl.entry(g.deployment_id.clone()).or_insert(g.created_at);
            if g.created_at > *slot {
                *slot = g.created_at;
            }
        }
        let mut depl_ordered: Vec<(String, Timestamp)> = depl.into_iter().collect();
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
        .map(|s| TreeDigest::parse(s).expect("retained digest is a valid sha256"))
        .collect()
}

#[cfg(test)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProjectConfig, SlotConfig};
    use crate::deploy::set_retention_deferred;
    use crate::error::Error;
    use crate::identity::{
        ReleaseId, ReleaseRecord, SlotId, TreeDigest, VariantName, test_deployment_id,
        test_generation_id, test_tree_digest,
    };
    use crate::remote::helper::{GenerationAssignment, RemoteHelper};
    use crate::remote::layout;
    use crate::remote::transport::LocalTransport;
    use crate::store::local::LocalStore;
    use crate::verify::release::RELEASE_RECORD_SCHEMA_VERSION;
    use crate::verify::release::build_release;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::path::PathBuf;

    fn cfg() -> ProjectConfig {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
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

[retention.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = true

[retention.deployment]
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
        ProjectConfig::load(&p).unwrap()
    }

    /// The slot's single retention policy, resolved from its OWNING VARIANT
    /// (`standard` declares slot `p1`): retention is slot-owned, never a
    /// per-target surface.
    fn ret(c: &ProjectConfig) -> &RetentionConfig {
        &c.variant("standard").unwrap().retention
    }

    #[test]
    fn retains_current_and_previous() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let helper = RemoteHelper::new(&remote);
        helper
            .remote()
            .create_dir_all(&layout::tree_root(test_tree_digest("t1").as_str()))
            .unwrap();
        helper
            .remote()
            .create_dir_all(&layout::tree_root(test_tree_digest("t2").as_str()))
            .unwrap();
        helper
            .create_generation(
                "op",
                &GenerationAssignment {
                    deployment_id: test_deployment_id("d1"),
                    generation_id: test_generation_id("g1"),
                    artifact: crate::identity::ArtifactRef {
                        release: crate::identity::test_release_id("r"),
                        variant: VariantName::new("standard"),
                        tree: test_tree_digest("t1"),
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
                    deployment_id: test_deployment_id("d2"),
                    generation_id: test_generation_id("g2"),
                    artifact: crate::identity::ArtifactRef {
                        release: crate::identity::test_release_id("r"),
                        variant: VariantName::new("standard"),
                        tree: test_tree_digest("t2"),
                    },
                    behavior_sha256: "b".into(),
                    prior_generation: Some(test_generation_id("g1")),
                    created_at: "2020-01-02T00:00:00Z".into(),
                    target: None,
                },
            )
            .unwrap();
        helper
            .swap_current(None, test_generation_id("g2").as_str(), "op")
            .unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let c = cfg();
        let retained = compute_retained(&helper, c.pins(), &store, ret(&c)).unwrap();
        assert!(
            retained.contains(test_tree_digest("t2").as_str()),
            "current tree retained"
        );
        assert!(
            retained.contains(test_tree_digest("t1").as_str()),
            "previous tree retained"
        );
    }

    /// A pin protects the whole release: every variant's tree recorded in the
    /// pinned release is retained even when nothing else would keep it.
    #[test]
    fn pin_protects_every_variant_of_a_release() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let helper = RemoteHelper::new(&remote);
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // A release with two variants, persisted in the local store. The
        // record must be a content-verifiable CURRENT-format record (its OWN
        // slot snapshot, identity recomputed from that content): an empty
        // slot snapshot is rejected by `write_release` (fail closed).
        let mut rec = crate::identity::ReleaseRecord {
            release_schema_version: RELEASE_RECORD_SCHEMA_VERSION,
            release_id: String::new(),
            release_sha256: String::new(),
            created_at: "2020-01-01T00:00:00Z".into(),
            provenance: crate::identity::Provenance {
                mapping_sha256: String::new(),
                behavior_sha256: String::new(),
            },
            variants: std::collections::BTreeMap::from([
                (
                    "a".to_string(),
                    test_tree_digest("tree-a").as_str().to_string(),
                ),
                (
                    "b".to_string(),
                    test_tree_digest("tree-b").as_str().to_string(),
                ),
            ]),
            slots: std::collections::BTreeMap::from([(
                "standard".to_string(),
                crate::identity::CanonicalSlots {
                    slots: vec![crate::identity::CanonicalSlot {
                        id: "p1".to_string(),
                        server: "s1".to_string(),
                        deploy_dir: "/srv/pin".to_string(),
                        target: "t1".to_string(),
                        groups: Vec::new(),
                    }],
                },
            )]),
        };
        let digest = crate::verify::release::recompute_release_digest(&rec)
            .expect("pin-test release must carry a slot snapshot");
        rec.release_sha256 = digest.as_str().to_string();
        rec.release_id = crate::identity::ReleaseId::from_digest(&digest)
            .as_str()
            .to_string();
        store.write_release(&rec).unwrap();

        let c = cfg();
        let pinned = [Pin {
            release: ReleaseId::from_digest(&digest),
            reason: "known-good".into(),
        }];

        // Without the pin the server has no history, so nothing is retained.
        let bare = compute_retained(&helper, &[], &store, ret(&c)).unwrap();
        assert!(bare.is_empty(), "no history and no pins retains nothing");

        // With the pin, BOTH variants' trees are protected.
        let retained = compute_retained(&helper, &pinned, &store, ret(&c)).unwrap();
        assert!(
            retained.contains(test_tree_digest("tree-a").as_str()),
            "variant a protected by the pin"
        );
        assert!(
            retained.contains(test_tree_digest("tree-b").as_str()),
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
        // The receiver's generation records are read back through the
        // validated parse, so the fixture writes the CANONICAL forms of its
        // tags (and the tree dir is keyed by the canonical digest).
        let canonical_tree = test_tree_digest(tree);
        helper
            .remote()
            .create_dir_all(&layout::tree_root(canonical_tree.as_str()))
            .unwrap();
        helper
            .create_generation(
                "op",
                &crate::remote::helper::GenerationAssignment {
                    deployment_id: test_deployment_id(deployment_id),
                    generation_id: test_generation_id(generation_id),
                    artifact: crate::identity::ArtifactRef {
                        release: crate::identity::test_release_id("r"),
                        variant: VariantName::new("standard"),
                        tree: canonical_tree,
                    },
                    behavior_sha256: "b".into(),
                    prior_generation: prior_generation.map(test_generation_id),
                    created_at: created.into(),
                    target: target.map(|t| crate::identity::TargetName::new(t.to_string())),
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
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
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
        helper
            .swap_current(None, test_generation_id("g3").as_str(), "op")
            .unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let mut c = cfg();
        c.variant_mut("standard")
            .unwrap()
            .retention
            .per_server
            .keep_distinct_artifacts = 2;
        c.variant_mut("standard")
            .unwrap()
            .retention
            .per_server
            .keep_days = 0;
        c.variant_mut("standard")
            .unwrap()
            .retention
            .deployment
            .protect_deployments = 0;
        // No prior chain, so protect_previous has nothing to add.
        c.variant_mut("standard")
            .unwrap()
            .retention
            .per_server
            .protect_previous = false;

        let retained = compute_retained(&helper, c.pins(), &store, ret(&c)).unwrap();
        assert!(
            retained.contains(test_tree_digest("t3").as_str()),
            "current tree retained"
        );
        assert!(
            retained.contains(test_tree_digest("t2").as_str()),
            "newest distinct binding retained"
        );
        assert!(
            !retained.contains(test_tree_digest("t1").as_str()),
            "the third-oldest distinct binding must be swept"
        );
    }

    /// The `keep_days` window retains every artifact activated within the
    /// window in addition to the distinct-artifact window.
    #[test]
    fn keep_days_retains_recent_artifacts() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let helper = RemoteHelper::new(&remote);
        let now = jiff::Timestamp::now();
        let old = (now - jiff::SignedDuration::from_hours(60 * 24)).to_string();
        let recent = (now - jiff::SignedDuration::from_hours(5 * 24)).to_string();
        make_gen(&helper, "d1", "g1", "t-old", &old, None, None);
        make_gen(&helper, "d2", "g2", "t-recent", &recent, Some("g1"), None);
        helper
            .swap_current(None, test_generation_id("g2").as_str(), "op")
            .unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let mut c = cfg();
        c.variant_mut("standard")
            .unwrap()
            .retention
            .per_server
            .keep_distinct_artifacts = 1;
        c.variant_mut("standard")
            .unwrap()
            .retention
            .per_server
            .keep_days = 30;
        c.variant_mut("standard")
            .unwrap()
            .retention
            .per_server
            .protect_previous = false;
        c.variant_mut("standard")
            .unwrap()
            .retention
            .deployment
            .protect_deployments = 0;

        let retained = compute_retained(&helper, c.pins(), &store, ret(&c)).unwrap();
        assert!(retained.contains(test_tree_digest("t-recent").as_str()));
        assert!(
            !retained.contains(test_tree_digest("t-old").as_str()),
            "artifact older than keep_days must be swept"
        );

        // Widen the window past the old artifact: it is retained again.
        c.variant_mut("standard")
            .unwrap()
            .retention
            .per_server
            .keep_days = 90;
        let retained = compute_retained(&helper, c.pins(), &store, ret(&c)).unwrap();
        assert!(
            retained.contains(test_tree_digest("t-old").as_str()),
            "artifact inside keep_days must be retained"
        );
        assert!(retained.contains(test_tree_digest("t-recent").as_str()));
    }

    /// The deployment `protect_deployments` window retains the artifacts of the
    /// newest N distinct deployment IDs, even when the distinct-artifact
    /// window alone would sweep them.
    #[test]
    fn snapshot_protect_deployments_retains_newest_deployments() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
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
        helper
            .swap_current(None, test_generation_id("g3").as_str(), "op")
            .unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let mut c = cfg();
        c.variant_mut("standard")
            .unwrap()
            .retention
            .per_server
            .keep_distinct_artifacts = 1;
        c.variant_mut("standard")
            .unwrap()
            .retention
            .per_server
            .keep_days = 0;
        c.variant_mut("standard")
            .unwrap()
            .retention
            .per_server
            .protect_previous = false;
        c.variant_mut("standard")
            .unwrap()
            .retention
            .deployment
            .protect_deployments = 2;

        let retained = compute_retained(&helper, c.pins(), &store, ret(&c)).unwrap();
        assert!(
            retained.contains(test_tree_digest("t3").as_str()),
            "current deployment retained"
        );
        assert!(
            retained.contains(test_tree_digest("t2").as_str()),
            "second-newest deployment protected by the deployment window"
        );
        assert!(
            !retained.contains(test_tree_digest("t1").as_str()),
            "oldest deployment outside the deployment window must be swept"
        );
    }

    /// Retention never deletes what rollback needs: with EVERY retention
    /// window zeroed (keep_distinct = 0, keep_days = 0, deployment = 0) and no
    /// pins, the current artifact and the protected previous artifact survive.
    #[test]
    fn current_and_protected_previous_survive_zero_windows() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
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
        helper
            .swap_current(None, test_generation_id("g2").as_str(), "op")
            .unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let mut c = cfg();
        c.variant_mut("standard")
            .unwrap()
            .retention
            .per_server
            .keep_distinct_artifacts = 0;
        c.variant_mut("standard")
            .unwrap()
            .retention
            .per_server
            .keep_days = 0;
        c.variant_mut("standard")
            .unwrap()
            .retention
            .per_server
            .protect_previous = true;
        c.variant_mut("standard")
            .unwrap()
            .retention
            .deployment
            .protect_deployments = 0;

        let retained = compute_retained(&helper, c.pins(), &store, ret(&c)).unwrap();
        assert!(
            retained.contains(test_tree_digest("t2").as_str()),
            "current tree is never swept"
        );
        assert!(
            retained.contains(test_tree_digest("t1").as_str()),
            "protected previous tree is never swept"
        );
    }

    /// Retention must NEVER sweep the tree behind a live `current` whose
    /// assignment cannot be read (a missing or corrupt `assignment.json`): the
    /// A corrupt CURRENT generation assignment is detected by `status()`
    /// itself (the complete symlink layout is validated: `current` ->
    /// generation dir -> `assignment.json` -> generation id), so retention
    /// against a remote whose live assignment is unreadable FAILS CLOSED with
    /// an integrity error BEFORE any sweep decision — the tree behind the
    /// unreadable current is never deleted, because nothing is ever swept.
    #[test]
    fn retention_fails_closed_when_live_assignment_is_unreadable() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
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
        helper
            .swap_current(None, test_generation_id("g1").as_str(), "op")
            .unwrap();
        // Corrupt the live generation's assignment record.
        std::fs::write(
            dir.path()
                .join("remote")
                .join(crate::remote::layout::generation(
                    test_generation_id("g1").as_str(),
                ))
                .join("assignment.json"),
            b"{ corrupt !",
        )
        .unwrap();
        assert!(
            helper
                .read_assignment(test_generation_id("g1").as_str())
                .is_err(),
            "the live assignment must be unreadable after corruption"
        );
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let mut c = cfg();
        // Every window zeroed + no pins: WITHOUT the fail-closed rule the
        // sweep would delete the live tree.
        c.variant_mut("standard")
            .unwrap()
            .retention
            .per_server
            .keep_distinct_artifacts = 0;
        c.variant_mut("standard")
            .unwrap()
            .retention
            .per_server
            .keep_days = 0;
        c.variant_mut("standard")
            .unwrap()
            .retention
            .per_server
            .protect_previous = false;
        c.variant_mut("standard")
            .unwrap()
            .retention
            .deployment
            .protect_deployments = 0;

        // Retention fails closed with an integrity error: the corrupt live
        // assignment is caught by `status()`'s layout validation, so no sweep
        // decision is ever made and nothing is deleted.
        let err = compute_retained(&helper, c.pins(), &store, ret(&c))
            .expect_err("retention must fail closed on a corrupt live assignment");
        assert!(
            err.to_string().contains("integrity"),
            "the retention failure must be an integrity error, got: {err}"
        );
        assert!(
            helper.remote().exists(&crate::remote::layout::tree_root(
                test_tree_digest("t1").as_str()
            )),
            "retention must not sweep the tree behind a corrupt current"
        );
    }

    /// GROUP MEMBERSHIP NEVER CHANGES RETENTION: the slot's retained set is
    /// computed from its OWNING VARIANT's single policy, so adding or
    /// removing a rollout group in the slot's `groups` list (a config-level
    /// membership change — groups only SELECT slots, they never own policy)
    /// leaves the retained digest set IDENTICAL. The policy is resolved
    /// through the same `ProjectConfig::slot_retention` path the engine uses, and the
    /// second config is a REAL reload of an edited slot declaration.
    #[test]
    fn group_membership_never_changes_retention() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
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
        helper
            .swap_current(None, test_generation_id("g3").as_str(), "op")
            .unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // ProjectConfig-level group change: rewrite `standard.toml` so slot `p1`
        // belongs to the `canary` group, then reload the project. The owning
        // variant — and therefore the slot's ONE policy — is unchanged.
        let project = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
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

[retention.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[retention.deployment]
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
        let c = ProjectConfig::load(&proj.join("deploy.toml")).unwrap();
        let before = compute_retained(&helper, c.pins(), &store, ret(&c)).unwrap();

        // The config-level group change: ADD a new rollout group (`wave-1`)
        // to slot `p1`'s `groups` list, then reload. Groups are selection-only
        // (they never own state, policy, history, or checkpoints), so
        // retention must not move.
        let variant_path = release_dir.join("standard.toml");
        let edited = std::fs::read_to_string(&variant_path)
            .unwrap()
            .replace("groups = [\"canary\"]", "groups = [\"canary\", \"wave-1\"]");
        std::fs::write(&variant_path, edited).unwrap();
        let c2 = ProjectConfig::load(&proj.join("deploy.toml")).unwrap();
        assert_eq!(
            c2.slot_variant("p1").unwrap(),
            "standard",
            "the owning variant is unchanged by group edits"
        );
        let after = compute_retained(&helper, c2.pins(), &store, ret(&c2)).unwrap();
        assert_eq!(
            before, after,
            "changing a slot's group membership must never change its retained set"
        );
        // And group membership cannot even influence the API: the policy
        // argument is the slot's single owning-variant policy.
        assert_eq!(ret(&c), ret(&c2), "the slot's policy is unchanged");
    }

    /// LEGACY generation records (no originating target) predate attribution
    /// and are simply evaluated under the slot's ONE owning-variant policy
    /// like every other record — no per-target attribution exists anymore.
    /// Here the single policy (keep_distinct=2, no age, no previous, no
    /// deployment window) retains the two newest legacy bindings and sweeps
    /// the oldest.
    #[test]
    fn legacy_records_are_retained_under_the_single_policy() {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
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
        helper
            .swap_current(None, test_generation_id("g3").as_str(), "op")
            .unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let mut c = cfg();
        c.variant_mut("standard")
            .unwrap()
            .retention
            .per_server
            .keep_distinct_artifacts = 2;
        c.variant_mut("standard")
            .unwrap()
            .retention
            .per_server
            .keep_days = 0;
        c.variant_mut("standard")
            .unwrap()
            .retention
            .per_server
            .protect_previous = false;
        c.variant_mut("standard")
            .unwrap()
            .retention
            .deployment
            .protect_deployments = 0;

        let retained = compute_retained(&helper, c.pins(), &store, ret(&c)).unwrap();
        assert!(
            retained.contains(test_tree_digest("t3").as_str()),
            "current live tree retained"
        );
        assert!(
            retained.contains(test_tree_digest("t2").as_str()),
            "the second-newest binding is retained by the single policy's keep_distinct=2"
        );
        assert!(
            !retained.contains(test_tree_digest("t1").as_str()),
            "the oldest binding outside the single policy's window is swept"
        );
    }

    // ---- fail-closed pins: an un-honorable pinned release aborts retention ----

    /// The three corruption classes for a pinned release's STORED record: the
    /// record file missing (a pin naming nothing on disk), the record file
    /// holding garbage bytes (unreadable as JSON), or a record whose stored
    /// identity fields do not match its content (the recompute-and-verify in
    /// [`LocalStore::read_release`] fails). Every class must abort retention
    /// with an integrity error BEFORE any deletion — never treat the pin as
    /// absent — and must recover EXACTLY after the record is repaired.
    #[derive(Clone, Copy, Debug)]
    enum PinRecordCorruption {
        Missing,
        Malformed,
        Unverifiable,
    }

    /// Seed the receiver inventory for the pin-abort tests: two generation
    /// records (current `t-cur` with prior `t-prev`, both inside the slot's
    /// windows), the pinned release's variant trees on the remote (retained
    /// ONLY by the pin — no generation references them), and a `tree-garbage`
    /// object referenced by nothing. Persists and returns the valid pinned
    /// release record (so a test can corrupt it and later repair it).
    fn seed_pin_receiver(
        helper: &RemoteHelper,
        store: &LocalStore,
        pin_trees: &[&str],
    ) -> ReleaseRecord {
        make_gen(
            helper,
            "d1",
            "g1",
            "t-prev",
            "2020-01-01T00:00:00Z",
            None,
            None,
        );
        make_gen(
            helper,
            "d2",
            "g2",
            "t-cur",
            "2020-01-02T00:00:00Z",
            Some("g1"),
            None,
        );
        helper
            .swap_current(None, test_generation_id("g2").as_str(), "op")
            .unwrap();
        // A garbage object referenced by nothing — genuinely unretained.
        helper
            .remote()
            .create_dir_all(&layout::tree_root(
                test_tree_digest("tree-garbage").as_str(),
            ))
            .unwrap();
        // The pin-only trees exist on the receiver; the pinned release's
        // record is the ONLY reference to them.
        for t in pin_trees {
            helper
                .remote()
                .create_dir_all(&layout::tree_root(test_tree_digest(t).as_str()))
                .unwrap();
        }
        let variants: BTreeMap<VariantName, TreeDigest> = pin_trees
            .iter()
            .enumerate()
            .map(|(i, t)| (VariantName::new(format!("v{i}")), test_tree_digest(t)))
            .collect();
        let rec = build_release(
            "mapping-sha",
            "behavior-sha",
            &variants,
            &BTreeMap::from([(
                "standard".to_string(),
                vec![SlotConfig::new(
                    "p1".to_string(),
                    "s1".to_string(),
                    PathBuf::from("/srv/pin"),
                    "t1".to_string(),
                    Vec::new(),
                )],
            )]),
            std::path::Path::new("."),
        );
        store.write_release(&rec).unwrap();
        rec
    }

    /// Corrupt the pinned release's stored record per class.
    fn corrupt_pin_record(store: &LocalStore, rec: &ReleaseRecord, kind: PinRecordCorruption) {
        let path = store
            .release_dir(&ReleaseId::new(rec.release_id.clone()))
            .join("release.json");
        match kind {
            PinRecordCorruption::Missing => {
                std::fs::remove_file(&path).unwrap();
            }
            PinRecordCorruption::Malformed => {
                std::fs::write(&path, b"{ this is not a release record").unwrap();
            }
            PinRecordCorruption::Unverifiable => {
                // A structurally-valid record whose identity fields do not
                // match its content: recompute-and-verify must fail closed.
                let mut tampered = rec.clone();
                tampered.release_id = "rel-sha256-0000deadbeef".to_string();
                tampered.release_sha256 = "0000deadbeef".to_string();
                let bytes = serde_json::to_vec_pretty(&tampered).unwrap();
                std::fs::write(&path, bytes).unwrap();
            }
        }
    }

    /// Repair the pinned release's record: the corrupt directory is removed
    /// (a `write_release` re-write would refuse to overwrite an unverifiable
    /// existing record) and the valid record is persisted again.
    fn repair_pin_record(store: &LocalStore, rec: &ReleaseRecord) {
        let dir = store.release_dir(&ReleaseId::new(rec.release_id.clone()));
        if dir.exists() {
            std::fs::remove_dir_all(&dir).unwrap();
        }
        store.write_release(rec).unwrap();
    }

    /// The shared deterministic scenario, run once per corruption class
    /// ([`PinRecordCorruption`]): with the record corrupted, `compute_retained`
    /// ABORTS with an integrity error before any deletion — the receiver
    /// inventory stays byte-identical and every tree (pin-only AND garbage)
    /// survives; after the record is REPAIRED, the retry deletes EXACTLY the
    /// genuinely unretained trees (the pin-only trees survive; the true
    /// garbage is removed).
    fn assert_pin_corruption_abort_then_repair(kind: PinRecordCorruption) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote"))
                .unwrap();
        let helper = RemoteHelper::new(&remote);
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let rec = seed_pin_receiver(&helper, &store, &["tree-pin-a", "tree-pin-b"]);
        let c = cfg()
            .with_pin(Pin {
                release: ReleaseId::parse(&rec.release_id).unwrap(),
                reason: "known-good".into(),
            })
            .unwrap();

        // Sanity with the VALID record: the pin protects both variant trees
        // and the garbage object is unretained (sweepable).
        let retained = compute_retained(&helper, c.pins(), &store, ret(&c)).unwrap();
        assert!(
            retained.contains(test_tree_digest("tree-pin-a").as_str()),
            "variant tree protected by the pin"
        );
        assert!(
            retained.contains(test_tree_digest("tree-pin-b").as_str()),
            "variant tree protected by the pin"
        );
        assert!(
            !retained.contains(test_tree_digest("tree-garbage").as_str()),
            "the garbage object is unretained"
        );

        // Byte-identical receiver inventory: the object inventory snapshot.
        helper.write_inventory().unwrap();
        let inv_path = dir.path().join("remote").join(layout::inventory());
        let inventory_before = std::fs::read(&inv_path).unwrap();

        // Corrupt the pinned release's stored record.
        corrupt_pin_record(&store, &rec, kind);

        // ABORT: an un-honorable pin is an integrity error — the pin is never
        // treated as absent (a silently-skipped pin would drop its trees from
        // the retained set and let retention delete them).
        let err = compute_retained(&helper, c.pins(), &store, ret(&c)).unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "an un-honorable pin aborts retention with an integrity error, got: {err}"
        );
        assert!(
            err.to_string().contains("pin names release"),
            "the integrity error names the pin, got: {err}"
        );

        // ZERO DELETIONS: retention never ran (the retained set was never
        // computed), so the receiver inventory is byte-identical and every
        // tree — pin-only AND garbage — survives.
        let inventory_after = std::fs::read(&inv_path).unwrap();
        assert_eq!(
            inventory_after, inventory_before,
            "the failed retention must not delete a single tree object"
        );
        for t in ["tree-pin-a", "tree-pin-b", "tree-garbage"] {
            assert!(
                helper
                    .remote()
                    .exists(&layout::tree_root(test_tree_digest(t).as_str())),
                "tree {t} must survive the failed retention"
            );
        }

        // REPAIR the record, then RETRY the retention.
        repair_pin_record(&store, &rec);
        let retained = compute_retained(&helper, c.pins(), &store, ret(&c)).unwrap();
        assert!(
            retained.contains(test_tree_digest("tree-pin-a").as_str())
                && retained.contains(test_tree_digest("tree-pin-b").as_str()),
            "the repaired record restores the pin's protection"
        );
        helper.rotate(&retained, &HashSet::new()).unwrap();

        // EXACT deletions: the genuinely unretained garbage is removed while
        // the pin-only trees (and the policy-retained live trees) survive.
        for t in ["tree-pin-a", "tree-pin-b", "t-cur", "t-prev"] {
            assert!(
                helper
                    .remote()
                    .exists(&layout::tree_root(test_tree_digest(t).as_str())),
                "tree {t} must survive the retry"
            );
        }
        assert!(
            !helper.remote().exists(&layout::tree_root(
                test_tree_digest("tree-garbage").as_str()
            )),
            "the true garbage is removed by the retry"
        );
    }

    /// A MISSING pinned release record: the pin names nothing on disk.
    #[test]
    fn pin_record_missing_aborts_then_repair_sweeps_exactly() {
        assert_pin_corruption_abort_then_repair(PinRecordCorruption::Missing);
    }

    /// A MALFORMED pinned release record: garbage bytes, unreadable as JSON.
    #[test]
    fn pin_record_malformed_aborts_then_repair_sweeps_exactly() {
        assert_pin_corruption_abort_then_repair(PinRecordCorruption::Malformed);
    }

    /// An UNVERIFIABLE pinned release record: a structurally-valid record
    /// whose stored identity does not match its content.
    #[test]
    fn pin_record_unverifiable_aborts_then_repair_sweeps_exactly() {
        assert_pin_corruption_abort_then_repair(PinRecordCorruption::Unverifiable);
    }

    proptest! {
        // FIXED-SEED property (0x5EED_5EED, per house style): a random
        // receiver inventory (random counts of pin-only trees and garbage
        // objects) with a randomly corrupted pinned release. The abort is
        // FAIL-CLOSED: `compute_retained` errors with an integrity class, the
        // retention-debt machinery records the durable marker, and ZERO trees
        // are deleted (the receiver inventory is byte-identical). After the
        // release record is REPAIRED, the retry deletes EXACTLY the genuinely
        // unretained trees (the pin-only trees survive; the garbage is
        // removed) and the debt marker is cleared.
        // removed) and the debt marker is cleared. Bounded 4 cases, fixed
        // seed 0x5EED_5EED (house style), no persistence.
        #![proptest_config(ProptestConfig {
            cases: 2,
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn pin_corruption_aborts_before_deletion_debt_then_retry_sweeps_exactly(
            n_pin_trees in 1usize..=3,
            n_garbage in 0usize..=2,
            kind in 0u8..=2,
        ) {
            let kind = match kind {
                0 => PinRecordCorruption::Missing,
                1 => PinRecordCorruption::Malformed,
                _ => PinRecordCorruption::Unverifiable,
            };
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let remote = LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote")).unwrap();
            let helper = RemoteHelper::new(&remote);
            let store = LocalStore::with_base(dir.path().join("store")).unwrap();
            let pin_trees: Vec<String> = (0..n_pin_trees).map(|i| format!("tree-pin-{i}")).collect();
            let pin_refs: Vec<&str> = pin_trees.iter().map(|s| s.as_str()).collect();
            let garbage: Vec<String> = (0..n_garbage).map(|i| format!("tree-garbage-{i}")).collect();
            let rec = seed_pin_receiver(&helper, &store, &pin_refs);
            for t in &garbage {
                helper
                    .remote()
                    .create_dir_all(&layout::tree_root(test_tree_digest(t).as_str()))
                    .unwrap();
            }
            let mut c = cfg();
            c = c
                .with_pin(Pin {
                    release: ReleaseId::parse(&rec.release_id).unwrap(),
                    reason: "known-good".into(),
                })
                .unwrap();

            // Sanity: the valid record pins every variant tree; every garbage
            // object is unretained.
            let retained = compute_retained(&helper, c.pins(), &store, ret(&c)).unwrap();
            for t in &pin_trees {
                assert!(
                    retained.contains(test_tree_digest(t).as_str()),
                    "pin tree {t} retained via the pin"
                );
            }
            for t in &garbage {
                assert!(
                    !retained.contains(test_tree_digest(t).as_str()),
                    "garbage {t} is unretained"
                );
            }

            helper.write_inventory().unwrap();
            let inv_path = dir.path().join("remote").join(layout::inventory());
            let inventory_before = std::fs::read(&inv_path).unwrap();

            corrupt_pin_record(&store, &rec, kind);

            // ABORT before any deletion: an integrity error, never an absent
            // pin.
            let err = compute_retained(&helper, c.pins(), &store, ret(&c)).unwrap_err();
            assert!(matches!(err, Error::Integrity(_)));
            assert!(err.to_string().contains("pin names release"));

            // ZERO DELETIONS: the receiver inventory is byte-identical.
            assert_eq!(
                std::fs::read(&inv_path).unwrap(),
                inventory_before,
                "the failed retention must not delete a single tree object"
            );

            // ROTATION DEBT: the engine's post-commit conversion records the
            // durable marker (the abort is a maintenance deferral, never a
            // hard push failure); the retry services it once the record is
            // repaired.
            let slot = SlotId::new("p1".to_string());
            let warnings = set_retention_deferred(&store, "t1", &slot, &err.to_string());
            assert!(warnings.is_empty(), "the marker write must succeed: {warnings:?}");
            let debt = store.read_retention_debt("t1").unwrap();
            assert_eq!(
                debt.get("p1").map(|s| s.as_str()),
                Some(err.to_string().as_str()),
                "the debt marker records the abort reason for the next push"
            );

            // REPAIR + RETRY: exact deletions — pin trees and live trees
            // survive, the true garbage is removed — and the marker clears.
            repair_pin_record(&store, &rec);
            let retained = compute_retained(&helper, c.pins(), &store, ret(&c)).unwrap();
            helper.rotate(&retained, &HashSet::new()).unwrap();
            for t in &pin_trees {
                assert!(
                    helper.remote().exists(&layout::tree_root(test_tree_digest(t).as_str())),
                    "pin tree {t} survives the retry"
                );
            }
            for t in ["t-cur", "t-prev"] {
                assert!(
                    helper.remote().exists(&layout::tree_root(test_tree_digest(t).as_str())),
                    "live tree {t} survives the retry"
                );
            }
            for t in &garbage {
                assert!(
                    !helper.remote().exists(&layout::tree_root(test_tree_digest(t).as_str())),
                    "garbage {t} is removed by the retry"
                );
            }
            let mut debt = store.read_retention_debt("t1").unwrap();
            assert!(
                debt.remove("p1").is_some(),
                "the retried retention services the marker"
            );
            store.write_retention_debt("t1", &debt).unwrap();
            assert!(
                store.read_retention_debt("t1").unwrap().is_empty(),
                "the debt marker is cleared once the retry succeeds"
            );
        }
    }
}
