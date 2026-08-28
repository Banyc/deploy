//! The slot-owned retention policy semantics (feature area A4): the retained-set
//! computation [`compute_retained`] under the slot's ONE owning-variant policy
//! (`per_server` `keep_distinct_artifacts` / `keep_days` / `protect_previous`,
//! `deployment` `protect_deployments`), evaluated against every generation
//! record on the server. Pin honoring lives in [`super::pins`]; the durable
//! pins are expanded into the retained set by
//! `LocalStore::expand_retention_pins`.
//!
//! The policy group also owns the two selection concerns that feed the
//! retained set: [`pins`] (durable pin honoring, fail closed on BOTH sweep
//! sides) and [`rotate`] (the receiver-side rotation contract the
//! mark-and-sweep pass honors).

pub mod pins;
pub mod rotate;

use crate::config::{Pin, RetentionConfig};
use crate::error::{Error, Result};
use crate::identity::{GenerationId, TreeDigest};
use crate::remote::helper::{RemoteHelper, RemoteStatus};
use crate::remote::layout;
use crate::store::local::LocalStore;
use jiff::Timestamp;
use std::collections::{BTreeMap, HashSet};

struct GenRecord {
    /// The record's identity: the generation directory name, validated by the
    /// fallible load (the assignment's `generation_id` must equal it). This is
    /// the map key of the ONE typed inventory — no second read ever needs to
    /// recover it.
    generation: GenerationId,
    created_at: Timestamp,
    release: String,
    variant: String,
    tree: String,
    deployment_id: String,
    /// The prior generation pointer (the assignment's `prior_generation`, already
    /// parsed during the fallible load). `None` is legitimate — no prior exists;
    /// a `Some` pointer that fails to resolve against the inventory aborts.
    prior_generation: Option<GenerationId>,
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
    //
    // The ENTIRE inventory is loaded through FALLIBLE TYPED operations into
    // ONE typed map keyed by `GenerationId` (the validated dir name): only a
    // CONFIRMED root absence (`metadata_opt` returning `Ok(None)` — the typed
    // replacement for the error-swallowing `exists` bool) means an empty
    // history. A root-metadata, listing, assignment-read, identity, or
    // timestamp failure ABORTS retention BEFORE any deletion — the step-17
    // caller records the retention-debt marker and sweeps nothing, so an
    // unreadable history is never mistaken for an unprotected one. The map is
    // the ONE source of truth for every later lookup — `protect_previous`
    // resolves the current and prior pointers against it and NEVER re-reads a
    // record through a second fallible path.
    let mut gens: BTreeMap<GenerationId, GenRecord> = BTreeMap::new();
    let gen_root = layout::generations();
    if helper.remote().metadata_opt(gen_root)?.is_some() {
        for e in helper.remote().list(gen_root)? {
            if !e.is_dir {
                continue;
            }
            // Assignment read/parse failure aborts the whole rotation (no
            // more `continue`): a generation that cannot be read must not
            // silently disappear from the inventory — its tree would look
            // unprotected and be deleted.
            let a = helper.read_assignment(&e.name)?;
            // Identity: the record must agree with the directory it lives
            // under. A tampered/mismatched record fails closed — it is never
            // trusted as evidence about the generation's tree.
            let dir_gen = GenerationId::parse(&e.name).map_err(|err| {
                Error::integrity(format!(
                    "generation directory {} names an invalid generation id: {err}",
                    e.name
                ))
            })?;
            if a.generation_id != dir_gen {
                return Err(Error::integrity(format!(
                    "generation {} assignment names generation {}, not its directory",
                    e.name, a.generation_id
                )));
            }
            // Timestamp: an unparseable `created_at` ABORTS (never the
            // current time — a corrupt record must not be treated as
            // brand-new).
            let created = crate::identity::Timestamp::parse(&a.created_at)
                .map(|t| *t.inner())
                .map_err(|err| {
                    Error::remote(format!(
                        "generation {} has an unparseable created_at {:?}: {err}",
                        e.name, a.created_at
                    ))
                })?;
            // Duplicate detection: two inventory entries with the same
            // `GenerationId` is an integrity error (the dirs are named by id,
            // so this fires only on corruption — it still fails closed rather
            // than silently overwriting one record).
            let rec = GenRecord {
                generation: dir_gen.clone(),
                created_at: created,
                release: a.artifact.release.as_str().to_string(),
                variant: a.artifact.variant.as_str().to_string(),
                tree: a.artifact.tree.as_str().to_string(),
                deployment_id: a.deployment_id.as_str().to_string(),
                prior_generation: a.prior_generation.clone(),
            };
            let rec_generation = rec.generation.clone();
            if gens.insert(dir_gen.clone(), rec).is_some() {
                return Err(Error::integrity(format!(
                    "generation inventory contains a duplicate generation id {rec_generation}"
                )));
            }
        }
    }

    // Apply the slot's ONE policy (from its owning variant) to ALL of the
    // server's records. No union, no membership lookup: the policy was
    // already resolved from the slot's owning variant by the caller.
    retained.extend(retained_for_policy(&status, &gens, retention)?);

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
    status: &RemoteStatus,
    gens: &BTreeMap<GenerationId, GenRecord>,
    retention: &RetentionConfig,
) -> Result<HashSet<String>> {
    let mut retained: HashSet<String> = HashSet::new();

    // Prior distinct successful generation when protect_previous is true.
    // Both pointers resolve against THE ONE typed inventory built above — the
    // current generation's dir is part of the inventory, and every record was
    // already loaded through the fail-closed build, so there is NO second
    // fallible read here (no `read_assignment` for current or prior). A
    // MISSING current record, or a `Some` prior pointer that fails to resolve
    // (a dangling pointer, or a record that aborted the inventory build),
    // ABORTS retention — the caller records debt and sweeps nothing, so the
    // prior is never silently unprotected. `prior_generation: None` is
    // legitimate: no prior exists, nothing to protect, no error.
    if retention.per_server.protect_previous
        && let Some(cur) = &status.current_generation
    {
        let cur_rec = gens.get(cur).ok_or_else(|| {
            Error::integrity(format!(
                "current generation {cur} is not in the generation inventory"
            ))
        })?;
        if let Some(prior) = &cur_rec.prior_generation {
            let prior_rec = gens.get(prior).ok_or_else(|| {
                Error::integrity(format!(
                    "generation {} names prior generation {prior}, which is not in the generation inventory",
                    cur_rec.generation
                ))
            })?;
            retained.insert(prior_rec.tree.clone());
        }
    }

    // Distinct successful artifact bindings on the server, keyed by
    // (release, variant, tree).
    let mut distinct: BTreeMap<(String, String, String), Timestamp> = BTreeMap::new();
    for g in gens.values() {
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
        for g in gens.values() {
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
        for g in gens.values() {
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
    use crate::config::{DeploymentRetention, PerServerRetention, ProjectConfig, SlotConfig};
    use crate::deploy::set_retention_deferred;
    use crate::error::Error;
    use crate::identity::{
        ArtifactRef, DeploymentId, GenerationId, ReleaseId, ReleaseRecord, SlotId, TreeDigest,
        VariantName, test_deployment_id, test_generation_id, test_release_id, test_tree_digest,
    };
    use crate::remote::helper::{GenerationAssignment, RemoteHelper};
    use crate::remote::layout;
    use crate::remote::transport::{
        CreateNewVerdict, LocalTransport, Remote, RemoteEntry, RemoteMeta,
    };
    use crate::store::local::LocalStore;
    use crate::verify::release::RELEASE_RECORD_SCHEMA_VERSION;
    use crate::verify::release::build_release;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::path::{Path, PathBuf};

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
            .swap_current(
                &crate::remote::helper::ExpectedCurrent::Absent,
                test_generation_id("g2").as_str(),
                "op",
            )
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
            .swap_current(
                &crate::remote::helper::ExpectedCurrent::Absent,
                test_generation_id("g3").as_str(),
                "op",
            )
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
            .swap_current(
                &crate::remote::helper::ExpectedCurrent::Absent,
                test_generation_id("g2").as_str(),
                "op",
            )
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
            .swap_current(
                &crate::remote::helper::ExpectedCurrent::Absent,
                test_generation_id("g3").as_str(),
                "op",
            )
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
            .swap_current(
                &crate::remote::helper::ExpectedCurrent::Absent,
                test_generation_id("g2").as_str(),
                "op",
            )
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
            .swap_current(
                &crate::remote::helper::ExpectedCurrent::Absent,
                test_generation_id("g1").as_str(),
                "op",
            )
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
            .swap_current(
                &crate::remote::helper::ExpectedCurrent::Absent,
                test_generation_id("g3").as_str(),
                "op",
            )
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
            .swap_current(
                &crate::remote::helper::ExpectedCurrent::Absent,
                test_generation_id("g3").as_str(),
                "op",
            )
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
            .swap_current(
                &crate::remote::helper::ExpectedCurrent::Absent,
                test_generation_id("g2").as_str(),
                "op",
            )
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
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
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

    // ---- fallible inventory loading: an unreadable history is NOT unprotected ----

    /// One generated generation record in the fixture history: the typed
    /// wire fields (canonical ids + digest) plus the parsed timestamp, so
    /// the fixture builder and the reference model share one source.
    #[derive(Clone, Debug)]
    struct TestGen {
        id: String,
        deployment: String,
        tree: String,
        created_at: Timestamp,
        prior: Option<String>,
        release: String,
        variant: String,
    }

    /// The REFERENCE-MODEL retained set for a generated history: every tree
    /// the slot policy MUST keep — the current tree, the protected previous
    /// tree, the newest `keep_distinct` distinct (release, variant, tree)
    /// bindings, every binding activated inside the `keep_days` window, and
    /// every tree of the newest `protect_deployments` distinct deployment
    /// ids. Computed INDEPENDENTLY of [`compute_retained`] — plain set
    /// arithmetic over the generated history + policy, no transport calls —
    /// so the healthy sanity and the post-repair retry both pin the exact
    /// expected set.
    fn reference_retained(
        history: &[TestGen],
        current: &TestGen,
        policy: &RetentionConfig,
    ) -> HashSet<String> {
        let mut retained: HashSet<String> = HashSet::new();
        retained.insert(current.tree.clone());

        if policy.per_server.protect_previous
            && let Some(prior) = &current.prior
            && let Some(p) = history.iter().find(|g| g.id == *prior)
        {
            retained.insert(p.tree.clone());
        }

        // Distinct successful artifact bindings, keyed by (release, variant,
        // tree), newest activation first.
        let mut distinct: BTreeMap<(String, String, String), Timestamp> = BTreeMap::new();
        for g in history {
            let key = (g.release.clone(), g.variant.clone(), g.tree.clone());
            let slot = distinct.entry(key).or_insert(g.created_at);
            if g.created_at > *slot {
                *slot = g.created_at;
            }
        }
        let mut ordered: Vec<((String, String, String), Timestamp)> =
            distinct.into_iter().collect();
        ordered.sort_by_key(|(_, ts)| std::cmp::Reverse(*ts));
        for ((_, _, tree), _) in ordered
            .iter()
            .take(policy.per_server.keep_distinct_artifacts as usize)
        {
            retained.insert(tree.clone());
        }

        let keep_days = policy.per_server.keep_days;
        if keep_days > 0 {
            let cutoff = Timestamp::now() - jiff::SignedDuration::from_hours(keep_days as i64 * 24);
            for ((_, _, tree), ts) in &ordered {
                if *ts >= cutoff {
                    retained.insert(tree.clone());
                }
            }
        }

        let protect_deployments = policy.deployment.protect_deployments as usize;
        if protect_deployments > 0 {
            let mut depl: BTreeMap<String, Timestamp> = BTreeMap::new();
            for g in history {
                let slot = depl.entry(g.deployment.clone()).or_insert(g.created_at);
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
            for g in history {
                if keep_ids.contains(&g.deployment) {
                    retained.insert(g.tree.clone());
                }
            }
        }
        retained
    }

    /// A one-shot fault-injection wrapper over [`LocalTransport`]: the FIRST
    /// `metadata_opt` (or `list`) on the `generations/` root fails with a
    /// remote error and then passes every operation through. Path-scoped so
    /// the `status()` reads that PRECEDE the inventory load (`current`, the
    /// object store, the lock, incoming) pass through untouched — the fault
    /// fires exactly in the inventory-loading section of `compute_retained`.
    struct FailOnceInventoryRemote {
        inner: LocalTransport,
        fail_root_metadata: std::cell::Cell<bool>,
        fail_root_list: std::cell::Cell<bool>,
    }

    impl FailOnceInventoryRemote {
        fn new(base: PathBuf, fail_metadata: bool, fail_list: bool) -> Self {
            FailOnceInventoryRemote {
                inner: LocalTransport::new(&crate::testutil::fixture_env(), base).unwrap(),
                fail_root_metadata: std::cell::Cell::new(fail_metadata),
                fail_root_list: std::cell::Cell::new(fail_list),
            }
        }
    }

    impl Remote for FailOnceInventoryRemote {
        fn root(&self) -> &Path {
            self.inner.root()
        }
        fn read(&self, rel: &Path) -> Result<Vec<u8>> {
            self.inner.read(rel)
        }
        fn write(&self, rel: &Path, data: &[u8], mode: u32) -> Result<()> {
            self.inner.write(rel, data, mode)
        }
        fn try_write_new(&self, rel: &Path, data: &[u8]) -> Result<CreateNewVerdict> {
            self.inner.try_write_new(rel, data)
        }
        fn create_dir(&self, rel: &Path) -> Result<()> {
            self.inner.create_dir(rel)
        }
        fn create_dir_all(&self, rel: &Path) -> Result<()> {
            self.inner.create_dir_all(rel)
        }
        fn set_mode(&self, rel: &Path, mode: u32) -> Result<()> {
            self.inner.set_mode(rel, mode)
        }
        fn list(&self, rel: &Path) -> Result<Vec<RemoteEntry>> {
            if self.fail_root_list.get() && rel == layout::generations() {
                self.fail_root_list.set(false);
                return Err(Error::remote(
                    "injected fault: generations listing failed once",
                ));
            }
            self.inner.list(rel)
        }
        fn rename(&self, from: &Path, to: &Path) -> Result<()> {
            self.inner.rename(from, to)
        }
        fn symlink(&self, target: &Path, link: &Path) -> Result<()> {
            self.inner.symlink(target, link)
        }
        fn read_link(&self, rel: &Path) -> Result<PathBuf> {
            self.inner.read_link(rel)
        }
        fn remove_file(&self, rel: &Path) -> Result<()> {
            self.inner.remove_file(rel)
        }
        fn remove_dir_all(&self, rel: &Path) -> Result<()> {
            self.inner.remove_dir_all(rel)
        }
        fn exists(&self, rel: &Path) -> bool {
            self.inner.exists(rel)
        }
        fn metadata(&self, rel: &Path) -> Result<RemoteMeta> {
            self.inner.metadata(rel)
        }
        fn metadata_opt(&self, rel: &Path) -> Result<Option<RemoteMeta>> {
            if self.fail_root_metadata.get() && rel == layout::generations() {
                self.fail_root_metadata.set(false);
                return Err(Error::remote(
                    "injected fault: generations metadata failed once",
                ));
            }
            self.inner.metadata_opt(rel)
        }
        fn exec(
            &self,
            argv: &[String],
            timeout: std::time::Duration,
        ) -> Result<crate::remote::transport::ExecOutcome> {
            self.inner.exec(argv, timeout)
        }
        fn filesystem_bytes(&self) -> Result<crate::remote::transport::FsBytes> {
            self.inner.filesystem_bytes()
        }
    }

    proptest! {
        // FIXED-SEED property (0x5EED_5EED, per house style): a random
        // history (2..=4 generations with canonical ids/trees/timestamps
        // relative to now) + a random policy, with ONE injected failure at
        // the root metadata / listing / assignment parsing / timestamp
        // parsing / identity check. The abort is FAIL-CLOSED: `compute_retained`
        // errors, the retention-debt machinery records the durable marker,
        // and ZERO trees are deleted (the receiver inventory is
        // byte-identical and every tree survives). After the fault is
        // REPAIRED, the retry's retained set is EXACTLY the reference-model
        // set (the healthy sanity already pinned equality), and the
        // mark-and-sweep retry deletes exactly the trees outside that set.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn inventory_failure_aborts_before_deletion_debt_then_retry_matches_reference(
            n_gens in 2usize..=4,
            keep_distinct in 0u32..=2,
            keep_days in prop::sample::select(vec![0u64, 2, 4]),
            protect_previous: bool,
            protect_deployments in 0u32..=2,
            fault in 0u8..=4,
            corrupt_idx in 0usize..=3,
        ) {
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let base = dir.path().join("remote");
            let plain =
                LocalTransport::new(&crate::testutil::fixture_env(), base.clone()).unwrap();
            let helper = RemoteHelper::new(&plain);

            // A generation record created at `now - (2*(n-1-i)+1)` days: the
            // NEWEST (i = n-1) is 1 day old, each older is 2 days further
            // back, so every generated `created_at` is an ODD number of days
            // before `now`. With `keep_days` even (0/2/4), no generated
            // timestamp can land within a day of the age cutoff — the
            // code-under-test and the reference model each call
            // `Timestamp::now()` independently, and the sub-day skew can
            // never flip the window boundary.
            let now = Timestamp::now();
            let mut history: Vec<TestGen> = Vec::new();
            for i in 0..n_gens {
                let offset_days = (2 * (n_gens - 1 - i) + 1) as i64;
                history.push(TestGen {
                    id: test_generation_id(&format!("g{i}")).as_str().to_string(),
                    deployment: test_deployment_id(&format!("d{i}")).as_str().to_string(),
                    tree: test_tree_digest(&format!("t{i}")).as_str().to_string(),
                    created_at: now - jiff::SignedDuration::from_hours(offset_days * 24),
                    prior: (i > 0).then(|| {
                        test_generation_id(&format!("g{}", i - 1)).as_str().to_string()
                    }),
                    release: test_release_id("r").as_str().to_string(),
                    variant: "standard".to_string(),
                });
            }

            // Build the fixture history on the remote: tree objects +
            // assignments + `current` -> the newest generation. The original
            // `GenerationAssignment` records are kept for deterministic
            // REPAIR after a corrupt-record fault.
            let mut assignments: Vec<GenerationAssignment> = Vec::new();
            for g in &history {
                helper
                    .remote()
                    .create_dir_all(&layout::tree_root(&g.tree))
                    .unwrap();
                let asn = GenerationAssignment {
                    deployment_id: DeploymentId::parse(&g.deployment).unwrap(),
                    generation_id: GenerationId::parse(&g.id).unwrap(),
                    artifact: ArtifactRef {
                        release: test_release_id("r"),
                        variant: VariantName::new("standard"),
                        tree: TreeDigest::parse(&g.tree).unwrap(),
                    },
                    behavior_sha256: "b".into(),
                    prior_generation: g.prior.as_ref().map(|p| GenerationId::parse(p).unwrap()),
                    created_at: g.created_at.to_string(),
                    target: None,
                };
                helper.create_generation("op", &asn).unwrap();
                assignments.push(asn);
            }
            let current = history.last().unwrap().clone();
            helper
                .swap_current(
                    &crate::remote::helper::ExpectedCurrent::Absent,
                    current.id.as_str(),
                    "op",
                )
                .unwrap();
            // A garbage tree referenced by nothing: retained by NO window, so
            // the retry's mark-and-sweep must remove it (and the
            // out-of-window history) while the reference set survives.
            helper
                .remote()
                .create_dir_all(&layout::tree_root(test_tree_digest("garbage").as_str()))
                .unwrap();

            let store = LocalStore::with_base(dir.path().join("store")).unwrap();
            let policy = RetentionConfig {
                per_server: PerServerRetention {
                    keep_distinct_artifacts: keep_distinct,
                    keep_days,
                    protect_previous,
                },
                deployment: DeploymentRetention {
                    protect_deployments,
                },
            };
            let expected = reference_retained(&history, &current, &policy);

            // Healthy sanity: the happy path's retained set is EXACTLY the
            // reference model — this pins behavior-identical-for-healthy-
            // remotes for every generated history + policy.
            assert_eq!(
                compute_retained(&helper, &[], &store, &policy).unwrap(),
                expected,
                "the healthy retained set must match the reference model"
            );

            // The receiver inventory snapshot (byte-identical after the
            // failed retention: the retained set was never computed, so the
            // sweep never ran).
            helper.write_inventory().unwrap();
            let inv_path = dir.path().join("remote").join(layout::inventory());
            let inventory_before = std::fs::read(&inv_path).unwrap();

            // Inject ONE failure: a one-shot transport fault on the
            // generations root (metadata / listing), or a corrupt record on
            // a NON-current generation (assignment / timestamp / identity).
            let corrupt_idx = corrupt_idx % (n_gens - 1);
            let fault_remote: Option<FailOnceInventoryRemote> = match fault {
                0 => Some(FailOnceInventoryRemote::new(base.clone(), true, false)),
                1 => Some(FailOnceInventoryRemote::new(base.clone(), false, true)),
                _ => None,
            };
            match fault {
                2 => {
                    let p = layout::generation(&history[corrupt_idx].id).join("assignment.json");
                    std::fs::write(dir.path().join("remote").join(p), b"{ corrupt !").unwrap();
                }
                3 => {
                    let mut a = assignments[corrupt_idx].clone();
                    a.created_at = "not-a-timestamp".into();
                    let p = layout::generation(&history[corrupt_idx].id).join("assignment.json");
                    std::fs::write(
                        dir.path().join("remote").join(p),
                        serde_json::to_vec_pretty(&a).unwrap(),
                    )
                    .unwrap();
                }
                4 => {
                    let mut a = assignments[corrupt_idx].clone();
                    a.generation_id = test_generation_id("tampered");
                    let p = layout::generation(&history[corrupt_idx].id).join("assignment.json");
                    std::fs::write(
                        dir.path().join("remote").join(p),
                        serde_json::to_vec_pretty(&a).unwrap(),
                    )
                    .unwrap();
                }
                _ => {}
            }

            // ABORT before any deletion: the injected fault propagates as an
            // `Err` — the inventory is never loaded as "unprotected", so
            // nothing is ever swept. The error names the injected step, so
            // the assertion proves the fault fired exactly where intended.
            let err = match &fault_remote {
                Some(fr) => {
                    let fh = RemoteHelper::new(fr);
                    compute_retained(&fh, &[], &store, &policy).unwrap_err()
                }
                None => compute_retained(&helper, &[], &store, &policy).unwrap_err(),
            };
            let err_text = err.to_string();
            let expected_marker = match fault {
                0 => "injected fault: generations metadata",
                1 => "injected fault: generations listing",
                2 => "parse assignment",
                3 => "unparseable created_at",
                _ => "assignment names generation",
            };
            assert!(
                err_text.contains(expected_marker),
                "the {fault}-fault must abort at the injected step, got: {err_text}"
            );

            // ZERO DELETIONS: the receiver inventory is byte-identical and
            // every tree — every history tree AND the garbage — survives.
            assert_eq!(
                std::fs::read(&inv_path).unwrap(),
                inventory_before,
                "the failed retention must not delete a single tree object"
            );
            for g in &history {
                assert!(
                    helper.remote().exists(&layout::tree_root(&g.tree)),
                    "history tree {} must survive the failed retention",
                    g.tree
                );
            }
            assert!(
                helper.remote().exists(&layout::tree_root(
                    test_tree_digest("garbage").as_str()
                )),
                "the garbage tree must survive the failed retention"
            );

            // ROTATION DEBT: the engine's post-commit conversion records the
            // durable marker (the abort is a maintenance deferral, never a
            // hard push failure); the retry services it once the fault is
            // repaired.
            let slot = SlotId::new("p1".to_string());
            let warnings = set_retention_deferred(&store, "t1", &slot, &err_text);
            assert!(warnings.is_empty(), "the marker write must succeed: {warnings:?}");
            let debt = store.read_retention_debt("t1").unwrap();
            assert_eq!(
                debt.get("p1").map(|s| s.as_str()),
                Some(err_text.as_str()),
                "the debt marker records the abort reason for the next push"
            );

            // REPAIR: restore the corrupted record (the one-shot wrapper
            // already disarmed itself after firing).
            if fault >= 2 {
                let asn = &assignments[corrupt_idx];
                let p = layout::generation(asn.generation_id.as_str()).join("assignment.json");
                helper
                    .remote()
                    .write(&p, &serde_json::to_vec_pretty(asn).unwrap(), 0o644)
                    .unwrap();
            }

            // RETRY: the retained set is EXACTLY the reference-model set,
            // and the mark-and-sweep deletes exactly the trees outside it.
            let retained = match &fault_remote {
                Some(fr) => {
                    let fh = RemoteHelper::new(fr);
                    compute_retained(&fh, &[], &store, &policy).unwrap()
                }
                None => compute_retained(&helper, &[], &store, &policy).unwrap(),
            };
            assert_eq!(
                retained, expected,
                "the retried retention must retain exactly the reference-model set"
            );
            helper.rotate(&retained, &HashSet::new()).unwrap();
            for g in &history {
                assert_eq!(
                    helper.remote().exists(&layout::tree_root(&g.tree)),
                    expected.contains(&g.tree),
                    "history tree {} must survive iff the reference model retains it",
                    g.tree
                );
            }
            assert!(
                !helper.remote().exists(&layout::tree_root(
                    test_tree_digest("garbage").as_str()
                )),
                "the garbage tree is removed by the retry"
            );

            // The retried retention services the marker.
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

    // ---- protect_previous resolves against the ONE typed inventory ----

    /// A fault-injecting transport wrapper for the protect_previous paths. It
    /// COUNTS `generations/<id>/assignment.json` reads for the tracked ids
    /// (the current + prior pointers) and FAILS any read beyond its
    /// LEGITIMATE count: the current assignment is legitimately read twice
    /// (once by `status()`'s chain validation, once by the inventory build),
    /// the prior assignment once (the build only) — so a further read is
    /// EXACTLY the removed second path, and the injected failure proves the
    /// path is gone (it never fires; the outcome is governed by the ONE
    /// inventory). It can also HIDE live generation dirs from the
    /// `generations/` listing (a listing/transport inconsistency that omits
    /// the current dir — the "absent current" fault).
    struct ProtectPreviousRemote {
        inner: LocalTransport,
        tracked: Vec<String>,
        /// Max legitimate `assignment.json` reads per tracked id.
        legit: BTreeMap<String, usize>,
        hide_from_listing: Vec<String>,
        counts: std::cell::RefCell<BTreeMap<String, usize>>,
    }

    impl ProtectPreviousRemote {
        fn new(
            base: PathBuf,
            tracked: Vec<String>,
            legit: &[(&str, usize)],
            hide_from_listing: Vec<String>,
        ) -> Self {
            ProtectPreviousRemote {
                inner: LocalTransport::new(&crate::testutil::fixture_env(), base).unwrap(),
                legit: legit
                    .iter()
                    .map(|(id, n)| ((*id).to_string(), *n))
                    .collect(),
                tracked,
                hide_from_listing,
                counts: std::cell::RefCell::new(BTreeMap::new()),
            }
        }

        /// The id of a tracked `generations/<id>/assignment.json` path, if any.
        fn tracked_assignment(&self, rel: &Path) -> Option<String> {
            let parts: Vec<&str> = rel.iter().map(|c| c.to_str().unwrap_or("")).collect();
            if parts.len() == 3 && parts[0] == "generations" && parts[2] == "assignment.json" {
                let id = parts[1];
                if self.tracked.iter().any(|t| t == id) {
                    return Some(id.to_string());
                }
            }
            None
        }

        /// The number of `assignment.json` reads observed for `id`.
        fn read_count(&self, id: &str) -> usize {
            self.counts.borrow().get(id).copied().unwrap_or(0)
        }
    }

    impl Remote for ProtectPreviousRemote {
        fn root(&self) -> &Path {
            self.inner.root()
        }
        fn read(&self, rel: &Path) -> Result<Vec<u8>> {
            if let Some(id) = self.tracked_assignment(rel) {
                let mut counts = self.counts.borrow_mut();
                let n = counts.entry(id.clone()).or_insert(0);
                *n += 1;
                if let Some(legit) = self.legit.get(&id)
                    && *n > *legit
                {
                    return Err(Error::remote(format!(
                        "injected fault: second read of assignment {id}"
                    )));
                }
            }
            self.inner.read(rel)
        }
        fn write(&self, rel: &Path, data: &[u8], mode: u32) -> Result<()> {
            self.inner.write(rel, data, mode)
        }
        fn try_write_new(&self, rel: &Path, data: &[u8]) -> Result<CreateNewVerdict> {
            self.inner.try_write_new(rel, data)
        }
        fn create_dir(&self, rel: &Path) -> Result<()> {
            self.inner.create_dir(rel)
        }
        fn create_dir_all(&self, rel: &Path) -> Result<()> {
            self.inner.create_dir_all(rel)
        }
        fn set_mode(&self, rel: &Path, mode: u32) -> Result<()> {
            self.inner.set_mode(rel, mode)
        }
        fn list(&self, rel: &Path) -> Result<Vec<RemoteEntry>> {
            let entries = self.inner.list(rel)?;
            if rel == layout::generations() && !self.hide_from_listing.is_empty() {
                return Ok(entries
                    .into_iter()
                    .filter(|e| !self.hide_from_listing.contains(&e.name))
                    .collect());
            }
            Ok(entries)
        }
        fn rename(&self, from: &Path, to: &Path) -> Result<()> {
            self.inner.rename(from, to)
        }
        fn symlink(&self, target: &Path, link: &Path) -> Result<()> {
            self.inner.symlink(target, link)
        }
        fn read_link(&self, rel: &Path) -> Result<PathBuf> {
            self.inner.read_link(rel)
        }
        fn remove_file(&self, rel: &Path) -> Result<()> {
            self.inner.remove_file(rel)
        }
        fn remove_dir_all(&self, rel: &Path) -> Result<()> {
            self.inner.remove_dir_all(rel)
        }
        fn exists(&self, rel: &Path) -> bool {
            self.inner.exists(rel)
        }
        fn metadata(&self, rel: &Path) -> Result<RemoteMeta> {
            self.inner.metadata(rel)
        }
        fn exec(
            &self,
            argv: &[String],
            timeout: std::time::Duration,
        ) -> Result<crate::remote::transport::ExecOutcome> {
            self.inner.exec(argv, timeout)
        }
        fn filesystem_bytes(&self) -> Result<crate::remote::transport::FsBytes> {
            self.inner.filesystem_bytes()
        }
    }

    proptest! {
        // FIXED-SEED property (0x5EED_5EED, per house style): a random
        // inventory + policy, with the CURRENT/PRIOR POINTERS generated
        // independently — the current id and the current record's prior may or
        // may not resolve in the inventory. `protect_previous` resolves both
        // against the ONE typed map: a MISSING current or a `Some` prior that
        // fails to resolve ABORTS (an integrity error — the caller records
        // debt, never silently unprotects), `prior_generation: None` is
        // legitimate (nothing to protect, no error), and after the pointer is
        // REPAIRED the retry is EXACTLY the reference-model set. The healthy
        // and prior-None cases pin behavior-identical-for-healthy-remotes for
        // every generated inventory + policy.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn protect_previous_resolves_against_the_one_inventory(
            n_gens in 2usize..=4,
            keep_distinct in 0u32..=2,
            keep_days in prop::sample::select(vec![0u64, 2, 4]),
            protect_deployments in 0u32..=2,
            scenario in 0u8..=3,
        ) {
            // The generated inventory: a chain of records with odd-day
            // timestamps relative to now (the same fixture shape as the
            // end-to-end reference model — even keep_days can never race the
            // cutoff because no generated timestamp lands within a day of it).
            let now = Timestamp::now();
            let mut history: Vec<TestGen> = Vec::new();
            for i in 0..n_gens {
                let offset_days = (2 * (n_gens - 1 - i) + 1) as i64;
                history.push(TestGen {
                    id: test_generation_id(&format!("g{i}")).as_str().to_string(),
                    deployment: test_deployment_id(&format!("d{i}")).as_str().to_string(),
                    tree: test_tree_digest(&format!("t{i}")).as_str().to_string(),
                    created_at: now - jiff::SignedDuration::from_hours(offset_days * 24),
                    prior: (i > 0).then(|| {
                        test_generation_id(&format!("g{}", i - 1)).as_str().to_string()
                    }),
                    release: test_release_id("r").as_str().to_string(),
                    variant: "standard".to_string(),
                });
            }
            let mut gens: BTreeMap<GenerationId, GenRecord> = BTreeMap::new();
            for g in &history {
                gens.insert(
                    GenerationId::parse(&g.id).unwrap(),
                    GenRecord {
                        generation: GenerationId::parse(&g.id).unwrap(),
                        created_at: g.created_at,
                        release: g.release.clone(),
                        variant: g.variant.clone(),
                        tree: g.tree.clone(),
                        deployment_id: g.deployment.clone(),
                        prior_generation: g
                            .prior
                            .as_ref()
                            .map(|p| GenerationId::parse(p).unwrap()),
                    },
                );
            }

            let policy = RetentionConfig {
                per_server: PerServerRetention {
                    keep_distinct_artifacts: keep_distinct,
                    keep_days,
                    protect_previous: true,
                },
                deployment: DeploymentRetention {
                    protect_deployments,
                },
            };
            let last = history.last().unwrap();

            // The generated POINTERS: the current id and the current record's
            // prior may or may not resolve in the inventory. `ref_current` is
            // the reference-model view of the mutated current record.
            let mut current_id = last.id.clone();
            let mut ref_current = last.clone();
            let mut expect_abort = false;
            match scenario {
                // Healthy: current in the inventory, prior in it.
                0 => {}
                // Absent CURRENT: the pointer names a generation with no
                // record in the inventory — abort.
                1 => {
                    current_id = test_generation_id("absent-cur").as_str().to_string();
                    expect_abort = true;
                }
                // Absent PRIOR: the current record's prior pointer names a
                // generation with no record in the inventory — abort.
                2 => {
                    let cur = gens
                        .get_mut(&GenerationId::parse(&last.id).unwrap())
                        .unwrap();
                    cur.prior_generation = Some(
                        GenerationId::parse(test_generation_id("absent-pri").as_str()).unwrap(),
                    );
                    expect_abort = true;
                }
                // No prior: `prior_generation: None` is legitimate — nothing
                // to protect, no error.
                _ => {
                    let cur = gens
                        .get_mut(&GenerationId::parse(&last.id).unwrap())
                        .unwrap();
                    cur.prior_generation = None;
                    ref_current.prior = None;
                }
            }
            let status = RemoteStatus {
                current_generation: Some(GenerationId::parse(&current_id).unwrap()),
                ..RemoteStatus::default()
            };

            // `compute_retained` adds the live current tree from
            // `status.current_tree` BEFORE the policy pass, so the direct
            // comparison must mirror that: the policy pass plus the current
            // record's tree.
            let policy_retained = |st: &RemoteStatus, gs: &BTreeMap<GenerationId, GenRecord>| {
                let mut retained = retained_for_policy(st, gs, &policy).unwrap();
                if let Some(cur) = &st.current_generation
                    && let Some(rec) = gs.get(cur)
                {
                    retained.insert(rec.tree.clone());
                }
                retained
            };

            if expect_abort {
                let err = retained_for_policy(&status, &gens, &policy).unwrap_err();
                assert!(
                    matches!(err, Error::Integrity(_)),
                    "a pointer that fails to resolve aborts with integrity, got: {err}"
                );
                assert!(
                    err.to_string().contains("not in the generation inventory"),
                    "the abort names the unresolvable pointer, got: {err}"
                );
            } else {
                let expected = reference_retained(&history, &ref_current, &policy);
                assert_eq!(
                    policy_retained(&status, &gens),
                    expected,
                    "a healthy inventory must retain exactly the reference-model set"
                );
            }

            // REPAIR + RETRY: restore the healthy pointers (both the dangling
            // prior of scenario 2 and the None'd prior of scenario 3); the
            // retry must equal EXACTLY the pure reference-model retained set.
            if scenario >= 2 {
                let cur = gens
                    .get_mut(&GenerationId::parse(&last.id).unwrap())
                    .unwrap();
                cur.prior_generation = last
                    .prior
                    .as_ref()
                    .map(|p| GenerationId::parse(p).unwrap());
            }
            let repaired_status = RemoteStatus {
                current_generation: Some(GenerationId::parse(&last.id).unwrap()),
                ..RemoteStatus::default()
            };
            let expected = reference_retained(&history, last, &policy);
            assert_eq!(
                policy_retained(&repaired_status, &gens),
                expected,
                "after repair the retry must equal the reference-model set"
            );
        }
    }

    proptest! {
        // FIXED-SEED property (0x5EED_5EED, per house style): a random
        // history + policy with `protect_previous` on, plus ONE injected
        // failure on the protect_previous evidence: a corrupt / timestamp /
        // identity record (aborts the fail-closed inventory build, including
        // the CURRENT record's timestamp — `status()` does not parse
        // `created_at`, so the current record can abort the build itself), a
        // DANGLING prior pointer (the current record names a prior with no
        // record — aborts the map lookup), a listing that HIDES the current
        // dir (the current id missing from the inventory — aborts the map
        // lookup), and a SECOND-READ failure (a remote that fails any
        // `assignment.json` read beyond the legitimate status/build reads —
        // the code NEVER performs it, so the outcome is governed by the ONE
        // inventory and the injected failure never fires). Every abort is
        // FAIL-CLOSED: `compute_retained` errors, the retention-debt
        // machinery records the durable marker, and ZERO trees are deleted.
        // After REPAIR the retry's retained set is EXACTLY the reference-model
        // set and the mark-and-sweep deletes exactly the trees outside it.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn protect_previous_faults_abort_before_deletion_then_retry_matches_reference(
            n_gens in 2usize..=4,
            keep_distinct in 0u32..=2,
            keep_days in prop::sample::select(vec![0u64, 2, 4]),
            protect_deployments in 0u32..=2,
            fault in 0u8..=6,
            corrupt_idx in 0usize..=3,
        ) {
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let base = dir.path().join("remote");
            let plain =
                LocalTransport::new(&crate::testutil::fixture_env(), base.clone()).unwrap();
            let helper = RemoteHelper::new(&plain);

            // The generated history (same fixture shape as the reference
            // model: a chain, newest last, odd-day timestamps).
            let now = Timestamp::now();
            let mut history: Vec<TestGen> = Vec::new();
            for i in 0..n_gens {
                let offset_days = (2 * (n_gens - 1 - i) + 1) as i64;
                history.push(TestGen {
                    id: test_generation_id(&format!("g{i}")).as_str().to_string(),
                    deployment: test_deployment_id(&format!("d{i}")).as_str().to_string(),
                    tree: test_tree_digest(&format!("t{i}")).as_str().to_string(),
                    created_at: now - jiff::SignedDuration::from_hours(offset_days * 24),
                    prior: (i > 0).then(|| {
                        test_generation_id(&format!("g{}", i - 1)).as_str().to_string()
                    }),
                    release: test_release_id("r").as_str().to_string(),
                    variant: "standard".to_string(),
                });
            }
            let mut assignments: Vec<GenerationAssignment> = Vec::new();
            for g in &history {
                helper
                    .remote()
                    .create_dir_all(&layout::tree_root(&g.tree))
                    .unwrap();
                let asn = GenerationAssignment {
                    deployment_id: DeploymentId::parse(&g.deployment).unwrap(),
                    generation_id: GenerationId::parse(&g.id).unwrap(),
                    artifact: ArtifactRef {
                        release: test_release_id("r"),
                        variant: VariantName::new("standard"),
                        tree: TreeDigest::parse(&g.tree).unwrap(),
                    },
                    behavior_sha256: "b".into(),
                    prior_generation: g.prior.as_ref().map(|p| GenerationId::parse(p).unwrap()),
                    created_at: g.created_at.to_string(),
                    target: None,
                };
                helper.create_generation("op", &asn).unwrap();
                assignments.push(asn);
            }
            let current = history.last().unwrap().clone();
            helper
                .swap_current(
                    &crate::remote::helper::ExpectedCurrent::Absent,
                    current.id.as_str(),
                    "op",
                )
                .unwrap();
            helper
                .remote()
                .create_dir_all(&layout::tree_root(test_tree_digest("garbage").as_str()))
                .unwrap();

            let store = LocalStore::with_base(dir.path().join("store")).unwrap();
            let policy = RetentionConfig {
                per_server: PerServerRetention {
                    keep_distinct_artifacts: keep_distinct,
                    keep_days,
                    protect_previous: true,
                },
                deployment: DeploymentRetention {
                    protect_deployments,
                },
            };
            let expected = reference_retained(&history, &current, &policy);

            // Healthy sanity: the happy path's retained set is EXACTLY the
            // reference model (the prior is protected through the ONE
            // inventory — no second read).
            assert_eq!(
                compute_retained(&helper, &[], &store, &policy).unwrap(),
                expected,
                "the healthy retained set must match the reference model"
            );

            helper.write_inventory().unwrap();
            let inv_path = dir.path().join("remote").join(layout::inventory());
            let inventory_before = std::fs::read(&inv_path).unwrap();

            let current_id = current.id.clone();
            let prior_id = current.prior.clone().unwrap();
            let corrupt_idx = corrupt_idx % (n_gens - 1);

            // Inject the fault. `wrapper` carries a remote whose transport
            // behavior deviates from the plain helper; `abort_marker` names
            // the exact abort step (None for the second-read fault, which
            // must NEVER fire because the second path is gone).
            let mut wrapper: Option<ProtectPreviousRemote> = None;
            let mut abort_marker: Option<&str> = Some("parse assignment");
            match fault {
                0 => {
                    let p = layout::generation(&history[corrupt_idx].id).join("assignment.json");
                    std::fs::write(dir.path().join("remote").join(p), b"{ corrupt !").unwrap();
                }
                1 => {
                    let mut a = assignments[corrupt_idx].clone();
                    a.created_at = "not-a-timestamp".into();
                    let p = layout::generation(&history[corrupt_idx].id).join("assignment.json");
                    std::fs::write(
                        dir.path().join("remote").join(p),
                        serde_json::to_vec_pretty(&a).unwrap(),
                    )
                    .unwrap();
                    abort_marker = Some("unparseable created_at");
                }
                2 => {
                    let mut a = assignments[corrupt_idx].clone();
                    a.generation_id = test_generation_id("tampered");
                    let p = layout::generation(&history[corrupt_idx].id).join("assignment.json");
                    std::fs::write(
                        dir.path().join("remote").join(p),
                        serde_json::to_vec_pretty(&a).unwrap(),
                    )
                    .unwrap();
                    abort_marker = Some("assignment names generation");
                }
                3 => {
                    // The CURRENT record's timestamp: `status()` does not
                    // parse `created_at`, so the chain validates while the
                    // inventory build aborts — the current dir was listed but
                    // its record failed the build.
                    let mut a = assignments[n_gens - 1].clone();
                    a.created_at = "not-a-timestamp".into();
                    let p = layout::generation(&current_id).join("assignment.json");
                    std::fs::write(
                        dir.path().join("remote").join(p),
                        serde_json::to_vec_pretty(&a).unwrap(),
                    )
                    .unwrap();
                    abort_marker = Some("unparseable created_at");
                }
                4 => {
                    // A DANGLING prior: the current record names a prior with
                    // no record on the remote. The chain validates (status()
                    // never consults the prior pointer), the inventory build
                    // loads the current record, and the map lookup for the
                    // prior ABORTS.
                    let mut a = assignments[n_gens - 1].clone();
                    a.prior_generation = Some(test_generation_id("absent-pri"));
                    let p = layout::generation(&current_id).join("assignment.json");
                    std::fs::write(
                        dir.path().join("remote").join(p),
                        serde_json::to_vec_pretty(&a).unwrap(),
                    )
                    .unwrap();
                    abort_marker = Some("not in the generation inventory");
                }
                5 => {
                    // SECOND-READ failure: a remote that fails any read of the
                    // current/prior assignment beyond its legitimate count (the
                    // current assignment is read once by `status()` and once by
                    // the inventory build; the prior once by the build). The
                    // removed second path would be an extra read — it must
                    // NEVER happen, so the injected fault never fires and the
                    // outcome is governed by the ONE inventory.
                    wrapper = Some(ProtectPreviousRemote::new(
                        base.clone(),
                        vec![current_id.clone(), prior_id.clone()],
                        &[(&current_id, 2), (&prior_id, 1)],
                        Vec::new(),
                    ));
                    abort_marker = None;
                }
                _ => {
                    // ABSENT CURRENT: a listing/transport inconsistency hides
                    // the live current dir from the `generations/` listing, so
                    // `status()` (which validates the chain directly) passes
                    // while the inventory lacks the current id — the map
                    // lookup ABORTS.
                    wrapper = Some(ProtectPreviousRemote::new(
                        base.clone(),
                        vec![current_id.clone()],
                        &[(&current_id, 2)],
                        vec![current_id.clone()],
                    ));
                    abort_marker = Some("not in the generation inventory");
                }
            }

            // Run the retention through the injected remote (or the plain
            // helper when the fault mutated the remote's files instead).
            let (abort, retained) = match &wrapper {
                Some(w) => {
                    let fh = RemoteHelper::new(w);
                    match compute_retained(&fh, &[], &store, &policy) {
                        Ok(r) => (None, Some(r)),
                        Err(e) => (Some(e.to_string()), None),
                    }
                }
                None => match compute_retained(&helper, &[], &store, &policy) {
                    Ok(r) => (None, Some(r)),
                    Err(e) => (Some(e.to_string()), None),
                },
            };

            match (&abort_marker, &abort) {
                // The second-read fault never fires: the retained set is
                // EXACTLY the reference model (the prior protected from the
                // inventory), and each tracked assignment was read EXACTLY its
                // legitimate count — the second path is structurally gone.
                (None, None) => {
                    let w = wrapper.as_ref().unwrap();
                    assert_eq!(
                        retained.as_ref().unwrap(),
                        &expected,
                        "the outcome must be governed by the ONE inventory, never a second read"
                    );
                    assert_eq!(
                        w.read_count(&current_id),
                        2,
                        "the current assignment is read once by status() and once by the build — never again"
                    );
                    assert_eq!(
                        w.read_count(&prior_id),
                        1,
                        "the prior assignment is read once by the build — protect_previous must not re-read it"
                    );
                }
                // Every other fault ABORTS at the injected step.
                (Some(marker), Some(err)) => {
                    assert!(
                        err.contains(marker),
                        "the {fault}-fault must abort at the injected step, got: {err}"
                    );
                }
                (Some(marker), None) => panic!(
                    "the {fault}-fault ({marker}) must abort retention, but it succeeded"
                ),
                (None, Some(err)) => panic!(
                    "the second-read fault must never fire (the second path is gone), got: {err}"
                ),
            }

            // ZERO DELETIONS on every abort: the receiver inventory is
            // byte-identical and every tree — every history tree AND the
            // garbage — survives.
            if abort.is_some() {
                assert_eq!(
                    std::fs::read(&inv_path).unwrap(),
                    inventory_before,
                    "the failed retention must not delete a single tree object"
                );
                for g in &history {
                    assert!(
                        helper.remote().exists(&layout::tree_root(&g.tree)),
                        "history tree {} must survive the failed retention",
                        g.tree
                    );
                }
                assert!(
                    helper.remote().exists(&layout::tree_root(
                        test_tree_digest("garbage").as_str()
                    )),
                    "the garbage tree must survive the failed retention"
                );

                // ROTATION DEBT: the engine's post-commit conversion records
                // the durable marker; the retry services it once the fault is
                // repaired.
                let slot = SlotId::new("p1".to_string());
                let err_text = abort.as_ref().unwrap();
                let warnings = set_retention_deferred(&store, "t1", &slot, err_text);
                assert!(warnings.is_empty(), "the marker write must succeed: {warnings:?}");
                let debt = store.read_retention_debt("t1").unwrap();
                assert_eq!(
                    debt.get("p1").map(|s| s.as_str()),
                    Some(err_text.as_str()),
                    "the debt marker records the abort reason for the next push"
                );
            }

            // REPAIR: restore the corrupted record / the healthy prior
            // pointer (the wrapper faults prove the second path is gone and
            // leave no durable damage).
            match fault {
                0..=2 => {
                    let asn = &assignments[corrupt_idx];
                    let p = layout::generation(asn.generation_id.as_str()).join("assignment.json");
                    helper
                        .remote()
                        .write(&p, &serde_json::to_vec_pretty(asn).unwrap(), 0o644)
                        .unwrap();
                }
                3 | 4 => {
                    let asn = &assignments[n_gens - 1];
                    let p = layout::generation(asn.generation_id.as_str()).join("assignment.json");
                    helper
                        .remote()
                        .write(&p, &serde_json::to_vec_pretty(asn).unwrap(), 0o644)
                        .unwrap();
                }
                _ => {}
            }

            // RETRY: the retained set is EXACTLY the reference-model set, and
            // the mark-and-sweep deletes exactly the trees outside it.
            let retained = compute_retained(&helper, &[], &store, &policy).unwrap();
            assert_eq!(
                retained, expected,
                "the retried retention must retain exactly the reference-model set"
            );
            helper.rotate(&retained, &HashSet::new()).unwrap();
            for g in &history {
                assert_eq!(
                    helper.remote().exists(&layout::tree_root(&g.tree)),
                    expected.contains(&g.tree),
                    "history tree {} must survive iff the reference model retains it",
                    g.tree
                );
            }
            assert!(
                !helper.remote().exists(&layout::tree_root(
                    test_tree_digest("garbage").as_str()
                )),
                "the garbage tree is removed by the retry"
            );

            // The retried retention services the marker.
            if abort.is_some() {
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
}
