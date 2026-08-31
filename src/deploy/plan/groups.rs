//! The direct-release membership gate:
//! [`validate_direct_release_membership`] rejects a `release:<id>` push
//! whose direct-release membership drifted from the current config.

use crate::error::Error;
use crate::error::Result;
use crate::identity::MatchingMembership;
use crate::identity::ReleaseId;
use crate::identity::SlotId;
use crate::identity::SlotSet;

// DIRECT-RELEASE MEMBERSHIP GATE (A1 deployment semantics): a `release:<id>`
// push deploys onto the CURRENT target's slots, so the release's frozen
// slot set must EXACTLY equal the target's current membership — refused
// before any lock or remote access. The {target, group} selection and the
// frozen-vs-current topology resolution live in the selection section above.

/// DIRECT-RELEASE MEMBERSHIP VALIDATION (before any remote access): a
/// `release:<id>` push deploys onto the CURRENT target's slots, so the
/// release's OWN canonical slot snapshot must freeze EXACTLY the slot-id set
/// the target currently has.
///
/// The expected set is the union over every variant in the record's snapshot
/// of the slots whose ONE owning `target` equals the destination target
/// (each slot has exactly one target, so the union is deduplicated by slot
/// id; the membership is a set). The comparison is LOGICAL membership only:
/// physical bindings (server / deploy_dir) are intentionally allowed to
/// differ — unlike the exact-rollback `Snapshot` branch, which also demands
/// identical physical bindings. A target whose membership DRIFTED since the
/// release was built — a slot added, removed, or renamed — is refused, before
/// any assignment is built and before any remote access, rather than
/// deploying to the wrong slot set.
///
/// Runs at TWO sites: the engine's early gate in `push()` — immediately
/// after the ref is parsed/resolved, BEFORE any lock and BEFORE the remote
/// factory is invoked, in both real and dry-run modes — and here, in the
/// `PushRef::Release` plan branch (the second line of defense protecting the
/// direct-`push_inner` test entry points). `current_slot_ids` is the target's
/// CURRENT member slot-id set, derived from the caller's config exactly as
/// [`plan_assignments`] derives it (`config.target_slots`, in deterministic
/// order), so both gates compare the SAME sets.
///
/// BOTH call sites pass the target's COMPLETE current member-slot set —
/// EVERY slot whose owning `target` equals the target — never a
/// group-filtered selection: a `release:<id> --group <g>` push validates
/// the FULL membership here and then plans ONLY the selected slots (the
/// group narrows the planned assignments, never the membership gate). A
/// `--group` push selecting a proper subset would otherwise compare the
/// release's full frozen set against the subset and fail for every proper
/// group.
pub(crate) fn validate_direct_release_membership(
    target_name: &str,
    release: &ReleaseId,
    vr: &crate::verify::release::ValidatedRelease,
    current_slot_ids: &[SlotId],
) -> Result<MatchingMembership> {
    let frozen: SlotSet = SlotSet::new(
        vr.slots()
            .values()
            .flat_map(|slots| slots.iter())
            .filter(|s| s.target().as_str() == target_name)
            .map(|s| s.id().clone()),
    );
    let current: SlotSet = SlotSet::new(current_slot_ids.iter().cloned());
    MatchingMembership::verify(frozen.clone(), current.clone()).map_err(|_| {
        let expected: Vec<String> = frozen.iter().map(|s| s.as_str().to_string()).collect();
        let current_list: Vec<String> = current.iter().map(|s| s.as_str().to_string()).collect();
        Error::rollback(format!(
            "release {release} targets slots [{}] but target '{target_name}' currently has [{}]; direct release membership drift is rejected before remote access",
            expected.join(", "),
            current_list.join(", "),
        ))
    })
}

#[cfg(test)]
mod groups_tests {
    use crate::config::ProjectConfig;
    use crate::deploy::plan::SlotSelection;
    use crate::deploy::plan::plan_assignments;
    use crate::deploy::plan::*;
    use crate::identity::{
        BehaviorContract, CanonicalSlot, CanonicalSlots, Provenance, ReleaseRecord, SlotId,
        test_tree_digest,
    };
    use crate::ledger::{PlanOrigin, PushRef, VerifiedReleaseRebinding};
    use crate::store::local::LocalStore;
    use crate::verify::release::RELEASE_RECORD_SCHEMA_VERSION;
    #[cfg(test)]
    use proptest::prelude::*;
    #[cfg(test)]
    use proptest::test_runner::RngSeed;
    use std::collections::{BTreeMap, BTreeSet};

    /// A release record in the pre-snapshot SHAPE: an EMPTY `slots` map (the
    /// shape written before the slots-into-identity refactor, and what
    /// `#[serde(default)]` yields for records without a `slots` member). The
    /// store now REJECTS empty slot snapshots at write and read (an empty
    /// snapshot cannot be verified from content), so fixtures that need a
    /// WRITABLE record must fill `slots` and recompute the identity with
    /// [`consistent`]. The bare empty-snapshot record is used directly only
    /// when a test needs the on-disk legacy shape. It still carries the
    /// per-variant tree bindings.
    fn legacy_record(id: &str, tree: &str) -> ReleaseRecord {
        ReleaseRecord {
            release_schema_version: RELEASE_RECORD_SCHEMA_VERSION,
            release_id: id.to_string(),
            release_sha256: format!("sha256-{id}"),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            provenance: Provenance {
                mapping_sha256: "m".to_string(),
                behavior_sha256: "b".to_string(),
            },
            // The variant tree must be a VALID digest (the record is read
            // back through the validated parse), so derive the canonical
            // 64-hex form of the tag.
            variants: BTreeMap::from([(
                "standard".to_string(),
                test_tree_digest(tree).as_str().to_string(),
            )]),
            slots: BTreeMap::new(),
        }
    }

    /// Recompute a release record's stored identity from its own content so
    /// `read_release`'s recompute-and-verify passes: the digest is derived
    /// from the record's slot snapshot, bindings, and provenance digests
    /// exactly as `build_release` derives it. Returns the record's release id
    /// (the digest form, which is also the store directory key).
    fn consistent(rec: &mut ReleaseRecord) -> ReleaseId {
        let digest = crate::verify::release::recompute_release_digest(rec)
            .expect("consistent record must carry a slot snapshot");
        rec.release_sha256 = digest.as_str().to_string();
        rec.release_id = crate::identity::ReleaseId::from_digest(&digest)
            .as_str()
            .to_string();
        crate::identity::ReleaseId::parse(&rec.release_id)
            .expect("consistent record carries a validated release id")
    }

    /// Seed a release record + its identity-verified behavior snapshot: the
    /// record's provenance `behavior_sha256` is set to the canonical digest of
    /// a per-variant contract set covering EXACTLY the record's variants, and
    /// the `behavior.json` aux file carries that same set, so the plan's
    /// [`crate::verify::release::ValidatedRelease`] construction (which reads
    /// and verifies the behavior snapshot) succeeds. Returns the release id.
    fn seed_release(store: &LocalStore, rec: &mut ReleaseRecord) -> ReleaseId {
        let behaviors: BTreeMap<String, BehaviorContract> = rec
            .variants
            .keys()
            .map(|v| {
                (
                    v.clone(),
                    BehaviorContract::new(
                        crate::config::Activation::None,
                        crate::config::Verification::Command(
                            crate::config::ValidatedCommand::new(vec!["true".to_string()], 5, 1, 0)
                                .expect("validated command"),
                        ),
                    ),
                )
            })
            .collect();
        rec.provenance.behavior_sha256 =
            crate::verify::release::variant_behaviors_digest(&behaviors);
        let rid = consistent(rec);
        store.write_release(rec).unwrap();
        store
            .write_release_aux(&rid, "mapping", &serde_json::to_value(&behaviors).unwrap())
            .unwrap();
        rid
    }

    /// Assert the planned origin is a Release origin naming the given
    /// release and carrying the VERIFIED rebinding proof; returns the proof
    /// (the caller then asserts its frozen topology / membership / physical
    /// slots). A Release origin without its proof is unrepresentable, so
    /// this single assertion covers both the release identity and the
    /// proof's presence.
    fn release_origin<'a>(
        origin: &'a PlanOrigin,
        release: &ReleaseId,
    ) -> &'a VerifiedReleaseRebinding {
        match origin {
            PlanOrigin::Release {
                release: r,
                rebinding,
            } => {
                assert_eq!(
                    r, release,
                    "the release origin must name the planned release"
                );
                rebinding
            }
            other => panic!("expected a Release origin for {release}, got {other:?}"),
        }
    }

    // The slot universe + fixed members the membership property draws from:
    // `p1`/`p2`/`p3` are the generated COMMON members (declared for BOTH
    // targets), `iso` is a `t2`-ONLY member (cross-target isolation: it must
    // never leak into t1's derived membership), and `phys` is a constant
    // member whose PHYSICAL binding (server) the fixture may drift while its
    // id stays (logical-only comparison). Each slot owns a distinct server so
    // the config's per-target server-uniqueness validation passes for every
    // generated membership.
    const SLOT_UNIVERSE: [&str; 3] = ["p1", "p2", "p3"];

    /// Build the membership-drift property fixture from two generated
    /// membership sets: `release_inc[i]` says whether universe slot `i` is
    /// frozen in the release record's OWN canonical slot snapshot (targets
    /// `t1`+`t2`); `current_inc[i]` says whether it is declared in the
    /// CURRENT config for both targets. `iso` (t2-only) and `phys`
    /// (t1+t2) are constant members of BOTH the record and the config;
    /// `physical_drift` rebinds `phys` to a different server in the config
    /// only (its id stays — logical membership unchanged). Returns the
    /// fixture plus the written record (so the test can cross-check the
    /// realized physical drift against the canonical binding).
    fn membership_drift_fixture(
        release_inc: [bool; 3],
        current_inc: [bool; 3],
        physical_drift: bool,
    ) -> (
        tempfile::TempDir,
        ProjectConfig,
        LocalStore,
        ReleaseId,
        ReleaseRecord,
    ) {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();

        // Current variant file: one slot entry per generated current member,
        // plus the constant `iso` (t2-only) and `phys` (rebound when
        // `physical_drift`).
        let mut variant = String::new();
        let add_slot = |variant: &mut String, id: &str, server: &str, target: &str, dir: &str| {
            variant.push_str(&format!(
                "[[slots]]\nid = \"{id}\"\nserver = \"{server}\"\ntarget = \"{target}\"\ndeploy_dir = \"{dir}\"\n\n"
            ));
        };
        for (i, inc) in current_inc.iter().enumerate() {
            if *inc {
                let id = SLOT_UNIVERSE[i];
                add_slot(
                    &mut variant,
                    id,
                    &format!("s{}", i + 1),
                    "t1",
                    &format!("/srv/{id}"),
                );
            }
        }
        add_slot(&mut variant, "iso", "s4", "t2", "/srv/iso");
        add_slot(
            &mut variant,
            "phys",
            if physical_drift { "s6" } else { "s5" },
            "t1",
            "/srv/phys",
        );
        variant.push_str(
            "[[artifact.mappings]]\nfrom = \"artifacts/build/output/\"\nto = \"app/\"\nrecursive = true\n\n[retention.per_server]\nkeep_distinct_artifacts = 1\nkeep_days = 0\nprotect_previous = true\n\n[retention.deployment]\nprotect_deployments = 1\n\n[activation]\nadapter = \"none\"\n\n[verification]\nadapter = \"command\"\nargv = [\"true\"]\ntimeout_seconds = 5\nattempts = 1\ninterval_seconds = 0\n",
        );
        std::fs::write(release_dir.join("standard.toml"), variant).unwrap();

        let mut servers = String::new();
        for i in 1..=6 {
            servers.push_str(&format!(
                "[[servers]]\nid = \"s{i}\"\naddress = \"a{i}\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n"
            ));
        }
        let cfg_path = project.join("deploy.toml");
        std::fs::write(
            &cfg_path,
            format!(
                "schema_version = 2\napplication = \"plan\"\nrelease = \"v1\"\n\n\
                 {servers}\
                 [targets.t1]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n\n\
                 [targets.t2]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n"
            ),
        )
        .unwrap();
        let config = ProjectConfig::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();

        // The release's OWN frozen canonical snapshot: the generated
        // membership (slots owning t1 or t2) plus the constant phys (owns
        // t1, at its ORIGINAL server s5) and iso (owns t2), exactly
        // mirroring the current config's owning-target assignments.
        let mut rec = legacy_record("unused", "tree-x");
        let mut canonical: Vec<CanonicalSlot> = Vec::new();
        for (i, id) in SLOT_UNIVERSE.iter().enumerate() {
            if release_inc[i] {
                canonical.push(CanonicalSlot {
                    id: id.to_string(),
                    server: format!("s{}", i + 1),
                    deploy_dir: format!("/srv/{id}"),
                    target: "t1".to_string(),
                    groups: Vec::new(),
                });
            }
        }
        canonical.push(CanonicalSlot {
            id: "phys".to_string(),
            server: "s5".to_string(),
            deploy_dir: "/srv/phys".to_string(),
            target: "t1".to_string(),
            groups: Vec::new(),
        });
        canonical.push(CanonicalSlot {
            id: "iso".to_string(),
            server: "s4".to_string(),
            deploy_dir: "/srv/iso".to_string(),
            target: "t2".to_string(),
            groups: Vec::new(),
        });
        canonical.sort_by(|a, b| a.id.cmp(&b.id));
        rec.slots = BTreeMap::from([("standard".to_string(), CanonicalSlots { slots: canonical })]);
        let release = seed_release(&store, &mut rec);

        (dir, config, store, release, rec)
    }

    // THE REQUIRED DIRECT-RELEASE MEMBERSHIP PROPERTY: for generated
    // release-versioned and current membership sets, direct release planning
    // onto the destination target SUCCEEDS iff the two slot-ID sets match
    // EXACTLY (logical equality) and REFUSES with the membership-drift error
    // otherwise — the drift refusal lands at PLAN time, before any remote
    // access. Also: cross-target isolation (t2's extra `iso` member never
    // disturbs t1's derived membership) and logical-only comparison (phys's
    // SERVER rebind with an unchanged id still plans).
    proptest! {
        #![proptest_config(ProptestConfig {
            // Bounded + fixed seed: deterministic floor, fast.
            cases: crate::testutil::proptest_cases(4),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn direct_release_membership_must_match_release_record(
            release_inc in prop::array::uniform3(prop::bool::ANY),
            current_inc in prop::array::uniform3(prop::bool::ANY),
            physical_drift in prop::bool::ANY,
        ) {
            let (_dir, config, store, release, rec) =
                membership_drift_fixture(release_inc, current_inc, physical_drift);
            let release_ref = PushRef::Release {
                release: release.clone()};
            let expected: BTreeSet<String> = SLOT_UNIVERSE
                .iter()
                .enumerate()
                .filter(|(i, _)| release_inc[*i])
                .map(|(_, id)| id.to_string())
                .collect();
            let current: BTreeSet<String> = SLOT_UNIVERSE
                .iter()
                .enumerate()
                .filter(|(i, _)| current_inc[*i])
                .map(|(_, id)| id.to_string())
                .collect();

            if expected == current {
                // Membership match: the direct release plans on BOTH targets.
                // Cross-target isolation: t2's extra `iso` member (frozen in
                // the record AND declared in the config) must not disturb
                // t1's derived membership — t1 plans exactly its own set.
                for dest in ["t1", "t2"] {
                    let (assignments, desired, origin) = plan_assignments(
                        &SlotSelection::normalize(&config, dest, None).unwrap(),
                        &release_ref,
                        &crate::identity::test_release_id("unused-local"),
                        &BTreeMap::new(),
                        &store,
                        &config,
                        &BTreeMap::new(),

                    )
                        .map(|planned| (planned.assignments, planned.releases, planned.origin))
                    .unwrap_or_else(|e| {
                        panic!("release:<id> must plan on target {dest} when the membership matches: {e}")
                    });
                    // The universe slots and `phys` are t1's; `iso` is
                    // t2's (a slot has exactly one owning target).
                    let mut want: Vec<String> = if dest == "t1" {
                        let mut w: Vec<String> = expected.iter().cloned().collect();
                        w.push("phys".to_string());
                        w
                    } else {
                        vec!["iso".to_string()]
                    };
                    want.sort();
                    let mut got: Vec<String> = assignments
                        .iter()
                        .map(|a| a.placement_slot.as_str().to_string())
                        .collect();
                    got.sort();
                    assert_eq!(
                        got, want,
                        "target {dest} must plan exactly its frozen membership"
                    );
                    for a in &assignments {
                        assert_eq!(a.artifact.variant.as_str(), "standard");
                        assert_eq!(a.artifact.release, release);
                    }
                    assert_eq!(desired, BTreeSet::from([release.clone()]));
                    release_origin(&origin, &release);
                }
                // LOGICAL-ONLY: when the fixture realized a physical binding
                // change (phys's server rebound), planning still succeeded
                // above — the membership check compares slot IDs only, never
                // server or deploy_dir. Cross-check the fixture actually
                // drifted (config server differs from the record's frozen
                // canonical binding) so the assertion is meaningful.
                if physical_drift {
                    let rec_phys = rec
                        .slots["standard"]
                        .slots
                        .iter()
                        .find(|s| s.id == "phys")
                        .expect("phys is frozen in the record");
                    let bindings = config.target_slot_bindings("t1").unwrap();
                    let cfg_phys = bindings
                        .get(&SlotId::new("phys"))
                        .expect("phys is a member of t1");
                    assert_ne!(
                        cfg_phys.server().as_str(),
                        rec_phys.server,
                        "the fixture must realize the physical drift: config server {} vs record server {}",
                        cfg_phys.server(),
                        rec_phys.server
                    );
                    assert_eq!(
                        cfg_phys.deploy_dir(), rec_phys.deploy_dir,
                        "only the server drifted; deploy_dir stays put"
                    );
                }
            } else {
                // Membership drift (missing / extra / renamed slots): REFUSED
                // at plan time on the DRIFTED target (`t1` — the universe
                // slots are t1's), with the drift error naming the release,
                // the expected vs current slot sets, and the
                // before-remote-access clause. `t2`'s membership is
                // unchanged ({iso} in both the record and the config), so it
                // still plans — a slot has exactly one owning target, so a
                // drift on t1 never disturbs t2.
                let err = plan_assignments(
                    &SlotSelection::normalize(&config, "t1", None).unwrap(),
                    &release_ref,
                    &crate::identity::test_release_id("unused-local"),
                    &BTreeMap::new(),
                    &store,
                    &config,
                    &BTreeMap::new(),

                )
                .expect_err("membership drift must refuse direct release planning");
                let msg = err.to_string();
                assert!(
                    msg.contains("release")
                        && msg.contains("drift")
                        && msg.contains("before remote access"),
                    "refusal must be the membership-drift error, got: {msg}"
                );
                // t2's membership is unchanged: it plans its own slot.
                let (assignments, _, _) = plan_assignments(
                    &SlotSelection::normalize(&config, "t2", None).unwrap(),
                    &release_ref,
                    &crate::identity::test_release_id("unused-local"),
                    &BTreeMap::new(),
                    &store,
                    &config,
                    &BTreeMap::new(),

                )
                    .map(|planned| (planned.assignments, planned.releases, planned.origin))
                .expect("t2's membership is unchanged, so it still plans");
                assert_eq!(assignments.len(), 1);
                assert_eq!(assignments[0].placement_slot, SlotId::new("iso"));
            }
        }
    }
}
