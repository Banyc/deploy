//! The two-sided sweep contract: receiver = retention, pusher = checkpoint.
//!
//! The Constitution's "No disk usage leak" rule is served by TWO sweep
//! mechanisms, one per side of the push:
//!
//! * RECEIVER side (every server's deployment root): swept by ROTATION. The
//!   slot's single owning-variant retention policy computes the retained
//!   digest set ([`crate::retention::compute_retained`]); the mark-and-sweep
//!   pass ([`crate::remote::helper::RemoteHelper::rotate`]) deletes every
//!   tree object NOT in the retained set and every abandoned incoming
//!   directory. Generation/release/commit metadata is small and kept by
//!   design; the disk usage — the tree content — is reclaimed.
//! * PUSHER side (the local store): swept by CHECKPOINT. The checkpoint
//!   atomically replaces the target's ONE ledger with the retained suffix
//!   (the only logical commit) and then runs the GLOBAL reachability sweep
//!   ([`crate::retention::history_floor::LocalStore::run_sweep`]): unreachable
//!   deployment directories, release records, and tree objects are unlinked;
//!   everything reachable from a retained ledger, the current/incomplete
//!   state, or a pin survives.
//!
//! BOTH sweeps are POST-COMMIT MAINTENANCE, never corrections: a sweep
//! failure (or a sweep that has not run) never blocks or rolls back the
//! operation that triggered it and never reports an ordinary failure — it
//! records DURABLE DEBT and the NEXT PUSH (real or no-op) fires the pending
//! sweep. The receiver's retention debt is `targets/<target>/retention-debt.json`
//! (serviced by [`crate::deploy::retry_deferred_retentions`]); the
//! pusher's sweep debt is `<base>/sweep-debt.json` (serviced by
//! [`crate::deploy::retry_pending_sweep`]). Both reports surface a
//! pending sweep as a WARNING, never an error.
//!
//! The property tests below assert the no-leak contract on both sides, the
//! independence of the two sides, and the maintenance-not-correction
//! discipline (faulted sweeps still succeed, debt is recorded, and the next
//! push converges).

use crate::config::ProjectConfig;
use crate::deploy::{PushOptions, push, retry_pending_sweep};
use crate::error::Result;
use crate::identity::{
    ArtifactRef, DeploymentId, PlacementSlotAssignment, ReleaseId, ServerId, SlotId, TargetName,
    TreeDigest, VariantName, test_deployment_id, test_generation_id, test_tree_digest,
};
use crate::ledger::{
    DeploymentIntent, DeploymentStatus, DesiredGeneration, IntentSlot, LedgerRollback,
    LedgerTerminal, NonEmptySlotTable, ObservationWire, ObservedGenerationWire, SlotOutcome,
    SlotOutcomeKind, SlotResult, SlotTable, TerminalDisposition,
};
use crate::remote::helper::{GenerationAssignment, RemoteHelper};
use crate::remote::layout;
use crate::remote::transport::{LocalTransport, Remote};
use crate::retention::checkpoint::run_checkpoint_unlocked;
use crate::retention::compute_retained;
use crate::store::local::LocalStore;
use crate::testutil::test_faults::FaultKind;
use crate::testutil::test_remotes::FailOnceInventoryRemote;
use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

const TARGET: &str = "t1";

/// A minimal but VALID variant file (the config loader requires a real
/// variant: mappings, activation, verification, and the slot's ONE retention
/// policy).
const VARIANT_TOML: &str = r#"
[artifact]
mappings = []

[[slots]]
id = "p1"
server = "s1"
target = "t1"
groups = []
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

/// The project file for the sweep fixtures: one server, one target, and —
/// when `pinned` is given — a durable `[[pins]]` entry protecting a release.
fn config_for(dir: &tempfile::TempDir, pinned: Option<&ReleaseId>) -> ProjectConfig {
    let project = dir.path().join("proj");
    std::fs::create_dir_all(project.join("releases").join("v1")).unwrap();
    std::fs::write(
        project.join("releases").join("v1").join("standard.toml"),
        VARIANT_TOML,
    )
    .unwrap();
    let mut deploy = format!(
        "schema_version = 2\napplication = \"sw\"\nrelease = \"v1\"\n\n\
         [[servers]]\nid = \"s1\"\naddress = \"a\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n\
         [targets.{TARGET}]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n"
    );
    if let Some(p) = pinned {
        deploy.push_str(&format!(
            "\n[[pins]]\nrelease = \"{p}\"\nreason = \"keep\"\n"
        ));
    }
    std::fs::write(project.join("deploy.toml"), deploy).unwrap();
    ProjectConfig::load(&project.join("deploy.toml")).unwrap()
}

/// Write a REAL release record (content-derived id) with one variant tree
/// `tree-pinned`, and return its id — the pin must reference the id the
/// record actually got.
fn seed_real_release(store: &LocalStore) -> ReleaseId {
    let rec = crate::verify::release::build_release(
        "sw",
        "sha256-aa",
        &BTreeMap::from([(
            VariantName::new("standard".to_string()),
            test_tree_digest("tree-pinned"),
        )]),
        &BTreeMap::from([(
            "standard".to_string(),
            vec![crate::config::SlotConfig::new(
                "p1".to_string(),
                "s1".to_string(),
                PathBuf::from("/srv/deploy/p1"),
                TARGET.to_string(),
                vec![],
            )],
        )]),
        std::path::Path::new("."),
    );
    let id = ReleaseId::new(rec.release_id.clone());
    store.write_release(&rec).unwrap();
    id
}

// ---- receiver (retention) fixture helpers -----------------------------------

/// Create one generation record (tree + assignment) on the receiver without
/// touching `current`. The tree object must exist for `status()` to follow
/// the `current` symlink chain.
fn make_gen(
    helper: &RemoteHelper,
    deployment_id: &str,
    generation_id: &str,
    tree: &str,
    created: &str,
    prior_generation: Option<&str>,
) {
    // The receiver's generation records are read back through the validated
    // parse, so the fixture writes the CANONICAL forms of its tags. `tree`
    // is already a canonical digest (the strategy generates canonical forms).
    let canonical_tree = TreeDigest::parse(tree).expect("canonical tree");
    helper
        .remote()
        .create_dir_all(&layout::tree_root(canonical_tree.as_str()))
        .unwrap();
    helper
        .create_generation(
            "op",
            &GenerationAssignment {
                deployment_id: test_deployment_id(deployment_id),
                generation_id: test_generation_id(generation_id),
                artifact: ArtifactRef {
                    release: crate::identity::test_release_id("r"),
                    variant: VariantName::new("standard".to_string()),
                    tree: canonical_tree,
                },
                behavior_sha256: "b".into(),
                prior_generation: prior_generation.map(test_generation_id),
                created_at: created.into(),
                target: None,
            },
        )
        .unwrap();
}

/// The receiver's generation record names, sorted (the independence
/// snapshot: a checkpoint must never change them).
fn list_generations(helper: &RemoteHelper) -> Vec<String> {
    let mut out = Vec::new();
    if helper.remote().exists(layout::generations()) {
        for e in helper.remote().list(layout::generations()).unwrap() {
            if e.is_dir {
                out.push(e.name);
            }
        }
    }
    out.sort();
    out
}

// ---- pusher (checkpoint) fixture helpers -----------------------------------

fn intent(id: &str, target: &str) -> DeploymentIntent {
    let p1 = SlotId::new("p1".to_string());
    // ONE slot table (the membership + desired/pre-push entries).
    let slots = BTreeMap::from([(
        p1.clone(),
        IntentSlot {
            desired: DesiredGeneration {
                generation: test_generation_id("gen-1"),
                artifact: ArtifactRef {
                    release: crate::identity::test_release_id("rel-1"),
                    variant: VariantName::new("standard".to_string()),
                    tree: test_tree_digest("tree-1"),
                },
            },
            pre_push: None,
            // The FROZEN plan-time physical binding (schema v6): the
            // fixture's single slot is bound to server s1 at /srv/deploy/p1.
            binding: crate::ledger::PhysicalBinding {
                server: ServerId::new("s1".to_string()),
                deploy_dir: "/srv/deploy/p1".to_string(),
            },
        },
    )]);
    DeploymentIntent {
        deployment_id: test_deployment_id(id),
        target: TargetName::new(target.to_string()),
        group: None,
        behavior_sha256: "sha256-aa".to_string(),
        attempted_at: "2026-01-01T00:00:00Z".to_string(),
        slots: NonEmptySlotTable::build(slots).expect("a fixture intent has at least one slot"),
        full_membership: BTreeSet::from([SlotId::new("p1".to_string())]),
    }
}

/// A SUCCESSFUL terminal whose rollback references `release` and `tree` —
/// the exact bindings the checkpoint's reachability scan keeps. The
/// EXACT-EQUAL shape: one Activated outcome per slotted generation (the
/// membership equations — outcomes == selected == full == rollback slots —
/// are enforced by the conversion).
fn terminal_for(release: &str, tree: &str) -> LedgerTerminal {
    LedgerTerminal {
        recorded_at: "2026-01-01T00:00:00Z".to_string(),
        // The EXACT-EQUAL shape: one Activated outcome per slotted
        // generation (the membership equations (outcomes == selected == full == rollback slots) are enforced by the conversion).
        disposition: TerminalDisposition::Successful {
            rollback: LedgerRollback {
                slots: BTreeMap::from([(
                    SlotId::new("p1".to_string()),
                    crate::identity::GenerationRef {
                        generation: test_generation_id("gen-1"),
                        assignment: PlacementSlotAssignment {
                            placement_slot: SlotId::new("p1".to_string()),
                            artifact: ArtifactRef {
                                release: ReleaseId::new(release.to_string()),
                                variant: VariantName::new("standard".to_string()),
                                tree: test_tree_digest(tree),
                            },
                        },
                    },
                )]),
                bindings: BTreeMap::from([(
                    SlotId::new("p1".to_string()),
                    crate::ledger::PhysicalBinding {
                        server: ServerId::new("s1".to_string()),
                        deploy_dir: "/srv/deploy/p1".to_string(),
                    },
                )]),
            },
            outcomes: SlotTable::from_map(BTreeMap::from([(
                SlotId::new("p1".to_string()),
                SlotOutcome::from_wire(SlotResult {
                    slot_id: SlotId::new("p1".to_string()),
                    outcome: SlotOutcomeKind::Activated,
                    observation: ObservationWire::Known(ObservedGenerationWire {
                        generation: test_generation_id("gen-1"),
                    }),
                    compensated: false,
                    error: None,
                })
                .unwrap(),
            )])),
            // THE EXACT-EQUAL MEMBERSHIPS: selected == full == the
            // one-slot membership (the rollback's slots / the outcomes'
            // keys) — the proven shape the conversion + read require.
            selected_membership: BTreeSet::from([SlotId::new("p1".to_string())]),
            full_membership: BTreeSet::from([SlotId::new("p1".to_string())]),
        },
        reason: None,
    }
}

fn failed_terminal() -> LedgerTerminal {
    LedgerTerminal {
        recorded_at: "2026-01-01T00:00:00Z".to_string(),
        // The FailedRolledBack compensation report IS the outcome table — it
        // must EXACTLY cover the membership (the status-specific outcome
        // rule).
        disposition: TerminalDisposition::FailedRolledBack {
            outcomes: SlotTable::from_map(BTreeMap::from([(
                SlotId::new("p1".to_string()),
                SlotOutcome::from_wire(SlotResult {
                    slot_id: SlotId::new("p1".to_string()),
                    outcome: SlotOutcomeKind::Restored,
                    observation: ObservationWire::Known(ObservedGenerationWire {
                        generation: test_generation_id("gen-1"),
                    }),
                    compensated: true,
                    error: None,
                })
                .unwrap(),
            )])),
        },
        reason: None,
    }
}

/// Seed a target's ledger with `history[i]`-shaped entries: `true` =
/// successful (intent + Successful terminal whose rollback references
/// `rel-sha256-<id>` / `tree-<id>`), `false` = failed (no rollback). Returns
/// the successful deployment ids in order.
fn seed_history(store: &LocalStore, target: &str, prefix: &str, history: &[bool]) -> Vec<String> {
    let mut successful = Vec::new();
    for (i, ok) in history.iter().enumerate() {
        let id = format!("{prefix}-{i}");
        let canonical = test_deployment_id(&id);
        store.append_intent(target, &intent(&id, target)).unwrap();
        if *ok {
            let rel = crate::identity::test_release_id(&id).as_str().to_string();
            let tree = format!("tree-{id}");
            store
                .append_terminal(target, &canonical, &terminal_for(&rel, &tree))
                .unwrap();
            successful.push(canonical.as_str().to_string());
        } else {
            store
                .append_terminal(target, &canonical, &failed_terminal())
                .unwrap();
        }
    }
    successful
}

/// Create a release directory under the given NAME (junk content) — the
/// sweep keeps or sweeps it by NAME (the reachability set carries the names
/// the ledgers reference).
fn seed_named_release(store: &LocalStore, name: &str) {
    let dir = store.release_dir(&ReleaseId::new(name.to_string()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("release.json"), "{}").unwrap();
}

/// Create a tree object directory under the given digest (the CANONICAL
/// 64-hex form of the tag — the ledger references the validated digest).
fn seed_object(store: &LocalStore, tree: &str) {
    let dir = store.object_root(&test_tree_digest(tree));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("file"), "x").unwrap();
}

/// Seed UNREACHABLE ghost content (a deployment dir + release record + tree
/// object referenced by nothing): the sweep must delete it.
fn seed_unreachable(store: &LocalStore, deployment: &str, release: &str, tree: &str) {
    let dir = store.deployment_dir(deployment);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("plan.json"), "{}").unwrap();
    seed_named_release(store, release);
    seed_object(store, tree);
}

// ---------------------------------------------------------------------------
// THE NO-LEAK CONTRACT (clean path): after a retention pass the receiver
// retains EXACTLY the policy-retained trees (stale ones gone, pins/retained
// content survive); after a checkpoint the pusher retains EXACTLY the
// reachable artifacts (unreachable releases/objects/deployment dirs gone,
// pins survive); and the two sides are independent (retention never touches
// the pusher's ledger; checkpoint never touches the receiver's generations).
// ---------------------------------------------------------------------------

fn run_no_leak_case(
    receiver_trees: Vec<String>,
    keep_distinct: usize,
    pusher_history: Vec<bool>,
    checkpoint_at: usize,
) {
    let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();

    // ---- the receiver: a remote with a generation history -----------------
    let remote =
        LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote")).unwrap();
    let helper = RemoteHelper::new(&remote);
    let n = receiver_trees.len();
    for (i, t) in receiver_trees.iter().enumerate() {
        let prior = (i > 0).then(|| format!("g{}", i - 1));
        make_gen(
            &helper,
            &format!("d{i}"),
            &format!("g{i}"),
            t,
            &format!("2020-01-{:02}T00:00:00Z", i + 1),
            prior.as_deref(),
        );
    }
    helper
        .swap_current(
            &crate::remote::helper::ExpectedCurrent::Absent,
            test_generation_id(&format!("g{}", n - 1)).as_str(),
            "op",
        )
        .unwrap();
    // The pinned tree exists on the receiver (pin-protected content). The
    // receiver's tree dirs are keyed by the canonical digest.
    helper
        .remote()
        .create_dir_all(&layout::tree_root(test_tree_digest("tree-pinned").as_str()))
        .unwrap();

    // ---- the pusher: a store with a ledger + ghost content ----------------
    let store = LocalStore::with_base(dir.path().join("store")).unwrap();
    let pinned = seed_real_release(&store);
    // The pinned release's tree object exists in the store (a real release
    // carries its tree bytes).
    seed_object(&store, "tree-pinned");
    let mut cfg = config_for(&dir, Some(&pinned));
    // The slot's ONE policy, tuned by the generated window.
    cfg.variant_mut("standard")
        .unwrap()
        .retention
        .per_server
        .keep_distinct_artifacts = keep_distinct as u32;
    cfg.variant_mut("standard")
        .unwrap()
        .retention
        .per_server
        .keep_days = 0;
    cfg.variant_mut("standard")
        .unwrap()
        .retention
        .per_server
        .protect_previous = true;
    cfg.variant_mut("standard")
        .unwrap()
        .retention
        .deployment
        .protect_deployments = 1;
    let ids = seed_history(&store, TARGET, "deploy", &pusher_history);
    for (i, _) in pusher_history.iter().enumerate() {
        let id = format!("deploy-{i}");
        seed_named_release(&store, crate::identity::test_release_id(&id).as_str());
        seed_object(&store, &format!("tree-{id}"));
    }
    seed_unreachable(
        &store,
        "ghost-deploy",
        crate::identity::test_release_id("rel-sha256-ghost").as_str(),
        "tree-ghost",
    );

    // ---- independence snapshots -------------------------------------------
    let ledger_before = store.read_ledger_lines(TARGET).unwrap();
    let gens_before = list_generations(&helper);

    // ---- receiver sweep: retention -----------------------------------------
    let retention = &cfg.variant("standard").unwrap().retention;
    let retained = compute_retained(&helper, cfg.pins(), &store, retention).unwrap();
    helper.rotate(&retained, &HashSet::new()).unwrap();
    // The receiver retains EXACTLY the policy-retained trees: stale ones are
    // gone, retained + pinned content survives.
    for t in &receiver_trees {
        let exists = helper.remote().exists(&layout::tree_root(t));
        assert_eq!(
            exists,
            retained.contains(t),
            "receiver tree {t} must be retained iff the slot's policy retains it"
        );
    }
    assert!(
        helper
            .remote()
            .exists(&layout::tree_root(test_tree_digest("tree-pinned").as_str())),
        "pinned content survives on the receiver"
    );
    // Independence: retention never touches the pusher's ledger.
    assert_eq!(
        store.read_ledger_lines(TARGET).unwrap(),
        ledger_before,
        "retention must never touch the pusher's ledger"
    );

    // ---- pusher sweep: checkpoint -----------------------------------------
    let at = checkpoint_at % ids.len();
    let checkpoint_id = &ids[at];
    let rep = run_checkpoint_unlocked(
        &store,
        &cfg,
        TARGET,
        &DeploymentId::parse(checkpoint_id).expect("canonical checkpoint id"),
    )
    .expect("checkpoint succeeds");
    assert!(rep.established);
    assert!(rep.sweep_completed);
    // The pusher retains EXACTLY the reachable artifacts: the retained
    // suffix's SUCCESSFUL entries' releases/trees survive; everything below
    // the checkpoint (and the ghost content) is gone.
    let mut pos = 0usize;
    let mut seen = 0usize;
    for (i, ok) in pusher_history.iter().enumerate() {
        if *ok {
            if seen == at {
                pos = i;
                break;
            }
            seen += 1;
        }
    }
    for (i, ok) in pusher_history.iter().enumerate() {
        let id = format!("deploy-{i}");
        let reachable = *ok && i >= pos;
        assert_eq!(
            store
                .release_dir(&crate::identity::test_release_id(&id))
                .exists(),
            reachable,
            "release of entry {id} must survive iff it is in the retained suffix"
        );
        assert_eq!(
            store
                .object_root(&test_tree_digest(&format!("tree-{id}")))
                .exists(),
            reachable,
            "tree of entry {id} must survive iff it is in the retained suffix"
        );
    }
    // Ghost content is gone.
    assert!(!store.deployment_dir("ghost-deploy").exists());
    assert!(
        !store
            .release_dir(&crate::identity::test_release_id("rel-sha256-ghost"))
            .exists()
    );
    assert!(!store.object_root(&test_tree_digest("tree-ghost")).exists());
    // Pinned content survives on the pusher.
    assert!(store.release_dir(&pinned).exists());
    assert!(store.object_root(&test_tree_digest("tree-pinned")).exists());
    // Independence: checkpoint never touches the receiver's generations.
    assert_eq!(
        list_generations(&helper),
        gens_before,
        "checkpoint must never touch the receiver's generations"
    );
}

proptest! {
    // The two-sided no-leak contract, bounded `proptest_cases(4)` (full 4
    // with `DEPLOY_FULL_TESTS=1`, fast default) + fixed seed per house
    // style (each case builds a tempdir remote + store, so the bound keeps
    // the suite fast).
    #![proptest_config(ProptestConfig {
        cases: crate::testutil::proptest_cases(4),
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn two_sided_sweep_no_leak(
        receiver_trees in prop::collection::vec(0usize..8, 3..=6)
            .prop_map(|v| {
                let mut s: Vec<String> = v
                    .into_iter()
                    .map(|i| test_tree_digest(&format!("t{i}")).as_str().to_string())
                    .collect();
                s.sort();
                s.dedup();
                s
            }),
        keep_distinct in 0usize..=2,
        pusher_history in prop::collection::vec(any::<bool>(), 3..=6)
            .prop_map(|mut v| {
                // A checkpoint needs a SUCCESSFUL deployment: guarantee at
                // least one success so `ids` is never empty.
                if !v.contains(&true) {
                    v[0] = true;
                }
                v
            }),
        checkpoint_at in 0usize..6,
    ) {
        run_no_leak_case(receiver_trees, keep_distinct, pusher_history, checkpoint_at);
    }
}

// ---------------------------------------------------------------------------
// MAINTENANCE, NOT CORRECTION (faulted path): with a sweep fault injected,
// the operation that triggered the sweep STILL SUCCEEDS (the checkpoint's
// ledger commit stands), durable sweep debt is recorded, and the NEXT PUSH
// fires the pending sweep — recomputing reachability fresh — and converges.
// ---------------------------------------------------------------------------

/// The pusher-side sweep faults the property injects: the checkpoint sweep's
/// three stages and the artifact GC's scan / release / tree phases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SweepFault {
    SweepDeployments,
    SweepReleases,
    SweepObjects,
    GcScan,
    GcDeleteReleases,
    GcDeleteTrees,
}

fn arm_sweep_fault(store: &LocalStore, checkpoint_id: &str, fault: SweepFault) {
    let reg = store.fault_registry();
    match fault {
        SweepFault::SweepDeployments => reg.arm_sweep_deployments(),
        SweepFault::SweepReleases => reg.arm_sweep_releases(),
        SweepFault::SweepObjects => reg.arm_sweep_objects(),
        SweepFault::GcScan => reg.arm(FaultKind::GcScan, checkpoint_id),
        SweepFault::GcDeleteReleases => reg.arm(FaultKind::GcDeleteReleases, checkpoint_id),
        SweepFault::GcDeleteTrees => reg.arm(FaultKind::GcDeleteTrees, checkpoint_id),
    }
}

fn run_fault_case(pusher_history: Vec<bool>, checkpoint_at: usize, fault: SweepFault) {
    let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
    let store = LocalStore::with_base(dir.path().join("store")).unwrap();
    let pinned = seed_real_release(&store);
    // The pinned release's tree object exists in the store.
    seed_object(&store, "tree-pinned");
    let cfg = config_for(&dir, Some(&pinned));
    let ids = seed_history(&store, TARGET, "deploy", &pusher_history);
    for (i, _) in pusher_history.iter().enumerate() {
        let id = format!("deploy-{i}");
        seed_named_release(&store, crate::identity::test_release_id(&id).as_str());
        seed_object(&store, &format!("tree-{id}"));
    }
    seed_unreachable(
        &store,
        "ghost-deploy",
        crate::identity::test_release_id("rel-sha256-ghost").as_str(),
        "tree-ghost",
    );
    let at = checkpoint_at % ids.len();
    let checkpoint_id = &ids[at];
    // The checkpoint entry's RAW tag (its release/tree dirs are seeded under
    // the raw `deploy-{pos}` name; the ledger references the canonical id).
    let mut pos = 0usize;
    let mut seen = 0usize;
    for (i, ok) in pusher_history.iter().enumerate() {
        if *ok {
            if seen == at {
                pos = i;
                break;
            }
            seen += 1;
        }
    }

    // Arm the sweep fault (one-shot: the checkpoint's sweep consumes it).
    arm_sweep_fault(&store, checkpoint_id, fault);

    // The faulted checkpoint: the operation STILL SUCCEEDS (maintenance, not
    // correction) — the ledger commit stands, the sweep is reported
    // retry-required, and durable sweep debt is recorded.
    let rep = run_checkpoint_unlocked(
        &store,
        &cfg,
        TARGET,
        &DeploymentId::parse(checkpoint_id).expect("canonical checkpoint id"),
    )
    .expect("the faulted checkpoint still succeeds");
    assert!(rep.established, "the ledger commit stands");
    assert!(
        !rep.sweep_completed,
        "the sweep is reported retry-required, never an error"
    );
    assert!(
        store.read_sweep_debt().unwrap().is_some(),
        "durable sweep debt is recorded"
    );
    // The faulted stage's content remains (extra garbage, never less).
    match fault {
        SweepFault::SweepDeployments => {
            assert!(store.deployment_dir("ghost-deploy").exists());
        }
        SweepFault::SweepReleases
        | SweepFault::SweepObjects
        | SweepFault::GcScan
        | SweepFault::GcDeleteReleases => {
            assert!(
                store
                    .release_dir(&crate::identity::test_release_id("rel-sha256-ghost"))
                    .exists()
            );
        }
        SweepFault::GcDeleteTrees => {
            assert!(store.object_root(&test_tree_digest("tree-ghost")).exists());
        }
    }

    // The NEXT PUSH fires the pending sweep: recompute reachability fresh,
    // converge, and clear the debt.
    let warnings = retry_pending_sweep(&store, &cfg, "next-push");
    assert!(
        warnings.is_empty(),
        "the next push converges the sweep cleanly: {warnings:?}"
    );
    assert!(
        store.read_sweep_debt().unwrap().is_none(),
        "the sweep debt is cleared once the sweep completes"
    );
    assert!(!store.deployment_dir("ghost-deploy").exists());
    assert!(
        !store
            .release_dir(&crate::identity::test_release_id("rel-sha256-ghost"))
            .exists()
    );
    assert!(!store.object_root(&test_tree_digest("tree-ghost")).exists());
    // Reachable + pinned content survives the converged sweep.
    assert!(
        store
            .release_dir(&crate::identity::test_release_id(&format!("deploy-{pos}")))
            .exists()
    );
    assert!(
        store
            .object_root(&test_tree_digest(&format!("tree-deploy-{pos}")))
            .exists()
    );
    assert!(store.release_dir(&pinned).exists());
    assert!(store.object_root(&test_tree_digest("tree-pinned")).exists());
}

proptest! {
    // The maintenance-not-correction contract, bounded `proptest_cases(4)`
    // (full 4 with `DEPLOY_FULL_TESTS=1`, fast default) + fixed seed.
    #![proptest_config(ProptestConfig {
        cases: crate::testutil::proptest_cases(4),
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn sweep_faults_are_maintenance_not_correction(
        pusher_history in prop::collection::vec(any::<bool>(), 3..=6)
            .prop_map(|mut v| {
                if !v.contains(&true) {
                    v[0] = true;
                }
                v
            }),
        checkpoint_at in 0usize..6,
        fault in prop_oneof![
            Just(SweepFault::SweepDeployments),
            Just(SweepFault::SweepReleases),
            Just(SweepFault::SweepObjects),
            Just(SweepFault::GcScan),
            Just(SweepFault::GcDeleteReleases),
            Just(SweepFault::GcDeleteTrees),
        ],
    ) {
        run_fault_case(pusher_history, checkpoint_at, fault);
    }
}

// ---------------------------------------------------------------------------
// FOCUSED UNIT TESTS
// ---------------------------------------------------------------------------

/// The sweep-debt marker round-trips: absent → recorded → cleared (the
/// marker file is removed, leaving no trace).
#[test]
fn sweep_debt_marker_roundtrip() {
    let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
    let store = LocalStore::with_base(dir.path().join("store")).unwrap();
    assert_eq!(store.read_sweep_debt().unwrap(), None);
    store.write_sweep_debt(Some("sweep pending")).unwrap();
    assert_eq!(
        store.read_sweep_debt().unwrap().as_deref(),
        Some("sweep pending")
    );
    store.write_sweep_debt(None).unwrap();
    assert_eq!(store.read_sweep_debt().unwrap(), None);
    assert!(
        !store.sweep_debt_path().exists(),
        "a fully-serviced store leaves no sweep-debt trace"
    );
}

/// The sweep-debt I/O is NON-FALLIBLE post-commit maintenance: a debt
/// read/write failure is a warning from the next push's retry, never an
/// `Err` — a debt-file fault can never turn a push into an error.
#[test]
fn sweep_debt_io_faults_are_warnings_not_errors() {
    let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
    let store = LocalStore::with_base(dir.path().join("store")).unwrap();
    let cfg = config_for(&dir, None);
    // A debt READ failure is treated as no debt: a warning, never an Err.
    store.fault_registry().arm_read_sweep_debt();
    let w = retry_pending_sweep(&store, &cfg, "anchor");
    assert_eq!(w.len(), 1, "the read fault warns: {w:?}");
    assert!(w[0].contains("failed to read sweep debt"), "{w:?}");
    // A debt WRITE failure (clearing the marker) is a warning, never an Err;
    // the marker stays for a later push to retry.
    store.write_sweep_debt(Some("pending")).unwrap();
    store.fault_registry().arm_write_sweep_debt();
    let w = retry_pending_sweep(&store, &cfg, "anchor");
    assert_eq!(w.len(), 1, "the write fault warns: {w:?}");
    assert!(w[0].contains("failed to clear sweep debt"), "{w:?}");
    assert!(
        store.read_sweep_debt().unwrap().is_some(),
        "the marker survives the failed clear for a later push"
    );
}

/// A full-push harness for the receiver-side maintenance test: one server /
/// one target project with real artifacts, a store, and a remotes base.
struct PushHarness {
    _dir: tempfile::TempDir,
    cfg_path: PathBuf,
    config: ProjectConfig,
    store: LocalStore,
    remotes_base: PathBuf,
}

impl PushHarness {
    fn new() -> PushHarness {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), VARIANT_TOML).unwrap();
        std::fs::write(
            project.join("deploy.toml"),
            format!(
                "schema_version = 2\napplication = \"sw\"\nrelease = \"v1\"\n\n\
                 [[servers]]\nid = \"s1\"\naddress = \"a\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n\
                 [targets.{TARGET}]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n"
            ),
        )
        .unwrap();
        let artifacts_dir = release_dir.join("artifacts");
        for (p, c) in [
            ("build/output/app/server", "v1\n"),
            ("deployment/common/README", "common\n"),
        ] {
            let fp = artifacts_dir.join(p);
            std::fs::create_dir_all(fp.parent().unwrap()).unwrap();
            std::fs::write(&fp, c).unwrap();
        }
        let cfg_path = project.join("deploy.toml");
        let config = ProjectConfig::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();
        PushHarness {
            _dir: dir,
            cfg_path,
            config,
            store,
            remotes_base,
        }
    }
}

/// RECEIVER-side maintenance, end to end: the retention's inventory write
/// fails once AFTER the deployment already committed. The push must STILL
/// SUCCEED (maintenance, not correction) — the retention is deferred as
/// durable retention debt plus a warning, never an Err — and the NEXT PUSH
/// (a no-op) fires the pending retention, succeeds, and clears the debt.
#[test]
fn receiver_retention_failure_is_maintenance_not_correction() {
    let h = PushHarness::new();
    // Push 1: the retention's `state/inventory.json` write fails once.
    let armed = Arc::new(AtomicBool::new(true));
    let armed_for_factory = armed.clone();
    let rf = h.remotes_base.clone();
    let fault_factory = move |s: &crate::config::ServerDef,
                              _slot: &crate::config::SlotConfig|
          -> Result<Box<dyn Remote>> {
        FailOnceInventoryRemote::build(rf.join(&s.id), armed_for_factory.clone())
    };
    let r1 = push(
        &h.cfg_path,
        &h.store,
        &fault_factory,
        "t1",
        &h.config,
        &PushOptions {
            dry_run: false,
            group: None,
            ref_token: None,
        },
    )
    .expect("the push succeeds despite the retention failure");
    assert_eq!(
        r1.status,
        Some(DeploymentStatus::Successful),
        "the deployment committed"
    );
    let warning = r1
        .warning
        .as_deref()
        .expect("the retention deferral is surfaced as a warning, never an error");
    assert!(
        warning.contains("retention deferred"),
        "the warning names the deferred retention: {warning}"
    );
    let debt = h.store.read_retention_debt("t1").unwrap();
    assert!(
        debt.contains_key("p1"),
        "durable retention debt is recorded: {debt:?}"
    );

    // Push 2 (no-op): the NEXT PUSH fires the pending retention — the retry
    // succeeds and clears the debt.
    let rf2 = h.remotes_base.clone();
    let clean_factory = move |s: &crate::config::ServerDef,
                              _slot: &crate::config::SlotConfig|
          -> Result<Box<dyn Remote>> {
        Ok(Box::new(
            LocalTransport::new(&crate::testutil::fixture_env(), rf2.join(&s.id)).unwrap(),
        ))
    };
    let r2 = push(
        &h.cfg_path,
        &h.store,
        &clean_factory,
        "t1",
        &h.config,
        &PushOptions {
            dry_run: false,
            group: None,
            ref_token: None,
        },
    )
    .expect("the no-op push succeeds");
    assert_eq!(r2.status, None, "the second push is a no-op");
    assert!(r2.message.contains("Everything up to date"));
    assert!(
        h.store.read_retention_debt("t1").unwrap().is_empty(),
        "the next push clears the retention debt"
    );
}
