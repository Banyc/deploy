//! Semantic-invariant test suite.
//!
//! Classifies failures by the VIOLATED SEMANTIC INVARIANT, not by the
//! returned [`crate::error::Error`] variant. Several important bugs return
//! `Ok`.
//!
//! Five semantic error classes are each pinned by a core invariant:
//!
//! * **Identity** — semantically equal inputs have the same identity; unequal
//!   assignments must not no-op.
//! * **Scope** — decisions and projections include every owner of shared
//!   state (a slot shared between targets is never decided under one target's
//!   policy, and every member's observed projection stays equal to the remote
//!   assignment). The observed projection is refreshed by the real-push path
//!   AND by the no-op path (a crash-window push recovered by an up-to-date
//!   retry must not leave the shared slot's projection stale/absent), so after
//!   ANY completed or recovered mutation every member target's observed slot
//!   equals the remote assignment (generation + artifact).
//! * **Lifecycle** — the returned outcome agrees with the durable transaction
//!   phase; retry converges without duplicating history.
//! * **Integrity** — stored identity is never trusted; content, structure,
//!   and storage path are verified, and every mutation fails closed.
//! * **Bounds** — resource calculations are total, overflow-free, and fail
//!   safely (checked against a u128 reference model).
//!
//! The bulk of the suite runs a tiny **state-machine fixture**: 1 physical
//! slot on 1 server, 2 targets (`t1` aggressive / `t2` conservative retention
//! over a shared slot), 2 variants materializing the same tree bytes, and 3+
//! tree generations via artifact-content versions. Actions are short
//! deterministic sequences (no sleeps, no network; every transport is a local
//! filesystem transport) and after every action the five invariant groups are
//! evaluated over the fixture state — interleaving bugs show up more cheaply
//! than one scenario per anticipated defect.
//!
//! A second layer is the per-class property suite (digest reordering,
//! per-field record tampering, the u128 bounds grid, retention monotonicity).
//!
//! A THIRD layer is the **model-based property test**: a deterministic
//! [`Model`] oracle (same-module, below) is driven by the SAME bounded RANDOM
//! action stream as the [`Fixture`] (proptest, fixed seed + bounded cases so
//! every run is reproducible). The model tracks, purely from the actions, the
//! invariants' ground truth — the remote current generation, every member
//! target's observed projection, the per-target fleet-snapshot and
//! deployment-attempt logs, pending-commit and rotation-debt state — and
//! [`assert_semantic_invariants`] cross-checks it against the system's
//! observable state after every action while re-evaluating all five
//! invariant groups. Random vectors with shrinking find interleaving bugs the
//! fixed sequences miss, and minimize any failing vector to its core.
//!
//! The five mutations the harness applies one at a time (and reverts) each
//! kill at least one test in this module or the suite it feeds:
//!
//! | Mutant | Killer(s) |
//! |---|---|
//! | Identity: no-op compares tree+release only | `identity_artifact_component_change_prevents_noop` |
//! | Scope: rotation uses only the pushing target's policy | `scope_retained_is_union_of_member_policies`, `state_machine_scope_projection_and_rotation_union` |
//! | Lifecycle: step-17 rotation `?` after commit | `state_machine_lifecycle_cleanup_failure_after_commit` |
//! | Integrity: `verify_release_identity` trusts stored digest | `integrity_digest_unchanged_after_tamper_fails_closed`, `integrity_tampered_stored_release_blocks_historical_push`, `integrity_identity_field_change_fails_closed` |
//! | Integrity: stored records carry only `SCHEMA_VERSION` | `integrity_stored_release_schema_version_tamper_fails_closed` |
//! | Bounds: `need + reserve > available` wraps | `bounds_capacity_matches_u128_reference_over_grid` |

use crate::config::{Config, SlotDef};
use crate::error::Result;
use crate::layout;
use crate::model::{
    ArtifactRef, DeploymentId, OperationId, PlacementSlotId, ReleaseId, TreeDigest, VariantName,
};
use crate::push::capacity::capacity_fits;
use crate::push::engine::{PushOptions, PushReport, push, push_with_id};
use crate::records::DeploymentStatus;
use crate::release::{
    canonicalize_slots, release_digest, variant_slots_digest, verify_release_identity,
};
use crate::remote::helper::{GenerationAssignment, RemoteHelper};
use crate::remote::transport::{
    ExecOutcome, FsBytes, LocalTransport, Remote, RemoteEntry, RemoteMeta,
};
use crate::rotation::compute_retained;
use crate::store::local::LocalStore;
use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Fixture project
// ---------------------------------------------------------------------------

/// Both variants map the same artifact sources, so `standard` and `canary`
/// ALWAYS materialize the SAME tree bytes: a variant switch never changes the
/// tree — the exact shape that pins the complete-ArtifactRef no-op comparison
/// (variant is the only differing component).
const VARIANT_BODY: &str = r#"
[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
to = "app/"
recursive = true

[activation]
adapter = "none"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

/// The single physical slot: server `s1`, member of BOTH targets, plus a
/// third single-member slot `pdx` (target `debtfx`) used ONLY by the
/// rotation-debt fault-matrix test. `debtfx`'s name is unique to that test
/// (no other test pushes it), so the TARGET-keyed debt fault arms
/// (`arm_read_rotation_debt` / `arm_write_rotation_debt`) cannot be consumed
/// by a concurrent test's push — the fixture's `t1`/`t2` pushes stay
/// untouched.
const SLOT_BODY: &str = r#"
[[slots]]
id = "p1"
server = "s1"
targets = ["t1", "t2"]
deploy_dir = "/srv/si"

[[slots]]
id = "pdx"
server = "s1"
targets = ["debtfx"]
deploy_dir = "/srv/si-debt"
"#;

/// Two CONTRASTING rotation policies over the shared slot: `t1` is AGGRESSIVE
/// (newest 1 distinct binding, no age window, no previous protection, 1 fleet
/// deployment) while `t2` is CONSERVATIVE (newest 5 distinct bindings, 30
/// days of age, the protected previous, 2 fleet deployments). The union is
/// strictly larger than either policy alone, so a rotation that consults only
/// the pushing target's policy sweeps content the other member retains.
const DEPLOY_TOML: &str = r#"
schema_version = 1
application = "si"
release = "v1"

[targets.t1.rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = false

[targets.t1.rotation.fleet]
protect_deployments = 1

[targets.t2.rotation.per_server]
keep_distinct_artifacts = 5
keep_days = 30
protect_previous = true

[targets.t2.rotation.fleet]
protect_deployments = 2

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }

[targets.t2]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }

[targets.debtfx.rotation.per_server]
keep_distinct_artifacts = 1
keep_days = 0
protect_previous = false

[targets.debtfx.rotation.fleet]
protect_deployments = 1

[targets.debtfx]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;

// ---------------------------------------------------------------------------
// Fault injection
// ---------------------------------------------------------------------------

/// The I/O boundaries the Lifecycle class injects failures at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureStep {
    /// Fleet-commit marker write on the remote (`state/commits/<id>.json`).
    CommitMarkerWrite,
    /// Post-commit rotation's inventory write (`state/inventory.json`).
    RotationInventoryWrite,
    /// Local intent persist (`append_attempt`) — BEFORE any remote mutation.
    IntentPersist,
    /// Local outcomes store (`write_results`) — after servers advanced.
    ResultsWrite,
    /// Local snapshot append (first step of replay-safe finalization).
    SnapshotAppend,
    /// `refs/last-successful` write.
    LastSuccessfulWrite,
    /// Terminal `Successful` transition append.
    TransitionSuccessful,
    /// Recoverable `PendingCommit` marker transition append.
    TransitionPending,
    /// Post-commit observed-refresh `write_server` (store) — runs after the
    /// deployment is durably committed.
    ObservedWriteServer,
    /// Post-commit observed-refresh `write_observed` for the PUSH'S OWN target
    /// (store) — the last write of the refresh, after the durable commit point.
    ObservedPrimaryWrite,
    /// Post-commit observed-refresh `write_observed` for the OTHER member
    /// target of the shared slot (store) — the shared-slot propagation.
    ObservedOtherWrite,
    /// Post-commit rotation-debt READ (`LocalStore::read_rotation_debt`,
    /// target-keyed) — the marker read during the deferred-rotation retry or
    /// the step-17 clear/defer, after the durable commit point.
    DebtRead,
    /// Post-commit rotation-debt WRITE/REMOVE
    /// (`LocalStore::write_rotation_debt`, target-keyed) — the marker's
    /// persist, and the empty-map removal that clears a serviced marker.
    DebtWrite,
    /// The "debt remove" arm of the matrix: the cleared-marker removal is the
    /// same `write_rotation_debt` call, so this maps onto [`DebtWrite`]'s arm
    /// (kept as a distinct step so the {read, write, remove} matrix is
    /// explicit).
    DebtRemove,
}

/// Remote-side fault configuration, shared between the fixture and the remote
/// wrappers the factory hands out.
#[derive(Clone, Debug, Default)]
struct RemoteFault {
    /// Fail the next WRITE whose path ends with this suffix exactly once.
    fail_write_once: Option<String>,
}

/// A transport that fails selected writes once, then passes through. Wraps
/// `LocalTransport`; deterministic, no sleeps.
struct FailOnceRemote {
    inner: LocalTransport,
    fault: Arc<Mutex<RemoteFault>>,
}

impl FailOnceRemote {
    fn build(base: PathBuf, fault: Arc<Mutex<RemoteFault>>) -> Result<Box<dyn Remote>> {
        Ok(Box::new(FailOnceRemote {
            inner: LocalTransport::new(base)?,
            fault,
        }))
    }
    fn should_fail(&self, rel: &Path) -> bool {
        let mut f = self.fault.lock().unwrap();
        if let Some(marker) = &f.fail_write_once {
            let rel = rel.to_string_lossy().to_string();
            // Commit-marker faults name the `state/commits/` DIRECTORY
            // (prefix match); the rotation-inventory fault names the exact
            // file. The fault is consumed ONLY by a matching write — a write
            // to any other path must leave it armed.
            if rel.starts_with(marker) || rel.ends_with(marker) {
                f.fail_write_once = None;
                return true;
            }
        }
        false
    }
}

impl Remote for FailOnceRemote {
    fn root(&self) -> &Path {
        self.inner.root()
    }
    fn read(&self, rel: &Path) -> Result<Vec<u8>> {
        self.inner.read(rel)
    }
    fn write(&self, rel: &Path, data: &[u8], mode: u32) -> Result<()> {
        if self.should_fail(rel) {
            return Err(crate::error::Error::transport(format!(
                "injected write failure at {}",
                rel.display()
            )));
        }
        self.inner.write(rel, data, mode)
    }
    fn try_write_new(&self, rel: &Path, data: &[u8]) -> Result<bool> {
        if self.should_fail(rel) {
            return Err(crate::error::Error::transport(format!(
                "injected write failure at {}",
                rel.display()
            )));
        }
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
    fn exec(&self, argv: &[String], timeout: std::time::Duration) -> Result<ExecOutcome> {
        self.inner.exec(argv, timeout)
    }
    fn filesystem_bytes(&self) -> Result<FsBytes> {
        self.inner.filesystem_bytes()
    }
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/// The state-machine actions. `Build` + `Push` map onto the real pipeline: a
/// HEAD push materializes the current artifact sources into a content-
/// addressed tree and release.
#[derive(Clone, Debug)]
pub(crate) enum Action {
    /// Rewrite the artifact source content (the next push materializes a new
    /// tree generation).
    Build(u32),
    /// Push target `t1` or `t2`.
    Push(&'static str),
    /// An up-to-date retry push on the target (no-op or reconcile).
    Retry(&'static str),
    /// Roll the target back to fleet snapshot index `n`.
    Rollback(&'static str, u64),
    /// Run a standalone rotation pass under the FULL member policy union.
    Rotate,
    /// Arm a one-shot remote failure for the next push.
    InjectFailure(FailureStep),
    /// Tamper with a specific record. Deliberately VIOLATES the Integrity
    /// group; used only by the dedicated integrity property tests, which run
    /// the specific detection assertions instead of the generic checks.
    Tamper(TamperKind),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TamperKind {
    /// Rewrite the CURRENT generation's stored assignment with ONE artifact
    /// component replaced (variant or release), keeping the other two. The
    /// tree component is tampered via [`Fixture::tamper_stored_tree`] with a
    /// real tree digest so the history stays consistent.
    StoredAssignmentVariant,
    StoredAssignmentRelease,
    /// Rewrite the stored `behavior.json` of the release the current
    /// generation runs (one identity-bearing field changed), so the historical
    /// behavior read and the publication path must fail closed.
    StoredBehaviorJson,
    /// Rewrite the STORED release record's `release_schema_version` to a
    /// non-canonical value: the record must fail closed on every read and
    /// block the next push (see
    /// `integrity_stored_release_schema_version_tamper_fails_closed`).
    StoredReleaseSchemaVersion,
}

/// The outcome of one applied action.
pub(crate) enum Outcome {
    Push(Result<PushReport>),
    Ok,
    Tampered,
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// The tiny state machine. `apply` runs an action and then evaluates all five
/// invariant groups (except after a deliberate [`Action::Tamper`]).
pub(crate) struct Fixture {
    _dir: tempfile::TempDir,
    project: PathBuf,
    cfg_path: PathBuf,
    config: Config,
    store: LocalStore,
    remotes_base: PathBuf,
    fault: Arc<Mutex<RemoteFault>>,
}

impl Fixture {
    fn new() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(
            release_dir.join("standard.toml"),
            format!("{VARIANT_BODY}\n{SLOT_BODY}"),
        )
        .unwrap();
        // canary declares no slots; identical mappings -> same tree bytes.
        std::fs::write(release_dir.join("canary.toml"), VARIANT_BODY).unwrap();
        let cfg_path = project.join("deploy.toml");
        std::fs::write(&cfg_path, DEPLOY_TOML).unwrap();
        let artifacts_dir = release_dir.join("artifacts");
        let common_dir = artifacts_dir.join("deployment/common");
        std::fs::create_dir_all(&common_dir).unwrap();
        std::fs::write(common_dir.join("README"), "common\n").unwrap();
        let config = Config::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();
        let fixture = Fixture {
            _dir: dir,
            project,
            cfg_path,
            config,
            store,
            remotes_base,
            fault: Arc::new(Mutex::new(RemoteFault::default())),
        };
        fixture.write_artifacts(1);
        fixture
    }

    fn artifacts_dir(&self) -> PathBuf {
        self.project.join("releases").join("v1").join("artifacts")
    }

    /// Write artifact content for the given tree generation (1..=3).
    fn write_artifacts(&self, version: u32) {
        let p = self.artifacts_dir().join("build/output/app/server");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, format!("server-v{version}\n")).unwrap();
    }

    fn remote_factory(
        &self,
    ) -> impl Fn(&crate::config::ServerDef, &crate::config::SlotDef) -> Result<Box<dyn Remote>> + 'static
    {
        let rf = self.remotes_base.clone();
        let fault = self.fault.clone();
        move |s: &crate::config::ServerDef, _slot: &crate::config::SlotDef| {
            FailOnceRemote::build(rf.join(&s.id), fault.clone())
        }
    }

    /// A transport handle over the server's remote directory. The directory
    /// is created on demand so reads work before the first push.
    fn remote(&self) -> Box<dyn Remote> {
        let p = self.remotes_base.join("s1");
        std::fs::create_dir_all(&p).unwrap();
        Box::new(LocalTransport::new(p).unwrap())
    }

    /// Run `f` with a live `RemoteHelper` over the server's remote directory.
    fn with_helper<R>(&self, f: impl FnOnce(RemoteHelper<'_>) -> R) -> R {
        let remote = self.remote();
        f(RemoteHelper::new(remote.as_ref()))
    }

    /// The current generation's stored assignment for the single slot, if any.
    fn current_assignment(&self) -> Option<GenerationAssignment> {
        self.with_helper(|helper| {
            let status = helper.status().ok()?;
            let g = status.current_generation?;
            helper.read_assignment(&g).ok()
        })
    }

    fn push(&self, target_name: &str) -> Result<PushReport> {
        push(
            &self.cfg_path,
            &self.store,
            &self.remote_factory(),
            target_name,
            &self.config,
            &PushOptions {
                dry_run: false,
                ref_token: None,
            },
        )
    }

    /// Push with a caller-supplied deployment id (for arming the one-shot
    /// store faults keyed by id).
    fn push_with_id(&self, target_name: &str, id: &DeploymentId) -> Result<PushReport> {
        push_with_id(
            &self.cfg_path,
            &self.store,
            &self.remote_factory(),
            target_name,
            &self.config,
            &PushOptions {
                dry_run: false,
                ref_token: None,
            },
            id,
        )
    }

    fn push_ref(&self, target_name: &str, ref_token: &str) -> Result<PushReport> {
        push(
            &self.cfg_path,
            &self.store,
            &self.remote_factory(),
            target_name,
            &self.config,
            &PushOptions {
                dry_run: false,
                ref_token: Some(ref_token.to_string()),
            },
        )
    }

    /// Arm a one-shot store fault on THIS fixture's per-fixture registry
    /// (see `src/testutil.rs`): the fixture's store consumes only its own
    /// registry, so no global slot or lock is involved.
    fn arm_store_fault(&self, step: FailureStep, id: &DeploymentId) {
        let reg = self.store.fault_registry();
        match step {
            FailureStep::IntentPersist => reg.arm_append_attempt(id.as_str()),
            FailureStep::ResultsWrite => reg.arm_write_results(id.as_str()),
            FailureStep::SnapshotAppend => reg.arm_append_snapshot(id.as_str()),
            FailureStep::LastSuccessfulWrite => reg.arm_write_last_successful(id.as_str()),
            FailureStep::TransitionSuccessful => reg.arm_append_transition_successful(id.as_str()),
            FailureStep::TransitionPending => reg.arm_append_transition_pending(id.as_str()),
            // The post-commit observed-refresh faults are keyed by deployment
            // id AND target: the fixture's single shared slot (`p1`) belongs to
            // `t1` (the pushed target) and `t2` (the other member).
            FailureStep::ObservedWriteServer => reg.arm_write_server(id.as_str(), "t1"),
            FailureStep::ObservedPrimaryWrite => reg.arm_write_observed(id.as_str(), "t1"),
            FailureStep::ObservedOtherWrite => reg.arm_write_observed(id.as_str(), "t2"),
            // The rotation-debt faults are keyed by the TARGET only (the debt
            // methods carry no deployment id) and fire on `debtfx` — the
            // fixture target no other test pushes — so no concurrent test's
            // push can consume the arm.
            FailureStep::DebtRead => reg.arm_read_rotation_debt("debtfx"),
            FailureStep::DebtWrite | FailureStep::DebtRemove => {
                reg.arm_write_rotation_debt("debtfx")
            }
            other => panic!("{other:?} is a remote step, not a store step"),
        }
    }

    fn set_remote_fault(&self, step: FailureStep) {
        let suffix = match step {
            FailureStep::CommitMarkerWrite => "state/commits/".to_string(),
            FailureStep::RotationInventoryWrite => "state/inventory.json".to_string(),
            other => panic!("{other:?} is a store step, not a remote step"),
        };
        self.fault.lock().unwrap().fail_write_once = Some(suffix);
    }

    /// The observed-scope property, asserted explicitly by the property
    /// sequences: every member target's observed slot for the shared
    /// placement `p1` equals the CURRENT remote assignment (generation +
    /// artifact) — no absent, stale, or partial entries. Requires a remote
    /// assignment to exist (call after the first completed push).
    fn assert_observed_scope_property(&self) {
        let asn = self
            .current_assignment()
            .expect("a remote assignment exists");
        for target in ["t1", "t2"] {
            let observed = self.store.read_observed(target).expect("observed reads");
            let slot = observed
                .slots
                .get(&PlacementSlotId::new("p1"))
                .unwrap_or_else(|| panic!("{target}: observed p1 entry must be present"));
            assert_eq!(
                slot.generation.as_ref(),
                Some(&asn.generation_id),
                "{target}: observed generation must equal the remote generation"
            );
            assert_eq!(
                slot.artifact.as_ref(),
                Some(&asn.artifact),
                "{target}: observed artifact must equal the remote assignment"
            );
        }
    }

    /// Apply one action, then evaluate every invariant group (unless the
    /// action was a deliberate tamper).
    fn apply(&self, action: Action) -> Outcome {
        let outcome = match action {
            Action::Build(v) => {
                self.write_artifacts(v);
                Outcome::Ok
            }
            Action::Push(t) | Action::Retry(t) => Outcome::Push(self.push(t)),
            Action::Rollback(t, i) => Outcome::Push(self.push_ref(t, &format!("{t}@f{i}"))),
            Action::Rotate => {
                self.rotate_union().expect("standalone rotation succeeds");
                Outcome::Ok
            }
            Action::InjectFailure(step) => {
                self.set_remote_fault(step);
                Outcome::Ok
            }
            Action::Tamper(kind) => {
                self.tamper(kind);
                return Outcome::Tampered;
            }
        };
        self.check_invariants();
        outcome
    }

    fn push_ref_impl(&self, target_name: &str, ref_token: &str) -> Result<PushReport> {
        push(
            &self.cfg_path,
            &self.store,
            &self.remote_factory(),
            target_name,
            &self.config,
            &PushOptions {
                dry_run: false,
                ref_token: Some(ref_token.to_string()),
            },
        )
    }

    /// Standalone rotation under the FULL member policy union, exactly as
    /// step 17 runs it (mutation lock + union retained set).
    fn rotate_union(&self) -> Result<()> {
        self.with_helper(|helper| {
            let op = OperationId::generate();
            let _guard = helper.acquire_lock_guard(op.as_str())?;
            let retained = compute_retained(
                &helper,
                &self.config.pins,
                &self.store,
                &self.config,
                &["t1".to_string(), "t2".to_string()],
            )?;
            helper.rotate(&retained, &HashSet::new())
        })
    }

    /// Tamper the CURRENT generation's stored assignment on the remote.
    fn tamper(&self, kind: TamperKind) {
        if kind == TamperKind::StoredBehaviorJson {
            return self.tamper_stored_behavior_json();
        }
        let asn = self
            .current_assignment()
            .expect("a current generation exists");
        let gen_id = asn.generation_id;
        let path = self
            .remotes_base
            .join("s1")
            .join(layout::generation(gen_id.as_str()))
            .join("assignment.json");
        let mut stored: GenerationAssignment =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        match kind {
            TamperKind::StoredAssignmentVariant => {
                stored.artifact.variant = VariantName::new("canary".to_string())
            }
            TamperKind::StoredAssignmentRelease => {
                stored.artifact.release = ReleaseId::new("rel-sha256-tampered".to_string())
            }
            TamperKind::StoredBehaviorJson => unreachable!("handled above"),
            TamperKind::StoredReleaseSchemaVersion => {
                // Rewrite the stored release record's version field to a
                // non-canonical value; the record must fail closed on read.
                self.tamper_stored_release(|v| {
                    v["release_schema_version"] = serde_json::json!(
                        crate::model::RELEASE_RECORD_SCHEMA_VERSION.wrapping_add(1)
                    );
                });
                return;
            }
            _ => {}
        }
        std::fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
    }

    /// Whether a live current generation exists on the remote (a
    /// [`Action::Tamper`] requires one; the property test skips generated
    /// tampers on an empty remote).
    fn has_current_generation(&self) -> bool {
        self.current_assignment().is_some()
    }

    /// Tamper the CURRENT generation's stored assignment TREE to `tree`
    /// (release + variant untouched).
    fn tamper_stored_tree(&self, tree: &TreeDigest) {
        let asn = self
            .current_assignment()
            .expect("a current generation exists");
        let gen_id = asn.generation_id;
        let path = self
            .remotes_base
            .join("s1")
            .join(layout::generation(gen_id.as_str()))
            .join("assignment.json");
        let mut stored: GenerationAssignment =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        stored.artifact.tree = tree.clone();
        std::fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
    }

    /// Tamper the single stored release record via a JSON-level mutation.
    fn tamper_stored_release(&self, mutate: impl FnOnce(&mut serde_json::Value)) {
        let releases_root = self.store.base().join(layout::RELEASES);
        let dirs: Vec<_> = std::fs::read_dir(&releases_root)
            .unwrap()
            .flatten()
            .collect();
        assert_eq!(dirs.len(), 1, "exactly one stored release in the fixture");
        let p = dirs[0].path().join("release.json");
        let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        mutate(&mut v);
        std::fs::write(&p, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    }

    /// Tamper the stored `behavior.json` of the fixture's single release:
    /// change one identity-bearing field (the activation adapter) while the
    /// release record's provenance `behavior_sha256` is left untouched — the
    /// exact "behavior JSON tampered while the digest is retained" case the
    /// historical read and the publication path must fail closed against.
    fn tamper_stored_behavior_json(&self) {
        let releases_root = self.store.base().join(layout::RELEASES);
        let dirs: Vec<_> = std::fs::read_dir(&releases_root)
            .unwrap()
            .flatten()
            .collect();
        assert_eq!(dirs.len(), 1, "exactly one stored release in the fixture");
        let p = dirs[0].path().join("behavior.json");
        let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        v["standard"]["activation"]["adapter"] = serde_json::json!("tampered");
        std::fs::write(&p, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    }

    // ---- invariant groups --------------------------------------------------

    /// Evaluate all five invariant groups against the fixture state.
    fn check_invariants(&self) {
        self.check_identity();
        self.check_scope();
        self.check_lifecycle();
        self.check_integrity();
        self.check_bounds();
    }

    /// Identity: every stored release record's identity is recomputed and
    /// consistent; the live generation's assignment artifact references a
    /// locally stored, verified release.
    fn check_identity(&self) {
        let releases_root = self.store.base().join(layout::RELEASES);
        if let Ok(entries) = std::fs::read_dir(&releases_root) {
            for e in entries.flatten() {
                let id = ReleaseId::new(e.file_name().to_string_lossy().into_owned());
                let rec = self
                    .store
                    .read_release(&id)
                    .expect("every stored release record must read and verify");
                verify_release_identity(&rec).expect("release identity verifies");
                assert_eq!(
                    rec.release_id,
                    id.as_str(),
                    "stored release must be bound to its read path"
                );
            }
        }
        if let Some(asn) = self.current_assignment() {
            let rec = self
                .store
                .read_release(&asn.artifact.release)
                .expect("live assignment's release must exist locally and verify");
            assert!(
                rec.variants.contains_key(asn.artifact.variant.as_str()),
                "live assignment's variant must be a binding of its release"
            );
        }
    }

    /// Scope: (1) every member target's observed projection equals the remote
    /// assignment — STRICTLY, with no absent-entry exception: after ANY
    /// completed or recovered mutation (a real push, a no-op retry, a
    /// rollback) every member target's observed slot for the shared placement
    /// is present and equals the remote assignment (generation + artifact).
    /// The only state in which an entry may legitimately be absent is the
    /// crash window — a push that aborted AFTER the remote advanced but
    /// BEFORE the observed refresh — which the fixture only ever enters via
    /// [`Fixture::push_with_id`] mid-sequence and never evaluates here; the
    /// recovery action that closes the window refreshes the projections (the
    /// no-op retry path does too), so by the time `check_invariants` runs the
    /// entry must exist; (2) the shared slot's retained set is the union of
    /// every member's policy; (3) every tree the union retains actually
    /// survives the post-push rotation.
    fn check_scope(&self) {
        if let Some(asn) = self.current_assignment() {
            for target in ["t1", "t2"] {
                let observed = self.store.read_observed(target).expect("observed reads");
                let slot = match observed.slots.get(&PlacementSlotId::new("p1")) {
                    Some(slot) => slot,
                    None => panic!(
                        "{target}: observed projection for p1 must be present after any \
                         completed/recovered mutation (a no-op retry refreshes observed; the \
                         crash window is entered only mid-sequence via push_with_id, never \
                         evaluated by check_invariants)"
                    ),
                };
                assert_eq!(
                    slot.artifact.as_ref(),
                    Some(&asn.artifact),
                    "{target}: observed projection must equal the remote assignment"
                );
                assert_eq!(
                    slot.generation.as_ref(),
                    Some(&asn.generation_id),
                    "{target}: observed generation must equal the remote generation"
                );
            }
        }
        let (single_t1, single_t2, full) = self.with_helper(|helper| {
            let single_t1 = compute_retained(
                &helper,
                &self.config.pins,
                &self.store,
                &self.config,
                &["t1".to_string()],
            )
            .expect("retained under t1");
            let single_t2 = compute_retained(
                &helper,
                &self.config.pins,
                &self.store,
                &self.config,
                &["t2".to_string()],
            )
            .expect("retained under t2");
            let full = compute_retained(
                &helper,
                &self.config.pins,
                &self.store,
                &self.config,
                &["t1".to_string(), "t2".to_string()],
            )
            .expect("retained under the full union");
            (single_t1, single_t2, full)
        });
        let union: HashSet<String> = single_t1.union(&single_t2).cloned().collect();
        assert_eq!(
            full, union,
            "the shared slot's retained set must be the union of every member target's policy"
        );
        // Every tree the union retains must actually survive the rotation the
        // last push (or standalone rotate) performed.
        for tree in &full {
            assert!(
                self.remote().exists(&layout::tree_root(tree)),
                "union-retained tree {tree} must survive rotation"
            );
        }
    }

    /// Lifecycle: every recorded attempt's latest transition agrees with its
    /// durable artifacts; no snapshot is ever duplicated; no locks linger.
    fn check_lifecycle(&self) {
        for target in ["t1", "t2"] {
            let attempts = self.store.read_attempts(target).unwrap_or_default();
            let snapshots = self.store.read_snapshots(target).unwrap_or_default();
            let last_ok = self.store.read_last_successful(target);
            let mut seen: HashSet<String> = HashSet::new();
            for snap in &snapshots {
                assert!(
                    seen.insert(snap.deployment_id.as_str().to_string()),
                    "no snapshot may be recorded twice for one deployment ({})",
                    snap.deployment_id
                );
            }
            for attempt in &attempts {
                let latest = self
                    .store
                    .latest_status(attempt.deployment_id.as_str())
                    .expect("transition stream readable")
                    .expect("every recorded attempt has a transition");
                let id = attempt.deployment_id.as_str();
                let snapshot_exists = snapshots.iter().any(|s| s.deployment_id.as_str() == id);
                match latest {
                    DeploymentStatus::Successful => {
                        assert!(
                            snapshot_exists,
                            "Successful attempt {id} must have a snapshot entry"
                        );
                        assert!(
                            self.remote().exists(&layout::commit_marker(id)),
                            "Successful attempt {id} must have a durable commit marker"
                        );
                    }
                    DeploymentStatus::PendingCommit => {
                        assert!(
                            !snapshot_exists,
                            "PendingCommit attempt {id} must NOT have a snapshot yet"
                        );
                        assert!(
                            self.store.read_results(id).is_ok(),
                            "PendingCommit attempt {id} must be recoverable from durable outcomes"
                        );
                    }
                    _ => {}
                }
            }
            // `refs/last-successful` points at the NEWEST successful attempt
            // (older successful attempts keep their own snapshot/marker).
            let newest_successful = attempts
                .iter()
                .filter(|a| {
                    self.store
                        .latest_status(a.deployment_id.as_str())
                        .ok()
                        .flatten()
                        == Some(DeploymentStatus::Successful)
                })
                .map(|a| a.deployment_id.as_str())
                .max_by_key(|a| *a);
            match (newest_successful, last_ok.as_deref()) {
                (Some(newest), Some(ok)) => assert_eq!(
                    newest, ok,
                    "refs/last-successful must point at the newest successful attempt"
                ),
                (None, None) => {}
                (None, Some(ok)) => panic!(
                    "refs/last-successful points at {ok} but no successful attempt is recorded"
                ),
                (Some(_), None) => {
                    panic!("refs/last-successful is missing after a successful attempt")
                }
            }
            assert!(
                !self.remote().exists(&layout::operation_lock()),
                "no stale operation lock may remain after an action"
            );
        }
    }

    /// Integrity: stored identity is never trusted — the current link
    /// resolves to a parseable assignment and the live tree object exists
    /// (content-address verified by path).
    fn check_integrity(&self) {
        self.with_helper(|helper| {
            if let Ok(status) = helper.status() {
                if let Some(g) = &status.current_generation {
                    let asn = helper
                        .read_assignment(g)
                        .expect("current generation assignment must parse");
                    assert!(
                        helper
                            .remote()
                            .exists(&layout::tree_root(asn.artifact.tree.as_str())),
                        "current generation's tree object must exist on the remote"
                    );
                }
            }
        });
    }

    /// Bounds: the capacity decision never panics or wraps and agrees with the
    /// u128 reference model on the boundary grid.
    fn check_bounds(&self) {
        for (need, reserve, avail) in bounds_grid() {
            let fits = capacity_fits(need, reserve, avail);
            let reference = (need as u128) + (reserve as u128) <= avail as u128;
            assert_eq!(
                fits, reference,
                "capacity decision for need={need} reserve={reserve} avail={avail} must match the u128 reference"
            );
        }
    }
}

/// The Bounds value grid: 0, 1, avail-1, avail, avail+1, u64::MAX-1, u64::MAX
/// crossed over avail in {0, 1, 1000, MAX-1, MAX}.
fn bounds_grid() -> Vec<(u64, u64, u64)> {
    let mut out = Vec::new();
    for avail in [0u64, 1, 1000, u64::MAX - 1, u64::MAX] {
        let mut vals = vec![
            0u64,
            1,
            avail.saturating_sub(1),
            avail,
            avail.saturating_add(1),
        ];
        vals.extend([u64::MAX - 1, u64::MAX]);
        for &need in &vals {
            for &reserve in &vals {
                out.push((need, reserve, avail));
            }
        }
    }
    out
}

// ===========================================================================
// State-machine tests (short fixed sequences, invariant checks after each)
// ===========================================================================

/// Identity mutant killer: the early "Everything up to date" comparison must
/// be sensitive to EVERY ArtifactRef component. We tamper the CURRENT
/// generation's stored assignment on the remote, changing exactly one
/// component (release / variant / tree) and keeping the other two identical,
/// then push HEAD: the push must be a REAL push, never a no-op. A tree+release
/// comparison would falsely no-op on the VARIANT tamper (release and tree are
/// untouched), silently keeping the service "claimed up to date".
#[test]
fn identity_artifact_component_change_prevents_noop() {
    // (a) VARIANT: release + tree identical, only the variant differs — the
    // mutant-killing case.
    let f = Fixture::new();
    let r1 = f.push("t1").expect("first push succeeds");
    assert_eq!(r1.status, Some(DeploymentStatus::Successful));
    let noop = f.push("t1").expect("unchanged push succeeds");
    assert_eq!(noop.message, "Everything up to date");
    f.apply(Action::Tamper(TamperKind::StoredAssignmentVariant));
    let r2 = f.push("t1").expect("a variant tamper forces a real push");
    assert_ne!(
        r2.message, "Everything up to date",
        "changing the variant component must prevent a no-op"
    );
    assert_eq!(r2.status, Some(DeploymentStatus::Successful));
    assert!(r2.attempt.is_some(), "a real push records an attempt");
    f.check_invariants();

    // (b) TREE: tamper the stored tree to a DIFFERENT REAL tree (the repair
    // push keeps the history consistent, so the invariant checks still hold).
    let f = Fixture::new();
    let r1 = f.push("t1").expect("push v1");
    let first_tree = r1.attempt.as_ref().expect("attempt").slots[&PlacementSlotId::new("p1")]
        .artifact
        .tree
        .clone();
    f.apply(Action::Build(2));
    f.push("t1").expect("push v2 (current is now T2)");
    f.tamper_stored_tree(&first_tree);
    let r2 = f.push("t1").expect("a tree tamper forces a real push");
    assert_ne!(
        r2.message, "Everything up to date",
        "changing the tree component must prevent a no-op"
    );
    assert!(r2.attempt.is_some());
    f.check_invariants();

    // (c) RELEASE: tamper the stored release id.
    let f = Fixture::new();
    f.push("t1").expect("first push");
    f.apply(Action::Tamper(TamperKind::StoredAssignmentRelease));
    let r2 = f.push("t1").expect("a release tamper forces a real push");
    assert_ne!(
        r2.message, "Everything up to date",
        "changing the release component must prevent a no-op"
    );
    assert!(r2.attempt.is_some());
    f.check_invariants();
}

/// Scope: interleaved pushes over the shared slot; after EVERY action the
/// observed projection in both member targets equals the remote assignment and
/// every union-retained tree survives rotation. The final push runs under the
/// AGGRESSIVE target `t1`, whose policy alone would sweep the trees the
/// conservative member `t2` retains — the union check catches exactly that.
#[test]
fn state_machine_scope_projection_and_rotation_union() {
    let f = Fixture::new();
    for (version, target) in [
        (1u32, "t1"),
        (2, "t2"),
        (3, "t1"),
        (4, "t2"),
        (5, "t1"),
        (6, "t2"),
        (7, "t1"),
    ] {
        f.apply(Action::Build(version));
        let r = f.apply(Action::Push(target));
        let Outcome::Push(res) = r else {
            panic!("expected a push outcome");
        };
        let report = res.expect("every push in the sequence succeeds");
        assert_eq!(
            report.status,
            Some(DeploymentStatus::Successful),
            "push {version} on {target} must succeed"
        );
    }
    // A standalone rotate under the union, then the same checks.
    f.apply(Action::Rotate);
    f.check_invariants();
}

/// Lifecycle mutant: after the deployment has durably committed, a post-commit
/// rotation failure must NOT turn the deployment into a deployment failure —
/// the push still returns Ok with the committed status, records a persistent
/// debt marker, and warns. The mutant (`?` instead of debt-marker+warning)
/// would make this push return Err.
#[test]
fn state_machine_lifecycle_cleanup_failure_after_commit() {
    let f = Fixture::new();
    f.apply(Action::InjectFailure(FailureStep::RotationInventoryWrite));
    let Outcome::Push(res) = f.apply(Action::Push("t1")) else {
        panic!("expected a push outcome");
    };
    let r1 =
        res.expect("a committed deployment must never fail because its cleanup rotation failed");
    assert_eq!(
        r1.status,
        Some(DeploymentStatus::Successful),
        "the deployment committed; step-17 rotation failure must not change its outcome"
    );
    assert!(
        r1.attempt.is_some(),
        "the committed deployment records its attempt"
    );
    let warning = r1
        .warning
        .as_ref()
        .expect("the push must warn about the deferred rotation");
    assert!(
        warning.contains("rotation deferred"),
        "the warning describes the deferred rotation, got: {warning}"
    );
    assert!(
        !f.store.read_rotation_debt("t1").unwrap().is_empty(),
        "a persistent debt marker must be recorded"
    );

    // An up-to-date no-op retry services the maintenance: marker cleared, no
    // warning remains, no attempt created.
    let r2 = f.push("t1").expect("the retrying push succeeds");
    assert_eq!(r2.message, "Everything up to date");
    assert_eq!(r2.status, None, "the retrying push is an up-to-date no-op");
    assert!(
        r2.warning.is_none(),
        "the maintenance succeeded on the no-op retry, so no warning remains"
    );
    assert!(
        f.store.read_rotation_debt("t1").unwrap().is_empty(),
        "the debt marker must be cleared once the rotation succeeds"
    );
    f.check_invariants();
}

/// Lifecycle: a FRESH step-17 rotation whose slot mutation lock is CONTENDED
/// (held by another operation) must never be skipped SILENTLY. The push still
/// succeeds (the deployment already committed), records a best-effort debt
/// marker, and surfaces a warning naming the slot — "rotation deferred for
/// slot 'p1': slot lock held by another operation". Then the maintenance
/// lifecycle over the same marker: an up-to-date no-op whose retry ALSO finds
/// the lock held stays deferred and keeps warning; the FIRST no-op with the
/// lock FREE services the rotation (marker cleared) and reports no warning.
///
/// Determinism: the contention is created by a SECOND RemoteHelper's lock
/// guard held directly (no sleeps, no wall clock). The push runs in a scoped
/// thread; the guard is acquired the moment the engine's own step-15 guard
/// drops (synchronized on the durable fleet-commit marker + the lock file's
/// release), long before step 17 — the engine still has its whole
/// finalize + observed-refresh window to run, so the acquire wins the race by
/// a wide margin. If the engine's own rotation ever wins instead (oracle
/// branch (a): the slot was rotated, no debt), the scenario is re-run on a
/// fresh fixture — the assertion below only accepts the debt+warning branch.
#[test]
fn state_machine_lifecycle_rotation_lock_contention_defers_not_silent() {
    let id = DeploymentId::new("si-lockcont-push".to_string());
    let holder = "op-lockcont-holder";
    for attempt in 0..16 {
        let f = Fixture::new();
        let remote = f.remote();
        let helper = RemoteHelper::new(remote.as_ref());

        // ---- Step 1: PUSH with the mutation lock held from step 17 on.
        // The push runs in a scoped thread; the main thread waits for the
        // fleet-commit marker (the engine passed preflight, the batch, and
        // step 15), then acquires the lock via the second helper the moment
        // the engine's own guard drops. Step 17's `acquire_lock_guard` then
        // contends and the maintenance is deferred (debt + warning), never
        // silent, never an `Err`.
        let report1 = std::thread::scope(|s| {
            let push = s.spawn(|| f.push_with_id("t1", &id));
            let _guard = {
                let marker = layout::commit_marker(id.as_str());
                let mut spins = 0u64;
                while !remote.exists(&marker) {
                    std::thread::yield_now();
                    spins += 1;
                    assert!(
                        spins < 20_000_000,
                        "attempt {attempt}: the push never wrote its fleet-commit marker (step 15)"
                    );
                }
                // The marker is written UNDER the engine's own guard; wait for
                // that guard to drop (lock file gone), then hold it ourselves.
                loop {
                    if !remote.exists(&layout::operation_lock())
                        && let Ok(g) = helper.acquire_lock_guard(holder)
                    {
                        break g;
                    }
                    std::thread::yield_now();
                    spins += 1;
                    assert!(
                        spins < 20_000_000,
                        "attempt {attempt}: the push never released the mutation lock after step 15"
                    );
                }
            };
            push.join().expect("push thread panicked")
        });
        // Oracle after the successful push: (b) the slot carries debt AND the
        // report warns naming it — never silent, never Err. (If the engine's
        // own rotation won the lock, oracle branch (a) holds instead: the slot
        // was rotated with no debt; retry the scenario on a fresh fixture.)
        let Ok(report1) = report1 else {
            panic!(
                "attempt {attempt}: a committed deployment must never fail (post-commit maintenance)"
            )
        };
        let warning1 = report1.warning.as_deref().unwrap_or("");
        let contended = report1.status == Some(DeploymentStatus::Successful)
            && warning1.contains("rotation deferred for slot 'p1'")
            && warning1.contains("slot lock held by another operation")
            && !f.store.read_rotation_debt("t1").unwrap().is_empty();
        if !contended {
            continue;
        }

        // ---- Step 2: NO-OP with the lock HELD — the deferred maintenance
        // stays deferred (marker kept) and keeps warning. The lock must be
        // held AFTER this push's preflight (which reads the lock fresh) but
        // BEFORE the no-op's deferred-maintenance retry: the write-once
        // protocol marker is removed first so the push's handshake re-creates
        // it as a fresh mid-push signal that the status read is done.
        remote
            .remove_file(&layout::protocol_marker())
            .expect("remove protocol marker for a fresh handshake signal");
        let report2 = std::thread::scope(|s| {
            let push = s.spawn(|| f.push_with_id("t1", &id));
            let _guard = {
                let marker = layout::protocol_marker();
                let mut spins = 0u64;
                while !remote.exists(&marker) {
                    std::thread::yield_now();
                    spins += 1;
                    assert!(
                        spins < 20_000_000,
                        "attempt {attempt}: the no-op push never handshaked"
                    );
                }
                // The no-op path holds the lock nowhere before its deferred-
                // maintenance retry, so the acquire lands immediately and is
                // certain to precede the retry (the no-op check still runs its
                // verification subprocess in between).
                loop {
                    if let Ok(g) = helper.acquire_lock_guard(holder) {
                        break g;
                    }
                    std::thread::yield_now();
                    spins += 1;
                    assert!(
                        spins < 20_000_000,
                        "attempt {attempt}: the mutation lock stayed acquired"
                    );
                }
            };
            push.join().expect("push thread panicked")
        });
        let Ok(report2) = report2 else {
            panic!(
                "attempt {attempt}: the no-op must never fail because its maintenance retry contended"
            )
        };
        let warning2 = report2.warning.as_deref().unwrap_or("");
        let still_deferred = report2.message == "Everything up to date"
            && report2.status.is_none()
            && warning2.contains("rotation still deferred for slot 'p1'")
            && warning2.contains("slot lock held by another operation")
            && !f.store.read_rotation_debt("t1").unwrap().is_empty();
        if !still_deferred {
            continue;
        }
        // Step 2's guard drops here (lock released).

        // ---- Step 3: the FIRST no-op with the lock FREE services the
        // deferred rotation: the marker is cleared, no warning remains.
        let report3 = f.push("t1").expect("the retrying push succeeds");
        assert_eq!(report3.message, "Everything up to date");
        assert_eq!(
            report3.status, None,
            "the retrying push is an up-to-date no-op"
        );
        assert!(
            report3.warning.is_none(),
            "the maintenance succeeded on the unlocked no-op, so no warning remains"
        );
        assert!(
            f.store.read_rotation_debt("t1").unwrap().is_empty(),
            "the debt marker must be cleared once the rotation succeeds"
        );
        f.check_invariants();
        return;
    }
    panic!(
        "the held-lock step-17 contention was never observed in 16 attempts; \
         the engine's own rotation kept winning the lock race"
    );
}

/// Lifecycle: a failure at the FIRST I/O boundary (the intent persist) must
/// abort BEFORE any remote mutation — no `current`, no generation — and a
/// clean retry succeeds.
#[test]
fn state_machine_lifecycle_intent_persist_leaves_remote_untouched() {
    let f = Fixture::new();
    let id = DeploymentId::new("si-intent-fault".to_string());
    let err = {
        f.arm_store_fault(FailureStep::IntentPersist, &id);
        f.push_with_id("t1", &id)
            .err()
            .expect("the intent persist fault must abort the push")
    };
    assert!(
        err.to_string().contains("append_attempt"),
        "error must name the injected fault, got: {err}"
    );
    assert!(
        !f.remote().exists(&layout::current()),
        "no remote current pointer before the intent is durable"
    );
    assert_eq!(
        f.remote().list(layout::generations()).unwrap().len(),
        0,
        "no generation may be created before the intent is durable"
    );
    assert!(
        f.store.read_attempts("t1").unwrap().is_empty(),
        "no attempt record when the intent persist failed"
    );
    // A clean push proceeds normally and every invariant holds.
    let r = f.push("t1").expect("the clean follow-up push succeeds");
    assert_eq!(r.status, Some(DeploymentStatus::Successful));
    f.check_invariants();
}

/// Lifecycle: a failure at the fleet-commit marker write (after activation,
/// before durable commit) leaves the attempt PendingCommit — never reported
/// fully successful anywhere — and a retry converges to exactly one snapshot
/// with no duplicated history.
#[test]
fn state_machine_lifecycle_pending_commit_recovery_no_duplicate_history() {
    let f = Fixture::new();
    f.apply(Action::InjectFailure(FailureStep::CommitMarkerWrite));
    let Outcome::Push(res) = f.apply(Action::Push("t1")) else {
        panic!("expected a push outcome");
    };
    let r1 = res.expect("marker-write failure is reported, not fatal");
    assert_eq!(
        r1.status,
        Some(DeploymentStatus::PendingCommit),
        "the failed fleet commit must be reported PendingCommit"
    );
    let attempt = r1.attempt.expect("the attempt is recorded");
    let id = attempt.deployment_id.clone();
    // Not reported fully successful ANYWHERE.
    assert!(
        f.store.read_snapshots("t1").unwrap().is_empty(),
        "no snapshot for a pending attempt"
    );
    assert!(
        f.store.read_last_successful("t1").is_none(),
        "refs/last-successful must not point at a pending attempt"
    );
    assert_eq!(
        f.store.latest_status(id.as_str()).unwrap(),
        Some(DeploymentStatus::PendingCommit)
    );
    // Recoverable: intent and outcomes are durable.
    assert!(
        f.store.read_results(id.as_str()).is_ok(),
        "outcomes durable"
    );
    f.check_invariants();

    // The no-op retry reconciles and finalizes exactly once.
    let r2 = f.push("t1").expect("the retrying push succeeds");
    assert_eq!(r2.message, "Everything up to date");
    assert_eq!(r2.status, None);
    let snapshots = f.store.read_snapshots("t1").unwrap();
    assert_eq!(snapshots.len(), 1, "exactly one snapshot after recovery");
    assert_eq!(
        f.store.read_last_successful("t1").as_deref(),
        Some(id.as_str())
    );
    assert_eq!(
        f.store.latest_status(id.as_str()).unwrap(),
        Some(DeploymentStatus::Successful)
    );
    f.check_invariants();

    // A further retry is fully idempotent: no duplicate history.
    let r3 = f.push("t1").expect("third push succeeds");
    assert_eq!(r3.status, None);
    assert_eq!(f.store.read_snapshots("t1").unwrap().len(), 1);
    assert_eq!(f.store.read_attempts("t1").unwrap().len(), 1);
    f.check_invariants();
}

/// One SHORT mixed sequence: build -> push -> rollback -> rotate -> retry,
/// checking all five invariant groups after every action.
#[test]
fn state_machine_mixed_sequence_invariants() {
    let f = Fixture::new();
    f.apply(Action::Build(1));
    let r = f.apply(Action::Push("t1"));
    let Outcome::Push(res) = r else {
        panic!("expected push")
    };
    res.expect("push t1 succeeds");

    f.apply(Action::Build(2));
    let r = f.apply(Action::Push("t2"));
    let Outcome::Push(res) = r else {
        panic!("expected push")
    };
    res.expect("push t2 succeeds");

    // Rollback t1 to its own f0 (tree v1) and t2 to f0 (tree v2).
    let r = f.apply(Action::Rollback("t1", 0));
    let Outcome::Push(res) = r else {
        panic!("expected push")
    };
    res.expect("rollback t1 succeeds");

    let r = f.apply(Action::Rotate);
    assert!(matches!(r, Outcome::Ok));

    let r = f.apply(Action::Retry("t2"));
    let Outcome::Push(res) = r else {
        panic!("expected push")
    };
    res.expect("no-op retry succeeds");
    f.check_invariants();
}

// ===========================================================================
// Property tests — Observed scope (push / fail / retry / rollback sequences)
// ===========================================================================

/// (a) Crash BEFORE the observed refresh on a SHARED slot: the very first
/// push on t1 aborts AFTER the remote advanced but BEFORE the observed
/// refresh (a faulted `write_results`), so the shared slot's observed entry
/// is ABSENT in BOTH member targets (t1 never refreshed, t2 never saw a
/// propagation). The recovery is an up-to-date no-op retry (reconcile then
/// "Everything up to date"); the no-op path must refresh the projections, so
/// after recovery every member target's observed slot for `p1` equals the
/// remote assignment.
#[test]
fn observed_scope_crash_before_refresh_recovered_by_noop_retry() {
    let f = Fixture::new();
    f.apply(Action::Build(1));
    let id = DeploymentId::new("si-obs-crash-before-refresh");
    let err = {
        f.arm_store_fault(FailureStep::ResultsWrite, &id);
        f.push_with_id("t1", &id)
            .err()
            .expect("the faulted push aborts before the observed refresh")
    };
    assert!(
        err.to_string().contains("test fault"),
        "error must name the injected fault, got: {err}"
    );
    // The crash window: the remote advanced (an assignment exists) but the
    // observed projections were never refreshed — both member targets have no
    // entry for the shared slot.
    f.current_assignment()
        .expect("remote advanced past the crash");
    for t in ["t1", "t2"] {
        let observed = f.store.read_observed(t).unwrap();
        assert!(
            observed.slots.get(&PlacementSlotId::new("p1")).is_none(),
            "{t}: the crash window must leave the shared slot's observed entry absent"
        );
    }

    // Recovery: the no-op retry reconciles the aborted attempt and returns
    // "Everything up to date" — and must refresh the observed projection in
    // BOTH member targets.
    let r = f.apply(Action::Retry("t1"));
    let Outcome::Push(res) = r else {
        panic!("expected a push outcome");
    };
    let report = res.expect("the no-op retry succeeds");
    assert_eq!(report.message, "Everything up to date");
    assert_eq!(report.status, None);
    f.assert_observed_scope_property();
    f.check_invariants();
}

/// (b) Rollback on ONE target: a fleet rollback is a REAL push; its observed
/// refresh must land the rolled-back assignment in EVERY member target's
/// projection, so after rolling t1 back to its own `@f0` both t1 and t2
/// observe the restored assignment (generation + artifact).
#[test]
fn observed_scope_rollback_refreshes_every_member_projection() {
    let f = Fixture::new();
    f.apply(Action::Build(1));
    f.apply(Action::Push("t1")); // remote v1
    f.apply(Action::Build(2));
    f.apply(Action::Push("t2")); // remote v2
    f.assert_observed_scope_property();

    let r = f.apply(Action::Rollback("t1", 0)); // back to tree v1
    let Outcome::Push(res) = r else {
        panic!("expected a push outcome");
    };
    let report = res.expect("rollback t1 succeeds");
    assert_eq!(report.status, Some(DeploymentStatus::Successful));
    f.assert_observed_scope_property();
    f.check_invariants();
}

/// (c) Failed push BEFORE any remote mutation (a preflight failure): the
/// observed projections must be untouched — and they still equal the
/// UNCHANGED remote assignment (no stale entry from the failed attempt).
#[test]
fn observed_scope_preflight_failure_leaves_observed_equal() {
    let f = Fixture::new();
    f.apply(Action::Build(1));
    f.apply(Action::Push("t1"));
    f.assert_observed_scope_property();
    let t1_before = f.store.read_observed("t1").unwrap();
    let t2_before = f.store.read_observed("t2").unwrap();

    // HEAD advances to v2 so the t2 push is a REAL push (not an up-to-date
    // no-op, which never persists an attempt) — it then fails at the intent
    // persist, BEFORE any remote mutation.
    f.apply(Action::Build(2));
    let id = DeploymentId::new("si-obs-preflight");
    let err = {
        f.arm_store_fault(FailureStep::IntentPersist, &id);
        f.push_with_id("t2", &id)
            .err()
            .expect("the preflight failure aborts before any remote mutation")
    };
    assert!(
        err.to_string().contains("append_attempt"),
        "error must name the injected fault, got: {err}"
    );
    assert_eq!(
        f.store.read_observed("t1").unwrap(),
        t1_before,
        "a failed preflight must not change t1's observed"
    );
    assert_eq!(
        f.store.read_observed("t2").unwrap(),
        t2_before,
        "a failed preflight must not change t2's observed"
    );
    f.assert_observed_scope_property();
    f.check_invariants();
}

/// (d) A LONGER interleaved sequence mixing every action across the two
/// shared targets: push t1 -> push t2 -> preflight failure -> rollback ->
/// crash before the observed refresh -> no-op retry recovery -> no-op retry
/// -> mid-flight failure that still returns `Ok` (PendingCommit) -> recovery
/// -> rotate. After EVERY completed action and after EVERY recovery the
/// property holds: each member target's observed slot for `p1` equals the
/// remote assignment (generation + artifact) — no absent or stale entries.
/// The faulted pushes use `push_with_id` directly (the fixture never
/// evaluates invariants inside the crash window), and every recovery asserts
/// the property explicitly. The faulted attempts use fixed `si-…` ids that
/// sort AFTER the engine's auto-generated `deploy-…` ids, so once a fixed-id
/// attempt is finalized on a target no later auto-id push runs on that target
/// (the lifecycle "newest successful" check orders ids lexicographically).
#[test]
fn observed_scope_interleaved_push_fail_retry_rollback_sequence() {
    let f = Fixture::new();

    // t1 deploys tree v1 on the shared slot.
    f.apply(Action::Build(1));
    let r = f.apply(Action::Push("t1"));
    let Outcome::Push(res) = r else {
        panic!("expected a push outcome");
    };
    assert_eq!(
        res.expect("push t1 succeeds").status,
        Some(DeploymentStatus::Successful)
    );
    f.assert_observed_scope_property();

    // t2 deploys tree v2 on the shared slot.
    f.apply(Action::Build(2));
    let r = f.apply(Action::Push("t2"));
    let Outcome::Push(res) = r else {
        panic!("expected a push outcome");
    };
    assert_eq!(
        res.expect("push t2 succeeds").status,
        Some(DeploymentStatus::Successful)
    );
    f.assert_observed_scope_property();

    // (c) Preflight failure on t2: HEAD advances to v3 so the t2 push is a
    // real one; it fails at the intent persist BEFORE any remote mutation, so
    // the observed projections stay equal to the unchanged v2 assignment.
    f.apply(Action::Build(3));
    let id_p = DeploymentId::new("si-obs-seq-preflight");
    let err = {
        f.arm_store_fault(FailureStep::IntentPersist, &id_p);
        f.push_with_id("t2", &id_p)
            .err()
            .expect("the preflight push aborts before mutation")
    };
    assert!(err.to_string().contains("append_attempt"), "{err}");
    f.assert_observed_scope_property();

    // (b) Rollback t1 to its own `@f0` (tree v1): a real push whose refresh
    // propagates the restored assignment to BOTH member targets.
    let r = f.apply(Action::Rollback("t1", 0));
    let Outcome::Push(res) = r else {
        panic!("expected a push outcome");
    };
    let report = res.expect("rollback t1 succeeds");
    assert_eq!(report.status, Some(DeploymentStatus::Successful));
    f.assert_observed_scope_property();

    // (a) Crash mid-flight on t1: the remote advances to v3 but the observed
    // refresh never runs — both member projections go stale (they still show
    // the rolled-back v1 assignment).
    let stale = f
        .store
        .read_observed("t1")
        .unwrap()
        .slots
        .get(&PlacementSlotId::new("p1"))
        .expect("observed p1 exists from the earlier push")
        .generation
        .clone();
    let id_c = DeploymentId::new("si-obs-seq-crash");
    let err = {
        f.arm_store_fault(FailureStep::ResultsWrite, &id_c);
        f.push_with_id("t1", &id_c)
            .err()
            .expect("the crash aborts before the observed refresh")
    };
    assert!(err.to_string().contains("test fault"), "{err}");
    let after_crash = f.current_assignment().expect("remote advanced");
    assert_ne!(
        stale.as_ref(),
        Some(&after_crash.generation_id),
        "the crash window must leave the projection stale"
    );

    // Recovery: the no-op retry reconciles and refreshes BOTH member
    // projections to the v3 assignment. No further t1 push runs after this
    // (the fixed `si-obs-seq-crash` id is then the lexicographically newest).
    let r = f.apply(Action::Retry("t1"));
    let Outcome::Push(res) = r else {
        panic!("expected a push outcome");
    };
    let report = res.expect("the recovery retry succeeds");
    assert_eq!(report.message, "Everything up to date");
    f.assert_observed_scope_property();

    // A no-op retry on t2 (remote already at v3): the shared projection
    // refreshes again.
    let r = f.apply(Action::Retry("t2"));
    let Outcome::Push(res) = r else {
        panic!("expected a push outcome");
    };
    assert_eq!(
        res.expect("the no-op retry succeeds").message,
        "Everything up to date"
    );
    f.assert_observed_scope_property();

    // A mid-flight failure that STILL returns Ok: the fleet-commit marker
    // write fails on a fresh t2 push (v4) -> PendingCommit. The observed
    // refresh has already run on that push, so the next retry finalizes and
    // keeps the projections current.
    f.apply(Action::InjectFailure(FailureStep::CommitMarkerWrite));
    f.apply(Action::Build(4));
    let r = f.apply(Action::Push("t2"));
    let Outcome::Push(res) = r else {
        panic!("expected a push outcome");
    };
    let report = res.expect("the pending-commit push succeeds");
    assert_eq!(report.status, Some(DeploymentStatus::PendingCommit));
    f.assert_observed_scope_property();
    let r = f.apply(Action::Retry("t2"));
    let Outcome::Push(res) = r else {
        panic!("expected a push outcome");
    };
    assert_eq!(
        res.expect("the recovery retry succeeds").message,
        "Everything up to date"
    );
    f.assert_observed_scope_property();

    // Wrap up with a standalone rotation under the full member union.
    f.apply(Action::Rotate);
    f.check_invariants();
}

// ===========================================================================
// Property tests — Identity
// ===========================================================================

fn sdef(id: &str, server: &str, dir: &str, targets: &[&str]) -> SlotDef {
    SlotDef {
        id: id.to_string(),
        server: server.to_string(),
        deploy_dir: PathBuf::from(dir),
        targets: targets.iter().map(|t| t.to_string()).collect(),
    }
}

/// Reordering slots, variants, or a slot's targets list preserves the digest.
#[test]
fn identity_reordering_preserves_digest() {
    let mut a: BTreeMap<String, Vec<SlotDef>> = BTreeMap::new();
    a.insert(
        "standard".to_string(),
        vec![
            sdef("p2", "s2", "/srv/p2", &["t1", "t2"]),
            sdef("p1", "s1", "/srv/p1", &["t2", "t1"]),
        ],
    );
    a.insert(
        "canary".to_string(),
        vec![sdef("c1", "s3", "/srv/c1", &["t3"])],
    );

    // Same declarations: slots in the opposite file order, targets lists in
    // the opposite order, variants inserted in the opposite order.
    let mut b: BTreeMap<String, Vec<SlotDef>> = BTreeMap::new();
    b.insert(
        "canary".to_string(),
        vec![sdef("c1", "s3", "/srv/c1", &["t3"])],
    );
    b.insert(
        "standard".to_string(),
        vec![
            sdef("p1", "s1", "/srv/p1", &["t2", "t1"]),
            sdef("p2", "s2", "/srv/p2", &["t1", "t2"]),
        ],
    );
    assert_eq!(
        variant_slots_digest(&a),
        variant_slots_digest(&b),
        "slot/variant/target reordering must not change the digest"
    );

    // The release identity digests agree too.
    let bindings: BTreeMap<String, String> = BTreeMap::from([
        ("standard".to_string(), "t1".to_string()),
        ("canary".to_string(), "t2".to_string()),
    ]);
    assert_eq!(
        release_digest("m", "b", &variant_slots_digest(&a), &bindings),
        release_digest("m", "b", &variant_slots_digest(&b), &bindings)
    );
}

/// Duplicate targets in a slot's declaration are rejected at config load, and
/// a list carrying a duplicate canonicalizes to the same identity as the
/// deduplicated list.
#[test]
fn identity_duplicates_are_rejected_and_canonicalize_identically() {
    // Config-level rejection.
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    let release_dir = project.join("releases").join("v1");
    std::fs::create_dir_all(&release_dir).unwrap();
    let dup_variant = format!(
        "{VARIANT_BODY}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntargets = [\"t1\", \"t1\"]\ndeploy_dir = \"/srv/si\"\n"
    );
    std::fs::write(release_dir.join("standard.toml"), dup_variant).unwrap();
    std::fs::write(project.join("deploy.toml"), DEPLOY_TOML).unwrap();
    assert!(
        Config::load(&project.join("deploy.toml")).is_err(),
        "a slot with a duplicated target name must be rejected"
    );

    // Digest-level: duplicate target names in the list canonicalize to the
    // same identity as the deduplicated list.
    let mut dedup: BTreeMap<String, Vec<SlotDef>> = BTreeMap::new();
    dedup.insert(
        "standard".to_string(),
        vec![sdef("p1", "s1", "/srv/si", &["t1", "t2"])],
    );
    let mut dup: BTreeMap<String, Vec<SlotDef>> = BTreeMap::new();
    dup.insert(
        "standard".to_string(),
        vec![sdef("p1", "s1", "/srv/si", &["t1", "t2", "t1"])],
    );
    assert_eq!(
        variant_slots_digest(&dedup),
        variant_slots_digest(&dup),
        "duplicate target names must canonicalize identically"
    );
    assert_eq!(
        canonicalize_slots(&dup["standard"]).slots[0].targets,
        vec!["t1".to_string(), "t2".to_string()]
    );
}

/// Canonical serialization round-trips to the same identity: an ArtifactRef
/// (and a release id) survives a serialize/deserialize cycle unchanged.
#[test]
fn identity_canonical_serialization_round_trips() {
    let art = ArtifactRef {
        release: ReleaseId::new("rel-sha256-abc".to_string()),
        variant: VariantName::new("standard".to_string()),
        tree: TreeDigest::new("tree-1".to_string()),
    };
    let bytes = serde_json::to_vec(&art).unwrap();
    let back: ArtifactRef = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        art, back,
        "ArtifactRef must round-trip to the same identity"
    );
    assert_eq!(
        serde_json::to_vec(&art).unwrap(),
        serde_json::to_vec(&back).unwrap(),
        "canonical serialization is stable"
    );
    let rid = ReleaseId::parse("rel-sha256-abc");
    assert_eq!(rid.as_str(), "rel-sha256-abc");
    assert_eq!(
        ReleaseId::from_digest(&rid.digest()),
        rid,
        "release id digest round-trips"
    );
}

// ===========================================================================
// Property tests — Scope
// ===========================================================================

/// The shared slot's retained set is the union of every member target's
/// policy: computing with the full member list equals the union of the
/// per-member computations.
#[test]
fn scope_retained_is_union_of_member_policies() {
    let f = Fixture::new();
    // Build history interleaved across both targets.
    for (v, t) in [(1u32, "t1"), (2, "t2"), (3, "t1"), (4, "t2"), (5, "t1")] {
        f.apply(Action::Build(v));
        f.apply(Action::Push(t));
    }
    let (t1, t2, full) = f.with_helper(|helper| {
        let t1 = compute_retained(
            &helper,
            &f.config.pins,
            &f.store,
            &f.config,
            &["t1".to_string()],
        )
        .unwrap();
        let t2 = compute_retained(
            &helper,
            &f.config.pins,
            &f.store,
            &f.config,
            &["t2".to_string()],
        )
        .unwrap();
        let full = compute_retained(
            &helper,
            &f.config.pins,
            &f.store,
            &f.config,
            &["t1".to_string(), "t2".to_string()],
        )
        .unwrap();
        (t1, t2, full)
    });
    let union: HashSet<String> = t1.union(&t2).cloned().collect();
    assert_eq!(
        full, union,
        "the shared slot's retained set must be the union of every member's policy"
    );
}

/// Strengthening a retention policy — more distinct artifacts, a wider age
/// window, protecting the previous — never REDUCES the retained set; neither
/// does adding a member target.
#[test]
fn scope_strengthening_policy_never_reduces_retained() {
    let f = Fixture::new();
    for (v, t) in [(1u32, "t1"), (2, "t2"), (3, "t1"), (4, "t2")] {
        f.apply(Action::Build(v));
        f.apply(Action::Push(t));
    }
    let baseline = |cfg: &Config| -> HashSet<String> {
        f.with_helper(|helper| {
            compute_retained(
                &helper,
                &cfg.pins,
                &f.store,
                cfg,
                &["t1".to_string(), "t2".to_string()],
            )
            .unwrap()
        })
    };
    let weak = baseline(&f.config);

    // Strengthen t1's policy: keep 5 distinct (was 1), protect the previous,
    // protect 2 fleet deployments.
    let mut strong_config = f.config.clone();
    let r = strong_config.targets.get_mut("t1").unwrap();
    r.rotation.per_server.keep_distinct_artifacts = 5;
    r.rotation.per_server.protect_previous = true;
    r.rotation.fleet.protect_deployments = 2;
    let strong = baseline(&mut strong_config);
    assert!(
        strong.is_superset(&weak),
        "strengthening a retention policy must never reduce the retained set"
    );

    // Widening the age window is monotone too.
    let mut wider = strong_config.clone();
    wider
        .targets
        .get_mut("t1")
        .unwrap()
        .rotation
        .per_server
        .keep_days = 90;
    let wider_retained = baseline(&mut wider);
    assert!(
        wider_retained.is_superset(&strong),
        "widening keep_days must never reduce the retained set"
    );

    // Adding a member target never reduces the retained set.
    let single: HashSet<String> = f.with_helper(|helper| {
        compute_retained(
            &helper,
            &f.config.pins,
            &f.store,
            &f.config,
            &["t1".to_string()],
        )
        .unwrap()
    });
    assert!(
        weak.is_superset(&single),
        "adding a member target must never reduce the retained set"
    );
}

// ===========================================================================
// Property tests — Lifecycle
// ===========================================================================

/// Inject a one-shot store failure at EVERY post-activation persistence step
/// (outcomes, snapshot, last-successful, terminal Successful transition, the
/// recoverable PendingCommit marker). Each leaves the attempt recoverable and
/// never reported fully successful; a clean retry converges to exactly one
/// snapshot / ref / marker / Successful transition — no duplicate history.
#[test]
fn lifecycle_store_fault_matrix_recovers_without_duplicate_history() {
    for (i, step) in [
        FailureStep::ResultsWrite,
        FailureStep::SnapshotAppend,
        FailureStep::LastSuccessfulWrite,
        FailureStep::TransitionSuccessful,
        FailureStep::TransitionPending,
    ]
    .into_iter()
    .enumerate()
    {
        let f = Fixture::new();
        let id = DeploymentId::new(format!("si-lc-fault-{i}"));
        let err = {
            f.arm_store_fault(step, &id);
            f.push_with_id("t1", &id)
                .err()
                .expect("the injected persistence fault must abort the push")
        };
        assert!(
            err.to_string().contains("test fault"),
            "{step:?}: error must name the injected fault, got: {err}"
        );
        // Never reported fully successful anywhere: the LATEST transition is
        // recoverable (PendingCommit / InProgress), never `Successful`. (For
        // the later finalization steps the snapshot / last-successful may
        // already be durable — the attempt is still not terminal.)
        assert!(
            matches!(
                f.store.latest_status(id.as_str()).unwrap(),
                Some(DeploymentStatus::PendingCommit) | Some(DeploymentStatus::InProgress)
            ),
            "{step:?}: the crash window must leave the attempt recoverable, never Successful"
        );

        // Clean retry converges to exactly one final state.
        let r2 = f.push("t1").expect("the retrying push succeeds");
        assert_eq!(r2.message, "Everything up to date");
        assert_eq!(r2.status, None, "{step:?}: retry is an up-to-date no-op");
        let snapshots = f.store.read_snapshots("t1").unwrap();
        assert_eq!(
            snapshots.len(),
            1,
            "{step:?}: exactly one snapshot after recovery"
        );
        assert_eq!(
            f.store.read_last_successful("t1").as_deref(),
            Some(id.as_str()),
            "{step:?}: refs/last-successful points at the recovered attempt"
        );
        assert_eq!(
            f.store.latest_status(id.as_str()).unwrap(),
            Some(DeploymentStatus::Successful),
            "{step:?}: latest transition finalized as Successful"
        );
        assert_eq!(
            f.store.read_attempts("t1").unwrap().len(),
            1,
            "{step:?}: the replay must not record a new attempt"
        );
        // Idempotent replay: no duplicate history.
        let r3 = f.push("t1").unwrap();
        assert_eq!(r3.status, None);
        assert_eq!(f.store.read_snapshots("t1").unwrap().len(), 1);
        f.check_invariants();
    }
}

/// Lifecycle: EVERY store operation in the observed-refresh block — the code
/// AFTER the durable commit point — is post-commit maintenance. Armed one at
/// a time (the per-server `write_server`, the push's OWN target
/// `write_observed`, and the OTHER member target's `write_observed` via the
/// shared-slot propagation), a one-shot store fault must NEVER turn the push
/// into an `Err`: the deployment is already durably `Successful` (snapshot,
/// attempt, and terminal transition recorded BEFORE the refresh runs), so the
/// push returns `Ok` with that status and the report carries a warning naming
/// the deferred observed refresh. No persistent debt marker is needed (unlike
/// rotation): the observed maps are projections of already-durable facts, and
/// a clean no-op retry converges WITHOUT duplicate history — snapshot count,
/// attempt count, transition stream, and `refs/last-successful` all stay
/// exactly-once.
///
/// AUDIT NOTE (the previously-missed fault matrix): with the old
/// process-global slots, this matrix armed its observed-refresh faults
/// WITHOUT holding FAULT_LOCK — a concurrent test could clobber or
/// consume the armed slot. The per-fixture registry makes the matrix
/// structurally safe: the arm lives on THIS fixture's registry and only THIS
/// fixture's store can consume it, so no lock window is needed.
#[test]
fn lifecycle_observed_refresh_faults_never_fail_after_commit() {
    for (i, step) in [
        FailureStep::ObservedWriteServer,
        FailureStep::ObservedPrimaryWrite,
        FailureStep::ObservedOtherWrite,
    ]
    .into_iter()
    .enumerate()
    {
        let f = Fixture::new();
        let id = DeploymentId::new(format!("si-obs-fault-{i}"));
        f.arm_store_fault(step, &id);
        let r1 = f
            .push_with_id("t1", &id)
            .expect("{step:?}: a push past the durable commit point must never fail");
        assert_eq!(
            r1.status,
            Some(DeploymentStatus::Successful),
            "{step:?}: the deployment committed; the observed fault must not change its outcome"
        );
        assert!(
            r1.attempt.is_some(),
            "{step:?}: the committed deployment records its attempt"
        );
        let warning = r1
            .warning
            .as_ref()
            .expect("{step:?}: the push must warn about the deferred observed refresh");
        assert!(
            warning.contains("observed refresh deferred"),
            "{step:?}: the warning names the deferred observed refresh, got: {warning}"
        );
        // Durable state is exactly-once: one snapshot, one attempt, the
        // terminal Successful transition, and `refs/last-successful` bound.
        assert_eq!(
            f.store.read_snapshots("t1").unwrap().len(),
            1,
            "{step:?}: exactly one snapshot entry"
        );
        assert_eq!(
            f.store.read_attempts("t1").unwrap().len(),
            1,
            "{step:?}: exactly one attempt record"
        );
        assert_eq!(
            f.store.latest_status(id.as_str()).unwrap(),
            Some(DeploymentStatus::Successful),
            "{step:?}: the terminal transition is Successful"
        );
        assert_eq!(
            f.store.read_transitions(id.as_str()).unwrap().len(),
            3,
            "{step:?}: exactly InProgress + PendingCommit + Successful — no duplicate transitions"
        );
        assert_eq!(
            f.store.read_last_successful("t1").as_deref(),
            Some(id.as_str()),
            "{step:?}: refs/last-successful points at the committed attempt"
        );
        assert!(
            f.store.read_rotation_debt("t1").unwrap().is_empty(),
            "{step:?}: observed refresh needs no persistent debt marker — the next real push \
             re-projects from durable facts"
        );
        // `check_invariants` is deliberately NOT evaluated in the crash-window
        // state here: the faulted refresh deferred the projection (the strict
        // `check_scope` contract permits absence only inside the crash window,
        // "never evaluated by check_invariants"). The no-op retry below closes
        // the window by re-projecting from the EXISTING assignment; the
        // invariant is checked AFTER it, where every member target's projection
        // must be present.

        // The faulted-then-clean NO-OP retry converges without duplicate
        // history: the no-op path creates no records, so the durable history
        // stays exactly-once and `refs/last-successful` is stable.
        let r2 = f.push("t1").expect("{step:?}: the retrying push succeeds");
        assert_eq!(r2.message, "Everything up to date");
        assert_eq!(
            r2.status, None,
            "{step:?}: the retry is an up-to-date no-op"
        );
        assert!(
            r2.warning.is_none(),
            "{step:?}: the no-op retry creates no new maintenance and does not re-warn"
        );
        assert_eq!(f.store.read_snapshots("t1").unwrap().len(), 1);
        assert_eq!(f.store.read_attempts("t1").unwrap().len(), 1);
        assert_eq!(
            f.store.read_last_successful("t1").as_deref(),
            Some(id.as_str()),
            "{step:?}: refs/last-successful unchanged by the retry"
        );
        assert_eq!(
            f.store.read_transitions(id.as_str()).unwrap().len(),
            3,
            "{step:?}: no duplicate transitions after the retry"
        );
        // The no-op retry refreshed every member target's projection from the
        // EXISTING assignment (the fault is one-shot and consumed), so the full
        // invariant set — including the strict observed-scope contract — holds.
        f.check_invariants();
        // A further retry is fully idempotent too.
        let r3 = f.push("t1").unwrap();
        assert_eq!(r3.status, None);
        assert_eq!(f.store.read_snapshots("t1").unwrap().len(), 1);
        f.check_invariants();
    }
}

/// Lifecycle: the rotation-debt maintenance I/O is POST-COMMIT maintenance —
/// every debt read/write/remove failure must never turn a push into an `Err`
/// once the deployment is durably committed. The matrix generates
/// {real push, no-op} × {debt read, debt write, debt remove} × {empty,
/// existing debt}. The "debt remove" arm is the same `write_rotation_debt`
/// call as the write (the cleared marker's removal is the empty-map write), so
/// it shares the write arm — the matrix keeps the third column explicit.
///
/// ORACLE per combination:
/// (a) the push returns `Ok` with the committed status — `Successful` for the
///     real push, the "Everything up to date" no-op report for the no-op;
/// (b) HISTORY REMAINS EXACTLY ONCE: one attempt, one snapshot, the terminal
///     `Successful` transition, `refs/last-successful` bound — no duplicates
///     (the no-op creates no records at all);
/// (c) MAINTENANCE EITHER CONVERGES OR REMAINS EXPLICITLY WARNED/DEFERRED:
///     every case that leaves the marker in place must carry a warning naming
///     the deferred debt maintenance (never silently lost, never silently
///     deferred), and a real push whose step-17 rotation succeeded clears the
///     pre-seeded marker even when the earlier retry's debt I/O faulted (the
///     fault is one-shot, so the later clear write succeeds) — the warning
///     from the faulted retry stays on the report.
///
/// The `debtfx` fixture target is pushed ONLY by this test, so the
/// target-keyed one-shot arms (`arm_read_rotation_debt` /
/// `arm_write_rotation_debt`) cannot be consumed by a concurrent test's
/// push. Each case arms THIS fixture's per-fixture registry (a fresh store
/// per case), so no arm can leak between cases or tests either — no lock
/// window and no global slots.
#[test]
fn lifecycle_debt_fault_matrix_never_fails_after_commit() {
    const SLOT: &str = "pdx";
    // Each case owns a fresh fixture whose store holds its own empty
    // registry; arms die with the fixture, so nothing needs clearing and
    // nothing can interleave with another fault-arming test.
    for (i, step) in [
        FailureStep::DebtRead,
        FailureStep::DebtWrite,
        FailureStep::DebtRemove,
    ]
    .into_iter()
    .enumerate()
    {
        for (j, have_debt) in [false, true].into_iter().enumerate() {
            let ctx = format!("{step:?} x have_debt={have_debt}");
            // ---- REAL push: the first push to `debtfx` commits, then the
            // maintenance block retries any pre-seeded debt and runs step 17
            // (which succeeds and clears the marker). ----
            {
                let f = Fixture::new();
                let id = DeploymentId::new(format!("si-debt-fault-{i}-{j}"));
                if have_debt {
                    f.store
                        .write_rotation_debt(
                            "debtfx",
                            &BTreeMap::from([(SLOT.to_string(), "seeded".to_string())]),
                        )
                        .unwrap();
                }
                let r1 = {
                    f.arm_store_fault(step, &id);
                    f.push_with_id("debtfx", &id)
                        .expect("{ctx}: a push past the durable commit point must never fail")
                };
                // (a) the committed status is unchanged by the fault.
                assert_eq!(
                    r1.status,
                    Some(DeploymentStatus::Successful),
                    "{ctx}: the deployment committed; the debt fault must not change its outcome"
                );
                assert!(
                    r1.attempt.is_some(),
                    "{ctx}: a real push records an attempt"
                );
                // (b) history remains EXACTLY ONCE.
                assert_eq!(
                    f.store.read_snapshots("debtfx").unwrap().len(),
                    1,
                    "{ctx}: exactly one snapshot entry"
                );
                assert_eq!(
                    f.store.read_attempts("debtfx").unwrap().len(),
                    1,
                    "{ctx}: exactly one attempt record"
                );
                assert_eq!(
                    f.store.latest_status(id.as_str()).unwrap(),
                    Some(DeploymentStatus::Successful),
                    "{ctx}: the terminal transition is Successful"
                );
                assert_eq!(
                    f.store.read_transitions(id.as_str()).unwrap().len(),
                    3,
                    "{ctx}: exactly InProgress + PendingCommit + Successful — no duplicates"
                );
                assert_eq!(
                    f.store.read_last_successful("debtfx").as_deref(),
                    Some(id.as_str()),
                    "{ctx}: refs/last-successful points at the committed attempt"
                );
                // (c) maintenance either converged or stayed explicitly
                // warned/deferred: a retained marker must be warned about;
                // a warning must name the debt maintenance; the real push's
                // step-17 clear always converges the marker (the one-shot
                // fault is spent by the retry's I/O).
                let debt = f.store.read_rotation_debt("debtfx").unwrap();
                let expect_warning = !matches!(
                    (step, have_debt),
                    (FailureStep::DebtWrite | FailureStep::DebtRemove, false)
                );
                if let Some(w) = &r1.warning {
                    assert!(
                        w.contains("debt"),
                        "{ctx}: the warning names the debt maintenance, got: {w}"
                    );
                }
                assert_eq!(
                    r1.warning.is_some(),
                    expect_warning,
                    "{ctx}: warning presence matches the faulted I/O"
                );
                assert!(
                    debt.is_empty(),
                    "{ctx}: the real push's step-17 rotation succeeded, so the (pre-seeded) \
                     marker must be cleared — the one-shot fault was spent by the retry"
                );
                // A retained marker must never be silent: no case here keeps
                // one, but assert the guard shape anyway.
                assert!(
                    debt.is_empty() || r1.warning.is_some(),
                    "{ctx}: a retained debt marker must be explicitly warned"
                );
                // The arm may not have fired (an empty-debt write case never
                // writes); the stale arm dies with the fixture's registry at
                // the end of this block — the next case starts a fresh fixture
                // with a fresh, empty registry.
            }
            // ---- NO-OP: push once clean, seed the debt (existing cases),
            // arm, then an up-to-date no-op push whose maintenance hook retries
            // the debt before reporting "Everything up to date". ----
            {
                let f = Fixture::new();
                let seed_id = DeploymentId::new(format!("si-debt-seed-{i}-{j}"));
                let r0 = f
                    .push_with_id("debtfx", &seed_id)
                    .expect("seed push succeeds");
                assert_eq!(r0.status, Some(DeploymentStatus::Successful));
                if have_debt {
                    f.store
                        .write_rotation_debt(
                            "debtfx",
                            &BTreeMap::from([(SLOT.to_string(), "seeded".to_string())]),
                        )
                        .unwrap();
                }
                let r2 = {
                    f.arm_store_fault(step, &seed_id);
                    f.push("debtfx")
                        .expect("{ctx}: a no-op past the durable commit point must never fail")
                };
                // (a) the no-op report is unchanged by the fault.
                assert_eq!(r2.message, "Everything up to date");
                assert_eq!(
                    r2.status, None,
                    "{ctx}: the retrying push is an up-to-date no-op"
                );
                // (b) history exactly ONCE — the no-op created no records.
                assert_eq!(
                    f.store.read_snapshots("debtfx").unwrap().len(),
                    1,
                    "{ctx}: the no-op adds no snapshot"
                );
                assert_eq!(
                    f.store.read_attempts("debtfx").unwrap().len(),
                    1,
                    "{ctx}: the no-op adds no attempt"
                );
                assert_eq!(
                    f.store.latest_status(seed_id.as_str()).unwrap(),
                    Some(DeploymentStatus::Successful),
                    "{ctx}: the seed deployment stays Successful"
                );
                assert_eq!(
                    f.store.read_last_successful("debtfx").as_deref(),
                    Some(seed_id.as_str()),
                    "{ctx}: refs/last-successful unchanged by the no-op"
                );
                // (c) with a pre-seeded marker the no-op's retry serviced the
                // debt and either cleared it (no fault) or left it retained
                // WITH a warning naming the deferred maintenance; with no
                // marker and a read fault the report warns about the failed
                // read; with no marker and a write/remove fault nothing is
                // written, the arm never fires, and nothing is warned.
                let debt = f.store.read_rotation_debt("debtfx").unwrap();
                let expect_warning = !matches!(
                    (step, have_debt),
                    (FailureStep::DebtWrite | FailureStep::DebtRemove, false)
                );
                assert_eq!(
                    r2.warning.is_some(),
                    expect_warning,
                    "{ctx}: warning presence must match the faulted I/O"
                );
                if let Some(w) = &r2.warning {
                    assert!(
                        w.contains("debt"),
                        "{ctx}: the warning names the debt maintenance, got: {w}"
                    );
                }
                assert_eq!(
                    !debt.is_empty(),
                    have_debt,
                    "{ctx}: a pre-seeded marker survives the faulted no-op retry (never silently \
                     lost); an empty debt stays empty"
                );
                assert!(
                    debt.is_empty() || r2.warning.is_some(),
                    "{ctx}: a retained marker must be explicitly warned — never silently deferred"
                );
            }
        }
    }
}

// ===========================================================================
// Property tests — Integrity
// ===========================================================================

/// Delete each required field of a stored release record individually: the
/// record must fail closed (unreadable or unverifiable), never silently
/// accepted.
#[test]
fn integrity_stored_release_per_field_deletion_fails_closed() {
    let f = Fixture::new();
    f.apply(Action::Push("t1"));
    let releases_root = f.store.base().join(layout::RELEASES);
    let p = std::fs::read_dir(&releases_root)
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .path()
        .join("release.json");
    for field in [
        "release_schema_version",
        "release_id",
        "release_sha256",
        "created_at",
        "provenance",
        "variants",
    ] {
        let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        v.as_object_mut().unwrap().remove(field);
        let tampered = serde_json::to_string(&v).unwrap();
        // Deleting a required field makes the record unreadable or
        // unverifiable — never silently accepted.
        let result = (|| -> Result<()> {
            let rec: crate::model::ReleaseRecord = serde_json::from_str(&tampered)?;
            verify_release_identity(&rec)?;
            Ok(())
        })();
        assert!(
            result.is_err(),
            "deleting field '{field}' must fail closed (deserialization or verification)"
        );
    }
}

/// Change each identity-bearing field of a stored release record individually
/// (digest fields, variant binding, slot snapshot): the record must fail
/// closed.
#[test]
fn integrity_identity_field_change_fails_closed() {
    let f = Fixture::new();
    f.apply(Action::Push("t1"));
    let releases_root = f.store.base().join(layout::RELEASES);
    let dir = std::fs::read_dir(&releases_root)
        .unwrap()
        .flatten()
        .next()
        .unwrap();
    let id = ReleaseId::new(dir.file_name().to_string_lossy().into_owned());
    let p = dir.path().join("release.json");

    let original: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    let write = |v: &serde_json::Value| {
        std::fs::write(&p, serde_json::to_vec_pretty(v).unwrap()).unwrap();
    };

    // (a) release_sha256 edited.
    let mut v = original.clone();
    v["release_sha256"] = serde_json::json!("deadbeef".repeat(8));
    write(&v);
    let err = f
        .store
        .read_release(&id)
        .expect_err("edited digest must fail");
    assert!(err.to_string().contains("identity mismatch"));

    // (b) release_id edited (self-consistent new id would need recompute; a
    // bare edit mismatches the recomputed identity).
    let mut v = original.clone();
    v["release_id"] = serde_json::json!(
        "rel-sha256-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    );
    write(&v);
    let err = f
        .store
        .read_release(&id)
        .expect_err("edited release id must fail");
    assert!(err.to_string().contains("identity mismatch"));

    // (c) variant binding edited while the digest fields were left unchanged.
    let mut v = original.clone();
    v["variants"]["standard"] = serde_json::json!("tree-other");
    write(&v);
    let err = f
        .store
        .read_release(&id)
        .expect_err("edited binding must fail");
    assert!(err.to_string().contains("identity mismatch"));

    // (d) slot snapshot edited (deploy_dir moved) with digests retained.
    let mut v = original.clone();
    v["slots"]["standard"]["slots"][0]["deploy_dir"] = serde_json::json!("/srv/elsewhere");
    write(&v);
    let err = f
        .store
        .read_release(&id)
        .expect_err("edited slot snapshot must fail");
    assert!(err.to_string().contains("identity mismatch"));

    // Restore: the fixture's own checks pass again.
    write(&original);
    f.check_invariants();
}

/// Tampering stored content while leaving the digest fields unchanged must
/// fail closed: the digest is never trusted from the stored fields.
#[test]
fn integrity_digest_unchanged_after_tamper_fails_closed() {
    let f = Fixture::new();
    f.apply(Action::Push("t1"));
    let releases_root = f.store.base().join(layout::RELEASES);
    let dir = std::fs::read_dir(&releases_root)
        .unwrap()
        .flatten()
        .next()
        .unwrap();
    let id = ReleaseId::new(dir.file_name().to_string_lossy().into_owned());
    let p = dir.path().join("release.json");
    let original: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    let sha = original["release_sha256"].clone();
    let rid = original["release_id"].clone();

    let mut tampered = original.clone();
    tampered["variants"]["standard"] = serde_json::json!("tree-tampered");
    // The digest fields are explicitly retained — exactly the "trust the
    // stored digest" bug.
    tampered["release_sha256"] = sha.clone();
    tampered["release_id"] = rid.clone();
    std::fs::write(&p, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();
    let err = f
        .store
        .read_release(&id)
        .err()
        .expect("content tamper with retained digest must fail");
    assert!(
        err.to_string().contains("identity mismatch"),
        "error must name the mismatch, got: {err}"
    );

    // An INCOMING tampered record must fail closed at one of the store's two
    // boundaries: `write_release` refuses it before writing (strict behavior)
    // or, if the write is accepted, the read recomputes and refuses it.
    let rec: crate::model::ReleaseRecord =
        serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    let fresh = tempfile::tempdir().unwrap();
    let store2 = LocalStore::with_base(fresh.path().join("store")).unwrap();
    match store2.write_release(&rec) {
        Err(e) => assert!(
            e.to_string().contains("identity mismatch"),
            "incoming verification must refuse the tampered record, got: {e}"
        ),
        Ok(()) => {
            let err = store2
                .read_release(&ReleaseId::new(rec.release_id.clone()))
                .err()
                .expect("a tampered record written to a fresh store must fail at read");
            assert!(err.to_string().contains("identity mismatch"));
        }
    }

    // Restore, and the store verifies again.
    std::fs::write(&p, serde_json::to_vec_pretty(&original).unwrap()).unwrap();
    f.store.read_release(&id).expect("restored record verifies");
}

/// A VALID record (self-consistent content) placed under the WRONG release
/// path must never be usable as that path's release: the read either fails
/// closed (the strict store binds the record to its read path) or hands the
/// caller a record whose `release_id` is provably NOT the requested id — in
/// no case is a caller handed a record masquerading as the requested release.
#[test]
fn integrity_valid_record_under_wrong_release_path_fails_closed() {
    let f = Fixture::new();
    f.apply(Action::Push("t1"));
    let releases_root = f.store.base().join(layout::RELEASES);
    let dir = std::fs::read_dir(&releases_root)
        .unwrap()
        .flatten()
        .next()
        .unwrap();
    let real_id = ReleaseId::new(dir.file_name().to_string_lossy().into_owned());
    let bytes = std::fs::read(dir.path().join("release.json")).unwrap();
    // Relocate the VALID record under a different release path.
    let other_id = ReleaseId::new(
        "rel-sha256-0000000000000000000000000000000000000000000000000000000000000000".to_string(),
    );
    let other_dir = f.store.release_dir(&other_id);
    std::fs::create_dir_all(&other_dir).unwrap();
    std::fs::write(other_dir.join("release.json"), &bytes).unwrap();
    match f.store.read_release(&other_id) {
        Err(e) => assert!(
            e.to_string()
                .contains("does not match the requested release id"),
            "a record under the wrong release path must fail closed, got: {e}"
        ),
        Ok(rec) => assert_ne!(
            rec.release_id,
            other_id.as_str(),
            "the store must never return a record masquerading as the requested release"
        ),
    }
    // The original path still reads fine.
    f.store
        .read_release(&real_id)
        .expect("the true path still verifies");
}

/// A tampered stored release record blocks a historical push end-to-end: the
/// rollback/release-ref preflight fails closed instead of deploying the
/// tampered identity.
#[test]
fn integrity_tampered_stored_release_blocks_historical_push() {
    let f = Fixture::new();
    f.apply(Action::Push("t1"));
    let releases_root = f.store.base().join(layout::RELEASES);
    let dir = std::fs::read_dir(&releases_root)
        .unwrap()
        .flatten()
        .next()
        .unwrap();
    let id = ReleaseId::new(dir.file_name().to_string_lossy().into_owned());
    let p = dir.path().join("release.json");
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    // Tamper the slot snapshot (an identity-bearing field) with digests
    // retained. The push reads the release through `read_release`, which
    // recomputes and verifies — it must fail closed before anything deploys.
    v["slots"]["standard"]["slots"][0]["deploy_dir"] = serde_json::json!("/srv/elsewhere");
    std::fs::write(&p, serde_json::to_vec_pretty(&v).unwrap()).unwrap();

    let err = f
        .push_ref_impl("t1", id.as_str())
        .err()
        .expect("a historical push against a tampered stored release must fail closed");
    assert!(
        err.to_string().contains("identity mismatch"),
        "error must name the identity mismatch, got: {err}"
    );
}

/// A tampered stored `behavior.json` (an identity-bearing field changed while
/// the release record's provenance `behavior_sha256` is retained) blocks a
/// historical push end-to-end: the release-ref preflight fails closed instead
/// of restoring the tampered contract.
#[test]
fn integrity_tampered_stored_behavior_json_blocks_historical_push() {
    let f = Fixture::new();
    f.apply(Action::Push("t1"));
    f.tamper(TamperKind::StoredBehaviorJson);

    // The tampered snapshot's canonical digest no longer matches the release
    // record's provenance: the historical read fails closed with an integrity
    // error naming the mismatch, surfaced through the historical-behavior
    // preflight.
    let releases_root = f.store.base().join(layout::RELEASES);
    let dir = std::fs::read_dir(&releases_root)
        .unwrap()
        .flatten()
        .next()
        .unwrap();
    let id = ReleaseId::new(dir.file_name().to_string_lossy().into_owned());
    let err = f
        .push_ref_impl("t1", id.as_str())
        .err()
        .expect("a historical push against a tampered behavior snapshot must fail closed");
    let msg = err.to_string();
    assert!(
        msg.contains("digest mismatch"),
        "error must name the behavior digest mismatch, got: {msg}"
    );
    assert!(
        msg.contains("historical behavior"),
        "error must surface through the historical-behavior preflight, got: {msg}"
    );
    // And the direct historical read fails closed too.
    let rerr = f
        .store
        .read_release_behaviors(&id)
        .err()
        .expect("the historical behavior read must fail closed");
    assert!(
        rerr.to_string().contains("digest mismatch"),
        "read error must name the digest mismatch, got: {rerr}"
    );
}

/// The schema-version property, end-to-end: a stored release record whose
/// `release_schema_version` was rewritten to any arbitrary `u32` value other
/// than [`crate::model::RELEASE_RECORD_SCHEMA_VERSION`] must fail closed on
/// every read and block the next push — never silently accepted, never
/// republished. The dedicated [`TamperKind::StoredReleaseSchemaVersion`]
/// action rewrites the field; the matrix here sweeps the full representative
/// arbitrary-u32 set (0, version - 1, version + 1, 3, u32::MAX).
#[test]
fn integrity_stored_release_schema_version_tamper_fails_closed() {
    let f = Fixture::new();
    f.apply(Action::Push("t1"));
    let releases_root = f.store.base().join(layout::RELEASES);
    let dir = std::fs::read_dir(&releases_root)
        .unwrap()
        .flatten()
        .next()
        .unwrap();
    let id = ReleaseId::new(dir.file_name().to_string_lossy().into_owned());
    let p = dir.path().join("release.json");

    // The pristine record reads fine.
    f.store.read_release(&id).expect("pristine record reads");

    // Sweep every non-canonical member of the arbitrary-u32 set: the read
    // must fail closed naming the version, and a historical push against the
    // tampered record must fail closed too.
    let write_version = |v: u32| {
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        value["release_schema_version"] = serde_json::json!(v);
        std::fs::write(&p, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    };
    let versions = [
        0u32,
        crate::model::RELEASE_RECORD_SCHEMA_VERSION.wrapping_sub(1),
        crate::model::RELEASE_RECORD_SCHEMA_VERSION.wrapping_add(1),
        3,
        u32::MAX,
    ];
    for v in versions {
        write_version(v);
        let err = f
            .store
            .read_release(&id)
            .err()
            .expect("a non-canonical record version must fail closed on read");
        let msg = err.to_string();
        assert!(
            msg.contains("release_schema_version"),
            "error must name the version field, got: {msg}"
        );
        assert!(
            msg.contains(&format!("{v}")),
            "error must name the stored version {v}, got: {msg}"
        );
        assert!(
            msg.contains("RELEASE_RECORD_SCHEMA_VERSION"),
            "error must name the accepted version, got: {msg}"
        );
        let push_err = f
            .push_ref_impl("t1", id.as_str())
            .err()
            .expect("a push against a tampered record version must fail closed");
        assert!(
            push_err.to_string().contains("release_schema_version"),
            "push error must name the version mismatch, got: {push_err}"
        );
    }

    // Restoring the canonical version restores readability (the tamper is
    // reversible; the record itself is unchanged otherwise).
    write_version(crate::model::RELEASE_RECORD_SCHEMA_VERSION);
    f.store
        .read_release(&id)
        .expect("the canonical version reads");
    f.push_ref_impl("t1", id.as_str())
        .expect("a push against the restored record succeeds");

    // And the dedicated Tamper action rewrites the field the same way.
    let f2 = Fixture::new();
    f2.apply(Action::Push("t1"));
    f2.apply(Action::Tamper(TamperKind::StoredReleaseSchemaVersion));
    let releases_root = f2.store.base().join(layout::RELEASES);
    let dir = std::fs::read_dir(&releases_root)
        .unwrap()
        .flatten()
        .next()
        .unwrap();
    let id = ReleaseId::new(dir.file_name().to_string_lossy().into_owned());
    let err = f2
        .store
        .read_release(&id)
        .err()
        .expect("the Tamper action's rewritten version must fail closed on read");
    assert!(
        err.to_string().contains("release_schema_version"),
        "error must name the version field, got: {err}"
    );
}

/// Incoming (not yet stored) attempt and transition records reject every
/// required-field deletion: a torn record never deserializes into a usable
/// fact.
#[test]
fn integrity_incoming_record_field_deletion_fails_closed() {
    let f = Fixture::new();
    f.apply(Action::Push("t1"));
    let attempts_path = f.store.target_dir("t1").join("attempts.jsonl");
    let line = std::fs::read_to_string(&attempts_path).unwrap();
    for field in [
        "deployment_id",
        "target",
        "slot_ids",
        "behavior_sha256",
        "attempted_at",
        "desired",
        "pre_push",
    ] {
        let mut v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        v.as_object_mut().unwrap().remove(field);
        let tampered = serde_json::to_string(&v).unwrap();
        let rec: std::result::Result<crate::records::DeploymentAttempt, _> =
            serde_json::from_str(&tampered);
        assert!(
            rec.is_err(),
            "deleting attempt field '{field}' must fail deserialization"
        );
    }
    // Transitions: every required field rejected individually.
    let attempts = f.store.read_attempts("t1").unwrap();
    let dep_id = attempts[0].deployment_id.as_str();
    let transitions_path = f.store.deployment_dir(dep_id).join("transitions.jsonl");
    let lines: Vec<String> = std::fs::read_to_string(&transitions_path)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    for field in ["deployment_id", "status", "recorded_at"] {
        let mut v: serde_json::Value = serde_json::from_str(lines[0].trim()).unwrap();
        v.as_object_mut().unwrap().remove(field);
        let tampered = serde_json::to_string(&v).unwrap();
        let rec: std::result::Result<crate::records::DeploymentTransition, _> =
            serde_json::from_str(&tampered);
        assert!(
            rec.is_err(),
            "deleting transition field '{field}' must fail deserialization"
        );
    }
}

// ===========================================================================
// Property tests — Bounds
// ===========================================================================

/// Compare the production capacity decision against a u128 reference model
/// over the full value grid (0, 1, avail-1, avail, avail+1, MAX-1, MAX across
/// avail in {0, 1, 1000, MAX-1, MAX}): the decision must agree with the
/// overflow-free u128 addition everywhere, and no input may panic or wrap.
#[test]
fn bounds_capacity_matches_u128_reference_over_grid() {
    for (need, reserve, avail) in bounds_grid() {
        let fits = capacity_fits(need, reserve, avail);
        let reference = (need as u128) + (reserve as u128) <= avail as u128;
        assert_eq!(
            fits, reference,
            "capacity decision for need={need} reserve={reserve} avail={avail} must match the u128 reference model"
        );
    }
}

/// Explicit boundary corners: the decision is total (every input), exact at
/// the boundary, and the extreme values fail safely.
#[test]
fn bounds_capacity_edge_corners_fail_safely() {
    // No reserve, no need: fits.
    assert!(capacity_fits(0, 0, 0));
    assert!(capacity_fits(1, 0, 1));
    assert!(!capacity_fits(1, 0, 0), "need > avail must fail");
    // Reserve alone exceeds available.
    assert!(!capacity_fits(0, 1, 0));
    // Exact boundary: need + reserve == available fits.
    assert!(capacity_fits(6000, 4000, 10_000));
    // One more byte fails.
    assert!(!capacity_fits(6000, 4001, 10_000));
    // u64::MAX-sized filesystem: exact fit and one past it.
    assert!(capacity_fits(u64::MAX - 6000, 0, u64::MAX));
    assert!(capacity_fits(0, u64::MAX, u64::MAX));
    assert!(
        !capacity_fits(1, u64::MAX, u64::MAX),
        "need+reserve must never wrap past MAX"
    );
    assert!(!capacity_fits(u64::MAX, u64::MAX, u64::MAX));
    assert!(!capacity_fits(u64::MAX, 1, u64::MAX));
    assert!(capacity_fits(u64::MAX, 0, u64::MAX));
}

// ===========================================================================
// Property-based state machine — Model oracle + bounded random action vectors
// ===========================================================================

/// The MODEL oracle for the state machine: a lightweight, deterministic
/// reimplementation of the semantic ground truth the five invariant groups
/// pin down, driven by the SAME [`Action`] stream as the [`Fixture`].
///
/// It does NOT reimplement the engine; it tracks only the invariants'
/// expected observable state:
///
/// * [`Model::head_version`] — the artifact content version the next HEAD
///   push materializes (updated by [`Action::Build`]);
/// * the remote `current` generation's expected content version;
/// * each member target's expected observed projection (a completed
///   push/rollback propagates the shared slot to BOTH members);
/// * the per-target fleet-snapshot log (`t@f{i}` rollback refs) and the
///   deployment-attempt log (one entry per real deployment);
/// * pending-commit state — a CommitMarker-write fault leaves the attempt
///   un-finalized until the next push of that target reconciles it (or
///   degrades it, when the remote current has since diverged);
/// * rotation-debt markers — an inventory-write fault after commit defers
///   the post-commit rotation to a later push (including no-ops, which
///   service the marker);
/// * the tamper flag — [`Action::Tamper`] deliberately breaks the live
///   assignment's identity until the next real push replaces the record.
///
/// Everything is derived from the action stream ALONE (the one-shot remote
/// faults are simulated with the engine's semantics), so the model is a
/// deterministic oracle the fixture can be cross-checked against. Digest
/// identities (release id, tree sha) are NOT recomputed: the
/// version→artifact join is performed by [`assert_semantic_invariants`]
/// against the system's durable snapshots and attempts.
#[derive(Clone, Debug)]
struct Model {
    /// Content version the next HEAD push materializes. The fixture writes
    /// version 1 at construction.
    head_version: u32,
    /// One-shot remote fault armed by [`Action::InjectFailure`]; consumed by
    /// the next write to the matching path.
    armed_fault: Option<FailureStep>,
    /// An action or fault kind this oracle cannot simulate (added by a
    /// sibling feature): cross-system equality assertions are suspended
    /// (the fixture's own five invariant groups still run each step).
    unknown: bool,
    /// The remote `current` generation's expected artifact content version.
    current: Option<u32>,
    /// A [`Action::Tamper`] edited the live assignment: the current's
    /// identity is deliberately inconsistent and the identity comparison
    /// defers until the next real push replaces the record.
    current_tampered: bool,
    /// Expected per-target observed projection (content version), or `None`
    /// before the first completed mutation.
    observed: BTreeMap<&'static str, Option<u32>>,
    /// Per-target fleet snapshot log: content version per snapshot index.
    snapshots: BTreeMap<&'static str, Vec<u32>>,
    /// Per-target deployment-attempt log: content version per attempt.
    attempts: BTreeMap<&'static str, Vec<u32>>,
    /// Un-finalized (PendingCommit) deployment per target: (content version,
    /// the generation counter of the minted generation).
    pending: BTreeMap<&'static str, (u32, u64)>,
    /// Monotone counter of deployed generations: every real deployment
    /// (push, rollback, or faulted push) mints exactly one new generation,
    /// and a pending attempt finalizes only while its OWN generation is
    /// still the remote current (the engine compares generation IDs, not
    /// versions — a same-version redeploy diverges the pending attempt).
    current_gen: u64,
    /// Expected rotation-debt marker presence per target.
    debt: BTreeMap<&'static str, bool>,
    /// True when the previous action was a deliberate tamper (the system's
    /// own invariant checks are skipped for that step too).
    last_was_tamper: bool,
    /// Actions applied so far; used to name the failing step in panics.
    index: usize,
}

impl Model {
    fn new() -> Model {
        Model {
            head_version: 1,
            armed_fault: None,
            unknown: false,
            current: None,
            current_tampered: false,
            observed: BTreeMap::from([("t1", None), ("t2", None)]),
            snapshots: BTreeMap::from([("t1", Vec::new()), ("t2", Vec::new())]),
            attempts: BTreeMap::from([("t1", Vec::new()), ("t2", Vec::new())]),
            pending: BTreeMap::new(),
            current_gen: 0,
            debt: BTreeMap::from([("t1", false), ("t2", false)]),
            last_was_tamper: false,
            index: 0,
        }
    }

    /// Advance the oracle by one action. Kept ADAPTIVE: unknown `Action`
    /// variants and `FailureStep` kinds added by sibling features fall into
    /// `_` arms that suspend the cross-comparisons instead of breaking the
    /// build or false-failing the invariant groups.
    fn apply(&mut self, action: &Action) {
        self.index += 1;
        self.last_was_tamper = false;
        match action {
            Action::Build(v) => self.head_version = *v,
            Action::Push(t) | Action::Retry(t) => self.deploy(t, None),
            Action::Rollback(t, i) => self.rollback(t, *i),
            Action::Rotate => self.rotate(),
            Action::InjectFailure(step) => match step {
                FailureStep::CommitMarkerWrite | FailureStep::RotationInventoryWrite => {
                    self.armed_fault = Some(*step)
                }
                _ => {
                    // A sibling feature's new injectable step: the model cannot
                    // simulate its consumption; suspend cross-comparisons.
                    self.armed_fault = None;
                    self.unknown = true;
                }
            },
            Action::Tamper(_) => {
                if self.current.is_some() {
                    // The fixture requires a live generation to tamper; with
                    // none, the property test skips the action entirely.
                    self.current_tampered = true;
                    self.last_was_tamper = true;
                }
            }
            _ => {
                // New action variant from a sibling feature: unknown effect.
                // Treat the step like a tamper (skip the system's own checks
                // for it too) and stop cross-comparing.
                self.unknown = true;
                self.last_was_tamper = true;
            }
        }
    }

    /// Reconcile a pending attempt of `t` at the START of a push/rollback,
    /// mirroring `reconcile_pending_commits` (which runs before the early
    /// no-op check): verify the attempt's generation, then write its missing
    /// fleet-commit marker. The marker write is a commit-path write, so an
    /// armed CommitMarker fault is consumed there and the attempt stays
    /// pending.
    fn reconcile(&mut self, t: &'static str) {
        let Some((pv, pg)) = self.pending.remove(t) else {
            return;
        };
        // The engine's reconciliation FIRST verifies the pending attempt's
        // generation against the remote current (before any marker write): a
        // diverged generation degrades the attempt with NO marker write, so
        // an armed fault is NOT consumed.
        if self.current_gen != pg {
            return;
        }
        match self.armed_fault {
            Some(FailureStep::CommitMarkerWrite) => {
                // The pending attempt's marker write consumes the armed fault
                // and fails, so the attempt stays pending.
                self.armed_fault = None;
                self.pending.insert(t, (pv, pg));
            }
            Some(_) => {
                self.armed_fault = None;
                self.unknown = true;
                self.pending.insert(t, (pv, pg));
            }
            None => {
                // The pending deployment's OWN generation is still the remote
                // current: the attempt finalizes (snapshot appended, refs
                // advanced).
                self.snapshots.entry(t).or_default().push(pv);
            }
        }
    }

    /// A fleet-rollback to snapshot `i`. Out-of-range refs are rejected by
    /// the engine's plan BEFORE reconcile or any mutation: model no-op.
    fn rollback(&mut self, t: &'static str, i: u64) {
        let Some(v) = self
            .snapshots
            .get(t)
            .and_then(|snaps| snaps.get(i as usize))
            .copied()
        else {
            return;
        };
        self.deploy(t, Some(v));
    }

    /// A HEAD push / no-op retry (`Push` and `Retry` are the same operation
    /// in the fixture) or a valid fleet-rollback (deploying `rollback_version`).
    fn deploy(&mut self, t: &'static str, rollback_version: Option<u32>) {
        self.reconcile(t);
        let version = match rollback_version {
            Some(v) => Some(v),
            None => {
                // HEAD push: deploy exactly when the remote current no longer
                // equals the materialized head (the engine's complete
                // ArtifactRef equality — a tampered current forces a real push).
                if self.current_tampered || self.current != Some(self.head_version) {
                    Some(self.head_version)
                } else {
                    None
                }
            }
        };
        let Some(v) = version else {
            // Up-to-date no-op: no records, no remote writes except the
            // deferred-maintenance hook (which services rotation debt).
            self.noop_maintenance(t);
            return;
        };
        let fault = self.armed_fault.take();
        let had_debt = self.debt.get(t).copied().unwrap_or(false);
        self.current_gen += 1;
        self.current = Some(v);
        self.current_tampered = false;
        // The shared slot's observed entry is refreshed in EVERY member
        // target whenever it changes.
        self.observed.insert("t1", Some(v));
        self.observed.insert("t2", Some(v));
        self.attempts.entry(t).or_default().push(v);
        match fault {
            Some(FailureStep::CommitMarkerWrite) => {
                // Fleet-commit marker write fails: the deployment is recorded
                // PendingCommit; `current` advanced and observed refreshed
                // (steps 15/16), but the snapshot/ref finalization is deferred
                // to the next push of this target. Step-17 rotation still
                // succeeds (the fault is spent), so no debt.
                self.pending.insert(t, (v, self.current_gen));
                self.debt.insert(t, false);
            }
            Some(FailureStep::RotationInventoryWrite) => {
                // Post-commit maintenance: step 17 retries an EXISTING debt
                // marker FIRST — that servicing write consumes the fault and
                // fails, then the push's own slot rotation succeeds and
                // CLEARS the marker. With no prior marker, the fault hits the
                // push's own rotation, which defers it as a new marker.
                self.snapshots.entry(t).or_default().push(v);
                self.debt.insert(t, !had_debt);
            }
            Some(_) => {
                // Unknown fault kind: assume a fully committed push and stop
                // cross-comparing.
                self.snapshots.entry(t).or_default().push(v);
                self.debt.insert(t, false);
                self.unknown = true;
            }
            None => {
                self.snapshots.entry(t).or_default().push(v);
                self.debt.insert(t, false);
            }
        }
    }

    /// The no-op retry path: `retry_deferred_rotations` services the debt
    /// marker (writing the inventory), and that write consumes an armed
    /// RotationInventory fault — failing, the marker stays. Commit-marker
    /// faults do not match the inventory write, so the rotation succeeds and
    /// clears the debt.
    fn noop_maintenance(&mut self, t: &'static str) {
        if !self.debt.get(t).copied().unwrap_or(false) {
            return;
        }
        match self.armed_fault {
            Some(FailureStep::RotationInventoryWrite) => {
                self.armed_fault = None;
                // rotation failed; the debt marker stays
            }
            Some(FailureStep::CommitMarkerWrite) => {
                self.debt.insert(t, false);
            }
            Some(_) => {
                self.armed_fault = None;
                self.debt.insert(t, false);
                self.unknown = true;
            }
            None => {
                self.debt.insert(t, false);
            }
        }
    }

    /// Whether `action` would replace the tampered current record with a new
    /// pristine generation. Only a REAL deployment does: a HEAD push/retry
    /// always deploys after a tamper (the tampered artifact never equals the
    /// materialized head), while a fleet-rollback repairs only when its ref
    /// resolves — an out-of-range index errors at plan time, before any
    /// mutation, leaving the tampered record in place.
    fn repairs_tamper(&self, action: &Action) -> bool {
        match action {
            Action::Push(_) | Action::Retry(_) => true,
            Action::Rollback(t, i) => self
                .snapshots
                .get(t)
                .map(|s| (*i as usize) < s.len())
                .unwrap_or(false),
            _ => false,
        }
    }

    /// A standalone union rotation. The fixture's `rotate_union` runs over a
    /// PLAIN `LocalTransport` (not the fault-injecting wrapper the pushes
    /// use), so it neither fails nor consumes an armed fault; it leaves the
    /// remote current, observed projections, and pending/debt state
    /// untouched. Faults stay armed for the next real push.
    fn rotate(&mut self) {
        let _ = &self.armed_fault;
    }
}

/// The bounded action strategy: every generated action stays inside the
/// 1-slot / 2-target / 3-generation fixture (versions 0..=3, rollback indices
/// 0..=1 — out-of-range refs are rejected by the plan, not panics). Only the
/// two REMOTE [`FailureStep`]s are injectable: the fixture's
/// `set_remote_fault` refuses store-level steps by design.
fn action_strategy() -> impl Strategy<Value = Action> {
    prop_oneof![
        // Rewrite the artifact sources; the next HEAD push materializes this
        // content version.
        4 => (0u32..=3).prop_map(Action::Build),
        // A HEAD push under t1 (aggressive retention) or t2 (conservative).
        4 => prop::sample::select(["t1", "t2"].as_slice()).prop_map(Action::Push),
        // Up-to-date retry (no-op or reconcile) — the same engine call.
        2 => prop::sample::select(["t1", "t2"].as_slice()).prop_map(Action::Retry),
        // Fleet rollback to snapshot index 0 or 1 of the target.
        2 => (prop::sample::select(["t1", "t2"].as_slice()), 0u64..2)
            .prop_map(|(t, i)| Action::Rollback(t, i)),
        // Standalone rotation under the full member-policy union.
        1 => Just(Action::Rotate),
        // One-shot REMOTE fault (commit marker / rotation inventory).
        3 => prop::sample::select([
            FailureStep::CommitMarkerWrite,
            FailureStep::RotationInventoryWrite,
        ]
        .as_slice())
        .prop_map(Action::InjectFailure),
        // Deliberate integrity violation; the property loop skips it while no
        // live generation exists (the fixture's tamper requires one), and the
        // system's own checks defer until the next real push.
        1 => prop::sample::select([
            TamperKind::StoredAssignmentVariant,
            TamperKind::StoredAssignmentRelease,
        ]
        .as_slice())
        .prop_map(Action::Tamper),
    ]
}

/// Whether the system has a deployment attempt for `t` still eligible for
/// reconciliation (latest transition `PendingCommit` / `InProgress`).
fn system_has_pending(system: &Fixture, t: &str) -> bool {
    system
        .store
        .read_attempts(t)
        .unwrap_or_default()
        .iter()
        .any(|a| {
            matches!(
                system
                    .store
                    .latest_status(a.deployment_id.as_str())
                    .ok()
                    .flatten(),
                Some(DeploymentStatus::PendingCommit) | Some(DeploymentStatus::InProgress)
            )
        })
}

/// Record `art` as the artifact for content version `v`. Every source (a
/// fleet snapshot, an attempt's desired assignment, the remote current, an
/// observed projection) must agree: the same version materializing into two
/// different artifacts is exactly the interleaving/state bug the oracle
/// exists to catch.
fn learn_artifact(
    learned: &mut BTreeMap<u32, ArtifactRef>,
    ctx: &str,
    v: u32,
    art: ArtifactRef,
    src: &str,
) {
    if let Some(prev) = learned.get(&v) {
        assert_eq!(
            prev, &art,
            "{ctx}: version {v} must materialize into exactly ONE artifact; {src} disagrees with an earlier source"
        );
    } else {
        learned.insert(v, art);
    }
}

/// Assert the model-vs-system agreement for ONE action step:
/// (a) re-run the fixture's five invariant groups — skipped after a
/// deliberate [`Action::Tamper`], which intentionally breaks the Integrity
/// group — and
/// (b) cross-check the model's expected state against the system's
/// observable state: the remote current generation (existence + artifact
/// identity), every member target's observed projection, the per-target
/// snapshot/attempt logs, pending-commit state, and rotation-debt markers.
///
/// The version→artifact identity join comes from the SYSTEM's durable
/// records (snapshots and attempts carry the deployed [`ArtifactRef`]): every
/// version the model ever deployed must have materialized into exactly ONE
/// artifact. Any divergence between sources for the same version, or between
/// the model's expected version and the system's actual artifact, is the
/// interleaving bug this layer exists to find — proptest then shrinks the
/// failing action vector to its minimal core. Panics name the failing action
/// index ([`Model::index`]) for debugging.
fn assert_semantic_invariants(model: &Model, system: &Fixture) {
    let ctx = format!("after action {}", model.index);
    if model.last_was_tamper || model.unknown {
        // A tamper deliberately broke identity (the fixture's apply skipped
        // its own checks too) and the model defers to the next real push that
        // replaces the tampered record; an UNKNOWN action/fault kind from a
        // sibling feature cannot be cross-checked either (the fixture's apply
        // already ran its own invariant checks for it). Both suspend the
        // comparisons without weakening them.
        return;
    }
    // (a) The five invariant groups (the system's own ground truth).
    system.check_invariants();

    let pid = PlacementSlotId::new("p1");
    let mut learned: BTreeMap<u32, ArtifactRef> = BTreeMap::new();

    // Fleet-snapshot logs: count + per-index artifact/version join.
    for t in ["t1", "t2"] {
        let sys_snaps = system.store.read_snapshots(t).unwrap_or_default();
        let want = model.snapshots.get(t).cloned().unwrap_or_default();
        assert_eq!(
            sys_snaps.len(),
            want.len(),
            "{ctx}: snapshot count for {t} must match the model ({sys} vs {model})",
            sys = sys_snaps.len(),
            model = want.len(),
        );
        for (i, (ss, mv)) in sys_snaps.iter().zip(&want).enumerate() {
            assert_eq!(ss.index, i as u64, "{ctx}: snapshot index order for {t}");
            let art = ss.slots[&pid].assignment.artifact.clone();
            learn_artifact(&mut learned, &ctx, *mv, art, &format!("snapshot {t}@f{i}"));
        }
    }
    // Deployment-attempt logs: exactly one record per real deployment.
    for t in ["t1", "t2"] {
        let sys_att = system.store.read_attempts(t).unwrap_or_default();
        let want = model.attempts.get(t).cloned().unwrap_or_default();
        assert_eq!(
            sys_att.len(),
            want.len(),
            "{ctx}: attempt count for {t} must match the model"
        );
        for (sa, mv) in sys_att.iter().zip(&want) {
            let art = sa.desired[&pid].assignment.artifact.clone();
            learn_artifact(&mut learned, &ctx, *mv, art, "attempt {t}");
        }
    }

    // Remote current generation: existence + artifact identity. The identity
    // check is skipped while the live record was tampered.
    let sys_current = system.current_assignment();
    match (model.current, sys_current) {
        (None, None) => {}
        (None, Some(asn)) => panic!(
            "{ctx}: unexpected remote current generation {}",
            asn.generation_id
        ),
        (Some(_), None) => {
            panic!("{ctx}: model expects a remote current generation, none present")
        }
        (Some(v), Some(asn)) => {
            if !model.current_tampered {
                let want = learned.get(&v).cloned().unwrap_or_else(|| {
                    panic!(
                        "{ctx}: current generation version {v} has no recorded attempt/snapshot in the system"
                    )
                });
                assert_eq!(
                    asn.artifact, want,
                    "{ctx}: the remote current generation must deploy the model's expected artifact for version {v}"
                );
            }
            // The current generation is the freshest identity source (e.g. a
            // still-pending deployment has a current but no snapshot yet).
            learn_artifact(
                &mut learned,
                &ctx,
                v,
                asn.artifact.clone(),
                "remote current",
            );
        }
    }

    // Observed projection for EVERY member target of the shared slot.
    for t in ["t1", "t2"] {
        let obs = system.store.read_observed(t).unwrap_or_default();
        let entry = obs.slots.get(&pid);
        match (model.observed[t], entry) {
            (None, None) => {}
            (None, Some(_)) => panic!("{ctx}: {t} observed an unexpected p1 entry"),
            (Some(_), None) => {
                panic!("{ctx}: {t} is missing its observed p1 entry though the model expects one")
            }
            (Some(v), Some(slot)) => {
                let art = slot.artifact.clone().expect("{ctx}: observed artifact");
                assert!(
                    slot.generation.is_some(),
                    "{ctx}: {t} observed generation must be present"
                );
                let want = learned.get(&v).cloned().unwrap_or_else(|| {
                    panic!(
                        "{ctx}: observed version {v} for {t} has no recorded artifact in the system"
                    )
                });
                assert_eq!(
                    art, want,
                    "{ctx}: {t} observed projection must match the model's expected version {v}"
                );
            }
        }
    }
    // Pending-commit state per target.
    for t in ["t1", "t2"] {
        let sys_pending = system_has_pending(system, t);
        assert_eq!(
            model.pending.contains_key(t),
            sys_pending,
            "{ctx}: pending-commit state for {t}"
        );
        if let Some((pv, _)) = model.pending.get(t) {
            // The pending attempt need not be the target's NEWEST attempt: a
            // later deployment can commit after the pending one (e.g. its
            // reconcile marker write consumed a newly-armed fault), so the
            // pending version must simply have a recorded attempt.
            assert!(
                model.attempts[t].contains(pv),
                "{ctx}: the pending deployment version {pv} must have a recorded attempt"
            );
        }
    }

    // Rotation-debt markers per target.
    for t in ["t1", "t2"] {
        let sys_debt = !system
            .store
            .read_rotation_debt(t)
            .unwrap_or_default()
            .is_empty();
        assert_eq!(
            model.debt[t], sys_debt,
            "{ctx}: rotation-debt marker for {t}"
        );
    }
}

// Property-based state machine: bounded RANDOM action vectors (1..20
// actions) drive a fresh [`Model`] oracle and [`Fixture`] in lockstep. After
// EVERY action [`assert_semantic_invariants`] cross-checks the model's
// expected state against the system's observable state and re-evaluates all
// five invariant groups — the same contract as the fixed `state_machine_*`
// sequences, but the generator explores interleavings the hand-written
// sequences miss and the shrinker minimizes any failing vector to its core.
//
// Determinism: the config pins a fixed seed and a bounded case count, and
// shrinking never consults the wall clock — two `cargo test` runs reproduce
// the identical vectors.
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn semantic_state_machine(actions in prop::collection::vec(action_strategy(), 1..20)) {
        // No fault lock: every arm targets the fixture's OWN per-fixture
        // registry (see `src/testutil.rs`), so the 128 cases run concurrently
        // with the fault-matrix and engine fault tests without any shared
        // process-global slot to race over.
        let mut model = Model::new();
        let system = Fixture::new();
        for action in actions {
            // A Tamper needs a live generation (it edits the CURRENT
            // assignment); generated tampers before the first deployment are
            // skipped rather than panicking the fixture by construction.
            if matches!(&action, Action::Tamper(_)) && !system.has_current_generation() {
                continue;
            }
            // After a tamper the fixture's OWN invariant checks cannot run
            // until a real push replaces the tampered assignment (the tamper
            // deliberately breaks current-vs-observed identity and the stored
            // release binding). Non-repairing actions in between are skipped
            // so the next applied action is always the repair.
            if model.current_tampered && !model.repairs_tamper(&action) {
                continue;
            }
            model.apply(&action);
            system.apply(action);
            assert_semantic_invariants(&model, &system);
        }
    }
}
