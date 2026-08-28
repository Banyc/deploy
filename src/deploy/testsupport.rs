//! Shared TEST fixtures for the push spine and its phase modules: the
//! single/two-slot harnesses ([`RecoveryHarness`], [`TwoSlotHarness`],
//! [`SysdHarness`]), the recording/faulting remotes, the membership /
//! group fixtures, and the push entry points that drive
//! [`crate::deploy::push::push_inner`] directly with caller-supplied
//! deployment ids. Round-5 decision: these are consumed by every phase
//! module's tests AND by [`crate::deploy::push`] /
//! [`crate::deploy::maintenance`] tests, so they live in a shared
//! test-support module rather than being duplicated per phase.

// The whole push-test vocabulary, re-exported so every phase module's tests
// (and the [`crate::deploy::push`] / [`crate::deploy::maintenance`] tests)
// glob ONE module: `use crate::deploy::testsupport::*;`.
pub(crate) use crate::config::{Mapping, ProjectConfig, SlotConfig};
pub(crate) use crate::deploy::push::{PushOptions, PushReport, push, push_inner, push_ref_with_id};
pub(crate) use crate::error::Result;
pub(crate) use crate::identity::{
    ArtifactRef, BehaviorContract, CanonicalSlot, CanonicalSlots, DeploymentId, GenerationId,
    GenerationRef, OperationId, Provenance, ReleaseId, ReleaseRecord, SlotId, TargetName,
    TreeDigest, VariantName, test_deployment_id, test_generation_id, test_tree_digest,
};
pub(crate) use crate::ledger::{
    self, DeploymentIntent, DeploymentPlan, DeploymentStatus, DesiredGeneration, IntentSlot,
    LedgerEntry, LedgerIntentReport, LedgerTerminal, NonEmptySlotTable, Observation,
    ObservationWire, ObservedAssignment, ObservedGenerationWire, RefExpr, SlotAttemptState,
    TerminalDisposition,
};
pub(crate) use crate::remote::transport::{
    CreateNewVerdict, FsBytes, LocalTransport, Remote, scripted::ScriptedExec,
};
pub(crate) use crate::store::local::LocalStore;
pub(crate) use crate::testutil::test_remotes::FailOnceMarkerRemote;
pub(crate) use crate::verify::release::RELEASE_RECORD_SCHEMA_VERSION;
pub(crate) use std::collections::{BTreeMap, BTreeSet};
pub(crate) use std::os::unix::fs::PermissionsExt;
pub(crate) use std::path::{Path, PathBuf};
pub(crate) use std::sync::atomic::{AtomicBool, Ordering};
pub(crate) use std::sync::{Arc, Mutex};

/// The KNOWN artifact of a report actual ([`SlotAttemptState`]): a
/// successful push's actuals are always `Known` — the post-push refresh
/// only records `Unknown` for an unreadable live assignment, which fails
/// the status read before any successful finalize. Test code asserting
/// on a real actual artifact unwraps the observation here.
pub(crate) fn known_artifact(s: &SlotAttemptState) -> &ArtifactRef {
    match &s.artifact {
        Observation::Known(a) => a,
        other => panic!("expected a Known actual artifact, got {other:?}"),
    }
}

pub(crate) const NONE_VARIANT: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/eng"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
to = "app-common/"
recursive = true

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

pub(crate) const NONE_TOML: &str = r#"
schema_version = 2
application = "eng"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;

/// The two-group variant for the multi-release harness: `p1` in
/// `group-a` (server `s1`), `p2` in `group-b` (server `s2`), verification
/// argv carrying the contract tag `a` (so contract B, produced by the
/// test's variant edit, digests DIFFERENTLY from contract A while both
/// pass `true`).
pub(crate) const TWO_SLOT_VARIANT: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
groups = ["group-a"]
deploy_dir = "/srv/eng-a"

[[slots]]
id = "p2"
server = "s2"
target = "t1"
groups = ["group-b"]
deploy_dir = "/srv/eng-b"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[[artifact.mappings]]
from = "artifacts/deployment/common/"
to = "app-common/"
recursive = true

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
argv = ["true", "a"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

/// The two-server config backing [`TWO_SLOT_VARIANT`] (one server per
/// group slot, so each slot's remote is its own host).
pub(crate) const TWO_SERVER_TOML: &str = r#"
schema_version = 2
application = "eng"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s2"
address = "b"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;

/// A two-group harness (slots `p1`/`p2` on their own servers, groups
/// `group-a`/`group-b`) so a test can build a REAL multi-release partial
/// snapshot: a full push establishes both slots under release R1, a
/// group-b push advances only `p2` to release R2, and the overlay
/// snapshot carries BOTH releases.
pub(crate) struct TwoSlotHarness {
    pub(crate) _dir: tempfile::TempDir,
    pub(crate) cfg_path: PathBuf,
    pub(crate) config: ProjectConfig,
    pub(crate) store: LocalStore,
    pub(crate) remotes_base: PathBuf,
    /// The deterministic fake exec every transport this harness builds
    /// injects: scripted verification outcomes, no real subprocesses — the
    /// push properties stay parallel-safe and deterministic.
    pub(crate) script: ScriptedExec,
}

impl TwoSlotHarness {
    pub(crate) fn new() -> TwoSlotHarness {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), TWO_SLOT_VARIANT).unwrap();
        std::fs::write(project.join("deploy.toml"), TWO_SERVER_TOML).unwrap();
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
        TwoSlotHarness {
            _dir: dir,
            cfg_path,
            config,
            store,
            remotes_base,
            script: ScriptedExec::default_success(),
        }
    }
}

/// One push against the two-slot harness with an explicit config, ref
/// expression, and rollout group.
pub(crate) fn two_slot_push(
    h: &TwoSlotHarness,
    config: &ProjectConfig,
    ref_expr: &RefExpr,
    group: Option<&str>,
    deployment_id: &DeploymentId,
) -> Result<PushReport> {
    let project_root = config.project_root(&h.cfg_path);
    let target = config.target("t1").expect("harness target");
    let op_id = OperationId::new(format!("op-{}", deployment_id.as_str()));
    let rf = h.remotes_base.clone();
    let script = h.script.clone();
    let factory = move |s: &crate::config::ServerDef,
                        _slot: &crate::config::SlotConfig|
          -> Result<Box<dyn Remote>> {
        Ok(Box::new(LocalTransport::with_exec(
            &crate::testutil::fixture_env(),
            rf.join(s.id.as_str()),
            script.clone(),
        )?))
    };
    push_inner(
        &project_root,
        &h.store,
        &factory,
        "t1",
        &crate::deploy::plan::SlotSelection::normalize(config, "t1", group).unwrap(),
        ref_expr,
        None,
        deployment_id,
        &op_id,
        config,
        target,
        &PushOptions {
            dry_run: false,
            ref_token: None,
            group: group.map(str::to_string),
        },
    )
}

/// A single-server (`s1`/`t1`) project + store + remote base for the
/// full-push recovery scenarios, mirroring the integration-test setup.
pub(crate) struct RecoveryHarness {
    pub(crate) _dir: tempfile::TempDir,
    pub(crate) cfg_path: PathBuf,
    pub(crate) config: ProjectConfig,
    pub(crate) store: LocalStore,
    pub(crate) remotes_base: PathBuf,
    /// The deterministic fake exec every transport this harness builds
    /// injects: scripted verification outcomes, no real subprocesses — the
    /// push/recovery properties stay parallel-safe and deterministic. Tests
    /// that need a scripted failure (e.g. a non-zero verification driving
    /// the compensation branch) build the harness's script before pushing.
    pub(crate) script: ScriptedExec,
}

impl RecoveryHarness {
    pub(crate) fn new() -> RecoveryHarness {
        RecoveryHarness::with_variant(NONE_VARIANT)
    }

    /// A harness whose variant file carries the given TOML (so a test can
    /// install a verification argv that renders template variables).
    pub(crate) fn with_variant(variant_toml: &str) -> RecoveryHarness {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), variant_toml).unwrap();
        std::fs::write(project.join("deploy.toml"), NONE_TOML).unwrap();
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
        RecoveryHarness {
            _dir: dir,
            cfg_path,
            config,
            store,
            remotes_base,
            script: ScriptedExec::default_success(),
        }
    }
}

/// Push 1 of the recovery scenarios: the commit marker write fails
/// once, so the attempt is recorded `PendingCommit` (activation already
/// happened; the latest transition says `PendingCommit`, no snapshot
/// entry, no `refs/last-successful`).
/// Seed the target's ledger with ONE successful deployment carrying the
/// given rollback payload (intent + `Successful` terminal). The entry's
/// position in the successful chain is its `sN` — there are no explicit
/// snapshot indices in the ledger.
pub(crate) fn seed_snapshot(
    store: &LocalStore,
    target: &str,
    deployment_id: &str,
    behavior_sha256: &str,
    slots: BTreeMap<SlotId, GenerationRef>,
    bindings: BTreeMap<SlotId, crate::ledger::PhysicalBinding>,
) {
    // ONE slot table: the membership + the desired entries.
    let slot_table: BTreeMap<SlotId, IntentSlot> = slots
        .iter()
        .map(|(k, g)| {
            (
                k.clone(),
                IntentSlot {
                    desired: DesiredGeneration {
                        generation: g.generation.clone(),
                        artifact: g.assignment.artifact.clone(),
                    },
                    pre_push: None,
                    // The intent FREEZES each slot's plan-time physical
                    // binding (schema v6) — seed it from the same bindings
                    // the terminal's rollback records (the seeded
                    // Successful terminal requires bindings to cover the
                    // slotted generations exactly).
                    binding: bindings
                        .get(k)
                        .cloned()
                        .expect("a seeded snapshot binds every slotted slot"),
                },
            )
        })
        .collect();
    store
        .append_intent(
            target,
            &DeploymentIntent {
                deployment_id: test_deployment_id(deployment_id),
                target: TargetName::new(target.to_string()),
                group: None,
                behavior_sha256: behavior_sha256.to_string(),
                attempted_at: "2026-01-01T00:00:00Z".to_string(),
                slots: NonEmptySlotTable::build(slot_table)
                    .expect("a seeded snapshot always has at least one slot"),
                full_membership: slots.keys().cloned().collect(),
            },
        )
        .unwrap();
    store
        .append_terminal(
            target,
            &test_deployment_id(deployment_id),
            &LedgerTerminal {
                recorded_at: "2026-01-01T00:00:00Z".to_string(),
                // THE EXACT-EQUAL shape: every slotted generation is
                // ACTIVATED (the memberships PROVE the equations —
                // activated == full == the rollback's slots — and the
                // per-slot generation/artifact facts are DERIVED from the
                // rollback, the single source of truth; a seeded
                // Successful terminal must carry one activated slot per
                // slotted generation).
                disposition: TerminalDisposition::Successful {
                    rollback: crate::ledger::LedgerRollback {
                        slots: slots.clone(),
                        bindings,
                    },
                    activated: slots.keys().cloned().collect(),
                    // THE EXACT-EQUAL MEMBERSHIPS: activated == full ==
                    // the slotted generations' keys (the rollback's
                    // slots) — the proven shape the conversion + read
                    // require.
                    full_membership: slots.keys().cloned().collect(),
                },
                reason: None,
            },
        )
        .unwrap();
}

pub(crate) fn push_pending_attempt(h: &RecoveryHarness) -> LedgerIntentReport {
    let armed = Arc::new(AtomicBool::new(true));
    let armed_for_factory = armed.clone();
    let rf = h.remotes_base.clone();
    let fault_factory = move |s: &crate::config::ServerDef,
                              _slot: &crate::config::SlotConfig|
          -> Result<Box<dyn Remote>> {
        FailOnceMarkerRemote::build(rf.join(s.id.as_str()), armed_for_factory.clone())
    };
    let r1 = push(
        &h.cfg_path,
        &h.store,
        &fault_factory,
        "t1",
        &h.config,
        &PushOptions {
            dry_run: false,
            ref_token: None,
            group: None,
        },
    )
    .unwrap();
    assert_eq!(
        r1.status,
        Some(DeploymentStatus::PendingCommit),
        "failed marker write must yield PendingCommit"
    );
    let attempt = r1.attempt.expect("attempt recorded");
    let marker = h
        .remotes_base
        .join("s1")
        .join(crate::remote::layout::commit_marker(
            attempt.deployment_id.as_str(),
        ));
    assert!(
        !marker.exists(),
        "marker must be absent after the failed push"
    );
    assert!(
        h.store.read_snapshots("t1").unwrap().is_empty(),
        "no snapshot for a pending attempt"
    );
    assert!(
        h.store.read_last_successful("t1").is_none(),
        "last-successful must not point at a pending attempt"
    );
    attempt
}

/// A remote that records every `exec` argv it is handed (delegating all
/// other operations to the wrapped `LocalTransport`), so a test can assert
/// the RENDERED verification command vector without spawning a process.
pub(crate) struct RecordingRemote {
    pub(crate) inner: LocalTransport,
    pub(crate) executed: Arc<Mutex<Vec<Vec<String>>>>,
}

impl RecordingRemote {
    pub(crate) fn new(base: PathBuf, executed: Arc<Mutex<Vec<Vec<String>>>>) -> Result<Self> {
        // The inner transport injects the deterministic fake exec: the
        // wrapper records every argv (the assertions' subject) while the fake
        // returns the scripted success outcome — no real `true` process.
        Ok(RecordingRemote {
            inner: LocalTransport::with_exec(
                &crate::testutil::fixture_env(),
                base,
                ScriptedExec::default_success(),
            )?,
            executed,
        })
    }
}

impl Remote for RecordingRemote {
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
    fn list(&self, rel: &Path) -> Result<Vec<crate::remote::transport::RemoteEntry>> {
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
    fn metadata(&self, rel: &Path) -> Result<crate::remote::transport::RemoteMeta> {
        self.inner.metadata(rel)
    }
    fn exec(
        &self,
        argv: &[String],
        timeout: std::time::Duration,
    ) -> Result<crate::remote::transport::ExecOutcome> {
        self.executed.lock().unwrap().push(argv.to_vec());
        self.inner.exec(argv, timeout)
    }
    fn filesystem_bytes(&self) -> Result<FsBytes> {
        self.inner.filesystem_bytes()
    }
}

/// The boundary at which a CONCURRENT controller's swap of a slot's
/// `current` is injected into the ONE lock-verified finalization
/// ([`crate::ledger::finalize::finalize_successful_locked`]): the swap
/// re-points `current` at a REAL foreign generation (minted up front, so
/// every later `status()` read validates it cleanly and reports a DIFFERENT
/// `GenerationRef` than the frozen desired assignment).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SwapStage {
    /// The swap is in place BEFORE the shared operation runs (the wrapper
    /// re-points `current` at construction) — i.e. before the re-observation
    /// status read.
    BeforeStatus,
    /// The swap lands right AFTER the re-observation's first `current`
    /// resolution read, before the assignment read.
    AfterStatus,
    /// The swap lands BETWEEN the selected slots' commit-marker writes
    /// (before the wrapper's own marker write — the second slot's marker).
    BetweenMarkers,
    /// The swap lands right BEFORE the final verification that precedes the
    /// terminal append (after every marker write).
    BeforeTerminal,
}

/// A remote wrapper that injects a concurrent controller's `current` swap
/// at a chosen stage of the ONE lock-verified finalization
/// ([`crate::ledger::finalize::finalize_successful_locked`]), then passes
/// through untouched. The foreign generation is a REAL generation (a valid
/// `generations/<gen>/assignment.json` + `root` chain + tree object, minted
/// by the harness), so a `status()` read after the swap validates it cleanly
/// and reports a DIFFERENT `GenerationRef` than the frozen desired
/// assignment — the state divergence the shared operation must refuse.
pub(crate) struct SwapInjectRemote {
    inner: LocalTransport,
    stage: SwapStage,
    fired: Arc<AtomicBool>,
    /// True once this remote has observed its commit-marker write (the
    /// `BeforeTerminal` trigger fires on the first `current` read after it).
    marker_seen: Arc<AtomicBool>,
    /// True once this remote's first `current` resolution read (a status
    /// read) has been observed (the `AfterStatus` trigger fires on the
    /// following call).
    current_read_seen: Arc<AtomicBool>,
    /// The foreign generation `current` is re-pointed at.
    foreign_gen: crate::identity::GenerationId,
}

impl SwapInjectRemote {
    pub(crate) fn build(
        base: PathBuf,
        stage: SwapStage,
        foreign_gen: crate::identity::GenerationId,
    ) -> Result<Box<dyn Remote>> {
        let inner = LocalTransport::with_exec(
            &crate::testutil::fixture_env(),
            base,
            ScriptedExec::default_success(),
        )?;
        let wrapper = SwapInjectRemote {
            inner,
            stage,
            fired: Arc::new(AtomicBool::new(false)),
            marker_seen: Arc::new(AtomicBool::new(false)),
            current_read_seen: Arc::new(AtomicBool::new(false)),
            foreign_gen,
        };
        if stage == SwapStage::BeforeStatus {
            wrapper.do_swap()?;
        }
        Ok(Box::new(wrapper))
    }

    /// Re-point `current` at the foreign generation (a concurrent controller
    /// that ignores the lock protocol).
    fn do_swap(&self) -> Result<()> {
        if self.fired.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.inner.remove_file(crate::remote::layout::current())?;
        let target = crate::remote::layout::generation(self.foreign_gen.as_str()).join("root");
        self.inner
            .symlink(&target, crate::remote::layout::current())?;
        Ok(())
    }

    /// The stage trigger, checked BEFORE every delegated remote operation:
    /// true when the injected swap must land before this call.
    fn stage_fire(&self, rel: &std::path::Path) -> bool {
        if self.fired.load(Ordering::SeqCst) {
            return false;
        }
        let is_current_read = rel == crate::remote::layout::current();
        let is_marker_write = rel.to_string_lossy().starts_with("state/commits/");
        match self.stage {
            SwapStage::BeforeStatus => false, // fired at construction
            SwapStage::AfterStatus => {
                if is_current_read {
                    self.current_read_seen.store(true, Ordering::SeqCst);
                    false
                } else if self.current_read_seen.load(Ordering::SeqCst) {
                    // The first call after the status read (the assignment
                    // read): the swap lands here.
                    true
                } else {
                    false
                }
            }
            SwapStage::BetweenMarkers => {
                // Before this remote's marker write — the second slot's
                // marker, i.e. BETWEEN the selected slots' marker writes.
                is_marker_write
            }
            SwapStage::BeforeTerminal => {
                if is_marker_write {
                    self.marker_seen.store(true, Ordering::SeqCst);
                }
                // The first status read after this remote's marker write is
                // the final verification right before the terminal append.
                is_current_read && self.marker_seen.load(Ordering::SeqCst)
            }
        }
    }
}

impl Remote for SwapInjectRemote {
    fn root(&self) -> &std::path::Path {
        self.inner.root()
    }
    fn read(&self, rel: &std::path::Path) -> Result<Vec<u8>> {
        if self.stage_fire(rel) {
            self.do_swap()?;
        }
        self.inner.read(rel)
    }
    fn write(&self, rel: &std::path::Path, data: &[u8], mode: u32) -> Result<()> {
        if self.stage_fire(rel) {
            self.do_swap()?;
        }
        self.inner.write(rel, data, mode)
    }
    fn try_write_new(&self, rel: &std::path::Path, data: &[u8]) -> Result<CreateNewVerdict> {
        if self.stage_fire(rel) {
            self.do_swap()?;
        }
        self.inner.try_write_new(rel, data)
    }
    fn create_dir(&self, rel: &std::path::Path) -> Result<()> {
        self.inner.create_dir(rel)
    }
    fn create_dir_all(&self, rel: &std::path::Path) -> Result<()> {
        self.inner.create_dir_all(rel)
    }
    fn set_mode(&self, rel: &std::path::Path, mode: u32) -> Result<()> {
        self.inner.set_mode(rel, mode)
    }
    fn list(&self, rel: &std::path::Path) -> Result<Vec<crate::remote::transport::RemoteEntry>> {
        self.inner.list(rel)
    }
    fn rename(&self, from: &std::path::Path, to: &std::path::Path) -> Result<()> {
        self.inner.rename(from, to)
    }
    fn symlink(&self, target: &std::path::Path, link: &std::path::Path) -> Result<()> {
        self.inner.symlink(target, link)
    }
    fn read_link(&self, rel: &std::path::Path) -> Result<std::path::PathBuf> {
        if self.stage_fire(rel) {
            self.do_swap()?;
        }
        self.inner.read_link(rel)
    }
    fn remove_file(&self, rel: &std::path::Path) -> Result<()> {
        self.inner.remove_file(rel)
    }
    fn remove_dir_all(&self, rel: &std::path::Path) -> Result<()> {
        self.inner.remove_dir_all(rel)
    }
    fn exists(&self, rel: &std::path::Path) -> bool {
        // `exists` is infallible: a stage-triggered swap swallows its own
        // failure the same way the raw `bool` API does (the swap itself
        // cannot fail here — the foreign generation is pre-minted and
        // `remove_file`/`symlink` on a healthy transport succeed).
        if self.stage_fire(rel) {
            let _ = self.do_swap();
        }
        self.inner.exists(rel)
    }
    fn metadata(&self, rel: &std::path::Path) -> Result<crate::remote::transport::RemoteMeta> {
        if self.stage_fire(rel) {
            self.do_swap()?;
        }
        self.inner.metadata(rel)
    }
    fn metadata_opt(
        &self,
        rel: &std::path::Path,
    ) -> Result<Option<crate::remote::transport::RemoteMeta>> {
        if self.stage_fire(rel) {
            self.do_swap()?;
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
    fn filesystem_bytes(&self) -> Result<FsBytes> {
        self.inner.filesystem_bytes()
    }
}

/// A push with a healthy `LocalTransport` remote.
pub(crate) fn push_clean(h: &RecoveryHarness) -> Result<PushReport> {
    let rf = h.remotes_base.clone();
    let script = h.script.clone();
    let clean_factory = move |s: &crate::config::ServerDef,
                              _slot: &crate::config::SlotConfig|
          -> Result<Box<dyn Remote>> {
        Ok(Box::new(LocalTransport::with_exec(
            &crate::testutil::fixture_env(),
            rf.join(s.id.as_str()),
            script.clone(),
        )?))
    };
    push(
        &h.cfg_path,
        &h.store,
        &clean_factory,
        "t1",
        &h.config,
        &PushOptions {
            dry_run: false,
            ref_token: None,
            group: None,
        },
    )
}

/// The latest recorded transition status for a deployment.
pub(crate) fn latest_status(h: &RecoveryHarness, deployment_id: &str) -> DeploymentStatus {
    h.store
        .latest_status(deployment_id)
        .unwrap()
        .expect("a transition must be recorded")
}

/// Assert the exactly-one end state of a fully replayed recovery: exactly
/// one snapshot entry at index 0 for the attempt, `refs/last-successful`
/// pointing at it, latest transition `Successful`, and the commit
/// marker present on the remote.
pub(crate) fn assert_finalized(h: &RecoveryHarness, attempt: &LedgerIntentReport) {
    let snapshots = h.store.read_snapshots("t1").unwrap();
    assert_eq!(
        snapshots.len(),
        1,
        "exactly one successful snapshot, got {}",
        snapshots.len()
    );
    assert_eq!(
        snapshots[0].deployment_id, attempt.deployment_id,
        "exactly one successful entry, and it is the recovered attempt"
    );
    assert_eq!(
        ledger::successful_index(&h.store, "t1", &attempt.deployment_id)
            .unwrap()
            .unwrap(),
        0,
        "the recovered attempt is the successful chain position s0"
    );
    assert_eq!(
        h.store.read_last_successful("t1").as_deref(),
        Some(attempt.deployment_id.as_str()),
        "refs/last-successful must point at the recovered attempt"
    );
    assert_eq!(
        latest_status(h, attempt.deployment_id.as_str()),
        DeploymentStatus::Successful,
        "latest transition must be finalized as Successful"
    );
    let marker = h
        .remotes_base
        .join("s1")
        .join(crate::remote::layout::commit_marker(
            attempt.deployment_id.as_str(),
        ));
    assert!(
        marker.exists(),
        "commit marker must be present on the remote"
    );
}

/// Build and persist a valid release record protecting the given variant
/// trees (the pin-only trees of the engine-level pin-abort test).
pub(crate) fn engine_pin_release(store: &LocalStore, pin_trees: &[&str]) -> ReleaseRecord {
    let variants: BTreeMap<VariantName, TreeDigest> = pin_trees
        .iter()
        .enumerate()
        .map(|(i, t)| {
            (
                VariantName::new(format!("v{i}")),
                TreeDigest::new(t.to_string()),
            )
        })
        .collect();
    let rec = crate::verify::release::build_release(
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

/// A normal single-server push with a caller-supplied deployment id over
/// healthy `LocalTransport` remotes (no injected remote faults). Drives
/// the FULL normal success path (`push_inner`) so a test can arm store
/// faults keyed by the fixed deployment id BEFORE the push runs.
pub(crate) fn push_main_with_id(
    h: &RecoveryHarness,
    deployment_id: &DeploymentId,
) -> Result<PushReport> {
    let project_root = h.config.project_root(&h.cfg_path);
    let target = h.config.target("t1").expect("harness configures target t1");
    let op_id = OperationId::new(format!("op-{}", deployment_id.as_str()));
    let rf = h.remotes_base.clone();
    let script = h.script.clone();
    let factory = move |s: &crate::config::ServerDef,
                        _slot: &crate::config::SlotConfig|
          -> Result<Box<dyn Remote>> {
        Ok(Box::new(LocalTransport::with_exec(
            &crate::testutil::fixture_env(),
            rf.join(s.id.as_str()),
            script.clone(),
        )?))
    };
    push_inner(
        &project_root,
        &h.store,
        &factory,
        "t1",
        &crate::deploy::plan::SlotSelection::normalize(&h.config, "t1", None).unwrap(),
        &RefExpr::Head,
        None,
        deployment_id,
        &op_id,
        &h.config,
        target,
        &PushOptions {
            dry_run: false,
            ref_token: None,
            group: None,
        },
    )
}

/// The single attempt recorded for target `t1`, in REPORT form (the
/// in-memory view of the persisted intent; the report's `slots` map is
/// empty because the persisted intent carries no outcomes).
pub(crate) fn single_attempt(h: &RecoveryHarness) -> LedgerIntentReport {
    let mut attempts = h.store.read_attempts("t1").unwrap();
    assert_eq!(attempts.len(), 1, "exactly one attempt recorded");
    LedgerIntentReport::from_intent(&attempts.remove(0).intent).expect("verified intent parses")
}

/// The rollback payload of a successful ledger entry (the test view of
/// the `DeploymentSnapshot` fields: `slots`, `bindings`).
pub(crate) fn rollback_of(entry: &LedgerEntry) -> &crate::ledger::LedgerRollback {
    match &entry
        .terminal
        .as_ref()
        .expect("the entry has a terminal")
        .disposition
    {
        TerminalDisposition::Successful { rollback, .. } => rollback,
        _ => panic!("a successful snapshot entry carries a rollback state"),
    }
}

/// Recursively snapshot every file under `dir` as (relative path, bytes),
/// sorted, for byte-for-byte store-comparison assertions.
pub(crate) fn snapshot_files(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let rel = p.strip_prefix(dir).unwrap().to_string_lossy().into_owned();
                out.push((rel, std::fs::read(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
}

pub(crate) const SYSD_VARIANT: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/sysd"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[activation]
adapter = "systemd"
scope = "user"
units = [{ name = "svc.service", artifact_path = "app/svc.service", enable = true, restart = true }]

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
attempts = 1
interval_seconds = 0
"#;

/// Install a fake `systemctl` shim on PATH and point `XDG_CONFIG_HOME` at
/// a hermetic temp dir (the installed unit lands there). The shim fails
/// `restart` (exit 1) while the marker file exists; with `once` it
/// CONSUMES the marker on the first failure, so a later restart (e.g. the
/// compensation's prior-activation restart) succeeds.
///
/// Round-4 decision: kept HERE (not moved to `crate::verify::systemd`
/// tests) because its only consumers are the push-spine activation
/// tests below (activation failure → compensation → status), which drive
/// `push_inner` through the `SysdHarness` — push-internal plumbing. The
/// systemd adapter's own tests use a simpler inline `exit 0` shim; the
/// FAIL/ONCE failure-injection semantics have no consumer there.
/// Install a fake `systemctl` (daemon-reload/enable/restart all succeed,
/// with an optional one-shot forced restart failure via `FAKE_SYSTEMCTL_FAIL`)
/// and return the HERMETIC environment the fake rides in: the child processes
/// (transport shell commands) receive this snapshot, so the parent process
/// environment is never mutated.
pub(crate) fn install_fake_systemctl(
    base: &std::path::Path,
    marker: &std::path::Path,
    once: bool,
) -> crate::env::SysEnv {
    let bindir = base.join("bin");
    std::fs::create_dir_all(&bindir).unwrap();
    let fake = bindir.join("systemctl");
    std::fs::write(
            &fake,
            "#!/bin/sh\nif [ \"$1\" = \"--user\" ]; then shift; fi\ncase \"$1\" in\nrestart)\n  if [ -n \"$FAKE_SYSTEMCTL_FAIL\" ] && [ -f \"$FAKE_SYSTEMCTL_FAIL\" ]; then\n    if [ \"$FAKE_SYSTEMCTL_ONCE\" = \"1\" ]; then rm -f \"$FAKE_SYSTEMCTL_FAIL\"; fi\n    echo \"fake systemctl: forced restart failure\" >&2\n    exit 1\n  fi\n  exit 0\n  ;;\n*)\n  exit 0\n  ;;\nesac\n",
        )
        .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let base_env = crate::testutil::fixture_env();
    let mut vars: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> =
        base_env.child_env().into_iter().collect();
    vars.insert(
        "PATH".into(),
        format!(
            "{}:{}",
            bindir.display(),
            base_env
                .path()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default()
        )
        .into(),
    );
    vars.insert(
        "XDG_CONFIG_HOME".into(),
        base.join("xdg").as_os_str().to_owned(),
    );
    vars.insert("FAKE_SYSTEMCTL_FAIL".into(), marker.as_os_str().to_owned());
    vars.insert(
        "FAKE_SYSTEMCTL_ONCE".into(),
        if once { "1" } else { "0" }.into(),
    );
    crate::env::SysEnv::from_map(vars)
}

/// A single-slot (`s1`/`t1`) project whose variant uses SYSTEMD
/// activation with a `restart` unit, plus the artifact files.
pub(crate) struct SysdHarness {
    pub(crate) _dir: tempfile::TempDir,
    pub(crate) cfg_path: PathBuf,
    pub(crate) config: ProjectConfig,
    pub(crate) store: LocalStore,
    pub(crate) remotes_base: PathBuf,
    env: crate::env::SysEnv,
}

impl SysdHarness {
    /// Build the harness with an explicit environment snapshot; the push
    /// factory's transports and their child processes receive THIS env (e.g.
    /// a hermetic env with a fake `systemctl` on PATH), never the parent's.
    pub(crate) fn with_env(env: crate::env::SysEnv) -> SysdHarness {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(release_dir.join("standard.toml"), SYSD_VARIANT).unwrap();
        std::fs::write(project.join("deploy.toml"), NONE_TOML).unwrap();
        let artifacts = release_dir.join("artifacts");
        for (p, c) in [
            ("build/output/app/server", "v1\n"),
            (
                "build/output/svc.service",
                "[Unit]\nDescription=svc ({{ user }})\n\n[Service]\nExecStart={{ deploy_dir }}/current/app/server\n",
            ),
        ] {
            let fp = artifacts.join(p);
            std::fs::create_dir_all(fp.parent().unwrap()).unwrap();
            std::fs::write(&fp, c).unwrap();
        }
        let cfg_path = project.join("deploy.toml");
        let config = ProjectConfig::load(&cfg_path).unwrap();
        let store = LocalStore::with_base(dir.path().join("store")).unwrap();
        let remotes_base = dir.path().join("remotes");
        std::fs::create_dir_all(&remotes_base).unwrap();
        SysdHarness {
            _dir: dir,
            cfg_path,
            config,
            store,
            remotes_base,
            env,
        }
    }

    pub(crate) fn push_head(&self, deployment_id: &DeploymentId) -> Result<PushReport> {
        let project_root = self.config.project_root(&self.cfg_path);
        let target = self.config.target("t1").expect("harness target");
        let op_id = OperationId::new(format!("op-{}", deployment_id.as_str()));
        let rf = self.remotes_base.clone();
        let env = self.env.clone();
        let factory = move |s: &crate::config::ServerDef,
                            _slot: &crate::config::SlotConfig|
              -> Result<Box<dyn Remote>> {
            Ok(Box::new(LocalTransport::new(&env, rf.join(s.id.as_str()))?))
        };
        push_inner(
            &project_root,
            &self.store,
            &factory,
            "t1",
            &crate::deploy::plan::SlotSelection::normalize(&self.config, "t1", None).unwrap(),
            &RefExpr::Head,
            None,
            deployment_id,
            &op_id,
            &self.config,
            target,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
        )
    }
}

/// A transport wrapper that reports a FIXED number of available bytes,
/// letting a test control the headroom the capacity preflight sees
/// deterministically (mirrors `plan::capacity_tests`).
pub(crate) struct FakeCapacityRemote {
    pub(crate) inner: LocalTransport,
    pub(crate) avail: u64,
}

impl FakeCapacityRemote {
    pub(crate) fn build(base: PathBuf, avail: u64) -> Result<Box<dyn Remote>> {
        Ok(Box::new(FakeCapacityRemote {
            inner: LocalTransport::with_exec(
                &crate::testutil::fixture_env(),
                base,
                ScriptedExec::default_success(),
            )?,
            avail,
        }))
    }
}

impl Remote for FakeCapacityRemote {
    fn root(&self) -> &std::path::Path {
        self.inner.root()
    }
    fn provision_layout(&self) -> Result<()> {
        self.inner.provision_layout()
    }
    fn read(&self, rel: &std::path::Path) -> Result<Vec<u8>> {
        self.inner.read(rel)
    }
    fn write(&self, rel: &std::path::Path, data: &[u8], mode: u32) -> Result<()> {
        self.inner.write(rel, data, mode)
    }
    fn try_write_new(&self, rel: &std::path::Path, data: &[u8]) -> Result<CreateNewVerdict> {
        self.inner.try_write_new(rel, data)
    }
    fn create_dir(&self, rel: &std::path::Path) -> Result<()> {
        self.inner.create_dir(rel)
    }
    fn create_dir_all(&self, rel: &std::path::Path) -> Result<()> {
        self.inner.create_dir_all(rel)
    }
    fn set_mode(&self, rel: &std::path::Path, mode: u32) -> Result<()> {
        self.inner.set_mode(rel, mode)
    }
    fn list(&self, rel: &std::path::Path) -> Result<Vec<crate::remote::transport::RemoteEntry>> {
        self.inner.list(rel)
    }
    fn rename(&self, from: &std::path::Path, to: &std::path::Path) -> Result<()> {
        self.inner.rename(from, to)
    }
    fn symlink(&self, target: &std::path::Path, link: &std::path::Path) -> Result<()> {
        self.inner.symlink(target, link)
    }
    fn read_link(&self, rel: &std::path::Path) -> Result<std::path::PathBuf> {
        self.inner.read_link(rel)
    }
    fn remove_file(&self, rel: &std::path::Path) -> Result<()> {
        self.inner.remove_file(rel)
    }
    fn remove_dir_all(&self, rel: &std::path::Path) -> Result<()> {
        self.inner.remove_dir_all(rel)
    }
    fn exists(&self, rel: &std::path::Path) -> bool {
        self.inner.exists(rel)
    }
    fn metadata(&self, rel: &std::path::Path) -> Result<crate::remote::transport::RemoteMeta> {
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
        Ok(crate::remote::transport::FsBytes {
            total: self.avail,
            available: self.avail,
        })
    }
}

/// The slot universe + fixed members the generated memberships draw from,
/// mirroring the plan.rs property: `p1`/`p2`/`p3` are the generated
/// COMMON members (declared for BOTH targets), `iso` is a `t2`-ONLY
/// member, and `phys` is a constant member whose PHYSICAL binding
/// (server) the fixture may drift while its id stays (logical-only
/// comparison). Each slot owns a distinct server so the per-target
/// server-uniqueness validation passes for every generated membership.
pub(crate) const MEMBERSHIP_UNIVERSE: [&str; 3] = ["p1", "p2", "p3"];

/// Build the membership-drift fixture: a project with targets `t1`/`t2`
/// whose CURRENT variant declares the generated membership (plus the
/// constants `phys`, `iso`), and a release record whose OWN frozen
/// canonical slot snapshot declares the RELEASE-VERSIONED membership
/// (plus the same constants). The variant is MATERIALIZED and the real
/// tree object stored, and the release record carries a REAL behavior
/// snapshot (verified against the record's provenance digest), so a
/// MATCHING-membership real push can complete the whole deployment (the
/// property's control branch). `physical_drift` rebinds `phys` to a
/// different server in the config only (its id stays — the membership
/// comparison is logical only). Returns the fixture's tempdir, config
/// path, config, store, and the written release id.
pub(crate) fn membership_drift_fixture(
    release_inc: [bool; 3],
    current_inc: [bool; 3],
    physical_drift: bool,
) -> (
    tempfile::TempDir,
    PathBuf,
    ProjectConfig,
    LocalStore,
    ReleaseId,
) {
    let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let release_dir = project.join("releases").join("v1");
    std::fs::create_dir_all(&release_dir).unwrap();

    // Current variant file: one slot entry per generated current member,
    // plus the constant `iso` (t2-only) and `phys` (rebound when
    // `physical_drift`). The mappings + activation/verification mirror the
    // harness `NONE_VARIANT` so a real push completes.
    let mut variant = String::new();
    let add_slot = |variant: &mut String, id: &str, server: &str, target: &str, dir: &str| {
        variant.push_str(&format!(
                "[[slots]]\nid = \"{id}\"\nserver = \"{server}\"\ntarget = \"{target}\"\ndeploy_dir = \"{dir}\"\n\n"
            ));
    };
    for (i, inc) in current_inc.iter().enumerate() {
        if *inc {
            let id = MEMBERSHIP_UNIVERSE[i];
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
            "[[artifact.mappings]]\nfrom = \"artifacts/build/output/\"\nto = \"app/\"\nrecursive = true\n\n\
             [[artifact.mappings]]\nfrom = \"artifacts/deployment/common/\"\nto = \"app-common/\"\nrecursive = true\n\n\
             [retention.per_server]\nkeep_distinct_artifacts = 1\nkeep_days = 0\nprotect_previous = true\n\n\
             [retention.deployment]\nprotect_deployments = 1\n\n\
             [activation]\nadapter = \"none\"\n\n\
             [verification]\nadapter = \"command\"\nargv = [\"true\"]\ntimeout_seconds = 5\nattempts = 1\ninterval_seconds = 0\n",
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
                "schema_version = 2\napplication = \"eng\"\nrelease = \"v1\"\n\n\
                 {servers}\
                 [targets.t1]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n\n\
                 [targets.t2]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n"
            ),
        )
        .unwrap();
    // The artifact files the mappings reference (and the real tree
    // materialized from them).
    let artifacts_dir = release_dir.join("artifacts");
    for (p, c) in [
        ("build/output/app/server", "v1\n"),
        ("deployment/common/README", "common\n"),
    ] {
        let fp = artifacts_dir.join(p);
        std::fs::create_dir_all(fp.parent().unwrap()).unwrap();
        std::fs::write(&fp, c).unwrap();
    }
    let config = ProjectConfig::load(&cfg_path).unwrap();
    let store = LocalStore::with_base(dir.path().join("store")).unwrap();
    let remotes_base = dir.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();

    // Materialize the variant and store the REAL tree object, exactly as a
    // HEAD push would, so the matching-membership control can run a FULL
    // real push (staging reads the local object).
    let staging = store.staging_dir().join("membership-fixture");
    crate::remote::canonical::materialize_variant(
        &release_dir,
        &config.variant("standard").unwrap().artifact.mappings,
        &crate::remote::canonical::TemplateVars::mapping(
            config.application().as_str(),
            config.release().as_str(),
            "standard",
        ),
        &staging,
    )
    .unwrap();
    let meta = crate::remote::canonical::canonicalize_tree(&staging).unwrap();
    let tree = meta.tree_sha256;
    store
        .store_object(&TreeDigest::new(tree.clone()), &staging)
        .unwrap();

    // The release's OWN frozen canonical snapshot: the generated
    // membership (slots owning t1 or t2) plus the constant phys (owns t1,
    // at its ORIGINAL server s5) and iso (owns t2), exactly mirroring the
    // current config's owning-target assignments.
    let mut canonical: Vec<CanonicalSlot> = Vec::new();
    for (i, id) in MEMBERSHIP_UNIVERSE.iter().enumerate() {
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

    // The behavior snapshot the real push's `read_release_behaviors`
    // verifies against the record's provenance digest, plus the mapping
    // aux file — mirroring what a HEAD push's `write_release_aux` stores.
    let vcfg = config.variant("standard").unwrap();
    let variant_behaviors: BTreeMap<String, BehaviorContract> = BTreeMap::from([(
        "standard".to_string(),
        BehaviorContract {
            activation: crate::config::ActivationConfig::from(vcfg.activation.clone()),
            verification: vcfg.verification.clone(),
        },
    )]);
    let behavior_sha = crate::verify::release::variant_behaviors_digest(&variant_behaviors);
    let behavior_json = serde_json::to_value(&variant_behaviors).unwrap();
    let mut variant_mappings: BTreeMap<String, Vec<Mapping>> = BTreeMap::new();
    variant_mappings.insert("standard".to_string(), vcfg.artifact.mappings.clone());
    let mapping_sha = crate::verify::release::variant_mappings_digest(&variant_mappings);

    // Assemble the record with the REAL provenance digests, then recompute
    // its identity from its own content (the digest folds the slot
    // snapshot, variant bindings, and provenance in), so `write_release`'s
    // recompute-and-verify passes.
    let mut rec = ReleaseRecord {
        release_schema_version: RELEASE_RECORD_SCHEMA_VERSION,
        release_id: "unused".to_string(),
        release_sha256: String::new(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        provenance: Provenance {
            mapping_sha256: mapping_sha,
            behavior_sha256: behavior_sha,
        },
        variants: BTreeMap::from([("standard".to_string(), tree.clone())]),
        slots: BTreeMap::from([("standard".to_string(), CanonicalSlots { slots: canonical })]),
    };
    let release = crate::verify::release::recompute_release_digest(&rec)
        .expect("the fixture record carries its slot snapshot");
    rec.release_sha256 = release.as_str().to_string();
    rec.release_id = crate::identity::ReleaseId::from_digest(&release)
        .as_str()
        .to_string();
    let rid = ReleaseId::new(rec.release_id.clone());
    store.write_release(&rec).unwrap();
    let mapping_toml = toml::to_string_pretty(&variant_mappings).unwrap();
    store
        .write_release_aux(&rid, &mapping_toml, &behavior_json)
        .unwrap();

    (dir, cfg_path, config, store, rid)
}

// THE REQUIRED DIRECT-RELEASE MEMBERSHIP PROPERTY: for generated
// RELEASE-VERSIONED vs CURRENT membership sets, a direct `release:<id>`
// push invokes the COMPLETE push path (`push(...)`) in BOTH modes — real
// (`dry_run: false`) and dry-run (`dry_run: true`) — with a RECORDING
// factory (construction AND every remote method call tick a shared
// counter). Every MISMATCHED membership is rejected with the
// membership-drift error BEFORE the remote factory is invoked: ZERO
// factory invocations and ZERO remote calls, in both modes — the drift
// gate lives in `push()` right after the ref is parsed/resolved, ahead of
// any lock and any factory contact (previously the check ran at plan time
// inside `push_inner`, after the read-only remote status had already
// contacted every remote).
//
// CONTROL (matching membership): both modes PLAN — the dry run returns a
// dry-run plan and the real push completes a FULL deployment — and the
// recording factory IS invoked (a valid push legitimately contacts
// remotes to inspect status / to deploy): the property's zero-contact
// assertion applies ONLY to the mismatch path, and the control's
// `calls > 0` checks prove the recording seam would catch a regression
// that re-introduced remote contact before the membership gate (a
// counter that could never move would make the zero-invocation assertion
// vacuous).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MembershipMutation {
    /// A fresh slot (`p99` on server `s7`) joins the target's current
    /// membership — the release froze a target without it.
    Add,
    /// The constant member `phys` is dropped from the target's current
    /// membership — the release froze it as a member.
    Remove,
    /// The constant member `phys` is renamed `physX` — the release froze
    /// the old id.
    Rename,
}

/// Render the variant file for a t1 membership: the generated universe
/// slots (`group_inc` in the group `group-a`, `extra_inc` outside any
/// group), the constant `phys` (id `phys_id` — `None` drops it, the
/// Remove mutation), and an optional extra slot (the Add mutation's
/// `p99`). Every slot owns a distinct server so the per-target
/// server-uniqueness validation passes for every rendered membership.
pub(crate) fn group_variant_string(
    group_inc: [bool; 3],
    extra_inc: [bool; 3],
    phys_id: Option<&str>,
    add_slot: Option<(&str, &str, &str)>,
) -> String {
    let mut variant = String::new();
    let push_slot = |variant: &mut String, id: &str, server: &str, groups: &[&str], dir: &str| {
        let groups_line = if groups.is_empty() {
            String::new()
        } else {
            format!("groups = [\"{}\"]\n", groups.join("\", \""))
        };
        variant.push_str(&format!(
                    "[[slots]]\nid = \"{id}\"\nserver = \"{server}\"\ntarget = \"t1\"\n{groups_line}deploy_dir = \"{dir}\"\n\n"
                ));
    };
    let group = "group-a";
    for (i, inc) in group_inc.iter().enumerate() {
        if *inc {
            let id = MEMBERSHIP_UNIVERSE[i];
            push_slot(
                &mut variant,
                id,
                &format!("s{}", i + 1),
                &[group],
                &format!("/srv/{id}"),
            );
        }
    }
    for (i, inc) in extra_inc.iter().enumerate() {
        if *inc && !group_inc[i] {
            let id = MEMBERSHIP_UNIVERSE[i];
            push_slot(
                &mut variant,
                id,
                &format!("s{}", i + 1),
                &[],
                &format!("/srv/{id}"),
            );
        }
    }
    if let Some(pid) = phys_id {
        push_slot(&mut variant, pid, "s5", &[], "/srv/phys");
    }
    if let Some((id, server, dir)) = add_slot {
        push_slot(&mut variant, id, server, &[], dir);
    }
    variant.push_str(
            "[[artifact.mappings]]\nfrom = \"artifacts/build/output/\"\nto = \"app/\"\nrecursive = true\n\n\
             [[artifact.mappings]]\nfrom = \"artifacts/deployment/common/\"\nto = \"app-common/\"\nrecursive = true\n\n\
             [retention.per_server]\nkeep_distinct_artifacts = 1\nkeep_days = 0\nprotect_previous = true\n\n\
             [retention.deployment]\nprotect_deployments = 1\n\n\
             [activation]\nadapter = \"none\"\n\n\
             [verification]\nadapter = \"command\"\nargv = [\"true\"]\ntimeout_seconds = 5\nattempts = 1\ninterval_seconds = 0\n",
        );
    variant
}

/// The group fixture's config: servers `s1..=s7` (s7 backs the Add
/// mutation's `p99`; unused servers are harmless) and the single target
/// `t1`.
pub(crate) fn group_config_string() -> String {
    let mut servers = String::new();
    for i in 1..=7 {
        servers.push_str(&format!(
                "[[servers]]\nid = \"s{i}\"\naddress = \"a{i}\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n"
            ));
    }
    format!(
        "schema_version = 2\napplication = \"eng\"\nrelease = \"v1\"\n\n\
             {servers}\
             [targets.t1]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }}\n"
    )
}

/// Build the direct-release GROUP fixture: target `t1`'s CURRENT config
/// declares the generated membership (the group `group-a` on exactly the
/// `group_inc` subset of the universe, the `extra_inc` slots outside any
/// group) plus the constant `phys`; the release record's OWN frozen
/// canonical snapshot declares the SAME membership (matching by
/// construction); and a SUCCESSFUL ledger entry carries every current t1
/// member with its current physical binding — the base a proper-subset
/// group push's partial-rollout guard needs to carry the unselected slots
/// forward. The behavior + mapping aux snapshots are stored so the
/// release path's `read_release_behaviors` verifies. Returns the
/// fixture's tempdir, config path, config, store, release id, and group
/// name.
pub(crate) fn group_membership_fixture(
    group_inc: [bool; 3],
    extra_inc: [bool; 3],
) -> (
    tempfile::TempDir,
    PathBuf,
    ProjectConfig,
    LocalStore,
    ReleaseId,
    String,
) {
    let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let release_dir = project.join("releases").join("v1");
    std::fs::create_dir_all(&release_dir).unwrap();
    std::fs::write(
        release_dir.join("standard.toml"),
        group_variant_string(group_inc, extra_inc, Some("phys"), None),
    )
    .unwrap();
    let cfg_path = project.join("deploy.toml");
    std::fs::write(&cfg_path, group_config_string()).unwrap();
    let config = ProjectConfig::load(&cfg_path).unwrap();
    let store = LocalStore::with_base(dir.path().join("store")).unwrap();
    let remotes_base = dir.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();

    // The behavior snapshot + mapping aux the release path verifies
    // against the record's provenance digests (mirroring a HEAD push's
    // `write_release_aux`).
    let vcfg = config.variant("standard").unwrap();
    let variant_behaviors: BTreeMap<String, BehaviorContract> = BTreeMap::from([(
        "standard".to_string(),
        BehaviorContract {
            activation: crate::config::ActivationConfig::from(vcfg.activation.clone()),
            verification: vcfg.verification.clone(),
        },
    )]);
    let behavior_sha = crate::verify::release::variant_behaviors_digest(&variant_behaviors);
    let behavior_json = serde_json::to_value(&variant_behaviors).unwrap();
    let mut variant_mappings: BTreeMap<String, Vec<Mapping>> = BTreeMap::new();
    variant_mappings.insert("standard".to_string(), vcfg.artifact.mappings.clone());
    let mapping_sha = crate::verify::release::variant_mappings_digest(&variant_mappings);

    // The release's OWN frozen canonical snapshot: the generated
    // membership (group declarations mirroring the config) plus the
    // constant `phys`.
    let group = "group-a".to_string();
    let mut canonical: Vec<CanonicalSlot> = Vec::new();
    for (i, id) in MEMBERSHIP_UNIVERSE.iter().enumerate() {
        if group_inc[i] || extra_inc[i] {
            canonical.push(CanonicalSlot {
                id: id.to_string(),
                server: format!("s{}", i + 1),
                deploy_dir: format!("/srv/{id}"),
                target: "t1".to_string(),
                groups: if group_inc[i] {
                    vec![group.clone()]
                } else {
                    Vec::new()
                },
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
    canonical.sort_by(|a, b| a.id.cmp(&b.id));
    let mut rec = ReleaseRecord {
        release_schema_version: RELEASE_RECORD_SCHEMA_VERSION,
        release_id: "unused".to_string(),
        release_sha256: String::new(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        provenance: Provenance {
            mapping_sha256: mapping_sha,
            behavior_sha256: behavior_sha,
        },
        variants: BTreeMap::from([(
            "standard".to_string(),
            test_tree_digest("tree-group").as_str().to_string(),
        )]),
        slots: BTreeMap::from([("standard".to_string(), CanonicalSlots { slots: canonical })]),
    };
    let release = crate::verify::release::recompute_release_digest(&rec)
        .expect("the fixture record carries its slot snapshot");
    rec.release_sha256 = release.as_str().to_string();
    rec.release_id = crate::identity::ReleaseId::from_digest(&release)
        .as_str()
        .to_string();
    let rid = ReleaseId::new(rec.release_id.clone());
    store.write_release(&rec).unwrap();
    let mapping_toml = toml::to_string_pretty(&variant_mappings).unwrap();
    store
        .write_release_aux(&rid, &mapping_toml, &behavior_json)
        .unwrap();

    // The SUCCESSFUL ledger entry whose rollback payload carries every
    // current t1 member and its current binding — the base a
    // proper-subset group push's partial-rollout guard needs to carry the
    // unselected slots forward.
    let artifact = ArtifactRef {
        release: rid.clone(),
        variant: VariantName::new("standard".to_string()),
        tree: test_tree_digest("tree-group"),
    };
    let slots: BTreeMap<SlotId, GenerationRef> = config
        .target_slots("t1")
        .unwrap()
        .into_iter()
        .map(|(slot, _)| {
            let slot_id =
                SlotId::parse(slot.id.as_str()).expect("validated slot id is a safe segment");

            (
                slot_id.clone(),
                GenerationRef {
                    generation: test_generation_id(slot.id.as_str()),
                    assignment: crate::identity::PlacementSlotAssignment {
                        placement_slot: slot_id.clone(),
                        artifact: artifact.clone(),
                    },
                },
            )
        })
        .collect();
    let bindings = config.target_slot_bindings("t1").unwrap();
    seed_snapshot(
        &store,
        "t1",
        "deploy-group-base",
        "sha256-base",
        slots,
        bindings,
    );

    (dir, cfg_path, config, store, rid, group)
}

/// Rewrite the fixture's CURRENT config with a COMPLETE-membership
/// mutation on target `t1` (the release record and ledger stay frozen to
/// the original membership), and return the reloaded config.
pub(crate) fn apply_group_membership_mutation(
    dir: &tempfile::TempDir,
    cfg_path: &Path,
    group_inc: [bool; 3],
    extra_inc: [bool; 3],
    mutation: MembershipMutation,
) -> ProjectConfig {
    let variant_path = dir
        .path()
        .join("proj")
        .join("releases")
        .join("v1")
        .join("standard.toml");
    let (phys_id, add_slot) = match mutation {
        MembershipMutation::Add => (Some("phys"), Some(("p99", "s7", "/srv/p99"))),
        MembershipMutation::Remove => (None, None),
        MembershipMutation::Rename => (Some("physX"), None),
    };
    std::fs::write(
        &variant_path,
        group_variant_string(group_inc, extra_inc, phys_id, add_slot),
    )
    .unwrap();
    ProjectConfig::load(cfg_path).unwrap()
}

// frozen/current memberships (the release freezes exactly the target's
// current membership, by construction) plus an ARBITRARY NONEMPTY group
// subset of the target's slots, a direct `release:<id> --group <g>` push
// (the COMPLETE push path, dry-run mode) RESOLVES AND PLANS — the
// membership gate now validates the release's FULL frozen set against the
// target's COMPLETE current set (never the group-filtered selection), so
// EVERY proper subset plans, and the dry-run plan covers EXACTLY the
// group's slots. MUTATING the COMPLETE membership (add/remove/rename of a
// full-target slot) ALWAYS fails BEFORE REMOTE ACCESS: the drift gate
// fires on the FULL set in BOTH real and dry-run modes with the recording
// factory reporting ZERO invocations.
