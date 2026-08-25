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
//! target's observed projection, the per-target snapshot and
//! deployment-attempt logs, pending-commit and rotation-debt state — and
//! [`assert_semantic_invariants`] cross-checks it against the system's
//! observable state after every action while re-evaluating all five
//! invariant groups. Random vectors with shrinking find interleaving bugs the
//! fixed sequences miss, and minimize any failing vector to its core.
//! The oracle classifies EVERY push outcome into two INDEPENDENT dimensions —
//! the return boundary (`Ok` report vs `Err`) and the deployment disposition
//! (what the attempt recorded) — so an `Err` that occurred before the intent
//! was persisted is never conflated with an `Ok` report carrying a terminal
//! failure status (the old single-class `ErrPreCommit` folded both together).
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
use crate::testutil::step17_hook;
use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, RngSeed};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
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
/// (newest 1 distinct binding, no age window, no previous protection, 1 snapshot
/// deployment) while `t2` is CONSERVATIVE (newest 5 distinct bindings, 30
/// days of age, the protected previous, 2 deployments). The union is
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

[targets.t1.rotation.deployment]
protect_deployments = 1

[targets.t2.rotation.per_server]
keep_distinct_artifacts = 5
keep_days = 30
protect_previous = true

[targets.t2.rotation.deployment]
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

[targets.debtfx.rotation.deployment]
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
    /// commit marker write on the remote (`state/commits/<id>.json`).
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
    /// Roll the target back to snapshot index `n`.
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
    AssignmentVariant,
    AssignmentRelease,
    /// Rewrite the stored `behavior.json` of the release the current
    /// generation runs (one identity-bearing field changed), so the historical
    /// behavior read and the publication path must fail closed.
    BehaviorJson,
    /// Rewrite the STORED release record's `release_schema_version` to a
    /// non-canonical value: the record must fail closed on every read and
    /// block the next push (see
    /// `integrity_stored_release_schema_version_tamper_fails_closed`).
    ReleaseSchemaVersion,
}

/// The outcome of one applied action.
pub(crate) enum Outcome {
    Push(Box<Result<PushReport>>),
    Ok,
    Tampered,
}

/// The RETURN BOUNDARY — the FIRST of the two independent outcome dimensions:
/// whether the push API returned `Ok(report)` or `Err(_)`. An `Err` means the
/// push call itself failed; an `Ok` means a report was returned (what the
/// report records is the SECOND dimension, the [`Disposition`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReturnBoundary {
    /// The push API returned `Ok(report)`.
    Ok,
    /// The push API returned `Err(_)`.
    Err,
}

/// The DEPLOYMENT DISPOSITION — the SECOND of the two independent outcome
/// dimensions: what, if anything, the push recorded. On an `Ok` return it
/// maps from the report status (`Successful` / `PendingCommit` / the terminal
/// failure statuses / `None` for the no-op report); on an `Err` return it is
/// resolved from the system's store — whether the intent was persisted BEFORE
/// the failure and, if so, the attempt's latest status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Disposition {
    /// Nothing was recorded: the no-op report (`status: None`), a non-push
    /// action's plain [`Outcome::Ok`], or an `Err` that occurred BEFORE the
    /// intent was persisted (plan rejection, early lock contention, the
    /// `append_attempt` itself) — no attempt/plan exists.
    NoAttempt,
    /// The deployment durably committed: report status `Successful` (attempt,
    /// snapshot, `refs/last-successful`, and the terminal transition all
    /// durable). Post-commit maintenance warnings (rotation, observed
    /// refresh, debt I/O) ride on the SAME report and never change the class.
    Successful,
    /// Recorded but NOT durably committed: report status `PendingCommit`
    /// (the commit marker write failed — a deferred/recoverable
    /// completion a later push reconciles), or a crash-window `Err` that left
    /// the recorded attempt recoverable-pending (`PendingCommit` /
    /// `InProgress`).
    Pending,
    /// The attempt ended terminal `FailedPreflight`: a pre-mutation failure
    /// AFTER the intent was persisted (capacity/staging) — the push returns
    /// `Err` with the attempt recorded `FailedPreflight`.
    FailedPreflight,
    /// The attempt ended terminal `FailedRolledBack` (activation failure
    /// fully compensated).
    FailedRolledBack,
    /// The attempt ended terminal `Degraded` (failed compensation / a
    /// non-rollback failure policy).
    Degraded,
}

/// The expected outcome CLASS of one applied action — the RESULT the model
/// oracle predicts and the property test compares against the actual
/// [`Outcome`] the system produced. A push is classified into TWO INDEPENDENT
/// dimensions — the [`ReturnBoundary`] (`Ok` report vs `Err`) and the
/// [`Disposition`] — asserted separately after EVERY action, so `Ok` +
/// [`Disposition::FailedPreflight`] is a DIFFERENT class from `Err` +
/// [`Disposition::NoAttempt`]: an IntentPersist regression that wrongly
/// returned `Ok(FailedPreflight)` would satisfy the OLD single-class
/// `ErrPreCommit` oracle but fails the boundary comparison here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutcomeClass {
    /// A push result — or a non-push action's plain [`Outcome::Ok`] (Build /
    /// Rotate / InjectFailure record nothing) — classified into the
    /// (boundary, disposition) pair. `Ok` + `NoAttempt` is the no-op report
    /// (and any non-push action); `Ok` + `Successful` is the durably
    /// committed deployment; `Ok` + `Pending` is the recoverable
    /// commit failure; `Err` + `NoAttempt` is a pre-intent failure;
    /// `Err` + `Pending` is a crash-window failure whose intent WAS recorded.
    Push {
        boundary: ReturnBoundary,
        disposition: Disposition,
    },
    /// A deliberate [`Action::Tamper`] — the Integrity group is broken by
    /// construction and the fixture reports [`Outcome::Tampered`]; no
    /// boundary/disposition pair is meaningful.
    Tampered,
}

/// The per-step failure class the property test injects, generated TOGETHER
/// with the action (the model must predict the outcome class under every
/// failure class). Local-store steps map onto the `test_faults` one-shot
/// arms keyed by the step's deployment id; the two remote steps use the
/// suffix-armed one-shot transport fault; [`FailureClass::LockContention`]
/// holds the slot's mutation lock via a second `RemoteHelper` guard for the
/// whole action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureClass {
    /// No fault: a clean action.
    None,
    /// Remote commit marker write fails: the attempt reports
    /// `PendingCommit` (recoverable; a later push reconciles it).
    CommitMarker,
    /// Remote post-commit rotation inventory write fails: the rotation is
    /// deferred (debt marker + warning) after the durable commit.
    RotationInventory,
    /// Local intent persist (`append_attempt`) fails BEFORE any remote
    /// mutation: the push returns `Err` with nothing recorded.
    IntentPersist,
    /// Local outcomes store (`write_results`) fails after the servers
    /// advanced but before any durable commit: `Err`, remote advanced, the
    /// observed refresh never ran (the crash window).
    ResultsWrite,
    /// Replay-safe finalizer's snapshot append fails: `Err`, the attempt is
    /// left `PendingCommit` (re-eligible), observed not refreshed.
    SnapshotAppend,
    /// Finalizer's `refs/last-successful` write fails: `Err`, the snapshot is
    /// durable, the ref stale, the attempt `PendingCommit`.
    LastSuccessfulWrite,
    /// Finalizer's terminal `Successful` transition append fails: `Err`, the
    /// snapshot + ref durable, the attempt `PendingCommit`.
    TransitionSuccessful,
    /// Finalizer's recoverable `PendingCommit` marker append fails: `Err`, the
    /// attempt stays `InProgress`.
    TransitionPending,
    /// Post-commit observed-refresh `write_server` fails (warning-only): the
    /// observed maps themselves still refresh.
    ObservedWriteServer,
    /// Post-commit observed-refresh `write_observed` for the PUSH'S OWN
    /// target fails: that target's projection stays stale.
    ObservedPrimaryWrite,
    /// Post-commit observed-refresh `write_observed` for the OTHER member
    /// target of the shared slot fails: the other member's projection stays
    /// stale.
    ObservedOtherWrite,
    /// Rotation-debt marker READ fails (target-keyed: the store's debt
    /// methods carry no deployment id, so the arm lands on the pushed
    /// target's `rotation-debt.json`). Post-commit maintenance is
    /// NON-FALLIBLE — a warning, never an `Err` — so the committed outcome
    /// class is unchanged and the marker effect the model tracks is
    /// deterministic.
    DebtRead,
    /// Rotation-debt marker WRITE fails (the same `write_rotation_debt`
    /// call as the remove). Warning-only; non-fallible.
    DebtWrite,
    /// Rotation-debt marker REMOVE — the same `write_rotation_debt` call as
    /// the write; kept as a distinct class so the {read, write, remove}
    /// matrix is explicit. Warning-only; non-fallible.
    DebtRemove,
    /// The slot's mutation lock is HELD for the whole action by a second
    /// `RemoteHelper` guard. The push's EARLY per-slot preflight checks the
    /// lock and aborts with `Err` BEFORE any attempt record, reconciliation,
    /// or the no-op check — even an up-to-date push errors, and nothing is
    /// recorded or mutated.
    LockContention,
    /// The slot's mutation lock is CONTENDED ONLY AT STEP 17 (the
    /// post-commit per-slot rotation), via the test-only step-17 phase hook
    /// ([`crate::testutil::step17_hook`]): the engine parks immediately
    /// before its per-slot `acquire_lock_guard`, the fixture holds the
    /// competing guard, then releases the engine — so the rotation
    /// deterministically defers (debt marker + warning naming the slot), the
    /// push still reports `Successful` (it already committed — the outcome
    /// class is `Ok` + `Successful`, NEVER `Err`), and a later clean no-op
    /// services the marker once the lock is free. The pre-commit lock checks
    /// (preflight, reconcile, commit) run while the lock is FREE: the
    /// fixture only grabs the guard the moment the engine parks at a
    /// step-17-equivalent lock acquisition — the push's own step-17 rotation
    /// AND, when prior debt exists, the deferred-maintenance retry that runs
    /// before it (the fixture services every park, so both contend). The
    /// park signal is PHASE-DISTINGUISHED ([`step17_hook::HookPhase`]): the
    /// retry is the [`step17_hook::HookPhase::DeferredRetry`] phase, the
    /// push's own rotation the [`step17_hook::HookPhase::FreshStep17`]
    /// phase.
    Step17Contended,
    /// [`FailureClass::Step17Contended`] combined with a rotation-debt
    /// marker READ fault in the same push, armed by the fixture ONLY at the
    /// FRESH step-17 park ([`step17_hook::HookPhase::FreshStep17`]) — never
    /// at the deferred-maintenance retry ([`step17_hook::HookPhase::DeferredRetry`]),
    /// which reads the debt FIRST and must pass unarmed. The fresh contended
    /// deferral's `set_rotation_deferred` read then fails (explicit "rotation
    /// debt maintenance deferred: failed to read" warning): NO new marker is
    /// persisted, and a PREEXISTING marker is preserved untouched. A later
    /// push re-defers. Warning-only; non-fallible.
    Step17ContentionDebtRead,
    /// [`FailureClass::Step17Contended`] combined with a rotation-debt
    /// marker WRITE fault (in the same push), armed by the fixture ONLY at
    /// the FRESH phase park — the retry's earlier debt write (preexisting
    /// marker) passes unarmed. The fresh contended deferral's
    /// `set_rotation_deferred` cannot persist the marker — explicit
    /// "rotation debt maintenance deferred: failed to write" warning, NO
    /// new marker (no automatic retryability claim) and any PREEXISTING
    /// marker preserved byte-identical (the failed write leaves the file
    /// untouched). Warning-only; non-fallible.
    Step17ContentionDebtWrite,
}

/// The step-17 contention else-branch's explicit per-slot warning: the
/// marker-persisted "retryable" claim the model asserts for the contention
/// combinations (a later push services the marker once the lock is free).
const STEP17_CONTENTION_WARNING: &str =
    "rotation deferred for slot 'p1': slot lock held by another operation";
/// The explicit debt-I/O failure notice — the marker was NOT persisted /
/// maintenance deferred WITHOUT a marker, so no automatic retryability is
/// claimed. `set_rotation_deferred` (and the retry's I/O) emit exactly this
/// shape on a read/write failure.
const DEBT_READ_WARNING: &str = "rotation debt maintenance deferred: failed to read rotation debt";
const DEBT_WRITE_WARNING: &str =
    "rotation debt maintenance deferred: failed to write rotation debt";

/// Classify an ACTUAL [`Outcome`] into the two-dimension [`OutcomeClass`] the
/// model must have predicted. `Push(Ok(report))` is classified by the report's
/// status (`Successful` -> `Ok` + `Successful`, `PendingCommit` -> `Ok` +
/// `Pending`, the terminal statuses -> `Ok` + their EXACT disposition, `None`
/// status -> the no-op, `Ok` + `NoAttempt`); `Push(Err(_))` is `Err` + the
/// disposition resolved by `err_disposition` — the caller (the fixture) asks
/// the system's OWN store whether THIS push's intent was persisted before it
/// failed (a pre-intent `Err` recorded nothing -> `NoAttempt`; the
/// crash-window `Err`s recorded a recoverable-pending attempt -> `Pending`; a
/// post-intent preflight failure recorded the terminal `FailedPreflight`).
fn classify_outcome(
    outcome: &Outcome,
    err_disposition: impl FnOnce() -> Disposition,
) -> OutcomeClass {
    match outcome {
        Outcome::Ok => OutcomeClass::Push {
            boundary: ReturnBoundary::Ok,
            disposition: Disposition::NoAttempt,
        },
        Outcome::Tampered => OutcomeClass::Tampered,
        Outcome::Push(result) => match &**result {
            Ok(report) => {
                let boundary = ReturnBoundary::Ok;
                let disposition = match report.status {
                    None => {
                        assert_eq!(
                            report.message, "Everything up to date",
                            "the only statusless report the fixture produces is the no-op"
                        );
                        Disposition::NoAttempt
                    }
                    Some(DeploymentStatus::Successful) => Disposition::Successful,
                    Some(DeploymentStatus::PendingCommit) => Disposition::Pending,
                    Some(DeploymentStatus::FailedPreflight) => Disposition::FailedPreflight,
                    Some(DeploymentStatus::Degraded) => Disposition::Degraded,
                    Some(DeploymentStatus::FailedRolledBack) => Disposition::FailedRolledBack,
                    Some(DeploymentStatus::InProgress) => {
                        panic!("a final push report must never carry InProgress")
                    }
                };
                OutcomeClass::Push {
                    boundary,
                    disposition,
                }
            }
            Err(_) => OutcomeClass::Push {
                boundary: ReturnBoundary::Err,
                disposition: err_disposition(),
            },
        },
    }
}

/// REGRESSION GUARD for the two-dimension split: the oracle must distinguish
/// the CORRECT IntentPersist outcome — `Err` + `NoAttempt` (the intent
/// persist fails BEFORE any record) — from the WRONG pair an IntentPersist
/// regression would return: `Ok` + `FailedPreflight` (a preflight failure
/// reported in an `Ok` report). The OLD single-class oracle folded both into
/// `ErrPreCommit` and passed the regression; the boundary dimension
/// distinguishes them.
#[test]
fn classifier_distinguishes_err_noattempt_from_ok_failed_preflight() {
    use crate::error::Error;
    let no_attempt = || Disposition::NoAttempt;

    // The correct outcome for the IntentPersist fault: the push returns Err
    // with nothing recorded (verified against the engine: `append_attempt`
    // fails before any remote mutation, `read_attempts` stays empty).
    let correct = classify_outcome(
        &Outcome::Push(Box::new(Err(Error::store(
            "test fault: append_attempt forced to fail once",
        )))),
        no_attempt,
    );
    assert_eq!(
        correct,
        OutcomeClass::Push {
            boundary: ReturnBoundary::Err,
            disposition: Disposition::NoAttempt,
        }
    );

    // The regression: the same fault wrongly reported as an Ok report with
    // the terminal `FailedPreflight` status. Different boundary AND different
    // disposition — the oracle must NOT conflate the two.
    let regression = classify_outcome(
        &Outcome::Push(Box::new(Ok(PushReport {
            status: Some(DeploymentStatus::FailedPreflight),
            attempt: None,
            message: "staging failed".to_string(),
            warning: None,
            dry_run: false,
        }))),
        no_attempt,
    );
    assert_eq!(
        regression,
        OutcomeClass::Push {
            boundary: ReturnBoundary::Ok,
            disposition: Disposition::FailedPreflight,
        }
    );
    assert_ne!(
        correct, regression,
        "Err+NoAttempt (IntentPersist) must never equal Ok+FailedPreflight (the regression)"
    );
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
    /// Monotonic counter for the property test's fixed deployment ids
    /// (`si-<tag>-<NNNN>`): every property push/rollback uses a caller id so
    /// the store faults (keyed by deployment id) can be armed per step, and
    /// the ids sort AFTER the engine's auto `deploy-…` ids while ordering
    /// lexicographically by push order (the lifecycle "newest successful"
    /// check compares id strings).
    prop_ids: AtomicU64,
    /// Per-fixture tag baked into every property deployment id (derived from
    /// the unique tempdir name) so concurrent proptest cases keep unique
    /// deployment ids (each case owns its per-fixture fault registry).
    prop_tag: String,
    /// The (target, deployment id) of the LAST property push/rollback step,
    /// so the oracle can resolve the DISPOSITION of an `Err` outcome by
    /// asking the store whether THAT push's intent was persisted (a pre-intent
    /// `Err` recorded nothing -> `NoAttempt`; the post-intent crash-window
    /// `Err`s recorded a recoverable attempt -> `Pending`). Set by
    /// [`Fixture::push_prop`]; a `Mutex` keeps `Fixture` `Sync` (some
    /// hand-written tests move the fixture into scoped threads).
    last_prop: Mutex<Option<(String, String)>>,
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
        let prop_tag = {
            // The tempdir name is unique per Fixture (per proptest case);
            // sanitize it so the ids stay path-friendly.
            dir.path()
                .file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default()
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .collect()
        };
        let fixture = Fixture {
            _dir: dir,
            project,
            cfg_path,
            config,
            store,
            remotes_base,
            fault: Arc::new(Mutex::new(RemoteFault::default())),
            prop_ids: AtomicU64::new(0),
            prop_tag,
            last_prop: Mutex::new(None),
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

    // ---- property plumbing -------------------------------------------------

    /// The next fixed deployment id for a property push/rollback. The
    /// per-fixture tag keeps concurrent proptest cases apart (each case owns
    /// its per-fixture fault registry, so ids only need to be unique within
    /// the fixture); the zero-padded counter makes the id string ordering
    /// equal the push order for the lifecycle "newest successful" check.
    fn next_prop_id(&self) -> DeploymentId {
        let i = self.prop_ids.fetch_add(1, Ordering::Relaxed);
        DeploymentId::new(format!("si-{}-{i:04}", self.prop_tag))
    }

    /// Arm the step's [`FailureClass`] for a push of `pushed` with deployment
    /// id `id`. The local-store arms are keyed by the deployment id (and, for
    /// the observed-refresh arms, by the target); the remote arms are
    /// suffix-armed; the debt-I/O arms are keyed by the pushed TARGET (the
    /// store's debt methods carry no deployment id). Lock contention needs no
    /// arm (the fixture holds the lock itself).
    fn arm_prop_fault(&self, class: FailureClass, pushed: &str, id: &DeploymentId) {
        let reg = self.store.fault_registry();
        let other = if pushed == "t1" { "t2" } else { "t1" };
        match class {
            FailureClass::CommitMarker | FailureClass::RotationInventory => {
                self.set_remote_fault(match class {
                    FailureClass::CommitMarker => FailureStep::CommitMarkerWrite,
                    _ => FailureStep::RotationInventoryWrite,
                })
            }
            FailureClass::IntentPersist => reg.arm_append_attempt(id.as_str()),
            FailureClass::ResultsWrite => reg.arm_write_results(id.as_str()),
            FailureClass::SnapshotAppend => reg.arm_append_snapshot(id.as_str()),
            FailureClass::LastSuccessfulWrite => reg.arm_write_last_successful(id.as_str()),
            FailureClass::TransitionSuccessful => reg.arm_append_transition_successful(id.as_str()),
            FailureClass::TransitionPending => reg.arm_append_transition_pending(id.as_str()),
            FailureClass::ObservedWriteServer => reg.arm_write_server(id.as_str(), pushed),
            FailureClass::ObservedPrimaryWrite => reg.arm_write_observed(id.as_str(), pushed),
            FailureClass::ObservedOtherWrite => reg.arm_write_observed(id.as_str(), other),
            FailureClass::DebtRead => reg.arm_read_rotation_debt(pushed),
            FailureClass::DebtWrite | FailureClass::DebtRemove => {
                reg.arm_write_rotation_debt(pushed)
            }
            // `None`, `LockContention` and `Step17Contended` need no registry
            // arm: contention is driven by the fixture itself (the whole-push
            // guard for `LockContention`, the step-17 phase hook for
            // `Step17Contended`). The step-17 DEBT COMBINATIONS also arm
            // NOTHING here: the target-keyed debt arm must fire only at the
            // FRESH step-17 phase (the engine's contended deferral), never at
            // the deferred-maintenance retry that reads/writes the debt
            // FIRST — so the fixture arms it while the engine is parked at
            // the fresh step-17 hook ([`Fixture::push_prop_step17_contended`]
            // matches on the [`step17_hook::HookPhase`]).
            FailureClass::None
            | FailureClass::LockContention
            | FailureClass::Step17Contended
            | FailureClass::Step17ContentionDebtRead
            | FailureClass::Step17ContentionDebtWrite => {}
        }
    }

    /// Clear every one-shot fault the property can arm: the failure classes
    /// are STEP-SCOPED — a fault a no-op step cannot consume is dropped,
    /// never leaked into the next step. The per-fixture registry is
    /// structurally isolated (no shared statics), but a leftover target-keyed
    /// debt arm would still fire on a LATER step of THIS fixture, so the
    /// registry is cleared wholesale; the remote transport fault is
    /// per-fixture too.
    fn disarm_prop_faults(&self) {
        self.fault.lock().unwrap().fail_write_once = None;
        self.store.fault_registry().clear();
    }

    /// Acquire the slot's mutation lock via a SECOND `RemoteHelper` (its own
    /// operation id) and return that id; [`Fixture::release_contention_lock`]
    /// must be called when the contended action is done. The lock is a
    /// single advisory file per server, so while it is held the push's own
    /// preflight lock check fails.
    fn hold_contention_lock(&self) -> String {
        let remote = self.remote();
        let helper = RemoteHelper::new(remote.as_ref());
        let op = format!("si-contend-{}", OperationId::generate().as_str());
        helper
            .acquire_lock(&op, false)
            .expect("the contention lock must be free at the start of the step");
        op
    }

    fn release_contention_lock(&self, op: &str) {
        let remote = self.remote();
        let helper = RemoteHelper::new(remote.as_ref());
        let _ = helper.release_lock(op);
    }

    /// Simulate STEP-17 lock contention (the post-commit rotation the action
    /// with a fixed deployment id, then disarm every one-shot fault (the
    /// classes are step-scoped). Invariant checks are NOT run here — the
    /// oracle runs them only when the model reports the step left the state
    /// checkable (no open crash window, no tamper, no unknown class).
    fn apply_prop(&self, action: &Action, class: FailureClass) -> Outcome {
        match action {
            Action::Push(t) | Action::Retry(t) => self.push_prop(t, None, class),
            Action::Rollback(t, i) => self.push_prop(t, Some(&format!("s{i}")), class),
            other => {
                // Build / Rotate / Tamper: nothing consumes a fault, so the
                // class is dropped without arming.
                self.apply_no_checks(other.clone())
            }
        }
    }

    /// Run a push/rollback step with a caller-supplied fixed deployment id
    /// (so the id-keyed store arms hit exactly this push) and the step-scoped
    /// failure class. For [`FailureClass::LockContention`] the slot's
    /// mutation lock is held by a second helper for the whole push. Returns
    /// the raw outcome; the caller gates the invariant checks.
    fn push_prop(&self, t: &str, ref_token: Option<&str>, class: FailureClass) -> Outcome {
        let id = self.next_prop_id();
        // Remember WHICH deployment this step pushed, so the oracle can ask
        // the store whether the intent was persisted when the push returns
        // `Err` (pre-intent Errs recorded nothing; the crash-window Errs
        // recorded a recoverable attempt under this id).
        *self.last_prop.lock().unwrap() = Some((t.to_string(), id.as_str().to_string()));
        self.arm_prop_fault(class, t, &id);
        // Step-17 lock contention is driven by the test-only phase hook for
        // ALL three step-17 classes (the fixture holds the competing guard
        // while the engine is parked at every step-17-equivalent lock
        // acquisition; the debt halves of the COMBINATIONS are armed by the
        // fixture ONLY at the FRESH step-17 park, so the deferred-maintenance
        // retry's earlier debt read/write passes unarmed), so the push runs
        // in a scoped thread.
        if matches!(
            class,
            FailureClass::Step17Contended
                | FailureClass::Step17ContentionDebtRead
                | FailureClass::Step17ContentionDebtWrite
        ) {
            let res = self.push_prop_step17_contended(t, ref_token, &id, class);
            self.disarm_prop_faults();
            return Outcome::Push(Box::new(res));
        }
        let contend = if class == FailureClass::LockContention {
            Some(self.hold_contention_lock())
        } else {
            None
        };
        let res = match ref_token {
            Some(rt) => crate::push::engine::push_ref_with_id(
                &self.cfg_path,
                &self.store,
                &self.remote_factory(),
                t,
                &self.config,
                &PushOptions {
                    dry_run: false,
                    ref_token: Some(rt.to_string()),
                },
                &id,
            ),
            None => self.push_with_id(t, &id),
        };
        if let Some(op) = contend {
            self.release_contention_lock(&op);
        }
        self.disarm_prop_faults();
        Outcome::Push(Box::new(res))
    }

    /// Resolve the DEPLOYMENT DISPOSITION of an `Err` outcome from the
    /// system's OWN store: the last property push's deployment id is looked up
    /// in the pushed target's attempt log. An attempt recorded for that id
    /// means the intent WAS persisted before the failure — the attempt's
    /// latest transition gives the disposition (the recoverable crash-window
    /// faults -> `Pending`, a post-intent preflight failure ->
    /// `FailedPreflight`); NO attempt for the id means the failure preceded
    /// the intent persist (early lock contention, plan rejection, the
    /// `append_attempt` itself) -> `NoAttempt`.
    fn err_disposition(&self) -> Disposition {
        let last = self.last_prop.lock().unwrap();
        let Some((t, id)) = last.as_ref() else {
            return Disposition::NoAttempt;
        };
        let attempts = self.store.read_attempts(t).unwrap_or_default();
        if !attempts.iter().any(|a| a.deployment_id.as_str() == id) {
            return Disposition::NoAttempt;
        }
        match self.store.latest_status(id).ok().flatten() {
            Some(DeploymentStatus::PendingCommit) | Some(DeploymentStatus::InProgress) => {
                Disposition::Pending
            }
            Some(DeploymentStatus::FailedPreflight) => Disposition::FailedPreflight,
            Some(DeploymentStatus::Degraded) => Disposition::Degraded,
            Some(DeploymentStatus::FailedRolledBack) => Disposition::FailedRolledBack,
            Some(DeploymentStatus::Successful) => Disposition::Successful,
            None => Disposition::NoAttempt,
        }
    }

    /// Run a push/rollback step under the step-17 phase hook (the
    /// [`FailureClass::Step17Contended`] branch of [`Fixture::push_prop`]):
    /// arm the hook for the step's deployment id, run the push in a scoped
    /// thread, and the instant the engine parks at a step-17-equivalent lock
    /// acquisition, acquire the slot's mutation lock via a SECOND helper and
    /// hold it until the push returns — the engine's own rotation then
    /// deterministically CONTENDS (deferred: debt marker + warning naming the
    /// slot), never silent and never via a race on the lock file.
    ///
    /// PHASE DISTINCTION: the park signal carries the
    /// [`step17_hook::HookPhase`]. The fixture services EVERY park with the
    /// same held guard, but arms the DEBT FAULT ONLY at the
    /// [`step17_hook::HookPhase::FreshStep17`] park — the engine's own
    /// per-slot rotation, whose contended else-branch runs the debt
    /// read-modify-write that must fault. The
    /// [`step17_hook::HookPhase::DeferredRetry`] park (reached only when a
    /// PRIOR push left a marker: the retry reads the debt FIRST, before this
    /// park) is released WITHOUT the fault armed, so the retry's earlier
    /// debt read/write passes and the one-shot arm is still live for the
    /// fresh phase. A push that finishes WITHOUT firing the hook is an
    /// up-to-date no-op carrying no debt (its maintenance retry never reaches
    /// a step-17 lock acquisition): the armed hook is dropped with no
    /// contention and the step is a plain clean no-op.
    fn push_prop_step17_contended(
        &self,
        t: &str,
        ref_token: Option<&str>,
        id: &DeploymentId,
        class: FailureClass,
    ) -> Result<PushReport> {
        let hook = step17_hook::Step17Hook::arm(self.store.step17_hook(), id.as_str());
        std::thread::scope(|s| {
            let push = s.spawn(|| match ref_token {
                Some(rt) => crate::push::engine::push_ref_with_id(
                    &self.cfg_path,
                    &self.store,
                    &self.remote_factory(),
                    t,
                    &self.config,
                    &PushOptions {
                        dry_run: false,
                        ref_token: Some(rt.to_string()),
                    },
                    id,
                ),
                None => self.push_with_id(t, id),
            });
            // The competing guard, held until AFTER the push returns — the
            // engine must find the lock held when it wakes from EVERY park.
            // The remote / helper are declared here so the guard's borrow
            // outlives the loop (an uncontended step just drops an unused
            // helper).
            let remote = self.remote();
            let helper = RemoteHelper::new(remote.as_ref());
            let mut guard: Option<crate::remote::helper::LockGuard<'_>> = None;
            // Service EVERY park, not just the first: with prior debt the
            // engine parks at the deferred-maintenance RETRY first (the
            // [`step17_hook::HookPhase::DeferredRetry`] phase) and AGAIN at
            // its own step-17 rotation ([`step17_hook::HookPhase::FreshStep17`])
            // — each is a step-17-equivalent lock acquisition, so each must
            // find the guard held. The first park acquires the competing
            // guard (deterministically — the engine cannot race it while
            // parked); every park is then released. The DEBT FAULT IS ARMED
            // ONLY AT THE FRESH PARK: the retry's earlier debt read/write
            // (preexisting marker) passes, and the one-shot is consumed by
            // the fresh phase's deferred read/write — the intended failure
            // phase.
            let reg = self.store.fault_registry();
            // loop exits when the push finishes WITHOUT ever reaching a
            // step-17 lock acquisition (the no-op-without-debt case, where
            // the hook can never fire). `recv_timeout` SLEEPS (it does not
            // spin), so the wait costs nothing while the engine runs.
            while !push.is_finished() {
                if let Ok(phase) = hook.wait_at_step17_bounded(std::time::Duration::from_millis(5))
                {
                    if guard.is_none() {
                        let holder = format!("si-step17-{}", OperationId::generate().as_str());
                        guard = Some(helper.acquire_lock_guard(&holder).expect(
                            "the slot mutation lock must be free while the engine is parked \
                             at the step-17 hook",
                        ));
                    }
                    if phase == step17_hook::HookPhase::FreshStep17 {
                        // Arm the debt half of the combination ONLY now, at
                        // the fresh step-17 phase: the deferred-maintenance
                        // retry (DeferredRetry) already ran its debt
                        // read/write unarmed, so the one-shot cannot be
                        // consumed at the wrong phase. The engine is parked
                        // — the arm races nothing and fires at the intended
                        // read/write inside the contended else-branch after
                        // the release below.
                        match class {
                            FailureClass::Step17ContentionDebtRead => reg.arm_read_rotation_debt(t),
                            FailureClass::Step17ContentionDebtWrite => {
                                reg.arm_write_rotation_debt(t)
                            }
                            _ => {}
                        }
                    }
                    hook.release();
                }
            }
            let res = push.join().expect("push thread panicked");
            drop(hook);
            res
        })
    }

    /// Apply a non-push action WITHOUT the invariant checks (the property
    /// gates them itself — an open crash window suspends them). Mirrors the
    /// mutation half of [`Fixture::apply`].
    fn apply_no_checks(&self, action: Action) -> Outcome {
        match action {
            Action::Build(v) => {
                self.write_artifacts(v);
                Outcome::Ok
            }
            Action::Rotate => {
                self.rotate_union().expect("standalone rotation succeeds");
                Outcome::Ok
            }
            Action::Tamper(kind) => {
                self.tamper(kind);
                Outcome::Tampered
            }
            // The property generates faults per step, never InjectFailure;
            // push-ish actions go through [`Fixture::push_prop`].
            other => self.apply(other),
        }
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
            Action::Push(t) | Action::Retry(t) => Outcome::Push(Box::new(self.push(t))),
            Action::Rollback(t, i) => Outcome::Push(Box::new(self.push_ref(t, &format!("s{i}")))),
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
        if kind == TamperKind::BehaviorJson {
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
            TamperKind::AssignmentVariant => {
                stored.artifact.variant = VariantName::new("canary".to_string())
            }
            TamperKind::AssignmentRelease => {
                stored.artifact.release = ReleaseId::new("rel-sha256-tampered".to_string())
            }
            TamperKind::BehaviorJson => unreachable!("handled above"),
            TamperKind::ReleaseSchemaVersion => {
                // Rewrite the stored release record's version field to a
                // non-canonical value; the record must fail closed on read.
                self.tamper_stored_release(|v| {
                    v["release_schema_version"] = serde_json::json!(
                        crate::model::RELEASE_RECORD_SCHEMA_VERSION.wrapping_add(1)
                    );
                });
                return;
            }
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
            // (older successful attempts keep their own snapshot/marker) —
            // with ONE documented crash-recovery corner: a mid-finalize crash
            // wrote the ref BEFORE the terminal `Successful` transition
            // landed (a faulted `append_transition(Successful)`), and if the
            // slot's generation diverged before the pending attempt was
            // reconciled, the recovery DEGRADES the attempt (terminal, never
            // re-eligible) leaving the ref stale — it must then point at a
            // `Degraded` attempt that still carries its snapshot, never at an
            // arbitrary or successful record.
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
                (Some(newest), Some(ok)) if newest == ok => {}
                (None, None) => {}
                (_, Some(ok)) => {
                    // The stale-ref crash corner: the ref must point at a
                    // terminal-Degraded attempt carrying its snapshot (the
                    // crashed finalize's), not at a successful or arbitrary
                    // record.
                    let ok_attempt = attempts
                        .iter()
                        .find(|a| a.deployment_id.as_str() == ok)
                        .unwrap_or_else(|| {
                            panic!("refs/last-successful points at {ok} but no attempt is recorded")
                        });
                    assert_eq!(
                        self.store
                            .latest_status(ok_attempt.deployment_id.as_str())
                            .ok()
                            .flatten(),
                        Some(DeploymentStatus::Degraded),
                        "a stale refs/last-successful must point at a Degraded crash-mid-finalize \
                         attempt (its generation diverged before recovery), got {ok}"
                    );
                    assert!(
                        snapshots.iter().any(|s| s.deployment_id.as_str() == ok),
                        "the Degraded crash-mid-finalize attempt {ok} must still carry its snapshot"
                    );
                }
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
            if let Ok(status) = helper.status()
                && let Some(g) = &status.current_generation
            {
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
    f.apply(Action::Tamper(TamperKind::AssignmentVariant));
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
    f.apply(Action::Tamper(TamperKind::AssignmentRelease));
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
/// Determinism: NO thread ever races on the lock file. The test arms the
/// test-only step-17 phase hook ([`crate::testutil::step17_hook`]) for the
/// push's deployment id; the engine signals "at step-17 lock acquisition"
/// and PARKS immediately before its per-slot `acquire_lock_guard`, the
/// fixture then acquires the slot lock via a second `RemoteHelper` while the
/// engine is parked, and releases the hook — the engine's own acquisition
/// afterwards fails deterministically. No spin, no retry, no oracle branch:
/// the deferred outcome is guaranteed. The no-op step is deterministic the
/// same way: the no-op's deferred-maintenance retry shares the step-17
/// RAII-guarded rotation block, so it parks at the SAME barrier.
#[test]
fn state_machine_lifecycle_rotation_lock_contention_defers_not_silent() {
    let id = DeploymentId::new("si-lockcont-push".to_string());
    let holder = "op-lockcont-holder";
    let f = Fixture::new();
    let remote = f.remote();
    let helper = RemoteHelper::new(remote.as_ref());

    // ---- Step 1: PUSH with the slot mutation lock contended from step 17
    // on. Arm the phase hook, run the push in a scoped thread, and the
    // instant the engine parks at its step-17 lock acquisition, hold the
    // competing guard via the second helper, then release the engine — its
    // own `acquire_lock_guard` now deterministically contends, so the
    // maintenance is deferred (debt + warning), never silent, never an `Err`.
    let report1 = {
        let hook = step17_hook::Step17Hook::arm(f.store.step17_hook(), id.as_str());
        std::thread::scope(|s| {
            let push = s.spawn(|| f.push_with_id("t1", &id));
            hook.wait_at_step17();
            let _guard = helper.acquire_lock_guard(holder).expect(
                "the slot lock must be free while the engine is parked at the step-17 hook",
            );
            hook.release();
            push.join().expect("push thread panicked")
        })
    };
    let report1 =
        report1.expect("a committed deployment must never fail (post-commit maintenance)");
    assert_eq!(
        report1.status,
        Some(DeploymentStatus::Successful),
        "the contended push still commits successfully"
    );
    let warning1 = report1.warning.as_deref().unwrap_or("");
    assert!(
        warning1.contains("rotation deferred for slot 'p1'")
            && warning1.contains("slot lock held by another operation"),
        "the contended push must warn naming the slot (never silent), got: {warning1}"
    );
    assert!(
        !f.store.read_rotation_debt("t1").unwrap().is_empty(),
        "the contended push must record the debt marker"
    );
    // Step 1's guard drops here (lock released).

    // ---- Step 2: NO-OP with the lock HELD — the deferred maintenance
    // stays deferred (marker kept) and keeps warning. The no-op path's only
    // step-17-equivalent lock acquisition is the deferred-maintenance retry,
    // so the same hook fires there: the fixture holds the guard while the
    // engine is parked, releases the hook, and the retry's acquire fails —
    // "rotation still deferred", marker kept, warning kept.
    let report2 = {
        let hook = step17_hook::Step17Hook::arm(f.store.step17_hook(), id.as_str());
        std::thread::scope(|s| {
            let push = s.spawn(|| f.push_with_id("t1", &id));
            hook.wait_at_step17();
            let _guard = helper.acquire_lock_guard(holder).expect(
                "the slot lock must be free while the engine is parked at the no-op retry hook",
            );
            hook.release();
            push.join().expect("push thread panicked")
        })
    };
    let report2 =
        report2.expect("the no-op must never fail because its maintenance retry contended");
    assert_eq!(report2.message, "Everything up to date");
    assert_eq!(report2.status, None, "the contended no-op is a no-op");
    let warning2 = report2.warning.as_deref().unwrap_or("");
    assert!(
        warning2.contains("rotation still deferred for slot 'p1'")
            && warning2.contains("slot lock held by another operation"),
        "the held-lock no-op must keep warning that the rotation is deferred, got: {warning2}"
    );
    assert!(
        !f.store.read_rotation_debt("t1").unwrap().is_empty(),
        "the held-lock no-op must keep the debt marker"
    );
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
            .expect_err("the intent persist fault must abort the push")
    };
    assert!(
        err.to_string().contains("append_attempt"),
        "error must name the injected fault, got: {err}"
    );
    assert!(
        !f.remote().exists(layout::current()),
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

/// Lifecycle: a failure at the commit marker write (after activation,
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
        "the failed commit must be reported PendingCommit"
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

    // Rollback t1 to its own s0 (tree v1) and t2 to s0 (tree v2).
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
            .expect_err("the faulted push aborts before the observed refresh")
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
            !observed.slots.contains_key(&PlacementSlotId::new("p1")),
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

/// (b) Rollback on ONE target: a snapshot rollback is a REAL push; its observed
/// refresh must land the rolled-back assignment in EVERY member target's
/// projection, so after rolling t1 back to its own `s0` both t1 and t2
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
            .expect_err("the preflight failure aborts before any remote mutation")
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
            .expect_err("the preflight push aborts before mutation")
    };
    assert!(err.to_string().contains("append_attempt"), "{err}");
    f.assert_observed_scope_property();

    // (b) Rollback t1 to its own `s0` (tree v1): a real push whose refresh
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
            .expect_err("the crash aborts before the observed refresh")
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

    // A mid-flight failure that STILL returns Ok: the commit marker
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
    // protect 2 deployments.
    let mut strong_config = f.config.clone();
    let r = strong_config.targets.get_mut("t1").unwrap();
    r.rotation.per_server.keep_distinct_artifacts = 5;
    r.rotation.per_server.protect_previous = true;
    r.rotation.deployment.protect_deployments = 2;
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
                .expect_err("the injected persistence fault must abort the push")
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
        .expect_err("content tamper with retained digest must fail");
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
                .expect_err("a tampered record written to a fresh store must fail at read");
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
        .push_ref_impl("t1", &format!("parent({}, 0)", id.as_str()))
        .expect_err("a historical push against a tampered stored release must fail closed");
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
    f.tamper(TamperKind::BehaviorJson);

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
        .push_ref_impl("t1", &format!("parent({}, 0)", id.as_str()))
        .expect_err("a historical push against a tampered behavior snapshot must fail closed");
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
        .expect_err("the historical behavior read must fail closed");
    assert!(
        rerr.to_string().contains("digest mismatch"),
        "read error must name the digest mismatch, got: {rerr}"
    );
}

/// The schema-version property, end-to-end: a stored release record whose
/// `release_schema_version` was rewritten to any arbitrary `u32` value other
/// than [`crate::model::RELEASE_RECORD_SCHEMA_VERSION`] must fail closed on
/// every read and block the next push — never silently accepted, never
/// republished. The dedicated [`TamperKind::ReleaseSchemaVersion`]
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
            .expect_err("a non-canonical record version must fail closed on read");
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
            .push_ref_impl("t1", &format!("parent({}, 0)", id.as_str()))
            .expect_err("a push against a tampered record version must fail closed");
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
    f.push_ref_impl("t1", &format!("parent({}, 0)", id.as_str()))
        .expect("a push against the restored record succeeds");

    // And the dedicated Tamper action rewrites the field the same way.
    let s2 = Fixture::new();
    s2.apply(Action::Push("t1"));
    s2.apply(Action::Tamper(TamperKind::ReleaseSchemaVersion));
    let releases_root = s2.store.base().join(layout::RELEASES);
    let dir = std::fs::read_dir(&releases_root)
        .unwrap()
        .flatten()
        .next()
        .unwrap();
    let id = ReleaseId::new(dir.file_name().to_string_lossy().into_owned());
    let err = s2
        .store
        .read_release(&id)
        .expect_err("the Tamper action's rewritten version must fail closed on read");
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
/// * the per-target snapshot log (`s{i}` rollback refs, one chain per
///   target) and the
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
    /// The CURRENT step's failure class, armed at the start of [`Model::apply`]
    /// and consumed by the action's own writes. STEP-SCOPED: whatever a step
    /// does not consume is dropped at the end (the fixture disarms identically).
    armed_fault: Option<FailureClass>,
    /// An action or failure class this oracle cannot simulate (added by a
    /// sibling feature): the cross-system equality assertions are suspended.
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
    /// Per-target snapshot log: content version per snapshot index.
    snapshots: BTreeMap<&'static str, Vec<u32>>,
    /// Per-target deployment-attempt log: content version per attempt.
    attempts: BTreeMap<&'static str, Vec<u32>>,
    /// Un-finalized pending deployment per target: (content version, the
    /// minted-generation counter, whether its snapshot is ALREADY durable).
    /// A `LastSuccessfulWrite` / `TransitionSuccessful` fault leaves the
    /// snapshot appended while the attempt stays pending, so the reconcile
    /// must not append it a second time.
    pending: BTreeMap<&'static str, (u32, u64, bool)>,
    /// Monotone counter of deployed generations: every real deployment
    /// (push, rollback, or faulted push) mints exactly one new generation,
    /// and a pending attempt finalizes only while its OWN generation is
    /// still the remote current (the engine compares generation IDs, not
    /// versions — a same-version redeploy diverges the pending attempt).
    current_gen: u64,
    /// Expected rotation-debt marker presence per target.
    debt: BTreeMap<&'static str, bool>,
    /// The crash window: an open post-mutation fault state where the observed
    /// projections legitimately disagree with the remote current, or where a
    /// crash-recovery attempt (PendingCommit with a durable snapshot) has not
    /// been finalized yet — both states the fixture's invariant groups cannot
    /// evaluate (see [`Model::lingering_crash`]). The five invariant groups
    /// and the model-vs-system comparisons are suspended while it is open.
    crash_window: bool,
    /// The warning the CURRENT step's push report must contain: one
    /// substring per entry, EVERY one asserted against the actual report's
    /// `warning`. Set ONLY by the step-17 contention classes (see
    /// [`FailureClass::Step17Contended`] and its debt combinations) so the
    /// oracle asserts the retryable-vs-not distinction — "rotation deferred
    /// for slot" (the marker-persisted claim) plus, on a debt read/write
    /// fault, the explicit "rotation debt maintenance deferred: failed to
    /// ..." notice that says the marker was NOT persisted (no automatic
    /// retryability). `None` for every other class (their warnings are not
    /// cross-checked).
    expected_warning: Option<&'static [&'static str]>,
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
            crash_window: false,
            expected_warning: None,
            last_was_tamper: false,
            index: 0,
        }
    }

    /// Advance the oracle by ONE property step — the action AND its failure
    /// class together — and return the two-dimension [`OutcomeClass`] the
    /// CORRECT engine must produce: the [`ReturnBoundary`] (Ok vs Err) AND the
    /// [`Disposition`]. The state transitions mirror the engine's real
    /// behavior per fault (a PRE-INTENT arm -> `Err` + `NoAttempt` — the
    /// intent was never persisted; a crash-window arm -> `Err` + `Pending` —
    /// the intent WAS persisted but the attempt is recoverable; a post-commit
    /// arm -> `Ok` + the committed class with the model's tracked debt/warning
    /// state). Kept ADAPTIVE: unknown action variants and failure classes
    /// added by sibling features fall into catch-alls that suspend the
    /// cross-comparisons instead of breaking the build.
    fn apply(&mut self, action: &Action, fault: FailureClass) -> OutcomeClass {
        self.index += 1;
        self.last_was_tamper = false;
        self.expected_warning = None;
        self.armed_fault = Some(fault);
        let (class, window) = match action {
            Action::Build(v) => {
                self.head_version = *v;
                (
                    OutcomeClass::Push {
                        boundary: ReturnBoundary::Ok,
                        disposition: Disposition::NoAttempt,
                    },
                    self.crash_window,
                )
            }
            Action::Push(t) | Action::Retry(t) => self.deploy(t),
            Action::Rollback(t, i) => self.rollback(t, *i),
            Action::Rotate => (
                OutcomeClass::Push {
                    boundary: ReturnBoundary::Ok,
                    disposition: Disposition::NoAttempt,
                },
                self.crash_window,
            ),
            Action::InjectFailure(_) => {
                // The property injects faults per step (never via this action);
                // a stray sticky arm cannot be cross-checked.
                self.unknown = true;
                (
                    OutcomeClass::Push {
                        boundary: ReturnBoundary::Ok,
                        disposition: Disposition::NoAttempt,
                    },
                    self.crash_window,
                )
            }
            Action::Tamper(_) => {
                if self.current.is_some() {
                    // The fixture requires a live generation to tamper; with
                    // none, the property test skips the action entirely.
                    self.current_tampered = true;
                    self.last_was_tamper = true;
                }
                (OutcomeClass::Tampered, self.crash_window)
            }
        };
        self.crash_window = window;
        // Step-scoped faults: whatever the action did not consume is dropped.
        self.armed_fault = None;
        class
    }

    /// Reconcile a pending attempt of `t` at the START of a push/rollback,
    /// mirroring `reconcile_pending_commits` (which runs before the early
    /// no-op check): verify the attempt's generation, then write its missing
    /// commit marker. The marker write is a commit-path write, so an
    /// armed [`FailureClass::CommitMarker`] is consumed there and the attempt
    /// stays pending; under [`FailureClass::LockContention`] the reconcile's
    /// lock acquisition fails BEFORE any write, so the attempt stays pending
    /// and the fault is NOT consumed.
    /// commit marker. The marker write is a commit-path write, so an
    /// armed [`FailureClass::CommitMarker`] is consumed there and the attempt
    /// stays pending; under [`FailureClass::LockContention`] the reconcile's
    /// lock acquisition fails BEFORE any write, so the attempt stays pending
    /// and the fault is NOT consumed.
    fn reconcile(&mut self, t: &'static str) {
        let Some((pv, pg, already_snapped)) = self.pending.remove(t) else {
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
            Some(FailureClass::LockContention) => {
                // The reconcile's marker write contends on the held lock: the
                // attempt stays pending, no write was attempted, so the fault
                // (a step-scoped contention marker) is not consumed.
                self.pending.insert(t, (pv, pg, already_snapped));
            }
            Some(FailureClass::CommitMarker) => {
                // The pending attempt's marker write consumes the armed fault
                // and fails, so the attempt stays pending.
                self.armed_fault = None;
                self.pending.insert(t, (pv, pg, already_snapped));
            }
            Some(_) => {
                // Any other armed class: the reconcile's writes are keyed to
                // the OLD attempt's id, so they pass through untouched and the
                // attempt finalizes (the step's fault stays armed for the
                // step's own deployment writes, or is dropped by a no-op).
                if !already_snapped {
                    self.snapshots.entry(t).or_default().push(pv);
                }
            }
            None => {
                // The pending deployment's OWN generation is still the remote
                // current: the attempt finalizes (snapshot appended, refs
                // advanced). A finalize fault (LastSuccessful etc.) already
                // recorded the snapshot, so it must not be duplicated.
                if !already_snapped {
                    self.snapshots.entry(t).or_default().push(pv);
                }
            }
        }
    }

    /// A snapshot rollback to snapshot `i`. The engine reconciles pending
    /// attempts BEFORE resolving the ref (the resolution point sits after
    /// `reconcile_pending_commits`), so the range is evaluated against the
    /// POST-reconciliation chain — the pending attempt's snapshot is appended
    /// first, and a ref that only the recovery brought into range now
    /// resolves. The reconciliation runs even when the ref still fails
    /// closed after it; the push then returns `Err` (nothing recorded —
    /// `NoAttempt`) BEFORE the observed refresh, so an open crash window
    /// STAYS open (the fixture's invariant groups stay suspended until a
    /// later successful push/no-op refreshes observed).
    fn rollback(&mut self, t: &'static str, i: u64) -> (OutcomeClass, bool) {
        // The engine reconciles pending attempts ONCE per push, before the
        // ref is resolved, so the index is evaluated against the
        // POST-reconciliation chain and the resolved deployment enters the
        // shared resolved-deploy stage with NO second reconciliation (a
        // second reconcile would wrongly finalize an attempt the reconcile's
        // OWN faulted marker write left pending).
        self.reconcile(t);
        let Some(v) = self
            .snapshots
            .get(t)
            .and_then(|snaps| snaps.get(i as usize))
            .copied()
        else {
            return (
                OutcomeClass::Push {
                    boundary: ReturnBoundary::Err,
                    disposition: Disposition::NoAttempt,
                },
                self.crash_window,
            );
        };
        self.deploy_resolved(t, Some(v))
    }

    /// A HEAD push / no-op retry (`Push` and `Retry` are the same operation
    /// in the fixture) under the step's failure class. The engine reconciles
    /// pending attempts once, then decides no-op-vs-deploy against the
    /// post-reconciliation state and enters the shared resolved-deploy stage.
    fn deploy(&mut self, t: &'static str) -> (OutcomeClass, bool) {
        self.reconcile(t);
        // HEAD push: deploy exactly when the remote current no longer
        // equals the materialized head (the engine's complete
        // ArtifactRef equality — a tampered current forces a fresh push).
        let version = if self.current_tampered || self.current != Some(self.head_version) {
            Some(self.head_version)
        } else {
            None
        };
        self.deploy_resolved(t, version)
    }

    /// The shared POST-RECONCILIATION deployment stage — everything the
    /// engine runs after `reconcile_pending_commits`, ref resolution, and
    /// planning: the mutation-lock preflight, then either the up-to-date
    /// no-op (no records) or the real deployment under the step's failure
    /// class. Returns the expected outcome class and the NEW crash-window
    /// state.
    fn deploy_resolved(&mut self, t: &'static str, version: Option<u32>) -> (OutcomeClass, bool) {
        // A contended push aborts with `Err` and records NOTHING — no attempt,
        // no recovery, no observed refresh — so the expected class is `Err` +
        // `NoAttempt`. The engine's mutation-lock preflight check sits in the
        // mutating remote phase (AFTER reconciliation, resolution, and
        // planning — the resolution point moved behind
        // `reconcile_pending_commits`), but the reconcile under contention
        // never finalizes (its marker lock acquisition contends too), so the
        // observable boundary and the crash-window state are identical to a
        // check that ran earlier: nothing recorded, the pending attempt left
        // for a later push, and the step's fault unconsumed. The step-15
        // commit contention, by contrast, happens AFTER the intent and yields
        // `Ok` + `Pending`.
        if matches!(self.armed_fault, Some(FailureClass::LockContention)) {
            return (
                OutcomeClass::Push {
                    boundary: ReturnBoundary::Err,
                    disposition: Disposition::NoAttempt,
                },
                self.crash_window,
            );
        }
        let Some(v) = version else {
            // Up-to-date no-op: no records. The deferred-maintenance hook
            // services rotation debt, and the no-op path refreshes observed
            // from the EXISTING generation into EVERY member target (the
            // crash-window recovery path), closing any open window.
            self.noop_maintenance(t);
            if let Some(c) = self.current {
                self.observed.insert("t1", Some(c));
                self.observed.insert("t2", Some(c));
            }
            return (
                OutcomeClass::Push {
                    boundary: ReturnBoundary::Ok,
                    disposition: Disposition::NoAttempt,
                },
                false,
            );
        };
        let fault = self.armed_fault.take();
        let had_debt = self.debt.get(t).copied().unwrap_or(false);
        // A PRE-MUTATION abort (the intent persist): the push returns `Err`
        // with NOTHING recorded or mutated and no refresh — `Err` + `NoAttempt`
        // (verified against the engine: `append_attempt` fails before any
        // remote mutation and `read_attempts` stays empty). The observed
        // projections and any open crash window stand exactly as before.
        if matches!(fault, Some(FailureClass::IntentPersist)) {
            return (
                OutcomeClass::Push {
                    boundary: ReturnBoundary::Err,
                    disposition: Disposition::NoAttempt,
                },
                self.crash_window,
            );
        }
        // A REAL deployment: the remote advances, the attempt is recorded,
        // and the observed refresh runs — EXCEPT for the crash-window faults,
        // which abort before the refresh.
        let crash = matches!(
            fault,
            Some(
                FailureClass::ResultsWrite
                    | FailureClass::SnapshotAppend
                    | FailureClass::LastSuccessfulWrite
                    | FailureClass::TransitionSuccessful
                    | FailureClass::TransitionPending
            )
        );
        let primary_stale = matches!(fault, Some(FailureClass::ObservedPrimaryWrite));
        let other_stale = matches!(fault, Some(FailureClass::ObservedOtherWrite));
        self.current_gen += 1;
        self.current = Some(v);
        self.current_tampered = false;
        self.attempts.entry(t).or_default().push(v);
        match fault {
            None | Some(FailureClass::None) => {
                self.snapshots.entry(t).or_default().push(v);
                self.debt.insert(t, false);
            }
            Some(FailureClass::CommitMarker) => {
                // commit marker write fails: the deployment is recorded
                // PendingCommit; current advanced and observed refreshed, but
                // the snapshot/ref finalization defers to the next push of
                // this target. Step-17 rotation still succeeds (the fault is
                // spent), so no debt.
                self.pending.insert(t, (v, self.current_gen, false));
                self.debt.insert(t, false);
            }
            Some(FailureClass::RotationInventory) => {
                // Post-commit maintenance: step 17 retries an EXISTING debt
                // marker FIRST — that servicing write consumes the fault and
                // fails, then the push's own slot rotation succeeds and
                // CLEARS the marker. With no prior marker, the fault hits the
                // push's own rotation, which defers it as a new marker.
                self.snapshots.entry(t).or_default().push(v);
                self.debt.insert(t, !had_debt);
            }
            Some(FailureClass::Step17Contended) => {
                // The step-17 mutation lock is CONTENDED (deterministic via
                // the phase hook: the fixture holds the guard while the
                // engine is parked at every step-17-equivalent lock
                // acquisition). The deployment already committed, so the
                // outcome class is unchanged; the rotation is DEFERRED — the
                // marker is ALWAYS set (both the deferred-maintenance retry,
                // when prior debt exists, and the push's own step-17
                // rotation run while the guard is held), with the explicit
                // "rotation deferred for slot 'p1'" warning naming the slot,
                // never silent. A later clean unlocked no-op services the
                // marker.
                self.snapshots.entry(t).or_default().push(v);
                self.debt.insert(t, true);
                self.expected_warning = Some(&[STEP17_CONTENTION_WARNING]);
            }
            Some(FailureClass::ObservedWriteServer) => {
                // The per-server projection write fails (warning-only); the
                // observed maps themselves still refresh.
                self.snapshots.entry(t).or_default().push(v);
                self.debt.insert(t, false);
            }
            Some(FailureClass::ObservedPrimaryWrite) | Some(FailureClass::ObservedOtherWrite) => {
                // One member's observed projection stays stale (crash window).
                self.snapshots.entry(t).or_default().push(v);
                self.debt.insert(t, false);
            }
            Some(FailureClass::DebtRead)
            | Some(FailureClass::DebtWrite)
            | Some(FailureClass::DebtRemove) => {
                // Debt maintenance is post-commit and NON-FALLIBLE (a failed
                // read/write is a warning, never an `Err`), so the committed
                // outcome class is unchanged. The marker itself is
                // deterministic: the step-17 retry's faulted I/O only
                // DEFERS, and the push's OWN successful rotation then clears
                // any marker via `clear_rotation_deferred` (its later debt
                // write passes — the one-shot arm was already consumed by
                // the retry).
                self.snapshots.entry(t).or_default().push(v);
                self.debt.insert(t, false);
            }
            Some(FailureClass::ResultsWrite)
            | Some(FailureClass::SnapshotAppend)
            | Some(FailureClass::TransitionPending) => {
                // Crash-window faults: the remote advanced and the attempt is
                // recorded (InProgress / PendingCommit), but the snapshot was
                // NOT written and the observed refresh never ran. The push
                // returns `Err` but the intent WAS persisted — the expected
                // class is `Err` + `Pending` (the attempt stays
                // recoverable-pending).
                self.pending.insert(t, (v, self.current_gen, false));
            }
            Some(FailureClass::LastSuccessfulWrite) | Some(FailureClass::TransitionSuccessful) => {
                // The snapshot was already appended before the ref / terminal
                // transition write failed; the attempt stays pending and the
                // recovery must not duplicate the snapshot.
                self.snapshots.entry(t).or_default().push(v);
                self.pending.insert(t, (v, self.current_gen, true));
            }
            Some(FailureClass::IntentPersist) | Some(FailureClass::LockContention) => {
                unreachable!("handled before the real-deployment mutation")
            }
            Some(FailureClass::Step17ContentionDebtRead)
            | Some(FailureClass::Step17ContentionDebtWrite) => {
                // STEP-17 LOCK CONTENTION (post-commit, via the phase hook)
                // combined with a rotation-debt I/O fault: the commit
                // succeeded and the slot's rotation lock is contended, so the
                // step-17 loop defers the rotation as a debt marker. The
                // deferral I/O is NON-FALLIBLE — a debt read/write failure
                // warns but never changes the committed outcome.
                self.snapshots.entry(t).or_default().push(v);
                match fault {
                    Some(FailureClass::Step17ContentionDebtRead) => {
                        // The debt READ arm is armed ONLY at the fresh
                        // step-17 park (the fixture distinguishes the phases):
                        // the deferred-maintenance retry — which runs FIRST
                        // and reads the debt before any park — passes
                        // unarmed, so a preexisting marker's read succeeds
                        // and its contended retry keeps the marker. The arm
                        // then fires at the FRESH phase's contended deferral
                        // (`set_rotation_deferred`'s read-modify-write): the
                        // read fails, nothing is persisted, and the explicit
                        // "failed to read rotation debt" notice appears —
                        // a preexisting marker is PRESERVED untouched, and a
                        // fresh push with no marker creates NONE.
                        self.debt.insert(t, had_debt);
                        self.expected_warning =
                            Some(&[STEP17_CONTENTION_WARNING, DEBT_READ_WARNING]);
                    }
                    Some(FailureClass::Step17ContentionDebtWrite) => {
                        // The debt WRITE arm is armed ONLY at the fresh
                        // step-17 park (the retry's earlier debt write passes
                        // unarmed): the fresh contended deferral's
                        // `set_rotation_deferred` cannot persist the marker —
                        // explicit "rotation debt maintenance deferred:
                        // failed to write" notice — so NO new marker is
                        // created and any PREEXISTING marker is preserved
                        // (the failed write leaves the file untouched). The
                        // model must NOT claim automatic retryability.
                        self.debt.insert(t, had_debt);
                        self.expected_warning =
                            Some(&[STEP17_CONTENTION_WARNING, DEBT_WRITE_WARNING]);
                    }
                    _ => unreachable!("step-17 classes handled above"),
                }
            }
        }
        // The post-finalize observed refresh: every member target is rebuilt
        // unless the step faulted inside the refresh (one member stays stale)
        // or crashed before it (all members stay stale).
        if !crash {
            let other = if t == "t1" { "t2" } else { "t1" };
            if !primary_stale {
                self.observed.insert(t, Some(v));
            }
            if !other_stale {
                self.observed.insert(other, Some(v));
            }
        }
        let window = crash || primary_stale || other_stale;
        // The TWO-DIMENSION class: the boundary is `Ok` unless the step crashed
        // inside the commit path (an `Err` whose intent WAS persisted —
        // disposition `Pending`); the disposition is `Pending` for the
        // commit marker failure and for the crash-window `Err`s, and
        // `Successful` for a durable commit. Terminal failure dispositions
        // (`FailedPreflight` / `Degraded` / `FailedRolledBack`) are not
        // reachable from the property's injected fault classes (no server
        // activation failure is generated), but the classifier maps their
        // report statuses to the EXACT disposition — `Ok` + `FailedPreflight`
        // is a DIFFERENT class from `Err` + `NoAttempt` (see
        // `classifier_distinguishes_err_noattempt_from_ok_failed_preflight`).
        let class = if matches!(fault, Some(FailureClass::CommitMarker)) {
            OutcomeClass::Push {
                boundary: ReturnBoundary::Ok,
                disposition: Disposition::Pending,
            }
        } else if crash {
            OutcomeClass::Push {
                boundary: ReturnBoundary::Err,
                disposition: Disposition::Pending,
            }
        } else {
            OutcomeClass::Push {
                boundary: ReturnBoundary::Ok,
                disposition: Disposition::Successful,
            }
        };
        (class, window)
    }

    /// The no-op retry path: `retry_deferred_rotations` services the debt
    /// marker (writing the inventory), and that write consumes an armed
    /// [`FailureClass::RotationInventory`] — failing, the marker stays.
    /// Commit-marker faults do not match the inventory write, so the rotation
    /// succeeds and clears the debt. Under contention the retry's lock
    /// acquisition fails first: the marker stays (both trunks agree).
    fn noop_maintenance(&mut self, t: &'static str) {
        // A no-op never reaches the FRESH step-17 rotation, and the step-17
        // DEBT COMBINATIONS arm their debt fault ONLY at that phase (the
        // fixture leaves the deferred-maintenance retry unarmed), so the
        // one-shot can never fire on the no-op: no "failed to read/write
        // rotation debt" notice is expected. The no-op's only
        // step-17-equivalent park is the DeferredRetry phase, whose lock
        // acquisition contends on the fixture's held guard.
        if !self.debt.get(t).copied().unwrap_or(false) {
            return;
        }
        match self.armed_fault {
            Some(FailureClass::RotationInventory) => {
                self.armed_fault = None;
                // rotation failed; the debt marker stays
            }
            Some(FailureClass::LockContention) => {
                // the retry cannot acquire the lock: the marker stays
            }
            Some(FailureClass::Step17Contended) => {
                // The no-op's deferred-maintenance retry is a
                // step-17-equivalent lock acquisition, so the phase hook
                // fires there (the DeferredRetry phase): the fixture holds
                // the lock, the retry cannot acquire, and the marker stays.
                // (Without a marker the hook never fires and the no-op is
                // plain — `noop_maintenance` already returned early.)
                self.armed_fault = None;
            }
            Some(FailureClass::CommitMarker) => {
                self.debt.insert(t, false);
            }
            Some(FailureClass::DebtRead)
            | Some(FailureClass::DebtWrite)
            | Some(FailureClass::DebtRemove) => {
                // The debt-I/O fault fires inside the no-op's maintenance
                // retry: a failed READ treats the marker as absent (nothing
                // serviced, marker stays), a failed WRITE keeps the marker.
                // Either way the marker STAYS and the maintenance warns — the
                // no-op report is unchanged.
                self.armed_fault = None;
            }
            Some(FailureClass::Step17ContentionDebtRead)
            | Some(FailureClass::Step17ContentionDebtWrite) => {
                // The no-op path runs no FRESH step-17 rotation, so the
                // debt arm (which the fixture places ONLY at the FreshStep17
                // park) can never fire here: the retry — the DeferredRetry
                // phase — reads and re-persists the marker unarmed, and its
                // lock acquisition contends on the fixture's held guard, so
                // the marker STAYS. No "failed to ... rotation debt" notice
                // is expected (the debt I/O never faulted). The fault is
                // dropped step-scoped.
                self.armed_fault = None;
            }
            Some(_) => {
                // Any other armed class does not touch the no-op's debt
                // maintenance: the id-keyed store faults (intent, results,
                // finalize) and the observed-refresh faults cannot fire on
                // the no-op path — it performs no id-keyed store write, and
                // the observed records are rebuilt keyed by the EXISTING
                // generation's deployment id, never the step's. The
                // servicing therefore succeeds and the marker is cleared;
                // the leftover arm is dropped step-scoped.
                self.debt.insert(t, false);
            }
            None => {
                self.debt.insert(t, false);
            }
        }
    }

    /// Whether a snapshot-carrying pending attempt is still unreconciled — a
    /// finalize fault (`LastSuccessfulWrite` / `TransitionSuccessful`) left
    /// the snapshot durable while the attempt stayed `PendingCommit`, and the
    /// recovery was itself blocked (a contended or faulted reconcile marker
    /// write). While true, `check_lifecycle` would reject the transient
    /// state ("PendingCommit must NOT have a snapshot"), so the comparisons
    /// stay suspended until the next reconcile finalizes the attempt.
    fn lingering_crash(&self) -> bool {
        self.pending
            .values()
            .any(|(_, _, already_snapped)| *already_snapped)
    }

    /// Whether `action` would replace the tampered current record with a new
    /// pristine generation. Only a REAL deployment does: a HEAD push/retry
    /// always deploys after a tamper (the tampered artifact never equals the
    /// materialized head), while a snapshot rollback repairs only when its ref
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
        // Rollback to snapshot index 0 or 1 of the target.
        2 => (prop::sample::select(["t1", "t2"].as_slice()), 0u64..2)
            .prop_map(|(t, i)| Action::Rollback(t, i)),
        // Standalone rotation under the full member-policy union.
        1 => Just(Action::Rotate),
        // Deliberate integrity violation; the property loop skips it while no
        // live generation exists (the fixture's tamper requires one), and the
        // system's own checks defer until the next real push.
        1 => prop::sample::select([
            TamperKind::AssignmentVariant,
            TamperKind::AssignmentRelease,
        ]
        .as_slice())
        .prop_map(Action::Tamper),
    ]
}

/// The failure-class strategy for the property test: injected PER STEP, so
/// the model must predict the outcome under every arm — a PRE-INTENT arm
/// (IntentPersist, early lock contention, a rejected plan) yields `Err` +
/// `NoAttempt`; a crash-window arm (results/finalizer I/O) yields `Err` +
/// `Pending`; a post-commit arm yields the committed class with the model's
/// tracked debt/warning state; and the commit marker failure yields
/// `Ok` + `Pending`. Lock contention demotes the whole attempt
/// (`LockContention`, pre-intent: `Err` + `NoAttempt`) or only the step-17
/// rotation (`Step17Contended`, deferred via the phase hook: debt + warning,
/// the committed outcome — `Ok` + `Successful` — unchanged). Weights: the
/// clean path dominates so the vectors stay realistic; every fault class is
/// reachable.
fn failure_class_strategy() -> impl Strategy<Value = FailureClass> {
    prop_oneof![
        12 => Just(FailureClass::None),
        // remote, suffix-armed
        1 => Just(FailureClass::CommitMarker),
        1 => Just(FailureClass::RotationInventory),
        // local persistence, id-armed
        1 => Just(FailureClass::IntentPersist),
        1 => Just(FailureClass::ResultsWrite),
        1 => Just(FailureClass::SnapshotAppend),
        1 => Just(FailureClass::LastSuccessfulWrite),
        1 => Just(FailureClass::TransitionSuccessful),
        1 => Just(FailureClass::TransitionPending),
        1 => Just(FailureClass::ObservedWriteServer),
        1 => Just(FailureClass::ObservedPrimaryWrite),
        1 => Just(FailureClass::ObservedOtherWrite),
        // debt I/O (target-keyed: the arm lands on the pushed target's debt
        // file; the model's classification must stay deterministic)
        1 => Just(FailureClass::DebtRead),
        1 => Just(FailureClass::DebtWrite),
        1 => Just(FailureClass::DebtRemove),
        // lock contention (the fixture holds the slot lock for the action)
        1 => Just(FailureClass::LockContention),
        // step-17 lock contention (deterministic via the test-only phase
        // hook: the fixture holds the guard while the engine is parked at its
        // step-17 lock acquisition), alone and combined with a rotation-debt
        // read/write fault in the same push. The outcome oracle predicts the
        // committed push stays `Ok` + `Successful` (never `Err`); successful
        // persistence (contention alone) leaves a debt marker + warning, while
        // a coincident debt read/write failure produces the explicit "rotation
        // debt maintenance deferred" notice (no automatic retryability claim).
        // The combined weights are bounded so the vector count does not grow.
        1 => Just(FailureClass::Step17Contended),
        1 => Just(FailureClass::Step17ContentionDebtRead),
        1 => Just(FailureClass::Step17ContentionDebtWrite),
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
/// snapshot, an attempt's desired assignment, the remote current, an
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
    if model.last_was_tamper
        || model.current_tampered
        || model.unknown
        || model.crash_window
        || model.lingering_crash()
    {
        // A tamper deliberately broke identity (the fixture's apply skipped
        // its own checks too) and the model defers to the next real push that
        // replaces the tampered record — WHILE THE TAMPERED RECORD IS STILL
        // LIVE (a faulted/contended repair step did not replace it) the
        // identity/scope groups cannot run either; an UNKNOWN action/fault
        // kind from a sibling feature cannot be cross-checked either; an OPEN
        // CRASH WINDOW leaves the observed projections legitimately out of
        // sync with the durable remote current (a post-mutation fault before
        // the observed refresh, or a faulted observed write); and a LINGERING
        // PendingCommit-with-snapshot attempt (a finalize fault whose
        // recovery was itself blocked) violates `check_lifecycle` until the
        // next reconcile finalizes it. All are documented fixture contracts
        // for the crash/recovery window, suspended until a later
        // push/rollback/no-op rebuilds the projections and finalizes the
        // attempt.
        return;
    }
    // (a) The five invariant groups (the system's own ground truth).
    system.check_invariants();

    let pid = PlacementSlotId::new("p1");
    let mut learned: BTreeMap<u32, ArtifactRef> = BTreeMap::new();

    // Snapshot logs: count + per-index artifact/version join.
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
            learn_artifact(
                &mut learned,
                &ctx,
                *mv,
                art,
                &format!("snapshot s{i} of {t}"),
            );
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
        if let Some((pv, _, _)) = model.pending.get(t) {
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

// Property-based state machine — TWO-DIMENSION outcome oracle + bounded
// random action vectors (1..20 steps). Every step is an (ACTION, FAILURE
// CLASS) pair — the actions and the injected failure classes are generated
// TOGETHER, so the model must predict the outcome under every arm. A fresh
// [`Model`] oracle and [`Fixture`] are driven in lockstep; after EVERY step
// the oracle asserts both the observable state (existing
// [`assert_semantic_invariants`]) and the TWO-DIMENSION result class
// ([`OutcomeClass`]: the [`ReturnBoundary`] AND the [`Disposition`], asserted
// independently).
//
// TWO configs: the main test runs ORDINARY RANDOMIZED seeds with failure
// persistence (a failing vector is written to
// `proptest-regressions/semantic_invariants.txt` and REPLAYED on the next
// run — commit the file so CI replays the regression until fixed), and a
// separate FIXED-SEED regression keeps CI deterministic even when no failure
// has ever been persisted. Shrinking never consults the wall clock.
fn run_semantic_state_case(steps: Vec<(Action, FailureClass)>) {
    // No fault lock: every arm targets the fixture's OWN per-fixture
    // registry (see `src/testutil.rs`), so the 128 cases run concurrently
    // with the fault-matrix and engine fault tests without any shared
    // process-global slot to race over.
    let mut model = Model::new();
    let system = Fixture::new();
    for (action, fault) in steps {
        // A Tamper needs a live generation (it edits the CURRENT assignment);
        // generated tampers before the first deployment are skipped rather
        // than panicking the fixture by construction.
        if matches!(&action, Action::Tamper(_)) && !system.has_current_generation() {
            continue;
        }
        // After a tamper the fixture's OWN invariant checks cannot run until a
        // real push replaces the tampered assignment (the tamper deliberately
        // breaks current-vs-observed identity and the stored release binding).
        // Non-repairing actions in between are skipped so the next applied
        // action is always the repair.
        if model.current_tampered && !model.repairs_tamper(&action) {
            continue;
        }
        // THE ORACLE: the model predicts the outcome class under the step's
        // failure class, then the system runs the same step and its actual
        // outcome is classified identically. Both must agree on BOTH
        // dimensions.
        let expected = model.apply(&action, fault);
        let outcome = system.apply_prop(&action, fault);
        // The HARD POST-COMMIT RULE, asserted explicitly: once the deployment
        // durably committed (the model expects `Ok` + `Successful`), the push
        // must NEVER return `Err` — the observed refresh, rotation, and debt
        // I/O are warning-only after the durable commit. This binds the
        // post-commit lifecycle + maintenance properties into the result
        // comparison.
        if let Outcome::Push(result) = &outcome
            && let Err(e) = &**result
            && expected
                == (OutcomeClass::Push {
                    boundary: ReturnBoundary::Ok,
                    disposition: Disposition::Successful,
                })
        {
            panic!(
                "after action {}: a push the model expected to durably commit returned Err — \
                 a post-commit failure must never produce Err: {e}",
                model.index
            );
        }
        let actual = classify_outcome(&outcome, || system.err_disposition());
        match (expected, actual) {
            (OutcomeClass::Tampered, OutcomeClass::Tampered) => {}
            (
                OutcomeClass::Push {
                    boundary: eb,
                    disposition: ed,
                },
                OutcomeClass::Push {
                    boundary: ab,
                    disposition: ad,
                },
            ) => {
                assert_eq!(
                    eb, ab,
                    "after action {}: the RETURN BOUNDARY (Ok report vs Err) must match the oracle",
                    model.index
                );
                assert_eq!(
                    ed, ad,
                    "after action {}: the DEPLOYMENT DISPOSITION must match the oracle",
                    model.index
                );
            }
            (e, a) => panic!(
                "after action {}: expected outcome class {e:?}, the system produced {a:?}",
                model.index
            ),
        }
        // THE REPORT'S WARNING CHANNEL (asserts the ACTUAL report text per
        // step-17 contention combination): the marker-persisted "rotation
        // deferred for slot 'p1'" claim — the retryable deferral a later push
        // services once the lock is free — plus, on the debt combinations,
        // the explicit "rotation debt maintenance deferred: failed to ..."
        // notice (the marker was NOT persisted / maintenance deferred without
        // a marker, so no automatic retryability is claimed). Every expected
        // substring must appear in the actual report's warning. Under the
        // two-dimension oracle the contended push is ALWAYS `Ok` +
        // `Successful` (never `Err`) — the boundary/disposition asserts above
        // already bind that — so a missing warning is the ONLY way a silent
        // skip could slip through.
        if let Some(wants) = model.expected_warning {
            let actual_warning = match &outcome {
                Outcome::Push(result) => match &**result {
                    Ok(report) => report.warning.as_deref().unwrap_or(""),
                    Err(_) => "",
                },
                _ => "",
            };
            for w in wants {
                assert!(
                    actual_warning.contains(w),
                    "after action {}: the report must warn with {w:?}, got: {actual_warning:?}",
                    model.index
                );
            }
        }
        // THE CONVERGENCE ORACLE: the first CLEAN unlocked no-op services
        // the deferred rotation — the marker is cleared (cross-checked by
        // `assert_semantic_invariants`) and no warning remains on the report.
        if fault == FailureClass::None
            && expected
                == (OutcomeClass::Push {
                    boundary: ReturnBoundary::Ok,
                    disposition: Disposition::NoAttempt,
                })
            && let Outcome::Push(result) = &outcome
            && let Ok(report) = &**result
        {
            assert!(
                report.warning.is_none(),
                "after action {}: a clean no-op must report no warning once the deferred \
                 rotation converged; got: {:?}",
                model.index,
                report.warning,
            );
        }
        // The observable-state oracle (the existing cross-check plus the five
        // invariant groups); internally suspended while the crash window is
        // open or the step was a tamper / an unknown class.
        assert_semantic_invariants(&model, &system);
    }
}

proptest! {
    // Main property test: ORDINARY RANDOMIZED SEEDS with FAILURE
    // PERSISTENCE (proptest's defaults) — a failing vector writes to
    // `proptest-regressions/semantic_invariants.txt` and is replayed on the
    // next run (commit it so CI keeps reproducing the regression until
    // fixed). Random streams explore interleavings the hand-written
    // sequences miss; the shrinker minimizes any failing vector. The case
    // count is bounded so the suite stays fast (each case drives a full
    // fixture).
    #![proptest_config(ProptestConfig {
        cases: 16,
        failure_persistence: Some(Box::new(FileFailurePersistence::default())),
        ..ProptestConfig::default()
    })]

    #[test]
    fn semantic_state_machine(
        steps in prop::collection::vec((action_strategy(), failure_class_strategy()), 1..20)
    ) {
        run_semantic_state_case(steps);
    }
}

proptest! {
    // FIXED-SEED REGRESSION: the deterministic floor for CI. The same
    // generator under the pinned 0x5EED_5EED seed with no persistence runs
    // the IDENTICAL vectors on every invocation, so the suite stays
    // reproducible even when no failure has ever been persisted by the main
    // test. The case count is bounded so the suite stays fast.
    #![proptest_config(ProptestConfig {
        cases: 16,
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn semantic_state_machine_fixed_seed_regression(
        steps in prop::collection::vec((action_strategy(), failure_class_strategy()), 1..20)
    ) {
        run_semantic_state_case(steps);
    }
}

// ---------------------------------------------------------------------------
// Step-17 contention × debt-I/O matrix property
// ---------------------------------------------------------------------------

/// The debt-I/O half of the step-17 contention matrix: WHICH debt operation
/// the fresh step-17 deferral must fail at. Generated together with the
/// preexisting-debt flag — the required `(preexisting_debt × Read|Write)`
/// matrix — and every combination runs as a GUARANTEED non-no-op push.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContentionDebtFault {
    /// The fresh deferral's `set_rotation_deferred` READ faults.
    Read,
    /// The fresh deferral's `set_rotation_deferred` WRITE faults.
    Write,
}

/// One case of the step-17-contention × debt-I/O matrix for a generated
/// `(preexisting_reason: Option<String>, fault: Read | Write)` pair — the
/// preexisting debt marker's reason is an ARBITRARY string (or absent), the
/// fault one of the two debt-I/O operations. Each case is a FRESH fixture
/// and a SINGLE push to `t1` (the shared slot `p1`) — the fixture's first
/// push is GUARANTEED non-no-op (it mints generation 1; asserted via the
/// recorded attempt + `Successful` status, never an up-to-date no-op). The
/// push runs under the test-only step-17 phase hook with the fixture holding
/// the slot's mutation guard at EVERY park; the debt fault is armed ONLY at
/// the FreshStep17 park ([`step17_hook::HookPhase::FreshStep17`] — the
/// fixture's own per-slot rotation, whose contended else-branch runs the
/// debt read-modify-write that must fault), so the deferred-maintenance
/// retry (which, with a preexisting marker, reads the debt FIRST — before
/// its park — and must pass unarmed at the
/// [`step17_hook::HookPhase::DeferredRetry`] phase) can never consume the
/// one-shot at the wrong phase.
///
/// Per combination asserts the post-commit contract:
/// (a) the push returns `Ok` with `Successful` — NEVER `Err`;
/// (b) BOTH required warnings present — the contention warning
///     (`rotation deferred for slot 'p1'`) AND the debt-I/O notice
///     (`failed to read` / `failed to write rotation debt`, per fault);
/// (c) FAILED PERSISTENCE creates NO new debt marker while PRESERVING any
///     preexisting one: `Some(reason)` leaves the marker file BYTE-IDENTICAL
///     (the faulted read/write leaves the file untouched) and the reason
///     round-trips exactly through [`crate::store::local::LocalStore::read_rotation_debt`];
///     `None` leaves no marker file at all.
fn run_step17_contention_debt_case(preexisting_reason: Option<&str>, fault: ContentionDebtFault) {
    let ctx = format!("preexisting_reason={preexisting_reason:?}, fault={fault:?}");
    let f = Fixture::new();
    let id = f.next_prop_id();
    const TARGET: &str = "t1";
    const SLOT: &str = "p1";
    // Seed the preexisting debt marker with the ARBITRARY reason and
    // snapshot it BEFORE the push: a failed persistence must leave it
    // byte-identical.
    let marker_path = f.store.rotation_debt_path(TARGET);
    let before = if let Some(reason) = preexisting_reason {
        f.store
            .write_rotation_debt(
                TARGET,
                &BTreeMap::from([(SLOT.to_string(), reason.to_string())]),
            )
            .expect("seeding the preexisting debt marker");
        std::fs::read(&marker_path).expect("the seeded marker file must exist")
    } else {
        Vec::new()
    };
    let class = match fault {
        ContentionDebtFault::Read => FailureClass::Step17ContentionDebtRead,
        ContentionDebtFault::Write => FailureClass::Step17ContentionDebtWrite,
    };
    // The phase-distinguished hook driver arms the debt fault ONLY at
    // the FreshStep17 park; the retry (DeferredRetry) park passes
    // unarmed.
    let res = f.push_prop_step17_contended(TARGET, None, &id, class);
    f.disarm_prop_faults();
    let report = res.expect("{ctx}: the push must never fail (post-commit maintenance)");
    // (a) Ok + Successful, and a REAL push (attempt recorded — a new
    // generation was minted, never an up-to-date no-op).
    assert_eq!(
        report.status,
        Some(DeploymentStatus::Successful),
        "{ctx}: the contended push must report the committed Successful status"
    );
    assert!(
        report.attempt.is_some(),
        "{ctx}: the push must be the REAL push (attempt recorded), never an up-to-date no-op"
    );
    // (b) BOTH required warnings: the contention warning naming the slot
    // AND the debt-I/O notice for the faulted operation.
    let warning = report.warning.as_deref().unwrap_or("");
    assert!(
        warning.contains(STEP17_CONTENTION_WARNING),
        "{ctx}: the report must carry the contention warning 'rotation deferred for slot \
         'p1''; got: {warning:?}"
    );
    let debt_notice = match fault {
        ContentionDebtFault::Read => DEBT_READ_WARNING,
        ContentionDebtFault::Write => DEBT_WRITE_WARNING,
    };
    assert!(
        warning.contains(debt_notice),
        "{ctx}: the report must carry the debt-I/O notice {debt_notice:?}; got: {warning:?}"
    );
    // (c) FAILED PERSISTENCE: no NEW marker is created, and any
    // PREEXISTING marker is preserved byte-identical — the faulted
    // fresh-phase read/write leaves the file untouched, and the retry's
    // earlier unarmed write re-persisted the SAME content (so the
    // arbitrary reason round-trips exactly).
    let after = std::fs::read(&marker_path).unwrap_or_default();
    if let Some(reason) = preexisting_reason {
        assert_eq!(
            after, before,
            "{ctx}: the preexisting debt marker must be preserved byte-identical"
        );
        let debt = f.store.read_rotation_debt(TARGET).unwrap();
        assert_eq!(
            debt.get(SLOT).map(String::as_str),
            Some(reason),
            "{ctx}: the preexisting marker must still name the slot with its reason INTACT"
        );
    } else {
        assert!(
            after.is_empty() && !marker_path.exists(),
            "{ctx}: no debt marker file may appear when the fresh deferral's persistence \
             failed"
        );
    }
}

/// The deterministic exhaustive driver: run the full four-combination
/// `{preexisting_debt} × {Read | Write}` matrix in a FIXED order. This is
/// the plain, deterministic floor (no generation, no shrinking) — the
/// genuine randomized `(preexisting_reason, fault)` coverage lives in
/// `step17_contention_debt_property` below.
fn run_step17_contention_debt_matrix(combos: &[(Option<String>, ContentionDebtFault)]) {
    assert_eq!(
        combos.len(),
        4,
        "the matrix case must cover all four (preexisting_reason, fault) combinations"
    );
    for (preexisting_reason, fault) in combos {
        run_step17_contention_debt_case(preexisting_reason.as_deref(), *fault);
    }
}

/// DETERMINISTIC EXHAUSTIVE unit test: the full four-combination matrix —
/// every `(preexisting_debt, fault)` pair from {no marker, seeded marker} ×
/// {Read, Write}, run in a FIXED order through
/// [`run_step17_contention_debt_matrix`]. This is the plain, deterministic
/// floor (no generation, no shrinking): it pins the four post-commit
/// contracts — `Ok`+`Successful`, both required warnings, marker
/// preservation / no-marker-on-failed-persistence — for the whole matrix in
/// one pass.
#[test]
fn step17_contention_debt_matrix_exhaustive() {
    run_step17_contention_debt_matrix(&[
        (None, ContentionDebtFault::Read),
        (None, ContentionDebtFault::Write),
        (Some("seeded".to_string()), ContentionDebtFault::Read),
        (Some("seeded".to_string()), ContentionDebtFault::Write),
    ]);
}

proptest! {
    // The GENUINE property test. The OLD matrix proptest's input was
    // CONSTANT: `prop::sample::subsequence(vec![...4 elements], 4)` always
    // yields the same full 4-vector — no random generation, no shrinking
    // value. This test generates the REQUIRED
    // `(preexisting_reason: Option<String>, fault: Read | Write)` pair for a
    // GUARANTEED NON-NO-OP push: the preexisting debt marker's reason is an
    // ARBITRARY string (or absent) and the fault is one of the two debt-I/O
    // operations. Each case is a fresh fixture whose FIRST push mints a
    // generation (the runner asserts the attempt/status). The
    // phase-distinguished hook is the deterministic mechanism: no sleeps
    // beyond the 5ms `recv_timeout` polling, no races — the fault is armed
    // while the engine is PARKED at the FreshStep17 barrier and released
    // only after.
    //
    // The shrinker now has a REAL dimension to minimize: a failing reason
    // string (a preservation / round-trip break shrinks toward the minimal
    // offending string — or to None), and the fault half shrinks toward
    // `Read`. Every generated case asserts the same post-commit contract as
    // the exhaustive unit test: (a) the disposition is `Ok` + `Successful` —
    // never `Err`; (b) the EXACT warnings — the contention warning naming the
    // slot AND the debt-I/O notice for the chosen fault; (c) SEMANTIC
    // PRESERVATION of the arbitrary preexisting debt — the marker file
    // survives byte-identical with its ARBITRARY reason round-tripped exactly
    // when preexisting debt exists, and no marker appears when it does not
    // exist and persistence failed.
    //
    // Bounded cases (16) keep the suite fast (~35s total); a fixed seed
    // keeps CI deterministic (no persistence file) — the project's fixed-seed
    // leg, mirroring `semantic_state_machine_fixed_seed_regression` (the
    // randomized-with-persistence leg lives in the main
    // `semantic_state_machine`).
    #![proptest_config(ProptestConfig {
        cases: 16,
        rng_seed: RngSeed::Fixed(0x5EED_17DE),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn step17_contention_debt_property(
        (preexisting_reason, fault) in (
            prop::option::of(prop::string::string_regex(".{0,64}").unwrap()),
            prop::sample::select(
                [ContentionDebtFault::Read, ContentionDebtFault::Write].as_slice(),
            ),
        )
    ) {
        run_step17_contention_debt_case(preexisting_reason.as_deref(), fault);
    }
}
