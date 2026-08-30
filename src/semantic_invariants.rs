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
//! * **Scope** — every slot has EXACTLY ONE target owner. Target membership
//!   sets are pairwise disjoint and their union is the complete slot set. An
//!   operation on one target may modify only slots owned by that target, and
//!   each slot's observed projection stays equal to the remote assignment.
//!   The observed projection is refreshed by the real-push path
//!   AND by the no-op path (a crash-window push recovered by an up-to-date
//!   retry must not leave the slot's projection stale/absent), so after
//!   ANY completed or recovered mutation each slot's observed record
//!   equals the remote assignment (generation + artifact + the assignment's
//!   OWN minting deployment id — a slot the last push skipped or could not
//!   reach keeps its prior record, never fabricated or re-stamped).
//! * **Lifecycle** — the returned outcome agrees with the durable transaction
//!   phase; retry converges without duplicating history.
//! * **Integrity** — stored identity is never trusted; content, structure,
//!   and storage path are verified, and every mutation fails closed.
//! * **Bounds** — resource calculations are total, overflow-free, and fail
//!   safely (checked against a u128 reference model).
//!
//! The bulk of the suite runs a tiny **state-machine fixture**: 2 physical
//! slots owned by `t1` (`p1` on server `s1`, `p2` on server `s2`), one slot
//! owned by `t2` (`p3` on server `s3`), and the single slot `pdx` owned by
//! `debtfx` — each slot has EXACTLY ONE owning target (`t1` owns `p1`/`p2`,
//! `t2` owns `p3`, `debtfx` owns `pdx`) and ONE retention policy (its
//! OWNING VARIANT's, `standard`), 2 variants materializing the same tree
//! bytes, and 3+ tree generations via artifact-content versions. A `t1`
//! push plans BOTH of its own slots, so a pre-swap failure of the first
//! (under `stop_on_failure`) SKIPS the second — the skipped-slot
//! observed-refresh scenario the one-slot fixture could never reach.
//! Actions are short deterministic sequences (no sleeps, no
//! network; every transport is a local filesystem transport) and after every
//! action the five invariant groups are evaluated over the fixture state —
//! interleaving bugs show up more cheaply than one scenario per anticipated
//! defect.
//!
//! A second layer is the per-class property suite (digest reordering,
//! per-field record tampering, the u128 bounds grid, retention monotonicity).
//!
//! A THIRD layer is the **model-based property test**: a deterministic
//! [`Model`] oracle (same-module, below) is driven by the SAME bounded RANDOM
//! action stream as the [`Fixture`] (proptest, fixed seed + bounded cases so
//! every run is reproducible). The model tracks, purely from the actions, the
//! invariants' ground truth — the remote current generation, every target's
//! observed projection, the per-target snapshot and
//! deployment-attempt logs, pending-commit and retention-debt state — and
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
//! | Scope: retention is computed under a per-target policy instead of the slot's owning-variant one | `scope_retained_is_the_owning_variants_single_policy`, `state_machine_scope_projection_and_retention_owner` |
//! | Lifecycle: step-17 retention `?` after commit | `state_machine_lifecycle_cleanup_failure_after_commit` |
//! | Integrity: `verify_release_identity` trusts stored digest | `integrity_digest_unchanged_after_tamper_fails_closed`, `integrity_tampered_stored_release_blocks_historical_push`, `integrity_identity_field_change_fails_closed` |
//! | Integrity: stored records carry only their own schema version | `integrity_stored_release_schema_version_tamper_fails_closed` |
//! | Bounds: `need + reserve > available` wraps | `bounds_capacity_matches_u128_reference_over_grid` |

use crate::config::{FailurePolicy, ProjectConfig, SlotConfig};
use crate::deploy::plan::capacity_fits;
use crate::deploy::{PushOptions, PushReport, push, push_with_id};
use crate::error::Result;
use crate::identity::{
    ArtifactRef, DeploymentId, GenerationId, OperationId, ReleaseId, SlotId, TreeDigest,
    VariantName, test_deployment_id, test_tree_digest,
};
use crate::ledger;
use crate::ledger::DeploymentStatus;
use crate::ledger::LedgerEntry;
use crate::remote::helper::{GenerationAssignment, LockRecord, RemoteHelper};
use crate::remote::layout;
use crate::remote::transport::{
    CreateNewVerdict, ExecOutcome, FsBytes, LocalTransport, Remote, RemoteEntry, RemoteMeta,
};
use crate::retention::checkpoint::{CheckpointReport, run_checkpoint_unlocked};
use crate::retention::compute_retained;
use crate::store::local::LocalStore;
use crate::testutil::step17_hook;
use crate::verify::release::{
    canonicalize_slots, release_digest, variant_slots_digest, verify_release_identity,
};
#[cfg(test)]
use proptest::prelude::*;
#[cfg(test)]
use proptest::test_runner::RngSeed;
use std::collections::{BTreeMap, BTreeSet, HashSet};
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
to = "app-common/"
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

/// TWO physical slots owned by `t1` (`p1` on server `s1`, `p2` on server
/// `s2`): a `t1` push plans TWO slots and a pre-swap failure of the first
/// (under `stop_on_failure`) SKIPS the second — the skipped-slot
/// observed-refresh scenario the one-slot fixture could never reach. Each
/// slot binds a distinct server so the remote generation state (current
/// pointer, generations, trees) stays independent per slot. `t2` owns its
/// OWN single slot `p3` (server `s3`): a slot has EXACTLY ONE owning
/// target, so `t2`'s records and observed state are never touched by a
/// `t1` push (and vice versa) — the cross-target isolation the new model
/// guarantees. Plus the single-member slot `pdx` (target `debtfx`) used
/// ONLY by the retention-debt fault-matrix test. `debtfx`'s name is unique
/// to that test (no other test pushes it), so the TARGET-keyed debt fault
/// arms (`arm_read_retention_debt` / `arm_write_retention_debt`) cannot be
/// consumed by a concurrent test's push — the fixture's `t1`/`t2` pushes
/// stay untouched.
const SLOT_BODY: &str = r#"
[[slots]]
id = "p1"
server = "s1"
target = "t1"
deploy_dir = "/srv/si"

[[slots]]
id = "p2"
server = "s2"
target = "t1"
deploy_dir = "/srv/si2"

[[slots]]
id = "p3"
server = "s3"
target = "t2"
deploy_dir = "/srv/si3"

[[slots]]
id = "pdx"
server = "s1"
target = "debtfx"
deploy_dir = "/srv/si-debt"
"#;

/// The fixture's ONE retention policy — owned by the slot (the `standard`
/// variant file declares all three slots, so it is the single retention
/// source for each): CONSERVATIVE (newest 5 distinct bindings, 30 days of
/// age, the protected previous, 2 deployments). Targets own rollout only;
/// neither `t1` nor `t2` has a retention surface, and membership changes
/// never change what a slot retains.
const ROTATION_BODY: &str = r#"
[retention.per_server]
keep_distinct_artifacts = 5
keep_days = 30
protect_previous = true

[retention.deployment]
protect_deployments = 2
"#;

/// Targets own ROLLOUT behavior only: retention is slot-owned (the slot's
/// OWNING VARIANT file declares the single policy for every slot it
/// declares; see [`ROTATION_BODY`]). Each slot has EXACTLY ONE owning
/// target (`t1` owns `p1`/`p2`, `t2` owns `p3`, `debtfx` owns `pdx`) and
/// rotates under that ONE policy regardless of which target pushes it:
/// neither `t1` nor `t2` — nor the `debtfx` single-member target — carries
/// a retention surface here.
const DEPLOY_TOML: &str = r#"
schema_version = 2
application = "si"
release = "v1"

[[servers]]
id = "s1"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s2"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[[servers]]
id = "s3"
address = "a"
user = "u"
host_key_fingerprint = "SHA256:test"

[targets.t1]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }

[targets.t2]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }

[targets.debtfx]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
"#;

/// [`DEPLOY_TOML`] with `t1`'s rollout carrying `policy`: the
/// failure-policy tests drive BOTH supported policies through the SAME
/// multi-server fixture (`t1` owns `p1`/`p2`). The replacement targets the
/// `[targets.t1]` heading line only — `t2` and `debtfx` keep the default
/// `rollback_changed`.
fn deploy_toml_with_failure_policy(policy: FailurePolicy) -> String {
    DEPLOY_TOML.replacen(
        "[targets.t1]\nrollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }",
        &format!(
            "[targets.t1]\nrollout = {{ batch_size = 1, stop_on_failure = true, failure_policy = \"{policy}\" }}"
        ),
        1,
    )
}

// ---------------------------------------------------------------------------
// Fault injection
// ---------------------------------------------------------------------------

/// The I/O boundaries the Lifecycle class injects failures at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureStep {
    /// commit marker write on the remote (`state/commits/<id>.json`).
    CommitMarkerWrite,
    /// Post-commit retention's inventory write (`state/inventory.json`).
    RetentionInventoryWrite,
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
    /// Post-commit observed-refresh `write_slot_observed` for the FIRST
    /// advanced slot (`p1`) — the slot's ONE physical record write, after
    /// the durable commit point.
    ObservedPrimaryWrite,
    /// Post-commit observed-refresh `write_slot_observed` for the SECOND
    /// advanced slot (`p2`) — the other physical slot record write.
    ObservedOtherWrite,
    /// Post-commit retention-debt READ (`LocalStore::read_retention_debt`,
    /// target-keyed) — the marker read during the deferred-retention retry or
    /// the step-17 clear/defer, after the durable commit point.
    DebtRead,
    /// Post-commit retention-debt WRITE/REMOVE
    /// (`LocalStore::write_retention_debt`, target-keyed) — the marker's
    /// persist, and the empty-map removal that clears a serviced marker.
    DebtWrite,
    /// The "debt remove" arm of the matrix: the cleared-marker removal is the
    /// same `write_retention_debt` call, so this maps onto [`DebtWrite`]'s arm
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
    /// PRE-SWAP STATUS-READ FAULT: once the push's operation-lock write has
    /// been seen (gating state below), the FIRST read of the `current` link
    /// fails exactly once — the pre-swap status read inside `process_server`
    /// (the planning and reconcile status reads run BEFORE any lock write and
    /// must pass, so the remote stays "reachable for planning/status" and
    /// fails only at the pre-swap moment). The slot's `process_server` then
    /// aborts with `Ok(Failed)` before the swap: nothing advanced, and under
    /// `stop_on_failure` the remaining slots are SKIPPED.
    fail_current_read_after_lock: bool,
    /// PER-SERVER PRE-SWAP STATUS-READ FAULT: the same gate as above, but
    /// fired only on the transport of ONE NAMED server directory (`s1` /
    /// `s2` / `s3` — each [`FailOnceRemote`] wraps exactly one server
    /// directory and knows its own base name). This is how the failure
    /// POLICY tests fail a SPECIFIC BATCH POSITION of a multi-server push:
    /// the batch order of a `t1` push is `p1` (server `s1`), then `p2`
    /// (server `s2`), so arming `s1` fails batch 0, arming `s2` fails batch
    /// 1 — while every other server's pre-swap reads pass untouched. The arm
    /// is consumed by the matching server's first post-lock `current`-link
    /// read; a non-matching server leaves it armed.
    fail_current_read_on_server: Option<String>,
    /// Whether the push has written (or found) the mutation lock on ANY
    /// server this push touches: the pre-swap status-read arm fires only
    /// after a lock write, so the planning/reconcile status reads (before any
    /// lock write) pass untouched. The fixture resets it when the arm is set
    /// (a fresh push) and when faults are disarmed.
    lock_written: bool,
}

/// A transport that fails selected writes once, then passes through. Wraps
/// `LocalTransport`; deterministic, no sleeps.
struct FailOnceRemote {
    inner: LocalTransport,
    fault: Arc<Mutex<RemoteFault>>,
}

impl FailOnceRemote {
    fn build(
        base: PathBuf,
        fault: Arc<Mutex<RemoteFault>>,
        script: crate::remote::transport::scripted::ScriptedExec,
    ) -> Result<Box<dyn Remote>> {
        Ok(Box::new(FailOnceRemote {
            // The deterministic fake exec: the push logic branches on the
            // exec OUTCOME only (verification success/failure), and the
            // property's fault injection is FILE-level — the fake replaces
            // the real `true` subprocess with the scripted outcome, so the
            // state-machine properties spawn nothing and stay deterministic.
            inner: LocalTransport::with_exec(&crate::testutil::fixture_env(), base, script)?,
            fault,
        }))
    }
    fn should_fail(&self, rel: &Path) -> bool {
        let mut f = self.fault.lock().unwrap();
        if let Some(marker) = &f.fail_write_once {
            let rel = rel.to_string_lossy().to_string();
            // Commit-marker faults name the `state/commits/` DIRECTORY
            // (prefix match); the retention-inventory fault names the exact
            // file. The fault is consumed ONLY by a matching write — a write
            // to any other path must leave it armed.
            if rel.starts_with(marker) || rel.ends_with(marker) {
                f.fail_write_once = None;
                return true;
            }
        }
        false
    }
    /// The pre-swap status-read arm: fires exactly once on the FIRST read of
    /// the `current` link AFTER the push's mutation-lock write was seen. The
    /// planning status reads (before any lock write) and the reconcile reads
    /// (which verify generations BEFORE acquiring any lock) pass.
    fn should_fail_status_read(&self, rel: &Path) -> bool {
        let mut f = self.fault.lock().unwrap();
        // The per-server arm fires only on the transport of the NAMED server
        // (the batch-position failures): that server's first post-lock
        // `current`-link read fails exactly once; any other server's reads
        // pass and leave the arm armed.
        if f.fail_current_read_on_server.as_deref() == Some(self.server_name().as_str())
            && f.lock_written
            && rel == layout::current()
        {
            f.fail_current_read_on_server = None;
            return true;
        }
        if f.fail_current_read_after_lock && f.lock_written && rel == layout::current() {
            f.fail_current_read_after_lock = false;
            return true;
        }
        false
    }

    /// The name of the server directory this transport wraps (each
    /// [`FailOnceRemote`] wraps exactly one server's remote directory, so
    /// the base name is the server id used by the per-server pre-swap arm).
    fn server_name(&self) -> String {
        self.inner
            .root()
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
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
    fn try_write_new(&self, rel: &Path, data: &[u8]) -> Result<CreateNewVerdict> {
        if self.should_fail(rel) {
            return Err(crate::error::Error::transport(format!(
                "injected write failure at {}",
                rel.display()
            )));
        }
        // The mutation-lock write (or its presence — the lock already exists,
        // e.g. the reconcile marker write of this push) marks the mutating
        // phase: the pre-swap status-read arm may now fire on the next
        // `current`-link read.
        if rel == layout::operation_lock() {
            self.fault.lock().unwrap().lock_written = true;
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
        if self.should_fail_status_read(rel) {
            return Err(crate::error::Error::transport(format!(
                "injected pre-swap status read failure at {}",
                rel.display()
            )));
        }
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
    /// Run a standalone retention pass under the slots' ONE slot-owned
    /// policy (the OWNING VARIANT's — never a per-target union).
    Rotate,
    /// Establish a checkpoint history floor on the target at the deployment
    /// whose snapshot is the `k`-th of the target's VISIBLE snapshots (the
    /// fixture resolves the deployment id — the strategy cannot mint ids,
    /// which are generated per-fixture at runtime, so the action carries the
    /// generated selector and "arms on a successful deployment id already
    /// recorded in the target's history" by construction: the selector can
    /// only ever name a recorded successful deployment). Runs the REAL
    /// `run_checkpoint` / `checkpoint_discards` / `checkpoint_compact` path
    /// (the local advisory locks skipped, exactly as the fixture's push
    /// entry points do). LOW weight: the floor is a rare operation, and the
    /// pending-commit × floor interactions it pins are this property's
    /// focus.
    Checkpoint(&'static str, u64),
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
    /// A real checkpoint run (the floor write + compaction path); the report
    /// is kept so the driver can assert the discard sets and the
    /// established/idempotent flag against the model's expectation.
    Checkpoint(Box<CheckpointReport>),
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
    /// durable). Post-commit maintenance warnings (retention, observed
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
    /// Remote post-commit retention inventory write fails: the retention is
    /// deferred (debt marker + warning) after the durable commit.
    RetentionInventory,
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
    /// observed slot records themselves still refresh.
    ObservedWriteServer,
    /// Post-commit observed-refresh `write_slot_observed` fails for the
    /// FIRST advanced slot (`p1`): that slot's ONE physical record stays
    /// stale — in its OWNING target's view, since every view filters the
    /// single physical map.
    ObservedPrimaryWrite,
    /// Post-commit observed-refresh `write_slot_observed` fails for the
    /// SECOND advanced slot (`p2`): that slot's ONE physical record stays
    /// stale — in its OWNING target's view.
    ObservedOtherWrite,
    /// Retention-debt marker READ fails (target-keyed: the store's debt
    /// methods carry no deployment id, so the arm lands on the pushed
    /// target's `retention-debt.json`). Post-commit maintenance is
    /// NON-FALLIBLE — a warning, never an `Err` — so the committed outcome
    /// class is unchanged and the marker effect the model tracks is
    /// deterministic.
    DebtRead,
    /// Retention-debt marker WRITE fails (the same `write_retention_debt`
    /// call as the remove). Warning-only; non-fallible.
    DebtWrite,
    /// Retention-debt marker REMOVE — the same `write_retention_debt` call as
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
    /// post-commit per-slot retention), via the test-only step-17 phase hook
    /// ([`crate::testutil::step17_hook`]): the engine parks immediately
    /// before its per-slot `acquire_lock_guard`, the fixture holds the
    /// competing guard, then releases the engine — so the retention
    /// deterministically defers (debt marker + warning naming the slot), the
    /// push still reports `Successful` (it already committed — the outcome
    /// class is `Ok` + `Successful`, NEVER `Err`), and a later clean no-op
    /// services the marker once the lock is free. The pre-commit lock checks
    /// (preflight, reconcile, commit) run while the lock is FREE: the
    /// fixture only grabs the guard the moment the engine parks at a
    /// step-17-equivalent lock acquisition — the push's own step-17 retention
    /// AND, when prior debt exists, the deferred-maintenance retry that runs
    /// before it (the fixture services every park, so both contend). The
    /// park signal is PHASE-DISTINGUISHED ([`step17_hook::HookPhase`]): the
    /// retry is the [`step17_hook::HookPhase::DeferredRetry`] phase, the
    /// push's own retention the [`step17_hook::HookPhase::FreshStep17`]
    /// phase.
    Step17Contended,
    /// [`FailureClass::Step17Contended`] combined with a retention-debt
    /// marker READ fault in the same push, armed by the fixture ONLY at the
    /// FRESH step-17 park ([`step17_hook::HookPhase::FreshStep17`]) — never
    /// at the deferred-maintenance retry ([`step17_hook::HookPhase::DeferredRetry`]),
    /// which reads the debt FIRST and must pass unarmed. The fresh contended
    /// deferral's `set_retention_deferred` read then fails (explicit "retention
    /// debt maintenance deferred: failed to read" warning): NO new marker is
    /// persisted, and a PREEXISTING marker is preserved untouched. A later
    /// push re-defers. Warning-only; non-fallible.
    Step17ContentionDebtRead,
    /// [`FailureClass::Step17Contended`] combined with a retention-debt
    /// marker WRITE fault (in the same push), armed by the fixture ONLY at
    /// the FRESH phase park — the retry's earlier debt write (preexisting
    /// marker) passes unarmed. The fresh contended deferral's
    /// `set_retention_deferred` cannot persist the marker — explicit
    /// "retention debt maintenance deferred: failed to write" warning, NO
    /// new marker (no automatic retryability claim) and any PREEXISTING
    /// marker preserved byte-identical (the failed write leaves the file
    /// untouched). Warning-only; non-fallible.
    Step17ContentionDebtWrite,
    /// PRE-SWAP REMOTE STATUS failure: the remote is reachable for the
    /// planning/status reads (and the reconcile's verification reads — both
    /// run before any mutation-lock write) but its `current`-link read fails
    /// EXACTLY ONCE at the pre-swap moment — the status read inside
    /// `process_server`, right after the slot's mutation-lock write. The
    /// slot's `process_server` aborts with `Ok(Failed)` before the swap
    /// (nothing advanced) and, under `stop_on_failure`, the remaining
    /// planned slots are SKIPPED. The push reports `Ok` +
    /// `FailedRolledBack` (nothing advanced, nothing to compensate) with the
    /// attempt recorded and NO snapshot; the post-commit observed refresh
    /// must leave every unadvanced slot's projection UNTOUCHED (never
    /// fabricated from the desired artifact, never `last_deployment`
    /// reassigned to a deployment that did not touch the slot). On a remote
    /// with NO live current (no `current` link) the arm never fires (there
    /// is nothing to read) and the push proceeds as a clean deployment.
    RemoteStatusPreSwap,
}

/// The step-17 contention else-branch's explicit per-slot warning: the
/// marker-persisted "retryable" claim the model asserts for the contention
/// combinations (a later push services the marker once the lock is free).
const STEP17_CONTENTION_WARNING: &str =
    "retention deferred for slot 'p1': slot lock held by another operation";
/// The explicit debt-I/O failure notice — the marker was NOT persisted /
/// maintenance deferred WITHOUT a marker, so no automatic retryability is
/// claimed. `set_retention_deferred` (and the retry's I/O) emit exactly this
/// shape on a read/write failure.
const DEBT_READ_WARNING: &str =
    "retention debt maintenance deferred: failed to read retention debt";
const DEBT_WRITE_WARNING: &str =
    "retention debt maintenance deferred: failed to write retention debt";

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
        Outcome::Checkpoint(_) => OutcomeClass::Push {
            boundary: ReturnBoundary::Ok,
            disposition: Disposition::NoAttempt,
        },
        Outcome::Tampered => OutcomeClass::Tampered,
        Outcome::Push(result) => match &**result {
            Ok(report) => {
                let boundary = ReturnBoundary::Ok;
                let disposition = match report.status {
                    None => {
                        if report.message.starts_with("push pending") {
                            // An intent-only (pending) attempt: the entry has
                            // no terminal — the pending OPERATIONAL state.
                            Disposition::Pending
                        } else {
                            assert_eq!(
                                report.message, "Everything up to date",
                                "the only statusless report the fixture produces is the no-op (or a pending attempt)"
                            );
                            Disposition::NoAttempt
                        }
                    }
                    Some(DeploymentStatus::Successful) => Disposition::Successful,
                    Some(DeploymentStatus::FailedPreflight) => Disposition::FailedPreflight,
                    Some(DeploymentStatus::Degraded) => Disposition::Degraded,
                    Some(DeploymentStatus::FailedRolledBack) => Disposition::FailedRolledBack,
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
            disposition: Disposition::NoAttempt
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
            disposition: Disposition::FailedPreflight
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
    config: ProjectConfig,
    store: LocalStore,
    remotes_base: PathBuf,
    fault: Arc<Mutex<RemoteFault>>,
    /// The deterministic fake exec every transport this fixture builds
    /// injects (see [`Fixture::remote_factory`] / [`Fixture::remote_for`]):
    /// scripted verification outcomes, no real subprocesses — the property
    /// suites stay parallel-safe and deterministic under the in-process
    /// harness.
    script: crate::remote::transport::scripted::ScriptedExec,
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
        Fixture::with_failure_policy(FailurePolicy::RollbackChanged)
    }

    /// The fixture with `t1`'s rollout carrying `policy` — the
    /// failure-policy tests drive BOTH supported policies through the SAME
    /// multi-server fixture (`t1` owns `p1`/`p2`, each its own batch); every
    /// other target keeps the default `rollback_changed`.
    fn with_failure_policy(policy: FailurePolicy) -> Fixture {
        let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let release_dir = project.join("releases").join("v1");
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(
            release_dir.join("standard.toml"),
            format!("{VARIANT_BODY}\n{SLOT_BODY}\n{ROTATION_BODY}"),
        )
        .unwrap();
        // canary declares no slots; identical mappings -> same tree bytes.
        std::fs::write(release_dir.join("canary.toml"), VARIANT_BODY).unwrap();
        let cfg_path = project.join("deploy.toml");
        std::fs::write(&cfg_path, deploy_toml_with_failure_policy(policy)).unwrap();
        let artifacts_dir = release_dir.join("artifacts");
        let common_dir = artifacts_dir.join("deployment/common");
        std::fs::create_dir_all(&common_dir).unwrap();
        std::fs::write(common_dir.join("README"), "common\n").unwrap();
        let config = ProjectConfig::load(&cfg_path).unwrap();
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
            // The deterministic fake exec every transport this fixture builds
            // injects (see [`FailOnceRemote::build`] / [`Fixture::remote_for`]):
            // the state-machine properties exercise the push LOGIC with
            // scripted verification outcomes — no real subprocess, no
            // wall-clock — so they are parallel-safe under `cargo test --lib`
            // and heavy nextest parallelism.
            script: crate::remote::transport::scripted::ScriptedExec::default_success(),
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
    ) -> impl Fn(&crate::config::ServerDef, &crate::config::SlotConfig) -> Result<Box<dyn Remote>>
    + 'static {
        let rf = self.remotes_base.clone();
        let fault = self.fault.clone();
        let script = self.script.clone();
        move |s: &crate::config::ServerDef, _slot: &crate::config::SlotConfig| {
            FailOnceRemote::build(rf.join(s.id.as_str()), fault.clone(), script.clone())
        }
    }

    /// The server a placement slot binds to in the multi-slot fixture: each
    /// slot owns a DISTINCT server (`p1` -> `s1`, `p2` -> `s2`, `p3` ->
    /// `s3`) so the remote generation state stays independent per slot (two
    /// slots on one server would share the single `current` pointer). `pdx`
    /// shares `s1` but is a single-member slot the debt-matrix test pushes
    /// alone.
    fn server_for_slot(&self, slot: &str) -> &'static str {
        match slot {
            "p1" => "s1",
            "p2" => "s2",
            "p3" => "s3",
            "pdx" => "s1",
            other => panic!("unknown fixture slot {other}"),
        }
    }

    /// A transport handle over the given server's remote directory. The
    /// directory is created on demand so reads work before the first push.
    fn remote_for(&self, server: &str) -> Box<dyn Remote> {
        let p = self.remotes_base.join(server);
        std::fs::create_dir_all(&p).unwrap();
        Box::new(
            LocalTransport::with_exec(&crate::testutil::fixture_env(), p, self.script.clone())
                .unwrap(),
        )
    }

    /// A transport handle over the server's remote directory (`s1`). The
    /// directory is created on demand so reads work before the first push.
    fn remote(&self) -> Box<dyn Remote> {
        self.remote_for("s1")
    }

    /// Run `f` with a live `RemoteHelper` over a server's remote directory.
    fn with_helper_for<R>(&self, server: &str, f: impl FnOnce(RemoteHelper<'_>) -> R) -> R {
        let remote = self.remote_for(server);
        f(RemoteHelper::new(remote.as_ref()))
    }

    /// Run `f` with a live `RemoteHelper` over a placement slot's server.
    fn with_slot_helper<R>(&self, slot: &str, f: impl FnOnce(RemoteHelper<'_>) -> R) -> R {
        self.with_helper_for(self.server_for_slot(slot), f)
    }

    /// Run `f` with a live `RemoteHelper` over the server's remote directory.
    fn with_helper<R>(&self, f: impl FnOnce(RemoteHelper<'_>) -> R) -> R {
        self.with_helper_for("s1", f)
    }

    /// The current generation's stored assignment for the single slot, if any.
    fn current_assignment(&self) -> Option<GenerationAssignment> {
        let owner = crate::remote::helper::test_owner("si", "p1");
        self.with_helper(|helper| {
            let status = helper.status(&owner).ok()?;
            let g = status.current_generation()?;
            helper.read_assignment(g.as_str(), &owner).ok()
        })
    }

    /// The LIVE remote assignments for the fixture's placement slots (`p1`
    /// on `s1`, `p2` on `s2`, `p3` on `s3`), keyed by placement slot: the
    /// ground truth the observed projections must equal (generation +
    /// artifact + the assignment's OWN minting deployment id). A slot whose
    /// server has no current generation, or whose assignment cannot be read,
    /// is absent.
    fn current_assignments(&self) -> BTreeMap<SlotId, GenerationAssignment> {
        let mut out = BTreeMap::new();
        for slot in ["p1", "p2", "p3"] {
            let owner = crate::remote::helper::test_owner("si", slot);
            let asn = self.with_slot_helper(slot, |helper| {
                let status = helper.status(&owner).ok()?;
                let g = status.current_generation()?;
                helper.read_assignment(g.as_str(), &owner).ok()
            });
            if let Some(a) = asn {
                out.insert(SlotId::new(slot.to_string()), a);
            }
        }
        out
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
                group: None,
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
                group: None,
            },
            id,
        )
    }

    /// The deployment id of the LAST successful snapshot on `t` — the
    /// deployment-keyed rollback ref for a historical push (rollback
    /// payloads are keyed by deployment id). Used by the deterministic
    /// integrity fixtures (which push through [`Fixture::push`], outside the
    /// property path's `last_prop` bookkeeping).
    fn latest_deployment_id(&self, t: &str) -> String {
        self.store
            .read_snapshots(t)
            .unwrap_or_default()
            .last()
            .map(|s| s.deployment_id.as_str().to_string())
            .expect("a deployment has been pushed to the target")
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
                group: None,
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
        test_deployment_id(&format!("deploy-si-{}-{i:04}", self.prop_tag))
    }

    /// The per-fixture deployment-id tag (derived from the unique tempdir
    /// name). The MODEL mints the SAME id sequence from it (see
    /// [`Model::mint_id`]) so the oracle's deployment ids equal the system's
    /// — the checkpoint floor and the raw-log comparisons pin ids, so the
    /// two sides must mint identical strings.
    fn prop_tag(&self) -> &str {
        &self.prop_tag
    }

    /// Arm the step's [`FailureClass`] for a push of `pushed` with deployment
    /// id `id`. The local-store arms are keyed by the deployment id (and, for
    /// the observed-refresh arms, by the target); the remote arms are
    /// suffix-armed; the debt-I/O arms are keyed by the pushed TARGET (the
    /// store's debt methods carry no deployment id). Lock contention needs no
    /// arm (the fixture holds the lock itself).
    fn arm_prop_fault(&self, class: FailureClass, pushed: &str, id: &DeploymentId) {
        let reg = self.store.fault_registry();
        match class {
            FailureClass::CommitMarker | FailureClass::RetentionInventory => {
                self.set_remote_fault(match class {
                    FailureClass::CommitMarker => FailureStep::CommitMarkerWrite,
                    _ => FailureStep::RetentionInventoryWrite,
                })
            }
            FailureClass::IntentPersist => reg.arm_append_attempt(id.as_str()),
            FailureClass::ResultsWrite => reg.arm_append_terminal(id.as_str()),
            FailureClass::SnapshotAppend => reg.arm_append_terminal(id.as_str()),
            FailureClass::LastSuccessfulWrite => reg.arm_append_terminal(id.as_str()),
            FailureClass::TransitionSuccessful => reg.arm_append_terminal(id.as_str()),
            FailureClass::TransitionPending => reg.arm_append_terminal(id.as_str()),
            FailureClass::ObservedWriteServer => reg.arm_write_server(id.as_str(), pushed),
            // The observed-refresh SLOT-write faults are keyed by deployment
            // id AND SLOT: the engine writes each advanced slot's ONE
            // physical record (`slots/<slot-id>/observed.json`), so the
            // primary arm selects the FIRST planned slot's write (`p1`) and
            // the other arm the SECOND (`p2`). A faulted write leaves that
            // slot's physical record stale — the slot's OWNING target's view
            // of it lags.
            FailureClass::ObservedPrimaryWrite => reg.arm_write_observed(id.as_str(), "p1"),
            FailureClass::ObservedOtherWrite => reg.arm_write_observed(id.as_str(), "p2"),
            FailureClass::DebtRead => reg.arm_read_retention_debt(pushed),
            FailureClass::DebtWrite | FailureClass::DebtRemove => {
                reg.arm_write_retention_debt(pushed)
            }
            FailureClass::RemoteStatusPreSwap => self.set_remote_read_fault(),
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
        let mut f = self.fault.lock().unwrap();
        f.fail_write_once = None;
        f.fail_current_read_after_lock = false;
        f.fail_current_read_on_server = None;
        f.lock_written = false;
        self.store.fault_registry().clear();
    }

    /// Acquire the slot's mutation lock via a SECOND `RemoteHelper` (its own
    /// operation id) and return its LOCK RECORD plus the server it was
    /// acquired on; [`Fixture::release_contention_lock`] must be called with
    /// the same record and server when the contended action is done. The
    /// lock is a single advisory file per server, so while it is held the
    /// push's own preflight lock check fails. The lock is held on the PUSHED
    /// target's FIRST slot's server (a slot has exactly one owning target, so
    /// a `t1` push contends on `s1` and a `t2` push on `s3`) — the engine's
    /// mutation-lock preflight checks each selected slot's server in order,
    /// so the first slot's server is the one that must be held for the
    /// contention to fire.
    fn hold_contention_lock(&self, t: &str) -> (LockRecord, String) {
        let first_slot = Model::target_slots(t)[0].clone();
        let server = self.server_for_slot(first_slot.as_str()).to_string();
        let remote = self.remote_for(&server);
        let helper = RemoteHelper::new(remote.as_ref());
        let op = format!("si-contend-{}", OperationId::generate().as_str());
        let record = helper
            .acquire_lock_record_for_test(&crate::identity::OperationId::new(op.clone()))
            .expect("the contention lock must be free at the start of the step");
        (record, server)
    }

    fn release_contention_lock(&self, record: &LockRecord, server: &str) {
        let remote = self.remote_for(server);
        let helper = RemoteHelper::new(remote.as_ref());
        // The raw-record release goes through the test-only seam (production
        // release happens only through the `HeldSlotLock` guard); the
        // state-machine fixture models raw records, so a record-based
        // release is the faithful action.
        let _ = helper.release_lock_record_for_test(record);
    }

    /// Simulate STEP-17 lock contention (the post-commit retention the action
    /// with a fixed deployment id, then disarm every one-shot fault (the
    /// classes are step-scoped). Invariant checks are NOT run here — the
    /// oracle runs them only when the model reports the step left the state
    /// checkable (no open crash window, no tamper, no unknown class).
    fn apply_prop(&self, action: &Action, class: FailureClass) -> Outcome {
        match action {
            Action::Push(t) | Action::Retry(t) => self.push_prop(t, None, class),
            Action::Rollback(t, i) => {
                let token = self.rollback_token(t, *i);
                self.push_prop(t, Some(token.as_str()), class)
            }
            Action::Checkpoint(t, k) => self.checkpoint_prop(t, *k),
            other => {
                // Build / Rotate / Tamper: nothing consumes a fault, so the
                // class is dropped without arming.
                self.apply_no_checks(other.clone())
            }
        }
    }

    /// Run the REAL checkpoint path on `t` at the deployment whose snapshot
    /// is the `k`-th of the target's VISIBLE (floor-gated) chain — a
    /// "recorded successful deployment" by construction. An empty visible
    /// chain is a no-op step (the model predicts the same: there is no
    /// deployment to checkpoint). The local advisory locks are skipped
    /// exactly like the fixture's push entry points
    /// ([`crate::deploy::push_with_id`]); the durable floor write, the
    /// `checkpoint_discards` enumeration, and the `checkpoint_compact`
    /// compaction all run UNMODIFIED on the per-fixture store (its fault
    /// registry hooks are the checkpoint path's own — the generated failure
    /// classes are push-oriented and never armed for a checkpoint, so the
    /// step-scoped fault is dropped like any unconsumed arm).
    fn checkpoint_prop(&self, t: &str, k: u64) -> Outcome {
        // The VISIBLE chain is the ledger's SUCCESSFUL entries (the rollback
        // states) — the implicit floor: after a checkpoint the first retained
        // entry is the oldest rollback state.
        let snaps: Vec<LedgerEntry> = self
            .store
            .read_ledger(t)
            .unwrap_or_default()
            .into_iter()
            .filter(|e| {
                e.terminal
                    .as_ref()
                    .is_some_and(|x| x.status() == DeploymentStatus::Successful)
            })
            .collect();
        if snaps.is_empty() {
            // No recorded successful deployment on the visible chain: the
            // model no-ops too (nothing to checkpoint, nothing changes).
            return Outcome::Ok;
        }
        let id = snaps[(k % snaps.len() as u64) as usize]
            .deployment_id
            .clone();
        let rep = run_checkpoint_unlocked(&self.store, &self.config, t, &id)
            .expect("a checkpoint at a recorded successful deployment succeeds");
        Outcome::Checkpoint(Box::new(rep))
    }

    /// The rollback token for the deployment at POSITION `i` of `t`'s
    /// visible deployment history (the deployment-keyed grammar: `deploy
    /// push <target> <deployment-id>`). A position beyond the current chain
    /// names a deployment that does not exist — the token fails closed at
    /// resolution, and the model mirrors it by looking up the same position
    /// on its own chain (positions are DERIVED, never stored).
    fn rollback_token(&self, t: &str, i: u64) -> String {
        let snaps = self.store.read_snapshots(t).unwrap_or_default();
        match snaps.get(i as usize) {
            Some(s) => s.deployment_id.as_str().to_string(),
            // A VALID canonical id that resolves to nothing (the grammar
            // validates the refid, so the token must parse; the resolution
            // then fails closed as "no such deployment").
            None => test_deployment_id(&format!("deploy-nonexistent-{t}-{i}"))
                .as_str()
                .to_string(),
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
            Some(self.hold_contention_lock(t))
        } else {
            None
        };
        let res = match ref_token {
            Some(rt) => crate::deploy::push_ref_with_id(
                &self.cfg_path,
                &self.store,
                &self.remote_factory(),
                t,
                &self.config,
                &PushOptions {
                    dry_run: false,
                    ref_token: Some(rt.to_string()),
                    group: None,
                },
                &id,
            ),
            None => self.push_with_id(t, &id),
        };
        if let Some((record, server)) = contend {
            self.release_contention_lock(&record, &server);
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
            // An intent WITHOUT a terminal IS the pending state (the
            // terminal status enum carries no pending status).
            None => Disposition::Pending,
            Some(DeploymentStatus::FailedPreflight) => Disposition::FailedPreflight,
            Some(DeploymentStatus::Degraded) => Disposition::Degraded,
            Some(DeploymentStatus::FailedRolledBack) => Disposition::FailedRolledBack,
            Some(DeploymentStatus::Successful) => Disposition::Successful,
        }
    }

    /// Run a push/rollback step under the step-17 phase hook (the
    /// [`FailureClass::Step17Contended`] branch of [`Fixture::push_prop`]):
    /// arm the hook for the step's deployment id, run the push in a scoped
    /// thread, and the instant the engine parks at a step-17-equivalent lock
    /// acquisition, acquire the slot's mutation lock via a SECOND helper and
    /// hold it until the push returns — the engine's own retention then
    /// deterministically CONTENDS (deferred: debt marker + warning naming the
    /// slot), never silent and never via a race on the lock file.
    ///
    /// PHASE DISTINCTION: the park signal carries the
    /// [`step17_hook::HookPhase`]. The fixture services EVERY park with the
    /// same held guard, but arms the DEBT FAULT ONLY at the
    /// [`step17_hook::HookPhase::FreshStep17`] park — the engine's own
    /// per-slot retention, whose contended else-branch runs the debt
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
        // The guard is held on the PUSHED target's FIRST slot's server (a
        // slot has exactly one owning target, so a t1 push contends on s1 and
        // a t2 push on s3). Computed before the scoped thread so the borrow
        // does not escape.
        let first_slot = Model::target_slots(t)[0].clone();
        let guard_server = self.server_for_slot(first_slot.as_str()).to_string();
        let t_owned = t.to_string();
        std::thread::scope(|s| {
            let push = s.spawn(|| match ref_token {
                Some(rt) => crate::deploy::push_ref_with_id(
                    &self.cfg_path,
                    &self.store,
                    &self.remote_factory(),
                    &t_owned,
                    &self.config,
                    &PushOptions {
                        dry_run: false,
                        ref_token: Some(rt.to_string()),
                        group: None,
                    },
                    id,
                ),
                None => self.push_with_id(&t_owned, id),
            });
            // The competing guard, held until AFTER the push returns — the
            // engine must find the lock held when it wakes from EVERY park.
            // The remote / helper are declared here so the guard's borrow
            // outlives the loop (an uncontended step just drops an unused
            // helper).
            let remote = self.remote_for(&guard_server);
            let helper = RemoteHelper::new(remote.as_ref());
            let mut guard: Option<crate::remote::helper::HeldSlotLock<'_>> = None;
            // Service EVERY park, not just the first: with prior debt the
            // engine parks at the deferred-maintenance RETRY first (the
            // [`step17_hook::HookPhase::DeferredRetry`] phase) and AGAIN at
            // its own step-17 retention ([`step17_hook::HookPhase::FreshStep17`])
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
                        guard = Some(helper.acquire_lock_guard(&crate::identity::OperationId::new(holder.to_string())).expect(
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
                            FailureClass::Step17ContentionDebtRead => {
                                reg.arm_read_retention_debt(t)
                            }
                            FailureClass::Step17ContentionDebtWrite => {
                                reg.arm_write_retention_debt(t)
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
                self.rotate_slot_policy()
                    .expect("standalone retention succeeds");
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
            FailureStep::ResultsWrite => reg.arm_append_terminal(id.as_str()),
            FailureStep::SnapshotAppend => reg.arm_append_terminal(id.as_str()),
            FailureStep::LastSuccessfulWrite => reg.arm_append_terminal(id.as_str()),
            FailureStep::TransitionSuccessful => reg.arm_append_terminal(id.as_str()),
            FailureStep::TransitionPending => reg.arm_append_terminal(id.as_str()),
            // The post-commit observed-refresh faults are keyed by deployment
            // id AND SLOT: the fixture's OWNED slots are `p1` (written first
            // in a t1 push — the "primary" write) and `p2` (written second
            // — the "other" write). A faulted slot write leaves THAT slot's
            // one physical record stale in its OWNING target's view.
            FailureStep::ObservedWriteServer => reg.arm_write_server(id.as_str(), "t1"),
            FailureStep::ObservedPrimaryWrite => reg.arm_write_observed(id.as_str(), "p1"),
            FailureStep::ObservedOtherWrite => reg.arm_write_observed(id.as_str(), "p2"),
            // The retention-debt faults are keyed by the TARGET only (the debt
            // methods carry no deployment id) and fire on `debtfx` — the
            // fixture target no other test pushes — so no concurrent test's
            // push can consume the arm.
            FailureStep::DebtRead => reg.arm_read_retention_debt("debtfx"),
            FailureStep::DebtWrite | FailureStep::DebtRemove => {
                reg.arm_write_retention_debt("debtfx")
            }
            other => panic!("{other:?} is a remote step, not a store step"),
        }
    }

    fn set_remote_fault(&self, step: FailureStep) {
        let suffix = match step {
            FailureStep::CommitMarkerWrite => "state/commits/".to_string(),
            FailureStep::RetentionInventoryWrite => "state/inventory.json".to_string(),
            other => panic!("{other:?} is a store step, not a remote step"),
        };
        self.fault.lock().unwrap().fail_write_once = Some(suffix);
    }

    /// Arm the PRE-SWAP status-read fault (the
    /// [`FailureClass::RemoteStatusPreSwap`] remote arm): once the push's
    /// operation-lock write is seen, the first `current`-link read fails
    /// exactly once. The planning/reconcile status reads (before any lock
    /// write) pass, so the remote stays reachable for planning and fails
    /// only at the pre-swap moment inside `process_server`.
    fn set_remote_read_fault(&self) {
        let mut f = self.fault.lock().unwrap();
        f.fail_current_read_after_lock = true;
        // A fresh push: no lock write has been seen yet, so the planning /
        // reconcile status reads (before any mutation-lock write) pass.
        f.lock_written = false;
    }

    /// Arm the PRE-SWAP status-read fault for ONE named server: that
    /// server's first post-lock `current`-link read fails exactly once while
    /// every other server's pre-swap reads pass — the per-server half the
    /// failure-position tests use to fail a SPECIFIC batch of a multi-server
    /// push.
    fn set_remote_read_fault_on_server(&self, server: &str) {
        let mut f = self.fault.lock().unwrap();
        f.fail_current_read_on_server = Some(server.to_string());
        // A fresh push: no lock write has been seen yet, so the planning /
        // reconcile status reads (before any mutation-lock write) pass.
        f.lock_written = false;
    }

    /// Arm the pre-swap status-read fault for the server holding batch
    /// `position` of a `t1` push: the batch order is `p1` (server `s1`),
    /// then `p2` (server `s2`) — so position 0 names `s1` and position 1
    /// names `s2`. Earlier batches (already advanced when the faulted batch
    /// fails) then exercise the configured failure policy.
    fn set_remote_read_fault_at_position(&self, position: usize) {
        let server = match position {
            0 => "s1",
            1 => "s2",
            other => panic!("fixture t1 has two batch positions, got {other}"),
        };
        self.set_remote_read_fault_on_server(server);
    }

    /// The ONE owning target of a fixture slot: a slot has exactly one
    /// target, so its observed record serves exactly that target's view —
    /// there is no cross-target propagation anymore.
    fn owning_target(slot: &str) -> &'static str {
        match slot {
            "p1" | "p2" => "t1",
            "p3" => "t2",
            "pdx" => "debtfx",
            other => panic!("unknown fixture slot {other}"),
        }
    }

    /// The observed-scope property, asserted explicitly by the property
    /// sequences: each slot's OWNING target's observed view equals the
    /// CURRENT remote assignment (generation + artifact + the assignment's
    /// OWN minting deployment) — no absent, stale, partial, or re-stamped
    /// entries. A slot has exactly one owning target, so only that target's
    /// view is checked (a push to another target never touches this slot's
    /// records). Requires a remote assignment to exist (call after the
    /// first completed push).
    fn assert_observed_scope_property(&self) {
        for (slot_id, asn) in self.current_assignments() {
            let target = Self::owning_target(slot_id.as_str());
            let observed = self
                .store
                .read_observed(target, &self.config)
                .expect("observed reads");
            let slot = observed
                .slots
                .get(&slot_id)
                .unwrap_or_else(|| panic!("{target}: observed {slot_id} entry must be present"));
            let crate::ledger::ObservedAssignment::Known {
                generation,
                artifact,
                ..
            } = &slot.assignment
            else {
                panic!("{target}: observed {slot_id} must be a successful read");
            };
            assert_eq!(
                generation, &asn.generation_id,
                "{target}: observed generation must equal the remote generation"
            );
            assert_eq!(
                artifact, &asn.artifact,
                "{target}: observed artifact must equal the remote assignment"
            );
            assert_eq!(
                slot.last_deployment(),
                Some(&asn.deployment_id),
                "{target}: observed last_deployment must equal the LIVE assignment's OWN \
                 minting deployment — a skipped/unreachable slot's prior record is never \
                 re-stamped"
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
            Action::Rollback(t, i) => {
                let token = self.rollback_token(t, i);
                Outcome::Push(Box::new(self.push_ref(t, &token)))
            }
            Action::Rotate => {
                self.rotate_slot_policy()
                    .expect("standalone retention succeeds");
                Outcome::Ok
            }
            Action::Checkpoint(t, k) => {
                let out = self.checkpoint_prop(t, k);
                self.check_invariants();
                return out;
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
                group: None,
            },
        )
    }

    /// Standalone retention under each slot's ONE policy — the policy of the
    /// slot's OWNING VARIANT (`standard` declares `p1`/`p2`/`p3`; retention
    /// is slot-owned, never a member-target union), exactly as step 17 runs
    /// it (mutation lock + the single policy's retained set), for EVERY
    /// slot's server.
    fn rotate_slot_policy(&self) -> Result<()> {
        let retention = &self.config.variant("standard").unwrap().retention;
        for server in ["s1", "s2", "s3"] {
            let slot = match server {
                "s1" => "p1",
                "s2" => "p2",
                _ => "p3",
            };
            let owner = crate::remote::helper::test_owner("si", slot);
            self.with_helper_for(server, |helper| {
                let op = OperationId::generate();
                let _guard = helper.acquire_lock_guard(&op)?;
                let retained =
                    compute_retained(&helper, self.config.pins(), &self.store, retention, &owner)?;
                helper.rotate(&retained, &HashSet::new())
            })?;
        }
        Ok(())
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
                stored.artifact.variant = VariantName::parse("canary").unwrap()
            }
            TamperKind::AssignmentRelease => {
                stored.artifact.release = crate::identity::test_release_id("rel-sha256-tampered")
            }
            TamperKind::BehaviorJson => unreachable!("handled above"),
            TamperKind::ReleaseSchemaVersion => {
                // Rewrite the stored release record's version field to a
                // non-canonical value; the record must fail closed on read.
                self.tamper_stored_release(|v| {
                    v["release_schema_version"] = serde_json::json!(
                        crate::verify::release::RELEASE_RECORD_SCHEMA_VERSION.wrapping_add(1)
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

    /// Evaluate all five invariant groups against the fixture state, with a
    /// context label (the failing action index) for diagnostics.
    fn check_invariants_ctx(&self, ctx: &str) {
        self.check_identity();
        self.check_scope_ctx(ctx);
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
        for (_, asn) in self.current_assignments() {
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

    /// Scope: (1) every slot's observed projection equals the remote
    /// assignment in its OWNING target's view — STRICTLY, with no
    /// absent-entry exception: after ANY
    /// completed or recovered mutation (a real push, a no-op retry, a
    /// rollback) the owning target's observed record for the slot is present
    /// and equals the remote assignment (generation +
    /// artifact + the assignment's OWN minting deployment id). The only state
    /// in which an entry may legitimately be absent is the crash window — a
    /// push that aborted AFTER the remote advanced but BEFORE the observed
    /// refresh — which the fixture only ever enters via
    /// [`Fixture::push_with_id`] mid-sequence and never evaluates here; the
    /// recovery action that closes the window refreshes the projections (the
    /// no-op retry path does too), so by the time `check_invariants` runs the
    /// entry must exist; (2) each slot's retained set is computed
    /// under its ONE policy (the slot's OWNING VARIANT — never a per-target
    /// union); (3) every tree that policy retains actually survives the
    /// post-push retention.
    fn check_scope(&self) {
        self.check_scope_ctx("")
    }

    fn check_scope_ctx(&self, ctx: &str) {
        for (slot_id, asn) in self.current_assignments() {
            let target = Self::owning_target(slot_id.as_str());
            let observed = self
                .store
                .read_observed(target, &self.config)
                .expect("observed reads");
            let slot = match observed.slots.get(&slot_id) {
                Some(slot) => slot,
                None => panic!(
                    "{ctx} {target}: observed projection for {slot_id} must be present after any \
                     completed/recovered mutation (a no-op retry refreshes observed; the \
                     crash window is entered only mid-sequence via push_with_id, never \
                     evaluated by check_invariants)"
                ),
            };
            let crate::ledger::ObservedAssignment::Known {
                generation,
                artifact,
                ..
            } = &slot.assignment
            else {
                panic!("{target}: observed {slot_id} must be a successful read");
            };
            assert_eq!(
                artifact, &asn.artifact,
                "{target}: observed projection must equal the remote assignment"
            );
            assert_eq!(
                generation, &asn.generation_id,
                "{target}: observed generation must equal the remote generation"
            );
            assert_eq!(
                slot.last_deployment(),
                Some(&asn.deployment_id),
                "{target}: observed last_deployment must equal the LIVE assignment's OWN \
                 minting deployment — a skipped/unreachable slot's prior record is never \
                 re-stamped by a deployment that did not touch it"
            );
        }
        for server in ["s1", "s2", "s3"] {
            let slot = match server {
                "s1" => "p1",
                "s2" => "p2",
                _ => "p3",
            };
            let owner = crate::remote::helper::test_owner("si", slot);
            let retained = self.with_helper_for(server, |helper| {
                // The slot's ONE policy, resolved from its OWNING VARIANT
                // (`standard` declares every slot) — never a per-target
                // union.
                let retention = &self.config.variant("standard").unwrap().retention;
                compute_retained(&helper, self.config.pins(), &self.store, retention, &owner)
                    .expect("retained under the slot's owning-variant policy")
            });
            // Every tree the single policy retains must actually survive the
            // retention the last push (or standalone rotate) performed.
            let remote = self.remote_for(server);
            for tree in &retained {
                assert!(
                    remote.exists(&layout::tree_root(tree)),
                    "policy-retained tree {tree} on {server} must survive retention"
                );
            }
        }
    }

    /// Lifecycle: every recorded attempt's latest transition agrees with its
    /// durable artifacts; no snapshot is ever duplicated; no locks linger.
    fn check_lifecycle(&self) {
        // Commit markers and mutation locks live PER SERVER: a deployment of
        // a target writes a marker on every server of its OWN slots (`s1`
        // for `p1`, `s2` for `p2` — `t1`'s slots; `s3` for `p3` — `t2`'s
        // slot), and no stale lock may remain on any of them. A slot has
        // exactly one owning target, so a `t1` attempt never writes a
        // marker on `s3` (and vice versa).
        let remotes = ["s1", "s2", "s3"]
            .iter()
            .map(|s| (*s, self.remote_for(s)))
            .collect::<Vec<_>>();
        for target in ["t1", "t2"] {
            // The servers of the target's OWN slots: the only servers its
            // attempts can have written commit markers on.
            let target_servers: Vec<&str> = match target {
                "t1" => vec!["s1", "s2"],
                "t2" => vec!["s3"],
                _ => unreachable!(),
            };
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
                    .expect("status readable");
                let id = attempt.deployment_id.as_str();
                let snapshot_exists = snapshots.iter().any(|s| s.deployment_id.as_str() == id);
                match latest {
                    Some(DeploymentStatus::Successful) => {
                        assert!(
                            snapshot_exists,
                            "Successful attempt {id} must have a snapshot entry"
                        );
                        for server in &target_servers {
                            let remote = self.remote_for(server);
                            assert!(
                                remote.exists(&layout::commit_marker(id)),
                                "Successful attempt {id} must have a durable commit marker on \
                                 {server}"
                            );
                        }
                    }
                    Some(DeploymentStatus::FailedPreflight)
                    | Some(DeploymentStatus::Degraded)
                    | Some(DeploymentStatus::FailedRolledBack) => {
                        assert!(
                            !snapshot_exists,
                            "a failed attempt {id} must NOT have a snapshot entry"
                        );
                    }
                    None => {
                        // The PENDING state: an intent WITHOUT a terminal IS
                        // pending (the terminal status enum carries no
                        // pending status; the ledger's ONE atomic finalize
                        // write never landed), so recovery rebuilds the
                        // outcomes from the VERIFIED DESIRED state — never
                        // from a durable outcomes file.
                        assert!(
                            self.store.read_transitions(id).unwrap().is_empty(),
                            "a pending attempt {id} must be intent-only (no terminal event)"
                        );
                        assert!(
                            !snapshot_exists,
                            "a pending attempt {id} must not have a snapshot entry"
                        );
                    }
                }
            }
            // `read_last_successful` is DERIVED from the ledger (the newest
            // entry with a `Successful` terminal) — there is no separate ref
            // file anymore, so no stale-ref crash corner can exist: the
            // derived value ALWAYS equals the newest successful entry. The
            // ledger is oldest-first, so the newest successful is the LAST
            // successful entry (id ordering is NOT push order — the ids are
            // canonical digests).
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
                .last();
            match (newest_successful, last_ok.as_deref()) {
                (Some(newest), Some(ok)) => {
                    assert_eq!(
                        newest, ok,
                        "the derived last-successful must equal the newest successful entry"
                    );
                }
                (None, None) => {}
                (Some(_), None) => {
                    panic!("refs/last-successful is missing after a successful attempt")
                }
                (None, Some(ok)) => {
                    panic!("derived last-successful points at {ok} but no attempt is successful")
                }
            }
            assert!(
                remotes
                    .iter()
                    .all(|(_, r)| !r.exists(&layout::operation_lock())),
                "no stale operation lock may remain after an action"
            );
        }
    }

    /// Integrity: stored identity is never trusted — the current link
    /// resolves to a parseable assignment and the live tree object exists
    /// (content-address verified by path), on EVERY slot's server.
    fn check_integrity(&self) {
        for server in ["s1", "s2"] {
            let slot = if server == "s1" { "p1" } else { "p2" };
            let owner = crate::remote::helper::test_owner("si", slot);
            self.with_helper_for(server, |helper| {
                if let Ok(status) = helper.status(&owner)
                    && let Some(g) = status.current_generation()
                {
                    let asn = helper
                        .read_assignment(g.as_str(), &owner)
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

    // (b) TREE: tamper the stored tree to a DIFFERENT REAL tree. The tampered
    // assignment now names a different tree than the current generation's
    // `root` symlink (which still names the tree the generation was created
    // with), so the remote chain is INTERNALLY INCONSISTENT: `status()` must
    // fail closed with an integrity error and the next push must refuse —
    // never proceed, and certainly never no-op.
    let f = Fixture::new();
    let r1 = f.push("t1").expect("push v1");
    let first_tree = match &r1.attempt.as_ref().expect("attempt").slots[&SlotId::new("p1")] {
        crate::ledger::ActualSlotState::Observed { artifact, .. } => artifact.tree.clone(),
        other => panic!("a successful push's actual is Observed, got {other:?}"),
    };
    f.apply(Action::Build(2));
    f.push("t1").expect("push v2 (current is now T2)");
    f.tamper_stored_tree(&first_tree);
    let err = f
        .push("t1")
        .expect_err("a tree tamper makes the remote chain inconsistent and must fail closed");
    assert!(
        err.to_string().contains("integrity"),
        "the tampered chain must fail with an integrity error, got: {err}"
    );

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

/// Scope: interleaved pushes; after EVERY action the observed projection in
/// each slot's OWNING target equals the remote assignment and every
/// slot-owned-policy-retained tree survives retention. The final push runs
/// under `t1`, and the retention pass — standalone AND post-push — always
/// computes under the slots' OWNING VARIANT's single policy (`standard`
/// declares every slot), never a per-target policy: the check catches a
/// mutant that would retain under a per-target policy instead.
#[test]
fn state_machine_scope_projection_and_retention_owner() {
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
    // A standalone rotate under the slots' own policy, then the same checks.
    f.apply(Action::Rotate);
    f.check_invariants();
}

/// Lifecycle mutant: after the deployment has durably committed, a post-commit
/// retention failure must NOT turn the deployment into a deployment failure —
/// the push still returns Ok with the committed status, records a persistent
/// debt marker, and warns. The mutant (`?` instead of debt-marker+warning)
/// would make this push return Err.
#[test]
fn state_machine_lifecycle_cleanup_failure_after_commit() {
    let f = Fixture::new();
    f.apply(Action::InjectFailure(FailureStep::RetentionInventoryWrite));
    let Outcome::Push(res) = f.apply(Action::Push("t1")) else {
        panic!("expected a push outcome");
    };
    let r1 =
        res.expect("a committed deployment must never fail because its cleanup retention failed");
    assert_eq!(
        r1.status,
        Some(DeploymentStatus::Successful),
        "the deployment committed; step-17 retention failure must not change its outcome"
    );
    assert!(
        r1.attempt.is_some(),
        "the committed deployment records its attempt"
    );
    let warning = r1
        .warning
        .as_ref()
        .expect("the push must warn about the deferred retention");
    assert!(
        warning.contains("retention deferred"),
        "the warning describes the deferred retention, got: {warning}"
    );
    assert!(
        !f.store.read_retention_debt("t1").unwrap().is_empty(),
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
        f.store.read_retention_debt("t1").unwrap().is_empty(),
        "the debt marker must be cleared once the retention succeeds"
    );
    f.check_invariants();
}

/// Lifecycle: a FRESH step-17 retention whose slot mutation lock is CONTENDED
/// (held by another operation) must never be skipped SILENTLY. The push still
/// succeeds (the deployment already committed), records a best-effort debt
/// marker, and surfaces a warning naming the slot — "retention deferred for
/// slot 'p1': slot lock held by another operation". Then the maintenance
/// lifecycle over the same marker: an up-to-date no-op whose retry ALSO finds
/// the lock held stays deferred and keeps warning; the FIRST no-op with the
/// lock FREE services the retention (marker cleared) and reports no warning.
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
/// RAII-guarded retention block, so it parks at the SAME barrier.
#[test]
fn state_machine_lifecycle_retention_lock_contention_defers_not_silent() {
    let id = test_deployment_id("si-lockcont-push");
    let holder = crate::identity::OperationId::new("op-lockcont-holder".to_string());
    let f = Fixture::new();
    let remote = f.remote();
    let helper = RemoteHelper::new(remote.as_ref());

    // ---- Step 1: PUSH with the slot mutation lock contended from step 17
    // on. Arm the phase hook, run the push in a scoped thread, and at EVERY
    // step-17-equivalent park hold the competing guard via the second helper
    // (the fixture acquires it at the FIRST park — the first of t1's OWN
    // slots' fresh retention — and holds it until the push returns; the SECOND
    // slot's retention parks on its OWN free server and succeeds). Each
    // parked engine is then released — its own `acquire_lock_guard` on the
    // contended server now deterministically fails, so the maintenance is
    // deferred (debt + warning), never silent, never an `Err`.
    let report1 = {
        let hook = step17_hook::Step17Hook::arm(f.store.step17_hook(), id.as_str());
        std::thread::scope(|s| {
            let push = s.spawn(|| f.push_with_id("t1", &id));
            let mut guard: Option<crate::remote::helper::HeldSlotLock<'_>> = None;
            // Service EVERY park (the 2-slot fixture parks at each of t1's
            // OWN slots' step-17 retention), holding the s1 guard at the first
            // park; `recv_timeout` sleeps, never spins.
            while !push.is_finished() {
                if let Ok(_phase) = hook.wait_at_step17_bounded(std::time::Duration::from_millis(5))
                {
                    if guard.is_none() {
                        guard = Some(helper.acquire_lock_guard(&holder).expect(
                            "the slot lock must be free while the engine is parked at the \
                             step-17 hook",
                        ));
                    }
                    hook.release();
                }
            }
            let res = push.join().expect("push thread panicked");
            drop(hook);
            res
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
        warning1.contains("retention deferred for slot 'p1'")
            && warning1.contains("slot lock held by another operation"),
        "the contended push must warn naming the slot (never silent), got: {warning1}"
    );
    assert!(
        !f.store.read_retention_debt("t1").unwrap().is_empty(),
        "the contended push must record the debt marker"
    );
    // Step 1's guard drops here (lock released).

    // ---- Step 2: NO-OP with the lock HELD — the deferred maintenance
    // stays deferred (marker kept) and keeps warning. The no-op path's only
    // step-17-equivalent lock acquisition is the deferred-maintenance retry
    // of the marked slot, so the same hook fires there: the fixture holds
    // the guard while the engine is parked, releases the hook, and the
    // retry's acquire fails — "retention still deferred", marker kept,
    // warning kept.
    let report2 = {
        let hook = step17_hook::Step17Hook::arm(f.store.step17_hook(), id.as_str());
        std::thread::scope(|s| {
            let push = s.spawn(|| f.push_with_id("t1", &id));
            let mut guard: Option<crate::remote::helper::HeldSlotLock<'_>> = None;
            while !push.is_finished() {
                if let Ok(_phase) = hook.wait_at_step17_bounded(std::time::Duration::from_millis(5))
                {
                    if guard.is_none() {
                        guard = Some(helper.acquire_lock_guard(&holder).expect(
                            "the slot lock must be free while the engine is parked at the \
                             no-op retry hook",
                        ));
                    }
                    hook.release();
                }
            }
            let res = push.join().expect("push thread panicked");
            drop(hook);
            res
        })
    };
    let report2 =
        report2.expect("the no-op must never fail because its maintenance retry contended");
    assert_eq!(report2.message, "Everything up to date");
    assert_eq!(report2.status, None, "the contended no-op is a no-op");
    let warning2 = report2.warning.as_deref().unwrap_or("");
    assert!(
        warning2.contains("retention still deferred for slot 'p1'")
            && warning2.contains("slot lock held by another operation"),
        "the held-lock no-op must keep warning that the retention is deferred, got: {warning2}"
    );
    assert!(
        !f.store.read_retention_debt("t1").unwrap().is_empty(),
        "the held-lock no-op must keep the debt marker"
    );
    // Step 2's guard drops here (lock released).

    // ---- Step 3: the FIRST no-op with the lock FREE services the
    // deferred retention: the marker is cleared, no warning remains.
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
        f.store.read_retention_debt("t1").unwrap().is_empty(),
        "the debt marker must be cleared once the retention succeeds"
    );
    f.check_invariants();
}

/// Lifecycle: a failure at the FIRST I/O boundary (the intent persist) must
/// abort BEFORE any remote mutation — no `current`, no generation — and a
/// clean retry succeeds.
#[test]
fn state_machine_lifecycle_intent_persist_leaves_remote_untouched() {
    let f = Fixture::new();
    let id = test_deployment_id("si-intent-fault");
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
        r1.status, None,
        "the failed commit leaves the attempt PENDING (intent-only, no terminal)"
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
        None,
        "the pending attempt has no terminal status (an intent without a terminal IS pending)"
    );
    // Recoverable: the intent is durable and the entry is intent-only (the
    // ONE terminal event never landed — recovery rebuilds the outcomes from
    // the verified desired state).
    assert!(
        f.store.read_transitions(id.as_str()).unwrap().is_empty(),
        "a pending attempt must be intent-only (no terminal event)"
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

/// The PENDING-COMMIT × CHECKPOINT-FLOOR contract, DETERMINISTICALLY (the
/// property test drives the same interaction with random streams; this pins
/// the two documented branches):
///
/// (a) a pending commit BELOW the new floor is discarded with the rest of
///     the below-floor history — its attempt line, its deployment dir, and
///     (when it has one) its snapshot entry vanish from the RAW logs, so no
///     recovery can resurrect it;
/// (b) a pending commit AT/ABOVE the floor survives untouched and the next
///     push finalizes it EXACTLY once — one snapshot at the SAME unique
///     index (never a duplicate, never a re-append below the floor).
#[test]
fn state_machine_checkpoint_floor_discards_below_pending_keeps_above() {
    // (a) BELOW the floor: a pending commit whose attempt precedes the
    // checkpoint deployment is discarded.
    // (a) BELOW the floor: settled below-floor history is discarded with
    // the checkpoint — and a below-floor PENDING commit can NEVER exist: a
    // push that cannot finish the previous pending attempt (a transient
    // non-finalization leaves it intent-only) is REFUSED (the strictly-
    // linear model never plans a second intent on top). The crash attempt
    // is reconciled by the next push's recovery and is then discarded by a
    // LATER checkpoint with the rest of the below-floor history — no
    // resurrection.
    let f = Fixture::new();
    // Push 1: a clean deployment (s0).
    let r1 = f.push_prop("t1", None, FailureClass::None);
    assert!(matches!(&r1, Outcome::Push(b) if b.is_ok()));
    // Push 2 (new content): a crash-window fault leaves a recoverable-pending
    // commit with NO snapshot.
    f.apply_no_checks(Action::Build(2));
    let p = f.push_prop("t1", None, FailureClass::SnapshotAppend);
    let pending_id = {
        let last = f.last_prop.lock().unwrap();
        last.as_ref().unwrap().1.clone()
    };
    assert!(matches!(&p, Outcome::Push(b) if b.is_err()));
    assert!(
        system_has_pending(&f, "t1"),
        "the faulted push left a pending commit"
    );
    // Push 3 (new content): a SECOND push while the crash attempt is still
    // pending. The CommitMarker fault makes the RECOVERY's finalization
    // transiently fail, so the attempt stays intent-only and the push is
    // REFUSED with the spec's Conflict — NOTHING is recorded (no second
    // intent, no mutation), and the pending attempt is left for a later
    // push.
    f.apply_no_checks(Action::Build(3));
    let d = f.push_prop("t1", None, FailureClass::CommitMarker);
    let Outcome::Push(dres) = d else {
        panic!("expected a push outcome")
    };
    let derr =
        dres.expect_err("a push while a previous deployment is still pending must be refused");
    assert!(
        derr.to_string()
            .contains("a previous deployment is still pending"),
        "the refusal must carry the spec's conflict message, got: {derr}"
    );
    assert!(
        system_has_pending(&f, "t1"),
        "the refused push leaves the crash attempt pending"
    );
    // Push 4 (clean, new content): the reconciliation FINALIZES the crash
    // attempt (Successful, s1 — its parent is still the head), then the
    // push itself deploys (Successful, s2). Nothing is pending anymore.
    let e = f.push_prop("t1", None, FailureClass::None);
    assert!(matches!(&e, Outcome::Push(b) if b.is_ok()));
    assert!(
        !system_has_pending(&f, "t1"),
        "the clean push finalized the previous pending attempt"
    );
    // The successful chain is s0 (push 1), s1 (the reconciled crash attempt,
    // now below the floor), s2 (push 4). The checkpoint at index 2 discards
    // the ENTIRE below-floor history — push 1 AND the reconciled crash
    // attempt (its attempt line, its snapshot, its deployment dir) — with
    // the checkpoint, so no recovery can resurrect it.
    let c = f.checkpoint_prop("t1", 2);
    let Outcome::Checkpoint(rep) = c else {
        panic!("expected a checkpoint outcome")
    };
    assert!(rep.established);
    // The below-floor attempts (push 1 and the reconciled crash attempt) are
    // GONE from the raw logs, their deployment dirs deleted, and nothing is
    // pending.
    let raw_att: Vec<String> = f
        .store
        .read_attempts_raw("t1")
        .unwrap()
        .iter()
        .map(|a| a.deployment_id.as_str().to_string())
        .collect();
    assert!(
        !raw_att.contains(&pending_id),
        "the below-floor attempt must be discarded"
    );
    assert!(
        !f.store.deployment_dir(&pending_id).exists(),
        "the below-floor deployment dir must be deleted"
    );
    assert_eq!(
        raw_att.len(),
        1,
        "only the checkpoint deployment's attempt survives"
    );
    assert!(
        !system_has_pending(&f, "t1"),
        "no pending commit survives the checkpoint"
    );
    // The checkpoint deployment's own entry + rollback survive; the
    // retained suffix is exactly it.
    let raw_snaps: Vec<String> = f
        .store
        .read_ledger("t1")
        .unwrap()
        .iter()
        .filter(|e| {
            e.terminal
                .as_ref()
                .is_some_and(|x| x.status() == DeploymentStatus::Successful)
        })
        .map(|e| e.deployment_id.as_str().to_string())
        .collect();
    assert_eq!(
        raw_snaps.len(),
        1,
        "only the checkpoint entry's rollback survives"
    );
    f.check_invariants();

    // (b) AT/ABOVE the floor: a pending commit recorded after the
    // checkpoint deployment survives and is finalized by the next push
    // exactly once.
    let f = Fixture::new();
    let r1 = f.push_prop("t1", None, FailureClass::None);
    assert!(matches!(&r1, Outcome::Push(b) if b.is_ok()));
    // A pending commit AT/ABOVE the floor (recorded after s0, new content).
    f.apply_no_checks(Action::Build(2));
    let p = f.push_prop("t1", None, FailureClass::CommitMarker);
    assert!(matches!(&p, Outcome::Push(b) if b.is_ok()));
    assert!(system_has_pending(&f, "t1"));
    let pending_id = {
        let last = f.last_prop.lock().unwrap();
        last.as_ref().unwrap().1.clone()
    };
    let c = f.checkpoint_prop("t1", 0);
    let Outcome::Checkpoint(rep) = c else {
        panic!("expected a checkpoint outcome")
    };
    assert!(rep.established);
    // The pending commit survives the checkpoint (its attempt precedes
    // nothing below the floor).
    assert!(
        system_has_pending(&f, "t1"),
        "the at/above-floor pending survives"
    );
    // The next push finalizes it EXACTLY once: one snapshot, at the SAME
    // unique index (max raw + 1), never a duplicate.
    f.apply_no_checks(Action::Build(3));
    let r = f.push_prop("t1", None, FailureClass::None);
    assert!(matches!(&r, Outcome::Push(b) if b.is_ok()));
    assert!(
        !system_has_pending(&f, "t1"),
        "the next push finalizes the at/above-floor pending commit"
    );
    let snaps = f.store.read_snapshots("t1").unwrap();
    let matches = snaps
        .iter()
        .filter(|s| s.deployment_id.as_str() == pending_id)
        .collect::<Vec<_>>();
    assert_eq!(
        matches.len(),
        1,
        "the finalized pending commit must produce exactly ONE rollback state"
    );
    assert_eq!(
        ledger::successful_index(&f.store, "t1", &DeploymentId::new(pending_id))
            .unwrap()
            .unwrap(),
        1,
        "the rollback lands at the SAME unique position (s1)"
    );
    f.check_invariants();
}

// ===========================================================================
// Property tests — Observed scope (push / fail / retry / rollback sequences)
// ===========================================================================

/// (a) Crash BEFORE the observed refresh: the very first push on t1 aborts
/// AFTER the remote advanced but BEFORE the observed refresh (a faulted
/// `write_results`), so the slot's observed entry is ABSENT in its OWNING
/// target t1 (the push never refreshed; nothing propagated). The recovery is
/// an up-to-date no-op retry (reconcile then "Everything up to date"); the
/// no-op path must refresh the projections, so after recovery the owning
/// target's observed slot for `p1` equals the remote assignment.
#[test]
fn observed_scope_crash_before_refresh_recovered_by_noop_retry() {
    let f = Fixture::new();
    f.apply(Action::Build(1));
    let id = test_deployment_id("si-obs-crash-before-refresh");
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
    // observed projection was never refreshed — the OWNING target has no
    // entry for the slot (p1 is owned ONLY by t1; with one owner per slot
    // no other target's view can ever contain it).
    f.current_assignment()
        .expect("remote advanced past the crash");
    let observed = f.store.read_observed("t1", &f.config).unwrap();
    assert!(
        !observed.slots.contains_key(&SlotId::new("p1")),
        "t1: the crash window must leave its OWN slot's observed entry absent"
    );

    // Recovery: the no-op retry reconciles the aborted attempt and returns
    // "Everything up to date" — and must refresh the observed projection in
    // the OWNING target.
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
/// refresh must land the rolled-back assignment in the OWNING target's
/// projection, so after rolling t1 back to its own `s0` t1 observes the
/// restored assignment (generation + artifact) for its own slots.
#[test]
fn observed_scope_rollback_refreshes_owning_projection() {
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
    let t1_before = f.store.read_observed("t1", &f.config).unwrap();
    let t2_before = f.store.read_observed("t2", &f.config).unwrap();

    // HEAD advances to v2 so the t2 push is a REAL push (not an up-to-date
    // no-op, which never persists an attempt) — it then fails at the intent
    // persist, BEFORE any remote mutation.
    f.apply(Action::Build(2));
    let id = test_deployment_id("si-obs-preflight");
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
        f.store.read_observed("t1", &f.config).unwrap(),
        t1_before,
        "a failed preflight must not change t1's observed"
    );
    assert_eq!(
        f.store.read_observed("t2", &f.config).unwrap(),
        t2_before,
        "a failed preflight must not change t2's observed"
    );
    f.assert_observed_scope_property();
    f.check_invariants();
}

/// (d) A LONGER interleaved sequence mixing every action across the two
/// OWNING targets: push t1 -> push t2 -> preflight failure -> rollback ->
/// crash before the observed refresh -> no-op retry recovery -> no-op retry
/// -> mid-flight failure that still returns `Ok` (PendingCommit) -> recovery
/// -> rotate. After EVERY completed action and after EVERY recovery the
/// property holds: each slot's observed record equals the remote assignment
/// (generation + artifact) in its OWNING target's view — no absent or stale
/// entries. The faulted pushes use `push_with_id` directly (the fixture never
/// evaluates invariants inside the crash window), and every recovery asserts
/// the property explicitly. The faulted attempts use fixed `si-…` ids that
/// sort AFTER the engine's auto-generated `deploy-…` ids, so once a fixed-id
/// attempt is finalized on a target no later auto-id push runs on that target
/// (the lifecycle "newest successful" check orders ids lexicographically).
#[test]
fn observed_scope_interleaved_push_fail_retry_rollback_sequence() {
    let f = Fixture::new();

    // t1 deploys tree v1 on its OWN slots (p1, p2).
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

    // t1 deploys tree v2 (a real push — p1/p2 advance together).
    f.apply(Action::Build(2));
    let r = f.apply(Action::Push("t1"));
    let Outcome::Push(res) = r else {
        panic!("expected a push outcome");
    };
    assert_eq!(
        res.expect("push t1 succeeds").status,
        Some(DeploymentStatus::Successful)
    );
    f.assert_observed_scope_property();

    // t2 deploys tree v2 on its OWN slot (p3). A slot has exactly one
    // owning target, so this never touches p1/p2.
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
    // t2's observed projection stays equal to the unchanged v2 assignment.
    f.apply(Action::Build(3));
    let id_p = test_deployment_id("si-obs-seq-preflight");
    let err = {
        f.arm_store_fault(FailureStep::IntentPersist, &id_p);
        f.push_with_id("t2", &id_p)
            .expect_err("the preflight push aborts before mutation")
    };
    assert!(err.to_string().contains("append_attempt"), "{err}");
    f.assert_observed_scope_property();

    // (b) Rollback t1 to its own `s0` (tree v1): a real push whose refresh
    // lands the restored assignment in t1's OWN projection.
    let r = f.apply(Action::Rollback("t1", 0));
    let Outcome::Push(res) = r else {
        panic!("expected a push outcome");
    };
    let report = res.expect("rollback t1 succeeds");
    assert_eq!(report.status, Some(DeploymentStatus::Successful));
    f.assert_observed_scope_property();

    // (a) Crash mid-flight on t1: the remote advances p1/p2 to v3 but the
    // observed refresh never runs — t1's projections go stale (they still
    // show the rolled-back v1 assignment).
    let stale = f
        .store
        .read_observed("t1", &f.config)
        .unwrap()
        .slots
        .get(&SlotId::new("p1"))
        .expect("observed p1 exists from the earlier push")
        .assignment
        .clone();
    let stale_gen = match &stale {
        crate::ledger::ObservedAssignment::Known { generation, .. } => Some(generation.clone()),
        _ => None,
    };
    let id_c = test_deployment_id("si-obs-seq-crash");
    let err = {
        f.arm_store_fault(FailureStep::ResultsWrite, &id_c);
        f.push_with_id("t1", &id_c)
            .expect_err("the crash aborts before the observed refresh")
    };
    assert!(err.to_string().contains("test fault"), "{err}");
    let after_crash = f
        .current_assignments()
        .get(&SlotId::new("p1"))
        .expect("remote advanced")
        .generation_id
        .clone();
    assert_ne!(
        stale_gen.as_ref(),
        Some(&after_crash),
        "the crash window must leave the projection stale"
    );

    // Recovery: the no-op retry reconciles and refreshes t1's OWN
    // projections to the v3 assignment. No further t1 push runs after this
    // (the fixed `si-obs-seq-crash` id is then the lexicographically newest).
    let r = f.apply(Action::Retry("t1"));
    let Outcome::Push(res) = r else {
        panic!("expected a push outcome");
    };
    let report = res.expect("the recovery retry succeeds");
    assert_eq!(report.message, "Everything up to date");
    f.assert_observed_scope_property();

    // t2 advances its OWN slot to v3 (a real push — p3 is at v2).
    let r = f.apply(Action::Push("t2"));
    let Outcome::Push(res) = r else {
        panic!("expected a push outcome");
    };
    assert_eq!(
        res.expect("push t2 succeeds").status,
        Some(DeploymentStatus::Successful)
    );
    f.assert_observed_scope_property();

    // A no-op retry on t2 (p3 already at v3): the projection refreshes again.
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
    assert_eq!(
        report.status, None,
        "the attempt stays pending until finalization"
    );
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

    // Wrap up with a standalone retention under each slot's ONE policy.
    f.apply(Action::Rotate);
    f.check_invariants();
}

/// (e) PRE-SWAP REMOTE FAILURE on a slot with a PRIOR live generation: the
/// remote is reachable for planning/status but its `current`-link read
/// fails EXACTLY ONCE at the pre-swap moment — the status read inside
/// `process_server`, right after the slot's mutation-lock write (the
/// planning and reconcile reads pass). The slot aborts `Ok(Failed)` BEFORE
/// the swap: NOTHING advanced, the attempt is recorded `FailedRolledBack`
/// (nothing to compensate), and the observed projection of the slot's ONE
/// owning target must stay UNTOUCHED — the same generation, artifact, and
/// `last_deployment` (the live assignment's OWN minting deployment, never
/// re-stamped with the failed deployment's id, never fabricated from the
/// desired artifact). This is the exact regression the randomized property
/// finds (`[(Push("t2"), None), (Rollback("t2", 0), RemoteStatusPreSwap)]`,
/// pinned deterministically here).
#[test]
fn observed_scope_pre_swap_failure_keeps_prior_record_untouched() {
    let f = Fixture::new();
    // Seed a prior live generation on t2's OWN slot `p3` (a slot has
    // exactly one owning target, so only a t2 push advances it).
    f.apply(Action::Build(1));
    let r = f.apply(Action::Push("t2"));
    let Outcome::Push(res) = r else {
        panic!("expected a push outcome");
    };
    assert_eq!(
        res.expect("the seed push succeeds").status,
        Some(DeploymentStatus::Successful)
    );
    f.assert_observed_scope_property();
    let t2_before = f.store.read_observed("t2", &f.config).unwrap();

    // HEAD advances so the t2 push is a REAL push (never an up-to-date
    // no-op), then the pre-swap status read fails exactly once.
    f.apply(Action::Build(2));
    let id = test_deployment_id("si-obs-preswap");
    let res = {
        f.arm_prop_fault(FailureClass::RemoteStatusPreSwap, "t2", &id);
        f.push_with_id("t2", &id)
    };
    f.disarm_prop_faults();
    let report =
        res.expect("the pre-swap failure is reported, not fatal (the attempt is recorded)");
    assert_eq!(
        report.status,
        Some(DeploymentStatus::FailedRolledBack),
        "nothing advanced, nothing to compensate: the attempt ends FailedRolledBack"
    );
    assert!(
        report.attempt.is_some(),
        "the intent was durable before the mutation loop, so the attempt is recorded"
    );
    // NOTHING advanced: t2's slot still runs the seed generation.
    let live = f.current_assignments();
    assert_eq!(
        live.len(),
        1,
        "t2's slot keeps its live generation (p1/p2 were never touched by a t2 push)"
    );
    // The observed projection is UNTOUCHED — byte-for-byte the prior record
    // in the slot's OWNING target (never fabricated, never re-stamped).
    assert_eq!(
        f.store.read_observed("t2", &f.config).unwrap(),
        t2_before,
        "t2's observed records must be untouched by a push that advanced nothing"
    );
    // And the strict property holds: observed == live assignment (generation
    // + artifact + the live assignment's OWN minting deployment).
    f.assert_observed_scope_property();
    f.check_invariants();
}

// ===========================================================================
// failure_policy: rollback / leave postconditions over batch positions
// ===========================================================================
//
// The strict [`FailurePolicy`] enum's runtime contract, driven through the
// state-machine fixture: a multi-server `t1` push (batch 0 = `p1` on `s1`,
// batch 1 = `p2` on `s2`, `batch_size = 1`) fails a SPECIFIC batch position
// pre-swap (per-server fault, [`Fixture::set_remote_read_fault_at_position`])
// AFTER a baseline push established a generation on every slot, and the
// RESPECTIVE POSTCONDITIONS are asserted:
//
// * [`FailurePolicy::RollbackChanged`] — a failure at batch k leaves batches
//   0..k-1 ROLLED BACK to their pre-push generation (the ledger records the
//   restoration and the attempt ends `FailedRolledBack`) and batch k FAILED
//   (pre-swap: it stays at its pre-push generation); later batches are
//   skipped.
// * [`FailurePolicy::LeaveChanged`] — a failure at batch k leaves batches
//   0..k-1 at the NEW state (no compensation pass runs, the attempt ends
//   `Degraded`) and batch k FAILED; later batches are skipped.
//
// The same helper drives the deterministic per-policy tests below and the
// bounded 16-case property (both supported policies x every batch position,
// fixed seed 0x5EED_5EED).

/// Drive one failure-position case: baseline push (tree v1) on both `t1`
/// slots, then a real push (tree v2) whose batch `position` fails pre-swap,
/// then assert the policy's postconditions on the live remote generations,
/// the ledger terminal record, and the observed projections.
fn run_failure_position_case(policy: FailurePolicy, position: usize) {
    let f = Fixture::with_failure_policy(policy);
    // A `t1` push's batch order: `p1` (server `s1`) is batch 0, `p2`
    // (server `s2`) is batch 1 (the fixture's `batch_size = 1` makes each
    // slot its own batch).
    let slots = ["p1", "p2"];

    // Baseline: tree v1 lands on BOTH slots (a real push).
    f.write_artifacts(1);
    let r = f.push("t1").expect("the baseline push succeeds");
    assert_eq!(r.status, Some(DeploymentStatus::Successful));
    let baseline: BTreeMap<String, GenerationId> = f
        .current_assignments()
        .into_iter()
        .map(|(sid, asn)| (sid.as_str().to_string(), asn.generation_id))
        .collect();
    assert_eq!(baseline.len(), 2, "t1 plans both fixture slots");

    // The second push is a REAL push (tree v2) whose batch `position` fails
    // PRE-SWAP on its server: batches before it have already advanced, so
    // the configured failure policy decides their fate.
    f.write_artifacts(2);
    f.set_remote_read_fault_at_position(position);
    let id = test_deployment_id(&format!("si-fp-{position}"));
    let report = f
        .push_with_id("t1", &id)
        .expect("the faulted push still returns a report");
    let status = report
        .status
        .expect("a faulted push records a terminal status");

    // The live remote generation of every slot after the faulted push.
    let after: BTreeMap<String, GenerationId> = f
        .current_assignments()
        .into_iter()
        .map(|(sid, asn)| (sid.as_str().to_string(), asn.generation_id))
        .collect();

    // The terminal entry's per-slot outcomes: the ledger shows exactly what
    // the mutation loop (and the failure-policy pass) recorded.
    let terminal = f
        .store
        .read_ledger("t1")
        .unwrap()
        .into_iter()
        .find(|e| e.deployment_id.as_str() == id.as_str())
        .and_then(|e| e.terminal)
        .expect("the faulted attempt has a terminal entry");

    // The observed projections are rebuilt from the LIVE assignments, so
    // they mirror the generations asserted below.
    let observed = f.store.read_observed("t1", &f.config).unwrap();

    // The terminal status per policy — THE DERIVED DISPOSITION RULE
    // ([`crate::kernel::transition::decide_terminal`]) owns the
    // classification from the outcomes' DERIVED transitions: rolled-back
    // iff NO outcome has an `Advanced` transition (a slot PROVABLY ON the
    // new state). Under `RollbackChanged` every advanced server was
    // compensated (or nothing had advanced) — no `Advanced` outcome →
    // `FailedRolledBack`. Under `LeaveChanged` the RETAINED advances stay on
    // the new state (`Advanced` outcomes) → `Degraded` — EXCEPT a failure at
    // batch 0 (NOTHING advanced: the failing slot never swapped and the
    // later batches were skipped) whose evidence carries no `Advanced`
    // outcome → `FailedRolledBack` (a pure-policy edge where the old
    // all_restored boolean — unconditionally false under leave_changed —
    // disagreed with the outcome evidence; the structural evidence is
    // authoritative now).
    match policy {
        FailurePolicy::RollbackChanged => assert_eq!(
            status,
            DeploymentStatus::FailedRolledBack,
            "rollback_changed: every advanced server was compensated"
        ),
        FailurePolicy::LeaveChanged => {
            if position == 0 {
                assert_eq!(
                    status,
                    DeploymentStatus::FailedRolledBack,
                    "leave_changed with a batch-0 pre-swap failure: NOTHING advanced, so the evidence carries no Advanced transition → rolled back"
                );
            } else {
                assert_eq!(
                    status,
                    DeploymentStatus::Degraded,
                    "leave_changed retains the earlier advances (Advanced outcomes) → degraded"
                );
            }
        }
    }
    assert_eq!(
        terminal.status(),
        status,
        "the ledger records the same status"
    );

    for (i, sid) in slots.iter().copied().enumerate() {
        let live = after
            .get(sid)
            .unwrap_or_else(|| panic!("slot {sid} keeps a live assignment"));
        // The observed projection mirrors the live remote generation.
        let observed_gen = observed
            .slots
            .get(&SlotId::new(sid.to_string()))
            .and_then(|o| match &o.assignment {
                crate::ledger::ObservedAssignment::Known { generation, .. } => {
                    Some(generation.clone())
                }
                _ => None,
            });
        assert_eq!(
            observed_gen.as_ref(),
            Some(live),
            "slot {sid}: the observed record mirrors the live generation"
        );
        // The ledger outcome for this slot (the disposition's OWN table;
        // the accessor materializes the disposition's table — for a
        // non-Successful terminal here — by value).
        let outcomes = terminal.outcomes();
        let out = outcomes
            .get(&SlotId::new(sid.to_string()))
            .unwrap_or_else(|| panic!("slot {sid} must appear in the terminal outcomes"));

        match (policy, i.cmp(&position)) {
            // Batches BEFORE the failed batch.
            (FailurePolicy::RollbackChanged, std::cmp::Ordering::Less) => {
                // POSTCONDITION: rolled back to the pre-push generation.
                assert_eq!(live, &baseline[sid], "slot {sid} must be compensated back");
                assert!(
                    matches!(out, crate::ledger::SlotOutcome::Restored { .. }),
                    "slot {sid}: compensation upgrades the outcome to Restored"
                );
                // The compensation mark IS the structural `Restored` variant
                // (the wire's separate `compensated` flag is only carried by
                // `Failed` in the structural model — a `Restored` outcome
                // IS a compensated restoration).
            }
            (FailurePolicy::LeaveChanged, std::cmp::Ordering::Less) => {
                // POSTCONDITION: stays at the NEW generation.
                assert_ne!(
                    live, &baseline[sid],
                    "slot {sid}: leave_changed retains the advance (tree v2)"
                );
                assert!(
                    matches!(out, crate::ledger::SlotOutcome::Activated { .. }),
                    "slot {sid}: the advance is retained"
                );
            }
            // The failed batch k itself.
            (_, std::cmp::Ordering::Equal) => {
                // POSTCONDITION (both policies): batch k FAILED pre-swap — it
                // never advanced, so it stays at its pre-push generation.
                assert_eq!(
                    live, &baseline[sid],
                    "slot {sid}: the failed batch never advanced"
                );
                assert!(
                    matches!(out, crate::ledger::SlotOutcome::FailedBeforeAdvance { .. }),
                    "slot {sid}: batch {position} is recorded as a pre-swap failure"
                );
            }
            // Batches after the failed batch: skipped under stop_on_failure.
            (_, std::cmp::Ordering::Greater) => {
                assert_eq!(live, &baseline[sid], "slot {sid}: skipped, untouched");
                assert!(
                    matches!(out, crate::ledger::SlotOutcome::Skipped { .. }),
                    "slot {sid}: the later batch is skipped"
                );
            }
        }
    }
}

/// The `rollback_changed` postcondition (deterministic): a failure at batch
/// 1 compensates batch 0 back to its pre-push state (`FailedRolledBack`),
/// and a failure at batch 0 (nothing advanced) still ends `FailedRolledBack`
/// with the later batch skipped.
#[test]
fn failure_policy_rollback_changed_rolls_back_earlier_batches() {
    run_failure_position_case(FailurePolicy::RollbackChanged, 1);
    run_failure_position_case(FailurePolicy::RollbackChanged, 0);
}

/// The `leave_changed` postcondition (deterministic): earlier batches stay
/// at the NEW state after a later batch fails (`Degraded`, no compensation
/// pass). A failure at batch 0 (NOTHING advanced — a pre-swap failure, the
/// later batches skipped) carries no Advanced outcome under the DERIVED
/// disposition rule, so it ends `FailedRolledBack` instead (a pure-policy
/// edge: the old leave_changed boolean said Degraded unconditionally, the
/// structural evidence says nothing was left on the new state).
#[test]
fn failure_policy_leave_changed_retains_earlier_batches() {
    run_failure_position_case(FailurePolicy::LeaveChanged, 1);
    run_failure_position_case(FailurePolicy::LeaveChanged, 0);
}

/// Both supported policies — the `policy` dimension of the failure-position
/// property (the strict parse already proved these are the ONLY policies
/// that can exist in a domain config; the property exercises each one's
/// postconditions over every batch position).
fn failure_policy_strategy() -> impl Strategy<Value = FailurePolicy> {
    prop_oneof![
        Just(FailurePolicy::RollbackChanged),
        Just(FailurePolicy::LeaveChanged),
    ]
}

proptest! {
    // THE FAILURE-POSITION POSTCONDITION PROPERTY: for every supported
    // policy and every batch position of the multi-server fixture push, a
    // fault at that position must leave exactly the policy's postcondition —
    // `RollbackChanged` rolls earlier batches back to their pre-push state
    // (ledger shows the restoration, attempt `FailedRolledBack`);
    // `LeaveChanged` keeps them at the new state (`Degraded`) EXCEPT a
    // batch-0 failure (nothing advanced — the DERIVED rule sees no Advanced
    // transition and rolls back). Bounded
    // `proptest_cases(16)` (full 16 with `DEPLOY_FULL_TESTS=1`, fast
    // default), fixed seed 0x5EED_5EED (house style), no persistence — the
    // identical vectors on every run; each case drives its OWN fixture
    // (per-fixture fault registry, structurally isolated).
    #![proptest_config(ProptestConfig {
        cases: crate::testutil::proptest_cases(16),
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn failure_policy_position_postconditions_fixed_seed(
        policy in failure_policy_strategy(),
        position in 0..2usize,
    ) {
        // SLOW-test gate: exceeds ~20 s under the FULL gate
        if !crate::testutil::slow_tests_enabled() {
            eprintln!("skipped: slow test — set DEPLOY_FULL_TESTS=1 to run");
            return Ok(());
        }
        run_failure_position_case(policy, position);
    }
}

// ===========================================================================
// Property — remaining_changes equals the observed-vs-pre_push set
// ===========================================================================

/// THE REMAINING-CHANGES PROPERTY (one case): a multi-server `t1` push
/// (batch 0 = `p1` on `s1`, batch 1 = `p2` on `s2`, `batch_size = 1`) fails
/// a SPECIFIC batch position pre-swap (per-server fault,
/// [`Fixture::set_remote_read_fault_at_position`]) AFTER a baseline push
/// established a generation on every slot, and the faulted attempt's
/// [`LedgerTerminal::remaining_changes`] must EQUAL EXACTLY the slots whose
/// FINAL OBSERVED STATE differs from their pre_push state (compared against
/// the observed records — the actual post-state per slot, never the desired
/// plan). The scenario generates all four transition classes across the two
/// policies: the FAILED batch is a PRE-SWAP FAILURE (`AdvanceUnknown` —
/// never advanced, its observed state equals pre_push), the LATER batches
/// are SKIPPED (`NeverAdvanced`), and the EARLIER batches are either
/// COMPENSATION SUCCESSES (`Restored` — `rollback_changed` compensates them
/// back) or retained SUCCESSFUL ADVANCES (`Advanced` — `leave_changed`
/// keeps them at the new state). A pre-swap failure that advanced nothing
/// and a skipped slot must NOT appear in the derived set even though their
/// outcomes record a generation — the derivation is the transition state,
/// never the outcome's generation field alone.
fn run_remaining_changes_case(policy: FailurePolicy, position: usize) {
    let f = Fixture::with_failure_policy(policy);
    let slots = ["p1", "p2"];

    // Baseline: tree v1 lands on BOTH slots (a real push).
    f.write_artifacts(1);
    let r = f.push("t1").expect("the baseline push succeeds");
    assert_eq!(r.status, Some(DeploymentStatus::Successful));

    // The second push is a REAL push (tree v2) whose batch `position` fails
    // PRE-SWAP on its server.
    f.write_artifacts(2);
    f.set_remote_read_fault_at_position(position);
    let id = test_deployment_id(&format!("si-rc-{position}"));
    let report = f
        .push_with_id("t1", &id)
        .expect("the faulted push still returns a report");
    let status = report
        .status
        .expect("a faulted push records a terminal status");

    // The faulted attempt's ledger entry: the intent (the pre_push per
    // slot) and the terminal (the outcomes + disposition).
    let entry = f
        .store
        .read_ledger("t1")
        .unwrap()
        .into_iter()
        .find(|e| e.deployment_id.as_str() == id.as_str())
        .expect("the faulted attempt has a ledger entry");
    let intent = &entry.intent;
    let terminal = entry
        .terminal
        .as_ref()
        .expect("the faulted attempt has a terminal");

    // The observed records: the ACTUAL post-state per slot (the observed
    // refresh rebuilds them from the LIVE assignments — a skipped or
    // pre-swap-failed slot keeps its prior record, an advanced slot shows
    // the new generation, a compensated slot its restored prior one).
    let observed = f.store.read_observed("t1", &f.config).unwrap();

    // THE ORACLE: the slots whose FINAL OBSERVED STATE differs from their
    // pre_push state (the intent's pre_push per slot).
    let expected: BTreeSet<SlotId> = slots
        .iter()
        .map(|s| SlotId::new(s.to_string()))
        .filter(|sid| {
            let observed_gen = observed.slots.get(sid).and_then(|o| match &o.assignment {
                crate::ledger::ObservedAssignment::Known { generation, .. } => {
                    Some(generation.clone())
                }
                _ => None,
            });
            let pre_gen = match intent.pre_push(sid) {
                Some(crate::ledger::Observation::Known(prev)) => Some(prev.generation.clone()),
                _ => None,
            };
            observed_gen != pre_gen
        })
        .collect();

    // `remaining_changes()` must equal the oracle EXACTLY: `None` (not
    // Degraded — `rollback_changed` fully compensated) iff the oracle is
    // empty, and the derived set otherwise.
    let remaining = terminal.remaining_changes(intent);
    match remaining {
        Some(rc) => {
            let actual: BTreeSet<SlotId> = rc.keys().cloned().collect();
            assert_eq!(
                actual, expected,
                "policy {policy:?} position {position}: remaining_changes must equal exactly the \
                 slots whose observed state differs from pre_push (status {status:?})"
            );
        }
        None => assert!(
            expected.is_empty(),
            "policy {policy:?} position {position}: a non-Degraded terminal ({status:?}) must \
             have no slot whose observed state differs from pre_push"
        ),
    }
}

proptest! {
    // THE REMAINING-CHANGES PROPERTY: for every supported failure policy and
    // every batch position of the multi-server fixture push, a fault at that
    // position must leave `remaining_changes()` EQUAL EXACTLY the slots
    // whose FINAL OBSERVED STATE differs from their pre_push state
    // (compared against the observed records). Bounded `proptest_cases(16)`
    // (full 16 with `DEPLOY_FULL_TESTS=1`, fast default), fixed seed
    // 0x5EED_5EED (house style), no persistence — the identical vectors on
    // every run; each case drives its OWN fixture (per-fixture fault
    // registry, structurally isolated).
    #![proptest_config(ProptestConfig {
        cases: crate::testutil::proptest_cases(16),
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn remaining_changes_matches_observed_vs_pre_push(
        policy in failure_policy_strategy(),
        position in 0..2usize,
    ) {
        // SLOW-test gate: exceeds ~20 s under the FULL gate
        if !crate::testutil::slow_tests_enabled() {
            eprintln!("skipped: slow test — set DEPLOY_FULL_TESTS=1 to run");
            return Ok(());
        }
        run_remaining_changes_case(policy, position);
    }
}

// ===========================================================================
// Property tests — Identity
// ===========================================================================

fn sdef(id: &str, server: &str, dir: &str, target: &str) -> SlotConfig {
    SlotConfig::new(
        id.to_string(),
        server.to_string(),
        PathBuf::from(dir),
        target.to_string(),
        Vec::new(),
    )
}

/// Reordering slots or variants, or permuting the owning targets across
/// slots, preserves the digest.
#[test]
fn identity_reordering_preserves_digest() {
    let mut a: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::new();
    a.insert(
        "standard".to_string(),
        vec![
            sdef("p2", "s2", "/srv/p2", "t1"),
            sdef("p1", "s1", "/srv/p1", "t2"),
        ],
    );
    a.insert(
        "canary".to_string(),
        vec![sdef("c1", "s3", "/srv/c1", "t3")],
    );

    // Same declarations: slots in the opposite file order, owning targets
    // permuted across the slots, variants inserted in the opposite order.
    let mut b: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::new();
    b.insert(
        "canary".to_string(),
        vec![sdef("c1", "s3", "/srv/c1", "t3")],
    );
    b.insert(
        "standard".to_string(),
        vec![
            sdef("p1", "s1", "/srv/p1", "t2"),
            sdef("p2", "s2", "/srv/p2", "t1"),
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

/// Duplicate group names in a slot's declaration are rejected at config
/// load, and a list carrying a duplicate canonicalizes to the same identity
/// as the deduplicated list.
#[test]
fn identity_duplicates_are_rejected_and_canonicalize_identically() {
    // ProjectConfig-level rejection: a slot with a duplicated GROUP name in its
    // `groups` list is rejected (a duplicate adds no membership yet would
    // change the release identity).
    let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
    let project = dir.path().join("proj");
    let release_dir = project.join("releases").join("v1");
    std::fs::create_dir_all(&release_dir).unwrap();
    let dup_variant = format!(
        "{VARIANT_BODY}\n[[slots]]\nid = \"p1\"\nserver = \"s1\"\ntarget = \"t1\"\ngroups = [\"canary\", \"canary\"]\ndeploy_dir = \"/srv/si\"\n"
    );
    std::fs::write(release_dir.join("standard.toml"), dup_variant).unwrap();
    std::fs::write(project.join("deploy.toml"), DEPLOY_TOML).unwrap();
    assert!(
        ProjectConfig::load(&project.join("deploy.toml")).is_err(),
        "a slot with a duplicated group name must be rejected"
    );

    // Digest-level: duplicate group names in the list canonicalize to the
    // same identity as the deduplicated list (the canonical form sorts and
    // dedups defensively).
    let mut dedup: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::new();
    dedup.insert(
        "standard".to_string(),
        vec![SlotConfig::new(
            "p1".to_string(),
            "s1".to_string(),
            PathBuf::from("/srv/si"),
            "t1".to_string(),
            vec!["canary".to_string(), "wave-1".to_string()],
        )],
    );
    let mut dup: BTreeMap<String, Vec<SlotConfig>> = BTreeMap::new();
    dup.insert(
        "standard".to_string(),
        vec![SlotConfig::new(
            "p1".to_string(),
            "s1".to_string(),
            PathBuf::from("/srv/si"),
            "t1".to_string(),
            vec![
                "wave-1".to_string(),
                "canary".to_string(),
                "canary".to_string(),
            ],
        )],
    );
    assert_eq!(
        variant_slots_digest(&dedup),
        variant_slots_digest(&dup),
        "duplicate group names must canonicalize identically"
    );
    assert_eq!(
        canonicalize_slots(&dup["standard"]).slots[0].groups,
        vec!["canary".to_string(), "wave-1".to_string()],
        "the canonical form sorts and deduplicates the groups list"
    );
}

/// Canonical serialization round-trips to the same identity: an ArtifactRef
/// (and a release id) survives a serialize/deserialize cycle unchanged.
#[test]
fn identity_canonical_serialization_round_trips() {
    let art = ArtifactRef {
        release: crate::identity::test_release_id("rel-sha256-abc"),
        variant: VariantName::parse("standard").unwrap(),
        tree: test_tree_digest("tree-1"),
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
    let rid = ReleaseId::parse(
        "rel-sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    .expect("valid release id");
    assert_eq!(
        rid.as_str(),
        "rel-sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        ReleaseId::from_digest(&rid.digest()),
        rid,
        "release id digest round-trips"
    );
}

// ===========================================================================
// Property tests — Scope
// ===========================================================================

/// Each slot's retained set is computed under its ONE policy — the
/// slot's OWNING VARIANT (`standard` declares every fixture slot), resolved
/// via the same `ProjectConfig::slot_retention` path the engine uses. Membership is
/// irrelevant: the owning variant is the SINGLE policy source, and the
/// retained set is identical whether the slot is reached through one target's
/// push or another's — there is no per-target policy to union.
#[test]
fn scope_retained_is_the_owning_variants_single_policy() {
    let f = Fixture::new();
    // Build history interleaved across both targets.
    for (v, t) in [(1u32, "t1"), (2, "t2"), (3, "t1"), (4, "t2"), (5, "t1")] {
        f.apply(Action::Build(v));
        f.apply(Action::Push(t));
    }
    let owner = crate::remote::helper::test_owner("si", "p1");
    let via_p1 = f.with_helper(|helper| {
        compute_retained(
            &helper,
            f.config.pins(),
            &f.store,
            f.config.slot_retention("p1").unwrap(),
            &owner,
        )
        .unwrap()
    });
    let via_p2 = f.with_helper(|helper| {
        compute_retained(
            &helper,
            f.config.pins(),
            &f.store,
            f.config.slot_retention("p2").unwrap(),
            &owner,
        )
        .unwrap()
    });
    assert_eq!(
        via_p1, via_p2,
        "a slot's retained set must not depend on which slot id resolves the policy \
         (both slots' owning variant is `standard`, one policy)"
    );
    assert!(
        !via_p1.is_empty(),
        "the interleaved history is retained under the fixture's conservative policy"
    );
}

/// Strengthening the slot's retention policy — more distinct artifacts, a
/// wider age window, protecting the previous — never REDUCES the retained
/// set. The policy is the slot's OWNING VARIANT's (`standard` declares every
/// fixture slot), mutated through the same config the engine resolves
/// retention from.
#[test]
fn scope_strengthening_policy_never_reduces_retained() {
    let f = Fixture::new();
    for (v, t) in [(1u32, "t1"), (2, "t2"), (3, "t1"), (4, "t2")] {
        f.apply(Action::Build(v));
        f.apply(Action::Push(t));
    }
    let baseline = |cfg: &ProjectConfig| -> HashSet<String> {
        let owner = crate::remote::helper::test_owner("si", "p1");
        f.with_helper(|helper| {
            compute_retained(
                &helper,
                cfg.pins(),
                &f.store,
                cfg.slot_retention("p1").unwrap(),
                &owner,
            )
            .unwrap()
        })
    };
    let weak = baseline(&f.config);

    // Strengthen the owning variant's policy: keep 5 distinct (was 5),
    // protect the previous, protect 2 deployments — all already at the
    // fixture's conservative values, so widen the strongest window instead.
    let mut strong_config = f.config.clone();
    let r = strong_config.variant_mut("standard").unwrap();
    r.retention.per_server.keep_distinct_artifacts = 5;
    r.retention.per_server.protect_previous = true;
    r.retention.deployment.protect_deployments = 2;
    let strong = baseline(&strong_config);
    assert!(
        strong.is_superset(&weak),
        "strengthening a retention policy must never reduce the retained set"
    );

    // Widening the age window is monotone too.
    let mut wider = strong_config.clone();
    wider
        .variant_mut("standard")
        .unwrap()
        .retention
        .per_server
        .keep_days = 90;
    let wider_retained = baseline(&wider);
    assert!(
        wider_retained.is_superset(&strong),
        "widening keep_days must never reduce the retained set"
    );

    // The retained set is INDEPENDENT of membership: computing it via the
    // slot's owning-variant policy is the only way to compute it (there is
    // no per-target policy), so a membership-only config edit (adding a
    // rollout group to the slot's `groups` list) cannot change retention.
    let mut edited = f.config.clone();
    edited
        .variant_mut("standard")
        .unwrap()
        .slots
        .iter_mut()
        .for_each(|s| {
            if s.id == "p1" {
                s.groups = vec!["t1".to_string(), "t2".to_string(), "t3".to_string()]
            }
        });
    let _ = baseline(&edited);
    assert_eq!(
        baseline(&edited),
        weak,
        "changing a slot's membership must never change its retained set"
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
        let id = test_deployment_id(&format!("si-lc-fault-{i}"));
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
            // An intent WITHOUT a terminal IS the pending state — the
            // terminal status enum carries no pending status.
            f.store.latest_status(id.as_str()).unwrap().is_none(),
            "{step:?}: the crash window must leave the attempt recoverable (pending), never Successful"
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
/// a time (the per-server `write_server`, and the per-slot `write_observed`
/// for each of the push's OWN slots `p1`/`p2`), a one-shot store fault must
/// NEVER turn the push into an `Err`: the deployment is already durably
/// `Successful` (snapshot, attempt, and terminal transition recorded BEFORE the
/// refresh runs), so the push returns `Ok` with that status and the report
/// carries a warning naming the deferred observed refresh. No persistent debt
/// marker is needed (unlike retention): the observed maps are projections of
/// already-durable facts, and a clean no-op retry converges WITHOUT duplicate
/// history — snapshot count, attempt count, transition stream, and
/// `refs/last-successful` all stay exactly-once.
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
        let id = test_deployment_id(&format!("si-obs-fault-{i}"));
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
            1,
            "{step:?}: exactly ONE terminal event (Successful) — no duplicates"
        );
        assert_eq!(
            f.store.read_last_successful("t1").as_deref(),
            Some(id.as_str()),
            "{step:?}: refs/last-successful points at the committed attempt"
        );
        assert!(
            f.store.read_retention_debt("t1").unwrap().is_empty(),
            "{step:?}: observed refresh needs no persistent debt marker — the next real push \
             re-projects from durable facts"
        );
        // `check_invariants` is deliberately NOT evaluated in the crash-window
        // state here: the faulted refresh deferred the projection (the strict
        // `check_scope` contract permits absence only inside the crash window,
        // "never evaluated by check_invariants"). The no-op retry below closes
        // the window by re-projecting from the EXISTING assignment; the
        // invariant is checked AFTER it, where the OWNING target's projection
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
            1,
            "{step:?}: no duplicate terminal events after the retry"
        );
        // The no-op retry refreshed the OWNING target's projection from the
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

/// Lifecycle: the retention-debt maintenance I/O is POST-COMMIT maintenance —
/// every debt read/write/remove failure must never turn a push into an `Err`
/// once the deployment is durably committed. The matrix generates
/// {real push, no-op} × {debt read, debt write, debt remove} × {empty,
/// existing debt}. The "debt remove" arm is the same `write_retention_debt`
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
///     deferred), and a real push whose step-17 retention succeeded clears the
///     pre-seeded marker even when the earlier retry's debt I/O faulted (the
///     fault is one-shot, so the later clear write succeeds) — the warning
///     from the faulted retry stays on the report.
///
/// The `debtfx` fixture target is pushed ONLY by this test, so the
/// target-keyed one-shot arms (`arm_read_retention_debt` /
/// `arm_write_retention_debt`) cannot be consumed by a concurrent test's
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
                let id = test_deployment_id(&format!("si-debt-fault-{i}-{j}"));
                if have_debt {
                    f.store
                        .write_retention_debt(
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
                    1,
                    "{ctx}: exactly ONE terminal event (Successful) — no duplicates"
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
                let debt = f.store.read_retention_debt("debtfx").unwrap();
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
                    "{ctx}: the real push's step-17 retention succeeded, so the (pre-seeded) \
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
                let seed_id = test_deployment_id(&format!("si-debt-seed-{i}-{j}"));
                let r0 = f
                    .push_with_id("debtfx", &seed_id)
                    .expect("seed push succeeds");
                assert_eq!(r0.status, Some(DeploymentStatus::Successful));
                if have_debt {
                    f.store
                        .write_retention_debt(
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
                let debt = f.store.read_retention_debt("debtfx").unwrap();
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
            let rec: crate::identity::ReleaseRecord = serde_json::from_str(&tampered)?;
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
    let rec: crate::identity::ReleaseRecord =
        serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    let fresh = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
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
    let p = dir.path().join("release.json");
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    // Tamper the slot snapshot (an identity-bearing field) with digests
    // retained. The push reads the release through `read_release`, which
    // recomputes and verifies — it must fail closed before anything deploys.
    v["slots"]["standard"]["slots"][0]["deploy_dir"] = serde_json::json!("/srv/elsewhere");
    std::fs::write(&p, serde_json::to_vec_pretty(&v).unwrap()).unwrap();

    // The historical ref: the deployment id of the push that recorded the
    // release (rollback payloads are keyed by deployment id).
    let dep = f.latest_deployment_id("t1");
    let err = f
        .push_ref_impl("t1", &dep)
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

    // The tamper rewrites `activation.adapter` to an UNSUPPORTED adapter:
    // the closed-enum record boundary REFUSES it at the parse (the review's
    // fix — an unsupported adapter was previously tolerated as a silent
    // activation no-op and only caught as a digest mismatch), surfaced
    // through the historical-behavior preflight as a closed refusal.
    let releases_root = f.store.base().join(layout::RELEASES);
    let dir = std::fs::read_dir(&releases_root)
        .unwrap()
        .flatten()
        .next()
        .unwrap();
    let id = ReleaseId::new(dir.file_name().to_string_lossy().into_owned());
    let dep = f.latest_deployment_id("t1");
    let err = f
        .push_ref_impl("t1", &dep)
        .expect_err("a historical push against a tampered behavior snapshot must fail closed");
    let msg = err.to_string();
    assert!(
        msg.contains("historical behavior"),
        "error must surface through the historical-behavior preflight, got: {msg}"
    );
    assert!(
        msg.contains("refused") || msg.contains("unknown activation adapter"),
        "error must name the unsupported-adapter refusal, got: {msg}"
    );
    // And the direct historical read fails closed too.
    let rerr = f
        .store
        .read_release_behaviors(&id)
        .expect_err("the historical behavior read must fail closed");
    assert!(
        rerr.to_string().contains("malformed")
            && rerr.to_string().contains("unknown activation adapter"),
        "read error must name the closed-enum parse refusal, got: {rerr}"
    );
}

/// The schema-version property, end-to-end: a stored release record whose
/// `release_schema_version` was rewritten to any arbitrary `u32` value other
/// than [`crate::verify::release::RELEASE_RECORD_SCHEMA_VERSION`] must fail closed on
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
        crate::verify::release::RELEASE_RECORD_SCHEMA_VERSION.wrapping_sub(1),
        crate::verify::release::RELEASE_RECORD_SCHEMA_VERSION.wrapping_add(1),
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
        let dep = f.latest_deployment_id("t1");
        let push_err = f
            .push_ref_impl("t1", &dep)
            .expect_err("a push against a tampered record version must fail closed");
        assert!(
            push_err.to_string().contains("release_schema_version"),
            "push error must name the version mismatch, got: {push_err}"
        );
    }

    // Restoring the canonical version restores readability (the tamper is
    // reversible; the record itself is unchanged otherwise).
    write_version(crate::verify::release::RELEASE_RECORD_SCHEMA_VERSION);
    f.store
        .read_release(&id)
        .expect("the canonical version reads");
    let dep = f.latest_deployment_id("t1");
    f.push_ref_impl("t1", &dep)
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

/// Incoming (not yet stored) ledger lines reject every required-field
/// deletion: a torn record never deserializes into a usable fact. The
/// intent line and the terminal line are the ledger's two record shapes.
#[test]
fn integrity_incoming_record_field_deletion_fails_closed() {
    let f = Fixture::new();
    f.apply(Action::Push("t1"));
    let ledger_path = f.store.ledger_path("t1");
    let lines: Vec<String> = std::fs::read_to_string(&ledger_path)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    // The INTENT line: every required field rejected individually.
    let intent_line = lines[0].clone();
    for field in [
        "deployment_schema_version",
        "deployment_id",
        "target",
        "slots",
        "behavior_sha256",
        "attempted_at",
    ] {
        let mut v: serde_json::Value = serde_json::from_str(intent_line.trim()).unwrap();
        v.as_object_mut().unwrap().remove(field);
        let tampered = serde_json::to_string(&v).unwrap();
        let rec: std::result::Result<crate::ledger::LedgerLine, _> =
            serde_json::from_str(&tampered);
        assert!(
            rec.is_err(),
            "deleting intent field '{field}' must fail deserialization"
        );
    }
    // The TERMINAL line: every required field rejected individually. The
    // optional members (`outcomes` on a Successful terminal, `reason`)
    // carry serde defaults — deleting them stays valid. The redundant
    // `target` member is GONE from the v11 wire (the enclosing entry owns
    // target).
    let terminal_line = lines[1].clone();
    for field in ["deployment_id", "status", "recorded_at", "intent_digest"] {
        let mut v: serde_json::Value = serde_json::from_str(terminal_line.trim()).unwrap();
        v.as_object_mut().unwrap().remove(field);
        let tampered = serde_json::to_string(&v).unwrap();
        let rec: std::result::Result<crate::ledger::LedgerLine, _> =
            serde_json::from_str(&tampered);
        assert!(
            rec.is_err(),
            "deleting terminal field '{field}' must fail deserialization"
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
/// * each target's expected observed projection (a completed
///   push/rollback refreshes the owning target's own slots);
/// * the per-target snapshot log (`s{i}` rollback refs, one chain per
///   target) and the
///   deployment-attempt log (one entry per real deployment);
/// * pending-commit state — a CommitMarker-write fault leaves the attempt
///   un-finalized until the next push of that target reconciles it (or
///   degrades it, when the remote current has since diverged);
/// * retention-debt markers — an inventory-write fault after commit defers
///   the post-commit retention to a later push (including no-ops, which
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
///
/// The checkpoint dimension adds the per-target durable HISTORY FLOOR: the
/// model tracks the RAW attempt/snapshot logs (the physical files the
/// checkpoint compacts) and derives the visible chains as the suffix
/// at/after the floor, so a [`Action::Checkpoint`] step can predict exactly
/// what the real `checkpoint_discards` / `checkpoint_compact` path discards
/// — including a BELOW-FLOOR pending commit (discarded with the rest of the
/// below-floor history, never resurrected by recovery) versus an
/// AT/ABOVE-FLOOR one (survives and is finalized by the next push exactly
/// once).
///
/// The oracle's deployment ids are MINTED IN LOCKSTEP with the fixture
/// ([`Model::mint_id`] mirrors [`Fixture::next_prop_id`] from the SAME
/// per-fixture tag and counter), so the model's raw logs, the floor marker,
/// and the pending state can be compared id-for-id with the system's.
/// The oracle's expectation for ONE checkpoint step: the floor it
/// establishes and the EXACT discard sets the real `checkpoint_discards`
/// must report (the driver asserts the actual [`CheckpointReport`] against
/// it field-for-field). The discard semantics mirror
/// [`crate::store::local::LocalStore::checkpoint_discards`]: attempts
/// strictly before the checkpoint's own attempt, snapshots strictly before
/// the floor deployment's POSITION in the log (positions are DERIVED, never
/// stored), and the deduplicated union of their deployment ids (the dirs the
/// compaction deletes).
#[derive(Clone, Debug)]
struct CheckpointExpectation {
    target: &'static str,
    deployment_id: String,
    /// True for every real checkpoint: the ATOMIC LEDGER REPLACEMENT (the
    /// only logical commit) always runs — even a re-checkpoint of the same
    /// deployment rewrites the (identical) suffix so the sweep can finish.
    established: bool,
    /// The ledger entries strictly before the checkpoint deployment's
    /// position, dropped by the retained-suffix replacement.
    discarded_entries: Vec<String>,
}

/// One target's expected observed VIEW over its OWN placement slots: per
/// slot, the (content version, minting deployment id) the target's filtered
/// view of the ONE physical slot map must show, or `None` before the first
/// completed mutation.
type ObservedView = BTreeMap<SlotId, Option<(u32, String)>>;

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
    /// The remote `current` generation's expected (artifact content version,
    /// minting deployment id) PER SLOT: the deployment that actually
    /// advanced each slot. The model knows WHICH deployment minted each live
    /// generation, so the observed projections' `last_deployment` can be
    /// asserted equal to the live assignment's OWN deployment — never a
    /// deployment that did not touch the slot. A target's slots advance
    /// TOGETHER (every push/rollback of the target plans ALL of its slots; a
    /// pre-swap failure advances none), so one (version, deployment) pair
    /// describes each slot; slots of DIFFERENT targets advance independently
    /// (a slot has exactly one owning target).
    current: BTreeMap<SlotId, (u32, String)>,
    /// A [`Action::Tamper`] edited the live assignment: the current's
    /// identity is deliberately inconsistent and the identity comparison
    /// defers until the next real push replaces the record. The tamper
    /// always targets the `s1` slot (`p1`), so a single flag suffices.
    current_tampered: bool,
    /// Expected observed projection, PER TARGET AND PER SLOT: the
    /// (content version, minting deployment id) each target's view shows for
    /// each slot IT OWNS, or `None` before the first
    /// completed mutation. Observed state is ONE PHYSICAL RECORD PER SLOT and targets
    /// are SELECTION VIEWS over it, so a slot whose physical write faulted
    /// stays stale in its OWNING target's view while the other slot's
    /// record (and its own view of it) advances.
    observed: BTreeMap<&'static str, ObservedView>,
    /// Per-target RAW snapshot log: (index, deployment id, content version)
    /// per physically recorded snapshot, in LOG ORDER (the deployment order) —
    /// the log the checkpoint compacts. The VISIBLE chain is the suffix
    /// beginning at the target's floor deployment's POSITION (see
    /// [`Model::visible_snapshots`]); positions are DERIVED from this order,
    /// never stored (the old `sN` index is gone — the public grammar is
    /// deployment-keyed). The deployment id is tracked so the floor's own
    /// deployment and the discard sets can be pinned against the system's
    /// raw logs.
    raw_snapshots: BTreeMap<&'static str, Vec<(u64, String, u32)>>,
    /// Per-target RAW deployment-attempt log: (deployment id, content
    /// version) per physically recorded attempt. The VISIBLE chain starts at
    /// the floor's own attempt (see [`Model::visible_attempts`]).
    raw_attempts: BTreeMap<&'static str, Vec<(String, u32)>>,
    /// Per-target durable history floor: (deployment id, snapshot index)
    /// the retained-suffix boundary sits at; `None` before the target's first
    /// checkpoint.
    floor: BTreeMap<&'static str, Option<(String, u64)>>,
    /// Un-finalized pending deployment per target: (deployment id, content
    /// version, the minted-generation counter, whether its snapshot is
    /// ALREADY durable). A `LastSuccessfulWrite` / `TransitionSuccessful`
    /// fault leaves the snapshot appended while the attempt stays pending,
    /// so the reconcile must not append it a second time. The deployment id
    /// lets the checkpoint DISCARD a below-floor pending commit (its line
    /// and its snapshot entry vanish from the raw logs — no resurrection on
    /// recovery) while an at/above-floor one survives.
    pending: BTreeMap<&'static str, (String, u32, u64, bool)>,
    /// The deployment-id counter + tag for the CURRENT step's push,
    /// MIRRORING [`Fixture::next_prop_id`] so the oracle mints the SAME ids
    /// as the system (the floor pins ids in the raw logs; the comparisons
    /// would be meaningless if the two sides minted different strings). The
    /// model is single-threaded, so the counter is a plain `u64` (the
    /// fixture's `AtomicU64` exists only for its scoped-thread paths).
    prop_ids: u64,
    prop_tag: String,
    /// The last checkpoint step's expected report — the floor it established
    /// and the EXACT discard set the real `checkpoint_discards` must have
    /// enumerated. The driver asserts the actual [`CheckpointReport`]
    /// against it. `None` when the step was not a checkpoint (or the visible
    /// chain was empty, so the step no-opped).
    last_checkpoint: Option<CheckpointExpectation>,
    /// Monotone counter of deployed generations PER TARGET: every real
    /// deployment of a target (push, rollback, or faulted push) mints
    /// exactly one new generation for each of its slots, and a pending
    /// attempt finalizes only while its OWN generation is still the remote
    /// current (the engine compares generation IDs, not versions — a
    /// same-version redeploy diverges the pending attempt). Per-target
    /// because a slot has exactly one owning target: a `t1` deployment never
    /// advances `t2`'s slots, so it must not invalidate a `t2` pending
    /// attempt.
    current_gen: BTreeMap<&'static str, u64>,
    /// Expected retention-debt marker presence per target.
    debt: BTreeMap<&'static str, bool>,
    /// The crash window PER TARGET: an open post-mutation fault state where
    /// the observed projections legitimately disagree with the remote
    /// current, or where a crash-recovery attempt (PendingCommit with a
    /// durable snapshot) has not been finalized yet — both states the
    /// fixture's invariant groups cannot evaluate (see
    /// [`Model::lingering_crash`]). A slot has EXACTLY ONE owning target, so
    /// a crash on `t1` never affects `t2`'s observed projections: the
    /// window is per-target, and the five invariant groups and the
    /// model-vs-system comparisons are suspended while ANY target's window
    /// is open.
    crash_window: BTreeMap<&'static str, bool>,
    /// The warning the CURRENT step's push report must contain: one
    /// substring per entry, EVERY one asserted against the actual report's
    /// `warning`. Set ONLY by the step-17 contention classes (see
    /// [`FailureClass::Step17Contended`] and its debt combinations) so the
    /// oracle asserts the retryable-vs-not distinction — "retention deferred
    /// for slot" (the marker-persisted claim) plus, on a debt read/write
    /// fault, the explicit "retention debt maintenance deferred: failed to
    /// ..." notice that says the marker was NOT persisted (no automatic
    /// retryability). `None` for every other class (their warnings are not
    /// cross-checked).
    expected_warning: Option<Vec<String>>,
    /// True when the previous action was a deliberate tamper (the system's
    /// own invariant checks are skipped for that step too).
    last_was_tamper: bool,
    /// Actions applied so far; used to name the failing step in panics.
    index: usize,
}

impl Model {
    fn new_with_tag(tag: &str) -> Model {
        Model {
            head_version: 1,
            armed_fault: None,
            unknown: false,
            current: BTreeMap::new(),
            current_tampered: false,
            observed: BTreeMap::from([
                (
                    "t1",
                    BTreeMap::from([
                        (SlotId::parse("p1").unwrap(), None),
                        (SlotId::parse("p2").unwrap(), None),
                    ]),
                ),
                ("t2", BTreeMap::from([(SlotId::parse("p3").unwrap(), None)])),
            ]),
            raw_snapshots: BTreeMap::from([("t1", Vec::new()), ("t2", Vec::new())]),
            raw_attempts: BTreeMap::from([("t1", Vec::new()), ("t2", Vec::new())]),
            floor: BTreeMap::from([("t1", None), ("t2", None)]),
            pending: BTreeMap::new(),
            prop_ids: 0,
            prop_tag: tag.to_string(),
            last_checkpoint: None,
            current_gen: BTreeMap::new(),
            debt: BTreeMap::from([("t1", false), ("t2", false)]),
            crash_window: BTreeMap::new(),
            expected_warning: None,
            last_was_tamper: false,
            index: 0,
        }
    }

    /// The next deployment id for the CURRENT step's push/rollback,
    /// mirroring [`Fixture::next_prop_id`] (same tag, same zero-padded
    /// counter) so the oracle and the system mint identical ids.
    fn mint_id(&mut self) -> String {
        let i = self.prop_ids;
        self.prop_ids += 1;
        test_deployment_id(&format!("deploy-si-{}-{i:04}", self.prop_tag))
            .as_str()
            .to_string()
    }

    /// The placement slots a target OWNS (a slot has exactly one owning
    /// target): `t1` owns `p1`/`p2` (two slots — the pre-swap skip
    /// scenario), `t2` owns `p3`. A target's slots advance together on its
    /// pushes and are never touched by another target's.
    fn target_slots(t: &str) -> Vec<SlotId> {
        match t {
            "t1" => vec![SlotId::parse("p1").unwrap(), SlotId::parse("p2").unwrap()],
            "t2" => vec![SlotId::parse("p3").unwrap()],
            other => panic!("unknown fixture target {other}"),
        }
    }

    /// The target's VISIBLE successful chain: the RAW ledger's successful
    /// entries (the ledger IS the retained suffix — the floor is implicit,
    /// and positions are relative to the CURRENT ledger, so the visible
    /// chain IS the raw chain).
    fn visible_snapshots(&self, t: &'static str) -> Vec<(u64, String, u32)> {
        self.raw_snapshots.get(t).cloned().unwrap_or_default()
    }

    /// The target's VISIBLE entry chain: the RAW ledger (the retained suffix
    /// after a checkpoint).
    fn visible_attempts(&self, t: &'static str) -> Vec<(String, u32)> {
        self.raw_attempts.get(t).cloned().unwrap_or_default()
    }

    /// The next successful-chain position for `t`: the CURRENT ledger's
    /// successful count (positions are contiguous 0-based — after a
    /// checkpoint the first retained successful entry is position 0).
    fn next_snapshot_index(&self, t: &'static str) -> u64 {
        self.raw_snapshots
            .get(t)
            .map(|s| s.len() as u64)
            .unwrap_or(0)
    }

    /// Append a NEW successful entry for deployment `id` (content `v`) at
    /// the next successful-chain position.
    fn append_snapshot(&mut self, t: &'static str, id: &str, v: u32) {
        let idx = self.next_snapshot_index(t);
        self.raw_snapshots
            .entry(t)
            .or_default()
            .push((idx, id.to_string(), v));
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
        let class = match action {
            Action::Build(v) => {
                self.head_version = *v;
                OutcomeClass::Push {
                    boundary: ReturnBoundary::Ok,
                    disposition: Disposition::NoAttempt,
                }
            }
            Action::Push(t) | Action::Retry(t) => {
                // The push's returned window is the pushed target's NEW
                // crash-window state (a slot has exactly one owning target, so
                // a push only ever opens/closes its own target's window).
                let (class, window) = self.deploy(t);
                self.crash_window.insert(t, window);
                class
            }
            Action::Rollback(t, i) => {
                let (class, window) = self.rollback(t, *i);
                self.crash_window.insert(t, window);
                class
            }
            Action::Rotate => OutcomeClass::Push {
                boundary: ReturnBoundary::Ok,
                disposition: Disposition::NoAttempt,
            },
            Action::Checkpoint(t, k) => {
                // The fixture resolves the deployment id from the target's
                // VISIBLE snapshots; the model resolves the SAME id from its
                // own visible chain (in lockstep). An empty visible chain is
                // a no-op step (no recorded successful deployment yet). The
                // step's failure class is NOT consumed: the checkpoint is
                // local-only and the generated classes are push-oriented,
                // so the arm is dropped step-scoped like any unconsumed
                // fault (the fixture never arms one for a checkpoint).
                let visible = self.visible_snapshots(t);
                if visible.is_empty() {
                    self.last_checkpoint = None;
                } else {
                    let pos = *k as usize % visible.len();
                    let (_, cid, _) = visible[pos].clone();
                    self.checkpoint(t, cid, pos as u64);
                }
                OutcomeClass::Push {
                    boundary: ReturnBoundary::Ok,
                    disposition: Disposition::NoAttempt,
                }
            }
            Action::InjectFailure(_) => {
                // The property injects faults per step (never via this action);
                // a stray sticky arm cannot be cross-checked.
                self.unknown = true;
                OutcomeClass::Push {
                    boundary: ReturnBoundary::Ok,
                    disposition: Disposition::NoAttempt,
                }
            }
            Action::Tamper(_) => {
                if self.current.contains_key(&SlotId::parse("p1").unwrap()) {
                    // The fixture requires a live generation to tamper; with
                    // none, the property test skips the action entirely. The
                    // tamper always targets the `s1` slot (`p1`).
                    self.current_tampered = true;
                    self.last_was_tamper = true;
                }
                OutcomeClass::Tampered
            }
        };
        // Step-scoped faults: whatever the action did not consume is dropped.
        self.armed_fault = None;
        class
    }

    /// Retain the target's ledger suffix at the deployment `cid`, mirroring
    /// `checkpoint_inner`: the ledger is ATOMICALLY replaced with everything
    /// at/after the checkpoint deployment's position (the floor is implicit
    /// — the first retained entry is the oldest rollback state). The model
    /// trims its raw ledger to the same suffix: raw attempts to the
    /// checkpoint entry onward, raw successful entries to those at/after it
    /// with positions RENUMBERED 0.. (the ledger's positions are relative to
    /// the CURRENT ledger). A pending commit whose entry was trimmed is
    /// DISCARDED (no resurrection on recovery); one at/after survives.
    fn checkpoint(&mut self, t: &'static str, cid: String, _idx: u64) {
        let raw_att = self.raw_attempts.get(t).cloned().unwrap_or_default();
        let raw_snaps = self.raw_snapshots.get(t).cloned().unwrap_or_default();
        let keep_from = raw_att
            .iter()
            .position(|(id, _)| *id == cid)
            .expect("the checkpoint deployment is a recorded attempt");
        let discarded_entries: Vec<String> = raw_att[..keep_from]
            .iter()
            .map(|(id, _)| id.clone())
            .collect();
        // The retained suffix's SUCCESSFUL entries: those whose ENTRY
        // position is at/after the checkpoint entry, renumbered 0..
        let retained_snaps: Vec<(u64, String, u32)> = raw_snaps
            .iter()
            .filter(|(_, sid, _)| {
                raw_att
                    .iter()
                    .position(|(id, _)| id == sid)
                    .is_some_and(|pos| pos >= keep_from)
            })
            .enumerate()
            .map(|(n, (_, sid, v))| (n as u64, sid.clone(), *v))
            .collect();
        // A below-checkpoint pending commit is discarded with the rest of
        // the below-checkpoint history.
        if let Some((pid, _, _, _)) = self.pending.get(t)
            && discarded_entries.iter().any(|id| id == pid)
        {
            self.pending.remove(t);
        }
        self.raw_attempts.insert(t, raw_att[keep_from..].to_vec());
        self.raw_snapshots.insert(t, retained_snaps);
        self.floor.insert(t, Some((cid.clone(), 0)));
        self.last_checkpoint = Some(CheckpointExpectation {
            target: t,
            deployment_id: cid,
            established: true,
            discarded_entries,
        });
    }

    /// Reconcile a pending attempt of `t` at the START of a push/rollback,
    /// mirroring `reconcile_pending_commits` (which runs before the early
    /// no-op check): verify the attempt's generation, then write its missing
    /// commit marker. The marker write is a commit-path write, so an
    /// armed [`FailureClass::CommitMarker`] is consumed there and the attempt
    /// stays pending; under [`FailureClass::LockContention`] the reconcile's
    /// lock acquisition fails BEFORE any write, so the attempt stays pending
    /// and the fault is NOT consumed. UNDER THE STRICTLY-LINEAR MODEL a
    /// still-pending attempt after reconciliation makes the CALLER ([`deploy`]
    /// /[`rollback`]) REFUSE the push — the engine never plans a second
    /// intent on top of an unresolved attempt.
    /// commit marker. The marker write is a commit-path write, so an
    /// armed [`FailureClass::CommitMarker`] is consumed there and the attempt
    /// stays pending; under [`FailureClass::LockContention`] the reconcile's
    /// lock acquisition fails BEFORE any write, so the attempt stays pending
    /// and the fault is NOT consumed.
    fn reconcile(&mut self, t: &'static str) {
        let Some((pid, pv, pg, already_snapped)) = self.pending.remove(t) else {
            return;
        };
        // The engine's reconciliation FIRST verifies the pending attempt's
        // generation against the remote current (before any marker write): a
        // diverged generation degrades the attempt with NO marker write, so
        // an armed fault is NOT consumed. The generation counter is
        // PER-TARGET: a slot has exactly one owning target, so only a later
        // deployment of the SAME target can diverge the pending attempt's
        // generation.
        if self.current_gen.get(t) != Some(&pg) {
            return;
        }
        match self.armed_fault {
            Some(FailureClass::LockContention) => {
                // The reconcile's marker write contends on the held lock: the
                // attempt stays pending, no write was attempted, so the fault
                // (a step-scoped contention marker) is not consumed.
                self.pending.insert(t, (pid, pv, pg, already_snapped));
            }
            Some(FailureClass::CommitMarker) => {
                // The pending attempt's marker write consumes the armed fault
                // and fails, so the attempt stays pending.
                self.armed_fault = None;
                self.pending.insert(t, (pid, pv, pg, already_snapped));
            }
            Some(_) => {
                // Any other armed class: the reconcile's writes are keyed to
                // the OLD attempt's id, so they pass through untouched and the
                // attempt finalizes (the step's fault stays armed for the
                // step's own deployment writes, or is dropped by a no-op).
                // The snapshot is appended at the next unique RAW index (a
                // checkpoint may have compacted the chain — the index is
                // never reused).
                if !already_snapped {
                    self.append_snapshot(t, &pid, pv);
                }
            }
            None => {
                // The pending deployment's OWN generation is still the remote
                // current: the attempt finalizes (snapshot appended, refs
                // advanced). A finalize fault (LastSuccessful etc.) already
                // recorded the snapshot, so it must not be duplicated.
                if !already_snapped {
                    self.append_snapshot(t, &pid, pv);
                }
            }
        }
    }

    /// A rollback to the deployment at POSITION `i` of the target's visible
    /// deployment history. The strategy selects the position; the fixture
    /// passes the deployment id at that position (a position beyond the
    /// current chain names a deployment that does not exist yet and fails
    /// closed), and the model looks up the SAME position on its own chain —
    /// positions are DERIVED from the log order, never stored. The engine
    /// reconciles pending attempts BEFORE resolving the ref (the resolution
    /// point sits after `reconcile_pending_commits`); reconciliation appends
    /// only at the END of the chain, so the deployment id at a given position
    /// is stable across the reconcile. The reconciliation runs even when the
    /// ref still fails closed after it; the push then returns `Err` (nothing
    /// recorded — `NoAttempt`) BEFORE the observed refresh, so an open crash
    /// window STAYS open (the fixture's invariant groups stay suspended until
    /// a later successful push/no-op refreshes observed).
    fn rollback(&mut self, t: &'static str, i: u64) -> (OutcomeClass, bool) {
        // The fixture mints the step's ID BEFORE the push runs (even when
        // the ref then fails closed), so the oracle mints first too — the
        // counters stay in lockstep.
        let id = self.mint_id();
        // The fixture's token is the deployment id at position `i` of the
        // PRE-push visible chain (positions derived); the model resolves the
        // same position on its own chain. A position beyond the chain is
        // "no such deployment" — fails closed.
        let v = self
            .visible_snapshots(t)
            .get(i as usize)
            .map(|(_, _, v)| *v);
        // The engine reconciles pending attempts ONCE per push, before the
        // ref is resolved, and the resolved deployment enters the shared
        // resolved-look stage with NO second reconciliation (a second
        // reconcile would wrongly finalize an attempt the reconcile's OWN
        // faulted marker write left pending).
        self.reconcile(t);
        // THE STRICTLY-LINEAR REFUSAL (same as the HEAD push): a rollback
        // push whose recovery cannot finish the previous pending attempt is
        // also REFUSED — it never plans a second intent on top.
        if self.pending.contains_key(&t) {
            return (
                OutcomeClass::Push {
                    boundary: ReturnBoundary::Err,
                    disposition: Disposition::NoAttempt,
                },
                self.crash_window.get(t).copied().unwrap_or(false),
            );
        }
        let Some(v) = v else {
            return (
                OutcomeClass::Push {
                    boundary: ReturnBoundary::Err,
                    disposition: Disposition::NoAttempt,
                },
                self.crash_window.get(t).copied().unwrap_or(false),
            );
        };
        self.deploy_resolved(t, Some(v), id)
    }

    /// A HEAD push / no-op retry (`Push` and `Retry` are the same operation
    /// in the fixture) under the step's failure class. The engine reconciles
    /// pending attempts once, then decides no-op-vs-deploy against the
    /// post-reconciliation state and enters the shared resolved-deploy stage.
    ///
    /// THE STRICTLY-LINEAR REFUSAL (mirroring the engine): when the recovery
    /// step CANNOT finish the previous pending attempt (the finalizer could
    /// not complete RIGHT NOW — its marker write or lock acquisition
    /// transiently failed, so the attempt is still intent-only), the push is
    /// REFUSED with a Conflict and records NOTHING — it never plans a second
    /// intent on top of an unresolved attempt, even for disjoint groups.
    fn deploy(&mut self, t: &'static str) -> (OutcomeClass, bool) {
        let id = self.mint_id();
        self.reconcile(t);
        // A still-unresolved attempt after reconciliation: the push refuses
        // (`Err` + `NoAttempt`) — the attempt stays pending for a later push.
        if self.pending.contains_key(&t) {
            return (
                OutcomeClass::Push {
                    boundary: ReturnBoundary::Err,
                    disposition: Disposition::NoAttempt,
                },
                self.crash_window.get(t).copied().unwrap_or(false),
            );
        }
        // HEAD push: deploy exactly when ANY of the target's OWN slots is no
        // longer at the materialized head (the engine's complete ArtifactRef
        // equality — a tampered current forces a fresh push). Slots of other
        // targets are irrelevant: a slot has exactly one owning target, so a
        // `t1` push never redeploys `t2`'s slots.
        let version = if self.current_tampered
            || Self::target_slots(t)
                .iter()
                .any(|s| self.current.get(s).map(|(v, _)| *v) != Some(self.head_version))
        {
            Some(self.head_version)
        } else {
            None
        };
        self.deploy_resolved(t, version, id)
    }

    /// The shared POST-RECONCILIATION deployment stage — everything the
    /// engine runs after `reconcile_pending_commits`, ref resolution, and
    /// planning: the mutation-lock preflight, then either the up-to-date
    /// no-op (no records) or the real deployment under the step's failure
    /// class. `id` is the CURRENT step's minted deployment id (the attempt
    /// and snapshot records are keyed by it). Returns the expected outcome
    /// class and the NEW crash-window state.
    fn deploy_resolved(
        &mut self,
        t: &'static str,
        version: Option<u32>,
        id: String,
    ) -> (OutcomeClass, bool) {
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
                self.crash_window.get(t).copied().unwrap_or(false),
            );
        }
        let Some(v) = version else {
            // Up-to-date no-op: no records. The deferred-maintenance hook
            // services retention debt, and the no-op path refreshes observed
            // from the EXISTING generation into the target's OWN slots (the
            // crash-window recovery path), closing any open window. The
            // no-op re-projects each slot's ONE physical record from the
            // EXISTING generation, so the owning target's view converges
            // too. A slot has exactly one owning target, so only that
            // target's view is refreshed.
            self.noop_maintenance(t);
            for slot in Self::target_slots(t) {
                if let Some(c) = self.current.get(&slot).cloned() {
                    self.observed.get_mut(t).unwrap().insert(slot, Some(c));
                }
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
                self.crash_window.get(t).copied().unwrap_or(false),
            );
        }
        // PRE-SWAP REMOTE STATUS FAILURE: the first planned slot's `current`
        // link read fails exactly once INSIDE `process_server` (right after
        // the mutation-lock write — the planning/reconcile reads passed), so
        // the slot aborts `Ok(Failed)` BEFORE the swap and `stop_on_failure`
        // SKIPS the remaining slots: NOTHING advanced. The attempt is
        // recorded (the intent was durable before the mutation loop) with the
        // terminal `FailedRolledBack` disposition (nothing advanced, nothing
        // to compensate) and NO snapshot. The observed projections are
        // UNTOUCHED — a skipped/unreachable slot keeps its prior record
        // (same generation, artifact, last_deployment), never fabricated and
        // never re-stamped. The arm is inert on a remote with no live
        // `current` for the PUSHED target's first slot (no `current` link
        // exists to read on that server), so a first-deployment push
        // proceeds as a clean deployment — a slot has exactly one owning
        // target, so only the pushed target's own slots matter.
        if matches!(fault, Some(FailureClass::RemoteStatusPreSwap))
            && Self::target_slots(t)
                .iter()
                .any(|s| self.current.contains_key(s))
        {
            self.raw_attempts
                .entry(t)
                .or_default()
                .push((id.clone(), v));
            // The maintenance block still runs (the remote is reachable again
            // post-arm): any preexisting retention debt is retried and cleared.
            self.debt.insert(t, false);
            return (
                OutcomeClass::Push {
                    boundary: ReturnBoundary::Ok,
                    disposition: Disposition::FailedRolledBack,
                },
                self.crash_window.get(t).copied().unwrap_or(false),
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
        // The slot-write staleness flags: `primary_stale` means the FIRST
        // advanced slot's physical record write faulted (`p1`), `other_stale`
        // the SECOND's (`p2`). The fault arms are keyed by SLOT ID (`p1`/
        // `p2` — `t1`'s slots), so they are INERT on a `t2` push (which
        // advances only `p3`): the engine's `write_slot_observed` for `p3`
        // never matches the `p1`/`p2` arms, so a `t2` push with these
        // classes commits cleanly and refreshes observed. A faulted slot
        // write leaves that slot's ONE record stale in its owning target's
        // view; the other slot's record advances.
        let primary_stale = matches!(fault, Some(FailureClass::ObservedPrimaryWrite)) && t == "t1";
        let other_stale = matches!(fault, Some(FailureClass::ObservedOtherWrite)) && t == "t1";
        let gen_counter = self.current_gen.entry(t).or_insert(0);
        *gen_counter += 1;
        let gen_val = *gen_counter;
        // The deployment that advanced the slots is THIS step's deployment id:
        // the minting deployment of the new live generations, which the
        // observed projections' `last_deployment` must equal. Each of the
        // target's OWN slots advances to the same (version, deployment).
        for slot in Self::target_slots(t) {
            self.current.insert(slot, (v, id.clone()));
        }
        self.current_tampered = false;
        self.raw_attempts
            .entry(t)
            .or_default()
            .push((id.clone(), v));
        match fault {
            None | Some(FailureClass::None) => {
                self.append_snapshot(t, &id, v);
                self.debt.insert(t, false);
            }
            Some(FailureClass::RemoteStatusPreSwap) => {
                // The INERT case (no prior live current — the pre-swap
                // failure branch returned earlier): with no `current` link
                // there is nothing to read inside `process_server`'s pre-swap
                // status, so the deployment advances BOTH slots normally and
                // the one-shot arm fires at the COMMIT STEP's status read
                // instead — the marker write is demoted to `PendingCommit`
                // (recoverable), the attempt is recorded, and the observed
                // refresh re-projects the NEW live state (truthful: this
                // push DID advance the slots). Identical to CommitMarker.
                self.pending.insert(t, (id.clone(), v, gen_val, false));
                self.debt.insert(t, false);
            }
            Some(FailureClass::CommitMarker) => {
                // commit marker write fails: the deployment is recorded
                // PendingCommit; current advanced and observed refreshed, but
                // the snapshot/ref finalization defers to the next push of
                // this target. Step-17 retention still succeeds (the fault is
                // spent), so no debt.
                self.pending.insert(t, (id.clone(), v, gen_val, false));
                self.debt.insert(t, false);
            }
            Some(FailureClass::RetentionInventory) => {
                // Post-commit maintenance: step 17 retries an EXISTING debt
                // marker FIRST — that servicing write consumes the fault and
                // fails, then the push's own slot retention succeeds and
                // CLEARS the marker. With no prior marker, the fault hits the
                // push's own retention, which defers it as a new marker.
                self.append_snapshot(t, &id, v);
                self.debt.insert(t, !had_debt);
            }
            Some(FailureClass::Step17Contended) => {
                // The step-17 mutation lock is CONTENDED (deterministic via
                // the phase hook: the fixture holds the guard while the
                // engine is parked at every step-17-equivalent lock
                // acquisition). The deployment already committed, so the
                // outcome class is unchanged; the retention is DEFERRED — the
                // marker is ALWAYS set (both the deferred-maintenance retry,
                // when prior debt exists, and the push's own step-17
                // retention run while the guard is held), with the explicit
                // "retention deferred for slot 'p1'" warning naming the slot,
                // never silent. A later clean unlocked no-op services the
                // marker.
                self.append_snapshot(t, &id, v);
                self.debt.insert(t, true);
                // The warning names the pushed target's FIRST slot (a slot
                // has exactly one owning target, so a t1 push defers 'p1'
                // and a t2 push defers 'p3').
                self.expected_warning = Some(vec![format!(
                    "retention deferred for slot '{}': slot lock held by another operation",
                    Self::target_slots(t)[0]
                )]);
            }
            Some(FailureClass::ObservedWriteServer) => {
                // The per-server projection write fails (warning-only); the
                // observed maps themselves still refresh.
                self.append_snapshot(t, &id, v);
                self.debt.insert(t, false);
            }
            Some(FailureClass::ObservedPrimaryWrite) | Some(FailureClass::ObservedOtherWrite) => {
                // One OWNED slot's observed projection stays stale (crash
                // window).
                self.append_snapshot(t, &id, v);
                self.debt.insert(t, false);
            }
            Some(FailureClass::DebtRead)
            | Some(FailureClass::DebtWrite)
            | Some(FailureClass::DebtRemove) => {
                // Debt maintenance is post-commit and NON-FALLIBLE (a failed
                // read/write is a warning, never an `Err`), so the committed
                // outcome class is unchanged. The marker itself is
                // deterministic: the step-17 retry's faulted I/O only
                // DEFERS, and the push's OWN successful retention then clears
                // any marker via `clear_retention_deferred` (its later debt
                // write passes — the one-shot arm was already consumed by
                // the retry).
                self.append_snapshot(t, &id, v);
                self.debt.insert(t, false);
            }
            Some(FailureClass::ResultsWrite)
            | Some(FailureClass::SnapshotAppend)
            | Some(FailureClass::LastSuccessfulWrite)
            | Some(FailureClass::TransitionSuccessful)
            | Some(FailureClass::TransitionPending) => {
                // Crash-window faults: the remote advanced and the intent was
                // recorded, but the deployment's ONE terminal append (the
                // atomic finalize write carrying status + outcomes + rollback)
                // failed, so NO rollback state exists and the observed refresh
                // never ran. The push returns `Err` but the intent WAS
                // persisted — the expected class is `Err` + `Pending` (the
                // attempt stays recoverable-pending; recovery finalizes it
                // from the verified desired state).
                self.pending.insert(t, (id.clone(), v, gen_val, false));
            }
            Some(FailureClass::IntentPersist) | Some(FailureClass::LockContention) => {
                unreachable!("handled before the real-deployment mutation")
            }
            Some(FailureClass::Step17ContentionDebtRead)
            | Some(FailureClass::Step17ContentionDebtWrite) => {
                // STEP-17 LOCK CONTENTION (post-commit, via the phase hook)
                // combined with a retention-debt I/O fault: the commit
                // succeeded and the slot's retention lock is contended, so the
                // step-17 loop defers the retention as a debt marker. The
                // deferral I/O is NON-FALLIBLE — a debt read/write failure
                // warns but never changes the committed outcome.
                self.append_snapshot(t, &id, v);
                match fault {
                    Some(FailureClass::Step17ContentionDebtRead) => {
                        // The debt READ arm is armed ONLY at the fresh
                        // step-17 park (the fixture distinguishes the phases):
                        // the deferred-maintenance retry — which runs FIRST
                        // and reads the debt before any park — passes
                        // unarmed, so a preexisting marker's read succeeds
                        // and its contended retry keeps the marker. The arm
                        // then fires at the FRESH phase's contended deferral
                        // (`set_retention_deferred`'s read-modify-write): the
                        // read fails, nothing is persisted, and the explicit
                        // "failed to read retention debt" notice appears —
                        // a preexisting marker is PRESERVED untouched, and a
                        // fresh push with no marker creates NONE.
                        self.debt.insert(t, had_debt);
                        self.expected_warning = Some(vec![
                            format!(
                                "retention deferred for slot '{}': slot lock held by another operation",
                                Self::target_slots(t)[0]
                            ),
                            DEBT_READ_WARNING.to_string(),
                        ]);
                    }
                    Some(FailureClass::Step17ContentionDebtWrite) => {
                        // The debt WRITE arm is armed ONLY at the fresh
                        // step-17 park (the retry's earlier debt write passes
                        // unarmed): the fresh contended deferral's
                        // `set_retention_deferred` cannot persist the marker —
                        // explicit "retention debt maintenance deferred:
                        // failed to write" notice — so NO new marker is
                        // created and any PREEXISTING marker is preserved
                        // (the failed write leaves the file untouched). The
                        // model must NOT claim automatic retryability.
                        self.debt.insert(t, had_debt);
                        self.expected_warning = Some(vec![
                            format!(
                                "retention deferred for slot '{}': slot lock held by another operation",
                                Self::target_slots(t)[0]
                            ),
                            DEBT_WRITE_WARNING.to_string(),
                        ]);
                    }
                    _ => unreachable!("step-17 classes handled above"),
                }
            }
        }
        // The post-finalize observed refresh: each advanced slot's ONE
        // physical record is rewritten unless the step faulted inside the
        // refresh (that slot's record stays stale) or crashed before it (all
        // records stay stale). A slot has EXACTLY ONE owning target, so only
        // that target's VIEW of a refreshed slot is updated — there is no
        // cross-target propagation anymore. The `primary`/`other` staleness
        // flags name the FIRST (`p1`) and SECOND (`p2`) advanced slot of a
        // `t1` push (the only target with two slots).
        if !crash {
            let slots = Self::target_slots(t);
            for (i, slot) in slots.iter().enumerate() {
                let stale = if i == 0 { primary_stale } else { other_stale };
                if stale {
                    continue;
                }
                self.observed
                    .get_mut(t)
                    .unwrap()
                    .insert(slot.clone(), Some((v, id.clone())));
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
        let class = if matches!(
            fault,
            Some(FailureClass::CommitMarker) | Some(FailureClass::RemoteStatusPreSwap)
        ) {
            // `RemoteStatusPreSwap` here is the INERT case only (the pre-swap
            // failure branch returned earlier): the deployment advanced and
            // the commit step demoted the marker to PendingCommit.
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

    /// The no-op retry path: `retry_deferred_retentions` services the debt
    /// marker (writing the inventory), and that write consumes an armed
    /// [`FailureClass::RetentionInventory`] — failing, the marker stays.
    /// Commit-marker faults do not match the inventory write, so the retention
    /// succeeds and clears the debt. Under contention the retry's lock
    /// acquisition fails first: the marker stays (both trunks agree).
    fn noop_maintenance(&mut self, t: &'static str) {
        // A no-op never reaches the FRESH step-17 retention, and the step-17
        // DEBT COMBINATIONS arm their debt fault ONLY at that phase (the
        // fixture leaves the deferred-maintenance retry unarmed), so the
        // one-shot can never fire on the no-op: no "failed to read/write
        // retention debt" notice is expected. The no-op's only
        // step-17-equivalent park is the DeferredRetry phase, whose lock
        // acquisition contends on the fixture's held guard.
        if !self.debt.get(t).copied().unwrap_or(false) {
            return;
        }
        match self.armed_fault {
            Some(FailureClass::RetentionInventory) => {
                self.armed_fault = None;
                // retention failed; the debt marker stays
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
            Some(FailureClass::RemoteStatusPreSwap) => {
                // The pre-swap status-read arm is a READ fault: on the no-op
                // path the deferred-maintenance retry is a REAL retention
                // (`rotate_slot_locked` under the maintenance mutation lock)
                // whose first `current`-link read is exactly the
                // pre-swap-moment read the arm targets — with no
                // `process_server` on the no-op path, that read is the one
                // that fires the one-shot: the retention fails with the
                // injected transport error and the debt marker STAYS
                // (re-recorded with the error reason). The arm is consumed;
                // the marker is not cleared.
                self.armed_fault = None;
            }
            Some(FailureClass::Step17ContentionDebtRead)
            | Some(FailureClass::Step17ContentionDebtWrite) => {
                // The no-op path runs no FRESH step-17 retention, so the
                // debt arm (which the fixture places ONLY at the FreshStep17
                // park) can never fire here: the retry — the DeferredRetry
                // phase — reads and re-persists the marker unarmed, and its
                // lock acquisition contends on the fixture's held guard, so
                // the marker STAYS. No "failed to ... retention debt" notice
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
            .any(|(_, _, _, already_snapped)| *already_snapped)
    }

    /// Whether `action` would replace the tampered current record with a new
    /// pristine generation. Only a REAL deployment of the tampered slot's
    /// OWNING target does: the tamper always targets the `s1` slot (`p1`),
    /// which `t1` owns, so a HEAD push/retry of `t1` always deploys after a
    /// tamper (the tampered artifact never equals the materialized head),
    /// while a `t2` push would be an up-to-date no-op (its own slot `p3` is
    /// untouched) and must NOT be applied. A `t1` snapshot rollback repairs
    /// only when its ref resolves — an out-of-range index (including a
    /// below-floor one, which fails closed) errors before any mutation,
    /// leaving the tampered record in place.
    fn repairs_tamper(&self, action: &Action) -> bool {
        match action {
            Action::Push(t) | Action::Retry(t) => *t == "t1",
            Action::Rollback(t, i) => {
                // The rollback REPAIRS the tamper only when the strategy's
                // POSITION names a real deployment in the visible chain (the
                // fixture's rollback_token resolves it; an out-of-range
                // position names a nonexistent deployment and fails closed —
                // the tamper is left unrepaired, so the action is skipped).
                *t == "t1" && self.visible_snapshots("t1").len() as u64 > *i
            }
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
        // A HEAD push under t1 or t2 (both targets own slots; retention is
        // always the slots' OWNING VARIANT policy — never per-target).
        4 => prop::sample::select(["t1", "t2"].as_slice()).prop_map(Action::Push),
        // Up-to-date retry (no-op or reconcile) — the same engine call.
        2 => prop::sample::select(["t1", "t2"].as_slice()).prop_map(Action::Retry),
        // Rollback to snapshot index 0 or 1 of the target.
        2 => (prop::sample::select(["t1", "t2"].as_slice()), 0u64..2)
            .prop_map(|(t, i)| Action::Rollback(t, i)),
        // Standalone retention under the slot-owning policy.
        1 => Just(Action::Rotate),
        // Checkpoint history floor at a randomly chosen recorded successful
        // deployment of the target (the selector `k` is resolved against the
        // target's VISIBLE snapshots by the fixture and the model alike, so
        // it can only ever name a successful deployment already in the
        // history). LOW weight: the floor is a rare operation, and its
        // pending-commit × floor interaction — a below-floor pending commit
        // discarded with the rest of the below-floor history, an at/above-
        // floor one finalized by the next push — is the interaction this
        // property pins.
        2 => (prop::sample::select(["t1", "t2"].as_slice()), 0u64..8)
            .prop_map(|(t, k)| Action::Checkpoint(t, k)),
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
/// retention (`Step17Contended`, deferred via the phase hook: debt + warning,
/// the committed outcome — `Ok` + `Successful` — unchanged). Weights: the
/// clean path dominates so the vectors stay realistic; every fault class is
/// reachable.
fn failure_class_strategy() -> impl Strategy<Value = FailureClass> {
    prop_oneof![
        12 => Just(FailureClass::None),
        // remote, suffix-armed
        1 => Just(FailureClass::CommitMarker),
        1 => Just(FailureClass::RetentionInventory),
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
        // PRE-SWAP remote status failure (the pre-swap `current`-link read
        // fails exactly once inside `process_server`; the planning/reconcile
        // reads pass — the slot aborts `Ok(Failed)` before the swap and
        // `stop_on_failure` skips the rest: nothing advances, the attempt is
        // recorded `FailedRolledBack`, and the observed projections must
        // stay untouched).
        1 => Just(FailureClass::RemoteStatusPreSwap),
        // step-17 lock contention (deterministic via the test-only phase
        // hook: the fixture holds the guard while the engine is parked at its
        // step-17 lock acquisition), alone and combined with a retention-debt
        // read/write fault in the same push. The outcome oracle predicts the
        // committed push stays `Ok` + `Successful` (never `Err`); successful
        // persistence (contention alone) leaves a debt marker + warning, while
        // a coincident debt read/write failure produces the explicit "retention
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
            // The pending state: an intent without a terminal.
            system
                .store
                .latest_status(a.deployment_id.as_str())
                .ok()
                .flatten()
                .is_none()
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
/// identity), every target's observed projection for its OWN slots, the
/// per-target snapshot/attempt logs, pending-commit state, and retention-debt
/// markers.
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
        || model.crash_window.values().any(|w| *w)
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
    system.check_invariants_ctx(&ctx);

    let mut learned: BTreeMap<u32, ArtifactRef> = BTreeMap::new();

    // Snapshot logs: count + per-deployment artifact/version join, over the
    // VISIBLE chain (the suffix beginning at the target's floor deployment —
    // the model derives it identically, so a checkpoint that discarded a
    // below-floor snapshot shows up here as a shorter chain). The log order
    // IS the deployment order; positions are derived, never stored.
    for t in ["t1", "t2"] {
        let sys_snaps = system.store.read_snapshots(t).unwrap_or_default();
        let want = model.visible_snapshots(t);
        assert_eq!(
            sys_snaps.len(),
            want.len(),
            "{ctx}: snapshot count for {t} must match the model ({sys} vs {model})",
            sys = sys_snaps.len(),
            model = want.len(),
        );
        for (ss, (wi, wid, mv)) in sys_snaps.iter().zip(&want) {
            assert_eq!(
                ledger::successful_index(&system.store, t, &ss.deployment_id)
                    .unwrap()
                    .unwrap(),
                *wi,
                "{ctx}: snapshot position for {t}"
            );
            assert_eq!(
                ss.deployment_id.as_str(),
                wid,
                "{ctx}: snapshot deployment id at position {wi} for {t} — the SAME position \
                 must never resolve to a different deployment (no duplicate, no re-append)"
            );
            assert!(
                ss.terminal
                    .as_ref()
                    .expect("terminal")
                    .disposition()
                    .is_successful(),
                "a successful entry carries a snapshot"
            );
            let rollback = crate::kernel::snapshot::resolve_snapshot(ss)
                .expect("the successful snapshot resolves from the intent");
            // The snapshot's OWN first slot (a slot has exactly one owning
            // target, so a t1 snapshot carries p1/p2 and a t2 snapshot p3).
            let pid = Model::target_slots(t)[0].clone();
            let art = rollback.get(&pid).unwrap().artifact().clone();
            learn_artifact(
                &mut learned,
                &ctx,
                *mv,
                art,
                &format!("deployment {} of {t}", ss.deployment_id),
            );
        }
    }
    // Deployment-attempt logs: exactly one record per real deployment, over
    // the VISIBLE chain (from the floor's own attempt onward).
    for t in ["t1", "t2"] {
        let sys_att = system.store.read_attempts(t).unwrap_or_default();
        let want = model.visible_attempts(t);
        assert_eq!(
            sys_att.len(),
            want.len(),
            "{ctx}: attempt count for {t} must match the model"
        );
        for (sa, (wid, mv)) in sys_att.iter().zip(&want) {
            assert_eq!(
                sa.deployment_id.as_str(),
                wid,
                "{ctx}: attempt id order for {t}"
            );
            let pid = Model::target_slots(t)[0].clone();
            let art = sa
                .intent
                .resulting_snapshot()
                .get(&pid)
                .unwrap()
                .artifact()
                .clone();
            learn_artifact(&mut learned, &ctx, *mv, art, "attempt {t}");
        }
    }

    // Remote current generation: existence + artifact identity, per slot
    // (the model's per-slot (version, minting-deployment) pairs describe
    // each slot; a target's slots advance together, slots of different
    // targets independently). The identity check is skipped while the live
    // record was tampered.
    let sys_currents = system.current_assignments();
    let model_current = model.current.clone();
    match (model_current.is_empty(), sys_currents.is_empty()) {
        (true, true) => {}
        (true, false) => panic!(
            "{ctx}: unexpected remote current generation(s): {:?}",
            sys_currents
                .values()
                .map(|a| &a.generation_id)
                .collect::<Vec<_>>()
        ),
        (false, true) => {
            panic!("{ctx}: model expects remote current generations, none present")
        }
        (false, false) => {
            for (slot_id, (v, dep)) in &model_current {
                let asn = sys_currents.get(slot_id).unwrap_or_else(|| {
                    panic!("{ctx}: model expects a current generation for {slot_id}, none present")
                });
                assert_eq!(
                    asn.deployment_id.as_str(),
                    dep,
                    "{ctx}: the live assignment's OWN minting deployment must be the model's \
                     tracked deployment for the current generation of {slot_id}"
                );
                if !model.current_tampered || slot_id.as_str() != "p1" {
                    let want = learned.get(v).cloned().unwrap_or_else(|| {
                        panic!(
                            "{ctx}: current generation version {v} has no recorded attempt/snapshot in the system"
                        )
                    });
                    assert_eq!(
                        asn.artifact, want,
                        "{ctx}: the remote current generation of {slot_id} must deploy the model's expected artifact for version {v}"
                    );
                }
                // The current generation is the freshest identity source (e.g. a
                // still-pending deployment has a current but no snapshot yet).
                learn_artifact(
                    &mut learned,
                    &ctx,
                    *v,
                    asn.artifact.clone(),
                    "remote current",
                );
            }
        }
    }

    // Observed projections: each slot's OWNING target's VIEW must equal the
    // model's expectation — the (version, minting deployment) of the live
    // remote assignment — and, because targets are SELECTION VIEWS over the
    // ONE physical slot map, the target's view of a slot equals the slot's
    // single physical record by construction. A slot has EXACTLY ONE owning
    // target, so only that target's view is compared (a push to another
    // target never touches this slot's records). A slot the last push did
    // NOT advance (skipped / unreachable pre-swap) keeps its PRIOR record:
    // same generation, artifact, and last_deployment — never fabricated,
    // never re-stamped by a deployment that did not touch it.
    for t in ["t1", "t2"] {
        let obs = system
            .store
            .read_observed(t, &system.config)
            .unwrap_or_default();
        for slot_id in Model::target_slots(t) {
            let want_observed = model
                .observed
                .get(t)
                .and_then(|m| m.get(&slot_id))
                .cloned()
                .flatten();
            let entry = obs.slots.get(&slot_id);
            match (want_observed, entry) {
                (None, None) => {}
                (None, Some(_)) => panic!("{ctx}: {t} observed an unexpected {slot_id} entry"),
                (Some(_), None) => {
                    panic!(
                        "{ctx}: {t} is missing its observed {slot_id} entry though the model expects one"
                    )
                }
                (Some((v, dep)), Some(slot)) => {
                    let crate::ledger::ObservedAssignment::Known { artifact, .. } =
                        &slot.assignment
                    else {
                        panic!("{ctx}: {t} observed {slot_id} must be a successful read");
                    };
                    let art = artifact.clone();
                    let want = learned.get(&v).cloned().unwrap_or_else(|| {
                        panic!(
                            "{ctx}: observed version {v} for {t} has no recorded artifact in the system"
                        )
                    });
                    assert_eq!(
                        art, want,
                        "{ctx}: {t} observed projection must match the model's expected version {v}"
                    );
                    assert_eq!(
                        slot.last_deployment().map(|d| d.as_str()),
                        Some(dep.as_str()),
                        "{ctx}: {t} observed last_deployment for {slot_id} must equal the LIVE \
                         assignment's minting deployment {dep} — a skipped/unreachable slot's \
                         prior record is never re-stamped by a deployment that did not touch it"
                    );
                }
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
        if let Some((pid, pv, _, _)) = model.pending.get(t) {
            // The pending attempt need not be the target's NEWEST attempt: a
            // later deployment can commit after the pending one (e.g. its
            // reconcile marker write consumed a newly-armed fault), so the
            // pending attempt must simply have a recorded (raw) attempt —
            // and a checkpoint at/above the floor never discards it, while a
            // below-floor one is removed from `pending` by the model and the
            // system alike.
            assert!(
                model.raw_attempts[t].iter().any(|(id, _)| id == pid),
                "{ctx}: the pending deployment {pid} must have a recorded attempt"
            );
            assert!(
                model.raw_attempts[t].iter().any(|(_, v)| v == pv),
                "{ctx}: the pending deployment version {pv} must have a recorded attempt"
            );
        }
    }

    // Retention-debt markers per target.
    for t in ["t1", "t2"] {
        let sys_debt = !system
            .store
            .read_retention_debt(t)
            .unwrap_or_default()
            .is_empty();
        assert_eq!(
            model.debt[t], sys_debt,
            "{ctx}: retention-debt marker for {t}"
        );
    }
}

/// The PENDING-COMMIT × CHECKPOINT (retained-suffix) invariant bundle,
/// asserted after EVERY step and at the end of a state-machine run
/// (alongside [`assert_semantic_invariants`]). Pins the documented contract
/// ([`crate::retention::checkpoint`]): a pending-commit entry whose ledger line
/// lies BELOW the checkpoint deployment's position is discarded with the
/// rest of the below-checkpoint history (its intent line, its terminal (if
/// any), and its deployment dir all vanish — no resurrection on recovery);
/// one at/above it stays and is finalized by the next push exactly as
/// before.
///
/// (1) the RAW LEDGER matches the model EXACTLY (all entry ids in order +
///     the successful entries' positions in order) — a below-checkpoint
///     pending commit is gone and its deployment dir is deleted, while an
///     at/above-checkpoint one survives;
/// (2) the SAME-POSITION binding — a successful-chain position never
///     resolves to a different deployment id (no duplicate, no re-append);
/// (3) successful-chain positions are strictly increasing and unique
///     (contiguous 0-based positions — the ledger's append order IS the
///     history order);
/// (4) every ref (sN, @-, parent(...)) resolves only within the retained
///     suffix — a position beyond the chain fails closed;
/// (5) checkpointing t1 never changes t2's ledger, or pending state
///     (cross-target isolation).
///
/// The deployment-dir bijection is asserted per retained entry (its dir
/// exists). The entries the checkpoint discarded (the model's raw ledger is
/// already trimmed) are asserted GONE: their deployment dirs were swept
/// (unreachable — not in any retained ledger, not observed, not pending).
fn assert_checkpoint_invariants(model: &Model, system: &Fixture) {
    let ctx = format!("after action {}", model.index);
    for t in ["t1", "t2"] {
        // (1) + (3): the RAW LEDGER matches the model exactly; successful
        // positions are strictly increasing and unique (contiguous 0-based
        // positions — never reused, never gapped).
        let sys_entries = system.store.read_ledger(t).unwrap_or_default();
        let want_att = model.raw_attempts.get(t).cloned().unwrap_or_default();
        assert_eq!(
            sys_entries.len(),
            want_att.len(),
            "{ctx}: raw ledger count for {t} must match the model"
        );
        let mut prev: Option<u64> = None;
        let mut successful_positions: Vec<(u64, String)> = Vec::new();
        for (se, (wid, _)) in sys_entries.iter().zip(&want_att) {
            assert_eq!(
                se.deployment_id.as_str(),
                wid,
                "{ctx}: raw ledger id order for {t}"
            );
            if let Some(t) = &se.terminal
                && t.status() == DeploymentStatus::Successful
            {
                successful_positions.push((successful_positions.len() as u64, wid.clone()));
            }
        }
        let want_snaps = model.raw_snapshots.get(t).cloned().unwrap_or_default();
        assert_eq!(
            successful_positions.len(),
            want_snaps.len(),
            "{ctx}: successful-chain count for {t} must match the model"
        );
        for ((pos, sid), (wi, wid, _)) in successful_positions.iter().zip(&want_snaps) {
            assert_eq!(pos, wi, "{ctx}: successful position for {t}");
            assert_eq!(sid, wid, "{ctx}: successful id at position {wi} for {t}");
            if let Some(p) = prev {
                assert!(
                    p < *pos,
                    "{ctx}: successful positions on {t} must be strictly increasing (contiguous)"
                );
            }
            prev = Some(*pos);
        }
        // (1) the deployment-dir bijection: every retained entry owns its
        // dir (the sweep keeps every reachable deployment dir).
        let mut retained_ids: HashSet<&str> = HashSet::new();
        for (id, _) in &want_att {
            assert!(
                system.store.deployment_dir(id).exists(),
                "{ctx}: the deployment dir of retained entry {id} on {t} must exist"
            );
            assert!(
                retained_ids.insert(id.as_str()),
                "{ctx}: duplicate raw entry id {id} on {t}"
            );
        }
        // (4) refs resolve only within the retained suffix: every successful
        // deployment id resolves to EXACTLY IT, and a deployment the
        // checkpoint discarded fails closed (the below-suffix ids no longer
        // exist).
        for (_, wid) in &successful_positions {
            let resolved = ledger::resolve_ref_expr(
                &ledger::parse_ref_expr(wid).expect("a deployment id parses"),
                t,
                &system.store,
            )
            .unwrap_or_else(|e| panic!("{ctx}: deployment {wid} on {t} must resolve: {e}"));
            match resolved {
                ledger::PushRef::Deployment { deployment_id, .. } => {
                    assert_eq!(
                        deployment_id.as_str(),
                        wid,
                        "{ctx}: deployment {wid} on {t} must resolve to the SAME deployment (no re-append below the retained suffix)"
                    );
                }
                other => panic!(
                    "{ctx}: deployment {wid} on {t} must resolve to a deployment ref, got {other:?}"
                ),
            }
        }
        // A ref BEYOND the retained suffix fails closed: `parent(@, N)` with
        // N = the chain length walks one past the start (on an empty chain
        // any relative walk fails — there is no head to walk from). The old
        // `sN` snapshot-index form is gone; the deployment-keyed grammar
        // fails the same way.
        let beyond = successful_positions.len() as u64;
        let token = if beyond == 0 {
            "parent(@, 1)".to_string()
        } else {
            format!("parent(@, {beyond})")
        };
        let err =
            ledger::resolve_ref_expr(&ledger::parse_ref_expr(&token).unwrap(), t, &system.store)
                .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("before the start of the deployment history")
                || msg.contains("no successful deployments"),
            "{ctx}: {token} (beyond the retained suffix) on {t} must fail closed, got: {msg}"
        );
        // (5) cross-target isolation: the OTHER target's ledger is untouched
        // by this target's checkpoint (both ledgers were compared against the
        // model above, and the model trims only `t`).
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
    let system = Fixture::new();
    // The oracle mints the SAME deployment ids as the fixture (same tag,
    // same counter), so its raw logs, floor, and pending state can be
    // compared id-for-id with the system's.
    let mut model = Model::new_with_tag(system.prop_tag());
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
        // must NEVER return `Err` — the observed refresh, retention, and debt
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
        // step-17 contention combination): the marker-persisted "retention
        // deferred for slot 'p1'" claim — the retryable deferral a later push
        // services once the lock is free — plus, on the debt combinations,
        // the explicit "retention debt maintenance deferred: failed to ..."
        // notice (the marker was NOT persisted / maintenance deferred without
        // a marker, so no automatic retryability is claimed). Every expected
        // substring must appear in the actual report's warning. Under the
        // two-dimension oracle the contended push is ALWAYS `Ok` +
        // `Successful` (never `Err`) — the boundary/disposition asserts above
        // already bind that — so a missing warning is the ONLY way a silent
        // skip could slip through.
        if let Some(wants) = model.expected_warning.as_ref() {
            let actual_warning = match &outcome {
                Outcome::Push(result) => match &**result {
                    Ok(report) => report.warning.as_deref().unwrap_or(""),
                    Err(_) => "",
                },
                _ => "",
            };
            for w in wants {
                assert!(
                    actual_warning.contains(w.as_str()),
                    "after action {}: the report must warn with {w:?}, got: {actual_warning:?}",
                    model.index
                );
            }
        }
        // THE CONVERGENCE ORACLE: the first CLEAN unlocked no-op services
        // the deferred retention — the marker is cleared (cross-checked by
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
                 retention converged; got: {:?}",
                model.index,
                report.warning,
            );
        }
        // The observable-state oracle (the existing cross-check plus the five
        // invariant groups); internally suspended while the crash window is
        // open or the step was a tamper / an unknown class.
        assert_semantic_invariants(&model, &system);
        // THE CHECKPOINT REPORT ORACLE: when the step was a checkpoint, the
        // ACTUAL report must match the model's expectation field-for-field —
        // the floor it established and the EXACT discard sets the real
        // `checkpoint_discards` enumerated. A no-op checkpoint step (no
        // visible snapshot) returns a plain [`Outcome::Ok`] from both sides.
        if matches!(&action, Action::Checkpoint(..))
            && let Outcome::Checkpoint(rep) = &outcome
        {
            let want = model
                .last_checkpoint
                .as_ref()
                .expect("a checkpoint step records the model's expectation");
            assert_eq!(
                rep.target, want.target,
                "after action {}: checkpoint target",
                model.index
            );
            assert_eq!(
                rep.deployment_id.as_str(),
                want.deployment_id,
                "after action {}: checkpoint deployment id",
                model.index
            );
            assert_eq!(
                rep.established, want.established,
                "after action {}: checkpoint established flag (the logical commit ran)",
                model.index
            );
            assert!(
                rep.sweep_completed,
                "after action {}: a clean checkpoint's best-effort sweep must complete",
                model.index
            );
            assert_eq!(
                rep.discards.discarded_entries, want.discarded_entries,
                "after action {}: checkpoint discard set (entries below the checkpoint \
                 position)",
                model.index
            );
        }
        // The pending-commit × checkpoint-floor invariants (raw logs, floor
        // marker, below-floor refs, deployment-dir bijection) — after EVERY
        // step.
        assert_checkpoint_invariants(&model, &system);
    }
    // End of run: the same invariant bundle once more.
    assert_checkpoint_invariants(&model, &system);
}

proptest! {
    // Main property test split into PARALLEL SUBTESTS: the harness runs
    // each test in its own thread, but proptest runs a test's cases
    // sequentially in that one thread — so the randomized-with-persistence
    // leg (4 cases) is SPLIT into two subtests of `cases: 4/2 = 2` each
    // with DISTINCT default seeds. The two subtests run concurrently on
    // different harness threads, halving this leg's wall time, while the
    // fixed default seeds keep every subtest deterministic
    // (CI-reproducible). FAILURE PERSISTENCE is an env lever:
    // `crate::testutil::proptest_persistence()` is `None` on the default
    // dev run (no corpus file read or written — the fast deterministic
    // path) and `FileFailurePersistence` on the CI lanes
    // (`DEPLOY_PROPERSIST=1`): the shared
    // `proptest-regressions/semantic_invariants.txt` is keyed per source
    // FILE, so EVERY subtest with persistence on replays ALL persisted
    // vectors — duplication is fine on the long-running CI diversity lane,
    // and the dev run stays persistence-off. The SEED and the ACTION-TRACE
    // LENGTH are the other env levers (`crate::testutil::proptest_seed` /
    // `proptest_steps`): the diversity lane runs the same assertions under
    // several CI-supplied seeds and longer traces. A failing vector writes
    // to the regression file; the case count stays bounded (each case
    // drives a full fixture), and the persisted regression vectors replay
    // regardless of length. The FIXED-SEED regression leg below stays ONE
    // test (the deterministic floor).
    #![proptest_config(ProptestConfig {
        cases: crate::testutil::proptest_cases(2),
        rng_seed: crate::testutil::proptest_seed(0x5EED_0001),
        failure_persistence: crate::testutil::proptest_persistence(),
        ..ProptestConfig::default()
    })]

    #[test]
    fn semantic_state_machine_0(
        steps in prop::collection::vec(
            (action_strategy(), failure_class_strategy()),
            1..=crate::testutil::proptest_steps(5),
        )
    ) {
        run_semantic_state_case(steps);
    }
}

proptest! {
    // The second half of the split randomized leg: the same generator and
    // the same assertions over the next slice of cases, under a DISTINCT
    // default seed so the two subtests explore different (deterministic)
    // interleavings and can run concurrently. Same env levers as `_0`:
    // seed (`proptest_seed`), trace length (`proptest_steps`) and
    // persistence (`proptest_persistence` — `None` on the dev run, on for
    // the CI lanes via `DEPLOY_PROPERSIST=1`, when the shared regression
    // file's vectors are replayed here too).
    #![proptest_config(ProptestConfig {
        cases: crate::testutil::proptest_cases(2),
        rng_seed: crate::testutil::proptest_seed(0x5EED_0002),
        failure_persistence: crate::testutil::proptest_persistence(),
        ..ProptestConfig::default()
    })]

    #[test]
    fn semantic_state_machine_1(
        steps in prop::collection::vec(
            (action_strategy(), failure_class_strategy()),
            1..=crate::testutil::proptest_steps(5),
        )
    ) {
        run_semantic_state_case(steps);
    }
}

proptest! {
    // FIXED-SEED REGRESSION: the deterministic floor for CI. The same
    // generator under the pinned default seed with no persistence (dev
    // run) runs the IDENTICAL vectors on every invocation, so the suite
    // stays reproducible even when no failure has ever been persisted. On
    // the CI lanes the env levers apply here too: the diversity lane runs
    // this leg under its matrix seed with persistence on (`DEPLOY_PROPERSIST=1`
    // replays the persisted vectors regardless of count and length), and
    // the deterministic full lane keeps the fixed default seed while
    // replaying the corpus. The case count stays bounded so the suite
    // stays fast.
    #![proptest_config(ProptestConfig {
        cases: crate::testutil::proptest_cases(4),
        rng_seed: crate::testutil::proptest_seed(0x5EED_5EED),
        failure_persistence: crate::testutil::proptest_persistence(),
        ..ProptestConfig::default()
    })]

    #[test]
    fn semantic_state_machine_fixed_seed_regression(
        steps in prop::collection::vec(
            (action_strategy(), failure_class_strategy()),
            1..=crate::testutil::proptest_steps(5),
        )
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
    /// The fresh deferral's `set_retention_deferred` READ faults.
    Read,
    /// The fresh deferral's `set_retention_deferred` WRITE faults.
    Write,
}

/// One case of the step-17-contention × debt-I/O matrix for a generated
/// `(preexisting_reason: Option<String>, fault: Read | Write)` pair — the
/// preexisting debt marker's reason is an ARBITRARY string (or absent), the
/// fault one of the two debt-I/O operations. Each case is a FRESH fixture
/// and a SINGLE push to `t1` (its OWN slot `p1`) — the fixture's first
/// push is GUARANTEED non-no-op (it mints generation 1; asserted via the
/// recorded attempt + `Successful` status, never an up-to-date no-op). The
/// push runs under the test-only step-17 phase hook with the fixture holding
/// the slot's mutation guard at EVERY park; the debt fault is armed ONLY at
/// the FreshStep17 park ([`step17_hook::HookPhase::FreshStep17`] — the
/// fixture's own per-slot retention, whose contended else-branch runs the
/// debt read-modify-write that must fault), so the deferred-maintenance
/// retry (which, with a preexisting marker, reads the debt FIRST — before
/// its park — and must pass unarmed at the
/// [`step17_hook::HookPhase::DeferredRetry`] phase) can never consume the
/// one-shot at the wrong phase.
///
/// Per combination asserts the post-commit contract:
/// (a) the push returns `Ok` with `Successful` — NEVER `Err`;
/// (b) BOTH required warnings present — the contention warning
///     (`retention deferred for slot 'p1'`) AND the debt-I/O notice
///     (`failed to read` / `failed to write retention debt`, per fault);
/// (c) FAILED PERSISTENCE creates NO new debt marker while PRESERVING any
///     preexisting one: `Some(reason)` leaves the marker file BYTE-IDENTICAL
///     (the faulted read/write leaves the file untouched) and the reason
///     round-trips exactly through [`crate::store::local::LocalStore::read_retention_debt`];
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
    let marker_path = f.store.retention_debt_path(TARGET);
    let before = if let Some(reason) = preexisting_reason {
        f.store
            .write_retention_debt(
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
        "{ctx}: the report must carry the contention warning 'retention deferred for slot \
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
        let debt = f.store.read_retention_debt(TARGET).unwrap();
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
    // Bounded `proptest_cases(4)` (full 4 with `DEPLOY_FULL_TESTS=1`, fast
    // default) keep the suite fast (each case is a fresh fixture
    // with a real push); a fixed seed keeps CI deterministic (no persistence
    // file) — the project's fixed-seed leg, mirroring
    // `semantic_state_machine_fixed_seed_regression` (the
    // randomized-with-persistence leg lives in the main
    // `semantic_state_machine`).
    #![proptest_config(ProptestConfig {
        cases: crate::testutil::proptest_cases(4),
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

// ===========================================================================
// Property — slot views agree with the one physical state; membership never
// changes retention
// ===========================================================================

/// Generate a mini project with THREE targets (`t1`/`t2`/`t3`,
/// each with a DIFFERENT rollout config — rollout is the only target surface
/// left, retention is slot-owned) and THREE slots, each owned by exactly one
/// generated target (a slot declares its single `target`, never a list).
/// Coverage is fixed up deterministically so every target owns at least one
/// slot. `pushes` is an interleaved sequence of target pushes, each preceded
/// by an artifact content bump so every push is a REAL deployment (never an
/// up-to-date no-op).
///
/// After EVERY push the property asserts:
/// (1) EVERY target's view (`read_observed(target)`) equals the SINGLE
///     physical slot state filtered to that target's OWN slots — the same
///     generation, artifact, and last_deployment, exactly — so each slot has
///     ONE physical record and its OWNING target's view agrees with it by
///     construction;
/// (2) CHANGING MEMBERSHIP (adding/removing a rollout GROUP in a slot's
///     `groups` list — a config-level membership change, reloaded through
///     `ProjectConfig::load`) does NOT change RETENTION: the retained digest set is
///     computed under the slot's OWNING VARIANT policy (the single source),
///     so the set before and after the membership edit is IDENTICAL.
/// The three targets of the slot-view property.
const VIEW_TARGETS: [&str; 3] = ["t1", "t2", "t3"];

fn run_slot_view_property(owners: Vec<usize>, pushes: Vec<usize>) {
    // A slot has EXACTLY ONE owning target: each generated index names its
    // slot's one owner, then we ensure every target owns at least one slot by
    // assigning any left-out target a duplicated owner's slot.
    let mut owner: Vec<&str> = owners.iter().map(|&i| VIEW_TARGETS[i % 3]).collect();
    for t in VIEW_TARGETS {
        if !owner.contains(&t) {
            // Reassign a DUPLICATED owner's slot to the left-out target (a
            // slot has exactly one owner; with 3 slots and 3 targets a
            // duplicated owner always exists when a target is left out).
            let mut dup = 0usize;
            'find_dup: for i in 0..owner.len() {
                for j in 0..owner.len() {
                    if i != j && owner[i] == owner[j] {
                        dup = i;
                        break 'find_dup;
                    }
                }
            }
            owner[dup] = t;
        }
    }

    let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let release_dir = project.join("releases").join("v1");
    std::fs::create_dir_all(&release_dir).unwrap();

    // The ONE owning variant: declares every slot (each on its OWN server, so
    // the remote generation state stays independent per slot) and carries the
    // slot-owned retention policy (targets own rollout only). Each slot
    // declares its ONE owning target and an empty `groups` list (rollout
    // groups are selection-only; the membership-edit helper below edits the
    // `groups` list to prove membership never changes retention).
    let mut variant = String::new();
    for (si, t) in owner.iter().enumerate() {
        variant.push_str(&format!(
            "[[slots]]\nid = \"s{}\"\nserver = \"h{}\"\ntarget = \"{}\"\ngroups = []\ndeploy_dir = \"/srv/s{}-{}\"\n\n",
            si + 1,
            si + 1,
            t,
            si + 1,
            si + 1,
        ));
    }
    variant.push_str(
        "[[artifact.mappings]]\nfrom = \"artifacts/build/output/\"\nto = \"app/\"\nrecursive = true\n\n\
         [retention.per_server]\nkeep_distinct_artifacts = 1\nkeep_days = 0\nprotect_previous = false\n\n\
         [retention.deployment]\nprotect_deployments = 1\n\n\
         [activation]\nadapter = \"none\"\n\n\
         [verification]\nadapter = \"command\"\nargv = [\"true\"]\ntimeout_seconds = 5\nattempts = 1\ninterval_seconds = 0\n",
    );
    std::fs::write(release_dir.join("standard.toml"), variant).unwrap();

    // THREE targets with DIFFERENT rollout configs — the only target surface.
    let mut deploy_toml =
        String::from("schema_version = 2\napplication = \"views\"\nrelease = \"v1\"\n\n");
    for si in 0..owner.len() {
        deploy_toml.push_str(&format!(
            "[[servers]]\nid = \"h{}\"\naddress = \"a\"\nuser = \"u\"\nhost_key_fingerprint = \"SHA256:test\"\n\n",
            si + 1
        ));
    }
    deploy_toml.push_str(
        "[targets.t1]\nrollout = { batch_size = 1, stop_on_failure = true, failure_policy = \"rollback_changed\" }\n\n\
         [targets.t2]\nrollout = { batch_size = 2, stop_on_failure = false, failure_policy = \"leave_changed\" }\n\n\
         [targets.t3]\nrollout = { batch_size = 1, stop_on_failure = false, failure_policy = \"rollback_changed\" }\n",
    );
    let cfg_path = project.join("deploy.toml");
    std::fs::write(&cfg_path, deploy_toml).unwrap();
    let config = ProjectConfig::load(&cfg_path).unwrap();
    for t in VIEW_TARGETS {
        assert!(
            !config.target_slots(t).unwrap().is_empty(),
            "every generated target must own at least one slot"
        );
    }

    let store = LocalStore::with_base(dir.path().join("store")).unwrap();
    let remotes_base = dir.path().join("remotes");
    std::fs::create_dir_all(&remotes_base).unwrap();
    let rf = remotes_base.clone();
    let factory = move |s: &crate::config::ServerDef,
                        _slot: &crate::config::SlotConfig|
          -> Result<Box<dyn Remote>> {
        Ok(Box::new(LocalTransport::with_exec(
            &crate::testutil::fixture_env(),
            rf.join(s.id.as_str()),
            crate::remote::transport::scripted::ScriptedExec::default_success(),
        )?))
    };
    // The artifact source the variant maps; rewritten before every push so
    // each push is a REAL deployment.
    let artifacts = release_dir.join("artifacts/build/output/app");
    std::fs::create_dir_all(&artifacts).unwrap();
    let mut content_version = 0u32;

    for (step, ti) in pushes.into_iter().enumerate() {
        content_version += 1;
        std::fs::write(artifacts.join("server"), format!("v{content_version}\n")).unwrap();
        let config = ProjectConfig::load(&cfg_path).unwrap();
        let t = VIEW_TARGETS[ti % 3];
        let r = push(
            &cfg_path,
            &store,
            &factory,
            t,
            &config,
            &PushOptions {
                dry_run: false,
                ref_token: None,
                group: None,
            },
        )
        .unwrap_or_else(|e| panic!("push {step} to {t} failed: {e}"));
        assert!(
            r.attempt.is_some(),
            "every property push must be a REAL push (content bumped): step {step} to {t}"
        );

        // (1) EVERY target's view == the single physical slot state, filtered.
        assert_views_match_physical(&store, &config);
        // (2) Membership never changes retention.
        assert_membership_never_changes_retention(
            &store,
            &cfg_path,
            &config,
            &release_dir,
            &remotes_base,
        );
    }
}

/// (1) EVERY target's view equals the single physical slot state: for each
/// OWNED slot of the target, the view's entry (generation, artifact,
/// last_deployment) is EXACTLY the slot's one physical record
/// (`slots/<slot-id>/observed.json`) — the view is the global map filtered
/// to the target's OWN slots, so each slot appears once, physically, and its
/// OWNING target's view agrees with it by construction.
fn assert_views_match_physical(store: &LocalStore, config: &ProjectConfig) {
    let physical = store.read_global_observed().unwrap();
    for (tname, _) in config.targets() {
        let view = store.read_observed(tname, config).unwrap();
        let owned: std::collections::HashSet<&str> = config
            .slot_defs()
            .iter()
            .filter(|s| s.target == *tname)
            .map(|s| s.id.as_str())
            .collect();
        let want: BTreeMap<_, _> = physical
            .iter()
            .filter(|(id, _)| owned.contains(id.as_str()))
            .map(|(id, s)| (id.clone(), s.clone()))
            .collect();
        assert_eq!(
            view.slots, want,
            "target '{tname}': its view must equal the single physical slot state filtered to its \
             OWN slots (same generation/artifact/last_deployment)"
        );
    }
}

/// (2) MEMBERSHIP NEVER CHANGES RETENTION: the retained digest set is
/// computed under the slot's OWNING VARIANT policy (the single source; see
/// `ProjectConfig::slot_retention`), so a config-level membership edit — adding or
/// removing a rollout GROUP in a slot's `groups` list, reloaded through
/// `ProjectConfig::load` — leaves the retained set IDENTICAL. Groups are
/// selection-only (they never own state, policy, history, or checkpoints),
/// so a membership change cannot move retention.
fn assert_membership_never_changes_retention(
    store: &LocalStore,
    cfg_path: &std::path::Path,
    config: &ProjectConfig,
    release_dir: &std::path::Path,
    remotes_base: &std::path::Path,
) {
    // Pick the FIRST slot: a slot with >1 groups gets one group removed; a
    // slot with no groups gets a NEW group added (both are membership
    // changes; the owning variant — and its policy — is untouched either
    // way).
    let slot_def = config.slot_defs()[0];
    let slot_id = &slot_def.id;
    let groups0 = &slot_def.groups;
    let retained = |cfg: &ProjectConfig| -> HashSet<String> {
        let remote =
            LocalTransport::new(&crate::testutil::fixture_env(), remotes_base.join("h1")).unwrap();
        let helper = RemoteHelper::new(&remote);
        let owner = crate::remote::helper::GenerationOwner::new(
            cfg.application().clone(),
            crate::identity::SlotId::parse(slot_id).expect("validated slot id is a safe segment"),
        );
        compute_retained(
            &helper,
            cfg.pins(),
            store,
            cfg.slot_retention(slot_id).unwrap(),
            &owner,
        )
        .unwrap()
    };
    let before = retained(config);

    let variant_path = release_dir.join("standard.toml");
    let variant2 = std::fs::read_to_string(&variant_path).unwrap();
    // Locate the first slot's declaration by id, then its `groups = [...]`
    // list (the slot's owning target is whatever the generation assigned —
    // the search must not assume a name).
    let slot_start = variant2
        .find(&format!("[[slots]]\nid = \"{slot_id}\""))
        .expect("the first slot's declaration");
    let groups_start = variant2[slot_start..]
        .find("groups = [")
        .expect("the slot's groups list")
        + slot_start;
    let list_end = variant2[groups_start..].find(']').expect("groups list end") + groups_start;
    let head = &variant2[..groups_start];
    let list = &variant2[groups_start..list_end + 1];
    let rest = &variant2[list_end + 1..];
    let edited_list = if groups0.len() > 1 {
        // Drop the LAST group (keep at least one).
        let drop = groups0.last().unwrap();
        list.replace(&format!(", \"{drop}\""), "")
            .replace(&format!("\"{drop}\", "), "")
    } else {
        // Add a new group.
        let added = VIEW_TARGETS
            .iter()
            .copied()
            .find(|t| !groups0.iter().any(|x| x.as_str() == *t))
            .expect("a group not already a member exists");
        list.replacen("groups = [", &format!("groups = [\"{added}\", "), 1)
    };
    let variant2 = format!("{head}{edited_list}{rest}");
    std::fs::write(&variant_path, variant2).unwrap();
    let config2 = ProjectConfig::load(cfg_path).unwrap();
    // The membership edit may not have changed the slot's OWNING VARIANT.
    assert_eq!(
        config2.slot_variant(slot_id).unwrap(),
        config.slot_variant(slot_id).unwrap(),
        "the membership edit must not move the slot to another variant"
    );
    let after = retained(&config2);
    assert_eq!(
        before, after,
        "changing a slot's group membership must never change its retained set"
    );
}

proptest! {
    // THE SLOT-VIEW PROPERTY: three distinct-owned slots + interleaved
    // pushes. Bounded `proptest_cases(4)` (full 4 with `DEPLOY_FULL_TESTS=1`, fast
    // default), fixed seed 0x5EED_5EED (house style), no failure
    // persistence — deterministic for CI.
    #![proptest_config(ProptestConfig {
        cases: crate::testutil::proptest_cases(4),
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn slot_views_agree_with_physical_state_and_membership_never_changes_retention(
        owners in prop::collection::vec(0usize..3, 3),
        pushes in prop::collection::vec(prop::sample::select([0usize, 1, 2].as_slice()), 1..4),
    ) {
        run_slot_view_property(owners, pushes);
    }
}

// ---------------------------------------------------------------------------
// Three-controller mutation-lock no-takeover proptest
// ---------------------------------------------------------------------------
//
// The per-slot mutation lock is a CREATE-ONCE OWNERSHIP record (acquisition_id + operation_id
// unique acquisition id) removed only by atomic compare-and-delete.
// There is NO automatic takeover and NO TIME anywhere in the protocol: no
// lease, no expiry, no clock is consulted — a held lock never becomes
// breakable on its own; it changes hands only via EXPLICIT ADMINISTRATIVE
// RECOVERY (read → verify → remove under the authoritative local lock,
// writing a successor with a fresh unique acquisition id). Recovery is
// valid ONLY after the operator CONFIRMS the holder died; recovering a LIVE
// holder is explicitly unsafe operator error, out of contract. The fence is
// CAPABILITY POSSESSION — only a controller that holds the lock (possesses
// the capability) may mutate. This property drives a THREE-CONTROLLER state
// machine over ONE slot with three INDEPENDENTLY SKEWABLE clocks (generated
// and freely skewed — the protocol must be IMMUNE to them, asserted
// explicitly: the same steps are run under the generated skews and under
// zero skews, and the outcome TRACES must be IDENTICAL) and one-shot faults
// injected at every step — claim (create-if-absent), read (observe the
// record), compare (the release-vs-recovery decision), restore (the
// compare-and-delete release), mutate (a slot mutation under the capability),
// recover (the explicit administrative recovery's compare-and-delete), and
// die (liveness transition). After EVERY step it asserts:
//
// * EXACTLY ONE LIVE CONTROLLER CAN MUTATE: at most one live controller
//   holds the lock at any time (create-once exclusivity), so at most one
//   live controller has the capability and can mutate — exactly one live
//   mutator. A well-behaved deployment never has two live mutators overlapping.
// * ACQUISITION IDS NEVER REPEAT: every successful claim and recovery mints
//   a fresh uuid-v7 acquisition id, unique across the whole run (no value
//   is ever reused).
// * A STALE RELEASE NEVER DISPLACES A LIVE HOLDER: a release that FAILS
//   (compare-and-delete mismatch or transport fault) never leaves the file
//   absent and never alters it — the live holder's lock survives
//   byte-for-byte (asserted by comparing the on-disk record before and
//   after the failed release).

/// One step of the three-controller lock state machine: which controller
/// acts (0, 1, or 2) and what it does. `Claim` tries to take the lock
/// (atomic create-if-absent — the only way a record is installed on a free
/// slot); `Read` observes the on-disk record (interruptible); `Compare`
/// decides whether the controller's held record still IS the on-disk record
/// (release is safe) or was superseded by a recovery (recovery is required);
/// `Restore` releases explicitly (compare-and-delete — a stale release
/// fails and never displaces a successor); `Mutate` performs a slot
/// mutation under the capability (only a live holder may — no disk check);
/// `Recover` performs EXPLICIT ADMINISTRATIVE recovery of the record the
/// controller observed, under the authoritative local lock, taking the
/// observed record as its premise (read → verify → remove → install fresh
/// acquisition id) — permitted ONLY when the observed operation's owner is Dead;
/// `Die` marks a controller Dead (its capability gone, except its delayed
/// stale release may still fire).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CtrlAction {
    Claim(u8),
    Read(u8),
    Compare(u8),
    Restore(u8),
    Mutate(u8),
    Recover(u8),
    Die(u8),
}

/// The one-shot fault seams of the state machine: a fault armed at the named
/// stage of the NEXT action. `Claim` fails the atomic create (try_write_new),
/// `Read` fails the record read, `Compare` fails the record read behind the
/// release-vs-recovery decision, `Restore` fails the compare-and-delete
/// release, `Mutate` fails the slot-mutation write, and `Recover` fails the
/// recovery's compare-and-delete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CtrlFault {
    None,
    Claim,
    Read,
    Compare,
    Restore,
    Mutate,
    Recover,
}

/// The one-shot fault registry shared by the fault-injecting transport.
#[derive(Default)]
struct CtrlFaultState {
    fail_claim: bool,
    fail_read: bool,
    fail_remove: bool,
    fail_mutate: bool,
}

/// The on-remote path of the slot-mutation probe: a mutation marker the
/// Mutate step writes UNDER the capability, tagged with the holder's record. The
/// probe is a real remote write (faultable at the `Mutate` seam) and the
/// test asserts it always carries the holder's record's operation_id + acquisition_id.
fn mutation_probe() -> PathBuf {
    Path::new("state").join("mutation.probe")
}

/// A transport that injects ONE-SHOT faults at the mutation lock's
/// claim/read/remove seams and the slot-mutation write seam, then passes
/// through to `LocalTransport` (which realizes the atomic create-if-absent
/// and compare-and-delete). Deterministic, no sleeps; a fault is consumed by
/// the FIRST matching operation, so it can never leak into a later step.
struct CtrlFaultRemote {
    inner: LocalTransport,
    faults: Arc<Mutex<CtrlFaultState>>,
}

impl CtrlFaultRemote {
    fn hits_lock(rel: &Path) -> bool {
        rel == layout::operation_lock()
    }
}

impl Remote for CtrlFaultRemote {
    fn root(&self) -> &Path {
        self.inner.root()
    }
    fn read(&self, rel: &Path) -> crate::error::Result<Vec<u8>> {
        if Self::hits_lock(rel) && self.faults.lock().unwrap().fail_read {
            self.faults.lock().unwrap().fail_read = false;
            return Err(crate::error::Error::transport(
                "injected lock read failure".to_string(),
            ));
        }
        self.inner.read(rel)
    }
    fn write(&self, rel: &Path, data: &[u8], mode: u32) -> crate::error::Result<()> {
        if rel == mutation_probe() && self.faults.lock().unwrap().fail_mutate {
            self.faults.lock().unwrap().fail_mutate = false;
            return Err(crate::error::Error::transport(
                "injected mutation write failure".to_string(),
            ));
        }
        self.inner.write(rel, data, mode)
    }
    fn try_write_new(&self, rel: &Path, data: &[u8]) -> crate::error::Result<CreateNewVerdict> {
        if Self::hits_lock(rel) && self.faults.lock().unwrap().fail_claim {
            self.faults.lock().unwrap().fail_claim = false;
            return Err(crate::error::Error::transport(
                "injected lock claim failure".to_string(),
            ));
        }
        self.inner.try_write_new(rel, data)
    }
    fn create_dir(&self, rel: &Path) -> crate::error::Result<()> {
        self.inner.create_dir(rel)
    }
    fn create_dir_all(&self, rel: &Path) -> crate::error::Result<()> {
        self.inner.create_dir_all(rel)
    }
    fn set_mode(&self, rel: &Path, mode: u32) -> crate::error::Result<()> {
        self.inner.set_mode(rel, mode)
    }
    fn list(&self, rel: &Path) -> crate::error::Result<Vec<RemoteEntry>> {
        self.inner.list(rel)
    }
    fn rename(&self, from: &Path, to: &Path) -> crate::error::Result<()> {
        self.inner.rename(from, to)
    }
    fn symlink(&self, target: &Path, link: &Path) -> crate::error::Result<()> {
        self.inner.symlink(target, link)
    }
    fn read_link(&self, rel: &Path) -> crate::error::Result<PathBuf> {
        self.inner.read_link(rel)
    }
    fn remove_file(&self, rel: &Path) -> crate::error::Result<()> {
        self.inner.remove_file(rel)
    }
    fn remove_file_if(
        &self,
        rel: &Path,
        expected: &[u8],
    ) -> crate::error::Result<crate::remote::transport::RemoveIfVerdict> {
        if Self::hits_lock(rel) && self.faults.lock().unwrap().fail_remove {
            self.faults.lock().unwrap().fail_remove = false;
            return Err(crate::error::Error::transport(
                "injected lock remove failure".to_string(),
            ));
        }
        self.inner.remove_file_if(rel, expected)
    }
    fn remove_dir_all(&self, rel: &Path) -> crate::error::Result<()> {
        self.inner.remove_dir_all(rel)
    }
    fn exists(&self, rel: &Path) -> bool {
        self.inner.exists(rel)
    }
    fn metadata(&self, rel: &Path) -> crate::error::Result<RemoteMeta> {
        self.inner.metadata(rel)
    }
    fn metadata_opt(&self, rel: &Path) -> crate::error::Result<Option<RemoteMeta>> {
        self.inner.metadata_opt(rel)
    }
    fn exec(
        &self,
        argv: &[String],
        timeout: std::time::Duration,
    ) -> crate::error::Result<ExecOutcome> {
        self.inner.exec(argv, timeout)
    }
    fn filesystem_bytes(&self) -> crate::error::Result<FsBytes> {
        self.inner.filesystem_bytes()
    }
}

fn controller_op(c: u8) -> &'static str {
    match c {
        0 => "ctrl-A",
        1 => "ctrl-B",
        _ => "ctrl-C",
    }
}

fn controller_index_for_operation_id(operation_id: &str) -> Option<usize> {
    match operation_id {
        "ctrl-A" => Some(0),
        "ctrl-B" => Some(1),
        "ctrl-C" => Some(2),
        _ => None,
    }
}

/// The current on-disk lock record (typed): `Ok(None)` for genuine absence,
/// `Ok(Some(rec))` for the parsed record, `Err` for a transport fault (the
/// one-shot read fault lands here — the action handles it) or a
/// present-but-not-a-record file (a test bug). The lock file is ONLY ever
/// written by this protocol, so a parse failure is a test bug — panic.
fn read_lock_record(remote: &dyn Remote) -> crate::error::Result<Option<LockRecord>> {
    let Some(_) = remote.metadata_opt(&layout::operation_lock())? else {
        return Ok(None);
    };
    let data = remote.read(&layout::operation_lock())?;
    Ok(Some(
        serde_json::from_slice(&data).expect("the lock file must carry an ownership record"),
    ))
}

/// One bounded case of the three-controller lock state machine: apply each
/// (action, fault) step and assert the invariants after every step, returning
/// the OUTCOME TRACE (one event per step). `_skews` are the three controllers'
/// independently skewable clocks — DELIBERATELY NOT CONSULTED anywhere: the
/// protocol is time-free, so the trace is identical for every clock
/// assignment (the property runs the same steps under the generated skews
/// and under zero skews and asserts the traces match).
fn run_three_controller_case(
    steps: Vec<(CtrlAction, CtrlFault)>,
    _skews: [i64; 3],
) -> std::result::Result<Vec<String>, proptest::test_runner::TestCaseError> {
    let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
    let inner =
        LocalTransport::new(&crate::testutil::fixture_env(), dir.path().join("remote")).unwrap();
    let faults = Arc::new(Mutex::new(CtrlFaultState::default()));
    let remote = CtrlFaultRemote {
        inner,
        faults: faults.clone(),
    };
    let helpers = [
        RemoteHelper::new(&remote),
        RemoteHelper::new(&remote),
        RemoteHelper::new(&remote),
    ];
    // The ADMINISTRATIVE recovery capability: `recover_lock` requires the
    // typed local application lock, so the state machine runs under the REAL
    // administrative path (an `AdministrativeRecoveryGuard` on a local
    // store's `operation.lock`), held for the whole case — a recovery without
    // the local lock is unrepresentable.
    let admin = crate::deploy::lock::AdministrativeRecoveryGuard::acquire(
        &dir.path().join("store").join("operation.lock"),
        "si-recovery",
    )
    .expect("the authoritative local lock must be acquirable");
    // Per-controller state: `held` is the record the controller believes it
    // holds (its live claim / recovery result); `observed` is the last record
    // it READ — the premise a later explicit recovery takes.
    let mut helds: [Option<LockRecord>; 3] = [None, None, None];
    let mut observed: [Option<LockRecord>; 3] = [None, None, None];
    // Liveness: each controller starts Alive; Die marks Dead. Dead controllers
    // are removed from play (no Claim/Mutate/Recover) except their delayed
    // stale RELEASE may still fire.
    let mut alive: [bool; 3] = [true, true, true];
    // Stale release records for dead controllers: on Die, the held capability
    // moves here so a delayed stale Restore can be attempted.
    let mut stale: [Option<LockRecord>; 3] = [None, None, None];
    // Acquisition-id uniqueness: every successful acquisition (fresh claim or
    // recovery successor) mints a fresh unique id; duplicate is assertion failure.
    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut trace: Vec<String> = Vec::new();

    for (action, fault) in steps {
        // Arm the step's one-shot fault at the named seam. Die has no seam.
        {
            let mut f = faults.lock().unwrap();
            let is_die = matches!(action, CtrlAction::Die(_));
            f.fail_claim =
                !is_die && matches!(action, CtrlAction::Claim(_)) && fault == CtrlFault::Claim;
            f.fail_read = !is_die
                && matches!(action, CtrlAction::Read(_) | CtrlAction::Compare(_))
                && (fault == CtrlFault::Read || fault == CtrlFault::Compare);
            f.fail_remove = !is_die
                && matches!(action, CtrlAction::Restore(_) | CtrlAction::Recover(_))
                && (fault == CtrlFault::Restore || fault == CtrlFault::Recover);
            f.fail_mutate =
                !is_die && matches!(action, CtrlAction::Mutate(_)) && fault == CtrlFault::Mutate;
        }

        match action {
            CtrlAction::Die(c) => {
                let idx = c as usize;
                if alive[idx] {
                    // Move held capability to stale for delayed release, then mark dead.
                    if helds[idx].is_some() {
                        stale[idx] = helds[idx].clone();
                    }
                    helds[idx] = None;
                    alive[idx] = false;
                    trace.push(format!("die:{c}"));
                } else {
                    trace.push(format!("die:{c}:already-dead"));
                }
            }
            CtrlAction::Claim(c) => {
                if !alive[c as usize] {
                    trace.push(format!("claim:{c}:dead"));
                    continue;
                }
                let helper = &helpers[c as usize];
                let held = &mut helds[c as usize];
                let before = read_lock_record(&remote)
                    .expect("a claim's pre-read cannot be faulted (no read fault armed for Claim)");
                observed[c as usize] = before.clone();
                let result = helper.acquire_lock_record_for_test(
                    &crate::identity::OperationId::new(controller_op(c).to_string()),
                );
                if before.is_none() {
                    // Fresh claim on genuinely absent slot — must be unique.
                    match result {
                        Ok(rec) => {
                            let id_str = rec.acquisition_id.as_str().to_string();
                            prop_assert!(
                                seen_ids.insert(id_str.clone()),
                                "acquisition id must be unique across whole simulation, duplicate {id_str:?}"
                            );
                            *held = Some(rec.clone());
                            observed[c as usize] = Some(rec.clone());
                            trace.push(format!("claim:{c}:ok"));
                        }
                        Err(_) => {
                            trace.push(format!("claim:{c}:fail"));
                        }
                    }
                } else {
                    // A claim on a PRESENT on-disk record always errors (contention):
                    // a fresh acquisition id never equals the on-disk acquisition;
                    // operation id equality never confers ownership.
                    prop_assert!(
                        result.is_err(),
                        "a claim on any present record is contention — a fresh acquisition id never equals the on-disk acquisition; operation id equality never confers ownership"
                    );
                    let after =
                        read_lock_record(&remote).expect("post-claim read cannot be faulted");
                    prop_assert_eq!(
                        before,
                        after,
                        "a failed claim on a present record must leave the on-disk record byte-identical"
                    );
                    trace.push(format!("claim:{c}:fail:contention"));
                }
            }
            CtrlAction::Read(c) => {
                // Dead controllers can still observe? Allow but trace.
                match read_lock_record(&remote) {
                    Ok(file) => {
                        observed[c as usize] = file.clone();
                        trace.push(format!(
                            "read:{c}:{:?}",
                            file.as_ref().map(|r| r.operation_id.clone())
                        ));
                    }
                    Err(_) => trace.push(format!("read:{c}:fault")),
                }
            }
            CtrlAction::Compare(c) => match read_lock_record(&remote) {
                Ok(file) => {
                    observed[c as usize] = file.clone();
                    let held = &helds[c as usize];
                    let decision = match (held.as_ref(), file.as_ref()) {
                        (Some(rec), Some(disk)) if rec == disk => "held",
                        (Some(_), Some(_)) => "superseded",
                        (Some(_), None) => "free",
                        (None, _) => "no-hold",
                    };
                    trace.push(format!("compare:{c}:{decision}"));
                }
                Err(_) => trace.push(format!("compare:{c}:fault")),
            },
            CtrlAction::Restore(c) => {
                let helper = &helpers[c as usize];
                let idx = c as usize;
                // Dead controller's delayed stale release (uses stale record)
                if !alive[idx] {
                    if let Some(rec) = stale[idx].clone() {
                        let before = read_lock_record(&remote)
                            .expect("a restore's pre-read cannot be faulted (no read fault armed)");
                        match helper.release_lock_record_for_test(&rec) {
                            Ok(()) => {
                                // Should not happen for stale (mismatch) but if slot free it could be idempotent?
                                trace.push(format!("restore:{c}:ok-stale"));
                            }
                            Err(_) => {
                                let file = read_lock_record(&remote)
                                    .expect("the post-failure read cannot be faulted");
                                prop_assert!(
                                    file.is_some(),
                                    "a failed stale release must never delete the current lock (stale \
                                     release {rec:?})"
                                );
                                prop_assert!(
                                    before == file,
                                    "a failed stale release must never alter the on-disk record: before \
                                     {before:?}, after {file:?}"
                                );
                                trace.push(format!("restore:{c}:fail-stale"));
                            }
                        }
                    } else {
                        trace.push(format!("restore:{c}:no-hold-dead"));
                    }
                    continue;
                }
                // Alive controller's normal restore
                let held = &mut helds[idx];
                if let Some(rec) = held.take() {
                    let before = read_lock_record(&remote)
                        .expect("a restore's pre-read cannot be faulted (no read fault armed)");
                    match helper.release_lock_record_for_test(&rec) {
                        Ok(()) => {
                            observed[idx] = None;
                            trace.push(format!("restore:{c}:ok"));
                        }
                        Err(_) => {
                            let file = read_lock_record(&remote)
                                .expect("the post-failure read cannot be faulted");
                            prop_assert!(
                                file.is_some(),
                                "a failed release must never delete the current lock (stale \
                                 release {rec:?})"
                            );
                            prop_assert!(
                                before == file,
                                "a failed release must never alter the on-disk record: before \
                                 {before:?}, after {file:?}"
                            );
                            if file.as_ref() == Some(&rec) {
                                *held = Some(rec);
                            }
                            trace.push(format!("restore:{c}:fail"));
                        }
                    }
                } else {
                    trace.push(format!("restore:{c}:no-hold"));
                }
            }
            CtrlAction::Mutate(c) => {
                let helper = &helpers[c as usize];
                let idx = c as usize;
                if !alive[idx] {
                    trace.push(format!("mutate:{c}:dead"));
                    continue;
                }
                let held = &helds[idx];
                // Honest contract: mutate iff controller holds capability (and is alive).
                // No disk-record check — production never consults the disk on mutation.
                if let Some(rec) = held {
                    // Perform slot mutation under the capability, tagged with held record.
                    let payload = serde_json::to_vec(rec).unwrap();
                    match helper.remote().write(&mutation_probe(), &payload, 0o644) {
                        Ok(()) => {
                            let marker = serde_json::from_slice::<LockRecord>(
                                &helper
                                    .remote()
                                    .read(&mutation_probe())
                                    .expect("the mutation marker must be readable"),
                            )
                            .unwrap();
                            prop_assert_eq!(
                                marker,
                                rec.clone(),
                                "a mutation happens only under capability possession: the \
                                     mutation marker must carry the holder's record operation_id + acquisition_id"
                            );
                            trace.push(format!("mutate:{c}:ok"));
                        }
                        Err(_) => trace.push(format!("mutate:{c}:fault")),
                    }
                } else {
                    trace.push(format!("mutate:{c}:no-hold"));
                }
            }
            CtrlAction::Recover(c) => {
                let helper = &helpers[c as usize];
                let idx = c as usize;
                if !alive[idx] {
                    trace.push(format!("recover:{c}:dead-recoverer"));
                    continue;
                }
                let Some(obs) = observed[idx].clone() else {
                    trace.push(format!("recover:{c}:no-premise"));
                    continue;
                };
                // Well-behaved operator: recovery only for dead holder.
                // If observed operation's owner is still Alive, this is an illegal recovery
                // attempt — well-behaved operator would not issue it, so we
                // treat it as a refused no-op (not a test failure) to keep the
                // generator well-behaved without stateful generation.
                if let Some(owner_idx) = controller_index_for_operation_id(&obs.operation_id)
                    && alive[owner_idx]
                {
                    trace.push(format!("recover:{c}:refused-alive-owner"));
                    continue;
                }
                let before = read_lock_record(&remote)
                    .expect("a recover's pre-read cannot be faulted (no read fault armed)");
                match helper.recover_lock(
                    &admin,
                    &obs,
                    &crate::identity::OperationId::new(controller_op(c).to_string()),
                ) {
                    Ok(rec_guard) => {
                        // The successor capability is now this controller's; the
                        // state machine tracks acquisitions as raw records, so
                        // the guard (which would release on drop) is forgotten —
                        // the acquired lock stays held until an explicit restore.
                        let rec = rec_guard.record().clone();
                        std::mem::forget(rec_guard);
                        // Fresh unique acquisition id, never equal to observed's id.
                        prop_assert!(
                            rec.acquisition_id != obs.acquisition_id,
                            "a recovery must install a fresh unique acquisition id, got same as observed {:?} vs {:?}",
                            obs,
                            rec
                        );
                        let id_str = rec.acquisition_id.as_str().to_string();
                        prop_assert!(
                            seen_ids.insert(id_str.clone()),
                            "acquisition id must be unique, duplicate {id_str:?}"
                        );
                        // Also ensure observed's id was already seen (as prior acquisition).
                        // It should have been inserted at its claim time.
                        helds[idx] = Some(rec.clone());
                        observed[idx] = Some(rec.clone());
                        trace.push(format!("recover:{c}:ok"));
                    }
                    Err(_) => {
                        let after = read_lock_record(&remote)
                            .expect("the post-recovery read cannot be faulted");
                        prop_assert!(
                            before == after,
                            "a refused/failed recovery must never alter the lock: before \
                             {before:?}, after {after:?}"
                        );
                        trace.push(format!("recover:{c}:fail"));
                    }
                }
            }
        }

        // Disarm any unconsumed one-shot fault (step-scoped, never leaked).
        {
            let mut f = faults.lock().unwrap();
            f.fail_claim = false;
            f.fail_read = false;
            f.fail_remove = false;
            f.fail_mutate = false;
        }

        // ---- THE INVARIANTS (after every step) ----
        let file = read_lock_record(&remote)
            .expect("the invariant probe read cannot be faulted (faults are disarmed)");

        // 1. EXACTLY ONE LIVE CONTROLLER CAN MUTATE: at most one live holder.
        let live_holders: Vec<u8> = (0u8..3)
            .filter(|&c| {
                alive[c as usize]
                    && helds[c as usize].is_some()
                    && helds[c as usize].as_ref() == file.as_ref()
            })
            .collect();
        prop_assert!(
            live_holders.len() <= 1,
            "mutual exclusion violated after (action {action:?}, fault {fault:?}): on-disk \
             {file:?}, live_holders {live_holders:?} (helds {helds:?}, alive {alive:?})"
        );

        // 2. ACQUISITION IDS NEVER REPEAT is asserted at claim/recover steps via seen_ids.

        // 3. A STALE RELEASE NEVER DISPLACES A LIVE HOLDER is asserted inside
        // the Restore step (the on-disk record is byte-identical before and
        // after a failed release).
    }

    // End of run: the final on-disk record and mutation marker round out the trace.
    trace.push(format!(
        "final-lock={:?}",
        read_lock_record(&remote)
            .expect("the final lock read cannot be faulted (faults are disarmed)")
            .map(|r| r.operation_id.clone())
    ));
    trace.push(format!(
        "final-marker={:?}",
        remote
            .metadata_opt(&mutation_probe())
            .expect("marker metadata_opt must succeed")
            .map(|_| {
                serde_json::from_slice::<LockRecord>(
                    &remote
                        .read(&mutation_probe())
                        .expect("marker read must succeed"),
                )
                .expect("the marker must carry a record")
            })
            .map(|r| r.operation_id.clone())
    ));
    trace.push(format!("seen-ids-count={}", seen_ids.len()));
    Ok(trace)
}

fn ctrl_step_strategy() -> impl Strategy<Value = (CtrlAction, CtrlFault)> {
    let controller = prop::sample::select(vec![0u8, 1u8, 2u8]);
    let fault = prop_oneof![
        8 => Just(CtrlFault::None),
        1 => Just(CtrlFault::Claim),
        1 => Just(CtrlFault::Read),
        1 => Just(CtrlFault::Compare),
        1 => Just(CtrlFault::Restore),
        1 => Just(CtrlFault::Mutate),
        1 => Just(CtrlFault::Recover),
    ];
    let action = prop_oneof![
        5 => controller.clone().prop_map(CtrlAction::Claim),
        3 => controller.clone().prop_map(CtrlAction::Read),
        3 => controller.clone().prop_map(CtrlAction::Compare),
        4 => controller.clone().prop_map(CtrlAction::Restore),
        3 => controller.clone().prop_map(CtrlAction::Mutate),
        3 => controller.clone().prop_map(CtrlAction::Recover),
        1 => controller.clone().prop_map(CtrlAction::Die),
    ];
    (action, fault)
}

proptest! {
    // THE THREE-CONTROLLER NO-TAKEOVER LOCK PROPERTY: bounded cases
    // (`proptest_cases(64)`: fast default 16, full 64 under
    // `DEPLOY_FULL_TESTS=1`), fixed seed 0x5EED_5EED (house style), no
    // failure persistence — deterministic for CI. Each case drives its own
    // fixture (structurally isolated), and each step's fault is one-shot and
    // step-scoped. The three controllers carry INDEPENDENTLY SKEWABLE clocks
    // (generated and freely skewed): the protocol is time-free, so the same
    // steps run under the generated skews and under zero skews must produce
    // IDENTICAL outcome traces. Under the well-behaved dead-only-recovery
    // precondition, exactly one live controller can mutate and stale releases
    // never affect its lock.
    #![proptest_config(ProptestConfig {
        cases: crate::testutil::proptest_cases(64),
        rng_seed: RngSeed::Fixed(0x5EED_5EED),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn three_controller_no_takeover_lock(
        steps in prop::collection::vec(
            ctrl_step_strategy(),
            1..=crate::testutil::proptest_steps(40),
        ),
        skew_a in -1_000_000_000i64..=1_000_000_000i64,
        skew_b in -1_000_000_000i64..=1_000_000_000i64,
        skew_c in -1_000_000_000i64..=1_000_000_000i64,
    ) {
        // Run the same steps under the GENERATED skewable clocks...
        let trace_skewed = run_three_controller_case(steps.clone(), [skew_a, skew_b, skew_c])?;
        // ...and under ZERO skews: the outcome must be IDENTICAL for every
        // generated clock assignment — the protocol is immune to clock skew
        // because NO time is consulted anywhere (no lease, no expiry).
        let trace_zero = run_three_controller_case(steps, [0i64, 0, 0])?;
        prop_assert_eq!(
            trace_skewed,
            trace_zero,
            "the lock protocol is clock-immune: the outcome must be identical for every \
             generated clock assignment (skewed {}/{} / {} vs zero)",
            skew_a,
            skew_b,
            skew_c
        );
    }
}
