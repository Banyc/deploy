//! Shared test-only utilities.
//!
//! # The env-lock invariant
//!
//! ANY test that mutates the process-global environment must hold
//! [`ENV_LOCK`] for the entire duration of the mutation — `PATH`,
//! `XDG_CONFIG_HOME`, `DEPLOY_SSH_KNOWNHOSTS_DIR`,
//! `FAKE_SSH_ROOT` / `FAKE_SSH_REMOTE_PREFIX`, or anything else.
//!
//! All lib unit tests share one process, and edition-2024
//! `std::env::set_var` / `remove_var` are process-global (and `unsafe`), so
//! two env-mutating tests running concurrently corrupt each other's
//! environment: the fake-`ssh`/`ssh-keyscan` fingerprint suite and the
//! fake-`systemctl` suite both rewrite the same `PATH`, and a race could make
//! one of them spawn the REAL binaries (e.g. the real `ssh-keyscan`, whose
//! getaddrinfo DNS failure panics and poisons the lock). Every env-mutating
//! test must therefore serialize on THIS single lock — a private per-suite
//! lock does not protect against the other suite.
//!
//! Per-test state that lives OUTSIDE the process env (e.g. each test's own
//! `DEPLOY_SSH_KNOWNHOSTS_DIR` temp dir for the pin cache) stays isolated as
//! before; the lock only serializes the env itself.
//!
//! Note: each integration-test *binary* (`tests/*.rs`) is a separate process
//! and cannot race the lib tests, so it only needs its own lock to serialize
//! its own tests within that binary.
//!
//! # Fault injection: per-fixture registries, no process-global slots
//!
//! One-shot store-fault injection lives in [`test_faults`] as a
//! **per-fixture fault registry** ([`test_faults::FaultRegistry`]) owned by
//! the [`crate::store::local::LocalStore`] of the fixture under test, NOT in
//! process-global statics. There are no shared slots and no `FAULT_LOCK`:
//! two fixtures' registries are distinct objects, so a fault armed in one
//! fixture can never be consumed (or clobbered) by another fixture's store —
//! isolation is structural, by construction, and holds under any interleaving
//! of parallel `cargo test` threads. A store only sees faults ARMED ON ITS
//! OWN registry (`store.fault_registry().arm_*`), and its store methods
//! consult exactly that registry (`self.fault_registry.consume(...)`).
//!
//! The registry is created empty by `LocalStore::with_base`; a test that
//! wants an injected fault arms its store's registry immediately before the
//! operation that must fail. Because the registry is per-fixture, the arm and
//! the consuming push no longer need to be wrapped in a lock window.
//!
//! Mechanical conversion for sibling fault work (e.g. the rotation-debt arms
//! `arm_read_rotation_debt` / `arm_write_rotation_debt`): the registry keeps
//! the historical `arm_<kind>(id)` (and `arm_<kind>(id, target)`) method
//! surface, so a call site `test_faults::arm_<kind>(id)` converts by changing
//! only the receiver: `store.fault_registry().arm_<kind>(id)`. The store
//! method's consume hook converts to a one-line registry call:
//! `self.fault_registry.consume(FaultKind::<Kind>, id)`.

use std::sync::Mutex;

/// THE lock guarding every env-mutating test in the lib test binary. See the
/// module docs for the invariant.
pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Test-only one-shot fault injection for crash-mid-finalization tests.
///
/// A fault is a one-shot arm keyed by the DEPLOYMENT ID of the attempt under
/// test (the two-part faults additionally by TARGET): the NEXT matching store
/// call fails exactly once (and disarms itself), while every other call —
/// including identical methods for different deployment IDs from any other
/// fixture, concurrently running — passes through untouched.
///
/// Faults exist for the `IntentPersist` ([`FaultKind::AppendAttempt`]), the
/// outcomes store ([`FaultKind::WriteResults`]), the snapshot append, the
/// `refs/last-successful` write, and the status-qualified transition appends
/// ([`FaultKind::AppendTransition`],
/// [`FaultKind::AppendTransitionSuccessful`],
/// [`FaultKind::AppendTransitionPending`]). The post-commit observed-refresh
/// faults ([`FaultKind::WriteServer`], [`FaultKind::WriteObserved`]) are
/// additionally keyed by TARGET, so a test can fault the primary target's
/// `write_observed` (the push's own target) or an other member target's
/// independently. The rotation-maintenance arms
/// ([`FaultKind::ReadRotationDebt`], [`FaultKind::WriteRotationDebt`]) are
/// keyed by TARGET (the debt file lives under `targets/<target>/`). The
/// checkpoint floor's durability stages ([`FaultKind::SyncFloorTemp`],
/// [`FaultKind::RenameFloor`], [`FaultKind::SyncFloorParent`], plus the
/// entry-point [`FaultKind::WriteHistoryFloor`]) are keyed by the
/// CHECKPOINT deployment id; a failure at ANY of them is returned from
/// `write_history_floor` itself (PRE-marker), so no floor exists and no
/// compaction can run. The cleanup-pending debt-marker kinds are keyed by
/// the FLOOR'S DEPLOYMENT ID for the WRITE
/// ([`FaultKind::WriteCleanupPending`] — the marker names it) and by
/// TARGET for the CLEAR ([`FaultKind::ClearCleanupPending`] — the marker
/// lives under `targets/<target>/refs/`, mirroring the rotation-debt
/// kinds). Both fire AFTER the floor marker is durable (post-commit
/// maintenance): a write failure means the debt could not be made durable
/// (surfaced as `cleanup_persistence_failed`), a clear failure leaves a
/// stale marker (surfaced as `cleanup_clear_failed`).
///
/// ISOLATION IS STRUCTURAL: a [`FaultRegistry`] belongs to exactly one
/// fixture (via its store); there are no process-global slots and no
/// FAULT_LOCK-style lock to hold. Two fixtures' arms can never interact,
/// so the fault-matrix, engine, and store fault tests run safely in parallel.
#[cfg(test)]
pub(crate) mod test_faults {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// The distinct store operations that can be faulted. Each kind is armed
    /// and consumed on a single [`FaultRegistry`], keyed by deployment id
    /// (and, for the observed-refresh kinds, additionally by target).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub(crate) enum FaultKind {
        /// `append_attempt` — the intent persist, the FIRST store I/O of a
        /// push (before any remote mutation).
        AppendAttempt,
        /// `write_results` — the outcomes store, written once after the
        /// mutation loop.
        WriteResults,
        /// `append_snapshot` — the first persistence step of the shared
        /// replay-safe finalizer.
        AppendSnapshot,
        /// `write_last_successful` — the second persistence step of the
        /// shared finalizer.
        WriteLastSuccessful,
        /// `append_transition` — any transition append.
        AppendTransition,
        /// `append_transition` recording a `Successful` status (the terminal
        /// finalizer step).
        AppendTransitionSuccessful,
        /// `append_transition` recording a `PendingCommit` status (the
        /// recoverable finalize marker).
        AppendTransitionPending,
        /// Post-commit observed-refresh per-server record write
        /// (`servers/<id>.json`), keyed by (deployment id, target).
        WriteServer,
        /// Post-commit observed-refresh SLOT record write
        /// (`slots/<slot-id>/observed.json` — the slot's ONE physical
        /// observed state, never replicated per target), keyed by
        /// (deployment id, SLOT id).
        WriteObserved,
        /// `read_rotation_debt` (rotation maintenance debt read), keyed by
        /// target.
        ReadRotationDebt,
        /// `write_rotation_debt` (rotation maintenance debt write), keyed by
        /// target.
        WriteRotationDebt,
        /// The checkpoint floor marker write (`write_history_floor`) — the
        /// FIRST durable step of a checkpoint; a failure here leaves no
        /// floor (and therefore no compaction).
        WriteHistoryFloor,
        /// The checkpoint floor marker's TEMP-FILE FSYNC — the first
        /// durability stage of `write_history_floor` (keyed by the
        /// checkpoint deployment id), after the temp is chmodded private
        /// and before the rename. A failure here returns `Err` from
        /// `write_history_floor` itself (PRE-marker: no floor, no
        /// compaction).
        SyncFloorTemp,
        /// The checkpoint floor marker's RENAME-into-place — the second
        /// durability stage of `write_history_floor` (keyed by the
        /// checkpoint deployment id). A failure here returns `Err` from
        /// `write_history_floor` itself (PRE-marker: no floor, no
        /// compaction).
        RenameFloor,
        /// The checkpoint floor marker's PARENT-DIRECTORY FSYNC — the third
        /// durability stage of `write_history_floor` (keyed by the
        /// checkpoint deployment id), the durability COMMIT POINT. A
        /// failure (fault or real) is returned from `write_history_floor`
        /// AFTER the already-renamed marker is unlinked; on an ADVANCE the
        /// previous floor A is then restored from the backup, so no B
        /// exists and A is durable again (a failed advancement never erases
        /// the previously durable floor).
        SyncFloorParent,
        /// The checkpoint floor marker's BACKUP RENAME (`history-floor.json`
        /// → `history-floor.json.prev.<id>`, the transaction-tagged backup
        /// name) — the first stage of a TRANSACTIONAL floor ADVANCE (keyed
        /// by the checkpoint deployment id), running BEFORE the new marker
        /// can overwrite the old one. A fault here fires BEFORE the rename
        /// (A still in place): the staged temp is dropped, A stands
        /// untouched, and the advance fails with `Err`.
        RenameFloorBackup,
        /// The checkpoint floor marker's RESTORE (the tagged backup
        /// `history-floor.json.prev.<id>` → `history-floor.json`) — the
        /// fail-closed half of a TRANSACTIONAL floor ADVANCE (keyed by the
        /// checkpoint deployment id), attempted whenever an advance fails
        /// before B's durability commit point. The restore ONLY ever
        /// renames the current transaction's tagged backup, verified to
        /// carry the tag AND to parse and equal the pre-advance floor. A
        /// fault here means the restore itself failed: the previous floor A
        /// stays in the backup and the marker may be left ABSENT — every
        /// read then fails closed with an integrity error (a leftover
        /// backup with no marker is a torn advance, never "no floor",
        /// which would expose the below-floor prefix).
        RestoreFloor,
        /// The checkpoint's success-path BACKUP REMOVAL — the best-effort
        /// cleanup of THIS transaction's tagged backup
        /// (`history-floor.json.prev.<id>`, holding the pre-advance floor)
        /// after the floor committed (keyed by the checkpoint deployment
        /// id). A fault here FORCES the removal to fail: the tagged backup
        /// stays on disk — harmless by design (it is never restored by a
        /// different transaction and the next advance reconciles it away),
        /// but it is exactly the "stale backup left behind by a committed
        /// advance" state the tagged scheme must make safe.
        RemoveFloorBackup,
        /// The checkpoint's attempts.jsonl suffix rewrite (a compaction
        /// phase after the floor marker is already durable and the
        /// below-floor deployment dirs are deleted).
        CompactAttempts,
        /// The checkpoint's snapshots.jsonl suffix rewrite (a compaction
        /// phase after the floor marker is already durable and the
        /// below-floor deployment dirs are deleted).
        CompactSnapshots,
        /// The checkpoint's `deployments/<id>/` directory deletion — the
        /// FIRST compaction phase, running while the logs still name every
        /// discarded id (the floor marker is already durable).
        CompactDeployments,
        /// The pending-checkpoint-cleanup FLAG marker WRITE
        /// (`write_cleanup_pending`), keyed by the FLOOR'S DEPLOYMENT ID
        /// (the marker names it). Post-commit maintenance: a failure here
        /// means the cleanup debt could NOT be made durable — the report
        /// must surface it explicitly
        /// (`CheckpointReport::cleanup_persistence_failed`), never claim
        /// durable debt that a crash/restart would lose (the retry
        /// recomputes the worklist from the intact logs and converges
        /// regardless).
        WriteCleanupPending,
        /// The pending-checkpoint-cleanup FLAG marker CLEAR
        /// (`clear_cleanup_pending`), keyed by TARGET (the marker lives
        /// under `targets/<target>/refs/`, mirroring the rotation-debt
        /// kinds). Post-commit maintenance: a failure leaves a STALE
        /// (harmless) marker that the next same-deployment checkpoint
        /// re-clears; the report surfaces it truthfully as
        /// `CheckpointReport::cleanup_clear_failed`.
        ClearCleanupPending,
        /// The artifact garbage collection SCAN (the retained-set
        /// computation of [`crate::store::gc`]), keyed by the checkpoint
        /// deployment id. Post-commit maintenance: a failure aborts the
        /// pass BEFORE any deletion (fail closed — nothing is ever unlinked
        /// against a partial retained set), the durable debt flag records
        /// the pending cleanup, and the retry recomputes reachability
        /// fresh.
        GcScan,
        /// The artifact GC's RELEASE-RECORD deletion phase, keyed by the
        /// checkpoint deployment id. Fires before any release dir is
        /// removed: the unreachable release records stay on disk (extra
        /// garbage, never less) and the retry reclaims them.
        GcDeleteReleases,
        /// The artifact GC's TREE-OBJECT deletion phase, keyed by the
        /// checkpoint deployment id. Fires before any tree dir is removed.
        GcDeleteTrees,
    }

    /// A per-fixture one-shot fault registry.
    ///
    /// Storage: a `Mutex<BTreeMap<FaultKey, ()>>` mapping each armed
    /// (kind, deployment-id[, target]) key to a one-shot marker. Arming
    /// inserts the key; the matching consume removes it and returns `true`
    /// (the fault FIRED and is now disarmed); any other consume returns
    /// `false` and leaves the key armed. The map is deterministic (BTreeMap)
    /// and the mutex makes the registry safe to share; two registries are
    /// always disjoint objects, so two fixtures can never interfere.
    ///
    /// `FaultKey` names the armed (kind, deployment-id[, target]) triple
    /// (factored out so the registry's storage type stays readable).
    type FaultKey = (FaultKind, String, Option<String>);

    #[derive(Default)]
    pub(crate) struct FaultRegistry {
        inner: Mutex<BTreeMap<FaultKey, ()>>,
    }

    impl FaultRegistry {
        /// Arm a one-shot fault keyed by deployment id (no target half).
        pub(crate) fn arm(&self, kind: FaultKind, deployment_id: &str) {
            self.inner
                .lock()
                .unwrap()
                .insert((kind, deployment_id.to_string(), None), ());
        }

        /// Arm a one-shot fault keyed by deployment id AND target.
        pub(crate) fn arm_target(&self, kind: FaultKind, deployment_id: &str, target: &str) {
            self.inner.lock().unwrap().insert(
                (kind, deployment_id.to_string(), Some(target.to_string())),
                (),
            );
        }

        /// Consume the one-shot deployment-id fault for `kind`; returns `true`
        /// only when it was armed (and disarms it).
        pub(crate) fn consume(&self, kind: FaultKind, deployment_id: &str) -> bool {
            self.inner
                .lock()
                .unwrap()
                .remove(&(kind, deployment_id.to_string(), None))
                .is_some()
        }

        /// Consume the one-shot `(deployment_id, target)` fault; returns
        /// `true` only when BOTH halves match (and disarms it); a
        /// non-matching call leaves the fault armed for the next matching
        /// call.
        pub(crate) fn consume_target(
            &self,
            kind: FaultKind,
            deployment_id: &str,
            target: &str,
        ) -> bool {
            self.inner
                .lock()
                .unwrap()
                .remove(&(kind, deployment_id.to_string(), Some(target.to_string())))
                .is_some()
        }

        /// Whether a one-shot (kind, deployment id) fault is currently armed.
        pub(crate) fn is_armed(&self, kind: FaultKind, deployment_id: &str) -> bool {
            self.inner
                .lock()
                .unwrap()
                .contains_key(&(kind, deployment_id.to_string(), None))
        }

        /// The number of currently armed faults in THIS registry (property
        /// tests assert the count tracks the oracle exactly).
        pub(crate) fn armed_len(&self) -> usize {
            self.inner.lock().unwrap().len()
        }

        /// Remove EVERY armed fault in this registry. The outcome-oracle
        /// property test arms one fault per step and disarms the leftovers
        /// between steps: the target-keyed debt arms are not deployment-id
        /// scoped, so a fault a step did not consume would otherwise fire on
        /// a later step of the same fixture.
        pub(crate) fn clear(&self) {
            self.inner.lock().unwrap().clear();
        }

        // ---- arm_* convenience surface (historical API) --------------
        //
        // These mirror the historical module-level `arm_<kind>(id)` /
        // `arm_<kind>(id, target)` functions one-to-one, so a call site that
        // used to read `test_faults::arm_<kind>(id)` converts mechanically to
        // `store.fault_registry().arm_<kind>(id)` (only the receiver
        // changes).

        /// Arm the next `append_snapshot` call for `deployment_id` to fail once.
        pub(crate) fn arm_append_snapshot(&self, deployment_id: &str) {
            self.arm(FaultKind::AppendSnapshot, deployment_id);
        }

        /// Arm the next `write_last_successful` call for `deployment_id` to
        /// fail once.
        pub(crate) fn arm_write_last_successful(&self, deployment_id: &str) {
            self.arm(FaultKind::WriteLastSuccessful, deployment_id);
        }

        /// Arm the next `append_transition` call for `deployment_id` to fail
        /// once.
        pub(crate) fn arm_append_transition(&self, deployment_id: &str) {
            self.arm(FaultKind::AppendTransition, deployment_id);
        }

        /// Arm the next `append_transition` call recording a `Successful`
        /// status for `deployment_id` to fail once. The replay-safe
        /// finalizer ([`crate::history::finalize_successful_attempt`]) writes
        /// the recoverable `PendingCommit` marker FIRST and the terminal
        /// `Successful` transition LAST, so faulting the terminal transition
        /// (rather than the earlier marker) requires qualifying on the
        /// recorded status: the `PendingCommit` marker append passes through
        /// untouched.
        pub(crate) fn arm_append_transition_successful(&self, deployment_id: &str) {
            self.arm(FaultKind::AppendTransitionSuccessful, deployment_id);
        }

        /// Arm the next `append_attempt` call for `deployment_id` to fail
        /// once. The attempt intent is persisted BEFORE any remote mutation,
        /// so a one-shot failure here leaves the remote untouched (no
        /// generation, no `current` change).
        pub(crate) fn arm_append_attempt(&self, deployment_id: &str) {
            self.arm(FaultKind::AppendAttempt, deployment_id);
        }

        /// Arm the next `write_results` call for `deployment_id` to fail
        /// once. The outcomes store (`deployments/<id>/results.json`) is then
        /// absent; a later recovery finalizes from the verified desired state
        /// instead.
        pub(crate) fn arm_write_results(&self, deployment_id: &str) {
            self.arm(FaultKind::WriteResults, deployment_id);
        }

        /// Arm the next `append_transition` call recording a `PendingCommit`
        /// status for `deployment_id` to fail once. Qualifies on the recorded
        /// status, mirroring [`FaultRegistry::arm_append_transition_successful`]:
        /// the earlier `InProgress` transition (and every non-pending
        /// transition) passes through untouched, and the one-shot fires ONLY
        /// at the recoverable `PendingCommit` marker — the first step of the
        /// shared finalizer ([`crate::history::finalize_successful_attempt`])
        /// — leaving the attempt's latest transition `InProgress` with intent
        /// + outcomes durable.
        pub(crate) fn arm_append_transition_pending(&self, deployment_id: &str) {
            self.arm(FaultKind::AppendTransitionPending, deployment_id);
        }

        /// Arm the next `write_server` call that records `deployment_id`
        /// (its `last_observed.last_deployment`) under `target` (its
        /// `last_seen_target`) to fail once. This is the post-commit
        /// observed-refresh per-server record write; the fault fires only
        /// when BOTH the deployment id and the target match, so the
        /// `servers/` writes of unrelated concurrent tests pass through
        /// untouched.
        pub(crate) fn arm_write_server(&self, deployment_id: &str, target: &str) {
            self.arm_target(FaultKind::WriteServer, deployment_id, target);
        }

        /// Arm the next `write_slot_observed` call that writes
        /// `deployment_id`'s SLOT record (`slots/<slot-id>/observed.json`) to
        /// fail once. Observed state is ONE PHYSICAL RECORD PER SLOT — the
        /// engine writes each advanced slot exactly once, never per target —
        /// so the slot half of the key selects exactly one physical write
        /// (e.g. a fixture's FIRST vs SECOND advanced slot).
        pub(crate) fn arm_write_observed(&self, deployment_id: &str, slot: &str) {
            self.arm_target(FaultKind::WriteObserved, deployment_id, slot);
        }

        /// Arm the next `read_rotation_debt` call for `target` to fail once
        /// (rotation-maintenance debt, keyed by target). Absorbs the
        /// debt-I/O sibling agent's `arm_read_rotation_debt`.
        pub(crate) fn arm_read_rotation_debt(&self, target: &str) {
            self.arm(FaultKind::ReadRotationDebt, target);
        }

        /// Arm the next `write_rotation_debt` call for `target` to fail once
        /// (rotation-maintenance debt, keyed by target). Absorbs the
        /// debt-I/O sibling agent's `arm_write_rotation_debt`.
        pub(crate) fn arm_write_rotation_debt(&self, target: &str) {
            self.arm(FaultKind::WriteRotationDebt, target);
        }

        /// Arm the next `write_history_floor` call for `deployment_id` (the
        /// checkpoint deployment) to fail once. A failure here fires BEFORE
        /// the floor marker is durable: no floor, no compaction — the
        /// checkpoint fails cleanly with history fully intact.
        pub(crate) fn arm_write_history_floor(&self, deployment_id: &str) {
            self.arm(FaultKind::WriteHistoryFloor, deployment_id);
        }

        /// Arm the next history-floor TEMP-FILE FSYNC (the first durability
        /// stage of `write_history_floor`, keyed by the checkpoint
        /// deployment id) to fail once. The failure is returned from
        /// `write_history_floor` itself — a PRE-marker failure, so no floor
        /// exists and no compaction can run.
        pub(crate) fn arm_sync_floor_temp(&self, deployment_id: &str) {
            self.arm(FaultKind::SyncFloorTemp, deployment_id);
        }

        /// Arm the next checkpoint floor marker RENAME-into-place (the
        /// second durability stage of `write_history_floor`, keyed by the
        /// checkpoint deployment id) to fail once. The failure is returned
        /// from `write_history_floor` itself — a PRE-marker failure, so no
        /// floor exists and no compaction can run.
        pub(crate) fn arm_rename_floor(&self, deployment_id: &str) {
            self.arm(FaultKind::RenameFloor, deployment_id);
        }

        /// Arm the next checkpoint floor marker PARENT-DIRECTORY FSYNC (the
        /// third durability stage of `write_history_floor` — the durability
        /// commit point, keyed by the checkpoint deployment id) to fail
        /// once. The marker may already be renamed into place when this
        /// fires; `write_history_floor` unlinks it (on an ADVANCE it then
        /// restores the previous floor A from the backup, so a failed
        /// advancement never erases the previously durable floor) and
        /// returns the failure.
        pub(crate) fn arm_sync_floor_parent(&self, deployment_id: &str) {
            self.arm(FaultKind::SyncFloorParent, deployment_id);
        }

        /// Arm the next checkpoint floor-marker BACKUP RENAME (the first
        /// stage of a TRANSACTIONAL ADVANCE — `history-floor.json` →
        /// `history-floor.json.prev.<id>`, the transaction-tagged backup
        /// name, keyed by the checkpoint deployment id) to fail once. The
        /// fault fires BEFORE the rename, so the previous floor A never
        /// moves: the staged temp is dropped and the failure is returned
        /// from `write_history_floor` — the failed advance leaves A
        /// durable.
        pub(crate) fn arm_rename_floor_backup(&self, deployment_id: &str) {
            self.arm(FaultKind::RenameFloorBackup, deployment_id);
        }

        /// Arm the next checkpoint floor-marker RESTORE (the fail-closed
        /// half of a TRANSACTIONAL ADVANCE, keyed by the checkpoint
        /// deployment id) to fail once. The restore is only attempted when
        /// an EARLIER advance stage already failed; a fault here leaves the
        /// previous floor A in the tagged backup and the marker absent —
        /// every read then fails closed with an integrity error (a torn
        /// advance is never "no floor").
        pub(crate) fn arm_restore_floor(&self, deployment_id: &str) {
            self.arm(FaultKind::RestoreFloor, deployment_id);
        }

        /// Arm the next checkpoint floor-marker success-path BACKUP REMOVAL
        /// (the best-effort cleanup of THIS transaction's tagged backup
        /// after the floor committed, keyed by the checkpoint deployment
        /// id) to fail once — the tagged backup (holding the pre-advance
        /// floor) stays on disk. Harmless by design: it is never restored
        /// by a different transaction and the next advance's pre-start
        /// reconciliation removes it durably.
        pub(crate) fn arm_remove_floor_backup(&self, deployment_id: &str) {
            self.arm(FaultKind::RemoveFloorBackup, deployment_id);
        }

        /// Arm the next checkpoint attempts.jsonl suffix rewrite for
        /// `deployment_id` (the checkpoint deployment) to fail once. The
        /// floor marker is ALREADY durable when this fires (the floor is
        /// written first), so an interrupted compaction must never expose
        /// history below the durable floor.
        pub(crate) fn arm_compact_attempts(&self, deployment_id: &str) {
            self.arm(FaultKind::CompactAttempts, deployment_id);
        }

        /// Arm the next checkpoint snapshots.jsonl suffix rewrite for
        /// `deployment_id` (the checkpoint deployment) to fail once. The
        /// floor marker is ALREADY durable when this fires.
        pub(crate) fn arm_compact_snapshots(&self, deployment_id: &str) {
            self.arm(FaultKind::CompactSnapshots, deployment_id);
        }

        /// Arm the next checkpoint `deployments/<id>/` directory deletion
        /// pass for `deployment_id` (the checkpoint deployment) to fail
        /// once. The floor marker is ALREADY durable when this fires, so
        /// even a total deletion failure leaves the visible history bounded
        /// below by the durable floor.
        pub(crate) fn arm_compact_deployments(&self, deployment_id: &str) {
            self.arm(FaultKind::CompactDeployments, deployment_id);
        }

        /// Arm the next cleanup-pending debt-marker WRITE for
        /// `deployment_id` (the floor's deployment id the marker names) to
        /// fail once. The write runs AFTER the floor marker is durable
        /// (post-commit maintenance); a failure is surfaced in the report
        /// as `cleanup_persistence_failed` — truthful reporting: the
        /// report never claims durable debt that a crash/restart would
        /// lose.
        pub(crate) fn arm_write_cleanup_pending(&self, deployment_id: &str) {
            self.arm(FaultKind::WriteCleanupPending, deployment_id);
        }

        /// Arm the next cleanup-pending debt-marker CLEAR for `target` to
        /// fail once (keyed by target — the marker lives under
        /// `targets/<target>/refs/`, mirroring the rotation-debt kinds).
        /// The clear runs after the compaction completes; a failure leaves
        /// a stale (harmless) marker that the retry re-clears, surfaced in
        /// the report as `cleanup_clear_failed`.
        pub(crate) fn arm_clear_cleanup_pending(&self, target: &str) {
            self.arm(FaultKind::ClearCleanupPending, target);
        }

        /// Arm the next artifact-GC SCAN for `deployment_id` (the
        /// checkpoint that triggers the GC) to fail once: the retained-set
        /// computation aborts BEFORE any deletion (fail closed), the
        /// checkpoint reports cleanup pending, and the retry recomputes
        /// reachability fresh.
        pub(crate) fn arm_gc_scan(&self, deployment_id: &str) {
            self.arm(FaultKind::GcScan, deployment_id);
        }

        /// Arm the next artifact-GC RELEASE deletion phase to fail once
        /// (keyed by the checkpoint deployment id): the unreachable release
        /// records stay on disk (extra garbage, never less) and the retry
        /// reclaims them.
        pub(crate) fn arm_gc_delete_releases(&self, deployment_id: &str) {
            self.arm(FaultKind::GcDeleteReleases, deployment_id);
        }

        /// Arm the next artifact-GC TREE deletion phase to fail once (keyed
        /// by the checkpoint deployment id).
        pub(crate) fn arm_gc_delete_trees(&self, deployment_id: &str) {
            self.arm(FaultKind::GcDeleteTrees, deployment_id);
        }
    }
}

/// Test-only step-17 phase hook: a per-fixture one-shot barrier that makes
/// step-17 lock contention DETERMINISTIC, distinguished by PHASE.
///
/// The engine calls [`Step17Hook::barrier`] immediately BEFORE a
/// step-17-equivalent lock acquisition — its per-slot rotation block in step
/// 17, and the deferred-maintenance retry that shares the same RAII-guarded
/// block — and passes the PHASE it is about to run
/// ([`HookPhase::FreshStep17`] vs [`HookPhase::DeferredRetry`]). The signal
/// the engine sends on the armed channel CARRIES that phase, so a test can
/// tell WHICH park it is servicing: the fresh per-slot rotation of THIS
/// push (where the contention else-branch defers the rotation as debt) or
/// the deferred-maintenance retry (which reads the debt FIRST). When a test
/// armed the hook for THIS deployment id, the engine (a) signals
/// "at step-17 lock acquisition" with the phase on the armed channel, then
/// (b) BLOCKS until the test releases it: while the engine is parked, the
/// test acquires the slot's mutation lock via a SECOND helper (and may arm
/// per-phase faults), then releases the engine — whose own acquisition
/// afterwards deterministically contends (no thread ever races on the lock
/// file). Unarmed stores and non-matching deployment ids pass through
/// untouched, and the whole module is `#[cfg(test)]` (the engine call sites
/// are `#[cfg(test)]` too), so this is a NO-OP in production builds.
///
/// The phase distinction exists so a test can arm a debt fault ONLY at the
/// phase that must fault: the retry phase (which reads the debt marker
/// FIRST, before any park) parks and releases WITHOUT the fault armed, and
/// the fresh step-17 phase (whose contended deferral runs the debt
/// read/write) arms it — the one-shot fault then fires at the INTENDED
/// phase instead of being consumed by the retry's earlier I/O.
///
/// Like the fault registry, the hook is PER-FIXTURE — owned by each
/// [`crate::store::local::LocalStore`], never a process-global slot: a hook
/// armed by one test can never fire in another fixture's push, so the
/// parallel `cargo test` threads stay structurally isolated. The
/// deployment-id half of the arm keys the barrier to exactly one push
/// (property cases and the contention test all use unique ids), so a hook
/// cannot even fire for a DIFFERENT push of the same fixture.
///
/// CANCELLATION SAFETY: dropping the handle must NEVER deadlock a parked
/// engine. A parked `barrier` holds the slot mutex while it waits, so the
/// drop must wake the engine BEFORE it takes that mutex to disarm. The wake
/// is by CHANNEL DISCONNECT, not by a token: the handle owns the ONLY sender
/// of the release channel, and [`Drop for HookHandle`] closes the channel
/// FIRST (`self.release.take()`, which needs no lock) so every parked
/// `recv()` returns `Err(RecvError)` unconditionally — no dependence on
/// which recv consumes a token. The token-based scheme deadlocked exactly
/// there: with MULTIPLE phases (deferred-maintenance retry + fresh step-17
/// rotation), a stale release token from a prior phase could be consumed by
/// the WRONG recv, leaving a later park waiting forever while its `barrier`
/// held the slot mutex — and the drop's own `inner.lock()` then blocked on
/// that held mutex, so nothing could ever release the parked engine. Only
/// AFTER the close does the drop take the slot mutex to disarm (the parked
/// engine has been woken and released it), and a fresh `barrier` after that
/// is a no-op. The [`step17_hook_property_tests`] matrix asserts the
/// guarantee across 1-4 phases × arbitrary cancellation points.
#[cfg(test)]
pub(crate) mod step17_hook {
    use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use crate::model::DeploymentId;

    /// WHICH step-17-equivalent lock acquisition the engine is parked at.
    /// Carried on the "at step-17" signal so the test-facing handle can
    /// tell the phases apart and act (e.g. arm a debt fault) only at the
    /// phase it intends to fault.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum HookPhase {
        /// The deferred-maintenance retry ([`crate::push::engine`]'s
        /// `retry_deferred_rotations`): the engine reads the rotation debt
        /// FIRST (before this park), then services each slot under the
        /// mutation lock. Runs on later pushes — before the fresh step-17
        /// rotation on the normal path and at the no-op return — whenever a
        /// prior push left a debt marker.
        DeferredRetry,
        /// The fresh per-slot rotation of THIS push (step 17): the
        /// post-commit rotation of every slot the push's target belongs to.
        /// Its contended else-branch defers the maintenance as a debt
        /// marker (a debt read-modify-write) — the phase where a debt-I/O
        /// fault is meant to fire.
        FreshStep17,
    }

    /// The armed half stored in the per-fixture slot: the ENGINE-facing ends.
    struct Armed {
        deployment_id: String,
        /// engine -> test: fired once, the instant the engine is parked,
        /// carrying the phase the engine is about to run.
        at_step17: Sender<HookPhase>,
        /// test -> engine: the engine parks here until the test releases it.
        release: Receiver<()>,
    }

    /// Per-fixture one-shot step-17 phase hook slot. Created empty by
    /// [`crate::store::local::LocalStore::with_base`]; a test arms it via
    /// [`Step17Hook::arm`] immediately before the push under test. The
    /// engine-side [`Step17Hook::barrier`] is a no-op while the slot is
    /// empty or the deployment id does not match.
    #[derive(Default)]
    pub(crate) struct Step17Hook {
        inner: Mutex<Option<Armed>>,
    }

    impl Step17Hook {
        /// Arm the hook for `deployment_id` (replacing any prior arm — a
        /// fired handle already left the slot empty) and return the
        /// TEST-facing handle. The engine of a push carrying THIS deployment
        /// id will now signal + park at EVERY step-17-equivalent lock
        /// acquisition (the deferred-maintenance retry AND the fresh step-17
        /// rotation), each signal carrying its [`HookPhase`]; the test receives
        /// each signal, holds the competing lock guard (and may arm per-phase
        /// faults), then releases the engine via [`HookHandle::release`].
        pub(crate) fn arm(hook: &Arc<Self>, deployment_id: &str) -> HookHandle {
            let (at_tx, at_rx) = channel();
            let (rel_tx, rel_rx) = channel();
            *hook.inner.lock().unwrap() = Some(Armed {
                deployment_id: deployment_id.to_string(),
                at_step17: at_tx,
                release: rel_rx,
            });
            HookHandle {
                hook: Arc::clone(hook),
                at_step17: at_rx,
                release: Some(rel_tx),
            }
        }

        /// ENGINE-side, called immediately before a step-17-equivalent lock
        /// acquisition: signal "at step-17" (with the phase being entered) and
        /// park until the test releases the engine — or return immediately when
        /// unarmed / the deployment id does not match. NEVER called from
        /// production code (the call sites in `src/push/engine.rs` are
        /// `#[cfg(test)]`).
        ///
        /// The slot mutex stays held while parked so a concurrently-dropped
        /// handle cannot disarm mid-park — but the park is woken by CHANNEL
        /// DISCONNECT, not by a token: [`HookHandle::drop`] closes the release
        /// channel FIRST (it drops its own sender half, taking no lock), so
        /// this `recv` returns `Err(RecvError)` the instant the handle drops,
        /// no matter which park is waiting or how many release tokens were
        /// already consumed. There is no dependence on a token reaching THE
        /// RIGHT `recv`: every parked engine wakes unconditionally, and a
        /// barrier arriving after the close returns immediately. Because the
        /// drop takes the slot mutex only AFTER the close, a parked engine
        /// holding that mutex is always woken (and releases it) before the
        /// disarm blocks on it — dropping the handle can never deadlock
        /// against a park.
        pub(crate) fn barrier(&self, deployment_id: &DeploymentId, phase: HookPhase) {
            let guard = self.inner.lock().unwrap();
            let Some(armed) = guard.as_ref() else {
                return;
            };
            if armed.deployment_id != deployment_id.as_str() {
                return;
            }
            let _ = armed.at_step17.send(phase);
            let _ = armed.release.recv();
        }
    }

    /// The TEST-facing handle: owns the receive end of the "at step 17"
    /// signal and the send end of the release. Dropping the handle disarms
    /// the slot AND wakes any parked engine first, so a panicked test can
    /// never strand the engine thread (see the module docs for the
    /// cancellation-safe ordering).
    pub(crate) struct HookHandle {
        hook: Arc<Step17Hook>,
        at_step17: Receiver<HookPhase>,
        /// `Some` while the handle is live; `Drop` takes it (closing the
        /// release channel — waking every parked `recv` — without taking the
        /// slot mutex) BEFORE disarming.
        release: Option<Sender<()>>,
    }

    impl HookHandle {
        /// Like [`HookHandle::wait_at_step17_bounded`], but bounded: returns
        /// `Err(Timeout)` when the engine did not fire within `timeout` —
        /// the caller then checks whether the push already completed (the
        /// hook will never fire, e.g. an up-to-date no-op with no debt).
        /// On success returns the [`HookPhase`] the engine is parked at.
        pub(crate) fn wait_at_step17_bounded(
            &self,
            timeout: Duration,
        ) -> Result<HookPhase, RecvTimeoutError> {
            self.at_step17.recv_timeout(timeout)
        }

        /// Release the parked engine: its step-17 lock acquisition now runs
        /// while the fixture holds the competing guard, so it contends
        /// deterministically. Safe to call more than once (an extra token is
        /// simply dropped with the handle); a no-op once the handle has been
        /// dropped (the release sender is gone).
        pub(crate) fn release(&self) {
            if let Some(tx) = &self.release {
                let _ = tx.send(());
            }
        }
    }

    impl Drop for HookHandle {
        fn drop(&mut self) {
            // CANCELLATION-SAFE ORDER: close the release channel FIRST by
            // dropping this handle's sender half (`self.release.take()`). Any
            // parked engine's `recv()` now returns `Err(RecvError)`
            // immediately — the wake does NOT depend on a token reaching any
            // particular `recv`, so a parked engine can never be left waiting
            // (a stale token from a prior phase can no longer be consumed by
            // the wrong park). This takes NO lock, so an engine parked with
            // the slot mutex held can always wake and release it. Only THEN
            // take the slot mutex to disarm: it is free (or freed within µs
            // as the woken engine unwinds) by the time we acquire it, so the
            // drop never blocks on a parked engine. The close also makes any
            // LATER `barrier` — racing the disarm or arriving after it —
            // return immediately.
            self.release.take();
            *self.hook.inner.lock().unwrap() = None;
        }
    }
}

/// Test-only fake remote transports + the recording factory: the shared
/// `LocalTransport`-wrapping fixtures that the engine and semantic test
/// suites build fake remotes from (each wrapper delegates every trait method
/// to an inner [`crate::remote::transport::LocalTransport`]).
///
/// The `FailOnce*` wrappers fail EXACTLY ONE matching operation — the
/// commit-marker write ([`FailOnceMarkerRemote`]), the generation-record
/// write ([`FailOnceGenerationRemote`]), or the incoming staging upload
/// ([`FailOnceStagingRemote`]) — then disarm and pass through untouched:
/// deterministic fault injection with no sleeps, the crate-internal mirror of
/// the integration-test `FailOnce*Remote` family.
///
/// [`CountingRemote`] + [`recording_factory`] form the ZERO-FACTORY-
/// INVOCATIONS seam: every factory invocation (each remote construction) and
/// every call on the produced remotes increments a shared counter, so a test
/// can assert the push engine never touched a remote at all (the dry-run ref
/// prevalidation and direct-release membership gates run BEFORE any factory
/// invocation).
#[cfg(test)]
pub(crate) mod test_remotes {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use crate::error::{Error, Result};
    use crate::remote::transport::{LocalTransport, Remote};

    /// A remote that fails commit marker writes exactly once: the first
    /// write/create under `state/commits/` errors (leaving the marker absent),
    /// then the wrapper behaves normally. Lets a test record a `PendingCommit`
    /// attempt on the first push and observe the next push's reconciliation
    /// completing the markers with the ORIGINAL deployment ID. Mirror of the
    /// integration-test `FailOnceMarkerRemote`, kept in-crate because the
    /// store fault hooks are `#[cfg(test)]` crate-internal.
    pub(crate) struct FailOnceMarkerRemote {
        inner: LocalTransport,
        armed: Arc<AtomicBool>,
    }

    impl FailOnceMarkerRemote {
        pub(crate) fn build(base: PathBuf, armed: Arc<AtomicBool>) -> Result<Box<dyn Remote>> {
            Ok(Box::new(FailOnceMarkerRemote {
                inner: LocalTransport::new(base)?,
                armed,
            }))
        }
        fn fail_marker(&self, rel: &std::path::Path) -> bool {
            self.armed.load(Ordering::SeqCst) && rel.to_string_lossy().starts_with("state/commits/")
        }
    }

    impl Remote for FailOnceMarkerRemote {
        fn root(&self) -> &std::path::Path {
            self.inner.root()
        }
        fn read(&self, rel: &std::path::Path) -> Result<Vec<u8>> {
            self.inner.read(rel)
        }
        fn write(&self, rel: &std::path::Path, data: &[u8], mode: u32) -> Result<()> {
            if self.fail_marker(rel) {
                self.armed.store(false, Ordering::SeqCst);
                return Err(Error::remote(
                    "FailOnceMarkerRemote: commit marker write forced to fail (once)",
                ));
            }
            self.inner.write(rel, data, mode)
        }
        fn try_write_new(&self, rel: &std::path::Path, data: &[u8]) -> Result<bool> {
            if self.fail_marker(rel) {
                self.armed.store(false, Ordering::SeqCst);
                return Err(Error::remote(
                    "FailOnceMarkerRemote: commit marker create forced to fail (once)",
                ));
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
        fn list(
            &self,
            rel: &std::path::Path,
        ) -> Result<Vec<crate::remote::transport::RemoteEntry>> {
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
            self.inner.filesystem_bytes()
        }
    }
    /// A remote that fails the FIRST generation-record write exactly once
    /// (`try_write_new` under `generations/`), then behaves normally. Fires
    /// inside `create_generation`, i.e. AFTER the intent is durable and BEFORE
    /// the server's `current` advances: the exact mid-mutation window.
    pub(crate) struct FailOnceGenerationRemote {
        inner: LocalTransport,
        armed: Arc<AtomicBool>,
    }

    impl FailOnceGenerationRemote {
        pub(crate) fn build(base: PathBuf, armed: Arc<AtomicBool>) -> Result<Box<dyn Remote>> {
            Ok(Box::new(FailOnceGenerationRemote {
                inner: LocalTransport::new(base)?,
                armed,
            }))
        }
        fn fail_generation(&self, rel: &std::path::Path) -> bool {
            self.armed.load(Ordering::SeqCst)
                && rel.to_string_lossy().starts_with("generations/")
                && rel.to_string_lossy().ends_with("assignment.json")
        }
    }

    impl Remote for FailOnceGenerationRemote {
        fn root(&self) -> &std::path::Path {
            self.inner.root()
        }
        fn read(&self, rel: &std::path::Path) -> Result<Vec<u8>> {
            self.inner.read(rel)
        }
        fn write(&self, rel: &std::path::Path, data: &[u8], mode: u32) -> Result<()> {
            self.inner.write(rel, data, mode)
        }
        fn try_write_new(&self, rel: &std::path::Path, data: &[u8]) -> Result<bool> {
            if self.fail_generation(rel) {
                self.armed.store(false, Ordering::SeqCst);
                return Err(Error::remote(
                    "FailOnceGenerationRemote: generation write forced to fail (once)",
                ));
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
        fn list(
            &self,
            rel: &std::path::Path,
        ) -> Result<Vec<crate::remote::transport::RemoteEntry>> {
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
            self.inner.filesystem_bytes()
        }
    }
    /// A transport wrapper that fails the FIRST file write under `incoming/`
    /// (the staging upload) once, letting a test inject a staging failure
    /// deterministically. Mirrors the `FailOnceMarkerRemote` pattern from
    /// tests/integration.rs: the fault fires on the first `write` whose path
    /// starts with `incoming/` and disarms itself, while every other call —
    /// including the `create_dir_all` that creates the incoming directory and
    /// the `control/`/`state/` writes of the handshake — passes through
    /// untouched. Failing the file WRITE (rather than the directory create)
    /// leaves a real partial upload behind, so a test can assert the
    /// best-effort incoming cleanup removed it.
    pub(crate) struct FailOnceStagingRemote {
        inner: LocalTransport,
        armed: Arc<AtomicBool>,
    }

    impl FailOnceStagingRemote {
        pub(crate) fn build(base: PathBuf, armed: Arc<AtomicBool>) -> Result<Box<dyn Remote>> {
            Ok(Box::new(FailOnceStagingRemote {
                inner: LocalTransport::new(base)?,
                armed,
            }))
        }
        fn fail_staging_write(&self, rel: &std::path::Path) -> bool {
            self.armed.load(Ordering::SeqCst) && rel.to_string_lossy().starts_with("incoming/")
        }
    }

    impl Remote for FailOnceStagingRemote {
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
            if self.fail_staging_write(rel) {
                self.armed.store(false, Ordering::SeqCst);
                return Err(Error::remote(
                    "FailOnceStagingRemote: incoming staging write forced to fail (once)",
                ));
            }
            self.inner.write(rel, data, mode)
        }
        fn try_write_new(&self, rel: &std::path::Path, data: &[u8]) -> Result<bool> {
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
        fn list(
            &self,
            rel: &std::path::Path,
        ) -> Result<Vec<crate::remote::transport::RemoteEntry>> {
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
            self.inner.filesystem_bytes()
        }
    }
    /// A remote that counts EVERY trait-method call (delegating the
    /// operation to the wrapped `LocalTransport`), so a test can assert the
    /// push engine never touched a remote at all: with an INVALID ref and
    /// `--dry-run`, the counter must stay at zero.
    pub(crate) struct CountingRemote {
        inner: LocalTransport,
        calls: Arc<AtomicUsize>,
    }

    impl CountingRemote {
        fn new(base: PathBuf, calls: Arc<AtomicUsize>) -> Result<Self> {
            Ok(CountingRemote {
                inner: LocalTransport::new(base)?,
                calls,
            })
        }
        fn tick(&self) {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Remote for CountingRemote {
        fn root(&self) -> &std::path::Path {
            self.inner.root()
        }
        fn read(&self, rel: &std::path::Path) -> Result<Vec<u8>> {
            self.tick();
            self.inner.read(rel)
        }
        fn write(&self, rel: &std::path::Path, data: &[u8], mode: u32) -> Result<()> {
            self.tick();
            self.inner.write(rel, data, mode)
        }
        fn try_write_new(&self, rel: &std::path::Path, data: &[u8]) -> Result<bool> {
            self.tick();
            self.inner.try_write_new(rel, data)
        }
        fn create_dir(&self, rel: &std::path::Path) -> Result<()> {
            self.tick();
            self.inner.create_dir(rel)
        }
        fn create_dir_all(&self, rel: &std::path::Path) -> Result<()> {
            self.tick();
            self.inner.create_dir_all(rel)
        }
        fn set_mode(&self, rel: &std::path::Path, mode: u32) -> Result<()> {
            self.tick();
            self.inner.set_mode(rel, mode)
        }
        fn list(
            &self,
            rel: &std::path::Path,
        ) -> Result<Vec<crate::remote::transport::RemoteEntry>> {
            self.tick();
            self.inner.list(rel)
        }
        fn rename(&self, from: &std::path::Path, to: &std::path::Path) -> Result<()> {
            self.tick();
            self.inner.rename(from, to)
        }
        fn symlink(&self, target: &std::path::Path, link: &std::path::Path) -> Result<()> {
            self.tick();
            self.inner.symlink(target, link)
        }
        fn read_link(&self, rel: &std::path::Path) -> Result<std::path::PathBuf> {
            self.tick();
            self.inner.read_link(rel)
        }
        fn remove_file(&self, rel: &std::path::Path) -> Result<()> {
            self.tick();
            self.inner.remove_file(rel)
        }
        fn remove_dir_all(&self, rel: &std::path::Path) -> Result<()> {
            self.tick();
            self.inner.remove_dir_all(rel)
        }
        fn exists(&self, rel: &std::path::Path) -> bool {
            self.tick();
            self.inner.exists(rel)
        }
        fn metadata(&self, rel: &std::path::Path) -> Result<crate::remote::transport::RemoteMeta> {
            self.tick();
            self.inner.metadata(rel)
        }
        fn exec(
            &self,
            argv: &[String],
            timeout: std::time::Duration,
        ) -> Result<crate::remote::transport::ExecOutcome> {
            self.tick();
            self.inner.exec(argv, timeout)
        }
        fn filesystem_bytes(&self) -> Result<crate::remote::transport::FsBytes> {
            self.tick();
            self.inner.filesystem_bytes()
        }
    }
    /// A RECORDING factory: every factory invocation (each remote
    /// construction) AND every call on the produced remotes increments a
    /// shared counter. The remotes delegate to `LocalTransport` rooted at
    /// `base/<server-id>` (mirroring the harness factory), so a push through
    /// this factory behaves exactly like a real one — the counters just tell
    /// us whether ANY remote was touched.
    pub(crate) fn recording_factory(
        base: PathBuf,
        calls: Arc<AtomicUsize>,
    ) -> impl Fn(&crate::config::ServerDef, &crate::config::SlotDef) -> Result<Box<dyn Remote>>
    {
        move |s, _slot| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(CountingRemote::new(
                base.join(&s.id),
                calls.clone(),
            )?))
        }
    }
}

#[cfg(test)]
mod registry_property_tests {
    // Property tests for the per-fixture fault registry: two DISTINCT fault
    // keys, interleaved arm/consume operations, and the exact-once oracle.

    use super::test_faults::{FaultKind, FaultRegistry};
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::collections::BTreeSet;

    const ID_A: &str = "deploy-prop-a";
    const ID_B: &str = "deploy-prop-b";
    const ID_FOREIGN: &str = "deploy-prop-foreign";

    /// A registry operation over the two distinct keys. `WrongKindConsume`
    /// consumes a DIFFERENT fault kind under key A (the "other operation"),
    /// and `ForeignIdConsume` consumes key A's kind under a third, never-armed
    /// id — both must never fire and never disarm.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum RegOp {
        ArmA,
        ArmB,
        ConsumeA,
        ConsumeB,
        WrongKindConsume,
        ForeignIdConsume,
    }

    fn reg_op_strategy() -> impl Strategy<Value = RegOp> {
        prop_oneof![
            Just(RegOp::ArmA),
            Just(RegOp::ArmB),
            Just(RegOp::ConsumeA),
            Just(RegOp::ConsumeB),
            Just(RegOp::WrongKindConsume),
            Just(RegOp::ForeignIdConsume),
        ]
    }

    /// Apply one op to the real registry and to the oracle set; every step
    /// must agree (fire/not-fire, disarm/not-disarm).
    fn apply(op: RegOp, reg: &FaultRegistry, oracle: &mut BTreeSet<(FaultKind, String)>) {
        let key_a = (FaultKind::AppendAttempt, ID_A.to_string());
        let key_b = (FaultKind::AppendAttempt, ID_B.to_string());
        match op {
            RegOp::ArmA => {
                reg.arm(FaultKind::AppendAttempt, ID_A);
                oracle.insert(key_a);
            }
            RegOp::ArmB => {
                reg.arm(FaultKind::AppendAttempt, ID_B);
                oracle.insert(key_b);
            }
            RegOp::ConsumeA => {
                let fired = reg.consume(FaultKind::AppendAttempt, ID_A);
                let expected = oracle.remove(&key_a);
                assert_eq!(
                    fired, expected,
                    "A fires exactly when its own arm is pending (one-shot)"
                );
            }
            RegOp::ConsumeB => {
                let fired = reg.consume(FaultKind::AppendAttempt, ID_B);
                let expected = oracle.remove(&key_b);
                assert_eq!(
                    fired, expected,
                    "B fires exactly when its own arm is pending (one-shot)"
                );
            }
            RegOp::WrongKindConsume => {
                // The OTHER operation (write_results) on key A: never fires
                // the AppendAttempt arm and never disarms it.
                assert!(
                    !reg.consume(FaultKind::WriteResults, ID_A),
                    "a different fault kind must never fire A's arm"
                );
            }
            RegOp::ForeignIdConsume => {
                assert!(
                    !reg.consume(FaultKind::AppendAttempt, ID_FOREIGN),
                    "a never-armed id must never fire either key"
                );
            }
        }
        assert_eq!(
            reg.armed_len(),
            oracle.len(),
            "the registry's armed set must track the oracle exactly"
        );
        for (kind, id) in oracle.iter() {
            assert!(
                reg.is_armed(*kind, id),
                "{id}: an oracle-armed key must be armed in the registry"
            );
        }
    }

    // Property test: arbitrary interleavings of arms and consumes over two
    // distinct keys. Oracle: each fault is consumed EXACTLY ONCE by its
    // matching (kind, id) consume; re-consume does not fire again; a
    // mismatched kind or id NEVER fires. Fixed seed + bounded cases for
    // deterministic `cargo test` runs (like `src/semantic_invariants.rs`).
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 256,
            rng_seed: RngSeed::Fixed(0xFA17_FA17),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn two_key_fault_interleavings_consume_exactly_once(
            ops in prop::collection::vec(reg_op_strategy(), 0..24),
        ) {
            let reg = FaultRegistry::default();
            let mut oracle: BTreeSet<(FaultKind, String)> = BTreeSet::new();
            for op in ops {
                apply(op, &reg, &mut oracle);
            }
        }
    }

    /// Exhaustive check of the strongest interleaving: every ordering that
    /// merges two sequences — arm A then two consumes of A (the second must
    /// NOT fire), arm B then two consumes of B — while preserving each
    /// sequence's internal order. All C(6,3) = 20 orderings must satisfy the
    /// exact-once oracle: each fault is consumed exactly once by its matching
    /// key and never fires for the other.
    #[test]
    fn two_key_exhaustive_interleavings_consume_each_arm_exactly_once() {
        let seq_a = [RegOp::ArmA, RegOp::ConsumeA, RegOp::ConsumeA];
        let seq_b = [RegOp::ArmB, RegOp::ConsumeB, RegOp::ConsumeB];
        let mut orderings = vec![];
        interleave(&mut orderings, &seq_a, &seq_b, 0, 0, &mut vec![]);
        assert_eq!(orderings.len(), 20, "C(6,3) order-preserving merges");
        for ops in orderings {
            let reg = FaultRegistry::default();
            let mut oracle: BTreeSet<(FaultKind, String)> = BTreeSet::new();
            for op in ops {
                apply(op, &reg, &mut oracle);
            }
            assert_eq!(oracle.len(), 0, "both arms consumed exactly once");
        }
    }

    /// Every order-preserving merge of `a` and `b` (each element keeps its
    /// relative position within its own sequence).
    fn interleave(
        out: &mut Vec<Vec<RegOp>>,
        a: &[RegOp],
        b: &[RegOp],
        i: usize,
        j: usize,
        acc: &mut Vec<RegOp>,
    ) {
        if i == a.len() && j == b.len() {
            out.push(acc.clone());
            return;
        }
        if i < a.len() {
            acc.push(a[i]);
            interleave(out, a, b, i + 1, j, acc);
            acc.pop();
        }
        if j < b.len() {
            acc.push(b[j]);
            interleave(out, a, b, i, j + 1, acc);
            acc.pop();
        }
    }
}

#[cfg(test)]
mod step17_hook_property_tests {
    // Property test for CANCELLATION SAFETY of the step-17 hook: dropping
    // the handle at an arbitrary moment — before any park, between parks, or
    // while the engine is parked at a random phase — must never deadlock the
    // engine, for ANY phase count (1-4, the engine's sequential barrier
    // calls). The token-based release deadlocked exactly here: with multiple
    // phases a stale release token could be consumed by the WRONG recv,
    // leaving a later park waiting forever while its `barrier` held the slot
    // mutex — and the drop's own `inner.lock()` then blocked on that held
    // mutex. The fix closes the release channel in `Drop` (dropping the only
    // Sender), which wakes EVERY parked recv unconditionally; every
    // assertion below is bounded via channels/timeouts (no sleeps).

    use super::step17_hook::{HookHandle, HookPhase, Step17Hook};
    use crate::model::DeploymentId;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::sync::Arc;
    use std::sync::mpsc::channel;
    use std::thread;
    use std::time::Duration;

    /// Bound for the worker to reach a park (hit only on a bug — the worker
    /// parks at every armed barrier, so the signal always arrives in µs).
    const PARK_BOUND: Duration = Duration::from_secs(30);
    /// Bound for the handle drop to complete (hit only on a bug: a
    /// cancellation-safe drop must never block on a parked engine's mutex).
    const DROP_BOUND: Duration = Duration::from_secs(5);
    /// Bound for the worker to exit (complete every barrier call) after the
    /// drop — the assertion channel, not a sleep.
    const WORKER_EXIT_BOUND: Duration = Duration::from_secs(30);
    /// Bound for a FRESH post-disarm `barrier` to return (it must no-op).
    const NOOP_BOUND: Duration = Duration::from_secs(5);

    /// WHERE the handle is dropped for one cancellation scenario.
    #[derive(Clone, Copy, Debug)]
    enum CancelPoint {
        /// Drop before observing any park: the worker may not have started,
        /// may be mid-flight, or may already be parked — the close must let
        /// it finish everything.
        BeforeFirstPark,
        /// Drop WHILE the worker is parked at park `phase` (1-based),
        /// holding the slot mutex: the close must wake it.
        WhileParked(usize),
        /// Release park `phase` (1-based), then drop WITHOUT waiting for the
        /// next park — the worker may be unwinding, re-parking, or parked:
        /// the close must let it finish.
        BetweenParks(usize),
    }

    /// Strategy: 1-4 phases the worker calls `barrier` for, plus a
    /// cancellation point valid for that count. With `n` phases there are
    /// `2n` points: one before any park, one per park (`WhileParked`), and
    /// one between consecutive parks (`BetweenParks`).
    fn scenario() -> impl Strategy<Value = (Vec<HookPhase>, CancelPoint)> {
        prop::collection::vec(
            prop_oneof![Just(HookPhase::DeferredRetry), Just(HookPhase::FreshStep17),],
            1..=4,
        )
        .prop_flat_map(|phases| {
            let n = phases.len() as u32;
            let point = (0..(2 * n)).prop_map(move |idx| match idx {
                0 => CancelPoint::BeforeFirstPark,
                i if i <= n => CancelPoint::WhileParked(i as usize),
                i => CancelPoint::BetweenParks((i - n) as usize),
            });
            (Just(phases), point)
        })
    }

    /// Block (bounded) until the worker signals park `park_idx` (1-based),
    /// and assert the signal still carries the phase the worker is about to
    /// run — the per-phase signal is part of the hook contract and must be
    /// unchanged by the cancellation fix.
    fn wait_for_park(handle: &HookHandle, phases: &[HookPhase], park_idx: usize) {
        let phase = handle
            .wait_at_step17_bounded(PARK_BOUND)
            .expect("the worker must reach every armed park");
        assert_eq!(
            phase,
            phases[park_idx - 1],
            "the park signal must carry the phase the worker is about to run"
        );
    }

    /// One matrix cell: `phases` × `point`. A worker thread calls
    /// [`Step17Hook::barrier`] once per phase and then reports completion;
    /// the driver advances to the cancellation point, drops the handle (on a
    /// helper thread, itself bounded), and asserts — all via bounded channel
    /// timeouts — that the worker EXITS and a fresh post-disarm barrier is a
    /// no-op.
    fn run_cancellation_case(
        hook: &Arc<Step17Hook>,
        id: &DeploymentId,
        phases: &[HookPhase],
        point: CancelPoint,
    ) {
        let handle = Step17Hook::arm(hook, id.as_str());
        let (done_tx, done_rx) = channel();
        let worker_hook = Arc::clone(hook);
        let worker_id = id.clone();
        let worker_phases = phases.to_vec();
        let worker = thread::spawn(move || {
            for phase in &worker_phases {
                worker_hook.barrier(&worker_id, *phase);
            }
            let _ = done_tx.send(());
        });

        // Advance to the cancellation point, servicing (releasing) every
        // park the driver must pass through.
        match point {
            CancelPoint::BeforeFirstPark => {}
            CancelPoint::WhileParked(i) => {
                for j in 1..i {
                    wait_for_park(&handle, phases, j);
                    handle.release();
                }
                wait_for_park(&handle, phases, i);
            }
            CancelPoint::BetweenParks(i) => {
                for j in 1..=i {
                    wait_for_park(&handle, phases, j);
                    handle.release();
                }
            }
        }

        // Drop on a helper thread and bound the drop itself: the close must
        // wake any parked engine before the disarm takes the slot mutex, so
        // `drop` can never block.
        let (drop_tx, drop_rx) = channel();
        let drop_thread = thread::spawn(move || {
            drop(handle);
            let _ = drop_tx.send(());
        });
        assert!(
            drop_rx.recv_timeout(DROP_BOUND).is_ok(),
            "dropping the handle must not block while the engine could be parked \
             (point {point:?}, {} phases)",
            phases.len()
        );

        // The worker must EXIT within the bound: every remaining barrier call
        // returns (the slot is disarmed / the channel closed) and the
        // completion message arrives.
        assert!(
            done_rx.recv_timeout(WORKER_EXIT_BOUND).is_ok(),
            "the worker must complete all its barrier calls after the handle is dropped \
             (point {point:?}, {} phases)",
            phases.len()
        );
        worker.join().expect("worker thread panicked");
        drop_thread.join().expect("drop thread panicked");

        // A FRESH barrier after the disarm is a no-op: it returns
        // immediately (asserted via a bounded completion channel).
        let (noop_tx, noop_rx) = channel();
        let noop_hook = Arc::clone(hook);
        let noop_id = id.clone();
        let noop = thread::spawn(move || {
            noop_hook.barrier(&noop_id, HookPhase::FreshStep17);
            let _ = noop_tx.send(());
        });
        assert!(
            noop_rx.recv_timeout(NOOP_BOUND).is_ok(),
            "a fresh barrier call after the drop must be a no-op \
             (point {point:?}, {} phases)",
            phases.len()
        );
        noop.join().expect("noop thread panicked");
    }

    // Property: for every generated (1-4 phases, arbitrary cancellation
    // point), dropping the handle lets the worker exit within the bound and
    // makes fresh barriers no-ops. Fixed seed + bounded cases for
    // deterministic `cargo test` runs (like the fault-registry property).
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 256,
            rng_seed: RngSeed::Fixed(0xC0FF_EE00),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn worker_exits_after_handle_drop_at_any_cancellation_point(
            (phases, point) in scenario(),
        ) {
            run_cancellation_case(&Arc::new(Step17Hook::default()), &DeploymentId::generate(), &phases, point);
        }
    }

    // Exhaustive matrix over phase-count × cancellation-point, deterministically
    // (independent of the proptest seed): every (n, point) combination with a
    // canonical alternating phase pattern must satisfy the same guarantee.
    #[test]
    fn exhaustive_cancellation_matrix() {
        for n in 1..=4 {
            let phases: Vec<HookPhase> = (0..n)
                .map(|i| {
                    if i % 2 == 0 {
                        HookPhase::FreshStep17
                    } else {
                        HookPhase::DeferredRetry
                    }
                })
                .collect();
            // The same 2n cancellation points as the property strategy.
            let mut points = vec![CancelPoint::BeforeFirstPark];
            points.extend((1..=n).map(CancelPoint::WhileParked));
            points.extend((1..n).map(CancelPoint::BetweenParks));
            for point in points {
                run_cancellation_case(
                    &Arc::new(Step17Hook::default()),
                    &DeploymentId::generate(),
                    &phases,
                    point,
                );
            }
        }
    }
}
