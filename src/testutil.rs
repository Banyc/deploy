//! Shared test-only utilities.
//!
//! # The hermetic-env invariant
//!
//! Tests NEVER read or mutate the process-global environment. Instead they
//! build a [`crate::env::SysEnv`] — via [`SysEnv::from_map`] for hermetic
//! values (a fake `systemctl`/`ssh` on `PATH`, a temp `XDG_CONFIG_HOME`,
//! fake-bin markers), or [`fixture_env`] for a plain snapshot — and pass it
//! to the fixture / transport under test. Child processes spawned by the
//! transports receive the snapshot via `Command::envs`; the parent process
//! environment is never touched. There is no `ENV_LOCK`: with zero
//! `std::env::set_var`/`remove_var` calls in the suite there is nothing to
//! serialize, and concurrent tests cannot corrupt each other (or spawn the
//! real binaries) because each test's children resolve from its own
//! snapshot.
//!
//! Temp placement goes through the snapshot too: [`fixture_tmpdir`] creates
//! a fresh tempdir under `env.temp_dir()` (which honors `TMPDIR` from the
//! snapshot, falling back to the platform temp dir) — no test reads
//! `std::env::temp_dir()` directly, and no test ever redirects `TMPDIR`.
//!
//! Note: each integration-test *binary* (`tests/*.rs`) is a separate process
//! and cannot race the lib tests.
//!
//! # The slow-test gate
//!
//! A test that individually exceeds ~20 SECONDS under the FULL gate
//! (`DEPLOY_FULL_TESTS=1 cargo nextest run --no-fail-fast`) is a SLOW test:
//! it runs ONLY under the full gate. The default gate (no env var) SKIPS it
//! with a printed `skipped:` note — a quick guarded no-op that still counts
//! as a passing test — so no default-gate test can exceed the ~20 s budget.
//! The skip guard is [`slow_tests_enabled`]; run the slow tests with
//! `DEPLOY_FULL_TESTS=1 cargo nextest run --no-fail-fast`.
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
//! Mechanical conversion for sibling fault work (e.g. the retention-debt arms
//! `arm_read_retention_debt` / `arm_write_retention_debt`): the registry keeps
//! the historical `arm_<kind>(id)` (and `arm_<kind>(id, target)`) method
//! surface, so a call site `test_faults::arm_<kind>(id)` converts by changing
//! only the receiver: `store.fault_registry().arm_<kind>(id)`. The store
//! method's consume hook converts to a one-line registry call:
//! `self.fault_registry.consume(FaultKind::<Kind>, id)`.

/// A fresh process-environment snapshot for tests that exercise NO
/// environment-dependent behavior (a transport whose children resolve from
/// the ambient `PATH`, e.g. `LocalTransport::new`/`SshTransport::new` in
/// filesystem-only tests). Tests that control the child environment build a
/// hermetic [`SysEnv::from_map`] and pass that instead — the transport's
/// children then receive the snapshot's variables, and the process env is
/// never touched.
#[cfg(test)]
pub(crate) fn fixture_env() -> crate::env::SysEnv {
    crate::env::SysEnv::from_process()
}

/// A fresh tempdir placed under the snapshot's `TMPDIR` (`env.temp_dir()`),
/// so tests never read the process environment for temp placement. A plain
/// `crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env())` reads `std::env::temp_dir()` implicitly — route all
/// test tempdirs through this helper instead.
#[cfg(test)]
pub(crate) fn fixture_tmpdir(env: &crate::env::SysEnv) -> std::io::Result<tempfile::TempDir> {
    tempfile::Builder::new().tempdir_in(env.temp_dir())
}

/// `true` when the FULL proptest budgets are requested (`DEPLOY_FULL_TESTS=1`).
/// The default (no env var) runs the FAST budgets: the same semantic
/// dimensions (all failure classes, all matrix arms, full sequence lengths),
/// but FEWER random draws per property.
#[cfg(test)]
pub(crate) fn full_proptest_suites() -> bool {
    std::env::var_os("DEPLOY_FULL_TESTS").is_some_and(|v| v != "0")
}

/// Whether SLOW tests are allowed to run (`DEPLOY_FULL_TESTS=1`). The
/// default (no env var) SKIPS the tests that individually exceed ~20 s
/// (measured under the full gate) so the default gate stays fast. The guard
/// lives at the top of each slow test's body: a default-gate run prints a
/// `skipped:` note and returns immediately (the test still shows as a
/// fast PASS), while a `DEPLOY_FULL_TESTS=1` run exercises the test in full.
#[cfg(test)]
pub(crate) fn slow_tests_enabled() -> bool {
    full_proptest_suites()
}

/// The proptest `cases:` budget: the full budget when full suites are
/// requested, else a FAST budget (full/4, clamped to at least 2 — the same
/// semantic dimensions, fewer samples).
#[cfg(test)]
pub(crate) fn proptest_cases(full: u32) -> u32 {
    if full_proptest_suites() {
        full
    } else {
        (full / 4).max(2)
    }
}

/// The externally-selectable proptest SEED: `RngSeed::Fixed(<DEPLOY_PROPSEED>)`
/// when the env var `DEPLOY_PROPSEED` is set (parsed as u64), else
/// `RngSeed::Fixed(default)`. The DEFAULT (no env var) is byte-for-byte the
/// current deterministic behavior — every test keeps its own house-style
/// seed as the `default` argument — while the CI DIVERSITY lane sets
/// `DEPLOY_PROPSEED` per matrix arm to run the same properties under
/// SEVERAL CI-SUPPLIED SEEDS (depth is unchanged, diversity is new).
#[cfg(test)]
pub(crate) fn proptest_seed(default: u64) -> proptest::test_runner::RngSeed {
    match std::env::var("DEPLOY_PROPSEED") {
        Ok(v) => v.trim().parse::<u64>().map_or(
            proptest::test_runner::RngSeed::Fixed(default),
            proptest::test_runner::RngSeed::Fixed,
        ),
        Err(_) => proptest::test_runner::RngSeed::Fixed(default),
    }
}

/// The externally-selectable ACTION-TRACE LENGTH for the semantic state
/// machines: `DEPLOY_PROPSTEPS` (parsed as usize, clamped to at least 1) when
/// the env var is set, else `default`. The DEFAULT (no env var) is the current
/// bounded trace length — the `1..=proptest_steps(N)` step bounds reduce to
/// the existing `1..=N` — while the diversity lane sets it to run LONGER
/// action traces (e.g. 2x the default).
#[cfg(test)]
pub(crate) fn proptest_steps(default: usize) -> usize {
    match std::env::var("DEPLOY_PROPSTEPS") {
        Ok(v) => v.trim().parse::<usize>().map_or(default, |n| n.max(1)),
        Err(_) => default,
    }
}

/// The proptest FAILURE-PERSISTENCE lever: `DEPLOY_PROPERSIST=1` (the
/// diversity lane sets it) enables proptest's file persistence writing to the
/// CHECKED-IN `proptest-regressions/` corpus — `SourceParallel(
/// "proptest-regressions")` resolves each source file's sibling corpus entry
/// (e.g. `proptest-regressions/semantic_invariants.txt`, the exact layout the
/// existing checked-in corpus files use), so a discovered MINIMAL failure is
/// persisted there and REPLAYED on every later run (before new cases) by any
/// test with persistence on. NOT set (the default dev run) → `None`: no
/// corpus file is read or written, the current deterministic behavior.
#[cfg(test)]
pub(crate) fn proptest_persistence() -> Option<Box<dyn proptest::test_runner::FailurePersistence>> {
    if std::env::var_os("DEPLOY_PROPERSIST").is_some_and(|v| v != "0") {
        Some(Box::new(
            proptest::test_runner::FileFailurePersistence::SourceParallel("proptest-regressions"),
        ))
    } else {
        None
    }
}

/// Test-only one-shot fault injection for crash-mid-finalization tests.
///
/// A fault is a one-shot arm keyed by the DEPLOYMENT ID of the attempt under
/// test (the two-part faults additionally by TARGET): the NEXT matching store
/// call fails exactly once (and disarms itself), while every other call —
/// including identical methods for different deployment IDs from any other
/// fixture, concurrently running — passes through untouched.
///
/// Faults exist for the INTENT persist ([`FaultKind::AppendAttempt`]), the
/// TERMINAL EVENT append ([`FaultKind::AppendTerminal`] — the deployment's
/// single finalize write; a one-shot failure leaves the entry intent-only and
/// recoverable), the four ATOMIC-APPEND stage kinds ([`FaultKind::AppendWrite`]
/// / [`FaultKind::AppendSync`] / [`FaultKind::AppendRename`] /
/// [`FaultKind::AppendDirSync`], keyed by deployment id, firing at the
/// whole-ledger rewrite's temp-write / temp-sync / rename / parent-dir-sync
/// stages), the FIRST-append durable dir-creation syncs
/// ([`FaultKind::SyncNewTargetDir`] / [`FaultKind::SyncTargetsDir`], keyed by
/// TARGET, firing only when the append actually created the target directory),
/// the LOCK-PATH target-dir creation ([`FaultKind::LockMkdir`], keyed by
/// TARGET, firing before the durable pre-creation the engine/checkpoint run
/// ahead of the target lock — the crash-at-mkdir boundary, leaving NO target
/// directory), the post-commit observed-refresh faults ([`FaultKind::WriteServer`],
/// [`FaultKind::WriteObserved`], keyed additionally by TARGET), and the
/// retention-maintenance arms ([`FaultKind::ReadRetentionDebt`],
/// [`FaultKind::WriteRetentionDebt`], keyed by TARGET). The CHECKPOINT kinds
/// are keyed by TARGET: the ledger replacement's four ATOMIC-REPLACEMENT
/// stages, mirroring the append path's stage faults
/// ([`FaultKind::LedgerReplaceWrite`] / `LedgerReplaceSync` /
/// `LedgerReplaceRename` / `LedgerReplaceDirSync`) and the three
/// best-effort sweep stages ([`FaultKind::SweepDeployments`],
/// [`FaultKind::SweepReleases`], [`FaultKind::SweepObjects`]). The old
/// floor-marker/cleanup-debt kinds are GONE with the machinery that
/// consumed them.
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
    /// (and, for the observed-refresh and checkpoint kinds, by target).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub(crate) enum FaultKind {
        /// `append_intent` — the intent persist, the FIRST store I/O of a
        /// push (before any remote mutation).
        AppendAttempt,
        /// `append_terminal` — the TERMINAL EVENT append, the deployment's
        /// single finalize write (status + outcomes + rollback). A one-shot
        /// failure here leaves the entry intent-only (recoverable-pending).
        AppendTerminal,
        /// The ledger append's TEMP-WRITE stage (the atomic whole-ledger
        /// rewrite, keyed by the deployment id being appended). Fires before
        /// any I/O: the visible ledger is wholly OLD.
        AppendWrite,
        /// The ledger append's TEMP-SYNC stage: fires after the temp file
        /// was written, before its fsync — the dot-prefixed temp exists but
        /// is invisible, and the visible ledger is wholly OLD.
        AppendSync,
        /// The ledger append's RENAME stage: fires after the temp was
        /// written AND fsynced, before the atomic rename — the visible
        /// ledger is wholly OLD (only an invisible temp was created).
        AppendRename,
        /// The ledger append's PARENT-DIR-SYNC stage: fires AFTER the atomic
        /// rename, BEFORE the parent-directory fsync — the ledger IS wholly
        /// NEW (the new content is in place under its final name, only the
        /// directory entry is not yet synced) but the append returns `Err`.
        AppendDirSync,
        /// The FIRST append's durable dir-creation: the sync that makes the NEW
        /// TARGET DIR's directory entry durable (the fsync of `targets/`, which
        /// holds the `targets/<target>/` entry), keyed by target. Fires ONLY
        /// when the append actually created the target directory (an existing
        /// target's append creates and syncs nothing, so the arm never fires
        /// there). The reported `Err` leaves the prior state: the target dir
        /// exists (it was created before the sync boundary) but no ledger was
        /// written — crash recovery finds the prior state, never a missing
        /// target directory after a reported success.
        SyncNewTargetDir,
        /// The FIRST append's durable dir-creation: the sync of the `targets/`
        /// directory's OWN entry (the fsync of the store base, which names
        /// `targets/` — `targets/` may have been created by an EARLIER unsynced
        /// store open), keyed by target. Fires ONLY when the append created the
        /// target directory (same conditioning as
        /// [`FaultKind::SyncNewTargetDir`]).
        SyncTargetsDir,
        /// The LOCK-PATH target-dir creation (the reported lock-bypass bug):
        /// the durable pre-creation the engine/checkpoint run BEFORE the
        /// target lock is acquired (the lock file lives inside the target
        /// dir, so a plain unsynced mkdir on the lock path used to bypass the
        /// first-append durability helper entirely). Keyed by target; fires
        /// BEFORE the durable helper creates anything — a crash at the mkdir
        /// step — so recovery finds the PRIOR STATE with NO target directory
        /// (a first target) and no ledger, and a retry re-appends cleanly.
        LockMkdir,
        /// Post-commit observed-refresh per-server record write
        /// (`servers/<id>.json`), keyed by (deployment id, target).
        WriteServer,
        /// Post-commit observed-refresh SLOT record write
        /// (`slots/<slot-id>/observed.json` — the slot's ONE physical
        /// observed state, never replicated per target), keyed by
        /// (deployment id, SLOT id).
        WriteObserved,
        /// `read_retention_debt` (retention maintenance debt read), keyed by
        /// target.
        ReadRetentionDebt,
        /// `write_retention_debt` (retention maintenance debt write), keyed by
        /// target.
        WriteRetentionDebt,
        /// `read_sweep_debt` (the store-global sweep-debt read), keyed by the
        /// empty global key (the sweep debt is store-global, not
        /// target-keyed). Post-commit maintenance: a failure is a warning,
        /// never an `Err`.
        ReadSweepDebt,
        /// `write_sweep_debt` (the store-global sweep-debt write/remove),
        /// keyed by the empty global key.
        WriteSweepDebt,
        /// The artifact garbage collection SCAN (the retained-set
        /// computation of [`crate::retention::gc`]), keyed by the checkpoint
        /// deployment id. Post-commit maintenance: a failure aborts the
        /// pass BEFORE any deletion (fail closed — nothing is ever unlinked
        /// against a partial retained set) and the sweep is reported
        /// retry-required; the retry recomputes reachability fresh.
        GcScan,
        /// The artifact GC's RELEASE-RECORD deletion phase, keyed by the
        /// checkpoint deployment id. Fires before any release dir is
        /// removed: the unreachable release records stay on disk (extra
        /// garbage, never less) and the retry reclaims them.
        GcDeleteReleases,
        /// The artifact GC's TREE-OBJECT deletion phase, keyed by the
        /// checkpoint deployment id. Fires before any tree dir is removed.
        GcDeleteTrees,
        /// The artifact GC's K-TH RELEASE unlink, keyed by the checkpoint
        /// deployment id and consumed PER CANDIDATE by the release-deletion
        /// loop on a sequence counter: the unlink attempt after k successful
        /// deletions fails — exactly k release records are removed and the
        /// stage aborts (fail closed) with the remaining candidates pending.
        /// Armed via [`FaultRegistry::arm_release_unlink_after`].
        GcUnlinkReleases,
        /// The artifact GC's K-TH TREE unlink — same per-candidate sequence
        /// semantics as [`FaultKind::GcUnlinkReleases`], in the tree
        /// deletion loop. Armed via [`FaultRegistry::arm_tree_unlink_after`].
        GcUnlinkTrees,
        /// The checkpoint sweep's K-TH DEPLOYMENT-DIR deletion (global empty
        /// key like the other sweep kinds), consumed per candidate by the
        /// deployment stage: the unlink fails after k successful deletions
        /// and the stage aborts with the remaining candidates pending.
        /// Armed via [`FaultRegistry::arm_deployment_unlink_after`].
        SweepDeploymentsNth,
        /// The checkpoint's ATOMIC LEDGER REPLACEMENT — TEMP-WRITE stage
        /// (keyed by target), fired at the replacement's first I/O stage:
        /// the checkpoint fails with `Err` (a PRE-RENAME failure — the
        /// visible ledger is wholly OLD and nothing was discarded).
        LedgerReplaceWrite,
        /// The checkpoint's ATOMIC LEDGER REPLACEMENT — TEMP-FSYNC stage
        /// (keyed by target), fired after the temp write, before its fsync:
        /// the checkpoint fails with `Err` and the visible ledger is wholly
        /// OLD (only an invisible dot-prefixed temp exists).
        LedgerReplaceSync,
        /// The checkpoint's ATOMIC LEDGER REPLACEMENT — RENAME stage (keyed
        /// by target), fired after the chmod, before the atomic rename: the
        /// checkpoint fails with `Err` and the visible ledger is wholly OLD.
        LedgerReplaceRename,
        /// The checkpoint's ATOMIC LEDGER REPLACEMENT — PARENT-DIRECTORY
        /// open/fsync stage (keyed by target), fired AFTER the atomic rename
        /// (the retained suffix IS visible under its final name) and converted
        /// by the replace primitive into
        /// [`crate::store::atomic::ReplaceOutcome::ReplacedDurabilityUnknown`]
        /// — NEVER an `Err`. The checkpoint returns a STRUCTURED report
        /// (established, durability warning, sweep deferred), no sweep ran,
        /// and a retry recomputes the suffix + reachability and converges.
        LedgerReplaceDirSync,
        /// The checkpoint sweep's DEPLOYMENT-DIR stage (keyed by target),
        /// fired at the stage's entry: no deployment dir is deleted and the
        /// report says sweep retry-required.
        SweepDeployments,
        /// The checkpoint sweep's RELEASE-RECORD stage (keyed by target),
        /// fired at the stage's entry: no release record is deleted and the
        /// report says sweep retry-required.
        SweepReleases,
        /// The checkpoint sweep's TREE-OBJECT stage (keyed by target), fired
        /// at the stage's entry: no object is deleted and the report says
        /// sweep retry-required.
        SweepObjects,
        /// The checkpoint sweep's REACHABILITY-SCAN stage (keyed by the
        /// empty global key, like the other sweep stages): fired at the
        /// sweep's entry, BEFORE the reachable-set computation — the sweep
        /// aborts with an error that the checkpoint flow converts into a
        /// warning (the ledger commit stands, the sweep is retry-required).
        /// This is the "sweep read" failure the explicit commit boundary
        /// must never surface as `Err`.
        SweepScan,
        /// The checkpoint sweep's DIRECTORY-ENUMERATION stage (keyed by the
        /// empty global key): fired AFTER the reachable-set scan succeeds,
        /// BEFORE the `deployments/` / `releases/` / `objects/` listings —
        /// the sweep fails with nothing deleted; the checkpoint flow
        /// converts the failure into a warning (established report,
        /// retry-required).
        SweepEnumerate,
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
        /// Per-candidate SEQUENCE-COUNTER arms: (kind, deployment id) ->
        /// (the unlink call number the fault fires ON, calls so far). An arm
        /// with target N fires on the N-th `consume_unlink` call for the
        /// kind — the `arm_*_unlink_after(k)` methods store k+1, so the
        /// fault fires after k successful unlinks (the (k+1)-th unlink
        /// attempt fails) and the stage aborts with exactly k candidates
        /// removed and the rest pending.
        unlinks: Mutex<BTreeMap<(FaultKind, String), (usize, usize)>>,
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
            self.unlinks.lock().unwrap().clear();
        }

        // ---- arm_* convenience surface (historical API) --------------
        //
        // These mirror the historical module-level `arm_<kind>(id)` /
        // `arm_<kind>(id, target)` functions one-to-one, so a call site that
        // used to read `test_faults::arm_<kind>(id)` converts mechanically to
        // `store.fault_registry().arm_<kind>(id)` (only the receiver
        // changes).

        /// Arm the next `append_intent` (ledger intent) call for
        /// `deployment_id` to fail once. The intent is persisted BEFORE any
        /// remote mutation, so a one-shot failure here leaves the remote
        /// untouched (no generation, no `current` change).
        pub(crate) fn arm_append_attempt(&self, deployment_id: &str) {
            self.arm(FaultKind::AppendAttempt, deployment_id);
        }

        /// Arm the next `append_terminal` (the deployment's TERMINAL EVENT
        /// append — status + outcomes + rollback in ONE atomic line) for
        /// `deployment_id` to fail once. A failure leaves the ledger entry
        /// intent-only (recoverable-pending): the next push reconciles it
        /// from the verified desired state.
        pub(crate) fn arm_append_terminal(&self, deployment_id: &str) {
            self.arm(FaultKind::AppendTerminal, deployment_id);
        }

        /// Arm the ledger append's TEMP-WRITE stage to fail once for
        /// `deployment_id`: the fault fires before any I/O, so the visible
        /// ledger is wholly OLD.
        pub(crate) fn arm_append_write(&self, deployment_id: &str) {
            self.arm(FaultKind::AppendWrite, deployment_id);
        }

        /// Arm the ledger append's TEMP-SYNC stage to fail once for
        /// `deployment_id`: the fault fires after the temp write, before its
        /// fsync — the visible ledger is wholly OLD.
        pub(crate) fn arm_append_sync(&self, deployment_id: &str) {
            self.arm(FaultKind::AppendSync, deployment_id);
        }

        /// Arm the ledger append's RENAME stage to fail once for
        /// `deployment_id`: the fault fires before the atomic rename — the
        /// visible ledger is wholly OLD.
        pub(crate) fn arm_append_rename(&self, deployment_id: &str) {
            self.arm(FaultKind::AppendRename, deployment_id);
        }

        /// Arm the ledger append's PARENT-DIR-SYNC stage to fail once for
        /// `deployment_id`: the fault fires AFTER the atomic rename, before
        /// the directory fsync — the ledger is wholly NEW but the append
        /// returns `Err`.
        pub(crate) fn arm_append_dir_sync(&self, deployment_id: &str) {
            self.arm(FaultKind::AppendDirSync, deployment_id);
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

        /// Arm the next `read_retention_debt` call for `target` to fail once
        /// (retention-maintenance debt, keyed by target). Absorbs the
        /// debt-I/O sibling agent's `arm_read_retention_debt`.
        pub(crate) fn arm_read_retention_debt(&self, target: &str) {
            self.arm(FaultKind::ReadRetentionDebt, target);
        }

        /// Arm the next `write_retention_debt` call for `target` to fail once
        /// (retention-maintenance debt, keyed by target). Absorbs the
        /// debt-I/O sibling agent's `arm_write_retention_debt`.
        pub(crate) fn arm_write_retention_debt(&self, target: &str) {
            self.arm(FaultKind::WriteRetentionDebt, target);
        }

        /// Arm the checkpoint's ATOMIC LEDGER REPLACEMENT TEMP-WRITE stage
        /// for `target` to fail once: the checkpoint fails with `Err` (a
        /// PRE-RENAME failure), no deletion happens, and the visible ledger
        /// is wholly OLD (nothing was discarded).
        pub(crate) fn arm_ledger_replace_write(&self, target: &str) {
            self.arm(FaultKind::LedgerReplaceWrite, target);
        }

        /// Arm the checkpoint's ATOMIC LEDGER REPLACEMENT TEMP-FSYNC stage
        /// for `target` to fail once: the checkpoint fails with `Err`, the
        /// visible ledger is wholly OLD, and no deletion happens.
        pub(crate) fn arm_ledger_replace_sync(&self, target: &str) {
            self.arm(FaultKind::LedgerReplaceSync, target);
        }

        /// Arm the checkpoint's ATOMIC LEDGER REPLACEMENT RENAME stage for
        /// `target` to fail once: the checkpoint fails with `Err` (the
        /// rename never happened), the visible ledger is wholly OLD, and no
        /// deletion happens.
        pub(crate) fn arm_ledger_replace_rename(&self, target: &str) {
            self.arm(FaultKind::LedgerReplaceRename, target);
        }

        /// Arm the checkpoint's ATOMIC LEDGER REPLACEMENT PARENT-DIRECTORY
        /// open/fsync stage for `target` to fail once: the fault fires
        /// AFTER the rename — the retained suffix IS visible under its
        /// final name but its durability is unconfirmed — and the replace
        /// primitive surfaces it as
        /// [`crate::store::atomic::ReplaceOutcome::ReplacedDurabilityUnknown`]
        /// (never an `Err`). The checkpoint returns an ESTABLISHED report
        /// with a durability warning and the sweep DEFERRED (no deletion,
        /// no `run_sweep`); a re-run of the same checkpoint recomputes the
        /// suffix + reachability and converges.
        pub(crate) fn arm_ledger_replace_dir_sync(&self, target: &str) {
            self.arm(FaultKind::LedgerReplaceDirSync, target);
        }

        /// Arm the checkpoint sweep's DEPLOYMENT-DIR stage to fail once (at
        /// the stage's entry: no deployment dir is deleted and the report
        /// says sweep retry-required). The sweep is GLOBAL (not
        /// target-keyed): the arm lands on the empty key the sweep consumes,
        /// so it fires on the next `run_sweep` regardless of which target
        /// triggered it.
        pub(crate) fn arm_sweep_deployments(&self) {
            self.arm(FaultKind::SweepDeployments, "");
        }

        /// Arm the checkpoint sweep's RELEASE-RECORD stage to fail once (at
        /// the stage's entry: no release record is deleted and the report
        /// says sweep retry-required). Global, like
        /// [`FaultRegistry::arm_sweep_deployments`].
        pub(crate) fn arm_sweep_releases(&self) {
            self.arm(FaultKind::SweepReleases, "");
        }

        /// Arm the checkpoint sweep's TREE-OBJECT stage to fail once (at the
        /// stage's entry: no object is deleted and the report says sweep
        /// retry-required). Global, like
        /// [`FaultRegistry::arm_sweep_deployments`].
        pub(crate) fn arm_sweep_objects(&self) {
            self.arm(FaultKind::SweepObjects, "");
        }

        /// Arm the checkpoint sweep's REACHABILITY-SCAN to fail once (before
        /// the retained-set computation: the sweep aborts with nothing
        /// deleted and the checkpoint reports the sweep retry-required as a
        /// WARNING — never an `Err`, the ledger commit stands). Global, like
        /// [`FaultRegistry::arm_sweep_deployments`].
        pub(crate) fn arm_sweep_scan(&self) {
            self.arm(FaultKind::SweepScan, "");
        }

        /// Arm the checkpoint sweep's DIRECTORY-ENUMERATION to fail once
        /// (after the reachable-set scan, before the root listings — the
        /// sweep aborts with nothing deleted and the checkpoint reports the
        /// sweep retry-required as a warning). Global, like
        /// [`FaultRegistry::arm_sweep_deployments`].
        pub(crate) fn arm_sweep_enumerate(&self) {
            self.arm(FaultKind::SweepEnumerate, "");
        }

        /// Arm the next store-global `read_sweep_debt` call to fail once
        /// (sweep-debt maintenance read, keyed by the empty global key).
        pub(crate) fn arm_read_sweep_debt(&self) {
            self.arm(FaultKind::ReadSweepDebt, "");
        }

        /// Arm the next store-global `write_sweep_debt` call to fail once
        /// (sweep-debt maintenance write/remove, keyed by the empty global
        /// key).
        pub(crate) fn arm_write_sweep_debt(&self) {
            self.arm(FaultKind::WriteSweepDebt, "");
        }

        // ---- per-candidate SEQUENCE-COUNTER unlink faults -----------------
        //
        // The k-th unlink failure arms: the stage aborts AFTER `k`
        // successful unlinks — the (k+1)-th unlink attempt fails — so
        // exactly `k` candidates are removed and the remaining candidates
        // stay PENDING (planned, still on disk). The count is consumed per
        // candidate by the deletion loops ([`FaultRegistry::consume_unlink`])
        // keyed by the checkpoint deployment id (or the empty global key for
        // the deployment stage, like the other sweep kinds).

        /// Arm the artifact GC's RELEASE stage to abort after `k` successful
        /// release unlinks: the (k+1)-th unlink attempt fails, exactly `k`
        /// candidates are removed, and the rest stay pending (the k-th
        /// release unlink arm). Keyed by the checkpoint deployment id.
        pub(crate) fn arm_release_unlink_after(&self, deployment_id: &str, k: usize) {
            self.arm_unlink_after(FaultKind::GcUnlinkReleases, deployment_id, k);
        }

        /// Arm the artifact GC's TREE stage to abort after `k` successful
        /// tree unlinks — same semantics as
        /// [`FaultRegistry::arm_release_unlink_after`].
        pub(crate) fn arm_tree_unlink_after(&self, deployment_id: &str, k: usize) {
            self.arm_unlink_after(FaultKind::GcUnlinkTrees, deployment_id, k);
        }

        /// Arm the checkpoint sweep's DEPLOYMENT-DIR stage to abort after
        /// `k` successful deletions (the k-th deployment unlink arm;
        /// global empty key, like the other sweep kinds).
        pub(crate) fn arm_deployment_unlink_after(&self, k: usize) {
            self.arm_unlink_after(FaultKind::SweepDeploymentsNth, "", k);
        }

        /// Shared arm: the fault fires on the (k+1)-th `consume_unlink` call
        /// — k deletions succeed first.
        fn arm_unlink_after(&self, kind: FaultKind, deployment_id: &str, k: usize) {
            self.unlinks
                .lock()
                .unwrap()
                .insert((kind, deployment_id.to_string()), (k + 1, 0));
        }

        /// Consume the per-candidate sequence-counter fault for `kind`: each
        /// call advances the counter, and the call that reaches the armed
        /// target returns `true` (that unlink fails and the stage aborts)
        /// and disarms. Every other call returns `false` (the unlink
        /// succeeds).
        pub(crate) fn consume_unlink(&self, kind: FaultKind, deployment_id: &str) -> bool {
            let mut m = self.unlinks.lock().unwrap();
            let key = (kind, deployment_id.to_string());
            match m.get_mut(&key) {
                Some((target, count)) => {
                    *count += 1;
                    if *count == *target {
                        m.remove(&key);
                        true
                    } else {
                        false
                    }
                }
                None => false,
            }
        }
    }
}
pub(crate) mod step17_hook {
    use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use crate::identity::DeploymentId;

    /// WHICH step-17-equivalent lock acquisition the engine is parked at.
    /// Carried on the "at step-17" signal so the test-facing handle can
    /// tell the phases apart and act (e.g. arm a debt fault) only at the
    /// phase it intends to fault.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum HookPhase {
        /// The deferred-maintenance retry ([`crate::deploy`]'s
        /// `retry_deferred_retentions`): the engine reads the retention debt
        /// FIRST (before this park), then services each slot under the
        /// mutation lock. Runs on later pushes — before the fresh step-17
        /// retention on the normal path and at the no-op return — whenever a
        /// prior push left a debt marker.
        DeferredRetry,
        /// The fresh per-slot retention of THIS push (step 17): the
        /// post-commit retention of every slot the push's target belongs to.
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
        /// retention), each signal carrying its [`HookPhase`]; the test receives
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
    use crate::remote::transport::{
        CreateNewVerdict, LocalTransport, Remote, scripted::ScriptedExec,
    };

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
                inner: LocalTransport::with_exec(
                    &crate::testutil::fixture_env(),
                    base,
                    ScriptedExec::default_success(),
                )?,
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
        fn try_write_new(&self, rel: &std::path::Path, data: &[u8]) -> Result<CreateNewVerdict> {
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
                inner: LocalTransport::with_exec(
                    &crate::testutil::fixture_env(),
                    base,
                    ScriptedExec::default_success(),
                )?,
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
        fn try_write_new(&self, rel: &std::path::Path, data: &[u8]) -> Result<CreateNewVerdict> {
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
                inner: LocalTransport::with_exec(
                    &crate::testutil::fixture_env(),
                    base,
                    ScriptedExec::default_success(),
                )?,
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
    /// A transport wrapper that fails the FIRST `state/inventory.json`
    /// write once (the last step of `RemoteHelper::rotate`), letting a test
    /// inject a post-commit ROTATION failure deterministically: the
    /// mark-and-sweep deletions have already happened, then the inventory
    /// write errors — exactly the "retention failed after commit" window the
    /// engine defers as durable retention debt. Mirrors the
    /// `FailOnceMarkerRemote` pattern: the fault fires on the first `write`
    /// whose path is exactly `state/inventory.json` and disarms itself,
    /// while every other call passes through untouched.
    pub(crate) struct FailOnceInventoryRemote {
        inner: LocalTransport,
        armed: Arc<AtomicBool>,
    }

    impl FailOnceInventoryRemote {
        pub(crate) fn build(base: PathBuf, armed: Arc<AtomicBool>) -> Result<Box<dyn Remote>> {
            Ok(Box::new(FailOnceInventoryRemote {
                inner: LocalTransport::with_exec(
                    &crate::testutil::fixture_env(),
                    base,
                    ScriptedExec::default_success(),
                )?,
                armed,
            }))
        }
        fn fail_inventory(&self, rel: &std::path::Path) -> bool {
            self.armed.load(Ordering::SeqCst) && rel.to_string_lossy() == "state/inventory.json"
        }
    }

    impl Remote for FailOnceInventoryRemote {
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
            if self.fail_inventory(rel) {
                self.armed.store(false, Ordering::SeqCst);
                return Err(Error::remote(
                    "FailOnceInventoryRemote: retention inventory write forced to fail (once)",
                ));
            }
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
                inner: LocalTransport::with_exec(
                    &crate::testutil::fixture_env(),
                    base,
                    ScriptedExec::default_success(),
                )?,
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
        fn try_write_new(&self, rel: &std::path::Path, data: &[u8]) -> Result<CreateNewVerdict> {
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
    ) -> impl Fn(&crate::config::ServerDef, &crate::config::SlotConfig) -> Result<Box<dyn Remote>>
    {
        move |s, _slot| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(CountingRemote::new(
                base.join(s.id.as_str()),
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
    #[cfg(test)]
    use proptest::prelude::*;
    #[cfg(test)]
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
                    !reg.consume(FaultKind::AppendTerminal, ID_A),
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
    use crate::identity::DeploymentId;
    #[cfg(test)]
    use proptest::prelude::*;
    #[cfg(test)]
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

/// TEST FIXTURES for the semantic-kernel record shapes: shared builders the
/// record-model and engine test modules use to construct VALID intents and
/// terminals through the KERNEL's validated constructors (the old direct
/// struct literals are gone — the domain types are private-fielded and the
/// constructors are the ONE validator). Tests that need INVALID values
/// mutate the WIRE objects, never the domain.
pub(crate) mod fixtures {
    use crate::identity::{
        ArtifactRef, BehaviorDigest, DeploymentId, RolloutGroupName, SlotId, TargetName, Timestamp,
        VariantName, test_deployment_id, test_generation_id, test_release_id, test_tree_digest,
    };
    use crate::kernel;
    use crate::kernel::intent::{PlanInput, PlannedDeploy};
    use crate::kernel::snapshot::{PreviousGeneration, SnapshotSlot};
    use crate::ledger::TargetSnapshot;
    use crate::ledger::records::{
        DegradedTerminal, LedgerTerminal, NonEmptySlotTable, Observation, PhysicalBinding,
        SlotOutcome, SlotTable, TerminalDisposition,
    };
    use std::collections::BTreeMap;

    /// The canonical test binding for a slot.
    pub(crate) fn binding(sid: &SlotId) -> PhysicalBinding {
        PhysicalBinding {
            server: crate::identity::ServerId::parse("s1").unwrap(),
            deploy_dir: format!("/srv/deploy/{}", sid.as_str()),
        }
    }

    /// A plan-minted result for a slot, derived deterministically from the
    /// slot id (generation/artifact by tag).
    pub(crate) fn snapshot_slot(sid: &SlotId) -> SnapshotSlot {
        SnapshotSlot::new(
            test_generation_id(sid.as_str()),
            ArtifactRef {
                release: test_release_id(sid.as_str()),
                variant: VariantName::parse("standard").unwrap(),
                tree: test_tree_digest(sid.as_str()),
            },
            binding(sid),
        )
    }

    /// The canonical behavior digest fixture.
    pub(crate) fn behavior_digest() -> BehaviorDigest {
        BehaviorDigest::parse(crate::identity::DIGEST_TEST_HEX_1).unwrap()
    }

    /// Build a FULL-push intent (group None, parent None) over `slots`, all
    /// deployed (rule: group None requires every slot Deploy), with the
    /// given pre-push observations (default `KnownAbsent`).
    pub(crate) fn full_intent(
        dep: &str,
        target: &str,
        slots: &[SlotId],
        pre_push: &[(SlotId, Observation<PreviousGeneration>)],
    ) -> crate::kernel::intent::DeploymentIntent {
        let target_name = TargetName::parse(target).unwrap();
        let planned: Vec<PlannedDeploy> = slots
            .iter()
            .map(|sid| PlannedDeploy {
                slot: sid.clone(),
                result: snapshot_slot(sid),
                pre_push: pre_push
                    .iter()
                    .find(|(k, _)| k == sid)
                    .map(|(_, o)| o.clone())
                    .unwrap_or(Observation::KnownAbsent),
            })
            .collect();
        kernel::intent::plan(PlanInput {
            deployment_id: test_deployment_id(dep),
            target: target_name,
            parent: None,
            parent_snapshot: None,
            group: None,
            selection: slots.to_vec(),
            planned,
            behavior_digest: behavior_digest(),
            attempted_at: Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        })
        .expect("a valid test intent plans")
    }

    /// Build a GROUP intent: a subset of slots deployed, the rest inherited
    /// from `base` (the parent snapshot). `base` must cover every slot in
    /// `slots`.
    pub(crate) fn group_intent(
        dep: &str,
        target: &str,
        group: &str,
        parent: &DeploymentId,
        base: &TargetSnapshot,
        slots: &[SlotId],
        group_slots: &[SlotId],
    ) -> crate::kernel::intent::DeploymentIntent {
        let target_name = TargetName::parse(target).unwrap();
        let planned: Vec<PlannedDeploy> = group_slots
            .iter()
            .map(|sid| PlannedDeploy {
                slot: sid.clone(),
                result: snapshot_slot(sid),
                pre_push: Observation::KnownAbsent,
            })
            .collect();
        kernel::intent::plan(PlanInput {
            deployment_id: test_deployment_id(dep),
            target: target_name,
            parent: Some(parent.clone()),
            parent_snapshot: Some(base.clone()),
            group: Some(RolloutGroupName::parse(group).unwrap()),
            selection: slots.to_vec(),
            planned,
            behavior_digest: behavior_digest(),
            attempted_at: Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
        })
        .expect("a valid test group intent plans")
    }

    /// A Successful TERMINAL for an intent: PAYLOAD-FREE, bound by the
    /// canonical intent digest.
    pub(crate) fn successful_terminal(
        intent: &crate::kernel::intent::DeploymentIntent,
    ) -> LedgerTerminal {
        LedgerTerminal::new(
            Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
            kernel::terminal::intent_digest(intent),
            TerminalDisposition::Successful,
            Some("test seeds a successful deployment".to_string()),
        )
    }

    /// A FailedPreflight TERMINAL for an intent.
    pub(crate) fn failed_preflight_terminal(
        intent: &crate::kernel::intent::DeploymentIntent,
    ) -> LedgerTerminal {
        LedgerTerminal::new(
            Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
            kernel::terminal::intent_digest(intent),
            TerminalDisposition::FailedPreflight,
            Some("test: preflight failed".to_string()),
        )
    }

    /// A FAILED-ROLLED-BACK terminal whose outcomes cover exactly `slots`
    /// (all Restored — the rolled-back class).
    pub(crate) fn rolled_back_terminal(
        intent: &crate::kernel::intent::DeploymentIntent,
        slots: &[SlotId],
    ) -> LedgerTerminal {
        let outcomes = SlotTable::from_map(
            slots
                .iter()
                .map(|sid| {
                    (
                        sid.clone(),
                        SlotOutcome::Restored {
                            observation: Observation::Known(
                                crate::ledger::records::ObservedGeneration {
                                    generation: test_generation_id(sid.as_str()),
                                },
                            ),
                        },
                    )
                })
                .collect(),
        );
        let payload = crate::kernel::terminal::FailedRolledBackTerminal::try_new(outcomes)
            .expect("a rolled-back payload is valid");
        LedgerTerminal::new(
            Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
            kernel::terminal::intent_digest(intent),
            TerminalDisposition::FailedRolledBack(payload),
            Some("test: rolled back".to_string()),
        )
    }

    /// A DEGRADED terminal whose outcomes cover exactly `slots` (all
    /// Failed/Advanced — the remaining-changes class).
    pub(crate) fn degraded_terminal(
        intent: &crate::kernel::intent::DeploymentIntent,
        slots: &[SlotId],
    ) -> LedgerTerminal {
        let outcomes: BTreeMap<SlotId, SlotOutcome> = slots
            .iter()
            .map(|sid| {
                (
                    sid.clone(),
                    SlotOutcome::Failed {
                        observation: Observation::Known(
                            crate::ledger::records::ObservedGeneration {
                                generation: test_generation_id(sid.as_str()),
                            },
                        ),
                        compensated: false,
                        error: Some("test failure".to_string()),
                    },
                )
            })
            .collect();
        let non_empty =
            NonEmptySlotTable::build(outcomes.iter().map(|(k, v)| (k.clone(), v.clone())))
                .expect("a degraded fixture outcome set is non-empty");
        let payload = DegradedTerminal::try_new(non_empty).expect("a degraded payload is valid");
        LedgerTerminal::new(
            Timestamp::parse("2026-01-01T00:00:00Z").unwrap(),
            kernel::terminal::intent_digest(intent),
            TerminalDisposition::Degraded(payload),
            Some("test: degraded".to_string()),
        )
    }
}
