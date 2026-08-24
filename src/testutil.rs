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
/// keyed by TARGET (the debt file lives under `targets/<target>/`).
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
        /// Post-commit observed-refresh observed record write
        /// (`targets/<target>/observed.json`), keyed by (deployment id,
        /// target).
        WriteObserved,
        /// `read_rotation_debt` (rotation maintenance debt read), keyed by
        /// target.
        ReadRotationDebt,
        /// `write_rotation_debt` (rotation maintenance debt write), keyed by
        /// target.
        WriteRotationDebt,
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

        /// Arm the next `write_observed` call that writes `deployment_id`'s
        /// slot into `target`'s observed record to fail once. The
        /// primary-target write is the last observed-refresh operation; the
        /// other-member writes happen per shared slot inside the propagation
        /// loop. The target half of the key selects exactly one of them.
        pub(crate) fn arm_write_observed(&self, deployment_id: &str, target: &str) {
            self.arm_target(FaultKind::WriteObserved, deployment_id, target);
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
