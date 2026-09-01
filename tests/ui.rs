//! THE COMPILE-FAIL SUITE (the review's acceptance): prove a library caller
//! CANNOT fabricate success or append outside a locked txn. The sealed
//! [`crate::kernel::terminal::VerifiedExecution`] proof and the
//! [`crate::store::local::ledger::TargetLedgerTxn`]-only write surface are
//! enforced at COMPILE time, not by a runtime check — the cases below
//! genuinely fail to compile (`trybuild` is a test-only dev-dependency).
//!
//! The UI cases live in `tests/ui/` and compile as EXTERNAL crates against
//! the library's PUBLIC surface only — exactly the position of a library
//! caller:
//!
//! * `fabricate_success.rs` — `LedgerTerminal::new(..., Successful, ...)`
//!   does not compile (the proof-less constructor type-excludes the
//!   `Successful` disposition);
//! * `sealed_proof.rs` — the `VerifiedExecution` proof has no public
//!   constructor (sealed `_sealed` field), so a caller cannot mint the
//!   evidence and `LedgerTerminal::successful` is unreachable;
//! * `append_outside_txn.rs` — the raw store-level `append_intent` /
//!   `append_terminal` / `append_checkpoint` methods do not exist: a ledger
//!   write happens only through the crate-internal `TargetLedgerTxn`;
//! * `identity_new.rs` — the identity `new` constructors are
//!   `#[cfg(test)]`-gated: `SlotId::new(...)` in production does not
//!   compile (a caller can only build identities through the validated
//!   `parse` path);
//! * `plan_literal.rs` — the `DeploymentPlan` fields are private: a
//!   library caller cannot fabricate a plan;
//! * `binding_literal.rs` — the `PhysicalBinding` fields are private and
//!   its constructor is the validated `PhysicalBinding::new`: a library
//!   caller cannot hand-write a binding with a junk `deploy_dir`;
//! * `rebinding_proof.rs` — the `VerifiedReleaseRebinding` proof is sealed
//!   (private invariant-bearing fields + a private `_sealed` marker): no
//!   struct literal can be written;
//! * `rebinding_deserialize.rs` — the proof is serde-free: a wire string
//!   can deserialize into the CLAIM `RebindingPlan`, never into a "verified"
//!   proof — only the verification (`TryFrom`) mints it.
//! * `unguarded_rotate.rs` — `RemoteHelper` has no `rotate` method: rotation
//!   is a destructive operation and therefore a `HeldSlotLock` method (a
//!   caller must HOLD the slot's mutation lock to sweep it).
//! * `unguarded_create_generation.rs` — `RemoteHelper` has no
//!   `create_generation` method: generation creation is a destructive
//!   operation and therefore a `HeldSlotLock` method (the assignment's
//!   OWNER is bound by the guard itself).
//! * `guard_primitives_are_crate_private.rs` — the guard mutation
//!   primitives (`create_generation`, `swap_current`, `rotate`,
//!   `publish_release`, `publish_tree`, `transaction_record`, ...) are
//!   CRATE-PRIVATE (the structural verdict's point 7 taken to its
//!   conclusion): even a caller HOLDING a `HeldSlotLock` guard cannot call
//!   them — the ONLY public mutation path is `deploy::rollout::commit` with
//!   a `PreparedSlotMutation`.
//!
//! * `unlocked_store_writer.rs` — the store's RAW writers (`write_plan`,
//!   `store_object`, `write_pins`, `write_slot_observed`, `write_server`,
//!   the debt writers, `write_release`, `recover_if_missing`) and the
//!   helper's `write_inventory` are CRATE-PRIVATE (point 7): a library
//!   caller cannot mutate a persistent aggregate through a capability-less
//!   public mutator.
//!
//! The `.pass()` case is the CONTRAST: the non-Successful dispositions are
//! constructible by any caller (there is nothing to fabricate).

#[test]
fn sealed_ledger_writes_are_compile_enforced() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/fabricate_success.rs");
    t.compile_fail("tests/ui/sealed_proof.rs");
    t.compile_fail("tests/ui/append_outside_txn.rs");
    t.compile_fail("tests/ui/identity_new.rs");
    t.compile_fail("tests/ui/plan_literal.rs");
    t.compile_fail("tests/ui/binding_literal.rs");
    t.compile_fail("tests/ui/rebinding_proof.rs");
    t.compile_fail("tests/ui/rebinding_deserialize.rs");
    t.compile_fail("tests/ui/unguarded_rotate.rs");
    t.compile_fail("tests/ui/unguarded_create_generation.rs");
    t.compile_fail("tests/ui/guard_primitives_are_crate_private.rs");
    t.compile_fail("tests/ui/unlocked_store_writer.rs");
    t.pass("tests/ui/non_successful_terminal_ok.rs");
}
