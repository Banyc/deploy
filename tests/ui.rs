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
//!   write happens only through the crate-internal `TargetLedgerTxn`.
//!
//! The `.pass()` case is the CONTRAST: the non-Successful dispositions are
//! constructible by any caller (there is nothing to fabricate).

#[test]
fn sealed_ledger_writes_are_compile_enforced() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/fabricate_success.rs");
    t.compile_fail("tests/ui/sealed_proof.rs");
    t.compile_fail("tests/ui/append_outside_txn.rs");
    t.pass("tests/ui/non_successful_terminal_ok.rs");
}
