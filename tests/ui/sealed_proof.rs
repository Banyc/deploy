//! The `VerifiedExecution` proof is SEALED: its only field is private
//! (`_sealed`) and it has no public constructor, so a library caller
//! cannot mint the proof — and without it, `LedgerTerminal::successful`
//! (the ONLY constructor that may produce a `Successful` terminal) is
//! unreachable. The proof is minted exclusively on the crate's
//! verified-execution evidence path (the successful finalizer's
//! `LockedObservation::Verified` / the kernel's `ExecutionReport::Verified`).

use deploy::kernel::terminal::VerifiedExecution;

fn main() {
    // ERROR: `VerifiedExecution` has no public constructor; the `_sealed`
    // field is private, so a struct literal cannot be written.
    let _proof = VerifiedExecution { _sealed: () };
}
