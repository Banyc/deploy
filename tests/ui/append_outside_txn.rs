//! The raw store-level ledger appends do NOT exist on the public surface:
//! `LocalStore::append_intent` / `append_terminal` / `append_checkpoint`
//! are GONE — a write to a target's ledger happens ONLY through the
//! crate-internal [`deploy::store::local::ledger::TargetLedgerTxn`] (which
//! owns the target `operation.lock` and the folded deployment state, and is
//! not constructible outside the crate). An external caller calling the raw
//! methods does not compile.

use deploy::store::local::LocalStore;

fn main() {
    let store =
        LocalStore::with_base(std::env::temp_dir().join("trybuild-append-outside-txn")).unwrap();
    let _ = &store;
    // ERROR: no such method — the raw appends are not part of the store's
    // public surface (only the locked `TargetLedgerTxn` writes a ledger).
    store.append_intent("t1", &todo!());
    store.append_terminal("t1", &todo!(), &todo!());
}
