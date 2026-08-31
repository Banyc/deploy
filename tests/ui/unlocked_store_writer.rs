//! A library caller cannot exercise an UNLOCKED STORE WRITER or a raw
//! unlocked remote mutation: the store's raw writers (`write_plan`,
//! `store_object`, `write_pins`, `write_slot_observed`, `write_server`, the
//! retention/sweep debt writers, `write_release`, `recover_if_missing`) and
//! the remote helper's inventory writer (`write_inventory`) are
//! CRATE-PRIVATE (the structural verdict's point 7): a persistent aggregate
//! is written through its ONE in-crate path (the ledger through the locked
//! `TargetLedgerTxn`, the observed records and debt through the engine's
//! maintenance wiring), never through a public capability-less mutator.

use deploy::remote::helper::RemoteHelper;
use deploy::store::local::LocalStore;

fn main() {
    let store: LocalStore = unimplemented!();
    let _ = store.write_plan(&unimplemented!(), &unimplemented!());
    let _ = store.write_release(&unimplemented!());
    let _ = store.store_object(&unimplemented!(), &unimplemented!());
    let _ = store.recover_if_missing(&unimplemented!(), &unimplemented!());
    let _ = store.write_pins(&unimplemented!());
    let _ = store.write_slot_observed(&unimplemented!(), &unimplemented!());
    let _ = store.write_server(&unimplemented!());
    let _ = store.write_retention_debt(&unimplemented!(), &unimplemented!());
    let _ = store.write_sweep_debt(&unimplemented!());
    let helper: RemoteHelper = unimplemented!();
    let _ = helper.write_inventory();
}
