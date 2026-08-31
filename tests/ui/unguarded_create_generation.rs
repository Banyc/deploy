//! UNGUARDED GENERATION CREATION IS IMPOSSIBLE: `RemoteHelper` has NO
//! `create_generation` method — generation creation is a DESTRUCTIVE
//! operation and therefore a [`deploy::remote::helper::HeldSlotLock`] method
//! (a caller must HOLD the slot's mutation lock to create a generation, and
//! the assignment's OWNER is bound by the guard itself). An external caller
//! calling `helper.create_generation(...)` on a bare `RemoteHelper` does not
//! compile.

use deploy::remote::helper::RemoteHelper;

fn main() {
    let helper: RemoteHelper = unimplemented!();
    let _ = &helper;
    // ERROR: no such method — `create_generation` exists only on the
    // `HeldSlotLock` guard, which can only be obtained by acquiring the lock
    // through a `SlotRemote` (the mutation capability bound to its owner).
    helper.create_generation(&unimplemented!());
}
