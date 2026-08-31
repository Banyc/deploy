//! UNGUARDED ROTATION IS IMPOSSIBLE: `RemoteHelper` has NO `rotate` method —
//! rotation is a DESTRUCTIVE operation and therefore a [`deploy::remote::helper::HeldSlotLock`]
//! method (a caller must HOLD the slot's mutation lock to sweep it). An
//! external caller calling `helper.rotate(...)` on a bare `RemoteHelper`
//! does not compile.

use deploy::remote::helper::RemoteHelper;

fn main() {
    let helper: RemoteHelper = unimplemented!();
    let _ = &helper;
    // ERROR: no such method — `rotate` exists only on the `HeldSlotLock`
    // guard, which can only be obtained by acquiring the lock through a
    // `SlotRemote` (the mutation capability bound to its owner).
    helper.rotate(&std::collections::HashSet::new(), &std::collections::HashSet::new());
}
