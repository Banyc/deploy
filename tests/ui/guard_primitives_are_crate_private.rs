//! GUARD MUTATION PRIMITIVES ARE CRATE-PRIVATE: a library caller holding a
//! [`deploy::remote::helper::HeldSlotLock`] guard CANNOT call the mutation
//! primitives directly — `create_generation`, `swap_current`, `rotate`,
//! `publish_release`, `publish_tree`, `transaction_record`, ... are
//! CRATE-PRIVATE (the structural verdict's point 7 taken to its conclusion).
//! The ONLY public mutation path is [`deploy::rollout::commit`] with a
//! [`deploy::rollout::PreparedSlotMutation`] (plus the capability
//! acquisition [`deploy::remote::helper::SlotRemote::acquire_lock_guard`]).
//! Calling a primitive on the guard does not compile.

use deploy::remote::helper::HeldSlotLock;

fn main() {
    let guard: HeldSlotLock = unimplemented!();
    let _ = &guard;
    // ERROR: the mutation primitives are crate-private — a library caller
    // cannot call them; the ONLY public mutation path is `commit`.
    guard.create_generation(&unimplemented!());
    guard.swap_current(&unimplemented!(), &unimplemented!(), "op");
}
