//! The [`PhysicalBinding`] fields are PRIVATE and its constructor is the
//! validated [`PhysicalBinding::new`]: a library caller CANNOT hand-write a
//! binding with a junk (relative / traversal / root) `deploy_dir` — the
//! invariant-bearing fields are closed.

use deploy::ledger::PhysicalBinding;

fn d<T>() -> T {
    panic!("never reached")
}

fn main() {
    // ERROR: `server` and `deploy_dir` are private; a struct literal cannot
    // be written by a library caller (the validated `PhysicalBinding::new`
    // is the only constructor).
    let _binding = PhysicalBinding {
        server: d(),
        deploy_dir: d(),
    };
}
