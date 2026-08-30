//! The identity `new` constructors are `#[cfg(test)]`-gated: a library
//! caller CANNOT build an identity without the validated `parse` /
//! `FromStr` / `TryFrom` path. `SlotId::new("..")` would smuggle a
//! traversal component past the format rule — the compile-fail proves the
//! unchecked constructor is not part of the production surface.

use deploy::identity::SlotId;

fn main() {
    // ERROR: `SlotId::new` exists only under `#[cfg(test)]`; a production
    // caller must go through the validated `SlotId::parse`.
    let _bad = SlotId::new("..");
}
