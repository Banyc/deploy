//! Store-global artifact retention pins (`pins.json`): the mutable,
//! atomically-replaced pin set with fail-closed, schema-versioned reads.

use crate::error::{Error, Result};
use crate::ledger::Pins;
use crate::store::atomic::{ReplaceOutcome, path_state, read_json};
use crate::store::local::LocalStore;
use std::path::PathBuf;

impl LocalStore {
    // ---- pins ------------------------------------------------------------

    /// Path of the store-global pins record (`pins.json`, at the store
    /// root). Pins are GLOBAL, not per-target: a release or binding is
    /// shared by every target that references it, and the artifact garbage
    /// collector is global too, so a pin protects content everywhere.
    pub fn pins_path(&self) -> PathBuf {
        self.base.join("pins.json")
    }

    /// Write the store's pins durably (atomic temp + rename + parent-dir
    /// fsync via `write_atomic_replace`:
    /// replacing the pin set is a mutable user operation, so the file is
    /// replaced atomically, never CAS'd). A no-op in the sense that the
    /// file may be absent entirely — [`LocalStore::read_pins`] treats a
    /// missing file as the empty pin set.
    ///
    /// ACCEPTS ONLY THE VALIDATED DOMAIN TYPE: the fields are private and
    /// the only constructors are [`Pins::empty`] (fixed to
    /// `PINS_SCHEMA_VERSION`) and the wire `Deserialize` (which refuses any
    /// other version), so a wrong-schema `Pins` is unconstructible. The
    /// schema check below is DEFENSE IN DEPTH: a pins file must never be
    /// persisted in a schema the reader rejects.
    ///
    /// FAIL CLOSED ON UNCONFIRMED DURABILITY: a
    /// [`ReplaceOutcome::ReplacedDurabilityUnknown`] outcome — the new pin
    /// set IS visible but the parent-directory fsync failed — is DOWNGRADED
    /// to `Err`, never reported as success. The pins marker is a retention
    /// anchor: the garbage collector treats a missing/unreadable pins file
    /// as "no pins" and could delete content a pin might protect, so a
    /// marker that may not survive power loss must not be reported written.
    /// (Unlike the checkpoint, whose whole commit boundary and ordering
    /// guarantee rest ON the ledger replace — there the rename itself is
    /// the commit and the durability uncertainty is surfaced as a
    /// structured outome so the caller knows the commit stands but the
    /// sweep must be deferred; a pins write has no such two-phase
    /// semantics — its caller has no facility to report "visible but
    /// unconfirmed", so failure is the only safe answer.)
    pub fn write_pins(&self, pins: &Pins) -> Result<()> {
        if pins.schema_version() != crate::ledger::PINS_SCHEMA_VERSION {
            return Err(Error::integrity(format!(
                "refusing to write pins with unsupported schema_version {} (expected {}): only PINS_SCHEMA_VERSION is accepted",
                pins.schema_version(),
                crate::ledger::PINS_SCHEMA_VERSION
            )));
        }
        let bytes = serde_json::to_vec_pretty(pins)
            .map_err(|e| Error::store(format!("serialize pins: {e}")))?;
        match self.write_atomic_replace_at(&self.pins_path(), &bytes)? {
            ReplaceOutcome::ReplacedDurable => Ok(()),
            ReplaceOutcome::ReplacedDurabilityUnknown { error } => Err(error),
        }
    }

    /// Read the store's pins record, or the DEFAULT (empty) pin set when no
    /// pins file exists. FAILS CLOSED on every integrity violation,
    /// mirroring the other marker readers:
    ///
    /// * `schema_version` must be exactly `PINS_SCHEMA_VERSION`; any other
    ///   version fails with an error naming the version (a pins file written
    ///   by a different schema is never silently interpreted). The wire
    ///   `Deserialize` is the PRIMARY gate — a wrong-schema `Pins` is
    ///   unconstructible — and the check below is defense in depth.
    /// * a present but MALFORMED pins file is a parse failure (semantic
    ///   corruption) — [`Error::store`] is reserved for mechanical
    ///   filesystem I/O.
    ///
    /// The garbage collector treats a failed read as a failed scan: it must
    /// never delete anything while a pin it could not read might have
    /// protected it.
    pub fn read_pins(&self) -> Result<Pins> {
        let p = self.pins_path();
        // Tri-state: only a genuine NotFound is the default (no pins); a
        // stat failure propagates as a Store error (an unreadable pins file
        // must not read as "no pins" — the GC would then delete content a
        // pin might protect).
        if !path_state(&p)? {
            return Ok(Pins::empty());
        }
        let pins: Pins = read_json(&p)?;
        if pins.schema_version() != crate::ledger::PINS_SCHEMA_VERSION {
            return Err(Error::integrity(format!(
                "pins file carries unsupported schema_version {} (expected {}): only PINS_SCHEMA_VERSION is accepted",
                pins.schema_version(),
                crate::ledger::PINS_SCHEMA_VERSION
            )));
        }
        Ok(pins)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{ArtifactRef, VariantName, test_release_id, test_tree_digest};
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    /// A VALID DOMAIN pins value, generated through the PUBLIC constructors
    /// ONLY (`Pins::empty()` + the `with_release` / `with_binding`
    /// builders) — exactly the set of values the type admits (a
    /// wrong-schema `Pins` is unconstructible).
    fn arbitrary_pins() -> impl Strategy<Value = Pins> {
        (
            prop::collection::vec(0..3usize, 0..=3),
            prop::collection::vec(
                (0..3usize, 0..3usize).prop_map(|(i, j)| ArtifactRef {
                    release: test_release_id(&format!("rel-{i}")),
                    variant: VariantName::parse("standard").unwrap(),
                    tree: test_tree_digest(&format!("tree-{i}-{j}")),
                }),
                0..=3,
            ),
        )
            .prop_map(|(rels, bindings)| {
                let mut pins = Pins::empty();
                for r in rels {
                    pins = pins.with_release(test_release_id(&format!("rel-{r}")));
                }
                for b in bindings {
                    pins = pins.with_binding(b);
                }
                pins
            })
    }

    proptest! {
        // THE USER'S PROPERTY: for every publicly constructible `Pins`,
        // `read(write(pins)) == pins` — the pin set round-trips EXACTLY
        // through the store (write durably, read back, equal). Bounded
        // `proptest_cases(16)` (full 16 with `DEPLOY_FULL_TESTS=1`, fast
        // default), fixed seed 0x5EED_5EED (house style), no persistence.
        #![proptest_config(ProptestConfig {
            cases: crate::testutil::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn pins_round_trip_through_the_store(pins in arbitrary_pins()) {
            let dir = crate::testutil::fixture_tmpdir(&crate::testutil::fixture_env()).unwrap();
            let store = LocalStore::with_base(dir.path().join("store")).unwrap();
            store.write_pins(&pins).unwrap();
            let read = store.read_pins().unwrap();
            prop_assert_eq!(read, pins);
        }
    }
}
