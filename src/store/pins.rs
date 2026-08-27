//! Store-global artifact retention pins (`pins.json`): the mutable,
//! atomically-replaced pin set with fail-closed, schema-versioned reads.

use crate::error::{Error, Result};
use crate::ledger::Pins;
use crate::store::atomic::{path_state, read_json, write_atomic_replace};
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
    /// fsync via [`write_atomic_replace`](crate::store::atomic::write_atomic_replace):
    /// replacing the pin set is a mutable user operation, so the file is
    /// replaced atomically, never CAS'd). A no-op in the sense that the
    /// file may be absent entirely — [`LocalStore::read_pins`] treats a
    /// missing file as the empty pin set.
    pub fn write_pins(&self, pins: &Pins) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(pins)
            .map_err(|e| Error::store(format!("serialize pins: {e}")))?;
        write_atomic_replace(&self.pins_path(), &bytes)
    }

    /// Read the store's pins record, or the DEFAULT (empty) pin set when no
    /// pins file exists. FAILS CLOSED on every integrity violation,
    /// mirroring the other marker readers:
    ///
    /// * `schema_version` must be exactly [`PINS_SCHEMA_VERSION`]; any other
    ///   version fails with an error naming the version (a pins file written
    ///   by a different schema is never silently interpreted).
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
            return Ok(Pins {
                schema_version: crate::ledger::PINS_SCHEMA_VERSION,
                releases: Vec::new(),
                bindings: Vec::new(),
            });
        }
        let pins: Pins = read_json(&p)?;
        if pins.schema_version != crate::ledger::PINS_SCHEMA_VERSION {
            return Err(Error::integrity(format!(
                "pins file carries unsupported schema_version {} (expected {}): only PINS_SCHEMA_VERSION is accepted",
                pins.schema_version,
                crate::ledger::PINS_SCHEMA_VERSION
            )));
        }
        Ok(pins)
    }
}
